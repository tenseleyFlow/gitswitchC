/* Tests for the SSH agent reuse fast path in ssh_start_isolated_agent:
 * a live per-account agent is adopted ONLY when it already holds the exact
 * key the account is configured with (ssh_key_fingerprint/ssh_socket_has_key
 * match by fingerprint). Reusing on socket liveness alone would keep serving
 * a stale key after `gitswitch edit` changed the account's key path — the
 * wrong identity would keep authenticating silently.
 *
 * All ssh-keygen/ssh-add/ssh-agent invocations are intercepted with a fake
 * runner; the "agent" is a real (bound but unserved) unix socket under a
 * private fake XDG_RUNTIME_DIR so validate_ssh_agent_socket sees a genuine
 * 0600 socket. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp, sockets) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fingerprints: the fake agent holds KEYA; accounts point at keyA or keyB. */
#define FP_A "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define FP_B "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

static int g_agent_start_attempts; /* execs of ssh-agent (i.e. reuse REFUSED) */
static const char *g_pid_link_to_plant;
static const char *g_pid_link_target;
static bool g_replace_dir_on_key_probe;
static bool g_replace_dir_on_agent_start;
static bool g_key_load_used_pinned_socket;
static char g_moved_agent_dir[256];
static char g_xdg[64]; /* short: the socket path must fit sun_path (~108) */

static int replace_agent_dir_namespace(void) {
    char live[256];

    if ((size_t)snprintf(live, sizeof(live), "%s/gitswitch-ssh", g_xdg) >=
            sizeof(live) ||
        (size_t)snprintf(g_moved_agent_dir, sizeof(g_moved_agent_dir),
                         "%s/gitswitch-ssh.pinned", g_xdg) >=
            sizeof(g_moved_agent_dir)) {
        return -1;
    }
    if (rename(live, g_moved_agent_dir) != 0 || mkdir(live, 0700) != 0) {
        return -1;
    }
    return 0;
}

static int replace_agent_dir_after_commit(int dir_fd) {
    (void)dir_fd;
    return replace_agent_dir_namespace();
}

static int with_runner_cwd(const run_opts_t *opts,
                           int (*operation)(const char *),
                           const char *path) {
    int saved_cwd = -1;
    int rc;

    if (!opts || !opts->use_cwd_fd) {
        return operation(path);
    }
    saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
    if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) {
        if (saved_cwd >= 0) close(saved_cwd);
        return -1;
    }
    rc = operation(path);
    if (fchdir(saved_cwd) != 0) rc = -1;
    close(saved_cwd);
    return rc;
}

static int bind_and_chmod_socket(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0 || strlen(path) >= sizeof(addr.sun_path)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return chmod(path, 0600);
}

static ssh_process_outcome_t refuse_agent_reap(pid_t pid,
                                                const char *socket_arg,
                                                int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_OWNED;
}

static int swap_pid_temp_path(int dir_fd, const char *temp_name) {
    static const char replacement[] = "replacement\n";
    int fd;

    if (unlinkat(dir_fd, temp_name, 0) != 0) return -1;
    fd = openat(dir_fd, temp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    if (write(fd, replacement, sizeof(replacement) - 1) !=
        (ssize_t)(sizeof(replacement) - 1)) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int fake_ssh_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    /* ssh-keygen -lf <key>: fingerprint derives from the key file name. */
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        const char *fp = strstr(argv[2], "keyB") ? FP_B : FP_A;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-add -l (against the socket in opts->extra_env): agent holds keyA. */
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (g_replace_dir_on_key_probe) {
            g_replace_dir_on_key_probe = false;
            if (replace_agent_dir_namespace() != 0) return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s agent-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-agent: reaching this means reuse was refused. Fail the start so the
     * test ends here deterministically. */
    if (strcmp(argv[0], "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }

    return 0;
}

/* Scratch runtime dir + a real 0600 unix socket standing in for the agent.
 * Returns 0 on success; sock_out receives the per-account socket path. */
static int setup_agent_socket(const char *account, char *sock_out, size_t size) {
    char dir[128];
    struct sockaddr_un addr;
    int fd;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    if (!ts_mkdtemp(g_xdg)) return -1;
    if (chmod(g_xdg, 0700) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    if (mkdir(dir, 0700) != 0) return -1;

    if ((size_t)snprintf(sock_out, size, "%s/ssh-agent.%s.sock", dir, account)
        >= size) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_out) >= sizeof(addr.sun_path)) { close(fd); return -1; }
    strcpy(addr.sun_path, sock_out);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd); /* the socket inode persists; nobody needs to accept() */
    return chmod(sock_out, 0600);
}

static void make_account(account_t *a, const char *key_basename) {
    memset(a, 0, sizeof(*a));
    a->id = 1;
    safe_strncpy(a->name, "work", sizeof(a->name));
    safe_strncpy(a->email, "w@x.com", sizeof(a->email));
    a->ssh_enabled = true;
    snprintf(a->ssh_key_path, sizeof(a->ssh_key_path), "%s/%s", g_xdg, key_basename);
}

/* Adoption control: agent holds the account's own key -> reused in place
 * (no ssh-agent exec, key marked already loaded, current.sock retargeted). */
TEST(ssh_fingerprint_reuse_adopts_matching_key) {
    char sock[256], cur[256];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    make_account(&acct, "keyA"); /* matches the FP_A the fake agent reports */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "99999", 1), 0);

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(cfg.key_already_loaded);       /* caller skips ssh_add_key */
    CHECK(!cfg.agent_owned);             /* no verified PID => never claim ownership */
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(getenv("SSH_AGENT_PID") == NULL);
    CHECK_EQ_INT(g_agent_start_attempts, 0); /* no restart, no re-prompt */
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(path_exists(sock));            /* the live agent was not reaped */

    /* current.sock points at the adopted agent's socket. */
    snprintf(cur, sizeof(cur), "%s/gitswitch-ssh/current.sock", g_xdg);
    CHECK_EQ_INT(lstat(cur, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

/* The guard itself: same live socket, but the account's key changed (edit) —
 * the fingerprint mismatch must REFUSE reuse, reap the stale agent, and go
 * start a fresh one (which the fake runner fails, ending the test there). */
TEST(ssh_fingerprint_reuse_rejects_different_key) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    make_account(&acct, "keyB"); /* FP_B: NOT what the fake agent holds */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    /* Reuse refused: the code moved on to a fresh agent start... */
    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    /* ...whose (fake-injected) failure fails the switch instead of silently
     * keeping the wrong key active. */
    CHECK_EQ_INT(rc, -1);
    /* The stale wrong-key agent socket was reaped, not left adoptable. */
    CHECK(!path_exists(sock));
}

/* T1 (AR-01-T1): parse_ssh_agent_output must unwrap a quoted
 * SSH_AUTH_SOCK="..." value, the way some ssh-agent builds and wrappers
 * report paths containing spaces/parens. Locks the T1 quoted-socket fix. */

/* Runner variant whose fake ssh-agent SUCCEEDS: it binds a real socket at the
 * requested -a path and reports it QUOTED, the way some ssh-agent builds and
 * wrappers do. Only a parser that strips the quotes can then validate it. */
static int fake_quoting_agent_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-agent") == 0) {
        /* Find "-a <path>" wherever it sits: the AR-03 H1 fix passes an
         * explicit -s ahead of it, so the socket is no longer argv[2]. */
        const char *sock = NULL;
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "-a") == 0 && argv[i + 1]) {
                sock = argv[i + 1];
                break;
            }
        }
        if (!sock) return -1;
        if (g_replace_dir_on_agent_start) {
            g_replace_dir_on_agent_start = false;
            if (replace_agent_dir_namespace() != 0) return -1;
        }
        if (with_runner_cwd(opts, bind_and_chmod_socket, sock) != 0) return -1;
        if (g_pid_link_to_plant && g_pid_link_target &&
            symlink(g_pid_link_target, g_pid_link_to_plant) != 0) {
            (void)unlink(sock);
            return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=\"%s\"; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n"
                     "echo Agent pid 12345;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-l") != 0) {
        const char *sock_env = NULL;
        if (opts && opts->extra_env) {
            for (size_t i = 0; opts->extra_env[i]; i++) {
                if (strncmp(opts->extra_env[i], "SSH_AUTH_SOCK=", 14) == 0) {
                    sock_env = opts->extra_env[i] + 14;
                    break;
                }
            }
        }
        g_key_load_used_pinned_socket = opts && opts->use_cwd_fd &&
            opts->cwd_fd >= 0 && sock_env &&
            strcmp(sock_env, "ssh-agent.work.sock") == 0;
        return g_key_load_used_pinned_socket ? 0 : -1;
    }
    /* No reusable socket exists in this test, so ssh-keygen/ssh-add answers
     * are irrelevant; succeed quietly. */
    return 0;
}

TEST(agent_output_quoted_auth_sock_is_unwrapped) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    /* Runtime dir only — deliberately NO pre-existing per-account socket, so
     * the reuse fast path is skipped and a fresh agent is "started". */
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    snprintf(sock, sizeof(sock), "%s/gitswitch-ssh/ssh-agent.work.sock", g_xdg);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    prev = run_set_runner(fake_quoting_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(strchr(cfg.agent_socket_path, '"') == NULL); /* quotes stripped */
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(g_key_load_used_pinned_socket);
}

/* The final public namespace check must run after current.sock is committed.
 * A same-uid replacement at that exact breakpoint is a failed transaction;
 * the pinned agent, PID sidecar, and link are cleaned from the moved inode. */
TEST(fresh_commit_revalidates_public_agent_directory) {
    char public_dir[256];
    char public_current[384];
    char moved_sock[384];
    char moved_pid[384];
    char moved_current[384];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev_runner;
    ssh_namespace_commit_hook_fn prev_hook;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(public_dir, sizeof(public_dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(public_current, sizeof(public_current), "%s/current.sock",
             public_dir);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    prev_hook = ssh_manager_set_namespace_commit_hook_fn(
        replace_agent_dir_after_commit);
    prev_runner = run_set_runner(fake_quoting_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev_runner);
    ssh_manager_set_namespace_commit_hook_fn(prev_hook);

    snprintf(moved_sock, sizeof(moved_sock),
             "%s/ssh-agent.work.sock", g_moved_agent_dir);
    snprintf(moved_pid, sizeof(moved_pid),
             "%s/ssh-agent.work.pid", g_moved_agent_dir);
    snprintf(moved_current, sizeof(moved_current),
             "%s/current.sock", g_moved_agent_dir);
    CHECK(!path_exists(public_current));
    CHECK(!path_exists(moved_sock));
    CHECK(!path_exists(moved_pid));
    CHECK(!path_exists(moved_current));
    CHECK(!cfg.agent_owned);
    CHECK_EQ_INT(cfg.agent_pid, -1);
}

/* A planted symlink at the account socket path must never be treated as an
 * agent socket merely because its target is a valid self-owned 0600 socket. */
TEST(ssh_reuse_refuses_symlinked_agent_socket) {
    char sock[256], external[256];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    snprintf(external, sizeof(external), "%s/external-agent.sock", g_xdg);
    CHECK_EQ_INT(rename(sock, external), 0);
    CHECK_EQ_INT(symlink(external, sock), 0);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(lstat(external, &st), 0);
    CHECK(S_ISSOCK(st.st_mode));
    CHECK(lstat(sock, &st) != 0 && errno == ENOENT);
}

/* Reuse reads its PID record as untrusted runtime state. A symlinked sidecar
 * is an error, not a path to fopen and not a reason to mutate its target. */
TEST(ssh_reuse_refuses_symlinked_pid_sidecar) {
    char sock[256], pid_path[256], victim[256], content[64];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    snprintf(pid_path, sizeof(pid_path),
             "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg);
    snprintf(victim, sizeof(victim), "%s/precious", g_xdg);
    CHECK_EQ_INT(write_string_to_file(victim, "424242\n", 0600), 0);
    CHECK_EQ_INT(symlink(victim, pid_path), 0);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 0);
    CHECK_EQ_INT(lstat(pid_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK_EQ_INT(read_file_to_string(victim, content, sizeof(content)), 7);
    CHECK_STR_EQ(content, "424242\n");
    CHECK(path_exists(sock));
}

/* The fresh-start sidecar commit uses temp+rename inside the pinned agent
 * directory. Plant a symlink after orphan cleanup but before the write: the
 * link itself must be atomically replaced and its target left untouched. */
TEST(fresh_agent_sidecar_atomically_replaces_planted_symlink) {
    char dir[128], pid_path[256], victim[256], content[64];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    snprintf(victim, sizeof(victim), "%s/precious", g_xdg);
    CHECK_EQ_INT(write_string_to_file(victim, "keep\n", 0600), 0);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_pid_link_to_plant = pid_path;
    g_pid_link_target = victim;
    prev = run_set_runner(fake_quoting_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), 0);
    run_set_runner(prev);
    g_pid_link_to_plant = NULL;
    g_pid_link_target = NULL;

    CHECK_EQ_INT(read_file_to_string(victim, content, sizeof(content)), 5);
    CHECK_STR_EQ(content, "keep\n");
    CHECK_EQ_INT(lstat(pid_path, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0600);
    CHECK_EQ_INT(read_file_to_string(pid_path, content, sizeof(content)), 6);
    CHECK_STR_EQ(content, "12345\n");
}

/* Reuse must stay inside the directory inode it pinned. Replacing the public
 * gitswitch-ssh pathname during the ssh-add probe must abort without reaping
 * the still-live socket in the renamed pinned directory or publishing state
 * into the replacement namespace. */
TEST(reuse_aborts_on_agent_directory_namespace_replacement) {
    char moved_sock[384];
    char moved_current[384];
    char public_sock[384];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    CHECK_EQ_INT(setup_agent_socket("work", public_sock,
                                    sizeof(public_sock)), 0);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_replace_dir_on_key_probe = true;
    prev = run_set_runner(fake_ssh_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev);
    g_replace_dir_on_key_probe = false;

    snprintf(moved_sock, sizeof(moved_sock),
             "%s/ssh-agent.work.sock", g_moved_agent_dir);
    snprintf(moved_current, sizeof(moved_current),
             "%s/current.sock", g_moved_agent_dir);
    CHECK(path_exists(moved_sock));
    CHECK(!path_exists(moved_current));
    CHECK(!path_exists(public_sock));
    CHECK(!cfg.agent_owned);
}

/* A fresh agent is started with a relative -a argument and a pinned cwd.
 * Even when the public directory pathname is replaced inside the runner, no
 * socket/sidecar/link may be split across the two namespaces and success may
 * not be reported through a public path that names the replacement. */
TEST(fresh_start_aborts_and_cleans_on_namespace_replacement) {
    char public_dir[256];
    char public_sock[384];
    char moved_sock[384];
    char moved_pid[384];
    char moved_current[384];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(public_dir, sizeof(public_dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(public_sock, sizeof(public_sock),
             "%s/ssh-agent.work.sock", public_dir);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_replace_dir_on_agent_start = true;
    prev = run_set_runner(fake_quoting_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev);
    g_replace_dir_on_agent_start = false;

    snprintf(moved_sock, sizeof(moved_sock),
             "%s/ssh-agent.work.sock", g_moved_agent_dir);
    snprintf(moved_pid, sizeof(moved_pid),
             "%s/ssh-agent.work.pid", g_moved_agent_dir);
    snprintf(moved_current, sizeof(moved_current),
             "%s/current.sock", g_moved_agent_dir);
    CHECK(!path_exists(public_sock));
    CHECK(!path_exists(moved_sock));
    CHECK(!path_exists(moved_pid));
    CHECK(!path_exists(moved_current));
    CHECK(!cfg.agent_owned);
    CHECK_EQ_INT(cfg.agent_pid, -1);
}

/* The deterministic PID temp name is attacker-visible. Replace it after the
 * writer fsyncs its opened fd but before renameat: the replacement must not be
 * installed as the sidecar or deleted as if it were the writer's inode. */
TEST(pid_sidecar_rejects_temp_path_inode_swap) {
    char dir[256];
    char temp_path[384];
    char pid_path[384];
    char content[64];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev_runner;
    ssh_pid_commit_hook_fn prev_hook;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(temp_path, sizeof(temp_path),
             "%s/.ssh-agent.work.pid.tmp.%d", dir, (int)getpid());
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    prev_hook = ssh_manager_set_pid_commit_hook_fn(swap_pid_temp_path);
    prev_runner = run_set_runner(fake_quoting_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    run_set_runner(prev_runner);
    ssh_manager_set_pid_commit_hook_fn(prev_hook);

    CHECK(!path_exists(pid_path));
    CHECK_EQ_INT(read_file_to_string(temp_path, content, sizeof(content)), 12);
    CHECK_STR_EQ(content, "replacement\n");
    CHECK(!cfg.agent_owned);
}

/* A failed reaper is retained state, not a warning. stop must leave the PID,
 * ownership, socket, and exported environment intact for a later retry. */
TEST(stop_agent_reap_failure_preserves_retry_handle) {
    char sock[256];
    ssh_config_t cfg;
    ssh_reap_fn prev_reap;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    safe_strncpy(cfg.agent_socket_path, sock, sizeof(cfg.agent_socket_path));
    safe_strncpy(cfg.agent_socket_arg, "ssh-agent.work.sock",
                 sizeof(cfg.agent_socket_arg));
    cfg.agent_pid = 12345;
    cfg.agent_owned = true;
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", sock, 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "12345", 1), 0);

    prev_reap = ssh_manager_set_reap_fn(refuse_agent_reap);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), -1);
    ssh_manager_set_reap_fn(prev_reap);

    CHECK(cfg.agent_owned);
    CHECK_EQ_INT(cfg.agent_pid, 12345);
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK_STR_EQ(cfg.agent_socket_arg, "ssh-agent.work.sock");
    CHECK(path_exists(sock));
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), sock);
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "12345");

    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
}

/* AR-02 #10: ssh_configure_host_alias writes "IdentityFile <path>" into
 * ~/.ssh/config; a newline in the path would inject an arbitrary ssh_config
 * directive (ProxyCommand => code execution on connect). The sink must refuse
 * such a path ITSELF — its only prior protection was the TOML-load sanitizer
 * stripping newlines, which a future non-TOML population path would bypass.
 * Drives the function directly with a hand-built account (exactly the bypass
 * the audit's PoC used) under a scratch HOME. */
TEST(host_alias_write_rejects_newline_key_path) {
    char home[128], cfg_path[256], buf[4096];
    account_t acct;
    FILE *f;
    size_t n;

    snprintf(home, sizeof(home), "/tmp/gswsshalias_XXXXXX");
    CHECK(ts_mkdtemp(home) != NULL);
    setenv("HOME", home, 1);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), "github.com-work");
    snprintf(acct.ssh_hostname, sizeof(acct.ssh_hostname), "github.com");
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path),
             "%s/key\nProxyCommand touch PWNED", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);

    /* Nothing may have been written: no config at all, or at least no
     * ProxyCommand line derived from the hostile path. */
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "r");
    if (f) {
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        CHECK(strstr(buf, "ProxyCommand") == NULL);
    }

    /* Control: a clean path writes the managed block with the IdentityFile. */
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key_ok", home);
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    f = fopen(cfg_path, "r");
    CHECK(f != NULL);
    if (f) {
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        CHECK(strstr(buf, "IdentityFile") != NULL);
        CHECK(strstr(buf, "key_ok") != NULL);
    }
}

/* AR-06 F15: a configured host-alias block used to leak forever — account
 * removal never cleaned ~/.ssh/config. ssh_remove_host_alias must excise
 * exactly the named managed block, leave unrelated managed blocks and
 * user-authored content intact, and no-op when the block or config is absent. */
TEST(host_alias_removal_excises_only_named_block) {
    char home[128], cfg_path[256], buf[4096];
    account_t work, personal;
    FILE *f;
    size_t n;

    snprintf(home, sizeof(home), "/tmp/gswsshrm_XXXXXX");
    CHECK(ts_mkdtemp(home) != NULL);
    setenv("HOME", home, 1);

    /* Seed a user-authored stanza first so we can prove it survives. */
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(cfg_path, 0700), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs("Host example\n    HostName example.com\n", f);
        fclose(f);
    }

    memset(&work, 0, sizeof(work));
    work.ssh_enabled = true;
    snprintf(work.ssh_host_alias, sizeof(work.ssh_host_alias), "github.com-work");
    snprintf(work.ssh_hostname, sizeof(work.ssh_hostname), "github.com");
    snprintf(work.ssh_key_path, sizeof(work.ssh_key_path), "%s/key_work", home);
    CHECK_EQ_INT(ssh_configure_host_alias(&work), 0);

    memset(&personal, 0, sizeof(personal));
    personal.ssh_enabled = true;
    snprintf(personal.ssh_host_alias, sizeof(personal.ssh_host_alias),
             "github.com-personal");
    snprintf(personal.ssh_hostname, sizeof(personal.ssh_hostname), "github.com");
    snprintf(personal.ssh_key_path, sizeof(personal.ssh_key_path),
             "%s/key_personal", home);
    CHECK_EQ_INT(ssh_configure_host_alias(&personal), 0);

    /* Remove only the work alias. */
    CHECK_EQ_INT(ssh_remove_host_alias("github.com-work"), 0);

    f = fopen(cfg_path, "r");
    CHECK(f != NULL);
    if (f) {
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        CHECK(strstr(buf, "github.com-work") == NULL);      /* excised */
        CHECK(strstr(buf, "key_work") == NULL);
        CHECK(strstr(buf, "github.com-personal") != NULL);  /* preserved */
        CHECK(strstr(buf, "key_personal") != NULL);
        CHECK(strstr(buf, "HostName example.com") != NULL); /* user content */
    }

    /* Idempotent: removing again (block now absent) is a clean no-op. */
    CHECK_EQ_INT(ssh_remove_host_alias("github.com-work"), 0);
    /* Removing against a nonexistent config is also a clean no-op. */
    unlink(cfg_path);
    CHECK_EQ_INT(ssh_remove_host_alias("github.com-personal"), 0);
}

/* AR-06 F29: a ~/.ssh/config larger than the old fixed 64 KiB cap must no
 * longer fail the whole switch. Seed ~200 KiB of user content, configure a
 * host alias (heap-sized read/write), and confirm the block installs while all
 * the user content survives; then remove it and confirm the large content is
 * still intact. */
TEST(host_alias_handles_config_larger_than_64k) {
    char home[128], cfg_path[256];
    account_t acct;
    FILE *f;
    size_t i;
    const size_t line_count = 8000; /* 8000 * ~26 bytes ≈ 208 KiB */
    char *content;
    long sz;

    snprintf(home, sizeof(home), "/tmp/gswsshbig_XXXXXX");
    CHECK(ts_mkdtemp(home) != NULL);
    setenv("HOME", home, 1);

    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(cfg_path, 0700), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "w");
    CHECK(f != NULL);
    if (f) {
        for (i = 0; i < line_count; i++) {
            fprintf(f, "# padding line %06zu filler\n", i);
        }
        fputs("Host sentinel-marker\n    HostName sentinel.example\n", f);
        CHECK_EQ_INT(fclose(f), 0);
    }

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), "github.com-big");
    snprintf(acct.ssh_hostname, sizeof(acct.ssh_hostname), "github.com");
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key_big", home);

    /* Pre-fix this returned -1 ("SSH config too large to update safely"). */
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);

    /* Read the whole thing back and confirm block + user content coexist. */
    f = fopen(cfg_path, "r");
    CHECK(f != NULL);
    if (f) {
        CHECK_EQ_INT(fseek(f, 0, SEEK_END), 0);
        sz = ftell(f);
        CHECK(sz > 200000);                       /* still large */
        rewind(f);
        content = malloc((size_t)sz + 1);
        CHECK(content != NULL);
        if (content) {
            size_t n = fread(content, 1, (size_t)sz, f);
            content[n] = '\0';
            CHECK(strstr(content, "Host sentinel-marker") != NULL); /* user kept */
            CHECK(strstr(content, "github.com-big") != NULL);       /* block added */
            CHECK(strstr(content, "key_big") != NULL);
            free(content);
        }
        fclose(f);
    }

    /* Removal on a large config also works and preserves user content. */
    CHECK_EQ_INT(ssh_remove_host_alias("github.com-big"), 0);
    f = fopen(cfg_path, "r");
    CHECK(f != NULL);
    if (f) {
        int saw_block = 0, saw_user = 0;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "github.com-big")) saw_block = 1;
            if (strstr(line, "Host sentinel-marker")) saw_user = 1;
        }
        fclose(f);
        CHECK(saw_block == 0); /* block gone */
        CHECK(saw_user == 1);  /* user content preserved */
    }
}

#if defined(__linux__)
/* AR-02 test menu (ranks 19/20): a sidecar PID that now belongs to a NON-agent
 * same-uid process — the classic PID-recycle scenario — must never be
 * signaled by the teardown path. reap_ssh_agent's identity check (comm +
 * exact socket in argv, /proc-based, hence Linux-only) must refuse it, keep
 * the bystander alive, and drop the sidecar as garbage. */
TEST(reset_never_signals_bystander_pid_in_sidecar) {
    char dir[128], pid_path[256], sock_path[256];
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 }; /* 100ms */
    FILE *pf;
    pid_t pid;
    int status = 0;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    CHECK_EQ_INT(mkdir(dir, 0700), 0);

    /* The bystander: our own forked child, parked on pause(). Its comm is
     * this test binary, not "ssh-agent", so the identity check must refuse. */
    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        for (;;) pause();
    }

    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    snprintf(sock_path, sizeof(sock_path), "%s/ssh-agent.work.sock", dir);
    pf = fopen(pid_path, "w");
    CHECK(pf != NULL);
    if (pf) {
        fprintf(pf, "%d\n", (int)pid);
        fclose(pf);
    }

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    nanosleep(&ts, NULL); /* let any (wrongly) sent signal land */

    CHECK_EQ_INT(kill(pid, 0), 0);          /* bystander untouched */
    CHECK(!path_exists(pid_path));          /* garbage record dropped */
    CHECK(!path_exists(sock_path));

    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
}
#endif

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(ssh_fingerprint_reuse_adopts_matching_key);
    RUN_TEST(ssh_fingerprint_reuse_rejects_different_key);
    RUN_TEST(agent_output_quoted_auth_sock_is_unwrapped);
    RUN_TEST(fresh_commit_revalidates_public_agent_directory);
    RUN_TEST(ssh_reuse_refuses_symlinked_agent_socket);
    RUN_TEST(ssh_reuse_refuses_symlinked_pid_sidecar);
    RUN_TEST(fresh_agent_sidecar_atomically_replaces_planted_symlink);
    RUN_TEST(reuse_aborts_on_agent_directory_namespace_replacement);
    RUN_TEST(fresh_start_aborts_and_cleans_on_namespace_replacement);
    RUN_TEST(pid_sidecar_rejects_temp_path_inode_swap);
    RUN_TEST(stop_agent_reap_failure_preserves_retry_handle);
    RUN_TEST(host_alias_write_rejects_newline_key_path);
    RUN_TEST(host_alias_removal_excises_only_named_block);
    RUN_TEST(host_alias_handles_config_larger_than_64k);
#if defined(__linux__)
    RUN_TEST(reset_never_signals_bystander_pid_in_sidecar);
#endif
TEST_MAIN_END()
