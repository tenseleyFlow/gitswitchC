/* AR-03 T1 coverage for src/ssh_manager.c:
 *   H1  — ssh-agent must be spawned with an explicit -s so a csh/tcsh $SHELL
 *         can't flip its output format past the Bourne-only parser, and a
 *         just-spawned agent that fails the post-spawn checks (parse or
 *         socket validation) must be reaped, not leaked holding the key.
 *   M2  — the reuse fast path adopts an agent only when it holds EXACTLY the
 *         account's key: one identity, fingerprint compared as a whole token.
 *   T3  — reap_ssh_agent's positive kill path against a REAL ssh-agent
 *         (Linux-gated: the identity check needs /proc).
 *   T5  — ssh_configure_host_alias preserve/splice/malformed branches with
 *         user stanzas above AND below the managed block.
 *   L6  — ssh_manager_reset refuses a symlinked/shared /tmp socket base.
 *   L16 — an identical ~/.ssh/config is not rewritten (no inode churn).
 *   L18 — the agent is probed (ssh-add -l) BEFORE ssh-keygen computes the
 *         expected fingerprint, so a stale socket costs no extra fork+exec.
 *
 * Same seams as tests/test_ssh_reuse.c: ssh-keygen/ssh-add/ssh-agent are
 * intercepted with run_set_runner fakes; "agents" are real bound-but-unserved
 * unix sockets under a private fake XDG_RUNTIME_DIR. The one exception is the
 * Linux-gated T3 test, which drives a REAL ssh-agent end to end. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp, sockets) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"
#include "runner_internal.h"
#include "error.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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

/* Fingerprints: fakes report FP by key-file basename (keyB -> FP_B). */
#define FP_A "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define FP_B "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

static char g_xdg[64]; /* short: socket paths must fit sun_path (~108) */

static int  g_agent_start_attempts;   /* execs of ssh-agent */
static bool g_agent_argv_had_dash_s;  /* H1: -s present in the spawn argv */
static char g_first_probe[32];        /* L18: first ssh-add/ssh-keygen exec */
#if defined(__linux__)
static ssh_process_image_t g_l29_image;
static int g_l29_denied_errno;
static ssh_process_generation_t g_l29_observed_generation;

static int l29_exact_image(pid_t pid, ssh_process_image_t *image) {
    (void)pid;
    if (!image) return -1;
    *image = g_l29_image;
    return 0;
}

static int l29_wrong_image(pid_t pid, ssh_process_image_t *image) {
    (void)pid;
    if (!image) return -1;
    *image = g_l29_image;
    image->executable_identity.st_ino++;
    return 0;
}

static int l29_wrong_uid(pid_t pid, ssh_process_image_t *image) {
    (void)pid;
    if (!image) return -1;
    *image = g_l29_image;
    image->effective_uid =
        g_l29_image.effective_uid == (uid_t)0 ? (uid_t)1 : (uid_t)0;
    return 0;
}

static int l29_inaccessible_image(pid_t pid, ssh_process_image_t *image) {
    (void)pid;
    (void)image;
    errno = EIO;
    return -1;
}

static int l29_denied_image(pid_t pid, ssh_process_image_t *image) {
    (void)pid;
    (void)image;
    errno = g_l29_denied_errno;
    return -1;
}

static int l29_wrong_generation(
    pid_t pid, ssh_process_generation_t *generation) {
    (void)pid;
    if (!generation) return -1;
    *generation = g_l29_observed_generation;
    return 0;
}
#endif

/* Find "-a <path>" wherever it sits in argv: the H1 fix inserts -s ahead of
 * it, so fakes must not assume a fixed position (and pre-fix argv still
 * matches, which is what makes the fail-before runs meaningful). */
static const char *argv_sock_path(const char *const argv[]) {
    for (size_t i = 1; argv[i]; i++) {
        if (strcmp(argv[i], "-a") == 0 && argv[i + 1]) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool argv_has(const char *const argv[], const char *flag) {
    for (size_t i = 1; argv[i]; i++) {
        if (strcmp(argv[i], flag) == 0) {
            return true;
        }
    }
    return false;
}

/* Bind a real unix socket at `path` with the given mode (0600 = passes
 * validate_ssh_agent_socket; anything else = fails it). */
static int bind_sock(const char *path, mode_t mode) {
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
    close(fd); /* the socket inode persists; nobody needs to accept() */
    return chmod(path, mode);
}

static int bind_sock_for_runner(const char *path, mode_t mode,
                                const run_opts_t *opts) {
    int saved_cwd;
    int rc;

    if (!opts || !opts->use_cwd_fd) return bind_sock(path, mode);
    saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
    if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) {
        if (saved_cwd >= 0) close(saved_cwd);
        return -1;
    }
    rc = bind_sock(path, mode);
    if (fchdir(saved_cwd) != 0) rc = -1;
    close(saved_cwd);
    return rc;
}

/* Scratch XDG_RUNTIME_DIR + the gitswitch-ssh dir under it. */
static int make_xdg_agent_dir(char *dir_out, size_t size) {
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswar03XXXXXX");
    if (!ts_mkdtemp(g_xdg)) return -1;
    if (chmod(g_xdg, 0700) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    if ((size_t)snprintf(dir_out, size, "%s/gitswitch-ssh", g_xdg) >= size) {
        return -1;
    }
    return mkdir(dir_out, 0700);
}

#if defined(__linux__)
static int write_live_agent_record(const char *dir, const char *name,
                                   pid_t pid) {
    ssh_agent_record_t record = {.pid = pid};
    int dir_fd;
    int rc;

    if (ssh_manager_test_capture_process_generation(
            pid, &record.generation) != 0) {
        return -1;
    }
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return -1;
    rc = ssh_manager_test_write_pid_sidecar(dir_fd, name, &record);
    if (close(dir_fd) != 0) rc = -1;
    return rc;
}
#endif

static int make_account(account_t *a, const char *key_basename) {
    static const char private_prefix[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    static const char private_suffix[] =
        "\n-----END OPENSSH PRIVATE KEY-----\n";
    const char *generation = strstr(key_basename, "keyB")
                                 ? "generation-b"
                                 : "generation-a";
    char key_data[256];

    memset(a, 0, sizeof(*a));
    a->id = 1;
    if (safe_strncpy(a->name, "work", sizeof(a->name)) != 0 ||
        safe_strncpy(a->email, "w@x.com", sizeof(a->email)) != 0 ||
        (size_t)snprintf(a->ssh_key_path, sizeof(a->ssh_key_path), "%s/%s",
                         g_xdg, key_basename) >= sizeof(a->ssh_key_path) ||
        (size_t)snprintf(key_data, sizeof(key_data), "%s%s%s",
                         private_prefix, generation, private_suffix) >=
            sizeof(key_data)) {
        return -1;
    }
    a->ssh_enabled = true;
    return write_string_to_file(a->ssh_key_path, key_data, 0600);
}

static int count_substr(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle)) n++;
    return n;
}

static int read_all(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) return -1;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return 0;
}

TEST(ssh_manager_reset_rejects_empty_selector) {
    char dir[128];
    char lock_path[160];

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswar03XXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    CHECK((size_t)snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg) <
          sizeof(dir));
    CHECK(access(dir, F_OK) != 0 && errno == ENOENT);
    clear_error();
    CHECK_EQ_INT(ssh_manager_reset(""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(access(dir, F_OK) != 0 && errno == ENOENT);

    CHECK_EQ_INT(mkdir(dir, 0700), 0);
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock", dir) <
          sizeof(lock_path));
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);
    clear_error();
    CHECK_EQ_INT(ssh_manager_reset(""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(path_exists(dir));
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);
}

/* ---- H1: csh/tcsh output format + leak-on-failure ------------------------ */

/* Fake ssh-agent that genuinely binds the -a socket, then reports in CSH
 * syntax — what a tcsh $SHELL provokes from a real ssh-agent spawned without
 * -s. This is exactly the half-alive state the audit's PoC leaked: agent up,
 * output unparseable, no PID sidecar yet. */
static int fake_csh_agent_runner(const char *const argv[], const run_opts_t *opts,
                                 run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s fixture (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        const char *sock = argv_sock_path(argv);
        g_agent_start_attempts++;
        g_agent_argv_had_dash_s = argv_has(argv, "-s");
        if (!sock || bind_sock_for_runner(sock, 0600, opts) != 0) return -1;
        if (result &&
            !run_launch_witness_capture(
                argv[0], &result->launch_witness)) {
            return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "setenv SSH_AUTH_SOCK %s;\n"
                     "setenv SSH_AGENT_PID 4242;\n"
                     "echo Agent pid 4242;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return 0; /* no reusable socket exists: ssh-keygen/ssh-add are irrelevant */
}

TEST(agent_spawn_pins_bourne_format_and_reaps_on_parse_failure) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_agent_argv_had_dash_s = false;
    prev = run_set_runner(fake_csh_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    /* The spawn must pin the output format regardless of $SHELL. */
    CHECK(g_agent_argv_had_dash_s);
    /* csh-format text stays unparseable (the parser is Bourne-only by
     * design), so the switch fails cleanly... */
    CHECK_EQ_INT(rc, -1);
    /* ...and the just-spawned agent must not be left adoptable: the failure
     * happens BEFORE the PID sidecar exists, so nothing else could ever reap
     * it. The socket is the only remaining handle on it. */
    CHECK(!path_exists(sock));
}

/* Fake ssh-agent whose socket fails validate_ssh_agent_socket (0644): the
 * parsed PID is known on this path, so the reap must target it directly. */
static int fake_badperm_agent_runner(const char *const argv[], const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s fixture (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        const char *sock = argv_sock_path(argv);
        g_agent_start_attempts++;
        if (!sock || bind_sock_for_runner(sock, 0644, opts) != 0) return -1;
        if (result &&
            !run_launch_witness_capture(
                argv[0], &result->launch_witness)) {
            return -1;
        }
        if (opts && opts->out) {
            /* PID far above any pid_max: reap_ssh_agent's identity check can
             * never find (let alone signal) a real process behind it. */
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=1073741824; export SSH_AGENT_PID;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return 0;
}

TEST(socket_validation_failure_reaps_spawned_agent) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_badperm_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK_EQ_INT(rc, -1);
    /* Same leak shape as the parse failure: alive agent, no sidecar yet.
     * The wrong-mode socket must not survive as a future adoption target. */
    CHECK(!path_exists(sock));
}

/* ---- M2: reuse exclusivity + L18 probe order ------------------------------ */

/* Fake agent that holds TWO identities: the account's own key AND a foreign
 * one (the contamination scenario: `SSH_AUTH_SOCK=current.sock ssh-add
 * ~/.ssh/personal_key` while `work` is active). */
static int fake_two_key_agent_runner(const char *const argv[], const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        const char *fp = strstr(argv[2], "keyB") ? FP_B : FP_A;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "256 %s work (ED25519)\n"
                     "256 %s personal (ED25519)\n", FP_A, FP_B);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1; /* end the test deterministically at the restart */
    }
    return 0;
}

TEST(reuse_refuses_contaminated_agent) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0); /* agent holds FP_A, not alone */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_two_key_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    /* Presence of the right key is NOT enough: a second identity means a
     * foreign key would ride along into the "isolated" session. The reuse
     * must be refused and a fresh single-key agent started. */
    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    /* ...whose (fake-injected) start failure fails the switch instead of
     * silently adopting the two-key agent. */
    CHECK_EQ_INT(rc, -1);
    /* The contaminated agent was reaped, not left adoptable. */
    CHECK(!path_exists(sock));
}

/* Single identity whose fingerprint merely CONTAINS ours as a prefix: a
 * substring match (strstr) would adopt it; a token compare must not. */
static int fake_prefix_token_agent_runner(const char *const argv[], const run_opts_t *opts,
                                          run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %sXY other (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }
    return 0;
}

TEST(reuse_requires_exact_fingerprint_token) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_prefix_token_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1); /* refused, restarted */
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(rc, -1);
}

/* Recording adoption runner: single matching identity (reuse succeeds), and
 * the first ssh-add/ssh-keygen exec is captured to pin the probe order. */
static int fake_recording_adopt_runner(const char *const argv[], const run_opts_t *opts,
                                       run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (!g_first_probe[0] &&
        (strcmp(argv[0], "ssh-add") == 0 || strcmp(argv[0], "ssh-keygen") == 0)) {
        snprintf(g_first_probe, sizeof(g_first_probe), "%s", argv[0]);
    }

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s agent-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }
    return 0;
}

static int g_live_validation_probe_attempts;
static int g_live_validation_fingerprint_attempts;

/* The reusable socket is live and reports one exact identity, but computing
 * the admitted key's fingerprint cannot even launch. The causal runner error
 * must survive, and a validation failure must not retire or replace the live
 * agent that was only being considered for adoption. */
static int fake_live_validation_launch_failure_runner(
    const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    if (result) memset(result, 0, sizeof(*result));
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-l") == 0) {
        g_live_validation_probe_attempts++;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "256 %s agent-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        if (result) {
            result->spawned = true;
            result->exit_code = 0;
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        g_live_validation_fingerprint_attempts++;
        if (result) result->exit_code = -1;
        set_error(ERR_SYSTEM_COMMAND_FAILED,
                  "causal live-agent fingerprint launch failure");
        return -1;
    }
    if (strcmp(ts_command_basename(argv[0]), "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) {
            result->spawned = true;
            result->exit_code = 1;
        }
        return -1;
    }
    if (result) {
        result->spawned = true;
        result->exit_code = 0;
    }
    return 0;
}

TEST(agent_probe_precedes_fingerprint_computation) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_first_probe[0] = '\0';
    prev = run_set_runner(fake_recording_adopt_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(cfg.key_already_loaded); /* single exact match: adopted */
    CHECK(cfg.reused_existing_agent);
    /* L18: the cheap liveness probe must come first — a stale socket (dead
     * agent, the common miss) must not cost an ssh-keygen fork+exec. */
    CHECK_STR_EQ(g_first_probe, "ssh-add");
}

TEST(live_agent_fingerprint_launch_failure_preserves_socket_and_diagnostic) {
    char dir[128], sock[256];
    struct stat before;
    struct stat after;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    CHECK_EQ_INT(lstat(sock, &before), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_live_validation_probe_attempts = 0;
    g_live_validation_fingerprint_attempts = 0;
    clear_error();
    prev = run_set_runner(fake_live_validation_launch_failure_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_live_validation_probe_attempts, 1);
    CHECK_EQ_INT(g_live_validation_fingerprint_attempts, 1);
    CHECK_EQ_INT(g_agent_start_attempts, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_COMMAND_FAILED);
    CHECK(strstr(get_last_error()->message,
                 "causal live-agent fingerprint launch failure") != NULL);
    CHECK_EQ_INT(lstat(sock, &after), 0);
    CHECK(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
}

/* ---- T3: reap_ssh_agent positive kill path (real agent, Linux-gated) ------ */

#if defined(__linux__)
static int capture_linux_socket_peer(
    const char *path, pid_t *peer_pid, uid_t *peer_uid) {
    struct sockaddr_un address;
    struct ucred credential;
    socklen_t credential_size = sizeof(credential);
    int fd;
    int rc = -1;

    if (!path || !peer_pid || !peer_uid ||
        strlen(path) >= sizeof(address.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (connect(fd, (struct sockaddr *)(void *)&address,
                sizeof(address)) == 0 &&
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential,
                   &credential_size) == 0 &&
        credential_size == sizeof(credential) &&
        credential.pid > 1) {
        *peer_pid = credential.pid;
        *peer_uid = credential.uid;
        rc = 0;
    }
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return rc;
}

static int saturate_unix_listener(
    const char *path, int *listener_out, int clients[], size_t client_capacity,
    size_t *client_count_out) {
    struct sockaddr_un address;
    int listener = -1;
    size_t client_count = 0;
    bool saturated = false;

    if (!path || !listener_out || !clients || client_capacity == 0 ||
        !client_count_out || strlen(path) >= sizeof(address.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 ||
        fcntl(listener, F_SETFD, FD_CLOEXEC) != 0 ||
        bind(listener, (struct sockaddr *)(void *)&address,
             sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 ||
        listen(listener, 0) != 0) {
        goto fail;
    }
    while (client_count < client_capacity) {
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        int flags;

        if (client < 0 ||
            fcntl(client, F_SETFD, FD_CLOEXEC) != 0 ||
            (flags = fcntl(client, F_GETFL, 0)) < 0 ||
            fcntl(client, F_SETFL, flags | O_NONBLOCK) != 0) {
            if (client >= 0) close(client);
            goto fail;
        }
        if (connect(client, (struct sockaddr *)(void *)&address,
                    sizeof(address)) == 0) {
            clients[client_count++] = client;
            continue;
        }
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
        ) {
            close(client);
            saturated = true;
            break;
        }
        close(client);
        goto fail;
    }
    if (!saturated) {
        errno = EBUSY;
        goto fail;
    }
    *listener_out = listener;
    *client_count_out = client_count;
    return 0;

fail:
    {
        int saved_errno = errno;
        for (size_t i = 0; i < client_count; i++) close(clients[i]);
        if (listener >= 0) close(listener);
        (void)unlink(path);
        errno = saved_errno;
    }
    return -1;
}

static int start_real_recorded_agent(const char *sock,
                                     ssh_agent_record_t *record) {
    char output[2048];
    char *pid_assignment;
    char trusted_path[MAX_PATH_LEN];
    run_opts_t opts;
    run_result_t result;
    const char *argv[] = {"ssh-agent", "-s", "-a", sock, NULL};

    if (!record ||
        find_command_path("ssh-agent", trusted_path,
                          sizeof(trusted_path)) != 0 ||
        stat(trusted_path, &g_l29_image.executable_identity) != 0 ||
        safe_strncpy(g_l29_image.executable_path, trusted_path,
                     sizeof(g_l29_image.executable_path)) != 0) {
        return -1;
    }
    g_l29_image.effective_uid = geteuid();
    g_l29_image.valid = true;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &result) != 0) return -1;
    pid_assignment = strstr(output, "SSH_AGENT_PID=");
    if (!pid_assignment) return -1;
    memset(record, 0, sizeof(*record));
    record->pid =
        (pid_t)atol(pid_assignment + strlen("SSH_AGENT_PID="));
    if (record->pid <= 1 ||
        ssh_manager_test_capture_process_generation(
            record->pid, &record->generation) != 0 ||
        capture_linux_socket_peer(
            sock, &g_l29_image.socket_peer_pid,
            &g_l29_image.socket_peer_uid) != 0) {
        if (record->pid > 1) (void)kill(record->pid, SIGKILL);
        return -1;
    }
    record->image = g_l29_image;
    return 0;
}

/* L29: generation plus an exact managed -a argument is still insufficient
 * signaling authority. Keep a genuine agent's argv/generation fixed while
 * independently corrupting its kernel image evidence, effective credential,
 * and evidence availability. Only the exact trusted native image may become
 * OWNED; every other case fails closed before reaping can signal it. */
TEST(process_identity_requires_trusted_image_and_effective_uid) {
    char dir[128], sock[256], pid_path[256];
    ssh_agent_record_t record;
    ssh_reap_test_ops_t ops;
    ssh_reap_test_ops_t previous;
    int dir_fd;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    memset(&record, 0, sizeof(record));
    CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
    if (record.pid <= 1) return;
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) {
        (void)kill(record.pid, SIGKILL);
        return;
    }
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     dir_fd, "ssh-agent.work.pid", &record), 0);
    CHECK_EQ_INT(close(dir_fd), 0);

    memset(&ops, 0, sizeof(ops));
    ops.image = l29_wrong_image;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));

    ops.image = l29_wrong_uid;
    (void)ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));

    ops.image = l29_inaccessible_image;
    (void)ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));

    ops.image = l29_exact_image;
    (void)ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(kill(record.pid, 0), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_test_ops(&previous);
    if (kill(record.pid, 0) == 0) (void)kill(record.pid, SIGKILL);
}

static void cleanup_l29_agent(const ssh_agent_record_t *record,
                              const char *socket_path,
                              const char *sidecar_path) {
    if (record && record->pid > 1 && kill(record->pid, 0) == 0) {
        (void)kill(record->pid, SIGKILL);
    }
    if (sidecar_path) (void)unlink(sidecar_path);
    if (socket_path) (void)unlink(socket_path);
}

/* OpenSSH's nondumpable daemon may deny /proc/PID/exe after launch. That
 * denial is not authority by itself: only the complete persisted launch
 * image, exact generation, argv, and kernel socket-peer tuple may use the
 * fallback. Exercise both expected denial errors and causal tuple failures. */
TEST(nondumpable_fallback_requires_complete_exact_tuple) {
    const int denied_errors[] = {EACCES, EPERM};

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    for (size_t i = 0;
         i < sizeof(denied_errors) / sizeof(denied_errors[0]); i++) {
        char dir[128], sock[256];
        ssh_agent_record_t record;
        ssh_reap_test_ops_t ops;
        ssh_reap_test_ops_t previous;
        int dir_fd;

        CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
        snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
        memset(&record, 0, sizeof(record));
        CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
        if (record.pid <= 1) continue;
        dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(dir_fd >= 0);
        if (dir_fd < 0) {
            cleanup_l29_agent(&record, sock, NULL);
            continue;
        }
        CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                         dir_fd, "ssh-agent.work.pid", &record), 0);
        CHECK_EQ_INT(close(dir_fd), 0);
        memset(&ops, 0, sizeof(ops));
        g_l29_denied_errno = denied_errors[i];
        ops.image = l29_denied_image;
        previous = ssh_manager_set_reap_test_ops(&ops);
        CHECK_EQ_INT(ssh_manager_reset("work"), 0);
        (void)ssh_manager_set_reap_test_ops(&previous);
        cleanup_l29_agent(&record, sock, NULL);
    }

    {
        char dir[128], sock[256], pid_path[256];
        ssh_agent_record_t record;
        ssh_reap_test_ops_t ops;
        ssh_reap_test_ops_t previous;
        int dir_fd;

        CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
        snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
        snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
        memset(&record, 0, sizeof(record));
        CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
        if (record.pid <= 1) return;
        record.image.socket_peer_pid =
            record.image.socket_peer_pid == INT_MAX
                ? record.image.socket_peer_pid - 1
                : record.image.socket_peer_pid + 1;
        dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(dir_fd >= 0);
        if (dir_fd < 0) {
            cleanup_l29_agent(&record, sock, pid_path);
            return;
        }
        CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                         dir_fd, "ssh-agent.work.pid", &record), 0);
        CHECK_EQ_INT(close(dir_fd), 0);
        memset(&ops, 0, sizeof(ops));
        g_l29_denied_errno = EACCES;
        ops.image = l29_denied_image;
        previous = ssh_manager_set_reap_test_ops(&ops);
        CHECK_EQ_INT(ssh_manager_reset("work"), -1);
        CHECK_EQ_INT(kill(record.pid, 0), 0);
        CHECK(path_exists(pid_path));
        (void)ssh_manager_set_reap_test_ops(&previous);
        cleanup_l29_agent(&record, sock, pid_path);
    }

    {
        char dir[128], sock[256], pid_path[256];
        ssh_agent_record_t record;
        ssh_reap_test_ops_t ops;
        ssh_reap_test_ops_t previous;
        int dir_fd;

        CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
        snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
        snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
        memset(&record, 0, sizeof(record));
        CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
        if (record.pid <= 1) return;
        dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(dir_fd >= 0);
        if (dir_fd < 0) {
            cleanup_l29_agent(&record, sock, pid_path);
            return;
        }
        CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                         dir_fd, "ssh-agent.work.pid", &record), 0);
        CHECK_EQ_INT(close(dir_fd), 0);
        g_l29_observed_generation = record.generation;
        g_l29_observed_generation.start_lo ^= UINT64_C(1);
        memset(&ops, 0, sizeof(ops));
        g_l29_denied_errno = EPERM;
        ops.generation = l29_wrong_generation;
        ops.image = l29_denied_image;
        previous = ssh_manager_set_reap_test_ops(&ops);
        CHECK_EQ_INT(ssh_manager_reset("work"), -1);
        CHECK_EQ_INT(kill(record.pid, 0), 0);
        CHECK(path_exists(pid_path));
        (void)ssh_manager_set_reap_test_ops(&previous);
        cleanup_l29_agent(&record, sock, pid_path);
    }
}

TEST(saturated_peer_backlog_fails_bounded_without_signaling) {
    char dir[128], sock[256], moved_sock[256], pid_path[256];
    ssh_agent_record_t record;
    struct stat saturated_before;
    struct stat saturated_after;
    struct timespec started;
    struct timespec finished;
    int clients[16];
    size_t client_count = 0;
    int listener = -1;
    int dir_fd;
    long elapsed_ms;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(moved_sock, sizeof(moved_sock), "%s/original.sock", dir);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    memset(&record, 0, sizeof(record));
    CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
    if (record.pid <= 1) return;
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) {
        cleanup_l29_agent(&record, sock, pid_path);
        return;
    }
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     dir_fd, "ssh-agent.work.pid", &record), 0);
    CHECK_EQ_INT(close(dir_fd), 0);
    CHECK_EQ_INT(rename(sock, moved_sock), 0);
    CHECK_EQ_INT(saturate_unix_listener(
                     sock, &listener, clients,
                     sizeof(clients) / sizeof(clients[0]),
                     &client_count), 0);
    if (listener < 0) {
        cleanup_l29_agent(&record, moved_sock, pid_path);
        return;
    }
    CHECK_EQ_INT(lstat(sock, &saturated_before), 0);
    CHECK_EQ_INT(clock_gettime(CLOCK_MONOTONIC, &started), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(clock_gettime(CLOCK_MONOTONIC, &finished), 0);
    elapsed_ms = (finished.tv_sec - started.tv_sec) * 1000 +
                 (finished.tv_nsec - started.tv_nsec) / 1000000;
    CHECK(elapsed_ms < 1000);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));
    CHECK_EQ_INT(lstat(sock, &saturated_after), 0);
    CHECK(saturated_before.st_dev == saturated_after.st_dev);
    CHECK(saturated_before.st_ino == saturated_after.st_ino);

    for (size_t i = 0; i < client_count; i++) close(clients[i]);
    close(listener);
    (void)unlink(sock);
    cleanup_l29_agent(&record, moved_sock, pid_path);
}

TEST(v2_record_rejects_unterminated_executable_path) {
    char dir[128], pid_path[256];
    ssh_agent_record_t record;
    int dir_fd;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    memset(&record, 0, sizeof(record));
    record.pid = getpid();
    CHECK_EQ_INT(ssh_manager_test_capture_process_generation(
                     record.pid, &record.generation), 0);
    record.image.valid = true;
    record.image.effective_uid = geteuid();
    record.image.socket_peer_pid = getpid();
    record.image.socket_peer_uid = geteuid();
    record.image.executable_identity.st_mode = S_IFREG | 0755;
    record.image.executable_identity.st_dev = 1;
    record.image.executable_identity.st_ino = 1;
    memset(record.image.executable_path, 'x',
           sizeof(record.image.executable_path));
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     dir_fd, "ssh-agent.work.pid", &record), -1);
    CHECK_EQ_INT(close(dir_fd), 0);
    CHECK(!path_exists(pid_path));
}

TEST(v2_record_rejects_fully_shaped_numeric_overflow) {
    char dir[128], sock[256], pid_path[256], text[1024];
    ssh_agent_record_t record;
    size_t executable_size;
    int written;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    memset(&record, 0, sizeof(record));
    CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
    if (record.pid <= 1) return;
    executable_size = strlen(record.image.executable_path);

    written = snprintf(
        text, sizeof(text),
        "v2 184467440737095516160 %" PRIu64
        " %016" PRIx64 "%016" PRIx64
        " %016" PRIx64 "%016" PRIx64
        " %ju %ju %ju %jx %jx %zu\n%s\n",
        record.generation.kind,
        record.generation.boot_hi, record.generation.boot_lo,
        record.generation.start_hi, record.generation.start_lo,
        (uintmax_t)record.image.effective_uid,
        (uintmax_t)record.image.socket_peer_pid,
        (uintmax_t)record.image.socket_peer_uid,
        (uintmax_t)record.image.executable_identity.st_dev,
        (uintmax_t)record.image.executable_identity.st_ino,
        executable_size, record.image.executable_path);
    CHECK(written > 0 && (size_t)written < sizeof(text));
    if (written <= 0 || (size_t)written >= sizeof(text)) {
        cleanup_l29_agent(&record, sock, pid_path);
        return;
    }
    CHECK_EQ_INT(write_string_to_file(pid_path, text, 0600), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));

    written = snprintf(
        text, sizeof(text),
        "v2 %ld %" PRIu64
        " %016" PRIx64 "%016" PRIx64
        " %016" PRIx64 "%016" PRIx64
        " %ju %ju %ju 10000000000000000 %jx %zu\n%s\n",
        (long)record.pid, record.generation.kind,
        record.generation.boot_hi, record.generation.boot_lo,
        record.generation.start_hi, record.generation.start_lo,
        (uintmax_t)record.image.effective_uid,
        (uintmax_t)record.image.socket_peer_pid,
        (uintmax_t)record.image.socket_peer_uid,
        (uintmax_t)record.image.executable_identity.st_ino,
        executable_size, record.image.executable_path);
    CHECK(written > 0 && (size_t)written < sizeof(text));
    if (written > 0 && (size_t)written < sizeof(text)) {
        CHECK_EQ_INT(write_string_to_file(pid_path, text, 0600), 0);
        CHECK_EQ_INT(ssh_manager_reset("work"), -1);
        CHECK_EQ_INT(kill(record.pid, 0), 0);
        CHECK(path_exists(pid_path));
    }
    cleanup_l29_agent(&record, sock, pid_path);
}

/* A pre-L29 v1 sidecar lacks launch-image and socket-peer provenance. Even
 * when its PID, generation, argv, and socket all describe a genuine agent,
 * it is migration data rather than signaling authority and must be retained
 * for an explicit retry/cleanup decision. */
TEST(legacy_v1_record_never_authorizes_signaling) {
    char dir[128], sock[256], pid_path[256], record_text[192];
    ssh_agent_record_t record;
    int record_size;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    memset(&record, 0, sizeof(record));
    CHECK_EQ_INT(start_real_recorded_agent(sock, &record), 0);
    if (record.pid <= 1) return;
    record_size = snprintf(
        record_text, sizeof(record_text),
        "v1 %ld %" PRIu64 " %016" PRIx64 "%016" PRIx64
        " %016" PRIx64 "%016" PRIx64 "\n",
        (long)record.pid, record.generation.kind,
        record.generation.boot_hi, record.generation.boot_lo,
        record.generation.start_hi, record.generation.start_lo);
    CHECK(record_size > 0 && (size_t)record_size < sizeof(record_text));
    if (record_size <= 0 || (size_t)record_size >= sizeof(record_text)) {
        (void)kill(record.pid, SIGKILL);
        return;
    }
    CHECK_EQ_INT(write_string_to_file(pid_path, record_text, 0600), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    CHECK_EQ_INT(kill(record.pid, 0), 0);
    CHECK(path_exists(pid_path));
    CHECK(path_exists(sock));

    (void)kill(record.pid, SIGKILL);
    (void)unlink(pid_path);
    (void)unlink(sock);
}

/* Every prior test approaches reap_ssh_agent from the refusal side (bystander
 * PID, above-pid_max PID, no sidecar). This drives the positive path end to
 * end: real ssh-agent, real sidecar, ssh_manager_reset — the agent must be
 * verified (comm + socket argv via /proc, hence Linux-gated), signaled, and
 * confirmed dead, with sidecar and socket removed. An always-refuse
 * regression in pid_is_our_ssh_agent fails this test instead of shipping
 * green while leaking live key-holding agents. */
TEST(reset_reaps_real_recorded_agent) {
    char dir[128], sock[256], pidp[256], out[2048];
    run_opts_t opts;
    run_result_t res;
    struct timespec t0, t1;
    long ms;
    char *p;
    pid_t pid;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(pidp, sizeof(pidp), "%s/ssh-agent.work.pid", dir);

    const char *argv[] = { "ssh-agent", "-s", "-a", sock, NULL };
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);

    p = strstr(out, "SSH_AGENT_PID=");
    CHECK(p != NULL);
    if (!p) return;
    pid = (pid_t)atol(p + strlen("SSH_AGENT_PID="));
    CHECK(pid > 1);
    CHECK_EQ_INT(kill(pid, 0), 0); /* the daemonized agent is alive */

    CHECK_EQ_INT(write_live_agent_record(
                     dir, "ssh-agent.work.pid", pid),
                 0);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    /* L19 evidence (informational, not asserted: timing thresholds flake
     * under CI load): the fixed 50ms post-SIGTERM poll used to floor this. */
    fprintf(stderr, "  (info: real-agent reap took %ld ms)\n", ms);

    /* A readable pidfd proves process exit before the parent namespace has
     * necessarily reaped the zombie, so kill(pid, 0) can briefly succeed even
     * though reset already has conclusive instance-level death evidence. */
    for (int attempts = 0; attempts < 100 && kill(pid, 0) == 0; attempts++) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
        nanosleep(&delay, NULL);
    }
    errno = 0;
    CHECK(kill(pid, 0) != 0);       /* reaped: ESRCH, not just signaled */
    CHECK_EQ_INT(errno, ESRCH);
    CHECK(!path_exists(pidp));      /* sidecar dropped once confirmed gone */
    CHECK(!path_exists(sock));

    if (kill(pid, 0) == 0) {
        kill(pid, SIGKILL); /* never leak a real agent on test failure */
    }
}
#endif

/* ---- L6: /tmp socket base hardening --------------------------------------- */

/* AR-17 test integrity: production image capture had ZERO real-path coverage.
 * Every test that reached it replaced `.image` with a stub, and the one test
 * that ran it for real discarded the result through a stubbed reap. That is
 * exactly how AR-16 shipped a Linux legacy migration that could never succeed:
 * the Linux branch never populated `executable_path`, which the identity gate
 * requires to be absolute. This drives the real function against a real,
 * dumpable process (ourselves) on every platform, so the Linux, Darwin and
 * FreeBSD branches all get exercised by CI instead of none of them. */
TEST(process_image_capture_populates_absolute_path_for_self) {
    ssh_process_image_t image;

    memset(&image, 0xA5, sizeof(image));
    CHECK_EQ_INT(ssh_manager_test_capture_process_image(getpid(), &image), 0);
    CHECK(image.valid);
    CHECK_EQ_INT((long)image.effective_uid, (long)geteuid());
    /* The gate in inspect_pid_ssh_agent_image rejects anything whose path is
     * not absolute, so an empty path here is a silent identity failure. */
    CHECK(image.executable_path[0] == '/');
    CHECK(image.executable_identity.st_ino != 0);
    CHECK(S_ISREG(image.executable_identity.st_mode));
    /* Capture is live inspection, never a durable launch witness, so it must
     * not claim the in-process nondumpable marker. */
    CHECK(!image.executable_object_unknown);
}

/* Invalid targets must fail closed rather than report a usable image. */
TEST(process_image_capture_rejects_invalid_target) {
    ssh_process_image_t image;

    memset(&image, 0, sizeof(image));
    CHECK_EQ_INT(ssh_manager_test_capture_process_image(0, &image), -1);
    CHECK_EQ_INT(ssh_manager_test_capture_process_image(1, &image), -1);
    CHECK_EQ_INT(ssh_manager_test_capture_process_image(getpid(), NULL), -1);
}

TEST(reset_refuses_unsafe_socket_dir) {
    char dir[192], real[192], pidfile[256];
    FILE *pf;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswar03XXXXXX");
    CHECK(ts_mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    /* A planted symlink base: everything reachable through it must stay
     * untouched, mirroring gpg_manager_reset's refusal. */
    snprintf(real, sizeof(real), "%s/realbase", g_xdg);
    CHECK_EQ_INT(mkdir(real, 0700), 0);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", real);
    pf = fopen(pidfile, "w");
    CHECK(pf != NULL);
    if (pf) {
        fprintf(pf, "0\n");
        fclose(pf);
    }
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    CHECK_EQ_INT(symlink(real, dir), 0);

    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK(path_exists(pidfile)); /* nothing reaped/unlinked through the link */

    /* A group-accessible base is just as disqualifying (predictable name in
     * sticky /tmp when XDG_RUNTIME_DIR is unset). */
    CHECK_EQ_INT(unlink(dir), 0);
    CHECK_EQ_INT(mkdir(dir, 0700), 0);
    CHECK_EQ_INT(chmod(dir, 0770), 0);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);

    /* Control: the genuine private dir proceeds. */
    CHECK_EQ_INT(chmod(dir, 0700), 0);
    CHECK_EQ_INT(ssh_manager_reset(NULL), 0);
}

/* ---- T5 / L16: host-alias config round-trip ------------------------------- */

#define USER_STANZA_ABOVE \
    "Host personal\n  User alice\n  IdentityFile ~/.ssh/personal\n"
#define USER_STANZA_BELOW \
    "Host other.example.com\n  User bob\n  Port 2222\n"
#define ALIAS "github.com-work"
#define BEGIN_MARK "# >>> gitswitch " ALIAS " >>>"
#define END_MARK   "# <<< gitswitch " ALIAS " <<<"

/* Scratch HOME with ~/.ssh/config pre-seeded to `content`. */
static int setup_home_with_ssh_config(char *home, size_t home_size,
                                      const char *content) {
    char sshdir[256], cfgp[320];
    FILE *f;

    snprintf(home, home_size, "/tmp/gswar03hXXXXXX");
    if (!ts_mkdtemp(home)) return -1;
    setenv("HOME", home, 1);
    snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
    if (mkdir(sshdir, 0700) != 0) return -1;
    if (!content) return 0;
    snprintf(cfgp, sizeof(cfgp), "%s/config", sshdir);
    f = fopen(cfgp, "w");
    if (!f) return -1;
    fputs(content, f);
    return fclose(f) == 0 ? 0 : -1;
}

/* Splice/preserve: user stanzas above AND below an existing managed block
 * must survive byte-for-byte, and repeated calls must leave exactly one
 * managed block (no duplication, no drift). */
TEST(host_alias_preserves_user_stanzas_around_managed_block) {
    char home[128], cfgp[256], buf[8192];
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home),
        USER_STANZA_ABOVE
        BEGIN_MARK "\n"
        "Host " ALIAS "\n"
        "  IdentityFile /stale/key\n"
        "  IdentitiesOnly yes\n"
        END_MARK "\n"
        USER_STANZA_BELOW), 0);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_hostname, sizeof(acct.ssh_hostname), "github.com");
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0); /* idempotent re-run */

    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);

    CHECK(strstr(buf, USER_STANZA_ABOVE) != NULL); /* byte-for-byte survival */
    CHECK(strstr(buf, USER_STANZA_BELOW) != NULL);
    CHECK_EQ_INT(count_substr(buf, BEGIN_MARK), 1); /* exactly one block */
    CHECK_EQ_INT(count_substr(buf, END_MARK), 1);
    CHECK(strstr(buf, "/stale/key") == NULL);       /* old block spliced out */
    CHECK(strstr(buf, "key1") != NULL);
}

/* AR-07 M12: an exact but malformed managed block is ambiguous. Preserve the
 * complete file and fail rather than guessing which user bytes are ours. */
TEST(host_alias_malformed_block_fails_without_rewrite) {
    char home[128], cfgp[256], buf[8192];
    const char *original =
        USER_STANZA_ABOVE
        BEGIN_MARK "\n"
        "Host " ALIAS "\n"
        "  IdentityFile /stale/key\n"
        "  IdentitiesOnly yes\n"
        USER_STANZA_BELOW;
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home),
                                            original), 0);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_hostname, sizeof(acct.ssh_hostname), "github.com");
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), -1);

    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, original);
}

/* L16: a byte-identical result must not be rewritten — mkstemp+rename churns
 * the inode (breaking hard links, waking dotfile sync) on every switch. */
TEST(host_alias_skips_rewrite_when_content_identical) {
    char home[128], cfgp[256], buf[8192];
    struct stat st1, st2, st3;
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home), NULL), 0);
    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_hostname, sizeof(acct.ssh_hostname), "github.com");
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(stat(cfgp, &st1), 0);

    /* Same account, same content: the file must not be replaced. */
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(stat(cfgp, &st2), 0);
    CHECK(st1.st_ino == st2.st_ino);

    /* Control: a real change still rewrites atomically. */
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key2", home);
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(stat(cfgp, &st3), 0);
    CHECK(st2.st_ino != st3.st_ino);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);
    CHECK(strstr(buf, "key2") != NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(ssh_manager_reset_rejects_empty_selector);
    RUN_TEST(agent_spawn_pins_bourne_format_and_reaps_on_parse_failure);
    RUN_TEST(socket_validation_failure_reaps_spawned_agent);
    RUN_TEST(reuse_refuses_contaminated_agent);
    RUN_TEST(reuse_requires_exact_fingerprint_token);
    RUN_TEST(agent_probe_precedes_fingerprint_computation);
    RUN_TEST(
        live_agent_fingerprint_launch_failure_preserves_socket_and_diagnostic);
#if defined(__linux__)
    RUN_TEST(process_identity_requires_trusted_image_and_effective_uid);
    RUN_TEST(nondumpable_fallback_requires_complete_exact_tuple);
    RUN_TEST(saturated_peer_backlog_fails_bounded_without_signaling);
    RUN_TEST(v2_record_rejects_unterminated_executable_path);
    RUN_TEST(v2_record_rejects_fully_shaped_numeric_overflow);
    RUN_TEST(legacy_v1_record_never_authorizes_signaling);
    RUN_TEST(reset_reaps_real_recorded_agent);
#endif
    RUN_TEST(process_image_capture_populates_absolute_path_for_self);
    RUN_TEST(process_image_capture_rejects_invalid_target);
    RUN_TEST(reset_refuses_unsafe_socket_dir);
    RUN_TEST(host_alias_preserves_user_stanzas_around_managed_block);
    RUN_TEST(host_alias_malformed_block_fails_without_rewrite);
    RUN_TEST(host_alias_skips_rewrite_when_content_identical);
TEST_MAIN_END()
