/* Tests for the SSH agent reuse fast path in ssh_start_isolated_agent:
 * a live per-account agent is adopted ONLY when it already holds the exact
 * key the account is configured with (ssh_key_fingerprint/ssh_socket_has_key
 * match by fingerprint). Reusing on socket liveness alone would keep serving
 * a stale key after `gitswitch edit` changed the account's key path — the
 * wrong identity would keep authenticating silently.
 *
 * ssh-keygen/ssh-add invocations are intercepted with deterministic answers.
 * Reuse fixtures use a real 0600 socket inode under a private
 * XDG_RUNTIME_DIR; fresh-start fixtures launch a real protocol-capable
 * ssh-agent so Darwin's credential binding is exercised truthfully. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp, sockets) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "runner_internal.h"
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
static bool g_agent_lists_certificate;
static const char *g_pid_link_to_plant;
static const char *g_pid_link_target;
static bool g_replace_dir_on_key_probe;
static bool g_replace_dir_on_agent_start;
static bool g_key_load_used_pinned_socket;
static char g_moved_agent_dir[256];
static char g_xdg[64]; /* short: the socket path must fit sun_path (~108) */
static bool g_generation_runner_mode;
static bool g_swap_key_after_fingerprint;
static int g_generation_loads;
static const char *g_generation_loaded_fp;
static char g_generation_key_path[MAX_PATH_LEN];
static char g_generation_replacement[MAX_PATH_LEN];
static bool g_keygen_used_admitted_bytes;

static bool is_ssh_agent_command(const char *path) {
    const char *base;

    if (!path || !*path) return false;
    base = strrchr(path, '/');
    return strcmp(base ? base + 1 : path, "ssh-agent") == 0;
}

static int certify_agent_launch(const char *path, run_result_t *result) {
    if (!path || !result ||
        !run_launch_witness_capture(path, &result->launch_witness)) {
        return -1;
    }
    return 0;
}

static const char *runner_generation_fingerprint(
    const char *const argv[], const run_opts_t *opts) {
    char data[256];
    size_t length = 0;

    memset(data, 0, sizeof(data));
    if (opts && opts->input && opts->input_len > 0) {
        length = opts->input_len < sizeof(data) - 1
                     ? opts->input_len
                     : sizeof(data) - 1;
        memcpy(data, opts->input, length);
    } else if (opts && opts->use_stdin_fd && opts->stdin_fd >= 0) {
        ssize_t n = pread(opts->stdin_fd, data, sizeof(data) - 1, 0);
        if (n > 0) length = (size_t)n;
    } else if (opts && opts->use_cwd_fd && opts->cwd_fd >= 0 && argv &&
               argv[2]) {
        int fd = openat(opts->cwd_fd, argv[2],
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            ssize_t n;
            do {
                n = read(fd, data, sizeof(data) - 1);
            } while (n < 0 && errno == EINTR);
            if (n > 0) length = (size_t)n;
            close(fd);
        }
    } else if (argv && argv[2]) {
        FILE *stream = fopen(argv[2], "r");
        if (stream) {
            length = fread(data, 1, sizeof(data) - 1, stream);
            fclose(stream);
        }
    }
    data[length] = '\0';
    if (strstr(data, "generation-b")) return FP_B;
    if (strstr(data, "generation-a")) return FP_A;
    return argv && argv[2] && strstr(argv[2], "keyB") ? FP_B : FP_A;
}

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

static int fail_namespace_commit(int dir_fd) {
    (void)dir_fd;
    errno = EIO;
    return -1;
}

static ssh_process_outcome_t refuse_agent_reap(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_OWNED;
}

static int g_classify_agent_gone_calls;

static ssh_process_outcome_t classify_agent_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_classify_agent_gone_calls++;
    return SSH_PROCESS_GONE;
}

#if defined(__FreeBSD__)
static char g_pid_ctime_successor_path[256];
static bool g_pid_ctime_successor_injected;
static char g_config_ctime_successor_path[256];
static bool g_config_ctime_successor_injected;

static ssh_process_outcome_t classify_agent_gone_after_pid_ctime_successor(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    struct stat before;
    struct stat after;
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 2000000 };
    struct timespec remaining;

    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    if (stat(g_pid_ctime_successor_path, &before) != 0) {
        return SSH_PROCESS_INDETERMINATE;
    }
    while (nanosleep(&delay, &remaining) != 0) {
        if (errno != EINTR) return SSH_PROCESS_INDETERMINATE;
        delay = remaining;
    }
    if (chmod(g_pid_ctime_successor_path, 0600) != 0 ||
        stat(g_pid_ctime_successor_path, &after) != 0) {
        return SSH_PROCESS_INDETERMINATE;
    }
    g_pid_ctime_successor_injected =
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec;
    return g_pid_ctime_successor_injected
               ? SSH_PROCESS_GONE
               : SSH_PROCESS_INDETERMINATE;
}

static int sync_config_dir_before_ctime_successor(int dir_fd) {
    struct stat before;
    struct stat after;
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 2000000 };
    struct timespec remaining;

    if (fsync(dir_fd) != 0 ||
        stat(g_config_ctime_successor_path, &before) != 0) {
        return -1;
    }
    while (nanosleep(&delay, &remaining) != 0) {
        if (errno != EINTR) return -1;
        delay = remaining;
    }
    if (chmod(g_config_ctime_successor_path, 0600) != 0 ||
        stat(g_config_ctime_successor_path, &after) != 0) {
        return -1;
    }
    g_config_ctime_successor_injected =
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec;
    if (!g_config_ctime_successor_injected) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}
#endif

static ssh_agent_record_t synthetic_agent_record(pid_t pid, uint64_t nonce) {
    run_launch_witness_t witness;
    char agent_path[MAX_PATH_LEN];
    ssh_agent_record_t record = {
        .pid = pid,
        .generation = {
            .kind = SSH_PROCESS_GENERATION_LINUX,
            .boot_hi = UINT64_C(0x0102030405060708),
            .boot_lo = UINT64_C(0x1112131415161718),
            .start_hi = UINT64_C(0x2122232425262728),
            .start_lo = nonce,
        },
    };

    memset(&witness, 0, sizeof(witness));
    if (find_command_path("ssh-agent", agent_path,
                          sizeof(agent_path)) == 0 &&
        run_launch_witness_capture(agent_path, &witness) &&
        witness.valid && !witness.is_script &&
        safe_strncpy(record.image.executable_path,
                     witness.executable_path,
                     sizeof(record.image.executable_path)) == 0) {
        record.image.valid = true;
        record.image.executable_identity = witness.executable_identity;
        record.image.effective_uid = geteuid();
        record.image.socket_peer_pid = pid;
        record.image.socket_peer_uid = geteuid();
    }
    return record;
}

static int write_agent_sidecar(const char *account,
                               const ssh_agent_record_t *record) {
    char dir[256];
    char name[128];
    int dir_fd;
    int rc;

    if (!account || !record ||
        safe_snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg) != 0 ||
        safe_snprintf(name, sizeof(name), "ssh-agent.%s.pid", account) != 0) {
        return -1;
    }
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return -1;
    rc = ssh_manager_test_write_pid_sidecar(dir_fd, name, record);
    if (close(dir_fd) != 0) rc = -1;
    return rc;
}

static int g_stop_dirsync_calls;
static int g_stop_dirsync_fail_call;
static int g_clear_agent_keys_calls;
static int g_clear_agent_keys_runner_rc;
static int g_clear_agent_keys_exit_code;
static bool g_clear_agent_keys_exact_argv;
static bool g_clear_agent_keys_saw_socket;

static int stop_counting_dirsync(int dir_fd) {
    (void)dir_fd;
    g_stop_dirsync_calls++;
    if (g_stop_dirsync_fail_call > 0 &&
        g_stop_dirsync_calls == g_stop_dirsync_fail_call) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int clear_agent_keys_runner(const char *const argv[],
                                   const run_opts_t *opts,
                                   run_result_t *result) {
    const char *auth_sock = getenv("SSH_AUTH_SOCK");
    bool fail;

    if (result) memset(result, 0, sizeof(*result));
    g_clear_agent_keys_calls++;
    g_clear_agent_keys_exact_argv = g_clear_agent_keys_exact_argv && argv &&
        argv[0] && strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-D") == 0 && argv[2] == NULL;
    g_clear_agent_keys_saw_socket = g_clear_agent_keys_saw_socket && auth_sock &&
        strcmp(auth_sock, "/tmp/l38-agent.sock") == 0;

    fail = g_clear_agent_keys_runner_rc != 0;
    if (opts && opts->out && opts->out_size > 0) {
        int written = snprintf(opts->out, opts->out_size, "%s",
                               fail ? "synthetic clear failure" : "");
        if (result && written >= 0) {
            result->out_len = (size_t)written < opts->out_size
                                  ? (size_t)written
                                  : opts->out_size - 1;
        }
    }
    if (result) {
        result->spawned = true;
        result->exit_code = g_clear_agent_keys_exit_code;
        result->term_signal = 0;
    }
    if (g_clear_agent_keys_runner_rc != 0 &&
        g_clear_agent_keys_exit_code == 0) {
        errno = EIO;
        set_system_error(ERR_SYSTEM_CALL,
                         "synthetic runner cleanup failure");
    }
    return g_clear_agent_keys_runner_rc;
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
        const char *fp = runner_generation_fingerprint(argv, opts);
        g_keygen_used_admitted_bytes =
            opts && ((opts->use_stdin_fd && opts->stdin_fd >= 0) ||
                     (opts->use_cwd_fd &&
                      strstr(argv[2], ".key-fingerprint.") != NULL));
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-add -l (against the socket in opts->extra_env): agent holds keyA.
     * The certificate mode exposes the OpenSSH substitution case: a raw key
     * and its certificate intentionally share one fingerprint. */
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (g_replace_dir_on_key_probe) {
            g_replace_dir_on_key_probe = false;
            if (replace_agent_dir_namespace() != 0) return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s agent-key (%s)\n",
                     FP_A,
                     g_agent_lists_certificate ? "ED25519-CERT" : "ED25519");
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-agent: reaching this means reuse was refused. Fail the start so the
     * test ends here deterministically. */
    if (is_ssh_agent_command(argv[0])) {
        g_agent_start_attempts++;
        if (certify_agent_launch(argv[0], result) != 0) return -1;
        if (result) result->exit_code = 1;
        return -1;
    }

    return 0;
}

static int make_xdg_runtime_dir(void) {
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    if (!ts_mkdtemp(g_xdg)) return -1;
    if (ts_canonicalize_dir_path(g_xdg, sizeof(g_xdg)) != 0) return -1;
    return chmod(g_xdg, 0700);
}

/* Scratch runtime dir + a real 0600 unix socket standing in for the agent.
 * Returns 0 on success; sock_out receives the per-account socket path. */
static int setup_agent_socket(const char *account, char *sock_out, size_t size) {
    char dir[128];
    struct sockaddr_un addr;
    int fd;

    if (make_xdg_runtime_dir() != 0) return -1;
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
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "99999", 1), 0);

    g_agent_start_attempts = 0;
    g_keygen_used_admitted_bytes = false;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(cfg.key_already_loaded);       /* caller skips ssh_add_key */
    CHECK(cfg.reused_existing_agent);    /* caller skips the network probe */
    CHECK(!cfg.agent_owned);             /* no verified PID => never claim ownership */
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(getenv("SSH_AGENT_PID") == NULL);
    CHECK_EQ_INT(g_agent_start_attempts, 0); /* no restart, no re-prompt */
    CHECK(g_keygen_used_admitted_bytes);
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(path_exists(sock));            /* the live agent was not reaped */

    /* This is a successful no-op, not a successful stop: an adopted agent is
     * still live and still holds the exact key we just proved. */
    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
    CHECK(cfg.key_already_loaded);
    CHECK(path_exists(sock));

    /* current.sock points at the adopted agent's socket. */
    snprintf(cur, sizeof(cur), "%s/gitswitch-ssh/current.sock", g_xdg);
    CHECK_EQ_INT(lstat(cur, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(precleanup_activation_failure_preserves_prior_key_truth) {
    ssh_config_t cfg;
    account_t acct;

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(acct.name, 'a', 160);
    acct.name[160] = '\0';

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    cfg.key_already_loaded = true;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path,
                              "/tmp/prior-agent.sock",
                              sizeof(cfg.agent_socket_path)), 0);

    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(strstr(get_last_error()->message, "socket") != NULL);
    CHECK(cfg.key_already_loaded);
    CHECK_STR_EQ(cfg.agent_socket_path, "/tmp/prior-agent.sock");

    CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    ts_rm_rf(g_xdg);
}

TEST(reuse_failure_preserves_only_reproven_target_key_truth) {
    for (int prior_is_target = 0; prior_is_target <= 1; prior_is_target++) {
        char sock[256];
        ssh_config_t cfg;
        account_t acct;
        command_runner_fn previous_runner;
        ssh_namespace_commit_hook_fn previous_hook;

        CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
        CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
        memset(&cfg, 0, sizeof(cfg));
        cfg.mode = SSH_AGENT_ISOLATED;
        cfg.agent_pid = -1;
        cfg.key_already_loaded = true;
        CHECK_EQ_INT(safe_strncpy(
                         cfg.agent_socket_path,
                         prior_is_target ? sock : "/tmp/prior-agent.sock",
                         sizeof(cfg.agent_socket_path)), 0);

        g_agent_start_attempts = 0;
        previous_hook = ssh_manager_set_namespace_commit_hook_fn(
            fail_namespace_commit);
        previous_runner = run_set_runner(fake_ssh_runner);
        CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), -1);
        run_set_runner(previous_runner);
        ssh_manager_set_namespace_commit_hook_fn(previous_hook);

        CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
        CHECK_EQ_INT(g_agent_start_attempts, 0);
        CHECK_EQ_INT(cfg.key_already_loaded, prior_is_target);
        CHECK(path_exists(sock));

        CHECK_EQ_INT(unsetenv("SSH_AUTH_SOCK"), 0);
        (void)unsetenv("SSH_AGENT_PID");
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
        ts_rm_rf(g_xdg);
    }
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
    CHECK_EQ_INT(make_account(&acct, "keyB"), 0);
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
    CHECK(!cfg.reused_existing_agent);
    /* ...whose (fake-injected) failure fails the switch instead of silently
     * keeping the wrong key active. */
    CHECK_EQ_INT(rc, -1);
    /* The stale wrong-key agent socket was reaped, not left adoptable. */
    CHECK(!path_exists(sock));
}

/* A certificate and its underlying public key deliberately have the same
 * fingerprint. Fingerprint equality alone therefore cannot prove that the
 * configured raw identity is loaded: a certificate-only agent must be
 * refused and replaced just like an agent holding a different key. */
TEST(ssh_fingerprint_reuse_rejects_same_fingerprint_certificate) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_agent_lists_certificate = true;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);
    g_agent_lists_certificate = false;

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    CHECK(!cfg.reused_existing_agent);
    CHECK_EQ_INT(rc, -1);
    CHECK(!path_exists(sock));
}

/* T1 (AR-01-T1): a quoted SSH_AUTH_SOCK="..." assignment from ssh-agent
 * must not leak quotes into the descriptor-derived public socket path. */

/* Runner variant whose ssh-agent SUCCEEDS: use the real daemon so Darwin's
 * protocol-qualified peer inspection exercises the same boundary as
 * production, while retaining deterministic fake ssh-add/ssh-keygen answers
 * and the namespace-race hooks below. Rewrite only the successful daemon's
 * output to the quoted form this parser regression is meant to cover. */
static int fake_quoting_agent_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    if (is_ssh_agent_command(argv[0])) {
        const char *sock = NULL;
        const char *pid_text;
        char *pid_end = NULL;
        long agent_pid;
        int written;
        int rc;

        /* Find "-a <path>" wherever it sits: the AR-03 H1 fix passes an
         * explicit -s ahead of it, so the socket is no longer argv[2]. */
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
        rc = run_argv_real(argv, opts, result);
        if (rc != 0 || !result || !opts || !opts->out ||
            result->out_truncated) {
            return rc != 0 ? rc : -1;
        }
        pid_text = strstr(opts->out, "SSH_AGENT_PID=");
        if (!pid_text) return -1;
        pid_text += strlen("SSH_AGENT_PID=");
        errno = 0;
        agent_pid = strtol(pid_text, &pid_end, 10);
        if (errno != 0 || pid_end == pid_text || agent_pid <= 1 ||
            (long)(pid_t)agent_pid != agent_pid) {
            return -1;
        }
        written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=\"%s\"; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld; export SSH_AGENT_PID;\n"
            "echo Agent pid %ld;\n",
            sock, agent_pid, agent_pid);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        result->out_len = (size_t)written;
        if (g_pid_link_to_plant && g_pid_link_target &&
            symlink(g_pid_link_target, g_pid_link_to_plant) != 0) {
            return -1;
        }
        return 0;
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s agent-key (ED25519)\n",
                     g_generation_runner_mode && g_generation_loaded_fp
                         ? g_generation_loaded_fp
                         : FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        const char *fp = g_generation_runner_mode
                             ? runner_generation_fingerprint(argv, opts)
                             : FP_A;
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        if (g_generation_runner_mode && g_swap_key_after_fingerprint) {
            g_swap_key_after_fingerprint = false;
            if (rename(g_generation_replacement,
                       g_generation_key_path) != 0) {
                return -1;
            }
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1]) {
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
        if (g_generation_runner_mode) {
            g_generation_loaded_fp = runner_generation_fingerprint(argv, opts);
            g_generation_loads++;
        }
        return g_key_load_used_pinned_socket ? 0 : -1;
    }
    /* No reusable socket exists in this test, so ssh-keygen/ssh-add answers
     * are irrelevant; succeed quietly. */
    return 0;
}

TEST(agent_output_quoted_auth_sock_preserves_pinned_path) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    /* Runtime dir only — deliberately NO pre-existing per-account socket, so
     * the reuse fast path is skipped and a fresh agent is "started". */
    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    snprintf(sock, sizeof(sock), "%s/gitswitch-ssh/ssh-agent.work.sock", g_xdg);

    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    /* A new activation owns this outcome. Prove it actively clears a stale
     * marker retained in a caller-reused configuration object. */
    cfg.reused_existing_agent = true;

    prev = run_set_runner(fake_quoting_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(strchr(cfg.agent_socket_path, '"') == NULL); /* quotes stripped */
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(g_key_load_used_pinned_socket);
    CHECK(!cfg.reused_existing_agent);
    CHECK_EQ_INT(ssh_manager_cleanup(&cfg), 0);
}

/* A stale agent forces a fingerprint-before-fresh-load sequence inside the
 * low-level activation entry point. Replacing the configured name immediately
 * after that fingerprint must not redirect the later ssh-add: both operations
 * consume generation A captured by that activation, while the public pathname
 * now names generation B. The complete public/account switch performs an
 * additional pre-mutation namespace proof, covered by the M22 admission
 * regressions, and therefore rejects an earlier replacement instead. */
TEST(isolated_activation_retains_generation_between_fingerprint_and_load) {
    static const char generation_a[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "generation-a\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    static const char generation_b[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "generation-b\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn previous;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
    CHECK_EQ_INT(write_string_to_file(acct.ssh_key_path, generation_a, 0600),
                 0);
    CHECK_EQ_INT(safe_strncpy(g_generation_key_path, acct.ssh_key_path,
                              sizeof(g_generation_key_path)), 0);
    CHECK_EQ_INT(safe_snprintf(g_generation_replacement,
                               sizeof(g_generation_replacement),
                               "%s.replacement", acct.ssh_key_path), 0);
    CHECK_EQ_INT(write_string_to_file(g_generation_replacement,
                                      generation_b, 0600), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_generation_runner_mode = true;
    g_generation_loaded_fp = FP_B; /* stale agent: refuse reuse */
    g_generation_loads = 0;
    g_swap_key_after_fingerprint = true;
    previous = run_set_runner(fake_quoting_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &acct), 0);
    run_set_runner(previous);

    CHECK(!g_swap_key_after_fingerprint);
    CHECK_EQ_INT(g_generation_loads, 1);
    CHECK_STR_EQ(g_generation_loaded_fp, FP_A);
    g_generation_runner_mode = false;
    g_generation_loaded_fp = NULL;
    CHECK_EQ_INT(ssh_manager_cleanup(&cfg), 0);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    unsetenv("XDG_RUNTIME_DIR");
    ts_rm_rf(g_xdg);
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

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(public_dir, sizeof(public_dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(public_current, sizeof(public_current), "%s/current.sock",
             public_dir);

    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
    char dir[128], pid_path[256], victim[256], content[512];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    char expected_prefix[64];

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);
    snprintf(victim, sizeof(victim), "%s/precious", g_xdg);
    CHECK_EQ_INT(write_string_to_file(victim, "keep\n", 0600), 0);

    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
    CHECK(read_file_to_string(pid_path, content, sizeof(content)) > 0);
    CHECK(snprintf(expected_prefix, sizeof(expected_prefix), "v2 %ld ",
                   (long)cfg.agent_pid) > 0);
    CHECK(strncmp(content, expected_prefix, strlen(expected_prefix)) == 0);
    CHECK_EQ_INT(ssh_manager_cleanup(&cfg), 0);
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
    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
 * sidecar/link may be split across namespaces and success may not be reported
 * through a public path that names the replacement. Every supported platform
 * can now protocol-probe and retire the descriptor-anchored old socket. */
TEST(fresh_start_aborts_without_claiming_replaced_namespace) {
    char public_dir[256];
    char public_sock[384];
    char moved_sock[384];
    char moved_pid[384];
    char moved_current[384];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(public_dir, sizeof(public_dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(public_sock, sizeof(public_sock),
             "%s/ssh-agent.work.sock", public_dir);

    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", g_xdg, 1), 0);
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    snprintf(temp_path, sizeof(temp_path),
             "%s/.ssh-agent.work.pid.tmp.%d", dir, (int)getpid());
    snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.work.pid", dir);

    CHECK_EQ_INT(make_account(&acct, "keyA"), 0);
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
    char pid_path[256];
    ssh_config_t cfg;
    ssh_reap_fn prev_reap;
    ssh_agent_record_t record =
        synthetic_agent_record((pid_t)12345, UINT64_C(0x3132333435363738));

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(safe_snprintf(pid_path, sizeof(pid_path),
                               "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg),
                 0);
    CHECK_EQ_INT(write_agent_sidecar("work", &record), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    safe_strncpy(cfg.agent_socket_path, sock, sizeof(cfg.agent_socket_path));
    safe_strncpy(cfg.agent_socket_arg, "ssh-agent.work.sock",
                 sizeof(cfg.agent_socket_arg));
    cfg.agent_pid = 12345;
    cfg.agent_generation = record.generation;
    cfg.agent_image = record.image;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;
    cfg.reused_existing_agent = true;
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", sock, 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "12345", 1), 0);

    prev_reap = ssh_manager_set_reap_fn(refuse_agent_reap);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), -1);
    ssh_manager_set_reap_fn(prev_reap);

    CHECK(cfg.agent_owned);
    CHECK(cfg.key_already_loaded);
    CHECK(cfg.reused_existing_agent);
    CHECK_EQ_INT(cfg.agent_pid, 12345);
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK_STR_EQ(cfg.agent_socket_arg, "ssh-agent.work.sock");
    CHECK(path_exists(sock));
    CHECK(path_exists(pid_path));
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), sock);
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "12345");

    prev_reap = ssh_manager_set_reap_fn(classify_agent_gone);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
    ssh_manager_set_reap_fn(prev_reap);
    CHECK(!cfg.key_already_loaded);
    CHECK(!cfg.reused_existing_agent);
    CHECK(!path_exists(sock));
    CHECK(!path_exists(pid_path));
    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
    CHECK(!cfg.key_already_loaded);
}

TEST(stop_agent_cleanup_failure_retains_sidecar_until_durable_retry) {
    char sock[256];
    char pid_path[256];
    ssh_config_t cfg;
    ssh_reap_fn previous_reap;
    ssh_dirsync_fn previous_dirsync;
    ssh_agent_record_t record =
        synthetic_agent_record((pid_t)12345, UINT64_C(0x3132333435363738));

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(safe_snprintf(pid_path, sizeof(pid_path),
                               "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg),
                 0);
    CHECK_EQ_INT(write_agent_sidecar("work", &record), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path, sock,
                              sizeof(cfg.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_arg,
                              "ssh-agent.work.sock",
                              sizeof(cfg.agent_socket_arg)), 0);
    cfg.agent_pid = 12345;
    cfg.agent_generation = record.generation;
    cfg.agent_image = record.image;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;

    g_stop_dirsync_calls = 0;
    g_stop_dirsync_fail_call = 1;
    previous_reap = ssh_manager_set_reap_fn(classify_agent_gone);
    previous_dirsync = ssh_manager_set_dirsync_fn(stop_counting_dirsync);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), -1);
    /* Descriptor pins need only the failed socket-removal sync.  Darwin's
     * fallback socket pin is a private hard-link anchor, whose retirement
     * adds a required directory sync while preserving the primary failure. */
    CHECK(g_stop_dirsync_calls >= 1);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK(strstr(get_last_error()->message,
                 "stopped agent socket cleanup") != NULL);
    CHECK(cfg.agent_owned);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, 12345);
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(!path_exists(sock));
    CHECK(path_exists(pid_path));

    g_stop_dirsync_calls = 0;
    g_stop_dirsync_fail_call = 0;
    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
    CHECK(g_stop_dirsync_calls >= 1);
    CHECK(!cfg.agent_owned);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK(!path_exists(sock));
    CHECK(!path_exists(pid_path));

    ssh_manager_set_dirsync_fn(previous_dirsync);
    ssh_manager_set_reap_fn(previous_reap);
}

#if defined(__FreeBSD__)
/* UFS may expose a delayed ctime successor after the sidecar's exact read.
 * The retained descriptor and exact canonical bytes still identify the same
 * process record, so cleanup may rebind that one-field successor without
 * weakening replacement or content-change rejection. */
TEST(freebsd_stop_rebinds_exact_pid_ctime_successor) {
    char sock[256];
    ssh_config_t cfg;
    ssh_reap_fn previous_reap;
    ssh_agent_record_t record =
        synthetic_agent_record((pid_t)12345,
                               UINT64_C(0x4142434445464748));

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(safe_snprintf(
                     g_pid_ctime_successor_path,
                     sizeof(g_pid_ctime_successor_path),
                     "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg),
                 0);
    CHECK_EQ_INT(write_agent_sidecar("work", &record), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path, sock,
                              sizeof(cfg.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_arg,
                              "ssh-agent.work.sock",
                              sizeof(cfg.agent_socket_arg)), 0);
    cfg.agent_pid = record.pid;
    cfg.agent_generation = record.generation;
    cfg.agent_image = record.image;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;

    g_pid_ctime_successor_injected = false;
    previous_reap = ssh_manager_set_reap_fn(
        classify_agent_gone_after_pid_ctime_successor);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), 0);
    ssh_manager_set_reap_fn(previous_reap);

    CHECK(g_pid_ctime_successor_injected);
    CHECK(!cfg.agent_owned);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK(!path_exists(sock));
    CHECK(!path_exists(g_pid_ctime_successor_path));
}
#endif

TEST(stop_agent_missing_exact_record_preserves_retry_handle) {
    char sock[256];
    char pid_path[256];
    ssh_config_t cfg;
    ssh_reap_fn previous_reap;
    ssh_dirsync_fn previous_dirsync;
    ssh_agent_record_t record =
        synthetic_agent_record((pid_t)12345, UINT64_C(0x3132333435363738));

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(safe_snprintf(pid_path, sizeof(pid_path),
                               "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg),
                 0);
    CHECK_EQ_INT(write_agent_sidecar("work", &record), 0);
    CHECK_EQ_INT(unlink(sock), 0);
    CHECK_EQ_INT(unlink(pid_path), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path, sock,
                              sizeof(cfg.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_arg,
                              "ssh-agent.work.sock",
                              sizeof(cfg.agent_socket_arg)), 0);
    cfg.agent_pid = 12345;
    cfg.agent_generation = record.generation;
    cfg.agent_image = record.image;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;

    g_stop_dirsync_calls = 0;
    g_stop_dirsync_fail_call = 0;
    previous_reap = ssh_manager_set_reap_fn(classify_agent_gone);
    previous_dirsync = ssh_manager_set_dirsync_fn(stop_counting_dirsync);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), -1);
    CHECK_EQ_INT(g_stop_dirsync_calls, 0);
    CHECK(cfg.agent_owned);
    CHECK(cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, 12345);
    CHECK(strstr(get_last_error()->message,
                 "no exact durable process sidecar") != NULL);
    CHECK(!path_exists(sock));
    CHECK(!path_exists(pid_path));

    ssh_manager_set_dirsync_fn(previous_dirsync);
    ssh_manager_set_reap_fn(previous_reap);
}

TEST(stop_agent_preserves_a_replacement_pid_sidecar) {
    char sock[256];
    char pid_path[256];
    ssh_config_t cfg;
    ssh_reap_fn previous_reap;
    ssh_agent_record_t owned =
        synthetic_agent_record((pid_t)12345, UINT64_C(0x3132333435363738));
    ssh_agent_record_t replacement = owned;

    /* PID and process generation alone are not the durable identity. A
     * same-generation replacement with a different kernel socket-peer tuple
     * must not be reaped or consumed as the in-memory owned record. */
    replacement.image.socket_peer_pid++;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    CHECK_EQ_INT(safe_snprintf(pid_path, sizeof(pid_path),
                               "%s/gitswitch-ssh/ssh-agent.work.pid", g_xdg),
                 0);
    CHECK_EQ_INT(write_agent_sidecar("work", &replacement), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path, sock,
                              sizeof(cfg.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_arg,
                              "ssh-agent.work.sock",
                              sizeof(cfg.agent_socket_arg)), 0);
    cfg.agent_pid = 12345;
    cfg.agent_generation = owned.generation;
    cfg.agent_image = owned.image;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;

    g_classify_agent_gone_calls = 0;
    previous_reap = ssh_manager_set_reap_fn(classify_agent_gone);
    CHECK_EQ_INT(ssh_stop_agent(&cfg), -1);
    CHECK_EQ_INT(g_classify_agent_gone_calls, 0);
    CHECK(cfg.agent_owned);
    CHECK(cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, 12345);
    CHECK(path_exists(sock));
    CHECK(path_exists(pid_path));
    CHECK(strstr(get_last_error()->message, "replacement retained") != NULL);
    ssh_manager_set_reap_fn(previous_reap);
}

TEST(clear_agent_keys_tracks_the_destructive_child_result) {
    ssh_config_t cfg;
    command_runner_fn previous_runner;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_path,
                              "/tmp/l38-agent.sock",
                              sizeof(cfg.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(cfg.agent_socket_arg,
                              "ssh-agent.work.sock",
                              sizeof(cfg.agent_socket_arg)), 0);
    cfg.agent_pid = 4321;
    cfg.agent_owned = true;
    cfg.key_already_loaded = true;
    cfg.reused_existing_agent = true;

    g_clear_agent_keys_calls = 0;
    g_clear_agent_keys_runner_rc = -1;
    g_clear_agent_keys_exit_code = 1;
    g_clear_agent_keys_exact_argv = true;
    g_clear_agent_keys_saw_socket = true;
    previous_runner = run_set_runner(clear_agent_keys_runner);

    CHECK_EQ_INT(ssh_clear_agent_keys(&cfg), -1);
    CHECK(cfg.key_already_loaded);
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_KEY_LOAD_FAILED);
    CHECK(strstr(get_last_error()->message, "synthetic clear failure") != NULL);
    CHECK_EQ_INT(cfg.agent_pid, 4321);
    CHECK(cfg.agent_owned);
    CHECK(cfg.reused_existing_agent);
    CHECK_STR_EQ(cfg.agent_socket_path, "/tmp/l38-agent.sock");
    CHECK_STR_EQ(cfg.agent_socket_arg, "ssh-agent.work.sock");

    g_clear_agent_keys_runner_rc = 0;
    g_clear_agent_keys_exit_code = 0;
    CHECK_EQ_INT(ssh_clear_agent_keys(&cfg), 0);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(cfg.agent_pid, 4321);
    CHECK(cfg.agent_owned);
    CHECK(cfg.reused_existing_agent);
    CHECK_STR_EQ(cfg.agent_socket_path, "/tmp/l38-agent.sock");
    CHECK_STR_EQ(cfg.agent_socket_arg, "ssh-agent.work.sock");

    /* The command can complete before runner pipe/signal cleanup fails. The
     * API still reports that parent-side failure, but key state follows the
     * destructive child's known-zero exit rather than the wrapper status. */
    cfg.key_already_loaded = true;
    g_clear_agent_keys_runner_rc = -1;
    g_clear_agent_keys_exit_code = 0;
    clear_error();
    CHECK_EQ_INT(ssh_clear_agent_keys(&cfg), -1);
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK(strstr(get_last_error()->message,
                 "synthetic runner cleanup failure") != NULL);

    g_clear_agent_keys_runner_rc = 0;
    CHECK_EQ_INT(ssh_clear_agent_keys(&cfg), 0);
    CHECK(!cfg.key_already_loaded);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(g_clear_agent_keys_calls, 4);
    CHECK(g_clear_agent_keys_exact_argv);
    CHECK(g_clear_agent_keys_saw_socket);
    CHECK_EQ_INT(unsetenv("SSH_AUTH_SOCK"), 0);
    CHECK_EQ_INT(unsetenv("SSH_AGENT_PID"), 0);
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

TEST(host_alias_identity_file_supports_apostrophes) {
    static const char *invalid_suffixes[] = {
        "key\"quoted",
        "key\\backslash",
        "key$HOME",
        "key\nHost injected"
    };
    char home[128];
    char cfg_path[256];
    char expected[512];
    char before[4096];
    char after[4096];
    account_t acct;

    snprintf(home, sizeof(home), "/tmp/gswsshaliasquote_XXXXXX");
    CHECK(ts_mkdtemp(home) != NULL);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    CHECK((size_t)snprintf(acct.ssh_host_alias,
                           sizeof(acct.ssh_host_alias),
                           "github.com-work") <
          sizeof(acct.ssh_host_alias));
    CHECK((size_t)snprintf(acct.ssh_hostname,
                           sizeof(acct.ssh_hostname),
                           "github.com") <
          sizeof(acct.ssh_hostname));
    CHECK((size_t)snprintf(acct.ssh_key_path,
                           sizeof(acct.ssh_key_path),
                           "%s/key's 100%%", home) <
          sizeof(acct.ssh_key_path));

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK((size_t)snprintf(cfg_path, sizeof(cfg_path),
                           "%s/.ssh/config", home) < sizeof(cfg_path));
    CHECK(read_file_to_string(cfg_path, before, sizeof(before)) > 0);
    CHECK((size_t)snprintf(expected, sizeof(expected),
                           "  IdentityFile \"%s/key's 100%%%%\"\n",
                           home) < sizeof(expected));
    CHECK(strstr(before, expected) != NULL);

    for (size_t i = 0;
         i < sizeof(invalid_suffixes) / sizeof(invalid_suffixes[0]); i++) {
        CHECK((size_t)snprintf(acct.ssh_key_path,
                               sizeof(acct.ssh_key_path),
                               "%s/%s", home, invalid_suffixes[i]) <
              sizeof(acct.ssh_key_path));
        clear_error();
        CHECK_EQ_INT(ssh_configure_host_alias(&acct), -1);
        CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
        CHECK(read_file_to_string(cfg_path, after, sizeof(after)) > 0);
        CHECK(strcmp(after, before) == 0);
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
    int remove_rc;
#if defined(__FreeBSD__)
    ssh_dirsync_fn previous_dirsync;
#endif

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

    /* Idempotent: removing again (block now absent) is a clean no-op. AR-14:
     * FreeBSD may expose the retained config inode's delayed ctime successor
     * after this no-op's directory sync; inject that exact shape so the
     * descriptor/name/byte stability proof remains deterministic. */
#if defined(__FreeBSD__)
    CHECK_EQ_INT(safe_strncpy(g_config_ctime_successor_path, cfg_path,
                              sizeof(g_config_ctime_successor_path)), 0);
    g_config_ctime_successor_injected = false;
    previous_dirsync =
        ssh_manager_set_dirsync_fn(sync_config_dir_before_ctime_successor);
#endif
    remove_rc = ssh_remove_host_alias("github.com-work");
#if defined(__FreeBSD__)
    ssh_manager_set_dirsync_fn(previous_dirsync);
    CHECK(g_config_ctime_successor_injected);
#endif
    CHECK_EQ_INT(remove_rc, 0);
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
    char legacy_pid[64];
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 }; /* 100ms */
    pid_t pid;
    int status = 0;

    CHECK_EQ_INT(make_xdg_runtime_dir(), 0);
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
    CHECK(snprintf(legacy_pid, sizeof(legacy_pid), "%ld\n",
                   (long)pid) > 0);
    CHECK_EQ_INT(write_string_to_file(pid_path, legacy_pid, 0600), 0);

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
    RUN_TEST(precleanup_activation_failure_preserves_prior_key_truth);
    RUN_TEST(reuse_failure_preserves_only_reproven_target_key_truth);
    RUN_TEST(ssh_fingerprint_reuse_rejects_different_key);
    RUN_TEST(ssh_fingerprint_reuse_rejects_same_fingerprint_certificate);
    RUN_TEST(agent_output_quoted_auth_sock_preserves_pinned_path);
    RUN_TEST(
        isolated_activation_retains_generation_between_fingerprint_and_load);
    RUN_TEST(fresh_commit_revalidates_public_agent_directory);
    RUN_TEST(ssh_reuse_refuses_symlinked_agent_socket);
    RUN_TEST(ssh_reuse_refuses_symlinked_pid_sidecar);
    RUN_TEST(fresh_agent_sidecar_atomically_replaces_planted_symlink);
    RUN_TEST(reuse_aborts_on_agent_directory_namespace_replacement);
    RUN_TEST(fresh_start_aborts_without_claiming_replaced_namespace);
    RUN_TEST(pid_sidecar_rejects_temp_path_inode_swap);
    RUN_TEST(stop_agent_reap_failure_preserves_retry_handle);
    RUN_TEST(stop_agent_cleanup_failure_retains_sidecar_until_durable_retry);
#if defined(__FreeBSD__)
    RUN_TEST(freebsd_stop_rebinds_exact_pid_ctime_successor);
#endif
    RUN_TEST(stop_agent_missing_exact_record_preserves_retry_handle);
    RUN_TEST(stop_agent_preserves_a_replacement_pid_sidecar);
    RUN_TEST(clear_agent_keys_tracks_the_destructive_child_result);
    RUN_TEST(host_alias_write_rejects_newline_key_path);
    RUN_TEST(host_alias_identity_file_supports_apostrophes);
    RUN_TEST(host_alias_removal_excises_only_named_block);
    RUN_TEST(host_alias_handles_config_larger_than_64k);
#if defined(__linux__)
    RUN_TEST(reset_never_signals_bystander_pid_in_sidecar);
#endif
TEST_MAIN_END()
