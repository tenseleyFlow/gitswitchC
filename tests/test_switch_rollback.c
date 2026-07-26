/* Behavioral tests for accounts_switch failure/interrupt handling:
 *
 *   F4     — a switch to an SSH/GPG-disabled target must NOT tear down the
 *            previously-active account's runtime isolation (current.sock,
 *            GNUPGHOME `current` symlink) until the git-config write — the
 *            point of no return — has succeeded. A failure there leaves the
 *            prior state intact; only a successful switch drops it.
 *   SIG-01 — a SIGINT landing mid git-config write must not kill the process
 *            between durable steps: the guard defers it, the rollback runs
 *            (observable as restore commands issued AFTER the signal), and
 *            the process then re-raises so it still dies by SIGINT.
 *
 * External commands are intercepted with the recording-runner pattern from
 * test_security.c; the runtime symlinks live under a private fake
 * XDG_RUNTIME_DIR so no real agents are involved. */

/* Enable POSIX extensions for mkdtemp/symlink/fork. glibc-only: on macOS and
 * the BSDs the strict macros hide default-namespace declarations (mkdtemp,
 * SA_*) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "accounts.h"
#include "config.h"
#include "git_ops.h"
#include "signals.h"
#include "ssh_manager.h"
#include "gpg_manager.h"
#include "runner_internal.h"
#include "utils.h"
#include "error.h"
#include "scratch_registry_test.h"

#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- fake runtime dir ---------------------------------------------------- */

static char g_xdg[256];
static char g_ssh_sock[512];   /* <xdg>/gitswitch-ssh/current.sock */
static char g_gpg_link[512];   /* <xdg>/gitswitch-gpg/current */
static char g_gpg_source_home[512]; /* external source keyring fixture */
static char g_gpg_command_dir[MAX_PATH_LEN];
static char *g_gpg_saved_path;
static bool g_gpg_saved_path_present;
static bool g_gpg_command_fixture_active;
static bool g_host_gpg_available;
static int g_fake_agent_listener = -1;
static gitswitch_ctx_t *g_finalizing_observer_ctx;
static bool g_finalizing_phase_observed;

static void observe_finalizing_switch_phase(void) {
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_COMPLETE;
    error_context_t saved_error = g_last_error;
    char expected_phase[32];
    int saved_errno = errno;

    snprintf(expected_phase, sizeof(expected_phase), "phase %d",
             ACCOUNTS_TRANSACTION_FINALIZING);
    if (accounts_switch_commit_result(g_finalizing_observer_ctx, &state) == -1 &&
        strstr(get_last_error()->message, expected_phase) != NULL) {
        g_finalizing_phase_observed = true;
    }
    g_last_error = saved_error;
    errno = saved_errno;
}

static void close_fake_agent_listener(void) {
    if (g_fake_agent_listener >= 0) {
        close(g_fake_agent_listener);
        g_fake_agent_listener = -1;
    }
}

/* Create a fresh fake XDG_RUNTIME_DIR holding the pre-switch runtime state of
 * a "previous" account: a current.sock symlink and a GNUPGHOME `current`
 * symlink pointing at a real (empty) home dir. Returns 0 on success. */
static int setup_runtime_dir(void) {
    char path[512];
    int cleanup_result;

    /* Some SSH rollback cases intentionally leave a restored session active.
     * Later GPG cases may clear it on platforms where gpg is installed, which
     * made the signal tests accidentally depend on the hosted tool matrix.
     * Start every case from a clean process session before changing XDG. */
    cleanup_result = accounts_session_cleanup();
    close_fake_agent_listener();
    if (cleanup_result != 0) return -1;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gsw_rollback_XXXXXX");
    if (!ts_mkdtemp(g_xdg) ||
        ts_canonicalize_dir_path(g_xdg, sizeof(g_xdg)) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(g_ssh_sock, sizeof(g_ssh_sock), "%s/gitswitch-ssh/current.sock", g_xdg);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.prev.sock", g_xdg);
    if (symlink(path, g_ssh_sock) != 0) return -1;

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/prevhome", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(g_gpg_link, sizeof(g_gpg_link), "%s/gitswitch-gpg/current", g_xdg);
    if (symlink(path, g_gpg_link) != 0) return -1;

    return 0;
}

/* A transaction with no pre-existing runtime identity is the smallest exact
 * fixture for signal-lifecycle tests: prepare/abort can prove a complete Git
 * rollback without manufacturing an SSH agent solely for restoration. */
static int setup_empty_runtime_dir(void) {
    int cleanup_result = accounts_session_cleanup();

    close_fake_agent_listener();
    if (cleanup_result != 0) return -1;
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gsw_rollback_empty_XXXXXX");
    if (!ts_mkdtemp(g_xdg) ||
        ts_canonicalize_dir_path(g_xdg, sizeof(g_xdg)) != 0) return -1;
    return setenv("XDG_RUNTIME_DIR", g_xdg, 1);
}

static int capture_accounts_switch_output(gitswitch_ctx_t *ctx,
                                          const char *account_name,
                                          char *output,
                                          size_t output_size,
                                          int *switch_result) {
    FILE *capture;
    int saved_stdout;
    int restore_result;
    size_t length;

    if (!ctx || !account_name || !output || output_size == 0U ||
        !switch_result) {
        return -1;
    }
    capture = tmpfile();
    if (!capture) return -1;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0 || fflush(stdout) != 0) {
        if (saved_stdout >= 0) close(saved_stdout);
        fclose(capture);
        return -1;
    }
    if (dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        close(saved_stdout);
        fclose(capture);
        return -1;
    }

    *switch_result = accounts_switch(ctx, account_name);
    if (fflush(stdout) != 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
        fclose(capture);
        return -1;
    }
    restore_result = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    rewind(capture);
    length = fread(output, 1, output_size - 1U, capture);
    output[length] = '\0';
    fclose(capture);
    return restore_result == STDOUT_FILENO ? 0 : -1;
}

/* Runtime locks are process-scoped on some supported kernels, so a fresh
 * child is the authoritative probe that a failed preparation did not retain
 * the cross-manager lock. */
static bool runtime_lock_available_to_child(void) {
    int status = 0;
    pid_t pid;

    fflush(NULL);
    pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int lock_fd = runtime_state_lock_acquire();

        if (lock_fd < 0) _exit(1);
        runtime_state_lock_release(lock_fd);
        _exit(0);
    }
    if (waitpid(pid, &status, 0) != pid) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

typedef struct {
    pid_t pid;
    int release_fd;
} runtime_lock_holder_t;

/* Hold the shared runtime lock in a separate process. A distinct process is
 * the portable contention fixture: same-process flock behavior differs
 * across supported kernels and would not prove the inter-process boundary. */
static int start_runtime_lock_holder(runtime_lock_holder_t *holder) {
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    pid_t pid;
    char marker = '\0';
    ssize_t count;

    if (!holder || pipe(ready) != 0 || pipe(release) != 0) {
        int saved_errno = errno;
        if (ready[0] >= 0) close(ready[0]);
        if (ready[1] >= 0) close(ready[1]);
        if (release[0] >= 0) close(release[0]);
        if (release[1] >= 0) close(release[1]);
        errno = saved_errno;
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        errno = saved_errno;
        return -1;
    }
    if (pid == 0) {
        int lock_fd;

        close(ready[0]);
        close(release[1]);
        lock_fd = runtime_state_lock_acquire();
        marker = lock_fd >= 0 ? 'R' : 'E';
        do {
            count = write(ready[1], &marker, 1);
        } while (count < 0 && errno == EINTR);
        close(ready[1]);
        if (lock_fd < 0 || count != 1) _exit(1);
        do {
            count = read(release[0], &marker, 1);
        } while (count < 0 && errno == EINTR);
        close(release[0]);
        runtime_state_lock_release(lock_fd);
        _exit(count == 1 ? 0 : 2);
    }

    close(ready[1]);
    close(release[0]);
    do {
        count = read(ready[0], &marker, 1);
    } while (count < 0 && errno == EINTR);
    close(ready[0]);
    if (count != 1 || marker != 'R') {
        int status = 0;
        close(release[1]);
        (void)waitpid(pid, &status, 0);
        errno = EBUSY;
        return -1;
    }
    holder->pid = pid;
    holder->release_fd = release[1];
    return 0;
}

static int stop_runtime_lock_holder(runtime_lock_holder_t *holder) {
    char marker = 'X';
    ssize_t count;
    pid_t waited;
    int status = 0;

    if (!holder || holder->pid <= 0 || holder->release_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    do {
        count = write(holder->release_fd, &marker, 1);
    } while (count < 0 && errno == EINTR);
    close(holder->release_fd);
    holder->release_fd = -1;
    do {
        waited = waitpid(holder->pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    holder->pid = -1;
    return count == 1 && waited > 0 && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0
               ? 0
               : -1;
}

/* The GPG runner below fakes key inventory and transfer, but production still
 * pins and validates the source keyring directory around every child spawn.
 * Give those tests a private external source so they never depend on the
 * operator's GNUPGHOME or on whether HOME/.gnupg exists. */
static int setup_gpg_source_home(void) {
    if (safe_snprintf(g_gpg_source_home, sizeof(g_gpg_source_home),
                      "%s/system-gnupg", g_xdg) != 0) {
        return -1;
    }
    if (mkdir(g_gpg_source_home, 0700) != 0) return -1;
    return setenv("GNUPGHOME", g_gpg_source_home, 1);
}

/* These cases fake every GPG child invocation, but gpg_manager_init and the
 * isolated-home activation still perform production's descriptor-pinned gpg
 * and gpgconf resolution. Homebrew's shared, group-writable prefix is
 * intentionally rejected by that resolver, even though the installed gpg is
 * a valid CI dependency. First execute the host gpg solely as a test-capability
 * preflight; when it is runnable, prepend private trusted tripwire scripts for
 * every command the fake runner intercepts. */
static int host_gpg_preflight(void) {
    int status;
    pid_t waited;
    pid_t pid = fork();

    if (pid < 0) return -1;
    if (pid == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        if (null_fd > STDERR_FILENO) close(null_fd);
        execlp("gpg", "gpg", "--version", (char *)NULL);
        _exit(127);
    }

    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

static int restore_gpg_command_fixture(void) {
    int rc;

    if (!g_gpg_command_fixture_active) return 0;
    rc = g_gpg_saved_path_present
             ? setenv("PATH", g_gpg_saved_path, 1)
             : unsetenv("PATH");
    free(g_gpg_saved_path);
    g_gpg_saved_path = NULL;
    g_gpg_saved_path_present = false;
    g_gpg_command_fixture_active = false;
    return rc;
}

static int setup_gpg_command_fixture(void) {
    static const char script[] = "#!/bin/sh\nexit 125\n";
    const char *path = getenv("PATH");
    char gpg_path[MAX_PATH_LEN];
    char gpgconf_path[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    char *saved_path = NULL;
    char *fixture_path = NULL;
    size_t dir_len;
    size_t path_len = path ? strlen(path) : 0;
    size_t fixture_len;
    bool append_path = path_len > 0;

    if (path) {
        saved_path = strdup(path);
        if (!saved_path) return -1;
    }
    if (!ts_mkdtemp_trusted(g_gpg_command_dir,
                            sizeof(g_gpg_command_dir), "gsw-gpg-bin") ||
        safe_snprintf(gpg_path, sizeof(gpg_path), "%s/gpg",
                      g_gpg_command_dir) != 0 ||
        safe_snprintf(gpgconf_path, sizeof(gpgconf_path), "%s/gpgconf",
                      g_gpg_command_dir) != 0 ||
        write_string_to_file(gpg_path, script, 0700) != 0 ||
        write_string_to_file(gpgconf_path, script, 0700) != 0) {
        free(saved_path);
        return -1;
    }

    dir_len = strlen(g_gpg_command_dir);
    if (path_len > SIZE_MAX - dir_len - 2) {
        free(saved_path);
        errno = EOVERFLOW;
        return -1;
    }
    fixture_len = dir_len + (append_path ? path_len + 1 : 0) + 1;
    fixture_path = malloc(fixture_len);
    if (!fixture_path) {
        free(saved_path);
        return -1;
    }
    memcpy(fixture_path, g_gpg_command_dir, dir_len);
    if (append_path) {
        fixture_path[dir_len] = ':';
        memcpy(fixture_path + dir_len + 1, path, path_len);
        fixture_path[dir_len + path_len + 1] = '\0';
    } else {
        fixture_path[dir_len] = '\0';
    }

    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        free(saved_path);
        return -1;
    }
    free(fixture_path);
    g_gpg_saved_path = saved_path;
    g_gpg_saved_path_present = path != NULL;
    g_gpg_command_fixture_active = true;
    if (find_command_path("gpg", resolved, sizeof(resolved)) != 0 ||
        strcmp(resolved, gpg_path) != 0 ||
        find_command_path("gpgconf", resolved, sizeof(resolved)) != 0 ||
        strcmp(resolved, gpgconf_path) != 0) {
        int saved_errno = errno;
        (void)restore_gpg_command_fixture();
        errno = saved_errno ? saved_errno : ENOENT;
        return -1;
    }
    return 0;
}

static bool gpg_test_command_available(void) {
    return g_host_gpg_available && command_exists("gpg");
}

static bool symlink_present(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* ---- selective runner ---------------------------------------------------- */

/* Behavior knobs for the fake runner. */
static bool g_fail_user_name_set;   /* fail `git config <scope> user.name X` */
static bool g_raise_on_user_name;   /* raise SIGINT during that same command */
static bool g_fail_list_config;     /* fail exact snapshot acquisition */
static bool g_mutate_name_before_seal;
static char g_preseal_gpgopenpgp_observed[MAX_PATH_LEN];
static int g_worktree_probe_failures; /* fail the next N --show-scope probes */
static int g_user_name_writes;
static int g_fake_runner_calls;
static int g_ssh_git_runner_calls;
static int g_ssh_activation_commands;
static int g_ssh_connection_probes;
static int g_ssh_alias_probes;
static int g_ssh_default_probes;
static int g_deadlined_ssh_probes;
static int g_deadlined_nonprobe_commands;
static int64_t g_ssh_probe_deadline;
static bool g_fail_ssh_probe;
static bool g_timeout_ssh_probe;
static bool g_spawn_fail_ssh_probe;
static char g_ssh_probe_target[MAX_NAME_LEN + sizeof("git@")];
static char g_ssh_probe_hostname[sizeof("HostName=") + MAX_NAME_LEN];
static gitswitch_ctx_t *g_probe_expected_ctx;
static const char *g_probe_expected_config_path;
static const char *g_probe_expected_alias;
static bool g_probe_observed_committed_state;
static error_context_t g_probe_error_before;
static int g_probe_errno_before;
static uint64_t g_probe_generation_before;
static bool g_probe_failure_pending_observation;
static bool g_post_probe_diagnostic_observed;
static error_context_t g_post_probe_error;
static int g_post_probe_errno;
static uint64_t g_post_probe_generation;
static bool g_fail_ssh_add;
static const char *g_retarget_gpg_on_user_name; /* simulate a later XDG writer */
static FILE *g_log;                 /* when set, every argv is logged here */
static char g_effective_signingkey_observed[MAX_GPG_FINGERPRINT_LEN];

#define FAKE_AGENT_PID 1073741824
#define FAKE_AGENT_FP "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static const int switch_guarded_signals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT
};
#define SWITCH_GUARDED_SIGNAL_COUNT \
    (sizeof(switch_guarded_signals) / sizeof(switch_guarded_signals[0]))

static ssh_process_outcome_t refuse_session_agent_reap(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_OWNED;
}

static int g_session_reap_signal;
static int g_session_reap_calls;
static ssh_reap_fn g_session_reap_delegate;

/* Causal AR-08 M4 probe: inject the repeated signal from inside the exact
 * previous-session reap boundary. The first call belongs to
 * accounts_session_cleanup(); a later call proves the checked abort reached
 * runtime rollback before the pending signal was re-raised. */
static ssh_process_outcome_t signal_during_session_agent_reap(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    int call = ++g_session_reap_calls;
    ssh_process_outcome_t outcome;

    if (g_log) {
        fprintf(g_log, "MARK-SESSION-REAP-%d-BEFORE\n", call);
        fflush(g_log);
    }
    if (call == 1) {
        raise(g_session_reap_signal);
        raise(g_session_reap_signal);
    }
    if (g_log) {
        fprintf(g_log, "MARK-SESSION-REAP-%d-AFTER\n", call);
        fflush(g_log);
    }
    outcome = g_session_reap_delegate
                  ? g_session_reap_delegate(record, socket_arg, runtime_dir_fd)
                  : SSH_PROCESS_INDETERMINATE;
    return outcome;
}

/* Minimal fake config store so git_set_config's read-back verification sees
 * what was "written": the two identity keys, plus core.sshcommand since
 * git_configure_ssh round-trips its write too (AR-05 M5). */
static char g_store_name[MAX_NAME_LEN];
static char g_store_email[MAX_EMAIL_LEN];
static char g_store_sshcmd[MAX_PATH_LEN * 2];
static char g_store_signingkey[MAX_GPG_SELECTOR_LEN];
static char g_store_gpgsign[16];
static char g_store_gpgformat[16];
static char g_store_gpgprogram[MAX_PATH_LEN];
static char g_store_gpgopenpgp[MAX_PATH_LEN];
static char g_store_gpgx509[MAX_PATH_LEN];
static char g_store_gpgssh[MAX_PATH_LEN];

/* git_ops.c deliberately keeps this test-only cache reset out of its public
 * header. Identity-sensitive cases below need a fresh snapshot/read-back view. */
void git_ops_test_reset_caches(void);

/* True for the 5-element write form {git, config, <scope>, <key>, value}
 * (the --unset form has "--unset" at argv[3], so it never matches). */
static bool is_config_write(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && argv[4] && !argv[5] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[3], key) == 0;
}

static bool is_config_add(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && argv[4] && argv[5] &&
           !argv[6] && strcmp(argv[0], "git") == 0 &&
           strcmp(argv[1], "config") == 0 && strcmp(argv[3], "--add") == 0 &&
           strcmp(argv[4], key) == 0;
}

static bool is_config_unset(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && argv[4] && !argv[5] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           (strcmp(argv[3], "--unset-all") == 0 ||
            strcmp(argv[3], "--unset") == 0) && strcmp(argv[4], key) == 0;
}

/* True for the 4-element read form {git, config, <scope>, <key>}. */
static bool is_config_read(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && !argv[4] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[3], key) == 0;
}

static bool is_global_config_command(const char *const argv[]) {
    return argv[0] && argv[1] && argv[2] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[2], "--global") == 0;
}

static bool is_config_list(const char *const argv[]) {
    if (!argv[0] || !argv[1] || strcmp(argv[0], "git") != 0 ||
        strcmp(argv[1], "config") != 0) {
        return false;
    }
    for (size_t i = 2; argv[i]; i++) {
        if (strcmp(argv[i], "--list") == 0) {
            return true;
        }
    }
    return false;
}

static bool is_effective_config_list(const char *const argv[]) {
    return argv[0] && argv[1] && argv[2] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[2], "--show-origin") == 0;
}

static int append_effective_record(char *out, size_t out_size, size_t *used,
                                   const char *key, const char *value) {
    const char scope[] = "global";
    const char origin[] = "file:/fake/global";
    size_t need = sizeof(scope) + sizeof(origin) + strlen(key) + 1 +
                  strlen(value) + 1;
    if (*used + need > out_size) return -1;
    memcpy(out + *used, scope, sizeof(scope));
    *used += sizeof(scope);
    memcpy(out + *used, origin, sizeof(origin));
    *used += sizeof(origin);
    *used += (size_t)snprintf(out + *used, out_size - *used,
                             "%s\n%s", key, value) + 1;
    return 0;
}

static int append_snapshot_record(char *out, size_t out_size, size_t *used,
                                  const char *key, const char *value) {
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    size_t need = key_len + 1U + value_len + 1U;
    if (*used + need > out_size) return -1;
    memcpy(out + *used, key, key_len);
    *used += key_len;
    out[(*used)++] = '\n';
    memcpy(out + *used, value, value_len);
    *used += value_len;
    out[(*used)++] = '\0';
    return 0;
}

static int emit_scope_config(const char *scope, const run_opts_t *opts,
                             run_result_t *result) {
    size_t used = 0;

    if (!opts || !opts->out || opts->out_size == 0) return -1;
#define APPEND_GLOBAL_IF_SET(key_, value_) do {                               \
    if (strcmp(scope, "--global") == 0 && (value_)[0] &&                     \
        append_snapshot_record(opts->out, opts->out_size, &used,              \
                               (key_), (value_)) != 0) {                       \
        if (result) result->out_truncated = true;                              \
        return -1;                                                             \
    }                                                                          \
} while (0)
    APPEND_GLOBAL_IF_SET("user.name", g_store_name);
    APPEND_GLOBAL_IF_SET("user.email", g_store_email);
    APPEND_GLOBAL_IF_SET("user.signingkey", g_store_signingkey);
    APPEND_GLOBAL_IF_SET("commit.gpgsign", g_store_gpgsign);
    APPEND_GLOBAL_IF_SET("gpg.program", g_store_gpgprogram);
    APPEND_GLOBAL_IF_SET("core.sshcommand", g_store_sshcmd);
    APPEND_GLOBAL_IF_SET("gpg.format", g_store_gpgformat);
    APPEND_GLOBAL_IF_SET("gpg.openpgp.program", g_store_gpgopenpgp);
    APPEND_GLOBAL_IF_SET("gpg.x509.program", g_store_gpgx509);
    APPEND_GLOBAL_IF_SET("gpg.ssh.program", g_store_gpgssh);
#undef APPEND_GLOBAL_IF_SET
    if (used < opts->out_size) opts->out[used] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
        result->out_len = used;
    }
    return 0;
}

static int emit_effective_config(const run_opts_t *opts, run_result_t *result) {
    size_t used = 0;
    if (!opts || !opts->out || opts->out_size == 0) return -1;
    if (g_store_signingkey[0] != '\0') {
        safe_strncpy(g_effective_signingkey_observed, g_store_signingkey,
                     sizeof(g_effective_signingkey_observed));
    }
#define APPEND_IF_SET(key_, value_) do {                                      \
    if ((value_)[0] && append_effective_record(opts->out, opts->out_size,     \
                                                &used, (key_), (value_)) != 0) \
        return -1;                                                            \
} while (0)
    APPEND_IF_SET("user.name", g_store_name);
    APPEND_IF_SET("user.email", g_store_email);
    APPEND_IF_SET("user.signingkey", g_store_signingkey);
    APPEND_IF_SET("commit.gpgsign", g_store_gpgsign);
    APPEND_IF_SET("gpg.program", g_store_gpgprogram);
    APPEND_IF_SET("core.sshcommand", g_store_sshcmd);
    APPEND_IF_SET("gpg.format", g_store_gpgformat);
    APPEND_IF_SET("gpg.openpgp.program", g_store_gpgopenpgp);
    APPEND_IF_SET("gpg.x509.program", g_store_gpgx509);
    APPEND_IF_SET("gpg.ssh.program", g_store_gpgssh);
#undef APPEND_IF_SET
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
        result->out_len = used;
    }
    return 0;
}

static int fake_runner(const char *const argv[], const run_opts_t *opts,
                       run_result_t *result) {
    int exit_code = 0;

    g_fake_runner_calls++;
    if (is_effective_config_list(argv))
        return emit_effective_config(opts, result);
    if (argv[0] && argv[1] && argv[2] &&
        strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[2], "--show-scope") == 0) {
        if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            result->exit_code = g_worktree_probe_failures > 0 ? 2 : 0;
        }
        if (g_worktree_probe_failures > 0) {
            g_worktree_probe_failures--;
            return -1;
        }
        return 0; /* no distinct worktree values in this fixture */
    }
    if (is_config_list(argv)) {
        if (g_mutate_name_before_seal && g_user_name_writes > 0) {
            safe_strncpy(g_preseal_gpgopenpgp_observed,
                         g_store_gpgopenpgp,
                         sizeof(g_preseal_gpgopenpgp_observed));
            safe_strncpy(g_store_name, "preseal-writer",
                         sizeof(g_store_name));
            g_mutate_name_before_seal = false;
        }
        if (g_fail_list_config) {
            if (result) {
                memset(result, 0, sizeof(*result));
                result->spawned = true;
                result->exit_code = 1;
            }
            return -1;
        }
        return emit_scope_config(argv[2], opts, result);
    }

    if (g_log) {
        for (int i = 0; argv[i]; i++) fprintf(g_log, "%s ", argv[i]);
        fprintf(g_log, "\n");
        fflush(g_log);
    }

    /* git_ops_init parses the version banner; everything else is happy with
     * empty output unless served from the fake store below. */
    if (opts && opts->out && opts->out_size > 0) {
        opts->out[0] = '\0';
        if (argv[1] && strcmp(argv[1], "--version") == 0) {
            snprintf(opts->out, opts->out_size, "git version 2.40.0\n");
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "user.name") && g_store_name[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_name);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "user.email") && g_store_email[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_email);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "core.sshcommand") && g_store_sshcmd[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_sshcmd);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "user.signingkey") &&
                   g_store_signingkey[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_signingkey);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "commit.gpgsign") &&
                   g_store_gpgsign[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgsign);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "gpg.program") &&
                   g_store_gpgprogram[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgprogram);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "gpg.format") &&
                   g_store_gpgformat[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgformat);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "gpg.openpgp.program") &&
                   g_store_gpgopenpgp[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgopenpgp);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "gpg.x509.program") &&
                   g_store_gpgx509[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgx509);
        } else if (is_global_config_command(argv) &&
                   is_config_read(argv, "gpg.ssh.program") &&
                   g_store_gpgssh[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_gpgssh);
        }
    }

    if (is_config_write(argv, "user.name")) {
        g_user_name_writes++;
        if (g_retarget_gpg_on_user_name) {
            unlink(g_gpg_link);
            if (symlink(g_retarget_gpg_on_user_name, g_gpg_link) != 0) {
                exit_code = 1;
            }
            g_retarget_gpg_on_user_name = NULL;
        }
        if (g_raise_on_user_name) {
            g_raise_on_user_name = false; /* once */
            if (g_log) { fprintf(g_log, "MARK-RAISE\n"); fflush(g_log); }
            raise(SIGINT); /* signal lands mid durable-write window */
        }
        if (g_fail_user_name_set) {
            exit_code = 1;
        } else {
            safe_strncpy(g_store_name, argv[4], sizeof(g_store_name));
        }
    } else if (is_config_write(argv, "user.email")) {
        safe_strncpy(g_store_email, argv[4], sizeof(g_store_email));
    } else if (is_config_write(argv, "core.sshcommand")) {
        safe_strncpy(g_store_sshcmd, argv[4], sizeof(g_store_sshcmd));
    } else if (is_config_write(argv, "user.signingkey")) {
        safe_strncpy(g_store_signingkey, argv[4], sizeof(g_store_signingkey));
    } else if (is_config_write(argv, "commit.gpgsign")) {
        safe_strncpy(g_store_gpgsign, argv[4], sizeof(g_store_gpgsign));
    } else if (is_config_write(argv, "gpg.program")) {
        safe_strncpy(g_store_gpgprogram, argv[4], sizeof(g_store_gpgprogram));
    } else if (is_config_write(argv, "gpg.format")) {
        safe_strncpy(g_store_gpgformat, argv[4], sizeof(g_store_gpgformat));
    } else if (is_config_write(argv, "gpg.openpgp.program")) {
        safe_strncpy(g_store_gpgopenpgp, argv[4], sizeof(g_store_gpgopenpgp));
    } else if (is_config_write(argv, "gpg.x509.program")) {
        safe_strncpy(g_store_gpgx509, argv[4], sizeof(g_store_gpgx509));
    } else if (is_config_write(argv, "gpg.ssh.program")) {
        safe_strncpy(g_store_gpgssh, argv[4], sizeof(g_store_gpgssh));
    } else if (is_config_add(argv, "user.name")) {
        safe_strncpy(g_store_name, argv[5], sizeof(g_store_name));
    } else if (is_config_add(argv, "user.email")) {
        safe_strncpy(g_store_email, argv[5], sizeof(g_store_email));
    } else if (is_config_add(argv, "core.sshcommand")) {
        safe_strncpy(g_store_sshcmd, argv[5], sizeof(g_store_sshcmd));
    } else if (is_config_add(argv, "user.signingkey")) {
        safe_strncpy(g_store_signingkey, argv[5], sizeof(g_store_signingkey));
    } else if (is_config_add(argv, "commit.gpgsign")) {
        safe_strncpy(g_store_gpgsign, argv[5], sizeof(g_store_gpgsign));
    } else if (is_config_add(argv, "gpg.program")) {
        safe_strncpy(g_store_gpgprogram, argv[5], sizeof(g_store_gpgprogram));
    } else if (is_config_add(argv, "gpg.format")) {
        safe_strncpy(g_store_gpgformat, argv[5], sizeof(g_store_gpgformat));
    } else if (is_config_add(argv, "gpg.openpgp.program")) {
        safe_strncpy(g_store_gpgopenpgp, argv[5], sizeof(g_store_gpgopenpgp));
    } else if (is_config_add(argv, "gpg.x509.program")) {
        safe_strncpy(g_store_gpgx509, argv[5], sizeof(g_store_gpgx509));
    } else if (is_config_add(argv, "gpg.ssh.program")) {
        safe_strncpy(g_store_gpgssh, argv[5], sizeof(g_store_gpgssh));
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "user.name")) {
        g_store_name[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "user.email")) {
        g_store_email[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "core.sshcommand")) {
        g_store_sshcmd[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "user.signingkey")) {
        g_store_signingkey[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "commit.gpgsign")) {
        g_store_gpgsign[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "gpg.program")) {
        g_store_gpgprogram[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "gpg.format")) {
        g_store_gpgformat[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "gpg.openpgp.program")) {
        g_store_gpgopenpgp[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "gpg.x509.program")) {
        g_store_gpgx509[0] = '\0';
    } else if (is_global_config_command(argv) &&
               is_config_unset(argv, "gpg.ssh.program")) {
        g_store_gpgssh[0] = '\0';
    } else if (is_config_read(argv, "user.name") &&
               (!is_global_config_command(argv) || !g_store_name[0])) {
        exit_code = 1; /* not set: git reports failure */
    } else if (is_config_read(argv, "user.email") &&
               (!is_global_config_command(argv) || !g_store_email[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "core.sshcommand") &&
               (!is_global_config_command(argv) || !g_store_sshcmd[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "user.signingkey") &&
               (!is_global_config_command(argv) || !g_store_signingkey[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "commit.gpgsign") &&
               (!is_global_config_command(argv) || !g_store_gpgsign[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "gpg.program") &&
               (!is_global_config_command(argv) || !g_store_gpgprogram[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "gpg.format") &&
               (!is_global_config_command(argv) || !g_store_gpgformat[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "gpg.openpgp.program") &&
               (!is_global_config_command(argv) || !g_store_gpgopenpgp[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "gpg.x509.program") &&
               (!is_global_config_command(argv) || !g_store_gpgx509[0])) {
        exit_code = 1;
    } else if (is_config_read(argv, "gpg.ssh.program") &&
               (!is_global_config_command(argv) || !g_store_gpgssh[0])) {
        exit_code = 1;
    }

    if (result) {
        result->spawned = true;
        result->exit_code = exit_code;
        result->term_signal = 0;
        result->out_len = (opts && opts->out) ? strlen(opts->out) : 0;
    }
    return exit_code == 0 ? 0 : -1;
}

/* ---- git+ssh runner for the SSH-restart rollback test (AR-02 #30) -------- */

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

/* Bind and retain a real listening 0600 unix socket so both inode validation
 * and the kernel-authenticated peer probe see a live fake agent endpoint. */
static int bind_fake_agent_socket(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || strlen(path) >= sizeof(addr.sun_path)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    close_fake_agent_listener();
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    if (chmod(path, 0600) != 0) {
        close(fd);
        return -1;
    }
    g_fake_agent_listener = fd;
    return 0;
}

static int bind_fake_agent_socket_for_runner(const char *path,
                                             const run_opts_t *opts) {
    int saved_cwd;
    int rc;

    if (!opts || !opts->use_cwd_fd) {
        return bind_fake_agent_socket(path);
    }
    saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
    if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) {
        if (saved_cwd >= 0) close(saved_cwd);
        return -1;
    }
    rc = bind_fake_agent_socket(path);
    if (fchdir(saved_cwd) != 0) rc = -1;
    close(saved_cwd);
    return rc;
}

/* Extends fake_runner with a working fake ssh-agent (binds the -a socket), a
 * happy ssh-add, and matching identity/fingerprint probes, so accounts_switch
 * can walk the full SSH activation and the rollback can genuinely re-start
 * the previous account's agent. git handling is delegated to fake_runner.
 * The reported agent PID is far above any platform's pid_max so the later
 * teardown's reaper can never find — let alone signal — a real process behind
 * it. */
static ssh_reap_test_ops_t g_previous_reap_ops;

static int capture_rollback_process_generation(
    pid_t pid, ssh_process_generation_t *generation) {
    if (!generation) {
        errno = EINVAL;
        return -1;
    }
    if (pid == (pid_t)FAKE_AGENT_PID) {
        *generation = (ssh_process_generation_t) {
            .kind = SSH_PROCESS_GENERATION_LINUX,
            .boot_hi = UINT64_C(0x0102030405060708),
            .boot_lo = UINT64_C(0x1112131415161718),
            .start_hi = UINT64_C(0x2122232425262728),
            .start_lo = UINT64_C(0x3132333435363738),
        };
        return 0;
    }
    return ssh_manager_test_capture_process_generation(pid, generation);
}

static int retire_fake_agent_pidfd_open(pid_t pid) {
    if (pid == (pid_t)FAKE_AGENT_PID) {
        close_fake_agent_listener();
        errno = ESRCH;
        return -1;
    }
    if (g_previous_reap_ops.pidfd_open) {
        return g_previous_reap_ops.pidfd_open(pid);
    }
    errno = ENOSYS;
    return -1;
}

static bool ssh_probe_observes_committed_switch(void) {
    char config[4096];
    char header[MAX_NAME_LEN + sizeof("Host \n")];
    char current_socket[MAX_PATH_LEN];
    char socket_target[MAX_PATH_LEN];
    ssize_t socket_target_len;
    account_t *target;

    if (!g_probe_expected_ctx) return true;
    target = &g_probe_expected_ctx->accounts[0];
    if (g_probe_expected_ctx->current_account != target ||
        strcmp(g_probe_expected_ctx->config.active_account, target->name) != 0 ||
        strcmp(g_store_name, target->name) != 0 ||
        strcmp(g_store_email, target->email) != 0 ||
        !strstr(g_store_sshcmd, target->ssh_key_path)) {
        return false;
    }
    if (g_probe_expected_config_path && g_probe_expected_alias) {
        if (read_file_to_string(g_probe_expected_config_path, config,
                                sizeof(config)) < 0 ||
            snprintf(header, sizeof(header), "Host %s\n",
                     g_probe_expected_alias) < 0 ||
            !strstr(config, header)) {
            return false;
        }
    }
    if (safe_snprintf(current_socket, sizeof(current_socket),
                      "%s/gitswitch-ssh/current.sock", g_xdg) != 0) {
        return false;
    }
    socket_target_len = readlink(current_socket, socket_target,
                                 sizeof(socket_target) - 1U);
    if (socket_target_len <= 0) return false;
    socket_target[socket_target_len] = '\0';
    return strstr(socket_target, "ssh-agent.testacct.sock") != NULL;
}

static int ssh_git_runner(const char *const argv[], const run_opts_t *opts,
                          run_result_t *result) {
    if (g_finalizing_observer_ctx) observe_finalizing_switch_phase();
    if (g_probe_failure_pending_observation && strcmp(argv[0], "ssh") != 0) {
        g_post_probe_error = *get_last_error();
        g_post_probe_errno = errno;
        g_post_probe_generation = error_report_generation();
        g_post_probe_diagnostic_observed = true;
        g_probe_failure_pending_observation = false;
    }
    g_ssh_git_runner_calls++;
    if (opts && opts->use_deadline) {
        if (strcmp(argv[0], "ssh") == 0) {
            g_deadlined_ssh_probes++;
            g_ssh_probe_deadline = opts->deadline_millis;
        } else {
            g_deadlined_nonprobe_commands++;
        }
    }
    if (strcmp(argv[0], "ssh") == 0) {
        bool alias_probe = false;

        g_probe_error_before = *get_last_error();
        g_probe_errno_before = errno;
        g_probe_generation_before = error_report_generation();
        g_ssh_connection_probes++;
        g_ssh_probe_target[0] = '\0';
        g_ssh_probe_hostname[0] = '\0';
        for (size_t i = 1; argv[i]; i++) {
            if (strncmp(argv[i], "HostName=", sizeof("HostName=") - 1U) == 0) {
                alias_probe = true;
                safe_strncpy(g_ssh_probe_hostname, argv[i],
                             sizeof(g_ssh_probe_hostname));
            }
            if (strncmp(argv[i], "git@", sizeof("git@") - 1U) == 0) {
                safe_strncpy(g_ssh_probe_target, argv[i],
                             sizeof(g_ssh_probe_target));
            }
        }
        if (alias_probe) {
            g_ssh_alias_probes++;
        } else {
            g_ssh_default_probes++;
        }
        g_probe_observed_committed_state =
            ssh_probe_observes_committed_switch();
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = !g_spawn_fail_ssh_probe;
            result->exit_code =
                g_spawn_fail_ssh_probe
                    ? -1
                    : (g_fail_ssh_probe || g_timeout_ssh_probe) ? 255 : 1;
            result->timed_out = g_timeout_ssh_probe;
        }
        if (opts && opts->out && opts->out_size > 0) {
            if (g_fail_ssh_probe) {
                snprintf(opts->out, opts->out_size,
                         "git@github.com: Permission denied (publickey).");
            } else if (g_timeout_ssh_probe || g_spawn_fail_ssh_probe) {
                opts->out[0] = '\0';
            } else {
                snprintf(opts->out, opts->out_size,
                         "Hi testacct! You've successfully authenticated, "
                         "but GitHub does not provide shell access.\n");
            }
            if (result) result->out_len = strlen(opts->out);
        }
        if (g_fail_ssh_probe || g_timeout_ssh_probe ||
            g_spawn_fail_ssh_probe) {
            g_probe_failure_pending_observation = true;
            errno = g_timeout_ssh_probe
                        ? ETIMEDOUT
                        : g_spawn_fail_ssh_probe ? ENOENT : EACCES;
            set_system_error(ERR_SYSTEM_COMMAND_FAILED,
                             g_timeout_ssh_probe
                                 ? "Injected SSH connection probe timeout"
                                 : g_spawn_fail_ssh_probe
                                       ? "Injected SSH probe spawn failure"
                                       : "Injected SSH authentication failure");
            return -1;
        }
        return 0;
    }
    if (is_ssh_agent_command(argv[0])) {
        g_ssh_activation_commands++;
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
        if (g_log) { fprintf(g_log, "ssh-agent -a %s\n", sock); fflush(g_log); }
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
        }
        if (certify_agent_launch(argv[0], result) != 0) return -1;
        if (bind_fake_agent_socket_for_runner(sock, opts) != 0) return -1;
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n",
                     sock, FAKE_AGENT_PID);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-l") == 0) {
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
        }
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s loaded-key (ED25519)\n", FAKE_AGENT_FP);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
        }
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size,
                     "256 %s key-file (ED25519)\n", FAKE_AGENT_FP);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0) {
        g_ssh_activation_commands++;
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            result->exit_code = g_fail_ssh_add ? 1 : 0;
        }
        if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
        return g_fail_ssh_add ? -1 : 0;
    }
    return fake_runner(argv, opts, result);
}

static const char g_concurrent_config_content[] =
    "Host concurrently-replaced\n  IdentityFile /tmp/id_concurrent\n";
static char g_concurrent_config_path[1024];
static bool g_replace_config_on_user_name;
static bool g_replace_config_with_symlink_on_user_name;

static int fail_alias_postrename_verification(int dir_fd) {
    (void)dir_fd;
    errno = EIO;
    return -1;
}

static int fail_alias_dirsync(int dir_fd) {
    (void)dir_fd;
    errno = EIO;
    return -1;
}

static int fail_alias_before_rename(int dir_fd, const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    errno = EIO;
    return -1;
}

static int replace_git_name_and_fail_alias_commit(int dir_fd,
                                                  const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    safe_strncpy(g_store_name, "Concurrent Name", sizeof(g_store_name));
    return -1;
}

static int replace_ssh_config_concurrently(void) {
    char replacement_path[1100];
    FILE *f;
    bool write_failed;

    if ((size_t)snprintf(replacement_path, sizeof(replacement_path), "%s.concurrent",
                         g_concurrent_config_path) >= sizeof(replacement_path)) {
        return -1;
    }
    f = fopen(replacement_path, "w");
    if (!f) {
        return -1;
    }
    write_failed = fputs(g_concurrent_config_content, f) == EOF;
    if (fclose(f) != 0) {
        write_failed = true;
    }
    if (write_failed) {
        unlink(replacement_path);
        return -1;
    }
    if (chmod(replacement_path, 0640) != 0 ||
        rename(replacement_path, g_concurrent_config_path) != 0) {
        unlink(replacement_path);
        return -1;
    }
    return 0;
}

static int replace_ssh_config_with_symlink(void) {
    char target_path[1100];
    char link_path[1100];
    FILE *f;
    bool write_failed;

    if ((size_t)snprintf(target_path, sizeof(target_path), "%s.target",
                         g_concurrent_config_path) >= sizeof(target_path) ||
        (size_t)snprintf(link_path, sizeof(link_path), "%s.concurrent-link",
                         g_concurrent_config_path) >= sizeof(link_path)) {
        return -1;
    }
    f = fopen(target_path, "w");
    if (!f) return -1;
    write_failed = fputs(g_concurrent_config_content, f) == EOF;
    if (fclose(f) != 0) write_failed = true;
    if (write_failed) {
        (void)unlink(target_path);
        return -1;
    }
    if (chmod(target_path, 0640) != 0 || symlink(target_path, link_path) != 0 ||
        rename(link_path, g_concurrent_config_path) != 0) {
        (void)unlink(link_path);
        (void)unlink(target_path);
        return -1;
    }
    return 0;
}

/* Replace ~/.ssh/config during the reversible Git step, after preflight but
 * before the host-alias writer's final commit. A failing Git write must never
 * be followed by an alias write or rollback rewrite, so the replacement wins. */
static int concurrent_config_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    if (g_replace_config_on_user_name && is_config_write(argv, "user.name")) {
        g_replace_config_on_user_name = false;
        if (replace_ssh_config_concurrently() != 0) {
            if (result) {
                memset(result, 0, sizeof(*result));
                result->spawned = true;
                result->exit_code = 1;
            }
            return -1;
        }
    }
    if (g_replace_config_with_symlink_on_user_name &&
        is_config_write(argv, "user.name")) {
        g_replace_config_with_symlink_on_user_name = false;
        if (replace_ssh_config_with_symlink() != 0) {
            if (result) {
                memset(result, 0, sizeof(*result));
                result->spawned = true;
                result->exit_code = 1;
            }
            return -1;
        }
    }
    return ssh_git_runner(argv, opts, result);
}

/* ---- ctx factory ---------------------------------------------------------- */

/* Hand-built contexts in this suite model accounts that already came from a
 * fully migrated persisted document. Derive a stable, canonical 256-bit token
 * from the fixture ID so multi-account contexts never accidentally share one
 * incarnation. Tests that explicitly exercise legacy accounts clear it. */
static void bind_rollback_test_incarnation(account_t *account) {
    static const char hexadecimal[] = "0123456789ABCDEF";
    uint32_t value;

    if (!account) return;
    memset(account->incarnation, '0', ACCOUNT_INCARNATION_HEX_LEN);
    value = account->id;
    for (size_t i = 0; i < sizeof(value) * 2U; i++) {
        account->incarnation[ACCOUNT_INCARNATION_HEX_LEN - 1U - i] =
            hexadecimal[value & 0x0FU];
        value >>= 4U;
    }
    account->incarnation[ACCOUNT_INCARNATION_HEX_LEN] = '\0';
    account->incarnation_persisted = true;
}

/* One SSH/GPG-disabled account with global preferred scope (avoids both real
 * agent startup and the not-in-a-repo consent prompt). */
static gitswitch_ctx_t make_ctx(void) {
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    account_t *a = &ctx.accounts[0];
    a->id = 1;
    bind_rollback_test_incarnation(a);
    safe_strncpy(a->name, "testacct", sizeof(a->name));
    safe_strncpy(a->email, "test@example.com", sizeof(a->email));
    safe_strncpy(a->description, "test account", sizeof(a->description));
    a->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx.account_count = 1;
    safe_strncpy(ctx.config.config_path, "/tmp/gsw_rollback_accounts.toml",
                 sizeof(ctx.config.config_path));
    return ctx;
}

static int prepare_switch_expect(
    gitswitch_ctx_t *ctx, const char *identifier,
    accounts_switch_prepare_state_t expected_state) {
    accounts_switch_prepare_state_t state =
        expected_state == ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE
            ? ACCOUNTS_SWITCH_PREPARE_PREPARED
            : ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;
    int rc = accounts_switch_prepare_result(ctx, identifier, &state);

    CHECK_EQ_INT(state, expected_state);
    return rc;
}

static int commit_switch_expect(
    gitswitch_ctx_t *ctx,
    accounts_switch_commit_state_t expected_state) {
    accounts_switch_commit_state_t state =
        expected_state == ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED
            ? ACCOUNTS_SWITCH_COMMIT_COMPLETE
            : ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    int rc = accounts_switch_commit_result(ctx, &state);

    CHECK_EQ_INT(state, expected_state);
    return rc;
}

/* Add the pre-switch account that owns the saved/current metadata. Runtime
 * capabilities are enabled by individual cases only when they are relevant. */
static account_t *add_previous_account(gitswitch_ctx_t *ctx) {
    account_t *prev = &ctx->accounts[1];
    memset(prev, 0, sizeof(*prev));
    prev->id = 2;
    bind_rollback_test_incarnation(prev);
    safe_strncpy(prev->name, "prev", sizeof(prev->name));
    safe_strncpy(prev->email, "prev@example.com", sizeof(prev->email));
    safe_strncpy(prev->description, "previous account", sizeof(prev->description));
    prev->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx->account_count = 2;
    ctx->current_account = prev;
    safe_strncpy(ctx->config.active_account, prev->name,
                 sizeof(ctx->config.active_account));
    return prev;
}

static void seed_previous_git_identity(void) {
    git_ops_test_reset_caches();
    g_user_name_writes = 0;
    g_fake_runner_calls = 0;
    safe_strncpy(g_store_name, "Previous Name", sizeof(g_store_name));
    safe_strncpy(g_store_email, "prev@example.com", sizeof(g_store_email));
    g_store_sshcmd[0] = '\0';
    g_store_signingkey[0] = '\0';
    g_store_gpgsign[0] = '\0';
    g_store_gpgformat[0] = '\0';
    g_store_gpgprogram[0] = '\0';
    g_store_gpgopenpgp[0] = '\0';
    g_store_gpgx509[0] = '\0';
    g_store_gpgssh[0] = '\0';
    g_preseal_gpgopenpgp_observed[0] = '\0';
    g_effective_signingkey_observed[0] = '\0';
    g_fail_list_config = false;
    g_mutate_name_before_seal = false;
    g_fail_ssh_add = false;
    g_ssh_activation_commands = 0;
    g_ssh_connection_probes = 0;
    g_ssh_alias_probes = 0;
    g_ssh_default_probes = 0;
    g_deadlined_ssh_probes = 0;
    g_deadlined_nonprobe_commands = 0;
    g_ssh_probe_deadline = -1;
    g_fail_ssh_probe = false;
    g_timeout_ssh_probe = false;
    g_spawn_fail_ssh_probe = false;
    g_ssh_probe_target[0] = '\0';
    g_ssh_probe_hostname[0] = '\0';
    g_probe_expected_ctx = NULL;
    g_probe_expected_config_path = NULL;
    g_probe_expected_alias = NULL;
    g_probe_observed_committed_state = false;
    memset(&g_probe_error_before, 0, sizeof(g_probe_error_before));
    g_probe_errno_before = 0;
    g_probe_generation_before = 0U;
    g_probe_failure_pending_observation = false;
    g_post_probe_diagnostic_observed = false;
    memset(&g_post_probe_error, 0, sizeof(g_post_probe_error));
    g_post_probe_errno = 0;
    g_post_probe_generation = 0U;
}

static int write_fake_key(const char *path);

/* ---- tests ---------------------------------------------------------------- */

/* AR-11 M8: durable Git provenance may only be attributed to an account that
 * has an immutable incarnation from a completed full-document save. A legacy
 * in-memory target must fail before Git inspection, runtime teardown, or
 * active-account publication rather than creating ownerless Git state. */
TEST(unpersisted_target_fails_before_switch_mutation) {
    error_context_t failure;
    int returned_errno;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    gitswitch_ctx_t ctx = make_ctx();
    memset(ctx.accounts[0].incarnation, 0,
           sizeof(ctx.accounts[0].incarnation));
    ctx.accounts[0].incarnation_persisted = false;
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    clear_error();
    errno = 0;

    command_runner_fn previous = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    returned_errno = errno;
    failure = *get_last_error();
    run_set_runner(previous);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(returned_errno, ESTALE);
    CHECK_EQ_INT(failure.code, ERR_CONFIG_INVALID);
    CHECK(strstr(failure.message, "no persisted immutable incarnation") !=
          NULL);
    CHECK_EQ_INT(g_fake_runner_calls, 0);
    CHECK_EQ_INT(g_user_name_writes, 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.config.active_account[0] == '\0');
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* AR-07 T1: snapshot acquisition is the Git transaction boundary. Fail only
 * the first worktree-scope probe: if accounts_switch ever ignores the
 * snapshot error, git_set_config's second probe succeeds and this test sees a
 * forbidden user.name write. */
TEST(snapshot_failure_aborts_before_any_git_write) {
    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    seed_previous_git_identity();
    g_worktree_probe_failures = 1;
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous);
    g_worktree_probe_failures = 0;
    g_fail_list_config = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_user_name_writes, 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK(strstr(get_last_error()->message,
                 "Cannot inspect Git worktree configuration") != NULL);
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* AR-08 M22 / AR-09 M4 phase 1: signals_guard_begin() is the final
 * fail-before-mutation boundary. Failure after one earlier handler was
 * installed must discard the already-captured Git snapshot, release the
 * runtime lock, and return without publishing an abort handle. */
TEST(signal_guard_failure_aborts_before_switch_mutation) {
    error_context_t failure;
    int returned_errno;
    int seal_rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    gitswitch_ctx_t ctx = make_ctx();
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;

    signals_guard_end();
    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_INSTALL,
                                EPERM);
    clear_error();
    errno = 0;
    command_runner_fn previous = run_set_runner(fake_runner);
    int rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    returned_errno = errno;
    failure = *get_last_error();
    seal_rc = git_config_seal();
    run_set_runner(previous);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(returned_errno, EPERM);
    CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(failure.system_errno, EPERM);
    CHECK_EQ_INT(g_user_name_writes, 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.config.active_account[0] == '\0');
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
    CHECK_EQ_INT(seal_rc, -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);

    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

/* AR-07 M24: the exact config listing is acquired before runtime activation,
 * not merely before the first Git write. A failed read must not spawn an
 * agent and then rely on runtime rollback to hide the ordering mistake. */
TEST(snapshot_listing_failure_aborts_before_ssh_activation) {
    char key_path[512];

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *target = &ctx.accounts[0];
    snprintf(key_path, sizeof(key_path), "%s/key_target", g_xdg);
    CHECK_EQ_INT(write_fake_key(key_path), 0);
    target->ssh_enabled = true;
    safe_strncpy(target->ssh_key_path, key_path,
                 sizeof(target->ssh_key_path));

    seed_previous_git_identity();
    g_fail_list_config = true;
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_ssh_activation_commands = 0;
    g_log = NULL;
    command_runner_fn previous = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous);
    g_fail_list_config = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_user_name_writes, 0);
    CHECK_EQ_INT(g_ssh_activation_commands, 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(strstr(get_last_error()->message,
                 "Cannot snapshot Git configuration") != NULL);
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* F4: a switch that fails AT the git-config step must leave the previous
 * account's current.sock and GNUPGHOME symlink untouched (teardown of the
 * previous runtime isolation is deferred past the point of no return). */
TEST(failed_git_config_keeps_previous_runtime_isolation) {
    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);
    g_fail_user_name_set = false;

    CHECK_EQ_INT(rc, -1);
    /* The previous account's entry points must still be there. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* The deferred teardown must still HAPPEN on success — otherwise the original
 * mixed-identity hazard (old agent live behind a new git identity) returns. */
TEST(successful_switch_still_tears_down_previous_isolation) {
    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);
    /* M3: a successful switch leaves the guard armed for main()'s save;
     * mimic main() and drop it so this test process isn't left guarded. */
    signals_guard_end();

    CHECK_EQ_INT(rc, 0);
    /* Target has SSH/GPG disabled: the previous entry points must be gone. */
    CHECK(!symlink_present(g_ssh_sock));
    CHECK(!symlink_present(g_gpg_link));
}

/* AR-04 transaction closeout / AR-09 M4 phase 7: Git has already been written
 * when teardown of a disabled target's previous runtime runs. A persistent
 * teardown obstruction makes the immediate rollback incomplete, so failed
 * prepare must publish an abort-only retry record after releasing its shared
 * lock; removing the obstruction lets the explicit retry finish. */
TEST(late_runtime_teardown_failure_rolls_back_git_and_gpg) {
    char lock_path[512];
    char gpg_target[512];
    ssize_t n;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-ssh/.lock", g_xdg);
    CHECK_EQ_INT(mkdir(lock_path, 0700), 0); /* open(O_CREAT) must fail */

    gitswitch_ctx_t ctx = make_ctx();
    account_t *prev_account = add_previous_account(&ctx);
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;

    command_runner_fn previous_runner = run_set_runner(fake_runner);
    int rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED);
    run_set_runner(previous_runner);
    g_fail_list_config = false;

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == prev_account);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(symlink_present(g_ssh_sock));
    n = readlink(g_gpg_link, gpg_target, sizeof(gpg_target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        gpg_target[n] = '\0';
        CHECK(strstr(gpg_target, "/prevhome") != NULL);
    }
    CHECK(strstr(get_last_error()->details,
                 "[SSH runtime deactivation]") != NULL);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);

    CHECK_EQ_INT(rmdir(lock_path), 0);
    previous_runner = run_set_runner(fake_runner);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    run_set_runner(previous_runner);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* AR-02 #12: a switch to an SSH-enabled target whose SSH setup fails at
 * ssh_manager_init — which only PATH-probes ssh-agent/ssh-add and touches no
 * agent — must NOT tear down the previous account's runtime isolation. The
 * pre-fix code marked the SSH state dirty before init ran, so this pure
 * lookup failure reaped the previous account's healthy agent and unlinked
 * current.sock for a switch that never started. */
TEST(ssh_init_failure_keeps_previous_runtime_isolation) {
    char key_path[512], emptybin[512];
    const char *env_path;
    char *saved_path;
    bool saved_path_present;
    error_context_t failure;
    FILE *kf;

    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *a = &ctx.accounts[0];
    a->ssh_enabled = true;
    /* A real 0600 private-key-shaped file. The injected SSH runner below
     * supplies a valid OpenSSH fingerprint for this exact preflight, so the
     * switch reaches ssh_manager_init even after PATH is intentionally
     * reduced to an empty trusted directory. */
    snprintf(key_path, sizeof(key_path), "%s/key_ed25519", g_xdg);
    kf = fopen(key_path, "w");
    CHECK(kf != NULL);
    if (kf) {
        fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
              "-----END OPENSSH PRIVATE KEY-----\n", kf);
        fclose(kf);
    }
    CHECK_EQ_INT(chmod(key_path, 0600), 0);
    safe_strncpy(a->ssh_key_path, key_path, sizeof(a->ssh_key_path));

    /* Warm the process-wide git-availability cache BEFORE crippling PATH, so
     * the switch fails exactly at ssh_manager_init's ssh-agent probe and not
     * earlier at git_ops_init. */
    CHECK_EQ_INT(git_ops_init(), 0);

    /* Cripple PATH: an empty (but trusted) dir makes command_exists fail for
     * ssh-agent/ssh-add without any agent operation being attempted. */
    env_path = getenv("PATH");
    saved_path_present = env_path != NULL;
    saved_path = env_path ? strdup(env_path) : NULL;
    CHECK(!saved_path_present || saved_path != NULL);
    if (saved_path_present && !saved_path) return;
    snprintf(emptybin, sizeof(emptybin), "%s/emptybin", g_xdg);
    CHECK_EQ_INT(mkdir(emptybin, 0755), 0);
    CHECK_EQ_INT(setenv("PATH", emptybin, 1), 0);

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(ssh_git_runner);
    int rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    failure = *get_last_error();
    run_set_runner(prev);
    CHECK_EQ_INT(saved_path_present ? setenv("PATH", saved_path, 1)
                                    : unsetenv("PATH"),
                 0);
    if (saved_path_present) {
        CHECK_STR_EQ(getenv("PATH"), saved_path);
    } else {
        CHECK(getenv("PATH") == NULL);
    }
    free(saved_path);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(failure.code, ERR_SSH_AGENT_NOT_FOUND);
    CHECK(strstr(failure.message, "ssh-agent command not found") != NULL);
    /* The previous account's entry points were never disturbed and must
     * survive; pre-fix the abort path reaped them. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* AR-09 M4 phase 3: ssh_manager_init may succeed and ssh_switch_account may
 * then fail at ssh-add. This is the first phase with newly-created runtime
 * state; its failed prepare must reap that state and release every transaction
 * owner synchronously. */
TEST(prepared_ssh_switch_failure_releases_transaction_ownership) {
    char key_path[512];
    error_context_t failure;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    CHECK((size_t)snprintf(key_path, sizeof(key_path), "%s/key_target",
                           g_xdg) < sizeof(key_path));
    CHECK_EQ_INT(write_fake_key(key_path), 0);
    ctx.accounts[0].ssh_enabled = true;
    safe_strncpy(ctx.accounts[0].ssh_key_path, key_path,
                 sizeof(ctx.accounts[0].ssh_key_path));
    seed_previous_git_identity();
    g_fail_ssh_add = true;
    previous_runner = run_set_runner(ssh_git_runner);
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    failure = *get_last_error();
    run_set_runner(previous_runner);
    g_fail_ssh_add = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(failure.code, ERR_SSH_KEY_LOAD_FAILED);
    CHECK(strstr(failure.message, "Failed to add SSH key") != NULL);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.config.active_account[0] == '\0');
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* A repeated switch used to call accounts_session_cleanup() before taking its
 * rollback snapshot or validating the next target. Consequently, a malformed
 * second target could stop the first switch's owned agent and return early
 * with current.sock dangling. The read-only failure must leave both the
 * in-process session and its published live socket untouched. */
TEST(repeated_switch_validation_failure_keeps_live_session) {
    char first_key[512];
    char target[512];
    ssize_t target_len;
    gitswitch_ctx_t init_target;
    gitswitch_ctx_t init_before;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *first = &ctx.accounts[0];
    snprintf(first_key, sizeof(first_key), "%s/key_first", g_xdg);
    CHECK_EQ_INT(write_fake_key(first_key), 0);
    first->ssh_enabled = true;
    safe_strncpy(first->ssh_key_path, first_key,
                 sizeof(first->ssh_key_path));

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_fail_list_config = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    signals_guard_end();

    /* AR-11 M1: accounts_init owns caller model storage only. It must reject
     * byte-exactly while the first switch still owns a live process-global
     * SSH session, leaving the original session record available for the
     * exact cleanup below. */
    memset(&init_target, 0x5A, sizeof(init_target));
    init_before = init_target;
    CHECK_EQ_INT(accounts_init(&init_target), -1);
    CHECK(memcmp(&init_target, &init_before, sizeof(init_target)) == 0);

    target_len = readlink(g_ssh_sock, target, sizeof(target) - 1);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK(path_exists(target));
    }

    account_t *broken = &ctx.accounts[1];
    memset(broken, 0, sizeof(*broken));
    broken->id = 2;
    bind_rollback_test_incarnation(broken);
    safe_strncpy(broken->name, "broken", sizeof(broken->name));
    safe_strncpy(broken->email, "broken@example.com", sizeof(broken->email));
    safe_strncpy(broken->description, "invalid second target",
                 sizeof(broken->description));
    broken->preferred_scope = GIT_SCOPE_GLOBAL;
    broken->ssh_enabled = true;
    safe_strncpy(broken->ssh_key_path, "/definitely/missing/gitswitch-key",
                 sizeof(broken->ssh_key_path));
    ctx.account_count = 2;

    CHECK_EQ_INT(accounts_switch(&ctx, "broken"), -1);
    CHECK(ctx.current_account == first);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");

    target_len = readlink(g_ssh_sock, target, sizeof(target) - 1);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK(path_exists(target));
    }

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    CHECK_EQ_INT(accounts_init(&init_target), 0);
    CHECK_EQ_INT(init_target.account_count, 0);
    CHECK(init_target.current_account == NULL);
    run_set_runner(previous_runner);
    g_fail_list_config = false;
}

/* AR-09 M4 phase 2: if guarded cleanup of the prior owned agent cannot prove
 * it dead, a prepared repeated switch must stop and publish an abort-only
 * retry. The old live session remains the only truthful state until that
 * checked abort finishes. */
TEST(repeated_switch_reap_failure_preserves_live_session) {
    char first_key[512];
    char second_key[512];
    char first_target[512];
    char target_after[512];
    char auth_sock_before[512];
    char agent_pid_before[64];
    ssize_t first_len;
    ssize_t after_len;
    ssh_reap_fn previous_reap;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *first = &ctx.accounts[0];
    snprintf(first_key, sizeof(first_key), "%s/key_first", g_xdg);
    CHECK_EQ_INT(write_fake_key(first_key), 0);
    first->ssh_enabled = true;
    safe_strncpy(first->ssh_key_path, first_key,
                 sizeof(first->ssh_key_path));

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_fail_list_config = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    signals_guard_end();

    first_len = readlink(g_ssh_sock, first_target, sizeof(first_target) - 1);
    CHECK(first_len > 0);
    if (first_len > 0) first_target[first_len] = '\0';
    CHECK(first_len > 0 && path_exists(first_target));
    safe_strncpy(auth_sock_before, getenv("SSH_AUTH_SOCK"),
                 sizeof(auth_sock_before));
    safe_strncpy(agent_pid_before, getenv("SSH_AGENT_PID"),
                 sizeof(agent_pid_before));

    account_t *second = &ctx.accounts[1];
    memset(second, 0, sizeof(*second));
    second->id = 2;
    bind_rollback_test_incarnation(second);
    safe_strncpy(second->name, "second", sizeof(second->name));
    safe_strncpy(second->email, "second@example.com", sizeof(second->email));
    safe_strncpy(second->description, "valid second target",
                 sizeof(second->description));
    second->preferred_scope = GIT_SCOPE_GLOBAL;
    second->ssh_enabled = true;
    snprintf(second_key, sizeof(second_key), "%s/key_second", g_xdg);
    CHECK_EQ_INT(write_fake_key(second_key), 0);
    safe_strncpy(second->ssh_key_path, second_key,
                 sizeof(second->ssh_key_path));
    ctx.account_count = 2;

    previous_reap = ssh_manager_set_reap_fn(refuse_session_agent_reap);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "second",
                     ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED),
                 -1);
    ssh_manager_set_reap_fn(previous_reap);

    CHECK(strstr(get_last_error()->details,
                 "[SSH runtime deactivation]") != NULL);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);

    CHECK(ctx.current_account == first);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), auth_sock_before);
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), agent_pid_before);
    after_len = readlink(g_ssh_sock, target_after, sizeof(target_after) - 1);
    CHECK_EQ_INT((int)after_len, (int)first_len);
    if (after_len > 0) {
        target_after[after_len] = '\0';
        CHECK_STR_EQ(target_after, first_target);
        CHECK(path_exists(target_after));
    }

    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    g_fail_list_config = false;
}

/* AR-08 M4: previous-session teardown is already a mutating switch phase.
 * Repeated signals raised from inside its reap callback must stay deferred
 * through the checked rollback. Before the fix, rollback deferral began only
 * after accounts_session_cleanup(), so the second raise terminated the child
 * before the callback's AFTER marker (and before any rollback reap). */
TEST(repeated_signals_during_previous_session_cleanup_wait_for_abort) {
    char first_key[512];
    char second_key[512];
    command_runner_fn previous_runner;
    gitswitch_ctx_t ctx;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    ctx = make_ctx();
    snprintf(first_key, sizeof(first_key), "%s/key_signal_first", g_xdg);
    CHECK_EQ_INT(write_fake_key(first_key), 0);
    ctx.accounts[0].ssh_enabled = true;
    safe_strncpy(ctx.accounts[0].ssh_key_path, first_key,
                 sizeof(ctx.accounts[0].ssh_key_path));

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_fail_list_config = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);

    memset(&ctx.accounts[1], 0, sizeof(ctx.accounts[1]));
    ctx.accounts[1].id = 2;
    bind_rollback_test_incarnation(&ctx.accounts[1]);
    safe_strncpy(ctx.accounts[1].name, "second",
                 sizeof(ctx.accounts[1].name));
    safe_strncpy(ctx.accounts[1].email, "second@example.com",
                 sizeof(ctx.accounts[1].email));
    safe_strncpy(ctx.accounts[1].description, "signal cleanup target",
                 sizeof(ctx.accounts[1].description));
    ctx.accounts[1].preferred_scope = GIT_SCOPE_GLOBAL;
    ctx.accounts[1].ssh_enabled = true;
    snprintf(second_key, sizeof(second_key), "%s/key_signal_second", g_xdg);
    CHECK_EQ_INT(write_fake_key(second_key), 0);
    safe_strncpy(ctx.accounts[1].ssh_key_path, second_key,
                 sizeof(ctx.accounts[1].ssh_key_path));
    ctx.account_count = 2;

    for (size_t signal_index = 0;
         signal_index < SWITCH_GUARDED_SIGNAL_COUNT; signal_index++) {
        char log_path[512];
        char line[256];
        bool cleanup_returned = false;
        bool previous_agent_restored_after_cleanup = false;
        int signal_number = switch_guarded_signals[signal_index];
        int status = 0;
        pid_t pid;

        CHECK((size_t)snprintf(log_path, sizeof(log_path),
                               "%s/session-cleanup-%d.log", g_xdg,
                               signal_number) < sizeof(log_path));
        fflush(NULL);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            struct sigaction default_action;

            if (accounts_switch(&ctx, "testacct") != 0) _exit(29);
            memset(&default_action, 0, sizeof(default_action));
            default_action.sa_handler = SIG_DFL;
            sigemptyset(&default_action.sa_mask);
            if (sigaction(signal_number, &default_action, NULL) != 0) _exit(30);
            g_log = fopen(log_path, "w");
            if (!g_log) _exit(31);
            g_session_reap_signal = signal_number;
            g_session_reap_calls = 0;
            g_session_reap_delegate =
                ssh_manager_set_reap_fn(signal_during_session_agent_reap);
            (void)accounts_switch(&ctx, "second");
            _exit(32); /* completed checked abort dispatches the signal */
        }

        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), signal_number);
        {
            FILE *log = fopen(log_path, "r");

            CHECK(log != NULL);
            if (log) {
                while (fgets(line, sizeof(line), log)) {
                    if (strstr(line, "MARK-SESSION-REAP-1-AFTER")) {
                        cleanup_returned = true;
                    }
                    if (cleanup_returned && strstr(line, "ssh-agent -a") &&
                        strstr(line, "ssh-agent.testacct.sock")) {
                        previous_agent_restored_after_cleanup = true;
                    }
                }
                fclose(log);
            }
        }
        CHECK(cleanup_returned);
        CHECK(previous_agent_restored_after_cleanup);
    }

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    g_fail_list_config = false;
}

/* Write a private-key-shaped 0600 file so ssh_validate_key_file accepts it. */
static int write_fake_key(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
          "-----END OPENSSH PRIVATE KEY-----\n", f);
    if (fclose(f) != 0) return -1;
    return chmod(path, 0600);
}

/* M2 at the accounts_switch boundary: a non-link current.sock cannot be
 * replaced atomically. The SSH manager's commit-point failure must propagate
 * before Git or active metadata changes, while unrelated GPG state survives. */
TEST(ssh_stable_link_obstruction_aborts_integrated_switch) {
    char key_path[512];

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(unlink(g_ssh_sock), 0);
    CHECK_EQ_INT(mkdir(g_ssh_sock, 0700), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *target = &ctx.accounts[0];
    account_t *prev_account = add_previous_account(&ctx);
    snprintf(key_path, sizeof(key_path), "%s/key_target", g_xdg);
    CHECK_EQ_INT(write_fake_key(key_path), 0);
    target->ssh_enabled = true;
    safe_strncpy(target->ssh_key_path, key_path, sizeof(target->ssh_key_path));

    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);
    g_fail_list_config = false;

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == prev_account);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(is_directory(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* AR-02 #30: the rollback branch that RE-STARTS the previous account's SSH
 * agent after a failed switch — starting the new account's agent has already
 * reaped it, so a symlink restore is not enough — was never exercised by any
 * test. Previous account "prev" is active; the switch to SSH-enabled
 * "testacct" activates a (fake) agent, then fails at the git-config write;
 * the rollback must leave current.sock pointing at a live agent socket for
 * "prev", not at the aborted target and not dangling. */
TEST(failed_switch_restarts_previous_accounts_agent) {
    char key_prev[512], key_target[512], target[512];
    ssize_t n;
    const char *base;

    /* The real ssh-agent/ssh-add must be findable for ssh_manager_init's
     * probes (the runner fakes the spawns themselves). */
    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *tgt = &ctx.accounts[0];
    account_t *prev = &ctx.accounts[1];
    memset(prev, 0, sizeof(*prev));
    prev->id = 2;
    bind_rollback_test_incarnation(prev);
    safe_strncpy(prev->name, "prev", sizeof(prev->name));
    safe_strncpy(prev->email, "prev@example.com", sizeof(prev->email));
    safe_strncpy(prev->description, "previous account", sizeof(prev->description));
    prev->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx.account_count = 2;
    ctx.current_account = prev;

    snprintf(key_prev, sizeof(key_prev), "%s/key_prev", g_xdg);
    snprintf(key_target, sizeof(key_target), "%s/key_target", g_xdg);
    CHECK_EQ_INT(write_fake_key(key_prev), 0);
    CHECK_EQ_INT(write_fake_key(key_target), 0);
    prev->ssh_enabled = true;
    safe_strncpy(prev->ssh_key_path, key_prev, sizeof(prev->ssh_key_path));
    tgt->ssh_enabled = true;
    safe_strncpy(tgt->ssh_key_path, key_target, sizeof(tgt->ssh_key_path));

    g_fail_user_name_set = true; /* fail exactly at the git-config write */
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev_runner = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev_runner);
    g_fail_user_name_set = false;

    CHECK_EQ_INT(rc, -1);

    /* current.sock must point at prev's re-started agent socket, and that
     * socket must actually exist — a symlink-only "restore" (or none) leaves
     * the user with git identity rolled back but no working agent. */
    n = readlink(g_ssh_sock, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        base = strrchr(target, '/');
        base = base ? base + 1 : target;
        CHECK_STR_EQ(base, "ssh-agent.prev.sock");
        CHECK(path_exists(target));
    }
}

/* ---- AR-03 M4: the durable ~/.ssh/config rewrite is rolled back ---------- */

/* Point HOME at a fresh dir under the fake runtime dir so the switch's
 * host-alias rewrite targets a throwaway ~/.ssh/config. Returns the previous
 * HOME value via saved (caller restores). */
static int setup_fake_home(char *home, size_t home_size,
                           char *saved, size_t saved_size) {
    const char *old = getenv("HOME");
    snprintf(saved, saved_size, "%s", old ? old : "");
    snprintf(home, home_size, "%s/home", g_xdg);
    if (mkdir(home, 0700) != 0) return -1;
    setenv("HOME", home, 1);
    return 0;
}

/* Build the two-account (prev active, SSH-enabled target) ctx the alias tests
 * share; target gets `alias`. Returns 0 on success. */
static int setup_alias_ctx(gitswitch_ctx_t *ctx, const char *alias) {
    char key_prev[512], key_target[512];
    account_t *tgt = &ctx->accounts[0];
    account_t *prev = &ctx->accounts[1];

    memset(prev, 0, sizeof(*prev));
    prev->id = 2;
    bind_rollback_test_incarnation(prev);
    safe_strncpy(prev->name, "prev", sizeof(prev->name));
    safe_strncpy(prev->email, "prev@example.com", sizeof(prev->email));
    safe_strncpy(prev->description, "previous account", sizeof(prev->description));
    prev->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx->account_count = 2;
    ctx->current_account = prev;

    snprintf(key_prev, sizeof(key_prev), "%s/key_prev", g_xdg);
    snprintf(key_target, sizeof(key_target), "%s/key_target", g_xdg);
    if (write_fake_key(key_prev) != 0 || write_fake_key(key_target) != 0) {
        return -1;
    }
    prev->ssh_enabled = true;
    safe_strncpy(prev->ssh_key_path, key_prev, sizeof(prev->ssh_key_path));
    tgt->ssh_enabled = true;
    safe_strncpy(tgt->ssh_key_path, key_target, sizeof(tgt->ssh_key_path));
    safe_strncpy(tgt->ssh_host_alias, alias, sizeof(tgt->ssh_host_alias));
    safe_strncpy(tgt->ssh_hostname, "github.com", sizeof(tgt->ssh_hostname));
    return 0;
}

static int setup_alias_config_file(char *home, size_t home_size,
                                   char *saved_home, size_t saved_home_size,
                                   char *config_path, size_t config_path_size,
                                   const char *content) {
    char ssh_dir[700];
    FILE *file;

    if (setup_fake_home(home, home_size, saved_home, saved_home_size) != 0 ||
        (size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) >=
            sizeof(ssh_dir) ||
        mkdir(ssh_dir, 0700) != 0 ||
        (size_t)snprintf(config_path, config_path_size, "%s/config",
                         ssh_dir) >= config_path_size) {
        return -1;
    }
    if (!content) return 0;
    file = fopen(config_path, "w");
    if (!file) return -1;
    if (fputs(content, file) == EOF || fclose(file) != 0) return -1;
    return chmod(config_path, 0600);
}

static int format_managed_alias_config(char *buffer, size_t buffer_size,
                                       const account_t *account) {
    int needed;

    if (!buffer || buffer_size == 0 || !account) return -1;
    needed = snprintf(
        buffer, buffer_size,
        "# >>> gitswitch %s >>>\n"
        "Host %s\n"
        "  HostName %s\n"
        "  IdentityFile \"%s\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch %s <<<\n",
        account->ssh_host_alias, account->ssh_host_alias,
        account->ssh_hostname, account->ssh_key_path,
        account->ssh_host_alias);
    return needed >= 0 && (size_t)needed < buffer_size ? needed : -1;
}

static int count_alias_config_temps(const char *ssh_dir) {
    DIR *dir = opendir(ssh_dir);
    struct dirent *entry;
    int count = 0;

    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "config.gitswitch.", 17) == 0) count++;
    }
    if (closedir(dir) != 0) return -1;
    return count;
}

/* The config transaction uses an opaque process-local token. Probe from a
 * fresh process so a leaked/reentrant registration cannot masquerade as an
 * available lock in the test process. */
static bool alias_config_lock_available_to_child(const char *ssh_dir) {
    int status = 0;
    pid_t pid;

    fflush(NULL);
    pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int dir_fd = open(ssh_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        int token_fd;

        if (dir_fd < 0) _exit(1);
        token_fd = try_lock_private_file_at(
            dir_fd, ".gitswitch-config.lock");
        if (token_fd < 0) {
            close(dir_fd);
            _exit(2);
        }
        unlock_private_file(token_fd);
        close(dir_fd);
        _exit(0);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int write_exact_bytes(const char *path, const void *bytes,
                             size_t length) {
    const unsigned char *cursor = bytes;
    size_t written = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    while (written < length) {
        ssize_t count = write(fd, cursor + written, length - written);

        if (count > 0) {
            written += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return -1;
        }
    }
    return close(fd);
}

static bool file_matches_exact_bytes(const char *path, const void *bytes,
                                     size_t length) {
    const unsigned char *expected = bytes;
    unsigned char chunk[256];
    size_t offset = 0;
    bool matches = true;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) return false;
    while (offset < length) {
        size_t wanted = length - offset;
        ssize_t count;

        if (wanted > sizeof(chunk)) wanted = sizeof(chunk);
        do {
            count = read(fd, chunk, wanted);
        } while (count < 0 && errno == EINTR);
        if (count <= 0 ||
            memcmp(chunk, expected + offset, (size_t)count) != 0) {
            matches = false;
            break;
        }
        offset += (size_t)count;
    }
    if (matches) {
        unsigned char extra;
        ssize_t count;

        do {
            count = read(fd, &extra, 1);
        } while (count < 0 && errno == EINTR);
        matches = count == 0;
    }
    if (close(fd) != 0) matches = false;
    return matches;
}

static bool ssh_probe_fixture_available(void) {
    return command_exists("ssh-agent") && command_exists("ssh-add") &&
           command_exists("ssh-keygen");
}

static int enable_switch_target_ssh(gitswitch_ctx_t *ctx,
                                    const char *alias) {
    char key_path[MAX_PATH_LEN];
    account_t *target;

    if (!ctx || ctx->account_count == 0 ||
        safe_snprintf(key_path, sizeof(key_path), "%s/key_target", g_xdg) != 0 ||
        write_fake_key(key_path) != 0) {
        return -1;
    }
    target = &ctx->accounts[0];
    target->ssh_enabled = true;
    if (safe_strncpy(target->ssh_key_path, key_path,
                     sizeof(target->ssh_key_path)) != 0) {
        return -1;
    }
    if (alias && alias[0] != '\0') {
        if (safe_strncpy(target->ssh_host_alias, alias,
                         sizeof(target->ssh_host_alias)) != 0 ||
            safe_strncpy(target->ssh_hostname, "github.com",
                         sizeof(target->ssh_hostname)) != 0) {
            return -1;
        }
    }
    return 0;
}

/* AR-11 L34: a freshly activated managed identity reaches the historical
 * best-effort connection probe exactly once, after Git, runtime, in-memory
 * account state, and the final alias bytes have all committed. */
TEST(fresh_alias_switch_runs_one_postcommit_probe) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700], after[4096];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int64_t deadline_lower;
    int64_t deadline_upper;
    int rc;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    g_probe_expected_ctx = &ctx;
    g_probe_expected_config_path = config_path;
    g_probe_expected_alias = "github.com-tgt";
    CHECK_EQ_INT(run_deadline_after_millis(0, &deadline_lower), 0);
    previous_runner = run_set_runner(ssh_git_runner);
    rc = accounts_switch(&ctx, "testacct");
    CHECK_EQ_INT(run_deadline_after_millis(7000, &deadline_upper), 0);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 1);
    CHECK_EQ_INT(g_ssh_alias_probes, 1);
    CHECK_EQ_INT(g_ssh_default_probes, 0);
    CHECK_EQ_INT(g_deadlined_ssh_probes, 1);
    CHECK_EQ_INT(g_deadlined_nonprobe_commands, 0);
    CHECK(g_ssh_probe_deadline >= deadline_lower + 7000);
    CHECK(g_ssh_probe_deadline <= deadline_upper);
    CHECK_STR_EQ(g_ssh_probe_target, "git@github.com-tgt");
    CHECK_STR_EQ(g_ssh_probe_hostname, "HostName=github.com");
    CHECK(g_ssh_activation_commands > 0);
    CHECK(g_probe_observed_committed_state);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK(strstr(after, "Host github.com-tgt\n") != NULL);
    CHECK(runtime_lock_available_to_child());

    g_probe_expected_ctx = NULL;
    g_probe_expected_config_path = NULL;
    g_probe_expected_alias = NULL;
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

/* The prepared path must retain the fresh-vs-reused activation outcome until
 * its later commit. A verbose alias-less switch probes the default GitHub
 * transport once at commit, never during prepare. */
TEST(prepared_verbose_fresh_switch_runs_one_default_probe) {
    gitswitch_ctx_t ctx;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    command_runner_fn previous_runner;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    ctx.config.verbose = true;
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, NULL), 0);
    seed_previous_git_identity();
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    g_probe_expected_ctx = &ctx;
    CHECK_EQ_INT(accounts_switch_commit_result(&ctx, &state), 0);

    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_COMPLETE);
    CHECK_EQ_INT(g_ssh_connection_probes, 1);
    CHECK_EQ_INT(g_ssh_alias_probes, 0);
    CHECK_EQ_INT(g_ssh_default_probes, 1);
    CHECK_STR_EQ(g_ssh_probe_target, "git@github.com");
    CHECK_STR_EQ(g_ssh_probe_hostname, "");
    CHECK(g_probe_observed_committed_state);
    CHECK(accounts_transaction_context_release_safe(&ctx));
    CHECK(runtime_lock_available_to_child());

    g_probe_expected_ctx = NULL;
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
}

/* Authentication, transport, and deadline failures are observational only.
 * The probe runner injects a structured timeout after verifying the exact
 * committed state visible at invocation; the successful switch must retain
 * that state and restore the caller-visible diagnostic it had beforehand. */
TEST(failed_postcommit_probe_preserves_switch_and_diagnostic) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700], after[4096];
    char output[4096];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    const error_context_t *observed_error;
    int rc;
    int observed_errno;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    g_timeout_ssh_probe = true;
    g_probe_expected_ctx = &ctx;
    g_probe_expected_config_path = config_path;
    g_probe_expected_alias = "github.com-tgt";
    clear_error();
    errno = 0;
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(capture_accounts_switch_output(
                     &ctx, "testacct", output, sizeof(output), &rc),
                 0);
    observed_error = get_last_error();
    observed_errno = errno;

    CHECK_EQ_INT(rc, 0);
    CHECK(strstr(output,
                 "SSH connection could not be verified (github.com-tgt)") !=
          NULL);
    CHECK(strstr(output, "unreachable") == NULL);
    CHECK_EQ_INT(g_ssh_connection_probes, 1);
    CHECK_EQ_INT(g_ssh_alias_probes, 1);
    CHECK_EQ_INT(g_ssh_default_probes, 0);
    CHECK_EQ_INT(g_deadlined_ssh_probes, 1);
    CHECK_EQ_INT(g_deadlined_nonprobe_commands, 0);
    CHECK(g_ssh_probe_deadline > 0);
    CHECK(g_probe_observed_committed_state);
    CHECK_EQ_INT(observed_error->code, g_probe_error_before.code);
    CHECK_STR_EQ(observed_error->message, g_probe_error_before.message);
    CHECK_STR_EQ(observed_error->details, g_probe_error_before.details);
    CHECK_EQ_INT(observed_error->system_errno,
                 g_probe_error_before.system_errno);
    CHECK(g_post_probe_diagnostic_observed);
    CHECK_EQ_INT(g_post_probe_error.code, g_probe_error_before.code);
    CHECK_STR_EQ(g_post_probe_error.message, g_probe_error_before.message);
    CHECK_STR_EQ(g_post_probe_error.details, g_probe_error_before.details);
    CHECK_EQ_INT(g_post_probe_error.system_errno,
                 g_probe_error_before.system_errno);
    CHECK_EQ_INT(g_post_probe_errno, g_probe_errno_before);
    CHECK(g_post_probe_generation == g_probe_generation_before);
    CHECK(observed_errno != ETIMEDOUT);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK(strstr(after, "Host github.com-tgt\n") != NULL);
    CHECK(ssh_probe_observes_committed_switch());
    CHECK(accounts_transaction_context_release_safe(&ctx));
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);

    g_timeout_ssh_probe = false;
    g_probe_expected_ctx = NULL;
    g_probe_expected_config_path = NULL;
    g_probe_expected_alias = NULL;
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

TEST(postcommit_probe_failure_messages_are_cause_neutral) {
    static const char original[] = "Host personal\n  User old\n";
    static const char *const causes[] = {
        "timeout",
        "authentication",
        "spawn",
    };
    size_t i;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    for (i = 0U; i < sizeof(causes) / sizeof(causes[0]); i++) {
        char home[600], saved_home[4096], config_path[700], output[4096];
        gitswitch_ctx_t ctx;
        command_runner_fn previous_runner;
        int rc;

        CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
        CHECK_EQ_INT(setup_alias_config_file(
                         home, sizeof(home), saved_home, sizeof(saved_home),
                         config_path, sizeof(config_path), original), 0);
        ctx = make_ctx();
        CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
        seed_previous_git_identity();
        g_timeout_ssh_probe = strcmp(causes[i], "timeout") == 0;
        g_fail_ssh_probe = strcmp(causes[i], "authentication") == 0;
        g_spawn_fail_ssh_probe = strcmp(causes[i], "spawn") == 0;
        previous_runner = run_set_runner(ssh_git_runner);

        CHECK_EQ_INT(capture_accounts_switch_output(
                         &ctx, "testacct", output, sizeof(output), &rc),
                     0);
        CHECK_EQ_INT(rc, 0);
        CHECK(strstr(
                  output,
                  "SSH connection could not be verified (github.com-tgt)") !=
              NULL);
        CHECK(strstr(output, "unreachable") == NULL);

        CHECK_EQ_INT(accounts_session_cleanup(), 0);
        run_set_runner(previous_runner);
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    }
}

/* Each existing policy exclusion gets an independent full-switch witness.
 * Fresh nonverbose no-alias and resume still activate SSH; dry-run and an
 * SSH-disabled account do not. None may execute a connection probe. */
TEST(postcommit_probe_policy_skip_matrix) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    previous_runner = run_set_runner(ssh_git_runner);

    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, NULL), 0);
    seed_previous_git_identity();
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK(g_ssh_activation_commands > 0);

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    ctx.config.resuming = true;
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK(g_ssh_activation_commands > 0);

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    ctx.config.dry_run = true;
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK_EQ_INT(g_ssh_activation_commands, 0);
    CHECK(ctx.current_account == NULL);
    CHECK_STR_EQ(ctx.config.active_account, "");

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, NULL), 0);
    ctx.accounts[0].ssh_enabled = false;
    safe_strncpy(ctx.accounts[0].ssh_host_alias, "github.com-tgt",
                 sizeof(ctx.accounts[0].ssh_host_alias));
    safe_strncpy(ctx.accounts[0].ssh_hostname, "github.com",
                 sizeof(ctx.accounts[0].ssh_hostname));
    seed_previous_git_identity();
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK_EQ_INT(g_ssh_activation_commands, 0);

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

/* A matching already-live account agent is adopted without loading a key or
 * contacting the host. Seed it outside accounts' process session so the
 * switch cannot reap it as a previous in-process activation first. */
TEST(reused_agent_skips_postcommit_probe) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    ssh_config_t seeded_agent;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(ssh_manager_init(&seeded_agent, SSH_AGENT_ISOLATED), 0);
    CHECK_EQ_INT(ssh_start_isolated_agent(&seeded_agent, &ctx.accounts[0]), 0);
    CHECK(seeded_agent.key_already_loaded);
    CHECK(g_ssh_activation_commands > 0);

    g_ssh_activation_commands = 0;
    g_ssh_connection_probes = 0;
    g_ssh_alias_probes = 0;
    g_ssh_default_probes = 0;
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK_EQ_INT(g_ssh_activation_commands, 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

/* M5 direct-library policy: once renameat has installed the alias, a failed
 * public-inode verification is a committed-but-uncertain switch, not a reason
 * to restore Git/runtime around the retained new alias. */
TEST(postrename_alias_verification_failure_retains_complete_direct_switch) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    char after[4096], detail[sizeof(g_last_error.message)];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_config_postrename_hook_fn previous_hook;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);
    previous_hook = ssh_manager_set_config_postrename_hook_fn(
        fail_alias_postrename_verification);
    rc = accounts_switch(&ctx, "testacct");
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    ssh_manager_set_config_postrename_hook_fn(previous_hook);

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    after[0] = '\0';
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK(strstr(after, "Host personal\n") != NULL);
    CHECK(strstr(after, "Host github.com-tgt\n") != NULL);
    CHECK(strstr(detail, "committed") != NULL);
    CHECK(strstr(detail, "public inode could not be verified") != NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    setenv("HOME", saved_home, 1);
}

/* The prepared/CLI boundary exposes the retained commit structurally. Main
 * consumes this exact state to keep its already-installed active file and
 * resume hint while exiting nonzero with truthful durability diagnostics. */
TEST(postrename_alias_fsync_failure_retains_complete_prepared_switch) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    char after[4096], detail[sizeof(g_last_error.message)];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_dirsync_fn previous_sync;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    previous_sync = ssh_manager_set_dirsync_fn(fail_alias_dirsync);
    rc = accounts_switch_commit_result(&ctx, &state);
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    ssh_manager_set_dirsync_fn(previous_sync);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(state,
                 ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    after[0] = '\0';
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK(strstr(after, "Host personal\n") != NULL);
    CHECK(strstr(after, "Host github.com-tgt\n") != NULL);
    CHECK(strstr(detail, "committed") != NULL);
    CHECK(strstr(detail, "directory-durable") != NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    signals_rollback_end();
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    setenv("HOME", saved_home, 1);
}

/* L35 parent durability fails before any alias bytes are public. The prepared
 * switch must therefore retain abort ownership instead of classifying the
 * empty, uncertain .ssh entry as an installed account commit. */
TEST(first_ssh_home_sync_failure_remains_abortable_preinstall) {
    char home[600], saved_home[4096], config_path[700], ssh_dir[700];
    char lock_path[760];
    error_context_t failure;
    struct stat directory_identity;
    struct stat directory_after_abort;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_dirsync_fn previous_sync;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home), saved_home,
                                 sizeof(saved_home)), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK((size_t)snprintf(config_path, sizeof(config_path), "%s/config",
                           ssh_dir) < sizeof(config_path));
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path),
                           "%s/.gitswitch-config.lock", ssh_dir) <
          sizeof(lock_path));
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    previous_sync = ssh_manager_set_dirsync_fn(fail_alias_dirsync);
    clear_error();
    rc = accounts_switch_commit_result(&ctx, &state);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(failure.system_errno, EIO);
    CHECK(strstr(failure.message, "HOME") != NULL);
    CHECK(strstr(failure.message, "uncertain") != NULL);
    CHECK_EQ_INT(lstat(ssh_dir, &directory_identity), 0);
    CHECK(S_ISDIR(directory_identity.st_mode));
    CHECK_EQ_INT(directory_identity.st_uid, getuid());
    CHECK_EQ_INT(directory_identity.st_mode & 0777, 0700);
    errno = 0;
    CHECK(access(config_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);

    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK(ctx.current_account == &ctx.accounts[1]);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_EQ_INT(lstat(ssh_dir, &directory_after_abort), 0);
    CHECK(S_ISDIR(directory_after_abort.st_mode));
    CHECK_EQ_INT(directory_after_abort.st_uid, getuid());
    CHECK_EQ_INT(directory_after_abort.st_mode & 0777, 0700);
    CHECK(directory_after_abort.st_dev == directory_identity.st_dev);
    CHECK(directory_after_abort.st_ino == directory_identity.st_ino);
    errno = 0;
    CHECK(access(config_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    setenv("HOME", saved_home, 1);
}

/* AR-11 L36: mode-only normalization is still a publication. If its secured
 * replacement fails before rename, the original byte-identical 0666 inode is
 * untouched and the prepared switch retains exact abort authority. */
TEST(identical_insecure_alias_prerename_failure_remains_abortable) {
    char home[600], saved_home[4096], config_path[700], ssh_dir[700];
    char lock_path[760], expected[4096];
    struct stat before;
    struct stat after;
    struct stat lock_identity;
    error_context_t failure;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_config_commit_hook_fn previous_hook;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN;
    size_t expected_len;
    int formatted;
    int before_fds;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), NULL), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path),
                           "%s/.gitswitch-config.lock", ssh_dir) <
          sizeof(lock_path));
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    formatted = format_managed_alias_config(
        expected, sizeof(expected), &ctx.accounts[0]);
    CHECK(formatted > 0);
    expected_len = formatted > 0 ? (size_t)formatted : 0U;
    CHECK_EQ_INT(write_exact_bytes(config_path, expected, expected_len), 0);

    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    before_fds = test_open_fd_count();
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_EQ_INT(chmod(config_path, 0666), 0);
    CHECK_EQ_INT(stat(config_path, &before), 0);
    CHECK(S_ISREG(before.st_mode));
    CHECK_EQ_INT(before.st_uid, getuid());
    CHECK_EQ_INT(before.st_mode & 0777, 0666);
    previous_hook = ssh_manager_set_config_commit_hook_fn(
        fail_alias_before_rename);
    clear_error();
    rc = accounts_switch_commit_result(&ctx, &state);
    failure = *get_last_error();
    ssh_manager_set_config_commit_hook_fn(previous_hook);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK(strstr(failure.message,
                 "Injected SSH config commit interruption") != NULL);
    CHECK(file_matches_exact_bytes(config_path, expected, expected_len));
    CHECK_EQ_INT(stat(config_path, &after), 0);
    CHECK(after.st_dev == before.st_dev);
    CHECK(after.st_ino == before.st_ino);
    CHECK_EQ_INT(after.st_uid, before.st_uid);
    CHECK_EQ_INT(after.st_mode & 0777, 0666);
    CHECK_EQ_INT(count_alias_config_temps(ssh_dir), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_identity), 0);
    CHECK(S_ISREG(lock_identity.st_mode));
    CHECK_EQ_INT(lock_identity.st_uid, getuid());
    CHECK_EQ_INT(lock_identity.st_mode & 0777, 0600);
    CHECK(alias_config_lock_available_to_child(ssh_dir));
    CHECK(!runtime_lock_available_to_child());

    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK(ctx.current_account == &ctx.accounts[1]);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(file_matches_exact_bytes(config_path, expected, expected_len));
    CHECK_EQ_INT(stat(config_path, &after), 0);
    CHECK(after.st_dev == before.st_dev);
    CHECK(after.st_ino == before.st_ino);
    CHECK_EQ_INT(after.st_mode & 0777, 0666);
    CHECK_EQ_INT(count_alias_config_temps(ssh_dir), 0);
    CHECK(alias_config_lock_available_to_child(ssh_dir));
    CHECK(accounts_transaction_context_release_safe(&ctx));
    CHECK(runtime_lock_available_to_child());

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    CHECK_EQ_INT(test_open_fd_count(), before_fds);
}

/* AR-11 L36: once the identical bytes have been atomically replaced by a
 * self-owned 0600 inode, a child-directory sync failure is post-commit
 * uncertainty. The switch and secured config remain installed and abort is no
 * longer authorized. */
TEST(identical_insecure_alias_dirsync_failure_retains_normalized_commit) {
    char home[600], saved_home[4096], config_path[700], ssh_dir[700];
    char lock_path[760], expected[4096];
    struct stat before;
    struct stat after;
    struct stat lock_identity;
    error_context_t failure;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_dirsync_fn previous_sync;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    size_t expected_len;
    int formatted;
    int before_fds;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), NULL), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path),
                           "%s/.gitswitch-config.lock", ssh_dir) <
          sizeof(lock_path));
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    formatted = format_managed_alias_config(
        expected, sizeof(expected), &ctx.accounts[0]);
    CHECK(formatted > 0);
    expected_len = formatted > 0 ? (size_t)formatted : 0U;
    CHECK_EQ_INT(write_exact_bytes(config_path, expected, expected_len), 0);

    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    before_fds = test_open_fd_count();
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_EQ_INT(chmod(config_path, 0666), 0);
    CHECK_EQ_INT(stat(config_path, &before), 0);
    CHECK(S_ISREG(before.st_mode));
    CHECK_EQ_INT(before.st_uid, getuid());
    CHECK_EQ_INT(before.st_mode & 0777, 0666);
    previous_sync = ssh_manager_set_dirsync_fn(fail_alias_dirsync);
    clear_error();
    rc = accounts_switch_commit_result(&ctx, &state);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(state,
                 ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(failure.system_errno, EIO);
    CHECK(strstr(failure.message,
                 "published SSH config state was retained") != NULL);
    CHECK(strstr(failure.message,
                 "SSH config entry could not be made directory-durable") !=
          NULL);
    CHECK(strstr(failure.message, "new SSH alias") == NULL);
    CHECK(strstr(failure.message, "installed bytes") == NULL);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(file_matches_exact_bytes(config_path, expected, expected_len));
    CHECK_EQ_INT(stat(config_path, &after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK_EQ_INT(after.st_uid, getuid());
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    CHECK(after.st_dev != before.st_dev || after.st_ino != before.st_ino);
    CHECK_EQ_INT(count_alias_config_temps(ssh_dir), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_identity), 0);
    CHECK(S_ISREG(lock_identity.st_mode));
    CHECK_EQ_INT(lock_identity.st_uid, getuid());
    CHECK_EQ_INT(lock_identity.st_mode & 0777, 0600);
    CHECK(alias_config_lock_available_to_child(ssh_dir));
    CHECK(accounts_transaction_context_release_safe(&ctx));

    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK(file_matches_exact_bytes(config_path, expected, expected_len));
    CHECK_EQ_INT(stat(config_path, &after), 0);
    CHECK_EQ_INT(after.st_uid, getuid());
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    CHECK_EQ_INT(count_alias_config_temps(ssh_dir), 0);
    CHECK(alias_config_lock_available_to_child(ssh_dir));

    signals_rollback_end();
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    CHECK(runtime_lock_available_to_child());
    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    CHECK_EQ_INT(test_open_fd_count(), before_fds);
}

/* A pre-rename alias failure remains rollback-authorized. If M7 detects an
 * external Git vector at that late point, direct API callers receive both the
 * cause and the retained retry handle instead of losing signal ownership. */
TEST(late_alias_failure_retains_incomplete_direct_git_rollback_for_retry) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    char after[4096], detail[sizeof(g_last_error.message)];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_config_commit_hook_fn previous_hook;
    int rc;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);
    previous_hook = ssh_manager_set_config_commit_hook_fn(
        replace_git_name_and_fail_alias_commit);
    rc = accounts_switch(&ctx, "testacct");
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    ssh_manager_set_config_commit_hook_fn(previous_hook);

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == &ctx.accounts[1]);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Concurrent Name");
    CHECK(strstr(detail, "rollback remains incomplete") != NULL);
    CHECK(strstr(detail, "changed outside this transaction") != NULL);
    CHECK(strstr(detail, "retry ownership retained") != NULL);
    after[0] = '\0';
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, original);

    /* Repair only the conflicting vector to the transaction's exact intended
     * post-image. The retained M7 retry restores its old value and completes
     * signal/rollback ownership without replaying already-restored keys. */
    safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    setenv("HOME", saved_home, 1);
}

/* AR-13 M3: a retained incomplete-rollback record from a prepared/integrated
 * switch (so abort_only == false) must survive a retry whose runtime-lock
 * reacquisition fails under transient cross-HOME contention. The abort path
 * advances the owner phase to FINALIZING before reacquiring the lock; if that
 * failure return left the phase FINALIZING, admission (PREPARED/ABORT_ONLY
 * only) would reject every subsequent abort and commit, stranding the owner —
 * armed signal guard, retained Git retry image and all — with no API able to
 * consume it. The failure return must restore ABORT_ONLY. */
TEST(incomplete_rollback_retry_survives_transient_runtime_lock_contention) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700];
    char after[4096], detail[sizeof(g_last_error.message)];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    runtime_lock_holder_t holder = {0, -1};

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(ssh_git_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    safe_strncpy(g_store_name, "Concurrent Name", sizeof(g_store_name));
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));

    /* Integrated switch left an incomplete rollback retained for retry. */
    CHECK(strstr(detail, "retry material retained") != NULL);
    after[0] = '\0';
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, original);

    /* Retry abort while another process holds the shared runtime lock: the
     * reacquisition at the top of the abort path fails and returns -1. */
    CHECK_EQ_INT(start_runtime_lock_holder(&holder), 0);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK_EQ_INT(stop_runtime_lock_holder(&holder), 0);

    /* Lock free again: repair the conflicting vector and retry. Pre-fix the
     * owner was stranded in FINALIZING and this returned -1 ("Cannot abort
     * switch transaction from phase 4") forever. */
    safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
    g_finalizing_observer_ctx = &ctx;
    g_finalizing_phase_observed = false;
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    g_finalizing_observer_ctx = NULL;
    CHECK(g_finalizing_phase_observed);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    setenv("HOME", saved_home, 1);
}

/* The alias writer is the final commit, so a Git failure must leave the
 * existing SSH config byte-for-byte untouched without invoking a rollback
 * writer at all. */
TEST(failed_switch_never_rewrites_existing_ssh_config) {
    static const char user_content[] =
        "Host personal\n  IdentityFile /tmp/id_personal\n";
    char home[600], saved_home[4096], cfg_path[700], after[4096];
    FILE *f;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home),
                                 saved_home, sizeof(saved_home)), 0);

    /* A pre-existing user config with a stanza and no gitswitch block. */
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(cfg_path, 0700), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(user_content, f);
        fclose(f);
    }
    CHECK_EQ_INT(chmod(cfg_path, 0600), 0);

    gitswitch_ctx_t ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);

    g_fail_user_name_set = true; /* fail exactly at the git-config write */
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev_runner = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev_runner);
    g_fail_user_name_set = false;
    setenv("HOME", saved_home, 1);

    CHECK_EQ_INT(rc, -1);
    /* No alias write ran before the failing Git step. */
    after[0] = '\0';
    CHECK(read_file_to_string(cfg_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, user_content);
    CHECK(strstr(after, "gitswitch") == NULL);
}

/* With no pre-existing config, a failed reversible step must not create one
 * and then depend on a racy unlink during rollback. */
TEST(failed_switch_never_creates_ssh_config) {
    char home[600], saved_home[4096], cfg_path[700];
    struct stat st;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home),
                                 saved_home, sizeof(saved_home)), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);

    gitswitch_ctx_t ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);

    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev_runner = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev_runner);
    g_fail_user_name_set = false;
    setenv("HOME", saved_home, 1);

    CHECK_EQ_INT(rc, -1);
    CHECK(lstat(cfg_path, &st) != 0); /* alias commit never ran */
}

/* A same-user replacement during a failing Git step must win. Neither an
 * early alias write nor a rollback restore is allowed to erase newer data. */
TEST(failed_switch_preserves_concurrent_ssh_config_replacement) {
    static const char original_content[] =
        "Host original\n  IdentityFile /tmp/id_original\n";
    char home[600], saved_home[4096], cfg_path[700], after[4096];
    FILE *f;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home),
                                 saved_home, sizeof(saved_home)), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(cfg_path, 0700), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(original_content, f);
        fclose(f);
    }
    CHECK_EQ_INT(chmod(cfg_path, 0600), 0);

    gitswitch_ctx_t ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    account_t *before_current = ctx.current_account;

    seed_previous_git_identity();
    safe_strncpy(g_concurrent_config_path, cfg_path,
                 sizeof(g_concurrent_config_path));
    g_replace_config_on_user_name = true;
    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(concurrent_config_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);
    g_fail_user_name_set = false;
    g_fail_list_config = false;
    g_replace_config_on_user_name = false;
    setenv("HOME", saved_home, 1);

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == before_current);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    after[0] = '\0';
    CHECK(read_file_to_string(cfg_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, g_concurrent_config_content);
    CHECK(strstr(after, "Host original") == NULL);
}

/* A replacement can arrive after the early no-follow preflight but before the
 * final alias commit. The writer must reject that symlink, the transaction
 * must roll back Git/runtime state, and no rollback path may touch the link or
 * its target. This closes both former inode-marking and restore-rename races. */
TEST(final_alias_commit_rejects_concurrent_symlink_and_rolls_back) {
    static const char original_content[] =
        "Host original\n  IdentityFile /tmp/id_original\n";
    char home[600], saved_home[4096], cfg_path[700], target_path[1100];
    char after[4096], link_target[1100];
    struct stat st;
    FILE *f;
    ssize_t n;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home),
                                 saved_home, sizeof(saved_home)), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(cfg_path, 0700), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    f = fopen(cfg_path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(original_content, f);
        fclose(f);
    }
    CHECK_EQ_INT(chmod(cfg_path, 0600), 0);

    gitswitch_ctx_t ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    account_t *before_current = ctx.current_account;

    seed_previous_git_identity();
    safe_strncpy(g_concurrent_config_path, cfg_path,
                 sizeof(g_concurrent_config_path));
    snprintf(target_path, sizeof(target_path), "%s.target", cfg_path);
    g_replace_config_with_symlink_on_user_name = true;
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(concurrent_config_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);
    g_fail_list_config = false;
    g_replace_config_with_symlink_on_user_name = false;
    setenv("HOME", saved_home, 1);

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == before_current);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_EQ_INT(lstat(cfg_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    n = readlink(cfg_path, link_target, sizeof(link_target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        link_target[n] = '\0';
        CHECK_STR_EQ(link_target, target_path);
    }
    after[0] = '\0';
    CHECK(read_file_to_string(target_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, g_concurrent_config_content);
    CHECK_EQ_INT(stat(target_path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0640);
    CHECK(strstr(get_last_error()->message,
                 "Failed to commit SSH host alias") != NULL);
}

/* AR-04 M4: a symlinked ~/.ssh/config is outside gitswitch's managed-file
 * policy. Refuse it during account-layer preflight, before SSH/Git/active
 * state changes, and leave both link and target untouched. */
TEST(symlinked_ssh_config_fails_before_switch_mutation) {
    static const char target_content[] =
        "Host personal\n  IdentityFile /tmp/id_personal\n";
    char home[600], saved_home[4096], ssh_dir[700], cfg_path[700];
    char target_path[700], after[4096], link_target[700];
    struct stat st;
    ssize_t n;
    FILE *f;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home),
                                 saved_home, sizeof(saved_home)), 0);
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    CHECK_EQ_INT(mkdir(ssh_dir, 0700), 0);
    snprintf(target_path, sizeof(target_path), "%s/dotfiles_ssh_config", g_xdg);
    f = fopen(target_path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(target_content, f);
        fclose(f);
    }
    CHECK_EQ_INT(chmod(target_path, 0640), 0);
    snprintf(cfg_path, sizeof(cfg_path), "%s/.ssh/config", home);
    CHECK_EQ_INT(symlink(target_path, cfg_path), 0);

    gitswitch_ctx_t ctx = make_ctx();
    CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
    safe_strncpy(ctx.config.active_account, "prev",
                 sizeof(ctx.config.active_account));
    account_t *before_current = ctx.current_account;

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(ssh_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);
    setenv("HOME", saved_home, 1);

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == before_current);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_EQ_INT(lstat(cfg_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    n = readlink(cfg_path, link_target, sizeof(link_target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        link_target[n] = '\0';
        CHECK_STR_EQ(link_target, target_path);
    }
    after[0] = '\0';
    CHECK(read_file_to_string(target_path, after, sizeof(after)) >= 0);
    CHECK_STR_EQ(after, target_content);
    CHECK_EQ_INT(stat(target_path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0640);
    CHECK(strstr(get_last_error()->message, "symlinked SSH config") != NULL);
}

/* AR-11 L33: the exact parser used by the final alias publisher is part of
 * read-only switch admission. Binary input and malformed owned markers must
 * fail before Git inspection, agent activation, transaction artifacts, or
 * account publication instead of relying on a late rollback. */
TEST(structurally_invalid_ssh_config_fails_before_switch_mutation) {
    static const unsigned char embedded_nul[] =
        "Host personal\n  User alice\n\0Host hidden\n  User mallory\n";
    static const unsigned char mismatched_marker[] =
        "# >>> gitswitch other >>>\n"
        "Host other\n"
        "  HostName github.com\n"
        "  IdentityFile \"/tmp/old\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch third <<<\n";
    static const struct {
        const unsigned char *bytes;
        size_t length;
        const char *diagnostic;
    } fixtures[] = {
        {embedded_nul, sizeof(embedded_nul) - 1U, "embedded NUL"},
        {mismatched_marker, sizeof(mismatched_marker) - 1U, "mismatched"}
    };

    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char home[600], saved_home[4096], ssh_dir[700], config_path[700];
        char lock_path[700], persistence_path[700];
        char failure[sizeof(get_last_error()->message)];
        char ssh_target_before[512], ssh_target_after[512];
        char gpg_target_before[512], gpg_target_after[512];
        struct stat before;
        struct stat after;
        struct stat ssh_before;
        struct stat ssh_after;
        struct stat gpg_before;
        struct stat gpg_after;
        gitswitch_ctx_t ctx;
        accounts_switch_prepare_state_t prepare_state;
        account_t *before_current;
        command_runner_fn previous_runner;
        ssize_t ssh_before_len;
        ssize_t ssh_after_len;
        ssize_t gpg_before_len;
        ssize_t gpg_after_len;
        int rc;

        CHECK_EQ_INT(setup_runtime_dir(), 0);
        CHECK_EQ_INT(setup_fake_home(home, sizeof(home), saved_home,
                                     sizeof(saved_home)), 0);
        CHECK(safe_snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) == 0);
        CHECK_EQ_INT(mkdir(ssh_dir, 0700), 0);
        CHECK(safe_snprintf(config_path, sizeof(config_path), "%s/config",
                            ssh_dir) == 0);
        CHECK(safe_snprintf(lock_path, sizeof(lock_path),
                            "%s/.gitswitch-config.lock", ssh_dir) == 0);
        CHECK(safe_snprintf(persistence_path, sizeof(persistence_path),
                            "%s/accounts.toml", home) == 0);
        CHECK_EQ_INT(write_exact_bytes(config_path, fixtures[i].bytes,
                                       fixtures[i].length), 0);
        CHECK_EQ_INT(stat(config_path, &before), 0);
        CHECK_EQ_INT(lstat(g_ssh_sock, &ssh_before), 0);
        CHECK_EQ_INT(lstat(g_gpg_link, &gpg_before), 0);
        ssh_before_len = readlink(g_ssh_sock, ssh_target_before,
                                  sizeof(ssh_target_before) - 1U);
        gpg_before_len = readlink(g_gpg_link, gpg_target_before,
                                  sizeof(gpg_target_before) - 1U);
        CHECK(ssh_before_len > 0);
        CHECK(gpg_before_len > 0);
        if (ssh_before_len > 0) ssh_target_before[ssh_before_len] = '\0';
        if (gpg_before_len > 0) gpg_target_before[gpg_before_len] = '\0';

        ctx = make_ctx();
        CHECK_EQ_INT(setup_alias_ctx(&ctx, "github.com-tgt"), 0);
        safe_strncpy(ctx.config.active_account, "prev",
                     sizeof(ctx.config.active_account));
        safe_strncpy(ctx.config.config_path, persistence_path,
                     sizeof(ctx.config.config_path));
        before_current = ctx.current_account;
        seed_previous_git_identity();
        g_fail_user_name_set = false;
        g_raise_on_user_name = false;
        g_ssh_git_runner_calls = 0;
        g_ssh_activation_commands = 0;
        g_log = NULL;
        clear_error();

        previous_runner = run_set_runner(ssh_git_runner);
        prepare_state = ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
        rc = accounts_switch_prepare_result(&ctx, "testacct",
                                            &prepare_state);
        safe_strncpy(failure, get_last_error()->message, sizeof(failure));
        run_set_runner(previous_runner);

        CHECK_EQ_INT(rc, -1);
        CHECK_EQ_INT(prepare_state, ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
        CHECK(strstr(failure, fixtures[i].diagnostic) != NULL);
        CHECK_EQ_INT(g_ssh_git_runner_calls, 0);
        CHECK_EQ_INT(g_fake_runner_calls, 0);
        CHECK_EQ_INT(g_ssh_activation_commands, 0);
        CHECK_EQ_INT(g_user_name_writes, 0);
        CHECK_STR_EQ(g_store_name, "Previous Name");
        CHECK_STR_EQ(g_store_email, "prev@example.com");
        CHECK(ctx.current_account == before_current);
        CHECK_STR_EQ(ctx.config.active_account, "prev");
        CHECK_EQ_INT(lstat(g_ssh_sock, &ssh_after), 0);
        CHECK_EQ_INT(lstat(g_gpg_link, &gpg_after), 0);
        CHECK(S_ISLNK(ssh_after.st_mode));
        CHECK(S_ISLNK(gpg_after.st_mode));
        CHECK(ssh_after.st_dev == ssh_before.st_dev);
        CHECK(ssh_after.st_ino == ssh_before.st_ino);
        CHECK(gpg_after.st_dev == gpg_before.st_dev);
        CHECK(gpg_after.st_ino == gpg_before.st_ino);
        ssh_after_len = readlink(g_ssh_sock, ssh_target_after,
                                 sizeof(ssh_target_after) - 1U);
        gpg_after_len = readlink(g_gpg_link, gpg_target_after,
                                 sizeof(gpg_target_after) - 1U);
        CHECK_EQ_INT(ssh_after_len, ssh_before_len);
        CHECK_EQ_INT(gpg_after_len, gpg_before_len);
        if (ssh_after_len > 0) ssh_target_after[ssh_after_len] = '\0';
        if (gpg_after_len > 0) gpg_target_after[gpg_after_len] = '\0';
        if (ssh_before_len > 0 && ssh_after_len > 0) {
            CHECK_STR_EQ(ssh_target_after, ssh_target_before);
        }
        if (gpg_before_len > 0 && gpg_after_len > 0) {
            CHECK_STR_EQ(gpg_target_after, gpg_target_before);
        }
        CHECK_EQ_INT(stat(config_path, &after), 0);
        CHECK(after.st_dev == before.st_dev);
        CHECK(after.st_ino == before.st_ino);
        CHECK_EQ_INT(after.st_mode, before.st_mode);
        CHECK_EQ_INT(after.st_size, before.st_size);
        CHECK_EQ_INT(after.st_mtime, before.st_mtime);
        CHECK(file_matches_exact_bytes(config_path, fixtures[i].bytes,
                                       fixtures[i].length));
        errno = 0;
        CHECK(lstat(lock_path, &after) != 0);
        CHECK_EQ_INT(errno, ENOENT);
        errno = 0;
        CHECK(lstat(persistence_path, &after) != 0);
        CHECK_EQ_INT(errno, ENOENT);
        CHECK(runtime_lock_available_to_child());
        CHECK(accounts_transaction_context_release_safe(&ctx));
        CHECK(!signals_guard_active());
        CHECK(!signals_rollback_active());
        CHECK_EQ_INT(git_config_seal(), -1);
        CHECK(strstr(get_last_error()->message,
                     "No Git snapshot to seal") != NULL);
        CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
        CHECK(strstr(get_last_error()->message,
                     "No prepared account switch") != NULL);
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    }
}

/* ---- AR-03 T1: the GPG half of the failed-switch rollback ---------------- */

/* A real `sec` line whose capability field contains 's' (same shape as
 * test_gpg_switch.c's). Answering every secret-key listing with it satisfies
 * both the up-front availability probe and the isolated-home idempotency
 * check, so the switch reaches the git-config write without a real gpg. */
#define SEC_SIGN \
    "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\n"
#define SEC_CERT_ONLY \
    "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::cC:::+:::23::0:\n" \
    "fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\n"

static const char *g_gpg_secret_listing = SEC_SIGN;

static int gpg_git_runner(const char *const argv[], const run_opts_t *opts,
                          run_result_t *result) {
    if (strncmp(ts_command_basename(argv[0]), "gpg", 3) == 0) {
        bool listing = false;
        bool list_components = false;
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            if (!run_launch_witness_capture(
                    argv[0], &result->launch_witness)) {
                return -1;
            }
        }
        if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) listing = true;
            if (strcmp(argv[i], "--list-components") == 0) {
                list_components = true;
            }
        }
        if (list_components && opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "gpg:OpenPGP:%s/gpg:\n", g_gpg_command_dir);
            if (result) result->out_len = strlen(opts->out);
        } else if (listing && opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", g_gpg_secret_listing);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return fake_runner(argv, opts, result);
}

static int ssh_gpg_git_runner(const char *const argv[], const run_opts_t *opts,
                              run_result_t *result) {
    if (strncmp(ts_command_basename(argv[0]), "gpg", 3) == 0) {
        return gpg_git_runner(argv, opts, result);
    }
    return ssh_git_runner(argv, opts, result);
}

static int gpg_fail_first_commit_count;
static int gpg_fail_first_commit_after_publication(int base_fd) {
    (void)base_fd;
    return gpg_fail_first_commit_count++ == 0 ? -1 : 0;
}

static int gpg_fail_first_inner_restore_count;
static int gpg_fail_first_inner_restore(int base_fd) {
    (void)base_fd;
    return gpg_fail_first_inner_restore_count++ == 0 ? -1 : 0;
}

static bool gpg_fail_session_env_restore;
static int gpg_fault_setenv(const char *name, const char *value,
                            int overwrite) {
    if (gpg_fail_session_env_restore && strcmp(name, "GNUPGHOME") == 0) {
        errno = EIO;
        return -1;
    }
    return setenv(name, value, overwrite);
}

/* AR-11 L25: the public abort owns one causal diagnostic across every
 * best-effort rollback component. A sealed Git post-image conflict is the
 * first failure; GPG then restores its stable link but cannot restore the
 * process environment. The published context must retain the Git provenance
 * and ambient errno exactly while appending the later GPG cause. Both retry
 * records remain live, and one exact retry completes them without replaying a
 * generic wrapper error over the original evidence. */
TEST(abort_accumulates_git_then_gpg_failure_and_retries_exactly) {
    char expected_details[sizeof(g_last_error.details)];
    char gpg_target[MAX_PATH_LEN];
    error_context_t failure;
    gitswitch_ctx_t ctx;
    account_t *target;
    account_t *previous;
    command_runner_fn previous_runner;
    ssize_t target_length;
    int failure_errno;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    ctx = make_ctx();
    target = &ctx.accounts[0];
    previous = add_previous_account(&ctx);
    target->gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(target->gpg_key_id, "FEEDFACE01234567",
                              sizeof(target->gpg_key_id)), 0);
    previous->gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(previous->gpg_key_id, "0123456789ABCDEF",
                              sizeof(previous->gpg_key_id)), 0);
    seed_previous_git_identity();
    previous_runner = run_set_runner(gpg_git_runner);

    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) {
        CHECK_EQ_INT(safe_strncpy(gpg_target, getenv("GNUPGHOME"),
                                  sizeof(gpg_target)), 0);
    } else {
        gpg_target[0] = '\0';
    }

    /* Two independent changes fail in rollback order. Git no longer matches
     * the sealed post-image, while the GPG environment setter fails only
     * after its stable link has been restored. */
    CHECK_EQ_INT(safe_strncpy(g_store_name, "concurrent-git-writer",
                              sizeof(g_store_name)), 0);
    gpg_fail_session_env_restore = true;
    gpg_manager_set_setenv_fn(gpg_fault_setenv);
    errno = EDOM;
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    failure = *get_last_error();
    failure_errno = errno;

    CHECK_EQ_INT(failure.code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(failure.system_errno, 0);
    CHECK(!failure.message_truncated);
    CHECK(!failure.details_truncated);
    CHECK(strstr(failure.message,
                 "Git rollback incomplete: 1 managed vector(s) changed "
                 "outside this transaction") != NULL);
    CHECK_STR_EQ(failure.file, "src/git_ops.c");
    CHECK(failure.line > 0);
    CHECK_STR_EQ(failure.function, "git_config_restore");
    CHECK_EQ_INT(failure_errno, EDOM);
    CHECK((size_t)snprintf(
              expected_details, sizeof(expected_details),
              "; [GPG isolation restore] Failed to restore GNUPGHOME "
              "environment variable (%s); System error: %s (errno=%d)",
              strerror(EIO), strerror(EIO), EIO) <
          sizeof(expected_details));
    CHECK_STR_EQ(failure.details, expected_details);
    CHECK_STR_EQ(g_store_name, "concurrent-git-writer");
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), gpg_target);
    target_length = readlink(g_gpg_link, gpg_target,
                             sizeof(gpg_target) - 1);
    CHECK(target_length > 0);
    if (target_length > 0) {
        gpg_target[target_length] = '\0';
        CHECK(strstr(gpg_target, "/prevhome") != NULL);
    }
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());

    /* Restore only the exact states each retained token expects. The retry
     * must recover the original Git identity and GPG environment, then release
     * the transaction and signal owners. */
    CHECK_EQ_INT(safe_strncpy(g_store_name, "testacct",
                              sizeof(g_store_name)), 0);
    gpg_fail_session_env_restore = false;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_STR_EQ(getenv("GNUPGHOME"), g_gpg_source_home);
    CHECK(!signals_guard_active());
    CHECK(!signals_rollback_active());
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);

    run_set_runner(previous_runner);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

TEST(failed_inner_gpg_retarget_is_finished_by_accounts_rollback) {
    char target[512];
    error_context_t failure;
    ssize_t n;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *account = &ctx.accounts[0];
    account->gpg_enabled = true;
    safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                 sizeof(account->gpg_key_id));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    gpg_fail_first_commit_count = 0;
    gpg_fail_first_inner_restore_count = 0;
    gpg_manager_set_retarget_commit_hook_fn(
        gpg_fail_first_commit_after_publication);
    gpg_manager_set_retarget_restore_hook_fn(gpg_fail_first_inner_restore);
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);

    int rc = accounts_switch(&ctx, "testacct");
    failure = *get_last_error();

    run_set_runner(previous_runner);
    gpg_manager_set_retarget_commit_hook_fn(NULL);
    gpg_manager_set_retarget_restore_hook_fn(NULL);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");

    CHECK_EQ_INT(rc, -1);
    CHECK(strstr(failure.message, "rollback failed") != NULL);
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    n = readlink(g_gpg_link, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK(strstr(target, "/prevhome") != NULL);
    }
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    unsetenv("GNUPGHOME");
}

/* AR-09 M4 phase 4: GPG activation can fail after the guard and snapshot are
 * owned but before Git publication. Exercise the prepared entry point so the
 * manager cleanup and transaction cleanup are one synchronous failure. */
TEST(signing_capability_failure_precedes_runtime_and_git_publication) {
    char target[MAX_PATH_LEN];
    error_context_t failure;
    ssize_t n;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *account = &ctx.accounts[0];
    account->gpg_enabled = true;
    account->gpg_signing_enabled = true;
    safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                 sizeof(account->gpg_key_id));
    seed_previous_git_identity();
    g_gpg_secret_listing = SEC_CERT_ONLY;
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);

    int rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    failure = *get_last_error();

    run_set_runner(previous_runner);
    g_gpg_secret_listing = SEC_SIGN;
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    CHECK_EQ_INT(rc, -1);
    CHECK(strstr(failure.message, "Failed to set up GPG for account") != NULL);
    CHECK_EQ_INT(g_user_name_writes, 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    n = readlink(g_gpg_link, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK(strstr(target, "/prevhome") != NULL);
    }
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
    unsetenv("GNUPGHOME");
}

/* GPG activation resolves a short selector to its canonical primary
 * fingerprint for runtime/Git use. The persisted account remains unchanged,
 * so commit must compare it with the distinct frozen model snapshot rather
 * than the normalized switch target. */
TEST(prepared_commit_accepts_unchanged_gpg_selector_after_normalization) {
    gitswitch_ctx_t ctx;
    account_t *account;
    command_runner_fn previous_runner;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }
    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    ctx = make_ctx();
    account = &ctx.accounts[0];
    account->gpg_enabled = true;
    account->gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                              sizeof(account->gpg_key_id)), 0);
    seed_previous_git_identity();
    g_gpg_secret_listing = SEC_SIGN;
    previous_runner = run_set_runner(gpg_git_runner);

    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "FEEDFACE01234567");
    CHECK_STR_EQ(g_store_signingkey,
                 "0123456789ABCDEF0123456789ABCDEF01234567");
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_COMPLETE),
                 0);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "FEEDFACE01234567");
    CHECK_EQ_INT(accounts_session_cleanup(), 0);

    run_set_runner(previous_runner);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

TEST(accounts_cleanup_retains_gpg_environment_for_checked_retry) {
    char active_home[MAX_PATH_LEN];
    struct stat home_before = {0};
    struct stat home_after = {0};

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *account = &ctx.accounts[0];
    account->gpg_enabled = true;
    safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                 sizeof(account->gpg_key_id));
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);

    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    signals_guard_end();
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) {
        CHECK_EQ_INT(safe_strncpy(active_home, getenv("GNUPGHOME"),
                                  sizeof(active_home)), 0);
    } else {
        active_home[0] = '\0';
    }
    CHECK(active_home[0] != '\0');
    if (active_home[0] != '\0') {
        CHECK_EQ_INT(stat(active_home, &home_before), 0);
        CHECK(S_ISDIR(home_before.st_mode));
    }
    gpg_fail_session_env_restore = true;
    gpg_manager_set_setenv_fn(gpg_fault_setenv);
    CHECK_EQ_INT(accounts_session_cleanup(), -1);
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), active_home);

    gpg_fail_session_env_restore = false;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), g_gpg_source_home);
    if (active_home[0] != '\0') {
        CHECK_EQ_INT(stat(active_home, &home_after), 0);
        CHECK(S_ISDIR(home_after.st_mode));
        CHECK(home_after.st_dev == home_before.st_dev);
        CHECK(home_after.st_ino == home_before.st_ino);
    }

    run_set_runner(previous_runner);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

TEST(repeated_switch_partial_cleanup_restores_ssh_and_retains_gpg_retry) {
    char first_key[MAX_PATH_LEN];
    char ssh_target[MAX_PATH_LEN];
    char active_gpg_home[MAX_PATH_LEN];
    ssize_t target_len;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }
    if (!command_exists("ssh-agent") || !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-agent/ssh-add unavailable in trusted PATH");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *first = &ctx.accounts[0];
    snprintf(first_key, sizeof(first_key), "%s/repeated-first-key", g_xdg);
    CHECK_EQ_INT(write_fake_key(first_key), 0);
    first->ssh_enabled = true;
    safe_strncpy(first->ssh_key_path, first_key,
                 sizeof(first->ssh_key_path));
    first->gpg_enabled = true;
    safe_strncpy(first->gpg_key_id, "FEEDFACE01234567",
                 sizeof(first->gpg_key_id));

    seed_previous_git_identity();
    command_runner_fn previous_runner = run_set_runner(ssh_gpg_git_runner);
    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    signals_guard_end();
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) {
        CHECK_EQ_INT(safe_strncpy(active_gpg_home, getenv("GNUPGHOME"),
                                  sizeof(active_gpg_home)), 0);
    } else {
        active_gpg_home[0] = '\0';
    }

    account_t *second = &ctx.accounts[1];
    memset(second, 0, sizeof(*second));
    second->id = 2;
    bind_rollback_test_incarnation(second);
    safe_strncpy(second->name, "second", sizeof(second->name));
    safe_strncpy(second->email, "second@example.com", sizeof(second->email));
    second->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx.account_count = 2;

    gpg_fail_session_env_restore = true;
    gpg_manager_set_setenv_fn(gpg_fault_setenv);
    CHECK_EQ_INT(accounts_switch(&ctx, "second"), -1);
    CHECK(ctx.current_account == first);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), active_gpg_home);
    target_len = readlink(g_ssh_sock, ssh_target, sizeof(ssh_target) - 1);
    CHECK(target_len > 0);
    if (target_len > 0) {
        ssh_target[target_len] = '\0';
        CHECK(path_exists(ssh_target));
    }

    gpg_fail_session_env_restore = false;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), g_gpg_source_home);
    run_set_runner(previous_runner);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

TEST(accounts_git_readback_uses_canonical_key_when_signing_is_disabled) {
    char expected_program[MAX_PATH_LEN];

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    gitswitch_ctx_t ctx = make_ctx();
    account_t *account = &ctx.accounts[0];
    account->gpg_enabled = true;
    account->gpg_signing_enabled = false;
    safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                 sizeof(account->gpg_key_id));
    seed_previous_git_identity();
    safe_strncpy(g_store_gpgprogram, "/foreign/gpg-wrapper",
                 sizeof(g_store_gpgprogram));
    safe_strncpy(g_store_gpgopenpgp, "/foreign/openpgp-wrapper",
                 sizeof(g_store_gpgopenpgp));
    safe_strncpy(g_store_gpgx509, "/foreign/x509-wrapper",
                 sizeof(g_store_gpgx509));
    safe_strncpy(g_store_gpgssh, "/foreign/ssh-wrapper",
                 sizeof(g_store_gpgssh));
    safe_strncpy(g_store_gpgformat, "ssh", sizeof(g_store_gpgformat));
    CHECK_EQ_INT(safe_snprintf(expected_program, sizeof(expected_program),
                               "%s/gpg", g_gpg_command_dir), 0);
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);

    CHECK_EQ_INT(accounts_switch(&ctx, "testacct"), 0);
    signals_guard_end();
    run_set_runner(previous_runner);

    CHECK_STR_EQ(g_store_signingkey,
                 "0123456789ABCDEF0123456789ABCDEF01234567");
    CHECK_STR_EQ(g_effective_signingkey_observed,
                 "0123456789ABCDEF0123456789ABCDEF01234567");
    CHECK_STR_EQ(g_store_gpgsign, "false");
    CHECK_STR_EQ(g_store_gpgformat, "openpgp");
    CHECK(g_store_gpgprogram[0] == '\0');
    CHECK_STR_EQ(g_store_gpgopenpgp, expected_program);
    CHECK(g_store_gpgx509[0] == '\0');
    CHECK(g_store_gpgssh[0] == '\0');
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

/* M11b: the bound OpenPGP program joins the managed Git post-image before
 * sealing. A later writer can conflict with user.name, but every unaffected
 * selector must still restore its exact before-image;
 * the retained abort retry owns only the conflicting name. */
TEST(late_seal_failure_restores_exact_gpg_selector_vectors) {
    static const char old_format[] = "ssh";
    static const char old_legacy[] = "/before/legacy-gpg";
    static const char old_openpgp[] = "/before/openpgp-gpg";
    static const char old_x509[] = "/before/x509-gpg";
    static const char old_ssh[] = "/before/ssh-gpg";
    char expected_program[MAX_PATH_LEN];
    gitswitch_ctx_t ctx;
    account_t *account;
    command_runner_fn previous_runner;
    int rc;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }
    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    ctx = make_ctx();
    account = &ctx.accounts[0];
    account->gpg_enabled = true;
    account->gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account->gpg_key_id, "FEEDFACE01234567",
                              sizeof(account->gpg_key_id)), 0);
    seed_previous_git_identity();
    CHECK_EQ_INT(safe_strncpy(g_store_gpgformat, old_format,
                              sizeof(g_store_gpgformat)), 0);
    CHECK_EQ_INT(safe_strncpy(g_store_gpgprogram, old_legacy,
                              sizeof(g_store_gpgprogram)), 0);
    CHECK_EQ_INT(safe_strncpy(g_store_gpgopenpgp, old_openpgp,
                              sizeof(g_store_gpgopenpgp)), 0);
    CHECK_EQ_INT(safe_strncpy(g_store_gpgx509, old_x509,
                              sizeof(g_store_gpgx509)), 0);
    CHECK_EQ_INT(safe_strncpy(g_store_gpgssh, old_ssh,
                              sizeof(g_store_gpgssh)), 0);
    CHECK_EQ_INT(safe_snprintf(expected_program, sizeof(expected_program),
                               "%s/gpg", g_gpg_command_dir), 0);
    g_mutate_name_before_seal = true;
    previous_runner = run_set_runner(gpg_git_runner);

    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED);
    g_mutate_name_before_seal = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_STR_EQ(g_preseal_gpgopenpgp_observed, expected_program);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_STR_EQ(g_store_gpgformat, old_format);
    CHECK_STR_EQ(g_store_gpgprogram, old_legacy);
    CHECK_STR_EQ(g_store_gpgopenpgp, old_openpgp);
    CHECK_STR_EQ(g_store_gpgx509, old_x509);
    CHECK_STR_EQ(g_store_gpgssh, old_ssh);
    CHECK(strstr(get_last_error()->details,
                 "[Git configuration restore]") != NULL);
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());

    CHECK_EQ_INT(safe_strncpy(g_store_name, "testacct",
                              sizeof(g_store_name)), 0);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK_STR_EQ(g_store_gpgformat, old_format);
    CHECK_STR_EQ(g_store_gpgprogram, old_legacy);
    CHECK_STR_EQ(g_store_gpgopenpgp, old_openpgp);
    CHECK_STR_EQ(g_store_gpgx509, old_x509);
    CHECK_STR_EQ(g_store_gpgssh, old_ssh);
    CHECK(!signals_guard_active());
    CHECK(!signals_rollback_active());

    run_set_runner(previous_runner);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    unsetenv("GNUPGHOME");
}

/* M2 at the accounts_switch boundary for GPG: an obstructing non-symlink at
 * `current` makes the stable-home commit fail. That failure must abort before
 * Git/active state changes and must not disturb the independent SSH link. */
TEST(gpg_stable_link_obstruction_aborts_integrated_switch) {
    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    CHECK_EQ_INT(unlink(g_gpg_link), 0);
    CHECK_EQ_INT(mkdir(g_gpg_link, 0700), 0);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *target = &ctx.accounts[0];
    account_t *prev_account = add_previous_account(&ctx);
    target->gpg_enabled = true;
    safe_strncpy(target->gpg_key_id, "FEEDFACE01234567",
                 sizeof(target->gpg_key_id));

    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);
    g_fail_list_config = false;
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");

    CHECK_EQ_INT(rc, -1);
    CHECK(ctx.current_account == prev_account);
    CHECK_STR_EQ(ctx.config.active_account, "prev");
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(is_directory(g_gpg_link));
    CHECK(symlink_present(g_ssh_sock));
    unsetenv("GNUPGHOME");
}

/* Mirror of failed_switch_restarts_previous_accounts_agent for the GPG side
 * (AR-03 T1): a gpg-enabled switch retargets the stable GNUPGHOME `current`
 * symlink at the TARGET's isolated home before the git-config write; when that
 * write fails, the rollback must retarget `current` back at the PREVIOUS
 * account's home — the branch of restore_previous_isolation no test ran. */
TEST(failed_switch_retargets_gpg_current_to_previous_home) {
    char target[512];
    ssize_t n;
    const char *base;

    /* gpg_manager_init PATH-probes the real gpg binary (the runner fakes the
     * spawns themselves). */
    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    /* The fake runtime dir lives under /tmp: opt out of the tmpfs fail-closed
     * guard so the test is independent of where /tmp is mounted. */
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *tgt = &ctx.accounts[0];
    account_t *prev = &ctx.accounts[1];
    memset(prev, 0, sizeof(*prev));
    prev->id = 2;
    bind_rollback_test_incarnation(prev);
    safe_strncpy(prev->name, "prev", sizeof(prev->name));
    safe_strncpy(prev->email, "prev@example.com", sizeof(prev->email));
    safe_strncpy(prev->description, "previous account", sizeof(prev->description));
    prev->preferred_scope = GIT_SCOPE_GLOBAL;
    prev->gpg_enabled = true;
    safe_strncpy(prev->gpg_key_id, "0123456789ABCDEF", sizeof(prev->gpg_key_id));
    ctx.account_count = 2;
    ctx.current_account = prev;

    tgt->gpg_enabled = true;
    safe_strncpy(tgt->gpg_key_id, "FEEDFACE01234567", sizeof(tgt->gpg_key_id));

    g_fail_user_name_set = true; /* fail exactly at the git-config write */
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev_runner = run_set_runner(gpg_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev_runner);
    g_fail_user_name_set = false;
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");

    CHECK_EQ_INT(rc, -1);

    /* `current` must resolve back to the previous account's home — not dangle,
     * and not stay at the aborted target's freshly-created home. */
    n = readlink(g_gpg_link, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        base = strrchr(target, '/');
        base = base ? base + 1 : target;
        CHECK_STR_EQ(base, "prevhome");
    }
    unsetenv("GNUPGHOME");
}

/* A failed transaction may share XDG_RUNTIME_DIR with a later writer whose
 * HOME gives it a different outer config lock. Rollback must compare the
 * current link with its own installed target before restoring the snapshot;
 * otherwise it overwrites the later writer with `prevhome`. */
TEST(failed_switch_does_not_overwrite_later_gpg_writer) {
    char later_home[512];
    char target[512];
    ssize_t n;

    if (!gpg_test_command_available()) {
        TS_SKIP("gpg", "gpg preflight or trusted test probe unavailable");
    }

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    CHECK_EQ_INT(setup_gpg_source_home(), 0);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    snprintf(later_home, sizeof(later_home), "%s/gitswitch-gpg/later", g_xdg);
    CHECK_EQ_INT(mkdir(later_home, 0700), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *tgt = &ctx.accounts[0];
    account_t *prev = add_previous_account(&ctx);
    prev->gpg_enabled = true;
    safe_strncpy(prev->gpg_key_id, "0123456789ABCDEF",
                 sizeof(prev->gpg_key_id));
    tgt->gpg_enabled = true;
    safe_strncpy(tgt->gpg_key_id, "FEEDFACE01234567",
                 sizeof(tgt->gpg_key_id));

    seed_previous_git_identity();
    g_retarget_gpg_on_user_name = later_home;
    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn previous_runner = run_set_runner(gpg_git_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);
    g_retarget_gpg_on_user_name = NULL;
    g_fail_user_name_set = false;
    g_fail_list_config = false;
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");

    CHECK_EQ_INT(rc, -1);
    n = readlink(g_gpg_link, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK_STR_EQ(target, later_home);
    }
    unsetenv("GNUPGHOME");
}

/* ---- AR-08 M4/M6: transaction-wide signal ownership ----------------------- */

static volatile sig_atomic_t g_guard_end_checkpoint_signal;
static int g_guard_end_hook_signal;

static void switch_inherited_handler(int signal_number) {
    g_guard_end_checkpoint_signal = signal_number;
}

static void raise_during_guard_end(void) {
    raise(g_guard_end_hook_signal);
}

static int raise_sigint_after_alias_rename(int dir_fd) {
    (void)dir_fd;
    raise(SIGINT);
    return 0;
}

/* sigaction has implementation padding, so compare the semantic fields and
 * every mask member this fixture deliberately varies. */
static bool switch_actions_equal(const struct sigaction *left,
                                 const struct sigaction *right) {
    static const int mask_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM
    };

    if (left->sa_handler != right->sa_handler ||
        left->sa_flags != right->sa_flags) {
        return false;
    }
    for (size_t i = 0; i < sizeof(mask_signals) / sizeof(mask_signals[0]); i++) {
        if (sigismember(&left->sa_mask, mask_signals[i]) !=
            sigismember(&right->sa_mask, mask_signals[i])) {
            return false;
        }
    }
    return true;
}

/* A late signal can arrive after the alias rename has crossed the switch's
 * final commit point. It must suppress the optional network probe while the
 * already-committed switch remains intact and the caller's returning handler
 * receives the deferred signal during guard teardown. */
TEST(pending_postcommit_signal_skips_ssh_probe) {
    static const char original[] = "Host personal\n  User old\n";
    char home[600], saved_home[4096], config_path[700], after[4096];
    struct sigaction original_action;
    struct sigaction returning_action;
    ssh_config_postrename_hook_fn previous_hook;
    command_runner_fn previous_runner;
    gitswitch_ctx_t ctx;
    int rc;

    if (!ssh_probe_fixture_available()) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_alias_config_file(
                     home, sizeof(home), saved_home, sizeof(saved_home),
                     config_path, sizeof(config_path), original), 0);
    ctx = make_ctx();
    CHECK_EQ_INT(enable_switch_target_ssh(&ctx, "github.com-tgt"), 0);
    seed_previous_git_identity();
    memset(&returning_action, 0, sizeof(returning_action));
    returning_action.sa_handler = switch_inherited_handler;
    sigemptyset(&returning_action.sa_mask);
    CHECK_EQ_INT(sigaction(SIGINT, NULL, &original_action), 0);
    CHECK_EQ_INT(sigaction(SIGINT, &returning_action, NULL), 0);
    g_guard_end_checkpoint_signal = 0;
    previous_runner = run_set_runner(ssh_git_runner);
    previous_hook = ssh_manager_set_config_postrename_hook_fn(
        raise_sigint_after_alias_rename);
    rc = accounts_switch(&ctx, "testacct");
    ssh_manager_set_config_postrename_hook_fn(previous_hook);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(g_guard_end_checkpoint_signal, SIGINT);
    CHECK(!signals_pending());
    CHECK_EQ_INT(g_ssh_connection_probes, 0);
    CHECK(g_ssh_activation_commands > 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "testacct");
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(read_file_to_string(config_path, after, sizeof(after)) >= 0);
    CHECK(strstr(after, "Host github.com-tgt\n") != NULL);
    CHECK(accounts_transaction_context_release_safe(&ctx));
    CHECK(runtime_lock_available_to_child());

    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(sigaction(SIGINT, &original_action, NULL), 0);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

/* AR-11 M4: the structured prepare result is a caller-lifetime contract.
 * Only an exact successful handoff is PREPARED; a failed call that publishes
 * an abort-only record says so explicitly, while validation or competing-
 * owner failures remain clean. */
TEST(structured_prepare_result_tracks_exact_context_ownership) {
    gitswitch_ctx_t owner;
    gitswitch_ctx_t contender;
    accounts_switch_prepare_state_t state;
    command_runner_fn previous_runner;

    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    owner = make_ctx();
    state = ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
    CHECK_EQ_INT(accounts_switch_prepare_result(&owner, "missing", &state),
                 -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    CHECK(accounts_transaction_context_release_safe(&owner));
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "missing",
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(accounts_transaction_context_release_safe(&owner));

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    owner = make_ctx();
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);
    state = ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;
    CHECK_EQ_INT(accounts_switch_prepare_result(&owner, "testacct", &state),
                 0);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_PREPARE_PREPARED);
    CHECK(!accounts_transaction_context_release_safe(&owner));
    CHECK_EQ_INT(commit_switch_expect(
                     &owner, ACCOUNTS_SWITCH_COMMIT_COMPLETE),
                 0);
    CHECK(accounts_transaction_context_release_safe(&owner));

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    owner = make_ctx();
    contender = make_ctx();
    seed_previous_git_identity();
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK(!accounts_transaction_context_release_safe(&owner));
    state = ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
    CHECK_EQ_INT(accounts_switch_prepare_result(&contender, NULL, &state),
                 -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    CHECK(accounts_transaction_context_release_safe(&contender));
    CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
    CHECK(accounts_transaction_context_release_safe(&owner));

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    owner = make_ctx();
    seed_previous_git_identity();
    g_mutate_name_before_seal = true;
    state = ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;
    CHECK_EQ_INT(accounts_switch_prepare_result(&owner, "testacct", &state),
                 -1);
    g_mutate_name_before_seal = false;
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED);
    CHECK(!accounts_transaction_context_release_safe(&owner));
    CHECK_EQ_INT(commit_switch_expect(
                     &owner, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);
    safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
    CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
    CHECK(accounts_transaction_context_release_safe(&owner));

    run_set_runner(previous_runner);
}

typedef enum {
    ACCOUNT_MUTATION_ID = 0,
    ACCOUNT_MUTATION_NAME,
    ACCOUNT_MUTATION_EMAIL,
    ACCOUNT_MUTATION_DESCRIPTION,
    ACCOUNT_MUTATION_SCOPE,
    ACCOUNT_MUTATION_SSH_ENABLED,
    ACCOUNT_MUTATION_SSH_KEY_PATH,
    ACCOUNT_MUTATION_SSH_HOST_ALIAS,
    ACCOUNT_MUTATION_SSH_HOSTNAME,
    ACCOUNT_MUTATION_GPG_ENABLED,
    ACCOUNT_MUTATION_GPG_SIGNING_ENABLED,
    ACCOUNT_MUTATION_GPG_KEY_ID,
    ACCOUNT_MUTATION_COUNT
} account_mutation_field_t;

static void mutate_account_field(account_t *account,
                                 account_mutation_field_t field) {
    switch (field) {
        case ACCOUNT_MUTATION_ID:
            account->id = 101;
            break;
        case ACCOUNT_MUTATION_NAME:
            CHECK_EQ_INT(safe_strncpy(account->name, "changed-name",
                                      sizeof(account->name)), 0);
            break;
        case ACCOUNT_MUTATION_EMAIL:
            CHECK_EQ_INT(safe_strncpy(account->email,
                                      "changed@example.test",
                                      sizeof(account->email)), 0);
            break;
        case ACCOUNT_MUTATION_DESCRIPTION:
            CHECK_EQ_INT(safe_strncpy(account->description,
                                      "changed description",
                                      sizeof(account->description)), 0);
            break;
        case ACCOUNT_MUTATION_SCOPE:
            account->preferred_scope = GIT_SCOPE_LOCAL;
            break;
        case ACCOUNT_MUTATION_SSH_ENABLED:
            account->ssh_enabled = true;
            break;
        case ACCOUNT_MUTATION_SSH_KEY_PATH:
            CHECK_EQ_INT(safe_strncpy(account->ssh_key_path, "~/.ssh/changed",
                                      sizeof(account->ssh_key_path)), 0);
            break;
        case ACCOUNT_MUTATION_SSH_HOST_ALIAS:
            CHECK_EQ_INT(safe_strncpy(account->ssh_host_alias,
                                      "changed-alias",
                                      sizeof(account->ssh_host_alias)), 0);
            break;
        case ACCOUNT_MUTATION_SSH_HOSTNAME:
            CHECK_EQ_INT(safe_strncpy(account->ssh_hostname,
                                      "changed.example.test",
                                      sizeof(account->ssh_hostname)), 0);
            break;
        case ACCOUNT_MUTATION_GPG_ENABLED:
            account->gpg_enabled = true;
            break;
        case ACCOUNT_MUTATION_GPG_SIGNING_ENABLED:
            account->gpg_signing_enabled = true;
            break;
        case ACCOUNT_MUTATION_GPG_KEY_ID:
            CHECK_EQ_INT(safe_strncpy(account->gpg_key_id,
                                      "0123456789ABCDEF",
                                      sizeof(account->gpg_key_id)), 0);
            break;
        case ACCOUNT_MUTATION_COUNT:
        default:
            CHECK(false);
            break;
    }
}

/* AR-11 M3: the prepared record owns the exact persisted account, not merely
 * its numeric ID. Every field change must stop before alias/final publication,
 * keep the runtime lock and Git rollback image, and leave exact abort usable. */
TEST(prepared_commit_rejects_every_frozen_account_field_change) {
    command_runner_fn previous_runner = run_set_runner(fake_runner);

    for (int field = 0; field < ACCOUNT_MUTATION_COUNT; field++) {
        gitswitch_ctx_t owner;
        gitswitch_ctx_t contender;
        accounts_switch_commit_state_t state =
            ACCOUNTS_SWITCH_COMMIT_ALIAS_CLEANUP_FAILED;
        int runner_calls;

        CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
        CHECK_EQ_INT(signals_guard_end(), 0);
        signals_rollback_end();
        owner = make_ctx();
        contender = make_ctx();
        seed_previous_git_identity();
        CHECK_EQ_INT(prepare_switch_expect(
                         &owner, "testacct",
                         ACCOUNTS_SWITCH_PREPARE_PREPARED),
                     0);
        runner_calls = g_fake_runner_calls;
        mutate_account_field(&owner.accounts[0],
                             (account_mutation_field_t)field);

        errno = 0;
        CHECK_EQ_INT(accounts_switch_commit_result(&owner, &state), -1);
        CHECK_EQ_INT(errno, ESTALE);
        CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED);
        CHECK(strstr(get_last_error()->message, "changed") != NULL);
        CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
        CHECK_STR_EQ(g_store_name, "testacct");
        CHECK_STR_EQ(g_store_email, "test@example.com");
        CHECK(!runtime_lock_available_to_child());
        CHECK(signals_guard_active());
        CHECK(signals_rollback_active());
        CHECK_EQ_INT(accounts_init(&contender), -1);
        CHECK_EQ_INT(git_config_seal(), 0);

        CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
        CHECK_STR_EQ(g_store_name, "Previous Name");
        CHECK_STR_EQ(g_store_email, "prev@example.com");
        CHECK(runtime_lock_available_to_child());
        CHECK(!signals_guard_active());
        CHECK(!signals_rollback_active());
    }
    run_set_runner(previous_runner);
}

/* Public model helpers cannot edit either the owner's context or another
 * context while a prepared switch exists. The rejection is owner-first and
 * byte-preserving, and the original switch remains exactly abortable. */
TEST(prepared_switch_gates_public_account_model_mutation_matrix) {
    gitswitch_ctx_t owner;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t contender_before;
    account_t added;
    account_t edited;
    command_runner_fn previous_runner;
    int runner_calls;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    owner = make_ctx();
    contender = make_ctx();
    memset(&added, 0, sizeof(added));
    added.id = 2;
    CHECK_EQ_INT(safe_strncpy(added.name, "added",
                              sizeof(added.name)), 0);
    CHECK_EQ_INT(safe_strncpy(added.email, "added@example.test",
                              sizeof(added.email)), 0);
    added.preferred_scope = GIT_SCOPE_GLOBAL;
    edited = owner.accounts[0];
    CHECK_EQ_INT(safe_strncpy(edited.description, "edited",
                              sizeof(edited.description)), 0);
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    owner_before = owner;
    contender_before = contender;
    runner_calls = g_fake_runner_calls;

    CHECK_EQ_INT(config_add_account(&owner, &added), -1);
    CHECK_EQ_INT(config_update_account(&owner, &edited), -1);
    CHECK_EQ_INT(config_remove_account(&owner, 1), -1);
    CHECK_EQ_INT(config_add_account(&contender, &added), -1);
    CHECK_EQ_INT(config_update_account(&contender, &edited), -1);
    CHECK_EQ_INT(config_remove_account(&contender, 1), -1);
    CHECK_EQ_INT(config_add_account(NULL, NULL), -1);
    CHECK_EQ_INT(config_update_account(NULL, NULL), -1);
    CHECK_EQ_INT(config_remove_account(NULL, 0), -1);
    CHECK_EQ_INT(config_add_account_owned(&owner, &added, 1), -1);
    CHECK_EQ_INT(config_update_account_owned(&owner, &edited, 1), -1);
    CHECK_EQ_INT(config_remove_account_owned(&owner, 1, 1), -1);

    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(!runtime_lock_available_to_child());
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());

    CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());
    run_set_runner(previous_runner);
}

/* The runtime SSH target expands '~', while the caller-owned account model
 * deliberately keeps the original spelling. A separate frozen snapshot makes
 * that normalization compatible with an unchanged prepared commit. */
TEST(prepared_commit_accepts_unchanged_tilde_ssh_path) {
    char home[MAX_PATH_LEN];
    char saved_home[MAX_PATH_LEN];
    char key_path[MAX_PATH_LEN];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add") ||
        !command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "SSH command fixture prerequisites unavailable");
    }
    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(setup_fake_home(home, sizeof(home), saved_home,
                                 sizeof(saved_home)), 0);
    CHECK_EQ_INT(safe_snprintf(key_path, sizeof(key_path), "%s/key_target",
                               home), 0);
    CHECK_EQ_INT(write_fake_key(key_path), 0);
    ctx = make_ctx();
    ctx.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(ctx.accounts[0].ssh_key_path, "~/key_target",
                              sizeof(ctx.accounts[0].ssh_key_path)), 0);
    seed_previous_git_identity();
    previous_runner = run_set_runner(ssh_git_runner);

    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, "~/key_target");
    CHECK(strstr(g_store_sshcmd, key_path) != NULL);
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_COMPLETE),
                 0);
    CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, "~/key_target");
    CHECK_EQ_INT(accounts_session_cleanup(), 0);

    run_set_runner(previous_runner);
    CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
}

/* AR-09 M5: a clean prepared transaction owns the singleton Git snapshot,
 * cross-manager runtime lock, and guarded signal dispositions.  Every switch
 * entry point must reject before even validating its arguments while that
 * record exists.  Mismatched finalizers likewise cannot consume it; the
 * matching commit and abort paths remain usable, and clearing either record
 * reopens admission. */
TEST(clean_pending_switch_excludes_competing_entry_matrix) {
    struct sigaction guarded[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t owner;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t contender_before;
    command_runner_fn previous_runner;
    int runner_calls;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    owner = make_ctx();
    contender = make_ctx();
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);

    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(!runtime_lock_available_to_child());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &guarded[i]), 0);
    }
    owner_before = owner;
    contender.config.dry_run = true;
    contender_before = contender;
    runner_calls = g_fake_runner_calls;

    /* Same owner, different owner, and invalid arguments all lose to the
     * pending-owner check.  The dry-run contender proves prepare's public
     * precondition checks also occur after singleton admission. */
    CHECK_EQ_INT(accounts_switch(&owner, "testacct"), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(accounts_switch(&contender, "testacct"), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(accounts_switch(NULL, NULL), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     &contender, NULL,
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     NULL, NULL,
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);

    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK(!runtime_lock_available_to_child());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed), 0);
        CHECK(switch_actions_equal(&observed, &guarded[i]));
    }

    CHECK_EQ_INT(commit_switch_expect(
                     &contender,
                     ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK_EQ_INT(accounts_switch_abort(&contender, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(!runtime_lock_available_to_child());

    CHECK_EQ_INT(commit_switch_expect(
                     &owner, ACCOUNTS_SWITCH_COMMIT_COMPLETE),
                 0);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    signals_rollback_end();
    CHECK_EQ_INT(signals_guard_end(), 0);

    /* A fresh prepared transaction is admitted after commit and its matching
     * abort clears normally.  A subsequent one-call switch proves both
     * finalization paths reopen the public admission gate. */
    owner = make_ctx();
    seed_previous_git_identity();
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());

    contender = make_ctx();
    CHECK_EQ_INT(accounts_switch(&contender, "testacct"), 0);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(runtime_lock_available_to_child());
    run_set_runner(previous_runner);
}

/* An abort-only M4 retry record is still an active pending switch.  In this
 * state the runtime lock has deliberately been released, so an unguarded
 * resume-style direct call used to enter the transaction and close the
 * original signal guard.  Reject both APIs before validation, preserve the
 * conflict-safe Git retry image, and admit a new switch only after the
 * matching abort consumes it. */
TEST(abort_only_pending_switch_excludes_competing_entry_matrix) {
    struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction expected[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction guarded[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t owner;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t contender_before;
    command_runner_fn previous_runner;
    runtime_lock_holder_t lock_holder = {.pid = -1, .release_fd = -1};
    int runner_calls;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction action;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &original[i]), 0);
        memset(&action, 0, sizeof(action));
        action.sa_handler = switch_inherited_handler;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
        sigaddset(&action.sa_mask,
                  switch_guarded_signals[(i + 1) %
                                         SWITCH_GUARDED_SIGNAL_COUNT]);
        action.sa_flags = i == 1 ? SA_RESTART : 0;
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &action, NULL), 0);
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &expected[i]), 0);
    }

    owner = make_ctx();
    contender = make_ctx();
    contender.config.resuming = true;
    seed_previous_git_identity();
    g_mutate_name_before_seal = true;
    previous_runner = run_set_runner(fake_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED),
                 -1);
    g_mutate_name_before_seal = false;
    CHECK(strstr(get_last_error()->details,
                 "[Git configuration restore]") != NULL);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &guarded[i]), 0);
    }
    owner_before = owner;
    contender_before = contender;
    runner_calls = g_fake_runner_calls;

    CHECK_EQ_INT(accounts_switch(&owner, "testacct"), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(accounts_switch(&contender, "testacct"), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(accounts_switch(NULL, NULL), -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     &owner, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     &contender, NULL,
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);
    CHECK_EQ_INT(prepare_switch_expect(
                     NULL, NULL,
                     ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE),
                 -1);
    CHECK(strstr(get_last_error()->message, "already pending") != NULL);

    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed), 0);
        CHECK(switch_actions_equal(&observed, &guarded[i]));
    }

    CHECK_EQ_INT(commit_switch_expect(
                     &contender,
                     ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK_EQ_INT(accounts_switch_abort(&contender, false), -1);
    CHECK(strstr(get_last_error()->message,
                 "No prepared account switch") != NULL);
    CHECK_EQ_INT(commit_switch_expect(
                     &owner, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);
    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed), 0);
        CHECK(switch_actions_equal(&observed, &guarded[i]));
    }

    /* AR-11 M2: the abort-only owner must survive a transient failure to
     * reacquire its cross-manager lock. While a child owns the lock, the exact
     * abort fails before rollback; no commit or cross-type admission may
     * consume the owner, its signal guard, or checked rollback depth. Once the
     * child releases the lock, the same abort remains authorized and clears
     * the original obligation. */
    CHECK_EQ_INT(start_runtime_lock_holder(&lock_holder), 0);
    CHECK(!runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&owner, false), -1);
    CHECK(strstr(get_last_error()->message, "shared runtime lock") != NULL);
    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK_EQ_INT(g_fake_runner_calls, runner_calls);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());
    CHECK_EQ_INT(commit_switch_expect(
                     &owner, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);
    CHECK_EQ_INT(accounts_init(&contender), -1);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed), 0);
        CHECK(switch_actions_equal(&observed, &guarded[i]));
    }
    CHECK_EQ_INT(stop_runtime_lock_holder(&lock_holder), 0);
    CHECK(runtime_lock_available_to_child());

    safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
    CHECK_EQ_INT(accounts_switch_abort(&owner, false), 0);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());
    CHECK(!signals_guard_active());
    CHECK(!signals_rollback_active());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed), 0);
        CHECK(switch_actions_equal(&observed, &expected[i]));
    }

    contender = make_ctx();
    CHECK_EQ_INT(accounts_switch(&contender, "testacct"), 0);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(runtime_lock_available_to_child());
    run_set_runner(previous_runner);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &original[i], NULL),
                     0);
    }
}

/* AR-12 M1: failures in the post-commit finalization tail (ownership
 * release, signal-guard restore) occur after the switch's point of no
 * return: the alias has published and git_config_commit() discarded the
 * before-image. The commit-state out-parameter must then report the
 * committed state, never NOT_COMMITTED — which would authorize main to
 * restore persistence before-images around a fully committed switch. */
TEST(guard_restore_failure_after_commit_reports_committed_state) {
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    ctx = make_ctx();
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);
    CHECK_EQ_INT(prepare_switch_expect(
                     &ctx, "testacct",
                     ACCOUNTS_SWITCH_PREPARE_PREPARED),
                 0);
    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE,
                                EIO);
    rc = accounts_switch_commit_result(&ctx, &state);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_COMPLETE);
    /* The switch really committed. */
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    signals_rollback_end();
    (void)signals_guard_end();
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
}

static void fail_guard_restore_retry(void) {
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE,
                                EAGAIN);
}

/* AR-09 M4 guard-begin subphase: installation can fail after a prior handler
 * was replaced, and that partial restoration can fail too. The prepared API
 * must drive a checked restoration retry, discard its Git snapshot, and
 * return with no handle when that retry completes. */
TEST(guard_begin_partial_restore_is_synchronously_released) {
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_INSTALL,
                                EPERM);
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
    ctx = make_ctx();
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(rc, -1);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

/* If the checked restoration retry also fails, the preparation still has a
 * live process-global obligation. Publish an abort-only record, reject commit,
 * and let a later accounts_switch_abort() finish that exact disposition. */
TEST(guard_begin_restore_retry_publishes_abort_only_handle) {
    struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction expected[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction action;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &original[i]), 0);
        memset(&action, 0, sizeof(action));
        action.sa_handler = switch_inherited_handler;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
        action.sa_flags = i == 1 ? SA_RESTART : 0;
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &action, NULL), 0);
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &expected[i]), 0);
    }

    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_INSTALL,
                                EPERM);
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
    signals_test_set_guard_end_hook(fail_guard_restore_retry);
    ctx = make_ctx();
    seed_previous_git_identity();
    previous_runner = run_set_runner(fake_runner);
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(rc, -1);
    CHECK(strstr(get_last_error()->details,
                 "[signal guard release]") != NULL);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message, "No Git snapshot to seal") !=
          NULL);
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);

    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    CHECK(runtime_lock_available_to_child());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL, &observed), 0);
        CHECK(switch_actions_equal(&observed, &expected[i]));
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &original[i], NULL),
                     0);
    }
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* AR-09 M4: a preparation failure is not a successful handoff. If rollback
 * finishes synchronously, the prepared API must also release its signal
 * ownership before returning; there is no published transaction for abort to
 * reach afterwards. */
TEST(failed_prepare_releases_callers_signal_dispositions) {
    struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction expected[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction observed[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction action;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &original[i]), 0);
        memset(&action, 0, sizeof(action));
        action.sa_handler = switch_inherited_handler;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
        sigaddset(&action.sa_mask,
                  switch_guarded_signals[(i + 1) %
                                         SWITCH_GUARDED_SIGNAL_COUNT]);
        action.sa_flags = i == 1 ? SA_RESTART : 0;
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &action, NULL), 0);
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &expected[i]), 0);
    }

    ctx = make_ctx();
    seed_previous_git_identity();
    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(fake_runner);
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    run_set_runner(previous_runner);
    g_fail_user_name_set = false;

    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &observed[i]), 0);
    }

    /* Keep a failing pre-remediation run from contaminating later cases. */
    signals_rollback_end();
    CHECK_EQ_INT(signals_guard_end(), 0);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &original[i], NULL),
                     0);
    }

    CHECK_EQ_INT(rc, -1);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.config.active_account[0] == '\0');
    CHECK(!signals_pending());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK(switch_actions_equal(&observed[i], &expected[i]));
    }
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* AR-09 M4: a caller-owned handler may return after the prepared failure path
 * restores and dispatches a deferred signal.  The API still returns failure in
 * that case, so its diagnostic must identify the interruption rather than
 * resurrecting an unrelated pre-signal error from the successful Git step. */
TEST(prepared_interruption_preserves_failure_diagnostic) {
    struct sigaction original;
    struct sigaction action;
    error_context_t failure;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK_EQ_INT(sigaction(SIGINT, NULL, &original), 0);
    memset(&action, 0, sizeof(action));
    action.sa_handler = switch_inherited_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    CHECK_EQ_INT(sigaction(SIGINT, &action, NULL), 0);

    ctx = make_ctx();
    seed_previous_git_identity();
    g_guard_end_checkpoint_signal = 0;
    g_fail_user_name_set = false;
    g_raise_on_user_name = true;
    g_log = NULL;
    previous_runner = run_set_runner(fake_runner);
    clear_error();
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    failure = *get_last_error();
    run_set_runner(previous_runner);
    g_raise_on_user_name = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_guard_end_checkpoint_signal, SIGINT);
    CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
    CHECK(strstr(failure.message, "Switch interrupted by signal") != NULL);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(!signals_pending());
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);

    CHECK_EQ_INT(sigaction(SIGINT, &original, NULL), 0);
}

/* AR-09 M4 phase 6: a writer arriving between managed Git publication and
 * post-image sealing makes rollback intentionally conflict-safe. Failed
 * preparation must expose that exact retained snapshot through an abort-only
 * handle; after the writer restores the sealed image, retry can recover the
 * before-image and release signal ownership. */
TEST(prepared_seal_failure_retains_abort_retry_handle) {
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    ctx = make_ctx();
    seed_previous_git_identity();
    g_mutate_name_before_seal = true;
    previous_runner = run_set_runner(fake_runner);
    rc = prepare_switch_expect(
        &ctx, "testacct", ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED);
    run_set_runner(previous_runner);
    g_mutate_name_before_seal = false;

    CHECK_EQ_INT(rc, -1);
    CHECK_STR_EQ(g_store_name, "preseal-writer");
    /* Non-conflicting vectors are restored immediately; only the externally
     * changed name remains in the retained retry record. */
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(strstr(get_last_error()->details,
                 "[Git configuration restore]") != NULL);
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(commit_switch_expect(
                     &ctx, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED),
                 -1);
    CHECK(strstr(get_last_error()->message, "can only be retried") != NULL);

    safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
    previous_runner = run_set_runner(fake_runner);
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), 0);
    run_set_runner(previous_runner);
    CHECK_STR_EQ(g_store_name, "Previous Name");
    CHECK_STR_EQ(g_store_email, "prev@example.com");
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.config.active_account[0] == '\0');
    CHECK(runtime_lock_available_to_child());
    CHECK_EQ_INT(accounts_switch_abort(&ctx, false), -1);
    CHECK(strstr(get_last_error()->message, "No prepared account switch") !=
          NULL);
}

/* AR-08 M6: the one-call API owns its complete signal lifecycle. This test
 * intentionally performs no signals_guard_end() cleanup after the switch;
 * every caller disposition and pending-state bit must already be restored. */
TEST(direct_switch_restores_callers_signal_dispositions) {
    struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
    struct sigaction expected[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction action;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &original[i]), 0);
        memset(&action, 0, sizeof(action));
        action.sa_handler = switch_inherited_handler;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
        sigaddset(&action.sa_mask,
                  switch_guarded_signals[(i + 1) %
                                         SWITCH_GUARDED_SIGNAL_COUNT]);
        action.sa_flags = i == 1 ? SA_RESTART : 0;
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &action, NULL), 0);
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &expected[i]), 0);
    }

    ctx = make_ctx();
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    previous_runner = run_set_runner(fake_runner);
    rc = accounts_switch(&ctx, "testacct");
    run_set_runner(previous_runner);

    CHECK_EQ_INT(rc, 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK(!signals_pending());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL, &observed), 0);
        CHECK(switch_actions_equal(&observed, &expected[i]));
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &original[i], NULL),
                     0);
    }
}

/* Restoration itself can fail after the durable switch has committed. The
 * API must report that exact partial-success truth and retain the unrestored
 * disposition for a checked retry instead of returning a false success. */
TEST(direct_switch_reports_signal_restoration_failure_after_commit) {
    struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    int rc;
    int returned_errno;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                               &original[i]), 0);
    }
    ctx = make_ctx();
    seed_previous_git_identity();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
    previous_runner = run_set_runner(fake_runner);
    errno = 0;
    rc = accounts_switch(&ctx, "testacct");
    returned_errno = errno;
    run_set_runner(previous_runner);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(returned_errno, EIO);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(g_store_name, "testacct");
    CHECK_STR_EQ(g_store_email, "test@example.com");
    CHECK(strstr(get_last_error()->message, "switch committed") != NULL);
    CHECK(strstr(get_last_error()->message, "signal dispositions failed") !=
          NULL);
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK(!signals_pending());
    for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction observed;

        CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL, &observed), 0);
        CHECK(switch_actions_equal(&observed, &original[i]));
    }
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

/* A signal can arrive after a direct API caller's first pending-state read but
 * while guard_end is still restoring handlers. The successful return path
 * must recheck and dispatch it instead of leaking stale pending ownership. */
TEST(direct_switch_dispatches_signal_arriving_during_guard_end) {
    for (size_t signal_index = 0;
         signal_index < SWITCH_GUARDED_SIGNAL_COUNT; signal_index++) {
        struct sigaction original[SWITCH_GUARDED_SIGNAL_COUNT];
        struct sigaction expected[SWITCH_GUARDED_SIGNAL_COUNT];
        int signal_number = switch_guarded_signals[signal_index];
        gitswitch_ctx_t ctx;
        command_runner_fn previous_runner;
        int rc;

        CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
        for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
            struct sigaction action;

            CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                                   &original[i]), 0);
            memset(&action, 0, sizeof(action));
            action.sa_handler = switch_inherited_handler;
            sigemptyset(&action.sa_mask);
            sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
            action.sa_flags = i == 2 ? SA_RESTART : 0;
            CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &action, NULL),
                         0);
            CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                                   &expected[i]), 0);
        }
        ctx = make_ctx();
        seed_previous_git_identity();
        g_fail_user_name_set = false;
        g_raise_on_user_name = false;
        g_log = NULL;
        g_guard_end_checkpoint_signal = 0;
        g_guard_end_hook_signal = signal_number;
        previous_runner = run_set_runner(fake_runner);
        (void)signals_test_set_guard_end_hook(raise_during_guard_end);
        rc = accounts_switch(&ctx, "testacct");
        run_set_runner(previous_runner);

        CHECK_EQ_INT(rc, 0);
        CHECK_EQ_INT(g_guard_end_checkpoint_signal, signal_number);
        CHECK(!signals_pending());
        for (size_t i = 0; i < SWITCH_GUARDED_SIGNAL_COUNT; i++) {
            struct sigaction observed;

            CHECK_EQ_INT(sigaction(switch_guarded_signals[i], NULL,
                                   &observed), 0);
            CHECK(switch_actions_equal(&observed, &expected[i]));
            CHECK_EQ_INT(sigaction(switch_guarded_signals[i], &original[i],
                                   NULL), 0);
        }
    }
}

/* Causal restoration-failure witness for the checked abort path. Before the
 * fix, abort ignored guard_end's failure and dispatch immediately retried it,
 * killing the child and erasing the only observable retry boundary. */
TEST(interrupted_switch_retains_pending_signal_on_restore_failure) {
    char retained_marker[512];
    int status = 0;
    pid_t pid;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
    CHECK((size_t)snprintf(retained_marker, sizeof(retained_marker),
                           "%s/guard-restore-retained", g_xdg) <
          sizeof(retained_marker));
    seed_previous_git_identity();
    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct sigaction default_action;
        gitswitch_ctx_t ctx = make_ctx();
        int marker_fd;
        int rc;

        memset(&default_action, 0, sizeof(default_action));
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        if (sigaction(SIGINT, &default_action, NULL) != 0) _exit(60);
        g_fail_user_name_set = false;
        g_raise_on_user_name = true;
        g_log = NULL;
        signals_test_fail_sigaction(SIGINT,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        run_set_runner(fake_runner);
        errno = 0;
        rc = accounts_switch(&ctx, "testacct");
        if (rc != -1 || errno != EIO) _exit(61);
        if (!signals_pending() || signals_pending_signal() != SIGINT) {
            _exit(62);
        }
        if (!strstr(get_last_error()->message, "retained for retry")) {
            _exit(63);
        }
        marker_fd = open(retained_marker,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker_fd < 0 || close(marker_fd) != 0) _exit(64);
        (void)signals_dispatch_pending(); /* explicit retry must terminate */
        _exit(65);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);
    CHECK(access(retained_marker, F_OK) == 0);
    (void)unlink(retained_marker);
}

/* AR-08 M4: prepare has already published Git/runtime state but persistence
 * has not committed. Two signals at this exact handoff must remain deferred;
 * abort restores the prior Git vector and only then re-raises normally. The
 * pre-fix implementation cleared repeat deferral before returning prepare,
 * so the second raise killed the child before any restore command appeared. */
TEST(repeated_signals_wait_for_prepared_switch_rollback) {
    for (size_t signal_index = 0;
         signal_index < SWITCH_GUARDED_SIGNAL_COUNT; signal_index++) {
        char log_path[512];
        int signal_number = switch_guarded_signals[signal_index];
        int status = 0;
        pid_t pid;
        bool seen_handoff = false;
        bool restored_after_handoff = false;

        CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
        CHECK((size_t)snprintf(log_path, sizeof(log_path),
                               "%s/handoff-%d.log", g_xdg,
                               signal_number) < sizeof(log_path));
        seed_previous_git_identity();
        fflush(NULL);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            struct sigaction default_action;
            gitswitch_ctx_t ctx = make_ctx();
            accounts_switch_prepare_state_t state =
                ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;

            memset(&default_action, 0, sizeof(default_action));
            default_action.sa_handler = SIG_DFL;
            sigemptyset(&default_action.sa_mask);
            if (sigaction(signal_number, &default_action, NULL) != 0) _exit(20);
            g_fail_user_name_set = false;
            g_raise_on_user_name = false;
            g_log = fopen(log_path, "w");
            if (!g_log) _exit(21);
            run_set_runner(fake_runner);
            if (accounts_switch_prepare_result(
                    &ctx, "testacct", &state) != 0) {
                _exit(22);
            }
            if (state != ACCOUNTS_SWITCH_PREPARE_PREPARED) _exit(26);
            if (fputs("MARK-HANDOFF\n", g_log) == EOF || fflush(g_log) != 0)
                _exit(23);
            raise(signal_number);
            raise(signal_number);
            if (!signals_pending() ||
                signals_pending_signal() != signal_number) _exit(24);
            (void)accounts_switch_abort(&ctx, false);
            _exit(25); /* completed abort dispatches the pending signal */
        }

        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), signal_number);
        {
            char line[1024];
            FILE *log = fopen(log_path, "r");

            CHECK(log != NULL);
            if (log) {
                while (fgets(line, sizeof(line), log)) {
                    if (strstr(line, "MARK-HANDOFF")) {
                        seen_handoff = true;
                    } else if (seen_handoff && strstr(line, "user.name") &&
                               strstr(line, "Previous Name")) {
                        restored_after_handoff = true;
                    }
                }
                fclose(log);
            }
        }
        CHECK(seen_handoff);
        CHECK(restored_after_handoff);
    }
}

/* AR-08 M4/M7: a prepared abort that preserves a concurrent Git vector is
 * intentionally incomplete and retryable. Its retained retry handle includes
 * both signal layers: two signals delivered before the writer repairs the
 * exact post-image cannot kill the process until the second abort restores
 * the before-image. This is also the accounts-level witness that M7's precise
 * conflict diagnostic survives the broader runtime cleanup path. */
TEST(incomplete_prepared_abort_retains_signal_ownership_until_retry) {
    for (size_t signal_index = 0;
         signal_index < SWITCH_GUARDED_SIGNAL_COUNT; signal_index++) {
        char log_path[512];
        char line[1024];
        int signal_number = switch_guarded_signals[signal_index];
        int status = 0;
        pid_t pid;
        bool seen_incomplete = false;
        bool restored_after_retry = false;

        CHECK_EQ_INT(setup_empty_runtime_dir(), 0);
        CHECK((size_t)snprintf(log_path, sizeof(log_path),
                               "%s/incomplete-abort-%d.log", g_xdg,
                               signal_number) < sizeof(log_path));
        seed_previous_git_identity();
        fflush(NULL);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            struct sigaction default_action;
            gitswitch_ctx_t ctx = make_ctx();
            accounts_switch_prepare_state_t state =
                ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;

            memset(&default_action, 0, sizeof(default_action));
            default_action.sa_handler = SIG_DFL;
            sigemptyset(&default_action.sa_mask);
            if (sigaction(signal_number, &default_action, NULL) != 0) _exit(40);
            g_fail_user_name_set = false;
            g_raise_on_user_name = false;
            g_log = fopen(log_path, "w");
            if (!g_log) _exit(41);
            run_set_runner(fake_runner);
            if (accounts_switch_prepare_result(
                    &ctx, "testacct", &state) != 0) {
                _exit(42);
            }
            if (state != ACCOUNTS_SWITCH_PREPARE_PREPARED) _exit(48);

            /* External writer after the sealed post-image. */
            safe_strncpy(g_store_name, "later-writer",
                         sizeof(g_store_name));
            if (accounts_switch_abort(&ctx, false) != -1) _exit(43);
            if (!strstr(get_last_error()->message, "1 managed vector(s)") ||
                !strstr(get_last_error()->message, "changed outside") ||
                !strstr(get_last_error()->message, "retry material")) {
                _exit(44);
            }
            if (fputs("MARK-INCOMPLETE-ABORT\n", g_log) == EOF ||
                fflush(g_log) != 0) {
                _exit(45);
            }

            raise(signal_number);
            raise(signal_number);
            if (!signals_pending() ||
                signals_pending_signal() != signal_number) {
                _exit(46);
            }

            /* Repair only the conflicted key to the sealed image. The
             * retained Git snapshot now owns it again and retry can finish. */
            safe_strncpy(g_store_name, "testacct", sizeof(g_store_name));
            (void)accounts_switch_abort(&ctx, false);
            _exit(47); /* completed retry dispatches the pending signal */
        }

        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), signal_number);
        {
            FILE *log = fopen(log_path, "r");

            CHECK(log != NULL);
            if (log) {
                while (fgets(line, sizeof(line), log)) {
                    if (strstr(line, "MARK-INCOMPLETE-ABORT")) {
                        seen_incomplete = true;
                    } else if (seen_incomplete && strstr(line, "user.name") &&
                               strstr(line, "Previous Name")) {
                        restored_after_retry = true;
                    }
                }
                fclose(log);
            }
        }
        CHECK(seen_incomplete);
        CHECK(restored_after_retry);
    }
}

/* ---- AR-03 M3: guard continuity through the post-switch window ------------ */

/* A signal landing AFTER the switch completed but BEFORE main() persists the
 * new active_account must be deferred, and main()'s re-arm around config_save
 * must not discard it. The child uses the prepared API that the CLI now owns,
 * then aborts so the deferred signal is re-raised after rollback. */
TEST(deferred_signal_survives_post_switch_window) {
    int status = 0;
    pid_t pid;

    CHECK_EQ_INT(setup_empty_runtime_dir(), 0);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        gitswitch_ctx_t ctx = make_ctx();
        accounts_switch_prepare_state_t state =
            ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;
        g_fail_user_name_set = false;
        g_raise_on_user_name = false;
        g_log = NULL;
        run_set_runner(fake_runner);
        if (accounts_switch_prepare_result(
                &ctx, "testacct", &state) != 0) {
            _exit(8);
        }
        if (state != ACCOUNTS_SWITCH_PREPARE_PREPARED) _exit(9);
        /* Ctrl-C in the prepared persistence gap. */
        raise(SIGINT);
        if (!signals_pending()) _exit(7);
        /* main()'s re-arm around config_save: a no-op re-begin while active —
         * it must NOT reset the deferred signal. */
        signals_guard_begin();
        if (!signals_pending() || signals_pending_signal() != SIGINT) _exit(6);
        (void)accounts_switch_abort(&ctx, false);
        _exit(5); /* abort dispatches */
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);
}

/* SIG-01: a SIGINT during the git-config write must be deferred, the rollback
 * must run (restore commands appear in the log AFTER the signal), and the
 * process must then die by SIGINT. Without the guard the raise() kills the
 * child on the spot: no log lines after MARK-RAISE and no rollback. */
TEST(sigint_mid_git_config_rolls_back_then_reraises) {
    char log_path[512];
    int status = 0;
    pid_t pid;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    snprintf(log_path, sizeof(log_path), "%s/runner.log", g_xdg);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        gitswitch_ctx_t ctx = make_ctx();
        g_fail_user_name_set = false;
        g_raise_on_user_name = true;
        g_log = fopen(log_path, "w");
        if (!g_log) _exit(9);
        run_set_runner(fake_runner);
        (void)accounts_switch(&ctx, "testacct");
        _exit(42); /* must NOT be reached: the deferred SIGINT re-raises */
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);

    /* The runtime symlinks of the previous account survive the rollback. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));

    /* The log must show the switch surviving the signal and rolling back:
     * at least one `git config ... --unset` restore command after MARK-RAISE. */
    {
        char line[1024];
        bool seen_mark = false, rollback_after_mark = false;
        FILE *f = fopen(log_path, "r");
        CHECK(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "MARK-RAISE")) {
                    seen_mark = true;
                } else if (seen_mark && strstr(line, "--unset")) {
                    rollback_after_mark = true;
                }
            }
            fclose(f);
        }
        CHECK(seen_mark);
        CHECK(rollback_after_mark);
    }
}

TEST_MAIN_BEGIN()
    const ssh_reap_test_ops_t generation_ops = {
        .generation = capture_rollback_process_generation,
        .pidfd_open = retire_fake_agent_pidfd_open,
    };
    ssh_reap_test_ops_t previous_reap_ops =
        ssh_manager_set_reap_test_ops(&generation_ops);
    g_previous_reap_ops = previous_reap_ops;
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(unpersisted_target_fails_before_switch_mutation);
    RUN_TEST(snapshot_failure_aborts_before_any_git_write);
    RUN_TEST(signal_guard_failure_aborts_before_switch_mutation);
    RUN_TEST(snapshot_listing_failure_aborts_before_ssh_activation);
    RUN_TEST(failed_git_config_keeps_previous_runtime_isolation);
    RUN_TEST(successful_switch_still_tears_down_previous_isolation);
    RUN_TEST(late_runtime_teardown_failure_rolls_back_git_and_gpg);
    RUN_TEST(ssh_init_failure_keeps_previous_runtime_isolation);
    RUN_TEST(prepared_ssh_switch_failure_releases_transaction_ownership);
    RUN_TEST(repeated_switch_validation_failure_keeps_live_session);
    RUN_TEST(repeated_switch_reap_failure_preserves_live_session);
    RUN_TEST(repeated_signals_during_previous_session_cleanup_wait_for_abort);
    RUN_TEST(ssh_stable_link_obstruction_aborts_integrated_switch);
    RUN_TEST(failed_switch_restarts_previous_accounts_agent);
    RUN_TEST(postrename_alias_verification_failure_retains_complete_direct_switch);
    RUN_TEST(postrename_alias_fsync_failure_retains_complete_prepared_switch);
    RUN_TEST(first_ssh_home_sync_failure_remains_abortable_preinstall);
    RUN_TEST(identical_insecure_alias_prerename_failure_remains_abortable);
    RUN_TEST(identical_insecure_alias_dirsync_failure_retains_normalized_commit);
    RUN_TEST(late_alias_failure_retains_incomplete_direct_git_rollback_for_retry);
    RUN_TEST(incomplete_rollback_retry_survives_transient_runtime_lock_contention);
    RUN_TEST(failed_switch_never_rewrites_existing_ssh_config);
    RUN_TEST(failed_switch_never_creates_ssh_config);
    RUN_TEST(failed_switch_preserves_concurrent_ssh_config_replacement);
    RUN_TEST(final_alias_commit_rejects_concurrent_symlink_and_rolls_back);
    RUN_TEST(symlinked_ssh_config_fails_before_switch_mutation);
    RUN_TEST(structurally_invalid_ssh_config_fails_before_switch_mutation);
    RUN_TEST(fresh_alias_switch_runs_one_postcommit_probe);
    RUN_TEST(prepared_verbose_fresh_switch_runs_one_default_probe);
    RUN_TEST(failed_postcommit_probe_preserves_switch_and_diagnostic);
    RUN_TEST(postcommit_probe_failure_messages_are_cause_neutral);
    RUN_TEST(postcommit_probe_policy_skip_matrix);
    RUN_TEST(reused_agent_skips_postcommit_probe);
    RUN_TEST(pending_postcommit_signal_skips_ssh_probe);
    int gpg_preflight_rc = host_gpg_preflight();
    if (gpg_preflight_rc < 0) {
        fprintf(stderr, "HARNESS FAIL: cannot run host GPG preflight\n");
        return 1;
    }
    g_host_gpg_available = gpg_preflight_rc > 0;
    if (g_host_gpg_available && setup_gpg_command_fixture() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot prepare trusted GPG probe\n");
        return 1;
    }
    RUN_TEST(failed_inner_gpg_retarget_is_finished_by_accounts_rollback);
    RUN_TEST(abort_accumulates_git_then_gpg_failure_and_retries_exactly);
    RUN_TEST(signing_capability_failure_precedes_runtime_and_git_publication);
    RUN_TEST(prepared_commit_accepts_unchanged_gpg_selector_after_normalization);
    RUN_TEST(accounts_cleanup_retains_gpg_environment_for_checked_retry);
    RUN_TEST(repeated_switch_partial_cleanup_restores_ssh_and_retains_gpg_retry);
    RUN_TEST(accounts_git_readback_uses_canonical_key_when_signing_is_disabled);
    RUN_TEST(late_seal_failure_restores_exact_gpg_selector_vectors);
    RUN_TEST(gpg_stable_link_obstruction_aborts_integrated_switch);
    RUN_TEST(failed_switch_retargets_gpg_current_to_previous_home);
    RUN_TEST(failed_switch_does_not_overwrite_later_gpg_writer);
    if (restore_gpg_command_fixture() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot restore PATH after GPG tests\n");
        return 1;
    }
    RUN_TEST(structured_prepare_result_tracks_exact_context_ownership);
    RUN_TEST(clean_pending_switch_excludes_competing_entry_matrix);
    RUN_TEST(prepared_commit_rejects_every_frozen_account_field_change);
    RUN_TEST(prepared_switch_gates_public_account_model_mutation_matrix);
    RUN_TEST(prepared_commit_accepts_unchanged_tilde_ssh_path);
    RUN_TEST(abort_only_pending_switch_excludes_competing_entry_matrix);
    RUN_TEST(guard_restore_failure_after_commit_reports_committed_state);
    RUN_TEST(guard_begin_partial_restore_is_synchronously_released);
    RUN_TEST(guard_begin_restore_retry_publishes_abort_only_handle);
    RUN_TEST(failed_prepare_releases_callers_signal_dispositions);
    RUN_TEST(prepared_interruption_preserves_failure_diagnostic);
    RUN_TEST(prepared_seal_failure_retains_abort_retry_handle);
    RUN_TEST(direct_switch_restores_callers_signal_dispositions);
    RUN_TEST(direct_switch_reports_signal_restoration_failure_after_commit);
    RUN_TEST(direct_switch_dispatches_signal_arriving_during_guard_end);
    RUN_TEST(interrupted_switch_retains_pending_signal_on_restore_failure);
    RUN_TEST(repeated_signals_wait_for_prepared_switch_rollback);
    RUN_TEST(incomplete_prepared_abort_retains_signal_ownership_until_retry);
    RUN_TEST(deferred_signal_survives_post_switch_window);
    RUN_TEST(sigint_mid_git_config_rolls_back_then_reraises);
    close_fake_agent_listener();
    ssh_manager_set_reap_test_ops(&previous_reap_ops);
TEST_MAIN_END()
