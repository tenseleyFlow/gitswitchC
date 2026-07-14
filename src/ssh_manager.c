/* SSH key and agent management with comprehensive isolation and security
 * Implements per-account SSH agents to prevent key leakage between accounts
 */

/* flock()/LOCK_EX are BSD extensions, not POSIX, and syscall()/pidfd need the
 * GNU namespace on glibc. On macOS they need _DARWIN_C_SOURCE; on the BSDs they
 * need the default fully-visible namespace, so defining _POSIX_C_SOURCE there
 * (strict POSIX) hides them and the build fails. On Linux use _GNU_SOURCE (a
 * superset of _POSIX_C_SOURCE) so flock AND syscall()/SYS_pidfd_* are visible. */
#if defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <poll.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <inttypes.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#include "ssh_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "signals.h"
#include "toml_parser.h"

/* Private keys are normally a few KiB. Bound the descriptor-backed generation
 * retained across validation/fingerprint/load so a planted giant regular file
 * cannot turn account switching into an unbounded secret-bearing allocation. */
#define SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)

typedef struct {
    char *data;
    size_t length;
    int fd;
    bool fd_open;
    struct stat identity;
} ssh_key_snapshot_t;

/* Internal helper functions */
/* merge_stderr is int, not bool: the parameter anchors va_start, and C11
 * makes va_start on a type that undergoes default argument promotion
 * (bool -> int) undefined behavior — clang rejects it under -Wvarargs. */
static int ssh_run(char *output, size_t output_size, int merge_stderr, ...);
static int ssh_run_in_dir(int cwd_fd, char *output, size_t output_size,
                          int merge_stderr, ...);
static int ssh_add_key_pinned(int dir_fd, const char *socket_arg,
                              const char *key_path,
                              const ssh_key_snapshot_t *snapshot);
static int ssh_add_key_snapshot(ssh_config_t *ssh_config,
                                const char *key_path,
                                const ssh_key_snapshot_t *snapshot);
static int ssh_start_isolated_agent_with_key(
    ssh_config_t *ssh_config, const account_t *account,
    const ssh_key_snapshot_t *snapshot);
static int ssh_key_snapshot_capture(const char *key_path,
                                    ssh_key_snapshot_t *snapshot);
static void ssh_key_snapshot_clear(ssh_key_snapshot_t *snapshot);
static int setup_ssh_environment(ssh_config_t *ssh_config);
static int open_isolated_agent_socket_dir(char *socket_dir,
                                          size_t socket_dir_size,
                                          bool create, bool *absent);
static int validate_ssh_agent_socket_at(int dir_fd, const char *socket_name,
                                        const char *display_path,
                                        struct stat *identity);
static int verify_socket_dir_namespace(int dir_fd, const char *socket_dir);

typedef struct {
    struct stat stat;
    char target[MAX_PATH_LEN];
} ssh_current_link_identity_t;

typedef struct {
    struct stat identity;
    int fd;
    char anchor[96];
} ssh_runtime_pin_t;

static int capture_current_socket_link(int dir_fd, const char *socket_path,
                                       const char *display_path,
                                       ssh_current_link_identity_t *identity);
static int publish_current_socket_link(int dir_fd, const char *socket_path,
                                       const char *display_path,
                                       ssh_current_link_identity_t *identity);
static int remove_current_socket_link_if_unchanged(
    int dir_fd, const ssh_current_link_identity_t *identity);
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config);
static int kill_orphaned_gitswitch_agents(int dir_fd, const char *socket_dir,
                                          const char *keep_account);
static bool same_runtime_identity(const struct stat *before,
                                  const struct stat *after);
static bool same_runtime_revision(const struct stat *before,
                                  const struct stat *after);
static bool same_runtime_symlink(const struct stat *before,
                                 const struct stat *after);
static void ssh_runtime_pin_init(ssh_runtime_pin_t *pin);
static int pin_ssh_runtime_entry_at(int dir_fd, const char *name,
                                    const char *display_path,
                                    ssh_runtime_pin_t *pin);
static int verify_ssh_runtime_pin_at(int dir_fd, const char *name,
                                     const char *display_path,
                                     const ssh_runtime_pin_t *pin);
static int release_ssh_runtime_pin(int dir_fd, ssh_runtime_pin_t *pin);
static int reconcile_ssh_runtime_pins(int dir_fd, const char *socket_dir);
static int read_ssh_agent_pid_at(int dir_fd, const char *name,
                                 const char *display_path, pid_t *pid_out,
                                 ssh_runtime_pin_t *pin);
static int write_ssh_agent_pid_at(int dir_fd, const char *name, pid_t pid);
static ssh_process_outcome_t reap_ssh_agent(pid_t pid, const char *sock,
                                            int runtime_dir_fd);
static ssh_process_outcome_t pid_is_our_ssh_agent(pid_t pid,
                                                   const char *expected_sock,
                                                   int runtime_dir_fd);
static int ssh_process_signal_real(pid_t pid, int signal_number);
static int ssh_pidfd_open_real(pid_t pid);
static int ssh_pidfd_signal_real(int pidfd, int signal_number);
static int sync_ssh_runtime_dir(int dir_fd, const char *operation);
static int unlink_ssh_runtime_entry(int dir_fd, const char *name,
                                    bool missing_ok,
                                    const char *description);
static int unlink_ssh_runtime_identity_at(
    int dir_fd, const char *name, const struct stat *expected,
    bool missing_ok, const char *description,
    ssh_quarantine_hook_fn predelete_hook, struct stat *observed_out);
static int unlink_ssh_reset_path_at(int dir_fd, const char *name,
                                    const char *display_path,
                                    const char *description,
                                    const ssh_runtime_pin_t *pin,
                                    bool expected_present);
static int wait_for_ssh_probe(int fd, int timeout_ms);
static int probe_ssh_agent_socket(const char *path, bool *reachable);
static int reconcile_current_socket_quarantines(int dir_fd,
                                                const char *socket_dir);

typedef struct {
    char *auth_sock;
    char *agent_pid;
} ssh_env_snapshot_t;

/* Narrow dependency seam for exercising partial setenv failures. Production
 * always uses libc setenv; tests can replace it temporarily and must restore
 * the returned previous function. Snapshot rollback deliberately keeps using
 * libc directly so an injected failure cannot disable recovery itself. */
static ssh_setenv_fn g_ssh_setenv = setenv;
static ssh_reap_fn g_ssh_reap = reap_ssh_agent;
static ssh_reap_test_ops_t g_reap_ops = {
    .identity = pid_is_our_ssh_agent,
    .signal = ssh_process_signal_real,
    .pidfd_open = ssh_pidfd_open_real,
    .pidfd_signal = ssh_pidfd_signal_real
};
static ssh_pid_commit_hook_fn g_pid_commit_hook;
static ssh_pid_commit_hook_fn g_pid_postrename_hook;
static ssh_namespace_commit_hook_fn g_namespace_commit_hook;
static ssh_dirsync_fn g_ssh_dirsync = fsync;
static ssh_config_commit_hook_fn g_ssh_config_commit_hook;
static ssh_config_postrename_hook_fn g_ssh_config_postrename_hook;
static ssh_current_cleanup_hook_fn g_current_cleanup_hook;
static ssh_current_precleanup_hook_fn g_current_precleanup_hook;
static ssh_current_publish_hook_fn g_current_publish_hook;
static ssh_quarantine_hook_fn g_quarantine_hook;
static ssh_quarantine_hook_fn g_quarantine_capture_hook;
static ssh_quarantine_hook_fn g_reset_retire_hook;
static ssh_quarantine_hook_fn g_unrecorded_cleanup_hook;
static bool g_force_portable_quarantine;
static unsigned int g_agent_lock_depth;
static int ssh_key_open_real(const char *path, int flags) {
    return open(path, flags);
}
static ssh_key_open_fn g_ssh_key_open = ssh_key_open_real;
static ssh_key_snapshot_clear_hook_fn g_key_snapshot_clear_hook;

static int64_t ssh_probe_clock_real(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int ssh_probe_poll_real(int fd, int timeout_ms) {
    struct pollfd pfd;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    return poll(&pfd, 1, timeout_ms);
}

static ssh_probe_clock_fn g_probe_clock = ssh_probe_clock_real;
static ssh_probe_poll_fn g_probe_poll = ssh_probe_poll_real;

ssh_setenv_fn ssh_manager_set_setenv_fn(ssh_setenv_fn fn) {
    ssh_setenv_fn previous = g_ssh_setenv;
    g_ssh_setenv = fn ? fn : setenv;
    return previous;
}

ssh_reap_fn ssh_manager_set_reap_fn(ssh_reap_fn fn) {
    ssh_reap_fn previous = g_ssh_reap;
    g_ssh_reap = fn ? fn : reap_ssh_agent;
    return previous;
}

ssh_reap_test_ops_t ssh_manager_set_reap_test_ops(
    const ssh_reap_test_ops_t *ops) {
    ssh_reap_test_ops_t previous = g_reap_ops;

    g_reap_ops.identity = ops && ops->identity
                              ? ops->identity
                              : pid_is_our_ssh_agent;
    g_reap_ops.signal = ops && ops->signal
                            ? ops->signal
                            : ssh_process_signal_real;
    g_reap_ops.pidfd_open = ops && ops->pidfd_open
                                ? ops->pidfd_open
                                : ssh_pidfd_open_real;
    g_reap_ops.pidfd_signal = ops && ops->pidfd_signal
                                  ? ops->pidfd_signal
                                  : ssh_pidfd_signal_real;
    return previous;
}

ssh_pid_commit_hook_fn ssh_manager_set_pid_commit_hook_fn(
    ssh_pid_commit_hook_fn fn) {
    ssh_pid_commit_hook_fn previous = g_pid_commit_hook;
    g_pid_commit_hook = fn;
    return previous;
}

ssh_pid_commit_hook_fn ssh_manager_set_pid_postrename_hook_fn(
    ssh_pid_commit_hook_fn fn) {
    ssh_pid_commit_hook_fn previous = g_pid_postrename_hook;
    g_pid_postrename_hook = fn;
    return previous;
}

ssh_namespace_commit_hook_fn ssh_manager_set_namespace_commit_hook_fn(
    ssh_namespace_commit_hook_fn fn) {
    ssh_namespace_commit_hook_fn previous = g_namespace_commit_hook;
    g_namespace_commit_hook = fn;
    return previous;
}

ssh_dirsync_fn ssh_manager_set_dirsync_fn(ssh_dirsync_fn fn) {
    ssh_dirsync_fn previous = g_ssh_dirsync;
    g_ssh_dirsync = fn ? fn : fsync;
    return previous;
}

ssh_config_commit_hook_fn ssh_manager_set_config_commit_hook_fn(
    ssh_config_commit_hook_fn fn) {
    ssh_config_commit_hook_fn previous = g_ssh_config_commit_hook;
    g_ssh_config_commit_hook = fn;
    return previous;
}

ssh_config_postrename_hook_fn ssh_manager_set_config_postrename_hook_fn(
    ssh_config_postrename_hook_fn fn) {
    ssh_config_postrename_hook_fn previous = g_ssh_config_postrename_hook;
    g_ssh_config_postrename_hook = fn;
    return previous;
}

ssh_current_cleanup_hook_fn ssh_manager_set_current_cleanup_hook_fn(
    ssh_current_cleanup_hook_fn fn) {
    ssh_current_cleanup_hook_fn previous = g_current_cleanup_hook;
    g_current_cleanup_hook = fn;
    return previous;
}

ssh_current_precleanup_hook_fn ssh_manager_set_current_precleanup_hook_fn(
    ssh_current_precleanup_hook_fn fn) {
    ssh_current_precleanup_hook_fn previous = g_current_precleanup_hook;
    g_current_precleanup_hook = fn;
    return previous;
}

ssh_current_publish_hook_fn ssh_manager_set_current_publish_hook_fn(
    ssh_current_publish_hook_fn fn) {
    ssh_current_publish_hook_fn previous = g_current_publish_hook;
    g_current_publish_hook = fn;
    return previous;
}

ssh_quarantine_hook_fn ssh_manager_set_quarantine_hook_fn(
    ssh_quarantine_hook_fn fn) {
    ssh_quarantine_hook_fn previous = g_quarantine_hook;
    g_quarantine_hook = fn;
    return previous;
}

ssh_quarantine_hook_fn ssh_manager_set_quarantine_capture_hook_fn(
    ssh_quarantine_hook_fn fn) {
    ssh_quarantine_hook_fn previous = g_quarantine_capture_hook;
    g_quarantine_capture_hook = fn;
    return previous;
}

ssh_quarantine_hook_fn ssh_manager_set_reset_retire_hook_fn(
    ssh_quarantine_hook_fn fn) {
    ssh_quarantine_hook_fn previous = g_reset_retire_hook;
    g_reset_retire_hook = fn;
    return previous;
}

ssh_quarantine_hook_fn ssh_manager_set_unrecorded_cleanup_hook_fn(
    ssh_quarantine_hook_fn fn) {
    ssh_quarantine_hook_fn previous = g_unrecorded_cleanup_hook;
    g_unrecorded_cleanup_hook = fn;
    return previous;
}

bool ssh_manager_set_force_portable_quarantine(bool force) {
    bool previous = g_force_portable_quarantine;
    g_force_portable_quarantine = force;
    return previous;
}

ssh_key_open_fn ssh_manager_set_key_open_fn(ssh_key_open_fn fn) {
    ssh_key_open_fn previous = g_ssh_key_open;
    g_ssh_key_open = fn ? fn : ssh_key_open_real;
    return previous;
}

ssh_key_snapshot_clear_hook_fn ssh_manager_set_key_snapshot_clear_hook_fn(
    ssh_key_snapshot_clear_hook_fn fn) {
    ssh_key_snapshot_clear_hook_fn previous = g_key_snapshot_clear_hook;
    g_key_snapshot_clear_hook = fn;
    return previous;
}

ssh_probe_clock_fn ssh_manager_set_probe_clock_fn(ssh_probe_clock_fn fn) {
    ssh_probe_clock_fn previous = g_probe_clock;
    g_probe_clock = fn ? fn : ssh_probe_clock_real;
    return previous;
}

ssh_probe_poll_fn ssh_manager_set_probe_poll_fn(ssh_probe_poll_fn fn) {
    ssh_probe_poll_fn previous = g_probe_poll;
    g_probe_poll = fn ? fn : ssh_probe_poll_real;
    return previous;
}

static int sync_ssh_runtime_dir(int dir_fd, const char *operation) {
    if (g_ssh_dirsync(dir_fd) == 0) return 0;
    set_system_error(ERR_FILE_IO, "Failed to sync SSH runtime directory after %s",
                     operation ? operation : "namespace change");
    return -1;
}

/* Runtime removals are not complete until the containing directory is
 * durable. Callers retain a nonzero result as retry/uncertain state instead of
 * claiming teardown succeeded after an unsynced unlink. */
static int unlink_ssh_runtime_entry(int dir_fd, const char *name,
                                    bool missing_ok,
                                    const char *description) {
    if (unlinkat(dir_fd, name, 0) == 0) {
        return sync_ssh_runtime_dir(dir_fd,
                                    description ? description : "artifact removal");
    }
    if (missing_ok && errno == ENOENT) {
        /* This can be a retry after an earlier unlink whose directory fsync
         * failed. Sync the observed absence now; otherwise the retry would
         * incorrectly convert uncertain durability into success. */
        return sync_ssh_runtime_dir(
            dir_fd, description ? description : "artifact absence verification");
    }
    set_system_error(ERR_FILE_IO, "Failed to remove SSH %s: %s",
                     description ? description : "runtime entry", name);
    return -1;
}

/* setup_ssh_environment mutates the process environment before the stable
 * current.sock link is committed. Preserve the old values so a failed commit
 * does not leave this process pointed at an account it rejected. */
static int ssh_env_snapshot_take(ssh_env_snapshot_t *snapshot) {
    const char *value;

    memset(snapshot, 0, sizeof(*snapshot));
    value = getenv("SSH_AUTH_SOCK");
    if (value) {
        snapshot->auth_sock = strdup(value);
        if (!snapshot->auth_sock) {
            set_error(ERR_MEMORY_ALLOCATION, "Failed to snapshot SSH_AUTH_SOCK");
            return -1;
        }
    }
    value = getenv("SSH_AGENT_PID");
    if (value) {
        snapshot->agent_pid = strdup(value);
        if (!snapshot->agent_pid) {
            free(snapshot->auth_sock);
            snapshot->auth_sock = NULL;
            set_error(ERR_MEMORY_ALLOCATION, "Failed to snapshot SSH_AGENT_PID");
            return -1;
        }
    }
    return 0;
}

static void ssh_env_snapshot_restore(ssh_env_snapshot_t *snapshot) {
    if (snapshot->auth_sock) {
        (void)setenv("SSH_AUTH_SOCK", snapshot->auth_sock, 1);
    } else {
        (void)unsetenv("SSH_AUTH_SOCK");
    }
    if (snapshot->agent_pid) {
        (void)setenv("SSH_AGENT_PID", snapshot->agent_pid, 1);
    } else {
        (void)unsetenv("SSH_AGENT_PID");
    }
    free(snapshot->auth_sock);
    free(snapshot->agent_pid);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ssh_env_snapshot_discard(ssh_env_snapshot_t *snapshot) {
    free(snapshot->auth_sock);
    free(snapshot->agent_pid);
    memset(snapshot, 0, sizeof(*snapshot));
}

/* Encode the pinned runtime-directory identity into the relative -a argument.
 * The marker directory is present only while ssh-agent binds; the lexical
 * dev/inode token remains in argv for later provenance checks. This preserves
 * descriptor-relative binding while making identical socket basenames in two
 * runtime roots distinguishable on Linux, macOS, and FreeBSD. */
#define SSH_AGENT_PROVENANCE_PREFIX ".gsp-"

static int build_provenance_socket_arg(int dir_fd, const char *socket_name,
                                       char *buf, size_t buf_size,
                                       char *marker, size_t marker_size) {
    struct stat runtime;
    const char *leaf;
    char local_marker[80];
    int marker_len;
    int arg_len;

    if (dir_fd < 0 || !socket_name || !*socket_name || !buf || buf_size == 0) {
        errno = EINVAL;
        return -1;
    }
    leaf = strrchr(socket_name, '/');
    leaf = leaf ? leaf + 1 : socket_name;
    if (!*leaf || strchr(leaf, '/')) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(dir_fd, &runtime) != 0) return -1;
    /* The format is a compile-time literal and every bounded-write failure is
     * rejected before local_marker is consumed. */
    // flawfinder: ignore
    marker_len = snprintf(local_marker, sizeof(local_marker),
                          SSH_AGENT_PROVENANCE_PREFIX "%jx-%jx",
                          (uintmax_t)runtime.st_dev,
                          (uintmax_t)runtime.st_ino);
    if (marker_len <= 0 || (size_t)marker_len >= sizeof(local_marker)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    arg_len = snprintf(buf, buf_size, "%s/../%s", local_marker, leaf);
    if (arg_len <= 0 || (size_t)arg_len >= buf_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (marker) {
        if (marker_size == 0 ||
            (size_t)marker_len >= marker_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(marker, local_marker, (size_t)marker_len + 1U);
    }
    return 0;
}

static ssh_process_outcome_t socket_argument_outcome(
    const char *actual, const char *expected, int runtime_dir_fd) {
    const char *leaf;
    char qualified[MAX_PATH_LEN];

    if (!actual || !*actual || !expected || !*expected) {
        return SSH_PROCESS_INDETERMINATE;
    }
    leaf = strrchr(expected, '/');
    leaf = leaf ? leaf + 1 : expected;

    /* A legacy absolute launch has an unambiguous complete argument. An
     * in-memory configuration may also retain the exact provenance argument. */
    if (strcmp(actual, expected) == 0) {
        if (actual[0] == '/' ||
            strncmp(actual, SSH_AGENT_PROVENANCE_PREFIX,
                    sizeof(SSH_AGENT_PROVENANCE_PREFIX) - 1U) == 0) {
            return SSH_PROCESS_OWNED;
        }
        /* A bare legacy basename cannot identify which runtime root resolved
         * it. Retain its record rather than guessing. */
        return SSH_PROCESS_INDETERMINATE;
    }
    if (runtime_dir_fd >= 0 &&
        build_provenance_socket_arg(runtime_dir_fd, leaf, qualified,
                                    sizeof(qualified), NULL, 0) == 0 &&
        strcmp(actual, qualified) == 0) {
        return SSH_PROCESS_OWNED;
    }
    if (strcmp(actual, leaf) == 0) {
        return SSH_PROCESS_INDETERMINATE;
    }
    return SSH_PROCESS_UNRELATED;
}

/* Classify a NUL-separated argv whose executable must be ssh-agent and whose
 * `-a` value must carry the exact managed socket provenance. Requiring the
 * complete option value, rather than a substring anywhere in the command
 * line, avoids signaling an agent whose unrelated argument mentions it.
 *
 * Guarded to the platforms whose reaper calls it (Linux procfs, FreeBSD
 * sysctl argv). macOS uses counted_argv_is_our_ssh_agent instead, so an
 * unguarded definition is an unused-function error there under clang+WERROR. */
#if defined(__linux__) || defined(__FreeBSD__)
static ssh_process_outcome_t argv_is_our_ssh_agent(
    const char *argv, size_t argv_len, const char *expected_sock,
    int runtime_dir_fd) {
    bool expect_socket = false;
    bool matched_socket = false;
    size_t offset = 0;
    size_t index = 0;

    if (!argv || argv_len == 0 || !expected_sock || !*expected_sock) {
        return SSH_PROCESS_INDETERMINATE;
    }

    while (offset < argv_len) {
        const char *token = argv + offset;
        size_t token_len = strnlen(token, argv_len - offset);
        if (token_len == argv_len - offset) {
            return SSH_PROCESS_INDETERMINATE;
        }
        if (token_len == 0) {
            offset++;
            continue;
        }

        if (index == 0) {
            const char *basename = strrchr(token, '/');
            basename = basename ? basename + 1 : token;
            if (strcmp(basename, "ssh-agent") != 0) {
                return SSH_PROCESS_UNRELATED;
            }
        } else if (expect_socket) {
            ssh_process_outcome_t socket_outcome = socket_argument_outcome(
                token, expected_sock, runtime_dir_fd);
            if (socket_outcome != SSH_PROCESS_OWNED) return socket_outcome;
            matched_socket = true;
            expect_socket = false;
        } else if (strcmp(token, "-a") == 0) {
            if (matched_socket) {
                return SSH_PROCESS_UNRELATED;
            }
            expect_socket = true;
        }

        index++;
        offset += token_len + 1;
    }
    if (expect_socket) return SSH_PROCESS_INDETERMINATE;
    return matched_socket ? SSH_PROCESS_OWNED : SSH_PROCESS_UNRELATED;
}
#endif /* __linux__ || __FreeBSD__ */

#ifdef __APPLE__
/* KERN_PROCARGS2 includes the environment after argv. Parse exactly the argc
 * entries reported by the kernel so an environment variable that happens to
 * contain "-a" and a managed socket can never authorize signaling a process.
 * Empty argv entries still count toward argc, as they do in the kernel's
 * flattened representation. */
static ssh_process_outcome_t counted_argv_is_our_ssh_agent(
    const char *argv, size_t argv_len, int argc, const char *expected_sock,
    int runtime_dir_fd) {
    bool expect_socket = false;
    bool matched_socket = false;
    size_t offset = 0;

    if (!argv || argv_len == 0 || argc <= 0 ||
        !expected_sock || !*expected_sock) {
        return SSH_PROCESS_INDETERMINATE;
    }

    for (int index = 0; index < argc; index++) {
        const char *token;
        size_t token_len;

        if (offset >= argv_len) {
            return SSH_PROCESS_INDETERMINATE;
        }
        token = argv + offset;
        token_len = strnlen(token, argv_len - offset);
        if (token_len == argv_len - offset) {
            return SSH_PROCESS_INDETERMINATE;
        }

        if (index == 0) {
            const char *basename = strrchr(token, '/');
            basename = basename ? basename + 1 : token;
            if (strcmp(basename, "ssh-agent") != 0) {
                return SSH_PROCESS_UNRELATED;
            }
        } else if (expect_socket) {
            ssh_process_outcome_t socket_outcome = socket_argument_outcome(
                token, expected_sock, runtime_dir_fd);
            if (socket_outcome != SSH_PROCESS_OWNED) return socket_outcome;
            matched_socket = true;
            expect_socket = false;
        } else if (strcmp(token, "-a") == 0) {
            if (matched_socket) {
                return SSH_PROCESS_UNRELATED;
            }
            expect_socket = true;
        }

        offset += token_len + 1;
    }
    if (expect_socket) return SSH_PROCESS_INDETERMINATE;
    return matched_socket ? SSH_PROCESS_OWNED : SSH_PROCESS_UNRELATED;
}
#endif

/* Best-effort check that a PID recorded in a sidecar still belongs to OUR
 * ssh-agent before we SIGTERM it. Sidecars can outlive their agent (crash,
 * logout, reboot on a /tmp-preserving distro); once the kernel recycles that
 * PID, a blind kill would terminate an unrelated process. Checking only that
 * the PID is *an* ssh-agent is not enough: the recycled PID may belong to the
 * user's OWN login/session ssh-agent (comm is also "ssh-agent"), and killing it
 * drops every key they had loaded. Require BOTH the ssh-agent executable and
 * our exact `-a <expected_sock>` argv pair. Linux exposes argv through procfs;
 * Darwin and FreeBSD expose it through their native process sysctl APIs. Any
 * unavailable, truncated, or unparseable identity fails closed. */
static ssh_process_outcome_t probe_process_presence(pid_t pid) {
    int attempts = 0;

    if (pid <= 1) return SSH_PROCESS_GONE;
    while (g_reap_ops.signal(pid, 0) != 0) {
        int saved_errno = errno;
        if (saved_errno == EINTR && attempts++ < 16) continue;
        if (saved_errno == ESRCH) return SSH_PROCESS_GONE;
        return SSH_PROCESS_INDETERMINATE;
    }
    return SSH_PROCESS_OWNED;
}

static ssh_process_outcome_t inspection_failure_outcome(pid_t pid) {
    ssh_process_outcome_t presence = probe_process_presence(pid);
    return presence == SSH_PROCESS_GONE ? SSH_PROCESS_GONE
                                        : SSH_PROCESS_INDETERMINATE;
}

#ifdef __linux__
static int read_proc_file(const char *path, char **data_out,
                          size_t *size_out) {
    const size_t limit = 1024U * 1024U;
    size_t capacity = 256U;
    size_t used = 0;
    char *data = NULL;
    int fd = -1;

    if (!path || !data_out || !size_out) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    data = malloc(capacity);
    if (!data) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    for (;;) {
        ssize_t n;
        if (used == capacity) {
            size_t next = capacity < limit / 2U ? capacity * 2U : limit;
            char *grown;
            if (capacity == limit) {
                free(data);
                close(fd);
                errno = EOVERFLOW;
                return -1;
            }
            grown = realloc(data, next);
            if (!grown) {
                free(data);
                close(fd);
                errno = ENOMEM;
                return -1;
            }
            data = grown;
            capacity = next;
        }
        n = read(fd, data + used, capacity - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        {
            int saved_errno = errno;
            free(data);
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    if (close(fd) != 0) {
        int saved_errno = errno;
        free(data);
        errno = saved_errno;
        return -1;
    }
    *data_out = data;
    *size_out = used;
    return 0;
}
#endif

static ssh_process_outcome_t pid_is_our_ssh_agent(
    pid_t pid, const char *expected_sock, int runtime_dir_fd) {
    ssh_process_outcome_t presence;

    if (pid <= 1) return SSH_PROCESS_GONE;
    if (!expected_sock || !*expected_sock) {
        return SSH_PROCESS_INDETERMINATE;
    }
    presence = probe_process_presence(pid);
    if (presence != SSH_PROCESS_OWNED) return presence;
#ifdef __linux__
    char path[64];
    char *comm = NULL;
    char *cmd = NULL;
    size_t comm_size = 0;
    size_t cmd_size = 0;
    ssh_process_outcome_t outcome;

    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    if (read_proc_file(path, &comm, &comm_size) != 0 || comm_size == 0) {
        free(comm);
        return inspection_failure_outcome(pid);
    }
    while (comm_size > 0 &&
           (comm[comm_size - 1U] == '\n' || comm[comm_size - 1U] == '\r')) {
        comm_size--;
    }
    if (comm_size != strlen("ssh-agent") ||
        memcmp(comm, "ssh-agent", comm_size) != 0) {
        free(comm);
        return SSH_PROCESS_UNRELATED;
    }
    free(comm);

    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    if (read_proc_file(path, &cmd, &cmd_size) != 0 || cmd_size == 0) {
        free(cmd);
        return inspection_failure_outcome(pid);
    }
    outcome = argv_is_our_ssh_agent(cmd, cmd_size, expected_sock,
                                    runtime_dir_fd);
    free(cmd);
    return outcome;
#elif defined(__APPLE__)
    /* KERN_PROCARGS2 begins with argc, then the executable path, alignment
     * NULs, the NUL-separated argv vector, then the environment. A fixed
     * buffer is unsafe here: when argv+environment exceeds it, XNU may not
     * return the prefix containing argc/executable/argv. KERN_ARGMAX is the
     * kernel's upper bound for the complete process argument area. */
    int argmax_mib[2] = {CTL_KERN, KERN_ARGMAX};
    int process_mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    int argmax = 0;
    int argc = 0;
    size_t argmax_len = sizeof(argmax);
    char *process_args;
    ssh_process_outcome_t matched;

    if (sysctl(argmax_mib, 2, &argmax, &argmax_len, NULL, 0) != 0 ||
        argmax_len != sizeof(argmax) || argmax <= (int)sizeof(int)) {
        return inspection_failure_outcome(pid);
    }
    size_t process_args_len = (size_t)argmax;
    process_args = malloc(process_args_len);
    if (!process_args) {
        return SSH_PROCESS_INDETERMINATE;
    }
    if (sysctl(process_mib, 3, process_args, &process_args_len, NULL, 0) != 0 ||
        process_args_len <= sizeof(argc)) {
        free(process_args);
        return inspection_failure_outcome(pid);
    }
    memcpy(&argc, process_args, sizeof(argc));
    if (argc <= 0) {
        free(process_args);
        return SSH_PROCESS_INDETERMINATE;
    }
    size_t offset = sizeof(int);
    size_t executable_len = strnlen(process_args + offset,
                                    process_args_len - offset);
    if (executable_len == 0 || executable_len == process_args_len - offset) {
        free(process_args);
        return SSH_PROCESS_INDETERMINATE;
    }
    const char *executable = process_args + offset;
    const char *executable_basename = strrchr(executable, '/');
    executable_basename = executable_basename ? executable_basename + 1
                                              : executable;
    if (strcmp(executable_basename, "ssh-agent") != 0) {
        free(process_args);
        return SSH_PROCESS_UNRELATED;
    }
    offset += executable_len + 1;
    while (offset < process_args_len && process_args[offset] == '\0') {
        offset++;
    }
    matched = offset < process_args_len &&
              counted_argv_is_our_ssh_agent(process_args + offset,
                                             process_args_len - offset,
                                             argc, expected_sock,
                                             runtime_dir_fd);
    free(process_args);
    return matched;
#elif defined(__FreeBSD__)
    /* FreeBSD's KERN_PROC_ARGS result is already a flattened NUL-separated
     * argv vector for the requested PID. */
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ARGS, (int)pid};
    char *process_args = NULL;
    size_t process_args_len = 0;
    ssh_process_outcome_t outcome;
    if (sysctl(mib, 4, NULL, &process_args_len, NULL, 0) != 0 ||
        process_args_len == 0) {
        return inspection_failure_outcome(pid);
    }
    process_args = malloc(process_args_len);
    if (!process_args) return SSH_PROCESS_INDETERMINATE;
    if (sysctl(mib, 4, process_args, &process_args_len, NULL, 0) != 0 ||
        process_args_len == 0) {
        free(process_args);
        return inspection_failure_outcome(pid);
    }
    outcome = argv_is_our_ssh_agent(process_args, process_args_len,
                                    expected_sock, runtime_dir_fd);
    free(process_args);
    return outcome;
#else
    /* Unknown platforms have no proven PID ownership mechanism here. Never
     * turn mere liveness into authority to signal the process. */
    (void)expected_sock;
    (void)runtime_dir_fd;
    return SSH_PROCESS_INDETERMINATE;
#endif
}

/* Wait up to `total_ms` for `pid` to disappear. ssh-agent daemonizes (it is
 * reparented to init, not our child), so kill(pid, 0) flips to ESRCH as soon
 * as init reaps it — no waitpid involved. Poll with exponential backoff
 * (1ms doubling to a 50ms cap) inside the same total budget: the very first
 * liveness check runs before the just-signaled agent has even been scheduled,
 * so a fixed 50ms interval used to stack ~50ms of dead time per reaped agent
 * — all of it under the held agent-dir lock (AR-03 L19). A healthy agent
 * exits within the first millisecond or two. */
static int64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int sleep_until_milliseconds(int64_t target_ms) {
    for (;;) {
        int64_t now = monotonic_milliseconds();
        int64_t remaining;
        struct timespec delay;
        if (now < 0) return -1;
        remaining = target_ms - now;
        if (remaining <= 0) return 0;
        delay.tv_sec = (time_t)(remaining / 1000);
        delay.tv_nsec = (long)(remaining % 1000) * 1000000L;
        if (nanosleep(&delay, NULL) == 0) return 0;
        if (errno != EINTR) return -1;
        /* Recompute from CLOCK_MONOTONIC. An interrupted sleep consumes only
         * the time that actually elapsed, never its requested slice. */
    }
}

static ssh_process_outcome_t wait_pid_gone(pid_t pid, int total_ms) {
    int64_t started;
    int64_t deadline;
    int delay = 1;

    if (total_ms < 0) return SSH_PROCESS_INDETERMINATE;
    started = monotonic_milliseconds();
    if (started < 0 || started > INT64_MAX - total_ms) {
        return SSH_PROCESS_INDETERMINATE;
    }
    deadline = started + total_ms;
    for (;;) {
        ssh_process_outcome_t presence = probe_process_presence(pid);
        int64_t now;
        int64_t next;
        if (presence != SSH_PROCESS_OWNED) return presence;
        now = monotonic_milliseconds();
        if (now < 0) return SSH_PROCESS_INDETERMINATE;
        if (now >= deadline) return SSH_PROCESS_OWNED;
        next = now + delay;
        if (next > deadline) next = deadline;
        if (sleep_until_milliseconds(next) != 0) {
            return SSH_PROCESS_INDETERMINATE;
        }
        if (delay < 50) {
            delay = delay * 2 < 50 ? delay * 2 : 50;
        }
    }
}

static ssh_process_outcome_t wait_pidfd_gone(int pidfd, int total_ms) {
    int64_t started = monotonic_milliseconds();
    int64_t deadline;
    struct pollfd pfd;

    if (total_ms < 0 || started < 0 || started > INT64_MAX - total_ms) {
        return SSH_PROCESS_INDETERMINATE;
    }
    deadline = started + total_ms;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = pidfd;
    pfd.events = POLLIN;
    for (;;) {
        int64_t now = monotonic_milliseconds();
        int timeout;
        int rc;
        if (now < 0) return SSH_PROCESS_INDETERMINATE;
        if (now >= deadline) return SSH_PROCESS_OWNED;
        timeout = (int)(deadline - now);
        rc = poll(&pfd, 1, timeout);
        if (rc > 0) {
            if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                return SSH_PROCESS_GONE;
            }
            return SSH_PROCESS_INDETERMINATE;
        }
        if (rc == 0) return SSH_PROCESS_OWNED;
        if (errno != EINTR) return SSH_PROCESS_INDETERMINATE;
    }
}

/* Classify a recorded PID against `sock`; when it is conclusively OWNED,
 * SIGTERM it, confirm death, and escalate to SIGKILL if it lingers (AR-02
 * #20). GONE means the PID is absent, UNRELATED means a live PID was proved
 * not to be this managed agent, and either permits sidecar cleanup.
 * INDETERMINATE covers every failed inspection/signal and OWNED after both
 * observation windows means the agent conclusively survived; both require
 * the caller to retain the recovery tuple.
 *
 * On Linux, pin the process with a pidfd BEFORE verifying+signaling so a PID
 * recycled in the check-then-signal window (CONC-4 TOCTOU) cannot receive
 * either signal — the pidfd refers to a specific process instance, not a
 * reusable number. Where pidfd is unavailable (older kernels, non-Linux) fall
 * back to plain kill guarded by the identity check, re-verified before the
 * SIGKILL escalation. */
static int ssh_process_signal_real(pid_t pid, int signal_number) {
    return kill(pid, signal_number);
}

static int ssh_pidfd_open_real(pid_t pid) {
#if defined(__linux__) && defined(SYS_pidfd_open)
    return (int)syscall(SYS_pidfd_open, (long)pid, 0L);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int ssh_pidfd_signal_real(int pidfd, int signal_number) {
#if defined(__linux__) && defined(SYS_pidfd_send_signal)
    return (int)syscall(SYS_pidfd_send_signal, (long)pidfd,
                        (long)signal_number, (void *)0, 0L);
#else
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

static ssh_process_outcome_t reap_ssh_agent(pid_t pid, const char *sock,
                                            int runtime_dir_fd) {
    ssh_process_outcome_t identity;
    ssh_process_outcome_t outcome;
    int pidfd;
    int open_errno;

    if (pid <= 1) return SSH_PROCESS_GONE;
    pidfd = g_reap_ops.pidfd_open(pid);
    open_errno = errno;
    if (pidfd >= 0) {
        identity = g_reap_ops.identity(pid, sock, runtime_dir_fd);
        if (identity != SSH_PROCESS_OWNED) {
            close(pidfd);
            return identity;
        }
        for (int attempts = 0;; attempts++) {
            if (g_reap_ops.pidfd_signal(pidfd, SIGTERM) == 0) {
                outcome = SSH_PROCESS_OWNED;
                break;
            }
            if (errno == EINTR && attempts < 16) continue;
            outcome = errno == ESRCH ? SSH_PROCESS_GONE
                                     : SSH_PROCESS_INDETERMINATE;
            break;
        }
        if (outcome == SSH_PROCESS_OWNED) {
            outcome = wait_pidfd_gone(pidfd, 500);
        }
        if (outcome == SSH_PROCESS_OWNED) {
            log_warning("ssh-agent PID %ld ignored SIGTERM; escalating to SIGKILL",
                        (long)pid);
            for (int attempts = 0;; attempts++) {
                if (g_reap_ops.pidfd_signal(pidfd, SIGKILL) == 0) break;
                if (errno == EINTR && attempts < 16) continue;
                outcome = errno == ESRCH ? SSH_PROCESS_GONE
                                         : SSH_PROCESS_INDETERMINATE;
                break;
            }
            if (outcome == SSH_PROCESS_OWNED) {
                outcome = wait_pidfd_gone(pidfd, 500);
            }
        }
        close(pidfd);
        return outcome;
    }
    if (open_errno == ESRCH) return SSH_PROCESS_GONE;
    if (open_errno != ENOSYS && open_errno != EINVAL &&
        open_errno != EOPNOTSUPP) {
        return SSH_PROCESS_INDETERMINATE;
    }

    identity = g_reap_ops.identity(pid, sock, runtime_dir_fd);
    if (identity != SSH_PROCESS_OWNED) return identity;
    for (int attempts = 0;; attempts++) {
        if (g_reap_ops.signal(pid, SIGTERM) == 0) {
            outcome = SSH_PROCESS_OWNED;
            break;
        }
        if (errno == EINTR && attempts < 16) continue;
        return errno == ESRCH ? SSH_PROCESS_GONE
                              : SSH_PROCESS_INDETERMINATE;
    }
    outcome = wait_pid_gone(pid, 500);
    if (outcome != SSH_PROCESS_OWNED) return outcome;

    /* Without a pidfd, re-prove the PID identity before the harder signal. */
    identity = g_reap_ops.identity(pid, sock, runtime_dir_fd);
    if (identity != SSH_PROCESS_OWNED) return identity;
    log_warning("ssh-agent PID %ld ignored SIGTERM; escalating to SIGKILL",
                (long)pid);
    for (int attempts = 0;; attempts++) {
        if (g_reap_ops.signal(pid, SIGKILL) == 0) break;
        if (errno == EINTR && attempts < 16) continue;
        return errno == ESRCH ? SSH_PROCESS_GONE
                              : SSH_PROCESS_INDETERMINATE;
    }
    return wait_pid_gone(pid, 500);
}

static bool ssh_reap_allows_cleanup(ssh_process_outcome_t outcome) {
    return outcome == SSH_PROCESS_GONE || outcome == SSH_PROCESS_UNRELATED;
}

static const char *ssh_process_outcome_name(ssh_process_outcome_t outcome) {
    switch (outcome) {
        case SSH_PROCESS_OWNED: return "OWNED";
        case SSH_PROCESS_UNRELATED: return "UNRELATED";
        case SSH_PROCESS_GONE: return "GONE";
        case SSH_PROCESS_INDETERMINATE: return "INDETERMINATE";
        default: return "INVALID";
    }
}

/* Recovery teardown of a just-spawned agent that failed the post-spawn
 * checks (output parse, socket validation) BEFORE its PID sidecar was
 * written. If reap is not conclusive, publish the recovered PID as a durable
 * sidecar and retain the socket. When the parsed PID is unknown, Linux scans
 * /proc for the exact provenance-qualified argv; other platforms retain a
 * live or uninspectable socket as the last discovery handle. The return value
 * is true exactly when recovery state remains for a later retry. */
static bool reap_unrecorded_agent(pid_t pid, const char *socket_arg,
                                  int dir_fd, const char *socket_name,
                                  const char *pid_name,
                                  const char *socket_path,
                                  const char *socket_dir) {
    ssh_process_outcome_t outcome = SSH_PROCESS_INDETERMINATE;
    ssh_runtime_pin_t socket_pin;
    bool socket_present = false;
    pid_t retry_pid = pid;

    ssh_runtime_pin_init(&socket_pin);
    int socket_rc = pin_ssh_runtime_entry_at(
        dir_fd, socket_name, socket_path, &socket_pin);
    if (socket_rc == 0) {
        socket_present = true;
    } else if (socket_rc < 0) {
        return true;
    }

    if (pid > 1) {
        outcome = g_ssh_reap(pid, socket_arg, dir_fd);
    }
#ifdef __linux__
    else {
        DIR *d = opendir("/proc");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                char *end = NULL;
                long scan = strtol(ent->d_name, &end, 10);
                if (end && *end == '\0' && scan > 1 &&
                    pid_is_our_ssh_agent((pid_t)scan, socket_arg, dir_fd) ==
                        SSH_PROCESS_OWNED) {
                    retry_pid = (pid_t)scan;
                    outcome = g_ssh_reap(retry_pid, socket_arg, dir_fd);
                    break;
                }
            }
            closedir(d);
        }
    }
#endif

    if (ssh_reap_allows_cleanup(outcome)) {
        if (g_unrecorded_cleanup_hook &&
            g_unrecorded_cleanup_hook(dir_fd, socket_name) != 0) {
            set_error(ERR_FILE_IO,
                      "SSH unrecorded-agent cleanup hook failed");
            (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
            return true;
        }
        bool retained = unlink_ssh_reset_path_at(
                            dir_fd, socket_name, socket_path,
                            "unrecorded agent socket cleanup",
                            &socket_pin,
                            socket_present) != 0;
        if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) retained = true;
        return retained;
    }
    if (retry_pid > 1) {
        if (write_ssh_agent_pid_at(dir_fd, pid_name, retry_pid) == 0) {
            log_warning("SSH agent reap outcome %s; retained PID %ld and socket for retry",
                        ssh_process_outcome_name(outcome), (long)retry_pid);
        } else {
            log_warning("SSH agent reap outcome %s and PID recovery publication failed; retaining socket",
                        ssh_process_outcome_name(outcome));
        }
        (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
        return true;
    }

    /* If the PID could not be recovered, the socket itself remains the only
     * discovery handle. A conclusively stale inode can be removed; a live or
     * uninspectable listener is retained so reset reports the unresolved
     * runtime instead of erasing its last trace. */
    if (socket_path) {
        bool reachable = false;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) == 0 &&
            probe_ssh_agent_socket(socket_path, &reachable) == 0 &&
            verify_socket_dir_namespace(dir_fd, socket_dir) == 0 &&
            !reachable) {
            if (g_unrecorded_cleanup_hook &&
                g_unrecorded_cleanup_hook(dir_fd, socket_name) != 0) {
                set_error(ERR_FILE_IO,
                          "SSH unrecorded-agent cleanup hook failed");
                (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
                return true;
            }
            bool retained = unlink_ssh_reset_path_at(
                                dir_fd, socket_name, socket_path,
                                "stale unrecorded agent socket cleanup",
                                &socket_pin,
                                socket_present) != 0;
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                retained = true;
            }
            return retained;
        }
    }
    log_warning("Unrecorded SSH agent state is indeterminate; retaining socket for recovery");
    (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
    return true;
}

/* Guard the agent socket base before scanning/locking/unlinking under it.
 * When XDG_RUNTIME_DIR is unset the base is the predictable
 * /tmp/gitswitch-ssh-<uid> in world-writable, sticky /tmp, so a co-located
 * user could pre-create it — or swap it for a symlink — and steer the
 * unlinks and the .lock open somewhere else entirely. The create path
 * already enforces this shape via ensure_private_dir(); the reset/orphan-
 * reap paths were asymmetric with the hardened gpg_manager_reset (AR-03 L6).
 * lstat (no follow) and refuse a symlink, a non-dir, a foreign owner, or any
 * group/other access. Returns 0 = safe, 1 = absent (nothing to do there),
 * -1 = unsafe (fail closed). */
/* Acquire an exclusive, blocking flock on <dir>/.lock, serializing the
 * reap/start/symlink sequence against other gitswitch processes sharing this
 * directory. Returns the held fd (>=0) or -1; pass it to unlock_agent_dir when
 * the critical section ends. The lock is advisory but every writer takes it.
 * O_NOFOLLOW: the lock lives in a dir an attacker can pre-create under /tmp;
 * never follow a planted symlink to open (and flock, holding it open) an
 * arbitrary file elsewhere (AR-03 L6). */
static int lock_agent_dir(int dir_fd) {
    int fd = lock_private_file_at(dir_fd, ".lock");
    if (fd >= 0) g_agent_lock_depth++;
    return fd;
}

/* Non-blocking variant for READ-ONLY discovery. A switch holds the agent-dir
 * lock across the interactive ssh-add passphrase prompt (unbounded human
 * latency), and discovery runs on EVERY invocation via config_load ->
 * accounts_detect_current — so a blocking lock here froze `gitswitch
 * list`/`status` and shell tab-completion until the prompt was answered
 * (AR-05 H2). Readers that fail to acquire must fall back to saved state,
 * exactly as main.c's config lock is non-blocking for the same reason
 * (AR-03 L10); only genuine writers (start/reap/reset) may block. */
static int try_lock_agent_dir(int dir_fd) {
    int fd = try_lock_private_file_at(dir_fd, ".lock");
    if (fd >= 0) g_agent_lock_depth++;
    return fd;
}

static void unlock_agent_dir(int fd) {
    if (fd >= 0) {
        if (g_agent_lock_depth > 0) g_agent_lock_depth--;
        unlock_private_file(fd);
    }
}

/* All callers validate the private runtime directory and hold its manager lock
 * before reading a symlink below it. Keep the static-analysis exception at this
 * one narrow boundary instead of scattering suppressions across call sites. */
static ssize_t read_locked_runtime_symlink_at(int dir_fd, const char *name,
                                              char *buf, size_t size) {
    return readlinkat(dir_fd, name, buf, size);
}

static bool ssh_key_snapshot_fd_matches(
    const ssh_key_snapshot_t *snapshot) {
    struct stat current;
    size_t offset = 0;

    if (!snapshot || !snapshot->fd_open || snapshot->fd < 0 ||
        !snapshot->data || snapshot->length == 0 ||
        fstat(snapshot->fd, &current) != 0 ||
        !same_runtime_identity(&snapshot->identity, &current) ||
        snapshot->identity.st_gid != current.st_gid ||
        current.st_size < 0 || (uintmax_t)current.st_size != snapshot->length) {
        return false;
    }
    /* Namespace replacement can legitimately change ctime/nlink on the still
     * open admitted inode. Compare the complete content instead: this permits
     * rename-over while rejecting an observed in-place key rewrite. */
    while (offset < snapshot->length) {
        char buf[4096];
        size_t wanted = snapshot->length - offset;
        if (wanted > sizeof(buf)) wanted = sizeof(buf);
        ssize_t n = pread(snapshot->fd, buf, wanted, (off_t)offset);
        if (n > 0) {
            if (memcmp(buf, snapshot->data + offset, (size_t)n) != 0) {
                secure_zero_memory(buf, sizeof(buf));
                return false;
            }
            offset += (size_t)n;
            secure_zero_memory(buf, sizeof(buf));
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            secure_zero_memory(buf, sizeof(buf));
            return false;
        }
    }
    return true;
}

/* Copy the SHA256:... fingerprint token of the key at `key_path` into `buf`.
 * Uses `ssh-keygen -lf`, which reads the fingerprint from the key's public
 * portion without needing the passphrase. Returns 0 on success. */
static int ssh_key_fingerprint_generation(
    const char *key_path, const ssh_key_snapshot_t *snapshot,
    char *buf, size_t size) {
    char out[1024];
#if defined(__linux__)
    const char *stdin_path = "/proc/self/fd/0";
#elif defined(__APPLE__) || defined(__FreeBSD__)
    const char *stdin_path = "/dev/fd/0";
#else
    const char *stdin_path = "/dev/stdin";
#endif
    const char *argv[] = {
        "ssh-keygen", "-lf", snapshot ? stdin_path : key_path, NULL
    };
    run_opts_t opts;
    run_result_t res;

    if ((!snapshot && (!key_path || !*key_path)) ||
        (snapshot && (!snapshot->data || snapshot->length == 0 ||
                      !snapshot->fd_open || snapshot->fd < 0)) ||
        !buf || size == 0) {
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    if (snapshot) {
        /* `ssh-keygen -lf -` expects a public-key stream and rejects private
         * keys. Preserve the admitted regular descriptor as seekable fd 0 and
         * name only that fd through the supported platform descriptor fs. */
        if (!ssh_key_snapshot_fd_matches(snapshot) ||
            lseek(snapshot->fd, 0, SEEK_SET) != 0) {
            set_error(ERR_SSH_KEY_INVALID,
                      "Validated SSH key changed before fingerprinting");
            return -1;
        }
        opts.stdin_fd = snapshot->fd;
        opts.use_stdin_fd = true;
    }
    int run_rc = run_argv(argv, &opts, &res);
    if (snapshot) {
        if (!ssh_key_snapshot_fd_matches(snapshot)) {
            set_error(ERR_SSH_KEY_INVALID,
                      "Validated SSH key changed while fingerprinting");
            return -1;
        }
    }
    if (run_rc != 0) {
        return -1;
    }

    /* Output: "<bits> SHA256:<hash> <comment> (<type>)". Extract the token
     * that starts with "SHA256:" (or "MD5:" on legacy setups). */
    const char *fp = strstr(out, "SHA256:");
    if (!fp) fp = strstr(out, "MD5:");
    if (!fp) return -1;

    size_t i = 0;
    while (fp[i] && fp[i] != ' ' && fp[i] != '\t' && fp[i] != '\n' && i + 1 < size) {
        buf[i] = fp[i];
        i++;
    }
    buf[i] = '\0';
    return i > 0 ? 0 : -1;
}

/* True if an ssh-agent is answering on `sock` AND holds EXACTLY the key at
 * `key_path` — one identity, fingerprint compared as a whole token — so
 * adopting it is safe and skips a passphrase re-prompt. Presence alone is not
 * enough (AR-03 M2): a foreign key injected into the per-account agent
 * (`SSH_AUTH_SOCK=current.sock ssh-add ~/.ssh/other_key`) would ride along
 * into the "isolated" session and let a push authenticate as the wrong
 * identity, so any extra identity refuses the reuse — the caller then kills
 * and restarts, loading only the account's key. A live agent holding a
 * *different* key — e.g. after `gitswitch edit` changed the key path — is
 * refused for the same reason. The agent is probed FIRST and the expected
 * fingerprint computed only once the probe answers (AR-03 L18): a stale
 * socket (dead agent) is the common miss, and running ssh-keygen before
 * knowing the agent is alive wasted a fork+exec on every such miss. Anything
 * indeterminate falls back to false (restart + load) rather than risk
 * adopting the wrong agent. */
static bool ssh_agent_has_exact_key_generation(
    int dir_fd, bool use_cwd_fd, const char *socket_arg,
    const char *key_path, const ssh_key_snapshot_t *snapshot) {
    char want_fp[256];
    char envbuf[MAX_PATH_LEN + 20];
    char out[2048];
    const char *env[2] = { NULL, NULL };
    const char *argv[] = { "ssh-add", "-l", NULL };
    run_opts_t opts;
    run_result_t res;

    if (!socket_arg || !*socket_arg || !key_path || !*key_path ||
        (snapshot && (!snapshot->data || snapshot->length == 0)) ||
        (size_t)snprintf(envbuf, sizeof(envbuf), "SSH_AUTH_SOCK=%s",
                         socket_arg) >= sizeof(envbuf)) {
        return false;
    }
    env[0] = envbuf;
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    opts.extra_env = env;
    opts.cwd_fd = dir_fd;
    opts.use_cwd_fd = use_cwd_fd;
    if (run_argv(argv, &opts, &res) != 0) {
        return false; /* exit 1 (no identities) / 2 (no agent) */
    }
    /* An incomplete capture cannot prove single-key exclusivity. In
     * particular, a long first identity can fill this buffer while a second
     * (foreign) key is entirely beyond the visible prefix. */
    if (res.out_truncated) {
        return false;
    }
    if (ssh_key_fingerprint_generation(key_path, snapshot, want_fp,
                                       sizeof(want_fp)) != 0) {
        return false;
    }

    /* Each `ssh-add -l` line is "<bits> <fingerprint> <comment> (<type>)".
     * Token-compare field 2 of every line: a substring search would accept a
     * prefix of a longer fingerprint or a match buried in a multi-key
     * listing. Adopt only a single-identity agent whose one fingerprint is
     * exactly ours. */
    int identities = 0;
    bool ours = false;
    char *saveptr = NULL;
    for (char *line = strtok_r(out, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *fsave = NULL;
        char *field = strtok_r(line, " \t", &fsave);          /* bits */
        field = field ? strtok_r(NULL, " \t", &fsave) : NULL; /* fingerprint */
        if (!field) {
            continue; /* blank line: not an identity */
        }
        identities++;
        if (strcmp(field, want_fp) == 0) {
            ours = true;
        }
    }
    return identities == 1 && ours;
}

static bool ssh_socket_has_key_generation(
    int dir_fd, const char *socket_arg, const char *key_path,
    const ssh_key_snapshot_t *snapshot) {
    return ssh_agent_has_exact_key_generation(
        dir_fd, true, socket_arg, key_path, snapshot);
}

static bool ssh_socket_has_key(int dir_fd, const char *socket_arg,
                               const char *key_path) {
    return ssh_socket_has_key_generation(dir_fd, socket_arg, key_path, NULL);
}

bool ssh_manager_test_socket_has_key(int dir_fd, const char *socket_arg,
                                     const char *key_path) {
    return ssh_socket_has_key(dir_fd, socket_arg, key_path);
}


/* Initialize SSH manager */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL ssh_config to ssh_manager_init");
        return -1;
    }
    
    log_debug("Initializing SSH manager with mode: %d", mode);
    
    /* Initialize structure */
    memset(ssh_config, 0, sizeof(ssh_config_t));
    ssh_config->mode = mode;
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    
    /* Validate the binaries this manager actually execs are available:
     * ssh-agent and ssh-add. `ssh` itself is deliberately NOT probed here
     * (AR-02 #24): only the best-effort connection test uses it — which
     * degrades gracefully through run_argv's own resolution failure — and
     * the boot-time resume path never execs it at all, so a missing `ssh`
     * was hard-failing resumes it could never affect. The probes are bounded,
     * parent-only checks; they do not spawn helpers. Every call reopens and
     * revalidates the candidate, and run_argv independently does so again
     * immediately before launch. */
    if (!command_exists("ssh-agent")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-agent command not found in PATH");
        return -1;
    }

    if (!command_exists("ssh-add")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-add command not found in PATH");
        return -1;
    }
    
    /* Set up based on mode */
    switch (mode) {
        case SSH_AGENT_SYSTEM:
            /* Use existing SSH_AUTH_SOCK */
            if (getenv("SSH_AUTH_SOCK")) {
                safe_strncpy(ssh_config->agent_socket_path, getenv("SSH_AUTH_SOCK"),
                           sizeof(ssh_config->agent_socket_path));
                log_info("Using system SSH agent at: %s", ssh_config->agent_socket_path);
            } else {
                log_warning("No system SSH agent found (SSH_AUTH_SOCK not set)");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Will create isolated agents on demand */
            log_info("Initialized for isolated SSH agent mode");
            break;
            
        case SSH_AGENT_NONE:
            log_info("SSH agent management disabled");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode: %d", mode);
            return -1;
    }
    
    /* NB: the started agent is intentionally left running after this process
     * exits — shells export SSH_AUTH_SOCK=<dir>/current.sock and must keep
     * reaching it — so there is deliberately no atexit/signal teardown here.
     * A half-configured agent from a failed switch is reaped inline on the
     * error paths (ssh_manager_cleanup) instead. */
    log_info("SSH manager initialized successfully");
    return 0;
}

/* Cleanup SSH manager. A surviving owned agent is retained verbatim so the
 * caller keeps the only truthful retry handle instead of zeroing it. */
int ssh_manager_cleanup(ssh_config_t *ssh_config) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL SSH configuration to cleanup");
        return -1;
    }
    
    log_debug("Cleaning up SSH manager");
    
    /* Stop agent if we own it */
    if (ssh_config->agent_owned) {
        if (ssh_config->agent_pid <= 0) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "Owned SSH agent has no verified PID; retained for retry");
            return -1;
        }
        log_info("Stopping owned SSH agent (PID: %d)", ssh_config->agent_pid);
        if (ssh_stop_agent(ssh_config) != 0) {
            log_warning("SSH manager cleanup retained live agent state for retry");
            return -1;
        }
    }
    
    /* Clear sensitive data */
    secure_zero_memory(ssh_config, sizeof(ssh_config_t));
    
    log_debug("SSH manager cleanup complete");
    return 0;
}

/* Switch to account's SSH configuration */
int ssh_switch_account(ssh_config_t *ssh_config, const account_t *account) {
    char expanded_key_path[MAX_PATH_LEN];
    ssh_key_snapshot_t key_snapshot;
    int rc = -1;

    memset(&key_snapshot, 0, sizeof(key_snapshot));
    
    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_switch_account");
        return -1;
    }
    
    /* Skip if SSH not enabled for this account */
    if (!account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        log_debug("SSH not enabled for account: %s", account->name);
        return 0;
    }
    
    log_info("Switching SSH configuration for account: %s", account->name);
    
    /* Validate and expand key path */
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH, "Failed to expand SSH key path: %s", account->ssh_key_path);
        return -1;
    }
    
    /* Capture and validate one pathname generation. Every fingerprint and
     * load below consumes these descriptor-derived bytes, so a rename over
     * the configured pathname cannot substitute a key after admission. */
    if (ssh_key_snapshot_capture(expanded_key_path, &key_snapshot) != 0) {
        return -1; /* Error already set */
    }
    
    /* Handle based on mode */
    switch (ssh_config->mode) {
        case SSH_AGENT_SYSTEM:
            /* Clear existing keys and add new one to system agent */
            if (strlen(ssh_config->agent_socket_path) > 0) {
                log_debug("Clearing system SSH agent keys");
                if (ssh_clear_agent_keys(ssh_config) != 0) {
                    goto done;
                }
                
                log_debug("Adding key to system SSH agent: %s", expanded_key_path);
                if (ssh_add_key_snapshot(ssh_config, expanded_key_path,
                                         &key_snapshot) != 0) {
                    set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to load key into system SSH agent");
                    goto done;
                }
                if (!ssh_agent_has_exact_key_generation(
                        -1, false, ssh_config->agent_socket_path,
                        expanded_key_path, &key_snapshot)) {
                    set_error(ERR_SSH_KEY_LOAD_FAILED,
                              "System SSH agent does not contain exactly the "
                              "requested key after replacement");
                    goto done;
                }
            } else {
                log_warning("No system SSH agent available");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Start the isolated agent and load its key while the socket
             * directory remains descriptor-pinned and manager-locked. */
            if (ssh_start_isolated_agent_with_key(
                    ssh_config, account, &key_snapshot) != 0) {
                goto done; /* Error already set */
            }
            break;
            
        case SSH_AGENT_NONE:
            /* No agent management - just validate key */
            log_info("SSH agent management disabled - key validated but not loaded");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode");
            goto done;
    }
    
    /* A requested alias is part of the account's SSH routing contract. If the
     * managed block cannot be installed safely, fail the switch so the account
     * layer rolls back the agent/runtime commit instead of claiming success
     * with stale user SSH configuration. */
    if (strlen(account->ssh_host_alias) > 0) {
        if (ssh_configure_host_alias(account) != 0) {
            log_warning("Failed to configure SSH host alias: %s", account->ssh_host_alias);
            goto done;
        }
    }
    
    log_info("SSH configuration switched successfully for account: %s", account->name);
    rc = 0;
done:
    ssh_key_snapshot_clear(&key_snapshot);
    return rc;
}

/* Start isolated SSH agent */
int ssh_start_isolated_agent(ssh_config_t *ssh_config, const account_t *account) {
    return ssh_start_isolated_agent_with_key(ssh_config, account, NULL);
}

static int ssh_start_isolated_agent_with_key(
    ssh_config_t *ssh_config, const account_t *account,
    const ssh_key_snapshot_t *snapshot) {
    char output[1024];
    char socket_dir[MAX_PATH_LEN];
    char socket_path[MAX_PATH_LEN];
    char symlink_path[MAX_PATH_LEN];
    char pid_path[MAX_PATH_LEN] = "";
    char socket_name[MAX_NAME_LEN + 32];
    char pid_name[MAX_NAME_LEN + 32];
    char launch_socket_arg[MAX_PATH_LEN];
    char provenance_marker[80];
    ssh_env_snapshot_t env_snapshot;
    bool env_snapshot_taken = false;
    bool pid_recorded = false;
    bool agent_retained = false;
    bool current_committed = false;
    ssh_current_link_identity_t committed_current;
    ssh_runtime_pin_t reuse_pin;
    bool reuse_pin_active = false;
    int dir_fd = -1;

    ssh_runtime_pin_init(&reuse_pin);

    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_start_isolated_agent");
        return -1;
    }

    log_info("Starting isolated SSH agent for account: %s", account->name);

    /* Create secure socket directory first, then take an exclusive lock on it
     * for the whole reap/start/symlink sequence. Without this, two concurrent
     * gitswitch invocations race: one's reaper SIGTERMs the agent the other
     * just started and unlinks its socket + current.sock, so shells briefly
     * see a dangling current.sock and one switch fails to load its key. */
    dir_fd = open_isolated_agent_socket_dir(socket_dir, sizeof(socket_dir),
                                            true, NULL);
    if (dir_fd < 0) {
        return -1;
    }
    int lock_fd = lock_agent_dir(dir_fd);
    if (lock_fd < 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO, "Failed to lock SSH agent directory");
        return -1;
    }
    if (reconcile_ssh_runtime_pins(dir_fd, socket_dir) != 0) {
        unlock_agent_dir(lock_fd);
        close(dir_fd);
        return -1;
    }

    int rc = -1;
    memset(&env_snapshot, 0, sizeof(env_snapshot));
    ssh_config->key_already_loaded = false;

    /* Build this account's per-account socket path up front. Guard against the
     * kernel's sockaddr_un.sun_path cap (108 on Linux, 104 on the BSDs), NOT
     * just the 4096 buffer: validate_name permits long names (up to 255 bytes),
     * and a name long enough to push the socket path past sun_path makes
     * `ssh-agent -a` fail to bind with a confusing error. Reject early with a
     * clear message instead. */
    int spn = snprintf(socket_path, sizeof(socket_path),
                       "%s/ssh-agent.%s.sock", socket_dir, account->name);
    int sn = snprintf(socket_name, sizeof(socket_name),
                      "ssh-agent.%s.sock", account->name);
    int pn = snprintf(pid_name, sizeof(pid_name),
                      "ssh-agent.%s.pid", account->name);
    if (spn < 0 || (size_t)spn >= sizeof(socket_path) || sn < 0 || pn < 0 ||
        (size_t)sn >= sizeof(socket_name) || (size_t)pn >= sizeof(pid_name)) {
        set_error(ERR_INVALID_ARGS, "SSH socket path too long");
        goto done;
    }
    if ((size_t)spn >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        set_error(ERR_INVALID_ARGS,
                  "Account name too long: the SSH agent socket path (%d bytes) "
                  "exceeds the %zu-byte UNIX socket limit. Use a shorter name.",
                  spn, sizeof(((struct sockaddr_un *)0)->sun_path));
        goto done;
    }
    if (build_provenance_socket_arg(
            dir_fd, socket_name, launch_socket_arg,
            sizeof(launch_socket_arg), provenance_marker,
            sizeof(provenance_marker)) != 0 ||
        strlen(launch_socket_arg) >=
            sizeof(((struct sockaddr_un *)0)->sun_path)) {
        set_error(ERR_INVALID_ARGS,
                  "Account name too long for a provenance-qualified SSH socket");
        goto done;
    }

    /* Reuse fast path: if this account's agent is already alive and holds
     * EXACTLY this key (single identity, fingerprint token match — see
     * ssh_socket_has_key), adopt it instead of killing and restarting
     * (which forces a fresh ssh-add and, for a passphrase-protected key, a
     * PIN/passphrase re-prompt on every re-switch to the already-active
     * account). Matching the specific key means that after `gitswitch edit`
     * changes the key path, the stale agent is NOT reused and the new key gets
     * loaded. We still reap every OTHER account's agent so only this one stays
     * live. The key path is expanded (~ etc.) for the fingerprint lookup. */
    char reuse_key_path[MAX_PATH_LEN];
    bool have_reuse_key =
        account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
        expand_path(account->ssh_key_path, reuse_key_path, sizeof(reuse_key_path)) == 0;
    bool can_reuse = false;

    if (!have_reuse_key) {
        set_error(ERR_INVALID_PATH,
                  "Cannot resolve isolated SSH key path for account: %s",
                  account->name);
        goto done;
    }
    {
        int pin_rc = pin_ssh_runtime_entry_at(
            dir_fd, socket_name, socket_path, &reuse_pin);
        if (pin_rc < 0) goto done;
        if (pin_rc == 0) {
            reuse_pin_active = true;
            if (S_ISSOCK(reuse_pin.identity.st_mode) &&
                reuse_pin.identity.st_uid == getuid() &&
                (reuse_pin.identity.st_mode & 0777) == 0600) {
                can_reuse = ssh_socket_has_key_generation(
                    dir_fd, socket_name, reuse_key_path, snapshot);
                if (verify_ssh_runtime_pin_at(
                        dir_fd, socket_name, socket_path, &reuse_pin) != 0) {
                    goto done;
                }
            }
        }
    }
    if (!can_reuse && reuse_pin_active) {
        if (release_ssh_runtime_pin(dir_fd, &reuse_pin) != 0) goto done;
        reuse_pin_active = false;
    }

    /* ssh-add/ssh-keygen are external scheduling points. Before any orphan
     * cleanup or publication, prove the public namespace still names the
     * descriptor-pinned directory used by the probe. */
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        goto done;
    }
    if (can_reuse) {
        ssh_config_t adopted = *ssh_config;
        safe_strncpy(adopted.agent_socket_path, socket_path,
                     sizeof(adopted.agent_socket_path));
        safe_strncpy(adopted.agent_socket_arg, socket_name,
                     sizeof(adopted.agent_socket_arg));
        adopted.agent_pid = -1;
        adopted.agent_owned = false;
        adopted.key_already_loaded = true;

        /* Recover the PID from the sidecar so cleanup/stop can still target
         * it — but only after verifying it is genuinely OUR agent on this
         * socket (AR-02 #18). The sidecar can be stale (crash, reboot on a
         * /tmp-preserving distro) with its PID since recycled; trusting it
         * blindly would mark an unrelated process agent_owned=true and feed
         * it into the kill path later. The socket itself was already
         * fingerprint-verified, so a missing/rejected PID permits reuse only
         * as explicitly unowned state; later cleanup must not claim it can
         * stop a process it cannot identify safely. */
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            pid_t pid = -1;
            int pid_rc = read_ssh_agent_pid_at(dir_fd, pid_name, pid_path,
                                               &pid, NULL);
            if (pid_rc == 0) {
                ssh_process_outcome_t qualified_identity =
                    pid_is_our_ssh_agent(pid, launch_socket_arg, -1);
                ssh_process_outcome_t absolute_identity =
                    qualified_identity == SSH_PROCESS_OWNED
                        ? SSH_PROCESS_UNRELATED
                        : pid_is_our_ssh_agent(pid, socket_path, -1);
                if (qualified_identity == SSH_PROCESS_OWNED ||
                    absolute_identity == SSH_PROCESS_OWNED) {
                    adopted.agent_pid = pid;
                    adopted.agent_owned = true;
                    safe_strncpy(
                        adopted.agent_socket_arg,
                        qualified_identity == SSH_PROCESS_OWNED
                            ? launch_socket_arg
                            : socket_path,
                        sizeof(adopted.agent_socket_arg));
                }
            } else if (pid_rc < 0) {
                goto done;
            }
        }

        /* Enforce one-account isolation before publishing this reused agent.
         * Cleanup failures are retained-state failures, not warnings: adopting
         * this agent while another managed listener cannot be classified or
         * reaped would violate the isolation promise. Running this before the
         * environment/link commit also leaves the prior stable link untouched
         * on failure. */
        if (kill_orphaned_gitswitch_agents(dir_fd, socket_dir,
                                           account->name) != 0) {
            goto done;
        }

        /* The stable link is the commit point. Environment and retarget errors
         * remain fatal and restore the caller's environment; the account-level
         * transaction restores any previous runtime that the successful orphan
         * cleanup above had to retire. */
        if (ssh_env_snapshot_take(&env_snapshot) != 0) {
            goto done;
        }
        if (setup_ssh_environment(&adopted) != 0) {
            ssh_env_snapshot_restore(&env_snapshot);
            set_error(ERR_SSH_AGENT_START_FAILED,
                      "Failed to set up SSH environment for reused agent");
            goto done;
        }
        if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                             "%s/current.sock", socket_dir) >= sizeof(symlink_path)) {
            ssh_env_snapshot_restore(&env_snapshot);
            set_error(ERR_INVALID_PATH, "Stable SSH socket path too long");
            goto done;
        }
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            ssh_env_snapshot_restore(&env_snapshot);
            goto done;
        }
        {
            ssh_current_link_identity_t committed;
            if (publish_current_socket_link(dir_fd, socket_path, symlink_path,
                                            &committed) != 0) {
                ssh_env_snapshot_restore(&env_snapshot);
                goto done;
            }
            if (g_namespace_commit_hook &&
                g_namespace_commit_hook(dir_fd) != 0) {
                set_error(ERR_FILE_IO,
                          "SSH namespace commit hook failed for reused agent");
                (void)remove_current_socket_link_if_unchanged(dir_fd,
                                                               &committed);
                ssh_env_snapshot_restore(&env_snapshot);
                goto done;
            }
            if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
                (void)remove_current_socket_link_if_unchanged(dir_fd,
                                                               &committed);
                ssh_env_snapshot_restore(&env_snapshot);
                goto done;
            }
            if (verify_ssh_runtime_pin_at(
                    dir_fd, socket_name, socket_path, &reuse_pin) != 0 ||
                release_ssh_runtime_pin(dir_fd, &reuse_pin) != 0) {
                (void)remove_current_socket_link_if_unchanged(dir_fd,
                                                               &committed);
                ssh_env_snapshot_restore(&env_snapshot);
                goto done;
            }
            reuse_pin_active = false;
        }

        ssh_env_snapshot_discard(&env_snapshot);
        *ssh_config = adopted;
        log_info("Reusing live SSH agent for account: %s", account->name);
        rc = 0;
        goto done;
    }

    /* Kill any orphaned gitswitch agents from previous runs (including a stale
     * agent for this same account, which we're about to replace). */
    if (kill_orphaned_gitswitch_agents(dir_fd, socket_dir, NULL) != 0) {
        goto done;
    }

    /* Stop any existing agent we own */
    if (ssh_config->agent_owned && ssh_config->agent_pid > 0) {
        log_debug("Stopping existing SSH agent");
        if (ssh_stop_agent(ssh_config) != 0) {
            goto done;
        }
    }

    /* Remove stale socket if it exists */
    struct stat stale_socket;
    if (fstatat(dir_fd, socket_name, &stale_socket, AT_SYMLINK_NOFOLLOW) == 0) {
        log_debug("Removing stale SSH agent socket: %s", socket_path);
        if (unlink_ssh_runtime_entry(dir_fd, socket_name, false,
                                     "stale agent socket cleanup") != 0) {
            goto done;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_FILE_IO, "Failed to inspect stale SSH socket");
        goto done;
    }

    /* Start ssh-agent on the per-account socket (no shell). `-s` pins the
     * output to Bourne syntax: without it ssh-agent guesses the format from
     * the inherited $SHELL, and a csh/tcsh login shell made it emit
     * `setenv SSH_AUTH_SOCK ...` lines the (deliberately Bourne-only) parser
     * below cannot read — so every switch failed AFTER the agent was already
     * alive but BEFORE its PID sidecar existed, leaking one unreapable
     * key-holding agent per attempt (AR-03 H1). Capture its stdout (the eval
     * script) only; stderr stays on the terminal. */
    log_debug("Starting SSH agent on provenance-qualified pinned entry: %s",
              launch_socket_arg);
    {
        struct stat marker_stat;
        int run_rc;
        if (mkdirat(dir_fd, provenance_marker, 0700) != 0 && errno != EEXIST) {
            set_system_error(ERR_FILE_IO,
                             "Failed to create SSH provenance marker");
            goto done;
        }
        if (fstatat(dir_fd, provenance_marker, &marker_stat,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(marker_stat.st_mode) ||
            marker_stat.st_uid != getuid() ||
            (marker_stat.st_mode & 0777) != 0700) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing unsafe SSH provenance marker");
            goto done;
        }
        run_rc = ssh_run_in_dir(dir_fd, output, sizeof(output), false,
                                "ssh-agent", "-s", "-a",
                                launch_socket_arg,
                                (const char *)NULL);
        if (unlinkat(dir_fd, provenance_marker, AT_REMOVEDIR) != 0 &&
            errno != ENOENT) {
            log_warning("Could not remove temporary SSH provenance marker: %s",
                        provenance_marker);
        }
        if (run_rc != 0) {
            set_error(ERR_SSH_AGENT_START_FAILED, "Failed to start SSH agent");
            goto done;
        }
    }

    /* Parse ssh-agent output for the PID. Do NOT trust the echoed SSH_AUTH_SOCK
     * path: modern OpenSSH ssh-agent double-quotes it when the path contains
     * shell-special characters — which validate_name permits in account names
     * (spaces/parens, e.g. "Jane Doe (Work)") — so the quotes would be taken
     * literally and the socket "not found", silently breaking SSH for that
     * account. We passed a provenance-qualified path resolved from the pinned
     * directory to `-a`; the public `socket_path` assembled above is therefore
     * the authoritative exported path. Use it directly and keep only the
     * parsed PID. */
    if (parse_ssh_agent_output(output, ssh_config) != 0) {
        bool retained;
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        /* The agent is typically already alive and bound to socket_path here,
         * but its PID sidecar does not exist yet, so the sidecar-driven
         * reaper could never find it: reap it now while we still know the
         * socket it was started on, or it holds the key until reboot
         * (AR-03 H1). The parsed PID may be unknown on this path. */
        safe_strncpy(ssh_config->agent_socket_path, socket_path,
                     sizeof(ssh_config->agent_socket_path));
        safe_strncpy(ssh_config->agent_socket_arg, launch_socket_arg,
                     sizeof(ssh_config->agent_socket_arg));
        retained = reap_unrecorded_agent(
            ssh_config->agent_pid, launch_socket_arg, dir_fd, socket_name,
            pid_name, socket_path, socket_dir);
        ssh_config->agent_owned = retained && ssh_config->agent_pid > 1;
        if (!retained) {
            ssh_config->agent_pid = -1;
            ssh_config->agent_socket_path[0] = '\0';
            ssh_config->agent_socket_arg[0] = '\0';
        }
        set_error(ERR_SSH_AGENT_START_FAILED,
                  retained
                      ? "Failed to parse ssh-agent output; runtime retained for retry"
                      : "Failed to parse ssh-agent output; spawned runtime removed");
        goto done;
    }
    safe_strncpy(ssh_config->agent_socket_path, socket_path,
                 sizeof(ssh_config->agent_socket_path));
    safe_strncpy(ssh_config->agent_socket_arg, launch_socket_arg,
                 sizeof(ssh_config->agent_socket_arg));

    /* Validate the agent is working */
    if (validate_ssh_agent_socket_at(dir_fd, socket_name, socket_path,
                                     NULL) != 0) {
        bool retained;
        set_error(ERR_SSH_AGENT_START_FAILED, "SSH agent socket validation failed");
        /* Same pre-sidecar leak shape as the parse failure above, but the
         * parsed PID is known here, so the reap targets it directly. */
        retained = reap_unrecorded_agent(
            ssh_config->agent_pid, launch_socket_arg, dir_fd, socket_name,
            pid_name, socket_path, socket_dir);
        ssh_config->agent_owned = retained && ssh_config->agent_pid > 1;
        if (!retained) {
            ssh_config->agent_pid = -1;
            ssh_config->agent_socket_path[0] = '\0';
            ssh_config->agent_socket_arg[0] = '\0';
        }
        set_error(ERR_SSH_AGENT_START_FAILED,
                  retained
                      ? "SSH agent socket validation failed; runtime retained for retry"
                      : "SSH agent socket validation failed; spawned runtime removed");
        goto done;
    }

    /* The runner used only the pinned cwd + provenance-qualified relative
     * socket entry. If the public directory was replaced while it ran, reap
     * that pinned agent and refuse to split its sidecar/link/environment into
     * another namespace. */
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        bool retained = reap_unrecorded_agent(
            ssh_config->agent_pid, launch_socket_arg, dir_fd, socket_name,
            pid_name, socket_path, socket_dir);
        ssh_config->agent_owned = retained && ssh_config->agent_pid > 1;
        if (!retained) {
            ssh_config->agent_pid = -1;
            ssh_config->agent_socket_path[0] = '\0';
            ssh_config->agent_socket_arg[0] = '\0';
        }
        goto done;
    }

    /* Mark as owned */
    ssh_config->agent_owned = true;

    /* Record the agent PID in a sidecar file so a later invocation can reap
     * this agent precisely by PID. This is FATAL on failure: the reaper only
     * kills PIDs it finds in sidecars, so an agent with no record would
     * outlive every future cleanup holding the account's decrypted key. If we
     * can't record it, stop the agent and fail the switch. */
    {
        bool recorded = false;
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            recorded = write_ssh_agent_pid_at(dir_fd, pid_name,
                                               ssh_config->agent_pid) == 0;
        }
        pid_recorded = recorded;
        if (!recorded) {
            char detail[sizeof(g_last_error.message)];
            ssh_process_outcome_t reap_outcome;
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            reap_outcome = g_ssh_reap(ssh_config->agent_pid,
                                      launch_socket_arg, dir_fd);
            if (ssh_reap_allows_cleanup(reap_outcome)) {
                (void)unlink_ssh_runtime_entry(
                    dir_fd, socket_name, true,
                    "agent socket cleanup after sidecar failure");
                ssh_config->agent_pid = -1;
                ssh_config->agent_owned = false;
                ssh_config->agent_socket_path[0] = '\0';
                ssh_config->agent_socket_arg[0] = '\0';
            } else {
                log_warning("SSH agent reap outcome %s after PID-sidecar failure; retaining ownership for retry",
                            ssh_process_outcome_name(reap_outcome));
            }
            set_error(ERR_FILE_IO,
                      "Failed to record SSH agent PID; %s: %s",
                      ssh_config->agent_owned ? "agent retained for retry"
                                              : "agent stopped",
                      detail[0] ? detail : "sidecar commit failed");
            goto done;
        }
    }

    /* Load the private key before publishing the stable link or releasing the
     * pinned directory.  SSH_AUTH_SOCK is a relative entry resolved only after
     * the child fchdir()s to dir_fd, so replacing the public runtime directory
     * cannot redirect ssh-add to an attacker-controlled agent. */
    if (ssh_add_key_pinned(dir_fd, socket_name, reuse_key_path,
                           snapshot) != 0) {
        goto fresh_commit_failed;
    }
    if (!ssh_socket_has_key_generation(dir_fd, socket_name, reuse_key_path,
                                       snapshot)) {
        set_error(ERR_SSH_KEY_LOAD_FAILED,
                  "Fresh isolated SSH agent does not contain exactly the "
                  "requested key");
        goto fresh_commit_failed;
    }
    ssh_config->key_already_loaded = true;
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        goto fresh_commit_failed;
    }

    /* Set up the process environment, but retain its prior values until the
     * stable-link commit succeeds so any failure is fully reversible. */
    if (ssh_env_snapshot_take(&env_snapshot) != 0) {
        goto fresh_commit_failed;
    }
    env_snapshot_taken = true;
    if (setup_ssh_environment(ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to set up SSH environment");
        goto fresh_commit_failed;
    }

    /* Atomically (re)point the stable current.sock at this agent's socket. It
     * is required, not warning-only: shells use this path, so without it the
     * new agent is not an active account. */
    if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                         "%s/current.sock", socket_dir) >= sizeof(symlink_path)) {
        set_error(ERR_INVALID_PATH, "Stable SSH socket path too long");
        goto fresh_commit_failed;
    }
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        goto fresh_commit_failed;
    }
    if (publish_current_socket_link(dir_fd, socket_path, symlink_path,
                                    &committed_current) != 0) {
        goto fresh_commit_failed;
    }
    current_committed = true;
    if (g_namespace_commit_hook && g_namespace_commit_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH namespace commit hook failed for fresh agent");
        goto fresh_commit_failed;
    }
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        goto fresh_commit_failed;
    }
    log_debug("Created symlink: %s -> %s", symlink_path, socket_path);

    ssh_env_snapshot_discard(&env_snapshot);
    env_snapshot_taken = false;
    log_info("Isolated SSH agent started successfully (PID: %d, Socket: %s)",
             ssh_config->agent_pid, ssh_config->agent_socket_path);

    rc = 0;
    goto done;

fresh_commit_failed:
    if (current_committed) {
        (void)remove_current_socket_link_if_unchanged(dir_fd,
                                                       &committed_current);
        current_committed = false;
    }
    if (env_snapshot_taken) {
        ssh_env_snapshot_restore(&env_snapshot);
        env_snapshot_taken = false;
    }
    if (ssh_config->agent_owned) {
        ssh_process_outcome_t reap_outcome = g_ssh_reap(
            ssh_config->agent_pid,
            ssh_config->agent_socket_arg[0]
                ? ssh_config->agent_socket_arg
                : socket_path,
            dir_fd);
        if (ssh_reap_allows_cleanup(reap_outcome)) {
            if (pid_recorded) {
                (void)unlink_ssh_runtime_entry(
                    dir_fd, pid_name, true,
                    "PID sidecar cleanup after failed publication");
            }
            (void)unlink_ssh_runtime_entry(
                dir_fd, socket_name, true,
                "agent socket cleanup after failed publication");
        } else {
            /* Preserve the sidecar/socket whenever reap is inconclusive:
             * deleting its targeting information would make a future retry
             * impossible and could leak a key-holding agent until reboot. */
            log_warning("SSH agent reap outcome %s after failed stable-link commit; keeping sidecar for retry",
                        ssh_process_outcome_name(reap_outcome));
            agent_retained = true;
        }
    }
    if (!agent_retained) {
        ssh_config->agent_pid = -1;
        ssh_config->agent_owned = false;
        ssh_config->key_already_loaded = false;
        ssh_config->agent_socket_path[0] = '\0';
        ssh_config->agent_socket_arg[0] = '\0';
    }
done:
    if (env_snapshot_taken) {
        ssh_env_snapshot_discard(&env_snapshot);
    }
    if (reuse_pin_active) {
        (void)release_ssh_runtime_pin(dir_fd, &reuse_pin);
    }
    unlock_agent_dir(lock_fd);
    close(dir_fd);
    return rc;
}

/* Stop SSH agent */
int ssh_stop_agent(ssh_config_t *ssh_config) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL SSH configuration to stop");
        return -1;
    }
    if (!ssh_config->agent_owned) {
        log_debug("Not stopping SSH agent - we don't own it");
        return 0;
    }
    if (ssh_config->agent_pid <= 0) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Owned SSH agent has no verified PID; retained for retry");
        return -1;
    }
    
    log_info("Stopping SSH agent (PID: %d)", ssh_config->agent_pid);

    /* Route through the same hardened reaper as every other kill path
     * (AR-02 #19): identity-verify the PID (comm + our socket in argv) and
     * pidfd-pin it before signaling, so a recorded PID that was recycled to
     * an unrelated same-uid process — or to the user's own login ssh-agent —
     * is never signaled. The old path gated only on kill(pid, 0) liveness. */
    ssh_process_outcome_t reap_outcome = g_ssh_reap(
        ssh_config->agent_pid,
        ssh_config->agent_socket_arg[0]
            ? ssh_config->agent_socket_arg
            : ssh_config->agent_socket_path,
        -1);
    if (!ssh_reap_allows_cleanup(reap_outcome)) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH agent PID %ld reap outcome %s; retained for retry",
                  (long)ssh_config->agent_pid,
                  ssh_process_outcome_name(reap_outcome));
        log_warning("SSH agent teardown was not conclusive; retaining ownership state");
        return -1;
    }
    log_debug("SSH agent stopped");
    
    /* Clean up socket file. AR-05 L15: this was the file's lone
     * absolute-path, symlink-following unlink() — reachable from
     * ssh_manager_cleanup's rollback paths with no agent-dir lock held and
     * no namespace re-validation, while every other socket mutation goes
     * through the pinned descriptor precisely because the runtime dir can
     * live in world-writable sticky /tmp. Route it through the same
     * validated, locked dir fd and unlinkat() the leaf component. The lock
     * helpers re-enter cleanly when a caller already holds the agent-dir
     * lock (per-process refcount), so the locked in-file caller is safe. The
     * unlink and directory sync are now part of the teardown contract: an
     * uncertain namespace commit retains this structure as a retry handle. */
    if (strlen(ssh_config->agent_socket_path) > 0) {
        char socket_dir[MAX_PATH_LEN];
        const char *slash = strrchr(ssh_config->agent_socket_path, '/');
        bool cleanup_complete = false;
        if (slash && slash != ssh_config->agent_socket_path &&
            *(slash + 1) != '\0' &&
            (size_t)(slash - ssh_config->agent_socket_path) < sizeof(socket_dir)) {
            const char *socket_name = slash + 1;
            size_t dir_len = (size_t)(slash - ssh_config->agent_socket_path);
            bool absent = false;
            memcpy(socket_dir, ssh_config->agent_socket_path, dir_len);
            socket_dir[dir_len] = '\0';
            int dir_fd = open_isolated_agent_socket_dir(socket_dir,
                                                        sizeof(socket_dir),
                                                        false, &absent);
            if (dir_fd >= 0) {
                int lock_fd = lock_agent_dir(dir_fd);
                if (lock_fd >= 0) {
                    if (verify_socket_dir_namespace(dir_fd, socket_dir) == 0 &&
                        unlink_ssh_runtime_entry(
                            dir_fd, socket_name, true,
                            "stopped agent socket cleanup") == 0) {
                        cleanup_complete = true;
                    }
                    unlock_agent_dir(lock_fd);
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to lock SSH agent directory during stop");
                }
                close(dir_fd);
            } else if (absent) {
                cleanup_complete = true;
            }
        } else {
            set_error(ERR_INVALID_PATH,
                      "Cannot identify SSH agent socket entry for durable cleanup");
        }
        if (cleanup_complete) {
            log_debug("Removed SSH agent socket: %s", ssh_config->agent_socket_path);
        } else {
            log_warning("SSH agent stopped but socket cleanup is not durable; retaining retry state");
            return -1;
        }
    }
    
    /* Reset state */
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    ssh_config->agent_socket_path[0] = '\0';
    ssh_config->agent_socket_arg[0] = '\0';
    
    /* Clear environment */
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    
    return 0;
}

/* Clear all keys from SSH agent */
int ssh_clear_agent_keys(ssh_config_t *ssh_config) {
    char output[512];
    
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        log_debug("No SSH agent available to clear keys");
        return 0;
    }
    
    log_debug("Clearing all keys from SSH agent");
    
    /* Set up environment for ssh-add */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -D to delete all keys. A nonzero result is not evidence
     * that the agent was already empty: it can also mean the agent was
     * unreachable or rejected the operation. Loading into that unproved state
     * would violate system mode's exact replacement contract. */
    if (ssh_run(output, sizeof(output), false, "ssh-add", "-D",
                (const char *)NULL) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED,
                  "Failed to clear SSH agent before key replacement: %s",
                  output);
        return -1;
    }
    log_debug("SSH agent keys cleared successfully");
    return 0;
}

/* Add key to SSH agent */
int ssh_add_key(ssh_config_t *ssh_config, const char *key_path) {
    char output[512];

    if (!ssh_config || !key_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_add_key");
        return -1;
    }

    if (strlen(ssh_config->agent_socket_path) == 0) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "No SSH agent available");
        return -1;
    }

    log_debug("Adding SSH key to agent: %s", key_path);

    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }

    /* `-k` disables ssh-add's implicit sibling-certificate autoload. The
     * switch contract is one exact private-key identity, not an unmodeled
     * key-plus-certificate pair. Keep the path as one argv element. */
    if (ssh_run(output, sizeof(output), false, "ssh-add", "-k", key_path,
                (const char *)NULL) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s", output);
        return -1;
    }

    log_info("SSH key added successfully: %s", key_path);
    return 0;
}

/* Load the already-admitted key generation through stdin. OpenSSH treats a
 * lone `-` as a private-key stream; passphrase acquisition remains on its
 * normal /dev/tty or SSH_ASKPASS channel after the runner closes this pipe.
 * run_argv writes directly from the caller-owned buffer and never logs it. */
static int ssh_add_key_snapshot(ssh_config_t *ssh_config,
                                const char *key_path,
                                const ssh_key_snapshot_t *snapshot) {
    const char *argv[] = {"ssh-add", "-k", "-", NULL};
    char output[512];
    run_opts_t opts;
    run_result_t res;

    if (!ssh_config || !key_path || !*key_path || !snapshot ||
        !snapshot->data || snapshot->length == 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid descriptor-backed SSH key-load arguments");
        return -1;
    }
    if (ssh_config->agent_socket_path[0] == '\0') {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "No SSH agent available");
        return -1;
    }
    if (setup_ssh_environment(ssh_config) != 0) return -1;

    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.input = snapshot->data;
    opts.input_len = snapshot->length;
    if (run_argv(argv, &opts, &res) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s",
                  output);
        return -1;
    }
    log_info("SSH key added successfully: %s", key_path);
    return 0;
}

/* List loaded SSH keys */
int ssh_list_keys(ssh_config_t *ssh_config, char *output, size_t output_size) {
    if (!ssh_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_list_keys");
        return -1;
    }
    
    if (strlen(ssh_config->agent_socket_path) == 0) {
        safe_strncpy(output, "No SSH agent available", output_size);
        return -1;
    }
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -l */
    if (ssh_run(output, output_size, false, "ssh-add", "-l",
                (const char *)NULL) != 0) {
        safe_strncpy(output, "No keys loaded in SSH agent", output_size);
        return -1;
    }
    
    return 0;
}

int ssh_inspect_key_file(const char *key_path,
                         ssh_key_inspection_t *inspection) {
    char first_line[256];
    struct stat st;
    size_t used = 0;
    int fd;

    if (!key_path || !inspection) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH key inspection arguments");
        return -1;
    }
    memset(inspection, 0, sizeof(*inspection));

    /* Resolve the pathname once, reject symlinks, then derive metadata and
     * content from the same pinned object. This closes the stat/fopen race and
     * gives status callers a reusable one-open result (AR-07 L28). */
    /* O_NONBLOCK prevents a planted FIFO/device from wedging `status` before
     * fstat can classify it as non-regular. Regular files ignore the flag. */
    fd = g_ssh_key_open(key_path,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot safely open SSH key file: %s", key_path);
        return -1;
    }
    inspection->exists = true;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot inspect SSH key file: %s", key_path);
        return -1;
    }
    inspection->mode = st.st_mode & 0777;
    inspection->regular = S_ISREG(st.st_mode);
    inspection->owned_by_user = st.st_uid == getuid();
    inspection->secure_permissions = (inspection->mode & 077) == 0;

    if (inspection->regular) {
        while (used + 1U < sizeof(first_line)) {
            ssize_t n = read(fd, first_line + used, 1);
            if (n == 1) {
                if (first_line[used++] == '\n') break;
                continue;
            }
            if (n == 0) break;
            if (errno == EINTR) continue;
            {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
                set_system_error(ERR_SSH_KEY_INVALID,
                                 "Cannot read SSH key file: %s", key_path);
                return -1;
            }
        }
        first_line[used] = '\0';
        inspection->private_key =
            strstr(first_line, "-----BEGIN") != NULL &&
            strstr(first_line, "PRIVATE KEY") != NULL;
    }
    if (close(fd) != 0) {
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot close SSH key file after inspection: %s",
                         key_path);
        return -1;
    }
    return 0;
}

static int ssh_require_valid_key_inspection(
    const char *key_path, const ssh_key_inspection_t *inspection) {
    if (!inspection->exists) {
        set_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s",
                  key_path);
        return -1;
    }
    if (!inspection->regular) {
        set_error(ERR_SSH_KEY_INVALID,
                  "SSH key path is not a regular file: %s", key_path);
        return -1;
    }
    /* Reject only group/other access, matching OpenSSH's own private-key policy
     * (AR-06 F28). Owner-only modes (0400, 0600, 0700) are accepted. */
    if (!inspection->secure_permissions) {
        set_error(ERR_SSH_KEY_PERMISSIONS,
                  "SSH key file has unsafe permissions: %o (group/other access not allowed): %s",
                  inspection->mode, key_path);
        return -1;
    }
    if (!inspection->owned_by_user) {
        set_error(ERR_SSH_KEY_OWNERSHIP,
                  "SSH key file not owned by current user: %s", key_path);
        return -1;
    }
    if (!inspection->private_key) {
        set_error(ERR_SSH_KEY_INVALID,
                  "File does not appear to be a valid SSH private key: %s",
                  key_path);
        return -1;
    }

    log_debug("SSH key validation passed: %s", key_path);
    return 0;
}

static void ssh_key_snapshot_clear(ssh_key_snapshot_t *snapshot) {
    if (!snapshot) return;
    if (snapshot->data) {
        secure_zero_memory(snapshot->data, snapshot->length);
        if (g_key_snapshot_clear_hook) {
            g_key_snapshot_clear_hook(
                snapshot->data, snapshot->length,
                snapshot->fd_open ? snapshot->fd : -1);
        }
        free(snapshot->data);
    }
    if (snapshot->fd_open) (void)close(snapshot->fd);
    memset(snapshot, 0, sizeof(*snapshot));
}

/* Resolve and admit the pathname once, then retain the admitted descriptor's
 * exact bytes for every later OpenSSH operation. The before/after revision
 * check also rejects ordinary in-place writes observed during capture. */
static int ssh_key_snapshot_capture(const char *key_path,
                                    ssh_key_snapshot_t *snapshot) {
    ssh_key_inspection_t inspection;
    struct stat before;
    struct stat after;
    char first_line[256];
    char *data = NULL;
    size_t length = 0;
    size_t total = 0;
    size_t first_length = 0;
    int fd = -1;

    if (!key_path || !snapshot) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH key snapshot arguments");
        return -1;
    }
    ssh_key_snapshot_clear(snapshot);
    memset(&inspection, 0, sizeof(inspection));

    fd = g_ssh_key_open(key_path,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            set_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s",
                      key_path);
        } else {
            set_system_error(ERR_SSH_KEY_INVALID,
                             "Cannot safely open SSH key file: %s", key_path);
        }
        return -1;
    }
    if (fstat(fd, &before) != 0) {
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot inspect SSH key file: %s", key_path);
        goto failed;
    }
    inspection.exists = true;
    inspection.mode = before.st_mode & 0777;
    inspection.regular = S_ISREG(before.st_mode);
    inspection.owned_by_user = before.st_uid == getuid();
    inspection.secure_permissions = (inspection.mode & 077) == 0;
    if (!inspection.regular || !inspection.secure_permissions ||
        !inspection.owned_by_user) {
        (void)ssh_require_valid_key_inspection(key_path, &inspection);
        goto failed;
    }
    if (before.st_size <= 0 ||
        (uintmax_t)before.st_size > SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES) {
        set_error(ERR_SSH_KEY_INVALID,
                  "SSH private key is empty or exceeds the %u-byte limit: %s",
                  SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES, key_path);
        goto failed;
    }
    length = (size_t)before.st_size;
    data = malloc(length);
    if (!data) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate descriptor-backed SSH key snapshot");
        goto failed;
    }
    while (total < length) {
        ssize_t n = read(fd, data + total, length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_error(ERR_SSH_KEY_INVALID,
                      "Cannot read the complete SSH key file: %s", key_path);
            goto failed;
        }
    }
    if (fstat(fd, &after) != 0 ||
        !same_runtime_revision(&before, &after)) {
        set_error(ERR_SSH_KEY_INVALID,
                  "SSH key changed while its validated snapshot was captured: %s",
                  key_path);
        goto failed;
    }
    while (first_length < length &&
           first_length + 1U < sizeof(first_line) &&
           data[first_length] != '\n') {
        first_line[first_length] = data[first_length];
        first_length++;
    }
    first_line[first_length] = '\0';
    inspection.private_key =
        strstr(first_line, "-----BEGIN") != NULL &&
        strstr(first_line, "PRIVATE KEY") != NULL;
    if (ssh_require_valid_key_inspection(key_path, &inspection) != 0) {
        goto failed;
    }
    snapshot->data = data;
    snapshot->length = length;
    snapshot->fd = fd;
    snapshot->fd_open = true;
    snapshot->identity = before;
    fd = -1;
    return 0;

failed:
    if (fd >= 0) (void)close(fd);
    if (data) {
        secure_zero_memory(data, length);
        free(data);
    }
    return -1;
}

/* Validate SSH key file */
int ssh_validate_key_file(const char *key_path) {
    ssh_key_inspection_t inspection;

    if (!key_path) {
        set_error(ERR_INVALID_ARGS, "NULL key_path to ssh_validate_key_file");
        return -1;
    }
    if (ssh_inspect_key_file(key_path, &inspection) != 0) return -1;
    return ssh_require_valid_key_inspection(key_path, &inspection);
}

typedef struct {
    size_t start;
    size_t text_len;
    size_t end;
} ssh_config_line_t;

typedef enum {
    SSH_CONFIG_MARKER_NONE,
    SSH_CONFIG_MARKER_BEGIN,
    SSH_CONFIG_MARKER_END
} ssh_config_marker_t;

/* Keep the manager's write-site checks identical to the persisted schema.
 * The manager still validates independently because direct in-memory callers
 * do not necessarily pass through config_load/config_save first. */
static bool valid_ssh_host_alias(const char *alias) {
    return toml_validate_ssh_host_alias(alias);
}

static bool same_ssh_config_directory(const struct stat *left,
                                      const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_uid == right->st_uid &&
           left->st_mode == right->st_mode &&
           S_ISDIR(right->st_mode);
}

static bool same_ssh_config_mtime(const struct stat *left,
                                  const struct stat *right) {
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static bool same_ssh_config_ctime(const struct stat *left,
                                  const struct stat *right) {
#ifdef __APPLE__
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool same_ssh_config_snapshot_except_ctime(const struct stat *left,
                                                  const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           same_ssh_config_mtime(left, right) &&
           S_ISREG(right->st_mode);
}

static bool same_ssh_config_snapshot(const struct stat *left,
                                     const struct stat *right) {
    return same_ssh_config_snapshot_except_ctime(left, right) &&
           same_ssh_config_ctime(left, right);
}

/* rename(2) is allowed to advance the renamed inode's ctime.  The exact
 * snapshot comparison above is therefore appropriate only while the inode is
 * still at the same directory entry.  After installation, prove that the
 * public entry names the secured temporary inode with the same immutable
 * security/content metadata, without treating the rename-induced ctime change
 * as an uncertain commit. */
static bool same_installed_ssh_config(const struct stat *temporary,
                                      const struct stat *installed) {
    bool mtime_matches;

#ifdef __APPLE__
    mtime_matches =
        temporary->st_mtimespec.tv_sec == installed->st_mtimespec.tv_sec &&
        temporary->st_mtimespec.tv_nsec == installed->st_mtimespec.tv_nsec;
#else
    mtime_matches =
        temporary->st_mtim.tv_sec == installed->st_mtim.tv_sec &&
        temporary->st_mtim.tv_nsec == installed->st_mtim.tv_nsec;
#endif
    return temporary->st_dev == installed->st_dev &&
           temporary->st_ino == installed->st_ino &&
           temporary->st_mode == installed->st_mode &&
           temporary->st_uid == installed->st_uid &&
           temporary->st_gid == installed->st_gid &&
           temporary->st_nlink == installed->st_nlink &&
           temporary->st_size == installed->st_size && mtime_matches &&
           S_ISREG(installed->st_mode);
}

static bool ssh_config_directory_is_safe(const struct stat *identity) {
    return S_ISDIR(identity->st_mode) && identity->st_uid == getuid() &&
           (identity->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int recheck_ssh_config_directory(const char *path,
                                        const struct stat *identity) {
    struct stat current;

    if (lstat(path, &current) != 0 ||
        !ssh_config_directory_is_safe(&current) ||
        !same_ssh_config_directory(identity, &current)) {
        set_error(ERR_FILE_IO,
                  "SSH config directory changed during update: %s", path);
        return -1;
    }
    return 0;
}

/* Pin ~/.ssh itself, not just its current pathname. All config/temp operations
 * below are relative to this O_NOFOLLOW directory descriptor. Rechecking the
 * public path before and after rename prevents a swapped-out directory from
 * turning a successful write to an unreachable inode into reported success. */
static int open_ssh_config_directory(const char *home, bool create,
                                     char *path, size_t path_size,
                                     struct stat *identity, bool *absent) {
    struct stat before;
    struct stat opened;
    int dir_fd;

    *absent = false;
    memset(identity, 0, sizeof(*identity));
    if ((size_t)snprintf(path, path_size, "%s/.ssh", home) >= path_size) {
        set_error(ERR_INVALID_PATH, "SSH config directory path too long");
        return -1;
    }
    if (lstat(path, &before) != 0) {
        if (errno == ENOENT && !create) {
            *absent = true;
            return -1;
        }
        if (errno != ENOENT || !create) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect SSH config directory: %s", path);
            return -1;
        }
        if (create_directory_recursive(path, 0700) != 0 ||
            lstat(path, &before) != 0) {
            return -1;
        }
    }
    if (!ssh_config_directory_is_safe(&before)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe or symlinked SSH config directory: %s",
                  path);
        return -1;
    }

    dir_fd = open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &opened) != 0 ||
        !ssh_config_directory_is_safe(&opened) ||
        !same_ssh_config_directory(&before, &opened)) {
        int saved_errno = errno;
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to pin SSH config directory safely: %s",
                         path);
        return -1;
    }
    *identity = opened;
    return dir_fd;
}

static bool ssh_config_next_line(const char *buf, size_t len, size_t offset,
                                 ssh_config_line_t *line) {
    const char *newline;

    if (offset >= len) return false;
    newline = memchr(buf + offset, '\n', len - offset);
    line->start = offset;
    if (newline) {
        line->text_len = (size_t)(newline - (buf + offset));
        /* Treat the CR in a conventional CRLF terminator as syntax, not as
         * part of the marker/directive text. line->end still spans both
         * bytes, so untouched ranges retain their original byte encoding. */
        if (line->text_len > 0U &&
            buf[line->start + line->text_len - 1U] == '\r') {
            line->text_len--;
        }
        line->end = (size_t)(newline - buf) + 1U;
    } else {
        line->text_len = len - offset;
        line->end = len;
    }
    return true;
}

static bool ssh_config_line_equals(const char *buf,
                                   const ssh_config_line_t *line,
                                   const char *expected) {
    size_t expected_len = strlen(expected);
    return line->text_len == expected_len &&
           memcmp(buf + line->start, expected, expected_len) == 0;
}

static bool ssh_config_line_prefix(const char *buf,
                                   const ssh_config_line_t *line,
                                   const char *prefix,
                                   const char **value, size_t *value_len) {
    size_t prefix_len = strlen(prefix);
    if (line->text_len <= prefix_len ||
        memcmp(buf + line->start, prefix, prefix_len) != 0) {
        return false;
    }
    *value = buf + line->start + prefix_len;
    *value_len = line->text_len - prefix_len;
    return true;
}

static ssh_config_marker_t ssh_config_parse_marker(
    const char *buf, const ssh_config_line_t *line,
    char alias[MAX_NAME_LEN]) {
    static const char begin_prefix[] = "# >>> gitswitch ";
    static const char begin_suffix[] = " >>>";
    static const char end_prefix[] = "# <<< gitswitch ";
    static const char end_suffix[] = " <<<";
    const char *prefix;
    const char *suffix;
    size_t prefix_len;
    size_t suffix_len;
    size_t alias_len;
    ssh_config_marker_t marker;

    if (line->text_len >= strlen(begin_prefix) + strlen(begin_suffix) + 1U &&
        memcmp(buf + line->start, begin_prefix, strlen(begin_prefix)) == 0) {
        prefix = begin_prefix;
        suffix = begin_suffix;
        marker = SSH_CONFIG_MARKER_BEGIN;
    } else if (line->text_len >= strlen(end_prefix) + strlen(end_suffix) + 1U &&
               memcmp(buf + line->start, end_prefix, strlen(end_prefix)) == 0) {
        prefix = end_prefix;
        suffix = end_suffix;
        marker = SSH_CONFIG_MARKER_END;
    } else {
        return SSH_CONFIG_MARKER_NONE;
    }
    prefix_len = strlen(prefix);
    suffix_len = strlen(suffix);
    if (memcmp(buf + line->start + line->text_len - suffix_len,
               suffix, suffix_len) != 0) {
        return SSH_CONFIG_MARKER_NONE;
    }
    alias_len = line->text_len - prefix_len - suffix_len;
    if (alias_len == 0 || alias_len >= MAX_NAME_LEN) {
        return SSH_CONFIG_MARKER_NONE;
    }
    memcpy(alias, buf + line->start + prefix_len, alias_len);
    alias[alias_len] = '\0';
    return valid_ssh_host_alias(alias) ? marker : SSH_CONFIG_MARKER_NONE;
}

static bool ssh_config_identity_option_valid(const char *value,
                                             size_t value_len) {
    size_t i;

    if (value_len == 0) return false;
    for (i = 0; i < value_len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c < 0x20 || c == 0x7f) return false;
    }
    if (value[0] != '"') {
        /* Legacy gitswitch releases emitted the expanded path bare, including
         * spaces. Accept that exact option shape so configure can repair it. */
        return memchr(value, '"', value_len) == NULL;
    }
    if (value_len < 2U || value[value_len - 1U] != '"') return false;
    for (i = 1; i + 1U < value_len; i++) {
        if (value[i] == '"') return false;
    }
    return true;
}

/* Serialize IdentityFile as one double-quoted OpenSSH argument. OpenSSH's
 * strdelim_internal removes quote delimiters but does NOT treat backslash as an
 * escape inside them, so a literal backslash must be emitted exactly once.
 * '%' is doubled so %h/%r/etc. token expansion cannot reinterpret a literal
 * filename. ${ENV} expansion has no portable literal-dollar escape at this
 * layer, so reject '$' rather than silently target a different key. */
static int ssh_quote_identity_file(const char *path, char **quoted_out) {
    size_t path_len = strlen(path);
    size_t quoted_len = 2U;
    size_t out = 0;
    char *quoted;

    *quoted_out = NULL;
    for (size_t i = 0; i < path_len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c < 0x20 || c == 0x7f || c == '\'' || c == '"' || c == '$') {
            set_error(ERR_INVALID_PATH,
                      "SSH key path contains a quote, control byte, or unsafe "
                      "OpenSSH expansion token: %s", path);
            return -1;
        }
        if (quoted_len > SIZE_MAX - (c == '%' ? 2U : 1U)) {
            set_error(ERR_MEMORY_ALLOCATION, "SSH key path is too large");
            return -1;
        }
        quoted_len += c == '%' ? 2U : 1U;
    }
    quoted = malloc(quoted_len + 1U);
    if (!quoted) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory serializing SSH key path");
        return -1;
    }
    quoted[out++] = '"';
    for (size_t i = 0; i < path_len; i++) {
        if (path[i] == '%') {
            quoted[out++] = '%';
            quoted[out++] = '%';
        } else {
            quoted[out++] = path[i];
        }
    }
    quoted[out++] = '"';
    quoted[out] = '\0';
    *quoted_out = quoted;
    return 0;
}

/* Read config through the pinned directory and carry its exact length. NUL is
 * rejected while the original descriptor and metadata snapshot are still the
 * only state involved: no temp file, chmod, rename, or directory sync has
 * happened, so a hostile binary config remains byte/inode/mtime identical.
 * Keep the descriptor open through the caller's transaction.  Some systems
 * finalize read-side inode timestamps on close; closing here would make our
 * own access look like hostile ctime drift at the pre-rename recheck. */
static int read_ssh_config_at(int dir_fd, const char *display_path,
                              char **out, size_t *out_len, bool *existed,
                              struct stat *identity, int *pinned_fd) {
    const size_t max_bytes = (size_t)GITSWITCH_SSH_CONFIG_MAX_BYTES;
    struct stat before;
    struct stat opened;
    struct stat after;
    size_t used = 0;
    size_t cap;
    char *buf = NULL;
    int fd = -1;

    *out = NULL;
    *out_len = 0;
    *existed = false;
    *pinned_fd = -1;
    memset(identity, 0, sizeof(*identity));

    if (fstatat(dir_fd, "config", &before, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            buf = malloc(1);
            if (!buf) {
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory reading SSH config");
                return -1;
            }
            buf[0] = '\0';
            *out = buf;
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect SSH config: %s",
                         display_path);
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  S_ISLNK(before.st_mode)
                      ? "Refusing to update symlinked SSH config: %s"
                      : "Refusing to update non-regular SSH config: %s",
                  display_path);
        return -1;
    }
    if (before.st_size < 0 ||
        (unsigned long long)before.st_size >
            (unsigned long long)max_bytes) {
        set_error(ERR_FILE_IO, "SSH config too large to update safely: %s",
                  display_path);
        return -1;
    }

    /* O_NONBLOCK prevents a raced FIFO/device from hanging before fstat rejects
     * it. Regular files ignore O_NONBLOCK. */
    fd = openat(dir_fd, "config",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to open SSH config safely: %s", display_path);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !same_ssh_config_snapshot(&before, &opened)) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "SSH config changed while it was being opened: %s",
                  display_path);
        return -1;
    }

    cap = (size_t)opened.st_size + 1U;
    if (cap < 4096U) cap = 4096U;
    if (cap > max_bytes + 1U) cap = max_bytes + 1U;
    buf = malloc(cap);
    if (!buf) {
        close(fd);
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory reading SSH config: %s", display_path);
        return -1;
    }

    for (;;) {
        ssize_t n;
        if (used == cap - 1U) {
            size_t newcap;
            char *grown;

            if (used == max_bytes) {
                unsigned char extra;
                do {
                    n = read(fd, &extra, 1);
                } while (n < 0 && errno == EINTR);
                if (n == 0) break;
                if (n > 0) {
                    set_error(ERR_FILE_IO,
                              "SSH config too large to update safely: %s",
                              display_path);
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to read SSH config: %s",
                                     display_path);
                }
                free(buf);
                close(fd);
                return -1;
            }
            newcap = cap <= (max_bytes + 1U) / 2U
                         ? cap * 2U
                         : max_bytes + 1U;
            grown = realloc(buf, newcap);
            if (!grown) {
                free(buf);
                close(fd);
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory reading SSH config: %s",
                          display_path);
                return -1;
            }
            buf = grown;
            cap = newcap;
        }
        n = read(fd, buf + used, cap - 1U - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        set_system_error(ERR_FILE_IO, "Failed to read SSH config: %s",
                         display_path);
        free(buf);
        close(fd);
        return -1;
    }
    if (fstat(fd, &after) != 0 ||
        !same_ssh_config_snapshot(&opened, &after)) {
        free(buf);
        close(fd);
        set_error(ERR_FILE_IO, "SSH config changed while it was read: %s",
                  display_path);
        return -1;
    }
    if (memchr(buf, '\0', used) != NULL) {
        set_error(ERR_FILE_IO,
                  "SSH config contains an embedded NUL; refusing any update: %s",
                  display_path);
        free(buf);
        close(fd);
        return -1;
    }

    buf[used] = '\0';
    *out = buf;
    *out_len = used;
    *existed = true;
    *identity = after;
    *pinned_fd = fd;
    return 0;
}

static int ssh_config_fd_matches_bytes(int fd, const char *expected,
                                       size_t expected_len, bool *matches) {
    unsigned char chunk[4096];
    size_t offset = 0;

    *matches = false;
    while (offset < expected_len) {
        size_t wanted = expected_len - offset;
        ssize_t n;

        if (wanted > sizeof(chunk)) wanted = sizeof(chunk);
        do {
            n = pread(fd, chunk, wanted, (off_t)offset);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to revalidate pinned SSH config bytes");
            return -1;
        }
        if (n == 0 ||
            memcmp(chunk, expected + offset, (size_t)n) != 0) {
            return 0;
        }
        offset += (size_t)n;
    }

    for (;;) {
        ssize_t n = pread(fd, chunk, 1, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to confirm pinned SSH config length");
            return -1;
        }
        *matches = n == 0;
        return 0;
    }
}

/* Refuse to rename over a path whose final component changed after the safe
 * read. For a previously absent config, any newly-created entry is a conflict;
 * for an existing config, both the retained descriptor and public name must
 * still identify the exact regular-file snapshot. */
static int ssh_config_recheck_before_rename(int dir_fd,
                                            const char *display_path,
                                            bool existed,
                                            const struct stat *identity,
                                            int pinned_fd,
                                            const char *original,
                                            size_t original_len) {
    struct stat expected;
    struct stat pinned;
    struct stat now;

    expected = *identity;
    if (existed) {
        bool bytes_match = false;

        if (pinned_fd < 0) {
            set_error(ERR_FILE_IO,
                      "Missing pinned SSH config descriptor: %s",
                      display_path);
            return -1;
        }
        if (fstat(pinned_fd, &pinned) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot recheck pinned SSH config: %s",
                             display_path);
            return -1;
        }
        if (!same_ssh_config_snapshot(identity, &pinned)) {
            struct stat candidate;
            bool stabilized = false;

            /* FreeBSD can advance the retained inode's ctime while finalizing
             * our own earlier read.  Accept only that single-field shape, and
             * only after a bounded stable pass proves the pinned bytes and EOF
             * are still exactly what the transaction parsed. */
            if (!same_ssh_config_snapshot_except_ctime(identity, &pinned) ||
                same_ssh_config_ctime(identity, &pinned) ||
                pinned.st_size < 0 ||
                (size_t)pinned.st_size != original_len || !original) {
                set_error(ERR_FILE_IO,
                          "Pinned SSH config changed before update: %s",
                          display_path);
                return -1;
            }
            candidate = pinned;
            for (int attempt = 0; attempt < 2; attempt++) {
                struct stat after_read;

                if (ssh_config_fd_matches_bytes(pinned_fd, original,
                                                original_len,
                                                &bytes_match) != 0) {
                    return -1;
                }
                if (!bytes_match) {
                    break;
                }
                if (fstat(pinned_fd, &after_read) != 0) {
                    set_system_error(
                        ERR_FILE_IO,
                        "Cannot finish pinned SSH config revalidation: %s",
                        display_path);
                    return -1;
                }
                if (same_ssh_config_snapshot(&candidate, &after_read)) {
                    expected = after_read;
                    stabilized = true;
                    break;
                }
                if (attempt == 0 &&
                    same_ssh_config_snapshot_except_ctime(&candidate,
                                                          &after_read) &&
                    !same_ssh_config_ctime(&candidate, &after_read)) {
                    candidate = after_read;
                    continue;
                }
                break;
            }
            if (!stabilized) {
                set_error(ERR_FILE_IO,
                          "Pinned SSH config bytes changed before update: %s",
                          display_path);
                return -1;
            }
        }
    }

    if (fstatat(dir_fd, "config", &now, AT_SYMLINK_NOFOLLOW) != 0) {
        if (!existed && errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "SSH config changed before update: %s",
                         display_path);
        return -1;
    }
    if (!existed || !same_ssh_config_snapshot(&expected, &now)) {
        set_error(ERR_FILE_IO,
                  "SSH config changed before update; refusing to replace it: %s "
                  "[existed=%d regular=%d dev=%d ino=%d mode=%d uid=%d gid=%d "
                  "nlink=%d size=%d mtime=%d ctime=%d]",
                  display_path, existed, S_ISREG(now.st_mode),
                  expected.st_dev == now.st_dev,
                  expected.st_ino == now.st_ino,
                  expected.st_mode == now.st_mode,
                  expected.st_uid == now.st_uid,
                  expected.st_gid == now.st_gid,
                  expected.st_nlink == now.st_nlink,
                  expected.st_size == now.st_size,
                  same_ssh_config_mtime(&expected, &now),
                  same_ssh_config_ctime(&expected, &now));
        return -1;
    }
    return 0;
}

/* Parse every exact gitswitch marker line in the complete file. A block is
 * owned only when begin/end aliases match, Host names the same alias, and all
 * intervening lines are recognized options with exact cardinality. Incidental
 * marker substrings are ordinary bytes. Any exact malformed/nested/mismatched
 * marker makes the whole operation fail without producing replacement bytes.
 * Valid target duplicates are all removed; valid blocks for other aliases are
 * copied byte-for-byte. */
static int ssh_filter_managed_blocks(const char *buf, size_t len,
                                     const char *target_alias,
                                     char **filtered_out,
                                     size_t *filtered_len_out,
                                     size_t *removed_out) {
    char *filtered;
    size_t scan = 0;
    size_t copied_from = 0;
    size_t written = 0;
    size_t removed = 0;

    *filtered_out = NULL;
    *filtered_len_out = 0;
    *removed_out = 0;
    filtered = malloc(len + 1U);
    if (!filtered) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory parsing SSH config managed blocks");
        return -1;
    }

    while (scan < len) {
        ssh_config_line_t begin_line;
        ssh_config_line_t line;
        ssh_config_marker_t marker;
        char block_alias[MAX_NAME_LEN];
        char marker_alias[MAX_NAME_LEN];
        char host_line[MAX_NAME_LEN + 8];
        size_t block_end;
        size_t identity_count = 0;
        size_t identities_only_count = 0;
        size_t hostname_count = 0;
        bool closed = false;

        (void)ssh_config_next_line(buf, len, scan, &begin_line);
        marker = ssh_config_parse_marker(buf, &begin_line, block_alias);
        if (marker == SSH_CONFIG_MARKER_NONE) {
            scan = begin_line.end;
            continue;
        }
        if (marker == SSH_CONFIG_MARKER_END) {
            set_error(ERR_FILE_IO,
                      "Unmatched gitswitch SSH end marker for '%s'", block_alias);
            free(filtered);
            return -1;
        }

        scan = begin_line.end;
        if (!ssh_config_next_line(buf, len, scan, &line) ||
            (size_t)snprintf(host_line, sizeof(host_line), "Host %s",
                             block_alias) >= sizeof(host_line) ||
            !ssh_config_line_equals(buf, &line, host_line)) {
            set_error(ERR_FILE_IO,
                      "Malformed gitswitch SSH block for '%s': expected exact Host line",
                      block_alias);
            free(filtered);
            return -1;
        }
        scan = line.end;

        while (ssh_config_next_line(buf, len, scan, &line)) {
            const char *value;
            size_t value_len;

            marker = ssh_config_parse_marker(buf, &line, marker_alias);
            if (marker != SSH_CONFIG_MARKER_NONE) {
                if (marker != SSH_CONFIG_MARKER_END ||
                    strcmp(marker_alias, block_alias) != 0) {
                    set_error(ERR_FILE_IO,
                              "Nested or mismatched gitswitch SSH marker inside '%s' block",
                              block_alias);
                    free(filtered);
                    return -1;
                }
                if (identity_count != 1U || identities_only_count != 1U ||
                    hostname_count > 1U) {
                    set_error(ERR_FILE_IO,
                              "Malformed gitswitch SSH options for '%s'",
                              block_alias);
                    free(filtered);
                    return -1;
                }
                block_end = line.end;
                closed = true;
                break;
            }

            if (ssh_config_line_prefix(buf, &line, "  IdentityFile ",
                                       &value, &value_len) &&
                ssh_config_identity_option_valid(value, value_len)) {
                identity_count++;
            } else if (ssh_config_line_equals(buf, &line,
                                              "  IdentitiesOnly yes")) {
                identities_only_count++;
            } else if (ssh_config_line_prefix(buf, &line, "  HostName ",
                                              &value, &value_len) &&
                       value_len < MAX_NAME_LEN) {
                char hostname[MAX_NAME_LEN];
                memcpy(hostname, value, value_len);
                hostname[value_len] = '\0';
                if (!toml_validate_ssh_hostname(hostname)) {
                    set_error(ERR_FILE_IO,
                              "Malformed HostName in gitswitch SSH block for '%s'",
                              block_alias);
                    free(filtered);
                    return -1;
                }
                hostname_count++;
            } else {
                set_error(ERR_FILE_IO,
                          "Unrecognized line in gitswitch SSH block for '%s'",
                          block_alias);
                free(filtered);
                return -1;
            }
            if (identity_count > 1U || identities_only_count > 1U ||
                hostname_count > 1U) {
                set_error(ERR_FILE_IO,
                          "Duplicate option in gitswitch SSH block for '%s'",
                          block_alias);
                free(filtered);
                return -1;
            }
            scan = line.end;
        }
        if (!closed) {
            set_error(ERR_FILE_IO,
                      "Unterminated gitswitch SSH block for '%s'", block_alias);
            free(filtered);
            return -1;
        }

        if (string_ascii_case_equal(block_alias, target_alias)) {
            size_t prefix_len = begin_line.start - copied_from;
            memcpy(filtered + written, buf + copied_from, prefix_len);
            written += prefix_len;
            copied_from = block_end;
            removed++;
        }
        scan = block_end;
    }

    if (copied_from < len) {
        memcpy(filtered + written, buf + copied_from, len - copied_from);
        written += len - copied_from;
    }
    filtered[written] = '\0';
    *filtered_out = filtered;
    *filtered_len_out = written;
    *removed_out = removed;
    return 0;
}

/* Create a random O_EXCL temp under the pinned directory, write and fsync its
 * exact byte length, revalidate directory/config/temp identities, renameat,
 * then fsync the directory entry. A post-rename verification/sync failure is
 * explicitly reported as changed/uncertain; callers must never claim success. */
static int ssh_write_config_atomic_at(
    int dir_fd, const char *dir_path, const struct stat *dir_identity,
    const char *display_path, const char *content, size_t content_len,
    bool config_existed, const struct stat *config_identity,
    int pinned_config_fd, const char *original_content,
    size_t original_len, ssh_config_publication_state_t *publication) {
    static const char random_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char suffix[17];
    char temp_name[64];
    char temp_path[MAX_PATH_LEN];
    struct stat temp_identity;
    struct stat current_temp;
    struct stat installed;
    size_t written = 0;
    int fd = -1;
    bool temp_registered = false;
    bool renamed = false;

    for (int attempt = 0; attempt < 16; attempt++) {
        if (generate_random_string(suffix, sizeof(suffix), random_chars) != 0) {
            return -1;
        }
        if ((size_t)snprintf(temp_name, sizeof(temp_name),
                             "config.gitswitch.%s", suffix) >=
                sizeof(temp_name) ||
            (size_t)snprintf(temp_path, sizeof(temp_path), "%s/%s",
                             dir_path, temp_name) >= sizeof(temp_path)) {
            set_error(ERR_INVALID_PATH, "SSH config temp path too long");
            return -1;
        }
        fd = openat(dir_fd, temp_name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0) break;
        if (errno != EEXIST) {
            set_system_error(ERR_FILE_IO,
                             "Failed to create temporary SSH config");
            return -1;
        }
    }
    if (fd < 0) {
        set_error(ERR_FILE_IO,
                  "Failed to allocate a unique temporary SSH config");
        return -1;
    }
    temp_registered = signals_scratch_register(temp_path) == 0;

    if (fchmod(fd, 0600) != 0 || fstat(fd, &temp_identity) != 0 ||
        !S_ISREG(temp_identity.st_mode) || temp_identity.st_uid != getuid() ||
        temp_identity.st_nlink != 1 ||
        (temp_identity.st_mode & 0777) != 0600) {
        set_system_error(ERR_FILE_IO, "Failed to secure temporary SSH config");
        goto fail;
    }
    while (written < content_len) {
        ssize_t n = write(fd, content + written, content_len - written);
        if (n > 0) {
            written += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_system_error(ERR_FILE_IO,
                             "Failed to write temporary SSH config");
            goto fail;
        }
    }
    if (fsync(fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to sync temporary SSH config");
        goto fail;
    }
    if (fstat(fd, &temp_identity) != 0 ||
        temp_identity.st_size != (off_t)content_len ||
        !S_ISREG(temp_identity.st_mode) || temp_identity.st_uid != getuid() ||
        temp_identity.st_nlink != 1 ||
        (temp_identity.st_mode & 0777) != 0600) {
        set_error(ERR_FILE_IO,
                  "Temporary SSH config failed final identity validation");
        goto fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO,
                         "Failed to close temporary SSH config");
        goto fail;
    }
    fd = -1;

    if (g_ssh_config_commit_hook &&
        g_ssh_config_commit_hook(dir_fd, temp_name) != 0) {
        set_error(ERR_FILE_IO, "Injected SSH config commit interruption");
        goto fail;
    }
    if (recheck_ssh_config_directory(dir_path, dir_identity) != 0 ||
        ssh_config_recheck_before_rename(dir_fd, display_path, config_existed,
                                         config_identity,
                                         pinned_config_fd,
                                         original_content,
                                         original_len) != 0) {
        goto fail;
    }
    if (fstatat(dir_fd, temp_name, &current_temp,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_ssh_config_snapshot(&temp_identity, &current_temp)) {
        set_error(ERR_FILE_IO,
                  "Temporary SSH config changed before installation");
        goto fail;
    }
    if (renameat(dir_fd, temp_name, dir_fd, "config") != 0) {
        set_system_error(ERR_FILE_IO, "Failed to install SSH config");
        goto fail;
    }
    renamed = true;
    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED;
    }
    if (temp_registered) signals_scratch_unregister(temp_path);
    temp_registered = false;

    if (g_ssh_config_postrename_hook &&
        g_ssh_config_postrename_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH config was installed but injected post-rename "
                  "verification failed; the new bytes were retained and "
                  "their public identity is uncertain");
        return -1;
    }
    if (recheck_ssh_config_directory(dir_path, dir_identity) != 0 ||
        fstatat(dir_fd, "config", &installed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_installed_ssh_config(&temp_identity, &installed)) {
        set_error(ERR_FILE_IO,
                  "SSH config was replaced but post-rename verification failed; "
                  "the commit changed bytes and its public state is uncertain");
        return -1;
    }
    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
    }
    if (g_ssh_dirsync(dir_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "SSH config was replaced but its directory sync failed; "
            "the commit changed bytes and durability is uncertain");
        return -1;
    }
    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_COMMITTED;
    }
    return 0;

fail:
    if (fd >= 0) close(fd);
    if (!renamed) (void)unlinkat(dir_fd, temp_name, 0);
    if (temp_registered) signals_scratch_unregister(temp_path);
    return -1;
}

/* Remove the managed host-alias block for `alias` from ~/.ssh/config (AR-06
 * F15). Account removal (and alias edits) used to leave a permanent
 * "Host <alias>" stanza routing git traffic to the removed account's key, since
 * nothing ever deleted a managed block. No-op if the config or the block is
 * absent. Returns 0 on success (including no-op), -1 on I/O failure. */
int ssh_remove_host_alias(const char *alias) {
    char ssh_config_dir[MAX_PATH_LEN];
    char ssh_config_path[MAX_PATH_LEN];
    char *buf = NULL;
    char *filtered = NULL;
    const char *home = getenv("HOME");
    struct stat dir_identity;
    struct stat config_identity;
    size_t buf_len = 0;
    size_t filtered_len = 0;
    size_t removed = 0;
    bool dir_absent = false;
    bool config_existed;
    int dir_fd = -1;
    int config_lock_fd = -1;
    int pinned_config_fd = -1;
    int rc = -1;

    if (!alias || !*alias) {
        return 0;
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH, "HOME not set");
        return -1;
    }
    if (!valid_ssh_host_alias(alias)) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH host alias: %s", alias);
        return -1;
    }
    dir_fd = open_ssh_config_directory(home, false, ssh_config_dir,
                                       sizeof(ssh_config_dir), &dir_identity,
                                       &dir_absent);
    if (dir_fd < 0) {
        if (dir_absent) return 0;
        return -1;
    }
    /* Serialize the complete read/transform/publish transaction.  Locking only
     * the final rename still lets two gitswitch processes read the same base
     * file and silently overwrite one another's managed-block update.  The
     * private-lock helper pins the parent and ~/.ssh directory as well as this
     * lock inode, so a namespace replacement cannot create a second unlocked
     * writer domain. */
    config_lock_fd = lock_private_file_at(dir_fd, ".gitswitch-config.lock");
    if (config_lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock SSH config transaction");
        goto done;
    }
    if ((size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config",
                         ssh_config_dir) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH, "SSH config path too long");
        goto done;
    }
    if (read_ssh_config_at(dir_fd, ssh_config_path, &buf, &buf_len,
                           &config_existed, &config_identity,
                           &pinned_config_fd) != 0) {
        goto done;
    }
    if (!config_existed) {
        rc = 0;
        goto done;
    }
    if (ssh_filter_managed_blocks(buf, buf_len, alias, &filtered,
                                  &filtered_len, &removed) != 0) {
        goto done;
    }
    if (removed == 0) {
        rc = 0; /* no managed block for this alias */
        goto done;
    }

    if (ssh_write_config_atomic_at(dir_fd, ssh_config_dir, &dir_identity,
                                   ssh_config_path, filtered, filtered_len,
                                   config_existed, &config_identity,
                                   pinned_config_fd, buf, buf_len, NULL) != 0) {
        goto done;
    }
    log_info("Removed %zu SSH host alias block%s: %s", removed,
             removed == 1U ? "" : "s", alias);
    rc = 0;
done:
    free(buf);
    free(filtered);
    if (pinned_config_fd >= 0 && close(pinned_config_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config");
        rc = -1;
    }
    if (config_lock_fd >= 0) unlock_private_file(config_lock_fd);
    if (dir_fd >= 0 && close(dir_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config directory");
        rc = -1;
    }
    return rc;
}

int ssh_configure_host_alias_result(
    const account_t *account,
    ssh_config_publication_state_t *publication) {
    char ssh_config_dir[MAX_PATH_LEN];
    char ssh_config_path[MAX_PATH_LEN];
    char expanded_key_path[MAX_PATH_LEN];
    char begin_marker[MAX_NAME_LEN + 32];
    char end_marker[MAX_NAME_LEN + 32];
    char *quoted_key_path = NULL;
    char *buf = NULL;
    char *filtered = NULL;
    char *newbuf = NULL;
    size_t buf_len = 0;
    size_t filtered_len = 0;
    size_t removed = 0;
    size_t block_len;
    size_t separator_len;
    size_t newbuf_len;
    const char *home = getenv("HOME");
    struct stat dir_identity;
    struct stat config_identity;
    bool dir_absent = false;
    bool config_existed;
    int dir_fd = -1;
    int config_lock_fd = -1;
    int pinned_config_fd = -1;
    int rc = -1;
    int need;

    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED;
    }
    if (!account || strlen(account->ssh_host_alias) == 0) {
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
        }
        return 0; /* Nothing to configure */
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH, "HOME not set");
        return -1;
    }
    if (!valid_ssh_host_alias(account->ssh_host_alias)) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH host alias: %s", account->ssh_host_alias);
        return -1;
    }
    if (!toml_validate_ssh_hostname(account->ssh_hostname)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid or missing SSH canonical hostname for alias '%s': %s",
                  account->ssh_host_alias,
                  account->ssh_hostname[0] ? account->ssh_hostname : "(empty)");
        return -1;
    }

    log_debug("Configuring SSH host alias: %s", account->ssh_host_alias);

    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        return -1;
    }
    /* The expanded path is written below as an "IdentityFile <path>" line; a
     * newline/CR in it would inject an arbitrary ssh_config directive
     * (ProxyCommand => code execution on the next connect). This sink used to
     * rely entirely on the TOML-load sanitizer having stripped such bytes — an
     * incidental, load-time-only defense — so guard the write site itself
     * (AR-02 #10). */
    if (!is_safe_ssh_key_path(expanded_key_path)) {
        set_error(ERR_INVALID_PATH,
                  "SSH key path contains an illegal character (quote/control): %s",
                  expanded_key_path);
        return -1;
    }
    if (ssh_quote_identity_file(expanded_key_path, &quoted_key_path) != 0) {
        return -1;
    }

    if ((size_t)snprintf(begin_marker, sizeof(begin_marker),
                         "# >>> gitswitch %s >>>",
                         account->ssh_host_alias) >= sizeof(begin_marker) ||
        (size_t)snprintf(end_marker, sizeof(end_marker),
                         "# <<< gitswitch %s <<<",
                         account->ssh_host_alias) >= sizeof(end_marker)) {
        set_error(ERR_INVALID_ARGS, "SSH host alias marker is too long");
        goto done;
    }

    dir_fd = open_ssh_config_directory(home, true, ssh_config_dir,
                                       sizeof(ssh_config_dir), &dir_identity,
                                       &dir_absent);
    if (dir_fd < 0) goto done;
    config_lock_fd = lock_private_file_at(dir_fd, ".gitswitch-config.lock");
    if (config_lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock SSH config transaction");
        goto done;
    }
    if ((size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config",
                         ssh_config_dir) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH, "SSH config path too long");
        goto done;
    }

    if (read_ssh_config_at(dir_fd, ssh_config_path, &buf, &buf_len,
                           &config_existed, &config_identity,
                           &pinned_config_fd) != 0) {
        goto done;
    }
    if (ssh_filter_managed_blocks(buf, buf_len, account->ssh_host_alias,
                                  &filtered, &filtered_len, &removed) != 0) {
        goto done;
    }

    separator_len = filtered_len > 0 && filtered[filtered_len - 1U] != '\n'
                        ? 1U
                        : 0U;
    block_len = strlen(begin_marker) + 1U + strlen("Host ") +
                strlen(account->ssh_host_alias) + 1U +
                strlen("  HostName ") + strlen(account->ssh_hostname) + 1U +
                strlen("  IdentityFile ") + strlen(quoted_key_path) + 1U +
                strlen("  IdentitiesOnly yes\n") + strlen(end_marker) + 1U;
    if (filtered_len > (size_t)GITSWITCH_SSH_CONFIG_MAX_BYTES ||
        separator_len + block_len >
            (size_t)GITSWITCH_SSH_CONFIG_MAX_BYTES - filtered_len) {
        set_error(ERR_FILE_IO, "SSH config too large to update safely");
        goto done;
    }
    newbuf_len = filtered_len + separator_len + block_len;
    newbuf = malloc(newbuf_len + 1U);
    if (!newbuf) {
        set_error(ERR_MEMORY_ALLOCATION, "Out of memory updating SSH config");
        goto done;
    }

    /* Assemble the final content and skip the whole write when it is
     * byte-identical to what is already on disk: the mkstemp+rename below
     * otherwise churned ~/.ssh/config's inode and mtime on every switch and
     * every boot-time resume — breaking hard links and waking dotfile-sync
     * watchers — for a no-op (AR-03 L16). */
    need = snprintf(newbuf, newbuf_len + 1U,
                    "%s%s%s\nHost %s\n  HostName %s\n"
                    "  IdentityFile %s\n  IdentitiesOnly yes\n%s\n",
                    filtered, separator_len ? "\n" : "", begin_marker,
                    account->ssh_host_alias, account->ssh_hostname,
                    quoted_key_path, end_marker);
    if (need < 0 || (size_t)need != newbuf_len) {
        set_error(ERR_FILE_IO, "SSH config too large to update safely");
        goto done;
    }
    if (config_existed && newbuf_len == buf_len &&
        memcmp(newbuf, buf, buf_len) == 0) {
        log_debug("SSH host alias block already current; skipping rewrite");
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
        }
        rc = 0;
        goto done;
    }

    /* Install atomically at 0600 via the shared writer (AR-06 F15 factored the
     * mkstemp + checked-write/fsync + recheck + rename dance out so remove can
     * reuse it). */
    if (ssh_write_config_atomic_at(dir_fd, ssh_config_dir, &dir_identity,
                                   ssh_config_path, newbuf, newbuf_len,
                                   config_existed, &config_identity,
                                   pinned_config_fd, buf, buf_len,
                                   publication) != 0) {
        goto done;
    }

    log_info("SSH host alias configured: %s -> %s using %s",
             account->ssh_host_alias, account->ssh_hostname,
             expanded_key_path);
    rc = 0;
done:
    free(buf);
    free(filtered);
    free(newbuf);
    free(quoted_key_path);
    if (pinned_config_fd >= 0 && close(pinned_config_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config");
        rc = -1;
    }
    if (config_lock_fd >= 0) unlock_private_file(config_lock_fd);
    if (dir_fd >= 0 && close(dir_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config directory");
        rc = -1;
    }
    return rc;
}

int ssh_configure_host_alias(const account_t *account) {
    return ssh_configure_host_alias_result(account, NULL);
}

static bool ssh_auth_identity_is_anonymous(const char *identity,
                                           size_t identity_len) {
    static const char anonymous[] = "anonymous";
    size_t i;

    if (identity_len != sizeof(anonymous) - 1U) return false;
    for (i = 0; i < identity_len; i++) {
        unsigned char c = (unsigned char)identity[i];
        if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
            c = (unsigned char)(c - (unsigned char)'A' +
                                (unsigned char)'a');
        }
        if (c != (unsigned char)anonymous[i]) return false;
    }
    return true;
}

/* Match a complete output line with a nonempty provider identity between a
 * fixed prefix/suffix. Embedded controls and GitLab's unauthenticated
 * "Anonymous" discovery result are not authentication proof. */
static bool ssh_auth_line_with_identity(const char *line, size_t line_len,
                                        const char *prefix,
                                        const char *suffix,
                                        bool reject_anonymous) {
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    const char *identity;
    size_t identity_len;
    size_t i;

    if (line_len <= prefix_len + suffix_len ||
        memcmp(line, prefix, prefix_len) != 0 ||
        memcmp(line + line_len - suffix_len, suffix, suffix_len) != 0) {
        return false;
    }
    identity = line + prefix_len;
    identity_len = line_len - prefix_len - suffix_len;
    for (i = 0; i < identity_len; i++) {
        unsigned char c = (unsigned char)identity[i];
        if (c < 0x20U || c == 0x7fU) return false;
    }
    return !reject_anonymous ||
           !ssh_auth_identity_is_anonymous(identity, identity_len);
}

/* Git hosting probes deliberately request no shell. GitHub documents a
 * successful authentication as exit 1; GitLab and Bitbucket discovery shells
 * return exit 0. A provider-specific complete line (or complete Bitbucket
 * line pair) is required in addition to that normal, unsignaled exit class. */
static bool ssh_authentication_was_proven(const char *output,
                                          size_t output_len,
                                          const run_result_t *result) {
    static const char github_suffix[] =
        "! You've successfully authenticated, but GitHub does not provide "
        "shell access.";
    static const char bitbucket_legacy_access[] =
        "You can use git or hg to connect to Bitbucket. Shell access is "
        "disabled.";
    static const char bitbucket_current_access[] =
        "You can use git to connect to Bitbucket. Shell access is disabled";
    bool github = false;
    bool gitlab = false;
    bool bitbucket_identity = false;
    bool bitbucket_access = false;
    size_t offset = 0U;

    if (!output || !result || !result->spawned || result->term_signal != 0 ||
        result->out_truncated) {
        return false;
    }
    while (offset < output_len) {
        const char *line = output + offset;
        const char *newline = memchr(line, '\n', output_len - offset);
        size_t line_len = newline ? (size_t)(newline - line)
                                  : output_len - offset;

        if (line_len > 0U && line[line_len - 1U] == '\r') line_len--;
        if (ssh_auth_line_with_identity(line, line_len, "Hi ",
                                        github_suffix, false)) {
            github = true;
        }
        if (ssh_auth_line_with_identity(line, line_len,
                                        "Welcome to GitLab, ", "!", true)) {
            gitlab = true;
        }
        if (ssh_auth_line_with_identity(line, line_len, "logged in as ",
                                        ".", true) ||
            (line_len == strlen("authenticated via ssh key.") &&
             memcmp(line, "authenticated via ssh key.", line_len) == 0)) {
            bitbucket_identity = true;
        }
        if ((line_len == sizeof(bitbucket_legacy_access) - 1U &&
             memcmp(line, bitbucket_legacy_access, line_len) == 0) ||
            (line_len == sizeof(bitbucket_current_access) - 1U &&
             memcmp(line, bitbucket_current_access, line_len) == 0)) {
            bitbucket_access = true;
        }
        if (!newline) break;
        offset = (size_t)(newline - output) + 1U;
    }

    if (result->exit_code == 1) return github;
    if (result->exit_code == 0) {
        return gitlab || (bitbucket_identity && bitbucket_access);
    }
    return false;
}

/* Test SSH connection */
int ssh_test_connection(const account_t *account, const char *host) {
    char output[1024] = {0};
    char expanded_key_path[MAX_PATH_LEN];
    char hostname_option[sizeof("HostName=") + MAX_NAME_LEN];
    run_opts_t opts;
    run_result_t result;

    if (!account || !host) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_test_connection");
        return -1;
    }
    if (expand_path(account->ssh_key_path, expanded_key_path,
                    sizeof(expanded_key_path)) != 0) {
        return -1;
    }
    
    log_debug("Testing SSH connection to: %s", host);
    
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;

    /* Git hosts print their discovery greeting on stderr. Every probe ignores
     * user and system configuration: IdentitiesOnly still permits inherited
     * IdentityFile entries, and a preceding Host block can win HostName's
     * first-obtained-value semantics. Managed aliases therefore carry their
     * validated destination as an argv option instead of trusting the shared
     * ~/.ssh/config block. */
    if (strlen(account->ssh_host_alias) > 0) {
        const char *alias_argv[] = {
            "ssh", "-T", "-F", "none", "-o", "ConnectTimeout=5", "-o",
            "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i",
            expanded_key_path, "-o", hostname_option,
            account->ssh_host_alias, NULL};

        if (!valid_ssh_host_alias(account->ssh_host_alias) ||
            !toml_validate_ssh_hostname(account->ssh_hostname)) {
            set_error(ERR_INVALID_ARGS,
                      "Managed SSH alias requires a valid alias and canonical "
                      "hostname");
            return -1;
        }
        if (safe_snprintf(hostname_option, sizeof(hostname_option),
                          "HostName=%s", account->ssh_hostname) != 0) {
            return -1;
        }
        (void)run_argv(alias_argv, &opts, &result);
    } else {
        const char *direct_argv[] = {
            "ssh", "-T", "-F", "none", "-o", "ConnectTimeout=5", "-o",
            "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i",
            expanded_key_path, host, NULL};

        (void)run_argv(direct_argv, &opts, &result);
    }

    if (result.out_len < sizeof(output) &&
        ssh_authentication_was_proven(output, result.out_len, &result)) {
        log_debug("SSH authentication successful to %s", host);
        return 0;
    }

    log_debug("SSH connection test failed to %s: %s", host, output);
    return -1;
}

/* Internal helper functions */

/* Run an ssh/ssh-add/ssh-agent command (NULL-terminated varargs argv, argv[0]
 * is the first vararg), no shell. SSH_AUTH_SOCK/SSH_AGENT_PID are inherited from
 * the process env (set by setup_ssh_environment). When merge_stderr is false,
 * the child's stderr is left attached to the terminal so ssh-add's "Identity
 * added" message still reaches the user (preserving prior behavior). Trailing
 * newline in captured stdout is trimmed. Returns 0 iff the child exits 0. */
static int ssh_run(char *output, size_t output_size, int merge_stderr, ...) {
    const char *argv[16];
    size_t n = 0;
    va_list ap;
    const char *a;
    run_opts_t opts;
    run_result_t res;
    int rc;

    va_start(ap, merge_stderr);
    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            va_end(ap);
            set_error(ERR_INVALID_ARGS, "Too many ssh arguments");
            return -1;
        }
        argv[n++] = a;
    }
    va_end(ap);
    argv[n] = NULL;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = merge_stderr;

    rc = run_argv(argv, &opts, &res);

    if (output && output_size > 0 && res.out_len > 0 && output[res.out_len - 1] == '\n') {
        output[res.out_len - 1] = '\0';
    }
    if (rc != 0) {
        return -1;
    }

    return 0;
}

/* Variant used for descriptor-pinned runtime endpoints. The helper resolves a
 * relative socket argument only after fchdir()ing to the validated directory;
 * a concurrent rename/replacement of its public pathname cannot redirect it. */
static int ssh_run_in_dir(int cwd_fd, char *output, size_t output_size,
                          int merge_stderr, ...) {
    const char *argv[16];
    size_t n = 0;
    va_list ap;
    const char *a;
    run_opts_t opts;
    run_result_t res;
    int rc;

    va_start(ap, merge_stderr);
    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            va_end(ap);
            set_error(ERR_INVALID_ARGS, "Too many ssh arguments");
            return -1;
        }
        argv[n++] = a;
    }
    va_end(ap);
    argv[n] = NULL;

    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = merge_stderr;
    opts.cwd_fd = cwd_fd;
    opts.use_cwd_fd = true;
    rc = run_argv(argv, &opts, &res);
    if (output && output_size > 0 && res.out_len > 0 &&
        output[res.out_len - 1] == '\n') {
        output[res.out_len - 1] = '\0';
    }
    return rc == 0 ? 0 : -1;
}

/* Load a key through a descriptor-pinned relative agent socket. */
static int ssh_add_key_pinned(int dir_fd, const char *socket_arg,
                              const char *key_path,
                              const ssh_key_snapshot_t *snapshot) {
    const char *argv[] = {
        "ssh-add", "-k", snapshot ? "-" : key_path, NULL
    };
    const char *env[2] = {NULL, NULL};
    char envbuf[MAX_PATH_LEN + 20];
    char output[512];
    run_opts_t opts;
    run_result_t res;

    if (dir_fd < 0 || !socket_arg || !*socket_arg || !key_path || !*key_path ||
        strchr(socket_arg, '/') ||
        (size_t)snprintf(envbuf, sizeof(envbuf), "SSH_AUTH_SOCK=%s",
                         socket_arg) >= sizeof(envbuf)) {
        set_error(ERR_INVALID_ARGS, "Invalid pinned SSH key-load arguments");
        return -1;
    }
    env[0] = envbuf;
    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.extra_env = env;
    opts.cwd_fd = dir_fd;
    opts.use_cwd_fd = true;
    if (snapshot) {
        if (!snapshot->data || snapshot->length == 0) {
            set_error(ERR_INVALID_ARGS,
                      "Invalid descriptor-backed pinned SSH key snapshot");
            return -1;
        }
        opts.input = snapshot->data;
        opts.input_len = snapshot->length;
    }
    if (run_argv(argv, &opts, &res) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s", output);
        return -1;
    }
    log_info("SSH key added successfully: %s", key_path);
    return 0;
}

/* Set up SSH environment variables */
static int setup_ssh_environment(ssh_config_t *ssh_config) {
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        return -1;
    }
    
    /* Set SSH_AUTH_SOCK */
    if (g_ssh_setenv("SSH_AUTH_SOCK", ssh_config->agent_socket_path, 1) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AUTH_SOCK");
        return -1;
    }
    
    /* Publish a PID only when it was identity-verified.  Reusing a live socket
     * without a trustworthy sidecar is explicitly unowned state, so retaining
     * an older account's SSH_AGENT_PID would be a false process handle. */
    if (ssh_config->agent_pid > 0) {
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", ssh_config->agent_pid);
        if (g_ssh_setenv("SSH_AGENT_PID", pid_str, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AGENT_PID");
            return -1;
        }
    } else if (unsetenv("SSH_AGENT_PID") != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to clear SSH_AGENT_PID");
        return -1;
    }
    
    log_debug("SSH environment configured: SSH_AUTH_SOCK=%s, SSH_AGENT_PID=%d",
              ssh_config->agent_socket_path, ssh_config->agent_pid);
    return 0;
}

/* Public: compute the stable SSH_AUTH_SOCK symlink path.
 * Mirrors the selection done by create_isolated_agent_socket_dir() so shell
 * integration emitted by `gitswitch init` points at the same socket the
 * runtime maintains. */
int ssh_manager_get_auth_sock_path(char *buf, size_t buf_size) {
    char runtime_parent[MAX_PATH_LEN];
    char child[64];
    int parent_fd;
    int child_written;
    if (!buf || buf_size == 0) {
        set_error(ERR_INVALID_ARGS, "NULL/empty buffer to ssh_manager_get_auth_sock_path");
        return -1;
    }

    parent_fd = open_runtime_parent(runtime_parent, sizeof(runtime_parent));
    if (parent_fd < 0) return -1;
    close(parent_fd);
    if (strcmp(runtime_parent, "/tmp") != 0) {
        child_written = snprintf(child, sizeof(child), "gitswitch-ssh");
    } else {
        child_written = snprintf(child, sizeof(child), "gitswitch-ssh-%d",
                                 getuid());
    }
    int written = child_written < 0
                      ? -1
                      : snprintf(buf, buf_size, "%s/%s/current.sock",
                                 runtime_parent, child);

    if (written < 0 || (size_t)written >= buf_size) {
        set_error(ERR_INVALID_PATH, "SSH auth sock path too long");
        return -1;
    }
    return 0;
}

/* Resolve the runtime parent once, pin it, and open/create the manager child
 * relative to that descriptor.  Callers retain the returned child fd through
 * lock acquisition and every filesystem mutation, so renaming/replacing the
 * pathname cannot redirect their open/unlink/rename operations. */
static int open_isolated_agent_socket_dir(char *socket_dir,
                                          size_t socket_dir_size,
                                          bool create, bool *absent) {
    char parent[MAX_PATH_LEN];
    char child[64];
    int parent_fd;
    int dir_fd;
    int written;

    parent_fd = open_runtime_parent(parent, sizeof(parent));
    if (parent_fd < 0) {
        return -1;
    }
    if (strcmp(parent, "/tmp") == 0) {
        written = snprintf(child, sizeof(child), "gitswitch-ssh-%d", getuid());
    } else {
        written = snprintf(child, sizeof(child), "gitswitch-ssh");
    }
    if (written < 0 || (size_t)written >= sizeof(child) ||
        (size_t)snprintf(socket_dir, socket_dir_size, "%s/%s", parent,
                         child) >= socket_dir_size) {
        close(parent_fd);
        set_error(ERR_INVALID_PATH, "Socket directory path too long");
        return -1;
    }
    dir_fd = open_private_subdir_at(parent_fd, child, create, absent);
    close(parent_fd);
    return dir_fd;
}

/* kill_ssh_agent_gracefully and its bare-liveness is_ssh_agent_running are
 * gone (AR-02 #19): they SIGTERM'd/SIGKILL'd a recorded PID on nothing more
 * than kill(pid, 0) — the exact blind kill reap_ssh_agent was hardened
 * against. ssh_stop_agent now routes through reap_ssh_agent, which identity-
 * verifies and pidfd-pins the PID and already escalates with death polling. */

/* Validate the socket entry through the directory descriptor that owns the
 * transaction. Absolute public paths are presentation state; they must never
 * redirect the actual reuse/spawn checks after the directory was pinned. */
static int validate_ssh_agent_socket_at(int dir_fd, const char *socket_name,
                                        const char *display_path,
                                        struct stat *identity) {
    struct stat socket_stat;

    if (dir_fd < 0 || !socket_name || !*socket_name) {
        set_error(ERR_INVALID_ARGS, "Invalid pinned SSH socket entry");
        return -1;
    }
    if (fstatat(dir_fd, socket_name, &socket_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_SSH_AGENT_SOCKET_INVALID,
                         "SSH agent socket not found: %s", display_path);
        return -1;
    }
    if (!S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != getuid() ||
        (socket_stat.st_mode & 0777) != 0600) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID,
                  "Unsafe SSH agent socket: %s", display_path);
        return -1;
    }
    if (identity) *identity = socket_stat;
    return 0;
}

/* The pinned fd remains authoritative, but the exported SSH_AUTH_SOCK and
 * stable link are public paths. Refuse to publish them if that pathname was
 * renamed/replaced while an external helper ran. */
static int verify_socket_dir_namespace(int dir_fd, const char *socket_dir) {
    struct stat pinned;
    struct stat named;

    if (fstat(dir_fd, &pinned) != 0 || lstat(socket_dir, &named) != 0) {
        set_system_error(ERR_FILE_IO,
                         "SSH agent directory namespace changed: %s",
                         socket_dir);
        return -1;
    }
    if (!same_runtime_identity(&pinned, &named) || !S_ISDIR(named.st_mode) ||
        named.st_uid != getuid() || (named.st_mode & 0777) != 0700) {
        set_error(ERR_FILE_IO,
                  "SSH agent directory was replaced during the transaction: %s",
                  socket_dir);
        return -1;
    }
    return 0;
}

/* Capture one symlink's inode and exact target through a stable read. Metadata
 * alone is not an identity proof: an equal-length replacement (or inode reuse)
 * must never inherit cleanup authority from the link it displaced. */
static int capture_runtime_symlink_at(
    int dir_fd, const char *name, const char *expected_target,
    const char *display_path, ssh_current_link_identity_t *identity) {
    struct stat before;
    struct stat after;
    int capture_errno;
    ssize_t n;

    if (!identity || !name || !*name) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH runtime symlink capture arguments");
        errno = EINVAL;
        return -1;
    }
    if (fstatat(dir_fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        capture_errno = errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH runtime symlink: %s",
                         display_path);
        errno = capture_errno;
        return -1;
    }
    if (!S_ISLNK(before.st_mode) || before.st_uid != getuid()) {
        set_error(ERR_FILE_IO,
                  "SSH runtime entry is not a self-owned symlink: %s",
                  display_path);
        errno = EINVAL;
        return -1;
    }
    n = read_locked_runtime_symlink_at(dir_fd, name, identity->target,
                                       sizeof(identity->target) - 1U);
    if (n < 0 || (size_t)n == sizeof(identity->target) - 1U ||
        fstatat(dir_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_symlink(&before, &after)) {
        capture_errno = n < 0 ? errno : ESTALE;
        set_error(ERR_FILE_IO,
                  "SSH runtime symlink changed while being inspected: %s",
                  display_path);
        errno = capture_errno;
        return -1;
    }
    identity->target[n] = '\0';
    if (expected_target && strcmp(identity->target, expected_target) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH runtime symlink has an unexpected target: %s",
                  display_path);
        errno = ESTALE;
        return -1;
    }
    identity->stat = after;
    return 0;
}

/* Capture the exact stable-link inode we just committed and prove its target.
 * Cleanup can then remove only that inode+target pair if a later public-
 * namespace check fails, never an entry substituted meanwhile. */
static int capture_current_socket_link(
    int dir_fd, const char *socket_path, const char *display_path,
    ssh_current_link_identity_t *identity) {
    if (!socket_path || !*socket_path) {
        set_error(ERR_INVALID_ARGS,
                  "Missing expected stable SSH socket target");
        return -1;
    }
    return capture_runtime_symlink_at(dir_fd, "current.sock", socket_path,
                                      display_path, identity);
}

/* atomic_symlink_at() has already made current.sock visible when verification
 * or its first durability barrier fails. Re-capture only the exact expected
 * target and conditionally remove that inode; a mismatch is someone else's
 * replacement and is retained. A final directory sync records whichever
 * namespace state was safely reached before returning explicit uncertainty. */
static int finish_uncertain_current_publication(
    int dir_fd, const char *socket_path, const char *display_path,
    const ssh_current_link_identity_t *known_identity, const char *detail) {
    ssh_current_link_identity_t observed_identity;
    const ssh_current_link_identity_t *cleanup_identity = known_identity;
    int cleanup_rc = -1;
    int confirmation_rc;

    if (!cleanup_identity &&
        capture_current_socket_link(dir_fd, socket_path, display_path,
                                    &observed_identity) == 0) {
        cleanup_identity = &observed_identity;
    }
    if (cleanup_identity) {
        cleanup_rc = remove_current_socket_link_if_unchanged(
            dir_fd, cleanup_identity);
    }
    confirmation_rc = sync_ssh_runtime_dir(
        dir_fd, "uncertain current.sock publication resolution");

    set_error(
        ERR_FILE_IO,
        "SSH current.sock publication is uncertain; %s; %s; directory state %s",
        detail && *detail ? detail : "post-rename verification failed",
        cleanup_identity
            ? (cleanup_rc == 0 ? "the verified publication was removed"
                               : "conditional cleanup requires retry")
            : "an unverifiable or replacement entry was preserved",
        confirmation_rc == 0 ? "was synchronized" : "also requires retry");
    return -1;
}

static int publish_current_socket_link(int dir_fd, const char *socket_path,
                                       const char *display_path,
                                       ssh_current_link_identity_t *identity) {
    char detail[sizeof(g_last_error.message)];

    if (dir_fd < 0 || !socket_path || !*socket_path || !display_path ||
        !identity) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid stable SSH socket publication arguments");
        return -1;
    }
    if (atomic_symlink_at(dir_fd, socket_path, "current.sock") != 0) {
        return -1;
    }
    if (g_current_publish_hook && g_current_publish_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH current.sock post-rename verification hook failed");
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        return finish_uncertain_current_publication(
            dir_fd, socket_path, display_path, NULL, detail);
    }
    if (capture_current_socket_link(dir_fd, socket_path, display_path,
                                    identity) != 0) {
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        return finish_uncertain_current_publication(
            dir_fd, socket_path, display_path, NULL, detail);
    }
    /* renameat made the link visible; only the directory sync makes that
     * namespace commit durable across a crash. */
    if (sync_ssh_runtime_dir(dir_fd, "current.sock publication") != 0) {
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        return finish_uncertain_current_publication(
            dir_fd, socket_path, display_path, identity, detail);
    }
    return 0;
}

static bool same_current_link_identity(
    const ssh_current_link_identity_t *left,
    const ssh_current_link_identity_t *right) {
    return same_runtime_symlink(&left->stat, &right->stat) &&
           strcmp(left->target, right->target) == 0;
}

/* Portable no-overwrite fallback for platforms/filesystems without an atomic
 * rename-exclusion flag. The cooperating writer lock is mandatory. linkat()
 * creates the quarantine name only if it is absent, so a raced destination is
 * never overwritten; the exact inode+target is re-proved before unlinking the
 * public name. Any partial link is synchronized and left discoverable for the
 * reset reconciler rather than deleting state of uncertain ownership. */
static int quarantine_current_socket_link_portable(
    int dir_fd, const char *quarantine,
    const ssh_current_link_identity_t *expected) {
    ssh_current_link_identity_t current;
    ssh_current_link_identity_t captured;

    if (g_agent_lock_depth == 0) {
        errno = ENOLCK;
        return -1;
    }
    if (linkat(dir_fd, "current.sock", dir_fd, quarantine, 0) != 0) {
        return -1; /* EEXIST is a no-overwrite collision. */
    }
    /* The hard-linked retry name must be durable before current.sock can be
     * removed. On failure both exact names remain, so the caller can report a
     * nonzero result without crossing an unrecorded namespace transition. */
    if (sync_ssh_runtime_dir(
            dir_fd, "portable current.sock quarantine publication") != 0) {
        return -1;
    }
    if (capture_runtime_symlink_at(dir_fd, quarantine, NULL, quarantine,
                                   &captured) != 0 ||
        capture_runtime_symlink_at(dir_fd, "current.sock", NULL,
                                   "current.sock", &current) != 0 ||
        !same_current_link_identity(&captured, expected) ||
        !same_current_link_identity(&current, expected) ||
        !same_current_link_identity(&captured, &current)) {
        (void)sync_ssh_runtime_dir(
            dir_fd, "portable current.sock quarantine retry publication");
        errno = ESTALE;
        return -1;
    }
    if (unlinkat(dir_fd, "current.sock", 0) != 0) {
        int saved_errno = errno;
        (void)sync_ssh_runtime_dir(
            dir_fd, "portable current.sock quarantine partial link");
        errno = saved_errno;
        return -1;
    }
    if (sync_ssh_runtime_dir(
            dir_fd, "portable current.sock quarantine removal") != 0) {
        return -1;
    }
    return 0;
}

/* Move current.sock out of the public namespace without overwriting a raced
 * quarantine destination. Prefer the native atomic primitive; the locked
 * link/re-prove/unlink protocol above is the portability fallback. */
static int quarantine_current_socket_link(
    int dir_fd, const char *quarantine,
    const ssh_current_link_identity_t *expected) {
    if (g_quarantine_hook && g_quarantine_hook(dir_fd, quarantine) != 0) {
        errno = EIO;
        return -1;
    }
    if (!g_force_portable_quarantine) {
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U)
#endif
        if (syscall(SYS_renameat2, dir_fd, "current.sock", dir_fd, quarantine,
                    RENAME_NOREPLACE) == 0) {
            return 0;
        }
        if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP) {
            return -1;
        }
#elif (defined(__APPLE__) || defined(__FreeBSD__)) && defined(RENAME_EXCL)
        if (renameatx_np(dir_fd, "current.sock", dir_fd, quarantine,
                         RENAME_EXCL) == 0) {
            return 0;
        }
        if (errno != ENOTSUP && errno != EOPNOTSUPP && errno != EINVAL) {
            return -1;
        }
#endif
    }
    return quarantine_current_socket_link_portable(dir_fd, quarantine,
                                                    expected);
}

/* Make a quarantined symlink public again without overwriting current.sock.
 * The quarantine name is removed only after the exact same inode+target is
 * durably available at current.sock. Thus even a restoration fsync failure
 * leaves both names as explicit retry evidence and never loses foreign data. */
static int restore_quarantined_current_socket(int dir_fd,
                                              const char *quarantine) {
    ssh_current_link_identity_t quarantined;
    ssh_current_link_identity_t current;
    struct stat current_stat;

    if (capture_runtime_symlink_at(dir_fd, quarantine, NULL, quarantine,
                                   &quarantined) != 0) {
        (void)sync_ssh_runtime_dir(
            dir_fd, "unreadable current.sock quarantine preservation");
        return -1;
    }
    if (fstatat(dir_fd, "current.sock", &current_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT ||
            linkat(dir_fd, quarantine, dir_fd, "current.sock", 0) != 0) {
            (void)sync_ssh_runtime_dir(
                dir_fd, "current.sock quarantine conflict preservation");
            return -1;
        }
    }
    if (capture_runtime_symlink_at(dir_fd, "current.sock", NULL,
                                   "current.sock", &current) != 0 ||
        !same_current_link_identity(&current, &quarantined)) {
        (void)sync_ssh_runtime_dir(
            dir_fd, "current.sock quarantine conflict preservation");
        return -1;
    }
    if (sync_ssh_runtime_dir(dir_fd,
                            "current.sock quarantine restoration") != 0) {
        return -1; /* both names retain the same symlink */
    }
    return unlink_ssh_runtime_entry(dir_fd, quarantine, false,
                                    "restored current-link quarantine cleanup");
}

static int remove_current_socket_link_if_unchanged(
    int dir_fd, const ssh_current_link_identity_t *identity) {
    static unsigned long quarantine_sequence;
    char quarantine[96];
    char detail[sizeof(g_last_error.message)];
    ssh_current_link_identity_t current;
    ssh_current_link_identity_t captured;
    int written;

    if (!identity) {
        set_error(ERR_INVALID_ARGS,
                  "Missing stable SSH socket identity during cleanup");
        return -1;
    }
    if (g_current_precleanup_hook && g_current_precleanup_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO, "SSH current-link pre-cleanup hook failed");
        return -1;
    }
    if (capture_runtime_symlink_at(dir_fd, "current.sock", NULL,
                                   "current.sock", &current) != 0) {
        if (errno == ENOENT) {
            return sync_ssh_runtime_dir(
                dir_fd, "current.sock cleanup absence confirmation");
        }
        return -1;
    }
    if (!same_current_link_identity(&current, identity)) {
        set_error(ERR_FILE_IO,
                  "Stable SSH socket changed before cleanup; replacement preserved");
        return -1;
    }
    if (g_current_cleanup_hook && g_current_cleanup_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO, "SSH current-link cleanup hook failed");
        return -1;
    }
    written = snprintf(quarantine, sizeof(quarantine),
                       ".current.sock.cleanup.%ld.%lu", (long)getpid(),
                       quarantine_sequence++);
    if (written < 0 || (size_t)written >= sizeof(quarantine)) {
        set_error(ERR_INVALID_PATH, "SSH current-link quarantine name is too long");
        return -1;
    }
    if (quarantine_current_socket_link(dir_fd, quarantine, identity) != 0) {
        int quarantine_errno = errno;
        if (errno == ENOENT) {
            return sync_ssh_runtime_dir(
                dir_fd, "current.sock quarantine absence confirmation");
        }
        if (fstatat(dir_fd, quarantine, &current.stat,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            (void)sync_ssh_runtime_dir(
                dir_fd, "current.sock quarantine collision preservation");
            errno = quarantine_errno;
            set_system_error(
                ERR_FILE_IO,
                "Cannot quarantine stable SSH socket; collision or retry state retained as %s",
                quarantine);
            return -1;
        }
        errno = quarantine_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot quarantine stable SSH socket before cleanup");
        return -1;
    }
    if (sync_ssh_runtime_dir(dir_fd,
                            "current.sock quarantine publication") != 0) {
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        (void)restore_quarantined_current_socket(dir_fd, quarantine);
        set_error(ERR_FILE_IO,
                  "SSH current.sock quarantine commit is uncertain; %s; restoration requires retry",
                  detail);
        return -1;
    }
    if (g_quarantine_capture_hook &&
        g_quarantine_capture_hook(dir_fd, quarantine) != 0) {
        (void)sync_ssh_runtime_dir(
            dir_fd, "failed current.sock quarantine capture hook");
        (void)restore_quarantined_current_socket(dir_fd, quarantine);
        set_error(ERR_FILE_IO,
                  "SSH current.sock quarantine capture hook failed; retry state retained as %s",
                  quarantine);
        return -1;
    }
    if (capture_runtime_symlink_at(dir_fd, quarantine, NULL, quarantine,
                                   &captured) != 0) {
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        (void)sync_ssh_runtime_dir(
            dir_fd, "failed current.sock quarantine capture");
        (void)restore_quarantined_current_socket(dir_fd, quarantine);
        set_error(ERR_FILE_IO,
                  "SSH current.sock quarantine identity is uncertain; %s; retry state retained as %s",
                  detail, quarantine);
        return -1;
    }
    if (same_current_link_identity(&captured, identity)) {
        if (unlink_ssh_runtime_entry(dir_fd, quarantine, false,
                                     "owned current-link cleanup") != 0) {
            return -1;
        }
        return 0;
    }

    /* A replacement occupied current.sock after validation. Restore the exact
     * replacement symlink; restore_quarantined_current_socket never deletes
     * the quarantine until the same inode+target is durably public. */
    (void)restore_quarantined_current_socket(dir_fd, quarantine);
    set_error(ERR_FILE_IO,
              "Stable SSH socket target changed during cleanup; replacement preserved for retry");
    return -1;
}

int ssh_manager_test_publish_current_link(int dir_fd, const char *target) {
    ssh_current_link_identity_t identity;
    int lock_fd;
    int rc;

    if (dir_fd < 0 || !target) {
        set_error(ERR_INVALID_ARGS, "Invalid current-link publication test arguments");
        return -1;
    }
    lock_fd = lock_agent_dir(dir_fd);
    if (lock_fd < 0) return -1;
    rc = publish_current_socket_link(dir_fd, target, "current.sock",
                                     &identity);
    unlock_agent_dir(lock_fd);
    return rc;
}

int ssh_manager_test_cleanup_current_link(int dir_fd) {
    ssh_current_link_identity_t identity;
    int lock_fd;
    int rc;

    if (dir_fd < 0) {
        set_error(ERR_INVALID_ARGS, "No stable SSH symlink to clean in test");
        return -1;
    }
    lock_fd = lock_agent_dir(dir_fd);
    if (lock_fd < 0) return -1;
    if (capture_runtime_symlink_at(dir_fd, "current.sock", NULL,
                                   "current.sock", &identity) != 0) {
        unlock_agent_dir(lock_fd);
        set_error(ERR_INVALID_ARGS, "No stable SSH symlink to clean in test");
        return -1;
    }
    rc = remove_current_socket_link_if_unchanged(dir_fd, &identity);
    unlock_agent_dir(lock_fd);
    return rc;
}

static bool current_quarantine_name_is_managed(const char *name) {
    static const char prefix[] = ".current.sock.cleanup.";
    const char *cursor;

    if (!name || strncmp(name, prefix, sizeof(prefix) - 1U) != 0) {
        return false;
    }
    cursor = name + sizeof(prefix) - 1U;
    if (!isdigit((unsigned char)*cursor)) return false;
    while (isdigit((unsigned char)*cursor)) cursor++;
    if (*cursor++ != '.' || !isdigit((unsigned char)*cursor)) return false;
    while (isdigit((unsigned char)*cursor)) cursor++;
    return *cursor == '\0';
}

static bool target_is_exact_managed_socket(const char *socket_dir,
                                           const char *target,
                                           char *component,
                                           size_t component_size) {
    static const char prefix[] = "ssh-agent.";
    static const char suffix[] = ".sock";
    char account[MAX_NAME_LEN];
    char expected[MAX_PATH_LEN];
    const char *leaf;
    size_t dir_len;
    size_t leaf_len;
    size_t account_len;

    if (!socket_dir || !target || !component || component_size == 0) {
        return false;
    }
    dir_len = strlen(socket_dir);
    if (strncmp(target, socket_dir, dir_len) != 0 || target[dir_len] != '/') {
        return false;
    }
    leaf = target + dir_len + 1U;
    leaf_len = strlen(leaf);
    if (strchr(leaf, '/') || strchr(leaf, '\\') ||
        leaf_len <= (sizeof(prefix) - 1U) + (sizeof(suffix) - 1U) ||
        strncmp(leaf, prefix, sizeof(prefix) - 1U) != 0 ||
        strcmp(leaf + leaf_len - (sizeof(suffix) - 1U), suffix) != 0) {
        return false;
    }
    account_len = leaf_len - (sizeof(prefix) - 1U) -
                  (sizeof(suffix) - 1U);
    if (account_len >= sizeof(account)) return false;
    memcpy(account, leaf + sizeof(prefix) - 1U, account_len);
    account[account_len] = '\0';
    if (!validate_name(account) ||
        (size_t)snprintf(expected, sizeof(expected), "%s/ssh-agent.%s.sock",
                         socket_dir, account) >= sizeof(expected) ||
        strcmp(expected, target) != 0 || leaf_len + 1U > component_size) {
        return false;
    }
    memcpy(component, leaf, leaf_len + 1U);
    return true;
}

/* Reconcile interrupted current.sock quarantines before any new reset/start
 * mutation. Foreign data is never deleted: a quarantine is unlinked only
 * after the same inode+target is durably public at current.sock. The first
 * reset that observes recovery evidence remains nonzero, forcing a clean
 * second pass to prove the resulting namespace. */
static int reconcile_current_socket_quarantines(int dir_fd,
                                                const char *socket_dir) {
    DIR *directory;
    struct dirent *entry;
    int scan_fd;
    bool saw_quarantine = false;
    bool failed = false;

    {
        int scan_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
        scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
        scan_flags |= O_NOFOLLOW;
#endif
        scan_fd = openat(dir_fd, ".", scan_flags);
    }
    directory = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!directory) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH current-link retry state: %s",
                         socket_dir);
        return -1;
    }
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) {
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot enumerate SSH current-link retry state: %s",
                    socket_dir);
                failed = true;
            }
            break;
        }
        if (!current_quarantine_name_is_managed(entry->d_name)) continue;
        saw_quarantine = true;
        if (restore_quarantined_current_socket(dir_fd, entry->d_name) != 0) {
            failed = true;
        }
    }
    if (closedir(directory) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot close SSH current-link retry scan: %s",
                         socket_dir);
        failed = true;
    }
    if (saw_quarantine) {
        set_error(
            ERR_FILE_IO,
            "SSH current-link retry state was %s; rerun reset to confirm the reconciled namespace",
            failed ? "retained for manual-safe retry" : "reconciled");
        return -1;
    }
    return failed ? -1 : 0;
}

/* Parse ssh-agent output */
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config) {
    char *line;
    char *output_copy;
    char *saveptr;
    
    if (!output || !ssh_config) {
        return -1;
    }
    
    /* Make a copy of output for parsing */
    output_copy = strdup(output);
    if (!output_copy) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate memory for parsing");
        return -1;
    }
    
    /* Parse line by line */
    line = strtok_r(output_copy, "\n", &saveptr);
    while (line) {
        /* Look for SSH_AUTH_SOCK */
        if (strstr(line, "SSH_AUTH_SOCK=")) {
            char *socket_start = strchr(line, '=') + 1;
            char *socket_end = strchr(socket_start, ';');
            if (socket_end) {
                *socket_end = '\0';
            }
            /* ssh-agent quotes the value when the path has shell-special chars
             * (spaces/parens). Trim surrounding whitespace and a matching pair
             * of single/double quotes so the stored path is the real one. */
            while (*socket_start == ' ' || *socket_start == '\t') socket_start++;
            size_t slen = strlen(socket_start);
            while (slen > 0 && (socket_start[slen - 1] == ' ' ||
                                socket_start[slen - 1] == '\t')) {
                socket_start[--slen] = '\0';
            }
            if (slen >= 2 &&
                ((socket_start[0] == '"' && socket_start[slen - 1] == '"') ||
                 (socket_start[0] == '\'' && socket_start[slen - 1] == '\''))) {
                socket_start[slen - 1] = '\0';
                socket_start++;
            }
            safe_strncpy(ssh_config->agent_socket_path, socket_start,
                        sizeof(ssh_config->agent_socket_path));
        }
        
        /* Look for SSH_AGENT_PID */
        if (strstr(line, "SSH_AGENT_PID=")) {
            char *pid_start = strchr(line, '=') + 1;
            char *pid_end = strchr(pid_start, ';');
            if (pid_end) {
                *pid_end = '\0';
            }
            ssh_config->agent_pid = (pid_t)strtol(pid_start, NULL, 10);
        }

        /* Preserve a recovery PID even when the surrounding output syntax is
         * not one the activation parser accepts. OpenSSH's diagnostic line is
         * emitted after both Bourne and csh forms; retaining it lets the
         * pre-sidecar failure path publish a durable retry tuple. This does
         * not make the overall parse succeed without SSH_AUTH_SOCK. */
        if (ssh_config->agent_pid <= 1) {
            char *agent_pid = strstr(line, "Agent pid ");
            if (agent_pid) {
                char *end = NULL;
                long parsed;
                errno = 0;
                agent_pid += strlen("Agent pid ");
                parsed = strtol(agent_pid, &end, 10);
                if (errno == 0 && end != agent_pid && parsed > 1 &&
                    (long)(pid_t)parsed == parsed) {
                    ssh_config->agent_pid = (pid_t)parsed;
                }
            }
        }
        
        line = strtok_r(NULL, "\n", &saveptr);
    }
    
    free(output_copy);
    
    /* Validate we got the required information */
    if (strlen(ssh_config->agent_socket_path) == 0 || ssh_config->agent_pid <= 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        return -1;
    }

    return 0;
}

/* Classify whether a sidecar-less socket path still has a live listener.
 * Merely finding the filesystem socket is insufficient: a dead ssh-agent
 * leaves the inode behind. A successful nonblocking connect proves a listener
 * is reachable; ECONNREFUSED/ENOENT proves the artifact is stale. Every other
 * outcome is indeterminate and therefore fail-closed. */
static int wait_for_ssh_probe(int fd, int timeout_ms) {
    int64_t started;
    int64_t deadline;

    if (timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    started = g_probe_clock();
    if (started < 0) return -1;
    if (started > INT64_MAX - timeout_ms) {
        errno = EOVERFLOW;
        return -1;
    }
    deadline = started + timeout_ms;

    for (;;) {
        int64_t now = g_probe_clock();
        int64_t remaining;
        int poll_timeout;
        int poll_rc;

        if (now < 0) return -1;
        if (now < started) {
            errno = ERANGE;
            return -1;
        }
        if (now >= deadline) return 0;
        remaining = deadline - now;
        poll_timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        poll_rc = g_probe_poll(fd, poll_timeout);
        if (poll_rc >= 0) return poll_rc;
        if (errno != EINTR) return -1;
    }
}

static int probe_ssh_agent_socket(const char *path, bool *reachable) {
    struct stat st;
    struct sockaddr_un addr;
    socklen_t err_len;
    int fd;
    int flags;
    int socket_error = 0;

    *reachable = false;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect sidecar-less SSH socket: %s", path);
        return -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        return 0; /* provably not a live UNIX-domain socket */
    }
    if (strlen(path) >= sizeof(addr.sun_path)) {
        set_error(ERR_INVALID_PATH,
                  "Cannot probe overlong sidecar-less SSH socket: %s", path);
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot create probe for sidecar-less SSH socket: %s", path);
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot configure probe for sidecar-less SSH socket: %s", path);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_strncpy(addr.sun_path, path, sizeof(addr.sun_path));
    /* Cast through void*: the direct sockaddr_un->sockaddr cast trips
     * -Wstrict-aliasing=2 on gcc 13 at -O2 (the CI release toolchain), which
     * WERROR promotes to an error. Same idiom as the test suites. */
    if (connect(fd, (struct sockaddr *)(void *)&addr, sizeof(addr)) == 0) {
        *reachable = true;
        close(fd);
        return 0;
    }
    if (errno == ECONNREFUSED || errno == ENOENT) {
        close(fd);
        return 0;
    }
    if (errno != EINPROGRESS && errno != EAGAIN && errno != EWOULDBLOCK) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Cannot prove sidecar-less SSH socket is unreachable: %s", path);
        return -1;
    }

    int poll_rc = wait_for_ssh_probe(fd, 100);
    if (poll_rc <= 0) {
        int saved_errno = poll_rc < 0 ? errno : ETIMEDOUT;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Timed out probing sidecar-less SSH socket: %s", path);
        return -1;
    }

    err_len = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &err_len) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Cannot finish probing sidecar-less SSH socket: %s", path);
        return -1;
    }
    close(fd);
    if (socket_error == 0) {
        *reachable = true;
        return 0;
    }
    if (socket_error == ECONNREFUSED || socket_error == ENOENT) {
        return 0;
    }
    errno = socket_error;
    set_system_error(ERR_SSH_AGENT_FAILED,
                     "Cannot prove sidecar-less SSH socket is unreachable: %s", path);
    return -1;
}

int ssh_manager_test_probe_socket(const char *path, bool *reachable) {
    if (!path || !reachable) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH socket probe test arguments");
        return -1;
    }
    return probe_ssh_agent_socket(path, reachable);
}

int ssh_manager_test_probe_deadline(int timeout_ms) {
    if (timeout_ms < 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH socket probe deadline test argument");
        return -1;
    }
    return wait_for_ssh_probe(-1, timeout_ms);
}

static bool same_runtime_identity(const struct stat *before,
                                  const struct stat *after) {
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_uid == after->st_uid;
}

/* Strict revision equality supplements identity with link, size, and
 * timestamp/generation checks. Use it only while the object is expected to be
 * quiescent, such as one bounded key capture or a finalized reset artifact;
 * later namespace renames legitimately change ctime/nlink. */
static bool same_runtime_revision(const struct stat *before,
                                  const struct stat *after) {
    if (!same_runtime_identity(before, after) ||
        before->st_gid != after->st_gid ||
        before->st_nlink != after->st_nlink ||
        before->st_size != after->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return before->st_gen == after->st_gen &&
           before->st_birthtimespec.tv_sec == after->st_birthtimespec.tv_sec &&
           before->st_birthtimespec.tv_nsec == after->st_birthtimespec.tv_nsec &&
           before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
           before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
           before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#elif defined(__FreeBSD__)
    return before->st_gen == after->st_gen &&
           before->st_birthtim.tv_sec == after->st_birthtim.tv_sec &&
           before->st_birthtim.tv_nsec == after->st_birthtim.tv_nsec &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#else
    return before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static void ssh_runtime_pin_init(ssh_runtime_pin_t *pin) {
    if (!pin) return;
    memset(pin, 0, sizeof(*pin));
    pin->fd = -1;
}

static int stat_ssh_runtime_pin(const ssh_runtime_pin_t *pin,
                                int dir_fd, struct stat *identity) {
    if (!pin || !identity) {
        errno = EINVAL;
        return -1;
    }
    if (pin->fd >= 0) {
        return fstat(pin->fd, identity);
    }
    if (pin->anchor[0] != '\0') {
        return fstatat(dir_fd, pin->anchor, identity, AT_SYMLINK_NOFOLLOW);
    }
    errno = EBADF;
    return -1;
}

/* Hold an object reference across every external scheduling point and
 * deletion hook. A stat tuple alone is not a pin: ext4 may immediately reuse
 * an unlinked inode and give a replacement the old dev/ino/mode/uid tuple.
 * Linux and FreeBSD can hold arbitrary runtime entries with O_PATH. Darwin
 * cannot open a filesystem socket (open(2) reports EOPNOTSUPP), so its
 * descriptor-equivalent reference is a private hard-link anchor in the
 * already locked 0700 runtime directory. Interrupted anchors are reconciled
 * before the next mutating start/reset transaction. The reserved anchor
 * namespace and manager lock are the Darwin concurrency boundary; removal by
 * a same-UID process that ignores the lock is detected and fails closed. */
static int pin_ssh_runtime_entry_at(int dir_fd, const char *name,
                                    const char *display_path,
                                    ssh_runtime_pin_t *pin) {
#if !defined(O_PATH)
    static unsigned long anchor_sequence;
    struct stat before;
#endif
    struct stat opened;
    struct stat named;
    int fd = -1;

    if (dir_fd < 0 || !name || !*name || !pin) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH runtime pin arguments");
        errno = EINVAL;
        return -1;
    }
    ssh_runtime_pin_init(pin);
#if defined(O_PATH)
    {
        int flags = O_PATH | O_NOFOLLOW;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        fd = openat(dir_fd, name, flags);
    }
#else
    if (fstatat(dir_fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 1;
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH runtime artifact before pinning: %s",
                         display_path ? display_path : name);
        return -1;
    }
    for (unsigned int attempts = 0; attempts < 128; attempts++) {
        int written = snprintf(pin->anchor, sizeof(pin->anchor),
                               ".runtime.pin.%ld.%lu", (long)getpid(),
                               anchor_sequence++);
        if (written < 0 || (size_t)written >= sizeof(pin->anchor)) {
            pin->anchor[0] = '\0';
            set_error(ERR_INVALID_PATH,
                      "SSH runtime pin anchor name is too long");
            return -1;
        }
        if (linkat(dir_fd, name, dir_fd, pin->anchor, 0) == 0) break;
        if (errno != EEXIST) {
            pin->anchor[0] = '\0';
            if (errno == ENOENT) return 1;
            set_system_error(ERR_FILE_IO,
                             "Cannot anchor SSH runtime artifact safely: %s",
                             display_path ? display_path : name);
            return -1;
        }
        pin->anchor[0] = '\0';
    }
    if (pin->anchor[0] == '\0') {
        errno = EEXIST;
        set_error(ERR_FILE_IO,
                  "Cannot allocate a private SSH runtime pin anchor");
        return -1;
    }
    if (fstatat(dir_fd, pin->anchor, &opened, AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot identify SSH runtime pin anchor: %s",
                         pin->anchor);
        return -1; /* uncertain reserved state is reconciled on next mutation */
    }
    if (fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&before, &opened) ||
        !same_runtime_identity(&opened, &named)) {
        int saved_errno = errno ? errno : ESTALE;
        int retire_rc = unlink_ssh_runtime_identity_at(
            dir_fd, pin->anchor, &opened, false,
            "failed SSH runtime pin anchor rollback", NULL, NULL);
        if (retire_rc == 0) pin->anchor[0] = '\0';
        errno = saved_errno;
        set_error(ERR_FILE_IO,
                  "SSH runtime artifact changed while being anchored; pin %s: %s",
                  retire_rc == 0 ? "retired" : "retained for retry",
                  display_path ? display_path : name);
        return -1;
    }
    pin->identity = opened;
    return 0;
#endif

    if (fd < 0) {
        if (errno == ENOENT) return 1;
        set_system_error(ERR_FILE_IO,
                         "Cannot pin SSH runtime artifact safely: %s",
                         display_path ? display_path : name);
        return -1;
    }
    if (fstat(fd, &opened) != 0 ||
        fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&opened, &named)) {
        int saved_errno = errno ? errno : ESTALE;
        close(fd);
        errno = saved_errno;
        set_error(ERR_FILE_IO,
                  "SSH runtime artifact changed while being pinned: %s",
                  display_path ? display_path : name);
        return -1;
    }
    pin->identity = opened;
    pin->fd = fd;
    return 0;
}

static int verify_ssh_runtime_pin_at(int dir_fd, const char *name,
                                     const char *display_path,
                                     const ssh_runtime_pin_t *pin) {
    struct stat held;
    struct stat named;

    if (stat_ssh_runtime_pin(pin, dir_fd, &held) != 0 ||
        fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_revision(&pin->identity, &held) ||
        !same_runtime_revision(&pin->identity, &named)) {
        set_error(ERR_FILE_IO,
                  "SSH runtime artifact changed while pinned: %s",
                  display_path ? display_path : name);
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int release_ssh_runtime_pin(int dir_fd, ssh_runtime_pin_t *pin) {
    if (!pin) return 0;
    if (pin->fd >= 0) {
        int fd = pin->fd;
        pin->fd = -1;
        if (close(fd) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot close SSH runtime descriptor pin");
            return -1;
        }
    }
    if (pin->anchor[0] != '\0') {
        if (unlink_ssh_runtime_identity_at(
                dir_fd, pin->anchor, &pin->identity, false,
                "SSH runtime pin anchor retirement", NULL, NULL) != 0) {
            return -1;
        }
        pin->anchor[0] = '\0';
    }
    return 0;
}

static bool ssh_runtime_pin_name_is_managed(const char *name) {
    static const char prefix[] = ".runtime.pin.";
    const char *cursor;

    if (!name || strncmp(name, prefix, sizeof(prefix) - 1U) != 0) {
        return false;
    }
    cursor = name + sizeof(prefix) - 1U;
    if (!isdigit((unsigned char)*cursor)) return false;
    while (isdigit((unsigned char)*cursor)) cursor++;
    if (*cursor++ != '.' || !isdigit((unsigned char)*cursor)) return false;
    while (isdigit((unsigned char)*cursor)) cursor++;
    return *cursor == '\0';
}

/* A Darwin/fallback hard-link pin is intentionally ephemeral. If a process
 * dies while holding one, the next top-level mutator retires it under the
 * manager lock, synchronizes that cleanup, and fails once so the following
 * retry starts from a freshly proved namespace. Malformed reserved names are
 * never guessed at or deleted. */
static int reconcile_ssh_runtime_pins(int dir_fd, const char *socket_dir) {
    static const char prefix[] = ".runtime.pin.";
    DIR *directory;
    struct dirent *entry;
    int scan_fd;
    bool saw_pin = false;
    bool failed = false;
    int scan_flags = O_RDONLY | O_CLOEXEC;

#ifdef O_DIRECTORY
    scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    scan_flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(dir_fd, ".", scan_flags);
    directory = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!directory) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH runtime pin recovery state: %s",
                         socket_dir);
        return -1;
    }
    for (;;) {
        struct stat identity;

        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) {
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot enumerate SSH runtime pin recovery state: %s",
                    socket_dir);
                failed = true;
            }
            break;
        }
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) != 0) {
            continue;
        }
        saw_pin = true;
        if (!ssh_runtime_pin_name_is_managed(entry->d_name)) {
            set_error(ERR_FILE_IO,
                      "Malformed reserved SSH runtime pin state was preserved: %s",
                      entry->d_name);
            failed = true;
            continue;
        }
        if (fstatat(dir_fd, entry->d_name, &identity,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            identity.st_uid != getuid() || S_ISDIR(identity.st_mode)) {
            set_error(ERR_FILE_IO,
                      "Unsafe SSH runtime pin recovery state was preserved: %s",
                      entry->d_name);
            failed = true;
            continue;
        }
        if (unlink_ssh_runtime_identity_at(
                dir_fd, entry->d_name, &identity, false,
                "interrupted SSH runtime pin reconciliation", NULL,
                NULL) != 0) {
            failed = true;
        }
    }
    if (closedir(directory) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot close SSH runtime pin recovery scan: %s",
                         socket_dir);
        failed = true;
    }
    if (saw_pin) {
        set_error(
            ERR_FILE_IO,
            "SSH runtime pin recovery state was %s; rerun the operation to confirm the reconciled namespace",
            failed ? "preserved for retry" : "reconciled");
        return -1;
    }
    return failed ? -1 : 0;
}

static bool same_runtime_symlink(const struct stat *before,
                                 const struct stat *after) {
    return same_runtime_identity(before, after) &&
           before->st_size == after->st_size;
}

static int ssh_manager_inspect_current_account(char *name, size_t name_size,
                                               bool *present,
                                               const account_t *expected,
                                               bool *expected_live) {
    static const char current_suffix[] = "/current.sock";
    static const char socket_prefix[] = "ssh-agent.";
    static const char socket_suffix[] = ".sock";
    char current[MAX_PATH_LEN];
    char socket_dir[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];
    char account_name[MAX_NAME_LEN];
    char expected_path[MAX_PATH_LEN];
    ssh_runtime_pin_t current_pin;
    ssh_runtime_pin_t socket_pin;
    const char *component;
    size_t current_len;
    size_t dir_len;
    size_t component_len;
    size_t prefix_len = sizeof(socket_prefix) - 1;
    size_t suffix_len = sizeof(socket_suffix) - 1;
    size_t account_len;
    bool reachable = false;
    bool absent = false;
    int dir_fd = -1;
    int lock_fd = -1;
    int rc = -1;

    ssh_runtime_pin_init(&current_pin);
    ssh_runtime_pin_init(&socket_pin);

    if (expected_live) {
        *expected_live = false;
    }
    if (present) {
        *present = false;
    }
    if (name && name_size > 0) {
        name[0] = '\0';
    }
    if (!name || name_size == 0 || !present ||
        ((expected == NULL) != (expected_live == NULL))) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH current-account inspection arguments");
        return -1;
    }
    if (expected &&
        (!validate_name(expected->name) || !expected->ssh_enabled ||
         expected->ssh_key_path[0] == '\0')) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account for SSH runtime liveness check");
        return -1;
    }

    if (ssh_manager_get_auth_sock_path(current, sizeof(current)) != 0) {
        return -1;
    }
    current_len = strlen(current);
    if (current_len <= sizeof(current_suffix) - 1 ||
        strcmp(current + current_len - (sizeof(current_suffix) - 1),
               current_suffix) != 0) {
        set_error(ERR_INVALID_PATH, "Invalid stable SSH socket path");
        return -1;
    }
    dir_len = current_len - (sizeof(current_suffix) - 1);
    memcpy(socket_dir, current, dir_len);
    socket_dir[dir_len] = '\0';

    dir_fd = open_isolated_agent_socket_dir(socket_dir, sizeof(socket_dir),
                                            false, &absent);
    if (dir_fd < 0 && absent) {
        return 0;
    }
    if (dir_fd < 0) {
        return -1;
    }

    /* Discovery never waits on a writer that may be parked at an interactive
     * prompt for minutes. On contention return an error so
     * accounts_detect_current serves the persisted saved-account fallback
     * instead of hanging every read-only command (AR-05 H2). Linux/FreeBSD
     * pins are descriptor-only; Darwin briefly creates a reserved hard-link
     * anchor inside this locked private directory and retires it before
     * returning, without changing either public runtime name. */
    lock_fd = try_lock_agent_dir(dir_fd);
    if (lock_fd < 0) {
        bool contended = errno == EWOULDBLOCK;
#if EAGAIN != EWOULDBLOCK
        contended = contended || errno == EAGAIN;
#endif
        if (contended) {
            set_error(ERR_FILE_IO,
                      "SSH agent directory is busy (another gitswitch is "
                      "mid-operation): %s", socket_dir);
        } else {
            set_system_error(ERR_FILE_IO,
                             "Failed to lock SSH agent directory: %s",
                             socket_dir);
        }
        close(dir_fd);
        return -1;
    }

    {
        int pin_rc = pin_ssh_runtime_entry_at(
            dir_fd, "current.sock", current, &current_pin);
        if (pin_rc > 0) {
            rc = 0;
            goto done;
        }
        if (pin_rc < 0) goto done;
    }
    if (!S_ISLNK(current_pin.identity.st_mode) ||
        current_pin.identity.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED,
                  "Stable SSH socket is not a self-owned symlink: %s", current);
        goto done;
    }
    if (current_pin.identity.st_size > 0 &&
        (uintmax_t)current_pin.identity.st_size >= (uintmax_t)sizeof(target)) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket target is too long: %s", current);
        goto done;
    }

    ssize_t target_len = read_locked_runtime_symlink_at(dir_fd, "current.sock",
                                                         target,
                                                         sizeof(target) - 1);
    int readlink_errno = errno;
    if (verify_ssh_runtime_pin_at(dir_fd, "current.sock", current,
                                  &current_pin) != 0) {
        goto done;
    }
    if (target_len < 0) {
        errno = readlink_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot read stable SSH socket: %s", current);
        goto done;
    }
    if ((size_t)target_len == sizeof(target) - 1) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket target is truncated: %s", current);
        goto done;
    }
    target[target_len] = '\0';

    if ((size_t)target_len <= dir_len + 1 ||
        strncmp(target, socket_dir, dir_len) != 0 ||
        target[dir_len] != '/') {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket target is outside its managed directory");
        goto done;
    }
    component = target + dir_len + 1;
    component_len = strlen(component);
    if (strchr(component, '/') != NULL || strchr(component, '\\') != NULL ||
        component_len <= prefix_len + suffix_len ||
        strncmp(component, socket_prefix, prefix_len) != 0 ||
        strcmp(component + component_len - suffix_len, socket_suffix) != 0) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket target has an invalid managed-socket shape");
        goto done;
    }

    account_len = component_len - prefix_len - suffix_len;
    if (account_len >= sizeof(account_name)) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket account name is too long");
        goto done;
    }
    memcpy(account_name, component + prefix_len, account_len);
    account_name[account_len] = '\0';
    if (!validate_name(account_name)) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket contains an invalid account name");
        goto done;
    }
    if ((size_t)snprintf(expected_path, sizeof(expected_path),
                         "%s/ssh-agent.%s.sock", socket_dir,
                         account_name) >= sizeof(expected_path) ||
        strcmp(target, expected_path) != 0) {
        set_error(ERR_INVALID_PATH,
                  "Stable SSH socket does not name the exact managed socket");
        goto done;
    }
    if (account_len + 1 > name_size) {
        set_error(ERR_INVALID_ARGS,
                  "Current SSH account output buffer is too small");
        goto done;
    }

    {
        int pin_rc = pin_ssh_runtime_entry_at(
            dir_fd, component, target, &socket_pin);
        if (pin_rc > 0 && expected) {
            rc = 0;
            goto done;
        }
        if (pin_rc > 0) {
            set_error(ERR_SSH_AGENT_SOCKET_INVALID,
                      "Current SSH agent socket is missing: %s", target);
            goto done;
        }
        if (pin_rc < 0) goto done;
    }
    if (!S_ISSOCK(socket_pin.identity.st_mode) ||
        socket_pin.identity.st_uid != getuid() ||
        (socket_pin.identity.st_mode & 0777) != 0600) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID,
                  "Current SSH agent socket is not a self-owned 0600 socket: %s",
                  target);
        goto done;
    }
    if (expected) {
        char key_path[MAX_PATH_LEN];

        /* The stable link, exact account target, agent identity listing, and
         * socket inode are all inspected while the manager lock is held. This
         * is the production counterpart of the reuse fast path: an empty,
         * wrong-key, or extra-key agent is not live for the saved account. */
        if (strcmp(account_name, expected->name) == 0) {
            if (expand_path(expected->ssh_key_path, key_path,
                            sizeof(key_path)) != 0) {
                goto done;
            }
            reachable = ssh_socket_has_key(dir_fd, component, key_path);
            if (!reachable) {
                /* Empty/wrong/extra identities are ordinary stale runtime,
                 * not an API failure. The caller will perform a real resume. */
                clear_error();
            }
        }
    } else {
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            probe_ssh_agent_socket(target, &reachable) != 0 ||
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            goto done;
        }
    }
    if (verify_ssh_runtime_pin_at(dir_fd, component, target,
                                  &socket_pin) != 0 ||
        verify_ssh_runtime_pin_at(dir_fd, "current.sock", current,
                                  &current_pin) != 0) {
        goto done;
    }
    if (!reachable && !expected) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID,
                  "Current SSH agent socket is not live: %s", target);
        goto done;
    }

    if (expected) {
        *expected_live = reachable;
    }

    memcpy(name, account_name, account_len + 1);
    *present = true;
    rc = 0;

done:
    if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) rc = -1;
    if (release_ssh_runtime_pin(dir_fd, &current_pin) != 0) rc = -1;
    unlock_agent_dir(lock_fd);
    close(dir_fd);
    return rc;
}

int ssh_manager_get_current_account(char *name, size_t name_size,
                                    bool *present) {
    return ssh_manager_inspect_current_account(name, name_size, present,
                                               NULL, NULL);
}

int ssh_manager_current_is_live_for_account(const account_t *account,
                                            bool *live) {
    char current_name[MAX_NAME_LEN];
    bool present = false;

    if (!live) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid output for SSH runtime liveness check");
        return -1;
    }
    *live = false;
    return ssh_manager_inspect_current_account(current_name,
                                               sizeof(current_name),
                                               &present, account, live);
}

/* Read a PID sidecar without following or accepting a swapped final
 * component. Missing is reported as 1; a validated PID as 0; every state in
 * which reset cannot prove what it is targeting is an error and leaves the
 * sidecar in place for inspection/retry. */
static int read_ssh_agent_pid_at(int dir_fd, const char *name,
                                 const char *display_path, pid_t *pid_out,
                                 ssh_runtime_pin_t *pin) {
    struct stat opened;
    struct stat entry;
    char buf[64];
    size_t used = 0;
    int fd;

    if (pin) ssh_runtime_pin_init(pin);

    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return 1;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH agent PID sidecar: %s",
                         display_path);
        return -1;
    }
    if (!S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        entry.st_nlink != 1 || (entry.st_mode & 022) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe SSH agent PID sidecar: %s", display_path);
        return -1;
    }

    fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot open SSH agent PID sidecar safely: %s",
                         display_path);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        !same_runtime_identity(&opened, &entry) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || (opened.st_mode & 022) != 0) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "SSH agent PID sidecar changed while opening: %s",
                  display_path);
        return -1;
    }
    while (used < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        set_system_error(ERR_FILE_IO, "Cannot read SSH agent PID sidecar: %s",
                         display_path);
        return -1;
    }
    if (used == sizeof(buf) - 1) {
        char extra;
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            close(fd);
            set_error(ERR_FILE_IO, "SSH agent PID sidecar is too large: %s",
                      display_path);
            return -1;
        }
    }
    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&opened, &entry)) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "SSH agent PID sidecar changed while being read: %s",
                  display_path);
        return -1;
    }
    buf[used] = '\0';

    errno = 0;
    char *end = NULL;
    long parsed = strtol(buf, &end, 10);
    while (end && isspace((unsigned char)*end)) {
        end++;
    }
    if (errno != 0 || end == buf || !end || *end != '\0' || parsed <= 1 ||
        (long)(pid_t)parsed != parsed) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "Invalid SSH agent PID sidecar; retained for retry: %s",
                  display_path);
        return -1;
    }
    *pid_out = (pid_t)parsed;
    if (pin) {
        pin->identity = opened;
        pin->fd = fd;
    } else {
        close(fd);
    }
    return 0;
}

static int write_all_fd(int fd, const char *buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, buf + off, size - off);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int resolve_uncertain_pid_publication(int dir_fd, const char *name,
                                             const struct stat *opened,
                                             const char *detail) {
    struct stat installed;
    bool exact_commit = false;
    int sync_rc;

    if (fstatat(dir_fd, name, &installed, AT_SYMLINK_NOFOLLOW) == 0) {
        exact_commit = same_runtime_identity(opened, &installed) &&
                       S_ISREG(installed.st_mode) &&
                       installed.st_uid == getuid() &&
                       installed.st_nlink == 1;
    }
    /* renameat already crossed the namespace commit point. Synchronize the
     * exact installed identity, a replacement, or observed absence; never
     * issue a compensating unlink against state whose ownership is uncertain. */
    sync_rc = sync_ssh_runtime_dir(
        dir_fd, "uncertain PID sidecar post-rename resolution");
    set_error(
        ERR_FILE_IO,
        "SSH PID sidecar publication is uncertain; %s; %s; directory state %s",
        detail && *detail ? detail : "post-rename identity capture failed",
        exact_commit ? "the complete committed sidecar was retained"
                     : "a replacement or absence was preserved",
        sync_rc == 0 ? "was synchronized" : "also requires retry");
    return -1;
}

static int write_ssh_agent_pid_at(int dir_fd, const char *name, pid_t pid) {
    char tmp[MAX_NAME_LEN + 64];
    char content[32];
    struct stat opened;
    struct stat fd_now;
    struct stat entry;
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;
    int len;
    int fd = -1;
    int rc = -1;
    bool have_opened_identity = false;
    bool renamed = false;

    len = snprintf(content, sizeof(content), "%ld\n", (long)pid);
    if (len <= 0 || (size_t)len >= sizeof(content) ||
        (size_t)snprintf(tmp, sizeof(tmp), ".%s.tmp.%d", name,
                         (int)getpid()) >= sizeof(tmp)) {
        set_error(ERR_INVALID_PATH, "SSH PID sidecar name is too long");
        return -1;
    }
    (void)unlinkat(dir_fd, tmp, 0);
    fd = openat(dir_fd, tmp, flags, 0600);
    if (fd < 0 || fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_uid != getuid() || opened.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600) {
        set_system_error(ERR_FILE_IO, "Failed to open SSH agent PID sidecar safely");
        goto out;
    }
    have_opened_identity = true;
    if (write_all_fd(fd, content, (size_t)len) != 0 || fsync(fd) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to write SSH agent PID sidecar");
        goto out;
    }

    /* Test seam lands in the exact race window: the opened object is durable,
     * but its deterministic pathname has not yet been committed. */
    if (g_pid_commit_hook && g_pid_commit_hook(dir_fd, tmp) != 0) {
        set_error(ERR_FILE_IO, "SSH PID sidecar commit hook failed");
        goto out;
    }

    /* Keep the descriptor open and prove immediately before renameat that the
     * temp pathname still names that same inode. An attacker can otherwise
     * unlink the deterministic temp and substitute a file/symlink which our
     * rename would faithfully install as the trusted PID record. */
    if (fstat(fd, &fd_now) != 0 ||
        fstatat(dir_fd, tmp, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&opened, &fd_now) ||
        !same_runtime_identity(&opened, &entry) ||
        !S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        fd_now.st_nlink != 1 || entry.st_nlink != 1) {
        set_error(ERR_FILE_IO,
                  "SSH agent PID temp changed before atomic commit");
        goto out;
    }
    if (renameat(dir_fd, tmp, dir_fd, name) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to install SSH agent PID sidecar atomically");
        goto out;
    }
    renamed = true;
    if (g_pid_postrename_hook &&
        g_pid_postrename_hook(dir_fd, name) != 0) {
        (void)resolve_uncertain_pid_publication(
            dir_fd, name, &opened,
            "post-rename verification hook failed");
        goto out;
    }
    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&opened, &entry) || entry.st_nlink != 1) {
        (void)resolve_uncertain_pid_publication(
            dir_fd, name, &opened,
            "post-rename identity verification failed");
        goto out;
    }
    if (sync_ssh_runtime_dir(dir_fd, "PID sidecar publication") != 0) {
        /* renameat may already be durable despite fsync failure. Retain the
         * fully written, fd-synced sidecar as explicit recovery evidence; do
         * not issue an unsynced compensating unlink and pretend no commit
         * happened. The caller fails and either retains or reaps the agent. */
        set_error(ERR_FILE_IO,
                  "SSH PID sidecar namespace durability is uncertain; complete sidecar retained for retry");
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO, "Failed to close SSH agent PID sidecar");
        goto out;
    }
    fd = -1;
    rc = 0;

out:
    if (fd >= 0) close(fd);
    if (rc != 0 && have_opened_identity &&
        fstatat(dir_fd, tmp, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_runtime_identity(&opened, &entry)) {
        (void)unlinkat(dir_fd, tmp, 0);
    }
    if (rc != 0 && have_opened_identity && !renamed &&
        fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_runtime_identity(&opened, &entry)) {
        (void)unlinkat(dir_fd, name, 0);
    }
    return rc;
}

int ssh_manager_test_write_pid_sidecar(int dir_fd, const char *name,
                                       pid_t pid) {
    return write_ssh_agent_pid_at(dir_fd, name, pid);
}

/* Re-prove an entry immediately before removing its name. POSIX has no
 * unlink-by-inode operation, so this is the narrowest fail-closed boundary:
 * the caller's captured identity must still own the name after every
 * durability wait and deterministic race hook. A changed name is preserved
 * and reported separately so callers can restore it to a public location. */
static int unlink_ssh_runtime_identity_at(
    int dir_fd, const char *name, const struct stat *expected,
    bool missing_ok, const char *description,
    ssh_quarantine_hook_fn predelete_hook, struct stat *observed_out) {
    struct stat observed;

    if (predelete_hook != NULL) {
        int hook_rc = (*predelete_hook)(dir_fd, name);
        if (hook_rc != 0) {
            set_error(
                ERR_FILE_IO,
                "SSH cleanup hook failed before identity-bound removal: %s",
                name);
            return -1;
        }
    }
    if (fstatat(dir_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0) {
        if (missing_ok && errno == ENOENT) {
            return sync_ssh_runtime_dir(
                dir_fd, description ? description
                                    : "identity-bound artifact absence");
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot identify SSH cleanup target: %s", name);
        return -1;
    }
    if (!expected || !same_runtime_identity(expected, &observed)) {
        if (observed_out) *observed_out = observed;
        errno = ESTALE;
        set_error(ERR_FILE_IO,
                  "SSH cleanup target identity changed; replacement preserved: %s",
                  name);
        return 1;
    }
    return unlink_ssh_runtime_entry(
        dir_fd, name, missing_ok,
        description ? description : "identity-bound artifact removal");
}

/* Final retirement happens only after the quarantine name is stable. Compare
 * the full quiescent revision after the deterministic hook, and also prove
 * that the transaction still holds the originally pinned object. */
static int unlink_ssh_runtime_revision_at(
    int dir_fd, const char *name, const struct stat *expected,
    const ssh_runtime_pin_t *pin, const char *witness_name,
    const char *description,
    ssh_quarantine_hook_fn predelete_hook, struct stat *observed_out) {
    struct stat held;
    struct stat observed;
    struct stat witness;
    bool held_matches = true;
    bool witness_matches = true;

    if (predelete_hook && predelete_hook(dir_fd, name) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH cleanup hook failed before revision-bound removal: %s",
                  name);
        return -1;
    }
    if (fstatat(dir_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot identify SSH cleanup target: %s", name);
        return -1;
    }
    if (pin &&
        (stat_ssh_runtime_pin(pin, dir_fd, &held) != 0 ||
         !same_runtime_identity(&pin->identity, &held) ||
         !same_runtime_identity(&pin->identity, &observed) ||
         !same_runtime_revision(expected, &held))) {
        held_matches = false;
    }
    if (witness_name &&
        (fstatat(dir_fd, witness_name, &witness, AT_SYMLINK_NOFOLLOW) != 0 ||
         !same_runtime_identity(expected, &witness) ||
         !same_runtime_identity(&witness, &observed) ||
         !same_runtime_revision(expected, &witness))) {
        witness_matches = false;
    }
    if (!expected || (!pin && !witness_name) || !held_matches ||
        !witness_matches ||
        !same_runtime_revision(expected, &observed)) {
        if (observed_out) *observed_out = observed;
        errno = ESTALE;
        set_error(ERR_FILE_IO,
                  "SSH cleanup target revision changed; replacement preserved: %s",
                  name);
        return 1;
    }
#if defined(__FreeBSD__)
    if (pin && pin->fd >= 0) {
        if (funlinkat(dir_fd, name, pin->fd, 0) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot remove descriptor-pinned SSH cleanup target: %s",
                             name);
            return -1;
        }
        return sync_ssh_runtime_dir(
            dir_fd,
            description ? description : "revision-bound artifact removal");
    }
#endif
    return unlink_ssh_runtime_entry(
        dir_fd, name, false,
        description ? description : "revision-bound artifact removal");
}

/* Atomically move a reset target out of its public name without overwriting a
 * pre-existing quarantine. Native no-replace rename is the race-free path;
 * the locked hard-link fallback mirrors current.sock's portable protocol and
 * re-proves both names before removing the public one. */
static int quarantine_ssh_reset_entry(
    int dir_fd, const char *name, const char *quarantine,
    const struct stat *expected) {
    struct stat source;
    struct stat captured;

    if (!g_force_portable_quarantine) {
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, dir_fd, name, dir_fd, quarantine,
                RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP) {
        return -1;
    }
#elif (defined(__APPLE__) || defined(__FreeBSD__)) && defined(RENAME_EXCL)
    if (renameatx_np(dir_fd, name, dir_fd, quarantine, RENAME_EXCL) == 0) {
        return 0;
    }
    if (errno != ENOTSUP && errno != EOPNOTSUPP && errno != EINVAL) {
        return -1;
    }
#endif
    }

    if (linkat(dir_fd, name, dir_fd, quarantine, 0) != 0) return -1;
    if (fstatat(dir_fd, name, &source, AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(dir_fd, quarantine, &captured, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(expected, &source) ||
        !same_runtime_identity(expected, &captured) ||
        !same_runtime_identity(&source, &captured)) {
        int saved_errno = errno == 0 ? ESTALE : errno;
        (void)unlink_ssh_runtime_identity_at(
            dir_fd, quarantine, expected, true,
            "failed portable reset quarantine rollback", NULL, NULL);
        errno = saved_errno;
        return -1;
    }
    if (sync_ssh_runtime_dir(
            dir_fd, "portable reset quarantine publication") != 0) {
        return -1; /* both names retain the exact same inode */
    }
    {
        int remove_rc = unlink_ssh_runtime_identity_at(
            dir_fd, name, expected, false,
            "portable reset public-name removal", NULL, NULL);
        if (remove_rc > 0) errno = ESTALE;
        return remove_rc == 0 ? 0 : -1;
    }
}

static int restore_ssh_reset_quarantine(
    int dir_fd, const char *name, const char *quarantine,
    const struct stat *identity) {
    struct stat restored;
    struct stat retirement_identity;
    int retirement_rc;

    if (!g_force_portable_quarantine) {
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, dir_fd, quarantine, dir_fd, name,
                RENAME_NOREPLACE) == 0) {
        return sync_ssh_runtime_dir(dir_fd,
                                    "reset quarantine restoration");
    }
    if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP) {
        return -1;
    }
#elif (defined(__APPLE__) || defined(__FreeBSD__)) && defined(RENAME_EXCL)
    if (renameatx_np(dir_fd, quarantine, dir_fd, name, RENAME_EXCL) == 0) {
        return sync_ssh_runtime_dir(dir_fd,
                                    "reset quarantine restoration");
    }
    if (errno != ENOTSUP && errno != EOPNOTSUPP && errno != EINVAL) {
        return -1;
    }
#endif
    }

    if (linkat(dir_fd, quarantine, dir_fd, name, 0) != 0 ||
        fstatat(dir_fd, name, &restored, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(identity, &restored) ||
        sync_ssh_runtime_dir(dir_fd,
                            "portable reset quarantine restoration") != 0) {
        return -1;
    }
    if (fstatat(dir_fd, quarantine, &retirement_identity,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    retirement_rc = unlink_ssh_runtime_revision_at(
        dir_fd, quarantine, &retirement_identity, NULL, name,
        "portable reset quarantine retirement", g_reset_retire_hook, NULL);
    return retirement_rc == 0 ? 0 : -1;
}

/* Remove exactly the inode classified by the reset transaction. A raced
 * replacement is moved only long enough to identify it, then restored to its
 * public name; it is never mistaken for the artifact that earned deletion
 * authority. */
static int unlink_ssh_reset_path_at(int dir_fd, const char *name,
                                    const char *display_path,
                                    const char *description,
                                    const ssh_runtime_pin_t *pin,
                                    bool expected_present) {
    static unsigned long sequence;
    char quarantine[96];
    struct stat current;
    struct stat captured;
    struct stat published;
    struct stat replacement;
    int written;
    int remove_rc;

    if (!expected_present) {
        if (fstatat(dir_fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0) {
            set_error(ERR_FILE_IO,
                      "SSH reset artifact appeared during cleanup; replacement preserved: %s",
                      display_path ? display_path : name);
            return -1;
        }
        if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot confirm absent SSH reset artifact: %s",
                             display_path ? display_path : name);
            return -1;
        }
        return sync_ssh_runtime_dir(
            dir_fd, description ? description : "reset artifact absence");
    }
    if (!pin) {
        set_error(ERR_INVALID_ARGS,
                  "Missing SSH reset artifact identity for cleanup");
        return -1;
    }
    if (verify_ssh_runtime_pin_at(dir_fd, name, display_path, pin) != 0) {
        return -1;
    }
    written = snprintf(quarantine, sizeof(quarantine),
                       ".reset.cleanup.%ld.%lu", (long)getpid(), sequence++);
    if (written < 0 || (size_t)written >= sizeof(quarantine)) {
        set_error(ERR_INVALID_PATH, "SSH reset quarantine name is too long");
        return -1;
    }
    if (quarantine_ssh_reset_entry(dir_fd, name, quarantine,
                                   &pin->identity) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot quarantine SSH reset artifact: %s",
                         display_path ? display_path : name);
        return -1;
    }
    if (fstatat(dir_fd, quarantine, &captured, AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot identify quarantined SSH reset artifact: %s",
                         display_path ? display_path : name);
        return -1;
    }
    if (!same_runtime_identity(&pin->identity, &captured)) {
        int restore_rc = restore_ssh_reset_quarantine(
            dir_fd, name, quarantine, &captured);
        set_error(ERR_FILE_IO,
                  "SSH reset artifact changed before cleanup; replacement %s: %s",
                  restore_rc == 0 ? "preserved" : "retained in quarantine",
                  display_path ? display_path : name);
        return -1;
    }
    if (sync_ssh_runtime_dir(dir_fd,
                            "reset artifact quarantine publication") != 0) {
        char detail[sizeof(g_last_error.message)];
        int restore_rc;

        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        restore_rc = restore_ssh_reset_quarantine(
            dir_fd, name, quarantine, &captured);
        set_error(ERR_FILE_IO, "%s; artifact %s: %s", detail,
                  restore_rc == 0 ? "restored" : "retained in quarantine",
                  display_path ? display_path : name);
        return -1;
    }
    /* Directory synchronization can finalize BSD metadata. Capture the
     * quiescent revision only after publication is durable, immediately
     * before the retirement hook whose mutation it must detect. */
    if (fstatat(dir_fd, quarantine, &published,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&captured, &published) ||
        !same_runtime_identity(&pin->identity, &published)) {
        int restore_rc = restore_ssh_reset_quarantine(
            dir_fd, name, quarantine, &captured);
        set_error(ERR_FILE_IO,
                  "SSH reset quarantine changed after publication; artifact %s: %s",
                  restore_rc == 0 ? "restored" : "retained in quarantine",
                  display_path ? display_path : name);
        return -1;
    }
    captured = published;
    remove_rc = unlink_ssh_runtime_revision_at(
        dir_fd, quarantine, &captured, pin, NULL,
        description ? description : "owned reset artifact cleanup",
        g_reset_retire_hook, &replacement);
    if (remove_rc != 0) {
        char detail[sizeof(g_last_error.message)];
        int restore_rc;
        const struct stat *restore_identity =
            remove_rc > 0 ? &replacement : &captured;

        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        restore_rc = restore_ssh_reset_quarantine(
            dir_fd, name, quarantine, restore_identity);
        set_error(ERR_FILE_IO, "%s; artifact %s: %s", detail,
                  restore_rc == 0 ? "restored" : "retained in quarantine",
                  display_path ? display_path : name);
    }
    return remove_rc == 0 ? 0 : -1;
}

/* Inspect current.sock without following it. Missing is success with
 * matches=false; a non-symlink or unreadable/truncated link is a cleanup
 * failure because reset cannot truthfully claim that the stable entry point
 * is in a known state. */
static int ssh_current_matches_socket_at(int dir_fd, const char *current,
                                         const char *socket, bool *matches,
                                         ssh_current_link_identity_t *matched_identity) {
    ssh_current_link_identity_t observed;
    struct stat before;

    *matches = false;
    if (fstatat(dir_fd, "current.sock", &before, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect stable SSH socket: %s", current);
        return -1;
    }
    if (capture_runtime_symlink_at(dir_fd, "current.sock", NULL, current,
                                   &observed) != 0) {
        return -1;
    }
    *matches = strcmp(observed.target, socket) == 0;
    if (*matches && matched_identity) *matched_identity = observed;
    return 0;
}

static int ssh_reset_incomplete(void) {
    char detail[sizeof(g_last_error.message)];
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    if (detail[0]) {
        set_error(ERR_FILE_IO,
                  "SSH reset incomplete; retained state for retry: %s", detail);
    } else {
        set_error(ERR_FILE_IO,
                  "SSH reset incomplete; retained remaining state for retry");
    }
    return -1;
}

/* Tear down isolated SSH agents: one account, or all when account is NULL.
 * Kills the agent(s) by recorded PID and removes their sockets/sidecars. Every
 * lock, identity/reap, and relevant unlink failure is fatal to the caller;
 * missing owned state remains idempotent success. */
int ssh_manager_reset(const char *account) {
    char socket_dir[MAX_PATH_LEN];
    bool absent = false;
    int dir_fd = -1;

    /* NULL alone selects reset-all. Any non-NULL selector reaches filesystem
     * path construction, so reject empty and otherwise invalid account names
     * before opening or locking the runtime namespace. */
    if (account && !validate_name(account)) {
        set_error(ERR_INVALID_ARGS, "Invalid account name for reset");
        return -1;
    }

    dir_fd = open_isolated_agent_socket_dir(socket_dir, sizeof(socket_dir),
                                            false, &absent);
    if (dir_fd < 0 && absent) {
        return 0;
    }
    if (dir_fd < 0) {
        return -1;
    }

    /* A validated existing base must never be mutated unlocked. A failed lock
     * is actionable retained state, not evidence that the base disappeared. */
    int lock_fd = lock_agent_dir(dir_fd);
    if (lock_fd < 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO, "Failed to lock SSH agent directory: %s", socket_dir);
        return -1;
    }
    if (reconcile_ssh_runtime_pins(dir_fd, socket_dir) != 0) {
        unlock_agent_dir(lock_fd);
        close(dir_fd);
        return ssh_reset_incomplete();
    }

    if (!account) {
        int all_rc = kill_orphaned_gitswitch_agents(dir_fd, socket_dir, NULL);
        unlock_agent_dir(lock_fd);
        close(dir_fd);
        return all_rc == 0 ? 0 : ssh_reset_incomplete();
    }

    char pid_path[MAX_PATH_LEN];
    char sock_path[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    char pid_name[MAX_NAME_LEN + 32];
    char sock_name[MAX_NAME_LEN + 32];
    bool current_matches = false;
    ssh_current_link_identity_t current_identity;
    bool failed = false;
    bool can_remove_runtime = true;
    bool socket_present = false;
    ssh_runtime_pin_t pid_pin;
    ssh_runtime_pin_t socket_pin;
    pid_t pid = -1;

    ssh_runtime_pin_init(&pid_pin);
    ssh_runtime_pin_init(&socket_pin);

    if (reconcile_current_socket_quarantines(dir_fd, socket_dir) != 0) {
        failed = true;
    }

    if ((size_t)snprintf(sock_path, sizeof(sock_path),
                         "%s/ssh-agent.%s.sock", socket_dir, account) >= sizeof(sock_path) ||
        (size_t)snprintf(pid_path, sizeof(pid_path),
                         "%s/ssh-agent.%s.pid", socket_dir, account) >= sizeof(pid_path) ||
        (size_t)snprintf(current, sizeof(current),
                         "%s/current.sock", socket_dir) >= sizeof(current) ||
        (size_t)snprintf(sock_name, sizeof(sock_name),
                         "ssh-agent.%s.sock", account) >= sizeof(sock_name) ||
        (size_t)snprintf(pid_name, sizeof(pid_name),
                         "ssh-agent.%s.pid", account) >= sizeof(pid_name)) {
        set_error(ERR_INVALID_PATH, "SSH reset artifact path too long");
        unlock_agent_dir(lock_fd);
        close(dir_fd);
        return -1;
    }

    int socket_rc = pin_ssh_runtime_entry_at(
        dir_fd, sock_name, sock_path, &socket_pin);
    if (socket_rc == 0) {
        socket_present = true;
    } else if (socket_rc < 0) {
        failed = true;
        can_remove_runtime = false;
    }

    int pid_rc = read_ssh_agent_pid_at(dir_fd, pid_name, pid_path, &pid,
                                       &pid_pin);
    if (pid_rc < 0) {
        failed = true;
        can_remove_runtime = false;
    } else if (pid_rc == 0) {
        ssh_process_outcome_t reap_outcome;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        reap_outcome = can_remove_runtime
                           ? g_ssh_reap(pid, sock_path, dir_fd)
                           : SSH_PROCESS_INDETERMINATE;
        if (can_remove_runtime &&
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        if (!ssh_reap_allows_cleanup(reap_outcome)) {
            if (can_remove_runtime) {
                set_error(ERR_SSH_AGENT_FAILED,
                          "SSH agent PID %ld reap outcome %s; retained for retry",
                          (long)pid, ssh_process_outcome_name(reap_outcome));
            }
            failed = true;
            can_remove_runtime = false;
        } else if (can_remove_runtime &&
                   unlink_ssh_reset_path_at(dir_fd, pid_name, pid_path,
                                            "SSH agent PID sidecar",
                                            &pid_pin,
                                            true) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        if (can_remove_runtime && socket_present) {
            struct stat after_reap;

            /* A real ssh-agent removes its listening socket while exiting.
             * Refresh only the presence bit after the cleanup-authorizing
             * reap: if any entry remains, keep the original identity so the
             * quarantine path detects and preserves a raced replacement. If
             * it is absent, unlink_ssh_reset_path_at performs a second
             * descriptor-relative absence proof before reporting success. */
            if (fstatat(dir_fd, sock_name, &after_reap,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT) {
                    socket_present = false;
                } else {
                    set_system_error(
                        ERR_FILE_IO,
                        "Cannot refresh SSH agent socket after reap: %s",
                        sock_path);
                    failed = true;
                    can_remove_runtime = false;
                }
            }
        }
    }

    /* A missing sidecar is idempotent only when the socket is absent or
     * provably stale. Apply the same proof after a recorded PID was classified
     * GONE/UNRELATED: a stale sidecar can coexist with a different live agent
     * on the managed socket, so a cleanup-authorizing process outcome alone
     * is insufficient authority to unlink the runtime entry point. */
    if (can_remove_runtime) {
        bool reachable = false;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            probe_ssh_agent_socket(sock_path, &reachable) != 0 ||
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            can_remove_runtime = false;
        } else if (reachable) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "Reachable SSH agent socket has no safely matched PID; "
                      "retained for retry: %s", sock_path);
            failed = true;
            can_remove_runtime = false;
        }
    }
    if (can_remove_runtime && pid_rc > 0) {
        struct stat appeared;
        if (fstatat(dir_fd, pid_name, &appeared,
                    AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
            set_error(ERR_FILE_IO,
                      "SSH PID sidecar appeared during reset; replacement retained: %s",
                      pid_path);
            failed = true;
            can_remove_runtime = false;
        }
    }

    if (can_remove_runtime) {
        /* Inspect the stable link before removing its target, then delete the
         * target first. If socket removal fails, retain current.sock so the
         * still-live/inspectable runtime entry point is not destroyed. */
        if (ssh_current_matches_socket_at(dir_fd, current, sock_path,
                                          &current_matches,
                                          &current_identity) != 0) {
            failed = true;
        }
        if (unlink_ssh_reset_path_at(dir_fd, sock_name, sock_path,
                                     "SSH agent socket", &socket_pin,
                                     socket_present) != 0) {
            failed = true;
        } else if (current_matches &&
                   remove_current_socket_link_if_unchanged(
                       dir_fd, &current_identity) != 0) {
            failed = true;
        }
    }

    /* A retry after an earlier unlink+fsync failure may observe no artifacts
     * at all. It becomes success only after this fresh durability barrier
     * confirms the now-empty (or already-clean) namespace. */
    if (!failed &&
        sync_ssh_runtime_dir(dir_fd, "single-account reset confirmation") != 0) {
        failed = true;
    }

    if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
    if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) failed = true;
    unlock_agent_dir(lock_fd);
    close(dir_fd);
    return failed ? ssh_reset_incomplete() : 0;
}

/* Kill orphaned gitswitch ssh-agents from previous runs and remove stale
 * sockets. Shell-free: agents are reaped precisely by the PID recorded in their
 * sidecar (ssh-agent.<name>.pid) rather than a pkill pattern match, and stale
 * sockets are unlinked via readdir. Only operates inside our own 0700 dir.
 * If keep_account is non-NULL, that account's live agent + sidecar are left
 * intact (used when reusing it), while every other account is still reaped. */
static int kill_orphaned_gitswitch_agents(int dir_fd, const char *socket_dir,
                                          const char *keep_account) {
    char keep_pid[MAX_NAME_LEN + 16];
    char keep_sock[MAX_NAME_LEN + 16];
    DIR *d;
    struct dirent *ent;
    bool failed = false;

    keep_pid[0] = keep_sock[0] = '\0';
    if (keep_account && *keep_account) {
        snprintf(keep_pid, sizeof(keep_pid), "ssh-agent.%s.pid", keep_account);
        snprintf(keep_sock, sizeof(keep_sock), "ssh-agent.%s.sock", keep_account);
    }

    if (dir_fd < 0 || !socket_dir) {
        set_error(ERR_INVALID_ARGS, "Invalid pinned SSH agent directory");
        return -1;
    }

    if (reconcile_current_socket_quarantines(dir_fd, socket_dir) != 0) {
        failed = true;
    }

    int scan_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    scan_flags |= O_NOFOLLOW;
#endif
    int scan_fd = openat(dir_fd, ".", scan_flags);
    d = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!d) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO, "Cannot enumerate SSH agent directory: %s", socket_dir);
        return -1;
    }

    /* Pass 1: process sidecars first. A sidecar is removed only after its PID
     * is safely classified/reaped. Failed or malformed sidecars remain, which
     * lets pass 2 retain the corresponding socket as retry evidence. */
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) {
            if (errno != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed while enumerating SSH PID sidecars: %s",
                                 socket_dir);
                failed = true;
            }
            break;
        }
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        char full[MAX_PATH_LEN];

        if (strncmp(name, "ssh-agent.", 10) != 0 ||
            nlen <= 4 || strcmp(name + nlen - 4, ".pid") != 0) {
            continue;
        }
        if (keep_pid[0] && strcmp(name, keep_pid) == 0) {
            continue;
        }
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", socket_dir, name) >= sizeof(full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup artifact path too long: %s", name);
            failed = true;
            continue;
        }

        /* The socket this agent was started on (ssh-agent.<name>.sock), used
         * to confirm the recorded PID is genuinely our agent. */
        char sock_full[MAX_PATH_LEN];
        ssh_runtime_pin_t pid_pin;
        int sw = snprintf(sock_full, sizeof(sock_full), "%s/%.*ssock",
                          socket_dir, (int)(nlen - 3), name);
        ssh_runtime_pin_init(&pid_pin);
        if (sw <= 0 || (size_t)sw >= sizeof(sock_full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup socket path too long: %s", name);
            failed = true;
            continue;
        }

        pid_t pid = -1;
        int pid_rc = read_ssh_agent_pid_at(dir_fd, name, full, &pid,
                                           &pid_pin);
        if (pid_rc != 0) {
            if (pid_rc > 0) {
                set_error(ERR_FILE_IO,
                          "SSH PID sidecar disappeared during cleanup: %s", full);
            }
            failed = true;
            continue;
        }
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        ssh_process_outcome_t reap_outcome = g_ssh_reap(
            pid, sock_full, dir_fd);
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        if (!ssh_reap_allows_cleanup(reap_outcome)) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "SSH agent PID %ld reap outcome %s; retained for retry",
                      (long)pid, ssh_process_outcome_name(reap_outcome));
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        log_debug("Reaped orphaned ssh-agent PID %ld", (long)pid);
        if (unlink_ssh_reset_path_at(dir_fd, name, full,
                                     "SSH agent PID sidecar", &pid_pin,
                                     true) != 0) {
            failed = true;
        }
        if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
    }
    if (closedir(d) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to close SSH agent directory: %s", socket_dir);
        failed = true;
    }

    /* Pass 2: remove sockets and other managed artifacts only when no sidecar
     * remains for that socket. This preserves the full retry tuple when an
     * agent could not be confirmed dead. current.sock is handled last. */
    scan_fd = openat(dir_fd, ".", scan_flags);
    d = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!d) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO, "Cannot re-enumerate SSH agent directory: %s", socket_dir);
        return -1;
    }
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) {
            if (errno != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed while enumerating SSH agent sockets: %s",
                                 socket_dir);
                failed = true;
            }
            break;
        }
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        char full[MAX_PATH_LEN];
        ssh_runtime_pin_t artifact_pin;

        ssh_runtime_pin_init(&artifact_pin);

        if (strncmp(name, "ssh-agent.", 10) != 0 ||
            (nlen > 4 && strcmp(name + nlen - 4, ".pid") == 0)) {
            continue;
        }
        if (keep_sock[0] && strcmp(name, keep_sock) == 0) {
            continue;
        }
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", socket_dir, name) >= sizeof(full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup artifact path too long: %s", name);
            failed = true;
            continue;
        }
        if (pin_ssh_runtime_entry_at(dir_fd, name, full,
                                     &artifact_pin) != 0) {
            failed = true;
            continue;
        }

        if (nlen > 5 && strcmp(name + nlen - 5, ".sock") == 0) {
            char pid_full[MAX_PATH_LEN];
            int pw = snprintf(pid_full, sizeof(pid_full), "%s/%.*spid",
                              socket_dir, (int)(nlen - 4), name);
            struct stat pst;
            if (pw <= 0 || (size_t)pw >= sizeof(pid_full)) {
                set_error(ERR_INVALID_PATH, "SSH cleanup PID path too long: %s", name);
                failed = true;
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }
            char pid_name[MAX_NAME_LEN + 16];
            int pn = snprintf(pid_name, sizeof(pid_name), "%.*spid",
                              (int)(nlen - 4), name);
            if (pn <= 0 || (size_t)pn >= sizeof(pid_name)) {
                set_error(ERR_INVALID_PATH,
                          "SSH cleanup PID name too long: %s", name);
                failed = true;
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }
            if (fstatat(dir_fd, pid_name, &pst, AT_SYMLINK_NOFOLLOW) == 0) {
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue; /* survivor/invalid sidecar: retain its socket */
            }
            if (errno != ENOENT) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot inspect SSH cleanup sidecar: %s", pid_full);
                failed = true;
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }

            /* No sidecar: remove only a socket proven dead/unreachable. A
             * reachable listener cannot be reaped safely without its PID, and
             * an indeterminate probe is equally non-destructive. */
            bool reachable = false;
            if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
                probe_ssh_agent_socket(full, &reachable) != 0 ||
                verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
                failed = true;
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }
            if (reachable) {
                set_error(ERR_SSH_AGENT_FAILED,
                          "Live SSH agent socket has no PID sidecar; retained for retry: %s",
                          full);
                failed = true;
                if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }
        }
        if (unlink_ssh_reset_path_at(dir_fd, name, full,
                                     "SSH agent artifact",
                                     &artifact_pin,
                                     true) != 0) {
            failed = true;
        }
        if (release_ssh_runtime_pin(dir_fd, &artifact_pin) != 0) failed = true;
    }
    if (closedir(d) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to close SSH agent directory: %s", socket_dir);
        failed = true;
    }

    /* Remove current.sock only when it does not still name a retained live
     * artifact. The reuse path's kept account remains untouched; an all-reset
     * failure likewise keeps a usable stable entry point for the retry. */
    char current[MAX_PATH_LEN];
    if ((size_t)snprintf(current, sizeof(current), "%s/current.sock", socket_dir) >= sizeof(current)) {
        set_error(ERR_INVALID_PATH, "Stable SSH socket path too long during cleanup");
        return -1;
    }
    struct stat current_entry;
    if (fstatat(dir_fd, "current.sock", &current_entry,
                AT_SYMLINK_NOFOLLOW) == 0) {
        ssh_current_link_identity_t current_identity;
        char component[MAX_NAME_LEN + 32];
        bool retain_current = false;
        if (capture_runtime_symlink_at(dir_fd, "current.sock", NULL, current,
                                       &current_identity) != 0) {
            failed = true;
            retain_current = true;
        } else if (!target_is_exact_managed_socket(
                       socket_dir, current_identity.target, component,
                       sizeof(component))) {
            set_error(ERR_FILE_IO,
                      "Stable SSH socket has a foreign target; replacement preserved: %s",
                      current_identity.target);
            failed = true;
            retain_current = true;
        } else if (keep_sock[0] && strcmp(component, keep_sock) == 0) {
            retain_current = true;
        } else if (failed) {
            struct stat target_entry;
            if (fstatat(dir_fd, component, &target_entry,
                        AT_SYMLINK_NOFOLLOW) == 0) {
                retain_current = true;
            }
        }
        if (!retain_current &&
            remove_current_socket_link_if_unchanged(dir_fd,
                                                     &current_identity) != 0) {
            failed = true;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_FILE_IO, "Cannot inspect stable SSH socket: %s", current);
        failed = true;
    }

    /* This also covers the otherwise-empty runtime directory and an already
     * absent current.sock on a retry after an uncertain teardown commit. */
    if (!failed &&
        sync_ssh_runtime_dir(dir_fd, "all-agent reset confirmation") != 0) {
        failed = true;
    }

    return failed ? -1 : 0;
}
