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
#include <sys/time.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <inttypes.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/memfd.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif
#ifdef __FreeBSD__
#include <sys/ucred.h>
#include <sys/user.h>
#endif

#define GITSWITCH_INTERNAL_API
#include "ssh_manager_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "error.h"
#include "utils.h"
#include "runner_internal.h"
#include "display.h"
#include "signals.h"
#include "toml_parser.h"

/* Private keys are normally a few KiB. Bound the descriptor-backed generation
 * retained across validation/fingerprint/load so a planted giant regular file
 * cannot turn account switching into an unbounded secret-bearing allocation. */
#define SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)

/* OpenSSH's text formatter can expand one stored comment byte into several
 * rendered bytes. Capture one complete fingerprint listing in a single child
 * execution, bounded from the admitted input size, instead of retrying across
 * extra scheduling points or accepting a prefix with an unknowable suffix. */
#define SSH_KEYGEN_FINGERPRINT_CAPTURE_MIN_BYTES (8U * 1024U)
#define SSH_KEYGEN_FINGERPRINT_CAPTURE_OVERHEAD_BYTES (4U * 1024U)
#define SSH_KEYGEN_FINGERPRINT_CAPTURE_MAX_BYTES \
    (4U * SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES + \
     SSH_KEYGEN_FINGERPRINT_CAPTURE_OVERHEAD_BYTES)

typedef struct {
    char *data;
    size_t length;
    int fd;
    bool fd_open;
    bool source_detached;
    bool fingerprint_valid;
    char fingerprint[256];
    struct stat identity;
} ssh_key_snapshot_t;

struct ssh_key_admission {
    char expanded_key_path[MAX_PATH_LEN];
    ssh_key_snapshot_t snapshot;
    bool named_generation_verified;
};

typedef enum {
    SSH_KEY_GENERATION_ERROR = -1,
    SSH_KEY_GENERATION_MISMATCH = 0,
    SSH_KEY_GENERATION_MATCH = 1
} ssh_key_generation_match_t;

/* Internal helper functions */
/* merge_stderr is int, not bool: the parameter anchors va_start, and C11
 * makes va_start on a type that undergoes default argument promotion
 * (bool -> int) undefined behavior — clang rejects it under -Wvarargs. */
static int ssh_run(char *output, size_t output_size, int merge_stderr, ...);
static int ssh_add_key_pinned(int dir_fd, const char *socket_arg,
                              const char *key_path,
                              const ssh_key_snapshot_t *snapshot);
static int ssh_start_isolated_agent_with_key(
    ssh_config_t *ssh_config, const account_t *account,
    ssh_key_snapshot_t *snapshot);
static int ssh_key_snapshot_capture(const char *key_path,
                                    ssh_key_snapshot_t *snapshot);
static void ssh_key_snapshot_clear(ssh_key_snapshot_t *snapshot);
static int write_all_fd(int fd, const char *buf, size_t size);
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
    bool observational;
    char anchor[96];
} ssh_runtime_pin_t;

static bool pinned_pid_sidecar_matches_record(
    const ssh_runtime_pin_t *pin, const ssh_agent_record_t *record);
static int retire_recorded_agent_endpoint(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const char *pid_name,
    const ssh_runtime_pin_t *socket_pin,
    const ssh_runtime_pin_t *pid_pin,
    const ssh_agent_record_t *record);

/* A malformed sidecar is materially different from an unsafe or unstable
 * one. Its contents cannot authorize process signaling, but its exact pinned
 * inode may be retired after the paired socket is conclusively dead. */
typedef enum {
    SSH_PID_SIDECAR_ERROR = -1,
    SSH_PID_SIDECAR_VALID = 0,
    SSH_PID_SIDECAR_ABSENT = 1,
    SSH_PID_SIDECAR_MALFORMED = 2,
    SSH_PID_SIDECAR_LEGACY = 3
} ssh_pid_sidecar_result_t;

typedef enum {
    SSH_UNRECORDED_CLEANED = 0,
    SSH_UNRECORDED_ARTIFACT_RETAINED,
    SSH_UNRECORDED_OWNERSHIP_RECORDED
} ssh_unrecorded_result_t;

static int capture_current_socket_link(int dir_fd, const char *socket_path,
                                       const char *display_path,
                                       ssh_current_link_identity_t *identity);
static int publish_current_socket_link(int dir_fd, const char *socket_path,
                                       const char *display_path,
                                       ssh_current_link_identity_t *identity);
static int remove_current_socket_link_if_unchanged(
    int dir_fd, const ssh_current_link_identity_t *identity);
static int parse_ssh_agent_output(const char *output, size_t output_len,
                                  bool output_truncated,
                                  ssh_config_t *ssh_config);
static bool parse_complete_ssh_agent_pid(const char *output,
                                         size_t output_len,
                                         bool output_truncated,
                                         pid_t *pid_out);
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
static int observe_ssh_runtime_entry_at(int dir_fd, const char *name,
                                        const char *display_path,
                                        ssh_runtime_pin_t *pin);
static int verify_ssh_runtime_pin_at(int dir_fd, const char *name,
                                     const char *display_path,
                                     const ssh_runtime_pin_t *pin);
static int prove_malformed_pid_socket_dead_at(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const ssh_runtime_pin_t *socket_pin,
    bool socket_present, bool allow_detached_namespace,
    const char *record_description);
static int retire_reaped_socket_if_dead(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const char *description);
static int release_ssh_runtime_pin(int dir_fd, ssh_runtime_pin_t *pin);
static int reconcile_ssh_runtime_pins(int dir_fd, const char *socket_dir);
static void warn_recorded_endpoint_retirement(const char *socket_path,
                                               bool detached);
static bool target_is_exact_managed_socket(const char *socket_dir,
                                           const char *target,
                                           char *component,
                                           size_t component_size);
static ssh_pid_sidecar_result_t read_ssh_agent_pid_at(
    int dir_fd, const char *name, const char *display_path,
    ssh_agent_record_t *record_out, ssh_runtime_pin_t *pin);
static int write_ssh_agent_pid_at(int dir_fd, const char *name,
                                  const ssh_agent_record_t *record);
static bool recover_exact_ssh_agent_record_at(
    int dir_fd, const char *name, const char *display_path,
    const ssh_agent_record_t *expected);
static ssh_process_outcome_t reap_ssh_agent(
    const ssh_agent_record_t *record, const char *sock,
                                            int runtime_dir_fd);
static ssh_process_outcome_t pid_is_our_ssh_agent(
                                                   const ssh_agent_record_t *record,
                                                   const char *expected_sock,
                                                   int runtime_dir_fd);
static int capture_process_generation(
    pid_t pid, ssh_process_generation_t *generation);
static int inspect_process_image_real(pid_t pid, ssh_process_image_t *image);
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
    .generation = capture_process_generation,
    .image = inspect_process_image_real,
    .signal = ssh_process_signal_real,
    .pidfd_open = ssh_pidfd_open_real,
    .pidfd_signal = ssh_pidfd_signal_real
};
static ssh_pid_commit_hook_fn g_pid_commit_hook;
static ssh_pid_commit_hook_fn g_pid_postrename_hook;
static ssh_namespace_commit_hook_fn g_namespace_commit_hook;

/* AR-13 L2: on Darwin fsync(2) only reaches the drive, not through its cache;
 * the M6 no-op re-proof, the post-rename COMMITTED barrier, and the HOME-entry
 * syncs all advertise power-loss durability, which needs F_FULLFSYNC. Fall back
 * to plain fsync only when the volume/descriptor cannot support the fcntl
 * (ENOTSUP/ENOTTY/EINVAL); retry EINTR; any other errno is a real flush failure
 * that must not be masked as durable success. */
static int ssh_full_fsync(int fd) {
#if defined(__APPLE__)
    int rc;
    do {
        rc = fcntl(fd, F_FULLFSYNC);
    } while (rc != 0 && errno == EINTR);
    if (rc == 0) return 0;
    if (errno != ENOTSUP && errno != ENOTTY && errno != EINVAL) return -1;
#endif
    return fsync(fd);
}
static ssh_dirsync_fn g_ssh_dirsync = ssh_full_fsync;
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
static ssh_metadata_test_hook_fn g_metadata_test_hook;
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
static ssh_socket_probe_fn g_socket_probe = probe_ssh_agent_socket;

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
    g_reap_ops.generation = ops && ops->generation
                                ? ops->generation
                                : capture_process_generation;
    g_reap_ops.image = ops && ops->image
                           ? ops->image
                           : inspect_process_image_real;
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
    g_ssh_dirsync = fn ? fn : ssh_full_fsync;
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

ssh_metadata_test_hook_fn ssh_manager_set_metadata_test_hook_fn(
    ssh_metadata_test_hook_fn fn) {
    ssh_metadata_test_hook_fn previous = g_metadata_test_hook;
    g_metadata_test_hook = fn;
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

ssh_socket_probe_fn ssh_manager_set_socket_probe_fn(ssh_socket_probe_fn fn) {
    ssh_socket_probe_fn previous = g_socket_probe;
    g_socket_probe = fn ? fn : probe_ssh_agent_socket;
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

static int parse_bounded_decimal_u64(const char *text, size_t length,
                                     uint64_t *value_out);

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

static bool same_process_executable_identity(const struct stat *left,
                                             const struct stat *right) {
    return left && right && S_ISREG(left->st_mode) &&
           S_ISREG(right->st_mode) &&
           left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino;
}

static bool ssh_process_image_equal(const ssh_process_image_t *left,
                                    const ssh_process_image_t *right) {
    size_t left_path_size;
    size_t right_path_size;

    if (!left || !right || !left->valid || !right->valid) return false;
    left_path_size = strnlen(
        left->executable_path, sizeof(left->executable_path));
    right_path_size = strnlen(
        right->executable_path, sizeof(right->executable_path));
    if (left_path_size == sizeof(left->executable_path) ||
        right_path_size == sizeof(right->executable_path) ||
        left_path_size != right_path_size) {
        return false;
    }
    return same_process_executable_identity(
               &left->executable_identity, &right->executable_identity) &&
           left->effective_uid == right->effective_uid &&
           left->socket_peer_pid == right->socket_peer_pid &&
           left->socket_peer_uid == right->socket_peer_uid &&
           memcmp(left->executable_path, right->executable_path,
                  left_path_size) == 0;
}

static bool process_image_from_launch_witness(
    const run_launch_witness_t *witness, ssh_process_image_t *image) {
    if (image) memset(image, 0, sizeof(*image));
    if (!witness || !image || !witness->valid || witness->is_script ||
        witness->executable_path[0] != '/' ||
        !S_ISREG(witness->executable_identity.st_mode) ||
        safe_strncpy(image->executable_path, witness->executable_path,
                     sizeof(image->executable_path)) != 0) {
        errno = EINVAL;
        return false;
    }
    image->executable_identity = witness->executable_identity;
    image->effective_uid = geteuid();
    image->valid = true;
    return true;
}

#define SSH_PEER_CONNECT_TIMEOUT_MS 100
#define SSH_AGENT_IO_TIMEOUT_MS 500
#define SSH_AGENT_MAX_MESSAGE (256U * 1024U)
#define SSH_AGENT_MAX_IDENTITIES 2048U

typedef struct {
    int fd;
    pid_t peer_pid;
    uid_t peer_uid;
} ssh_agent_connection_t;

static int ssh_agent_request_identities(int fd, int64_t deadline,
                                        uint32_t *identity_count);
static int ssh_agent_deadline(int64_t *deadline);

static int wait_for_socket_connection(int fd, int timeout_ms) {
    int64_t started;
    int64_t deadline;

    if (fd < 0 || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    started = ssh_probe_clock_real();
    if (started < 0 || started > INT64_MAX - timeout_ms) {
        if (started >= 0) errno = EOVERFLOW;
        return -1;
    }
    deadline = started + timeout_ms;
    for (;;) {
        struct pollfd pfd;
        int64_t now = ssh_probe_clock_real();
        int64_t remaining;
        int timeout;
        int poll_rc;

        if (now < 0) return -1;
        if (now < started) {
            errno = ERANGE;
            return -1;
        }
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        remaining = deadline - now;
        timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLOUT;
        poll_rc = poll(&pfd, 1, timeout);
        if (poll_rc > 0) {
            int socket_error = 0;
            socklen_t error_size = sizeof(socket_error);

            if ((pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == 0 ||
                (pfd.revents & POLLNVAL) != 0) {
                errno = EIO;
                return -1;
            }
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                           &error_size) != 0) {
                return -1;
            }
            if (error_size != sizeof(socket_error)) {
                errno = EIO;
                return -1;
            }
            if (socket_error != 0) {
                errno = socket_error;
                return -1;
            }
            return 0;
        }
        if (poll_rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR) return -1;
    }
}

static int capture_socket_peer_credentials(int fd, pid_t *peer_pid,
                                           uid_t *peer_uid) {
    if (fd < 0 || !peer_pid || !peer_uid) {
        errno = EINVAL;
        return -1;
    }
#ifdef __linux__
    {
        struct ucred credential;
        socklen_t credential_size = sizeof(credential);

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential,
                       &credential_size) != 0) {
            return -1;
        }
        if (credential_size != sizeof(credential) ||
            credential.pid <= 1) {
            errno = EPROTO;
            return -1;
        }
        *peer_pid = credential.pid;
        *peer_uid = credential.uid;
    }
#elif defined(__FreeBSD__)
    {
        struct xucred credential;
        socklen_t credential_size = sizeof(credential);

        memset(&credential, 0, sizeof(credential));
        if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credential,
                       &credential_size) != 0) {
            return -1;
        }
        if (credential_size != sizeof(credential) ||
            credential.cr_version != XUCRED_VERSION ||
            credential.cr_pid <= 1) {
            errno = EPROTO;
            return -1;
        }
        *peer_pid = credential.cr_pid;
        *peer_uid = credential.cr_uid;
    }
#elif defined(__APPLE__)
    {
        uid_t effective_uid;
        gid_t effective_gid;
#ifdef LOCAL_PEERPID
        pid_t process_id = -1;
        socklen_t process_id_size = sizeof(process_id);
#endif

        if (getpeereid(fd, &effective_uid, &effective_gid) != 0) return -1;
        (void)effective_gid;
#ifdef LOCAL_PEERPID
        if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &process_id,
                       &process_id_size) != 0) {
            return -1;
        }
        if (process_id_size != sizeof(process_id) || process_id <= 1) {
            errno = EPROTO;
            return -1;
        }
        *peer_pid = process_id;
        *peer_uid = effective_uid;
#else
        errno = ENOTSUP;
        return -1;
#endif
    }
#else
    errno = ENOTSUP;
    return -1;
#endif
    return 0;
}

static int open_socket_peer(const char *socket_arg, int runtime_dir_fd,
                            ssh_agent_connection_t *connection) {
    struct sockaddr_un address;
    struct stat held_dir;
    char anchored_path[MAX_PATH_LEN];
    char pinned_dir_path[MAX_PATH_LEN];
    const char *connect_path = socket_arg;
    bool anchored = false;
    int fd = -1;
    int flags;
    int rc = -1;

    if (connection) {
        connection->fd = -1;
        connection->peer_pid = -1;
        connection->peer_uid = (uid_t)-1;
    }
    if (!socket_arg || !*socket_arg || !connection) {
        errno = EINVAL;
        return -1;
    }
    if (runtime_dir_fd >= 0) {
        const char *leaf = strrchr(socket_arg, '/');
        struct stat named_dir;
        int written;

        leaf = leaf ? leaf + 1 : socket_arg;
        if (!*leaf || strchr(leaf, '/') ||
            fstat(runtime_dir_fd, &held_dir) != 0) {
            errno = EINVAL;
            return -1;
        }
#ifdef __linux__
        written = snprintf(pinned_dir_path, sizeof(pinned_dir_path),
                           "/proc/self/fd/%d", runtime_dir_fd);
        if (written <= 0 ||
            (size_t)written >= sizeof(pinned_dir_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
#elif defined(__APPLE__)
        if (fcntl(runtime_dir_fd, F_GETPATH, pinned_dir_path) != 0) {
            return -1;
        }
#elif defined(__FreeBSD__) && defined(F_KINFO)
        {
            struct kinfo_file info;
            memset(&info, 0, sizeof(info));
            info.kf_structsize = sizeof(info);
            if (fcntl(runtime_dir_fd, F_KINFO, &info) != 0 ||
                info.kf_path[0] == '\0' ||
                safe_strncpy(pinned_dir_path, info.kf_path,
                             sizeof(pinned_dir_path)) != 0) {
                return -1;
            }
        }
#else
        errno = ENOTSUP;
        return -1;
#endif
        if (stat(pinned_dir_path, &named_dir) != 0 ||
            !same_runtime_identity(&held_dir, &named_dir)) {
            errno = ESTALE;
            return -1;
        }
        written = snprintf(anchored_path, sizeof(anchored_path),
                           "%s/%s", pinned_dir_path, leaf);
        if (written <= 0 || (size_t)written >= sizeof(anchored_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        connect_path = anchored_path;
        anchored = true;
    } else if (socket_arg[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (strlen(connect_path) >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        goto out;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) goto out;
#if defined(SO_NOSIGPIPE)
    {
        int enabled = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                       sizeof(enabled)) != 0) {
            goto out;
        }
    }
#endif
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        goto out;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (safe_strncpy(address.sun_path, connect_path,
                     sizeof(address.sun_path)) != 0) {
        goto out;
    }
    if (connect(fd, (struct sockaddr *)(void *)&address,
                sizeof(address)) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN &&
            errno != EWOULDBLOCK) {
            goto out;
        }
        if (wait_for_socket_connection(
                fd, SSH_PEER_CONNECT_TIMEOUT_MS) != 0) {
            goto out;
        }
    }
    if (anchored) {
        struct stat held_after;
        struct stat named_after;
        if (fstat(runtime_dir_fd, &held_after) != 0 ||
            stat(pinned_dir_path, &named_after) != 0 ||
            !same_runtime_identity(&held_dir, &held_after) ||
            !same_runtime_identity(&held_dir, &named_after)) {
            errno = ESTALE;
            goto out;
        }
    }
    if (capture_socket_peer_credentials(
            fd, &connection->peer_pid, &connection->peer_uid) != 0) {
        goto out;
    }
    connection->fd = fd;
    fd = -1;
    rc = 0;
out:
    {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        errno = saved_errno;
    }
    return rc;
}

static int inspect_socket_peer(const char *socket_arg, int runtime_dir_fd,
                               pid_t *peer_pid, uid_t *peer_uid) {
    ssh_agent_connection_t connection;
#ifdef __APPLE__
    uint32_t identity_count;
    int64_t deadline;
#endif
    int rc;

    if (!peer_pid || !peer_uid) {
        errno = EINVAL;
        return -1;
    }
    rc = open_socket_peer(socket_arg, runtime_dir_fd, &connection);
    if (rc != 0) return -1;
#ifdef __APPLE__
    if (ssh_agent_deadline(&deadline) != 0 ||
        ssh_agent_request_identities(
            connection.fd, deadline, &identity_count) != 0 ||
        capture_socket_peer_credentials(
            connection.fd, &connection.peer_pid,
            &connection.peer_uid) != 0) {
        int saved_errno = errno;
        close(connection.fd);
        errno = saved_errno;
        return -1;
    }
#endif
    *peer_pid = connection.peer_pid;
    *peer_uid = connection.peer_uid;
    if (close(connection.fd) != 0) return -1;
    return 0;
}

static uint32_t ssh_agent_read_u32(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static void ssh_agent_write_u32(unsigned char *bytes, uint32_t value) {
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static int ssh_agent_wait_io(int fd, short events, int64_t deadline) {
    int64_t started = deadline - SSH_AGENT_IO_TIMEOUT_MS;

    for (;;) {
        struct pollfd pfd;
        int64_t now = ssh_probe_clock_real();
        int timeout;
        int rc;

        if (now < 0) return -1;
        if (now < started) {
            errno = ERANGE;
            return -1;
        }
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        timeout = deadline - now > INT_MAX
                      ? INT_MAX
                      : (int)(deadline - now);
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = events;
        rc = poll(&pfd, 1, timeout);
        if (rc > 0) {
            if ((pfd.revents & events) != 0) return 0;
            errno = (pfd.revents & POLLNVAL) != 0 ? EBADF : EIO;
            return -1;
        }
        if (rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR) return -1;
    }
}

static int ssh_agent_write_all(int fd, const unsigned char *bytes,
                               size_t size, int64_t deadline) {
    size_t offset = 0;

    while (offset < size) {
        ssize_t written;
        if (ssh_agent_wait_io(fd, POLLOUT, deadline) != 0) return -1;
#ifdef MSG_NOSIGNAL
        written = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
#else
        written = send(fd, bytes + offset, size - offset, 0);
#endif
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (written == 0) errno = EPIPE;
        return -1;
    }
    return 0;
}

static int ssh_agent_read_all(int fd, unsigned char *bytes, size_t size,
                              int64_t deadline) {
    size_t offset = 0;

    while (offset < size) {
        ssize_t received;
        if (ssh_agent_wait_io(fd, POLLIN, deadline) != 0) return -1;
        received = recv(fd, bytes + offset, size - offset, 0);
        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (received == 0) errno = ECONNRESET;
        return -1;
    }
    return 0;
}

static int ssh_agent_send_message(int fd, unsigned char type,
                                  int64_t deadline) {
    unsigned char frame[5];

    ssh_agent_write_u32(frame, 1);
    frame[4] = type;
    return ssh_agent_write_all(fd, frame, sizeof(frame), deadline);
}

static int ssh_agent_read_message(int fd, unsigned char **message,
                                  size_t *message_size, int64_t deadline) {
    unsigned char header[4];
    uint32_t size;
    unsigned char *payload;

    if (!message || !message_size) {
        errno = EINVAL;
        return -1;
    }
    *message = NULL;
    *message_size = 0;
    if (ssh_agent_read_all(fd, header, sizeof(header), deadline) != 0) {
        return -1;
    }
    size = ssh_agent_read_u32(header);
    if (size == 0 || size > SSH_AGENT_MAX_MESSAGE) {
        errno = EMSGSIZE;
        return -1;
    }
    payload = malloc(size);
    if (!payload) return -1;
    if (ssh_agent_read_all(fd, payload, size, deadline) != 0) {
        int saved_errno = errno;
        free(payload);
        errno = saved_errno;
        return -1;
    }
    *message = payload;
    *message_size = size;
    return 0;
}

static int ssh_agent_request_identities(int fd, int64_t deadline,
                                        uint32_t *identity_count) {
    static const unsigned char request_identities = 11;
    static const unsigned char identities_answer = 12;
    unsigned char *message = NULL;
    size_t size = 0;
    size_t offset;
    uint32_t count;
    int rc = -1;

    if (!identity_count) {
        errno = EINVAL;
        return -1;
    }
    if (ssh_agent_send_message(fd, request_identities, deadline) != 0 ||
        ssh_agent_read_message(fd, &message, &size, deadline) != 0) {
        goto out;
    }
    if (size < 5 || message[0] != identities_answer) {
        errno = EPROTO;
        goto out;
    }
    count = ssh_agent_read_u32(message + 1);
    if (count > SSH_AGENT_MAX_IDENTITIES) {
        errno = EOVERFLOW;
        goto out;
    }
    offset = 5;
    for (uint32_t i = 0; i < count; i++) {
        for (int field = 0; field < 2; field++) {
            uint32_t field_size;
            if (size - offset < 4) {
                errno = EPROTO;
                goto out;
            }
            field_size = ssh_agent_read_u32(message + offset);
            offset += 4;
            if ((size_t)field_size > size - offset) {
                errno = EPROTO;
                goto out;
            }
            offset += field_size;
        }
    }
    if (offset != size) {
        errno = EPROTO;
        goto out;
    }
    *identity_count = count;
    rc = 0;
out:
    free(message);
    return rc;
}

static int ssh_agent_remove_all_identities(int fd, int64_t deadline) {
    static const unsigned char remove_all_identities = 19;
    static const unsigned char success = 6;
    unsigned char *message = NULL;
    size_t size = 0;
    int rc = -1;

    if (ssh_agent_send_message(fd, remove_all_identities, deadline) != 0 ||
        ssh_agent_read_message(fd, &message, &size, deadline) != 0) {
        goto out;
    }
    if (size != 1 || message[0] != success) {
        errno = EPROTO;
        goto out;
    }
    rc = 0;
out:
    free(message);
    return rc;
}

static int ssh_agent_deadline(int64_t *deadline) {
    int64_t now;

    if (!deadline) {
        errno = EINVAL;
        return -1;
    }
    now = ssh_probe_clock_real();
    if (now < 0 || now > INT64_MAX - SSH_AGENT_IO_TIMEOUT_MS) {
        if (now >= 0) errno = EOVERFLOW;
        return -1;
    }
    *deadline = now + SSH_AGENT_IO_TIMEOUT_MS;
    return 0;
}

#ifdef __linux__
static int parse_linux_effective_uid(const char *status, size_t status_size,
                                     uid_t *effective_uid) {
    static const char prefix[] = "Uid:";
    size_t offset = 0;

    if (!status || !effective_uid) {
        errno = EINVAL;
        return -1;
    }
    while (offset < status_size) {
        size_t line_size = 0;
        const char *line = status + offset;
        const char *cursor;
        uint64_t value = 0;

        while (offset + line_size < status_size &&
               status[offset + line_size] != '\n') {
            line_size++;
        }
        if (line_size < sizeof(prefix) - 1U ||
            memcmp(line, prefix, sizeof(prefix) - 1U) != 0) {
            offset += line_size + (offset + line_size < status_size);
            continue;
        }
        cursor = line + sizeof(prefix) - 1U;
        for (int field = 0; field < 2; field++) {
            const char *field_start;

            while (cursor < line + line_size &&
                   isspace((unsigned char)*cursor)) {
                cursor++;
            }
            if (cursor == line + line_size) {
                errno = EINVAL;
                return -1;
            }
            field_start = cursor;
            while (cursor < line + line_size &&
                   !isspace((unsigned char)*cursor)) {
                cursor++;
            }
            if (parse_bounded_decimal_u64(
                    field_start, (size_t)(cursor - field_start),
                    &value) != 0) {
                errno = EINVAL;
                return -1;
            }
        }
        if ((uint64_t)(uid_t)value != value) {
            errno = EOVERFLOW;
            return -1;
        }
        *effective_uid = (uid_t)value;
        return 0;
    }
    errno = EINVAL;
    return -1;
}
#endif

/* Capture kernel-owned executable and credential evidence for one live PID.
 * Linux exposes the loaded executable object itself through /proc/PID/exe.
 * Darwin and FreeBSD expose the executable spelling and effective credential
 * through native process sysctls. BSD signaling relies on the descriptor-
 * trusted launch witness plus native socket credentials instead, because
 * those pathname interfaces do not identify the loaded executable object. */
static int inspect_process_image_real(pid_t pid, ssh_process_image_t *image) {
    if (pid <= 1 || !image) {
        errno = EINVAL;
        return -1;
    }
    memset(image, 0, sizeof(*image));
#ifdef __linux__
    {
        char proc_path[64];
        char *status = NULL;
        size_t status_size = 0;
        int fd;

        snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe", (long)pid);
        fd = open(proc_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        if (fstat(fd, &image->executable_identity) != 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        close(fd);

        snprintf(proc_path, sizeof(proc_path), "/proc/%ld/status", (long)pid);
        if (read_proc_file(proc_path, &status, &status_size) != 0 ||
            parse_linux_effective_uid(status, status_size,
                                      &image->effective_uid) != 0) {
            int saved_errno = errno ? errno : EIO;
            free(status);
            errno = saved_errno;
            return -1;
        }
        free(status);
        image->valid = true;
        return 0;
    }
#elif defined(__APPLE__)
    {
        int process_mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
        int proc_mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
        int argmax_mib[2] = {CTL_KERN, KERN_ARGMAX};
        struct kinfo_proc info;
        size_t info_size = sizeof(info);
        int argmax = 0;
        size_t argmax_size = sizeof(argmax);
        char *args = NULL;
        char *canonical = NULL;
        size_t args_size;
        size_t executable_size;
        int rc = -1;

        if (sysctl(proc_mib, 4, &info, &info_size, NULL, 0) != 0 ||
            info_size != sizeof(info) || info.kp_proc.p_pid != pid ||
            sysctl(argmax_mib, 2, &argmax, &argmax_size, NULL, 0) != 0 ||
            argmax_size != sizeof(argmax) ||
            argmax <= (int)sizeof(int)) {
            return -1;
        }
        args_size = (size_t)argmax;
        args = malloc(args_size);
        if (!args) return -1;
        if (sysctl(process_mib, 3, args, &args_size, NULL, 0) != 0 ||
            args_size <= sizeof(int)) {
            goto out;
        }
        executable_size = strnlen(args + sizeof(int),
                                  args_size - sizeof(int));
        if (executable_size == 0 ||
            executable_size == args_size - sizeof(int)) {
            errno = EINVAL;
            goto out;
        }
        canonical = realpath(args + sizeof(int), NULL);
        if (!canonical ||
            safe_strncpy(image->executable_path, canonical,
                         sizeof(image->executable_path)) != 0 ||
            stat(canonical, &image->executable_identity) != 0) {
            goto out;
        }
        image->effective_uid = info.kp_eproc.e_ucred.cr_uid;
        image->valid = true;
        rc = 0;
out:
        {
            int saved_errno = errno;
            free(canonical);
            free(args);
            errno = saved_errno;
        }
        return rc;
    }
#elif defined(__FreeBSD__)
    {
        int path_mib[4] = {
            CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, (int)pid
        };
        int proc_mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
        struct kinfo_proc info;
        size_t info_size = sizeof(info);
        char kernel_path[MAX_PATH_LEN];
        size_t kernel_path_size = sizeof(kernel_path);
        char *canonical;

        if (sysctl(proc_mib, 4, &info, &info_size, NULL, 0) != 0 ||
            info_size != sizeof(info) || info.ki_pid != pid ||
            sysctl(path_mib, 4, kernel_path, &kernel_path_size, NULL, 0) != 0 ||
            kernel_path_size == 0 ||
            !memchr(kernel_path, '\0', kernel_path_size)) {
            return -1;
        }
        canonical = realpath(kernel_path, NULL);
        if (!canonical) return -1;
        if (safe_strncpy(image->executable_path, canonical,
                         sizeof(image->executable_path)) != 0 ||
            stat(canonical, &image->executable_identity) != 0) {
            int saved_errno = errno;
            free(canonical);
            errno = saved_errno;
            return -1;
        }
        free(canonical);
        image->effective_uid = info.ki_uid;
        image->valid = true;
        return 0;
    }
#else
    (void)pid;
    errno = ENOTSUP;
    return -1;
#endif
}

static ssh_process_outcome_t inspect_pid_ssh_agent_image(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
#ifdef __linux__
    ssh_process_image_t observed;
#endif
    pid_t peer_pid = -1;
    uid_t peer_uid = (uid_t)-1;

    if (!record || record->pid <= 1 || !record->image.valid ||
        record->image.executable_path[0] != '/' ||
        record->image.effective_uid != geteuid()) {
        return SSH_PROCESS_INDETERMINATE;
    }
    if (inspect_socket_peer(socket_arg, runtime_dir_fd,
                            &peer_pid, &peer_uid) != 0) {
        return inspection_failure_outcome(record->pid);
    }
    if (peer_pid != record->image.socket_peer_pid ||
        peer_uid != record->image.socket_peer_uid) {
        return SSH_PROCESS_UNRELATED;
    }
#if !defined(__linux__)
    /* The BSD process pathname interfaces name the executable but do not
     * identify the loaded executable object. The descriptor-trusted launch
     * witness persisted in v2, the unchanged process generation, and native
     * socket peer credentials are the authoritative tuple there. */
    return SSH_PROCESS_OWNED;
#else
    if (g_reap_ops.image(record->pid, &observed) != 0) {
        /* OpenSSH deliberately becomes nondumpable, denying /proc/PID/exe
         * even to its launcher. The durable trusted launch image, unchanged
         * process generation, and kernel-authenticated socket peer remain the
         * exact usable proof. Other call sites still fail closed if any part
         * of that tuple is absent. */
        return errno == EACCES || errno == EPERM
                   ? SSH_PROCESS_OWNED
                   : inspection_failure_outcome(record->pid);
    }
    if (!observed.valid ||
        observed.effective_uid != record->image.effective_uid ||
        !same_process_executable_identity(
            &observed.executable_identity,
            &record->image.executable_identity)) {
        return SSH_PROCESS_UNRELATED;
    }
    return SSH_PROCESS_OWNED;
#endif
}

static void ssh_process_generation_clear(
    ssh_process_generation_t *generation) {
    if (generation) memset(generation, 0, sizeof(*generation));
}

static bool ssh_process_generation_valid(
    const ssh_process_generation_t *generation) {
    if (!generation) return false;
    if (generation->kind != SSH_PROCESS_GENERATION_LINUX &&
        generation->kind != SSH_PROCESS_GENERATION_DARWIN &&
        generation->kind != SSH_PROCESS_GENERATION_FREEBSD) {
        return false;
    }
    return (generation->boot_hi | generation->boot_lo) != 0 &&
           (generation->start_hi | generation->start_lo) != 0;
}

static bool ssh_process_generation_equal(
    const ssh_process_generation_t *left,
    const ssh_process_generation_t *right) {
    return ssh_process_generation_valid(left) &&
           ssh_process_generation_valid(right) &&
           left->kind == right->kind &&
           left->boot_hi == right->boot_hi &&
           left->boot_lo == right->boot_lo &&
           left->start_hi == right->start_hi &&
           left->start_lo == right->start_lo;
}

static int parse_fixed_hex_u64(const char *text, size_t length,
                               uint64_t *value_out) {
    uint64_t value = 0;
    if (!text || !value_out || length != 16U) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        unsigned digit;
        if (c >= '0' && c <= '9') {
            digit = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (unsigned)(c - 'a') + 10U;
        } else {
            return -1;
        }
        value = (value << 4) | digit;
    }
    *value_out = value;
    return 0;
}

static int parse_bounded_decimal_u64(const char *text, size_t length,
                                     uint64_t *value_out) {
    uint64_t value = 0;
    if (!text || !value_out || length == 0) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        unsigned digit;
        if (c < '0' || c > '9') return -1;
        digit = (unsigned)(c - '0');
        if (value > (UINT64_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    *value_out = value;
    return 0;
}

static int parse_bounded_hex_u64(const char *text, size_t length,
                                 uint64_t *value_out) {
    uint64_t value = 0;

    if (!text || !value_out || length == 0 || length > 16U) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        unsigned digit;

        if (c >= '0' && c <= '9') {
            digit = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (unsigned)(c - 'a') + 10U;
        } else {
            return -1;
        }
        if (value > (UINT64_MAX - digit) / 16U) return -1;
        value = value * 16U + digit;
    }
    *value_out = value;
    return 0;
}

static int next_bounded_record_field(
    const char *text, size_t text_size, size_t *offset, char delimiter,
    const char **field, size_t *field_size) {
    const char *end;
    size_t remaining;

    if (!text || !offset || !field || !field_size ||
        *offset >= text_size) {
        return -1;
    }
    remaining = text_size - *offset;
    end = memchr(text + *offset, delimiter, remaining);
    if (!end || end == text + *offset) return -1;
    *field = text + *offset;
    *field_size = (size_t)(end - *field);
    *offset += *field_size + 1U;
    return 0;
}

#ifdef __linux__
static int capture_linux_process_generation(
    pid_t pid, ssh_process_generation_t *generation) {
    char stat_path[64];
    char *boot = NULL;
    char *stat_data = NULL;
    char compact_boot[32];
    size_t boot_size = 0;
    size_t stat_size = 0;
    size_t compact_used = 0;
    char *cursor;
    const char *start_end;
    uint64_t start;
    int rc = -1;

    if (pid <= 1 || !generation) {
        errno = EINVAL;
        return -1;
    }
    ssh_process_generation_clear(generation);
    if (read_proc_file("/proc/sys/kernel/random/boot_id",
                       &boot, &boot_size) != 0) {
        goto out;
    }
    for (size_t i = 0; i < boot_size; i++) {
        if (boot[i] == '-' || boot[i] == '\n') continue;
        if (compact_used >= sizeof(compact_boot) ||
            !isxdigit((unsigned char)boot[i]) ||
            isupper((unsigned char)boot[i])) {
            errno = EINVAL;
            goto out;
        }
        compact_boot[compact_used++] = boot[i];
    }
    if (compact_used != sizeof(compact_boot) ||
        parse_fixed_hex_u64(compact_boot, 16U, &generation->boot_hi) != 0 ||
        parse_fixed_hex_u64(compact_boot + 16U, 16U,
                            &generation->boot_lo) != 0) {
        errno = EINVAL;
        goto out;
    }

    snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", (long)pid);
    if (read_proc_file(stat_path, &stat_data, &stat_size) != 0 ||
        stat_size == 0) {
        goto out;
    }
    cursor = stat_data + stat_size;
    while (cursor > stat_data && cursor[-1] != ')') cursor--;
    if (cursor == stat_data || cursor >= stat_data + stat_size ||
        *cursor != ' ') {
        errno = EINVAL;
        goto out;
    }
    cursor++;
    for (unsigned field = 3; field < 22; field++) {
        while (cursor < stat_data + stat_size &&
               *cursor != ' ' && *cursor != '\n') {
            cursor++;
        }
        while (cursor < stat_data + stat_size && *cursor == ' ') cursor++;
        if (cursor >= stat_data + stat_size) {
            errno = EINVAL;
            goto out;
        }
    }
    start_end = cursor;
    while (start_end < stat_data + stat_size &&
           *start_end != ' ' && *start_end != '\n') {
        start_end++;
    }
    if (parse_bounded_decimal_u64(
            cursor, (size_t)(start_end - cursor), &start) != 0 ||
        start == 0) {
        errno = EINVAL;
        goto out;
    }
    generation->kind = SSH_PROCESS_GENERATION_LINUX;
    generation->start_lo = (uint64_t)start;
    rc = 0;
out:
    free(boot);
    free(stat_data);
    if (rc != 0) ssh_process_generation_clear(generation);
    return rc;
}
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
static int capture_bsd_boot_generation(ssh_process_generation_t *generation) {
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    struct timeval boot;
    size_t length = sizeof(boot);
    if (sysctl(mib, 2, &boot, &length, NULL, 0) != 0 ||
        length != sizeof(boot) || boot.tv_sec <= 0 ||
        boot.tv_usec < 0 || boot.tv_usec > 999999) {
        return -1;
    }
    generation->boot_hi = (uint64_t)boot.tv_sec;
    generation->boot_lo = (uint64_t)boot.tv_usec;
    return 0;
}
#endif

static int capture_process_generation(
    pid_t pid, ssh_process_generation_t *generation) {
    if (!generation) {
        errno = EINVAL;
        return -1;
    }
    ssh_process_generation_clear(generation);
#ifdef __linux__
    return capture_linux_process_generation(pid, generation);
#elif defined(__APPLE__)
    {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
        struct kinfo_proc info;
        size_t length = sizeof(info);
        if (capture_bsd_boot_generation(generation) != 0 ||
            sysctl(mib, 4, &info, &length, NULL, 0) != 0 ||
            length != sizeof(info) || info.kp_proc.p_pid != pid ||
            info.kp_proc.p_starttime.tv_sec <= 0 ||
            info.kp_proc.p_starttime.tv_usec < 0 ||
            info.kp_proc.p_starttime.tv_usec > 999999) {
            ssh_process_generation_clear(generation);
            return -1;
        }
        generation->kind = SSH_PROCESS_GENERATION_DARWIN;
        generation->start_hi = (uint64_t)info.kp_proc.p_starttime.tv_sec;
        generation->start_lo = (uint64_t)info.kp_proc.p_starttime.tv_usec;
        return 0;
    }
#elif defined(__FreeBSD__)
    {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
        struct kinfo_proc info;
        size_t length = sizeof(info);
        if (capture_bsd_boot_generation(generation) != 0 ||
            sysctl(mib, 4, &info, &length, NULL, 0) != 0 ||
            length != sizeof(info) || info.ki_pid != pid ||
            info.ki_start.tv_sec <= 0 || info.ki_start.tv_usec < 0 ||
            info.ki_start.tv_usec > 999999) {
            ssh_process_generation_clear(generation);
            return -1;
        }
        generation->kind = SSH_PROCESS_GENERATION_FREEBSD;
        generation->start_hi = (uint64_t)info.ki_start.tv_sec;
        generation->start_lo = (uint64_t)info.ki_start.tv_usec;
        return 0;
    }
#else
    (void)pid;
    errno = ENOTSUP;
    return -1;
#endif
}

static ssh_process_outcome_t inspect_pid_ssh_agent_argv(
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
    /* AR-12 H5: never collapse ssh_process_outcome_t through a boolean
     * expression — `&&` would map INDETERMINATE (3) to UNRELATED (1) and an
     * exhausted argv region to OWNED (0), both inverting the fail-closed
     * contract in ssh_manager.h. A truncated argument area is an
     * indeterminate inspection, and the enum must flow through intact. */
    if (offset >= process_args_len) {
        free(process_args);
        return SSH_PROCESS_INDETERMINATE;
    }
    matched = counted_argv_is_our_ssh_agent(process_args + offset,
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

static ssh_process_outcome_t pid_is_our_ssh_agent(
    const ssh_agent_record_t *record, const char *expected_sock,
    int runtime_dir_fd) {
    ssh_process_generation_t observed;
    ssh_process_outcome_t outcome;

    if (!record || record->pid <= 1 ||
        !ssh_process_generation_valid(&record->generation)) {
        return SSH_PROCESS_INDETERMINATE;
    }
    if (g_reap_ops.generation(record->pid, &observed) != 0) {
        return inspection_failure_outcome(record->pid);
    }
    if (!ssh_process_generation_equal(&record->generation, &observed)) {
        return SSH_PROCESS_REPLACED;
    }
    outcome = inspect_pid_ssh_agent_image(record, expected_sock,
                                          runtime_dir_fd);
    if (outcome != SSH_PROCESS_OWNED) return outcome;
    outcome = inspect_pid_ssh_agent_argv(record->pid, expected_sock,
                                         runtime_dir_fd);
    if (outcome != SSH_PROCESS_OWNED) return outcome;
    if (g_reap_ops.generation(record->pid, &observed) != 0) {
        return inspection_failure_outcome(record->pid);
    }
    return ssh_process_generation_equal(&record->generation, &observed)
               ? SSH_PROCESS_OWNED
               : SSH_PROCESS_REPLACED;
}

static int64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
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
 * reusable number. Where pidfd is unavailable, fail closed and retain the
 * durable recovery tuple; numeric PID ownership evidence never authorizes a
 * nonzero signal. */
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

static ssh_process_outcome_t verify_expected_process_generation(
    const ssh_agent_record_t *record) {
    ssh_process_generation_t observed;
    if (!record || !ssh_process_generation_valid(&record->generation)) {
        return SSH_PROCESS_INDETERMINATE;
    }
    if (g_reap_ops.generation(record->pid, &observed) != 0) {
        return inspection_failure_outcome(record->pid);
    }
    return ssh_process_generation_equal(&record->generation, &observed)
               ? SSH_PROCESS_OWNED
               : SSH_PROCESS_REPLACED;
}

static ssh_process_outcome_t probe_pidfd_liveness(int pidfd) {
    struct pollfd alive_check = {.fd = pidfd, .events = POLLIN};

    for (int attempts = 0;; attempts++) {
        int rc;

        alive_check.revents = 0;
        rc = poll(&alive_check, 1, 0);
        if (rc == 0) break;
        if (rc > 0) {
            return (alive_check.revents & (POLLIN | POLLHUP)) != 0
                       ? SSH_PROCESS_GONE
                       : SSH_PROCESS_INDETERMINATE;
        }
        if (errno == EINTR && attempts < 16) continue;
        return SSH_PROCESS_INDETERMINATE;
    }

    for (int attempts = 0;; attempts++) {
        if (g_reap_ops.pidfd_signal(pidfd, 0) == 0) {
            return SSH_PROCESS_OWNED;
        }
        if (errno == EINTR && attempts < 16) continue;
        return errno == ESRCH ? SSH_PROCESS_GONE
                              : SSH_PROCESS_INDETERMINATE;
    }
}

static ssh_process_outcome_t verify_expected_process_generation_with_pidfd(
    const ssh_agent_record_t *record, int pidfd) {
    ssh_process_outcome_t observed;
    ssh_process_outcome_t pinned = probe_pidfd_liveness(pidfd);

    if (pinned != SSH_PROCESS_OWNED) return pinned;
    observed = verify_expected_process_generation(record);
    pinned = probe_pidfd_liveness(pidfd);
    if (pinned != SSH_PROCESS_OWNED) return pinned;
    return observed == SSH_PROCESS_GONE ? SSH_PROCESS_INDETERMINATE
                                        : observed;
}

static ssh_process_outcome_t inspect_process_identity_with_pidfd(
    const ssh_agent_record_t *record, const char *sock, int runtime_dir_fd,
    int pidfd) {
    ssh_process_outcome_t observed;
    ssh_process_outcome_t pinned = probe_pidfd_liveness(pidfd);

    if (pinned != SSH_PROCESS_OWNED) return pinned;
    observed = g_reap_ops.identity(record, sock, runtime_dir_fd);
    pinned = probe_pidfd_liveness(pidfd);
    if (pinned != SSH_PROCESS_OWNED) return pinned;
    return observed == SSH_PROCESS_GONE ? SSH_PROCESS_INDETERMINATE
                                        : observed;
}

static ssh_process_outcome_t reap_ssh_agent(
    const ssh_agent_record_t *record, const char *sock, int runtime_dir_fd) {
    ssh_process_outcome_t identity;
    ssh_process_outcome_t outcome;
    int pidfd;
    int open_errno;

    if (!record || record->pid <= 1 ||
        !ssh_process_generation_valid(&record->generation)) {
        return SSH_PROCESS_INDETERMINATE;
    }
    identity = verify_expected_process_generation(record);
    if (identity != SSH_PROCESS_OWNED) return identity;
    pidfd = g_reap_ops.pidfd_open(record->pid);
    open_errno = errno;
    if (pidfd >= 0) {
        identity =
            verify_expected_process_generation_with_pidfd(record, pidfd);
        if (identity != SSH_PROCESS_OWNED) {
            close(pidfd);
            return identity;
        }
        identity = inspect_process_identity_with_pidfd(
            record, sock, runtime_dir_fd, pidfd);
        if (identity != SSH_PROCESS_OWNED) {
            close(pidfd);
            return identity;
        }
        identity =
            verify_expected_process_generation_with_pidfd(record, pidfd);
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
                        (long)record->pid);
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
    return SSH_PROCESS_INDETERMINATE;
}

static bool ssh_reap_allows_cleanup(ssh_process_outcome_t outcome) {
    return outcome == SSH_PROCESS_GONE || outcome == SSH_PROCESS_UNRELATED;
}

static const char *ssh_process_outcome_name(ssh_process_outcome_t outcome) {
    switch (outcome) {
        case SSH_PROCESS_OWNED: return "OWNED";
        case SSH_PROCESS_UNRELATED: return "UNRELATED";
        case SSH_PROCESS_GONE: return "GONE";
        case SSH_PROCESS_REPLACED: return "REPLACED";
        case SSH_PROCESS_INDETERMINATE: return "INDETERMINATE";
        default: return "INVALID";
    }
}

static void apply_unrecorded_result(ssh_config_t *ssh_config,
                                    ssh_unrecorded_result_t result) {
    if (!ssh_config) return;

    ssh_config->agent_owned =
        result == SSH_UNRECORDED_OWNERSHIP_RECORDED;
    if (!ssh_config->agent_owned) {
        ssh_config->agent_pid = -1;
        ssh_process_generation_clear(&ssh_config->agent_generation);
        memset(&ssh_config->agent_image, 0,
               sizeof(ssh_config->agent_image));
    }
    if (result == SSH_UNRECORDED_CLEANED) {
        ssh_config->agent_socket_path[0] = '\0';
        ssh_config->agent_socket_arg[0] = '\0';
    }
}

static const char *unrecorded_result_summary(
    ssh_unrecorded_result_t result) {
    switch (result) {
        case SSH_UNRECORDED_OWNERSHIP_RECORDED:
            return "runtime durably retained for retry";
        case SSH_UNRECORDED_ARTIFACT_RETAINED:
            return "runtime artifact retained unowned for retry";
        case SSH_UNRECORDED_CLEANED:
        default:
            return "spawned runtime removed";
    }
}

/* Recovery teardown of a just-spawned agent that failed the post-spawn
 * checks (output parse, socket validation) BEFORE its PID sidecar was
 * written. If reap is not conclusive, publish the recovered PID as a durable
 * sidecar and retain the socket. A missing launch witness never authorizes
 * process discovery or signaling; the live or uninspectable socket remains
 * the last recovery handle. The return value controls whether the caller may
 * retain process ownership, not whether an inert socket artifact remains. */
static ssh_unrecorded_result_t reap_unrecorded_agent(
    ssh_config_t *ssh_config, const char *socket_arg, int dir_fd,
    const char *socket_name, const char *pid_name, const char *pid_path,
    const char *socket_path, const char *socket_dir) {
    ssh_process_outcome_t outcome = SSH_PROCESS_INDETERMINATE;
    ssh_runtime_pin_t socket_pin;
    bool socket_present = false;
    ssh_agent_record_t retry_record;

    (void)socket_arg;
    memset(&retry_record, 0, sizeof(retry_record));
    retry_record.pid = ssh_config ? ssh_config->agent_pid : -1;
    if (ssh_config) {
        retry_record.generation = ssh_config->agent_generation;
        retry_record.image = ssh_config->agent_image;
    }

    ssh_runtime_pin_init(&socket_pin);
    int socket_rc = pin_ssh_runtime_entry_at(
        dir_fd, socket_name, socket_path, &socket_pin);
    if (socket_rc == 0) {
        socket_present = true;
        if (retry_record.image.valid &&
            inspect_socket_peer(
                socket_path, dir_fd,
                &retry_record.image.socket_peer_pid,
                &retry_record.image.socket_peer_uid) != 0) {
            retry_record.image.valid = false;
        } else if (retry_record.image.valid && ssh_config) {
            ssh_config->agent_image = retry_record.image;
        }
    } else if (socket_rc < 0) {
        return SSH_UNRECORDED_ARTIFACT_RETAINED;
    }

    if (retry_record.pid > 1 &&
        ssh_process_generation_valid(&retry_record.generation)) {
        outcome = g_ssh_reap(&retry_record, socket_path, dir_fd);
    }

    if (ssh_reap_allows_cleanup(outcome)) {
        if (prove_malformed_pid_socket_dead_at(
                dir_fd, socket_dir, socket_name, socket_path, &socket_pin,
                socket_present, true, "unrecorded SSH process") != 0) {
            (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
            /* The exact witnessed process is conclusively gone/unrelated.
             * Namespace replacement can make its old pinned socket impossible
             * to probe or retire by public path, but that inert artifact must
             * not be converted into a durable ownership claim without a
             * sidecar. Preserve it for later reconciliation and clear process
             * ownership in the caller. */
            return SSH_UNRECORDED_ARTIFACT_RETAINED;
        }
        if (g_unrecorded_cleanup_hook &&
            g_unrecorded_cleanup_hook(dir_fd, socket_name) != 0) {
            set_error(ERR_FILE_IO,
                      "SSH unrecorded-agent cleanup hook failed");
            (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
            return SSH_UNRECORDED_ARTIFACT_RETAINED;
        }
        bool retained = unlink_ssh_reset_path_at(
                            dir_fd, socket_name, socket_path,
                            "unrecorded agent socket cleanup",
                            &socket_pin,
                            socket_present) != 0;
        if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) retained = true;
        if (retained) {
            log_warning(
                "Conclusive SSH process cleanup left an inert socket artifact for later reconciliation");
        }
        return retained ? SSH_UNRECORDED_ARTIFACT_RETAINED
                        : SSH_UNRECORDED_CLEANED;
    }
    if (outcome == SSH_PROCESS_REPLACED) {
        log_warning(
            "SSH agent process generation was replaced before recovery; "
            "retaining socket evidence without claiming process ownership");
        (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
        return SSH_UNRECORDED_ARTIFACT_RETAINED;
    }
    if (retry_record.pid > 1 &&
        ssh_process_generation_valid(&retry_record.generation)) {
        if (write_ssh_agent_pid_at(dir_fd, pid_name, &retry_record) == 0) {
            log_warning("SSH agent reap outcome %s; retained PID %ld and socket for retry",
                        ssh_process_outcome_name(outcome),
                        (long)retry_record.pid);
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                return SSH_UNRECORDED_ARTIFACT_RETAINED;
            }
            return SSH_UNRECORDED_OWNERSHIP_RECORDED;
        } else if (recover_exact_ssh_agent_record_at(
                       dir_fd, pid_name, pid_path, &retry_record)) {
            log_warning(
                "SSH PID recovery publication was uncertain; exact durable record recovered");
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                return SSH_UNRECORDED_ARTIFACT_RETAINED;
            }
            return SSH_UNRECORDED_OWNERSHIP_RECORDED;
        } else {
            log_warning("SSH agent reap outcome %s and PID recovery publication failed; retaining socket",
                        ssh_process_outcome_name(outcome));
        }
        (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
        return SSH_UNRECORDED_ARTIFACT_RETAINED;
    }

    /* If the PID could not be recovered, the socket itself remains the only
     * discovery handle. A conclusively stale inode can be removed; a live or
     * uninspectable listener is retained so reset reports the unresolved
     * runtime instead of erasing its last trace. */
    if (socket_path) {
        bool reachable = false;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) == 0 &&
            g_socket_probe(socket_path, &reachable) == 0 &&
            verify_socket_dir_namespace(dir_fd, socket_dir) == 0 &&
            !reachable) {
            if (g_unrecorded_cleanup_hook &&
                g_unrecorded_cleanup_hook(dir_fd, socket_name) != 0) {
                set_error(ERR_FILE_IO,
                          "SSH unrecorded-agent cleanup hook failed");
                (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
                return SSH_UNRECORDED_ARTIFACT_RETAINED;
            }
            bool retained = unlink_ssh_reset_path_at(
                                dir_fd, socket_name, socket_path,
                                "stale unrecorded agent socket cleanup",
                                &socket_pin,
                                socket_present) != 0;
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                retained = true;
            }
            return retained ? SSH_UNRECORDED_ARTIFACT_RETAINED
                            : SSH_UNRECORDED_CLEANED;
        }
    }
    log_warning("Unrecorded SSH agent state is indeterminate; retaining socket for recovery");
    (void)release_ssh_runtime_pin(dir_fd, &socket_pin);
    return SSH_UNRECORDED_ARTIFACT_RETAINED;
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
    int fd = try_lock_existing_private_file_at(dir_fd, ".lock");
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

    if (!snapshot || !snapshot->data || snapshot->length == 0) {
        return false;
    }
    /* An account admission performs one final pathname/descriptor identity
     * proof immediately before any prior-session teardown, then closes the
     * mutable source descriptor. From that point the private in-memory copy is
     * the exact admitted generation. A later rename or in-place source rewrite
     * cannot substitute bytes or turn safe activation into a post-teardown
     * validation failure. */
    if (snapshot->source_detached) {
        return !snapshot->fd_open && snapshot->fd < 0;
    }
    if (!snapshot->fd_open || snapshot->fd < 0 ||
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

/* OpenSSH probes `<private-path>.pub` before extracting the public portion of
 * the private key itself. Give the portable scratch an exact NAME_MAX-byte
 * component: the scratch remains openable, while the kernel must reject the
 * appended `.pub` component as ENAMETOOLONG before any sibling lookup. This
 * avoids both accidental sidecar selection and an otherwise unavoidable
 * same-UID sentinel replacement race. The component is deterministic because
 * the enclosing private directory lock permits one cooperating writer and a
 * fixed slot bounds crash leftovers to one recoverable entry. */
static int ssh_fingerprint_scratch_name(int dir_fd, char *name, size_t size) {
    static const char prefix[] = ".key-fingerprint.";
    const size_t prefix_length = sizeof(prefix) - 1U;
    long name_max;

    if (dir_fd < 0 || !name || size == 0U) return -1;
    errno = 0;
    name_max = fpathconf(dir_fd, _PC_NAME_MAX);
    if (name_max < 0 || (uintmax_t)name_max >= (uintmax_t)size ||
        (uintmax_t)name_max < (uintmax_t)(prefix_length + 16U)) {
        return -1;
    }
    memcpy(name, prefix, prefix_length);
    memset(name + prefix_length, 'k', (size_t)name_max - prefix_length);
    name[name_max] = '\0';
    return 0;
}

/* Recover the one portable staging slot left by an uncatchable termination.
 * The caller holds the validation-directory lock. Refuse anything except the
 * exact self-owned 0600 single-link regular-file shape that this process
 * creates; hostile or ambiguous entries remain untouched and block further
 * validation. Scrub through the retained descriptor before retiring the
 * verified name. FreeBSD can bind unlink to the descriptor; Darwin uses the
 * same locked-writer plus immediately-before-unlink identity contract as the
 * ordinary cleanup path. */
static int ssh_fingerprint_scratch_recover_at(int dir_fd, const char *name) {
    static const char zeros[4096];
    struct stat opened;
    struct stat scrubbed;
    struct stat named;
    size_t length;
    size_t offset = 0U;
    int fd;
    int rc = -1;

    if (dir_fd < 0 || !name || !*name) return -1;
    fd = openat(dir_fd, name,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &opened) != 0 ||
        !S_ISREG(opened.st_mode) ||
        opened.st_uid != getuid() ||
        opened.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600 ||
        opened.st_size < 0 ||
        (uintmax_t)opened.st_size >
            (uintmax_t)SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES) {
        goto done;
    }
    length = (size_t)opened.st_size;
    while (offset < length) {
        size_t wanted = length - offset;
        ssize_t written;

        if (wanted > sizeof(zeros)) wanted = sizeof(zeros);
        written = pwrite(fd, zeros, wanted, (off_t)offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            goto done;
        }
    }
    if (ftruncate(fd, 0) != 0 ||
        fstat(fd, &scrubbed) != 0 ||
        !same_runtime_identity(&opened, &scrubbed) ||
        !S_ISREG(scrubbed.st_mode) ||
        scrubbed.st_uid != getuid() ||
        scrubbed.st_nlink != 1 ||
        (scrubbed.st_mode & 0777) != 0600 ||
        scrubbed.st_size != 0 ||
        fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_revision(&scrubbed, &named)) {
        goto done;
    }
#if defined(__FreeBSD__)
    if (funlinkat(dir_fd, name, fd, 0) != 0) goto done;
#else
    if (unlinkat(dir_fd, name, 0) != 0) goto done;
#endif
    rc = 0;
done:
    if (close(fd) != 0) rc = -1;
    return rc;
}

int ssh_manager_test_fingerprint_slot_name(int dir_fd, char *name,
                                           size_t name_size) {
    return ssh_fingerprint_scratch_name(dir_fd, name, name_size);
}

int ssh_manager_test_recover_fingerprint_slot(int dir_fd) {
    char name[MAX_PATH_LEN];

    if (ssh_fingerprint_scratch_name(dir_fd, name, sizeof(name)) != 0) {
        return -1;
    }
    return ssh_fingerprint_scratch_recover_at(dir_fd, name);
}

#if !defined(__linux__)
typedef struct {
    int fd;
    size_t length;
    bool created;
    bool have_identity;
    char name[MAX_PATH_LEN];
    struct stat identity;
} ssh_fingerprint_scratch_t;

static bool ssh_fingerprint_scratch_matches(
    int dir_fd, const ssh_fingerprint_scratch_t *scratch,
    const ssh_key_snapshot_t *snapshot) {
    struct stat opened;
    struct stat named;
    size_t offset = 0;

    if (dir_fd < 0 || !scratch || scratch->fd < 0 ||
        !scratch->have_identity || !snapshot ||
        !ssh_key_snapshot_fd_matches(snapshot) ||
        fstat(scratch->fd, &opened) != 0 ||
        fstatat(dir_fd, scratch->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_revision(&scratch->identity, &opened) ||
        !same_runtime_revision(&scratch->identity, &named) ||
        !S_ISREG(opened.st_mode) || !S_ISREG(named.st_mode) ||
        opened.st_uid != getuid() || named.st_uid != getuid() ||
        opened.st_nlink != 1 || named.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600 ||
        (named.st_mode & 0777) != 0600 ||
        opened.st_size < 0 || named.st_size != opened.st_size ||
        (uintmax_t)opened.st_size != snapshot->length) {
        return false;
    }

    while (offset < snapshot->length) {
        char bytes[4096];
        size_t wanted = snapshot->length - offset;
        if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
        ssize_t n = pread(scratch->fd, bytes, wanted, (off_t)offset);
        if (n > 0) {
            bool matches =
                memcmp(bytes, snapshot->data + offset, (size_t)n) == 0;
            secure_zero_memory(bytes, sizeof(bytes));
            if (!matches) return false;
            offset += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            secure_zero_memory(bytes, sizeof(bytes));
            return false;
        }
    }
    return true;
}

static int ssh_fingerprint_scratch_cleanup(
    int dir_fd, ssh_fingerprint_scratch_t *scratch) {
    static const char zeros[4096];
    struct stat named;
    size_t offset = 0;
    int rc = 0;

    if (!scratch) return 0;
    if (scratch->fd >= 0 && scratch->created) {
        while (offset < scratch->length) {
            size_t wanted = scratch->length - offset;
            if (wanted > sizeof(zeros)) wanted = sizeof(zeros);
            ssize_t n = pwrite(scratch->fd, zeros, wanted, (off_t)offset);
            if (n > 0) {
                offset += (size_t)n;
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                rc = -1;
                break;
            }
        }
        if (ftruncate(scratch->fd, 0) != 0) {
            rc = -1;
        }
    }

    if (dir_fd >= 0 && scratch->name[0] != '\0' &&
        scratch->created && scratch->have_identity) {
        if (fstatat(dir_fd, scratch->name, &named,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            if (same_runtime_identity(&scratch->identity, &named) &&
                S_ISREG(named.st_mode) && named.st_uid == getuid()) {
#if defined(__FreeBSD__)
                if (funlinkat(dir_fd, scratch->name, scratch->fd, 0) == 0) {
#else
                /* Darwin has no unlink-by-descriptor primitive. The private
                 * runtime manager lock is the supported writer boundary; the
                 * identity check immediately before unlink also ensures an
                 * observed replacement is preserved. */
                if (unlinkat(dir_fd, scratch->name, 0) == 0) {
#endif
                } else {
                    rc = -1;
                }
            } else {
                /* Preserve a raced replacement rather than unlinking data we
                 * no longer own. The original inode is still scrubbed through
                 * the retained descriptor above. */
                rc = -1;
            }
        } else if (errno == ENOENT) {
            rc = -1;
        } else {
            rc = -1;
        }
    } else if (dir_fd >= 0 && scratch->name[0] != '\0' &&
               scratch->created) {
        /* Creation succeeded but identity capture did not, so pathname
         * deletion has no ownership proof. The file is still empty at this
         * stage; preserve the uncertain name for locked recovery. */
        rc = -1;
    }

    /* The fixed slot is deliberately absent from the process-global,
     * pathname-only emergency registry. Normal/deferred-signal cleanup uses
     * the retained descriptor here; an uncatchable termination leaves at
     * most this one slot for the next locked, identity-checked recovery. */
    if (scratch->fd >= 0 && close(scratch->fd) != 0) rc = -1;
    secure_zero_memory(scratch, sizeof(*scratch));
    scratch->fd = -1;
    return rc;
}

static int ssh_fingerprint_scratch_create(
    int dir_fd, const ssh_key_snapshot_t *snapshot,
    ssh_fingerprint_scratch_t *scratch) {
    struct stat created;
    struct stat named;

    if (dir_fd < 0 || !snapshot || !scratch ||
        !ssh_key_snapshot_fd_matches(snapshot)) {
        return -1;
    }
    memset(scratch, 0, sizeof(*scratch));
    scratch->fd = -1;

    if (ssh_fingerprint_scratch_name(
            dir_fd, scratch->name, sizeof(scratch->name)) != 0) {
        return -1;
    }
    scratch->fd = openat(
        dir_fd, scratch->name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (scratch->fd < 0 && errno == EEXIST) {
        if (ssh_fingerprint_scratch_recover_at(
                dir_fd, scratch->name) != 0) {
            return -1;
        }
        scratch->fd = openat(
            dir_fd, scratch->name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
    if (scratch->fd < 0) return -1;
    scratch->created = true;
    scratch->length = snapshot->length;
    if (fchmod(scratch->fd, 0600) != 0 ||
        fstat(scratch->fd, &scratch->identity) != 0 ||
        !S_ISREG(scratch->identity.st_mode) ||
        scratch->identity.st_uid != getuid() ||
        scratch->identity.st_nlink != 1 ||
        (scratch->identity.st_mode & 0777) != 0600) {
        (void)ssh_fingerprint_scratch_cleanup(dir_fd, scratch);
        return -1;
    }
    scratch->have_identity = true;
    if (write_all_fd(scratch->fd, snapshot->data, snapshot->length) != 0 ||
        fstat(scratch->fd, &created) != 0 ||
        fstatat(dir_fd, scratch->name, &named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_runtime_identity(&scratch->identity, &created) ||
        !same_runtime_identity(&created, &named) ||
        !same_runtime_revision(&created, &named)) {
        (void)ssh_fingerprint_scratch_cleanup(dir_fd, scratch);
        return -1;
    }
    /* Seal the fully populated revision, not the empty O_EXCL creation
     * revision. A rewrite-and-restore during ssh-keygen now changes ctime or
     * generation and is rejected even if the bytes are restored afterward. */
    scratch->identity = created;
    if (!ssh_fingerprint_scratch_matches(dir_fd, scratch, snapshot)) {
        (void)ssh_fingerprint_scratch_cleanup(dir_fd, scratch);
        return -1;
    }
    return 0;
}
#endif

static size_t ssh_keygen_fingerprint_capture_size(
    const char *key_path, const ssh_key_snapshot_t *snapshot) {
    struct stat st;
    size_t source_size = 0U;
    size_t capture_size;

    if (snapshot) {
        source_size = snapshot->length;
    } else if (key_path && stat(key_path, &st) == 0 && S_ISREG(st.st_mode) &&
               st.st_size > 0 &&
               (uintmax_t)st.st_size <=
                   (uintmax_t)SSH_PRIVATE_KEY_SNAPSHOT_MAX_BYTES) {
        source_size = (size_t)st.st_size;
    }
    if (source_size >
        (SSH_KEYGEN_FINGERPRINT_CAPTURE_MAX_BYTES -
         SSH_KEYGEN_FINGERPRINT_CAPTURE_OVERHEAD_BYTES) / 4U) {
        return SSH_KEYGEN_FINGERPRINT_CAPTURE_MAX_BYTES;
    }
    capture_size = source_size * 4U +
                   SSH_KEYGEN_FINGERPRINT_CAPTURE_OVERHEAD_BYTES;
    if (capture_size < SSH_KEYGEN_FINGERPRINT_CAPTURE_MIN_BYTES) {
        capture_size = SSH_KEYGEN_FINGERPRINT_CAPTURE_MIN_BYTES;
    }
    return capture_size;
}

static bool ssh_fingerprint_token_is_canonical(
    const char *fingerprint, size_t fingerprint_length) {
    static const char sha256_prefix[] = "SHA256:";
    static const char md5_prefix[] = "MD5:";

    if (fingerprint_length == 50U &&
        memcmp(fingerprint, sha256_prefix, sizeof(sha256_prefix) - 1U) == 0) {
        for (size_t i = sizeof(sha256_prefix) - 1U;
             i < fingerprint_length; i++) {
            unsigned char byte = (unsigned char)fingerprint[i];
            if (!((byte >= (unsigned char)'A' &&
                   byte <= (unsigned char)'Z') ||
                  (byte >= (unsigned char)'a' &&
                   byte <= (unsigned char)'z') ||
                  (byte >= (unsigned char)'0' &&
                   byte <= (unsigned char)'9') || byte == (unsigned char)'+' ||
                  byte == (unsigned char)'/')) {
                return false;
            }
        }
        return true;
    }
    if (fingerprint_length == 51U &&
        memcmp(fingerprint, md5_prefix, sizeof(md5_prefix) - 1U) == 0) {
        for (size_t i = sizeof(md5_prefix) - 1U;
             i < fingerprint_length; i++) {
            size_t body_offset = i - (sizeof(md5_prefix) - 1U);
            unsigned char byte = (unsigned char)fingerprint[i];

            if (body_offset % 3U == 2U) {
                if (byte != (unsigned char)':') return false;
            } else if (!((byte >= (unsigned char)'0' &&
                         byte <= (unsigned char)'9') ||
                        (byte >= (unsigned char)'a' &&
                         byte <= (unsigned char)'f') ||
                        (byte >= (unsigned char)'A' &&
                         byte <= (unsigned char)'F'))) {
                return false;
            }
        }
        return true;
    }
    return false;
}

/* Parse complete canonical leading fields from one fully captured
 * `ssh-keygen -lf` result. Fingerprint-looking comment text, embedded binary
 * data, destination truncation, and an unterminated field all fail closed. */
static bool ssh_keygen_fingerprint_prefix(
    const char *listing, size_t listing_length,
    char *fingerprint, size_t fingerprint_size) {
    const char *end;
    const char *cursor;
    const char *fingerprint_start;
    size_t fingerprint_length;

    if (!listing || listing_length == 0U || !fingerprint ||
        fingerprint_size == 0U ||
        memchr(listing, '\0', listing_length) != NULL) {
        return false;
    }

    end = listing + listing_length;
    cursor = listing;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') {
        if (*cursor < '0' || *cursor > '9') return false;
        cursor++;
    }
    if (cursor == listing || cursor == end) return false;
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;

    fingerprint_start = cursor;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') {
        unsigned char byte = (unsigned char)*cursor;
        if (byte < 0x21U || byte > 0x7eU) return false;
        cursor++;
    }
    fingerprint_length = (size_t)(cursor - fingerprint_start);
    if (fingerprint_length == 0U || cursor == end ||
        fingerprint_length >= fingerprint_size ||
        !ssh_fingerprint_token_is_canonical(fingerprint_start,
                                            fingerprint_length)) {
        return false;
    }

    memcpy(fingerprint, fingerprint_start, fingerprint_length);
    fingerprint[fingerprint_length] = '\0';
    return true;
}

/* Copy the SHA256:... fingerprint token of the admitted key generation into
 * `buf`. Linux copies the captured bytes into a sealed anonymous memfd and
 * exposes that immutable generation through procfs: each ssh-keygen reopen
 * gets an independent file offset without observing the mutable source fd.
 * Darwin and FreeBSD /dev/fd entries use dup-style shared offsets; OpenSSH
 * reads the private-key header, reopens the path, and otherwise starts the
 * second read at EOF. On those platforms, expose the already-captured bytes
 * briefly through a 0600 file in the pinned, locked manager directory. Its
 * NAME_MAX component prevents OpenSSH from selecting an adjacent `.pub`; its
 * exact inode and contents are checked before and after ssh-keygen, then
 * scrubbed and unlinked. */
static int ssh_key_fingerprint_generation(
    int dir_fd, bool use_cwd_fd, const char *key_path,
    const ssh_key_snapshot_t *snapshot,
    char *buf, size_t size) {
    char *out;
    size_t out_size;
#if defined(__linux__)
    const char *stdin_path = "/proc/self/fd/0";
    int sealed_fd = -1;
#endif
    const char *argv[] = {"ssh-keygen", "-lf", key_path, NULL};
    run_opts_t opts;
    run_result_t res;
    uint64_t run_error_generation;
#if !defined(__linux__)
    ssh_fingerprint_scratch_t scratch;
    memset(&scratch, 0, sizeof(scratch));
    scratch.fd = -1;
#endif

    if ((!snapshot && (!key_path || !*key_path)) ||
        (snapshot && (!snapshot->data || snapshot->length == 0 ||
                      !snapshot->fd_open || snapshot->fd < 0)) ||
        !buf || size == 0) {
        return -1;
    }
    out_size = ssh_keygen_fingerprint_capture_size(key_path, snapshot);
    out = malloc(out_size);
    if (!out) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory capturing SSH key fingerprint");
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = out;
    opts.out_size = out_size;
    opts.stderr_to_devnull = true;
    if (snapshot) {
        if (!ssh_key_snapshot_fd_matches(snapshot)) {
            set_error(ERR_SSH_KEY_INVALID,
                      "Validated SSH key changed before fingerprinting");
            free(out);
            return -1;
        }
#if defined(__linux__)
#if defined(SYS_memfd_create) && defined(MFD_ALLOW_SEALING) && \
    defined(MFD_CLOEXEC) && defined(F_ADD_SEALS) && defined(F_GET_SEALS) && \
    defined(F_SEAL_WRITE) && defined(F_SEAL_GROW) && \
    defined(F_SEAL_SHRINK) && defined(F_SEAL_SEAL)
        const int required_seals =
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        int applied_seals;
        sealed_fd = (int)syscall(
            SYS_memfd_create, "gitswitch-ssh-key",
            (unsigned int)(MFD_CLOEXEC | MFD_ALLOW_SEALING));
        if (sealed_fd < 0 ||
            write_all_fd(sealed_fd, snapshot->data, snapshot->length) != 0 ||
            fcntl(sealed_fd, F_ADD_SEALS, required_seals) != 0 ||
            (applied_seals = fcntl(sealed_fd, F_GET_SEALS)) < 0 ||
            (applied_seals & required_seals) != required_seals ||
            lseek(sealed_fd, 0, SEEK_SET) != 0) {
            int saved_errno = errno;
            if (sealed_fd >= 0) (void)close(sealed_fd);
            errno = saved_errno;
            set_system_error(
                ERR_SYSTEM_CALL,
                "Cannot seal an immutable SSH key fingerprint snapshot");
            free(out);
            return -1;
        }
        argv[2] = stdin_path;
        opts.stdin_fd = sealed_fd;
        opts.use_stdin_fd = true;
#else
        set_error(
            ERR_SYSTEM_CALL,
            "This Linux build cannot create a sealed SSH key fingerprint snapshot");
        free(out);
        return -1;
#endif
#else
        if (!use_cwd_fd || ssh_fingerprint_scratch_create(
                dir_fd, snapshot, &scratch) != 0) {
            set_error(ERR_SSH_KEY_INVALID,
                      "Cannot stage the validated SSH key for portable fingerprinting");
            free(out);
            return -1;
        }
        argv[2] = scratch.name;
        opts.cwd_fd = dir_fd;
        opts.use_cwd_fd = true;
#endif
    }
    run_error_generation = error_report_generation();
    int run_rc = run_argv(argv, &opts, &res);
#if defined(__linux__)
    if (sealed_fd >= 0 && close(sealed_fd) != 0 && run_rc == 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot close sealed SSH key fingerprint snapshot");
        run_rc = -1;
    }
#endif
    bool generation_matches = !snapshot || ssh_key_snapshot_fd_matches(snapshot);
#if !defined(__linux__)
    if (snapshot &&
        !ssh_fingerprint_scratch_matches(dir_fd, &scratch, snapshot)) {
        generation_matches = false;
    }
    int cleanup_rc = snapshot
                         ? ssh_fingerprint_scratch_cleanup(dir_fd, &scratch)
                         : 0;
    if (cleanup_rc != 0) {
        set_error(ERR_SSH_KEY_INVALID,
                  "Portable SSH fingerprint scratch could not be retired safely");
        free(out);
        return -1;
    }
#else
    (void)dir_fd;
    (void)use_cwd_fd;
#endif
    if (!generation_matches) {
        set_error(ERR_SSH_KEY_INVALID,
                  "Validated SSH key changed while fingerprinting");
        free(out);
        return -1;
    }
    if (run_rc != 0) {
        if (error_report_generation() == run_error_generation) {
            if (res.spawned && res.term_signal == 0 && res.exit_code != 0) {
                set_error(
                    ERR_SSH_KEY_INVALID,
                    "OpenSSH could not parse the admitted SSH private key: %s",
                    key_path);
            } else if (res.spawned && res.term_signal != 0) {
                set_error(
                    ERR_SYSTEM_COMMAND_FAILED,
                    "OpenSSH SSH key validation was terminated by signal %d",
                    res.term_signal);
            } else {
                set_error(ERR_SYSTEM_COMMAND_FAILED,
                          "OpenSSH SSH key validation did not complete");
            }
        }
        free(out);
        return -1;
    }
    if (res.out_truncated || res.out_len >= out_size ||
        !ssh_keygen_fingerprint_prefix(out, res.out_len, buf, size)) {
        set_error(ERR_SSH_KEY_INVALID,
                  "OpenSSH returned an invalid fingerprint for the admitted "
                  "SSH private key: %s",
                  key_path);
        free(out);
        return -1;
    }
    free(out);
    return 0;
}

/* Prove that OpenSSH can parse the exact admitted key generation without
 * decrypting it. `ssh-keygen -lf` accepts encrypted private keys without an
 * askpass interaction, unlike `ssh-keygen -y` or `ssh-add`.
 *
 * Linux exposes a sealed anonymous copy through procfs, so no pathname is
 * created and the parser cannot observe a concurrent rewrite of the admitted
 * inode. Darwin and FreeBSD use the portable scrubbed-scratch machinery above
 * inside one bounded, reusable private staging directory per runtime
 * parent/user. Its private lock serializes cooperating writers and makes
 * Darwin's pathname cleanup boundary explicit. A fixed NAME_MAX slot bounds
 * an uncatchable-crash remnant to one entry, which the next locked validation
 * scrubs and retires before reuse. This is validation staging, not SSH agent
 * runtime state. */
static int ssh_key_snapshot_require_openssh_parse(
    const char *key_path, ssh_key_snapshot_t *snapshot) {
#if !defined(__linux__)
    char runtime_parent[MAX_PATH_LEN];
    char child[64];
    int parent_fd = -1;
    int dir_fd = -1;
    int lock_fd = -1;
    int rc = -1;
    bool owns_signal_guard = false;
    bool signal_guard_was_active;
    int written;

    signal_guard_was_active = signals_guard_active();
    if (signals_guard_begin() != 0) {
        return -1;
    }
    owns_signal_guard = !signal_guard_was_active;
    parent_fd = open_runtime_parent(
        runtime_parent, sizeof(runtime_parent));
    if (parent_fd < 0) {
        goto finish;
    }
    if (strcmp(runtime_parent, "/tmp") == 0) {
        written = snprintf(child, sizeof(child),
                           "gitswitch-key-validation-%d", getuid());
    } else {
        written = snprintf(child, sizeof(child),
                           "gitswitch-key-validation");
    }
    if (written < 0 || (size_t)written >= sizeof(child)) {
        set_error(ERR_INVALID_PATH,
                  "SSH key validation staging path is too long");
        goto finish;
    }
    dir_fd = open_private_subdir_at(parent_fd, child, true, NULL);
    close(parent_fd);
    parent_fd = -1;
    if (dir_fd < 0) goto finish;
    lock_fd = lock_private_file_at(dir_fd, ".lock");
    if (lock_fd < 0) {
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot lock private SSH key validation staging");
        goto finish;
    }
    rc = ssh_key_fingerprint_generation(
        dir_fd, true, key_path, snapshot,
        snapshot->fingerprint, sizeof(snapshot->fingerprint));
    snapshot->fingerprint_valid = rc == 0;
    if (verify_private_lock_file_at(lock_fd, dir_fd, ".lock") != 0) {
        rc = -1;
        set_system_error(ERR_SSH_KEY_INVALID,
                         "SSH key validation staging lock changed unexpectedly");
    }
finish:
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (dir_fd >= 0 && close(dir_fd) != 0 && rc == 0) {
        rc = -1;
        set_system_error(ERR_SSH_KEY_INVALID,
                         "Cannot close SSH key validation staging");
    }
    if (parent_fd >= 0) close(parent_fd);
    if (owns_signal_guard) {
        int guard_rc;

        if (signals_pending()) {
            guard_rc = signals_dispatch_pending();
        } else {
            guard_rc = signals_guard_end();
            if (guard_rc == 0 && signals_pending()) {
                guard_rc = signals_dispatch_pending();
            }
        }
        if (guard_rc != 0) rc = -1;
    }
    snapshot->fingerprint_valid = rc == 0;
    if (!snapshot->fingerprint_valid) {
        secure_zero_memory(
            snapshot->fingerprint, sizeof(snapshot->fingerprint));
    }
    return rc;
#else
    int rc = ssh_key_fingerprint_generation(
        -1, false, key_path, snapshot,
        snapshot->fingerprint, sizeof(snapshot->fingerprint));
    snapshot->fingerprint_valid = rc == 0;
    if (!snapshot->fingerprint_valid) {
        secure_zero_memory(
            snapshot->fingerprint, sizeof(snapshot->fingerprint));
    }
    return rc;
#endif
}

static bool ssh_agent_type_is_certificate(const char *type, size_t length) {
    static const char suffix[] = "-CERT";
    const size_t suffix_length = sizeof(suffix) - 1U;

    if (!type || length < suffix_length) return false;
    type += length - suffix_length;
    for (size_t i = 0; i < suffix_length; i++) {
        unsigned char actual = (unsigned char)type[i];
        unsigned char expected = (unsigned char)suffix[i];

        if (actual >= (unsigned char)'a' && actual <= (unsigned char)'z') {
            actual = (unsigned char)(actual - (unsigned char)'a' +
                                     (unsigned char)'A');
        }
        if (actual != expected) return false;
    }
    return true;
}

/* Parse one complete `ssh-add -l` record and copy its whole fingerprint.
 * OpenSSH deliberately fingerprints a certificate as its underlying plain
 * public key, so fingerprint equality alone cannot prove that a configured
 * raw private key is loaded. The terminal type is generated by the local
 * ssh-add (not copied from the agent comment); require it to be explicit and
 * non-certificate. Any second physical record, control data, missing field,
 * or malformed terminal type makes the proof indeterminate and fails closed. */
static bool ssh_agent_raw_identity_fingerprint(
    const char *listing, size_t listing_length,
    char *fingerprint, size_t fingerprint_size) {
    const char *end;
    const char *cursor;
    const char *bits;
    const char *fingerprint_start;
    const char *type_open;
    const char *type_close;
    size_t fingerprint_length;
    size_t type_length;

    if (!listing || listing_length == 0U || !fingerprint ||
        fingerprint_size == 0U ||
        memchr(listing, '\0', listing_length) != NULL) {
        return false;
    }

    end = listing + listing_length;
    if (end[-1] == '\n') end--;
    if (end == listing || memchr(listing, '\n', (size_t)(end - listing))) {
        return false;
    }
    for (cursor = listing; cursor < end; cursor++) {
        unsigned char byte = (unsigned char)*cursor;
        if ((byte < 0x20U && byte != (unsigned char)'\t') || byte == 0x7fU) {
            return false;
        }
    }

    /* Field 1 is the decimal key size. Leading whitespace and non-digits are
     * not canonical ssh-add output and must not be silently skipped. */
    bits = listing;
    cursor = bits;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') {
        if (*cursor < '0' || *cursor > '9') return false;
        cursor++;
    }
    if (cursor == bits || cursor == end) return false;
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;

    /* Field 2 is compared later against the admitted generation's complete
     * fingerprint token. Keep comments out of the comparison. */
    fingerprint_start = cursor;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') cursor++;
    fingerprint_length = (size_t)(cursor - fingerprint_start);
    if (fingerprint_length == 0U || fingerprint_length >= fingerprint_size ||
        cursor == end) {
        return false;
    }
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;
    if (cursor == end || end[-1] != ')') return false;

    type_close = end - 1;
    type_open = type_close;
    while (type_open > cursor && type_open[-1] != '(') type_open--;
    if (type_open == cursor || type_open[-1] != '(') return false;
    type_open--;
    if (type_open == listing ||
        (type_open[-1] != ' ' && type_open[-1] != '\t')) {
        return false;
    }
    type_length = (size_t)(type_close - (type_open + 1));
    if (type_length == 0U) return false;
    for (const char *p = type_open + 1; p < type_close; p++) {
        unsigned char byte = (unsigned char)*p;
        if (byte <= 0x20U || byte >= 0x7fU || *p == '(' || *p == ')') {
            return false;
        }
    }
    if (ssh_agent_type_is_certificate(type_open + 1, type_length)) {
        return false;
    }

    memcpy(fingerprint, fingerprint_start, fingerprint_length);
    fingerprint[fingerprint_length] = '\0';
    return true;
}

/* Classify whether an ssh-agent is answering on `sock` AND holds EXACTLY the
 * raw key at `key_path` — one complete identity, fingerprint compared as a
 * whole token, explicit non-certificate type — so adopting it is safe and
 * skips a passphrase re-prompt. Presence alone is not enough (AR-03 M2): a foreign
 * key injected into the per-account agent
 * (`SSH_AUTH_SOCK=current.sock ssh-add ~/.ssh/other_key`) would ride along
 * into the "isolated" session and let a push authenticate as the wrong
 * identity, so any extra identity refuses the reuse — the caller then kills
 * and restarts, loading only the account's key. A live agent holding a
 * *different* key — e.g. after `gitswitch edit` changed the key path — is
 * refused for the same reason. The agent is probed FIRST and the expected
 * fingerprint computed only once the probe answers (AR-03 L18): a stale
 * socket (dead agent) is the common miss, and running ssh-keygen before
 * knowing the agent is alive wasted a fork+exec on every such miss. Anything
 * indeterminate refuses adoption. A definite identity/fingerprint mismatch
 * authorizes replacement; helper, staging, signal, or admitted-generation
 * failures return ERROR so activation cannot destructively reinterpret an
 * operational failure as a mismatch. */
static ssh_key_generation_match_t ssh_agent_has_exact_key_generation(
    int dir_fd, bool use_cwd_fd, const char *socket_arg,
    const char *key_path, ssh_key_snapshot_t *snapshot) {
    char want_fp[256];
    char agent_fp[256];
    char envbuf[MAX_PATH_LEN + 20];
    char out[2048];
    const char *env[2] = { NULL, NULL };
    const char *argv[] = { "ssh-add", "-l", NULL };
    run_opts_t opts;
    run_result_t res;
    uint64_t run_error_generation;

    if (!socket_arg || !*socket_arg || !key_path || !*key_path ||
        (snapshot && (!snapshot->data || snapshot->length == 0)) ||
        (size_t)snprintf(envbuf, sizeof(envbuf), "SSH_AUTH_SOCK=%s",
                         socket_arg) >= sizeof(envbuf)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH key-generation match arguments");
        return SSH_KEY_GENERATION_ERROR;
    }
    env[0] = envbuf;
    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    res.exit_code = -1;
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    opts.extra_env = env;
    opts.cwd_fd = dir_fd;
    opts.use_cwd_fd = use_cwd_fd;
    run_error_generation = error_report_generation();
    if (run_argv(argv, &opts, &res) != 0) {
        if (error_report_generation() != run_error_generation) {
            return SSH_KEY_GENERATION_ERROR;
        }
        if (res.spawned && res.term_signal == 0 &&
            (res.exit_code == 1 || res.exit_code == 2)) {
            /* OpenSSH: no identities or no reachable agent. */
            return SSH_KEY_GENERATION_MISMATCH;
        }
        if (res.spawned && res.term_signal != 0) {
            set_error(ERR_SYSTEM_COMMAND_FAILED,
                      "SSH agent identity probe was terminated by signal %d",
                      res.term_signal);
        } else {
            set_error(ERR_SYSTEM_COMMAND_FAILED,
                      "SSH agent identity probe did not complete");
        }
        return SSH_KEY_GENERATION_ERROR;
    }
    /* An incomplete capture cannot prove single-key exclusivity. In
     * particular, a long first identity can fill this buffer while a second
     * (foreign) key is entirely beyond the visible prefix. */
    if (res.out_truncated || res.out_len >= sizeof(out) ||
        !ssh_agent_raw_identity_fingerprint(
            out, res.out_len, agent_fp, sizeof(agent_fp))) {
        return SSH_KEY_GENERATION_MISMATCH;
    }
    if (snapshot) {
        if ((!snapshot->fingerprint_valid &&
             ssh_key_snapshot_require_openssh_parse(
                 key_path, snapshot) != 0)) {
            return SSH_KEY_GENERATION_ERROR;
        }
        if (!ssh_key_snapshot_fd_matches(snapshot)) {
            set_error(ERR_SSH_KEY_INVALID,
                      "Admitted SSH key changed during agent verification");
            return SSH_KEY_GENERATION_ERROR;
        }
        return strcmp(agent_fp, snapshot->fingerprint) == 0
                   ? SSH_KEY_GENERATION_MATCH
                   : SSH_KEY_GENERATION_MISMATCH;
    }
    if (ssh_key_fingerprint_generation(
            dir_fd, use_cwd_fd, key_path, NULL, want_fp,
            sizeof(want_fp)) != 0) {
        return SSH_KEY_GENERATION_ERROR;
    }

    return strcmp(agent_fp, want_fp) == 0
               ? SSH_KEY_GENERATION_MATCH
               : SSH_KEY_GENERATION_MISMATCH;
}

static ssh_key_generation_match_t ssh_socket_has_key_generation(
    int dir_fd, const char *socket_arg, const char *key_path,
    ssh_key_snapshot_t *snapshot) {
    return ssh_agent_has_exact_key_generation(
        dir_fd, true, socket_arg, key_path, snapshot);
}

static bool ssh_socket_has_key(int dir_fd, const char *socket_arg,
                               const char *key_path) {
    return ssh_socket_has_key_generation(
               dir_fd, socket_arg, key_path, NULL) ==
           SSH_KEY_GENERATION_MATCH;
}

bool ssh_manager_test_socket_has_key(int dir_fd, const char *socket_arg,
                                     const char *key_path) {
    return ssh_socket_has_key(dir_fd, socket_arg, key_path);
}

static int reject_system_agent_mode(void) {
    set_error(
        ERR_INVALID_ARGS,
        "System SSH agent replacement mode is deprecated and unsupported: "
        "gitswitch cannot restore cleared private identities; use isolated "
        "or no-agent mode");
    return -1;
}

/* Initialize SSH manager */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL ssh_config to ssh_manager_init");
        return -1;
    }
    /* Retain the legacy enum token for source compatibility, but reject it
     * before touching caller storage or probing the host. The agent protocol
     * cannot export private identities, so `ssh-add -D` has no truthful
     * rollback if a later load, verification, or alias publication fails. */
    if (mode == SSH_AGENT_SYSTEM) return reject_system_agent_mode();
    
    log_debug("Initializing SSH manager with mode: %d", mode);
    
    /* Initialize structure */
    memset(ssh_config, 0, sizeof(ssh_config_t));
    ssh_config->mode = mode;
    ssh_config->agent_pid = -1;
    ssh_process_generation_clear(&ssh_config->agent_generation);
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
            return reject_system_agent_mode();
            
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

/* Cleanup SSH manager. A retryable owned-agent teardown retains its process
 * and artifact recovery handles instead of zeroing them. Once retirement is
 * conclusive, key-presence truth may already be false even if artifact
 * cleanup still needs a later retry. */
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
            log_warning("SSH manager cleanup retained agent recovery state for retry");
            return -1;
        }
    }
    
    /* Clear sensitive data */
    secure_zero_memory(ssh_config, sizeof(ssh_config_t));
    
    log_debug("SSH manager cleanup complete");
    return 0;
}

int ssh_key_admission_begin(const char *expanded_key_path,
                            ssh_key_admission_t **admission) {
    ssh_key_admission_t *prepared;
    size_t path_length;

    if (!expanded_key_path || !*expanded_key_path || !admission ||
        *admission) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH key admission arguments");
        return -1;
    }
    path_length = strnlen(expanded_key_path, MAX_PATH_LEN);
    if (path_length == MAX_PATH_LEN) {
        set_error(ERR_INVALID_PATH,
                  "Expanded SSH key path exceeds the supported limit");
        return -1;
    }
    prepared = calloc(1, sizeof(*prepared));
    if (!prepared) {
        errno = ENOMEM;
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate SSH key admission state");
        return -1;
    }
    memcpy(prepared->expanded_key_path, expanded_key_path, path_length + 1U);
    if (ssh_key_snapshot_capture(
            prepared->expanded_key_path, &prepared->snapshot) != 0 ||
        ssh_key_snapshot_require_openssh_parse(
            prepared->expanded_key_path, &prepared->snapshot) != 0) {
        ssh_key_admission_end(&prepared);
        return -1;
    }
    *admission = prepared;
    return 0;
}

/* Prove the configured name still selects the generation that OpenSSH parsed.
 * Once this point-in-time namespace proof succeeds, close the mutable source
 * descriptor. Activation is then bound only to the retained private bytes and
 * cached fingerprint, so a later source replacement cannot substitute a key
 * or create a post-teardown parse failure. */
int ssh_key_admission_verify_named(ssh_key_admission_t *admission) {
    struct stat named;
    int named_fd;
    int close_rc;

    if (!admission || admission->named_generation_verified ||
        admission->snapshot.source_detached ||
        !admission->snapshot.fingerprint_valid) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid or already-consumed SSH key admission");
        return -1;
    }
    named_fd = g_ssh_key_open(
        admission->expanded_key_path,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (named_fd < 0) {
        errno = ESTALE;
        set_error(
            ERR_SSH_KEY_INVALID,
            "SSH key path changed after OpenSSH validation: %s",
            admission->expanded_key_path);
        return -1;
    }
    if (fstat(named_fd, &named) != 0 ||
        !same_runtime_identity(&admission->snapshot.identity, &named) ||
        admission->snapshot.identity.st_gid != named.st_gid ||
        named.st_size < 0 ||
        (uintmax_t)named.st_size != admission->snapshot.length ||
        !ssh_key_snapshot_fd_matches(&admission->snapshot)) {
        int saved_errno = errno;

        (void)close(named_fd);
        errno = saved_errno ? saved_errno : ESTALE;
        set_error(
            ERR_SSH_KEY_INVALID,
            "SSH key path changed after OpenSSH validation: %s",
            admission->expanded_key_path);
        return -1;
    }
    close_rc = close(named_fd);
    if (close_rc != 0) {
        set_system_error(
            ERR_SYSTEM_CALL,
            "Cannot close the verified SSH key namespace descriptor");
        return -1;
    }

    close_rc = close(admission->snapshot.fd);
    admission->snapshot.fd = -1;
    admission->snapshot.fd_open = false;
    if (close_rc != 0) {
        set_system_error(
            ERR_SYSTEM_CALL,
            "Cannot detach the admitted SSH key generation");
        return -1;
    }
    admission->snapshot.source_detached = true;
    admission->named_generation_verified = true;
    return 0;
}

void ssh_key_admission_end(ssh_key_admission_t **admission) {
    error_context_t saved_error;
    int saved_errno;

    if (!admission || !*admission) return;
    saved_error = *get_last_error();
    saved_errno = errno;
    ssh_key_snapshot_clear(&(*admission)->snapshot);
    secure_zero_memory(*admission, sizeof(**admission));
    free(*admission);
    *admission = NULL;
    g_last_error = saved_error;
    errno = saved_errno;
}

/* Switch using the exact generation retained by account-layer admission. */
int ssh_switch_account_admitted(ssh_config_t *ssh_config,
                                const account_t *account,
                                ssh_key_admission_t *admission) {
    char expanded_key_path[MAX_PATH_LEN];
    ssh_key_snapshot_t *key_snapshot;
    int rc = -1;

    if (!ssh_config || !account || !admission) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to ssh_switch_account_admitted");
        return -1;
    }
    if (ssh_config->mode == SSH_AGENT_SYSTEM) {
        return reject_system_agent_mode();
    }
    if (!account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        set_error(ERR_INVALID_ARGS,
                  "SSH key admission supplied for an account without SSH");
        return -1;
    }
    if (expand_path(account->ssh_key_path, expanded_key_path,
                    sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH,
                  "Failed to expand SSH key path: %s",
                  account->ssh_key_path);
        return -1;
    }
    if (strcmp(expanded_key_path, admission->expanded_key_path) != 0 ||
        !admission->named_generation_verified ||
        !admission->snapshot.source_detached ||
        !admission->snapshot.fingerprint_valid ||
        !ssh_key_snapshot_fd_matches(&admission->snapshot)) {
        set_error(
            ERR_SSH_KEY_INVALID,
            "SSH activation does not match the admitted key generation");
        return -1;
    }
    key_snapshot = &admission->snapshot;
    log_info("Switching SSH configuration for account: %s", account->name);

    /* Handle based on mode */
    switch (ssh_config->mode) {
        case SSH_AGENT_SYSTEM:
            rc = reject_system_agent_mode();
            goto done;
            
        case SSH_AGENT_ISOLATED:
            /* Start the isolated agent and load its key while the socket
             * directory remains descriptor-pinned and manager-locked. */
            if (ssh_start_isolated_agent_with_key(
                    ssh_config, account, key_snapshot) != 0) {
                goto done; /* Error already set */
            }
            break;
            
        case SSH_AGENT_NONE:
            /* Admission already proved that OpenSSH parses this generation. */
            log_info("SSH agent management disabled - key validated but not loaded");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode");
            goto done;
    }
    
    /* A requested alias is part of the account's SSH routing contract. If the
     * managed block cannot be installed safely, fail the switch so the account
     * layer rolls back the agent/runtime commit instead of claiming success
     * with stale user SSH configuration.
     *
     * AR-12 U2 (adjudicated, kept): this one-call library path deliberately
     * folds every alias-install outcome into pass/fail — an
     * installed-but-uncertain publication reports failure and the runtime
     * rolls back around the (benign) already-public block. The CLI's
     * prepared/commit path uses ssh_configure_host_alias_result to
     * distinguish retained commits; direct callers keep the simpler
     * historical contract. */
    if (strlen(account->ssh_host_alias) > 0) {
        if (ssh_configure_host_alias(account) != 0) {
            log_warning("Failed to configure SSH host alias: %s", account->ssh_host_alias);
            goto done;
        }
    }
    
    log_info("SSH configuration switched successfully for account: %s", account->name);
    rc = 0;
done:
    return rc;
}

/* Source-compatible one-call entry point. It creates the same exact-generation
 * admission used by the account transaction, verifies the configured name
 * before manager mutation, and destroys the sensitive handle on every path. */
int ssh_switch_account(ssh_config_t *ssh_config, const account_t *account) {
    char expanded_key_path[MAX_PATH_LEN];
    ssh_key_admission_t *admission = NULL;
    int rc;

    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_switch_account");
        return -1;
    }
    if (ssh_config->mode == SSH_AGENT_SYSTEM) {
        return reject_system_agent_mode();
    }
    if (!account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        log_debug("SSH not enabled for account: %s", account->name);
        return 0;
    }
    if (expand_path(account->ssh_key_path, expanded_key_path,
                    sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH,
                  "Failed to expand SSH key path: %s",
                  account->ssh_key_path);
        return -1;
    }
    if (ssh_key_admission_begin(expanded_key_path, &admission) != 0 ||
        ssh_key_admission_verify_named(admission) != 0) {
        ssh_key_admission_end(&admission);
        return -1;
    }
    rc = ssh_switch_account_admitted(ssh_config, account, admission);
    ssh_key_admission_end(&admission);
    return rc;
}

/* Start isolated SSH agent */
int ssh_start_isolated_agent(ssh_config_t *ssh_config, const account_t *account) {
    ssh_key_snapshot_t key_snapshot;
    char expanded_key_path[MAX_PATH_LEN];
    int rc;

    memset(&key_snapshot, 0, sizeof(key_snapshot));
    if (!ssh_config || !account || !account->ssh_enabled ||
        account->ssh_key_path[0] == '\0') {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to ssh_start_isolated_agent");
        return -1;
    }
    if (expand_path(account->ssh_key_path, expanded_key_path,
                    sizeof(expanded_key_path)) != 0 ||
        ssh_key_snapshot_capture(expanded_key_path, &key_snapshot) != 0) {
        ssh_key_snapshot_clear(&key_snapshot);
        return -1;
    }
    rc = ssh_start_isolated_agent_with_key(ssh_config, account, &key_snapshot);
    ssh_key_snapshot_clear(&key_snapshot);
    return rc;
}

static int ssh_start_isolated_agent_with_key(
    ssh_config_t *ssh_config, const account_t *account,
    ssh_key_snapshot_t *snapshot) {
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
    error_context_t causal_match_error;
    run_launch_witness_t agent_launch_witness;
    size_t launch_output_len = 0U;
    bool launch_output_truncated = false;
    bool preserve_causal_match_error = false;
    int causal_match_errno = 0;
    int dir_fd = -1;
    bool prior_key_names_reuse_target = false;

    ssh_runtime_pin_init(&reuse_pin);
    memset(&causal_match_error, 0, sizeof(causal_match_error));
    memset(&agent_launch_witness, 0, sizeof(agent_launch_witness));

    if (!ssh_config || !account || !snapshot) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_start_isolated_agent");
        return -1;
    }
    /* Activation outcome, not key presence: publish true only through the
     * committed adoption path below. A failed retry must never retain a stale
     * reuse decision from an earlier successful call. */
    ssh_config->reused_existing_agent = false;

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
    prior_key_names_reuse_target = ssh_config->key_already_loaded &&
        strcmp(ssh_config->agent_socket_path, socket_path) == 0;
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
                ssh_key_generation_match_t match =
                    ssh_socket_has_key_generation(
                    dir_fd, socket_name, reuse_key_path, snapshot);
                if (match == SSH_KEY_GENERATION_ERROR) {
                    causal_match_error = *get_last_error();
                    causal_match_errno = errno;
                    preserve_causal_match_error = true;
                    goto done;
                }
                can_reuse = match == SSH_KEY_GENERATION_MATCH;
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

    /* Complete switch admission already parsed and cached its retained
     * generation. The low-level legacy entry point can still arrive with only
     * a captured shape: a canonical live-agent listing parses before it can
     * authorize reuse, and every other path performs the same full OpenSSH
     * parse here before orphan cleanup or prior-agent retirement. */
    if (!snapshot->fingerprint_valid &&
        ssh_key_snapshot_require_openssh_parse(
            reuse_key_path, snapshot) != 0) {
        goto done;
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
        ssh_process_generation_clear(&adopted.agent_generation);
        memset(&adopted.agent_image, 0, sizeof(adopted.agent_image));
        adopted.agent_owned = false;
        adopted.key_already_loaded = true;
        adopted.reused_existing_agent = true;

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
            ssh_agent_record_t record;
            memset(&record, 0, sizeof(record));
            ssh_pid_sidecar_result_t pid_rc = read_ssh_agent_pid_at(
                dir_fd, pid_name, pid_path, &record, NULL);
            if (pid_rc == SSH_PID_SIDECAR_VALID) {
                ssh_process_outcome_t identity =
                    pid_is_our_ssh_agent(&record, socket_path, -1);
                if (identity == SSH_PROCESS_OWNED) {
                    adopted.agent_pid = record.pid;
                    adopted.agent_generation = record.generation;
                    adopted.agent_image = record.image;
                    adopted.agent_owned = true;
                    safe_strncpy(
                        adopted.agent_socket_arg,
                        launch_socket_arg,
                        sizeof(adopted.agent_socket_arg));
                }
            } else if (pid_rc == SSH_PID_SIDECAR_MALFORMED ||
                       pid_rc == SSH_PID_SIDECAR_LEGACY) {
                set_error(
                    ERR_FILE_IO,
                    "Invalid SSH agent PID sidecar; retained for retry: %s",
                    pid_path);
                goto done;
            } else if (pid_rc == SSH_PID_SIDECAR_ERROR) {
                goto done;
            } else if (pid_rc == SSH_PID_SIDECAR_ABSENT) {
                /* Fingerprint-qualified reuse remains explicitly unowned. */
            } else {
                set_error(ERR_FILE_IO,
                          "Unexpected SSH agent PID sidecar classification");
                goto done;
            }
        }

        /* Enforce one-account isolation before publishing this reused agent.
         * Cleanup failures are retained-state failures, not warnings: adopting
         * this agent while another managed listener cannot be classified or
         * reaped would violate the isolation promise. Running this before the
         * environment/link commit also leaves the prior stable link untouched
         * on failure. */
        if (!prior_key_names_reuse_target) {
            ssh_config->key_already_loaded = false;
        }
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
    ssh_config->key_already_loaded = false;
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
        struct stat launched_socket;
        run_result_t launch_result;
        char agent_program[MAX_PATH_LEN];
        char runner_detail[sizeof(g_last_error.message)] = "";
        int run_rc;
        if (find_command_path("ssh-agent", agent_program,
                              sizeof(agent_program)) != 0 ||
            !run_launch_witness_capture(
                agent_program, &agent_launch_witness) ||
            !process_image_from_launch_witness(
                &agent_launch_witness, &ssh_config->agent_image)) {
            set_error(ERR_SSH_AGENT_NOT_FOUND,
                      "No trusted native SSH agent executable is available");
            goto done;
        }
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
        /* A runner failure after fork does not prove ssh-agent failed to
         * daemonize. Clear any prior in-memory handle before launch, retain
         * the runner's spawned bit/output, and recover the exact managed
         * socket below if the launch outcome is ambiguous. */
        ssh_config->agent_pid = -1;
        ssh_process_generation_clear(&ssh_config->agent_generation);
        ssh_config->agent_owned = false;
        ssh_config->agent_socket_path[0] = '\0';
        ssh_config->agent_socket_arg[0] = '\0';
        memset(&launch_result, 0, sizeof(launch_result));
        launch_result.exit_code = -1;
        clear_error();
        {
            const char *const launch_argv[] = {
                agent_program, "-s", "-a", launch_socket_arg, NULL
            };
            run_opts_t launch_opts;

            memset(&launch_opts, 0, sizeof(launch_opts));
            launch_opts.out = output;
            launch_opts.out_size = sizeof(output);
            launch_opts.cwd_fd = dir_fd;
            launch_opts.use_cwd_fd = true;
            run_rc = run_argv_with_expected_launch(
                launch_argv, &launch_opts, &agent_launch_witness,
                &launch_result);
            if (launch_result.out_len > 0 &&
                launch_result.out_len < sizeof(output) &&
                output[launch_result.out_len - 1U] == '\n') {
                launch_result.out_len--;
                output[launch_result.out_len] = '\0';
            }
            launch_output_len = launch_result.out_len;
            launch_output_truncated = launch_result.out_truncated;
        }
        if (unlinkat(dir_fd, provenance_marker, AT_REMOVEDIR) != 0 &&
            errno != ENOENT) {
            log_warning("Could not remove temporary SSH provenance marker: %s",
                        provenance_marker);
        }
        if (run_rc != 0) {
            pid_t recovery_pid = -1;
            int socket_rc = fstatat(dir_fd, socket_name, &launched_socket,
                                    AT_SYMLINK_NOFOLLOW);
            int socket_errno = socket_rc == 0 ? 0 : errno;
            bool socket_may_exist =
                socket_rc == 0 || socket_errno != ENOENT;
            bool have_recovery_pid =
                launch_result.out_len < sizeof(output) &&
                parse_complete_ssh_agent_pid(
                    output, launch_result.out_len,
                    launch_result.out_truncated, &recovery_pid);

            safe_strncpy(runner_detail, get_last_error()->message,
                         sizeof(runner_detail));

            if (launch_result.spawned || socket_may_exist ||
                have_recovery_pid) {
                ssh_unrecorded_result_t recovery;

                /* Even when the runner itself failed, a complete captured
                 * assignment may identify the daemon. Never feed partial
                 * failure output through the activation parser: a truncated
                 * numeric prefix could target the wrong PID, make its identity
                 * look unrelated, and unlink the real daemon's last socket. */
                if (have_recovery_pid) {
                    ssh_config->agent_pid = recovery_pid;
                    (void)g_reap_ops.generation(
                        recovery_pid, &ssh_config->agent_generation);
                }
                safe_strncpy(ssh_config->agent_socket_path, socket_path,
                             sizeof(ssh_config->agent_socket_path));
                safe_strncpy(ssh_config->agent_socket_arg,
                             launch_socket_arg,
                             sizeof(ssh_config->agent_socket_arg));
                recovery = reap_unrecorded_agent(
                    ssh_config, launch_socket_arg, dir_fd,
                    socket_name, pid_name, pid_path, socket_path, socket_dir);
                apply_unrecorded_result(ssh_config, recovery);
                char summary[192];
                (void)snprintf(
                    summary, sizeof(summary),
                    "SSH agent runner failed after an ambiguous launch; %s",
                    unrecorded_result_summary(recovery));
                if (runner_detail[0] != '\0') {
                    set_error(ERR_SSH_AGENT_START_FAILED, "%s: %s",
                              summary, runner_detail);
                } else {
                    set_error(ERR_SSH_AGENT_START_FAILED, "%s", summary);
                }
            } else {
                if (runner_detail[0] != '\0') {
                    set_error(ERR_SSH_AGENT_START_FAILED,
                              "Failed to start SSH agent before spawn: %s",
                              runner_detail);
                } else {
                    set_error(ERR_SSH_AGENT_START_FAILED,
                              "Failed to start SSH agent before spawn");
                }
            }
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
    if (parse_ssh_agent_output(output, launch_output_len,
                               launch_output_truncated, ssh_config) != 0) {
        ssh_unrecorded_result_t recovery;
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
        recovery = reap_unrecorded_agent(
            ssh_config, launch_socket_arg, dir_fd, socket_name,
            pid_name, pid_path, socket_path, socket_dir);
        apply_unrecorded_result(ssh_config, recovery);
        set_error(ERR_SSH_AGENT_START_FAILED,
                  "Failed to parse ssh-agent output; %s",
                  unrecorded_result_summary(recovery));
        goto done;
    }
    safe_strncpy(ssh_config->agent_socket_path, socket_path,
                 sizeof(ssh_config->agent_socket_path));
    safe_strncpy(ssh_config->agent_socket_arg, launch_socket_arg,
                 sizeof(ssh_config->agent_socket_arg));
    if (g_reap_ops.generation(
            ssh_config->agent_pid, &ssh_config->agent_generation) != 0) {
        ssh_unrecorded_result_t recovery = reap_unrecorded_agent(
            ssh_config, launch_socket_arg, dir_fd, socket_name,
            pid_name, pid_path, socket_path, socket_dir);
        apply_unrecorded_result(ssh_config, recovery);
        set_error(ERR_SSH_AGENT_START_FAILED,
                  "Cannot capture SSH agent process generation; %s",
                  unrecorded_result_summary(recovery));
        goto done;
    }

    /* Validate the agent is working */
    if (validate_ssh_agent_socket_at(dir_fd, socket_name, socket_path,
                                     NULL) != 0) {
        ssh_unrecorded_result_t recovery;
        set_error(ERR_SSH_AGENT_START_FAILED, "SSH agent socket validation failed");
        /* Same pre-sidecar leak shape as the parse failure above, but the
         * parsed PID is known here, so the reap targets it directly. */
        recovery = reap_unrecorded_agent(
            ssh_config, launch_socket_arg, dir_fd, socket_name,
            pid_name, pid_path, socket_path, socket_dir);
        apply_unrecorded_result(ssh_config, recovery);
        set_error(ERR_SSH_AGENT_START_FAILED,
                  "SSH agent socket validation failed; %s",
                  unrecorded_result_summary(recovery));
        goto done;
    }
    if (inspect_socket_peer(
            socket_path, dir_fd,
            &ssh_config->agent_image.socket_peer_pid,
            &ssh_config->agent_image.socket_peer_uid) != 0 ||
        ssh_config->agent_image.socket_peer_uid != geteuid()) {
        ssh_unrecorded_result_t recovery = reap_unrecorded_agent(
            ssh_config, launch_socket_arg, dir_fd, socket_name,
            pid_name, pid_path, socket_path, socket_dir);
        apply_unrecorded_result(ssh_config, recovery);
        set_error(
            ERR_SSH_AGENT_START_FAILED,
            "Cannot bind SSH agent launch to its kernel socket credential; %s",
            unrecorded_result_summary(recovery));
        goto done;
    }

    /* The runner used only the pinned cwd + provenance-qualified relative
     * socket entry. If the public directory was replaced while it ran, reap
     * that pinned agent and refuse to split its sidecar/link/environment into
     * another namespace. */
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
        ssh_unrecorded_result_t recovery = reap_unrecorded_agent(
            ssh_config, launch_socket_arg, dir_fd, socket_name,
            pid_name, pid_path, socket_path, socket_dir);
        apply_unrecorded_result(ssh_config, recovery);
        goto done;
    }

    /* Mark as owned */
    ssh_config->agent_owned = true;

    /* Record the exact agent process in a sidecar so a later invocation can
     * safely terminate it or perform an eligible native endpoint retirement.
     * This is FATAL on failure: without the record, future cleanup cannot
     * authorize either operation for a key-holding process. */
    {
        bool recorded = false;
        ssh_agent_record_t record = {
            .pid = ssh_config->agent_pid,
            .generation = ssh_config->agent_generation,
            .image = ssh_config->agent_image
        };
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            recorded = write_ssh_agent_pid_at(dir_fd, pid_name,
                                               &record) == 0;
        }
        pid_recorded = recorded;
        if (!recorded) {
            char detail[sizeof(g_last_error.message)];
            ssh_process_outcome_t reap_outcome = SSH_PROCESS_INDETERMINATE;
            bool exact_record_recovered = false;
            bool runtime_cleaned = false;

            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            if (pid_path[0] != '\0') {
                exact_record_recovered = recover_exact_ssh_agent_record_at(
                    dir_fd, pid_name, pid_path, &record);
            }
            if (exact_record_recovered) {
                pid_recorded = true;
                ssh_config->agent_owned = true;
                set_error(
                    ERR_FILE_IO,
                    "Failed to record SSH agent PID; exact durable record "
                    "recovered and agent retained for retry: %s",
                    detail[0] ? detail : "sidecar commit failed");
                goto done;
            }

            reap_outcome = g_ssh_reap(&record, socket_path, dir_fd);
            runtime_cleaned =
                ssh_reap_allows_cleanup(reap_outcome) &&
                retire_reaped_socket_if_dead(
                    dir_fd, socket_dir, socket_name, socket_path,
                    "agent socket cleanup after sidecar failure") == 0;
            ssh_config->agent_pid = -1;
            ssh_process_generation_clear(&ssh_config->agent_generation);
            memset(&ssh_config->agent_image, 0,
                   sizeof(ssh_config->agent_image));
            ssh_config->agent_owned = false;
            if (runtime_cleaned) {
                ssh_config->agent_socket_path[0] = '\0';
                ssh_config->agent_socket_arg[0] = '\0';
            } else {
                log_warning("SSH agent reap/socket outcome %s after PID-sidecar failure; runtime artifact retained unowned for retry",
                            ssh_process_outcome_name(reap_outcome));
            }
            set_error(ERR_FILE_IO,
                      "Failed to record SSH agent PID; %s: %s",
                      runtime_cleaned
                          ? "agent runtime retired"
                          : "runtime artifact retained unowned for retry",
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
    {
        ssh_key_generation_match_t match =
            ssh_socket_has_key_generation(
                dir_fd, socket_name, reuse_key_path, snapshot);
        if (match == SSH_KEY_GENERATION_ERROR) {
            causal_match_error = *get_last_error();
            causal_match_errno = errno;
            preserve_causal_match_error = true;
            goto fresh_commit_failed;
        }
        if (match != SSH_KEY_GENERATION_MATCH) {
            set_error(ERR_SSH_KEY_LOAD_FAILED,
                      "Fresh isolated SSH agent does not contain exactly the "
                      "requested key");
            goto fresh_commit_failed;
        }
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
        ssh_agent_record_t record = {
            .pid = ssh_config->agent_pid,
            .generation = ssh_config->agent_generation,
            .image = ssh_config->agent_image
        };
        ssh_process_outcome_t reap_outcome = g_ssh_reap(
            &record, socket_path, dir_fd);
        if (ssh_reap_allows_cleanup(reap_outcome)) {
            if (retire_reaped_socket_if_dead(
                    dir_fd, socket_dir, socket_name, socket_path,
                    "agent socket cleanup after failed publication") != 0) {
                agent_retained = true;
            } else if (pid_recorded &&
                       unlink_ssh_runtime_entry(
                    dir_fd, pid_name, true,
                    "PID sidecar cleanup after failed publication") != 0) {
                agent_retained = true;
            }
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
        ssh_process_generation_clear(&ssh_config->agent_generation);
        memset(&ssh_config->agent_image, 0,
               sizeof(ssh_config->agent_image));
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
    if (preserve_causal_match_error) {
        g_last_error = causal_match_error;
        errno = causal_match_errno;
    }
    return rc;
}

/* Bind stop, reap, and recovery-name retirement to one locked runtime
 * namespace and one exact persisted process generation. */
static int cleanup_stopped_agent_runtime(ssh_config_t *ssh_config) {
    static const char socket_suffix[] = ".sock";
    char expected_dir[MAX_PATH_LEN];
    char runtime_dir[MAX_PATH_LEN];
    char socket_name[MAX_NAME_LEN + 32];
    char pid_name[MAX_NAME_LEN + 32];
    char pid_path[MAX_PATH_LEN];
    const char *slash;
    size_t dir_len;
    size_t socket_len;
    size_t pid_base_len;
    ssh_runtime_pin_t socket_pin;
    ssh_runtime_pin_t pid_pin;
    ssh_agent_record_t recorded;
    bool dir_absent = false;
    bool socket_present = false;
    bool pid_present = false;
    bool recorded_endpoint_retired = false;
    bool recorded_endpoint_detached = false;
    bool primary_failure = false;
    error_context_t primary_error;
    int primary_errno = 0;
    int dir_fd = -1;
    int lock_fd = -1;
    int rc = -1;
    int socket_rc;
    ssh_pid_sidecar_result_t pid_rc;

    ssh_runtime_pin_init(&socket_pin);
    ssh_runtime_pin_init(&pid_pin);
    memset(&recorded, 0, sizeof(recorded));
    if (!ssh_config || ssh_config->agent_socket_path[0] == '\0') {
        set_error(ERR_INVALID_PATH,
                  "Cannot identify stopped SSH agent runtime for cleanup");
        return -1;
    }
    slash = strrchr(ssh_config->agent_socket_path, '/');
    if (!slash || slash == ssh_config->agent_socket_path ||
        slash[1] == '\0') {
        set_error(ERR_INVALID_PATH,
                  "Cannot identify SSH agent socket entry for durable cleanup");
        return -1;
    }
    dir_len = (size_t)(slash - ssh_config->agent_socket_path);
    if (dir_len >= sizeof(expected_dir)) {
        set_error(ERR_INVALID_PATH, "SSH agent runtime directory is too long");
        return -1;
    }
    memcpy(expected_dir, ssh_config->agent_socket_path, dir_len);
    expected_dir[dir_len] = '\0';
    if (!target_is_exact_managed_socket(
            expected_dir, ssh_config->agent_socket_path, socket_name,
            sizeof(socket_name))) {
        set_error(ERR_INVALID_PATH,
                  "Stopped SSH agent socket is not an exact managed entry");
        return -1;
    }
    socket_len = strlen(socket_name);
    if (socket_len <= sizeof(socket_suffix) - 1U ||
        strcmp(socket_name + socket_len - (sizeof(socket_suffix) - 1U),
               socket_suffix) != 0) {
        set_error(ERR_INVALID_PATH, "Invalid managed SSH socket suffix");
        return -1;
    }
    pid_base_len = socket_len - (sizeof(socket_suffix) - 1U);
    if ((size_t)snprintf(pid_name, sizeof(pid_name), "%.*s.pid",
                         (int)pid_base_len, socket_name) >= sizeof(pid_name) ||
        (size_t)snprintf(pid_path, sizeof(pid_path), "%s/%s", expected_dir,
                         pid_name) >= sizeof(pid_path)) {
        set_error(ERR_INVALID_PATH, "SSH agent PID sidecar path is too long");
        return -1;
    }

    runtime_dir[0] = '\0';
    dir_fd = open_isolated_agent_socket_dir(runtime_dir, sizeof(runtime_dir),
                                            false, &dir_absent);
    if (runtime_dir[0] != '\0' && strcmp(runtime_dir, expected_dir) != 0) {
        if (dir_fd >= 0) close(dir_fd);
        set_error(ERR_FILE_IO,
                  "SSH runtime root changed before stopped-agent cleanup");
        return -1;
    }
    if (dir_fd < 0) {
        if (dir_absent) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "Owned SSH runtime has no durable process sidecar");
        }
        return -1;
    }
    lock_fd = lock_agent_dir(dir_fd);
    if (lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock SSH agent directory during stop");
        goto done;
    }
    if (verify_socket_dir_namespace(dir_fd, runtime_dir) != 0) goto done;
    if (reconcile_ssh_runtime_pins(dir_fd, runtime_dir) != 0) goto done;

    socket_rc = pin_ssh_runtime_entry_at(
        dir_fd, socket_name, ssh_config->agent_socket_path, &socket_pin);
    if (socket_rc < 0) goto done;
    socket_present = socket_rc == 0;
    if (socket_present &&
        (!S_ISSOCK(socket_pin.identity.st_mode) ||
         socket_pin.identity.st_uid != getuid() ||
         (socket_pin.identity.st_mode & 0777) != 0600 ||
         verify_ssh_runtime_pin_at(dir_fd, socket_name,
                                   ssh_config->agent_socket_path,
                                   &socket_pin) != 0)) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID,
                  "Stopped SSH agent socket changed or is unsafe: %s",
                  ssh_config->agent_socket_path);
        goto done;
    }

    pid_rc = read_ssh_agent_pid_at(dir_fd, pid_name, pid_path, &recorded,
                                   &pid_pin);
    if (pid_rc == SSH_PID_SIDECAR_ERROR) goto done;
    if (pid_rc == SSH_PID_SIDECAR_MALFORMED ||
        pid_rc == SSH_PID_SIDECAR_LEGACY) {
        set_error(ERR_FILE_IO,
                  "Invalid stopped SSH agent PID sidecar; retained for retry: %s",
                  pid_path);
        goto done;
    }
    if (pid_rc != SSH_PID_SIDECAR_VALID) {
        set_error(ERR_FILE_IO,
                  "Owned SSH agent has no exact durable process sidecar");
        goto done;
    }
    pid_present = true;
    if (recorded.pid != ssh_config->agent_pid ||
        !ssh_process_generation_equal(
            &recorded.generation, &ssh_config->agent_generation) ||
        !ssh_process_image_equal(
            &recorded.image, &ssh_config->agent_image)) {
        set_error(ERR_FILE_IO,
                  "SSH agent process sidecar changed; replacement retained: %s",
                  pid_path);
        goto done;
    }
    {
        ssh_process_outcome_t reap_outcome = g_ssh_reap(
            &recorded, ssh_config->agent_socket_path, dir_fd);
        bool retirement_attempted = false;

        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            reap_outcome == SSH_PROCESS_INDETERMINATE && socket_present) {
            retirement_attempted = true;
            if (retire_recorded_agent_endpoint(
                    dir_fd, runtime_dir, socket_name,
                    ssh_config->agent_socket_path, pid_name,
                    &socket_pin, &pid_pin, &recorded) == 0) {
                recorded_endpoint_retired = true;
            }
        }
        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            !recorded_endpoint_retired) {
            if (!retirement_attempted) {
                set_error(
                    ERR_SSH_AGENT_FAILED,
                    "SSH agent PID %ld reap outcome %s; retained for retry",
                    (long)recorded.pid,
                    ssh_process_outcome_name(reap_outcome));
            }
            goto done;
        }
        ssh_config->key_already_loaded = false;
    }
    if (socket_present) {
        struct stat after_reap;
        if (fstatat(dir_fd, socket_name, &after_reap,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                socket_present = false;
            } else {
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot refresh stopped SSH agent socket: %s",
                    ssh_config->agent_socket_path);
                goto done;
            }
        } else if (!same_runtime_revision(
                       &socket_pin.identity, &after_reap)) {
            set_error(
                ERR_FILE_IO,
                "Stopped SSH agent socket was replaced; retained for retry: %s",
                ssh_config->agent_socket_path);
            goto done;
        }
    }
    if (verify_ssh_runtime_pin_at(
            dir_fd, pid_name, pid_path, &pid_pin) != 0) {
        goto done;
    }
    if (!pinned_pid_sidecar_matches_record(&pid_pin, &recorded)) {
        set_error(
            ERR_FILE_IO,
            "SSH agent process sidecar changed; replacement retained: %s",
            pid_path);
        goto done;
    }
    if (socket_present &&
        verify_ssh_runtime_pin_at(dir_fd, socket_name,
                                  ssh_config->agent_socket_path,
                                  &socket_pin) != 0) {
        goto done;
    }
    if (!recorded_endpoint_retired &&
        prove_malformed_pid_socket_dead_at(
            dir_fd, runtime_dir, socket_name,
            ssh_config->agent_socket_path, &socket_pin,
            socket_present, false, "a valid SSH process record") != 0) {
        goto done;
    }

    /* A protocol-retired endpoint may still have a live process behind it.
     * Retire its targeting record before detaching the listening name so a
     * partial teardown never leaves a durable record naming an unreachable
     * but potentially key-holding process. */
    if (recorded_endpoint_retired && pid_present &&
        unlink_ssh_runtime_identity_at(
            dir_fd, pid_name, &pid_pin.identity, false,
            "protocol-retired stopped agent PID sidecar cleanup",
            NULL, NULL) != 0) {
        goto done;
    }
    if (socket_present &&
        unlink_ssh_runtime_identity_at(
            dir_fd, socket_name, &socket_pin.identity, false,
            "stopped agent socket cleanup", NULL, NULL) != 0) {
        goto done;
    }
    if (recorded_endpoint_retired && socket_present) {
        recorded_endpoint_detached = true;
    }
    if (!recorded_endpoint_retired && pid_present &&
        unlink_ssh_runtime_identity_at(
            dir_fd, pid_name, &pid_pin.identity, false,
            "stopped agent PID sidecar cleanup", NULL, NULL) != 0) {
        goto done;
    }
    if (!socket_present && !pid_present &&
        sync_ssh_runtime_dir(dir_fd,
                             "stopped agent artifact absence verification") !=
            0) {
        goto done;
    }
    rc = 0;

done:
    if (rc != 0) {
        primary_error = g_last_error;
        primary_errno = errno;
        primary_failure = true;
    }
    if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) {
        if (primary_failure) {
            log_warning("Secondary failure releasing stopped-agent PID pin: %s",
                        get_last_error()->message);
        }
        rc = -1;
    }
    if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
        if (primary_failure) {
            log_warning(
                "Secondary failure releasing stopped-agent socket pin: %s",
                get_last_error()->message);
        }
        rc = -1;
    }
    if (primary_failure) {
        g_last_error = primary_error;
        errno = primary_errno;
    }
    if (recorded_endpoint_retired) {
        warn_recorded_endpoint_retirement(
            ssh_config->agent_socket_path, recorded_endpoint_detached);
    }
    if (lock_fd >= 0) unlock_agent_dir(lock_fd);
    if (dir_fd >= 0) close(dir_fd);
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
    if (!ssh_process_generation_valid(&ssh_config->agent_generation)) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Owned SSH agent has no verified process generation; retained for retry");
        return -1;
    }
    if (!ssh_config->agent_image.valid) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Owned SSH agent has no verified launch image; retained for retry");
        return -1;
    }

    log_info("Stopping SSH agent (PID: %d)", ssh_config->agent_pid);

    /* Route through the same hardened reaper as every other kill path
     * (AR-02 #19): identity-verify the PID (comm + our socket in argv) and
     * pidfd-pin it before signaling, so a recorded PID that was recycled to
     * an unrelated same-uid process — or to the user's own login ssh-agent —
     * is never signaled. The old path gated only on kill(pid, 0) liveness. */
    if (cleanup_stopped_agent_runtime(ssh_config) != 0) {
        log_warning("SSH agent stop/runtime cleanup is not conclusive; retaining retry state");
        return -1;
    }
    log_debug("SSH agent runtime safely retired");

    /* Reset state only after both recovery names are durably absent. */
    ssh_config->agent_pid = -1;
    ssh_process_generation_clear(&ssh_config->agent_generation);
    memset(&ssh_config->agent_image, 0, sizeof(ssh_config->agent_image));
    ssh_config->agent_owned = false;
    ssh_config->reused_existing_agent = false;
    ssh_config->agent_socket_path[0] = '\0';
    ssh_config->agent_socket_arg[0] = '\0';

    /* Clear environment */
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");

    return 0;
}

/* Clear all keys from SSH agent */
int ssh_clear_agent_keys(ssh_config_t *ssh_config) {
    const char *argv[] = {"ssh-add", "-D", NULL};
    char output[512];
    run_opts_t opts;
    run_result_t result;
    uint64_t error_generation_before;
    bool child_cleared_keys;
    bool runner_reported_error;
    int run_rc;
    
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        log_debug("No SSH agent available to clear keys");
        return 0;
    }
    
    log_debug("Clearing all keys from SSH agent");
    
    /* Set up environment for ssh-add */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -D to delete all keys. This low-level operation is
     * intentionally destructive and nontransactional; ssh_switch_account()
     * never calls it. A nonzero result is not evidence that the agent was
     * already empty: it can also mean the agent was unreachable or rejected
     * the operation. */
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    output[0] = '\0';
    opts.out = output;
    opts.out_size = sizeof(output);
    error_generation_before = error_report_generation();
    run_rc = run_argv(argv, &opts, &result);
    runner_reported_error =
        error_report_generation() != error_generation_before;
    if (result.out_len > 0 && result.out_len < sizeof(output) &&
        output[result.out_len - 1] == '\n') {
        output[result.out_len - 1] = '\0';
    }
    /* A parent-side pipe or signal-state cleanup failure can make run_argv()
     * return -1 after ssh-add itself exited zero. The destructive transition
     * still happened, so publish the new key state from either success proof. */
    child_cleared_keys =
        run_rc == 0 ||
        (result.spawned && result.term_signal == 0 && result.exit_code == 0);
    if (child_cleared_keys) {
        ssh_config->key_already_loaded = false;
    }
    if (run_rc != 0) {
        if (child_cleared_keys) {
            /* run_argv() already published the causal parent-side failure.
             * Keep it byte-for-byte instead of falsely reporting that the
             * destructive ssh-add operation failed. A test runner that
             * violates the structured-error contract still gets a truthful
             * fallback diagnostic. */
            if (!runner_reported_error ||
                get_last_error()->code == ERR_SUCCESS) {
                set_error(
                    ERR_SYSTEM_CALL,
                    "SSH agent keys were cleared, but command runner cleanup failed");
            }
            return -1;
        }
        set_error(ERR_SSH_KEY_LOAD_FAILED,
                  "Failed to clear SSH agent before key replacement: %s",
                  output);
        return -1;
    }
    log_debug("SSH agent keys cleared successfully");
    return 0;
}

/* Low-level compatibility primitive. The caller owns key admission; keep the
 * supplied path as one argv element and make success mean only that ssh-add
 * accepted the command. ssh_switch_account() owns validated exact-set loading. */
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

    /* `-k` disables ssh-add's implicit sibling-certificate autoload. Keep the
     * caller-supplied path as one argv element. */
    if (ssh_run(output, sizeof(output), false, "ssh-add", "-k", key_path,
                (const char *)NULL) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s", output);
        return -1;
    }

    log_info("ssh-add accepted SSH key path: %s", key_path);
    return 0;
}

/* List loaded SSH keys */
int ssh_list_keys(ssh_config_t *ssh_config, char *output, size_t output_size) {
    const char *const argv[] = {"ssh-add", "-l", NULL};
    run_opts_t opts;
    run_result_t result;
    int rc;

    if (!ssh_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_list_keys");
        return -1;
    }
    output[0] = '\0';
    
    if (strlen(ssh_config->agent_socket_path) == 0) {
        safe_strncpy(output, "No SSH agent available", output_size);
        return -1;
    }
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -l with the complete runner result. A caller-supplied
     * buffer is the public storage contract, so an oversized listing cannot be
     * recaptured invisibly; fail with an empty result instead of publishing a
     * prefix that could hide a later identity. */
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.out = output;
    opts.out_size = output_size;
    rc = run_argv(argv, &opts, &result);
    if (result.out_truncated || result.out_len >= output_size) {
        output[0] = '\0';
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH key listing was incomplete; increase the output buffer");
        return -1;
    }
    if (memchr(output, '\0', result.out_len) != NULL) {
        output[0] = '\0';
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH key listing contained invalid binary data");
        return -1;
    }
    if (rc != 0 && result.spawned && !result.timed_out &&
        result.term_signal == 0 && result.exit_code == 1) {
        safe_strncpy(output, "No keys loaded in SSH agent", output_size);
        return -1;
    }
    if (rc != 0) {
        const char *outcome;
        char outcome_detail[64];

        output[0] = '\0';
        if (result.timed_out) {
            outcome = result.spawned
                ? "timed out"
                : "timed out before it could be started";
        } else if (!result.spawned) {
            outcome = "could not be started";
        } else if (result.term_signal != 0) {
            (void)snprintf(outcome_detail, sizeof(outcome_detail),
                           "was terminated by signal %d",
                           result.term_signal);
            outcome = outcome_detail;
        } else if (result.exit_code >= 0) {
            (void)snprintf(outcome_detail, sizeof(outcome_detail),
                           "exited with status %d", result.exit_code);
            outcome = outcome_detail;
        } else {
            outcome = "did not complete normally";
        }
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH key listing failed: ssh-add %s "
                  "(spawned=%s, timed_out=%s, signal=%d, exit_status=%d)",
                  outcome, result.spawned ? "true" : "false",
                  result.timed_out ? "true" : "false",
                  result.term_signal, result.exit_code);
        return -1;
    }

    if (result.out_len > 0U && output[result.out_len - 1U] == '\n') {
        output[result.out_len - 1U] = '\0';
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

int ssh_validate_key_file(const char *key_path) {
    ssh_key_snapshot_t snapshot;
    int rc;

    if (!key_path) {
        set_error(ERR_INVALID_ARGS, "NULL key_path to ssh_validate_key_file");
        return -1;
    }
    memset(&snapshot, 0, sizeof(snapshot));
    rc = ssh_key_snapshot_capture(key_path, &snapshot);
    if (rc == 0) {
        rc = ssh_key_snapshot_require_openssh_parse(key_path, &snapshot);
    }
    ssh_key_snapshot_clear(&snapshot);
    return rc;
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

static bool same_ssh_config_directory_revision(const struct stat *left,
                                               const struct stat *right) {
    return same_ssh_config_directory(left, right) &&
           left->st_gid == right->st_gid &&
           left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           same_ssh_config_mtime(left, right) &&
           same_ssh_config_ctime(left, right);
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

static bool ssh_config_file_is_safe_unchanged(const struct stat *identity) {
    return S_ISREG(identity->st_mode) && identity->st_uid == getuid() &&
           (identity->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

typedef struct {
    char path[MAX_PATH_LEN];
    struct stat home_identity;
    struct stat dir_identity;
    int home_fd;
    int dir_fd;
    bool absent;
    bool home_entry_synced;
} ssh_config_directory_t;

static bool ssh_directory_publication_matches(
    const publication_identity_t *expected, const struct stat *observed);

static int recheck_ssh_home_directory(
    const char *home, const ssh_config_directory_t *directory) {
    struct stat pinned;
    struct stat named;

    if (fstat(directory->home_fd, &pinned) != 0 ||
        stat(home, &named) != 0 ||
        !same_ssh_config_directory(&directory->home_identity, &pinned) ||
        !same_ssh_config_directory(&directory->home_identity, &named)) {
        set_error(ERR_FILE_IO,
                  "HOME changed during SSH config update: %s", home);
        return -1;
    }
    return 0;
}

/* Prove a missing ~/.ssh entry against one pinned HOME generation. The
 * exclusive HOME lock serializes this observation with gitswitch's first-time
 * .ssh creation path; the strict directory revision checks reject namespace
 * activity by other writers across the absence observation and parent fsync. */
static int prove_absent_ssh_config_directory_durable(
    const char *home,
    const config_retirement_ssh_alias_obligation_t *obligation,
    ssh_config_publication_state_t *publication) {
    char canonical_home[MAX_PATH_LEN];
    struct stat named_before;
    struct stat pinned_before;
    struct stat pinned_after;
    struct stat named_after;
    struct stat unexpected;
    int home_fd = -1;
    int lock_rc;
    int rc = -1;
    int saved_errno;
    bool locked = false;

    if (obligation &&
        (realpath(home, canonical_home) == NULL ||
         strcmp(canonical_home, obligation->home_path) != 0)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME namespace does not match SSH alias obligation");
        return -1;
    }
    if (stat(home, &named_before) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot inspect HOME while proving absent SSH config directory");
        return -1;
    }
    if (!S_ISDIR(named_before.st_mode)) {
        errno = ENOTDIR;
        set_system_error(
            ERR_FILE_IO,
            "HOME is not a directory while proving absent SSH config "
            "directory");
        return -1;
    }
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (home_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to pin HOME while proving absent SSH config directory");
        return -1;
    }
    if (fstat(home_fd, &pinned_before) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect pinned HOME while proving absent SSH config "
            "directory");
        goto done;
    }
    if (!same_ssh_config_directory(&named_before, &pinned_before)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME changed while proving absent SSH config directory");
        goto done;
    }
    if (obligation &&
        !ssh_directory_publication_matches(
            &obligation->home_identity, &pinned_before)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME generation does not match SSH alias obligation");
        goto done;
    }

    do {
        lock_rc = flock(home_fd, LOCK_EX);
    } while (lock_rc != 0 && errno == EINTR);
    if (lock_rc != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to lock HOME while proving absent SSH config directory");
        goto done;
    }
    locked = true;

    if (fstat(home_fd, &pinned_before) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to reinspect pinned HOME while proving absent SSH config "
            "directory");
        goto done;
    }
    if (stat(home, &named_before) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to rebind HOME while proving absent SSH config directory");
        goto done;
    }
    if (!same_ssh_config_directory(&pinned_before, &named_before)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME changed while proving absent SSH config directory");
        goto done;
    }
    if (obligation &&
        (!ssh_directory_publication_matches(
             &obligation->home_identity, &pinned_before) ||
         realpath(home, canonical_home) == NULL ||
         strcmp(canonical_home, obligation->home_path) != 0)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME namespace changed before proving absent SSH directory");
        goto done;
    }
    if (fstatat(home_fd, ".ssh", &unexpected, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH config directory appeared while proving its absence");
        goto done;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to verify absent SSH config directory");
        goto done;
    }

    if (g_ssh_dirsync(home_fd) != 0) {
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
        }
        set_system_error(
            ERR_FILE_IO,
            "SSH config directory is absent but the pinned HOME sync failed; "
            "alias-removal durability remains uncertain");
        goto done;
    }
    if (fstatat(home_fd, ".ssh", &unexpected, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH config directory appeared after its absence was synced");
        goto done;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to reverify absent SSH config directory after HOME sync");
        goto done;
    }
    if (fstat(home_fd, &pinned_after) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to reinspect synced HOME while proving absent SSH config "
            "directory");
        goto done;
    }
    if (stat(home, &named_after) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to rebind synced HOME while proving absent SSH config "
            "directory");
        goto done;
    }
    if (!same_ssh_config_directory_revision(&pinned_before, &pinned_after) ||
        !same_ssh_config_directory_revision(&pinned_before, &named_after)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME changed while finalizing absent SSH config directory");
        goto done;
    }
    if (obligation &&
        (!ssh_directory_publication_matches(
             &obligation->home_identity, &pinned_after) ||
         realpath(home, canonical_home) == NULL ||
         strcmp(canonical_home, obligation->home_path) != 0)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME namespace changed while finalizing SSH alias obligation");
        goto done;
    }

    rc = 0;
done:
    /* Cleanup must not replace the errno that explains the primary proof
     * failure. A cleanup failure is promoted only after an otherwise
     * successful proof. */
    saved_errno = errno;
    if (locked) {
        do {
            lock_rc = flock(home_fd, LOCK_UN);
        } while (lock_rc != 0 && errno == EINTR);
        if (lock_rc != 0 && rc == 0) {
            saved_errno = errno;
            set_system_error(
                ERR_FILE_IO,
                "Failed to unlock HOME after proving absent SSH config "
                "directory");
            rc = -1;
        }
    }
    if (home_fd >= 0 && close(home_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(
            ERR_FILE_IO,
            "Failed to close HOME after proving absent SSH config directory");
        rc = -1;
    }
    if (rc != 0) errno = saved_errno;
    return rc;
}

static int recheck_ssh_config_directory(
    const char *home, const ssh_config_directory_t *directory) {
    struct stat current;

    if (recheck_ssh_home_directory(home, directory) != 0) return -1;
    if (fstatat(directory->home_fd, ".ssh", &current,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !ssh_config_directory_is_safe(&current) ||
        !same_ssh_config_directory(&directory->dir_identity, &current)) {
        set_error(ERR_FILE_IO,
                  "SSH config directory changed during update: %s",
                  directory->path);
        return -1;
    }
    return 0;
}

static int sync_ssh_home_entry(
    const char *home, ssh_config_directory_t *directory) {
    if (recheck_ssh_config_directory(home, directory) != 0) return -1;
    if (g_ssh_dirsync(directory->home_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to sync HOME for first SSH config publication; "
            "the .ssh entry durability is uncertain");
        return -1;
    }
    if (recheck_ssh_config_directory(home, directory) != 0) return -1;
    directory->home_entry_synced = true;
    return 0;
}

/* mkdirat() has already made the child name live, so do not place any
 * fallible inspection between that namespace mutation and its parent sync.
 * The resolved HOME descriptor is the durability boundary; the pathname
 * recheck after fsync rejects a concurrently retargeted symlinked HOME. */
static int sync_new_ssh_home_entry(
    const char *home, ssh_config_directory_t *directory) {
    if (g_ssh_dirsync(directory->home_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to sync HOME after creating .ssh; "
            "the .ssh entry durability is uncertain");
        return -1;
    }
    if (recheck_ssh_home_directory(home, directory) != 0) return -1;
    directory->home_entry_synced = true;
    return 0;
}

/* Pin HOME and ~/.ssh as one descriptor-anchored namespace. Creation is
 * serialized on the resolved HOME inode and performed with mkdirat(), so two
 * first-time writers cannot let one publish before the other's parent sync.
 * A symlinked HOME remains supported; only the .ssh leaf is no-follow. */
static int open_ssh_config_directory(
    const char *home, bool create, ssh_config_directory_t *directory) {
    struct stat named_home;
    struct stat opened_home;
    struct stat before;
    struct stat opened;
    bool home_locked = false;
    bool created = false;
    int lock_rc;

    memset(directory, 0, sizeof(*directory));
    directory->home_fd = -1;
    directory->dir_fd = -1;
    if ((size_t)snprintf(directory->path, sizeof(directory->path),
                         "%s/.ssh", home) >= sizeof(directory->path)) {
        set_error(ERR_INVALID_PATH, "SSH config directory path too long");
        return -1;
    }
    if (stat(home, &named_home) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect HOME for SSH config: %s", home);
        return -1;
    }
    if (!S_ISDIR(named_home.st_mode)) {
        errno = ENOTDIR;
        set_system_error(ERR_FILE_IO,
                         "HOME is not a directory for SSH config: %s", home);
        return -1;
    }
    directory->home_fd =
        open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (directory->home_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to pin HOME for SSH config safely: %s",
                         home);
        return -1;
    }
    if (fstat(directory->home_fd, &opened_home) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to inspect pinned HOME for SSH config: %s",
                         home);
        goto fail;
    }
    if (!same_ssh_config_directory(&named_home, &opened_home)) {
        errno = EAGAIN;
        set_system_error(ERR_FILE_IO,
                         "HOME changed while being pinned for SSH config: %s",
                         home);
        goto fail;
    }
    directory->home_identity = opened_home;

    if (create) {
        do {
            lock_rc = flock(directory->home_fd, LOCK_EX);
        } while (lock_rc != 0 && errno == EINTR);
        if (lock_rc != 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to lock HOME for SSH config creation");
            goto fail;
        }
        home_locked = true;
        if (recheck_ssh_home_directory(home, directory) != 0) goto fail;
    }

    if (fstatat(directory->home_fd, ".ssh", &before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT && !create) {
            directory->absent = true;
            goto fail;
        }
        if (errno != ENOENT || !create) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect SSH config directory: %s",
                             directory->path);
            goto fail;
        }
        /* Deterministic namespace-race seam: production leaves the metadata
         * hook NULL. Tests may retarget a symlinked HOME after the absence
         * observation to prove mkdirat remains anchored to home_fd. */
        if (g_metadata_test_hook) {
            (void)g_metadata_test_hook(
                SSH_METADATA_TEST_CONFIG_HOME_CREATE);
        }
        if (mkdirat(directory->home_fd, ".ssh", 0700) == 0) {
            created = true;
        } else if (errno != EEXIST) {
            set_system_error(ERR_FILE_IO,
                             "Cannot create SSH config directory: %s",
                             directory->path);
            goto fail;
        }
        if (created && sync_new_ssh_home_entry(home, directory) != 0) {
            goto fail;
        }
        if (fstatat(directory->home_fd, ".ssh", &before,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect created SSH config directory: %s",
                             directory->path);
            goto fail;
        }
    }
    if (!ssh_config_directory_is_safe(&before)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe or symlinked SSH config directory: %s",
                  directory->path);
        goto fail;
    }

    directory->dir_fd =
        openat(directory->home_fd, ".ssh",
               O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory->dir_fd < 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to pin SSH config directory safely: %s",
                         directory->path);
        goto fail;
    }
    if (fstat(directory->dir_fd, &opened) != 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to inspect pinned SSH config directory: %s",
                         directory->path);
        goto fail;
    }
    if (!ssh_config_directory_is_safe(&opened) ||
        !same_ssh_config_directory(&before, &opened)) {
        errno = !ssh_config_directory_is_safe(&opened) ? EACCES : EAGAIN;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to pin SSH config directory safely: %s",
                         directory->path);
        goto fail;
    }
    directory->dir_identity = opened;
    if (recheck_ssh_config_directory(home, directory) != 0) goto fail;

    if (home_locked) {
        if (flock(directory->home_fd, LOCK_UN) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to unlock HOME after SSH config creation");
            goto fail;
        }
        home_locked = false;
    }
    return 0;

fail: {
        int saved_errno = errno;
        if (home_locked) (void)flock(directory->home_fd, LOCK_UN);
        if (directory->dir_fd >= 0) close(directory->dir_fd);
        if (directory->home_fd >= 0) close(directory->home_fd);
        directory->dir_fd = -1;
        directory->home_fd = -1;
        errno = saved_errno;
        return -1;
    }
}

static bool ssh_publication_identity_is_zero(
    const publication_identity_t *identity) {
    publication_identity_t zero;

    if (!identity) return false;
    memset(&zero, 0, sizeof(zero));
    return memcmp(identity, &zero, sizeof(zero)) == 0;
}

static bool ssh_directory_publication_matches(
    const publication_identity_t *expected, const struct stat *observed) {
    return expected && observed && expected->present &&
           expected->device == (uintmax_t)observed->st_dev &&
           expected->inode == (uintmax_t)observed->st_ino &&
           expected->mode == (uintmax_t)observed->st_mode &&
           expected->uid == (uintmax_t)observed->st_uid &&
           expected->gid == (uintmax_t)observed->st_gid &&
           S_ISDIR(observed->st_mode);
}

static bool ssh_directory_publication_equal_stable(
    const publication_identity_t *left,
    const publication_identity_t *right) {
    return left && right && left->present == right->present &&
           (!left->present ||
            (left->device == right->device &&
             left->inode == right->inode &&
             left->mode == right->mode &&
             left->uid == right->uid &&
             left->gid == right->gid));
}

static bool ssh_alias_obligation_is_valid(
    const config_retirement_ssh_alias_obligation_t *obligation) {
    mode_t home_mode;
    mode_t ssh_mode;

    if (!obligation || !obligation->known || !obligation->present ||
        memchr(obligation->ssh_host_alias, '\0',
               sizeof(obligation->ssh_host_alias)) == NULL ||
        !valid_ssh_host_alias(obligation->ssh_host_alias) ||
        memchr(obligation->home_path, '\0',
               sizeof(obligation->home_path)) == NULL ||
        obligation->home_path[0] != '/' ||
        !obligation->home_identity.present) {
        return false;
    }
    home_mode = (mode_t)obligation->home_identity.mode;
    if ((uintmax_t)home_mode != obligation->home_identity.mode ||
        !S_ISDIR(home_mode)) {
        return false;
    }
    if (!obligation->ssh_directory_identity.present) {
        return ssh_publication_identity_is_zero(
            &obligation->ssh_directory_identity);
    }
    ssh_mode = (mode_t)obligation->ssh_directory_identity.mode;
    return (uintmax_t)ssh_mode ==
               obligation->ssh_directory_identity.mode &&
           S_ISDIR(ssh_mode);
}

int ssh_capture_host_alias_obligation(
    const char *alias,
    config_retirement_ssh_alias_obligation_t *obligation) {
    config_retirement_ssh_alias_obligation_t captured;
    const char *home = getenv("HOME");
    char canonical_home[MAX_PATH_LEN];
    char final_canonical_home[MAX_PATH_LEN];
    struct stat named_home;
    struct stat pinned_home;
    struct stat final_home;
    struct stat named_ssh;
    struct stat pinned_ssh;
    struct stat final_ssh;
    int home_fd = -1;
    int ssh_fd = -1;
    int rc = -1;
    int saved_errno;

    if (obligation) memset(obligation, 0, sizeof(*obligation));
    memset(&captured, 0, sizeof(captured));
    if (!obligation || !alias || !valid_ssh_host_alias(alias)) {
        set_error(ERR_INVALID_ARGS,
                  "Cannot capture an invalid SSH alias obligation");
        return -1;
    }
    if (!home || !*home) {
        set_error(
            ERR_INVALID_PATH,
            "HOME is not set for SSH alias retirement");
        return -1;
    }
    if (realpath(home, canonical_home) == NULL) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to resolve HOME for SSH alias retirement");
        return -1;
    }
    if (stat(canonical_home, &named_home) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect canonical HOME for SSH alias retirement");
        return -1;
    }
    if (!S_ISDIR(named_home.st_mode)) {
        errno = ENOTDIR;
        set_system_error(
            ERR_FILE_IO,
            "Canonical HOME is not a directory for SSH alias retirement");
        return -1;
    }
    home_fd = open(canonical_home,
                   O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (home_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to pin canonical HOME for SSH alias retirement");
        return -1;
    }
    if (fstat(home_fd, &pinned_home) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect pinned HOME during SSH alias capture");
        goto done;
    }
    if (!same_ssh_config_directory(&named_home, &pinned_home)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "Canonical HOME changed during SSH alias capture");
        goto done;
    }

    if (fstatat(home_fd, ".ssh", &named_ssh, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!ssh_config_directory_is_safe(&named_ssh)) {
            set_error(
                ERR_PERMISSION_DENIED,
                "Refusing unsafe SSH directory during alias capture");
            goto done;
        }
        ssh_fd = openat(home_fd, ".ssh",
                        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (ssh_fd < 0 || fstat(ssh_fd, &pinned_ssh) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Failed to pin SSH directory during alias capture");
            goto done;
        }
        if (!ssh_config_directory_is_safe(&pinned_ssh) ||
            !same_ssh_config_directory(&named_ssh, &pinned_ssh) ||
            fstatat(home_fd, ".ssh", &final_ssh,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_ssh_config_directory(&pinned_ssh, &final_ssh)) {
            errno = EAGAIN;
            set_system_error(
                ERR_FILE_IO,
                "SSH directory changed during alias capture");
            goto done;
        }
        publication_identity_from_stat(
            &captured.ssh_directory_identity, &pinned_ssh);
    } else if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect SSH directory during alias capture");
        goto done;
    }

    if (fstat(home_fd, &final_home) != 0 ||
        stat(canonical_home, &named_home) != 0 ||
        realpath(home, final_canonical_home) == NULL) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to recheck HOME while finalizing SSH alias capture");
        goto done;
    }
    if (strcmp(final_canonical_home, canonical_home) != 0 ||
        !same_ssh_config_directory(&pinned_home, &final_home) ||
        !same_ssh_config_directory(&pinned_home, &named_home)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "Canonical HOME changed while finalizing SSH alias capture");
        goto done;
    }
    if (!captured.ssh_directory_identity.present) {
        if (fstatat(home_fd, ".ssh", &final_ssh,
                    AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT) {
            errno = EAGAIN;
            set_system_error(
                ERR_FILE_IO,
                "SSH directory appeared while finalizing alias capture");
            goto done;
        }
    }

    captured.known = true;
    captured.present = true;
    memcpy(captured.ssh_host_alias, alias, strlen(alias) + 1U);
    memcpy(captured.home_path, canonical_home,
           strlen(canonical_home) + 1U);
    publication_identity_from_stat(
        &captured.home_identity, &pinned_home);
    rc = 0;
done:
    /* Preserve the capture failure's errno across descriptor retirement;
     * promote the first close failure only when capture otherwise succeeded. */
    saved_errno = errno;
    if (ssh_fd >= 0 && close(ssh_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(
            ERR_FILE_IO,
            "Failed to close SSH directory after alias capture");
        rc = -1;
    }
    if (home_fd >= 0 && close(home_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(
            ERR_FILE_IO,
            "Failed to close HOME after SSH alias capture");
        rc = -1;
    }
    if (rc == 0) {
        *obligation = captured;
    } else {
        memset(obligation, 0, sizeof(*obligation));
        errno = saved_errno;
    }
    return rc;
}

static int ssh_recheck_open_alias_obligation(
    const char *home, const ssh_config_directory_t *directory,
    const config_retirement_ssh_alias_obligation_t *obligation) {
    char canonical_home[MAX_PATH_LEN];
    struct stat pinned_home;
    struct stat named_home;
    struct stat pinned_ssh;
    struct stat named_ssh;

    if (!obligation ||
        realpath(home, canonical_home) == NULL ||
        strcmp(canonical_home, obligation->home_path) != 0) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME namespace does not match SSH alias obligation");
        return -1;
    }
    if (fstat(directory->home_fd, &pinned_home) != 0 ||
        stat(obligation->home_path, &named_home) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect HOME for SSH alias obligation");
        return -1;
    }
    if (!ssh_directory_publication_matches(
            &obligation->home_identity, &pinned_home) ||
        !same_ssh_config_directory(&pinned_home, &named_home)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "HOME generation does not match SSH alias obligation");
        return -1;
    }
    if (!obligation->ssh_directory_identity.present) {
        if (fstatat(directory->home_fd, ".ssh", &named_ssh,
                    AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT) {
            errno = EAGAIN;
            set_system_error(
                ERR_FILE_IO,
                "SSH directory appeared after alias obligation capture");
            return -1;
        }
        return 0;
    }
    if (fstat(directory->dir_fd, &pinned_ssh) != 0 ||
        fstatat(directory->home_fd, ".ssh", &named_ssh,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to inspect SSH directory for alias obligation");
        return -1;
    }
    if (!ssh_config_directory_is_safe(&pinned_ssh) ||
        !ssh_directory_publication_matches(
            &obligation->ssh_directory_identity, &pinned_ssh) ||
        !same_ssh_config_directory(&pinned_ssh, &named_ssh)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH directory generation does not match alias obligation");
        return -1;
    }
    return 0;
}

int ssh_revalidate_host_alias_obligation(
    const config_retirement_ssh_alias_obligation_t *obligation) {
    config_retirement_ssh_alias_obligation_t observed;

    if (!ssh_alias_obligation_is_valid(obligation)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH alias retirement obligation");
        return -1;
    }
    if (ssh_capture_host_alias_obligation(
            obligation->ssh_host_alias, &observed) != 0) {
        return -1;
    }
    if (strcmp(observed.home_path, obligation->home_path) != 0 ||
        !ssh_directory_publication_equal_stable(
            &observed.home_identity, &obligation->home_identity) ||
        !ssh_directory_publication_equal_stable(
            &observed.ssh_directory_identity,
            &obligation->ssh_directory_identity)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH alias retirement namespace no longer matches obligation");
        return -1;
    }
    return 0;
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

static bool ssh_config_ascii_case_equal(const char *left, size_t left_len,
                                        const char *right) {
    size_t right_len = strlen(right);

    if (left_len != right_len) return false;
    for (size_t i = 0; i < left_len; i++) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];

        if (a >= (unsigned char)'A' && a <= (unsigned char)'Z') {
            a = (unsigned char)(a - (unsigned char)'A' +
                                (unsigned char)'a');
        }
        if (b >= (unsigned char)'A' && b <= (unsigned char)'Z') {
            b = (unsigned char)(b - (unsigned char)'A' +
                                (unsigned char)'a');
        }
        if (a != b) return false;
    }
    return true;
}

static bool ssh_config_argument_space(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

/* Split an ssh_config directive without interpreting its arguments. OpenSSH
 * accepts either whitespace or '=' between a keyword and its first argument;
 * spaces, tabs, and a bare carriage return are argument whitespace, while
 * keyword case is insignificant. */
static bool ssh_config_parse_directive(
    const char *buf, const ssh_config_line_t *line,
    const char **keyword, size_t *keyword_len,
    const char **arguments, size_t *arguments_len) {
    size_t offset = 0;
    size_t keyword_start;

    while (offset < line->text_len &&
           ssh_config_argument_space(buf[line->start + offset])) {
        offset++;
    }
    if (offset == line->text_len || buf[line->start + offset] == '#') {
        return false;
    }
    keyword_start = offset;
    while (offset < line->text_len &&
           !ssh_config_argument_space(buf[line->start + offset]) &&
           buf[line->start + offset] != '=') {
        offset++;
    }
    if (offset == keyword_start) return false;

    *keyword = buf + line->start + keyword_start;
    *keyword_len = offset - keyword_start;
    while (offset < line->text_len &&
           ssh_config_argument_space(buf[line->start + offset])) {
        offset++;
    }
    if (offset < line->text_len && buf[line->start + offset] == '=') {
        offset++;
        while (offset < line->text_len &&
               ssh_config_argument_space(buf[line->start + offset])) {
            offset++;
        }
    }
    *arguments = buf + line->start + offset;
    *arguments_len = line->text_len - offset;
    return true;
}

/* OpenSSH Host patterns use '*' and '?' and retain byte case. The managed
 * alias grammar excludes escapes and character classes, so a bounded rolling
 * DP exactly decides whether one existing Host pattern selects the literal
 * alias gitswitch will hand to ssh. */
static bool ssh_config_host_pattern_matches(const char *pattern,
                                            size_t pattern_len,
                                            const char *alias) {
    bool previous[MAX_NAME_LEN] = {false};
    bool current[MAX_NAME_LEN] = {false};
    size_t alias_len = strlen(alias);

    if (alias_len >= MAX_NAME_LEN) return false;
    previous[0] = true;
    for (size_t i = 0; i < pattern_len; i++) {
        unsigned char pattern_byte = (unsigned char)pattern[i];

        memset(current, 0, (alias_len + 1U) * sizeof(current[0]));
        if (pattern_byte == (unsigned char)'*') {
            current[0] = previous[0];
            for (size_t j = 1; j <= alias_len; j++) {
                current[j] = previous[j] || current[j - 1U];
            }
        } else {
            for (size_t j = 1; j <= alias_len; j++) {
                unsigned char alias_byte = (unsigned char)alias[j - 1U];

                current[j] =
                    previous[j - 1U] &&
                    (pattern_byte == (unsigned char)'?' ||
                     pattern_byte == alias_byte);
            }
        }
        memcpy(previous, current,
               (alias_len + 1U) * sizeof(previous[0]));
    }
    return previous[alias_len];
}

static bool ssh_config_pattern_has_wildcard(const char *pattern,
                                            size_t pattern_len) {
    return memchr(pattern, '*', pattern_len) != NULL ||
           memchr(pattern, '?', pattern_len) != NULL;
}

static bool ssh_config_pattern_bytes_overlap(unsigned char left,
                                             unsigned char right) {
    if (left == (unsigned char)'*' || left == (unsigned char)'?' ||
        right == (unsigned char)'*' || right == (unsigned char)'?') {
        return true;
    }
    return left == right;
}

/* Decide non-empty intersection of two OpenSSH '*'/'?' pattern languages.
 * Each pattern is a tiny NFA: '*' has an epsilon transition to its successor
 * and a consuming self-loop; '?' and literals consume one byte. Reachability
 * in the product NFA proves whether a concrete hostname can select both
 * blocks. Inputs above the persisted alias bound are conservatively treated as
 * overlapping so an adversarial config cannot turn the proof into unbounded
 * work. */
static int ssh_config_host_patterns_intersect(const char *left,
                                              size_t left_len,
                                              const char *right,
                                              size_t right_len,
                                              bool *intersects_out) {
    size_t columns;
    size_t state_count;
    bool *visited;
    size_t *queue;
    size_t head = 0;
    size_t tail = 0;
    bool intersects = false;

    *intersects_out = false;
    if (left_len >= MAX_NAME_LEN || right_len >= MAX_NAME_LEN) {
        *intersects_out = true;
        return 0;
    }
    columns = right_len + 1U;
    state_count = (left_len + 1U) * columns;
    visited = calloc(state_count, sizeof(*visited));
    queue = malloc(state_count * sizeof(*queue));
    if (!visited || !queue) {
        free(visited);
        free(queue);
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory proving SSH Host pattern precedence");
        return -1;
    }

#define SSH_CONFIG_ENQUEUE(_left, _right)                                  \
    do {                                                                    \
        size_t state_ = (_left) * columns + (_right);                       \
        if (!visited[state_]) {                                             \
            visited[state_] = true;                                         \
            queue[tail++] = state_;                                         \
        }                                                                   \
    } while (0)

    SSH_CONFIG_ENQUEUE(0U, 0U);
    while (head < tail) {
        size_t state = queue[head++];
        size_t left_offset = state / columns;
        size_t right_offset = state % columns;

        if (left_offset == left_len && right_offset == right_len) {
            intersects = true;
            break;
        }
        if (left_offset < left_len && left[left_offset] == '*') {
            SSH_CONFIG_ENQUEUE(left_offset + 1U, right_offset);
        }
        if (right_offset < right_len && right[right_offset] == '*') {
            SSH_CONFIG_ENQUEUE(left_offset, right_offset + 1U);
        }
        if (left_offset < left_len && right_offset < right_len &&
            ssh_config_pattern_bytes_overlap(
                (unsigned char)left[left_offset],
                (unsigned char)right[right_offset])) {
            size_t next_left =
                left[left_offset] == '*' ? left_offset : left_offset + 1U;
            size_t next_right =
                right[right_offset] == '*' ? right_offset : right_offset + 1U;

            SSH_CONFIG_ENQUEUE(next_left, next_right);
        }
    }

#undef SSH_CONFIG_ENQUEUE
    free(visited);
    free(queue);
    *intersects_out = intersects;
    return 0;
}

/* Decode the whitespace-separated pattern-list on one Host directive. Quotes
 * and backslash protect the following bytes exactly as they do in OpenSSH's
 * argument splitter. A Host line selects the alias when any positive pattern
 * matches and no negated pattern matches. For a wildcard managed alias, the
 * question is whether the two pattern languages can select any same hostname.
 * Exact containment under an arbitrary list of negated glob languages is
 * intentionally not approximated as safe: only an identical negative pattern
 * or '*' proves that the complete managed language is excluded. */
static int ssh_config_host_directive_matches(
    const char *arguments, size_t arguments_len, const char *alias,
    bool *matches) {
    char pattern[MAX_NAME_LEN];
    size_t offset = 0;
    bool positive_match = false;
    bool negative_match = false;
    bool alias_is_pattern =
        ssh_config_pattern_has_wildcard(alias, strlen(alias));

    *matches = false;

    while (offset < arguments_len) {
        size_t written = 0;
        char quote = '\0';
        bool escaped = false;
        bool first_byte_escaped = false;
        bool negated;

        while (offset < arguments_len &&
               ssh_config_argument_space(arguments[offset])) {
            offset++;
        }
        if (offset == arguments_len || arguments[offset] == '#') break;

        while (offset < arguments_len) {
            char c = arguments[offset++];

            if (escaped) {
                if (written + 1U >= sizeof(pattern)) {
                    set_error(ERR_FILE_IO,
                              "SSH Host pattern is too long to validate");
                    return -1;
                }
                if (written == 0U) first_byte_escaped = true;
                pattern[written++] = c;
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (quote != '\0') {
                if (c == quote) {
                    quote = '\0';
                } else {
                    if (written + 1U >= sizeof(pattern)) {
                        set_error(ERR_FILE_IO,
                                  "SSH Host pattern is too long to validate");
                        return -1;
                    }
                    pattern[written++] = c;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                quote = c;
                continue;
            }
            if (ssh_config_argument_space(c)) break;
            if (c == '#') {
                offset = arguments_len;
                break;
            }
            if (written + 1U >= sizeof(pattern)) {
                set_error(ERR_FILE_IO,
                          "SSH Host pattern is too long to validate");
                return -1;
            }
            pattern[written++] = c;
        }
        if (escaped || quote != '\0') {
            set_error(ERR_FILE_IO,
                      "Malformed quoting in SSH Host pattern list");
            return -1;
        }
        if (written == 0U) continue;
        pattern[written] = '\0';
        negated = !first_byte_escaped && pattern[0] == '!' && written > 1U;
        if (alias_is_pattern) {
            const char *candidate = pattern + (negated ? 1U : 0U);
            size_t candidate_len = written - (negated ? 1U : 0U);
            bool intersects;

            if (negated) {
                if ((candidate_len == 1U && candidate[0] == '*') ||
                    (candidate_len == strlen(alias) &&
                     memcmp(candidate, alias, candidate_len) == 0)) {
                    negative_match = true;
                }
            } else {
                if (ssh_config_host_patterns_intersect(
                        candidate, candidate_len, alias, strlen(alias),
                        &intersects) != 0) {
                    return -1;
                }
                if (intersects) positive_match = true;
            }
        } else if (ssh_config_host_pattern_matches(
                       pattern + (negated ? 1U : 0U),
                       written - (negated ? 1U : 0U), alias)) {
            if (negated) negative_match = true;
            else positive_match = true;
        }
    }
    *matches = positive_match && !negative_match;
    return 0;
}

/* The generated block is appended. An earlier matching Host section can
 * preempt HostName/IdentitiesOnly or add IdentityFile/CertificateFile
 * credential material, defeating the managed account boundary. Target-owned
 * blocks have already been filtered out before this check. Other transport
 * policy such as ProxyCommand, ProxyJump, User, or Port remains intentionally
 * user-controlled and does not contaminate the selected credential set. */
static int ssh_config_reject_prior_alias_routing(
    const char *buf, size_t len, const char *alias) {
    size_t scan = 0;
    bool matching_host = true;

    while (scan < len) {
        ssh_config_line_t line;
        const char *keyword;
        const char *arguments;
        size_t keyword_len;
        size_t arguments_len;

        (void)ssh_config_next_line(buf, len, scan, &line);
        scan = line.end;
        if (!ssh_config_parse_directive(
                buf, &line, &keyword, &keyword_len,
                &arguments, &arguments_len)) {
            continue;
        }
        if (ssh_config_ascii_case_equal(keyword, keyword_len, "host")) {
            if (ssh_config_host_directive_matches(
                    arguments, arguments_len, alias, &matching_host) != 0) {
                return -1;
            }
            continue;
        }
        if (ssh_config_ascii_case_equal(keyword, keyword_len, "match")) {
            set_error(ERR_FILE_IO,
                      "Cannot prove managed SSH alias '%s' precedence across "
                      "an existing Match directive",
                      alias);
            return -1;
        }
        if (ssh_config_ascii_case_equal(keyword, keyword_len, "include")) {
            if (!matching_host) continue;
            set_error(ERR_FILE_IO,
                      "Cannot prove managed SSH alias '%s' precedence across "
                      "an active Include directive",
                      alias);
            return -1;
        }
        if (matching_host &&
            (ssh_config_ascii_case_equal(keyword, keyword_len, "hostname") ||
             ssh_config_ascii_case_equal(keyword, keyword_len,
                                         "identityfile") ||
             ssh_config_ascii_case_equal(keyword, keyword_len,
                                         "identitiesonly") ||
             ssh_config_ascii_case_equal(keyword, keyword_len,
                                         "certificatefile"))) {
            set_error(ERR_FILE_IO,
                      "Earlier SSH Host pattern conflicts with managed alias "
                      "'%s' through option '%.*s'",
                      alias, (int)keyword_len, keyword);
            return -1;
        }
    }
    return 0;
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

/* Serialize IdentityFile as one double-quoted OpenSSH argument. Backslash
 * handling differs across supported OpenSSH parser generations, so reject it
 * rather than emit a path that can be invalid or silently retargeted. '%'
 * is doubled so %h/%r/etc. token expansion cannot reinterpret a literal
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
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\' || c == '$') {
            set_error(ERR_INVALID_PATH,
                      "SSH key path contains a double quote, backslash, "
                      "control byte, or unsafe OpenSSH expansion token: %s",
                      path);
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
                  "SSH config changed before update; refusing to continue: %s "
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

/* Rebind the final no-op proof to the currently public HOME/.ssh path. Opening
 * the public directory through the pinned HOME descriptor prevents an earlier
 * check of the retained directory fd from authorizing UNCHANGED after .ssh is
 * replaced. The trailing directory recheck detects a swap during this proof. */
static int ssh_config_recheck_public_unchanged(
    const char *home, const ssh_config_directory_t *directory,
    const char *display_path, const struct stat *identity, int pinned_fd,
    const char *original, size_t original_len) {
    struct stat current_directory;
    int current_dir_fd = -1;
    int rc = -1;
    int saved_errno;

    if (recheck_ssh_home_directory(home, directory) != 0) return -1;
    current_dir_fd = openat(directory->home_fd, ".ssh",
                            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (current_dir_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot reopen public SSH config directory: %s",
                         directory->path);
        return -1;
    }
    if (fstat(current_dir_fd, &current_directory) != 0 ||
        !ssh_config_directory_is_safe(&current_directory) ||
        !same_ssh_config_directory(&directory->dir_identity,
                                   &current_directory)) {
        set_error(ERR_FILE_IO,
                  "SSH config directory changed during final unchanged "
                  "verification: %s",
                  directory->path);
        goto done;
    }
    if (ssh_config_recheck_before_rename(
            current_dir_fd, display_path, true, identity, pinned_fd, original,
            original_len) != 0 ||
        recheck_ssh_config_directory(home, directory) != 0) {
        goto done;
    }
    rc = 0;

done:
    /* Preserve the transaction failure's errno across lock/descriptor
     * retirement; promote cleanup only after an otherwise successful result. */
    saved_errno = errno;
    if (close(current_dir_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot close final public SSH config directory "
                         "verification descriptor: %s",
                         directory->path);
        rc = -1;
    }
    if (rc != 0) errno = saved_errno;
    return rc;
}

/* Rebind a config-absent no-op to the currently public ~/.ssh directory after
 * its durability sync. A callback may replace the public directory during
 * fsync; checking only the retained dir_fd would then settle the wrong
 * namespace. */
static int ssh_config_recheck_public_absent(
    const char *home, const ssh_config_directory_t *directory) {
    struct stat current_directory;
    struct stat unexpected;
    int current_dir_fd = -1;
    int rc = -1;
    int saved_errno;

    if (recheck_ssh_home_directory(home, directory) != 0) return -1;
    current_dir_fd = openat(directory->home_fd, ".ssh",
                            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (current_dir_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot reopen public SSH directory for absent-config proof");
        return -1;
    }
    if (fstat(current_dir_fd, &current_directory) != 0 ||
        !ssh_config_directory_is_safe(&current_directory) ||
        !same_ssh_config_directory(
            &directory->dir_identity, &current_directory)) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH directory changed during absent-config verification");
        goto done;
    }
    if (fstatat(current_dir_fd, "config", &unexpected,
                AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH config appeared after its absent state was synchronized");
        goto done;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to reprove absent SSH config after directory sync");
        goto done;
    }
    if (recheck_ssh_config_directory(home, directory) != 0) {
        goto done;
    }
    if (fstatat(current_dir_fd, "config", &unexpected,
                AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EAGAIN;
        set_system_error(
            ERR_FILE_IO,
            "SSH config appeared while finalizing its absent state");
        goto done;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Failed final absent SSH config verification");
        goto done;
    }
    rc = 0;

done:
    saved_errno = errno;
    if (close(current_dir_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot close absent-config verification descriptor");
        rc = -1;
    }
    if (rc != 0) errno = saved_errno;
    return rc;
}

/* M25 narrowed new destinations so any colon-bearing value must be real IPv6.
 * Blocks emitted by older gitswitch versions could nevertheless contain a
 * host:port-shaped value under the former injection-safe ASCII grammar. The
 * ownership parser must recognize that exact historical output so configure
 * and remove can repair it. This helper is read/retirement compatibility only;
 * all admission and emission continue through toml_validate_ssh_hostname(). */
static bool ssh_config_historical_managed_hostname_valid(
    const char *hostname) {
    size_t len;

    if (!hostname) return false;
    len = strlen(hostname);
    if (len == 0U || len >= MAX_NAME_LEN) return false;
    for (const unsigned char *p = (const unsigned char *)hostname; *p; p++) {
        bool alphanumeric = (*p >= (unsigned char)'A' &&
                             *p <= (unsigned char)'Z') ||
                            (*p >= (unsigned char)'a' &&
                             *p <= (unsigned char)'z') ||
                            (*p >= (unsigned char)'0' &&
                             *p <= (unsigned char)'9');

        if (!(alphanumeric || *p == (unsigned char)'.' ||
              *p == (unsigned char)'-' || *p == (unsigned char)'_' ||
              *p == (unsigned char)':')) {
            return false;
        }
    }
    return true;
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
                if (!ssh_config_historical_managed_hostname_valid(hostname)) {
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

int ssh_preflight_host_alias_config(const account_t *account) {
    char ssh_config_path[MAX_PATH_LEN];
    char *buf = NULL;
    char *filtered = NULL;
    const char *home = getenv("HOME");
    struct stat config_identity;
    ssh_config_directory_t directory;
    size_t buf_len = 0;
    size_t filtered_len = 0;
    size_t removed = 0;
    bool config_existed = false;
    int pinned_config_fd = -1;
    int rc = -1;

    if (!account) {
        set_error(ERR_INVALID_ARGS,
                  "Cannot preflight SSH config for a null account");
        return -1;
    }
    if (!account->ssh_enabled || account->ssh_key_path[0] == '\0' ||
        account->ssh_host_alias[0] == '\0') {
        return 0;
    }
    if (!valid_ssh_host_alias(account->ssh_host_alias)) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH host alias: %s",
                  account->ssh_host_alias);
        return -1;
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH,
                  "Cannot preflight ~/.ssh/config: HOME is not set");
        return -1;
    }

    if (open_ssh_config_directory(home, false, &directory) != 0) {
        return directory.absent ? 0 : -1;
    }
    if ((size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config",
                         directory.path) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH,
                  "Cannot preflight ~/.ssh/config: path is too long");
        goto done;
    }
    if (read_ssh_config_at(directory.dir_fd, ssh_config_path, &buf, &buf_len,
                           &config_existed, &config_identity,
                           &pinned_config_fd) != 0) {
        goto done;
    }
    if (ssh_filter_managed_blocks(buf, buf_len, account->ssh_host_alias,
                                  &filtered, &filtered_len, &removed) != 0) {
        goto done;
    }
    if (ssh_config_reject_prior_alias_routing(
            filtered, filtered_len, account->ssh_host_alias) != 0) {
        goto done;
    }
    rc = 0;

done:
    free(buf);
    free(filtered);
    if (pinned_config_fd >= 0 && close(pinned_config_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close preflighted SSH config");
        rc = -1;
    }
    if (directory.dir_fd >= 0 && close(directory.dir_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close preflighted SSH config directory");
        rc = -1;
    }
    if (directory.home_fd >= 0 && close(directory.home_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close preflighted SSH config HOME");
        rc = -1;
    }
    return rc;
}

/* Create a random O_EXCL temp under the pinned directory, write and fsync its
 * exact byte length, revalidate directory/config/temp identities, renameat,
 * then fsync the directory entry. A post-rename verification/sync failure is
 * explicitly reported as installed/uncertain; callers must never claim
 * success. */
static int ssh_write_config_atomic_at(
    const char *home, const ssh_config_directory_t *directory,
    const char *display_path, const char *content, size_t content_len,
    bool config_existed, const struct stat *config_identity,
    int pinned_config_fd, const char *original_content,
    size_t original_len,
    const config_retirement_ssh_alias_obligation_t *obligation,
    ssh_config_publication_state_t *publication) {
    static const char random_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char suffix[17];
    char temp_name[64];
    char temp_path[MAX_PATH_LEN];
    struct stat created_temp;
    struct stat temp_identity;
    struct stat current_temp;
    struct stat held_temp;
    struct stat installed;
    error_accumulator_t failures;
    size_t written = 0;
    int dir_fd = directory->dir_fd;
    const char *dir_path = directory->path;
    int fd = -1;
    int saved_errno;
    bool cleanup_resolved = false;
    bool forced_failure;
    bool have_temp_identity = false;
    bool temp_registered = false;
    bool renamed = false;

    /* Every caller holds the pinned directory's private config-transaction
     * lock. Settle any exact identity-bound obligation from an earlier
     * failed unlink before admitting another writer generation. */
    if (signals_scratch_cleanup_identities_at(dir_fd, dir_path) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Failed to settle a retained temporary SSH config cleanup");
        return -1;
    }

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
    /* Capture the O_EXCL generation before any other fallible operation.
     * Without that identity, deleting by pathname would be unsafe: another
     * same-UID actor may already have replaced the entry. */
    errno = 0;
    forced_failure =
        g_metadata_test_hook &&
        g_metadata_test_hook(SSH_METADATA_TEST_CONFIG_TEMP_INITIAL_FSTAT);
    if (forced_failure || fstat(fd, &created_temp) != 0) {
        if (forced_failure && errno == 0) errno = EIO;
        set_system_error(ERR_FILE_IO,
                         "Failed to capture temporary SSH config identity");
        goto fail;
    }
    have_temp_identity = true;
    if (signals_scratch_register_identity(temp_path, &created_temp) != 0) {
        set_error(ERR_FILE_IO,
                  "Failed to register temporary SSH config identity for cleanup");
        goto fail;
    }
    temp_registered = true;

    if (fchmod(fd, 0600) != 0 || fstat(fd, &temp_identity) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to secure temporary SSH config");
        goto fail;
    }
    if (!S_ISREG(temp_identity.st_mode) ||
        temp_identity.st_uid != getuid() || temp_identity.st_nlink != 1 ||
        (temp_identity.st_mode & 0777) != 0600) {
        set_error(ERR_FILE_IO,
                  "Temporary SSH config failed security validation");
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
    if (g_ssh_config_commit_hook &&
        g_ssh_config_commit_hook(dir_fd, temp_name) != 0) {
        set_error(ERR_FILE_IO, "Injected SSH config commit interruption");
        goto fail;
    }
    if (recheck_ssh_config_directory(home, directory) != 0 ||
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
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(
            ERR_FILE_IO,
            "SSH config was installed but its temporary descriptor could not "
            "be closed; the replacement's public state is uncertain");
        return -1;
    }
    fd = -1;

    if (g_ssh_config_postrename_hook &&
        g_ssh_config_postrename_hook(dir_fd) != 0) {
        set_error(ERR_FILE_IO,
                  "SSH config was installed but injected post-rename "
                  "verification failed; the replacement was retained and "
                  "its public identity is uncertain");
        return -1;
    }
    if (recheck_ssh_config_directory(home, directory) != 0 ||
        fstatat(dir_fd, "config", &installed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_installed_ssh_config(&temp_identity, &installed)) {
        set_error(ERR_FILE_IO,
                  "SSH config was replaced but post-rename verification failed; "
                  "the replacement's public state is uncertain");
        return -1;
    }
    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
    }
    if (g_ssh_dirsync(dir_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "SSH config was replaced but its directory sync failed; "
            "replacement durability is uncertain");
        return -1;
    }
    if (obligation) {
        if (ssh_recheck_open_alias_obligation(
                home, directory, obligation) != 0) {
            return -1;
        }
    } else if (recheck_ssh_config_directory(home, directory) != 0) {
        return -1;
    }
    if (fstatat(dir_fd, "config", &installed,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_installed_ssh_config(&temp_identity, &installed)) {
        set_error(
            ERR_FILE_IO,
            "SSH config was synchronized but its final installed generation "
            "changed; publication remains uncertain");
        return -1;
    }
    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_COMMITTED;
    }
    return 0;

fail:
    saved_errno = errno;
    error_accumulator_init(&failures);
    errno = saved_errno;
    (void)error_accumulator_add_last(&failures, "SSH config publication");

    if (!renamed && !have_temp_identity) {
        set_error(
            ERR_FILE_IO,
            "Temporary SSH config identity is unknown; retained untracked "
            "path '%s' rather than risk deleting a replacement generation",
            temp_path);
        (void)error_accumulator_add_last(
            &failures, "temporary SSH config cleanup");
    } else if (!renamed) {
        errno = 0;
        if (fd < 0 || fstat(fd, &held_temp) != 0 ||
            held_temp.st_dev != created_temp.st_dev ||
            held_temp.st_ino != created_temp.st_ino) {
            if (errno == 0) errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Temporary SSH config descriptor changed; retained '%s' %s",
                temp_path,
                temp_registered
                    ? "for checked cleanup retry"
                    : "without cleanup tracking for manual recovery");
            (void)error_accumulator_add_last(
                &failures, "temporary SSH config cleanup");
        } else {
            /* The metadata hook represents the last in-process writer
             * boundary and therefore runs before the final name proof. All
             * cooperating writers hold .gitswitch-config.lock; after this
             * hook there is no callback or fallible step between fstatat()
             * and unlinkat(). An uncooperative process with the same uid can
             * rewrite any entry in this user-owned directory and is outside
             * that POSIX serialization boundary. */
            errno = 0;
            forced_failure =
                g_metadata_test_hook &&
                g_metadata_test_hook(
                    SSH_METADATA_TEST_CONFIG_TEMP_CLEANUP_PREPROOF);
            if (forced_failure) {
                if (errno == 0) errno = EIO;
                set_system_error(
                    ERR_FILE_IO,
                    "Failed to remove temporary SSH config '%s'; %s",
                    temp_path,
                    temp_registered
                        ? "identity-bound cleanup remains registered for retry"
                        : "the untracked file was retained for manual cleanup");
                (void)error_accumulator_add_last(
                    &failures, "temporary SSH config cleanup");
            } else if (fstatat(dir_fd, temp_name, &current_temp,
                               AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT) {
                    cleanup_resolved = true;
                } else {
                    set_system_error(
                        ERR_FILE_IO,
                        "Failed to inspect temporary SSH config '%s'; %s",
                        temp_path,
                        temp_registered
                            ? "retained its identity-bound cleanup "
                              "registration for retry"
                            : "retained the untracked file for manual "
                              "recovery");
                    (void)error_accumulator_add_last(
                        &failures, "temporary SSH config cleanup");
                }
            } else if (current_temp.st_dev != created_temp.st_dev ||
                       current_temp.st_ino != created_temp.st_ino ||
                       !S_ISREG(current_temp.st_mode) ||
                       current_temp.st_uid != getuid() ||
                       current_temp.st_nlink != 1) {
                /* The public name no longer denotes our O_EXCL generation.
                 * Preserve the replacement and retire only our stale
                 * obligation. */
                cleanup_resolved = true;
            } else if (unlinkat(dir_fd, temp_name, 0) == 0 ||
                       errno == ENOENT) {
                cleanup_resolved = true;
            } else {
                set_system_error(
                    ERR_FILE_IO,
                    "Failed to remove temporary SSH config '%s'; %s",
                    temp_path,
                    temp_registered
                        ? "identity-bound cleanup remains registered for retry"
                        : "the untracked file was retained for manual cleanup");
                (void)error_accumulator_add_last(
                    &failures, "temporary SSH config cleanup");
            }
        }
    }
    if (cleanup_resolved && temp_registered) {
        signals_scratch_unregister(temp_path);
        temp_registered = false;
    }
    if (fd >= 0 && close(fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close temporary SSH config descriptor");
        (void)error_accumulator_add_last(
            &failures, "temporary SSH config descriptor cleanup");
    }
    (void)error_accumulator_publish(&failures);
    return -1;
}

/* Remove the managed host-alias block for `alias` from ~/.ssh/config (AR-06
 * F15). Account removal (and alias edits) used to leave a permanent
 * "Host <alias>" stanza routing git traffic to the removed account's key, since
 * nothing ever deleted a managed block. No-op if the config or the block is
 * absent. Returns 0 on success (including no-op), -1 on I/O failure. */
static int ssh_remove_host_alias_result_internal(
    const char *alias,
    const config_retirement_ssh_alias_obligation_t *obligation,
    ssh_config_publication_state_t *publication) {
    char ssh_config_path[MAX_PATH_LEN];
    char *buf = NULL;
    char *filtered = NULL;
    const char *home = getenv("HOME");
    struct stat config_identity;
    ssh_config_directory_t directory = {
        .home_fd = -1,
        .dir_fd = -1
    };
    size_t buf_len = 0;
    size_t filtered_len = 0;
    size_t removed = 0;
    bool config_existed;
    int config_lock_fd = -1;
    int pinned_config_fd = -1;
    int rc = -1;
    int saved_errno;

    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED;
    }
    if (!alias || !*alias) {
        set_error(ERR_INVALID_ARGS,
                  "SSH host alias removal requires a non-empty alias");
        return -1;
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH, "HOME not set");
        return -1;
    }
    if (!valid_ssh_host_alias(alias)) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH host alias: %s", alias);
        return -1;
    }
    if (open_ssh_config_directory(home, false, &directory) != 0) {
        if (directory.absent) {
            if (obligation) {
                errno = EAGAIN;
                set_system_error(
                    ERR_FILE_IO,
                    "Required SSH directory is absent for alias obligation");
                return -1;
            }
            if (prove_absent_ssh_config_directory_durable(
                    home, NULL, publication) != 0) {
                return -1;
            }
            if (publication) {
                *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
            }
            return 0;
        }
        return -1;
    }
    if (obligation &&
        ssh_recheck_open_alias_obligation(
            home, &directory, obligation) != 0) {
        goto done;
    }
    /* Serialize the complete read/transform/publish transaction.  Locking only
     * the final rename still lets two gitswitch processes read the same base
     * file and silently overwrite one another's managed-block update.  The
     * private-lock helper pins the parent and ~/.ssh directory as well as this
     * lock inode, so a namespace replacement cannot create a second unlocked
     * writer domain. */
    config_lock_fd = lock_private_file_at(directory.dir_fd,
                                          ".gitswitch-config.lock");
    if (config_lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock SSH config transaction");
        goto done;
    }
    if (obligation &&
        ssh_recheck_open_alias_obligation(
            home, &directory, obligation) != 0) {
        goto done;
    }
    if ((size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config",
                         directory.path) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH, "SSH config path too long");
        goto done;
    }
    if (read_ssh_config_at(directory.dir_fd, ssh_config_path, &buf, &buf_len,
                           &config_existed, &config_identity,
                           &pinned_config_fd) != 0) {
        goto done;
    }
    if (!config_existed) {
        if (publication) {
            *publication =
                SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
        }
        if (g_ssh_dirsync(directory.dir_fd) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "SSH config is absent but its directory sync failed; "
                "alias-removal durability remains uncertain");
            goto done;
        }
        if (obligation &&
            ssh_recheck_open_alias_obligation(
                home, &directory, obligation) != 0) {
            goto done;
        }
        if (ssh_config_recheck_public_absent(
                home, &directory) != 0) {
            goto done;
        }
        if (obligation &&
            ssh_recheck_open_alias_obligation(
                home, &directory, obligation) != 0) {
            goto done;
        }
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
        }
        rc = 0;
        goto done;
    }
    if (ssh_filter_managed_blocks(buf, buf_len, alias, &filtered,
                                  &filtered_len, &removed) != 0) {
        goto done;
    }
    if (removed == 0) {
        /* AR-13 M2 (AR-12 M6 class): the current on-disk config has no managed
         * block for this alias — but a prior removal may have written exactly
         * this content and then failed its directory sync, leaving the removal
         * cache-visible yet not durable. Re-prove durability with the same
         * directory sync the write path performs before reporting the no-op
         * committed, rather than converting that uncertainty into success. */
        if (publication) {
            *publication =
                SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
        }
        if (g_ssh_dirsync(directory.dir_fd) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "SSH host alias is already absent but the config directory "
                "sync failed; alias-removal durability remains uncertain");
            goto done; /* rc remains -1 */
        }
        if (obligation &&
            ssh_recheck_open_alias_obligation(
                home, &directory, obligation) != 0) {
            goto done;
        }
        if (ssh_config_recheck_public_unchanged(
                home, &directory, ssh_config_path,
                &config_identity, pinned_config_fd, buf, buf_len) != 0) {
            goto done;
        }
        if (obligation &&
            ssh_recheck_open_alias_obligation(
                home, &directory, obligation) != 0) {
            goto done;
        }
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
        }
        rc = 0;
        goto done;
    }

    if (ssh_write_config_atomic_at(home, &directory,
                                   ssh_config_path, filtered, filtered_len,
                                   config_existed, &config_identity,
                                   pinned_config_fd, buf, buf_len,
                                   obligation, publication) != 0) {
        goto done;
    }
    log_info("Removed %zu SSH host alias block%s: %s", removed,
             removed == 1U ? "" : "s", alias);
    rc = 0;
done:
    saved_errno = errno;
    free(buf);
    free(filtered);
    if (pinned_config_fd >= 0 && close(pinned_config_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config");
        rc = -1;
    }
    if (config_lock_fd >= 0) unlock_private_file(config_lock_fd);
    if (directory.dir_fd >= 0 && close(directory.dir_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config directory");
        rc = -1;
    }
    if (directory.home_fd >= 0 && close(directory.home_fd) != 0 && rc == 0) {
        saved_errno = errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config HOME");
        rc = -1;
    }
    if (rc != 0) errno = saved_errno;
    return rc;
}

int ssh_remove_host_alias_obligation_result(
    const config_retirement_ssh_alias_obligation_t *obligation,
    ssh_config_publication_state_t *publication) {
    const char *home = getenv("HOME");

    if (publication) {
        *publication = SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED;
    }
    if (!ssh_alias_obligation_is_valid(obligation)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH alias retirement obligation");
        return -1;
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH, "HOME not set");
        return -1;
    }
    if (!obligation->ssh_directory_identity.present) {
        if (prove_absent_ssh_config_directory_durable(
                home, obligation, publication) != 0) {
            return -1;
        }
        if (publication) {
            *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
        }
        return 0;
    }
    return ssh_remove_host_alias_result_internal(
        obligation->ssh_host_alias, obligation, publication);
}

int ssh_remove_host_alias_result(
    const char *alias,
    ssh_config_publication_state_t *publication) {
    return ssh_remove_host_alias_result_internal(
        alias, NULL, publication);
}

int ssh_remove_host_alias(const char *alias) {
    if (!alias || !*alias) return 0;
    return ssh_remove_host_alias_result(alias, NULL);
}

int ssh_configure_host_alias_result(
    const account_t *account,
    ssh_config_publication_state_t *publication) {
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
    struct stat config_identity;
    ssh_config_directory_t directory = {
        .home_fd = -1,
        .dir_fd = -1
    };
    bool config_existed;
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
    /* IdentityFile has its own OpenSSH-grammar serializer. Keep validation at
     * this sink: it rejects controls, double quotes, non-portable backslashes,
     * and dollar expansion; doubles percent tokens; and permits apostrophes
     * because they are literal inside OpenSSH's double-quoted argument form. */
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

    if (open_ssh_config_directory(home, true, &directory) != 0) goto done;
    config_lock_fd = lock_private_file_at(directory.dir_fd,
                                          ".gitswitch-config.lock");
    if (config_lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock SSH config transaction");
        goto done;
    }
    if ((size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config",
                         directory.path) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH, "SSH config path too long");
        goto done;
    }

    if (read_ssh_config_at(directory.dir_fd, ssh_config_path, &buf, &buf_len,
                           &config_existed, &config_identity,
                           &pinned_config_fd) != 0) {
        goto done;
    }
    if (ssh_filter_managed_blocks(buf, buf_len, account->ssh_host_alias,
                                  &filtered, &filtered_len, &removed) != 0) {
        goto done;
    }
    if (ssh_config_reject_prior_alias_routing(
            filtered, filtered_len, account->ssh_host_alias) != 0) {
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
        if (ssh_config_file_is_safe_unchanged(&config_identity)) {
            /* The read-side snapshot alone cannot authorize a no-op: mode,
             * ownership, the public name, or either containing directory may
             * change while the managed block is rebuilt. Tests may mutate at
             * this exact boundary; production leaves the hook NULL. */
            if (g_metadata_test_hook) {
                (void)g_metadata_test_hook(
                    SSH_METADATA_TEST_CONFIG_UNCHANGED_RECHECK);
            }
            if (recheck_ssh_config_directory(home, &directory) != 0 ||
                ssh_config_recheck_before_rename(
                    directory.dir_fd, ssh_config_path, true,
                    &config_identity, pinned_config_fd, buf, buf_len) != 0) {
                goto done;
            }
            if (g_metadata_test_hook) {
                (void)g_metadata_test_hook(
                    SSH_METADATA_TEST_CONFIG_UNCHANGED_FINAL_RECHECK);
            }
            if (ssh_config_recheck_public_unchanged(
                    home, &directory, ssh_config_path, &config_identity,
                    pinned_config_fd, buf, buf_len) != 0) {
                goto done;
            }
            /* AR-12 M6: this retry may follow a rename whose directory sync
             * failed (DURABILITY_UNCERTAIN was reported and the switch
             * retained). Content identity alone cannot convert that
             * uncertainty into success — re-prove the directory entry's
             * durability now, mirroring unlink_ssh_runtime_entry's
             * sync-the-observed-state principle. */
            if (publication) {
                *publication =
                    SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
            }
            if (g_ssh_dirsync(directory.dir_fd) != 0) {
                set_system_error(
                    ERR_FILE_IO,
                    "SSH config is already current but its directory sync "
                    "failed; publication durability remains uncertain");
                goto done;
            }
            if (ssh_config_recheck_public_unchanged(
                    home, &directory, ssh_config_path, &config_identity,
                    pinned_config_fd, buf, buf_len) != 0) {
                goto done;
            }
            log_debug(
                "SSH host alias block already current and private; "
                "skipping rewrite");
            if (publication) {
                *publication = SSH_CONFIG_PUBLICATION_UNCHANGED;
            }
            rc = 0;
            goto done;
        }
        /* Preserve the exact bytes, but sever any writable hard link or open
         * writer from the public config name by using the same atomic 0600
         * replacement protocol as a content change. */
        log_debug(
            "SSH host alias block is current but its owner or mode is unsafe; "
            "normalizing with an atomic replacement");
    }

    /* A failed or interrupted first-creation HOME sync can leave an empty
     * .ssh in the live namespace without proving that entry crash-durable.
     * There is no trustworthy on-disk provenance marker that distinguishes
     * that residue from an older config-less .ssh, so the first config
     * publication conservatively re-syncs HOME unless this call already
     * proved the parent sync. */
    if (!config_existed && !directory.home_entry_synced &&
        sync_ssh_home_entry(home, &directory) != 0) {
        goto done;
    }

    /* Install atomically at 0600 via the shared writer (AR-06 F15 factored the
     * mkstemp + checked-write/fsync + recheck + rename dance out so remove can
     * reuse it). */
    if (ssh_write_config_atomic_at(home, &directory,
                                   ssh_config_path, newbuf, newbuf_len,
                                   config_existed, &config_identity,
                                   pinned_config_fd, buf, buf_len,
                                   NULL, publication) != 0) {
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
    if (directory.dir_fd >= 0 && close(directory.dir_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config directory");
        rc = -1;
    }
    if (directory.home_fd >= 0 && close(directory.home_fd) != 0 && rc == 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close pinned SSH config HOME");
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
        result->out_truncated || result->timed_out) {
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

static int ssh_test_connection_impl(const account_t *account,
                                    const char *host,
                                    bool use_deadline,
                                    int64_t deadline_millis) {
    char output[1024] = {0};
    char expanded_key_path[MAX_PATH_LEN];
    char hostname_option[sizeof("HostName=") + MAX_NAME_LEN];
    char alias_target[sizeof("git@") + MAX_NAME_LEN];
    run_opts_t opts;
    run_result_t result;

    if (!account || !host || (use_deadline && deadline_millis < 0)) {
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
    opts.use_deadline = use_deadline;
    opts.deadline_millis = use_deadline ? deadline_millis : 0;

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
            alias_target, NULL};

        if (!valid_ssh_host_alias(account->ssh_host_alias) ||
            !toml_validate_ssh_hostname(account->ssh_hostname)) {
            set_error(ERR_INVALID_ARGS,
                      "Managed SSH alias requires a valid alias and canonical "
                      "hostname");
            return -1;
        }
        /* `-F none` deliberately removes every configured `User` value too.
         * Keep the managed probe aligned with Git's direct transport target
         * instead of silently authenticating as the local login account. */
        if (safe_snprintf(hostname_option, sizeof(hostname_option),
                          "HostName=%s", account->ssh_hostname) != 0 ||
            safe_snprintf(alias_target, sizeof(alias_target), "git@%s",
                          account->ssh_host_alias) != 0) {
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

/* Public compatibility entry point: existing callers retain the historical
 * unbounded process-runner contract. */
int ssh_test_connection(const account_t *account, const char *host) {
    return ssh_test_connection_impl(account, host, false, 0);
}

int ssh_test_connection_with_deadline(const account_t *account,
                                      const char *host,
                                      int64_t deadline_millis) {
    return ssh_test_connection_impl(account, host, true, deadline_millis);
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

/* Public: compute the stable SSH_AUTH_SOCK symlink path. A configured
 * nonempty XDG_RUNTIME_DIR is authoritative and missing/invalid roots fail;
 * /tmp is selected only when the variable is unset or empty. Mirrors the
 * selection done by create_isolated_agent_socket_dir() so shell
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
static bool parse_complete_ssh_agent_pid(const char *output,
                                         size_t output_len,
                                         bool output_truncated,
                                         pid_t *pid_out) {
    static const char prefix[] = "SSH_AGENT_PID=";
    bool found = false;
    pid_t parsed_pid = -1;

    if (!output || !pid_out || output_len == 0U || output_truncated ||
        strnlen(output, output_len) != output_len) {
        return false;
    }
    for (size_t i = 0; i + sizeof(prefix) - 1U < output_len; i++) {
        size_t cursor;
        uintmax_t value = 0U;
        pid_t candidate;

        if ((i != 0U && output[i - 1U] != '\n') ||
            memcmp(output + i, prefix, sizeof(prefix) - 1U) != 0) {
            continue;
        }
        cursor = i + sizeof(prefix) - 1U;
        if (cursor >= output_len || output[cursor] < '0' ||
            output[cursor] > '9') {
            return false;
        }
        while (cursor < output_len && output[cursor] >= '0' &&
               output[cursor] <= '9') {
            unsigned digit = (unsigned)(output[cursor] - '0');
            if (value > (UINTMAX_MAX - digit) / 10U) return false;
            value = value * 10U + digit;
            cursor++;
        }
        if (cursor >= output_len || output[cursor] != ';') return false;
        candidate = (pid_t)value;
        if (candidate <= 1 || (uintmax_t)candidate != value) return false;
        if (found && parsed_pid != candidate) return false;
        found = true;
        parsed_pid = candidate;
        i = cursor;
    }
    if (found) *pid_out = parsed_pid;
    return found;
}

static int parse_ssh_agent_output(const char *output, size_t output_len,
                                  bool output_truncated,
                                  ssh_config_t *ssh_config) {
    char *line;
    char *output_copy;
    char *saveptr;
    pid_t parsed_pid = -1;
    
    if (!output || !ssh_config ||
        !parse_complete_ssh_agent_pid(output, output_len,
                                      output_truncated, &parsed_pid)) {
        return -1;
    }
    ssh_config->agent_pid = parsed_pid;
    
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
    if (fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;
        int retire_rc = unlink_ssh_runtime_identity_at(
            dir_fd, pin->anchor, &opened, false,
            "failed SSH runtime pin anchor rollback", NULL, NULL);
        if (retire_rc == 0) pin->anchor[0] = '\0';
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "SSH runtime artifact changed while being anchored; pin %s: %s",
            retire_rc == 0 ? "retired" : "retained for retry",
            display_path ? display_path : name);
        return -1;
    }
    {
        bool forced_mismatch =
            g_metadata_test_hook &&
            g_metadata_test_hook(SSH_METADATA_TEST_RUNTIME_PIN);
        errno = 0;
        if (forced_mismatch || !same_runtime_identity(&before, &opened) ||
            !same_runtime_identity(&opened, &named)) {
            int retire_rc = unlink_ssh_runtime_identity_at(
                dir_fd, pin->anchor, &opened, false,
                "failed SSH runtime pin anchor rollback", NULL, NULL);
            if (retire_rc == 0) pin->anchor[0] = '\0';
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "SSH runtime artifact changed while being anchored; pin %s: %s",
                retire_rc == 0 ? "retired" : "retained for retry",
                display_path ? display_path : name);
            return -1;
        }
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
        fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "SSH runtime artifact changed while being pinned: %s",
                         display_path ? display_path : name);
        return -1;
    }
    {
        bool forced_mismatch =
            g_metadata_test_hook &&
            g_metadata_test_hook(SSH_METADATA_TEST_RUNTIME_PIN);
        errno = 0;
        if (forced_mismatch || !same_runtime_identity(&opened, &named)) {
            close(fd);
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "SSH runtime artifact changed while being pinned: %s",
                display_path ? display_path : name);
            return -1;
        }
    }
    pin->identity = opened;
    pin->fd = fd;
    return 0;
}

/* Runtime discovery is observational. On systems with O_PATH, reuse the
 * descriptor pin without touching the namespace. Platforms that cannot open
 * a filesystem socket use a revision snapshot under the already-held exact
 * manager lock; every supported writer takes that lock, and the named entry
 * is revalidated after each external scheduling point. Mutating teardown and
 * publication paths retain the hard-link anchor fallback above. */
static int observe_ssh_runtime_entry_at(int dir_fd, const char *name,
                                        const char *display_path,
                                        ssh_runtime_pin_t *pin) {
#if defined(O_PATH)
    return pin_ssh_runtime_entry_at(dir_fd, name, display_path, pin);
#else
    struct stat named;

    if (dir_fd < 0 || !name || !*name || !pin) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid SSH runtime observation arguments");
        errno = EINVAL;
        return -1;
    }
    ssh_runtime_pin_init(pin);
    if (fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 1;
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH runtime artifact: %s",
                         display_path ? display_path : name);
        return -1;
    }
    pin->identity = named;
    pin->observational = true;
    return 0;
#endif
}

static int verify_ssh_runtime_pin_at(int dir_fd, const char *name,
                                     const char *display_path,
                                     const ssh_runtime_pin_t *pin) {
    struct stat held;
    struct stat named;

    if (pin && pin->observational) {
        if (fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_runtime_revision(&pin->identity, &named)) {
            set_error(ERR_FILE_IO,
                      "SSH runtime artifact changed while observed: %s",
                      display_path ? display_path : name);
            errno = ESTALE;
            return -1;
        }
        return 0;
    }

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

/* A safe malformed PID record can never authorize signaling. It can authorize
 * retirement only when the paired socket generation, observed under the same
 * manager lock, is conclusively absent or unreachable. */
static int prove_malformed_pid_socket_dead_at(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const ssh_runtime_pin_t *socket_pin,
    bool socket_present, bool allow_detached_namespace,
    const char *record_description) {
    bool reachable = false;
    const char *description =
        record_description && *record_description
            ? record_description
            : "an untrusted process record";
    bool public_namespace_current =
        verify_socket_dir_namespace(dir_fd, socket_dir) == 0;

    if (public_namespace_current) {
        if (g_socket_probe(socket_path, &reachable) != 0 ||
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            return -1;
        }
    } else if (socket_present && allow_detached_namespace) {
#ifdef __linux__
        char anchored_path[MAX_PATH_LEN];
        int written = snprintf(anchored_path, sizeof(anchored_path),
                               "/proc/self/fd/%d/%s", dir_fd, socket_name);
        if (written <= 0 || (size_t)written >= sizeof(anchored_path) ||
            g_socket_probe(anchored_path, &reachable) != 0) {
            return -1;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__)
        char pinned_dir_path[MAX_PATH_LEN];
        char anchored_path[MAX_PATH_LEN];
        struct stat held_dir;
        struct stat named_dir;
        int written;
#if defined(__APPLE__)
        if (fcntl(dir_fd, F_GETPATH, pinned_dir_path) != 0) return -1;
#elif defined(F_KINFO)
        {
            struct kinfo_file info;
            memset(&info, 0, sizeof(info));
            info.kf_structsize = sizeof(info);
            if (fcntl(dir_fd, F_KINFO, &info) != 0 ||
                info.kf_path[0] == '\0' ||
                safe_strncpy(pinned_dir_path, info.kf_path,
                             sizeof(pinned_dir_path)) != 0) {
                return -1;
            }
        }
#else
        return -1;
#endif
        if (fstat(dir_fd, &held_dir) != 0 ||
            stat(pinned_dir_path, &named_dir) != 0 ||
            !same_runtime_identity(&held_dir, &named_dir)) {
            return -1;
        }
        written = snprintf(anchored_path, sizeof(anchored_path), "%s/%s",
                           pinned_dir_path, socket_name);
        if (written <= 0 || (size_t)written >= sizeof(anchored_path) ||
            g_socket_probe(anchored_path, &reachable) != 0 ||
            stat(pinned_dir_path, &named_dir) != 0 ||
            !same_runtime_identity(&held_dir, &named_dir)) {
            return -1;
        }
#else
        return -1;
#endif
    } else if (!public_namespace_current &&
               (!allow_detached_namespace || socket_present)) {
        return -1;
    }
    if (reachable) {
        set_error(
            ERR_SSH_AGENT_FAILED,
            "Reachable SSH agent socket has %s; retained for retry: %s",
            description, socket_path);
        return -1;
    }
    if (socket_present) {
        return verify_ssh_runtime_pin_at(dir_fd, socket_name, socket_path,
                                         socket_pin);
    }

    struct stat appeared;
    if (fstatat(dir_fd, socket_name, &appeared, AT_SYMLINK_NOFOLLOW) == 0) {
        set_error(
            ERR_FILE_IO,
            "SSH agent socket appeared during %s recovery; replacement retained: %s",
            description, socket_path);
        return -1;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot confirm absent SSH agent socket during %s recovery: %s",
            description, socket_path);
        return -1;
    }
    return 0;
}

static ssh_process_outcome_t prove_recorded_agent_identity(
    const ssh_agent_record_t *record, const char *socket_path, int dir_fd) {
    ssh_process_outcome_t outcome =
        g_reap_ops.identity(record, socket_path, dir_fd);

    if (outcome == SSH_PROCESS_INDETERMINATE) {
        outcome = g_reap_ops.identity(record, socket_path, dir_fd);
    }
    return outcome;
}

static int retire_recorded_agent_endpoint(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const char *pid_name,
    const ssh_runtime_pin_t *socket_pin,
    const ssh_runtime_pin_t *pid_pin,
    const ssh_agent_record_t *record) {
    ssh_agent_connection_t connection;
    ssh_process_outcome_t process_outcome;
    uint32_t identity_count;
    int64_t preflight_deadline;
    int64_t deadline;
    int rc = -1;

    connection.fd = -1;
    if (!record || !record->image.valid ||
        (record->generation.kind != SSH_PROCESS_GENERATION_DARWIN &&
         record->generation.kind != SSH_PROCESS_GENERATION_FREEBSD) ||
        record->image.effective_uid != getuid() ||
        !socket_pin || !pid_pin ||
        !S_ISSOCK(socket_pin->identity.st_mode) ||
        socket_pin->identity.st_uid != getuid() ||
        (socket_pin->identity.st_mode & 0777) != 0600 ||
        verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, socket_name, socket_path, socket_pin) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, pid_name, NULL, pid_pin) != 0 ||
        !pinned_pid_sidecar_matches_record(pid_pin, record)) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Recorded SSH endpoint proof is incomplete; retained for retry: %s",
                  socket_path);
        return -1;
    }
    if (open_socket_peer(socket_path, dir_fd, &connection) != 0) {
        set_system_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint connection could not be authenticated; "
            "retained for retry: %s",
            socket_path);
        goto out;
    }
    if (record->generation.kind == SSH_PROCESS_GENERATION_DARWIN) {
        if (ssh_agent_deadline(&preflight_deadline) != 0 ||
            ssh_agent_request_identities(
                connection.fd, preflight_deadline,
                &identity_count) != 0 ||
            capture_socket_peer_credentials(
                connection.fd, &connection.peer_pid,
                &connection.peer_uid) != 0) {
            set_system_error(
                ERR_SSH_AGENT_FAILED,
                "Recorded Darwin SSH endpoint preflight could not be "
                "authenticated; retained for retry: %s",
                socket_path);
            goto out;
        }
    }
    if (connection.peer_pid != record->image.socket_peer_pid ||
        connection.peer_uid != record->image.socket_peer_uid ||
        connection.peer_uid != getuid()) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Recorded SSH endpoint socket peer mismatch; retained for "
                  "retry: %s",
                  socket_path);
        goto out;
    }
    process_outcome = verify_expected_process_generation(record);
    if (process_outcome != SSH_PROCESS_OWNED) {
        set_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint process generation outcome %s; retained "
            "for retry: %s",
            ssh_process_outcome_name(process_outcome), socket_path);
        goto out;
    }
    process_outcome =
        prove_recorded_agent_identity(record, socket_path, dir_fd);
    if (process_outcome != SSH_PROCESS_OWNED) {
        set_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint process identity outcome %s; retained "
            "for retry: %s",
            ssh_process_outcome_name(process_outcome), socket_path);
        goto out;
    }
    if (ssh_agent_deadline(&deadline) != 0) {
        set_system_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint protocol deadline could not be established; "
            "retained for retry: %s",
            socket_path);
        goto out;
    }

    /* Mutation authority is established only immediately before REMOVE_ALL.
     * Every proof remains anchored to the original connected descriptor and
     * the exact pinned sidecar/socket generations. */
    if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, socket_name, socket_path, socket_pin) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, pid_name, NULL, pid_pin) != 0 ||
        !pinned_pid_sidecar_matches_record(pid_pin, record)) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Recorded SSH endpoint namespace changed before key "
                  "retirement; "
                  "retained for retry: %s", socket_path);
        goto out;
    }
    if (connection.peer_pid != record->image.socket_peer_pid ||
        connection.peer_uid != record->image.socket_peer_uid) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "Recorded SSH endpoint socket peer changed before key "
                  "retirement; retained for retry: %s",
                  socket_path);
        goto out;
    }
    process_outcome = verify_expected_process_generation(record);
    if (process_outcome != SSH_PROCESS_OWNED) {
        set_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint process generation changed before key "
            "retirement (%s); retained for retry: %s",
            ssh_process_outcome_name(process_outcome), socket_path);
        goto out;
    }
    process_outcome =
        prove_recorded_agent_identity(record, socket_path, dir_fd);
    if (process_outcome != SSH_PROCESS_OWNED) {
        set_error(
            ERR_SSH_AGENT_FAILED,
            "Recorded SSH endpoint process identity changed before key "
            "retirement (%s); retained for retry: %s",
            ssh_process_outcome_name(process_outcome), socket_path);
        goto out;
    }
    if (ssh_agent_remove_all_identities(connection.fd, deadline) != 0) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH agent key retirement was not acknowledged; "
                  "retained for retry: %s", socket_path);
        goto out;
    }
    if (ssh_agent_request_identities(
            connection.fd, deadline, &identity_count) != 0 ||
        identity_count != 0 ||
        verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, socket_name, socket_path, socket_pin) != 0 ||
        verify_ssh_runtime_pin_at(
            dir_fd, pid_name, NULL, pid_pin) != 0 ||
        !pinned_pid_sidecar_matches_record(pid_pin, record)) {
        set_error(ERR_SSH_AGENT_FAILED,
                  "SSH endpoint retirement could not be confirmed; "
                  "retry evidence retained: %s", socket_path);
        goto out;
    }
    rc = 0;
out:
    if (connection.fd >= 0) {
        int operation_errno = errno;

        if (close(connection.fd) != 0 && rc == 0) {
            log_warning(
                "Failed to close the SSH agent connection after confirmed "
                "key retirement; retirement proof remains valid");
        }
        if (rc != 0) errno = operation_errno;
    }
    return rc;
}

static void warn_recorded_endpoint_retirement(const char *socket_path,
                                               bool detached) {
    if (detached) {
        log_warning(
            "Cleared identities and detached recorded SSH endpoint %s "
            "without process signaling; the process and preexisting "
            "connections may remain active",
            socket_path ? socket_path : "(unknown)");
    } else {
        log_warning(
            "Cleared identities for recorded SSH endpoint %s without process "
            "signaling, but managed endpoint retirement is incomplete; the "
            "process and preexisting connections may remain active",
            socket_path ? socket_path : "(unknown)");
    }
}

static int retire_reaped_socket_if_dead(
    int dir_fd, const char *socket_dir, const char *socket_name,
    const char *socket_path, const char *description) {
    ssh_runtime_pin_t socket_pin;
    bool socket_present;
    int pin_rc;
    int rc = -1;

    ssh_runtime_pin_init(&socket_pin);
    pin_rc = pin_ssh_runtime_entry_at(
        dir_fd, socket_name, socket_path, &socket_pin);
    if (pin_rc < 0) goto done;
    socket_present = pin_rc == 0;
    if (prove_malformed_pid_socket_dead_at(
            dir_fd, socket_dir, socket_name, socket_path, &socket_pin,
            socket_present, false, "a valid SSH process record") != 0) {
        goto done;
    }
    if (unlink_ssh_reset_path_at(
            dir_fd, socket_name, socket_path, description, &socket_pin,
            socket_present) != 0) {
        goto done;
    }
    rc = 0;
done:
    if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) rc = -1;
    return rc;
}

static int release_ssh_runtime_pin(int dir_fd, ssh_runtime_pin_t *pin) {
    if (!pin) return 0;
    if (pin->observational) {
        ssh_runtime_pin_init(pin);
        return 0;
    }
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
    ssh_key_snapshot_t key_snapshot;
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
    memset(&key_snapshot, 0, sizeof(key_snapshot));

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

    /* Discovery never creates or repairs the writer lock and never waits on a
     * writer that may be parked at an interactive prompt for minutes. A
     * missing lock means no manager-owned runtime generation can be proven;
     * return an ordinary absence without inspecting unlocked entries. On
     * contention return an error so
     * accounts_detect_current serves the persisted saved-account fallback
     * instead of hanging every read-only command (AR-05 H2). Observation is
     * namespace-preserving on every supported platform. */
    lock_fd = try_lock_agent_dir(dir_fd);
    if (lock_fd < 0) {
        if (errno == ENOENT) {
            close(dir_fd);
            return 0;
        }
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
        int pin_rc = observe_ssh_runtime_entry_at(
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
        int pin_rc = observe_ssh_runtime_entry_at(
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
            if (ssh_key_snapshot_capture(key_path, &key_snapshot) == 0) {
                reachable =
                    ssh_socket_has_key_generation(
                        dir_fd, component, key_path, &key_snapshot) ==
                    SSH_KEY_GENERATION_MATCH;
            }
            if (!reachable) {
                /* Empty/wrong/extra identities are ordinary stale runtime,
                 * not an API failure. The caller will perform a real resume. */
                clear_error();
            }
        }
    } else {
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            g_socket_probe(target, &reachable) != 0 ||
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
    ssh_key_snapshot_clear(&key_snapshot);
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

#define SSH_PID_RECORD_MAX_BYTES (MAX_PATH_LEN + 320U)

static int format_ssh_agent_record(const ssh_agent_record_t *record,
                                   char *buffer, size_t buffer_size) {
    size_t path_size;
    int header_size;

    if (!record || !buffer || buffer_size == 0 || record->pid <= 1 ||
        !ssh_process_generation_valid(&record->generation) ||
        !record->image.valid ||
        record->image.executable_path[0] != '/' ||
        record->image.socket_peer_pid <= 1 ||
        record->image.socket_peer_uid != record->image.effective_uid ||
        !S_ISREG(record->image.executable_identity.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    path_size = strnlen(record->image.executable_path,
                        sizeof(record->image.executable_path));
    if (path_size == 0 ||
        path_size == sizeof(record->image.executable_path)) {
        errno = EINVAL;
        return -1;
    }
    header_size = snprintf(
        buffer, buffer_size,
        "v2 %ld %" PRIu64 " %016" PRIx64 "%016" PRIx64
        " %016" PRIx64 "%016" PRIx64 " %ju %ju %ju %jx %jx %zu\n",
        (long)record->pid, record->generation.kind,
        record->generation.boot_hi, record->generation.boot_lo,
        record->generation.start_hi, record->generation.start_lo,
        (uintmax_t)record->image.effective_uid,
        (uintmax_t)record->image.socket_peer_pid,
        (uintmax_t)record->image.socket_peer_uid,
        (uintmax_t)record->image.executable_identity.st_dev,
        (uintmax_t)record->image.executable_identity.st_ino,
        path_size);
    if (header_size <= 0 || (size_t)header_size >= buffer_size ||
        path_size + 1U > buffer_size - (size_t)header_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buffer + header_size, record->image.executable_path, path_size);
    buffer[(size_t)header_size + path_size] = '\n';
    return header_size + (int)path_size + 1;
}

/* Read a PID sidecar without following or accepting a swapped final
 * component. Safe, stable content that cannot encode exactly one PID is
 * returned as MALFORMED with its descriptor pin retained for callers that can
 * establish independent dead-socket authority. Unsafe metadata, read errors,
 * and generation changes remain non-retirable errors. */
static ssh_pid_sidecar_result_t read_ssh_agent_pid_at(
    int dir_fd, const char *name, const char *display_path,
    ssh_agent_record_t *record_out, ssh_runtime_pin_t *pin) {
    struct stat opened;
    struct stat held;
    struct stat entry;
    char buf[SSH_PID_RECORD_MAX_BYTES];
    size_t used = 0;
    bool oversized = false;
    int fd;

    if (pin) ssh_runtime_pin_init(pin);

    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return SSH_PID_SIDECAR_ABSENT;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH agent PID sidecar: %s",
                         display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    if (!S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        entry.st_nlink != 1 || (entry.st_mode & 022) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe SSH agent PID sidecar: %s", display_path);
        return SSH_PID_SIDECAR_ERROR;
    }

    fd = openat(dir_fd, name,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot open SSH agent PID sidecar safely: %s",
                         display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    if (fstat(fd, &opened) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot identify opened SSH agent PID sidecar: %s",
                         display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    if (!S_ISREG(opened.st_mode) ||
        !same_runtime_identity(&opened, &entry) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || (opened.st_mode & 022) != 0) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "SSH agent PID sidecar changed while opening: %s",
                  display_path);
        return SSH_PID_SIDECAR_ERROR;
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
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Cannot read SSH agent PID sidecar: %s",
                         display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    if (used == sizeof(buf) - 1) {
        char extra;
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot finish reading SSH agent PID sidecar: %s",
                             display_path);
            return SSH_PID_SIDECAR_ERROR;
        }
        oversized = n > 0;
    }
    if (fstat(fd, &held) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot revalidate SSH agent PID sidecar: %s",
                         display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;
        close(fd);
        if (saved_errno == ENOENT) {
            set_error(ERR_FILE_IO,
                      "SSH agent PID sidecar changed while being read: %s",
                      display_path);
        } else {
            errno = saved_errno;
            set_system_error(
                ERR_FILE_IO,
                "Cannot revalidate named SSH agent PID sidecar: %s",
                display_path);
        }
        return SSH_PID_SIDECAR_ERROR;
    }
    if (!same_runtime_revision(&opened, &held) ||
        !same_runtime_revision(&opened, &entry)) {
        close(fd);
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "SSH agent PID sidecar changed while being read: %s",
            display_path);
        return SSH_PID_SIDECAR_ERROR;
    }
    buf[used] = '\0';

    if (!oversized && memchr(buf, '\0', used) == NULL) {
        size_t legacy_len = used;
        uint64_t legacy;
        if (legacy_len > 0 && buf[legacy_len - 1U] == '\n') legacy_len--;
        if (parse_bounded_decimal_u64(buf, legacy_len, &legacy) == 0 &&
            legacy > 1 && legacy <= (uint64_t)INT_MAX &&
            (legacy_len == used || legacy_len + 1U == used)) {
            if (record_out) {
                memset(record_out, 0, sizeof(*record_out));
                record_out->pid = (pid_t)legacy;
            }
            if (pin) {
                pin->identity = held;
                pin->fd = fd;
            } else {
                close(fd);
            }
            return SSH_PID_SIDECAR_LEGACY;
        }
    }
    if (!oversized && used > 3U && memcmp(buf, "v2 ", 3U) == 0 &&
        memchr(buf, '\0', used) == NULL) {
        ssh_agent_record_t parsed_record;
        const char *fields[10];
        size_t field_sizes[10];
        uint64_t parsed_pid;
        uint64_t parsed_kind;
        uint64_t parsed_euid;
        uint64_t parsed_peer_pid;
        uint64_t parsed_peer_uid;
        uint64_t parsed_device;
        uint64_t parsed_inode;
        uint64_t parsed_path_u64;
        size_t parsed_path_size;
        size_t path_offset = 3U;
        int canonical_size = -1;
        char canonical[SSH_PID_RECORD_MAX_BYTES];
        bool fields_valid = true;

        memset(&parsed_record, 0, sizeof(parsed_record));
        for (size_t i = 0; i < 10U; i++) {
            char delimiter = i == 9U ? '\n' : ' ';
            if (next_bounded_record_field(
                    buf, used, &path_offset, delimiter,
                    &fields[i], &field_sizes[i]) != 0) {
                fields_valid = false;
                break;
            }
        }
        if (fields_valid &&
            parse_bounded_decimal_u64(
                fields[0], field_sizes[0], &parsed_pid) == 0 &&
            parse_bounded_decimal_u64(
                fields[1], field_sizes[1], &parsed_kind) == 0 &&
            field_sizes[2] == 32U &&
            parse_fixed_hex_u64(
                fields[2], 16U,
                &parsed_record.generation.boot_hi) == 0 &&
            parse_fixed_hex_u64(
                fields[2] + 16U, 16U,
                &parsed_record.generation.boot_lo) == 0 &&
            field_sizes[3] == 32U &&
            parse_fixed_hex_u64(
                fields[3], 16U,
                &parsed_record.generation.start_hi) == 0 &&
            parse_fixed_hex_u64(
                fields[3] + 16U, 16U,
                &parsed_record.generation.start_lo) == 0 &&
            parse_bounded_decimal_u64(
                fields[4], field_sizes[4], &parsed_euid) == 0 &&
            parse_bounded_decimal_u64(
                fields[5], field_sizes[5], &parsed_peer_pid) == 0 &&
            parse_bounded_decimal_u64(
                fields[6], field_sizes[6], &parsed_peer_uid) == 0 &&
            parse_bounded_hex_u64(
                fields[7], field_sizes[7], &parsed_device) == 0 &&
            parse_bounded_hex_u64(
                fields[8], field_sizes[8], &parsed_inode) == 0 &&
            parse_bounded_decimal_u64(
                fields[9], field_sizes[9], &parsed_path_u64) == 0 &&
            parsed_path_u64 <= SIZE_MAX &&
            parsed_pid > 1 && parsed_pid <= (uint64_t)INT_MAX &&
            parsed_euid == (uint64_t)(uid_t)parsed_euid &&
            parsed_peer_pid > 1 &&
            parsed_peer_pid <= (uint64_t)INT_MAX &&
            parsed_peer_uid == (uint64_t)(uid_t)parsed_peer_uid &&
            parsed_peer_uid == parsed_euid &&
            parsed_device == (uint64_t)(dev_t)parsed_device &&
            parsed_inode == (uint64_t)(ino_t)parsed_inode &&
            (parsed_path_size = (size_t)parsed_path_u64) > 0 &&
            parsed_path_size < sizeof(parsed_record.image.executable_path) &&
            path_offset + parsed_path_size + 1U == used &&
            buf[path_offset] == '/' &&
            buf[used - 1U] == '\n') {
            parsed_record.pid = (pid_t)parsed_pid;
            parsed_record.generation.kind = parsed_kind;
            parsed_record.image.valid = true;
            parsed_record.image.effective_uid = (uid_t)parsed_euid;
            parsed_record.image.socket_peer_pid = (pid_t)parsed_peer_pid;
            parsed_record.image.socket_peer_uid = (uid_t)parsed_peer_uid;
            parsed_record.image.executable_identity.st_dev =
                (dev_t)parsed_device;
            parsed_record.image.executable_identity.st_ino =
                (ino_t)parsed_inode;
            parsed_record.image.executable_identity.st_mode = S_IFREG;
            memcpy(parsed_record.image.executable_path,
                   buf + path_offset, parsed_path_size);
            parsed_record.image.executable_path[parsed_path_size] = '\0';
            canonical_size = format_ssh_agent_record(
                &parsed_record, canonical, sizeof(canonical));
            if (ssh_process_generation_valid(&parsed_record.generation) &&
                canonical_size > 0 && (size_t)canonical_size == used &&
                memcmp(canonical, buf, used) == 0) {
                if (record_out) *record_out = parsed_record;
                if (pin) {
                    pin->identity = held;
                    pin->fd = fd;
                } else {
                    close(fd);
                }
                return SSH_PID_SIDECAR_VALID;
            }
        }
    }
    {
        const char *pid_start = buf + 3;
        const char *pid_end;
        const char *kind_start;
        const char *kind_end;
        const char *boot_start;
        const char *start_start;
        char canonical[160];
        ssh_agent_record_t parsed_record;
        uint64_t parsed_pid;
        uint64_t parsed_kind;
        int canonical_len;

        memset(&parsed_record, 0, sizeof(parsed_record));
        pid_end = !oversized && used >= 3U &&
                          memcmp(buf, "v1 ", 3U) == 0
                      ? strchr(pid_start, ' ')
                      : NULL;
        kind_start = pid_end ? pid_end + 1 : NULL;
        kind_end = kind_start ? strchr(kind_start, ' ') : NULL;
        boot_start = kind_end ? kind_end + 1 : NULL;
        start_start = boot_start && strlen(boot_start) >= 33U &&
                              boot_start[32] == ' '
                          ? boot_start + 33
                          : NULL;
        if (!oversized && memchr(buf, '\0', used) == NULL &&
            pid_end && kind_end && boot_start && start_start &&
            (size_t)(pid_end - pid_start) > 0 &&
            (size_t)(kind_end - kind_start) > 0 &&
            parse_bounded_decimal_u64(
                pid_start, (size_t)(pid_end - pid_start), &parsed_pid) == 0 &&
            parse_bounded_decimal_u64(
                kind_start, (size_t)(kind_end - kind_start),
                &parsed_kind) == 0 &&
            parsed_pid > 1 && parsed_pid <= (uint64_t)INT_MAX &&
            (size_t)((buf + used) - start_start) == 33U &&
            start_start[32] == '\n' && start_start[33] == '\0' &&
            parse_fixed_hex_u64(boot_start, 16U,
                                &parsed_record.generation.boot_hi) == 0 &&
            parse_fixed_hex_u64(boot_start + 16U, 16U,
                                &parsed_record.generation.boot_lo) == 0 &&
            parse_fixed_hex_u64(start_start, 16U,
                                &parsed_record.generation.start_hi) == 0 &&
            parse_fixed_hex_u64(start_start + 16U, 16U,
                                &parsed_record.generation.start_lo) == 0) {
            parsed_record.pid = (pid_t)parsed_pid;
            parsed_record.generation.kind = parsed_kind;
            canonical_len = snprintf(
                canonical, sizeof(canonical),
                "v1 %ld %" PRIu64 " %016" PRIx64 "%016" PRIx64
                " %016" PRIx64 "%016" PRIx64 "\n",
                (long)parsed_record.pid, parsed_record.generation.kind,
                parsed_record.generation.boot_hi,
                parsed_record.generation.boot_lo,
                parsed_record.generation.start_hi,
                parsed_record.generation.start_lo);
            if (ssh_process_generation_valid(&parsed_record.generation) &&
                canonical_len > 0 && (size_t)canonical_len == used &&
                memcmp(canonical, buf, used) == 0) {
                if (record_out) *record_out = parsed_record;
                if (pin) {
                    pin->identity = held;
                    pin->fd = fd;
                } else {
                    close(fd);
                }
                return SSH_PID_SIDECAR_LEGACY;
            }
        }
    }
    {
        if (pin) {
            pin->identity = held;
            pin->fd = fd;
        } else {
            close(fd);
        }
        return SSH_PID_SIDECAR_MALFORMED;
    }
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

static bool pinned_pid_sidecar_matches_record(
    const ssh_runtime_pin_t *pin, const ssh_agent_record_t *record) {
    char expected[SSH_PID_RECORD_MAX_BYTES];
    char observed[SSH_PID_RECORD_MAX_BYTES + 1U];
    int expected_len;
    ssize_t read_len;

    if (!pin || pin->fd < 0 || !record) return false;
    expected_len = format_ssh_agent_record(
        record, expected, sizeof(expected));
    if (expected_len <= 0 || (size_t)expected_len >= sizeof(expected)) {
        return false;
    }
    do {
        read_len = pread(pin->fd, observed, sizeof(observed), 0);
    } while (read_len < 0 && errno == EINTR);
    return read_len == expected_len &&
           memcmp(observed, expected, (size_t)expected_len) == 0;
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

static int write_ssh_agent_pid_at(
    int dir_fd, const char *name, const ssh_agent_record_t *record) {
    char tmp[MAX_NAME_LEN + 64];
    char content[SSH_PID_RECORD_MAX_BYTES];
    struct stat opened;
    struct stat fd_now;
    struct stat entry;
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;
    int len;
    int fd = -1;
    int rc = -1;
    bool have_opened_identity = false;
    bool renamed = false;

    if (!record || record->pid <= 1 ||
        !ssh_process_generation_valid(&record->generation) ||
        !record->image.valid) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH agent process record");
        return -1;
    }
    len = format_ssh_agent_record(record, content, sizeof(content));
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

static bool recover_exact_ssh_agent_record_at(
    int dir_fd, const char *name, const char *display_path,
    const ssh_agent_record_t *expected) {
    ssh_agent_record_t observed;
    ssh_runtime_pin_t pin;
    bool exact = false;

    if (dir_fd < 0 || !name || !*name || !display_path || !expected) {
        return false;
    }
    memset(&observed, 0, sizeof(observed));
    ssh_runtime_pin_init(&pin);
    if (read_ssh_agent_pid_at(
            dir_fd, name, display_path, &observed, &pin) !=
            SSH_PID_SIDECAR_VALID) {
        (void)release_ssh_runtime_pin(dir_fd, &pin);
        return false;
    }
    exact = observed.pid == expected->pid &&
            ssh_process_generation_equal(
                &observed.generation, &expected->generation) &&
            pinned_pid_sidecar_matches_record(&pin, expected) &&
            verify_ssh_runtime_pin_at(
                dir_fd, name, display_path, &pin) == 0 &&
            sync_ssh_runtime_dir(
                dir_fd, "exact SSH PID sidecar recovery") == 0 &&
            verify_ssh_runtime_pin_at(
                dir_fd, name, display_path, &pin) == 0 &&
            pinned_pid_sidecar_matches_record(&pin, expected);
    if (release_ssh_runtime_pin(dir_fd, &pin) != 0) exact = false;
    return exact;
}

int ssh_manager_test_write_pid_sidecar(int dir_fd, const char *name,
                                       const ssh_agent_record_t *record) {
    ssh_agent_record_t completed;
    run_launch_witness_t witness;
    char path[MAX_PATH_LEN];
    char socket_name[MAX_NAME_LEN + 32];
    size_t name_size;

    if (!record) return write_ssh_agent_pid_at(dir_fd, name, record);
    completed = *record;
    if (!completed.image.valid) {
        memset(&witness, 0, sizeof(witness));
        if (find_command_path("ssh-agent", path, sizeof(path)) != 0 ||
            !run_launch_witness_capture(path, &witness) ||
            !process_image_from_launch_witness(
                &witness, &completed.image)) {
            return -1;
        }
    }
    name_size = name ? strlen(name) : 0;
    if (completed.image.socket_peer_pid <= 1 &&
        name_size > 4U && strcmp(name + name_size - 4U, ".pid") == 0 &&
        name_size + 2U <= sizeof(socket_name)) {
        memcpy(socket_name, name, name_size - 4U);
        memcpy(socket_name + name_size - 4U, ".sock", 6U);
        if (inspect_socket_peer(
                socket_name, dir_fd,
                &completed.image.socket_peer_pid,
                &completed.image.socket_peer_uid) != 0) {
            return -1;
        }
    }
    return write_ssh_agent_pid_at(dir_fd, name, &completed);
}

int ssh_manager_test_capture_process_generation(
    pid_t pid, ssh_process_generation_t *generation) {
    return capture_process_generation(pid, generation);
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
        fstatat(dir_fd, quarantine, &captured, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;
        (void)unlink_ssh_runtime_identity_at(
            dir_fd, quarantine, expected, true,
            "failed portable reset quarantine rollback", NULL, NULL);
        errno = saved_errno;
        return -1;
    }
    {
        bool forced_mismatch =
            g_metadata_test_hook &&
            g_metadata_test_hook(SSH_METADATA_TEST_RESET_QUARANTINE);
        errno = 0;
        if (forced_mismatch || !same_runtime_identity(expected, &source) ||
            !same_runtime_identity(expected, &captured) ||
            !same_runtime_identity(&source, &captured)) {
            (void)unlink_ssh_runtime_identity_at(
                dir_fd, quarantine, expected, true,
                "failed portable reset quarantine rollback", NULL, NULL);
            errno = ESTALE;
            return -1;
        }
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
    int saved_system_errno = get_last_error()->system_errno;
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    if (detail[0]) {
        if (saved_system_errno != 0) {
            char suffix[sizeof(detail)];
            int suffix_length = snprintf(suffix, sizeof(suffix), " (%s)",
                                         strerror(saved_system_errno));
            size_t detail_length = strlen(detail);

            /* set_system_error() appends this diagnostic itself. Remove the
             * one already carried by the nested failure so retry wrapping
             * preserves errno without duplicating its human-readable text. */
            if (suffix_length > 0 &&
                (size_t)suffix_length < sizeof(suffix) &&
                detail_length >= (size_t)suffix_length &&
                memcmp(detail + detail_length - (size_t)suffix_length,
                       suffix, (size_t)suffix_length) == 0) {
                detail[detail_length - (size_t)suffix_length] = '\0';
            }
            errno = saved_system_errno;
            set_system_error(
                ERR_FILE_IO,
                "SSH reset incomplete; retained state for retry: %s", detail);
        } else {
            set_error(ERR_FILE_IO,
                      "SSH reset incomplete; retained state for retry: %s",
                      detail);
        }
    } else {
        set_error(ERR_FILE_IO,
                  "SSH reset incomplete; retained remaining state for retry");
    }
    return -1;
}

/* Tear down isolated SSH agents: one account, or all when account is NULL.
 * Terminate a recorded process only through a safe descriptor-backed signal;
 * otherwise an exact eligible recorded endpoint may be cleared and detached
 * without a process-death claim. A reachable sidecar-less endpoint has no
 * process identity that can authorize teardown, so retain its recovery
 * evidence and fail for retry. Every lock, identity/reap, protocol, and
 * relevant unlink failure is fatal; missing owned state is idempotent. */
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
    bool recorded_endpoint_retired = false;
    bool recorded_endpoint_detached = false;
    bool socket_present = false;
    ssh_runtime_pin_t pid_pin;
    ssh_runtime_pin_t socket_pin;
    ssh_agent_record_t record;

    memset(&record, 0, sizeof(record));
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

    ssh_pid_sidecar_result_t pid_rc = read_ssh_agent_pid_at(
        dir_fd, pid_name, pid_path, &record, &pid_pin);
    if (pid_rc == SSH_PID_SIDECAR_ERROR) {
        failed = true;
        can_remove_runtime = false;
    } else if (pid_rc == SSH_PID_SIDECAR_VALID) {
        ssh_process_outcome_t reap_outcome;
        bool retirement_attempted = false;

        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        reap_outcome = can_remove_runtime
                           ? g_ssh_reap(&record, sock_path, dir_fd)
                           : SSH_PROCESS_INDETERMINATE;
        if (can_remove_runtime &&
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            reap_outcome == SSH_PROCESS_INDETERMINATE &&
            socket_present && can_remove_runtime) {
            retirement_attempted = true;
            if (retire_recorded_agent_endpoint(
                    dir_fd, socket_dir, sock_name, sock_path, pid_name,
                    &socket_pin, &pid_pin, &record) == 0) {
                recorded_endpoint_retired = true;
            }
        }
        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            !recorded_endpoint_retired) {
            if (can_remove_runtime && !retirement_attempted) {
                set_error(ERR_SSH_AGENT_FAILED,
                          "SSH agent PID %ld reap outcome %s; retained for retry",
                          (long)record.pid,
                          ssh_process_outcome_name(reap_outcome));
            }
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
    } else if (pid_rc != SSH_PID_SIDECAR_ABSENT &&
               pid_rc != SSH_PID_SIDECAR_MALFORMED &&
               pid_rc != SSH_PID_SIDECAR_LEGACY) {
        set_error(ERR_FILE_IO,
                  "Unexpected SSH agent PID sidecar classification");
        failed = true;
        can_remove_runtime = false;
    }

    if (can_remove_runtime && pid_rc == SSH_PID_SIDECAR_ABSENT &&
        socket_present) {
        bool reachable = false;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            verify_ssh_runtime_pin_at(
                dir_fd, sock_name, sock_path, &socket_pin) != 0 ||
            g_socket_probe(sock_path, &reachable) != 0 ||
            verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            verify_ssh_runtime_pin_at(
                dir_fd, sock_name, sock_path, &socket_pin) != 0) {
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

    /* An absent sidecar with no authenticated endpoint is idempotent only
     * when the socket is absent or provably stale. Apply the same proof after
     * a valid PID was classified
     * GONE/UNRELATED: a stale record can coexist with a different live agent
     * on the managed socket, so a cleanup-authorizing process outcome alone
     * is insufficient authority to unlink the runtime entry point. Malformed
     * records use the pinned proof helper below before their own retirement. */
    if (can_remove_runtime && !recorded_endpoint_retired &&
        pid_rc == SSH_PID_SIDECAR_VALID) {
        bool reachable = false;
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
            g_socket_probe(sock_path, &reachable) != 0 ||
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
    if (can_remove_runtime && pid_rc == SSH_PID_SIDECAR_VALID &&
        unlink_ssh_reset_path_at(
            dir_fd, pid_name, pid_path,
            recorded_endpoint_retired
                ? "protocol-retired SSH agent PID sidecar"
                : "SSH agent PID sidecar",
            &pid_pin, true) != 0) {
        failed = true;
        can_remove_runtime = false;
    }
    if (can_remove_runtime &&
        (pid_rc == SSH_PID_SIDECAR_MALFORMED ||
         pid_rc == SSH_PID_SIDECAR_LEGACY)) {
            if (prove_malformed_pid_socket_dead_at(
                    dir_fd, socket_dir, sock_name, sock_path, &socket_pin,
                    socket_present, false,
                    pid_rc == SSH_PID_SIDECAR_LEGACY
                        ? "a legacy PID-only record"
                        : "a malformed PID sidecar") != 0) {
            failed = true;
            can_remove_runtime = false;
        }
        if (can_remove_runtime &&
            unlink_ssh_reset_path_at(
                dir_fd, pid_name, pid_path,
                "malformed SSH agent PID sidecar", &pid_pin, true) != 0) {
            failed = true;
            can_remove_runtime = false;
        }
    }
    if (can_remove_runtime && pid_rc == SSH_PID_SIDECAR_ABSENT) {
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
        bool socket_removed = false;

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
        } else {
            socket_removed = true;
            recorded_endpoint_detached =
                recorded_endpoint_retired && socket_present;
        }
        if (socket_removed && current_matches &&
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
    if (recorded_endpoint_retired) {
        warn_recorded_endpoint_retirement(
            sock_path, recorded_endpoint_detached);
    }
    if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
    if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) failed = true;
    unlock_agent_dir(lock_fd);
    close(dir_fd);
    return failed ? ssh_reset_incomplete() : 0;
}

/* Retire orphaned gitswitch ssh-agent state from previous runs. Recorded
 * processes are signaled only through a descriptor-backed proof; eligible
 * native endpoints may instead have identities cleared and managed names
 * detached. Reachable sidecar-less agents are retained because their endpoint
 * alone cannot prove bounded process termination. Only operates inside our
 * own 0700 directory.
 * If keep_account is non-NULL, that account's live agent + sidecar are left
 * intact while every other account is considered for retirement. */
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

    /* Pass 1: process sidecars first. Valid records require a conclusive reap;
     * safe malformed records require a conclusive dead-socket proof. Unsafe,
     * unstable, live, or indeterminate tuples remain so pass 2 retains their
     * corresponding socket as retry evidence. */
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
        char sock_name[MAX_NAME_LEN + 16];
        ssh_runtime_pin_t pid_pin;
        int sn = snprintf(sock_name, sizeof(sock_name), "%.*ssock",
                          (int)(nlen - 3), name);
        int sw = snprintf(sock_full, sizeof(sock_full), "%s/%.*ssock",
                          socket_dir, (int)(nlen - 3), name);
        ssh_runtime_pin_init(&pid_pin);
        if (sn <= 0 || (size_t)sn >= sizeof(sock_name) ||
            sw <= 0 || (size_t)sw >= sizeof(sock_full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup socket path too long: %s", name);
            failed = true;
            continue;
        }

        ssh_agent_record_t record;
        memset(&record, 0, sizeof(record));
        ssh_pid_sidecar_result_t pid_rc = read_ssh_agent_pid_at(
            dir_fd, name, full, &record, &pid_pin);
        if (pid_rc == SSH_PID_SIDECAR_ERROR) {
            failed = true;
            continue;
        }
        if (pid_rc == SSH_PID_SIDECAR_ABSENT) {
            set_error(ERR_FILE_IO,
                      "SSH PID sidecar disappeared during cleanup: %s", full);
            failed = true;
            continue;
        }
        if (pid_rc == SSH_PID_SIDECAR_MALFORMED ||
            pid_rc == SSH_PID_SIDECAR_LEGACY) {
            ssh_runtime_pin_t socket_pin;
            bool entry_failed = false;
            bool socket_present = false;
            int socket_rc;

            ssh_runtime_pin_init(&socket_pin);
            socket_rc = pin_ssh_runtime_entry_at(
                dir_fd, sock_name, sock_full, &socket_pin);
            if (socket_rc == 0) {
                socket_present = true;
            } else if (socket_rc < 0) {
                entry_failed = true;
            }
            if (!entry_failed &&
                prove_malformed_pid_socket_dead_at(
                    dir_fd, socket_dir, sock_name, sock_full, &socket_pin,
                    socket_present, false,
                    pid_rc == SSH_PID_SIDECAR_LEGACY
                        ? "a legacy PID-only record"
                        : "a malformed PID sidecar") != 0) {
                entry_failed = true;
            }
            if (!entry_failed &&
                unlink_ssh_reset_path_at(
                    dir_fd, name, full,
                    "malformed SSH agent PID sidecar", &pid_pin, true) != 0) {
                entry_failed = true;
            }
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                entry_failed = true;
            }
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) {
                entry_failed = true;
            }
            if (entry_failed) failed = true;
            continue;
        }
        if (pid_rc != SSH_PID_SIDECAR_VALID) {
            set_error(ERR_FILE_IO,
                      "Unexpected SSH PID sidecar classification: %s", full);
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        ssh_process_outcome_t reap_outcome = g_ssh_reap(
            &record, sock_full, dir_fd);
        bool recorded_endpoint_retired = false;
        bool retirement_attempted = false;
        ssh_runtime_pin_t socket_pin;
        bool socket_pin_held = false;
        ssh_runtime_pin_init(&socket_pin);
        if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0) {
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            reap_outcome == SSH_PROCESS_INDETERMINATE &&
            pin_ssh_runtime_entry_at(
                dir_fd, sock_name, sock_full, &socket_pin) == 0) {
            socket_pin_held = true;
            retirement_attempted = true;
            if (retire_recorded_agent_endpoint(
                    dir_fd, socket_dir, sock_name, sock_full, name,
                    &socket_pin, &pid_pin, &record) == 0) {
                recorded_endpoint_retired = true;
            }
        }
        if (!ssh_reap_allows_cleanup(reap_outcome) &&
            !recorded_endpoint_retired) {
            if (!retirement_attempted) {
                set_error(
                    ERR_SSH_AGENT_FAILED,
                    "SSH agent PID %ld reap outcome %s; retained for retry",
                    (long)record.pid,
                    ssh_process_outcome_name(reap_outcome));
            }
            failed = true;
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                failed = true;
            }
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) failed = true;
            continue;
        }
        if (recorded_endpoint_retired &&
            unlink_ssh_reset_path_at(
                dir_fd, name, full,
                "protocol-retired SSH agent PID sidecar",
                &pid_pin, true) != 0) {
            failed = true;
            warn_recorded_endpoint_retirement(sock_full, false);
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                failed = true;
            }
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) {
                failed = true;
            }
            continue;
        }
        if ((!recorded_endpoint_retired &&
             retire_reaped_socket_if_dead(
                 dir_fd, socket_dir, sock_name, sock_full,
                 "orphaned SSH agent socket cleanup") != 0) ||
            (recorded_endpoint_retired &&
             unlink_ssh_reset_path_at(
                 dir_fd, sock_name, sock_full,
                 "protocol-retired SSH agent socket",
                 &socket_pin, true) != 0)) {
            failed = true;
            if (recorded_endpoint_retired) {
                warn_recorded_endpoint_retirement(sock_full, false);
            }
            if (release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
                failed = true;
            }
            if (release_ssh_runtime_pin(dir_fd, &pid_pin) != 0) {
                failed = true;
            }
            continue;
        }
        if (recorded_endpoint_retired) {
            warn_recorded_endpoint_retirement(sock_full, true);
        } else {
            log_debug("Reaped orphaned ssh-agent PID %ld",
                      (long)record.pid);
        }
        if (!recorded_endpoint_retired &&
            unlink_ssh_reset_path_at(dir_fd, name, full,
                                     "SSH agent PID sidecar", &pid_pin,
                                     true) != 0) {
            failed = true;
        }
        if (socket_pin_held &&
            release_ssh_runtime_pin(dir_fd, &socket_pin) != 0) {
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

            /* Without a trusted process record, a reachable endpoint cannot
             * authorize signaling or namespace removal. Preserve the exact
             * pinned socket (and current.sock below) as retry evidence. */
            bool reachable = false;
            if (verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
                verify_ssh_runtime_pin_at(
                    dir_fd, name, full, &artifact_pin) != 0 ||
                g_socket_probe(full, &reachable) != 0 ||
                verify_socket_dir_namespace(dir_fd, socket_dir) != 0 ||
                verify_ssh_runtime_pin_at(
                    dir_fd, name, full, &artifact_pin) != 0) {
                failed = true;
                if (release_ssh_runtime_pin(
                        dir_fd, &artifact_pin) != 0) {
                    failed = true;
                }
                continue;
            }
            if (reachable) {
                set_error(ERR_SSH_AGENT_FAILED,
                          "Reachable SSH agent socket has no safely matched "
                          "PID; retained for retry: %s", full);
                failed = true;
                if (release_ssh_runtime_pin(
                        dir_fd, &artifact_pin) != 0) {
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
