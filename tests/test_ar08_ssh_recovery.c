/* AR-08 T10 causal coverage for SSH process provenance and recovery:
 *
 * M39: OWNED, UNRELATED, GONE, and INDETERMINATE remain distinct through
 *      identity inspection, pidfd/fallback signaling, and sidecar cleanup.
 * M40: an ssh-agent launched from one pinned runtime root cannot be reaped by
 *      an identically named sidecar in a different runtime root.
 * M41: repeated EINTR during both observation windows cannot consume time
 *      that did not actually elapse.
 * L25: a failed pre-sidecar reap publishes a durable retry tuple instead of
 *      unlinking the surviving runtime's final discovery handle.
 */

/* Keep strict feature selection glibc-only: Darwin and the BSDs hide
 * default-namespace test helpers such as mkdtemp() when it is enabled. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST_PID ((pid_t)1073741824)

typedef struct {
    char xdg[64];
    char runtime[128];
    char socket[192];
    char sidecar[192];
    int dir_fd;
} ssh_fixture_t;

static int make_fixture(ssh_fixture_t *fixture, const char *stem) {
    int written;

    if (!fixture || !stem) return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->dir_fd = -1;
    written = snprintf(fixture->xdg, sizeof(fixture->xdg),
                       "/tmp/%sXXXXXX", stem);
    if (written < 0 || (size_t)written >= sizeof(fixture->xdg) ||
        !ts_mkdtemp(fixture->xdg) || chmod(fixture->xdg, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->xdg, 1) != 0) {
        return -1;
    }
    written = snprintf(fixture->runtime, sizeof(fixture->runtime),
                       "%s/gitswitch-ssh", fixture->xdg);
    if (written < 0 || (size_t)written >= sizeof(fixture->runtime) ||
        mkdir(fixture->runtime, 0700) != 0) {
        return -1;
    }
    fixture->dir_fd = open(fixture->runtime,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->dir_fd < 0) return -1;
    written = snprintf(fixture->socket, sizeof(fixture->socket),
                       "%s/ssh-agent.work.sock", fixture->runtime);
    if (written < 0 || (size_t)written >= sizeof(fixture->socket)) return -1;
    written = snprintf(fixture->sidecar, sizeof(fixture->sidecar),
                       "%s/ssh-agent.work.pid", fixture->runtime);
    if (written < 0 || (size_t)written >= sizeof(fixture->sidecar)) return -1;
    return 0;
}

static int publish_sidecar(const ssh_fixture_t *fixture, pid_t pid) {
    return ssh_manager_test_write_pid_sidecar(
        fixture->dir_fd, "ssh-agent.work.pid", pid);
}

static ssh_process_outcome_t reap_gone(pid_t pid, const char *socket_arg,
                                       int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_GONE;
}

static ssh_process_outcome_t reap_indeterminate(pid_t pid,
                                                const char *socket_arg,
                                                int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_INDETERMINATE;
}

static char g_race_runtime[192];
static char g_race_moved_runtime[192];
static char g_race_socket[256];
static char g_race_sidecar[256];
static bool g_race_hook_succeeded;
static char g_retire_quarantine[128];
static const char *g_retire_replacement;
static int g_retire_hook_calls;
static int g_retire_mutations;
static int g_retire_replace_on_call;
static int g_reset_dirsync_calls;

static int bind_stale_socket(const char *path) {
    struct sockaddr_un address;
    int fd;

    if (!path || strlen(path) >= sizeof(address.sun_path)) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(fd, (struct sockaddr *)(void *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int replace_unrecorded_socket_before_cleanup(int dir_fd,
                                                    const char *name) {
    g_race_hook_succeeded =
        unlinkat(dir_fd, name, 0) == 0 &&
        bind_stale_socket(g_race_socket) == 0;
    return g_race_hook_succeeded ? 0 : -1;
}

static int replace_reset_retirement_entry(int dir_fd, const char *name) {
    int fd;
    size_t content_len;
    ssize_t written;

    g_retire_hook_calls++;
    if (g_retire_hook_calls != g_retire_replace_on_call) return 0;
    g_retire_mutations++;
    if (safe_strncpy(g_retire_quarantine, name,
                     sizeof(g_retire_quarantine)) != 0 ||
        unlinkat(dir_fd, name, 0) != 0 || !g_retire_replacement) {
        return -1;
    }
    fd = openat(dir_fd, name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    content_len = strlen(g_retire_replacement);
    written = write(fd, g_retire_replacement, content_len);
    if (written < 0 || (size_t)written != content_len) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int fail_third_reset_dirsync(int dir_fd) {
    g_reset_dirsync_calls++;
    if (g_reset_dirsync_calls == 3) {
        errno = EIO;
        return -1;
    }
    return fsync(dir_fd);
}

static ssh_process_outcome_t swap_runtime_namespace_then_gone(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    char replacement_socket[256];
    char replacement_sidecar[256];
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;

    g_race_hook_succeeded =
        rename(g_race_runtime, g_race_moved_runtime) == 0 &&
        mkdir(g_race_runtime, 0700) == 0 &&
        (size_t)snprintf(replacement_socket, sizeof(replacement_socket),
                         "%s/ssh-agent.work.sock", g_race_runtime) <
            sizeof(replacement_socket) &&
        (size_t)snprintf(replacement_sidecar, sizeof(replacement_sidecar),
                         "%s/ssh-agent.work.pid", g_race_runtime) <
            sizeof(replacement_sidecar) &&
        write_string_to_file(replacement_socket, "foreign socket\n", 0600) ==
            0 &&
        write_string_to_file(replacement_sidecar, "31337\n", 0600) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t replace_sidecar_then_gone(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_race_hook_succeeded =
        unlink(g_race_sidecar) == 0 &&
        write_string_to_file(g_race_sidecar, "424242\n", 0600) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t replace_socket_then_gone(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_race_hook_succeeded =
        unlink(g_race_socket) == 0 && bind_stale_socket(g_race_socket) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t remove_socket_then_gone(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    g_race_hook_succeeded =
        unlinkat(runtime_dir_fd, "ssh-agent.work.sock", 0) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static void cleanup_retained_fixture(const ssh_fixture_t *fixture) {
    ssh_reap_fn previous = ssh_manager_set_reap_fn(reap_gone);
    (void)setenv("XDG_RUNTIME_DIR", fixture->xdg, 1);
    (void)ssh_manager_reset("work");
    ssh_manager_set_reap_fn(previous);
}

static int pidfd_unavailable(pid_t pid) {
    (void)pid;
    errno = ENOSYS;
    return -1;
}

static int pidfd_signal_unused(int pidfd, int signal_number) {
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
}

static int g_signal_calls;
static int g_last_signal;

static int signal_must_not_run(pid_t pid, int signal_number) {
    (void)pid;
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = EACCES;
    return -1;
}

static ssh_process_outcome_t identity_indeterminate(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t identity_owned(pid_t pid,
                                            const char *socket_arg,
                                            int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_OWNED;
}

TEST(indeterminate_identity_retains_retry_sidecar) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_indeterminate,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08id"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

static int signal_permission_denied(pid_t pid, int signal_number) {
    (void)pid;
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = EPERM;
    return -1;
}

TEST(permission_denied_presence_probe_is_indeterminate) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = NULL, /* production inspection begins with kill(pid, 0) */
        .signal = signal_permission_denied,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08perm"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 1);
    CHECK_EQ_INT(g_last_signal, 0);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static int pidfd_open_devnull(pid_t pid) {
    (void)pid;
    return open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static int pidfd_signal_permission_denied(int pidfd, int signal_number) {
    (void)pidfd;
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = EPERM;
    return -1;
}

TEST(failed_pidfd_signal_retains_retry_sidecar) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_devnull,
        .pidfd_signal = pidfd_signal_permission_denied
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08pidfd"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 1);
    CHECK_EQ_INT(g_last_signal, SIGTERM);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static int signal_eintr_then_esrch(pid_t pid, int signal_number) {
    (void)pid;
    g_signal_calls++;
    g_last_signal = signal_number;
    if (g_signal_calls == 1) {
        errno = EINTR;
    } else {
        errno = ESRCH;
    }
    return -1;
}

TEST(interrupted_fallback_signal_retries_and_esrch_cleans) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .signal = signal_eintr_then_esrch,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08eintr"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 2);
    CHECK_EQ_INT(g_last_signal, SIGTERM);
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(real_kernel_esrch_consumes_stale_sidecar) {
    ssh_fixture_t fixture;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08esrch"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(runtime_namespace_replacement_fails_without_mutating_either_tree) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char moved_socket[256];
    char moved_sidecar[256];
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08namespace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_runtime, fixture.runtime,
                              sizeof(g_race_runtime)), 0);
    CHECK_EQ_INT(safe_snprintf(g_race_moved_runtime,
                               sizeof(g_race_moved_runtime), "%s.pinned",
                               fixture.runtime), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(swap_runtime_namespace_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(safe_snprintf(moved_socket, sizeof(moved_socket),
                               "%s/ssh-agent.work.sock",
                               g_race_moved_runtime), 0);
    CHECK_EQ_INT(safe_snprintf(moved_sidecar, sizeof(moved_sidecar),
                               "%s/ssh-agent.work.pid",
                               g_race_moved_runtime), 0);
    CHECK(path_exists(moved_socket));
    CHECK(path_exists(moved_sidecar));
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.socket, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "foreign socket\n");
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "31337\n");
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(sidecar_replacement_before_cleanup_is_restored_and_retained) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08pidrace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_sidecar, fixture.sidecar,
                              sizeof(g_race_sidecar)), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(replace_sidecar_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "424242\n");
    CHECK(strstr(get_last_error()->message, "retained state for retry") !=
          NULL);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(socket_replacement_before_cleanup_survives_with_stable_link) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char current[256];
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08sockrace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_snprintf(current, sizeof(current), "%s/current.sock",
                               fixture.runtime), 0);
    CHECK_EQ_INT(symlink(fixture.socket, current), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(replace_socket_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK(path_exists(current));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message, "retained state for retry") !=
          NULL);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(reaped_agent_socket_self_removal_is_idempotent) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char current[256];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08selfunlink"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_snprintf(current, sizeof(current), "%s/current.sock",
                               fixture.runtime), 0);
    CHECK_EQ_INT(symlink(fixture.socket, current), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(remove_socket_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(!path_exists(current));
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

static void check_final_quarantine_substitution_is_not_deleted(
    bool force_portable) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    ssh_quarantine_hook_fn previous_retire;
    bool previous_portable;
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08retire"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_retire_quarantine[0] = '\0';
    g_retire_replacement = "foreign final-delete replacement\n";
    g_retire_hook_calls = 0;
    g_retire_mutations = 0;
    g_retire_replace_on_call = 1;
    previous_portable =
        ssh_manager_set_force_portable_quarantine(force_portable);
    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    previous_retire = ssh_manager_set_reset_retire_hook_fn(
        replace_reset_retirement_entry);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reset_retire_hook_fn(previous_retire);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    CHECK(g_retire_hook_calls >= (force_portable ? 2 : 1));
    CHECK_EQ_INT(g_retire_mutations, 1);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "foreign final-delete replacement\n");
    close(fixture.dir_fd);
}

TEST(final_quarantine_substitution_is_not_deleted) {
    check_final_quarantine_substitution_is_not_deleted(false);
}

TEST(portable_final_quarantine_substitution_is_not_deleted) {
    check_final_quarantine_substitution_is_not_deleted(true);
}

TEST(portable_restore_retirement_substitution_is_preserved) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    ssh_quarantine_hook_fn previous_retire;
    ssh_dirsync_fn previous_dirsync;
    bool previous_portable;
    char quarantine_path[320];
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08restore"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_retire_quarantine[0] = '\0';
    g_retire_replacement = "foreign restoration-retirement replacement\n";
    g_retire_hook_calls = 0;
    g_retire_mutations = 0;
    g_retire_replace_on_call = 1;
    g_reset_dirsync_calls = 0;
    previous_portable = ssh_manager_set_force_portable_quarantine(true);
    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    previous_retire = ssh_manager_set_reset_retire_hook_fn(
        replace_reset_retirement_entry);
    previous_dirsync = ssh_manager_set_dirsync_fn(fail_third_reset_dirsync);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_dirsync_fn(previous_dirsync);
    ssh_manager_set_reset_retire_hook_fn(previous_retire);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    CHECK(g_reset_dirsync_calls >= 4);
    CHECK_EQ_INT(g_retire_hook_calls, 1);
    CHECK_EQ_INT(g_retire_mutations, 1);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "1073741824\n");
    CHECK_EQ_INT(safe_snprintf(quarantine_path, sizeof(quarantine_path),
                               "%s/%s", fixture.runtime,
                               g_retire_quarantine), 0);
    CHECK(path_exists(quarantine_path));
    CHECK(read_file_to_string(quarantine_path, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content,
                 "foreign restoration-retirement replacement\n");
    close(fixture.dir_fd);
}

TEST(unrelated_live_pid_is_not_signaled) {
    ssh_fixture_t fixture;
    pid_t child;
    int status = 0;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08other"), 0);
    if (fixture.dir_fd < 0) return;
    child = fork();
    CHECK(child >= 0);
    if (child < 0) {
        close(fixture.dir_fd);
        return;
    }
    if (child == 0) {
        for (;;) pause();
    }

    CHECK_EQ_INT(publish_sidecar(&fixture, child), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK_EQ_INT(kill(child, 0), 0);
    CHECK(!path_exists(fixture.sidecar));

    (void)kill(child, SIGKILL);
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    CHECK(WIFSIGNALED(status));
    close(fixture.dir_fd);
}

static volatile sig_atomic_t g_alarm_count;
static int g_term_calls;
static int g_kill_calls;

static void record_alarm(int signal_number) {
    (void)signal_number;
    g_alarm_count++;
}

static int signal_target_survives(pid_t pid, int signal_number) {
    (void)pid;
    if (signal_number == SIGTERM) g_term_calls++;
    if (signal_number == SIGKILL) g_kill_calls++;
    return 0;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

TEST(signal_storm_preserves_term_and_kill_deadlines) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .signal = signal_target_survives,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;
    struct sigaction action;
    struct sigaction old_action;
    struct itimerval timer;
    struct itimerval old_timer;
    struct itimerval disabled;
    int64_t started;
    int64_t elapsed;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08storm"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);

    memset(&action, 0, sizeof(action));
    action.sa_handler = record_alarm;
    CHECK_EQ_INT(sigemptyset(&action.sa_mask), 0);
    CHECK_EQ_INT(sigaction(SIGALRM, &action, &old_action), 0);
    CHECK_EQ_INT(getitimer(ITIMER_REAL, &old_timer), 0);
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
    g_alarm_count = 0;
    g_term_calls = 0;
    g_kill_calls = 0;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &timer, NULL), 0);
    started = monotonic_ms();
    CHECK(started >= 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    elapsed = monotonic_ms() - started;
    memset(&disabled, 0, sizeof(disabled));
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &disabled, NULL), 0);
    ssh_manager_set_reap_test_ops(&previous);
    CHECK_EQ_INT(sigaction(SIGALRM, &old_action, NULL), 0);
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &old_timer, NULL), 0);

    CHECK(g_alarm_count > 100);
    CHECK_EQ_INT(g_term_calls, 1);
    CHECK_EQ_INT(g_kill_calls, 1);
    CHECK(elapsed >= 900);
    CHECK(elapsed <= 3000);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static void stop_process(pid_t pid) {
    struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 10000000L};

    if (pid <= 1) return;
    if (kill(pid, 0) != 0) return;
    (void)kill(pid, SIGTERM);
    for (int attempts = 0; attempts < 50 && kill(pid, 0) == 0; attempts++) {
        (void)nanosleep(&pause_time, NULL);
    }
    if (kill(pid, 0) == 0) (void)kill(pid, SIGKILL);
}

static int wait_process_absent(pid_t pid) {
    struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 10000000L};

    for (int attempts = 0; attempts < 100; attempts++) {
        if (kill(pid, 0) != 0) return errno == ESRCH ? 0 : -1;
        (void)nanosleep(&pause_time, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

TEST(runtime_root_provenance_prevents_cross_root_reap) {
    ssh_fixture_t first;
    ssh_fixture_t second;
    struct stat runtime_identity;
    char marker[80];
    char socket_arg[160];
    char output[2048];
    const char *argv[6];
    run_opts_t opts;
    run_result_t result;
    char *pid_text;
    pid_t pid = -1;
    int marker_created = 0;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_fixture(&first, "gsar08roota"), 0);
    CHECK_EQ_INT(make_fixture(&second, "gsar08rootb"), 0);
    if (first.dir_fd < 0 || second.dir_fd < 0) return;
    CHECK_EQ_INT(fstat(first.dir_fd, &runtime_identity), 0);
    CHECK((size_t)snprintf(marker, sizeof(marker), ".gsp-%jx-%jx",
                           (uintmax_t)runtime_identity.st_dev,
                           (uintmax_t)runtime_identity.st_ino) <
          sizeof(marker));
    CHECK((size_t)snprintf(socket_arg, sizeof(socket_arg),
                           "%s/../ssh-agent.work.sock", marker) <
          sizeof(socket_arg));
    if (mkdirat(first.dir_fd, marker, 0700) == 0) marker_created = 1;
    CHECK(marker_created);
    if (!marker_created) {
        close(first.dir_fd);
        close(second.dir_fd);
        return;
    }

    argv[0] = "ssh-agent";
    argv[1] = "-s";
    argv[2] = "-a";
    argv[3] = socket_arg;
    argv[4] = NULL;
    argv[5] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    opts.cwd_fd = first.dir_fd;
    opts.use_cwd_fd = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK_EQ_INT(unlinkat(first.dir_fd, marker, AT_REMOVEDIR), 0);
    marker_created = 0;
    pid_text = strstr(output, "SSH_AGENT_PID=");
    CHECK(pid_text != NULL);
    if (pid_text) {
        pid = (pid_t)strtol(pid_text + strlen("SSH_AGENT_PID="), NULL, 10);
    }
    CHECK(pid > 1);
    CHECK(path_exists(first.socket));

    if (pid > 1) {
        CHECK_EQ_INT(publish_sidecar(&second, pid), 0);
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", second.xdg, 1), 0);
        CHECK_EQ_INT(ssh_manager_reset("work"), 0);
        CHECK_EQ_INT(kill(pid, 0), 0);
        CHECK(!path_exists(second.sidecar));

        CHECK_EQ_INT(publish_sidecar(&first, pid), 0);
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", first.xdg, 1), 0);
        CHECK_EQ_INT(ssh_manager_reset("work"), 0);
        CHECK_EQ_INT(wait_process_absent(pid), 0);
        CHECK(!path_exists(first.sidecar));
        CHECK(!path_exists(first.socket));
    }

    if (marker_created) (void)unlinkat(first.dir_fd, marker, AT_REMOVEDIR);
    stop_process(pid);
    close(first.dir_fd);
    close(second.dir_fd);
}

static const char *runner_socket_arg(const char *const argv[]) {
    for (size_t index = 1; argv && argv[index]; index++) {
        if (strcmp(argv[index], "-a") == 0 && argv[index + 1]) {
            return argv[index + 1];
        }
    }
    return NULL;
}

static int bind_runner_socket(const char *path, mode_t mode,
                              const run_opts_t *opts) {
    struct sockaddr_un address;
    int saved_cwd = -1;
    int socket_fd = -1;
    int rc = -1;

    if (!path || strlen(path) >= sizeof(address.sun_path)) return -1;
    if (opts && opts->use_cwd_fd) {
        saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
        if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) goto done;
    }
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) goto done;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, mode) != 0) {
        goto done;
    }
    rc = 0;

done:
    if (socket_fd >= 0) close(socket_fd);
    if (saved_cwd >= 0) {
        if (fchdir(saved_cwd) != 0) rc = -1;
        close(saved_cwd);
    }
    return rc;
}

static int bad_permission_agent_runner(const char *const argv[],
                                       const run_opts_t *opts,
                                       run_result_t *result) {
    const char *socket_arg;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || strcmp(argv[0], "ssh-agent") != 0) return 0;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0644, opts) != 0) {
        return -1;
    }
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld; export SSH_AGENT_PID;\n"
            "echo Agent pid %ld;\n",
            socket_arg, (long)TEST_PID, (long)TEST_PID);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return 0;
}

static int missing_pid_agent_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    const char *socket_arg;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || strcmp(argv[0], "ssh-agent") != 0) return 0;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
        return -1;
    }
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "echo Agent pid unavailable;\n",
            socket_arg);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return 0;
}

TEST(pre_sidecar_failed_reap_publishes_retry_tuple) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    char sidecar_text[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08retry"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    safe_strncpy(account.name, "work", sizeof(account.name));
    safe_strncpy(account.email, "work@example.invalid", sizeof(account.email));
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key", fixture.xdg) <
          sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    run_set_runner(previous_runner);
    ssh_manager_set_reap_fn(reap_gone);

    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(config.agent_owned);
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, sidecar_text,
                              sizeof(sidecar_text)) > 0);
    CHECK_STR_EQ(sidecar_text, "1073741824\n");

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(pre_sidecar_cleanup_preserves_reaped_socket_replacement) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08prerace"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(replace_socket_then_gone);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(config.agent_owned);
    CHECK(!path_exists(fixture.sidecar));
    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST(pre_sidecar_probe_cleanup_preserves_socket_replacement) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_quarantine_hook_fn previous_hook;
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08proberace"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;

    previous_runner = run_set_runner(missing_pid_agent_runner);
    previous_hook = ssh_manager_set_unrecorded_cleanup_hook_fn(
        replace_unrecorded_socket_before_cleanup);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_unrecorded_cleanup_hook_fn(previous_hook);
    run_set_runner(previous_runner);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(!path_exists(fixture.sidecar));
    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(indeterminate_identity_retains_retry_sidecar);
    RUN_TEST(permission_denied_presence_probe_is_indeterminate);
    RUN_TEST(failed_pidfd_signal_retains_retry_sidecar);
    RUN_TEST(interrupted_fallback_signal_retries_and_esrch_cleans);
    RUN_TEST(real_kernel_esrch_consumes_stale_sidecar);
    RUN_TEST(runtime_namespace_replacement_fails_without_mutating_either_tree);
    RUN_TEST(sidecar_replacement_before_cleanup_is_restored_and_retained);
    RUN_TEST(socket_replacement_before_cleanup_survives_with_stable_link);
    RUN_TEST(reaped_agent_socket_self_removal_is_idempotent);
    RUN_TEST(final_quarantine_substitution_is_not_deleted);
    RUN_TEST(portable_final_quarantine_substitution_is_not_deleted);
    RUN_TEST(portable_restore_retirement_substitution_is_preserved);
    RUN_TEST(unrelated_live_pid_is_not_signaled);
    RUN_TEST(signal_storm_preserves_term_and_kill_deadlines);
    RUN_TEST(runtime_root_provenance_prevents_cross_root_reap);
    RUN_TEST(pre_sidecar_failed_reap_publishes_retry_tuple);
    RUN_TEST(pre_sidecar_cleanup_preserves_reaped_socket_replacement);
    RUN_TEST(pre_sidecar_probe_cleanup_preserves_socket_replacement);
TEST_MAIN_END()
