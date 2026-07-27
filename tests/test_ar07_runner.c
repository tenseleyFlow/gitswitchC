/* AR-07 T2: subprocess setup, input integrity, capture liveness, and fd close. */
#define _GNU_SOURCE
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#define GITSWITCH_RUNNER_GROUP_TEST_API
#include "runner_internal.h"
#undef GITSWITCH_RUNNER_GROUP_TEST_API
#include "error.h"
#include "signals.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_self_path[MAX_PATH_LEN];

typedef enum {
    SIGPIPE_DISPOSITION_DEFAULT = 0,
    SIGPIPE_DISPOSITION_IGNORE,
    SIGPIPE_DISPOSITION_CUSTOM
} sigpipe_disposition_t;

static volatile sig_atomic_t g_sigpipe_witness_calls;

static void sigpipe_witness_handler(int signal_number) {
    (void)signal_number;
    g_sigpipe_witness_calls++;
}

static bool sigactions_semantically_equal(const struct sigaction *left,
                                          const struct sigaction *right) {
    if (!left || !right || left->sa_flags != right->sa_flags) return false;
#ifdef SA_SIGINFO
    if ((left->sa_flags & SA_SIGINFO) != 0) {
        if (left->sa_sigaction != right->sa_sigaction) return false;
    } else
#endif
    if (left->sa_handler != right->sa_handler) {
        return false;
    }

#ifdef NSIG
    const int signal_limit = NSIG;
#else
    const int signal_limit = 128;
#endif
    for (int signal_number = 1; signal_number < signal_limit;
         signal_number++) {
        int left_member = sigismember(&left->sa_mask, signal_number);
        int right_member = sigismember(&right->sa_mask, signal_number);
        if (left_member != right_member) return false;
    }
    return true;
}

static int install_default_signal_fixture(
    int signal_number, struct sigaction *original,
    struct sigaction *configured) {
    struct sigaction action;

    if (!original || !configured ||
        sigaction(signal_number, NULL, original) != 0) {
        return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(signal_number, &action, NULL) != 0) {
        return -1;
    }
    if (sigaction(signal_number, NULL, configured) != 0) {
        int saved_errno = errno;

        (void)sigaction(signal_number, original, NULL);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

typedef bool (*signal_fixture_check_fn)(void);

static bool ignored_signal_fixture_check_passes(
    int signal_number, signal_fixture_check_fn check) {
    struct sigaction original;
    struct sigaction ignored;
    struct sigaction configured;
    struct sigaction after;
    bool passed;
    int query_rc;
    int restore_rc;

    if (!check || sigaction(signal_number, NULL, &original) != 0) {
        return false;
    }
    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) != 0 ||
        sigaction(signal_number, &ignored, NULL) != 0) {
        return false;
    }
    if (sigaction(signal_number, NULL, &configured) != 0) {
        (void)sigaction(signal_number, &original, NULL);
        return false;
    }
    passed = check();
    query_rc = sigaction(signal_number, NULL, &after);
    restore_rc = sigaction(signal_number, &original, NULL);
    return passed && query_rc == 0 && restore_rc == 0 &&
           sigactions_semantically_equal(&configured, &after);
}

static int install_sigpipe_disposition(sigpipe_disposition_t disposition,
                                       struct sigaction *original,
                                       struct sigaction *installed) {
    struct sigaction action;

    if (sigaction(SIGPIPE, NULL, original) != 0) return -1;
    memset(&action, 0, sizeof(action));
    if (sigemptyset(&action.sa_mask) != 0) return -1;
    switch (disposition) {
        case SIGPIPE_DISPOSITION_DEFAULT:
            action.sa_handler = SIG_DFL;
            break;
        case SIGPIPE_DISPOSITION_IGNORE:
            action.sa_handler = SIG_IGN;
            break;
        case SIGPIPE_DISPOSITION_CUSTOM:
            action.sa_handler = sigpipe_witness_handler;
            if (sigaddset(&action.sa_mask, SIGUSR1) != 0) return -1;
            action.sa_flags = SA_RESTART;
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    if (sigaction(SIGPIPE, &action, NULL) != 0) return -1;
    return sigaction(SIGPIPE, NULL, installed);
}

static int sigpipe_round_trip_worker(sigpipe_disposition_t disposition) {
    const char *argv[] = {"true", NULL};
    struct sigaction original;
    struct sigaction installed;
    struct sigaction after;
    run_result_t result;

    if (install_sigpipe_disposition(disposition, &original, &installed) != 0) {
        return 10;
    }
    int run_rc = run_argv(argv, NULL, &result);
    int query_rc = sigaction(SIGPIPE, NULL, &after);
    int restore_rc = sigaction(SIGPIPE, &original, NULL);
    if (run_rc != 0 || !result.spawned || result.exit_code != 0) return 11;
    if (query_rc != 0 || restore_rc != 0) return 12;
    if (!sigactions_semantically_equal(&installed, &after)) return 13;
    return 0;
}

static bool sigpipe_round_trip_passes(sigpipe_disposition_t disposition) {
    int status = 0;

    fflush(NULL);
    pid_t worker = fork();
    if (worker < 0) return false;
    if (worker == 0) _exit(sigpipe_round_trip_worker(disposition));
    return waitpid(worker, &status, 0) == worker && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

static bool reap_within(pid_t pid, int timeout_ms, int *status_out);

static bool isolated_runner_check_passes(int (*check)(void)) {
    int status = 0;

    fflush(NULL);
    pid_t worker = fork();
    if (worker < 0) return false;
    if (worker == 0) _exit(check());
    if (!reap_within(worker, 2000, &status)) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  isolated runner worker status=%d\n", status);
        return false;
    }
    return true;
}

static bool isolated_runner_check_returns_normally(int (*check)(void)) {
    int status = 0;

    fflush(NULL);
    pid_t worker = fork();
    if (worker < 0) return false;
    if (worker == 0) exit(check());
    if (!reap_within(worker, 2000, &status)) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  normal-exit runner worker status=%d\n", status);
        return false;
    }
    return true;
}

static bool sigsets_semantically_equal(const sigset_t *left,
                                       const sigset_t *right) {
#ifdef NSIG
    const int signal_limit = NSIG;
#else
    const int signal_limit = 128;
#endif
    for (int signal_number = 1; signal_number < signal_limit;
         signal_number++) {
        int left_member = sigismember(left, signal_number);
        int right_member = sigismember(right, signal_number);
        if (left_member < 0 && right_member < 0) continue;
        if (left_member != right_member) return false;
    }
    return true;
}

typedef enum {
    SIGPIPE_PENDING_NO_INPUT = 0,
    SIGPIPE_PENDING_WITH_EPIPE,
    SIGPIPE_NEW_EPIPE
} sigpipe_pending_case_t;

static int sigpipe_pending_worker(sigpipe_pending_case_t test_case) {
    /* Exceed supported platforms' pipe capacities so the parent cannot queue
     * every byte before the helper closes fd 0; an actual EPIPE is required
     * to exercise selective pending-SIGPIPE consumption deterministically. */
    static char input[8U * 1024U * 1024U];
    const char *argv_no_input[] = {g_self_path, "--ar07-fd-probe", NULL};
    const char *argv_epipe[] = {g_self_path, "--ar11-close-stdin", NULL};
    struct sigaction original_action;
    struct sigaction installed_action;
    struct sigaction after_action;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    sigset_t pending;
    sigset_t pipe_set;
    run_opts_t opts;
    run_result_t result;
    bool initially_pending = test_case != SIGPIPE_NEW_EPIPE;
    bool with_input = test_case != SIGPIPE_PENDING_NO_INPUT;

    if (install_sigpipe_disposition(SIGPIPE_DISPOSITION_CUSTOM,
                                    &original_action,
                                    &installed_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) {
        return 20;
    }
    configured_mask = original_mask;
    if (initially_pending) sigaddset(&configured_mask, SIGPIPE);
    else sigdelset(&configured_mask, SIGPIPE);
    sigaddset(&configured_mask, SIGUSR2);
    if (sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) return 21;
    if (initially_pending && raise(SIGPIPE) != 0) return 22;

    memset(&opts, 0, sizeof(opts));
    if (with_input) {
        opts.input = input;
        opts.input_len = sizeof(input);
    }
    g_sigpipe_witness_calls = 0;
    int run_rc = run_argv(with_input ? argv_epipe : argv_no_input,
                          with_input ? &opts : NULL, &result);
    int returned_errno = errno;
    if (sigaction(SIGPIPE, NULL, &after_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0 ||
        sigpending(&pending) != 0) {
        return 23;
    }
    bool remains_pending = sigismember(&pending, SIGPIPE) == 1;
    bool exact_action =
        sigactions_semantically_equal(&installed_action, &after_action);
    bool exact_mask = sigsets_semantically_equal(&configured_mask, &after_mask);

    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    int drain_error = 0;
    int drained_signal = 0;
    if (remains_pending) {
        do {
            drain_error = sigwait(&pipe_set, &drained_signal);
        } while (drain_error == EINTR);
    }
    int action_restore = sigaction(SIGPIPE, &original_action, NULL);
    int mask_restore = sigprocmask(SIG_SETMASK, &original_mask, NULL);
    if (drain_error != 0 ||
        (remains_pending && drained_signal != SIGPIPE) ||
        action_restore != 0 || mask_restore != 0) {
        return 24;
    }
    if (!result.spawned || !exact_action || !exact_mask) return 25;
    if (initially_pending != remains_pending) return 26;
    if (g_sigpipe_witness_calls != 0) return 27;
    if (with_input && run_rc != -1) return 28;
    if (!with_input && (run_rc != 0 || result.exit_code != 0)) return 29;
    /* Pending-set inspection and synchronous draining are internal
     * bookkeeping; their transient errno must never escape the runner. */
    if (with_input && returned_errno == EAGAIN) return 30;
    return 0;
}

TEST(sigpipe_default_disposition_round_trips_exactly) {
    CHECK(sigpipe_round_trip_passes(SIGPIPE_DISPOSITION_DEFAULT));
}

TEST(sigpipe_ignore_disposition_round_trips_exactly) {
    CHECK(sigpipe_round_trip_passes(SIGPIPE_DISPOSITION_IGNORE));
}

TEST(sigpipe_custom_handler_mask_and_flags_round_trip_exactly) {
    CHECK(sigpipe_round_trip_passes(SIGPIPE_DISPOSITION_CUSTOM));
}

static int sigpipe_pending_no_input_worker(void) {
    return sigpipe_pending_worker(SIGPIPE_PENDING_NO_INPUT);
}

static int sigpipe_pending_epipe_worker(void) {
    return sigpipe_pending_worker(SIGPIPE_PENDING_WITH_EPIPE);
}

static int sigpipe_new_epipe_worker(void) {
    return sigpipe_pending_worker(SIGPIPE_NEW_EPIPE);
}

TEST(sigpipe_initial_pending_instance_survives_no_input_execution) {
    CHECK(isolated_runner_check_passes(sigpipe_pending_no_input_worker));
}

TEST(sigpipe_initial_pending_instance_survives_epipe) {
    CHECK(isolated_runner_check_passes(sigpipe_pending_epipe_worker));
}

TEST(sigpipe_runner_generated_epipe_leaves_no_pending_instance) {
    CHECK(isolated_runner_check_passes(sigpipe_new_epipe_worker));
}

static int fd_probe_main(void) {
    const int inherited_fds[] = {64, 128, 200};
    for (size_t i = 0;
         i < sizeof(inherited_fds) / sizeof(inherited_fds[0]); i++) {
        errno = 0;
        if (fcntl(inherited_fds[i], F_GETFD) >= 0 || errno != EBADF) {
            return 1;
        }
    }
    return 0;
}

static bool write_full(int fd, const void *buffer, size_t length) {
    const char *bytes = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static bool read_full(int fd, void *buffer, size_t length) {
    char *bytes = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t got = read(fd, bytes + offset, length - offset);
        if (got > 0) {
            offset += (size_t)got;
        } else if (got == 0) {
            return false;
        } else if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

static int stdin_eof_probe_main(void) {
    char byte;
    ssize_t got;
    do {
        got = read(STDIN_FILENO, &byte, 1);
    } while (got < 0 && errno == EINTR);
    return got == 0 ? 0 : 1;
}

static int stdout_probe_main(void) {
    static const char witness[] = "AR07-DISCARD-WITNESS";
    return write_full(STDOUT_FILENO, witness, sizeof(witness) - 1) ? 0 : 1;
}

static int close_stdin_pause_main(void) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 300000000L};

    if (close(STDIN_FILENO) != 0) return 1;
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
    return 0;
}

static int quiet_capture_holder_main(void) {
    pid_t holder = fork();
    if (holder < 0) return 1;
    if (holder == 0) {
        struct timespec lifetime = {.tv_sec = 2, .tv_nsec = 0};
        while (nanosleep(&lifetime, &lifetime) != 0 && errno == EINTR) {}
        _exit(0);
    }
    return 0;
}

static int deadline_pause_main(bool close_stdout) {
    struct timespec lifetime = {.tv_sec = 5, .tv_nsec = 0};
    if (close_stdout && close(STDOUT_FILENO) != 0) return 1;
    while (nanosleep(&lifetime, &lifetime) != 0 && errno == EINTR) {}
    return 0;
}

static int64_t test_monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool waitpid_within(pid_t pid, int timeout_ms, int *status_out) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
    int elapsed = 0;
    while (elapsed <= timeout_ms) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            if (status_out) *status_out = status;
            return true;
        }
        if (waited < 0 && errno != EINTR) return false;
        nanosleep(&pause, NULL);
        elapsed += 10;
    }
    return false;
}

static bool reap_within(pid_t pid, int timeout_ms, int *status_out) {
    if (waitpid_within(pid, timeout_ms, status_out)) return true;
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) return false;
    return waitpid_within(pid, 1000, status_out);
}

/* M45/T13: with no descriptor available even for trusted-command pinning,
 * run_argv must stop in the parent and never fork a helper. */
TEST(runner_fails_before_spawn_under_fd_exhaustion) {
    int status = 0;

    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        struct rlimit limit = {.rlim_cur = 3, .rlim_max = 3};
        const char *argv[] = {"true", NULL};
        run_result_t result;

        if (fcntl(STDIN_FILENO, F_GETFD) < 0 ||
            fcntl(STDOUT_FILENO, F_GETFD) < 0 ||
            fcntl(STDERR_FILENO, F_GETFD) < 0 ||
            setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            _exit(2);
        }
        clear_error();
        int rc = run_argv(argv, NULL, &result);
        const error_context_t *error = get_last_error();
        _exit(rc != 0 && !result.spawned && error &&
                      strstr(error->message, "trusted PATH") != NULL
                  ? 0 : 1);
    }
    CHECK(reap_within(worker, 1500, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* The checked CLOEXEC status channel must carry a child-side setup failure to
 * the parent instead of reducing it to a bare helper exit status. */
TEST(child_setup_status_is_reported_explicitly) {
    char invalid_env[300];
    const char *env[] = {invalid_env, NULL};
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;

    memset(invalid_env, 'K', sizeof(invalid_env));
    invalid_env[270] = '=';
    invalid_env[271] = 'x';
    invalid_env[272] = '\0';
    memset(&opts, 0, sizeof(opts));
    opts.extra_env = env;

    clear_error();
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 126);
    CHECK(strstr(get_last_error()->message, "environment setup failed") != NULL);
}

TEST(process_group_supervisor_setup_failure_is_truthful_and_reaped) {
    const char *argv[] = {"true", NULL};
    run_result_t failed;
    run_result_t retry;
    int64_t started = test_monotonic_ms();

    run_test_set_child_process_group_failure(EPERM);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &failed), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, EPERM);
    CHECK(failed.spawned);
    CHECK_EQ_INT(failed.exit_code, 126);
    CHECK(elapsed >= 0 && elapsed < 1000);
    CHECK(strstr(get_last_error()->message,
                 "process-group supervisor setup failed") != NULL);

    errno = 0;
    CHECK_EQ_INT(waitpid(-1, NULL, WNOHANG), -1);
    CHECK_EQ_INT(errno, ECHILD);
    CHECK_EQ_INT(run_argv(argv, NULL, &retry), 0);
    CHECK(retry.spawned);
    CHECK_EQ_INT(retry.exit_code, 0);
}

TEST(supervisor_stage_failures_are_truthful_reaped_and_one_shot) {
    static const struct {
        run_test_supervisor_failure_stage_t stage;
        int system_errno;
    } cases[] = {
        {RUN_TEST_SUPERVISOR_FAILURE_WORKER_RELEASE_PIPE, EMFILE},
        {RUN_TEST_SUPERVISOR_FAILURE_INNER_FORK, EAGAIN},
        {RUN_TEST_SUPERVISOR_FAILURE_REPLAY, EIO},
        {RUN_TEST_SUPERVISOR_FAILURE_RELEASE_WRITE, EPIPE}
    };
    const char *argv[] = {"true", NULL};

    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_result_t failed;
        run_result_t retry;
        int64_t started = test_monotonic_ms();

        run_test_set_supervisor_failure(
            cases[i].stage, cases[i].system_errno);
        clear_error();
        errno = 0;
        CHECK_EQ_INT(run_argv(argv, NULL, &failed), -1);
        int returned_errno = errno;
        int64_t elapsed = test_monotonic_ms() - started;

        CHECK_EQ_INT(returned_errno, cases[i].system_errno);
        CHECK(failed.spawned);
        CHECK_EQ_INT(failed.exit_code, 126);
        CHECK(elapsed >= 0 && elapsed < 1000);
        CHECK(strstr(get_last_error()->message,
                     "process-group supervisor setup failed") != NULL);

        errno = 0;
        CHECK_EQ_INT(waitpid(-1, NULL, WNOHANG), -1);
        CHECK_EQ_INT(errno, ECHILD);
        CHECK_EQ_INT(run_argv(argv, NULL, &retry), 0);
        CHECK(retry.spawned);
        CHECK_EQ_INT(retry.exit_code, 0);
    }
}

static volatile sig_atomic_t g_pre_release_hook_called;
static volatile sig_atomic_t g_pre_release_hook_rollback_active;
static volatile sig_atomic_t g_pre_release_hook_waited;

static void kill_gated_supervisor_before_release(pid_t supervisor_pid) {
    siginfo_t info;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
    int64_t started;

    g_pre_release_hook_called = 1;
    g_pre_release_hook_rollback_active =
        signals_rollback_active() ? 1 : 0;
    if (raise(SIGTERM) != 0 || raise(SIGTERM) != 0) return;
    started = test_monotonic_ms();
    while (started >= 0) {
        int64_t now;
        int wait_rc;

        memset(&info, 0, sizeof(info));
        wait_rc = waitid(P_PID, (id_t)supervisor_pid, &info,
                         WEXITED | WNOWAIT | WNOHANG);
        if (wait_rc == 0 && info.si_pid == supervisor_pid) {
            g_pre_release_hook_waited = 1;
            return;
        }
        if (wait_rc != 0 && errno != EINTR) return;
        now = test_monotonic_ms();
        if (now < 0 || now - started >= 1000) return;
        (void)nanosleep(&pause, NULL);
    }
}

static int pre_release_sigpipe_worker(void) {
    const char *argv[] = {"true", NULL};
    struct sigaction original_action;
    struct sigaction installed_action;
    struct sigaction after_action;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    sigset_t pending;
    run_result_t failed;
    run_result_t retry;
    int64_t started;

    if (install_sigpipe_disposition(SIGPIPE_DISPOSITION_CUSTOM,
                                    &original_action,
                                    &installed_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) {
        return 31;
    }
    configured_mask = original_mask;
    if (sigdelset(&configured_mask, SIGPIPE) != 0 ||
        sigdelset(&configured_mask, SIGTERM) != 0 ||
        sigaddset(&configured_mask, SIGUSR2) != 0 ||
        sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0 ||
        signals_guard_begin() != 0) {
        return 32;
    }
    signals_rollback_begin();
    g_pre_release_hook_called = 0;
    g_pre_release_hook_rollback_active = 0;
    g_pre_release_hook_waited = 0;
    g_sigpipe_witness_calls = 0;
    run_test_set_pre_group_release_hook(
        kill_gated_supervisor_before_release);
    clear_error();
    errno = 0;
    started = test_monotonic_ms();
    int run_rc = run_argv(argv, NULL, &failed);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;
    run_test_set_pre_group_release_hook(NULL);
    if (sigaction(SIGPIPE, NULL, &after_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0 ||
        sigpending(&pending) != 0) {
        return 33;
    }
    errno = 0;
    int unreaped = waitpid(-1, NULL, WNOHANG);
    int unreaped_errno = errno;
    int retry_rc = run_argv(argv, NULL, &retry);
    signals_rollback_end();
    int guard_rc = signals_guard_end();
    int action_restore = sigaction(SIGPIPE, &original_action, NULL);
    int mask_restore =
        sigprocmask(SIG_SETMASK, &original_mask, NULL);

    return run_rc == -1 && returned_errno == EPIPE &&
                   failed.spawned &&
                   elapsed >= 0 && elapsed < 1000 &&
                   g_pre_release_hook_called == 1 &&
                   g_pre_release_hook_rollback_active == 1 &&
                   g_pre_release_hook_waited == 1 &&
                   strstr(get_last_error()->message,
                          "cannot release child process-group gate") != NULL &&
                   sigactions_semantically_equal(
                       &installed_action, &after_action) &&
                   sigsets_semantically_equal(
                       &configured_mask, &after_mask) &&
                   sigismember(&pending, SIGPIPE) == 0 &&
                   g_sigpipe_witness_calls == 0 &&
                   unreaped == -1 && unreaped_errno == ECHILD &&
                   retry_rc == 0 && retry.spawned &&
                   retry.exit_code == 0 &&
                   guard_rc == 0 && action_restore == 0 &&
                   mask_restore == 0
               ? 0 : 34;
}

TEST(pre_release_group_death_cannot_sigpipe_parent) {
    CHECK(isolated_runner_check_passes(pre_release_sigpipe_worker));
}

/* M30: accepting only a prefix into the kernel pipe is not successful input
 * delivery when the helper closes stdin and exits zero. */
TEST(early_stdin_close_is_a_runner_failure) {
    const size_t input_len = 1024 * 1024;
    char *input = malloc(input_len);
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;

    CHECK(input != NULL);
    if (!input) return;
    memset(input, 0x5a, input_len);
    memset(&opts, 0, sizeof(opts));
    opts.input = input;
    opts.input_len = input_len;

    clear_error();
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(strstr(get_last_error()->message,
                 "before all input was delivered") != NULL);
    free(input);
}

TEST(full_binary_stdin_delivery_remains_successful) {
    const size_t input_len = 128 * 1024;
    unsigned char *input = malloc(input_len);
    char *output = malloc(input_len + 1);
    const char *argv[] = {"cat", NULL};
    run_opts_t opts;
    run_result_t result;

    CHECK(input != NULL);
    CHECK(output != NULL);
    if (!input || !output) {
        free(input);
        free(output);
        return;
    }
    for (size_t i = 0; i < input_len; i++) input[i] = (unsigned char)i;
    memset(&opts, 0, sizeof(opts));
    opts.input = (const char *)input;
    opts.input_len = input_len;
    opts.out = output;
    opts.out_size = input_len + 1;

    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK_EQ_INT((long)result.out_len, (long)input_len);
    CHECK(!result.out_truncated);
    CHECK(memcmp(input, output, input_len) == 0);
    CHECK(output[input_len] == '\0');
    free(input);
    free(output);
}

/* A non-NULL input pointer with length zero is an intentional empty stream,
 * not "no stdin policy" and not a writable pipe that may be left open.  Keep
 * the witness bounded so a regression cannot wedge the suite. */
TEST(intentional_zero_byte_input_delivers_eof_successfully) {
    int status = 0;
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) return;
    if (worker == 0) {
        const char empty = '\0';
        const char *argv[] = {g_self_path, "--ar07-stdin-eof-probe", NULL};
        run_opts_t opts;
        run_result_t result;

        memset(&opts, 0, sizeof(opts));
        opts.input = &empty;
        opts.input_len = 0;
        int rc = run_argv(argv, &opts, &result);
        _exit(rc == 0 && result.spawned && result.exit_code == 0 ? 0 : 1);
    }
    CHECK(reap_within(worker, 1500, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* With opts->input absent, the helper receives /dev/null.  A byte deliberately
 * queued on the worker's own stdin must remain there after the helper exits,
 * proving the helper neither inherited nor consumed parent input. */
TEST(default_stdin_is_devnull_and_parent_input_is_preserved) {
    int supplied_stdin[2];
    int status = 0;
    const char witness = 'S';

    if (pipe(supplied_stdin) != 0) {
        CHECK(!"cannot create stdin witness pipe");
        return;
    }
    if (write_full(supplied_stdin[1], &witness, 1)) {
        close(supplied_stdin[1]);
    } else {
        close(supplied_stdin[0]);
        close(supplied_stdin[1]);
        CHECK(!"cannot seed stdin witness");
        return;
    }

    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) {
        close(supplied_stdin[0]);
        return;
    }
    if (worker == 0) {
        const char *argv[] = {g_self_path, "--ar07-stdin-eof-probe", NULL};
        run_result_t result;
        char preserved = '\0';

        if (dup2(supplied_stdin[0], STDIN_FILENO) != STDIN_FILENO) _exit(2);
        if (supplied_stdin[0] != STDIN_FILENO) close(supplied_stdin[0]);
        int rc = run_argv(argv, NULL, &result);
        ssize_t got;
        do {
            got = read(STDIN_FILENO, &preserved, 1);
        } while (got < 0 && errno == EINTR);
        _exit(rc == 0 && result.exit_code == 0 && got == 1 &&
                      preserved == witness
                  ? 0 : 1);
    }
    close(supplied_stdin[0]);
    CHECK(reap_within(worker, 1500, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* With no capture buffer, child stdout is nominally discarded.  Put the
 * worker's stdout on a private capture pipe and prove the direct child marker
 * never reaches that parent-owned stream. */
TEST(default_stdout_is_devnull_not_parent_stdout) {
    int captured_stdout[2];
    int status = 0;

    if (pipe(captured_stdout) != 0) {
        CHECK(!"cannot create stdout capture pipe");
        return;
    }
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) {
        close(captured_stdout[0]);
        close(captured_stdout[1]);
        return;
    }
    if (worker == 0) {
        close(captured_stdout[0]);
        if (dup2(captured_stdout[1], STDOUT_FILENO) != STDOUT_FILENO) _exit(2);
        if (captured_stdout[1] != STDOUT_FILENO) close(captured_stdout[1]);

        const char *argv[] = {g_self_path, "--ar07-stdout-probe", NULL};
        run_result_t result;
        int rc = run_argv(argv, NULL, &result);
        _exit(rc == 0 && result.exit_code == 0 ? 0 : 1);
    }
    close(captured_stdout[1]);
    bool reaped = reap_within(worker, 1500, &status);
    char leaked[64];
    ssize_t got;
    do {
        got = read(captured_stdout[0], leaked, sizeof(leaked));
    } while (got < 0 && errno == EINTR);
    close(captured_stdout[0]);
    CHECK(reaped);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK_EQ_INT(got, 0);
}

/* L12: the direct shell exits while its background child retains stdout.  Run
 * the witness in a bounded worker so neutering WNOHANG cannot wedge the suite. */
TEST(descendant_held_capture_pipe_returns_within_grace) {
    int status = 0;
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        const char *argv[] = {"sh", "-c", "sleep 1 &", NULL};
        char output[32];
        run_opts_t opts;
        run_result_t result;
        int64_t start = test_monotonic_ms();

        memset(&opts, 0, sizeof(opts));
        opts.out = output;
        opts.out_size = sizeof(output);
        opts.stderr_to_devnull = true;
        clear_error();
        int rc = run_argv(argv, &opts, &result);
        int64_t elapsed = test_monotonic_ms() - start;
        _exit(rc != 0 && result.spawned && result.exit_code == 0 &&
                      elapsed >= 0 && elapsed < 750 &&
                      strstr(get_last_error()->message,
                             "remained open after the direct child") != NULL
                  ? 0 : 1);
    }
    CHECK(reap_within(worker, 2000, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static bool process_gone_within(pid_t pid, int timeout_ms) {
    int waited = 0;
    while (waited < timeout_ms) {
        if (kill(pid, 0) != 0 && errno == ESRCH) return true;
        struct timespec delay = {.tv_nsec = 10000000L};
        nanosleep(&delay, NULL);
        waited += 10;
    }
    return kill(pid, 0) != 0 && errno == ESRCH;
}

TEST(timeout_kills_the_proven_group_grandchild) {
    const char *argv[] = {
        "sh", "-c", "sleep 30 & child=$!; echo \"$child\"; wait", NULL
    };
    char output[64];
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    /* The deadline proves group cleanup, not shell startup latency. Leave
     * enough room for Darwin's sanitizer runtime to start the shell and
     * publish the descendant PID before expiring the group. */
    CHECK_EQ_INT(run_deadline_after_millis(1000, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    pid_t descendant = (pid_t)strtol(output, NULL, 10);
    CHECK(descendant > 1);
    if (descendant > 1) CHECK(process_gone_within(descendant, 1000));
}

TEST(successful_leader_with_stdout_holder_kills_group_before_pid_release) {
    const char *argv[] = {
        "sh", "-c", "sleep 30 & echo \"$!\"", NULL
    };
    char output[64];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int64_t elapsed = test_monotonic_ms() - started;
    pid_t descendant = (pid_t)strtol(output, NULL, 10);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(elapsed >= 0 && elapsed < 1000);
    CHECK(descendant > 1);
    if (descendant > 1) CHECK(process_gone_within(descendant, 1000));
}

TEST(closed_stdio_daemon_like_descendant_remains_supported) {
    const char *argv[] = {
        "sh", "-c", "sleep 1 </dev/null >/dev/null 2>&1 &", NULL
    };
    char output[16];
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
}

static int rollback_group_signal_worker(void) {
    const char *argv[] = {
        "sh", "-c", "trap '' TERM; sleep 30 & echo \"$!\"; wait", NULL
    };
    char output[64];
    run_opts_t opts;
    run_result_t result;
    pid_t signaler;

    if (signals_guard_begin() != 0) {
        return 70;
    }
    signals_rollback_begin();
    signaler = fork();
    if (signaler < 0) return 71;
    if (signaler == 0) {
        struct timespec delay = {.tv_nsec = 100000000L};
        nanosleep(&delay, NULL);
        (void)kill(getppid(), SIGTERM);
        nanosleep(&delay, NULL);
        (void)kill(getppid(), SIGTERM);
        _exit(0);
    }
    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    int rc = run_argv(argv, &opts, &result);
    int signaler_status = 0;
    (void)waitpid(signaler, &signaler_status, 0);
    pid_t descendant = (pid_t)strtol(output, NULL, 10);
    bool gone = descendant > 1 && process_gone_within(descendant, 1000);
    signals_rollback_end();
    (void)signals_guard_end();
    return rc != 0 && gone ? 0 : 72;
}

TEST(repeated_rollback_signal_terminates_group_descendant) {
    CHECK(isolated_runner_check_passes(rollback_group_signal_worker));
}

static int supervisor_termination_worker(int signal_number,
                                         bool post_replay) {
    const char *argv[] = {"sleep", "30", NULL};
    struct sigaction original_action;
    struct sigaction configured_action;
    struct sigaction after_action;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    run_opts_t opts;
    run_result_t result;
    int rc = -1;
    int outcome = 78;
    bool action_configured = false;
    bool mask_configured = false;
    bool guard_started = false;
    bool correct = false;

    if (install_default_signal_fixture(
            signal_number, &original_action, &configured_action) != 0) {
        return 73;
    }
    action_configured = true;
    if (sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) {
        outcome = 73;
        goto cleanup;
    }
    configured_mask = original_mask;
    if (sigdelset(&configured_mask, signal_number) != 0 ||
        sigaddset(&configured_mask, SIGUSR1) != 0 ||
        sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) {
        outcome = 74;
        goto cleanup;
    }
    mask_configured = true;
    if (signals_guard_begin() != 0) {
        outcome = 75;
        goto cleanup;
    }
    guard_started = true;
    memset(&opts, 0, sizeof(opts));
    if (run_deadline_after_millis(1000, &opts.deadline_millis) != 0) {
        outcome = 76;
        goto cleanup;
    }
    opts.use_deadline = true;
    if (post_replay) {
        run_test_set_post_replay_signal(signal_number);
    } else {
        run_test_set_supervisor_pending_signal(signal_number);
    }
    rc = run_argv(argv, &opts, &result);
    run_test_set_supervisor_pending_signal(0);
    run_test_set_post_replay_signal(0);
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0) {
        outcome = 77;
        goto cleanup;
    }
    correct = rc == -1 && result.spawned && !result.timed_out &&
              result.exit_code == -1 &&
              result.term_signal == signal_number &&
              signals_pending_signal() == signal_number &&
              sigsets_semantically_equal(&configured_mask, &after_mask);
    if (signals_guard_end() != 0) goto cleanup;
    guard_started = false;
    if (sigaction(signal_number, NULL, &after_action) != 0 ||
        !sigactions_semantically_equal(
            &configured_action, &after_action)) {
        goto cleanup;
    }
    outcome = correct ? 0 : 78;

cleanup:
    run_test_set_supervisor_pending_signal(0);
    run_test_set_post_replay_signal(0);
    if (guard_started && signals_guard_end() != 0 && outcome == 0) {
        outcome = 78;
    }
    if (mask_configured &&
        sigprocmask(SIG_SETMASK, &original_mask, NULL) != 0 &&
        outcome == 0) {
        outcome = 78;
    }
    if (action_configured &&
        sigaction(signal_number, &original_action, NULL) != 0 &&
        outcome == 0) {
        outcome = 78;
    }
    return outcome;
}

static int supervisor_pending_sigterm_worker(void) {
    return supervisor_termination_worker(SIGTERM, false);
}

static int supervisor_pending_sigint_worker(void) {
    return supervisor_termination_worker(SIGINT, false);
}

static int post_replay_group_sigterm_worker(void) {
    return supervisor_termination_worker(SIGTERM, true);
}

static int post_replay_group_sigint_worker(void) {
    return supervisor_termination_worker(SIGINT, true);
}

static bool supervisor_pending_sigint_fixture_passes(void) {
    return isolated_runner_check_passes(
        supervisor_pending_sigint_worker);
}

static bool post_replay_group_sigint_fixture_passes(void) {
    return isolated_runner_check_passes(
        post_replay_group_sigint_worker);
}

static int supervisor_pending_sighup_worker(void) {
    return supervisor_termination_worker(SIGHUP, false);
}

static int post_replay_group_sigquit_worker(void) {
    return supervisor_termination_worker(SIGQUIT, true);
}

TEST(supervisor_only_pending_termination_reaches_gated_worker_once) {
    CHECK(isolated_runner_check_passes(supervisor_pending_sigterm_worker));
    CHECK(ignored_signal_fixture_check_passes(
        SIGINT, supervisor_pending_sigint_fixture_passes));
}

TEST(post_replay_group_termination_reaches_worker_once) {
    CHECK(isolated_runner_check_passes(
        post_replay_group_sigterm_worker));
    CHECK(ignored_signal_fixture_check_passes(
        SIGINT, post_replay_group_sigint_fixture_passes));
}

TEST(hangup_and_quit_relays_are_parent_observable_once) {
    CHECK(isolated_runner_check_returns_normally(
        supervisor_pending_sighup_worker));
    CHECK(isolated_runner_check_returns_normally(
        post_replay_group_sigquit_worker));
}

static int pending_replay_failure_worker(void) {
    const char *argv[] = {"true", NULL};
    struct sigaction original_action;
    struct sigaction configured_action;
    struct sigaction after_action;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    run_result_t failed;
    run_result_t retry;
    int outcome = 91;
    bool action_configured = false;
    bool mask_configured = false;
    bool guard_started = false;

    if (install_default_signal_fixture(
            SIGHUP, &original_action, &configured_action) != 0) {
        return 91;
    }
    action_configured = true;
    if (sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) goto cleanup;
    configured_mask = original_mask;
    if (sigdelset(&configured_mask, SIGHUP) != 0 ||
        sigaddset(&configured_mask, SIGUSR1) != 0 ||
        sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) {
        goto cleanup;
    }
    mask_configured = true;
    if (signals_guard_begin() != 0) goto cleanup;
    guard_started = true;

    run_test_set_supervisor_pending_signal(SIGHUP);
    run_test_set_supervisor_failure(
        RUN_TEST_SUPERVISOR_FAILURE_REPLAY, EIO);
    clear_error();
    errno = 0;
    int run_rc = run_argv(argv, NULL, &failed);
    int returned_errno = errno;
    run_test_set_supervisor_pending_signal(0);
    run_test_set_supervisor_failure(
        RUN_TEST_SUPERVISOR_FAILURE_NONE, 0);
    int retry_rc = run_argv(argv, NULL, &retry);
    int guard_end_rc = signals_guard_end();
    if (guard_end_rc == 0) guard_started = false;
    int mask_query_rc =
        sigprocmask(SIG_SETMASK, NULL, &after_mask);
    int action_query_rc =
        sigaction(SIGHUP, NULL, &after_action);
    errno = 0;
    int unreaped = waitpid(-1, NULL, WNOHANG);
    int unreaped_errno = errno;

    outcome =
        run_rc == -1 && returned_errno == EIO &&
                failed.spawned && failed.exit_code == 126 &&
                strstr(get_last_error()->message,
                       "process-group supervisor setup failed") != NULL &&
                !signals_pending() && signals_pending_signal() == 0 &&
                retry_rc == 0 && retry.spawned && retry.exit_code == 0 &&
                guard_end_rc == 0 &&
                mask_query_rc == 0 && action_query_rc == 0 &&
                sigsets_semantically_equal(
                    &configured_mask, &after_mask) &&
                sigactions_semantically_equal(
                    &configured_action, &after_action) &&
                unreaped == -1 && unreaped_errno == ECHILD
            ? 0 : 92;

cleanup:
    run_test_set_supervisor_pending_signal(0);
    run_test_set_supervisor_failure(
        RUN_TEST_SUPERVISOR_FAILURE_NONE, 0);
    if (guard_started && signals_guard_end() != 0 && outcome == 0) {
        outcome = 92;
    }
    if (mask_configured &&
        sigprocmask(SIG_SETMASK, &original_mask, NULL) != 0 &&
        outcome == 0) {
        outcome = 92;
    }
    if (action_configured &&
        sigaction(SIGHUP, &original_action, NULL) != 0 &&
        outcome == 0) {
        outcome = 92;
    }
    return outcome;
}

TEST(pending_signal_is_not_published_when_replay_setup_fails) {
    CHECK(isolated_runner_check_returns_normally(
        pending_replay_failure_worker));
}

static int supervisor_stop_worker(bool post_replay) {
    const char *argv[] = {"sleep", "30", NULL};
    struct sigaction original_action;
    struct sigaction default_action;
    struct sigaction configured_action;
    struct sigaction after_action;
    sigset_t before_mask;
    sigset_t after_mask;
    run_opts_t opts;
    run_result_t result;
    int64_t started;

    if (sigaction(SIGTSTP, NULL, &original_action) != 0) return 79;
    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    if (sigemptyset(&default_action.sa_mask) != 0 ||
        sigaction(SIGTSTP, &default_action, NULL) != 0 ||
        sigaction(SIGTSTP, NULL, &configured_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &before_mask) != 0 ||
        sigdelset(&before_mask, SIGTSTP) != 0 ||
        sigprocmask(SIG_SETMASK, &before_mask, NULL) != 0) {
        return 79;
    }
    memset(&opts, 0, sizeof(opts));
    if (run_deadline_after_millis(1000, &opts.deadline_millis) != 0) {
        return 80;
    }
    opts.use_deadline = true;
    started = test_monotonic_ms();
    if (post_replay) {
        run_test_set_post_replay_signal(SIGTSTP);
    } else {
        run_test_set_supervisor_pending_signal(SIGTSTP);
    }
    int rc = run_argv(argv, &opts, &result);
    run_test_set_supervisor_pending_signal(0);
    run_test_set_post_replay_signal(0);
    int64_t elapsed = test_monotonic_ms() - started;
    int mask_query_rc = sigprocmask(SIG_SETMASK, NULL, &after_mask);
    int action_query_rc = sigaction(SIGTSTP, NULL, &after_action);
    int action_restore_rc =
        sigaction(SIGTSTP, &original_action, NULL);
    return rc == -1 && result.spawned && !result.timed_out &&
                   result.exit_code == -1 &&
                   result.term_signal == SIGKILL &&
                   elapsed >= 0 && elapsed < 1000 &&
                   mask_query_rc == 0 && action_query_rc == 0 &&
                   action_restore_rc == 0 &&
                   sigsets_semantically_equal(&before_mask, &after_mask) &&
                   sigactions_semantically_equal(
                       &configured_action, &after_action)
               ? 0 : 82;
}

static int supervisor_pending_stop_worker(void) {
    return supervisor_stop_worker(false);
}

static int supervisor_post_replay_stop_worker(void) {
    return supervisor_stop_worker(true);
}

TEST(supervisor_only_pending_stop_fails_closed_without_hanging) {
    CHECK(isolated_runner_check_passes(supervisor_pending_stop_worker));
}

TEST(post_replay_supervisor_stop_handler_fails_group_closed) {
    CHECK(isolated_runner_check_passes(
        supervisor_post_replay_stop_worker));
}

static int supervisor_ignored_signal_worker(int signal_number) {
    const char *argv[] = {"true", NULL};
    struct sigaction original_action;
    struct sigaction ignored_action;
    struct sigaction installed_action;
    struct sigaction after_action;
    run_result_t result;

    if (sigaction(signal_number, NULL, &original_action) != 0) return 83;
    memset(&ignored_action, 0, sizeof(ignored_action));
    ignored_action.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored_action.sa_mask) != 0 ||
        sigaction(signal_number, &ignored_action, NULL) != 0 ||
        sigaction(signal_number, NULL, &installed_action) != 0) {
        return 84;
    }
    run_test_set_supervisor_pending_signal(signal_number);
    int rc = run_argv(argv, NULL, &result);
    run_test_set_supervisor_pending_signal(0);
    int query_rc = sigaction(signal_number, NULL, &after_action);
    int restore_rc = sigaction(signal_number, &original_action, NULL);
    return rc == 0 && result.spawned && result.exit_code == 0 &&
                   query_rc == 0 && restore_rc == 0 &&
                   sigactions_semantically_equal(
                       &installed_action, &after_action)
               ? 0 : 85;
}

static int supervisor_ignored_hup_worker(void) {
    return supervisor_ignored_signal_worker(SIGHUP);
}

static int supervisor_ignored_stop_worker(void) {
    return supervisor_ignored_signal_worker(SIGTSTP);
}

TEST(supervisor_injection_preserves_inherited_ignored_signal) {
    CHECK(isolated_runner_check_passes(supervisor_ignored_hup_worker));
    CHECK(isolated_runner_check_passes(supervisor_ignored_stop_worker));
}

static int pending_signal_mask_probe_main(void) {
    sigset_t current;
    sigset_t pending;

    if (sigprocmask(SIG_SETMASK, NULL, &current) != 0 ||
        sigpending(&pending) != 0) {
        return 86;
    }
    return sigismember(&current, SIGTERM) == 1 &&
                   sigismember(&current, SIGUSR1) == 1 &&
                   sigismember(&current, SIGINT) == 0 &&
                   sigismember(&current, SIGHUP) == 0 &&
                   sigismember(&current, SIGQUIT) == 0 &&
                   sigismember(&current, SIGTSTP) == 0 &&
                   sigismember(&pending, SIGTERM) == 1
               ? 0 : 87;
}

static int supervisor_pending_blocked_signal_worker(void) {
    const char *argv[] = {
        g_self_path, "--ar14-pending-signal-mask-probe", NULL
    };
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    run_opts_t opts;
    run_result_t result;

    if (sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) return 88;
    configured_mask = original_mask;
    if (sigaddset(&configured_mask, SIGTERM) != 0 ||
        sigaddset(&configured_mask, SIGUSR1) != 0 ||
        sigdelset(&configured_mask, SIGINT) != 0 ||
        sigdelset(&configured_mask, SIGHUP) != 0 ||
        sigdelset(&configured_mask, SIGQUIT) != 0 ||
        sigdelset(&configured_mask, SIGTSTP) != 0 ||
        sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) {
        return 89;
    }
    run_test_set_supervisor_pending_signal(SIGTERM);
    memset(&opts, 0, sizeof(opts));
    if (run_deadline_after_millis(1000, &opts.deadline_millis) != 0) {
        run_test_set_supervisor_pending_signal(0);
        (void)sigprocmask(SIG_SETMASK, &original_mask, NULL);
        return 90;
    }
    opts.use_deadline = true;
    int rc = run_argv(argv, &opts, &result);
    run_test_set_supervisor_pending_signal(0);
    int query_rc = sigprocmask(SIG_SETMASK, NULL, &after_mask);
    int restore_rc =
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
    return rc == 0 && result.spawned && result.exit_code == 0 &&
                   result.term_signal == 0 && query_rc == 0 &&
                   restore_rc == 0 &&
                   sigsets_semantically_equal(
                       &configured_mask, &after_mask)
               ? 0 : 90;
}

TEST(supervisor_only_pending_blocked_signal_survives_exec) {
    CHECK(isolated_runner_check_passes(
        supervisor_pending_blocked_signal_worker));
}

static int pty_foreground_signal_worker(int slave_fd, int ready_fd,
                                        int expected_signal,
                                        bool expect_pending) {
    const char *argv[] = {"sleep", "30", NULL};
    struct sigaction original_action;
    struct sigaction configured_action;
    struct sigaction after_action;
    run_result_t result;
    pid_t caller_group;
    int controlled_signal =
        expect_pending ? expected_signal : SIGTSTP;
    int outcome = 84;
    bool action_configured = false;
    bool guard_started = false;

    if (install_default_signal_fixture(
            controlled_signal, &original_action,
            &configured_action) != 0) {
        return 79;
    }
    action_configured = true;
    if (setsid() < 0 || ioctl(slave_fd, TIOCSCTTY, 0) != 0) {
        outcome = 80;
        goto cleanup;
    }
    if (dup2(slave_fd, STDIN_FILENO) != STDIN_FILENO ||
        dup2(slave_fd, STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(slave_fd, STDERR_FILENO) != STDERR_FILENO) {
        outcome = 81;
        goto cleanup;
    }
    if (slave_fd > STDERR_FILENO) close(slave_fd);
    caller_group = getpgrp();
    if (tcsetpgrp(STDIN_FILENO, caller_group) != 0 ||
        write(ready_fd, &caller_group, sizeof(caller_group)) !=
            (ssize_t)sizeof(caller_group)) {
        outcome = 82;
        goto cleanup;
    }
    close(ready_fd);
    ready_fd = -1;
    if (signals_guard_begin() != 0) {
        outcome = 83;
        goto cleanup;
    }
    guard_started = true;
    int rc = run_argv(argv, NULL, &result);
    bool restored = tcgetpgrp(STDIN_FILENO) == caller_group;
    bool relayed = expect_pending
                       ? signals_pending_signal() == expected_signal
                       : signals_pending_signal() == 0;
    if (signals_guard_end() != 0) goto cleanup;
    guard_started = false;
    if (sigaction(controlled_signal, NULL, &after_action) != 0 ||
        !sigactions_semantically_equal(
            &configured_action, &after_action)) {
        goto cleanup;
    }
    outcome = rc != 0 && result.spawned &&
                      result.term_signal == expected_signal &&
                      restored && relayed
                  ? 0 : 84;

cleanup:
    if (ready_fd >= 0) close(ready_fd);
    if (guard_started && signals_guard_end() != 0 && outcome == 0) {
        outcome = 84;
    }
    if (action_configured &&
        sigaction(controlled_signal, &original_action, NULL) != 0 &&
        outcome == 0) {
        outcome = 84;
    }
    return outcome;
}

static bool pty_control_round_trip(unsigned char control,
                                   int expected_signal,
                                   bool expect_pending) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        if (master >= 0) close(master);
        return false;
    }
    char *slave_name = ptsname(master);
    if (!slave_name) {
        close(master);
        return false;
    }
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    int ready[2];
    int pipe_rc = pipe(ready);
    if (slave < 0 || pipe_rc != 0) {
        if (slave >= 0) close(slave);
        close(master);
        return false;
    }
    pid_t worker = fork();
    if (worker == 0) {
        close(master);
        close(ready[0]);
        _exit(pty_foreground_signal_worker(
            slave, ready[1], expected_signal, expect_pending));
    }
    if (worker < 0) {
        close(slave);
        close(master);
        close(ready[0]);
        close(ready[1]);
        return false;
    }
    close(slave);
    close(ready[1]);
    pid_t caller_group = 0;
    ssize_t got = read(ready[0], &caller_group, sizeof(caller_group));
    close(ready[0]);
    if (got != (ssize_t)sizeof(caller_group)) {
        close(master);
        return false;
    }
    bool transferred = false;
    for (int elapsed = 0; elapsed < 1000; elapsed += 10) {
        pid_t foreground = tcgetpgrp(master);
        if (foreground > 0 && foreground != caller_group) {
            transferred = true;
            break;
        }
        struct timespec delay = {.tv_nsec = 10000000L};
        nanosleep(&delay, NULL);
    }
    if (!transferred || write(master, &control, 1U) != 1) {
        (void)kill(worker, SIGKILL);
        close(master);
        return false;
    }
    int status = 0;
    bool reaped = waitpid_within(worker, 2000, &status);
    if (!reaped) {
        /* Darwin can retain a controlling-session leader in the exiting
         * state until the peer releases the PTY master. Do not turn that
         * teardown interlock into an unbounded post-SIGKILL wait: release the
         * master, then give the already-completed worker a bounded reap. */
        close(master);
        master = -1;
        reaped = waitpid_within(worker, 1000, &status);
    }
    if (!reaped) {
        (void)kill(worker, SIGKILL);
        (void)waitpid_within(worker, 1000, &status);
    }
    bool passed =
        reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (master >= 0) close(master);
    return passed;
}

static bool pty_interrupt_fixture_passes(void) {
    return pty_control_round_trip(0x03U, SIGINT, true);
}

TEST(pty_interrupt_targets_child_group_and_restores_foreground_owner) {
    CHECK(ignored_signal_fixture_check_passes(
        SIGINT, pty_interrupt_fixture_passes));
}

TEST(pty_stop_fails_closed_without_hanging_and_restores_foreground_owner) {
    CHECK(pty_control_round_trip(0x1aU, SIGKILL, false));
}

static volatile sig_atomic_t g_periodic_alarm_calls;

static void periodic_alarm_handler(int signal_number) {
    (void)signal_number;
    g_periodic_alarm_calls++;
}

static int interrupted_poll_deadline_worker(void) {
    const char *argv[] = {g_self_path, "--ar11-quiet-holder", NULL};
    struct sigaction original_action;
    struct sigaction action;
    struct itimerval timer;
    struct itimerval stopped = {{0, 0}, {0, 0}};
    char output[16];
    run_opts_t opts;
    run_result_t result;

    if (sigaction(SIGALRM, NULL, &original_action) != 0) return 50;
    memset(&action, 0, sizeof(action));
    action.sa_handler = periodic_alarm_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0) {
        return 51;
    }
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 10000;
    timer.it_interval.tv_usec = 10000;
    g_periodic_alarm_calls = 0;
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) return 52;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    int64_t started = test_monotonic_ms();
    clear_error();
    int rc = run_argv(argv, &opts, &result);
    int64_t elapsed = test_monotonic_ms() - started;
    int timer_rc = setitimer(ITIMER_REAL, &stopped, NULL);
    int action_rc = sigaction(SIGALRM, &original_action, NULL);

    if (timer_rc != 0 || action_rc != 0) return 53;
    if (rc != -1 || !result.spawned || result.exit_code != 0) return 54;
    if (elapsed < 180 || elapsed > 1000) return 55;
    if (g_periodic_alarm_calls < 5) return 56;
    if (!strstr(get_last_error()->message,
                "remained open after the direct child")) {
        return 57;
    }
    return 0;
}

/* AR-11 M29: handled signals may interrupt every poll cycle, but the direct
 * child still starts the retained-stream grace deadline immediately. */
TEST(interrupted_poll_still_advances_child_capture_deadline) {
    CHECK(isolated_runner_check_passes(interrupted_poll_deadline_worker));
}

/* A finite drain-to-EAGAIN loop is not sufficient when a descendant writes
 * faster than the reader.  The per-poll chunk budget must still let waitpid
 * observe the exited shell and enforce the same post-exit grace. */
TEST(continuous_descendant_output_cannot_starve_capture_deadline) {
    int status = 0;
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        const char *argv[] = {"sh", "-c", "yes x &", NULL};
        char output[32];
        run_opts_t opts;
        run_result_t result;
        int64_t start = test_monotonic_ms();

        memset(&opts, 0, sizeof(opts));
        opts.out = output;
        opts.out_size = sizeof(output);
        opts.stderr_to_devnull = true;
        clear_error();
        int rc = run_argv(argv, &opts, &result);
        int64_t elapsed = test_monotonic_ms() - start;
        _exit(rc != 0 && result.spawned && result.exit_code == 0 &&
                      result.out_truncated && elapsed >= 0 && elapsed < 750 &&
                      strstr(get_last_error()->message,
                             "remained open after the direct child") != NULL
                  ? 0 : 1);
    }
    CHECK(reap_within(worker, 2000, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST(ordinary_buffered_capture_is_fully_drained) {
    const char *argv[] = {"sh", "-c", "printf 'buffered-output'", NULL};
    char output[64];
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK_STR_EQ(output, "buffered-output");
    CHECK_EQ_INT((long)result.out_len, 15);
}

TEST(deadline_helper_rejects_invalid_and_overflowing_durations) {
    int64_t deadline = 0;

    errno = 0;
    CHECK_EQ_INT(run_deadline_after_millis(-1, &deadline), -1);
    CHECK_EQ_INT(errno, EINVAL);
    errno = 0;
    CHECK_EQ_INT(run_deadline_after_millis(1, NULL), -1);
    CHECK_EQ_INT(errno, EINVAL);
    errno = 0;
    CHECK_EQ_INT(run_deadline_after_millis(INT64_MAX, &deadline), -1);
    CHECK_EQ_INT(errno, EOVERFLOW);
}

TEST(monotonic_millisecond_conversion_checks_quotient_remainder) {
    const int64_t seconds = INT64_MAX / 1000;
    const int64_t remainder = INT64_MAX % 1000;
    int64_t deadline = 0;

    run_test_set_monotonic_timespec(
        1, seconds, (long)(remainder + 1) * 1000000L);
    errno = 0;
    CHECK_EQ_INT(run_deadline_after_millis(0, &deadline), -1);
    CHECK_EQ_INT(errno, EOVERFLOW);

    run_test_set_monotonic_timespec(
        1, seconds, (long)remainder * 1000000L);
    CHECK_EQ_INT(run_deadline_after_millis(0, &deadline), 0);
    CHECK_EQ_INT(deadline, INT64_MAX);
}

TEST(expired_and_negative_deadlines_fail_before_spawn) {
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.use_deadline = true;
    opts.deadline_millis = -1;
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK_EQ_INT(errno, EINVAL);
    CHECK(!result.spawned);
    CHECK(!result.timed_out);

    opts.deadline_millis = 0;
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK_EQ_INT(errno, ETIMEDOUT);
    CHECK(!result.spawned);
    CHECK(result.timed_out);
}

TEST(invalid_invocation_precedes_expired_deadline) {
    const char *argv[] = {"true", NULL};
    const char input = 'x';
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.use_deadline = true;
    opts.deadline_millis = 0;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(NULL, &opts, &result), -1);
    CHECK(!result.spawned);
    CHECK(!result.timed_out);
    CHECK(strstr(get_last_error()->message, "empty argv") != NULL);

    opts.input = &input;
    opts.input_len = 1;
    opts.use_stdin_fd = true;
    opts.stdin_fd = STDIN_FILENO;
    clear_error();
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK(!result.spawned);
    CHECK(!result.timed_out);
    CHECK(strstr(get_last_error()->message,
                 "mutually exclusive") != NULL);
}

TEST(deadline_covers_child_setup_status_and_reaps_timeout) {
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    CHECK_EQ_INT(run_deadline_after_millis(80, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    run_test_set_child_setup_delay(2000);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;
    run_test_set_child_setup_delay(0);

    CHECK_EQ_INT(returned_errno, ETIMEDOUT);
    CHECK(result.spawned);
    CHECK(result.timed_out);
    CHECK_EQ_INT(result.term_signal, SIGKILL);
    CHECK(elapsed >= 0 && elapsed < 1000);
    CHECK(strstr(get_last_error()->message, "deadline expired") != NULL);
}

static void check_pause_deadline(bool close_stdout) {
    const char *argv[] = {
        g_self_path,
        close_stdout ? "--ar14-deadline-close-stdout"
                     : "--ar14-deadline-pause",
        NULL
    };
    char output[32];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    CHECK_EQ_INT(run_deadline_after_millis(100, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, ETIMEDOUT);
    CHECK(result.spawned);
    CHECK(result.timed_out);
    CHECK_EQ_INT(result.term_signal, SIGKILL);
    CHECK(elapsed >= 0 && elapsed < 1000);
}

TEST(deadline_kills_and_reaps_hung_child_with_open_capture) {
    check_pause_deadline(false);
}

TEST(deadline_kills_and_reaps_hung_child_after_capture_eof) {
    check_pause_deadline(true);
}

TEST(poll_failure_kills_and_reaps_before_reporting_primary_errno) {
    const char *argv[] = {g_self_path, "--ar14-deadline-pause", NULL};
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    CHECK_EQ_INT(run_deadline_after_millis(1000, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    run_test_set_poll_failure(2, EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, EIO);
    CHECK(result.spawned);
    CHECK(!result.timed_out);
    CHECK_EQ_INT(result.term_signal, SIGKILL);
    CHECK(elapsed >= 0 && elapsed < 750);
    CHECK(strstr(get_last_error()->message,
                 "subprocess pipe I/O failed") != NULL);
}

TEST(poll_failure_closes_open_input_and_capture_before_reaping) {
    static const char input[] = "input remains pending";
    const char *argv[] = {g_self_path, "--ar14-deadline-pause", NULL};
    char output[16];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.input = input;
    opts.input_len = sizeof(input) - 1;
    opts.out = output;
    opts.out_size = sizeof(output);
    run_test_set_poll_failure(1, EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, EIO);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.term_signal, SIGKILL);
    CHECK_EQ_INT(result.out_len, 0);
    CHECK_STR_EQ(output, "");
    CHECK(elapsed >= 0 && elapsed < 750);
    CHECK(strstr(get_last_error()->message,
                 "subprocess pipe I/O failed") != NULL);
}

TEST(relay_eof_does_not_hide_descendant_held_capture) {
    const char *argv[] = {g_self_path, "--ar11-quiet-holder", NULL};
    char output[16];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    clear_error();
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK_EQ_INT(result.out_len, 0);
    CHECK(elapsed >= 180 && elapsed < 1000);
    CHECK(strstr(get_last_error()->message,
                 "remained open after the direct child") != NULL);
}

static void fail_final_deadline_observation(pid_t supervisor_pid) {
    (void)supervisor_pid;
    /* After release: child-status EOF, one runner-loop observation, then the
     * final post-loop observation covered by this fault. */
    run_test_set_monotonic_failure(3, EIO);
}

TEST(final_deadline_clock_failure_preserves_reaped_exit_status) {
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.use_deadline = true;
    opts.deadline_millis = INT64_MAX;
    run_test_set_pre_group_release_hook(fail_final_deadline_observation);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);

    CHECK_EQ_INT(errno, EIO);
    CHECK(result.spawned);
    CHECK(!result.timed_out);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK_EQ_INT(result.term_signal, 0);
    CHECK(strstr(get_last_error()->message,
                 "cannot observe monotonic deadline while running child") !=
          NULL);
}

/* Leave enough launch headroom for a contended scheduler while remaining
 * below the runner's 250 ms retained-capture grace that these tests preempt. */
TEST(global_deadline_preempts_descendant_capture_grace) {
    const char *argv[] = {"sh", "-c", "sleep 2 &", NULL};
    char output[32];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_deadline_after_millis(200, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, ETIMEDOUT);
    CHECK(result.spawned);
    CHECK(result.timed_out);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(elapsed >= 0 && elapsed < 750);
}

TEST(global_deadline_survives_continuous_descendant_output) {
    const char *argv[] = {"sh", "-c", "yes x &", NULL};
    char output[32];
    run_opts_t opts;
    run_result_t result;
    int64_t started = test_monotonic_ms();

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_deadline_after_millis(200, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    int64_t elapsed = test_monotonic_ms() - started;

    CHECK_EQ_INT(returned_errno, ETIMEDOUT);
    CHECK(result.spawned);
    CHECK(result.timed_out);
    CHECK(result.out_truncated);
    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(elapsed >= 0 && elapsed < 750);
}

TEST(global_deadline_survives_repeated_poll_interruptions) {
    const char *argv[] = {g_self_path, "--ar14-deadline-pause", NULL};
    struct sigaction original_action;
    struct sigaction action;
    struct itimerval timer;
    struct itimerval stopped = {{0, 0}, {0, 0}};
    run_opts_t opts;
    run_result_t result;

    CHECK_EQ_INT(sigaction(SIGALRM, NULL, &original_action), 0);
    memset(&action, 0, sizeof(action));
    action.sa_handler = periodic_alarm_handler;
    CHECK_EQ_INT(sigemptyset(&action.sa_mask), 0);
    CHECK_EQ_INT(sigaction(SIGALRM, &action, NULL), 0);
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 5000;
    timer.it_interval.tv_usec = 5000;
    g_periodic_alarm_calls = 0;
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &timer, NULL), 0);

    memset(&opts, 0, sizeof(opts));
    CHECK_EQ_INT(run_deadline_after_millis(100, &opts.deadline_millis), 0);
    opts.use_deadline = true;
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    int returned_errno = errno;
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &stopped, NULL), 0);
    CHECK_EQ_INT(sigaction(SIGALRM, &original_action, NULL), 0);

    CHECK_EQ_INT(returned_errno, ETIMEDOUT);
    CHECK(result.timed_out);
    CHECK_EQ_INT(result.term_signal, SIGKILL);
    CHECK(g_periodic_alarm_calls >= 5);
}

TEST(clock_failure_and_rollback_fail_closed_without_timeout_claim) {
    const char *argv[] = {"true", NULL};
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.use_deadline = true;
    opts.deadline_millis = INT64_MAX;
    run_test_set_monotonic_failure(1, EIO);
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK(!result.spawned);
    CHECK(!result.timed_out);
    CHECK(strstr(get_last_error()->message,
                 "cannot observe monotonic deadline") != NULL);

    run_test_set_monotonic_rollback(2, 10000);
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
    CHECK_EQ_INT(errno, ERANGE);
    CHECK(!result.spawned);
    CHECK(!result.timed_out);
    CHECK(strstr(get_last_error()->message,
                 "monotonic clock moved backwards") != NULL);

    /* Both one-shot hooks self-clear; an ordinary deadline remains usable. */
    CHECK_EQ_INT(run_deadline_after_millis(1000, &opts.deadline_millis), 0);
    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK(result.spawned);
    CHECK(!result.timed_out);
    CHECK_EQ_INT(result.exit_code, 0);
}

/* L21 safety matrix: sparse inherited descriptors must be absent under every
 * selectable cleanup branch, not only the host's AUTO choice. */
typedef struct {
    int runner_ok;
    int observation_valid;
    run_test_fd_close_observation_t observation;
} sparse_fd_report_t;

static bool sparse_fds_closed_by(
    run_test_fd_close_strategy_t strategy,
    run_test_fd_close_observation_t *observation_out) {
    int report_pipe[2];
    int status = 0;

    if (pipe(report_pipe) != 0) return false;
    pid_t worker = fork();
    if (worker < 0) {
        close(report_pipe[0]);
        close(report_pipe[1]);
        return false;
    }
    if (worker == 0) {
        close(report_pipe[0]);
        int nullfd = open("/dev/null", O_RDONLY);
        const char *argv[] = {g_self_path, "--ar07-fd-probe", NULL};
        run_result_t result;
        sparse_fd_report_t report = {0};

        run_test_set_fd_close_observation(true);
        if (run_test_set_fd_close_strategy(strategy) != 0 || nullfd < 0 ||
            dup2(nullfd, 64) != 64 ||
            dup2(nullfd, 128) != 128 || dup2(nullfd, 200) != 200) {
            _exit(2);
        }
        if (nullfd != 64 && nullfd != 128 && nullfd != 200) close(nullfd);
        report.runner_ok =
            run_argv(argv, NULL, &result) == 0 && result.exit_code == 0;
        report.observation_valid =
            run_test_get_fd_close_observation(&report.observation);
        bool reported = write_full(report_pipe[1], &report, sizeof(report));
        close(report_pipe[1]);
        _exit(reported ? 0 : 3);
    }
    close(report_pipe[1]);
    sparse_fd_report_t report = {0};
    bool reaped = reap_within(worker, 1500, &status);
    bool reported = read_full(report_pipe[0], &report, sizeof(report));
    close(report_pipe[0]);
    if (reported && report.observation_valid && observation_out) {
        *observation_out = report.observation;
    }
    return reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           reported && report.runner_ok && report.observation_valid;
}

TEST(sparse_parent_descriptors_close_in_auto_branch) {
    run_test_fd_close_observation_t observation = {0};
    CHECK(sparse_fds_closed_by(RUN_TEST_FD_CLOSE_AUTO, &observation));
    CHECK_EQ_INT(observation.method,
                 run_test_fd_close_bulk_supported()
                     ? RUN_TEST_FD_METHOD_BULK
                     : RUN_TEST_FD_METHOD_SNAPSHOT);
    CHECK(observation.close_syscalls >= 1);
}

TEST(sparse_parent_descriptors_close_in_snapshot_branch) {
    run_test_fd_close_observation_t observation = {0};
    CHECK(sparse_fds_closed_by(RUN_TEST_FD_CLOSE_SNAPSHOT, &observation));
    CHECK_EQ_INT(observation.method, RUN_TEST_FD_METHOD_SNAPSHOT);
    CHECK(observation.close_syscalls >= 3);
}

TEST(sparse_parent_descriptors_close_in_numeric_branch) {
    run_test_fd_close_observation_t observation = {0};
    CHECK(sparse_fds_closed_by(RUN_TEST_FD_CLOSE_NUMERIC, &observation));
    CHECK_EQ_INT(observation.method, RUN_TEST_FD_METHOD_NUMERIC);
    CHECK(observation.close_syscalls > 200);
}

TEST(sparse_parent_descriptors_close_in_bulk_branch_when_supported) {
    if (!run_test_fd_close_bulk_supported()) {
        TS_SKIP("bulk-fd-close",
                "bulk child-descriptor close is unavailable");
    }
    run_test_fd_close_observation_t observation = {0};
    bool passed = sparse_fds_closed_by(RUN_TEST_FD_CLOSE_BULK,
                                       &observation);
    CHECK(passed);
    CHECK_EQ_INT(observation.method, RUN_TEST_FD_METHOD_BULK);
    CHECK_EQ_INT(observation.close_syscalls, 1);
    if (passed) {
        printf("[ info ] bulk child-FD close branch exercised\n");
    }
}

/* Forced BULK is a diagnostic contract, not AUTO: if the selected primitive
 * cannot execute, the child must report setup failure instead of silently
 * sweeping numerically.  The injected errno models a runtime syscall denial
 * on platforms where the primitive is normally available. */
TEST(forced_bulk_failure_is_reported_without_fallback) {
    const char *argv[] = {"true", NULL};
    run_result_t result;
    run_test_fd_close_observation_t observation = {0};
    bool bulk_supported = run_test_fd_close_bulk_supported();

    CHECK_EQ_INT(run_test_set_fd_close_strategy(RUN_TEST_FD_CLOSE_BULK), 0);
    run_test_set_fd_close_observation(true);
    if (bulk_supported) run_test_set_bulk_close_failure(EIO);

    clear_error();
    int rc = run_argv(argv, NULL, &result);
    const error_context_t *error = get_last_error();
    bool observed = run_test_get_fd_close_observation(&observation);

    run_test_set_bulk_close_failure(0);
    run_test_set_fd_close_observation(false);
    CHECK_EQ_INT(run_test_set_fd_close_strategy(RUN_TEST_FD_CLOSE_AUTO), 0);
    CHECK_EQ_INT(rc, -1);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 126);
    CHECK(error && strstr(error->message,
                          "child descriptor cleanup failed") != NULL);
    CHECK(observed);
    CHECK_EQ_INT(observation.method, RUN_TEST_FD_METHOD_BULK);
    CHECK_EQ_INT(observation.close_syscalls, 0);
}

static bool auto_bulk_failure_fails_closed(const struct rlimit *limit,
                                           int high_fd) {
    int status = 0;

    pid_t worker = fork();
    if (worker < 0) return false;
    if (worker == 0) {
        const char *argv[] = {"true", NULL};
        run_result_t result;
        int nullfd = -1;

        if (high_fd >= 0) {
            struct rlimit raised = *limit;
            if (raised.rlim_cur <= (rlim_t)high_fd) {
                raised.rlim_cur = (rlim_t)high_fd + 1;
                if (setrlimit(RLIMIT_NOFILE, &raised) != 0) _exit(2);
            }
            nullfd = open("/dev/null", O_RDONLY);
            if (nullfd < 0 || dup2(nullfd, high_fd) != high_fd) _exit(2);
            if (nullfd != high_fd) close(nullfd);
        }

        if (run_test_set_fd_close_strategy(RUN_TEST_FD_CLOSE_AUTO) != 0) {
            _exit(2);
        }
        run_test_set_bulk_close_failure(EIO);
        clear_error();
        int rc = run_argv(argv, NULL, &result);
        const error_context_t *error = get_last_error();
        bool failed_closed =
            rc == -1 && result.spawned && result.exit_code == 126 && error &&
            strstr(error->message,
                   "child descriptor cleanup failed") != NULL;

        if (high_fd >= 0) close(high_fd);
        _exit(failed_closed ? 0 : 1);
    }

    return reap_within(worker, 2000, &status) && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

/* M21: AUTO must report an unexpected bulk-close failure over the checked
 * child setup-status channel instead of executing the helper. */
TEST(auto_bulk_failure_fails_child_setup_closed) {
    if (!run_test_fd_close_bulk_supported()) {
        TS_SKIP("bulk-fd-close",
                "AUTO bulk-close failure requires a bulk-close platform");
    }
    CHECK(auto_bulk_failure_fails_closed(NULL, -1));
}

/* A non-CLOEXEC descriptor above the old numeric-sweep cap is the concrete
 * leak witness. Keep it separate so a low hard limit is a truthful skip and
 * never hides the ordinary AUTO fail-closed assertion above. */
TEST(auto_bulk_failure_with_high_fd_fails_child_setup_closed) {
    enum { HIGH_FD = 70000 };
    struct rlimit limit;

    if (!run_test_fd_close_bulk_supported()) {
        TS_SKIP("bulk-fd-close",
                "high-descriptor witness requires bulk close");
    }
    int limit_rc = getrlimit(RLIMIT_NOFILE, &limit);
    CHECK_EQ_INT(limit_rc, 0);
    if (limit_rc != 0) return;
    if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max <= HIGH_FD) {
        TS_SKIP("high-fd",
                "hard descriptor limit cannot represent descriptor 70000");
    }
    CHECK(auto_bulk_failure_fails_closed(&limit, HIGH_FD));
}

static void exhaust_fds_after_exec_pin(const char *resolved_path) {
    (void)resolved_path;
    while (open("/dev/null", O_RDONLY) >= 0) {
        /* The short-lived worker intentionally retains every descriptor. */
    }
}

/* Forced SNAPSHOT must prove enumeration complete before any fork.  The T13
 * post-resolution hook exhausts the worker's remaining slots only AFTER the
 * trusted executable descriptor has been pinned, so enumeration (not command
 * lookup) is the deterministic failure boundary. */
TEST(forced_incomplete_snapshot_fails_before_spawn) {
    int status = 0;

    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        struct rlimit limit = {.rlim_cur = 16, .rlim_max = 16};
        const char *argv[] = {"true", NULL};
        run_result_t result;

        if (fcntl(STDIN_FILENO, F_GETFD) < 0 ||
            fcntl(STDOUT_FILENO, F_GETFD) < 0 ||
            fcntl(STDERR_FILENO, F_GETFD) < 0 ||
            run_test_set_fd_close_strategy(
                RUN_TEST_FD_CLOSE_SNAPSHOT) != 0 ||
            setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            _exit(2);
        }
        run_test_set_exec_resolved_hook(exhaust_fds_after_exec_pin);
        clear_error();
        int rc = run_argv(argv, NULL, &result);
        const error_context_t *error = get_last_error();
        _exit(rc != 0 && !result.spawned && error &&
                      strstr(error->message,
                             "forced child-FD snapshot is incomplete") != NULL
                  ? 0 : 1);
    }
    CHECK(reap_within(worker, 1500, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* M21's portable AUTO choice has the same completeness obligation as forced
 * SNAPSHOT.  Exhaust descriptors after the executable pin so enumeration is
 * deterministically incomplete; AUTO must reject that state before fork,
 * rather than reaching its bounded numeric child fallback. */
TEST(auto_incomplete_snapshot_fails_before_spawn) {
    int status = 0;

    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) return;
    if (worker == 0) {
        struct rlimit limit = {.rlim_cur = 16, .rlim_max = 16};
        const char *argv[] = {"true", NULL};
        run_result_t result;

        if (fcntl(STDIN_FILENO, F_GETFD) < 0 ||
            fcntl(STDOUT_FILENO, F_GETFD) < 0 ||
            fcntl(STDERR_FILENO, F_GETFD) < 0 ||
            run_test_set_fd_close_strategy(RUN_TEST_FD_CLOSE_AUTO) != 0 ||
            setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            _exit(2);
        }
        run_test_set_auto_bulk_close_unavailable(true);
        run_test_set_exec_resolved_hook(exhaust_fds_after_exec_pin);
        clear_error();
        int rc = run_argv(argv, NULL, &result);
        const error_context_t *error = get_last_error();
        _exit(rc != 0 && !result.spawned && error &&
                      strstr(error->message,
                             "automatic child-FD snapshot is incomplete") != NULL
                  ? 0 : 1);
    }
    CHECK(reap_within(worker, 1500, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

typedef struct {
    int64_t elapsed_ms;
    uint64_t close_syscalls;
    run_test_fd_close_method_t method;
} fd_close_measurement_t;

static bool measure_fd_close_strategy(
    run_test_fd_close_strategy_t strategy, int iterations,
    fd_close_measurement_t *measurement) {
    const char *argv[] = {"true", NULL};
    int64_t start;

    memset(measurement, 0, sizeof(*measurement));
    if (run_test_set_fd_close_strategy(strategy) != 0) return false;
    run_test_set_fd_close_observation(true);
    start = test_monotonic_ms();
    if (start < 0) return false;
    for (int i = 0; i < iterations; i++) {
        run_result_t result;
        run_test_fd_close_observation_t observation;
        if (run_argv(argv, NULL, &result) != 0 || result.exit_code != 0) {
            return false;
        }
        if (!run_test_get_fd_close_observation(&observation)) return false;
        if (i == 0) {
            measurement->method = observation.method;
        } else if (measurement->method != observation.method) {
            return false;
        }
        measurement->close_syscalls += observation.close_syscalls;
    }
    int64_t finish = test_monotonic_ms();
    if (finish < 0) return false;
    measurement->elapsed_ms = finish - start;
    return true;
}

/* Complexity and timing witness under a large descriptor limit.  Syscall
 * counts are the regression gate (stable even on overloaded CI); timings are
 * recorded with a generous absolute AUTO liveness bound rather than a noisy
 * cross-process ratio assertion. */
TEST(large_fd_limit_proves_auto_avoids_numeric_sweep) {
    const int iterations = 3;
    struct rlimit original;
    struct rlimit raised;
    fd_close_measurement_t auto_measurement;
    fd_close_measurement_t numeric_measurement;

    if (getrlimit(RLIMIT_NOFILE, &original) != 0) {
        CHECK(!"getrlimit failed");
        return;
    }
    raised = original;
    rlim_t target = 65536;
    if (original.rlim_max != RLIM_INFINITY && original.rlim_max < target) {
        target = original.rlim_max;
    }
    if (original.rlim_cur > target) target = original.rlim_cur;
    raised.rlim_cur = target;
    if (setrlimit(RLIMIT_NOFILE, &raised) != 0) {
        raised = original;
    }

    bool auto_ok = measure_fd_close_strategy(RUN_TEST_FD_CLOSE_AUTO,
                                             iterations,
                                             &auto_measurement);
    bool numeric_ok = measure_fd_close_strategy(RUN_TEST_FD_CLOSE_NUMERIC,
                                                iterations,
                                                &numeric_measurement);
    long numeric_maxfd = sysconf(_SC_OPEN_MAX);
    if (numeric_maxfd < 0 || numeric_maxfd > 65536) numeric_maxfd = 65536;
    uint64_t expected_numeric_calls = numeric_maxfd > 5
        ? (uint64_t)(numeric_maxfd - 5) * (uint64_t)iterations
        : 0;
    run_test_set_fd_close_observation(false);
    int restore_strategy =
        run_test_set_fd_close_strategy(RUN_TEST_FD_CLOSE_AUTO);
    int restore_limit = setrlimit(RLIMIT_NOFILE, &original);

    printf("[ timing ] fd-close limit=%llu iterations=%d "
           "auto(method=%d,calls=%llu,time=%lldms) "
           "numeric(calls=%llu,time=%lldms)\n",
           (unsigned long long)raised.rlim_cur, iterations,
           (int)auto_measurement.method,
           (unsigned long long)auto_measurement.close_syscalls,
           (long long)auto_measurement.elapsed_ms,
           (unsigned long long)numeric_measurement.close_syscalls,
           (long long)numeric_measurement.elapsed_ms);
    CHECK_EQ_INT(restore_strategy, 0);
    CHECK_EQ_INT(restore_limit, 0);
    CHECK(auto_ok);
    CHECK(numeric_ok);
    CHECK(auto_measurement.elapsed_ms >= 0 &&
          auto_measurement.elapsed_ms < 3000);
    CHECK(numeric_measurement.elapsed_ms >= 0);
    CHECK(auto_measurement.method == RUN_TEST_FD_METHOD_BULK ||
          auto_measurement.method == RUN_TEST_FD_METHOD_SNAPSHOT);
    CHECK_EQ_INT(numeric_measurement.method, RUN_TEST_FD_METHOD_NUMERIC);
    CHECK_EQ_INT(numeric_measurement.close_syscalls, expected_numeric_calls);
    CHECK(auto_measurement.close_syscalls <
          numeric_measurement.close_syscalls);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--ar07-fd-probe") == 0) {
        return fd_probe_main();
    }
    if (argc == 2 && strcmp(argv[1], "--ar07-stdin-eof-probe") == 0) {
        return stdin_eof_probe_main();
    }
    if (argc == 2 && strcmp(argv[1], "--ar07-stdout-probe") == 0) {
        return stdout_probe_main();
    }
    if (argc == 2 && strcmp(argv[1], "--ar11-close-stdin") == 0) {
        return close_stdin_pause_main();
    }
    if (argc == 2 && strcmp(argv[1], "--ar11-quiet-holder") == 0) {
        return quiet_capture_holder_main();
    }
    if (argc == 2 && strcmp(argv[1], "--ar14-deadline-pause") == 0) {
        return deadline_pause_main(false);
    }
    if (argc == 2 &&
        strcmp(argv[1], "--ar14-deadline-close-stdout") == 0) {
        return deadline_pause_main(true);
    }
    if (argc == 2 &&
        strcmp(argv[1], "--ar14-pending-signal-mask-probe") == 0) {
        /* This probe observes signal state at executable entry. Bypass
         * sanitizer/stdio exit finalizers so they cannot alter or wait on the
         * deliberately blocked pending signal after the observation. */
        _exit(pending_signal_mask_probe_main());
    }

    error_init(LOG_LEVEL_WARNING, NULL);
    if (argc != 1 || !realpath(argv[0], g_self_path)) {
        fprintf(stderr, "test_ar07_runner: cannot resolve own executable\n");
        return 2;
    }
    RUN_TEST(sigpipe_default_disposition_round_trips_exactly);
    RUN_TEST(sigpipe_ignore_disposition_round_trips_exactly);
    RUN_TEST(sigpipe_custom_handler_mask_and_flags_round_trip_exactly);
    RUN_TEST(sigpipe_initial_pending_instance_survives_no_input_execution);
    RUN_TEST(sigpipe_initial_pending_instance_survives_epipe);
    RUN_TEST(sigpipe_runner_generated_epipe_leaves_no_pending_instance);
    RUN_TEST(runner_fails_before_spawn_under_fd_exhaustion);
    RUN_TEST(child_setup_status_is_reported_explicitly);
    RUN_TEST(process_group_supervisor_setup_failure_is_truthful_and_reaped);
    RUN_TEST(supervisor_stage_failures_are_truthful_reaped_and_one_shot);
    RUN_TEST(pre_release_group_death_cannot_sigpipe_parent);
    RUN_TEST(early_stdin_close_is_a_runner_failure);
    RUN_TEST(full_binary_stdin_delivery_remains_successful);
    RUN_TEST(intentional_zero_byte_input_delivers_eof_successfully);
    RUN_TEST(default_stdin_is_devnull_and_parent_input_is_preserved);
    RUN_TEST(default_stdout_is_devnull_not_parent_stdout);
    RUN_TEST(descendant_held_capture_pipe_returns_within_grace);
    RUN_TEST(timeout_kills_the_proven_group_grandchild);
    RUN_TEST(successful_leader_with_stdout_holder_kills_group_before_pid_release);
    RUN_TEST(closed_stdio_daemon_like_descendant_remains_supported);
    RUN_TEST(repeated_rollback_signal_terminates_group_descendant);
    RUN_TEST(supervisor_only_pending_termination_reaches_gated_worker_once);
    RUN_TEST(post_replay_group_termination_reaches_worker_once);
    RUN_TEST(hangup_and_quit_relays_are_parent_observable_once);
    RUN_TEST(pending_signal_is_not_published_when_replay_setup_fails);
    RUN_TEST(supervisor_only_pending_stop_fails_closed_without_hanging);
    RUN_TEST(post_replay_supervisor_stop_handler_fails_group_closed);
    RUN_TEST(supervisor_injection_preserves_inherited_ignored_signal);
    RUN_TEST(supervisor_only_pending_blocked_signal_survives_exec);
    RUN_TEST(pty_interrupt_targets_child_group_and_restores_foreground_owner);
    RUN_TEST(pty_stop_fails_closed_without_hanging_and_restores_foreground_owner);
    RUN_TEST(interrupted_poll_still_advances_child_capture_deadline);
    RUN_TEST(continuous_descendant_output_cannot_starve_capture_deadline);
    RUN_TEST(ordinary_buffered_capture_is_fully_drained);
    RUN_TEST(deadline_helper_rejects_invalid_and_overflowing_durations);
    RUN_TEST(monotonic_millisecond_conversion_checks_quotient_remainder);
    RUN_TEST(expired_and_negative_deadlines_fail_before_spawn);
    RUN_TEST(invalid_invocation_precedes_expired_deadline);
    RUN_TEST(deadline_covers_child_setup_status_and_reaps_timeout);
    RUN_TEST(deadline_kills_and_reaps_hung_child_with_open_capture);
    RUN_TEST(deadline_kills_and_reaps_hung_child_after_capture_eof);
    RUN_TEST(poll_failure_kills_and_reaps_before_reporting_primary_errno);
    RUN_TEST(poll_failure_closes_open_input_and_capture_before_reaping);
    RUN_TEST(relay_eof_does_not_hide_descendant_held_capture);
    RUN_TEST(final_deadline_clock_failure_preserves_reaped_exit_status);
    RUN_TEST(global_deadline_preempts_descendant_capture_grace);
    RUN_TEST(global_deadline_survives_continuous_descendant_output);
    RUN_TEST(global_deadline_survives_repeated_poll_interruptions);
    RUN_TEST(clock_failure_and_rollback_fail_closed_without_timeout_claim);
    RUN_TEST(sparse_parent_descriptors_close_in_auto_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_snapshot_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_numeric_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_bulk_branch_when_supported);
    RUN_TEST(forced_bulk_failure_is_reported_without_fallback);
    RUN_TEST(auto_bulk_failure_fails_child_setup_closed);
    RUN_TEST(auto_bulk_failure_with_high_fd_fails_child_setup_closed);
    RUN_TEST(forced_incomplete_snapshot_fails_before_spawn);
    RUN_TEST(auto_incomplete_snapshot_fails_before_spawn);
    RUN_TEST(large_fd_limit_proves_auto_avoids_numeric_sweep);
    return ts_test_finish();
}
