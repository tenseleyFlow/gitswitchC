/* AR-07 T2: subprocess setup, input integrity, capture liveness, and fd close. */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_self_path[MAX_PATH_LEN];

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

static int64_t test_monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool reap_within(pid_t pid, int timeout_ms, int *status_out) {
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
    kill(pid, SIGKILL);
    (void)waitpid(pid, NULL, 0);
    return false;
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
        printf("[ info ] bulk child-FD close is unavailable on this platform\n");
        return;
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

/* M21: AUTO must not turn an unexpected bulk-close failure into the capped
 * numeric sweep.  A non-CLOEXEC descriptor above that old 65536 cap is the
 * concrete leak witness; fail-closed AUTO reports the cleanup error over the
 * checked child setup-status channel instead of executing the helper. */
TEST(auto_bulk_failure_with_high_fd_fails_child_setup_closed) {
    enum { HIGH_FD = 70000 };
    struct rlimit limit;
    int status = 0;

    if (!run_test_fd_close_bulk_supported()) {
        printf("[ info ] AUTO bulk-close failure requires a bulk-close platform\n");
        return;
    }
    int limit_rc = getrlimit(RLIMIT_NOFILE, &limit);
    CHECK_EQ_INT(limit_rc, 0);
    if (limit_rc != 0) return;
    bool high_fd_representable =
        limit.rlim_max == RLIM_INFINITY || limit.rlim_max > HIGH_FD;
    if (!high_fd_representable) {
        printf("[ info ] hard descriptor limit cannot represent fd %d; "
               "still checking AUTO setup-status failure\n", HIGH_FD);
    }

    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) return;
    if (worker == 0) {
        struct rlimit raised = limit;
        const char *argv[] = {"true", NULL};
        run_result_t result;
        int nullfd;

        if (high_fd_representable) {
            if (raised.rlim_cur <= HIGH_FD) {
                raised.rlim_cur = (rlim_t)HIGH_FD + 1;
                if (setrlimit(RLIMIT_NOFILE, &raised) != 0) _exit(2);
            }
            nullfd = open("/dev/null", O_RDONLY);
            if (nullfd < 0 || dup2(nullfd, HIGH_FD) != HIGH_FD) _exit(2);
            if (nullfd != HIGH_FD) close(nullfd);
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

        if (high_fd_representable) close(HIGH_FD);
        _exit(failed_closed ? 0 : 1);
    }

    CHECK(reap_within(worker, 2000, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
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

    error_init(LOG_LEVEL_WARNING, NULL);
    if (argc != 1 || !realpath(argv[0], g_self_path)) {
        fprintf(stderr, "test_ar07_runner: cannot resolve own executable\n");
        return 2;
    }
    RUN_TEST(runner_fails_before_spawn_under_fd_exhaustion);
    RUN_TEST(child_setup_status_is_reported_explicitly);
    RUN_TEST(early_stdin_close_is_a_runner_failure);
    RUN_TEST(full_binary_stdin_delivery_remains_successful);
    RUN_TEST(intentional_zero_byte_input_delivers_eof_successfully);
    RUN_TEST(default_stdin_is_devnull_and_parent_input_is_preserved);
    RUN_TEST(default_stdout_is_devnull_not_parent_stdout);
    RUN_TEST(descendant_held_capture_pipe_returns_within_grace);
    RUN_TEST(continuous_descendant_output_cannot_starve_capture_deadline);
    RUN_TEST(ordinary_buffered_capture_is_fully_drained);
    RUN_TEST(sparse_parent_descriptors_close_in_auto_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_snapshot_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_numeric_branch);
    RUN_TEST(sparse_parent_descriptors_close_in_bulk_branch_when_supported);
    RUN_TEST(forced_bulk_failure_is_reported_without_fallback);
    RUN_TEST(auto_bulk_failure_with_high_fd_fails_child_setup_closed);
    RUN_TEST(forced_incomplete_snapshot_fails_before_spawn);
    RUN_TEST(auto_incomplete_snapshot_fails_before_spawn);
    RUN_TEST(large_fd_limit_proves_auto_avoids_numeric_sweep);
    printf("\n%s: %d run, %d failed\n",
           ts_tests_failed ? "RESULT FAIL" : "RESULT OK",
           ts_tests_run, ts_tests_failed);
    return ts_tests_failed == 0 ? 0 : 1;
}
