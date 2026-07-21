/* Tests for the shell-free subprocess runner (run_argv). */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include "signals.h"
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>

static volatile sig_atomic_t g_post_fork_hook_called;
static volatile sig_atomic_t g_post_fork_hook_mask_exact;
static sigset_t g_expected_parent_mask;

static bool signal_masks_equal(const sigset_t *left, const sigset_t *right) {
    for (int signal_number = 1; signal_number < NSIG; signal_number++) {
        int left_member = sigismember(left, signal_number);
        int right_member = sigismember(right, signal_number);
        /* Some platforms reserve holes below NSIG. They are absent from both
         * masks by definition, so matching EINVAL results do not make two
         * otherwise identical masks unequal. */
        if (left_member < 0 && right_member < 0) continue;
        if (left_member != right_member) {
            return false;
        }
    }
    return true;
}

static bool signal_actions_equal(const struct sigaction *left,
                                 const struct sigaction *right) {
    if (left->sa_handler != right->sa_handler ||
        left->sa_flags != right->sa_flags) {
        return false;
    }
    return signal_masks_equal(&left->sa_mask, &right->sa_mask);
}

static void sigchld_reaping_handler(int signal_number) {
    int saved_errno = errno;
    int status;
    (void)signal_number;
    while (waitpid(-1, &status, WNOHANG) > 0) {}
    errno = saved_errno;
}

typedef enum {
    SIGCHLD_POLICY_IGNORE = 0,
    SIGCHLD_POLICY_NOCLDWAIT,
    SIGCHLD_POLICY_REAPER
} sigchld_policy_t;

static int exercise_rejected_sigchld_policy(sigchld_policy_t policy) {
    char marker[] = "/tmp/gitswitch-ar11-sigchld.XXXXXX";
    char command[MAX_PATH_LEN + 32];
    const char *argv[] = {"sh", "-c", command, NULL};
    struct sigaction original_action;
    struct sigaction installed;
    struct sigaction after_action;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    run_result_t result;
    int marker_fd = mkstemp(marker);

    if (marker_fd < 0) return 20;
    close(marker_fd);
    if (unlink(marker) != 0) return 21;
    if ((size_t)snprintf(command, sizeof(command), ": > '%s'", marker) >=
        sizeof(command)) {
        return 22;
    }
    if (sigaction(SIGCHLD, NULL, &original_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) {
        return 23;
    }
    configured_mask = original_mask;
    if (sigaddset(&configured_mask, SIGUSR1) != 0 ||
        sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) {
        return 24;
    }

    memset(&installed, 0, sizeof(installed));
    if (sigemptyset(&installed.sa_mask) != 0 ||
        sigaddset(&installed.sa_mask, SIGUSR2) != 0) {
        return 25;
    }
    switch (policy) {
        case SIGCHLD_POLICY_IGNORE:
            installed.sa_handler = SIG_IGN;
            break;
        case SIGCHLD_POLICY_NOCLDWAIT:
            installed.sa_handler = SIG_DFL;
            installed.sa_flags = SA_NOCLDWAIT;
            break;
        case SIGCHLD_POLICY_REAPER:
            installed.sa_handler = sigchld_reaping_handler;
            installed.sa_flags = SA_RESTART;
            break;
        default:
            return 26;
    }
    if (sigaction(SIGCHLD, &installed, NULL) != 0 ||
        sigaction(SIGCHLD, NULL, &installed) != 0) {
        return 27;
    }

    clear_error();
    errno = 0;
    int rc = run_argv(argv, NULL, &result);
    int returned_errno = errno;
    bool marker_absent = access(marker, F_OK) != 0 && errno == ENOENT;
    if (sigaction(SIGCHLD, NULL, &after_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0) {
        return 28;
    }
    int action_restore = sigaction(SIGCHLD, &original_action, NULL);
    int mask_restore = sigprocmask(SIG_SETMASK, &original_mask, NULL);
    (void)unlink(marker);

    if (action_restore != 0 || mask_restore != 0) return 29;
    if (rc != -1 || result.spawned || returned_errno != EBUSY) return 30;
    if (!marker_absent) return 31;
    if (!signal_actions_equal(&installed, &after_action)) return 32;
    if (!signal_masks_equal(&configured_mask, &after_mask)) return 33;
    return 0;
}

static bool sigchld_policy_is_rejected(sigchld_policy_t policy) {
    int status = 0;
    pid_t worker = fork();
    if (worker < 0) return false;
    if (worker == 0) _exit(exercise_rejected_sigchld_policy(policy));
    return waitpid(worker, &status, 0) == worker && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

TEST(run_rejects_ignored_sigchld_before_spawn) {
    CHECK(sigchld_policy_is_rejected(SIGCHLD_POLICY_IGNORE));
}

TEST(run_rejects_nocldwait_sigchld_before_spawn) {
    CHECK(sigchld_policy_is_rejected(SIGCHLD_POLICY_NOCLDWAIT));
}

TEST(run_rejects_foreign_sigchld_reaper_before_spawn) {
    CHECK(sigchld_policy_is_rejected(SIGCHLD_POLICY_REAPER));
}

static void raise_second_rollback_signal_before_pid_publication(void) {
    sigset_t current;
    sigset_t expected = g_expected_parent_mask;

    /* The ownership window keeps SIGCHLD blocked, and the spawn window adds
     * every guard-INSTALLED signal: SIGINT, SIGTERM, and (AR-10 L16)
     * SIGQUIT. SIGHUP is SIG_IGN here, so the guard deliberately skipped it. */
    sigaddset(&expected, SIGCHLD);
    sigaddset(&expected, SIGINT);
    sigaddset(&expected, SIGTERM);
    sigaddset(&expected, SIGQUIT);
    g_post_fork_hook_called = 1;
    g_post_fork_hook_mask_exact =
        sigprocmask(SIG_SETMASK, NULL, &current) == 0 &&
        signal_masks_equal(&current, &expected);
    (void)raise(SIGTERM);
}

static int exercise_post_fork_signal_publication(void) {
    const char *argv[] = {"sleep", "2", NULL};
    run_result_t result;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    struct sigaction default_action;
    struct sigaction ignored_action;
    int run_rc;

    if (sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) return 10;
    configured_mask = original_mask;
    sigdelset(&configured_mask, SIGINT);
    sigdelset(&configured_mask, SIGTERM);
    sigdelset(&configured_mask, SIGHUP);
    sigaddset(&configured_mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) return 11;
    /* The runner deliberately preserves inherited SIG_IGN dispositions, but
     * this fixture asserts one exact guard shape. Normalize its private worker
     * so INT/TERM/QUIT are installed while inherited HUP ignore is preserved;
     * the release-lock contract independently checks supervisor inheritance. */
    memset(&default_action, 0, sizeof(default_action));
    memset(&ignored_action, 0, sizeof(ignored_action));
    default_action.sa_handler = SIG_DFL;
    ignored_action.sa_handler = SIG_IGN;
    if (sigemptyset(&default_action.sa_mask) != 0 ||
        sigemptyset(&ignored_action.sa_mask) != 0 ||
        sigaction(SIGINT, &default_action, NULL) != 0 ||
        sigaction(SIGTERM, &default_action, NULL) != 0 ||
        sigaction(SIGQUIT, &default_action, NULL) != 0 ||
        sigaction(SIGHUP, &ignored_action, NULL) != 0) {
        return 12;
    }
    if (signals_guard_begin() != 0) return 13;
    if (raise(SIGTERM) != 0 || !signals_pending()) return 14;
    signals_rollback_begin();

    g_expected_parent_mask = configured_mask;
    g_post_fork_hook_called = 0;
    g_post_fork_hook_mask_exact = 0;
    run_test_set_post_fork_pre_publish_hook(
        raise_second_rollback_signal_before_pid_publication);
    run_rc = run_argv(argv, NULL, &result);
    run_test_set_post_fork_pre_publish_hook(NULL);
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0) return 15;

    signals_rollback_end();
    if (signals_guard_end() != 0) return 16;
    if (!g_post_fork_hook_called) return 17;
    if (!g_post_fork_hook_mask_exact) return 18;
    if (!signal_masks_equal(&after_mask, &configured_mask)) return 19;
    if (run_rc != -1 || !result.spawned || result.exit_code != -1 ||
        result.term_signal != SIGTERM) {
        return 20;
    }
    return 0;
}

/* AR-08 M23: a second rollback signal in the few instructions after fork but
 * before child-PID publication must remain pending until publication, then be
 * forwarded to the child. The helper's two-second lifetime bounds the old
 * lost-signal behavior without relying on scheduler timing. */
TEST(run_publishes_child_before_releasing_blocked_rollback_signal) {
    int status = 0;
    pid_t worker;

    fflush(NULL);
    worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        _exit(exercise_post_fork_signal_publication());
    }
    if (worker > 0) {
        CHECK_EQ_INT(waitpid(worker, &status, 0), worker);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

static int exercise_fork_failure_mask_restoration(void) {
    const char *argv[] = {"true", NULL};
    const error_context_t *failure;
    run_result_t result;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t after_mask;
    int run_rc;
    int returned_errno;

    if (sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) return 30;
    configured_mask = original_mask;
    sigdelset(&configured_mask, SIGINT);
    sigdelset(&configured_mask, SIGTERM);
    sigdelset(&configured_mask, SIGHUP);
    sigaddset(&configured_mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) return 31;
    if (signals_guard_begin() != 0) return 32;

    run_test_set_fork_failure(EAGAIN);
    errno = 0;
    run_rc = run_argv(argv, NULL, &result);
    returned_errno = errno;
    failure = get_last_error();
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) != 0) return 33;
    if (signals_guard_end() != 0) return 34;

    if (run_rc != -1 || result.spawned) return 35;
    if (returned_errno != EAGAIN || failure->system_errno != EAGAIN) return 36;
    if (!signal_masks_equal(&after_mask, &configured_mask)) return 37;
    return 0;
}

/* Every failed-fork path releases the barrier and preserves fork's errno,
 * rather than leaking the temporary guarded-signal mask into the parent. */
TEST(run_restores_exact_mask_and_errno_when_fork_fails) {
    int status = 0;
    pid_t worker;

    fflush(NULL);
    worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
        _exit(exercise_fork_failure_mask_restoration());
    }
    if (worker > 0) {
        CHECK_EQ_INT(waitpid(worker, &status, 0), worker);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

/* Run the zero-input edge in a disposable process. Before AR-04 L1 the
 * nested run_argv() polls forever, so the parent must bound the wait and reap
 * deterministically instead of hanging the whole test binary. */
static bool zero_length_input_finishes(const char *input) {
    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        const char *argv[] = {"cat", NULL};
        char out[8];
        run_opts_t opts;
        run_result_t res;
        memset(&opts, 0, sizeof(opts));
        opts.out = out;
        opts.out_size = sizeof(out);
        opts.input = input;
        opts.input_len = 0;
        _exit(run_argv(argv, &opts, &res) == 0 &&
              res.exit_code == 0 && res.out_len == 0 && out[0] == '\0'
                  ? 0 : 1);
    }

    for (int i = 0; i < 500; i++) {
        int status;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (waited < 0) {
            if (errno == EINTR) continue;
            kill(pid, SIGKILL);
            (void)waitpid(pid, NULL, 0);
            return false;
        }
        usleep(10000);
    }

    kill(pid, SIGKILL);
    (void)waitpid(pid, NULL, 0);
    return false;
}

TEST(run_echo_captures_stdout) {
    const char *argv[] = {"echo", "hello", NULL};
    char out[64];
    run_opts_t opts;
    run_result_t res;
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK(res.spawned);
    CHECK_EQ_INT(res.exit_code, 0);
    CHECK_STR_EQ(out, "hello\n");
}

TEST(run_false_reports_exit_1) {
    const char *argv[] = {"false", NULL};
    run_result_t res;
    CHECK_EQ_INT(run_argv(argv, NULL, &res), -1);
    CHECK(res.spawned);
    CHECK_EQ_INT(res.exit_code, 1);
}

TEST(run_true_succeeds) {
    const char *argv[] = {"true", NULL};
    run_result_t res;
    CHECK_EQ_INT(run_argv(argv, NULL, &res), 0);
    CHECK_EQ_INT(res.exit_code, 0);
}

/* Since the PS-1/PS-2 exec pinning, an unresolvable command fails closed in
 * the parent (no fork, no execvp PATH search), so spawned stays false instead
 * of the old "child exec failed with 127" convention. */
TEST(run_nonexistent_command_fails_without_spawn) {
    const char *argv[] = {"gitswitch_no_such_command_xyz", NULL};
    run_result_t res;
    CHECK_EQ_INT(run_argv(argv, NULL, &res), -1);
    CHECK(!res.spawned);
    CHECK_EQ_INT(res.exit_code, -1);
}

TEST(run_feeds_stdin) {
    const char *argv[] = {"cat", NULL};
    char out[64];
    run_opts_t opts;
    run_result_t res;
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.input = "abc123";
    opts.input_len = 6;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK_STR_EQ(out, "abc123");
    CHECK_EQ_INT((long)res.out_len, 6);
}

TEST(run_zero_length_input_sends_immediate_eof) {
    CHECK(zero_length_input_finishes(""));

    /* input_len is authoritative and binary-safe: no byte may be read from an
     * arbitrary non-NULL address when the declared length is zero. */
    CHECK(zero_length_input_finishes((const char *)(uintptr_t)1));
}

TEST(run_feeds_binary_stdin_at_exact_length) {
    const char *argv[] = {"cat", NULL};
    const char input[] = {'A', '\0', 'B'};
    char out[8];
    run_opts_t opts;
    run_result_t res;

    memset(&opts, 0, sizeof(opts));
    memset(out, 0x7f, sizeof(out));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.input = input;
    opts.input_len = sizeof(input);
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK_EQ_INT((long)res.out_len, (long)sizeof(input));
    CHECK(memcmp(out, input, sizeof(input)) == 0);
    CHECK(out[sizeof(input)] == '\0');
}

TEST(run_null_input_retains_devnull_eof) {
    const char *argv[] = {"cat", NULL};
    char out[8];
    run_opts_t opts;
    run_result_t res;

    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK_EQ_INT((long)res.out_len, 0);
    CHECK_STR_EQ(out, "");
}

TEST(run_passes_extra_env) {
    const char *argv[] = {"printenv", "GITSWITCH_TEST_VAR", NULL};
    const char *env[] = {"GITSWITCH_TEST_VAR=hello_env", NULL};
    char out[64];
    run_opts_t opts;
    run_result_t res;
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.extra_env = env;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK_STR_EQ(out, "hello_env\n");
}

TEST(run_unsets_environment_before_applying_additions) {
    const char *name = "GITSWITCH_TEST_UNSET_VAR";
    const char *argv[] = {"printenv", "GITSWITCH_TEST_UNSET_VAR", NULL};
    const char *unset_env[] = {"GITSWITCH_TEST_UNSET_VAR", NULL};
    const char *extra_env[] = {"GITSWITCH_TEST_UNSET_VAR=child", NULL};
    const char *inherited = getenv(name);
    char *saved = inherited ? strdup(inherited) : NULL;
    char out[64];
    run_opts_t opts;
    run_result_t res;

    CHECK(!inherited || saved != NULL);
    if (inherited && !saved) return;
    CHECK_EQ_INT(setenv(name, "parent", 1), 0);

    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.unset_env = unset_env;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), -1);
    CHECK(res.spawned);
    CHECK_EQ_INT(res.exit_code, 1);
    CHECK_STR_EQ(out, "");
    CHECK_STR_EQ(getenv(name), "parent");

    memset(&res, 0, sizeof(res));
    opts.extra_env = extra_env;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK(res.spawned);
    CHECK_EQ_INT(res.exit_code, 0);
    CHECK_STR_EQ(out, "child\n");
    CHECK_STR_EQ(getenv(name), "parent");

    if (saved) {
        CHECK_EQ_INT(setenv(name, saved, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv(name), 0);
    }
    free(saved);
}

TEST(run_uses_pinned_child_working_directory) {
    char dir[] = "/tmp/gswrunpwd_XXXXXX";
    /* PATH_MAX: glibc's fortified realpath (__realpath_chk) aborts the whole
     * process if the destination is smaller, regardless of the actual
     * resolved length — only visible in release builds (_FORTIFY_SOURCE=2),
     * which is exactly what the AR-05 L3 CI memcheck lane now runs. */
    char canonical_dir[PATH_MAX];
    char out[512];
    char expected[512];
    char parent_before[512];
    char parent_after[512];
    const char *argv[] = {"pwd", NULL};
    run_opts_t opts;
    run_result_t res;
    int dir_fd;

    CHECK(getcwd(parent_before, sizeof(parent_before)) != NULL);
    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK(realpath(dir, canonical_dir) != NULL);
    CHECK_EQ_INT(chmod(dir, 0700), 0);
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);

    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.cwd_fd = dir_fd;
    opts.use_cwd_fd = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK(res.spawned);
    CHECK_EQ_INT(safe_snprintf(expected, sizeof(expected), "%s\n", canonical_dir), 0);
    CHECK_STR_EQ(out, expected);

    CHECK(getcwd(parent_after, sizeof(parent_after)) != NULL);
    CHECK_STR_EQ(parent_after, parent_before);
    if (dir_fd >= 0) close(dir_fd);
    CHECK_EQ_INT(rmdir(dir), 0);
}

/* A caller may legitimately begin with stdout closed, making the subsequently
 * opened directory land on fd 1.  The child must preserve that descriptor
 * before installing its stdout pipe or the pinned fchdir silently fails. */
TEST(run_preserves_pinned_cwd_when_it_collides_with_closed_stdio) {
    char dir[] = "/tmp/gswrunstdio_XXXXXX";
    char canonical_dir[PATH_MAX]; /* see run_uses_pinned_child_working_directory */
    char expected[512];
    pid_t child;
    int status = 0;

    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK(realpath(dir, canonical_dir) != NULL);
    CHECK_EQ_INT(chmod(dir, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(expected, sizeof(expected), "%s\n", canonical_dir), 0);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const char *argv[] = {"pwd", NULL};
        char out[512];
        run_opts_t opts;
        run_result_t res;
        int dir_fd;

        close(STDOUT_FILENO);
        dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir_fd != STDOUT_FILENO) _exit(2);
        memset(&opts, 0, sizeof(opts));
        opts.out = out;
        opts.out_size = sizeof(out);
        opts.cwd_fd = dir_fd;
        opts.use_cwd_fd = true;
        if (run_argv(argv, &opts, &res) != 0 || !res.spawned ||
            strcmp(out, expected) != 0) {
            _exit(3);
        }
        _exit(0);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK_EQ_INT(rmdir(dir), 0);
}

TEST(run_empty_argv_fails) {
    const char *argv[] = {NULL};
    CHECK_EQ_INT(run_argv(argv, NULL, NULL), -1);
}

/* AR-02 #4: output that exceeds the capture buffer must be REPORTED as
 * truncated, not silently capped — the GPG secret-key export feeds its
 * capture straight into `gpg --import`, where a silent cap meant importing
 * corrupt armor. */
TEST(run_reports_output_truncation) {
    const char *argv[] = {"cat", NULL};
    char big[8192];
    char out[64];
    run_opts_t opts;
    run_result_t res;

    memset(big, 'x', sizeof(big));
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.input = big;
    opts.input_len = sizeof(big);
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK(res.out_truncated);
    CHECK_EQ_INT((long)res.out_len, (long)sizeof(out) - 1);

    /* ...and a capture that fits is not flagged. */
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.input = "fits";
    opts.input_len = 4;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);
    CHECK(!res.out_truncated);
    CHECK_EQ_INT((long)res.out_len, 4);
}

/* AR-03 L21: a helper killed by a signal must be reported as death-by-signal
 * (return -1, exit_code -1, term_signal set) and never as a normal exit — a
 * regression here would let a SIGKILLed git/gpg/ssh helper read as success
 * with the suite green. */
TEST(run_reports_death_by_signal) {
    const char *argv[] = {"sh", "-c", "kill -TERM $$", NULL};
    run_result_t res;
    CHECK_EQ_INT(run_argv(argv, NULL, &res), -1);
    CHECK(res.spawned);
    CHECK_EQ_INT(res.exit_code, -1);
    CHECK_EQ_INT(res.term_signal, SIGTERM);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(run_echo_captures_stdout);
    RUN_TEST(run_false_reports_exit_1);
    RUN_TEST(run_true_succeeds);
    RUN_TEST(run_nonexistent_command_fails_without_spawn);
    RUN_TEST(run_feeds_stdin);
    RUN_TEST(run_zero_length_input_sends_immediate_eof);
    RUN_TEST(run_feeds_binary_stdin_at_exact_length);
    RUN_TEST(run_null_input_retains_devnull_eof);
    RUN_TEST(run_passes_extra_env);
    RUN_TEST(run_unsets_environment_before_applying_additions);
    RUN_TEST(run_uses_pinned_child_working_directory);
    RUN_TEST(run_preserves_pinned_cwd_when_it_collides_with_closed_stdio);
    RUN_TEST(run_empty_argv_fails);
    RUN_TEST(run_reports_output_truncation);
    RUN_TEST(run_reports_death_by_signal);
    RUN_TEST(run_rejects_ignored_sigchld_before_spawn);
    RUN_TEST(run_rejects_nocldwait_sigchld_before_spawn);
    RUN_TEST(run_rejects_foreign_sigchld_reaper_before_spawn);
    RUN_TEST(run_publishes_child_before_releasing_blocked_rollback_signal);
    RUN_TEST(run_restores_exact_mask_and_errno_when_fork_fails);
TEST_MAIN_END()
