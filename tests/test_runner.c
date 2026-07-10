/* Tests for the shell-free subprocess runner (run_argv). */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

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
    RUN_TEST(run_empty_argv_fails);
    RUN_TEST(run_reports_output_truncation);
    RUN_TEST(run_reports_death_by_signal);
TEST_MAIN_END()
