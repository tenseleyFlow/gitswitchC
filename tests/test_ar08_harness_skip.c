#define _GNU_SOURCE
#include "test.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CHILD_OUTPUT_MAX 16384

typedef struct {
    int exit_code;
    char output[CHILD_OUTPUT_MAX];
} child_result_t;

static char g_self_path[4096];

TEST(child_passes) {
    CHECK(1);
}

TEST(child_skips_fish) {
    TS_SKIP("fish", "fish is unavailable in this fixture");
}

TEST(child_skips_sh) {
    TS_SKIP("sh", "sh is unavailable in this fixture");
}

TEST(child_fails) {
    CHECK(0);
}

TEST(child_fails_then_requests_skip) {
    CHECK(0);
    TS_SKIP("fish", "failure must remain authoritative");
}

static int run_child_scenario(const char *scenario) {
    if (strcmp(scenario, "pass") == 0) {
        RUN_TEST(child_passes);
    } else if (strcmp(scenario, "skip-fish") == 0) {
        RUN_TEST(child_skips_fish);
    } else if (strcmp(scenario, "skip-sh") == 0) {
        RUN_TEST(child_skips_sh);
    } else if (strcmp(scenario, "fail-then-skip") == 0) {
        RUN_TEST(child_fails_then_requests_skip);
    } else if (strcmp(scenario, "mixed") == 0) {
        RUN_TEST(child_passes);
        RUN_TEST(child_skips_sh);
        RUN_TEST(child_fails);
    } else {
        fprintf(stderr, "unknown child scenario: %s\n", scenario);
        return 2;
    }
    return ts_test_finish();
}

static int capture_scenario(const char *scenario, const char *required_caps,
                            child_result_t *result) {
    if (!scenario || !result) {
        errno = EINVAL;
        return -1;
    }

    int output_pipe[2];
    if (pipe(output_pipe) != 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(output_pipe[0]);
        close(output_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    if (child == 0) {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0) {
            _exit(125);
        }
        if (output_pipe[1] != STDOUT_FILENO &&
            output_pipe[1] != STDERR_FILENO) {
            close(output_pipe[1]);
        }
        int env_result = required_caps
                             ? setenv("GITSWITCH_TEST_REQUIRED_CAPS",
                                      required_caps, 1)
                             : unsetenv("GITSWITCH_TEST_REQUIRED_CAPS");
        if (env_result != 0) _exit(125);
        execl(g_self_path, g_self_path, "--child", scenario, (char *)NULL);
        _exit(125);
    }

    close(output_pipe[1]);
    size_t used = 0;
    int read_error = 0;
    for (;;) {
        char discard[512];
        char *destination = used + 1 < sizeof(result->output)
                                ? result->output + used
                                : discard;
        size_t capacity = used + 1 < sizeof(result->output)
                              ? sizeof(result->output) - used - 1
                              : sizeof(discard);
        ssize_t count = read(output_pipe[0], destination, capacity);
        if (count > 0) {
            if (destination != discard) used += (size_t)count;
            else read_error = EOVERFLOW;
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        read_error = errno;
        break;
    }
    close(output_pipe[0]);
    result->output[used] = '\0';

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) return -1;
    if (read_error != 0) {
        errno = read_error;
        return -1;
    }
    result->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return 0;
}

static bool output_contains(const child_result_t *result,
                            const char *expected) {
    return result && expected && strstr(result->output, expected) != NULL;
}

TEST(optional_skip_is_visible_and_successful) {
    child_result_t result;
    int captured = capture_scenario("skip-fish", NULL, &result);
    CHECK_EQ_INT(captured, 0);
    if (captured != 0) return;

    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(output_contains(
        &result,
        "[SKIP] child_skips_fish (fish: fish is unavailable in this fixture)"));
    CHECK(output_contains(
        &result,
        "RESULT OK: 1 run, 0 passed, 0 failed, 1 skipped"));
}

TEST(required_skip_fails_the_suite_without_double_counting) {
    child_result_t result;
    int captured = capture_scenario("skip-fish", "fish", &result);
    CHECK_EQ_INT(captured, 0);
    if (captured != 0) return;

    CHECK(result.exit_code != 0);
    CHECK(output_contains(
        &result,
        "HARNESS FAIL: required capability skipped: fish"));
    CHECK(output_contains(
        &result,
        "RESULT FAIL: 1 run, 0 passed, 0 failed, 1 skipped"));
}

TEST(required_capabilities_use_exact_token_matching) {
    child_result_t result;
    int captured = capture_scenario("skip-sh", "fish", &result);
    CHECK_EQ_INT(captured, 0);
    if (captured != 0) return;

    CHECK_EQ_INT(result.exit_code, 0);
    CHECK(!output_contains(
        &result,
        "HARNESS FAIL: required capability skipped"));
    CHECK(output_contains(
        &result,
        "RESULT OK: 1 run, 0 passed, 0 failed, 1 skipped"));
}

TEST(unknown_and_malformed_policy_values_fail_closed) {
    child_result_t unknown;
    child_result_t malformed;
    int unknown_captured =
        capture_scenario("pass", "not-a-capability", &unknown);
    int malformed_captured =
        capture_scenario("pass", "fish,,sh", &malformed);
    CHECK_EQ_INT(unknown_captured, 0);
    CHECK_EQ_INT(malformed_captured, 0);
    if (unknown_captured != 0 || malformed_captured != 0) return;

    CHECK(unknown.exit_code != 0);
    CHECK(malformed.exit_code != 0);
    CHECK(output_contains(
        &unknown,
        "HARNESS FAIL: invalid GITSWITCH_TEST_REQUIRED_CAPS"));
    CHECK(output_contains(
        &malformed,
        "HARNESS FAIL: invalid GITSWITCH_TEST_REQUIRED_CAPS"));
    CHECK(output_contains(
        &unknown,
        "RESULT FAIL: 1 run, 1 passed, 0 failed, 0 skipped"));
    CHECK(output_contains(
        &malformed,
        "RESULT FAIL: 1 run, 1 passed, 0 failed, 0 skipped"));
}

TEST(test_failure_takes_precedence_over_a_later_skip) {
    child_result_t result;
    int captured = capture_scenario("fail-then-skip", NULL, &result);
    CHECK_EQ_INT(captured, 0);
    if (captured != 0) return;

    CHECK(result.exit_code != 0);
    CHECK(output_contains(&result, "[FAIL] child_fails_then_requests_skip"));
    CHECK(!output_contains(&result, "[SKIP] child_fails_then_requests_skip"));
    CHECK(output_contains(
        &result,
        "RESULT FAIL: 1 run, 0 passed, 1 failed, 0 skipped"));
}

TEST(summary_partitions_every_run_into_one_terminal_state) {
    child_result_t result;
    int captured = capture_scenario("mixed", NULL, &result);
    CHECK_EQ_INT(captured, 0);
    if (captured != 0) return;

    CHECK(result.exit_code != 0);
    CHECK(output_contains(
        &result,
        "RESULT FAIL: 3 run, 1 passed, 1 failed, 1 skipped"));
    CHECK(!output_contains(
        &result,
        "HARNESS FAIL: test accounting invariant violated"));
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--child") == 0) {
        return run_child_scenario(argv[2]);
    }
    if (argc != 1 || !realpath(argv[0], g_self_path)) {
        fprintf(stderr, "RESULT FAIL: cannot resolve harness test binary\n");
        return 1;
    }

    RUN_TEST(optional_skip_is_visible_and_successful);
    RUN_TEST(required_skip_fails_the_suite_without_double_counting);
    RUN_TEST(required_capabilities_use_exact_token_matching);
    RUN_TEST(unknown_and_malformed_policy_values_fail_closed);
    RUN_TEST(test_failure_takes_precedence_over_a_later_skip);
    RUN_TEST(summary_partitions_every_run_into_one_terminal_state);
    return ts_test_finish();
}
