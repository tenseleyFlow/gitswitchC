/* AR-07 M24/M25/M27: exact, fail-closed, retryable Git rollback snapshots. */
#include "test.h"
#include "git_ops.h"
#include "utils.h"
#include "error.h"

#include <string.h>

void git_ops_test_reset_caches(void);

#define LIST_CAP 65536
#define LOG_CAP 64

static char g_direct[LIST_CAP];
static char g_expanded[LIST_CAP];
static size_t g_direct_len;
static size_t g_expanded_len;
static bool g_fail_lists;
static int g_fail_lists_remaining;
static bool g_fail_list_reports_error;
typedef enum {
    LIST_ERROR_NONE = 0,
    LIST_ERROR_MISSING,
    LIST_ERROR_PERMISSION
} list_error_t;
static list_error_t g_list_error;
static bool g_always_truncate;
static int g_list_calls;
static int g_mutations;
static int g_fail_add_once;
static const char *g_fail_add_key;
static const char *g_fail_add_value;
static char g_add_key[LOG_CAP][64];
static char g_add_value[LOG_CAP][256];
static int g_adds;
static char g_unset_key[LOG_CAP][64];
static int g_unsets;
static const char *g_large_expected;
static bool g_large_restored;

static const char *const managed_keys[] = {
    "user.name", "user.email", "user.signingkey", "commit.gpgsign",
    "gpg.program", "core.sshcommand", "gpg.format",
    "gpg.openpgp.program", "gpg.x509.program", "gpg.ssh.program"
};
#define MANAGED_KEY_COUNT (sizeof(managed_keys) / sizeof(managed_keys[0]))

static int fake_ret(run_result_t *result, int code) {
    if (result) {
        result->spawned = true;
        result->exit_code = code;
        result->term_signal = 0;
    }
    return code == 0 ? 0 : -1;
}

static bool append_record(char *buf, size_t *used, const char *key,
                          const char *value) {
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    if (*used + key_len + value_len + 2U > LIST_CAP) return false;
    memcpy(buf + *used, key, key_len);
    *used += key_len;
    buf[(*used)++] = '\n';
    memcpy(buf + *used, value, value_len);
    *used += value_len;
    buf[(*used)++] = '\0';
    return true;
}

static void fixture_reset(void) {
    git_ops_test_reset_caches();
    memset(g_direct, 0, sizeof(g_direct));
    memset(g_expanded, 0, sizeof(g_expanded));
    g_direct_len = g_expanded_len = 0;
    g_fail_lists = false;
    g_fail_lists_remaining = 0;
    g_fail_list_reports_error = false;
    g_list_error = LIST_ERROR_NONE;
    g_always_truncate = false;
    g_list_calls = g_mutations = 0;
    g_fail_add_once = 0;
    g_fail_add_key = g_fail_add_value = NULL;
    g_adds = g_unsets = 0;
    g_large_expected = NULL;
    g_large_restored = false;
    memset(g_add_key, 0, sizeof(g_add_key));
    memset(g_add_value, 0, sizeof(g_add_value));
    memset(g_unset_key, 0, sizeof(g_unset_key));
}

static bool is_list(const char *const argv[]) {
    return argv[0] && argv[1] && argv[2] && argv[3] && argv[4] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[3], "--list") == 0 && strcmp(argv[4], "-z") == 0;
}

static int fake_list_error(const run_opts_t *opts, run_result_t *result,
                           const char *message) {
    size_t message_len = strlen(message);
    size_t copied = 0;

    if (opts && opts->out && opts->out_size > 0) {
        copied = message_len;
        if (copied >= opts->out_size) copied = opts->out_size - 1U;
        memcpy(opts->out, message, copied);
        opts->out[copied] = '\0';
    }
    if (result) {
        result->out_len = copied;
        result->out_truncated = copied != message_len;
    }
    return fake_ret(result, 128);
}

static int snapshot_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (result) memset(result, 0, sizeof(*result));
    if (argv[0] && argv[1] && strcmp(argv[0], "git") == 0 &&
        strcmp(argv[1], "rev-parse") == 0) {
        return fake_ret(result, 1); /* no repo: global snapshot only */
    }
    if (is_list(argv)) {
        const char *src;
        size_t src_len;
        size_t copied;

        g_list_calls++;
        if (g_fail_lists || g_fail_lists_remaining > 0) {
            if (g_fail_lists_remaining > 0) g_fail_lists_remaining--;
            if (g_fail_list_reports_error) {
                errno = EPERM;
                set_system_error(ERR_SYSTEM_CALL,
                                 "injected snapshot runner failure");
            }
            return fake_ret(result, 2);
        }
        if (g_list_error == LIST_ERROR_MISSING) {
            return fake_list_error(
                opts, result,
                "fatal: unable to read config file '/home/test/.gitconfig': No such file or directory\n");
        }
        if (g_list_error == LIST_ERROR_PERMISSION) {
            return fake_list_error(
                opts, result,
                "fatal: unable to read config file '/home/test/.gitconfig': Permission denied\n");
        }
        src = (argv[5] && strcmp(argv[5], "--includes") == 0)
                  ? g_expanded : g_direct;
        src_len = (src == g_expanded) ? g_expanded_len : g_direct_len;
        if (!opts || !opts->out || opts->out_size == 0)
            return fake_ret(result, 2);
        copied = src_len;
        if (copied >= opts->out_size) copied = opts->out_size - 1U;
        if (copied) memcpy(opts->out, src, copied);
        opts->out[copied] = '\0';
        if (result) {
            result->out_len = copied;
            result->out_truncated = g_always_truncate || copied != src_len;
        }
        return fake_ret(result, 0);
    }
    if (argv[0] && argv[1] && argv[2] && argv[3] && argv[4] &&
        strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[3], "--unset-all") == 0) {
        g_mutations++;
        if (g_unsets < LOG_CAP)
            snprintf(g_unset_key[g_unsets], sizeof(g_unset_key[0]), "%s",
                     argv[4]);
        g_unsets++;
        return fake_ret(result, 0);
    }
    if (argv[0] && argv[1] && argv[2] && argv[3] && argv[4] && argv[5] &&
        strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[3], "--add") == 0) {
        g_mutations++;
        if (g_fail_add_once && strcmp(argv[4], g_fail_add_key) == 0 &&
            strcmp(argv[5], g_fail_add_value) == 0) {
            g_fail_add_once = 0;
            return fake_ret(result, 1);
        }
        if (g_large_expected && strcmp(argv[4], "core.sshcommand") == 0 &&
            strcmp(argv[5], g_large_expected) == 0) {
            g_large_restored = true;
        }
        if (g_adds < LOG_CAP) {
            snprintf(g_add_key[g_adds], sizeof(g_add_key[0]), "%s", argv[4]);
            snprintf(g_add_value[g_adds], sizeof(g_add_value[0]), "%s", argv[5]);
        }
        g_adds++;
        return fake_ret(result, 0);
    }
    return fake_ret(result, 1);
}

TEST(dynamic_snapshot_restores_value_beyond_initial_capture) {
    static char large[24000];
    memset(large, 'x', sizeof(large) - 1U);
    large[sizeof(large) - 1U] = '\0';
    memcpy(large, "ssh -i /", 8);
    fixture_reset();
    CHECK(append_record(g_direct, &g_direct_len, "core.sshcommand", large));
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    g_large_expected = large;
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK(g_list_calls >= 4); /* direct and expanded each grow at least once */
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK(g_large_restored);

    run_set_runner(previous);
}

TEST(snapshot_read_and_oversize_fail_before_mutation) {
    fixture_reset();
    command_runner_fn previous = run_set_runner(snapshot_runner);
    g_fail_lists = true;
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(g_mutations, 0);
    CHECK(strstr(get_last_error()->message, "includes=off") != NULL);
    CHECK(strstr(get_last_error()->message, "spawned=1") != NULL);
    CHECK(strstr(get_last_error()->message, "exit=2") != NULL);
    CHECK(strstr(get_last_error()->message, "runner=none") != NULL);
    CHECK_EQ_INT(g_list_calls, 2); /* one retry, then fail closed */

    fixture_reset();
    g_always_truncate = true;
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK(g_list_calls > 1);
    CHECK_EQ_INT(g_mutations, 0);
    run_set_runner(previous);
}

TEST(one_empty_snapshot_read_failure_is_retried_observationally) {
    fixture_reset();
    g_fail_lists_remaining = 1;
    g_fail_list_reports_error = true;
    command_runner_fn previous = run_set_runner(snapshot_runner);
    set_error(ERR_UNKNOWN, "retained caller diagnostic");
    uint64_t error_generation = error_report_generation();

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(g_list_calls, 3); /* failed direct, retry, expanded */
    CHECK_EQ_INT(g_mutations, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_UNKNOWN);
    CHECK_STR_EQ(get_last_error()->message, "retained caller diagnostic");
    CHECK_EQ_INT(error_report_generation(), error_generation);

    clear_error();
    run_set_runner(previous);
}

TEST(missing_scope_file_is_an_exact_empty_snapshot) {
    fixture_reset();
    g_list_error = LIST_ERROR_MISSING;
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(g_list_calls, 2); /* direct and include-expanded emptiness */
    CHECK_EQ_INT(g_mutations, 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(g_unsets, MANAGED_KEY_COUNT);
    CHECK_EQ_INT(g_adds, 0);

    run_set_runner(previous);
}

TEST(non_enoent_scope_failure_is_refused_before_mutation) {
    fixture_reset();
    g_list_error = LIST_ERROR_PERMISSION;
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(g_list_calls, 1);
    CHECK_EQ_INT(g_mutations, 0);

    run_set_runner(previous);
}

TEST(included_managed_value_is_refused_before_mutation) {
    fixture_reset();
    CHECK(append_record(g_direct, &g_direct_len, "user.name", "direct"));
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    CHECK(append_record(g_expanded, &g_expanded_len, "user.name", "included"));
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(g_mutations, 0);
    run_set_runner(previous);
}

TEST(implicit_managed_boolean_is_refused_before_mutation) {
    static const char implicit[] = "commit.gpgsign\0";
    fixture_reset();
    memcpy(g_direct, implicit, sizeof(implicit) - 1U);
    g_direct_len = sizeof(implicit) - 1U;
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(g_mutations, 0);
    run_set_runner(previous);
}

TEST(multivalue_restore_preserves_every_key_count_and_order) {
    fixture_reset();
    for (size_t i = 0; i < sizeof(managed_keys) / sizeof(managed_keys[0]); i++) {
        char first[64];
        char second[64];
        snprintf(first, sizeof(first), "first-%zu\nline", i);
        snprintf(second, sizeof(second), " second-%zu ", i);
        CHECK(append_record(g_direct, &g_direct_len, managed_keys[i], first));
        CHECK(append_record(g_direct, &g_direct_len, managed_keys[i], second));
    }
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(g_unsets, MANAGED_KEY_COUNT);
    CHECK_EQ_INT(g_adds, MANAGED_KEY_COUNT * 2U);
    for (size_t i = 0; i < MANAGED_KEY_COUNT; i++) {
        char first[64];
        char second[64];
        snprintf(first, sizeof(first), "first-%zu\nline", i);
        snprintf(second, sizeof(second), " second-%zu ", i);
        CHECK_STR_EQ(g_add_key[i * 2], managed_keys[i]);
        CHECK_STR_EQ(g_add_value[i * 2], first);
        CHECK_STR_EQ(g_add_key[i * 2 + 1], managed_keys[i]);
        CHECK_STR_EQ(g_add_value[i * 2 + 1], second);
    }
    run_set_runner(previous);
}

TEST(failed_restore_retains_snapshot_and_retries_only_incomplete_key) {
    fixture_reset();
    CHECK(append_record(g_direct, &g_direct_len, "user.name", "old name"));
    CHECK(append_record(g_direct, &g_direct_len, "user.email", "first@old"));
    CHECK(append_record(g_direct, &g_direct_len, "user.email", "second@old"));
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    g_fail_add_once = 1;
    g_fail_add_key = "user.email";
    g_fail_add_value = "second@old";
    command_runner_fn previous = run_set_runner(snapshot_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    {
        int list_calls = g_list_calls;
        CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
        CHECK_EQ_INT(g_list_calls, list_calls);
    }
    /* The failed second --add left the exact transaction-owned prefix in the
     * real config. Reflect that state in the fake listing: retry is permitted
     * only while the vector still equals this recorded progress. */
    memset(g_direct, 0, sizeof(g_direct));
    g_direct_len = 0;
    CHECK(append_record(g_direct, &g_direct_len,
                        "user.email", "first@old"));
    memcpy(g_expanded, g_direct, g_direct_len);
    g_expanded_len = g_direct_len;
    CHECK_EQ_INT(git_config_restore(), 0);
    /* user.name completed once; failed user.email was force-cleared/replayed. */
    CHECK_STR_EQ(g_unset_key[0], "user.name");
    CHECK_STR_EQ(g_unset_key[1], "user.email");
    CHECK_STR_EQ(g_unset_key[MANAGED_KEY_COUNT], "user.email");
    CHECK_EQ_INT(g_unsets, MANAGED_KEY_COUNT + 1U);
    CHECK_EQ_INT(git_config_restore(), 0); /* consumed only after exact success */
    CHECK_EQ_INT(g_unsets, MANAGED_KEY_COUNT + 1U);
    run_set_runner(previous);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(dynamic_snapshot_restores_value_beyond_initial_capture);
    RUN_TEST(snapshot_read_and_oversize_fail_before_mutation);
    RUN_TEST(one_empty_snapshot_read_failure_is_retried_observationally);
    RUN_TEST(missing_scope_file_is_an_exact_empty_snapshot);
    RUN_TEST(non_enoent_scope_failure_is_refused_before_mutation);
    RUN_TEST(included_managed_value_is_refused_before_mutation);
    RUN_TEST(implicit_managed_boolean_is_refused_before_mutation);
    RUN_TEST(multivalue_restore_preserves_every_key_count_and_order);
    RUN_TEST(failed_restore_retains_snapshot_and_retries_only_incomplete_key);
TEST_MAIN_END()
