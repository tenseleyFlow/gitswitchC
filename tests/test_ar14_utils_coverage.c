/* AR-14 coverage recovery for stable public utility contracts.
 *
 * These helpers predate the current campaign but had no behavioral execution
 * in the accumulated coverage lane. Keep the assertions portable: fixtures
 * live below harness-owned temporary directories, environment changes are
 * restored, and memory-lock tests cover validation without depending on host
 * resource limits or privileges. */
#include "test.h"

#include "error.h"
#include "gitswitch.h"
#include "utils.h"

#include <limits.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    char *value;
    bool present;
} saved_env_t;

static bool save_env(const char *name, saved_env_t *saved) {
    const char *value = getenv(name);

    memset(saved, 0, sizeof(*saved));
    if (!value) return true;
    saved->value = strdup(value);
    if (!saved->value) return false;
    saved->present = true;
    return true;
}

static bool restore_env(const char *name, saved_env_t *saved) {
    int rc = saved->present ? setenv(name, saved->value, 1)
                            : unsetenv(name);
    free(saved->value);
    memset(saved, 0, sizeof(*saved));
    return rc == 0;
}

static bool make_regular_file(const char *path, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) return false;
    if (write(fd, "x", 1) != 1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return false;
    }
    return close(fd) == 0;
}

static bool read_text_file(const char *path, char *text, size_t text_size) {
    size_t used = 0U;
    int fd;

    if (!path || !text || text_size == 0U) return false;
    text[0] = '\0';
    fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    while (used + 1U < text_size) {
        ssize_t count = read(fd, text + used, text_size - used - 1U);

        if (count > 0) {
            used += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            close(fd);
            return false;
        }
    }
    text[used] = '\0';
    return close(fd) == 0;
}

TEST(process_liveness_rejects_invalid_pid_and_accepts_self) {
    CHECK(!process_is_running(0));
    CHECK(!process_is_running(-1));
    CHECK(process_is_running(getpid()));
}

TEST(environment_helpers_round_trip_and_honor_overwrite) {
    static const char name[] = "GITSWITCH_TEST_AR14_UTIL_ENV";
    char value[32];

    CHECK_EQ_INT(unsetenv(name), 0);
    CHECK_EQ_INT(get_env_var(name, value, sizeof(value)), 1);
    CHECK_STR_EQ(value, "");

    CHECK_EQ_INT(set_env_var(name, "first", true), 0);
    CHECK_EQ_INT(set_env_var(name, "second", false), 0);
    CHECK_EQ_INT(get_env_var(name, value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "first");

    CHECK_EQ_INT(set_env_var(name, "second", true), 0);
    CHECK_EQ_INT(get_env_var(name, value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "second");
    CHECK_EQ_INT(unset_env_var(name), 0);
    CHECK(getenv(name) == NULL);
}

TEST(environment_helpers_reject_invalid_arguments_and_small_buffers) {
    char byte = 'x';

    CHECK_EQ_INT(get_env_var(NULL, &byte, 1), -1);
    CHECK_EQ_INT(get_env_var("PATH", NULL, 1), -1);
    CHECK_EQ_INT(get_env_var("PATH", &byte, 0), -1);
    CHECK_EQ_INT(set_env_var(NULL, "x", true), -1);
    CHECK_EQ_INT(set_env_var("X", NULL, true), -1);
    CHECK_EQ_INT(unset_env_var(NULL), -1);

    CHECK_EQ_INT(setenv("GITSWITCH_TEST_AR14_UTIL_LONG", "long", 1), 0);
    CHECK_EQ_INT(get_env_var("GITSWITCH_TEST_AR14_UTIL_LONG", &byte, 1), -1);
    CHECK_EQ_INT(unsetenv("GITSWITCH_TEST_AR14_UTIL_LONG"), 0);

    CHECK_EQ_INT(set_env_var("", "x", true), -1);
    CHECK_EQ_INT(unset_env_var(""), -1);
}

TEST(string_helpers_cover_null_empty_case_and_boundary_contracts) {
    char blank[] = " \t\n ";
    char empty[] = "";
    char padded[] = "\t Alpha Beta \n";

    CHECK(trim_whitespace(NULL) == NULL);
    CHECK_STR_EQ(trim_whitespace(empty), "");
    CHECK_STR_EQ(trim_whitespace(blank), "");
    CHECK_STR_EQ(trim_whitespace(padded), "Alpha Beta");

    CHECK(string_empty(NULL));
    CHECK(string_empty(""));
    CHECK(!string_empty("value"));

    CHECK(string_equals(NULL, NULL));
    CHECK(!string_equals(NULL, "value"));
    CHECK(!string_equals("value", NULL));
    CHECK(string_equals("value", "value"));
    CHECK(!string_equals("value", "other"));

    CHECK(string_ascii_case_equal(NULL, NULL));
    CHECK(!string_ascii_case_equal(NULL, "alpha"));
    CHECK(!string_ascii_case_equal("alpha", NULL));
    CHECK(string_ascii_case_equal("", ""));
    CHECK(string_ascii_case_equal("Alpha-Z", "aLPHA-z"));
    CHECK(!string_ascii_case_equal("alpha", "alph"));
    CHECK(!string_ascii_case_equal("alph", "alpha"));
    CHECK(!string_ascii_case_equal("alpha", "alpHa!"));

    CHECK(!string_starts_with(NULL, "prefix"));
    CHECK(!string_starts_with("prefix", NULL));
    CHECK(string_starts_with("prefix-value", ""));
    CHECK(string_starts_with("prefix-value", "prefix"));
    CHECK(!string_starts_with("prefix-value", "value"));

    CHECK(!string_ends_with(NULL, "suffix"));
    CHECK(!string_ends_with("suffix", NULL));
    CHECK(string_ends_with("value-suffix", ""));
    CHECK(string_ends_with("value-suffix", "suffix"));
    CHECK(!string_ends_with("short", "longer-suffix"));
    CHECK(!string_ends_with("value-suffix", "value"));
}

TEST(string_replace_reports_invalid_missing_overflow_and_success) {
    char unchanged[32] = "alpha beta";
    char overflow[8] = "alpha";
    char shorter[32] = "alpha beta";
    char longer[32] = "alpha beta";

    CHECK_EQ_INT(string_replace(NULL, 0, "alpha", "beta"), -1);
    CHECK_EQ_INT(string_replace(unchanged, sizeof(unchanged), NULL, "beta"),
                 -1);
    CHECK_EQ_INT(string_replace(unchanged, sizeof(unchanged), "alpha", NULL),
                 -1);
    CHECK_EQ_INT(string_replace(unchanged, sizeof(unchanged), "missing", "x"),
                 0);
    CHECK_STR_EQ(unchanged, "alpha beta");

    CHECK_EQ_INT(string_replace(overflow, sizeof(overflow), "alpha",
                                "overflow"), -1);
    CHECK_STR_EQ(overflow, "alpha");

    CHECK_EQ_INT(string_replace(shorter, sizeof(shorter), "alpha", "a"), 1);
    CHECK_STR_EQ(shorter, "a beta");
    CHECK_EQ_INT(string_replace(longer, sizeof(longer), "beta",
                                "longer-value"), 1);
    CHECK_STR_EQ(longer, "alpha longer-value");
}

TEST(path_helpers_cover_tilde_separators_types_and_bounds) {
    char root[] = "/tmp/gitswitch-ar14-utils-path-XXXXXX";
    char regular[MAX_PATH_LEN];
    char missing[MAX_PATH_LEN];
    char expanded[MAX_PATH_LEN];
    char joined[MAX_PATH_LEN];
    char tiny[4] = "";
    saved_env_t saved_home;
    bool environment_saved = save_env("HOME", &saved_home);

    CHECK(environment_saved);
    if (!environment_saved) return;
    if (!ts_mkdtemp(root)) {
        CHECK(!"failed to create isolated path fixture");
        CHECK(restore_env("HOME", &saved_home));
        return;
    }
    CHECK_EQ_INT(safe_snprintf(regular, sizeof(regular), "%s/value", root), 0);
    CHECK_EQ_INT(safe_snprintf(missing, sizeof(missing), "%s/missing", root),
                 0);
    CHECK(make_regular_file(regular, 0600));
    CHECK_EQ_INT(setenv("HOME", root, 1), 0);

    CHECK_EQ_INT(expand_path(NULL, expanded, sizeof(expanded)), -1);
    CHECK_EQ_INT(expand_path("/value", NULL, sizeof(expanded)), -1);
    CHECK_EQ_INT(expand_path("/value", expanded, 0), -1);
    CHECK_EQ_INT(expand_path("~someone/value", expanded, sizeof(expanded)),
                 -1);
    CHECK_EQ_INT(expand_path("~", expanded, sizeof(expanded)), 0);
    CHECK_EQ_INT(safe_snprintf(joined, sizeof(joined), "%s/", root), 0);
    CHECK_STR_EQ(expanded, joined);
    CHECK_EQ_INT(expand_path("~/value", expanded, sizeof(expanded)), 0);
    CHECK_STR_EQ(expanded, regular);
    CHECK_EQ_INT(expand_path("/value", tiny, sizeof(tiny)), -1);
    CHECK_EQ_INT(expand_path("/value", expanded, sizeof(expanded)), 0);
    CHECK_STR_EQ(expanded, "/value");
    CHECK_EQ_INT(get_home_directory(tiny, sizeof(tiny)), -1);

    CHECK_EQ_INT(join_path(NULL, sizeof(joined), root, "value"), -1);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), NULL, "value"), -1);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), root, NULL), -1);
    CHECK_EQ_INT(join_path(joined, 0, root, "value"), -1);
    CHECK_EQ_INT(join_path(tiny, sizeof(tiny), root, "value"), -1);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), root, "value"), 0);
    CHECK_STR_EQ(joined, regular);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), root, "/value"), 0);
    CHECK_STR_EQ(joined, regular);
    CHECK_EQ_INT(safe_snprintf(expanded, sizeof(expanded), "%s/", root), 0);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), expanded, "value"), 0);
    CHECK_STR_EQ(joined, regular);
    CHECK_EQ_INT(join_path(joined, sizeof(joined), "", "value"), 0);
    CHECK_STR_EQ(joined, "value");

    CHECK(!path_exists(NULL));
    CHECK(path_exists(root));
    CHECK(path_exists(regular));
    CHECK(!path_exists(missing));
    CHECK(!is_directory(NULL));
    CHECK(is_directory(root));
    CHECK(!is_directory(regular));
    CHECK(!is_directory(missing));
    CHECK(!is_regular_file(NULL));
    CHECK(!is_regular_file(root));
    CHECK(is_regular_file(regular));
    CHECK(!is_regular_file(missing));
    CHECK(restore_env("HOME", &saved_home));
}

TEST(file_validation_distinguishes_existing_missing_and_invalid_paths) {
    char root[] = "/tmp/gitswitch-ar14-utils-file-XXXXXX";
    char file[MAX_PATH_LEN];
    char missing[MAX_PATH_LEN];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(safe_snprintf(file, sizeof(file), "%s/value", root), 0);
    CHECK_EQ_INT(safe_snprintf(missing, sizeof(missing), "%s/missing", root),
                 0);
    CHECK(make_regular_file(file, 0600));

    CHECK(validate_file_path(file));
    CHECK(!validate_file_path(missing));
    CHECK(!validate_file_path(NULL));
    CHECK(!validate_file_path(""));
}

TEST(permission_validation_requires_the_exact_requested_mode) {
    char root[] = "/tmp/gitswitch-ar14-utils-mode-XXXXXX";
    char file[MAX_PATH_LEN];
    char missing[MAX_PATH_LEN];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(safe_snprintf(file, sizeof(file), "%s/value", root), 0);
    CHECK_EQ_INT(safe_snprintf(missing, sizeof(missing), "%s/missing", root),
                 0);
    CHECK(make_regular_file(file, 0600));

    CHECK(check_file_permissions_safe(file, 0600));
    CHECK(!check_file_permissions_safe(file, 0644));
    CHECK(!check_file_permissions_safe(missing, 0600));
    CHECK(!check_file_permissions_safe(NULL, 0600));
}

TEST(config_directory_creation_is_isolated_and_idempotent) {
    char home[] = "/tmp/gitswitch-ar14-utils-home-XXXXXX";
    char config_dir[MAX_PATH_LEN];
    char expected[MAX_PATH_LEN];
    saved_env_t saved_home;
    bool environment_saved = save_env("HOME", &saved_home);

    CHECK(environment_saved);
    if (!environment_saved) return;
    if (!ts_mkdtemp(home)) {
        CHECK(!"failed to create isolated HOME");
        CHECK(restore_env("HOME", &saved_home));
        return;
    }
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(get_config_directory(config_dir, sizeof(config_dir)), 0);
    CHECK_EQ_INT(safe_snprintf(expected, sizeof(expected), "%s/%s", home,
                               DEFAULT_CONFIG_DIR), 0);
    CHECK_STR_EQ(config_dir, expected);

    CHECK(!is_directory(expected));
    CHECK_EQ_INT(ensure_config_directory_exists(), 0);
    CHECK(is_directory(expected));
    CHECK_EQ_INT(ensure_config_directory_exists(), 0);
    CHECK(is_directory(expected));
    CHECK(restore_env("HOME", &saved_home));
}

TEST(time_helpers_publish_bounded_nonempty_values) {
    char current[64] = "";
    char timestamp[64] = "";
    char *end = NULL;
    long parsed;

    get_current_time_string(NULL, sizeof(current));
    get_current_time_string(current, 0);
    get_current_time_string(current, sizeof(current));
    CHECK(current[0] != '\0');
    CHECK(strlen(current) < sizeof(current));

    get_timestamp_string(NULL, sizeof(timestamp));
    get_timestamp_string(timestamp, 0);
    get_timestamp_string(timestamp, sizeof(timestamp));
    errno = 0;
    parsed = strtol(timestamp, &end, 10);
    CHECK(errno == 0);
    CHECK(end && *end == '\0');
    CHECK(parsed > 0);
}

TEST(timestamp_expiry_respects_age_boundary_direction) {
    time_t now = time(NULL);

    CHECK(is_timestamp_expired(now - 10, 1));
    CHECK(!is_timestamp_expired(now, 60));
}

static void initialize_account(account_t *account, uint32_t id,
                               const char *name, const char *description,
                               const char *email) {
    memset(account, 0, sizeof(*account));
    account->id = id;
    CHECK_EQ_INT(safe_strncpy(account->name, name,
                              sizeof(account->name)), 0);
    CHECK_EQ_INT(safe_strncpy(account->description, description,
                              sizeof(account->description)), 0);
    CHECK_EQ_INT(safe_strncpy(account->email, email,
                              sizeof(account->email)), 0);
}

TEST(comparison_helpers_define_id_name_and_string_ordering) {
    account_t low;
    account_t high;
    const char *alpha = "alpha";
    const char *beta = "beta";

    initialize_account(&low, 1, "alpha", "", "a@example.com");
    initialize_account(&high, 2, "beta", "", "b@example.com");
    CHECK(compare_accounts_by_id(&low, &high) < 0);
    CHECK(compare_accounts_by_id(&high, &low) > 0);
    CHECK_EQ_INT(compare_accounts_by_id(&low, &low), 0);
    CHECK(compare_accounts_by_name(&low, &high) < 0);
    CHECK(compare_accounts_by_name(&high, &low) > 0);
    CHECK(compare_strings(&alpha, &beta) < 0);
    CHECK(compare_strings(&beta, &alpha) > 0);
}

TEST(account_sorting_orders_multiple_accounts_and_ignores_noops) {
    account_t accounts[3];

    initialize_account(&accounts[0], 30, "charlie", "", "c@example.com");
    initialize_account(&accounts[1], 10, "alpha", "", "a@example.com");
    initialize_account(&accounts[2], 20, "beta", "", "b@example.com");

    sort_accounts(NULL, 3, compare_accounts_by_id);
    sort_accounts(accounts, 1, compare_accounts_by_id);
    sort_accounts(accounts, 3, NULL);
    CHECK_EQ_INT(accounts[0].id, 30);

    sort_accounts(accounts, 3, compare_accounts_by_id);
    CHECK_EQ_INT(accounts[0].id, 10);
    CHECK_EQ_INT(accounts[1].id, 20);
    CHECK_EQ_INT(accounts[2].id, 30);

    sort_accounts(accounts, 3, compare_accounts_by_name);
    CHECK_STR_EQ(accounts[0].name, "alpha");
    CHECK_STR_EQ(accounts[1].name, "beta");
    CHECK_STR_EQ(accounts[2].name, "charlie");
}

TEST(account_lookup_supports_id_name_description_and_email) {
    account_t accounts[3];

    initialize_account(&accounts[0], 7, "personal", "daily account",
                       "person@example.com");
    initialize_account(&accounts[1], 19, "work", "corporate identity",
                       "worker@example.com");
    initialize_account(&accounts[2], 42, "archive", "old credentials",
                       "old@example.com");

    CHECK(find_account_in_array(NULL, 3, "work") == NULL);
    CHECK(find_account_in_array(accounts, 3, NULL) == NULL);
    CHECK(find_account_in_array(accounts, 0, "work") == NULL);
    CHECK(find_account_in_array(accounts, 3, "19") == &accounts[1]);
    CHECK(find_account_in_array(accounts, 3, "99") == NULL);
    CHECK(find_account_in_array(accounts, 3, "son") == &accounts[0]);
    CHECK(find_account_in_array(accounts, 3, "corporate") == &accounts[1]);
    CHECK(find_account_in_array(accounts, 3, "old@example.com") ==
          &accounts[2]);
    CHECK(find_account_in_array(accounts, 3, "absent") == NULL);
}

TEST(safe_memory_helpers_validate_arguments_and_copy_bytes) {
    unsigned char source[] = {1, 2, 3, 4};
    unsigned char destination[sizeof(source)] = {0};

    CHECK(safe_memset(NULL, 0, 1) == NULL);
    CHECK(safe_memset(destination, 0, 0) == NULL);
    CHECK(safe_memset(destination, 0xa5, sizeof(destination)) == destination);
    CHECK(destination[0] == 0xa5 && destination[3] == 0xa5);

    CHECK(safe_memcpy(NULL, source, sizeof(source)) == NULL);
    CHECK(safe_memcpy(destination, NULL, sizeof(source)) == NULL);
    CHECK(safe_memcpy(destination, source, 0) == NULL);
    CHECK(safe_memcpy(destination, source, sizeof(source)) == destination);
    CHECK(memcmp(destination, source, sizeof(source)) == 0);
}

TEST(memory_lock_helpers_reject_invalid_requests_portably) {
    unsigned char byte = 0;

    CHECK_EQ_INT(safe_mlock(NULL, 1), -1);
    CHECK_EQ_INT(safe_mlock(&byte, 0), -1);
    CHECK_EQ_INT(safe_munlock(NULL, 1), -1);
    CHECK_EQ_INT(safe_munlock(&byte, 0), -1);
}

TEST(memory_lock_helpers_never_report_false_platform_success) {
    long page_size = sysconf(_SC_PAGESIZE);
    void *page = NULL;
    int lock_result;

    CHECK(page_size > 0);
    if (page_size <= 0) return;
    CHECK_EQ_INT(posix_memalign(&page, (size_t)page_size,
                               (size_t)page_size), 0);
    if (!page) return;
    memset(page, 0xa5, (size_t)page_size);

    clear_error();
    errno = 0;
    lock_result = safe_mlock(page, 1);
    if (lock_result == 0) {
        CHECK_EQ_INT(safe_munlock(page, 1), 0);
    } else {
        CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
        CHECK(get_last_error()->system_errno != 0);
    }
    free(page);
}

TEST(debug_dumps_accept_null_and_populated_models) {
    char root[] = "/tmp/gitswitch-ar14-utils-log-XXXXXX";
    char log_path[MAX_PATH_LEN];
    char log_text[32768];
    account_t disabled;
    account_t enabled;
    config_t quiet;
    config_t verbose;
    gitswitch_ctx_t context;
    bool previous_log_to_stderr = g_log_to_stderr;
    int init_result;

    memset(&quiet, 0, sizeof(quiet));
    memset(&verbose, 0, sizeof(verbose));
    memset(&context, 0, sizeof(context));
    initialize_account(&disabled, 1, "disabled", "none",
                       "disabled@example.com");
    initialize_account(&enabled, 2, "enabled", "all",
                       "enabled@example.com");
    enabled.ssh_enabled = true;
    enabled.gpg_enabled = true;
    enabled.gpg_signing_enabled = true;
    verbose.verbose = true;
    verbose.dry_run = true;
    verbose.color_output = true;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(safe_snprintf(log_path, sizeof(log_path), "%s/debug.log",
                               root), 0);
    set_log_to_stderr(false);
    init_result = error_init(LOG_LEVEL_DEBUG, log_path);
    CHECK_EQ_INT(init_result, 0);
    if (init_result == 0) {
        dump_account(NULL);
        dump_account(&disabled);
        dump_config(NULL);
        dump_config(&quiet);
        dump_context(NULL);
        dump_context(&context);

        context.account_count = 1;
        context.accounts[0] = enabled;
        context.current_account = &context.accounts[0];
        context.config = verbose;
        dump_context(&context);
    }
    CHECK_EQ_INT(error_init(LOG_LEVEL_CRITICAL, NULL), 0);
    set_log_to_stderr(previous_log_to_stderr);
    if (init_result == 0) {
        CHECK(read_text_file(log_path, log_text, sizeof(log_text)));
        CHECK(strstr(log_text, "Account: NULL") != NULL);
        CHECK(strstr(log_text, "ID: 2") != NULL);
        CHECK(strstr(log_text, "Name: enabled") != NULL);
        CHECK(strstr(log_text, "SSH enabled: no") != NULL);
        CHECK(strstr(log_text, "SSH enabled: yes") != NULL);
        CHECK(strstr(log_text, "GPG signing: yes") != NULL);
        CHECK(strstr(log_text, "Config: NULL") != NULL);
        CHECK(strstr(log_text, "Verbose: no") != NULL);
        CHECK(strstr(log_text, "Verbose: yes") != NULL);
        CHECK(strstr(log_text, "Dry run: yes") != NULL);
        CHECK(strstr(log_text, "Color output: yes") != NULL);
        CHECK(strstr(log_text, "Context: NULL") != NULL);
        CHECK(strstr(log_text, "Account count: 0") != NULL);
        CHECK(strstr(log_text, "Current account: none") != NULL);
        CHECK(strstr(log_text, "Account count: 1") != NULL);
        CHECK(strstr(log_text, "Current account: enabled") != NULL);
    }
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(process_liveness_rejects_invalid_pid_and_accepts_self);
    RUN_TEST(environment_helpers_round_trip_and_honor_overwrite);
    RUN_TEST(environment_helpers_reject_invalid_arguments_and_small_buffers);
    RUN_TEST(string_helpers_cover_null_empty_case_and_boundary_contracts);
    RUN_TEST(string_replace_reports_invalid_missing_overflow_and_success);
    RUN_TEST(path_helpers_cover_tilde_separators_types_and_bounds);
    RUN_TEST(file_validation_distinguishes_existing_missing_and_invalid_paths);
    RUN_TEST(permission_validation_requires_the_exact_requested_mode);
    RUN_TEST(config_directory_creation_is_isolated_and_idempotent);
    RUN_TEST(time_helpers_publish_bounded_nonempty_values);
    RUN_TEST(timestamp_expiry_respects_age_boundary_direction);
    RUN_TEST(comparison_helpers_define_id_name_and_string_ordering);
    RUN_TEST(account_sorting_orders_multiple_accounts_and_ignores_noops);
    RUN_TEST(account_lookup_supports_id_name_description_and_email);
    RUN_TEST(safe_memory_helpers_validate_arguments_and_copy_bytes);
    RUN_TEST(memory_lock_helpers_reject_invalid_requests_portably);
    RUN_TEST(memory_lock_helpers_never_report_false_platform_success);
    RUN_TEST(debug_dumps_accept_null_and_populated_models);
TEST_MAIN_END()
