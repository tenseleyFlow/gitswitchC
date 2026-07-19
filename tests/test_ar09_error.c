/* AR-09 H4: error contexts must own provenance supplied by direct callers. */

#include "test.h"
#include "error.h"

#include <errno.h>
#include <string.h>

typedef struct {
    uint64_t generation_before;
    uint64_t generation_during;
} observational_failure_t;

typedef struct {
    bool inner_result_preserved;
    bool inner_context_restored;
    bool inner_generation_restored;
    bool inner_errno_restored;
} nested_observation_t;

static int publish_observational_failure(void *context) {
    observational_failure_t *observation = context;

    set_error(ERR_NETWORK_ERROR, "first observational failure");
    errno = EIO;
    set_system_error(ERR_SYSTEM_CALL, "second observational failure");
    observation->generation_during = error_report_generation();
    clear_error();
    errno = ENOSPC;
    return 73;
}

static int publish_nested_observational_failure(void *context) {
    (void)context;
    errno = ENOTTY;
    set_system_error(ERR_FILE_IO, "nested observational failure");
    errno = ECHILD;
    return 19;
}

static int run_nested_observation(void *context) {
    nested_observation_t *observation = context;
    error_context_t outer_error;
    uint64_t outer_generation;
    int nested_result;

    set_error(ERR_NETWORK_ERROR, "outer observational failure");
    outer_error = *get_last_error();
    outer_generation = error_report_generation();
    errno = EPIPE;
    nested_result = error_run_observational(
        publish_nested_observational_failure, NULL);

    observation->inner_result_preserved = nested_result == 19;
    observation->inner_context_restored =
        memcmp(get_last_error(), &outer_error, sizeof(outer_error)) == 0;
    observation->inner_generation_restored =
        error_report_generation() == outer_generation;
    observation->inner_errno_restored = errno == EPIPE;
    return 29;
}

TEST(observational_scope_restores_context_generation_and_errno) {
    observational_failure_t observation = {0};
    error_context_t saved;

    set_error(ERR_ACCOUNT_INVALID, "retained causal diagnostic");
    saved = *get_last_error();
    errno = EAGAIN;
    observation.generation_before = error_report_generation();

    CHECK_EQ_INT(error_run_observational(publish_observational_failure,
                                         &observation),
                 73);
    CHECK(observation.generation_during != observation.generation_before);
    CHECK(error_report_generation() == observation.generation_before);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK_EQ_INT(get_last_error()->code, saved.code);
    CHECK_STR_EQ(get_last_error()->message, saved.message);
    CHECK_STR_EQ(get_last_error()->details, saved.details);
    CHECK_STR_EQ(get_last_error()->file, saved.file);
    CHECK_STR_EQ(get_last_error()->function, saved.function);
    CHECK_EQ_INT(get_last_error()->line, saved.line);
    CHECK_EQ_INT(get_last_error()->system_errno, saved.system_errno);
}

TEST(nested_observational_scopes_restore_in_lifo_order) {
    nested_observation_t observation = {0};
    error_context_t saved;
    uint64_t saved_generation;

    set_error(ERR_ACCOUNT_INVALID, "nested retained diagnostic");
    saved = *get_last_error();
    saved_generation = error_report_generation();
    errno = EAGAIN;

    CHECK_EQ_INT(error_run_observational(run_nested_observation,
                                         &observation),
                 29);
    CHECK(observation.inner_result_preserved);
    CHECK(observation.inner_context_restored);
    CHECK(observation.inner_generation_restored);
    CHECK(observation.inner_errno_restored);
    CHECK(memcmp(get_last_error(), &saved, sizeof(saved)) == 0);
    CHECK(error_report_generation() == saved_generation);
    CHECK_EQ_INT(errno, EAGAIN);
}

TEST(null_observational_callback_publishes_api_misuse) {
    uint64_t saved_generation;

    set_error(ERR_ACCOUNT_INVALID, "replaced diagnostic");
    saved_generation = error_report_generation();
    errno = 0;

    CHECK_EQ_INT(error_run_observational(NULL, NULL), -1);
    CHECK_EQ_INT(errno, EINVAL);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(get_last_error()->system_errno, EINVAL);
    CHECK_STR_EQ(get_last_error()->message,
                 "NULL observational error callback (Invalid argument)");
    CHECK(error_report_generation() != saved_generation);
}

TEST(direct_error_context_copies_mutable_provenance) {
    char file[64] = "mutable-source.c";
    char function[64] = "mutable_function";
    char formatted[2048];
    const error_context_t *error;

    set_error_context(ERR_INVALID_ARGS, file, 37, function,
                      "mutable provenance");
    snprintf(file, sizeof(file), "%s", "changed-source.c");
    snprintf(function, sizeof(function), "%s", "changed_function");

    error = get_last_error();
    CHECK_STR_EQ(error->file, "mutable-source.c");
    CHECK_STR_EQ(error->function, "mutable_function");
    CHECK_EQ_INT(error->line, 37);
    CHECK_STR_EQ(error->message, "mutable provenance");
    memset(formatted, 0, sizeof(formatted));
    format_error_message(formatted, sizeof(formatted), error);
    CHECK(strstr(formatted, "mutable-source.c:37 in mutable_function()") !=
          NULL);
}

TEST(system_error_context_copies_mutable_provenance) {
    char file[64] = "system-source.c";
    char function[64] = "system_function";
    char errno_fragment[32];
    const error_context_t *error;

    errno = ENOENT;
    set_system_error_context(ERR_FILE_IO, file, 91, function,
                             "system provenance");
    snprintf(file, sizeof(file), "%s", "changed-system.c");
    snprintf(function, sizeof(function), "%s", "changed_system_function");

    error = get_last_error();
    CHECK_STR_EQ(error->file, "system-source.c");
    CHECK_STR_EQ(error->function, "system_function");
    CHECK_EQ_INT(error->line, 91);
    CHECK_EQ_INT(error->system_errno, ENOENT);
    CHECK(snprintf(errno_fragment, sizeof(errno_fragment), "errno=%d",
                   ENOENT) > 0);
    CHECK(strstr(error->details, errno_fragment) != NULL);
    CHECK(strstr(error->message, "system provenance") != NULL);
}

TEST(error_context_value_copy_has_independent_provenance) {
    char file[64] = "saved-source.c";
    char function[64] = "saved_function";
    char formatted[2048];
    error_context_t saved;

    set_error_context(ERR_ACCOUNT_INVALID, file, 123, function,
                      "saved failure");
    saved = *get_last_error();
    snprintf(file, sizeof(file), "%s", "overwritten-source.c");
    snprintf(function, sizeof(function), "%s", "overwritten_function");
    set_error_context(ERR_UNKNOWN, "second-source.c", 456,
                      "second_function", "second failure");

    CHECK_STR_EQ(saved.file, "saved-source.c");
    CHECK_STR_EQ(saved.function, "saved_function");
    CHECK_STR_EQ(saved.message, "saved failure");
    memset(formatted, 0, sizeof(formatted));
    format_error_message(formatted, sizeof(formatted), &saved);
    CHECK(strstr(formatted, "saved-source.c:123 in saved_function()") !=
          NULL);
    CHECK_STR_EQ(get_last_error()->file, "second-source.c");
    CHECK_STR_EQ(get_last_error()->function, "second_function");
}

TEST(error_macro_keeps_static_provenance_exact) {
    const error_context_t *error;

    set_error(ERR_INVALID_ARGS, "macro provenance");
    error = get_last_error();
    CHECK(strstr(error->file, "test_ar09_error.c") != NULL);
    CHECK_STR_EQ(error->function,
                 "error_macro_keeps_static_provenance_exact");
    CHECK(error->line > 0);
}

TEST(null_provenance_is_owned_and_printable) {
    char formatted[2048];
    const error_context_t *error;

    set_error_context(ERR_UNKNOWN, NULL, 7, NULL, "unknown provenance");
    error = get_last_error();
    CHECK_STR_EQ(error->file, "unknown");
    CHECK_STR_EQ(error->function, "unknown");
    memset(formatted, 0, sizeof(formatted));
    format_error_message(formatted, sizeof(formatted), error);
    CHECK(strstr(formatted, "unknown:7 in unknown()") != NULL);
}

TEST(overlong_provenance_is_bounded_and_terminated) {
    char file[MAX_PATH_LEN + 32U];
    char function[MAX_NAME_LEN + 32U];
    const error_context_t *error;

    memset(file, 'f', sizeof(file) - 1U);
    file[sizeof(file) - 1U] = '\0';
    memset(function, 'g', sizeof(function) - 1U);
    function[sizeof(function) - 1U] = '\0';
    set_error_context(ERR_UNKNOWN, file, 8, function,
                      "bounded provenance");

    error = get_last_error();
    CHECK_EQ_INT((int)strlen(error->file), MAX_PATH_LEN - 1);
    CHECK_EQ_INT((int)strlen(error->function), MAX_NAME_LEN - 1);
    CHECK(error->file[MAX_PATH_LEN - 1] == '\0');
    CHECK(error->function[MAX_NAME_LEN - 1] == '\0');
}

TEST(clear_error_clears_owned_provenance) {
    const error_context_t *error;

    set_error_context(ERR_UNKNOWN, "clear-source.c", 8, "clear_function",
                      "clear provenance");
    clear_error();
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SUCCESS);
    CHECK(error->file[0] == '\0');
    CHECK(error->function[0] == '\0');
    CHECK(error->message[0] == '\0');
}

TEST(exact_fit_error_message_remains_complete) {
    char source[sizeof(g_last_error.message)];
    const error_context_t *error;

    memset(source, 'e', sizeof(source) - 1U);
    source[sizeof(source) - 1U] = '\0';
    CHECK_EQ_INT(set_error_context(ERR_UNKNOWN, "boundary.c", 9,
                                   "boundary_function", "%s", source),
                 0);

    error = get_last_error();
    CHECK_EQ_INT((int)strlen(error->message), (int)sizeof(source) - 1);
    CHECK_STR_EQ(error->message, source);
    CHECK(!error->message_truncated);
    CHECK(strstr(error->message, "[truncated]") == NULL);
}

TEST(oversized_error_message_reports_truncation) {
    char source[sizeof(g_last_error.message) + 1U];
    char formatted[2048];
    const error_context_t *error;

    memset(source, 'o', sizeof(source) - 1U);
    source[sizeof(source) - 1U] = '\0';
    CHECK_EQ_INT(set_error_context(ERR_UNKNOWN, "boundary.c", 10,
                                   "boundary_function", "%s", source),
                 -1);

    error = get_last_error();
    CHECK(error->message[sizeof(error->message) - 1U] == '\0');
    CHECK(error->message_truncated);
    CHECK(strstr(error->message, "[truncated]") != NULL);
    memset(formatted, 0, sizeof(formatted));
    format_error_message(formatted, sizeof(formatted), error);
    CHECK(strstr(formatted, "[truncated]") != NULL);
}

TEST(exact_fit_system_suffix_remains_complete) {
    char source[sizeof(g_last_error.message)];
    const char *system_text = strerror(ENOENT);
    int suffix_length;
    size_t base_length;
    const error_context_t *error;

    suffix_length = snprintf(NULL, 0, " (%s)", system_text);
    CHECK(suffix_length > 0);
    base_length = sizeof(g_last_error.message) - 1U -
                  (size_t)suffix_length;
    memset(source, 's', base_length);
    source[base_length] = '\0';
    errno = ENOENT;
    CHECK_EQ_INT(set_system_error_context(ERR_FILE_IO, "boundary.c", 11,
                                          "boundary_function", "%s", source),
                 0);

    error = get_last_error();
    CHECK_EQ_INT(error->system_errno, ENOENT);
    CHECK(!error->message_truncated);
    CHECK(!error->details_truncated);
    CHECK_EQ_INT((int)strlen(error->message),
                 (int)sizeof(error->message) - 1);
    CHECK(strstr(error->message, system_text) != NULL);
    CHECK(strstr(error->message, "[truncated]") == NULL);
    CHECK(strstr(error->details, "errno=") != NULL);
}

TEST(oversized_system_suffix_reports_truncation) {
    char source[sizeof(g_last_error.message)];
    char formatted[2048];
    const char *system_text = strerror(ENOENT);
    int suffix_length;
    size_t base_length;
    const error_context_t *error;

    suffix_length = snprintf(NULL, 0, " (%s)", system_text);
    CHECK(suffix_length > 0);
    base_length = sizeof(g_last_error.message) - (size_t)suffix_length;
    memset(source, 's', base_length);
    source[base_length] = '\0';
    errno = ENOENT;
    CHECK_EQ_INT(set_system_error_context(ERR_FILE_IO, "boundary.c", 12,
                                          "boundary_function", "%s", source),
                 -1);

    error = get_last_error();
    CHECK_EQ_INT(error->system_errno, ENOENT);
    CHECK(error->message_truncated);
    CHECK(!error->details_truncated);
    CHECK(strstr(error->details, "errno=") != NULL);
    CHECK(strstr(error->message, "[truncated]") != NULL);
    memset(formatted, 0, sizeof(formatted));
    format_error_message(formatted, sizeof(formatted), error);
    CHECK(strstr(formatted, "[truncated]") != NULL);
    CHECK(strstr(formatted, "errno=") != NULL);
}

TEST(error_context_preserves_aliased_previous_message) {
    CHECK_EQ_INT(set_error_context(ERR_FILE_IO, "inner.c", 13,
                                   "inner_function", "inner diagnostic"),
                 0);
    CHECK_EQ_INT(set_error_context(ERR_UNKNOWN, "outer.c", 14,
                                   "outer_function", "outer: %s",
                                   get_last_error()->message),
                 0);

    CHECK_STR_EQ(get_last_error()->message, "outer: inner diagnostic");
}

TEST(very_large_message_and_saved_context_keep_truncation_state) {
    char source[4097];
    error_context_t saved;

    memset(source, 'v', sizeof(source) - 1U);
    source[sizeof(source) - 1U] = '\0';
    CHECK_EQ_INT(set_error_context(ERR_UNKNOWN, "large.c", 15,
                                   "large_function", "%s", source),
                 -1);
    saved = *get_last_error();
    CHECK(saved.message_truncated);
    CHECK(strstr(saved.message, "[truncated]") != NULL);

    CHECK_EQ_INT(set_error_context(ERR_UNKNOWN, "next.c", 16,
                                   "next_function", "complete"),
                 0);
    CHECK(!get_last_error()->message_truncated);
    CHECK(saved.message_truncated);
    CHECK(strstr(saved.message, "[truncated]") != NULL);
}

TEST(display_format_marks_its_own_bounded_truncation) {
    struct {
        unsigned char before;
        char formatted[96];
        unsigned char after;
    } guarded = {0xA5, {0}, 0x5A};
    error_context_t error = {0};

    memset(error.message, 'm', sizeof(error.message) - 1U);
    memset(error.details, 'd', sizeof(error.details) - 1U);
    memset(error.file, 'f', sizeof(error.file) - 1U);
    memset(error.function, 'n', sizeof(error.function) - 1U);
    error.system_errno = ENOENT;
    error.line = 2147483647;

    format_error_message(guarded.formatted, sizeof(guarded.formatted), &error);

    CHECK_EQ_INT(guarded.before, 0xA5);
    CHECK_EQ_INT(guarded.after, 0x5A);
    CHECK(guarded.formatted[sizeof(guarded.formatted) - 1U] == '\0');
    CHECK(strstr(guarded.formatted, ERROR_MESSAGE_TRUNCATION_MARKER) != NULL);
}

TEST(display_format_rejects_unterminated_context_fields_truthfully) {
    char formatted[256];
    error_context_t error = {0};

    memset(error.message, 'm', sizeof(error.message));
    memcpy(error.file, "source.c", sizeof("source.c"));
    memcpy(error.function, "function", sizeof("function"));
    error.line = 17;

    format_error_message(formatted, sizeof(formatted), &error);

    CHECK(formatted[sizeof(formatted) - 1U] == '\0');
    CHECK(strstr(formatted, ERROR_MESSAGE_TRUNCATION_MARKER) != NULL);
}

/* AR-10 L9: a failed re-init must keep the previous sink and level live —
 * the old order closed the working stream and committed the level before the
 * fopen could fail. Observable contract: the failed call returns -1 and a
 * subsequent log line still lands in the ORIGINAL log file. */
TEST(failed_error_init_retains_previous_log_sink) {
    char dir[64];
    char good[128];
    char bad[128];
    char content[512];
    FILE *stream;
    size_t got;

    snprintf(dir, sizeof(dir), "/tmp/gswar10err_XXXXXX");
    CHECK(ts_mkdtemp(dir) != NULL);
    snprintf(good, sizeof(good), "%s/good.log", dir);
    /* Unopenable: path through a nonexistent directory. */
    snprintf(bad, sizeof(bad), "%s/missing-dir/bad.log", dir);

    CHECK_EQ_INT(error_init(LOG_LEVEL_INFO, good), 0);
    CHECK_EQ_INT(error_init(LOG_LEVEL_INFO, bad), -1);
    log_info("post-failure line lands in the original sink");

    stream = fopen(good, "r");
    CHECK(stream != NULL);
    if (stream) {
        got = fread(content, 1, sizeof(content) - 1U, stream);
        content[got] = '\0';
        fclose(stream);
        CHECK(strstr(content,
                     "post-failure line lands in the original sink") != NULL);
    }

    /* Restore the suite's quiet logging configuration. */
    CHECK_EQ_INT(error_init(LOG_LEVEL_CRITICAL, NULL), 0);
}

TEST(error_accumulator_retains_first_context_without_global_side_effects) {
    error_accumulator_t accumulator;
    error_context_t first;
    error_context_t first_bytes;
    error_context_t global_before = {0};

    memset(&first, 0xA5, sizeof(first));
    first.code = ERR_CONFIG_WRITE_FAILED;
    snprintf(first.message, sizeof(first.message), "%s", "first failure");
    first.message_truncated = false;
    snprintf(first.details, sizeof(first.details), "%s", "first details");
    first.details_truncated = false;
    snprintf(first.file, sizeof(first.file), "%s", "first-source.c");
    first.line = 271;
    snprintf(first.function, sizeof(first.function), "%s", "first_function");
    first.system_errno = EIO;
    memcpy(&first_bytes, &first, sizeof(first_bytes));

    global_before.code = ERR_UNKNOWN;
    snprintf(global_before.message, sizeof(global_before.message), "%s",
             "unrelated global error");
    memcpy(&g_last_error, &global_before, sizeof(g_last_error));

    errno = EDOM;
    error_accumulator_init(&accumulator);
    CHECK_EQ_INT(errno, EDOM);
    CHECK(!accumulator.active);

    errno = EINTR;
    CHECK(error_accumulator_add(&accumulator, "initial", &first));
    CHECK_EQ_INT(errno, EINTR);
    CHECK(memcmp(&g_last_error, &global_before, sizeof(g_last_error)) == 0);
    CHECK(memcmp(&accumulator.first_error, &first_bytes,
                 sizeof(first_bytes)) == 0);
    CHECK(accumulator.active);
    CHECK_EQ_INT(accumulator.first_errno, EINTR);
    CHECK_EQ_INT(accumulator.failure_count, 1);
    CHECK_EQ_INT(accumulator.rendered_count, 1);
    CHECK(!accumulator.chain_truncated);
    CHECK_STR_EQ(accumulator.accumulated_details, "first details");
}

TEST(error_accumulator_appends_in_order_and_publishes_first_cause) {
    error_accumulator_t accumulator;
    error_context_t first = {0};
    error_context_t first_bytes;
    error_context_t later = {0};
    error_context_t global_before;

    first.code = ERR_FILE_IO;
    snprintf(first.message, sizeof(first.message), "%s", "save failed");
    snprintf(first.details, sizeof(first.details), "%s", "save errno detail");
    snprintf(first.file, sizeof(first.file), "%s", "resume.c");
    first.line = 41;
    snprintf(first.function, sizeof(first.function), "%s", "restore_resume");
    first.system_errno = ENOSPC;
    memcpy(&first_bytes, &first, sizeof(first_bytes));

    error_accumulator_init(&accumulator);
    errno = EBUSY;
    CHECK(error_accumulator_add(&accumulator, "save", &first));

    set_error_context(ERR_CONFIG_WRITE_FAILED, "metadata.c", 52,
                      "restore_metadata", "metadata restore failed");
    memcpy(&global_before, &g_last_error, sizeof(global_before));
    errno = EAGAIN;
    CHECK(error_accumulator_add_last(&accumulator, "resume restore"));
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK(memcmp(&g_last_error, &global_before, sizeof(g_last_error)) == 0);

    later.code = ERR_SYSTEM_CALL;
    snprintf(later.message, sizeof(later.message), "%s", "abort failed");
    snprintf(later.details, sizeof(later.details), "%s",
             "; [nested cleanup] nested failure");
    snprintf(later.file, sizeof(later.file), "%s", "accounts.c");
    later.line = 63;
    snprintf(later.function, sizeof(later.function), "%s", "abort_switch");
    later.system_errno = EPERM;
    errno = ENOTTY;
    CHECK(error_accumulator_add(&accumulator, "account abort", &later));
    CHECK_EQ_INT(errno, ENOTTY);
    CHECK(memcmp(&g_last_error, &global_before, sizeof(g_last_error)) == 0);

    CHECK_EQ_INT(accumulator.failure_count, 3);
    CHECK_EQ_INT(accumulator.rendered_count, 3);
    CHECK(!accumulator.chain_truncated);
    CHECK_STR_EQ(accumulator.accumulated_details,
                 "save errno detail; [resume restore] metadata restore failed; "
                 "[account abort] abort failed; [nested cleanup] nested failure");
    CHECK(memcmp(&accumulator.first_error, &first_bytes,
                 sizeof(first_bytes)) == 0);

    set_error_context(ERR_UNKNOWN, "sentinel.c", 99, "sentinel",
                      "publish replaces this once");
    errno = ERANGE;
    CHECK(error_accumulator_publish(&accumulator));
    CHECK_EQ_INT(errno, EBUSY);
    CHECK_EQ_INT(g_last_error.code, ERR_FILE_IO);
    CHECK_EQ_INT(g_last_error.system_errno, ENOSPC);
    CHECK_STR_EQ(g_last_error.message, "save failed");
    CHECK_STR_EQ(g_last_error.details,
                 "save errno detail; [resume restore] metadata restore failed; "
                 "[account abort] abort failed; [nested cleanup] nested failure");
    CHECK_STR_EQ(g_last_error.file, "resume.c");
    CHECK_EQ_INT(g_last_error.line, 41);
    CHECK_STR_EQ(g_last_error.function, "restore_resume");
    CHECK(!g_last_error.details_truncated);
    CHECK(memcmp(&accumulator.first_error, &first_bytes,
                 sizeof(first_bytes)) == 0);
}

TEST(error_accumulator_marks_bounded_chain_truncation_and_counts_failures) {
    error_accumulator_t accumulator;
    error_context_t first = {0};
    error_context_t first_bytes;
    error_context_t later = {0};
    error_context_t global_before = {0};
    char truncated_details[sizeof(accumulator.accumulated_details)];
    size_t initial_length = sizeof(first.details) - 24U;

    first.code = ERR_CONFIG_WRITE_FAILED;
    snprintf(first.message, sizeof(first.message), "%s", "primary failure");
    memset(first.details, 'd', initial_length);
    first.details[initial_length] = '\0';
    snprintf(first.file, sizeof(first.file), "%s", "primary.c");
    first.line = 72;
    snprintf(first.function, sizeof(first.function), "%s", "primary_stage");
    first.system_errno = EROFS;
    memcpy(&first_bytes, &first, sizeof(first_bytes));

    memset(later.message, 'x', sizeof(later.message) - 1U);
    later.message[sizeof(later.message) - 1U] = '\0';
    later.code = ERR_SYSTEM_CALL;

    global_before.code = ERR_ACCOUNT_INVALID;
    snprintf(global_before.message, sizeof(global_before.message), "%s",
             "global sentinel");
    memcpy(&g_last_error, &global_before, sizeof(g_last_error));

    error_accumulator_init(&accumulator);
    errno = ECHILD;
    CHECK(error_accumulator_add(&accumulator, "primary", &first));
    errno = EPIPE;
    CHECK(!error_accumulator_add(&accumulator, "secondary", &later));
    CHECK_EQ_INT(errno, EPIPE);
    CHECK(accumulator.chain_truncated);
    CHECK_EQ_INT(accumulator.failure_count, 2);
    CHECK_EQ_INT(accumulator.rendered_count, 1);
    CHECK(strstr(accumulator.accumulated_details,
                 ERROR_MESSAGE_TRUNCATION_MARKER) != NULL);
    memcpy(truncated_details, accumulator.accumulated_details,
           sizeof(truncated_details));

    errno = ENFILE;
    CHECK(!error_accumulator_add(&accumulator, "tertiary", &later));
    CHECK_EQ_INT(errno, ENFILE);
    CHECK_EQ_INT(accumulator.failure_count, 3);
    CHECK_EQ_INT(accumulator.rendered_count, 1);
    CHECK(memcmp(truncated_details, accumulator.accumulated_details,
                 sizeof(truncated_details)) == 0);
    CHECK(memcmp(&g_last_error, &global_before, sizeof(g_last_error)) == 0);
    CHECK(memcmp(&accumulator.first_error, &first_bytes,
                 sizeof(first_bytes)) == 0);

    errno = ENOMSG;
    CHECK(error_accumulator_publish(&accumulator));
    CHECK_EQ_INT(errno, ECHILD);
    CHECK_EQ_INT(g_last_error.code, ERR_CONFIG_WRITE_FAILED);
    CHECK_EQ_INT(g_last_error.system_errno, EROFS);
    CHECK_STR_EQ(g_last_error.message, "primary failure");
    CHECK_STR_EQ(g_last_error.file, "primary.c");
    CHECK_EQ_INT(g_last_error.line, 72);
    CHECK_STR_EQ(g_last_error.function, "primary_stage");
    CHECK(g_last_error.details_truncated);
    CHECK(strstr(g_last_error.details, ERROR_MESSAGE_TRUNCATION_MARKER) != NULL);
}

TEST(safe_strncat_accepts_empty_and_exact_fit_without_replacing_error) {
    char empty[1] = "";
    char exact[5] = "ab";
    error_context_t saved;
    uint64_t saved_generation;

    set_error(ERR_ACCOUNT_INVALID, "retained concatenation diagnostic");
    saved = *get_last_error();
    saved_generation = error_report_generation();

    CHECK_EQ_INT(safe_strncat(empty, "", sizeof(empty)), 0);
    CHECK_STR_EQ(empty, "");
    CHECK_EQ_INT(safe_strncat(exact, "cd", sizeof(exact)), 0);
    CHECK_STR_EQ(exact, "abcd");
    CHECK(memcmp(get_last_error(), &saved, sizeof(saved)) == 0);
    CHECK(error_report_generation() == saved_generation);
}

TEST(safe_strncat_rejects_invalid_and_short_capacities_atomically) {
    char short_dest[4] = "ab";
    char short_before[sizeof(short_dest)];
    char one_byte[1] = "";
    char full[5] = "abcd";
    char full_before[sizeof(full)];

    memcpy(short_before, short_dest, sizeof(short_before));
    CHECK_EQ_INT(safe_strncat(NULL, "x", sizeof(short_dest)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(safe_strncat(short_dest, NULL, sizeof(short_dest)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(safe_strncat(short_dest, "x", 0), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(short_dest, short_before, sizeof(short_dest)) == 0);

    CHECK_EQ_INT(safe_strncat(short_dest, "cd", sizeof(short_dest)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(short_dest, short_before, sizeof(short_dest)) == 0);

    CHECK_EQ_INT(safe_strncat(one_byte, "x", sizeof(one_byte)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_STR_EQ(one_byte, "");

    memcpy(full_before, full, sizeof(full_before));
    CHECK_EQ_INT(safe_strncat(full, "", sizeof(full)), 0);
    CHECK(memcmp(full, full_before, sizeof(full)) == 0);
    CHECK_EQ_INT(safe_strncat(full, "x", sizeof(full)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(full, full_before, sizeof(full)) == 0);
}

TEST(safe_strncat_bounds_unterminated_destination_and_source_scans) {
    char *unterminated_dest = malloc(4U);
    char *unterminated_src = malloc(4U);
    char dest_before[4];
    char source_dest[5] = "a";
    char source_dest_before[sizeof(source_dest)];

    CHECK(unterminated_dest != NULL);
    CHECK(unterminated_src != NULL);
    if (!unterminated_dest || !unterminated_src) {
        free(unterminated_dest);
        free(unterminated_src);
        return;
    }

    memset(unterminated_dest, 'd', 4U);
    memcpy(dest_before, unterminated_dest, sizeof(dest_before));
    CHECK_EQ_INT(safe_strncat(unterminated_dest, "x", 4U), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(unterminated_dest, dest_before, sizeof(dest_before)) == 0);

    memset(unterminated_src, 's', 4U);
    memcpy(source_dest_before, source_dest, sizeof(source_dest_before));
    CHECK_EQ_INT(safe_strncat(source_dest, unterminated_src,
                             sizeof(source_dest)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(source_dest, source_dest_before, sizeof(source_dest)) == 0);

    free(unterminated_dest);
    free(unterminated_src);
}

TEST(safe_strncat_rejects_copy_overlap_without_mutation) {
    char self[8] = "ab";
    char self_before[sizeof(self)];
    char interior[8] = "abc";
    char interior_before[sizeof(interior)];
    char destination_inside_source[16] = "abc";
    char destination_inside_before[sizeof(destination_inside_source)];
    char tail_source[16] = {'a', 'b', '\0', 'c', 'd', '\0'};
    char tail_source_before[sizeof(tail_source)];

    memcpy(self_before, self, sizeof(self_before));
    CHECK_EQ_INT(safe_strncat(self, self, sizeof(self)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(self, self_before, sizeof(self)) == 0);

    memcpy(interior_before, interior, sizeof(interior_before));
    CHECK_EQ_INT(safe_strncat(interior, interior + 1, sizeof(interior)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(interior, interior_before, sizeof(interior)) == 0);

    memcpy(destination_inside_before, destination_inside_source,
           sizeof(destination_inside_before));
    CHECK_EQ_INT(safe_strncat(destination_inside_source + 1,
                             destination_inside_source,
                             sizeof(destination_inside_source) - 1U),
                 -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(destination_inside_source, destination_inside_before,
                 sizeof(destination_inside_source)) == 0);

    memcpy(tail_source_before, tail_source, sizeof(tail_source_before));
    CHECK_EQ_INT(safe_strncat(tail_source, tail_source + 3,
                             sizeof(tail_source)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(memcmp(tail_source, tail_source_before, sizeof(tail_source)) == 0);
}

TEST(safe_strncat_accepts_adjacent_nonoverlapping_ranges) {
    struct {
        char dest[4];
        char src[4];
    } adjacent = {{'a', '\0'}, {'b', 'c', '\0'}};

    CHECK_EQ_INT(safe_strncat(adjacent.dest, adjacent.src,
                             sizeof(adjacent.dest)),
                 0);
    CHECK_STR_EQ(adjacent.dest, "abc");
    CHECK_STR_EQ(adjacent.src, "bc");
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(observational_scope_restores_context_generation_and_errno);
    RUN_TEST(nested_observational_scopes_restore_in_lifo_order);
    RUN_TEST(null_observational_callback_publishes_api_misuse);
    RUN_TEST(direct_error_context_copies_mutable_provenance);
    RUN_TEST(system_error_context_copies_mutable_provenance);
    RUN_TEST(error_context_value_copy_has_independent_provenance);
    RUN_TEST(error_macro_keeps_static_provenance_exact);
    RUN_TEST(null_provenance_is_owned_and_printable);
    RUN_TEST(overlong_provenance_is_bounded_and_terminated);
    RUN_TEST(clear_error_clears_owned_provenance);
    RUN_TEST(exact_fit_error_message_remains_complete);
    RUN_TEST(oversized_error_message_reports_truncation);
    RUN_TEST(exact_fit_system_suffix_remains_complete);
    RUN_TEST(oversized_system_suffix_reports_truncation);
    RUN_TEST(error_context_preserves_aliased_previous_message);
    RUN_TEST(very_large_message_and_saved_context_keep_truncation_state);
    RUN_TEST(display_format_marks_its_own_bounded_truncation);
    RUN_TEST(display_format_rejects_unterminated_context_fields_truthfully);
    RUN_TEST(failed_error_init_retains_previous_log_sink);
    RUN_TEST(error_accumulator_retains_first_context_without_global_side_effects);
    RUN_TEST(error_accumulator_appends_in_order_and_publishes_first_cause);
    RUN_TEST(error_accumulator_marks_bounded_chain_truncation_and_counts_failures);
    RUN_TEST(safe_strncat_accepts_empty_and_exact_fit_without_replacing_error);
    RUN_TEST(safe_strncat_rejects_invalid_and_short_capacities_atomically);
    RUN_TEST(safe_strncat_bounds_unterminated_destination_and_source_scans);
    RUN_TEST(safe_strncat_rejects_copy_overlap_without_mutation);
    RUN_TEST(safe_strncat_accepts_adjacent_nonoverlapping_ranges);
TEST_MAIN_END()
