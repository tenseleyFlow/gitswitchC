/* AR-09 H4: error contexts must own provenance supplied by direct callers. */

#include "test.h"
#include "error.h"

#include <errno.h>
#include <string.h>

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

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
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
TEST_MAIN_END()
