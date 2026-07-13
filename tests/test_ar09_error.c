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

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(direct_error_context_copies_mutable_provenance);
    RUN_TEST(system_error_context_copies_mutable_provenance);
    RUN_TEST(error_context_value_copy_has_independent_provenance);
    RUN_TEST(error_macro_keeps_static_provenance_exact);
    RUN_TEST(null_provenance_is_owned_and_printable);
    RUN_TEST(overlong_provenance_is_bounded_and_terminated);
    RUN_TEST(clear_error_clears_owned_provenance);
TEST_MAIN_END()
