/* AR-08 M31: Unicode formatting controls must not reach identity output. */
#include "test.h"

#include "accounts.h"
#include "config.h"
#include "error.h"
#include "toml_parser.h"
#include "utils.h"

typedef struct {
    uint32_t first;
    uint32_t last;
} codepoint_range_t;

static const codepoint_range_t default_ignorable_ranges[] = {
    {0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C},
    {0x115F, 0x1160}, {0x17B4, 0x17B5}, {0x180B, 0x180F},
    {0x200B, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x206F},
    {0x3164, 0x3164}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF},
    {0xFFA0, 0xFFA0}, {0xFFF0, 0xFFF8},
    {0x1BCA0, 0x1BCA3}, {0x1D173, 0x1D17A},
    {0xE0000, 0xE0FFF}
};

static size_t encode_utf8(uint32_t cp, char output[5]) {
    if (cp <= 0x7F) {
        output[0] = (char)cp;
        output[1] = '\0';
        return 1;
    }
    if (cp <= 0x7FF) {
        output[0] = (char)(0xC0U | (cp >> 6));
        output[1] = (char)(0x80U | (cp & 0x3FU));
        output[2] = '\0';
        return 2;
    }
    if (cp <= 0xFFFF) {
        output[0] = (char)(0xE0U | (cp >> 12));
        output[1] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        output[2] = (char)(0x80U | (cp & 0x3FU));
        output[3] = '\0';
        return 3;
    }
    output[0] = (char)(0xF0U | (cp >> 18));
    output[1] = (char)(0x80U | ((cp >> 12) & 0x3FU));
    output[2] = (char)(0x80U | ((cp >> 6) & 0x3FU));
    output[3] = (char)(0x80U | (cp & 0x3FU));
    output[4] = '\0';
    return 4;
}

static void wrap_codepoint(uint32_t cp, char text[8], size_t *length) {
    char encoded[5];
    size_t encoded_length = encode_utf8(cp, encoded);

    text[0] = 'A';
    memcpy(text + 1, encoded, encoded_length);
    text[encoded_length + 1] = 'B';
    text[encoded_length + 2] = '\0';
    *length = encoded_length + 2;
}

TEST(rejects_every_unicode_16_default_ignorable_codepoint) {
    for (size_t range = 0;
         range < sizeof(default_ignorable_ranges) /
                     sizeof(default_ignorable_ranges[0]);
         range++) {
        bool every_codepoint_rejected = true;
        for (uint32_t cp = default_ignorable_ranges[range].first;
             cp <= default_ignorable_ranges[range].last;
             cp++) {
            if (tty_safe_codepoint(cp)) {
                every_codepoint_rejected = false;
                break;
            }
        }
        CHECK(every_codepoint_rejected);
    }

    CHECK(!tty_safe_codepoint(0x2028));
    CHECK(!tty_safe_codepoint(0x2029));
    CHECK(!tty_safe_codepoint(0xD800));
    CHECK(!tty_safe_codepoint(0x110000));
}

TEST(bidi_marks_zero_width_and_variation_selectors_fail_text_gates) {
    static const uint32_t samples[] = {
        0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0x206F,
        0xFE0F, 0xFEFF, 0xE0001, 0xE0100
    };

    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        char input[8];
        char sanitized[8];
        size_t length;

        wrap_codepoint(samples[i], input, &length);
        CHECK(!toml_validate_safe_characters(input, length));
        CHECK_EQ_INT(toml_sanitize_string(input, sanitized,
                                          sizeof(sanitized)), 0);
        CHECK_STR_EQ(sanitized, "AB");
    }
}

TEST(visible_unicode_combining_marks_and_strict_utf8_remain_exact) {
    static const uint32_t visible[] = {
        0x20, 0x41, 0x00E9, 0x0301, 0x4E8B, 0x1F680
    };
    static const unsigned char malformed[][4] = {
        {0x80, 0, 0, 0},
        {0xC0, 0xAF, 0, 0},
        {0xE0, 0x80, 0xAF, 0},
        {0xED, 0xA0, 0x80, 0},
        {0xF4, 0x90, 0x80, 0x80}
    };
    static const size_t malformed_lengths[] = {1, 2, 3, 3, 4};

    for (size_t i = 0; i < sizeof(visible) / sizeof(visible[0]); i++) {
        char input[8];
        size_t length;

        CHECK(tty_safe_codepoint(visible[i]));
        wrap_codepoint(visible[i], input, &length);
        CHECK(toml_validate_safe_characters(input, length));
    }

    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        char input[8] = {'A', 0, 0, 0, 0, 'B', '\0', '\0'};
        memcpy(input + 1, malformed[i], malformed_lengths[i]);
        input[malformed_lengths[i] + 1] = 'B';
        input[malformed_lengths[i] + 2] = '\0';
        CHECK(!toml_validate_safe_characters(
            input, malformed_lengths[i] + 2));
    }
}

static void fill_account(account_t *account, const char *name,
                         const char *description) {
    memset(account, 0, sizeof(*account));
    account->id = 1;
    account->preferred_scope = GIT_SCOPE_GLOBAL;
    (void)snprintf(account->name, sizeof(account->name), "%s", name);
    (void)snprintf(account->email, sizeof(account->email), "%s",
                   "unicode@example.test");
    (void)snprintf(account->description, sizeof(account->description), "%s",
                   description);
}

TEST(account_admission_rejects_invisible_name_and_description) {
    static const char bidi_name[] = "trusted\xE2\x80\xAE" "txt";
    static const char isolate_description[] =
        "safe\xE2\x81\xA6" "hidden\xE2\x81\xA9";
    static const char variation_name[] = "work\xEF\xB8\x8F";
    gitswitch_ctx_t context;
    account_t account;

    memset(&context, 0, sizeof(context));
    fill_account(&account, bidi_name, "description");
    CHECK_EQ_INT(config_add_account(&context, &account), -1);
    CHECK_EQ_INT(context.account_count, 0);
    CHECK(strstr(get_last_error()->message, bidi_name) == NULL);

    fill_account(&account, "work", isolate_description);
    CHECK_EQ_INT(config_add_account(&context, &account), -1);
    CHECK_EQ_INT(context.account_count, 0);
    CHECK(strstr(get_last_error()->message, isolate_description) == NULL);

    fill_account(&account, variation_name, "description");
    CHECK_EQ_INT(config_add_account(&context, &account), -1);
    CHECK_EQ_INT(context.account_count, 0);
}

TEST(account_selectors_and_validation_never_reflect_invisible_bytes) {
    static const char bidi_selector[] = "safe\xE2\x80\xAE" "txt";
    static const char bidi_email[] = "safe\xE2\x80\xAE" "@example.test";
    gitswitch_ctx_t context;
    account_t account;

    memset(&context, 0, sizeof(context));
    fill_account(&context.accounts[0], "visible", "visible description");
    context.account_count = 1;

    CHECK(config_find_account(&context, bidi_selector) == NULL);
    CHECK(strstr(get_last_error()->message, bidi_selector) == NULL);
    CHECK(config_find_account_destructive(&context, bidi_selector) == NULL);
    CHECK(strstr(get_last_error()->message, bidi_selector) == NULL);

    context.config.resuming = true;
    CHECK_EQ_INT(accounts_switch(&context, bidi_selector), -1);
    CHECK(strstr(get_last_error()->message, bidi_selector) == NULL);

    memset(&context, 0, sizeof(context));
    fill_account(&account, "visible", "visible description");
    (void)snprintf(account.email, sizeof(account.email), "%s", bidi_email);
    CHECK_EQ_INT(config_add_account(&context, &account), -1);
    CHECK(strstr(get_last_error()->message, bidi_email) == NULL);
}

static int run_interactive_add(const char *input_text, char *output,
                               size_t output_size, gitswitch_ctx_t *context) {
    FILE *input = tmpfile();
    FILE *capture = tmpfile();
    int saved_stdin = -1;
    int saved_stdout = -1;
    int result = -2;
    size_t length;

    if (!input || !capture || !output || output_size == 0 || !context) {
        if (input) fclose(input);
        if (capture) fclose(capture);
        return -2;
    }
    if (fwrite(input_text, 1, strlen(input_text), input) != strlen(input_text) ||
        fflush(input) != 0 || fseek(input, 0, SEEK_SET) != 0) {
        goto cleanup;
    }
    saved_stdin = dup(STDIN_FILENO);
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdin < 0 || saved_stdout < 0 || fflush(stdout) != 0 ||
        dup2(fileno(input), STDIN_FILENO) != STDIN_FILENO ||
        dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        goto cleanup;
    }
    result = accounts_add_interactive(context);
    if (fflush(stdout) != 0) result = -2;

cleanup:
    if (saved_stdin >= 0) {
        (void)dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }
    if (saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    rewind(capture);
    length = fread(output, 1, output_size - 1U, capture);
    output[length] = '\0';
    fclose(input);
    fclose(capture);
    return result;
}

TEST(interactive_add_rejects_controls_before_summary_or_error_output) {
    static const char bidi[] = "safe\xE2\x80\xAE" "txt";
    static const char isolate_description[] =
        "visible\xE2\x81\xA6" "hidden\xE2\x81\xA9";
    char input[1024];
    char output[16384];
    gitswitch_ctx_t context;

    memset(&context, 0, sizeof(context));
    context.config.default_scope = GIT_SCOPE_LOCAL;
    context.config.assume_yes = true;
    CHECK((size_t)snprintf(input, sizeof(input),
                           "%s\nvisible-name\nvisible@example.test\n%s\n"
                           "visible description\n\n\n\n",
                           bidi, isolate_description) < sizeof(input));
    CHECK_EQ_INT(run_interactive_add(input, output, sizeof(output),
                                     &context), 0);
    CHECK_EQ_INT(context.account_count, 1);
    CHECK(strstr(output, bidi) == NULL);
    CHECK(strstr(output, isolate_description) == NULL);
    CHECK(strstr(output, "Name: visible-name") != NULL);
    CHECK(strstr(output, "Description: visible description") != NULL);
}

static int write_fixture(const char *path, const char *contents) {
    FILE *file = fopen(path, "w");
    int result = 0;

    if (!file) return -1;
    if (fputs(contents, file) == EOF || fflush(file) != 0 ||
        fsync(fileno(file)) != 0) {
        result = -1;
    }
    if (fclose(file) != 0) result = -1;
    if (result == 0 && chmod(path, 0600) != 0) result = -1;
    return result;
}

static int capture_accounts_call(const gitswitch_ctx_t *context,
                                 bool status, char *output,
                                 size_t output_size) {
    FILE *capture = tmpfile();
    int saved_stdout;
    int call_result;
    size_t length;

    if (!capture || !context || !output || output_size == 0) return -2;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        fclose(capture);
        return -2;
    }
    if (fflush(stdout) != 0 ||
        dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        close(saved_stdout);
        fclose(capture);
        return -2;
    }
    call_result = status ? accounts_show_status(context)
                         : accounts_list(context);
    if (fflush(stdout) != 0 ||
        dup2(saved_stdout, STDOUT_FILENO) != STDOUT_FILENO) {
        call_result = -2;
    }
    close(saved_stdout);
    rewind(capture);
    length = fread(output, 1, output_size - 1, capture);
    output[length] = '\0';
    fclose(capture);
    return call_result;
}

static int unavailable_git_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    (void)argv;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 1;
    }
    return -1;
}

TEST(load_rejects_bidi_and_valid_unicode_lists_and_reports_exactly) {
    static const char hostile_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "[accounts.1]\n"
        "name = \"trusted\xE2\x80\xAE" "txt\"\n"
        "email = \"unicode@example.test\"\n"
        "description = \"description\"\n";
    static const char valid_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "[accounts.1]\n"
        "name = \"Jos\xC3\xA9 \xE4\xBA\x8B\"\n"
        "email = \"unicode@example.test\"\n"
        "description = \"Cafe\xCC\x81 \xF0\x9F\x9A\x80\"\n";
    char root[] = "/tmp/gitswitch-unicode-XXXXXX";
    char path[512];
    char output[16384];
    gitswitch_ctx_t context;
    command_runner_fn previous_runner;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/config.toml", root) <
          sizeof(path));
    CHECK_EQ_INT(write_fixture(path, hostile_config), 0);
    memset(&context, 0, sizeof(context));
    CHECK_EQ_INT(config_load(&context, path), -1);
    CHECK_EQ_INT(context.account_count, 0);

    CHECK_EQ_INT(write_fixture(path, valid_config), 0);
    memset(&context, 0, sizeof(context));
    CHECK_EQ_INT(config_load(&context, path), 0);
    CHECK_EQ_INT(context.account_count, 1);
    if (context.account_count != 1) return;
    context.current_account = &context.accounts[0];

    CHECK_EQ_INT(capture_accounts_call(&context, false, output,
                                       sizeof(output)), 0);
    CHECK(strstr(output, "Jos\xC3\xA9 \xE4\xBA\x8B") != NULL);
    CHECK(strstr(output, "Cafe\xCC\x81 \xF0\x9F\x9A\x80") != NULL);
    CHECK(strchr(output, '\x1B') == NULL);

    previous_runner = run_set_runner(unavailable_git_runner);
    CHECK_EQ_INT(capture_accounts_call(&context, true, output,
                                       sizeof(output)), -1);
    run_set_runner(previous_runner);
    CHECK(strstr(output,
                 "Active Account: Jos\xC3\xA9 \xE4\xBA\x8B (ID: 1)") !=
          NULL);
    CHECK(strstr(output,
                 "Description: Cafe\xCC\x81 \xF0\x9F\x9A\x80") != NULL);
    CHECK(strchr(output, '\x1B') == NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(rejects_every_unicode_16_default_ignorable_codepoint);
    RUN_TEST(bidi_marks_zero_width_and_variation_selectors_fail_text_gates);
    RUN_TEST(visible_unicode_combining_marks_and_strict_utf8_remain_exact);
    RUN_TEST(account_admission_rejects_invisible_name_and_description);
    RUN_TEST(account_selectors_and_validation_never_reflect_invisible_bytes);
    RUN_TEST(interactive_add_rejects_controls_before_summary_or_error_output);
    RUN_TEST(load_rejects_bidi_and_valid_unicode_lists_and_reports_exactly);
TEST_MAIN_END()
