/* Focused display regressions for AR-08 M32.
 *
 * The color path must preserve the complete diagnostic payload, and a
 * variadic formatting failure must be detected before a status prefix or any
 * partially formatted bytes reach stdout. */
#include "test.h"
#include "display.h"
#include "error.h"

#include <locale.h>
#include <wchar.h>

typedef void (*stdout_emitter_fn)(void *context);

static char *capture_stdout(stdout_emitter_fn emit, void *context,
                            size_t *length_out) {
    FILE *capture;
    int saved_stdout;
    int restore_result;
    long end;
    size_t length;
    char *output;

    if (!emit || !length_out) return NULL;
    *length_out = 0;
    capture = tmpfile();
    if (!capture) return NULL;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        fclose(capture);
        return NULL;
    }
    if (fflush(stdout) != 0 ||
        dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        close(saved_stdout);
        fclose(capture);
        return NULL;
    }

    emit(context);
    if (fflush(stdout) != 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
        fclose(capture);
        return NULL;
    }
    restore_result = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    if (restore_result != STDOUT_FILENO ||
        fseek(capture, 0, SEEK_END) != 0) {
        fclose(capture);
        return NULL;
    }
    end = ftell(capture);
    if (end < 0 || (unsigned long)end > SIZE_MAX - 1U ||
        fseek(capture, 0, SEEK_SET) != 0) {
        fclose(capture);
        return NULL;
    }

    length = (size_t)end;
    output = malloc(length + 1U);
    if (!output) {
        fclose(capture);
        return NULL;
    }
    if (length > 0 && fread(output, 1, length, capture) != length) {
        free(output);
        fclose(capture);
        return NULL;
    }
    output[length] = '\0';
    fclose(capture);
    *length_out = length;
    return output;
}

static char *strip_sgr_sequences(const char *input, size_t input_length,
                                 size_t *output_length) {
    char *plain;
    size_t source = 0;
    size_t destination = 0;

    if (!input || !output_length || input_length == SIZE_MAX) return NULL;
    plain = malloc(input_length + 1U);
    if (!plain) return NULL;

    while (source < input_length) {
        if ((unsigned char)input[source] == 0x1bU &&
            source + 1U < input_length && input[source + 1U] == '[') {
            size_t cursor = source + 2U;
            while (cursor < input_length &&
                   ((input[cursor] >= '0' && input[cursor] <= '9') ||
                    input[cursor] == ';')) {
                cursor++;
            }
            if (cursor < input_length && input[cursor] == 'm') {
                source = cursor + 1U;
                continue;
            }
        }
        plain[destination++] = input[source++];
    }
    plain[destination] = '\0';
    *output_length = destination;
    return plain;
}

typedef struct {
    const char *payload;
    bool color;
} long_status_context_t;

static void emit_long_error(void *opaque) {
    const long_status_context_t *context = opaque;
    (void)display_init(context->color, !context->color);
    display_status("error", "%s", context->payload);
}

TEST(long_colored_status_preserves_every_payload_byte) {
    enum { PAYLOAD_LENGTH = 900 };
    static const char suffix[] = "--M32-TAIL--";
    static const char colored_ending[] = COLOR_RESET "\n";
    char payload[PAYLOAD_LENGTH + 1U];
    char expected[sizeof(STATUS_ERROR) + PAYLOAD_LENGTH + 2U];
    long_status_context_t context;
    char *plain_output;
    char *colored_output;
    char *stripped_output;
    size_t plain_length;
    size_t colored_length;
    size_t stripped_length;
    int expected_length;

    memset(payload, 'x', PAYLOAD_LENGTH);
    memcpy(payload + PAYLOAD_LENGTH - (sizeof(suffix) - 1U), suffix,
           sizeof(suffix) - 1U);
    payload[PAYLOAD_LENGTH] = '\0';
    expected_length = snprintf(expected, sizeof(expected), "%s %s\n",
                               STATUS_ERROR, payload);
    CHECK_EQ_INT(expected_length, (int)sizeof(expected) - 1);
    if (expected_length < 0 || (size_t)expected_length >= sizeof(expected)) {
        return;
    }

    context.payload = payload;
    context.color = false;
    plain_output = capture_stdout(emit_long_error, &context, &plain_length);
    CHECK(plain_output != NULL);
    if (!plain_output) return;

    context.color = true;
    colored_output = capture_stdout(emit_long_error, &context,
                                    &colored_length);
    CHECK(colored_output != NULL);
    if (!colored_output) {
        free(plain_output);
        return;
    }
    stripped_output = strip_sgr_sequences(colored_output, colored_length,
                                          &stripped_length);
    CHECK(stripped_output != NULL);
    if (!stripped_output) {
        free(colored_output);
        free(plain_output);
        return;
    }

    CHECK_EQ_INT(plain_length, (size_t)expected_length);
    CHECK(memcmp(plain_output, expected, (size_t)expected_length + 1U) == 0);
    CHECK(strstr(plain_output, suffix) != NULL);
    CHECK(strstr(colored_output, COLOR_RED) != NULL);
    CHECK(strstr(colored_output, COLOR_RESET) != NULL);
    CHECK(colored_length >= sizeof(colored_ending) - 1U &&
          memcmp(colored_output + colored_length -
                     (sizeof(colored_ending) - 1U),
                 colored_ending, sizeof(colored_ending) - 1U) == 0);
    CHECK_EQ_INT(stripped_length, plain_length);
    CHECK(memcmp(stripped_output, plain_output, plain_length + 1U) == 0);
    CHECK(strstr(stripped_output, suffix) != NULL);

    free(stripped_output);
    free(colored_output);
    free(plain_output);
}

static void emit_unrepresentable_diagnostics(void *unused) {
    const wint_t invalid_wide_character = (wint_t)0xd800;
    (void)unused;

    (void)display_init(true, false);
    display_status("error", "status-prefix-%lc-status-suffix",
                   invalid_wide_character);
    display_error("context", "error-prefix-%lc-error-suffix",
                  invalid_wide_character);
    display_warning("warning-prefix-%lc-warning-suffix",
                    invalid_wide_character);
    display_success("success-prefix-%lc-success-suffix",
                    invalid_wide_character);
    display_info("info-prefix-%lc-info-suffix", invalid_wide_character);
}

TEST(formatting_failure_emits_no_partial_or_uninitialized_output) {
    char *output;
    size_t output_length;

    CHECK(setlocale(LC_CTYPE, "C") != NULL);
    output = capture_stdout(emit_unrepresentable_diagnostics, NULL,
                            &output_length);
    CHECK(output != NULL);
    if (!output) return;

    CHECK_EQ_INT(output_length, 0);
    CHECK(output[0] == '\0');
    free(output);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(long_colored_status_preserves_every_payload_byte);
    RUN_TEST(formatting_failure_emits_no_partial_or_uninitialized_output);
TEST_MAIN_END()
