/* Direct display contracts for AR-08 L30, including the M32 long-format
 * regression and L21 retained-public-API link probe. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test.h"
#include "display.h"
#include "error.h"

#include <locale.h>
#include <sys/ioctl.h>
#include <wchar.h>

typedef void (*output_emitter_fn)(void *context);

typedef struct {
    char *standard_output;
    size_t standard_output_length;
    char *standard_error;
    size_t standard_error_length;
} captured_output_t;

typedef struct {
    const char *name;
    char *value;
    bool was_set;
} saved_environment_t;

typedef struct {
    saved_environment_t variables[4];
    size_t count;
} saved_color_environment_t;

static void captured_output_free(captured_output_t *captured) {
    if (!captured) return;
    free(captured->standard_output);
    free(captured->standard_error);
    memset(captured, 0, sizeof(*captured));
}

static int read_capture(FILE *stream, char **text_out, size_t *length_out) {
    long end;
    size_t length;
    char *text;

    if (!stream || !text_out || !length_out) return -1;
    *text_out = NULL;
    *length_out = 0;
    if (fseek(stream, 0, SEEK_END) != 0) return -1;
    end = ftell(stream);
    if (end < 0 || (uintmax_t)end > (uintmax_t)SIZE_MAX - 1U ||
        fseek(stream, 0, SEEK_SET) != 0) {
        return -1;
    }

    length = (size_t)end;
    text = malloc(length + 1U);
    if (!text) return -1;
    if (length > 0 && fread(text, 1, length, stream) != length) {
        free(text);
        return -1;
    }
    text[length] = '\0';
    *text_out = text;
    *length_out = length;
    return 0;
}

static int capture_output(output_emitter_fn emit, void *context,
                          captured_output_t *captured) {
    FILE *stdout_capture = NULL;
    FILE *stderr_capture = NULL;
    int saved_stdout = -1;
    int saved_stderr = -1;
    bool stdout_redirected = false;
    bool stderr_redirected = false;
    int result = -1;

    if (!emit || !captured) return -1;
    memset(captured, 0, sizeof(*captured));
    stdout_capture = tmpfile();
    stderr_capture = tmpfile();
    if (!stdout_capture || !stderr_capture || fflush(NULL) != 0) goto cleanup;

    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0) goto cleanup;
    if (dup2(fileno(stdout_capture), STDOUT_FILENO) != STDOUT_FILENO) {
        goto cleanup;
    }
    stdout_redirected = true;
    if (dup2(fileno(stderr_capture), STDERR_FILENO) != STDERR_FILENO) {
        goto cleanup;
    }
    stderr_redirected = true;

    emit(context);
    if (fflush(stdout) != 0 || fflush(stderr) != 0) goto cleanup;
    if (dup2(saved_stdout, STDOUT_FILENO) != STDOUT_FILENO) goto cleanup;
    stdout_redirected = false;
    if (dup2(saved_stderr, STDERR_FILENO) != STDERR_FILENO) goto cleanup;
    stderr_redirected = false;

    if (read_capture(stdout_capture, &captured->standard_output,
                     &captured->standard_output_length) != 0 ||
        read_capture(stderr_capture, &captured->standard_error,
                     &captured->standard_error_length) != 0) {
        captured_output_free(captured);
        goto cleanup;
    }
    result = 0;

cleanup:
    if (stdout_redirected && saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
    }
    if (stderr_redirected && saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
    }
    if (saved_stdout >= 0) close(saved_stdout);
    if (saved_stderr >= 0) close(saved_stderr);
    if (stdout_capture) fclose(stdout_capture);
    if (stderr_capture) fclose(stderr_capture);
    return result;
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

static int save_environment(saved_environment_t *saved, const char *name) {
    const char *current;

    if (!saved || !name) return -1;
    memset(saved, 0, sizeof(*saved));
    saved->name = name;
    current = getenv(name);
    if (!current) return 0;
    saved->value = strdup(current);
    if (!saved->value) return -1;
    saved->was_set = true;
    return 0;
}

static int restore_environment(saved_environment_t *saved) {
    int result;

    if (!saved || !saved->name) return -1;
    result = saved->was_set ? setenv(saved->name, saved->value, 1)
                            : unsetenv(saved->name);
    free(saved->value);
    memset(saved, 0, sizeof(*saved));
    return result;
}

/* Automatic-color cases must be hermetic with respect to all policy inputs,
 * including overrides inherited from a developer shell or hosted runner. */
static int isolate_color_environment(saved_color_environment_t *saved) {
    static const char *const names[] = {
        "TERM", "COLORTERM", "NO_COLOR", "CLICOLOR_FORCE"
    };

    if (!saved) return -1;
    memset(saved, 0, sizeof(*saved));
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (save_environment(&saved->variables[i], names[i]) != 0) {
            goto fail;
        }
        saved->count++;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (unsetenv(names[i]) != 0) goto fail;
    }
    return 0;

fail:
    while (saved->count > 0) {
        saved->count--;
        (void)restore_environment(&saved->variables[saved->count]);
    }
    return -1;
}

static int restore_color_environment(saved_color_environment_t *saved) {
    int result = 0;

    if (!saved) return -1;
    while (saved->count > 0) {
        saved->count--;
        if (restore_environment(&saved->variables[saved->count]) != 0) {
            result = -1;
        }
    }
    return result;
}

static int set_color_environment(const char *term, const char *colorterm) {
    if ((term ? setenv("TERM", term, 1) : unsetenv("TERM")) != 0) return -1;
    if ((colorterm ? setenv("COLORTERM", colorterm, 1)
                   : unsetenv("COLORTERM")) != 0) {
        return -1;
    }
    return 0;
}

static int initialize_with_stdout(int stdout_fd, bool force_color,
                                  bool no_color, bool *supports_color) {
    int saved_stdout;
    int result = -1;

    if (stdout_fd < 0 || !supports_color || fflush(stdout) != 0) return -1;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) return -1;
    if (dup2(stdout_fd, STDOUT_FILENO) == STDOUT_FILENO) {
        if (display_init(force_color, no_color) == 0) {
            *supports_color = display_supports_color();
            result = 0;
        }
        if (dup2(saved_stdout, STDOUT_FILENO) != STDOUT_FILENO) result = -1;
    }
    close(saved_stdout);
    return result;
}

/* Returns 1 only when the host cannot provide a usable pseudo-terminal. */
static int open_test_pty(int *master_out, int *slave_out) {
    struct winsize window_size;
    char *slave_name;
    int master;
    int slave;

    if (!master_out || !slave_out) return -1;
    *master_out = -1;
    *slave_out = -1;
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) return 1;
    if (grantpt(master) != 0 || unlockpt(master) != 0 ||
        (slave_name = ptsname(master)) == NULL) {
        close(master);
        return 1;
    }
    slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        close(master);
        return 1;
    }

    memset(&window_size, 0, sizeof(window_size));
    window_size.ws_col = 80;
    window_size.ws_row = 24;
    if (ioctl(slave, TIOCSWINSZ, &window_size) != 0) {
        close(slave);
        close(master);
        return -1;
    }

    *master_out = master;
    *slave_out = slave;
    return 0;
}

TEST(retained_public_display_api_links) {
    int (*init_fn)(bool, bool) = display_init;
    void (*header_fn)(const char *) = display_header;
    void (*status_fn)(const char *, const char *, ...) = display_status;
    void (*error_fn)(const char *, const char *, ...) = display_error;
    void (*warning_fn)(const char *, ...) = display_warning;
    void (*success_fn)(const char *, ...) = display_success;
    void (*info_fn)(const char *, ...) = display_info;
    char *(*colorize_fn)(const char *, const char *) = display_colorize;
    bool (*supports_color_fn)(void) = display_supports_color;
    void (*config_info_fn)(const gitswitch_ctx_t *) = display_config_info;

    CHECK(init_fn != NULL);
    CHECK(header_fn != NULL);
    CHECK(status_fn != NULL);
    CHECK(error_fn != NULL);
    CHECK(warning_fn != NULL);
    CHECK(success_fn != NULL);
    CHECK(info_fn != NULL);
    CHECK(colorize_fn != NULL);
    CHECK(supports_color_fn != NULL);
    CHECK(config_info_fn != NULL);
}

TEST(explicit_color_flags_have_deterministic_precedence) {
    saved_color_environment_t saved;

    if (isolate_color_environment(&saved) != 0) {
        CHECK(false);
        return;
    }
    CHECK_EQ_INT(setenv("NO_COLOR", "inherited-disable", 1), 0);
    CHECK_EQ_INT(display_init(false, true), 0);
    CHECK(!display_supports_color());
    CHECK_EQ_INT(display_init(true, false), 0);
    CHECK(display_supports_color());
    CHECK_EQ_INT(setenv("CLICOLOR_FORCE", "1", 1), 0);
    CHECK_EQ_INT(display_init(true, true), 0);
    CHECK(!display_supports_color());
    CHECK_EQ_INT(restore_color_environment(&saved), 0);
}

TEST(environment_color_policy_precedence_and_values_are_exact) {
    saved_color_environment_t saved;

    if (isolate_color_environment(&saved) != 0) {
        CHECK(false);
        return;
    }

    /* NO_COLOR wins over CLICOLOR_FORCE, and every non-empty NO_COLOR value
     * (including the commonly misunderstood string "0") disables color. */
    CHECK_EQ_INT(setenv("NO_COLOR", "1", 1), 0);
    CHECK_EQ_INT(setenv("CLICOLOR_FORCE", "1", 1), 0);
    CHECK_EQ_INT(display_init(false, false), 0);
    CHECK(!display_supports_color());
    CHECK_EQ_INT(setenv("NO_COLOR", "0", 1), 0);
    CHECK_EQ_INT(display_init(false, false), 0);
    CHECK(!display_supports_color());

    /* Empty NO_COLOR is inactive. A nonzero force value then enables color
     * even when automatic terminal detection would reject this stream. */
    CHECK_EQ_INT(setenv("NO_COLOR", "", 1), 0);
    CHECK_EQ_INT(setenv("TERM", "dumb", 1), 0);
    CHECK_EQ_INT(unsetenv("COLORTERM"), 0);
    CHECK_EQ_INT(display_init(false, false), 0);
    CHECK(display_supports_color());

    /* Empty and literal-zero CLICOLOR_FORCE values both fall through to
     * automatic detection; TERM=dumb keeps that result deterministic. */
    CHECK_EQ_INT(setenv("CLICOLOR_FORCE", "", 1), 0);
    CHECK_EQ_INT(display_init(false, false), 0);
    CHECK(!display_supports_color());
    CHECK_EQ_INT(setenv("CLICOLOR_FORCE", "0", 1), 0);
    CHECK_EQ_INT(display_init(false, false), 0);
    CHECK(!display_supports_color());

    CHECK_EQ_INT(restore_color_environment(&saved), 0);
}

typedef struct {
    bool supports_color;
} automatic_color_context_t;

static void emit_automatic_color_probe(void *opaque) {
    automatic_color_context_t *context = opaque;

    (void)display_init(false, false);
    context->supports_color = display_supports_color();
}

TEST(automatic_color_requires_tty_and_color_environment) {
    saved_color_environment_t saved;
    captured_output_t captured;
    automatic_color_context_t context;
    bool supports_color = false;
    int master = -1;
    int slave = -1;
    int pty_result;

    if (isolate_color_environment(&saved) != 0) {
        CHECK(false);
        return;
    }

    CHECK_EQ_INT(set_color_environment("xterm-256color", "truecolor"), 0);
    context.supports_color = true;
    CHECK_EQ_INT(capture_output(emit_automatic_color_probe, &context,
                                &captured), 0);
    if (captured.standard_output) {
        CHECK(!context.supports_color);
        CHECK_EQ_INT(captured.standard_output_length, 0);
        CHECK_EQ_INT(captured.standard_error_length, 0);
        captured_output_free(&captured);
    }

    pty_result = open_test_pty(&master, &slave);
    if (pty_result == 1) {
        CHECK_EQ_INT(restore_color_environment(&saved), 0);
        TS_SKIP("pty", "host cannot provide a usable pseudo-terminal");
    }
    CHECK_EQ_INT(pty_result, 0);
    if (pty_result != 0) goto cleanup;

    CHECK_EQ_INT(set_color_environment("xterm-256color", NULL), 0);
    CHECK_EQ_INT(initialize_with_stdout(slave, false, false,
                                        &supports_color), 0);
    CHECK(supports_color);

    CHECK_EQ_INT(set_color_environment("dumb", "truecolor"), 0);
    supports_color = false;
    CHECK_EQ_INT(initialize_with_stdout(slave, false, false,
                                        &supports_color), 0);
    CHECK(supports_color);

    CHECK_EQ_INT(set_color_environment("dumb", NULL), 0);
    supports_color = true;
    CHECK_EQ_INT(initialize_with_stdout(slave, false, false,
                                        &supports_color), 0);
    CHECK(!supports_color);

    CHECK_EQ_INT(set_color_environment(NULL, NULL), 0);
    supports_color = true;
    CHECK_EQ_INT(initialize_with_stdout(slave, false, false,
                                        &supports_color), 0);
    CHECK(!supports_color);

cleanup:
    if (slave >= 0) close(slave);
    if (master >= 0) close(master);
    CHECK_EQ_INT(restore_color_environment(&saved), 0);
}

static void check_owned_colorized_result(const char *text, const char *type,
                                         const char *expected) {
    char *result = display_colorize(text, type);

    CHECK(result != NULL);
    if (!result) return;
    CHECK(result != text);
    CHECK_STR_EQ(result, expected);
    free(result);
}

TEST(colorize_maps_exact_styles_resets_and_passthroughs) {
    static const char sample[] = "sample";

    CHECK_EQ_INT(display_init(true, false), 0);
    check_owned_colorized_result(sample, "success",
                                 COLOR_GREEN "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "error",
                                 COLOR_RED "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "warning",
                                 COLOR_YELLOW "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "info",
                                 COLOR_BLUE "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "header",
                                 COLOR_BOLD COLOR_CYAN "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "current",
                                 COLOR_BOLD COLOR_GREEN "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "inactive",
                                 COLOR_DIM "sample" COLOR_RESET);
    check_owned_colorized_result(sample, "unknown", sample);
    check_owned_colorized_result(sample, NULL, sample);
    CHECK(display_colorize(NULL, "success") == NULL);

    CHECK_EQ_INT(display_init(false, true), 0);
    check_owned_colorized_result(sample, "success", sample);
}

/* Retaining more results than the historical rotating-slot count must not let
 * later, larger calls overwrite or invalidate earlier output. The inputs stay
 * live for the whole test so any change is owned by display_colorize itself. */
TEST(colorize_results_remain_valid_across_later_growth) {
    enum { RESULT_COUNT = 17, INPUT_CAPACITY = 160, EXPECTED_CAPACITY = 192 };
    char inputs[RESULT_COUNT][INPUT_CAPACITY];
    char expected[RESULT_COUNT][EXPECTED_CAPACITY];
    char *results[RESULT_COUNT];

    CHECK_EQ_INT(display_init(true, false), 0);
    for (size_t i = 0; i < RESULT_COUNT; i++) {
        int prefix_length = snprintf(inputs[i], sizeof(inputs[i]),
                                     "retained-%02zu-", i);
        size_t target_length = 24U + i * 6U;
        size_t cursor;

        CHECK(prefix_length > 0);
        cursor = prefix_length > 0 ? (size_t)prefix_length : 0U;
        CHECK(target_length < sizeof(inputs[i]));
        while (cursor < target_length) {
            inputs[i][cursor++] = (char)('a' + (int)(i % 26U));
        }
        inputs[i][cursor] = '\0';
        CHECK(snprintf(expected[i], sizeof(expected[i]), "%s%s%s",
                       COLOR_GREEN, inputs[i], COLOR_RESET) > 0);
        results[i] = display_colorize(inputs[i], "success");
        CHECK(results[i] != NULL);
    }

    for (size_t i = 0; i < RESULT_COUNT; i++) {
        for (size_t j = 0; j < i; j++) {
            CHECK(results[i] != results[j]);
        }
        if (results[i]) {
            CHECK_STR_EQ(results[i], expected[i]);
            free(results[i]);
        }
    }
}

typedef struct {
    bool color;
} color_output_context_t;

static void emit_status_matrix(void *opaque) {
    const color_output_context_t *context = opaque;
    void (*status_fn)(const char *, const char *, ...) = display_status;

    (void)display_init(context->color, !context->color);
    display_status("success", "success-%s-%d", "value", 1);
    display_status("error", "error-%s-%d", "value", 2);
    display_status("warning", "warning-%s-%d", "value", 3);
    display_status("info", "info-%s-%d", "value", 4);
    display_status("other", "other-%s-%d", "value", 5);
    status_fn("info", "");
    status_fn(NULL, "ignored");
    status_fn("info", NULL);
}

TEST(status_levels_and_variadic_formatting_are_exact) {
    /* AR-10 L4: error-level status lines follow the Unix convention and go
     * to stderr; every other level stays on stdout. */
    static const char expected[] =
        "[OK] success-value-1\n"
        "[WARN] warning-value-3\n"
        "[INFO] info-value-4\n"
        "- other-value-5\n"
        "[INFO]\n";
    static const char expected_error[] = "[ERROR] error-value-2\n";
    color_output_context_t context;
    captured_output_t plain;
    captured_output_t colored;
    char *stripped;
    size_t stripped_length;

    context.color = false;
    CHECK_EQ_INT(capture_output(emit_status_matrix, &context, &plain), 0);
    if (!plain.standard_output) return;
    CHECK_STR_EQ(plain.standard_output, expected);
    CHECK(plain.standard_error != NULL);
    if (plain.standard_error) {
        CHECK_STR_EQ(plain.standard_error, expected_error);
    }

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_status_matrix, &context, &colored), 0);
    if (!colored.standard_output) {
        captured_output_free(&plain);
        return;
    }
    stripped = strip_sgr_sequences(colored.standard_output,
                                   colored.standard_output_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_EQ_INT(stripped_length, plain.standard_output_length);
        CHECK_STR_EQ(stripped, expected);
        free(stripped);
    }
    CHECK(strstr(colored.standard_output, COLOR_GREEN STATUS_SUCCESS
                 COLOR_RESET) != NULL);
    CHECK(colored.standard_error != NULL &&
          strstr(colored.standard_error, COLOR_RED STATUS_ERROR
                 COLOR_RESET) != NULL);
    CHECK(strstr(colored.standard_output, COLOR_YELLOW STATUS_WARNING
                 COLOR_RESET) != NULL);
    CHECK(strstr(colored.standard_output, COLOR_BLUE STATUS_INFO
                 COLOR_RESET) != NULL);
    stripped = strip_sgr_sequences(colored.standard_error,
                                   colored.standard_error_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_STR_EQ(stripped, expected_error);
        free(stripped);
    }

    captured_output_free(&colored);
    captured_output_free(&plain);
}

static void emit_wrapper_matrix(void *opaque) {
    const color_output_context_t *context = opaque;
    void (*error_fn)(const char *, const char *, ...) = display_error;
    void (*warning_fn)(const char *, ...) = display_warning;
    void (*success_fn)(const char *, ...) = display_success;
    void (*info_fn)(const char *, ...) = display_info;

    (void)display_init(context->color, !context->color);
    display_error("context", "problem-%s-%d", "value", 1);
    display_error(NULL, "plain-%d", 2);
    display_error("", "empty-context");
    error_fn("context", "");
    error_fn("context", NULL);
    display_warning("warning-%d", 3);
    warning_fn("");
    warning_fn(NULL);
    display_success("success-%s", "four");
    success_fn("");
    success_fn(NULL);
    display_info("info-%d", 5);
    info_fn("");
    info_fn(NULL);
}

TEST(message_wrappers_obey_streams_and_null_empty_context_contracts) {
    /* AR-10 L4: display_error emits on stderr; the other wrappers on stdout. */
    static const char expected[] =
        "[WARN] warning-3\n"
        "[WARN]\n"
        "[OK] success-four\n"
        "[OK]\n"
        "[INFO] info-5\n"
        "[INFO]\n";
    static const char expected_error[] =
        "[ERROR] context: problem-value-1\n"
        "[ERROR] plain-2\n"
        "[ERROR] empty-context\n";
    color_output_context_t context;
    captured_output_t plain;
    captured_output_t colored;
    char *stripped;
    size_t stripped_length;

    context.color = false;
    CHECK_EQ_INT(capture_output(emit_wrapper_matrix, &context, &plain), 0);
    if (!plain.standard_output) return;
    CHECK_STR_EQ(plain.standard_output, expected);
    CHECK(plain.standard_error != NULL);
    if (plain.standard_error) {
        CHECK_STR_EQ(plain.standard_error, expected_error);
    }

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_wrapper_matrix, &context, &colored), 0);
    if (!colored.standard_output) {
        captured_output_free(&plain);
        return;
    }
    stripped = strip_sgr_sequences(colored.standard_output,
                                   colored.standard_output_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_EQ_INT(stripped_length, plain.standard_output_length);
        CHECK_STR_EQ(stripped, plain.standard_output);
        free(stripped);
    }
    stripped = strip_sgr_sequences(colored.standard_error,
                                   colored.standard_error_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_STR_EQ(stripped, expected_error);
        free(stripped);
    }

    captured_output_free(&colored);
    captured_output_free(&plain);
}

static int append_text(char *buffer, size_t capacity, size_t *length,
                       const char *text) {
    size_t text_length;

    if (!buffer || !length || !text) return -1;
    text_length = strlen(text);
    if (*length >= capacity || text_length > capacity - *length - 1U) {
        return -1;
    }
    memcpy(buffer + *length, text, text_length);
    *length += text_length;
    buffer[*length] = '\0';
    return 0;
}

static int build_header_expected(char *buffer, size_t capacity, bool color) {
    size_t length = 0;
    int index;

    if (!buffer || capacity == 0) return -1;
    buffer[0] = '\0';
    if (append_text(buffer, capacity, &length, "┌") != 0) return -1;
    for (index = 0; index < 38; index++) {
        if (append_text(buffer, capacity, &length, "─") != 0) return -1;
    }
    if (append_text(buffer, capacity, &length,
                    "┐\n│                ") != 0 ||
        (color && append_text(buffer, capacity, &length,
                              COLOR_BOLD COLOR_CYAN) != 0) ||
        append_text(buffer, capacity, &length, "Title") != 0 ||
        (color && append_text(buffer, capacity, &length, COLOR_RESET) != 0) ||
        append_text(buffer, capacity, &length,
                    "                 │\n└") != 0) {
        return -1;
    }
    for (index = 0; index < 38; index++) {
        if (append_text(buffer, capacity, &length, "─") != 0) return -1;
    }
    return append_text(buffer, capacity, &length, "┘\n");
}

static void emit_header(void *opaque) {
    const color_output_context_t *context = opaque;
    void (*header_fn)(const char *) = display_header;

    (void)display_init(context->color, !context->color);
    display_header("Title");
    header_fn(NULL);
}

TEST(header_bytes_and_ansi_stripped_parity_are_exact) {
    char plain_expected[512];
    char colored_expected[512];
    color_output_context_t context;
    captured_output_t plain;
    captured_output_t colored;
    char *stripped;
    size_t stripped_length;

    CHECK_EQ_INT(build_header_expected(plain_expected,
                                       sizeof(plain_expected), false), 0);
    CHECK_EQ_INT(build_header_expected(colored_expected,
                                       sizeof(colored_expected), true), 0);

    context.color = false;
    CHECK_EQ_INT(capture_output(emit_header, &context, &plain), 0);
    if (!plain.standard_output) return;
    CHECK_STR_EQ(plain.standard_output, plain_expected);
    CHECK_EQ_INT(plain.standard_error_length, 0);

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_header, &context, &colored), 0);
    if (!colored.standard_output) {
        captured_output_free(&plain);
        return;
    }
    CHECK_STR_EQ(colored.standard_output, colored_expected);
    CHECK_EQ_INT(colored.standard_error_length, 0);
    stripped = strip_sgr_sequences(colored.standard_output,
                                   colored.standard_output_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_EQ_INT(stripped_length, plain.standard_output_length);
        CHECK_STR_EQ(stripped, plain.standard_output);
        free(stripped);
    }

    captured_output_free(&colored);
    captured_output_free(&plain);
}

typedef struct {
    const gitswitch_ctx_t *application;
    bool color;
} config_info_context_t;

static void emit_config_info(void *opaque) {
    const config_info_context_t *context = opaque;

    (void)display_init(context->color, !context->color);
    display_config_info(context->application);
}

TEST(config_info_reports_existing_missing_null_and_color_parity) {
    char root[] = "/tmp/gitswitch-display-XXXXXX";
    char expected[2 * MAX_PATH_LEN];
    gitswitch_ctx_t application;
    config_info_context_t context;
    captured_output_t existing_plain;
    captured_output_t existing_colored;
    captured_output_t missing_plain;
    captured_output_t missing_colored;
    captured_output_t null_output;
    char *stripped;
    size_t stripped_length;
    int descriptor;
    int written;

    CHECK(ts_mkdtemp(root) != NULL);
    if (root[0] == '\0' || strstr(root, "XXXXXX") != NULL) return;
    memset(&application, 0, sizeof(application));
    written = snprintf(application.config.config_path,
                       sizeof(application.config.config_path), "%s/config",
                       root);
    CHECK(written > 0 &&
          (size_t)written < sizeof(application.config.config_path));
    if (written <= 0 ||
        (size_t)written >= sizeof(application.config.config_path)) {
        return;
    }
    application.account_count = 2;
    descriptor = open(application.config.config_path,
                      O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(descriptor >= 0);
    if (descriptor < 0) return;
    CHECK_EQ_INT(close(descriptor), 0);

    written = snprintf(expected, sizeof(expected),
                       "\nConfiguration: %s\n"
                       "Accounts:      2 configured\n"
                       "Status:        exists\n",
                       application.config.config_path);
    CHECK(written > 0 && (size_t)written < sizeof(expected));
    if (written <= 0 || (size_t)written >= sizeof(expected)) return;

    context.application = &application;
    context.color = false;
    CHECK_EQ_INT(capture_output(emit_config_info, &context,
                                &existing_plain), 0);
    if (!existing_plain.standard_output) return;
    CHECK_STR_EQ(existing_plain.standard_output, expected);
    CHECK_EQ_INT(existing_plain.standard_error_length, 0);

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_config_info, &context,
                                &existing_colored), 0);
    if (!existing_colored.standard_output) goto existing_cleanup;
    CHECK(strstr(existing_colored.standard_output,
                 COLOR_GREEN "exists" COLOR_RESET) != NULL);
    CHECK_EQ_INT(existing_colored.standard_error_length, 0);
    stripped = strip_sgr_sequences(existing_colored.standard_output,
                                   existing_colored.standard_output_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_EQ_INT(stripped_length, existing_plain.standard_output_length);
        CHECK_STR_EQ(stripped, existing_plain.standard_output);
        free(stripped);
    }

    CHECK_EQ_INT(unlink(application.config.config_path), 0);
    written = snprintf(expected, sizeof(expected),
                       "\nConfiguration: %s\n"
                       "Accounts:      2 configured\n"
                       "Status:        not found\n",
                       application.config.config_path);
    CHECK(written > 0 && (size_t)written < sizeof(expected));

    context.color = false;
    CHECK_EQ_INT(capture_output(emit_config_info, &context, &missing_plain), 0);
    if (!missing_plain.standard_output) goto existing_colored_cleanup;
    CHECK_STR_EQ(missing_plain.standard_output, expected);
    CHECK_EQ_INT(missing_plain.standard_error_length, 0);

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_config_info, &context,
                                &missing_colored), 0);
    if (!missing_colored.standard_output) goto missing_plain_cleanup;
    CHECK(strstr(missing_colored.standard_output,
                 COLOR_YELLOW "not found" COLOR_RESET) != NULL);
    CHECK_EQ_INT(missing_colored.standard_error_length, 0);
    stripped = strip_sgr_sequences(missing_colored.standard_output,
                                   missing_colored.standard_output_length,
                                   &stripped_length);
    CHECK(stripped != NULL);
    if (stripped) {
        CHECK_EQ_INT(stripped_length, missing_plain.standard_output_length);
        CHECK_STR_EQ(stripped, missing_plain.standard_output);
        free(stripped);
    }

    context.application = NULL;
    context.color = true;
    CHECK_EQ_INT(capture_output(emit_config_info, &context, &null_output), 0);
    if (null_output.standard_output) {
        CHECK_EQ_INT(null_output.standard_output_length, 0);
        CHECK_EQ_INT(null_output.standard_error_length, 0);
        captured_output_free(&null_output);
    }

    captured_output_free(&missing_colored);
missing_plain_cleanup:
    captured_output_free(&missing_plain);
existing_colored_cleanup:
    captured_output_free(&existing_colored);
existing_cleanup:
    captured_output_free(&existing_plain);
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
    captured_output_t plain;
    captured_output_t colored;
    char *stripped_output;
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

    /* AR-10 L4: the error-level line now lands on stderr. */
    context.payload = payload;
    context.color = false;
    CHECK_EQ_INT(capture_output(emit_long_error, &context, &plain), 0);
    if (!plain.standard_error) return;

    context.color = true;
    CHECK_EQ_INT(capture_output(emit_long_error, &context, &colored), 0);
    if (!colored.standard_error) {
        captured_output_free(&plain);
        return;
    }
    stripped_output = strip_sgr_sequences(colored.standard_error,
                                          colored.standard_error_length,
                                          &stripped_length);
    CHECK(stripped_output != NULL);
    if (!stripped_output) {
        captured_output_free(&colored);
        captured_output_free(&plain);
        return;
    }

    CHECK_EQ_INT(plain.standard_error_length, (size_t)expected_length);
    CHECK(memcmp(plain.standard_error, expected,
                 (size_t)expected_length + 1U) == 0);
    CHECK(strstr(plain.standard_error, suffix) != NULL);
    CHECK(strstr(colored.standard_error, COLOR_RED) != NULL);
    CHECK(strstr(colored.standard_error, COLOR_RESET) != NULL);
    CHECK(colored.standard_error_length >= sizeof(colored_ending) - 1U &&
          memcmp(colored.standard_error + colored.standard_error_length -
                     (sizeof(colored_ending) - 1U),
                 colored_ending, sizeof(colored_ending) - 1U) == 0);
    CHECK_EQ_INT(stripped_length, plain.standard_error_length);
    CHECK(memcmp(stripped_output, plain.standard_error,
                 plain.standard_error_length + 1U) == 0);
    CHECK(strstr(stripped_output, suffix) != NULL);
    CHECK_EQ_INT(plain.standard_output_length, 0);
    CHECK_EQ_INT(colored.standard_output_length, 0);

    free(stripped_output);
    captured_output_free(&colored);
    captured_output_free(&plain);
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

/* AR-10 L2/L8: the width-clamp branch was structurally unreachable from the
 * pipe-backed harness (always 80x24), hiding the negative-%*s widening bug.
 * Drive display_init against a real pty whose winsize we control. */
static void emit_overlong_header(void *unused) {
    (void)unused;
    display_header("This title is much longer than the narrow terminal");
}

/* No display_init here: these emitters run under pipe-backed capture, where
 * a re-init would clobber the pty-derived dimensions under test. */
static void emit_plain_header(void *unused) {
    (void)unused;
    display_header("Title");
}

static int build_boxed_expected(char *buffer, size_t capacity,
                                const char *shown_title, int inner_width,
                                int padding) {
    size_t length = 0;
    int index;
    int right = inner_width - (int)strlen(shown_title) - padding;

    if (!buffer || capacity == 0 || right < 0) return -1;
    buffer[0] = '\0';
    if (append_text(buffer, capacity, &length, "┌") != 0) return -1;
    for (index = 0; index < inner_width; index++) {
        if (append_text(buffer, capacity, &length, "─") != 0) return -1;
    }
    if (append_text(buffer, capacity, &length, "┐\n│") != 0) return -1;
    for (index = 0; index < padding; index++) {
        if (append_text(buffer, capacity, &length, " ") != 0) return -1;
    }
    if (append_text(buffer, capacity, &length, shown_title) != 0) return -1;
    for (index = 0; index < right; index++) {
        if (append_text(buffer, capacity, &length, " ") != 0) return -1;
    }
    if (append_text(buffer, capacity, &length, "│\n└") != 0) return -1;
    for (index = 0; index < inner_width; index++) {
        if (append_text(buffer, capacity, &length, "─") != 0) return -1;
    }
    return append_text(buffer, capacity, &length, "┘\n");
}

static int init_display_on_pty(unsigned short columns, unsigned short rows) {
    struct winsize window_size;
    bool supports_color;
    int master;
    int slave;
    int pty_rc = open_test_pty(&master, &slave);
    int result = -1;

    if (pty_rc != 0) return pty_rc;
    memset(&window_size, 0, sizeof(window_size));
    window_size.ws_col = columns;
    window_size.ws_row = rows;
    if (ioctl(slave, TIOCSWINSZ, &window_size) == 0 &&
        initialize_with_stdout(slave, false, true, &supports_color) == 0) {
        result = 0;
    }
    close(slave);
    close(master);
    return result;
}

TEST(narrow_terminal_truncates_header_instead_of_widening) {
    char expected[512];
    captured_output_t captured;
    int pty_rc = init_display_on_pty(20, 24);

    if (pty_rc == 1) TS_SKIP("pty", "no usable pseudo-terminal");
    CHECK_EQ_INT(pty_rc, 0);

    /* total_width = 20-2 = 18, inner = 16: the 51-byte title must come back
     * truncated to exactly 16 bytes with zero padding — the pre-fix code
     * emitted a 55-column line here. */
    CHECK_EQ_INT(build_boxed_expected(expected, sizeof(expected),
                                      "This title is mu", 16, 0), 0);
    CHECK_EQ_INT(capture_output(emit_overlong_header, NULL, &captured), 0);
    if (!captured.standard_output) return;
    CHECK_STR_EQ(captured.standard_output, expected);
    CHECK_EQ_INT(captured.standard_error_length, 0);
    captured_output_free(&captured);

    /* Restore the default 80x24 layout state for later tests. */
    (void)init_display_on_pty(80, 24);
}

TEST(zero_size_pty_falls_back_to_default_dimensions) {
    char expected[512];
    captured_output_t captured;
    /* AR-10 L33: a fresh pty legitimately reports 0x0 from a SUCCEEDING
     * TIOCGWINSZ; get_terminal_size must reject it so display_init falls
     * back to 80x24 instead of collapsing the layout. */
    int pty_rc = init_display_on_pty(0, 0);

    if (pty_rc == 1) TS_SKIP("pty", "no usable pseudo-terminal");
    CHECK_EQ_INT(pty_rc, 0);

    CHECK_EQ_INT(build_boxed_expected(expected, sizeof(expected),
                                      "Title", 38, 16), 0);
    CHECK_EQ_INT(capture_output(emit_plain_header, NULL, &captured), 0);
    if (!captured.standard_output) return;
    CHECK_STR_EQ(captured.standard_output, expected);
    captured_output_free(&captured);
}

TEST(formatting_failure_emits_no_partial_or_uninitialized_output) {
    captured_output_t captured;

    CHECK(setlocale(LC_CTYPE, "C") != NULL);
    CHECK_EQ_INT(capture_output(emit_unrepresentable_diagnostics, NULL,
                                &captured), 0);
    if (!captured.standard_output) return;

    CHECK_EQ_INT(captured.standard_output_length, 0);
    CHECK_EQ_INT(captured.standard_error_length, 0);
    CHECK(captured.standard_output[0] == '\0');
    CHECK(captured.standard_error[0] == '\0');
    captured_output_free(&captured);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(retained_public_display_api_links);
    RUN_TEST(explicit_color_flags_have_deterministic_precedence);
    RUN_TEST(environment_color_policy_precedence_and_values_are_exact);
    RUN_TEST(automatic_color_requires_tty_and_color_environment);
    RUN_TEST(colorize_maps_exact_styles_resets_and_passthroughs);
    RUN_TEST(colorize_results_remain_valid_across_later_growth);
    RUN_TEST(status_levels_and_variadic_formatting_are_exact);
    RUN_TEST(message_wrappers_obey_streams_and_null_empty_context_contracts);
    RUN_TEST(header_bytes_and_ansi_stripped_parity_are_exact);
    RUN_TEST(config_info_reports_existing_missing_null_and_color_parity);
    RUN_TEST(long_colored_status_preserves_every_payload_byte);
    RUN_TEST(narrow_terminal_truncates_header_instead_of_widening);
    RUN_TEST(zero_size_pty_falls_back_to_default_dimensions);
    RUN_TEST(formatting_failure_emits_no_partial_or_uninitialized_output);
TEST_MAIN_END()
