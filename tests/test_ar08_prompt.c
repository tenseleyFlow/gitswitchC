/* AR-08 L19: prompt input must be atomic across readline and fgets builds. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"

#include "accounts.h"
#include "error.h"
#include "gpg_manager.h"
#include "prompt.h"

#ifdef HAVE_READLINE
#include <readline/readline.h>
#endif

typedef struct {
    FILE *stream;
    int saved_fd;
} redirected_stream_t;

static int redirect_fd(FILE *stream, int target_fd,
                       redirected_stream_t *redirected) {
    redirected->stream = stream;
    redirected->saved_fd = dup(target_fd);
    if (redirected->saved_fd < 0 ||
        dup2(fileno(stream), target_fd) < 0) {
        if (redirected->saved_fd >= 0) close(redirected->saved_fd);
        redirected->saved_fd = -1;
        return -1;
    }
    if (target_fd == STDIN_FILENO) clearerr(stdin);
    return 0;
}

static void restore_fd(int target_fd, redirected_stream_t *redirected) {
    if (redirected->saved_fd >= 0) {
        (void)dup2(redirected->saved_fd, target_fd);
        close(redirected->saved_fd);
        redirected->saved_fd = -1;
    }
    if (target_fd == STDIN_FILENO) clearerr(stdin);
}

static FILE *input_stream(const char *text) {
    FILE *stream = tmpfile();
    if (!stream) return NULL;
    if (text && fputs(text, stream) == EOF) {
        fclose(stream);
        return NULL;
    }
    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static int begin_input(FILE *stream, redirected_stream_t *redirected) {
    return redirect_fd(stream, STDIN_FILENO, redirected);
}

static void end_input(redirected_stream_t *redirected) {
    restore_fd(STDIN_FILENO, redirected);
}

TEST(exact_boundary_is_accepted) {
    char buffer[8] = "dirty";
    FILE *stream = input_stream("1234567\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "1234567");
        end_input(&redirected);
    }
    fclose(stream);
}

TEST(oversized_line_is_rejected_and_next_line_recovers) {
    char buffer[8] = "secret";
    FILE *stream = input_stream("12345678\nnext\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        set_error(ERR_UNKNOWN, "stale before overlong input");
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_TRUNCATED);
        CHECK_STR_EQ(buffer, "");
        CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "next");
        end_input(&redirected);
    }
    fclose(stream);
}

TEST(unterminated_exact_boundary_and_eof_keep_their_semantics) {
    char buffer[8] = "dirty";
    FILE *stream = input_stream("1234567");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "1234567");
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_EOF);
        CHECK_STR_EQ(buffer, "");
        end_input(&redirected);
    }
    fclose(stream);
}

TEST(success_clears_stale_error_state) {
    char buffer[8] = "dirty";
    FILE *stream = input_stream("ok\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        set_error(ERR_UNKNOWN, "stale before recovered input");
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "ok");
        CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
        end_input(&redirected);
    }
    fclose(stream);
}

TEST(input_error_is_distinct_from_eof) {
    char buffer[8] = "secret";
    FILE *stream = input_stream("");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        CHECK_EQ_INT(close(STDIN_FILENO), 0);
        clearerr(stdin);
        /* Prime the stdio error indicator explicitly: readline reports NULL
         * for both cancellation and lower-level input failure, so prompt_line
         * must consult this state rather than collapsing the two outcomes. */
        CHECK_EQ_INT(fgetc(stdin), EOF);
        CHECK(ferror(stdin));
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_ERROR);
        CHECK_STR_EQ(buffer, "");
        CHECK(ferror(stdin));
        end_input(&redirected);
    }
    fclose(stream);
}

#if defined(__GLIBC__) && !defined(HAVE_READLINE)
typedef struct {
    const char *bytes;
    size_t length;
    size_t offset;
} failing_cookie_t;

static ssize_t failing_cookie_read(void *opaque, char *buffer, size_t size) {
    failing_cookie_t *cookie = opaque;
    if (cookie->offset < cookie->length && size > 0) {
        buffer[0] = cookie->bytes[cookie->offset++];
        return 1;
    }
    errno = EIO;
    return -1;
}

TEST(drain_error_is_not_reported_as_truncation) {
    char buffer[8] = "secret";
    failing_cookie_t cookie = {
        .bytes = "12345678",
        .length = sizeof("12345678") - 1,
        .offset = 0
    };
    cookie_io_functions_t functions = {
        .read = failing_cookie_read,
        .write = NULL,
        .seek = NULL,
        .close = NULL
    };
    FILE *stream = fopencookie(&cookie, "r", functions);
    FILE *saved_stdin = stdin;

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(setvbuf(stream, NULL, _IONBF, 0), 0);
    stdin = stream;
    clearerr(stdin);
    set_error(ERR_UNKNOWN, "preserve error across failed drain");
    CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                 PROMPT_LINE_ERROR);
    CHECK_STR_EQ(buffer, "");
    CHECK(ferror(stdin));
    CHECK_EQ_INT(get_last_error()->code, ERR_UNKNOWN);
    stdin = saved_stdin;
    fclose(stream);
    clearerr(stdin);
}
#endif

static int write_long_line(FILE *stream, int byte) {
    for (size_t i = 0; i < 600; i++) {
        if (fputc(byte, stream) == EOF) return -1;
    }
    return fputc('\n', stream) == EOF ? -1 : 0;
}

static size_t count_occurrences(const char *text, const char *needle) {
    size_t count = 0;
    size_t needle_size = strlen(needle);
    while ((text = strstr(text, needle)) != NULL) {
        count++;
        text += needle_size;
    }
    return count;
}

TEST(account_flow_reprompts_without_accepting_any_prefix) {
    gitswitch_ctx_t ctx;
    char root[] = "/tmp/gsw-prompt-XXXXXX";
    char key_path[256];
    char output[32768];
    FILE *input = tmpfile();
    FILE *capture = tmpfile();
    redirected_stream_t redirected_input = { .stream = NULL, .saved_fd = -1 };
    redirected_stream_t redirected_output = { .stream = NULL, .saved_fd = -1 };
    int rc = -1;
    char *fixture_root;

    CHECK(input != NULL && capture != NULL);
    if (!input || !capture) goto cleanup;
    fixture_root = ts_mkdtemp(root);
    CHECK(fixture_root != NULL);
    if (!fixture_root) goto cleanup;
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK((size_t)snprintf(key_path, sizeof(key_path), "%s/id_test", root) <
          sizeof(key_path));
    {
        FILE *key = fopen(key_path, "w");
        CHECK(key != NULL);
        if (!key) goto cleanup;
        CHECK(fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", key) !=
              EOF);
        CHECK_EQ_INT(fclose(key), 0);
        CHECK_EQ_INT(chmod(key_path, 0600), 0);
    }
    gpg_manager_note_key_available("ABCDEF0123456789");

    /* Every one of accounts.c's nine prompt sites receives an overlong answer
     * followed by the answer that must actually reach the account model:
     * name, email, description, SSH path and alias, GPG ID and signing choice,
     * scope, then final confirmation. */
    CHECK_EQ_INT(write_long_line(input, 'n'), 0);
    CHECK(fputs("goodname\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'e'), 0);
    CHECK(fputs("good@example.com\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'd'), 0);
    CHECK(fputs("clean description\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 's'), 0);
    CHECK(fprintf(input, "%s\n", key_path) > 0);
    CHECK_EQ_INT(write_long_line(input, 'a'), 0);
    CHECK(fputs("github.com-work\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'g'), 0);
    CHECK(fputs("ABCDEF0123456789\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'y'), 0);
    CHECK(fputs("y\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'p'), 0);
    CHECK(fputs("local\n", input) != EOF);
    CHECK_EQ_INT(write_long_line(input, 'c'), 0);
    CHECK(fputs("y\n", input) != EOF);
    CHECK_EQ_INT(fflush(input), 0);
    CHECK_EQ_INT(fseek(input, 0, SEEK_SET), 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    CHECK_EQ_INT(begin_input(input, &redirected_input), 0);
    CHECK_EQ_INT(fflush(stdout), 0);
    CHECK_EQ_INT(redirect_fd(capture, STDOUT_FILENO, &redirected_output), 0);
    if (redirected_input.saved_fd >= 0 && redirected_output.saved_fd >= 0) {
        rc = accounts_add_interactive(&ctx);
    }
    CHECK_EQ_INT(fflush(stdout), 0);
    restore_fd(STDOUT_FILENO, &redirected_output);
    end_input(&redirected_input);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].name, "goodname");
        CHECK_STR_EQ(ctx.accounts[0].email, "good@example.com");
        CHECK_STR_EQ(ctx.accounts[0].description, "clean description");
        CHECK_EQ_INT(ctx.accounts[0].preferred_scope, GIT_SCOPE_LOCAL);
        CHECK(ctx.accounts[0].ssh_enabled);
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, key_path);
        CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "github.com-work");
        CHECK(ctx.accounts[0].gpg_enabled);
        CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "ABCDEF0123456789");
        CHECK(ctx.accounts[0].gpg_signing_enabled);
    }

    CHECK_EQ_INT(fseek(capture, 0, SEEK_SET), 0);
    {
        size_t size = fread(output, 1, sizeof(output) - 1, capture);
        output[size] = '\0';
    }
    CHECK_EQ_INT(count_occurrences(output, "Input is too long"), 9);

cleanup:
    restore_fd(STDOUT_FILENO, &redirected_output);
    end_input(&redirected_input);
    if (input) fclose(input);
    if (capture) fclose(capture);
}

TEST_MAIN_BEGIN()
    /* Prevent stdio read-ahead from retaining bytes across dup2-backed input
     * fixtures; readline already consumes each complete logical line. */
    (void)setvbuf(stdin, NULL, _IONBF, 0);
    RUN_TEST(exact_boundary_is_accepted);
    RUN_TEST(oversized_line_is_rejected_and_next_line_recovers);
    RUN_TEST(unterminated_exact_boundary_and_eof_keep_their_semantics);
    RUN_TEST(success_clears_stale_error_state);
    RUN_TEST(input_error_is_distinct_from_eof);
#if defined(__GLIBC__) && !defined(HAVE_READLINE)
    RUN_TEST(drain_error_is_not_reported_as_truncation);
#endif
    RUN_TEST(account_flow_reprompts_without_accepting_any_prefix);
TEST_MAIN_END()
