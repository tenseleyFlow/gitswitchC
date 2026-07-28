/* AR-08 L19: prompt input must be atomic across readline and bounded-stdio
 * paths. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"

#include "accounts.h"
#include "error.h"
#include "gpg_manager.h"
#include "prompt.h"
#include "utils.h"
#include "trusted_command_fixture.h"

#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#endif

typedef struct {
    FILE *stream;
    int saved_fd;
} redirected_stream_t;

#ifdef HAVE_READLINE
static int g_readline_fault_fd = -1;
static int g_readline_fault_calls;
static int g_readline_fault_errno;

static int readline_pty_error_getc(FILE *stream) {
    unsigned char byte;
    ssize_t count;

    (void)stream;
    g_readline_fault_calls++;
    do {
        count = read(g_readline_fault_fd, &byte, 1);
    } while (count < 0 && errno == EINTR);
    if (count == 1) return byte;
    g_readline_fault_errno = count < 0 ? errno : 0;
    return count == 0 ? EOF : READERR;
}

static void drain_readline_master(int master) {
    char discarded[256];

    for (int reads = 0; reads < 16; reads++) {
        ssize_t count = read(master, discarded, sizeof(discarded));

        if (count > 0) continue;
        if (count < 0 && errno == EINTR) {
            reads--;
            continue;
        }
        break;
    }
}

static bool reap_readline_child_within(pid_t child, int master,
                                       int timeout_ms, int *status_out) {
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
    int flags = fcntl(master, F_GETFL);

    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        return false;
    }

    for (int elapsed = 0; elapsed <= timeout_ms; elapsed += 10) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);

        drain_readline_master(master);
        if (waited == child) {
            if (status_out) *status_out = status;
            return true;
        }
        if (waited < 0 && errno != EINTR) break;
        (void)nanosleep(&pause, NULL);
    }

    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return false;
}
#endif

static int g_unavailable_gpg_runner_calls;

#define PROMPT_GPG_M5_MISS_STATUS \
    "[GNUPG:] ERROR keylist.getkey 17\n" \
    "[GNUPG:] FAILURE gpg-exit 33554433\n"

typedef enum {
    PROMPT_GPG_M5_MISS,
    PROMPT_GPG_M5_SETUP_126
} prompt_gpg_m5_mode_t;

static prompt_gpg_m5_mode_t g_prompt_gpg_m5_mode;
static int g_prompt_gpg_m5_calls;

static bool prompt_gpg_m5_argv_has(const char *const argv[],
                                   const char *needle) {
    if (!argv || !needle) return false;
    for (size_t i = 0; argv[i]; i++) {
        if (strcmp(argv[i], needle) == 0) return true;
    }
    return false;
}

static int prompt_gpg_m5_runner(const char *const argv[],
                                const run_opts_t *opts,
                                run_result_t *result) {
    const char *output = "";
    int exit_code;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!prompt_gpg_m5_argv_has(argv, "--list-secret-keys")) {
        return 0;
    }

    g_prompt_gpg_m5_calls++;
    switch (g_prompt_gpg_m5_mode) {
        case PROMPT_GPG_M5_MISS:
            output = PROMPT_GPG_M5_MISS_STATUS;
            exit_code = 2;
            break;
        case PROMPT_GPG_M5_SETUP_126:
            exit_code = 126;
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    if (opts && opts->out && opts->out_size > 0) {
        size_t length = strlen(output);
        size_t copied = length < opts->out_size - 1U
                            ? length : opts->out_size - 1U;

        memcpy(opts->out, output, copied);
        opts->out[copied] = '\0';
        if (result) {
            result->out_len = copied;
            result->out_truncated = copied < length;
        }
    }
    if (result) result->exit_code = exit_code;
    errno = ECHILD;
    return -1;
}

static int unavailable_gpg_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    static const char key_listing[] =
        "256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
        "prompt-fixture (ED25519)\n";

    if (argv && argv[0] && argv[1] &&
        strcmp(argv[0], "ssh-keygen") == 0 &&
        strcmp(argv[1], "-lf") == 0) {
        size_t listing_length = sizeof(key_listing) - 1U;

        if (!opts || !opts->out || opts->out_size <= listing_length) {
            errno = ENOSPC;
            return -1;
        }
        memcpy(opts->out, key_listing, listing_length + 1U);
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            result->exit_code = 0;
            result->out_len = listing_length;
        }
        return 0;
    }

    g_unavailable_gpg_runner_calls++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 2;
    }
    errno = EIO;
    return -1;
}

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
    if (target_fd == STDOUT_FILENO) clearerr(stdout);
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

/* AR-11 M33: emitting a prompt is part of the authorization boundary. A
 * caller must never consume a pre-fed affirmative answer after the operator
 * could not see the prompt, and the low-level prompt reader must leave both
 * the causal write errno and an unrelated global error report intact. */
static void exercise_prompt_output_failure(FILE *failure_stream,
                                           int expected_errno,
                                           const char *prompt_text) {
    typedef struct {
        int result;
        int saved_errno;
        int buffer_empty;
        int error_same;
    } prompt_failure_result_t;

    FILE *input = input_stream("yes\nnext\n");
    prompt_failure_result_t child_result = {0};
    int result_pipe[2] = {-1, -1};
    off_t input_offset_before = -1;
    off_t input_offset_after = -1;
    size_t result_used = 0;
    int flush_result;
    int status = 0;
    pid_t child = -1;

    CHECK(input != NULL);
    CHECK(failure_stream != NULL);
    if (!input || !failure_stream) goto cleanup;

    flush_result = fflush(stdout);
    CHECK_EQ_INT(flush_result, 0);
    if (flush_result != 0) goto cleanup;
    CHECK_EQ_INT(pipe(result_pipe), 0);
    if (result_pipe[0] < 0 || result_pipe[1] < 0) goto cleanup;

    input_offset_before = lseek(fileno(input), 0, SEEK_CUR);
    CHECK(input_offset_before >= 0);
    if (input_offset_before < 0) goto cleanup;

    child = fork();
    CHECK(child >= 0);
    if (child < 0) goto cleanup;
    if (child == 0) {
        char buffer[16] = "secret";
        error_context_t before_error;
        error_context_t after_error;
        size_t written = 0;

        close(result_pipe[0]);
        if (dup2(fileno(input), STDIN_FILENO) < 0 ||
            dup2(fileno(failure_stream), STDOUT_FILENO) < 0) {
            _exit(2);
        }
        clearerr(stdin);
        clearerr(stdout);
        set_error(ERR_UNKNOWN,
                  "preserve context across prompt output failure");
        before_error = *get_last_error();
        errno = 0;
        child_result.result = prompt_line(
            prompt_text, buffer, sizeof(buffer), false);
        child_result.saved_errno = errno;
        after_error = *get_last_error();
        child_result.buffer_empty = buffer[0] == '\0';
        child_result.error_same =
            memcmp(&after_error, &before_error, sizeof(before_error)) == 0;

        while (written < sizeof(child_result)) {
            ssize_t count = write(
                result_pipe[1],
                (const char *)&child_result + written,
                sizeof(child_result) - written);

            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) _exit(3);
            written += (size_t)count;
        }
        close(result_pipe[1]);
        _exit(0);
    }

    close(result_pipe[1]);
    result_pipe[1] = -1;
    while (result_used < sizeof(child_result)) {
        ssize_t count = read(
            result_pipe[0], (char *)&child_result + result_used,
            sizeof(child_result) - result_used);

        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        result_used += (size_t)count;
    }
    {
        pid_t waited = waitpid(child, &status, 0);

        CHECK(waited == child);
        if (waited != child) goto cleanup;
    }
    child = -1;
    CHECK(WIFEXITED(status));
    if (!WIFEXITED(status)) goto cleanup;
    CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(result_used == sizeof(child_result));
    if (result_used != sizeof(child_result)) goto cleanup;

    input_offset_after = lseek(fileno(input), 0, SEEK_CUR);
    CHECK_EQ_INT(child_result.result, PROMPT_LINE_ERROR);
    CHECK(child_result.buffer_empty);
    CHECK_EQ_INT(child_result.saved_errno, expected_errno);
    CHECK(child_result.error_same);
    CHECK(input_offset_after == input_offset_before);

cleanup:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (result_pipe[0] >= 0) close(result_pipe[0]);
    if (result_pipe[1] >= 0) close(result_pipe[1]);
    if (input) fclose(input);
}

TEST(prompt_write_ebadf_fails_before_consuming_confirmation) {
    char oversized_prompt[(BUFSIZ * 2U) + 1U];
    FILE *read_only_stdout = fopen("/dev/null", "r");

    CHECK(read_only_stdout != NULL);
    if (!read_only_stdout) return;
    memset(oversized_prompt, 'P', sizeof(oversized_prompt) - 1U);
    oversized_prompt[sizeof(oversized_prompt) - 1U] = '\0';
    /* Larger than stdout's configured buffer, so this case fails inside the
     * checked fputs rather than waiting for the explicit final flush. */
    exercise_prompt_output_failure(read_only_stdout, EBADF,
                                   oversized_prompt);
    fclose(read_only_stdout);
}

TEST(prompt_flush_enospc_fails_before_consuming_confirmation) {
    FILE *full_stdout;

    if (access("/dev/full", W_OK) != 0) {
        TS_SKIP("dev-full", "/dev/full is unavailable or not writable");
    }
    full_stdout = fopen("/dev/full", "w");
    CHECK(full_stdout != NULL);
    if (!full_stdout) return;
    exercise_prompt_output_failure(
        full_stdout, ENOSPC, "Type 'yes' to continue: ");
    fclose(full_stdout);
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

/* AR-10 L32: an embedded NUL used to hide the newline fgets had consumed, so
 * the boundary probe ate the first byte of the NEXT line and the drain
 * destroyed the rest of it — reproduced as "second" vanishing. Exactly one
 * line may be consumed per call, whatever its bytes. */
TEST(embedded_nul_rejects_one_line_and_preserves_the_next) {
    static const char fixture[] = "fir\0st\nsecond\n";
    char buffer[16] = "dirty";
    FILE *stream = tmpfile();
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT((int)fwrite(fixture, 1, sizeof(fixture) - 1U, stream),
                 (int)(sizeof(fixture) - 1U));
    CHECK_EQ_INT(fflush(stream), 0);
    CHECK_EQ_INT(fseek(stream, 0, SEEK_SET), 0);
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_TRUNCATED);
        CHECK_STR_EQ(buffer, "");
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "second");
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

TEST(empty_line_is_accepted_as_an_empty_answer) {
    char buffer[8] = "dirty";
    FILE *stream = input_stream("\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_OK);
        CHECK_STR_EQ(buffer, "");
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

#ifdef HAVE_READLINE
/* AR-14 L40: both standard streams are a PTY, so prompt_line must enter GNU
 * readline rather than its redirected-stdio fallback. Readline's input
 * callback performs a real read(2) from a dedicated O_WRONLY /dev/null
 * descriptor, deterministically producing EBADF without relying on pipe
 * directionality or platform-specific PTY hangup behavior. The parent drains
 * the PTY while Readline restores termios: FreeBSD may otherwise wait for
 * unread slave output during TCSADRAIN. */
TEST(readline_pty_input_error_is_distinct_from_eof) {
    typedef struct {
        int result;
        int saved_errno;
        int buffer_empty;
        int stdin_is_tty;
        int stdout_is_tty;
        int callback_calls;
        int callback_errno;
    } readline_error_result_t;

    readline_error_result_t observed = {0};
    char *slave_name;
    int master = -1;
    int slave = -1;
    int result_pipe[2] = {-1, -1};
    size_t result_used = 0;
    int status = 0;
    pid_t child = -1;

    master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(master >= 0);
    if (master < 0) goto cleanup;
    CHECK_EQ_INT(grantpt(master), 0);
    CHECK_EQ_INT(unlockpt(master), 0);
    slave_name = ptsname(master);
    CHECK(slave_name != NULL);
    if (!slave_name) goto cleanup;
    slave = open(slave_name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    if (slave < 0) goto cleanup;
    CHECK_EQ_INT(pipe(result_pipe), 0);
    if (result_pipe[0] < 0 || result_pipe[1] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child < 0) goto cleanup;
    if (child == 0) {
        char buffer[16] = "secret";
        size_t written = 0;

        close(result_pipe[0]);
        if (dup2(slave, STDIN_FILENO) != STDIN_FILENO ||
            dup2(slave, STDOUT_FILENO) != STDOUT_FILENO) {
            _exit(2);
        }
        close(master);
        close(slave);
        clearerr(stdin);
        clearerr(stdout);
        observed.stdin_is_tty = isatty(STDIN_FILENO);
        observed.stdout_is_tty = isatty(STDOUT_FILENO);
        if (setenv("TERM", "dumb", 1) != 0 ||
            setenv("INPUTRC", "/dev/null", 1) != 0) {
            _exit(3);
        }
        rl_instream = stdin;
        rl_outstream = stdout;
        rl_catch_signals = 0;
        rl_catch_sigwinch = 0;
        if (rl_initialize() != 0) _exit(3);
        g_readline_fault_fd = open("/dev/null", O_WRONLY);
        if (g_readline_fault_fd < 0) _exit(3);
        g_readline_fault_calls = 0;
        g_readline_fault_errno = 0;
        rl_getc_function = readline_pty_error_getc;
        errno = 0;
        observed.result = prompt_line("", buffer, sizeof(buffer), false);
        observed.saved_errno = errno;
        observed.buffer_empty = buffer[0] == '\0';
        observed.callback_calls = g_readline_fault_calls;
        observed.callback_errno = g_readline_fault_errno;
        if (close(g_readline_fault_fd) != 0) _exit(3);
        g_readline_fault_fd = -1;

        while (written < sizeof(observed)) {
            ssize_t count = write(
                result_pipe[1], (const char *)&observed + written,
                sizeof(observed) - written);

            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) _exit(4);
            written += (size_t)count;
        }
        close(result_pipe[1]);
        _exit(0);
    }

    close(result_pipe[1]);
    result_pipe[1] = -1;
    close(slave);
    slave = -1;
    bool reaped =
        reap_readline_child_within(child, master, 3000, &status);
    child = -1;
    while (result_used < sizeof(observed)) {
        ssize_t count = read(
            result_pipe[0], (char *)&observed + result_used,
            sizeof(observed) - result_used);

        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        result_used += (size_t)count;
    }
    CHECK(reaped);
    if (reaped) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(result_used == sizeof(observed));
    if (result_used == sizeof(observed)) {
        CHECK(observed.stdin_is_tty);
        CHECK(observed.stdout_is_tty);
        CHECK(observed.callback_calls > 0);
        CHECK_EQ_INT(observed.callback_errno, EBADF);
        CHECK_EQ_INT(observed.result, PROMPT_LINE_ERROR);
        CHECK_EQ_INT(observed.saved_errno, EBADF);
        CHECK(observed.buffer_empty);
    }

cleanup:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (result_pipe[0] >= 0) close(result_pipe[0]);
    if (result_pipe[1] >= 0) close(result_pipe[1]);
    if (slave >= 0) close(slave);
    if (master >= 0) close(master);
}
#else
TEST(readline_pty_input_error_is_distinct_from_eof) {
    TS_SKIP("readline", "test requires a HAVE_READLINE build");
}
#endif

#if defined(__GLIBC__)
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

static int begin_cookie_input(FILE *cookie_stream, FILE **saved_stdin,
                              FILE **non_tty_stream,
                              redirected_stream_t *redirected) {
    *non_tty_stream = input_stream("");
    if (!*non_tty_stream ||
        begin_input(*non_tty_stream, redirected) != 0) {
        if (*non_tty_stream) fclose(*non_tty_stream);
        *non_tty_stream = NULL;
        return -1;
    }
    *saved_stdin = stdin;
    stdin = cookie_stream;
    clearerr(stdin);
    return 0;
}

static void end_cookie_input(FILE *saved_stdin, FILE *non_tty_stream,
                             redirected_stream_t *redirected) {
    stdin = saved_stdin;
    end_input(redirected);
    fclose(non_tty_stream);
}

TEST(partial_initial_read_error_clears_the_caller_buffer) {
    char buffer[8] = "secret";
    failing_cookie_t cookie = {
        .bytes = "abc",
        .length = sizeof("abc") - 1,
        .offset = 0
    };
    cookie_io_functions_t functions = {
        .read = failing_cookie_read,
        .write = NULL,
        .seek = NULL,
        .close = NULL
    };
    FILE *stream = fopencookie(&cookie, "r", functions);
    FILE *saved_stdin = NULL;
    FILE *non_tty_stream = NULL;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(setvbuf(stream, NULL, _IONBF, 0), 0);
    CHECK_EQ_INT(begin_cookie_input(stream, &saved_stdin, &non_tty_stream,
                                    &redirected), 0);
    if (saved_stdin) {
        set_error(ERR_UNKNOWN, "preserve context across partial read error");
        errno = 0;
        int result = prompt_line("", buffer, sizeof(buffer), false);
        int saved_errno = errno;

        CHECK_EQ_INT(result, PROMPT_LINE_ERROR);
        CHECK_STR_EQ(buffer, "");
        CHECK(ferror(stdin));
        CHECK_EQ_INT(saved_errno, EIO);
        CHECK_EQ_INT(get_last_error()->code, ERR_UNKNOWN);
        CHECK_STR_EQ(get_last_error()->message,
                     "preserve context across partial read error");
        end_cookie_input(saved_stdin, non_tty_stream, &redirected);
    }
    fclose(stream);
    clearerr(stdin);
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
    FILE *saved_stdin = NULL;
    FILE *non_tty_stream = NULL;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };

    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(setvbuf(stream, NULL, _IONBF, 0), 0);
    CHECK_EQ_INT(begin_cookie_input(stream, &saved_stdin, &non_tty_stream,
                                    &redirected), 0);
    if (saved_stdin) {
        set_error(ERR_UNKNOWN, "preserve error across failed drain");
        CHECK_EQ_INT(prompt_line("", buffer, sizeof(buffer), false),
                     PROMPT_LINE_ERROR);
        CHECK_STR_EQ(buffer, "");
        CHECK(ferror(stdin));
        CHECK_EQ_INT(get_last_error()->code, ERR_UNKNOWN);
        end_cookie_input(saved_stdin, non_tty_stream, &redirected);
    }
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

typedef enum {
    OPTIONAL_DESCRIPTION,
    OPTIONAL_SSH_KEY,
    OPTIONAL_SSH_ALIAS,
    OPTIONAL_GPG_KEY,
    OPTIONAL_GPG_SIGNING,
    OPTIONAL_SCOPE,
    OPTIONAL_PROMPT_COUNT
} optional_prompt_stage_t;

static const char *optional_prompt_error(optional_prompt_stage_t stage) {
    switch (stage) {
        case OPTIONAL_DESCRIPTION: return "account description";
        case OPTIONAL_SSH_KEY: return "SSH key path";
        case OPTIONAL_SSH_ALIAS: return "SSH host alias";
        case OPTIONAL_GPG_KEY: return "GPG key ID";
        case OPTIONAL_GPG_SIGNING: return "GPG signing preference";
        case OPTIONAL_SCOPE: return "preferred Git scope";
        case OPTIONAL_PROMPT_COUNT: break;
        default: break;
    }
    return "unknown optional prompt";
}

static int build_optional_prompt_prefix(char *buffer, size_t size,
                                        bool edit,
                                        optional_prompt_stage_t stage,
                                        const char *key_path) {
    const char *required = edit ? "\n\n"
                                : "matrix\nmatrix@example.com\n";
    int length;

    switch (stage) {
        case OPTIONAL_DESCRIPTION:
            length = snprintf(buffer, size, "%s", required);
            break;
        case OPTIONAL_SSH_KEY:
            length = snprintf(buffer, size, "%s\n", required);
            break;
        case OPTIONAL_SSH_ALIAS:
            length = snprintf(buffer, size, "%s\n%s\n", required,
                              key_path);
            break;
        case OPTIONAL_GPG_KEY:
            length = snprintf(buffer, size, "%s\n\n", required);
            break;
        case OPTIONAL_GPG_SIGNING:
            length = snprintf(buffer, size, "%s\n\n%s\n", required,
                              "ABCDEF0123456789");
            break;
        case OPTIONAL_SCOPE:
            length = snprintf(buffer, size, "%s\n\n\n", required);
            break;
        case OPTIONAL_PROMPT_COUNT:
        default:
            return -1;
    }
    return length >= 0 && (size_t)length < size ? 0 : -1;
}

typedef struct {
    char *value;
    bool present;
    bool captured;
} prompt_env_snapshot_t;

typedef struct {
    char runtime[128];
    char source_home[MAX_PATH_LEN];
    prompt_env_snapshot_t xdg_runtime;
    prompt_env_snapshot_t allow_tmp_gpg;
    prompt_env_snapshot_t gnupg_home;
    ts_trusted_command_fixture_t commands;
    command_runner_fn previous_runner;
    bool runner_installed;
} prompt_gpg_m5_fixture_t;

static int prompt_env_snapshot_capture(prompt_env_snapshot_t *snapshot,
                                       const char *name) {
    const char *value;

    if (!snapshot || !name) {
        errno = EINVAL;
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    value = getenv(name);
    snapshot->present = value != NULL;
    if (value) {
        snapshot->value = strdup(value);
        if (!snapshot->value) return -1;
    }
    snapshot->captured = true;
    return 0;
}

static int prompt_env_snapshot_restore(prompt_env_snapshot_t *snapshot,
                                       const char *name) {
    int rc = 0;

    if (!snapshot || !snapshot->captured || !name) return 0;
    rc = snapshot->present ? setenv(name, snapshot->value, 1)
                           : unsetenv(name);
    free(snapshot->value);
    memset(snapshot, 0, sizeof(*snapshot));
    return rc;
}

static int prompt_gpg_m5_fixture_end(prompt_gpg_m5_fixture_t *fixture) {
    int saved_errno = errno;
    int cleanup_errno = 0;
    int rc = 0;

    if (!fixture) return 0;
    if (fixture->runner_installed) {
        run_set_runner(fixture->previous_runner);
        fixture->runner_installed = false;
    }
    if (ts_trusted_command_fixture_restore(&fixture->commands) != 0) {
        rc = -1;
        cleanup_errno = errno;
    }
    if (prompt_env_snapshot_restore(&fixture->gnupg_home, "GNUPGHOME") != 0 &&
        rc == 0) {
        rc = -1;
        cleanup_errno = errno;
    }
    if (prompt_env_snapshot_restore(&fixture->allow_tmp_gpg,
                                    "GITSWITCH_ALLOW_TMP_GPG") != 0 &&
        rc == 0) {
        rc = -1;
        cleanup_errno = errno;
    }
    if (prompt_env_snapshot_restore(&fixture->xdg_runtime,
                                    "XDG_RUNTIME_DIR") != 0 &&
        rc == 0) {
        rc = -1;
        cleanup_errno = errno;
    }
    if (fixture->runtime[0] != '\0') {
        ts_rm_rf(fixture->runtime);
        fixture->runtime[0] = '\0';
    }
    errno = rc == 0 ? saved_errno : cleanup_errno;
    return rc;
}

static int prompt_gpg_m5_fixture_begin(prompt_gpg_m5_fixture_t *fixture,
                                       bool install_gpg) {
    static const char *const gpg_names[] = {"gpg", NULL};
    static const char *const empty_path_names[] = {"notgpg", NULL};

    if (!fixture) {
        errno = EINVAL;
        return -1;
    }
    memset(fixture, 0, sizeof(*fixture));
    if (prompt_env_snapshot_capture(&fixture->xdg_runtime,
                                    "XDG_RUNTIME_DIR") != 0 ||
        prompt_env_snapshot_capture(&fixture->allow_tmp_gpg,
                                    "GITSWITCH_ALLOW_TMP_GPG") != 0 ||
        prompt_env_snapshot_capture(&fixture->gnupg_home,
                                    "GNUPGHOME") != 0 ||
        snprintf(fixture->runtime, sizeof(fixture->runtime),
                 "/tmp/gsw-prompt-m5-XXXXXX") < 0 ||
        !ts_mkdtemp(fixture->runtime) ||
        chmod(fixture->runtime, 0700) != 0 ||
        safe_snprintf(fixture->source_home, sizeof(fixture->source_home),
                      "%s/source", fixture->runtime) != 0 ||
        mkdir(fixture->source_home, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        setenv("GNUPGHOME", fixture->source_home, 1) != 0 ||
        ts_trusted_command_fixture_install(
            &fixture->commands, "gsw_prompt_m5",
            install_gpg ? gpg_names : empty_path_names) != 0 ||
        (!install_gpg &&
         setenv("PATH", fixture->commands.directory, 1) != 0)) {
        int saved_errno = errno ? errno : EIO;

        (void)prompt_gpg_m5_fixture_end(fixture);
        errno = saved_errno;
        return -1;
    }
    fixture->previous_runner = run_set_runner(prompt_gpg_m5_runner);
    fixture->runner_installed = true;
    return 0;
}

static void initialize_prompt_context(gitswitch_ctx_t *ctx, bool edit) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->config.assume_yes = true;
    ctx->config.default_scope = GIT_SCOPE_GLOBAL;
    if (!edit) return;

    ctx->account_count = 1;
    ctx->accounts[0].id = 7;
    snprintf(ctx->accounts[0].name, sizeof(ctx->accounts[0].name), "%s",
             "original");
    snprintf(ctx->accounts[0].email, sizeof(ctx->accounts[0].email), "%s",
             "original@example.com");
    snprintf(ctx->accounts[0].description,
             sizeof(ctx->accounts[0].description), "%s",
             "original description");
    ctx->accounts[0].preferred_scope = GIT_SCOPE_LOCAL;
}

static int invoke_account_prompt_flow_capture(gitswitch_ctx_t *ctx, bool edit,
                                              char *output,
                                              size_t output_size) {
    FILE *capture = tmpfile();
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    error_context_t flow_error;
    int flow_errno;
    int result;

    if (output && output_size > 0) output[0] = '\0';
    if (!capture || fflush(stdout) != 0 ||
        redirect_fd(capture, STDOUT_FILENO, &redirected) != 0) {
        if (capture) fclose(capture);
        return -2;
    }
    result = edit ? accounts_edit_interactive(ctx, "original")
                  : accounts_add_interactive(ctx);
    flow_error = *get_last_error();
    flow_errno = errno;
    CHECK_EQ_INT(fflush(stdout), 0);
    restore_fd(STDOUT_FILENO, &redirected);
    if (output && output_size > 0 && fseek(capture, 0, SEEK_SET) == 0) {
        size_t used = fread(output, 1, output_size - 1U, capture);

        output[used] = '\0';
    }
    fclose(capture);
    g_last_error = flow_error;
    errno = flow_errno;
    return result;
}

static int invoke_account_prompt_flow(gitswitch_ctx_t *ctx, bool edit) {
    return invoke_account_prompt_flow_capture(ctx, edit, NULL, 0);
}

static int create_prompt_key(char *root, char *key_path,
                             size_t key_path_size) {
    FILE *key;
    int length;
    int write_failed;
    int close_failed;

    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0) {
        return -1;
    }
    length = snprintf(key_path, key_path_size, "%s/id_matrix", root);
    if (length < 0 || (size_t)length >= key_path_size) return -1;
    key = fopen(key_path, "w");
    if (!key) return -1;
    write_failed = fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                         key) == EOF;
    close_failed = fclose(key) != 0;
    if (write_failed || close_failed || chmod(key_path, 0600) != 0) {
        return -1;
    }
    return 0;
}

static void exercise_optional_prompt_eof(bool edit,
                                         optional_prompt_stage_t stage,
                                         const char *key_path) {
    char prefix[1024];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t before;
    error_context_t error;
    FILE *stream;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    int result = -2;

    CHECK_EQ_INT(build_optional_prompt_prefix(prefix, sizeof(prefix), edit,
                                              stage, key_path), 0);
    stream = input_stream(prefix);
    CHECK(stream != NULL);
    if (!stream) return;
    initialize_prompt_context(&ctx, edit);
    before = ctx;
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) result = invoke_account_prompt_flow(&ctx, edit);
    error = *get_last_error();
    end_input(&redirected);
    fclose(stream);

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT(error.code, ERR_FILE_IO);
    CHECK(strstr(error.message, optional_prompt_error(stage)) != NULL);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
}

#if defined(__GLIBC__)
static void exercise_optional_prompt_read_error(
    bool edit, optional_prompt_stage_t stage, const char *key_path) {
    char prefix[1024];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t before;
    error_context_t error;
    failing_cookie_t cookie;
    cookie_io_functions_t functions = {
        .read = failing_cookie_read,
        .write = NULL,
        .seek = NULL,
        .close = NULL
    };
    FILE *stream;
    FILE *saved_stdin = NULL;
    FILE *non_tty_stream = NULL;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    int result = -2;

    CHECK_EQ_INT(build_optional_prompt_prefix(prefix, sizeof(prefix), edit,
                                              stage, key_path), 0);
    cookie.bytes = prefix;
    cookie.length = strlen(prefix);
    cookie.offset = 0;
    stream = fopencookie(&cookie, "r", functions);
    CHECK(stream != NULL);
    if (!stream) return;
    CHECK_EQ_INT(setvbuf(stream, NULL, _IONBF, 0), 0);
    initialize_prompt_context(&ctx, edit);
    before = ctx;
    CHECK_EQ_INT(begin_cookie_input(stream, &saved_stdin, &non_tty_stream,
                                    &redirected), 0);
    if (saved_stdin) result = invoke_account_prompt_flow(&ctx, edit);
    error = *get_last_error();
    if (saved_stdin) {
        end_cookie_input(saved_stdin, non_tty_stream, &redirected);
    }
    fclose(stream);
    clearerr(stdin);

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT(error.code, ERR_FILE_IO);
    CHECK(strstr(error.message, optional_prompt_error(stage)) != NULL);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
}
#endif

TEST(optional_prompt_failures_never_publish_add_or_edit_candidates) {
    char root[] = "/tmp/gsw-prompt-m1-XXXXXX";
    char key_path[256];
    command_runner_fn old_runner;
    int key_result = create_prompt_key(root, key_path, sizeof(key_path));

    CHECK_EQ_INT(key_result, 0);
    if (key_result != 0) return;
    g_unavailable_gpg_runner_calls = 0;
    old_runner = run_set_runner(unavailable_gpg_runner);
    gpg_manager_note_key_available("ABCDEF0123456789");
    for (int edit = 0; edit <= 1; edit++) {
        for (optional_prompt_stage_t stage = OPTIONAL_DESCRIPTION;
             stage < OPTIONAL_PROMPT_COUNT; stage++) {
            exercise_optional_prompt_eof(edit != 0, stage, key_path);
#if defined(__GLIBC__)
            exercise_optional_prompt_read_error(edit != 0, stage, key_path);
#endif
        }
    }
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_unavailable_gpg_runner_calls, 0);
}

TEST(successful_blank_optional_answers_apply_only_documented_defaults) {
    gitswitch_ctx_t ctx;
    FILE *stream = input_stream(
        "blank-defaults\nblank@example.com\n\n\n\n\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    int result = -2;

    CHECK(stream != NULL);
    if (!stream) return;
    initialize_prompt_context(&ctx, false);
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) result = invoke_account_prompt_flow(&ctx, false);
    end_input(&redirected);
    fclose(stream);

    CHECK_EQ_INT(result, 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].description, "blank-defaults");
        CHECK(!ctx.accounts[0].ssh_enabled);
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, "");
        CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "");
        CHECK(!ctx.accounts[0].gpg_enabled);
        CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "");
        CHECK(!ctx.accounts[0].gpg_signing_enabled);
        CHECK_EQ_INT(ctx.accounts[0].preferred_scope, GIT_SCOPE_GLOBAL);
    }
}

TEST(successful_nested_blank_answers_do_not_invent_alias_or_signing) {
    char root[] = "/tmp/gsw-prompt-m1-nested-XXXXXX";
    char key_path[256];
    char answers[1024];
    gitswitch_ctx_t ctx;
    FILE *stream;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    command_runner_fn old_runner;
    int result = -2;
    int key_result;
    int answer_length;

    key_result = create_prompt_key(root, key_path, sizeof(key_path));
    CHECK_EQ_INT(key_result, 0);
    if (key_result != 0) return;
    gpg_manager_note_key_available("ABCDEF0123456789");
    answer_length = snprintf(
        answers, sizeof(answers),
        "nested\nnested@example.com\n\n%s\n\n%s\n\n\n",
        key_path, "ABCDEF0123456789");
    CHECK(answer_length >= 0 && (size_t)answer_length < sizeof(answers));
    if (answer_length < 0 || (size_t)answer_length >= sizeof(answers)) return;
    stream = input_stream(answers);
    CHECK(stream != NULL);
    if (!stream) return;
    initialize_prompt_context(&ctx, false);
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    g_unavailable_gpg_runner_calls = 0;
    old_runner = run_set_runner(unavailable_gpg_runner);
    if (redirected.saved_fd >= 0) result = invoke_account_prompt_flow(&ctx, false);
    run_set_runner(old_runner);
    end_input(&redirected);
    fclose(stream);

    CHECK_EQ_INT(g_unavailable_gpg_runner_calls, 0);
    CHECK_EQ_INT(result, 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK(ctx.accounts[0].ssh_enabled);
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, key_path);
        CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "");
        CHECK(ctx.accounts[0].gpg_enabled);
        CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "ABCDEF0123456789");
        CHECK(!ctx.accounts[0].gpg_signing_enabled);
        CHECK_EQ_INT(ctx.accounts[0].preferred_scope, GIT_SCOPE_GLOBAL);
    }
}

TEST(successful_blank_edit_answers_preserve_the_account) {
    gitswitch_ctx_t ctx;
    account_t before;
    FILE *stream = input_stream("\n\n\n\n\n\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    int result = -2;

    CHECK(stream != NULL);
    if (!stream) return;
    initialize_prompt_context(&ctx, true);
    before = ctx.accounts[0];
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) result = invoke_account_prompt_flow(&ctx, true);
    end_input(&redirected);
    fclose(stream);

    CHECK_EQ_INT(result, 0);
    CHECK(memcmp(&ctx.accounts[0], &before, sizeof(before)) == 0);
}

TEST(blank_gpg_edit_can_change_only_signing_without_source_resolution) {
    static const char retained_selector[] =
        "1234567890ABCDEF1234567890ABCDEF12345678";
    gitswitch_ctx_t ctx;
    account_t expected;
    FILE *stream = input_stream("\n\n\n\n\ny\n\n");
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    command_runner_fn old_runner;
    int result = -2;

    CHECK(stream != NULL);
    if (!stream) return;
    initialize_prompt_context(&ctx, true);
    ctx.accounts[0].gpg_enabled = true;
    ctx.accounts[0].gpg_signing_enabled = false;
    CHECK_EQ_INT(safe_strncpy(ctx.accounts[0].gpg_key_id,
                              retained_selector,
                              sizeof(ctx.accounts[0].gpg_key_id)), 0);
    expected = ctx.accounts[0];
    expected.gpg_signing_enabled = true;

    g_unavailable_gpg_runner_calls = 0;
    old_runner = run_set_runner(unavailable_gpg_runner);
    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        result = invoke_account_prompt_flow(&ctx, true);
    }
    end_input(&redirected);
    run_set_runner(old_runner);
    fclose(stream);

    CHECK_EQ_INT(result, 0);
    CHECK_EQ_INT(g_unavailable_gpg_runner_calls, 0);
    CHECK(memcmp(&ctx.accounts[0], &expected, sizeof(expected)) == 0);
}

TEST(structured_gpg_miss_reprompts_and_blank_skip_completes) {
    static const char selector[] = "DEADBEEFCAFEBABE";
    static const char expected_diagnostic[] =
        "GPG selector resolved no secret key: DEADBEEFCAFEBABE";
    char answers[256];
    char output[8192];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t before;
    prompt_gpg_m5_fixture_t fixture;
    FILE *stream = NULL;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    int result = -2;

    CHECK_EQ_INT(prompt_gpg_m5_fixture_begin(&fixture, true), 0);
    if (!fixture.commands.active) return;
    CHECK((size_t)snprintf(answers, sizeof(answers),
                           "\n\n\n\n%s\n\n\n", selector) <
          sizeof(answers));
    stream = input_stream(answers);
    CHECK(stream != NULL);
    if (!stream) goto cleanup;
    initialize_prompt_context(&ctx, true);
    before = ctx;
    g_prompt_gpg_m5_mode = PROMPT_GPG_M5_MISS;
    g_prompt_gpg_m5_calls = 0;

    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    if (redirected.saved_fd >= 0) {
        result = invoke_account_prompt_flow_capture(
            &ctx, true, output, sizeof(output));
    }
    end_input(&redirected);

    CHECK_EQ_INT(result, 0);
    CHECK_EQ_INT(g_prompt_gpg_m5_calls, 1);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK(strstr(output, expected_diagnostic) != NULL);
    CHECK(strstr(output, "(try again, or Enter to skip)") != NULL);
    CHECK_EQ_INT(count_occurrences(output, "GPG Key ID"), 2);
    CHECK(strstr(output, "Preferred Git Scope") != NULL);
    CHECK(strstr(output, "GPG key not found in keyring") == NULL);

cleanup:
    end_input(&redirected);
    if (stream) fclose(stream);
    CHECK_EQ_INT(prompt_gpg_m5_fixture_end(&fixture), 0);
}

static void exercise_gpg_operational_prompt_failure(
    bool edit, bool install_gpg, prompt_gpg_m5_mode_t mode,
    const char *selector, error_code_t expected_code,
    int expected_runner_calls,
    const char *expected_diagnostic) {
    char answers[256];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char output[8192];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t before;
    error_context_t reference_error;
    error_context_t error;
    prompt_gpg_m5_fixture_t fixture = {0};
    FILE *stream = NULL;
    redirected_stream_t redirected = { .stream = NULL, .saved_fd = -1 };
    uint64_t reference_generation_before;
    uint64_t reference_generation_after;
    uint64_t flow_generation_before;
    uint64_t flow_generation_after;
    int reference_errno;
    int flow_errno;
    int result = -2;

    CHECK_EQ_INT(prompt_gpg_m5_fixture_begin(&fixture, install_gpg), 0);
    if (!fixture.commands.active) goto cleanup;
    g_prompt_gpg_m5_mode = mode;
    g_prompt_gpg_m5_calls = 0;
    reference_generation_before = error_report_generation();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     selector, false, fingerprint, sizeof(fingerprint)),
                 -1);
    reference_error = *get_last_error();
    reference_errno = errno;
    reference_generation_after = error_report_generation();
    CHECK(reference_generation_after > reference_generation_before);
    CHECK_EQ_INT(g_prompt_gpg_m5_calls, expected_runner_calls);
    CHECK_EQ_INT(reference_error.code, expected_code);
    CHECK_STR_EQ(reference_error.message, expected_diagnostic);

    if (edit) {
        CHECK((size_t)snprintf(answers, sizeof(answers),
                               "\n\n\n\n%s\nlocal\n", selector) <
              sizeof(answers));
    } else {
        CHECK((size_t)snprintf(
                  answers, sizeof(answers),
                  "candidate\ncandidate@example.test\n\n\n%s\nlocal\n",
                  selector) < sizeof(answers));
    }
    stream = input_stream(answers);
    CHECK(stream != NULL);
    if (!stream) goto cleanup;
    initialize_prompt_context(&ctx, edit);
    before = ctx;
    g_prompt_gpg_m5_calls = 0;

    CHECK_EQ_INT(begin_input(stream, &redirected), 0);
    flow_generation_before = error_report_generation();
    if (redirected.saved_fd >= 0) {
        result = invoke_account_prompt_flow_capture(
            &ctx, edit, output, sizeof(output));
    }
    error = *get_last_error();
    flow_errno = errno;
    flow_generation_after = error_report_generation();
    end_input(&redirected);

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT(g_prompt_gpg_m5_calls, expected_runner_calls);
    CHECK(memcmp(&error, &reference_error, sizeof(error)) == 0);
    CHECK_EQ_INT(flow_errno, reference_errno);
    CHECK(flow_generation_after - flow_generation_before ==
          reference_generation_after - reference_generation_before);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK(accounts_transaction_context_release_safe(&ctx));
    CHECK(strstr(output, "GPG key validation failed:") != NULL);
    CHECK(strstr(output, expected_diagnostic) != NULL);
    CHECK(strstr(output, "(try again, or Enter to skip)") == NULL);
    CHECK(strstr(output, "GPG key not found in keyring") == NULL);
    CHECK(strstr(output, "Preferred Git Scope") == NULL);
    CHECK_EQ_INT(count_occurrences(output, "GPG Key ID"), 1);

cleanup:
    end_input(&redirected);
    if (stream) fclose(stream);
    CHECK_EQ_INT(prompt_gpg_m5_fixture_end(&fixture), 0);
}

TEST(operational_gpg_validation_errors_abort_without_reprompt_or_mutation) {
    exercise_gpg_operational_prompt_failure(
        true, false, PROMPT_GPG_M5_SETUP_126, "BADC0FFEE0DDF00D",
        ERR_GPG_NOT_FOUND, 0,
        "No trusted GPG executable ('gpg' or 'gpg2') found in PATH");
    exercise_gpg_operational_prompt_failure(
        false, true, PROMPT_GPG_M5_SETUP_126, "FEEDFACECAFED00D",
        ERR_GPG_KEY_FAILED, 1,
        "GPG secret-key helper failed during child setup or exec (exit 126) "
        "for FEEDFACECAFED00D");
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
    command_runner_fn old_runner;
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

    /* Every one of accounts.c's ten prompt sites receives an overlong answer
     * followed by the answer that must actually reach the account model:
     * name, email, description, SSH path, alias and canonical hostname
     * (AR-12 M2), GPG ID and signing choice, scope, then final
     * confirmation. */
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
    CHECK_EQ_INT(write_long_line(input, 'h'), 0);
    CHECK(fputs("github.com\n", input) != EOF);
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
    g_unavailable_gpg_runner_calls = 0;
    old_runner = run_set_runner(unavailable_gpg_runner);
    if (redirected_input.saved_fd >= 0 && redirected_output.saved_fd >= 0) {
        rc = accounts_add_interactive(&ctx);
    }
    run_set_runner(old_runner);
    CHECK_EQ_INT(fflush(stdout), 0);
    restore_fd(STDOUT_FILENO, &redirected_output);
    end_input(&redirected_input);

    CHECK_EQ_INT(g_unavailable_gpg_runner_calls, 0);
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
        CHECK_STR_EQ(ctx.accounts[0].ssh_hostname, "github.com");
        CHECK(ctx.accounts[0].gpg_enabled);
        CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "ABCDEF0123456789");
        CHECK(ctx.accounts[0].gpg_signing_enabled);
    }

    CHECK_EQ_INT(fseek(capture, 0, SEEK_SET), 0);
    {
        size_t size = fread(output, 1, sizeof(output) - 1, capture);
        output[size] = '\0';
    }
    CHECK_EQ_INT(count_occurrences(output, "Input is too long"), 10);

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
    /* Keep prompt bytes buffered until the explicit flush so the /dev/full
     * regression exercises the buffered-output failure path deterministically
     * even when the suite itself is launched from an interactive terminal. */
    (void)setvbuf(stdout, NULL, _IOFBF, BUFSIZ);
    RUN_TEST(prompt_write_ebadf_fails_before_consuming_confirmation);
    RUN_TEST(prompt_flush_enospc_fails_before_consuming_confirmation);
    RUN_TEST(exact_boundary_is_accepted);
    RUN_TEST(oversized_line_is_rejected_and_next_line_recovers);
    RUN_TEST(embedded_nul_rejects_one_line_and_preserves_the_next);
    RUN_TEST(unterminated_exact_boundary_and_eof_keep_their_semantics);
    RUN_TEST(success_clears_stale_error_state);
    RUN_TEST(empty_line_is_accepted_as_an_empty_answer);
    RUN_TEST(input_error_is_distinct_from_eof);
    RUN_TEST(readline_pty_input_error_is_distinct_from_eof);
#if defined(__GLIBC__)
    RUN_TEST(partial_initial_read_error_clears_the_caller_buffer);
    RUN_TEST(drain_error_is_not_reported_as_truncation);
#endif
    RUN_TEST(optional_prompt_failures_never_publish_add_or_edit_candidates);
    RUN_TEST(successful_blank_optional_answers_apply_only_documented_defaults);
    RUN_TEST(successful_nested_blank_answers_do_not_invent_alias_or_signing);
    RUN_TEST(successful_blank_edit_answers_preserve_the_account);
    RUN_TEST(
        blank_gpg_edit_can_change_only_signing_without_source_resolution);
    RUN_TEST(structured_gpg_miss_reprompts_and_blank_skip_completes);
    RUN_TEST(
        operational_gpg_validation_errors_abort_without_reprompt_or_mutation);
    RUN_TEST(account_flow_reprompts_without_accepting_any_prefix);
TEST_MAIN_END()
