/* Interactive line prompt — see prompt.h. */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "prompt.h"
#include "utils.h"
#include "error.h"

static int prompt_getchar_retry(void) {
    for (;;) {
        errno = 0;
        int byte = fgetc(stdin);
        if (byte != EOF || !ferror(stdin) || errno != EINTR) return byte;
        clearerr(stdin);
    }
}

static int prompt_drain_line(void) {
    int byte;
    do {
        byte = prompt_getchar_retry();
    } while (byte != '\n' && byte != EOF);
    return byte == EOF && ferror(stdin) ? PROMPT_LINE_ERROR
                                        : PROMPT_LINE_OK;
}

/* Byte-wise reader instead of fgets (AR-10 L32): fgets gives no length back,
 * so an embedded NUL hid the newline fgets HAD consumed from the strchr scan
 * — the "is the next byte a newline?" probe then ate the first byte of the
 * FOLLOWING line and the drain destroyed the rest of it. Reading bytes
 * directly keeps consumption exactly one line regardless of content. */
static int prompt_line_stdio(const char *prompt, char *buf, size_t size) {
    size_t used = 0;
    bool saw_nul = false;
    bool saw_any = false;

    if (!buf || size == 0) return PROMPT_LINE_ERROR;
    buf[0] = '\0';

    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    for (;;) {
        int byte = prompt_getchar_retry();
        if (byte == EOF) {
            if (ferror(stdin)) {
                buf[0] = '\0';
                return PROMPT_LINE_ERROR;
            }
            if (!saw_any) return PROMPT_LINE_EOF;
            break; /* final line without a trailing newline */
        }
        saw_any = true;
        if (byte == '\n') break;
        if (byte == '\0') {
            /* A NUL can never survive into a C-string answer; keep consuming
             * this line only and reject it below so the caller re-asks. */
            saw_nul = true;
            continue;
        }
        if (used + 1U >= size) {
            /* Overflow: drain the remainder of THIS line so the retry starts
             * at the next answer. A prefix is never a valid answer. */
            int drain_result = prompt_drain_line();
            buf[0] = '\0';
            if (drain_result != PROMPT_LINE_OK) return drain_result;
            clear_error();
            return PROMPT_LINE_TRUNCATED;
        }
        buf[used++] = (char)byte;
    }
    buf[used] = '\0';

    if (saw_nul) {
        buf[0] = '\0';
        clear_error();
        return PROMPT_LINE_TRUNCATED;
    }

    char *trimmed = trim_whitespace(buf);
    if (trimmed != buf) {
        memmove(buf, trimmed, strlen(trimmed) + 1);
    }
    clear_error();
    return PROMPT_LINE_OK;
}

#ifdef HAVE_READLINE
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion) {
    if (!buf || size == 0) return PROMPT_LINE_ERROR;
    buf[0] = '\0';

    /* readline writes the physical input back to stdout even when input is a
     * pipe or file. Besides being surprising for scripts, that reflected a
     * rejected control-bearing value before the caller could validate it.
     * Line editing only has meaning on a real terminal; redirected flows use
     * the same bounded, non-echoing reader as no-readline builds. */
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        return prompt_line_stdio(prompt, buf, size);
    }

    /* Only offer filename completion where it helps (the SSH key path);
     * elsewhere a stray TAB should not spew the working directory. */
    rl_inhibit_completion = path_completion ? 0 : 1;

    errno = 0;
    char *line = readline(prompt ? prompt : "");
    if (!line) {
        /* AR-10 L34: readline reads through its own read(2) and never sets
         * stdio's error flag, so ferror(stdin) was structurally false here
         * and a hard tty error was misclassified as a polite EOF. readline
         * leaves the failing read's errno in place; classify the specific
         * hard-error values and keep everything else as EOF (Ctrl-D). */
        int saved_errno = errno;
        if (ferror(stdin) || saved_errno == EIO || saved_errno == EBADF ||
            saved_errno == ENXIO) {
            return PROMPT_LINE_ERROR;
        }
        return PROMPT_LINE_EOF;
    }

    /* Apply the limit to the physical input, before trimming, so readline and
     * fgets builds accept exactly the same lines. A prefix is never a valid
     * answer: the caller can distinguish this result and ask again. */
    if (strlen(line) >= size) {
        free(line);
        clear_error();
        return PROMPT_LINE_TRUNCATED;
    }

    char *trimmed = trim_whitespace(line); /* trims both ends, may offset */
    memcpy(buf, trimmed, strlen(trimmed) + 1);
    free(line);
    clear_error();
    return PROMPT_LINE_OK;
}

#else /* !HAVE_READLINE */

int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion) {
    (void)path_completion;
    return prompt_line_stdio(prompt, buf, size);
}

#endif
