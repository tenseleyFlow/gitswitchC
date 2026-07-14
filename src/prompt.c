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

static int prompt_line_stdio(const char *prompt, char *buf, size_t size) {
    if (!buf || size == 0) return PROMPT_LINE_ERROR;
    buf[0] = '\0';

    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }
    /* fgets cannot consume even an empty line with a one-byte destination. */
    if (size == 1) {
        int byte = prompt_getchar_retry();
        if (byte == EOF) {
            return ferror(stdin) ? PROMPT_LINE_ERROR : PROMPT_LINE_EOF;
        }
        if (byte != '\n') {
            int drain_result = prompt_drain_line();
            if (drain_result != PROMPT_LINE_OK) return drain_result;
            clear_error();
            return PROMPT_LINE_TRUNCATED;
        }
        clear_error();
        return PROMPT_LINE_OK;
    }

    if (!fgets(buf, (int)size, stdin)) {
        int saved_errno = errno;
        int result = ferror(stdin) ? PROMPT_LINE_ERROR : PROMPT_LINE_EOF;
        /* A failed fgets may already have copied a prefix. Never expose that
         * indeterminate partial answer to callers, and do not let cleanup
         * obscure the underlying input error. */
        buf[0] = '\0';
        errno = saved_errno;
        return result;
    }

    /* No newline is ambiguous: size - 1 bytes are a valid exact-boundary line
     * if the following byte is newline/EOF; any other byte proves overflow.
     * Drain that complete line so the retry starts at the next answer. */
    if (strchr(buf, '\n') == NULL) {
        int byte = prompt_getchar_retry();
        if (byte != '\n' && byte != EOF) {
            int drain_result = prompt_drain_line();
            buf[0] = '\0';
            if (drain_result != PROMPT_LINE_OK) return drain_result;
            clear_error();
            return PROMPT_LINE_TRUNCATED;
        }
        if (byte == EOF && ferror(stdin)) {
            buf[0] = '\0';
            return PROMPT_LINE_ERROR;
        }
    }
    buf[strcspn(buf, "\n")] = '\0';

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

    char *line = readline(prompt ? prompt : "");
    if (!line) {
        return ferror(stdin) ? PROMPT_LINE_ERROR
                             : PROMPT_LINE_EOF; /* EOF (Ctrl-D) */
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
