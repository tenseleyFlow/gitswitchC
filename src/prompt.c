/* Interactive line prompt — see prompt.h. */

#include <stdio.h>
#include <string.h>

#include "prompt.h"
#include "utils.h"
#include "error.h"

#ifdef HAVE_READLINE
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion) {
    if (!buf || size == 0) return -1;
    buf[0] = '\0';

    /* Only offer filename completion where it helps (the SSH key path);
     * elsewhere a stray TAB should not spew the working directory. */
    rl_inhibit_completion = path_completion ? 0 : 1;

    char *line = readline(prompt ? prompt : "");
    if (!line) {
        return -1; /* EOF (Ctrl-D) */
    }

    char *trimmed = trim_whitespace(line); /* trims both ends, may offset */
    if (safe_strncpy(buf, trimmed, size) != 0) {
        /* Too long for buf: keep what fits rather than nothing. */
        strncpy(buf, trimmed, size - 1);
        buf[size - 1] = '\0';
    }
    free(line);
    return 0;
}

#else /* !HAVE_READLINE */

int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion) {
    (void)path_completion;
    if (!buf || size == 0) return -1;
    buf[0] = '\0';

    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }
    if (!fgets(buf, (int)size, stdin)) {
        return -1;
    }
    buf[strcspn(buf, "\n")] = '\0';

    char *trimmed = trim_whitespace(buf);
    if (trimmed != buf) {
        memmove(buf, trimmed, strlen(trimmed) + 1);
    }
    return 0;
}

#endif
