/* Interactive line prompt with optional GNU readline support.
 *
 * When built with -DHAVE_READLINE (the Makefile auto-detects libreadline), the
 * prompts get line editing, history-free recall, and TAB completion; the SSH
 * key path prompt gets filename completion. Without readline it degrades
 * cleanly to fgets. Either way the returned line is newline-stripped and
 * whitespace-trimmed on both ends, and buf is always NUL-terminated.
 */

#ifndef PROMPT_H
#define PROMPT_H

#include <stddef.h>
#include <stdbool.h>

/* Read one line after printing `prompt`. If path_completion is true, TAB
 * completes filesystem paths (readline builds only). Returns 0 on success,
 * -1 on EOF/error (buf set to ""). */
int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion);

#endif /* PROMPT_H */
