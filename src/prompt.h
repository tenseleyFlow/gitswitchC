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

typedef enum {
    PROMPT_LINE_OK = 0,
    PROMPT_LINE_EOF = -1,
    PROMPT_LINE_TRUNCATED = -2,
    PROMPT_LINE_ERROR = -3
} prompt_result_t;

/* Read one line after printing `prompt`. If path_completion is true, TAB
 * completes filesystem paths (readline builds only). At most size - 1 input
 * bytes are accepted; an overlong physical line is consumed but never exposed
 * as a successful prefix. Every non-success result leaves buf empty. */
int prompt_line(const char *prompt, char *buf, size_t size, bool path_completion);

/* Checked destructive-confirmation variant. The complete prompt is flushed
 * before stdin is touched. Returns 1 only for exact `yes`, 0 for any other or
 * overlong answer, PROMPT_LINE_EOF for clean EOF, and PROMPT_LINE_ERROR for a
 * prompt-output or input failure while preserving the causal errno. */
int prompt_confirm_exact_yes_prompt(const char *prompt);

/* AR-10 L20 compatibility entry point for the shared exact-yes rule. It
 * flushes any caller-emitted warning/prompt before reading, returns 1 only for
 * exact `yes` after surrounding-whitespace trimming, 0 for any other or
 * overlong answer, and -1 for EOF or input/output failure. New destructive
 * callers use the detailed variant above. */
int prompt_confirm_exact_yes(void);

#endif /* PROMPT_H */
