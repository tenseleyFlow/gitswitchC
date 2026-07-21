/* Display and user interface functions
 * Provides safe, accessible terminal output for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "display.h"
#include "utils.h"
#include "error.h"

typedef enum {
    DISPLAY_COLOR_DISABLED,
    DISPLAY_COLOR_FORCED,
    DISPLAY_COLOR_AUTOMATIC
} display_color_policy_t;

/* Automatic mode combines process-wide terminal capability with the TTY
 * state of the stream used for each emission. Keeping the policy distinct
 * prevents a stdout decision from leaking into stderr diagnostics. */
static display_color_policy_t g_color_policy = DISPLAY_COLOR_DISABLED;
static bool g_auto_color_capable = false;
static int g_terminal_width = 80;
static int g_terminal_height = 24;

/* Format a complete diagnostic before any bytes are emitted.  The first pass
 * determines the exact allocation, and the second pass is checked again: an
 * encoding error (for example, an unrepresentable %lc) or an inconsistent
 * result must never expose a partially initialized buffer to a display path. */
static char *display_vformat(const char *format, va_list arguments) {
    va_list measured_arguments;
    va_list written_arguments;
    int required;
    int written;
    size_t buffer_size;
    char *buffer;

    if (!format) return NULL;

    va_copy(measured_arguments, arguments);
    required = vsnprintf(NULL, 0, format, measured_arguments); /* Flawfinder: ignore -- sizing pass; fmt from internal callers */
    va_end(measured_arguments);
    /* AR-10 L5: a non-negative int always fits in size_t with room for the
     * terminator (INT_MAX < SIZE_MAX), so only the failure sign needs a guard. */
    if (required < 0) return NULL;

    buffer_size = (size_t)required + 1U;
    buffer = malloc(buffer_size);
    if (!buffer) return NULL;

    va_copy(written_arguments, arguments);
    written = vsnprintf(buffer, buffer_size, format, written_arguments); /* Flawfinder: ignore -- exact checked allocation; fmt from internal callers */
    va_end(written_arguments);
    if (written < 0 || written != required ||
        (size_t)written >= buffer_size) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

/* Color support detection */
static bool detect_color_support(void) {
    const char *term = getenv("TERM");
    const char *colorterm = getenv("COLORTERM");
    
    /* A non-empty COLORTERM identifies a color-capable environment. */
    if (colorterm && *colorterm) {
        return true;
    }
    
    /* Check for common color-capable terminals */
    if (term) {
        if (strstr(term, "color") || 
            strstr(term, "xterm") ||
            strstr(term, "screen") ||
            strstr(term, "tmux") ||
            strcmp(term, "linux") == 0) {
            return true;
        }
    }
    
    return false;
}

static const char *display_color_policy_name(void) {
    switch (g_color_policy) {
        case DISPLAY_COLOR_DISABLED:
            return "disabled";
        case DISPLAY_COLOR_FORCED:
            return "forced";
        case DISPLAY_COLOR_AUTOMATIC:
            return "automatic";
        default:
            return "unknown";
    }
}

/* Terminal probing is advisory and must not overwrite a caller's errno.
 * Forced and disabled policy remain global; only automatic mode inspects the
 * descriptor currently backing the actual destination stream. */
static bool display_stream_supports_color(FILE *stream) {
    int saved_errno;
    int descriptor;
    bool supported;

    if (g_color_policy == DISPLAY_COLOR_DISABLED) return false;
    if (g_color_policy == DISPLAY_COLOR_FORCED) return true;
    if (!stream || !g_auto_color_capable) return false;

    saved_errno = errno;
    descriptor = fileno(stream);
    supported = descriptor >= 0 && is_terminal(descriptor);
    errno = saved_errno;
    return supported;
}

/* Initialize display system */
int display_init(bool force_color, bool no_color) {
    g_auto_color_capable = false;
    if (no_color) {
        g_color_policy = DISPLAY_COLOR_DISABLED;
    } else if (force_color) {
        g_color_policy = DISPLAY_COLOR_FORCED;
    } else {
        /* AR-10 L6: honor the ecosystem conventions between the explicit CLI
         * flags and auto-detection. NO_COLOR (any non-empty value) disables;
         * CLICOLOR_FORCE (non-empty, not "0") forces color even when a stream
         * is not a terminal. https://no-color.org / https://bixense.com/clicolors */
        const char *no_color_env = getenv("NO_COLOR");
        const char *force_env = getenv("CLICOLOR_FORCE");

        if (no_color_env && *no_color_env) {
            g_color_policy = DISPLAY_COLOR_DISABLED;
        } else if (force_env && *force_env && strcmp(force_env, "0") != 0) {
            g_color_policy = DISPLAY_COLOR_FORCED;
        } else {
            g_color_policy = DISPLAY_COLOR_AUTOMATIC;
            g_auto_color_capable = detect_color_support();
        }
    }
    
    /* Get terminal size */
    if (get_terminal_size(&g_terminal_width, &g_terminal_height) != 0) {
        /* Use defaults if we can't get size */
        g_terminal_width = 80;
        g_terminal_height = 24;
    }
    
    log_debug("Display initialized: color-policy=%s, auto-capable=%s, size=%dx%d",
              display_color_policy_name(),
              g_auto_color_capable ? "yes" : "no",
              g_terminal_width, g_terminal_height);
    
    return 0;
}

/* Report the current policy result for the stdout-oriented public API. */
bool display_supports_color(void) {
    return display_stream_supports_color(stdout);
}

/* Format and colorize text based on content type. Each result has independent
 * caller-owned storage, so later calls cannot invalidate a retained pointer. */
static char *display_colorize_with_decision(const char *text, const char *type,
                                            bool color_enabled) {
    char *result;
    const char *color_code = NULL;
    size_t code_len;
    size_t text_len;
    size_t reset_len;
    size_t required;

    if (!text) return NULL;

    /* Select color based on type */
    if (!color_enabled || !type) {
        color_code = NULL;
    } else if (strcmp(type, "success") == 0) {
        color_code = COLOR_GREEN;
    } else if (strcmp(type, "error") == 0) {
        color_code = COLOR_RED;
    } else if (strcmp(type, "warning") == 0) {
        color_code = COLOR_YELLOW;
    } else if (strcmp(type, "info") == 0) {
        color_code = COLOR_BLUE;
    } else if (strcmp(type, "header") == 0) {
        color_code = COLOR_BOLD COLOR_CYAN;
    } else if (strcmp(type, "current") == 0) {
        color_code = COLOR_BOLD COLOR_GREEN;
    } else if (strcmp(type, "inactive") == 0) {
        color_code = COLOR_DIM;
    }

    text_len = strlen(text);
    if (!color_code) {
        if (text_len == SIZE_MAX) return NULL;
        result = malloc(text_len + 1U);
        if (!result) return NULL;
        memcpy(result, text, text_len + 1U);
        return result;
    }

    code_len = strlen(color_code);
    reset_len = strlen(COLOR_RESET);
    if (code_len > SIZE_MAX - reset_len - 1U ||
        text_len > SIZE_MAX - code_len - reset_len - 1U) {
        return NULL;
    }
    required = code_len + text_len + reset_len + 1U;

    result = malloc(required);
    if (!result) return NULL;
    memcpy(result, color_code, code_len);
    memcpy(result + code_len, text, text_len);
    memcpy(result + code_len + text_len, COLOR_RESET,
           reset_len + 1U);

    return result;
}

char *display_colorize(const char *text, const char *type) {
    return display_colorize_with_decision(
        text, type, display_stream_supports_color(stdout));
}

/* Print formatted header with decorative border. Widths are counted in BYTES,
 * which equals display columns only for single-width ASCII titles — every
 * in-tree caller. A multibyte/wide title would misalign the box (AR-10 L1);
 * widen this to wcswidth() accounting before introducing such a caller. */
void display_header(const char *title) {
    int title_len, padding, inner_width, total_width;
    int i;
    char *truncated = NULL;
    char *colored_title;
    const char *shown;

    if (!title) return;

    title_len = (int)strlen(title);
    total_width = (title_len + 4 > 40) ? title_len + 4 : 40;
    if (total_width > g_terminal_width - 2) {
        total_width = g_terminal_width - 2;
    }
    /* Keep the box drawable even on absurdly narrow terminals. */
    if (total_width < 4) {
        total_width = 4;
    }
    inner_width = total_width - 2;

    /* AR-10 L2: the clamp above can leave the title wider than the box, and
     * the old code fed the resulting NEGATIVE field widths to %*s —
     * left-justifying with a positive width and WIDENING exactly the line it
     * meant to shrink. Truncate the plain title to the inner width (before
     * colorizing, so an escape sequence is never split) and keep both pads
     * non-negative. */
    if (title_len > inner_width) {
        truncated = malloc((size_t)inner_width + 1U);
        if (!truncated) return;
        memcpy(truncated, title, (size_t)inner_width);
        truncated[inner_width] = '\0';
        title_len = inner_width;
    }
    shown = truncated ? truncated : title;

    padding = (inner_width - title_len) / 2;

    /* Top border */
    printf("┌");
    for (i = 0; i < total_width - 2; i++) {
        printf("─");
    }
    printf("┐\n");

    /* Title line. No bare COLOR_RESET here: display_colorize already appends
     * the reset when color is on, and with color off it returns the plain
     * text — an unconditional reset would inject a raw ESC[0m into
     * --no-color/piped output (AR-03 L15). */
    colored_title = display_colorize(shown, "header");
    printf("│%*s%s%*s│\n",
           padding, "",
           colored_title ? colored_title : shown,
           inner_width - title_len - padding, "");
    free(colored_title);
    free(truncated);

    /* Bottom border */
    printf("└");
    for (i = 0; i < total_width - 2; i++) {
        printf("─");
    }
    printf("┘\n");
    /* AR-10 L7: match display_status's flush discipline so a header is never
     * stranded in the stdio buffer ahead of an interleaved stderr line. */
    fflush(stdout);
}

/* Print status message with appropriate color and icon */
void display_status(const char *level, const char *message, ...) {
    va_list args;
    char *formatted_message;
    char *colored_icon;
    char *colored_message = NULL;
    const char *icon = "";
    const char *color_type = "";
    
    if (!level || !message) return;
    
    /* Format the message */
    va_start(args, message);
    formatted_message = display_vformat(message, args);
    va_end(args);
    if (!formatted_message) return;
    
    /* Select icon and color based on level */
    if (strcmp(level, "success") == 0) {
        icon = STATUS_SUCCESS;
        color_type = "success";
    } else if (strcmp(level, "error") == 0) {
        icon = STATUS_ERROR;
        color_type = "error";
    } else if (strcmp(level, "warning") == 0) {
        icon = STATUS_WARNING;
        color_type = "warning";
    } else if (strcmp(level, "info") == 0) {
        icon = STATUS_INFO;
        color_type = "info";
    } else {
        icon = "-";
        color_type = "info";
    }
    
    /* AR-10 L4: user-facing errors follow the Unix convention — diagnostics
     * on stderr, results on stdout. Routing them to stdout interleaved error
     * text into pipelines and shell-eval'd output (`gitswitch init`) while
     * the internal log already went to stderr. */
    {
        FILE *out = strcmp(level, "error") == 0 ? stderr : stdout;
        bool color_enabled = display_stream_supports_color(out);

        colored_icon = display_colorize_with_decision(icon, color_type,
                                                       color_enabled);
        if (formatted_message[0] != '\0') {
            colored_message = display_colorize_with_decision(
                formatted_message, color_type, color_enabled);
            fprintf(out, "%s %s\n",
                    colored_icon ? colored_icon : icon,
                    colored_message ? colored_message : formatted_message);
        } else {
            fprintf(out, "%s\n", colored_icon ? colored_icon : icon);
        }
        fflush(out);
    }
    free(colored_message);
    free(colored_icon);
    free(formatted_message);
}

/* Print error message with context */
void display_error(const char *context, const char *message, ...) {
    va_list args;
    char *formatted_message;
    
    if (!message) return;
    
    va_start(args, message);
    formatted_message = display_vformat(message, args);
    va_end(args);
    if (!formatted_message) return;

    /* Don't display if message is empty */
    if (formatted_message[0] == '\0') {
        free(formatted_message);
        return;
    }
    
    if (context && strlen(context) > 0) {
        display_status("error", "%s: %s", context, formatted_message);
    } else {
        display_status("error", "%s", formatted_message);
    }
    free(formatted_message);
}

/* Print warning message */
void display_warning(const char *message, ...) {
    va_list args;
    char *formatted_message;
    
    if (!message) return;
    
    va_start(args, message);
    formatted_message = display_vformat(message, args);
    va_end(args);
    if (!formatted_message) return;

    display_status("warning", "%s", formatted_message);
    free(formatted_message);
}

/* Print success message */
void display_success(const char *message, ...) {
    va_list args;
    char *formatted_message;
    
    if (!message) return;
    
    va_start(args, message);
    formatted_message = display_vformat(message, args);
    va_end(args);
    if (!formatted_message) return;

    display_status("success", "%s", formatted_message);
    free(formatted_message);
}

/* Print info message */
void display_info(const char *message, ...) {
    va_list args;
    char *formatted_message;
    
    if (!message) return;
    
    va_start(args, message);
    formatted_message = display_vformat(message, args);
    va_end(args);
    if (!formatted_message) return;

    display_status("info", "%s", formatted_message);
    free(formatted_message);
}

/* Print configuration file location and status */
void display_config_info(const gitswitch_ctx_t *ctx) {
    const char *status_text;
    const char *status_type;
    char *colored_status;

    if (!ctx) return;
    
    printf("\n");
    printf("Configuration: %s\n", ctx->config.config_path);
    printf("Accounts:      %zu configured\n", ctx->account_count);
    
    if (path_exists(ctx->config.config_path)) {
        status_text = "exists";
        status_type = "success";
    } else {
        status_text = "not found";
        status_type = "warning";
    }
    colored_status = display_colorize(status_text, status_type);
    printf("Status:        %s\n",
           colored_status ? colored_status : status_text);
    free(colored_status);
    fflush(stdout);
}
