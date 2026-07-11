/* Display and user interface functions
 * Provides safe, accessible terminal output for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <termios.h>

#include "display.h"
#include "utils.h"
#include "error.h"
#include "git_ops.h"

/* Global display state */
static bool g_color_enabled = false;
static bool g_color_forced = false;
static int g_terminal_width = 80;
static int g_terminal_height = 24;

/* Color support detection */
static bool detect_color_support(void) {
    const char *term = getenv("TERM");
    const char *colorterm = getenv("COLORTERM");
    
    /* Force color if COLORTERM is set */
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

/* Initialize display system */
int display_init(bool force_color, bool no_color) {
    if (no_color) {
        g_color_enabled = false;
        g_color_forced = true;
    } else if (force_color) {
        g_color_enabled = true;
        g_color_forced = true;
    } else {
        /* Auto-detect color support */
        g_color_enabled = is_terminal(STDOUT_FILENO) && detect_color_support();
        g_color_forced = false;
    }
    
    /* Get terminal size */
    if (get_terminal_size(&g_terminal_width, &g_terminal_height) != 0) {
        /* Use defaults if we can't get size */
        g_terminal_width = 80;
        g_terminal_height = 24;
    }
    
    log_debug("Display initialized: color=%s, size=%dx%d", 
              g_color_enabled ? "enabled" : "disabled",
              g_terminal_width, g_terminal_height);
    
    return 0;
}

/* Check if terminal supports color output */
bool display_supports_color(void) {
    return g_color_enabled;
}

/* Format and colorize text based on content type */
const char *display_colorize(const char *text, const char *type) {
    /* Rotating buffers so several calls can appear in one printf argument list
     * (all args are evaluated before printf runs). Keep this >= the most
     * colorize() results ever live in a single expression, or an earlier call's
     * buffer gets clobbered by a later one before printf reads it. */
    enum { COLORED_BUFFER_SIZE = 512 };
    static char colored_buffers[8][COLORED_BUFFER_SIZE];
    static int buffer_index = 0;
    char *colored_buffer;
    const char *color_code = "";

    if (!g_color_enabled || !text || !type) {
        return text;
    }

    /* Select color based on type */
    if (strcmp(type, "success") == 0) {
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
    } else {
        return text; /* No coloring */
    }

    /* Use next buffer in rotation */
    colored_buffer = colored_buffers[buffer_index];
    buffer_index = (buffer_index + 1) % (int)(sizeof(colored_buffers) / sizeof(colored_buffers[0]));

    /* AR-06 F54/F55: reserve room for the trailing COLOR_RESET so it is NEVER
     * the part that gets truncated. A long message that overran the 512-byte
     * buffer used to lose its reset, leaving the terminal stuck in the color
     * (and every following line miscolored). Bound the TEXT with a precision so
     * the prefix color code and the reset always fit. */
    {
        size_t code_len = strlen(color_code);
        size_t reset_len = strlen(COLOR_RESET);
        int text_budget = (int)COLORED_BUFFER_SIZE - 1 - (int)code_len - (int)reset_len;
        if (text_budget < 0) {
            text_budget = 0;
        }
        snprintf(colored_buffer, COLORED_BUFFER_SIZE,
                 "%s%.*s%s", color_code, text_budget, text, COLOR_RESET);
    }

    return colored_buffer;
}

/* Print formatted header with decorative border */
void display_header(const char *title) {
    int title_len, padding, total_width;
    int i;
    
    if (!title) return;
    
    title_len = strlen(title);
    total_width = (title_len + 4 > 40) ? title_len + 4 : 40;
    if (total_width > g_terminal_width - 2) {
        total_width = g_terminal_width - 2;
    }
    
    padding = (total_width - title_len - 2) / 2;
    
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
    printf("│%*s%s%*s│\n",
           padding, "",
           display_colorize(title, "header"),
           total_width - title_len - padding - 2, "");
    
    /* Bottom border */
    printf("└");
    for (i = 0; i < total_width - 2; i++) {
        printf("─");
    }
    printf("┘\n");
}

/* Print status message with appropriate color and icon */
void display_status(const char *level, const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    const char *icon = "";
    const char *color_type = "";
    
    if (!level || !message) return;
    
    /* Format the message */
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args); /* Flawfinder: ignore — bounded; fmt from internal callers */
    va_end(args);
    
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
    
    if (strlen(formatted_message) > 0) {
        printf("%s %s\n",
               display_colorize(icon, color_type),
               display_colorize(formatted_message, color_type));
    } else {
        printf("%s\n", display_colorize(icon, color_type));
    }
    fflush(stdout);
}

/* Print error message with context */
void display_error(const char *context, const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args); /* Flawfinder: ignore — bounded; fmt from internal callers */
    va_end(args);
    
    /* Don't display if message is empty */
    if (strlen(formatted_message) == 0) return;
    
    if (context && strlen(context) > 0) {
        display_status("error", "%s: %s", context, formatted_message);
    } else {
        display_status("error", "%s", formatted_message);
    }
}

/* Print warning message */
void display_warning(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args); /* Flawfinder: ignore — bounded; fmt from internal callers */
    va_end(args);
    
    display_status("warning", "%s", formatted_message);
}

/* Print success message */
void display_success(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args); /* Flawfinder: ignore — bounded; fmt from internal callers */
    va_end(args);
    
    display_status("success", "%s", formatted_message);
}

/* Print info message */
void display_info(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args); /* Flawfinder: ignore — bounded; fmt from internal callers */
    va_end(args);
    
    display_status("info", "%s", formatted_message);
}

/* Print configuration file location and status */
void display_config_info(const gitswitch_ctx_t *ctx) {
    if (!ctx) return;
    
    printf("\n");
    printf("Configuration: %s\n", ctx->config.config_path);
    printf("Accounts:      %zu configured\n", ctx->account_count);
    
    if (path_exists(ctx->config.config_path)) {
        printf("Status:        %s\n", display_colorize("exists", "success"));
    } else {
        printf("Status:        %s\n", display_colorize("not found", "warning"));
    }
}
