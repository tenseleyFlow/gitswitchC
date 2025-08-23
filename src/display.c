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
    static char colored_buffer[512];
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
    
    snprintf(colored_buffer, sizeof(colored_buffer), 
             "%s%s%s", color_code, text, COLOR_RESET);
    
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
    
    /* Title line */
    printf("│%*s%s%s%*s│\n", 
           padding, "",
           display_colorize(title, "header"),
           COLOR_RESET,
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
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
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
}

/* Print error message with context */
void display_error(const char *context, const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);
    
    if (context) {
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
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);
    
    display_status("warning", "%s", formatted_message);
}

/* Print success message */
void display_success(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);
    
    display_status("success", "%s", formatted_message);
}

/* Print info message */
void display_info(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    
    if (!message) return;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);
    
    display_status("info", "%s", formatted_message);
}

/* Format table with proper column alignment */
void display_table_header(const char **headers, const int *widths, int columns) {
    int i;
    
    if (!headers || !widths || columns <= 0) return;
    
    /* Print header row */
    printf("│");
    for (i = 0; i < columns; i++) {
        printf(" %s%-*s%s │", 
               display_colorize("", "header"),
               widths[i] - 1, headers[i],
               COLOR_RESET);
    }
    printf("\n");
    
    /* Print separator */
    printf("├");
    for (i = 0; i < columns; i++) {
        int j;
        for (j = 0; j < widths[i] + 1; j++) {
            printf("─");
        }
        printf(i < columns - 1 ? "┼" : "┤");
    }
    printf("\n");
}

void display_table_row(const char **values, const int *widths, int columns) {
    int i;
    
    if (!values || !widths || columns <= 0) return;
    
    printf("│");
    for (i = 0; i < columns; i++) {
        printf(" %-*s │", widths[i] - 1, values[i] ? values[i] : "");
    }
    printf("\n");
}

void display_table_separator(const int *widths, int columns) {
    int i;
    
    if (!widths || columns <= 0) return;
    
    printf("└");
    for (i = 0; i < columns; i++) {
        int j;
        for (j = 0; j < widths[i] + 1; j++) {
            printf("─");
        }
        printf(i < columns - 1 ? "┴" : "┘");
    }
    printf("\n");
}

/* Print account information in formatted table */
void display_account(const account_t *account, bool is_current) {
    if (!account) return;
    
    const char *marker = is_current ? "→" : " ";
    const char *color_type = is_current ? "current" : "inactive";
    
    printf("%s %s%3u%s │ %s%-20s%s │ %s%-30s%s │ %s%s%s\n",
           display_colorize(marker, color_type),
           display_colorize("", color_type), account->id, COLOR_RESET,
           display_colorize("", color_type), account->name, COLOR_RESET,
           display_colorize("", color_type), account->email, COLOR_RESET,
           display_colorize("", color_type), account->description, COLOR_RESET);
}

/* Print accounts list in formatted table */
void display_accounts_list(const gitswitch_ctx_t *ctx) {
    const char *headers[] = {"", "ID", "Name", "Email", "Description"};
    const int widths[] = {3, 5, 22, 32, 30};
    size_t i;
    
    if (!ctx) return;
    
    if (ctx->account_count == 0) {
        display_info("No accounts configured");
        display_info("Run 'gitswitch add' to create your first account");
        return;
    }
    
    printf("\n");
    display_header("Configured Accounts");
    printf("\n");
    
    /* Print table */
    display_table_header(headers, widths, 5);
    
    for (i = 0; i < ctx->account_count; i++) {
        bool is_current = ctx->current_account && 
                         ctx->current_account->id == ctx->accounts[i].id;
        display_account(&ctx->accounts[i], is_current);
    }
    
    display_table_separator(widths, 5);
    printf("\n");
}

/* These functions will be implemented in later phases when we have git/ssh/gpg components

void display_current_status(const git_current_config_t *config) { ... }
void display_ssh_status(const ssh_config_t *ssh_config) { ... }
void display_gpg_status(const gpg_config_t *gpg_config) { ... }
void display_validation_results(const account_validation_t *validation) { ... }

*/

/* Print health check results */
void display_health_check(const gitswitch_ctx_t *ctx) {
    if (!ctx) return;
    
    printf("\n");
    display_header("System Health Check");
    printf("\n");
    
    /* Check git availability */
    if (command_exists("git")) {
        display_success("Git is available");
    } else {
        display_error("Git command not found", "Install git to use gitswitch");
    }
    
    /* Check SSH agent */
    if (command_exists("ssh-agent")) {
        display_success("SSH agent is available");
    } else {
        display_warning("SSH agent not found - SSH key management may not work");
    }
    
    /* Check GPG */
    if (command_exists("gpg") || command_exists("gpg2")) {
        display_success("GPG is available");
    } else {
        display_warning("GPG not found - GPG signing will not work");
    }
    
    /* Check configuration */
    char config_path[MAX_PATH_LEN];
    if (get_config_directory(config_path, sizeof(config_path)) == 0) {
        if (is_directory(config_path)) {
            display_success("Configuration directory exists: %s", config_path);
        } else {
            display_warning("Configuration directory not found: %s", config_path);
        }
    }
    
    printf("\n");
}

/* Display interactive account selection menu */
uint32_t display_account_menu(const gitswitch_ctx_t *ctx) {
    char input[64];
    char *endptr;
    unsigned long selected_id;
    
    if (!ctx || ctx->account_count == 0) {
        display_error("No accounts available", "");
        return 0;
    }
    
    display_accounts_list(ctx);
    
    printf("Select account (ID or name): ");
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        display_error("Failed to read input", "");
        return 0;
    }
    
    /* Remove trailing newline */
    input[strcspn(input, "\n")] = '\0';
    trim_whitespace(input);
    
    if (string_empty(input)) {
        return 0; /* User cancelled */
    }
    
    /* Try to parse as number first */
    selected_id = strtoul(input, &endptr, 10);
    if (*endptr == '\0' && selected_id > 0) {
        /* It's a valid number - verify it exists */
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id == (uint32_t)selected_id) {
                return (uint32_t)selected_id;
            }
        }
        display_error("Account ID not found", "%lu", selected_id);
        return 0;
    }
    
    /* Search by name/description */
    account_t *found = find_account_in_array((account_t *)ctx->accounts, 
                                            ctx->account_count, input);
    if (found) {
        return found->id;
    }
    
    display_error("Account not found", "%s", input);
    return 0;
}

/* Prompt user for account information during add/edit */
int display_prompt_account_info(account_t *account, bool is_edit) {
    char input[512];
    char *trimmed;
    
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to display_prompt_account_info");
        return -1;
    }
    
    printf("\n");
    display_header(is_edit ? "Edit Account" : "Add New Account");
    printf("\n");
    
    /* Name */
    printf("Name%s: ", is_edit ? " (current: " : "");
    if (is_edit && account->name[0] != '\0') {
        printf("%s): ", account->name);
    }
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        trimmed = trim_whitespace(input);
        trimmed[strcspn(trimmed, "\n")] = '\0';
        if (strlen(trimmed) > 0 && validate_name(trimmed)) {
            safe_strncpy(account->name, trimmed, sizeof(account->name));
        } else if (!is_edit) {
            display_error("Invalid name", "Name cannot be empty");
            return -1;
        }
    }
    
    /* Email */
    printf("Email%s: ", is_edit ? " (current: " : "");
    if (is_edit && account->email[0] != '\0') {
        printf("%s): ", account->email);
    }
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        trimmed = trim_whitespace(input);
        trimmed[strcspn(trimmed, "\n")] = '\0';
        if (strlen(trimmed) > 0 && validate_email(trimmed)) {
            safe_strncpy(account->email, trimmed, sizeof(account->email));
        } else if (!is_edit) {
            display_error("Invalid email", "Please enter a valid email address");
            return -1;
        }
    }
    
    /* Description */
    printf("Description%s: ", is_edit ? " (current: " : "");
    if (is_edit && account->description[0] != '\0') {
        printf("%s): ", account->description);
    }
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        trimmed = trim_whitespace(input);
        trimmed[strcspn(trimmed, "\n")] = '\0';
        if (strlen(trimmed) > 0) {
            safe_strncpy(account->description, trimmed, sizeof(account->description));
        }
    }
    
    /* SSH Key Path */
    printf("SSH Key Path (optional)%s: ", is_edit ? " (current: " : "");
    if (is_edit && account->ssh_key_path[0] != '\0') {
        printf("%s): ", account->ssh_key_path);
    }
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        trimmed = trim_whitespace(input);
        trimmed[strcspn(trimmed, "\n")] = '\0';
        if (strlen(trimmed) > 0) {
            char expanded[MAX_PATH_LEN];
            if (expand_path(trimmed, expanded, sizeof(expanded)) == 0 && 
                path_exists(expanded)) {
                safe_strncpy(account->ssh_key_path, expanded, sizeof(account->ssh_key_path));
                account->ssh_enabled = true;
            } else {
                display_warning("SSH key file not found: %s", trimmed);
                account->ssh_enabled = false;
            }
        }
    }
    
    /* GPG Key ID */
    printf("GPG Key ID (optional)%s: ", is_edit ? " (current: " : "");
    if (is_edit && account->gpg_key_id[0] != '\0') {
        printf("%s): ", account->gpg_key_id);
    }
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        trimmed = trim_whitespace(input);
        trimmed[strcspn(trimmed, "\n")] = '\0';
        if (strlen(trimmed) > 0 && validate_key_id(trimmed)) {
            safe_strncpy(account->gpg_key_id, trimmed, sizeof(account->gpg_key_id));
            account->gpg_enabled = true;
            
            /* Ask about GPG signing */
            printf("Enable GPG signing? (y/N): ");
            fflush(stdout);
            if (fgets(input, sizeof(input), stdin)) {
                trimmed = trim_whitespace(input);
                account->gpg_signing_enabled = (tolower(trimmed[0]) == 'y');
            }
        }
    }
    
    return 0;
}

/* Confirm dangerous operations */
bool display_confirm(const char *message, ...) {
    va_list args;
    char formatted_message[1024];
    char input[64];
    char *trimmed;
    
    if (!message) return false;
    
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);
    
    printf("%s %s (y/N): ", 
           display_colorize(STATUS_WARNING, "warning"),
           formatted_message);
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        return false;
    }
    
    trimmed = trim_whitespace(input);
    return tolower(trimmed[0]) == 'y';
}

/* Display progress indicator for long operations */
void display_progress(const char *operation, int percent) {
    const int bar_width = 40;
    int filled = (percent * bar_width) / 100;
    int i;
    
    if (!operation) return;
    
    printf("\r%s [", operation);
    
    for (i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("█");
        } else {
            printf("░");
        }
    }
    
    printf("] %3d%%", percent);
    fflush(stdout);
    
    if (percent >= 100) {
        printf("\n");
    }
}

/* Clear current line */
void display_clear_line(void) {
    printf("\r\033[K");
    fflush(stdout);
}

/* Get user input with prompt and validation */
int display_get_input(const char *prompt, char *buffer, size_t buffer_size,
                      bool (*validator)(const char *)) {
    char *trimmed;
    
    if (!prompt || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to display_get_input");
        return -1;
    }
    
    printf("%s: ", prompt);
    fflush(stdout);
    
    if (!fgets(buffer, buffer_size, stdin)) {
        set_error(ERR_FILE_IO, "Failed to read user input");
        return -1;
    }
    
    trimmed = trim_whitespace(buffer);
    trimmed[strcspn(trimmed, "\n")] = '\0';
    
    /* Move trimmed string to start of buffer */
    if (trimmed != buffer) {
        memmove(buffer, trimmed, strlen(trimmed) + 1);
    }
    
    /* Validate if validator provided */
    if (validator && !validator(buffer)) {
        set_error(ERR_INVALID_ARGS, "Input validation failed");
        return -1;
    }
    
    return 0;
}

/* Get password/sensitive input (hidden) */
int display_get_password(const char *prompt, char *buffer, size_t buffer_size) {
    char *trimmed;
    
    if (!prompt || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to display_get_password");
        return -1;
    }
    
    printf("%s: ", prompt);
    fflush(stdout);
    
    /* Disable echo */
    disable_echo();
    
    if (!fgets(buffer, buffer_size, stdin)) {
        enable_echo();
        printf("\n");
        set_error(ERR_FILE_IO, "Failed to read password input");
        return -1;
    }
    
    /* Re-enable echo */
    enable_echo();
    printf("\n");
    
    trimmed = trim_whitespace(buffer);
    trimmed[strcspn(trimmed, "\n")] = '\0';
    
    /* Move trimmed string to start of buffer */
    if (trimmed != buffer) {
        memmove(buffer, trimmed, strlen(trimmed) + 1);
    }
    
    return 0;
}

/* Show help text */
void display_help(const char *command) {
    printf("\n");
    display_header("gitswitch-c Help");
    printf("\n");
    
    if (!command) {
        /* General help */
        printf("Usage: gitswitch [OPTIONS] [COMMAND] [ARGS]\n\n");
        printf("Commands:\n");
        printf("  list                 List all configured accounts\n");
        printf("  switch <account>     Switch to specified account\n");
        printf("  add                  Add new account interactively\n");
        printf("  remove <account>     Remove specified account\n");
        printf("  status               Show current git configuration\n");
        printf("  doctor               Run system health checks\n\n");
        printf("Options:\n");
        printf("  --global             Set git config globally\n");
        printf("  --local              Set git config locally (default)\n");
        printf("  --no-ssh             Skip SSH key management\n");
        printf("  --no-gpg             Skip GPG key management\n");
        printf("  --dry-run            Show what would be done without executing\n");
        printf("  --verbose            Enable verbose output\n");
        printf("  --color              Force color output\n");
        printf("  --no-color           Disable color output\n");
        printf("  --help               Show this help message\n");
        printf("  --version            Show version information\n\n");
        printf("Examples:\n");
        printf("  gitswitch                    # Interactive account selection\n");
        printf("  gitswitch list               # List all accounts\n");
        printf("  gitswitch switch 1           # Switch to account ID 1\n");
        printf("  gitswitch switch work        # Switch to account matching 'work'\n");
        printf("  gitswitch add                # Add new account\n");
        printf("  gitswitch doctor             # Check system health\n");
    }
    
    printf("\n");
}

/* Display version and build information */
void display_version(void) {
    printf("%s version %s\n", GITSWITCH_NAME, GITSWITCH_VERSION);
    printf("Safe git identity switching with SSH/GPG isolation\n");
    printf("Built with security and reliability in mind\n\n");
    printf("Features:\n");
    printf("- Isolated SSH agents per account\n");
    printf("- Separate GPG environments\n");
    printf("- Comprehensive validation\n");
    printf("- Secure memory handling\n");
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