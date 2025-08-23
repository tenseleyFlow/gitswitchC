/* Display and user interface functions */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdbool.h>
#include "gitswitch.h"

/* Forward declarations - only declare what we need for Phase 2 */

/* Color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"

/* Status indicators */
#define STATUS_SUCCESS "[OK]"
#define STATUS_ERROR   "[ERROR]" 
#define STATUS_WARNING "[WARN]"
#define STATUS_INFO    "[INFO]"

/* Function prototypes */

/**
 * Initialize display system
 * - Detect terminal capabilities
 * - Set up color output based on TTY and preferences
 */
int display_init(bool force_color, bool no_color);

/**
 * Print formatted header with decorative border
 */
void display_header(const char *title);

/**
 * Print status message with appropriate color and icon
 */
void display_status(const char *level, const char *message, ...);

/**
 * Print account information in formatted table
 */
void display_account(const account_t *account, bool is_current);

/**
 * Print accounts list in formatted table
 */
void display_accounts_list(const gitswitch_ctx_t *ctx);

/* These functions will be implemented in later phases
void display_current_status(const git_current_config_t *config);
void display_ssh_status(const ssh_config_t *ssh_config);
void display_gpg_status(const gpg_config_t *gpg_config);
void display_validation_results(const account_validation_t *validation);
*/

/**
 * Print health check results
 */
void display_health_check(const gitswitch_ctx_t *ctx);

/**
 * Display interactive account selection menu
 * Returns selected account ID or 0 if cancelled
 */
uint32_t display_account_menu(const gitswitch_ctx_t *ctx);

/**
 * Prompt user for account information during add/edit
 */
int display_prompt_account_info(account_t *account, bool is_edit);

/**
 * Confirm dangerous operations (account removal, etc.)
 */
bool display_confirm(const char *message, ...);

/**
 * Display progress indicator for long operations
 */
void display_progress(const char *operation, int percent);

/**
 * Clear current line (for progress updates)
 */
void display_clear_line(void);

/**
 * Print error message with context
 */
void display_error(const char *context, const char *message, ...);

/**
 * Print warning message
 */
void display_warning(const char *message, ...);

/**
 * Print success message
 */
void display_success(const char *message, ...);

/**
 * Print info message
 */
void display_info(const char *message, ...);

/**
 * Format and colorize text based on content type
 */
const char *display_colorize(const char *text, const char *type);

/**
 * Check if terminal supports color output
 */
bool display_supports_color(void);

/**
 * Get user input with prompt and validation
 */
int display_get_input(const char *prompt, char *buffer, size_t buffer_size,
                      bool (*validator)(const char *));

/**
 * Get password/sensitive input (hidden)
 */
int display_get_password(const char *prompt, char *buffer, size_t buffer_size);

/**
 * Show help text for command or general usage
 */
void display_help(const char *command);

/**
 * Display version and build information
 */
void display_version(void);

/**
 * Print configuration file location and status
 */
void display_config_info(const gitswitch_ctx_t *ctx);

/**
 * Format table with proper column alignment
 */
void display_table_header(const char **headers, const int *widths, int columns);
void display_table_row(const char **values, const int *widths, int columns);
void display_table_separator(const int *widths, int columns);

#endif /* DISPLAY_H */