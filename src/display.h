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
void display_status(const char *level, const char *message, ...) GS_PRINTF_FMT(2, 3);

/* These functions will be implemented in later phases
void display_current_status(const git_current_config_t *config);
void display_ssh_status(const ssh_config_t *ssh_config);
void display_gpg_status(const gpg_config_t *gpg_config);
void display_validation_results(const account_validation_t *validation);
*/

/**
 * Print error message with context
 */
void display_error(const char *context, const char *message, ...) GS_PRINTF_FMT(2, 3);

/**
 * Print warning message
 */
void display_warning(const char *message, ...) GS_PRINTF_FMT(1, 2);

/**
 * Print success message
 */
void display_success(const char *message, ...) GS_PRINTF_FMT(1, 2);

/**
 * Print info message
 */
void display_info(const char *message, ...) GS_PRINTF_FMT(1, 2);

/**
 * Format and colorize text based on content type.
 *
 * Returns a newly allocated string for every non-NULL text input, including
 * when color is disabled or the type is unknown. The caller must free it.
 * Returns NULL for NULL text or when the result cannot be allocated.
 */
char *display_colorize(const char *text, const char *type);

/**
 * Check if terminal supports color output
 */
bool display_supports_color(void);

/**
 * Print configuration file location and status
 */
void display_config_info(const gitswitch_ctx_t *ctx);

#endif /* DISPLAY_H */
