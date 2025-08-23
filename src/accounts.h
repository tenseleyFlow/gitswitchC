/* Account management and operations */

#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include "gitswitch.h"

/* Account validation result */
typedef struct {
    bool valid;
    char error_message[512];
    char warnings[1024];
} account_validation_t;

/* Function prototypes */

/**
 * Initialize accounts system
 */
int accounts_init(gitswitch_ctx_t *ctx);

/**
 * Switch to specified account
 * - Validates account exists and is properly configured
 * - Coordinates SSH and GPG switching
 * - Updates git configuration
 * - Verifies switch was successful
 */
int accounts_switch(gitswitch_ctx_t *ctx, const char *identifier);

/**
 * Add new account interactively
 * - Prompts for account details
 * - Validates input
 * - Tests SSH/GPG configuration if provided
 * - Saves to configuration
 */
int accounts_add_interactive(gitswitch_ctx_t *ctx);

/**
 * Remove account with confirmation
 * - Shows account details
 * - Prompts for confirmation
 * - Cleans up associated SSH/GPG resources
 * - Updates configuration
 */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier);

/**
 * List all configured accounts
 * - Shows account details in formatted table
 * - Indicates current active account
 * - Shows validation status for each account
 */
int accounts_list(const gitswitch_ctx_t *ctx);

/**
 * Show current account status
 * - Displays currently active git configuration
 * - Shows SSH keys loaded
 * - Shows GPG signing configuration
 * - Indicates scope (local/global)
 */
int accounts_show_status(const gitswitch_ctx_t *ctx);

/**
 * Validate account configuration
 * - Checks required fields are present
 * - Validates email format
 * - Verifies SSH key file exists and has correct permissions
 * - Validates GPG key exists and is usable
 * - Tests connectivity if possible
 */
int accounts_validate(const account_t *account);

/**
 * Find account by various identifiers
 * - Numeric ID (exact match)
 * - Name (exact or partial match)
 * - Email (exact match)
 * - Description (partial match)
 */
account_t *accounts_find(const gitswitch_ctx_t *ctx, const char *identifier);

/**
 * Get next available account ID
 */
uint32_t accounts_get_next_id(const gitswitch_ctx_t *ctx);

/**
 * Clone account configuration (for editing)
 */
int accounts_clone(const account_t *src, account_t *dst);

/**
 * Compare two accounts for equality
 */
bool accounts_equal(const account_t *a, const account_t *b);

/**
 * Initialize account structure with defaults
 */
void accounts_init_struct(account_t *account);

/**
 * Clean up account resources
 */
void accounts_cleanup_struct(account_t *account);

/**
 * Run comprehensive health check on all accounts
 * - Validates configuration
 * - Tests SSH connectivity
 * - Verifies GPG functionality
 * - Reports issues and recommendations
 */
int accounts_health_check(const gitswitch_ctx_t *ctx);

#endif /* ACCOUNTS_H */