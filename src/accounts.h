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

/* Prepared-switch commit result. NOT_COMMITTED authorizes the caller to use
 * accounts_switch_abort(). Every other non-success state means Git/runtime,
 * active metadata, and the installed SSH alias were intentionally retained as
 * one committed transaction; the caller reports failure but must not restore
 * persistence before-images around it. */
typedef enum {
    ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED,
    ACCOUNTS_SWITCH_COMMIT_COMPLETE,
    ACCOUNTS_SWITCH_COMMIT_ALIAS_UNVERIFIED,
    ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN,
    ACCOUNTS_SWITCH_COMMIT_ALIAS_CLEANUP_FAILED
} accounts_switch_commit_state_t;

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
 * CLI transaction boundary: prepare applies a switch while retaining its
 * rollback state and runtime lock. Commit releases that state only after the
 * caller durably saves active-account metadata; abort restores the prior Git,
 * runtime, and in-memory active state. Resume and direct library callers keep
 * using accounts_switch().
 */
int accounts_switch_prepare(gitswitch_ctx_t *ctx, const char *identifier);
int accounts_switch_commit(gitswitch_ctx_t *ctx);
int accounts_switch_commit_result(gitswitch_ctx_t *ctx,
                                  accounts_switch_commit_state_t *state);
/* continue_persistence_rollback keeps the signal rollback window active so
 * the caller can restore config/hint state without an interruptible gap. */
int accounts_switch_abort(gitswitch_ctx_t *ctx,
                          bool continue_persistence_rollback);

/**
 * Add new account interactively
 * - Prompts for account details
 * - Validates input
 * - Tests SSH/GPG configuration if provided
 * - Saves to configuration
 */
int accounts_add_interactive(gitswitch_ctx_t *ctx);

/**
 * Edit an existing account interactively (prompts default to current values)
 */
int accounts_edit_interactive(gitswitch_ctx_t *ctx, const char *identifier);

/* CLI edit transaction. Prepare validates and installs the candidate in the
 * in-memory context while retaining enough state to restore managed SSH alias
 * routing if the full config save fails before installation. An installed-
 * but durability-uncertain save must commit, not abort, so config and routing
 * continue to describe the same account. */
int accounts_edit_interactive_prepare(gitswitch_ctx_t *ctx,
                                      const char *identifier);
int accounts_edit_candidate_prepare(gitswitch_ctx_t *ctx,
                                    const account_t *candidate);
int accounts_edit_commit(gitswitch_ctx_t *ctx);
int accounts_edit_abort(gitswitch_ctx_t *ctx);

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
 * Run comprehensive health check on all accounts
 * - Validates configuration
 * - Tests SSH connectivity
 * - Verifies GPG functionality
 * - Reports issues and recommendations
 */
int accounts_health_check(const gitswitch_ctx_t *ctx);

/**
 * Clean up active session resources
 * - Stops SSH agent if one was started
 * - Restores original GNUPGHOME environment
 * - Cleans up isolated GPG home if created
 * Call this before program exit or when switching accounts
 */
int accounts_session_cleanup(void);

/**
 * Detect current account from SSH socket symlink
 * - Reads the current.sock symlink in gitswitch-ssh directory
 * - Parses account name from socket filename
 * - Sets ctx->current_account if a match is found
 * Call this after accounts are loaded from config
 */
int accounts_detect_current(gitswitch_ctx_t *ctx);

#endif /* ACCOUNTS_H */
