/* Account management and operations */

#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include "gitswitch.h"
#include "publication.h"

/* One process-global owner serializes every account mutation family. Tokens
 * are monotonically assigned and must match every rollback/finalizer call;
 * kind and context identity are checked independently so a stale or
 * cross-type finalizer cannot consume another operation's obligation. */
typedef uint64_t accounts_transaction_token_t;

typedef enum {
    ACCOUNTS_TRANSACTION_NONE = 0,
    ACCOUNTS_TRANSACTION_INITIALIZE,
    ACCOUNTS_TRANSACTION_SWITCH,
    ACCOUNTS_TRANSACTION_ADD,
    ACCOUNTS_TRANSACTION_EDIT,
    ACCOUNTS_TRANSACTION_REMOVE,
    ACCOUNTS_TRANSACTION_RESET
} accounts_transaction_kind_t;

typedef enum {
    ACCOUNTS_TRANSACTION_IDLE = 0,
    ACCOUNTS_TRANSACTION_ENTERING,
    ACCOUNTS_TRANSACTION_PREPARED,
    ACCOUNTS_TRANSACTION_ABORT_ONLY,
    ACCOUNTS_TRANSACTION_FINALIZING
} accounts_transaction_phase_t;

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

/* Transactional prepare outcome. A nonzero return with CLEAN_FAILURE owns no
 * caller context. ABORT_REQUIRED means the exact caller context is still
 * referenced by an abort-only process-global record and must remain alive
 * until accounts_switch_abort() consumes it. PREPARED is the only state that
 * authorizes persistence and commit. */
typedef enum {
    ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE = 0,
    ACCOUNTS_SWITCH_PREPARE_PREPARED,
    ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED
} accounts_switch_prepare_state_t;

/* Classification supplied by the outer CLI save boundary after Git
 * retirement has been published.  A proven pre-install failure authorizes
 * exact Git restoration; an installed-but-uncertain result must retain the
 * retired state and its durable activation blocker. */
typedef enum {
    ACCOUNTS_RETIREMENT_SAVE_DURABLE = 0,
    ACCOUNTS_RETIREMENT_SAVE_UNCERTAIN,
    ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED
} accounts_retirement_save_outcome_t;

/* Function prototypes */

/**
 * Initialize accounts system
 */
int accounts_init(gitswitch_ctx_t *ctx);

/* Low-level owner boundary used by the CLI reset flow and focused embedders.
 * Most callers should use the operation-specific APIs below. Begin fails
 * before mutation if another owner, signal guard, or rollback obligation is
 * live. Rollback calls nest only for the exact token. Finish requires zero
 * owned rollback depth and consumes only the matching kind/context/token. */
int accounts_transaction_begin(gitswitch_ctx_t *ctx,
                               accounts_transaction_kind_t kind,
                               accounts_transaction_token_t *token);
int accounts_transaction_rollback_begin(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token);
int accounts_transaction_rollback_end(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token);
int accounts_transaction_finish(gitswitch_ctx_t *ctx,
                                accounts_transaction_kind_t kind,
                                accounts_transaction_token_t token);

/* Capability check for config.c's account-model mutation boundary. Public
 * config mutation passes NONE/0 and is admitted only while no account
 * transaction exists. Operation-owned mutation must present the exact
 * context/kind/token while that owner is still entering; there is no API for
 * discovering a live owner's token. */
int accounts_transaction_authorize_model_mutation(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token);

/* True only when no process-global account owner or pending account record
 * retains the caller's context address. This is a storage-lifetime query, not
 * an operation capability and it exposes no owner token. */
bool accounts_transaction_context_release_safe(const gitswitch_ctx_t *ctx);

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
int accounts_switch_prepare_result(gitswitch_ctx_t *ctx,
                                   const char *identifier,
                                   accounts_switch_prepare_state_t *state);
int accounts_switch_commit(gitswitch_ctx_t *ctx);
int accounts_switch_commit_result(gitswitch_ctx_t *ctx,
                                  accounts_switch_commit_state_t *state);
/* Borrow the exact sealed Git publication owned by a prepared switch. The
 * pointer remains valid only until that switch is committed or aborted. CLI
 * persistence uses it to install provenance in the same atomic active-state
 * bundle before releasing transaction ownership. */
int accounts_switch_publication(
    const gitswitch_ctx_t *ctx, const publication_record_t **publication);
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
int accounts_add_interactive_prepare(gitswitch_ctx_t *ctx);
int accounts_add_commit(gitswitch_ctx_t *ctx);
int accounts_add_abort(gitswitch_ctx_t *ctx);

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

/* Remove transaction. accounts_remove() confirms, tears down runtime state,
 * and removes the account from the in-memory model. CLI/outer-transaction
 * callers defer signal cleanup and must classify persistence with
 * accounts_remove_finalize(): DURABLE after proven directory sync, UNCERTAIN
 * after installation without proven durability, or PREINSTALL_FAILED only
 * when the account document was not installed. The commit/abort wrappers are
 * retained for direct one-call compatibility. Finalization retires only an
 * exclusively owned SSH alias after installation; a pre-install failure
 * deliberately leaves it paired with the retained durable account. */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier);
int accounts_remove_commit(gitswitch_ctx_t *ctx);
int accounts_remove_abort(gitswitch_ctx_t *ctx);
int accounts_remove_finalize(
    gitswitch_ctx_t *ctx, accounts_retirement_save_outcome_t outcome);

/* Reset owns runtime teardown in main, but its Git retirement must survive
 * until main classifies the active-state save. `target == NULL` batches all
 * accounts into one shared-destination-aware transaction. The strict order is
 * prepare, publish, then finalize; cancel is valid only before publication.
 * A wrong-phase call is rejected without consuming the pending transaction or
 * clearing its durable blocker. */
int accounts_reset_retirement_prepare(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    const account_t *target);
int accounts_reset_retirement_publish(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    size_t *cleared);
int accounts_reset_retirement_cancel(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token);
int accounts_reset_retirement_finalize(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    accounts_retirement_save_outcome_t outcome);

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

/* Retire only durable Git identity/credential state whose ownership is proven
 * by a sealed PUBLISHED record in the ledger belonging to `ctx`. Missing,
 * incomplete, ambiguous, or non-authorizing provenance fails closed before
 * Git/PATH work; callers must retain the exact account/incarnation as the
 * retry handle. Legacy state is never reconstructed from the live model. */
int accounts_retire_git_identity(const gitswitch_ctx_t *ctx,
                                 const account_t *account,
                                 size_t *cleared);

/**
 * Validate account configuration
 * - Checks the shared account model and required fields
 * - Validates name, email, and configured key-selector syntax
 * - Verifies the local SSH private-key node and permissions when enabled
 * - Does not contact an SSH server or inspect/use a GPG keyring
 */
int accounts_validate(const account_t *account);

/**
 * Run bounded local readiness checks on all accounts
 * - Validates the account model and fields
 * - Rechecks the local SSH private-key node and permissions
 * - Confirms current local GPG secret material and configured capability
 * - Does not attempt remote SSH authentication or create a test signature
 */
int accounts_health_check(const gitswitch_ctx_t *ctx);

/**
 * Finish cleanup of process-scoped account session state
 * - Stops any SSH agent owned by this process session
 * - Restores manager-owned GNUPGHOME and GPG_AGENT_INFO changes and completes
 *   any retained GPG publication rollback
 * - Deliberately retains reusable per-account isolated GPG homes; use
 *   `gitswitch reset [account]` to stop their agents, delete their homes,
 *   retire stable links, and synchronize the GPG namespace
 * - Retains incomplete session state after failure so cleanup can be retried
 * Returns -1 during an active account transaction or while cleanup remains
 * incomplete. Account switching performs guarded cleanup internally; direct
 * callers may use this after a transaction, before exit, or for a retry.
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
