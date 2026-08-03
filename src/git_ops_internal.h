#ifndef GIT_OPS_INTERNAL_H
#define GIT_OPS_INTERNAL_H

#include "git_ops.h"
#include "utils.h"

#ifdef GITSWITCH_INTERNAL_API
typedef struct git_config_finalization git_config_finalization_t;
typedef struct git_retirement_recovery git_retirement_recovery_t;

typedef enum {
    GIT_RETIREMENT_FAILED_PUBLISH_MUTATED_OR_UNCERTAIN = 0,
    GIT_RETIREMENT_FAILED_PUBLISH_UNCHANGED_CLEAN
} git_retirement_failed_publish_outcome_t;

/* Consume a transaction whose publish operation failed and classify whether
 * the caller may safely treat canonical Git configuration as unchanged.
 * The output is initialized fail-closed. UNCHANGED_CLEAN is returned only
 * when no mutation-capable publication backend was entered, no earlier
 * checked cleanup was uncertain, and final checked disposal succeeds.
 *
 * A NULL, inherited, or wrong-state capability is rejected with -1 and the
 * fail-closed outcome. A valid publish-failed capability is consumed and its
 * caller-owned pointer is set to NULL on both cleanup success and failure. */
int git_retirement_transaction_dispose_failed_publish(
    git_retirement_transaction_t **transaction,
    git_retirement_failed_publish_outcome_t *outcome);

/* A fork child may inherit process-global snapshot descriptors but never the
 * parent's namespace authority. Forget raw descriptor numbers and free that
 * transaction state without rollback, finalization, marker recovery, or any
 * pathname mutation. A current-owner or empty process is unchanged. */
void git_config_abandon_inherited_transaction(void);

/* Return the exact physical destination set reconciled by an outer rollback,
 * including destinations that were already absent. Present entries carry
 * their freshly re-proved generation; absent entries carry a canonical zero
 * identity that tells the config ledger refresh to preserve each matching
 * record's prior generation. Repeated queries after terminal preparation are
 * read-only final proofs over retained bytes or exact parent absence. */
size_t git_retirement_transaction_rollback_destination_count(
    const git_retirement_transaction_t *transaction);

int git_retirement_transaction_rollback_destination(
    git_retirement_transaction_t *transaction, size_t index,
    char *config_path, size_t path_size,
    publication_identity_t *post_config);

/* Convert every transaction-owned empty canonical lock into a complete
 * retained recovery marker after a successful outer rollback, then retire
 * the marker-encoded private stage and sync its parent before the restored
 * identity/ledger can be sealed. Retain exact restored-byte or absence
 * witnesses for terminal revalidation. Every reconciled destination
 * must already have been enumerated through
 * git_retirement_transaction_rollback_destination(). After success,
 * rollback_destination() remains the read-only terminal revalidation
 * operation, while commit() becomes release-only and may not inspect or
 * synchronize the Git namespace. A settlement failure is sticky: the
 * transaction can be disposed but cannot later become terminally prepared. */
int git_retirement_transaction_prepare_terminal_rollback(
    git_retirement_transaction_t *transaction);

/* After the retirement guard has committed, settle each retained canonical
 * recovery marker as far as the platform safely permits, sync its directory,
 * and consume the terminal transaction. Private stages were already settled
 * before ledger sealing. This outcome-consuming finish is infallible once the
 * handle/state/PID contract is valid: cleanup residue, sync failures, and
 * foreign conflicts are diagnostics, while any retained marker remains
 * complete and restart-recoverable. Generic commit() is the descriptor-only
 * failure path and deliberately leaves these markers untouched. */
int git_retirement_transaction_finish_terminal_rollback(
    git_retirement_transaction_t **transaction);

/* Convert every transaction-owned canonical lock into a complete retained
 * recovery marker after a successful Git publication. The exact clean
 * post-image (or exact destination absence) remains pinned for a read-only
 * terminal proof while generic commit becomes descriptor-only. */
int git_retirement_transaction_prepare_terminal_commit(
    git_retirement_transaction_t *transaction);

/* Re-prove the exact clean post-image/absence and retained marker without
 * mutating or synchronizing the Git namespace. */
int git_retirement_transaction_verify_terminal_commit(
    git_retirement_transaction_t *transaction);

/* Consume a terminally prepared commit after its outer guard has committed.
 * Cleanup failures are warnings over the committed outcome. */
int git_retirement_transaction_finish_terminal_commit(
    git_retirement_transaction_t **transaction);

/* Validate the effective Git account model and require the raw OpenPGP key
 * probe to execute through the exact launch generation retained by the active
 * GPG switch transaction. A GPG-enabled account requires a valid witness
 * whose canonical invocation path equals expected_gpg_program. */
int git_test_config_with_gpg_witness(
    const account_t *account, git_scope_t scope,
    const char *expected_gpg_program,
    const run_launch_witness_t *expected_gpg_witness);

/* Acquire the canonical Git lock names for every distinct config destination
 * tracked by the active sealed switch, then re-prove its exact namespace,
 * file generations, and managed vectors. The returned lease keeps supported
 * Git writers out until end; callers must retain durable recovery ownership
 * throughout the lease. */
int git_config_finalization_begin(git_config_finalization_t **finalization);

/* Release every canonical Git lock owned by the lease. The handle is consumed
 * on both success and failure: any retained canonical entry is already a
 * complete restart-recoverable certificate. A proven foreign replacement is
 * never unlinked. */
int git_config_finalization_end(git_config_finalization_t **finalization);

/* Adopt an already-installed retirement tombstone without reviving its
 * authority to mutate Git. Every record must be RETIRING. The complete set is
 * copied, grouped by physical config destination, and checked under Git's
 * canonical `<config>.lock` names. Success proves that no exact SSH command
 * or GPG fingerprint anchor sealed by the records remains live and retains
 * those locks until end, so the caller can settle the durable tombstone and
 * retirement guard without a cooperative Git writer racing that decision.
 *
 * This recovery path never issues a Git unset. A live attributed value,
 * malformed record, inaccessible namespace, changed generation, repeated
 * ambiguity, or cleanup/proof uncertainty fails closed. */
int git_retirement_recovery_begin(
    const publication_record_t *const publications[],
    size_t publication_count, git_retirement_recovery_t **recovery);

/* Repeat the complete clean-generation proof without releasing any lock or
 * consuming the handle. Call immediately before clearing the durable
 * retirement guard; failure leaves the handle owned for checked cleanup. */
int git_retirement_recovery_verify(
    git_retirement_recovery_t *recovery);

/* Retain complete restart-recoverable marker authority for every clean
 * recovery destination before the outer recovery guard commits. */
int git_retirement_recovery_prepare_terminal(
    git_retirement_recovery_t *recovery);

/* Re-prove the terminal recovery witnesses without namespace mutation. */
int git_retirement_recovery_verify_terminal(
    git_retirement_recovery_t *recovery);

/* Consume terminal recovery authority after the outer guard commits.
 * Cleanup residue is diagnostic and does not reverse the committed outcome. */
int git_retirement_recovery_finish_terminal(
    git_retirement_recovery_t **recovery);

/* Re-prove the exact clean config generations, checked-clean every owned Git
 * artifact, release all canonical locks, consume the handle, and set it to
 * NULL. The handle is consumed on success and failure. Call only from the
 * retirement guard's final pre-publication barrier, after its completion
 * stage is durable and while the Git leases are still held. */
int git_retirement_recovery_end(
    git_retirement_recovery_t **recovery);

typedef enum {
    GIT_FINALIZATION_TEST_AFTER_PRIVATE_PREPARE = 1,
    GIT_FINALIZATION_TEST_AFTER_CANONICAL_PUBLISH,
    GIT_FINALIZATION_TEST_BEFORE_RELEASE,
    GIT_FINALIZATION_TEST_BEFORE_RELEASE_DIRECTORY_SYNC
} git_finalization_test_stage_t;

typedef bool (*git_finalization_test_hook_fn)(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf);

/* Copy the numeric descriptors retained by the active snapshot so fork
 * regressions can deliberately close/reuse those exact child-side numbers. */
size_t git_ops_test_snapshot_descriptors(int *fds, size_t capacity);

/* Copy every raw descriptor retained by an opaque Git capability. Foreign
 * fork regressions replace these exact child-side numbers before disposal,
 * proving inherited cleanup never closes a reused descriptor. */
size_t git_ops_test_finalization_descriptors(
    const git_config_finalization_t *finalization,
    int *fds, size_t capacity);
size_t git_ops_test_retirement_transaction_descriptors(
    const git_retirement_transaction_t *transaction,
    int *fds, size_t capacity);
size_t git_ops_test_retirement_recovery_descriptors(
    const git_retirement_recovery_t *recovery,
    int *fds, size_t capacity);

#ifdef GITSWITCH_TESTING
git_finalization_test_hook_fn git_ops_test_set_finalization_hook(
    git_finalization_test_hook_fn fn);
#endif
#endif

#endif
