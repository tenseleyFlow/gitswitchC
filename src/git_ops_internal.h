#ifndef GIT_OPS_INTERNAL_H
#define GIT_OPS_INTERNAL_H

#include "git_ops.h"

#ifdef GITSWITCH_INTERNAL_API
typedef struct git_config_finalization git_config_finalization_t;
typedef struct git_retirement_recovery git_retirement_recovery_t;

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

/* Re-prove the exact clean config generations, checked-clean every owned Git
 * artifact, release all canonical locks, consume the handle, and set it to
 * NULL. The handle is consumed on success and failure. Call only after the
 * caller's durable tombstone/guard settlement attempt, while the leases are
 * still held. */
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

#ifdef GITSWITCH_TESTING
git_finalization_test_hook_fn git_ops_test_set_finalization_hook(
    git_finalization_test_hook_fn fn);
#endif
#endif

#endif
