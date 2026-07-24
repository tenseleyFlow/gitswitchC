#ifndef GIT_OPS_INTERNAL_H
#define GIT_OPS_INTERNAL_H

#include "git_ops.h"

#ifdef GITSWITCH_INTERNAL_API
typedef struct git_config_finalization git_config_finalization_t;

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
