/* Internal contracts shared by descriptor-bound command consumers. */

#ifndef RUNNER_INTERNAL_H
#define RUNNER_INTERNAL_H

#include <stdbool.h>

#include "utils.h"

/* Re-walk `program_path` through the production executable-trust policy and
 * require the exact binary/script plus direct-interpreter generation recorded
 * by a prior successful real launch. Returns false for an invalid witness,
 * any trust/reopen failure, or any generation/invocation-contract change. */
bool run_launch_witness_revalidate(
    const char *program_path, const run_launch_witness_t *witness);

#endif /* RUNNER_INTERNAL_H */
