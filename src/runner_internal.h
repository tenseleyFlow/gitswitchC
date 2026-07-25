/* Internal contracts shared by descriptor-bound command consumers. */

#ifndef RUNNER_INTERNAL_H
#define RUNNER_INTERNAL_H

#include <stdbool.h>

#include "utils.h"

/* Open `program_path` through the production executable-trust and direct
 * shebang policy without executing it. `program_path` must be the exact
 * canonical absolute path selected for the invocation. On success `out`
 * identifies the executable/script generation and, for scripts, the direct
 * interpreter generation plus shebang invocation contract. */
bool run_launch_witness_capture(
    const char *program_path, run_launch_witness_t *out);

/* Compare every generation and invocation component of two valid witnesses. */
bool run_launch_witness_matches(
    const run_launch_witness_t *a, const run_launch_witness_t *b);

/* Re-walk `program_path` through the production executable-trust policy and
 * require the exact binary/script plus direct-interpreter generation recorded
 * by a prior successful real launch. Returns false for an invalid witness,
 * any trust/reopen failure, or any generation/invocation-contract change. */
bool run_launch_witness_revalidate(
    const char *program_path, const run_launch_witness_t *witness);

/* Execute only the launch contract represented by `expected`. The production
 * runner compares the already-opened executable/script and interpreter before
 * fork. An injected runner must return an exactly matching launch witness on
 * success; an absent or mismatched witness fails the call. */
int run_argv_with_expected_launch(
    const char *const argv[], const run_opts_t *opts,
    const run_launch_witness_t *expected, run_result_t *result);

#endif /* RUNNER_INTERNAL_H */
