/* Internal contracts shared by descriptor-bound command consumers. */

#ifndef RUNNER_INTERNAL_H
#define RUNNER_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "utils.h"

/* Convert a nonnegative relative duration to one absolute CLOCK_MONOTONIC
 * deadline. The caller passes that same value through every downstream
 * operation so elapsed setup time is never reset. */
int run_deadline_after_millis(int64_t timeout_ms, int64_t *deadline_millis);

#ifdef GITSWITCH_TESTING
/* One-shot deterministic clock failures for deadline-path regressions.
 * `call_ordinal` is one-based and applies to the next runner/deadline-helper
 * clock sequence. A positive rollback_millis makes that selected observation
 * precede the prior one without changing wall time. */
void run_test_set_monotonic_failure(unsigned int call_ordinal,
                                    int system_errno);
void run_test_set_monotonic_rollback(unsigned int call_ordinal,
                                     int64_t rollback_millis);
void run_test_set_monotonic_timespec(unsigned int call_ordinal,
                                     int64_t seconds, long nanoseconds);
void run_test_set_poll_failure(unsigned int call_ordinal,
                               int system_errno);
void run_test_set_child_setup_delay(int64_t delay_millis);
#endif

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
