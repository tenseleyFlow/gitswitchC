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
typedef enum {
    RUN_TEST_SUPERVISOR_FAILURE_NONE = 0,
    RUN_TEST_SUPERVISOR_FAILURE_WORKER_RELEASE_PIPE,
    RUN_TEST_SUPERVISOR_FAILURE_INNER_FORK,
    RUN_TEST_SUPERVISOR_FAILURE_REPLAY,
    RUN_TEST_SUPERVISOR_FAILURE_RELEASE_WRITE
} run_test_supervisor_failure_stage_t;
/* Parent-side seam after the proven group is published and guarded signals
 * are restored, but before its private release gate is written. */
typedef void (*run_test_pre_group_release_hook_fn)(pid_t supervisor_pid);
void run_test_set_pre_group_release_hook(
    run_test_pre_group_release_hook_fn hook);
/* Overlay a deterministic 1..999999999 generation epoch on successful real
 * witness captures for one exact canonical executable path. The production
 * trust walk and descriptor identity checks still run before this test-only
 * generation is applied. */
int run_test_set_launch_witness_epoch(const char *program_path,
                                      unsigned int epoch);
void run_test_clear_launch_witness_epochs(void);
#ifdef GITSWITCH_RUNNER_GROUP_TEST_API
/* One-shot child-supervisor setpgid(2) failure before GROUP_READY. */
void run_test_set_child_process_group_failure(int system_errno);
/* Raise one signal only in the process-group supervisor after its worker fork
 * while the relay set is still blocked. */
void run_test_set_supervisor_pending_signal(int signal_number);
/* Inject one signal after worker release but before the supervisor restores
 * its inherited mask. Normal signals target the complete process group;
 * SIGTSTP targets the supervisor to exercise its local fail-closed handler. */
void run_test_set_post_replay_signal(int signal_number);
/* One-shot supervisor-stage failure with exact errno propagation. */
void run_test_set_supervisor_failure(
    run_test_supervisor_failure_stage_t stage, int system_errno);
#endif
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
