/* Signal guarding for the account-switch critical section (SIG-01, SIG-02).
 *
 * accounts_switch() applies SSH -> GPG -> git config as separate durable
 * steps, and Ctrl-C at an ssh-add passphrase or GPG pinentry prompt is a
 * NORMAL path through that window. Without a handler, SIGINT/SIGTERM/SIGHUP/
 * SIGQUIT killed the process between steps, bypassing the rollback machinery
 * and leaving a half-applied identity (e.g. current.sock repointed at the new
 * account while git user.email still names the old one) — exactly the
 * mixed-identity state the tool exists to prevent.
 *
 * Design (async-signal-safe by construction):
 *   - signals_guard_begin() installs a handler for SIGINT/SIGTERM/SIGHUP/
 *     SIGQUIT that only records the signal in a volatile sig_atomic_t. The
 *     mainline checks signals_pending() between durable steps and runs the
 *     ordinary rollback (git_config_restore + runtime-isolation teardown) in
 *     normal, non-handler context, then signals_dispatch_pending() re-raises
 *     so the exit status still reports death-by-signal to the shell.
 *   - A SECOND signal while one is already pending is an emergency exit (e.g.
 *     a child pinentry that swallowed the first Ctrl-C): the handler unlinks
 *     the registered scratch files below (unlink(2) is async-signal-safe),
 *     restores the default disposition and re-raises immediately. This skips
 *     the git rollback by design — running git from a handler is not
 *     async-signal-safe — so the escape hatch trades atomicity for liveness
 *     only when the user insists twice.
 *   - EXCEPT while a transaction-critical mutation or rollback is running
 *     (signals_rollback_begin/end): the emergency exit there would abandon
 *     forward publication, prepared persistence, or git_config_restore
 *     mid-way and persist a mixed identity (AR-08 M4 / AR-02 #2), so further
 *     signals stay recorded until commit or completed abort. Interactive
 *     children keep default dispositions, so Ctrl-C still interrupts them.
 *   - That rollback deferral is BOUNDED, not absolute (AR-03 L8/L20).
 *     run_argv publishes an independently proven, isolated child process
 *     group while guarded signals are blocked. A further guarded signal
 *     during rollback reaches the whole group, escalating to SIGKILL on a
 *     repeat, so wrappers and their descendants cannot keep rollback wedged.
 *   - Signals whose disposition is SIG_IGN at guard time stay ignored (so a
 *     nohup'd run keeps ignoring SIGHUP), matching sigaction(2) convention.
 */

#ifndef SIGNALS_H
#define SIGNALS_H

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>

/**
 * Install the deferring handler for SIGINT/SIGTERM/SIGHUP/SIGQUIT and clear
 * any previously pending signal. Idempotent while a guard is active.
 * SA_RESTART restarts the wait family and status-pipe reads. On Linux poll()
 * is never restarted after a handler (signal(7)), so a guarded signal
 * delivered while run_argv is blocked in poll yields EINTR and run_argv's
 * explicit EINTR fall-through runs its waitpid maintenance promptly (AR-12
 * L19). Correctness does not depend on that platform detail, though: run_argv
 * always polls with a bounded slice (RUNNER_POLL_SLICE_MS, 50ms), so even where
 * a poll is restarted or the signal is coalesced, the maintenance runs within
 * that bound — the EINTR path only makes it prompt, not correct. Returns
 * 0 on success and -1 if any disposition query or installation fails. A
 * failed begin restores every disposition it already changed and preserves
 * the originating errno; only an inherited SIG_IGN is intentionally skipped.
 */
int signals_guard_begin(void);

/** Read-only guard ownership query. True includes a guard whose disposition
 * restoration is incomplete, because starting another process-global
 * transaction in that state could consume or overwrite the retained cleanup
 * obligation. */
bool signals_guard_active(void);

/* Deterministic, one-shot fault injection for each sigaction(2) stage used by
 * the guard. Failures are stored independently by stage, so a test can arm an
 * installation failure and the rollback restoration failure it triggers at
 * the same time. Passing SIGNALS_TEST_SIGACTION_NONE clears every stage.
 * The types stay unconditional (internal plumbing references them); the
 * entry points exist only in GITSWITCH_TESTING objects (AR-10 L15). */
typedef enum {
    SIGNALS_TEST_SIGACTION_NONE = 0,
    SIGNALS_TEST_SIGACTION_QUERY,
    SIGNALS_TEST_SIGACTION_INSTALL,
    SIGNALS_TEST_SIGACTION_RESTORE
} signals_test_sigaction_stage_t;

/* One-shot checkpoint immediately before guard_end starts restoration. It is
 * used to reproduce the pending-check/restoration race deterministically. */
typedef void (*signals_test_guard_end_hook_fn)(void);

#ifdef GITSWITCH_TESTING
void signals_test_fail_sigaction(int signal_number,
                                 signals_test_sigaction_stage_t stage,
                                 int system_errno);

signals_test_guard_end_hook_fn signals_test_set_guard_end_hook(
    signals_test_guard_end_hook_fn hook);
#endif

#ifdef GITSWITCH_TESTING
/* Deterministic, independent one-shot failures for normal-context dispatch
 * boundaries. The production signals object exports none of this surface. */
typedef enum {
    SIGNALS_TEST_DISPATCH_NONE = 0,
    SIGNALS_TEST_DISPATCH_MASK_QUERY,
    SIGNALS_TEST_DISPATCH_UNBLOCK,
    SIGNALS_TEST_DISPATCH_RAISE,
    SIGNALS_TEST_DISPATCH_MASK_RESTORE
} signals_test_dispatch_stage_t;

void signals_test_fail_dispatch(signals_test_dispatch_stage_t stage,
                                int system_errno);
#endif

/**
 * Restore the dispositions saved by signals_guard_begin(). Idempotent. Does
 * NOT clear a pending signal — callers finish their teardown first and then
 * either signals_dispatch_pending() (failure path) or deliberately complete
 * the already-applied switch (success path). Returns 0 once every installed
 * disposition is restored, or -1 while one or more restorations remain
 * pending; failed entries stay recorded so a later call can retry them.
 */
int signals_guard_end(void);

/**
 * Mark a transaction-critical mutation/rollback window. Between begin and
 * end, the handler defers even a second guarded signal (no emergency exit) so
 * forward publication, prepared persistence, and multi-exec restoration can
 * never be abandoned half-done (AR-08 M4 / AR-02 #2). Calls are idempotent,
 * not nesting; the transaction owner ends the state once at commit or after
 * completed abort, before dispatching any pending signal.
 */
void signals_rollback_begin(void);
void signals_rollback_end(void);

/** Checked rollback ownership for transaction coordinators. A nonzero token
 * may enter recursively; only that exact token may leave, and the handler's
 * rollback deferral remains armed until the matching depth reaches zero.
 * Legacy signals_rollback_begin()/end() ownership is tracked independently,
 * so an unrelated compatibility caller cannot clear a checked owner. */
int signals_rollback_begin_owned(uint64_t token);
int signals_rollback_end_owned(uint64_t token);

/** True while either legacy or checked rollback deferral is active. */
bool signals_rollback_active(void);

/**
 * Reset only signals whose dispositions signals_guard_begin() actually
 * replaced, in a freshly-forked child before it execs (AR-06 F76 / AR-07
 * M32). This closes the window where the child still runs guard_handler
 * without changing an inherited SIG_IGN or its mask. Pass the mask captured
 * before any runner-owned SIGCHLD or guarded-signal blocking so the child's
 * mask is restored to exactly what it would otherwise have inherited — a
 * supervisor-blocked signal stays blocked. NULL falls back to unblocking only
 * the guard-installed set. Async-signal-safe enough for our single-threaded
 * fork; call it first thing in the child branch.
 */
void signals_reset_for_child(const sigset_t *inherited_mask);

/**
 * Close the post-fork/pre-publication race for a guarded child launch.
 * signals_block_for_child_spawn() adds exactly the dispositions installed by
 * the active guard to the caller's mask and captures the complete prior mask.
 * In the parent, publish the PID and then restore that exact mask with
 * signals_restore_after_child_spawn(). The child instead passes its earlier
 * pre-ownership snapshot to signals_reset_for_child(), which resets inherited
 * guard dispositions and restores the mask it should have inherited.
 */
int signals_block_for_child_spawn(sigset_t *previous_mask);
int signals_restore_after_child_spawn(const sigset_t *previous_mask);

/**
 * Establish exclusive wait ownership before a helper is forked. SIGCHLD is
 * blocked before its disposition is inspected. An inherited SIG_IGN,
 * SA_NOCLDWAIT, or non-default handler is rejected with EBUSY before spawn;
 * the exact caller mask is restored on rejection. A successful caller keeps
 * SIGCHLD blocked until signals_child_wait_end() after the child is retired.
 */
int signals_child_wait_begin(sigset_t *previous_mask);
int signals_child_wait_end(const sigset_t *previous_mask);

typedef struct {
    pid_t waited;       /* waitpid result; -1 when wait was not attempted */
    int wait_errno;     /* errno from waitid/waitpid when waited < 0 */
    int mask_errno;     /* guarded-mask block/restore failure, independently */
} signals_child_wait_result_t;

/**
 * Observe the requested child state without reaping, then execute waitpid
 * while every installed guarded signal is blocked and retire the
 * handler-visible PID before restoring the exact entry mask. The observed
 * transition keeps blocking waits interruptible while WNOWAIT prevents PID
 * reuse before the guarded reap. Wait and mask outcomes are independent so a
 * caller never retries a reaped child merely because mask restoration failed.
 */
signals_child_wait_result_t signals_wait_child(pid_t pid, int *status,
                                                int options);

/**
 * Publish the in-flight subprocess and, only when independently proven equal
 * to pid, its isolated process group. run_argv calls this while guarded
 * signals are blocked and before releasing the supervisor's pre-exec gate.
 * Retirement is owned exclusively by signals_wait_child(), which clears PID,
 * PGID, escalation, and relay-credit state in the guarded reap transition.
 */
void signals_child_spawned(pid_t pid);

#ifdef GITSWITCH_SIGNALS_RUNNER_INTERNAL
void signals_child_group_spawned(pid_t pid, pid_t proven_pgid);
/* Record a guarded signal proven by the runner supervisor relay. */
void signals_record_relayed_group_signal(int signal_number);
#endif

#ifdef GITSWITCH_TESTING
/* One-shot checkpoint after waitpid returns but before child publication is
 * retired. Guarded signals are blocked at this checkpoint. */
typedef void (*signals_test_post_wait_hook_fn)(void);
signals_test_post_wait_hook_fn signals_test_set_post_wait_hook(
    signals_test_post_wait_hook_fn hook);
pid_t signals_test_published_child(void);
#endif

/** True if a guarded signal arrived since signals_guard_begin(). */
bool signals_pending(void);

/** The pending signal number, or 0 when none is pending. */
int signals_pending_signal(void);

/**
 * If a signal is pending: capture the caller's exact signal mask, end the
 * guard (restoring the caller's saved dispositions), temporarily unblock only
 * the selected signal, and re-raise it. The library-pending signal remains
 * published throughout delivery, then is cleared only if raise() returns
 * successfully; a returning inherited handler therefore observes the pending
 * signal during its call. The caller's exact mask is restored before return.
 *
 * A disposition-restoration, mask-query, unblock, or raise failure returns -1
 * with the library-pending signal retained for an explicit checked retry. A
 * raise failure remains the primary error even if restoring the caller mask
 * also fails. If delivery succeeds but exact mask restoration fails, return
 * -1 with the delivered signal cleared and retain only the mask-restoration
 * obligation: a retry restores the mask without re-raising the signal.
 * Returns 0 when nothing remains pending or when a non-terminating inherited
 * handler accepted the re-raised signal and exact mask restoration succeeded.
 * Call only after rollback/teardown is done.
 */
int signals_dispatch_pending(void);

/* --- SIG-02: scratch-file registry -----------------------------------------
 *
 * Temp files written via a create-then-rename pattern leak when the process
 * dies to a signal mid-write. Creators register the temp path right after
 * creating the file and unregister it after the rename/unlink; the emergency
 * (second-signal) handler and signals_scratch_cleanup() unlink whatever is
 * still registered. Fixed-size table, no allocation: registration in normal
 * context publishes a slot only after the path is fully copied, so the
 * handler can never observe a half-written entry.
 *
 * Adopters register around the temp file's lifetime; the table and handler
 * here do the rest. Registration is only effective while a guard is active:
 *   - src/config.c config_save() registers "<config_path>.tmp.<pid>" itself,
 *     and main() holds a guard across the save-after-switch (AR-02 #27).
 *   - src/ssh_manager.c ssh_configure_host_alias() registers the mkstemp-
 *     resolved "~/.ssh/config.gitswitch.XXXXXX" path across its write+rename
 *     (created inside accounts_switch's guarded window; its error paths also
 *     unlink it themselves) — AR-03 L9 closed what used to be the remaining
 *     hook point here.
 */

/**
 * Register a path to unlink on emergency signal teardown. Returns 0 on
 * success (or if already registered), -1 if the path is invalid/too long or
 * the table is full — callers must keep their own error-path unlink either way.
 */
int signals_scratch_register(const char *path);

/** Remove a path from the registry (after the temp was renamed/unlinked). */
void signals_scratch_unregister(const char *path);

/**
 * Unlink and drop every registered scratch path (normal context). Used on the
 * switch failure path so an interrupted switch leaves no *.tmp.* orphans;
 * unlinking an already-renamed/nonexistent path is harmless.
 */
void signals_scratch_cleanup(void);

#endif /* SIGNALS_H */
