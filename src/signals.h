/* Signal guarding for the account-switch critical section (SIG-01, SIG-02).
 *
 * accounts_switch() applies SSH -> GPG -> git config as separate durable
 * steps, and Ctrl-C at an ssh-add passphrase or GPG pinentry prompt is a
 * NORMAL path through that window. Without a handler, SIGINT/SIGTERM/SIGHUP
 * killed the process between steps, bypassing the rollback machinery and
 * leaving a half-applied identity (e.g. current.sock repointed at the new
 * account while git user.email still names the old one) — exactly the
 * mixed-identity state the tool exists to prevent.
 *
 * Design (async-signal-safe by construction):
 *   - signals_guard_begin() installs a handler for SIGINT/SIGTERM/SIGHUP that
 *     only records the signal in a volatile sig_atomic_t. The mainline checks
 *     signals_pending() between durable steps and runs the ordinary rollback
 *     (git_config_restore + runtime-isolation teardown) in normal, non-handler
 *     context, then signals_dispatch_pending() re-raises so the exit status
 *     still reports death-by-signal to the shell.
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
 *   - That rollback deferral is BOUNDED, not absolute (AR-03 L8): a
 *     PROCESS-TARGETED kill never reaches the child's terminal group, so a
 *     rollback blocked at a re-prompting ssh-add passphrase read used to
 *     defer `kill -TERM <pid>` forever — unkillable short of SIGKILL, with
 *     the identity left half-rolled-back. Now run_argv publishes the
 *     in-flight child pid (signals_child_spawned/reaped, a single
 *     sig_atomic_t store), and a further guarded signal inside the rollback
 *     window forwards that signal to the CHILD's pid via kill() (which is
 *     async-signal-safe), escalating to SIGKILL if the same child survives a
 *     repeat. Killing the blocker makes the rollback PROCEED — every restore
 *     step is already per-key/best-effort, so the sequence still runs to
 *     completion and the mainline dispatches normally; this is not a return
 *     of the emergency exit mid-restore.
 *   - Signals whose disposition is SIG_IGN at guard time stay ignored (so a
 *     nohup'd run keeps ignoring SIGHUP), matching sigaction(2) convention.
 */

#ifndef SIGNALS_H
#define SIGNALS_H

#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>

/**
 * Install the deferring handler for SIGINT/SIGTERM/SIGHUP and clear any
 * previously pending signal. Idempotent while a guard is active. SA_RESTART
 * is used so a signal doesn't interrupt the parent blocked in poll/waitpid on
 * an in-flight child (run_argv already retries EINTR; restarting avoids
 * surprising every other syscall in the window). Returns 0 on success and -1
 * if any disposition query or installation fails. A failed begin restores
 * every disposition it already changed and preserves the originating errno;
 * only an inherited SIG_IGN is intentionally skipped.
 */
int signals_guard_begin(void);

/* Deterministic, one-shot fault injection for each sigaction(2) stage used by
 * the guard. Failures are stored independently by stage, so a test can arm an
 * installation failure and the rollback restoration failure it triggers at
 * the same time. Passing SIGNALS_TEST_SIGACTION_NONE clears every stage. */
typedef enum {
    SIGNALS_TEST_SIGACTION_NONE = 0,
    SIGNALS_TEST_SIGACTION_QUERY,
    SIGNALS_TEST_SIGACTION_INSTALL,
    SIGNALS_TEST_SIGACTION_RESTORE
} signals_test_sigaction_stage_t;

void signals_test_fail_sigaction(int signal_number,
                                 signals_test_sigaction_stage_t stage,
                                 int system_errno);

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

/**
 * Reset only signals whose dispositions signals_guard_begin() actually
 * replaced, and unblock only that same set, in a freshly-forked child before
 * it execs (AR-06 F76 / AR-07 M32). This closes the window where the child
 * still runs guard_handler without changing an inherited SIG_IGN or its mask.
 * Async-signal-safe enough for our single-threaded fork; call it first thing
 * in the child branch.
 */
void signals_reset_for_child(void);

/**
 * Close the post-fork/pre-publication race for a guarded child launch.
 * signals_block_for_child_spawn() adds exactly the dispositions installed by
 * the active guard to the caller's mask and captures the complete prior mask.
 * In the parent, publish the PID and then restore that exact mask with
 * signals_restore_after_child_spawn(). In the child, signals_reset_for_child()
 * resets the inherited guard dispositions and unblocks that installed set.
 */
int signals_block_for_child_spawn(sigset_t *previous_mask);
int signals_restore_after_child_spawn(const sigset_t *previous_mask);

/**
 * Publish / retract the in-flight subprocess (AR-03 L8). run_argv's spawn
 * path calls signals_child_spawned(pid) right after fork() returns in the
 * parent and signals_child_reaped() right after waitpid() reaps, so the
 * handler can kill() the child that a blocked rollback is waiting on (see the
 * bounded-deferral bullet above). Both are single sig_atomic_t stores —
 * cheap, lock-free, and safe against the handler observing a torn value.
 * Publishing outside the rollback window is harmless: the handler only
 * consults the pid when a second guarded signal lands during rollback.
 */
void signals_child_spawned(pid_t pid);
void signals_child_reaped(void);

/** True if a guarded signal arrived since signals_guard_begin(). */
bool signals_pending(void);

/** The pending signal number, or 0 when none is pending. */
int signals_pending_signal(void);

/**
 * If a signal is pending: end the guard (restoring default dispositions) and
 * re-raise it, terminating the process with the correct signal exit status.
 * No-op when nothing is pending. Call only after rollback/teardown is done.
 */
void signals_dispatch_pending(void);

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
