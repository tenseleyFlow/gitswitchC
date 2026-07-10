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
 *   - EXCEPT while the rollback itself is running (signals_rollback_begin/
 *     end): the emergency exit there would abandon git_config_restore mid-way
 *     and permanently persist the aborted account's identity (AR-02 #2), so
 *     further signals stay recorded until the restore completes and the
 *     mainline dispatches. Interactive children spawned by the rollback keep
 *     default dispositions, so Ctrl-C still interrupts them.
 *   - Signals whose disposition is SIG_IGN at guard time stay ignored (so a
 *     nohup'd run keeps ignoring SIGHUP), matching sigaction(2) convention.
 */

#ifndef SIGNALS_H
#define SIGNALS_H

#include <stdbool.h>

/**
 * Install the deferring handler for SIGINT/SIGTERM/SIGHUP and clear any
 * previously pending signal. Idempotent while a guard is active. SA_RESTART
 * is used so a signal doesn't interrupt the parent blocked in poll/waitpid on
 * an in-flight child (run_argv already retries EINTR; restarting avoids
 * surprising every other syscall in the window). Returns 0.
 */
int signals_guard_begin(void);

/**
 * Restore the dispositions saved by signals_guard_begin(). Idempotent. Does
 * NOT clear a pending signal — callers finish their teardown first and then
 * either signals_dispatch_pending() (failure path) or deliberately complete
 * the already-applied switch (success path).
 */
void signals_guard_end(void);

/**
 * Mark the failed-switch rollback window. Between begin and end, the handler
 * defers even a second guarded signal (no emergency exit) so the multi-exec
 * git_config_restore can never be abandoned half-done (AR-02 #2). Callers
 * must pair these around the whole rollback sequence, before dispatching any
 * pending signal.
 */
void signals_rollback_begin(void);
void signals_rollback_end(void);

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
 * Adoption hook points for files owned by other remediation tickets (add a
 * register/unregister pair around the temp file's lifetime; the table and
 * handler here already do the rest):
 *   - src/config.c  config_save():              "<config_path>.tmp.<pid>"
 *   - src/ssh_manager.c ssh_configure_host_alias(): the mkstemp-resolved
 *     "~/.ssh/config.gitswitch.XXXXXX" path
 *   - src/git_ops.c: any future temp-then-rename write
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
