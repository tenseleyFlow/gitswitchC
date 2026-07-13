/* Signal guarding for the account-switch critical section (SIG-01, SIG-02).
 * See signals.h for the design rationale. Everything reachable from the
 * handler is restricted to the POSIX async-signal-safe set: sig_atomic_t
 * stores, unlink(), signal(), raise(), kill().
 */

/* glibc wants a POSIX feature macro for sigaction; FreeBSD gates SA_RESTART
 * as an XSI extension that strict _POSIX_C_SOURCE hides, and macOS likewise
 * prunes its default namespace under it — leave those on their fully-visible
 * defaults (the same trap documented in ssh_manager.c). */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "signals.h"
#include "gitswitch.h"
#include "error.h"

/* The signals we guard. SIGINT covers Ctrl-C at a passphrase/pinentry prompt,
 * SIGTERM a polite kill, SIGHUP a closed terminal — all three default to
 * terminating the process, which is what bypassed the rollback machinery. */
static const int g_guarded_signals[] = { SIGINT, SIGTERM, SIGHUP };
#define GUARDED_SIGNAL_COUNT \
    (sizeof(g_guarded_signals) / sizeof(g_guarded_signals[0]))

/* First guarded signal received, or 0. sig_atomic_t is the only integer type
 * guaranteed readable/writable atomically with respect to a signal handler. */
static volatile sig_atomic_t g_pending_signal = 0;

/* Nonzero while the mainline owns a transaction-critical mutation/rollback
 * window. The handler's second-signal emergency exit must not fire between
 * forward publication and prepared commit/abort, nor mid-git_config_restore:
 * either gap can persist a chimera identity (AR-08 M4 / AR-02 #2).
 * Set/cleared only in normal context. */
static volatile sig_atomic_t g_rollback_in_progress = 0;

/* AR-03 L8: the pid of the subprocess run_argv is currently blocked on, or 0.
 * Published right after fork() and cleared right after waitpid() so the
 * handler can kill() a child the rollback is wedged behind (a re-prompting
 * ssh-add reading a passphrase that will never come). sig_atomic_t is the
 * only type the handler may read while the mainline writes it; pid_t is int
 * on every platform we build for — the static assert makes that assumption
 * fail loudly rather than truncate a pid. */
static volatile sig_atomic_t g_child_pid = 0;
_Static_assert(sizeof(sig_atomic_t) >= sizeof(pid_t),
               "pid_t must fit in sig_atomic_t for the L8 child-pid publication");

/* The child pid the handler already forwarded a signal to. A repeat signal
 * against the SAME still-in-flight child escalates to SIGKILL — the polite
 * forward is enough for anything with default dispositions (all our
 * interactive children), the escalation covers a wrapper that ignores it. */
static volatile sig_atomic_t g_child_signaled = 0;

/* Saved dispositions so signals_guard_end() restores exactly what was there
 * (default action, or an outer SIG_IGN we chose not to override). */
static struct sigaction g_saved_actions[GUARDED_SIGNAL_COUNT];
static bool g_action_installed[GUARDED_SIGNAL_COUNT];
typedef enum {
    GUARD_INACTIVE = 0,
    GUARD_ACTIVE,
    GUARD_RESTORE_PENDING
} guard_state_t;
static guard_state_t g_guard_state = GUARD_INACTIVE;

/* Independent one-shot faults let a single begin attempt fail installation
 * and then fail the rollback restoration of an earlier disposition. */
typedef struct {
    int signal_number;
    int system_errno;
} sigaction_test_fault_t;

static sigaction_test_fault_t
    g_test_sigaction_faults[SIGNALS_TEST_SIGACTION_RESTORE + 1];

void signals_test_fail_sigaction(int signal_number,
                                 signals_test_sigaction_stage_t stage,
                                 int system_errno) {
    if (stage <= SIGNALS_TEST_SIGACTION_NONE || signal_number <= 0 ||
        system_errno <= 0 || stage > SIGNALS_TEST_SIGACTION_RESTORE) {
        memset(g_test_sigaction_faults, 0,
               sizeof(g_test_sigaction_faults));
        return;
    }
    g_test_sigaction_faults[stage].signal_number = signal_number;
    g_test_sigaction_faults[stage].system_errno = system_errno;
}

static int guard_sigaction(int signal_number, const struct sigaction *action,
                           struct sigaction *old_action,
                           signals_test_sigaction_stage_t stage) {
    sigaction_test_fault_t *fault = &g_test_sigaction_faults[stage];

    if (fault->signal_number == signal_number) {
        int injected_errno = fault->system_errno;
        fault->signal_number = 0;
        fault->system_errno = 0;
        errno = injected_errno;
        return -1;
    }
    return sigaction(signal_number, action, old_action);
}

/* Restore every disposition changed by the current guard, newest first.
 * Failed entries remain published in the bitmap so cleanup or a later begin
 * can retry rather than falsely claiming no handler is installed. */
static bool restore_partial_guard(int *restore_signal, int *restore_errno) {
    bool restored_all = true;

    *restore_signal = 0;
    *restore_errno = 0;
    for (size_t i = GUARDED_SIGNAL_COUNT; i > 0; i--) {
        size_t index = i - 1;
        if (!g_action_installed[index]) {
            continue;
        }
        if (guard_sigaction(g_guarded_signals[index],
                            &g_saved_actions[index], NULL,
                            SIGNALS_TEST_SIGACTION_RESTORE) == 0) {
            g_action_installed[index] = false;
        } else {
            if (*restore_errno == 0) {
                *restore_signal = g_guarded_signals[index];
                *restore_errno = errno;
            }
            restored_all = false;
        }
    }
    return restored_all;
}

/* SIG-02 scratch registry: fixed-size, allocation-free so the handler can
 * walk it safely. `used` is the publish flag — set only after `path` is fully
 * written (normal context), cleared before a slot is considered free — so the
 * handler never sees a torn entry. */
#define SCRATCH_TABLE_SIZE 8
typedef struct {
    char path[MAX_PATH_LEN];
    volatile sig_atomic_t used;
} scratch_slot_t;
static scratch_slot_t g_scratch[SCRATCH_TABLE_SIZE];

/* Unlink every registered scratch path. Called from the handler (emergency
 * exit) and from signals_scratch_cleanup(); uses only unlink(), which is
 * async-signal-safe. */
static void scratch_unlink_all(void) {
    for (size_t i = 0; i < SCRATCH_TABLE_SIZE; i++) {
        if (g_scratch[i].used) {
            (void)unlink(g_scratch[i].path);
            g_scratch[i].used = 0;
        }
    }
}

static void guard_handler(int sig) {
    /* AR-06 F67: a signal handler runs asynchronously in the middle of mainline
     * code; the kill()/unlink() calls below clobber errno, so save and restore
     * it around the whole handler or the interrupted mainline sees a corrupted
     * errno (e.g. a checked syscall's ESRCH/EINTR turned into something else). */
    int saved_errno = errno;

    if (g_pending_signal == 0) {
        /* First signal: record it and return. The mainline notices via
         * signals_pending() between durable steps and rolls back in normal
         * context — running git/teardown from here would not be
         * async-signal-safe. */
        g_pending_signal = sig;
        errno = saved_errno;
        return;
    }

    /* Second signal while a critical mutation window is open — a rollback,
     * the deferred previous-account teardown, or the forward SSH/GPG/git
     * activation of a switch (AR-05 M4): stay deferred. The emergency exit
     * below would abandon git_config_restore mid-way and permanently leave
     * the aborted account's identity written (AR-02 #2), or strand a
     * half-activated identity plus a live key-holding agent (M4).
     * The rollback is bounded work (a handful of local git execs) and its
     * interactive children (e.g. a re-prompting ssh-add) keep their default
     * dispositions, so Ctrl-C still kills THEM — liveness is preserved
     * without sacrificing restore atomicity.
     *
     * A PROCESS-TARGETED kill is the exception (AR-03 L8): it never reaches
     * the child's terminal group, so a rollback blocked at an ssh-add
     * passphrase read would defer it forever. Forward the signal to the
     * in-flight child (kill() is async-signal-safe) so the blocker dies and
     * the rollback PROCEEDS — every restore step is per-key/best-effort, so
     * the sequence still runs to completion and the mainline dispatches the
     * pending signal at the end. Signal the child's PID, not its pgid: our
     * children share this process group (no setpgid at spawn), so a group
     * kill would loop the signal back at us and any sibling; the recorded
     * pid is exactly the process that is blocked. If the same child survives
     * a repeat signal (something ignoring SIGTERM), escalate to SIGKILL. */
    if (g_rollback_in_progress) {
        pid_t child = (pid_t)g_child_pid;
        if (child > 0) {
            if ((pid_t)g_child_signaled == child) {
                (void)kill(child, SIGKILL);
            } else {
                g_child_signaled = (sig_atomic_t)child;
                (void)kill(child, sig);
            }
        }
        errno = saved_errno;
        return;
    }

    /* Second signal while one is pending: the user insists (or the first was
     * swallowed by a stuck child prompt). Do the only teardown that is safe
     * here — drop registered scratch files — then die with the correct
     * signal status. signal() and raise() are on the async-signal-safe list. */
    scratch_unlink_all();
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

int signals_block_for_child_spawn(sigset_t *previous_mask) {
    sigset_t installed;

    if (!previous_mask) {
        errno = EINVAL;
        return -1;
    }
    sigemptyset(&installed);
    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        if (g_action_installed[i]) {
            sigaddset(&installed, g_guarded_signals[i]);
        }
    }
    return sigprocmask(SIG_BLOCK, &installed, previous_mask);
}

int signals_restore_after_child_spawn(const sigset_t *previous_mask) {
    if (!previous_mask) {
        errno = EINVAL;
        return -1;
    }
    return sigprocmask(SIG_SETMASK, previous_mask, NULL);
}

void signals_reset_for_child(void) {
    /* AR-06 F76 / AR-07 M32: reset only dispositions this guard actually
     * replaced.  An inherited SIG_IGN is deliberately left untouched by
     * signals_guard_begin(); resetting every nominally guarded signal here
     * resurrected that ignored signal as SIG_DFL in the fork-to-exec window.
     * The installed bitmap is copied atomically by fork, so it is the exact
     * record of which child dispositions still point at guard_handler. */
    sigset_t installed;
    sigemptyset(&installed);
    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        if (!g_action_installed[i]) {
            continue;
        }
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        (void)sigaction(g_guarded_signals[i], &dfl, NULL);
        sigaddset(&installed, g_guarded_signals[i]);
    }
    /* Only handlers installed by the guard are unblocked.  Preserving both
     * the disposition and mask of a skipped inherited signal keeps the
     * supervisor/nohup contract byte-for-byte until exec. */
    (void)sigprocmask(SIG_UNBLOCK, &installed, NULL);
}

void signals_rollback_begin(void) {
    g_rollback_in_progress = 1;
}

void signals_rollback_end(void) {
    g_rollback_in_progress = 0;
}

void signals_child_spawned(pid_t pid) {
    if (pid > 0) {
        g_child_pid = (sig_atomic_t)pid;
    }
}

void signals_child_reaped(void) {
    /* Clear the pid FIRST: once waitpid() has reaped, the kernel may reuse
     * the pid, and a handler firing between reap and this store must not
     * kill() a stranger. The window is the few instructions between waitpid
     * returning and this call — and the handler only consults the pid when a
     * repeat signal lands mid-rollback — so the residual race is accepted.
     * Then retire the escalation latch so the next child (which could
     * legitimately be handed the same pid) starts back at the polite step. */
    g_child_pid = 0;
    g_child_signaled = 0;
}

int signals_guard_begin(void) {
    sig_atomic_t previous_pending;

    if (g_guard_state == GUARD_ACTIVE) {
        return 0;
    }
    if (g_guard_state == GUARD_RESTORE_PENDING) {
        int restore_signal;
        int restore_errno;

        if (!restore_partial_guard(&restore_signal, &restore_errno)) {
            g_guard_state = GUARD_RESTORE_PENDING;
            errno = restore_errno;
            set_system_error(
                ERR_SYSTEM_CALL,
                "Cannot begin signal guard while restoration of signal %d "
                "remains pending",
                restore_signal);
            errno = restore_errno;
            return -1;
        }

        /* This call entered with a partial guard, so never report it as a
         * successful active guard.  The retained dispositions are now fully
         * restored and a clean retry may install a new guard. */
        g_guard_state = GUARD_INACTIVE;
        errno = EBUSY;
        set_system_error(ERR_SYSTEM_CALL,
                         "Recovered an incomplete signal guard restoration; "
                         "retry the operation");
        errno = EBUSY;
        return -1;
    }

    previous_pending = g_pending_signal;
    g_pending_signal = 0;
    memset(g_action_installed, 0, sizeof(g_action_installed));

    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction current, ours;
        int failure_errno;
        int restore_signal;
        int restore_errno;
        const char *operation;

        /* Respect an inherited SIG_IGN (e.g. nohup ignores SIGHUP): the
         * caller's environment already decided this signal must not act, and
         * deferring-then-re-raising it would resurrect it. */
        if (guard_sigaction(g_guarded_signals[i], NULL, &current,
                            SIGNALS_TEST_SIGACTION_QUERY) != 0) {
            operation = "query";
            goto begin_failed;
        }
        if (current.sa_handler == SIG_IGN) {
            continue;
        }

        memset(&ours, 0, sizeof(ours));
        ours.sa_handler = guard_handler;
        sigemptyset(&ours.sa_mask);
        /* Block the sibling guarded signals while the handler runs so the
         * pending-vs-emergency decision is not raced by a different signal. */
        for (size_t j = 0; j < GUARDED_SIGNAL_COUNT; j++) {
            sigaddset(&ours.sa_mask, g_guarded_signals[j]);
        }
        /* SA_RESTART: the guarded window spends its time blocked in
         * poll()/waitpid() on children (git, ssh-add, gpg); run_argv retries
         * EINTR anyway, but restarting keeps every other syscall in the
         * window from failing spuriously. */
        ours.sa_flags = SA_RESTART;

        if (guard_sigaction(g_guarded_signals[i], &ours,
                            &g_saved_actions[i],
                            SIGNALS_TEST_SIGACTION_INSTALL) == 0) {
            g_action_installed[i] = true;
            continue;
        }

        operation = "install";

begin_failed:
        failure_errno = errno;
        if (g_pending_signal == 0) {
            g_pending_signal = previous_pending;
        }
        g_guard_state = restore_partial_guard(&restore_signal, &restore_errno)
            ? GUARD_INACTIVE : GUARD_RESTORE_PENDING;
        errno = failure_errno;
        if (restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to %s guarded disposition for signal %d; "
                "also failed to restore signal %d (restore errno=%d)",
                operation, g_guarded_signals[i], restore_signal,
                restore_errno);
        } else {
            set_system_error(ERR_SYSTEM_CALL,
                             "Failed to %s guarded disposition for signal %d",
                             operation, g_guarded_signals[i]);
        }
        errno = failure_errno;
        return -1;
    }

    g_guard_state = GUARD_ACTIVE;
    log_debug("Signal guard installed for switch critical section");
    return 0;
}

int signals_guard_end(void) {
    int restore_signal;
    int restore_errno;

    if (g_guard_state == GUARD_INACTIVE) {
        return 0;
    }
    if (!restore_partial_guard(&restore_signal, &restore_errno)) {
        g_guard_state = GUARD_RESTORE_PENDING;
        errno = restore_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to restore guarded disposition for signal %d",
                         restore_signal);
        errno = restore_errno;
        return -1;
    }
    g_guard_state = GUARD_INACTIVE;
    log_debug("Signal guard removed");
    return 0;
}

bool signals_pending(void) {
    return g_pending_signal != 0;
}

int signals_pending_signal(void) {
    return (int)g_pending_signal;
}

void signals_dispatch_pending(void) {
    int sig = (int)g_pending_signal;
    if (sig == 0) {
        return;
    }
    signals_guard_end();
    g_pending_signal = 0;
    /* Re-raise under the restored (normally default) disposition so the
     * process reports death-by-signal — scripts and shells relying on the
     * 128+N convention see the truth, not a made-up exit code. */
    (void)raise(sig);
}

int signals_scratch_register(const char *path) {
    if (!path || path[0] == '\0' || strlen(path) >= MAX_PATH_LEN) {
        return -1;
    }
    /* Already registered? (idempotent for retry loops) */
    for (size_t i = 0; i < SCRATCH_TABLE_SIZE; i++) {
        if (g_scratch[i].used && strcmp(g_scratch[i].path, path) == 0) {
            return 0;
        }
    }
    for (size_t i = 0; i < SCRATCH_TABLE_SIZE; i++) {
        if (!g_scratch[i].used) {
            /* Copy the path fully BEFORE publishing the slot via `used` so a
             * handler interrupting mid-copy sees an unused slot, never a
             * truncated path it might unlink. */
            safe_strncpy(g_scratch[i].path, path, sizeof(g_scratch[i].path));
            g_scratch[i].used = 1;
            return 0;
        }
    }
    /* Table full: fail closed — the caller keeps its own error-path unlink. */
    log_warning("Scratch registry full; %s not covered by signal cleanup", path);
    return -1;
}

void signals_scratch_unregister(const char *path) {
    if (!path) {
        return;
    }
    for (size_t i = 0; i < SCRATCH_TABLE_SIZE; i++) {
        if (g_scratch[i].used && strcmp(g_scratch[i].path, path) == 0) {
            g_scratch[i].used = 0;
        }
    }
}

void signals_scratch_cleanup(void) {
    scratch_unlink_all();
}
