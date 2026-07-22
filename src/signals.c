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
#include <stdatomic.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "signals.h"
#include "gitswitch.h"
#include "error.h"

/* The signals we guard. SIGINT covers Ctrl-C at a passphrase/pinentry prompt,
 * SIGTERM a polite kill, SIGHUP a closed terminal — all three default to
 * terminating the process, which is what bypassed the rollback machinery.
 * AR-10 L16: SIGQUIT (Ctrl-\) terminates too and bypassed the deferral
 * exactly as unguarded SIGINT once did; deferral preserves its core-dump
 * semantics because dispatch re-raises with the default disposition. */
static const int g_guarded_signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };
#define GUARDED_SIGNAL_COUNT \
    (sizeof(g_guarded_signals) / sizeof(g_guarded_signals[0]))

/* First guarded signal received, or 0. sig_atomic_t is the only integer type
 * guaranteed readable/writable atomically with respect to a signal handler. */
static volatile sig_atomic_t g_pending_signal = 0;

/* signals_dispatch_pending() temporarily removes only the selected signal
 * from the caller's mask. If restoring that exact mask fails after delivery,
 * the signal must not be raised again on retry; if raise itself failed, the
 * retained library-pending signal must not be retried against the temporary
 * mask. Preserve the original mask until an explicit dispatch retry restores
 * it in either case. This state is normal-context-only: the handler never
 * reads or writes it. */
static sigset_t g_dispatch_saved_mask;
static bool g_dispatch_mask_restore_pending = false;

/* Nonzero while the mainline owns a transaction-critical mutation/rollback
 * window. The handler's second-signal emergency exit must not fire between
 * forward publication and prepared commit/abort, nor mid-git_config_restore:
 * either gap can persist a chimera identity (AR-08 M4 / AR-02 #2).
 * Set/cleared only in normal context. */
static volatile sig_atomic_t g_rollback_in_progress = 0;

/* The historical public rollback API is intentionally idempotent. Account
 * transactions additionally need exact nesting and owner matching, so keep
 * the two sources independent and derive the handler-visible Boolean from
 * both. Normal-context code is single-threaded; the handler reads only the
 * sig_atomic_t publication above. */
static bool g_legacy_rollback_in_progress = false;
static uint64_t g_owned_rollback_token = 0;
static size_t g_owned_rollback_depth = 0;

static void publish_rollback_state(void) {
    g_rollback_in_progress =
        (g_legacy_rollback_in_progress || g_owned_rollback_depth > 0) ? 1 : 0;
}

/* AR-03 L8: the pid of the subprocess run_argv is currently blocked on, or 0.
 * Published right after fork() and retired with its matching guarded reap;
 * WNOWAIT keeps the PID unreusable until that transition. The handler can
 * kill() a child the rollback is wedged behind (for example ssh-add awaiting
 * input). sig_atomic_t is the only type the handler may read while mainline
 * writes it; the static assert prevents pid_t truncation. */
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

/* AR-10 L15: like the dispatch injection below, the sigaction fault and
 * guard-end sabotage seams exist ONLY in GITSWITCH_TESTING objects. They
 * used to compile into the production object as callable guard-sabotage
 * entry points. */
#ifdef GITSWITCH_TESTING
/* Independent one-shot faults let a single begin attempt fail installation
 * and then fail the rollback restoration of an earlier disposition. */
typedef struct {
    int signal_number;
    int system_errno;
} sigaction_test_fault_t;

static sigaction_test_fault_t
    g_test_sigaction_faults[SIGNALS_TEST_SIGACTION_RESTORE + 1];
static signals_test_guard_end_hook_fn g_test_guard_end_hook;
static signals_test_post_wait_hook_fn g_test_post_wait_hook;
#endif

enum {
    DISPATCH_STAGE_NONE = 0,
    DISPATCH_STAGE_MASK_QUERY,
    DISPATCH_STAGE_UNBLOCK,
    DISPATCH_STAGE_RAISE,
    DISPATCH_STAGE_MASK_RESTORE
};

#ifdef GITSWITCH_TESTING
static int g_test_dispatch_errno[DISPATCH_STAGE_MASK_RESTORE + 1];

_Static_assert((int)SIGNALS_TEST_DISPATCH_NONE == DISPATCH_STAGE_NONE,
               "dispatch test stages must remain aligned");
_Static_assert((int)SIGNALS_TEST_DISPATCH_MASK_QUERY ==
                   DISPATCH_STAGE_MASK_QUERY,
               "dispatch test stages must remain aligned");
_Static_assert((int)SIGNALS_TEST_DISPATCH_UNBLOCK == DISPATCH_STAGE_UNBLOCK,
               "dispatch test stages must remain aligned");
_Static_assert((int)SIGNALS_TEST_DISPATCH_RAISE == DISPATCH_STAGE_RAISE,
               "dispatch test stages must remain aligned");
_Static_assert((int)SIGNALS_TEST_DISPATCH_MASK_RESTORE ==
                   DISPATCH_STAGE_MASK_RESTORE,
               "dispatch test stages must remain aligned");

void signals_test_fail_dispatch(signals_test_dispatch_stage_t stage,
                                int system_errno) {
    if (stage <= SIGNALS_TEST_DISPATCH_NONE ||
        stage > SIGNALS_TEST_DISPATCH_MASK_RESTORE || system_errno <= 0) {
        memset(g_test_dispatch_errno, 0, sizeof(g_test_dispatch_errno));
        return;
    }
    g_test_dispatch_errno[stage] = system_errno;
}
#endif

static int dispatch_sigprocmask(int how, const sigset_t *set,
                                sigset_t *old_set, int stage) {
#ifdef GITSWITCH_TESTING
    if (stage > DISPATCH_STAGE_NONE &&
        stage <= DISPATCH_STAGE_MASK_RESTORE &&
        g_test_dispatch_errno[stage] != 0) {
        int injected_errno = g_test_dispatch_errno[stage];

        g_test_dispatch_errno[stage] = 0;
        errno = injected_errno;
        return -1;
    }
#else
    (void)stage;
#endif
    return sigprocmask(how, set, old_set);
}

static int dispatch_raise(int signal_number) {
#ifdef GITSWITCH_TESTING
    if (g_test_dispatch_errno[DISPATCH_STAGE_RAISE] != 0) {
        int injected_errno =
            g_test_dispatch_errno[DISPATCH_STAGE_RAISE];

        g_test_dispatch_errno[DISPATCH_STAGE_RAISE] = 0;
        errno = injected_errno;
        return -1;
    }
#endif
    return raise(signal_number);
}

#ifdef GITSWITCH_TESTING
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

signals_test_guard_end_hook_fn signals_test_set_guard_end_hook(
    signals_test_guard_end_hook_fn hook) {
    signals_test_guard_end_hook_fn previous = g_test_guard_end_hook;

    g_test_guard_end_hook = hook;
    return previous;
}

signals_test_post_wait_hook_fn signals_test_set_post_wait_hook(
    signals_test_post_wait_hook_fn hook) {
    signals_test_post_wait_hook_fn previous = g_test_post_wait_hook;

    g_test_post_wait_hook = hook;
    return previous;
}

pid_t signals_test_published_child(void) {
    return (pid_t)g_child_pid;
}
#endif

static int guard_sigaction(int signal_number, const struct sigaction *action,
                           struct sigaction *old_action,
                           signals_test_sigaction_stage_t stage) {
#ifdef GITSWITCH_TESTING
    sigaction_test_fault_t *fault = &g_test_sigaction_faults[stage];

    if (fault->signal_number == signal_number) {
        int injected_errno = fault->system_errno;
        fault->signal_number = 0;
        fault->system_errno = 0;
        errno = injected_errno;
        return -1;
    }
#else
    (void)stage;
#endif
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

void signals_reset_for_child(const sigset_t *inherited_mask) {
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
    /* AR-10 L17: the caller's pre-spawn mask is the inherited-mask contract.
     * The old unconditional SIG_UNBLOCK also unblocked a guarded signal the
     * SUPERVISOR had blocked before gitswitch even started, so exec'd
     * children diverged from what they would have inherited. Restore the
     * exact snapshot when the caller provides one; the unblock of
     * guard-installed signals remains the fallback for legacy callers. */
    if (inherited_mask) {
        (void)sigprocmask(SIG_SETMASK, inherited_mask, NULL);
    } else {
        /* Only handlers installed by the guard are unblocked.  Preserving
         * both the disposition and mask of a skipped inherited signal keeps
         * the supervisor/nohup contract byte-for-byte until exec. */
        (void)sigprocmask(SIG_UNBLOCK, &installed, NULL);
    }
}

void signals_rollback_begin(void) {
    g_legacy_rollback_in_progress = true;
    publish_rollback_state();
}

void signals_rollback_end(void) {
    g_legacy_rollback_in_progress = false;
    publish_rollback_state();
}

int signals_rollback_begin_owned(uint64_t token) {
    if (token == 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "A checked signal rollback owner requires a nonzero token");
        return -1;
    }
    if (g_owned_rollback_depth > 0 && g_owned_rollback_token != token) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Signal rollback is owned by another transaction token");
        return -1;
    }
    if (g_owned_rollback_depth == SIZE_MAX) {
        errno = EOVERFLOW;
        set_error(ERR_SYSTEM_CALL,
                  "Signal rollback nesting depth overflow");
        return -1;
    }
    if (g_owned_rollback_depth == 0) {
        g_owned_rollback_token = token;
    }
    g_owned_rollback_depth++;
    publish_rollback_state();
    return 0;
}

int signals_rollback_end_owned(uint64_t token) {
    if (token == 0 || g_owned_rollback_depth == 0 ||
        g_owned_rollback_token != token) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Signal rollback finalizer does not match its owner token");
        return -1;
    }
    g_owned_rollback_depth--;
    if (g_owned_rollback_depth == 0) {
        g_owned_rollback_token = 0;
    }
    publish_rollback_state();
    return 0;
}

bool signals_rollback_active(void) {
    return g_rollback_in_progress != 0;
}

void signals_child_spawned(pid_t pid) {
    if (pid > 0) {
        g_child_pid = (sig_atomic_t)pid;
    }
}

static void signals_child_retire(pid_t pid) {
    if ((pid_t)g_child_pid == pid) {
        g_child_pid = 0;
        g_child_signaled = 0;
    }
}

int signals_child_wait_begin(sigset_t *previous_mask) {
    sigset_t block;
    struct sigaction action;
    int failure_errno;

    memset(&action, 0, sizeof(action));

    if (!previous_mask) {
        errno = EINVAL;
        set_system_error(ERR_INVALID_ARGS,
                         "Cannot establish child wait ownership without a mask output");
        errno = EINVAL;
        return -1;
    }
    if (sigemptyset(&block) != 0 || sigaddset(&block, SIGCHLD) != 0) {
        failure_errno = errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot prepare SIGCHLD wait-ownership mask");
        errno = failure_errno;
        return -1;
    }
    if (sigprocmask(SIG_BLOCK, &block, previous_mask) != 0) {
        failure_errno = errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot block SIGCHLD before checking wait ownership");
        errno = failure_errno;
        return -1;
    }
    if (sigaction(SIGCHLD, NULL, &action) != 0) {
        failure_errno = errno;
        int restore_errno = 0;
        if (sigprocmask(SIG_SETMASK, previous_mask, NULL) != 0) {
            restore_errno = errno;
        }
        errno = failure_errno;
        if (restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Cannot query SIGCHLD wait ownership; also failed to restore the caller mask (restore errno=%d)",
                restore_errno);
        } else {
            set_system_error(ERR_SYSTEM_CALL,
                             "Cannot query SIGCHLD wait ownership");
        }
        errno = failure_errno;
        return -1;
    }
    if (action.sa_handler == SIG_IGN || action.sa_handler != SIG_DFL ||
        (action.sa_flags & SA_NOCLDWAIT) != 0) {
        failure_errno = EBUSY;
        int restore_errno = 0;
        if (sigprocmask(SIG_SETMASK, previous_mask, NULL) != 0) {
            restore_errno = errno;
        }
        errno = failure_errno;
        if (restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Cannot spawn helper while SIGCHLD is ignored, auto-reaped, or owned by another reaper; also failed to restore the caller mask (restore errno=%d)",
                restore_errno);
        } else {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Cannot spawn helper while SIGCHLD is ignored, auto-reaped, or owned by another reaper");
        }
        errno = failure_errno;
        return -1;
    }
    return 0;
}

int signals_child_wait_end(const sigset_t *previous_mask) {
    if (!previous_mask) {
        errno = EINVAL;
        return -1;
    }
    return sigprocmask(SIG_SETMASK, previous_mask, NULL);
}

signals_child_wait_result_t signals_wait_child(pid_t pid, int *status,
                                                int options) {
    signals_child_wait_result_t result = {
        .waited = -1,
        .wait_errno = 0,
        .mask_errno = 0
    };
    siginfo_t observed;
    sigset_t guarded;
    sigset_t saved_mask;
    int observe_options = WEXITED | WNOWAIT;
    bool observed_echild = false;
    /* AR-13 L5: always reap into a real status buffer — a local one when the
     * caller passed none — so retirement is judged from what waitpid actually
     * reaped, never the pre-reap observe verdict (which WSTOPPED/WCONTINUED can
     * leave non-terminal while the child dies in the window before waitpid). */
    int local_status = 0;
    int *reap_status = status ? status : &local_status;

    /* First observe the child without releasing its PID.  A blocking waitid
     * remains interruptible by the guard handler, so a repeated rollback
     * signal can still reach and terminate a wedged helper.  WNOWAIT keeps a
     * completed child waitable (and therefore its PID unreusable) until the
     * guarded waitpid+retire transition below. */
    if ((options & WNOHANG) != 0) observe_options |= WNOHANG;
#ifdef WUNTRACED
    if ((options & WUNTRACED) != 0) observe_options |= WSTOPPED;
#endif
#ifdef WCONTINUED
    if ((options & WCONTINUED) != 0) observe_options |= WCONTINUED;
#endif
    memset(&observed, 0, sizeof(observed));
    if (waitid(P_PID, (id_t)pid, &observed, observe_options) != 0) {
        result.wait_errno = errno;
        if (result.wait_errno != ECHILD) return result;
        /* An initial ECHILD proves this process no longer owns the published
         * PID. Still enter the guarded retirement transition so the handler
         * cannot retain or act on that stale publication. */
        observed_echild = true;
    }
    if (!observed_echild && observed.si_pid == 0) {
        result.waited = 0;
        return result;
    }

    if (sigemptyset(&guarded) != 0) {
        result.mask_errno = errno;
        return result;
    }
    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        if (g_action_installed[i] &&
            sigaddset(&guarded, g_guarded_signals[i]) != 0) {
            result.mask_errno = errno;
            return result;
        }
    }
    if (sigprocmask(SIG_BLOCK, &guarded, &saved_mask) != 0) {
        result.mask_errno = errno;
        return result;
    }

    if (!observed_echild) {
        result.waited = waitpid(pid, reap_status, options);
        if (result.waited < 0) result.wait_errno = errno;
    }

#ifdef GITSWITCH_TESTING
    if (g_test_post_wait_hook &&
        (result.waited == pid ||
         (result.waited < 0 && result.wait_errno == ECHILD))) {
        signals_test_post_wait_hook_fn checkpoint = g_test_post_wait_hook;
        g_test_post_wait_hook = NULL;
        checkpoint();
    }
#endif

    /* AR-12 L18 / AR-13 L5: judge retirement by what waitpid actually REAPED,
     * not the pre-reap observe verdict — with WUNTRACED/WCONTINUED the observe
     * leg can report a stop/continue while the child dies in the window before
     * waitpid, which then releases the PID with a death status. reap_status is
     * always a real buffer (a local one when the caller passed none), so the
     * reaped status is available regardless. An initial ECHILD (waited < 0)
     * likewise proves this process no longer owns the published PID. */
    if ((result.waited == pid &&
         (WIFEXITED(*reap_status) || WIFSIGNALED(*reap_status))) ||
        (result.waited < 0 && result.wait_errno == ECHILD)) {
        /* waitpid has either released the PID or proved that this process no
         * longer owns it. Retire while every handler that could consult the
         * publication is still blocked. */
        signals_child_retire(pid);
    }
    if (sigprocmask(SIG_SETMASK, &saved_mask, NULL) != 0) {
        result.mask_errno = errno;
    }
    return result;
}

int signals_guard_begin(void) {
    sig_atomic_t previous_pending;

    if (g_dispatch_mask_restore_pending) {
        errno = EBUSY;
        set_system_error(
            ERR_SYSTEM_CALL,
            "Cannot begin signal guard while deferred-dispatch mask restoration remains pending");
        errno = EBUSY;
        return -1;
    }
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
        /* SA_RESTART: guarded work often blocks in poll()/waitid()/waitpid()
         * on children. The runner handles EINTR, while restart semantics keep
         * unrelated syscalls from failing spuriously. */
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

bool signals_guard_active(void) {
    return g_guard_state != GUARD_INACTIVE;
}

int signals_guard_end(void) {
    int restore_signal;
    int restore_errno;
#ifdef GITSWITCH_TESTING
    signals_test_guard_end_hook_fn checkpoint;
#endif

    if (g_guard_state == GUARD_INACTIVE) {
        return 0;
    }
#ifdef GITSWITCH_TESTING
    checkpoint = g_test_guard_end_hook;
    g_test_guard_end_hook = NULL;
    if (checkpoint) {
        checkpoint();
    }
#endif
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

int signals_dispatch_pending(void) {
    sigset_t caller_mask;
    sigset_t target_set;
    int raise_errno;
    int raise_rc;
    int restore_errno;
    int sig;

    /* A previous delivery may have returned successfully before exact mask
     * restoration failed. Repair that state first and do not re-raise when
     * the library-pending signal was already consumed. A failed raise keeps
     * g_pending_signal set, but likewise cannot be retried until the original
     * mask has been recovered. */
    if (g_dispatch_mask_restore_pending) {
        if (dispatch_sigprocmask(SIG_SETMASK, &g_dispatch_saved_mask, NULL,
                                 DISPATCH_STAGE_MASK_RESTORE) != 0) {
            int retry_errno = errno;

            errno = retry_errno;
            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to restore caller signal mask before resuming "
                "deferred signal dispatch");
            errno = retry_errno;
            return -1;
        }
        g_dispatch_mask_restore_pending = false;
    }

    sig = (int)g_pending_signal;
    if (sig == 0) {
        return 0;
    }
    if (dispatch_sigprocmask(SIG_SETMASK, NULL, &caller_mask,
                             DISPATCH_STAGE_MASK_QUERY) != 0) {
        int mask_errno = errno;

        errno = mask_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to capture caller signal mask before "
                         "dispatching deferred signal %d",
                         sig);
        errno = mask_errno;
        return -1;
    }
    /* Restoration is part of dispatch, not a best-effort prelude. Clearing
     * and raising while even one saved disposition remains unrestored can
     * route the signal back through our own handler, return to the caller,
     * and silently discard both the interruption and guard ownership. */
    if (signals_guard_end() != 0) {
        return -1;
    }
    if (sigemptyset(&target_set) != 0 || sigaddset(&target_set, sig) != 0) {
        int mask_errno = errno;

        errno = mask_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to prepare deferred signal %d for dispatch",
                         sig);
        errno = mask_errno;
        return -1;
    }
    if (dispatch_sigprocmask(SIG_UNBLOCK, &target_set, NULL,
                             DISPATCH_STAGE_UNBLOCK) != 0) {
        int mask_errno = errno;

        errno = mask_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to unblock deferred signal %d for dispatch",
                         sig);
        errno = mask_errno;
        return -1;
    }

    /* Keep the library state published throughout synchronous delivery so a
     * returning inherited handler can observe which deferred signal it is
     * handling. With the selected signal unblocked, raise() cannot report
     * successful dispatch merely because the kernel left it pending. */
    raise_rc = dispatch_raise(sig);
    raise_errno = errno;
    if (raise_rc == 0) {
        g_pending_signal = 0;
    }

    if (dispatch_sigprocmask(SIG_SETMASK, &caller_mask, NULL,
                             DISPATCH_STAGE_MASK_RESTORE) != 0) {
        restore_errno = errno;
        g_dispatch_saved_mask = caller_mask;
        g_dispatch_mask_restore_pending = true;
        if (raise_rc != 0) {
            errno = raise_errno;
            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to dispatch deferred signal %d; also failed to "
                "restore the caller signal mask (restore errno=%d)",
                sig, restore_errno);
            errno = raise_errno;
            return -1;
        }

        errno = restore_errno;
        set_system_error(
            ERR_SYSTEM_CALL,
            "Deferred signal %d was delivered, but the caller signal mask "
            "could not be restored",
            sig);
        errno = restore_errno;
        return -1;
    }

    if (raise_rc != 0) {
        errno = raise_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to dispatch deferred signal %d", sig);
        errno = raise_errno;
        return -1;
    }
    return 0;
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
             * truncated path it might unlink. AR-10 L18: the fence makes the
             * copy/publish order a language guarantee instead of an artifact
             * of current codegen — nothing else stops the compiler from
             * sinking the copy past the volatile store. */
            safe_strncpy(g_scratch[i].path, path, sizeof(g_scratch[i].path));
            atomic_signal_fence(memory_order_release);
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
