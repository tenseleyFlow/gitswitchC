/* Signal guarding for the account-switch critical section (SIG-01, SIG-02).
 * See signals.h for the design rationale. Everything reachable from the
 * handler is restricted to the POSIX async-signal-safe set: sig_atomic_t
 * stores, unlink(), signal(), raise().
 */

/* glibc wants a POSIX feature macro for sigaction; FreeBSD gates SA_RESTART
 * as an XSI extension that strict _POSIX_C_SOURCE hides, and macOS likewise
 * prunes its default namespace under it — leave those on their fully-visible
 * defaults (the same trap documented in ssh_manager.c). */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

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

/* Nonzero while the mainline is running the failed-switch rollback. The
 * handler's second-signal emergency exit must not fire in that window: dying
 * mid-git_config_restore (up to 12 sequential git execs) persists a chimera
 * identity — the exact half-applied state the rollback exists to undo
 * (AR-02 #2). Set/cleared only in normal context. */
static volatile sig_atomic_t g_rollback_in_progress = 0;

/* Saved dispositions so signals_guard_end() restores exactly what was there
 * (default action, or an outer SIG_IGN we chose not to override). */
static struct sigaction g_saved_actions[GUARDED_SIGNAL_COUNT];
static bool g_action_installed[GUARDED_SIGNAL_COUNT];
static bool g_guard_active = false;

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
    if (g_pending_signal == 0) {
        /* First signal: record it and return. The mainline notices via
         * signals_pending() between durable steps and rolls back in normal
         * context — running git/teardown from here would not be
         * async-signal-safe. */
        g_pending_signal = sig;
        return;
    }

    /* Second signal while the rollback is already running: stay deferred.
     * The emergency exit below would abandon git_config_restore mid-way and
     * permanently leave the aborted account's identity written (AR-02 #2).
     * The rollback is bounded work (a handful of local git execs) and its
     * interactive children (e.g. a re-prompting ssh-add) keep their default
     * dispositions, so Ctrl-C still kills THEM — liveness is preserved
     * without sacrificing restore atomicity. */
    if (g_rollback_in_progress) {
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

void signals_rollback_begin(void) {
    g_rollback_in_progress = 1;
}

void signals_rollback_end(void) {
    g_rollback_in_progress = 0;
}

int signals_guard_begin(void) {
    if (g_guard_active) {
        return 0;
    }

    g_pending_signal = 0;

    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction current, ours;
        g_action_installed[i] = false;

        /* Respect an inherited SIG_IGN (e.g. nohup ignores SIGHUP): the
         * caller's environment already decided this signal must not act, and
         * deferring-then-re-raising it would resurrect it. */
        if (sigaction(g_guarded_signals[i], NULL, &current) != 0 ||
            current.sa_handler == SIG_IGN) {
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

        if (sigaction(g_guarded_signals[i], &ours, &g_saved_actions[i]) == 0) {
            g_action_installed[i] = true;
        }
    }

    g_guard_active = true;
    log_debug("Signal guard installed for switch critical section");
    return 0;
}

void signals_guard_end(void) {
    if (!g_guard_active) {
        return;
    }
    for (size_t i = 0; i < GUARDED_SIGNAL_COUNT; i++) {
        if (g_action_installed[i]) {
            (void)sigaction(g_guarded_signals[i], &g_saved_actions[i], NULL);
            g_action_installed[i] = false;
        }
    }
    g_guard_active = false;
    log_debug("Signal guard removed");
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
