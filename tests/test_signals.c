/* Tests for the switch-window signal guard (SIG-01) and the scratch-file
 * registry (SIG-02). Death-by-signal behaviors are exercised in forked
 * children so the harness process survives to report. */

/* Enable POSIX extensions for sigaction/fork/kill. glibc-only: on macOS and
 * the BSDs the strict macro hides default-namespace declarations (SA_RESTART,
 * mkdtemp) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "gitswitch.h"
#include "signals.h"
#include "error.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A raised SIGINT inside the guard must be recorded, not kill the process —
 * this is the entire SIG-01 mechanism (the mainline rolls back and re-raises). */
TEST(guard_defers_first_signal) {
    signals_guard_begin();
    raise(SIGINT); /* would terminate the process without the guard */
    CHECK(signals_pending());
    CHECK_EQ_INT(signals_pending_signal(), SIGINT);
    signals_guard_end();
}

/* guard_end must put the default disposition back so the rest of the program
 * (and a later dispatch) sees normal signal semantics. */
TEST(guard_end_restores_default_disposition) {
    struct sigaction sa;
    signals_guard_begin();
    CHECK_EQ_INT(sigaction(SIGTERM, NULL, &sa), 0);
    CHECK(sa.sa_handler != SIG_DFL); /* guard handler installed */
    signals_guard_end();
    CHECK_EQ_INT(sigaction(SIGTERM, NULL, &sa), 0);
    CHECK(sa.sa_handler == SIG_DFL);
}

/* An inherited SIG_IGN (nohup ignores SIGHUP) must be preserved: the guard
 * neither overrides it nor records the ignored signal — re-raising it later
 * would resurrect a signal the environment decided must not act. */
TEST(guard_respects_inherited_sig_ign) {
    struct sigaction sa;
    signal(SIGHUP, SIG_IGN);
    signals_guard_begin();
    raise(SIGHUP); /* ignored: must neither kill us nor set pending */
    CHECK(!signals_pending());
    signals_guard_end();
    CHECK_EQ_INT(sigaction(SIGHUP, NULL, &sa), 0);
    CHECK(sa.sa_handler == SIG_IGN);
    signal(SIGHUP, SIG_DFL);
}

/* SIG-02: registered scratch paths are unlinked by cleanup; unregistered ones
 * are left alone. */
TEST(scratch_registry_unlinks_registered_paths) {
    char keep_path[128], drop_path[128];
    snprintf(keep_path, sizeof(keep_path), "/tmp/gsw_scratch_keep.%d", (int)getpid());
    snprintf(drop_path, sizeof(drop_path), "/tmp/gsw_scratch_drop.%d", (int)getpid());

    FILE *f = fopen(keep_path, "w");
    CHECK(f != NULL);
    if (f) fclose(f);
    f = fopen(drop_path, "w");
    CHECK(f != NULL);
    if (f) fclose(f);

    CHECK_EQ_INT(signals_scratch_register(keep_path), 0);
    CHECK_EQ_INT(signals_scratch_register(drop_path), 0);
    signals_scratch_unregister(keep_path);

    signals_scratch_cleanup();
    CHECK(path_exists(keep_path));  /* unregistered: untouched */
    CHECK(!path_exists(drop_path)); /* registered: unlinked */

    unlink(keep_path);
}

/* Registration must fail closed on garbage input. */
TEST(scratch_registry_rejects_invalid) {
    CHECK_EQ_INT(signals_scratch_register(NULL), -1);
    CHECK_EQ_INT(signals_scratch_register(""), -1);
}

/* signals_dispatch_pending must terminate the process with the deferred
 * signal's default action so shells see the 128+N convention. Forked child:
 * exit code 10/11 mark the specific failure mode. */
TEST(dispatch_terminates_with_deferred_signal) {
    int status = 0;
    pid_t pid;

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        signals_guard_begin();
        raise(SIGTERM);
        if (!signals_pending()) _exit(10); /* guard failed to defer */
        signals_dispatch_pending();        /* must not return */
        _exit(11);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
}

/* A second signal while one is pending is the emergency exit: the handler
 * unlinks registered scratch files (SIG-02) and dies immediately with the
 * signal's default action. */
TEST(second_signal_is_emergency_exit_and_drops_scratch) {
    char scratch[128];
    int status = 0;
    pid_t pid;
    FILE *f;

    snprintf(scratch, sizeof(scratch), "/tmp/gsw_scratch_emerg.%d", (int)getpid());
    f = fopen(scratch, "w");
    CHECK(f != NULL);
    if (f) fclose(f);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        signals_scratch_register(scratch);
        signals_guard_begin();
        raise(SIGINT);
        if (!signals_pending()) _exit(10); /* first signal must defer */
        raise(SIGINT);                     /* second: must terminate NOW */
        _exit(11);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);
    CHECK(!path_exists(scratch)); /* handler unlinked it before dying */

    unlink(scratch); /* in case the child failed */
}

/* AR-02 #2: a second signal arriving while the failed-switch ROLLBACK is
 * running must NOT take the emergency exit — dying mid-git_config_restore
 * persists the aborted account's identity. Inside the rollback window the
 * signal stays deferred; once the window closes the mainline dispatches it
 * with the correct death-by-signal status. Exit code 10/11/12 mark the
 * specific failure mode. */
TEST(second_signal_during_rollback_is_deferred) {
    char marker[128];
    int status = 0;
    pid_t pid;

    /* Stands in for "the rest of git_config_restore": pre-fix the child died
     * at the second raise and never created it; post-fix the whole window
     * completes first, so the marker must exist. */
    snprintf(marker, sizeof(marker), "/tmp/gsw_rollback_done.%d", (int)getpid());
    unlink(marker);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        FILE *f;
        signals_guard_begin();
        raise(SIGINT);                     /* the signal that aborted the switch */
        if (!signals_pending()) _exit(10); /* first signal must defer */
        signals_rollback_begin();
        raise(SIGINT);                     /* second: pre-fix this killed us HERE */
        if (!signals_pending()) _exit(11); /* must still be recorded, not lost */
        f = fopen(marker, "w");            /* "restore completed" evidence */
        if (f) fclose(f);
        signals_rollback_end();
        signals_dispatch_pending();        /* rollback done: now die correctly */
        _exit(12);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));            /* still reports death-by-signal */
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);
    CHECK(path_exists(marker));            /* ...but only AFTER the window closed */

    unlink(marker);
}

/* Reap `pid` with a deadline. Returns true and fills *status if it exited
 * within `budget_ms`; on timeout SIGKILLs it (and reaps) and returns false.
 * The L8 tests need this: the pre-fix failure mode is precisely "unkillable
 * until SIGKILL", which would otherwise hang the harness for the full length
 * of the blocking grandchild's sleep. */
static bool wait_child_bounded(pid_t pid, int *status, int budget_ms) {
    int waited = 0;
    while (waited < budget_ms) {
        pid_t w = waitpid(pid, status, WNOHANG);
        if (w == pid) return true;
        if (w < 0 && errno != EINTR) break;
        struct timespec ts = { 0, 50 * 1000 * 1000 }; /* 50 ms */
        nanosleep(&ts, NULL);
        waited += 50;
    }
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, status, 0);
    return false;
}

/* AR-03 L8: a targeted SIGTERM arriving while the rollback window is blocked
 * on a child must not be deferred forever. The child process simulates the
 * wedged rollback: first signal pending, rollback window open, run_argv
 * blocked in waitpid() on an exec'd `sleep 30` (default dispositions, like a
 * real ssh-add; a process-targeted kill never reaches it via the TTY group).
 * The harness delivers the second, targeted SIGTERM: the handler must forward
 * it to the published child pid so the rollback PROCEEDS to completion (the
 * marker file — AR-02 #2 stays intact) and the process then dies by the
 * deferred signal. Pre-fix the second signal was swallowed and the child sat
 * in waitpid for the full 30 s — the bounded reaper turns that into a FAIL
 * instead of a hang. Exit codes 10-15 mark the specific failure mode. */
TEST(second_signal_during_rollback_kills_blocking_child) {
    char marker[128], b;
    int status = 0, sync[2];
    pid_t pid;
    bool exited;

    snprintf(marker, sizeof(marker), "/tmp/gsw_rollback_unblocked.%d", (int)getpid());
    unlink(marker);
    /* Exec barrier: the write end is CLOEXEC, so the harness's read() below
     * sees EOF exactly when the grandchild's exec has replaced the inherited
     * guard handler with default dispositions. Signaling before that point
     * would be swallowed by the grandchild's inherited rollback deferral —
     * a fork-to-exec window that is microseconds in run_argv but must not
     * flake the test. */
    CHECK_EQ_INT(pipe(sync), 0);
    CHECK(fcntl(sync[1], F_SETFD, FD_CLOEXEC) == 0);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pid_t child, w;
        int cst = 0;
        FILE *f;

        close(sync[0]);
        signals_guard_begin();
        raise(SIGTERM);                    /* the signal that aborted the switch */
        if (!signals_pending()) _exit(10);
        signals_rollback_begin();

        /* Stand-in for the rollback's interactive ssh-add: exec resets it to
         * default dispositions, and it outlives the whole test budget. */
        child = fork();
        if (child < 0) _exit(13);
        if (child == 0) {
            execlp("sleep", "sleep", "30", (char *)NULL);
            _exit(127);
        }
        signals_child_spawned(child);
        close(sync[1]); /* grandchild's CLOEXEC copy is now the last writer */

        /* run_argv's blocking reap — pre-fix, stuck here for 30 s. */
        do { w = waitpid(child, &cst, 0); } while (w < 0 && errno == EINTR);
        signals_child_reaped();
        if (w != child) _exit(14);
        /* The handler must have forwarded OUR signal, not something else. */
        if (!WIFSIGNALED(cst) || WTERMSIG(cst) != SIGTERM) _exit(15);
        if (!signals_pending()) _exit(11); /* deferred signal must survive */

        f = fopen(marker, "w");            /* "rollback ran to completion" */
        if (f) fclose(f);
        signals_rollback_end();
        signals_dispatch_pending();        /* rollback done: die correctly */
        _exit(12);
    }

    close(sync[1]);
    CHECK_EQ_INT((int)read(sync[0], &b, 1), 0); /* EOF: sleep is exec'd */
    close(sync[0]);
    CHECK_EQ_INT(kill(pid, SIGTERM), 0);   /* the targeted second signal */

    exited = wait_child_bounded(pid, &status, 8000);
    CHECK(exited);                          /* pre-fix: deferred forever */
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
    CHECK(path_exists(marker));             /* restore finished BEFORE dying */

    unlink(marker);
}

/* L8 escalation: if the published child ignores the forwarded signal (a
 * wrapper that traps SIGTERM), a repeat signal against the SAME child must
 * escalate to SIGKILL rather than politely re-forwarding forever. The
 * grandchild here skips exec and sets SIGTERM to SIG_IGN before blocking. */
TEST(rollback_child_kill_escalates_to_sigkill) {
    int status = 0, sync[2];
    pid_t pid;
    bool exited;

    CHECK_EQ_INT(pipe(sync), 0);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pid_t child, w;
        int cst = 0;

        close(sync[0]);
        signals_guard_begin();
        raise(SIGTERM);
        if (!signals_pending()) _exit(10);
        signals_rollback_begin();

        child = fork();
        if (child < 0) _exit(13);
        if (child == 0) {
            /* No exec, so shed the inherited guard handler explicitly, then
             * ignore the polite signal — only SIGKILL ends this early. The
             * lifetime is BOUNDED (not an infinite pause loop) so a
             * regression that stops the escalation leaks this process for
             * 30 s at most instead of wedging the harness's output pipe. */
            signal(SIGINT, SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            signal(SIGTERM, SIG_IGN);
            sleep(30); /* an ignored SIGTERM does not even interrupt this */
            _exit(0);
        }
        signals_child_spawned(child);
        (void)!write(sync[1], "r", 1);
        close(sync[1]);

        do { w = waitpid(child, &cst, 0); } while (w < 0 && errno == EINTR);
        signals_child_reaped();
        if (w != child) _exit(14);
        if (!WIFSIGNALED(cst) || WTERMSIG(cst) != SIGKILL) _exit(15);

        signals_rollback_end();
        signals_dispatch_pending();
        _exit(12);
    }

    close(sync[1]);
    { char b; CHECK_EQ_INT((int)read(sync[0], &b, 1), 1); }
    close(sync[0]);
    CHECK_EQ_INT(kill(pid, SIGTERM), 0);   /* forwarded politely — ignored */
    {   /* let the first handler pass land before insisting */
        struct timespec ts = { 0, 300 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    CHECK_EQ_INT(kill(pid, SIGTERM), 0);   /* same child still up: SIGKILL */

    exited = wait_child_bounded(pid, &status, 8000);
    CHECK(exited);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(guard_defers_first_signal);
    RUN_TEST(guard_end_restores_default_disposition);
    RUN_TEST(guard_respects_inherited_sig_ign);
    RUN_TEST(scratch_registry_unlinks_registered_paths);
    RUN_TEST(scratch_registry_rejects_invalid);
    RUN_TEST(dispatch_terminates_with_deferred_signal);
    RUN_TEST(second_signal_is_emergency_exit_and_drops_scratch);
    RUN_TEST(second_signal_during_rollback_is_deferred);
    RUN_TEST(second_signal_during_rollback_kills_blocking_child);
    RUN_TEST(rollback_child_kill_escalates_to_sigkill);
TEST_MAIN_END()
