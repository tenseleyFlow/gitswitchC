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

static const int test_guarded_signals[] = { SIGINT, SIGTERM, SIGHUP };
#define TEST_GUARDED_SIGNAL_COUNT \
    (sizeof(test_guarded_signals) / sizeof(test_guarded_signals[0]))

static void inherited_test_handler(int signal_number) {
    (void)signal_number;
}

/* struct sigaction can contain implementation padding/restorer fields, so
 * compare every disposition property controlled by this suite rather than
 * byte-comparing the object representation. */
static bool test_actions_equal(const struct sigaction *left,
                               const struct sigaction *right) {
    static const int mask_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, SIGALRM
    };

    if (left->sa_handler != right->sa_handler ||
        left->sa_flags != right->sa_flags) {
        return false;
    }
    for (size_t i = 0; i < sizeof(mask_signals) / sizeof(mask_signals[0]); i++) {
        if (sigismember(&left->sa_mask, mask_signals[i]) !=
            sigismember(&right->sa_mask, mask_signals[i])) {
            return false;
        }
    }
    return true;
}

static void install_distinct_test_actions(struct sigaction *observed) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = inherited_test_handler;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
        sigaddset(&action.sa_mask,
                  test_guarded_signals[(i + 1) % TEST_GUARDED_SIGNAL_COUNT]);
        action.sa_flags = i == 1 ? SA_RESTART : 0;
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], &action, NULL), 0);
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &observed[i]), 0);
    }
}

static void restore_test_actions(const struct sigaction *actions) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], &actions[i], NULL), 0);
    }
}

static void check_current_actions(const struct sigaction *expected) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        struct sigaction current;
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &current), 0);
        CHECK(test_actions_equal(&current, &expected[i]));
    }
}

/* AR-08 M22: every query/install position is a transactional boundary.  A
 * failure must restore every earlier disposition before returning, retain the
 * originating errno/error context, and leave the guard retryable. */
TEST(guard_begin_failures_restore_every_disposition) {
    static const signals_test_sigaction_stage_t stages[] = {
        SIGNALS_TEST_SIGACTION_QUERY,
        SIGNALS_TEST_SIGACTION_INSTALL
    };
    static const char *stage_names[] = { "query", "install" };
    struct sigaction original[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction baseline[TEST_GUARDED_SIGNAL_COUNT];

    signals_guard_end();
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &original[i]), 0);
    }
    install_distinct_test_actions(baseline);

    for (size_t stage = 0; stage < sizeof(stages) / sizeof(stages[0]); stage++) {
        for (size_t target = 0; target < TEST_GUARDED_SIGNAL_COUNT; target++) {
            char signal_text[32];
            int injected_errno = stage == 0 ? EIO : EPERM;

            clear_error();
            errno = 0;
            signals_test_fail_sigaction(test_guarded_signals[target],
                                        stages[stage], injected_errno);
            int rc = signals_guard_begin();
            int returned_errno = errno;
            error_context_t failure = *get_last_error();

            CHECK_EQ_INT(rc, -1);
            CHECK_EQ_INT(returned_errno, injected_errno);
            CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
            CHECK_EQ_INT(failure.system_errno, injected_errno);
            CHECK(strstr(failure.message, stage_names[stage]) != NULL);
            snprintf(signal_text, sizeof(signal_text), "%d",
                     test_guarded_signals[target]);
            CHECK(strstr(failure.message, signal_text) != NULL);

            /* This check deliberately precedes guard_end(): begin itself, not
             * eventual caller cleanup, owns the transactional restoration. */
            check_current_actions(baseline);
            signals_guard_end(); /* also repairs the pre-fix implementation */
            signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
            check_current_actions(baseline);

            clear_error();
            CHECK_EQ_INT(signals_guard_begin(), 0);
            signals_guard_end();
            check_current_actions(baseline);
        }
    }

    restore_test_actions(original);
}

/* A restoration error is a third state, not an active guard.  Retain the
 * exact failed entry, reject every begin that encounters or repairs that
 * partial state, and allow only a later clean begin to report success. */
TEST(guard_begin_never_reports_restore_pending_as_active) {
    struct sigaction original[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction baseline[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction current;
    error_context_t failure;
    int rc;

    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &original[i]), 0);
    }
    install_distinct_test_actions(baseline);

    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_INSTALL,
                                EPERM);
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
    clear_error();
    errno = 0;
    rc = signals_guard_begin();
    failure = *get_last_error();
    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, EPERM);
    CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(failure.system_errno, EPERM);
    CHECK(strstr(failure.message, "also failed to restore") != NULL);
    CHECK_EQ_INT(sigaction(SIGINT, NULL, &current), 0);
    CHECK(!test_actions_equal(&current, &baseline[0]));

    /* A second restoration failure must remain pending, not get erased by
     * begin's idempotent-active fast path. */
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE,
                                EAGAIN);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(signals_guard_begin(), -1);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK_EQ_INT(sigaction(SIGINT, NULL, &current), 0);
    CHECK(!test_actions_equal(&current, &baseline[0]));

    /* The next call repairs the retained entry but still cannot claim this
     * dirty entry as a successful begin.  Only a fresh retry may activate. */
    clear_error();
    errno = 0;
    CHECK_EQ_INT(signals_guard_begin(), -1);
    CHECK_EQ_INT(errno, EBUSY);
    check_current_actions(baseline);
    CHECK_EQ_INT(signals_guard_begin(), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    check_current_actions(baseline);

    restore_test_actions(original);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

/* guard_end has the same fail-closed retry contract: restore what it can,
 * retain only failed entries, and report failure until the last one is back. */
TEST(guard_end_retains_failed_restoration_for_retry) {
    struct sigaction original[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction baseline[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction current;

    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &original[i]), 0);
    }
    install_distinct_test_actions(baseline);
    CHECK_EQ_INT(signals_guard_begin(), 0);

    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
    errno = 0;
    CHECK_EQ_INT(signals_guard_end(), -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(sigaction(SIGTERM, NULL, &current), 0);
    CHECK(!test_actions_equal(&current, &baseline[1]));

    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE,
                                EAGAIN);
    errno = 0;
    CHECK_EQ_INT(signals_guard_end(), -1);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK_EQ_INT(sigaction(SIGTERM, NULL, &current), 0);
    CHECK(!test_actions_equal(&current, &baseline[1]));

    CHECK_EQ_INT(signals_guard_end(), 0);
    check_current_actions(baseline);
    restore_test_actions(original);
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

/* SIG_IGN is the sole non-error skip.  Arm an install failure for each
 * ignored signal: success proves begin never attempted that installation,
 * while exact post-end comparison proves the inherited action survived. */
TEST(guard_begin_skips_only_inherited_sig_ign) {
    struct sigaction original[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction baseline[TEST_GUARDED_SIGNAL_COUNT];

    signals_guard_end();
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &original[i]), 0);
    }
    install_distinct_test_actions(baseline);

    for (size_t target = 0; target < TEST_GUARDED_SIGNAL_COUNT; target++) {
        struct sigaction ignored;
        struct sigaction before[TEST_GUARDED_SIGNAL_COUNT];
        struct sigaction during;

        restore_test_actions(baseline);
        memset(&ignored, 0, sizeof(ignored));
        ignored.sa_handler = SIG_IGN;
        sigemptyset(&ignored.sa_mask);
        sigaddset(&ignored.sa_mask, SIGUSR1);
        ignored.sa_flags = SA_RESTART;
        CHECK_EQ_INT(sigaction(test_guarded_signals[target], &ignored, NULL), 0);
        for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
            CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &before[i]), 0);
        }

        signals_test_fail_sigaction(test_guarded_signals[target],
                                    SIGNALS_TEST_SIGACTION_INSTALL, EIO);
        CHECK_EQ_INT(signals_guard_begin(), 0);
        CHECK_EQ_INT(sigaction(test_guarded_signals[target], NULL, &during), 0);
        CHECK(during.sa_handler == SIG_IGN);
        signals_guard_end();
        signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
        check_current_actions(before);
    }

    restore_test_actions(original);
}

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
    RUN_TEST(guard_begin_failures_restore_every_disposition);
    RUN_TEST(guard_begin_never_reports_restore_pending_as_active);
    RUN_TEST(guard_end_retains_failed_restoration_for_retry);
    RUN_TEST(guard_begin_skips_only_inherited_sig_ign);
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
