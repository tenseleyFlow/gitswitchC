/* Tests for the switch-window signal guard (SIG-01) and the scratch-file
 * registry (SIG-02). Death-by-signal behaviors are exercised in forked
 * children so the harness process survives to report. */

/* Enable POSIX extensions for sigaction/fork/kill */
#define _POSIX_C_SOURCE 200809L

#include "test.h"
#include "gitswitch.h"
#include "signals.h"
#include "error.h"
#include "utils.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
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

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(guard_defers_first_signal);
    RUN_TEST(guard_end_restores_default_disposition);
    RUN_TEST(guard_respects_inherited_sig_ign);
    RUN_TEST(scratch_registry_unlinks_registered_paths);
    RUN_TEST(scratch_registry_rejects_invalid);
    RUN_TEST(dispatch_terminates_with_deferred_signal);
    RUN_TEST(second_signal_is_emergency_exit_and_drops_scratch);
TEST_MAIN_END()
