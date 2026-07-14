/* AR-07 T17: signal-inheritance, runtime-lock diagnostic, and log-label
 * regressions. */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "error.h"
#include "signals.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const int guarded_signals[] = {SIGINT, SIGTERM, SIGHUP};

static void inherited_caught_handler(int sig) {
    (void)sig;
}

static int set_signal_state(int sig, void (*handler)(int), bool blocked) {
    struct sigaction action;
    sigset_t one;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(sig, &action, NULL) != 0) return -1;
    sigemptyset(&one);
    sigaddset(&one, sig);
    return sigprocmask(blocked ? SIG_BLOCK : SIG_UNBLOCK, &one, NULL);
}

static int signal_state_is(int sig, void (*handler)(int), bool blocked) {
    struct sigaction action;
    sigset_t current_mask;

    if (sigaction(sig, NULL, &action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &current_mask) != 0) {
        return -1;
    }
    return action.sa_handler == handler &&
                   (sigismember(&current_mask, sig) == 1) == blocked
               ? 0
               : -1;
}

static int child_dispositions_are(int expected_handler,
                                  bool expected_blocked) {
    sigset_t current_mask;

    if (sigprocmask(SIG_SETMASK, NULL, &current_mask) != 0) return -1;
    for (size_t i = 0;
         i < sizeof(guarded_signals) / sizeof(guarded_signals[0]); i++) {
        struct sigaction action;
        if (sigaction(guarded_signals[i], NULL, &action) != 0) return -1;
        if ((expected_handler == 1 && action.sa_handler != SIG_IGN) ||
            (expected_handler == 0 && action.sa_handler != SIG_DFL) ||
            ((sigismember(&current_mask, guarded_signals[i]) == 1) !=
             expected_blocked)) {
            return -1;
        }
    }
    return 0;
}

TEST(child_reset_preserves_every_inherited_ignore_and_mask) {
    int status = 0;
    pid_t child = fork();

    CHECK(child >= 0);
    if (child == 0) {
        sigset_t blocked;
        sigemptyset(&blocked);
        for (size_t i = 0;
             i < sizeof(guarded_signals) / sizeof(guarded_signals[0]); i++) {
            if (signal(guarded_signals[i], SIG_IGN) == SIG_ERR) _exit(10);
            sigaddset(&blocked, guarded_signals[i]);
        }
        if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) _exit(11);
        if (signals_guard_begin() != 0) _exit(12);
        signals_guard_end();

        /* Pre-fix this reset all three to SIG_DFL and unblocked them even
         * though guard_begin deliberately skipped every inherited ignore and
         * guard_end retired the installed-disposition bitmap. */
        signals_reset_for_child(NULL);
        _exit(child_dispositions_are(1, true) == 0 ? 0 : 13);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(child_reset_defaults_and_unblocks_only_installed_handlers) {
    int status = 0;
    pid_t child = fork();

    CHECK(child >= 0);
    if (child == 0) {
        sigset_t blocked;
        sigemptyset(&blocked);
        for (size_t i = 0;
             i < sizeof(guarded_signals) / sizeof(guarded_signals[0]); i++) {
            if (signal(guarded_signals[i], SIG_DFL) == SIG_ERR) _exit(20);
            sigaddset(&blocked, guarded_signals[i]);
        }
        if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) _exit(21);
        if (signals_guard_begin() != 0) _exit(22);
        signals_reset_for_child(NULL);
        _exit(child_dispositions_are(0, false) == 0 ? 0 : 23);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

/* Uniform all-ignore/all-default fixtures catch the original reset-all bug,
 * but a broken global "if any signal is ignored, skip everything" repair could
 * still pass both. Keep ignored, inherited-caught, and default dispositions in
 * the same child so the installed bitmap must be correct per signal. */
TEST(child_reset_handles_mixed_ignored_caught_and_default_dispositions) {
    int status = 0;
    pid_t child = fork();

    CHECK(child >= 0);
    if (child == 0) {
        if (set_signal_state(SIGHUP, SIG_IGN, true) != 0) _exit(30);
        if (set_signal_state(SIGINT, inherited_caught_handler, true) != 0) {
            _exit(31);
        }
        if (set_signal_state(SIGTERM, SIG_DFL, true) != 0) _exit(32);
        if (signals_guard_begin() != 0) _exit(33);

        signals_reset_for_child(NULL);
        if (signal_state_is(SIGHUP, SIG_IGN, true) != 0) _exit(34);
        if (signal_state_is(SIGINT, SIG_DFL, false) != 0) _exit(35);
        if (signal_state_is(SIGTERM, SIG_DFL, false) != 0) _exit(36);
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

/* guard_end() restores only handlers guard_begin() replaced and retires the
 * installed bitmap. A later child reset must therefore be a no-op: it must not
 * resurrect an inherited ignore, erase an outer caught handler, or alter the
 * caller's original masks. */
TEST(child_reset_after_guard_end_preserves_original_dispositions_and_masks) {
    int status = 0;
    pid_t child = fork();

    CHECK(child >= 0);
    if (child == 0) {
        if (set_signal_state(SIGHUP, SIG_IGN, true) != 0) _exit(40);
        if (set_signal_state(SIGINT, inherited_caught_handler, false) != 0) {
            _exit(41);
        }
        if (set_signal_state(SIGTERM, SIG_DFL, true) != 0) _exit(42);
        if (signals_guard_begin() != 0) _exit(43);
        signals_guard_end();
        signals_reset_for_child(NULL);

        if (signal_state_is(SIGHUP, SIG_IGN, true) != 0) _exit(44);
        if (signal_state_is(SIGINT, inherited_caught_handler, false) != 0) {
            _exit(45);
        }
        if (signal_state_is(SIGTERM, SIG_DFL, true) != 0) _exit(46);
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

/* AR-10 L17: a guarded signal the SUPERVISOR blocked before gitswitch ran
 * must stay blocked in the exec'd child. Passing the pre-spawn mask restores
 * the exact inherited mask; the old unconditional unblock stripped it. */
TEST(child_reset_restores_supervisor_blocked_mask_exactly) {
    int status = 0;
    pid_t child = fork();

    CHECK(child >= 0);
    if (child == 0) {
        sigset_t supervisor;
        sigset_t pre_spawn;
        sigset_t current;

        sigemptyset(&supervisor);
        sigaddset(&supervisor, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &supervisor, NULL) != 0) _exit(50);
        if (signals_guard_begin() != 0) _exit(51);
        if (signals_block_for_child_spawn(&pre_spawn) != 0) _exit(52);
        /* (fork of the helper would happen here) */
        signals_reset_for_child(&pre_spawn);
        if (sigprocmask(SIG_SETMASK, NULL, &current) != 0) _exit(53);
        if (!sigismember(&current, SIGTERM)) _exit(54);
        if (sigismember(&current, SIGINT)) _exit(55);
        if (sigismember(&current, SIGHUP)) _exit(56);
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

static int read_log(FILE *stream, char *buffer, size_t size) {
    long length;

    if (!stream || !buffer || size == 0 || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_END) != 0) {
        return -1;
    }
    length = ftell(stream);
    if (length < 0 || (size_t)length >= size ||
        fseek(stream, 0, SEEK_SET) != 0) {
        return -1;
    }
    if (fread(buffer, 1, (size_t)length, stream) != (size_t)length) {
        return -1;
    }
    buffer[length] = '\0';
    return 0;
}

typedef struct {
    char root[MAX_PATH_LEN];
    char xdg[MAX_PATH_LEN];
    char child[MAX_PATH_LEN];
    char moved_parent[MAX_PATH_LEN];
    char moved_child[MAX_PATH_LEN];
    char *saved_xdg;
    bool had_xdg;
    bool environment_changed;
    FILE *capture;
    FILE *saved_log_file;
    bool saved_log_to_stderr;
    log_level_t saved_log_level;
    int lock_fd;
} runtime_lock_fixture_t;

static int copy_environment_value(const char *name, char **value,
                                  bool *present) {
    const char *current = getenv(name);

    *value = NULL;
    *present = current != NULL;
    if (!current) return 0;
    size_t length = strlen(current) + 1;
    *value = malloc(length);
    if (!*value) return -1;
    memcpy(*value, current, length);
    return 0;
}

static int runtime_lock_fixture_restore_environment(
    runtime_lock_fixture_t *fixture) {
    int rc;

    if (!fixture->environment_changed) return 0;
    rc = fixture->had_xdg
             ? setenv("XDG_RUNTIME_DIR", fixture->saved_xdg, 1)
             : unsetenv("XDG_RUNTIME_DIR");
    fixture->environment_changed = false;
    return rc;
}

static int runtime_lock_fixture_begin(runtime_lock_fixture_t *fixture) {
    int written;

    memset(fixture, 0, sizeof(*fixture));
    fixture->lock_fd = -1;
    if (copy_environment_value("XDG_RUNTIME_DIR", &fixture->saved_xdg,
                               &fixture->had_xdg) != 0) {
        return -1;
    }
    if (safe_strncpy(fixture->root, "/tmp/gitswitch-ar07-lock.XXXXXX",
                     sizeof(fixture->root)) != 0 ||
        !ts_mkdtemp(fixture->root)) {
        free(fixture->saved_xdg);
        fixture->saved_xdg = NULL;
        return -1;
    }
    written = snprintf(fixture->xdg, sizeof(fixture->xdg), "%s/xdg",
                       fixture->root);
    if (written < 0 || (size_t)written >= sizeof(fixture->xdg) ||
        mkdir(fixture->xdg, 0700) != 0 || chmod(fixture->xdg, 0700) != 0) {
        free(fixture->saved_xdg);
        fixture->saved_xdg = NULL;
        return -1;
    }
    written = snprintf(fixture->child, sizeof(fixture->child),
                       "%s/gitswitch-runtime", fixture->xdg);
    if (written < 0 || (size_t)written >= sizeof(fixture->child)) goto fail;
    written = snprintf(fixture->moved_parent,
                       sizeof(fixture->moved_parent), "%s/xdg-moved",
                       fixture->root);
    if (written < 0 ||
        (size_t)written >= sizeof(fixture->moved_parent)) goto fail;
    written = snprintf(fixture->moved_child, sizeof(fixture->moved_child),
                       "%s/gitswitch-runtime-moved", fixture->xdg);
    if (written < 0 ||
        (size_t)written >= sizeof(fixture->moved_child)) goto fail;
    if (setenv("XDG_RUNTIME_DIR", fixture->xdg, 1) != 0) goto fail;
    fixture->environment_changed = true;

    fixture->capture = tmpfile();
    if (!fixture->capture) goto fail;
    fixture->saved_log_file = g_log_file;
    fixture->saved_log_to_stderr = g_log_to_stderr;
    fixture->saved_log_level = g_log_level;
    g_log_file = fixture->capture;
    g_log_to_stderr = false;
    g_log_level = LOG_LEVEL_DEBUG;
    return 0;

fail:
    (void)runtime_lock_fixture_restore_environment(fixture);
    free(fixture->saved_xdg);
    fixture->saved_xdg = NULL;
    return -1;
}

static int runtime_lock_fixture_acquire(runtime_lock_fixture_t *fixture) {
    fixture->lock_fd = runtime_state_lock_acquire();
    return fixture->lock_fd >= 0 ? 0 : -1;
}

static void runtime_lock_fixture_release(runtime_lock_fixture_t *fixture) {
    if (fixture->lock_fd >= 0) {
        runtime_state_lock_release(fixture->lock_fd);
        fixture->lock_fd = -1;
    }
}

static int runtime_lock_fixture_reacquire(runtime_lock_fixture_t *fixture) {
    if (runtime_lock_fixture_acquire(fixture) != 0) return -1;
    runtime_lock_fixture_release(fixture);
    return 0;
}

static int runtime_lock_fixture_reset_log(runtime_lock_fixture_t *fixture) {
    if (!fixture->capture || fflush(fixture->capture) != 0 ||
        ftruncate(fileno(fixture->capture), 0) != 0 ||
        fseek(fixture->capture, 0, SEEK_SET) != 0) {
        return -1;
    }
    clearerr(fixture->capture);
    return 0;
}

static int runtime_lock_fixture_end(runtime_lock_fixture_t *fixture) {
    int rc;

    runtime_lock_test_fail_release_stat(RUNTIME_LOCK_RELEASE_STAT_NONE, 0);
    runtime_lock_fixture_release(fixture);
    if (fixture->capture) {
        g_log_file = fixture->saved_log_file;
        g_log_to_stderr = fixture->saved_log_to_stderr;
        g_log_level = fixture->saved_log_level;
        fclose(fixture->capture);
        fixture->capture = NULL;
    }
    rc = runtime_lock_fixture_restore_environment(fixture);
    free(fixture->saved_xdg);
    fixture->saved_xdg = NULL;
    return rc;
}

TEST(every_release_stat_failure_is_distinct_and_release_still_works) {
    static const struct {
        runtime_lock_release_stat_probe_t probe;
        int error;
        const char *subject;
        const char *kind;
    } cases[] = {
        {RUNTIME_LOCK_RELEASE_STAT_PINNED_PARENT, EBADF,
         "runtime lock pinned parent", "could not be inspected"},
        {RUNTIME_LOCK_RELEASE_STAT_NAMED_PARENT, ENOENT,
         "runtime lock named parent", "disappeared"},
        {RUNTIME_LOCK_RELEASE_STAT_PINNED_DIRECTORY, EIO,
         "runtime lock pinned directory", "could not be inspected"},
        {RUNTIME_LOCK_RELEASE_STAT_NAMED_DIRECTORY, EACCES,
         "runtime lock named directory", "became inaccessible"}
    };
    runtime_lock_fixture_t fixture;
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char errno_text[32];

        CHECK_EQ_INT(runtime_lock_fixture_reset_log(&fixture), 0);
        if (runtime_lock_fixture_acquire(&fixture) != 0) {
            CHECK(false);
            break;
        }
        runtime_lock_test_fail_release_stat(cases[i].probe, cases[i].error);
        runtime_lock_fixture_release(&fixture);
        output[0] = '\0';
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        snprintf(errno_text, sizeof(errno_text), "(errno=%d)",
                 cases[i].error);
        CHECK(strstr(output, cases[i].subject) != NULL);
        CHECK(strstr(output, cases[i].kind) != NULL);
        CHECK(strstr(output, errno_text) != NULL);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
    }
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(renamed_runtime_parent_reports_disappearance_and_releases) {
    runtime_lock_fixture_t fixture;
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;
    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        CHECK_EQ_INT(rename(fixture.xdg, fixture.moved_parent), 0);
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named parent") != NULL);
        CHECK(strstr(output, "disappeared during release") != NULL);
        CHECK_EQ_INT(rename(fixture.moved_parent, fixture.xdg), 0);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
    }
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(renamed_runtime_directory_reports_disappearance_and_releases) {
    runtime_lock_fixture_t fixture;
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;
    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        CHECK_EQ_INT(rename(fixture.child, fixture.moved_child), 0);
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named directory") != NULL);
        CHECK(strstr(output, "disappeared during release") != NULL);
        CHECK_EQ_INT(rename(fixture.moved_child, fixture.child), 0);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
    }
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(removed_runtime_directory_reports_disappearance_and_releases) {
    runtime_lock_fixture_t fixture;
    char lock_path[MAX_PATH_LEN];
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;
    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        int written = snprintf(lock_path, sizeof(lock_path), "%s/.lock",
                               fixture.child);
        CHECK(written >= 0 && (size_t)written < sizeof(lock_path));
        if (written >= 0 && (size_t)written < sizeof(lock_path)) {
            CHECK_EQ_INT(unlink(lock_path), 0);
            CHECK_EQ_INT(rmdir(fixture.child), 0);
        }
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named directory") != NULL);
        CHECK(strstr(output, "disappeared during release") != NULL);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
    }
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(inaccessible_runtime_parent_reports_permission_failure_and_releases) {
    runtime_lock_fixture_t fixture;
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;
    if (geteuid() == 0) {
        /* The injected matrix above remains authoritative for EACCES when a
         * privileged test runner bypasses search-permission checks. */
        CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
        TS_SKIP("unprivileged",
                "search-permission denial is ineffective as root");
    }
    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        CHECK_EQ_INT(chmod(fixture.root, 0000), 0);
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(chmod(fixture.root, 0700), 0);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named parent") != NULL);
        CHECK(strstr(output, "became inaccessible during release") != NULL);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
    }
    (void)chmod(fixture.root, 0700);
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(replaced_runtime_parent_and_directory_are_reported_separately) {
    runtime_lock_fixture_t fixture;
    char output[8192] = "";
    int begin_rc = runtime_lock_fixture_begin(&fixture);

    CHECK_EQ_INT(begin_rc, 0);
    if (begin_rc != 0) return;

    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        CHECK_EQ_INT(rename(fixture.child, fixture.moved_child), 0);
        CHECK_EQ_INT(mkdir(fixture.child, 0700), 0);
        CHECK_EQ_INT(chmod(fixture.child, 0700), 0);
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named directory") != NULL);
        CHECK(strstr(output, "was replaced during the critical section") !=
              NULL);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
        ts_rm_rf(fixture.child);
        CHECK_EQ_INT(rename(fixture.moved_child, fixture.child), 0);
    }

    CHECK_EQ_INT(runtime_lock_fixture_reset_log(&fixture), 0);
    CHECK_EQ_INT(runtime_lock_fixture_acquire(&fixture), 0);
    if (fixture.lock_fd >= 0) {
        CHECK_EQ_INT(rename(fixture.xdg, fixture.moved_parent), 0);
        CHECK_EQ_INT(mkdir(fixture.xdg, 0700), 0);
        CHECK_EQ_INT(chmod(fixture.xdg, 0700), 0);
        runtime_lock_fixture_release(&fixture);
        CHECK_EQ_INT(read_log(fixture.capture, output, sizeof(output)), 0);
        CHECK(strstr(output, "runtime lock named parent") != NULL);
        CHECK(strstr(output, "was replaced during the critical section") !=
              NULL);
        CHECK_EQ_INT(runtime_lock_fixture_reacquire(&fixture), 0);
        ts_rm_rf(fixture.xdg);
        CHECK_EQ_INT(rename(fixture.moved_parent, fixture.xdg), 0);
    }
    CHECK_EQ_INT(runtime_lock_fixture_end(&fixture), 0);
}

TEST(every_log_level_has_a_bounded_exact_label) {
    static const char *const labels[] = {
        "DEBUG", "INFO", "WARN", "ERROR", "CRIT"
    };
    char output[8192] = "";
    FILE *capture = tmpfile();
    FILE *saved_log_file = g_log_file;
    bool saved_log_to_stderr = g_log_to_stderr;
    log_level_t saved_log_level = g_log_level;

    CHECK(capture != NULL);
    if (!capture) return;
    g_log_file = capture;
    g_log_to_stderr = false;
    g_log_level = LOG_LEVEL_DEBUG;

    for (int level = LOG_LEVEL_DEBUG; level <= LOG_LEVEL_CRITICAL; level++) {
        log_message((log_level_t)level, "diagnostic.c", level, "probe",
                    "level-%d", level);
    }
    log_message((log_level_t)(LOG_LEVEL_DEBUG - 1),
                "diagnostic.c", 90, "probe", "below-range");
    log_message((log_level_t)(LOG_LEVEL_CRITICAL + 1),
                "diagnostic.c", 91, "probe", "above-range");

    CHECK_EQ_INT(read_log(capture, output, sizeof(output)), 0);
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        char expected[64];
        snprintf(expected, sizeof(expected), "] %s diagnostic.c:%zu ",
                 labels[i], i);
        CHECK(strstr(output, expected) != NULL);
    }
    CHECK(strstr(output,
                 "] UNKNOWN diagnostic.c:90 (probe) - below-range") != NULL);
    CHECK(strstr(output,
                 "] UNKNOWN diagnostic.c:91 (probe) - above-range") != NULL);

    fclose(capture);
    g_log_file = saved_log_file;
    g_log_to_stderr = saved_log_to_stderr;
    g_log_level = saved_log_level;
}

TEST_MAIN_BEGIN()
    RUN_TEST(child_reset_preserves_every_inherited_ignore_and_mask);
    RUN_TEST(child_reset_defaults_and_unblocks_only_installed_handlers);
    RUN_TEST(child_reset_handles_mixed_ignored_caught_and_default_dispositions);
    RUN_TEST(child_reset_after_guard_end_preserves_original_dispositions_and_masks);
    RUN_TEST(child_reset_restores_supervisor_blocked_mask_exactly);
    RUN_TEST(every_release_stat_failure_is_distinct_and_release_still_works);
    RUN_TEST(renamed_runtime_parent_reports_disappearance_and_releases);
    RUN_TEST(renamed_runtime_directory_reports_disappearance_and_releases);
    RUN_TEST(removed_runtime_directory_reports_disappearance_and_releases);
    RUN_TEST(inaccessible_runtime_parent_reports_permission_failure_and_releases);
    RUN_TEST(replaced_runtime_parent_and_directory_are_reported_separately);
    RUN_TEST(every_log_level_has_a_bounded_exact_label);
TEST_MAIN_END()
