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

/* Every file used to coordinate the signal tests lives below one private,
 * randomized directory.  Keep an open descriptor to that directory so file
 * creation and ordinary cleanup cannot be redirected through a replaced path
 * component.  ts_mkdtemp() also pins the directory for its no-follow atexit
 * sweep, so a preplaced/replacement symlink is unlinked rather than followed. */
static char test_fixture_root[] = "/tmp/gitswitch-signals.XXXXXX";
static int test_fixture_root_fd = -1;

static bool test_fixture_name_is_safe(const char *name) {
    return name && name[0] != '\0' && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static int test_fixture_init(void) {
    struct stat st;

    if (!ts_mkdtemp(test_fixture_root)) return -1;
    test_fixture_root_fd = ts_open_dir_nofollow(test_fixture_root);
    if (test_fixture_root_fd < 0) return -1;
    if (fstat(test_fixture_root_fd, &st) != 0) {
        int saved_errno = errno;
        close(test_fixture_root_fd);
        test_fixture_root_fd = -1;
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0700) {
        close(test_fixture_root_fd);
        test_fixture_root_fd = -1;
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int test_fixture_path(char *path, size_t path_size, const char *name) {
    int written;

    if (!path || path_size == 0 || !test_fixture_name_is_safe(name)) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf(path, path_size, "%s/%s", test_fixture_root, name);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int test_fixture_create(const char *name) {
    int flags = O_WRONLY | O_CREAT | O_EXCL;
    int fd;

    if (test_fixture_root_fd < 0 || !test_fixture_name_is_safe(name)) {
        errno = EINVAL;
        return -1;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = openat(test_fixture_root_fd, name, flags, 0600);
    if (fd < 0) return -1;
#ifndef O_CLOEXEC
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(fd);
        (void)unlinkat(test_fixture_root_fd, name, 0);
        errno = saved_errno;
        return -1;
    }
#endif
    if (close(fd) != 0) {
        int saved_errno = errno;
        (void)unlinkat(test_fixture_root_fd, name, 0);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static bool test_fixture_exists(const char *name) {
    struct stat st;

    return test_fixture_root_fd >= 0 && test_fixture_name_is_safe(name) &&
           fstatat(test_fixture_root_fd, name, &st,
                   AT_SYMLINK_NOFOLLOW) == 0;
}

static void test_fixture_unlink(const char *name) {
    if (test_fixture_root_fd >= 0 && test_fixture_name_is_safe(name)) {
        (void)unlinkat(test_fixture_root_fd, name, 0);
    }
}

static const int test_guarded_signals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT
};
#define TEST_GUARDED_SIGNAL_COUNT \
    (sizeof(test_guarded_signals) / sizeof(test_guarded_signals[0]))

static void inherited_test_handler(int signal_number) {
    (void)signal_number;
}

static volatile sig_atomic_t dispatch_handler_calls;
static volatile sig_atomic_t dispatch_handler_pending;
static volatile sig_atomic_t post_wait_hook_called;
static volatile sig_atomic_t post_wait_hook_guarded_masked;
static volatile sig_atomic_t unrelated_handler_calls;

static void dispatch_observing_handler(int signal_number) {
    (void)signal_number;
    dispatch_handler_calls++;
    dispatch_handler_pending = (sig_atomic_t)signals_pending_signal();
}

static void raise_repeat_signal_at_reap_transition(void) {
    sigset_t current;

    post_wait_hook_called = 1;
    post_wait_hook_guarded_masked =
        sigprocmask(SIG_SETMASK, NULL, &current) == 0 &&
        sigismember(&current, SIGINT) == 1 &&
        sigismember(&current, SIGTERM) == 1 &&
        sigismember(&current, SIGHUP) == 1 &&
        sigismember(&current, SIGQUIT) == 1;
    (void)raise(SIGTERM);
}

static void unrelated_observing_handler(int signal_number) {
    (void)signal_number;
    unrelated_handler_calls++;
}

static bool dispatch_test_masks_equal(const sigset_t *left,
                                      const sigset_t *right) {
    static const int observed_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT,
        SIGUSR1, SIGUSR2, SIGALRM, SIGPIPE, SIGCHLD
    };

    for (size_t i = 0;
         i < sizeof(observed_signals) / sizeof(observed_signals[0]); i++) {
        if (sigismember(left, observed_signals[i]) !=
            sigismember(right, observed_signals[i])) {
            return false;
        }
    }
    return true;
}

static int dispatch_test_install_handler(
    int signal_number, void (*handler)(int), struct sigaction *original) {
    struct sigaction action;

    if (sigaction(signal_number, NULL, original) != 0) return -1;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGUSR2);
    action.sa_flags = SA_RESTART;
    return sigaction(signal_number, &action, NULL);
}

static int dispatch_test_defer(int signal_number) {
    sigset_t target;

    if (sigemptyset(&target) != 0 || sigaddset(&target, signal_number) != 0 ||
        sigprocmask(SIG_UNBLOCK, &target, NULL) != 0) {
        return -1;
    }
    if (signals_guard_begin() != 0 || raise(signal_number) != 0) return -1;
    return signals_pending_signal() == signal_number ? 0 : -1;
}

static void dispatch_test_restore(int signal_number,
                                  const struct sigaction *original_action,
                                  const sigset_t *original_mask) {
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_NONE, 0);
    (void)signals_guard_end();
    (void)sigprocmask(SIG_SETMASK, original_mask, NULL);
    (void)sigaction(signal_number, original_action, NULL);
}

/* struct sigaction can contain implementation padding/restorer fields, so
 * compare every disposition property controlled by this suite rather than
 * byte-comparing the object representation. */
static bool test_actions_equal(const struct sigaction *left,
                               const struct sigaction *right) {
    static const int mask_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM
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

    /* Run the retry contract at every production slot. In particular, the
     * SIGQUIT iteration is a causal mutant check: leaving its guard handler
     * installed after guard_end() differs from baseline and fails here. */
    for (size_t target = 0; target < TEST_GUARDED_SIGNAL_COUNT; target++) {
        int signal_number = test_guarded_signals[target];

        CHECK_EQ_INT(signals_guard_begin(), 0);
        signals_test_fail_sigaction(signal_number,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        errno = 0;
        CHECK_EQ_INT(signals_guard_end(), -1);
        CHECK_EQ_INT(errno, EIO);
        CHECK_EQ_INT(sigaction(signal_number, NULL, &current), 0);
        CHECK(!test_actions_equal(&current, &baseline[target]));

        signals_test_fail_sigaction(signal_number,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EAGAIN);
        errno = 0;
        CHECK_EQ_INT(signals_guard_end(), -1);
        CHECK_EQ_INT(errno, EAGAIN);
        CHECK_EQ_INT(sigaction(signal_number, NULL, &current), 0);
        CHECK(!test_actions_equal(&current, &baseline[target]));

        CHECK_EQ_INT(signals_guard_end(), 0);
        check_current_actions(baseline);
    }
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

/* Every guarded signal must be recorded rather than taking its default action
 * inside the window. Starting the next guard clears the preceding pending
 * value, so each production slot is exercised independently. */
TEST(guard_defers_first_signal) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(signals_guard_begin(), 0);
        CHECK_EQ_INT(raise(test_guarded_signals[i]), 0);
        CHECK(signals_pending());
        CHECK_EQ_INT(signals_pending_signal(), test_guarded_signals[i]);
        CHECK_EQ_INT(signals_guard_end(), 0);
    }
}

/* guard_end must put every default disposition back so the rest of the
 * program (and a later dispatch) sees normal signal semantics. */
TEST(guard_end_restores_default_disposition) {
    struct sigaction original[TEST_GUARDED_SIGNAL_COUNT];
    struct sigaction default_action;
    struct sigaction sa;

    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    sigemptyset(&default_action.sa_mask);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &original[i]), 0);
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], &default_action, NULL),
                     0);
    }

    CHECK_EQ_INT(signals_guard_begin(), 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &sa), 0);
        CHECK(sa.sa_handler != SIG_DFL); /* guard handler installed */
    }
    CHECK_EQ_INT(signals_guard_end(), 0);
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], NULL, &sa), 0);
        CHECK(sa.sa_handler == SIG_DFL);
        CHECK_EQ_INT(sigaction(test_guarded_signals[i], &original[i], NULL), 0);
    }
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

/* AR-08 M23: the fork barrier blocks only dispositions actually installed by
 * the guard. An inherited ignored signal remains untouched, unrelated mask
 * entries survive, and the complete parent mask is restored exactly. */
TEST(child_spawn_barrier_blocks_only_installed_guard_signals) {
    struct sigaction original_hup;
    struct sigaction ignored;
    sigset_t original_mask;
    sigset_t configured_mask;
    sigset_t saved_mask;
    sigset_t during_mask;
    sigset_t restored_mask;

    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK_EQ_INT(sigaction(SIGHUP, NULL, &original_hup), 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    configured_mask = original_mask;
    sigdelset(&configured_mask, SIGINT);
    sigdelset(&configured_mask, SIGTERM);
    sigdelset(&configured_mask, SIGHUP);
    sigdelset(&configured_mask, SIGQUIT);
    sigdelset(&configured_mask, SIGUSR2);
    sigaddset(&configured_mask, SIGUSR1);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &configured_mask, NULL), 0);

    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    CHECK_EQ_INT(sigaction(SIGHUP, &ignored, NULL), 0);
    CHECK_EQ_INT(signals_guard_begin(), 0);
    CHECK_EQ_INT(signals_block_for_child_spawn(&saved_mask), 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &during_mask), 0);
    CHECK_EQ_INT(sigismember(&during_mask, SIGINT), 1);
    CHECK_EQ_INT(sigismember(&during_mask, SIGTERM), 1);
    CHECK_EQ_INT(sigismember(&during_mask, SIGHUP), 0);
    CHECK_EQ_INT(sigismember(&during_mask, SIGQUIT), 1);
    CHECK_EQ_INT(sigismember(&during_mask, SIGUSR1), 1);
    CHECK_EQ_INT(sigismember(&during_mask, SIGUSR2), 0);

    CHECK_EQ_INT(signals_restore_after_child_spawn(&saved_mask), 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &restored_mask), 0);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGINT), 0);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGTERM), 0);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGHUP), 0);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGQUIT), 0);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGUSR1), 1);
    CHECK_EQ_INT(sigismember(&restored_mask, SIGUSR2), 0);

    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK_EQ_INT(sigaction(SIGHUP, &original_hup, NULL), 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &original_mask, NULL), 0);
}

TEST(fixture_root_is_private_and_pinned) {
    struct stat opened;
    struct stat named;

    CHECK(test_fixture_root_fd >= 0);
    CHECK_EQ_INT(fstat(test_fixture_root_fd, &opened), 0);
    CHECK_EQ_INT(lstat(test_fixture_root, &named), 0);
    CHECK(S_ISDIR(opened.st_mode));
    CHECK(S_ISDIR(named.st_mode));
    CHECK_EQ_INT(opened.st_mode & 0777, 0700);
    CHECK(ts_same_identity(&opened, &named));
}

/* SIG-02: registered scratch paths are unlinked by cleanup; unregistered ones
 * are left alone. */
TEST(scratch_registry_unlinks_registered_paths) {
    char keep_path[256], drop_path[256];

    CHECK_EQ_INT(test_fixture_path(keep_path, sizeof(keep_path),
                                   "scratch-keep"), 0);
    CHECK_EQ_INT(test_fixture_path(drop_path, sizeof(drop_path),
                                   "scratch-drop"), 0);
    CHECK_EQ_INT(test_fixture_create("scratch-keep"), 0);
    CHECK_EQ_INT(test_fixture_create("scratch-drop"), 0);

    CHECK_EQ_INT(signals_scratch_register(keep_path), 0);
    CHECK_EQ_INT(signals_scratch_register(drop_path), 0);
    signals_scratch_unregister(keep_path);

    signals_scratch_cleanup();
    CHECK(test_fixture_exists("scratch-keep"));  /* unregistered: untouched */
    CHECK(!test_fixture_exists("scratch-drop")); /* registered: unlinked */

    test_fixture_unlink("scratch-keep");
}

/* A hostile leaf inside the private root must neither be opened for fixture
 * output nor cause scratch cleanup to remove its external target.  O_EXCL
 * makes the creation refusal portable; O_NOFOLLOW adds defense in depth on
 * platforms that provide it. */
TEST(fixture_creation_and_cleanup_do_not_follow_preplaced_symlink) {
    char foreign[] = "/tmp/gitswitch-signals-foreign.XXXXXX";
    char link_path[256];
    char observed[8] = { 0 };
    const char sentinel[] = "safe";
    int fd = mkstemp(foreign);

    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT((int)write(fd, sentinel, sizeof(sentinel)),
                 (int)sizeof(sentinel));
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(test_fixture_path(link_path, sizeof(link_path),
                                   "preplaced-link"), 0);
    CHECK_EQ_INT(symlinkat(foreign, test_fixture_root_fd,
                           "preplaced-link"), 0);

    errno = 0;
    CHECK_EQ_INT(test_fixture_create("preplaced-link"), -1);
    CHECK(errno == EEXIST || errno == ELOOP);
    CHECK_EQ_INT(signals_scratch_register(link_path), 0);
    signals_scratch_cleanup();
    CHECK(!test_fixture_exists("preplaced-link"));

    fd = open(foreign, O_RDONLY);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK_EQ_INT((int)read(fd, observed, sizeof(sentinel)),
                     (int)sizeof(sentinel));
        CHECK_EQ_INT(close(fd), 0);
        CHECK(memcmp(observed, sentinel, sizeof(sentinel)) == 0);
    }
    (void)unlink(foreign);
}

/* Registration must fail closed on garbage input. */
TEST(scratch_registry_rejects_invalid) {
    CHECK_EQ_INT(signals_scratch_register(NULL), -1);
    CHECK_EQ_INT(signals_scratch_register(""), -1);
}

/* signals_dispatch_pending must terminate the process with the deferred
 * signal's default action so shells see the 128+N convention. Forked child:
 * exit codes 10-12 mark the specific failure mode. */
TEST(dispatch_terminates_with_deferred_signal) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        int signal_number = test_guarded_signals[i];
        int status = 0;
        pid_t pid;

        fflush(NULL);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            if (signals_guard_begin() != 0) _exit(10);
            if (raise(signal_number) != 0 || !signals_pending() ||
                signals_pending_signal() != signal_number) {
                _exit(11);
            }
            (void)signals_dispatch_pending(); /* must not return */
            _exit(12);
        }
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) {
            CHECK_EQ_INT(WTERMSIG(status), signal_number);
        }
    }
}

/* Dispatch must never turn restoration into two unchecked attempts (one in
 * the caller and one before raise). The first injected failure returns with
 * both pending-signal and guard ownership intact; only the explicit retry may
 * restore the final disposition and terminate by the original signal. */
TEST(dispatch_retains_pending_until_exact_restoration_succeeds) {
    int status = 0;
    pid_t pid;

    test_fixture_unlink("dispatch-restore-retained");
    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct sigaction default_action;

        memset(&default_action, 0, sizeof(default_action));
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        if (sigaction(SIGTERM, &default_action, NULL) != 0) _exit(20);
        if (signals_guard_begin() != 0) _exit(21);
        raise(SIGTERM);
        if (!signals_pending()) _exit(22);
        signals_test_fail_sigaction(SIGTERM,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        errno = 0;
        if (signals_dispatch_pending() != -1 || errno != EIO) _exit(23);
        if (!signals_pending() || signals_pending_signal() != SIGTERM) {
            _exit(24);
        }
        if (test_fixture_create("dispatch-restore-retained") != 0) _exit(25);
        (void)signals_dispatch_pending(); /* checked retry must terminate */
        _exit(26);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
    CHECK(test_fixture_exists("dispatch-restore-retained"));
    test_fixture_unlink("dispatch-restore-retained");
}

/* AR-09 M29: dispatch is synchronous even when the caller had the selected
 * signal blocked. The inherited handler must run before dispatch returns,
 * observe the still-published library signal, and leave the complete caller
 * mask unchanged. Run the same contract from both caller mask states. */
TEST(dispatch_returning_handler_observes_pending_and_restores_mask) {
    struct sigaction original_action;
    sigset_t original_mask;

    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_action),
                 0);

    for (int initially_blocked = 0; initially_blocked <= 1;
         initially_blocked++) {
        sigset_t caller_mask = original_mask;
        sigset_t observed_mask;

        sigdelset(&caller_mask, SIGTERM);
        sigaddset(&caller_mask, SIGUSR1);
        sigdelset(&caller_mask, SIGUSR2);
        CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
        dispatch_handler_calls = 0;
        dispatch_handler_pending = 0;
        CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
        if (initially_blocked) {
            sigaddset(&caller_mask, SIGTERM);
            CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
        }

        CHECK_EQ_INT(signals_dispatch_pending(), 0);
        CHECK_EQ_INT(dispatch_handler_calls, 1);
        CHECK_EQ_INT(dispatch_handler_pending, SIGTERM);
        CHECK(!signals_pending());
        CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
        CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));
    }

    dispatch_test_restore(SIGTERM, &original_action, &original_mask);
}

/* A blocked caller mask must not convert default-action dispatch into a
 * successful return with a kernel-pending signal. The selected signal is
 * temporarily unblocked and terminates the child before dispatch can return. */
TEST(dispatch_blocked_default_disposition_terminates) {
    int status = 0;
    pid_t pid;

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct sigaction default_action;
        sigset_t target;

        memset(&default_action, 0, sizeof(default_action));
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        if (sigaction(SIGTERM, &default_action, NULL) != 0) _exit(30);
        if (dispatch_test_defer(SIGTERM) != 0) _exit(31);
        sigemptyset(&target);
        sigaddset(&target, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &target, NULL) != 0) _exit(32);
        (void)signals_dispatch_pending();
        _exit(33);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
}

/* Temporarily delivering SIGTERM must not disturb an unrelated signal that
 * was both blocked and kernel-pending at entry. This kills implementations
 * that replace the live mask with an empty/full convenience mask. */
TEST(dispatch_preserves_unrelated_blocked_pending_signal) {
    struct sigaction original_term;
    struct sigaction original_usr1;
    struct sigaction ignore;
    sigset_t original_mask;
    sigset_t caller_mask;
    sigset_t observed_mask;
    sigset_t pending;

    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_term),
                 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGUSR1, unrelated_observing_handler, &original_usr1),
                 0);
    caller_mask = original_mask;
    sigdelset(&caller_mask, SIGTERM);
    sigaddset(&caller_mask, SIGUSR1);
    sigdelset(&caller_mask, SIGUSR2);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
    unrelated_handler_calls = 0;
    dispatch_handler_calls = 0;
    dispatch_handler_pending = 0;
    CHECK_EQ_INT(raise(SIGUSR1), 0);
    CHECK_EQ_INT(sigpending(&pending), 0);
    CHECK_EQ_INT(sigismember(&pending, SIGUSR1), 1);
    CHECK_EQ_INT(unrelated_handler_calls, 0);
    CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
    sigaddset(&caller_mask, SIGTERM);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);

    CHECK_EQ_INT(signals_dispatch_pending(), 0);
    CHECK_EQ_INT(dispatch_handler_calls, 1);
    CHECK_EQ_INT(dispatch_handler_pending, SIGTERM);
    CHECK_EQ_INT(unrelated_handler_calls, 0);
    CHECK_EQ_INT(sigpending(&pending), 0);
    CHECK_EQ_INT(sigismember(&pending, SIGUSR1), 1);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));

    /* Ignoring a blocked pending signal discards it, so restoring the harness
     * mask below cannot deliver a cleanup artifact. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    CHECK_EQ_INT(sigaction(SIGUSR1, &ignore, NULL), 0);
    dispatch_test_restore(SIGTERM, &original_term, &original_mask);
    CHECK_EQ_INT(sigaction(SIGUSR1, &original_usr1, NULL), 0);
}

/* A raise failure occurs before delivery: retain library ownership, restore
 * the exact caller mask, and let one explicit retry deliver exactly once. */
TEST(dispatch_raise_failure_retains_pending_for_retry) {
    struct sigaction original_action;
    sigset_t original_mask;
    sigset_t caller_mask;
    sigset_t observed_mask;

    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_action),
                 0);
    dispatch_handler_calls = 0;
    dispatch_handler_pending = 0;
    CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
    caller_mask = original_mask;
    sigaddset(&caller_mask, SIGTERM);
    sigaddset(&caller_mask, SIGUSR1);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_RAISE, EAGAIN);

    errno = 0;
    CHECK_EQ_INT(signals_dispatch_pending(), -1);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK(signals_pending());
    CHECK_EQ_INT(signals_pending_signal(), SIGTERM);
    CHECK_EQ_INT(dispatch_handler_calls, 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));

    CHECK_EQ_INT(signals_dispatch_pending(), 0);
    CHECK_EQ_INT(dispatch_handler_calls, 1);
    CHECK_EQ_INT(dispatch_handler_pending, SIGTERM);
    CHECK(!signals_pending());
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));
    dispatch_test_restore(SIGTERM, &original_action, &original_mask);
}

/* Once a returning handler accepted the signal, a mask-restore failure owns
 * only restoration. Retry must repair the saved mask without raising again. */
TEST(dispatch_restore_failure_after_delivery_does_not_reraise) {
    struct sigaction original_action;
    sigset_t original_mask;
    sigset_t caller_mask;
    sigset_t observed_mask;

    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_action),
                 0);
    dispatch_handler_calls = 0;
    dispatch_handler_pending = 0;
    CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
    caller_mask = original_mask;
    sigaddset(&caller_mask, SIGTERM);
    sigaddset(&caller_mask, SIGUSR1);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_MASK_RESTORE, EIO);

    errno = 0;
    CHECK_EQ_INT(signals_dispatch_pending(), -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(dispatch_handler_calls, 1);
    CHECK_EQ_INT(dispatch_handler_pending, SIGTERM);
    CHECK(!signals_pending());
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK_EQ_INT(sigismember(&observed_mask, SIGTERM), 0);

    CHECK_EQ_INT(signals_dispatch_pending(), 0);
    CHECK_EQ_INT(dispatch_handler_calls, 1);
    CHECK(!signals_pending());
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));
    dispatch_test_restore(SIGTERM, &original_action, &original_mask);
}

/* When raise and mask restoration both fail, raise remains the reported
 * primary error. Retry repairs the saved mask before delivering once. */
TEST(dispatch_raise_and_restore_failure_preserves_primary_error) {
    struct sigaction original_action;
    sigset_t original_mask;
    sigset_t caller_mask;
    sigset_t observed_mask;
    error_context_t failure;
    char restore_errno_text[64];

    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_action),
                 0);
    dispatch_handler_calls = 0;
    dispatch_handler_pending = 0;
    CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
    caller_mask = original_mask;
    sigaddset(&caller_mask, SIGTERM);
    sigaddset(&caller_mask, SIGUSR1);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &caller_mask, NULL), 0);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_RAISE, EAGAIN);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_MASK_RESTORE, EIO);
    clear_error();

    errno = 0;
    CHECK_EQ_INT(signals_dispatch_pending(), -1);
    failure = *get_last_error();
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(failure.system_errno, EAGAIN);
    CHECK(snprintf(restore_errno_text, sizeof(restore_errno_text),
                   "restore errno=%d", EIO) > 0);
    CHECK(strstr(failure.message, restore_errno_text) != NULL);
    CHECK(signals_pending());
    CHECK_EQ_INT(dispatch_handler_calls, 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK_EQ_INT(sigismember(&observed_mask, SIGTERM), 0);

    CHECK_EQ_INT(signals_dispatch_pending(), 0);
    CHECK_EQ_INT(dispatch_handler_calls, 1);
    CHECK_EQ_INT(dispatch_handler_pending, SIGTERM);
    CHECK(!signals_pending());
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &caller_mask));
    dispatch_test_restore(SIGTERM, &original_action, &original_mask);
}

/* AR-11 L11: a delivered signal whose exact mask restoration failed leaves a
 * single dispatch-owned obligation. Starting another guard must not adopt or
 * overwrite that saved mask; only an explicit dispatch retry may discharge it. */
TEST(dispatch_mask_debt_rejects_new_guard_until_explicit_retry) {
    struct sigaction original_action;
    sigset_t original_mask;
    sigset_t first_mask;
    sigset_t changed_mask;
    sigset_t observed_mask;

    CHECK_EQ_INT(dispatch_test_install_handler(
                     SIGTERM, dispatch_observing_handler, &original_action),
                 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &original_mask), 0);
    first_mask = original_mask;
    sigdelset(&first_mask, SIGTERM);
    sigaddset(&first_mask, SIGUSR1);
    sigdelset(&first_mask, SIGUSR2);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &first_mask, NULL), 0);

    dispatch_handler_calls = 0;
    CHECK_EQ_INT(dispatch_test_defer(SIGTERM), 0);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_MASK_RESTORE, EIO);
    errno = 0;
    CHECK_EQ_INT(signals_dispatch_pending(), -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(dispatch_handler_calls, 1);

    changed_mask = original_mask;
    sigdelset(&changed_mask, SIGTERM);
    sigdelset(&changed_mask, SIGUSR1);
    sigaddset(&changed_mask, SIGUSR2);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, &changed_mask, NULL), 0);
    errno = 0;
    CHECK_EQ_INT(signals_guard_begin(), -1);
    CHECK_EQ_INT(errno, EBUSY);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &changed_mask));

    CHECK_EQ_INT(signals_dispatch_pending(), 0);
    CHECK_EQ_INT(sigprocmask(SIG_SETMASK, NULL, &observed_mask), 0);
    CHECK(dispatch_test_masks_equal(&observed_mask, &first_mask));
    dispatch_test_restore(SIGTERM, &original_action, &original_mask);
}

static int exercise_atomic_reap_retirement(void) {
    const char *argv[] = {"true", NULL};
    run_result_t result;

    if (signals_guard_begin() != 0) return 40;
    if (raise(SIGTERM) != 0 || !signals_pending()) return 41;
    signals_rollback_begin();
    post_wait_hook_called = 0;
    post_wait_hook_guarded_masked = 0;
    signals_test_set_post_wait_hook(raise_repeat_signal_at_reap_transition);
    int run_rc = run_argv(argv, NULL, &result);
    signals_test_set_post_wait_hook(NULL);
    if (run_rc != 0 || !result.spawned || result.exit_code != 0) return 42;
    if (!post_wait_hook_called || !post_wait_hook_guarded_masked) return 43;
    if (!signals_pending()) return 44;
    signals_rollback_end();
    if (signals_guard_end() != 0) return 45;
    return 0;
}

/* AR-11 M31: the deterministic post-wait checkpoint runs with every installed
 * guarded signal blocked. The repeated rollback signal is delivered only
 * after the reaped PID publication has been retired, while the real child
 * status remains intact. */
TEST(reap_and_child_pid_retirement_are_one_guarded_transition) {
    int status = 0;
    pid_t worker = fork();

    CHECK(worker >= 0);
    if (worker == 0) _exit(exercise_atomic_reap_retirement());
    if (worker > 0) {
        CHECK_EQ_INT(waitpid(worker, &status, 0), worker);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

static int exercise_initial_echild_retirement(bool matching_publication) {
    int status = 0;
    pid_t child = fork();
    if (child < 0) return 50;
    if (child == 0) _exit(0);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 51;

    pid_t published = matching_publication ? child : child + 1000000;
    signals_child_spawned(published);
    if (signals_test_published_child() != published) return 52;
    signals_child_wait_result_t result = signals_wait_child(child, NULL, 0);
    if (result.waited != -1 || result.wait_errno != ECHILD ||
        result.mask_errno != 0) {
        return 53;
    }
    if (matching_publication) {
        return signals_test_published_child() == 0 ? 0 : 54;
    }
    return signals_test_published_child() == published ? 0 : 55;
}

TEST(initial_echild_retires_only_the_matching_publication) {
    for (int matching = 0; matching <= 1; matching++) {
        int status = 0;
        pid_t worker = fork();
        CHECK(worker >= 0);
        if (worker == 0) {
            _exit(exercise_initial_echild_retirement(matching != 0));
        }
        if (worker > 0) {
            CHECK_EQ_INT(waitpid(worker, &status, 0), worker);
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }
}

/* A second signal while one is pending is the emergency exit: the handler
 * unlinks registered scratch files (SIG-02) and dies immediately with the
 * signal's default action. */
TEST(second_signal_is_emergency_exit_and_drops_scratch) {
    for (size_t i = 0; i < TEST_GUARDED_SIGNAL_COUNT; i++) {
        char name[64];
        char scratch[256];
        int signal_number = test_guarded_signals[i];
        int status = 0;
        pid_t pid;

        CHECK(snprintf(name, sizeof(name), "scratch-emergency-%d",
                       signal_number) > 0);
        CHECK_EQ_INT(test_fixture_path(scratch, sizeof(scratch), name), 0);
        CHECK_EQ_INT(test_fixture_create(name), 0);

        fflush(NULL);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            if (signals_scratch_register(scratch) != 0 ||
                signals_guard_begin() != 0 || raise(signal_number) != 0 ||
                !signals_pending()) {
                _exit(10);
            }
            (void)raise(signal_number); /* second: must terminate NOW */
            _exit(11);
        }
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) {
            CHECK_EQ_INT(WTERMSIG(status), signal_number);
        }
        CHECK(!test_fixture_exists(name));

        test_fixture_unlink(name); /* in case the child failed */
    }
}

/* AR-02 #2: a second signal arriving while the failed-switch ROLLBACK is
 * running must NOT take the emergency exit — dying mid-git_config_restore
 * persists the aborted account's identity. Inside the rollback window the
 * signal stays deferred; once the window closes the mainline dispatches it
 * with the correct death-by-signal status. Exit code 10/11/12 mark the
 * specific failure mode. */
TEST(second_signal_during_rollback_is_deferred) {
    int status = 0;
    pid_t pid;

    /* Stands in for "the rest of git_config_restore": pre-fix the child died
     * at the second raise and never created it; post-fix the whole window
     * completes first, so the marker must exist. */
    CHECK(!test_fixture_exists("rollback-done"));

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        signals_guard_begin();
        raise(SIGINT);                     /* the signal that aborted the switch */
        if (!signals_pending()) _exit(10); /* first signal must defer */
        signals_rollback_begin();
        raise(SIGINT);                     /* second: pre-fix this killed us HERE */
        if (!signals_pending()) _exit(11); /* must still be recorded, not lost */
        if (test_fixture_create("rollback-done") != 0) _exit(13);
        signals_rollback_end();
        signals_dispatch_pending();        /* rollback done: now die correctly */
        _exit(12);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));            /* still reports death-by-signal */
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);
    CHECK(test_fixture_exists("rollback-done"));

    test_fixture_unlink("rollback-done");
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
    char b;
    int status = 0, sync[2];
    pid_t pid;
    bool exited;

    CHECK(!test_fixture_exists("rollback-unblocked"));
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
        signals_child_wait_result_t wait_result;
        do {
            wait_result = signals_wait_child(child, &cst, 0);
            w = wait_result.waited;
        } while (w < 0 && wait_result.wait_errno == EINTR &&
                 wait_result.mask_errno == 0);
        if (wait_result.mask_errno != 0) _exit(17);
        if (w != child) _exit(14);
        /* The handler must have forwarded OUR signal, not something else. */
        if (!WIFSIGNALED(cst) || WTERMSIG(cst) != SIGTERM) _exit(15);
        if (!signals_pending()) _exit(11); /* deferred signal must survive */

        if (test_fixture_create("rollback-unblocked") != 0) _exit(16);
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
    CHECK(test_fixture_exists("rollback-unblocked"));

    test_fixture_unlink("rollback-unblocked");
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

        signals_child_wait_result_t wait_result;
        do {
            wait_result = signals_wait_child(child, &cst, 0);
            w = wait_result.waited;
        } while (w < 0 && wait_result.wait_errno == EINTR &&
                 wait_result.mask_errno == 0);
        if (wait_result.mask_errno != 0) _exit(16);
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
    if (test_fixture_init() != 0) {
        perror("test_signals: create private fixture root");
        return 1;
    }
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(guard_begin_failures_restore_every_disposition);
    RUN_TEST(guard_begin_never_reports_restore_pending_as_active);
    RUN_TEST(guard_end_retains_failed_restoration_for_retry);
    RUN_TEST(guard_begin_skips_only_inherited_sig_ign);
    RUN_TEST(guard_defers_first_signal);
    RUN_TEST(guard_end_restores_default_disposition);
    RUN_TEST(guard_respects_inherited_sig_ign);
    RUN_TEST(child_spawn_barrier_blocks_only_installed_guard_signals);
    RUN_TEST(fixture_root_is_private_and_pinned);
    RUN_TEST(scratch_registry_unlinks_registered_paths);
    RUN_TEST(fixture_creation_and_cleanup_do_not_follow_preplaced_symlink);
    RUN_TEST(scratch_registry_rejects_invalid);
    RUN_TEST(dispatch_terminates_with_deferred_signal);
    RUN_TEST(dispatch_retains_pending_until_exact_restoration_succeeds);
    RUN_TEST(dispatch_returning_handler_observes_pending_and_restores_mask);
    RUN_TEST(dispatch_blocked_default_disposition_terminates);
    RUN_TEST(dispatch_preserves_unrelated_blocked_pending_signal);
    RUN_TEST(dispatch_raise_failure_retains_pending_for_retry);
    RUN_TEST(dispatch_restore_failure_after_delivery_does_not_reraise);
    RUN_TEST(dispatch_raise_and_restore_failure_preserves_primary_error);
    RUN_TEST(dispatch_mask_debt_rejects_new_guard_until_explicit_retry);
    RUN_TEST(reap_and_child_pid_retirement_are_one_guarded_transition);
    RUN_TEST(initial_echild_retires_only_the_matching_publication);
    RUN_TEST(second_signal_is_emergency_exit_and_drops_scratch);
    RUN_TEST(second_signal_during_rollback_is_deferred);
    RUN_TEST(second_signal_during_rollback_kills_blocking_child);
    RUN_TEST(rollback_child_kill_escalates_to_sigkill);
    close(test_fixture_root_fd);
    test_fixture_root_fd = -1;
TEST_MAIN_END()
