/* AR-08 L20: failed terminal-echo restoration must stay visible/retryable. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test.h"

#include "error.h"
#include "utils.h"

#include <termios.h>

/* Linked only against the GITSWITCH_TESTING utils object. */
typedef void (*echo_tcsetattr_test_hook_fn)(int fd);
void gitswitch_test_fail_echo_tcsetattr(int system_errno);
echo_tcsetattr_test_hook_fn gitswitch_test_set_echo_tcsetattr_hook(
    echo_tcsetattr_test_hook_fn hook);

static int g_echo_hook_target = -1;
static int g_echo_hook_observed_fd = -1;
static int g_echo_hook_dup2_result = -1;

static void rebind_stdin_before_echo_change(int fd) {
    g_echo_hook_observed_fd = fd;
    g_echo_hook_dup2_result = dup2(g_echo_hook_target, STDIN_FILENO);
}

static void observe_echo_change_fd(int fd) {
    g_echo_hook_observed_fd = fd;
}

static int open_test_pty(int *master_out, int *slave_out) {
    char *slave_name;
    int master;
    int slave;

    if (!master_out || !slave_out) return -1;
    *master_out = -1;
    *slave_out = -1;
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 ||
        (slave_name = ptsname(master)) == NULL) {
        if (master >= 0) close(master);
        return -1;
    }
    slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        close(master);
        return -1;
    }
    *master_out = master;
    *slave_out = slave;
    return 0;
}

static int replace_stdin(int source_fd, int *saved_stdin) {
    if (source_fd < 0 || !saved_stdin) return -1;
    *saved_stdin = dup(STDIN_FILENO);
    if (*saved_stdin < 0) return -1;
    if (dup2(source_fd, STDIN_FILENO) != STDIN_FILENO) {
        close(*saved_stdin);
        *saved_stdin = -1;
        return -1;
    }
    return 0;
}

static void restore_stdin(int *saved_stdin) {
    if (saved_stdin && *saved_stdin >= 0) {
        (void)dup2(*saved_stdin, STDIN_FILENO);
        close(*saved_stdin);
        *saved_stdin = -1;
    }
}

static int force_echo_enabled(int fd, struct termios *original_out) {
    struct termios termios;

    if (tcgetattr(fd, &termios) != 0) return -1;
    if (original_out) *original_out = termios;
    termios.c_lflag |= ECHO;
    return tcsetattr(fd, TCSANOW, &termios);
}

static int terminal_echo_is_enabled(int fd, bool *enabled_out) {
    struct termios termios;

    if (!enabled_out || tcgetattr(fd, &termios) != 0) return -1;
    *enabled_out = (termios.c_lflag & ECHO) != 0;
    return 0;
}

TEST(disable_echo_failure_reports_errno_and_does_not_fake_success) {
    int null_fd = open("/dev/null", O_RDONLY);
    int saved_stdin = -1;
    int result;
    int failure_errno;
    const error_context_t *error;

    CHECK(null_fd >= 0);
    if (null_fd < 0) return;
    CHECK_EQ_INT(replace_stdin(null_fd, &saved_stdin), 0);
    if (saved_stdin < 0) {
        close(null_fd);
        return;
    }

    clear_error();
    errno = 0;
    result = disable_echo();
    failure_errno = errno;
    error = get_last_error();
    CHECK_EQ_INT(result, -1);
    CHECK(failure_errno != 0);
    CHECK_EQ_INT(error->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(error->system_errno, failure_errno);
    CHECK(strstr(error->message, "terminal state") != NULL);

    restore_stdin(&saved_stdin);
    close(null_fd);
}

TEST(echo_state_stays_bound_across_two_pty_stdin_reuse_and_retry) {
    struct termios initial_a;
    struct termios initial_b;
    int master_a = -1;
    int slave_a = -1;
    int master_b = -1;
    int slave_b = -1;
    int saved_stdin = -1;
    int operation_result;
    bool echo_a = false;
    bool echo_b = false;
    bool initial_a_valid = false;
    bool initial_b_valid = false;
    int restore_owner = -1;
    const error_context_t *error;

    CHECK_EQ_INT(open_test_pty(&master_a, &slave_a), 0);
    CHECK_EQ_INT(open_test_pty(&master_b, &slave_b), 0);
    if (master_a < 0 || slave_a < 0 || master_b < 0 || slave_b < 0) {
        goto cleanup;
    }
    operation_result = force_echo_enabled(slave_a, &initial_a);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    initial_a_valid = true;
    operation_result = force_echo_enabled(slave_b, &initial_b);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    initial_b_valid = true;
    operation_result = replace_stdin(slave_a, &saved_stdin);
    CHECK_EQ_INT(operation_result, 0);
    if (saved_stdin < 0) goto cleanup;

    operation_result = disable_echo();
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = slave_a;
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(!echo_a);
    CHECK(echo_b);
    CHECK_EQ_INT(disable_echo(), 0); /* Same terminal is idempotent. */

    /* dup2 reuses descriptor zero for a different PTY. Identity, not the
     * descriptor number, must govern both repeated disable and restore. */
    operation_result = dup2(slave_b, STDIN_FILENO);
    CHECK_EQ_INT(operation_result, STDIN_FILENO);
    if (operation_result != STDIN_FILENO) goto cleanup;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(disable_echo(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(error->system_errno, ESTALE);
    CHECK(strstr(error->message, "another terminal") != NULL);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(enable_echo(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(error->system_errno, ESTALE);
    CHECK(strstr(error->message, "restore terminal echo") != NULL);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(!echo_a); /* The retained A state remains pending. */
    CHECK(echo_b);  /* Neither mismatched operation touched B. */

    operation_result = dup2(slave_a, STDIN_FILENO);
    CHECK_EQ_INT(operation_result, STDIN_FILENO);
    if (operation_result != STDIN_FILENO) goto cleanup;

    gitswitch_test_fail_echo_tcsetattr(EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(enable_echo(), -1);
    CHECK_EQ_INT(errno, EIO);
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(error->system_errno, EIO);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK(!echo_a);

    /* Rebind fd zero only after enable_echo() validates A. The production
     * transition still restores through its retained descriptor; restoring
     * through current stdin would instead alter B and strand A with echo off. */
    g_echo_hook_target = slave_b;
    g_echo_hook_observed_fd = -1;
    g_echo_hook_dup2_result = -1;
    (void)gitswitch_test_set_echo_tcsetattr_hook(
        rebind_stdin_before_echo_change);
    operation_result = enable_echo();
    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = -1;
    CHECK_EQ_INT(g_echo_hook_dup2_result, STDIN_FILENO);
    CHECK(g_echo_hook_observed_fd > STDIN_FILENO);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_a);
    CHECK(echo_b);
    CHECK_EQ_INT(enable_echo(), 0); /* Restored state is idempotent. */

    /* After A releases ownership, B can complete an independent clean cycle. */
    operation_result = disable_echo();
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = slave_b;
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_a);
    CHECK(!echo_b);
    operation_result = enable_echo();
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = -1;
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_b);

cleanup:
    gitswitch_test_fail_echo_tcsetattr(0);
    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
    if (restore_owner >= 0) {
        (void)dup2(restore_owner, STDIN_FILENO);
        (void)enable_echo();
    }
    if (initial_a_valid) (void)tcsetattr(slave_a, TCSANOW, &initial_a);
    if (initial_b_valid) (void)tcsetattr(slave_b, TCSANOW, &initial_b);
    restore_stdin(&saved_stdin);
    if (slave_b >= 0) close(slave_b);
    if (master_b >= 0) close(master_b);
    if (slave_a >= 0) close(slave_a);
    if (master_a >= 0) close(master_a);
}

TEST(retained_echo_fd_does_not_occupy_closed_standard_streams) {
    struct termios initial;
    int master = -1;
    int slave = -1;
    int saved_stdin = -1;
    int saved_stdout = -1;
    int saved_stderr = -1;
    int null_stdout = -1;
    int null_stderr = -1;
    int reused_stdout_fd = -1;
    int reused_stderr_fd = -1;
    int close_stdout_result = -1;
    int close_stderr_result = -1;
    int restore_stdout_result = -1;
    int restore_stderr_result = -1;
    int disable_result = -1;
    int enable_result = -1;
    int read_disabled_result = -1;
    int read_restored_result = -1;
    int setup_result;
    bool echo_disabled = false;
    bool echo_restored = false;
    bool initial_valid = false;
    bool restore_pending = false;

    CHECK_EQ_INT(open_test_pty(&master, &slave), 0);
    if (master < 0 || slave < 0) goto cleanup;
    setup_result = force_echo_enabled(slave, &initial);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    initial_valid = true;
    CHECK_EQ_INT(replace_stdin(slave, &saved_stdin), 0);
    if (saved_stdin < 0) goto cleanup;

    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    CHECK(saved_stdout >= STDERR_FILENO + 1);
    CHECK(saved_stderr >= STDERR_FILENO + 1);
    if (saved_stdout < 0 || saved_stderr < 0) goto cleanup;

    g_echo_hook_observed_fd = -1;
    (void)gitswitch_test_set_echo_tcsetattr_hook(observe_echo_change_fd);
    close_stdout_result = close(STDOUT_FILENO);
    close_stderr_result = close(STDERR_FILENO);
    if (close_stdout_result == 0 && close_stderr_result == 0) {
        disable_result = disable_echo();
        if (disable_result == 0) restore_pending = true;
        read_disabled_result =
            terminal_echo_is_enabled(slave, &echo_disabled);

        /* The retained terminal descriptor must leave both standard-stream
         * slots available for unrelated reuse throughout the pending state. */
        null_stdout = open("/dev/null", O_WRONLY);
        null_stderr = open("/dev/null", O_WRONLY);
        reused_stdout_fd = null_stdout;
        reused_stderr_fd = null_stderr;

        enable_result = enable_echo();
        if (enable_result == 0) restore_pending = false;
        read_restored_result =
            terminal_echo_is_enabled(slave, &echo_restored);
    }

    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
    if (null_stdout >= 0) close(null_stdout);
    if (null_stderr >= 0) close(null_stderr);
    null_stdout = -1;
    null_stderr = -1;
    restore_stdout_result = dup2(saved_stdout, STDOUT_FILENO);
    restore_stderr_result = dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdout);
    close(saved_stderr);
    saved_stdout = -1;
    saved_stderr = -1;

    CHECK_EQ_INT(close_stdout_result, 0);
    CHECK_EQ_INT(close_stderr_result, 0);
    CHECK_EQ_INT(restore_stdout_result, STDOUT_FILENO);
    CHECK_EQ_INT(restore_stderr_result, STDERR_FILENO);
    CHECK_EQ_INT(disable_result, 0);
    CHECK(g_echo_hook_observed_fd >= STDERR_FILENO + 1);
    CHECK_EQ_INT(read_disabled_result, 0);
    CHECK(!echo_disabled);
    CHECK_EQ_INT(reused_stdout_fd, STDOUT_FILENO);
    CHECK_EQ_INT(reused_stderr_fd, STDERR_FILENO);
    CHECK_EQ_INT(enable_result, 0);
    CHECK_EQ_INT(read_restored_result, 0);
    CHECK(echo_restored);

cleanup:
    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
    if (null_stdout >= 0) close(null_stdout);
    if (null_stderr >= 0) close(null_stderr);
    if (saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (restore_pending && slave >= 0) {
        (void)dup2(slave, STDIN_FILENO);
        (void)enable_echo();
    }
    if (initial_valid) (void)tcsetattr(slave, TCSANOW, &initial);
    restore_stdin(&saved_stdin);
    if (slave >= 0) close(slave);
    if (master >= 0) close(master);
}

TEST(failed_disable_does_not_publish_terminal_ownership) {
    struct termios initial_a;
    struct termios initial_b;
    int master_a = -1;
    int slave_a = -1;
    int master_b = -1;
    int slave_b = -1;
    int saved_stdin = -1;
    int operation_result;
    bool echo_a = false;
    bool echo_b = false;
    bool initial_a_valid = false;
    bool initial_b_valid = false;
    int restore_owner = -1;

    CHECK_EQ_INT(open_test_pty(&master_a, &slave_a), 0);
    CHECK_EQ_INT(open_test_pty(&master_b, &slave_b), 0);
    if (master_a < 0 || slave_a < 0 || master_b < 0 || slave_b < 0) {
        goto cleanup;
    }
    operation_result = force_echo_enabled(slave_a, &initial_a);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    initial_a_valid = true;
    operation_result = force_echo_enabled(slave_b, &initial_b);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    initial_b_valid = true;
    operation_result = replace_stdin(slave_a, &saved_stdin);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;

    gitswitch_test_fail_echo_tcsetattr(EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(disable_echo(), -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_a);
    CHECK(echo_b);

    operation_result = dup2(slave_b, STDIN_FILENO);
    CHECK_EQ_INT(operation_result, STDIN_FILENO);
    if (operation_result != STDIN_FILENO) goto cleanup;
    operation_result = disable_echo();
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = slave_b;
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_a, &echo_a), 0);
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_a);
    CHECK(!echo_b);
    operation_result = enable_echo();
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result == 0) restore_owner = -1;
    CHECK_EQ_INT(terminal_echo_is_enabled(slave_b, &echo_b), 0);
    CHECK(echo_b);

cleanup:
    gitswitch_test_fail_echo_tcsetattr(0);
    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
    if (restore_owner >= 0) {
        (void)dup2(restore_owner, STDIN_FILENO);
        (void)enable_echo();
    }
    if (initial_a_valid) (void)tcsetattr(slave_a, TCSANOW, &initial_a);
    if (initial_b_valid) (void)tcsetattr(slave_b, TCSANOW, &initial_b);
    restore_stdin(&saved_stdin);
    if (slave_b >= 0) close(slave_b);
    if (master_b >= 0) close(master_b);
    if (slave_a >= 0) close(slave_a);
    if (master_a >= 0) close(master_a);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(disable_echo_failure_reports_errno_and_does_not_fake_success);
    RUN_TEST(echo_state_stays_bound_across_two_pty_stdin_reuse_and_retry);
    RUN_TEST(retained_echo_fd_does_not_occupy_closed_standard_streams);
    RUN_TEST(failed_disable_does_not_publish_terminal_ownership);
    gitswitch_test_fail_echo_tcsetattr(0);
    (void)gitswitch_test_set_echo_tcsetattr_hook(NULL);
TEST_MAIN_END()
