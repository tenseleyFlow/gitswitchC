/* AR-08 L20: failed terminal-echo restoration must stay visible/retryable. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test.h"

#include "error.h"
#include "utils.h"

#include <termios.h>

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

TEST(failed_restore_remains_pending_and_later_retry_restores_echo) {
    struct termios initial;
    struct termios echo_on;
    struct termios observed;
    int master = -1;
    int slave = -1;
    int null_fd = -1;
    int saved_stdin = -1;
    int restore_errno;
    int operation_result;
    bool initial_valid = false;
    const error_context_t *error;

    CHECK_EQ_INT(open_test_pty(&master, &slave), 0);
    if (master < 0 || slave < 0) goto cleanup;
    operation_result = tcgetattr(slave, &initial);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    initial_valid = true;
    echo_on = initial;
    echo_on.c_lflag |= ECHO;
    operation_result = tcsetattr(slave, TCSANOW, &echo_on);
    CHECK_EQ_INT(operation_result, 0);
    if (operation_result != 0) goto cleanup;
    operation_result = replace_stdin(slave, &saved_stdin);
    CHECK_EQ_INT(operation_result, 0);
    if (saved_stdin < 0) goto cleanup;

    CHECK_EQ_INT(disable_echo(), 0);
    CHECK_EQ_INT(tcgetattr(slave, &observed), 0);
    CHECK((observed.c_lflag & ECHO) == 0);

    null_fd = open("/dev/null", O_RDONLY);
    CHECK(null_fd >= 0);
    if (null_fd < 0) goto cleanup;
    operation_result = dup2(null_fd, STDIN_FILENO);
    CHECK_EQ_INT(operation_result, STDIN_FILENO);
    if (operation_result != STDIN_FILENO) goto cleanup;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(enable_echo(), -1);
    restore_errno = errno;
    error = get_last_error();
    CHECK(restore_errno != 0);
    CHECK_EQ_INT(error->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(error->system_errno, restore_errno);
    CHECK(strstr(error->message, "restore terminal echo") != NULL);
    CHECK_EQ_INT(tcgetattr(slave, &observed), 0);
    CHECK((observed.c_lflag & ECHO) == 0);

    operation_result = dup2(slave, STDIN_FILENO);
    CHECK_EQ_INT(operation_result, STDIN_FILENO);
    if (operation_result != STDIN_FILENO) goto cleanup;
    CHECK_EQ_INT(enable_echo(), 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    CHECK_EQ_INT(tcgetattr(slave, &observed), 0);
    CHECK((observed.c_lflag & ECHO) != 0);
    CHECK_EQ_INT(enable_echo(), 0); /* Restored state is idempotent. */

cleanup:
    if (slave >= 0) {
        (void)dup2(slave, STDIN_FILENO);
        (void)enable_echo();
        if (initial_valid) (void)tcsetattr(slave, TCSANOW, &initial);
    }
    restore_stdin(&saved_stdin);
    if (null_fd >= 0) close(null_fd);
    if (slave >= 0) close(slave);
    if (master >= 0) close(master);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(disable_echo_failure_reports_errno_and_does_not_fake_success);
    RUN_TEST(failed_restore_remains_pending_and_later_retry_restores_echo);
TEST_MAIN_END()
