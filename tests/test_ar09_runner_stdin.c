/* AR-09 M14: descriptor-backed child stdin for seekable key consumers. */

#include "test.h"
#include "error.h"
#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_input_fixture(char *root, size_t root_size,
                              char *path, size_t path_size) {
    if (root_size < sizeof("/tmp/gsw-ar09-stdin.XXXXXX")) return -1;
    snprintf(root, root_size, "/tmp/gsw-ar09-stdin.XXXXXX");
    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        safe_snprintf(path, path_size, "%s/input", root) != 0 ||
        write_string_to_file(path, "prefix:descriptor-input\n", 0600) != 0) {
        return -1;
    }
    return 0;
}

TEST(runner_seekable_stdin_uses_current_offset_and_keeps_caller_fd) {
    char root[128];
    char path[256];
    char output[128];
    const char *argv[] = {"cat", NULL};
    run_opts_t opts;
    run_result_t result;
    int fd;

    if (!command_exists("cat")) TS_SKIP("coreutils", "cat unavailable");
    CHECK_EQ_INT(make_input_fixture(root, sizeof(root), path, sizeof(path)), 0);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(fd >= 0);
    CHECK_EQ_INT((int)lseek(fd, 7, SEEK_SET), 7);

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stdin_fd = fd;
    opts.use_stdin_fd = true;
    CHECK_EQ_INT(run_argv_real(argv, &opts, &result), 0);
    CHECK_STR_EQ(output, "descriptor-input\n");
    CHECK(result.spawned);
    CHECK(fcntl(fd, F_GETFD, 0) >= 0); /* caller still owns the descriptor */
    CHECK_EQ_INT((int)lseek(fd, 0, SEEK_CUR), 24);

    close(fd);
    ts_rm_rf(root);
}

TEST(runner_rejects_byte_input_with_seekable_stdin_fd) {
    char root[128];
    char path[256];
    const char *argv[] = {"cat", NULL};
    run_opts_t opts;
    run_result_t result;
    int fd;

    CHECK_EQ_INT(make_input_fixture(root, sizeof(root), path, sizeof(path)), 0);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(fd >= 0);
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.input = "competing";
    opts.input_len = strlen(opts.input);
    opts.stdin_fd = fd;
    opts.use_stdin_fd = true;

    CHECK_EQ_INT(run_argv_real(argv, &opts, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(!result.spawned);
    CHECK_EQ_INT((int)lseek(fd, 0, SEEK_CUR), 0);
    CHECK(fcntl(fd, F_GETFD, 0) >= 0);

    close(fd);
    ts_rm_rf(root);
}

TEST(runner_rejects_nonregular_seekable_stdin_fd) {
    char root[128];
    char path[256];
    const char *argv[] = {"cat", NULL};
    run_opts_t opts;
    run_result_t result;
    int fd;

    CHECK_EQ_INT(make_input_fixture(root, sizeof(root), path, sizeof(path)), 0);
    fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0);
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stdin_fd = fd;
    opts.use_stdin_fd = true;

    CHECK_EQ_INT(run_argv_real(argv, &opts, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(!result.spawned);
    CHECK(fcntl(fd, F_GETFD, 0) >= 0);

    close(fd);
    ts_rm_rf(root);
}

TEST(runner_rejects_write_only_seekable_stdin_fd) {
    char root[128];
    char path[256];
    const char *argv[] = {"cat", NULL};
    run_opts_t opts;
    run_result_t result;
    int fd;

    CHECK_EQ_INT(make_input_fixture(root, sizeof(root), path, sizeof(path)), 0);
    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(fd >= 0);
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stdin_fd = fd;
    opts.use_stdin_fd = true;

    CHECK_EQ_INT(run_argv_real(argv, &opts, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(!result.spawned);
    CHECK(fcntl(fd, F_GETFD, 0) >= 0);

    close(fd);
    ts_rm_rf(root);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(runner_seekable_stdin_uses_current_offset_and_keeps_caller_fd);
    RUN_TEST(runner_rejects_byte_input_with_seekable_stdin_fd);
    RUN_TEST(runner_rejects_nonregular_seekable_stdin_fd);
    RUN_TEST(runner_rejects_write_only_seekable_stdin_fd);
TEST_MAIN_END()
