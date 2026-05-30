/* Security regression tests: command arguments must never reach a shell.
 * These freeze the audit's C1 fix (ssh-add path injection) and the
 * find_command_path no-shell behavior. */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include "ssh_manager.h"
#include <string.h>

/* Recording runner: captures the argv vector instead of executing anything. */
static char rec_argv[16][512];
static int rec_argc;

static int recording_runner(const char *const argv[], const run_opts_t *opts,
                            run_result_t *result) {
    (void)opts;
    rec_argc = 0;
    for (int i = 0; argv[i] != NULL && i < 16; i++) {
        strncpy(rec_argv[i], argv[i], sizeof(rec_argv[i]) - 1);
        rec_argv[i][sizeof(rec_argv[i]) - 1] = '\0';
        rec_argc++;
    }
    if (result) {
        result->spawned = true;
        result->exit_code = 0;
        result->term_signal = 0;
        result->out_len = 0;
    }
    return 0;
}

/* The C1 vulnerability: an ssh_key path with shell metacharacters. With argv
 * execution it must arrive as a SINGLE, intact argv element — never split or
 * interpreted by a shell. */
TEST(ssh_add_key_path_is_one_argv_element) {
    ssh_config_t cfg;
    const char *payload = "/home/u/.ssh/k';touch /tmp/PWNED;'";
    command_runner_fn prev;
    int rc;

    memset(&cfg, 0, sizeof(cfg));
    safe_strncpy(cfg.agent_socket_path, "/tmp/dummy-agent.sock", sizeof(cfg.agent_socket_path));

    prev = run_set_runner(recording_runner);
    rc = ssh_add_key(&cfg, payload);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(rec_argc, 2);              /* {"ssh-add", payload} */
    CHECK_STR_EQ(rec_argv[0], "ssh-add");
    CHECK_STR_EQ(rec_argv[1], payload);     /* intact: no shell splitting */
}

/* find_command_path must resolve via a PATH walk (no shell); a name containing
 * shell metacharacters must simply not resolve and must not execute anything. */
TEST(find_command_path_rejects_metachars) {
    char buf[256];
    CHECK_EQ_INT(find_command_path("x; touch /tmp/gs_pwned_marker", buf, sizeof(buf)), -1);
}

TEST(find_command_path_finds_real_binary) {
    char buf[256];
    CHECK_EQ_INT(find_command_path("echo", buf, sizeof(buf)), 0);
    CHECK(buf[0] == '/');
}

TEST(command_exists_basic) {
    CHECK(command_exists("echo"));
    CHECK(!command_exists("gitswitch_no_such_command_xyz"));
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(ssh_add_key_path_is_one_argv_element);
    RUN_TEST(find_command_path_rejects_metachars);
    RUN_TEST(find_command_path_finds_real_binary);
    RUN_TEST(command_exists_basic);
TEST_MAIN_END()
