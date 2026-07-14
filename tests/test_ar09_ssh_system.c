/* AR-09 L10: shared-agent replacement cannot be rolled back because the SSH
 * agent protocol does not export loaded private identities. Keep the legacy
 * enum token source-compatible, but reject that mode before probing commands,
 * reading keys, changing the process environment, or invoking ssh-add. */

#include "test.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_runner_calls;

static int count_and_reject_runner(const char *const argv[],
                                   const run_opts_t *opts,
                                   run_result_t *result) {
    (void)argv;
    g_runner_calls++;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 1;
    }
    return -1;
}

static int make_key_account(char *root, size_t root_size,
                            char *key, size_t key_size,
                            account_t *account) {
    static const char private_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "ar09-system-mode-fixture\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

    if (root_size < sizeof("/tmp/gsw-ar09-system.XXXXXX")) return -1;
    snprintf(root, root_size, "/tmp/gsw-ar09-system.XXXXXX");
    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        safe_snprintf(key, key_size, "%s/id_test", root) != 0 ||
        write_string_to_file(key, private_key, 0600) != 0) {
        return -1;
    }
    memset(account, 0, sizeof(*account));
    account->id = 1;
    account->ssh_enabled = true;
    return safe_strncpy(account->name, "system", sizeof(account->name)) == 0 &&
                   safe_strncpy(account->email, "system@example.test",
                                sizeof(account->email)) == 0 &&
                   safe_strncpy(account->ssh_key_path, key,
                                sizeof(account->ssh_key_path)) == 0
               ? 0
               : -1;
}

TEST(system_mode_init_is_rejected_without_mutating_caller_state) {
    ssh_config_t config;
    ssh_config_t before;

    memset(&config, 0x5a, sizeof(config));
    before = config;
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", "/tmp/existing-agent.sock", 1), 0);

    CHECK_EQ_INT(ssh_manager_init(&config, SSH_AGENT_SYSTEM), -1);
    CHECK(memcmp(&config, &before, sizeof(config)) == 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(strstr(get_last_error()->message, "deprecated") != NULL);
    CHECK(strstr(get_last_error()->message, "isolated") != NULL);
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), "/tmp/existing-agent.sock");

    unsetenv("SSH_AUTH_SOCK");
}

TEST(system_mode_switch_is_rejected_before_shared_agent_mutation) {
    char root[128];
    char key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;

    CHECK_EQ_INT(make_key_account(root, sizeof(root), key, sizeof(key),
                                  &account), 0);
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_SYSTEM;
    config.agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(config.agent_socket_path,
                              "/tmp/existing-agent.sock",
                              sizeof(config.agent_socket_path)), 0);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    g_runner_calls = 0;
    previous_runner = run_set_runner(count_and_reject_runner);

    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);

    run_set_runner(previous_runner);
    CHECK_EQ_INT(g_runner_calls, 0);
    CHECK(getenv("SSH_AUTH_SOCK") == NULL);
    CHECK(getenv("SSH_AGENT_PID") == NULL);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(strstr(get_last_error()->message, "deprecated") != NULL);
    CHECK(strstr(get_last_error()->message, "cannot restore") != NULL);

    ts_rm_rf(root);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(system_mode_init_is_rejected_without_mutating_caller_state);
    RUN_TEST(system_mode_switch_is_rejected_before_shared_agent_mutation);
TEST_MAIN_END()
