/* AR-09 M30: a successful public SSH-key listing is always complete. */
#include "test.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <signal.h>
#include <stdbool.h>
#include <string.h>

static const char *g_listing;
static size_t g_listing_len;
static int g_exit_code;
static int g_term_signal;
static int g_runner_rc;
static bool g_spawned;
static bool g_timed_out;
static bool g_force_truncated;
static int g_calls;
static int g_argc;
static char g_argv[4][32];

static int listing_runner(const char *const argv[], const run_opts_t *opts,
                          run_result_t *result) {
    size_t full_len = g_listing_len;
    size_t copied = 0U;
    int i;

    g_calls++;
    g_argc = 0;
    for (i = 0; argv && argv[i] && i < 4; i++) {
        CHECK_EQ_INT(safe_strncpy(g_argv[i], argv[i],
                                  sizeof(g_argv[i])), 0);
        g_argc++;
    }

    if (opts && opts->out && opts->out_size > 0U) {
        copied = full_len;
        if (copied >= opts->out_size) copied = opts->out_size - 1U;
        if (copied > 0U) memcpy(opts->out, g_listing, copied);
        opts->out[copied] = '\0';
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = g_spawned;
        result->timed_out = g_timed_out;
        result->exit_code = g_exit_code;
        result->term_signal = g_term_signal;
        result->out_len = copied;
        result->out_truncated = g_force_truncated || copied != full_len;
    }
    return g_runner_rc;
}

static void make_config(ssh_config_t *config) {
    memset(config, 0, sizeof(*config));
    config->agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(config->agent_socket_path,
                              "/tmp/ar09-listing-agent.sock",
                              sizeof(config->agent_socket_path)), 0);
}

static void script_listing(const char *listing, int exit_code,
                           bool truncated) {
    g_listing = listing;
    g_listing_len = listing ? strlen(listing) : 0U;
    g_exit_code = exit_code;
    g_term_signal = 0;
    g_runner_rc = exit_code == 0 ? 0 : -1;
    g_spawned = true;
    g_timed_out = false;
    g_force_truncated = truncated;
    g_calls = 0;
    g_argc = 0;
}

static void script_listing_bytes(const char *listing, size_t listing_len,
                                 int exit_code, bool truncated) {
    script_listing(NULL, exit_code, truncated);
    g_listing = listing;
    g_listing_len = listing_len;
}

static void script_failed_outcome(const char *listing, bool spawned,
                                  bool timed_out, int term_signal,
                                  int exit_code) {
    script_listing(listing, exit_code, false);
    g_spawned = spawned;
    g_timed_out = timed_out;
    g_term_signal = term_signal;
    g_runner_rc = -1;
}

TEST(complete_listing_preserves_normal_output) {
    static const char listing[] =
        "256 SHA256:one account-one (ED25519)\n"
        "4096 SHA256:two account-two (RSA)\n";
    ssh_config_t config;
    char output[sizeof(listing)];
    command_runner_fn previous;

    make_config(&config);
    script_listing(listing, 0, false);
    previous = run_set_runner(listing_runner);

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), 0);
    CHECK_STR_EQ(output,
                 "256 SHA256:one account-one (ED25519)\n"
                 "4096 SHA256:two account-two (RSA)");
    CHECK_EQ_INT(g_calls, 1);
    CHECK_EQ_INT(g_argc, 2);
    CHECK_STR_EQ(g_argv[0], "ssh-add");
    CHECK_STR_EQ(g_argv[1], "-l");

    run_set_runner(previous);
}

TEST(exact_fit_listing_is_successful) {
    static const char listing[] = "256 SHA256:boundary exact-fit (ED25519)\n";
    ssh_config_t config;
    char output[sizeof(listing)];
    command_runner_fn previous;

    make_config(&config);
    script_listing(listing, 0, false);
    previous = run_set_runner(listing_runner);

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), 0);
    CHECK_STR_EQ(output, "256 SHA256:boundary exact-fit (ED25519)");

    run_set_runner(previous);
}

TEST(oversized_listing_never_returns_a_successful_prefix) {
    static const char listing[] =
        "256 SHA256:first first-key (ED25519)\n"
        "256 SHA256:foreign second-key (ED25519)\n";
    ssh_config_t config;
    char output[32];
    command_runner_fn previous;

    make_config(&config);
    script_listing(listing, 0, false);
    previous = run_set_runner(listing_runner);
    memset(output, 'X', sizeof(output));

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(get_last_error()->message, "incomplete") != NULL);
    CHECK_EQ_INT(g_calls, 1);

    run_set_runner(previous);
}

TEST(explicit_runner_truncation_never_returns_success) {
    ssh_config_t config;
    char output[128];
    command_runner_fn previous;

    make_config(&config);
    script_listing("256 SHA256:visible key (ED25519)\n", 0, true);
    previous = run_set_runner(listing_runner);

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_AGENT_FAILED);

    run_set_runner(previous);
}

TEST(binary_listing_never_returns_a_successful_prefix) {
    static const char listing[] = {
        '2', '5', '6', ' ', 'S', 'H', 'A', '\0', 'h', 'i', 'd', 'd', 'e',
        'n', '\n'};
    ssh_config_t config;
    char output[64];
    command_runner_fn previous;

    make_config(&config);
    script_listing_bytes(listing, sizeof(listing), 0, false);
    previous = run_set_runner(listing_runner);

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(get_last_error()->message, "binary") != NULL);

    run_set_runner(previous);
}

TEST(nonzero_agent_result_keeps_legacy_failure_text) {
    ssh_config_t config;
    char output[64];
    command_runner_fn previous;

    make_config(&config);
    script_listing("The agent has no identities.\n", 1, false);
    previous = run_set_runner(listing_runner);
    clear_error();

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "No keys loaded in SSH agent");
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);

    run_set_runner(previous);
}

TEST(exit_two_is_an_actionable_agent_failure) {
    const error_context_t *error;
    ssh_config_t config;
    char output[128];
    command_runner_fn previous;

    make_config(&config);
    script_failed_outcome("Error connecting to agent.\n", true, false, 0, 2);
    previous = run_set_runner(listing_runner);
    clear_error();

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(error->message, "ssh-add") != NULL);
    CHECK(strstr(error->message, "exited with status 2") != NULL);
    CHECK(strstr(error->message, "exit_status=2") != NULL);
    CHECK(strstr(error->message, "No keys loaded") == NULL);

    run_set_runner(previous);
}

TEST(spawn_failure_is_an_actionable_agent_failure) {
    const error_context_t *error;
    ssh_config_t config;
    char output[128];
    command_runner_fn previous;

    make_config(&config);
    script_failed_outcome("", false, false, 0, -1);
    previous = run_set_runner(listing_runner);
    clear_error();

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(error->message, "could not be started") != NULL);
    CHECK(strstr(error->message, "spawned=false") != NULL);
    CHECK(strstr(error->message, "No keys loaded") == NULL);

    run_set_runner(previous);
}

TEST(timeout_is_an_actionable_agent_failure) {
    const error_context_t *error;
    ssh_config_t config;
    char output[128];
    command_runner_fn previous;

    make_config(&config);
    script_failed_outcome("", true, true, SIGKILL, -1);
    previous = run_set_runner(listing_runner);
    clear_error();

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(error->message, "timed out") != NULL);
    CHECK(strstr(error->message, "timed_out=true") != NULL);
    CHECK(strstr(error->message, "No keys loaded") == NULL);

    run_set_runner(previous);
}

TEST(signal_is_an_actionable_agent_failure) {
    const error_context_t *error;
    ssh_config_t config;
    char output[128];
    char signal_detail[32];
    command_runner_fn previous;

    make_config(&config);
    script_failed_outcome("", true, false, SIGTERM, -1);
    previous = run_set_runner(listing_runner);
    clear_error();

    CHECK_EQ_INT(ssh_list_keys(&config, output, sizeof(output)), -1);
    CHECK_STR_EQ(output, "");
    error = get_last_error();
    CHECK_EQ_INT(error->code, ERR_SSH_AGENT_FAILED);
    CHECK(strstr(error->message, "terminated by signal") != NULL);
    CHECK(snprintf(signal_detail, sizeof(signal_detail), "signal=%d",
                   SIGTERM) > 0);
    CHECK(strstr(error->message, signal_detail) != NULL);
    CHECK(strstr(error->message, "No keys loaded") == NULL);

    run_set_runner(previous);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(complete_listing_preserves_normal_output);
    RUN_TEST(exact_fit_listing_is_successful);
    RUN_TEST(oversized_listing_never_returns_a_successful_prefix);
    RUN_TEST(explicit_runner_truncation_never_returns_success);
    RUN_TEST(binary_listing_never_returns_a_successful_prefix);
    RUN_TEST(nonzero_agent_result_keeps_legacy_failure_text);
    RUN_TEST(exit_two_is_an_actionable_agent_failure);
    RUN_TEST(spawn_failure_is_an_actionable_agent_failure);
    RUN_TEST(timeout_is_an_actionable_agent_failure);
    RUN_TEST(signal_is_an_actionable_agent_failure);
TEST_MAIN_END()
