/* AR-08 T12: an SSH connection probe proves both the child outcome and a
 * complete provider greeting. Direct probes must restrict authentication to
 * the account key instead of silently succeeding through an unrelated agent. */
#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef enum {
    CONNECTION_SCRIPTED = 0,
    CONNECTION_CAUSAL_REJECT_ACCOUNT_KEY,
    CONNECTION_CAUSAL_ACCEPT_ACCOUNT_KEY,
    CONNECTION_CAUSAL_ACCEPT_MANAGED_ALIAS
} connection_runner_mode_t;

static connection_runner_mode_t g_mode;
static const char *g_output;
static int g_exit_code;
static int g_term_signal;
static bool g_spawned;
static bool g_truncated;
static char g_argv[16][MAX_PATH_LEN];
static int g_argc;

static bool argv_has_option_value(const char *option, const char *value) {
    int i;

    for (i = 0; i + 1 < g_argc; i++) {
        if (strcmp(g_argv[i], option) == 0 &&
            strcmp(g_argv[i + 1], value) == 0) {
            return true;
        }
    }
    return false;
}

static void publish_result(const run_opts_t *opts, run_result_t *result,
                           const char *output, int exit_code,
                           int term_signal, bool spawned,
                           bool truncated) {
    size_t output_len = output ? strlen(output) : 0U;
    size_t copied = 0U;

    if (opts && opts->out && opts->out_size > 0U) {
        copied = output_len;
        if (copied >= opts->out_size) copied = opts->out_size - 1U;
        if (copied > 0U) memcpy(opts->out, output, copied);
        opts->out[copied] = '\0';
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = spawned;
        result->exit_code = exit_code;
        result->term_signal = term_signal;
        result->out_len = copied;
        result->out_truncated = truncated || copied != output_len;
    }
}

static int connection_runner(const char *const argv[],
                             const run_opts_t *opts,
                             run_result_t *result) {
    const char *output = g_output;
    int exit_code = g_exit_code;
    int term_signal = g_term_signal;
    bool spawned = g_spawned;
    bool truncated = g_truncated;
    bool strict_identity;
    bool config_isolated;
    bool exact_identity;
    bool destination_pinned;
    int i;

    g_argc = 0;
    for (i = 0; argv && argv[i] && i < 16; i++) {
        CHECK_EQ_INT(safe_strncpy(g_argv[i], argv[i],
                                  sizeof(g_argv[i])), 0);
        g_argc++;
    }

    strict_identity = argv_has_option_value("-o", "IdentitiesOnly=yes");
    config_isolated = argv_has_option_value("-F", "none");
    exact_identity = strict_identity && config_isolated &&
                     argv_has_option_value("-i",
                                           "/tmp/intended-account-key");
    destination_pinned =
        argv_has_option_value("-o", "HostName=github.com");
    if (g_mode == CONNECTION_CAUSAL_REJECT_ACCOUNT_KEY) {
        /* Model an unrelated IdentityFile inherited from ssh_config and
         * accepted by the server. IdentitiesOnly alone still offers it; only
         * config isolation plus the explicit account key makes this a causal
         * probe of the intended identity. */
        output = exact_identity
                     ? "git@github.com: Permission denied (publickey)."
                     : "Hi unrelated-user! You've successfully authenticated, "
                       "but GitHub does not provide shell access.";
        exit_code = exact_identity ? 255 : 1;
        term_signal = 0;
        spawned = true;
        truncated = false;
    } else if (g_mode == CONNECTION_CAUSAL_ACCEPT_ACCOUNT_KEY) {
        output = exact_identity
                     ? "Hi intended-user! You've successfully authenticated, "
                       "but GitHub does not provide shell access."
                     : "git@github.com: exact identity isolation missing";
        exit_code = exact_identity ? 1 : 255;
        term_signal = 0;
        spawned = true;
        truncated = false;
    } else if (g_mode == CONNECTION_CAUSAL_ACCEPT_MANAGED_ALIAS) {
        bool exact_alias = exact_identity && destination_pinned &&
                           g_argc > 0 &&
                           strcmp(g_argv[g_argc - 1], "work-github") == 0;
        output = exact_alias
                     ? "Hi intended-user! You've successfully authenticated, "
                       "but GitHub does not provide shell access."
                     : "git@github.com: managed alias isolation missing";
        exit_code = exact_alias ? 1 : 255;
        term_signal = 0;
        spawned = true;
        truncated = false;
    }

    publish_result(opts, result, output, exit_code, term_signal, spawned,
                   truncated);
    return spawned && term_signal == 0 && exit_code == 0 ? 0 : -1;
}

static void make_account(account_t *account, bool with_alias) {
    memset(account, 0, sizeof(*account));
    account->ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account->name, "work",
                              sizeof(account->name)), 0);
    CHECK_EQ_INT(safe_strncpy(account->ssh_key_path,
                              "/tmp/intended-account-key",
                              sizeof(account->ssh_key_path)), 0);
    if (with_alias) {
        CHECK_EQ_INT(safe_strncpy(account->ssh_host_alias, "work-github",
                                  sizeof(account->ssh_host_alias)), 0);
        CHECK_EQ_INT(safe_strncpy(account->ssh_hostname, "github.com",
                                  sizeof(account->ssh_hostname)), 0);
    }
}

static int scripted_probe(const account_t *account, const char *output,
                          int exit_code, int term_signal, bool spawned,
                          bool truncated) {
    g_mode = CONNECTION_SCRIPTED;
    g_output = output;
    g_exit_code = exit_code;
    g_term_signal = term_signal;
    g_spawned = spawned;
    g_truncated = truncated;
    return ssh_test_connection(account, "git@github.com");
}

TEST(diagnostic_fragments_never_authenticate) {
    account_t account;
    command_runner_fn previous;
    const char *diagnostic =
        "ssh: successfully authenticated is only a diagnostic; "
        "Welcome to GitLab was expected; logged in as nobody; Hi failure; "
        "authentication successful was not observed";

    make_account(&account, true);
    previous = run_set_runner(connection_runner);
    CHECK_EQ_INT(scripted_probe(&account, diagnostic, 255, 0, true, false),
                 -1);
    CHECK_EQ_INT(scripted_probe(&account, diagnostic, 1, 0, true, false), -1);
    CHECK_EQ_INT(scripted_probe(&account, diagnostic, 0, 0, true, false), -1);
    run_set_runner(previous);
}

TEST(provider_greetings_require_exact_lines_and_exit_classes) {
    account_t account;
    command_runner_fn previous;
    const char *github =
        "Hi octocat! You've successfully authenticated, but GitHub does not "
        "provide shell access.";
    const char *gitlab = "Welcome to GitLab, @alice!";
    const char *bitbucket_legacy =
        "logged in as alice.\n"
        "You can use git or hg to connect to Bitbucket. Shell access is "
        "disabled.";
    const char *bitbucket_current =
        "authenticated via ssh key.\n\n"
        "You can use git to connect to Bitbucket. Shell access is disabled";

    make_account(&account, true);
    previous = run_set_runner(connection_runner);

    CHECK_EQ_INT(scripted_probe(&account, github, 1, 0, true, false), 0);
    CHECK_EQ_INT(scripted_probe(&account, github, 0, 0, true, false), -1);
    CHECK_EQ_INT(scripted_probe(&account, github, 1, SIGTERM, true, false),
                 -1);
    CHECK_EQ_INT(scripted_probe(&account, github, 1, 0, false, false), -1);
    CHECK_EQ_INT(scripted_probe(&account, github, 1, 0, true, true), -1);
    CHECK_EQ_INT(scripted_probe(
                     &account,
                     "Hi octocat! You've successfully authenticated, but "
                     "GitHub does not provide shell access. trailing",
                     1, 0, true, false),
                 -1);

    CHECK_EQ_INT(scripted_probe(&account, gitlab, 0, 0, true, false), 0);
    CHECK_EQ_INT(scripted_probe(&account, gitlab, 1, 0, true, false), -1);
    CHECK_EQ_INT(scripted_probe(&account, "Welcome to GitLab, Anonymous!", 0,
                                0, true, false),
                 -1);
    CHECK_EQ_INT(scripted_probe(&account,
                                "Welcome to GitLab, @alice! trailing", 0, 0,
                                true, false),
                 -1);

    CHECK_EQ_INT(scripted_probe(&account, bitbucket_legacy, 0, 0, true,
                                false),
                 0);
    CHECK_EQ_INT(scripted_probe(&account, bitbucket_current, 0, 0, true,
                                false),
                 0);
    CHECK_EQ_INT(scripted_probe(&account, bitbucket_current, 1, 0, true,
                                false),
                 -1);
    CHECK_EQ_INT(scripted_probe(&account, "logged in as alice.", 0, 0, true,
                                false),
                 -1);
    run_set_runner(previous);
}

TEST(direct_probe_offers_only_the_intended_account_key) {
    account_t account;
    command_runner_fn previous;

    make_account(&account, false);
    previous = run_set_runner(connection_runner);

    g_mode = CONNECTION_CAUSAL_REJECT_ACCOUNT_KEY;
    CHECK_EQ_INT(ssh_test_connection(&account, "git@github.com"), -1);
    CHECK_EQ_INT(g_argc, 13);
    CHECK_STR_EQ(g_argv[0], "ssh");
    CHECK_STR_EQ(g_argv[1], "-T");
    CHECK_STR_EQ(g_argv[2], "-F");
    CHECK_STR_EQ(g_argv[3], "none");
    CHECK_STR_EQ(g_argv[4], "-o");
    CHECK_STR_EQ(g_argv[5], "ConnectTimeout=5");
    CHECK_STR_EQ(g_argv[6], "-o");
    CHECK_STR_EQ(g_argv[7], "BatchMode=yes");
    CHECK_STR_EQ(g_argv[8], "-o");
    CHECK_STR_EQ(g_argv[9], "IdentitiesOnly=yes");
    CHECK_STR_EQ(g_argv[10], "-i");
    CHECK_STR_EQ(g_argv[11], "/tmp/intended-account-key");
    CHECK_STR_EQ(g_argv[12], "git@github.com");

    g_mode = CONNECTION_CAUSAL_ACCEPT_ACCOUNT_KEY;
    CHECK_EQ_INT(ssh_test_connection(&account, "git@github.com"), 0);
    run_set_runner(previous);
}

TEST(managed_alias_probe_ignores_shared_config_and_pins_destination) {
    account_t account;
    command_runner_fn previous;

    make_account(&account, true);
    previous = run_set_runner(connection_runner);

    g_mode = CONNECTION_CAUSAL_ACCEPT_MANAGED_ALIAS;
    CHECK_EQ_INT(ssh_test_connection(&account, "work-github"), 0);
    CHECK_EQ_INT(g_argc, 15);
    CHECK_STR_EQ(g_argv[0], "ssh");
    CHECK_STR_EQ(g_argv[1], "-T");
    CHECK_STR_EQ(g_argv[2], "-F");
    CHECK_STR_EQ(g_argv[3], "none");
    CHECK_STR_EQ(g_argv[4], "-o");
    CHECK_STR_EQ(g_argv[5], "ConnectTimeout=5");
    CHECK_STR_EQ(g_argv[6], "-o");
    CHECK_STR_EQ(g_argv[7], "BatchMode=yes");
    CHECK_STR_EQ(g_argv[8], "-o");
    CHECK_STR_EQ(g_argv[9], "IdentitiesOnly=yes");
    CHECK_STR_EQ(g_argv[10], "-i");
    CHECK_STR_EQ(g_argv[11], "/tmp/intended-account-key");
    CHECK_STR_EQ(g_argv[12], "-o");
    CHECK_STR_EQ(g_argv[13], "HostName=github.com");
    CHECK_STR_EQ(g_argv[14], "work-github");

    run_set_runner(previous);
}

TEST(managed_alias_probe_rejects_a_missing_canonical_destination) {
    account_t account;
    command_runner_fn previous;

    make_account(&account, true);
    account.ssh_hostname[0] = '\0';
    previous = run_set_runner(connection_runner);
    g_argc = 99;

    CHECK_EQ_INT(scripted_probe(
                     &account,
                     "Hi unrelated-user! You've successfully authenticated, "
                     "but GitHub does not provide shell access.",
                     1, 0, true, false),
                 -1);
    CHECK_EQ_INT(g_argc, 99);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);

    run_set_runner(previous);
}

TEST(managed_alias_probe_rejects_host_port_without_running_ssh) {
    account_t account;
    command_runner_fn previous;

    make_account(&account, true);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname,
                              "git.example.test:2222",
                              sizeof(account.ssh_hostname)), 0);
    previous = run_set_runner(connection_runner);
    g_argc = 99;

    CHECK_EQ_INT(scripted_probe(
                     &account,
                     "Hi intended-user! You've successfully authenticated, "
                     "but GitHub does not provide shell access.",
                     1, 0, true, false),
                 -1);
    CHECK_EQ_INT(g_argc, 99);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);

    run_set_runner(previous);
}

TEST(managed_git_command_ignores_shared_config_and_pins_destination) {
    account_t account;
    char command[GIT_CONFIG_VALUE_MAX];

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    make_account(&account, true);
    CHECK_EQ_INT(git_expected_ssh_command(&account, command,
                                          sizeof(command)), 0);
    CHECK(strstr(command, " -F none ") != NULL);
    CHECK(strstr(command, " -i '/tmp/intended-account-key'") != NULL);
    CHECK(strstr(command, " -o IdentitiesOnly=yes") != NULL);
    CHECK(strstr(command, " -o HostName='github.com'") != NULL);
}

TEST(managed_git_command_rejects_host_port_destination) {
    account_t account;
    char command[GIT_CONFIG_VALUE_MAX];

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    make_account(&account, true);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname,
                              "git.example.test:2222",
                              sizeof(account.ssh_hostname)), 0);
    memset(command, 'X', sizeof(command));

    CHECK_EQ_INT(git_expected_ssh_command(&account, command,
                                          sizeof(command)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(command[0], '\0');
}

TEST(managed_ipv6_destination_is_preserved_in_probe) {
    static const char ipv6_hostname[] = "2001:db8::1";
    account_t account;
    command_runner_fn previous;

    make_account(&account, true);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname, ipv6_hostname,
                              sizeof(account.ssh_hostname)), 0);
    previous = run_set_runner(connection_runner);

    CHECK_EQ_INT(scripted_probe(
                     &account,
                     "Hi intended-user! You've successfully authenticated, "
                     "but GitHub does not provide shell access.",
                     1, 0, true, false),
                 0);
    CHECK_EQ_INT(g_argc, 15);
    CHECK_STR_EQ(g_argv[13], "HostName=2001:db8::1");
    CHECK_STR_EQ(g_argv[14], "work-github");
    run_set_runner(previous);
}

TEST(managed_ipv6_destination_is_preserved_in_git_command) {
    account_t account;
    char command[GIT_CONFIG_VALUE_MAX];

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    make_account(&account, true);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname, "2001:db8::1",
                              sizeof(account.ssh_hostname)), 0);
    CHECK_EQ_INT(git_expected_ssh_command(&account, command,
                                          sizeof(command)), 0);
    CHECK(strstr(command, " -o HostName='2001:db8::1'") != NULL);
}

static bool output_has_identity_file(const char *output, const char *path) {
    static const char prefix[] = "identityfile ";
    const char *line = output;
    size_t path_len = strlen(path);

    while (line && *line) {
        const char *newline = strchr(line, '\n');
        size_t line_len = newline ? (size_t)(newline - line) : strlen(line);
        if (line_len > 0U && line[line_len - 1U] == '\r') line_len--;
        if (line_len == sizeof(prefix) - 1U + path_len &&
            memcmp(line, prefix, sizeof(prefix) - 1U) == 0 &&
            memcmp(line + sizeof(prefix) - 1U, path, path_len) == 0) {
            return true;
        }
        line = newline ? newline + 1 : NULL;
    }
    return false;
}

static size_t output_identity_file_count(const char *output) {
    static const char prefix[] = "identityfile ";
    const char *line = output;
    size_t count = 0U;

    while (line && *line) {
        const char *newline = strchr(line, '\n');
        size_t line_len = newline ? (size_t)(newline - line) : strlen(line);
        if (line_len >= sizeof(prefix) - 1U &&
            memcmp(line, prefix, sizeof(prefix) - 1U) == 0) {
            count++;
        }
        line = newline ? newline + 1 : NULL;
    }
    return count;
}

static bool output_has_setting(const char *output, const char *setting) {
    const char *line = output;
    size_t setting_len = strlen(setting);

    while (line && *line) {
        const char *newline = strchr(line, '\n');
        size_t line_len = newline ? (size_t)(newline - line) : strlen(line);
        if (line_len > 0U && line[line_len - 1U] == '\r') line_len--;
        if (line_len == setting_len &&
            memcmp(line, setting, setting_len) == 0) {
            return true;
        }
        line = newline ? newline + 1 : NULL;
    }
    return false;
}

TEST(openssh_effective_config_confirms_direct_probe_isolation) {
    static const char foreign_key[] = "/tmp/foreign-inherited-key";
    static const char intended_key[] = "/dev/null";
    char fixture_dir[] = "/tmp/gsar08sshconfigXXXXXX";
    char fixture_config[MAX_PATH_LEN];
    char output[32768];
    run_opts_t opts;
    run_result_t result;

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    CHECK(ts_mkdtemp(fixture_dir) != NULL);
    if (!path_exists(fixture_dir)) return;
    CHECK_EQ_INT(safe_snprintf(fixture_config, sizeof(fixture_config),
                               "%s/config", fixture_dir), 0);
    CHECK_EQ_INT(write_string_to_file(
                     fixture_config,
                     "Host exact-probe.invalid\n"
                     "  IdentityFile /tmp/foreign-inherited-key\n",
                     0600), 0);

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    {
        const char *const inherited_argv[] = {
            "ssh", "-G", "-F", fixture_config, "-o",
            "IdentitiesOnly=yes", "-i", intended_key,
            "exact-probe.invalid", NULL};
        CHECK_EQ_INT(run_argv(inherited_argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_identity_file(output, intended_key));
    CHECK(output_has_identity_file(output, foreign_key));

    memset(output, 0, sizeof(output));
    memset(&result, 0, sizeof(result));
    {
        const char *const isolated_argv[] = {
            "ssh", "-G", "-F", "none", "-o",
            "IdentitiesOnly=yes", "-i", intended_key,
            "exact-probe.invalid", NULL};
        CHECK_EQ_INT(run_argv(isolated_argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_identity_file(output, intended_key));
    CHECK(!output_has_identity_file(output, foreign_key));
}

TEST(openssh_effective_config_confirms_managed_alias_isolation) {
    static const char intended_key[] = "/dev/null";
    char fixture_dir[] = "/tmp/gsar09sshaliasXXXXXX";
    char fixture_config[MAX_PATH_LEN];
    char output[32768];
    run_opts_t opts;
    run_result_t result;

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    CHECK(ts_mkdtemp(fixture_dir) != NULL);
    if (!path_exists(fixture_dir)) return;
    CHECK_EQ_INT(safe_snprintf(fixture_config, sizeof(fixture_config),
                               "%s/config", fixture_dir), 0);
    CHECK_EQ_INT(write_string_to_file(
                     fixture_config,
                     "Host *\n"
                     "  HostName preceding-wildcard.invalid\n"
                     "  IdentityFile /tmp/preceding-wildcard-key\n"
                     "Host work-github\n"
                     "  HostName exact-middle.invalid\n"
                     "  IdentityFile /tmp/exact-middle-key\n"
                     "Host *\n"
                     "  IdentityFile /tmp/following-wildcard-key\n"
                     "Host work-github\n"
                     "  IdentityFile /tmp/following-exact-key\n",
                     0600), 0);

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    {
        const char *const inherited_argv[] = {
            "ssh", "-G", "-F", fixture_config, "-o",
            "IdentitiesOnly=yes", "-i", intended_key,
            "work-github", NULL};
        CHECK_EQ_INT(run_argv(inherited_argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_setting(output,
                             "hostname preceding-wildcard.invalid"));
    CHECK(output_has_identity_file(output, intended_key));
    CHECK(output_has_identity_file(output, "/tmp/preceding-wildcard-key"));
    CHECK(output_has_identity_file(output, "/tmp/exact-middle-key"));
    CHECK(output_has_identity_file(output, "/tmp/following-wildcard-key"));
    CHECK(output_has_identity_file(output, "/tmp/following-exact-key"));

    memset(output, 0, sizeof(output));
    memset(&result, 0, sizeof(result));
    {
        const char *const isolated_argv[] = {
            "ssh", "-G", "-F", "none", "-o",
            "IdentitiesOnly=yes", "-i", intended_key, "-o",
            "HostName=github.com", "work-github", NULL};
        CHECK_EQ_INT(run_argv(isolated_argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_setting(output, "hostname github.com"));
    CHECK(output_has_identity_file(output, intended_key));
    CHECK_EQ_INT((int)output_identity_file_count(output), 1);

    CHECK_EQ_INT(unlink(fixture_config), 0);
    CHECK_EQ_INT(rmdir(fixture_dir), 0);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(diagnostic_fragments_never_authenticate);
    RUN_TEST(provider_greetings_require_exact_lines_and_exit_classes);
    RUN_TEST(direct_probe_offers_only_the_intended_account_key);
    RUN_TEST(managed_alias_probe_ignores_shared_config_and_pins_destination);
    RUN_TEST(managed_alias_probe_rejects_a_missing_canonical_destination);
    RUN_TEST(managed_alias_probe_rejects_host_port_without_running_ssh);
    RUN_TEST(managed_git_command_ignores_shared_config_and_pins_destination);
    RUN_TEST(managed_git_command_rejects_host_port_destination);
    RUN_TEST(managed_ipv6_destination_is_preserved_in_probe);
    RUN_TEST(managed_ipv6_destination_is_preserved_in_git_command);
    RUN_TEST(openssh_effective_config_confirms_direct_probe_isolation);
    RUN_TEST(openssh_effective_config_confirms_managed_alias_isolation);
TEST_MAIN_END()
