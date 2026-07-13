/* AR-08 T8: Git signing model, bounded worktree inspection, effective SSH
 * environment precedence, and truthful list truncation. */
#define _POSIX_C_SOURCE 200809L

#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "utils.h"

#include <limits.h>

void git_ops_test_reset_caches(void);

typedef struct {
    char *value;
    bool present;
} saved_env_t;

typedef struct {
    char base[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char xdg[MAX_PATH_LEN];
    char repo[MAX_PATH_LEN];
    char global_config[MAX_PATH_LEN];
    char key[MAX_PATH_LEN];
    char saved_cwd[MAX_PATH_LEN];
    saved_env_t home_env;
    saved_env_t xdg_env;
    saved_env_t global_env;
    saved_env_t nosystem_env;
    saved_env_t config_count_env;
    saved_env_t ssh_command_env;
    saved_env_t ssh_env;
    saved_env_t trace_env;
    bool initialized;
} git_fixture_t;

static const char *const g_gpg_model_keys[] = {
    "gpg.format",
    "gpg.program",
    "gpg.openpgp.program",
    "gpg.x509.program",
    "gpg.ssh.program"
};

static saved_env_t save_env(const char *name) {
    saved_env_t saved;
    const char *value = getenv(name);
    saved.present = value != NULL;
    saved.value = value ? strdup(value) : NULL;
    return saved;
}

static void restore_env(const char *name, saved_env_t *saved) {
    if (saved->present && saved->value) {
        (void)setenv(name, saved->value, 1);
    } else {
        (void)unsetenv(name);
    }
    free(saved->value);
    saved->value = NULL;
}

static int write_text_file(const char *path, const char *contents,
                           mode_t mode) {
    FILE *file = fopen(path, "w");
    int failed;
    if (!file) return -1;
    failed = fputs(contents, file) == EOF;
    if (fclose(file) != 0) failed = 1;
    if (failed) return -1;
    return chmod(path, mode);
}

static int run_command(const char *const argv[], char *output,
                       size_t output_size, bool merge_stderr,
                       run_result_t *result) {
    run_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    if (output && output_size > 0) {
        output[0] = '\0';
        opts.out = output;
        opts.out_size = output_size;
    }
    opts.merge_stderr = merge_stderr;
    opts.stderr_to_devnull = !merge_stderr;
    if (result) memset(result, 0, sizeof(*result));
    return run_argv(argv, &opts, result);
}

static int run_git(const char *const argv[]) {
    run_result_t result;
    return run_command(argv, NULL, 0, false, &result);
}

static bool fixture_init(git_fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->home_env = save_env("HOME");
    fixture->xdg_env = save_env("XDG_CONFIG_HOME");
    fixture->global_env = save_env("GIT_CONFIG_GLOBAL");
    fixture->nosystem_env = save_env("GIT_CONFIG_NOSYSTEM");
    fixture->config_count_env = save_env("GIT_CONFIG_COUNT");
    fixture->ssh_command_env = save_env("GIT_SSH_COMMAND");
    fixture->ssh_env = save_env("GIT_SSH");
    fixture->trace_env = save_env("GIT_TRACE");
    if (!getcwd(fixture->saved_cwd, sizeof(fixture->saved_cwd))) return false;
    if ((size_t)snprintf(fixture->base, sizeof(fixture->base),
                         "/tmp/gsw_ar08_git_XXXXXX") >= sizeof(fixture->base) ||
        !ts_mkdtemp(fixture->base) ||
        (size_t)snprintf(fixture->home, sizeof(fixture->home), "%s/home",
                         fixture->base) >= sizeof(fixture->home) ||
        (size_t)snprintf(fixture->xdg, sizeof(fixture->xdg), "%s/xdg",
                         fixture->base) >= sizeof(fixture->xdg) ||
        (size_t)snprintf(fixture->repo, sizeof(fixture->repo), "%s/repo",
                         fixture->base) >= sizeof(fixture->repo) ||
        (size_t)snprintf(fixture->global_config,
                         sizeof(fixture->global_config), "%s/global.gitconfig",
                         fixture->base) >= sizeof(fixture->global_config) ||
        (size_t)snprintf(fixture->key, sizeof(fixture->key), "%s/id_test",
                         fixture->base) >= sizeof(fixture->key) ||
        mkdir(fixture->home, 0700) != 0 || mkdir(fixture->xdg, 0700) != 0 ||
        mkdir(fixture->repo, 0700) != 0 ||
        write_text_file(fixture->key, "fixture key\n", 0600) != 0 ||
        setenv("HOME", fixture->home, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", fixture->xdg, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", fixture->global_config, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        unsetenv("GIT_CONFIG_COUNT") != 0 ||
        unsetenv("GIT_SSH_COMMAND") != 0 || unsetenv("GIT_SSH") != 0 ||
        unsetenv("GIT_TRACE") != 0 || chdir(fixture->repo) != 0) {
        return false;
    }
    {
        const char *const init[] = { "git", "init", "-q", NULL };
        if (run_git(init) != 0) return false;
    }
    fixture->initialized = true;
    git_ops_test_reset_caches();
    return true;
}

static void fixture_cleanup(git_fixture_t *fixture) {
    git_ops_test_reset_caches();
    if (fixture->saved_cwd[0] != '\0' && chdir(fixture->saved_cwd) != 0) {
        perror("restore test working directory");
    }
    restore_env("GIT_TRACE", &fixture->trace_env);
    restore_env("GIT_SSH", &fixture->ssh_env);
    restore_env("GIT_SSH_COMMAND", &fixture->ssh_command_env);
    restore_env("GIT_CONFIG_COUNT", &fixture->config_count_env);
    restore_env("GIT_CONFIG_NOSYSTEM", &fixture->nosystem_env);
    restore_env("GIT_CONFIG_GLOBAL", &fixture->global_env);
    restore_env("XDG_CONFIG_HOME", &fixture->xdg_env);
    restore_env("HOME", &fixture->home_env);
    fixture->initialized = false;
}

static int git_set(const char *scope, const char *key, const char *value) {
    const char *const argv[] = { "git", "config", scope, key, value, NULL };
    return run_git(argv);
}

static int git_add(const char *scope, const char *key, const char *value) {
    const char *const argv[] = {
        "git", "config", scope, "--add", key, value, NULL
    };
    return run_git(argv);
}

static int git_unset_all(const char *scope, const char *key) {
    const char *const argv[] = {
        "git", "config", scope, "--unset-all", key, NULL
    };
    return run_git(argv);
}

static int git_get_all(const char *scope, const char *key, char *output,
                       size_t output_size) {
    const char *const argv[] = {
        "git", "config", scope, "--get-all", key, NULL
    };
    run_result_t result;
    int rc = run_command(argv, output, output_size, false, &result);
    if (rc == 0 && result.out_truncated) return -1;
    return rc;
}

static account_t basic_account(const git_fixture_t *fixture, bool with_gpg) {
    account_t account;
    memset(&account, 0, sizeof(account));
    account.id = 8;
    (void)snprintf(account.name, sizeof(account.name), "AR08 Git User");
    (void)snprintf(account.email, sizeof(account.email),
                   "ar08-git@example.test");
    account.preferred_scope = GIT_SCOPE_GLOBAL;
    if (fixture) {
        (void)snprintf(account.ssh_key_path, sizeof(account.ssh_key_path),
                       "%s", fixture->key);
    }
    if (with_gpg) {
        account.gpg_enabled = true;
        account.gpg_signing_enabled = true;
        (void)snprintf(account.gpg_key_id, sizeof(account.gpg_key_id),
                       "0123456789ABCDEF0123456789ABCDEF01234567");
    }
    return account;
}

static int read_file(const char *path, char *output, size_t output_size) {
    FILE *file = fopen(path, "r");
    size_t length;
    if (!file || output_size == 0) {
        if (file) fclose(file);
        return -1;
    }
    length = fread(output, 1, output_size - 1U, file);
    if (ferror(file) || fclose(file) != 0) return -1;
    output[length] = '\0';
    return 0;
}

static int create_marker_helper(const char *path, const char *marker,
                                const char *word) {
    char script[MAX_PATH_LEN * 2U];
    if ((size_t)snprintf(script, sizeof(script),
                         "#!/bin/sh\nprintf '%%s\\n' '%s' > '%s'\nexit 1\n",
                         word, marker) >= sizeof(script)) {
        return -1;
    }
    return write_text_file(path, script, 0700);
}

TEST(real_git_proves_narrow_ssh_environment_precedence_and_api_rejects_it) {
    git_fixture_t fixture;
    char core_helper[MAX_PATH_LEN];
    char env_helper[MAX_PATH_LEN];
    char legacy_helper[MAX_PATH_LEN];
    char marker[MAX_PATH_LEN];
    char marker_value[64];
    char old_name[128];
    char expected_ssh[GIT_CONFIG_VALUE_MAX];
    char restored_core[GIT_CONFIG_VALUE_MAX];
    git_current_config_t current;
    account_t account;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(core_helper, sizeof(core_helper), "%s/core-ssh",
                           fixture.base) < sizeof(core_helper));
    CHECK((size_t)snprintf(env_helper, sizeof(env_helper), "%s/env-ssh",
                           fixture.base) < sizeof(env_helper));
    CHECK((size_t)snprintf(legacy_helper, sizeof(legacy_helper),
                           "%s/legacy-ssh", fixture.base) <
          sizeof(legacy_helper));
    CHECK((size_t)snprintf(marker, sizeof(marker), "%s/ssh.marker",
                           fixture.base) < sizeof(marker));
    CHECK_EQ_INT(create_marker_helper(core_helper, marker, "core"), 0);
    CHECK_EQ_INT(create_marker_helper(env_helper, marker, "environment"), 0);
    CHECK_EQ_INT(create_marker_helper(legacy_helper, marker, "legacy"), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "Old Git User"), 0);
    CHECK_EQ_INT(git_set("--global", "user.email", "old@example.test"), 0);
    CHECK_EQ_INT(git_set("--global", "core.sshCommand", core_helper), 0);

    /* Real Git: GIT_SSH_COMMAND outranks core.sshCommand. */
    CHECK_EQ_INT(setenv("GIT_SSH_COMMAND", env_helper, 1), 0);
    {
        const char *const argv[] = {
            "git", "ls-remote", "ssh://ar08.invalid/repository", NULL
        };
        CHECK_EQ_INT(run_git(argv), -1);
    }
    CHECK_EQ_INT(read_file(marker, marker_value, sizeof(marker_value)), 0);
    CHECK_STR_EQ(marker_value, "environment\n");

    /* Real Git: legacy GIT_SSH does not outrank core.sshCommand. */
    CHECK_EQ_INT(unsetenv("GIT_SSH_COMMAND"), 0);
    CHECK_EQ_INT(setenv("GIT_SSH", legacy_helper, 1), 0);
    CHECK_EQ_INT(unlink(marker), 0);
    {
        const char *const argv[] = {
            "git", "ls-remote", "ssh://ar08.invalid/repository", NULL
        };
        CHECK_EQ_INT(run_git(argv), -1);
    }
    CHECK_EQ_INT(read_file(marker, marker_value, sizeof(marker_value)), 0);
    CHECK_STR_EQ(marker_value, "core\n");

    /* Without core.sshCommand, the legacy variable is used. */
    CHECK_EQ_INT(git_unset_all("--global", "core.sshCommand"), 0);
    CHECK_EQ_INT(unlink(marker), 0);
    {
        const char *const argv[] = {
            "git", "ls-remote", "ssh://ar08.invalid/repository", NULL
        };
        CHECK_EQ_INT(run_git(argv), -1);
    }
    CHECK_EQ_INT(read_file(marker, marker_value, sizeof(marker_value)), 0);
    CHECK_STR_EQ(marker_value, "legacy\n");

    CHECK_EQ_INT(git_set("--global", "core.sshCommand", core_helper), 0);
    CHECK_EQ_INT(setenv("GIT_SSH_COMMAND", env_helper, 1), 0);
    account = basic_account(&fixture, false);
    account.ssh_enabled = true;
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK(strstr(get_last_error()->message, "GIT_SSH_COMMAND") != NULL);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    CHECK(strstr(get_last_error()->message, "GIT_SSH_COMMAND") != NULL);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    CHECK(strstr(get_last_error()->message, "GIT_SSH_COMMAND") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", old_name,
                             sizeof(old_name)), 0);
    CHECK_STR_EQ(old_name, "Old Git User\n");

    /* Presence is authoritative even when the override is explicitly empty. */
    CHECK_EQ_INT(setenv("GIT_SSH_COMMAND", "", 1), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    CHECK(strstr(get_last_error()->message, "GIT_SSH_COMMAND") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", old_name,
                             sizeof(old_name)), 0);
    CHECK_STR_EQ(old_name, "Old Git User\n");

    /* The refuted broader case remains accepted: core.sshCommand outranks
     * legacy GIT_SSH, so a real switch and status may use it normally. */
    CHECK_EQ_INT(unsetenv("GIT_SSH_COMMAND"), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.ssh_command.present);
    CHECK_EQ_INT(git_expected_ssh_command(&account, expected_ssh,
                                          sizeof(expected_ssh)), 0);
    CHECK_STR_EQ(current.ssh_command.value, expected_ssh);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "core.sshCommand", restored_core,
                             sizeof(restored_core)), 0);
    CHECK(strlen(restored_core) > 0U);
    restored_core[strcspn(restored_core, "\n")] = '\0';
    CHECK_STR_EQ(restored_core, core_helper);

    fixture_cleanup(&fixture);
}

TEST(all_gpg_format_and_program_keys_normalize_and_restore_exactly) {
    static const char *const scopes[] = {
        "--global", "--local", "--worktree"
    };
    git_fixture_t fixture;
    char expected[3][5][1024];
    char actual[1024];
    char value[256];
    git_current_config_t current;
    account_t account;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    memset(expected, 0, sizeof(expected));
    for (size_t scope = 0; scope < 3; scope++) {
        for (size_t key = 0;
             key < sizeof(g_gpg_model_keys) / sizeof(g_gpg_model_keys[0]);
             key++) {
            for (size_t ordinal = 0; ordinal < 2; ordinal++) {
                if (key == 0) {
                    (void)snprintf(value, sizeof(value), "%s",
                                   ordinal == 0 ? "x509" : "ssh");
                } else {
                    (void)snprintf(value, sizeof(value),
                                   "/private/ar08/s%zu-k%zu-v%zu",
                                   scope, key, ordinal);
                }
                CHECK_EQ_INT(git_add(scopes[scope], g_gpg_model_keys[key],
                                     value), 0);
                CHECK(strlen(expected[scope][key]) + strlen(value) + 2U <
                      sizeof(expected[scope][key]));
                (void)strcat(expected[scope][key], value);
                (void)strcat(expected[scope][key], "\n");
            }
        }
    }

    account = basic_account(&fixture, true);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_get_all("--global", "gpg.format", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "openpgp\n");
    for (size_t scope = 0; scope < 3; scope++) {
        for (size_t key = scope == 0 ? 1U : 0U;
             key < sizeof(g_gpg_model_keys) / sizeof(g_gpg_model_keys[0]);
             key++) {
            CHECK_EQ_INT(git_get_all(scopes[scope], g_gpg_model_keys[key],
                                     actual, sizeof(actual)), -1);
        }
    }
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.valid);
    CHECK_STR_EQ(current.name, account.name);
    CHECK_STR_EQ(current.signing_key, account.gpg_key_id);

    CHECK_EQ_INT(git_config_restore(), 0);
    for (size_t scope = 0; scope < 3; scope++) {
        for (size_t key = 0;
             key < sizeof(g_gpg_model_keys) / sizeof(g_gpg_model_keys[0]);
             key++) {
            memset(actual, 0, sizeof(actual));
            CHECK_EQ_INT(git_get_all(scopes[scope], g_gpg_model_keys[key],
                                     actual, sizeof(actual)), 0);
            CHECK_STR_EQ(actual, expected[scope][key]);
        }
    }

    /* The restored worktree gpg.format=ssh must be reported as unsafe, not
     * mistaken for an OpenPGP fingerprint configuration. */
    git_ops_test_reset_caches();
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    CHECK(strstr(get_last_error()->message, "gpg.format") != NULL);

    fixture_cleanup(&fixture);
}

TEST(large_unrelated_config_allows_snapshot_switch_status_and_rollback) {
    git_fixture_t fixture;
    account_t account;
    git_current_config_t current;
    char key[64];
    char value[321];
    char listing[65536];
    char restored[512];
    run_result_t listing_result;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    memset(value, 'u', sizeof(value) - 1U);
    value[sizeof(value) - 1U] = '\0';
    for (size_t i = 0; i < 80; i++) {
        (void)snprintf(key, sizeof(key), "audit.unrelated%03zu", i);
        value[0] = (char)('a' + (i % 26U));
        CHECK_EQ_INT(git_set("--local", key, value), 0);
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "Before Large Config"), 0);
    CHECK_EQ_INT(git_set("--global", "user.email",
                         "before-large@example.test"), 0);
    {
        const char *const argv[] = {
            "git", "config", "--show-scope", "-z", "--list", NULL
        };
        CHECK_EQ_INT(run_command(argv, listing, sizeof(listing), false,
                                 &listing_result), 0);
    }
    CHECK(!listing_result.out_truncated);
    CHECK(listing_result.out_len > 16384U);

    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK_STR_EQ(current.name, account.name);
    CHECK_STR_EQ(current.email, account.email);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", restored,
                             sizeof(restored)), 0);
    CHECK_STR_EQ(restored, "Before Large Config\n");
    CHECK_EQ_INT(git_get_all("--local", "audit.unrelated037", restored,
                             sizeof(restored)), 0);
    CHECK(strlen(restored) == sizeof(value)); /* value plus Git newline */
    CHECK(restored[0] == (char)('a' + (37 % 26)));

    fixture_cleanup(&fixture);
}

static int g_probe_calls;
static int g_probe_mutations;

static int truncated_probe_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    if (result) memset(result, 0, sizeof(*result));
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv[0] || strcmp(argv[0], "git") != 0 || !argv[1]) return -1;
    if (strcmp(argv[1], "rev-parse") == 0) {
        if (result) {
            result->spawned = true;
            result->exit_code = 0;
        }
        return 0;
    }
    if (strcmp(argv[1], "config") == 0 && argv[2] &&
        strcmp(argv[2], "--show-scope") == 0) {
        g_probe_calls++;
        if (opts && opts->out && opts->out_size > 1U) {
            memset(opts->out, 'x', opts->out_size - 1U);
            opts->out[opts->out_size - 1U] = '\0';
        }
        if (result) {
            result->spawned = true;
            result->exit_code = 0;
            result->out_len = opts && opts->out_size > 0
                                  ? opts->out_size - 1U : 0U;
            result->out_truncated = true;
        }
        return 0;
    }
    g_probe_mutations++;
    if (result) {
        result->spawned = true;
        result->exit_code = 1;
    }
    return -1;
}

TEST(worktree_probe_has_a_truthful_hard_bound_before_mutation) {
    saved_env_t ssh_command = save_env("GIT_SSH_COMMAND");
    command_runner_fn previous;

    (void)unsetenv("GIT_SSH_COMMAND");
    git_ops_test_reset_caches();
    g_probe_calls = 0;
    g_probe_mutations = 0;
    previous = run_set_runner(truncated_probe_runner);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);
    CHECK(g_probe_calls > 1);
    CHECK_EQ_INT(g_probe_mutations, 0);
    CHECK(strstr(get_last_error()->message, "exceeds") != NULL);
    restore_env("GIT_SSH_COMMAND", &ssh_command);
}

TEST(git_list_config_never_returns_a_successful_prefix) {
    git_fixture_t fixture;
    char value[513];
    char small[32];
    char complete[2048];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    memset(value, 'l', sizeof(value) - 1U);
    value[sizeof(value) - 1U] = '\0';
    CHECK_EQ_INT(git_set("--global", "audit.large", value), 0);
    CHECK_EQ_INT(git_list_config(GIT_SCOPE_GLOBAL, small, sizeof(small)), -1);
    CHECK(strstr(get_last_error()->message, "trunc") != NULL ||
          strstr(get_last_error()->message, "buffer") != NULL);
    CHECK_EQ_INT(git_list_config(GIT_SCOPE_GLOBAL, complete,
                                 sizeof(complete)), 0);
    CHECK(strstr(complete, "audit.large=") != NULL);
    CHECK(strstr(complete, value) != NULL);

    fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(real_git_proves_narrow_ssh_environment_precedence_and_api_rejects_it);
    RUN_TEST(all_gpg_format_and_program_keys_normalize_and_restore_exactly);
    RUN_TEST(large_unrelated_config_allows_snapshot_switch_status_and_rollback);
    RUN_TEST(worktree_probe_has_a_truthful_hard_bound_before_mutation);
    RUN_TEST(git_list_config_never_returns_a_successful_prefix);
TEST_MAIN_END()
