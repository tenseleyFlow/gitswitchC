/* AR-07 T1: fail-closed clearing, worktree scope, and truthful status. */
#include "test.h"
#include "accounts.h"
#include "error.h"
#include "git_ops.h"
#include "utils.h"

#include <fcntl.h>

void git_ops_test_reset_caches(void);

static int fake_unsets;
static int fake_writes;
static bool fake_repo;
static const char *fake_failed_unset;

static int fake_result(run_result_t *result, int exit_code) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = exit_code;
    }
    return exit_code == 0 ? 0 : -1;
}

static int clearing_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv[0] || strcmp(argv[0], "git") != 0) return fake_result(result, 1);
    if (argv[1] && strcmp(argv[1], "rev-parse") == 0)
        return fake_result(result, fake_repo ? 0 : 1);
    if (!argv[1] || strcmp(argv[1], "config") != 0)
        return fake_result(result, 1);

    for (size_t i = 2; argv[i]; i++) {
        if (strcmp(argv[i], "--show-scope") == 0)
            return fake_result(result, 0); /* no distinct worktree records */
    }
    if (argv[3] && strcmp(argv[3], "--unset-all") == 0 && argv[4]) {
        fake_unsets++;
        if (fake_failed_unset && strcmp(argv[4], fake_failed_unset) == 0)
            return fake_result(result, 2);
        return fake_result(result, 5); /* already absent */
    }
    if (argv[3] && argv[4]) {
        fake_writes++;
        return fake_result(result, 0);
    }
    return fake_result(result, 1);
}

static account_t basic_account(void) {
    account_t account;
    memset(&account, 0, sizeof(account));
    snprintf(account.name, sizeof(account.name), "AR07 User");
    snprintf(account.email, sizeof(account.email), "ar07@example.test");
    account.preferred_scope = GIT_SCOPE_GLOBAL;
    return account;
}

TEST(global_switch_stops_before_writes_when_any_local_clear_fails) {
    account_t account = basic_account();
    git_ops_test_reset_caches();
    fake_unsets = fake_writes = 0;
    fake_repo = true;
    fake_failed_unset = GIT_CONFIG_USER_EMAIL;
    command_runner_fn previous = run_set_runner(clearing_runner);

    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(fake_unsets, 10); /* aggregate every managed unset */
    CHECK_EQ_INT(fake_writes, 0); /* no forward global identity write */

    run_set_runner(previous);
}

TEST(disabled_ssh_unset_failure_is_fatal) {
    account_t account = basic_account();
    git_ops_test_reset_caches();
    fake_unsets = fake_writes = 0;
    fake_repo = false;
    fake_failed_unset = GIT_CONFIG_CORE_SSHCOMMAND;
    command_runner_fn previous = run_set_runner(clearing_runner);

    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    CHECK(fake_unsets >= 2); /* signing key plus core.sshCommand */
    CHECK(fake_writes > 0);  /* failure is specifically the checked SSH clear */

    run_set_runner(previous);
}

typedef struct {
    char base[96];
    char home[160];
    char xdg[160];
    char repo[160];
    char key[192];
} real_fixture_t;

static int run_git(const char *const argv[]) {
    run_opts_t opts;
    run_result_t result;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    return run_argv(argv, &opts, &result);
}

static bool fixture_init(real_fixture_t *fixture) {
    FILE *key;
    memset(fixture, 0, sizeof(*fixture));
    snprintf(fixture->base, sizeof(fixture->base), "/tmp/gsw_ar07_git_XXXXXX");
    if (!ts_mkdtemp(fixture->base)) return false;
    snprintf(fixture->home, sizeof(fixture->home), "%s/home", fixture->base);
    snprintf(fixture->xdg, sizeof(fixture->xdg), "%s/xdg", fixture->base);
    snprintf(fixture->repo, sizeof(fixture->repo), "%s/repo", fixture->base);
    snprintf(fixture->key, sizeof(fixture->key), "%s/id_test", fixture->base);
    if (mkdir(fixture->home, 0700) != 0 || mkdir(fixture->xdg, 0700) != 0 ||
        mkdir(fixture->repo, 0700) != 0) return false;
    key = fopen(fixture->key, "w");
    if (!key) return false;
    fputs("fixture\n", key);
    fclose(key);
    if (chmod(fixture->key, 0600) != 0) return false;
    setenv("HOME", fixture->home, 1);
    setenv("XDG_CONFIG_HOME", fixture->xdg, 1);
    setenv("GIT_CONFIG_NOSYSTEM", "1", 1);
    unsetenv("GIT_CONFIG_GLOBAL");
    if (chdir(fixture->repo) != 0) return false;
    {
        const char *const init[] = { "git", "init", "-q", NULL };
        if (run_git(init) != 0) return false;
    }
    git_ops_test_reset_caches();
    return true;
}

static int set_git_value(const char *scope, const char *key, const char *value) {
    const char *const argv[] = { "git", "config", scope, key, value, NULL };
    return run_git(argv);
}

static int get_git_value(const char *scope, const char *key,
                         char *value, size_t value_size) {
    const char *const argv[] = { "git", "config", scope, key, NULL };
    run_opts_t opts;
    run_result_t result;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = value;
    opts.out_size = value_size;
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &result) != 0) return -1;
    if (result.out_len > 0 && value[result.out_len - 1] == '\n')
        value[result.out_len - 1] = '\0';
    return 0;
}

TEST(worktree_values_are_cleared_and_restored_around_global_switch) {
    real_fixture_t fixture;
    account_t account = basic_account();
    char value[GIT_CONFIG_VALUE_MAX];
    char global_config[192];
    char xdg_global_config[192];
    CHECK(fixture_init(&fixture));
    CHECK_EQ_INT(set_git_value("--local", "extensions.worktreeConfig", "true"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_USER_NAME, "Old Worktree"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_USER_EMAIL,
                               "old-worktree@example.test"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_USER_SIGNINGKEY,
                               "OLD-WORKTREE-SIGNING-KEY"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_COMMIT_GPGSIGN,
                               "true"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_CORE_SSHCOMMAND,
                               "ssh -i /old/worktree/key"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_GPG_PROGRAM,
                               "/old/worktree/gpg"), 0);

    /* Keep the primary global scope genuinely absent. Git reports this as
     * fatal/ENOENT for --global --list, while an exact snapshot must model it
     * as an empty value vector and still preserve the populated worktree
     * override scope. */
    snprintf(global_config, sizeof(global_config), "%s/.gitconfig",
             fixture.home);
    snprintf(xdg_global_config, sizeof(xdg_global_config), "%s/git/config",
             fixture.xdg);
    errno = 0;
    CHECK_EQ_INT(access(global_config, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    errno = 0;
    CHECK_EQ_INT(access(xdg_global_config, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_USER_NAME,
                               value, sizeof(value)), -1);
    CHECK_EQ_INT(get_git_value("--global", GIT_CONFIG_USER_NAME,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, account.name);

    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_USER_NAME,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "Old Worktree");
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_USER_EMAIL,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "old-worktree@example.test");
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_USER_SIGNINGKEY,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "OLD-WORKTREE-SIGNING-KEY");
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_COMMIT_GPGSIGN,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "true");
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_CORE_SSHCOMMAND,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "ssh -i /old/worktree/key");
    CHECK_EQ_INT(get_git_value("--worktree", GIT_CONFIG_GPG_PROGRAM,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "/old/worktree/gpg");
}

/* H1 real-command witness: a global switch must clear all repository-local
 * overrides before writing the new global identity. Make .git non-writable so
 * Git cannot create config.lock, then prove the old global identity remains
 * byte-for-byte intact. */
TEST(unwritable_repo_config_stops_global_identity_write) {
    real_fixture_t fixture;
    account_t account = basic_account();
    char git_dir[192];
    char value[GIT_CONFIG_VALUE_MAX];
    struct stat before;
    int switch_rc;
    int restore_mode_rc;

    if (geteuid() == 0) {
        TS_SKIP("unprivileged",
                "repository permission witness requires an unprivileged uid");
    }

    CHECK(fixture_init(&fixture));
    CHECK_EQ_INT(set_git_value("--global", GIT_CONFIG_USER_NAME,
                               "Old Global User"), 0);
    CHECK_EQ_INT(set_git_value("--global", GIT_CONFIG_USER_EMAIL,
                               "old-global@example.test"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_USER_NAME,
                               "Old Local User"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_USER_EMAIL,
                               "old-local@example.test"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_USER_SIGNINGKEY,
                               "OLD-LOCAL-SIGNING-KEY"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_COMMIT_GPGSIGN,
                               "true"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_GPG_PROGRAM,
                               "/old/local/gpg"), 0);
    CHECK_EQ_INT(set_git_value("--local", GIT_CONFIG_CORE_SSHCOMMAND,
                               "ssh -i /old/local/key"), 0);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    snprintf(git_dir, sizeof(git_dir), "%s/.git", fixture.repo);
    CHECK_EQ_INT(stat(git_dir, &before), 0);
    CHECK_EQ_INT(chmod(git_dir, 0500), 0);
    switch_rc = git_set_config(&account, GIT_SCOPE_GLOBAL);
    /* Restore immediately, before any assertion/cleanup can take another
     * branch and strand the fixture in a non-writable state. */
    restore_mode_rc = chmod(git_dir, before.st_mode & 0777);

    CHECK_EQ_INT(restore_mode_rc, 0);
    CHECK_EQ_INT(switch_rc, -1);
    CHECK(strstr(get_last_error()->message,
                 "Failed to clear") != NULL);
    CHECK_EQ_INT(get_git_value("--global", GIT_CONFIG_USER_NAME,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "Old Global User");
    CHECK_EQ_INT(get_git_value("--global", GIT_CONFIG_USER_EMAIL,
                               value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "old-global@example.test");
    CHECK_EQ_INT(git_config_restore(), 0);
}

TEST(status_attributes_stale_worktree_ssh_and_gpg_program) {
    real_fixture_t fixture;
    gitswitch_ctx_t ctx;
    git_current_config_t current;
    char output[16384];
    FILE *capture;
    size_t captured;
    int saved_stdout;
    char global_config[192];

    CHECK(fixture_init(&fixture));
    snprintf(global_config, sizeof(global_config), "%s/global\nconfig",
             fixture.base);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", global_config, 1), 0);
    CHECK_EQ_INT(set_git_value("--global", GIT_CONFIG_USER_NAME, "AR07 User"), 0);
    CHECK_EQ_INT(set_git_value("--global", GIT_CONFIG_USER_EMAIL,
                               "ar07@example.test"), 0);
    CHECK_EQ_INT(set_git_value("--local", "extensions.worktreeConfig", "true"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_CORE_SSHCOMMAND,
                               "ssh -i /stale/key"), 0);
    CHECK_EQ_INT(set_git_value("--worktree", GIT_CONFIG_GPG_PROGRAM,
                               "/stale/gpg"), 0);
    CHECK_EQ_INT(set_git_value("--worktree",
                               GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                               "/stale/gpg"), 0);

    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.ssh_command.present);
    CHECK_EQ_INT(current.ssh_command.scope, GIT_CONFIG_ORIGIN_WORKTREE);
    CHECK(strstr(current.ssh_command.origin, "config.worktree") != NULL);
    CHECK(current.gpg_program.present);
    CHECK_EQ_INT(current.gpg_program.scope, GIT_CONFIG_ORIGIN_WORKTREE);
    /* Selector identity is data: the same bytes under legacy gpg.program do
     * not become an OpenPGP binding, and neither field may overwrite the
     * other while effective configuration is captured. */
    CHECK(current.gpg_openpgp_program.present);
    CHECK_EQ_INT(current.gpg_openpgp_program.scope,
                 GIT_CONFIG_ORIGIN_WORKTREE);
    CHECK_STR_EQ(current.gpg_program.value, "/stale/gpg");
    CHECK_STR_EQ(current.gpg_openpgp_program.value, "/stale/gpg");
    CHECK(!current.gpg_x509_program.present);
    CHECK(!current.gpg_ssh_program.present);

    memset(&ctx, 0, sizeof(ctx));
    ctx.account_count = 1;
    ctx.accounts[0] = basic_account();
    ctx.accounts[0].ssh_enabled = true;
    snprintf(ctx.accounts[0].ssh_key_path,
             sizeof(ctx.accounts[0].ssh_key_path), "%s", fixture.key);
    ctx.current_account = &ctx.accounts[0];

    capture = tmpfile();
    CHECK(capture != NULL);
    saved_stdout = dup(STDOUT_FILENO);
    CHECK(saved_stdout >= 0);
    fflush(stdout);
    CHECK_EQ_INT(dup2(fileno(capture), STDOUT_FILENO), STDOUT_FILENO);
    CHECK_EQ_INT(accounts_show_status(&ctx), 0);
    fflush(stdout);
    CHECK_EQ_INT(dup2(saved_stdout, STDOUT_FILENO), STDOUT_FILENO);
    close(saved_stdout);
    rewind(capture);
    memset(output, 0, sizeof(output));
    captured = fread(output, 1, sizeof(output) - 1U, capture);
    CHECK(!ferror(capture));
    output[captured] = '\0';
    fclose(capture);
    unsetenv("GIT_CONFIG_GLOBAL");

    CHECK(strstr(output, "Match Status: [WARN]") != NULL);
    CHECK(strstr(output, "Effective SSH Command: [MISMATCH] (worktree scope") != NULL);
    CHECK(strstr(output,
                 "Effective OpenPGP Program: [MISMATCH] (worktree scope") !=
          NULL);
    CHECK(strstr(output,
                 "Effective Legacy GPG Program: [FOREIGN] (worktree scope") !=
          NULL);
    CHECK(strstr(output, "global\\x0Aconfig") != NULL);
    CHECK(strstr(output, "global\nconfig") == NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(global_switch_stops_before_writes_when_any_local_clear_fails);
    RUN_TEST(disabled_ssh_unset_failure_is_fatal);
    RUN_TEST(worktree_values_are_cleared_and_restored_around_global_switch);
    RUN_TEST(unwritable_repo_config_stops_global_identity_write);
    RUN_TEST(status_attributes_stale_worktree_ssh_and_gpg_program);
TEST_MAIN_END()
