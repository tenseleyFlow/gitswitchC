/* AR-11 M8: production-runner integration coverage for sealed Git
 * publication export. The fixture confines every Git/keyring input to a
 * private temporary tree; individual cases choose whether that tree contains
 * a real repository. */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "gpg_manager.h"
#include "publication.h"
#include "utils.h"
#include "trusted_command_fixture.h"

#include <stdint.h>

#define TEST_INCARNATION \
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
#define OTHER_INCARNATION \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define TEST_SOURCE_SELECTOR "0x01234567"
#define TEST_NORMALIZED_SELECTOR "01234567"
#define TEST_GIT_SCOPE_WORKTREE ((git_scope_t)3)

void git_ops_test_reset_caches(void);

typedef struct {
    bool present;
    char *value;
} saved_env_t;

enum fixture_env_index {
    FIXTURE_ENV_HOME = 0,
    FIXTURE_ENV_XDG_CONFIG_HOME,
    FIXTURE_ENV_GNUPGHOME,
    FIXTURE_ENV_GIT_CONFIG_GLOBAL,
    FIXTURE_ENV_GIT_CONFIG_NOSYSTEM,
    FIXTURE_ENV_GIT_CONFIG_COUNT,
    FIXTURE_ENV_GIT_SSH_COMMAND,
    FIXTURE_ENV_GIT_SSH,
    FIXTURE_ENV_GIT_TRACE,
    FIXTURE_ENV_GIT_DIR,
    FIXTURE_ENV_GIT_WORK_TREE,
    FIXTURE_ENV_GIT_COMMON_DIR,
    FIXTURE_ENV_GIT_CEILING_DIRECTORIES,
    FIXTURE_ENV_COUNT
};

static const char *const fixture_env_names[FIXTURE_ENV_COUNT] = {
    "HOME",
    "XDG_CONFIG_HOME",
    "GNUPGHOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_TRACE",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES"
};

typedef struct {
    char base[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char xdg[MAX_PATH_LEN];
    char gnupg_home[MAX_PATH_LEN];
    char work[MAX_PATH_LEN];
    char global_config[MAX_PATH_LEN];
    char saved_cwd[MAX_PATH_LEN];
    saved_env_t env[FIXTURE_ENV_COUNT];
    size_t saved_env_count;
    bool cwd_saved;
    bool cwd_changed;
} publication_fixture_t;

static bool save_fixture_environment(publication_fixture_t *fixture) {
    for (size_t i = 0; i < FIXTURE_ENV_COUNT; i++) {
        const char *value = getenv(fixture_env_names[i]);

        fixture->env[i].present = value != NULL;
        fixture->env[i].value = value ? strdup(value) : NULL;
        if (value && !fixture->env[i].value) return false;
        fixture->saved_env_count = i + 1U;
    }
    return true;
}

static void restore_fixture_environment(publication_fixture_t *fixture) {
    while (fixture->saved_env_count > 0U) {
        size_t i = --fixture->saved_env_count;
        int rc;

        if (fixture->env[i].present) {
            rc = setenv(fixture_env_names[i], fixture->env[i].value, 1);
        } else {
            rc = unsetenv(fixture_env_names[i]);
        }
        CHECK_EQ_INT(rc, 0);
        free(fixture->env[i].value);
        fixture->env[i].value = NULL;
    }
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

static int run_git_command(const char *const argv[]) {
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    return run_argv(argv, &opts, &result);
}

static bool publication_fixture_init(publication_fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    if (!save_fixture_environment(fixture) ||
        !getcwd(fixture->saved_cwd, sizeof(fixture->saved_cwd))) {
        return false;
    }
    fixture->cwd_saved = true;
    if (safe_strncpy(fixture->base,
                     "/tmp/gsw_ar11_git_publication_XXXXXX",
                     sizeof(fixture->base)) != 0 ||
        !ts_mkdtemp(fixture->base) ||
        ts_canonicalize_dir_path(fixture->base,
                                 sizeof(fixture->base)) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home), "%s/home",
                      fixture->base) != 0 ||
        safe_snprintf(fixture->xdg, sizeof(fixture->xdg), "%s/xdg",
                      fixture->base) != 0 ||
        safe_snprintf(fixture->gnupg_home, sizeof(fixture->gnupg_home),
                      "%s/gnupg", fixture->base) != 0 ||
        safe_snprintf(fixture->work, sizeof(fixture->work), "%s/work",
                      fixture->base) != 0 ||
        safe_snprintf(fixture->global_config,
                      sizeof(fixture->global_config), "%s/global.gitconfig",
                      fixture->base) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        mkdir(fixture->xdg, 0700) != 0 ||
        mkdir(fixture->gnupg_home, 0700) != 0 ||
        mkdir(fixture->work, 0700) != 0 ||
        write_text_file(fixture->global_config,
                        "[fixture]\n\tretained = before\n", 0600) != 0 ||
        setenv("HOME", fixture->home, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", fixture->xdg, 1) != 0 ||
        setenv("GNUPGHOME", fixture->gnupg_home, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", fixture->global_config, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        unsetenv("GIT_CONFIG_COUNT") != 0 ||
        unsetenv("GIT_SSH_COMMAND") != 0 ||
        unsetenv("GIT_SSH") != 0 ||
        unsetenv("GIT_TRACE") != 0 ||
        unsetenv("GIT_DIR") != 0 ||
        unsetenv("GIT_WORK_TREE") != 0 ||
        unsetenv("GIT_COMMON_DIR") != 0 ||
        setenv("GIT_CEILING_DIRECTORIES", fixture->base, 1) != 0 ||
        chdir(fixture->work) != 0) {
        return false;
    }
    fixture->cwd_changed = true;
    git_ops_test_reset_caches();
    clear_error();
    return true;
}

static void publication_fixture_cleanup(publication_fixture_t *fixture) {
    git_config_commit();
    git_ops_test_reset_caches();
    if (fixture->cwd_changed) {
        CHECK(fixture->cwd_saved);
        CHECK_EQ_INT(chdir(fixture->saved_cwd), 0);
        fixture->cwd_changed = false;
    }
    restore_fixture_environment(fixture);
}

static account_t publication_account(void) {
    account_t account;

    memset(&account, 0, sizeof(account));
    account.id = 11U;
    CHECK_EQ_INT(safe_strncpy(account.incarnation, TEST_INCARNATION,
                              sizeof(account.incarnation)), 0);
    account.incarnation_persisted = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "AR11 Publication User",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email,
                              "ar11-publication@example.test",
                              sizeof(account.email)), 0);
    account.preferred_scope = GIT_SCOPE_GLOBAL;
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(
                     account.gpg_key_id,
                     "0123456789ABCDEF0123456789ABCDEF01234567",
                     sizeof(account.gpg_key_id)), 0);
    return account;
}

TEST(bound_publication_rejects_other_accounts_and_raw_managed_writes) {
    static const struct {
        const char *key;
        const char *value;
    } raw_writes[] = {
        { GIT_CONFIG_USER_SIGNINGKEY,
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
        { GIT_CONFIG_CORE_SSHCOMMAND, "/usr/bin/ssh -F none" }
    };
    publication_fixture_t fixture;
    account_t account;
    account_t other;
    account_t legacy;
    char git_path[MAX_PATH_LEN];
    bool snapshot_active = false;
    int rc;

    memset(&fixture, 0, sizeof(fixture));
    if (find_command_path("git", git_path, sizeof(git_path)) != 0) {
        TS_SKIP("unprivileged",
                "trusted Git unavailable in this restricted execution context");
    }
    if (!publication_fixture_init(&fixture)) {
        CHECK(false);
        publication_fixture_cleanup(&fixture);
        return;
    }

    account = publication_account();
    account.gpg_enabled = false;
    account.gpg_signing_enabled = false;
    other = account;
    other.id++;
    other.gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(other.incarnation, OTHER_INCARNATION,
                              sizeof(other.incarnation)), 0);
    legacy = other;
    memset(legacy.incarnation, 0, sizeof(legacy.incarnation));
    legacy.incarnation_persisted = false;

    rc = git_config_snapshot(GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);

    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_set_config(&other, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_set_config(&legacy, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_configure_openpgp_publication(
                     &other, "/usr/bin/gpg", GIT_SCOPE_GLOBAL),
                 -1);
    CHECK_EQ_INT(errno, ESTALE);

    CHECK_EQ_INT(git_config_restore(), 0);
    snapshot_active = false;

    for (size_t i = 0; i < sizeof(raw_writes) / sizeof(raw_writes[0]); i++) {
        CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
        snapshot_active = true;
        CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
        CHECK_EQ_INT(git_set_config_value(raw_writes[i].key,
                                          raw_writes[i].value,
                                          GIT_SCOPE_GLOBAL), 0);
        errno = 0;
        clear_error();
        CHECK_EQ_INT(git_config_seal(), -1);
        CHECK_EQ_INT(errno, ESTALE);
        CHECK(strstr(get_last_error()->message,
                     "unowned managed-key write") != NULL);
        CHECK_EQ_INT(git_config_restore(), 0);
        snapshot_active = false;
    }

cleanup:
    if (snapshot_active) {
        rc = git_config_restore();
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) git_config_commit();
    }
    publication_fixture_cleanup(&fixture);
}

TEST(bound_publication_rejects_standalone_tracked_override_writers) {
    publication_fixture_t fixture;
    account_t account;
    account_t other;
    char git_path[MAX_PATH_LEN];
    char value[128];
    const char *init_argv[] = {git_path, "init", "--quiet", NULL};
    const char *worktree_argv[] = {
        git_path, "config", "--local", "extensions.worktreeConfig", "true",
        NULL
    };
    bool snapshot_active = false;
    int rc;

    memset(&fixture, 0, sizeof(fixture));
    if (find_command_path("git", git_path, sizeof(git_path)) != 0) {
        TS_SKIP("unprivileged",
                "trusted Git unavailable in this restricted execution context");
    }
    if (!publication_fixture_init(&fixture)) {
        CHECK(false);
        publication_fixture_cleanup(&fixture);
        return;
    }
    rc = run_git_command(init_argv);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = run_git_command(worktree_argv);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    git_ops_test_reset_caches();

    account = publication_account();
    account.gpg_enabled = false;
    account.gpg_signing_enabled = false;
    other = account;
    other.id++;
    other.gpg_enabled = true;
    other.gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(other.incarnation, OTHER_INCARNATION,
                              sizeof(other.incarnation)), 0);

    rc = git_config_snapshot(GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    rc = git_set_config(&account, GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_set_config(&other, GIT_SCOPE_LOCAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "primary scope") != NULL);
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_configure_gpg(&account, GIT_SCOPE_LOCAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "primary scope") != NULL);
    value[0] = '\0';
    clear_error();
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_USER_NAME, value,
                                      sizeof(value), GIT_SCOPE_LOCAL), -1);
    CHECK_EQ_INT(value[0], '\0');

    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_configure_gpg(&other, TEST_GIT_SCOPE_WORKTREE), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "primary scope") != NULL);
    value[0] = '\0';
    clear_error();
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_USER_SIGNINGKEY, value,
                                      sizeof(value),
                                      TEST_GIT_SCOPE_WORKTREE), -1);
    CHECK_EQ_INT(value[0], '\0');

    /* Rejected override writers neither taint nor invalidate the already
     * complete primary image: no mutation occurred, so sealing remains safe. */
    clear_error();
    CHECK_EQ_INT(git_config_seal(), 0);

    rc = git_config_restore();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = false;

    /* The same admission rule covers lower-precedence stores that were not
     * captured by this transaction at all. They are outside rollback and the
     * durable destination, so neither account wrappers nor raw managed-key
     * APIs may mutate them while a primary transaction is active. */
    rc = git_config_snapshot(GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    rc = git_set_config(&account, GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_set_config(&other, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "primary scope") != NULL);
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_EMAIL,
                                      "foreign@example.test",
                                      GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 "outside the active Git transaction scopes") != NULL);
    value[0] = '\0';
    clear_error();
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_USER_EMAIL, value,
                                      sizeof(value), GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(value[0], '\0');
    clear_error();
    CHECK_EQ_INT(git_config_seal(), 0);

    rc = git_config_restore();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = false;

cleanup:
    if (snapshot_active) {
        rc = git_config_restore();
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) git_config_commit();
    }
    publication_fixture_cleanup(&fixture);
}

TEST(default_runner_exports_exact_sealed_global_publication) {
    publication_fixture_t fixture;
    publication_record_t record;
    publication_identity_t expected_parent;
    publication_identity_t expected_post;
    publication_identity_t expected_program;
    publication_identity_t expected_ssh_program;
    publication_identity_t empty_identity;
    const publication_record_t *generation_records[1];
    const publication_record_t *live_generation = NULL;
    gpg_config_t gpg_config;
    account_t account;
    account_t other_account;
    struct stat parent_stat;
    struct stat post_stat;
    struct stat program_stat;
    struct stat ssh_program_stat;
    char git_path[MAX_PATH_LEN];
    char gpg_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char expected_ssh_command[GIT_CONFIG_VALUE_MAX];
    char restored_value[64];
    bool snapshot_active = false;
    int rc;

    memset(&fixture, 0, sizeof(fixture));
    memset(&record, 0, sizeof(record));
    memset(&expected_parent, 0, sizeof(expected_parent));
    memset(&expected_post, 0, sizeof(expected_post));
    memset(&expected_program, 0, sizeof(expected_program));
    memset(&expected_ssh_program, 0, sizeof(expected_ssh_program));
    memset(&empty_identity, 0, sizeof(empty_identity));
    memset(&gpg_config, 0, sizeof(gpg_config));

    CHECK(run_uses_default_runner());
    if (!run_uses_default_runner()) return;
    if (gpg_manager_resolve_executable(gpg_program,
                                       sizeof(gpg_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }
    if (find_command_path("ssh", ssh_program, sizeof(ssh_program)) != 0) {
        TS_SKIP("openssh", "no trusted SSH executable on this host");
    }
    rc = find_command_path("git", git_path, sizeof(git_path));
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) return;

    if (!publication_fixture_init(&fixture)) {
        CHECK(false);
        publication_fixture_cleanup(&fixture);
        return;
    }
    CHECK(!git_is_repository());
    if (git_is_repository()) goto cleanup;
    rc = stat(fixture.base, &parent_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    publication_identity_from_stat(&expected_parent, &parent_stat);

    if (safe_snprintf(ssh_key, sizeof(ssh_key), "%s/id_ed25519",
                      fixture.home) != 0 ||
        write_text_file(ssh_key,
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                        0600) != 0) {
        CHECK(false);
        goto cleanup;
    }
    account = publication_account();
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, ssh_key,
                              sizeof(account.ssh_key_path)), 0);
    rc = git_expected_ssh_command(&account, expected_ssh_command,
                                  sizeof(expected_ssh_command));
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    CHECK_EQ_INT(safe_strncpy(gpg_config.current_key_id,
                              account.gpg_key_id,
                              sizeof(gpg_config.current_key_id)), 0);
    CHECK_EQ_INT(safe_strncpy(gpg_config.executable_path, gpg_program,
                              sizeof(gpg_config.executable_path)), 0);
    gpg_manager_note_key_available(account.gpg_key_id);

    rc = git_config_snapshot(GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    rc = git_set_config(&account, GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    /* Ownership comes from the account that supplied the managed transaction
     * image, not from arguments later handed to the exporter. A second durable
     * incarnation must be rejected before it can write into the same slot. */
    other_account = account;
    other_account.id++;
    CHECK_EQ_INT(safe_strncpy(other_account.incarnation,
                              OTHER_INCARNATION,
                              sizeof(other_account.incarnation)), 0);
    errno = 0;
    clear_error();
    rc = git_set_config(&other_account, GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 "another account incarnation") != NULL);
    clear_error();
    rc = gpg_configure_git_signing(&gpg_config, &account,
                                   GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = git_config_seal();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    rc = stat(fixture.global_config, &post_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = lstat(gpg_program, &program_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = lstat(ssh_program, &ssh_program_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    publication_identity_from_stat(&expected_post, &post_stat);
    publication_identity_from_stat(&expected_program, &program_stat);
    publication_identity_from_stat(&expected_ssh_program,
                                   &ssh_program_stat);

    rc = git_config_export_sealed_publication(&record,
                                               TEST_SOURCE_SELECTOR);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    CHECK_EQ_INT(publication_record_validate(&record), 0);
    CHECK_EQ_INT(record.account_id, account.id);
    CHECK_STR_EQ(record.account_incarnation, account.incarnation);
    CHECK_EQ_INT(record.scope, PUBLICATION_SCOPE_GLOBAL);
    CHECK_EQ_INT(record.state, PUBLICATION_STATE_PUBLISHED);
    CHECK_EQ_INT(record.capabilities,
                 PUBLICATION_CAP_DESTINATION |
                     PUBLICATION_CAP_POST_GENERATION |
                     PUBLICATION_CAP_GPG_FINGERPRINT |
                     PUBLICATION_CAP_GPG_PROGRAM |
                     PUBLICATION_CAP_GPG_SELECTOR |
                     PUBLICATION_CAP_GPG_SIGNING_STATE |
                     PUBLICATION_CAP_SSH_COMMAND |
                     PUBLICATION_CAP_SSH_PROGRAM);
    CHECK_STR_EQ(record.config_path, fixture.global_config);
    CHECK(publication_identity_equal(&record.config_parent,
                                     &expected_parent));
    CHECK(publication_identity_equal(&record.post_config, &expected_post));
    CHECK_STR_EQ(record.repository_path, "");
    CHECK(publication_identity_equal(&record.repository, &empty_identity));
    CHECK_STR_EQ(record.gpg_fingerprint, account.gpg_key_id);
    CHECK_STR_EQ(record.gpg_selector, TEST_NORMALIZED_SELECTOR);
    CHECK_STR_EQ(record.gpg_program, gpg_program);
    CHECK(publication_identity_equal(&record.gpg_program_identity,
                                     &expected_program));
    CHECK(record.gpg_signing_enabled);
    CHECK_STR_EQ(record.ssh_command, expected_ssh_command);
    CHECK_STR_EQ(record.ssh_program, ssh_program);
    CHECK(publication_identity_equal(&record.ssh_program_identity,
                                     &expected_ssh_program));

    rc = git_config_restore();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = false;
    memset(restored_value, 0, sizeof(restored_value));
    CHECK_EQ_INT(git_get_config_value("fixture.retained", restored_value,
                                      sizeof(restored_value),
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_STR_EQ(restored_value, "before");
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_USER_NAME, restored_value,
                                      sizeof(restored_value),
                                      GIT_SCOPE_GLOBAL), -1);

    rc = git_config_snapshot(GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    rc = git_set_config(&account, GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = gpg_configure_git_signing(&gpg_config, &account,
                                   GIT_SCOPE_GLOBAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = git_config_seal();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = git_config_export_sealed_publication(&record,
                                               TEST_SOURCE_SELECTOR);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    /* Closing the transaction's retained descriptor must not invalidate the
     * exact publication generation exported by the production seal path. */
    git_config_commit();
    snapshot_active = false;
    generation_records[0] = &record;
    CHECK_EQ_INT(publication_record_verify_live_destination(
                     &record, generation_records, 1U, &live_generation), 0);
    CHECK(live_generation == &record);
    CHECK_EQ_INT(git_config_restore(), 0);

cleanup:
    if (snapshot_active) {
        rc = git_config_restore();
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) git_config_commit();
    }
    publication_fixture_cleanup(&fixture);
}

TEST(default_runner_exports_exact_sealed_local_publication) {
    publication_fixture_t fixture;
    publication_record_t record;
    publication_identity_t expected_parent;
    publication_identity_t expected_post;
    publication_identity_t expected_program;
    publication_identity_t expected_ssh_program;
    publication_identity_t expected_repository;
    gpg_config_t gpg_config;
    account_t account;
    struct stat parent_stat;
    struct stat post_stat;
    struct stat program_stat;
    struct stat ssh_program_stat;
    struct stat repository_stat;
    char git_path[MAX_PATH_LEN];
    char gpg_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char expected_ssh_command[GIT_CONFIG_VALUE_MAX];
    char git_dir[MAX_PATH_LEN];
    char local_config[MAX_PATH_LEN];
    char restored_value[64];
    const char *init_argv[] = {git_path, "init", "--quiet", NULL};
    const char *retained_argv[] = {
        git_path, "config", "--local", "fixture.retained", "before", NULL
    };
    bool snapshot_active = false;
    int rc;

    memset(&fixture, 0, sizeof(fixture));
    memset(&record, 0, sizeof(record));
    memset(&expected_parent, 0, sizeof(expected_parent));
    memset(&expected_post, 0, sizeof(expected_post));
    memset(&expected_program, 0, sizeof(expected_program));
    memset(&expected_ssh_program, 0, sizeof(expected_ssh_program));
    memset(&expected_repository, 0, sizeof(expected_repository));
    memset(&gpg_config, 0, sizeof(gpg_config));

    CHECK(run_uses_default_runner());
    if (!run_uses_default_runner()) return;
    if (gpg_manager_resolve_executable(gpg_program,
                                       sizeof(gpg_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }
    if (find_command_path("ssh", ssh_program, sizeof(ssh_program)) != 0) {
        TS_SKIP("openssh", "no trusted SSH executable on this host");
    }
    rc = find_command_path("git", git_path, sizeof(git_path));
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) return;

    if (!publication_fixture_init(&fixture)) {
        CHECK(false);
        publication_fixture_cleanup(&fixture);
        return;
    }
    rc = run_git_command(init_argv);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = run_git_command(retained_argv);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    git_ops_test_reset_caches();
    CHECK(git_is_repository());
    if (!git_is_repository()) goto cleanup;

    rc = safe_snprintf(git_dir, sizeof(git_dir), "%s/.git", fixture.work);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = safe_snprintf(local_config, sizeof(local_config), "%s/config",
                       git_dir);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = stat(git_dir, &parent_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = stat(fixture.work, &repository_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    publication_identity_from_stat(&expected_parent, &parent_stat);
    publication_identity_from_stat(&expected_repository, &repository_stat);

    if (safe_snprintf(ssh_key, sizeof(ssh_key), "%s/id_ed25519",
                      fixture.home) != 0 ||
        write_text_file(ssh_key,
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                        0600) != 0) {
        CHECK(false);
        goto cleanup;
    }
    account = publication_account();
    account.preferred_scope = GIT_SCOPE_LOCAL;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, ssh_key,
                              sizeof(account.ssh_key_path)), 0);
    rc = git_expected_ssh_command(&account, expected_ssh_command,
                                  sizeof(expected_ssh_command));
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    CHECK_EQ_INT(safe_strncpy(gpg_config.current_key_id,
                              account.gpg_key_id,
                              sizeof(gpg_config.current_key_id)), 0);
    CHECK_EQ_INT(safe_strncpy(gpg_config.executable_path, gpg_program,
                              sizeof(gpg_config.executable_path)), 0);
    gpg_manager_note_key_available(account.gpg_key_id);

    rc = git_config_snapshot(GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = true;
    rc = git_set_config(&account, GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = gpg_configure_git_signing(&gpg_config, &account,
                                   GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = git_config_seal();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;

    rc = stat(local_config, &post_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = lstat(gpg_program, &program_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    rc = lstat(ssh_program, &ssh_program_stat);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    publication_identity_from_stat(&expected_post, &post_stat);
    publication_identity_from_stat(&expected_program, &program_stat);
    publication_identity_from_stat(&expected_ssh_program,
                                   &ssh_program_stat);

    rc = git_config_export_sealed_publication(&record,
                                               TEST_SOURCE_SELECTOR);
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    CHECK_EQ_INT(publication_record_validate(&record), 0);
    CHECK_EQ_INT(record.account_id, account.id);
    CHECK_STR_EQ(record.account_incarnation, account.incarnation);
    CHECK_EQ_INT(record.scope, PUBLICATION_SCOPE_LOCAL);
    CHECK_EQ_INT(record.state, PUBLICATION_STATE_PUBLISHED);
    CHECK_EQ_INT(record.capabilities,
                 PUBLICATION_CAP_DESTINATION |
                     PUBLICATION_CAP_POST_GENERATION |
                     PUBLICATION_CAP_GPG_FINGERPRINT |
                     PUBLICATION_CAP_GPG_PROGRAM |
                     PUBLICATION_CAP_GPG_SELECTOR |
                     PUBLICATION_CAP_GPG_SIGNING_STATE |
                     PUBLICATION_CAP_SSH_COMMAND |
                     PUBLICATION_CAP_SSH_PROGRAM);
    CHECK_STR_EQ(record.config_path, local_config);
    CHECK(publication_identity_equal(&record.config_parent,
                                     &expected_parent));
    CHECK(publication_identity_equal(&record.post_config, &expected_post));
    CHECK_STR_EQ(record.repository_path, fixture.work);
    CHECK(publication_identity_equal(&record.repository,
                                     &expected_repository));
    CHECK_STR_EQ(record.gpg_fingerprint, account.gpg_key_id);
    CHECK_STR_EQ(record.gpg_selector, TEST_NORMALIZED_SELECTOR);
    CHECK_STR_EQ(record.gpg_program, gpg_program);
    CHECK(publication_identity_equal(&record.gpg_program_identity,
                                     &expected_program));
    CHECK(record.gpg_signing_enabled);
    CHECK_STR_EQ(record.ssh_command, expected_ssh_command);
    CHECK_STR_EQ(record.ssh_program, ssh_program);
    CHECK(publication_identity_equal(&record.ssh_program_identity,
                                     &expected_ssh_program));

    rc = git_config_restore();
    CHECK_EQ_INT(rc, 0);
    if (rc != 0) goto cleanup;
    snapshot_active = false;
    memset(restored_value, 0, sizeof(restored_value));
    CHECK_EQ_INT(git_get_config_value("fixture.retained", restored_value,
                                      sizeof(restored_value),
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_STR_EQ(restored_value, "before");
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_USER_NAME, restored_value,
                                      sizeof(restored_value),
                                      GIT_SCOPE_LOCAL), -1);
    git_config_commit();
    CHECK_EQ_INT(git_config_restore(), 0);

cleanup:
    if (snapshot_active) {
        rc = git_config_restore();
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) git_config_commit();
    }
    publication_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    static const char *const trusted_commands[] = {"gpg", NULL};
    ts_trusted_command_fixture_t command_fixture = {0};

    error_init(LOG_LEVEL_WARNING, NULL);
    if (ts_trusted_command_fixture_install(
            &command_fixture, "gsw-ar11-git-publication",
            trusted_commands) != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot install trusted GPG fixture\n");
        return 1;
    }
    RUN_TEST(bound_publication_rejects_other_accounts_and_raw_managed_writes);
    RUN_TEST(bound_publication_rejects_standalone_tracked_override_writers);
    RUN_TEST(default_runner_exports_exact_sealed_global_publication);
    RUN_TEST(default_runner_exports_exact_sealed_local_publication);
    if (ts_trusted_command_fixture_restore(&command_fixture) != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot restore PATH after Git publication tests\n");
        return 1;
    }
    error_cleanup();
TEST_MAIN_END()
