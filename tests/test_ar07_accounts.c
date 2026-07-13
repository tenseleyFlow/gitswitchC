/* AR-07 T7: account selector, alias ownership, edit transaction, admission,
 * and inactive GPG-key lifecycle regressions. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "gpg_manager.h"
#include "signals.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

static const char private_key_text[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
static const char public_key_text[] =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture test@example\n";

static config_io_boundary_t g_fault_boundary;

static bool fail_config_at(config_io_boundary_t boundary) {
    return boundary == g_fault_boundary;
}

static int null_runner(const char *const argv[], const run_opts_t *opts,
                       run_result_t *result) {
    (void)argv;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    return 0;
}

static int g_source_probe_count;
static bool g_source_probe_pinned;

#define ACCOUNT_SYSTEM_FPR "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
static const char account_system_listing[] =
    "sec:u:4096:1:BBBBBBBBBBBBBBBB:1700000000:::-:::scESC:::+:::23::0:\n"
    "fpr:::::::::" ACCOUNT_SYSTEM_FPR ":\n";

static bool source_probe_uses_pinned_home(const run_opts_t *opts) {
    const char *const *env;
    bool dot_home = false;

    for (env = opts ? opts->extra_env : NULL; env && *env; env++) {
        if (strcmp(*env, "GNUPGHOME=.") == 0) {
            dot_home = true;
        }
    }
    return opts && opts->use_cwd_fd && opts->cwd_fd >= 0 && dot_home;
}

static int missing_system_gpg_key_runner(const char *const argv[],
                                         const run_opts_t *opts,
                                         run_result_t *result) {
    bool list_secret = false;

    if (argv && argv[0] && strcmp(argv[0], "gpg") == 0) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = list_secret ? 2 : 0;
    }
    if (list_secret) {
        g_source_probe_count++;
        g_source_probe_pinned = source_probe_uses_pinned_home(opts);
        return -1;
    }
    return 0;
}

static int present_system_gpg_key_runner(const char *const argv[],
                                         const run_opts_t *opts,
                                         run_result_t *result) {
    bool list_secret = false;

    if (argv && argv[0] && strcmp(argv[0], "gpg") == 0) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (!list_secret) return null_runner(argv, opts, result);

    g_source_probe_count++;
    g_source_probe_pinned = source_probe_uses_pinned_home(opts);
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", account_system_listing);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->out_len = strlen(account_system_listing);
    }
    return 0;
}

static int failed_system_gpg_setup_runner(const char *const argv[],
                                          const run_opts_t *opts,
                                          run_result_t *result) {
    bool list_secret = false;

    if (argv && argv[0] && strcmp(argv[0], "gpg") == 0) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (!list_secret) return null_runner(argv, opts, result);

    g_source_probe_count++;
    g_source_probe_pinned = source_probe_uses_pinned_home(opts);
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 126;
    }
    return -1;
}

static int fail_predelete(int home_fd) {
    (void)home_fd;
    errno = EIO;
    return -1;
}

static int write_mode(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t n = write(fd, text + total, length - total);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (close(fd) != 0) return -1;
    return chmod(path, mode);
}

static size_t read_text(const char *path, char *text, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;

    if (fd < 0 || size == 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    while (total + 1 < size) {
        ssize_t n = read(fd, text + total, size - total - 1);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    text[total] = '\0';
    return total;
}

static int count_text(const char *text, const char *needle) {
    int count = 0;
    size_t length = strlen(needle);
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += length) {
        count++;
    }
    return count;
}

static int make_sandbox(char *root, size_t root_size, char *key_one,
                        size_t key_one_size, char *key_two,
                        size_t key_two_size) {
    char runtime[512];

    if ((size_t)snprintf(root, root_size, "/tmp/gsw-ar07-acct.XXXXXX") >=
        root_size || !ts_mkdtemp(root) || chmod(root, 0700) != 0) return -1;
    if ((size_t)snprintf(runtime, sizeof(runtime), "%s/runtime", root) >=
        sizeof(runtime) || mkdir(runtime, 0700) != 0) return -1;
    if ((size_t)snprintf(key_one, key_one_size, "%s/key-one", root) >=
        key_one_size ||
        (size_t)snprintf(key_two, key_two_size, "%s/key-two", root) >=
        key_two_size) return -1;
    if (write_mode(key_one, private_key_text, 0600) != 0 ||
        write_mode(key_two, private_key_text, 0600) != 0) return -1;
    setenv("HOME", root, 1);
    setenv("XDG_RUNTIME_DIR", runtime, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    return 0;
}

static void fill_account(account_t *account, uint32_t id, const char *name,
                         const char *email, const char *key,
                         const char *alias) {
    memset(account, 0, sizeof(*account));
    account->id = id;
    snprintf(account->name, sizeof(account->name), "%s", name);
    snprintf(account->email, sizeof(account->email), "%s", email);
    snprintf(account->description, sizeof(account->description), "%s", name);
    account->preferred_scope = GIT_SCOPE_LOCAL;
    if (key) {
        account->ssh_enabled = true;
        snprintf(account->ssh_key_path, sizeof(account->ssh_key_path), "%s",
                 key);
    }
    if (alias) {
        snprintf(account->ssh_host_alias,
                 sizeof(account->ssh_host_alias), "%s", alias);
        snprintf(account->ssh_hostname, sizeof(account->ssh_hostname), "%s",
                 "github.com");
    }
}

static void end_edit_guard(void) {
    signals_rollback_end();
    signals_guard_end();
}

/* AR-08 M22: edit preparation has already updated the in-memory account when
 * it arms the rollback guard.  A guard failure must therefore put the exact
 * before-image back and surface the signal error instead of publishing a
 * prepared mutation. */
TEST(edit_guard_failure_restores_candidate_before_image) {
    gitswitch_ctx_t ctx;
    account_t original;
    account_t changed;
    error_context_t failure;
    int rc;
    int returned_errno;

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    original = ctx.accounts[0];
    changed = original;
    snprintf(changed.description, sizeof(changed.description), "%s",
             "candidate description");

    signals_guard_end();
    signals_test_fail_sigaction(SIGTERM, SIGNALS_TEST_SIGACTION_INSTALL,
                                EPERM);
    clear_error();
    errno = 0;
    rc = accounts_edit_candidate_prepare(&ctx, &changed);
    returned_errno = errno;
    failure = *get_last_error();

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(returned_errno, EPERM);
    CHECK_EQ_INT(failure.code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(failure.system_errno, EPERM);
    CHECK(memcmp(&ctx.accounts[0], &original, sizeof(original)) == 0);
    CHECK_EQ_INT((int)ctx.account_count, 1);
    CHECK(ctx.current_account == NULL);

    /* Leave the suite clean under both the pre-fix success and fixed failure
     * outcomes; inspect mutation/error state above before this cleanup. */
    if (rc == 0) {
        (void)accounts_edit_abort(&ctx);
    }
    end_edit_guard();
    signals_test_fail_sigaction(0, SIGNALS_TEST_SIGACTION_NONE, 0);
}

TEST(duplicate_email_is_ambiguous_for_every_account_selector) {
    gitswitch_ctx_t ctx;
    account_t one, two;

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&one, 1, "one", "shared@example.com", NULL, NULL);
    fill_account(&two, 2, "two", "shared@example.com", NULL, NULL);
    CHECK_EQ_INT(config_add_account(&ctx, &one), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &two), 0);

    CHECK(config_find_account(&ctx, "shared@example.com") == NULL);
    CHECK(strstr(get_last_error()->message, "one (id 1)") != NULL);
    CHECK(strstr(get_last_error()->message, "two (id 2)") != NULL);
    CHECK(config_find_account_destructive(&ctx, "shared@example.com") == NULL);
    CHECK_EQ_INT(accounts_switch(&ctx, "shared@example.com"), -1);
    CHECK(strstr(get_last_error()->message, "ambiguous") != NULL);
    CHECK_EQ_INT(accounts_edit_interactive_prepare(
                     &ctx, "shared@example.com"), -1);
    ctx.config.assume_yes = true;
    CHECK_EQ_INT(accounts_remove(&ctx, "shared@example.com"), -1);
    CHECK_EQ_INT(ctx.account_count, 2);

    CHECK(config_find_account(&ctx, "1") == &ctx.accounts[0]);
    CHECK(config_find_account(&ctx, "two") == &ctx.accounts[1]);
}

TEST(alias_collisions_are_rejected_on_add_update_and_load) {
    char root[256], key_one[512], key_two[512], path[512], body[4096];
    gitswitch_ctx_t ctx, loaded;
    account_t one, two, changed;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&one, 1, "one", "one@example.com", key_one, "GitHub-Work");
    fill_account(&two, 2, "two", "two@example.com", key_two, "other");
    CHECK_EQ_INT(config_add_account(&ctx, &one), 0);
    changed = two;
    snprintf(changed.ssh_host_alias, sizeof(changed.ssh_host_alias), "%s",
             "github-work");
    CHECK_EQ_INT(config_add_account(&ctx, &changed), -1);
    CHECK(strstr(get_last_error()->message, "case-insensitive") != NULL);
    CHECK_EQ_INT(config_add_account(&ctx, &two), 0);
    changed = ctx.accounts[1];
    snprintf(changed.ssh_host_alias, sizeof(changed.ssh_host_alias), "%s",
             "GITHUB-WORK");
    CHECK_EQ_INT(config_update_account(&ctx, &changed), -1);
    CHECK_STR_EQ(ctx.accounts[1].ssh_host_alias, "other");

    snprintf(path, sizeof(path), "%s/accounts.toml", root);
    snprintf(body, sizeof(body),
             "[settings]\ndefault_scope=\"local\"\n"
             "[accounts.1]\nname=\"one\"\nemail=\"one@example.com\"\n"
             "ssh_key=\"%s\"\nssh_host=\"GitHub-Work\"\n"
             "ssh_hostname=\"github.com\"\n"
             "[accounts.2]\nname=\"two\"\nemail=\"two@example.com\"\n"
             "ssh_key=\"%s\"\nssh_host=\"github-work\"\n"
             "ssh_hostname=\"github.com\"\n",
             key_one, key_two);
    CHECK_EQ_INT(write_mode(path, body, 0600), 0);
    memset(&loaded, 0, sizeof(loaded));
    CHECK_EQ_INT(config_load(&loaded, path), 0);
    CHECK_EQ_INT(loaded.account_count, 1);
    CHECK_EQ_INT(loaded.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(config_check_rewritable(&loaded), -1);
}

TEST(case_varied_alias_blocks_reconcile_and_shared_remove_is_non_destructive) {
    char root[256], key_one[512], key_two[512], ssh_path[512];
    char before[4096], after[4096];
    gitswitch_ctx_t ctx;
    account_t one, two;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    fill_account(&one, 1, "one", "one@example.com", key_one, "GitHub-Work");
    CHECK_EQ_INT(ssh_configure_host_alias(&one), 0);
    two = one;
    two.id = 2;
    snprintf(two.name, sizeof(two.name), "%s", "two");
    snprintf(two.email, sizeof(two.email), "%s", "two@example.com");
    snprintf(two.ssh_key_path, sizeof(two.ssh_key_path), "%s", key_two);
    snprintf(two.ssh_host_alias, sizeof(two.ssh_host_alias), "%s",
             "github-work");
    CHECK_EQ_INT(ssh_configure_host_alias(&two), 0);

    snprintf(ssh_path, sizeof(ssh_path), "%s/.ssh/config", root);
    CHECK(read_text(ssh_path, before, sizeof(before)) > 0);
    CHECK_EQ_INT(count_text(before, "# >>> gitswitch "), 1);
    CHECK(strstr(before, key_two) != NULL);
    CHECK(strstr(before, key_one) == NULL);

    /* Corrupted contexts can predate admission. Removing one claimant must
     * preserve the shared block for the survivor. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.accounts[0] = one;
    ctx.accounts[1] = two;
    ctx.account_count = 2;
    ctx.config.assume_yes = true;
    CHECK_EQ_INT(accounts_remove(&ctx, "1"), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK(read_text(ssh_path, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);
}

static void exercise_key_only_save_fault(config_io_boundary_t boundary,
                                         bool expect_installed) {
    char root[256], key_one[512], key_two[512], path[512], ssh_path[512];
    char text[8192];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    bool installed = false;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", key_one,
                 "github-work");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", root);
    snprintf(ctx.config.config_path, sizeof(ctx.config.config_path), "%s",
             path);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&ctx.accounts[0]), 0);

    changed = ctx.accounts[0];
    snprintf(changed.ssh_key_path, sizeof(changed.ssh_key_path), "%s",
             key_two);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    snprintf(ssh_path, sizeof(ssh_path), "%s/.ssh/config", root);
    CHECK(read_text(ssh_path, text, sizeof(text)) > 0);
    CHECK(strstr(text, key_two) != NULL);
    CHECK(strstr(text, key_one) == NULL);

    g_fault_boundary = boundary;
    config_set_io_fault_fn(fail_config_at);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(installed, expect_installed);
    if (installed) {
        CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, key_two);
    } else {
        CHECK_EQ_INT(accounts_edit_abort(&ctx), 0);
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, key_one);
    }
    end_edit_guard();

    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK(strstr(text, installed ? key_two : key_one) != NULL);
    CHECK(read_text(ssh_path, text, sizeof(text)) > 0);
    CHECK(strstr(text, installed ? key_two : key_one) != NULL);
    CHECK(strstr(text, installed ? key_one : key_two) == NULL);
}

TEST(key_only_edit_rolls_back_before_install) {
    exercise_key_only_save_fault(CONFIG_IO_DOCUMENT_BEFORE_RENAME, false);
}

TEST(key_only_edit_stays_consistent_after_uncertain_install) {
    exercise_key_only_save_fault(CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, true);
}

TEST(private_key_admission_rejects_public_content) {
    char root[256], key_one[512], key_two[512], public_path[512], link_path[512];
    gitswitch_ctx_t ctx;
    account_t account;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    snprintf(public_path, sizeof(public_path), "%s/id.pub", root);
    snprintf(link_path, sizeof(link_path), "%s/key-link", root);
    CHECK_EQ_INT(write_mode(public_path, public_key_text, 0600), 0);
    CHECK_EQ_INT(symlink(key_one, link_path), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&account, 1, "one", "one@example.com", public_path, NULL);
    CHECK_EQ_INT(config_add_account(&ctx, &account), -1);
    CHECK(strstr(get_last_error()->message, "private key") != NULL);
    snprintf(account.ssh_key_path, sizeof(account.ssh_key_path), "%s",
             link_path);
    CHECK_EQ_INT(config_add_account(&ctx, &account), -1);
    snprintf(account.ssh_key_path, sizeof(account.ssh_key_path), "%s",
             key_one);
    CHECK_EQ_INT(chmod(key_one, 0400), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &account), 0);
    CHECK_EQ_INT(chmod(key_one, 0700), 0);
    CHECK_EQ_INT(ssh_validate_key_file(key_one), 0);
}

static int make_gpg_home(const char *root, const char *name,
                         char *home, size_t home_size,
                         char *marker, size_t marker_size) {
    char base[512];
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    (void)root;
    if (!runtime ||
        (size_t)snprintf(base, sizeof(base), "%s/gitswitch-gpg", runtime) >=
            sizeof(base) || mkdir(base, 0700) != 0 ||
        (size_t)snprintf(home, home_size, "%s/%s", base, name) >= home_size ||
        mkdir(home, 0700) != 0 ||
        (size_t)snprintf(marker, marker_size, "%s/secret-marker", home) >=
            marker_size) return -1;
    return write_mode(marker, "secret\n", 0600);
}

TEST(gpg_identity_edit_rejects_an_existing_isolated_home_without_mutation) {
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    gitswitch_ctx_t ctx;
    account_t original, changed;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    snprintf(original.gpg_key_id, sizeof(original.gpg_key_id), "%s",
             "AAAAAAAAAAAAAAAA");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    changed = ctx.accounts[0];
    snprintf(changed.name, sizeof(changed.name), "%s", "renamed");

    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");
    CHECK(path_exists(marker));
    CHECK(strstr(get_last_error()->message, "gitswitch reset 1") != NULL);

    changed = ctx.accounts[0];
    snprintf(changed.gpg_key_id, sizeof(changed.gpg_key_id), "%s",
             "BBBBBBBBBBBBBBBB");
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");
    CHECK(path_exists(marker));
    CHECK(strstr(get_last_error()->message, "gitswitch reset 1") != NULL);

    changed = ctx.accounts[0];
    changed.gpg_enabled = false;
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK(ctx.accounts[0].gpg_enabled);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");
    CHECK(path_exists(marker));
    CHECK(strstr(get_last_error()->message, "gitswitch reset 1") != NULL);
}

TEST(gpg_rename_rejects_an_orphaned_candidate_home_without_deleting_it) {
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    gitswitch_ctx_t ctx;
    account_t original, changed;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "renamed", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    snprintf(original.gpg_key_id, sizeof(original.gpg_key_id), "%s",
             "AAAAAAAAAAAAAAAA");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    changed = ctx.accounts[0];
    snprintf(changed.name, sizeof(changed.name), "%s", "renamed");

    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");
    CHECK(path_exists(marker));
    CHECK(strstr(get_last_error()->message, "isolated GPG home") != NULL);
    CHECK(strstr(get_last_error()->message, "gitswitch reset") != NULL);
}

TEST(targeted_gpg_reset_failure_preserves_the_edit_retry_handle) {
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    command_runner_fn old_runner;
    gpg_cleanup_predelete_fn old_hook;
    int runtime_lock_fd;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    snprintf(original.gpg_key_id, sizeof(original.gpg_key_id), "%s",
             "AAAAAAAAAAAAAAAA");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);

    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_cleanup_predelete_fn(fail_predelete);
    runtime_lock_fd = runtime_state_lock_acquire();
    CHECK(runtime_lock_fd >= 0);
    if (runtime_lock_fd >= 0) {
        CHECK_EQ_INT(gpg_manager_reset("one"), -1);
        runtime_state_lock_release(runtime_lock_fd);
    }
    gpg_manager_set_cleanup_predelete_fn(old_hook);

    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    changed = ctx.accounts[0];
    snprintf(changed.name, sizeof(changed.name), "%s", "renamed");
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    CHECK(strstr(get_last_error()->message, "gitswitch reset 1") != NULL);
    run_set_runner(old_runner);
}

TEST(targeted_gpg_reset_still_requires_a_fresh_system_key_source) {
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    char source_home[512];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    command_runner_fn old_runner;
    int runtime_lock_fd;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK((size_t)snprintf(source_home, sizeof(source_home), "%s/.gnupg",
                           root) < sizeof(source_home));
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    snprintf(original.gpg_key_id, sizeof(original.gpg_key_id), "%s",
             "AAAAAAAAAAAAAAAA");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);

    old_runner = run_set_runner(null_runner);
    runtime_lock_fd = runtime_state_lock_acquire();
    CHECK(runtime_lock_fd >= 0);
    if (runtime_lock_fd >= 0) {
        CHECK_EQ_INT(gpg_manager_reset("one"), 0);
        runtime_state_lock_release(runtime_lock_fd);
    }
    CHECK(!path_exists(home));

    changed = ctx.accounts[0];
    snprintf(changed.gpg_key_id, sizeof(changed.gpg_key_id), "%s",
             "BBBBBBBBBBBBBBBB");

    /* Even a cached earlier success is not current proof after destructive
     * cleanup. The first retry must consult the real keyring and preserve the
     * account when that fresh source probe fails. */
    gpg_manager_note_key_available(changed.gpg_key_id);
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    run_set_runner(missing_system_gpg_key_runner);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK_EQ_INT(g_source_probe_count, 1);
    CHECK(g_source_probe_pinned);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");
    CHECK(!path_exists(home));
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_NOT_FOUND);
    CHECK(strstr(get_last_error()->message, "resolved no secret key") != NULL);

    /* An operational helper failure must survive the accounts boundary as an
     * operational GPG error, never be flattened into the ordinary miss above. */
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    run_set_runner(failed_system_gpg_setup_runner);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK_EQ_INT(g_source_probe_count, 1);
    CHECK(g_source_probe_pinned);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(get_last_error()->message, "child setup or exec") != NULL);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "AAAAAAAAAAAAAAAA");

    /* Positive control: once a fresh system-keyring probe succeeds, the same
     * post-reset identity edit may proceed. */
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    run_set_runner(present_system_gpg_key_runner);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    CHECK_EQ_INT(g_source_probe_count, 1);
    CHECK(g_source_probe_pinned);
    CHECK(gpg_manager_key_available_cached(ACCOUNT_SYSTEM_FPR));
    CHECK(gpg_manager_key_available_cached(changed.gpg_key_id));
    CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    end_edit_guard();
    CHECK_STR_EQ(ctx.accounts[0].name, "one");
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, "BBBBBBBBBBBBBBBB");
    CHECK(!path_exists(home));
    run_set_runner(old_runner);
}

TEST(gpg_signing_only_edit_preserves_the_isolated_home) {
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    gitswitch_ctx_t ctx;
    account_t original, changed;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    snprintf(original.gpg_key_id, sizeof(original.gpg_key_id), "%s",
             "AAAAAAAAAAAAAAAA");
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);

    changed = ctx.accounts[0];
    changed.gpg_signing_enabled = true;
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    CHECK(path_exists(marker));
    CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    end_edit_guard();
    CHECK(path_exists(marker));
}

TEST_MAIN_BEGIN()
    RUN_TEST(edit_guard_failure_restores_candidate_before_image);
    RUN_TEST(duplicate_email_is_ambiguous_for_every_account_selector);
    RUN_TEST(alias_collisions_are_rejected_on_add_update_and_load);
    RUN_TEST(case_varied_alias_blocks_reconcile_and_shared_remove_is_non_destructive);
    RUN_TEST(key_only_edit_rolls_back_before_install);
    RUN_TEST(key_only_edit_stays_consistent_after_uncertain_install);
    RUN_TEST(private_key_admission_rejects_public_content);
    RUN_TEST(gpg_identity_edit_rejects_an_existing_isolated_home_without_mutation);
    RUN_TEST(gpg_rename_rejects_an_orphaned_candidate_home_without_deleting_it);
    RUN_TEST(targeted_gpg_reset_failure_preserves_the_edit_retry_handle);
    RUN_TEST(targeted_gpg_reset_still_requires_a_fresh_system_key_source);
    RUN_TEST(gpg_signing_only_edit_preserves_the_isolated_home);
TEST_MAIN_END()
