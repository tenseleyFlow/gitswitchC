/* AR-07 T10: adversarial GPG activation/identity/rollback regressions. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define SECOND_FPR  "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define SUBKEY_FPR  "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
#define V5_FPR \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define PRIMARY_SIGN \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define V5_PRIMARY_SIGN \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" V5_FPR ":\n"
#define PRIMARY_CERT \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::cC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define AMBIGUOUS_KEYS \
    PRIMARY_SIGN \
    "sec:u:4096:1:89ABCDEF01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" SECOND_FPR ":\n"

static int make_runtime(char *xdg, size_t size) {
    if (snprintf(xdg, size, "/tmp/gswar07gpg_XXXXXX") >= (int)size ||
        !ts_mkdtemp(xdg) || chmod(xdg, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", xdg, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0) {
        return -1;
    }
    return 0;
}

TEST(strict_capability_parser_rejects_unusable_keys) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char expired[1024];
    const char *revoked =
        "sec:r:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *expired_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:1::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *disabled_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::sD:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *valid_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *token_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::D2760001240102000000000000010000:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *stub_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::#:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *malformed_secret_marker =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::++:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *subkey_fpr_cannot_replace_missing_primary_fpr =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::cC:::+:::23::0:\n"
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_CERT, true, fingerprint, sizeof(fingerprint)),
                 -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     revoked, true, fingerprint, sizeof(fingerprint)), -1);
    snprintf(expired, sizeof(expired),
             "sec:u:4096:1:0123456789ABCDEF:1700000000:1::-:::scESC:::+:::23::0:\n"
             "fpr:::::::::%s:\n", PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired_subkey, true, fingerprint, sizeof(fingerprint)),
                 -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     disabled_subkey, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     valid_subkey, true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     token_subkey, true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     stub_subkey, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     malformed_secret_marker, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     subkey_fpr_cannot_replace_missing_primary_fpr, true,
                     fingerprint, sizeof(fingerprint)), -1);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "out of order") != NULL);
}

TEST(selector_inventory_is_exact_and_canonical) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     AMBIGUOUS_KEYS, false, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK(strstr(get_last_error()->message, "Ambiguous") != NULL);
    CHECK(fingerprint[0] == '\0');
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_SIGN, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

enum fake_mode {
    FAKE_PRESENT,
    FAKE_V5_FIRST_IMPORT,
    FAKE_AMBIGUOUS_SOURCE,
    FAKE_FIRST_IMPORT
};
static enum fake_mode g_fake_mode;
static bool g_fake_imported;
static bool g_fake_exported;
static bool g_fake_export_used_fingerprint;
static bool g_fake_git_used_fingerprint;
static bool g_fake_listing_used_v5_selector;
static bool g_fake_git_used_v5_fingerprint;
static char g_fake_git_signingkey[MAX_GPG_FINGERPRINT_LEN];
static char g_fake_git_gpgsign[16];
static bool g_fake_git_program_unset;
enum fake_git_failure {
    FAKE_GIT_OK,
    FAKE_GIT_FAIL_SIGNINGKEY,
    FAKE_GIT_FAIL_GPGSIGN,
    FAKE_GIT_FAIL_PROGRAM_UNSET
};
static enum fake_git_failure g_fake_git_failure;

void git_ops_test_reset_caches(void);

static bool argv_has(const char *const argv[], const char *needle) {
    size_t i;
    for (i = 0; argv[i]; i++) {
        if (strcmp(argv[i], needle) == 0) return true;
    }
    return false;
}

static int strict_key_runner(const char *const argv[], const run_opts_t *opts,
                             run_result_t *result) {
    bool listing = argv_has(argv, "--list-secret-keys");
    bool export_key = argv_has(argv, "--export-secret-keys");
    bool import_key = argv_has(argv, "--import");

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (listing) {
        bool pinned = opts && opts->use_cwd_fd;
        const char *inventory =
            g_fake_mode == FAKE_V5_FIRST_IMPORT ? V5_PRIMARY_SIGN
                                                 : PRIMARY_SIGN;

        if (g_fake_mode == FAKE_V5_FIRST_IMPORT && argv_has(argv, V5_FPR)) {
            g_fake_listing_used_v5_selector = true;
        }

        if (g_fake_mode == FAKE_AMBIGUOUS_SOURCE && !pinned) {
            inventory = AMBIGUOUS_KEYS;
        } else if ((g_fake_mode == FAKE_AMBIGUOUS_SOURCE ||
                    g_fake_mode == FAKE_FIRST_IMPORT ||
                    g_fake_mode == FAKE_V5_FIRST_IMPORT) &&
                   pinned && !g_fake_imported) {
            if (result) result->exit_code = 2;
            return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", inventory);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (export_key) {
        g_fake_exported = true;
        g_fake_export_used_fingerprint =
            argv_has(argv, g_fake_mode == FAKE_V5_FIRST_IMPORT
                                ? V5_FPR : PRIMARY_FPR);
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE\n"
                     "-----END PGP PRIVATE KEY BLOCK-----\n");
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (import_key) {
        g_fake_imported = true;
        return 0;
    }
    if (strcmp(argv[0], "git") == 0 && argv_has(argv, "user.signingkey") &&
        argv_has(argv, PRIMARY_FPR)) {
        g_fake_git_used_fingerprint = true;
    }
    if (strcmp(argv[0], "git") == 0 && argv_has(argv, "user.signingkey") &&
        argv_has(argv, V5_FPR)) {
        g_fake_git_used_v5_fingerprint = true;
    }
    if (strcmp(argv[0], "git") == 0) {
        size_t i;

        for (i = 0; argv[i]; i++) {
            if (strcmp(argv[i], GIT_CONFIG_USER_SIGNINGKEY) == 0 &&
                argv[i + 1]) {
                safe_strncpy(g_fake_git_signingkey, argv[i + 1],
                             sizeof(g_fake_git_signingkey));
            } else if (strcmp(argv[i], GIT_CONFIG_COMMIT_GPGSIGN) == 0 &&
                       argv[i + 1]) {
                safe_strncpy(g_fake_git_gpgsign, argv[i + 1],
                             sizeof(g_fake_git_gpgsign));
            } else if (strcmp(argv[i], GIT_CONFIG_GPG_PROGRAM) == 0) {
                g_fake_git_program_unset = true;
            }
        }
        if ((g_fake_git_failure == FAKE_GIT_FAIL_SIGNINGKEY &&
             argv_has(argv, GIT_CONFIG_USER_SIGNINGKEY)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_GPGSIGN &&
             argv_has(argv, GIT_CONFIG_COMMIT_GPGSIGN)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_PROGRAM_UNSET &&
             argv_has(argv, GIT_CONFIG_GPG_PROGRAM))) {
            if (result) result->exit_code = 2;
            return -1;
        }
    }
    return 0;
}

static void fill_account(account_t *account, const char *name,
                         const char *selector, bool signing) {
    memset(account, 0, sizeof(*account));
    snprintf(account->name, sizeof(account->name), "%s", name);
    snprintf(account->email, sizeof(account->email), "%s@example.test", name);
    snprintf(account->gpg_key_id, sizeof(account->gpg_key_id), "%s", selector);
    account->gpg_enabled = true;
    account->gpg_signing_enabled = signing;
}

TEST(ambiguous_selector_exports_and_imports_nothing) {
    char xdg[128];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    fill_account(&account, "ambiguous", "01234567", false);
    g_fake_mode = FAKE_AMBIGUOUS_SOURCE;
    g_fake_imported = false;
    g_fake_exported = false;
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    run_set_runner(previous);
    CHECK(!g_fake_exported);
    CHECK(!g_fake_imported);
    CHECK(strstr(get_last_error()->message, "Ambiguous") != NULL);
}

TEST(unique_selector_threads_fingerprint_through_import_and_publication) {
    char xdg[128];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    setenv("GNUPGHOME", "/external/original-gpg", 1);
    fill_account(&account, "unique", "01234567", true);
    g_fake_mode = FAKE_FIRST_IMPORT;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_export_used_fingerprint = false;
    g_fake_git_used_fingerprint = false;
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);
    CHECK(g_fake_exported);
    CHECK(g_fake_imported);
    CHECK(g_fake_export_used_fingerprint);
    CHECK(g_fake_git_used_fingerprint);
    CHECK_STR_EQ(config.current_key_id, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/original-gpg");
}

TEST(full_v5_fingerprint_selector_survives_switch_and_git_publication) {
    char xdg[128];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", "/external/v5-original", 1), 0);
    fill_account(&account, "v5", V5_FPR, true);
    CHECK_EQ_INT((int)strlen(V5_FPR), 64);
    CHECK_EQ_INT((int)strlen(account.gpg_key_id), 64);
    CHECK_STR_EQ(account.gpg_key_id, V5_FPR);
    g_fake_mode = FAKE_V5_FIRST_IMPORT;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_export_used_fingerprint = false;
    g_fake_listing_used_v5_selector = false;
    g_fake_git_used_v5_fingerprint = false;
    previous = run_set_runner(strict_key_runner);

    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);

    CHECK(g_fake_listing_used_v5_selector);
    CHECK(g_fake_exported);
    CHECK(g_fake_imported);
    CHECK(g_fake_export_used_fingerprint);
    CHECK(g_fake_git_used_v5_fingerprint);
    CHECK_STR_EQ(config.current_key_id, V5_FPR);
    CHECK_EQ_INT((int)strlen(config.current_key_id), 64);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/v5-original");
}

TEST(disabled_signing_keeps_canonical_identity_and_all_writes_are_fatal) {
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    fill_account(&account, "manual", "01234567", false);
    CHECK_EQ_INT(safe_strncpy(config.current_key_id, PRIMARY_FPR,
                              sizeof(config.current_key_id)), 0);
    g_fake_git_failure = FAKE_GIT_OK;
    g_fake_git_signingkey[0] = '\0';
    g_fake_git_gpgsign[0] = '\0';
    g_fake_git_program_unset = false;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);
    CHECK_STR_EQ(g_fake_git_signingkey, PRIMARY_FPR);
    CHECK_STR_EQ(g_fake_git_gpgsign, "false");
    CHECK(g_fake_git_program_unset);

    g_fake_git_failure = FAKE_GIT_FAIL_SIGNINGKEY;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_GPGSIGN;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_PROGRAM_UNSET;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);
    g_fake_git_failure = FAKE_GIT_OK;
}

TEST(managed_home_classification_uses_exact_components) {
    char xdg[128], home[256], base[512];
    char external[MAX_PATH_LEN], expected[MAX_PATH_LEN];
    char alias[MAX_PATH_LEN], dangling_managed[MAX_PATH_LEN];
    char fallback[MAX_PATH_LEN], missing_child[MAX_PATH_LEN];
    char managed_child[MAX_PATH_LEN];

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    snprintf(home, sizeof(home), "%s/home", xdg);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    snprintf(expected, sizeof(expected), "%s/.gnupg", home);
    snprintf(external, sizeof(external), "%s/gitswitch-gpg-backup", xdg);
    CHECK_EQ_INT(setenv("GNUPGHOME", external, 1), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(base, sizeof(base)), 0);
    CHECK_STR_EQ(base, external);

    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    snprintf(external, sizeof(external), "%s/current", base);
    CHECK_EQ_INT(setenv("GNUPGHOME", external, 1), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(external, sizeof(external)), 0);
    CHECK_STR_EQ(external, expected);

    snprintf(managed_child, sizeof(managed_child), "%s/account", base);
    CHECK_EQ_INT(mkdir(managed_child, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", managed_child, 1), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(external, sizeof(external)), 0);
    CHECK_STR_EQ(external, expected);

    /* realpath() cannot classify a dangling external-looking alias.  Resolve
     * the symlink itself so an alias to managed current remains rejected even
     * before a later switch creates that current target. */
    snprintf(alias, sizeof(alias), "%s/dangling-gpg-source", xdg);
    snprintf(dangling_managed, sizeof(dangling_managed), "%s/current", base);
    CHECK_EQ_INT(symlink(dangling_managed, alias), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", alias, 1), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(external, sizeof(external)), 0);
    CHECK_STR_EQ(external, expected);

    /* Falling back from an inherited managed GNUPGHOME is not permission to
     * trust HOME/.gnupg blindly. Resolve and classify that path through the
     * same exact alias logic for live and not-yet-created managed targets. */
    snprintf(fallback, sizeof(fallback), "%s/.gnupg", home);
    CHECK_EQ_INT(gpg_manager_retarget_current(managed_child), 0);
    CHECK_EQ_INT(symlink(dangling_managed, fallback), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", dangling_managed, 1), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(alias, sizeof(alias)), -1);
    CHECK_EQ_INT(unlink(fallback), 0);

    CHECK_EQ_INT(gpg_manager_drop_current(), 0);
    CHECK_EQ_INT(symlink(dangling_managed, fallback), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(alias, sizeof(alias)), -1);
    CHECK_EQ_INT(unlink(fallback), 0);

    CHECK_EQ_INT(symlink(managed_child, fallback), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(alias, sizeof(alias)), -1);
    CHECK_EQ_INT(unlink(fallback), 0);

    snprintf(missing_child, sizeof(missing_child), "%s/missing-child", base);
    CHECK_EQ_INT(symlink(missing_child, fallback), 0);
    CHECK_EQ_INT(gpg_manager_system_keyring_home(alias, sizeof(alias)), -1);
    CHECK_EQ_INT(unlink(fallback), 0);
}

TEST(busy_runtime_never_claims_requested_account_live) {
    char xdg[128], base[512];
    char home[MAX_PATH_LEN], lock_path[MAX_PATH_LEN];
    int ready[2];
    int release[2];
    pid_t child;
    bool live = true;
    int status;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/other", base);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(home), 0);
    CHECK_EQ_INT(pipe(ready), 0);
    CHECK_EQ_INT(pipe(release), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char marker = 'x';
        int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        close(ready[0]);
        close(release[1]);
        if (fd < 0 || flock(fd, LOCK_EX) != 0 ||
            write(ready[1], &marker, 1) != 1) _exit(9);
        if (read(release[0], &marker, 1) != 1) _exit(10);
        flock(fd, LOCK_UN);
        close(fd);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    CHECK_EQ_INT((int)read(ready[0], base, 1), 1);
    close(ready[0]);
    CHECK_EQ_INT(gpg_manager_current_is_live_for_account("requested", &live),
                 -1);
    CHECK(!live);
    CHECK_EQ_INT((int)write(release[1], "x", 1), 1);
    close(release[1]);
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int fail_commit(int base_fd) {
    (void)base_fd;
    return -1;
}

static int g_restore_failures;
static int fail_first_restore(int base_fd) {
    (void)base_fd;
    if (g_restore_failures++ == 0) return -1;
    return 0;
}

static int read_current(char *target, size_t size) {
    char current[MAX_PATH_LEN];
    ssize_t n;
    if (gpg_manager_get_home_path(current, sizeof(current)) != 0) return -1;
    n = readlink(current, target, size - 1);
    if (n <= 0 || (size_t)n >= size - 1) return -1;
    target[n] = '\0';
    return 0;
}

static int make_cas_runtime(char *base, size_t base_size,
                            char *one, size_t one_size,
                            char *two, size_t two_size,
                            char *three, size_t three_size,
                            char *current, size_t current_size) {
    char xdg[128];

    if (make_runtime(xdg, sizeof(xdg)) != 0 ||
        snprintf(base, base_size, "%s/gitswitch-gpg", xdg) >=
            (int)base_size ||
        snprintf(one, one_size, "%s/one", base) >= (int)one_size ||
        snprintf(two, two_size, "%s/two", base) >= (int)two_size ||
        snprintf(three, three_size, "%s/three", base) >= (int)three_size ||
        snprintf(current, current_size, "%s/current", base) >=
            (int)current_size ||
        mkdir(base, 0700) != 0 || mkdir(one, 0700) != 0 ||
        mkdir(two, 0700) != 0 || mkdir(three, 0700) != 0) {
        return -1;
    }
    return 0;
}

static gpg_rollback_hook_stage_t g_writer_stage;
static const char *g_writer_target;
static int rollback_writer_hook(int base_fd,
                                gpg_rollback_hook_stage_t stage,
                                const char *quarantine) {
    (void)quarantine;
    if (stage != g_writer_stage) return 0;
    (void)unlinkat(base_fd, ".gpg-race-writer", 0);
    if (!g_writer_target ||
        symlinkat(g_writer_target, base_fd, ".gpg-race-writer") != 0 ||
        renameat(base_fd, ".gpg-race-writer", base_fd, "current") != 0) {
        return -1;
    }
    return 0;
}

static int unsupported_noreplace(int old_dir_fd, const char *old_name,
                                 int new_dir_fd, const char *new_name) {
    (void)old_dir_fd;
    (void)old_name;
    (void)new_dir_fd;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
}

static int g_sync_calls;
static int g_sync_fail_call;
static int fail_selected_base_sync(int base_fd) {
    g_sync_calls++;
    if (g_sync_calls == g_sync_fail_call) {
        errno = EIO;
        return -1;
    }
    return fsync(base_fd);
}

static int replace_current_writer(const char *base, const char *current,
                                  const char *target) {
    char prepared[MAX_PATH_LEN];

    if (snprintf(prepared, sizeof(prepared), "%s/.gpg-public-done-writer",
                 base) >= (int)sizeof(prepared)) {
        return -1;
    }
    (void)unlink(prepared);
    if (symlink(target, prepared) != 0 || rename(prepared, current) != 0) {
        (void)unlink(prepared);
        return -1;
    }
    return 0;
}

TEST(rollback_cas_preserves_same_target_and_distinct_later_writers) {
    char base[512], one[512], two[512], three[512], current[512], target[512];
    struct stat original;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = true;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    CHECK_EQ_INT(lstat(current, &original), 0);

    /* Same-target ABA: spelling equality must not authorize removal. The hook
     * installs a different inode after the retained identity was captured but
     * before the native no-replace move. */
    g_writer_stage = GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE;
    g_writer_target = one;
    gpg_manager_set_rollback_hook_fn(rollback_writer_hook);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(original.st_dev != replacement.st_dev ||
          original.st_ino != replacement.st_ino);

    /* A distinct writer in the same window is likewise moved, classified as
     * foreign, and restored without ever being overwritten by `three`. */
    memset(&config, 0, sizeof(config));
    g_writer_target = two;
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* Writer-after-quarantine: current is empty only briefly; a later writer
     * occupying it wins and the owned quarantine alone is retired. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    g_writer_stage = GPG_ROLLBACK_HOOK_AFTER_QUARANTINE;
    g_writer_target = two;
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);
    gpg_manager_set_rollback_hook_fn(NULL);
    g_writer_target = NULL;
}

TEST(rollback_cas_retries_stale_collision_unsupported_and_sync_states) {
    char base[512], one[512], two[512], three[512], current[512], target[512];
    char stale[640];
    struct stat current_stat;
    gpg_config_t config = {0};
    bool changed = false;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    snprintf(stale, sizeof(stale),
             "%s/.gitswitch-gpg-rollback.preplanted", base);
    CHECK_EQ_INT(symlink(two, stale), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    /* The stale artifact is a preflight blocker: no namespace mutation has
     * occurred yet, so there must be no fabricated rollback ownership. */
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    CHECK_EQ_INT(unlink(stale), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    gpg_manager_set_rename_noreplace_fn(unsupported_noreplace);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    gpg_manager_set_rename_noreplace_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(!config.rollback.final_present);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK(lstat(current, &current_stat) != 0 && errno == ENOENT);
}

TEST(public_done_retry_reproves_owned_present_identity) {
    char base[MAX_PATH_LEN], one[MAX_PATH_LEN], two[MAX_PATH_LEN];
    char three[MAX_PATH_LEN], current[MAX_PATH_LEN], target[MAX_PATH_LEN];
    struct stat intended;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = false;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);

    /* An unchanged retry can truthfully report success after re-proving the
     * exact privately captured restoration inode. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(config.rollback.final_present);
    CHECK(config.rollback.final_link.valid);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* Same-target ABA after the failed PUBLIC_DONE fsync is a conflict because
     * spelling equality cannot prove ownership of the replacement inode. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK_EQ_INT(lstat(current, &intended), 0);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, three), 0);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(intended.st_dev != replacement.st_dev ||
          intended.st_ino != replacement.st_ino);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* Removal and a distinct managed writer after PUBLIC_DONE likewise retire
     * the old token as conflicts instead of returning stale success. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(unlink(current), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK(lstat(current, &replacement) != 0 && errno == ENOENT);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, two), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);
}

TEST(public_done_retry_reproves_absence_and_direct_publication) {
    char base[MAX_PATH_LEN], one[MAX_PATH_LEN], two[MAX_PATH_LEN];
    char three[MAX_PATH_LEN], current[MAX_PATH_LEN], target[MAX_PATH_LEN];
    struct stat intended;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = true;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);

    /* A writer appearing after an absent restoration reached PUBLIC_DONE
     * invalidates success while remaining untouched. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(!config.rollback.final_present);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, two), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* Direct absent-to-present restoration uses the same private publication
     * identity. First prove its positive retry, including pending retirement. */
    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = false;
    g_sync_calls = 0;
    g_sync_fail_call = 1;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(config.rollback.final_present);
    CHECK(config.rollback.final_link.valid);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* A same-target ABA before that direct retry is still a conflict. */
    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 1;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), -1);
    CHECK_EQ_INT(lstat(current, &intended), 0);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, three), 0);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(intended.st_dev != replacement.st_dev ||
          intended.st_ino != replacement.st_ino);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);
}

TEST(failed_retarget_retains_dirty_state_until_controlled_retry) {
    char xdg[128], base[512];
    char old_home[MAX_PATH_LEN], target[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    setenv("GNUPGHOME", "/external/before-rollback", 1);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(old_home, sizeof(old_home), "%s/old", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(old_home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(old_home), 0);
    fill_account(&account, "new", "01234567", true);
    g_fake_mode = FAKE_PRESENT;
    previous = run_set_runner(strict_key_runner);
    g_restore_failures = 0;
    gpg_manager_set_retarget_commit_hook_fn(fail_commit);
    gpg_manager_set_retarget_restore_hook_fn(fail_first_restore);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    gpg_manager_set_retarget_commit_hook_fn(NULL);
    gpg_manager_set_retarget_restore_hook_fn(NULL);
    run_set_runner(previous);

    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(strstr(get_last_error()->message, "rollback failed") != NULL);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK(strstr(target, "/new") != NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, old_home);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/before-rollback");
}

static bool g_fail_env_set;
static bool g_fail_env_unset;
static int fault_setenv(const char *name, const char *value, int overwrite) {
    if (g_fail_env_set && strcmp(name, "GNUPGHOME") == 0) {
        errno = EIO;
        return -1;
    }
    return setenv(name, value, overwrite);
}

static int fault_unsetenv(const char *name) {
    if (g_fail_env_unset && strcmp(name, "GNUPGHOME") == 0) {
        errno = EIO;
        return -1;
    }
    return unsetenv(name);
}

TEST(environment_failures_are_fatal_and_retryable) {
    char xdg[128], current[MAX_PATH_LEN];
    struct stat st;
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    setenv("GNUPGHOME", "/external/env-before", 1);
    fill_account(&account, "envset", "01234567", true);
    g_fake_mode = FAKE_PRESENT;
    previous = run_set_runner(strict_key_runner);
    g_fail_env_set = true;
    gpg_manager_set_setenv_fn(fault_setenv);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    CHECK_EQ_INT(gpg_manager_get_home_path(current, sizeof(current)), 0);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/env-before");
    g_fail_env_set = false;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    g_fail_env_set = true;
    gpg_manager_set_setenv_fn(fault_setenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(config.current_key_id[0] != '\0');
    g_fail_env_set = false;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/env-before");

    unsetenv("GNUPGHOME");
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "envunset", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    g_fail_env_unset = true;
    gpg_manager_set_unsetenv_fn(fault_unsetenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(config.current_key_id[0] != '\0');
    g_fail_env_unset = false;
    gpg_manager_set_unsetenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GNUPGHOME") == NULL);

    CHECK_EQ_INT(setenv("GNUPGHOME", "", 1), 0);
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "envempty", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), "");
    run_set_runner(previous);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(strict_capability_parser_rejects_unusable_keys);
    RUN_TEST(selector_inventory_is_exact_and_canonical);
    RUN_TEST(ambiguous_selector_exports_and_imports_nothing);
    RUN_TEST(unique_selector_threads_fingerprint_through_import_and_publication);
    RUN_TEST(full_v5_fingerprint_selector_survives_switch_and_git_publication);
    RUN_TEST(disabled_signing_keeps_canonical_identity_and_all_writes_are_fatal);
    RUN_TEST(managed_home_classification_uses_exact_components);
    RUN_TEST(busy_runtime_never_claims_requested_account_live);
    RUN_TEST(failed_retarget_retains_dirty_state_until_controlled_retry);
    RUN_TEST(rollback_cas_preserves_same_target_and_distinct_later_writers);
    RUN_TEST(rollback_cas_retries_stale_collision_unsupported_and_sync_states);
    RUN_TEST(public_done_retry_reproves_owned_present_identity);
    RUN_TEST(public_done_retry_reproves_absence_and_direct_publication);
    RUN_TEST(environment_failures_are_fatal_and_retryable);
TEST_MAIN_END()
