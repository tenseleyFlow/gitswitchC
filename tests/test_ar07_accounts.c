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
#include "publication.h"
#include "signals.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

#define STATUS_NO_SECRET_KEY \
    "[GNUPG:] ERROR keylist.getkey 17\n" \
    "[GNUPG:] FAILURE gpg-exit 33554433\n"

#define ALIAS_REMOVE_INCARNATION \
    "2727272727272727272727272727272727272727272727272727272727272727"

static const char private_key_text[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
static const char public_key_text[] =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture test@example\n";

static char g_gpg_command_dir[MAX_PATH_LEN];
static char *g_saved_path;
static bool g_saved_path_present;
static bool g_gpg_command_fixture_active;

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
static int g_gpg_retirement_attempts;

#define ACCOUNT_SYSTEM_FPR "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
static const char account_system_listing[] =
    "sec:u:4096:1:BBBBBBBBBBBBBBBB:1700000000:::-:::scESC:::+:::23::0:\n"
    "fpr:::::::::" ACCOUNT_SYSTEM_FPR ":\n";

#define HEALTH_NONSIGNING_FPR "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
#define HEALTH_EXPIRED_FPR "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
#define HEALTH_OTHER_FPR "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
static const char health_nonsigning_listing[] =
    "sec:u:4096:1:CCCCCCCCCCCCCCCC:1700000000:::-:::eE:::+:::23::0:\n"
    "fpr:::::::::" HEALTH_NONSIGNING_FPR ":\n";
static const char health_expired_listing[] =
    "sec:u:4096:1:DDDDDDDDDDDDDDDD:1700000000:1::-:::scESC:::+:::23::0:\n"
    "fpr:::::::::" HEALTH_EXPIRED_FPR ":\n";
static const char health_other_listing[] =
    "sec:u:4096:1:EEEEEEEEEEEEEEEE:1700000000:::-:::eE:::+:::23::0:\n"
    "fpr:::::::::" HEALTH_OTHER_FPR ":\n";
static const char *g_health_listing;
static int g_health_gpg_list_calls;
static int g_health_ssh_calls;
static bool g_health_probe_pinned;
static struct stat g_health_retained_home_identity;
static struct stat g_health_source_home_identity;
static const char *g_health_retained_listing;
static const char *g_health_source_listing;
static bool g_health_retained_missing;
static bool g_health_source_missing;
static bool g_health_source_error;
static int g_health_retained_list_calls;
static int g_health_source_list_calls;

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

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") || ts_command_is(argv[0], "gpg2"))) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (opts && opts->out && opts->out_size > 0) {
        if (list_secret) {
            snprintf(opts->out, opts->out_size, "%s", STATUS_NO_SECRET_KEY);
        } else {
            opts->out[0] = '\0';
        }
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = list_secret ? 2 : 0;
        if (list_secret && opts && opts->out) {
            result->out_len = strlen(opts->out);
        }
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

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") || ts_command_is(argv[0], "gpg2"))) {
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

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") || ts_command_is(argv[0], "gpg2"))) {
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

static int health_local_probe_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    bool list_secret = false;

    if (argv && argv[0] && strncmp(argv[0], "ssh", 3) == 0) {
        g_health_ssh_calls++;
        return null_runner(argv, opts, result);
    }
    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") || ts_command_is(argv[0], "gpg2"))) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (!list_secret || !g_health_listing) {
        return null_runner(argv, opts, result);
    }

    g_health_gpg_list_calls++;
    g_health_probe_pinned = source_probe_uses_pinned_home(opts);
    if (opts && opts->out && opts->out_size > 0) {
        size_t length = strlen(g_health_listing);
        size_t copied = length < opts->out_size - 1U
                            ? length : opts->out_size - 1U;
        memcpy(opts->out, g_health_listing, copied);
        opts->out[copied] = '\0';
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            result->out_len = copied;
            result->out_truncated = copied < length;
        }
    }
    return 0;
}

static bool health_probe_uses_directory(const run_opts_t *opts,
                                        const struct stat *expected) {
    struct stat actual;

    return opts && opts->use_cwd_fd && opts->cwd_fd >= 0 && expected &&
           fstat(opts->cwd_fd, &actual) == 0 &&
           actual.st_dev == expected->st_dev &&
           actual.st_ino == expected->st_ino;
}

static int health_retained_probe_runner(const char *const argv[],
                                        const run_opts_t *opts,
                                        run_result_t *result) {
    const char *listing = NULL;
    bool list_secret = false;
    bool missing = false;
    bool operational_error = false;

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") || ts_command_is(argv[0], "gpg2"))) {
        for (size_t i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) {
                list_secret = true;
                break;
            }
        }
    }
    if (!list_secret) return null_runner(argv, opts, result);

    if (health_probe_uses_directory(opts,
                                    &g_health_retained_home_identity)) {
        g_health_retained_list_calls++;
        listing = g_health_retained_listing;
        missing = g_health_retained_missing;
    } else if (health_probe_uses_directory(
                   opts, &g_health_source_home_identity)) {
        g_health_source_list_calls++;
        listing = g_health_source_listing;
        missing = g_health_source_missing;
        operational_error = g_health_source_error;
    } else {
        return null_runner(argv, opts, result);
    }

    if (missing) listing = STATUS_NO_SECRET_KEY;

    if (opts && opts->out && opts->out_size > 0) {
        size_t length = operational_error ? 0U
                                          : (listing ? strlen(listing) : 0U);
        size_t copied = length < opts->out_size - 1U
                            ? length : opts->out_size - 1U;

        if (copied > 0) memcpy(opts->out, listing, copied);
        opts->out[copied] = '\0';
        if (result) {
            memset(result, 0, sizeof(*result));
            result->spawned = true;
            result->exit_code = operational_error ? 126 : (missing ? 2 : 0);
            result->out_len = copied;
            result->out_truncated = copied < length;
        }
    }
    return missing || operational_error ? -1 : 0;
}

static int fail_predelete(int home_fd) {
    (void)home_fd;
    errno = EIO;
    return -1;
}

static int count_and_reject_predelete(int home_fd) {
    (void)home_fd;
    g_gpg_retirement_attempts++;
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

static int restore_gpg_command_fixture(void) {
    int result;

    if (!g_gpg_command_fixture_active) return 0;
    result = g_saved_path_present ? setenv("PATH", g_saved_path, 1)
                                  : unsetenv("PATH");
    free(g_saved_path);
    g_saved_path = NULL;
    g_saved_path_present = false;
    g_gpg_command_fixture_active = false;
    return result;
}

/* These tests replace GPG execution with deterministic runners, but the
 * production path correctly resolves and pins a trusted executable before it
 * calls a runner. Homebrew's operator-writable prefix is intentionally outside
 * that trust policy. Supply a private tripwire executable so this suite tests
 * runner semantics without depending on the host package layout. */
static int setup_gpg_command_fixture(void) {
    static const char script[] = "#!/bin/sh\nexit 125\n";
    const char *path = getenv("PATH");
    char command_path[MAX_PATH_LEN];
    char *fixture_path;
    size_t dir_length;
    size_t path_length = path ? strlen(path) : 0U;
    size_t fixture_length;

    if (g_gpg_command_fixture_active) {
        errno = EALREADY;
        return -1;
    }
    if (path) {
        g_saved_path = strdup(path);
        if (!g_saved_path) return -1;
        g_saved_path_present = true;
    }
    if (!ts_mkdtemp_trusted(g_gpg_command_dir,
                            sizeof(g_gpg_command_dir),
                            "gsw-ar07-gpg-bin") ||
        safe_snprintf(command_path, sizeof(command_path), "%s/gpg",
                      g_gpg_command_dir) != 0 ||
        write_mode(command_path, script, 0700) != 0) {
        free(g_saved_path);
        g_saved_path = NULL;
        g_saved_path_present = false;
        return -1;
    }

    dir_length = strlen(g_gpg_command_dir);
    if (path_length > SIZE_MAX - dir_length - 2U) {
        free(g_saved_path);
        g_saved_path = NULL;
        g_saved_path_present = false;
        errno = EOVERFLOW;
        return -1;
    }
    fixture_length = dir_length + (path_length > 0U ? path_length + 1U : 0U) +
                     1U;
    fixture_path = malloc(fixture_length);
    if (!fixture_path) {
        free(g_saved_path);
        g_saved_path = NULL;
        g_saved_path_present = false;
        return -1;
    }
    memcpy(fixture_path, g_gpg_command_dir, dir_length);
    if (path_length > 0U) {
        fixture_path[dir_length] = ':';
        memcpy(fixture_path + dir_length + 1U, path, path_length + 1U);
    } else {
        fixture_path[dir_length] = '\0';
    }
    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        free(g_saved_path);
        g_saved_path = NULL;
        g_saved_path_present = false;
        return -1;
    }
    free(fixture_path);
    g_gpg_command_fixture_active = true;
    if (!command_exists("gpg")) {
        int saved_errno = errno;

        (void)restore_gpg_command_fixture();
        errno = saved_errno ? saved_errno : ENOENT;
        return -1;
    }
    return 0;
}

static int write_all_fd(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t total = 0U;

    while (total < length) {
        ssize_t written = write(fd, cursor + total, length - total);

        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

/* A direct removal still retires every durable Git destination before it may
 * discard the account handle. Seed the exact authority a completed
 * credentialless global switch would have persisted: immutable account
 * ownership plus a destination and its sealed post-generation. */
static int seed_credentialless_publication(const char *root,
                                           gitswitch_ctx_t *ctx,
                                           const account_t *account) {
    static const char git_body[] =
        "[fixture]\n"
        "\tgeneration = alias-removal\n";
    static const char state_header[] = "none\ninactive=v1\n";
    char config_path[512];
    char git_path[512];
    char canonical_root[MAX_PATH_LEN];
    char canonical_git_path[MAX_PATH_LEN];
    char state_path[512];
    char config_body[2048];
    publication_record_t record;
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    struct stat st;
    int fd = -1;
    int written;
    int result = -1;

    if (!root || !ctx || !account || !account->incarnation_persisted ||
        (size_t)snprintf(config_path, sizeof(config_path),
                         "%s/accounts.toml", root) >= sizeof(config_path) ||
        (size_t)snprintf(git_path, sizeof(git_path), "%s/.gitconfig",
                         root) >= sizeof(git_path) ||
        (size_t)snprintf(state_path, sizeof(state_path), "%s/.resume-hint",
                         root) >= sizeof(state_path)) {
        return -1;
    }
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "[accounts.%u]\n"
        "incarnation = \"%s\"\n"
        "name = \"%s\"\n"
        "email = \"%s\"\n"
        "description = \"%s\"\n",
        account->id, account->incarnation, account->name, account->email,
        account->description);
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        write_mode(config_path, config_body, 0600) != 0 ||
        write_mode(git_path, git_body, 0600) != 0 ||
        safe_strncpy(ctx->config.config_path, config_path,
                     sizeof(ctx->config.config_path)) != 0) {
        return -1;
    }
    if (safe_strncpy(canonical_root, root, sizeof(canonical_root)) != 0 ||
        ts_canonicalize_dir_path(canonical_root,
                                 sizeof(canonical_root)) != 0 ||
        safe_snprintf(canonical_git_path, sizeof(canonical_git_path),
                      "%s/.gitconfig", canonical_root) != 0) {
        return -1;
    }

    publication_record_init(&record);
    record.account_id = account->id;
    record.scope = PUBLICATION_SCOPE_GLOBAL;
    record.state = PUBLICATION_STATE_PUBLISHED;
    record.capabilities = PUBLICATION_CAP_DESTINATION |
                          PUBLICATION_CAP_POST_GENERATION;
    if (safe_strncpy(record.account_incarnation, account->incarnation,
                     sizeof(record.account_incarnation)) != 0 ||
        safe_strncpy(record.config_path, canonical_git_path,
                     sizeof(record.config_path)) != 0 ||
        stat(root, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record.config_parent, &st);
    if (stat(git_path, &st) != 0) return -1;
    publication_identity_from_stat(&record.post_config, &st);
    if (publication_record_validate(&record) != 0) return -1;

    publication_ledger_init(&ledger);
    if (publication_ledger_upsert(&ledger, &record) != 0 ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }
    fd = open(state_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write_all_fd(fd, state_header, sizeof(state_header) - 1U) != 0 ||
        write_all_fd(fd, tail, tail_length) != 0 || fsync(fd) != 0) {
        goto cleanup;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    if (tail) {
        secure_zero_memory(tail, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
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

static int capture_health_output(const gitswitch_ctx_t *ctx, char *output,
                                 size_t output_size, int *health_result) {
    FILE *capture;
    int saved_stdout;
    int restore_result;
    size_t length;

    if (!ctx || !output || output_size == 0 || !health_result) return -1;
    capture = tmpfile();
    if (!capture) return -1;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0 || fflush(stdout) != 0) {
        if (saved_stdout >= 0) close(saved_stdout);
        fclose(capture);
        return -1;
    }
    if (dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        close(saved_stdout);
        fclose(capture);
        return -1;
    }

    *health_result = accounts_health_check(ctx);
    if (fflush(stdout) != 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
        fclose(capture);
        return -1;
    }
    restore_result = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    rewind(capture);
    length = fread(output, 1, output_size - 1U, capture);
    output[length] = '\0';
    fclose(capture);
    return restore_result == STDOUT_FILENO ? 0 : -1;
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

/* A disabled manager has no runtime identity to retire. Renaming a fully
 * credentialless inactive account must remain a config-only edit even when the
 * shared runtime namespace is deliberately unusable. */
TEST(credentialless_rename_skips_runtime_retirement) {
    char root[256], key_one[512], key_two[512], lock_dir[512];
    gitswitch_ctx_t ctx;
    account_t original, changed;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK((size_t)snprintf(lock_dir, sizeof(lock_dir),
                           "%s/runtime/gitswitch-runtime", root) <
          sizeof(lock_dir));
    CHECK_EQ_INT(write_mode(lock_dir, "not a directory\n", 0600), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    changed = ctx.accounts[0];
    snprintf(changed.name, sizeof(changed.name), "%s", "renamed");

    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    CHECK_STR_EQ(ctx.accounts[0].name, "renamed");
    CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    end_edit_guard();
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
     * preserve the shared block for the survivor. Keep the removed claimant
     * credentialless while retaining its stale alias metadata so its durable
     * publication authority does not falsely claim an SSH credential leg. */
    one.ssh_enabled = false;
    one.ssh_key_path[0] = '\0';
    one.ssh_hostname[0] = '\0';
    one.preferred_scope = GIT_SCOPE_GLOBAL;
    one.incarnation_persisted = true;
    CHECK_EQ_INT(safe_strncpy(one.incarnation, ALIAS_REMOVE_INCARNATION,
                              sizeof(one.incarnation)), 0);
    memset(&ctx, 0, sizeof(ctx));
    ctx.accounts[0] = one;
    ctx.accounts[1] = two;
    ctx.account_count = 2;
    ctx.config.assume_yes = true;
    CHECK_EQ_INT(seed_credentialless_publication(root, &ctx,
                                                 &ctx.accounts[0]), 0);
    CHECK_EQ_INT(accounts_remove(&ctx, "1"), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "github-work");
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

TEST(inactive_invalid_gpg_selector_repair_preserves_causal_error_state) {
    static const char invalid_selector[] = "not-a-gpg-selector";
    char root[256], key_one[512], key_two[512], source_home[512];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    command_runner_fn old_runner;
    error_context_t retained_error;
    error_context_t observed_error;
    uint64_t retained_generation;
    int prepare_rc;
    int observed_errno;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK((size_t)snprintf(source_home, sizeof(source_home), "%s/.gnupg",
                           root) < sizeof(source_home));
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(original.gpg_key_id, ACCOUNT_SYSTEM_FPR,
                              sizeof(original.gpg_key_id)), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);

    /* Model a hand-built or previously corrupted inactive context. Admission
     * rejects this spelling on new input, but an edit must still be able to
     * repair it without turning an internal semantic comparison into the
     * caller-visible cause of an otherwise successful transaction. */
    CHECK_EQ_INT(safe_strncpy(ctx.accounts[0].gpg_key_id, invalid_selector,
                              sizeof(ctx.accounts[0].gpg_key_id)), 0);
    changed = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(changed.gpg_key_id, ACCOUNT_SYSTEM_FPR,
                              sizeof(changed.gpg_key_id)), 0);

    old_runner = run_set_runner(present_system_gpg_key_runner);
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    (void)set_error(ERR_NETWORK_ERROR,
                    "retained error across selector repair comparison");
    retained_error = *get_last_error();
    retained_generation = error_report_generation();
    /* Missing managed homes are a successful first-run condition and may
     * leave ENOENT ambient. Seed that exact caller value so the full repair
     * path can prove it did not replace the caller's errno contract. */
    errno = ENOENT;

    prepare_rc = accounts_edit_candidate_prepare(&ctx, &changed);
    observed_errno = errno;
    observed_error = *get_last_error();

    CHECK_EQ_INT(prepare_rc, 0);
    CHECK(memcmp(&observed_error, &retained_error,
                 sizeof(retained_error)) == 0);
    CHECK(error_report_generation() == retained_generation);
    CHECK_EQ_INT(observed_errno, ENOENT);
    CHECK_EQ_INT(g_source_probe_count, 1);
    CHECK(g_source_probe_pinned);
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, ACCOUNT_SYSTEM_FPR);

    if (prepare_rc == 0) {
        CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    }
    end_edit_guard();
    run_set_runner(old_runner);
}

TEST(inactive_equivalent_gpg_selector_edit_preserves_runtime_and_spelling) {
    static const char original_selector[] = "A1B2C3D4E5F60708";
    static const char equivalent_selector[] = "0xa1b2c3d4e5f60708";
    static const char different_length_selector[] =
        "0xa1b2c3d4e5f6070809";
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    char config_path[512], persisted[8192];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    command_runner_fn old_runner;
    gpg_cleanup_predelete_fn old_hook;
    bool installed = false;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/accounts.toml", root) < sizeof(config_path));
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(original.gpg_key_id, original_selector,
                              sizeof(original.gpg_key_id)), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);

    old_runner = run_set_runner(missing_system_gpg_key_runner);
    old_hook =
        gpg_manager_set_cleanup_predelete_fn(count_and_reject_predelete);
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    g_gpg_retirement_attempts = 0;

    changed = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(changed.gpg_key_id, equivalent_selector,
                              sizeof(changed.gpg_key_id)), 0);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    CHECK_EQ_INT(g_source_probe_count, 0);
    CHECK(!g_source_probe_pinned);
    CHECK_EQ_INT(g_gpg_retirement_attempts, 0);
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);
    CHECK_EQ_INT(config_save_transactional(&ctx, config_path, &installed), 0);
    CHECK(installed);
    CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    end_edit_guard();

    CHECK(path_exists(home));
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);
    CHECK(read_text(config_path, persisted, sizeof(persisted)) > 0);
    CHECK(strstr(persisted, equivalent_selector) != NULL);
    CHECK(strstr(persisted, original_selector) == NULL);

    /* A selector with a different normalized length is not equivalent. The
     * inactive edit must still enter the destructive-identity path and stop
     * at the retained-home gate before probing or retiring anything. */
    changed = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(changed.gpg_key_id,
                              different_length_selector,
                              sizeof(changed.gpg_key_id)), 0);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK(strstr(get_last_error()->message, "isolated GPG home") != NULL);
    CHECK_EQ_INT(g_source_probe_count, 0);
    CHECK_EQ_INT(g_gpg_retirement_attempts, 0);
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);

    gpg_manager_set_cleanup_predelete_fn(old_hook);
    run_set_runner(old_runner);
}

TEST(active_equivalent_gpg_selector_edit_preserves_runtime_and_spelling) {
    static const char original_selector[] = "A1B2C3D4E5F60708";
    static const char equivalent_selector[] = "0Xa1b2c3d4e5f60708";
    static const char different_length_selector[] =
        "0Xa1b2c3d4e5f6070809";
    char root[256], key_one[512], key_two[512], home[512], marker[768];
    char config_path[512], persisted[8192];
    gitswitch_ctx_t ctx;
    account_t original, changed;
    command_runner_fn old_runner;
    gpg_cleanup_predelete_fn old_hook;
    bool installed = false;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK_EQ_INT(make_gpg_home(root, "one", home, sizeof(home), marker,
                               sizeof(marker)), 0);
    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/accounts.toml", root) < sizeof(config_path));
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&original, 1, "one", "one@example.com", NULL, NULL);
    original.gpg_enabled = true;
    CHECK_EQ_INT(safe_strncpy(original.gpg_key_id, original_selector,
                              sizeof(original.gpg_key_id)), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &original), 0);
    ctx.current_account = &ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(ctx.config.active_account, "one",
                              sizeof(ctx.config.active_account)), 0);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);

    old_runner = run_set_runner(missing_system_gpg_key_runner);
    old_hook =
        gpg_manager_set_cleanup_predelete_fn(count_and_reject_predelete);
    g_source_probe_count = 0;
    g_source_probe_pinned = false;
    g_gpg_retirement_attempts = 0;

    changed = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(changed.gpg_key_id, equivalent_selector,
                              sizeof(changed.gpg_key_id)), 0);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), 0);
    CHECK_EQ_INT(g_source_probe_count, 0);
    CHECK(!g_source_probe_pinned);
    CHECK_EQ_INT(g_gpg_retirement_attempts, 0);
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);
    CHECK_EQ_INT(config_save_transactional(&ctx, config_path, &installed), 0);
    CHECK(installed);
    CHECK_EQ_INT(accounts_edit_commit(&ctx), 0);
    end_edit_guard();

    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK(path_exists(home));
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);
    CHECK(read_text(config_path, persisted, sizeof(persisted)) > 0);
    CHECK(strstr(persisted, equivalent_selector) != NULL);
    CHECK(strstr(persisted, original_selector) == NULL);

    /* The semantic relaxation is exact: a different normalized selector
     * remains a live-field mutation and is rejected before any source probe,
     * reset, or in-memory candidate installation. */
    changed = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(changed.gpg_key_id,
                              different_length_selector,
                              sizeof(changed.gpg_key_id)), 0);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&ctx, &changed), -1);
    CHECK(strstr(get_last_error()->message, "Cannot change live fields") !=
          NULL);
    CHECK_EQ_INT(g_source_probe_count, 0);
    CHECK_EQ_INT(g_gpg_retirement_attempts, 0);
    CHECK(path_exists(marker));
    CHECK_STR_EQ(ctx.accounts[0].gpg_key_id, equivalent_selector);

    gpg_manager_set_cleanup_predelete_fn(old_hook);
    run_set_runner(old_runner);
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

TEST(health_reports_only_the_local_capabilities_it_proves) {
    char root[256], key_one[512], key_two[512], source_home[512];
    char output[8192];
    gitswitch_ctx_t ctx;
    account_t account;
    command_runner_fn previous_runner;
    int health_result = 0;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK((size_t)snprintf(source_home, sizeof(source_home), "%s/.gnupg",
                           root) < sizeof(source_home));
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&account, 1, "local-only", "local@example.com", key_one,
                 NULL);
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    snprintf(account.gpg_key_id, sizeof(account.gpg_key_id), "%s",
             HEALTH_NONSIGNING_FPR);
    CHECK_EQ_INT(config_add_account(&ctx, &account), 0);

    g_health_listing = health_nonsigning_listing;
    g_health_gpg_list_calls = 0;
    g_health_ssh_calls = 0;
    g_health_probe_pinned = false;
    previous_runner = run_set_runner(health_local_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, -1);
    CHECK_EQ_INT(g_health_gpg_list_calls, 1);
    CHECK_EQ_INT(g_health_ssh_calls, 0);
    CHECK(g_health_probe_pinned);
    CHECK(strstr(output, "Account Local Readiness Check") != NULL);
    CHECK(strstr(output,
                 "Local checks only; remote SSH authentication and a test "
                 "signature are not attempted") != NULL);
    CHECK(strstr(output,
                 "SSH private key file passed local validation "
                 "(authentication not tested)") != NULL);
    CHECK(strstr(output,
                 "GPG signing-key metadata/material check failed "
                 "(signature not attempted)") != NULL);
    CHECK(strstr(output, "SSH key functional") == NULL);
    CHECK(strstr(output, "GPG key functional") == NULL);
    CHECK(strstr(output, "All accounts are healthy") == NULL);
    CHECK(strstr(output, "SSH connection verified") == NULL);

    /* The same non-signing key is a valid local-presence result when signing
     * is not requested. A successful command must still say exactly what it
     * did not prove. */
    ctx.accounts[0].gpg_signing_enabled = false;
    g_health_listing = health_nonsigning_listing;
    g_health_gpg_list_calls = 0;
    g_health_probe_pinned = false;
    previous_runner = run_set_runner(health_local_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_gpg_list_calls, 1);
    CHECK(g_health_probe_pinned);
    CHECK(strstr(output,
                 "GPG secret key is present and locally usable "
                 "(signing not tested)") != NULL);
    CHECK(strstr(output,
                 "All configured accounts passed the reported local checks")
          != NULL);
    CHECK(strstr(output, "GPG key functional") == NULL);

    snprintf(ctx.accounts[0].gpg_key_id,
             sizeof(ctx.accounts[0].gpg_key_id), "%s", HEALTH_EXPIRED_FPR);
    g_health_listing = health_expired_listing;
    g_health_gpg_list_calls = 0;
    g_health_probe_pinned = false;
    previous_runner = run_set_runner(health_local_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, -1);
    CHECK_EQ_INT(g_health_gpg_list_calls, 1);
    CHECK(g_health_probe_pinned);
    CHECK(strstr(output,
                 "GPG secret-key local presence/usability check failed "
                 "(signing not tested)") != NULL);
    CHECK(strstr(output, "GPG key functional") == NULL);
    g_health_listing = NULL;
}

TEST(health_uses_retained_gpg_home_before_source_recovery) {
    char root[256], key_one[512], key_two[512], source_home[512];
    char retained_home[512], marker[768], output[8192];
    gitswitch_ctx_t ctx;
    account_t account;
    command_runner_fn previous_runner;
    int health_result = 0;

    CHECK_EQ_INT(make_sandbox(root, sizeof(root), key_one, sizeof(key_one),
                              key_two, sizeof(key_two)), 0);
    CHECK((size_t)snprintf(source_home, sizeof(source_home), "%s/.gnupg",
                           root) < sizeof(source_home));
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(make_gpg_home(root, "retained", retained_home,
                               sizeof(retained_home), marker,
                               sizeof(marker)), 0);
    CHECK_EQ_INT(stat(source_home, &g_health_source_home_identity), 0);
    CHECK_EQ_INT(stat(retained_home, &g_health_retained_home_identity), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&account, 1, "retained", "retained@example.com", NULL,
                 NULL);
    account.gpg_enabled = true;
    snprintf(account.gpg_key_id, sizeof(account.gpg_key_id), "%s",
             HEALTH_NONSIGNING_FPR);
    CHECK_EQ_INT(config_add_account(&ctx, &account), 0);

    g_health_retained_listing = health_nonsigning_listing;
    g_health_source_listing = NULL;
    g_health_retained_missing = false;
    g_health_source_missing = true;
    g_health_source_error = false;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 1);
    CHECK(strstr(output, "retained isolated GPG home") != NULL);
    CHECK(strstr(output, "source keyring") != NULL);
    CHECK(strstr(output, "recover") != NULL);

    /* A matching source identity is independently recognized as a complete
     * recovery path, without changing retained-home authority. */
    g_health_source_listing = health_nonsigning_listing;
    g_health_source_missing = false;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 1);
    CHECK(strstr(output,
                 "source keyring currently contains the same locally usable "
                 "identity for recovery") != NULL);

    /* A selector that resolves differently in the source keyring cannot
     * recover the retained identity, but does not make that retained key
     * unusable today. */
    g_health_source_listing = health_other_listing;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 1);
    CHECK(strstr(output, "resolves the selector to a different identity") !=
          NULL);

    /* A source helper failure is recoverability uncertainty, not evidence
     * against the retained key that was just validated. */
    g_health_source_listing = NULL;
    g_health_source_error = true;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 1);
    CHECK(strstr(output, "recoverability could not be verified") != NULL);

    /* Only an ordinary retained-key miss may continue to the source. */
    g_health_retained_missing = true;
    g_health_source_listing = health_nonsigning_listing;
    g_health_source_error = false;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, 0);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 1);
    CHECK(strstr(output, "retained isolated GPG home") == NULL);
    CHECK(strstr(output,
                 "source keyring currently contains the same locally usable "
                 "identity for recovery") != NULL);

    /* A retained-home operational failure is not an ordinary key miss and
     * must not be hidden by an otherwise usable source fallback. */
    snprintf(ctx.accounts[0].gpg_key_id,
             sizeof(ctx.accounts[0].gpg_key_id), "%s", HEALTH_EXPIRED_FPR);
    g_health_retained_listing = health_expired_listing;
    g_health_retained_missing = false;
    g_health_retained_list_calls = 0;
    g_health_source_list_calls = 0;
    previous_runner = run_set_runner(health_retained_probe_runner);
    CHECK_EQ_INT(capture_health_output(&ctx, output, sizeof(output),
                                       &health_result), 0);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(health_result, -1);
    CHECK_EQ_INT(g_health_retained_list_calls, 1);
    CHECK_EQ_INT(g_health_source_list_calls, 0);
    CHECK(strstr(output, "presence/usability check failed") != NULL);
    g_health_retained_listing = NULL;
    g_health_source_listing = NULL;
    g_health_retained_missing = false;
    g_health_source_missing = false;
    g_health_source_error = false;
}

TEST_MAIN_BEGIN()
    if (setup_gpg_command_fixture() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot prepare trusted GPG fixture\n");
        return 1;
    }
    RUN_TEST(edit_guard_failure_restores_candidate_before_image);
    RUN_TEST(credentialless_rename_skips_runtime_retirement);
    RUN_TEST(duplicate_email_is_ambiguous_for_every_account_selector);
    RUN_TEST(alias_collisions_are_rejected_on_add_update_and_load);
    RUN_TEST(case_varied_alias_blocks_reconcile_and_shared_remove_is_non_destructive);
    RUN_TEST(key_only_edit_rolls_back_before_install);
    RUN_TEST(key_only_edit_stays_consistent_after_uncertain_install);
    RUN_TEST(private_key_admission_rejects_public_content);
    RUN_TEST(
        inactive_invalid_gpg_selector_repair_preserves_causal_error_state);
    RUN_TEST(
        inactive_equivalent_gpg_selector_edit_preserves_runtime_and_spelling);
    RUN_TEST(
        active_equivalent_gpg_selector_edit_preserves_runtime_and_spelling);
    RUN_TEST(gpg_identity_edit_rejects_an_existing_isolated_home_without_mutation);
    RUN_TEST(gpg_rename_rejects_an_orphaned_candidate_home_without_deleting_it);
    RUN_TEST(targeted_gpg_reset_failure_preserves_the_edit_retry_handle);
    RUN_TEST(targeted_gpg_reset_still_requires_a_fresh_system_key_source);
    RUN_TEST(gpg_signing_only_edit_preserves_the_isolated_home);
    RUN_TEST(health_reports_only_the_local_capabilities_it_proves);
    RUN_TEST(health_uses_retained_gpg_home_before_source_recovery);
    if (restore_gpg_command_fixture() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot restore PATH after GPG tests\n");
        return 1;
    }
    return ts_test_finish();
}
