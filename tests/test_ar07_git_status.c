/* AR-07 T14: trusted persisted SSH command and truthful Git status. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "accounts.h"
#include "error.h"
#include "git_ops.h"
#define GITSWITCH_INTERNAL_API
#include "git_status_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "gpg_manager.h"
#include "ssh_manager.h"
#include "utils.h"

#include <fcntl.h>

void git_ops_test_reset_caches(void);

#define STATUS_TEST_INCARNATION \
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
#define STATUS_TEST_INCARNATION_B \
    "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"

static void bind_status_test_incarnation(account_t *account) {
    if (!account) return;
    CHECK_EQ_INT(safe_strncpy(account->incarnation,
                              STATUS_TEST_INCARNATION,
                              sizeof(account->incarnation)), 0);
    account->incarnation_persisted = true;
}

typedef struct {
    char *value;
    bool present;
} saved_env_t;

static saved_env_t save_env(const char *name) {
    saved_env_t saved;
    const char *value = getenv(name);
    saved.present = value != NULL;
    saved.value = value ? strdup(value) : NULL;
    return saved;
}

static char trusted_gpg_dir[MAX_PATH_LEN];
static char *saved_gpg_path;
static bool saved_gpg_path_present;
static bool trusted_gpg_active;

static void remove_trusted_gpg_fixture(void) {
    if (trusted_gpg_dir[0] != '\0') {
        ts_rm_rf(trusted_gpg_dir);
        trusted_gpg_dir[0] = '\0';
    }
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

static int write_all_test_bytes(int fd, const void *data, size_t length) {
    const unsigned char *bytes = data;
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, bytes + written, length - written);
        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int run_command(const char *const argv[], char *output,
                       size_t output_size, run_result_t *result) {
    run_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    if (output && output_size > 0) {
        output[0] = '\0';
        opts.out = output;
        opts.out_size = output_size;
    }
    opts.stderr_to_devnull = true;
    return run_argv(argv, &opts, result);
}

static int restore_trusted_gpg(void) {
    int rc;

    if (!trusted_gpg_active) return 0;
    rc = saved_gpg_path_present ? setenv("PATH", saved_gpg_path, 1)
                                : unsetenv("PATH");
    free(saved_gpg_path);
    saved_gpg_path = NULL;
    saved_gpg_path_present = false;
    trusted_gpg_active = false;
    remove_trusted_gpg_fixture();
    return rc;
}

/* The production resolver intentionally rejects Homebrew's group-writable
 * prefix. These cases exercise status attribution rather than path trust, so
 * run the already-provisioned GnuPG binary from a private trusted fixture.
 * This preserves the real process and only changes its executable pathname. */
static int activate_trusted_gpg_copy(const char *source_path) {
    char destination[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    struct stat source_stat;
    const char *path = getenv("PATH");
    char *saved_path = NULL;
    char *fixture_path = NULL;
    size_t dir_len;
    size_t path_len = path ? strlen(path) : 0;
    size_t fixture_len;

    if (!source_path || !*source_path || trusted_gpg_active) {
        errno = EINVAL;
        return -1;
    }
    /* Do not execute the package-manager pathname before it has crossed into
     * the private fixture. Homebrew's bin directory is intentionally rejected
     * by the production trust policy, and run_argv() applies that same policy
     * to absolute paths. Here the provisioned executable is only a byte source
     * for a test fixture; the copied pathname is re-resolved through the full
     * production policy before any test can execute it. */
    if (stat(source_path, &source_stat) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) return 0;
        return -1;
    }
    if (!S_ISREG(source_stat.st_mode) ||
        (source_stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        errno = ENOEXEC;
        return -1;
    }
    if (path) {
        saved_path = strdup(path);
        if (!saved_path) return -1;
    }
    if (!ts_mkdtemp_trusted(trusted_gpg_dir, sizeof(trusted_gpg_dir),
                            "gsw-ar11-gpg-bin") ||
        safe_snprintf(destination, sizeof(destination), "%s/gpg",
                      trusted_gpg_dir) != 0 ||
        copy_file(source_path, destination) != 0 ||
        chmod(destination, 0700) != 0) {
        free(saved_path);
        remove_trusted_gpg_fixture();
        return -1;
    }

    dir_len = strlen(trusted_gpg_dir);
    if (path_len > SIZE_MAX - dir_len - 2U) {
        free(saved_path);
        remove_trusted_gpg_fixture();
        errno = EOVERFLOW;
        return -1;
    }
    fixture_len = dir_len + (path_len > 0 ? path_len + 1U : 0U) + 1U;
    fixture_path = malloc(fixture_len);
    if (!fixture_path) {
        free(saved_path);
        remove_trusted_gpg_fixture();
        return -1;
    }
    memcpy(fixture_path, trusted_gpg_dir, dir_len);
    if (path_len > 0) {
        fixture_path[dir_len] = ':';
        memcpy(fixture_path + dir_len + 1U, path, path_len + 1U);
    } else {
        fixture_path[dir_len] = '\0';
    }

    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        free(saved_path);
        remove_trusted_gpg_fixture();
        return -1;
    }
    free(fixture_path);
    saved_gpg_path = saved_path;
    saved_gpg_path_present = path != NULL;
    trusted_gpg_active = true;
    if (gpg_manager_resolve_executable(resolved, sizeof(resolved)) != 0 ||
        strcmp(resolved, destination) != 0) {
        int saved_errno = errno;

        (void)restore_trusted_gpg();
        errno = saved_errno ? saved_errno : ENOEXEC;
        return -1;
    }
    return 1;
}

/* The macOS hosted runner installs GnuPG below Homebrew's group-writable
 * prefix. Lock the fallback contract with a source path that production must
 * reject: the original is never executed, while its private copy is accepted
 * and runnable through the normal execution boundary. */
TEST(untrusted_gpg_source_is_only_executed_after_trusted_copy) {
    static const char probe[] = "#!/bin/sh\nexit 0\n";
    char source_dir[MAX_PATH_LEN];
    char source_target[MAX_PATH_LEN];
    char source_path[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *path = getenv("PATH");
    char *original_path = path ? strdup(path) : NULL;
    bool path_present = path != NULL;
    bool source_created = false;
    bool source_path_installed = false;
    int activation_rc;

    if (path && !original_path) {
        CHECK(false);
        return;
    }
    if (!ts_mkdtemp_trusted(source_dir, sizeof(source_dir),
                            "gsw-ar11-gpg-source") ||
        safe_snprintf(source_target, sizeof(source_target), "%s/gpg-real",
                      source_dir) != 0 ||
        safe_snprintf(source_path, sizeof(source_path), "%s/gpg",
                      source_dir) != 0 ||
        write_text_file(source_target, probe, 0700) != 0 ||
        symlink("gpg-real", source_path) != 0 ||
        chmod(source_dir, 0770) != 0) {
        CHECK(false);
        goto cleanup;
    }
    source_created = true;
    if (setenv("PATH", source_dir, 1) != 0) {
        CHECK(false);
        goto cleanup;
    }
    source_path_installed = true;
    CHECK(gpg_manager_resolve_executable(resolved, sizeof(resolved)) != 0);

    activation_rc = activate_trusted_gpg_copy(source_path);
    CHECK_EQ_INT(activation_rc, 1);
    if (activation_rc == 1) {
        int resolve_rc = gpg_manager_resolve_executable(resolved,
                                                        sizeof(resolved));
        run_result_t version_result;

        CHECK_EQ_INT(resolve_rc, 0);
        if (resolve_rc == 0) {
            const char *version_argv[] = { resolved, "--version", NULL };

            CHECK(strcmp(resolved, source_path) != 0);
            memset(&version_result, 0, sizeof(version_result));
            CHECK_EQ_INT(run_command(version_argv, NULL, 0,
                                     &version_result), 0);
        }
    }

cleanup:
    if (restore_trusted_gpg() != 0) CHECK(false);
    if (source_path_installed || !path_present) {
        int rc = path_present ? setenv("PATH", original_path, 1)
                              : unsetenv("PATH");
        if (rc != 0) CHECK(false);
    }
    if (source_created) ts_rm_rf(source_dir);
    free(original_path);
}

static int prepare_real_gpg(void) {
    static const char *const homebrew_candidates[] = {
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        NULL
    };
    char resolved[MAX_PATH_LEN];

    if (gpg_manager_resolve_executable(resolved, sizeof(resolved)) == 0) {
        return 1;
    }
    for (size_t i = 0; homebrew_candidates[i]; i++) {
        int rc = activate_trusted_gpg_copy(homebrew_candidates[i]);

        if (rc != 0) return rc;
    }
    return 0;
}

static int fake_finish(run_result_t *result, int exit_code) {
    if (result) {
        result->spawned = true;
        result->exit_code = exit_code;
    }
    return exit_code == 0 ? 0 : -1;
}

static unsigned char fake_listing[70000];
static size_t fake_listing_len;
static int fake_listing_calls;
static bool fake_execution_failure;
static bool fake_reject_int_min_boolean;
static const unsigned char default_failure_diagnostic[] =
    "fatal: injected unreadable git configuration\n";
static const unsigned char *fake_failure_diagnostic =
    default_failure_diagnostic;
static size_t fake_failure_diagnostic_len =
    sizeof(default_failure_diagnostic) - 1U;
static bool fake_repository;
static const unsigned char *fake_repo_root;
static size_t fake_repo_root_len;
static int fake_git_calls;
static int fake_non_git_calls;
static const char *publication_selector_override;
static bool publication_omit_selector_override;

static bool fake_append(const void *bytes, size_t length) {
    if (length > sizeof(fake_listing) - fake_listing_len) return false;
    memcpy(fake_listing + fake_listing_len, bytes, length);
    fake_listing_len += length;
    return true;
}

static bool fake_append_record(const char *scope, const char *origin,
                               const char *key, const char *value,
                               size_t value_len) {
    const char newline = '\n';
    const char nul = '\0';
    return fake_append(scope, strlen(scope)) && fake_append(&nul, 1) &&
           fake_append(origin, strlen(origin)) && fake_append(&nul, 1) &&
           fake_append(key, strlen(key)) && fake_append(&newline, 1) &&
           fake_append(value, value_len) && fake_append(&nul, 1);
}

static int fake_write_output(const run_opts_t *opts, run_result_t *result,
                             const unsigned char *bytes, size_t length) {
    size_t copied;

    if (!opts || !opts->out || opts->out_size == 0 || !bytes) {
        return fake_finish(result, 1);
    }
    copied = length < opts->out_size - 1U ? length : opts->out_size - 1U;
    memcpy(opts->out, bytes, copied);
    opts->out[copied] = '\0';
    if (result) {
        result->out_len = copied;
        result->out_truncated = copied < length;
    }
    return fake_finish(result, 0);
}

static int fake_write_error(const run_opts_t *opts, run_result_t *result,
                            const char *diagnostic, int exit_code) {
    size_t length = strlen(diagnostic);

    if (opts && opts->merge_stderr && opts->out && opts->out_size > 0) {
        size_t copied = length < opts->out_size - 1U
                            ? length : opts->out_size - 1U;
        memcpy(opts->out, diagnostic, copied);
        opts->out[copied] = '\0';
        if (result) {
            result->out_len = copied;
            result->out_truncated = copied < length;
        }
    }
    return fake_finish(result, exit_code);
}

static int status_fake_runner(const char *const argv[], const run_opts_t *opts,
                              run_result_t *result) {
    if (result) memset(result, 0, sizeof(*result));
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (!argv[0] || strcmp(argv[0], "git") != 0 || !argv[1]) {
        fake_non_git_calls++;
        return fake_finish(result, 127);
    }
    fake_git_calls++;
    if (strcmp(argv[1], "rev-parse") == 0) {
        static const unsigned char git_dir[] = ".git\n";

        if (!argv[2] || !fake_repository) return fake_finish(result, 1);
        if (strcmp(argv[2], "--git-dir") == 0) {
            return fake_write_output(opts, result, git_dir,
                                     sizeof(git_dir) - 1U);
        }
        if (strcmp(argv[2], "--show-toplevel") == 0 && fake_repo_root) {
            return fake_write_output(opts, result, fake_repo_root,
                                     fake_repo_root_len);
        }
        return fake_finish(result, 1);
    }
    if (strcmp(argv[1], "config") != 0 || !argv[2])
        return fake_finish(result, 1);

    if (strcmp(argv[2], "--file") == 0 && argv[3] && argv[4] &&
        argv[5] && argv[6] && argv[7] &&
        strcmp(argv[3], "/dev/null") == 0 &&
        strcmp(argv[4], "--bool") == 0 &&
        strncmp(argv[5], "--default=", strlen("--default=")) == 0 &&
        strcmp(argv[6], "--get") == 0 &&
        strcmp(argv[7], "gitswitch.boolean") == 0) {
        const char *raw = argv[5] + strlen("--default=");
        bool int_min = strcmp(raw, "-2g") == 0 ||
                       strcmp(raw, "-2097152k") == 0;

        if (int_min && !fake_reject_int_min_boolean) {
            static const unsigned char canonical_true[] = "true\n";
            return fake_write_output(opts, result, canonical_true,
                                     sizeof(canonical_true) - 1U);
        }
        {
            char diagnostic[256];
            snprintf(diagnostic, sizeof(diagnostic),
                     "fatal: bad boolean config value '%s' for "
                     "'gitswitch.boolean'\n",
                     raw);
            return fake_write_error(opts, result, diagnostic, 128);
        }
    }

    if (strcmp(argv[2], "--show-origin") == 0) {
        fake_listing_calls++;
        if (fake_execution_failure) {
            if (opts && opts->merge_stderr && opts->out &&
                opts->out_size > 0) {
                size_t length = fake_failure_diagnostic_len;
                size_t copied = length < opts->out_size - 1U
                                    ? length : opts->out_size - 1U;
                memcpy(opts->out, fake_failure_diagnostic, copied);
                opts->out[copied] = '\0';
                if (result) {
                    result->out_len = copied;
                    result->out_truncated = copied < length;
                }
            }
            return fake_finish(result, 128);
        }

        if (!opts || !opts->out || opts->out_size == 0)
            return fake_finish(result, 1);
        size_t capacity = opts->out_size - 1U;
        size_t copied = fake_listing_len < capacity
                            ? fake_listing_len : capacity;
        memcpy(opts->out, fake_listing, copied);
        opts->out[copied] = '\0';
        if (result) {
            result->out_len = copied;
            result->out_truncated = copied < fake_listing_len;
        }
        return fake_finish(result, 0);
    }

    return fake_finish(result, 1);
}

TEST(oversized_unrelated_config_is_captured_without_losing_identity) {
    static char huge_value[50000];
    git_current_config_t current;
    command_runner_fn previous;

    memset(huge_value, 'x', sizeof(huge_value));
    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", "file:/ar07/global", "audit.huge",
                             huge_value, sizeof(huge_value)));
    CHECK(fake_append_record("global", "file:/ar07/global", "user.name",
                             "Dynamic User", strlen("Dynamic User")));
    CHECK(fake_append_record("global", "file:/ar07/global", "user.email",
                             "dynamic@example.test",
                             strlen("dynamic@example.test")));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    run_set_runner(previous);

    CHECK(current.valid);
    CHECK_STR_EQ(current.name, "Dynamic User");
    CHECK_STR_EQ(current.email, "dynamic@example.test");
    CHECK(fake_listing_calls > 1); /* The capture grew instead of truncating. */
}

TEST(malformed_effective_listing_is_an_error_not_absence) {
    git_current_config_t current;
    command_runner_fn previous;
    const char scope[] = "global\0";
    const char origin[] = "file:/broken\0";
    const char unterminated[] = "user.name\nBroken";

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append(scope, sizeof(scope) - 1U));
    CHECK(fake_append(origin, sizeof(origin) - 1U));
    CHECK(fake_append(unterminated, sizeof(unterminated) - 1U));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    run_set_runner(previous);

    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message, "Malformed") != NULL);
    CHECK(!current.valid);
}

static int capture_status_output_for(const gitswitch_ctx_t *context,
                                     char *output, size_t output_size) {
    FILE *capture = tmpfile();
    int saved_stdout;
    size_t length;

    if (!capture || !context || !output || output_size == 0) return -1;
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        fclose(capture);
        return -1;
    }
    fflush(stdout);
    if (dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        close(saved_stdout);
        fclose(capture);
        return -1;
    }
    int status_rc = accounts_show_status(context);
    fflush(stdout);
    int restore_rc = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    rewind(capture);
    length = fread(output, 1, output_size - 1U, capture);
    output[length] = '\0';
    fclose(capture);
    if (restore_rc != STDOUT_FILENO) return -2;
    return status_rc;
}

static int capture_status_output(char *output, size_t output_size) {
    gitswitch_ctx_t context;
    memset(&context, 0, sizeof(context));
    return capture_status_output_for(&context, output, output_size);
}

static int capture_git_error_log(git_current_config_t *current,
                                 char *output, size_t output_size) {
    FILE *capture = tmpfile();
    int saved_stderr;
    size_t length;

    if (!capture || !current || !output || output_size == 0) return -1;
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        fclose(capture);
        return -1;
    }
    fflush(stderr);
    if (dup2(fileno(capture), STDERR_FILENO) != STDERR_FILENO) {
        close(saved_stderr);
        fclose(capture);
        return -1;
    }
    int git_rc = git_get_current_config(current);
    fflush(stderr);
    int restore_rc = dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    rewind(capture);
    length = fread(output, 1, output_size - 1U, capture);
    output[length] = '\0';
    fclose(capture);
    if (restore_rc != STDERR_FILENO) return -2;
    return git_rc;
}

static bool contains_bytes(const char *haystack, size_t haystack_length,
                           const unsigned char *needle,
                           size_t needle_length) {
    if (!haystack || !needle || needle_length == 0 ||
        needle_length > haystack_length) {
        return false;
    }
    for (size_t i = 0; i <= haystack_length - needle_length; i++) {
        if (memcmp(haystack + i, needle, needle_length) == 0) return true;
    }
    return false;
}

static size_t count_text(const char *haystack, const char *needle) {
    size_t count = 0;
    size_t needle_length = strlen(needle);

    if (!haystack || needle_length == 0) return 0;
    while ((haystack = strstr(haystack, needle)) != NULL) {
        count++;
        haystack += needle_length;
    }
    return count;
}

static void check_effective_git_value(
    const git_config_effective_value_t *value, bool expected_present,
    const char *expected_value, const char *expected_origin) {
    CHECK(value != NULL);
    if (!value) return;

    CHECK_EQ_INT(value->present, expected_present);
    if (!expected_present) {
        CHECK_EQ_INT(value->scope, GIT_CONFIG_ORIGIN_UNKNOWN);
        CHECK(value->origin[0] == '\0');
        CHECK(value->value[0] == '\0');
        return;
    }

    CHECK(!value->value_unknown);
    CHECK_STR_EQ(value->value, expected_value);
    CHECK_EQ_INT(value->scope, GIT_CONFIG_ORIGIN_GLOBAL);
    CHECK_STR_EQ(value->origin, expected_origin);
}

TEST(status_escapes_and_bounds_every_external_value) {
    static const unsigned char hostile_name[] = {
        'G', 'i', 't', '\n', 'N', 'a', 'm', 'e', 0x1b, '[', '3', '1', 'm'
    };
    static const unsigned char hostile_email[] = {
        'm', 'a', 'i', 'l', '\\', 'x', 0xc2, 0x9b, '@', 'x'
    };
    static const unsigned char hostile_signing_key[] = {
        'K', 'E', 'Y', 0xe2, 0x80, 0xae, 0xff
    };
    static const unsigned char encoded_c1[] = {0xc2, 0x9b};
    static const unsigned char encoded_bidi[] = {0xe2, 0x80, 0xae};
    char long_origin[768];
    unsigned char long_root[768];
    gitswitch_ctx_t context;
    char status[8192];
    command_runner_fn previous;

    memset(long_origin, 'o', sizeof(long_origin));
    memcpy(long_origin, "file:/cfg\\origin", strlen("file:/cfg\\origin"));
    long_origin[20] = (char)0x1b;
    long_origin[21] = '\n';
    long_origin[700] = '\0';
    memset(long_root, 'r', sizeof(long_root));
    memcpy(long_root, "/repo\\root", strlen("/repo\\root"));
    long_root[16] = '\n';
    long_root[17] = 0x9b;
    long_root[700] = '\n';

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = true;
    fake_repo_root = long_root;
    fake_repo_root_len = 701U;
    CHECK(fake_append_record("global", long_origin, "user.name",
                             (const char *)hostile_name,
                             sizeof(hostile_name)));
    CHECK(fake_append_record("global", long_origin, "user.email",
                             (const char *)hostile_email,
                             sizeof(hostile_email)));
    CHECK(fake_append_record("global", long_origin, "user.signingkey",
                             (const char *)hostile_signing_key,
                             sizeof(hostile_signing_key)));

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0].id = 1;
    context.accounts[0].preferred_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Expected User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "expected@example.test",
                              sizeof(context.accounts[0].email)), 0);
    context.current_account = &context.accounts[0];

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status, sizeof(status)), 0);
    run_set_runner(previous);
    fake_repository = false;
    fake_repo_root = NULL;
    fake_repo_root_len = 0;
    git_ops_test_reset_caches();

    CHECK(strstr(status, "Current Name: Git\\x0AName\\x1B[31m") != NULL);
    CHECK(strstr(status, "Current Email: mail\\\\x\\xC2\\x9B@x") != NULL);
    CHECK(strstr(status, "GPG Signing Key: KEY\\xE2\\x80\\xAE\\xFF") !=
          NULL);
    CHECK(strstr(status, "file:/cfg\\\\origin") != NULL);
    CHECK(strstr(status, "/repo\\\\root") != NULL);
    CHECK(strstr(status, "\\x0A") != NULL);
    CHECK(strstr(status, "\\x9B") != NULL);
    CHECK(count_text(status, "...[truncated]") >= 2U);
    CHECK(memchr(status, 0x1b, strlen(status)) == NULL);
    CHECK(memchr(status, 0x9b, strlen(status)) == NULL);
    CHECK(!contains_bytes(status, strlen(status), encoded_c1,
                          sizeof(encoded_c1)));
    CHECK(!contains_bytes(status, strlen(status), encoded_bidi,
                          sizeof(encoded_bidi)));
    CHECK(memchr(status, 0xff, strlen(status)) == NULL);
}

TEST(execution_failure_retains_diagnostic_and_status_reports_error) {
    git_current_config_t current;
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = true;
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);

    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message, "injected unreadable") != NULL);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), -1);

    run_set_runner(previous);
    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status, "injected unreadable") != NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
}

TEST(execution_diagnostic_is_sanitized_before_error_logging) {
    static const unsigned char hostile_diagnostic[] = {
        'f', 'a', 't', 'a', 'l', ':', ' ', 0x1b, '[', '3', '1', 'm',
        'R', 'E', 'D', ' ', 0xc2, 0x9b, '2', 'J', ' ', 0x9b, '\n'
    };
    static const unsigned char encoded_csi[] = { 0xc2, 0x9b };
    git_current_config_t current;
    char log_output[8192];
    const error_context_t *error;
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = true;
    fake_failure_diagnostic = hostile_diagnostic;
    fake_failure_diagnostic_len = sizeof(hostile_diagnostic);
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);

    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(capture_git_error_log(&current, log_output,
                                       sizeof(log_output)), -1);
    error = get_last_error();

    run_set_runner(previous);
    fake_failure_diagnostic = default_failure_diagnostic;
    fake_failure_diagnostic_len = sizeof(default_failure_diagnostic) - 1U;
    fake_execution_failure = false;

    CHECK_EQ_INT(error->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(error->message, "fatal:") != NULL);
    CHECK(strstr(error->message, "RED") != NULL);
    CHECK(memchr(error->message, 0x1b, strlen(error->message)) == NULL);
    CHECK(memchr(error->message, 0x9b, strlen(error->message)) == NULL);
    CHECK(!contains_bytes(error->message, strlen(error->message), encoded_csi,
                          sizeof(encoded_csi)));
    CHECK(memchr(log_output, 0x1b, strlen(log_output)) == NULL);
    CHECK(memchr(log_output, 0x9b, strlen(log_output)) == NULL);
    CHECK(!contains_bytes(log_output, strlen(log_output), encoded_csi,
                          sizeof(encoded_csi)));
}

TEST(absent_identity_remains_a_normal_status_result) {
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), 0);
    run_set_runner(previous);

    CHECK(strstr(status, "Status: [NOT FOUND]") != NULL);
    CHECK(strstr(status, "Status: [ERROR]") == NULL);
}

TEST(partial_identity_renders_every_credential_leg) {
    static const struct {
        bool include_name;
        bool include_email;
    } cases[] = {
        { false, true },
        { true, false },
        { false, false }
    };
    static const char origin[] = "file:/ar11/partial.gitconfig";
    static const char name[] = "Partial Residue User";
    static const char email[] = "partial-residue@example.test";
    static const char fingerprint[] =
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    static const char ssh_command[] =
        "'/trusted/ar11/ssh' -i '/keys/ar11-residue' -F '/dev/null'";
    static const char openpgp_program[] = "/trusted/ar11/openpgp";
    static const char legacy_program[] = "/foreign/ar11/legacy-gpg";
    static const char x509_program[] = "/foreign/ar11/x509-gpg";
    static const char ssh_program[] = "/foreign/ar11/ssh-gpg";

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        git_status_snapshot_t *current = NULL;
        git_current_config_t legacy;
        char status[8192];
        command_runner_fn previous;

        fake_listing_len = 0;
        fake_listing_calls = 0;
        fake_execution_failure = false;
        fake_repository = false;
        if (cases[i].include_name) {
            CHECK(fake_append_record("global", origin, GIT_CONFIG_USER_NAME,
                                     name, strlen(name)));
        }
        if (cases[i].include_email) {
            CHECK(fake_append_record("global", origin, GIT_CONFIG_USER_EMAIL,
                                     email, strlen(email)));
        }
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_CORE_SSHCOMMAND, ssh_command,
                                 strlen(ssh_command)));
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_USER_SIGNINGKEY, fingerprint,
                                 strlen(fingerprint)));
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_COMMIT_GPGSIGN, "true",
                                 strlen("true")));
        CHECK(fake_append_record("global", origin, GIT_CONFIG_GPG_FORMAT,
                                 "openpgp", strlen("openpgp")));
        CHECK(fake_append_record("global", origin, GIT_CONFIG_GPG_PROGRAM,
                                 legacy_program, strlen(legacy_program)));
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                 openpgp_program, strlen(openpgp_program)));
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_GPG_X509_PROGRAM, x509_program,
                                 strlen(x509_program)));
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_GPG_SSH_PROGRAM, ssh_program,
                                 strlen(ssh_program)));

        git_ops_test_reset_caches();
        previous = run_set_runner(status_fake_runner);
        CHECK_EQ_INT(git_status_snapshot_read(&current), 0);
        run_set_runner(previous);

        CHECK(current != NULL);
        CHECK(current && current->valid);
        if (!current) continue;
        check_effective_git_value(&current->user_name,
                                  cases[i].include_name, name, origin);
        check_effective_git_value(&current->user_email,
                                  cases[i].include_email, email, origin);
        check_effective_git_value(&current->user_signing_key, true,
                                  fingerprint, origin);
        check_effective_git_value(&current->commit_gpgsign, true, "true",
                                  origin);
        check_effective_git_value(&current->gpg_format, true, "openpgp",
                                  origin);
        check_effective_git_value(&current->ssh_command, true, ssh_command,
                                  origin);
        check_effective_git_value(&current->gpg_program, true, legacy_program,
                                  origin);
        check_effective_git_value(&current->gpg_openpgp_program, true,
                                  openpgp_program, origin);
        check_effective_git_value(&current->gpg_x509_program, true,
                                  x509_program, origin);
        check_effective_git_value(&current->gpg_ssh_program, true,
                                  ssh_program, origin);
        CHECK(current->gpg_signing_enabled);
        git_status_snapshot_free(current);
        current = NULL;

        /* The retained caller-owned API keeps its historical complete-
         * identity contract; the richer internal projection cannot change
         * its layout or mixed-version behavior. */
        git_ops_test_reset_caches();
        previous = run_set_runner(status_fake_runner);
        memset(&legacy, 0, sizeof(legacy));
        CHECK_EQ_INT(git_get_current_config(&legacy), -1);
        run_set_runner(previous);
        CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_NOT_FOUND);
        CHECK(!legacy.valid);

        git_ops_test_reset_caches();
        previous = run_set_runner(status_fake_runner);
        CHECK_EQ_INT(capture_status_output(status, sizeof(status)), 0);
        run_set_runner(previous);
        git_ops_test_reset_caches();

        CHECK(strstr(status, "No account currently active.") != NULL);
        CHECK(strstr(status,
                     cases[i].include_name
                         ? "Name: Partial Residue User"
                         : "Name: [ABSENT]") != NULL);
        CHECK(strstr(status,
                     cases[i].include_email
                         ? "Email: partial-residue@example.test"
                         : "Email: [ABSENT]") != NULL);
        CHECK(strstr(status, "Effective SSH Command: [SET]") != NULL);
        CHECK(strstr(status, "GPG Signing Key: ") != NULL);
        CHECK(strstr(status, fingerprint) != NULL);
        CHECK(strstr(status, "GPG Signing Enabled: [YES]") != NULL);
        CHECK(strstr(status, "Effective GPG Format: [SET]") != NULL);
        CHECK(strstr(status, "Effective OpenPGP Program: [SET]") != NULL);
        CHECK(strstr(status, "Effective Legacy GPG Program: [SET]") != NULL);
        CHECK(strstr(status, "Effective X.509 GPG Program: [SET]") != NULL);
        CHECK(strstr(status, "Effective SSH Signing Program: [SET]") != NULL);
        CHECK(count_text(status, origin) >= 8U);
        CHECK(strstr(status,
                     "[WARN] Durable Git credential configuration is set") !=
              NULL);
        CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
        CHECK(strstr(status, "Status: [ERROR]") == NULL);
    }
}

TEST(explicit_false_signing_state_is_present_residue) {
    static const char origin[] = "file:/ar11/false-signing.gitconfig";
    git_status_snapshot_t *current = NULL;
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, GIT_CONFIG_COMMIT_GPGSIGN,
                             "false", strlen("false")));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(git_status_snapshot_read(&current), 0);
    run_set_runner(previous);

    CHECK(current != NULL);
    CHECK(current && current->valid);
    if (!current) return;
    check_effective_git_value(&current->user_name, false, "", "");
    check_effective_git_value(&current->user_email, false, "", "");
    check_effective_git_value(&current->commit_gpgsign, true, "false", origin);
    CHECK(!current->gpg_signing_enabled);
    git_status_snapshot_free(current);

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), 0);
    run_set_runner(previous);
    git_ops_test_reset_caches();

    CHECK(strstr(status, "Name: [ABSENT]") != NULL);
    CHECK(strstr(status, "Email: [ABSENT]") != NULL);
    CHECK(strstr(status, "GPG Signing Key: [ABSENT]") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [NO]") != NULL);
    CHECK(strstr(status, origin) != NULL);
    CHECK(strstr(status, "Effective GPG Format: [ABSENT]") != NULL);
    CHECK(strstr(status,
                 "[WARN] Durable Git credential configuration is set") !=
          NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
    CHECK(strstr(status, "Status: [ERROR]") == NULL);
}

TEST(explicit_openpgp_format_is_visible_residue) {
    static const char origin[] = "file:/ar11/format-only.gitconfig";
    git_status_snapshot_t *current = NULL;
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, GIT_CONFIG_GPG_FORMAT,
                             "openpgp", strlen("openpgp")));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(git_status_snapshot_read(&current), 0);
    run_set_runner(previous);

    CHECK(current != NULL);
    CHECK(current && current->valid);
    if (!current) return;
    check_effective_git_value(&current->gpg_format, true, "openpgp", origin);
    check_effective_git_value(&current->commit_gpgsign, false, "", "");
    git_status_snapshot_free(current);

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), 0);
    run_set_runner(previous);
    git_ops_test_reset_caches();

    CHECK(strstr(status, "Name: [ABSENT]") != NULL);
    CHECK(strstr(status, "Email: [ABSENT]") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [ABSENT]") != NULL);
    CHECK(strstr(status, "Effective GPG Format: [SET]") != NULL);
    CHECK(strstr(status, origin) != NULL);
    CHECK(strstr(status,
                 "[WARN] Durable Git credential configuration is set") !=
          NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
    CHECK(strstr(status, "Status: [ERROR]") == NULL);
}

TEST(active_partial_identity_renders_residue_without_trusted_match) {
    static const char origin[] = "file:/ar11/active-partial.gitconfig";
    static const char ssh_command[] =
        "'/trusted/ar11/ssh' -i '/keys/active-partial' -F '/dev/null'";
    gitswitch_ctx_t context;
    char status[8192];
    command_runner_fn previous;

    memset(&context, 0, sizeof(context));
    context.account_count = 1U;
    context.accounts[0].id = 61U;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name,
                              "Expected Active User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "expected-active@example.test",
                              sizeof(context.accounts[0].email)), 0);
    bind_status_test_incarnation(&context.accounts[0]);
    context.current_account = &context.accounts[0];

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, GIT_CONFIG_USER_EMAIL,
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_CORE_SSHCOMMAND, ssh_command,
                             strlen(ssh_command)));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_COMMIT_GPGSIGN, "false",
                             strlen("false")));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), 0);
    run_set_runner(previous);
    git_ops_test_reset_caches();

    CHECK(strstr(status, "Current Name: [ABSENT]") != NULL);
    CHECK(strstr(status,
                 "Current Email: expected-active@example.test") != NULL);
    CHECK(strstr(status,
                 "Match Status: [WARN] Effective Git identity is incomplete") !=
          NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
    CHECK(strstr(status, "Effective SSH Command: [SET]") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [NO]") != NULL);
    CHECK(strstr(status, origin) != NULL);
    CHECK(strstr(status,
                 "Durable Git credential configuration is set with an incomplete identity") !=
                 NULL);
}

TEST(active_projection_failure_still_renders_captured_residue) {
    static const char origin[] = "file:/ar11/projection-failure.gitconfig";
    static const char ssh_command[] =
        "'/trusted/ar11/ssh' -i '/keys/projection-failure' -F '/dev/null'";
    char oversized_signing_key[MAX_GPG_FINGERPRINT_LEN + 16U];
    gitswitch_ctx_t context;
    char status[32768];
    command_runner_fn previous;

    memset(oversized_signing_key, 'A', sizeof(oversized_signing_key) - 1U);
    oversized_signing_key[sizeof(oversized_signing_key) - 1U] = '\0';
    memset(&context, 0, sizeof(context));
    context.account_count = 1U;
    context.accounts[0].id = 62U;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name,
                              "Projection User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "projection@example.test",
                              sizeof(context.accounts[0].email)), 0);
    bind_status_test_incarnation(&context.accounts[0]);
    context.current_account = &context.accounts[0];

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, GIT_CONFIG_USER_NAME,
                             context.accounts[0].name,
                             strlen(context.accounts[0].name)));
    CHECK(fake_append_record("global", origin, GIT_CONFIG_USER_EMAIL,
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_USER_SIGNINGKEY,
                             oversized_signing_key,
                             strlen(oversized_signing_key)));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_CORE_SSHCOMMAND, ssh_command,
                             strlen(ssh_command)));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), -1);
    run_set_runner(previous);
    git_ops_test_reset_caches();

    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status,
                 "Effective Git signing key exceeds supported field length") !=
          NULL);
    CHECK(strstr(status, "Captured Managed Git State:") != NULL);
    CHECK(strstr(status, "Current Name: Projection User") != NULL);
    CHECK(strstr(status, oversized_signing_key) != NULL);
    CHECK(strstr(status, "Effective SSH Command: [SET]") != NULL);
    CHECK(strstr(status, ssh_command) != NULL);
    CHECK(strstr(status, origin) != NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
}

TEST(absent_identity_with_invalid_boolean_reports_error) {
    static const char origin[] = "file:/ar07/global";
    static const char ssh_command[] =
        "'/trusted/ar11/ssh' -i '/keys/invalid-bool' -F '/dev/null'";
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", origin,
                             "commit.gpgsign", "not-a-git-boolean",
                             strlen("not-a-git-boolean")));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_CORE_SSHCOMMAND, ssh_command,
                             strlen(ssh_command)));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), -1);
    run_set_runner(previous);

    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status, "Invalid effective Git Boolean") != NULL);
    CHECK(strstr(status, "Captured Managed Git State:") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [ERROR]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [SET]") != NULL);
    CHECK(strstr(status, ssh_command) != NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
}

TEST(int_min_boolean_follows_selected_gits_grammar) {
    static const char *const int_min_spellings[] = {
        "-2g", "-2097152k"
    };
    command_runner_fn previous;

    previous = run_set_runner(status_fake_runner);
    for (size_t i = 0;
         i < sizeof(int_min_spellings) / sizeof(int_min_spellings[0]); i++) {
        git_current_config_t current;

        fake_listing_len = 0;
        fake_listing_calls = 0;
        fake_execution_failure = false;
        CHECK(fake_append_record("global", "file:/ar07/global", "user.name",
                                 "INT_MIN User", strlen("INT_MIN User")));
        CHECK(fake_append_record("global", "file:/ar07/global", "user.email",
                                 "int-min@example.test",
                                 strlen("int-min@example.test")));
        CHECK(fake_append_record("global", "file:/ar07/global",
                                 "commit.gpgsign", int_min_spellings[i],
                                 strlen(int_min_spellings[i])));

        fake_reject_int_min_boolean = false;
        git_ops_test_reset_caches();
        memset(&current, 0, sizeof(current));
        CHECK_EQ_INT(git_get_current_config(&current), 0);
        CHECK(current.valid);
        CHECK(current.gpg_signing_enabled);

        fake_reject_int_min_boolean = true;
        git_ops_test_reset_caches();
        memset(&current, 0, sizeof(current));
        CHECK_EQ_INT(git_get_current_config(&current), -1);
        CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
        CHECK(strstr(get_last_error()->message,
                     "Invalid effective Git Boolean value for "
                     "commit.gpgsign") != NULL);
        CHECK(strstr(get_last_error()->message, int_min_spellings[i]) != NULL);
        CHECK(!current.valid);
    }
    fake_reject_int_min_boolean = false;
    run_set_runner(previous);
}

TEST(absent_identity_with_oversized_managed_value_reports_error) {
    static char oversized[GIT_CONFIG_VALUE_MAX + 1U];
    char status[8192];
    command_runner_fn previous;

    memset(oversized, 's', sizeof(oversized));
    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", "file:/ar07/global",
                             "core.sshcommand", oversized,
                             sizeof(oversized)));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), -1);
    run_set_runner(previous);

    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status, "exceeds the supported status representation") !=
          NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
}

TEST(oversized_signing_boolean_is_not_rendered_as_false) {
    static char oversized[GIT_CONFIG_VALUE_MAX + 1U];
    static const char origin[] = "file:/ar11/oversized-signing.gitconfig";
    static const char ssh_command[] =
        "'/trusted/ar11/ssh' -i '/keys/oversized-signing' -F '/dev/null'";
    char status[32768];
    command_runner_fn previous;

    memset(oversized, '7', sizeof(oversized));
    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_COMMIT_GPGSIGN, oversized,
                             sizeof(oversized)));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_CORE_SSHCOMMAND, ssh_command,
                             strlen(ssh_command)));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), -1);
    run_set_runner(previous);

    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status, "Captured Managed Git State:") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [ERROR]") != NULL);
    CHECK(strstr(status, "GPG Signing Enabled: [NO]") == NULL);
    CHECK(strstr(status, "Effective SSH Command: [SET]") != NULL);
    CHECK(strstr(status, ssh_command) != NULL);
    CHECK(strstr(status, origin) != NULL);
    CHECK(strstr(status, "Status: [NOT FOUND]") == NULL);
}

static int install_ssh_publication(gitswitch_ctx_t *context,
                                   const account_t *account,
                                   const char *ssh_command,
                                   const char *ssh_program,
                                   char *origin, size_t origin_size) {
    static const unsigned char header_prefix[] = "gpg\nactive=";
    char root[MAX_PATH_LEN] = "/tmp/gsw_ar11_ssh_status_XXXXXX";
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    publication_record_t publication;
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    struct stat st;
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    publication_record_init(&publication);
    if (!context || !account || !ssh_command || !ssh_program ||
        !origin || origin_size == 0U || !ts_mkdtemp(root) ||
        chmod(root, 0700) != 0 ||
        ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        safe_snprintf(config_path, sizeof(config_path), "%s/gitconfig",
                      root) != 0 ||
        safe_snprintf(state_path, sizeof(state_path), "%s/.resume-hint",
                      root) != 0 ||
        write_text_file(config_path, "[fixture]\n", 0600) != 0 ||
        stat(root, &st) != 0 ||
        safe_snprintf(origin, origin_size, "file:%s", config_path) != 0 ||
        safe_strncpy(context->config.config_path, config_path,
                     sizeof(context->config.config_path)) != 0) {
        goto cleanup;
    }

    publication.account_id = account->id;
    if (safe_strncpy(publication.account_incarnation,
                     account->incarnation,
                     sizeof(publication.account_incarnation)) != 0 ||
        safe_strncpy(publication.config_path, config_path,
                     sizeof(publication.config_path)) != 0) {
        goto cleanup;
    }
    publication.scope = PUBLICATION_SCOPE_GLOBAL;
    publication_identity_from_stat(&publication.config_parent, &st);
    if (stat(config_path, &st) != 0 || stat(ssh_program, &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        safe_strncpy(publication.ssh_command, ssh_command,
                     sizeof(publication.ssh_command)) != 0 ||
        safe_strncpy(publication.ssh_program, ssh_program,
                     sizeof(publication.ssh_program)) != 0) {
        goto cleanup;
    }
    /* Re-read the config generation after the independent program stat. */
    if (stat(config_path, &st) != 0) goto cleanup;
    publication_identity_from_stat(&publication.post_config, &st);
    if (stat(ssh_program, &st) != 0) goto cleanup;
    publication_identity_from_stat(&publication.ssh_program_identity, &st);
    publication.capabilities = PUBLICATION_CAP_DESTINATION |
                               PUBLICATION_CAP_POST_GENERATION |
                               PUBLICATION_CAP_SSH_COMMAND |
                               PUBLICATION_CAP_SSH_PROGRAM;
    publication.state = PUBLICATION_STATE_PUBLISHED;
    if (publication_record_validate(&publication) != 0 ||
        publication_ledger_upsert(&ledger, &publication) != 0 ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }

    fd = open(state_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write_all_test_bytes(fd, header_prefix,
                             sizeof(header_prefix) - 1U) != 0 ||
        write_all_test_bytes(fd, account->name,
                             strlen(account->name)) != 0 ||
        write_all_test_bytes(fd, "\n", 1U) != 0 ||
        write_all_test_bytes(fd, tail, tail_length) != 0) {
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
        memset(tail, 0, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
}

TEST(active_ssh_without_publication_fails_before_any_git_probe) {
    gitswitch_ctx_t context;
    char status[8192];
    int status_rc;
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_git_calls = 0;
    fake_non_git_calls = 0;
    fake_execution_failure = false;

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0].id = 7;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Active User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "active@example.test",
                              sizeof(context.accounts[0].email)), 0);
    bind_status_test_incarnation(&context.accounts[0]);
    context.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path,
                              "/definitely/not/present/ar07-status-key",
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    context.current_account = &context.accounts[0];

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, sizeof(status));
    run_set_runner(previous);

    CHECK_EQ_INT(status_rc, -1);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "SSH provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [ERROR]") != NULL);
    CHECK_EQ_INT(fake_git_calls, 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);
}

TEST(active_ssh_status_uses_saved_program_and_exact_destination) {
    char key_a[] = "/tmp/gsw_ar11_status_key_a_XXXXXX";
    char key_b[] = "/tmp/gsw_ar11_status_key_b_XXXXXX";
    char ssh_program[MAX_PATH_LEN];
    char published_command[GIT_CONFIG_VALUE_MAX];
    char origin[MAX_PATH_LEN];
    char status[8192];
    gitswitch_ctx_t context;
    command_runner_fn previous;
    saved_env_t path = save_env("PATH");
    int key_a_fd = -1;
    int key_b_fd = -1;

    if (find_command_path("ssh", ssh_program, sizeof(ssh_program)) != 0) {
        TS_SKIP("openssh", "no trusted SSH executable on this host");
    }
    key_a_fd = mkstemp(key_a);
    key_b_fd = mkstemp(key_b);
    CHECK(key_a_fd >= 0);
    CHECK(key_b_fd >= 0);
    if (key_a_fd < 0 || key_b_fd < 0) goto cleanup;
    CHECK_EQ_INT(fchmod(key_a_fd, 0600), 0);
    CHECK_EQ_INT(fchmod(key_b_fd, 0600), 0);
    CHECK_EQ_INT(close(key_a_fd), 0);
    key_a_fd = -1;
    CHECK_EQ_INT(close(key_b_fd), 0);
    key_b_fd = -1;

    memset(&context, 0, sizeof(context));
    context.account_count = 1U;
    context.accounts[0].id = 17U;
    bind_status_test_incarnation(&context.accounts[0]);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "SSH Ledger User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "ssh-ledger@example.test",
                              sizeof(context.accounts[0].email)), 0);
    context.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path, key_a,
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    context.current_account = &context.accounts[0];
    CHECK_EQ_INT(git_expected_ssh_command(
                     &context.accounts[0], published_command,
                     sizeof(published_command)), 0);
    CHECK_EQ_INT(install_ssh_publication(
                     &context, &context.accounts[0], published_command,
                     ssh_program, origin, sizeof(origin)), 0);

    CHECK_EQ_INT(setenv("PATH", "/definitely/not/present", 1), 0);
    fake_listing_len = 0U;
    fake_listing_calls = 0;
    fake_git_calls = 0;
    fake_non_git_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, "user.name",
                             context.accounts[0].name,
                             strlen(context.accounts[0].name)));
    CHECK(fake_append_record("global", origin, "user.email",
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("global", origin, GIT_CONFIG_CORE_SSHCOMMAND,
                             published_command, strlen(published_command)));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), 0);
    run_set_runner(previous);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [MATCH]") != NULL);
    CHECK(fake_git_calls > 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);

    /* The account model changed after publication. Rebuild it with the saved
     * program, not PATH, and report the exact old Git value as drift. */
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path, key_b,
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    fake_git_calls = 0;
    fake_non_git_calls = 0;
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), 0);
    run_set_runner(previous);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [MISMATCH]") != NULL);
    CHECK(fake_git_calls > 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);

    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path, key_a,
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    fake_listing_len = 0U;
    CHECK(fake_append_record("global", origin, "user.name",
                             context.accounts[0].name,
                             strlen(context.accounts[0].name)));
    CHECK(fake_append_record("global", origin, "user.email",
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("local", origin, GIT_CONFIG_CORE_SSHCOMMAND,
                             published_command, strlen(published_command)));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), 0);
    run_set_runner(previous);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [MISMATCH]") != NULL);

    fake_listing_len = 0U;
    CHECK(fake_append_record("global", origin, "user.name",
                             context.accounts[0].name,
                             strlen(context.accounts[0].name)));
    CHECK(fake_append_record("global", origin, "user.email",
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("global", "file:/foreign/gitconfig",
                             GIT_CONFIG_CORE_SSHCOMMAND,
                             published_command, strlen(published_command)));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), 0);
    run_set_runner(previous);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [MISMATCH]") != NULL);

cleanup:
    if (key_a_fd >= 0) CHECK_EQ_INT(close(key_a_fd), 0);
    if (key_b_fd >= 0) CHECK_EQ_INT(close(key_b_fd), 0);
    if (key_a[0] != '\0') (void)unlink(key_a);
    if (key_b[0] != '\0') (void)unlink(key_b);
    restore_env("PATH", &path);
    git_ops_test_reset_caches();
}

static int denied_status_key_open(const char *path, int flags) {
    (void)path;
    (void)flags;
    errno = EACCES;
    return -1;
}

TEST(active_status_propagates_required_key_inspection_failure) {
    gitswitch_ctx_t context;
    char key_path[] = "/tmp/gsw_ar09_status_key_XXXXXX";
    char expected_ssh[GIT_CONFIG_VALUE_MAX];
    char ssh_program[MAX_PATH_LEN];
    char origin[MAX_PATH_LEN];
    char status[8192];
    command_runner_fn previous_runner;
    ssh_key_open_fn previous_open;
    int key_fd = -1;
    int status_rc;

    if (find_command_path("ssh", ssh_program, sizeof(ssh_program)) != 0) {
        TS_SKIP("openssh", "no trusted SSH executable on this host");
    }
    key_fd = mkstemp(key_path);
    CHECK(key_fd >= 0);
    if (key_fd < 0) return;
    CHECK_EQ_INT(fchmod(key_fd, 0600), 0);
    CHECK_EQ_INT(write(key_fd,
                       "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                       strlen("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n")),
                 (ssize_t)strlen(
                     "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n"));
    CHECK_EQ_INT(close(key_fd), 0);
    key_fd = -1;

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0].id = 10;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Inspection User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "inspection@example.test",
                              sizeof(context.accounts[0].email)), 0);
    bind_status_test_incarnation(&context.accounts[0]);
    context.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path,
                              key_path,
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    context.current_account = &context.accounts[0];
    CHECK_EQ_INT(git_expected_ssh_command(&context.accounts[0], expected_ssh,
                                          sizeof(expected_ssh)), 0);
    CHECK_EQ_INT(install_ssh_publication(
                     &context, &context.accounts[0], expected_ssh,
                     ssh_program, origin, sizeof(origin)), 0);

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, "user.name",
                             context.accounts[0].name,
                             strlen(context.accounts[0].name)));
    CHECK(fake_append_record("global", origin, "user.email",
                             context.accounts[0].email,
                             strlen(context.accounts[0].email)));
    CHECK(fake_append_record("global", origin, GIT_CONFIG_CORE_SSHCOMMAND,
                             expected_ssh, strlen(expected_ssh)));

    git_ops_test_reset_caches();
    previous_runner = run_set_runner(status_fake_runner);
    previous_open = ssh_manager_set_key_open_fn(denied_status_key_open);
    status_rc = capture_status_output_for(&context, status, sizeof(status));
    ssh_manager_set_key_open_fn(previous_open);
    run_set_runner(previous_runner);
    git_ops_test_reset_caches();

    CHECK_EQ_INT(status_rc, -1);
    CHECK(strstr(status, "Key File: [ERROR] Unable to inspect safely") != NULL);
    CHECK(strstr(status, "Cannot safely open SSH key file") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [MATCH]") != NULL);
    CHECK(strstr(status, "Match Status: [ERROR]") == NULL);

    git_ops_test_reset_caches();
    previous_runner = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, sizeof(status));
    run_set_runner(previous_runner);
    git_ops_test_reset_caches();

    CHECK_EQ_INT(status_rc, 0);
    CHECK(strstr(status, "Key File: [FOUND]") != NULL);
    CHECK(strstr(status, "Permissions: [SECURE] (600)") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);
    if (key_fd >= 0) CHECK_EQ_INT(close(key_fd), 0);
    CHECK_EQ_INT(unlink(key_path), 0);
}

static int install_signing_publication(gitswitch_ctx_t *context,
                                       const account_t *account,
                                       const char *fingerprint,
                                       const char *gpg_program,
                                       publication_state_t state,
                                       char *origin, size_t origin_size) {
    static const unsigned char header_prefix[] = "gpg\nactive=";
    char root[MAX_PATH_LEN] = "/tmp/gsw_ar11_status_XXXXXX";
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    publication_record_t publication;
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0;
    struct stat st;
    int origin_length;
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    publication_record_init(&publication);
    if (!context || !account || !origin || origin_size == 0U ||
        !ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        (size_t)snprintf(config_path, sizeof(config_path), "%s/gitconfig",
                         root) >= sizeof(config_path) ||
        (size_t)snprintf(state_path, sizeof(state_path), "%s/.resume-hint",
                         root) >= sizeof(state_path) ||
        write_text_file(config_path, "[fixture]\n", 0600) != 0 ||
        stat(root, &st) != 0) {
        goto cleanup;
    }

    origin_length = snprintf(origin, origin_size, "file:%s", config_path);
    if (safe_strncpy(context->config.config_path, config_path,
                     sizeof(context->config.config_path)) != 0 ||
        origin_length < 0 || (size_t)origin_length >= origin_size) {
        goto cleanup;
    }
    if (!fingerprint) {
        result = 0;
        goto cleanup;
    }
    if (!gpg_program) goto cleanup;

    publication.account_id = account->id;
    if (safe_strncpy(publication.account_incarnation,
                     account->incarnation,
                     sizeof(publication.account_incarnation)) != 0) {
        goto cleanup;
    }
    publication.scope = PUBLICATION_SCOPE_GLOBAL;
    if (safe_strncpy(publication.config_path, config_path,
                     sizeof(publication.config_path)) != 0) {
        goto cleanup;
    }
    publication_identity_from_stat(&publication.config_parent, &st);
    if (stat(config_path, &st) != 0) goto cleanup;
    publication_identity_from_stat(&publication.post_config, &st);
    if (stat(gpg_program, &st) != 0 || !S_ISREG(st.st_mode) ||
        safe_strncpy(publication.gpg_fingerprint, fingerprint,
                     sizeof(publication.gpg_fingerprint)) != 0 ||
        safe_strncpy(publication.gpg_program, gpg_program,
                     sizeof(publication.gpg_program)) != 0) {
        goto cleanup;
    }
    publication_identity_from_stat(&publication.gpg_program_identity, &st);
    publication.capabilities = PUBLICATION_CAP_DESTINATION |
                               PUBLICATION_CAP_POST_GENERATION |
                               PUBLICATION_CAP_GPG_FINGERPRINT |
                               PUBLICATION_CAP_GPG_PROGRAM;
    if (!publication_omit_selector_override) {
        if (publication_normalize_gpg_selector(
                publication_selector_override
                    ? publication_selector_override
                    : account->gpg_key_id,
                publication.gpg_selector) != 0) {
            goto cleanup;
        }
        publication.capabilities |= PUBLICATION_CAP_GPG_SELECTOR;
    }
    publication.state = state;
    if (publication_ledger_upsert(&ledger, &publication) != 0 ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0 ||
        publication_record_validate(&publication) != 0) {
        goto cleanup;
    }

    fd = open(state_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write_all_test_bytes(fd, header_prefix,
                             sizeof(header_prefix) - 1U) != 0 ||
        write_all_test_bytes(fd, account->name,
                             strlen(account->name)) != 0 ||
        write_all_test_bytes(fd, "\n", 1U) != 0 ||
        write_all_test_bytes(fd, tail, tail_length) != 0) {
        goto cleanup;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) close(fd);
    if (tail) {
        memset(tail, 0, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
}

static int capture_signing_status_incarnation_state(
    const account_t *account, const char *publication_incarnation,
    const char *published_fingerprint,
    const char *published_gpg_program, publication_state_t state,
    const char *signing_key, const char *gpg_signing,
    const char *openpgp_program, const char *foreign_program_key,
    const char *foreign_program, char *status, size_t status_size) {
    gitswitch_ctx_t context;
    account_t publication_owner;
    command_runner_fn previous;
    char origin[MAX_PATH_LEN] = "file:/ar09/global";
    int status_rc;

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0] = *account;
    if (!account_incarnation_is_valid(context.accounts[0].incarnation)) {
        bind_status_test_incarnation(&context.accounts[0]);
    }
    context.current_account = &context.accounts[0];
    publication_owner = context.accounts[0];
    if (publication_incarnation &&
        safe_strncpy(publication_owner.incarnation,
                     publication_incarnation,
                     sizeof(publication_owner.incarnation)) != 0) {
        return -1;
    }
    publication_owner.incarnation_persisted = true;
    if (install_signing_publication(&context, &publication_owner,
                                    published_fingerprint,
                                    published_gpg_program, state, origin,
                                    sizeof(origin)) != 0) {
        return -1;
    }

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_non_git_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, "user.name",
                             account->name, strlen(account->name)));
    CHECK(fake_append_record("global", origin, "user.email",
                             account->email, strlen(account->email)));
    if (signing_key) {
        CHECK(fake_append_record("global", origin,
                                 "user.signingkey", signing_key,
                                 strlen(signing_key)));
    }
    if (gpg_signing) {
        CHECK(fake_append_record("global", origin,
                                 "commit.gpgsign", gpg_signing,
                                 strlen(gpg_signing)));
    }
    if (openpgp_program) {
        CHECK(fake_append_record("global", origin,
                                 GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                 openpgp_program,
                                 strlen(openpgp_program)));
    }
    if (foreign_program_key && foreign_program) {
        CHECK(fake_append_record("global", origin,
                                 foreign_program_key, foreign_program,
                                 strlen(foreign_program)));
    }

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, status_size);
    run_set_runner(previous);
    git_ops_test_reset_caches();
    publication_selector_override = NULL;
    publication_omit_selector_override = false;
    return status_rc;
}

static int capture_signing_status_state(
    const account_t *account, const char *published_fingerprint,
    const char *published_gpg_program, publication_state_t state,
    const char *signing_key, const char *gpg_signing,
    const char *openpgp_program, const char *foreign_program_key,
    const char *foreign_program, char *status, size_t status_size) {
    return capture_signing_status_incarnation_state(
        account, NULL, published_fingerprint, published_gpg_program, state,
        signing_key, gpg_signing, openpgp_program, foreign_program_key,
        foreign_program, status, status_size);
}

static int capture_signing_status(const account_t *account,
                                  const char *published_fingerprint,
                                  const char *published_gpg_program,
                                  const char *signing_key,
                                  const char *gpg_signing,
                                  const char *openpgp_program,
                                  const char *foreign_program_key,
                                  const char *foreign_program,
                                  char *status, size_t status_size) {
    return capture_signing_status_state(
        account, published_fingerprint, published_gpg_program,
        PUBLICATION_STATE_PUBLISHED, signing_key, gpg_signing,
        openpgp_program, foreign_program_key, foreign_program, status,
        status_size);
}

TEST(active_status_includes_every_selected_signing_field) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    static const char wrong_key[] =
        "0123456789ABCDEF0123456789ABCDEFFEDCBA98";
    account_t account;
    char status[8192];
    char expected_program[MAX_PATH_LEN];
    saved_env_t gnupg_home;

    if (gpg_manager_resolve_executable(expected_program,
                                       sizeof(expected_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }

    memset(&account, 0, sizeof(account));
    account.id = 9;
    CHECK_EQ_INT(safe_strncpy(account.name, "Signing User",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "signing@example.test",
                              sizeof(account.email)), 0);
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    bind_status_test_incarnation(&account);
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0x89abcdef",
                              sizeof(account.gpg_key_id)), 0);

    /* A successful switch publishes the canonical primary fingerprint even
     * when the persisted account retains a shorter, 0x-prefixed selector. */
    gnupg_home = save_env("GNUPGHOME");
    CHECK_EQ_INT(setenv("GNUPGHOME",
                        "/definitely/not/present/ar11-status-source", 1), 0);
    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    restore_env("GNUPGHOME", &gnupg_home);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);
    CHECK(strstr(status, "Effective OpenPGP Program: [MATCH]") != NULL);
    CHECK_EQ_INT(fake_non_git_calls, 0);

    /* Missing/wrong OpenPGP bindings and foreign selector spellings are all
     * mismatches. In particular, the exact same path under legacy
     * gpg.program must not be accepted as equivalent to gpg.openpgp.program. */
    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", NULL, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", "/wrong/ar11/gpg", NULL,
                     NULL, status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", NULL, GIT_CONFIG_GPG_PROGRAM,
                     expected_program, status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", expected_program,
                     GIT_CONFIG_GPG_X509_PROGRAM, expected_program,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "true", expected_program,
                     GIT_CONFIG_GPG_SSH_PROGRAM, expected_program,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program, NULL,
                     "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program, wrong_key,
                     "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "false", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    account.gpg_signing_enabled = false;
    CHECK_EQ_INT(capture_signing_status(
                     &account, canonical_key, expected_program,
                     canonical_key, "false", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    account.gpg_enabled = false;
    CHECK_EQ_INT(capture_signing_status(
                     &account, NULL, NULL, NULL, "false", NULL, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, NULL, NULL, canonical_key, "false", NULL,
                     NULL, NULL, status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(
                     &account, NULL, NULL, NULL, "true", NULL, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
}

TEST(edited_short_selector_cannot_reuse_historical_fingerprint) {
    static const char published_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    account_t account;
    char status[8192];
    char expected_program[MAX_PATH_LEN];

    if (gpg_manager_resolve_executable(expected_program,
                                       sizeof(expected_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }

    memset(&account, 0, sizeof(account));
    account.id = 12;
    CHECK_EQ_INT(safe_strncpy(account.name, "Edited Selector",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "edited@example.test",
                              sizeof(account.email)), 0);
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    bind_status_test_incarnation(&account);
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0xFEDCBA98",
                              sizeof(account.gpg_key_id)), 0);

    /* The immutable account incarnation did not change, but its saved short
     * selector did. Git still carrying the old canonical publication can no
     * longer be attributed to this edited account. No keyring observation is
     * needed or allowed. */
    publication_selector_override = "0x89abcdef";
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     published_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
    CHECK(strstr(status,
                 "Expected Switch-time GPG Selector: 89ABCDEF") != NULL);
    CHECK(strstr(status,
                 "Current Account GPG Selector:  FEDCBA98") != NULL);
    CHECK(strstr(status, "Expected GPG Signing Key:") == NULL);

    /* Optional 0x and ASCII hex case are representation only. */
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0x89abcdef",
                              sizeof(account.gpg_key_id)), 0);
    publication_selector_override = "89ABCDEF";
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     published_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    /* Selector length is identity-significant even when the short spelling is
     * a suffix of the historical full selector. */
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "89ABCDEF",
                              sizeof(account.gpg_key_id)), 0);
    publication_selector_override = published_key;
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     published_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), 0);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
    CHECK(strstr(status,
                 "Expected Switch-time GPG Selector: 0123456789ABCDEF0123456789ABCDEF89ABCDEF") != NULL);
    CHECK(strstr(status,
                 "Current Account GPG Selector:  89ABCDEF") != NULL);

    /* Malformed current account input is distinct from missing persisted
     * switch-time provenance. The status path remains observational and
     * reports the actual invalid field. */
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "not-hex",
                              sizeof(account.gpg_key_id)), 0);
    publication_selector_override = "89ABCDEF";
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     published_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), -1);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") == NULL);
    CHECK(strstr(status,
                 "Signing attribution: [UNAVAILABLE] current account GPG selector is invalid") != NULL);
    CHECK(strstr(status,
                 "Expected Switch-time GPG Selector: 89ABCDEF") != NULL);
    CHECK(strstr(status,
                 "Current Account GPG Selector:  not-hex [INVALID]") != NULL);
    CHECK(strstr(status,
                 "complete switch-time selector provenance unavailable") == NULL);

    /* Invalid current input keeps ERROR precedence when the configured key is
     * independently foreign; comparison order cannot downgrade it to WARN. */
    publication_selector_override = "89ABCDEF";
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     "0123456789ABCDEF0123456789ABCDEFFEDCBA98", "true",
                     expected_program, NULL, NULL, status, sizeof(status)),
                 -1);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status,
                 "Signing attribution: [UNAVAILABLE] current account GPG selector is invalid") != NULL);
    CHECK(strstr(status, "Match Status: [WARN]") == NULL);

    /* A legacy fingerprint/program record remains parseable for retirement,
     * but missing switch-time selector proof is status-unavailable. */
    publication_omit_selector_override = true;
    CHECK_EQ_INT(capture_signing_status(
                     &account, published_key, expected_program,
                     published_key, "true", expected_program, NULL, NULL,
                     status, sizeof(status)), -1);
    CHECK_EQ_INT(fake_non_git_calls, 0);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Signing attribution: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
}

TEST(historical_short_selector_without_publication_is_incomplete) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    account_t account;
    char status[8192];
    char expected_program[MAX_PATH_LEN];

    if (gpg_manager_resolve_executable(expected_program,
                                       sizeof(expected_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }

    memset(&account, 0, sizeof(account));
    account.id = 10;
    CHECK_EQ_INT(safe_strncpy(account.name, "Historical Selector",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email,
                              "historical@example.test",
                              sizeof(account.email)), 0);
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    bind_status_test_incarnation(&account);
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0x89abcdef",
                              sizeof(account.gpg_key_id)), 0);

    CHECK_EQ_INT(capture_signing_status(
                     &account, NULL, NULL, canonical_key, "true",
                     expected_program, NULL, NULL, status,
                     sizeof(status)), -1);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Signing attribution: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status,
                 "Expected GPG Signing Key: [PROVENANCE UNAVAILABLE]") !=
          NULL);
    CHECK(strstr(status, canonical_key) != NULL);
}

TEST(retiring_publication_cannot_attribute_a_reused_account_id) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    account_t replacement;
    char status[8192];
    char expected_program[MAX_PATH_LEN];

    if (gpg_manager_resolve_executable(expected_program,
                                       sizeof(expected_program)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }

    memset(&replacement, 0, sizeof(replacement));
    replacement.id = 41;
    CHECK_EQ_INT(safe_strncpy(replacement.name, "Replacement Account",
                              sizeof(replacement.name)), 0);
    CHECK_EQ_INT(safe_strncpy(replacement.email,
                              "replacement@example.test",
                              sizeof(replacement.email)), 0);
    replacement.gpg_enabled = true;
    replacement.gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(replacement.gpg_key_id, "0x89abcdef",
                              sizeof(replacement.gpg_key_id)), 0);

    /* The same complete record and live Git values are an exact match while
     * published. Once account deletion commits its RETIRING tombstone, the
     * reusable integer alone must no longer confer status attribution. */
    CHECK_EQ_INT(capture_signing_status_state(
                     &replacement, canonical_key, expected_program,
                     PUBLICATION_STATE_PUBLISHED, canonical_key, "true",
                     expected_program, NULL, NULL, status, sizeof(status)),
                 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    CHECK_EQ_INT(capture_signing_status_state(
                     &replacement, canonical_key, expected_program,
                     PUBLICATION_STATE_RETIRING, canonical_key, "true",
                     expected_program, NULL, NULL, status, sizeof(status)),
                 -1);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "Signing attribution: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
}

TEST(published_record_from_different_incarnation_cannot_attribute_status) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    account_t replacement;
    char status[8192];
    char program[MAX_PATH_LEN] = "";

    CHECK_EQ_INT(safe_strncpy(program, "/bin/sh", sizeof(program)), 0);
    memset(&replacement, 0, sizeof(replacement));
    replacement.id = 41;
    CHECK_EQ_INT(safe_strncpy(replacement.incarnation,
                              STATUS_TEST_INCARNATION_B,
                              sizeof(replacement.incarnation)), 0);
    replacement.incarnation_persisted = true;
    CHECK_EQ_INT(safe_strncpy(replacement.name, "Replacement Account",
                              sizeof(replacement.name)), 0);
    CHECK_EQ_INT(safe_strncpy(replacement.email,
                              "replacement@example.test",
                              sizeof(replacement.email)), 0);
    replacement.gpg_enabled = true;
    replacement.gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(replacement.gpg_key_id, "0x89abcdef",
                              sizeof(replacement.gpg_key_id)), 0);

    CHECK_EQ_INT(capture_signing_status_incarnation_state(
                     &replacement, STATUS_TEST_INCARNATION,
                     canonical_key, program, PUBLICATION_STATE_PUBLISHED,
                     canonical_key, "true", program, NULL, NULL,
                     status, sizeof(status)), -1);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);
}

TEST(status_rejects_replaced_or_missing_published_gpg_program) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    char trusted_root[MAX_PATH_LEN];
    char program[MAX_PATH_LEN];
    char replacement[MAX_PATH_LEN];
    char origin[MAX_PATH_LEN];
    char status[8192];
    account_t account;
    gitswitch_ctx_t context;
    command_runner_fn previous;

    if (!ts_mkdtemp_trusted(trusted_root, sizeof(trusted_root),
                            "ar11-status-program") ||
        safe_snprintf(program, sizeof(program), "%s/gpg", trusted_root) !=
            0 ||
        safe_snprintf(replacement, sizeof(replacement), "%s/gpg.new",
                      trusted_root) != 0 ||
        write_text_file(program, "#!/bin/sh\nexit 0\n", 0700) != 0) {
        CHECK(false);
        return;
    }

    memset(&account, 0, sizeof(account));
    account.id = 11;
    bind_status_test_incarnation(&account);
    CHECK_EQ_INT(safe_strncpy(account.name, "Program Generation",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "program@example.test",
                              sizeof(account.email)), 0);
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0x89abcdef",
                              sizeof(account.gpg_key_id)), 0);

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0] = account;
    context.current_account = &context.accounts[0];
    CHECK_EQ_INT(install_signing_publication(
                     &context, &account, canonical_key, program,
                     PUBLICATION_STATE_PUBLISHED, origin, sizeof(origin)), 0);

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", origin, "user.name", account.name,
                             strlen(account.name)));
    CHECK(fake_append_record("global", origin, "user.email", account.email,
                             strlen(account.email)));
    CHECK(fake_append_record("global", origin, "user.signingkey",
                             canonical_key, strlen(canonical_key)));
    CHECK(fake_append_record("global", origin, "commit.gpgsign", "true",
                             strlen("true")));
    CHECK(fake_append_record("global", origin,
                             GIT_CONFIG_GPG_OPENPGP_PROGRAM, program,
                             strlen(program)));

    /* Preserve the configured spelling while replacing the exact executable
     * generation sealed in the publication record. */
    CHECK_EQ_INT(write_text_file(replacement,
                                 "#!/bin/sh\n# replacement\nexit 0\n",
                                 0700), 0);
    CHECK_EQ_INT(rename(replacement, program), 0);
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), -1);
    run_set_runner(previous);
    git_ops_test_reset_caches();
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Effective OpenPGP Program: [ERROR]") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") == NULL);

    CHECK_EQ_INT(unlink(program), 0);
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output_for(&context, status,
                                           sizeof(status)), -1);
    run_set_runner(previous);
    git_ops_test_reset_caches();
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "OpenPGP provenance: [UNAVAILABLE]") != NULL);
    CHECK(strstr(status, "Effective OpenPGP Program: [ERROR]") != NULL);
}

TEST(no_active_account_warns_for_residual_openpgp_program) {
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", "file:/ar11/global", "user.name",
                             "Residual User", strlen("Residual User")));
    CHECK(fake_append_record("global", "file:/ar11/global", "user.email",
                             "residual@example.test",
                             strlen("residual@example.test")));
    CHECK(fake_append_record("global", "file:/ar11/global",
                             GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                             "/trusted/ar11/gpg",
                             strlen("/trusted/ar11/gpg")));

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), 0);
    run_set_runner(previous);
    git_ops_test_reset_caches();

    CHECK(strstr(status, "No account currently active.") != NULL);
    CHECK(strstr(status, "Effective OpenPGP Program: [SET]") != NULL);
    CHECK(strstr(status,
                 "[WARN] Durable Git credential configuration is set") !=
          NULL);
}

TEST(stale_current_account_is_rejected_before_use_or_cleared_for_discovery) {
    gitswitch_ctx_t context;
    account_t detached;

    memset(&context, 0, sizeof(context));
    context.account_count = 1U;
    context.accounts[0].id = 77U;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Pointer User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "pointer@example.test",
                              sizeof(context.accounts[0].email)), 0);
    detached = context.accounts[0];
    context.current_account = &detached;
    context.config.dry_run = true;
    context.config.assume_yes = true;

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_list(&context), -1);
    CHECK_EQ_INT(errno, ESTALE);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_show_status(&context), -1);
    CHECK_EQ_INT(errno, ESTALE);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_switch(&context, "Pointer User"), -1);
    CHECK_EQ_INT(errno, ESTALE);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&context, &detached), -1);
    CHECK_EQ_INT(errno, ESTALE);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_add_interactive_prepare(&context), -1);
    CHECK_EQ_INT(errno, ESTALE);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(accounts_remove(&context, "Pointer User"), -1);
    CHECK_EQ_INT(errno, ESTALE);

    /* Discovery treats a stale reference as no observation. With no saved
     * active name it may not find a replacement, but it must clear the
     * unproven pointer without ever dereferencing it. */
    clear_error();
    context.current_account = &detached;
    context.config.active_account[0] = '\0';
    CHECK_EQ_INT(accounts_detect_current(&context), -1);
    CHECK(context.current_account == NULL);
}

static int setup_isolated_git(char *base, size_t base_size,
                              char *config_path, size_t config_size,
                              char *saved_cwd, size_t cwd_size) {
    if ((size_t)snprintf(base, base_size, "/tmp/gsw_ar07_status_XXXXXX") >=
            base_size ||
        !ts_mkdtemp(base) || !getcwd(saved_cwd, cwd_size) ||
        (size_t)snprintf(config_path, config_size, "%s/gitconfig", base) >=
            config_size ||
        setenv("GIT_CONFIG_GLOBAL", config_path, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 || chdir(base) != 0) {
        return -1;
    }
    return 0;
}

static int set_global_value(const char *key, const char *value) {
    const char *argv[] = { "git", "config", "--global", key, value, NULL };
    run_result_t result;
    memset(&result, 0, sizeof(result));
    return run_command(argv, NULL, 0, &result);
}

TEST(real_malformed_config_retains_gits_diagnostic) {
    char base[MAX_PATH_LEN] = "";
    char config[MAX_PATH_LEN] = "";
    char saved_cwd[MAX_PATH_LEN] = "";
    git_current_config_t current;
    saved_env_t global = save_env("GIT_CONFIG_GLOBAL");
    saved_env_t nosystem = save_env("GIT_CONFIG_NOSYSTEM");
    saved_env_t config_count = save_env("GIT_CONFIG_COUNT");
    saved_env_t ssh_command = save_env("GIT_SSH_COMMAND");

    (void)unsetenv("GIT_CONFIG_COUNT");
    (void)unsetenv("GIT_SSH_COMMAND");

    if (setup_isolated_git(base, sizeof(base), config, sizeof(config),
                           saved_cwd, sizeof(saved_cwd)) != 0) {
        CHECK(false);
        goto cleanup;
    }
    CHECK_EQ_INT(write_text_file(config, "[unterminated\n", 0600), 0);
    git_ops_test_reset_caches();
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message, "bad config") != NULL ||
          strstr(get_last_error()->message, "fatal") != NULL);
    CHECK(!current.valid);

cleanup:
    if (saved_cwd[0] != '\0') CHECK_EQ_INT(chdir(saved_cwd), 0);
    restore_env("GIT_SSH_COMMAND", &ssh_command);
    restore_env("GIT_CONFIG_COUNT", &config_count);
    restore_env("GIT_CONFIG_NOSYSTEM", &nosystem);
    restore_env("GIT_CONFIG_GLOBAL", &global);
}

TEST(git_boolean_grammar_matches_gits_canonical_oracle) {
    static const char *const values[] = {
        "true", "TRUE", "yes", "YeS", "on", "ON", "1", "2", "-1",
        "01", "010", "0x0", "0x1", "0k", "1k", "1K", "-1k", "+1k",
        "1m", "1M", "1g", "-2g", "2097151k", "-2097152k", "0x1k",
        "false", "FALSE", "no", "No", "off", "OFF", "0", "00", "",
        "definitely-not-a-bool", "08", "1kb", "1k ", "2g", "2097152k",
        "-2097153k", "2048m", "-2049m", "0x80000000"
    };
    char base[MAX_PATH_LEN] = "";
    char config[MAX_PATH_LEN] = "";
    char saved_cwd[MAX_PATH_LEN] = "";
    saved_env_t global = save_env("GIT_CONFIG_GLOBAL");
    saved_env_t nosystem = save_env("GIT_CONFIG_NOSYSTEM");
    saved_env_t config_count = save_env("GIT_CONFIG_COUNT");
    saved_env_t ssh_command = save_env("GIT_SSH_COMMAND");

    (void)unsetenv("GIT_CONFIG_COUNT");
    (void)unsetenv("GIT_SSH_COMMAND");

    if (setup_isolated_git(base, sizeof(base), config, sizeof(config),
                           saved_cwd, sizeof(saved_cwd)) != 0) {
        CHECK(false);
        goto cleanup;
    }
    CHECK_EQ_INT(set_global_value("user.name", "Boolean User"), 0);
    CHECK_EQ_INT(set_global_value("user.email", "boolean@example.test"), 0);

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        char oracle[32];
        run_result_t oracle_result;
        git_current_config_t current;
        const char *oracle_argv[] = {
            "git", "config", "--bool", "--get", "commit.gpgsign", NULL
        };

        CHECK_EQ_INT(set_global_value("commit.gpgsign", values[i]), 0);
        memset(&oracle_result, 0, sizeof(oracle_result));
        int oracle_rc = run_command(oracle_argv, oracle, sizeof(oracle),
                                    &oracle_result);
        if (oracle_rc == 0 && oracle_result.out_len > 0 &&
            oracle[oracle_result.out_len - 1U] == '\n') {
            oracle[oracle_result.out_len - 1U] = '\0';
        }

        git_ops_test_reset_caches();
        memset(&current, 0, sizeof(current));
        int status_rc = git_get_current_config(&current);
        if (status_rc != oracle_rc) {
            fprintf(stderr,
                    "  Boolean oracle mismatch for value <%s>: status=%d "
                    "git=%d\n",
                    values[i], status_rc, oracle_rc);
        }
        CHECK_EQ_INT(status_rc, oracle_rc);
        if (oracle_rc == 0) {
            CHECK(current.valid);
            CHECK_EQ_INT(current.gpg_signing_enabled,
                         strcmp(oracle, "true") == 0);
        } else {
            CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
            CHECK(!current.valid);
        }
    }

    /* A valueless key is Git's implicit Boolean true form. Exercise the real
     * config-file spelling so both Git's oracle and our binary-list parser see
     * the same implicit record. */
    CHECK_EQ_INT(write_text_file(
                     config,
                     "[user]\n"
                     "\tname = Boolean User\n"
                     "\temail = boolean@example.test\n"
                     "[commit]\n"
                     "\tgpgsign\n",
                     0600),
                 0);
    {
        char oracle[32];
        run_result_t oracle_result;
        git_current_config_t current;
        const char *oracle_argv[] = {
            "git", "config", "--bool", "--get", "commit.gpgsign", NULL
        };

        memset(&oracle_result, 0, sizeof(oracle_result));
        CHECK_EQ_INT(run_command(oracle_argv, oracle, sizeof(oracle),
                                 &oracle_result), 0);
        git_ops_test_reset_caches();
        memset(&current, 0, sizeof(current));
        CHECK_EQ_INT(git_get_current_config(&current), 0);
        CHECK(current.valid);
        CHECK(current.gpg_signing_enabled);
        CHECK(strncmp(oracle, "true", 4) == 0);
    }

cleanup:
    if (saved_cwd[0] != '\0') CHECK_EQ_INT(chdir(saved_cwd), 0);
    restore_env("GIT_SSH_COMMAND", &ssh_command);
    restore_env("GIT_CONFIG_COUNT", &config_count);
    restore_env("GIT_CONFIG_NOSYSTEM", &nosystem);
    restore_env("GIT_CONFIG_GLOBAL", &global);
}

TEST(persisted_absolute_ssh_ignores_later_writable_path_shadow) {
    char trusted_root[MAX_PATH_LEN] = "";
    char trusted_dir[MAX_PATH_LEN] = "";
    char trusted_ssh[MAX_PATH_LEN] = "";
    char trusted_marker[MAX_PATH_LEN] = "";
    char trusted_git[MAX_PATH_LEN] = "";
    char trusted_git_dir[MAX_PATH_LEN] = "";
    char key_path[MAX_PATH_LEN] = "";
    char hostile_root[MAX_PATH_LEN] = "/tmp/gsw_ar07_shadow_XXXXXX";
    char hostile_ssh[MAX_PATH_LEN] = "";
    char hostile_marker[MAX_PATH_LEN] = "";
    char global_config[MAX_PATH_LEN] = "";
    char stored[GIT_CONFIG_VALUE_MAX];
    char git_output[4096];
    char marker_output[8192];
    char original_cwd[MAX_PATH_LEN] = "";
    char initial_path[MAX_PATH_LEN * 2U];
    char hostile_path[MAX_PATH_LEN * 2U];
    account_t account;
    saved_env_t path = save_env("PATH");
    saved_env_t global = save_env("GIT_CONFIG_GLOBAL");
    saved_env_t nosystem = save_env("GIT_CONFIG_NOSYSTEM");
    saved_env_t config_count = save_env("GIT_CONFIG_COUNT");
    saved_env_t ssh_command = save_env("GIT_SSH_COMMAND");
    FILE *marker = NULL;
    char *git_leaf;

    (void)unsetenv("GIT_CONFIG_COUNT");
    (void)unsetenv("GIT_SSH_COMMAND");

    /* The test deliberately replaces PATH below, but Git is installed in
     * /usr/local/bin on FreeBSD rather than the Linux/macOS /usr/bin default.
     * Preserve the directory of the already trust-checked ambient Git instead
     * of baking a platform-specific installation prefix into the fixture. */
    if (find_command_path("git", trusted_git, sizeof(trusted_git)) != 0 ||
        !(git_leaf = strrchr(trusted_git, '/')) || git_leaf == trusted_git) {
        CHECK(false);
        goto cleanup;
    }
    if ((size_t)(git_leaf - trusted_git) >= sizeof(trusted_git_dir)) {
        CHECK(false);
        goto cleanup;
    }
    memcpy(trusted_git_dir, trusted_git, (size_t)(git_leaf - trusted_git));
    trusted_git_dir[git_leaf - trusted_git] = '\0';

    if (!getcwd(original_cwd, sizeof(original_cwd)) ||
        !ts_mkdtemp_trusted(trusted_root, sizeof(trusted_root),
                            "gitswitch-ar07-status") ||
        !ts_mkdtemp(hostile_root)) {
        CHECK(false);
        goto cleanup;
    }
    if ((size_t)snprintf(trusted_dir, sizeof(trusted_dir),
                         "%s/ssh tools'quoted", trusted_root) >=
            sizeof(trusted_dir) ||
        (size_t)snprintf(trusted_ssh, sizeof(trusted_ssh), "%s/ssh",
                         trusted_dir) >= sizeof(trusted_ssh) ||
        (size_t)snprintf(trusted_marker, sizeof(trusted_marker),
                         "%s/trusted.marker", trusted_dir) >=
            sizeof(trusted_marker) ||
        (size_t)snprintf(key_path, sizeof(key_path), "%s/identity key",
                         trusted_root) >= sizeof(key_path) ||
        (size_t)snprintf(hostile_ssh, sizeof(hostile_ssh), "%s/ssh",
                         hostile_root) >= sizeof(hostile_ssh) ||
        (size_t)snprintf(hostile_marker, sizeof(hostile_marker),
                         "%s/hostile.marker", hostile_root) >=
            sizeof(hostile_marker) ||
        (size_t)snprintf(global_config, sizeof(global_config), "%s/gitconfig",
                         hostile_root) >= sizeof(global_config)) {
        CHECK(false);
        goto cleanup;
    }
    CHECK_EQ_INT(mkdir(trusted_dir, 0700), 0);
    CHECK_EQ_INT(write_text_file(
                     trusted_ssh,
                     "#!/bin/sh\n"
                     "dir=${0%/*}\n"
                     "{ printf '%s\\n' \"$0\"; for arg do printf '%s\\n' \"$arg\"; done; } > \"$dir/trusted.marker\"\n"
                     "exit 1\n",
                     0700),
                 0);
    CHECK_EQ_INT(write_text_file(key_path, "test key\n", 0600), 0);
    CHECK_EQ_INT(write_text_file(
                     hostile_ssh,
                     "#!/bin/sh\n"
                     "dir=${0%/*}\n"
                     ": > \"$dir/hostile.marker\"\n"
                     "exit 1\n",
                     0700),
                 0);
    if ((size_t)snprintf(initial_path, sizeof(initial_path), "%s:%s:/usr/bin:/bin",
                         trusted_dir, trusted_git_dir) >= sizeof(initial_path) ||
        (size_t)snprintf(hostile_path, sizeof(hostile_path), "%s:%s:/usr/bin:/bin",
                         hostile_root, trusted_git_dir) >= sizeof(hostile_path)) {
        CHECK(false);
        goto cleanup;
    }
    CHECK_EQ_INT(setenv("PATH", initial_path, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", global_config, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_NOSYSTEM", "1", 1), 0);
    CHECK_EQ_INT(chdir(hostile_root), 0);

    memset(&account, 0, sizeof(account));
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key_path,
                              sizeof(account.ssh_key_path)), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_configure_ssh(&account, GIT_SCOPE_GLOBAL), 0);
    memset(stored, 0, sizeof(stored));
    CHECK_EQ_INT(git_get_config_value(GIT_CONFIG_CORE_SSHCOMMAND, stored,
                                      sizeof(stored), GIT_SCOPE_GLOBAL), 0);
    CHECK(stored[0] == '\'');
    CHECK(strncmp(stored, "'ssh'", 5) != 0);
    CHECK(strstr(stored, " -i '") != NULL);

    /* A later Git process receives a hostile writable PATH. Its configured
     * command must invoke the already-persisted absolute trusted executable,
     * and shell parsing must preserve both executable and key paths as one
     * argument despite spaces/quotes. */
    CHECK_EQ_INT(setenv("PATH", hostile_path, 1), 0);
    {
        const char *argv[] = {
            "git", "ls-remote", "ssh://ar07.invalid/repository", NULL
        };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        CHECK_EQ_INT(run_command(argv, git_output, sizeof(git_output), &result),
                     -1);
    }
    CHECK_EQ_INT(access(trusted_marker, F_OK), 0);
    CHECK_EQ_INT(access(hostile_marker, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    marker = fopen(trusted_marker, "r");
    CHECK(marker != NULL);
    if (marker) {
        size_t length = fread(marker_output, 1, sizeof(marker_output) - 1U,
                              marker);
        marker_output[length] = '\0';
        fclose(marker);
        marker = NULL;
        CHECK(strncmp(marker_output, trusted_ssh, strlen(trusted_ssh)) == 0);
        char expected_key_arg[MAX_PATH_LEN + 8U];
        CHECK((size_t)snprintf(expected_key_arg, sizeof(expected_key_arg),
                               "\n-i\n%s\n", key_path) <
              sizeof(expected_key_arg));
        CHECK(strstr(marker_output, expected_key_arg) != NULL);
    }

cleanup:
    if (marker) fclose(marker);
    if (original_cwd[0] != '\0') CHECK_EQ_INT(chdir(original_cwd), 0);
    restore_env("GIT_SSH_COMMAND", &ssh_command);
    restore_env("GIT_CONFIG_COUNT", &config_count);
    restore_env("GIT_CONFIG_NOSYSTEM", &nosystem);
    restore_env("GIT_CONFIG_GLOBAL", &global);
    restore_env("PATH", &path);
}

static int set_local_value_with_git(const char *git_path, const char *key,
                                    const char *value) {
    const char *argv[] = {
        git_path, "config", "--local", key, value, NULL
    };
    run_result_t result;

    memset(&result, 0, sizeof(result));
    return run_command(argv, NULL, 0, &result);
}

/* M11b causal witness: Git must consume the exact absolute OpenPGP program
 * published by the switch. A later writable PATH entry contains a marker shim
 * named gpg; a real signed commit must invoke wrapper A and leave shim B
 * untouched. The generated keyring and secret key live only in this registered
 * temporary fixture and are recursively removed before the test returns. */
TEST(persisted_absolute_openpgp_ignores_later_writable_path_shadow) {
    static const char signing_identity[] =
        "AR11 Binding Witness <ar11-binding@example.test>";
    char real_gpg[MAX_PATH_LEN] = "";
    char real_git[MAX_PATH_LEN] = "";
    char real_gpgconf[MAX_PATH_LEN] = "";
    char original_cwd[MAX_PATH_LEN] = "";
    char base[MAX_PATH_LEN] = "/tmp/gsw_ar11_gpg_binding_XXXXXX";
    char home[MAX_PATH_LEN] = "";
    char gnupg_home[MAX_PATH_LEN] = "";
    char repo[MAX_PATH_LEN] = "";
    char shim_dir[MAX_PATH_LEN] = "";
    char wrapper_a[MAX_PATH_LEN] = "";
    char shim_b[MAX_PATH_LEN] = "";
    char marker_a[MAX_PATH_LEN] = "";
    char marker_b[MAX_PATH_LEN] = "";
    char global_config[MAX_PATH_LEN] = "";
    char hostile_path[MAX_PATH_LEN * 2U] = "";
    char commit_object[16384];
    saved_env_t path;
    saved_env_t home_env;
    saved_env_t gnupg_env;
    saved_env_t global;
    saved_env_t nosystem;
    saved_env_t config_count;
    saved_env_t real_gpg_env;
    saved_env_t trusted_marker_env;
    saved_env_t hostile_marker_env;
    bool fixture_created = false;
    int rc;

    if (gpg_manager_resolve_executable(real_gpg, sizeof(real_gpg)) != 0) {
        TS_SKIP("gpg", "no trusted OpenPGP executable on this host");
    }
    if (find_command_path("git", real_git, sizeof(real_git)) != 0) {
        TS_SKIP("git", "no trusted Git executable on this host");
    }
    /* Optional cleanup aid. The fixture is still removed if gpgconf is not
     * installed, but when present this prevents an ephemeral agent process
     * from retaining the deleted GNUPGHOME until its idle timeout. */
    (void)find_command_path("gpgconf", real_gpgconf, sizeof(real_gpgconf));

    path = save_env("PATH");
    home_env = save_env("HOME");
    gnupg_env = save_env("GNUPGHOME");
    global = save_env("GIT_CONFIG_GLOBAL");
    nosystem = save_env("GIT_CONFIG_NOSYSTEM");
    config_count = save_env("GIT_CONFIG_COUNT");
    real_gpg_env = save_env("AR11_REAL_GPG");
    trusted_marker_env = save_env("AR11_TRUSTED_GPG_MARKER");
    hostile_marker_env = save_env("AR11_HOSTILE_GPG_MARKER");

    if (!getcwd(original_cwd, sizeof(original_cwd))) {
        CHECK(false);
        goto cleanup;
    }
    if (!ts_mkdtemp(base)) {
        CHECK(false);
        goto cleanup;
    }
    fixture_created = true;
    if ((size_t)snprintf(home, sizeof(home), "%s/home", base) >=
            sizeof(home) ||
        (size_t)snprintf(gnupg_home, sizeof(gnupg_home), "%s/gnupg", base) >=
            sizeof(gnupg_home) ||
        (size_t)snprintf(repo, sizeof(repo), "%s/repo", base) >=
            sizeof(repo) ||
        (size_t)snprintf(shim_dir, sizeof(shim_dir), "%s/shim", base) >=
            sizeof(shim_dir) ||
        (size_t)snprintf(wrapper_a, sizeof(wrapper_a), "%s/wrapper-a", base) >=
            sizeof(wrapper_a) ||
        (size_t)snprintf(shim_b, sizeof(shim_b), "%s/gpg", shim_dir) >=
            sizeof(shim_b) ||
        (size_t)snprintf(marker_a, sizeof(marker_a), "%s/a.marker", base) >=
            sizeof(marker_a) ||
        (size_t)snprintf(marker_b, sizeof(marker_b), "%s/b.marker", base) >=
            sizeof(marker_b) ||
        (size_t)snprintf(global_config, sizeof(global_config),
                         "%s/global.gitconfig", base) >=
            sizeof(global_config) ||
        (size_t)snprintf(hostile_path, sizeof(hostile_path), "%s:/usr/bin:/bin",
                         shim_dir) >= sizeof(hostile_path)) {
        CHECK(false);
        goto cleanup;
    }
    if (mkdir(home, 0700) != 0 || mkdir(gnupg_home, 0700) != 0 ||
        mkdir(repo, 0700) != 0 || mkdir(shim_dir, 0700) != 0) {
        CHECK(false);
        goto cleanup;
    }
    if (write_text_file(
            wrapper_a,
            "#!/bin/sh\n"
            ": > \"$AR11_TRUSTED_GPG_MARKER\"\n"
            "exec \"$AR11_REAL_GPG\" \"$@\"\n",
            0700) != 0 ||
        write_text_file(
            shim_b,
            "#!/bin/sh\n"
            ": > \"$AR11_HOSTILE_GPG_MARKER\"\n"
            "exit 99\n",
            0700) != 0 ||
        setenv("HOME", home, 1) != 0 ||
        setenv("GNUPGHOME", gnupg_home, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", global_config, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        unsetenv("GIT_CONFIG_COUNT") != 0 ||
        setenv("AR11_REAL_GPG", real_gpg, 1) != 0 ||
        setenv("AR11_TRUSTED_GPG_MARKER", marker_a, 1) != 0 ||
        setenv("AR11_HOSTILE_GPG_MARKER", marker_b, 1) != 0) {
        CHECK(false);
        goto cleanup;
    }

    {
        const char *argv[] = {
            real_gpg, "--batch", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-generate-key", signing_identity,
            "rsa2048", "sign", "0", NULL
        };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        rc = run_command(argv, NULL, 0, &result);
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) goto cleanup;
    }
    {
        const char *argv[] = { real_git, "init", "-q", repo, NULL };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        rc = run_command(argv, NULL, 0, &result);
        CHECK_EQ_INT(rc, 0);
        if (rc != 0 || chdir(repo) != 0) {
            CHECK(rc == 0);
            goto cleanup;
        }
    }
    CHECK_EQ_INT(set_local_value_with_git(real_git, "user.name",
                                           "AR11 Binding Witness"), 0);
    CHECK_EQ_INT(set_local_value_with_git(real_git, "user.email",
                                           "ar11-binding@example.test"), 0);
    CHECK_EQ_INT(set_local_value_with_git(real_git, "user.signingkey",
                                           "ar11-binding@example.test"), 0);
    CHECK_EQ_INT(set_local_value_with_git(real_git, "commit.gpgsign", "true"),
                 0);
    CHECK_EQ_INT(set_local_value_with_git(real_git, "gpg.format", "openpgp"),
                 0);
    CHECK_EQ_INT(set_local_value_with_git(real_git,
                                           GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                           wrapper_a), 0);

    /* The hostile selector becomes the first gpg in PATH only after the exact
     * absolute program has been persisted. */
    CHECK_EQ_INT(setenv("PATH", hostile_path, 1), 0);
    {
        const char *argv[] = {
            real_git, "commit", "--allow-empty", "-S", "-m",
            "AR11 exact OpenPGP binding", NULL
        };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        rc = run_command(argv, NULL, 0, &result);
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) goto cleanup;
    }

    CHECK_EQ_INT(access(marker_a, F_OK), 0);
    errno = 0;
    CHECK_EQ_INT(access(marker_b, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    {
        const char *argv[] = { real_git, "cat-file", "commit", "HEAD", NULL };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        memset(commit_object, 0, sizeof(commit_object));
        CHECK_EQ_INT(run_command(argv, commit_object, sizeof(commit_object),
                                 &result), 0);
        CHECK(strstr(commit_object,
                     "gpgsig -----BEGIN PGP SIGNATURE-----") != NULL);
    }

cleanup:
    if (real_gpgconf[0] != '\0' && gnupg_home[0] != '\0') {
        const char *argv[] = {
            real_gpgconf, "--homedir", gnupg_home, "--kill", "gpg-agent",
            NULL
        };
        run_result_t result;
        memset(&result, 0, sizeof(result));
        (void)run_command(argv, NULL, 0, &result);
    }
    if (original_cwd[0] != '\0') CHECK_EQ_INT(chdir(original_cwd), 0);
    restore_env("AR11_HOSTILE_GPG_MARKER", &hostile_marker_env);
    restore_env("AR11_TRUSTED_GPG_MARKER", &trusted_marker_env);
    restore_env("AR11_REAL_GPG", &real_gpg_env);
    restore_env("GIT_CONFIG_COUNT", &config_count);
    restore_env("GIT_CONFIG_NOSYSTEM", &nosystem);
    restore_env("GIT_CONFIG_GLOBAL", &global);
    restore_env("GNUPGHOME", &gnupg_env);
    restore_env("HOME", &home_env);
    restore_env("PATH", &path);
    if (fixture_created) ts_rm_rf(base);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(untrusted_gpg_source_is_only_executed_after_trusted_copy);
    int gpg_rc = prepare_real_gpg();
    if (gpg_rc < 0) {
        fprintf(stderr, "HARNESS FAIL: cannot prepare trusted real GPG\n");
        return 1;
    }
    RUN_TEST(oversized_unrelated_config_is_captured_without_losing_identity);
    RUN_TEST(malformed_effective_listing_is_an_error_not_absence);
    RUN_TEST(status_escapes_and_bounds_every_external_value);
    RUN_TEST(execution_failure_retains_diagnostic_and_status_reports_error);
    RUN_TEST(execution_diagnostic_is_sanitized_before_error_logging);
    RUN_TEST(absent_identity_remains_a_normal_status_result);
    RUN_TEST(partial_identity_renders_every_credential_leg);
    RUN_TEST(explicit_false_signing_state_is_present_residue);
    RUN_TEST(explicit_openpgp_format_is_visible_residue);
    RUN_TEST(active_partial_identity_renders_residue_without_trusted_match);
    RUN_TEST(active_projection_failure_still_renders_captured_residue);
    RUN_TEST(absent_identity_with_invalid_boolean_reports_error);
    RUN_TEST(int_min_boolean_follows_selected_gits_grammar);
    RUN_TEST(absent_identity_with_oversized_managed_value_reports_error);
    RUN_TEST(oversized_signing_boolean_is_not_rendered_as_false);
    RUN_TEST(active_ssh_without_publication_fails_before_any_git_probe);
    RUN_TEST(active_ssh_status_uses_saved_program_and_exact_destination);
    RUN_TEST(active_status_propagates_required_key_inspection_failure);
    RUN_TEST(active_status_includes_every_selected_signing_field);
    RUN_TEST(edited_short_selector_cannot_reuse_historical_fingerprint);
    RUN_TEST(historical_short_selector_without_publication_is_incomplete);
    RUN_TEST(retiring_publication_cannot_attribute_a_reused_account_id);
    RUN_TEST(published_record_from_different_incarnation_cannot_attribute_status);
    RUN_TEST(status_rejects_replaced_or_missing_published_gpg_program);
    RUN_TEST(no_active_account_warns_for_residual_openpgp_program);
    RUN_TEST(stale_current_account_is_rejected_before_use_or_cleared_for_discovery);
    RUN_TEST(real_malformed_config_retains_gits_diagnostic);
    RUN_TEST(git_boolean_grammar_matches_gits_canonical_oracle);
    RUN_TEST(persisted_absolute_ssh_ignores_later_writable_path_shadow);
    RUN_TEST(persisted_absolute_openpgp_ignores_later_writable_path_shadow);
    if (restore_trusted_gpg() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot restore PATH after GPG tests\n");
        return 1;
    }
TEST_MAIN_END()
