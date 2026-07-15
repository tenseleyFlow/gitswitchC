/* AR-07 T14: trusted persisted SSH command and truthful Git status. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "accounts.h"
#include "error.h"
#include "git_ops.h"
#include "gpg_manager.h"
#include "ssh_manager.h"
#include "utils.h"

#include <fcntl.h>

void git_ops_test_reset_caches(void);

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

    if (!argv[0] || strcmp(argv[0], "git") != 0 || !argv[1])
        return fake_finish(result, 127);
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

TEST(absent_identity_with_invalid_boolean_reports_error) {
    char status[8192];
    command_runner_fn previous;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", "file:/ar07/global",
                             "commit.gpgsign", "not-a-git-boolean",
                             strlen("not-a-git-boolean")));
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    CHECK_EQ_INT(capture_status_output(status, sizeof(status)), -1);
    run_set_runner(previous);

    CHECK(strstr(status, "Status: [ERROR]") != NULL);
    CHECK(strstr(status, "Invalid effective Git Boolean") != NULL);
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

TEST(active_status_reports_expected_ssh_resolution_failure) {
    gitswitch_ctx_t context;
    char status[8192];
    int status_rc;
    command_runner_fn previous;
    saved_env_t path = save_env("PATH");

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    CHECK(fake_append_record("global", "file:/ar07/global", "user.name",
                             "Active User", strlen("Active User")));
    CHECK(fake_append_record("global", "file:/ar07/global", "user.email",
                             "active@example.test",
                             strlen("active@example.test")));

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0].id = 7;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Active User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "active@example.test",
                              sizeof(context.accounts[0].email)), 0);
    context.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path,
                              "/definitely/not/present/ar07-status-key",
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    context.current_account = &context.accounts[0];

    /* The fake runner still supplies Git's read-only answers, while this PATH
     * contains no trusted ssh executable for expected-command construction. */
    CHECK_EQ_INT(setenv("PATH", "/tmp", 1), 0);
    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, sizeof(status));
    run_set_runner(previous);
    restore_env("PATH", &path);

    CHECK_EQ_INT(status_rc, -1);
    CHECK(strstr(status, "Match Status: [ERROR]") != NULL);
    CHECK(strstr(status, "Effective SSH Command: [ERROR]") != NULL);
    CHECK(strstr(status, "No trusted SSH executable") != NULL);
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
    char status[8192];
    command_runner_fn previous_runner;
    ssh_key_open_fn previous_open;
    int key_fd;
    int status_rc;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", "file:/ar09/global", "user.name",
                             "Inspection User", strlen("Inspection User")));
    CHECK(fake_append_record("global", "file:/ar09/global", "user.email",
                             "inspection@example.test",
                             strlen("inspection@example.test")));

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0].id = 10;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].name, "Inspection User",
                              sizeof(context.accounts[0].name)), 0);
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].email,
                              "inspection@example.test",
                              sizeof(context.accounts[0].email)), 0);
    context.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path,
                              "/private/ar09/status-key",
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    context.current_account = &context.accounts[0];

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
    /* Prove the exit failure came from key inspection, not from expected SSH
     * executable discovery or the independent Git status read. */
    CHECK(strstr(status, "Effective SSH Command: [MISMATCH]") != NULL);
    CHECK(strstr(status, "Match Status: [ERROR]") == NULL);

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
    CHECK_EQ_INT(safe_strncpy(context.accounts[0].ssh_key_path, key_path,
                              sizeof(context.accounts[0].ssh_key_path)), 0);
    CHECK_EQ_INT(git_expected_ssh_command(&context.accounts[0], expected_ssh,
                                          sizeof(expected_ssh)), 0);

    fake_listing_len = 0;
    CHECK(fake_append_record("global", "file:/ar09/global", "user.name",
                             "Inspection User", strlen("Inspection User")));
    CHECK(fake_append_record("global", "file:/ar09/global", "user.email",
                             "inspection@example.test",
                             strlen("inspection@example.test")));
    CHECK(fake_append_record("global", "file:/ar09/global",
                             "core.sshcommand", expected_ssh,
                             strlen(expected_ssh)));
    git_ops_test_reset_caches();
    previous_runner = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, sizeof(status));
    run_set_runner(previous_runner);
    git_ops_test_reset_caches();

    CHECK_EQ_INT(status_rc, 0);
    CHECK(strstr(status, "Key File: [FOUND]") != NULL);
    CHECK(strstr(status, "Permissions: [SECURE] (600)") != NULL);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);
    CHECK_EQ_INT(unlink(key_path), 0);
}

static int capture_signing_status(const account_t *account,
                                  const char *signing_key,
                                  const char *gpg_signing,
                                  const char *openpgp_program,
                                  const char *foreign_program_key,
                                  const char *foreign_program,
                                  char *status, size_t status_size) {
    gitswitch_ctx_t context;
    command_runner_fn previous;
    int status_rc;

    fake_listing_len = 0;
    fake_listing_calls = 0;
    fake_execution_failure = false;
    fake_repository = false;
    CHECK(fake_append_record("global", "file:/ar09/global", "user.name",
                             account->name, strlen(account->name)));
    CHECK(fake_append_record("global", "file:/ar09/global", "user.email",
                             account->email, strlen(account->email)));
    if (signing_key) {
        CHECK(fake_append_record("global", "file:/ar09/global",
                                 "user.signingkey", signing_key,
                                 strlen(signing_key)));
    }
    if (gpg_signing) {
        CHECK(fake_append_record("global", "file:/ar09/global",
                                 "commit.gpgsign", gpg_signing,
                                 strlen(gpg_signing)));
    }
    if (openpgp_program) {
        CHECK(fake_append_record("global", "file:/ar09/global",
                                 GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                 openpgp_program,
                                 strlen(openpgp_program)));
    }
    if (foreign_program_key && foreign_program) {
        CHECK(fake_append_record("global", "file:/ar09/global",
                                 foreign_program_key, foreign_program,
                                 strlen(foreign_program)));
    }

    memset(&context, 0, sizeof(context));
    context.account_count = 1;
    context.accounts[0] = *account;
    context.current_account = &context.accounts[0];

    git_ops_test_reset_caches();
    previous = run_set_runner(status_fake_runner);
    status_rc = capture_status_output_for(&context, status, status_size);
    run_set_runner(previous);
    git_ops_test_reset_caches();
    return status_rc;
}

TEST(active_status_includes_every_selected_signing_field) {
    static const char canonical_key[] =
        "0123456789ABCDEF0123456789ABCDEF89ABCDEF";
    static const char wrong_key[] =
        "0123456789ABCDEF0123456789ABCDEFFEDCBA98";
    account_t account;
    char status[8192];
    char expected_program[MAX_PATH_LEN];

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
    CHECK_EQ_INT(safe_strncpy(account.gpg_key_id, "0x89abcdef",
                              sizeof(account.gpg_key_id)), 0);

    /* A successful switch publishes the canonical primary fingerprint even
     * when the persisted account retains a shorter, 0x-prefixed selector. */
    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        expected_program, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);
    CHECK(strstr(status, "Effective OpenPGP Program: [MATCH]") != NULL);

    /* Missing/wrong OpenPGP bindings and foreign selector spellings are all
     * mismatches. In particular, the exact same path under legacy
     * gpg.program must not be accepted as equivalent to gpg.openpgp.program. */
    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        NULL, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        "/wrong/ar11/gpg", NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        NULL, GIT_CONFIG_GPG_PROGRAM,
                                        expected_program,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        expected_program,
                                        GIT_CONFIG_GPG_X509_PROGRAM,
                                        expected_program,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "true",
                                        expected_program,
                                        GIT_CONFIG_GPG_SSH_PROGRAM,
                                        expected_program,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, NULL, "true",
                                        expected_program, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, wrong_key, "true",
                                        expected_program, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "false",
                                        expected_program, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    account.gpg_signing_enabled = false;
    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "false",
                                        expected_program, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    account.gpg_enabled = false;
    CHECK_EQ_INT(capture_signing_status(&account, NULL, "false",
                                        NULL, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [OK]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, canonical_key, "false",
                                        NULL, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);

    CHECK_EQ_INT(capture_signing_status(&account, NULL, "true",
                                        NULL, NULL, NULL,
                                        status, sizeof(status)), 0);
    CHECK(strstr(status, "Match Status: [WARN]") != NULL);
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
    RUN_TEST(oversized_unrelated_config_is_captured_without_losing_identity);
    RUN_TEST(malformed_effective_listing_is_an_error_not_absence);
    RUN_TEST(status_escapes_and_bounds_every_external_value);
    RUN_TEST(execution_failure_retains_diagnostic_and_status_reports_error);
    RUN_TEST(execution_diagnostic_is_sanitized_before_error_logging);
    RUN_TEST(absent_identity_remains_a_normal_status_result);
    RUN_TEST(absent_identity_with_invalid_boolean_reports_error);
    RUN_TEST(int_min_boolean_follows_selected_gits_grammar);
    RUN_TEST(absent_identity_with_oversized_managed_value_reports_error);
    RUN_TEST(active_status_reports_expected_ssh_resolution_failure);
    RUN_TEST(active_status_propagates_required_key_inspection_failure);
    RUN_TEST(active_status_includes_every_selected_signing_field);
    RUN_TEST(no_active_account_warns_for_residual_openpgp_program);
    RUN_TEST(real_malformed_config_retains_gits_diagnostic);
    RUN_TEST(git_boolean_grammar_matches_gits_canonical_oracle);
    RUN_TEST(persisted_absolute_ssh_ignores_later_writable_path_shadow);
    RUN_TEST(persisted_absolute_openpgp_ignores_later_writable_path_shadow);
TEST_MAIN_END()
