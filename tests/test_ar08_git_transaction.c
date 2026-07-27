/* AR-08 T8/M7: Git signing model, bounded worktree inspection, effective SSH
 * environment precedence, truthful list truncation, and rollback ownership. */
/* Keep strict feature selection glibc-only: Darwin and the BSDs hide
 * default-namespace test helpers such as mkdtemp() when it is enabled. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "error.h"
#include "git_ops.h"
#define GITSWITCH_INTERNAL_API
#include "git_ops_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "gpg_manager.h"
#include "utils.h"

#include <limits.h>
#include <sys/wait.h>
#include <time.h>

void git_ops_test_reset_caches(void);
void git_ops_test_set_restore_prelock_hook(void (*fn)(git_scope_t scope));
void git_ops_test_set_restore_locked_hook(void (*fn)(git_scope_t scope));
void git_ops_test_set_restore_postpublish_hook(void (*fn)(git_scope_t scope));
typedef enum {
    GIT_METADATA_TEST_SOURCE_PIN = 1,
    GIT_METADATA_TEST_STAGE_REVALIDATE
} git_metadata_test_stage_t;
typedef bool (*git_metadata_test_hook_fn)(git_metadata_test_stage_t stage);
git_metadata_test_hook_fn git_ops_test_set_metadata_hook(
    git_metadata_test_hook_fn fn);
size_t git_ops_test_set_cleanup_arena_capacity(size_t capacity);

static git_metadata_test_stage_t g_metadata_mismatch_stage;
static int g_metadata_mismatch_calls;
static git_metadata_test_stage_t g_metadata_trace[2];
static int g_metadata_trace_count;
static bool g_fork_coverage_child;

static bool force_git_metadata_mismatch(git_metadata_test_stage_t stage) {
    if (g_metadata_trace_count <
        (int)(sizeof(g_metadata_trace) / sizeof(g_metadata_trace[0]))) {
        g_metadata_trace[g_metadata_trace_count] = stage;
    }
    g_metadata_trace_count++;
    errno = E2BIG;
    if (stage != g_metadata_mismatch_stage) return false;
    g_metadata_mismatch_calls++;
    return true;
}

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
    saved_env_t config_key0_env;
    saved_env_t config_value0_env;
    saved_env_t config_parameters_env;
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

static const char *const g_managed_override_keys[] = {
    GIT_CONFIG_USER_NAME,
    GIT_CONFIG_USER_EMAIL,
    GIT_CONFIG_CORE_SSHCOMMAND,
    GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_PROGRAM,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM,
    GIT_CONFIG_GPG_X509_PROGRAM,
    GIT_CONFIG_GPG_SSH_PROGRAM
};

typedef enum {
    COMMAND_OVERRIDE_COUNT = 0,
    COMMAND_OVERRIDE_PARAMETERS
} command_override_encoding_t;

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

static int write_binary_file(const char *path, const unsigned char *contents,
                             size_t length, mode_t mode) {
    FILE *file = fopen(path, "wb");
    int failed;

    if (!file) return -1;
    failed = fwrite(contents, 1U, length, file) != length;
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
    fixture->config_key0_env = save_env("GIT_CONFIG_KEY_0");
    fixture->config_value0_env = save_env("GIT_CONFIG_VALUE_0");
    fixture->config_parameters_env = save_env("GIT_CONFIG_PARAMETERS");
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
        unsetenv("GIT_CONFIG_KEY_0") != 0 ||
        unsetenv("GIT_CONFIG_VALUE_0") != 0 ||
        unsetenv("GIT_CONFIG_PARAMETERS") != 0 ||
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
    restore_env("GIT_CONFIG_PARAMETERS", &fixture->config_parameters_env);
    restore_env("GIT_CONFIG_VALUE_0", &fixture->config_value0_env);
    restore_env("GIT_CONFIG_KEY_0", &fixture->config_key0_env);
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

static int git_get_file_all(const char *path, const char *key, char *output,
                            size_t output_size) {
    const char *const argv[] = {
        "git", "config", "--file", path, "--get-all", key, NULL
    };
    run_result_t result;
    int rc = run_command(argv, output, output_size, false, &result);
    if (rc == 0 && result.out_truncated) return -1;
    return rc;
}

static int git_set_file(const char *path, const char *key,
                        const char *value) {
    const char *const argv[] = {
        "git", "config", "--file", path, key, value, NULL
    };
    return run_git(argv);
}

static int clear_command_override(void) {
    int result = 0;

    if (unsetenv("GIT_CONFIG_COUNT") != 0) result = -1;
    if (unsetenv("GIT_CONFIG_KEY_0") != 0) result = -1;
    if (unsetenv("GIT_CONFIG_VALUE_0") != 0) result = -1;
    if (unsetenv("GIT_CONFIG_PARAMETERS") != 0) result = -1;
    return result;
}

static int set_command_override(command_override_encoding_t encoding,
                                const char *key, const char *value) {
    char parameters[GIT_CONFIG_VALUE_MAX + 128U];

    if (!key || !value || clear_command_override() != 0) return -1;
    if (encoding == COMMAND_OVERRIDE_COUNT) {
        return setenv("GIT_CONFIG_KEY_0", key, 1) == 0 &&
                       setenv("GIT_CONFIG_VALUE_0", value, 1) == 0 &&
                       setenv("GIT_CONFIG_COUNT", "1", 1) == 0
                   ? 0
                   : -1;
    }
    if (encoding != COMMAND_OVERRIDE_PARAMETERS ||
        strchr(key, '\'') != NULL || strchr(value, '\'') != NULL ||
        (size_t)snprintf(parameters, sizeof(parameters), "'%s'='%s'",
                         key, value) >= sizeof(parameters)) {
        return -1;
    }
    return setenv("GIT_CONFIG_PARAMETERS", parameters, 1);
}

static int retain_file_generation(const char *path, char *retained,
                                  size_t retained_size) {
    if ((size_t)snprintf(retained, retained_size, "%s.retained", path) >=
        retained_size) {
        return -1;
    }
    return link(path, retained);
}

static int git_replace_vector(const char *scope, const char *key,
                              const char *const values[], size_t count) {
    if (git_unset_all(scope, key) != 0) return -1;
    for (size_t i = 0; i < count; i++) {
        if (git_add(scope, key, values[i]) != 0) return -1;
    }
    return 0;
}

static int g_prelock_writer_calls;
static pid_t g_locked_writer_pid;
static int g_locked_writer_first_failed;
static int g_locked_ctime_drift_calls;
static int g_locked_ctime_drift_result;
static int g_locked_retained_link_calls;
static int g_locked_retained_link_result;
static int g_locked_content_rewrite_calls;
static int g_locked_content_rewrite_result;
static char g_locked_config[MAX_PATH_LEN];
static char g_locked_hardlink[MAX_PATH_LEN];
static int g_postpublish_writer_calls;
static char g_postpublish_config[MAX_PATH_LEN];
static char g_postpublish_installed[MAX_PATH_LEN];
static command_runner_fn g_late_override_delegate;
static const char *g_late_override_value;
static int g_late_override_injected;

static int inject_command_override_after_name_write(
    const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    int command_result;

    if (!g_late_override_delegate) return -1;
    command_result = g_late_override_delegate(argv, opts, result);
    if (command_result == 0 && g_late_override_injected == 0 &&
        argv && argv[0] && argv[1] && argv[2] && argv[3] && argv[4] &&
        argv[5] == NULL &&
        strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[2], "--global") == 0 &&
        strcmp(argv[3], GIT_CONFIG_USER_NAME) == 0) {
        g_late_override_injected =
            set_command_override(COMMAND_OVERRIDE_COUNT,
                                 GIT_CONFIG_USER_NAME,
                                 g_late_override_value) == 0
                ? 1
                : -1;
    }
    return command_result;
}

static void drift_config_ctime_while_restore_lock_is_held(
    git_scope_t scope) {
    if (scope != GIT_SCOPE_GLOBAL || g_locked_ctime_drift_calls != 0) return;
    g_locked_ctime_drift_calls++;
    g_locked_ctime_drift_result = -1;
    if (link(g_locked_config, g_locked_hardlink) != 0) return;
    if (unlink(g_locked_hardlink) != 0) {
        (void)unlink(g_locked_hardlink);
        return;
    }
    g_locked_ctime_drift_result = 0;
}

static void retain_config_hardlink_while_restore_lock_is_held(
    git_scope_t scope) {
    if (scope != GIT_SCOPE_GLOBAL || g_locked_retained_link_calls != 0) {
        return;
    }
    g_locked_retained_link_calls++;
    g_locked_retained_link_result = link(g_locked_config,
                                         g_locked_hardlink);
}

static int rewrite_unrelated_config_value(void) {
    static const char before[] = "stable-before";
    static const char after[] = "stable-after!";
    struct stat original;
    struct timespec times[2];
    char *contents = NULL;
    char *match;
    size_t length;
    size_t offset = 0;
    int fd = -1;
    int result = -1;
    int flags = O_RDWR;

    _Static_assert(sizeof(before) == sizeof(after),
                   "rewrite fixture values must have equal length");
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(g_locked_config, flags);
    if (fd < 0 || ts_set_cloexec(fd) != 0 || fstat(fd, &original) != 0 ||
        original.st_size < 0 || (uintmax_t)original.st_size > SIZE_MAX - 1U) {
        goto cleanup;
    }
    length = (size_t)original.st_size;
    contents = malloc(length + 1U);
    if (!contents) goto cleanup;
    while (offset < length) {
        ssize_t count = pread(fd, contents + offset, length - offset,
                              (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto cleanup;
        offset += (size_t)count;
    }
    contents[length] = '\0';
    match = strstr(contents, before);
    if (!match || strstr(match + sizeof(before) - 1U, before)) {
        errno = EINVAL;
        goto cleanup;
    }
    offset = (size_t)(match - contents);
    if (pwrite(fd, after, sizeof(after) - 1U, (off_t)offset) !=
            (ssize_t)(sizeof(after) - 1U) ||
        fsync(fd) != 0) {
        goto cleanup;
    }
#if defined(__APPLE__)
    times[0] = original.st_atimespec;
    times[1] = original.st_mtimespec;
#else
    times[0] = original.st_atim;
    times[1] = original.st_mtim;
#endif
    if (futimens(fd, times) != 0 || fsync(fd) != 0) goto cleanup;
    result = 0;

cleanup:
    {
        int saved_errno = errno;
        free(contents);
        if (fd >= 0 && close(fd) != 0 && result == 0) {
            result = -1;
            saved_errno = errno;
        }
        errno = saved_errno;
    }
    return result;
}

static void rewrite_config_content_while_restore_lock_is_held(
    git_scope_t scope) {
    if (scope != GIT_SCOPE_GLOBAL || g_locked_content_rewrite_calls != 0) {
        return;
    }
    g_locked_content_rewrite_calls++;
    g_locked_content_rewrite_result = rewrite_unrelated_config_value();
}

static void add_name_before_restore_lock(git_scope_t scope) {
    if (scope != GIT_SCOPE_GLOBAL || g_prelock_writer_calls != 0) return;
    g_prelock_writer_calls++;
    if (git_add("--global", "user.name", "race-before-lock") != 0 ||
        git_set("--global", "audit.concurrent", "unmanaged-survives") != 0) {
        g_prelock_writer_calls = -1;
    }
}

static void replace_config_after_rollback_publish(git_scope_t scope) {
    static const char replacement[] =
        "[user]\n"
        "\tname = later-replacement\n"
        "[audit]\n"
        "\treplacement = must-survive\n";

    if (scope != GIT_SCOPE_LOCAL || g_postpublish_writer_calls != 0) return;
    g_postpublish_writer_calls++;
    if (rename(g_postpublish_config, g_postpublish_installed) != 0 ||
        write_text_file(g_postpublish_config, replacement, 0600) != 0) {
        g_postpublish_writer_calls = -1;
    }
}

/* The child proves a real `git config` writer cannot enter after the in-lock
 * ownership read. It exits after that required failure so it cannot race the
 * rollback's post-publication generation adoption. The parent issues the
 * later write only after restore returns, proving it is serialized after (and
 * never deleted by) the transaction. */
static void attempt_name_while_restore_lock_is_held(git_scope_t scope) {
    int ready[2];
    char outcome = '0';

    if (scope != GIT_SCOPE_GLOBAL || g_locked_writer_pid != 0) return;
    if (pipe(ready) != 0) {
        g_locked_writer_pid = -1;
        return;
    }
    g_locked_writer_pid = fork();
    if (g_locked_writer_pid == 0) {
        int first_rc;
        ssize_t written;
        close(ready[0]);
        first_rc = git_add("--global", "user.name", "race-after-lock");
        outcome = first_rc == 0 ? 'S' : 'F';
        do {
            written = write(ready[1], &outcome, 1);
        } while (written < 0 && errno == EINTR);
        if (written != 1) _exit(43);
        close(ready[1]);
        if (first_rc == 0) _exit(41);
        _exit(0);
    }
    close(ready[1]);
    if (g_locked_writer_pid < 0 || read(ready[0], &outcome, 1) != 1) {
        g_locked_writer_first_failed = -1;
    } else {
        g_locked_writer_first_failed = outcome == 'F' ? 1 : -1;
    }
    close(ready[0]);
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

static int read_binary_file_exact(const char *path, unsigned char *output,
                                  size_t expected_length) {
    FILE *file = fopen(path, "rb");
    size_t length;
    int trailing;
    int failed;

    if (!file) return -1;
    length = fread(output, 1U, expected_length, file);
    trailing = fgetc(file);
    failed = length != expected_length || trailing != EOF || ferror(file);
    if (fclose(file) != 0) failed = 1;
    return failed ? -1 : 0;
}

static char g_finalization_lock_path[MAX_PATH_LEN];
static int g_finalization_hook_calls;
static const unsigned char g_foreign_finalization_bytes[] = {
    0x00U, 0x67U, 0x69U, 0x74U, 0xffU, 0x0aU, 0x7fU
};

static bool finalization_hook_targets_global(const char *lock_leaf) {
    return lock_leaf &&
           strcmp(lock_leaf, "global.gitconfig.lock") == 0;
}

static bool kill_after_finalization_certificate_publish(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    if (stage == GIT_FINALIZATION_TEST_AFTER_CANONICAL_PUBLISH &&
        finalization_hook_targets_global(lock_leaf)) {
        _exit(86);
    }
    return false;
}

static bool kill_after_private_finalization_certificate_prepare(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    if (stage == GIT_FINALIZATION_TEST_AFTER_PRIVATE_PREPARE &&
        finalization_hook_targets_global(lock_leaf)) {
        _exit(87);
    }
    return false;
}

static bool fail_after_private_finalization_certificate_prepare(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    return stage == GIT_FINALIZATION_TEST_AFTER_PRIVATE_PREPARE &&
           finalization_hook_targets_global(lock_leaf);
}

static bool fail_finalization_release_once(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    if (stage == GIT_FINALIZATION_TEST_BEFORE_RELEASE &&
        finalization_hook_targets_global(lock_leaf) &&
        g_finalization_hook_calls++ == 0) {
        return true;
    }
    return false;
}

static bool fail_finalization_release_sync_once(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    if (stage ==
            GIT_FINALIZATION_TEST_BEFORE_RELEASE_DIRECTORY_SYNC &&
        finalization_hook_targets_global(lock_leaf) &&
        g_finalization_hook_calls++ == 0) {
        return true;
    }
    return false;
}

static bool replace_finalization_certificate_with_foreign_lock(
    git_finalization_test_stage_t stage, int directory_fd,
    const char *lock_leaf) {
    (void)directory_fd;
    if (stage == GIT_FINALIZATION_TEST_BEFORE_RELEASE &&
        finalization_hook_targets_global(lock_leaf) &&
        g_finalization_hook_calls++ == 0) {
        if (unlink(g_finalization_lock_path) != 0 ||
            write_binary_file(
                g_finalization_lock_path, g_foreign_finalization_bytes,
                sizeof(g_foreign_finalization_bytes), 0600) != 0) {
            return true;
        }
    }
    return false;
}

static size_t count_finalization_private_aliases(const char *directory_path) {
    static const char prefix[] = ".gitswitch-finalization-";
    DIR *directory = opendir(directory_path);
    struct dirent *entry;
    size_t count = 0U;

    if (!directory) return SIZE_MAX;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) == 0) {
            count++;
        }
    }
    if (errno != 0) count = SIZE_MAX;
    (void)closedir(directory);
    return count;
}

static int count_open_descriptors(void) {
    const char *directories[] = { "/proc/self/fd", "/dev/fd" };

    for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) {
        DIR *directory = opendir(directories[i]);
        struct dirent *entry;
        int count = 0;
        if (!directory) continue;
        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                count++;
            }
        }
        {
            int read_errno = errno;
            int close_rc = closedir(directory);
            if (read_errno != 0 || close_rc != 0) return -1;
        }
        return count;
    }
    return -1;
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
    CHECK_EQ_INT(git_config_seal(), 0);
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

TEST(managed_command_scope_overrides_are_rejected_before_snapshot) {
    static const char same_value[] = "same-command-value";
    static const char *const scope_flags[] = {"--global", "--local"};
    static const git_scope_t scopes[] = {
        GIT_SCOPE_GLOBAL, GIT_SCOPE_LOCAL
    };
    git_fixture_t fixture;
    char actual[256];
    git_current_config_t current;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    for (int encoding = COMMAND_OVERRIDE_COUNT;
         encoding <= COMMAND_OVERRIDE_PARAMETERS; encoding++) {
        for (size_t scope = 0;
             scope < sizeof(scopes) / sizeof(scopes[0]); scope++) {
            for (size_t key = 0;
                 key < sizeof(g_managed_override_keys) /
                           sizeof(g_managed_override_keys[0]);
                 key++) {
                CHECK_EQ_INT(git_set(scope_flags[scope],
                                     g_managed_override_keys[key],
                                     same_value), 0);
                CHECK_EQ_INT(set_command_override(
                                 (command_override_encoding_t)encoding,
                                 g_managed_override_keys[key], same_value),
                             0);
                git_ops_test_reset_caches();
                clear_error();
                errno = 0;
                CHECK_EQ_INT(git_config_snapshot(scopes[scope]), -1);
                CHECK_EQ_INT(get_last_error()->code,
                             ERR_GIT_CONFIG_FAILED);
                CHECK_EQ_INT(errno, ESTALE);
                CHECK(strstr(get_last_error()->message,
                             g_managed_override_keys[key]) != NULL);

                CHECK_EQ_INT(clear_command_override(), 0);
                CHECK_EQ_INT(git_get_all(scope_flags[scope],
                                         g_managed_override_keys[key],
                                         actual, sizeof(actual)), 0);
                CHECK_STR_EQ(actual, "same-command-value\n");
                CHECK_EQ_INT(git_unset_all(
                                 scope_flags[scope],
                                 g_managed_override_keys[key]), 0);
            }
        }

        /* Command scope itself is not prohibited. Only the managed identity
         * and signing selectors are incompatible with durable publication. */
        CHECK_EQ_INT(set_command_override(
                         (command_override_encoding_t)encoding,
                         "audit.unrelated", "allowed"),
                     0);
        git_ops_test_reset_caches();
        CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
        git_config_commit();
        CHECK_EQ_INT(clear_command_override(), 0);
    }

    /* Status remains observational: it reports the winning command scope
     * instead of treating an override as a persisted publication. */
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_NAME,
                         "persisted-name"), 0);
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_EMAIL,
                         "persisted@example.test"), 0);
    CHECK_EQ_INT(set_command_override(COMMAND_OVERRIDE_COUNT,
                                      GIT_CONFIG_USER_NAME,
                                      "command-name"), 0);
    git_ops_test_reset_caches();
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK_STR_EQ(current.name, "command-name");
    CHECK_EQ_INT(current.effective_name_scope,
                 GIT_CONFIG_ORIGIN_COMMAND);
    CHECK_EQ_INT(clear_command_override(), 0);

    fixture_cleanup(&fixture);
}

TEST(late_command_override_is_rejected_at_account_writer_boundary) {
    git_fixture_t fixture;
    account_t account;
    char before[4096];
    char after[4096];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_NAME,
                         "writer-boundary-before"), 0);
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_EMAIL,
                         "writer-boundary@example.test"), 0);
    CHECK_EQ_INT(read_file(fixture.global_config, before, sizeof(before)), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);

    /* The environment can change after snapshot. The public account writer
     * must repeat the preflight before its first Git mutation. */
    CHECK_EQ_INT(set_command_override(COMMAND_OVERRIDE_PARAMETERS,
                                      GIT_CONFIG_USER_NAME,
                                      account.name), 0);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 GIT_CONFIG_USER_NAME) != NULL);
    CHECK_EQ_INT(read_file(fixture.global_config, after, sizeof(after)), 0);
    CHECK_STR_EQ(after, before);

    CHECK_EQ_INT(clear_command_override(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(read_file(fixture.global_config, after, sizeof(after)), 0);
    CHECK_STR_EQ(after, before);
    fixture_cleanup(&fixture);
}

TEST(post_write_command_override_fails_merged_proof_and_restores_exactly) {
    git_fixture_t fixture;
    account_t account;
    command_runner_fn previous;
    char before[4096];
    char after[4096];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_NAME,
                         "verification-before"), 0);
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_EMAIL,
                         "verification@example.test"), 0);
    CHECK_EQ_INT(git_set("--global", "audit.preserved",
                         "byte-for-byte"), 0);
    CHECK_EQ_INT(read_file(fixture.global_config, before, sizeof(before)), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);

    /* Inject a same-valued command override only after the persisted name
     * write succeeds. Scoped read-back still matches, so the final atomic
     * merged listing is the boundary that must detect the lost provenance. */
    g_late_override_value = account.name;
    g_late_override_injected = 0;
    previous = run_set_runner(inject_command_override_after_name_write);
    g_late_override_delegate = previous;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);
    g_late_override_delegate = NULL;
    CHECK_EQ_INT(g_late_override_injected, 1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 GIT_CONFIG_USER_NAME) != NULL);

    CHECK_EQ_INT(clear_command_override(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(read_file(fixture.global_config, after, sizeof(after)), 0);
    CHECK_STR_EQ(after, before);
    fixture_cleanup(&fixture);
}

TEST(all_gpg_format_and_program_keys_normalize_and_restore_exactly) {
    static const char *const scopes[] = {
        "--global", "--local", "--worktree"
    };
    git_fixture_t fixture;
    char trusted_directory[MAX_PATH_LEN] = "";
    char bound_program[MAX_PATH_LEN];
    char expected[3][5][1024];
    char actual[1024];
    char value[256];
    git_current_config_t current;
    gpg_config_t gpg_config;
    account_t account;

    if (!ts_mkdtemp_trusted(trusted_directory, sizeof(trusted_directory),
                            "gsw-ar08-git-transaction") ||
        safe_snprintf(bound_program, sizeof(bound_program),
                      "%s/transaction-gpg", trusted_directory) != 0 ||
        write_text_file(bound_program, "#!/bin/sh\nexit 0\n", 0700) != 0) {
        CHECK(false);
        ts_rm_rf(trusted_directory);
        return;
    }
    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        ts_rm_rf(trusted_directory);
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
    memset(&gpg_config, 0, sizeof(gpg_config));
    CHECK_EQ_INT(safe_strncpy(gpg_config.current_key_id,
                              account.gpg_key_id,
                              sizeof(gpg_config.current_key_id)), 0);
    CHECK_EQ_INT(safe_strncpy(gpg_config.executable_path, bound_program,
                              sizeof(gpg_config.executable_path)), 0);
    /* This transaction test owns Git publication/rollback, not keyring
     * inventory. Model the activation proof that accounts_switch completes
     * before it reaches these writes. */
    gpg_manager_note_key_available(account.gpg_key_id);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(gpg_configure_git_signing(&gpg_config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_get_all("--global", "gpg.format", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "openpgp\n");
    for (size_t scope = 0; scope < 3; scope++) {
        for (size_t key = scope == 0 ? 1U : 0U;
             key < sizeof(g_gpg_model_keys) / sizeof(g_gpg_model_keys[0]);
             key++) {
            int expected_present = scope == 0 && key == 2U;
            CHECK_EQ_INT(git_get_all(scopes[scope], g_gpg_model_keys[key],
                                     actual, sizeof(actual)),
                         expected_present ? 0 : -1);
            if (expected_present) {
                CHECK((size_t)snprintf(value, sizeof(value), "%s\n",
                                       bound_program) < sizeof(value));
                CHECK_STR_EQ(actual, value);
            }
        }
    }
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.valid);
    CHECK_STR_EQ(current.name, account.name);
    CHECK_STR_EQ(current.signing_key, account.gpg_key_id);
    CHECK(!current.gpg_program.present);
    CHECK(current.gpg_openpgp_program.present);
    CHECK_STR_EQ(current.gpg_openpgp_program.value, bound_program);
    CHECK(!current.gpg_x509_program.present);
    CHECK(!current.gpg_ssh_program.present);

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
    ts_rm_rf(trusted_directory);
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
    CHECK_EQ_INT(git_config_seal(), 0);
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

TEST(rollback_preserves_concurrent_ordered_vectors_in_every_managed_scope) {
    static const char *const scopes[] = {
        "--global", "--local", "--worktree"
    };
    static const char *const before[3][2] = {
        {"global-before-1", NULL},
        {"local-before-1", "local-before-2"},
        {"worktree-before-1", "worktree-before-2"}
    };
    static const size_t before_count[] = {1, 2, 2};
    static const char *const later[3][2] = {
        {"global-later-1", "global-later-2"},
        {"local-later-1", "local-later-2"},
        {"worktree-later-1", "worktree-later-2"}
    };
    git_fixture_t fixture;
    account_t account;
    char config_paths[3][MAX_PATH_LEN];
    char retained_paths[3][MAX_PATH_LEN];
    char actual[512];
    char expected[512];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < before_count[i]; j++) {
            CHECK_EQ_INT(git_add(scopes[i], "user.name", before[i][j]), 0);
        }
    }

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK(safe_strncpy(config_paths[0], fixture.global_config,
                       sizeof(config_paths[0])) == 0);
    CHECK((size_t)snprintf(config_paths[1], sizeof(config_paths[1]),
                           "%s/.git/config", fixture.repo) <
          sizeof(config_paths[1]));
    CHECK((size_t)snprintf(config_paths[2], sizeof(config_paths[2]),
                           "%s/.git/config.worktree", fixture.repo) <
          sizeof(config_paths[2]));
    for (size_t i = 0; i < 3; i++) {
        CHECK_EQ_INT(retain_file_generation(config_paths[i],
                                            retained_paths[i],
                                            sizeof(retained_paths[i])), 0);
    }

    /* A later writer appends to each exact ordered vector after the
     * transaction's post-image has been sealed. A second seal is deliberately
     * a no-op: it must not launder those values into transaction ownership. */
    for (size_t i = 0; i < 3; i++) {
        CHECK_EQ_INT(git_add(scopes[i], "user.name", later[i][0]), 0);
        CHECK_EQ_INT(git_add(scopes[i], "user.name", later[i][1]), 0);
    }
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "3 managed vector(s)") != NULL);
    CHECK(strstr(get_last_error()->message, "changed outside") != NULL);
    CHECK(strstr(get_last_error()->message, "retry material retained") != NULL);
    for (size_t i = 0; i < 3; i++) {
        if (i == 0) {
            (void)snprintf(expected, sizeof(expected), "%s\n%s\n%s\n",
                           account.name, later[i][0], later[i][1]);
        } else {
            (void)snprintf(expected, sizeof(expected), "%s\n%s\n",
                           later[i][0], later[i][1]);
        }
        CHECK_EQ_INT(git_get_all(scopes[i], "user.name", actual,
                                 sizeof(actual)), 0);
        CHECK_STR_EQ(actual, expected);
    }

    /* An unchanged retry remains non-destructive. Value-only repair cannot
     * transfer rollback ownership to a new inode; reinstall each exact sealed
     * generation before applying the retained before-image. */
    CHECK_EQ_INT(git_config_restore(), -1);
    for (size_t i = 0; i < 3; i++) {
        CHECK_EQ_INT(rename(retained_paths[i], config_paths[i]), 0);
    }
    CHECK_EQ_INT(git_config_restore(), 0);
    for (size_t i = 0; i < 3; i++) {
        if (before_count[i] == 1) {
            (void)snprintf(expected, sizeof(expected), "%s\n", before[i][0]);
        } else {
            (void)snprintf(expected, sizeof(expected), "%s\n%s\n",
                           before[i][0], before[i][1]);
        }
        CHECK_EQ_INT(git_get_all(scopes[i], "user.name", actual,
                                 sizeof(actual)), 0);
        CHECK_STR_EQ(actual, expected);
    }

    fixture_cleanup(&fixture);
}

TEST(writer_in_old_compare_write_gap_is_rechecked_under_canonical_lock) {
    git_fixture_t fixture;
    account_t account;
    char retained_config[MAX_PATH_LEN];
    char concurrent_config[MAX_PATH_LEN];
    char actual[512];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-gap"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(retain_file_generation(fixture.global_config,
                                        retained_config,
                                        sizeof(retained_config)), 0);
    CHECK((size_t)snprintf(concurrent_config, sizeof(concurrent_config),
                           "%s.concurrent", fixture.global_config) <
          sizeof(concurrent_config));

    g_prelock_writer_calls = 0;
    git_ops_test_set_restore_prelock_hook(add_name_before_restore_lock);
    CHECK_EQ_INT(git_config_restore(), -1);
    git_ops_test_set_restore_prelock_hook(NULL);
    CHECK_EQ_INT(g_prelock_writer_calls, 1);
    CHECK(strstr(get_last_error()->message, "changed outside") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "AR08 Git User\nrace-before-lock\n");
    CHECK_EQ_INT(git_get_all("--global", "audit.concurrent", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "unmanaged-survives\n");

    CHECK_EQ_INT(rename(fixture.global_config, concurrent_config), 0);
    CHECK_EQ_INT(rename(retained_config, fixture.global_config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-gap\n");
    CHECK_EQ_INT(git_get_file_all(concurrent_config, "audit.concurrent",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "unmanaged-survives\n");
    fixture_cleanup(&fixture);
}

TEST(real_git_writer_is_serialized_after_in_lock_ownership_read) {
    git_fixture_t fixture;
    account_t account;
    char actual[512];
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-locked-race"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    g_locked_writer_pid = 0;
    g_locked_writer_first_failed = 0;
    git_ops_test_set_restore_locked_hook(
        attempt_name_while_restore_lock_is_held);
    CHECK_EQ_INT(git_config_restore(), 0);
    git_ops_test_set_restore_locked_hook(NULL);
    CHECK(g_locked_writer_pid > 0);
    if (g_locked_writer_pid > 0) {
        CHECK(waitpid(g_locked_writer_pid, &status, 0) == g_locked_writer_pid);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(g_locked_writer_first_failed, 1);
    CHECK_EQ_INT(git_add("--global", "user.name", "race-after-lock"), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-locked-race\nrace-after-lock\n");
    fixture_cleanup(&fixture);
}

TEST(ctime_only_drift_under_restore_lock_keeps_exact_generation_owned) {
    git_fixture_t fixture;
    account_t account;
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-ctime-drift"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK(safe_strncpy(g_locked_config, fixture.global_config,
                       sizeof(g_locked_config)) == 0);
    CHECK((size_t)snprintf(g_locked_hardlink, sizeof(g_locked_hardlink),
                           "%s.ctime-drift", fixture.global_config) <
          sizeof(g_locked_hardlink));

    g_locked_ctime_drift_calls = 0;
    g_locked_ctime_drift_result = -1;
    git_ops_test_set_restore_locked_hook(
        drift_config_ctime_while_restore_lock_is_held);
    CHECK_EQ_INT(git_config_restore(), 0);
    git_ops_test_set_restore_locked_hook(NULL);
    CHECK_EQ_INT(g_locked_ctime_drift_calls, 1);
    CHECK_EQ_INT(g_locked_ctime_drift_result, 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-ctime-drift\n");

    git_config_commit();
    fixture_cleanup(&fixture);
}

TEST(persistent_hardlink_under_restore_lock_invalidates_generation) {
    git_fixture_t fixture;
    account_t account;
    struct stat config_stat;
    struct stat retained_stat;
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-retained-link"),
                 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK(safe_strncpy(g_locked_config, fixture.global_config,
                       sizeof(g_locked_config)) == 0);
    CHECK((size_t)snprintf(g_locked_hardlink, sizeof(g_locked_hardlink),
                           "%s.retained-link", fixture.global_config) <
          sizeof(g_locked_hardlink));

    g_locked_retained_link_calls = 0;
    g_locked_retained_link_result = -1;
    git_ops_test_set_restore_locked_hook(
        retain_config_hardlink_while_restore_lock_is_held);
    CHECK_EQ_INT(git_config_restore(), -1);
    git_ops_test_set_restore_locked_hook(NULL);
    CHECK_EQ_INT(g_locked_retained_link_calls, 1);
    CHECK_EQ_INT(g_locked_retained_link_result, 0);
    CHECK(strstr(get_last_error()->message,
                 "destination generation") != NULL);
    CHECK_EQ_INT(stat(fixture.global_config, &config_stat), 0);
    CHECK_EQ_INT(stat(g_locked_hardlink, &retained_stat), 0);
    CHECK(config_stat.st_dev == retained_stat.st_dev);
    CHECK(config_stat.st_ino == retained_stat.st_ino);
    CHECK(config_stat.st_nlink >= 2);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "AR08 Git User\n");

    git_config_commit();
    CHECK_EQ_INT(unlink(g_locked_hardlink), 0);
    fixture_cleanup(&fixture);
}

TEST(same_metadata_content_rewrite_under_restore_lock_is_rejected) {
    git_fixture_t fixture;
    account_t account;
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-content-race"), 0);
    CHECK_EQ_INT(git_set("--global", "audit.unrelated", "stable-before"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK(safe_strncpy(g_locked_config, fixture.global_config,
                       sizeof(g_locked_config)) == 0);

    g_locked_content_rewrite_calls = 0;
    g_locked_content_rewrite_result = -1;
    git_ops_test_set_restore_locked_hook(
        rewrite_config_content_while_restore_lock_is_held);
    CHECK_EQ_INT(git_config_restore(), -1);
    git_ops_test_set_restore_locked_hook(NULL);
    CHECK_EQ_INT(g_locked_content_rewrite_calls, 1);
    CHECK_EQ_INT(g_locked_content_rewrite_result, 0);
    CHECK(strstr(get_last_error()->message, "changed outside") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "AR08 Git User\n");
    CHECK_EQ_INT(git_get_all("--global", "audit.unrelated", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "stable-after!\n");

    git_config_commit();
    fixture_cleanup(&fixture);
}

TEST(global_xdg_write_target_is_locked_and_restored_exactly) {
    git_fixture_t fixture;
    account_t account;
    char xdg_git[MAX_PATH_LEN];
    char xdg_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(xdg_git, sizeof(xdg_git), "%s/git", fixture.xdg) <
          sizeof(xdg_git));
    CHECK((size_t)snprintf(xdg_config, sizeof(xdg_config), "%s/config",
                           xdg_git) < sizeof(xdg_config));
    CHECK_EQ_INT(mkdir(xdg_git, 0700), 0);
    CHECK_EQ_INT(write_text_file(xdg_config,
                                 "[user]\n\tname = before-xdg\n", 0600), 0);
    CHECK_EQ_INT(unsetenv("GIT_CONFIG_GLOBAL"), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-xdg\n");
    CHECK(access(fixture.global_config, F_OK) != 0);
    fixture_cleanup(&fixture);
}

TEST(config_and_parent_symlinks_keep_identity_while_targets_restore) {
    git_fixture_t fixture;
    account_t account;
    char config_target[MAX_PATH_LEN];
    char parent_target[MAX_PATH_LEN];
    char parent_link[MAX_PATH_LEN];
    char parent_config[MAX_PATH_LEN];
    char actual[256];
    struct stat config_link_before;
    struct stat config_link_after;
    struct stat parent_link_before;
    struct stat parent_link_after;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(config_target, sizeof(config_target),
                           "%s/symlink-target.gitconfig", fixture.base) <
          sizeof(config_target));
    CHECK_EQ_INT(write_text_file(config_target,
                                 "[user]\n\tname = before-file-link\n",
                                 0600), 0);
    CHECK_EQ_INT(symlink(config_target, fixture.global_config), 0);
    CHECK_EQ_INT(lstat(fixture.global_config, &config_link_before), 0);
    CHECK(S_ISLNK(config_link_before.st_mode));
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(lstat(fixture.global_config, &config_link_after), 0);
    CHECK(S_ISLNK(config_link_after.st_mode));
    CHECK(config_link_after.st_dev == config_link_before.st_dev);
    CHECK(config_link_after.st_ino == config_link_before.st_ino);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-file-link\n");

    CHECK_EQ_INT(unlink(fixture.global_config), 0);
    CHECK((size_t)snprintf(parent_target, sizeof(parent_target),
                           "%s/physical-config-dir", fixture.base) <
          sizeof(parent_target));
    CHECK((size_t)snprintf(parent_link, sizeof(parent_link),
                           "%s/config-dir-link", fixture.base) <
          sizeof(parent_link));
    CHECK((size_t)snprintf(parent_config, sizeof(parent_config),
                           "%s/global.gitconfig", parent_link) <
          sizeof(parent_config));
    CHECK_EQ_INT(mkdir(parent_target, 0700), 0);
    CHECK_EQ_INT(symlink(parent_target, parent_link), 0);
    CHECK_EQ_INT(lstat(parent_link, &parent_link_before), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", parent_config, 1), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-parent-link"), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(lstat(parent_link, &parent_link_after), 0);
    CHECK(S_ISLNK(parent_link_after.st_mode));
    CHECK(parent_link_after.st_dev == parent_link_before.st_dev);
    CHECK(parent_link_after.st_ino == parent_link_before.st_ino);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-parent-link\n");
    fixture_cleanup(&fixture);
}

TEST(maximum_git_lock_basename_uses_short_staging_name) {
    git_fixture_t fixture;
    account_t account;
    char basename[NAME_MAX - sizeof(".lock") + 2U];
    char config_path[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    memset(basename, 'c', sizeof(basename) - 1U);
    basename[sizeof(basename) - 1U] = '\0';
    CHECK(strlen(basename) + strlen(".lock") == NAME_MAX);
    CHECK((size_t)snprintf(config_path, sizeof(config_path), "%s/%s",
                           fixture.base, basename) < sizeof(config_path));
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", config_path, 1), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-long-name"), 0);
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-long-name\n");
    fixture_cleanup(&fixture);
}

TEST(partial_retry_skips_completed_scopes_and_preserves_their_later_changes) {
    static const char *const scopes[] = {
        "--global", "--local", "--worktree"
    };
    static const char *const before[] = {
        "global-before", "local-before", "worktree-before"
    };
    git_fixture_t fixture;
    account_t account;
    char lock_path[MAX_PATH_LEN];
    char actual[512];
    char expected[512];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    for (size_t i = 0; i < 3; i++) {
        CHECK_EQ_INT(git_set(scopes[i], "user.name", before[i]), 0);
    }
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    account = basic_account(&fixture, false);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    CHECK((size_t)snprintf(lock_path, sizeof(lock_path), "%s.lock",
                           fixture.global_config) < sizeof(lock_path));
    CHECK_EQ_INT(write_text_file(lock_path, "held\n", 0600), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "restore operation(s) failed") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    (void)snprintf(expected, sizeof(expected), "%s\n", account.name);
    CHECK_STR_EQ(actual, expected);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "local-before\n");
    CHECK_EQ_INT(git_get_all("--worktree", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "worktree-before\n");

    /* These writers arrive after their scopes completed rollback. The retry
     * owns only the still-incomplete global keys and must never revisit the
     * completed local/worktree keys. */
    CHECK_EQ_INT(git_add("--local", "user.name", "local-after-rollback"), 0);
    CHECK_EQ_INT(git_add("--worktree", "user.name",
                         "worktree-after-rollback"), 0);
    CHECK_EQ_INT(unlink(lock_path), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "global-before\n");
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "local-before\nlocal-after-rollback\n");
    CHECK_EQ_INT(git_get_all("--worktree", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "worktree-before\nworktree-after-rollback\n");

    fixture_cleanup(&fixture);
}

TEST(preseal_writer_is_rejected_and_never_laundered_into_rollback_ownership) {
    git_fixture_t fixture;
    char actual[512];
    const char *const intended[] = {"owned-post"};

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-preseal"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, intended[0],
                                      GIT_SCOPE_GLOBAL), 0);

    /* Deterministic external writer in the exact gap between the final owned
     * write and seal. Seal compares against the recorded intended vector; it
     * must not adopt this reread and later overwrite it during rollback. */
    CHECK_EQ_INT(git_add("--global", "user.name", "external-preseal"), 0);
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message,
                 "before post-image verification") != NULL);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "1 managed vector(s)") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "owned-post\nexternal-preseal\n");

    CHECK_EQ_INT(git_replace_vector("--global", "user.name", intended, 1), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-preseal\n");

    fixture_cleanup(&fixture);
}

TEST(enabled_empty_worktree_scope_rejects_preseal_writer) {
    git_fixture_t fixture;
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-empty-worktree"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "owned-post",
                                      GIT_SCOPE_GLOBAL), 0);

    /* The worktree store exists and outranks the selected global scope even
     * though it had no managed values when the transaction began. */
    CHECK_EQ_INT(git_set("--worktree", "user.name", "later-worktree"), 0);
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK(strstr(get_last_error()->message,
                 "before post-image verification") != NULL);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "1 managed vector(s)") != NULL);
    CHECK_EQ_INT(git_get_all("--worktree", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "later-worktree\n");

    CHECK_EQ_INT(git_unset_all("--worktree", "user.name"), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-empty-worktree\n");

    fixture_cleanup(&fixture);
}

TEST(enabled_empty_worktree_scope_preserves_postseal_writer) {
    git_fixture_t fixture;
    char worktree_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-empty-worktree"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "owned-post",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK((size_t)snprintf(worktree_config, sizeof(worktree_config),
                           "%s/.git/config.worktree", fixture.repo) <
          sizeof(worktree_config));

    CHECK_EQ_INT(git_set("--worktree", "user.name", "later-worktree"), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "1 managed vector(s)") != NULL);
    CHECK_EQ_INT(git_get_all("--worktree", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "later-worktree\n");

    CHECK_EQ_INT(unlink(worktree_config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-empty-worktree\n");

    fixture_cleanup(&fixture);
}

TEST(direct_worktree_extension_true_ignores_later_included_false) {
    git_fixture_t fixture;
    char include_path[MAX_PATH_LEN];
    char worktree_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(include_path, sizeof(include_path),
                           "%s/included.gitconfig", fixture.base) <
          sizeof(include_path));
    CHECK_EQ_INT(write_text_file(include_path,
                                 "[extensions]\n\tworktreeConfig = false\n",
                                 0600), 0);
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "true"), 0);
    CHECK_EQ_INT(git_set("--local", "include.path", include_path), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-direct-true"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "owned-post",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK((size_t)snprintf(worktree_config, sizeof(worktree_config),
                           "%s/.git/config.worktree", fixture.repo) <
          sizeof(worktree_config));

    CHECK_EQ_INT(git_set("--worktree", "user.name", "later-worktree"), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "1 managed vector(s)") != NULL);
    CHECK_EQ_INT(git_get_all("--worktree", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "later-worktree\n");

    CHECK_EQ_INT(unlink(worktree_config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-direct-true\n");

    fixture_cleanup(&fixture);
}

TEST(direct_worktree_extension_false_ignores_later_included_true) {
    git_fixture_t fixture;
    char include_path[MAX_PATH_LEN];
    char local_config[MAX_PATH_LEN];
    char retained_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(include_path, sizeof(include_path),
                           "%s/included.gitconfig", fixture.base) <
          sizeof(include_path));
    CHECK_EQ_INT(write_text_file(include_path,
                                 "[extensions]\n\tworktreeConfig = true\n",
                                 0600), 0);
    CHECK_EQ_INT(git_set("--local", "extensions.worktreeConfig", "false"), 0);
    CHECK_EQ_INT(git_set("--local", "include.path", include_path), 0);
    CHECK_EQ_INT(git_set("--global", "user.name", "before-direct-false"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "owned-post",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK((size_t)snprintf(local_config, sizeof(local_config),
                           "%s/.git/config", fixture.repo) <
          sizeof(local_config));
    CHECK_EQ_INT(retain_file_generation(local_config, retained_config,
                                        sizeof(retained_config)), 0);

    /* With no distinct store, Git aliases --worktree to --local. Tracking both
     * would count the same later vector twice instead of the single conflict
     * owned by the local scope. */
    CHECK_EQ_INT(git_set("--worktree", "user.name", "later-local"), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "1 managed vector(s)") != NULL);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "later-local\n");

    CHECK_EQ_INT(rename(retained_config, local_config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-direct-false\n");

    fixture_cleanup(&fixture);
}

TEST(committed_git_transaction_discards_rollback_ownership) {
    git_fixture_t fixture;
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-commit"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "committed-value",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "too-late",
                                      GIT_SCOPE_GLOBAL), -1);
    CHECK(strstr(get_last_error()->message, "sealed") != NULL);
    git_config_commit();
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "committed-value\n");

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

TEST(replaced_repository_with_identical_managed_vectors_is_never_rolled_back) {
    git_fixture_t fixture;
    char original_repo[MAX_PATH_LEN];
    char replacement_repo[MAX_PATH_LEN];
    char replacement_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(original_repo, sizeof(original_repo), "%s.original",
                           fixture.repo) < sizeof(original_repo));
    CHECK((size_t)snprintf(replacement_repo, sizeof(replacement_repo),
                           "%s.replacement", fixture.repo) <
          sizeof(replacement_repo));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s/.git/config", replacement_repo) <
          sizeof(replacement_config));
    CHECK_EQ_INT(git_add("--local", "user.name", "before-generation-1"), 0);
    CHECK_EQ_INT(git_add("--local", "user.name", "before-generation-2"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_unset_config_value(GIT_CONFIG_USER_NAME,
                                        GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME,
                                      "sealed-replacement-value",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    CHECK_EQ_INT(rename(fixture.repo, original_repo), 0);
    CHECK_EQ_INT(mkdir(fixture.repo, 0700), 0);
    CHECK_EQ_INT(chdir(fixture.repo), 0);
    {
        const char *const init[] = { "git", "init", "-q", NULL };
        CHECK_EQ_INT(run_git(init), 0);
    }
    CHECK_EQ_INT(git_set("--local", "user.name",
                         "sealed-replacement-value"), 0);
    CHECK_EQ_INT(git_set("--local", "audit.replacement",
                         "must-survive"), 0);

    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-replacement-value\n");
    CHECK_EQ_INT(git_get_all("--local", "audit.replacement", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    CHECK_EQ_INT(chdir(fixture.base), 0);
    CHECK_EQ_INT(rename(fixture.repo, replacement_repo), 0);
    CHECK_EQ_INT(rename(original_repo, fixture.repo), 0);
    CHECK_EQ_INT(chdir(fixture.repo), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-generation-1\nbefore-generation-2\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-replacement-value\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

TEST(replaced_config_namespace_with_identical_vectors_is_never_rolled_back) {
    git_fixture_t fixture;
    char config_dir[MAX_PATH_LEN];
    char original_dir[MAX_PATH_LEN];
    char replacement_dir[MAX_PATH_LEN];
    char live_config[MAX_PATH_LEN];
    char replacement_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(config_dir, sizeof(config_dir), "%s/config-home",
                           fixture.base) < sizeof(config_dir));
    CHECK((size_t)snprintf(original_dir, sizeof(original_dir), "%s.original",
                           config_dir) < sizeof(original_dir));
    CHECK((size_t)snprintf(replacement_dir, sizeof(replacement_dir),
                           "%s.replacement", config_dir) <
          sizeof(replacement_dir));
    CHECK((size_t)snprintf(live_config, sizeof(live_config), "%s/config",
                           config_dir) < sizeof(live_config));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s/config", replacement_dir) <
          sizeof(replacement_config));
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", live_config, 1), 0);
    CHECK_EQ_INT(git_add("--global", "user.name", "global-before-1"), 0);
    CHECK_EQ_INT(git_add("--global", "user.name", "global-before-2"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_unset_config_value(GIT_CONFIG_USER_NAME,
                                        GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME,
                                      "sealed-global-replacement",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    CHECK_EQ_INT(rename(config_dir, original_dir), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "sealed-global-replacement"), 0);
    CHECK_EQ_INT(git_set("--global", "audit.replacement",
                         "must-survive"), 0);

    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-global-replacement\n");
    CHECK_EQ_INT(git_get_all("--global", "audit.replacement", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    CHECK_EQ_INT(rename(config_dir, replacement_dir), 0);
    CHECK_EQ_INT(rename(original_dir, config_dir), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "global-before-1\nglobal-before-2\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-global-replacement\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

TEST(replaced_config_file_with_identical_vectors_is_never_rolled_back) {
    git_fixture_t fixture;
    char config[MAX_PATH_LEN];
    char original_config[MAX_PATH_LEN];
    char replacement_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(config, sizeof(config), "%s/.git/config",
                           fixture.repo) < sizeof(config));
    CHECK((size_t)snprintf(original_config, sizeof(original_config),
                           "%s.original", config) < sizeof(original_config));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s.replacement", config) <
          sizeof(replacement_config));
    CHECK_EQ_INT(git_set("--local", "user.name", "file-before"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME,
                                      "sealed-file-replacement",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    CHECK_EQ_INT(rename(config, original_config), 0);
    CHECK_EQ_INT(git_set_file(config, "user.name",
                              "sealed-file-replacement"), 0);
    CHECK_EQ_INT(git_set_file(config, "audit.replacement", "must-survive"), 0);

    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_file_all(config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-file-replacement\n");
    CHECK_EQ_INT(git_get_file_all(config, "audit.replacement", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    CHECK_EQ_INT(rename(config, replacement_config), 0);
    CHECK_EQ_INT(rename(original_config, config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "file-before\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "sealed-file-replacement\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

TEST(replaced_config_file_with_one_conflict_is_never_partially_rebased) {
    git_fixture_t fixture;
    char config[MAX_PATH_LEN];
    char original_config[MAX_PATH_LEN];
    char replacement_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(config, sizeof(config), "%s/.git/config",
                           fixture.repo) < sizeof(config));
    CHECK((size_t)snprintf(original_config, sizeof(original_config),
                           "%s.original", config) < sizeof(original_config));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s.replacement", config) <
          sizeof(replacement_config));
    CHECK_EQ_INT(git_set("--local", "user.name", "before-name"), 0);
    CHECK_EQ_INT(git_set("--local", "user.email", "before@example.test"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "post-name",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_EMAIL,
                                      "post@example.test",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    /* One conflicting managed vector must not authorize rollback of another
     * vector in an unrelated file generation at the same pathname. */
    CHECK_EQ_INT(rename(config, original_config), 0);
    CHECK_EQ_INT(git_set_file(config, "user.name", "unrelated-conflict"), 0);
    CHECK_EQ_INT(git_set_file(config, "user.email", "post@example.test"), 0);
    CHECK_EQ_INT(git_set_file(config, "audit.replacement", "must-survive"), 0);

    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_file_all(config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "unrelated-conflict\n");
    CHECK_EQ_INT(git_get_file_all(config, "user.email", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "post@example.test\n");

    CHECK_EQ_INT(rename(config, replacement_config), 0);
    CHECK_EQ_INT(rename(original_config, config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-name\n");
    CHECK_EQ_INT(git_get_all("--local", "user.email", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before@example.test\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "user.email", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "post@example.test\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

TEST(conflict_retry_never_rebases_onto_unrelated_same_path_generation) {
    git_fixture_t fixture;
    char config[MAX_PATH_LEN];
    char retained_config[MAX_PATH_LEN];
    char conflicted_config[MAX_PATH_LEN];
    char replacement_config[MAX_PATH_LEN];
    char actual[256];
    int retry_result;
    int retry_errno;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(config, sizeof(config), "%s/.git/config",
                           fixture.repo) < sizeof(config));
    CHECK((size_t)snprintf(conflicted_config, sizeof(conflicted_config),
                           "%s.conflicted", config) <
          sizeof(conflicted_config));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s.replacement", config) <
          sizeof(replacement_config));
    CHECK_EQ_INT(git_set("--local", "user.name", "before-name"), 0);
    CHECK_EQ_INT(git_set("--local", "user.email", "before@example.test"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME, "post-name",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_EMAIL,
                                      "post@example.test",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);
    CHECK_EQ_INT(retain_file_generation(config, retained_config,
                                        sizeof(retained_config)), 0);

    /* A real conflict on one generation cannot grant a reusable allowance to
     * a later replacement generation, even when every managed value is then
     * repaired to the sealed post-image. */
    CHECK_EQ_INT(git_add("--local", "user.name", "legitimate-conflict"), 0);
    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK_EQ_INT(rename(config, conflicted_config), 0);
    CHECK_EQ_INT(git_set_file(config, "user.name", "post-name"), 0);
    CHECK_EQ_INT(git_set_file(config, "user.email", "post@example.test"), 0);
    CHECK_EQ_INT(git_set_file(config, "audit.replacement", "must-survive"), 0);

    CHECK_EQ_INT(git_config_restore(), -1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_file_all(config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "post-name\n");
    CHECK_EQ_INT(git_get_file_all(config, "audit.replacement", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    CHECK_EQ_INT(rename(config, replacement_config), 0);
    CHECK_EQ_INT(rename(retained_config, config), 0);
    retry_result = git_config_restore();
    retry_errno = errno;
    if (retry_result != 0) {
        fprintf(stderr,
                "exact-generation retry failed (errno=%d): %s\n",
                retry_errno, get_last_error()->message);
    }
    CHECK_EQ_INT(retry_result, 0);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-name\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "post-name\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

TEST(postpublish_path_race_retains_the_installed_generation_for_retry) {
    git_fixture_t fixture;
    char replacement_config[MAX_PATH_LEN];
    char actual[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK((size_t)snprintf(g_postpublish_config,
                           sizeof(g_postpublish_config), "%s/.git/config",
                           fixture.repo) < sizeof(g_postpublish_config));
    CHECK((size_t)snprintf(g_postpublish_installed,
                           sizeof(g_postpublish_installed), "%s.installed",
                           g_postpublish_config) <
          sizeof(g_postpublish_installed));
    CHECK((size_t)snprintf(replacement_config, sizeof(replacement_config),
                           "%s.replacement", g_postpublish_config) <
          sizeof(replacement_config));
    CHECK_EQ_INT(git_set("--local", "user.name", "before-publish-race"), 0);
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_USER_NAME,
                                      "owned-post-publish-race",
                                      GIT_SCOPE_LOCAL), 0);
    CHECK_EQ_INT(git_config_seal(), 0);

    /* The rollback has already installed its before-image when another writer
     * replaces the pathname. Its verified publication descriptor must become
     * the retained generation without reopening that now-unrelated pathname. */
    g_postpublish_writer_calls = 0;
    git_ops_test_set_restore_postpublish_hook(
        replace_config_after_rollback_publish);
    CHECK_EQ_INT(git_config_restore(), -1);
    git_ops_test_set_restore_postpublish_hook(NULL);
    CHECK_EQ_INT(g_postpublish_writer_calls, 1);
    CHECK(strstr(get_last_error()->message, "generation") != NULL);
    CHECK_EQ_INT(git_get_file_all(g_postpublish_config, "user.name", actual,
                                  sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "later-replacement\n");

    CHECK_EQ_INT(rename(g_postpublish_config, replacement_config), 0);
    CHECK_EQ_INT(rename(g_postpublish_installed, g_postpublish_config), 0);
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--local", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "before-publish-race\n");
    CHECK_EQ_INT(git_get_file_all(replacement_config, "audit.replacement",
                                  actual, sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "must-survive\n");

    fixture_cleanup(&fixture);
}

static int prepare_finalization_transaction(const char *post_name) {
    if (git_config_snapshot(GIT_SCOPE_GLOBAL) != 0 ||
        git_set_config_value(GIT_CONFIG_USER_NAME, post_name,
                             GIT_SCOPE_GLOBAL) != 0 ||
        git_config_seal() != 0) {
        return -1;
    }
    return 0;
}

static int install_git_fd_sentinel(int stale_fd, int minimum);

static void fork_coverage_child_return(void) {
    /* The child must reach normal process exit for gcov to flush, but it must
     * not run the harness's inherited atexit sweep over the parent's fixture.
     * Release only the child copies of the tracking allocations and pinned
     * root descriptors; main observes the flag immediately after the one fork
     * test returns. */
    for (int i = 0; i < ts_tmpdir_count; i++) {
        if (ts_tmpdirs[i].root_fd >= 0) close(ts_tmpdirs[i].root_fd);
        free(ts_tmpdirs[i].path);
        memset(&ts_tmpdirs[i], 0, sizeof(ts_tmpdirs[i]));
        ts_tmpdirs[i].root_fd = -1;
    }
    ts_tmpdir_count = 0;
    g_fork_coverage_child = true;
}

static bool fd_has_identity(int fd, const struct stat *expected) {
    struct stat observed;

    return fd >= 0 && expected && fstat(fd, &observed) == 0 &&
           observed.st_dev == expected->st_dev &&
           observed.st_ino == expected->st_ino;
}

static pid_t fork_with_atfork_coverage(void) {
    /* GCC recognizes direct fork() calls and resets the child's counters
     * after fork returns. pthread_atfork child handlers run before that reset,
     * making their genuine execution invisible even when the child exits
     * normally. An indirect libc fork remains a real pthread_atfork-aware
     * fork, while the parent waits for the child before either writes gcda. */
    pid_t (*volatile call_fork)(void) = fork;

    return call_fork();
}

static int prepare_descriptor_only_retirement(
    const git_fixture_t *fixture, account_t *account,
    publication_record_t *publication,
    git_retirement_transaction_t **transaction) {
    static const char incarnation[] =
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF";
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    char config_path[MAX_PATH_LEN];
    struct stat parent_stat;
    struct stat config_stat;

    if (!fixture || !account || !publication || !transaction ||
        safe_snprintf(config_path, sizeof(config_path),
                      "%s/retirement.gitconfig", fixture->base) != 0 ||
        write_text_file(config_path, "[fixture]\n\tmarker = retired\n",
                        0600) != 0 ||
        stat(config_path, &config_stat) != 0 ||
        unlink(config_path) != 0 ||
        stat(fixture->base, &parent_stat) != 0) {
        return -1;
    }

    memset(account, 0, sizeof(*account));
    account->id = UINT32_C(808);
    account->incarnation_persisted = true;
    if (safe_strncpy(account->incarnation, incarnation,
                     sizeof(account->incarnation)) != 0) {
        return -1;
    }

    publication_record_init(publication);
    publication->account_id = account->id;
    publication->scope = PUBLICATION_SCOPE_GLOBAL;
    publication->state = PUBLICATION_STATE_PUBLISHED;
    /* An absent recorded destination has no credential mutation to plan, but
     * retirement must retain its exact parent and canonical lock lease until
     * settlement. That makes the descriptor contract platform-independent;
     * a present publication with no attributable values may settle eagerly. */
    publication->capabilities = PUBLICATION_CAP_DESTINATION |
                                PUBLICATION_CAP_POST_GENERATION;
    if (safe_strncpy(publication->account_incarnation, incarnation,
                     sizeof(publication->account_incarnation)) != 0 ||
        safe_strncpy(publication->config_path, config_path,
                     sizeof(publication->config_path)) != 0) {
        return -1;
    }
    publication_identity_from_stat(&publication->config_parent,
                                   &parent_stat);
    publication_identity_from_stat(&publication->post_config,
                                   &config_stat);
    if (publication_record_validate(publication) != 0) return -1;

    accounts[0] = account;
    publications[0] = publication;
    return git_retirement_transaction_prepare(
        accounts, publications, 1U, transaction);
}

TEST(fork_child_with_empty_git_registry_preserves_unrelated_descriptor) {
    git_fixture_t fixture;
    struct stat identity;
    int unrelated_fd = -1;
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    git_config_commit();
    unrelated_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(unrelated_fd >= 0);
    CHECK(unrelated_fd >= 0 && fstat(unrelated_fd, &identity) == 0);
    CHECK_EQ_INT(fflush(NULL), 0);

    child = fork_with_atfork_coverage();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(fd_has_identity(unrelated_fd, &identity));
        if (unrelated_fd >= 0) close(unrelated_fd);
        fixture_cleanup(&fixture);
        fork_coverage_child_return();
        return;
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if (unrelated_fd >= 0) close(unrelated_fd);
    fixture_cleanup(&fixture);
}

TEST(fork_child_identity_gate_preserves_parent_reused_snapshot_descriptor) {
    git_fixture_t fixture;
    int inherited[9];
    size_t inherited_count;
    int replacement = -1;
    struct stat replacement_identity;
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    inherited_count = git_ops_test_snapshot_descriptors(
        inherited, sizeof(inherited) / sizeof(inherited[0]));
    CHECK(inherited_count > 0U);
    if (inherited_count == 0U) {
        git_config_commit();
        fixture_cleanup(&fixture);
        return;
    }

    CHECK_EQ_INT(close(inherited[0]), 0);
    replacement = install_git_fd_sentinel(inherited[0],
                                           inherited[0] + 1);
    CHECK(replacement > inherited[0]);
    CHECK(replacement > inherited[0] &&
          fstat(inherited[0], &replacement_identity) == 0);
    CHECK_EQ_INT(fflush(NULL), 0);

    child = fork_with_atfork_coverage();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(fd_has_identity(inherited[0], &replacement_identity));
        close(inherited[0]);
        if (replacement >= 0) close(replacement);
        fixture_cleanup(&fixture);
        fork_coverage_child_return();
        return;
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(fd_has_identity(inherited[0], &replacement_identity));
    git_config_commit();
    close(inherited[0]);
    if (replacement >= 0) close(replacement);
    fixture_cleanup(&fixture);
}

TEST(fork_child_closes_active_snapshot_finalizer_and_retirement_descriptors) {
    git_fixture_t fixture;
    account_t retirement_account;
    publication_record_t retirement_publication;
    git_retirement_transaction_t *retirement = NULL;
    git_config_finalization_t *finalization = NULL;
    int snapshot_fds[9];
    int finalization_fds[6];
    int retirement_fds[16];
    size_t snapshot_count;
    size_t finalization_count;
    size_t retirement_count;
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(prepare_descriptor_only_retirement(
                     &fixture, &retirement_account,
                     &retirement_publication, &retirement), 0);
    CHECK(retirement != NULL);
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-combined-fork-cleanup"), 0);
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "combined-fork-cleanup-postimage"), 0);
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    CHECK(finalization != NULL);

    snapshot_count = git_ops_test_snapshot_descriptors(
        snapshot_fds, sizeof(snapshot_fds) / sizeof(snapshot_fds[0]));
    finalization_count = git_ops_test_finalization_descriptors(
        finalization, finalization_fds,
        sizeof(finalization_fds) / sizeof(finalization_fds[0]));
    retirement_count = git_ops_test_retirement_transaction_descriptors(
        retirement, retirement_fds,
        sizeof(retirement_fds) / sizeof(retirement_fds[0]));
    CHECK(snapshot_count > 0U &&
          snapshot_count <= sizeof(snapshot_fds) / sizeof(snapshot_fds[0]));
    CHECK(finalization_count > 0U &&
          finalization_count <=
              sizeof(finalization_fds) / sizeof(finalization_fds[0]));
    CHECK(retirement_count > 0U &&
          retirement_count <=
              sizeof(retirement_fds) / sizeof(retirement_fds[0]));
    CHECK_EQ_INT(fflush(NULL), 0);

    child = fork_with_atfork_coverage();
    CHECK(child >= 0);
    if (child == 0) {
        for (size_t i = 0U; i < snapshot_count; i++) {
            errno = 0;
            CHECK(fcntl(snapshot_fds[i], F_GETFD) == -1 &&
                  errno == EBADF);
        }
        for (size_t i = 0U; i < finalization_count; i++) {
            errno = 0;
            CHECK(fcntl(finalization_fds[i], F_GETFD) == -1 &&
                  errno == EBADF);
        }
        for (size_t i = 0U; i < retirement_count; i++) {
            errno = 0;
            CHECK(fcntl(retirement_fds[i], F_GETFD) == -1 &&
                  errno == EBADF);
        }
        errno = 0;
        CHECK(git_config_finalization_end(&finalization) == -1 &&
              finalization == NULL && errno == EINVAL);
        errno = 0;
        CHECK(git_retirement_transaction_commit(&retirement) == -1 &&
              retirement == NULL && errno == EINVAL);
        fixture_cleanup(&fixture);
        fork_coverage_child_return();
        return;
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK_EQ_INT(git_config_finalization_end(&finalization), 0);
    git_config_commit();
    CHECK_EQ_INT(git_retirement_transaction_commit(&retirement), 0);
    fixture_cleanup(&fixture);
}

TEST(fork_child_cannot_use_parent_snapshot_and_can_start_fresh) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    char actual[256];
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "parent-before-snapshot"), 0);
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "parent-sealed-postimage"), 0);

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (git_config_restore() != -1) _exit(90);
        if (git_config_finalization_begin(&finalization) != -1 ||
            finalization != NULL) {
            _exit(91);
        }
        if (git_set_config_value(
                GIT_CONFIG_USER_NAME, "forbidden-child-write",
                GIT_SCOPE_GLOBAL) != -1) {
            _exit(92);
        }
        if (git_unset_config_value(
                GIT_CONFIG_USER_NAME, GIT_SCOPE_GLOBAL) != -1) {
            _exit(93);
        }
        if (git_clear_config(GIT_SCOPE_GLOBAL) != -1) _exit(94);
        git_config_commit();
        if (git_config_snapshot(GIT_SCOPE_GLOBAL) != 0) _exit(95);
        git_config_commit();
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "parent-sealed-postimage\n");
    CHECK_EQ_INT(git_config_restore(), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "parent-before-snapshot\n");

    fixture_cleanup(&fixture);
}

static int install_git_fd_sentinel(int stale_fd, int minimum) {
    int source;
    int sentinel;

    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0) return -1;
#ifdef F_DUPFD_CLOEXEC
    sentinel = fcntl(source, F_DUPFD_CLOEXEC, minimum);
#else
    sentinel = fcntl(source, F_DUPFD, minimum);
    if (sentinel >= 0 &&
        fcntl(sentinel, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;

        close(sentinel);
        sentinel = -1;
        errno = saved_errno;
    }
#endif
    close(source);
    if (sentinel < minimum ||
        dup2(sentinel, stale_fd) != stale_fd) {
        if (sentinel >= 0) close(sentinel);
        return -1;
    }
    return sentinel;
}

TEST(fork_child_abandon_preserves_reused_snapshot_descriptors) {
    git_fixture_t fixture;
    int inherited[9];
    size_t inherited_count;
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "parent-before-fd-reuse"), 0);
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "parent-postimage-before-fd-reuse"), 0);
    inherited_count = git_ops_test_snapshot_descriptors(
        inherited, sizeof(inherited) / sizeof(inherited[0]));
    CHECK(inherited_count > 0U);
    CHECK(inherited_count <=
          sizeof(inherited) / sizeof(inherited[0]));

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int replacements[9];
        int minimum = 0;

        if (inherited_count == 0U ||
            inherited_count >
                sizeof(inherited) / sizeof(inherited[0])) {
            _exit(96);
        }
        for (size_t i = 0U; i < inherited_count; i++) {
            if (inherited[i] >= minimum) minimum = inherited[i] + 1;
        }
        for (size_t i = 0U; i < inherited_count; i++) {
            errno = 0;
            if (fcntl(inherited[i], F_GETFD) != -1 ||
                errno != EBADF) {
                _exit(97);
            }
            replacements[i] =
                install_git_fd_sentinel(inherited[i], minimum);
            if (replacements[i] < minimum) _exit(97);
            minimum = replacements[i] + 1;
        }
        git_config_commit();
        for (size_t i = 0U; i < inherited_count; i++) {
            if (fcntl(inherited[i], F_GETFD) < 0) _exit(98);
            close(inherited[i]);
            close(replacements[i]);
        }
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK_EQ_INT(git_config_restore(), 0);
    fixture_cleanup(&fixture);
}

TEST(finalization_sigkill_leaves_complete_self_healing_certificate) {
    static const char marker_magic[] = "gitswitch-recovery-v1 ";
    git_fixture_t fixture;
    struct stat marker_stat;
    char marker[1024];
    char actual[256];
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-kill"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        git_config_finalization_t *finalization = NULL;

        git_ops_test_reset_caches();
        if (prepare_finalization_transaction("published-before-kill") != 0) {
            _exit(80);
        }
        (void)git_ops_test_set_finalization_hook(
            kill_after_finalization_certificate_publish);
        if (git_config_finalization_begin(&finalization) != 0) {
            _exit(81);
        }
        _exit(82);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 86);
    }
    CHECK_EQ_INT(lstat(g_finalization_lock_path, &marker_stat), 0);
    CHECK(S_ISREG(marker_stat.st_mode));
    CHECK(marker_stat.st_nlink == 1 || marker_stat.st_nlink == 2);
    CHECK_EQ_INT(marker_stat.st_uid, geteuid());
    CHECK_EQ_INT(marker_stat.st_mode & 07777, 0600);
    CHECK(marker_stat.st_size > 0);
    CHECK_EQ_INT(read_file(g_finalization_lock_path, marker,
                           sizeof(marker)), 0);
    CHECK(strncmp(marker, marker_magic, strlen(marker_magic)) == 0);

    /* This process did not inherit the child's transaction or descriptors.
     * Its first managed write must claim the strict certificate, retire any
     * portable hard-link alias, and retry through real Git. */
    git_ops_test_reset_caches();
    CHECK_EQ_INT(git_set_config_value(
                     GIT_CONFIG_USER_NAME, "after-kill-recovery",
                     GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "after-kill-recovery\n");
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &marker_stat) != 0 &&
          errno == ENOENT);
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 0);

    fixture_cleanup(&fixture);
}

TEST(private_prepublication_sigkill_is_reconciled_exactly) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    char foreign_private[MAX_PATH_LEN];
    char contents[256];
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-private-kill"), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        git_ops_test_reset_caches();
        if (prepare_finalization_transaction(
                "private-before-kill") != 0) {
            _exit(83);
        }
        (void)git_ops_test_set_finalization_hook(
            kill_after_private_finalization_certificate_prepare);
        if (git_config_finalization_begin(&finalization) != 0) {
            _exit(84);
        }
        _exit(85);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 87);
    }
    CHECK((size_t)snprintf(
              foreign_private, sizeof(foreign_private),
              "%s/.gitswitch-finalization-999-1",
              fixture.base) < sizeof(foreign_private));
    CHECK_EQ_INT(write_text_file(
                     foreign_private, "foreign-private-marker\n", 0600), 0);
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 2);

    git_ops_test_reset_caches();
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "private-orphan-reconciled"), 0);
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 1);
    CHECK_EQ_INT(read_file(foreign_private, contents, sizeof(contents)), 0);
    CHECK_STR_EQ(contents, "foreign-private-marker\n");
    CHECK_EQ_INT(git_config_finalization_end(&finalization), 0);
    CHECK(finalization == NULL);
    git_config_commit();
    CHECK_EQ_INT(unlink(foreign_private), 0);

    fixture_cleanup(&fixture);
}

TEST(private_prepare_interruption_cleans_unpublished_certificate) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    struct stat named;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-private-interruption"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "private-interruption-postimage"), 0);

    (void)git_ops_test_set_finalization_hook(
        fail_after_private_finalization_certificate_prepare);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), -1);
    CHECK(finalization == NULL);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK(strstr(get_last_error()->message,
                 "Injected private Git finalization-certificate "
                 "interruption") != NULL);
    (void)git_ops_test_set_finalization_hook(NULL);

    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 0);
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &named) != 0 &&
          errno == ENOENT);

    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    CHECK(finalization != NULL);
    CHECK_EQ_INT(git_config_finalization_end(&finalization), 0);
    CHECK(finalization == NULL);
    git_config_commit();
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 0);
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &named) != 0 &&
          errno == ENOENT);

    fixture_cleanup(&fixture);
}

TEST(finalization_arena_exhaustion_precedes_private_and_canonical_creation) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    size_t previous_capacity;
    struct stat named;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-finalization-capacity"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "finalization-capacity-postimage"), 0);
    previous_capacity = git_ops_test_set_cleanup_arena_capacity(1U);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), -1);
    CHECK(finalization == NULL);
    CHECK_EQ_INT(errno, ENOSPC);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message,
                 "exhausted before finalization mutation") != NULL);
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &named) != 0 &&
          errno == ENOENT);
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 0);
    (void)git_ops_test_set_cleanup_arena_capacity(previous_capacity);
    git_config_commit();

    fixture_cleanup(&fixture);
}

TEST(finalization_release_failure_consumes_handle_and_self_heals) {
    static const char marker_magic[] = "gitswitch-recovery-v1 ";
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    struct stat marker_stat;
    char marker[1024];
    char actual[256];
    int descriptors_before;
    int descriptors_after;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name", "before-release-fail"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "release-failure-postimage"), 0);
    descriptors_before = count_open_descriptors();
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    CHECK(finalization != NULL);
    g_finalization_hook_calls = 0;
    (void)git_ops_test_set_finalization_hook(
        fail_finalization_release_once);
    CHECK_EQ_INT(git_config_finalization_end(&finalization), -1);
    CHECK(finalization == NULL);
    (void)git_ops_test_set_finalization_hook(NULL);
    descriptors_after = count_open_descriptors();
    if (descriptors_before >= 0 && descriptors_after >= 0) {
        CHECK_EQ_INT(descriptors_after, descriptors_before);
    }
    CHECK_EQ_INT(read_file(g_finalization_lock_path, marker,
                           sizeof(marker)), 0);
    CHECK(strncmp(marker, marker_magic, strlen(marker_magic)) == 0);

    /* Committing the sealed transaction models accounts.c's irreversible
     * boundary. The consumed lease left no in-process fcntl claim, so the same
     * process can immediately recover on its next managed write. */
    git_config_commit();
    CHECK_EQ_INT(git_set_config_value(
                     GIT_CONFIG_USER_NAME, "same-process-recovery",
                     GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_get_all("--global", "user.name", actual,
                             sizeof(actual)), 0);
    CHECK_STR_EQ(actual, "same-process-recovery\n");
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &marker_stat) != 0 &&
          errno == ENOENT);
    CHECK_EQ_INT((long)count_finalization_private_aliases(fixture.base), 0);

    fixture_cleanup(&fixture);
}

TEST(forked_child_finalization_end_is_descriptor_only) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    int inherited[6];
    size_t inherited_count;
    struct stat before;
    struct stat after;
    char marker_before[1024];
    char marker_after[1024];
    pid_t child;
    int status = 0;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-forked-finalization-end"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "forked-finalization-postimage"), 0);
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    CHECK(finalization != NULL);
    inherited_count = git_ops_test_finalization_descriptors(
        finalization, inherited,
        sizeof(inherited) / sizeof(inherited[0]));
    CHECK(inherited_count > 0U);
    CHECK(inherited_count <=
          sizeof(inherited) / sizeof(inherited[0]));
    CHECK_EQ_INT(lstat(g_finalization_lock_path, &before), 0);
    CHECK_EQ_INT(read_file(g_finalization_lock_path, marker_before,
                           sizeof(marker_before)), 0);

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int replacements[6];
        struct stat replacement_identity[6];
        int minimum = 0;

        if (inherited_count == 0U ||
            inherited_count >
                sizeof(inherited) / sizeof(inherited[0])) {
            _exit(87);
        }
        for (size_t i = 0U; i < inherited_count; i++) {
            if (inherited[i] >= minimum) minimum = inherited[i] + 1;
        }
        for (size_t i = 0U; i < inherited_count; i++) {
            errno = 0;
            if (fcntl(inherited[i], F_GETFD) != -1 ||
                errno != EBADF) {
                _exit(89);
            }
            replacements[i] =
                install_git_fd_sentinel(inherited[i], minimum);
            if (replacements[i] < minimum ||
                fstat(replacements[i], &replacement_identity[i]) != 0 ||
                fstat(inherited[i], &replacement_identity[i]) != 0) {
                _exit(89);
            }
            minimum = replacements[i] + 1;
        }
        clear_error();
        errno = 0;
        if (git_config_finalization_end(&finalization) != -1 ||
            finalization != NULL || errno != EINVAL ||
            get_last_error()->code != ERR_INVALID_ARGS) {
            _exit(88);
        }
        for (size_t i = 0U; i < inherited_count; i++) {
            struct stat retained;

            if (fcntl(inherited[i], F_GETFD) < 0 ||
                fstat(inherited[i], &retained) != 0 ||
                retained.st_dev != replacement_identity[i].st_dev ||
                retained.st_ino != replacement_identity[i].st_ino) {
                _exit(90);
            }
            close(inherited[i]);
            close(replacements[i]);
        }
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(g_finalization_lock_path, &after), 0);
    CHECK(before.st_dev == after.st_dev);
    CHECK(before.st_ino == after.st_ino);
    CHECK_EQ_INT(read_file(g_finalization_lock_path, marker_after,
                           sizeof(marker_after)), 0);
    CHECK_STR_EQ(marker_after, marker_before);
    CHECK_EQ_INT(git_config_finalization_end(&finalization), 0);
    CHECK(finalization == NULL);
    errno = 0;
    CHECK(lstat(g_finalization_lock_path, &after) != 0 &&
          errno == ENOENT);
    git_config_commit();

    fixture_cleanup(&fixture);
}

TEST(finalization_release_preserves_foreign_replacement) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    unsigned char contents[sizeof(g_foreign_finalization_bytes)];
    char config_before[4096];
    char config_after[4096];
    char value[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-foreign-release"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "foreign-release-postimage"), 0);
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    g_finalization_hook_calls = 0;
    (void)git_ops_test_set_finalization_hook(
        replace_finalization_certificate_with_foreign_lock);
    CHECK_EQ_INT(git_config_finalization_end(&finalization), -1);
    CHECK(finalization == NULL);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message,
                 "foreign namespace entry was preserved") != NULL);
    (void)git_ops_test_set_finalization_hook(NULL);
    CHECK_EQ_INT(read_binary_file_exact(
                     g_finalization_lock_path, contents,
                     sizeof(contents)), 0);
    CHECK(memcmp(contents, g_foreign_finalization_bytes,
                 sizeof(contents)) == 0);
    git_config_commit();
    CHECK_EQ_INT(read_file(fixture.global_config, config_before,
                           sizeof(config_before)), 0);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_set_config_value(
                     GIT_CONFIG_USER_NAME, "must-not-overwrite-lock",
                     GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, EEXIST);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(get_last_error()->system_errno, 0);
    CHECK_STR_EQ(get_last_error()->function,
                 "git_recover_scope_finalization_marker");
    CHECK_STR_EQ(
        get_last_error()->message,
        "Existing Git configuration lock is not an exact recoverable "
        "gitswitch certificate");
    CHECK(strstr(get_last_error()->message,
                 "Failed to set git config") == NULL);
    CHECK_EQ_INT(read_binary_file_exact(
                     g_finalization_lock_path, contents,
                     sizeof(contents)), 0);
    CHECK(memcmp(contents, g_foreign_finalization_bytes,
                 sizeof(contents)) == 0);
    CHECK_EQ_INT(read_file(fixture.global_config, config_after,
                           sizeof(config_after)), 0);
    CHECK_STR_EQ(config_after, config_before);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_unset_config_value(
                     GIT_CONFIG_USER_NAME, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(errno, EEXIST);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_EQ_INT(get_last_error()->system_errno, 0);
    CHECK_STR_EQ(get_last_error()->function,
                 "git_recover_scope_finalization_marker");
    CHECK_STR_EQ(
        get_last_error()->message,
        "Existing Git configuration lock is not an exact recoverable "
        "gitswitch certificate");
    CHECK(strstr(get_last_error()->message,
                 "Failed to unset git config") == NULL);
    CHECK_EQ_INT(read_binary_file_exact(
                     g_finalization_lock_path, contents,
                     sizeof(contents)), 0);
    CHECK(memcmp(contents, g_foreign_finalization_bytes,
                 sizeof(contents)) == 0);
    CHECK_EQ_INT(read_file(fixture.global_config, config_after,
                           sizeof(config_after)), 0);
    CHECK_STR_EQ(config_after, config_before);

    CHECK_EQ_INT(unlink(g_finalization_lock_path), 0);
    /* Both failures must leave the scalar cache uncertain. A later corrective
     * set and unset therefore execute instead of being elided by stale state. */
    CHECK_EQ_INT(git_set_config_value(
                     GIT_CONFIG_USER_NAME, "cache-retry-set",
                     GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_get_all("--global", GIT_CONFIG_USER_NAME,
                             value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "cache-retry-set\n");
    CHECK_EQ_INT(git_set("--global", GIT_CONFIG_USER_NAME,
                         "external-before-retry-unset"), 0);
    CHECK_EQ_INT(git_unset_config_value(
                     GIT_CONFIG_USER_NAME, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_get_all("--global", GIT_CONFIG_USER_NAME,
                             value, sizeof(value)), -1);

    fixture_cleanup(&fixture);
}

TEST(finalization_postunlink_retry_never_removes_later_foreign_lock) {
    git_fixture_t fixture;
    git_config_finalization_t *finalization = NULL;
    char contents[256];

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(git_set("--global", "user.name",
                         "before-postunlink-fail"), 0);
    CHECK((size_t)snprintf(
              g_finalization_lock_path,
              sizeof(g_finalization_lock_path), "%s.lock",
              fixture.global_config) < sizeof(g_finalization_lock_path));
    CHECK_EQ_INT(prepare_finalization_transaction(
                     "postunlink-failure-postimage"), 0);
    CHECK_EQ_INT(git_config_finalization_begin(&finalization), 0);
    g_finalization_hook_calls = 0;
    (void)git_ops_test_set_finalization_hook(
        fail_finalization_release_sync_once);
    CHECK_EQ_INT(git_config_finalization_end(&finalization), -1);
    CHECK(finalization == NULL);
    (void)git_ops_test_set_finalization_hook(NULL);
    CHECK_EQ_INT(write_text_file(g_finalization_lock_path,
                                 "foreign-after-unlink\n", 0600), 0);
    CHECK_EQ_INT(read_file(g_finalization_lock_path, contents,
                           sizeof(contents)), 0);
    CHECK_STR_EQ(contents, "foreign-after-unlink\n");
    CHECK_EQ_INT(unlink(g_finalization_lock_path), 0);
    git_config_commit();

    fixture_cleanup(&fixture);
}

TEST(snapshot_commit_releases_all_generation_descriptors) {
    git_fixture_t fixture;
    int before;
    int after;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    before = count_open_descriptors();
    for (int iteration = 0; iteration < 32; iteration++) {
        CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
        CHECK_EQ_INT(git_config_seal(), 0);
        git_config_commit();
    }
    after = count_open_descriptors();
    if (before >= 0 && after >= 0) CHECK_EQ_INT(after, before);

    fixture_cleanup(&fixture);
}

static void check_metadata_mismatch_errno(
    git_metadata_test_stage_t stage) {
    git_fixture_t fixture;
    git_metadata_test_hook_fn previous;
    bool hook_installed = false;
    int setup_rc;
    int restore_rc;
    int restore_errno;

    if (!fixture_init(&fixture)) {
        CHECK(false);
        fixture_cleanup(&fixture);
        return;
    }
    setup_rc = git_set("--local", "user.name", "before-mismatch");
    CHECK_EQ_INT(setup_rc, 0);
    if (setup_rc != 0) goto cleanup;
    setup_rc = git_config_snapshot(GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(setup_rc, 0);
    if (setup_rc != 0) goto cleanup;
    setup_rc = git_set_config_value("user.name", "owned-postimage",
                                    GIT_SCOPE_LOCAL);
    CHECK_EQ_INT(setup_rc, 0);
    if (setup_rc != 0) goto cleanup;

    /* These seams are restore-time metadata checks. Rollback before sealing is
     * a supported partial-write failure path and isolates the exact branches
     * from an unrelated real-Git post-image read. */

    g_metadata_mismatch_stage = stage;
    g_metadata_mismatch_calls = 0;
    memset(g_metadata_trace, 0, sizeof(g_metadata_trace));
    g_metadata_trace_count = 0;
    previous = git_ops_test_set_metadata_hook(force_git_metadata_mismatch);
    hook_installed = true;
    clear_error();
    restore_rc = git_config_restore();
    restore_errno = errno;
    git_ops_test_set_metadata_hook(previous);
    hook_installed = false;

    CHECK_EQ_INT(restore_rc, -1);
    CHECK_EQ_INT(g_metadata_mismatch_calls, 1);
    CHECK_EQ_INT(restore_errno, EAGAIN);
    if (stage == GIT_METADATA_TEST_SOURCE_PIN) {
        CHECK_EQ_INT(g_metadata_trace_count, 1);
        if (g_metadata_trace_count >= 1) {
            CHECK_EQ_INT(g_metadata_trace[0], GIT_METADATA_TEST_SOURCE_PIN);
        }
    } else {
        CHECK_EQ_INT(g_metadata_trace_count, 2);
        if (g_metadata_trace_count >= 1) {
            CHECK_EQ_INT(g_metadata_trace[0], GIT_METADATA_TEST_SOURCE_PIN);
        }
        if (g_metadata_trace_count >= 2) {
            CHECK_EQ_INT(g_metadata_trace[1],
                         GIT_METADATA_TEST_STAGE_REVALIDATE);
        }
    }

cleanup:
    if (hook_installed) git_ops_test_set_metadata_hook(previous);
    git_config_commit();
    fixture_cleanup(&fixture);
    ts_rm_rf(fixture.base);
}

TEST(metadata_mismatches_use_stable_eagain_diagnostics) {
    check_metadata_mismatch_errno(GIT_METADATA_TEST_SOURCE_PIN);
    check_metadata_mismatch_errno(GIT_METADATA_TEST_STAGE_REVALIDATE);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    if (getenv("GITSWITCH_AR08_CONFLICT_RETRY_ONLY")) {
        RUN_TEST(conflict_retry_never_rebases_onto_unrelated_same_path_generation);
        return ts_test_finish();
    }
    RUN_TEST(fork_child_with_empty_git_registry_preserves_unrelated_descriptor);
    if (g_fork_coverage_child) return ts_test_finish();
    RUN_TEST(fork_child_identity_gate_preserves_parent_reused_snapshot_descriptor);
    if (g_fork_coverage_child) return ts_test_finish();
    RUN_TEST(fork_child_closes_active_snapshot_finalizer_and_retirement_descriptors);
    if (g_fork_coverage_child) return ts_test_finish();
    RUN_TEST(conflict_retry_never_rebases_onto_unrelated_same_path_generation);
    RUN_TEST(real_git_proves_narrow_ssh_environment_precedence_and_api_rejects_it);
    RUN_TEST(managed_command_scope_overrides_are_rejected_before_snapshot);
    RUN_TEST(late_command_override_is_rejected_at_account_writer_boundary);
    RUN_TEST(post_write_command_override_fails_merged_proof_and_restores_exactly);
    RUN_TEST(all_gpg_format_and_program_keys_normalize_and_restore_exactly);
    RUN_TEST(large_unrelated_config_allows_snapshot_switch_status_and_rollback);
    RUN_TEST(rollback_preserves_concurrent_ordered_vectors_in_every_managed_scope);
    RUN_TEST(writer_in_old_compare_write_gap_is_rechecked_under_canonical_lock);
    RUN_TEST(real_git_writer_is_serialized_after_in_lock_ownership_read);
    RUN_TEST(ctime_only_drift_under_restore_lock_keeps_exact_generation_owned);
    RUN_TEST(persistent_hardlink_under_restore_lock_invalidates_generation);
    RUN_TEST(same_metadata_content_rewrite_under_restore_lock_is_rejected);
    RUN_TEST(global_xdg_write_target_is_locked_and_restored_exactly);
    RUN_TEST(config_and_parent_symlinks_keep_identity_while_targets_restore);
    RUN_TEST(maximum_git_lock_basename_uses_short_staging_name);
    RUN_TEST(partial_retry_skips_completed_scopes_and_preserves_their_later_changes);
    RUN_TEST(preseal_writer_is_rejected_and_never_laundered_into_rollback_ownership);
    RUN_TEST(enabled_empty_worktree_scope_rejects_preseal_writer);
    RUN_TEST(enabled_empty_worktree_scope_preserves_postseal_writer);
    RUN_TEST(direct_worktree_extension_true_ignores_later_included_false);
    RUN_TEST(direct_worktree_extension_false_ignores_later_included_true);
    RUN_TEST(committed_git_transaction_discards_rollback_ownership);
    RUN_TEST(worktree_probe_has_a_truthful_hard_bound_before_mutation);
    RUN_TEST(git_list_config_never_returns_a_successful_prefix);
    RUN_TEST(replaced_repository_with_identical_managed_vectors_is_never_rolled_back);
    RUN_TEST(replaced_config_namespace_with_identical_vectors_is_never_rolled_back);
    RUN_TEST(replaced_config_file_with_identical_vectors_is_never_rolled_back);
    RUN_TEST(replaced_config_file_with_one_conflict_is_never_partially_rebased);
    RUN_TEST(postpublish_path_race_retains_the_installed_generation_for_retry);
    RUN_TEST(fork_child_cannot_use_parent_snapshot_and_can_start_fresh);
    RUN_TEST(fork_child_abandon_preserves_reused_snapshot_descriptors);
    RUN_TEST(finalization_sigkill_leaves_complete_self_healing_certificate);
    RUN_TEST(private_prepublication_sigkill_is_reconciled_exactly);
    RUN_TEST(private_prepare_interruption_cleans_unpublished_certificate);
    RUN_TEST(finalization_arena_exhaustion_precedes_private_and_canonical_creation);
    RUN_TEST(finalization_release_failure_consumes_handle_and_self_heals);
    RUN_TEST(forked_child_finalization_end_is_descriptor_only);
    RUN_TEST(finalization_release_preserves_foreign_replacement);
    RUN_TEST(finalization_postunlink_retry_never_removes_later_foreign_lock);
    RUN_TEST(snapshot_commit_releases_all_generation_descriptors);
    RUN_TEST(metadata_mismatches_use_stable_eagain_diagnostics);
TEST_MAIN_END()
