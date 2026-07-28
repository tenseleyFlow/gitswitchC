/* AR-11 M10: retirement follows every exact recorded Git destination. */
#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "utils.h"

#define M10_INCARNATION \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define M10_FINGERPRINT \
    "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define M10_FOREIGN_FINGERPRINT \
    "9999888877776666555544440000111122223333"
#define M10_FOREIGN_BEFORE_FINGERPRINT \
    "111122223333444455556666777788889999AAAA"
#define M10_FOREIGN_AFTER_FINGERPRINT \
    "BBBBCCCCDDDDEEEEFFFF00001111222233334444"
#define M10_SELECTOR "22223333"
#define M10_VALUE_CAPACITY 4U

void git_ops_test_reset_caches(void);

enum m10_key_index {
    M10_SIGNING_KEY = 0,
    M10_SIGNING_ENABLED,
    M10_GPG_FORMAT,
    M10_GPG_PROGRAM,
    M10_KEY_COUNT
};

static const char *const m10_keys[M10_KEY_COUNT] = {
    GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM
};

typedef struct {
    char path[MAX_PATH_LEN];
    char values[M10_KEY_COUNT][M10_VALUE_CAPACITY][MAX_PATH_LEN];
    size_t value_count[M10_KEY_COUNT];
    bool fail_unset[M10_KEY_COUNT];
    size_t gets;
    size_t unsets;
} m10_destination_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char original_cwd[MAX_PATH_LEN];
    char state_dir[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char repo_a[MAX_PATH_LEN];
    char repo_a_git[MAX_PATH_LEN];
    char repo_a_local[MAX_PATH_LEN];
    char repo_a_worktree[MAX_PATH_LEN];
    char repo_b[MAX_PATH_LEN];
    char repo_b_git[MAX_PATH_LEN];
    char repo_b_local[MAX_PATH_LEN];
    char program[MAX_PATH_LEN];
    gitswitch_ctx_t ctx;
    publication_record_t records[3];
    size_t record_count;
} m10_fixture_t;

static m10_destination_t m10_destinations[3];
static size_t m10_destination_count;
static size_t m10_runner_calls;
static bool m10_saw_scope_flag;
static bool m10_saw_rev_parse;
static bool m10_saw_unknown_path;
static bool m10_first_git_saw_preflight_failure;
static bool m10_fail_stale_stage_snapshot;

static unsigned char m10_status_listing[4096];
static size_t m10_status_listing_length;
static char m10_status_repository[MAX_PATH_LEN];

typedef struct {
    char *value;
    bool present;
} m10_saved_env_t;

static m10_saved_env_t m10_save_env(const char *name) {
    const char *value = getenv(name);
    m10_saved_env_t saved = {NULL, value != NULL};

    if (value) saved.value = strdup(value);
    return saved;
}

static void m10_restore_env(const char *name, m10_saved_env_t *saved) {
    if (saved->present && saved->value) {
        (void)setenv(name, saved->value, 1);
    } else {
        (void)unsetenv(name);
    }
    free(saved->value);
    saved->value = NULL;
}

static int m10_write_all(int fd, const char *contents, size_t length) {
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);

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

static int m10_write_file(const char *path, const char *contents) {
    int fd;
    size_t length;

    if (!path || !contents) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    length = strlen(contents);
    if (m10_write_all(fd, contents, length) != 0 || fsync(fd) != 0) {
        (void)close(fd);
        return -1;
    }
    return close(fd);
}

static int m10_make_dir(const char *path) {
    return mkdir(path, 0700);
}

static void m10_fixture_cleanup(m10_fixture_t *fixture) {
    if (!fixture) return;
    if (fixture->original_cwd[0] != '\0') {
        if (chdir(fixture->original_cwd) != 0) return;
    }
    if (fixture->root[0] != '\0') ts_rm_rf(fixture->root);
}

static int m10_parent_path(const char *path, char *parent,
                           size_t parent_size) {
    char *slash;

    if (safe_strncpy(parent, path, parent_size) != 0) return -1;
    slash = strrchr(parent, '/');
    if (!slash || slash == parent) return -1;
    *slash = '\0';
    return 0;
}

static int m10_make_record(publication_record_t *record,
                           const m10_fixture_t *fixture,
                           publication_scope_t scope,
                           const char *config_path,
                           const char *repository_path) {
    char parent[MAX_PATH_LEN];
    struct stat st;

    publication_record_init(record);
    record->account_id = UINT32_C(41);
    if (safe_strncpy(record->account_incarnation, M10_INCARNATION,
                     sizeof(record->account_incarnation)) != 0 ||
        safe_strncpy(record->config_path, config_path,
                     sizeof(record->config_path)) != 0 ||
        m10_parent_path(config_path, parent, sizeof(parent)) != 0 ||
        stat(parent, &st) != 0) {
        return -1;
    }
    record->scope = scope;
    publication_identity_from_stat(&record->config_parent, &st);
    if (scope != PUBLICATION_SCOPE_GLOBAL) {
        if (!repository_path ||
            safe_strncpy(record->repository_path, repository_path,
                         sizeof(record->repository_path)) != 0 ||
            stat(repository_path, &st) != 0) {
            return -1;
        }
        publication_identity_from_stat(&record->repository, &st);
    }
    if (stat(config_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->post_config, &st);
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION |
                           PUBLICATION_CAP_GPG_FINGERPRINT |
                           PUBLICATION_CAP_GPG_PROGRAM |
                           PUBLICATION_CAP_GPG_SELECTOR |
                           PUBLICATION_CAP_GPG_SIGNING_STATE;
    record->gpg_signing_enabled = true;
    if (safe_strncpy(record->gpg_fingerprint, M10_FINGERPRINT,
                     sizeof(record->gpg_fingerprint)) != 0 ||
        safe_strncpy(record->gpg_selector, M10_SELECTOR,
                     sizeof(record->gpg_selector)) != 0 ||
        safe_strncpy(record->gpg_program, fixture->program,
                     sizeof(record->gpg_program)) != 0 ||
        stat(fixture->program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->gpg_program_identity, &st);
    record->state = PUBLICATION_STATE_PUBLISHED;
    return publication_record_validate(record);
}

static int m10_write_ledger(m10_fixture_t *fixture) {
    static const char header[] = "gpg\nactive=alice\n";
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    for (size_t i = 0; i < fixture->record_count; i++) {
        if (publication_ledger_upsert(&ledger, &fixture->records[i]) != 0) {
            goto cleanup;
        }
    }
    if (publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }
    fd = open(fixture->state_path,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 ||
        m10_write_all(fd, header, sizeof(header) - 1U) != 0 ||
        m10_write_all(fd, (const char *)tail, tail_length) != 0 ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
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

static int m10_fixture_init_internal(m10_fixture_t *fixture,
                                     bool trusted_executable_root) {
    char root_template[MAX_PATH_LEN] =
        "/tmp/gsw-ar11-m10-real.XXXXXX";

    memset(fixture, 0, sizeof(*fixture));
    if (!getcwd(fixture->original_cwd, sizeof(fixture->original_cwd)) ||
        (trusted_executable_root
             ? !ts_mkdtemp_trusted(root_template, sizeof(root_template),
                                   "gsw-ar11-m10")
             : !ts_mkdtemp(root_template)) ||
        ts_canonicalize_dir_path(root_template,
                                 sizeof(root_template)) != 0 ||
        safe_strncpy(fixture->root, root_template,
                     sizeof(fixture->root)) != 0 ||
        safe_snprintf(fixture->state_dir, sizeof(fixture->state_dir),
                      "%s/state", fixture->root) != 0 ||
        safe_snprintf(fixture->config_path, sizeof(fixture->config_path),
                      "%s/accounts.toml", fixture->state_dir) != 0 ||
        safe_snprintf(fixture->state_path, sizeof(fixture->state_path),
                      "%s/.resume-hint", fixture->state_dir) != 0 ||
        safe_snprintf(fixture->repo_a, sizeof(fixture->repo_a),
                      "%s/repo-a", fixture->root) != 0 ||
        safe_snprintf(fixture->repo_a_git, sizeof(fixture->repo_a_git),
                      "%s/.git", fixture->repo_a) != 0 ||
        safe_snprintf(fixture->repo_a_local,
                      sizeof(fixture->repo_a_local), "%s/config",
                      fixture->repo_a_git) != 0 ||
        safe_snprintf(fixture->repo_a_worktree,
                      sizeof(fixture->repo_a_worktree), "%s/config.worktree",
                      fixture->repo_a_git) != 0 ||
        safe_snprintf(fixture->repo_b, sizeof(fixture->repo_b),
                      "%s/repo-b", fixture->root) != 0 ||
        safe_snprintf(fixture->repo_b_git, sizeof(fixture->repo_b_git),
                      "%s/.git", fixture->repo_b) != 0 ||
        safe_snprintf(fixture->repo_b_local,
                      sizeof(fixture->repo_b_local), "%s/config",
                      fixture->repo_b_git) != 0 ||
        safe_snprintf(fixture->program, sizeof(fixture->program),
                      "%s/gpg-program", fixture->root) != 0 ||
        m10_make_dir(fixture->state_dir) != 0 ||
        m10_make_dir(fixture->repo_a) != 0 ||
        m10_make_dir(fixture->repo_a_git) != 0 ||
        m10_make_dir(fixture->repo_b) != 0 ||
        m10_make_dir(fixture->repo_b_git) != 0 ||
        m10_write_file(fixture->repo_a_local, "[fixture]\nvalue = 1\n") != 0 ||
        m10_write_file(fixture->repo_a_worktree,
                       "[fixture]\nvalue = 2\n") != 0 ||
        m10_write_file(fixture->repo_b_local, "[fixture]\nvalue = 3\n") != 0 ||
        m10_write_file(fixture->program, "#!/bin/sh\nexit 0\n") != 0 ||
        chmod(fixture->program, 0700) != 0) {
        m10_fixture_cleanup(fixture);
        return -1;
    }
    memset(&fixture->ctx, 0, sizeof(fixture->ctx));
    fixture->ctx.account_count = 1U;
    fixture->ctx.accounts[0].id = UINT32_C(41);
    fixture->ctx.accounts[0].incarnation_persisted = true;
    fixture->ctx.accounts[0].gpg_enabled = true;
    fixture->ctx.accounts[0].gpg_signing_enabled = true;
    if (safe_strncpy(fixture->ctx.config.config_path, fixture->config_path,
                     sizeof(fixture->ctx.config.config_path)) != 0 ||
        safe_strncpy(fixture->ctx.accounts[0].incarnation, M10_INCARNATION,
                     sizeof(fixture->ctx.accounts[0].incarnation)) != 0 ||
        safe_strncpy(fixture->ctx.accounts[0].name, "alice",
                     sizeof(fixture->ctx.accounts[0].name)) != 0 ||
        safe_strncpy(fixture->ctx.accounts[0].email, "alice@example.test",
                     sizeof(fixture->ctx.accounts[0].email)) != 0 ||
        safe_strncpy(fixture->ctx.accounts[0].gpg_key_id, M10_SELECTOR,
                     sizeof(fixture->ctx.accounts[0].gpg_key_id)) != 0) {
        m10_fixture_cleanup(fixture);
        return -1;
    }
    fixture->ctx.current_account = &fixture->ctx.accounts[0];
    return 0;
}

static int m10_fixture_init(m10_fixture_t *fixture) {
    return m10_fixture_init_internal(fixture, true);
}

static int m10_fixture_init_tmp(m10_fixture_t *fixture) {
    return m10_fixture_init_internal(fixture, false);
}

static int m10_add_record(m10_fixture_t *fixture,
                          publication_scope_t scope,
                          const char *config_path,
                          const char *repository_path) {
    if (fixture->record_count >=
        sizeof(fixture->records) / sizeof(fixture->records[0])) {
        return -1;
    }
    if (m10_make_record(&fixture->records[fixture->record_count], fixture,
                        scope, config_path, repository_path) != 0) {
        return -1;
    }
    fixture->record_count++;
    return 0;
}

static int m10_destination_insert_value(m10_destination_t *destination,
                                        size_t key, size_t index,
                                        const char *value) {
    size_t count;

    if (!destination || key >= M10_KEY_COUNT || !value) return -1;
    count = destination->value_count[key];
    if (count >= M10_VALUE_CAPACITY || index > count) return -1;
    for (size_t i = count; i > index; i--) {
        memcpy(destination->values[key][i],
               destination->values[key][i - 1U],
               sizeof(destination->values[key][i]));
    }
    if (safe_strncpy(destination->values[key][index], value,
                     sizeof(destination->values[key][index])) != 0) {
        return -1;
    }
    destination->value_count[key]++;
    return 0;
}

static int m10_destination_append_value(m10_destination_t *destination,
                                        size_t key, const char *value) {
    if (!destination || key >= M10_KEY_COUNT) return -1;
    return m10_destination_insert_value(
        destination, key, destination->value_count[key], value);
}

static size_t m10_destination_remove_exact(m10_destination_t *destination,
                                           size_t key,
                                           const char *value) {
    size_t survivors = 0U;
    size_t removed = 0U;

    if (!destination || key >= M10_KEY_COUNT || !value) return 0U;
    for (size_t i = 0U; i < destination->value_count[key]; i++) {
        if (strcmp(destination->values[key][i], value) == 0) {
            removed++;
            continue;
        }
        if (survivors != i) {
            memcpy(destination->values[key][survivors],
                   destination->values[key][i],
                   sizeof(destination->values[key][survivors]));
        }
        survivors++;
    }
    for (size_t i = survivors; i < destination->value_count[key]; i++) {
        destination->values[key][i][0] = '\0';
    }
    destination->value_count[key] = survivors;
    return removed;
}

static void m10_destination_clear_values(m10_destination_t *destination) {
    if (!destination) return;
    memset(destination->values, 0, sizeof(destination->values));
    memset(destination->value_count, 0, sizeof(destination->value_count));
}

static void m10_model_records(const m10_fixture_t *fixture) {
    memset(m10_destinations, 0, sizeof(m10_destinations));
    m10_destination_count = fixture->record_count;
    for (size_t i = 0; i < fixture->record_count; i++) {
        CHECK_EQ_INT(safe_strncpy(m10_destinations[i].path,
                                  fixture->records[i].config_path,
                                  sizeof(m10_destinations[i].path)), 0);
        CHECK_EQ_INT(m10_destination_append_value(
                         &m10_destinations[i], M10_SIGNING_KEY,
                         fixture->records[i].gpg_fingerprint), 0);
        CHECK_EQ_INT(m10_destination_append_value(
                         &m10_destinations[i], M10_SIGNING_ENABLED,
                         "true"), 0);
        CHECK_EQ_INT(m10_destination_append_value(
                         &m10_destinations[i], M10_GPG_FORMAT,
                         "openpgp"), 0);
        CHECK_EQ_INT(m10_destination_append_value(
                         &m10_destinations[i], M10_GPG_PROGRAM,
                         fixture->records[i].gpg_program), 0);
    }
    m10_runner_calls = 0U;
    m10_saw_scope_flag = false;
    m10_saw_rev_parse = false;
    m10_saw_unknown_path = false;
    m10_first_git_saw_preflight_failure = false;
    m10_fail_stale_stage_snapshot = false;
}

static int m10_finish(run_result_t *result, int exit_code) {
    if (result) {
        result->spawned = true;
        result->exit_code = exit_code;
    }
    return exit_code == 0 ? 0 : -1;
}

static int m10_output(const run_opts_t *opts, run_result_t *result,
                      const char *value) {
    int length;

    if (!opts || !opts->out || opts->out_size == 0U) {
        return m10_finish(result, 2);
    }
    length = snprintf(opts->out, opts->out_size, "%s\n", value);
    if (length < 0 || (size_t)length >= opts->out_size) {
        return m10_finish(result, 2);
    }
    if (result) result->out_len = (size_t)length;
    return m10_finish(result, 0);
}

static int m10_output_values(const m10_destination_t *destination,
                             size_t key, const run_opts_t *opts,
                             run_result_t *result) {
    size_t used = 0U;

    if (!destination || key >= M10_KEY_COUNT ||
        destination->value_count[key] == 0U || !opts || !opts->out ||
        opts->out_size == 0U) {
        return m10_finish(result, 1);
    }
    for (size_t i = 0U; i < destination->value_count[key]; i++) {
        int length = snprintf(opts->out + used, opts->out_size - used,
                              "%s\n", destination->values[key][i]);

        if (length < 0 || (size_t)length >= opts->out_size - used) {
            return m10_finish(result, 2);
        }
        used += (size_t)length;
    }
    if (result) result->out_len = used;
    return m10_finish(result, 0);
}

static int m10_binary_output(const run_opts_t *opts, run_result_t *result,
                             const unsigned char *bytes, size_t length) {
    if (!opts || !opts->out || opts->out_size == 0U ||
        length >= opts->out_size) {
        return m10_finish(result, 2);
    }
    memcpy(opts->out, bytes, length);
    opts->out[length] = '\0';
    if (result) result->out_len = length;
    return m10_finish(result, 0);
}

static int m10_status_append(const void *bytes, size_t length) {
    if (!bytes || length > sizeof(m10_status_listing) -
                              m10_status_listing_length) {
        return -1;
    }
    memcpy(m10_status_listing + m10_status_listing_length, bytes, length);
    m10_status_listing_length += length;
    return 0;
}

static int m10_status_append_record(const char *scope, const char *origin,
                                    const char *key, const char *value) {
    const char nul = '\0';
    const char newline = '\n';

    return m10_status_append(scope, strlen(scope)) == 0 &&
                   m10_status_append(&nul, 1U) == 0 &&
                   m10_status_append(origin, strlen(origin)) == 0 &&
                   m10_status_append(&nul, 1U) == 0 &&
                   m10_status_append(key, strlen(key)) == 0 &&
                   m10_status_append(&newline, 1U) == 0 &&
                   m10_status_append(value, strlen(value)) == 0 &&
                   m10_status_append(&nul, 1U) == 0
               ? 0
               : -1;
}

static int m10_prepare_status_listing(const m10_fixture_t *fixture,
                                      const char *shared_config,
                                      const char *repository) {
    char origin[MAX_PATH_LEN];

    if (!fixture || !shared_config || !repository ||
        safe_snprintf(origin, sizeof(origin), "file:%s", shared_config) != 0 ||
        safe_strncpy(m10_status_repository, repository,
                     sizeof(m10_status_repository)) != 0) {
        return -1;
    }
    m10_status_listing_length = 0U;
    return m10_status_append_record("local", origin, GIT_CONFIG_USER_NAME,
                                    fixture->ctx.accounts[0].name) == 0 &&
                   m10_status_append_record(
                       "local", origin, GIT_CONFIG_USER_EMAIL,
                       fixture->ctx.accounts[0].email) == 0 &&
                   m10_status_append_record(
                       "local", origin, GIT_CONFIG_USER_SIGNINGKEY,
                       M10_FINGERPRINT) == 0 &&
                   m10_status_append_record(
                       "local", origin, GIT_CONFIG_COMMIT_GPGSIGN,
                       "true") == 0 &&
                   m10_status_append_record(
                       "local", origin, GIT_CONFIG_GPG_FORMAT,
                       "openpgp") == 0 &&
                   m10_status_append_record(
                       "local", origin, GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                       fixture->program) == 0
               ? 0
               : -1;
}

static int m10_status_runner(const char *const argv[],
                             const run_opts_t *opts,
                             run_result_t *result) {
    if (result) memset(result, 0, sizeof(*result));
    if (!argv || !argv[0] || !ts_command_is(argv[0], "git") || !argv[1]) {
        return m10_finish(result, 127);
    }
    if (strcmp(argv[1], "rev-parse") == 0 && argv[2]) {
        if (strcmp(argv[2], "--git-dir") == 0) {
            return m10_output(opts, result, ".git");
        }
        if (strcmp(argv[2], "--show-toplevel") == 0) {
            return m10_output(opts, result, m10_status_repository);
        }
        return m10_finish(result, 2);
    }
    if (strcmp(argv[1], "config") == 0 && argv[2] &&
        strcmp(argv[2], "--show-origin") == 0) {
        return m10_binary_output(opts, result, m10_status_listing,
                                 m10_status_listing_length);
    }
    return m10_finish(result, 2);
}

static int m10_capture_status(const gitswitch_ctx_t *ctx, char *output,
                              size_t output_size) {
    FILE *capture;
    int saved_stdout;
    int status_result;
    int restore_result;
    size_t length;

    if (!ctx || !output || output_size == 0U ||
        (capture = tmpfile()) == NULL) {
        return -1;
    }
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        (void)fclose(capture);
        return -1;
    }
    (void)fflush(stdout);
    if (dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        (void)close(saved_stdout);
        (void)fclose(capture);
        return -1;
    }
    status_result = accounts_show_status(ctx);
    (void)fflush(stdout);
    restore_result = dup2(saved_stdout, STDOUT_FILENO);
    (void)close(saved_stdout);
    rewind(capture);
    length = fread(output, 1U, output_size - 1U, capture);
    output[length] = '\0';
    (void)fclose(capture);
    return restore_result == STDOUT_FILENO ? status_result : -1;
}

static int m10_run_real_command(const char *const argv[], char *output,
                                size_t output_size) {
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    if (output && output_size > 0U) {
        output[0] = '\0';
        opts.out = output;
        opts.out_size = output_size;
    }
    opts.stderr_to_devnull = true;
    return run_argv_real(argv, &opts, &result);
}

static int m10_trim_command_output(char *output) {
    size_t length;

    if (!output) return -1;
    length = strlen(output);
    while (length > 0U &&
           (output[length - 1U] == '\n' || output[length - 1U] == '\r')) {
        output[--length] = '\0';
    }
    return length > 0U ? 0 : -1;
}

static int m10_real_git_config(const char *repository, const char *key,
                               const char *value) {
    const char *const argv[] = {
        "git", "-C", repository, "config", "--local", key, value, NULL
    };

    return m10_run_real_command(argv, NULL, 0U);
}

static int m10_real_git_toplevel(const char *repository, char *output,
                                 size_t output_size) {
    const char *const argv[] = {
        "git", "-C", repository, "rev-parse", "--show-toplevel", NULL
    };

    return m10_run_real_command(argv, output, output_size) == 0
               ? m10_trim_command_output(output)
               : -1;
}

static int m10_real_git_local_config_path(const char *repository,
                                          char *output,
                                          size_t output_size) {
    const char *const argv[] = {
        "git", "-C", repository, "rev-parse", "--path-format=absolute",
        "--git-path", "config", NULL
    };

    return m10_run_real_command(argv, output, output_size) == 0
               ? m10_trim_command_output(output)
               : -1;
}

static int m10_key_slot(const char *key) {
    for (int i = 0; i < M10_KEY_COUNT; i++) {
        if (strcmp(key, m10_keys[i]) == 0) return i;
    }
    return -1;
}

static bool m10_path_is_stage(const char *path,
                              const m10_destination_t *destination) {
    static const char stage_prefix[] = "/.gitswitch-config-";
    const char *slash;
    size_t parent_length;

    if (!path || !destination) return false;
    slash = strrchr(destination->path, '/');
    if (!slash) return false;
    parent_length = (size_t)(slash - destination->path);
    return strncmp(path, destination->path, parent_length) == 0 &&
           strncmp(path + parent_length, stage_prefix,
                   sizeof(stage_prefix) - 1U) == 0;
}

static bool m10_path_is_destination_or_stage(
    const char *path, const m10_destination_t *destination) {
    return path && destination &&
           (strcmp(path, destination->path) == 0 ||
            m10_path_is_stage(path, destination));
}

static int m10_snapshot_output(const m10_destination_t *destination,
                               const run_opts_t *opts,
                               run_result_t *result) {
    unsigned char listing[4096];
    size_t length = 0U;

    if (!destination) return m10_finish(result, 2);
    for (size_t slot = 0U; slot < M10_KEY_COUNT; slot++) {
        for (size_t value_index = 0U;
             value_index < destination->value_count[slot]; value_index++) {
            const char *value = destination->values[slot][value_index];
            size_t key_length = strlen(m10_keys[slot]);
            size_t value_length = strlen(value);

            if (key_length + value_length + 2U >
                sizeof(listing) - length) {
                return m10_finish(result, 2);
            }
            memcpy(listing + length, m10_keys[slot], key_length);
            length += key_length;
            listing[length++] = '\n';
            memcpy(listing + length, value, value_length);
            length += value_length;
            listing[length++] = '\0';
        }
    }
    return m10_binary_output(opts, result, listing, length);
}

static int m10_retirement_runner(const char *const argv[],
                                 const run_opts_t *opts,
                                 run_result_t *result) {
    m10_destination_t *destination = NULL;
    int slot;

    m10_runner_calls++;
    if (m10_runner_calls == 1U) {
        const error_context_t *error = get_last_error();

        m10_first_git_saw_preflight_failure =
            error && error->code == ERR_GIT_CONFIG_FAILED &&
            strstr(error->message, "inaccessible or changed") != NULL;
    }
    if (result) memset(result, 0, sizeof(*result));
    if (!argv || !argv[0] || !ts_command_is(argv[0], "git") || !argv[1]) {
        return m10_finish(result, 127);
    }
    if (strcmp(argv[1], "rev-parse") == 0 || strcmp(argv[1], "-C") == 0) {
        m10_saw_rev_parse = true;
        return m10_finish(result, 2);
    }
    if (strcmp(argv[1], "config") != 0 || !argv[2]) {
        return m10_finish(result, 2);
    }
    if (strcmp(argv[2], "--global") == 0 ||
        strcmp(argv[2], "--local") == 0 ||
        strcmp(argv[2], "--worktree") == 0) {
        m10_saw_scope_flag = true;
        return m10_finish(result, 2);
    }
    if (strcmp(argv[2], "--file") != 0 || !argv[3] || !argv[4]) {
        return m10_finish(result, 2);
    }
    for (size_t i = 0; i < m10_destination_count; i++) {
        if (m10_path_is_destination_or_stage(
                argv[3], &m10_destinations[i])) {
            destination = &m10_destinations[i];
            break;
        }
    }
    if (!destination) {
        m10_saw_unknown_path = true;
        return m10_finish(result, 2);
    }
    if (strcmp(argv[4], "--list") == 0) {
        if (!argv[5] || strcmp(argv[5], "-z") != 0 || !argv[6] ||
            strcmp(argv[6], "--no-includes") != 0 || argv[7]) {
            return m10_finish(result, 2);
        }
        destination->gets++;
        if (m10_fail_stale_stage_snapshot &&
            m10_path_is_stage(argv[3], destination)) {
            m10_fail_stale_stage_snapshot = false;
            return m10_finish(result, 2);
        }
        return m10_snapshot_output(destination, opts, result);
    }
    if (strcmp(argv[4], "--no-includes") != 0 || !argv[5]) {
        return m10_finish(result, 2);
    }
    if (strcmp(argv[5], "--get") == 0 ||
        strcmp(argv[5], "--get-all") == 0) {
        if (!argv[6] || argv[7]) return m10_finish(result, 2);
        slot = m10_key_slot(argv[6]);
        if (slot < 0) return m10_finish(result, 2);
        destination->gets++;
        if (strcmp(argv[5], "--get") == 0) {
            if (destination->value_count[slot] == 0U) {
                return m10_finish(result, 1);
            }
            return m10_output(opts, result,
                              destination->values[slot][0]);
        }
        return m10_output_values(destination, (size_t)slot, opts, result);
    }
    if (strcmp(argv[5], "--fixed-value") == 0 && argv[6] &&
        strcmp(argv[6], "--unset-all") == 0 && argv[7] && argv[8] &&
        !argv[9]) {
        slot = m10_key_slot(argv[7]);
        if (slot < 0) return m10_finish(result, 2);
        destination->unsets++;
        if (destination->fail_unset[slot]) {
            if (opts && opts->out && opts->out_size > 0U) {
                (void)snprintf(opts->out, opts->out_size,
                               "injected unset failure");
                if (result) result->out_len = strlen(opts->out);
            }
            return m10_finish(result, 2);
        }
        if (m10_destination_remove_exact(
                destination, (size_t)slot, argv[8]) == 0U) {
            return m10_finish(result, 5);
        }
        return m10_finish(result, 0);
    }
    return m10_finish(result, 2);
}

static bool m10_destination_cleared(size_t index) {
    for (size_t key = 0; key < M10_KEY_COUNT; key++) {
        if (m10_destinations[index].value_count[key] != 0U) return false;
    }
    return true;
}

static bool m10_destination_unchanged(size_t index) {
    for (size_t key = 0; key < M10_KEY_COUNT; key++) {
        if (m10_destinations[index].value_count[key] != 1U) return false;
    }
    return true;
}

static void m10_check_exact_file_only(void) {
    CHECK(m10_runner_calls > 0U);
    CHECK(!m10_saw_scope_flag);
    CHECK(!m10_saw_rev_parse);
    CHECK(!m10_saw_unknown_path);
}

static bool m10_error_contains(const char *text) {
    const error_context_t *error = get_last_error();

    return text && error &&
           (strstr(error->message, text) != NULL ||
            strstr(error->details, text) != NULL);
}

static bool m10_retirement_artifacts_absent(const char *config_path) {
    static const char stage_prefix[] = ".gitswitch-config-";
    char parent[MAX_PATH_LEN];
    char lock_leaf[MAX_PATH_LEN];
    const char *leaf;
    char *slash;
    DIR *directory;
    struct dirent *entry;
    bool absent = true;

    if (!config_path ||
        safe_strncpy(parent, config_path, sizeof(parent)) != 0) {
        return false;
    }
    slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return false;
    leaf = slash + 1U;
    if (safe_snprintf(lock_leaf, sizeof(lock_leaf), "%s.lock", leaf) != 0) {
        return false;
    }
    *slash = '\0';
    directory = opendir(parent[0] != '\0' ? parent : "/");
    if (!directory) return false;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, lock_leaf) == 0 ||
            strncmp(entry->d_name, stage_prefix,
                    sizeof(stage_prefix) - 1U) == 0) {
            absent = false;
            break;
        }
    }
    if (closedir(directory) != 0) return false;
    return absent;
}

static int m10_prepare_remove_recovery(
    m10_fixture_t *fixture,
    const char *record_incarnation,
    publication_state_t record_state,
    bool include_record,
    const config_retirement_ssh_alias_obligation_t *obligation) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "active_account = \"alice\"\n"
        "[accounts.41]\n"
        "incarnation = \"" M10_INCARNATION "\"\n"
        "name = \"alice\"\n"
        "email = \"alice@example.test\"\n"
        "preferred_scope = \"local\"\n";
    config_retirement_owner_t owner;
    config_retirement_guard_t *guard = NULL;

    if (!fixture || !record_incarnation || !obligation ||
        m10_write_file(fixture->config_path, config_body) != 0 ||
        config_load(&fixture->ctx, fixture->config_path) != 0) {
        return -1;
    }
    if (include_record) {
        if (m10_add_record(fixture, PUBLICATION_SCOPE_LOCAL,
                           fixture->repo_a_local, fixture->repo_a) != 0 ||
            safe_strncpy(
                fixture->records[0].account_incarnation,
                record_incarnation,
                sizeof(fixture->records[0].account_incarnation)) != 0) {
            return -1;
        }
        fixture->records[0].state = record_state;
        if (publication_record_validate(&fixture->records[0]) != 0) {
            return -1;
        }
    }
    if (m10_write_ledger(fixture) != 0) return -1;
    memset(&owner, 0, sizeof(owner));
    owner.account_id = UINT32_C(41);
    if (safe_strncpy(owner.account_incarnation, M10_INCARNATION,
                     sizeof(owner.account_incarnation)) != 0 ||
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture->config_path, CONFIG_RETIREMENT_REMOVE,
            &owner, 1U, obligation, &guard) != 0 ||
        !guard) {
        config_retirement_guard_abandon(&guard);
        return -1;
    }
    config_retirement_guard_abandon(&guard);
    fixture->ctx.account_count = 0U;
    fixture->ctx.current_account = NULL;
    fixture->ctx.config.active_account[0] = '\0';
    m10_model_records(fixture);
    if (include_record) {
        m10_destination_clear_values(&m10_destinations[0]);
    }
    return 0;
}

static int m10_alias_obligation(
    const m10_fixture_t *fixture,
    config_retirement_ssh_alias_obligation_t *obligation) {
    struct stat home_st;
    struct stat ssh_st;

    if (!fixture || !obligation ||
        stat(fixture->root, &home_st) != 0 ||
        stat(fixture->repo_a, &ssh_st) != 0) {
        return -1;
    }
    memset(obligation, 0, sizeof(*obligation));
    obligation->known = true;
    obligation->present = true;
    if (safe_strncpy(obligation->ssh_host_alias, "retired-alias",
                     sizeof(obligation->ssh_host_alias)) != 0 ||
        safe_strncpy(obligation->home_path, fixture->root,
                     sizeof(obligation->home_path)) != 0) {
        return -1;
    }
    publication_identity_from_stat(&obligation->home_identity, &home_st);
    publication_identity_from_stat(
        &obligation->ssh_directory_identity, &ssh_st);
    return 0;
}

TEST(incomplete_remove_recovery_settles_clean_retiring_destination) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    command_runner_fn previous;
    bool blocked = true;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    previous = run_set_runner(NULL);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), 1);
    run_set_runner(previous);
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(!blocked);
    CHECK_EQ_INT(access(fixture.repo_a_local, F_OK), 0);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_rejects_conflicting_incarnation_tombstone) {
    static const char other_incarnation[] =
        "2222222222222222222222222222222222222222222222222222222222222222";
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, other_incarnation,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("conflicting durable incarnation"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_rejects_nonretiring_tombstone) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_PUBLISHED, true, &obligation), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("non-retiring publication provenance"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_requires_canonical_tombstone_ledger) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, false, &obligation), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("no canonical publication tombstone ledger"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_requires_owner_tombstone) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    fixture.records[0].account_id = UINT32_C(42);
    CHECK_EQ_INT(publication_record_validate(&fixture.records[0]), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("no durable publication tombstones"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_rejects_live_alias_claimant) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_alias_obligation(&fixture, &obligation), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    fixture.ctx.account_count = 1U;
    fixture.ctx.accounts[0].id = UINT32_C(77);
    CHECK_EQ_INT(safe_strncpy(
                     fixture.ctx.accounts[0].ssh_host_alias,
                     obligation.ssh_host_alias,
                     sizeof(fixture.ctx.accounts[0].ssh_host_alias)), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("live account ID 77 claims SSH alias"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_ignores_noncanonical_identifiers) {
    gitswitch_ctx_t ctx;
    static const char *const identifiers[] = {
        "", "0", "-1", "41x", "4294967296"
    };

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(accounts_remove_recover_incomplete(NULL, "41"), -1);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(&ctx, NULL), -1);
    for (size_t i = 0U;
         i < sizeof(identifiers) / sizeof(identifiers[0]); i++) {
        CHECK_EQ_INT(accounts_remove_recover_incomplete(
                         &ctx, identifiers[i]), 0);
    }
}

TEST(incomplete_remove_recovery_defers_to_exact_live_owner) {
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    fixture.ctx.account_count = 1U;
    fixture.ctx.current_account = &fixture.ctx.accounts[0];
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), 0);
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(incomplete_remove_recovery_rejects_reused_live_owner_id) {
    static const char other_incarnation[] =
        "2222222222222222222222222222222222222222222222222222222222222222";
    config_retirement_ssh_alias_obligation_t obligation;
    m10_fixture_t fixture;
    bool blocked = false;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_prepare_remove_recovery(
                     &fixture, M10_INCARNATION,
                     PUBLICATION_STATE_RETIRING, true, &obligation), 0);
    fixture.ctx.account_count = 1U;
    fixture.ctx.accounts[0].incarnation_persisted = true;
    CHECK_EQ_INT(safe_strncpy(
                     fixture.ctx.accounts[0].incarnation,
                     other_incarnation,
                     sizeof(fixture.ctx.accounts[0].incarnation)), 0);
    CHECK_EQ_INT(accounts_remove_recover_incomplete(
                     &fixture.ctx, "41"), -1);
    CHECK(m10_error_contains("live account uses a different incarnation"));
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), 0);
    CHECK(blocked);
    m10_fixture_cleanup(&fixture);
}

TEST(removal_from_repository_b_retires_repository_a_and_b_destinations) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    /* Retirement ownership comes from each sealed record, not mutable account
     * feature flags that may have been edited after publication. */
    fixture.ctx.accounts[0].gpg_enabled = false;
    fixture.ctx.accounts[0].gpg_signing_enabled = false;
    fixture.ctx.accounts[0].gpg_key_id[0] = '\0';
    CHECK_EQ_INT(chdir(fixture.repo_b), 0);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)(2U * M10_KEY_COUNT));
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_cleared(1U));
    m10_check_exact_file_only();
    CHECK_EQ_INT(chdir(fixture.original_cwd), 0);
    m10_fixture_cleanup(&fixture);
}

TEST(removal_outside_repository_ignores_poisoned_git_environment) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    static const char *const environment_names[] = {
        "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_DIR", "GIT_WORK_TREE",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"
    };
    static const char *const poisoned_values[] = {
        "/poison/home", "/poison/xdg", "/poison/global",
        "/poison/system", "/poison/repository", "/poison/worktree",
        "1", "user.signingkey",
        M10_FOREIGN_FINGERPRINT
    };
    m10_saved_env_t saved_environment[
        sizeof(environment_names) / sizeof(environment_names[0])];
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(chdir(fixture.state_dir), 0);
    for (size_t i = 0;
         i < sizeof(environment_names) / sizeof(environment_names[0]); i++) {
        saved_environment[i] = m10_save_env(environment_names[i]);
        CHECK(!saved_environment[i].present || saved_environment[i].value);
        CHECK_EQ_INT(setenv(environment_names[i], poisoned_values[i], 1), 0);
    }
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)(2U * M10_KEY_COUNT));
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_cleared(1U));
    m10_check_exact_file_only();
    for (size_t i = 0;
         i < sizeof(environment_names) / sizeof(environment_names[0]); i++) {
        m10_restore_env(environment_names[i], &saved_environment[i]);
    }
    CHECK_EQ_INT(chdir(fixture.original_cwd), 0);
    m10_fixture_cleanup(&fixture);
}

TEST(local_and_worktree_publications_in_one_repository_are_both_retired) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_WORKTREE,
                                fixture.repo_a_worktree, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)(2U * M10_KEY_COUNT));
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_cleared(1U));
    m10_check_exact_file_only();
    m10_fixture_cleanup(&fixture);
}

TEST(real_linked_worktree_status_uses_current_shared_config_witness) {
    static const char *const environment_names[] = {
        "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_DIR",
        "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"
    };
    m10_saved_env_t saved_environment[
        sizeof(environment_names) / sizeof(environment_names[0])];
    m10_fixture_t fixture;
    command_runner_fn previous_runner = NULL;
    char home[MAX_PATH_LEN];
    char xdg[MAX_PATH_LEN];
    char global_config[MAX_PATH_LEN];
    char main_config_query[MAX_PATH_LEN];
    char linked_config_query[MAX_PATH_LEN];
    char main_config[MAX_PATH_LEN];
    char linked_config[MAX_PATH_LEN];
    char expected_config[MAX_PATH_LEN];
    char main_top_query[MAX_PATH_LEN];
    char linked_top_query[MAX_PATH_LEN];
    char main_top[MAX_PATH_LEN];
    char linked_top[MAX_PATH_LEN];
    char status_output[8192];
    char main_status_output[8192];
    size_t saved_count = 0U;
    bool runner_replaced = false;
    int status_result;
    int main_status_result;

    memset(saved_environment, 0, sizeof(saved_environment));
    if (m10_fixture_init_tmp(&fixture) != 0) {
        CHECK(false);
        return;
    }
    /* The repository and mutable state stay under /tmp. The sealed OpenPGP
     * program witness must not: production deliberately rejects executables
     * below sticky/world-writable ancestors. Reuse the already-required,
     * trusted real Git binary as a read-only identity witness; status never
     * invokes it as an OpenPGP implementation. */
    if (find_command_path("git", fixture.program,
                          sizeof(fixture.program)) != 0) {
        CHECK(false);
        goto cleanup;
    }
    if (safe_snprintf(home, sizeof(home), "%s/home", fixture.root) != 0 ||
        safe_snprintf(xdg, sizeof(xdg), "%s/xdg", fixture.root) != 0 ||
        safe_snprintf(global_config, sizeof(global_config), "%s/gitconfig",
                      fixture.root) != 0 ||
        m10_make_dir(home) != 0 || m10_make_dir(xdg) != 0 ||
        m10_write_file(global_config, "") != 0) {
        CHECK(false);
        goto cleanup;
    }
    for (size_t i = 0U;
         i < sizeof(environment_names) / sizeof(environment_names[0]); i++) {
        saved_environment[i] = m10_save_env(environment_names[i]);
        if (saved_environment[i].present && !saved_environment[i].value) {
            CHECK(false);
            goto cleanup;
        }
        saved_count++;
    }
    if (setenv("HOME", home, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", xdg, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", global_config, 1) != 0 ||
        setenv("GIT_CONFIG_SYSTEM", "/dev/null", 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0) {
        CHECK(false);
        goto cleanup;
    }
    for (size_t i = 5U;
         i < sizeof(environment_names) / sizeof(environment_names[0]); i++) {
        if (unsetenv(environment_names[i]) != 0) {
            CHECK(false);
            goto cleanup;
        }
    }

    ts_rm_rf(fixture.repo_a_git);
    ts_rm_rf(fixture.repo_b);
    {
        const char *const init_argv[] = {
            "git", "init", "--quiet", fixture.repo_a, NULL
        };
        const char *const commit_argv[] = {
            "git", "-C", fixture.repo_a, "-c", "user.name=fixture",
            "-c", "user.email=fixture@example.test", "-c",
            "commit.gpgSign=false", "commit", "--quiet", "--allow-empty",
            "-m", "seed", NULL
        };
        const char *const worktree_argv[] = {
            "git", "-C", fixture.repo_a, "worktree", "add", "--quiet",
            "--detach", fixture.repo_b, NULL
        };

        if (m10_run_real_command(init_argv, NULL, 0U) != 0 ||
            m10_run_real_command(commit_argv, NULL, 0U) != 0 ||
            m10_run_real_command(worktree_argv, NULL, 0U) != 0) {
            CHECK(false);
            goto cleanup;
        }
    }
    if (m10_real_git_config(fixture.repo_a, GIT_CONFIG_USER_NAME,
                            fixture.ctx.accounts[0].name) != 0 ||
        m10_real_git_config(fixture.repo_a, GIT_CONFIG_USER_EMAIL,
                            fixture.ctx.accounts[0].email) != 0 ||
        m10_real_git_config(fixture.repo_a, GIT_CONFIG_USER_SIGNINGKEY,
                            M10_FOREIGN_FINGERPRINT) != 0 ||
        m10_real_git_config(fixture.repo_a, GIT_CONFIG_COMMIT_GPGSIGN,
                            "true") != 0 ||
        m10_real_git_config(fixture.repo_a, GIT_CONFIG_GPG_FORMAT,
                            "openpgp") != 0 ||
        m10_real_git_config(fixture.repo_a,
                            GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                            fixture.program) != 0 ||
        m10_real_git_local_config_path(fixture.repo_a, main_config_query,
                                       sizeof(main_config_query)) != 0 ||
        m10_real_git_local_config_path(fixture.repo_b, linked_config_query,
                                       sizeof(linked_config_query)) != 0 ||
        !realpath(main_config_query, main_config) ||
        !realpath(linked_config_query, linked_config) ||
        !realpath(fixture.repo_a_local, expected_config) ||
        m10_real_git_toplevel(fixture.repo_a, main_top_query,
                              sizeof(main_top_query)) != 0 ||
        m10_real_git_toplevel(fixture.repo_b, linked_top_query,
                              sizeof(linked_top_query)) != 0 ||
        !realpath(main_top_query, main_top) ||
        !realpath(linked_top_query, linked_top)) {
        CHECK(false);
        goto cleanup;
    }
    CHECK_STR_EQ(main_config, linked_config);
    CHECK_STR_EQ(main_config, expected_config);
    CHECK_STR_EQ(main_top, fixture.repo_a);
    CHECK_STR_EQ(linked_top, fixture.repo_b);
    CHECK(strcmp(main_top, linked_top) != 0);

    if (m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL, main_config,
                       main_top) != 0 ||
        safe_strncpy(fixture.records[0].gpg_fingerprint,
                     M10_FOREIGN_FINGERPRINT,
                     sizeof(fixture.records[0].gpg_fingerprint)) != 0 ||
        publication_record_validate(&fixture.records[0]) != 0 ||
        m10_real_git_config(fixture.repo_b, GIT_CONFIG_USER_SIGNINGKEY,
                            M10_FINGERPRINT) != 0 ||
        m10_real_git_config(fixture.repo_b, "fixture.generation",
                            "linked-current") != 0 ||
        m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL, linked_config,
                       linked_top) != 0 ||
        m10_write_ledger(&fixture) != 0) {
        CHECK(false);
        goto cleanup;
    }
    CHECK(!publication_identity_equal(&fixture.records[0].repository,
                                      &fixture.records[1].repository));
    CHECK(!publication_identity_equal(&fixture.records[0].post_config,
                                      &fixture.records[1].post_config));
    {
        publication_ledger_t persisted;
        publication_identity_t live_generation;
        struct stat live_stat;

        publication_ledger_init(&persisted);
        if (stat(main_config, &live_stat) != 0 ||
            config_load_publication_ledger(fixture.config_path,
                                           &persisted) != 0) {
            publication_ledger_clear(&persisted);
            CHECK(false);
            goto cleanup;
        }
        publication_identity_from_stat(&live_generation, &live_stat);
        CHECK_EQ_INT((long)persisted.count, 2);
        CHECK(!publication_identity_equal(&fixture.records[0].post_config,
                                          &live_generation));
        CHECK(publication_identity_equal(&fixture.records[1].post_config,
                                         &live_generation));
        publication_ledger_clear(&persisted);
    }
    if (chdir(fixture.repo_b) != 0) {
        CHECK(false);
        goto cleanup;
    }
    git_ops_test_reset_caches();
    previous_runner = run_set_runner(NULL);
    runner_replaced = true;
    status_result = m10_capture_status(&fixture.ctx, status_output,
                                       sizeof(status_output));
    run_set_runner(previous_runner);
    runner_replaced = false;
    if (status_result != 0) {
        fprintf(stderr, "real linked-worktree status output:\n%s\n",
                status_output);
    }
    CHECK_EQ_INT(status_result, 0);
    CHECK(strstr(status_output,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK(strstr(status_output, "ambiguous") == NULL);
    CHECK(strstr(status_output, "incomplete") == NULL);
    if (chdir(fixture.repo_a) != 0) {
        CHECK(false);
        goto cleanup;
    }
    git_ops_test_reset_caches();
    previous_runner = run_set_runner(NULL);
    runner_replaced = true;
    main_status_result = m10_capture_status(&fixture.ctx, main_status_output,
                                            sizeof(main_status_output));
    run_set_runner(previous_runner);
    runner_replaced = false;
    if (main_status_result != 0) {
        fprintf(stderr, "real main-worktree status output:\n%s\n",
                main_status_output);
    }
    CHECK_EQ_INT(main_status_result, 0);
    CHECK(strstr(main_status_output,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK(strstr(main_status_output, "ambiguous") == NULL);
    CHECK(strstr(main_status_output, "incomplete") == NULL);

cleanup:
    if (runner_replaced) run_set_runner(previous_runner);
    if (fixture.original_cwd[0] != '\0') {
        CHECK_EQ_INT(chdir(fixture.original_cwd), 0);
    }
    while (saved_count > 0U) {
        saved_count--;
        m10_restore_env(environment_names[saved_count],
                        &saved_environment[saved_count]);
    }
    git_ops_test_reset_caches();
    m10_fixture_cleanup(&fixture);
}

TEST(linked_repository_witnesses_share_one_local_config_retirement) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    /* Linked worktree roots are distinct durable repository witnesses while
     * their local scope is stored in the main worktree's physical config. */
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_write_file(
                     fixture.repo_a_local,
                     "[fixture]\nvalue = linked-worktree-current-generation\n"),
                 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_b), 0);
    CHECK(!publication_identity_equal(&fixture.records[0].post_config,
                                      &fixture.records[1].post_config));
    CHECK_EQ_INT(safe_strncpy(fixture.records[0].gpg_fingerprint,
                              M10_FOREIGN_FINGERPRINT,
                              sizeof(fixture.records[0].gpg_fingerprint)), 0);
    CHECK_EQ_INT(publication_record_validate(&fixture.records[0]), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);

    memset(m10_destinations, 0, sizeof(m10_destinations));
    m10_destination_count = 1U;
    CHECK_EQ_INT(safe_strncpy(m10_destinations[0].path,
                              fixture.repo_a_local,
                              sizeof(m10_destinations[0].path)), 0);
    CHECK_EQ_INT(m10_destination_append_value(
                     &m10_destinations[0], M10_SIGNING_KEY,
                     M10_FINGERPRINT), 0);
    CHECK_EQ_INT(m10_destination_append_value(
                     &m10_destinations[0], M10_SIGNING_ENABLED,
                     "true"), 0);
    CHECK_EQ_INT(m10_destination_append_value(
                     &m10_destinations[0], M10_GPG_FORMAT,
                     "openpgp"), 0);
    CHECK_EQ_INT(m10_destination_append_value(
                     &m10_destinations[0], M10_GPG_PROGRAM,
                     fixture.program), 0);
    m10_runner_calls = 0U;
    m10_saw_scope_flag = false;
    m10_saw_rev_parse = false;
    m10_saw_unknown_path = false;
    m10_first_git_saw_preflight_failure = false;
    m10_fail_stale_stage_snapshot = false;

    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_cleared(0U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, (long)M10_KEY_COUNT);
    m10_check_exact_file_only();
    m10_fixture_cleanup(&fixture);
}

TEST(status_selects_linked_repository_witness_independent_of_ledger_order) {
    m10_fixture_t fixture;
    publication_record_t first;
    command_runner_fn previous;
    char forward[8192];
    char reverse[8192];
    int status_result;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_write_file(
                     fixture.repo_a_local,
                     "[fixture]\nvalue = linked-status-current-generation\n"),
                 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_b), 0);
    CHECK(!publication_identity_equal(&fixture.records[0].post_config,
                                      &fixture.records[1].post_config));
    CHECK_EQ_INT(safe_strncpy(fixture.records[0].gpg_fingerprint,
                              M10_FOREIGN_FINGERPRINT,
                              sizeof(fixture.records[0].gpg_fingerprint)), 0);
    CHECK_EQ_INT(publication_record_validate(&fixture.records[0]), 0);
    CHECK_EQ_INT(m10_prepare_status_listing(
                     &fixture, fixture.repo_a_local, fixture.repo_b), 0);
    CHECK_EQ_INT(chdir(fixture.repo_b), 0);

    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    git_ops_test_reset_caches();
    previous = run_set_runner(m10_status_runner);
    status_result = m10_capture_status(&fixture.ctx, forward,
                                       sizeof(forward));
    run_set_runner(previous);
    if (status_result != 0) {
        fprintf(stderr, "forward status output:\n%s\n", forward);
    }
    CHECK_EQ_INT(status_result, 0);

    first = fixture.records[0];
    fixture.records[0] = fixture.records[1];
    fixture.records[1] = first;
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    git_ops_test_reset_caches();
    previous = run_set_runner(m10_status_runner);
    status_result = m10_capture_status(&fixture.ctx, reverse,
                                       sizeof(reverse));
    run_set_runner(previous);
    if (status_result != 0) {
        fprintf(stderr, "reverse status output:\n%s\n", reverse);
    }
    CHECK_EQ_INT(status_result, 0);

    CHECK(strstr(forward,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK(strstr(reverse,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK_STR_EQ(forward, reverse);
    CHECK_EQ_INT(chdir(fixture.original_cwd), 0);
    m10_fixture_cleanup(&fixture);
}

TEST(status_ignores_stale_same_path_membership_in_both_ledger_orders) {
    static const char current_contents[] =
        "[fixture]\nvalue = replacement-parent-current-generation\n";
    m10_fixture_t fixture;
    publication_record_t first;
    command_runner_fn previous;
    char replaced_parent[MAX_PATH_LEN];
    char forward[8192];
    char reverse[8192];
    int status_result;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(safe_strncpy(fixture.records[0].gpg_fingerprint,
                              M10_FOREIGN_FINGERPRINT,
                              sizeof(fixture.records[0].gpg_fingerprint)), 0);
    CHECK_EQ_INT(publication_record_validate(&fixture.records[0]), 0);
    CHECK_EQ_INT(safe_snprintf(replaced_parent, sizeof(replaced_parent),
                               "%s.sealed", fixture.repo_a_git), 0);
    CHECK_EQ_INT(rename(fixture.repo_a_git, replaced_parent), 0);
    CHECK_EQ_INT(m10_make_dir(fixture.repo_a_git), 0);
    CHECK_EQ_INT(m10_write_file(fixture.repo_a_local, current_contents), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK(!publication_identity_equal(&fixture.records[0].config_parent,
                                      &fixture.records[1].config_parent));
    CHECK_EQ_INT(m10_prepare_status_listing(
                     &fixture, fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(chdir(fixture.repo_a), 0);

    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    git_ops_test_reset_caches();
    clear_error();
    previous = run_set_runner(m10_status_runner);
    status_result = m10_capture_status(&fixture.ctx, forward,
                                       sizeof(forward));
    run_set_runner(previous);
    if (status_result != 0) {
        fprintf(stderr, "stale-first status output:\n%s\n", forward);
    }
    CHECK_EQ_INT(status_result, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);

    first = fixture.records[0];
    fixture.records[0] = fixture.records[1];
    fixture.records[1] = first;
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    git_ops_test_reset_caches();
    clear_error();
    previous = run_set_runner(m10_status_runner);
    status_result = m10_capture_status(&fixture.ctx, reverse,
                                       sizeof(reverse));
    run_set_runner(previous);
    if (status_result != 0) {
        fprintf(stderr, "valid-first status output:\n%s\n", reverse);
    }
    CHECK_EQ_INT(status_result, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);

    CHECK(strstr(forward,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK(strstr(reverse,
                 "Match Status: [OK] Git config matches account") != NULL);
    CHECK(strstr(forward, "ambiguous") == NULL);
    CHECK(strstr(reverse, "ambiguous") == NULL);
    CHECK_STR_EQ(forward, reverse);
    CHECK_EQ_INT(chdir(fixture.original_cwd), 0);
    m10_fixture_cleanup(&fixture);
}

TEST(stale_later_generation_is_preserved_after_all_record_preflight) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    char replaced[MAX_PATH_LEN];
    publication_ledger_t ledger;
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_snprintf(replaced, sizeof(replaced), "%s.old",
                               fixture.repo_b_local), 0);
    CHECK_EQ_INT(rename(fixture.repo_b_local, replaced), 0);
    CHECK_EQ_INT(m10_write_file(fixture.repo_b_local,
                                "[foreign]\nvalue = preserved\n"), 0);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_unchanged(1U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, (long)M10_KEY_COUNT);
    CHECK_EQ_INT((long)m10_destinations[1].unsets, 0);
    CHECK(!m10_first_git_saw_preflight_failure);
    CHECK(m10_error_contains("attributed values"));
    CHECK(strstr(get_last_error()->details,
                 "retirement summary") != NULL);
    CHECK(strstr(get_last_error()->details,
                 "cleared 4 key(s)") != NULL);
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(fixture.config_path,
                                                &ledger), 0);
    CHECK_EQ_INT((long)ledger.count, 2);
    if (ledger.count == 2U) {
        CHECK_EQ_INT(ledger.records[0].state, PUBLICATION_STATE_PUBLISHED);
        CHECK_EQ_INT(ledger.records[1].state, PUBLICATION_STATE_PUBLISHED);
    }
    publication_ledger_clear(&ledger);
    m10_fixture_cleanup(&fixture);
}

TEST(stale_first_destination_does_not_block_later_valid_retirement) {
    static const char replacement_contents[] =
        "[foreign]\nvalue = stale-first-preserved\n";
    m10_fixture_t fixture;
    command_runner_fn previous;
    char replaced[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_snprintf(replaced, sizeof(replaced), "%s.old",
                               fixture.repo_a_local), 0);
    CHECK_EQ_INT(rename(fixture.repo_a_local, replaced), 0);
    CHECK_EQ_INT(m10_write_file(fixture.repo_a_local,
                                replacement_contents), 0);

    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_unchanged(0U));
    CHECK(m10_destination_cleared(1U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, 0);
    CHECK_EQ_INT((long)m10_destinations[1].unsets, (long)M10_KEY_COUNT);
    CHECK(!m10_first_git_saw_preflight_failure);
    m10_check_exact_file_only();
    CHECK(m10_error_contains("attributed values"));
    CHECK(strstr(get_last_error()->details,
                 "cleared 4 key(s)") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST(stale_locked_read_failure_cleans_artifacts_and_retry_succeeds) {
    static const char replacement_contents[] =
        "[foreign]\nvalue = clean-post-publication-target\n";
    m10_fixture_t fixture;
    command_runner_fn previous;
    char replaced[MAX_PATH_LEN];
    char observed[128];
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_snprintf(replaced, sizeof(replaced), "%s.old",
                               fixture.repo_a_local), 0);
    CHECK_EQ_INT(rename(fixture.repo_a_local, replaced), 0);
    CHECK_EQ_INT(m10_write_file(fixture.repo_a_local,
                                replacement_contents), 0);
    m10_destination_clear_values(&m10_destinations[0]);
    m10_fail_stale_stage_snapshot = true;

    clear_error();
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK_EQ_INT((long)m10_destinations[0].unsets, 0);
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_cleared(1U));
    CHECK_EQ_INT((long)m10_destinations[1].unsets,
                 (long)M10_KEY_COUNT);
    CHECK(!m10_fail_stale_stage_snapshot);
    CHECK(m10_error_contains("re-read stale Git retirement destination"));
    CHECK(m10_retirement_artifacts_absent(fixture.repo_a_local));
    CHECK_EQ_INT(read_file_to_string(fixture.repo_a_local, observed,
                                     sizeof(observed)),
                 (int)(sizeof(replacement_contents) - 1U));
    CHECK_STR_EQ(observed, replacement_contents);

    clear_error();
    cleared = 99U;
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(m10_retirement_artifacts_absent(fixture.repo_a_local));
    CHECK_EQ_INT(read_file_to_string(fixture.repo_a_local, observed,
                                     sizeof(observed)),
                 (int)(sizeof(replacement_contents) - 1U));
    CHECK_STR_EQ(observed, replacement_contents);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    m10_fixture_cleanup(&fixture);
}

TEST(replaced_config_parent_preserves_replacement_and_retires_later_destination) {
    static const char replacement_contents[] =
        "[foreign]\nvalue = replacement-parent-preserved\n";
    m10_fixture_t fixture;
    command_runner_fn previous;
    char replaced_parent[MAX_PATH_LEN];
    char observed[128];
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_snprintf(replaced_parent, sizeof(replaced_parent),
                               "%s.old", fixture.repo_a_git), 0);
    CHECK_EQ_INT(rename(fixture.repo_a_git, replaced_parent), 0);
    CHECK_EQ_INT(m10_make_dir(fixture.repo_a_git), 0);
    CHECK_EQ_INT(m10_write_file(fixture.repo_a_local,
                                replacement_contents), 0);

    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_unchanged(0U));
    CHECK(m10_destination_cleared(1U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, 0);
    CHECK_EQ_INT((long)m10_destinations[1].unsets, (long)M10_KEY_COUNT);
    CHECK(m10_first_git_saw_preflight_failure);
    m10_check_exact_file_only();
    CHECK_EQ_INT(read_file_to_string(fixture.repo_a_local, observed,
                                     sizeof(observed)),
                 (int)(sizeof(replacement_contents) - 1U));
    CHECK_STR_EQ(observed, replacement_contents);
    CHECK(strstr(get_last_error()->message,
                 "inaccessible or changed") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST(replaced_repository_identity_preserves_external_config_and_retires_later_destination) {
    static const char external_contents[] =
        "[fixture]\nvalue = stable-external-config\n";
    m10_fixture_t fixture;
    command_runner_fn previous;
    publication_identity_t live_config;
    char external_config[MAX_PATH_LEN];
    char replaced_repository[MAX_PATH_LEN];
    char observed[128];
    struct stat st;
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(external_config, sizeof(external_config),
                               "%s/external.gitconfig", fixture.root), 0);
    CHECK_EQ_INT(m10_write_file(external_config, external_contents), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                external_config, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_snprintf(replaced_repository,
                               sizeof(replaced_repository), "%s.old",
                               fixture.repo_a), 0);
    CHECK_EQ_INT(rename(fixture.repo_a, replaced_repository), 0);
    CHECK_EQ_INT(m10_make_dir(fixture.repo_a), 0);
    CHECK_EQ_INT(stat(external_config, &st), 0);
    publication_identity_from_stat(&live_config, &st);
    CHECK(publication_identity_equal(&fixture.records[0].post_config,
                                     &live_config));

    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_unchanged(0U));
    CHECK(m10_destination_cleared(1U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, 0);
    CHECK_EQ_INT((long)m10_destinations[1].unsets, (long)M10_KEY_COUNT);
    CHECK(m10_first_git_saw_preflight_failure);
    m10_check_exact_file_only();
    CHECK_EQ_INT(read_file_to_string(external_config, observed,
                                     sizeof(observed)),
                 (int)(sizeof(external_contents) - 1U));
    CHECK_STR_EQ(observed, external_contents);
    CHECK(strstr(get_last_error()->message,
                 "inaccessible or changed") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST(exact_retirement_preserves_ordered_foreign_occurrences) {
    static const char *const before[M10_KEY_COUNT] = {
        M10_FOREIGN_BEFORE_FINGERPRINT,
        "false",
        "ssh",
        "/foreign/before/gpg"
    };
    static const char *const after[M10_KEY_COUNT] = {
        M10_FOREIGN_AFTER_FINGERPRINT,
        "maybe",
        "x509",
        "/foreign/after/gpg"
    };
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    for (size_t key = 0U; key < M10_KEY_COUNT; key++) {
        CHECK_EQ_INT(m10_destination_insert_value(
                         &m10_destinations[0], key, 0U, before[key]), 0);
        CHECK_EQ_INT(m10_destination_append_value(
                         &m10_destinations[0], key, after[key]), 0);
    }

    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), 0);
    run_set_runner(previous);

    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK_EQ_INT((long)m10_destinations[0].unsets, (long)M10_KEY_COUNT);
    for (size_t key = 0U; key < M10_KEY_COUNT; key++) {
        CHECK_EQ_INT((long)m10_destinations[0].value_count[key], 2);
        CHECK_STR_EQ(m10_destinations[0].values[key][0], before[key]);
        CHECK_STR_EQ(m10_destinations[0].values[key][1], after[key]);
    }
    m10_check_exact_file_only();
    m10_fixture_cleanup(&fixture);
}

TEST(partial_failure_keeps_anchor_and_continues_later_destinations) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    m10_destinations[0].fail_unset[M10_GPG_FORMAT] = true;
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    /* The fake command path removes companion values before the signing-key
     * anchor and stops this destination at the first failed companion. The
     * later independent destination still completes. */
    CHECK_EQ_INT((long)cleared, (long)(M10_KEY_COUNT + 1U));
    CHECK_EQ_INT((long)m10_destinations[0].value_count[M10_SIGNING_ENABLED],
                 0);
    CHECK_EQ_INT((long)m10_destinations[0].value_count[M10_SIGNING_KEY], 1);
    CHECK_EQ_INT((long)m10_destinations[0].value_count[M10_GPG_FORMAT], 1);
    CHECK_EQ_INT((long)m10_destinations[0].value_count[M10_GPG_PROGRAM], 1);
    CHECK(m10_destination_cleared(1U));
    CHECK_EQ_INT((long)m10_destinations[0].unsets, 2);
    CHECK_EQ_INT((long)m10_destinations[1].unsets, (long)M10_KEY_COUNT);
    m10_check_exact_file_only();
    CHECK(strstr(get_last_error()->details,
                 "retirement summary") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST(foreign_anchor_with_owned_companions_fails_while_other_destination_retires) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 0U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    CHECK_EQ_INT(safe_strncpy(
                     m10_destinations[1].values[M10_SIGNING_KEY][0],
                     M10_FOREIGN_FINGERPRINT,
                     sizeof(m10_destinations[1]
                                .values[M10_SIGNING_KEY][0])), 0);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, (long)M10_KEY_COUNT);
    CHECK(m10_destination_cleared(0U));
    CHECK(m10_destination_unchanged(1U));
    CHECK_EQ_INT((long)m10_destinations[1].unsets, 0);
    m10_check_exact_file_only();
    CHECK(m10_error_contains("ambiguous repeated attributed values"));
    m10_fixture_cleanup(&fixture);
}

TEST(different_incarnation_in_multi_destination_set_fails_before_git) {
    static const char other_incarnation[] =
        "2222222222222222222222222222222222222222222222222222222222222222";
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    CHECK_EQ_INT(safe_strncpy(fixture.records[1].account_incarnation,
                              other_incarnation,
                              sizeof(fixture.records[1].account_incarnation)),
                 0);
    CHECK_EQ_INT(publication_record_validate(&fixture.records[1]), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT((long)m10_runner_calls, 0);
    CHECK(m10_destination_unchanged(0U));
    CHECK(m10_destination_unchanged(1U));
    CHECK(strstr(get_last_error()->message, "different incarnation") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST(retiring_record_in_multi_destination_set_fails_before_git) {
    m10_fixture_t fixture;
    command_runner_fn previous;
    size_t cleared = 99U;

    CHECK_EQ_INT(m10_fixture_init(&fixture), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_a_local, fixture.repo_a), 0);
    CHECK_EQ_INT(m10_add_record(&fixture, PUBLICATION_SCOPE_LOCAL,
                                fixture.repo_b_local, fixture.repo_b), 0);
    fixture.records[1].state = PUBLICATION_STATE_RETIRING;
    CHECK_EQ_INT(publication_record_validate(&fixture.records[1]), 0);
    CHECK_EQ_INT(m10_write_ledger(&fixture), 0);
    m10_model_records(&fixture);
    previous = run_set_runner(m10_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &fixture.ctx, &fixture.ctx.accounts[0], &cleared), -1);
    run_set_runner(previous);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT((long)m10_runner_calls, 0);
    CHECK(m10_destination_unchanged(0U));
    CHECK(m10_destination_unchanged(1U));
    CHECK(strstr(get_last_error()->message, "incomplete") != NULL);
    m10_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(incomplete_remove_recovery_settles_clean_retiring_destination);
    RUN_TEST(
        incomplete_remove_recovery_rejects_conflicting_incarnation_tombstone);
    RUN_TEST(incomplete_remove_recovery_rejects_nonretiring_tombstone);
    RUN_TEST(
        incomplete_remove_recovery_requires_canonical_tombstone_ledger);
    RUN_TEST(incomplete_remove_recovery_requires_owner_tombstone);
    RUN_TEST(incomplete_remove_recovery_rejects_live_alias_claimant);
    RUN_TEST(incomplete_remove_recovery_ignores_noncanonical_identifiers);
    RUN_TEST(incomplete_remove_recovery_defers_to_exact_live_owner);
    RUN_TEST(incomplete_remove_recovery_rejects_reused_live_owner_id);
    RUN_TEST(removal_from_repository_b_retires_repository_a_and_b_destinations);
    RUN_TEST(removal_outside_repository_ignores_poisoned_git_environment);
    RUN_TEST(local_and_worktree_publications_in_one_repository_are_both_retired);
    RUN_TEST(real_linked_worktree_status_uses_current_shared_config_witness);
    RUN_TEST(linked_repository_witnesses_share_one_local_config_retirement);
    RUN_TEST(status_selects_linked_repository_witness_independent_of_ledger_order);
    RUN_TEST(status_ignores_stale_same_path_membership_in_both_ledger_orders);
    RUN_TEST(stale_later_generation_is_preserved_after_all_record_preflight);
    RUN_TEST(stale_first_destination_does_not_block_later_valid_retirement);
    RUN_TEST(stale_locked_read_failure_cleans_artifacts_and_retry_succeeds);
    RUN_TEST(
        replaced_config_parent_preserves_replacement_and_retires_later_destination);
    RUN_TEST(
        replaced_repository_identity_preserves_external_config_and_retires_later_destination);
    RUN_TEST(exact_retirement_preserves_ordered_foreign_occurrences);
    RUN_TEST(partial_failure_keeps_anchor_and_continues_later_destinations);
    RUN_TEST(
        foreign_anchor_with_owned_companions_fails_while_other_destination_retires);
    RUN_TEST(different_incarnation_in_multi_destination_set_fails_before_git);
    RUN_TEST(retiring_record_in_multi_destination_set_fails_before_git);
TEST_MAIN_END()
