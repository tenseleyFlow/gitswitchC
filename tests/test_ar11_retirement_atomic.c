/* AR-11 M13-M15: exact-value Git retirement is a canonical-file transaction.
 *
 * These regressions deliberately use the production command runner and a
 * real Git executable.  Faults are injected only at the private retirement
 * checkpoints; the canonical config must remain byte-identical until the
 * final rename publishes a completely prepared survivor image. */
#include "test.h"
#include "error.h"
#include "git_ops.h"
#define GITSWITCH_INTERNAL_API
#include "git_ops_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "publication.h"
#include "utils.h"

#include <dirent.h>
#include <sys/wait.h>

#define AT_INCARNATION \
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
#define AT_FINGERPRINT \
    "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define AT_SELECTOR "22223333"
#define AT_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)
#define AT_RECOVERY_HEADER_MAX 512U

static const char at_foreign_lock[] =
    "foreign concurrent Git lock\n";

typedef enum {
    GIT_RETIREMENT_TEST_LOCKED_READ = 1,
    GIT_RETIREMENT_TEST_BEFORE_REMOVE,
    GIT_RETIREMENT_TEST_BEFORE_PUBLISH,
    GIT_RETIREMENT_TEST_BEFORE_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_CLEANUP,
    GIT_RETIREMENT_TEST_FORCE_EXCHANGE_FALLBACK,
    GIT_RETIREMENT_TEST_CLEANUP_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH
} git_retirement_test_stage_t;
typedef bool (*git_retirement_test_hook_fn)(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value);
git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn);

enum at_key_index {
    AT_SSH_COMMAND = 0,
    AT_SIGNING_KEY,
    AT_SIGNING_ENABLED,
    AT_GPG_FORMAT,
    AT_GPG_PROGRAM,
    AT_KEY_COUNT
};

static const char *const at_keys[AT_KEY_COUNT] = {
    GIT_CONFIG_CORE_SSHCOMMAND,
    GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM
};

static const char *const at_removal_order[AT_KEY_COUNT] = {
    GIT_CONFIG_CORE_SSHCOMMAND,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM,
    GIT_CONFIG_USER_SIGNINGKEY
};

static const char *const at_foreign_before[AT_KEY_COUNT] = {
    "ssh -F /foreign/before",
    "1111111111111111111111111111111111111111",
    "false",
    "x509",
    "/foreign/gpg-before"
};

static const char *const at_foreign_after[AT_KEY_COUNT] = {
    "ssh -F /foreign/after",
    "9999999999999999999999999999999999999999",
    "always",
    "ssh",
    "/foreign/gpg-after"
};

typedef struct {
    unsigned char *data;
    size_t length;
} at_bytes_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char repository[MAX_PATH_LEN];
    char git_dir[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char lock_path[MAX_PATH_LEN];
    char alias_path[MAX_PATH_LEN];
    char replacement_path[MAX_PATH_LEN];
    char gpg_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    account_t account;
    publication_record_t publication;
    publication_scope_t scope;
} at_fixture_t;

typedef enum {
    AT_HOOK_NONE = 0,
    AT_HOOK_FAIL_REMOVE,
    AT_HOOK_FAIL_PUBLISH,
    AT_HOOK_LATE_REPLACE_GENERATION,
    AT_HOOK_LATE_HARDLINK,
    AT_HOOK_FAIL_DIRECTORY_SYNC,
    AT_HOOK_REPLACE_FAILURE_LOCK,
    AT_HOOK_REPLACE_CLEANUP_LOCK,
    AT_HOOK_FORCE_FALLBACK,
    AT_HOOK_FALLBACK_REPLACE_CANONICAL,
    AT_HOOK_FALLBACK_REPLACE_LOCK,
    AT_HOOK_FAIL_OWNED_LOCK_UNLINK_ONCE,
    AT_HOOK_FAIL_OWNED_LOCK_UNLINK_TWICE,
    AT_HOOK_REPLACE_POST_EXCHANGE_STAGE,
    AT_HOOK_FAIL_MARKER_PUBLISH,
    AT_HOOK_LARGE_MARKER_RECOVERY
} at_hook_mode_t;

static at_hook_mode_t at_hook_mode;
static char at_hook_config[MAX_PATH_LEN];
static char at_hook_replacement[MAX_PATH_LEN];
static char at_hook_alias[MAX_PATH_LEN];
static char at_hook_key[128];
static char at_hook_stage_path[MAX_PATH_LEN];
static at_bytes_t at_hook_post_exchange_canonical;
static bool at_hook_observed;
static unsigned at_hook_attempts;

static int at_write_all(int fd, const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, cursor + written, length - written);

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

static int at_write_file(const char *path, const char *contents,
                         mode_t mode) {
    int fd;
    int saved_errno;

    if (!path || !contents) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    if (at_write_all(fd, contents, strlen(contents)) != 0 ||
        fsync(fd) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int at_append_file(const char *path, const char *contents) {
    int fd;
    int saved_errno;

    if (!path || !contents) return -1;
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (at_write_all(fd, contents, strlen(contents)) != 0 ||
        fsync(fd) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int at_build_ssh_command(at_fixture_t *fixture) {
    const char *path = getenv("PATH");
    char *saved_path = path ? strdup(path) : NULL;
    int result = -1;
    int restore_result;

    if (!fixture || (path && !saved_path) ||
        setenv("PATH", fixture->root, 1) != 0) {
        free(saved_path);
        return -1;
    }
    result = git_expected_ssh_command(
        &fixture->account, fixture->ssh_command,
        sizeof(fixture->ssh_command));
    restore_result = path ? setenv("PATH", saved_path, 1)
                          : unsetenv("PATH");
    free(saved_path);
    return restore_result == 0 ? result : -1;
}

static size_t at_count_prefixed_artifacts(const char *directory,
                                          const char *prefix) {
    struct dirent *entry;
    DIR *dir;
    size_t count = 0U;
    size_t prefix_length;

    if (!directory || !prefix) return SIZE_MAX;
    prefix_length = strlen(prefix);
    dir = opendir(directory);
    if (!dir) return SIZE_MAX;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, prefix_length) == 0) {
            count++;
        }
    }
    if (closedir(dir) != 0) return SIZE_MAX;
    return count;
}

static size_t at_count_stage_artifacts(const char *directory) {
    return at_count_prefixed_artifacts(directory, ".gitswitch-config-");
}

static size_t at_count_recovery_artifacts(const char *directory) {
    return at_count_prefixed_artifacts(directory, ".gitswitch-recovery-");
}

static int at_pad_file_exact(const char *path, size_t target_length) {
    unsigned char block[4096];
    struct stat before;
    struct stat after;
    size_t remaining;
    int fd;
    int saved_errno;

    if (!path || stat(path, &before) != 0 || before.st_size < 0 ||
        (uintmax_t)before.st_size > (uintmax_t)target_length) {
        errno = EINVAL;
        return -1;
    }
    remaining = target_length - (size_t)before.st_size;
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;

    /* Start on a new line even if a future fixture stops ending in one. Each
     * bounded block after that is an independently valid Git comment line. */
    if (remaining > 0U) {
        static const unsigned char newline = '\n';

        if (at_write_all(fd, &newline, 1U) != 0) goto fail;
        remaining--;
    }
    while (remaining > 0U) {
        size_t chunk = remaining < sizeof(block) ? remaining : sizeof(block);

        if (chunk == 1U) {
            block[0] = '\n';
        } else {
            memset(block, 'x', chunk);
            block[0] = '#';
            block[chunk - 1U] = '\n';
        }
        if (at_write_all(fd, block, chunk) != 0) goto fail;
        remaining -= chunk;
    }
    if (fsync(fd) != 0) goto fail;
    if (close(fd) != 0) return -1;
    if (stat(path, &after) != 0 || after.st_size < 0 ||
        (uintmax_t)after.st_size != (uintmax_t)target_length) {
        errno = EIO;
        return -1;
    }
    return 0;

fail:
    saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return -1;
}

static int at_run(const char *const argv[], char *output,
                  size_t output_size, size_t *output_length) {
    int pipe_fds[2] = {-1, -1};
    pid_t child;
    size_t used = 0U;
    bool truncated = false;
    int status = 0;
    pid_t waited;

    if (output_length) *output_length = 0U;
    if (output && output_size > 0U) output[0] = '\0';
    if (!argv || !argv[0] || pipe(pipe_fds) != 0) return -1;
    child = fork();
    if (child < 0) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        return -1;
    }
    if (child == 0) {
        int dev_null;

        (void)close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0) _exit(125);
        dev_null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (dev_null < 0 || dup2(dev_null, STDERR_FILENO) < 0) _exit(125);
        if (dev_null != STDERR_FILENO) (void)close(dev_null);
        if (pipe_fds[1] != STDOUT_FILENO) (void)close(pipe_fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)close(pipe_fds[1]);
    pipe_fds[1] = -1;
    for (;;) {
        char chunk[512];
        ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));

        if (got > 0) {
            size_t count = (size_t)got;
            size_t room = output && output_size > used + 1U
                              ? output_size - used - 1U
                              : 0U;
            size_t copied = count < room ? count : room;

            if (copied > 0U) memcpy(output + used, chunk, copied);
            used += copied;
            if (copied != count) truncated = true;
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) truncated = true;
        break;
    }
    (void)close(pipe_fds[0]);
    if (output && output_size > 0U) output[used] = '\0';
    if (output_length) *output_length = used;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || truncated || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int at_git_init(const char *repository) {
    const char *const argv[] = {
        "git", "init", "--quiet", repository, NULL
    };

    return at_run(argv, NULL, 0U, NULL) == 0 ? 0 : -1;
}

static int at_git_add(const char *path, const char *key,
                      const char *value) {
    const char *const argv[] = {
        "git", "config", "--file", path, "--no-includes",
        "--add", key, value, NULL
    };

    return at_run(argv, NULL, 0U, NULL) == 0 ? 0 : -1;
}

static int at_git_get_all(const char *path, const char *key,
                          char *output, size_t output_size) {
    const char *const argv[] = {
        "git", "config", "--file", path, "--no-includes",
        "--get-all", key, NULL
    };

    return at_run(argv, output, output_size, NULL);
}

static int at_read_bytes(const char *path, at_bytes_t *bytes) {
    struct stat st;
    unsigned char *data = NULL;
    size_t used = 0U;
    int fd;

    if (!path || !bytes || stat(path, &st) != 0 || st.st_size < 0) return -1;
    memset(bytes, 0, sizeof(*bytes));
    if ((uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) return -1;
    if (st.st_size > 0) {
        data = malloc((size_t)st.st_size);
        if (!data) return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        free(data);
        return -1;
    }
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);

        if (got > 0) {
            used += (size_t)got;
        } else if (got < 0 && errno == EINTR) {
            continue;
        } else {
            (void)close(fd);
            free(data);
            return -1;
        }
    }
    if (close(fd) != 0) {
        free(data);
        return -1;
    }
    bytes->data = data;
    bytes->length = used;
    return 0;
}

static void at_bytes_clear(at_bytes_t *bytes) {
    if (!bytes) return;
    free(bytes->data);
    memset(bytes, 0, sizeof(*bytes));
}

static bool at_file_equals_bytes(const char *path,
                                 const at_bytes_t *expected) {
    at_bytes_t observed;
    bool equal = false;

    if (at_read_bytes(path, &observed) != 0) return false;
    equal = observed.length == expected->length &&
            (observed.length == 0U ||
             memcmp(observed.data, expected->data, observed.length) == 0);
    at_bytes_clear(&observed);
    return equal;
}

static bool at_file_equals_text(const char *path, const char *expected) {
    at_bytes_t observed;
    size_t expected_length;
    bool equal;

    if (!expected || at_read_bytes(path, &observed) != 0) return false;
    expected_length = strlen(expected);
    equal = observed.length == expected_length &&
            (expected_length == 0U ||
             memcmp(observed.data, expected, expected_length) == 0);
    at_bytes_clear(&observed);
    return equal;
}

static int at_parent_path(const char *path, char *parent,
                          size_t parent_size) {
    char *slash;

    if (safe_strncpy(parent, path, parent_size) != 0) return -1;
    slash = strrchr(parent, '/');
    if (!slash || slash == parent) return -1;
    *slash = '\0';
    return 0;
}

static const char *at_owned_value(const at_fixture_t *fixture,
                                  enum at_key_index key) {
    switch (key) {
        case AT_SSH_COMMAND: return fixture->ssh_command;
        case AT_SIGNING_KEY: return AT_FINGERPRINT;
        case AT_SIGNING_ENABLED: return "true";
        case AT_GPG_FORMAT: return "openpgp";
        case AT_GPG_PROGRAM: return fixture->gpg_program;
        default: return NULL;
    }
}

static int at_refresh_publication(at_fixture_t *fixture) {
    char parent[MAX_PATH_LEN];
    struct stat st;
    publication_record_t *publication;

    if (!fixture ||
        at_parent_path(fixture->config_path, parent, sizeof(parent)) != 0) {
        return -1;
    }
    publication = &fixture->publication;
    publication_record_init(publication);
    publication->account_id = fixture->account.id;
    publication->scope = fixture->scope;
    publication->state = PUBLICATION_STATE_PUBLISHED;
    publication->capabilities = PUBLICATION_CAP_DESTINATION |
                                PUBLICATION_CAP_POST_GENERATION |
                                PUBLICATION_CAP_GPG_FINGERPRINT |
                                PUBLICATION_CAP_GPG_PROGRAM |
                                PUBLICATION_CAP_GPG_SELECTOR |
                                PUBLICATION_CAP_GPG_SIGNING_STATE |
                                PUBLICATION_CAP_SSH_COMMAND |
                                PUBLICATION_CAP_SSH_PROGRAM;
    publication->gpg_signing_enabled = true;
    if (safe_strncpy(publication->account_incarnation,
                     fixture->account.incarnation,
                     sizeof(publication->account_incarnation)) != 0 ||
        safe_strncpy(publication->config_path, fixture->config_path,
                     sizeof(publication->config_path)) != 0 ||
        stat(parent, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&publication->config_parent, &st);
    if (fixture->scope != PUBLICATION_SCOPE_GLOBAL) {
        if (safe_strncpy(publication->repository_path,
                         fixture->repository,
                         sizeof(publication->repository_path)) != 0 ||
            stat(fixture->repository, &st) != 0) {
            return -1;
        }
        publication_identity_from_stat(&publication->repository, &st);
    }
    if (stat(fixture->config_path, &st) != 0) return -1;
    publication_identity_from_stat(&publication->post_config, &st);
    if (safe_strncpy(publication->gpg_fingerprint, AT_FINGERPRINT,
                     sizeof(publication->gpg_fingerprint)) != 0 ||
        safe_strncpy(publication->gpg_selector, AT_SELECTOR,
                     sizeof(publication->gpg_selector)) != 0 ||
        safe_strncpy(publication->gpg_program, fixture->gpg_program,
                     sizeof(publication->gpg_program)) != 0 ||
        stat(fixture->gpg_program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&publication->gpg_program_identity, &st);
    if (safe_strncpy(publication->ssh_command, fixture->ssh_command,
                     sizeof(publication->ssh_command)) != 0 ||
        safe_strncpy(publication->ssh_program, fixture->ssh_program,
                     sizeof(publication->ssh_program)) != 0 ||
        stat(fixture->ssh_program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&publication->ssh_program_identity, &st);
    return publication_record_validate(publication);
}

static int at_fixture_init(at_fixture_t *fixture,
                           publication_scope_t scope,
                           bool mixed_values, mode_t mode) {
    char local_config[MAX_PATH_LEN];
    static const char initial_config[] =
        "[fixture]\n\tmarker = keep\n";

    memset(fixture, 0, sizeof(*fixture));
    fixture->scope = scope;
    if (!ts_mkdtemp_trusted(fixture->root, sizeof(fixture->root),
                            "gsw-ar11-atomic") ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        safe_snprintf(fixture->repository, sizeof(fixture->repository),
                      "%s/repository", fixture->root) != 0 ||
        safe_snprintf(fixture->git_dir, sizeof(fixture->git_dir),
                      "%s/.git", fixture->repository) != 0 ||
        safe_snprintf(fixture->gpg_program, sizeof(fixture->gpg_program),
                      "%s/gpg-program", fixture->root) != 0 ||
        safe_snprintf(fixture->ssh_program, sizeof(fixture->ssh_program),
                      "%s/ssh", fixture->root) != 0 ||
        safe_snprintf(fixture->ssh_key, sizeof(fixture->ssh_key),
                      "%s/id_key", fixture->root) != 0 ||
        safe_snprintf(fixture->alias_path, sizeof(fixture->alias_path),
                      "%s/config-alias", fixture->root) != 0 ||
        safe_snprintf(fixture->replacement_path,
                      sizeof(fixture->replacement_path),
                      "%s/config-replacement", fixture->root) != 0 ||
        mkdir(fixture->repository, 0700) != 0 ||
        at_write_file(fixture->gpg_program, "#!/bin/sh\nexit 0\n",
                      0700) != 0 ||
        at_write_file(fixture->ssh_program, "#!/bin/sh\nexit 0\n",
                      0700) != 0 ||
        at_write_file(fixture->ssh_key, "fixture-key\n", 0600) != 0) {
        return -1;
    }
    fixture->account.ssh_enabled = true;
    if (safe_strncpy(fixture->account.ssh_key_path, fixture->ssh_key,
                     sizeof(fixture->account.ssh_key_path)) != 0 ||
        at_build_ssh_command(fixture) != 0) {
        return -1;
    }

    if (scope == PUBLICATION_SCOPE_GLOBAL) {
        if (safe_snprintf(fixture->config_path,
                          sizeof(fixture->config_path),
                          "%s/global-config", fixture->root) != 0 ||
            at_write_file(fixture->config_path, initial_config, mode) != 0) {
            return -1;
        }
    } else {
        if (at_git_init(fixture->repository) != 0 ||
            safe_snprintf(local_config, sizeof(local_config),
                          "%s/config", fixture->git_dir) != 0) {
            return -1;
        }
        if (scope == PUBLICATION_SCOPE_LOCAL) {
            if (safe_strncpy(fixture->config_path, local_config,
                             sizeof(fixture->config_path)) != 0 ||
                at_git_add(fixture->config_path,
                           "fixture.marker", "keep") != 0) {
                return -1;
            }
        } else {
            if (at_git_add(local_config, "extensions.worktreeConfig",
                           "true") != 0 ||
                safe_snprintf(fixture->config_path,
                              sizeof(fixture->config_path),
                              "%s/config.worktree", fixture->git_dir) != 0 ||
                at_write_file(fixture->config_path, initial_config,
                              mode) != 0) {
                return -1;
            }
        }
    }

    for (int key = 0; key < AT_KEY_COUNT; key++) {
        const char *owned = at_owned_value(
            fixture, (enum at_key_index)key);

        if ((mixed_values &&
             at_git_add(fixture->config_path, at_keys[key],
                        at_foreign_before[key]) != 0) ||
            at_git_add(fixture->config_path, at_keys[key], owned) != 0 ||
            (mixed_values &&
             at_git_add(fixture->config_path, at_keys[key],
                        at_foreign_after[key]) != 0)) {
            return -1;
        }
    }
    if (chmod(fixture->config_path, mode) != 0 ||
        safe_snprintf(fixture->lock_path, sizeof(fixture->lock_path),
                      "%s.lock", fixture->config_path) != 0) {
        return -1;
    }

    fixture->account.id = UINT32_C(41);
    fixture->account.incarnation_persisted = true;
    fixture->account.gpg_enabled = true;
    fixture->account.gpg_signing_enabled = true;
    if (safe_strncpy(fixture->account.incarnation, AT_INCARNATION,
                     sizeof(fixture->account.incarnation)) != 0 ||
        safe_strncpy(fixture->account.name, "atomic-retirement",
                     sizeof(fixture->account.name)) != 0 ||
        safe_strncpy(fixture->account.gpg_key_id, AT_SELECTOR,
                     sizeof(fixture->account.gpg_key_id)) != 0) {
        return -1;
    }
    return at_refresh_publication(fixture);
}

static int at_retire(at_fixture_t *fixture, size_t *cleared) {
    const publication_record_t *records[] = {&fixture->publication};

    clear_error();
    return git_retire_account_identity_publications(
        &fixture->account, records, 1U, cleared);
}

static void at_check_foreign_survivors(const at_fixture_t *fixture) {
    char observed[PUBLICATION_SSH_COMMAND_MAX * 2U];
    char expected[PUBLICATION_SSH_COMMAND_MAX * 2U];

    for (int key = 0; key < AT_KEY_COUNT; key++) {
        CHECK_EQ_INT(safe_snprintf(expected, sizeof(expected), "%s\n%s\n",
                                   at_foreign_before[key],
                                   at_foreign_after[key]), 0);
        CHECK_EQ_INT(at_git_get_all(fixture->config_path, at_keys[key],
                                    observed, sizeof(observed)), 0);
        CHECK_STR_EQ(observed, expected);
    }
}

static void at_check_owned_absent(const at_fixture_t *fixture) {
    char observed[256];

    for (int key = 0; key < AT_KEY_COUNT; key++) {
        CHECK_EQ_INT(at_git_get_all(fixture->config_path, at_keys[key],
                                    observed, sizeof(observed)), 1);
        CHECK_STR_EQ(observed, "");
    }
}

static bool at_retirement_hook(git_retirement_test_stage_t stage,
                               const char *path, const char *key,
                               const char *value) {
    char lock_path[MAX_PATH_LEN];

    (void)value;
    if (!path || strcmp(path, at_hook_config) != 0) return false;
    if (at_hook_mode == AT_HOOK_FAIL_REMOVE &&
        stage == GIT_RETIREMENT_TEST_BEFORE_REMOVE && key &&
        strcmp(key, at_hook_key) == 0) {
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_FAIL_PUBLISH &&
        stage == GIT_RETIREMENT_TEST_BEFORE_PUBLISH) {
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_LATE_REPLACE_GENERATION &&
        stage == GIT_RETIREMENT_TEST_BEFORE_EXCHANGE) {
        if (rename(at_hook_replacement, at_hook_config) != 0) return true;
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_LATE_HARDLINK &&
        stage == GIT_RETIREMENT_TEST_BEFORE_EXCHANGE) {
        if (link(at_hook_config, at_hook_alias) != 0) return true;
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_FAIL_DIRECTORY_SYNC &&
        stage == GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC) {
        at_hook_observed = true;
        return true;
    }
    if ((at_hook_mode == AT_HOOK_REPLACE_FAILURE_LOCK &&
         stage == GIT_RETIREMENT_TEST_BEFORE_PUBLISH) ||
        (at_hook_mode == AT_HOOK_REPLACE_CLEANUP_LOCK &&
         stage == GIT_RETIREMENT_TEST_BEFORE_CLEANUP)) {
        if (safe_snprintf(lock_path, sizeof(lock_path), "%s.lock", path) != 0 ||
            unlink(lock_path) != 0 ||
            at_write_file(lock_path, at_foreign_lock, 0600) != 0) {
            return true;
        }
        at_hook_observed = true;
        return at_hook_mode == AT_HOOK_REPLACE_FAILURE_LOCK;
    }
    if ((at_hook_mode == AT_HOOK_FORCE_FALLBACK ||
         at_hook_mode == AT_HOOK_FALLBACK_REPLACE_CANONICAL ||
         at_hook_mode == AT_HOOK_FALLBACK_REPLACE_LOCK) &&
        stage == GIT_RETIREMENT_TEST_FORCE_EXCHANGE_FALLBACK) {
        if (at_hook_mode == AT_HOOK_FALLBACK_REPLACE_CANONICAL &&
            rename(at_hook_replacement, at_hook_config) != 0) {
            return true;
        }
        if (at_hook_mode == AT_HOOK_FALLBACK_REPLACE_LOCK &&
            (safe_snprintf(lock_path, sizeof(lock_path), "%s.lock", path) != 0 ||
             unlink(lock_path) != 0 ||
             at_write_file(lock_path, at_foreign_lock, 0600) != 0)) {
            return true;
        }
        at_hook_observed = true;
        return true;
    }
    if ((at_hook_mode == AT_HOOK_FAIL_OWNED_LOCK_UNLINK_ONCE ||
         at_hook_mode == AT_HOOK_FAIL_OWNED_LOCK_UNLINK_TWICE) &&
        stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK && value &&
        strcmp(value, "canonical lock") == 0) {
        unsigned failure_limit =
            at_hook_mode == AT_HOOK_FAIL_OWNED_LOCK_UNLINK_ONCE ? 1U : 2U;

        at_hook_attempts++;
        if (at_hook_attempts <= failure_limit) {
            at_hook_observed = true;
            errno = EIO;
            return true;
        }
    }
    if (at_hook_mode == AT_HOOK_FAIL_MARKER_PUBLISH &&
        stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK && value &&
        strcmp(value, "canonical lock") == 0) {
        at_hook_attempts++;
        if (at_hook_attempts <= 2U) {
            errno = EIO;
            return true;
        }
    }
    if (at_hook_mode == AT_HOOK_FAIL_MARKER_PUBLISH &&
        stage == GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH) {
        at_hook_observed = true;
        errno = EIO;
        return true;
    }
    if (at_hook_mode == AT_HOOK_LARGE_MARKER_RECOVERY &&
        stage == GIT_RETIREMENT_TEST_LOCKED_READ) {
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_LARGE_MARKER_RECOVERY &&
        stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK && value &&
        strcmp(value, "staging file") == 0) {
        at_hook_attempts++;
        if (at_hook_attempts <= 2U) {
            errno = EIO;
            return true;
        }
    }
    if (at_hook_mode == AT_HOOK_REPLACE_POST_EXCHANGE_STAGE &&
        stage == GIT_RETIREMENT_TEST_AFTER_EXCHANGE && key) {
        at_hook_observed = true;
        if (safe_strncpy(at_hook_stage_path, key,
                         sizeof(at_hook_stage_path)) != 0 ||
            at_read_bytes(path, &at_hook_post_exchange_canonical) != 0 ||
            rename(at_hook_replacement, at_hook_stage_path) != 0) {
            return true;
        }
    }
    return false;
}

static void at_install_hook(const at_fixture_t *fixture,
                            at_hook_mode_t mode, const char *key) {
    at_hook_mode = mode;
    at_hook_observed = false;
    at_hook_attempts = 0U;
    at_bytes_clear(&at_hook_post_exchange_canonical);
    at_hook_stage_path[0] = '\0';
    CHECK_EQ_INT(safe_strncpy(at_hook_config, fixture->config_path,
                              sizeof(at_hook_config)), 0);
    CHECK_EQ_INT(safe_strncpy(at_hook_replacement,
                              fixture->replacement_path,
                              sizeof(at_hook_replacement)), 0);
    CHECK_EQ_INT(safe_strncpy(at_hook_alias, fixture->alias_path,
                              sizeof(at_hook_alias)), 0);
    CHECK_EQ_INT(safe_strncpy(at_hook_key, key ? key : "",
                              sizeof(at_hook_key)), 0);
    (void)git_ops_test_set_retirement_hook(at_retirement_hook);
}

static void at_clear_hook(void) {
    (void)git_ops_test_set_retirement_hook(NULL);
    at_hook_mode = AT_HOOK_NONE;
    at_hook_config[0] = '\0';
    at_hook_replacement[0] = '\0';
    at_hook_alias[0] = '\0';
    at_hook_key[0] = '\0';
    at_hook_stage_path[0] = '\0';
    at_bytes_clear(&at_hook_post_exchange_canonical);
    at_hook_attempts = 0U;
}

static void at_run_mixed_scope_success(publication_scope_t scope) {
    at_fixture_t fixture;
    struct stat st;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, scope, true, 0640), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_foreign_survivors(&fixture);
    CHECK_EQ_INT(stat(fixture.config_path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 07777, 0640);
}

TEST(global_exact_retirement_preserves_ordered_foreign_values) {
    at_run_mixed_scope_success(PUBLICATION_SCOPE_GLOBAL);
}

TEST(local_exact_retirement_preserves_ordered_foreign_values) {
    at_run_mixed_scope_success(PUBLICATION_SCOPE_LOCAL);
}

TEST(worktree_exact_retirement_preserves_ordered_foreign_values) {
    at_run_mixed_scope_success(PUBLICATION_SCOPE_WORKTREE);
}

TEST(duplicate_identical_owned_value_conflicts_without_mutation) {
    at_fixture_t fixture;
    at_bytes_t before;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0600), 0);
    CHECK_EQ_INT(at_git_add(fixture.config_path,
                            GIT_CONFIG_USER_SIGNINGKEY,
                            AT_FINGERPRINT), 0);
    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&before);
}

TEST(existing_canonical_git_lock_blocks_all_mutation_and_retry_succeeds) {
    at_fixture_t fixture;
    at_bytes_t before;
    size_t cleared = 99U;
    int lock_fd;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    lock_fd = open(fixture.lock_path,
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(lock_fd >= 0);
    if (lock_fd >= 0) CHECK_EQ_INT(close(lock_fd), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    at_bytes_clear(&before);
}

TEST(every_ordered_removal_failure_is_byte_atomic_and_retry_succeeds) {
    for (size_t leg = 0U; leg < AT_KEY_COUNT; leg++) {
        at_fixture_t fixture;
        at_bytes_t before;
        struct stat original;
        struct stat after_failure;
        size_t cleared = 99U;

        CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                     false, 0600), 0);
        CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
        CHECK_EQ_INT(stat(fixture.config_path, &original), 0);
        at_install_hook(&fixture, AT_HOOK_FAIL_REMOVE,
                        at_removal_order[leg]);
        CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
        CHECK(at_hook_observed);
        at_clear_hook();
        CHECK_EQ_INT((long)cleared, 0);
        CHECK(at_file_equals_bytes(fixture.config_path, &before));
        CHECK_EQ_INT(stat(fixture.config_path, &after_failure), 0);
        CHECK(original.st_dev == after_failure.st_dev &&
              original.st_ino == after_failure.st_ino);
        CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
        cleared = 99U;
        CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
        CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
        at_check_owned_absent(&fixture);
        at_bytes_clear(&before);
    }
}

TEST(prepublication_failure_is_byte_atomic_and_retry_succeeds) {
    at_fixture_t fixture;
    at_bytes_t before;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_PUBLISH, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    at_bytes_clear(&before);
}

static void at_run_late_replacement_scope(publication_scope_t scope) {
    static const char replacement[] =
        "[fixture]\n\tmarker = external-replacement\n";
    at_fixture_t fixture;
    at_bytes_t expected;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, scope, false, 0600), 0);
    CHECK_EQ_INT(at_write_file(fixture.replacement_path,
                               replacement, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.replacement_path, &expected), 0);
    at_install_hook(&fixture, AT_HOOK_LATE_REPLACE_GENERATION, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &expected));
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &expected));
    at_bytes_clear(&expected);
}

TEST(late_generation_replacement_survives_exchange_in_every_scope) {
    at_run_late_replacement_scope(PUBLICATION_SCOPE_GLOBAL);
    at_run_late_replacement_scope(PUBLICATION_SCOPE_LOCAL);
    at_run_late_replacement_scope(PUBLICATION_SCOPE_WORKTREE);
}

static void at_run_late_hardlink_scope(publication_scope_t scope) {
    at_fixture_t fixture;
    at_bytes_t before;
    struct stat config_stat;
    struct stat alias_stat;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, scope, false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    at_install_hook(&fixture, AT_HOOK_LATE_HARDLINK, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(at_file_equals_bytes(fixture.alias_path, &before));
    CHECK_EQ_INT(stat(fixture.config_path, &config_stat), 0);
    CHECK_EQ_INT(stat(fixture.alias_path, &alias_stat), 0);
    CHECK(config_stat.st_dev == alias_stat.st_dev &&
          config_stat.st_ino == alias_stat.st_ino &&
          config_stat.st_nlink == 2);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

    /* The external alias changes the durable generation even after it is
     * removed. A newly sealed witness is required before another mutation. */
    CHECK_EQ_INT(unlink(fixture.alias_path), 0);
    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    at_bytes_clear(&before);
}

TEST(late_hardlink_race_is_reversed_without_publish_in_every_scope) {
    at_run_late_hardlink_scope(PUBLICATION_SCOPE_GLOBAL);
    at_run_late_hardlink_scope(PUBLICATION_SCOPE_LOCAL);
    at_run_late_hardlink_scope(PUBLICATION_SCOPE_WORKTREE);
}

TEST(postpublication_directory_sync_failure_reconciles_on_retry) {
    at_fixture_t fixture;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_DIRECTORY_SYNC, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

    /* The unchanged publication names the pre-rename generation. The retry
     * may report success only after locking, proving the clean target, and
     * durably syncing both the target and cleanup directory transitions. */
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
}

TEST(retiring_recovery_rejects_live_values_without_forward_unsets) {
    at_fixture_t fixture;
    at_bytes_t before;
    const publication_record_t *records[1];
    git_retirement_recovery_t *recovery = NULL;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    fixture.publication.state = PUBLICATION_STATE_RETIRING;
    records[0] = &fixture.publication;
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    CHECK_EQ_INT(git_retirement_recovery_begin(
                     records, 1U, &recovery), -1);
    CHECK(recovery == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&before);
}

TEST(retiring_recovery_holds_canonical_lock_through_clean_reproof) {
    at_fixture_t fixture;
    const publication_record_t *records[1];
    git_retirement_recovery_t *recovery = NULL;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    fixture.publication.state = PUBLICATION_STATE_RETIRING;
    records[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_recovery_begin(
                     records, 1U, &recovery), 0);
    CHECK(recovery != NULL);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(at_git_add(fixture.config_path,
                            GIT_CONFIG_CORE_SSHCOMMAND,
                            fixture.ssh_command), -1);
    at_check_owned_absent(&fixture);
    CHECK_EQ_INT(git_retirement_recovery_verify(recovery), 0);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(git_retirement_recovery_end(&recovery), 0);
    CHECK(recovery == NULL);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
}

TEST(retiring_recovery_fails_closed_on_uncooperative_reintroduction) {
    at_fixture_t fixture;
    const publication_record_t *records[1];
    git_retirement_recovery_t *recovery = NULL;
    char reintroduced[PUBLICATION_SSH_COMMAND_MAX + 64U];
    char observed[PUBLICATION_SSH_COMMAND_MAX * 2U];
    char expected[PUBLICATION_SSH_COMMAND_MAX + 2U];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    fixture.publication.state = PUBLICATION_STATE_RETIRING;
    records[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_recovery_begin(
                     records, 1U, &recovery), 0);
    CHECK_EQ_INT(safe_snprintf(
                     reintroduced, sizeof(reintroduced),
                     "\n[core]\n\tsshCommand = %s\n",
                     fixture.ssh_command), 0);
    CHECK_EQ_INT(at_append_file(
                     fixture.config_path, reintroduced), 0);
    CHECK_EQ_INT(git_retirement_recovery_verify(recovery), -1);
    CHECK(recovery != NULL);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(git_retirement_recovery_end(&recovery), -1);
    CHECK(recovery == NULL);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(at_git_get_all(
                     fixture.config_path, GIT_CONFIG_CORE_SSHCOMMAND,
                     observed, sizeof(observed)), 0);
    CHECK_EQ_INT(safe_snprintf(
                     expected, sizeof(expected), "%s\n",
                     fixture.ssh_command), 0);
    CHECK_STR_EQ(observed, expected);
}

TEST(foreign_lock_survives_checked_ordinary_failure_cleanup) {
    at_fixture_t fixture;
    at_bytes_t before;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    at_install_hook(&fixture, AT_HOOK_REPLACE_FAILURE_LOCK, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(at_file_equals_text(fixture.lock_path, at_foreign_lock));

    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    at_bytes_clear(&before);
}

TEST(foreign_lock_survives_stale_reconciliation_cleanup_conflict) {
    at_fixture_t fixture;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_DIRECTORY_SYNC, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    at_check_owned_absent(&fixture);

    cleared = 99U;
    at_install_hook(&fixture, AT_HOOK_REPLACE_CLEANUP_LOCK, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_text(fixture.lock_path, at_foreign_lock));
    at_check_owned_absent(&fixture);

    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
}

TEST(forced_unsupported_exchange_fallback_preserves_ordered_survivors) {
    at_fixture_t fixture;
    struct stat before;
    struct stat after;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0640), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &before), 0);
    at_install_hook(&fixture, AT_HOOK_FORCE_FALLBACK, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_foreign_survivors(&fixture);
    CHECK_EQ_INT(stat(fixture.config_path, &after), 0);
    CHECK_EQ_INT(before.st_mode & 07777, after.st_mode & 07777);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
}

TEST(unsupported_exchange_fallback_reproves_lock_and_canonical) {
    static const char replacement[] =
        "[fixture]\n\tmarker = fallback-external-replacement\n";
    at_fixture_t canonical_fixture;
    at_fixture_t lock_fixture;
    at_bytes_t expected_replacement;
    at_bytes_t original;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&canonical_fixture,
                                 PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_write_file(canonical_fixture.replacement_path,
                               replacement, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(canonical_fixture.replacement_path,
                               &expected_replacement), 0);
    at_install_hook(&canonical_fixture,
                    AT_HOOK_FALLBACK_REPLACE_CANONICAL, NULL);
    CHECK_EQ_INT(at_retire(&canonical_fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(canonical_fixture.config_path,
                               &expected_replacement));
    CHECK(access(canonical_fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(canonical_fixture.root), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&canonical_fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(canonical_fixture.config_path,
                               &expected_replacement));
    at_bytes_clear(&expected_replacement);

    CHECK_EQ_INT(at_fixture_init(&lock_fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(lock_fixture.config_path, &original), 0);
    cleared = 99U;
    at_install_hook(&lock_fixture, AT_HOOK_FALLBACK_REPLACE_LOCK, NULL);
    CHECK_EQ_INT(at_retire(&lock_fixture, &cleared), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(lock_fixture.config_path, &original));
    CHECK(at_file_equals_text(lock_fixture.lock_path, at_foreign_lock));
    CHECK_EQ_INT((long)at_count_stage_artifacts(lock_fixture.root), 0);
    CHECK_EQ_INT(unlink(lock_fixture.lock_path), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&lock_fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&lock_fixture);
    at_bytes_clear(&original);
}

TEST(transient_owned_cleanup_failure_retries_with_witness) {
    at_fixture_t fixture;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_OWNED_LOCK_UNLINK_ONCE, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 2);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_clear_hook();
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
}

TEST(two_owned_cleanup_failures_recover_on_next_retirement) {
    at_fixture_t fixture;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_OWNED_LOCK_UNLINK_TWICE, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 2);
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
    CHECK_EQ_INT(access(fixture.lock_path, F_OK), 0);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    at_clear_hook();

    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
}

TEST(failed_private_marker_publish_preserves_exact_empty_lock) {
    at_fixture_t fixture;
    struct stat lock_stat;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_FAIL_MARKER_PUBLISH, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 2);
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
    CHECK_EQ_INT(stat(fixture.lock_path, &lock_stat), 0);
    CHECK(S_ISREG(lock_stat.st_mode));
    CHECK_EQ_INT((long)lock_stat.st_nlink, 1);
    CHECK_EQ_INT((long)lock_stat.st_uid, (long)geteuid());
    CHECK_EQ_INT((long)lock_stat.st_size, 0);
    CHECK(at_file_equals_text(fixture.lock_path, ""));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_clear_hook();

    /* The injected pre-rename failure deliberately leaves the still-exact
     * canonical lock as the only owned artifact. Remove that proven empty
     * lock as an operator would, then ensure stale reconciliation can retry. */
    CHECK(at_file_equals_text(fixture.lock_path, ""));
    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
}

TEST(oversized_recovery_numeric_token_preserves_foreign_lock) {
    static const char malformed_marker[] =
        "gitswitch-recovery-v1 - "
        "99999999999999999999999999999999999999999999999999"
        "99999999999999999999999999999999999999999999999999"
        "99999999999999999999999999999999999999999999999999"
        " 0 0 0 0 0 0 0 0 0\n";
    at_fixture_t fixture;
    at_bytes_t config_before;
    at_bytes_t lock_before;
    struct stat config_identity;
    struct stat config_after;
    struct stat lock_identity;
    struct stat lock_after;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &config_before), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &config_identity), 0);
    CHECK_EQ_INT(at_write_file(fixture.lock_path,
                               malformed_marker, 0600), 0);
    CHECK_EQ_INT(chmod(fixture.lock_path, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.lock_path, &lock_before), 0);
    CHECK_EQ_INT(lstat(fixture.lock_path, &lock_identity), 0);
    CHECK(S_ISREG(lock_identity.st_mode));
    CHECK_EQ_INT(lock_identity.st_mode & 07777, 0600);
    CHECK_EQ_INT((long)lock_identity.st_uid, (long)geteuid());
    CHECK_EQ_INT((long)lock_identity.st_nlink, 1);

    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(at_file_equals_bytes(fixture.config_path, &config_before));
    CHECK(at_file_equals_bytes(fixture.lock_path, &lock_before));
    CHECK_EQ_INT(stat(fixture.config_path, &config_after), 0);
    CHECK(config_after.st_dev == config_identity.st_dev &&
          config_after.st_ino == config_identity.st_ino);
    CHECK_EQ_INT(lstat(fixture.lock_path, &lock_after), 0);
    CHECK(lock_after.st_dev == lock_identity.st_dev &&
          lock_after.st_ino == lock_identity.st_ino);
    CHECK(S_ISREG(lock_after.st_mode));
    CHECK_EQ_INT(lock_after.st_mode & 07777, 0600);
    CHECK_EQ_INT((long)lock_after.st_uid, (long)geteuid());
    CHECK_EQ_INT((long)lock_after.st_nlink, 1);
    CHECK_EQ_INT((long)lock_after.st_size,
                 (long)lock_identity.st_size);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);

    at_bytes_clear(&lock_before);
    at_bytes_clear(&config_before);
    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
}

TEST(maximum_snapshot_recovery_marker_crosses_old_reader_limit) {
    at_fixture_t fixture;
    at_bytes_t before;
    struct stat config_stat;
    struct stat marker_stat;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_pad_file_exact(fixture.config_path,
                                  AT_SNAPSHOT_MAX_BYTES), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &config_stat), 0);
    CHECK_EQ_INT((long)config_stat.st_size,
                 (long)AT_SNAPSHOT_MAX_BYTES);
    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);

    at_install_hook(&fixture, AT_HOOK_LARGE_MARKER_RECOVERY, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 2);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK_EQ_INT(stat(fixture.lock_path, &marker_stat), 0);
    CHECK(S_ISREG(marker_stat.st_mode));
    CHECK_EQ_INT((long)marker_stat.st_nlink, 1);
    CHECK_EQ_INT((long)marker_stat.st_uid, (long)geteuid());
    CHECK_EQ_INT(marker_stat.st_mode & 07777, 0600);
    CHECK(marker_stat.st_size > (off_t)AT_SNAPSHOT_MAX_BYTES);
    CHECK(marker_stat.st_size <=
          (off_t)(AT_SNAPSHOT_MAX_BYTES + AT_RECOVERY_HEADER_MAX));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_clear_hook();

    /* Acquisition must parse the full marker beyond the ordinary snapshot
     * cap, remove its exact stage, and only then begin the fresh retirement. */
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_bytes_clear(&before);
}

TEST(post_exchange_foreign_stage_is_never_reverse_published) {
    static const char foreign_stage[] =
        "[fixture]\n\tmarker = foreign-post-exchange-stage\n";
    at_fixture_t fixture;
    size_t cleared = 99U;
    int retirement_result;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_write_file(fixture.replacement_path,
                               foreign_stage, 0600), 0);
    at_install_hook(&fixture, AT_HOOK_REPLACE_POST_EXCHANGE_STAGE, NULL);
    retirement_result = at_retire(&fixture, &cleared);
    if (!at_hook_observed && retirement_result == 0) {
        at_clear_hook();
        TS_SKIP("persistent-fs", "native atomic name exchange unavailable");
    }
    if (!at_hook_observed) {
        CHECK(at_hook_observed);
        (void)unlink(fixture.lock_path);
        at_clear_hook();
        return;
    }

    CHECK_EQ_INT(retirement_result, -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_hook_post_exchange_canonical.data != NULL);
    CHECK(at_hook_post_exchange_canonical.length > 0U);
    CHECK(at_file_equals_bytes(fixture.config_path,
                               &at_hook_post_exchange_canonical));
    CHECK(!at_file_equals_text(fixture.config_path, foreign_stage));
    CHECK(at_file_equals_text(at_hook_stage_path, foreign_stage));
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

    if (at_hook_stage_path[0] != '\0') (void)unlink(at_hook_stage_path);
    at_clear_hook();
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
}

TEST(hardlinked_destination_is_refused_without_mutation) {
    at_fixture_t fixture;
    at_bytes_t before;
    struct stat config_stat;
    struct stat alias_stat;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(link(fixture.config_path, fixture.alias_path), 0);
    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK(at_file_equals_bytes(fixture.alias_path, &before));
    CHECK_EQ_INT(stat(fixture.config_path, &config_stat), 0);
    CHECK_EQ_INT(stat(fixture.alias_path, &alias_stat), 0);
    CHECK(config_stat.st_dev == alias_stat.st_dev &&
          config_stat.st_ino == alias_stat.st_ino &&
          config_stat.st_nlink == 2);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&before);
}

TEST(outer_abort_restores_exact_bytes_and_exports_reconciled_witness) {
    at_fixture_t fixture;
    at_bytes_t before = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t expected_identity;
    publication_identity_t restored_identity;
    struct stat restored_stat = {0};
    char restored_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;
    int query_result;
    int stat_result;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &before), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;

    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) == 0);

    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    CHECK_EQ_INT(
        (long)git_retirement_transaction_restored_destination_count(
            transaction),
        1);
    CHECK(access(fixture.lock_path, F_OK) == 0);

    memset(&restored_identity, 0, sizeof(restored_identity));
    query_result = git_retirement_transaction_restored_destination(
        transaction, 0U, restored_path,
        sizeof(restored_path), &restored_identity);
    CHECK_EQ_INT(query_result, 0);
    if (query_result == 0) {
        CHECK_STR_EQ(restored_path, fixture.config_path);
        stat_result = stat(fixture.config_path, &restored_stat);
        CHECK_EQ_INT(stat_result, 0);
        if (stat_result == 0) {
            publication_identity_from_stat(&expected_identity,
                                           &restored_stat);
            CHECK(publication_identity_equal(&restored_identity,
                                             &expected_identity));
        }
    }
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

cleanup:
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &before));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&before);
}

TEST(absent_recorded_destination_retires_without_recreation) {
    static const char neighboring_contents[] =
        "neighboring file must remain exact\n";
    at_fixture_t fixture;
    at_bytes_t neighbor_before = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_write_file(fixture.replacement_path,
                               neighboring_contents, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.replacement_path,
                               &neighbor_before), 0);
    CHECK_EQ_INT(unlink(fixture.config_path), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;

    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    errno = 0;
    CHECK(access(fixture.config_path, F_OK) != 0 && errno == ENOENT);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK(at_file_equals_bytes(fixture.replacement_path,
                               &neighbor_before));
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    errno = 0;
    CHECK(access(fixture.config_path, F_OK) != 0 && errno == ENOENT);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK(at_file_equals_bytes(fixture.replacement_path,
                               &neighbor_before));

cleanup:
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    errno = 0;
    CHECK(access(fixture.config_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK(at_file_equals_bytes(fixture.replacement_path,
                               &neighbor_before));
    at_bytes_clear(&neighbor_before);
}

TEST(successful_publication_preserves_nondefault_file_mode) {
    at_fixture_t fixture;
    struct stat before;
    struct stat after;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &before), 0);
    CHECK_EQ_INT(before.st_mode & 07777, 0640);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(stat(fixture.config_path, &after), 0);
    CHECK_EQ_INT(after.st_mode & 07777, 0640);
    at_check_owned_absent(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(global_exact_retirement_preserves_ordered_foreign_values);
    RUN_TEST(local_exact_retirement_preserves_ordered_foreign_values);
    RUN_TEST(worktree_exact_retirement_preserves_ordered_foreign_values);
    RUN_TEST(duplicate_identical_owned_value_conflicts_without_mutation);
    RUN_TEST(existing_canonical_git_lock_blocks_all_mutation_and_retry_succeeds);
    RUN_TEST(every_ordered_removal_failure_is_byte_atomic_and_retry_succeeds);
    RUN_TEST(prepublication_failure_is_byte_atomic_and_retry_succeeds);
    RUN_TEST(late_generation_replacement_survives_exchange_in_every_scope);
    RUN_TEST(late_hardlink_race_is_reversed_without_publish_in_every_scope);
    RUN_TEST(postpublication_directory_sync_failure_reconciles_on_retry);
    RUN_TEST(retiring_recovery_rejects_live_values_without_forward_unsets);
    RUN_TEST(retiring_recovery_holds_canonical_lock_through_clean_reproof);
    RUN_TEST(retiring_recovery_fails_closed_on_uncooperative_reintroduction);
    RUN_TEST(foreign_lock_survives_checked_ordinary_failure_cleanup);
    RUN_TEST(foreign_lock_survives_stale_reconciliation_cleanup_conflict);
    RUN_TEST(forced_unsupported_exchange_fallback_preserves_ordered_survivors);
    RUN_TEST(unsupported_exchange_fallback_reproves_lock_and_canonical);
    RUN_TEST(transient_owned_cleanup_failure_retries_with_witness);
    RUN_TEST(two_owned_cleanup_failures_recover_on_next_retirement);
    RUN_TEST(failed_private_marker_publish_preserves_exact_empty_lock);
    RUN_TEST(oversized_recovery_numeric_token_preserves_foreign_lock);
    RUN_TEST(maximum_snapshot_recovery_marker_crosses_old_reader_limit);
    RUN_TEST(post_exchange_foreign_stage_is_never_reverse_published);
    RUN_TEST(hardlinked_destination_is_refused_without_mutation);
    RUN_TEST(outer_abort_restores_exact_bytes_and_exports_reconciled_witness);
    RUN_TEST(absent_recorded_destination_retires_without_recreation);
    RUN_TEST(successful_publication_preserves_nondefault_file_mode);
TEST_MAIN_END()
