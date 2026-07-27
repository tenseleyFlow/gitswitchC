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
#include <limits.h>
#include <sys/wait.h>

#define AT_INCARNATION \
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
#define AT_FINGERPRINT \
    "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define AT_SELECTOR "22223333"
#define AT_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)
#define AT_RECOVERY_HEADER_MAX 512U
#define AT_PUBLICATION_RESEAL_ATTEMPTS 8U

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
    GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH,
    GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE,
    GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE,
    GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_ORIGINAL_UNLINK,
    GIT_RETIREMENT_TEST_FORCE_FALLBACK_LINK_FAILURE,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_CANONICAL_LINK,
    GIT_RETIREMENT_TEST_AFTER_REVERSE_PUBLISHED_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_AUTHORITY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_CANONICAL_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_TERMINAL_SECOND_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_PUBLISH,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS,
    GIT_RETIREMENT_TEST_AFTER_STABLE_WITNESS_CLOSE
} git_retirement_test_stage_t;
typedef bool (*git_retirement_test_hook_fn)(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value);
git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn);
size_t git_ops_test_set_cleanup_arena_capacity(size_t capacity);
size_t git_ops_test_set_retirement_prelock_witness_budget(
    size_t capacity);
void git_ops_test_terminal_namespace_activity(
    size_t *mutations, size_t *syncs);

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
    AT_HOOK_LARGE_MARKER_RECOVERY,
    AT_HOOK_RACE_TERMINAL_STAGE_CLEANUP,
    AT_HOOK_RACE_TERMINAL_MARKER_CLEANUP,
    AT_HOOK_RACE_MARKER_PUBLICATION,
    AT_HOOK_RACE_PRIVATE_QUARANTINE,
    AT_HOOK_RACE_POST_PROOF_QUARANTINE,
    AT_HOOK_COLLIDE_SETTLED_QUARANTINE,
    AT_HOOK_EXIT_AFTER_PRIVATE_QUARANTINE,
    AT_HOOK_FAIL_AFTER_FALLBACK_UNLINK,
    AT_HOOK_FAIL_FALLBACK_LINK,
    AT_HOOK_FAIL_AFTER_FALLBACK_LINK,
    AT_HOOK_FAIL_AFTER_REVERSE_UNLINK,
    AT_HOOK_EXIT_AFTER_TERMINAL_AUTHORITY_SYNC,
    AT_HOOK_EXIT_AFTER_TERMINAL_CANONICAL_SYNC,
    AT_HOOK_FAIL_RECOVERY_FINAL_PROOF,
    AT_HOOK_FAIL_TERMINAL_PREMARKER,
    AT_HOOK_FAIL_TERMINAL_SECOND_PROOF,
    AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_PUBLISH,
    AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_PUBLISH,
    AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
    AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
    AT_HOOK_FAIL_FREEBSD_PREPUBLICATION_AUTHORITY_CLEANUP,
    AT_HOOK_PRELOCK_CTIME_ONLY_DRIFT,
    AT_HOOK_PRELOCK_SAME_SIZE_REWRITE,
    AT_HOOK_STABLE_CLOSE_CTIME_ONCE,
    AT_HOOK_STABLE_CLOSE_CTIME_REPEATED,
    AT_HOOK_STABLE_CLOSE_SAME_SIZE_REWRITE
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

static int at_write_file_bytes(const char *path,
                               const unsigned char *contents,
                               size_t length, mode_t mode) {
    int fd;
    int saved_errno;

    if (!path || (!contents && length != 0U)) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    if (at_write_all(fd, contents, length) != 0 || fsync(fd) != 0) {
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

static int at_find_single_stage_artifact(const char *directory,
                                         char *path,
                                         size_t path_size) {
    static const char prefix[] = ".gitswitch-config-";
    struct dirent *entry;
    DIR *dir;
    size_t found = 0U;
    int result = -1;

    if (!directory || !path || path_size == 0U) return -1;
    path[0] = '\0';
    dir = opendir(directory);
    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) != 0) {
            continue;
        }
        found++;
        if (found == 1U &&
            safe_snprintf(path, path_size, "%s/%s",
                          directory, entry->d_name) != 0) {
            goto done;
        }
    }
    result = found == 1U ? 0 : -1;
done:
    if (closedir(dir) != 0) result = -1;
    return result;
}

static size_t at_count_recovery_artifacts(const char *directory) {
    return at_count_prefixed_artifacts(directory, ".gitswitch-recovery-");
}

#if defined(__FreeBSD__)
static size_t at_count_lease_artifacts(const char *directory) {
    return at_count_prefixed_artifacts(directory, ".gitswitch-lease-");
}
#endif

#if defined(__FreeBSD__)
static int at_find_single_recovery_artifact(const char *directory,
                                            char *path,
                                            size_t path_size) {
    static const char prefix[] = ".gitswitch-recovery-";
    struct dirent *entry;
    DIR *dir;
    size_t found = 0U;
    int result = -1;

    if (!directory || !path || path_size == 0U) return -1;
    path[0] = '\0';
    dir = opendir(directory);
    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) != 0) {
            continue;
        }
        found++;
        if (found == 1U &&
            safe_snprintf(path, path_size, "%s/%s",
                          directory, entry->d_name) != 0) {
            goto done;
        }
    }
    result = found == 1U ? 0 : -1;
done:
    if (closedir(dir) != 0) result = -1;
    return result;
}
#endif

static int at_read_bytes(const char *path, at_bytes_t *bytes);

static int at_read_retained_recovery(const char *directory,
                                     const char *lock_path,
                                     at_bytes_t *bytes,
                                     char *recovery_path,
                                     size_t recovery_path_size) {
    if (!directory || !lock_path || !bytes || !recovery_path ||
        recovery_path_size == 0U) {
        return -1;
    }
#if defined(__FreeBSD__)
    if (at_find_single_recovery_artifact(
            directory, recovery_path, recovery_path_size) != 0) {
        return -1;
    }
#else
    if (safe_strncpy(recovery_path, lock_path,
                     recovery_path_size) != 0) {
        return -1;
    }
#endif
    return at_read_bytes(recovery_path, bytes);
}

static size_t at_count_cleanup_artifacts(const char *directory) {
    return at_count_prefixed_artifacts(directory, ".gitswitch-cleanup-");
}

#if !defined(__FreeBSD__)
static uint64_t at_cleanup_leaf_hash(const char *leaf) {
    uint64_t hash = UINT64_C(14695981039346656037);

    if (!leaf) return 0U;
    for (const unsigned char *cursor =
             (const unsigned char *)leaf;
         *cursor; cursor++) {
        hash ^= (uint64_t)*cursor;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t at_cleanup_leaf_hash_secondary(const char *leaf) {
    uint64_t hash = UINT64_C(7809847782465536322);
    size_t length;

    if (!leaf) return 0U;
    length = strlen(leaf);
    while (length > 0U) {
        hash ^= (uint64_t)(unsigned char)leaf[--length];
        hash *= UINT64_C(1099511628211);
        hash ^= hash >> 32U;
    }
    return hash;
}

static int at_cleanup_slot_path(
    const char *directory, const char *leaf, bool pending, size_t slot,
    char *path, size_t path_size) {
    return safe_snprintf(
        path, path_size,
        "%s/.gitswitch-cleanup-v2-%016" PRIx64 "%016" PRIx64
        "-%08zx-%s-%04zu",
        directory, at_cleanup_leaf_hash(leaf),
        at_cleanup_leaf_hash_secondary(leaf), strlen(leaf),
        pending ? "pending" : "settled", slot);
}

static int at_find_cleanup_artifact_for_leaf(
    const char *directory, const char *leaf,
    char *path, size_t path_size) {
    if (!directory || !leaf || !path || path_size == 0U) return -1;
    path[0] = '\0';
    for (size_t slot = 0U; slot < 64U; slot++) {
        if (at_cleanup_slot_path(
                directory, leaf, true, slot, path, path_size) != 0) {
            return -1;
        }
        if (access(path, F_OK) == 0) {
            return 0;
        }
        if (errno != ENOENT) return -1;
    }
    path[0] = '\0';
    return -1;
}
#endif

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

static bool at_same_file_state(const struct stat *left,
                               const struct stat *right) {
    if (!left || !right ||
        left->st_dev != right->st_dev ||
        left->st_ino != right->st_ino ||
        left->st_mode != right->st_mode ||
        left->st_uid != right->st_uid ||
        left->st_gid != right->st_gid ||
        left->st_nlink != right->st_nlink ||
        left->st_size != right->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

/* FreeBSD UFS may materialize a link/funlink ctime update after the
 * publication boundary that caused it. In tests which have already proved
 * exact file bytes, that delayed timestamp alone is not evidence that the
 * inherited child mutated the namespace. All durable identity fields and
 * mtime remain strict; every other platform retains the full comparison. */
static bool at_same_file_state_after_exact_bytes(
    const struct stat *left, const struct stat *right) {
    if (at_same_file_state(left, right)) return true;
#if defined(__FreeBSD__)
    return left && right &&
           left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#else
    return false;
#endif
}

static void at_bytes_clear_secure(at_bytes_t *bytes) {
    if (!bytes) return;
    if (bytes->data && bytes->length > 0U) {
        secure_zero_memory(bytes->data, bytes->length);
    }
    at_bytes_clear(bytes);
}

static int at_read_complete_observation(
    const char *path, at_bytes_t *bytes, struct stat *state) {
    struct stat opened_state;
    struct stat read_state;
    struct stat closed_state;
    unsigned char *data = NULL;
    unsigned char extra;
    size_t length = 0U;
    size_t used = 0U;
    int fd = -1;
    int saved_errno = 0;

    if (!path || !bytes || !state) {
        errno = EINVAL;
        return -1;
    }
    memset(bytes, 0, sizeof(*bytes));
    memset(state, 0, sizeof(*state));
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) goto failed;
    if (fstat(fd, &opened_state) != 0) goto failed;
    if (!S_ISREG(opened_state.st_mode) || opened_state.st_size < 0 ||
        (uintmax_t)opened_state.st_size >
            (uintmax_t)AT_SNAPSHOT_MAX_BYTES) {
        errno = ESTALE;
        goto failed;
    }
    length = (size_t)opened_state.st_size;
    if (length > 0U) {
        data = malloc(length);
        if (!data) goto failed;
    }
    while (used < length) {
        ssize_t got = read(fd, data + used, length - used);

        if (got > 0) {
            used += (size_t)got;
        } else if (got < 0 && errno == EINTR) {
            continue;
        } else {
            if (got == 0) errno = ESTALE;
            goto failed;
        }
    }
    for (;;) {
        ssize_t got = read(fd, &extra, 1U);

        if (got == 0) break;
        if (got < 0 && errno == EINTR) continue;
        if (got > 0) errno = ESTALE;
        goto failed;
    }
    {
        int sync_result;

        do {
            sync_result = fsync(fd);
        } while (sync_result != 0 && errno == EINTR);
        if (sync_result != 0) goto failed;
    }
    if (fstat(fd, &read_state) != 0) goto failed;
    if (!at_same_file_state(&opened_state, &read_state)) {
        errno = ESTALE;
        goto failed;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto failed;
    }
    fd = -1;
    if (lstat(path, &closed_state) != 0) goto failed;
    if (!S_ISREG(closed_state.st_mode) ||
        !at_same_file_state(&read_state, &closed_state)) {
        errno = ESTALE;
        goto failed;
    }
    bytes->data = data;
    bytes->length = length;
    *state = closed_state;
    return 0;

failed:
    saved_errno = errno != 0 ? errno : ESTALE;
    if (fd >= 0) (void)close(fd);
    if (data) {
        if (length > 0U) secure_zero_memory(data, length);
        free(data);
    }
    errno = saved_errno;
    return -1;
}

static int at_reseal_post_config(
    const char *path, publication_identity_t *identity) {
    static const struct timespec retry_pause = {0, 2000000L};

    if (!path || !identity) {
        errno = EINVAL;
        return -1;
    }
    for (unsigned attempt = 0U;
         attempt < AT_PUBLICATION_RESEAL_ATTEMPTS; attempt++) {
        at_bytes_t first = {0};
        at_bytes_t second = {0};
        struct stat first_state = {0};
        struct stat second_state = {0};
        bool stable = false;
        int observation_errno = 0;

        if (at_read_complete_observation(
                path, &first, &first_state) != 0) {
            observation_errno = errno;
        } else if (at_read_complete_observation(
                       path, &second, &second_state) != 0) {
            observation_errno = errno;
        } else {
            stable =
                at_same_file_state(&first_state, &second_state) &&
                first.length == second.length &&
                (first.length == 0U ||
                 memcmp(first.data, second.data, first.length) == 0);
        }
        at_bytes_clear_secure(&first);
        at_bytes_clear_secure(&second);
        if (stable) {
            publication_identity_from_stat(identity, &second_state);
            return 0;
        }
        if (observation_errno != 0 &&
            observation_errno != ESTALE) {
            errno = observation_errno;
            return -1;
        }
        if (attempt + 1U < AT_PUBLICATION_RESEAL_ATTEMPTS) {
            int sleep_result;

            do {
                sleep_result = nanosleep(&retry_pause, NULL);
            } while (sleep_result != 0 && errno == EINTR);
            if (sleep_result != 0) return -1;
        }
    }
    errno = ESTALE;
    return -1;
}

static bool at_publication_identity_equal_except_ctime(
    const publication_identity_t *left,
    const publication_identity_t *right) {
    return left && right &&
           left->present == right->present &&
           left->device == right->device &&
           left->inode == right->inode &&
           left->mode == right->mode &&
           left->uid == right->uid &&
           left->gid == right->gid &&
           left->link_count == right->link_count &&
           left->size == right->size &&
           left->mtime_seconds == right->mtime_seconds &&
           left->mtime_nanoseconds == right->mtime_nanoseconds;
}

static bool at_canonical_lock_is_held(const char *lock_path) {
    pid_t probe;
    pid_t waited;
    int status = 0;

    if (!lock_path) return false;
    probe = fork();
    if (probe < 0) return false;
    if (probe == 0) {
        struct flock claim;
        int fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);

        if (fd < 0) _exit(2);
        memset(&claim, 0, sizeof(claim));
        claim.l_type = F_WRLCK;
        claim.l_whence = SEEK_SET;
        if (fcntl(fd, F_SETLK, &claim) == -1 &&
            (errno == EACCES || errno == EAGAIN)) {
            _exit(0);
        }
        _exit(1);
    }
    do {
        waited = waitpid(probe, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == probe && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
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

static int at_sync_parent_directory(const char *path) {
    char parent[MAX_PATH_LEN];
    int fd = -1;
    int result;
    int saved_errno;

    if (!path ||
        at_parent_path(path, parent, sizeof(parent)) != 0) {
        errno = EINVAL;
        return -1;
    }
    fd = open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return -1;
    do {
        result = fsync(fd);
    } while (result != 0 && errno == EINTR);
    saved_errno = errno;
    if (close(fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    errno = saved_errno;
    return result;
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
    if (at_reseal_post_config(
            fixture->config_path, &publication->post_config) != 0) {
        return -1;
    }
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

static bool at_owned_values_are_exact(const at_fixture_t *fixture) {
    char observed[PUBLICATION_SSH_COMMAND_MAX * 2U];
    char expected[PUBLICATION_SSH_COMMAND_MAX * 2U];

    if (!fixture) return false;
    for (int key = 0; key < AT_KEY_COUNT; key++) {
        if (safe_snprintf(expected, sizeof(expected), "%s\n",
                          at_owned_value(fixture, key)) != 0 ||
            at_git_get_all(fixture->config_path, at_keys[key],
                           observed, sizeof(observed)) != 0 ||
            strcmp(observed, expected) != 0) {
            return false;
        }
    }
    return true;
}

/* FreeBSD UFS may expose the completed hardlink/unlink ctime only after a
 * later observation. Retry solely when the failed retirement is one of the
 * three strict pre-mutation generation-rejection paths and every independent
 * observation proves zero mutation plus an exact-byte ctime-only successor. */
static int at_retire_with_bounded_ctime_reseal(
    at_fixture_t *fixture, const at_bytes_t *expected,
    size_t *cleared, unsigned *successful_attempt) {
    char expected_capture_error[512];
    char expected_prelock_error[512];
    char expected_stale_error[512];
    const char *scope_label;
    unsigned attempt_limit = 1U;

    if (!fixture || !expected || !cleared) {
        errno = EINVAL;
        return -1;
    }
    scope_label =
        fixture->publication.scope == PUBLICATION_SCOPE_GLOBAL
            ? "--global"
            : (fixture->publication.scope == PUBLICATION_SCOPE_LOCAL
                   ? "--local"
                   : "--worktree");
    if (safe_snprintf(
            expected_capture_error, sizeof(expected_capture_error),
            "account '%s' destination 1 source witness (%s): "
            "Git retirement source changed while capturing its pre-lock "
            "witness (%s)",
            fixture->account.name, scope_label,
            strerror(ESTALE)) != 0 ||
        safe_snprintf(
            expected_prelock_error, sizeof(expected_prelock_error),
            "account '%s' destination 1 preparation (%s): "
            "Git retirement destination changed before its canonical lock "
            "was acquired",
            fixture->account.name, scope_label) != 0 ||
        safe_snprintf(
            expected_stale_error, sizeof(expected_stale_error),
            "account '%s' destination 1 preparation (%s): "
            "Stale Git retirement destination still contains attributed "
            "values",
            fixture->account.name, scope_label) != 0) {
        return -1;
    }
#if defined(__FreeBSD__)
    attempt_limit = AT_PUBLICATION_RESEAL_ATTEMPTS;
#endif
    if (successful_attempt) {
        *successful_attempt = attempt_limit;
    }
    for (unsigned attempt = 0U; attempt < attempt_limit; attempt++) {
        publication_identity_t sealed =
            fixture->publication.post_config;
        publication_identity_t live;
        struct stat live_stat;
        struct stat lock_stat;
        error_context_t retirement_error;
        bool capture_rejection;
        bool prelock_rejection;
        bool stale_rejection;
        bool lock_absent;
        bool retry_shape;
        int retire_result;

        *cleared = 99U;
        retire_result = at_retire(fixture, cleared);
        if (retire_result == 0) {
            if (successful_attempt) *successful_attempt = attempt;
            return 0;
        }
        retirement_error = *get_last_error();
        capture_rejection =
            strcmp(
                retirement_error.function,
                "git_retirement_capture_prelock_witness") == 0 &&
            strcmp(retirement_error.message,
                   expected_capture_error) == 0;
        prelock_rejection =
            strcmp(
                retirement_error.function,
                "git_retirement_prepare_group_atomic") == 0 &&
            strcmp(retirement_error.message,
                   expected_prelock_error) == 0;
        stale_rejection =
            strcmp(
                retirement_error.function,
                "git_retirement_prepare_stale_group_atomic") == 0 &&
            strcmp(retirement_error.message,
                   expected_stale_error) == 0;
        errno = 0;
        lock_absent =
            lstat(fixture->lock_path, &lock_stat) != 0 &&
            errno == ENOENT;
        retry_shape =
            retirement_error.code == ERR_GIT_CONFIG_FAILED &&
            (capture_rejection || prelock_rejection ||
             stale_rejection) &&
            *cleared == 0U &&
            at_file_equals_bytes(fixture->config_path, expected) &&
            at_owned_values_are_exact(fixture) &&
            lock_absent &&
            stat(fixture->config_path, &live_stat) == 0;
        if (retry_shape) {
            publication_identity_from_stat(&live, &live_stat);
            retry_shape =
                at_publication_identity_equal_except_ctime(
                    &sealed, &live) &&
                !publication_identity_equal(&sealed, &live);
        }
        if (!retry_shape) {
            fprintf(
                stderr,
                "  Unexpected ctime-reseal failure: code=%d "
                "function=%s message=%s cleared=%zu lock_absent=%d\n",
                (int)retirement_error.code,
                retirement_error.function,
                retirement_error.message, *cleared,
                lock_absent ? 1 : 0);
            return -1;
        }
        if (at_reseal_post_config(
                fixture->config_path,
                &fixture->publication.post_config) != 0 ||
            publication_record_validate(&fixture->publication) != 0) {
            return -1;
        }
    }
    errno = EAGAIN;
    return -1;
}

static int at_finish_terminal_capture_warning(
    git_retirement_transaction_t **transaction,
    char *output, size_t output_size) {
    FILE *capture = NULL;
    int saved_stderr = -1;
    int result = -1;
    int finish_result;
    size_t length;

    if (!transaction || !output || output_size == 0U ||
        fflush(stderr) != 0 ||
        (capture = tmpfile()) == NULL ||
        (saved_stderr = dup(STDERR_FILENO)) < 0 ||
        dup2(fileno(capture), STDERR_FILENO) != STDERR_FILENO) {
        goto done;
    }
    finish_result =
        git_retirement_transaction_finish_terminal_rollback(transaction);
    if (fflush(stderr) != 0 ||
        dup2(saved_stderr, STDERR_FILENO) != STDERR_FILENO ||
        fseek(capture, 0L, SEEK_SET) != 0) {
        goto done;
    }
    length = fread(output, 1U, output_size - 1U, capture);
    if (ferror(capture)) goto done;
    output[length] = '\0';
    result = finish_result;

done:
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        (void)close(saved_stderr);
    }
    if (capture) (void)fclose(capture);
    return result;
}

static int at_replace_cleanup_target(const char *config_path,
                                     const char *leaf) {
    char parent[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];

    if (!config_path || !leaf ||
        at_parent_path(config_path, parent, sizeof(parent)) != 0 ||
        safe_snprintf(target, sizeof(target), "%s/%s",
                      parent, leaf) != 0 ||
        safe_strncpy(at_hook_stage_path, target,
                     sizeof(at_hook_stage_path)) != 0 ||
        unlink(target) != 0 ||
        rename(at_hook_replacement, target) != 0) {
        return -1;
    }
    return 0;
}

static int at_replace_canonical_lock(const char *config_path) {
    char target[MAX_PATH_LEN];

    if (!config_path ||
        safe_snprintf(target, sizeof(target), "%s.lock",
                      config_path) != 0 ||
        safe_strncpy(at_hook_stage_path, target,
                     sizeof(at_hook_stage_path)) != 0 ||
        unlink(target) != 0 ||
        rename(at_hook_replacement, target) != 0) {
        return -1;
    }
    return 0;
}

static int at_mutate_prelock_source(const char *path, bool rewrite_bytes) {
    struct stat before;
    struct stat after;
    struct timespec times[2];
    unsigned char byte;
    int fd = -1;
    int saved_errno;

    if (!path || stat(path, &before) != 0) return -1;
    if (!rewrite_bytes) {
        mode_t alternate = (before.st_mode & 07777) ^ S_IXUSR;
        struct timespec pause = {0, 2000000L};

        for (unsigned attempt = 0U; attempt < 4U; attempt++) {
            if (chmod(path, alternate) != 0 ||
                nanosleep(&pause, NULL) != 0 ||
                chmod(path, before.st_mode & 07777) != 0 ||
                stat(path, &after) != 0) {
                return -1;
            }
            if (!at_same_file_state(&before, &after)) return 0;
        }
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || pread(fd, &byte, 1U, 0) != 1) goto failed;
    byte ^= UINT8_C(0x01);
    if (pwrite(fd, &byte, 1U, 0) != 1 || fsync(fd) != 0) goto failed;
#if defined(__APPLE__)
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (futimens(fd, times) != 0 || fsync(fd) != 0 ||
        fstat(fd, &after) != 0) {
        goto failed;
    }
    (void)close(fd);
    return 0;

failed:
    saved_errno = errno;
    if (fd >= 0) (void)close(fd);
    errno = saved_errno;
    return -1;
}

static bool at_retirement_hook(git_retirement_test_stage_t stage,
                               const char *path, const char *key,
                               const char *value) {
    char lock_path[MAX_PATH_LEN];

    (void)value;
    if ((at_hook_mode == AT_HOOK_PRELOCK_CTIME_ONLY_DRIFT ||
         at_hook_mode == AT_HOOK_PRELOCK_SAME_SIZE_REWRITE) &&
        stage == GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS) {
        int mutation_result = at_mutate_prelock_source(
            path, at_hook_mode == AT_HOOK_PRELOCK_SAME_SIZE_REWRITE);

        at_hook_attempts++;
        at_hook_observed = mutation_result == 0;
        return mutation_result != 0;
    }
    if ((at_hook_mode == AT_HOOK_STABLE_CLOSE_CTIME_ONCE ||
         at_hook_mode == AT_HOOK_STABLE_CLOSE_CTIME_REPEATED ||
        at_hook_mode == AT_HOOK_STABLE_CLOSE_SAME_SIZE_REWRITE) &&
        stage == GIT_RETIREMENT_TEST_AFTER_STABLE_WITNESS_CLOSE &&
        path &&
        (at_hook_attempts == 0U ||
         (at_hook_mode == AT_HOOK_STABLE_CLOSE_CTIME_REPEATED &&
          at_hook_attempts < 3U))) {
        int mutation_result = at_mutate_prelock_source(
            path,
            at_hook_mode ==
                AT_HOOK_STABLE_CLOSE_SAME_SIZE_REWRITE);

        at_hook_attempts++;
        at_hook_observed = mutation_result == 0;
        return mutation_result != 0;
    }
    if (at_hook_mode == AT_HOOK_FAIL_RECOVERY_FINAL_PROOF &&
        stage ==
            GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF) {
        at_hook_observed = true;
        return true;
    }
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
         at_hook_mode == AT_HOOK_FALLBACK_REPLACE_LOCK ||
         at_hook_mode == AT_HOOK_FAIL_AFTER_FALLBACK_UNLINK ||
         at_hook_mode == AT_HOOK_FAIL_FALLBACK_LINK ||
         at_hook_mode == AT_HOOK_FAIL_AFTER_FALLBACK_LINK ||
         at_hook_mode == AT_HOOK_FAIL_AFTER_REVERSE_UNLINK) &&
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
    if (at_hook_mode == AT_HOOK_FAIL_AFTER_FALLBACK_UNLINK &&
        stage == GIT_RETIREMENT_TEST_AFTER_FALLBACK_ORIGINAL_UNLINK) {
        at_hook_attempts++;
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_FAIL_FALLBACK_LINK &&
        stage == GIT_RETIREMENT_TEST_FORCE_FALLBACK_LINK_FAILURE) {
        at_hook_attempts++;
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_FAIL_AFTER_FALLBACK_LINK &&
        stage == GIT_RETIREMENT_TEST_AFTER_FALLBACK_CANONICAL_LINK) {
        at_hook_attempts++;
        at_hook_observed = true;
        return true;
    }
    if (at_hook_mode == AT_HOOK_FAIL_AFTER_REVERSE_UNLINK &&
        stage == GIT_RETIREMENT_TEST_AFTER_REVERSE_PUBLISHED_UNLINK) {
        at_hook_attempts++;
        if (at_hook_attempts == 1U) {
            at_hook_observed = true;
            return true;
        }
    }
    if (at_hook_mode == AT_HOOK_EXIT_AFTER_TERMINAL_AUTHORITY_SYNC &&
        stage == GIT_RETIREMENT_TEST_AFTER_TERMINAL_AUTHORITY_SYNC) {
        _exit(74);
    }
    if (at_hook_mode == AT_HOOK_EXIT_AFTER_TERMINAL_CANONICAL_SYNC &&
        stage == GIT_RETIREMENT_TEST_AFTER_TERMINAL_CANONICAL_SYNC) {
        _exit(75);
    }
    if (stage ==
            GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_PUBLISH) {
        if (at_hook_mode ==
            AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_PUBLISH) {
            _exit(78);
        }
        if (at_hook_mode ==
            AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_PUBLISH) {
            at_hook_observed = true;
            return true;
        }
    }
    if (stage ==
            GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC) {
        if (at_hook_mode ==
            AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC) {
            _exit(79);
        }
        if (at_hook_mode ==
            AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC) {
            at_hook_observed = true;
            return true;
        }
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
    if (at_hook_mode == AT_HOOK_FAIL_TERMINAL_PREMARKER &&
        stage == GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH) {
        at_hook_observed = true;
        errno = EIO;
        return true;
    }
    if (at_hook_mode ==
            AT_HOOK_FAIL_FREEBSD_PREPUBLICATION_AUTHORITY_CLEANUP &&
        stage == GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH) {
        errno = EIO;
        return true;
    }
    if (at_hook_mode ==
            AT_HOOK_FAIL_FREEBSD_PREPUBLICATION_AUTHORITY_CLEANUP &&
        stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK && value &&
        strcmp(value, "private recovery authority") == 0) {
        at_hook_attempts++;
        at_hook_observed = true;
        errno = EIO;
        return true;
    }
    if (at_hook_mode == AT_HOOK_FAIL_TERMINAL_SECOND_PROOF &&
        stage == GIT_RETIREMENT_TEST_BEFORE_TERMINAL_SECOND_PROOF) {
        at_hook_observed = true;
        errno = EIO;
        return true;
    }
    if (at_hook_mode == AT_HOOK_RACE_MARKER_PUBLICATION &&
        stage == GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH) {
        char parent[MAX_PATH_LEN];

        at_hook_attempts++;
        if (!key ||
            at_parent_path(path, parent, sizeof(parent)) != 0 ||
            safe_snprintf(at_hook_alias, sizeof(at_hook_alias), "%s/%s",
                          parent, key) != 0 ||
            at_replace_canonical_lock(path) != 0) {
            return true;
        }
        at_hook_observed = true;
        return false;
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
    if (((at_hook_mode == AT_HOOK_RACE_TERMINAL_STAGE_CLEANUP &&
          value &&
          strcmp(value, "terminal rollback staging file") == 0) ||
         (at_hook_mode == AT_HOOK_RACE_TERMINAL_MARKER_CLEANUP &&
          value &&
          strcmp(value, "terminal rollback recovery marker") == 0)) &&
        stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK && key) {
        at_hook_attempts++;
        if (at_replace_cleanup_target(path, key) != 0) return true;
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_RACE_PRIVATE_QUARANTINE &&
        stage == GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE &&
        key && value) {
        char parent[MAX_PATH_LEN];
        char quarantine[MAX_PATH_LEN];

        at_hook_attempts++;
        if (at_parent_path(path, parent, sizeof(parent)) != 0 ||
            safe_snprintf(quarantine, sizeof(quarantine), "%s/%s",
                          parent, value) != 0 ||
            safe_strncpy(at_hook_stage_path, quarantine,
                         sizeof(at_hook_stage_path)) != 0 ||
            unlink(quarantine) != 0 ||
            rename(at_hook_replacement, quarantine) != 0) {
            return true;
        }
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_RACE_POST_PROOF_QUARANTINE &&
        stage == GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF &&
        key && value) {
        char parent[MAX_PATH_LEN];
        char quarantine[MAX_PATH_LEN];

        at_hook_attempts++;
        if (at_parent_path(path, parent, sizeof(parent)) != 0 ||
            safe_snprintf(quarantine, sizeof(quarantine), "%s/%s",
                          parent, value) != 0 ||
            safe_strncpy(at_hook_stage_path, quarantine,
                         sizeof(at_hook_stage_path)) != 0 ||
            unlink(quarantine) != 0 ||
            rename(at_hook_replacement, quarantine) != 0) {
            return true;
        }
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_COLLIDE_SETTLED_QUARANTINE &&
        stage == GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE &&
        key && value) {
        char parent[MAX_PATH_LEN];
        char settled_name[NAME_MAX + 1U];
        char settled_path[MAX_PATH_LEN];
        char *state;

        at_hook_attempts++;
        if (safe_strncpy(settled_name, value,
                         sizeof(settled_name)) != 0 ||
            (state = strstr(settled_name, "-pending-")) == NULL) {
            return true;
        }
        memcpy(state, "-settled-", sizeof("-settled-") - 1U);
        if (at_parent_path(path, parent, sizeof(parent)) != 0 ||
            safe_snprintf(settled_path, sizeof(settled_path), "%s/%s",
                          parent, settled_name) != 0 ||
            safe_strncpy(at_hook_stage_path, settled_path,
                         sizeof(at_hook_stage_path)) != 0 ||
            rename(at_hook_replacement, settled_path) != 0) {
            return true;
        }
        at_hook_observed = true;
        return false;
    }
    if (at_hook_mode == AT_HOOK_EXIT_AFTER_PRIVATE_QUARANTINE &&
        stage == GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE &&
        key && value) {
        _exit(73);
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

TEST(ordinary_prelock_ctime_only_drift_is_rejected) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    at_install_hook(&fixture, AT_HOOK_PRELOCK_CTIME_ONLY_DRIFT, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_clear_hook();
    at_bytes_clear(&original);
}

TEST(prelock_same_size_rewrite_with_restored_mtime_is_rejected) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    publication_identity_t current_identity;
    struct stat current_stat;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    at_install_hook(&fixture, AT_HOOK_PRELOCK_SAME_SIZE_REWRITE, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(!at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(stat(fixture.config_path, &current_stat), 0);
    publication_identity_from_stat(&current_identity, &current_stat);
    CHECK(at_publication_identity_equal_except_ctime(
        &fixture.publication.post_config, &current_identity));
    CHECK(!publication_identity_equal(
        &fixture.publication.post_config, &current_identity));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_clear_hook();
    at_bytes_clear(&original);
}

static void at_run_stable_close_ctime_convergence(
    at_hook_mode_t mode, unsigned expected_mutations) {
    at_fixture_t fixture;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t restored_identity;
    char restored_path[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) return;
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    at_install_hook(&fixture, mode, NULL);
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, restored_path,
                     sizeof(restored_path), &restored_identity), 0);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts,
                 (long)expected_mutations);
    at_clear_hook();
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
}

TEST(restored_witness_reproves_one_delayed_ctime_step) {
    at_run_stable_close_ctime_convergence(
        AT_HOOK_STABLE_CLOSE_CTIME_ONCE, 1U);
}

TEST(restored_witness_reproves_repeated_delayed_ctime_steps) {
    at_run_stable_close_ctime_convergence(
        AT_HOOK_STABLE_CLOSE_CTIME_REPEATED, 3U);
}

TEST(restored_witness_rejects_same_size_rewrite_with_restored_mtime) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t restored_identity;
    char restored_path[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) {
        at_bytes_clear(&original);
        return;
    }
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    at_install_hook(
        &fixture, AT_HOOK_STABLE_CLOSE_SAME_SIZE_REWRITE, NULL);
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, restored_path,
                     sizeof(restored_path), &restored_identity), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK(!at_file_equals_bytes(fixture.config_path, &original));
    at_clear_hook();
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    at_bytes_clear(&original);
}

TEST(prelock_witness_aggregate_budget_fails_before_lock_mutation) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    size_t previous_budget =
        git_ops_test_set_retirement_prelock_witness_budget(16U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(errno, EFBIG);
    CHECK(strstr(get_last_error()->message,
                 "bounded transaction budget") != NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

    git_ops_test_set_retirement_prelock_witness_budget(previous_budget);
    at_bytes_clear(&original);
}

TEST(early_prelock_failure_preserves_standard_input_descriptor) {
    at_fixture_t fixture;
    size_t previous_budget =
        git_ops_test_set_retirement_prelock_witness_budget(16U);
    size_t cleared = 99U;
    int saved_stdin = -1;
    int null_fd = -1;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    saved_stdin = dup(STDIN_FILENO);
    CHECK(saved_stdin >= 0);
    null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(null_fd >= 0);
    if (saved_stdin >= 0 && null_fd >= 0) {
        CHECK_EQ_INT(dup2(null_fd, STDIN_FILENO), STDIN_FILENO);
        CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
        CHECK_EQ_INT((long)cleared, 0);
        CHECK(fcntl(STDIN_FILENO, F_GETFD) >= 0);
        CHECK_EQ_INT(dup2(saved_stdin, STDIN_FILENO), STDIN_FILENO);
    }
    if (null_fd >= 0) CHECK_EQ_INT(close(null_fd), 0);
    if (saved_stdin >= 0) CHECK_EQ_INT(close(saved_stdin), 0);
    git_ops_test_set_retirement_prelock_witness_budget(previous_budget);
}

TEST(absent_first_later_witness_budget_failure_has_no_namespace_mutation) {
    static const char absent_original[] =
        "[fixture]\n\tmarker = originally-absent\n";
    at_fixture_t fixture;
    at_bytes_t present_before = {0};
    publication_record_t absent_publication;
    const account_t *accounts[2];
    const publication_record_t *publications[2];
    git_retirement_transaction_t *transaction = NULL;
    struct stat absent_stat;
    char absent_path[MAX_PATH_LEN];
    char absent_lock_path[MAX_PATH_LEN];
    size_t mutations_before = 0U;
    size_t mutations_after = 0U;
    size_t syncs_before = 0U;
    size_t syncs_after = 0U;
    size_t previous_budget =
        git_ops_test_set_retirement_prelock_witness_budget(16U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &present_before), 0);
    CHECK_EQ_INT(safe_snprintf(absent_path, sizeof(absent_path),
                               "%s/aa-absent-config", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(absent_lock_path,
                               sizeof(absent_lock_path),
                               "%s.lock", absent_path), 0);
    CHECK_EQ_INT(at_write_file(absent_path, absent_original, 0600), 0);
    CHECK_EQ_INT(stat(absent_path, &absent_stat), 0);
    absent_publication = fixture.publication;
    CHECK_EQ_INT(safe_strncpy(absent_publication.config_path,
                              absent_path,
                              sizeof(absent_publication.config_path)), 0);
    publication_identity_from_stat(
        &absent_publication.post_config, &absent_stat);
    CHECK_EQ_INT(unlink(absent_path), 0);
    accounts[0] = &fixture.account;
    accounts[1] = &fixture.account;
    publications[0] = &absent_publication;
    publications[1] = &fixture.publication;
    git_ops_test_terminal_namespace_activity(
        &mutations_before, &syncs_before);

    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 2U, &transaction), 0);
    CHECK(transaction != NULL);
    git_ops_test_terminal_namespace_activity(
        &mutations_after, &syncs_after);
    CHECK_EQ_INT((long)mutations_after, (long)mutations_before);
    CHECK_EQ_INT((long)syncs_after, (long)syncs_before);
    errno = 0;
    CHECK(access(absent_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(absent_lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);

    if (transaction) {
        clear_error();
        errno = 0;
        CHECK_EQ_INT(git_retirement_transaction_publish(
                         transaction, &cleared), -1);
        CHECK_EQ_INT((long)cleared, 0);
        CHECK_EQ_INT(errno, EFBIG);
        CHECK(strstr(get_last_error()->message,
                     "bounded transaction budget") != NULL);
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    errno = 0;
    CHECK(access(absent_lock_path, F_OK) != 0 && errno == ENOENT);

    git_ops_test_set_retirement_prelock_witness_budget(previous_budget);
    at_bytes_clear(&present_before);
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
    unsigned successful_attempt = AT_PUBLICATION_RESEAL_ATTEMPTS;
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
    CHECK_EQ_INT(at_sync_parent_directory(fixture.alias_path), 0);
    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    CHECK_EQ_INT(at_retire_with_bounded_ctime_reseal(
                     &fixture, &before, &cleared,
                     &successful_attempt), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
#if !defined(__FreeBSD__)
    CHECK_EQ_INT((long)successful_attempt, 0);
#else
    (void)successful_attempt;
#endif
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

TEST(terminal_commit_retains_clean_postimage_until_consumed_finish) {
    at_fixture_t fixture;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    size_t cleared = 99U;
    size_t mutations_before_verify;
    size_t syncs_before_verify;
    size_t mutations_after_verify;
    size_t syncs_after_verify;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0640), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_verify_terminal_commit(
                     transaction), -1);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_commit(
                     transaction), 0);
    git_ops_test_terminal_namespace_activity(
        &mutations_before_verify, &syncs_before_verify);
    CHECK_EQ_INT(git_retirement_transaction_verify_terminal_commit(
                     transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_verify_terminal_commit(
                     transaction), 0);
    git_ops_test_terminal_namespace_activity(
        &mutations_after_verify, &syncs_after_verify);
    CHECK_EQ_INT((long)mutations_after_verify,
                 (long)mutations_before_verify);
    CHECK_EQ_INT((long)syncs_after_verify,
                 (long)syncs_before_verify);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(at_git_add(fixture.config_path,
                            GIT_CONFIG_CORE_SSHCOMMAND,
                            fixture.ssh_command), -1);
    at_check_foreign_survivors(&fixture);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_commit(
                     &transaction), 0);
    CHECK(transaction == NULL);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
}

TEST(terminal_recovery_uses_same_prepare_verify_finish_authority) {
    at_fixture_t fixture;
    const publication_record_t *records[1];
    git_retirement_recovery_t *recovery = NULL;
    size_t cleared = 99U;
    size_t mutations_before_verify;
    size_t syncs_before_verify;
    size_t mutations_after_verify;
    size_t syncs_after_verify;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    fixture.publication.state = PUBLICATION_STATE_RETIRING;
    records[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_recovery_begin(
                     records, 1U, &recovery), 0);
    CHECK_EQ_INT(git_retirement_recovery_prepare_terminal(recovery), 0);
    git_ops_test_terminal_namespace_activity(
        &mutations_before_verify, &syncs_before_verify);
    CHECK_EQ_INT(git_retirement_recovery_verify_terminal(recovery), 0);
    CHECK_EQ_INT(git_retirement_recovery_verify_terminal(recovery), 0);
    git_ops_test_terminal_namespace_activity(
        &mutations_after_verify, &syncs_after_verify);
    CHECK_EQ_INT((long)mutations_after_verify,
                 (long)mutations_before_verify);
    CHECK_EQ_INT((long)syncs_after_verify,
                 (long)syncs_before_verify);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(at_git_add(fixture.config_path,
                            GIT_CONFIG_CORE_SSHCOMMAND,
                            fixture.ssh_command), -1);
    at_check_owned_absent(&fixture);
    CHECK_EQ_INT(git_retirement_recovery_finish_terminal(&recovery), 0);
    CHECK(recovery == NULL);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
}

TEST(terminal_recovery_end_abandons_without_final_proof_or_marker_cleanup) {
    at_fixture_t fixture;
    const publication_record_t *records[1];
    git_retirement_recovery_t *recovery = NULL;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    fixture.publication.state = PUBLICATION_STATE_RETIRING;
    records[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_recovery_begin(
                     records, 1U, &recovery), 0);
    CHECK_EQ_INT(git_retirement_recovery_prepare_terminal(recovery), 0);
    at_install_hook(
        &fixture, AT_HOOK_FAIL_RECOVERY_FINAL_PROOF, NULL);
    CHECK_EQ_INT(git_retirement_recovery_end(&recovery), 0);
    CHECK(recovery == NULL);
    CHECK(!at_hook_observed);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    at_clear_hook();

    /* A fresh acquisition recognizes and settles the complete marker before
     * proving the already-clean destination. */
    fixture.publication.state = PUBLICATION_STATE_PUBLISHED;
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
}

static void at_run_multigroup_terminal_prepare_failure(
    bool recovery_mode, at_hook_mode_t failure_mode) {
    at_fixture_t fixture;
    at_bytes_t initial = {0};
    publication_record_t second_publication;
    const account_t *accounts[2];
    const publication_record_t *publications[2];
    git_retirement_transaction_t *transaction = NULL;
    git_retirement_recovery_t *recovery = NULL;
    struct stat second_stat;
    char second_path[MAX_PATH_LEN];
    char second_lock_path[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0600), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &initial), 0);
    CHECK_EQ_INT(safe_snprintf(
                     second_path, sizeof(second_path),
                     "%s/zz-second-config", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(
                     second_lock_path, sizeof(second_lock_path),
                     "%s.lock", second_path), 0);
    CHECK_EQ_INT(at_write_file_bytes(
                     second_path, initial.data, initial.length, 0600), 0);
    CHECK_EQ_INT(stat(second_path, &second_stat), 0);
    second_publication = fixture.publication;
    CHECK_EQ_INT(safe_strncpy(
                     second_publication.config_path, second_path,
                     sizeof(second_publication.config_path)), 0);
    publication_identity_from_stat(
        &second_publication.post_config, &second_stat);
    accounts[0] = &fixture.account;
    accounts[1] = &fixture.account;
    publications[0] = &fixture.publication;
    publications[1] = &second_publication;

    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 2U, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)(AT_KEY_COUNT * 2U));
    if (recovery_mode) {
        CHECK_EQ_INT(git_retirement_transaction_commit(
                         &transaction), 0);
        fixture.publication.state = PUBLICATION_STATE_RETIRING;
        second_publication.state = PUBLICATION_STATE_RETIRING;
        CHECK_EQ_INT(git_retirement_recovery_begin(
                         publications, 2U, &recovery), 0);
    }

    at_install_hook(&fixture, failure_mode, NULL);
    CHECK_EQ_INT(safe_strncpy(
                     at_hook_config, second_path,
                     sizeof(at_hook_config)), 0);
    if (recovery_mode) {
        CHECK_EQ_INT(git_retirement_recovery_prepare_terminal(
                         recovery), -1);
        CHECK_EQ_INT(git_retirement_recovery_end(&recovery), 0);
        CHECK(recovery == NULL);
    } else {
        CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_commit(
                         transaction), -1);
        CHECK_EQ_INT(git_retirement_transaction_commit(
                         &transaction), 0);
        CHECK(transaction == NULL);
    }
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK(access(fixture.lock_path, F_OK) == 0);
    errno = 0;
    CHECK(access(second_lock_path, F_OK) != 0 && errno == ENOENT);

    /* A fresh owner must recover the first complete marker and acquire the
     * second destination normally; no empty unmarked lock may be stranded. */
    if (recovery_mode) {
        CHECK_EQ_INT(git_retirement_recovery_begin(
                         publications, 2U, &recovery), 0);
        CHECK_EQ_INT(git_retirement_recovery_verify(recovery), 0);
        CHECK_EQ_INT(git_retirement_recovery_end(&recovery), 0);
    } else {
        cleared = 99U;
        CHECK_EQ_INT(git_retirement_transaction_prepare(
                         accounts, publications, 2U, &transaction), 0);
        CHECK_EQ_INT(git_retirement_transaction_publish(
                         transaction, &cleared), 0);
        CHECK_EQ_INT((long)cleared, 0);
        CHECK_EQ_INT(git_retirement_transaction_commit(
                         &transaction), 0);
    }
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(second_lock_path, F_OK) != 0 && errno == ENOENT);

    at_clear_hook();
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(
                         &transaction), 0);
    }
    if (recovery) {
        CHECK_EQ_INT(git_retirement_recovery_end(&recovery), 0);
    }
    at_bytes_clear(&initial);
}

TEST(multigroup_terminal_commit_premarker_failure_is_selectively_cleaned) {
    at_run_multigroup_terminal_prepare_failure(
        false, AT_HOOK_FAIL_TERMINAL_PREMARKER);
}

TEST(multigroup_terminal_commit_second_proof_failure_is_selectively_cleaned) {
    at_run_multigroup_terminal_prepare_failure(
        false, AT_HOOK_FAIL_TERMINAL_SECOND_PROOF);
}

TEST(multigroup_terminal_recovery_premarker_failure_is_selectively_cleaned) {
    at_run_multigroup_terminal_prepare_failure(
        true, AT_HOOK_FAIL_TERMINAL_PREMARKER);
}

TEST(multigroup_terminal_recovery_second_proof_failure_is_selectively_cleaned) {
    at_run_multigroup_terminal_prepare_failure(
        true, AT_HOOK_FAIL_TERMINAL_SECOND_PROOF);
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
    at_bytes_t original = {0};
    struct stat before;
    struct stat after;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0640), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &before), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    at_install_hook(&fixture, AT_HOOK_FORCE_FALLBACK, NULL);
#if defined(__FreeBSD__)
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
#else
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
#endif
    CHECK(at_hook_observed);
    at_clear_hook();
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_foreign_survivors(&fixture);
#else
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
#endif
    CHECK_EQ_INT(stat(fixture.config_path, &after), 0);
    CHECK_EQ_INT(before.st_mode & 07777, after.st_mode & 07777);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    at_bytes_clear(&original);
}

static void at_run_freebsd_forward_fallback_failure(
    at_hook_mode_t mode) {
#if defined(__FreeBSD__)
    at_fixture_t fixture;
    at_bytes_t original = {0};
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    at_install_hook(&fixture, mode, NULL);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    at_clear_hook();

    if (mode == AT_HOOK_FAIL_AFTER_FALLBACK_LINK) {
        CHECK_EQ_INT((long)cleared, 0);
        CHECK(at_count_recovery_artifacts(fixture.root) >= 1U);
        cleared = 99U;
        CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
        CHECK_EQ_INT((long)cleared, 0);
        at_check_foreign_survivors(&fixture);
    } else {
        CHECK_EQ_INT((long)cleared, 0);
        CHECK(at_file_equals_bytes(fixture.config_path, &original));
    }
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_bytes_clear(&original);
#else
    (void)mode;
    TS_SKIP("persistent-fs",
            "FreeBSD descriptor-conditioned fallback only");
#endif
}

TEST(freebsd_fallback_after_original_unlink_restores_before_image) {
    at_run_freebsd_forward_fallback_failure(
        AT_HOOK_FAIL_AFTER_FALLBACK_UNLINK);
}

TEST(freebsd_fallback_link_failure_restores_before_image) {
    at_run_freebsd_forward_fallback_failure(
        AT_HOOK_FAIL_FALLBACK_LINK);
}

TEST(freebsd_fallback_postlink_failure_retains_recovery_authority) {
    at_run_freebsd_forward_fallback_failure(
        AT_HOOK_FAIL_AFTER_FALLBACK_LINK);
}

TEST(freebsd_reverse_absent_canonical_retries_from_exact_original) {
#if defined(__FreeBSD__)
    at_fixture_t fixture;
    at_bytes_t original = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 true, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    at_install_hook(&fixture, AT_HOOK_FAIL_AFTER_REVERSE_UNLINK, NULL);
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    errno = 0;
    CHECK(access(fixture.config_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);

    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_clear_hook();
    at_bytes_clear(&original);
#else
    TS_SKIP("persistent-fs",
            "FreeBSD descriptor-conditioned fallback only");
#endif
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
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)lock_stat.st_nlink, 2);
#else
    CHECK_EQ_INT((long)lock_stat.st_nlink, 1);
#endif
    CHECK_EQ_INT((long)lock_stat.st_uid, (long)geteuid());
    CHECK_EQ_INT((long)lock_stat.st_size, 0);
    CHECK(at_file_equals_text(fixture.lock_path, ""));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_clear_hook();

    /* The injected pre-publication failure leaves only the exact empty lock
     * authority. FreeBSD's fixed W/C pair is self-healed on acquisition;
     * other platforms retain the canonical empty lock for operator review. */
    CHECK(at_file_equals_text(fixture.lock_path, ""));
#if !defined(__FreeBSD__)
    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
#endif
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_check_owned_absent(&fixture);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
}

TEST(marker_publication_preserves_raced_binary_canonical_lock) {
    static const unsigned char foreign_lock[] = {
        0x00U, 0xffU, 0x47U, 0x69U, 0x74U, 0x0aU, 0x80U, 0x00U
    };
    at_fixture_t fixture;
    at_bytes_t original = {0};
    at_bytes_t expected_foreign = {
        (unsigned char *)foreign_lock, sizeof(foreign_lock)
    };
    publication_identity_t exported_identity;
    publication_identity_t untouched_identity;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    char exported_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));

    CHECK_EQ_INT(at_write_file_bytes(
                     fixture.replacement_path, foreign_lock,
                     sizeof(foreign_lock), 0600), 0);
    at_install_hook(&fixture, AT_HOOK_RACE_MARKER_PUBLICATION, NULL);
    memset(&exported_identity, 0xa5, sizeof(exported_identity));
    untouched_identity = exported_identity;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, exported_path,
                     sizeof(exported_path), &exported_identity), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_STR_EQ(exported_path, fixture.config_path);
    CHECK(memcmp(&exported_identity, &untouched_identity,
                 sizeof(exported_identity)) == 0);
    CHECK_STR_EQ(at_hook_stage_path, fixture.lock_path);
    CHECK(at_file_equals_bytes(fixture.lock_path, &expected_foreign));
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    errno = 0;
    CHECK(access(fixture.replacement_path, F_OK) != 0 &&
          errno == ENOENT);
    at_clear_hook();

    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), -1);
    CHECK(transaction == NULL);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message, "changed") != NULL ||
          strstr(get_last_error()->message, "cleanup") != NULL ||
          strstr(get_last_error()->details, "changed") != NULL);
    CHECK(at_file_equals_bytes(fixture.lock_path, &expected_foreign));
    CHECK(at_file_equals_bytes(fixture.config_path, &original));

cleanup:
    at_clear_hook();
    if (transaction) {
        (void)git_retirement_transaction_commit(&transaction);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    if (at_hook_observed) {
        CHECK(at_file_equals_bytes(fixture.lock_path, &expected_foreign));
    }
    at_bytes_clear(&original);
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
#if defined(__FreeBSD__)
    char authority_path[MAX_PATH_LEN] = {0};
#endif
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
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)marker_stat.st_nlink, 2);
    CHECK_EQ_INT((long)marker_stat.st_size, 0);
    CHECK_EQ_INT(at_find_single_recovery_artifact(
                     fixture.root, authority_path,
                     sizeof(authority_path)), 0);
    CHECK_EQ_INT(stat(authority_path, &marker_stat), 0);
#else
    CHECK_EQ_INT((long)marker_stat.st_nlink, 1);
#endif
    CHECK_EQ_INT((long)marker_stat.st_uid, (long)geteuid());
    CHECK_EQ_INT(marker_stat.st_mode & 07777, 0600);
    CHECK(marker_stat.st_size > (off_t)AT_SNAPSHOT_MAX_BYTES);
    CHECK(marker_stat.st_size <=
          (off_t)(AT_SNAPSHOT_MAX_BYTES + AT_RECOVERY_HEADER_MAX +
                  512U));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 1);
#else
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
#endif
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
    CHECK_EQ_INT(lstat(fixture.lock_path, &restored_stat), 0);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)restored_stat.st_size, 0);
    CHECK_EQ_INT((long)restored_stat.st_nlink, 2);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 1);
#else
    CHECK(restored_stat.st_size > 0);
#endif

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

TEST(forked_child_cannot_mutate_or_release_published_transaction) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    at_bytes_t published = {0};
    at_bytes_t stage = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t restored_identity;
    struct stat config_before;
    struct stat config_after;
    struct stat lock_before;
    struct stat lock_after;
    struct stat root_before;
    struct stat root_after;
    struct stat stage_before;
    struct stat stage_after;
    char stage_path[MAX_PATH_LEN] = {0};
    char restored_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;
    pid_t child;
    pid_t waited;
    int status = 0;
    bool was_published = false;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    was_published = true;
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &published), 0);
    CHECK_EQ_INT(at_find_single_stage_artifact(
                     fixture.root, stage_path, sizeof(stage_path)), 0);
    CHECK_EQ_INT(at_read_bytes(stage_path, &stage), 0);
    CHECK_EQ_INT(lstat(fixture.config_path, &config_before), 0);
    CHECK_EQ_INT(lstat(fixture.lock_path, &lock_before), 0);
    CHECK_EQ_INT(lstat(fixture.root, &root_before), 0);
    CHECK_EQ_INT(lstat(stage_path, &stage_before), 0);
    CHECK_EQ_INT((long)lock_before.st_size, 0);

    child = fork();
    CHECK(child >= 0);
    if (child < 0) goto cleanup;
    if (child == 0) {
        git_retirement_transaction_t *child_transaction = transaction;
        publication_identity_t identity;
        struct stat observed;
        char path[MAX_PATH_LEN];
        size_t child_cleared = 99U;

        if (git_retirement_transaction_publish(
                child_transaction, &child_cleared) != -1 ||
            child_cleared != 0U) {
            _exit(11);
        }
        if (git_retirement_transaction_abort(child_transaction) != -1)
            _exit(12);
        if (git_retirement_transaction_restored_destination_count(
                child_transaction) != 0U) {
            _exit(13);
        }
        if (git_retirement_transaction_rollback_destination_count(
                child_transaction) != 0U) {
            _exit(14);
        }
        memset(&identity, 0, sizeof(identity));
        if (git_retirement_transaction_restored_destination(
                child_transaction, 0U, path, sizeof(path),
                &identity) != -1) {
            _exit(15);
        }
        if (git_retirement_transaction_rollback_destination(
                child_transaction, 0U, path, sizeof(path),
                &identity) != -1) {
            _exit(16);
        }
        if (git_retirement_transaction_prepare_terminal_rollback(
                child_transaction) != -1) {
            _exit(17);
        }
        if (git_retirement_transaction_commit(
                &child_transaction) != -1 ||
            child_transaction != NULL) {
            _exit(18);
        }
        if (!at_file_equals_bytes(fixture.config_path, &published))
            _exit(19);
        if (!at_file_equals_bytes(stage_path, &stage)) _exit(20);
        if (lstat(fixture.config_path, &observed) != 0 ||
            !at_same_file_state_after_exact_bytes(
                &config_before, &observed)) {
            _exit(21);
        }
        if (lstat(fixture.lock_path, &observed) != 0 ||
            !at_same_file_state(&lock_before, &observed)) {
            _exit(22);
        }
        if (lstat(stage_path, &observed) != 0 ||
            !at_same_file_state_after_exact_bytes(
                &stage_before, &observed)) {
            _exit(23);
        }
        if (lstat(fixture.root, &observed) != 0 ||
            !at_same_file_state(&root_before, &observed) ||
            at_count_stage_artifacts(fixture.root) != 1U) {
            _exit(24);
        }
        _exit(0);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == child);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);

    CHECK(at_file_equals_bytes(fixture.config_path, &published));
    CHECK(at_file_equals_bytes(stage_path, &stage));
    CHECK_EQ_INT(lstat(fixture.config_path, &config_after), 0);
    CHECK_EQ_INT(lstat(fixture.lock_path, &lock_after), 0);
    CHECK_EQ_INT(lstat(fixture.root, &root_after), 0);
    CHECK_EQ_INT(lstat(stage_path, &stage_after), 0);
    CHECK(at_same_file_state_after_exact_bytes(
        &config_before, &config_after));
    CHECK(at_same_file_state(&lock_before, &lock_after));
    CHECK(at_same_file_state(&root_before, &root_after));
    CHECK(at_same_file_state_after_exact_bytes(
        &stage_before, &stage_after));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);
    CHECK(at_canonical_lock_is_held(fixture.lock_path));

    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(
        (long)git_retirement_transaction_restored_destination_count(
            transaction),
        1);
    memset(&restored_identity, 0, sizeof(restored_identity));
    CHECK_EQ_INT(git_retirement_transaction_restored_destination(
                     transaction, 0U, restored_path,
                     sizeof(restored_path), &restored_identity), 0);
    CHECK_STR_EQ(restored_path, fixture.config_path);
    CHECK(restored_identity.present);
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);

cleanup:
    if (transaction) {
        if (was_published) {
            CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
        }
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    if (original.data) {
        CHECK(at_file_equals_bytes(fixture.config_path, &original));
    }
    at_bytes_clear(&stage);
    at_bytes_clear(&published);
    at_bytes_clear(&original);
}

TEST(terminal_rollback_present_premarker_failure_is_checked_cleaned) {
    at_fixture_t fixture;
    at_bytes_t original = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t identity;
    char observed_path[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    at_install_hook(
        &fixture, AT_HOOK_FAIL_TERMINAL_PREMARKER, NULL);
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, observed_path,
                     sizeof(observed_path), &identity), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    at_bytes_clear(&original);
}

TEST(terminal_rollback_absent_premarker_failure_is_checked_cleaned) {
    static const char initial[] =
        "[fixture]\n\tmarker = absent-before-transaction\n";
    at_fixture_t fixture;
    publication_record_t absent_publication;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    publication_identity_t identity;
    struct stat initial_stat;
    char absent_path[MAX_PATH_LEN];
    char absent_lock_path[MAX_PATH_LEN];
    char observed_path[MAX_PATH_LEN];
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(safe_snprintf(absent_path, sizeof(absent_path),
                               "%s/rollback-absent", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(absent_lock_path,
                               sizeof(absent_lock_path),
                               "%s.lock", absent_path), 0);
    CHECK_EQ_INT(at_write_file(absent_path, initial, 0600), 0);
    CHECK_EQ_INT(stat(absent_path, &initial_stat), 0);
    absent_publication = fixture.publication;
    CHECK_EQ_INT(safe_strncpy(absent_publication.config_path,
                              absent_path,
                              sizeof(absent_publication.config_path)), 0);
    publication_identity_from_stat(
        &absent_publication.post_config, &initial_stat);
    CHECK_EQ_INT(unlink(absent_path), 0);
    accounts[0] = &fixture.account;
    publications[0] = &absent_publication;

    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, observed_path,
                     sizeof(observed_path), &identity), 0);
    CHECK_EQ_INT(safe_strncpy(
                     at_hook_config, absent_path,
                     sizeof(at_hook_config)), 0);
    at_hook_mode = AT_HOOK_FAIL_TERMINAL_PREMARKER;
    at_hook_observed = false;
    at_hook_attempts = 0U;
    (void)git_ops_test_set_retirement_hook(at_retirement_hook);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), -1);
    CHECK(at_hook_observed);
    at_clear_hook();
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    errno = 0;
    CHECK(access(absent_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(absent_lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
}

TEST(terminal_rollback_revalidates_present_and_absent_destinations_in_order) {
    static const char absent_original[] =
        "[fixture]\n\tmarker = originally-absent\n";
    static const char foreign_recreation[] =
        "foreign recreation must remain exact\n";
    at_fixture_t fixture;
    at_bytes_t present_before = {0};
    publication_record_t absent_publication;
    publication_identity_t expected_present;
    publication_identity_t observed_identity;
    publication_identity_t zero_identity = {0};
    const account_t *accounts[2];
    const publication_record_t *publications[2];
    git_retirement_transaction_t *transaction = NULL;
    struct stat observed_stat = {0};
    char absent_path[MAX_PATH_LEN] = {0};
    char absent_lock_path[MAX_PATH_LEN] = {0};
    char observed_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;
    size_t mutations_before_verify = 0U;
    size_t mutations_after_verify = 0U;
    size_t syncs_before_verify = 0U;
    size_t syncs_after_verify = 0U;
    int query_errno;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &present_before), 0);
    CHECK_EQ_INT(safe_snprintf(absent_path, sizeof(absent_path),
                               "%s/aa-absent-config", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(absent_lock_path,
                               sizeof(absent_lock_path),
                               "%s.lock", absent_path), 0);
    CHECK_EQ_INT(at_write_file(absent_path, absent_original, 0600), 0);
    CHECK_EQ_INT(stat(absent_path, &observed_stat), 0);
    absent_publication = fixture.publication;
    CHECK_EQ_INT(safe_strncpy(absent_publication.config_path,
                              absent_path,
                              sizeof(absent_publication.config_path)), 0);
    publication_identity_from_stat(&absent_publication.post_config,
                                   &observed_stat);
    CHECK_EQ_INT(unlink(absent_path), 0);

    accounts[0] = &fixture.account;
    accounts[1] = &fixture.account;
    publications[0] = &fixture.publication;
    publications[1] = &absent_publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 2U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    errno = 0;
    CHECK(access(absent_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(
        (long)git_retirement_transaction_restored_destination_count(
            transaction),
        1);
    CHECK_EQ_INT(
        (long)git_retirement_transaction_rollback_destination_count(
            transaction),
        2);

    memset(&observed_identity, 0, sizeof(observed_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, observed_path,
                     sizeof(observed_path), &observed_identity), 0);
    CHECK_STR_EQ(observed_path, fixture.config_path);
    CHECK(observed_identity.present);
    CHECK_EQ_INT(stat(fixture.config_path, &observed_stat), 0);
    publication_identity_from_stat(&expected_present, &observed_stat);
    CHECK(publication_identity_equal(&observed_identity,
                                     &expected_present));

    memset(&observed_identity, 0xff, sizeof(observed_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 1U, observed_path,
                     sizeof(observed_path), &observed_identity), 0);
    CHECK_STR_EQ(observed_path, absent_path);
    CHECK(memcmp(&observed_identity, &zero_identity,
                 sizeof(observed_identity)) == 0);

    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), 0);
    CHECK_EQ_INT(stat(fixture.config_path, &observed_stat), 0);
    publication_identity_from_stat(&expected_present, &observed_stat);
    git_ops_test_terminal_namespace_activity(
        &mutations_before_verify, &syncs_before_verify);
    memset(&observed_identity, 0, sizeof(observed_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, observed_path,
                     sizeof(observed_path), &observed_identity), 0);
    CHECK_STR_EQ(observed_path, fixture.config_path);
    CHECK(publication_identity_equal(&observed_identity,
                                     &expected_present));
    memset(&observed_identity, 0xff, sizeof(observed_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 1U, observed_path,
                     sizeof(observed_path), &observed_identity), 0);
    CHECK_STR_EQ(observed_path, absent_path);
    CHECK(memcmp(&observed_identity, &zero_identity,
                 sizeof(observed_identity)) == 0);
    git_ops_test_terminal_namespace_activity(
        &mutations_after_verify, &syncs_after_verify);
    CHECK_EQ_INT((long)mutations_after_verify,
                 (long)mutations_before_verify);
    CHECK_EQ_INT((long)syncs_after_verify,
                 (long)syncs_before_verify);

    CHECK_EQ_INT(at_write_file(absent_path, foreign_recreation, 0600), 0);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 1U, observed_path,
                     sizeof(observed_path), &observed_identity), -1);
    query_errno = errno;
    CHECK(query_errno == EEXIST || query_errno == ESTALE);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK(at_file_equals_text(absent_path, foreign_recreation));

    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    CHECK(at_file_equals_text(absent_path, foreign_recreation));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(absent_lock_path, F_OK) != 0 && errno == ENOENT);

cleanup:
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    if (access(absent_path, F_OK) == 0) {
        CHECK(at_file_equals_text(absent_path, foreign_recreation));
    }
    at_bytes_clear(&present_before);
}

TEST(terminal_rollback_marker_release_preserves_raced_foreign_bytes) {
    static const char foreign_marker[] =
        "foreign replacement at terminal marker release\n";
    at_fixture_t fixture;
    at_bytes_t original = {0};
    publication_identity_t exported_identity;
    publication_identity_t current_identity;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    struct stat current_stat;
    char exported_path[MAX_PATH_LEN] = {0};
    char warning[2048] = {0};
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    memset(&exported_identity, 0, sizeof(exported_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, exported_path,
                     sizeof(exported_path), &exported_identity), 0);
    CHECK_STR_EQ(exported_path, fixture.config_path);
    CHECK(exported_identity.present);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(stat(fixture.config_path, &current_stat), 0);
    publication_identity_from_stat(&current_identity, &current_stat);
#if defined(__FreeBSD__)
    /* A later directory/authority fsync can expose the already-admitted UFS
     * ctime-only materialization. Require every durable generation field
     * except that timestamp. */
    CHECK(at_publication_identity_equal_except_ctime(
        &exported_identity, &current_identity));
#else
    CHECK(publication_identity_equal(&exported_identity,
                                     &current_identity));
#endif
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);

    CHECK_EQ_INT(at_write_file(fixture.replacement_path,
                               foreign_marker, 0600), 0);
    at_install_hook(&fixture,
                    AT_HOOK_RACE_TERMINAL_MARKER_CLEANUP, NULL);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_finish_terminal_capture_warning(
                     &transaction, warning, sizeof(warning)), 0);
    CHECK(transaction == NULL);
    CHECK(strstr(
              warning,
              "Consumed terminal Git rollback completed with cleanup diagnostics") != NULL);
    CHECK(strstr(warning, "preserving the foreign path") != NULL);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    CHECK_EQ_INT(errno, 0);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK_STR_EQ(at_hook_stage_path, fixture.lock_path);
    CHECK(at_file_equals_text(fixture.lock_path, foreign_marker));
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(stat(fixture.config_path, &current_stat), 0);
    publication_identity_from_stat(&current_identity, &current_stat);
#if defined(__FreeBSD__)
    CHECK(at_publication_identity_equal_except_ctime(
        &exported_identity, &current_identity));
#else
    CHECK(publication_identity_equal(&exported_identity,
                                     &current_identity));
#endif
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 0);
#else
    CHECK(at_count_cleanup_artifacts(fixture.root) >= 1U);
#endif
    errno = 0;
    CHECK(access(fixture.replacement_path, F_OK) != 0 &&
          errno == ENOENT);
    at_clear_hook();

cleanup:
    at_clear_hook();
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    at_bytes_clear(&original);
}

static void at_run_freebsd_authority_publication_interruption(
    at_hook_mode_t mode, int expected_exit, bool crash_mode) {
#if defined(__FreeBSD__)
    at_fixture_t fixture;
    pid_t child = -1;
    int status = 0;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    if (crash_mode) {
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            const account_t *accounts[] = {&fixture.account};
            const publication_record_t *publications[] = {
                &fixture.publication
            };
            git_retirement_transaction_t *transaction = NULL;
            size_t child_cleared = 99U;

            if (git_retirement_transaction_prepare(
                    accounts, publications, 1U, &transaction) != 0 ||
                git_retirement_transaction_publish(
                    transaction, &child_cleared) != 0 ||
                child_cleared != AT_KEY_COUNT) {
                _exit(80);
            }
            at_install_hook(&fixture, mode, NULL);
            (void)git_retirement_transaction_prepare_terminal_commit(
                transaction);
            _exit(81);
        }
        if (child > 0) {
            CHECK(waitpid(child, &status, 0) == child);
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) {
                CHECK_EQ_INT(WEXITSTATUS(status), expected_exit);
            }
        }
    } else {
        const account_t *accounts[] = {&fixture.account};
        const publication_record_t *publications[] = {
            &fixture.publication
        };
        git_retirement_transaction_t *transaction = NULL;

        CHECK_EQ_INT(git_retirement_transaction_prepare(
                         accounts, publications, 1U,
                         &transaction), 0);
        CHECK_EQ_INT(git_retirement_transaction_publish(
                         transaction, &cleared), 0);
        at_install_hook(&fixture, mode, NULL);
        CHECK_EQ_INT(
            git_retirement_transaction_prepare_terminal_commit(
                transaction), -1);
        CHECK(at_hook_observed);
        at_clear_hook();
        CHECK_EQ_INT(git_retirement_transaction_commit(
                         &transaction), 0);
    }

    at_check_owned_absent(&fixture);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 1);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 1);
    CHECK(access(fixture.lock_path, F_OK) == 0);

    /* Restart discovery requires A to classify W/C and the encoded stage.
     * A fresh retirement must settle the complete authority and proceed. */
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 0);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
#else
    (void)mode;
    (void)expected_exit;
    (void)crash_mode;
    TS_SKIP("persistent-fs",
            "FreeBSD fixed W/C/A recovery protocol only");
#endif
}

TEST(freebsd_crash_after_authority_publish_retains_restart_authority) {
    at_run_freebsd_authority_publication_interruption(
        AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_PUBLISH, 78, true);
}

TEST(freebsd_fault_after_authority_publish_retains_restart_authority) {
    at_run_freebsd_authority_publication_interruption(
        AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_PUBLISH, 0, false);
}

TEST(freebsd_crash_after_authority_dirsync_retains_restart_authority) {
    at_run_freebsd_authority_publication_interruption(
        AT_HOOK_EXIT_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC, 79,
        true);
}

TEST(freebsd_fault_after_authority_dirsync_retains_restart_authority) {
    at_run_freebsd_authority_publication_interruption(
        AT_HOOK_FAIL_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC, 0,
        false);
}

TEST(freebsd_failed_prepublish_authority_cleanup_retains_restart_authority) {
#if defined(__FreeBSD__)
    at_fixture_t fixture;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_install_hook(
        &fixture,
        AT_HOOK_FAIL_FREEBSD_PREPUBLICATION_AUTHORITY_CLEANUP,
        NULL);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_commit(
                     transaction), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 2);
    at_clear_hook();
    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);

    at_check_owned_absent(&fixture);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 1);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 1);
    CHECK(access(fixture.lock_path, F_OK) == 0);

    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 0);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
#else
    TS_SKIP("persistent-fs",
            "FreeBSD fixed W/C/A recovery protocol only");
#endif
}

static void at_run_freebsd_terminal_cleanup_crash_once(
    at_hook_mode_t mode, int expected_exit,
    bool canonical_expected) {
#if defined(__FreeBSD__)
    at_fixture_t fixture;
    at_bytes_t original = {0};
    pid_t child;
    int status = 0;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const account_t *accounts[] = {&fixture.account};
        const publication_record_t *publications[] = {
            &fixture.publication
        };
        git_retirement_transaction_t *transaction = NULL;
        publication_identity_t identity;
        char path[MAX_PATH_LEN];
        size_t child_cleared = 99U;

        if (git_retirement_transaction_prepare(
                accounts, publications, 1U, &transaction) != 0 ||
            git_retirement_transaction_publish(
                transaction, &child_cleared) != 0 ||
            child_cleared != AT_KEY_COUNT ||
            git_retirement_transaction_abort(transaction) != 0 ||
            git_retirement_transaction_rollback_destination(
                transaction, 0U, path, sizeof(path), &identity) != 0 ||
            git_retirement_transaction_prepare_terminal_rollback(
                transaction) != 0) {
            _exit(76);
        }
        at_install_hook(&fixture, mode, NULL);
        (void)git_retirement_transaction_finish_terminal_rollback(
            &transaction);
        _exit(77);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), expected_exit);
        }
    }
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 1);
    errno = 0;
    if (canonical_expected) {
        CHECK(access(fixture.lock_path, F_OK) == 0);
    } else {
        CHECK(access(fixture.lock_path, F_OK) != 0 &&
              errno == ENOENT);
    }

    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    CHECK_EQ_INT(at_retire_with_bounded_ctime_reseal(
                     &fixture, &original, &cleared, NULL), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_lease_artifacts(fixture.root), 0);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&original);
#else
    (void)mode;
    (void)expected_exit;
    (void)canonical_expected;
    TS_SKIP("persistent-fs",
            "FreeBSD fixed W/C/A recovery protocol only");
#endif
}

TEST(freebsd_crash_after_authority_sync_recovers_canonical_and_lease) {
    for (unsigned iteration = 0U; iteration < 4U; iteration++) {
        at_run_freebsd_terminal_cleanup_crash_once(
            AT_HOOK_EXIT_AFTER_TERMINAL_AUTHORITY_SYNC, 74, true);
    }
}

TEST(freebsd_crash_after_canonical_sync_recovers_private_lease) {
    for (unsigned iteration = 0U; iteration < 4U; iteration++) {
        at_run_freebsd_terminal_cleanup_crash_once(
            AT_HOOK_EXIT_AFTER_TERMINAL_CANONICAL_SYNC, 75, false);
    }
}

TEST(postproof_quarantine_replacement_is_preserved_and_blocks_reuse) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD uses descriptor-conditioned funlinkat without quarantine");
#else
    static const unsigned char foreign_quarantine[] = {
        0x71U, 0x00U, 0xffU, 0x75U, 0x61U, 0x72U, 0x0aU
    };
    at_fixture_t fixture;
    at_bytes_t original = {0};
    at_bytes_t expected_foreign = {
        (unsigned char *)foreign_quarantine, sizeof(foreign_quarantine)
    };
    publication_identity_t exported_identity;
    publication_identity_t current_identity;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    struct stat current_stat;
    char exported_path[MAX_PATH_LEN] = {0};
    size_t cleanup_before = 0U;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    memset(&exported_identity, 0, sizeof(exported_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, exported_path,
                     sizeof(exported_path), &exported_identity), 0);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    cleanup_before = at_count_cleanup_artifacts(fixture.root);
    CHECK(cleanup_before != SIZE_MAX);
    CHECK(cleanup_before >= 1U);

    CHECK_EQ_INT(at_write_file_bytes(
                     fixture.replacement_path, foreign_quarantine,
                     sizeof(foreign_quarantine), 0600), 0);
    at_install_hook(&fixture,
                    AT_HOOK_RACE_POST_PROOF_QUARANTINE, NULL);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    CHECK_EQ_INT(errno, 0);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK(at_file_equals_bytes(at_hook_stage_path, &expected_foreign));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(stat(fixture.config_path, &current_stat), 0);
    publication_identity_from_stat(&current_identity, &current_stat);
    CHECK(publication_identity_equal(&exported_identity,
                                     &current_identity));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root),
                 (long)cleanup_before + 1L);
    fixture.publication.post_config = current_identity;
    cleared = 99U;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(get_last_error()->code == ERR_GIT_CONFIG_FAILED);
    CHECK(strstr(get_last_error()->message,
                 "pending private cleanup residue") != NULL);
    CHECK(at_file_equals_bytes(at_hook_stage_path, &expected_foreign));
    errno = 0;
    CHECK(access(fixture.replacement_path, F_OK) != 0 &&
          errno == ENOENT);
    at_clear_hook();

cleanup:
    at_clear_hook();
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    at_bytes_clear(&original);
#endif
}

TEST(crashed_terminal_marker_quarantine_blocks_fresh_acquisition) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD uses descriptor-conditioned funlinkat without quarantine");
#else
    static const unsigned char recovery_prefix[] =
        "gitswitch-recovery-v1 ";
    at_fixture_t fixture;
    at_bytes_t original = {0};
    at_bytes_t residue = {0};
    const char *lock_leaf;
    char residue_path[MAX_PATH_LEN] = {0};
    pid_t child;
    pid_t waited;
    int status = 0;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    lock_leaf = strrchr(fixture.lock_path, '/');
    CHECK(lock_leaf != NULL);
    if (!lock_leaf) goto cleanup;
    lock_leaf++;

    child = fork();
    CHECK(child >= 0);
    if (child < 0) goto cleanup;
    if (child == 0) {
        const account_t *accounts[] = {&fixture.account};
        const publication_record_t *publications[] = {
            &fixture.publication
        };
        git_retirement_transaction_t *transaction = NULL;
        publication_identity_t identity;
        char path[MAX_PATH_LEN];
        size_t cleared = 99U;

        if (git_retirement_transaction_prepare(
                accounts, publications, 1U, &transaction) != 0 ||
            !transaction) {
            _exit(61);
        }
        if (git_retirement_transaction_publish(
                transaction, &cleared) != 0 ||
            cleared != AT_KEY_COUNT) {
            _exit(62);
        }
        if (git_retirement_transaction_abort(transaction) != 0) {
            _exit(63);
        }
        memset(&identity, 0, sizeof(identity));
        if (git_retirement_transaction_rollback_destination(
                transaction, 0U, path, sizeof(path), &identity) != 0 ||
            !identity.present ||
            git_retirement_transaction_prepare_terminal_rollback(
                transaction) != 0) {
            _exit(64);
        }
        at_install_hook(
            &fixture, AT_HOOK_EXIT_AFTER_PRIVATE_QUARANTINE, NULL);
        (void)git_retirement_transaction_finish_terminal_rollback(
            &transaction);
        _exit(65);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == child);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 73);

    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(at_find_cleanup_artifact_for_leaf(
                     fixture.root, lock_leaf,
                     residue_path, sizeof(residue_path)), 0);
    CHECK_EQ_INT(at_read_bytes(residue_path, &residue), 0);
    CHECK(residue.length > sizeof(recovery_prefix) - 1U);
    if (residue.length >= sizeof(recovery_prefix) - 1U) {
        CHECK(memcmp(residue.data, recovery_prefix,
                     sizeof(recovery_prefix) - 1U) == 0);
    }

    child = fork();
    CHECK(child >= 0);
    if (child < 0) goto cleanup;
    if (child == 0) {
        size_t cleared = 99U;
        int result = at_retire(&fixture, &cleared);

        if (!at_file_equals_bytes(residue_path, &residue)) {
            _exit(71);
        }
        if (result == -1 && cleared == 0U &&
            get_last_error()->code == ERR_GIT_CONFIG_FAILED &&
            strstr(get_last_error()->message,
                   "pending private cleanup residue") != NULL &&
            at_file_equals_bytes(fixture.config_path, &original)) {
            _exit(0);
        }
        _exit(72);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == child);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK(at_file_equals_bytes(residue_path, &residue));

cleanup:
    at_clear_hook();
    at_bytes_clear(&residue);
    at_bytes_clear(&original);
#endif
}

TEST(settled_terminal_marker_residue_allows_two_fresh_retirements) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes terminal markers with descriptor-conditioned funlinkat");
#else
    at_fixture_t fixture;
    at_bytes_t original = {0};
    publication_identity_t exported_identity;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    char exported_path[MAX_PATH_LEN] = {0};
    size_t cleanup_after_finish;
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    memset(&exported_identity, 0, sizeof(exported_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, exported_path,
                     sizeof(exported_path), &exported_identity), 0);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    cleanup_after_finish = at_count_cleanup_artifacts(fixture.root);
    CHECK(cleanup_after_finish != SIZE_MAX);
    CHECK(cleanup_after_finish >= 1U);

    fixture.publication.post_config = exported_identity;
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    at_check_owned_absent(&fixture);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, 0);
    at_check_owned_absent(&fixture);
    CHECK(at_count_cleanup_artifacts(fixture.root) >=
          cleanup_after_finish);

cleanup:
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    at_bytes_clear(&original);
#endif
}

TEST(terminal_preledger_stage_cleanup_preserves_raced_foreign_bytes) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD no-replace rollback consumes the original staging alias before terminal settlement");
#else
    static const char foreign_stage[] =
        "foreign replacement at terminal stage settlement\n";
    at_fixture_t fixture;
    at_bytes_t original = {0};
    at_bytes_t retained_marker = {0};
    publication_identity_t exported_identity;
    publication_identity_t zero_identity = {0};
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    git_retirement_transaction_t *transaction = NULL;
    char stage_path[MAX_PATH_LEN] = {0};
    char recovery_path[MAX_PATH_LEN] = {0};
    char exported_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    accounts[0] = &fixture.account;
    publications[0] = &fixture.publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 1U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(at_find_single_stage_artifact(
                     fixture.root, stage_path, sizeof(stage_path)), 0);
    CHECK_EQ_INT(at_write_file(fixture.replacement_path,
                               foreign_stage, 0600), 0);
    at_install_hook(&fixture,
                    AT_HOOK_RACE_TERMINAL_STAGE_CLEANUP, NULL);

    memset(&exported_identity, 0, sizeof(exported_identity));
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, exported_path,
                     sizeof(exported_path), &exported_identity), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    CHECK_STR_EQ(exported_path, fixture.config_path);
    CHECK(memcmp(&exported_identity, &zero_identity,
                 sizeof(exported_identity)) == 0);
    CHECK_STR_EQ(at_hook_stage_path, stage_path);
    CHECK(at_file_equals_text(stage_path, foreign_stage));
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT(at_read_retained_recovery(
                     fixture.root, fixture.lock_path, &retained_marker,
                     recovery_path, sizeof(recovery_path)), 0);
    CHECK(retained_marker.length > 0U);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 1);
#else
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);
#endif
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 0);
#else
    CHECK(at_count_cleanup_artifacts(fixture.root) >= 1U);
#endif
    errno = 0;
    CHECK(access(fixture.replacement_path, F_OK) != 0 &&
          errno == ENOENT);
    at_clear_hook();

    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    CHECK(at_file_equals_text(stage_path, foreign_stage));
    CHECK(at_file_equals_bytes(recovery_path, &retained_marker));
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 1);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 0);
#else
    CHECK(at_count_cleanup_artifacts(fixture.root) >= 1U);
#endif

cleanup:
    at_clear_hook();
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    at_bytes_clear(&retained_marker);
    at_bytes_clear(&original);
#endif
}

TEST(partial_terminal_disposal_preserves_settled_recovery_marker) {
    static const char absent_original[] =
        "[fixture]\n\tmarker = originally-absent\n";
    static const char foreign_recreation[] =
        "foreign recreation must remain exact\n";
    at_fixture_t fixture;
    at_bytes_t present_before = {0};
    at_bytes_t recovery_marker = {0};
    publication_record_t absent_publication;
    publication_identity_t observed_identity;
    const account_t *accounts[2];
    const publication_record_t *publications[2];
    git_retirement_transaction_t *transaction = NULL;
    struct stat observed_stat = {0};
    char absent_path[MAX_PATH_LEN] = {0};
    char absent_lock_path[MAX_PATH_LEN] = {0};
    char observed_path[MAX_PATH_LEN] = {0};
    char recovery_path[MAX_PATH_LEN] = {0};
    size_t cleared = 99U;
    int query_errno;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &present_before), 0);
    CHECK_EQ_INT(safe_snprintf(absent_path, sizeof(absent_path),
                               "%s/aa-disposal-absent-config",
                               fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(absent_lock_path,
                               sizeof(absent_lock_path),
                               "%s.lock", absent_path), 0);
    CHECK_EQ_INT(at_write_file(absent_path, absent_original, 0600), 0);
    CHECK_EQ_INT(stat(absent_path, &observed_stat), 0);
    absent_publication = fixture.publication;
    CHECK_EQ_INT(safe_strncpy(absent_publication.config_path,
                              absent_path,
                              sizeof(absent_publication.config_path)), 0);
    publication_identity_from_stat(&absent_publication.post_config,
                                   &observed_stat);
    CHECK_EQ_INT(unlink(absent_path), 0);

    accounts[0] = &fixture.account;
    accounts[1] = &fixture.account;
    publications[0] = &fixture.publication;
    publications[1] = &absent_publication;
    CHECK_EQ_INT(git_retirement_transaction_prepare(
                     accounts, publications, 2U, &transaction), 0);
    CHECK(transaction != NULL);
    if (!transaction) goto cleanup;

    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    CHECK_EQ_INT(
        (long)git_retirement_transaction_rollback_destination_count(
            transaction),
        2);

    memset(&observed_identity, 0, sizeof(observed_identity));
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 0U, observed_path,
                     sizeof(observed_path), &observed_identity), 0);
    CHECK_STR_EQ(observed_path, fixture.config_path);
    CHECK(observed_identity.present);
    CHECK_EQ_INT(at_read_retained_recovery(
                     fixture.root, fixture.lock_path, &recovery_marker,
                     recovery_path, sizeof(recovery_path)), 0);
    CHECK(recovery_marker.length > 0U);

    CHECK_EQ_INT(at_write_file(absent_path, foreign_recreation, 0600), 0);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                     transaction, 1U, observed_path,
                     sizeof(observed_path), &observed_identity), -1);
    query_errno = errno;
    CHECK(query_errno == EEXIST || query_errno == ESTALE);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);

    CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    CHECK(transaction == NULL);
    CHECK(at_file_equals_bytes(recovery_path, &recovery_marker));
    CHECK(!at_canonical_lock_is_held(fixture.lock_path));
    CHECK(at_file_equals_bytes(fixture.config_path, &present_before));
    CHECK(at_file_equals_text(absent_path, foreign_recreation));

    CHECK_EQ_INT(at_refresh_publication(&fixture), 0);
    cleared = 99U;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    at_check_owned_absent(&fixture);
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_stage_artifacts(fixture.root), 0);
    CHECK_EQ_INT((long)at_count_recovery_artifacts(fixture.root), 0);

cleanup:
    if (transaction) {
        CHECK_EQ_INT(git_retirement_transaction_commit(&transaction), 0);
    }
    CHECK(transaction == NULL);
    if (access(absent_path, F_OK) == 0) {
        CHECK(at_file_equals_text(absent_path, foreign_recreation));
        CHECK_EQ_INT(unlink(absent_path), 0);
    }
    errno = 0;
    CHECK(access(absent_lock_path, F_OK) != 0 && errno == ENOENT);
    at_bytes_clear(&recovery_marker);
    at_bytes_clear(&present_before);
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
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_commit(
                     transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_verify_terminal_commit(
                     transaction), 0);
    errno = 0;
    CHECK(access(fixture.config_path, F_OK) != 0 && errno == ENOENT);
    CHECK(access(fixture.lock_path, F_OK) == 0);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_commit(
                     &transaction), 0);
    CHECK(transaction == NULL);

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

TEST(finite_cleanup_arena_has_exact_happy_path_residue) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes owned names with descriptor-conditioned funlinkat");
#else
    at_fixture_t fixture;
    size_t previous_capacity =
        git_ops_test_set_cleanup_arena_capacity(8U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 2);
    git_ops_test_set_cleanup_arena_capacity(previous_capacity);
#endif
}

TEST(settled_slot_collision_preserves_both_entries_and_blocks_reuse) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes owned names with descriptor-conditioned funlinkat");
#else
    static const unsigned char foreign_settled[] = {
        0x73U, 0x65U, 0x74U, 0x00U, 0xffU, 0x0aU
    };
    at_fixture_t fixture;
    at_bytes_t settled_bytes = {
        (unsigned char *)foreign_settled, sizeof(foreign_settled)
    };
    at_bytes_t pending_bytes = {0};
    struct stat current;
    char pending_path[MAX_PATH_LEN];
    char settled_path[MAX_PATH_LEN];
    char *state;
    size_t previous_capacity =
        git_ops_test_set_cleanup_arena_capacity(8U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_write_file_bytes(
                     fixture.replacement_path, foreign_settled,
                     sizeof(foreign_settled), 0600), 0);
    at_install_hook(&fixture, AT_HOOK_COLLIDE_SETTLED_QUARANTINE, NULL);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK(at_hook_observed);
    CHECK_EQ_INT((long)at_hook_attempts, 1);
    CHECK(at_file_equals_bytes(at_hook_stage_path, &settled_bytes));
    CHECK_EQ_INT(safe_strncpy(settled_path, at_hook_stage_path,
                              sizeof(settled_path)), 0);
    CHECK_EQ_INT(safe_strncpy(pending_path, at_hook_stage_path,
                              sizeof(pending_path)), 0);
    state = strstr(pending_path, "-settled-");
    CHECK(state != NULL);
    if (state) {
        memcpy(state, "-pending-", sizeof("-pending-") - 1U);
        CHECK_EQ_INT(at_read_bytes(pending_path, &pending_bytes), 0);
        CHECK(pending_bytes.length > 0U);
    }
    CHECK_EQ_INT(stat(fixture.config_path, &current), 0);
    publication_identity_from_stat(&fixture.publication.post_config,
                                   &current);
    at_clear_hook();
    cleared = 99U;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(strstr(get_last_error()->message,
                 "pending private cleanup residue") != NULL);
    CHECK(at_file_equals_bytes(settled_path, &settled_bytes));
    CHECK(at_file_equals_bytes(pending_path, &pending_bytes));

    at_clear_hook();
    git_ops_test_set_cleanup_arena_capacity(previous_capacity);
    at_bytes_clear(&pending_bytes);
#endif
}

TEST(cleanup_arena_exhaustion_precedes_canonical_mutation) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes owned names with descriptor-conditioned funlinkat");
#else
    static const char occupied[] = "untrusted settled slot\n";
    at_fixture_t fixture;
    at_bytes_t original = {0};
    char settled_path[MAX_PATH_LEN];
    const char *lock_leaf;
    size_t previous_capacity =
        git_ops_test_set_cleanup_arena_capacity(8U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_read_bytes(fixture.config_path, &original), 0);
    lock_leaf = strrchr(fixture.lock_path, '/');
    CHECK(lock_leaf != NULL);
    if (!lock_leaf) goto cleanup;
    lock_leaf++;
    CHECK_EQ_INT(at_cleanup_slot_path(
                     fixture.root, lock_leaf, false, 0U,
                     settled_path, sizeof(settled_path)), 0);
    CHECK_EQ_INT(at_write_file(settled_path, occupied, 0600), 0);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(at_retire(&fixture, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(errno, ENOSPC);
    CHECK(strstr(get_last_error()->message,
                 "offline quiescence") != NULL);
    CHECK(at_file_equals_bytes(fixture.config_path, &original));
    CHECK(at_file_equals_text(settled_path, occupied));
    errno = 0;
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 1);

cleanup:
    git_ops_test_set_cleanup_arena_capacity(previous_capacity);
    at_bytes_clear(&original);
#endif
}

TEST(cleanup_arena_pending_association_isolates_other_lock_leaf) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes owned names with descriptor-conditioned funlinkat");
#else
    static const char other_pending[] = "other leaf pending residue\n";
    at_fixture_t fixture;
    char pending_path[MAX_PATH_LEN];
    size_t previous_capacity =
        git_ops_test_set_cleanup_arena_capacity(8U);
    size_t cleared = 99U;

    CHECK_EQ_INT(at_fixture_init(&fixture, PUBLICATION_SCOPE_GLOBAL,
                                 false, 0640), 0);
    CHECK_EQ_INT(at_cleanup_slot_path(
                     fixture.root, "unrelated-config.lock", true, 0U,
                     pending_path, sizeof(pending_path)), 0);
    CHECK_EQ_INT(at_write_file(pending_path, other_pending, 0600), 0);
    CHECK_EQ_INT(at_retire(&fixture, &cleared), 0);
    CHECK_EQ_INT((long)cleared, (long)AT_KEY_COUNT);
    CHECK(at_file_equals_text(pending_path, other_pending));
    CHECK_EQ_INT((long)at_count_cleanup_artifacts(fixture.root), 3);

    git_ops_test_set_cleanup_arena_capacity(previous_capacity);
#endif
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
    RUN_TEST(ordinary_prelock_ctime_only_drift_is_rejected);
    RUN_TEST(prelock_same_size_rewrite_with_restored_mtime_is_rejected);
    RUN_TEST(restored_witness_reproves_one_delayed_ctime_step);
    RUN_TEST(restored_witness_reproves_repeated_delayed_ctime_steps);
    RUN_TEST(restored_witness_rejects_same_size_rewrite_with_restored_mtime);
    RUN_TEST(prelock_witness_aggregate_budget_fails_before_lock_mutation);
    RUN_TEST(early_prelock_failure_preserves_standard_input_descriptor);
    RUN_TEST(absent_first_later_witness_budget_failure_has_no_namespace_mutation);
    RUN_TEST(every_ordered_removal_failure_is_byte_atomic_and_retry_succeeds);
    RUN_TEST(prepublication_failure_is_byte_atomic_and_retry_succeeds);
    RUN_TEST(late_generation_replacement_survives_exchange_in_every_scope);
    RUN_TEST(late_hardlink_race_is_reversed_without_publish_in_every_scope);
    RUN_TEST(postpublication_directory_sync_failure_reconciles_on_retry);
    RUN_TEST(retiring_recovery_rejects_live_values_without_forward_unsets);
    RUN_TEST(retiring_recovery_holds_canonical_lock_through_clean_reproof);
    RUN_TEST(terminal_commit_retains_clean_postimage_until_consumed_finish);
    RUN_TEST(terminal_recovery_uses_same_prepare_verify_finish_authority);
    RUN_TEST(terminal_recovery_end_abandons_without_final_proof_or_marker_cleanup);
    RUN_TEST(multigroup_terminal_commit_premarker_failure_is_selectively_cleaned);
    RUN_TEST(multigroup_terminal_commit_second_proof_failure_is_selectively_cleaned);
    RUN_TEST(multigroup_terminal_recovery_premarker_failure_is_selectively_cleaned);
    RUN_TEST(multigroup_terminal_recovery_second_proof_failure_is_selectively_cleaned);
    RUN_TEST(retiring_recovery_fails_closed_on_uncooperative_reintroduction);
    RUN_TEST(foreign_lock_survives_checked_ordinary_failure_cleanup);
    RUN_TEST(foreign_lock_survives_stale_reconciliation_cleanup_conflict);
    RUN_TEST(forced_unsupported_exchange_fallback_preserves_ordered_survivors);
    RUN_TEST(freebsd_fallback_after_original_unlink_restores_before_image);
    RUN_TEST(freebsd_fallback_link_failure_restores_before_image);
    RUN_TEST(freebsd_fallback_postlink_failure_retains_recovery_authority);
    RUN_TEST(freebsd_reverse_absent_canonical_retries_from_exact_original);
    RUN_TEST(unsupported_exchange_fallback_reproves_lock_and_canonical);
    RUN_TEST(transient_owned_cleanup_failure_retries_with_witness);
    RUN_TEST(two_owned_cleanup_failures_recover_on_next_retirement);
    RUN_TEST(failed_private_marker_publish_preserves_exact_empty_lock);
    RUN_TEST(marker_publication_preserves_raced_binary_canonical_lock);
    RUN_TEST(oversized_recovery_numeric_token_preserves_foreign_lock);
    RUN_TEST(maximum_snapshot_recovery_marker_crosses_old_reader_limit);
    RUN_TEST(post_exchange_foreign_stage_is_never_reverse_published);
    RUN_TEST(hardlinked_destination_is_refused_without_mutation);
    RUN_TEST(outer_abort_restores_exact_bytes_and_exports_reconciled_witness);
    RUN_TEST(forked_child_cannot_mutate_or_release_published_transaction);
    RUN_TEST(terminal_rollback_present_premarker_failure_is_checked_cleaned);
    RUN_TEST(terminal_rollback_absent_premarker_failure_is_checked_cleaned);
    RUN_TEST(terminal_rollback_revalidates_present_and_absent_destinations_in_order);
    RUN_TEST(terminal_rollback_marker_release_preserves_raced_foreign_bytes);
    RUN_TEST(freebsd_crash_after_authority_publish_retains_restart_authority);
    RUN_TEST(freebsd_fault_after_authority_publish_retains_restart_authority);
    RUN_TEST(freebsd_crash_after_authority_dirsync_retains_restart_authority);
    RUN_TEST(freebsd_fault_after_authority_dirsync_retains_restart_authority);
    RUN_TEST(freebsd_failed_prepublish_authority_cleanup_retains_restart_authority);
    RUN_TEST(freebsd_crash_after_authority_sync_recovers_canonical_and_lease);
    RUN_TEST(freebsd_crash_after_canonical_sync_recovers_private_lease);
    RUN_TEST(postproof_quarantine_replacement_is_preserved_and_blocks_reuse);
    RUN_TEST(crashed_terminal_marker_quarantine_blocks_fresh_acquisition);
    RUN_TEST(settled_terminal_marker_residue_allows_two_fresh_retirements);
    RUN_TEST(terminal_preledger_stage_cleanup_preserves_raced_foreign_bytes);
    RUN_TEST(partial_terminal_disposal_preserves_settled_recovery_marker);
    RUN_TEST(absent_recorded_destination_retires_without_recreation);
    RUN_TEST(finite_cleanup_arena_has_exact_happy_path_residue);
    RUN_TEST(settled_slot_collision_preserves_both_entries_and_blocks_reuse);
    RUN_TEST(cleanup_arena_exhaustion_precedes_canonical_mutation);
    RUN_TEST(cleanup_arena_pending_association_isolates_other_lock_leaf);
    RUN_TEST(successful_publication_preserves_nondefault_file_mode);
TEST_MAIN_END()
