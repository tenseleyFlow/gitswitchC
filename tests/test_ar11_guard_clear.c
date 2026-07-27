/* AR-11 M18: retirement completion is a fixed, generation-matched
 * certificate. The canonical incomplete record is never deleted by clear();
 * every pre-commit failure remains blocked, while post-publication lost
 * acknowledgements classify an exact pair as committed. */
#include "test.h"

#include "config.h"
#include "error.h"

#include <stdint.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>

#define GUARD_MAX_BYTES 8192U
#define GUARD_NAME ".retirement-incomplete"
#define COMPLETE_NAME ".retirement-complete"
#define STAGE_NAME ".retirement-transition"
#define LOCK_NAME ".retirement.lock"
#define SETTLED_PREFIX ".gitswitch-retirement-settled-"

typedef enum {
    RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE = 0,
    RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
    RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
    RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
    RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
    RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
    RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_READ_AFTER_CLOSE,
    RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
    RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
    RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
    RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
    RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
    RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
    RETIREMENT_GUARD_CLEAR_AFTER_PREPARED_PUBLISH
} retirement_guard_clear_test_stage_t;
typedef int (*retirement_guard_clear_test_hook_fn)(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name);
retirement_guard_clear_test_hook_fn
gitswitch_test_set_retirement_guard_clear_hook(
    retirement_guard_clear_test_hook_fn hook);
unsigned int gitswitch_test_set_retirement_settled_slot_limit(
    unsigned int limit);
int gitswitch_test_retirement_guard_directory_fd(
    const config_retirement_guard_t *guard);

typedef struct {
    config_retirement_guard_t *guard;
    config_retirement_owner_t owner;
    char directory[128];
    char config_path[256];
    char marker_path[256];
    char completion_path[256];
    char stage_path[256];
    char lock_path[256];
    unsigned char marker_data[GUARD_MAX_BYTES];
    size_t marker_length;
    struct stat marker_identity;
} guard_fixture_t;

static int guard_write_all(int fd, const unsigned char *data, size_t length) {
    size_t total = 0U;

    while (total < length) {
        ssize_t count = write(fd, data + total, length - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static size_t guard_read_file(const char *path, unsigned char *data,
                              size_t capacity) {
    struct stat st;
    size_t total = 0U;
    int fd;

    if (!path || !data || stat(path, &st) != 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > capacity) {
        return 0U;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0U;
    while (total < (size_t)st.st_size) {
        ssize_t count = read(fd, data + total, (size_t)st.st_size - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            total = 0U;
            break;
        }
    }
    if (close(fd) != 0) return 0U;
    return total;
}

static bool guard_files_equal(const char *left, const char *right) {
    unsigned char left_data[GUARD_MAX_BYTES];
    unsigned char right_data[GUARD_MAX_BYTES];
    size_t left_length = guard_read_file(
        left, left_data, sizeof(left_data));
    size_t right_length = guard_read_file(
        right, right_data, sizeof(right_data));

    return left_length > 0U && left_length == right_length &&
           memcmp(left_data, right_data, left_length) == 0;
}

static int guard_atomic_replace_at(
    int directory_fd, const char *destination,
    const unsigned char *data, size_t length) {
    static const char temp_name[] = ".retirement-test-replacement";
    int fd;

    (void)unlinkat(directory_fd, temp_name, 0);
    fd = openat(directory_fd, temp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (fd < 0 ||
        guard_write_all(fd, data, length) != 0 ||
        fsync(fd) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (close(fd) != 0 ||
        renameat(directory_fd, temp_name,
                 directory_fd, destination) != 0 ||
        fsync(directory_fd) != 0) {
        return -1;
    }
    return 0;
}

static size_t guard_read_file_at(
    int directory_fd, const char *name, unsigned char *data,
    size_t capacity) {
    struct stat st;
    size_t total = 0U;
    int fd;

    if (directory_fd < 0 || !name || !data ||
        fstatat(directory_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        st.st_size <= 0 || (uintmax_t)st.st_size > capacity) {
        return 0U;
    }
    fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0U;
    while (total < (size_t)st.st_size) {
        ssize_t count = read(fd, data + total, (size_t)st.st_size - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            total = 0U;
            break;
        }
    }
    if (close(fd) != 0) return 0U;
    return total;
}

static bool guard_same_ctime(const struct stat *left,
                             const struct stat *right) {
#if defined(__APPLE__)
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool guard_same_except_ctime(const struct stat *left,
                                    const struct stat *right) {
    if (!left || !right ||
        left->st_dev != right->st_dev ||
        left->st_ino != right->st_ino ||
        left->st_mode != right->st_mode ||
        left->st_uid != right->st_uid ||
        left->st_gid != right->st_gid ||
        left->st_nlink != right->st_nlink ||
        left->st_rdev != right->st_rdev ||
        left->st_size != right->st_size ||
        left->st_blksize != right->st_blksize ||
        left->st_blocks != right->st_blocks) {
        return false;
    }
#if defined(__APPLE__)
    return left->st_atimespec.tv_sec == right->st_atimespec.tv_sec &&
           left->st_atimespec.tv_nsec == right->st_atimespec.tv_nsec &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_atim.tv_sec == right->st_atim.tv_sec &&
           left->st_atim.tv_nsec == right->st_atim.tv_nsec &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static int guard_force_ctime_only_drift_at(
    int directory_fd, const char *name, struct stat *before_out,
    struct stat *after_out) {
    const struct timespec retry = {.tv_sec = 0, .tv_nsec = 1000000L};
    struct stat before;
    struct stat after;

    if (directory_fd < 0 || !name || !before_out || !after_out ||
        fstatat(directory_fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0 ||
        (before.st_mode & 0777U) != 0600U) {
        errno = errno ? errno : EINVAL;
        return -1;
    }
    for (size_t attempt = 0U; attempt < 256U; attempt++) {
        if (fchmodat(directory_fd, name, 0400, 0) != 0 ||
            fchmodat(directory_fd, name, 0600, 0) != 0 ||
            fstatat(directory_fd, name, &after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !guard_same_except_ctime(&before, &after)) {
            errno = errno ? errno : ESTALE;
            return -1;
        }
        if (!guard_same_ctime(&before, &after)) {
            *before_out = before;
            *after_out = after;
            return 0;
        }
        (void)nanosleep(&retry, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static bool guard_mutate_token(
    const unsigned char *source, size_t length,
    unsigned char mutated[GUARD_MAX_BYTES]) {
    static const char token_prefix[] = "token=";
    unsigned char *token;

    if (!source || length == 0U || length > GUARD_MAX_BYTES) return false;
    memcpy(mutated, source, length);
    token = memmem(mutated, length, token_prefix,
                   sizeof(token_prefix) - 1U);
    if (!token ||
        (size_t)(token - mutated) + sizeof(token_prefix) - 1U >= length) {
        return false;
    }
    token += sizeof(token_prefix) - 1U;
    *token = *token == (unsigned char)'A'
                 ? (unsigned char)'B'
                 : (unsigned char)'A';
    return true;
}

static int guard_change_bytes_restore_mtime_at(
    int directory_fd, const char *name,
    unsigned char original_out[GUARD_MAX_BYTES],
    unsigned char mutated[GUARD_MAX_BYTES], size_t *mutated_length,
    struct stat *before_out, struct stat *after_out) {
    unsigned char original[GUARD_MAX_BYTES];
    struct stat before;
    struct stat drift_before;
    struct stat after;
    struct timespec times[2];
    size_t length;
    size_t total = 0U;
    int fd = -1;
    int failure_errno = EIO;

    if (directory_fd < 0 || !name || !original_out || !mutated ||
        !mutated_length || !before_out || !after_out) {
        errno = EINVAL;
        return -1;
    }
    fd = openat(
        directory_fd, name,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        before.st_size <= 0 ||
        (uintmax_t)before.st_size > GUARD_MAX_BYTES) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    length = (size_t)before.st_size;
    while (total < length) {
        ssize_t count = pread(
            fd, original + total, length - total, (off_t)total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            failure_errno = errno ? errno : ESTALE;
            goto mutation_fail;
        }
    }
    if (!guard_mutate_token(original, length, mutated)) {
        failure_errno = EINVAL;
        goto mutation_fail;
    }
#if defined(__APPLE__)
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    total = 0U;
    while (total < length) {
        ssize_t count = pwrite(
            fd, mutated + total, length - total, (off_t)total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            failure_errno = errno ? errno : EIO;
            goto mutation_fail;
        }
    }
    if (futimens(fd, times) != 0 || fsync(fd) != 0) {
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    fd = -1;
    if (guard_force_ctime_only_drift_at(
            directory_fd, name, &drift_before, &after) != 0 ||
        !guard_same_except_ctime(&before, &drift_before) ||
        !guard_same_except_ctime(&before, &after) ||
        guard_same_ctime(&before, &after)) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    *mutated_length = length;
    memcpy(original_out, original, length);
    *before_out = before;
    *after_out = after;
    memset(original, 0, sizeof(original));
    return 0;

mutation_fail:
    if (fd >= 0) close(fd);
    memset(original, 0, sizeof(original));
    errno = failure_errno;
    return -1;
}

static size_t guard_make_v1_marker(
    const guard_fixture_t *fixture, config_retirement_kind_t kind,
    unsigned char legacy[GUARD_MAX_BYTES]) {
    static const char v2_header[] =
        "gitswitch-retirement-incomplete-v2";
    static const char obligation_line[] = "ssh_obligation=none\n";
    static const char reset_line[] = "operation=reset\n";
    static const char remove_line[] = "operation=remove\n";
    unsigned char *line;
    size_t legacy_length;
    size_t line_offset;
    size_t tail_offset;
    size_t tail_length;

    if (!fixture || !legacy ||
        fixture->marker_length > GUARD_MAX_BYTES ||
        fixture->marker_length < sizeof(v2_header) - 1U ||
        memcmp(fixture->marker_data, v2_header,
               sizeof(v2_header) - 1U) != 0 ||
        (kind != CONFIG_RETIREMENT_RESET &&
         kind != CONFIG_RETIREMENT_REMOVE)) {
        return 0U;
    }
    memcpy(legacy, fixture->marker_data, fixture->marker_length);
    legacy[sizeof(v2_header) - 2U] = (unsigned char)'1';
    line = memmem(legacy, fixture->marker_length, obligation_line,
                  sizeof(obligation_line) - 1U);
    if (!line) return 0U;
    legacy_length = (size_t)(line - legacy);
    if (kind == CONFIG_RETIREMENT_RESET) return legacy_length;

    line = memmem(legacy, legacy_length, reset_line,
                  sizeof(reset_line) - 1U);
    if (!line ||
        legacy_length + sizeof(remove_line) - sizeof(reset_line) >
            GUARD_MAX_BYTES) {
        return 0U;
    }
    line_offset = (size_t)(line - legacy);
    tail_offset = line_offset + sizeof(reset_line) - 1U;
    tail_length = legacy_length - tail_offset;
    memmove(legacy + line_offset + sizeof(remove_line) - 1U,
            legacy + tail_offset, tail_length);
    memcpy(legacy + line_offset, remove_line,
           sizeof(remove_line) - 1U);
    return legacy_length + sizeof(remove_line) - sizeof(reset_line);
}

static bool guard_make_alias_obligation(
    const guard_fixture_t *fixture, const char *alias,
    config_retirement_ssh_alias_obligation_t *obligation) {
    struct stat home;

    if (!fixture || !alias || !obligation ||
        stat(fixture->directory, &home) != 0) {
        return false;
    }
    memset(obligation, 0, sizeof(*obligation));
    obligation->known = true;
    obligation->present = true;
    if ((size_t)snprintf(
            obligation->ssh_host_alias,
            sizeof(obligation->ssh_host_alias), "%s", alias) >=
            sizeof(obligation->ssh_host_alias) ||
        (size_t)snprintf(
            obligation->home_path, sizeof(obligation->home_path),
            "%s", fixture->directory) >=
            sizeof(obligation->home_path)) {
        return false;
    }
    publication_identity_from_stat(&obligation->home_identity, &home);
    return true;
}

static int guard_count_retirement_entries(
    const char *directory, int *unexpected) {
    DIR *stream;
    struct dirent *entry;
    int count = 0;
    int bad = 0;

    if (!directory || !unexpected) return -1;
    stream = opendir(directory);
    if (!stream) return -1;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, ".retirement", 11U) != 0) continue;
        count++;
        if (strcmp(entry->d_name, GUARD_NAME) != 0 &&
            strcmp(entry->d_name, COMPLETE_NAME) != 0 &&
            strcmp(entry->d_name, STAGE_NAME) != 0 &&
            strcmp(entry->d_name, LOCK_NAME) != 0) {
            bad++;
        }
    }
    if (closedir(stream) != 0) return -1;
    *unexpected = bad;
    return count;
}

static int guard_fixture_init(guard_fixture_t *fixture) {
    static const char incarnation[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    if (!fixture) return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->owner.account_id = UINT32_C(1);
    memcpy(fixture->owner.account_incarnation, incarnation,
           sizeof(incarnation));
    if ((size_t)snprintf(fixture->directory, sizeof(fixture->directory),
                         "/tmp/gswguardclear.XXXXXX") >=
            sizeof(fixture->directory) ||
        !ts_mkdtemp(fixture->directory) ||
        (size_t)snprintf(fixture->config_path,
                         sizeof(fixture->config_path),
                         "%s/accounts.toml", fixture->directory) >=
            sizeof(fixture->config_path) ||
        (size_t)snprintf(fixture->marker_path,
                         sizeof(fixture->marker_path), "%s/%s",
                         fixture->directory, GUARD_NAME) >=
            sizeof(fixture->marker_path) ||
        (size_t)snprintf(fixture->completion_path,
                         sizeof(fixture->completion_path), "%s/%s",
                         fixture->directory, COMPLETE_NAME) >=
            sizeof(fixture->completion_path) ||
        (size_t)snprintf(fixture->stage_path,
                         sizeof(fixture->stage_path), "%s/%s",
                         fixture->directory, STAGE_NAME) >=
            sizeof(fixture->stage_path) ||
        (size_t)snprintf(fixture->lock_path,
                         sizeof(fixture->lock_path), "%s/%s",
                         fixture->directory, LOCK_NAME) >=
            sizeof(fixture->lock_path) ||
        config_retirement_guard_install_or_adopt(
            fixture->config_path, CONFIG_RETIREMENT_RESET,
            &fixture->owner, 1U, &fixture->guard) != 0) {
        return -1;
    }
    fixture->marker_length = guard_read_file(
        fixture->marker_path, fixture->marker_data,
        sizeof(fixture->marker_data));
    if (fixture->marker_length == 0U ||
        stat(fixture->marker_path, &fixture->marker_identity) != 0) {
        return -1;
    }
    return 0;
}

static void guard_fixture_cleanup(guard_fixture_t *fixture) {
    if (!fixture) return;
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture->guard);
    (void)unlink(fixture->marker_path);
    (void)unlink(fixture->completion_path);
    (void)unlink(fixture->stage_path);
    (void)unlink(fixture->lock_path);
    for (unsigned int slot = 0U; slot < 4U; slot++) {
        char path[256];

        if ((size_t)snprintf(
                path, sizeof(path), "%s/%s%u",
                fixture->directory, SETTLED_PREFIX, slot) <
            sizeof(path)) {
            (void)unlink(path);
        }
    }
    (void)rmdir(fixture->directory);
}

TEST(fork_child_abandon_preserves_reused_retirement_guard_directory_fd) {
    guard_fixture_t fixture;
    pid_t child;
    int status = 0;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int directory_fd =
            gitswitch_test_retirement_guard_directory_fd(fixture.guard);
        int sentinel = directory_fd >= 0
                           ? openat(
                                 directory_fd, ".",
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                     O_NOFOLLOW)
                           : -1;

        if (directory_fd < 0 || sentinel < 0 ||
            directory_fd == sentinel ||
            close(directory_fd) != 0 ||
            dup2(sentinel, directory_fd) != directory_fd) {
            _exit(90);
        }
        config_retirement_guard_abandon(&fixture.guard);
        if (fixture.guard != NULL ||
            fcntl(directory_fd, F_GETFD) < 0) {
            _exit(91);
        }
        close(directory_fd);
        close(sentinel);
        _exit(0);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    guard_fixture_cleanup(&fixture);
}

#if !defined(__FreeBSD__)
static int guard_fixture_rotate_active(guard_fixture_t *fixture) {
    if (!fixture ||
        config_retirement_guard_clear(&fixture->guard) != 0 ||
        config_retirement_guard_install_or_adopt(
            fixture->config_path, CONFIG_RETIREMENT_RESET,
            &fixture->owner, 1U, &fixture->guard) != 0) {
        return -1;
    }
    fixture->marker_length = guard_read_file(
        fixture->marker_path, fixture->marker_data,
        sizeof(fixture->marker_data));
    return fixture->marker_length > 0U &&
                   stat(fixture->marker_path,
                        &fixture->marker_identity) == 0
               ? 0
               : -1;
}
#endif

typedef enum {
    HOOK_FAIL = 0,
    HOOK_SYNC_THEN_FAIL,
    HOOK_REPLACE_CANONICAL,
    HOOK_REPLACE_COMPLETION,
    HOOK_REPLACE_STAGE,
    HOOK_REPLACE_NAMED,
    HOOK_CTIME_AT_INSTALL_SYNC,
    HOOK_CTIME_AFTER_FRESH_READ,
    HOOK_REPLACE_AFTER_FRESH_READ,
    HOOK_CHANGED_BYTES_RESTORED_MTIME,
    HOOK_CTIME_AFTER_STAGE_REMOVAL,
    HOOK_CHANGED_BYTES_AFTER_STAGE_REMOVAL,
    HOOK_REPLACE_LOCK
} hook_action_t;

static retirement_guard_clear_test_stage_t hook_stage;
static hook_action_t hook_action;
static bool hook_armed;
static bool hook_fresh_publish_seen;
static bool hook_action_observed;
static int hook_action_error;
static unsigned int hook_action_count;
static struct stat hook_identity_before;
static struct stat hook_identity_after;
static unsigned char hook_original[GUARD_MAX_BYTES];
static unsigned char hook_replacement[GUARD_MAX_BYTES];
static size_t hook_replacement_length;

static int guard_fault_hook(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name) {
    if (!hook_armed) return 0;
    if ((hook_action == HOOK_CTIME_AFTER_FRESH_READ ||
         hook_action == HOOK_REPLACE_AFTER_FRESH_READ ||
         (hook_action == HOOK_CHANGED_BYTES_RESTORED_MTIME &&
          hook_stage !=
              RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ)) &&
        stage == RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC) {
        hook_fresh_publish_seen = true;
        return 0;
    }
    if (stage != hook_stage ||
        ((hook_action == HOOK_CTIME_AFTER_FRESH_READ ||
          hook_action == HOOK_REPLACE_AFTER_FRESH_READ ||
          (hook_action == HOOK_CHANGED_BYTES_RESTORED_MTIME &&
           hook_stage !=
               RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ)) &&
         !hook_fresh_publish_seen)) {
        return 0;
    }
    if (hook_action == HOOK_CTIME_AFTER_STAGE_REMOVAL ||
        hook_action == HOOK_CHANGED_BYTES_AFTER_STAGE_REMOVAL) {
        struct stat stage_identity;

        if (!marker_name || strcmp(marker_name, GUARD_NAME) != 0) return 0;
        errno = 0;
        if (fstatat(descriptor, STAGE_NAME, &stage_identity,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            return 0;
        }
        if (errno != ENOENT) {
            hook_action_error = errno ? errno : EIO;
            return -1;
        }
        errno = 0;
    }
    hook_armed = false;
    hook_action_observed = true;
    hook_action_count++;
    if (hook_action == HOOK_SYNC_THEN_FAIL &&
        fsync(descriptor) != 0) {
        return -1;
    }
    if (hook_action == HOOK_REPLACE_CANONICAL) {
        return guard_atomic_replace_at(
            descriptor, GUARD_NAME, hook_replacement,
            hook_replacement_length);
    }
    if (hook_action == HOOK_REPLACE_COMPLETION) {
        return guard_atomic_replace_at(
            descriptor, COMPLETE_NAME, hook_replacement,
            hook_replacement_length);
    }
    if (hook_action == HOOK_REPLACE_STAGE) {
        return guard_atomic_replace_at(
            descriptor, STAGE_NAME, hook_replacement,
            hook_replacement_length);
    }
    if (hook_action == HOOK_REPLACE_NAMED) {
        return guard_atomic_replace_at(
            descriptor, marker_name, hook_replacement,
            hook_replacement_length);
    }
    if (hook_action == HOOK_REPLACE_LOCK) {
        return guard_atomic_replace_at(
            descriptor, LOCK_NAME, hook_replacement,
            hook_replacement_length);
    }
    if (hook_action == HOOK_CTIME_AT_INSTALL_SYNC ||
        hook_action == HOOK_CTIME_AFTER_FRESH_READ ||
        hook_action == HOOK_CTIME_AFTER_STAGE_REMOVAL) {
        if (guard_force_ctime_only_drift_at(
                descriptor, marker_name, &hook_identity_before,
                &hook_identity_after) != 0) {
            hook_action_error = errno ? errno : EIO;
            errno = hook_action_error;
            return -1;
        }
        return 0;
    }
    if (hook_action == HOOK_REPLACE_AFTER_FRESH_READ) {
        hook_replacement_length = guard_read_file_at(
            descriptor, marker_name, hook_replacement,
            sizeof(hook_replacement));
        if (hook_replacement_length == 0U ||
            fstatat(descriptor, marker_name, &hook_identity_before,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            guard_atomic_replace_at(
                descriptor, marker_name, hook_replacement,
                hook_replacement_length) != 0 ||
            fstatat(descriptor, marker_name, &hook_identity_after,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            hook_action_error = errno ? errno : EIO;
            errno = hook_action_error;
            return -1;
        }
        return 0;
    }
    if (hook_action == HOOK_CHANGED_BYTES_RESTORED_MTIME ||
        hook_action == HOOK_CHANGED_BYTES_AFTER_STAGE_REMOVAL) {
        if (guard_change_bytes_restore_mtime_at(
                descriptor, marker_name, hook_original, hook_replacement,
                &hook_replacement_length, &hook_identity_before,
                &hook_identity_after) != 0) {
            hook_action_error = errno ? errno : EIO;
            errno = hook_action_error;
            return -1;
        }
        return 0;
    }
    errno = EIO;
    return -1;
}

static void guard_arm_hook(
    retirement_guard_clear_test_stage_t stage, hook_action_t action) {
    hook_stage = stage;
    hook_action = action;
    hook_armed = true;
    hook_fresh_publish_seen = false;
    hook_action_observed = false;
    hook_action_error = 0;
    hook_action_count = 0U;
    memset(&hook_identity_before, 0, sizeof(hook_identity_before));
    memset(&hook_identity_after, 0, sizeof(hook_identity_after));
    (void)gitswitch_test_set_retirement_guard_clear_hook(
        guard_fault_hook);
}

static bool guard_probe(const guard_fixture_t *fixture, bool *blocked) {
    return fixture && blocked &&
           config_retirement_guard_probe(
               fixture->config_path, blocked) == 0;
}

static unsigned int barrier_call_count;
static int barrier_failure_errno;
static error_context_t barrier_failure_error;

static int guard_commit_barrier(void *context) {
    const char *diagnostic = context;

    barrier_call_count++;
    if (barrier_failure_errno == 0) return 0;
    errno = barrier_failure_errno;
    set_system_error(
        ERR_SYSTEM_CALL, "%s",
        diagnostic ? diagnostic : "retirement barrier failure");
    barrier_failure_error = *get_last_error();
    return -1;
}

static void guard_arm_barrier(int failure_errno) {
    barrier_call_count = 0U;
    barrier_failure_errno = failure_errno;
    memset(&barrier_failure_error, 0, sizeof(barrier_failure_error));
}

static bool guard_error_context_same(
    const error_context_t *left, const error_context_t *right) {
    return left && right && left->code == right->code &&
           strcmp(left->message, right->message) == 0 &&
           left->message_truncated == right->message_truncated &&
           strcmp(left->details, right->details) == 0 &&
           left->details_truncated == right->details_truncated &&
           strcmp(left->file, right->file) == 0 &&
           left->line == right->line &&
           strcmp(left->function, right->function) == 0 &&
           left->system_errno == right->system_errno;
}

static int guard_pipe_barrier(void *context) {
    int descriptor = context ? *(int *)context : -1;
    const unsigned char invoked = 1U;

    barrier_call_count++;
    return descriptor >= 0 &&
                   write(descriptor, &invoked, sizeof(invoked)) ==
                       (ssize_t)sizeof(invoked)
               ? 0
               : -1;
}

typedef struct {
    config_retirement_guard_t **guard;
    int recursive_result;
    bool abandon_retained;
} guard_reentrant_barrier_context_t;

static int guard_reentrant_barrier(void *context) {
    guard_reentrant_barrier_context_t *state = context;
    config_retirement_guard_t *before =
        state && state->guard ? *state->guard : NULL;

    barrier_call_count++;
    state->recursive_result =
        config_retirement_guard_clear(state->guard);
    config_retirement_guard_abandon(state->guard);
    state->abandon_retained =
        state->guard && *state->guard == before;
    return 0;
}

typedef struct {
    config_retirement_guard_t **guard;
    const char *config_path;
    const config_retirement_owner_t *owner;
    int child_status;
} guard_fork_barrier_context_t;

static int guard_fork_abandon_barrier(void *context) {
    guard_fork_barrier_context_t *state = context;
    pid_t child;
    pid_t waited;

    barrier_call_count++;
    if (!state || !state->guard || !*state->guard ||
        !state->config_path || !state->owner) {
        errno = EINVAL;
        return -1;
    }
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        config_retirement_guard_t *independent = NULL;

        config_retirement_guard_abandon(state->guard);
        errno = 0;
        if (*state->guard != NULL ||
            config_retirement_guard_install_or_adopt(
                state->config_path, CONFIG_RETIREMENT_RESET,
                state->owner, 1U, &independent) != -1 ||
            independent != NULL || errno != EWOULDBLOCK) {
            config_retirement_guard_abandon(&independent);
            _exit(1);
        }
        _exit(0);
    }
    state->child_status = -1;
    do {
        waited = waitpid(child, &state->child_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) return -1;
    errno = EAGAIN;
    return -1;
}

static int guard_arm_observation_barrier(void *context) {
    (void)context;
    barrier_call_count++;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH, HOOK_FAIL);
    return 0;
}

TEST(completion_keeps_canonical_generation_and_unblocks) {
    guard_fixture_t fixture;
    struct stat after;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&fixture.marker_identity, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, hook_replacement,
                     sizeof(hook_replacement)),
                 (long)fixture.marker_length);
    CHECK(memcmp(hook_replacement, fixture.marker_data,
                 fixture.marker_length) == 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_clear_is_durable_blocking_and_commits_without_ack_hooks) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), 0);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(hook_armed);
    CHECK(!hook_action_observed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_clear_skips_directory_sync_hooks) {
    guard_fixture_t fixture;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(hook_armed);
    CHECK(!hook_action_observed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_clear_replaces_a_prior_completion_generation) {
    guard_fixture_t fixture;
    bool blocked = true;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK(config_retirement_guard_was_created(fixture.guard));
    CHECK(!guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), 0);

    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK_EQ_INT(access(fixture.completion_path, F_OK), 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepare_clear_rejects_foreign_stage_without_deleting_it) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat before;
    struct stat after;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, STAGE_NAME,
                         hook_replacement,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(fstatat(
                         directory_fd, STAGE_NAME, &before,
                         AT_SYMLINK_NOFOLLOW), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(stat(fixture.stage_path, &after), 0);
    CHECK(ts_same_identity(&before, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.stage_path, observed, sizeof(observed)),
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, hook_replacement,
                 fixture.marker_length) == 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_handle_rejects_completion_inserted_after_prepare) {
    guard_fixture_t fixture;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, COMPLETE_NAME,
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_handle_rejects_prior_completion_inode_replacement) {
    guard_fixture_t fixture;
    struct stat before;
    struct stat after;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK_EQ_INT(stat(fixture.completion_path, &before), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, COMPLETE_NAME,
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(stat(fixture.completion_path, &after), 0);
    CHECK(!ts_same_identity(&before, &after));

    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_handle_accepts_prior_completion_ctime_only_drift) {
    guard_fixture_t fixture;
    struct stat before;
    struct stat after;
    bool blocked = true;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_force_ctime_only_drift_at(
                         directory_fd, COMPLETE_NAME,
                         &before, &after), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK(guard_same_except_ctime(&before, &after));
    CHECK(!guard_same_ctime(&before, &after));

    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_handle_rejects_prior_completion_content_change) {
    guard_fixture_t fixture;
    struct stat before;
    struct stat after;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_change_bytes_restore_mtime_at(
                         directory_fd, COMPLETE_NAME,
                         hook_original, hook_replacement,
                         &hook_replacement_length,
                         &before, &after), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK(guard_same_except_ctime(&before, &after));
    CHECK(!guard_same_ctime(&before, &after));

    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_clear_failure_before_rename_retains_blocking_stage) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_barrier_eagain_retains_capability_and_retry_commits) {
    static char diagnostic[] =
        "synthetic retryable retirement barrier";
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_barrier(EAGAIN);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier,
                     diagnostic), -1);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK(guard_error_context_same(
        get_last_error(), &barrier_failure_error));
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    barrier_failure_errno = 0;
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier,
                     diagnostic), 0);
    CHECK_EQ_INT((long)barrier_call_count, 2);
    CHECK(fixture.guard == NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_guard_mismatch_prevents_barrier_invocation) {
    guard_fixture_t fixture;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME,
                         hook_replacement,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    CHECK_EQ_INT((long)barrier_call_count, 0);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_barrier_hard_failure_retains_blocking_state) {
    static char diagnostic[] =
        "synthetic hard retirement barrier failure";
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_barrier(EPERM);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier,
                     diagnostic), -1);
    CHECK_EQ_INT(errno, EPERM);
    CHECK(guard_error_context_same(
        get_last_error(), &barrier_failure_error));
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(fork_child_cannot_invoke_barrier_and_parent_can_retry) {
    guard_fixture_t fixture;
    unsigned char observed = 0U;
    int invocation_pipe[2] = {-1, -1};
    int status = 0;
    pid_t child;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK_EQ_INT(pipe(invocation_pipe), 0);
    if (invocation_pipe[0] >= 0) {
        CHECK(fcntl(
                  invocation_pipe[0], F_SETFL,
                  fcntl(invocation_pipe[0], F_GETFL) | O_NONBLOCK) >= 0);
    }
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        config_retirement_guard_t *independent = NULL;
        int result;

        close(invocation_pipe[0]);
        result = config_retirement_guard_clear_with_barrier(
            &fixture.guard, guard_pipe_barrier,
            &invocation_pipe[1]);
        config_retirement_guard_abandon(&fixture.guard);
        errno = 0;
        if (result != -1 || fixture.guard != NULL ||
            config_retirement_guard_install_or_adopt(
                fixture.config_path, CONFIG_RETIREMENT_RESET,
                &fixture.owner, 1U, &independent) != -1 ||
            independent != NULL || errno != EWOULDBLOCK) {
            config_retirement_guard_abandon(&independent);
            _exit(1);
        }
        _exit(0);
    }
    if (child > 0) {
        int competing_lock;

        close(invocation_pipe[1]);
        invocation_pipe[1] = -1;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        errno = 0;
        CHECK_EQ_INT(
            read(invocation_pipe[0], &observed, sizeof(observed)), 0);
        competing_lock = open(
            fixture.lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        CHECK(competing_lock >= 0);
        if (competing_lock >= 0) {
            errno = 0;
            CHECK(flock(
                      competing_lock,
                      LOCK_EX | LOCK_NB) != 0 &&
                  (errno == EWOULDBLOCK || errno == EAGAIN));
            CHECK_EQ_INT(close(competing_lock), 0);
        }
    }
    if (invocation_pipe[0] >= 0) close(invocation_pipe[0]);
    invocation_pipe[0] = -1;

    CHECK_EQ_INT(pipe(invocation_pipe), 0);
    guard_arm_barrier(0);
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_pipe_barrier,
                     &invocation_pipe[1]), 0);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK_EQ_INT(
        read(invocation_pipe[0], &observed, sizeof(observed)),
        (long)sizeof(observed));
    CHECK_EQ_INT((long)observed, 1);
    close(invocation_pipe[0]);
    close(invocation_pipe[1]);
    guard_fixture_cleanup(&fixture);
}

TEST(fork_inside_barrier_child_abandons_without_releasing_parent) {
    guard_fixture_t fixture;
    guard_fork_barrier_context_t barrier_state;
    bool blocked = false;
    int competing_lock;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    memset(&barrier_state, 0, sizeof(barrier_state));
    barrier_state.guard = &fixture.guard;
    barrier_state.config_path = fixture.config_path;
    barrier_state.owner = &fixture.owner;
    guard_arm_barrier(0);
    errno = 0;
    CHECK_EQ_INT(
        config_retirement_guard_clear_with_barrier(
            &fixture.guard, guard_fork_abandon_barrier,
            &barrier_state),
        -1);
    CHECK_EQ_INT(errno, EAGAIN);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(WIFEXITED(barrier_state.child_status));
    if (WIFEXITED(barrier_state.child_status)) {
        CHECK_EQ_INT(WEXITSTATUS(barrier_state.child_status), 0);
    }
    CHECK(fixture.guard != NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    competing_lock = open(
        fixture.lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    CHECK(competing_lock >= 0);
    if (competing_lock >= 0) {
        errno = 0;
        CHECK(flock(competing_lock, LOCK_EX | LOCK_NB) != 0 &&
              (errno == EWOULDBLOCK || errno == EAGAIN));
        CHECK_EQ_INT(close(competing_lock), 0);
    }
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(lock_name_replacement_suppresses_barrier) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    hook_replacement[0] = 0x5aU;
    hook_replacement_length = 1U;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_REPLACE_LOCK);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)barrier_call_count, 0);
    CHECK(hook_action_observed);
    CHECK(fixture.guard != NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(unprepared_clear_revalidates_named_lock_before_publish) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    hook_replacement[0] = 0x5aU;
    hook_replacement_length = 1U;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_REPLACE_LOCK);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(hook_action_observed);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(successful_barrier_is_reinvoked_after_pre_rename_failure) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
        HOOK_FAIL);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), 0);
    CHECK_EQ_INT((long)barrier_call_count, 2);
    CHECK(fixture.guard == NULL);
    guard_fixture_cleanup(&fixture);
}

TEST(barrier_cannot_reenter_or_abandon_its_handle) {
    guard_fixture_t fixture;
    guard_reentrant_barrier_context_t context;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    memset(&context, 0, sizeof(context));
    context.guard = &fixture.guard;
    context.recursive_result = 1;
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_reentrant_barrier,
                     &context), 0);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK_EQ_INT(context.recursive_result, -1);
    CHECK(context.abandon_retained);
    CHECK(fixture.guard == NULL);
    guard_fixture_cleanup(&fixture);
}

TEST(callback_armed_post_publish_hook_observes_no_later_checkpoint) {
    guard_fixture_t fixture;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_barrier(0);
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_arm_observation_barrier,
                     NULL), 0);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard == NULL);
    CHECK(hook_armed);
    CHECK(!hook_action_observed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_publish_preserves_stage_replaced_after_barrier) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    size_t observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
        HOOK_REPLACE_STAGE);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    observed_length = guard_read_file(
        fixture.stage_path, observed, sizeof(observed));
    CHECK_EQ_INT(
        (long)observed_length, (long)hook_replacement_length);
    CHECK(memcmp(
        observed, hook_replacement, hook_replacement_length) == 0);
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_publish_preserves_completion_replaced_after_barrier) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    size_t observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
        HOOK_REPLACE_COMPLETION);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    observed_length = guard_read_file(
        fixture.completion_path, observed, sizeof(observed));
    CHECK_EQ_INT(
        (long)observed_length, (long)hook_replacement_length);
    CHECK(memcmp(
        observed, hook_replacement, hook_replacement_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_commit_consumes_exact_certificate_with_later_blocker) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    size_t observed_length;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_PREPARED_PUBLISH,
        HOOK_REPLACE_CANONICAL);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard == NULL);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT(
        (long)observed_length, (long)hook_replacement_length);
    CHECK(memcmp(
        observed, hook_replacement, hook_replacement_length) == 0);
    CHECK_EQ_INT(
        (long)guard_read_file(
            fixture.completion_path, observed, sizeof(observed)),
        (long)fixture.marker_length);
    CHECK(memcmp(
        observed, fixture.marker_data, fixture.marker_length) == 0);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_commit_consumes_handle_when_first_namespace_reproof_fails) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    fixture.marker_length = guard_read_file(
        fixture.marker_path, fixture.marker_data,
        sizeof(fixture.marker_data));
    CHECK(fixture.marker_length > 0U);
    CHECK_EQ_INT(stat(
                     fixture.marker_path,
                     &fixture.marker_identity), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
        HOOK_FAIL);
    guard_arm_barrier(0);

    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard == NULL);
    CHECK_EQ_INT((long)barrier_call_count, 1);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(
        (long)guard_read_file(
            fixture.completion_path, observed, sizeof(observed)),
        (long)fixture.marker_length);
    CHECK(memcmp(
        observed, fixture.marker_data, fixture.marker_length) == 0);
    guard_fixture_cleanup(&fixture);
}

#if !defined(__FreeBSD__)
TEST(prepared_settled_arena_exhaustion_fails_before_stage) {
    guard_fixture_t fixture;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(guard_fixture_rotate_active(&fixture), 0);
    (void)gitswitch_test_set_retirement_settled_slot_limit(2U);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd,
                         SETTLED_PREFIX "0",
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd,
                         SETTLED_PREFIX "1",
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), -1);
    CHECK_EQ_INT(errno, ENOSPC);
    CHECK(strstr(
        get_last_error()->message, "offline quiescent cleanup") != NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    (void)gitswitch_test_set_retirement_settled_slot_limit(0U);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_slot_replacement_after_move_is_preserved) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    char slot_path[256];
    size_t observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(guard_fixture_rotate_active(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
        HOOK_REPLACE_NAMED);
    guard_arm_barrier(0);
    CHECK_EQ_INT(config_retirement_guard_clear_with_barrier(
                     &fixture.guard, guard_commit_barrier, NULL), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK((size_t)snprintf(
              slot_path, sizeof(slot_path), "%s/%s1",
              fixture.directory, SETTLED_PREFIX) < sizeof(slot_path));
    observed_length = guard_read_file(
        slot_path, observed, sizeof(observed));
    CHECK_EQ_INT(
        (long)observed_length, (long)hook_replacement_length);
    CHECK(memcmp(
        observed, hook_replacement, hook_replacement_length) == 0);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    guard_fixture_cleanup(&fixture);
}

TEST(interrupted_slot_move_consumes_slot_and_retry_uses_next) {
    guard_fixture_t fixture;
    char first_slot[256];
    char second_slot[256];

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(guard_fixture_rotate_active(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK((size_t)snprintf(
              first_slot, sizeof(first_slot), "%s/%s0",
              fixture.directory, SETTLED_PREFIX) < sizeof(first_slot));
    CHECK((size_t)snprintf(
              second_slot, sizeof(second_slot), "%s/%s1",
              fixture.directory, SETTLED_PREFIX) < sizeof(second_slot));
    CHECK_EQ_INT(access(first_slot, F_OK), 0);
    CHECK_EQ_INT(access(second_slot, F_OK), 0);
    guard_fixture_cleanup(&fixture);
}
#endif

TEST(prepare_clear_sync_failure_retains_blocking_stage_and_retries) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_clear_reproof_rejects_checkpoint_marker_replacement) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    size_t observed_length;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
        HOOK_REPLACE_CANONICAL);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(prepared_handle_revalidation_rejects_stage_replacement) {
    guard_fixture_t fixture;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, STAGE_NAME,
                         hook_replacement,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(interrupted_prepared_stage_is_adopted_and_settled) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(
        config_retirement_guard_prepare_clear(fixture.guard), 0);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK(fixture.guard == NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    memset(&recovery, 0, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), 0);
    CHECK(adopted != NULL);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    CHECK(adopted == NULL);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(completion_accepts_ctime_only_drift_before_pair_final_reproof) {
    guard_fixture_t fixture;
    bool blocked = true;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
        HOOK_CTIME_AT_INSTALL_SYNC);
    CHECK(guard_probe(&fixture, &blocked));
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(!blocked);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));
    guard_fixture_cleanup(&fixture);
}

TEST(completion_rejects_changed_bytes_before_pair_final_reproof) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat after;
    size_t observed_length;
    bool blocked = false;
    int probe_errno;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
        HOOK_CHANGED_BYTES_RESTORED_MTIME);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), -1);
    probe_errno = errno;
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT(probe_errno, ESTALE);
    CHECK(blocked);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(ts_same_identity(
        &hook_identity_before, &hook_identity_after));
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(hook_replacement_length > 0U);
    CHECK(memcmp(
        hook_original, hook_replacement,
        hook_replacement_length) != 0);

    observed_length = guard_read_file(
        fixture.completion_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    CHECK_EQ_INT(stat(fixture.completion_path, &after), 0);
    CHECK(ts_same_identity(&hook_identity_after, &after));
    memset(observed, 0, sizeof(observed));
    guard_fixture_cleanup(&fixture);
}

TEST(prepublication_sync_failure_stays_blocked_and_converges) {
    guard_fixture_t fixture;
    bool blocked = false;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(hook_armed == false);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    guard_fixture_cleanup(&fixture);
}

static void exercise_postpublication_ack(
    retirement_guard_clear_test_stage_t stage, hook_action_t action) {
    guard_fixture_t fixture;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(stage, action);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard == NULL);
    CHECK(!hook_armed);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);
    guard_fixture_cleanup(&fixture);
}

TEST(postpublication_sync_failures_are_committed) {
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH, HOOK_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC, HOOK_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
        HOOK_SYNC_THEN_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC, HOOK_FAIL);
}

TEST(mixed_generation_probe_never_unblocks) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    bool blocked = true;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
        HOOK_REPLACE_CANONICAL);
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(blocked);
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK(!guard_files_equal(
        fixture.marker_path, fixture.completion_path));

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), 0);
    CHECK(!config_retirement_guard_was_created(recovery));
    CHECK_EQ_INT(config_retirement_guard_clear(&recovery), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(canonical_replacement_before_publication_fails_closed) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    unsigned char stage_observed[GUARD_MAX_BYTES];
    bool blocked = false;
    size_t observed_length;
    size_t stage_observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
        HOOK_REPLACE_CANONICAL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    stage_observed_length = guard_read_file(
        fixture.stage_path, stage_observed, sizeof(stage_observed));
    CHECK_EQ_INT((long)stage_observed_length,
                 (long)fixture.marker_length);
    CHECK(memcmp(stage_observed, fixture.marker_data,
                 fixture.marker_length) == 0);

    config_retirement_guard_abandon(&fixture.guard);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), -1);
    CHECK(recovery == NULL);
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    stage_observed_length = guard_read_file(
        fixture.stage_path, stage_observed, sizeof(stage_observed));
    CHECK_EQ_INT((long)stage_observed_length,
                 (long)fixture.marker_length);
    CHECK(memcmp(stage_observed, fixture.marker_data,
                 fixture.marker_length) == 0);
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(completion_insertion_before_publication_fails_closed) {
    guard_fixture_t fixture;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    memcpy(hook_replacement, fixture.marker_data,
           fixture.marker_length);
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
        HOOK_REPLACE_COMPLETION);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.stage_path));
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(settled_pair_rotates_fresh_and_residue_is_bounded) {
    guard_fixture_t fixture;
    unsigned char previous[GUARD_MAX_BYTES];
    size_t previous_length;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    previous_length = guard_read_file(
        fixture.marker_path, previous, sizeof(previous));
    CHECK(previous_length > 0U);

    for (unsigned int cycle = 0U; cycle < 64U; cycle++) {
        unsigned char current[GUARD_MAX_BYTES];
        size_t current_length;

        CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                         fixture.config_path, CONFIG_RETIREMENT_RESET,
                         &fixture.owner, 1U, &fixture.guard), 0);
        CHECK(config_retirement_guard_was_created(fixture.guard));
        current_length = guard_read_file(
            fixture.marker_path, current, sizeof(current));
        CHECK(current_length > 0U);
        CHECK(current_length != previous_length ||
              memcmp(current, previous, current_length) != 0);
        blocked = false;
        CHECK(guard_probe(&fixture, &blocked));
        CHECK(blocked);
        CHECK(!guard_files_equal(
            fixture.marker_path, fixture.completion_path));
        CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
        CHECK_EQ_INT(guard_count_retirement_entries(
                         fixture.directory, &unexpected), 3);
        CHECK_EQ_INT(unexpected, 0);

        CHECK_EQ_INT(config_retirement_guard_clear(
                         &fixture.guard), 0);
        blocked = true;
        CHECK(guard_probe(&fixture, &blocked));
        CHECK(!blocked);
        CHECK(guard_files_equal(
            fixture.marker_path, fixture.completion_path));
        memcpy(previous, current, current_length);
        previous_length = current_length;
    }
    guard_fixture_cleanup(&fixture);
}

TEST(lone_and_mismatched_certificates_block) {
    guard_fixture_t fixture;
    unsigned char completion[GUARD_MAX_BYTES];
    unsigned char mismatched[GUARD_MAX_BYTES];
    size_t completion_length;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    completion_length = guard_read_file(
        fixture.completion_path, completion, sizeof(completion));
    CHECK(completion_length > 0U);
    CHECK_EQ_INT(unlink(fixture.marker_path), 0);
    directory_fd = open(fixture.directory,
                        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(fsync(directory_fd), 0);
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME,
                         completion, completion_length), 0);
        CHECK(guard_mutate_token(
            completion, completion_length, mismatched));
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, COMPLETE_NAME,
                         mismatched, completion_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(lifecycle_lock_serializes_guard_owners) {
    guard_fixture_t fixture;
    config_retirement_guard_t *second = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &second), -1);
    CHECK(second == NULL);
    CHECK_EQ_INT(errno, EBUSY);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(unproven_install_is_not_adopted_until_directory_sync_succeeds) {
    guard_fixture_t fixture;
    config_retirement_guard_t *retry = NULL;
    unsigned char retained[GUARD_MAX_BYTES];
    struct stat retained_identity;
    size_t retained_length;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);

    guard_arm_hook(
        RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), -1);
    CHECK(retry == NULL);
    CHECK(!hook_armed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    retained_length = guard_read_file(
        fixture.marker_path, retained, sizeof(retained));
    CHECK(retained_length > 0U);
    CHECK_EQ_INT(stat(fixture.marker_path, &retained_identity), 0);
    CHECK(!guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    guard_arm_hook(
        RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), -1);
    CHECK(retry == NULL);
    CHECK(!hook_armed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, hook_replacement,
                     sizeof(hook_replacement)),
                 (long)retained_length);
    CHECK(memcmp(retained, hook_replacement, retained_length) == 0);
    {
        struct stat after;

        CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
        CHECK(ts_same_identity(&retained_identity, &after));
    }
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), 0);
    CHECK(retry != NULL);
    CHECK(!config_retirement_guard_was_created(retry));
    CHECK_EQ_INT(config_retirement_guard_clear(&retry), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(fresh_install_accepts_ctime_only_drift_after_stage_close) {
    guard_fixture_t fixture;
    config_retirement_guard_t *installed = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
        HOOK_CTIME_AT_INSTALL_SYNC);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &installed), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(installed != NULL);
    CHECK(config_retirement_guard_was_created(installed));
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));

    fixture.guard = installed;
    guard_fixture_cleanup(&fixture);
}

TEST(fresh_install_accepts_ctime_only_drift_after_reader_close) {
    guard_fixture_t fixture;
    config_retirement_guard_t *installed = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_READ_AFTER_CLOSE,
        HOOK_CTIME_AFTER_FRESH_READ);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &installed), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(installed != NULL);
    CHECK(config_retirement_guard_was_created(installed));
    CHECK(!hook_armed);
    CHECK(hook_fresh_publish_seen);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));

    fixture.guard = installed;
    guard_fixture_cleanup(&fixture);
}

TEST(fresh_install_accepts_ctime_only_drift_before_pair_final_reproof) {
    guard_fixture_t fixture;
    config_retirement_guard_t *installed = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
        HOOK_CTIME_AFTER_FRESH_READ);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &installed), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(installed != NULL);
    CHECK(config_retirement_guard_was_created(installed));
    CHECK(!hook_armed);
    CHECK(hook_fresh_publish_seen);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));

    fixture.guard = installed;
    guard_fixture_cleanup(&fixture);
}

TEST(fresh_install_rejects_changed_bytes_before_pair_final_reproof) {
    guard_fixture_t fixture;
    config_retirement_guard_t *installed = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat after;
    size_t observed_length;
    int install_errno;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
        HOOK_CHANGED_BYTES_RESTORED_MTIME);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &installed), -1);
    install_errno = errno;
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(installed == NULL);
    CHECK_EQ_INT(install_errno, ESTALE);
    CHECK(!hook_armed);
    CHECK(hook_fresh_publish_seen);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(ts_same_identity(
        &hook_identity_before, &hook_identity_after));
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(hook_replacement_length > 0U);
    CHECK(memcmp(
        hook_original, hook_replacement,
        hook_replacement_length) != 0);

    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&hook_identity_after, &after));
    memset(observed, 0, sizeof(observed));
    guard_fixture_cleanup(&fixture);
}

TEST(fresh_install_rejects_identical_inode_swap_after_reader_close) {
    guard_fixture_t fixture;
    config_retirement_guard_t *installed = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat after;
    size_t observed_length;
    int install_errno;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_READ_AFTER_CLOSE,
        HOOK_REPLACE_AFTER_FRESH_READ);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &installed), -1);
    install_errno = errno;
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(installed == NULL);
    CHECK_EQ_INT(install_errno, ESTALE);
    CHECK(!hook_armed);
    CHECK(hook_fresh_publish_seen);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(!ts_same_identity(
        &hook_identity_before, &hook_identity_after));

    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&hook_identity_after, &after));
    guard_fixture_cleanup(&fixture);
}

TEST(exact_adoption_accepts_retained_marker_ctime_only_drift) {
    guard_fixture_t fixture;
    config_retirement_guard_t *adopted = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK(fixture.guard == NULL);

    guard_arm_hook(
        RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
        HOOK_CTIME_AT_INSTALL_SYNC);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &adopted), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(adopted != NULL);
    CHECK(!config_retirement_guard_was_created(adopted));
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));

    fixture.guard = adopted;
    guard_fixture_cleanup(&fixture);
}

TEST(abandon_after_failed_clear_never_reopens) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK(fixture.guard == NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&recovery), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(recovery_projection_adopts_only_the_exact_active_owner_set) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat after;
    size_t observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(recovery.marker_version, 2);
    CHECK(recovery.ssh_alias_obligation.known);
    CHECK(!recovery.ssh_alias_obligation.present);
    CHECK_EQ_INT(recovery.kind, CONFIG_RETIREMENT_RESET);
    CHECK_EQ_INT((long)recovery.owner_count, 1);
    CHECK_EQ_INT(recovery.owners[0].account_id,
                 fixture.owner.account_id);
    CHECK(strcmp(recovery.owners[0].account_incarnation,
                 fixture.owner.account_incarnation) == 0);

    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_REMOVE,
                     &fixture.owner, 1U, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&fixture.marker_identity, &after));
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, fixture.marker_data,
                 fixture.marker_length) == 0);

    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), 0);
    CHECK(adopted != NULL);
    CHECK(!config_retirement_guard_was_created(adopted));
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&fixture.marker_identity, &after));
    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    CHECK(adopted == NULL);

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(!recovery.valid);
    CHECK_EQ_INT((long)recovery.owner_count, 0);
    guard_fixture_cleanup(&fixture);
}

TEST(v2_remove_alias_obligation_roundtrips_and_adopts_exactly) {
    guard_fixture_t fixture;
    config_retirement_ssh_alias_obligation_t obligation;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_make_alias_obligation(
        &fixture, "github.com-work", &obligation));
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &obligation, &fixture.guard), 0);
    config_retirement_guard_abandon(&fixture.guard);

    memset(&recovery, 0, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(recovery.marker_version, 2);
    CHECK(recovery.ssh_alias_obligation.known);
    CHECK(recovery.ssh_alias_obligation.present);
    CHECK(strcmp(recovery.ssh_alias_obligation.ssh_host_alias,
                 obligation.ssh_host_alias) == 0);
    CHECK(strcmp(recovery.ssh_alias_obligation.home_path,
                 obligation.home_path) == 0);
    CHECK(publication_identity_equal(
        &recovery.ssh_alias_obligation.home_identity,
        &obligation.home_identity));
    CHECK(publication_identity_equal(
        &recovery.ssh_alias_obligation.ssh_directory_identity,
        &obligation.ssh_directory_identity));
    CHECK_EQ_INT(
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            fixture.config_path, recovery.kind, recovery.owners,
            recovery.owner_count, &recovery.ssh_alias_obligation,
            &adopted), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(v1_reset_projects_no_alias_obligation_and_legacy_wrappers_adopt) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char legacy[GUARD_MAX_BYTES];
    size_t legacy_length;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);
    legacy_length = guard_make_v1_marker(
        &fixture, CONFIG_RETIREMENT_RESET, legacy);
    CHECK(legacy_length > 0U);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME, legacy,
                         legacy_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(recovery.marker_version, 1);
    CHECK(recovery.ssh_alias_obligation.known);
    CHECK(!recovery.ssh_alias_obligation.present);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), 0);
    CHECK(adopted != NULL);
    CHECK(!config_retirement_guard_was_created(adopted));
    config_retirement_guard_abandon(&adopted);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(v1_remove_projects_unknown_alias_and_cannot_be_adopted) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char legacy[GUARD_MAX_BYTES];
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat legacy_identity;
    struct stat after;
    size_t legacy_length;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);
    legacy_length = guard_make_v1_marker(
        &fixture, CONFIG_RETIREMENT_REMOVE, legacy);
    CHECK(legacy_length > 0U);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME, legacy,
                         legacy_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(stat(fixture.marker_path, &legacy_identity), 0);

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(recovery.marker_version, 1);
    CHECK_EQ_INT(recovery.kind, CONFIG_RETIREMENT_REMOVE);
    CHECK(!recovery.ssh_alias_obligation.known);
    CHECK(!recovery.ssh_alias_obligation.present);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            fixture.config_path, recovery.kind, recovery.owners,
            recovery.owner_count, &recovery.ssh_alias_obligation,
            &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&legacy_identity, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)legacy_length);
    CHECK(memcmp(observed, legacy, legacy_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(changed_alias_obligation_never_adopts_or_mutates_marker) {
    guard_fixture_t fixture;
    config_retirement_ssh_alias_obligation_t obligation;
    config_retirement_ssh_alias_obligation_t changed;
    config_retirement_guard_t *adopted = NULL;
    unsigned char marker[GUARD_MAX_BYTES];
    struct stat identity;
    struct stat after;
    size_t marker_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_make_alias_obligation(
        &fixture, "github.com-work", &obligation));
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &obligation, &fixture.guard), 0);
    config_retirement_guard_abandon(&fixture.guard);
    marker_length = guard_read_file(
        fixture.marker_path, marker, sizeof(marker));
    CHECK(marker_length > 0U);
    CHECK_EQ_INT(stat(fixture.marker_path, &identity), 0);

    changed = obligation;
    memcpy(changed.ssh_host_alias, "github.com-other",
           sizeof("github.com-other"));
    CHECK_EQ_INT(
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &changed, &adopted), -1);
    changed = obligation;
    changed.home_path[strlen(changed.home_path) - 1U] ^= 1;
    CHECK_EQ_INT(
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &changed, &adopted), -1);
    changed = obligation;
    changed.home_identity.inode++;
    CHECK_EQ_INT(
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &changed, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&identity, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, hook_replacement,
                     sizeof(hook_replacement)),
                 (long)marker_length);
    CHECK(memcmp(marker, hook_replacement, marker_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(malformed_v2_alias_field_is_rejected_without_rewrite) {
    guard_fixture_t fixture;
    config_retirement_ssh_alias_obligation_t obligation;
    config_retirement_recovery_t recovery;
    unsigned char malformed[GUARD_MAX_BYTES];
    unsigned char observed[GUARD_MAX_BYTES];
    static const char alias_prefix[] = "ssh_alias=";
    unsigned char *alias;
    struct stat identity;
    struct stat after;
    size_t length;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_make_alias_obligation(
        &fixture, "github.com-work", &obligation));
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &obligation, &fixture.guard), 0);
    config_retirement_guard_abandon(&fixture.guard);
    length = guard_read_file(
        fixture.marker_path, malformed, sizeof(malformed));
    alias = memmem(malformed, length, alias_prefix,
                   sizeof(alias_prefix) - 1U);
    CHECK(alias != NULL);
    if (alias) {
        alias[sizeof(alias_prefix) - 1U] = (unsigned char)'Z';
    }
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME, malformed,
                         length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(stat(fixture.marker_path, &identity), 0);
    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), -1);
    CHECK(!recovery.valid);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&identity, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)length);
    CHECK(memcmp(malformed, observed, length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(alias_obligation_is_remove_only_and_single_owner) {
    guard_fixture_t fixture;
    config_retirement_ssh_alias_obligation_t obligation;
    config_retirement_owner_t owners[2];
    config_retirement_guard_t *guard = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_make_alias_obligation(
        &fixture, "github.com-work", &obligation));
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_RESET,
            &fixture.owner, 1U, &obligation, &guard), -1);
    owners[0] = fixture.owner;
    owners[1] = fixture.owner;
    owners[1].account_id = UINT32_C(2);
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            owners, 2U, &obligation, &guard), -1);
    CHECK(guard == NULL);
    guard_fixture_cleanup(&fixture);
}

TEST(handle_revalidation_accepts_only_its_exact_active_generation) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
        HOOK_CTIME_AT_INSTALL_SYNC);
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(guard_same_except_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK(!guard_same_ctime(
        &hook_identity_before, &hook_identity_after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, fixture.marker_data,
                 fixture.marker_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(handle_revalidation_rejects_marker_replacement_without_mutation) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat replacement;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME,
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(stat(fixture.marker_path, &replacement), 0);
    CHECK(!ts_same_identity(
        &fixture.marker_identity, &replacement));
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, fixture.marker_data,
                 fixture.marker_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(handle_revalidation_rejects_obligation_change_without_rewrite) {
    guard_fixture_t fixture;
    config_retirement_ssh_alias_obligation_t obligation;
    unsigned char changed[GUARD_MAX_BYTES];
    unsigned char observed[GUARD_MAX_BYTES];
    static const char alias_prefix[] = "ssh_alias=";
    unsigned char *alias;
    size_t changed_length;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_make_alias_obligation(
        &fixture, "github.com-work", &obligation));
    CHECK_EQ_INT(
        config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
            fixture.config_path, CONFIG_RETIREMENT_REMOVE,
            &fixture.owner, 1U, &obligation, &fixture.guard), 0);
    changed_length = guard_read_file(
        fixture.marker_path, changed, sizeof(changed));
    alias = memmem(changed, changed_length, alias_prefix,
                   sizeof(alias_prefix) - 1U);
    CHECK(alias != NULL);
    if (alias) {
        alias += sizeof(alias_prefix) - 1U;
        *alias = *alias == (unsigned char)'6'
                     ? (unsigned char)'7'
                     : (unsigned char)'6';
    }
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME, changed,
                         changed_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)changed_length);
    CHECK(memcmp(observed, changed, changed_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(handle_revalidation_rejects_stage_and_certificate_interference) {
    guard_fixture_t fixture;
    unsigned char observed[GUARD_MAX_BYTES];
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, STAGE_NAME,
                         fixture.marker_data,
                         fixture.marker_length), 0);
    }
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT(unlink(fixture.stage_path), 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, COMPLETE_NAME,
                         fixture.marker_data,
                         fixture.marker_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, fixture.marker_data,
                 fixture.marker_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST(handle_revalidation_rejects_directory_namespace_replacement) {
    guard_fixture_t fixture;
    char displaced[160];

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK((size_t)snprintf(
              displaced, sizeof(displaced), "%s.displaced",
              fixture.directory) < sizeof(displaced));
    CHECK_EQ_INT(rename(fixture.directory, displaced), 0);
    CHECK_EQ_INT(mkdir(fixture.directory, 0700), 0);
    CHECK_EQ_INT(config_retirement_guard_revalidate(fixture.guard), -1);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(rmdir(fixture.directory), 0);
    CHECK_EQ_INT(rename(displaced, fixture.directory), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(adopt_only_never_creates_or_rotates_a_marker) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char settled[GUARD_MAX_BYTES];
    unsigned char observed[GUARD_MAX_BYTES];
    struct stat settled_identity;
    size_t settled_length;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK_EQ_INT(unlink(fixture.marker_path), 0);
    CHECK_EQ_INT(unlink(fixture.lock_path), 0);
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(fsync(directory_fd), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(!recovery.valid);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK(access(fixture.marker_path, F_OK) != 0 && errno == ENOENT);
    CHECK(access(fixture.completion_path, F_OK) != 0 &&
          errno == ENOENT);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(access(fixture.lock_path, F_OK) != 0 && errno == ENOENT);

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    settled_length = guard_read_file(
        fixture.marker_path, settled, sizeof(settled));
    CHECK(settled_length > 0U);
    CHECK_EQ_INT(stat(fixture.marker_path, &settled_identity), 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));

    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)settled_length);
    CHECK(memcmp(settled, observed, settled_length) == 0);
    {
        struct stat after;

        CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
        CHECK(ts_same_identity(&settled_identity, &after));
    }
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    guard_fixture_cleanup(&fixture);
}

TEST(exact_staged_clear_is_projected_adopted_and_settled) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    config_retirement_guard_abandon(&fixture.guard);

    memset(&recovery, 0, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    CHECK_EQ_INT(recovery.kind, CONFIG_RETIREMENT_RESET);
    CHECK_EQ_INT((long)recovery.owner_count, 1);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count, &adopted), 0);
    CHECK(adopted != NULL);
    CHECK(!config_retirement_guard_was_created(adopted));
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, observed, sizeof(observed)),
                 (long)fixture.marker_length);
    CHECK(memcmp(observed, fixture.marker_data,
                 fixture.marker_length) == 0);

    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    CHECK(adopted == NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    guard_fixture_cleanup(&fixture);
}

TEST(exact_stage_cleanup_reproves_one_ctime_only_reader_race) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture.guard);

    memset(&recovery, 0, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    guard_arm_hook(
        RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
        HOOK_CTIME_AFTER_STAGE_REMOVAL);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count,
                     &adopted), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(adopted != NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(config_retirement_guard_clear(&adopted), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(exact_stage_cleanup_rejects_changed_bytes_after_reader_race) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture.guard);

    memset(&recovery, 0, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), 0);
    CHECK(recovery.valid);
    guard_arm_hook(
        RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
        HOOK_CHANGED_BYTES_AFTER_STAGE_REMOVAL);
    errno = 0;
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, recovery.kind,
                     recovery.owners, recovery.owner_count,
                     &adopted), -1);
    CHECK_EQ_INT(errno, ESTALE);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(adopted == NULL);
    CHECK(!hook_armed);
    CHECK(hook_action_observed);
    CHECK_EQ_INT((long)hook_action_count, 1);
    CHECK_EQ_INT(hook_action_error, 0);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(foreign_staged_generation_remains_fail_closed_and_untouched) {
    guard_fixture_t fixture;
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *adopted = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    directory_fd = open(
        fixture.directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, STAGE_NAME,
                         hook_replacement,
                         hook_replacement_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }

    memset(&recovery, 0xA5, sizeof(recovery));
    CHECK_EQ_INT(config_retirement_guard_recovery_probe(
                     fixture.config_path, &recovery), -1);
    CHECK(!recovery.valid);
    CHECK_EQ_INT(config_retirement_guard_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &adopted), -1);
    CHECK(adopted == NULL);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &fixture.guard), -1);
    CHECK(fixture.guard == NULL);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.stage_path, observed, sizeof(observed)),
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);
    guard_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(
        fork_child_abandon_preserves_reused_retirement_guard_directory_fd);
    RUN_TEST(completion_keeps_canonical_generation_and_unblocks);
    RUN_TEST(
        prepared_clear_is_durable_blocking_and_commits_without_ack_hooks);
    RUN_TEST(prepared_clear_skips_directory_sync_hooks);
    RUN_TEST(prepared_clear_replaces_a_prior_completion_generation);
    RUN_TEST(
        prepare_clear_rejects_foreign_stage_without_deleting_it);
    RUN_TEST(
        prepared_handle_rejects_completion_inserted_after_prepare);
    RUN_TEST(
        prepared_handle_rejects_prior_completion_inode_replacement);
    RUN_TEST(
        prepared_handle_accepts_prior_completion_ctime_only_drift);
    RUN_TEST(
        prepared_handle_rejects_prior_completion_content_change);
    RUN_TEST(
        prepared_clear_failure_before_rename_retains_blocking_stage);
    RUN_TEST(
        prepared_barrier_eagain_retains_capability_and_retry_commits);
    RUN_TEST(prepared_guard_mismatch_prevents_barrier_invocation);
    RUN_TEST(prepared_barrier_hard_failure_retains_blocking_state);
    RUN_TEST(fork_child_cannot_invoke_barrier_and_parent_can_retry);
    RUN_TEST(
        fork_inside_barrier_child_abandons_without_releasing_parent);
    RUN_TEST(lock_name_replacement_suppresses_barrier);
    RUN_TEST(unprepared_clear_revalidates_named_lock_before_publish);
    RUN_TEST(successful_barrier_is_reinvoked_after_pre_rename_failure);
    RUN_TEST(barrier_cannot_reenter_or_abandon_its_handle);
    RUN_TEST(
        callback_armed_post_publish_hook_observes_no_later_checkpoint);
    RUN_TEST(
        prepared_publish_preserves_stage_replaced_after_barrier);
    RUN_TEST(
        prepared_publish_preserves_completion_replaced_after_barrier);
    RUN_TEST(
        prepared_commit_consumes_exact_certificate_with_later_blocker);
    RUN_TEST(
        prepared_commit_consumes_handle_when_first_namespace_reproof_fails);
#if !defined(__FreeBSD__)
    RUN_TEST(prepared_settled_arena_exhaustion_fails_before_stage);
    RUN_TEST(prepared_slot_replacement_after_move_is_preserved);
    RUN_TEST(interrupted_slot_move_consumes_slot_and_retry_uses_next);
#endif
    RUN_TEST(
        prepare_clear_sync_failure_retains_blocking_stage_and_retries);
    RUN_TEST(
        prepared_clear_reproof_rejects_checkpoint_marker_replacement);
    RUN_TEST(prepared_handle_revalidation_rejects_stage_replacement);
    RUN_TEST(interrupted_prepared_stage_is_adopted_and_settled);
    RUN_TEST(
        completion_accepts_ctime_only_drift_before_pair_final_reproof);
    RUN_TEST(
        completion_rejects_changed_bytes_before_pair_final_reproof);
    RUN_TEST(prepublication_sync_failure_stays_blocked_and_converges);
    RUN_TEST(postpublication_sync_failures_are_committed);
    RUN_TEST(mixed_generation_probe_never_unblocks);
    RUN_TEST(canonical_replacement_before_publication_fails_closed);
    RUN_TEST(completion_insertion_before_publication_fails_closed);
    RUN_TEST(settled_pair_rotates_fresh_and_residue_is_bounded);
    RUN_TEST(lone_and_mismatched_certificates_block);
    RUN_TEST(lifecycle_lock_serializes_guard_owners);
    RUN_TEST(unproven_install_is_not_adopted_until_directory_sync_succeeds);
    RUN_TEST(fresh_install_accepts_ctime_only_drift_after_stage_close);
    RUN_TEST(fresh_install_accepts_ctime_only_drift_after_reader_close);
    RUN_TEST(
        fresh_install_accepts_ctime_only_drift_before_pair_final_reproof);
    RUN_TEST(
        fresh_install_rejects_changed_bytes_before_pair_final_reproof);
    RUN_TEST(fresh_install_rejects_identical_inode_swap_after_reader_close);
    RUN_TEST(exact_adoption_accepts_retained_marker_ctime_only_drift);
    RUN_TEST(abandon_after_failed_clear_never_reopens);
    RUN_TEST(recovery_projection_adopts_only_the_exact_active_owner_set);
    RUN_TEST(v2_remove_alias_obligation_roundtrips_and_adopts_exactly);
    RUN_TEST(v1_reset_projects_no_alias_obligation_and_legacy_wrappers_adopt);
    RUN_TEST(v1_remove_projects_unknown_alias_and_cannot_be_adopted);
    RUN_TEST(changed_alias_obligation_never_adopts_or_mutates_marker);
    RUN_TEST(malformed_v2_alias_field_is_rejected_without_rewrite);
    RUN_TEST(alias_obligation_is_remove_only_and_single_owner);
    RUN_TEST(handle_revalidation_accepts_only_its_exact_active_generation);
    RUN_TEST(handle_revalidation_rejects_marker_replacement_without_mutation);
    RUN_TEST(handle_revalidation_rejects_obligation_change_without_rewrite);
    RUN_TEST(handle_revalidation_rejects_stage_and_certificate_interference);
    RUN_TEST(handle_revalidation_rejects_directory_namespace_replacement);
    RUN_TEST(adopt_only_never_creates_or_rotates_a_marker);
    RUN_TEST(exact_staged_clear_is_projected_adopted_and_settled);
    RUN_TEST(exact_stage_cleanup_reproves_one_ctime_only_reader_race);
    RUN_TEST(exact_stage_cleanup_rejects_changed_bytes_after_reader_race);
    RUN_TEST(foreign_staged_generation_remains_fail_closed_and_untouched);
TEST_MAIN_END()
