/* AR-11 M20: changed gpg-agent.conf bytes must be applied to a persistent
 * agent before an isolated identity is published.  These tests use the
 * public home/switch flows and the command-runner seam: no real keyring or
 * operator agent is touched. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "runner_internal.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define M20_PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define M20_SECRET_LISTING                                                   \
    "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" M20_PRIMARY_FPR ":\n"

static const char m20_config_a[] =
    "default-cache-ttl 17\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_config_b[] =
    "default-cache-ttl 29\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_live_config_a[] =
    "s2k-count 65536\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_live_config_b[] =
    "s2k-count 1048576\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";

typedef struct {
    bool present;
    char *value;
} m20_saved_env_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char gpg[MAX_PATH_LEN];
    char gpgconf[MAX_PATH_LEN];
    char base[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    char source_config[MAX_PATH_LEN];
    char installed_config[MAX_PATH_LEN];
    char reload_state[MAX_PATH_LEN];
    account_t account;
} m20_fixture_t;

typedef enum {
    M20_TOOLS_STABLE_REQUIRED = 0,
    M20_TOOLS_LIVE_OPTIONAL = 1
} m20_tool_fixture_t;

static char g_expected_home[MAX_PATH_LEN];
static char g_expected_gpg[MAX_PATH_LEN];
static char g_expected_gpgconf[MAX_PATH_LEN];
static const char *g_expected_reload_config;
static int g_reload_calls;
static int g_reload_protocol_errors;
static int g_gpg_listing_calls;
static int g_config_commits;
static bool g_fail_reload;
static bool g_reload_capture_is_merged;
typedef enum {
    M20_COMPONENT_METADATA_VALID = 0,
    M20_COMPONENT_METADATA_MISMATCHED_GPG,
    M20_COMPONENT_METADATA_DUPLICATE_GPG,
    M20_COMPONENT_METADATA_MISSING_GPG,
    M20_COMPONENT_METADATA_MALFORMED_ESCAPE,
    M20_COMPONENT_METADATA_EXTRA_FIELD,
    M20_COMPONENT_METADATA_NONABSOLUTE_PATH
} m20_component_metadata_t;
static m20_component_metadata_t g_component_metadata;
static bool g_advance_gpgconf_epoch_after_components;
static bool g_advance_toolchain_epoch_after_reload;
static int g_live_reload_calls;
static int g_sync_file_calls;
static int g_sync_directory_calls;
static int g_fail_file_sync_at;
static int g_fail_directory_sync_at;
static bool g_fail_clean_marker_sync;
static bool g_fail_closed_home_sync;
static int g_fail_closed_home_sync_at;
static int g_closed_home_sync_calls;
typedef enum {
    M20_RELOAD_MUTATION_NONE = 0,
    M20_RELOAD_MUTATION_EXACT_CTIME,
    M20_RELOAD_MUTATION_DIFFERENT_BYTES,
    M20_RELOAD_MUTATION_MTIME,
    M20_RELOAD_MUTATION_IDENTICAL_REPLACEMENT,
    M20_RELOAD_MUTATION_PUBLIC_MODE,
    M20_RELOAD_MUTATION_HARDLINK,
    M20_RELOAD_MUTATION_TRUNCATE,
    M20_RELOAD_MUTATION_UNLINK
} m20_reload_mutation_t;
static m20_reload_mutation_t g_reload_mutation;
static int g_sync_mutation_at;
static m20_reload_mutation_t g_sync_mutation;
static m20_reload_mutation_t g_closed_home_sync_mutation;
static int g_closed_home_sync_mutation_applications;
static bool g_closed_home_sync_observed;
static bool g_closed_home_sync_mutation_identity_valid;
static struct stat g_closed_home_sync_mutation_before;
static struct stat g_closed_home_sync_mutation_after;
static int g_publication_hook_calls;
static int g_publication_mutation_applications;
static int g_publication_mutation_limit;
static gpg_agent_conf_publication_hook_stage_t
    g_publication_mutation_stage;
static m20_reload_mutation_t g_publication_mutation;
static bool g_publication_hook_fail_without_errno;
static int g_terminal_preopen_calls;
static int g_terminal_preopen_mutation_applications;
static int g_terminal_preopen_mutation_limit;
static m20_reload_mutation_t g_terminal_preopen_mutation;
static bool g_terminal_preopen_fail_without_errno;
static int g_postclose_mutation_count;
static int g_postclose_mutation_applications;
static int g_postclose_first_stable_at;
static int g_postclose_mutation_limit;
static int g_postclose_mutation_at;
static m20_reload_mutation_t g_postclose_mutation;
static bool g_postclose_replace_reload_state;
static bool g_postclose_require_closed_reload_state;
static bool g_postclose_observed_closed_reload_state;
static bool g_postclose_fail_without_errno;
static int g_text_settle_mutation_limit;
static int g_text_settle_attempts;
static int g_text_settle_file_syncs;
static int g_text_settle_parent_barriers;
static int g_text_settle_mutation_applications;
static bool g_text_settle_observed_closed;
static bool g_text_publisher_open;
static int g_text_postclose_mutation_limit;
static int g_text_postclose_mutation_applications;
static bool g_text_postclose_observed_closed;
static char g_hosted_tools_dir[MAX_PATH_LEN];
static m20_saved_env_t g_hosted_tools_path;
static bool g_hosted_tools_path_saved;
static bool g_hosted_tools_active;

static m20_saved_env_t m20_save_env(const char *name) {
    const char *value = getenv(name);
    m20_saved_env_t saved = {
        .present = value != NULL,
        .value = value ? strdup(value) : NULL
    };

    return saved;
}

static int m20_restore_env(const char *name, m20_saved_env_t *saved) {
    int rc;

    if (!name || !saved || (saved->present && !saved->value)) {
        errno = EINVAL;
        return -1;
    }
    rc = saved->present ? setenv(name, saved->value, 1) : unsetenv(name);
    free(saved->value);
    saved->value = NULL;
    saved->present = false;
    return rc;
}

/* Production deliberately rejects package-manager executables below a
 * group/world-writable ancestor. Hosted Darwin installs GnuPG below such a
 * Homebrew prefix, so relocate the already-provisioned suite into the same
 * private trusted fixture class used by the other real-runtime tests. The
 * original paths are byte sources only and are never launched here. */
static int m20_find_provisioned_tool(const char *name, char *output,
                                     size_t output_size) {
    const char *path = getenv("PATH");
    const char *cursor;
    size_t name_len;

    if (!name || !*name || !output || output_size == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (!path) {
        errno = ENOENT;
        return -1;
    }
    name_len = strlen(name);
    cursor = path;
    while (true) {
        const char *separator = strchr(cursor, ':');
        size_t directory_len = separator
                                   ? (size_t)(separator - cursor)
                                   : strlen(cursor);

        if (directory_len > 0U &&
            directory_len <= SIZE_MAX - name_len - 2U &&
            directory_len + name_len + 2U <= MAX_PATH_LEN) {
            char candidate[MAX_PATH_LEN];
            char resolved[MAX_PATH_LEN];
            struct stat st;

            memcpy(candidate, cursor, directory_len);
            candidate[directory_len] = '/';
            memcpy(candidate + directory_len + 1U, name, name_len + 1U);
            if (realpath(candidate, resolved) &&
                stat(resolved, &st) == 0 && S_ISREG(st.st_mode) &&
                (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 &&
                access(resolved, X_OK) == 0 &&
                safe_strncpy(output, resolved, output_size) == 0) {
                return 0;
            }
        }
        if (!separator) break;
        cursor = separator + 1;
    }
    errno = ENOENT;
    return -1;
}

static int m20_restore_hosted_tools(void) {
    int saved_errno = 0;

    if (g_hosted_tools_path_saved &&
        m20_restore_env("PATH", &g_hosted_tools_path) != 0) {
        saved_errno = errno ? errno : EIO;
    }
    g_hosted_tools_path_saved = false;
    g_hosted_tools_active = false;
    if (g_hosted_tools_dir[0] != '\0') {
        if (ts_cleanup_tracked_tmpdir(g_hosted_tools_dir) != 0 &&
            errno != ENOENT && saved_errno == 0) {
            saved_errno = errno ? errno : EIO;
        }
        g_hosted_tools_dir[0] = '\0';
    }
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m20_prepend_hosted_tools_path(void) {
    const char *path = getenv("PATH");
    size_t directory_len = strlen(g_hosted_tools_dir);
    size_t path_len = path ? strlen(path) : 0U;
    size_t combined_size;
    char *combined;
    int rc;

    if (directory_len == 0U ||
        path_len > SIZE_MAX - directory_len - 2U) {
        errno = directory_len == 0U ? EINVAL : EOVERFLOW;
        return -1;
    }
    combined_size =
        directory_len + (path_len > 0U ? path_len + 1U : 0U) + 1U;
    combined = malloc(combined_size);
    if (!combined) return -1;
    memcpy(combined, g_hosted_tools_dir, directory_len);
    if (path_len > 0U) {
        combined[directory_len] = ':';
        memcpy(combined + directory_len + 1U, path, path_len + 1U);
    } else {
        combined[directory_len] = '\0';
    }
    rc = setenv("PATH", combined, 1);
    free(combined);
    return rc;
}

/* Return 0 when trusted tools are ready, 1 when no provisioned suite exists,
 * and -1 for a fixture failure. A relocated suite remains active for this
 * process so every deterministic transaction observes one stable generation. */
static int m20_prepare_hosted_tools(void) {
    static const char *const names[] = {
        "gpg", "gpgconf", "gpg-connect-agent"
    };
    char sources[3][MAX_PATH_LEN];
    char destination[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];

    if (find_command_path(names[0], resolved, sizeof(resolved)) == 0 &&
        find_command_path(names[1], resolved, sizeof(resolved)) == 0 &&
        find_command_path(names[2], resolved, sizeof(resolved)) == 0) {
        return 0;
    }
    for (size_t i = 0; i < 3U; i++) {
        if (m20_find_provisioned_tool(
                names[i], sources[i], sizeof(sources[i])) != 0) {
            return errno == ENOENT ? 1 : -1;
        }
    }
    g_hosted_tools_path = m20_save_env("PATH");
    if (g_hosted_tools_path.present && !g_hosted_tools_path.value) {
        errno = ENOMEM;
        return -1;
    }
    g_hosted_tools_path_saved = true;
    if (!ts_mkdtemp_trusted(
            g_hosted_tools_dir, sizeof(g_hosted_tools_dir),
            "gitswitch-ar11-reload-tools")) {
        goto fail;
    }
    for (size_t i = 0; i < 3U; i++) {
        if (safe_snprintf(destination, sizeof(destination), "%s/%s",
                          g_hosted_tools_dir, names[i]) != 0 ||
            copy_file(sources[i], destination) != 0 ||
            chmod(destination, 0700) != 0) {
            goto fail;
        }
    }
    if (m20_prepend_hosted_tools_path() != 0) goto fail;
    g_hosted_tools_active = true;
    for (size_t i = 0; i < 3U; i++) {
        if (safe_snprintf(destination, sizeof(destination), "%s/%s",
                          g_hosted_tools_dir, names[i]) != 0 ||
            find_command_path(names[i], resolved, sizeof(resolved)) != 0 ||
            strcmp(resolved, destination) != 0) {
            errno = errno ? errno : ENOEXEC;
            goto fail;
        }
    }
    return 0;

fail:
    {
        int saved_errno = errno ? errno : EIO;

        (void)m20_restore_hosted_tools();
        errno = saved_errno;
        return -1;
    }
}

static const char *m20_extra_env(const run_opts_t *opts,
                                 const char *prefix) {
    size_t prefix_len;

    if (!opts || !opts->extra_env || !prefix) return NULL;
    prefix_len = strlen(prefix);
    for (size_t i = 0; opts->extra_env[i]; i++) {
        if (strncmp(opts->extra_env[i], prefix, prefix_len) == 0) {
            return opts->extra_env[i] + prefix_len;
        }
    }
    return NULL;
}

static bool m20_unsets_env(const run_opts_t *opts, const char *name) {
    if (!opts || !opts->unset_env || !name) return false;
    for (size_t i = 0; opts->unset_env[i]; i++) {
        if (strcmp(opts->unset_env[i], name) == 0) return true;
    }
    return false;
}

static bool m20_argv_has(const char *const argv[], const char *value) {
    if (!argv || !value) return false;
    for (size_t i = 0; argv[i]; i++) {
        if (strcmp(argv[i], value) == 0) return true;
    }
    return false;
}

static int m20_read_config_at(int home_fd, char *output, size_t output_size) {
    size_t used = 0;
    int fd;

    if (home_fd < 0 || !output || output_size < 2) return -1;
    output[0] = '\0';
    fd = openat(home_fd, "gpg-agent.conf",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    while (used + 1U < output_size) {
        ssize_t count = read(fd, output + used, output_size - used - 1U);

        if (count > 0) {
            used += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    output[used] = '\0';
    if (close(fd) != 0) return -1;
    return 0;
}

static bool m20_reload_shape_is_exact(const char *const argv[]) {
    return argv && argv[0] && argv[1] && argv[2] && !argv[3] &&
           argv[0][0] == '/' &&
           strcmp(argv[0], g_expected_gpgconf) == 0 &&
           strcmp(argv[1], "--reload") == 0 &&
           strcmp(argv[2], "gpg-agent") == 0;
}

static bool m20_same_file_version(const struct stat *left,
                                  const struct stat *right) {
    if (!left || !right || left->st_dev != right->st_dev ||
        left->st_ino != right->st_ino || left->st_mode != right->st_mode ||
        left->st_uid != right->st_uid || left->st_gid != right->st_gid ||
        left->st_nlink != right->st_nlink ||
        left->st_size != right->st_size) {
        return false;
    }
#ifdef __APPLE__
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

static bool m20_ctime_only_file_change(const struct stat *left,
                                       const struct stat *right) {
    if (!left || !right || left->st_dev != right->st_dev ||
        left->st_ino != right->st_ino || left->st_mode != right->st_mode ||
        left->st_uid != right->st_uid || left->st_gid != right->st_gid ||
        left->st_nlink != right->st_nlink ||
        left->st_size != right->st_size) {
        return false;
    }
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           (left->st_ctimespec.tv_sec != right->st_ctimespec.tv_sec ||
            left->st_ctimespec.tv_nsec != right->st_ctimespec.tv_nsec);
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           (left->st_ctim.tv_sec != right->st_ctim.tv_sec ||
            left->st_ctim.tv_nsec != right->st_ctim.tv_nsec);
#endif
}

static int m20_full_sync_fd(int fd) {
#ifdef __APPLE__
    if (fcntl(fd, F_FULLFSYNC) == 0) return 0;
    if (errno != ENOTSUP && errno != ENOTTY && errno != EINVAL) return -1;
#endif
    return fsync(fd);
}

static int m20_open_private_directory(const char *path) {
    struct stat named_before;
    struct stat opened;
    struct stat named_after;
    int fd;

    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &named_before) != 0) return -1;
    if (!S_ISDIR(named_before.st_mode) ||
        named_before.st_uid != getuid() ||
        (named_before.st_mode & 0777) != 0700) {
        errno = EPERM;
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &opened) != 0 ||
        fstatat(AT_FDCWD, path, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!m20_same_file_version(&named_before, &opened) ||
        !m20_same_file_version(&opened, &named_after)) {
        (void)close(fd);
        errno = ESTALE;
        return -1;
    }
    return fd;
}

static int m20_sync_private_text_at(int parent_fd, const char *leaf) {
    struct stat named_before;
    struct stat opened;
    struct stat named_after;
    int fd;
    int saved_errno = 0;

    if (parent_fd < 0 || !leaf) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(parent_fd, leaf, &named_before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!S_ISREG(named_before.st_mode) ||
        named_before.st_uid != getuid() ||
        named_before.st_nlink != 1) {
        errno = EPERM;
        return -1;
    }
    if ((named_before.st_mode & 0777) != 0600) {
        errno = EPERM;
        return -1;
    }
    fd = openat(parent_fd, leaf,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    if (fstat(fd, &opened) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!m20_same_file_version(&named_before, &opened)) {
        (void)close(fd);
        errno = ESTALE;
        return -1;
    }
    if (m20_full_sync_fd(fd) != 0) saved_errno = errno;
    if (close(fd) != 0 && saved_errno == 0) saved_errno = errno;
    if (saved_errno == 0 &&
        fstatat(parent_fd, leaf, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
    }
    if (saved_errno == 0 &&
        !m20_same_file_version(&opened, &named_after) &&
        !m20_ctime_only_file_change(&opened, &named_after)) {
        saved_errno = ESTALE;
    }
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m20_split_private_path(const char *path, char *parent,
                                  size_t parent_size,
                                  const char **leaf_out) {
    char *slash;

    if (!path || !parent || !leaf_out ||
        safe_strncpy(parent, path, parent_size) != 0 ||
        !(slash = strrchr(parent, '/')) || slash == parent ||
        slash[1] == '\0') {
        errno = EINVAL;
        return -1;
    }
    *leaf_out = path + (slash - parent) + 1;
    *slash = '\0';
    return 0;
}

static int m20_mutate_private_text_successor(const char *path);

static bool m20_same_ctime(const struct stat *left,
                           const struct stat *right) {
#ifdef __APPLE__
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool m20_same_mtime(const struct stat *left,
                           const struct stat *right) {
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static int m20_mutate_private_text_successor(const char *path) {
    struct stat before;
    struct stat after;
    struct timespec times[2];
    mode_t original_mode;
    mode_t alternate_mode;
    unsigned char byte;
    int fd;

    if (!path) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        pread(fd, &byte, 1, 0) != 1) {
        int saved_errno = errno ? errno : ESTALE;

        if (fd >= 0) (void)close(fd);
        errno = saved_errno;
        return -1;
    }
#ifdef __APPLE__
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    original_mode = before.st_mode & 07777;
    alternate_mode = original_mode ^ S_IWUSR;
    if (pwrite(fd, &byte, 1, 0) != 1 ||
        fchmod(fd, alternate_mode) != 0 ||
        fchmod(fd, original_mode) != 0 ||
        futimens(fd, times) != 0 || m20_full_sync_fd(fd) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0) return -1;
    if (stat(path, &after) != 0 ||
        !m20_ctime_only_file_change(&before, &after)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int m20_write_all(int fd, const char *text) {
    size_t length;
    size_t written = 0;

    if (fd < 0 || !text) {
        errno = EINVAL;
        return -1;
    }
    length = strlen(text);
    while (written < length) {
        ssize_t count = write(fd, text + written, length - written);

        if (count > 0) {
            written += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            if (count == 0) errno = EIO;
            return -1;
        }
    }
    return 0;
}

static int m20_write_private_text_at(int parent_fd, const char *leaf,
                                     const char *text, bool exclusive) {
    struct stat opened;
    int flags = O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    int fd = -1;
    int saved_errno = 0;
    bool created = false;

    if (parent_fd < 0 || !leaf || leaf[0] == '\0' ||
        strchr(leaf, '/') || !text) {
        errno = EINVAL;
        return -1;
    }
    fd = openat(parent_fd, leaf, flags | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        created = true;
    } else if (!exclusive && errno == EEXIST) {
        fd = openat(parent_fd, leaf, flags);
    }
    if (fd < 0) return -1;
    if (fstat(fd, &opened) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (!S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1) {
        saved_errno = EPERM;
        goto out;
    }
    if (fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0 ||
        m20_write_all(fd, text) != 0 ||
        m20_full_sync_fd(fd) != 0) {
        saved_errno = errno ? errno : EIO;
    }
out:
    if (fd >= 0 && close(fd) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0 && created) {
        (void)unlinkat(parent_fd, leaf, 0);
    }
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m20_private_text_postclose_hook(const char *path, int proof_fd) {
    if (g_text_postclose_mutation_applications >=
        g_text_postclose_mutation_limit) {
        return 0;
    }
    errno = 0;
    if (proof_fd < 0 ||
        fcntl(proof_fd, F_GETFD) != -1 || errno != EBADF) {
        errno = EBUSY;
        return -1;
    }
    g_text_postclose_observed_closed = true;
    errno = 0;
    if (m20_mutate_private_text_successor(path) != 0) return -1;
    g_text_postclose_mutation_applications++;
    return 0;
}

static int m20_capture_private_text(const char *path, const char *expected,
                                    struct stat *identity) {
    enum { M20_PRIVATE_TEXT_MAX = 96 * 1024 };
    char parent[MAX_PATH_LEN];
    const char *leaf;
    struct stat named_before;
    struct stat opened_before;
    struct stat opened_after;
    struct stat named_before_close;
    struct stat named_after;
    size_t expected_length;
    size_t used = 0;
    char *buffer = NULL;
    unsigned char extra;
    int parent_fd = -1;
    int fd = -1;
    int closed_proof_fd = -1;
    int saved_errno = 0;

    if (!path || !expected || !identity) {
        errno = EINVAL;
        return -1;
    }
    expected_length = strlen(expected);
    if (expected_length > M20_PRIVATE_TEXT_MAX ||
        m20_split_private_path(path, parent, sizeof(parent), &leaf) != 0) {
        if (expected_length > M20_PRIVATE_TEXT_MAX) errno = EOVERFLOW;
        return -1;
    }
    buffer = malloc(expected_length > 0U ? expected_length : 1U);
    if (!buffer) return -1;
    parent_fd = m20_open_private_directory(parent);
    if (parent_fd < 0) {
        saved_errno = errno;
        goto out;
    }
    if (fstatat(parent_fd, leaf, &named_before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (!S_ISREG(named_before.st_mode) ||
        named_before.st_uid != getuid() ||
        named_before.st_nlink != 1 ||
        (named_before.st_mode & 0777) != 0600) {
        saved_errno = EPERM;
        goto out;
    }
    fd = openat(parent_fd, leaf,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        saved_errno = errno;
        goto out;
    }
    if (fstat(fd, &opened_before) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (!m20_same_file_version(&named_before, &opened_before)) {
        saved_errno = ESTALE;
        goto out;
    }
    while (used < expected_length) {
        ssize_t count =
            read(fd, buffer + used, expected_length - used);

        if (count > 0) {
            used += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            saved_errno = errno;
            goto out;
        }
    }
    if (used != expected_length ||
        memcmp(buffer, expected, expected_length) != 0) {
        saved_errno = ESTALE;
        goto out;
    }
    for (;;) {
        ssize_t count = read(fd, &extra, 1U);

        if (count == 0) break;
        if (count > 0) {
            saved_errno = ESTALE;
            goto out;
        }
        if (errno != EINTR) {
            saved_errno = errno;
            goto out;
        }
    }
    if (fstat(fd, &opened_after) != 0 ||
        fstatat(parent_fd, leaf, &named_before_close,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (!m20_same_file_version(&named_before, &opened_before) ||
        !m20_same_file_version(&opened_before, &opened_after) ||
        !m20_same_file_version(
            &opened_after, &named_before_close)) {
        saved_errno = ESTALE;
        goto out;
    }
    closed_proof_fd = fd;
    if (close(fd) != 0) {
        saved_errno = errno;
        fd = -1;
        goto out;
    }
    fd = -1;
    if (m20_private_text_postclose_hook(path, closed_proof_fd) != 0 ||
        fstatat(parent_fd, leaf, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (!m20_same_file_version(
            &named_before_close, &named_after) &&
        !m20_ctime_only_file_change(
            &named_before_close, &named_after)) {
        saved_errno = ESTALE;
        goto out;
    }
out:
    if (fd >= 0 && close(fd) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 &&
        saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0) {
        free(buffer);
        errno = saved_errno;
        return -1;
    }
    *identity = named_after;
    free(buffer);
    return 0;
}

static int m20_private_text_settle_hook(const char *path) {
    g_text_settle_attempts++;
    if (g_text_publisher_open) {
        errno = EBUSY;
        return -1;
    }
    g_text_settle_observed_closed = true;
    if (g_text_settle_mutation_limit < 0 ||
        g_text_settle_mutation_applications <
            g_text_settle_mutation_limit) {
        if (m20_mutate_private_text_successor(path) != 0) return -1;
        g_text_settle_mutation_applications++;
    }
    return 0;
}

static int m20_settle_private_text(const char *path,
                                   const char *expected) {
    enum { M20_TEXT_SETTLE_ATTEMPTS = 8 };
    char parent[MAX_PATH_LEN];
    const char *leaf;
    struct stat previous;
    bool have_previous = false;
    unsigned int stable_transitions = 0;

    if (m20_split_private_path(
            path, parent, sizeof(parent), &leaf) != 0) {
        return -1;
    }
    memset(&previous, 0, sizeof(previous));
    for (int attempt = 0; attempt < M20_TEXT_SETTLE_ATTEMPTS; attempt++) {
        struct stat current;
        int capture_errno;
        int parent_fd = -1;
        int sync_errno = 0;

        if (m20_private_text_settle_hook(path) != 0) return -1;
        parent_fd = m20_open_private_directory(parent);
        if (parent_fd < 0) {
            sync_errno = errno ? errno : EIO;
        } else if (m20_sync_private_text_at(parent_fd, leaf) != 0) {
            sync_errno = errno ? errno : EIO;
        } else {
            g_text_settle_file_syncs++;
            if (m20_full_sync_fd(parent_fd) != 0) {
                sync_errno = errno ? errno : EIO;
            }
        }
        if (parent_fd >= 0 && close(parent_fd) != 0 &&
            sync_errno == 0) {
            sync_errno = errno ? errno : EIO;
        }
        if (sync_errno != 0) {
            if (sync_errno != ESTALE) {
                errno = sync_errno;
                return -1;
            }
            have_previous = false;
            stable_transitions = 0;
            continue;
        }
        g_text_settle_parent_barriers++;
        if (m20_capture_private_text(path, expected, &current) != 0) {
            capture_errno = errno ? errno : EIO;
            if (capture_errno != ESTALE) {
                errno = capture_errno;
                return -1;
            }
            have_previous = false;
            stable_transitions = 0;
            continue;
        }
        if (have_previous &&
            m20_same_file_version(&previous, &current)) {
            stable_transitions++;
            if (stable_transitions >= 2U) return 0;
        } else {
            stable_transitions = 0;
        }
        previous = current;
        have_previous = true;
    }
    errno = ESTALE;
    return -1;
}

static int m20_publish_private_text(const char *path, const char *text) {
    char parent[MAX_PATH_LEN];
    const char *leaf;
    int parent_fd = -1;
    int saved_errno = 0;
    int rc = -1;

    if (m20_split_private_path(path, parent, sizeof(parent), &leaf) != 0) {
        return -1;
    }
    parent_fd = m20_open_private_directory(parent);
    if (parent_fd < 0) return -1;
    g_text_publisher_open = true;
    if (m20_write_private_text_at(parent_fd, leaf, text, false) != 0 ||
        m20_full_sync_fd(parent_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }
    if (close(parent_fd) != 0) {
        saved_errno = errno;
        parent_fd = -1;
        goto out;
    }
    parent_fd = -1;
    g_text_publisher_open = false;
    if (m20_settle_private_text(path, text) != 0) {
        saved_errno = errno ? errno : ESTALE;
        goto out;
    }
    rc = 0;
out:
    if (parent_fd >= 0) {
        if (close(parent_fd) != 0 && saved_errno == 0) {
            saved_errno = errno;
        }
        parent_fd = -1;
    }
    g_text_publisher_open = false;
    if (rc != 0) errno = saved_errno ? saved_errno : EIO;
    return rc;
}

static int m20_replace_private_text_atomically(const char *path,
                                               const char *text) {
    static const char temporary_leaf[] =
        ".gitswitch-ar11-fixture-replacement";
    char parent[MAX_PATH_LEN];
    const char *leaf;
    int parent_fd = -1;
    int saved_errno = 0;
    int rc = -1;
    bool temporary_created = false;

    if (m20_split_private_path(path, parent, sizeof(parent), &leaf) != 0) {
        return -1;
    }
    parent_fd = m20_open_private_directory(parent);
    if (parent_fd < 0) return -1;
    g_text_publisher_open = true;
    if (m20_write_private_text_at(parent_fd, temporary_leaf, text, true) !=
        0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }
    temporary_created = true;
    if (renameat(parent_fd, temporary_leaf, parent_fd, leaf) != 0) {
        saved_errno = errno;
        goto out;
    }
    temporary_created = false;
    if (m20_full_sync_fd(parent_fd) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (close(parent_fd) != 0) {
        saved_errno = errno;
        parent_fd = -1;
        goto out;
    }
    parent_fd = -1;
    g_text_publisher_open = false;
    if (m20_settle_private_text(path, text) != 0) {
        saved_errno = errno ? errno : ESTALE;
        goto out;
    }
    rc = 0;
out:
    if (temporary_created && parent_fd >= 0) {
        (void)unlinkat(parent_fd, temporary_leaf, 0);
    }
    if (parent_fd >= 0) {
        if (close(parent_fd) != 0 && saved_errno == 0) {
            saved_errno = errno;
        }
        parent_fd = -1;
    }
    g_text_publisher_open = false;
    if (rc != 0) errno = saved_errno ? saved_errno : EIO;
    return rc;
}

static int m20_mutate_config_during_reload(m20_reload_mutation_t mutation) {
    char path[MAX_PATH_LEN];
    char hardlink_path[MAX_PATH_LEN];
    struct stat before;
    struct stat after;
    struct timespec times[2];
    unsigned char byte;
    int fd;

    if (mutation == M20_RELOAD_MUTATION_NONE ||
        safe_snprintf(path, sizeof(path), "%s/gpg-agent.conf",
                      g_expected_home) != 0) {
        return -1;
    }
    if (mutation == M20_RELOAD_MUTATION_IDENTICAL_REPLACEMENT) {
        if (!g_expected_reload_config ||
            stat(path, &before) != 0 ||
            m20_replace_private_text_atomically(
                path, g_expected_reload_config) != 0 ||
            stat(path, &after) != 0 ||
            (before.st_dev == after.st_dev &&
             before.st_ino == after.st_ino) ||
            !S_ISREG(after.st_mode) || after.st_uid != getuid() ||
            after.st_nlink != 1 || (after.st_mode & 0777) != 0600) {
            return -1;
        }
        return 0;
    }
    if (mutation == M20_RELOAD_MUTATION_HARDLINK) {
        if (safe_snprintf(
                hardlink_path, sizeof(hardlink_path),
                "%s/.gitswitch-ar11-gpg-agent-hardlink",
                g_expected_home) != 0 ||
            stat(path, &before) != 0 ||
            link(path, hardlink_path) != 0 ||
            stat(path, &after) != 0 ||
            before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino ||
            after.st_nlink != 2) {
            return -1;
        }
        return 0;
    }
    if (mutation == M20_RELOAD_MUTATION_UNLINK) {
        return unlink(path);
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        pread(fd, &byte, 1, 0) != 1) {
        if (fd >= 0) close(fd);
        return -1;
    }
#ifdef __APPLE__
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (mutation == M20_RELOAD_MUTATION_MTIME) {
        if (times[1].tv_nsec == 999999999L) {
            times[1].tv_sec++;
            times[1].tv_nsec = 0;
        } else {
            times[1].tv_nsec++;
        }
        if (futimens(fd, times) != 0 || fsync(fd) != 0) {
            (void)close(fd);
            return -1;
        }
        if (close(fd) != 0) return -1;
        fd = -1;
        if (stat(path, &after) != 0 ||
            before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino ||
            before.st_size != after.st_size ||
            !S_ISREG(after.st_mode) ||
            (after.st_mode & 0777) != 0600 ||
            m20_same_ctime(&before, &after) ||
            m20_same_mtime(&before, &after)) {
            return -1;
        }
        return 0;
    }
    if (mutation == M20_RELOAD_MUTATION_PUBLIC_MODE) {
        if (fchmod(fd, 0644) != 0 || fsync(fd) != 0) {
            (void)close(fd);
            return -1;
        }
        if (close(fd) != 0) return -1;
        if (stat(path, &after) != 0 ||
            before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino ||
            (after.st_mode & 0777) != 0644) {
            return -1;
        }
        return 0;
    }
    if (mutation == M20_RELOAD_MUTATION_TRUNCATE) {
        if (ftruncate(fd, 0) != 0 || fsync(fd) != 0) {
            (void)close(fd);
            return -1;
        }
        if (close(fd) != 0) return -1;
        if (stat(path, &after) != 0 ||
            before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino || after.st_size != 0) {
            return -1;
        }
        return 0;
    }
    if (mutation == M20_RELOAD_MUTATION_DIFFERENT_BYTES) byte ^= 1U;
    if (pwrite(fd, &byte, 1, 0) != 1 ||
        fchmod(fd, 0400) != 0 || fchmod(fd, 0600) != 0 ||
        futimens(fd, times) != 0 || fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0) return -1;
    if (stat(path, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        !S_ISREG(after.st_mode) || (after.st_mode & 0777) != 0600 ||
        m20_same_ctime(&before, &after)) {
        return -1;
    }
    return 0;
}

static int m20_rewrite_config_preserving_metadata(
    const char *path, const char *text, const struct stat *restore) {
    struct stat opened;
    struct stat after;
    struct timespec times[2];
    size_t length;
    size_t offset = 0;
    int fd;

    if (!path || !text || !restore || restore->st_size < 0) {
        errno = EINVAL;
        return -1;
    }
    length = strlen(text);
    if ((uintmax_t)length != (uintmax_t)restore->st_size) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        opened.st_dev != restore->st_dev ||
        opened.st_ino != restore->st_ino ||
        !S_ISREG(opened.st_mode) || opened.st_nlink != 1 ||
        opened.st_size != restore->st_size) {
        int saved_errno = errno ? errno : ESTALE;

        if (fd >= 0) (void)close(fd);
        errno = saved_errno;
        return -1;
    }
#ifdef __APPLE__
    times[0] = restore->st_atimespec;
    times[1] = restore->st_mtimespec;
#else
    times[0] = restore->st_atim;
    times[1] = restore->st_mtim;
#endif
    while (offset < length) {
        ssize_t count = pwrite(fd, text + offset, length - offset,
                               (off_t)offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            int saved_errno = errno ? errno : EIO;

            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    if (fchmod(fd, 0400) != 0 ||
        fchmod(fd, restore->st_mode & 0777) != 0 ||
        futimens(fd, times) != 0 || fsync(fd) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0 ||
        stat(path, &after) != 0 ||
        !m20_ctime_only_file_change(restore, &after)) {
        if (errno == 0) errno = ESTALE;
        return -1;
    }
    return 0;
}

static int m20_reload_state_descriptor_is_closed(void) {
    char path[MAX_PATH_LEN];
    struct stat marker;
    DIR *directory;
    struct dirent *entry;
    int directory_fd;
    int result = 1;

    if (safe_snprintf(path, sizeof(path),
                      "%s/.gitswitch-gpg-agent-reload.state",
                      g_expected_home) != 0 ||
        fstatat(AT_FDCWD, path, &marker, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(marker.st_mode) || marker.st_uid != getuid() ||
        marker.st_nlink != 1) {
        return -1;
    }
    directory = opendir("/dev/fd");
    if (!directory) return -1;
    directory_fd = dirfd(directory);
    for (;;) {
        char *end = NULL;
        long descriptor;
        struct stat opened;

        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) result = -1;
            break;
        }
        descriptor = strtol(entry->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' ||
            descriptor < 0 || descriptor > INT_MAX ||
            descriptor == directory_fd) {
            continue;
        }
        if (fstat((int)descriptor, &opened) == 0 &&
            opened.st_dev == marker.st_dev &&
            opened.st_ino == marker.st_ino) {
            result = 0;
            break;
        }
    }
    if (closedir(directory) != 0) result = -1;
    return result;
}

static bool m20_reload_state_binds_identity(
    const m20_fixture_t *fixture, const struct stat *identity) {
    char actual[1024];
    char expected[1024];
    char config[512];
    intmax_t mtime_sec;
    long mtime_nsec;
    intmax_t ctime_sec;
    long ctime_nsec;
    size_t expected_len;
    int config_len;
    ssize_t read_count;
    int fd;
    int written;

    if (!fixture || !identity || identity->st_size < 0) return false;
#ifdef __APPLE__
    mtime_sec = (intmax_t)identity->st_mtimespec.tv_sec;
    mtime_nsec = identity->st_mtimespec.tv_nsec;
    ctime_sec = (intmax_t)identity->st_ctimespec.tv_sec;
    ctime_nsec = identity->st_ctimespec.tv_nsec;
#else
    mtime_sec = (intmax_t)identity->st_mtim.tv_sec;
    mtime_nsec = identity->st_mtim.tv_nsec;
    ctime_sec = (intmax_t)identity->st_ctim.tv_sec;
    ctime_nsec = identity->st_ctim.tv_nsec;
#endif
    config_len = read_file_to_string(
        fixture->installed_config, config, sizeof(config));
    if (config_len < 0 ||
        (uintmax_t)config_len != (uintmax_t)identity->st_size) {
        return false;
    }
    written = snprintf(
        expected, sizeof(expected),
        "C4;%ju:%ju:%ju:%ju:%ju:%ju:%ju:%jd:%ld:%jd:%ld;%d:",
        (uintmax_t)identity->st_dev, (uintmax_t)identity->st_ino,
        (uintmax_t)identity->st_mode, (uintmax_t)identity->st_uid,
        (uintmax_t)identity->st_gid, (uintmax_t)identity->st_nlink,
        (uintmax_t)identity->st_size,
        mtime_sec, mtime_nsec, ctime_sec, ctime_nsec, config_len);
    if (written < 0 ||
        (size_t)written + (size_t)config_len + 1U >
            sizeof(expected)) {
        return false;
    }
    memcpy(expected + written, config, (size_t)config_len);
    expected_len = (size_t)written + (size_t)config_len;
    expected[expected_len++] = ';';
    fd = open(fixture->reload_state,
              O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    do {
        read_count = pread(fd, actual, expected_len, 0);
    } while (read_count < 0 && errno == EINTR);
    if (close(fd) != 0) return false;
    return read_count == (ssize_t)expected_len &&
           memcmp(actual, expected, expected_len) == 0;
}

static int m20_replace_clean_state_with_legacy_format(
    const m20_fixture_t *fixture, const struct stat *identity,
    bool use_c2) {
    char config[512];
    char c4_header[512];
    char legacy_header[512];
    char *c4 = NULL;
    char *legacy = NULL;
    struct stat marker;
    intmax_t mtime_sec;
    long mtime_nsec;
    intmax_t ctime_sec;
    long ctime_nsec;
    size_t c4_prefix_len;
    size_t suffix_len;
    size_t legacy_len;
    int config_len;
    int c4_len;
    int c4_header_len;
    int legacy_header_len;
    int rc = -1;

    if (!fixture || !identity || identity->st_size < 0 ||
        stat(fixture->reload_state, &marker) != 0 ||
        marker.st_size <= 0 || marker.st_size > 96 * 1024) {
        return -1;
    }
#ifdef __APPLE__
    mtime_sec = (intmax_t)identity->st_mtimespec.tv_sec;
    mtime_nsec = identity->st_mtimespec.tv_nsec;
    ctime_sec = (intmax_t)identity->st_ctimespec.tv_sec;
    ctime_nsec = identity->st_ctimespec.tv_nsec;
#else
    mtime_sec = (intmax_t)identity->st_mtim.tv_sec;
    mtime_nsec = identity->st_mtim.tv_nsec;
    ctime_sec = (intmax_t)identity->st_ctim.tv_sec;
    ctime_nsec = identity->st_ctim.tv_nsec;
#endif
    config_len = read_file_to_string(
        fixture->installed_config, config, sizeof(config));
    if (config_len < 0 ||
        (uintmax_t)config_len != (uintmax_t)identity->st_size) {
        return -1;
    }
    c4_header_len = snprintf(
        c4_header, sizeof(c4_header),
        "C4;%ju:%ju:%ju:%ju:%ju:%ju:%ju:%jd:%ld:%jd:%ld;%d:",
        (uintmax_t)identity->st_dev, (uintmax_t)identity->st_ino,
        (uintmax_t)identity->st_mode, (uintmax_t)identity->st_uid,
        (uintmax_t)identity->st_gid, (uintmax_t)identity->st_nlink,
        (uintmax_t)identity->st_size,
        mtime_sec, mtime_nsec, ctime_sec, ctime_nsec, config_len);
    if (use_c2) {
        legacy_header_len = snprintf(
            legacy_header, sizeof(legacy_header),
            "C2;%ju:%ju:%ju:%ju:%ju:%ju:%ju:%jd:%ld:%jd:%ld;",
            (uintmax_t)identity->st_dev, (uintmax_t)identity->st_ino,
            (uintmax_t)identity->st_mode, (uintmax_t)identity->st_uid,
            (uintmax_t)identity->st_gid, (uintmax_t)identity->st_nlink,
            (uintmax_t)identity->st_size,
            mtime_sec, mtime_nsec, ctime_sec, ctime_nsec);
    } else {
        legacy_header_len = snprintf(
            legacy_header, sizeof(legacy_header),
            "C3;%ju:%ju:%ju:%ju:%ju:%ju:%ju:%jd:%ld;%d:",
            (uintmax_t)identity->st_dev, (uintmax_t)identity->st_ino,
            (uintmax_t)identity->st_mode, (uintmax_t)identity->st_uid,
            (uintmax_t)identity->st_gid, (uintmax_t)identity->st_nlink,
            (uintmax_t)identity->st_size,
            mtime_sec, mtime_nsec, config_len);
    }
    if (c4_header_len < 0 ||
        (size_t)c4_header_len >= sizeof(c4_header) ||
        legacy_header_len < 0 ||
        (size_t)legacy_header_len >= sizeof(legacy_header)) {
        return -1;
    }
    c4_prefix_len =
        (size_t)c4_header_len + (size_t)config_len + 1U;
    if ((uintmax_t)c4_prefix_len > (uintmax_t)marker.st_size) {
        return -1;
    }
    c4 = malloc((size_t)marker.st_size + 1U);
    if (!c4) goto out;
    c4_len = read_file_to_string(
        fixture->reload_state, c4,
        (size_t)marker.st_size + 1U);
    if (c4_len < 0 || (off_t)c4_len != marker.st_size ||
        memcmp(c4, c4_header, (size_t)c4_header_len) != 0 ||
        memcmp(c4 + c4_header_len, config,
               (size_t)config_len) != 0 ||
        c4[c4_prefix_len - 1U] != ';') {
        goto out;
    }
    suffix_len = (size_t)marker.st_size - c4_prefix_len;
    legacy_len = (size_t)legacy_header_len + suffix_len;
    if (!use_c2) {
        legacy_len += (size_t)config_len + 1U;
    }
    legacy = malloc(legacy_len + 1U);
    if (!legacy) goto out;
    memcpy(legacy, legacy_header, (size_t)legacy_header_len);
    if (use_c2) {
        memcpy(legacy + legacy_header_len,
               c4 + c4_prefix_len, suffix_len);
    } else {
        memcpy(legacy + legacy_header_len, config,
               (size_t)config_len);
        legacy[legacy_header_len + config_len] = ';';
        memcpy(legacy + legacy_header_len + config_len + 1U,
               c4 + c4_prefix_len, suffix_len);
    }
    legacy[legacy_len] = '\0';
    if (m20_publish_private_text(fixture->reload_state, legacy) != 0) {
        goto out;
    }
    rc = 0;
out:
    free(c4);
    free(legacy);
    return rc;
}

static int m20_replace_clean_state_with_legacy_c2(
    const m20_fixture_t *fixture, const struct stat *identity) {
    return m20_replace_clean_state_with_legacy_format(
        fixture, identity, true);
}

static int m20_replace_clean_state_with_legacy_c3(
    const m20_fixture_t *fixture, const struct stat *identity) {
    return m20_replace_clean_state_with_legacy_format(
        fixture, identity, false);
}

static int m20_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
        if (argv && argv[0]) {
            CHECK(run_launch_witness_capture(
                argv[0], &result->launch_witness));
        }
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") ||
         ts_command_is(argv[0], "gpg2") ||
         ts_command_is(argv[0], "gpgconf"))) {
        CHECK(m20_unsets_env(opts, "GPG_AGENT_INFO"));
        CHECK(m20_unsets_env(opts, "GNUPG_BUILDDIR"));
        CHECK(m20_unsets_env(opts, "GNUPG_BUILD_ROOT"));
    }

    if (argv && argv[0] && ts_command_is(argv[0], "gpgconf")) {
        if (argv[1] && strcmp(argv[1], "--list-components") == 0 &&
            !argv[2]) {
            int written;

            switch (g_component_metadata) {
                case M20_COMPONENT_METADATA_MISMATCHED_GPG:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:%s:\n", argv[0]);
                    break;
                case M20_COMPONENT_METADATA_DUPLICATE_GPG:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:%s:\n"
                                       "gpg:OpenPGP:%s:\n",
                                       g_expected_gpg, g_expected_gpg);
                    break;
                case M20_COMPONENT_METADATA_MISSING_GPG:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpgsm:S/MIME:%s:\n",
                                       g_expected_gpg);
                    break;
                case M20_COMPONENT_METADATA_MALFORMED_ESCAPE:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:%s%%Q0:\n",
                                       g_expected_gpg);
                    break;
                case M20_COMPONENT_METADATA_EXTRA_FIELD:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:%s:unexpected:\n",
                                       g_expected_gpg);
                    break;
                case M20_COMPONENT_METADATA_NONABSOLUTE_PATH:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:relative-gpg:\n");
                    break;
                case M20_COMPONENT_METADATA_VALID:
                default:
                    written = snprintf(opts->out, opts->out_size,
                                       "gpg:OpenPGP:%s:\n",
                                       g_expected_gpg);
                    break;
            }
            if (written < 0 || (size_t)written >= opts->out_size) {
                if (result) result->out_truncated = true;
                return -1;
            }
            if (result) result->out_len = (size_t)written;
            if (g_advance_gpgconf_epoch_after_components) {
                g_advance_gpgconf_epoch_after_components = false;
                CHECK_EQ_INT(run_test_set_launch_witness_epoch(
                                 argv[0], 2U), 0);
            }
            return 0;
        }
        if (m20_reload_shape_is_exact(argv)) {
            char installed[512];
            struct stat expected;
            struct stat pinned;
            const char *gnupg_home = m20_extra_env(opts, "GNUPGHOME=");

            g_reload_calls++;
            if (!opts || !opts->use_cwd_fd || opts->cwd_fd < 0 ||
                !gnupg_home || strcmp(gnupg_home, ".") != 0 ||
                stat(g_expected_home, &expected) != 0 ||
                fstat(opts->cwd_fd, &pinned) != 0 ||
                expected.st_dev != pinned.st_dev ||
                expected.st_ino != pinned.st_ino ||
                m20_read_config_at(opts->cwd_fd, installed,
                                   sizeof(installed)) != 0 ||
                !g_expected_reload_config ||
                strcmp(installed, g_expected_reload_config) != 0) {
                g_reload_protocol_errors++;
                if (result) result->exit_code = 8;
                return -1;
            }
            if (g_reload_mutation != M20_RELOAD_MUTATION_NONE) {
                m20_reload_mutation_t mutation = g_reload_mutation;
                g_reload_mutation = M20_RELOAD_MUTATION_NONE;
                if (m20_mutate_config_during_reload(mutation) != 0) {
                    g_reload_protocol_errors++;
                    if (result) result->exit_code = 8;
                    return -1;
                }
            }
            if (g_fail_reload) {
                static const char diagnostic[] =
                    "gpgconf: reload failed: agent refused configuration";

                g_reload_capture_is_merged =
                    opts && opts->merge_stderr &&
                    !opts->stderr_to_devnull && opts->out &&
                    opts->out_size > sizeof(diagnostic);
                if (opts && opts->out && opts->out_size > 0U) {
                    snprintf(opts->out, opts->out_size, "%s", diagnostic);
                }
                if (result) {
                    result->exit_code = 9;
                    result->out_len =
                        opts && opts->out ? strlen(opts->out) : 0U;
                }
                return -1;
            }
            if (g_advance_toolchain_epoch_after_reload) {
                g_advance_toolchain_epoch_after_reload = false;
                CHECK_EQ_INT(run_test_set_launch_witness_epoch(
                                 g_expected_gpg, 2U), 0);
                CHECK_EQ_INT(run_test_set_launch_witness_epoch(
                                 g_expected_gpgconf, 2U), 0);
            }
            return 0;
        }
        if (result) result->exit_code = 8;
        return -1;
    }

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") ||
         ts_command_is(argv[0], "gpg2")) &&
        m20_argv_has(argv, "--list-secret-keys")) {
        g_gpg_listing_calls++;
        if (opts && opts->out && opts->out_size > sizeof(M20_SECRET_LISTING)) {
            memcpy(opts->out, M20_SECRET_LISTING,
                   sizeof(M20_SECRET_LISTING));
            if (result) result->out_len = sizeof(M20_SECRET_LISTING) - 1U;
            return 0;
        }
        if (result) result->exit_code = 7;
        return -1;
    }

    return 0;
}

static int m20_observe_external_reload(const m20_fixture_t *fixture,
                                       const char *expected_config) {
    const char *const unset_env[] = {
        "GPG_AGENT_INFO", "GNUPG_BUILDDIR", "GNUPG_BUILD_ROOT", NULL
    };
    const char *const extra_env[] = { "GNUPGHOME=.", NULL };
    const char *argv[4];
    char output[256];
    run_opts_t opts;
    run_result_t result;
    int calls_before;
    int home_fd;
    int rc;

    if (!fixture || !expected_config) {
        errno = EINVAL;
        return -1;
    }
    home_fd = m20_open_private_directory(fixture->home);
    if (home_fd < 0) return -1;
    argv[0] = fixture->gpgconf;
    argv[1] = "--reload";
    argv[2] = "gpg-agent";
    argv[3] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    memset(output, 0, sizeof(output));
    result.exit_code = -1;
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    opts.unset_env = unset_env;
    opts.extra_env = extra_env;
    opts.cwd_fd = home_fd;
    opts.use_cwd_fd = true;
    g_expected_reload_config = expected_config;
    calls_before = g_reload_calls;
    rc = m20_runner(argv, &opts, &result);
    if (close(home_fd) != 0 && rc == 0) rc = -1;
    if (rc != 0 || !result.spawned || result.exit_code != 0 ||
        result.term_signal != 0 || result.out_truncated ||
        g_reload_calls != calls_before + 1 ||
        g_reload_protocol_errors != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int m20_real_recording_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    if (g_hosted_tools_active && argv && argv[0] && argv[1] &&
        !argv[2] && strcmp(argv[0], g_expected_gpgconf) == 0 &&
        strcmp(argv[1], "--list-components") == 0) {
        /* The relocated gpgconf retains its package-prefix metadata. The
         * deterministic cases already validate parsing and suite matching;
         * this live case substitutes only the relocated sibling spelling,
         * then executes the real copied gpgconf for the reload itself. */
        return m20_runner(argv, opts, result);
    }
    if (m20_reload_shape_is_exact(argv)) g_live_reload_calls++;
    return run_argv_real(argv, opts, result);
}

static int m20_query_agent_number(const char *home, const char *query,
                                  unsigned long long *value) {
    const char *env[] = {"GNUPGHOME=.", NULL};
    char executable[MAX_PATH_LEN];
    char output[512];
    const char *argv[4];
    run_opts_t opts;
    run_result_t result;
    char *line;
    char *end;
    int home_fd;
    int rc;

    if (!home || !query || !value ||
        find_command_path("gpg-connect-agent", executable,
                          sizeof(executable)) != 0) {
        return -1;
    }
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (home_fd < 0) return -1;
    argv[0] = executable;
    argv[1] = query;
    argv[2] = "/bye";
    argv[3] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    opts.extra_env = env;
    opts.cwd_fd = home_fd;
    opts.use_cwd_fd = true;
    rc = run_argv(argv, &opts, &result);
    if (close(home_fd) != 0 || rc != 0 || !result.spawned ||
        result.exit_code != 0 || result.term_signal != 0 ||
        result.out_truncated) {
        return -1;
    }
    line = strstr(output, "D ");
    if (!line) return -1;
    errno = 0;
    *value = strtoull(line + 2, &end, 10);
    if (errno != 0 || end == line + 2 ||
        (*end != '\n' && *end != '\r' && *end != '\0')) {
        return -1;
    }
    return 0;
}

static int m20_count_config_commit(int home_fd, const char *temp_name) {
    struct stat st;

    if (home_fd < 0 || !temp_name || !*temp_name ||
        fstatat(home_fd, temp_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode)) {
        return -1;
    }
    g_config_commits++;
    return 0;
}

static int m20_selective_sync(int fd, bool directory) {
    struct stat descriptor;
    struct stat named;
    bool is_home = false;
    bool is_reload_state = false;
    bool reload_state_closed = false;
    int call;
    int rc;

    if (fstat(fd, &descriptor) == 0 && g_expected_home[0] == '/') {
        if (stat(g_expected_home, &named) == 0) {
            is_home = descriptor.st_dev == named.st_dev &&
                      descriptor.st_ino == named.st_ino;
        }
        {
            char reload_state[MAX_PATH_LEN];

            if (safe_snprintf(reload_state, sizeof(reload_state),
                              "%s/.gitswitch-gpg-agent-reload.state",
                              g_expected_home) == 0 &&
                stat(reload_state, &named) == 0) {
                is_reload_state = descriptor.st_dev == named.st_dev &&
                                  descriptor.st_ino == named.st_ino;
            }
        }
    }
    if (is_home) {
        int closed = m20_reload_state_descriptor_is_closed();

        reload_state_closed = closed == 1;
        if (closed < 0) return -1;
        if (reload_state_closed) g_closed_home_sync_calls++;
    }
    if (directory) {
        call = ++g_sync_directory_calls;
        if (g_fail_closed_home_sync && is_home &&
            reload_state_closed &&
            g_closed_home_sync_calls == g_fail_closed_home_sync_at) {
            g_fail_closed_home_sync = false;
            errno = EIO;
            return -1;
        }
        if (g_fail_directory_sync_at > 0 &&
            call == g_fail_directory_sync_at) {
            errno = EIO;
            return -1;
        }
    } else {
        call = ++g_sync_file_calls;
        if (g_fail_clean_marker_sync && is_reload_state &&
            descriptor.st_size > 0) {
            g_fail_clean_marker_sync = false;
            errno = EIO;
            return -1;
        }
        if (g_fail_file_sync_at > 0 && call == g_fail_file_sync_at) {
            errno = EIO;
            return -1;
        }
    }
    rc = fsync(fd);
    if (rc == 0 && directory && is_home && reload_state_closed &&
        g_closed_home_sync_mutation != M20_RELOAD_MUTATION_NONE &&
        g_closed_home_sync_mutation_applications == 0) {
        char path[MAX_PATH_LEN];
        m20_reload_mutation_t mutation = g_closed_home_sync_mutation;

        g_closed_home_sync_observed = true;
        if (safe_snprintf(path, sizeof(path), "%s/gpg-agent.conf",
                          g_expected_home) != 0 ||
            stat(path, &g_closed_home_sync_mutation_before) != 0 ||
            m20_mutate_config_during_reload(mutation) != 0 ||
            stat(path, &g_closed_home_sync_mutation_after) != 0) {
            return -1;
        }
        g_closed_home_sync_mutation_identity_valid = true;
        g_closed_home_sync_mutation_applications++;
    }
    if (rc == 0 && !directory && g_sync_mutation_at > 0 &&
        call == g_sync_mutation_at) {
        m20_reload_mutation_t mutation = g_sync_mutation;

        g_sync_mutation_at = 0;
        g_sync_mutation = M20_RELOAD_MUTATION_NONE;
        return m20_mutate_config_during_reload(mutation);
    }
    return rc;
}

static int m20_terminal_preopen_mutation(int home_fd) {
    (void)home_fd;
    g_terminal_preopen_calls++;
    if (g_terminal_preopen_fail_without_errno) {
        errno = 0;
        return -1;
    }
    if (g_terminal_preopen_mutation == M20_RELOAD_MUTATION_NONE ||
        (g_terminal_preopen_mutation_limit >= 0 &&
         g_terminal_preopen_mutation_applications >=
             g_terminal_preopen_mutation_limit)) {
        return 0;
    }
    if (m20_mutate_config_during_reload(
            g_terminal_preopen_mutation) != 0) {
        return -1;
    }
    g_terminal_preopen_mutation_applications++;
    return 0;
}

static int m20_publication_mutation(
    int home_fd, gpg_agent_conf_publication_hook_stage_t stage) {
    (void)home_fd;
    if (stage != g_publication_mutation_stage) return 0;
    g_publication_hook_calls++;
    if (g_publication_hook_fail_without_errno) {
        errno = 0;
        return -1;
    }
    if (g_publication_mutation == M20_RELOAD_MUTATION_NONE ||
        (g_publication_mutation_limit >= 0 &&
         g_publication_mutation_applications >=
             g_publication_mutation_limit)) {
        return 0;
    }
    if (m20_mutate_config_during_reload(
            g_publication_mutation) != 0) {
        return -1;
    }
    g_publication_mutation_applications++;
    return 0;
}

static int m20_postclose_mutation(int home_fd) {
    bool selected;
    int rc;

    (void)home_fd;
    g_postclose_mutation_count++;
    if (g_postclose_fail_without_errno) {
        errno = 0;
        return -1;
    }
    if (g_postclose_mutation == M20_RELOAD_MUTATION_NONE) {
        return 0;
    }
    selected = g_postclose_mutation_at > 0
                   ? g_postclose_mutation_count ==
                         g_postclose_mutation_at
                   : g_postclose_mutation_limit < 0 ||
                         g_postclose_mutation_count <=
                             g_postclose_mutation_limit;
    if (!selected) {
        bool after_selected_range =
            (g_postclose_mutation_at > 0 &&
             g_postclose_mutation_count >
                 g_postclose_mutation_at) ||
            (g_postclose_mutation_at == 0 &&
             g_postclose_mutation_limit >= 0 &&
             g_postclose_mutation_count >
                 g_postclose_mutation_limit);

        if (after_selected_range &&
            g_postclose_first_stable_at == 0) {
            g_postclose_first_stable_at =
                g_postclose_mutation_count;
        }
        return 0;
    }
    if (g_postclose_require_closed_reload_state) {
        g_postclose_require_closed_reload_state = false;
        if (m20_reload_state_descriptor_is_closed() != 1) return -1;
        g_postclose_observed_closed_reload_state = true;
    }
    rc = m20_mutate_config_during_reload(g_postclose_mutation);
    if (rc != 0) return rc;
    g_postclose_mutation_applications++;
    if (g_postclose_replace_reload_state) {
        char replacement[MAX_PATH_LEN];
        char reload_state[MAX_PATH_LEN];

        g_postclose_replace_reload_state = false;
        if (safe_snprintf(replacement, sizeof(replacement),
                          "%s/.gitswitch-gpg-agent-reload.new",
                          g_expected_home) != 0 ||
            safe_snprintf(reload_state, sizeof(reload_state),
                          "%s/.gitswitch-gpg-agent-reload.state",
                          g_expected_home) != 0 ||
            write_string_to_file(replacement, "corrupt\n", 0600) != 0 ||
            rename(replacement, reload_state) != 0) {
            (void)unlink(replacement);
            return -1;
        }
    }
    return 0;
}

static int m20_postclose_ctime_then_changed_bytes(int home_fd) {
    m20_reload_mutation_t mutation;

    (void)home_fd;
    g_postclose_mutation_count++;
    if (g_postclose_mutation_count == 1) {
        mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    } else if (g_postclose_mutation_count == 2) {
        mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    } else {
        return 0;
    }
    if (m20_mutate_config_during_reload(mutation) != 0) {
        return -1;
    }
    g_postclose_mutation_applications++;
    return 0;
}

static void m20_reset_sync_faults(int fail_file_at, int fail_directory_at) {
    g_sync_file_calls = 0;
    g_sync_directory_calls = 0;
    g_fail_file_sync_at = fail_file_at;
    g_fail_directory_sync_at = fail_directory_at;
    g_fail_clean_marker_sync = false;
    g_fail_closed_home_sync = false;
    g_fail_closed_home_sync_at = 1;
    g_closed_home_sync_calls = 0;
    g_sync_mutation_at = 0;
    g_sync_mutation = M20_RELOAD_MUTATION_NONE;
    g_closed_home_sync_mutation = M20_RELOAD_MUTATION_NONE;
    g_closed_home_sync_mutation_applications = 0;
    g_closed_home_sync_observed = false;
    g_closed_home_sync_mutation_identity_valid = false;
    memset(&g_closed_home_sync_mutation_before, 0,
           sizeof(g_closed_home_sync_mutation_before));
    memset(&g_closed_home_sync_mutation_after, 0,
           sizeof(g_closed_home_sync_mutation_after));
    g_publication_hook_calls = 0;
    g_publication_mutation_applications = 0;
    g_publication_mutation_limit = 0;
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation = M20_RELOAD_MUTATION_NONE;
    g_publication_hook_fail_without_errno = false;
    g_terminal_preopen_calls = 0;
    g_terminal_preopen_mutation_applications = 0;
    g_terminal_preopen_mutation_limit = 0;
    g_terminal_preopen_mutation = M20_RELOAD_MUTATION_NONE;
    g_terminal_preopen_fail_without_errno = false;
    g_postclose_mutation_count = 0;
    g_postclose_mutation_applications = 0;
    g_postclose_first_stable_at = 0;
    g_postclose_mutation_limit = 0;
    g_postclose_mutation_at = 0;
    g_postclose_mutation = M20_RELOAD_MUTATION_NONE;
    g_postclose_replace_reload_state = false;
    g_postclose_require_closed_reload_state = false;
    g_postclose_observed_closed_reload_state = false;
    g_postclose_fail_without_errno = false;
}

static void m20_reset_observation(const m20_fixture_t *fixture,
                                  const char *expected_config,
                                  bool fail_reload) {
    g_expected_home[0] = '\0';
    g_expected_gpg[0] = '\0';
    g_expected_gpgconf[0] = '\0';
    if (fixture) {
        (void)safe_strncpy(g_expected_home, fixture->home,
                           sizeof(g_expected_home));
        (void)safe_strncpy(g_expected_gpg, fixture->gpg,
                           sizeof(g_expected_gpg));
        (void)safe_strncpy(g_expected_gpgconf, fixture->gpgconf,
                           sizeof(g_expected_gpgconf));
    }
    g_expected_reload_config = expected_config;
    g_reload_calls = 0;
    g_reload_protocol_errors = 0;
    g_gpg_listing_calls = 0;
    g_fail_reload = fail_reload;
    g_reload_capture_is_merged = false;
    g_component_metadata = M20_COMPONENT_METADATA_VALID;
    g_advance_gpgconf_epoch_after_components = false;
    g_advance_toolchain_epoch_after_reload = false;
    g_reload_mutation = M20_RELOAD_MUTATION_NONE;
    g_sync_mutation_at = 0;
    g_sync_mutation = M20_RELOAD_MUTATION_NONE;
}

/* Return 0 when one installed GnuPG suite is available and 1 otherwise. */
static int m20_prepare_live_tools(m20_fixture_t *fixture) {
    char connect[MAX_PATH_LEN];

    if (find_command_path("gpg", fixture->gpg,
                          sizeof(fixture->gpg)) == 0 &&
        find_command_path("gpgconf", fixture->gpgconf,
                          sizeof(fixture->gpgconf)) == 0 &&
        find_command_path("gpg-connect-agent", connect,
                          sizeof(connect)) == 0) {
        return 0;
    }
    return 1;
}

static int m20_install_stable_tools(m20_fixture_t *fixture) {
    if (!fixture ||
        find_command_path("gpg", fixture->gpg,
                          sizeof(fixture->gpg)) != 0 ||
        find_command_path("gpgconf", fixture->gpgconf,
                          sizeof(fixture->gpgconf)) != 0) {
        return -1;
    }
    return 0;
}

static int m20_set_tool_witness_epochs(
    const m20_fixture_t *fixture, unsigned int gpg_epoch,
    unsigned int gpgconf_epoch) {
    if (!fixture || fixture->gpg[0] != '/' ||
        fixture->gpgconf[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (run_test_set_launch_witness_epoch(
            fixture->gpg, gpg_epoch) != 0) {
        return -1;
    }
    if (run_test_set_launch_witness_epoch(
            fixture->gpgconf, gpgconf_epoch) != 0) {
        int saved_errno = errno;

        run_test_clear_launch_witness_epochs();
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m20_make_fixture(m20_fixture_t *fixture,
                            const char *initial_config,
                            m20_tool_fixture_t tools) {
    if (!fixture || !initial_config) return -1;
    memset(fixture, 0, sizeof(*fixture));
    if (safe_strncpy(fixture->root, "/tmp/gswar11reload_XXXXXX",
                     sizeof(fixture->root)) != 0 ||
        !ts_mkdtemp(fixture->root) ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        chmod(fixture->root, 0700) != 0 ||
        safe_snprintf(fixture->base, sizeof(fixture->base),
                      "%s/gitswitch-gpg", fixture->root) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home), "%s/reload",
                      fixture->base) != 0 ||
        safe_snprintf(fixture->current, sizeof(fixture->current),
                      "%s/current", fixture->base) != 0 ||
        safe_snprintf(fixture->source_home,
                      sizeof(fixture->source_home), "%s/source",
                      fixture->root) != 0 ||
        safe_snprintf(fixture->source_config,
                      sizeof(fixture->source_config), "%s/gpg-agent.conf",
                      fixture->source_home) != 0 ||
        safe_snprintf(fixture->installed_config,
                      sizeof(fixture->installed_config),
                      "%s/gpg-agent.conf", fixture->home) != 0 ||
        safe_snprintf(fixture->reload_state,
                      sizeof(fixture->reload_state),
                      "%s/.gitswitch-gpg-agent-reload.state",
                      fixture->home) != 0 ||
        mkdir(fixture->source_home, 0700) != 0 ||
        m20_publish_private_text(fixture->source_config,
                                 initial_config) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->root, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        setenv("GNUPGHOME", fixture->source_home, 1) != 0) {
        return -1;
    }
    if (tools == M20_TOOLS_STABLE_REQUIRED &&
        m20_install_stable_tools(fixture) != 0) {
        return -1;
    }
    if (tools != M20_TOOLS_STABLE_REQUIRED &&
        tools != M20_TOOLS_LIVE_OPTIONAL) {
        errno = EINVAL;
        return -1;
    }

    safe_strncpy(fixture->account.name, "reload",
                 sizeof(fixture->account.name));
    safe_strncpy(fixture->account.email, "reload@example.test",
                 sizeof(fixture->account.email));
    safe_strncpy(fixture->account.gpg_key_id, "FEEDFACE01234567",
                 sizeof(fixture->account.gpg_key_id));
    fixture->account.gpg_enabled = true;
    fixture->account.gpg_signing_enabled = true;
    return 0;
}

static void m20_prepare_config(gpg_config_t *config,
                               const m20_fixture_t *fixture) {
    memset(config, 0, sizeof(*config));
    config->mode = GPG_MODE_ISOLATED;
    /* Bind the stable installed executable generation while the fake runner
     * keeps deterministic cases independent of the host keyring and agent. */
    if (fixture && fixture->gpg[0] == '/') {
        safe_strncpy(config->executable_path, fixture->gpg,
                     sizeof(config->executable_path));
        CHECK(run_launch_witness_capture(
            config->executable_path, &config->executable_witness));
    } else {
        CHECK_EQ_INT(gpg_manager_init(config, GPG_MODE_ISOLATED), 0);
    }
}

static bool m20_identity_is_unpublished(const gpg_config_t *config,
                                        const m20_fixture_t *fixture) {
    struct stat st;

    if (!config || !fixture || config->current_key_id[0] != '\0' ||
        config->signing_enabled || config->environment_installed ||
        config->published_link_valid || config->runtime_restore_pending) {
        return false;
    }
    errno = 0;
    return lstat(fixture->current, &st) != 0 && errno == ENOENT;
}

TEST(changed_and_unchanged_config_reload_is_exactly_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat first;
    struct stat second;
    struct stat third;
    char installed[256];
    int reloads_after_first;
    int reloads_after_second;
    int first_rc;
    int second_rc;
    int third_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);

    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &first), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    reloads_after_first = g_reload_calls;

    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &second), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls - reloads_after_first, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(first.st_ino, second.st_ino);
    CHECK_EQ_INT(read_file_to_string(
                     fixture.installed_config, installed,
                     sizeof(installed)),
                 (int)(sizeof(m20_config_a) - 1U));
    CHECK_STR_EQ(installed, m20_config_a);
    reloads_after_second = g_reload_calls;

    CHECK_EQ_INT(m20_publish_private_text(fixture.source_config,
                                          m20_config_b), 0);
    g_expected_reload_config = m20_config_b;
    third_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(third_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &third), 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls - reloads_after_second, 1);
    CHECK_EQ_INT(g_reload_calls, 2);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK(first.st_dev != third.st_dev || first.st_ino != third.st_ino);

    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(reload_failure_prevents_activation_and_identity_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    char installed[256];
    struct stat reload_state;
    int switch_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, true);
    old_runner = run_set_runner(m20_runner);
    switch_rc = gpg_switch_account(&config, &fixture.account);
    failure = *get_last_error();
    run_set_runner(old_runner);

    CHECK_EQ_INT(switch_rc, -1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK(g_reload_capture_is_merged);
    CHECK(strstr(failure.message,
                 "gpgconf: reload failed: agent refused configuration") !=
          NULL);
    CHECK(strstr(failure.message, "spawned=yes") != NULL);
    CHECK(strstr(failure.message, "exit=9") != NULL);
    CHECK(strstr(failure.message, "signal=0") != NULL);
    CHECK(strstr(failure.message, "output-truncated=no") != NULL);
    CHECK(strstr(failure.message, "retry required") != NULL);
    CHECK_EQ_INT(stat(fixture.reload_state, &reload_state), 0);
    CHECK_EQ_INT(reload_state.st_size, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&config, &fixture));
    CHECK_STR_EQ(getenv("GNUPGHOME"), fixture.source_home);
    CHECK_EQ_INT(read_file_to_string(fixture.installed_config, installed,
                                     sizeof(installed)),
                 (int)(sizeof(m20_config_a) - 1U));
    CHECK_STR_EQ(installed, m20_config_a);

    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(config_write_failure_prevents_activation_and_identity_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat st;
    int switch_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(1, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    switch_rc = gpg_switch_account(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(switch_rc, -1);
    CHECK_EQ_INT(g_sync_file_calls, 1);
    CHECK_EQ_INT(g_sync_directory_calls, 0);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&config, &fixture));
    errno = 0;
    CHECK(lstat(fixture.installed_config, &st) != 0 && errno == ENOENT);
    CHECK_STR_EQ(getenv("GNUPGHOME"), fixture.source_home);

    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(post_rename_sync_failure_is_retried_without_rewriting_config) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&first, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 2);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_switch_account(&first, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(first_rc, -1);
    CHECK(!g_fail_clean_marker_sync);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_sync_directory_calls, 2);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&first, &fixture));
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);

    m20_prepare_config(&retry, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&first), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(clean_state_sync_failure_blocks_publication_and_retries_safely) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&first, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_fail_clean_marker_sync = true;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_switch_account(&first, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(first_rc, -1);
    CHECK(!g_fail_clean_marker_sync);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_sync_file_calls, 3);
    CHECK_EQ_INT(g_sync_directory_calls, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&first, &fixture));
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);

    m20_prepare_config(&retry, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK(g_sync_file_calls <= 2);
    CHECK(g_sync_directory_calls >= 2 &&
          g_sync_directory_calls <= 3);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&first), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(post_close_directory_sync_failure_after_reload_retries_cleanly) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    error_context_t retry_error;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&first, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_fail_closed_home_sync = true;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_switch_account(&first, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_sync_file_calls, 3);
    CHECK_EQ_INT(g_sync_directory_calls, 3);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&first, &fixture));
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);

    m20_prepare_config(&retry, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    if (retry_rc != 0) {
        fprintf(stderr, "post-close retry failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK(g_sync_file_calls <= 2);
    CHECK(g_sync_directory_calls >= 2 &&
          g_sync_directory_calls <= 3);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&first), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(post_close_directory_sync_failure_for_clean_state_retries_cleanly) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t retry_error;
    int initial_rc;
    int failed_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    initial_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(initial_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_fail_closed_home_sync = true;
    g_fail_closed_home_sync_at = 2;
    failed_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(failed_rc, -1);
    CHECK(!g_fail_closed_home_sync);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK(g_sync_file_calls <= 2);
    CHECK(g_sync_directory_calls >= 2 &&
          g_sync_directory_calls <= 3);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    if (retry_rc != 0) {
        fprintf(stderr,
                "clean-state post-close retry failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK(g_sync_file_calls <= 2);
    CHECK(g_sync_directory_calls >= 2 &&
          g_sync_directory_calls <= 3);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(closed_home_sync_same_inode_ctime_successor_is_reproved) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat mutation_before;
    struct stat mutation_after;
    struct stat final_config;
    bool mutation_identity_valid;
    bool observed_closed_reload_state;
    int mutation_applications;
    int first_directory_syncs;
    int first_reload_calls;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_closed_home_sync_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    mutation_applications = g_closed_home_sync_mutation_applications;
    mutation_identity_valid =
        g_closed_home_sync_mutation_identity_valid;
    mutation_before = g_closed_home_sync_mutation_before;
    mutation_after = g_closed_home_sync_mutation_after;
    observed_closed_reload_state =
        g_closed_home_sync_observed;
    first_directory_syncs = g_sync_directory_calls;
    first_reload_calls = g_reload_calls;

    CHECK_EQ_INT(stat(fixture.installed_config, &final_config), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &final_config));

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(mutation_applications, 1);
    CHECK(mutation_identity_valid);
    CHECK(observed_closed_reload_state);
    CHECK(m20_ctime_only_file_change(
        &mutation_before, &mutation_after));
    CHECK(first_directory_syncs >= 3);
    CHECK(m20_same_file_version(&mutation_after, &final_config) ||
          m20_ctime_only_file_change(&mutation_after, &final_config));
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(closed_home_sync_ctime_successor_rebinds_marker) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat final_config;
    int first_directory_syncs;
    int first_mutations;
    bool observed_closed_reload_state;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_closed_home_sync_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_directory_syncs = g_sync_directory_calls;
    first_mutations = g_closed_home_sync_mutation_applications;
    observed_closed_reload_state =
        g_closed_home_sync_observed;

    CHECK_EQ_INT(stat(fixture.installed_config, &final_config), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &final_config));

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK(first_directory_syncs >= 3);
    CHECK(observed_closed_reload_state);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK(g_sync_directory_calls >= 2 &&
          g_sync_directory_calls <= 3);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(same_inode_ctime_successor_between_invocations_reloads_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat after;
    char installed[256];
    int first_rc;
    int retry_rc;
    int clean_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK_EQ_INT(m20_mutate_config_during_reload(
                     M20_RELOAD_MUTATION_EXACT_CTIME), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK(m20_ctime_only_file_change(&before, &after));
    CHECK_EQ_INT(read_file_to_string(
                     fixture.installed_config, installed,
                     sizeof(installed)),
                 (int)(sizeof(m20_config_a) - 1U));
    CHECK_STR_EQ(installed, m20_config_a);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    clean_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(clean_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(transient_config_reload_restoration_forces_corrective_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat clean_a;
    struct stat loaded_b;
    struct stat restored_a;
    struct stat corrected_a;
    char installed[256];

    CHECK_EQ_INT(sizeof(m20_config_a), sizeof(m20_config_b));
    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &clean_a), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &clean_a));

    CHECK_EQ_INT(m20_rewrite_config_preserving_metadata(
                     fixture.installed_config, m20_config_b, &clean_a), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &loaded_b), 0);
    CHECK(m20_ctime_only_file_change(&clean_a, &loaded_b));
    CHECK_EQ_INT(read_file_to_string(
                     fixture.installed_config, installed,
                     sizeof(installed)),
                 (int)(sizeof(m20_config_b) - 1U));
    CHECK_STR_EQ(installed, m20_config_b);
    CHECK_EQ_INT(m20_observe_external_reload(
                     &fixture, m20_config_b), 0);
    CHECK_EQ_INT(g_reload_calls, 2);

    CHECK_EQ_INT(m20_rewrite_config_preserving_metadata(
                     fixture.installed_config, m20_config_a, &clean_a), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &restored_a), 0);
    CHECK(m20_ctime_only_file_change(&clean_a, &restored_a));
    CHECK_EQ_INT(read_file_to_string(
                     fixture.installed_config, installed,
                     sizeof(installed)),
                 (int)(sizeof(m20_config_a) - 1U));
    CHECK_STR_EQ(installed, m20_config_a);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &corrected_a), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &corrected_a));

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(cross_invocation_ctime_successors_each_reload_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);

    g_config_commits = 0;
    for (int successor = 0; successor < 32; successor++) {
        struct stat before;
        struct stat after;

        CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
        CHECK_EQ_INT(m20_mutate_config_during_reload(
                         M20_RELOAD_MUTATION_EXACT_CTIME), 0);
        CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
        CHECK(m20_ctime_only_file_change(&before, &after));
        m20_reset_observation(&fixture, m20_config_a, false);
        m20_reset_sync_faults(0, 0);
        CHECK_EQ_INT(gpg_create_isolated_home(
                         &config, &fixture.account), 0);
        CHECK_EQ_INT(g_reload_calls, 1);
        CHECK_EQ_INT(g_reload_protocol_errors, 0);
    }
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(persistent_mtime_change_invalidates_c4_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat changed;
    struct stat settled;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK_EQ_INT(m20_mutate_config_during_reload(
                     M20_RELOAD_MUTATION_MTIME), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &changed), 0);
    CHECK_EQ_INT(before.st_ino, changed.st_ino);
    CHECK(!m20_same_mtime(&before, &changed));

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &settled), 0);
    CHECK(m20_same_file_version(&changed, &settled) ||
          m20_ctime_only_file_change(&changed, &settled));
    CHECK(!m20_same_mtime(&before, &settled));
    CHECK(m20_reload_state_binds_identity(&fixture, &settled));

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(persistent_changed_bytes_with_restored_mtime_reload_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat changed;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK_EQ_INT(m20_mutate_config_during_reload(
                     M20_RELOAD_MUTATION_DIFFERENT_BYTES), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &changed), 0);
    CHECK_EQ_INT(before.st_ino, changed.st_ino);
    CHECK(m20_same_mtime(&before, &changed));
    CHECK(m20_ctime_only_file_change(&before, &changed));

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_config_commits, 1);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

static int m20_failed_attempt_in_child(const m20_fixture_t *fixture) {
    command_runner_fn old_runner;
    gpg_config_t config;
    int rc;

    m20_prepare_config(&config, fixture);
    g_config_commits = 0;
    m20_reset_observation(fixture, m20_config_a, true);
    old_runner = run_set_runner(m20_runner);
    rc = gpg_switch_account(&config, &fixture->account);
    run_set_runner(old_runner);

    if (rc != -1) return 21;
    if (g_reload_calls != 1 || g_reload_protocol_errors != 0) return 22;
    if (g_gpg_listing_calls != 0) return 23;
    if (!m20_identity_is_unpublished(&config, fixture)) return 24;
    if (g_config_commits != 1) return 25;
    return 0;
}

TEST(reload_failure_is_durably_retried_without_rewriting_config) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    char target[MAX_PATH_LEN];
    ssize_t target_len;
    pid_t child;
    int status = 0;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    g_config_commits = 0;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(m20_failed_attempt_in_child(&fixture));
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK(m20_identity_is_unpublished(&(gpg_config_t){0}, &fixture));

    m20_prepare_config(&retry, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);
    target_len = readlink(fixture.current, target, sizeof(target) - 1U);
    CHECK(target_len > 0 && (size_t)target_len < sizeof(target) - 1U);
    if (target_len > 0 && (size_t)target_len < sizeof(target) - 1U) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, fixture.home);
    }

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(missing_reload_state_for_matching_config_forces_one_migration_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat after;
    struct stat state;
    error_context_t first_error;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    CHECK_EQ_INT(mkdir(fixture.base, 0700), 0);
    CHECK_EQ_INT(mkdir(fixture.home, 0700), 0);
    CHECK_EQ_INT(m20_publish_private_text(fixture.installed_config,
                                          m20_config_a), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    errno = 0;
    CHECK(lstat(fixture.reload_state, &state) != 0 && errno == ENOENT);

    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_error = *get_last_error();
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    if (first_rc != 0) {
        fprintf(stderr, "first migration reload failed: %s\n",
                first_error.message);
    }
    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_EQ_INT(stat(fixture.reload_state, &state), 0);
    CHECK(S_ISREG(state.st_mode));
    CHECK(state.st_size > 0);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

static void m20_verify_legacy_clean_state_migration(bool use_c2) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat identity;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &identity), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &identity));
    CHECK_EQ_INT(
        use_c2
            ? m20_replace_clean_state_with_legacy_c2(
                  &fixture, &identity)
            : m20_replace_clean_state_with_legacy_c3(
                  &fixture, &identity),
        0);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &identity), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &identity));

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &config, &fixture.account), 0);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(valid_legacy_c2_state_migrates_once_then_c4_is_clean) {
    m20_verify_legacy_clean_state_migration(true);
}

TEST(valid_legacy_c3_state_migrates_once_then_c4_is_clean) {
    m20_verify_legacy_clean_state_migration(false);
}

TEST(corrupt_clean_state_for_matching_config_forces_one_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat after;
    int corrupt_rc;
    int clean_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(m20_publish_private_text(
                     fixture.reload_state, "not-a-clean-record\n"), 0);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    corrupt_rc = gpg_create_isolated_home(&config, &fixture.account);
    clean_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(corrupt_rc, 0);
    CHECK_EQ_INT(clean_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(stale_clean_state_after_identical_config_replacement_forces_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat original;
    struct stat replaced;
    struct stat after;
    int stale_rc;
    int clean_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &original), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(m20_replace_private_text_atomically(
                     fixture.installed_config, m20_config_a), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &replaced), 0);
    CHECK(original.st_dev != replaced.st_dev ||
          original.st_ino != replaced.st_ino);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    stale_rc = gpg_create_isolated_home(&config, &fixture.account);
    clean_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(stale_rc, 0);
    CHECK_EQ_INT(clean_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(replaced.st_ino, after.st_ino);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(exact_ctime_drift_during_reload_is_byte_proved_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t second_error;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    g_reload_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    m20_reset_observation(&fixture, m20_config_a, false);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    second_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    if (second_rc != 0) {
        fprintf(stderr, "unchanged retry after ctime drift failed: %s\n",
                second_error.message);
    }
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(unchanged_sync_ctime_successor_reloads_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat mutation_before;
    struct stat mutation_after;
    struct stat final_config;
    bool mutation_identity_valid;
    bool observed_closed_reload_state;
    int mutation_applications;
    int second_reload_calls;
    int second_rc;
    int third_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_closed_home_sync_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    mutation_applications =
        g_closed_home_sync_mutation_applications;
    mutation_identity_valid =
        g_closed_home_sync_mutation_identity_valid;
    mutation_before = g_closed_home_sync_mutation_before;
    mutation_after = g_closed_home_sync_mutation_after;
    observed_closed_reload_state =
        g_closed_home_sync_observed;
    second_reload_calls = g_reload_calls;
    CHECK_EQ_INT(stat(fixture.installed_config, &final_config), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &final_config));

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    third_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(mutation_applications, 1);
    CHECK(mutation_identity_valid);
    CHECK(observed_closed_reload_state);
    CHECK(m20_ctime_only_file_change(
        &mutation_before, &mutation_after));
    CHECK(m20_same_file_version(&mutation_after, &final_config) ||
          m20_ctime_only_file_change(
              &mutation_after, &final_config));
    CHECK_EQ_INT(second_reload_calls, 1);
    CHECK_EQ_INT(third_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(unchanged_sync_changed_bytes_fail_then_retry_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    error_context_t retry_error;
    int mutation_applications;
    int raced_reload_calls;
    int raced_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_closed_home_sync_mutation =
        M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    raced_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    mutation_applications =
        g_closed_home_sync_mutation_applications;
    raced_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(raced_rc, -1);
    CHECK_EQ_INT(mutation_applications, 1);
    CHECK_EQ_INT(raced_reload_calls, 0);
    CHECK(strstr(failure.message, "bytes or identity changed") != NULL);
    if (retry_rc != 0) {
        fprintf(stderr,
                "unchanged-sync byte-change retry failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(late_clean_state_ctime_is_rebound_without_second_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat clean_state;
    int first_reload_calls;
    int first_protocol_errors;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    /* Config temp, pending obligation, then completed-state persistence. */
    g_sync_mutation_at = 3;
    g_sync_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_reload_calls = g_reload_calls;
    first_protocol_errors = g_reload_protocol_errors;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(first_protocol_errors, 0);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.reload_state, &clean_state), 0);
    CHECK(clean_state.st_size > 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(closed_home_sync_changed_bytes_fail_then_retry) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    int first_reload_calls;
    int first_protocol_errors;
    int first_mutation_applications;
    int first_directory_syncs;
    bool observed_closed_reload_state;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_closed_home_sync_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_reload_calls = g_reload_calls;
    first_protocol_errors = g_reload_protocol_errors;
    first_mutation_applications =
        g_closed_home_sync_mutation_applications;
    first_directory_syncs = g_sync_directory_calls;
    observed_closed_reload_state =
        g_closed_home_sync_observed;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_mutation_applications, 1);
    CHECK_EQ_INT(first_directory_syncs, 3);
    CHECK(observed_closed_reload_state);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(first_protocol_errors, 0);
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

static void m20_check_publication_metadata_rejection(
    m20_reload_mutation_t mutation) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    bool first_identity_unpublished;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation_limit = 1;
    g_publication_mutation = mutation;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;
    first_identity_unpublished =
        m20_identity_is_unpublished(&config, &fixture);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 0);
    CHECK(first_identity_unpublished);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed after synchronization");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(publication_chmod_0644_fails_closed_then_reloads_once) {
    m20_check_publication_metadata_rejection(
        M20_RELOAD_MUTATION_PUBLIC_MODE);
}

TEST(publication_hardlink_fails_closed_then_reloads_once) {
    m20_check_publication_metadata_rejection(
        M20_RELOAD_MUTATION_HARDLINK);
}

TEST(publication_truncate_fails_closed_then_reloads_once) {
    m20_check_publication_metadata_rejection(
        M20_RELOAD_MUTATION_TRUNCATE);
}

TEST(publication_unlink_fails_closed_then_reloads_once) {
    m20_check_publication_metadata_rejection(
        M20_RELOAD_MUTATION_UNLINK);
}

TEST(postsync_ctime_successor_is_proved_before_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat final_config;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation_limit = 1;
    g_publication_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;
    CHECK_EQ_INT(stat(fixture.installed_config, &final_config), 0);
    CHECK(m20_reload_state_binds_identity(&fixture, &final_config));

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postsync_mtime_change_fails_then_reloads) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation_limit = 1;
    g_publication_mutation = M20_RELOAD_MUTATION_MTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 0);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed after synchronization");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postsync_changed_bytes_fail_then_retry_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    error_context_t retry_error;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation_limit = 1;
    g_publication_mutation =
        M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 0);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed after synchronization");
    if (retry_rc != 0) {
        fprintf(stderr,
                "post-sync byte-change retry failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postsync_identical_replacement_fails_then_reloads) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat replaced;
    struct stat final_config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_POSTSYNC_PREOBSERVE;
    g_publication_mutation_limit = 1;
    g_publication_mutation =
        M20_RELOAD_MUTATION_IDENTICAL_REPLACEMENT;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;
    CHECK_EQ_INT(stat(fixture.installed_config, &replaced), 0);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(stat(fixture.installed_config, &final_config), 0);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 0);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed after synchronization");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(replaced.st_dev, final_config.st_dev);
    CHECK_EQ_INT(replaced.st_ino, final_config.st_ino);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(publication_proof_continuous_ctime_drift_is_bounded) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    gpg_agent_conf_terminal_preopen_fn old_terminal;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int terminal_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_PROOF_PREOPEN;
    g_publication_mutation_limit = -1;
    g_publication_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_terminal =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_publication_hook_calls;
    first_mutations = g_publication_mutation_applications;
    first_reload_calls = g_reload_calls;
    terminal_calls = g_terminal_preopen_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_terminal);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 8);
    CHECK_EQ_INT(first_mutations, 8);
    CHECK_EQ_INT(first_reload_calls, 0);
    CHECK_EQ_INT(terminal_calls, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK(strstr(
              failure.message,
              "did not settle after publication") != NULL);
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

typedef enum {
    M20_ERRNO_ZERO_PUBLICATION = 0,
    M20_ERRNO_ZERO_TERMINAL_PREOPEN,
    M20_ERRNO_ZERO_POSTCLOSE
} m20_errno_zero_hook_t;

static void m20_check_errno_zero_hook_rejection(
    m20_errno_zero_hook_t hook) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_publication_hook_fn old_publication;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    bool first_identity_unpublished;
    int first_publication_calls;
    int first_terminal_calls;
    int first_postclose_calls;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_publication_mutation_stage =
        GPG_AGENT_CONF_PUBLICATION_PROOF_PREOPEN;
    g_publication_hook_fail_without_errno =
        hook == M20_ERRNO_ZERO_PUBLICATION;
    g_terminal_preopen_fail_without_errno =
        hook == M20_ERRNO_ZERO_TERMINAL_PREOPEN;
    g_postclose_fail_without_errno =
        hook == M20_ERRNO_ZERO_POSTCLOSE;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_publication =
        gpg_manager_set_agent_conf_publication_hook_fn(
            m20_publication_mutation);
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_publication_calls = g_publication_hook_calls;
    first_terminal_calls = g_terminal_preopen_calls;
    first_postclose_calls = g_postclose_mutation_count;
    first_reload_calls = g_reload_calls;
    first_identity_unpublished =
        m20_identity_is_unpublished(&config, &fixture);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);
    gpg_manager_set_agent_conf_publication_hook_fn(old_publication);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK(first_identity_unpublished);
    if (hook == M20_ERRNO_ZERO_PUBLICATION) {
        CHECK_EQ_INT(first_publication_calls, 1);
        CHECK_EQ_INT(first_terminal_calls, 0);
        CHECK_EQ_INT(first_postclose_calls, 0);
        CHECK_EQ_INT(first_reload_calls, 0);
        CHECK_EQ_INT(failure.system_errno, EIO);
        CHECK(strstr(
                  failure.message,
                  "publication proof hook failed") != NULL);
    } else if (hook == M20_ERRNO_ZERO_TERMINAL_PREOPEN) {
        CHECK_EQ_INT(first_terminal_calls, 1);
        CHECK_EQ_INT(first_postclose_calls, 0);
        CHECK_EQ_INT(first_reload_calls, 1);
        CHECK_STR_EQ(
            failure.message,
            "Installed gpg-agent.conf changed while its activation proof was closing");
    } else {
        CHECK_EQ_INT(first_terminal_calls, 1);
        CHECK_EQ_INT(first_postclose_calls, 1);
        CHECK_EQ_INT(first_reload_calls, 1);
        CHECK(strstr(
                  failure.message,
                  "post-close proof hook failed") != NULL);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(publication_hook_errno_zero_fails_closed_then_reloads_once) {
    m20_check_errno_zero_hook_rejection(
        M20_ERRNO_ZERO_PUBLICATION);
}

TEST(terminal_preopen_hook_errno_zero_fails_closed_then_reloads_once) {
    m20_check_errno_zero_hook_rejection(
        M20_ERRNO_ZERO_TERMINAL_PREOPEN);
}

TEST(postclose_hook_errno_zero_fails_closed_then_reloads_once) {
    m20_check_errno_zero_hook_rejection(
        M20_ERRNO_ZERO_POSTCLOSE);
}

static void m20_check_terminal_metadata_rejection(
    m20_reload_mutation_t mutation) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    bool first_identity_unpublished;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_terminal_preopen_mutation_limit = 1;
    g_terminal_preopen_mutation = mutation;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_terminal_preopen_calls;
    first_mutations = g_terminal_preopen_mutation_applications;
    first_reload_calls = g_reload_calls;
    first_identity_unpublished =
        m20_identity_is_unpublished(&config, &fixture);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK(first_identity_unpublished);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(terminal_preopen_chmod_0644_fails_closed_then_reloads_once) {
    m20_check_terminal_metadata_rejection(
        M20_RELOAD_MUTATION_PUBLIC_MODE);
}

TEST(terminal_preopen_hardlink_fails_closed_then_reloads_once) {
    m20_check_terminal_metadata_rejection(
        M20_RELOAD_MUTATION_HARDLINK);
}

TEST(terminal_preopen_truncate_fails_closed_then_reloads_once) {
    m20_check_terminal_metadata_rejection(
        M20_RELOAD_MUTATION_TRUNCATE);
}

TEST(terminal_preopen_unlink_fails_closed_then_reloads_once) {
    m20_check_terminal_metadata_rejection(
        M20_RELOAD_MUTATION_UNLINK);
}

TEST(terminal_preopen_ctime_transition_is_reproved) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    command_runner_fn old_runner;
    gpg_config_t config;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_terminal_preopen_mutation_limit = 1;
    g_terminal_preopen_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_calls = g_terminal_preopen_calls;
    first_mutations = g_terminal_preopen_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_calls, 3);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(terminal_preopen_changed_bytes_fail_closed) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_terminal_preopen_mutation_limit = 1;
    g_terminal_preopen_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_terminal_preopen_calls;
    first_mutations = g_terminal_preopen_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(terminal_preopen_identical_replacement_fails_closed) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_terminal_preopen_mutation_limit = 1;
    g_terminal_preopen_mutation =
        M20_RELOAD_MUTATION_IDENTICAL_REPLACEMENT;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_terminal_preopen_calls;
    first_mutations = g_terminal_preopen_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(terminal_preopen_continuous_ctime_drift_is_bounded) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_terminal_preopen_fn old_preopen;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_calls;
    int first_mutations;
    int first_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_terminal_preopen_mutation_limit = -1;
    g_terminal_preopen_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_preopen =
        gpg_manager_set_agent_conf_terminal_preopen_fn(
            m20_terminal_preopen_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_calls = g_terminal_preopen_calls;
    first_mutations = g_terminal_preopen_mutation_applications;
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_terminal_preopen_fn(old_preopen);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_calls, 8);
    CHECK_EQ_INT(first_mutations, 8);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK(strstr(
              failure.message,
              "did not settle after its activation proof closed") != NULL);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postclose_ctime_is_reproved_before_clean_state) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t second_error;
    int first_mutations;
    int first_stable_at;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_limit = 1;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_mutations = g_postclose_mutation_applications;
    first_stable_at = g_postclose_first_stable_at;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    second_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_stable_at, 2);
    if (second_rc != 0) {
        fprintf(stderr, "postclose ctime retry failed: %s\n",
                second_error.message);
    }
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(four_postclose_ctime_successors_settle_before_clean_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    int first_mutations;
    int first_stable_at;
    int first_reload_calls;
    int first_protocol_errors;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_limit = 4;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_mutations = g_postclose_mutation_applications;
    first_stable_at = g_postclose_first_stable_at;
    first_reload_calls = g_reload_calls;
    first_protocol_errors = g_reload_protocol_errors;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_mutations, 4);
    CHECK_EQ_INT(first_stable_at, 5);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(first_protocol_errors, 0);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postclose_changed_bytes_fail_before_clean_state) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    error_context_t retry_error;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_at = 1;
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_mutations = g_postclose_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    if (retry_rc != 0) {
        fprintf(stderr,
                "post-close byte-change retry failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(final_descriptor_close_changed_bytes_fail_before_clean_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    struct stat state;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_ctime_then_changed_bytes);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_mutations = g_postclose_mutation_applications;
    first_reload_calls = g_reload_calls;
    CHECK_EQ_INT(stat(fixture.reload_state, &state), 0);

    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_mutations, 2);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_EQ_INT(state.st_size, 0);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(clean_state_final_reproof_absorbs_ctime_successor) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    bool observed_closed_reload_state;
    int first_mutations;
    int first_stable_at;
    int first_reload_calls;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_at = 2;
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    g_postclose_require_closed_reload_state = true;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    first_mutations = g_postclose_mutation_applications;
    first_stable_at = g_postclose_first_stable_at;
    first_reload_calls = g_reload_calls;
    observed_closed_reload_state =
        g_postclose_observed_closed_reload_state;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_stable_at, 3);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK(observed_closed_reload_state);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(clean_state_final_reproof_rejects_changed_bytes) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_at = 2;
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_mutations = g_postclose_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK_STR_EQ(
        failure.message,
        "Installed gpg-agent.conf changed while its activation proof was closing");
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(closed_clean_state_replacement_fails_closed_then_reloads) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_mutations;
    int first_reload_calls;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_at = 2;
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    g_postclose_replace_reload_state = true;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    first_mutations = g_postclose_mutation_applications;
    first_reload_calls = g_reload_calls;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(first_mutations, 1);
    CHECK_EQ_INT(first_reload_calls, 1);
    CHECK(strstr(
              failure.message,
              "reload state changed while settling completed activation") !=
          NULL);
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(unchanged_clean_state_settles_after_marker_close) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    bool observed_closed_reload_state;
    int first_rc;
    int second_rc;
    int third_rc;
    int second_mutations;
    int second_reload_calls;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_at = 1;
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    g_postclose_require_closed_reload_state = true;
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    second_mutations = g_postclose_mutation_applications;
    second_reload_calls = g_reload_calls;
    observed_closed_reload_state =
        g_postclose_observed_closed_reload_state;

    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    third_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(second_mutations, 1);
    CHECK_EQ_INT(second_reload_calls, 0);
    CHECK(observed_closed_reload_state);
    CHECK_EQ_INT(third_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(postclose_continuous_ctime_drift_is_bounded) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_postclose_fn old_postclose;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t failure;
    int first_rc;
    int mutation_applications;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    g_postclose_mutation_limit = -1;
    g_postclose_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_postclose = gpg_manager_set_agent_conf_postclose_fn(
        m20_postclose_mutation);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    failure = *get_last_error();
    mutation_applications = g_postclose_mutation_applications;
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_postclose_fn(old_postclose);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(mutation_applications, 8);
    CHECK(strstr(
              failure.message,
              "did not settle after its activation proof closed") != NULL);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(changed_bytes_with_restored_mtime_fail_then_retry) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    error_context_t retry_error;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    g_reload_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK(strstr(get_last_error()->message,
                 "changed during GPG agent activation") != NULL);

    m20_reset_observation(&fixture, m20_config_a, false);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    retry_error = *get_last_error();
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    if (retry_rc != 0) {
        fprintf(stderr,
                "retry after changed bytes failed: %s\n",
                retry_error.message);
    }
    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

static void m20_expect_component_metadata_failure(
    m20_component_metadata_t metadata) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat st;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, M20_TOOLS_STABLE_REQUIRED), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    g_component_metadata = metadata;
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), -1);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    errno = 0;
    CHECK(lstat(fixture.current, &st) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.installed_config, &st) != 0 && errno == ENOENT);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(unrelated_gpgconf_suite_is_rejected_before_publication) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_MISMATCHED_GPG);
}

TEST(duplicate_gpg_component_metadata_is_rejected_before_reload) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_DUPLICATE_GPG);
}

TEST(missing_gpg_component_metadata_is_rejected_before_reload) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_MISSING_GPG);
}

TEST(malformed_percent_escape_in_component_metadata_is_rejected_before_reload) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_MALFORMED_ESCAPE);
}

TEST(extra_component_metadata_field_is_rejected_before_reload) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_EXTRA_FIELD);
}

TEST(nonabsolute_gpg_component_path_is_rejected_before_reload) {
    m20_expect_component_metadata_failure(
        M20_COMPONENT_METADATA_NONABSOLUTE_PATH);
}

TEST(launch_witness_epoch_preserves_real_identity) {
    char gpg[MAX_PATH_LEN];
    run_launch_witness_t real;
    run_launch_witness_t epoch_one;
    run_launch_witness_t epoch_two;

    run_test_clear_launch_witness_epochs();
    CHECK_EQ_INT(find_command_path("gpg", gpg, sizeof(gpg)), 0);
    CHECK(run_launch_witness_capture(gpg, &real));
    CHECK_EQ_INT(run_test_set_launch_witness_epoch(gpg, 1U), 0);
    CHECK(run_launch_witness_capture(gpg, &epoch_one));
    CHECK_EQ_INT(run_test_set_launch_witness_epoch(gpg, 2U), 0);
    CHECK(run_launch_witness_capture(gpg, &epoch_two));

    CHECK(m20_ctime_only_file_change(
        &real.executable_identity, &epoch_one.executable_identity));
    CHECK(m20_ctime_only_file_change(
        &real.executable_identity, &epoch_two.executable_identity));
#ifdef __APPLE__
    CHECK_EQ_INT(real.executable_identity.st_ctimespec.tv_sec,
                 epoch_one.executable_identity.st_ctimespec.tv_sec);
    CHECK_EQ_INT(
        epoch_one.executable_identity.st_ctimespec.tv_nsec,
        (real.executable_identity.st_ctimespec.tv_nsec + 1L) %
            1000000000L);
    CHECK_EQ_INT(
        epoch_two.executable_identity.st_ctimespec.tv_nsec,
        (real.executable_identity.st_ctimespec.tv_nsec + 2L) %
            1000000000L);
#else
    CHECK_EQ_INT(real.executable_identity.st_ctim.tv_sec,
                 epoch_one.executable_identity.st_ctim.tv_sec);
    CHECK_EQ_INT(
        epoch_one.executable_identity.st_ctim.tv_nsec,
        (real.executable_identity.st_ctim.tv_nsec + 1L) %
            1000000000L);
    CHECK_EQ_INT(
        epoch_two.executable_identity.st_ctim.tv_nsec,
        (real.executable_identity.st_ctim.tv_nsec + 2L) %
            1000000000L);
#endif
    CHECK(!run_launch_witness_matches(&real, &epoch_one));
    CHECK(!run_launch_witness_matches(&epoch_one, &epoch_two));
    run_test_clear_launch_witness_epochs();
}

TEST(gpgconf_epoch_change_after_components_is_rejected_before_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat st;

    run_test_clear_launch_witness_epochs();
    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    CHECK_EQ_INT(m20_set_tool_witness_epochs(&fixture, 1U, 1U), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    g_advance_gpgconf_epoch_after_components = true;
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), -1);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(stat(fixture.reload_state, &st), 0);
    CHECK_EQ_INT(st.st_size, 0);
    errno = 0;
    CHECK(lstat(fixture.current, &st) != 0 && errno == ENOENT);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    run_test_clear_launch_witness_epochs();
}

TEST(clean_state_is_invalidated_by_gpgconf_generation_change) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    run_test_clear_launch_witness_epochs();
    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    CHECK_EQ_INT(m20_set_tool_witness_epochs(&fixture, 1U, 1U), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(run_test_set_launch_witness_epoch(
                     fixture.gpgconf, 2U), 0);
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    run_test_clear_launch_witness_epochs();
}

TEST(clean_state_is_invalidated_by_transaction_gpg_generation_change) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t next_transaction;
    run_test_clear_launch_witness_epochs();
    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    CHECK_EQ_INT(m20_set_tool_witness_epochs(&fixture, 1U, 1U), 0);
    m20_prepare_config(&first, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&first, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(run_test_set_launch_witness_epoch(
                     fixture.gpg, 2U), 0);
    m20_prepare_config(&next_transaction, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &next_transaction, &fixture.account), 0);
    CHECK_EQ_INT(gpg_create_isolated_home(
                     &next_transaction, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    run_test_clear_launch_witness_epochs();
}

TEST(toolchain_epoch_change_after_reload_is_rejected_before_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat state;
    int switch_rc;

    run_test_clear_launch_witness_epochs();
    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_config_a,
                     M20_TOOLS_STABLE_REQUIRED), 0);
    CHECK_EQ_INT(m20_set_tool_witness_epochs(&fixture, 1U, 1U), 0);
    m20_prepare_config(&config, &fixture);
    m20_reset_observation(&fixture, m20_config_a, false);
    g_advance_toolchain_epoch_after_reload = true;
    old_runner = run_set_runner(m20_runner);
    switch_rc = gpg_switch_account(&config, &fixture.account);
    run_set_runner(old_runner);

    CHECK_EQ_INT(switch_rc, -1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&config, &fixture));
    CHECK_EQ_INT(stat(fixture.reload_state, &state), 0);
    CHECK_EQ_INT(state.st_size, 0);

    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    run_test_clear_launch_witness_epochs();
}

TEST(changed_config_is_observed_by_the_retained_live_agent) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    unsigned long long pid_before = 0;
    unsigned long long pid_after = 0;
    unsigned long long count_before = 0;
    unsigned long long count_after = 0;
    int query_rc;
    int tools_rc;

    CHECK_EQ_INT(m20_make_fixture(
                     &fixture, m20_live_config_a,
                     M20_TOOLS_LIVE_OPTIONAL), 0);
    tools_rc = m20_prepare_live_tools(&fixture);
    if (tools_rc > 0) {
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        TS_SKIP("gpg", "trusted GnuPG suite unavailable");
    }
    if (tools_rc < 0) {
        CHECK_EQ_INT(tools_rc, 0);
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        return;
    }
    m20_prepare_config(&config, &fixture);

    g_live_reload_calls = 0;
    m20_reset_observation(&fixture, m20_live_config_a, false);
    old_runner = run_set_runner(m20_real_recording_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_live_reload_calls, 1);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO pid",
                                        &pid_before), 0);
    query_rc = m20_query_agent_number(fixture.home, "GETINFO s2k_count",
                                      &count_before);
    if (query_rc != 0) {
        CHECK_EQ_INT(gpg_manager_reset("reload"), 0);
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        TS_SKIP("gpg", "agent does not expose GETINFO s2k_count");
    }

    CHECK_EQ_INT(m20_publish_private_text(fixture.source_config,
                                          m20_live_config_b), 0);
    g_live_reload_calls = 0;
    m20_reset_observation(&fixture, m20_live_config_b, false);
    old_runner = run_set_runner(m20_real_recording_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_live_reload_calls, 1);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO pid",
                                        &pid_after), 0);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO s2k_count",
                                        &count_after), 0);
    CHECK_EQ_INT(pid_before, pid_after);
    CHECK(count_before != count_after);

    CHECK_EQ_INT(gpg_manager_reset("reload"), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
}

static void m20_reset_text_settle_seam(int mutation_limit) {
    g_text_settle_mutation_limit = mutation_limit;
    g_text_settle_attempts = 0;
    g_text_settle_file_syncs = 0;
    g_text_settle_parent_barriers = 0;
    g_text_settle_mutation_applications = 0;
    g_text_settle_observed_closed = false;
    g_text_publisher_open = false;
    g_text_postclose_mutation_limit = 0;
    g_text_postclose_mutation_applications = 0;
    g_text_postclose_observed_closed = false;
}

TEST(private_text_publication_settles_four_closed_successors) {
    char directory[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    struct stat first;
    struct stat second;

    CHECK(ts_mkdtemp_trusted(directory, sizeof(directory),
                            "gitswitch-ar11-private-text"));
    CHECK_EQ_INT(chmod(directory, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(path, sizeof(path), "%s/config",
                               directory), 0);
    m20_reset_text_settle_seam(4);
    CHECK_EQ_INT(m20_publish_private_text(path, m20_config_a), 0);
    CHECK(g_text_settle_observed_closed);
    CHECK(!g_text_publisher_open);
    CHECK_EQ_INT(g_text_settle_mutation_applications, 4);
    CHECK(g_text_settle_attempts >= 6);
    CHECK(g_text_settle_attempts <= 8);
    CHECK_EQ_INT(g_text_settle_file_syncs,
                 g_text_settle_attempts);
    CHECK_EQ_INT(g_text_settle_parent_barriers,
                 g_text_settle_attempts);
    CHECK_EQ_INT(m20_capture_private_text(path, m20_config_a, &first), 0);
    CHECK_EQ_INT(m20_capture_private_text(path, m20_config_a, &second), 0);
    CHECK(m20_same_file_version(&first, &second));

    m20_reset_text_settle_seam(0);
    ts_rm_rf(directory);
}

TEST(private_text_publication_binds_postclose_successor) {
    char directory[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    struct stat first;
    struct stat second;

    CHECK(ts_mkdtemp_trusted(directory, sizeof(directory),
                            "gitswitch-ar11-private-text"));
    CHECK_EQ_INT(chmod(directory, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(path, sizeof(path), "%s/config",
                               directory), 0);
    m20_reset_text_settle_seam(0);
    g_text_postclose_mutation_limit = 1;
    CHECK_EQ_INT(m20_publish_private_text(path, m20_config_a), 0);
    CHECK(g_text_postclose_observed_closed);
    CHECK_EQ_INT(g_text_postclose_mutation_applications, 1);
    CHECK(g_text_settle_attempts >= 3);
    CHECK(g_text_settle_attempts <= 8);
    CHECK_EQ_INT(g_text_settle_file_syncs,
                 g_text_settle_attempts);
    CHECK_EQ_INT(g_text_settle_parent_barriers,
                 g_text_settle_attempts);
    CHECK(g_text_postclose_mutation_applications <
          g_text_settle_parent_barriers);
    CHECK_EQ_INT(m20_capture_private_text(path, m20_config_a, &first), 0);
    CHECK_EQ_INT(m20_capture_private_text(path, m20_config_a, &second), 0);
    CHECK(m20_same_file_version(&first, &second));

    m20_reset_text_settle_seam(0);
    ts_rm_rf(directory);
}

TEST(private_text_publication_continuous_drift_is_bounded) {
    char directory[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    struct stat identity;
    int failure_errno;
    int rc;

    CHECK(ts_mkdtemp_trusted(directory, sizeof(directory),
                            "gitswitch-ar11-private-text"));
    CHECK_EQ_INT(chmod(directory, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(path, sizeof(path), "%s/config",
                               directory), 0);
    m20_reset_text_settle_seam(-1);
    errno = 0;
    rc = m20_publish_private_text(path, m20_config_a);
    failure_errno = errno;
    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(failure_errno, ESTALE);
    CHECK(g_text_settle_observed_closed);
    CHECK(!g_text_publisher_open);
    CHECK_EQ_INT(g_text_settle_mutation_applications, 8);
    CHECK_EQ_INT(g_text_settle_attempts, 8);
    CHECK_EQ_INT(g_text_settle_file_syncs, 8);
    CHECK_EQ_INT(g_text_settle_parent_barriers, 8);

    m20_reset_text_settle_seam(0);
    CHECK_EQ_INT(m20_capture_private_text(
                     path, m20_config_a, &identity), 0);
    CHECK(S_ISREG(identity.st_mode));
    CHECK_EQ_INT(identity.st_mode & 0777, 0600);
    ts_rm_rf(directory);
}

TEST(private_text_publication_accepts_clean_state_sized_records) {
    char directory[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    char text[1025];
    struct stat identity;

    memset(text, 'x', sizeof(text) - 1U);
    text[sizeof(text) - 1U] = '\0';
    CHECK(ts_mkdtemp_trusted(directory, sizeof(directory),
                            "gitswitch-ar11-private-text"));
    CHECK_EQ_INT(chmod(directory, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(path, sizeof(path), "%s/config",
                               directory), 0);
    m20_reset_text_settle_seam(0);
    CHECK_EQ_INT(m20_publish_private_text(path, text), 0);
    CHECK_EQ_INT(m20_capture_private_text(path, text, &identity), 0);
    CHECK_EQ_INT(identity.st_size, (off_t)(sizeof(text) - 1U));
    ts_rm_rf(directory);
}

int main(int argc, char **argv) {
    int tools_rc;
    int result;

    (void)argv;
    (void)unsetenv("GNUPGHOME");
    if (argc != 1) {
        fprintf(stderr,
                "test_ar11_gpg_reload: unexpected arguments\n");
        return 2;
    }
    error_init(LOG_LEVEL_ERROR, NULL);
    tools_rc = m20_prepare_hosted_tools();
    if (tools_rc != 0) {
        fprintf(stderr,
                "test_ar11_gpg_reload: cannot prepare trusted GnuPG suite\n");
        return 2;
    }
    RUN_TEST(private_text_publication_settles_four_closed_successors);
    RUN_TEST(private_text_publication_binds_postclose_successor);
    RUN_TEST(private_text_publication_continuous_drift_is_bounded);
    RUN_TEST(private_text_publication_accepts_clean_state_sized_records);
    RUN_TEST(changed_and_unchanged_config_reload_is_exactly_once);
    RUN_TEST(reload_failure_prevents_activation_and_identity_publication);
    RUN_TEST(config_write_failure_prevents_activation_and_identity_publication);
    RUN_TEST(post_rename_sync_failure_is_retried_without_rewriting_config);
    RUN_TEST(clean_state_sync_failure_blocks_publication_and_retries_safely);
    RUN_TEST(post_close_directory_sync_failure_after_reload_retries_cleanly);
    RUN_TEST(post_close_directory_sync_failure_for_clean_state_retries_cleanly);
    RUN_TEST(closed_home_sync_same_inode_ctime_successor_is_reproved);
    RUN_TEST(closed_home_sync_ctime_successor_rebinds_marker);
    RUN_TEST(same_inode_ctime_successor_between_invocations_reloads_once);
    RUN_TEST(transient_config_reload_restoration_forces_corrective_reload);
    RUN_TEST(cross_invocation_ctime_successors_each_reload_once);
    RUN_TEST(persistent_mtime_change_invalidates_c4_once);
    RUN_TEST(persistent_changed_bytes_with_restored_mtime_reload_once);
    RUN_TEST(reload_failure_is_durably_retried_without_rewriting_config);
    RUN_TEST(missing_reload_state_for_matching_config_forces_one_migration_reload);
    RUN_TEST(valid_legacy_c2_state_migrates_once_then_c4_is_clean);
    RUN_TEST(valid_legacy_c3_state_migrates_once_then_c4_is_clean);
    RUN_TEST(corrupt_clean_state_for_matching_config_forces_one_reload);
    RUN_TEST(stale_clean_state_after_identical_config_replacement_forces_reload);
    RUN_TEST(exact_ctime_drift_during_reload_is_byte_proved_once);
    RUN_TEST(unchanged_sync_ctime_successor_reloads_once);
    RUN_TEST(unchanged_sync_changed_bytes_fail_then_retry_reload);
    RUN_TEST(late_clean_state_ctime_is_rebound_without_second_reload);
    RUN_TEST(closed_home_sync_changed_bytes_fail_then_retry);
    RUN_TEST(publication_chmod_0644_fails_closed_then_reloads_once);
    RUN_TEST(publication_hardlink_fails_closed_then_reloads_once);
    RUN_TEST(publication_truncate_fails_closed_then_reloads_once);
    RUN_TEST(publication_unlink_fails_closed_then_reloads_once);
    RUN_TEST(postsync_ctime_successor_is_proved_before_reload);
    RUN_TEST(postsync_mtime_change_fails_then_reloads);
    RUN_TEST(postsync_changed_bytes_fail_then_retry_reload);
    RUN_TEST(postsync_identical_replacement_fails_then_reloads);
    RUN_TEST(publication_proof_continuous_ctime_drift_is_bounded);
    RUN_TEST(publication_hook_errno_zero_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_hook_errno_zero_fails_closed_then_reloads_once);
    RUN_TEST(postclose_hook_errno_zero_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_chmod_0644_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_hardlink_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_truncate_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_unlink_fails_closed_then_reloads_once);
    RUN_TEST(terminal_preopen_ctime_transition_is_reproved);
    RUN_TEST(terminal_preopen_changed_bytes_fail_closed);
    RUN_TEST(terminal_preopen_identical_replacement_fails_closed);
    RUN_TEST(terminal_preopen_continuous_ctime_drift_is_bounded);
    RUN_TEST(postclose_ctime_is_reproved_before_clean_state);
    RUN_TEST(four_postclose_ctime_successors_settle_before_clean_publication);
    RUN_TEST(postclose_changed_bytes_fail_before_clean_state);
    RUN_TEST(final_descriptor_close_changed_bytes_fail_before_clean_publication);
    RUN_TEST(clean_state_final_reproof_absorbs_ctime_successor);
    RUN_TEST(clean_state_final_reproof_rejects_changed_bytes);
    RUN_TEST(closed_clean_state_replacement_fails_closed_then_reloads);
    RUN_TEST(unchanged_clean_state_settles_after_marker_close);
    RUN_TEST(postclose_continuous_ctime_drift_is_bounded);
    RUN_TEST(changed_bytes_with_restored_mtime_fail_then_retry);
    RUN_TEST(unrelated_gpgconf_suite_is_rejected_before_publication);
    RUN_TEST(duplicate_gpg_component_metadata_is_rejected_before_reload);
    RUN_TEST(missing_gpg_component_metadata_is_rejected_before_reload);
    RUN_TEST(malformed_percent_escape_in_component_metadata_is_rejected_before_reload);
    RUN_TEST(extra_component_metadata_field_is_rejected_before_reload);
    RUN_TEST(nonabsolute_gpg_component_path_is_rejected_before_reload);
    RUN_TEST(launch_witness_epoch_preserves_real_identity);
    RUN_TEST(gpgconf_epoch_change_after_components_is_rejected_before_reload);
    RUN_TEST(clean_state_is_invalidated_by_gpgconf_generation_change);
    RUN_TEST(clean_state_is_invalidated_by_transaction_gpg_generation_change);
    RUN_TEST(toolchain_epoch_change_after_reload_is_rejected_before_publication);
    RUN_TEST(changed_config_is_observed_by_the_retained_live_agent);
    result = ts_test_finish();
    if (m20_restore_hosted_tools() != 0) {
        fprintf(stderr,
                "test_ar11_gpg_reload: cannot restore hosted GnuPG fixture\n");
        return 2;
    }
    return result;
}
