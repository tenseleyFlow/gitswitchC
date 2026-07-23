/* Utility functions and helpers with security focus
 * Provides secure, validated utility functions for gitswitch-c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <regex.h>
#include <limits.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/acl.h>
#endif

#if defined(__linux__)
#include <sys/mman.h>
#include <linux/random.h>
#include <sys/syscall.h>
#endif

#include "utils.h"
#include "error.h"
#include "signals.h"

/* POSIX exposes the process environment through this external object, but
 * Darwin and FreeBSD do not declare it from <unistd.h> under every feature
 * profile used by our warnings-as-errors builds. Keep the declaration beside
 * the execve/fexecve portability layer instead of relying on libc extensions. */
#if defined(__APPLE__) || defined(__FreeBSD__)
extern char **environ;
#endif

/* Linux, macOS, and FreeBSD can pin a directory descriptor without following
 * a replaced final-component symlink. Other platforms fail closed rather than
 * attempt a pathname chmod that could be redirected after validation. */
#if defined(O_NOFOLLOW) && defined(O_DIRECTORY)
#define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 1
#else
#define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 0
#endif

typedef struct {
    bool active;
    int fd;
    dev_t dev;
    ino_t ino;
    dev_t rdev;
    struct termios original;
} terminal_echo_state_t;

/* Echo recovery owns the exact terminal it changed, not whichever object is
 * later installed as standard input.  Publish this state only after the
 * no-echo transition succeeds. */
static terminal_echo_state_t g_terminal_echo_state = {
    .fd = -1
};

#define RUNTIME_LOCK_CONTEXTS 8
#define PRIVATE_LOCK_INODES 64
#define PRIVATE_LOCK_CONTEXTS 64

typedef struct {
    bool active;
    dev_t dev;
    ino_t ino;
    int fd;
    unsigned refs;
} private_lock_inode_t;

typedef struct {
    bool active;
    int token_fd;
    dev_t token_dev;
    ino_t token_ino;
    int guard_fd;
    dev_t guard_dev;
    ino_t guard_ino;
    uint64_t token_generation;
    size_t parent_slot;
    size_t leaf_slot;
    size_t file_slot;
} private_lock_context_t;

typedef struct {
    bool active;
    int lock_fd;
    uint64_t lock_generation;
    size_t anchor_slot;
    int parent_fd;
    int dir_fd;
    dev_t parent_dev;
    ino_t parent_ino;
    dev_t dir_dev;
    ino_t dir_ino;
    char parent_path[MAX_PATH_LEN];
    char child_name[64];
} runtime_lock_context_t;
static runtime_lock_context_t g_runtime_locks[RUNTIME_LOCK_CONTEXTS];
static private_lock_inode_t g_private_lock_inodes[PRIVATE_LOCK_INODES];
static private_lock_context_t g_private_lock_contexts[PRIVATE_LOCK_CONTEXTS];
static pid_t g_private_lock_pid;
static pid_t g_runtime_lock_pid;
static uint64_t g_private_lock_next_generation;

static int dup_cloexec(int fd, int minimum);
static int private_lock_create_token(int *token_fd, int *guard_fd,
                                     struct stat *token_stat,
                                     struct stat *guard_stat);
static int private_lock_inode_acquire(int owned_fd, bool nonblocking,
                                      size_t *slot_out);
static void private_lock_inode_release(size_t slot);
static bool same_fs_identity(const struct stat *a, const struct stat *b);
static bool exec_fd_acl_is_trusted(int fd);
#ifdef GITSWITCH_TESTING
bool runtime_entry_test_may_be_replaced(
    uid_t uid, mode_t parent_mode, uid_t parent_uid,
    bool parent_acl_trusted, uid_t child_uid, bool child_acl_trusted,
    bool child_owner_can_add_delete_acl);
#endif

/* String utilities */

char *trim_whitespace(char *str) {
    char *end;
    
    if (!str) return NULL;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    /* All spaces? */
    if (*str == '\0') return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    end[1] = '\0';
    
    return str;
}

bool string_empty(const char *str) {
    return !str || *str == '\0';
}

bool string_equals(const char *a, const char *b) {
    if (!a && !b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

bool string_ascii_case_equal(const char *a, const char *b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return *a == '\0' && *b == '\0';
}

bool string_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return false;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool string_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

int string_replace(char *str, size_t str_size, const char *old, const char *new) {
    if (!str || !old || !new) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to string_replace");
        return -1;
    }
    
    char *pos = strstr(str, old);
    if (!pos) return 0; /* No replacement needed */
    
    size_t old_len = strlen(old);
    size_t new_len = strlen(new);
    size_t str_len = strlen(str);
    
    /* Check if replacement would overflow buffer */
    if (str_len - old_len + new_len >= str_size) {
        set_error(ERR_INVALID_ARGS, "String replacement would overflow buffer");
        return -1;
    }
    
    /* Move the rest of the string */
    memmove(pos + new_len, pos + old_len, strlen(pos + old_len) + 1);
    
    /* Copy new string */
    memcpy(pos, new, new_len);
    
    return 1;
}

/* Path utilities */

int expand_path(const char *path, char *expanded_path, size_t path_size) {
    if (!path || !expanded_path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to expand_path");
        return -1;
    }
    
    /* Handle tilde expansion */
    if (path[0] == '~') {
        char home_path[MAX_PATH_LEN];

        /* Only the current user's home is supported: "~" and "~/...". A
         * "~user/..." form is rejected rather than silently mis-expanded to
         * "$HOME/user/..." (which produced confusing "not found" paths and,
         * if such a path happened to exist, could load the wrong key). */
        if (path[1] != '\0' && path[1] != '/') {
            set_error(ERR_INVALID_ARGS,
                      "~user paths are not supported; use an absolute path or ~/: %s", path);
            return -1;
        }

        if (get_home_directory(home_path, sizeof(home_path)) != 0) {
            return -1;
        }

        /* Handle ~/path and ~ cases */
        const char *rest = (path[1] == '/') ? path + 2 : path + 1;

        if (snprintf(expanded_path, path_size, "%s/%s", home_path, rest) >= (int)path_size) {
            set_error(ERR_INVALID_ARGS, "Expanded path too long");
            return -1;
        }
    } else {
        /* Path doesn't need expansion */
        if (strlen(path) >= path_size) {
            set_error(ERR_INVALID_ARGS, "Path too long for buffer");
            return -1;
        }
        strcpy(expanded_path, path); /* Flawfinder: ignore — length-checked above */
    }
    
    return 0;
}

int get_home_directory(char *home_path, size_t path_size) {
    const char *home = getenv("HOME");

    /* AR-12 P11: an empty or relative HOME would silently anchor the config
     * at '/' or the CWD — inconsistent with the validated XDG_RUNTIME_DIR
     * and git_ops HOME guards. Treat it like an absent HOME and fall back
     * to the password database. */
    if (home && home[0] != '/') {
        home = NULL;
    }
    if (!home) {
        /* Fall back to password database */
        struct passwd *pw = getpwuid(getuid());
        if (!pw || !pw->pw_dir || pw->pw_dir[0] != '/') {
            set_system_error(ERR_SYSTEM_CALL, "Failed to get user home directory");
            return -1;
        }
        home = pw->pw_dir;
    }
    
    if (strlen(home) >= path_size) {
        set_error(ERR_INVALID_ARGS, "Home directory path too long");
        return -1;
    }
    
    strcpy(home_path, home); /* Flawfinder: ignore — length-checked above */
    return 0;
}

int join_path(char *result, size_t result_size, const char *base, const char *component) {
    if (!result || !base || !component || result_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to join_path");
        return -1;
    }
    
    size_t base_len = strlen(base);
    size_t comp_len = strlen(component);
    bool needs_separator = (base_len > 0 && base[base_len - 1] != '/') && 
                          (comp_len > 0 && component[0] != '/');
    
    size_t total_len = base_len + comp_len + (needs_separator ? 1 : 0);
    
    if (total_len >= result_size) {
        set_error(ERR_INVALID_ARGS, "Joined path too long for buffer");
        return -1;
    }
    
    strcpy(result, base); /* Flawfinder: ignore — length-checked above */
    if (needs_separator) {
        strcat(result, "/");
    }
    strcat(result, component); /* Flawfinder: ignore — length-checked above */
    
    return 0;
}

bool path_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

bool is_directory(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

#ifdef GITSWITCH_TESTING
typedef void (*create_directory_test_hook_fn)(int stage, const char *path);
create_directory_test_hook_fn gitswitch_test_set_create_directory_hook(
    create_directory_test_hook_fn hook);

static create_directory_test_hook_fn g_create_directory_test_hook;

create_directory_test_hook_fn gitswitch_test_set_create_directory_hook(
    create_directory_test_hook_fn hook) {
    create_directory_test_hook_fn previous = g_create_directory_test_hook;
    g_create_directory_test_hook = hook;
    return previous;
}

#define CREATE_DIRECTORY_TEST_CHECKPOINT(stage, path) \
    do { \
        if (g_create_directory_test_hook) \
            g_create_directory_test_hook((stage), (path)); \
    } while (0)
#else
#define CREATE_DIRECTORY_TEST_CHECKPOINT(stage, path) \
    do { (void)(stage); (void)(path); } while (0)
#endif

enum {
    CREATE_DIRECTORY_TEST_AFTER_FINAL_OPEN = 1
};

int create_directory_recursive(const char *path, mode_t mode) {
    char *path_copy = NULL;
    char *saveptr = NULL;
    char *component;
    int current_fd = -1;
    int final_fd = -1;
    int named_fd = -1;
    int result = -1;
    int open_flags = O_RDONLY;
    struct stat opened;
    struct stat entry;
    struct stat named;

    if (!path || !*path) {
        /* Reject NULL/empty (AR-06 F78, rationale updated AR-12 L24): the
         * component walk below requires at least one component, and the
         * absolute-vs-relative dispatch must not consult path[0] of an
         * empty string. */
        set_error(ERR_INVALID_ARGS, "NULL or empty path to create_directory_recursive");
        return -1;
    }
    if (strlen(path) >= MAX_PATH_LEN) {
        set_error(ERR_INVALID_ARGS, "Path too long");
        return -1;
    }
    path_copy = strdup(path);
    if (!path_copy) {
        set_system_error(ERR_MEMORY_ALLOCATION,
                         "Failed to copy directory path");
        return -1;
    }
#ifdef O_DIRECTORY
    open_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
    current_fd = open(path[0] == '/' ? "/" : ".", open_flags);
    if (current_fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to open directory walk root: %s",
                         path);
        goto cleanup;
    }

    component = strtok_r(path_copy, "/", &saveptr);
    if (!component) {
        final_fd = current_fd;
        current_fd = -1;
    }
    while (component) {
        char *next = strtok_r(NULL, "/", &saveptr);
        bool final = next == NULL;
        int child_fd;
        int child_flags = open_flags;

        if (mkdirat(current_fd, component, mode) != 0 && errno != EEXIST) {
            set_system_error(ERR_FILE_IO, "Failed to create directory: %s",
                             path);
            goto cleanup;
        }
#ifdef O_NOFOLLOW
        if (final) child_flags |= O_NOFOLLOW;
#endif
        child_fd = openat(current_fd, component, child_flags);
        if (child_fd < 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to open directory path component: %s",
                             path);
            goto cleanup;
        }
        if (fstat(child_fd, &opened) != 0) {
            int saved_errno = errno;
            close(child_fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Failed to inspect directory path component: %s",
                             path);
            goto cleanup;
        }
        if (!S_ISDIR(opened.st_mode)) {
            close(child_fd);
            errno = ENOTDIR;
            set_system_error(ERR_FILE_IO,
                             "Directory path component is not a directory: %s",
                             path);
            goto cleanup;
        }
        int entry_rc = fstatat(current_fd, component, &entry,
                               final ? AT_SYMLINK_NOFOLLOW : 0);
        if (entry_rc != 0 || !S_ISDIR(entry.st_mode) ||
            !same_fs_identity(&opened, &entry)) {
            int saved_errno = entry_rc != 0
                                  ? errno
                                  : (!S_ISDIR(entry.st_mode) ? ENOTDIR
                                                             : EAGAIN);
            close(child_fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Directory path changed during creation: %s",
                             path);
            goto cleanup;
        }
        close(current_fd);
        current_fd = -1;
        if (final) {
            final_fd = child_fd;
        } else {
            current_fd = child_fd;
        }
        component = next;
    }

    CREATE_DIRECTORY_TEST_CHECKPOINT(CREATE_DIRECTORY_TEST_AFTER_FINAL_OPEN,
                                     path);
    {
        int named_flags = open_flags;
#ifdef O_NOFOLLOW
        named_flags |= O_NOFOLLOW;
#endif
        named_fd = open(path, named_flags);
    }
    if (named_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Directory path changed during creation: %s", path);
        goto cleanup;
    }
    if (fstat(final_fd, &opened) != 0 || fstat(named_fd, &named) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to verify created directory: %s", path);
        goto cleanup;
    }
    if (!S_ISDIR(named.st_mode) || !same_fs_identity(&opened, &named)) {
        errno = !S_ISDIR(named.st_mode) ? ENOTDIR : EAGAIN;
        set_system_error(ERR_FILE_IO,
                         "Directory path changed during creation: %s", path);
        goto cleanup;
    }
    result = 0;

cleanup: {
        int saved_errno = errno;
        if (named_fd >= 0) close(named_fd);
        if (final_fd >= 0) close(final_fd);
        if (current_fd >= 0) close(current_fd);
        free(path_copy);
        errno = saved_errno;
        return result;
    }
}

int ensure_private_dir(const char *path) {
    struct stat path_st;

    if (!path || !*path) {
        set_error(ERR_INVALID_ARGS, "NULL path to ensure_private_dir");
        return -1;
    }

    if (lstat(path, &path_st) != 0) {
        if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO, "Cannot stat directory: %s", path);
            return -1;
        }
        /* Create it (parents may already exist with other ownership, which is
         * fine — only the leaf holds our private material). */
        if (create_directory_recursive(path, 0700) != 0) {
            return -1;
        }
        if (lstat(path, &path_st) != 0) {
            set_system_error(ERR_FILE_IO, "Cannot stat created directory: %s", path);
            return -1;
        }
    }

    /* Must be a real directory (lstat does not follow symlinks), owned by us,
     * with no group/other access — refuse a hostile pre-created/redirected dir. */
    if (S_ISLNK(path_st.st_mode) || !S_ISDIR(path_st.st_mode)) {
        set_error(ERR_PERMISSION_DENIED, "Refusing to use non-directory/symlink path: %s", path);
        return -1;
    }
    if (path_st.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED, "Directory not owned by current user: %s", path);
        return -1;
    }

#if GITSWITCH_HAVE_DIRECTORY_NOFOLLOW
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot open private directory safely: %s", path);
        return -1;
    }

    struct stat fd_st;
    if (fstat(fd, &fd_st) != 0) {
        close(fd);
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot verify private directory: %s", path);
        return -1;
    }
    if (!S_ISDIR(fd_st.st_mode) || fd_st.st_uid != getuid() ||
        fd_st.st_dev != path_st.st_dev || fd_st.st_ino != path_st.st_ino) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Private directory changed while being verified: %s", path);
        return -1;
    }

    if ((fd_st.st_mode & 077) != 0) {
        if (fchmod(fd, 0700) != 0 || fstat(fd, &fd_st) != 0 ||
            !S_ISDIR(fd_st.st_mode) || fd_st.st_uid != getuid() ||
            (fd_st.st_mode & 077) != 0) {
            close(fd);
            set_error(ERR_PERMISSION_DENIED, "Directory has unsafe permissions: %s", path);
            return -1;
        }
    }

    struct stat final_st;
    if (lstat(path, &final_st) != 0 || !S_ISDIR(final_st.st_mode) ||
        final_st.st_dev != fd_st.st_dev || final_st.st_ino != fd_st.st_ino) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Private directory changed while being secured: %s", path);
        return -1;
    }
    close(fd);
#else
    if ((path_st.st_mode & 077) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Directory permissions are unsafe and this platform cannot "
                  "tighten them without following paths: %s", path);
        return -1;
    }
#endif
    return 0;
}

static bool same_fs_identity(const struct stat *a, const struct stat *b) {
    return a && b && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int open_directory_nofollow(const char *path, struct stat *opened) {
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd < 0 || fstat(fd, opened) != 0 || !S_ISDIR(opened->st_mode)) {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

/* Conservatively decide whether this uid could replace the child entry. Mode
 * checks deliberately over-approximate group access: an unnecessary ancestor
 * lock only narrows concurrency, while missing one can split the namespace.
 * Sticky directories still protect entries not owned by this uid. Nontrivial
 * or unreadable ACLs are treated as permitting replacement. */
static bool runtime_entry_permissions_may_be_replaced(
    uid_t uid, const struct stat *parent, bool parent_acl_trusted,
    const struct stat *child, bool child_acl_trusted,
    bool child_owner_can_add_delete_acl) {
    bool writable;

    if (uid == (uid_t)0) return true;
    /* An owner can add write permission later, so current mode bits cannot
     * make an owned ancestor stable for the lifetime of the transaction. */
    if (parent->st_uid == uid) return true;
    /* Darwin and NFSv4 child owners can later add a DELETE ACL even when the
     * current ACL is trivial. Keep this capability platform-scoped so Linux
     * paths do not acquire an unnecessarily broad system-directory lock. */
    if (child_owner_can_add_delete_acl && child->st_uid == uid) return true;
    /* Darwin and NFSv4 ACLs may grant deletion on the child itself even when
     * the parent mode/ACL appears immutable. Ambiguous ACLs serialize. */
    if (!parent_acl_trusted || !child_acl_trusted) return true;
    writable =
        (parent->st_mode & (S_IWGRP | S_IXGRP)) ==
            (S_IWGRP | S_IXGRP) ||
        (parent->st_mode & (S_IWOTH | S_IXOTH)) ==
            (S_IWOTH | S_IXOTH);
    if (!writable) return false;
    if ((parent->st_mode & S_ISVTX) != 0 && parent->st_uid != uid &&
        child->st_uid != uid) {
        return false;
    }
    return true;
}

static bool runtime_entry_may_be_replaced(int parent_fd, int child_fd,
                                          const struct stat *parent,
                                          const struct stat *child) {
#if defined(__APPLE__) || defined(__FreeBSD__)
    const bool child_owner_can_add_delete_acl = true;
#else
    const bool child_owner_can_add_delete_acl = false;
#endif

    return runtime_entry_permissions_may_be_replaced(
        getuid(), parent, exec_fd_acl_is_trusted(parent_fd), child,
        exec_fd_acl_is_trusted(child_fd), child_owner_can_add_delete_acl);
}

#ifdef GITSWITCH_TESTING
bool runtime_entry_test_may_be_replaced(
    uid_t uid, mode_t parent_mode, uid_t parent_uid,
    bool parent_acl_trusted, uid_t child_uid, bool child_acl_trusted,
    bool child_owner_can_add_delete_acl) {
    struct stat parent;
    struct stat child;

    memset(&parent, 0, sizeof(parent));
    memset(&child, 0, sizeof(child));
    parent.st_mode = S_IFDIR | parent_mode;
    parent.st_uid = parent_uid;
    child.st_mode = S_IFDIR | 0700;
    child.st_uid = child_uid;
    return runtime_entry_permissions_may_be_replaced(
        uid, &parent, parent_acl_trusted, &child, child_acl_trusted,
        child_owner_can_add_delete_acl);
}
#endif

static void runtime_path_release_anchor(size_t *anchor_slot) {
    if (anchor_slot && *anchor_slot != PRIVATE_LOCK_INODES) {
        private_lock_inode_release(*anchor_slot);
        *anchor_slot = PRIVATE_LOCK_INODES;
    }
}

/* Open an absolute, lexically normalized runtime path one component at a
 * time.  Whole-path O_NOFOLLOW protects only the leaf; using openat() from a
 * pinned parent makes the same no-link rule apply to every directory entry.
 * Each opened descriptor is also matched to the entry observed without
 * following links before the walk advances. When anchor_slot is non-NULL,
 * acquire and retain a non-blocking lock on the parent of the first entry this
 * uid could replace. Every cooperating traversal then shares that stable
 * prefix even if a lower ordinary directory is renamed and recreated. */
static int open_runtime_path_nofollow(const char *path, struct stat *opened,
                                      size_t *anchor_slot,
                                      bool *anchor_lock_failed) {
    char component[MAX_PATH_LEN];
    struct stat current_stat;
    int current_fd;

    if (anchor_slot) *anchor_slot = PRIVATE_LOCK_INODES;
    if (anchor_lock_failed) *anchor_lock_failed = false;
    if (!path || path[0] != '/' || !opened ||
        (anchor_slot && !anchor_lock_failed)) {
        errno = EINVAL;
        return -1;
    }
    current_fd = open_directory_nofollow("/", &current_stat);
    if (current_fd < 0) return -1;

    const char *cursor = path + 1;
    while (*cursor) {
        const char *separator = strchr(cursor, '/');
        size_t length = separator ? (size_t)(separator - cursor)
                                  : strlen(cursor);
        struct stat entry_stat;
        struct stat next_stat;
        int flags = O_RDONLY;
        int next_fd;

        if (length == 0 || length >= sizeof(component)) {
            close(current_fd);
            runtime_path_release_anchor(anchor_slot);
            errno = length == 0 ? EINVAL : ENAMETOOLONG;
            return -1;
        }
        memcpy(component, cursor, length);
        component[length] = '\0';
#ifdef O_DIRECTORY
        flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        next_fd = openat(current_fd, component, flags);
        if (next_fd < 0) {
            int saved_errno = errno;
            close(current_fd);
            runtime_path_release_anchor(anchor_slot);
            errno = saved_errno;
            return -1;
        }
        if (fstat(next_fd, &next_stat) != 0 ||
            fstatat(current_fd, component, &entry_stat,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            int saved_errno = errno;
            close(next_fd);
            close(current_fd);
            runtime_path_release_anchor(anchor_slot);
            errno = saved_errno;
            return -1;
        }
        if (!S_ISDIR(next_stat.st_mode) || !S_ISDIR(entry_stat.st_mode) ||
            !same_fs_identity(&next_stat, &entry_stat)) {
            close(next_fd);
            close(current_fd);
            runtime_path_release_anchor(anchor_slot);
            errno = EACCES;
            return -1;
        }
        if (anchor_slot && *anchor_slot == PRIVATE_LOCK_INODES &&
            runtime_entry_may_be_replaced(current_fd, next_fd, &current_stat,
                                          &next_stat)) {
            int anchor_fd = dup_cloexec(current_fd, 0);
            if (anchor_fd < 0 ||
                private_lock_inode_acquire(anchor_fd, true,
                                           anchor_slot) != 0) {
                int saved_errno = errno;
                *anchor_lock_failed = true;
                close(next_fd);
                close(current_fd);
                runtime_path_release_anchor(anchor_slot);
                errno = saved_errno;
                return -1;
            }
            if (fstatat(current_fd, component, &entry_stat,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                int saved_errno = errno;
                close(next_fd);
                close(current_fd);
                runtime_path_release_anchor(anchor_slot);
                errno = saved_errno;
                return -1;
            }
            if (!S_ISDIR(entry_stat.st_mode) ||
                !same_fs_identity(&next_stat, &entry_stat)) {
                close(next_fd);
                close(current_fd);
                runtime_path_release_anchor(anchor_slot);
                errno = EACCES;
                return -1;
            }
        }
        close(current_fd);
        current_fd = next_fd;
        current_stat = next_stat;
        cursor = separator ? separator + 1 : cursor + length;
    }
    *opened = current_stat;
    return current_fd;
}

static bool runtime_path_component_error(int error) {
    if (error == EACCES || error == EPERM || error == ENOTDIR ||
        error == ELOOP) {
        return true;
    }
#ifdef EMLINK
    if (error == EMLINK) return true;
#endif
    return false;
}

static bool runtime_lock_is_contended_error(int error) {
    bool contended = error == EWOULDBLOCK;
#if EAGAIN != EWOULDBLOCK
    contended = contended || error == EAGAIN;
#endif
    return contended;
}

/* Normalize only lexical no-op components in XDG_RUNTIME_DIR.  In particular,
 * do not call realpath(): every component must remain visible to the later
 * descriptor-relative no-follow walk, so `link`, `link/`, and `link/.` all
 * receive the same decision. Parent traversal is rejected rather than
 * normalized because `..` across an intermediate link has filesystem-
 * dependent meaning. */
static int normalize_runtime_path(const char *input, char *output,
                                  size_t output_size) {
    if (!input || input[0] != '/' || !output || output_size < 2) {
        errno = EINVAL;
        return -1;
    }

    size_t written = 1;
    output[0] = '/';
    const char *cursor = input + 1;
    while (*cursor) {
        while (*cursor == '/') cursor++;
        if (!*cursor) break;

        const char *component = cursor;
        while (*cursor && *cursor != '/') cursor++;
        size_t length = (size_t)(cursor - component);
        if (length == 1 && component[0] == '.') continue;
        if (length == 2 && component[0] == '.' && component[1] == '.') {
            errno = EINVAL;
            return -1;
        }
        if (written > 1) {
            if (written + 1 >= output_size) {
                errno = ENAMETOOLONG;
                return -1;
            }
            output[written++] = '/';
        }
        if (length >= output_size - written) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(output + written, component, length);
        written += length;
    }
    output[written] = '\0';
    return 0;
}

/* Darwin exposes /tmp as the system-owned /private/tmp alias. Test fixtures
 * and callers commonly spell private runtime directories below /tmp, so
 * translate that one documented platform alias before the strict no-follow
 * walk. No caller-controlled component below it is resolved. */
static int canonicalize_runtime_tmp_prefix(const char *normalized,
                                           char *canonical,
                                           size_t canonical_size) {
    if (strncmp(normalized, "/tmp", 4) != 0 ||
        (normalized[4] != '\0' && normalized[4] != '/')) {
        return safe_strncpy(canonical, normalized, canonical_size);
    }

    char *tmp_target = realpath("/tmp", NULL);
    if (!tmp_target) return -1;
    int written = snprintf(canonical, canonical_size, "%s%s", tmp_target,
                           normalized + 4);
    free(tmp_target);
    if (written < 0 || (size_t)written >= canonical_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int open_runtime_parent_impl(char *path, size_t path_size,
                                    size_t *anchor_slot) {
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    char normalized_xdg[MAX_PATH_LEN];
    char canonical_xdg[MAX_PATH_LEN];
    const char *configured_xdg = xdg;
    struct stat opened;
    bool anchor_lock_failed = false;
    int fd;

    if (anchor_slot) *anchor_slot = PRIVATE_LOCK_INODES;
    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid runtime-parent output buffer");
        return -1;
    }

    /* XDG Base Directory requires an absolute runtime path.  Reject a
     * relative value before the first pathname operation: otherwise the same
     * shell environment names a different runtime/lock namespace after every
     * chdir(), and two gitswitch processes can believe they serialize through
     * one lock while actually mutating different trees (AR-07 M44). */
    if (xdg && *xdg && xdg[0] != '/') {
        set_error(ERR_INVALID_PATH,
                  "XDG_RUNTIME_DIR must be an absolute path: %s", xdg);
        return -1;
    }
    if (xdg && *xdg) {
        if (normalize_runtime_path(xdg, normalized_xdg,
                                   sizeof(normalized_xdg)) != 0) {
            set_error(ERR_INVALID_PATH,
                      "XDG_RUNTIME_DIR has an unsafe or oversized path spelling: %s",
                      xdg);
            return -1;
        }
        if (canonicalize_runtime_tmp_prefix(normalized_xdg, canonical_xdg,
                                            sizeof(canonical_xdg)) != 0) {
            if (errno == ENAMETOOLONG) {
                set_error(
                    ERR_INVALID_PATH,
                    "XDG_RUNTIME_DIR has an oversized system-temporary path: %s",
                    xdg);
            } else {
                set_system_error(ERR_FILE_IO,
                                 "Cannot resolve system temporary alias");
            }
            return -1;
        }
        configured_xdg = canonical_xdg;
    }

    if (xdg && *xdg) {
        fd = open_runtime_path_nofollow(configured_xdg, &opened,
                                        anchor_slot, &anchor_lock_failed);
        if (fd >= 0) {
            if (opened.st_uid != getuid() ||
                (opened.st_mode & 0777) != PERM_USER_RWX) {
                close(fd);
                runtime_path_release_anchor(anchor_slot);
                set_error(ERR_PERMISSION_DENIED,
                          "XDG_RUNTIME_DIR must be an accessible 0700 self-owned directory: %s",
                          configured_xdg);
                return -1;
            }
            if (safe_strncpy(path, configured_xdg, path_size) != 0) {
                close(fd);
                runtime_path_release_anchor(anchor_slot);
                set_error(ERR_INVALID_PATH, "XDG_RUNTIME_DIR path is too long");
                return -1;
            }
            return fd;
        }
        int open_error = errno;
        if (anchor_lock_failed) {
            errno = open_error;
            if (runtime_lock_is_contended_error(open_error)) {
                set_error(ERR_FILE_IO,
                          "Another gitswitch holds the shared runtime lock "
                          "(possibly waiting at a passphrase/PIN prompt); try "
                          "again after that command finishes");
            } else {
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot lock stable XDG_RUNTIME_DIR ancestor: %s",
                    configured_xdg);
            }
            return -1;
        }
        if (open_error != ENOENT) {
            if (open_error == EACCES || open_error == EPERM) {
                errno = open_error;
                set_system_error(ERR_FILE_IO,
                                 "Cannot access XDG_RUNTIME_DIR: %s",
                                 configured_xdg);
            } else if (runtime_path_component_error(open_error)) {
                set_error(ERR_PERMISSION_DENIED,
                          "XDG_RUNTIME_DIR contains an unsafe path component: %s",
                          configured_xdg);
            } else {
                errno = open_error;
                set_system_error(ERR_FILE_IO,
                                 "Cannot inspect XDG_RUNTIME_DIR: %s",
                                 configured_xdg);
            }
            return -1;
        }
        errno = open_error;
        set_system_error(ERR_FILE_IO,
                         "Configured XDG_RUNTIME_DIR does not exist: %s",
                         configured_xdg);
        return -1;
    }

    /* /tmp is a symlink to /private/tmp on macOS.  Open its canonical target
     * with O_NOFOLLOW, while retaining the literal /tmp spelling that callers
     * use to select their uid-specific fallback layout. */
    char *fallback = realpath("/tmp", NULL);
    if (!fallback) {
        set_system_error(ERR_FILE_IO,
                         "Cannot resolve temporary runtime parent");
        return -1;
    }
    if (safe_strncpy(path, "/tmp", path_size) != 0) {
        free(fallback);
        set_error(ERR_INVALID_PATH, "Temporary runtime-parent path is too long");
        return -1;
    }
    fd = open_directory_nofollow(fallback, &opened);
    free(fallback);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot open runtime parent: %s", path);
        return -1;
    }
    return fd;
}

int open_runtime_parent(char *path, size_t path_size) {
    return open_runtime_parent_impl(path, path_size, NULL);
}

/* Configured XDG roots are re-opened through the same component-wise no-follow
 * walk used for acquisition. The fixed /tmp fallback may itself be a platform
 * symlink (Darwin), so its identity check follows that one supported alias. */
static int runtime_parent_named_stat(const char *path, struct stat *st) {
    if (strcmp(path, "/tmp") == 0) return stat(path, st);

    int fd = open_runtime_path_nofollow(path, st, NULL, NULL);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static const char *runtime_lock_stat_failure_kind(int error) {
    if (error == ENOENT || error == ENOTDIR) return "disappeared";
    if (error == EACCES || error == EPERM) return "became inaccessible";
    return "could not be inspected";
}

static void runtime_lock_warn_stat_failure(const char *subject,
                                           const char *parent_path,
                                           const char *child_name,
                                           int error) {
    const char *kind = runtime_lock_stat_failure_kind(error);
    if (child_name) {
        log_warning("runtime lock %s '%s/%s' %s during release: %s "
                    "(errno=%d)", subject, parent_path, child_name, kind,
                    strerror(error), error);
    } else {
        log_warning("runtime lock %s '%s' %s during release: %s (errno=%d)",
                    subject, parent_path, kind, strerror(error), error);
    }
}

static runtime_lock_release_stat_probe_t
    g_runtime_lock_test_release_stat_probe = RUNTIME_LOCK_RELEASE_STAT_NONE;
static int g_runtime_lock_test_release_stat_errno = EIO;

void runtime_lock_test_fail_release_stat(
    runtime_lock_release_stat_probe_t probe, int system_errno) {
    switch (probe) {
        case RUNTIME_LOCK_RELEASE_STAT_NONE:
        case RUNTIME_LOCK_RELEASE_STAT_PINNED_PARENT:
        case RUNTIME_LOCK_RELEASE_STAT_NAMED_PARENT:
        case RUNTIME_LOCK_RELEASE_STAT_PINNED_DIRECTORY:
        case RUNTIME_LOCK_RELEASE_STAT_NAMED_DIRECTORY:
            g_runtime_lock_test_release_stat_probe = probe;
            break;
        default:
            g_runtime_lock_test_release_stat_probe =
                RUNTIME_LOCK_RELEASE_STAT_NONE;
            break;
    }
    g_runtime_lock_test_release_stat_errno =
        system_errno > 0 ? system_errno : EIO;
}

static bool runtime_lock_test_consume_release_stat(
    runtime_lock_release_stat_probe_t probe) {
    if (g_runtime_lock_test_release_stat_probe != probe) return false;
    g_runtime_lock_test_release_stat_probe = RUNTIME_LOCK_RELEASE_STAT_NONE;
    errno = g_runtime_lock_test_release_stat_errno;
    return true;
}

int open_private_subdir_at(int parent_fd, const char *name, bool create,
                           bool *absent) {
    struct stat opened;
    struct stat entry;
    int flags = O_RDONLY;
    int fd;

    if (absent) *absent = false;
    if (parent_fd < 0 || !name || !*name || strchr(name, '/') ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid private runtime subdirectory");
        return -1;
    }
    if (create && mkdirat(parent_fd, name, 0700) != 0 && errno != EEXIST) {
        set_system_error(ERR_FILE_IO,
                         "Cannot create private runtime subdirectory: %s", name);
        return -1;
    }
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = openat(parent_fd, name, flags);
    if (fd < 0) {
        if (!create && errno == ENOENT && absent) {
            *absent = true;
            return -1;
        }
        /* O_NOFOLLOW reports a terminal symlink differently across kernels:
         * Linux/macOS use ELOOP or ENOTDIR, while FreeBSD returns EMLINK. */
        if (errno == ELOOP || errno == ENOTDIR || errno == EMLINK) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing non-directory/symlink runtime subdirectory: %s",
                      name);
            return -1;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot open private runtime subdirectory: %s", name);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !S_ISDIR(opened.st_mode) ||
        opened.st_uid != getuid()) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Runtime subdirectory is not a self-owned directory: %s", name);
        return -1;
    }
    if ((opened.st_mode & 077) != 0) {
        if (!create || fchmod(fd, 0700) != 0 || fstat(fd, &opened) != 0 ||
            !S_ISDIR(opened.st_mode) || opened.st_uid != getuid() ||
            (opened.st_mode & 077) != 0) {
            close(fd);
            set_error(ERR_PERMISSION_DENIED,
                      "Runtime subdirectory permissions are unsafe: %s", name);
            return -1;
        }
    }
    if (fstatat(parent_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(entry.st_mode) || !same_fs_identity(&opened, &entry)) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Runtime subdirectory changed while being opened: %s", name);
        return -1;
    }
    return fd;
}

static bool private_lock_fd_has_identity(int fd, dev_t dev, ino_t ino) {
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 && st.st_dev == dev && st.st_ino == ino;
}

static int dup_cloexec(int fd, int minimum) {
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, minimum);
#else
    int copy = fcntl(fd, F_DUPFD, minimum);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(copy);
        errno = saved_errno;
        return -1;
    }
    return copy;
#endif
}

/* Return an anonymous descriptor as the public lock token.  The retained peer
 * keeps the anonymous object alive even if a caller closes the public token,
 * preventing the token inode from being recycled while stale bookkeeping
 * exists.  Neither endpoint aliases the real lock-file description. */
static int private_lock_create_token(int *token_fd, int *guard_fd,
                                     struct stat *token_stat,
                                     struct stat *guard_stat) {
    int pipe_fds[2] = {-1, -1};

    if (!token_fd || !guard_fd || !token_stat || !guard_stat) {
        errno = EINVAL;
        return -1;
    }
    if (pipe(pipe_fds) != 0) return -1;
    for (size_t i = 0; i < 2; i++) {
        int flags = fcntl(pipe_fds[i], F_GETFD);
        if (flags < 0 || fcntl(pipe_fds[i], F_SETFD, flags | FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            errno = saved_errno;
            return -1;
        }
    }
    if (fstat(pipe_fds[0], token_stat) != 0 ||
        fstat(pipe_fds[1], guard_stat) != 0) {
        int saved_errno = errno;
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    *token_fd = pipe_fds[0];
    *guard_fd = pipe_fds[1];
    return 0;
}

/* flock state is inherited across fork because parent and child initially
 * share the same open descriptions.  The child must discard that inherited
 * bookkeeping before trying to acquire anything: treating it as reentrant
 * ownership would let the child enter while the parent still holds the lock.
 * Identity checks avoid closing an unrelated descriptor if test/application
 * code closed and reused an exposed token before its first post-fork acquire. */
static void private_lock_prepare_process(void) {
    pid_t pid = getpid();

    if (g_private_lock_pid == 0) {
        g_private_lock_pid = pid;
        return;
    }
    if (g_private_lock_pid == pid) return;

    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        private_lock_context_t *ctx = &g_private_lock_contexts[i];
        if (ctx->active &&
            private_lock_fd_has_identity(ctx->token_fd, ctx->token_dev,
                                         ctx->token_ino)) {
            close(ctx->token_fd);
        }
        if (ctx->active &&
            private_lock_fd_has_identity(ctx->guard_fd, ctx->guard_dev,
                                         ctx->guard_ino)) {
            close(ctx->guard_fd);
        }
    }
    for (size_t i = 0; i < PRIVATE_LOCK_INODES; i++) {
        private_lock_inode_t *inode = &g_private_lock_inodes[i];
        if (inode->active &&
            private_lock_fd_has_identity(inode->fd, inode->dev, inode->ino)) {
            close(inode->fd);
        }
    }
    memset(g_private_lock_contexts, 0, sizeof(g_private_lock_contexts));
    memset(g_private_lock_inodes, 0, sizeof(g_private_lock_inodes));
    g_private_lock_next_generation = 0;
    g_private_lock_pid = pid;
}

static int private_lock_allocate_generation(uint64_t *generation_out) {
    if (!generation_out) {
        errno = EINVAL;
        return -1;
    }
    if (g_private_lock_next_generation == UINT64_MAX) {
        for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
            if (g_private_lock_contexts[i].active) {
                errno = EOVERFLOW;
                return -1;
            }
        }
        g_private_lock_next_generation = 0;
    }
    *generation_out = ++g_private_lock_next_generation;
    return 0;
}

static int private_lock_inode_acquire(int owned_fd, bool nonblocking,
                                      size_t *slot_out) {
    struct stat st;
    int operation = LOCK_EX | (nonblocking ? LOCK_NB : 0);

    if (fstat(owned_fd, &st) != 0) {
        int saved_errno = errno;
        close(owned_fd);
        errno = saved_errno;
        return -1;
    }
    for (size_t i = 0; i < PRIVATE_LOCK_INODES; i++) {
        private_lock_inode_t *inode = &g_private_lock_inodes[i];
        if (inode->active && inode->dev == st.st_dev && inode->ino == st.st_ino) {
            close(owned_fd);
            inode->refs++;
            *slot_out = i;
            return 0;
        }
    }
    for (size_t i = 0; i < PRIVATE_LOCK_INODES; i++) {
        private_lock_inode_t *inode = &g_private_lock_inodes[i];
        if (!inode->active) {
            if (flock(owned_fd, operation) != 0) {
                int saved_errno = errno;
                close(owned_fd);
                errno = saved_errno;
                return -1;
            }
            inode->active = true;
            inode->dev = st.st_dev;
            inode->ino = st.st_ino;
            inode->fd = owned_fd;
            inode->refs = 1;
            *slot_out = i;
            return 0;
        }
    }
    close(owned_fd);
    errno = EMFILE;
    return -1;
}

static void private_lock_inode_release(size_t slot) {
    private_lock_inode_t *inode;

    if (slot >= PRIVATE_LOCK_INODES) return;
    inode = &g_private_lock_inodes[slot];
    if (!inode->active || inode->refs == 0) return;
    inode->refs--;
    if (inode->refs == 0) {
        (void)flock(inode->fd, LOCK_UN);
        close(inode->fd);
        memset(inode, 0, sizeof(*inode));
    }
}

static int lock_private_file_at_mode(int dir_fd, const char *name,
                                     bool nonblocking,
                                     bool create_and_repair) {
    struct stat opened;
    struct stat entry;
    struct stat leaf;
    int flags = O_RDWR;
    int dir_flags = O_RDONLY;
    int parent_fd = -1;
    int leaf_fd = -1;
    int file_fd = -1;
    int token_fd = -1;
    int guard_fd = -1;
    struct stat token_stat;
    struct stat guard_stat;
    uint64_t token_generation = 0;
    size_t parent_slot = PRIVATE_LOCK_INODES;
    size_t leaf_slot = PRIVATE_LOCK_INODES;
    size_t file_slot = PRIVATE_LOCK_INODES;
    size_t context_slot = PRIVATE_LOCK_CONTEXTS;

    if (dir_fd < 0 || !name || !*name || strchr(name, '/')) {
        set_error(ERR_INVALID_ARGS, "Invalid private lock file");
        return -1;
    }
    private_lock_prepare_process();
    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        if (!g_private_lock_contexts[i].active) {
            context_slot = i;
            break;
        }
    }
    if (context_slot == PRIVATE_LOCK_CONTEXTS) {
        errno = EMFILE;
        return -1;
    }
#ifdef O_DIRECTORY
    dir_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    dir_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    dir_flags |= O_NOFOLLOW;
#endif
    parent_fd = openat(dir_fd, "..", dir_flags);
    leaf_fd = dup_cloexec(dir_fd, 0);
    if (parent_fd < 0 || leaf_fd < 0 || fstat(leaf_fd, &leaf) != 0 ||
        !S_ISDIR(leaf.st_mode)) {
        int saved_errno = errno;
        if (parent_fd >= 0) close(parent_fd);
        if (leaf_fd >= 0) close(leaf_fd);
        errno = saved_errno;
        return -1;
    }
    /* One global order for every participant prevents ABBA deadlocks.  Parent
     * is the namespace anchor: a replacement leaf beneath that same parent
     * cannot enter until the old leaf's holder releases this lock.  It MUST be
     * exclusive (AR-06 F31 considered SHARED to decouple the sibling chains
     * rooted at XDG_RUNTIME_DIR, but that breaks the leaf-replacement
     * guarantee: after a leaf dir is renamed away and recreated the new leaf is
     * a distinct inode, so the leaf/file locks below no longer serialize the old
     * holder against a new locker — only this exclusive parent lock does, as
     * config_lock_survives_post_acquisition_namespace_replacement proves). */
    if (private_lock_inode_acquire(parent_fd, nonblocking, &parent_slot) != 0) {
        close(leaf_fd);
        return -1;
    }
    parent_fd = -1;
    if (private_lock_inode_acquire(leaf_fd, nonblocking, &leaf_slot) != 0) {
        private_lock_inode_release(parent_slot);
        return -1;
    }
    leaf_fd = -1;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    if (create_and_repair) flags |= O_CREAT;
    file_fd = openat(dir_fd, name, flags, 0600);
    if (file_fd < 0) {
        goto fail;
    }
    if (fstat(file_fd, &opened) != 0) {
        goto fail;
    }
    if (!S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1) {
        errno = EACCES;
        goto fail;
    }
    if (create_and_repair) {
        if (fchmod(file_fd, 0600) != 0) {
            goto fail;
        }
    } else if ((opened.st_mode & 0777) != 0600) {
        errno = EACCES;
        goto fail;
    }
    if (private_lock_inode_acquire(file_fd, nonblocking, &file_slot) != 0) {
        file_fd = -1; /* acquire consumes the descriptor on every outcome */
        goto fail;
    }
    file_fd = -1;
    if (fstatat(dir_fd, name, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(entry.st_mode) || !same_fs_identity(&opened, &entry)) {
        errno = EACCES;
        goto fail;
    }
    if (private_lock_create_token(&token_fd, &guard_fd, &token_stat,
                                  &guard_stat) != 0) goto fail;
    if (private_lock_allocate_generation(&token_generation) != 0) goto fail;

    g_private_lock_contexts[context_slot].active = true;
    g_private_lock_contexts[context_slot].token_fd = token_fd;
    g_private_lock_contexts[context_slot].token_dev = token_stat.st_dev;
    g_private_lock_contexts[context_slot].token_ino = token_stat.st_ino;
    g_private_lock_contexts[context_slot].guard_fd = guard_fd;
    g_private_lock_contexts[context_slot].guard_dev = guard_stat.st_dev;
    g_private_lock_contexts[context_slot].guard_ino = guard_stat.st_ino;
    g_private_lock_contexts[context_slot].token_generation = token_generation;
    g_private_lock_contexts[context_slot].parent_slot = parent_slot;
    g_private_lock_contexts[context_slot].leaf_slot = leaf_slot;
    g_private_lock_contexts[context_slot].file_slot = file_slot;
    return token_fd;

fail: {
        int saved_errno = errno;
        if (file_fd >= 0) close(file_fd);
        if (token_fd >= 0) close(token_fd);
        if (guard_fd >= 0) close(guard_fd);
        private_lock_inode_release(file_slot);
        private_lock_inode_release(leaf_slot);
        private_lock_inode_release(parent_slot);
        errno = saved_errno;
        return -1;
    }
}

int lock_private_file_at(int dir_fd, const char *name) {
    return lock_private_file_at_mode(dir_fd, name, false, true);
}

int try_lock_private_file_at(int dir_fd, const char *name) {
    return lock_private_file_at_mode(dir_fd, name, true, true);
}

int try_lock_existing_private_file_at(int dir_fd, const char *name) {
    return lock_private_file_at_mode(dir_fd, name, true, false);
}

int verify_private_lock_file_at(int token_fd, int dir_fd, const char *name) {
    const private_lock_context_t *matched = NULL;
    const private_lock_inode_t *leaf_inode;
    const private_lock_inode_t *file_inode;
    struct stat token;
    struct stat leaf;
    struct stat named;

    if (token_fd < 0 || dir_fd < 0 || !name || !*name || strchr(name, '/')) {
        errno = EINVAL;
        return -1;
    }
    private_lock_prepare_process();
    if (fstat(token_fd, &token) != 0) {
        errno = ESTALE;
        return -1;
    }
    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        const private_lock_context_t *ctx = &g_private_lock_contexts[i];

        if (ctx->active && ctx->token_fd == token_fd &&
            ctx->token_dev == token.st_dev && ctx->token_ino == token.st_ino) {
            matched = ctx;
            break;
        }
    }
    if (!matched || matched->leaf_slot >= PRIVATE_LOCK_INODES ||
        matched->file_slot >= PRIVATE_LOCK_INODES) {
        errno = ESTALE;
        return -1;
    }
    leaf_inode = &g_private_lock_inodes[matched->leaf_slot];
    file_inode = &g_private_lock_inodes[matched->file_slot];
    if (!leaf_inode->active || leaf_inode->refs == 0 ||
        !file_inode->active || file_inode->refs == 0 ||
        !private_lock_fd_has_identity(leaf_inode->fd, leaf_inode->dev,
                                      leaf_inode->ino) ||
        !private_lock_fd_has_identity(file_inode->fd, file_inode->dev,
                                      file_inode->ino) ||
        fstat(dir_fd, &leaf) != 0 || !S_ISDIR(leaf.st_mode) ||
        leaf.st_dev != leaf_inode->dev || leaf.st_ino != leaf_inode->ino ||
        fstatat(dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named.st_mode) || named.st_uid != getuid() ||
        named.st_nlink != 1 || (named.st_mode & 0777) != 0600 ||
        named.st_dev != file_inode->dev || named.st_ino != file_inode->ino) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static uint64_t private_lock_latest_generation_for_fd(int token_fd) {
    uint64_t latest = 0;

    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        const private_lock_context_t *ctx = &g_private_lock_contexts[i];
        if (ctx->active && ctx->token_fd == token_fd &&
            ctx->token_generation > latest) {
            latest = ctx->token_generation;
        }
    }
    return latest;
}

static void private_lock_context_retire(private_lock_context_t *ctx,
                                        bool close_live_token) {
    size_t parent_slot = ctx->parent_slot;
    size_t leaf_slot = ctx->leaf_slot;
    size_t file_slot = ctx->file_slot;

    if (close_live_token &&
        private_lock_fd_has_identity(ctx->token_fd, ctx->token_dev,
                                     ctx->token_ino)) {
        close(ctx->token_fd);
    }
    if (private_lock_fd_has_identity(ctx->guard_fd, ctx->guard_dev,
                                     ctx->guard_ino)) {
        close(ctx->guard_fd);
    }
    memset(ctx, 0, sizeof(*ctx));
    private_lock_inode_release(file_slot);
    private_lock_inode_release(leaf_slot);
    private_lock_inode_release(parent_slot);
}

static bool private_lock_release_generation(int token_fd,
                                            uint64_t token_generation) {
    uint64_t latest = private_lock_latest_generation_for_fd(token_fd);

    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        private_lock_context_t *ctx = &g_private_lock_contexts[i];
        if (ctx->active && ctx->token_fd == token_fd &&
            ctx->token_generation == token_generation) {
            private_lock_context_retire(
                ctx, token_generation == latest && latest != 0);
            return true;
        }
    }
    return false;
}

void unlock_private_file(int token_fd) {
    private_lock_context_t *oldest = NULL;
    int saved_errno = errno;

    private_lock_prepare_process();
    if (token_fd < 0) {
        errno = saved_errno;
        return;
    }

    /* A closed token number can be reused by a later registered token. The
     * only descriptor that can still be live is the newest registration for
     * that number; consume older generations one release at a time without
     * closing the descriptor. This also resolves same-inode ABA, for which a
     * device/inode comparison alone cannot distinguish nested registrations. */
    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        private_lock_context_t *ctx = &g_private_lock_contexts[i];
        if (ctx->active && ctx->token_fd == token_fd &&
            (!oldest ||
             ctx->token_generation < oldest->token_generation)) {
            oldest = ctx;
        }
    }
    if (oldest) {
        (void)private_lock_release_generation(token_fd,
                                              oldest->token_generation);
    }

    /* Opaque tokens are valid only while registered in this process. Unknown
     * or double-released numbers are no-ops; acting on them could close an
     * unrelated descriptor that later reused the integer. */
    errno = saved_errno;
}

static void runtime_lock_prepare_process(void) {
    pid_t pid = getpid();

    /* Reset the generic registry first, before opening anything that could
     * reuse a descriptor number closed explicitly by post-fork caller code. */
    private_lock_prepare_process();
    if (g_runtime_lock_pid == 0) {
        g_runtime_lock_pid = pid;
        return;
    }
    if (g_runtime_lock_pid == pid) return;

    for (size_t i = 0; i < RUNTIME_LOCK_CONTEXTS; i++) {
        runtime_lock_context_t *ctx = &g_runtime_locks[i];
        if (!ctx->active) continue;
        if (private_lock_fd_has_identity(ctx->dir_fd, ctx->dir_dev,
                                         ctx->dir_ino)) {
            close(ctx->dir_fd);
        }
        if (private_lock_fd_has_identity(ctx->parent_fd, ctx->parent_dev,
                                         ctx->parent_ino)) {
            close(ctx->parent_fd);
        }
    }
    memset(g_runtime_locks, 0, sizeof(g_runtime_locks));
    g_runtime_lock_pid = pid;
}

int runtime_state_lock_acquire(void) {
    char runtime_parent[MAX_PATH_LEN];
    char lock_dir[MAX_PATH_LEN];
    const char *child_name;
    int parent_fd = -1;
    int dir_fd = -1;
    int lock_fd = -1;
    size_t anchor_slot = PRIVATE_LOCK_INODES;
    uint64_t lock_generation = 0;
    int written;

    runtime_lock_prepare_process();
    parent_fd = open_runtime_parent_impl(runtime_parent,
                                         sizeof(runtime_parent),
                                         &anchor_slot);
    if (parent_fd < 0) {
        return -1;
    }
    if (strcmp(runtime_parent, "/tmp") != 0) {
        child_name = "gitswitch-runtime";
    } else {
        static char fallback_name[64];
        if ((size_t)snprintf(fallback_name, sizeof(fallback_name),
                             "gitswitch-runtime-%d", getuid()) >=
            sizeof(fallback_name)) {
            close(parent_fd);
            private_lock_inode_release(anchor_slot);
            set_error(ERR_INVALID_PATH, "Shared runtime lock name is too long");
            return -1;
        }
        child_name = fallback_name;
    }
    written = snprintf(lock_dir, sizeof(lock_dir), "%s/%s",
                       runtime_parent, child_name);
    if (written < 0 || (size_t)written >= sizeof(lock_dir)) {
        close(parent_fd);
        private_lock_inode_release(anchor_slot);
        set_error(ERR_INVALID_PATH, "Shared runtime lock path is too long");
        return -1;
    }
    dir_fd = open_private_subdir_at(parent_fd, child_name, true, NULL);
    if (dir_fd < 0) {
        close(parent_fd);
        private_lock_inode_release(anchor_slot);
        return -1;
    }
    /* Non-blocking (AR-05 L13): the holder keeps this lock across ssh-add
     * passphrase and GPG pinentry prompts — unbounded human latency. Within
     * one HOME the non-blocking config lock in main.c fails fast first, but
     * a second gitswitch sharing XDG_RUNTIME_DIR under a DIFFERENT HOME
     * bypasses that outer lock and used to hang here silently, with no
     * message and no bound — the exact indefinite-prompt-holder hazard the
     * config lock was made non-blocking to avoid (AR-03 L10). Fail fast with
     * the same actionable message instead. */
    lock_fd = try_lock_private_file_at(dir_fd, ".lock");
    if (lock_fd < 0) {
        bool contended = runtime_lock_is_contended_error(errno);
        close(dir_fd);
        close(parent_fd);
        private_lock_inode_release(anchor_slot);
        if (contended) {
            set_error(ERR_FILE_IO,
                      "Another gitswitch holds the shared runtime lock "
                      "(possibly waiting at a passphrase/PIN prompt); try "
                      "again after that command finishes");
        } else {
            set_system_error(ERR_FILE_IO, "Cannot open shared runtime lock: %s",
                             lock_dir);
        }
        return -1;
    }
    lock_generation = private_lock_latest_generation_for_fd(lock_fd);
    if (lock_generation == 0) {
        unlock_private_file(lock_fd);
        close(dir_fd);
        close(parent_fd);
        private_lock_inode_release(anchor_slot);
        errno = EINVAL;
        set_error(ERR_SYSTEM_CALL,
                  "Shared runtime lock token was not registered");
        return -1;
    }

    /* A same-uid process may have renamed/replaced either path between the
     * opens and the (non-blocking) flock succeeding.  Keep both descriptors
     * pinned for the lock lifetime and refuse an
     * acquisition whose public namespace no longer resolves to those inodes;
     * otherwise a later contender could lock a replacement .lock and enter a
     * supposedly serialized transaction concurrently. */
    struct stat parent_st;
    struct stat parent_path_st;
    struct stat dir_st;
    struct stat dir_entry_st;
    if (fstat(parent_fd, &parent_st) != 0 || fstat(dir_fd, &dir_st) != 0 ||
        runtime_parent_named_stat(runtime_parent, &parent_path_st) != 0 ||
        !same_fs_identity(&parent_st, &parent_path_st) ||
        fstatat(parent_fd, child_name, &dir_entry_st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_fs_identity(&dir_st, &dir_entry_st)) {
        (void)private_lock_release_generation(lock_fd, lock_generation);
        close(dir_fd);
        close(parent_fd);
        private_lock_inode_release(anchor_slot);
        set_error(ERR_PERMISSION_DENIED,
                  "Shared runtime lock namespace changed during acquisition");
        return -1;
    }

    for (size_t i = 0; i < RUNTIME_LOCK_CONTEXTS; i++) {
        if (!g_runtime_locks[i].active) {
            g_runtime_locks[i].active = true;
            g_runtime_locks[i].lock_fd = lock_fd;
            g_runtime_locks[i].lock_generation = lock_generation;
            g_runtime_locks[i].anchor_slot = anchor_slot;
            g_runtime_locks[i].parent_fd = parent_fd;
            g_runtime_locks[i].dir_fd = dir_fd;
            g_runtime_locks[i].parent_dev = parent_st.st_dev;
            g_runtime_locks[i].parent_ino = parent_st.st_ino;
            g_runtime_locks[i].dir_dev = dir_st.st_dev;
            g_runtime_locks[i].dir_ino = dir_st.st_ino;
            safe_strncpy(g_runtime_locks[i].parent_path, runtime_parent,
                         sizeof(g_runtime_locks[i].parent_path));
            safe_strncpy(g_runtime_locks[i].child_name, child_name,
                         sizeof(g_runtime_locks[i].child_name));
            return lock_fd;
        }
    }
    (void)private_lock_release_generation(lock_fd, lock_generation);
    close(dir_fd);
    close(parent_fd);
    private_lock_inode_release(anchor_slot);
    set_error(ERR_SYSTEM_CALL, "Too many nested shared runtime locks");
    return -1;
}

void runtime_state_lock_release(int fd) {
    runtime_lock_prepare_process();
    if (fd >= 0) {
        size_t selected = RUNTIME_LOCK_CONTEXTS;

        for (size_t i = 0; i < RUNTIME_LOCK_CONTEXTS; i++) {
            if (g_runtime_locks[i].active && g_runtime_locks[i].lock_fd == fd &&
                (selected == RUNTIME_LOCK_CONTEXTS ||
                 g_runtime_locks[i].lock_generation <
                     g_runtime_locks[selected].lock_generation)) {
                selected = i;
            }
        }
        if (selected != RUNTIME_LOCK_CONTEXTS) {
            size_t i = selected;

                /* Retained descriptors are deliberately closed only after the
                 * critical section; release also performs a final namespace
                 * check as diagnostic hardening. The void API cannot surface a
                 * late replacement to the caller, but it CAN log it — the old
                 * code computed these four stats and discarded every result, so
                 * the "check" did nothing at all (AR-06 F77). Compare the pinned
                 * (fd) inode against the currently-named (path) inode and warn
                 * if the parent or the locked dir was swapped underneath us. */
                struct stat pinned_parent;
                struct stat named_parent;
                struct stat pinned_dir;
                struct stat named_dir;
                int pinned_parent_rc =
                    runtime_lock_test_consume_release_stat(
                        RUNTIME_LOCK_RELEASE_STAT_PINNED_PARENT)
                        ? -1
                        : fstat(g_runtime_locks[i].parent_fd,
                                &pinned_parent);
                int pinned_parent_errno =
                    pinned_parent_rc == 0 ? 0 : errno;
                int named_parent_rc =
                    runtime_lock_test_consume_release_stat(
                        RUNTIME_LOCK_RELEASE_STAT_NAMED_PARENT)
                        ? -1
                        : runtime_parent_named_stat(
                              g_runtime_locks[i].parent_path, &named_parent);
                int named_parent_errno = named_parent_rc == 0 ? 0 : errno;
                int pinned_dir_rc =
                    runtime_lock_test_consume_release_stat(
                        RUNTIME_LOCK_RELEASE_STAT_PINNED_DIRECTORY)
                        ? -1
                        : fstat(g_runtime_locks[i].dir_fd, &pinned_dir);
                int pinned_dir_errno = pinned_dir_rc == 0 ? 0 : errno;
                int named_dir_rc =
                    runtime_lock_test_consume_release_stat(
                        RUNTIME_LOCK_RELEASE_STAT_NAMED_DIRECTORY)
                        ? -1
                        : fstatat(g_runtime_locks[i].parent_fd,
                                  g_runtime_locks[i].child_name, &named_dir,
                                  AT_SYMLINK_NOFOLLOW);
                int named_dir_errno = named_dir_rc == 0 ? 0 : errno;

                if (pinned_parent_errno != 0) {
                    runtime_lock_warn_stat_failure(
                        "pinned parent", g_runtime_locks[i].parent_path,
                        NULL, pinned_parent_errno);
                }
                if (named_parent_errno != 0) {
                    runtime_lock_warn_stat_failure(
                        "named parent", g_runtime_locks[i].parent_path,
                        NULL, named_parent_errno);
                }
                if (pinned_dir_errno != 0) {
                    runtime_lock_warn_stat_failure(
                        "pinned directory", g_runtime_locks[i].parent_path,
                        g_runtime_locks[i].child_name, pinned_dir_errno);
                }
                if (named_dir_errno != 0) {
                    runtime_lock_warn_stat_failure(
                        "named directory", g_runtime_locks[i].parent_path,
                        g_runtime_locks[i].child_name, named_dir_errno);
                }

                if (pinned_parent_rc == 0 && named_parent_rc == 0 &&
                    !same_fs_identity(&pinned_parent, &named_parent)) {
                    log_warning("runtime lock named parent '%s' was replaced "
                                "during the critical section",
                                g_runtime_locks[i].parent_path);
                }
                if (pinned_dir_rc == 0 && named_dir_rc == 0 &&
                    !same_fs_identity(&pinned_dir, &named_dir)) {
                    log_warning("runtime lock named directory '%s/%s' was "
                                "replaced during the critical section",
                                g_runtime_locks[i].parent_path,
                                g_runtime_locks[i].child_name);
                }
                (void)private_lock_release_generation(
                    fd, g_runtime_locks[i].lock_generation);
                close(g_runtime_locks[i].dir_fd);
                close(g_runtime_locks[i].parent_fd);
                private_lock_inode_release(g_runtime_locks[i].anchor_slot);
                memset(&g_runtime_locks[i], 0, sizeof(g_runtime_locks[i]));
                return;
        }
    }
}

int atomic_symlink(const char *target, const char *linkpath) {
    char tmp[MAX_PATH_LEN];

    if (!target || !linkpath) {
        set_error(ERR_INVALID_ARGS, "NULL args to atomic_symlink");
        return -1;
    }
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp.%d", linkpath, (int)getpid()) >= sizeof(tmp)) {
        set_error(ERR_INVALID_PATH, "Symlink temp path too long");
        return -1;
    }
    unlink(tmp); /* clear any stale temp */
    if (symlink(target, tmp) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to create symlink: %s", linkpath);
        return -1;
    }
    if (rename(tmp, linkpath) != 0) {
        unlink(tmp);
        set_system_error(ERR_FILE_IO, "Failed to install symlink: %s", linkpath);
        return -1;
    }
    return 0;
}

int atomic_symlink_at(int dir_fd, const char *target, const char *link_name) {
    char tmp[MAX_NAME_LEN + 64];

    if (dir_fd < 0 || !target || !link_name || !*link_name ||
        strchr(link_name, '/')) {
        set_error(ERR_INVALID_ARGS, "Invalid atomic symlink arguments");
        return -1;
    }
    if ((size_t)snprintf(tmp, sizeof(tmp), ".%s.tmp.%d", link_name,
                         (int)getpid()) >= sizeof(tmp)) {
        set_error(ERR_INVALID_PATH, "Symlink temp name too long");
        return -1;
    }
    (void)unlinkat(dir_fd, tmp, 0);
    if (symlinkat(target, dir_fd, tmp) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to create symlink: %s", link_name);
        return -1;
    }
    if (renameat(dir_fd, tmp, dir_fd, link_name) != 0) {
        int saved_errno = errno;
        (void)unlinkat(dir_fd, tmp, 0);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to install symlink: %s", link_name);
        return -1;
    }
    return 0;
}

int get_file_permissions(const char *path, mode_t *mode) {
    struct stat st;
    
    if (!path || !mode) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_file_permissions");
        return -1;
    }
    
    if (stat(path, &st) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to stat file: %s", path);
        return -1;
    }
    
    *mode = st.st_mode & 07777; /* Only permission bits */
    return 0;
}

/* File utilities */

enum {
    READ_FILE_TEST_BEFORE_INITIAL_READ = 1,
    READ_FILE_TEST_BEFORE_EXACT_FIT_PROBE
};

#ifdef GITSWITCH_TESTING
typedef void (*read_file_test_hook_fn)(int stage, int file_fd);
read_file_test_hook_fn gitswitch_test_set_read_file_hook(
    read_file_test_hook_fn hook);

static read_file_test_hook_fn g_read_file_test_hook;

read_file_test_hook_fn gitswitch_test_set_read_file_hook(
    read_file_test_hook_fn hook) {
    read_file_test_hook_fn previous = g_read_file_test_hook;
    g_read_file_test_hook = hook;
    return previous;
}

#define READ_FILE_TEST_CHECKPOINT(stage, file) \
    do { \
        if (g_read_file_test_hook) \
            g_read_file_test_hook((stage), fileno(file)); \
    } while (0)
#else
#define READ_FILE_TEST_CHECKPOINT(stage, file) \
    do { (void)(stage); (void)(file); } while (0)
#endif

int read_file_to_string(const char *file_path, char *buffer, size_t buffer_size) {
    FILE *file;
    size_t bytes_read;
    
    if (!file_path || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to read_file_to_string");
        return -1;
    }
    
    /* "e" = O_CLOEXEC on every fopen here: belt-and-braces with the child fd
     * sweep in run_argv, so a file held open across a spawn can never leak
     * into a long-lived git/gpg/ssh child (fd-CLOEXEC finding). */
    file = fopen(file_path, "re");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for reading: %s", file_path);
        return -1;
    }

    READ_FILE_TEST_CHECKPOINT(READ_FILE_TEST_BEFORE_INITIAL_READ, file);
    bytes_read = fread(buffer, 1, buffer_size - 1, file);
    if (ferror(file)) {
        set_system_error(ERR_FILE_IO, "Failed to read from file: %s", file_path);
        fclose(file);
        return -1;
    }

    /* If we filled the buffer, the file MIGHT be exactly buffer_size-1 bytes
     * (a perfect fit) or larger. An EOF flag is not a portable discriminator:
     * stdio may or may not set it while satisfying an exact-size fread. Clear
     * the stream state and perform one real probe: clean EOF means an exact
     * fit, a byte means too large, and ferror means the probe failed. */
    if (bytes_read == buffer_size - 1) {
        int probe;
        int probe_errno;

        /* Some stdio implementations mark EOF while satisfying an exact-size
         * fread. Clear that sticky state so this is a real discriminating
         * read, including when the file grew after the buffered read. */
        clearerr(file);
        READ_FILE_TEST_CHECKPOINT(READ_FILE_TEST_BEFORE_EXACT_FIT_PROBE,
                                  file);
        errno = 0;
        probe = fgetc(file);
        probe_errno = errno;
        if (probe != EOF) {
            set_error(ERR_FILE_IO, "File too large for buffer: %s", file_path);
            fclose(file);
            return -1;
        }
        if (ferror(file)) {
            int saved_errno = probe_errno ? probe_errno : EIO;

            errno = saved_errno;
            set_system_error(ERR_FILE_IO, "Failed to read from file: %s",
                             file_path);
            fclose(file);
            return -1;
        }
    }

    buffer[bytes_read] = '\0';
    fclose(file);

    /* bytes_read <= buffer_size-1, so the cast is safe for any sane buffer. */
    return (int)bytes_read;
}

int write_string_to_file(const char *file_path, const char *content, mode_t mode) {
    FILE *file;
    size_t content_len, bytes_written;
    
    if (!file_path || !content) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to write_string_to_file");
        return -1;
    }
    
    file = fopen(file_path, "we");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for writing: %s", file_path);
        return -1;
    }

    /* Apply the requested mode to the descriptor we actually opened. A
     * pathname chmod after fclose could affect a replacement file instead. */
    if (fchmod(fileno(file), mode) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set permissions on: %s", file_path);
        fclose(file);
        return -1;
    }
    
    content_len = strlen(content);
    bytes_written = fwrite(content, 1, content_len, file);
    
    if (bytes_written != content_len) {
        set_system_error(ERR_FILE_IO, "Failed to write complete content to: %s", file_path);
        fclose(file);
        return -1;
    }
    
    if (fclose(file) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to close file after writing: %s", file_path);
        return -1;
    }

    return 0;
}

#ifdef GITSWITCH_TESTING
typedef void (*copy_file_test_hook_fn)(int stage, const char *dst_path);
copy_file_test_hook_fn gitswitch_test_set_copy_file_hook(
    copy_file_test_hook_fn hook);

static copy_file_test_hook_fn g_copy_file_test_hook;

copy_file_test_hook_fn gitswitch_test_set_copy_file_hook(
    copy_file_test_hook_fn hook) {
    copy_file_test_hook_fn previous = g_copy_file_test_hook;
    g_copy_file_test_hook = hook;
    return previous;
}

#define COPY_FILE_TEST_CHECKPOINT(stage, path) \
    do { \
        if (g_copy_file_test_hook) g_copy_file_test_hook((stage), (path)); \
    } while (0)
#else
#define COPY_FILE_TEST_CHECKPOINT(stage, path) \
    do { (void)(stage); (void)(path); } while (0)
#endif

enum {
    COPY_FILE_TEST_AFTER_DESTINATION_OPEN = 1,
    COPY_FILE_TEST_AFTER_FIRST_WRITE,
    COPY_FILE_TEST_BEFORE_DESTINATION_OPEN
};

static int copy_file_split_destination(const char *path, char **parent_out,
                                       char **leaf_out) {
    const char *slash;
    char *parent = NULL;
    char *leaf = NULL;

    if (!path || !*path || !parent_out || !leaf_out) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        parent = strdup(".");
        leaf = strdup(path);
    } else {
        if (slash[1] == '\0') {
            errno = EINVAL;
            return -1;
        }
        parent = slash == path
                     ? strdup("/")
                     : strndup(path, (size_t)(slash - path));
        leaf = strdup(slash + 1);
    }
    if (!parent || !leaf) {
        int saved_errno = errno ? errno : ENOMEM;
        free(parent);
        free(leaf);
        errno = saved_errno;
        return -1;
    }
    if (!*leaf || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) {
        free(parent);
        free(leaf);
        errno = EINVAL;
        return -1;
    }
    *parent_out = parent;
    *leaf_out = leaf;
    return 0;
}

/* AR-12 P6 (adjudicated, kept as-is): this copies IN PLACE — the
 * destination is truncated before the loop, so a mid-copy failure leaves
 * truncated/partial bytes with the prior content destroyed. Production code
 * does not call this surface (config.c uses its own atomic temp+rename
 * writers); it is retained for tests and external API users, who must
 * treat the destination as expendable on failure. */
int copy_file(const char *src_path, const char *dst_path) {
    FILE *src = NULL;
    FILE *dst = NULL;
    char *dst_parent = NULL;
    char *dst_leaf = NULL;
    char buffer[4096];
    size_t bytes;
    int result = 0;
    int operation_errno = 0;
    int parent_fd = -1;
    int dst_fd = -1;
    int verify_fd = -1;
    int named_parent_fd = -1;
    int dst_flags = O_WRONLY | O_CREAT;
    int parent_flags = O_RDONLY;
    struct stat src_stat;
    struct stat dst_stat;
    struct stat entry_stat;
    struct stat parent_stat;
    struct stat named_parent_stat;
#ifdef GITSWITCH_TESTING
    bool first_write_checkpointed = false;
#endif
    
    if (!src_path || !dst_path || !*dst_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_file");
        return -1;
    }
    if (copy_file_split_destination(dst_path, &dst_parent, &dst_leaf) != 0) {
        if (errno == EINVAL) {
            set_error(ERR_INVALID_ARGS, "Invalid destination path: %s",
                      dst_path);
        } else {
            set_system_error(ERR_MEMORY_ALLOCATION,
                             "Failed to allocate destination path state");
        }
        return -1;
    }
    
    src = fopen(src_path, "rbe");
    if (!src) {
        set_system_error(ERR_FILE_IO, "Failed to open source file: %s", src_path);
        result = -1;
        goto cleanup;
    }
    
    /* Capture metadata from the same source object whose bytes are copied. */
    if (fstat(fileno(src), &src_stat) != 0) {
        int saved_errno = errno;
        (void)fclose(src);
        src = NULL;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to inspect source file: %s", src_path);
        result = -1;
        goto cleanup;
    }

#ifdef O_DIRECTORY
    parent_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    parent_flags |= O_CLOEXEC;
#endif
    parent_fd = open(dst_parent, parent_flags);
    if (parent_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to open destination parent: %s", dst_parent);
        result = -1;
        goto cleanup;
    }
    if (fstat(parent_fd, &parent_stat) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to inspect destination parent: %s",
                         dst_parent);
        result = -1;
        goto cleanup;
    }
    if (!S_ISDIR(parent_stat.st_mode)) {
        errno = ENOTDIR;
        set_system_error(ERR_FILE_IO,
                         "Destination parent is not a directory: %s",
                         dst_parent);
        result = -1;
        goto cleanup;
    }
#ifdef O_CLOEXEC
    dst_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    dst_flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    /* Refuse special nodes without waiting for a FIFO peer or device. The
     * flag is removed after the descriptor is proven to be a regular file. */
    dst_flags |= O_NONBLOCK;
#endif
    COPY_FILE_TEST_CHECKPOINT(COPY_FILE_TEST_BEFORE_DESTINATION_OPEN, dst_path);
    /* A new destination is born private even under umask(000). For an
     * existing destination, the creation mode is ignored, so fchmod the
     * already-open descriptor before fdopen or the first byte write. */
    dst_fd = openat(parent_fd, dst_leaf, dst_flags, 0600);
    if (dst_fd < 0) {
        int saved_errno = errno;
        errno = saved_errno;
        if (saved_errno == ELOOP
#if defined(__FreeBSD__)
            /* FreeBSD deliberately reports EMLINK for a final symlink rejected
             * by O_NOFOLLOW; POSIX and the other supported hosts use ELOOP. */
            || saved_errno == EMLINK
#endif
        ) {
            set_error(ERR_INVALID_ARGS,
                      "Refusing symlink destination: %s", dst_path);
        } else {
            set_system_error(ERR_FILE_IO,
                             "Failed to open destination file: %s",
                             dst_path);
        }
        result = -1;
        goto cleanup;
    }
#ifndef O_CLOEXEC
    {
        int fd_flags = fcntl(dst_fd, F_GETFD);
        if (fd_flags < 0 ||
            fcntl(dst_fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Failed to secure destination descriptor: %s",
                             dst_path);
            result = -1;
            goto cleanup;
        }
    }
#endif
    if (fstat(dst_fd, &dst_stat) != 0) {
        int saved_errno = errno;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to inspect destination file: %s",
                         dst_path);
        result = -1;
        goto cleanup;
    }
    if (!S_ISREG(dst_stat.st_mode)) {
        errno = EINVAL;
        set_system_error(ERR_FILE_IO,
                         "Destination is not a regular file: %s", dst_path);
        result = -1;
        goto cleanup;
    }
#ifdef O_NONBLOCK
    {
        int status_flags = fcntl(dst_fd, F_GETFL);
        if (status_flags < 0 ||
            fcntl(dst_fd, F_SETFL, status_flags & ~O_NONBLOCK) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to normalize destination descriptor: %s",
                             dst_path);
            result = -1;
            goto cleanup;
        }
    }
#endif
    if (fstatat(parent_fd, dst_leaf, &entry_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to re-inspect destination: %s", dst_path);
        result = -1;
        goto cleanup;
    }
    if (!S_ISREG(entry_stat.st_mode) ||
        !same_fs_identity(&dst_stat, &entry_stat)) {
        errno = !S_ISREG(entry_stat.st_mode) ? EINVAL : EAGAIN;
        set_system_error(ERR_FILE_IO,
                         "Destination changed while being opened: %s",
                         dst_path);
        result = -1;
        goto cleanup;
    }
    if (src_stat.st_dev == dst_stat.st_dev &&
        src_stat.st_ino == dst_stat.st_ino) {
        set_error(ERR_INVALID_ARGS,
                  "Source and destination refer to the same file");
        result = -1;
        goto cleanup;
    }
    verify_fd = dup_cloexec(dst_fd, 0);
    if (verify_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to retain destination identity: %s",
                         dst_path);
        result = -1;
        goto cleanup;
    }
    if (ftruncate(dst_fd, 0) != 0) {
        int saved_errno = errno;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to truncate destination file: %s", dst_path);
        result = -1;
        goto cleanup;
    }
    COPY_FILE_TEST_CHECKPOINT(COPY_FILE_TEST_AFTER_DESTINATION_OPEN, dst_path);
    if (fchmod(dst_fd, src_stat.st_mode & 0777) != 0) {
        int saved_errno = errno;
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to set destination permissions: %s", dst_path);
        result = -1;
        goto cleanup;
    }
    dst = fdopen(dst_fd, "wb");
    if (!dst) {
        int saved_errno = errno;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to open destination stream: %s", dst_path);
        result = -1;
        goto cleanup;
    }
    dst_fd = -1; /* fdopen owns it from here. */

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            int saved_errno = errno ? errno : EIO;
            errno = saved_errno;
            set_system_error(ERR_FILE_IO, "Failed to write to destination file: %s", dst_path);
            result = -1;
            operation_errno = saved_errno;
            break;
        }
#ifdef GITSWITCH_TESTING
        if (!first_write_checkpointed) {
            if (fflush(dst) != 0) {
                int saved_errno = errno ? errno : EIO;
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Failed to flush destination file: %s",
                                 dst_path);
                result = -1;
                operation_errno = saved_errno;
                break;
            }
            COPY_FILE_TEST_CHECKPOINT(COPY_FILE_TEST_AFTER_FIRST_WRITE,
                                      dst_path);
            first_write_checkpointed = true;
        }
#endif
    }
    
    if (ferror(src) && result == 0) {
        int saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Error reading source file: %s", src_path);
        result = -1;
        operation_errno = saved_errno;
    }

    if (result == 0 && fflush(dst) != 0) {
        int saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to flush destination file: %s", dst_path);
        result = -1;
        operation_errno = saved_errno;
    }

    if (fclose(src) != 0 && result == 0) {
        int saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to close source file: %s", src_path);
        result = -1;
        operation_errno = saved_errno;
    }
    src = NULL;
    if (fclose(dst) != 0 && result == 0) {
        int saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO, "Failed to close destination file: %s", dst_path);
        result = -1;
        operation_errno = saved_errno;
    }
    dst = NULL;
    if (result != 0 && operation_errno != 0) errno = operation_errno;

    if (result == 0 && fstat(verify_fd, &dst_stat) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to verify copied destination: %s", dst_path);
        result = -1;
    }
    if (result == 0) {
        named_parent_fd = open(dst_parent, parent_flags);
        if (named_parent_fd < 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to reopen destination parent: %s",
                             dst_parent);
            result = -1;
        }
    }
    if (result == 0 && fstat(named_parent_fd, &named_parent_stat) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to verify destination parent: %s",
                         dst_parent);
        result = -1;
    }
    if (result == 0 &&
        !same_fs_identity(&parent_stat, &named_parent_stat)) {
        errno = EAGAIN;
        set_system_error(ERR_FILE_IO,
                         "Destination parent changed during copy: %s",
                         dst_parent);
        result = -1;
    }
    if (result == 0 &&
        fstatat(named_parent_fd, dst_leaf, &entry_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to verify published destination: %s",
                         dst_path);
        result = -1;
    }
    if (result == 0 &&
        (!S_ISREG(entry_stat.st_mode) ||
         !same_fs_identity(&dst_stat, &entry_stat))) {
        errno = !S_ISREG(entry_stat.st_mode) ? EINVAL : EAGAIN;
        set_system_error(ERR_FILE_IO,
                         "Destination path changed during copy: %s",
                         dst_path);
        result = -1;
    }

cleanup: {
        int saved_errno = errno;
        if (dst) (void)fclose(dst);
        else if (dst_fd >= 0) close(dst_fd);
        if (src) (void)fclose(src);
        if (verify_fd >= 0) close(verify_fd);
        if (named_parent_fd >= 0) close(named_parent_fd);
        if (parent_fd >= 0) close(parent_fd);
        free(dst_parent);
        free(dst_leaf);
        errno = saved_errno;
        return result;
    }
}

int backup_file(const char *file_path, const char *backup_suffix) {
    char backup_path[MAX_PATH_LEN];
    
    if (!file_path || !backup_suffix) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to backup_file");
        return -1;
    }
    
    if ((size_t)snprintf(backup_path, sizeof(backup_path), "%s%s", 
                        file_path, backup_suffix) >= sizeof(backup_path)) {
        set_error(ERR_INVALID_ARGS, "Backup path too long");
        return -1;
    }
    
    return copy_file(file_path, backup_path);
}

bool file_is_readable(const char *file_path) {
    return file_path && access(file_path, R_OK) == 0; /* Flawfinder: ignore — advisory readability probe, not an auth decision */
}

bool file_is_writable(const char *file_path) {
    return file_path && access(file_path, W_OK) == 0; /* Flawfinder: ignore — advisory writability probe, not an auth decision */
}

size_t get_file_size(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return (size_t)st.st_size;
}

time_t get_file_mtime(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return st.st_mtime;
}

/* Process utilities */

/* ---- Shell-free subprocess execution -------------------------------------
 *
 * run_argv_real spawns argv[0] via fork plus verified executable launch (no
 * shell) with optional
 * stdin input, stdout capture, extra environment, and stderr policy. I/O is
 * driven by poll() so an input+output pair cannot deadlock regardless of
 * payload size. The real child exit code is reported via WEXITSTATUS. */

static int open_trusted_command(const char *name, char *resolved,
                                size_t resolved_size,
                                struct stat *file_stat);
static int exec_open_canonical(const char *canonical,
                               struct stat *file_stat);

static bool exec_stat_identity_matches(const struct stat *expected,
                                       const struct stat *observed) {
    if (!expected || !observed ||
        expected->st_dev != observed->st_dev ||
        expected->st_ino != observed->st_ino ||
        expected->st_uid != observed->st_uid ||
        expected->st_gid != observed->st_gid ||
        expected->st_mode != observed->st_mode ||
        expected->st_size != observed->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return expected->st_mtimespec.tv_sec == observed->st_mtimespec.tv_sec &&
           expected->st_mtimespec.tv_nsec == observed->st_mtimespec.tv_nsec &&
           expected->st_ctimespec.tv_sec == observed->st_ctimespec.tv_sec &&
           expected->st_ctimespec.tv_nsec == observed->st_ctimespec.tv_nsec;
#else
    return expected->st_mtim.tv_sec == observed->st_mtim.tv_sec &&
           expected->st_mtim.tv_nsec == observed->st_mtim.tv_nsec &&
           expected->st_ctim.tv_sec == observed->st_ctim.tv_sec &&
           expected->st_ctim.tv_nsec == observed->st_ctim.tv_nsec;
#endif
}

/* Reserve low child slots for status (3), the executable/script (4), and a
 * script interpreter (5). Parent launch pins live at >=6 so stdio repair and
 * the final dup2 layout cannot clobber them. */
static int exec_fd_at_least(int fd, int minimum) {
    if (fd < 0) return -1;
    if (fd >= minimum) return fd;

#ifdef F_DUPFD_CLOEXEC
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, minimum);
#else
    int moved = fcntl(fd, F_DUPFD, minimum);
    if (moved >= 0 && fcntl(moved, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(moved);
        errno = saved_errno;
        moved = -1;
    }
#endif
    if (moved >= 0) close(fd);
    return moved;
}

#define EXEC_SHEBANG_LIMIT 256

#ifdef GITSWITCH_TESTING
static unsigned int g_test_exec_parse_failure_ordinal;
static unsigned int g_test_exec_parse_call_count;
static int g_test_exec_parse_failure_errno;
#endif

typedef enum {
    EXEC_FORMAT_UNKNOWN = 0,
    EXEC_FORMAT_BINARY,
    EXEC_FORMAT_SCRIPT
} exec_format_t;

typedef struct {
    bool is_script;
    int interpreter_fd;
    struct stat interpreter_identity;
    char interpreter_path[MAX_PATH_LEN];
    char interpreter_argv0[EXEC_SHEBANG_LIMIT];
    char interpreter_arg[EXEC_SHEBANG_LIMIT];
    bool has_interpreter_arg;
    char script_fd_path[32];
    char **script_argv;
} trusted_script_launch_t;

static bool exec_prefix_is_binary(const unsigned char *prefix, size_t size) {
    static const unsigned char magics[][4] = {
        {0x7f, 'E', 'L', 'F'}, /* ELF: Linux and FreeBSD */
        {0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
        {0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
        {0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
        {0xca, 0xfe, 0xba, 0xbf}, {0xbf, 0xba, 0xfe, 0xca}
    };
    if (!prefix || size < 4) return false;
    for (size_t i = 0; i < sizeof(magics) / sizeof(magics[0]); i++) {
        if (memcmp(prefix, magics[i], sizeof(magics[i])) == 0) return true;
    }
    return false;
}

static int exec_parse_format(int fd, exec_format_t *format,
                             char *interpreter, size_t interpreter_size,
                             char *argument, size_t argument_size,
                             bool *has_argument) {
    unsigned char prefix[EXEC_SHEBANG_LIMIT + 1];
    ssize_t got;
#ifdef GITSWITCH_TESTING
    g_test_exec_parse_call_count++;
    if (g_test_exec_parse_failure_errno != 0 &&
        g_test_exec_parse_call_count == g_test_exec_parse_failure_ordinal) {
        int injected_errno = g_test_exec_parse_failure_errno;
        g_test_exec_parse_failure_errno = 0;
        g_test_exec_parse_failure_ordinal = 0;
        errno = injected_errno;
        return -1;
    }
#endif
    do {
        got = pread(fd, prefix, sizeof(prefix), 0);
    } while (got < 0 && errno == EINTR);
    if (got < 0) return -1;

    size_t size = (size_t)got;
    if (exec_prefix_is_binary(prefix, size)) {
        *format = EXEC_FORMAT_BINARY;
        return 0;
    }
    if (size < 2 || prefix[0] != '#' || prefix[1] != '!') {
        errno = ENOEXEC;
        return -1;
    }

    size_t line_end = 2;
    while (line_end < size && prefix[line_end] != '\n') line_end++;
    if (line_end == size && size == sizeof(prefix)) {
        errno = E2BIG;
        return -1;
    }
    for (size_t i = 2; i < line_end; i++) {
        /* A NUL would truncate the C pathname after validation; other ASCII
         * controls have no portable shebang meaning.  Permit only the two
         * whitespace delimiters handled explicitly below. */
        if ((prefix[i] < ' ' && prefix[i] != '\t') || prefix[i] == 0x7f) {
            errno = EINVAL;
            return -1;
        }
    }
    while (line_end > 2 &&
           (prefix[line_end - 1] == ' ' || prefix[line_end - 1] == '\t')) {
        line_end--;
    }
    if (line_end > 2 && prefix[line_end - 1] == '\r') {
        errno = EINVAL;
        return -1;
    }

    size_t cursor = 2;
    while (cursor < line_end &&
           (prefix[cursor] == ' ' || prefix[cursor] == '\t')) {
        cursor++;
    }
    size_t start = cursor;
    while (cursor < line_end && prefix[cursor] != ' ' &&
           prefix[cursor] != '\t' && prefix[cursor] != '\r') {
        cursor++;
    }
    size_t length = cursor - start;
    if (length == 0 || prefix[start] != '/' ||
        length >= interpreter_size) {
        errno = EINVAL;
        return -1;
    }
    memcpy(interpreter, prefix + start, length);
    interpreter[length] = '\0';

    const char *base = strrchr(interpreter, '/');
    if (base && strcmp(base + 1, "env") == 0) {
        errno = EPERM;
        return -1;
    }

    while (cursor < line_end &&
           (prefix[cursor] == ' ' || prefix[cursor] == '\t')) {
        cursor++;
    }
    *has_argument = cursor < line_end;
    if (*has_argument) {
        start = cursor;
        while (cursor < line_end && prefix[cursor] != ' ' &&
               prefix[cursor] != '\t' && prefix[cursor] != '\r') {
            cursor++;
        }
        length = cursor - start;
        while (cursor < line_end &&
               (prefix[cursor] == ' ' || prefix[cursor] == '\t')) {
            cursor++;
        }
        if (length == 0 || length >= argument_size || cursor != line_end) {
            errno = EINVAL;
            return -1;
        }
        memcpy(argument, prefix + start, length);
        argument[length] = '\0';
    } else if (argument_size > 0) {
        argument[0] = '\0';
    }
    *format = EXEC_FORMAT_SCRIPT;
    return 0;
}

static void trusted_script_launch_cleanup(trusted_script_launch_t *launch) {
    if (!launch) return;
    if (launch->interpreter_fd >= 0) close(launch->interpreter_fd);
    free(launch->script_argv);
    launch->interpreter_fd = -1;
    launch->script_argv = NULL;
}

static int prepare_trusted_script_launch(
    int exec_fd, const char *const argv[], trusted_script_launch_t *launch) {
    exec_format_t format = EXEC_FORMAT_UNKNOWN;
    memset(launch, 0, sizeof(*launch));
    launch->interpreter_fd = -1;
    if (exec_parse_format(exec_fd, &format, launch->interpreter_argv0,
                          sizeof(launch->interpreter_argv0),
                          launch->interpreter_arg,
                          sizeof(launch->interpreter_arg),
                          &launch->has_interpreter_arg) != 0) {
        return -1;
    }
    if (format == EXEC_FORMAT_BINARY) return 0;

    launch->interpreter_fd = open_trusted_command(
        launch->interpreter_argv0, launch->interpreter_path,
        sizeof(launch->interpreter_path), &launch->interpreter_identity);
    if (launch->interpreter_fd < 0) return -1;

    /* Also apply the env ban after canonicalization so a trusted symlink such
     * as /private/bin/sh -> /usr/bin/env cannot reintroduce a PATH lookup. */
    const char *canonical_base = strrchr(launch->interpreter_path, '/');
    if (canonical_base && strcmp(canonical_base + 1, "env") == 0) {
        trusted_script_launch_cleanup(launch);
        errno = EPERM;
        return -1;
    }

    exec_format_t interpreter_format = EXEC_FORMAT_UNKNOWN;
    char unused_interpreter[EXEC_SHEBANG_LIMIT];
    char unused_argument[EXEC_SHEBANG_LIMIT];
    bool unused_has_argument = false;
    if (exec_parse_format(launch->interpreter_fd, &interpreter_format,
                          unused_interpreter, sizeof(unused_interpreter),
                          unused_argument, sizeof(unused_argument),
                          &unused_has_argument) != 0) {
        int parse_errno = errno;
        trusted_script_launch_cleanup(launch);
        errno = parse_errno;
        return -1;
    }
    if (interpreter_format != EXEC_FORMAT_BINARY) {
        trusted_script_launch_cleanup(launch);
        errno = ENOEXEC;
        return -1;
    }

#if defined(__linux__)
    const char *fd_path = "/proc/self/fd/4";
#elif defined(__FreeBSD__) || defined(__APPLE__)
    const char *fd_path = "/dev/fd/4";
#else
    trusted_script_launch_cleanup(launch);
    errno = ENOTSUP;
    return -1;
#endif
    if (safe_strncpy(launch->script_fd_path, fd_path,
                     sizeof(launch->script_fd_path)) != 0) {
        trusted_script_launch_cleanup(launch);
        errno = ENAMETOOLONG;
        return -1;
    }

    size_t original_argc = 0;
    while (argv[original_argc]) {
        if (original_argc > SIZE_MAX - 5) {
            trusted_script_launch_cleanup(launch);
            errno = E2BIG;
            return -1;
        }
        original_argc++;
    }
    size_t capacity = original_argc + 4;
    launch->script_argv = calloc(capacity, sizeof(*launch->script_argv));
    if (!launch->script_argv) {
        trusted_script_launch_cleanup(launch);
        return -1;
    }
    size_t out = 0;
    launch->script_argv[out++] = launch->interpreter_argv0;
    if (launch->has_interpreter_arg) {
        launch->script_argv[out++] = launch->interpreter_arg;
    }
    launch->script_argv[out++] = launch->script_fd_path;
    for (size_t i = 1; i < original_argc; i++) {
        launch->script_argv[out++] = (char *)argv[i];
    }
    launch->script_argv[out] = NULL;
    launch->is_script = true;
    return 0;
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl == -1) return -1;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) return -1;
    return 0;
}

typedef struct {
    int *fds;
    size_t count;
    bool complete;
} child_fd_snapshot_t;

/* The runner's descriptors must never occupy 0/1/2 in the parent.  A caller is
 * allowed to start with one of those slots closed; keeping our bookkeeping
 * descriptors above stderr prevents the child-side stdio dup2 operations from
 * accidentally overwriting the setup-status channel. */
static int internal_fd_above_stdio(int fd) {
    if (fd < 0) return -1;

    if (fd <= STDERR_FILENO) {
#ifdef F_DUPFD_CLOEXEC
        int moved = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
#else
        int moved = fcntl(fd, F_DUPFD, STDERR_FILENO + 1);
        if (moved >= 0 && fcntl(moved, F_SETFD, FD_CLOEXEC) != 0) {
            int saved = errno;
            close(moved);
            errno = saved;
            moved = -1;
        }
#endif
        if (moved < 0) return -1;
        close(fd);
        return moved;
    }

    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    return fd;
}

static int make_internal_pipe(int pipefd[2]) {
    int raw[2] = {-1, -1};
    if (pipe(raw) != 0) return -1;

    int first = internal_fd_above_stdio(raw[0]);
    if (first < 0) {
        int saved = errno;
        close(raw[0]);
        close(raw[1]);
        errno = saved;
        return -1;
    }
    raw[0] = -1;

    int second = internal_fd_above_stdio(raw[1]);
    if (second < 0) {
        int saved = errno;
        close(first);
        close(raw[1]);
        errno = saved;
        return -1;
    }

    pipefd[0] = first;
    pipefd[1] = second;
    return 0;
}

static int open_internal_devnull(void) {
    int flags = O_RDWR;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open("/dev/null", flags);
    if (fd < 0) return -1;

    int moved = internal_fd_above_stdio(fd);
    if (moved < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return moved;
}

/* On platforms without a close-range primitive, enumerate the descriptors
 * that are actually open before fork.  The child can then close O(open-fds)
 * entries rather than issuing one syscall for every value below OPEN_MAX.
 * Allocation and directory traversal intentionally happen in the parent. */
static child_fd_snapshot_t child_fd_snapshot_capture(void) {
    child_fd_snapshot_t snapshot = {0};
    const char *paths[] = {"/proc/self/fd", "/dev/fd", NULL};
    DIR *dir = NULL;

    for (size_t i = 0; paths[i]; i++) {
        dir = opendir(paths[i]);
        if (dir) break;
    }
    if (!dir) return snapshot;

    size_t capacity = 16;
    snapshot.fds = malloc(capacity * sizeof(*snapshot.fds));
    if (!snapshot.fds) {
        closedir(dir);
        return snapshot;
    }

    int scan_fd = dirfd(dir);
    struct dirent *entry;
    int scan_errno = 0;
    for (;;) {
        /* POSIX distinguishes end-of-directory from failure through errno.
         * Reset it immediately before readdir; strtol below also uses errno. */
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            scan_errno = errno;
            break;
        }
        char *end = NULL;
        errno = 0;
        long value = strtol(entry->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' || value < 3 ||
            value > INT_MAX || value == scan_fd) {
            continue;
        }
        if (snapshot.count == capacity) {
            size_t next_capacity = capacity * 2;
            int *next = realloc(snapshot.fds,
                                next_capacity * sizeof(*snapshot.fds));
            if (!next) {
                free(snapshot.fds);
                snapshot.fds = NULL;
                snapshot.count = 0;
                closedir(dir);
                return snapshot;
            }
            snapshot.fds = next;
            capacity = next_capacity;
        }
        snapshot.fds[snapshot.count++] = (int)value;
    }
    snapshot.complete = (scan_errno == 0);
    closedir(dir);
    return snapshot;
}

static bool child_bulk_close_available(void) {
#if defined(__linux__) && defined(SYS_close_range)
    /* Probe without touching the descriptor table: a supported syscall rejects
     * the reversed range with EINVAL; old kernels report ENOSYS. */
    errno = 0;
    if (syscall(SYS_close_range, 1U, 0U, 0U) < 0 && errno == ENOSYS) {
        return false;
    }
    return errno == EINVAL;
#elif defined(__FreeBSD__)
    return true;
#else
    return false;
#endif
}

/* Test-only strategy/observation seam.  Zero-initialized AUTO with observation
 * disabled is the sole production mode, so normal callers neither emit nor
 * consume the extra pre-exec status record. */
static run_test_fd_close_strategy_t g_test_fd_close_strategy =
    RUN_TEST_FD_CLOSE_AUTO;
static bool g_test_fd_close_observation_enabled;
static bool g_test_fd_close_observation_valid;
static run_test_fd_close_observation_t g_test_fd_close_observation;
static int g_test_bulk_close_failure_errno;
static bool g_test_auto_bulk_close_unavailable;
static run_test_exec_resolved_hook_fn g_test_exec_resolved_hook;
static run_test_post_fork_pre_publish_hook_fn
    g_test_post_fork_pre_publish_hook;
static int g_test_fork_failure_errno;
#ifdef GITSWITCH_TESTING
static unsigned int g_test_path_candidate_failure_ordinal;
static int g_test_path_candidate_failure_errno;
static unsigned int g_test_directory_open_failure_ordinal;
static unsigned int g_test_directory_open_call_count;
static int g_test_directory_open_failure_errno;
static int g_test_exec_acl_failure_target;
static int g_test_exec_acl_failure_errno;
#endif

/* A pipe write has no portable per-call "do not generate SIGPIPE" flag.
 * Follow the POSIX thread-mask pattern instead: block only for actual stdin
 * writes, temporarily consume any caller-owned pending instance, consume the
 * runner-generated instance after EPIPE, then re-raise the caller's instance
 * while it is still blocked. The explicit remove/restore is necessary on
 * kernels which retain the two standard-signal instances separately; merely
 * remembering that SIGPIPE was already pending can leak the generated instance
 * back to the caller. The process-wide disposition is never changed. */
typedef struct {
    bool active;
    bool initially_pending;
    bool saw_epipe;
    sigset_t set;
    sigset_t saved_mask;
} run_sigpipe_state_t;

static int run_sigpipe_begin(run_sigpipe_state_t *state) {
    sigset_t pending;
    int consumed_signal = 0;
    int wait_error;

    memset(state, 0, sizeof(*state));
    if (sigemptyset(&state->set) != 0 ||
        sigaddset(&state->set, SIGPIPE) != 0) {
        return -1;
    }
    if (sigprocmask(SIG_BLOCK, &state->set, &state->saved_mask) != 0) {
        return -1;
    }
    state->active = true;
    if (sigpending(&pending) != 0) {
        int pending_errno = errno;
        (void)sigprocmask(SIG_SETMASK, &state->saved_mask, NULL);
        state->active = false;
        errno = pending_errno;
        return -1;
    }
    state->initially_pending = sigismember(&pending, SIGPIPE) == 1;
    if (state->initially_pending) {
        do {
            wait_error = sigwait(&state->set, &consumed_signal);
        } while (wait_error == EINTR);
        if (wait_error != 0 || consumed_signal != SIGPIPE) {
            int consume_errno = wait_error != 0 ? wait_error : EIO;
            (void)sigprocmask(SIG_SETMASK, &state->saved_mask, NULL);
            state->active = false;
            errno = consume_errno;
            return -1;
        }
    }
    return 0;
}

static int run_sigpipe_end(run_sigpipe_state_t *state) {
    int entry_errno = errno;
    int consume_errno = 0;
    int restore_pending_errno = 0;

    if (!state->active) return 0;
    if (state->saw_epipe) {
        sigset_t pending;

        /* macOS has sigwait() but no sigtimedwait(). Check the blocked set
         * first so the portable wait cannot block when an ignored SIGPIPE was
         * discarded instead of becoming pending. */
        if (sigpending(&pending) != 0) {
            consume_errno = errno;
        } else {
            int pending_member = sigismember(&pending, SIGPIPE);

            if (pending_member < 0) {
                consume_errno = errno;
            } else if (pending_member == 1) {
                int consumed_signal = 0;
                int wait_error;

                do {
                    wait_error = sigwait(&state->set, &consumed_signal);
                } while (wait_error == EINTR);
                if (wait_error != 0) {
                    consume_errno = wait_error;
                } else if (consumed_signal != SIGPIPE) {
                    consume_errno = EIO;
                }
            }
        }
    }
    if (state->initially_pending) {
        sigset_t pending;

        if (raise(SIGPIPE) != 0) {
            restore_pending_errno = errno;
        } else if (sigpending(&pending) != 0) {
            restore_pending_errno = errno;
        } else {
            int pending_member = sigismember(&pending, SIGPIPE);
            if (pending_member != 1) {
                restore_pending_errno = pending_member < 0 ? errno : EIO;
            }
        }
    }
    if (sigprocmask(SIG_SETMASK, &state->saved_mask, NULL) != 0) {
        int restore_errno = errno;
        state->active = false;
        errno = restore_errno;
        return -1;
    }
    state->active = false;
    if (consume_errno != 0) {
        errno = consume_errno;
        return -1;
    }
    if (restore_pending_errno != 0) {
        errno = restore_pending_errno;
        return -1;
    }
    errno = entry_errno;
    return 0;
}

static void report_secondary_runner_cleanup_failure(
    const char *operation, int cleanup_errno) {
    if (!operation || cleanup_errno <= 0) return;

    int primary_errno = errno;
    error_context_t primary_error = g_last_error;
    log_warning("run_argv: secondary cleanup failure %s "
                "(errno=%d: %s)",
                operation, cleanup_errno, strerror(cleanup_errno));
    g_last_error = primary_error;
    errno = primary_errno;
}

static void report_secondary_signal_cleanup_failures(
    int sigpipe_errno, int wait_ownership_errno) {
    report_secondary_runner_cleanup_failure(
        "while restoring the subprocess SIGPIPE state", sigpipe_errno);
    report_secondary_runner_cleanup_failure(
        "while restoring SIGCHLD wait ownership", wait_ownership_errno);
}

int run_test_set_fd_close_strategy(run_test_fd_close_strategy_t strategy) {
    switch (strategy) {
        case RUN_TEST_FD_CLOSE_AUTO:
        case RUN_TEST_FD_CLOSE_SNAPSHOT:
        case RUN_TEST_FD_CLOSE_NUMERIC:
        case RUN_TEST_FD_CLOSE_BULK:
            g_test_fd_close_strategy = strategy;
            return 0;
        default:
            errno = EINVAL;
            return -1;
    }
}

bool run_test_fd_close_bulk_supported(void) {
    return child_bulk_close_available();
}

void run_test_set_fd_close_observation(bool enabled) {
    g_test_fd_close_observation_enabled = enabled;
    g_test_fd_close_observation_valid = false;
    memset(&g_test_fd_close_observation, 0,
           sizeof(g_test_fd_close_observation));
}

bool run_test_get_fd_close_observation(
    run_test_fd_close_observation_t *out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    if (!g_test_fd_close_observation_valid) return false;
    *out = g_test_fd_close_observation;
    return true;
}

void run_test_set_bulk_close_failure(int system_errno) {
    g_test_bulk_close_failure_errno = system_errno > 0 ? system_errno : 0;
}

void run_test_set_auto_bulk_close_unavailable(bool unavailable) {
    g_test_auto_bulk_close_unavailable = unavailable;
}

void run_test_set_exec_resolved_hook(run_test_exec_resolved_hook_fn hook) {
    g_test_exec_resolved_hook = hook;
}

void run_test_set_post_fork_pre_publish_hook(
    run_test_post_fork_pre_publish_hook_fn hook) {
    g_test_post_fork_pre_publish_hook = hook;
}

void run_test_set_fork_failure(int system_errno) {
    g_test_fork_failure_errno = system_errno > 0 ? system_errno : 0;
}

#ifdef GITSWITCH_TESTING
void run_test_set_exec_parse_failure(unsigned int parse_ordinal,
                                     int system_errno) {
    g_test_exec_parse_failure_ordinal =
        system_errno > 0 ? parse_ordinal : 0;
    g_test_exec_parse_call_count = 0;
    g_test_exec_parse_failure_errno = system_errno > 0 ? system_errno : 0;
}

void run_test_set_path_candidate_failure(unsigned int candidate_ordinal,
                                         int system_errno) {
    g_test_path_candidate_failure_ordinal =
        system_errno > 0 ? candidate_ordinal : 0;
    g_test_path_candidate_failure_errno =
        system_errno > 0 ? system_errno : 0;
}

void run_test_set_directory_open_failure(unsigned int open_ordinal,
                                         int system_errno) {
    g_test_directory_open_failure_ordinal =
        system_errno > 0 ? open_ordinal : 0;
    g_test_directory_open_call_count = 0;
    g_test_directory_open_failure_errno =
        system_errno > 0 ? system_errno : 0;
}

void run_test_set_exec_acl_failure(run_test_exec_acl_target_t target,
                                   int system_errno) {
    bool enabled =
        system_errno > 0 &&
        (target == RUN_TEST_EXEC_ACL_DIRECTORY ||
         target == RUN_TEST_EXEC_ACL_LEAF);
    g_test_exec_acl_failure_target = enabled ? (int)target : 0;
    g_test_exec_acl_failure_errno = enabled ? system_errno : 0;
}
#endif

/* Close every descriptor >= lowfd in the forked child before exec (fd-CLOEXEC).
 * Without this, any fd the parent left open without O_CLOEXEC — a config or
 * backup FILE*, the isolated-home lock, a stray dup — leaks into every git/
 * gpg/ssh child, where a long-lived agent could hold it (and whatever it
 * guards) open indefinitely. Runs post-fork, pre-exec, so only plain syscalls
 * are used.  `snapshot` was collected in the parent and supplies either the
 * portable AUTO path or the strict test-selected snapshot path. */
static int child_close_fds_from(
    int lowfd, bool use_bulk_close, bool require_bulk_close,
    const child_fd_snapshot_t *snapshot,
    run_test_fd_close_observation_t *observation) {
    memset(observation, 0, sizeof(*observation));

    if (use_bulk_close) {
        observation->method = RUN_TEST_FD_METHOD_BULK;
        if (g_test_bulk_close_failure_errno != 0) {
            errno = g_test_bulk_close_failure_errno;
            if (require_bulk_close) return -1;
        } else {
#if defined(__linux__) && defined(SYS_close_range)
            /* close_range(2) is Linux >= 5.9. Invoke via syscall(): the libc
             * wrapper only exists in glibc >= 2.34, and newer headers with an
             * older runtime kernel are common. */
            observation->close_syscalls++;
            if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U, 0U) == 0) {
                return 0;
            }
            if (require_bulk_close) return -1;
#elif defined(__FreeBSD__)
            /* FreeBSD has closefrom(2) since 8.0, well before our 14.4 floor.
             * Its void return means completing the call is success. */
            observation->close_syscalls++;
            closefrom(lowfd);
            return 0;
#else
            errno = ENOTSUP;
            if (require_bulk_close) return -1;
#endif
        }
    }

    if (snapshot && snapshot->complete) {
        observation->method = RUN_TEST_FD_METHOD_SNAPSHOT;
        for (size_t i = 0; i < snapshot->count; i++) {
            if (snapshot->fds[i] >= lowfd) {
                observation->close_syscalls++;
                (void)close(snapshot->fds[i]);
            }
        }
        return 0;
    }

    /* Portable fallback (macOS has neither call): close(2) on an unused fd is
     * harmless (EBADF). Cap the sweep — sysconf can report "unlimited" or a
     * raised RLIMIT_NOFILE in the millions, and this runs on every spawn. */
    observation->method = RUN_TEST_FD_METHOD_NUMERIC;
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) {
        maxfd = 65536;
    }
    for (long fd = lowfd; fd < maxfd; fd++) {
        observation->close_syscalls++;
        (void)close((int)fd);
    }
    return 0;
}

typedef enum {
    CHILD_STAGE_STDIO = 1,
    CHILD_STAGE_CWD,
    CHILD_STAGE_FD_CLOSE,
    CHILD_STAGE_ENV,
    CHILD_STAGE_EXEC
} child_stage_t;

typedef enum {
    CHILD_STATUS_FAILURE = 1,
    CHILD_STATUS_FD_CLOSE_OBSERVATION
} child_status_kind_t;

typedef struct {
    int kind;
    int stage;
    int system_errno;
    int fd_close_method;
    uint64_t fd_close_syscalls;
} child_status_t;

static int child_write_status(int status_fd, const child_status_t *status) {
    const char *bytes = (const char *)status;
    size_t offset = 0;
    while (offset < sizeof(*status)) {
        ssize_t written = write(status_fd, bytes + offset,
                                sizeof(*status) - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void child_report_failure(int status_fd, child_stage_t stage,
                                 int system_errno, int exit_code) {
    child_status_t status = {
        .kind = CHILD_STATUS_FAILURE,
        .stage = (int)stage,
        .system_errno = system_errno
    };
    (void)child_write_status(status_fd, &status);
    _exit(exit_code);
}

static int child_report_fd_close_observation(
    int status_fd, const run_test_fd_close_observation_t *observation) {
    child_status_t status = {
        .kind = CHILD_STATUS_FD_CLOSE_OBSERVATION,
        .fd_close_method = (int)observation->method,
        .fd_close_syscalls = observation->close_syscalls
    };
    return child_write_status(status_fd, &status);
}

/* Returns 0 for the CLOEXEC EOF that proves exec succeeded, 1 for a complete
 * child failure report, and -1 for a malformed/failed status read.  Optional
 * observation messages can precede either EOF or a later setup failure. */
static int read_child_status(
    int fd, child_status_t *failure,
    run_test_fd_close_observation_t *observation, bool *observation_valid) {
    *observation_valid = false;
    for (;;) {
        child_status_t status = {0};
        char *bytes = (char *)&status;
        size_t offset = 0;
        while (offset < sizeof(status)) {
            ssize_t got = read(fd, bytes + offset, sizeof(status) - offset);
            if (got > 0) {
                offset += (size_t)got;
            } else if (got == 0) {
                if (offset == 0) return 0;
                errno = EIO;
                return -1;
            } else if (errno != EINTR) {
                return -1;
            }
        }

        if (status.kind == CHILD_STATUS_FAILURE) {
            *failure = status;
            return 1;
        }
        if (status.kind == CHILD_STATUS_FD_CLOSE_OBSERVATION &&
            status.fd_close_method >= RUN_TEST_FD_METHOD_BULK &&
            status.fd_close_method <= RUN_TEST_FD_METHOD_NUMERIC) {
            observation->method =
                (run_test_fd_close_method_t)status.fd_close_method;
            observation->close_syscalls = status.fd_close_syscalls;
            *observation_valid = true;
            continue;
        }
        errno = EPROTO;
        return -1;
    }
}

static int64_t monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

#define RUNNER_POLL_SLICE_MS 50
#define RUNNER_CAPTURE_GRACE_MS 250
#define RUNNER_DRAIN_CHUNKS_PER_POLL 16

int run_argv_real(const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    run_opts_t no_opts;
    run_result_t local;
    memset(&no_opts, 0, sizeof(no_opts));
    if (!opts) opts = &no_opts;
    if (!result) result = &local;
    result->exit_code = -1;
    result->term_signal = 0;
    result->spawned = false;
    result->out_len = 0;
    result->out_truncated = false;
    /* AR-12 L12 (defense in depth): terminate the caller's capture buffer
     * before any early-return validation path, so a pre-spawn failure never
     * leaves callers formatting uninitialized bytes. */
    if (opts->out && opts->out_size > 0) opts->out[0] = '\0';
    g_test_fd_close_observation_valid = false;
    memset(&g_test_fd_close_observation, 0,
           sizeof(g_test_fd_close_observation));

    if (!argv || !argv[0]) {
        set_error(ERR_INVALID_ARGS, "run_argv: empty argv");
        return -1;
    }

    if (opts->input && opts->use_stdin_fd) {
        set_error(ERR_INVALID_ARGS,
                  "run_argv: byte input and stdin_fd are mutually exclusive");
        return -1;
    }
    if (opts->use_stdin_fd) {
        struct stat stdin_st;
        int stdin_flags;

        if (opts->stdin_fd < 0 || fstat(opts->stdin_fd, &stdin_st) != 0 ||
            !S_ISREG(stdin_st.st_mode) || stdin_st.st_uid != getuid()) {
            set_error(ERR_INVALID_ARGS,
                      "run_argv: stdin_fd is not a readable self-owned regular file");
            return -1;
        }
        stdin_flags = fcntl(opts->stdin_fd, F_GETFL, 0);
        if (stdin_flags < 0 || (stdin_flags & O_ACCMODE) == O_WRONLY
#ifdef O_PATH
            || (stdin_flags & O_PATH) == O_PATH
#endif
        ) {
            set_error(ERR_INVALID_ARGS,
                      "run_argv: stdin_fd is not a readable self-owned regular file");
            return -1;
        }
    }

    /* Some helpers can consume sensitive state only through a pathname (for
     * example GNUPGHOME). Let callers pin that directory before fork and make
     * the child enter the descriptor-backed directory, so a same-uid namespace
     * replacement cannot redirect the helper between validation and exec. */
    if (opts->use_cwd_fd) {
        struct stat cwd_st;
        if (opts->cwd_fd < 0 || fstat(opts->cwd_fd, &cwd_st) != 0 ||
            !S_ISDIR(cwd_st.st_mode)) {
            set_error(ERR_INVALID_ARGS,
                      "run_argv: cwd_fd is not an open directory");
            return -1;
        }
    }

    /* Resolve, verify, and OPEN the helper in the parent.  The descriptor —
     * not this diagnostic pathname — is the launch authority.  It survives a
     * rename/symlink swap after lookup and is rechecked in the child before
     * fexecve (AR-07 M28). */
    char exec_path[MAX_PATH_LEN];
    struct stat exec_identity;
    trusted_script_launch_t script_launch;
    memset(&script_launch, 0, sizeof(script_launch));
    script_launch.interpreter_fd = -1;
    int exec_fd = open_trusted_command(argv[0], exec_path,
                                       sizeof(exec_path), &exec_identity);
    if (exec_fd < 0) {
        int resolve_errno = errno;
        if (resolve_errno == ENOENT) {
            set_error(
                ERR_SYSTEM_CALL,
                "run_argv: '%s' not found in any trusted PATH directory",
                argv[0]);
        } else {
            errno = resolve_errno;
            set_system_error(
                ERR_SYSTEM_CALL,
                "run_argv: trusted PATH resolution failed for '%s'",
                argv[0]);
        }
        errno = resolve_errno;
        return -1;
    }
    if (prepare_trusted_script_launch(exec_fd, argv, &script_launch) != 0) {
        int saved_errno = errno;
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = saved_errno;
        if (saved_errno == ENOEXEC || saved_errno == EINVAL ||
            saved_errno == E2BIG || saved_errno == EPERM) {
            set_system_error(
                ERR_PERMISSION_DENIED,
                "run_argv: rejected unsafe or unsupported executable format/shebang for '%s'",
                exec_path);
        } else {
            set_system_error(
                ERR_SYSTEM_CALL,
                "run_argv: cannot inspect executable format for '%s'",
                exec_path);
        }
        errno = saved_errno;
        return -1;
    }

    int reserved_exec_fd = exec_fd_at_least(exec_fd, STDERR_FILENO + 4);
    if (reserved_exec_fd < 0) {
        int saved_errno = errno;
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = saved_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot pin trusted executable descriptor");
        return -1;
    }
    exec_fd = reserved_exec_fd;
    if (script_launch.is_script) {
        int reserved_interpreter_fd = exec_fd_at_least(
            script_launch.interpreter_fd, STDERR_FILENO + 4);
        if (reserved_interpreter_fd < 0) {
            int saved_errno = errno;
            close(exec_fd);
            trusted_script_launch_cleanup(&script_launch);
            errno = saved_errno;
            set_system_error(ERR_SYSTEM_CALL,
                             "run_argv: cannot pin trusted shebang interpreter descriptor");
            return -1;
        }
        script_launch.interpreter_fd = reserved_interpreter_fd;
    }
    if (g_test_exec_resolved_hook) g_test_exec_resolved_hook(exec_path);

    bool pipe_input = opts->input != NULL;
    bool fd_input = opts->use_stdin_fd;
    bool want_in = pipe_input || fd_input;
    bool want_out = (opts->out && opts->out_size > 0);
    bool need_devnull = !want_in || !want_out ||
                        (!opts->merge_stderr && opts->stderr_to_devnull);
    if (want_out) opts->out[0] = '\0';

    bool use_bulk_close = false;
    bool capture_fd_snapshot = false;
    bool require_bulk_close = false;
    switch (g_test_fd_close_strategy) {
        case RUN_TEST_FD_CLOSE_AUTO:
            use_bulk_close = !g_test_auto_bulk_close_unavailable &&
                             child_bulk_close_available();
            capture_fd_snapshot = !use_bulk_close;
            /* A bulk-capable AUTO launch deliberately avoids the O(open-fds)
             * parent snapshot.  If the selected primitive then fails, there
             * is no complete fallback: report child setup failure instead of
             * leaking descriptors beyond the bounded numeric sweep. */
            require_bulk_close = use_bulk_close;
            break;
        case RUN_TEST_FD_CLOSE_SNAPSHOT:
            capture_fd_snapshot = true;
            break;
        case RUN_TEST_FD_CLOSE_NUMERIC:
            break;
        case RUN_TEST_FD_CLOSE_BULK:
            use_bulk_close = true;
            require_bulk_close = true;
            break;
        default:
            /* Defensive equivalent of AUTO if memory corruption reaches this
             * test-only selector. */
            use_bulk_close = !g_test_auto_bulk_close_unavailable &&
                             child_bulk_close_available();
            capture_fd_snapshot = !use_bulk_close;
            require_bulk_close = use_bulk_close;
            break;
    }
    child_fd_snapshot_t fd_snapshot = {0};
    if (capture_fd_snapshot) {
        fd_snapshot = child_fd_snapshot_capture();
        if (!fd_snapshot.complete) {
            const char *snapshot_kind =
                g_test_fd_close_strategy == RUN_TEST_FD_CLOSE_SNAPSHOT
                    ? "forced" : "automatic";
            set_error(ERR_SYSTEM_CALL,
                      "run_argv: %s child-FD snapshot is incomplete",
                      snapshot_kind);
            free(fd_snapshot.fds);
            close(exec_fd);
            trusted_script_launch_cleanup(&script_launch);
            return -1;
        }
    }

    int devnull = -1;
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int status_pipe[2] = {-1, -1};
    if (need_devnull && (devnull = open_internal_devnull()) < 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot acquire /dev/null for child stdio");
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        return -1;
    }
    if (pipe_input && make_internal_pipe(in_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot create child stdin pipe");
        if (devnull >= 0) close(devnull);
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        return -1;
    }
    if (want_out && make_internal_pipe(out_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot create child stdout pipe");
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        return -1;
    }
    if (make_internal_pipe(status_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot create child setup-status pipe");
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        return -1;
    }

    /* Own SIGCHLD before fork so an inherited auto-reap policy or foreign
     * signal handler can never consume a helper after it has side effects.
     * The exact caller mask is restored only after final reap/retirement. */
    sigset_t pre_wait_mask;
    if (signals_child_wait_begin(&pre_wait_mask) != 0) {
        int ownership_errno = errno;
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        close(status_pipe[0]);
        close(status_pipe[1]);
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = ownership_errno;
        return -1;
    }

    sigset_t pre_spawn_mask;
    if (signals_block_for_child_spawn(&pre_spawn_mask) != 0) {
        int block_errno = errno;
        int ownership_restore_errno = 0;
        if (signals_child_wait_end(&pre_wait_mask) != 0) {
            ownership_restore_errno = errno;
        }
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        close(status_pipe[0]);
        close(status_pipe[1]);
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = block_errno;
        if (ownership_restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "run_argv: cannot block guarded signals before fork; also failed to restore SIGCHLD ownership mask (restore errno=%d)",
                ownership_restore_errno);
        } else {
            set_system_error(ERR_SYSTEM_CALL,
                             "run_argv: cannot block guarded signals before fork");
        }
        errno = block_errno;
        return -1;
    }

    pid_t pid;
    if (g_test_fork_failure_errno != 0) {
        int injected_errno = g_test_fork_failure_errno;
        g_test_fork_failure_errno = 0;
        errno = injected_errno;
        pid = -1;
    } else {
        pid = fork();
    }
    if (pid < 0) {
        int fork_errno = errno;
        int mask_restore_errno = 0;
        int wait_mask_restore_errno = 0;
        if (signals_restore_after_child_spawn(&pre_spawn_mask) != 0) {
            mask_restore_errno = errno;
        }
        if (signals_child_wait_end(&pre_wait_mask) != 0) {
            wait_mask_restore_errno = errno;
        }
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        close(status_pipe[0]);
        close(status_pipe[1]);
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = fork_errno;
        if (mask_restore_errno != 0 || wait_mask_restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "fork() failed; also failed to restore parent signal mask (spawn restore errno=%d, wait restore errno=%d)",
                mask_restore_errno, wait_mask_restore_errno);
        } else {
            set_system_error(ERR_SYSTEM_CALL, "fork() failed");
        }
        errno = fork_errno;
        return -1;
    }

    if (pid == 0) {
        /* ---- child ---- */
        /* Drop the parent's guard handler first (AR-06 F76): until exec resets
         * it, a signal delivered to this child would run guard_handler (which
         * only records and returns), swallowing it and leaving the helper
         * "pre-interrupted" instead of terminating normally. */
        signals_reset_for_child(&pre_wait_mask);

        int child_status_fd = status_pipe[1];
        close(status_pipe[0]);
        int child_cwd_fd = -1;

        /* Preserve a pinned working-directory descriptor before touching
         * stdio.  If the parent began with fd 0/1/2 closed, cwd_fd can occupy
         * one of those numbers and the dup2 setup below would otherwise
         * destroy it before fchdir(). */
        if (opts->use_cwd_fd) {
#ifdef F_DUPFD_CLOEXEC
            child_cwd_fd = fcntl(opts->cwd_fd, F_DUPFD_CLOEXEC, 3);
#else
            child_cwd_fd = fcntl(opts->cwd_fd, F_DUPFD, 3);
            if (child_cwd_fd >= 0 &&
                fcntl(child_cwd_fd, F_SETFD, FD_CLOEXEC) != 0) {
                close(child_cwd_fd);
                child_cwd_fd = -1;
            }
#endif
            if (child_cwd_fd < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_CWD,
                                     errno, 126);
            }
        }

        int stdin_source = fd_input
                               ? opts->stdin_fd
                               : (pipe_input ? in_pipe[0] : devnull);
        int stdout_source = want_out ? out_pipe[1] : devnull;
        if (dup2(stdin_source, STDIN_FILENO) < 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                 errno, 126);
        }
        if (dup2(stdout_source, STDOUT_FILENO) < 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                 errno, 126);
        }
        if (opts->merge_stderr) {
            if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                     errno, 126);
            }
        } else if (opts->stderr_to_devnull) {
            if (dup2(devnull, STDERR_FILENO) < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                     errno, 126);
            }
        }

        /* Close the pipe/devnull fds only above the stdio range (AR-06 F30).
         * When the parent starts with fd 0 or 1 closed, pipe()/open() hand
         * those low numbers back, so after the dup2 dance fds 0/1/2 ARE the
         * child's std streams — an unconditional close here closed the very
         * stdin/stdout we just installed, corrupting the child. Anything in
         * 0..2 is now a std stream we must keep; the close sweep below reaps
         * every remaining fd above the status/executable channels. */
        if (in_pipe[0] > STDERR_FILENO) close(in_pipe[0]);
        if (in_pipe[1] > STDERR_FILENO) close(in_pipe[1]);
        if (out_pipe[0] > STDERR_FILENO) close(out_pipe[0]);
        if (out_pipe[1] > STDERR_FILENO) close(out_pipe[1]);
        if (devnull > STDERR_FILENO && devnull != child_status_fd) close(devnull);

        if (opts->use_cwd_fd) {
            if (fchdir(child_cwd_fd) != 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_CWD,
                                     errno, 126);
            }
            close(child_cwd_fd);
        }

        /* Reserve fd 3 for the setup-status channel.  Keeping that one fd
         * below the close-from boundary lets the child report failures through
         * descriptor exec, while FD_CLOEXEC turns success into an EOF proof. */
        if (child_status_fd != STDERR_FILENO + 1) {
            if (dup2(child_status_fd, STDERR_FILENO + 1) < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                     errno, 126);
            }
            close(child_status_fd);
            child_status_fd = STDERR_FILENO + 1;
        }
        int status_flags = fcntl(child_status_fd, F_GETFD, 0);
        if (status_flags < 0 ||
            fcntl(child_status_fd, F_SETFD,
                  status_flags | FD_CLOEXEC) != 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                 errno, 126);
        }

        /* Preserve exactly the verified executable/script at fd 4. A script
         * also receives its separately verified binary interpreter at fd 5.
         * Parent pins are >=6 and are swept after these dup2 operations. */
        int child_exec_fd = STDERR_FILENO + 2;
        if (dup2(exec_fd, child_exec_fd) < 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                 errno, 127);
        }
        close(exec_fd);
        int child_exec_flags = fcntl(child_exec_fd, F_GETFD, 0);
        if (child_exec_flags < 0 ||
            fcntl(child_exec_fd, F_SETFD,
                  script_launch.is_script
                      ? child_exec_flags & ~FD_CLOEXEC
                      : child_exec_flags | FD_CLOEXEC) != 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                 errno, 127);
        }

        int child_interpreter_fd = -1;
        if (script_launch.is_script) {
            child_interpreter_fd = STDERR_FILENO + 3;
            if (dup2(script_launch.interpreter_fd,
                     child_interpreter_fd) < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     errno, 127);
            }
            close(script_launch.interpreter_fd);
            int interpreter_flags = fcntl(child_interpreter_fd, F_GETFD, 0);
            if (interpreter_flags < 0 ||
                fcntl(child_interpreter_fd, F_SETFD,
                      interpreter_flags | FD_CLOEXEC) != 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     errno, 127);
            }
        }

        /* fd-CLOEXEC: the explicit closes above only cover our own pipes;
         * binaries sweep from 5 so an unrelated inherited fd 5 never leaks.
         * Scripts retain fd 4 intentionally for /proc/self/fd or /dev/fd and
         * reserve fd 5 only until the interpreter exec, so they sweep from 6.
         * Nothing else is intentionally handed to a child. */
        run_test_fd_close_observation_t fd_close_observation;
        int close_lowfd = script_launch.is_script
                              ? STDERR_FILENO + 4
                              : STDERR_FILENO + 3;
        if (child_close_fds_from(close_lowfd, use_bulk_close,
                                 require_bulk_close, &fd_snapshot,
                                 &fd_close_observation) != 0) {
            int close_errno = errno;
            if (g_test_fd_close_observation_enabled) {
                (void)child_report_fd_close_observation(
                    child_status_fd, &fd_close_observation);
            }
            child_report_failure(child_status_fd, CHILD_STAGE_FD_CLOSE,
                                 close_errno, 126);
        }
        if (g_test_fd_close_observation_enabled &&
            child_report_fd_close_observation(
                child_status_fd, &fd_close_observation) != 0) {
            child_report_failure(child_status_fd, CHILD_STAGE_STDIO,
                                 errno, 126);
        }

        /* Apply removals before additions so callers can express a clean
         * baseline and still deliberately replace one of the same names.
         * Neither operation mutates the parent process environment. */
        if (opts->unset_env) {
            for (size_t i = 0; opts->unset_env[i]; i++) {
                const char *name = opts->unset_env[i];
                if (!*name || strchr(name, '=') != NULL) {
                    child_report_failure(child_status_fd,
                                         CHILD_STAGE_ENV, EINVAL, 126);
                }
                if (unsetenv(name) != 0) {
                    child_report_failure(child_status_fd,
                                         CHILD_STAGE_ENV, errno, 126);
                }
            }
        }

        if (opts->extra_env) {
            for (size_t i = 0; opts->extra_env[i]; i++) {
                const char *e = opts->extra_env[i];
                const char *eq = strchr(e, '=');
                if (eq) {
                    char key[256];
                    size_t klen = (size_t)(eq - e);
                    if (klen == 0 || klen >= sizeof(key)) {
                        child_report_failure(child_status_fd,
                                             CHILD_STAGE_ENV, EINVAL, 126);
                    }
                    memcpy(key, e, klen);
                    key[klen] = '\0';
                    if (setenv(key, eq + 1, 1) != 0) {
                        child_report_failure(child_status_fd,
                                             CHILD_STAGE_ENV, errno, 126);
                    }
                }
            }
        }

        /* Same-inode metadata/content churn that changes size, mode, uid/gid,
         * or nanosecond mtime/ctime fails closed. The fd itself prevents a
         * pathname/inode replacement from redirecting execution. */
        struct stat child_exec_stat;
        if (fstat(child_exec_fd, &child_exec_stat) != 0 ||
            !exec_stat_identity_matches(&exec_identity, &child_exec_stat)) {
            child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                 EACCES, 127);
        }
        if (script_launch.is_script) {
            struct stat child_interpreter_stat;
            if (fstat(child_interpreter_fd, &child_interpreter_stat) != 0 ||
                !exec_stat_identity_matches(
                    &script_launch.interpreter_identity,
                    &child_interpreter_stat)) {
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     EACCES, 127);
            }

            /* Prove that the platform descriptor filesystem maps the exact
             * argv path to fd 4 before starting the interpreter. Absence of
             * procfs/fdescfs/devfs or an unexpected mapping is a setup error,
             * never a fallback to the mutable script pathname. */
            int proof_flags = O_RDONLY | O_NONBLOCK;
#ifdef O_CLOEXEC
            proof_flags |= O_CLOEXEC;
#endif
            int proof_fd = open(script_launch.script_fd_path, proof_flags);
            struct stat proof_stat;
            if (proof_fd < 0) {
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     errno, 127);
            }
            if (fstat(proof_fd, &proof_stat) != 0) {
                int proof_errno = errno;
                close(proof_fd);
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     proof_errno, 127);
            }
            if (!exec_stat_identity_matches(&exec_identity, &proof_stat)) {
                close(proof_fd);
                child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                     EACCES, 127);
            }
            close(proof_fd);
        }

        char *const *launch_argv = script_launch.is_script
                                       ? script_launch.script_argv
                                       : (char *const *)argv;

#if defined(__linux__) || defined(__FreeBSD__)
        /* Scripts never enter the kernel's shebang path. The already-pinned,
         * proven-binary direct interpreter executes instead, with the pinned
         * readable script descriptor as its script operand. */
        int launch_fd = script_launch.is_script
                            ? child_interpreter_fd
                            : child_exec_fd;
        fexecve(launch_fd, launch_argv, environ); /* Flawfinder: ignore — descriptor-pinned binary/interpreter; no shell */
#elif defined(__APPLE__)
        /* macOS 14 has no supported fexecve/execveat equivalent.  Re-walk the
         * canonical pathname from root with no-follow directory descriptors
         * immediately before execve and require it still names the exact
         * parent-pinned inode and metadata.  This catches every deterministic
         * lookup-to-launch mutation (including the test hook).  One
         * irreducible kernel pathname lookup remains between this proof and
         * execve; unlike Linux/FreeBSD, Darwin exposes no descriptor-exec API. */
        const char *apple_launch_path = script_launch.is_script
                                            ? script_launch.interpreter_path
                                            : exec_path;
        const struct stat *apple_identity = script_launch.is_script
                                                 ? &script_launch.interpreter_identity
                                                 : &exec_identity;
        struct stat apple_reopened;
        int apple_fd = exec_open_canonical(apple_launch_path, &apple_reopened);
        if (apple_fd < 0 ||
            !exec_stat_identity_matches(apple_identity, &apple_reopened)) {
            if (apple_fd >= 0) close(apple_fd);
            child_report_failure(child_status_fd, CHILD_STAGE_EXEC,
                                 EACCES, 127);
        }
        close(apple_fd);
        execve(apple_launch_path, launch_argv, environ); /* Flawfinder: ignore — canonical path was descriptor-reproved immediately above; no shell */
#else
        errno = ENOTSUP;
#endif
        child_report_failure(child_status_fd, CHILD_STAGE_EXEC, errno, 127);
    }

    /* ---- parent ---- */
    result->spawned = true;
    if (g_test_post_fork_pre_publish_hook) {
        g_test_post_fork_pre_publish_hook();
    }
    /* AR-03 L8: publish the in-flight child while guarded signals are still
     * blocked, so a pending rollback signal can observe it when the exact
     * parent mask is restored below. */
    signals_child_spawned(pid);
    if (signals_restore_after_child_spawn(&pre_spawn_mask) != 0) {
        int restore_errno = errno;
        int cleanup_wait_errno = 0;
        int wait_mask_restore_errno = 0;
        signals_child_wait_result_t wait_result;

        (void)kill(pid, SIGKILL);
        do {
            wait_result = signals_wait_child(pid, NULL, 0);
        } while (wait_result.waited < 0 &&
                 wait_result.wait_errno == EINTR &&
                 wait_result.mask_errno == 0);
        if (wait_result.waited != pid) {
            cleanup_wait_errno = wait_result.wait_errno != 0
                                     ? wait_result.wait_errno
                                     : ECHILD;
        }
        if (signals_child_wait_end(&pre_wait_mask) != 0) {
            wait_mask_restore_errno = errno;
        }
        if (devnull >= 0) close(devnull);
        if (pipe_input) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        close(status_pipe[0]);
        close(status_pipe[1]);
        free(fd_snapshot.fds);
        close(exec_fd);
        trusted_script_launch_cleanup(&script_launch);
        errno = restore_errno;
        if (cleanup_wait_errno != 0 || wait_result.mask_errno != 0 ||
            wait_mask_restore_errno != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "run_argv: cannot restore parent signal mask after fork; child cleanup also failed (reap errno=%d, wait-mask errno=%d, final-mask errno=%d)",
                cleanup_wait_errno, wait_result.mask_errno,
                wait_mask_restore_errno);
        } else {
            set_system_error(ERR_SYSTEM_CALL,
                             "run_argv: cannot restore parent signal mask after fork");
        }
        errno = restore_errno;
        return -1;
    }
    free(fd_snapshot.fds);
    close(exec_fd);
    trusted_script_launch_cleanup(&script_launch);
    if (devnull >= 0) close(devnull);
    if (pipe_input) close(in_pipe[0]);
    if (want_out) close(out_pipe[1]);
    close(status_pipe[1]);

    child_status_t child_status = {0};
    run_test_fd_close_observation_t child_fd_close_observation = {0};
    bool child_fd_close_observation_valid = false;
    int child_status_rc = read_child_status(
        status_pipe[0], &child_status, &child_fd_close_observation,
        &child_fd_close_observation_valid);
    int child_status_errno = errno;
    close(status_pipe[0]);
    if (g_test_fd_close_observation_enabled &&
        child_fd_close_observation_valid) {
        g_test_fd_close_observation = child_fd_close_observation;
        g_test_fd_close_observation_valid = true;
    }

    run_sigpipe_state_t sigpipe_state;
    memset(&sigpipe_state, 0, sizeof(sigpipe_state));
    if (pipe_input && run_sigpipe_begin(&sigpipe_state) != 0) {
        int block_errno = errno;
        int cleanup_wait_errno = 0;
        int cleanup_wait_mask_errno = 0;
        int cleanup_final_mask_errno = 0;
        signals_child_wait_result_t wait_result;

        close(in_pipe[1]);
        if (want_out) close(out_pipe[0]);
        (void)kill(pid, SIGKILL);
        do {
            wait_result = signals_wait_child(pid, NULL, 0);
        } while (wait_result.waited < 0 &&
                 wait_result.wait_errno == EINTR &&
                 wait_result.mask_errno == 0);
        if (wait_result.waited != pid) {
            cleanup_wait_errno = wait_result.wait_errno != 0
                                     ? wait_result.wait_errno
                                     : ECHILD;
        }
        cleanup_wait_mask_errno = wait_result.mask_errno;
        if (signals_child_wait_end(&pre_wait_mask) != 0) {
            cleanup_final_mask_errno = errno;
        }
        errno = block_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: cannot block SIGPIPE for child stdin writes");
        errno = block_errno;
        report_secondary_runner_cleanup_failure(
            "while reaping after SIGPIPE-mask setup failure",
            cleanup_wait_errno);
        report_secondary_runner_cleanup_failure(
            "while restoring the guarded wait mask after SIGPIPE-mask setup failure",
            cleanup_wait_mask_errno);
        report_secondary_runner_cleanup_failure(
            "while restoring SIGCHLD ownership after SIGPIPE-mask setup failure",
            cleanup_final_mask_errno);
        return -1;
    }

    int infd = pipe_input ? in_pipe[1] : -1;
    int outfd = want_out ? out_pipe[0] : -1;
    size_t in_off = 0, out_off = 0;
    bool input_failed = false;
    bool output_stalled = false;
    bool io_failed = false;
    bool nonblock_setup_failed = false;
    int io_errno = 0;
    /* Function-scope (not loop-scope) so it can be scrubbed after the loop:
     * captured child stdout transits this buffer, and for the GPG secret-key
     * export that is unencrypted private-key material — the caller scrubs its
     * own copy, but these bytes would otherwise stay resident in this frame
     * after return (AR-02 #25). */
    char rdbuf[4096];
    if (infd >= 0 && set_nonblock(infd) != 0) {
        io_failed = true;
        nonblock_setup_failed = true;
        io_errno = errno;
    }
    if (!io_failed && outfd >= 0 && set_nonblock(outfd) != 0) {
        io_failed = true;
        nonblock_setup_failed = true;
        io_errno = errno;
    }
    if (io_failed) {
        /* A blocking endpoint would invalidate the poll-driven liveness
         * contract. Close both directions so the child gets EOF/SIGPIPE, then
         * use the normal wait/reap path before reporting the setup failure. */
        if (infd >= 0) { close(infd); infd = -1; }
        if (outfd >= 0) { close(outfd); outfd = -1; }
        (void)kill(pid, SIGKILL);
    }

    /* A child-side report means no helper was successfully exec'd.  Close the
     * data pipes now; the status payload is handled after the child is reaped. */
    if (child_status_rc != 0) {
        if (infd >= 0) { close(infd); infd = -1; }
        if (outfd >= 0) { close(outfd); outfd = -1; }
    }

    /* A provided zero-length buffer means "send no bytes, then EOF". Leaving
     * the pipe open would make poll() report it writable forever: write(...,
     * 0) returns zero, advances nothing, and a child such as cat keeps waiting
     * for EOF. Close before the poll loop, without touching opts->input. */
    if (infd >= 0 && opts->input_len == 0) {
        close(infd);
        infd = -1;
    }

    int status = 0;
    bool child_reaped = false;
    bool wait_failed = false;
    int wait_errno = 0;
    int64_t capture_deadline = -1;

    while (infd >= 0 || outfd >= 0) {
        int timeout_ms = RUNNER_POLL_SLICE_MS;
        if (child_reaped && outfd >= 0) {
            int64_t now = monotonic_millis();
            if (now < 0) {
                io_failed = true;
                io_errno = errno;
                close(outfd);
                outfd = -1;
                continue;
            }
            if (capture_deadline < 0) {
                capture_deadline = now + RUNNER_CAPTURE_GRACE_MS;
            }
            int64_t remaining = capture_deadline - now;
            if (remaining <= 0) {
                output_stalled = true;
                close(outfd);
                outfd = -1;
                continue;
            }
            if (remaining < timeout_ms) timeout_ms = (int)remaining;
        }

        struct pollfd pfds[2];
        int n = 0, in_idx = -1, out_idx = -1;
        if (infd >= 0) { pfds[n].fd = infd; pfds[n].events = POLLOUT; in_idx = n++; }
        if (outfd >= 0) { pfds[n].fd = outfd; pfds[n].events = POLLIN; out_idx = n++; }

        int poll_rc = poll(pfds, (nfds_t)n, timeout_ms);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                /* Still execute the child-state/deadline maintenance below. */
                poll_rc = 0;
            } else {
                /* Close both pipe ends before bailing: leaving infd open means
                 * a child reading stdin never sees EOF, and the wait below
                 * would then block forever. */
                if (infd >= 0) { close(infd); infd = -1; }
                if (outfd >= 0) { close(outfd); outfd = -1; }
                io_failed = true;
                io_errno = errno;
                break;
            }
        }

        if (poll_rc > 0 && in_idx >= 0 &&
            (pfds[in_idx].revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL))) {
            short revents = pfds[in_idx].revents;
            if (revents & POLLOUT) {
                ssize_t w = write(infd, opts->input + in_off, opts->input_len - in_off);
                if (w > 0) {
                    in_off += (size_t)w;
                    if (in_off >= opts->input_len) { close(infd); infd = -1; }
                } else if (w == 0 ||
                           (w < 0 && errno != EAGAIN && errno != EINTR)) {
                    if (w < 0 && errno == EPIPE) {
                        sigpipe_state.saw_epipe = true;
                    }
                    if (in_off < opts->input_len) input_failed = true;
                    close(infd); infd = -1;
                }
            }
            if (infd >= 0 && (revents & (POLLERR | POLLHUP | POLLNVAL))) {
                if (in_off < opts->input_len) input_failed = true;
                close(infd);
                infd = -1;
            }
        }

        if (poll_rc > 0 && out_idx >= 0 &&
            (pfds[out_idx].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
            short revents = pfds[out_idx].revents;
            unsigned int chunks = 0;
            while (chunks < RUNNER_DRAIN_CHUNKS_PER_POLL) {
                ssize_t r = read(outfd, rdbuf, sizeof(rdbuf));
                if (r > 0) {
                    chunks++;
                    size_t cp = 0;
                    if (out_off < opts->out_size - 1) {
                        size_t space = opts->out_size - 1 - out_off;
                        cp = ((size_t)r < space) ? (size_t)r : space;
                        memcpy(opts->out + out_off, rdbuf, cp);
                        out_off += cp;
                    }
                    /* Bytes beyond the capture buffer are still drained (so
                     * the child never blocks) but LOST — record that, so
                     * callers can reject incomplete structured output. */
                    if (cp < (size_t)r) result->out_truncated = true;
                    continue;
                }
                if (r == 0) {
                    close(outfd);
                    outfd = -1;
                } else if (errno == EAGAIN || errno == EINTR) {
                    if (errno == EAGAIN && (revents & POLLHUP)) {
                        close(outfd);
                        outfd = -1;
                    }
                } else {
                    io_failed = true;
                    io_errno = errno;
                    close(outfd);
                    outfd = -1;
                }
                break;
            }
            /* A continuously writing descendant can keep a nonblocking pipe
             * readable forever.  The chunk budget deliberately yields here
             * so waitpid(WNOHANG) and the post-exit deadline run every cycle. */
        }

        /* Finite polling lets us observe the direct child independently of
         * capture EOF.  A background descendant may retain stdout forever;
         * once the direct child is reaped, only a short drain grace remains. */
        if (!child_reaped) {
            signals_child_wait_result_t wait_result;
            do {
                wait_result = signals_wait_child(pid, &status, WNOHANG);
            } while (wait_result.waited < 0 &&
                     wait_result.wait_errno == EINTR &&
                     wait_result.mask_errno == 0);

            /* AR-12 U4: process a successful reap FIRST even when a
             * mask-restore failure is reported alongside it — the PID is
             * consumed and the exit status is valid; discarding the reap
             * left child_reaped false and re-waited a released PID. The
             * mask failure still fails the call afterwards. */
            if (wait_result.waited == pid) {
                child_reaped = true;
                if (infd >= 0) {
                    if (in_off < opts->input_len) input_failed = true;
                    close(infd);
                    infd = -1;
                }
                if (outfd >= 0) {
                    int64_t now = monotonic_millis();
                    if (now < 0) {
                        io_failed = true;
                        io_errno = errno;
                        close(outfd);
                        outfd = -1;
                    } else {
                        capture_deadline = now + RUNNER_CAPTURE_GRACE_MS;
                    }
                }
                if (wait_result.mask_errno != 0) {
                    wait_failed = true;
                    wait_errno = wait_result.mask_errno;
                    if (infd >= 0) { close(infd); infd = -1; }
                    if (outfd >= 0) { close(outfd); outfd = -1; }
                    break;
                }
            } else if (wait_result.mask_errno != 0) {
                wait_failed = true;
                wait_errno = wait_result.mask_errno;
                if (infd >= 0) { close(infd); infd = -1; }
                if (outfd >= 0) { close(outfd); outfd = -1; }
                break;
            } else if (wait_result.waited < 0) {
                wait_failed = true;
                wait_errno = wait_result.wait_errno;
                if (infd >= 0) { close(infd); infd = -1; }
                if (outfd >= 0) { close(outfd); outfd = -1; }
                break;
            }
        }
    }
    if (want_out) {
        opts->out[out_off] = '\0';
        /* Drop the transit copy of the child's output (AR-02 #25). */
        secure_zero_memory(rdbuf, sizeof(rdbuf));
    }
    result->out_len = out_off;

    if (!child_reaped && !wait_failed) {
        signals_child_wait_result_t wait_result;
        do {
            wait_result = signals_wait_child(pid, &status, 0);
        } while (wait_result.waited < 0 &&
                 wait_result.wait_errno == EINTR &&
                 wait_result.mask_errno == 0);
        /* AR-13 L6: mirror the U4 ordering used in the WNOHANG loop — record a
         * successful reap FIRST so the child's exit status is not discarded
         * when guarded-mask restoration fails alongside it; only then surface
         * the mask failure. The pre-fix mask-first order dropped child_reaped,
         * losing the exit code the later WIFEXITED/WIFSIGNALED extraction needs. */
        if (wait_result.waited == pid) {
            child_reaped = true;
            if (wait_result.mask_errno != 0) {
                wait_failed = true;
                wait_errno = wait_result.mask_errno;
            }
        } else if (wait_result.mask_errno != 0) {
            wait_failed = true;
            wait_errno = wait_result.mask_errno;
        } else {
            wait_failed = true;
            wait_errno = wait_result.wait_errno;
        }
    }
    int sigpipe_cleanup_errno = 0;
    int wait_ownership_cleanup_errno = 0;
    if (run_sigpipe_end(&sigpipe_state) != 0) {
        sigpipe_cleanup_errno = errno;
    }
    if (signals_child_wait_end(&pre_wait_mask) != 0) {
        wait_ownership_cleanup_errno = errno;
    }

    if (child_reaped && WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (child_reaped && WIFSIGNALED(status)) {
        result->term_signal = WTERMSIG(status);
        result->exit_code = -1;
    }

    if (child_status_rc > 0) {
        int primary_errno = child_status.system_errno;
        errno = primary_errno;
        switch ((child_stage_t)child_status.stage) {
            case CHILD_STAGE_STDIO:
                set_system_error(ERR_SYSTEM_CALL,
                                 "run_argv: child stdio setup failed");
                break;
            case CHILD_STAGE_CWD:
                set_system_error(ERR_SYSTEM_CALL,
                                 "run_argv: child working-directory setup failed");
                break;
            case CHILD_STAGE_FD_CLOSE:
                set_system_error(ERR_SYSTEM_CALL,
                                 "run_argv: child descriptor cleanup failed");
                break;
            case CHILD_STAGE_ENV:
                set_system_error(ERR_SYSTEM_CALL,
                                 "run_argv: child environment setup failed");
                break;
            case CHILD_STAGE_EXEC:
                set_system_error(ERR_SYSTEM_COMMAND_FAILED,
                                 "run_argv: verified descriptor execution failed for '%s'",
                                 exec_path);
                break;
            default:
                set_error(ERR_SYSTEM_CALL,
                          "run_argv: child returned an unknown setup failure");
                break;
        }
        errno = primary_errno;
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (child_status_rc < 0) {
        int primary_errno = child_status_errno;
        errno = primary_errno;
        set_system_error(ERR_SYSTEM_CALL,
                         "run_argv: child setup-status channel failed");
        errno = primary_errno;
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (wait_failed) {
        int primary_errno = wait_errno;
        errno = primary_errno;
        set_system_error(ERR_SYSTEM_CALL, "waitpid() failed");
        errno = primary_errno;
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (io_failed) {
        int primary_errno = io_errno;
        errno = primary_errno;
        if (nonblock_setup_failed) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "run_argv: cannot configure subprocess pipe as nonblocking");
        } else {
            set_system_error(ERR_SYSTEM_CALL,
                             "run_argv: subprocess pipe I/O failed");
        }
        errno = primary_errno;
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (input_failed) {
        set_error(ERR_SYSTEM_COMMAND_FAILED,
                  "run_argv: child stdin closed before all input was delivered "
                  "(%zu/%zu bytes)", in_off, opts->input_len);
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (output_stalled) {
        set_error(ERR_SYSTEM_COMMAND_FAILED,
                  "run_argv: captured stdout remained open after the direct "
                  "child exited");
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (!result->spawned || result->exit_code != 0) {
        report_secondary_signal_cleanup_failures(
            sigpipe_cleanup_errno, wait_ownership_cleanup_errno);
        return -1;
    }
    if (sigpipe_cleanup_errno != 0 || wait_ownership_cleanup_errno != 0) {
        int primary_cleanup_errno = sigpipe_cleanup_errno != 0
                                        ? sigpipe_cleanup_errno
                                        : wait_ownership_cleanup_errno;
        errno = primary_cleanup_errno;
        set_system_error(
            ERR_SYSTEM_CALL,
            "run_argv: cannot restore subprocess signal mask state");
        errno = primary_cleanup_errno;
        if (sigpipe_cleanup_errno != 0 &&
            wait_ownership_cleanup_errno != 0) {
            report_secondary_runner_cleanup_failure(
                "while restoring SIGCHLD wait ownership",
                wait_ownership_cleanup_errno);
        }
        return -1;
    }
    return 0;
}

static command_runner_fn g_runner = run_argv_real;

command_runner_fn run_set_runner(command_runner_fn fn) {
    command_runner_fn prev = g_runner;
    g_runner = fn ? fn : run_argv_real;
    return prev;
}

bool run_uses_default_runner(void) {
    return g_runner == run_argv_real;
}

int run_argv(const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    return g_runner(argv, opts, result);
}

/* AR-07 M28/M29 executable trust.  A helper is trusted only when every
 * root-to-leaf directory is pinned with openat(O_NOFOLLOW), is owned by root
 * or this uid, and cannot be replaced by a group/other or extended-ACL writer.
 * The final executable is opened and verified as a descriptor, which run_argv
 * keeps through fork. Linux/FreeBSD execute that descriptor; macOS performs a
 * final descriptor-relative identity proof before its pathname-only execve fallback.
 * find_command_path closes its descriptor and therefore redoes this complete
 * walk on every call: no positive pathname memo can outlive chmod/chown/inode/
 * ancestor replacement. */

static bool exec_owner_is_allowed(uid_t owner) {
    return owner == (uid_t)0 || owner == getuid();
}

static bool exec_directory_stat_is_trusted(const struct stat *st) {
    return st && S_ISDIR(st->st_mode) && exec_owner_is_allowed(st->st_uid) &&
           (st->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* Darwin ACLs are independent access-control entries, while FreeBSD may expose
 * either POSIX.1e or NFSv4 ACLs. A safe-looking 0755 mode is therefore not a
 * complete writer check on those systems. FreeBSD provides a canonical
 * triviality check, so reject every nontrivial ACL there. Darwin deny ACEs and
 * read/execute-only allow ACEs cannot mutate the object and remain usable; all
 * other allow bits and unknown entries fail closed. Filesystems that do not
 * implement ACL retrieval still use their authoritative mode bits. Linux POSIX
 * ACL write grants are reflected in the group-class mode mask, so the existing
 * mode check remains complete there. */
#if defined(__APPLE__) || defined(__FreeBSD__)
static bool exec_acl_query_is_unsupported(int error) {
    return error == EOPNOTSUPP
#ifdef ENOTSUP
#if ENOTSUP != EOPNOTSUPP
           || error == ENOTSUP
#endif
#endif
        ;
}

#if defined(__FreeBSD__)
static bool exec_freebsd_acl_is_trivial(acl_t acl) {
    int trivial = 0;
    errno = 0;
    int check_rc = acl_is_trivial_np(acl, &trivial);
    int check_errno = errno;
    errno = 0;
    int free_rc = acl_free(acl);
    int free_errno = errno;
    if (check_rc != 0) {
        errno = check_errno ? check_errno : EIO;
        return false;
    }
    if (free_rc != 0) {
        errno = free_errno ? free_errno : EIO;
        return false;
    }
    if (trivial != 1) {
        errno = EACCES;
        return false;
    }
    return true;
}
#endif

static bool exec_fd_acl_is_trusted(int fd) {
#if defined(__APPLE__)
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) {
        int query_errno = errno;
        /* Darwin represents an object with no extended ACL as NULL/ENOENT:
         * acl_get_fd_np() delegates to filesec_get_property(FILESEC_ACL),
         * whose missing-property result is ENOENT. That is the safe, trivial
         * ACL case; every other supported-filesystem query failure remains
         * ambiguous and fails closed. */
        if (query_errno == ENOENT ||
            exec_acl_query_is_unsupported(query_errno)) return true;
        errno = query_errno ? query_errno : EIO;
        return false;
    }

    const acl_permset_mask_t harmless_allow =
        (acl_permset_mask_t)ACL_READ_DATA |
        (acl_permset_mask_t)ACL_EXECUTE |
        (acl_permset_mask_t)ACL_READ_ATTRIBUTES |
        (acl_permset_mask_t)ACL_READ_EXTATTRIBUTES |
        (acl_permset_mask_t)ACL_READ_SECURITY |
        (acl_permset_mask_t)ACL_SYNCHRONIZE;
    int entry_id = ACL_FIRST_ENTRY;
    bool trusted = true;
    int operation_errno = 0;
    for (;;) {
        acl_entry_t entry;
        errno = 0;
        int entry_rc = acl_get_entry(acl, entry_id, &entry);
        if (entry_rc != 0) {
            /* A valid ACL reports EINVAL after its last entry (and for an
             * empty ACL). Other errors are ambiguous and fail closed. */
            if (errno != EINVAL) operation_errno = errno ? errno : EIO;
            break;
        }

        acl_tag_t tag;
        errno = 0;
        if (acl_get_tag_type(entry, &tag) != 0) {
            operation_errno = errno ? errno : EIO;
            break;
        }
        if (tag == ACL_EXTENDED_ALLOW) {
            acl_permset_mask_t permissions = 0;
            errno = 0;
            if (acl_get_permset_mask_np(entry, &permissions) != 0) {
                operation_errno = errno ? errno : EIO;
                break;
            }
            if ((permissions & ~harmless_allow) != 0) {
                trusted = false;
                break;
            }
        } else if (tag != ACL_EXTENDED_DENY) {
            trusted = false;
            break;
        }
        entry_id = ACL_NEXT_ENTRY;
    }

    errno = 0;
    int free_rc = acl_free(acl);
    int free_errno = errno;
    if (operation_errno != 0) {
        errno = operation_errno;
        return false;
    }
    if (free_rc != 0) {
        errno = free_errno ? free_errno : EIO;
        return false;
    }
    if (!trusted) {
        errno = EACCES;
        return false;
    }
    return true;
#elif defined(__FreeBSD__)
    acl_t acl;
#ifdef ACL_TYPE_NFS4
    errno = 0;
    acl = acl_get_fd_np(fd, ACL_TYPE_NFS4);
    if (acl) return exec_freebsd_acl_is_trivial(acl);
    int nfs4_errno = errno;
    if (nfs4_errno != EINVAL &&
        !exec_acl_query_is_unsupported(nfs4_errno)) {
        errno = nfs4_errno ? nfs4_errno : EIO;
        return false;
    }
#endif

    errno = 0;
    acl = acl_get_fd(fd);
    if (!acl) {
        int access_errno = errno;
        if (exec_acl_query_is_unsupported(access_errno)) return true;
        errno = access_errno ? access_errno : EIO;
        return false;
    }
    return exec_freebsd_acl_is_trivial(acl);
#endif
}
#else
static bool exec_fd_acl_is_trusted(int fd) {
    (void)fd;
    return true;
}
#endif

typedef enum {
    EXEC_ACL_TARGET_DIRECTORY = 1,
    EXEC_ACL_TARGET_LEAF
} exec_acl_target_t;

static bool exec_command_acl_is_trusted(int fd, exec_acl_target_t target) {
#ifdef GITSWITCH_TESTING
    if (g_test_exec_acl_failure_errno != 0 &&
        g_test_exec_acl_failure_target == (int)target) {
        int injected_errno = g_test_exec_acl_failure_errno;
        g_test_exec_acl_failure_target = 0;
        g_test_exec_acl_failure_errno = 0;
        errno = injected_errno;
        return false;
    }
#else
    (void)target;
#endif
    return exec_fd_acl_is_trusted(fd);
}

static bool exec_current_user_in_group(gid_t group) {
    if (group == getgid()) return true;

    int count = getgroups(0, NULL);
    if (count <= 0) return false;
    gid_t *groups = malloc((size_t)count * sizeof(*groups));
    if (!groups) return false;
    int got = getgroups(count, groups);
    bool found = false;
    if (got >= 0) {
        for (int i = 0; i < got; i++) {
            if (groups[i] == group) {
                found = true;
                break;
            }
        }
    }
    free(groups);
    return found;
}

static bool exec_file_stat_is_trusted(const struct stat *st) {
    if (!st || !S_ISREG(st->st_mode) ||
        !exec_owner_is_allowed(st->st_uid) ||
        (st->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }

    uid_t uid = getuid();
    if (uid == (uid_t)0) {
        return (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
    }
    /* Header/format validation must read the exact pinned inode before any
     * fork. Execute-only files are therefore deliberately unsupported: raw
     * descriptor execution could otherwise run an unreadable script whose
     * interpreter was never validated. */
    if (st->st_uid == uid) {
        return (st->st_mode & (S_IRUSR | S_IXUSR)) ==
               (S_IRUSR | S_IXUSR);
    }
    if (exec_current_user_in_group(st->st_gid)) {
        return (st->st_mode & (S_IRGRP | S_IXGRP)) ==
               (S_IRGRP | S_IXGRP);
    }
    return (st->st_mode & (S_IROTH | S_IXOTH)) ==
           (S_IROTH | S_IXOTH);
}

/* Mode bits alone are not an execution authorization decision: a POSIX ACL
 * can deny this caller and a noexec mount rejects every leaf regardless of
 * its mode.  Use the same credentials the eventual exec will use.  This
 * utility is not a set-id boundary, so reject split real/effective identities
 * rather than validating under one identity and launching under another. */
static int exec_leaf_is_effectively_executable_at(int parent_fd,
                                                  const char *component) {
    if (getuid() != geteuid() || getgid() != getegid()) {
        errno = EPERM;
        return -1;
    }

    /* With the identities equal, the real-ID contract is also the effective
     * launch contract. Keep flags zero so older glibc uses the kernel access
     * check; its historical AT_EACCESS emulation derived permission from mode
     * bits and could miss an ACL denial. */
    return faccessat(parent_fd, component, X_OK, 0);
}

static int exec_open_directory_at(int parent_fd, const char *component,
                                  struct stat *opened) {
#if defined(O_DIRECTORY) && defined(O_NOFOLLOW)
    int flags = O_DIRECTORY | O_NOFOLLOW;
#if defined(__FreeBSD__) && defined(O_SEARCH)
    flags |= O_SEARCH;
#elif defined(__linux__) && defined(O_PATH)
    flags |= O_PATH;
#elif defined(O_SEARCH)
    flags |= O_SEARCH;
#else
    /* O_NONBLOCK is immaterial for a directory but keeps this fallback from
     * acquiring a blocking special-file open if a platform ignores
     * O_DIRECTORY before type validation. */
    flags |= O_RDONLY | O_NONBLOCK;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef GITSWITCH_TESTING
    g_test_directory_open_call_count++;
    if (g_test_directory_open_failure_errno != 0 &&
        g_test_directory_open_call_count ==
            g_test_directory_open_failure_ordinal) {
        int injected_errno = g_test_directory_open_failure_errno;
        g_test_directory_open_failure_errno = 0;
        g_test_directory_open_failure_ordinal = 0;
        errno = injected_errno;
        return -1;
    }
#endif
    int fd = openat(parent_fd, component, flags);
    if (fd < 0) return -1;
    if (fstat(fd, opened) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!exec_directory_stat_is_trusted(opened)) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    if (!exec_command_acl_is_trusted(fd, EXEC_ACL_TARGET_DIRECTORY)) {
        int saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    struct stat sealed;
    if (fstat(fd, &sealed) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!exec_stat_identity_matches(opened, &sealed)) {
        close(fd);
        errno = EACCES;
        return -1;
    }
#ifndef O_CLOEXEC
    int fd_flags = fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
#endif
    return fd;
#else
    (void)parent_fd;
    (void)component;
    (void)opened;
    errno = ENOTSUP;
    return -1;
#endif
}

static bool exec_path_candidate_errno_is_fatal(int candidate_errno) {
    switch (candidate_errno) {
        case ENOENT:
        case ENOTDIR:
        case EACCES:
        case EPERM:
        case ELOOP:
        case EINVAL:
        case ENAMETOOLONG:
            return false;
        default:
            return true;
    }
}

/* Validate the spelling supplied by PATH as well as its canonical target.
 * This prevents `/tmp/safe-looking-link -> /usr/bin` from erasing the hostile
 * 01777 lexical ancestor during realpath().  A symlink is accepted only when
 * it is itself held in an already-pinned trusted directory and owned by root
 * or this uid; the separately pinned canonical walk validates its target. */
static bool exec_lexical_path_is_trusted(const char *path) {
    if (!path || path[0] != '/' || strlen(path) >= MAX_PATH_LEN) {
        errno = EINVAL;
        return false;
    }

    struct stat root_st;
    int root_fd = exec_open_directory_at(AT_FDCWD, "/", &root_st);
    if (root_fd < 0) return false;

    const char *cursor = path + 1;
    while (*cursor) {
        const char *slash = strchr(cursor, '/');
        size_t length = slash ? (size_t)(slash - cursor) : strlen(cursor);
        if (length == 0) {
            cursor++;
            continue;
        }
        if (length >= MAX_PATH_LEN) {
            close(root_fd);
            errno = EINVAL;
            return false;
        }

        char component[MAX_PATH_LEN];
        memcpy(component, cursor, length);
        component[length] = '\0';
        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
            close(root_fd);
            errno = EINVAL;
            return false;
        }

        if (!slash) {
            struct stat leaf;
            if (fstatat(root_fd, component, &leaf,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                int stat_errno = errno;
                close(root_fd);
                errno = stat_errno;
                return false;
            }
            close(root_fd);
            if (!exec_owner_is_allowed(leaf.st_uid)) {
                errno = EACCES;
                return false;
            }
            return true;
        }

        struct stat next_st;
        int next_fd = exec_open_directory_at(root_fd, component, &next_st);
        if (next_fd >= 0) {
            close(root_fd);
            root_fd = next_fd;
            cursor = slash + 1;
            continue;
        }
        int open_errno = errno;

        /* A no-follow open can fail for a policy reason that merits a symlink
         * probe, or for an operational reason that must stop PATH selection.
         * Preserve the primary operational error even when fstatat would
         * successfully describe the same component. */
        if (exec_path_candidate_errno_is_fatal(open_errno)) {
            close(root_fd);
            errno = open_errno;
            return false;
        }

        struct stat link_st;
        if (fstatat(root_fd, component, &link_st,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            int stat_errno = errno;
            close(root_fd);
            errno = stat_errno;
            return false;
        }
        close(root_fd);
        if (!S_ISLNK(link_st.st_mode) ||
            !exec_owner_is_allowed(link_st.st_uid)) {
            errno = EACCES;
            return false;
        }
        return true;
    }
    close(root_fd);
    errno = EINVAL;
    return false;
}

static int exec_open_canonical(const char *canonical,
                               struct stat *file_stat) {
    if (!canonical || canonical[0] != '/' ||
        canonical[1] == '\0' || strlen(canonical) >= MAX_PATH_LEN) {
        errno = EINVAL;
        return -1;
    }

    struct stat root_st;
    int dir_fd = exec_open_directory_at(AT_FDCWD, "/", &root_st);
    if (dir_fd < 0) return -1;

    const char *cursor = canonical + 1;
    for (;;) {
        const char *slash = strchr(cursor, '/');
        size_t length = slash ? (size_t)(slash - cursor) : strlen(cursor);
        if (length == 0 || length >= MAX_PATH_LEN) {
            close(dir_fd);
            errno = EINVAL;
            return -1;
        }

        char component[MAX_PATH_LEN];
        memcpy(component, cursor, length);
        component[length] = '\0';
        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
            close(dir_fd);
            errno = EINVAL;
            return -1;
        }

        if (slash) {
            struct stat opened;
            int next_fd = exec_open_directory_at(dir_fd, component, &opened);
            close(dir_fd);
            if (next_fd < 0) return -1;
            dir_fd = next_fd;
            cursor = slash + 1;
            continue;
        }

#if defined(O_NOFOLLOW)
        /* Acquire a metadata/execute-only handle first. This cannot block on
         * a FIFO and does not activate a device before regular-file/type and
         * trust validation. A second readable handle is identity-matched for
         * bounded format/shebang parsing. */
        int metadata_flags = O_NOFOLLOW;
#if defined(__linux__) && defined(O_PATH)
        metadata_flags |= O_PATH;
#elif defined(__FreeBSD__) && defined(O_EXEC)
        metadata_flags |= O_EXEC | O_NONBLOCK;
#elif defined(O_EVTONLY)
        metadata_flags |= O_EVTONLY | O_NONBLOCK;
#else
        metadata_flags |= O_RDONLY | O_NONBLOCK;
#endif
#ifdef O_CLOEXEC
        metadata_flags |= O_CLOEXEC;
#endif
        int metadata_fd = openat(dir_fd, component, metadata_flags);
        int open_errno = errno;
        if (metadata_fd < 0) {
            close(dir_fd);
            errno = open_errno;
            return -1;
        }
        if (fstat(metadata_fd, file_stat) != 0) {
            int saved_errno = errno;
            close(metadata_fd);
            close(dir_fd);
            errno = saved_errno;
            return -1;
        }
        if (!exec_file_stat_is_trusted(file_stat)) {
            close(metadata_fd);
            close(dir_fd);
            errno = EACCES;
            return -1;
        }

        int read_flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW;
#ifdef O_CLOEXEC
        read_flags |= O_CLOEXEC;
#endif
        int fd = openat(dir_fd, component, read_flags);
        int read_errno = errno;
        if (fd < 0) {
            close(metadata_fd);
            close(dir_fd);
            errno = read_errno;
            return -1;
        }
        struct stat readable_stat;
        if (fstat(fd, &readable_stat) != 0) {
            int saved_errno = errno;
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = saved_errno;
            return -1;
        }
        if (!exec_stat_identity_matches(file_stat, &readable_stat)) {
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = EACCES;
            return -1;
        }
        if (!exec_command_acl_is_trusted(fd, EXEC_ACL_TARGET_LEAF)) {
            int saved_errno = errno ? errno : EIO;
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = saved_errno;
            return -1;
        }

        if (exec_leaf_is_effectively_executable_at(dir_fd, component) != 0) {
            int saved_errno = errno;
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = saved_errno;
            return -1;
        }

        /* Seal the pathname-based ACL/noexec probe back to both pinned
         * handles. ACL edits update ctime; leaf replacement changes inode.
         * A later metadata mutation is caught again in the child immediately
         * before descriptor execution. */
        struct stat named_after_access;
        struct stat readable_after_access;
        if (fstatat(dir_fd, component, &named_after_access,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            fstat(fd, &readable_after_access) != 0) {
            int saved_errno = errno;
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = saved_errno;
            return -1;
        }
        if (!exec_stat_identity_matches(file_stat, &named_after_access) ||
            !exec_stat_identity_matches(file_stat,
                                        &readable_after_access)) {
            close(fd);
            close(metadata_fd);
            close(dir_fd);
            errno = EACCES;
            return -1;
        }
        close(metadata_fd);
        close(dir_fd);
#ifndef O_CLOEXEC
        int fd_flags = fcntl(fd, F_GETFD, 0);
        if (fd_flags < 0 ||
            fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
#endif
        return fd;
#else
        close(dir_fd);
        errno = ENOTSUP;
        return -1;
#endif
    }
}

static int exec_open_candidate(const char *candidate, char *resolved,
                               size_t resolved_size, struct stat *file_stat) {
    if (!exec_lexical_path_is_trusted(candidate)) return -1;

    char *canonical = realpath(candidate, NULL);
    if (!canonical) return -1;
    if (strlen(canonical) >= MAX_PATH_LEN ||
        safe_strncpy(resolved, canonical, resolved_size) != 0) {
        free(canonical);
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = exec_open_canonical(canonical, file_stat);
    free(canonical);
    return fd;
}

typedef enum {
    EXEC_CANDIDATE_FOUND = 0,
    EXEC_CANDIDATE_SKIP,
    EXEC_CANDIDATE_FATAL
} exec_candidate_outcome_t;

static exec_candidate_outcome_t exec_candidate_classify_errno(
    int candidate_errno) {
    /* Resource exhaustion, storage failure, stale handles, and every unknown
     * operational error are fatal. Only ordinary absence and explicit
     * trust/policy rejection permit selection of a later PATH entry. */
    return exec_path_candidate_errno_is_fatal(candidate_errno)
               ? EXEC_CANDIDATE_FATAL
               : EXEC_CANDIDATE_SKIP;
}

static int open_trusted_command(const char *name, char *resolved,
                                size_t resolved_size,
                                struct stat *file_stat) {
    if (!name || !resolved || resolved_size == 0 || !file_stat || !*name) {
        errno = EINVAL;
        return -1;
    }

    if (strchr(name, '/')) {
        if (name[0] != '/') {
            errno = EINVAL;
            return -1;
        }
        return exec_open_candidate(name, resolved, resolved_size, file_stat);
    }

    const char *path_env = getenv("PATH");
    if (!path_env || !*path_env) {
        path_env = "/usr/local/bin:/usr/bin:/bin";
    }

    const char *cursor = path_env;
#ifdef GITSWITCH_TESTING
    unsigned int candidate_ordinal = 0;
#endif
    while (*cursor) {
        const char *colon = strchr(cursor, ':');
        size_t dir_length = colon ? (size_t)(colon - cursor) : strlen(cursor);
        size_t name_length = strlen(name);
        char candidate[MAX_PATH_LEN];

        if (dir_length > 0 && cursor[0] == '/' &&
            dir_length + 1 + name_length + 1 <= sizeof(candidate)) {
#ifdef GITSWITCH_TESTING
            candidate_ordinal++;
#endif
            memcpy(candidate, cursor, dir_length);
            candidate[dir_length] = '/';
            memcpy(candidate + dir_length + 1, name, name_length + 1);
            int fd;
#ifdef GITSWITCH_TESTING
            if (g_test_path_candidate_failure_errno != 0 &&
                candidate_ordinal ==
                    g_test_path_candidate_failure_ordinal) {
                errno = g_test_path_candidate_failure_errno;
                g_test_path_candidate_failure_errno = 0;
                g_test_path_candidate_failure_ordinal = 0;
                fd = -1;
            } else
#endif
            {
                fd = exec_open_candidate(candidate, resolved, resolved_size,
                                         file_stat);
            }
            if (fd >= 0) return fd;
            int candidate_errno = errno;
            if (exec_candidate_classify_errno(candidate_errno) ==
                EXEC_CANDIDATE_FATAL) {
                errno = candidate_errno;
                return -1;
            }
        }

        if (!colon) break;
        cursor = colon + 1;
    }
    errno = ENOENT;
    return -1;
}

int find_command_path(const char *name, char *buf, size_t size) {
    struct stat file_stat;
    trusted_script_launch_t launch;
    const char *probe_argv[] = {name, NULL};
    int fd = open_trusted_command(name, buf, size, &file_stat);
    if (fd < 0) return -1;

    /* A dependency probe must answer the same parent-side eligibility
     * question as the default runner. Reuse its pinned-descriptor format and
     * shebang validation instead of accepting a file run_argv would reject
     * before fork (AR-08 L10). The synthetic argv is sufficient because this
     * path validates launch shape but does not execute the constructed argv. */
    if (prepare_trusted_script_launch(fd, probe_argv, &launch) != 0) {
        int saved_errno = errno;
        close(fd);
        trusted_script_launch_cleanup(&launch);
        errno = saved_errno;
        return -1;
    }
    trusted_script_launch_cleanup(&launch);
    close(fd);
    return 0;
}

bool command_exists(const char *command) {
    char path[MAX_PATH_LEN];
    if (!command) return false;
    return find_command_path(command, path, sizeof(path)) == 0;
}

bool process_is_running(pid_t pid) {
    if (pid <= 0) return false;
    return kill(pid, 0) == 0;
}

/* Environment utilities */

int get_env_var(const char *name, char *buffer, size_t buffer_size) {
    const char *value;
    
    if (!name || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_env_var");
        return -1;
    }
    
    value = getenv(name);
    if (!value) {
        buffer[0] = '\0';
        return 1; /* Not an error, just not found */
    }
    
    if (strlen(value) >= buffer_size) {
        set_error(ERR_INVALID_ARGS, "Environment variable value too long");
        return -1;
    }
    
    strcpy(buffer, value); /* Flawfinder: ignore — length-checked above */
    return 0;
}

int set_env_var(const char *name, const char *value, bool overwrite) {
    if (!name || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to set_env_var");
        return -1;
    }
    
    if (setenv(name, value, overwrite ? 1 : 0) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

int unset_env_var(const char *name) {
    if (!name) {
        set_error(ERR_INVALID_ARGS, "NULL name to unset_env_var");
        return -1;
    }
    
    if (unsetenv(name) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unset environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

/* Validation utilities */

bool validate_email(const char *email) {
    /* Compile the constant pattern once and reuse it. This is called 2N+ times
     * per config load (schema + security validation per account, plus on
     * switch), on the every-shell init/resume path, so recompiling the same
     * regex each time was pure waste. Single-threaded, so a static cache is safe. */
    static regex_t regex;
    static bool compiled = false;

    /* >= not >: account_t.email[MAX_EMAIL_LEN] stores at most MAX_EMAIL_LEN-1
     * chars plus the NUL, so an exactly-MAX_EMAIL_LEN-char address would pass
     * here only to have the copy into the account fail (AR-03 L1). Matches
     * validate_name's bound. */
    if (!email || strlen(email) >= MAX_EMAIL_LEN) {
        return false;
    }

    if (!compiled) {
        /* Basic email regex - not RFC compliant but good enough for git configs */
        const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            return false;
        }
        compiled = true;
    }

    return regexec(&regex, email, 0, NULL, 0) == 0;
}

/* AR-06 F26: a new account name that collides with a command keyword or is
 * purely numeric can never be switched to by name (the dispatcher matches the
 * keyword, and a bare number is read as an account ID first), and completion
 * would feed such a name straight back as a destructive command. Reject at the
 * CREATION/rename path only — NOT in validate_name, which also gates loads and
 * runtime teardown, so an already-created such account can still be reset/
 * removed. Numeric = one or more ASCII digits with no other characters. */
bool name_is_reserved_for_commands(const char *name) {
    static const char *const keywords[] = {
        "add", "edit", "list", "ls", "remove", "rm", "delete", "status",
        "doctor", "health", "config", "init", "resume", "reset", "switch",
        NULL
    };
    if (!name || !*name) {
        return false;
    }
    for (size_t i = 0; keywords[i]; i++) {
        if (strcasecmp(name, keywords[i]) == 0) {
            return true;
        }
    }
    bool all_digits = true;
    for (const char *p = name; *p; p++) {
        if (*p < '0' || *p > '9') {
            all_digits = false;
            break;
        }
    }
    return all_digits;
}

bool validate_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) >= MAX_NAME_LEN) {
        return false;
    }

    /* The account name doubles as a filesystem path component (the isolated
     * GNUPGHOME <base>/<name> and the ssh-agent.<name>.sock socket) as well as
     * the git user.name. So it must stay a single, safe path component while
     * still allowing ordinary display names with spaces and parentheses
     * ("Jane Doe (Work)"). Reject path separators and traversal, control
     * characters, and a leading '-'/'.' (option-like / hidden / '..'). */
    if (name[0] == '-' || name[0] == '.') {
        return false;
    }
    if (strstr(name, "..") != NULL) {
        return false;
    }
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f) {
            return false;
        }
    }
    /* Names are printed interactively before config admission and also key
     * filesystem/runtime state. Reject malformed UTF-8 and every invisible or
     * terminal-affecting codepoint at this first shared boundary so no prompt,
     * summary, log, or later validation error can echo hostile identity text. */
    if (!text_is_tty_safe(name)) {
        return false;
    }

    /* Reserve "current": the per-account GNUPGHOME is <base>/<name>, and the
     * stable GPG symlink the shell integration exports is <base>/current. An
     * account literally named "current" would create a real directory there,
     * so the symlink could never be installed/retargeted and every other
     * account's switch would silently keep pointing GNUPGHOME at this one. */
    if (strcasecmp(name, "current") == 0) {
        return false;
    }

    /* Name should contain at least one non-whitespace character */
    for (const char *p = name; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            return true;
        }
    }

    return false;
}

/* ssh-1 (shared; moved from git_ops.c for AR-02 #10): the account SSH key
 * path ends up in two security-sensitive sinks, and EACH sink must apply this
 * check itself rather than assume the other (or the TOML-load sanitizer)
 * already did:
 *
 *  1. core.sshCommand — the ONE git config value git hands to /bin/sh. The
 *     path is wrapped in single quotes; inside '...' the shell treats every
 *     byte literally EXCEPT a single quote, which ends the quote and lets a
 *     crafted path smuggle extra ssh options (-oProxyCommand=..., i.e.
 *     arbitrary code on the next fetch). Guarded in git_configure_ssh.
 *  2. ~/.ssh/config — the same path is emitted as an "IdentityFile <path>"
 *     line by the host-alias support. There, a \n or \r starts a new line,
 *     i.e. injects an arbitrary ssh_config keyword (ProxyCommand again), and
 *     a quote breaks the directive's tokenization. Guarded in
 *     ssh_configure_host_alias.
 *
 * So reject both quote characters and every control byte (\n and \r included)
 * up front, before the path is probed or written anywhere. A real SSH key
 * path never needs any of these. */
bool is_safe_ssh_key_path(const char *path) {
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f || c == '\'' || c == '"') {
            return false;
        }
    }
    return true;
}

/* Shared strict UTF-8 decoding and terminal-safety policy — moved here from
 * config.c so the TOML parser's raw-buffer charset gate can apply the same
 * rules instead of rejecting every byte >= 0x80 (AR-02 #6). See utils.h for
 * the full rationale. */
size_t utf8_decode(const unsigned char *s, size_t available,
                   uint32_t *cp_out) {
    if (!s || !cp_out || available == 0) {
        return 0;
    }

    unsigned char b0 = s[0];

    if (b0 < 0x80) {
        *cp_out = b0;
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if (available < 2) return 0;
        if ((s[1] & 0xC0) != 0x80) return 0;
        *cp_out = ((uint32_t)(b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if (available < 3) return 0;
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (b0 == 0xE0 && s[1] < 0xA0) return 0;              /* overlong */
        if (b0 == 0xED && s[1] >= 0xA0) return 0;             /* surrogate */
        *cp_out = ((uint32_t)(b0 & 0x0F) << 12) |
                  ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if (available < 4) return 0;
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        if (b0 == 0xF0 && s[1] < 0x90) return 0;              /* overlong */
        if (b0 == 0xF4 && s[1] > 0x8F) return 0;              /* > U+10FFFF */
        *cp_out = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
                  ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0; /* 0x80-0xC1 lead (bare continuation/overlong) or 0xF5+ */
}

bool tty_safe_codepoint(uint32_t cp) {
    /* Unicode 16.0 Default_Ignorable_Code_Point ranges. These characters are
     * intentionally invisible or alter the display/order of neighboring
     * glyphs. That is useful in rich text, but unsafe in identity text printed
     * by list/status: an account can look empty, hide a suffix, or visually
     * reorder trusted text. Reject the complete property instead of chasing
     * only the currently abused bidi controls. This deliberately also rejects
     * variation selectors and joiners; account identity remains the visible
     * base text rather than an invisible presentation sequence. Ordinary
     * combining marks (for example U+0301) remain allowed. */
    static const struct {
        uint32_t first;
        uint32_t last;
    } default_ignorable_ranges[] = {
        {0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C},
        {0x115F, 0x1160}, {0x17B4, 0x17B5}, {0x180B, 0x180F},
        {0x200B, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x206F},
        {0x3164, 0x3164}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF},
        {0xFFA0, 0xFFA0}, {0xFFF0, 0xFFF8},
        {0x1BCA0, 0x1BCA3}, {0x1D173, 0x1D17A},
        {0xE0000, 0xE0FFF}
    };

    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) ||
        cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F) ||
        cp == 0x2028 || cp == 0x2029) {
        return false;
    }

    for (size_t i = 0;
         i < sizeof(default_ignorable_ranges) /
                 sizeof(default_ignorable_ranges[0]);
         i++) {
        if (cp >= default_ignorable_ranges[i].first &&
            cp <= default_ignorable_ranges[i].last) {
            return false;
        }
    }
    return true;
}

bool text_is_tty_safe(const char *text) {
    const unsigned char *cursor;
    size_t remaining;

    if (!text) return false;
    cursor = (const unsigned char *)text;
    remaining = strlen(text);
    while (remaining > 0) {
        uint32_t codepoint;
        size_t consumed = utf8_decode(cursor, remaining, &codepoint);

        if (consumed == 0 || !tty_safe_codepoint(codepoint)) {
            return false;
        }
        cursor += consumed;
        remaining -= consumed;
    }
    return true;
}

bool validate_key_id(const char *key_id) {
    const char *p;
    size_t digits;

    if (!key_id || *key_id == '\0' ||
        strlen(key_id) >= MAX_GPG_SELECTOR_LEN) {
        return false;
    }

    /* Accept the common "0x" prefix that `gpg -k` and keyservers display —
     * gpg itself accepts a 0x-prefixed key id, so rejecting it only tripped up
     * users pasting the id exactly as shown. The remainder must be hex. */
    p = key_id;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    digits = strlen(p);
    if (digits == 0 || digits > MAX_GPG_FINGERPRINT_LEN - 1) {
        return false;
    }
    for (; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return false;
        }
    }

    return true;
}

bool validate_file_path(const char *path) {
    char expanded[MAX_PATH_LEN];
    
    if (!path || strlen(path) == 0 || strlen(path) >= MAX_PATH_LEN) {
        return false;
    }
    
    /* Expand path and check if it exists */
    if (expand_path(path, expanded, sizeof(expanded)) != 0) {
        return false;
    }
    
    return path_exists(expanded);
}

/* Security utilities */

void secure_zero_memory(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    /* Use explicit_bzero if available, otherwise volatile memset */
#ifdef __GLIBC__
    explicit_bzero(ptr, size);
#else
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
#endif
}

int generate_random_string(char *buffer, size_t buffer_size, const char *charset) {
    size_t charset_len;
    size_t i;
    FILE *urandom;
    
    if (!buffer || buffer_size == 0 || !charset) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to generate_random_string");
        return -1;
    }
    
    charset_len = strlen(charset);
    if (charset_len == 0) {
        set_error(ERR_INVALID_ARGS, "Empty charset");
        return -1;
    }
    
    urandom = fopen("/dev/urandom", "rbe");
    if (!urandom) {
        set_system_error(ERR_FILE_IO, "Failed to open /dev/urandom");
        return -1;
    }
    
    for (i = 0; i < buffer_size - 1; i++) {
        unsigned char rand_byte;
        if (fread(&rand_byte, 1, 1, urandom) != 1) {
            set_system_error(ERR_FILE_IO, "Failed to read random data");
            fclose(urandom);
            return -1;
        }
        buffer[i] = charset[rand_byte % charset_len];
    }
    
    buffer[buffer_size - 1] = '\0';
    fclose(urandom);
    
    return 0;
}

bool account_incarnation_is_valid(const char *incarnation) {
    if (!incarnation ||
        strnlen(incarnation, ACCOUNT_INCARNATION_LEN) !=
            ACCOUNT_INCARNATION_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < ACCOUNT_INCARNATION_HEX_LEN; i++) {
        unsigned char byte = (unsigned char)incarnation[i];
        if (!((byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              (byte >= (unsigned char)'A' && byte <= (unsigned char)'F'))) {
            return false;
        }
    }
    return true;
}

bool check_file_permissions_safe(const char *file_path, mode_t expected_mode) {
    mode_t actual_mode;
    
    if (!file_path) return false;
    
    if (get_file_permissions(file_path, &actual_mode) != 0) {
        return false;
    }
    
    /* Check if permissions are as expected or more restrictive */
    return (actual_mode & 07777) == expected_mode;
}

/* Configuration utilities */

int get_config_directory(char *config_dir, size_t dir_size) {
    char home[MAX_PATH_LEN];
    
    if (!config_dir || dir_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_config_directory");
        return -1;
    }
    
    if (get_home_directory(home, sizeof(home)) != 0) {
        return -1;
    }
    
    if (snprintf(config_dir, dir_size, "%s/%s", home, DEFAULT_CONFIG_DIR) >= (int)dir_size) {
        set_error(ERR_INVALID_ARGS, "Config directory path too long");
        return -1;
    }
    
    return 0;
}

int ensure_config_directory_exists(void) {
    char config_dir[MAX_PATH_LEN];
    
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    if (!is_directory(config_dir)) {
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        log_info("Created config directory: %s", config_dir);
    }
    
    return 0;
}

/* Terminal utilities */

bool is_terminal(int fd) {
    return isatty(fd) == 1;
}

int get_terminal_size(int *width, int *height) {
    struct winsize ws;

    if (!width || !height) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to get_terminal_size");
        return -1;
    }

    /* Skip the ioctl when stdout isn't a terminal (piped, redirected,
     * command-substituted). Return failure silently so callers fall back to
     * their default width without spamming stderr on every invocation. */
    if (!isatty(STDOUT_FILENO)) {
        return -1;
    }

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        /* AR-12 U5: fail silently like the isatty and 0x0 branches —
         * display_init falls back to defaults and returns success, so a
         * live global error here would surface in unrelated later
         * diagnostics. */
        return -1;
    }

    /* AR-10 L33: a fresh pty reports 0x0 with a SUCCEEDING ioctl. Accepting
     * that as a valid size collapsed display layout (display_init only falls
     * back to 80x24 on nonzero return); report failure so callers use their
     * defaults. */
    if (ws.ws_col == 0 || ws.ws_row == 0) {
        return -1;
    }

    *width = ws.ws_col;
    *height = ws.ws_row;

    return 0;
}

#ifdef GITSWITCH_TESTING
typedef void (*echo_tcsetattr_test_hook_fn)(int fd);

static int g_test_echo_tcsetattr_errno;
static echo_tcsetattr_test_hook_fn g_test_echo_tcsetattr_hook;

void gitswitch_test_fail_echo_tcsetattr(int system_errno);
echo_tcsetattr_test_hook_fn gitswitch_test_set_echo_tcsetattr_hook(
    echo_tcsetattr_test_hook_fn hook);

void gitswitch_test_fail_echo_tcsetattr(int system_errno) {
    g_test_echo_tcsetattr_errno = system_errno > 0 ? system_errno : 0;
}

echo_tcsetattr_test_hook_fn gitswitch_test_set_echo_tcsetattr_hook(
    echo_tcsetattr_test_hook_fn hook) {
    echo_tcsetattr_test_hook_fn previous = g_test_echo_tcsetattr_hook;
    g_test_echo_tcsetattr_hook = hook;
    return previous;
}
#endif

static int terminal_echo_tcsetattr(int fd, const struct termios *termios) {
#ifdef GITSWITCH_TESTING
    if (g_test_echo_tcsetattr_hook) {
        echo_tcsetattr_test_hook_fn hook = g_test_echo_tcsetattr_hook;
        g_test_echo_tcsetattr_hook = NULL;
        hook(fd);
    }
    if (g_test_echo_tcsetattr_errno != 0) {
        int injected_errno = g_test_echo_tcsetattr_errno;
        g_test_echo_tcsetattr_errno = 0;
        errno = injected_errno;
        return -1;
    }
#endif
    return tcsetattr(fd, TCSANOW, termios);
}

static bool terminal_echo_identity_matches(const struct stat *st) {
    return st && st->st_dev == g_terminal_echo_state.dev &&
           st->st_ino == g_terminal_echo_state.ino &&
           st->st_rdev == g_terminal_echo_state.rdev;
}

static int terminal_echo_fail(const char *action, const char *reason,
                              int system_errno) {
    errno = system_errno;
    set_system_error(ERR_SYSTEM_CALL, "Failed to %s: %s", action, reason);
    errno = system_errno;
    return -1;
}

static int terminal_echo_validate_owner(const char *action) {
    struct stat retained;
    struct stat current;

    if (fstat(g_terminal_echo_state.fd, &retained) != 0) {
        int saved_errno = errno;
        return terminal_echo_fail(action,
                                  "retained terminal descriptor is unavailable",
                                  saved_errno);
    }
    if (!terminal_echo_identity_matches(&retained)) {
        return terminal_echo_fail(action,
                                  "retained terminal descriptor changed identity",
                                  ESTALE);
    }
    if (fstat(STDIN_FILENO, &current) != 0) {
        int saved_errno = errno;
        return terminal_echo_fail(action,
                                  "standard input is unavailable",
                                  saved_errno);
    }
    if (!terminal_echo_identity_matches(&current)) {
        return terminal_echo_fail(action,
                                  "standard input identifies another terminal",
                                  ESTALE);
    }
    return 0;
}

int disable_echo(void) {
    struct termios original;
    struct termios new_termios;
    struct stat retained;
    struct stat current;
    int retained_fd;

    if (g_terminal_echo_state.active) {
        if (terminal_echo_validate_owner("disable terminal echo") != 0) {
            return -1;
        }
        clear_error();
        return 0;
    }

    retained_fd = dup_cloexec(STDIN_FILENO, STDERR_FILENO + 1);
    if (retained_fd < 0) {
        int saved_errno = errno;
        return terminal_echo_fail("disable terminal echo",
                                  "could not retain standard input",
                                  saved_errno);
    }

    if (fstat(retained_fd, &retained) != 0 ||
        fstat(STDIN_FILENO, &current) != 0) {
        int saved_errno = errno;
        close(retained_fd);
        return terminal_echo_fail("disable terminal echo",
                                  "could not inspect terminal identity",
                                  saved_errno);
    }
    if (retained.st_dev != current.st_dev ||
        retained.st_ino != current.st_ino ||
        retained.st_rdev != current.st_rdev) {
        close(retained_fd);
        return terminal_echo_fail("disable terminal echo",
                                  "standard input changed while being retained",
                                  ESTALE);
    }

    if (tcgetattr(retained_fd, &original) != 0) {
        int saved_errno = errno;
        close(retained_fd);
        return terminal_echo_fail(
            "disable terminal echo",
            "could not read the original terminal state", saved_errno);
    }

    new_termios = original;
    new_termios.c_lflag &= ~ECHO;

    if (terminal_echo_tcsetattr(retained_fd, &new_termios) != 0) {
        int saved_errno = errno;
        close(retained_fd);
        return terminal_echo_fail("disable terminal echo",
                                  "terminal rejected the no-echo state",
                                  saved_errno);
    }

    g_terminal_echo_state.fd = retained_fd;
    g_terminal_echo_state.dev = retained.st_dev;
    g_terminal_echo_state.ino = retained.st_ino;
    g_terminal_echo_state.rdev = retained.st_rdev;
    g_terminal_echo_state.original = original;
    g_terminal_echo_state.active = true;
    clear_error();
    return 0;
}

int enable_echo(void) {
    int retained_fd;

    if (!g_terminal_echo_state.active) {
        clear_error();
        return 0;
    }

    if (terminal_echo_validate_owner("restore terminal echo") != 0) {
        return -1;
    }

    /* Keep ownership until the retained terminal accepts the restore. A
     * transient failure must remain retryable and a replacement standard
     * input must never receive another terminal's saved attributes. */
    if (terminal_echo_tcsetattr(g_terminal_echo_state.fd,
                                &g_terminal_echo_state.original) != 0) {
        int saved_errno = errno;
        return terminal_echo_fail("restore terminal echo",
                                  "terminal rejected the original state",
                                  saved_errno);
    }

    retained_fd = g_terminal_echo_state.fd;
    memset(&g_terminal_echo_state, 0, sizeof(g_terminal_echo_state));
    g_terminal_echo_state.fd = -1;
    close(retained_fd);
    clear_error();
    return 0;
}

/* Time utilities */

void get_current_time_string(char *buffer, size_t buffer_size) {
    time_t now;
    struct tm *tm_info;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "UNKNOWN", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
}

void get_timestamp_string(char *buffer, size_t buffer_size) {
    time_t now;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    snprintf(buffer, buffer_size, "%ld", (long)now);
}

bool is_timestamp_expired(time_t timestamp, int max_age_seconds) {
    time_t now;
    time(&now);
    return (now - timestamp) > max_age_seconds;
}

/* Comparison utilities */

int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int compare_accounts_by_id(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    if (acc_a->id < acc_b->id) return -1;
    if (acc_a->id > acc_b->id) return 1;
    return 0;
}

int compare_accounts_by_name(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    return strcmp(acc_a->name, acc_b->name);
}

/* Array utilities */

void sort_accounts(account_t *accounts, size_t count, 
                   int (*compare)(const void *, const void *)) {
    if (accounts && count > 1 && compare) {
        qsort(accounts, count, sizeof(account_t), compare);
    }
}

account_t *find_account_in_array(account_t *accounts, size_t count, 
                                 const char *identifier) {
    if (!accounts || !identifier || count == 0) {
        return NULL;
    }
    
    /* Try numeric ID first */
    char *endptr;
    unsigned long id = strtoul(identifier, &endptr, 10);
    if (*endptr == '\0') {
        /* It's a number - search by ID */
        for (size_t i = 0; i < count; i++) {
            if (accounts[i].id == (uint32_t)id) {
                return &accounts[i];
            }
        }
    }
    
    /* Search by name or description */
    for (size_t i = 0; i < count; i++) {
        if (strstr(accounts[i].name, identifier) ||
            strstr(accounts[i].description, identifier) ||
            strcmp(accounts[i].email, identifier) == 0) {
            return &accounts[i];
        }
    }
    
    return NULL;
}

/* Memory utilities */

void *safe_memset(void *ptr, int value, size_t size) {
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memset");
        return NULL;
    }
    
    return memset(ptr, value, size);
}

void *safe_memcpy(void *dest, const void *src, size_t size) {
    if (!dest || !src || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memcpy");
        return NULL;
    }
    
    return memcpy(dest, src, size);
}

int safe_mlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_mlock");
        return -1;
    }
    
    if (mlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to lock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

int safe_munlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_munlock");
        return -1;
    }
    
    if (munlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unlock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

/* Debug utilities */

void dump_account(const account_t *account) {
    if (!account) {
        log_debug("Account: NULL");
        return;
    }
    
    log_debug("Account dump:");
    log_debug("  ID: %u", account->id);
    log_debug("  Name: %s", account->name);
    log_debug("  Email: %s", account->email);
    log_debug("  Description: %s", account->description);
    log_debug("  SSH enabled: %s", account->ssh_enabled ? "yes" : "no");
    log_debug("  SSH key: %s", account->ssh_key_path);
    log_debug("  GPG enabled: %s", account->gpg_enabled ? "yes" : "no");
    log_debug("  GPG signing: %s", account->gpg_signing_enabled ? "yes" : "no");
    log_debug("  GPG key: %s", account->gpg_key_id);
}

void dump_config(const config_t *config) {
    if (!config) {
        log_debug("Config: NULL");
        return;
    }
    
    log_debug("Config dump:");
    log_debug("  Default scope: %d", config->default_scope);
    log_debug("  Config path: %s", config->config_path);
    log_debug("  Verbose: %s", config->verbose ? "yes" : "no");
    log_debug("  Dry run: %s", config->dry_run ? "yes" : "no");
    log_debug("  Color output: %s", config->color_output ? "yes" : "no");
}

void dump_context(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        log_debug("Context: NULL");
        return;
    }
    
    log_debug("Context dump:");
    log_debug("  Account count: %zu", ctx->account_count);
    log_debug("  Current account: %s", 
              ctx->current_account ? ctx->current_account->name : "none");
    
    dump_config(&ctx->config);
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        dump_account(&ctx->accounts[i]);
    }
}
