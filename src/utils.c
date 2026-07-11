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
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <regex.h>

#if defined(__linux__)
#include <sys/mman.h>
#include <linux/random.h>
#include <sys/syscall.h>
#endif

#include "utils.h"
#include "error.h"
#include "signals.h"

/* Linux, macOS, and FreeBSD can pin a directory descriptor without following
 * a replaced final-component symlink. Other platforms fail closed rather than
 * attempt a pathname chmod that could be redirected after validation. */
#if defined(O_NOFOLLOW) && defined(O_DIRECTORY)
#define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 1
#else
#define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 0
#endif

/* Static variables for terminal state management */
static struct termios g_original_termios;
static bool g_echo_disabled = false;

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
    size_t parent_slot;
    size_t leaf_slot;
    size_t file_slot;
} private_lock_context_t;

typedef struct {
    bool active;
    int lock_fd;
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
    
    if (!home) {
        /* Fall back to password database */
        struct passwd *pw = getpwuid(getuid());
        if (!pw) {
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

int create_directory_recursive(const char *path, mode_t mode) {
    if (!path || !*path) {
        /* Reject an empty path too (AR-06 F78): the trailing-slash check below
         * reads temp_path[len-1], an out-of-bounds stack read when len == 0. */
        set_error(ERR_INVALID_ARGS, "NULL or empty path to create_directory_recursive");
        return -1;
    }

    char temp_path[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    if ((size_t)snprintf(temp_path, sizeof(temp_path), "%s", path) >= sizeof(temp_path)) {
        set_error(ERR_INVALID_ARGS, "Path too long");
        return -1;
    }

    len = strlen(temp_path);
    if (temp_path[len - 1] == '/') {
        temp_path[len - 1] = '\0';
    }
    
    for (p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
                set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
        set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
        return -1;
    }

    return 0;
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

int open_runtime_parent(char *path, size_t path_size) {
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    struct stat before;
    struct stat opened;
    struct stat after;
    bool use_xdg = false;
    int fd;

    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid runtime-parent output buffer");
        return -1;
    }

    if (xdg && *xdg) {
        if (lstat(xdg, &before) == 0) {
            use_xdg = true;
        } else if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect XDG_RUNTIME_DIR: %s", xdg);
            return -1;
        }
    }

    if (use_xdg) {
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode) ||
            before.st_uid != getuid() || (before.st_mode & 077) != 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "XDG_RUNTIME_DIR must be a private self-owned directory: %s",
                      xdg);
            return -1;
        }
        if (safe_strncpy(path, xdg, path_size) != 0) {
            set_error(ERR_INVALID_PATH, "XDG_RUNTIME_DIR path is too long");
            return -1;
        }
        fd = open_directory_nofollow(path, &opened);
        if (fd < 0 || opened.st_uid != getuid() ||
            (opened.st_mode & 077) != 0 || !same_fs_identity(&before, &opened)) {
            if (fd >= 0) close(fd);
            set_error(ERR_PERMISSION_DENIED,
                      "XDG_RUNTIME_DIR changed or is unsafe: %s", path);
            return -1;
        }
        if (lstat(path, &after) != 0 || !S_ISDIR(after.st_mode) ||
            !same_fs_identity(&opened, &after)) {
            close(fd);
            set_error(ERR_PERMISSION_DENIED,
                      "XDG_RUNTIME_DIR changed while being opened: %s", path);
            return -1;
        }
        return fd;
    }

    if (safe_strncpy(path, "/tmp", path_size) != 0) {
        set_error(ERR_INVALID_PATH, "Temporary runtime-parent path is too long");
        return -1;
    }
    fd = open_directory_nofollow(path, &opened);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot open runtime parent: %s", path);
        return -1;
    }
    return fd;
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

static int private_lock_dup_cloexec(int fd) {
    int copy = dup(fd);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(copy);
        errno = saved_errno;
        return -1;
    }
    return copy;
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
    g_private_lock_pid = pid;
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
                                     bool nonblocking) {
    struct stat opened;
    struct stat entry;
    struct stat leaf;
    int flags = O_RDWR | O_CREAT;
    int dir_flags = O_RDONLY;
    int parent_fd = -1;
    int leaf_fd = -1;
    int file_fd = -1;
    int token_fd = -1;
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
    leaf_fd = private_lock_dup_cloexec(dir_fd);
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
    if (fchmod(file_fd, 0600) != 0) {
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
    token_fd = private_lock_dup_cloexec(g_private_lock_inodes[file_slot].fd);
    if (token_fd < 0) goto fail;

    g_private_lock_contexts[context_slot].active = true;
    g_private_lock_contexts[context_slot].token_fd = token_fd;
    g_private_lock_contexts[context_slot].token_dev = opened.st_dev;
    g_private_lock_contexts[context_slot].token_ino = opened.st_ino;
    g_private_lock_contexts[context_slot].parent_slot = parent_slot;
    g_private_lock_contexts[context_slot].leaf_slot = leaf_slot;
    g_private_lock_contexts[context_slot].file_slot = file_slot;
    return token_fd;

fail: {
        int saved_errno = errno;
        if (file_fd >= 0) close(file_fd);
        if (token_fd >= 0) close(token_fd);
        private_lock_inode_release(file_slot);
        private_lock_inode_release(leaf_slot);
        private_lock_inode_release(parent_slot);
        errno = saved_errno;
        return -1;
    }
}

int lock_private_file_at(int dir_fd, const char *name) {
    return lock_private_file_at_mode(dir_fd, name, false);
}

int try_lock_private_file_at(int dir_fd, const char *name) {
    return lock_private_file_at_mode(dir_fd, name, true);
}

void unlock_private_file(int token_fd) {
    private_lock_prepare_process();
    if (token_fd < 0) return;

    for (size_t i = 0; i < PRIVATE_LOCK_CONTEXTS; i++) {
        private_lock_context_t *ctx = &g_private_lock_contexts[i];
        if (ctx->active && ctx->token_fd == token_fd) {
            size_t parent_slot = ctx->parent_slot;
            size_t leaf_slot = ctx->leaf_slot;
            size_t file_slot = ctx->file_slot;
            close(ctx->token_fd);
            memset(ctx, 0, sizeof(*ctx));
            private_lock_inode_release(file_slot);
            private_lock_inode_release(leaf_slot);
            private_lock_inode_release(parent_slot);
            return;
        }
    }

    /* Opaque tokens are valid only while registered in this process.  An
     * inherited token can be closed and its descriptor number reused before
     * the first post-fork release.  Acting on an unknown number here would
     * unlock/close that unrelated resource, so stale tokens are a no-op. */
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
    int written;

    runtime_lock_prepare_process();
    parent_fd = open_runtime_parent(runtime_parent, sizeof(runtime_parent));
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
            set_error(ERR_INVALID_PATH, "Shared runtime lock name is too long");
            return -1;
        }
        child_name = fallback_name;
    }
    written = snprintf(lock_dir, sizeof(lock_dir), "%s/%s",
                       runtime_parent, child_name);
    if (written < 0 || (size_t)written >= sizeof(lock_dir)) {
        close(parent_fd);
        set_error(ERR_INVALID_PATH, "Shared runtime lock path is too long");
        return -1;
    }
    dir_fd = open_private_subdir_at(parent_fd, child_name, true, NULL);
    if (dir_fd < 0) {
        close(parent_fd);
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
        bool contended = errno == EWOULDBLOCK;
#if EAGAIN != EWOULDBLOCK
        contended = contended || errno == EAGAIN;
#endif
        close(dir_fd);
        close(parent_fd);
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
        lstat(runtime_parent, &parent_path_st) != 0 ||
        !same_fs_identity(&parent_st, &parent_path_st) ||
        fstatat(parent_fd, child_name, &dir_entry_st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_fs_identity(&dir_st, &dir_entry_st)) {
        unlock_private_file(lock_fd);
        close(dir_fd);
        close(parent_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Shared runtime lock namespace changed during acquisition");
        return -1;
    }

    for (size_t i = 0; i < RUNTIME_LOCK_CONTEXTS; i++) {
        if (!g_runtime_locks[i].active) {
            g_runtime_locks[i].active = true;
            g_runtime_locks[i].lock_fd = lock_fd;
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
    unlock_private_file(lock_fd);
    close(dir_fd);
    close(parent_fd);
    set_error(ERR_SYSTEM_CALL, "Too many nested shared runtime locks");
    return -1;
}

void runtime_state_lock_release(int fd) {
    runtime_lock_prepare_process();
    if (fd >= 0) {
        for (size_t i = 0; i < RUNTIME_LOCK_CONTEXTS; i++) {
            if (g_runtime_locks[i].active && g_runtime_locks[i].lock_fd == fd) {
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
                bool have_pp = fstat(g_runtime_locks[i].parent_fd, &pinned_parent) == 0;
                bool have_np = lstat(g_runtime_locks[i].parent_path, &named_parent) == 0;
                bool have_pd = fstat(g_runtime_locks[i].dir_fd, &pinned_dir) == 0;
                bool have_nd = fstatat(g_runtime_locks[i].parent_fd,
                                       g_runtime_locks[i].child_name, &named_dir,
                                       AT_SYMLINK_NOFOLLOW) == 0;
                if ((have_pp && have_np &&
                     (pinned_parent.st_dev != named_parent.st_dev ||
                      pinned_parent.st_ino != named_parent.st_ino)) ||
                    (have_pd && have_nd &&
                     (pinned_dir.st_dev != named_dir.st_dev ||
                      pinned_dir.st_ino != named_dir.st_ino))) {
                    log_warning("runtime lock namespace for '%s' was replaced during "
                                "the critical section", g_runtime_locks[i].child_name);
                }
                unlock_private_file(fd);
                close(g_runtime_locks[i].dir_fd);
                close(g_runtime_locks[i].parent_fd);
                memset(&g_runtime_locks[i], 0, sizeof(g_runtime_locks[i]));
                return;
            }
        }
        unlock_private_file(fd);
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
    
    bytes_read = fread(buffer, 1, buffer_size - 1, file);
    if (ferror(file)) {
        set_system_error(ERR_FILE_IO, "Failed to read from file: %s", file_path);
        fclose(file);
        return -1;
    }

    /* If we filled the buffer, the file MIGHT be exactly buffer_size-1 bytes
     * (a perfect fit) or larger. feof isn't set here — fread stopped at the
     * byte limit without reading past the data — so the old `!feof` test
     * wrongly rejected an exact-fit file (AR-06 F75). Probe one more byte:
     * EOF means it fit exactly; any byte means it is genuinely too large. */
    if (bytes_read == buffer_size - 1 && fgetc(file) != EOF) {
        set_error(ERR_FILE_IO, "File too large for buffer: %s", file_path);
        fclose(file);
        return -1;
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

int copy_file(const char *src_path, const char *dst_path) {
    FILE *src, *dst;
    char buffer[4096];
    size_t bytes;
    int result = 0;
    struct stat src_stat;
    
    if (!src_path || !dst_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_file");
        return -1;
    }
    
    src = fopen(src_path, "rbe");
    if (!src) {
        set_system_error(ERR_FILE_IO, "Failed to open source file: %s", src_path);
        return -1;
    }
    
    dst = fopen(dst_path, "wbe");
    if (!dst) {
        set_system_error(ERR_FILE_IO, "Failed to open destination file: %s", dst_path);
        fclose(src);
        return -1;
    }

    /* Capture metadata from the same source object whose bytes are copied. */
    if (fstat(fileno(src), &src_stat) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to inspect source file: %s", src_path);
        fclose(src);
        fclose(dst);
        return -1;
    }
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            set_system_error(ERR_FILE_IO, "Failed to write to destination file: %s", dst_path);
            result = -1;
            break;
        }
    }
    
    if (ferror(src)) {
        set_system_error(ERR_FILE_IO, "Error reading source file: %s", src_path);
        result = -1;
    }

    if (result == 0 && fflush(dst) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to flush destination file: %s", dst_path);
        result = -1;
    }

    /* Pin the destination descriptor while applying ordinary permission bits;
     * never propagate set-id or sticky bits from a copied input. */
    if (result == 0) {
        if (fchmod(fileno(dst), src_stat.st_mode & 0777) != 0) {
            set_system_error(ERR_PERMISSION_DENIED,
                             "Failed to set destination permissions: %s", dst_path);
            result = -1;
        }
    }

    if (fclose(src) != 0 && result == 0) {
        set_system_error(ERR_FILE_IO, "Failed to close source file: %s", src_path);
        result = -1;
    }
    if (fclose(dst) != 0 && result == 0) {
        set_system_error(ERR_FILE_IO, "Failed to close destination file: %s", dst_path);
        result = -1;
    }

    return result;
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
 * run_argv_real spawns argv[0] via fork+execvp (no shell) with optional
 * stdin input, stdout capture, extra environment, and stderr policy. I/O is
 * driven by poll() so an input+output pair cannot deadlock regardless of
 * payload size. The real child exit code is reported via WEXITSTATUS. */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) {
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* Close every descriptor >= lowfd in the forked child before exec (fd-CLOEXEC).
 * Without this, any fd the parent left open without O_CLOEXEC — a config or
 * backup FILE*, the isolated-home lock, a stray dup — leaks into every git/
 * gpg/ssh child, where a long-lived agent could hold it (and whatever it
 * guards) open indefinitely. Runs post-fork, pre-exec, so only plain syscalls
 * are used. */
static void child_close_fds_from(int lowfd) {
#if defined(__linux__) && defined(SYS_close_range)
    /* close_range(2) is Linux >= 5.9. Invoke via syscall(): the libc wrapper
     * only exists in glibc >= 2.34, and building against newer kernel headers
     * than the running kernel is common — on ENOSYS fall through to the loop. */
    if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U, 0U) == 0) {
        return;
    }
#elif defined(__FreeBSD__)
    /* FreeBSD has closefrom(2) since 8.0, well before our 12.2 floor. Other
     * BSDs and macOS take the portable loop below. */
    closefrom(lowfd);
    return;
#endif
    /* Portable fallback (macOS has neither call): close(2) on an unused fd is
     * harmless (EBADF). Cap the sweep — sysconf can report "unlimited" or a
     * raised RLIMIT_NOFILE in the millions, and this runs on every spawn. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) {
        maxfd = 65536;
    }
    for (long fd = lowfd; fd < maxfd; fd++) {
        (void)close((int)fd);
    }
}

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

    if (!argv || !argv[0]) {
        set_error(ERR_INVALID_ARGS, "run_argv: empty argv");
        return -1;
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

    /* PS-1/PS-2: pin the helper to an absolute path resolved through the
     * sanitized PATH walk in find_command_path() and exec exactly that path
     * with execv() below. execvp()'s own PATH search would happily pick a
     * shadowing "git"/"ssh-add" out of a relative or group/world-writable PATH
     * entry — and since `gitswitch resume` runs from every interactive shell
     * startup, that is arbitrary code execution with the user's keys in
     * scope. Resolving in the parent also yields a real error message instead
     * of a bare 127. */
    char exec_path[MAX_PATH_LEN];
    if (find_command_path(argv[0], exec_path, sizeof(exec_path)) != 0) {
        set_error(ERR_SYSTEM_CALL,
                  "run_argv: '%s' not found in any trusted PATH directory", argv[0]);
        return -1;
    }

    bool want_in = (opts->input != NULL);
    bool want_out = (opts->out && opts->out_size > 0);
    if (want_out) opts->out[0] = '\0';

    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    if (want_in && pipe(in_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "pipe() failed");
        return -1;
    }
    if (want_out && pipe(out_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "pipe() failed");
        if (want_in) { close(in_pipe[0]); close(in_pipe[1]); }
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        set_system_error(ERR_SYSTEM_CALL, "fork() failed");
        if (want_in) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        return -1;
    }

    if (pid == 0) {
        /* ---- child ---- */
        /* Drop the parent's guard handler first (AR-06 F76): until execv resets
         * it, a signal delivered to this child would run guard_handler (which
         * only records and returns), swallowing it and leaving the helper
         * "pre-interrupted" instead of terminating normally. */
        signals_reset_for_child();

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
                _exit(126);
            }
        }

        int devnull = open("/dev/null", O_RDWR);
        if (want_in) { dup2(in_pipe[0], STDIN_FILENO); }
        else if (devnull >= 0) { dup2(devnull, STDIN_FILENO); }
        if (want_out) { dup2(out_pipe[1], STDOUT_FILENO); }
        else if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); }
        if (opts->merge_stderr) { dup2(STDOUT_FILENO, STDERR_FILENO); }
        else if (opts->stderr_to_devnull && devnull >= 0) { dup2(devnull, STDERR_FILENO); }

        /* Close the pipe/devnull fds only above the stdio range (AR-06 F30).
         * When the parent starts with fd 0 or 1 closed, pipe()/open() hand
         * those low numbers back, so after the dup2 dance fds 0/1/2 ARE the
         * child's std streams — an unconditional close here closed the very
         * stdin/stdout we just installed, corrupting the child. Anything in
         * 0..2 is now a std stream we must keep; child_close_fds_from(3) below
         * reaps every remaining fd at or above 3. */
        if (in_pipe[0] > STDERR_FILENO) close(in_pipe[0]);
        if (in_pipe[1] > STDERR_FILENO) close(in_pipe[1]);
        if (out_pipe[0] > STDERR_FILENO) close(out_pipe[0]);
        if (out_pipe[1] > STDERR_FILENO) close(out_pipe[1]);
        if (devnull > STDERR_FILENO) close(devnull);

        if (opts->use_cwd_fd) {
            if (fchdir(child_cwd_fd) != 0) {
                _exit(126);
            }
            close(child_cwd_fd);
        }

        /* fd-CLOEXEC: the explicit closes above only cover our own pipes;
         * sweep everything else the parent had open so the child starts with
         * just stdin/stdout/stderr. Nothing in this codebase intentionally
         * hands an fd to a child (SSH_AUTH_SOCK etc. are paths, not fds). */
        child_close_fds_from(3);

        if (opts->extra_env) {
            for (size_t i = 0; opts->extra_env[i]; i++) {
                const char *e = opts->extra_env[i];
                const char *eq = strchr(e, '=');
                if (eq) {
                    char key[256];
                    size_t klen = (size_t)(eq - e);
                    if (klen < sizeof(key)) {
                        memcpy(key, e, klen);
                        key[klen] = '\0';
                        setenv(key, eq + 1, 1);
                    }
                }
            }
        }

        /* execv, not execvp: the path was pinned pre-fork; re-searching PATH
         * here would reopen the PS-1 window between resolve and exec. */
        execv(exec_path, (char *const *)argv); /* Flawfinder: ignore — argv exec of a pre-pinned path; no shell */
        _exit(127); /* exec failed (e.g. binary vanished after resolution) */
    }

    /* ---- parent ---- */
    result->spawned = true;
    /* AR-03 L8: publish the in-flight child so the signal handler can kill()
     * it if a rollback wedges behind an interactive prompt (see signals.h). */
    signals_child_spawned(pid);
    if (want_in) close(in_pipe[0]);
    if (want_out) close(out_pipe[1]);
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    int infd = want_in ? in_pipe[1] : -1;
    int outfd = want_out ? out_pipe[0] : -1;
    size_t in_off = 0, out_off = 0;
    /* Function-scope (not loop-scope) so it can be scrubbed after the loop:
     * captured child stdout transits this buffer, and for the GPG secret-key
     * export that is unencrypted private-key material — the caller scrubs its
     * own copy, but these bytes would otherwise stay resident in this frame
     * after return (AR-02 #25). */
    char rdbuf[4096];
    if (infd >= 0) set_nonblock(infd);
    if (outfd >= 0) set_nonblock(outfd);

    /* A provided zero-length buffer means "send no bytes, then EOF". Leaving
     * the pipe open would make poll() report it writable forever: write(...,
     * 0) returns zero, advances nothing, and a child such as cat keeps waiting
     * for EOF. Close before the poll loop, without touching opts->input. */
    if (infd >= 0 && opts->input_len == 0) {
        close(infd);
        infd = -1;
    }

    while (infd >= 0 || outfd >= 0) {
        struct pollfd pfds[2];
        int n = 0, in_idx = -1, out_idx = -1;
        if (infd >= 0) { pfds[n].fd = infd; pfds[n].events = POLLOUT; in_idx = n++; }
        if (outfd >= 0) { pfds[n].fd = outfd; pfds[n].events = POLLIN; out_idx = n++; }

        if (poll(pfds, (nfds_t)n, -1) < 0) {
            if (errno == EINTR) continue;
            /* Close both pipe ends before bailing: leaving infd open means a
             * child reading stdin (e.g. `gpg --import`) never sees EOF, and
             * the waitpid() below would then block forever. Closing also lets
             * a child blocked writing a full pipe get SIGPIPE and exit. */
            if (infd >= 0) { close(infd); infd = -1; }
            if (outfd >= 0) { close(outfd); outfd = -1; }
            break;
        }

        if (in_idx >= 0 && (pfds[in_idx].revents & (POLLOUT | POLLERR | POLLHUP))) {
            if (pfds[in_idx].revents & (POLLERR | POLLHUP)) {
                close(infd); infd = -1;
            } else {
                ssize_t w = write(infd, opts->input + in_off, opts->input_len - in_off);
                if (w > 0) {
                    in_off += (size_t)w;
                    if (in_off >= opts->input_len) { close(infd); infd = -1; }
                } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
                    close(infd); infd = -1;
                }
            }
        }

        if (out_idx >= 0 && (pfds[out_idx].revents & (POLLIN | POLLERR | POLLHUP))) {
            ssize_t r = read(outfd, rdbuf, sizeof(rdbuf));
            if (r > 0) {
                size_t cp = 0;
                if (out_off < opts->out_size - 1) {
                    size_t space = opts->out_size - 1 - out_off;
                    cp = ((size_t)r < space) ? (size_t)r : space;
                    memcpy(opts->out + out_off, rdbuf, cp);
                    out_off += cp;
                }
                /* Bytes beyond the capture buffer are still drained (so the
                 * child never blocks) but LOST — record that, so callers that
                 * feed `out` onward can refuse the incomplete copy instead of
                 * silently processing corrupt data (AR-02 #4). */
                if (cp < (size_t)r) {
                    result->out_truncated = true;
                }
            } else if (r == 0) {
                close(outfd); outfd = -1;
            } else if (r < 0 && errno != EAGAIN && errno != EINTR) {
                close(outfd); outfd = -1;
            }
        }
    }
    if (want_out) {
        opts->out[out_off] = '\0';
        /* Drop the transit copy of the child's output (AR-02 #25). */
        secure_zero_memory(rdbuf, sizeof(rdbuf));
    }
    result->out_len = out_off;

    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    /* Retract immediately after the reap: past this point the pid is free for
     * kernel reuse, and the handler must not signal a stranger (AR-03 L8). */
    signals_child_reaped();
    signal(SIGPIPE, old_sigpipe);

    if (w < 0) {
        set_system_error(ERR_SYSTEM_CALL, "waitpid() failed");
        return -1;
    }
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->term_signal = WTERMSIG(status);
        result->exit_code = -1;
    }
    return (result->spawned && result->exit_code == 0) ? 0 : -1;
}

static command_runner_fn g_runner = run_argv_real;

command_runner_fn run_set_runner(command_runner_fn fn) {
    command_runner_fn prev = g_runner;
    g_runner = fn ? fn : run_argv_real;
    return prev;
}

int run_argv(const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    return g_runner(argv, opts, result);
}

/* PS-1/PS-2 PATH supply-chain defense: every trusted helper (git, gpg,
 * ssh-add, ssh-agent, gpgconf, ...) is resolved through these checks before it
 * is executed, and `gitswitch resume` runs from every interactive shell
 * startup — so a shadowing binary in a hostile PATH entry would otherwise run
 * automatically with the user's keys in scope.
 *
 * A directory may supply an executable only if it is an absolute path to a
 * real directory that is not group- or world-writable. Relative entries (".", "", "bin")
 * resolve against the CWD — inside a freshly cloned repo that is attacker
 * territory. Writable dirs are rejected even with the sticky bit set: sticky
 * only stops deleting other users' files, while a writable group member can
 * still replace or create a shadowing helper. User-owned prefixes like
 * ~/.local/bin, Homebrew's /opt/homebrew/bin, or Nix profiles are
 * 0755-or-tighter and keep working. */
static bool exec_dir_is_trusted(const char *dir) {
    struct stat st;

    if (dir[0] != '/') {
        return false;
    }
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return false;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        return false;
    }
    return true;
}

/* The resolved binary itself must be a regular file (access(X_OK) alone would
 * happily "find" a directory named git) and not group- or world-writable — a
 * writable binary in an otherwise sane directory is just as replaceable as a
 * writable directory. */
static bool exec_candidate_is_trusted(const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        return false;
    }
    return access(path, X_OK) == 0; /* Flawfinder: ignore — advisory post-stat probe; exec re-validates */
}

/* Process-lifetime memo for find_command_path (AR-02 #24): one switch
 * resolves the same handful of helpers (git, ssh-add, gpg, ...) ~16 times —
 * init-time probes plus every run_argv spawn — and each resolution walks the
 * trusted-PATH at ~3 syscalls per entry, ~550 redundant stat/access calls per
 * switch. Sub-millisecond warm, but each stat is a network round trip on cold
 * NFS/autofs PATH entries. Keyed on the exact PATH string so an intra-process
 * PATH change (tests do this) drops the cache. Positive results only: a miss
 * usually aborts the command anyway, and caching one could outlive a
 * transient failure. Single-threaded, like the other utils caches. */
#define CMD_MEMO_SLOTS 16
#define CMD_MEMO_NAME_LEN 32
typedef struct {
    char name[CMD_MEMO_NAME_LEN];
    char path[MAX_PATH_LEN];
} cmd_memo_slot_t;
static cmd_memo_slot_t g_cmd_memo[CMD_MEMO_SLOTS];
static size_t g_cmd_memo_used = 0;
static char *g_cmd_memo_pathenv = NULL;

int find_command_path(const char *name, char *buf, size_t size) {
    const char *path_env;
    const char *p;

    if (!name || !buf || size == 0 || name[0] == '\0') {
        return -1;
    }

    /* A name containing a slash is used directly, no PATH search — but only
     * if absolute ("./git" or "bin/git" would resolve against the CWD, which
     * is exactly the hole this function closes) and only out of a trusted
     * directory, same rules as a PATH entry. */
    if (strchr(name, '/')) {
        char dir[MAX_PATH_LEN];
        const char *slash = strrchr(name, '/');
        /* Keep the leading '/' when the binary sits directly under the root. */
        size_t dirlen = (slash == name) ? 1 : (size_t)(slash - name);

        if (name[0] != '/' || dirlen >= sizeof(dir)) {
            return -1;
        }
        memcpy(dir, name, dirlen);
        dir[dirlen] = '\0';

        if (!exec_dir_is_trusted(dir) || !exec_candidate_is_trusted(name)) {
            return -1;
        }
        if (safe_strncpy(buf, name, size) != 0) return -1;
        return 0;
    }

    path_env = getenv("PATH");
    if (!path_env || !*path_env) {
        path_env = "/usr/local/bin:/usr/bin:/bin";
    }

    /* Memo lookup, valid only while PATH is byte-identical to the PATH the
     * cache was filled under. Staleness within one short-lived process (a
     * memoized binary deleted mid-run) is the same resolve-to-exec TOCTOU
     * window that already exists for a single call. */
    if (!g_cmd_memo_pathenv || strcmp(g_cmd_memo_pathenv, path_env) != 0) {
        free(g_cmd_memo_pathenv);
        g_cmd_memo_pathenv = strdup(path_env);
        g_cmd_memo_used = 0;
    } else {
        for (size_t i = 0; i < g_cmd_memo_used; i++) {
            if (strcmp(g_cmd_memo[i].name, name) == 0) {
                return safe_strncpy(buf, g_cmd_memo[i].path, size);
            }
        }
    }

    /* Walk colon-separated PATH entries, testing <dir>/<name> in each trusted
     * directory. Untrusted entries are skipped, not fatal: a stray "." or
     * group/world-writable dir in PATH must not hide the real /usr/bin/git
     * behind it. An empty
     * entry historically means the CWD — refused, not honored. */
    p = path_env;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dirlen = colon ? (size_t)(colon - p) : strlen(p);
        char dir[MAX_PATH_LEN];
        char candidate[MAX_PATH_LEN];

        if (dirlen > 0 && dirlen < sizeof(dir) &&
            dirlen + 1 + strlen(name) + 1 <= sizeof(candidate)) {
            memcpy(dir, p, dirlen);
            dir[dirlen] = '\0';
            memcpy(candidate, dir, dirlen);
            candidate[dirlen] = '/';
            strcpy(candidate + dirlen + 1, name); /* Flawfinder: ignore — bounds proven by dirlen+name checks above */
            if (exec_dir_is_trusted(dir) && exec_candidate_is_trusted(candidate)) {
                if (g_cmd_memo_pathenv && g_cmd_memo_used < CMD_MEMO_SLOTS &&
                    strlen(name) < CMD_MEMO_NAME_LEN) {
                    cmd_memo_slot_t *slot = &g_cmd_memo[g_cmd_memo_used];
                    if (safe_strncpy(slot->name, name, sizeof(slot->name)) == 0 &&
                        safe_strncpy(slot->path, candidate, sizeof(slot->path)) == 0) {
                        g_cmd_memo_used++;
                    }
                }
                if (safe_strncpy(buf, candidate, size) != 0) return -1;
                return 0;
            }
        }

        if (!colon) break;
        p = colon + 1;
    }
    return -1;
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
        "doctor", "health", "config", "init", "resume", "reset", NULL
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
size_t utf8_decode(const unsigned char *s, uint32_t *cp_out) {
    unsigned char b0 = s[0];

    if (b0 < 0x80) {
        *cp_out = b0;
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if ((s[1] & 0xC0) != 0x80) return 0;
        *cp_out = ((uint32_t)(b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (b0 == 0xE0 && s[1] < 0xA0) return 0;              /* overlong */
        if (b0 == 0xED && s[1] >= 0xA0) return 0;             /* surrogate */
        *cp_out = ((uint32_t)(b0 & 0x0F) << 12) |
                  ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4) {
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
    return cp >= 0x20 && cp != 0x7F && !(cp >= 0x80 && cp <= 0x9F);
}

bool validate_key_id(const char *key_id) {
    if (!key_id || strlen(key_id) == 0 || strlen(key_id) >= MAX_KEY_ID_LEN) {
        return false;
    }

    /* Accept the common "0x" prefix that `gpg -k` and keyservers display —
     * gpg itself accepts a 0x-prefixed key id, so rejecting it only tripped up
     * users pasting the id exactly as shown. The remainder must be hex. */
    const char *p = key_id;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    if (*p == '\0') {
        return false; /* "0x" with no digits */
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
        set_system_error(ERR_SYSTEM_CALL, "Failed to get terminal size");
        return -1;
    }

    *width = ws.ws_col;
    *height = ws.ws_row;

    return 0;
}

void disable_echo(void) {
    struct termios new_termios;
    
    if (g_echo_disabled) return;
    
    if (tcgetattr(STDIN_FILENO, &g_original_termios) != 0) {
        return; /* Can't save original, don't disable echo */
    }
    
    new_termios = g_original_termios;
    new_termios.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_termios) == 0) {
        g_echo_disabled = true;
    }
}

void enable_echo(void) {
    if (!g_echo_disabled) return;
    
    tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
    g_echo_disabled = false;
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
