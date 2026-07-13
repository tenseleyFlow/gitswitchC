/* Minimal dependency-free test harness for gitswitch-c.
 *
 * Each test file defines tests with TEST(), registers them in main() via
 * RUN_TEST(), and exits 0 when every test passed or 1 if any failed (AR-06 F79:
 * it is a boolean status, not the failure count), so the Makefile `test` target
 * fails the build on any failure. CHECK* macros are non-fatal (they record a
 * failure but let the rest of the test run). */
#ifndef GITSWITCH_TEST_H
#define GITSWITCH_TEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static int ts_tests_run = 0;
static int ts_tests_failed = 0;
static int ts_current_fail = 0; /* per-test failure flag */

/* AR-06 F81: unit suites mkdtemp() one or more /tmp fixtures per test and most
 * never removed the tree, leaking ~186 dirs per full run (tens of thousands
 * accumulate over a development cycle). ts_mkdtemp() is a drop-in mkdtemp()
 * that records each created directory and, on first use, registers an atexit
 * sweep that recursively removes them when the suite process exits. Tests that
 * already rmdir their own fixtures still work — the depth-first removal is
 * best-effort and ignores already-gone paths. static inline keeps suites that
 * create no fixtures from tripping -Wunused-function under -Werror. */
#define TS_MAX_TMPDIRS 1024

typedef struct {
    char *path;
    int root_fd;
    dev_t dev;
    ino_t ino;
} ts_tmpdir_record_t;

static ts_tmpdir_record_t ts_tmpdirs[TS_MAX_TMPDIRS];
static int ts_tmpdir_count = 0;
static int ts_cleanup_registered = 0;

/* Deterministic cleanup-race seam used only by the harness containment
 * regression. It runs after a child has been classified as a directory but
 * before descent; production test runs leave it NULL. */
typedef void (*ts_cleanup_pre_descend_hook_fn)(void);
static ts_cleanup_pre_descend_hook_fn ts_cleanup_pre_descend_hook = NULL;

static inline ts_cleanup_pre_descend_hook_fn
ts_set_cleanup_pre_descend_hook(ts_cleanup_pre_descend_hook_fn hook) {
    ts_cleanup_pre_descend_hook_fn previous = ts_cleanup_pre_descend_hook;
    ts_cleanup_pre_descend_hook = hook;
    return previous;
}

/* Narrow fault seam for the trusted-fixture cwd round trip. */
typedef char *(*ts_trusted_getcwd_hook_fn)(char *, size_t);
typedef int (*ts_trusted_chdir_hook_fn)(const char *);
static ts_trusted_getcwd_hook_fn ts_trusted_getcwd_hook = NULL;
static ts_trusted_chdir_hook_fn ts_trusted_chdir_hook = NULL;

static inline void ts_set_trusted_cwd_hooks(
    ts_trusted_getcwd_hook_fn getcwd_hook,
    ts_trusted_chdir_hook_fn chdir_hook) {
    ts_trusted_getcwd_hook = getcwd_hook;
    ts_trusted_chdir_hook = chdir_hook;
}

static inline char *ts_trusted_getcwd(char *buffer, size_t size) {
    return ts_trusted_getcwd_hook ? ts_trusted_getcwd_hook(buffer, size)
                                  : getcwd(buffer, size);
}

static inline int ts_trusted_chdir(const char *path) {
    return ts_trusted_chdir_hook ? ts_trusted_chdir_hook(path) : chdir(path);
}

static inline int ts_same_identity(const struct stat *a,
                                   const struct stat *b) {
    return a && b && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static inline int ts_set_cloexec(int fd) {
#ifdef O_CLOEXEC
    (void)fd;
    return 0;
#else
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
}

static inline int ts_open_dir_nofollow(const char *path) {
#if defined(O_DIRECTORY) && defined(O_NOFOLLOW)
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd >= 0 && ts_set_cloexec(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
#else
    (void)path;
    errno = ENOTSUP;
    return -1;
#endif
}

static inline int ts_openat_dir_nofollow(int parent_fd, const char *name) {
#if defined(O_DIRECTORY) && defined(O_NOFOLLOW)
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = openat(parent_fd, name, flags);
    if (fd >= 0 && ts_set_cloexec(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
#else
    (void)parent_fd;
    (void)name;
    errno = ENOTSUP;
    return -1;
#endif
}

static inline int ts_dup_dir_fd(int fd) {
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
    int duplicate = dup(fd);
    if (duplicate >= 0 &&
        fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(duplicate);
        errno = saved_errno;
        return -1;
    }
    return duplicate;
#endif
}

static inline void ts_rm_rf_contents_fd(int dir_fd) {
#if defined(AT_SYMLINK_NOFOLLOW) && defined(AT_REMOVEDIR)
    int scan_fd = ts_dup_dir_fd(dir_fd);
    if (scan_fd < 0) return;
    DIR *directory = fdopendir(scan_fd);
    if (!directory) {
        close(scan_fd);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        int parent_fd = dirfd(directory);
        struct stat named_before;
        if (fstatat(parent_fd, entry->d_name, &named_before,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        if (!S_ISDIR(named_before.st_mode)) {
            (void)unlinkat(parent_fd, entry->d_name, 0);
            continue;
        }

        int child_fd = ts_openat_dir_nofollow(parent_fd, entry->d_name);
        if (child_fd < 0) continue;
        struct stat opened_child;
        if (fstat(child_fd, &opened_child) != 0 ||
            !S_ISDIR(opened_child.st_mode) ||
            !ts_same_identity(&named_before, &opened_child)) {
            close(child_fd);
            continue;
        }

        if (ts_cleanup_pre_descend_hook) ts_cleanup_pre_descend_hook();
        ts_rm_rf_contents_fd(child_fd);

        struct stat named_after;
        if (fstatat(parent_fd, entry->d_name, &named_after,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(named_after.st_mode) &&
            ts_same_identity(&opened_child, &named_after)) {
            (void)unlinkat(parent_fd, entry->d_name, AT_REMOVEDIR);
        }
        close(child_fd);
    }
    closedir(directory);
#else
    (void)dir_fd;
#endif
}

static inline void ts_cleanup_pinned_root(const char *path, int root_fd,
                                          dev_t dev, ino_t ino) {
    struct stat pinned;
    if (root_fd < 0 || fstat(root_fd, &pinned) != 0 ||
        !S_ISDIR(pinned.st_mode) || pinned.st_dev != dev ||
        pinned.st_ino != ino) {
        if (root_fd >= 0) close(root_fd);
        return;
    }

    ts_rm_rf_contents_fd(root_fd);

    struct stat named;
    if (path && lstat(path, &named) == 0 && S_ISDIR(named.st_mode) &&
        named.st_dev == dev && named.st_ino == ino) {
        (void)rmdir(path);
    }
    close(root_fd);
}

/* Safe one-shot wrapper retained for suites that explicitly clean a fixture
 * before process exit. A replaced final symlink is unlinked, never followed. */
static inline void ts_rm_rf(const char *path) {
    struct stat named;
    if (!path || lstat(path, &named) != 0) return;
    if (!S_ISDIR(named.st_mode)) {
        (void)unlink(path);
        return;
    }

    int root_fd = ts_open_dir_nofollow(path);
    if (root_fd < 0) return;
    struct stat pinned;
    if (fstat(root_fd, &pinned) != 0 || !S_ISDIR(pinned.st_mode) ||
        !ts_same_identity(&named, &pinned)) {
        close(root_fd);
        return;
    }
    ts_cleanup_pinned_root(path, root_fd, pinned.st_dev, pinned.st_ino);
}

static inline void ts_cleanup_tmpdirs(void) {
    for (int i = 0; i < ts_tmpdir_count; i++) {
        ts_cleanup_pinned_root(ts_tmpdirs[i].path, ts_tmpdirs[i].root_fd,
                               ts_tmpdirs[i].dev, ts_tmpdirs[i].ino);
        free(ts_tmpdirs[i].path);
        memset(&ts_tmpdirs[i], 0, sizeof(ts_tmpdirs[i]));
        ts_tmpdirs[i].root_fd = -1;
    }
    ts_tmpdir_count = 0;
}

static inline char *ts_mkdtemp(char *tmpl) {
    char *created = mkdtemp(tmpl);
    if (!created) return NULL;
    if (ts_tmpdir_count >= TS_MAX_TMPDIRS) {
        (void)rmdir(created);
        errno = ENOSPC;
        return NULL;
    }

    int root_fd = ts_open_dir_nofollow(created);
    if (root_fd < 0) {
        int saved_errno = errno;
        (void)rmdir(created);
        errno = saved_errno;
        return NULL;
    }

    struct stat pinned;
    struct stat named;
    if (fstat(root_fd, &pinned) != 0 || lstat(created, &named) != 0) {
        int saved_errno = errno;
        close(root_fd);
        (void)rmdir(created);
        errno = saved_errno;
        return NULL;
    }
    if (!S_ISDIR(pinned.st_mode) || !S_ISDIR(named.st_mode) ||
        !ts_same_identity(&pinned, &named)) {
        close(root_fd);
        errno = EAGAIN;
        return NULL;
    }

    size_t length = strlen(created) + 1;
    char *tracked = malloc(length);
    if (!tracked) {
        ts_cleanup_pinned_root(created, root_fd, pinned.st_dev,
                               pinned.st_ino);
        errno = ENOMEM;
        return NULL;
    }
    if (!ts_cleanup_registered && atexit(ts_cleanup_tmpdirs) != 0) {
        free(tracked);
        ts_cleanup_pinned_root(created, root_fd, pinned.st_dev,
                               pinned.st_ino);
        errno = ENOMEM;
        return NULL;
    }
    ts_cleanup_registered = 1;
    memcpy(tracked, created, length);
    ts_tmpdirs[ts_tmpdir_count].path = tracked;
    ts_tmpdirs[ts_tmpdir_count].root_fd = root_fd;
    ts_tmpdirs[ts_tmpdir_count].dev = pinned.st_dev;
    ts_tmpdirs[ts_tmpdir_count].ino = pinned.st_ino;
    ts_tmpdir_count++;
    return created;
}

/* Create an executable-fixture root below canonical HOME rather than sticky
 * /tmp. The production executable resolver intentionally rejects every leaf
 * below a group/world-writable ancestor, so tests that place PATH shims,
 * copied binaries, or self-exec probes under /tmp cannot be positive controls.
 * Keep ordinary ts_mkdtemp() for data/runtime fixtures and negative tests.
 * `stem` is a short filename component (letters, digits, '-' or '_'); `path`
 * receives a private 0700 directory and is registered for the usual sweep. */
static inline char *ts_mkdtemp_trusted(char *path, size_t path_size,
                                       const char *stem) {
    char canonical_home[4096];
    char original_cwd[4096];
    const char *home = getenv("HOME");

    if (!path || path_size == 0 || !stem || !*stem || !home || !*home) {
        errno = EINVAL;
        return NULL;
    }
    for (const unsigned char *byte = (const unsigned char *)stem;
         *byte; byte++) {
        if (!((*byte >= 'a' && *byte <= 'z') ||
              (*byte >= 'A' && *byte <= 'Z') ||
              (*byte >= '0' && *byte <= '9') ||
              *byte == '-' || *byte == '_')) {
            errno = EINVAL;
            return NULL;
        }
    }
    /* Some suites deliberately compile with strict POSIX feature profiles
     * under which realpath() is not declared on every supported libc. Tests
     * are single-threaded while fixtures are created, so briefly enter HOME,
     * ask the kernel for its canonical cwd spelling, and restore the caller's
     * cwd without expanding the harness's feature-macro surface. */
    if (home[0] != '/' ||
        !ts_trusted_getcwd(original_cwd, sizeof(original_cwd)) ||
        ts_trusted_chdir(home) != 0) {
        if (home[0] != '/') errno = EINVAL;
        return NULL;
    }
    if (!ts_trusted_getcwd(canonical_home, sizeof(canonical_home))) {
        int saved_errno = errno;
        if (ts_trusted_chdir(original_cwd) != 0) return NULL;
        errno = saved_errno;
        return NULL;
    }
    if (ts_trusted_chdir(original_cwd) != 0) return NULL;

    int written = snprintf(path, path_size, "%s/.%s.XXXXXX",
                           canonical_home, stem);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char *created = ts_mkdtemp(path);
    if (!created) return NULL;
    if (chmod(created, 0700) != 0) {
        int saved_errno = errno;
        ts_rm_rf(created);
        errno = saved_errno;
        return NULL;
    }
    return created;
}

#define TEST(name) static void name(void)

#define CHECK(cond) do {                                                       \
    if (!(cond)) {                                                             \
        ts_current_fail = 1;                                                   \
        fprintf(stderr, "  FAIL %s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
    }                                                                          \
} while (0)

#define CHECK_EQ_INT(a, b) do {                                               \
    long _a = (long)(a), _b = (long)(b);                                      \
    if (_a != _b) {                                                           \
        ts_current_fail = 1;                                                  \
        fprintf(stderr, "  FAIL %s:%d: %s == %s  (%ld != %ld)\n",            \
                __FILE__, __LINE__, #a, #b, _a, _b);                          \
    }                                                                         \
} while (0)

#define CHECK_STR_EQ(a, b) do {                                              \
    const char *_a = (a), *_b = (b);                                         \
    if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) {                   \
        ts_current_fail = 1;                                                 \
        fprintf(stderr, "  FAIL %s:%d: \"%s\" == \"%s\"  (\"%s\" != \"%s\")\n",\
                __FILE__, __LINE__, #a, #b,                                  \
                _a ? _a : "(null)", _b ? _b : "(null)");                     \
    }                                                                        \
} while (0)

#define RUN_TEST(fn) do {                                                    \
    ts_current_fail = 0;                                                     \
    ts_tests_run++;                                                          \
    fn();                                                                    \
    if (ts_current_fail) { ts_tests_failed++; printf("[FAIL] %s\n", #fn); }  \
    else                 { printf("[ ok ] %s\n", #fn); }                     \
} while (0)

#define TEST_MAIN_BEGIN() int main(void) {
#define TEST_MAIN_END()                                                      \
    printf("\n%s: %d run, %d failed\n",                                      \
           ts_tests_failed ? "RESULT FAIL" : "RESULT OK",                    \
           ts_tests_run, ts_tests_failed);                                   \
    return ts_tests_failed == 0 ? 0 : 1;                                     \
}

#endif /* GITSWITCH_TEST_H */
