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
static char *ts_tmpdirs[TS_MAX_TMPDIRS];
static int ts_tmpdir_count = 0;

static inline void ts_rm_rf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            char child[4096];
            if ((size_t)snprintf(child, sizeof(child), "%s/%s", path,
                                 e->d_name) < sizeof(child)) {
                struct stat st;
                if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
                    ts_rm_rf(child);
                } else {
                    unlink(child);
                }
            }
        }
        closedir(d);
    }
    rmdir(path);
}

static inline void ts_cleanup_tmpdirs(void) {
    for (int i = 0; i < ts_tmpdir_count; i++) {
        ts_rm_rf(ts_tmpdirs[i]);
        free(ts_tmpdirs[i]);
        ts_tmpdirs[i] = NULL;
    }
    ts_tmpdir_count = 0;
}

static inline char *ts_mkdtemp(char *tmpl) {
    char *r = mkdtemp(tmpl);
    if (r) {
        if (ts_tmpdir_count >= TS_MAX_TMPDIRS) {
            ts_rm_rf(r);
            errno = ENOSPC;
            return NULL;
        }
        size_t length = strlen(r) + 1;
        char *tracked = malloc(length);
        if (!tracked) {
            ts_rm_rf(r);
            errno = ENOMEM;
            return NULL;
        }
        if (ts_tmpdir_count == 0 && atexit(ts_cleanup_tmpdirs) != 0) {
            free(tracked);
            ts_rm_rf(r);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(tracked, r, length);
        ts_tmpdirs[ts_tmpdir_count++] = tracked;
    }
    return r;
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
    if (home[0] != '/' || !getcwd(original_cwd, sizeof(original_cwd)) ||
        chdir(home) != 0) {
        if (home[0] != '/') errno = EINVAL;
        return NULL;
    }
    if (!getcwd(canonical_home, sizeof(canonical_home))) {
        int saved_errno = errno;
        (void)chdir(original_cwd);
        errno = saved_errno;
        return NULL;
    }
    if (chdir(original_cwd) != 0) return NULL;

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
