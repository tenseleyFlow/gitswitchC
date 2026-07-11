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
static char ts_tmpdirs[TS_MAX_TMPDIRS][96];
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
    }
    ts_tmpdir_count = 0;
}

static inline char *ts_mkdtemp(char *tmpl) {
    char *r = mkdtemp(tmpl);
    if (r) {
        if (ts_tmpdir_count == 0) {
            atexit(ts_cleanup_tmpdirs);
        }
        if (ts_tmpdir_count < TS_MAX_TMPDIRS &&
            strlen(r) < sizeof(ts_tmpdirs[0])) {
            snprintf(ts_tmpdirs[ts_tmpdir_count++], sizeof(ts_tmpdirs[0]),
                     "%s", r);
        }
    }
    return r;
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
