/* Minimal dependency-free test harness for gitswitch-c.
 *
 * Each test file defines tests with TEST(), registers them in main() via
 * RUN_TEST(), and returns the failure count as its exit code so the Makefile
 * `test` target fails the build on any failure. CHECK* macros are non-fatal
 * (they record a failure but let the rest of the test run). */
#ifndef GITSWITCH_TEST_H
#define GITSWITCH_TEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int ts_tests_run = 0;
static int ts_tests_failed = 0;
static int ts_current_fail = 0; /* per-test failure flag */

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
