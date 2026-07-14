#ifndef GITSWITCH_SCRATCH_REGISTRY_TEST_H
#define GITSWITCH_SCRATCH_REGISTRY_TEST_H

#include "signals.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define TEST_SCRATCH_PROBE_MAX 32U
#define TEST_SCRATCH_PATH_SIZE 160U

static inline size_t test_scratch_fill(
    char paths[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE],
    const char *tag) {
    size_t registered = 0;

    for (; registered < TEST_SCRATCH_PROBE_MAX; registered++) {
        int length = snprintf(paths[registered], TEST_SCRATCH_PATH_SIZE,
                              "/tmp/gitswitch-%s-%ld-%zu.scratch", tag,
                              (long)getpid(), registered);
        if (length < 0 || (size_t)length >= TEST_SCRATCH_PATH_SIZE ||
            signals_scratch_register(paths[registered]) != 0) {
            break;
        }
    }
    return registered;
}

static inline void test_scratch_release(
    char paths[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE],
    size_t registered) {
    for (size_t i = 0; i < registered; i++) {
        signals_scratch_unregister(paths[i]);
    }
}

static inline int test_open_fd_count(void) {
    long limit = sysconf(_SC_OPEN_MAX);
    int count = 0;

    if (limit < 0 || limit > 4096) limit = 4096;
    for (int fd = 0; fd < (int)limit; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) count++;
    }
    return count;
}

#endif /* GITSWITCH_SCRATCH_REGISTRY_TEST_H */
