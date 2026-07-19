#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#define _GNU_SOURCE 1
#endif

#include "../src/freebsd_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/random.h>
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
#include <sys/resource.h>
#endif
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0
#endif

#ifndef GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS
#define GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS 300000
#endif

#if GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS <= 0
#error "GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS must be positive"
#endif

/* AR-10 M2: main() opens its working descriptors immediately, so when the
 * caller execs this helper with any of fds 0/1/2 closed, the directory,
 * staging, and published descriptors land in the standard slots. Every later
 * fprintf(stderr, ...) then writes into whichever file owns fd 2 — on the
 * named-temp fallback path the post-publication retire WARNING landed on the
 * staging inode, a hard link to the just-published archive, appending the
 * diagnostic INTO the published artifact after fsync while still exiting 0.
 * Pin the standard slots to /dev/null before any other open. Deliberately no
 * O_CLOEXEC: the producer child must inherit real descriptors too. */
static int reserve_standard_descriptors(void)
{
    for (;;) {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) {
            return -1;
        }
        if (fd > STDERR_FILENO) {
            (void)close(fd);
            return 0;
        }
    }
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s OUTPUT_DIRECTORY CANONICAL_DIRECTORY FINAL_NAME -- COMMAND [ARG ...]\n",
            program);
}

static bool same_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           S_ISREG(left->st_mode) && S_ISREG(right->st_mode);
}

#define SHA256_BLOCK_SIZE 64U
#define SHA256_DIGEST_SIZE 32U

typedef struct sha256_context {
    uint32_t state[8];
    uint64_t total_size;
    unsigned char block[SHA256_BLOCK_SIZE];
    size_t block_size;
} sha256_context_t;

static uint32_t rotate_right(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static uint32_t load_big_endian_32(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24U) |
           ((uint32_t)bytes[1] << 16U) |
           ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static void store_big_endian_32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)(value >> 24U);
    bytes[1] = (unsigned char)(value >> 16U);
    bytes[2] = (unsigned char)(value >> 8U);
    bytes[3] = (unsigned char)value;
}

static void sha256_transform(sha256_context_t *context,
                             const unsigned char block[SHA256_BLOCK_SIZE])
{
    static const uint32_t constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t words[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t index;

    for (index = 0; index < 16U; index++) {
        words[index] = load_big_endian_32(block + (index * 4U));
    }
    for (; index < 64U; index++) {
        uint32_t left = words[index - 15U];
        uint32_t right = words[index - 2U];
        uint32_t sigma_zero = rotate_right(left, 7U) ^
                              rotate_right(left, 18U) ^ (left >> 3U);
        uint32_t sigma_one = rotate_right(right, 17U) ^
                             rotate_right(right, 19U) ^ (right >> 10U);

        words[index] = words[index - 16U] + sigma_zero +
                       words[index - 7U] + sigma_one;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (index = 0; index < 64U; index++) {
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sum_zero = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                            rotate_right(a, 22U);
        uint32_t sum_one = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                           rotate_right(e, 25U);
        uint32_t first = h + sum_one + choice + constants[index] +
                         words[index];
        uint32_t second = sum_zero + majority;

        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(sha256_context_t *context)
{
    static const uint32_t initial_state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    memcpy(context->state, initial_state, sizeof(initial_state));
    context->total_size = 0U;
    context->block_size = 0U;
}

static int sha256_update(sha256_context_t *context,
                         const unsigned char *bytes, size_t size)
{
    if ((uint64_t)size > UINT64_MAX - context->total_size) {
        errno = EOVERFLOW;
        return -1;
    }
    context->total_size += (uint64_t)size;
    while (size > 0U) {
        size_t available = SHA256_BLOCK_SIZE - context->block_size;
        size_t count = size < available ? size : available;

        memcpy(context->block + context->block_size, bytes, count);
        context->block_size += count;
        bytes += count;
        size -= count;
        if (context->block_size == SHA256_BLOCK_SIZE) {
            sha256_transform(context, context->block);
            context->block_size = 0U;
        }
    }
    return 0;
}

static int sha256_final(sha256_context_t *context,
                        unsigned char digest[SHA256_DIGEST_SIZE])
{
    uint64_t bit_size;
    size_t index;

    if (context->total_size > UINT64_MAX / 8U) {
        errno = EOVERFLOW;
        return -1;
    }
    bit_size = context->total_size * 8U;
    context->block[context->block_size++] = 0x80U;
    if (context->block_size > 56U) {
        memset(context->block + context->block_size, 0,
               SHA256_BLOCK_SIZE - context->block_size);
        sha256_transform(context, context->block);
        context->block_size = 0U;
    }
    memset(context->block + context->block_size, 0,
           56U - context->block_size);
    for (index = 0; index < 8U; index++) {
        context->block[63U - index] =
            (unsigned char)(bit_size >> (index * 8U));
    }
    sha256_transform(context, context->block);
    for (index = 0; index < 8U; index++) {
        store_big_endian_32(digest + (index * 4U), context->state[index]);
    }
    return 0;
}

static int digest_read_only_regular_descriptor(
    int fd, off_t expected_size, unsigned char digest[SHA256_DIGEST_SIZE])
{
    unsigned char buffer[64U * 1024U];
    sha256_context_t context;
    struct stat before;
    struct stat after;
    off_t offset = 0;

    if (expected_size < 0 ||
        (uintmax_t)expected_size > UINT64_MAX / 8U) {
        errno = EOVERFLOW;
        return -1;
    }
    if (fstat(fd, &before) != 0) {
        return -1;
    }
    if (!S_ISREG(before.st_mode) || before.st_size != expected_size ||
        (before.st_mode & 07777) !=
            (S_IRUSR | S_IRGRP | S_IROTH)) {
        errno = ESTALE;
        return -1;
    }

    sha256_init(&context);
    while (offset < expected_size) {
        off_t remaining = expected_size - offset;
        size_t wanted = sizeof(buffer);
        ssize_t count;

        if (remaining < (off_t)wanted) {
            wanted = (size_t)remaining;
        }
        do {
            count = pread(fd, buffer, wanted, offset);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) {
            if (count == 0) {
                errno = ESTALE;
            }
            return -1;
        }
        if (sha256_update(&context, buffer, (size_t)count) != 0) {
            return -1;
        }
        offset += count;
    }
    if (fstat(fd, &after) != 0) {
        return -1;
    }
    if (!same_identity(&before, &after) || after.st_size != expected_size ||
        (after.st_mode & 07777) !=
            (S_IRUSR | S_IRGRP | S_IROTH)) {
        errno = ESTALE;
        return -1;
    }
    return sha256_final(&context, digest);
}

#if defined(GITSWITCH_RELEASE_TEST_DIGEST)
static bool digest_matches_hex(
    const unsigned char digest[SHA256_DIGEST_SIZE], const char *expected)
{
    static const char hex[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < SHA256_DIGEST_SIZE; index++) {
        if (expected[index * 2U] != hex[digest[index] >> 4U] ||
            expected[(index * 2U) + 1U] !=
                hex[digest[index] & 0x0fU]) {
            return false;
        }
    }
    return expected[SHA256_DIGEST_SIZE * 2U] == '\0';
}

static bool sha256_matches_vector(const unsigned char *bytes, size_t size,
                                  size_t chunk_size, const char *expected)
{
    sha256_context_t context;
    unsigned char digest[SHA256_DIGEST_SIZE];
    size_t offset = 0U;

    sha256_init(&context);
    while (offset < size) {
        size_t count = size - offset;

        if (count > chunk_size) {
            count = chunk_size;
        }
        if (sha256_update(&context, bytes + offset, count) != 0) {
            return false;
        }
        offset += count;
    }
    return sha256_final(&context, digest) == 0 &&
           digest_matches_hex(digest, expected);
}

static int run_sha256_known_answer_tests(void)
{
    static const unsigned char abc[] = "abc";
    static const unsigned char padding_boundary[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char thousand_a[1000];
    sha256_context_t context;
    unsigned char digest[SHA256_DIGEST_SIZE];
    size_t index;

    if (!sha256_matches_vector((const unsigned char *)"", 0U, 1U,
                               "e3b0c44298fc1c149afbf4c8996fb924"
                               "27ae41e4649b934ca495991b7852b855") ||
        !sha256_matches_vector(abc, sizeof(abc) - 1U, 2U,
                               "ba7816bf8f01cfea414140de5dae2223"
                               "b00361a396177a9cb410ff61f20015ad") ||
        !sha256_matches_vector(padding_boundary,
                               sizeof(padding_boundary) - 1U, 7U,
                               "248d6a61d20638b8e5c026930c3e6039"
                               "a33ce45964ff2167f6ecedd419db06c1")) {
        return -1;
    }

    memset(thousand_a, 'a', sizeof(thousand_a));
    sha256_init(&context);
    for (index = 0U; index < 1000U; index++) {
        if (sha256_update(&context, thousand_a, sizeof(thousand_a)) != 0) {
            return -1;
        }
    }
    if (sha256_final(&context, digest) != 0 ||
        !digest_matches_hex(digest,
                            "cdc76e5c9914fb9281a1c7e284d73e67"
                            "f1809a48a497200e046d39ccc7112cd0")) {
        return -1;
    }
    return 0;
}
#endif

static int read_random(void *buffer, size_t size)
{
    unsigned char *cursor = buffer;

    /* FreeBSD exposes /dev/urandom as a symlink to /dev/random and reports an
     * O_NOFOLLOW open as EMLINK. Use the supported libc entropy interface so
     * secure staging names never depend on following a device pathname.
     * getentropy(3) limits each request to 256 bytes on every supported host. */
    while (size > 0U) {
        size_t count = size > 256U ? 256U : size;

        if (getentropy(cursor, count) != 0) {
            return -1;
        }
        cursor += count;
        size -= count;
    }
    return 0;
}

static int create_named_temp(int directory_fd, const char *final_name,
                             char *temp_name, size_t temp_name_size)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char random_bytes[16];
    char suffix[(sizeof(random_bytes) * 2U) + 1U];
    size_t index;
    int attempt;

    for (attempt = 0; attempt < 32; attempt++) {
        int length;
        int fd;

        if (read_random(random_bytes, sizeof(random_bytes)) != 0) {
            return -1;
        }
        for (index = 0; index < sizeof(random_bytes); index++) {
            suffix[index * 2U] = hex[random_bytes[index] >> 4U];
            suffix[(index * 2U) + 1U] = hex[random_bytes[index] & 0x0fU];
        }
        suffix[sizeof(suffix) - 1U] = '\0';
        length = snprintf(temp_name, temp_name_size, ".%s.tmp.%s", final_name,
                          suffix);
        if (length < 0 || (size_t)length >= temp_name_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = openat(directory_fd, temp_name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

static int create_temp(int directory_fd, const char *final_name,
                       char *temp_name, size_t temp_name_size,
                       bool *has_name)
{
#if !defined(GITSWITCH_RELEASE_FORCE_NAMED_TEMP) && \
    defined(O_TMPFILE) && O_TMPFILE != 0
    int fd = openat(directory_fd, ".",
                    O_RDWR | O_TMPFILE | O_CLOEXEC,
                    S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        temp_name[0] = '\0';
        *has_name = false;
        return fd;
    }
    if (errno != EOPNOTSUPP && errno != EISDIR && errno != EINVAL &&
        errno != ENOSYS) {
        return -1;
    }
#endif
    *has_name = true;
    return create_named_temp(directory_fd, final_name, temp_name,
                             temp_name_size);
}

static int verify_named_temp_identity(int directory_fd, const char *temp_name,
                                      int temp_fd)
{
    struct stat descriptor_stat;
    struct stat path_stat;

    if (fstat(temp_fd, &descriptor_stat) != 0 ||
        fstatat(directory_fd, temp_name, &path_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!same_identity(&descriptor_stat, &path_stat)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

#if defined(GITSWITCH_RELEASE_TEST_CLEANUP_RACE) || \
    defined(GITSWITCH_RELEASE_TEST_ADOPTION_RACE) || \
    (defined(__FreeBSD__) && \
     defined(GITSWITCH_RELEASE_TEST_PUBLICATION_RACE))
static int run_test_race_hook(const char *marker_variable,
                              const char *release_variable, bool *hook_used)
{
    const char *marker = getenv(marker_variable);
    const char *release = getenv(release_variable);
    struct timespec delay = {0, 50L * 1000L * 1000L};
    struct stat released;
    int marker_fd;
    int attempt;

    if (*hook_used || (marker == NULL && release == NULL)) {
        return 0;
    }
    if (marker == NULL || marker[0] == '\0' || release == NULL ||
        release[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    *hook_used = true;
    marker_fd = open(marker,
                     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     S_IRUSR | S_IWUSR);
    if (marker_fd < 0 || close(marker_fd) != 0) {
        return -1;
    }
    for (attempt = 0; attempt < 200; attempt++) {
        if (lstat(release, &released) == 0) {
            return 0;
        }
        if (errno != ENOENT) {
            return -1;
        }
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR) {
                return -1;
            }
        }
        delay.tv_sec = 0;
        delay.tv_nsec = 50L * 1000L * 1000L;
    }
    errno = ETIMEDOUT;
    return -1;
}
#endif

static int run_cleanup_race_hook(void)
{
#if defined(GITSWITCH_RELEASE_TEST_CLEANUP_RACE)
    static bool hook_used;

    return run_test_race_hook("GITSWITCH_RELEASE_TEST_CLEANUP_MARKER",
                              "GITSWITCH_RELEASE_TEST_CLEANUP_RELEASE",
                              &hook_used);
#else
    return 0;
#endif
}

#if defined(__FreeBSD__)
static int run_publication_race_hook(void)
{
#if defined(GITSWITCH_RELEASE_TEST_PUBLICATION_RACE)
    static bool hook_used;

    return run_test_race_hook("GITSWITCH_RELEASE_TEST_PUBLICATION_MARKER",
                              "GITSWITCH_RELEASE_TEST_PUBLICATION_RELEASE",
                              &hook_used);
#else
    return 0;
#endif
}
#endif

/* FreeBSD can condition unlink on the still-open vnode with funlinkat(2).
 * Linux and Darwin cannot: after any pathname proof, a same-UID writer can
 * substitute the name before unlinkat(2).  Their named fallback is therefore
 * retained, never renamed, unlinked, or truncated: a same-UID process can
 * hard-link the staging inode after any user-space proof, so descriptor
 * truncation could still mutate a substituted public name. Return 0 for
 * removed, 1 for safely retained, and -1 for an identity race or cleanup
 * failure. */
static int retire_named_temp(int directory_fd, const char *temp_name,
                             int temp_fd)
{
    if (verify_named_temp_identity(directory_fd, temp_name, temp_fd) != 0 ||
        run_cleanup_race_hook() != 0) {
        return -1;
    }
#if defined(__FreeBSD__)
    if (funlinkat(directory_fd, temp_name, temp_fd, 0) != 0) {
        return -1;
    }
    return 0;
#else
    if (verify_named_temp_identity(directory_fd, temp_name, temp_fd) != 0) {
        return -1;
    }
    return 1;
#endif
}

static int create_producer_pipe(int pipe_fds[2])
{
    int index;
    int saved_errno;

    if (pipe(pipe_fds) != 0) {
        return -1;
    }
    for (index = 0; index < 2; index++) {
        int flags = fcntl(pipe_fds[index], F_GETFD);

        if (flags < 0 ||
            fcntl(pipe_fds[index], F_SETFD, flags | FD_CLOEXEC) != 0) {
            saved_errno = errno;
            (void)close(pipe_fds[0]);
            (void)close(pipe_fds[1]);
            errno = saved_errno;
            return -1;
        }
    }
    return 0;
}

static int monotonic_milliseconds(int64_t *milliseconds)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    if (now.tv_sec < 0 ||
        (uint64_t)now.tv_sec >
            ((uint64_t)INT64_MAX - (uint64_t)(now.tv_nsec / 1000000L)) /
                1000U) {
        errno = EOVERFLOW;
        return -1;
    }
    *milliseconds = ((int64_t)now.tv_sec * 1000) +
                    (int64_t)(now.tv_nsec / 1000000L);
    return 0;
}

/* Return one while time remains, zero at the deadline, and minus one when the
 * monotonic clock itself cannot be sampled. */
static int deadline_remaining(int64_t deadline, int *remaining)
{
    int64_t difference;
    int64_t now;

    if (monotonic_milliseconds(&now) != 0) {
        return -1;
    }
    difference = deadline - now;
    if (difference <= 0) {
        *remaining = 0;
        return 0;
    }
    *remaining = difference > INT_MAX ? INT_MAX : (int)difference;
    return 1;
}

static int write_all(int fd, const unsigned char *buffer, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        ssize_t written = write(fd, buffer + offset, size - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

/* Keep the direct child PID published until its terminal status has been
 * retained. In particular, a successful direct child can become waitable
 * while a descendant still owns the output pipe. */
static volatile pid_t fatal_signal_producer = 0;

typedef enum producer_status_result {
    PRODUCER_STATUS_ERROR = -1,
    PRODUCER_STATUS_RUNNING = 0,
    PRODUCER_STATUS_SUCCESS = 1,
    PRODUCER_STATUS_FAILURE = 2
} producer_status_result_t;

typedef enum producer_stream_result {
    PRODUCER_STREAM_CAPTURE_ERROR = -1,
    PRODUCER_STREAM_COMPLETE = 0,
    PRODUCER_STREAM_FAILURE = 1,
    PRODUCER_STREAM_WAIT_ERROR = 2
} producer_stream_result_t;

/* Observe without releasing the PID first. A failed producer's process group
 * must be terminated while child still pins that numeric identity; only then
 * may waitpid retain the exact status and make the PID reusable. A successful
 * producer is left waitable when reap_success is false so inherited output can
 * still be drained under the same owned lifetime boundary. */
static producer_status_result_t observe_producer_status(pid_t child,
                                                         bool reap_success,
                                                         int *status)
{
    siginfo_t observed;
    pid_t waited;
    bool failed;
    int waitid_rc;

    do {
        memset(&observed, 0, sizeof(observed));
        waitid_rc = waitid(P_PID, (id_t)child, &observed,
                           WEXITED | WNOHANG | WNOWAIT);
    } while (waitid_rc != 0 && errno == EINTR);
    if (waitid_rc != 0) {
        return PRODUCER_STATUS_ERROR;
    }
    if (observed.si_pid == 0) {
        return PRODUCER_STATUS_RUNNING;
    }
    if (observed.si_code == CLD_EXITED) {
        failed = observed.si_status != 0;
    } else if (observed.si_code == CLD_KILLED ||
               observed.si_code == CLD_DUMPED) {
        failed = true;
    } else {
        errno = EIO;
        return PRODUCER_STATUS_ERROR;
    }
    if (!failed && !reap_success) {
        return PRODUCER_STATUS_SUCCESS;
    }

    if (failed) {
        (void)kill(-child, SIGKILL);
    }
    do {
        waited = waitpid(child, status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0) {
        errno = EAGAIN;
        return PRODUCER_STATUS_ERROR;
    }
    if (waited < 0) {
        return PRODUCER_STATUS_ERROR;
    }
    fatal_signal_producer = 0;
    return failed ? PRODUCER_STATUS_FAILURE : PRODUCER_STATUS_SUCCESS;
}

static int supervise_producer_status(pid_t child, bool *producer_succeeded,
                                     int *status)
{
    producer_status_result_t result;

    if (*producer_succeeded) {
        return 0;
    }
    result = observe_producer_status(child, false, status);
    if (result == PRODUCER_STATUS_ERROR) {
        return -1;
    }
    if (result == PRODUCER_STATUS_FAILURE) {
        return 1;
    }
    if (result == PRODUCER_STATUS_SUCCESS) {
        *producer_succeeded = true;
    }
    return 0;
}

static producer_stream_result_t copy_producer_stream(int input_fd,
                                                      int output_fd,
                                                      pid_t child,
                                                      int64_t deadline,
                                                      int *status)
{
    unsigned char buffer[64U * 1024U];
    struct pollfd input;
    bool producer_succeeded = false;

    input.fd = input_fd;
    input.events = POLLIN;
    for (;;) {
        int remaining;
        int remaining_rc = deadline_remaining(deadline, &remaining);
        int producer_rc;
        int poll_rc;
        int poll_timeout;
        ssize_t count;

        if (remaining_rc <= 0) {
            producer_rc = supervise_producer_status(
                child, &producer_succeeded, status);
            if (producer_rc < 0) {
                return PRODUCER_STREAM_WAIT_ERROR;
            }
            if (producer_rc > 0) {
                return PRODUCER_STREAM_FAILURE;
            }
            if (remaining_rc == 0) {
                errno = ETIMEDOUT;
            }
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        poll_timeout = producer_succeeded || remaining <= 50 ? remaining : 50;
        input.revents = 0;
        poll_rc = poll(&input, 1, poll_timeout);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        if (poll_rc == 0) {
            producer_rc = supervise_producer_status(
                child, &producer_succeeded, status);
            if (producer_rc < 0) {
                return PRODUCER_STREAM_WAIT_ERROR;
            }
            if (producer_rc > 0) {
                return PRODUCER_STREAM_FAILURE;
            }
            continue;
        }
        if ((input.revents & POLLNVAL) != 0) {
            errno = EBADF;
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        if ((input.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            errno = EIO;
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        do {
            count = read(input_fd, buffer, sizeof(buffer));
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        if (count > 0 &&
            write_all(output_fd, buffer, (size_t)count) != 0) {
            return PRODUCER_STREAM_CAPTURE_ERROR;
        }
        producer_rc = supervise_producer_status(
            child, &producer_succeeded, status);
        if (producer_rc < 0) {
            return PRODUCER_STREAM_WAIT_ERROR;
        }
        if (producer_rc > 0) {
            return PRODUCER_STREAM_FAILURE;
        }
        if (count == 0) {
            return PRODUCER_STREAM_COMPLETE;
        }
    }
}

/* AR-10 L30: the producer runs in its own process group as the helper's
 * lifetime boundary — which also removes it from the terminal's foreground
 * group, so a Ctrl-C (or any SIGINT/SIGTERM/SIGHUP delivered to the helper)
 * used to kill only the helper and abandon the still-running producer group.
 * The handler makes the boundary hold: kill the group, then die by the same
 * signal with default disposition so the caller observes a truthful
 * signal-death status. kill/signal/raise are all async-signal-safe. */

static void forward_fatal_signal(int signal_number)
{
    pid_t child = fatal_signal_producer;

    if (child > 0) {
        (void)kill(-child, SIGKILL);
        (void)kill(child, SIGKILL);
    }
    (void)signal(signal_number, SIG_DFL);
    (void)raise(signal_number);
}

/* Preserve an inherited SIG_IGN (nohup semantics); otherwise forward. */
static int install_fatal_signal_forwarding(void)
{
    static const int fatal_signals[] = { SIGINT, SIGTERM, SIGHUP };
    size_t index;

    for (index = 0;
         index < sizeof(fatal_signals) / sizeof(fatal_signals[0]); index++) {
        struct sigaction current;
        struct sigaction forwarding;

        if (sigaction(fatal_signals[index], NULL, &current) != 0) {
            return -1;
        }
        if (current.sa_handler == SIG_IGN) {
            continue;
        }
        memset(&forwarding, 0, sizeof(forwarding));
        forwarding.sa_handler = forward_fatal_signal;
        if (sigemptyset(&forwarding.sa_mask) != 0 ||
            sigaction(fatal_signals[index], &forwarding, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int wait_for_producer(pid_t child, int64_t deadline, int *status)
{
    for (;;) {
        producer_status_result_t result =
            observe_producer_status(child, true, status);

        if (result == PRODUCER_STATUS_SUCCESS ||
            result == PRODUCER_STATUS_FAILURE) {
            return 0;
        }
        if (result == PRODUCER_STATUS_ERROR) {
            return -1;
        }
        {
            int remaining;
            int remaining_rc = deadline_remaining(deadline, &remaining);
            int pause_ms;
            int poll_rc;

            if (remaining_rc <= 0) {
                if (remaining_rc == 0) {
                    errno = ETIMEDOUT;
                }
                return -1;
            }
            pause_ms = remaining > 50 ? 50 : remaining;
            poll_rc = poll(NULL, 0, pause_ms);
            if (poll_rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
        }
    }
}

static void terminate_producer(pid_t child)
{
    int saved_errno = errno;
    int status;
    pid_t waited;

    /* The child creates this process group before it can exec or write output,
     * so ordinary descendants remain inside the lifetime boundary. Killing the
     * direct PID as well covers an early setpgid failure. */
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    fatal_signal_producer = 0;
    errno = saved_errno;
}

static void report_producer_failure(int status)
{
    if (WIFEXITED(status)) {
        fprintf(stderr, "ERROR: archive command exited with status %d\n",
                WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "ERROR: archive command terminated by signal %d\n",
                WTERMSIG(status));
    } else {
        fprintf(stderr, "ERROR: archive command did not exit normally\n");
    }
}

static int run_to_descriptor(int output_fd, char *const command[])
{
    int pipe_fds[2];
    int status;
    int saved_errno;
    int64_t deadline;
    int64_t started;
    pid_t child;
    producer_stream_result_t stream_result;

    if (create_producer_pipe(pipe_fds) != 0) {
        return -1;
    }
    child = fork();

    if (child < 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    if (child == 0) {
        int descriptor_flags;

        (void)close(pipe_fds[0]);
        if (setpgid(0, 0) != 0) {
            _exit(126);
        }
        if (pipe_fds[1] == STDOUT_FILENO) {
            descriptor_flags = fcntl(STDOUT_FILENO, F_GETFD);
            if (descriptor_flags < 0 ||
                fcntl(STDOUT_FILENO, F_SETFD,
                      descriptor_flags & ~FD_CLOEXEC) != 0) {
                _exit(126);
            }
        } else if (dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        if (pipe_fds[1] != STDOUT_FILENO) {
            (void)close(pipe_fds[1]);
        }
        if (output_fd != STDOUT_FILENO) {
            (void)close(output_fd);
        }
        execvp(command[0], command); /* Flawfinder: ignore — argv-vector exec of the operator's archive command; no shell, vector from the Makefile recipe */
        _exit(errno == ENOENT ? 127 : 126);
    }
    /* Publish the producer to the fatal-signal forwarder before anything in
     * this parent can fail or block. */
    fatal_signal_producer = child;
    (void)close(pipe_fds[1]);
    /* Close the fork/setpgid race from the parent side as well. EACCES/ESRCH
     * only mean the child already crossed that boundary or exited; the child
     * itself cannot exec until its own setpgid succeeds. */
    (void)setpgid(child, child);
    if (monotonic_milliseconds(&started) != 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (started > INT64_MAX -
                      (int64_t)GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS) {
        (void)close(pipe_fds[0]);
        errno = EOVERFLOW;
        terminate_producer(child);
        return -1;
    }
    deadline = started + (int64_t)GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS;
    stream_result = copy_producer_stream(pipe_fds[0], output_fd, child,
                                         deadline, &status);
    if (stream_result != PRODUCER_STREAM_COMPLETE) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        if (stream_result == PRODUCER_STREAM_FAILURE) {
            report_producer_failure(status);
            errno = EIO;
            return -1;
        }
        if (stream_result == PRODUCER_STREAM_WAIT_ERROR) {
            fprintf(stderr, "ERROR: cannot wait for archive command: %s\n",
                    strerror(saved_errno));
        } else if (saved_errno == ETIMEDOUT) {
            fprintf(stderr,
                    "ERROR: archive command timed out before output stream completion\n");
        } else {
            fprintf(stderr, "ERROR: cannot capture archive command output: %s\n",
                    strerror(saved_errno));
        }
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    (void)close(pipe_fds[0]);
    if (wait_for_producer(child, deadline, &status) != 0) {
        saved_errno = errno;
        if (saved_errno == ETIMEDOUT) {
            fprintf(stderr,
                    "ERROR: archive command timed out before output stream completion\n");
        } else {
            fprintf(stderr, "ERROR: cannot wait for archive command: %s\n",
                    strerror(saved_errno));
        }
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    /* Reaped: the group may still hold inherited-descriptor descendants, but
     * the direct producer pid is no longer this process's to kill. */
    fatal_signal_producer = 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        report_producer_failure(status);
        errno = EIO;
        return -1;
    }
    return 0;
}

#if !defined(__APPLE__)
static int link_descriptor(int source_fd, int directory_fd,
                           const char *source_name,
                           const char *final_name)
{
#if defined(__FreeBSD__)
    /* FreeBSD reserves linkat(AT_EMPTY_PATH) for privileged callers, while a
     * link through fdescfs is rejected as cross-device. The source necessarily
     * has a private random name on this platform, so identity-seal that name
     * immediately before the atomic no-replace link. The caller proves the
     * published name still selects source_fd immediately afterward; a source
     * substitution can therefore leave evidence but can never report success. */
    if (source_name == NULL || source_name[0] == '\0') {
        errno = ENOTSUP;
        return -1;
    }
    if (verify_named_temp_identity(directory_fd, source_name, source_fd) != 0 ||
        run_publication_race_hook() != 0) {
        return -1;
    }
    return linkat(directory_fd, source_name, directory_fd, final_name, 0);
#else
    (void)source_name;
#if defined(AT_EMPTY_PATH) && AT_EMPTY_PATH != 0
    if (linkat(source_fd, "", directory_fd, final_name, AT_EMPTY_PATH) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return -1;
    }
#endif
#if defined(AT_SYMLINK_FOLLOW)
    {
        char descriptor_path[64];
        int length = snprintf(descriptor_path, sizeof(descriptor_path),
                              "/dev/fd/%d", source_fd);

        if (length < 0 || (size_t)length >= sizeof(descriptor_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return linkat(AT_FDCWD, descriptor_path, directory_fd, final_name,
                      AT_SYMLINK_FOLLOW);
    }
#else
    (void)source_fd;
    (void)directory_fd;
    (void)final_name;
    errno = ENOTSUP;
    return -1;
#endif
#endif
}
#endif

static int verify_published_identity(int source_fd, int directory_fd,
                                     const char *final_name)
{
    struct stat descriptor_stat;
    struct stat published_stat;

    if (fstat(source_fd, &descriptor_stat) != 0 ||
        fstatat(directory_fd, final_name, &published_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!same_identity(&descriptor_stat, &published_stat)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int verify_canonical_directory(int directory_fd,
                                      const char *canonical_directory)
{
    struct stat pinned_stat;
    struct stat canonical_stat;
    int canonical_fd;
    int saved_errno;

    if (fstat(directory_fd, &pinned_stat) != 0) {
        return -1;
    }
    canonical_fd = open(canonical_directory,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (canonical_fd < 0) {
        return -1;
    }
    if (fstat(canonical_fd, &canonical_stat) != 0) {
        saved_errno = errno;
        (void)close(canonical_fd);
        errno = saved_errno;
        return -1;
    }
    if (close(canonical_fd) != 0) {
        return -1;
    }
    if (pinned_stat.st_dev != canonical_stat.st_dev ||
        pinned_stat.st_ino != canonical_stat.st_ino ||
        !S_ISDIR(pinned_stat.st_mode) || !S_ISDIR(canonical_stat.st_mode)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

#if defined(__APPLE__)
static int clone_id_for_descriptor(int fd, uint64_t *clone_id)
{
    unsigned char buffer[sizeof(uint32_t) + sizeof(uint64_t)];
    struct attrlist attributes;
    uint32_t returned_size;

    memset(&attributes, 0, sizeof(attributes));
    memset(buffer, 0, sizeof(buffer));
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.forkattr = ATTR_CMNEXT_CLONEID;
    if (fgetattrlist(fd, &attributes, buffer, sizeof(buffer),
                     FSOPT_ATTR_CMN_EXTENDED) != 0) {
        return -1;
    }
    memcpy(&returned_size, buffer, sizeof(returned_size));
    if (returned_size != sizeof(buffer)) {
        errno = ENOTSUP;
        return -1;
    }
    memcpy(clone_id, buffer + sizeof(returned_size), sizeof(*clone_id));
    if (*clone_id == 0U) {
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}

static int descriptors_have_same_contents(int source_fd, int destination_fd)
{
    unsigned char source_buffer[64U * 1024U];
    unsigned char destination_buffer[sizeof(source_buffer)];
    struct stat source_stat;
    struct stat destination_stat;
    off_t offset = 0;

    if (fstat(source_fd, &source_stat) != 0 ||
        fstat(destination_fd, &destination_stat) != 0) {
        return -1;
    }
    if (same_identity(&source_stat, &destination_stat)) {
        errno = ESTALE;
        return -1;
    }
    if (!S_ISREG(source_stat.st_mode) ||
        !S_ISREG(destination_stat.st_mode) ||
        source_stat.st_size != destination_stat.st_size ||
        (source_stat.st_mode & 07777) !=
            (destination_stat.st_mode & 07777)) {
        errno = ESTALE;
        return -1;
    }
    while (offset < source_stat.st_size) {
        size_t wanted = sizeof(source_buffer);
        ssize_t source_count;
        ssize_t destination_count;

        if (source_stat.st_size - offset < (off_t)wanted) {
            wanted = (size_t)(source_stat.st_size - offset);
        }
        do {
            source_count = pread(source_fd, source_buffer, wanted, offset);
        } while (source_count < 0 && errno == EINTR);
        if (source_count <= 0) {
            if (source_count == 0) {
                errno = EIO;
            }
            return -1;
        }
        do {
            destination_count = pread(destination_fd, destination_buffer,
                                      (size_t)source_count, offset);
        } while (destination_count < 0 && errno == EINTR);
        if (destination_count != source_count ||
            memcmp(source_buffer, destination_buffer,
                   (size_t)source_count) != 0) {
            if (destination_count >= 0) {
                errno = ESTALE;
            }
            return -1;
        }
        offset += source_count;
    }
    return 0;
}

static int run_adoption_race_hook(void)
{
#if defined(GITSWITCH_RELEASE_TEST_ADOPTION_RACE)
    static bool hook_used;

    return run_test_race_hook("GITSWITCH_RELEASE_TEST_ADOPTION_MARKER",
                              "GITSWITCH_RELEASE_TEST_ADOPTION_RELEASE",
                              &hook_used);
#else
    return 0;
#endif
}

static int publish_descriptor_clone(int source_fd, int directory_fd,
                                    const char *final_name,
                                    int *published_fd)
{
    int destination_fd;
    int reserve_fd;
    int saved_errno;
    uint64_t source_clone_id;
    uint64_t destination_clone_id;
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
    struct rlimit saved_limit;
    struct rlimit pressure_limit;
#endif

    /* fclonefileat binds its source to source_fd, creates the destination only
     * if absent, and publishes the complete clone atomically.  Do not fall
     * back to a pathname rename or visible incremental copy on filesystems
     * without clone support: both would reopen a race/crash window. */
    /* Reserve one descriptor before committing the clone. Releasing it gives
     * this single-threaded helper capacity under its process descriptor limit
     * before adoption. Global file-table capacity can still be consumed by
     * another process; that post-commit failure is reported as uncertainty and
     * both complete paths are retained. */
    reserve_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (reserve_fd < 0) {
        return -1;
    }
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
    if (getrlimit(RLIMIT_NOFILE, &saved_limit) != 0) {
        saved_errno = errno;
        (void)close(reserve_fd);
        errno = saved_errno;
        return -1;
    }
    pressure_limit = saved_limit;
    pressure_limit.rlim_cur = (rlim_t)reserve_fd + 1U;
    if (setrlimit(RLIMIT_NOFILE, &pressure_limit) != 0) {
        saved_errno = errno;
        (void)close(reserve_fd);
        errno = saved_errno;
        return -1;
    }
#endif
    if (fclonefileat(source_fd, directory_fd, final_name, 0) != 0) {
        saved_errno = errno;
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
        (void)setrlimit(RLIMIT_NOFILE, &saved_limit);
#endif
        (void)close(reserve_fd);
        errno = saved_errno;
        return -1;
    }
    (void)close(reserve_fd);
    if (run_adoption_race_hook() != 0) {
        saved_errno = errno;
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
        (void)setrlimit(RLIMIT_NOFILE, &saved_limit);
#endif
        errno = saved_errno;
        return 1;
    }
    do {
        destination_fd = openat(directory_fd, final_name,
                                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (destination_fd < 0 && errno == EINTR);
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
    saved_errno = errno;
    if (setrlimit(RLIMIT_NOFILE, &saved_limit) != 0) {
        if (destination_fd >= 0) {
            (void)close(destination_fd);
        }
        return 1;
    }
    errno = saved_errno;
#endif
    if (destination_fd < 0) {
        return 1;
    }

    /* The open occurs after the atomic clone syscall, so prove it adopted a
     * pure clone of our source before reporting the committed name as fully
     * verified.  A pathname replacement with unrelated contents is closed and
     * preserved; publication is never compensated with pathname deletion. */
    if (clone_id_for_descriptor(source_fd, &source_clone_id) != 0 ||
        clone_id_for_descriptor(destination_fd, &destination_clone_id) != 0 ||
        source_clone_id != destination_clone_id ||
        descriptors_have_same_contents(source_fd, destination_fd) != 0) {
        saved_errno = errno;
        (void)close(destination_fd);
        errno = saved_errno == 0 ? ESTALE : saved_errno;
        return 1;
    }
    if (verify_published_identity(destination_fd, directory_fd,
                                  final_name) == 0) {
        *published_fd = destination_fd;
        return 0;
    }

    saved_errno = errno;
    (void)close(destination_fd);
    errno = saved_errno;
    return 1;
}
#endif

static int publish_output(int source_fd, int directory_fd,
                          const char *source_name,
                          const char *final_name, int *published_fd)
{
#if defined(__APPLE__)
    (void)source_name;
    return publish_descriptor_clone(source_fd, directory_fd, final_name,
                                    published_fd);
#else
    if (link_descriptor(source_fd, directory_fd, source_name,
                        final_name) != 0) {
        return -1;
    }
    *published_fd = source_fd;
    return 0;
#endif
}

int main(int argc, char **argv)
{
    char temp_name[NAME_MAX + 1U];
    const char *directory_path;
    const char *canonical_directory;
    const char *final_name;
    int directory_fd = -1;
    int output_fd = -1;
    int published_fd = -1;
    int publish_rc;
    int retire_rc;
    bool has_name = false;
    unsigned char expected_digest[SHA256_DIGEST_SIZE];
    unsigned char published_digest[SHA256_DIGEST_SIZE];
    struct stat existing;
    struct stat output_stat;
    int result = EXIT_FAILURE;

    /* Must precede every other descriptor acquisition; see the helper. On
     * failure there is no guaranteed-safe stderr to report on. */
    if (reserve_standard_descriptors() != 0) {
        return EXIT_FAILURE;
    }
#if defined(GITSWITCH_RELEASE_TEST_DIGEST)
    if (argc == 2 && strcmp(argv[1], "--test-sha256") == 0) {
        if (run_sha256_known_answer_tests() != 0) {
            fprintf(stderr, "ERROR: internal SHA-256 known-answer test failed\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
#endif
    if (install_fatal_signal_forwarding() != 0) {
        fprintf(stderr, "ERROR: cannot install signal forwarding: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (argc < 6 || strcmp(argv[4], "--") != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    directory_path = argv[1];
    canonical_directory = argv[2];
    final_name = argv[3];
    if (final_name[0] == '\0' || strcmp(final_name, ".") == 0 ||
        strcmp(final_name, "..") == 0 || strchr(final_name, '/') != NULL) {
        fprintf(stderr, "ERROR: final archive name is not a single component\n");
        return EXIT_FAILURE;
    }

    directory_fd = open(directory_path,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        fprintf(stderr, "ERROR: cannot open distribution directory: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (verify_canonical_directory(directory_fd, canonical_directory) != 0) {
        fprintf(stderr, "ERROR: canonical distribution directory changed identity\n");
        goto cleanup;
    }
    if (fstatat(directory_fd, final_name, &existing,
                AT_SYMLINK_NOFOLLOW) == 0) {
        fprintf(stderr,
                "ERROR: distribution archive already exists; refusing to replace it\n");
        goto cleanup;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "ERROR: cannot inspect distribution output: %s\n",
                strerror(errno));
        goto cleanup;
    }

    output_fd = create_temp(directory_fd, final_name, temp_name,
                            sizeof(temp_name), &has_name);
    if (output_fd < 0) {
        fprintf(stderr, "ERROR: cannot create pinned distribution output: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (run_to_descriptor(output_fd, &argv[5]) != 0) {
        goto cleanup;
    }
    if (fstat(output_fd, &output_stat) != 0 ||
        !S_ISREG(output_stat.st_mode) || output_stat.st_size <= 0) {
        fprintf(stderr, "ERROR: archive command produced no regular output\n");
        goto cleanup;
    }
    /* Make the completed bytes read-only before any public name can select
     * them. The open descriptor remains usable for sync and descriptor-bound
     * verification without reopening a writable pathname. */
    if (fchmod(output_fd, S_IRUSR | S_IRGRP | S_IROTH) != 0 ||
        fsync(output_fd) != 0) {
        fprintf(stderr, "ERROR: cannot sync completed distribution output: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (digest_read_only_regular_descriptor(output_fd, output_stat.st_size,
                                            expected_digest) != 0) {
        fprintf(stderr,
                "ERROR: cannot prove completed distribution output bytes: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (has_name &&
        verify_named_temp_identity(directory_fd, temp_name, output_fd) != 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: distribution temporary output changed before publication; replacement retained\n");
        goto cleanup;
    }
    publish_rc = publish_output(output_fd, directory_fd,
                                has_name ? temp_name : NULL, final_name,
                                &published_fd);
    if (publish_rc < 0) {
        fprintf(stderr,
                "ERROR: cannot publish pinned distribution output without replacement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (publish_rc > 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: distribution output was atomically published, but its final identity could not be adopted; complete artifact and private source retained for inspection\n");
        goto cleanup;
    }
    if (verify_published_identity(published_fd, directory_fd,
                                  final_name) != 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: published distribution output changed identity; artifact and private source retained\n");
        goto cleanup;
    }
    if (published_fd != output_fd && fsync(published_fd) != 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: cannot sync adopted distribution output; artifact and private source retained: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (has_name &&
        (retire_rc = retire_named_temp(directory_fd, temp_name,
                                      output_fd)) < 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: distribution temporary output changed identity; published artifact and temporary name retained\n");
        goto cleanup;
    }
    if (has_name && retire_rc > 0) {
        fprintf(stderr,
                "WARNING: platform lacks descriptor-conditioned unlink; private distribution staging name retained\n");
    }
    has_name = false;
    if (fsync(directory_fd) != 0) {
        fprintf(stderr,
                "ERROR: cannot sync distribution directory; published artifact retained: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (verify_canonical_directory(directory_fd, canonical_directory) != 0) {
        fprintf(stderr,
                "ERROR: canonical distribution directory changed during publication; artifact retained\n");
        goto cleanup;
    }
    if (verify_published_identity(published_fd, directory_fd,
                                  final_name) != 0) {
        fprintf(stderr,
                "ERROR: published distribution output changed before completion; artifact retained\n");
        goto cleanup;
    }
    if (digest_read_only_regular_descriptor(published_fd,
                                            output_stat.st_size,
                                            published_digest) != 0) {
        fprintf(stderr,
                "ERROR: cannot prove published distribution output bytes before completion; artifact retained: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (memcmp(expected_digest, published_digest,
               sizeof(expected_digest)) != 0) {
        errno = ESTALE;
        fprintf(stderr,
                "ERROR: published distribution output changed content before completion; artifact retained\n");
        goto cleanup;
    }
    /* Close a replacement race during the descriptor digest: this is the
     * final publication proof before provisional success. Descriptor closes
     * below remain checked and can still turn the overall result into failure. */
    if (verify_published_identity(published_fd, directory_fd,
                                  final_name) != 0) {
        fprintf(stderr,
                "ERROR: published distribution output changed before completion; artifact retained\n");
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    if (has_name && output_fd >= 0) {
        retire_rc = retire_named_temp(directory_fd, temp_name, output_fd);
        if (retire_rc < 0) {
            fprintf(stderr,
                    "ERROR: distribution staging name changed; replacement retained\n");
        } else if (retire_rc > 0) {
            fprintf(stderr,
                    "WARNING: failed publication retained its private staging name\n");
        }
        result = EXIT_FAILURE;
    }
    if (published_fd >= 0 && published_fd != output_fd &&
        close(published_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (output_fd >= 0 && close(output_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (directory_fd >= 0 && close(directory_fd) != 0) {
        result = EXIT_FAILURE;
    }
    return result;
}
