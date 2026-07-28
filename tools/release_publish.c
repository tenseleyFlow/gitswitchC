#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#define _GNU_SOURCE 1
#endif

#include "../src/freebsd_compat.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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
#include <crt_externs.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/random.h>
#include <sys/sysctl.h>
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
#include <sys/resource.h>
#endif
#endif

#if defined(__APPLE__)
#define archive_process_environ (*_NSGetEnviron())
#else
extern char **environ;
#define archive_process_environ environ
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

#ifndef GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS
#define GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS 3600000
#endif

#if GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS <= 0
#error "GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS must be positive"
#endif

#if GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS <= 0
#error "GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS must be positive"
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
/* AR-12 L27 / AR-13 L3: on Darwin fsync(2) only reaches the drive, not through
 * its cache; power-loss durability — the guarantee the stage barriers and rpm
 * retirement advertise — needs F_FULLFSYNC. Fall back to plain fsync ONLY when
 * the volume/descriptor cannot support the fcntl (ENOTSUP/ENOTTY/EINVAL);
 * retry EINTR; propagate any other errno as a hard failure rather than masking
 * a real flush error as durable success. */
static int full_fsync(int fd)
{
#if defined(__APPLE__)
    int rc;
    do {
        rc = fcntl(fd, F_FULLFSYNC);
    } while (rc != 0 && errno == EINTR);
    if (rc == 0) {
        return 0;
    }
    if (errno != ENOTSUP && errno != ENOTTY && errno != EINVAL) {
        return -1;
    }
#endif
    return fsync(fd);
}

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
            "usage: %s OUTPUT_DIRECTORY CANONICAL_DIRECTORY FINAL_NAME -- COMMAND [ARG ...]\n"
            "       %s --internal-release-tree-v1 ROOT BUILD_COMPONENT DIST_COMPONENT FINAL_NAME -- COMMAND [ARG ...]\n"
            "       %s --internal-release-tree-consume-v1 ROOT BUILD_COMPONENT DIST_COMPONENT PRIVATE_NAME -- PRODUCER [ARG ...] --internal-consumer-v1 CONSUMER [ARG ...]\n"
            "       %s --internal-release-tree-from-dir-v1 ROOT BUILD_COMPONENT DIST_COMPONENT FINAL_NAME SOURCE_DIR_FD SOURCE_DIR_DEV SOURCE_DIR_INO EXPECTED_DEV EXPECTED_INO EXPECTED_SIZE EXPECTED_SHA256\n"
            "       %s --internal-rpm-stage-v1 RPMS_FD RPMS_DEV RPMS_INO SRPMS_FD SRPMS_DEV SRPMS_INO PUBLISH_FD PUBLISH_DEV PUBLISH_INO\n"
            "       %s --internal-regular-fd-identity-v1 FD\n"
            "       %s --internal-retire-tree-v1 HOME PRIVATE_NAME EXPECTED_DEV EXPECTED_INO\n",
            program, program, program, program, program, program, program);
}

static bool same_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           S_ISREG(left->st_mode) && S_ISREG(right->st_mode);
}

static bool same_directory_identity(const struct stat *left,
                                    const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           S_ISDIR(left->st_mode) && S_ISDIR(right->st_mode);
}

#define PRIVATE_RPM_PREFIX ".gitswitch-rpmbuild."
#define PRIVATE_RPM_SUFFIX_SIZE 6U
#define RETIRE_TREE_MAX_DEPTH 256U
#define RETIRE_TREE_RETAINED_STATUS 2
#define PRIVATE_ARCHIVE_ARGUMENT "@GITSWITCH_PRIVATE_ARCHIVE_FD@"
#define PRIVATE_CONSUMER_SEPARATOR "--internal-consumer-v1"

static int run_cleanup_race_hook(void);

static bool private_rpm_name_is_valid(const char *name)
{
    const size_t prefix_size = sizeof(PRIVATE_RPM_PREFIX) - 1U;
    size_t index;

    if (strncmp(name, PRIVATE_RPM_PREFIX, prefix_size) != 0 ||
        strlen(name) != prefix_size + PRIVATE_RPM_SUFFIX_SIZE) {
        return false;
    }
    for (index = prefix_size;
         index < prefix_size + PRIVATE_RPM_SUFFIX_SIZE; index++) {
        unsigned char byte = (unsigned char)name[index];

        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9'))) {
            return false;
        }
    }
    return true;
}

static int parse_decimal_identity(const char *text, uintmax_t *identity)
{
    const unsigned char *cursor = (const unsigned char *)text;
    char *end = NULL;
    uintmax_t value;

    if (*cursor == '\0') {
        errno = EINVAL;
        return -1;
    }
    while (*cursor != '\0') {
        if (*cursor < (unsigned char)'0' ||
            *cursor > (unsigned char)'9') {
            errno = EINVAL;
            return -1;
        }
        cursor++;
    }
    errno = 0;
    value = strtoumax(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0') {
        if (errno == 0) {
            errno = EINVAL;
        }
        return -1;
    }
    *identity = value;
    return 0;
}

/* Pin an absolute lexical-canonical directory without following a symlink in
 * any component. Empty, dot, and dot-dot components would make the supplied
 * spelling differ from the descriptor walk, so reject them. */
static int open_canonical_absolute_directory(const char *path)
{
    const char *cursor;
    int directory_fd;

    if (path[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    do {
        directory_fd =
            open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (directory_fd < 0 && errno == EINTR);
    if (directory_fd < 0) {
        return -1;
    }
    cursor = path + 1;
    if (*cursor == '\0') {
        return directory_fd;
    }
    for (;;) {
        const char *separator = strchr(cursor, '/');
        size_t component_size = separator == NULL
                                    ? strlen(cursor)
                                    : (size_t)(separator - cursor);
        char *component;
        int child_fd;
        int saved_errno;

        if (component_size == 0U ||
            (component_size == 1U && cursor[0] == '.') ||
            (component_size == 2U && cursor[0] == '.' &&
             cursor[1] == '.')) {
            (void)close(directory_fd);
            errno = EINVAL;
            return -1;
        }
        if (component_size > SIZE_MAX - 1U) {
            (void)close(directory_fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        component = malloc(component_size + 1U);
        if (component == NULL) {
            saved_errno = errno;
            (void)close(directory_fd);
            errno = saved_errno;
            return -1;
        }
        memcpy(component, cursor, component_size);
        component[component_size] = '\0';
        do {
            child_fd = openat(directory_fd, component,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        } while (child_fd < 0 && errno == EINTR);
        saved_errno = errno;
        free(component);
        if (child_fd < 0) {
            (void)close(directory_fd);
            errno = saved_errno;
            return -1;
        }
        if (close(directory_fd) != 0) {
            saved_errno = errno;
            (void)close(child_fd);
            errno = saved_errno;
            return -1;
        }
        directory_fd = child_fd;
        if (separator == NULL) {
            return directory_fd;
        }
        cursor = separator + 1;
    }
}

static int revalidate_canonical_directory_path(const char *path,
                                               const struct stat *expected)
{
    struct stat current;
    int directory_fd = open_canonical_absolute_directory(path);
    int saved_errno;

    if (directory_fd < 0) {
        return -1;
    }
    if (fstat(directory_fd, &current) != 0) {
        saved_errno = errno;
        (void)close(directory_fd);
        errno = saved_errno;
        return -1;
    }
    if (!same_directory_identity(expected, &current)) {
        (void)close(directory_fd);
        errno = ESTALE;
        return -1;
    }
    return close(directory_fd);
}

static int revalidate_directory_entry(int parent_fd, const char *name,
                                      int child_fd,
                                      const struct stat *expected)
{
    struct stat descriptor_stat;
    struct stat path_stat;

    if (fstat(child_fd, &descriptor_stat) != 0) {
        return -1;
    }
    if (!same_directory_identity(expected, &descriptor_stat)) {
        errno = ESTALE;
        return -1;
    }
    if (fstatat(parent_fd, name, &path_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!same_directory_identity(&descriptor_stat, &path_stat)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

#if defined(__FreeBSD__)
static int visit_retirement_tree(int directory_fd, dev_t tree_device,
                                 unsigned int depth, bool remove_entries)
{
    DIR *stream;
    int stream_fd;
    int result = 0;

    if (depth >= RETIRE_TREE_MAX_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    do {
        stream_fd = openat(directory_fd, ".",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (stream_fd < 0 && errno == EINTR);
    if (stream_fd < 0) return -1;
    stream = fdopendir(stream_fd);
    if (stream == NULL) {
        int saved_errno = errno;

        (void)close(stream_fd);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        struct dirent *entry;
        struct stat before;
        struct stat pinned;
        int saved_errno;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                result = -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (fstatat(directory_fd, entry->d_name, &before,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            result = -1;
            break;
        }
        if (before.st_dev != tree_device) {
            errno = EXDEV;
            result = -1;
            break;
        }
        if (S_ISDIR(before.st_mode)) {
            int child_fd = -1;

            do {
                child_fd = openat(directory_fd, entry->d_name,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);
            } while (child_fd < 0 && errno == EINTR);
            if (child_fd < 0 || fstat(child_fd, &pinned) != 0 ||
                pinned.st_dev != before.st_dev ||
                pinned.st_ino != before.st_ino ||
                !S_ISDIR(pinned.st_mode) ||
                revalidate_directory_entry(directory_fd, entry->d_name,
                                           child_fd, &pinned) != 0 ||
                visit_retirement_tree(child_fd, tree_device, depth + 1U,
                                      remove_entries) != 0) {
                saved_errno = errno;
                if (saved_errno == 0) saved_errno = ESTALE;
                if (child_fd >= 0) {
                    (void)close(child_fd);
                }
                errno = saved_errno;
                result = -1;
                break;
            }
            if (remove_entries &&
                funlinkat(directory_fd, entry->d_name, child_fd,
                          AT_REMOVEDIR) != 0) {
                saved_errno = errno;
                (void)close(child_fd);
                errno = saved_errno;
                result = -1;
                break;
            }
            saved_errno = 0;
            if (close(child_fd) != 0) {
                saved_errno = errno;
            }
            if (saved_errno != 0) {
                errno = saved_errno;
                result = -1;
                break;
            }
        } else if (S_ISREG(before.st_mode)) {
            int entry_fd = -1;

            /* Use a normally operable descriptor for regular leaves. Keeping
             * the open nonblocking means a raced FIFO/device cannot stall;
             * fstat plus funlinkat then bind deletion to that exact vnode. */
            do {
                entry_fd = openat(directory_fd, entry->d_name,
                                  O_RDONLY | O_NONBLOCK | O_NOFOLLOW |
                                      O_CLOEXEC);
            } while (entry_fd < 0 && errno == EINTR);
            if (entry_fd < 0 || fstat(entry_fd, &pinned) != 0 ||
                pinned.st_dev != before.st_dev ||
                pinned.st_ino != before.st_ino ||
                !S_ISREG(pinned.st_mode)) {
                saved_errno = errno;
                if (entry_fd >= 0) (void)close(entry_fd);
                errno = saved_errno != 0 ? saved_errno : ESTALE;
                result = -1;
                break;
            }
            if (remove_entries &&
                funlinkat(directory_fd, entry->d_name, entry_fd, 0) != 0) {
                saved_errno = errno;
                (void)close(entry_fd);
                errno = saved_errno;
                result = -1;
                break;
            }
            if (close(entry_fd) != 0) {
                result = -1;
                break;
            }
        } else if (S_ISLNK(before.st_mode)) {
            int entry_fd = -1;

            /* A FreeBSD 14.4 O_PATH descriptor is accepted by funlinkat(2)
             * for a symlink even though the same descriptor kind is rejected
             * for a directory. O_NOFOLLOW pins the link itself, never its
             * external target. */
            do {
                entry_fd = openat(directory_fd, entry->d_name,
                                  O_PATH | O_NOFOLLOW | O_CLOEXEC);
            } while (entry_fd < 0 && errno == EINTR);
            if (entry_fd < 0 || fstat(entry_fd, &pinned) != 0 ||
                pinned.st_dev != before.st_dev ||
                pinned.st_ino != before.st_ino ||
                !S_ISLNK(pinned.st_mode)) {
                saved_errno = errno;
                if (entry_fd >= 0) (void)close(entry_fd);
                errno = saved_errno != 0 ? saved_errno : ESTALE;
                result = -1;
                break;
            }
            if (remove_entries &&
                funlinkat(directory_fd, entry->d_name, entry_fd, 0) != 0) {
                saved_errno = errno;
                (void)close(entry_fd);
                errno = saved_errno;
                result = -1;
                break;
            }
            if (close(entry_fd) != 0) {
                result = -1;
                break;
            }
        } else {
            /* Preserve a tree containing unexpected special files rather
             * than opening a FIFO/device or degrading to pathname unlink.
             * The validation pass reaches this branch before any mutation. */
            errno = EOPNOTSUPP;
            result = -1;
            break;
        }
    }
    {
        int saved_errno = errno;

        if (closedir(stream) != 0 && result == 0) {
            return -1;
        }
        errno = saved_errno;
    }
    return result;
}
#endif

static int run_internal_retire_tree(const char *home_path,
                                    const char *private_name,
                                    const char *expected_device_text,
                                    const char *expected_inode_text)
{
    uintmax_t expected_device;
    uintmax_t expected_inode;
    struct stat home_stat;
    struct stat private_stat;
    int home_fd = -1;
    int private_fd = -1;
    int result = EXIT_FAILURE;
#if defined(__FreeBSD__)
    struct stat current_private_stat;
#endif

    if (!private_rpm_name_is_valid(private_name)) {
        fprintf(stderr, "ERROR: private RPM namespace name is invalid\n");
        return EXIT_FAILURE;
    }
    if (parse_decimal_identity(expected_device_text, &expected_device) != 0 ||
        parse_decimal_identity(expected_inode_text, &expected_inode) != 0) {
        fprintf(stderr, "ERROR: private RPM namespace identity is invalid\n");
        return EXIT_FAILURE;
    }
    home_fd = open_canonical_absolute_directory(home_path);
    if (home_fd < 0 || fstat(home_fd, &home_stat) != 0) {
        fprintf(stderr, "ERROR: cannot pin canonical HOME directory: %s\n",
                strerror(errno));
        goto cleanup;
    }
    do {
        private_fd = openat(home_fd, private_name,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (private_fd < 0 && errno == EINTR);
    if (private_fd < 0 || fstat(private_fd, &private_stat) != 0) {
        fprintf(stderr, "ERROR: cannot pin private RPM namespace: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (!S_ISDIR(private_stat.st_mode) ||
        (uintmax_t)private_stat.st_dev != expected_device ||
        (uintmax_t)private_stat.st_ino != expected_inode ||
        private_stat.st_uid != geteuid() ||
        (private_stat.st_mode & 07777) != 0700) {
        errno = ESTALE;
        fprintf(stderr,
                "ERROR: private RPM namespace identity or permissions changed\n");
        goto cleanup;
    }
    if (revalidate_directory_entry(home_fd, private_name, private_fd,
                                   &private_stat) != 0) {
        fprintf(stderr,
                "ERROR: private RPM namespace changed before retirement\n");
        goto cleanup;
    }
    if (revalidate_canonical_directory_path(home_path, &home_stat) != 0) {
        fprintf(stderr,
                "ERROR: canonical HOME changed before retirement: %s\n",
                strerror(errno));
        goto cleanup;
    }
#if !defined(__FreeBSD__)
    /* These systems cannot make unlink conditional on private_fd still
     * naming this directory. Return a distinct non-success status before the
     * first content mutation; the caller may report the safe retention
     * without converting an otherwise successful package build to failure. */
    if (run_cleanup_race_hook() != 0 ||
        revalidate_directory_entry(home_fd, private_name, private_fd,
                                   &private_stat) != 0 ||
        revalidate_canonical_directory_path(home_path, &home_stat) != 0) {
        fprintf(stderr,
                "ERROR: private RPM namespace changed at final retirement boundary; replacement retained\n");
        goto cleanup;
    }
    fprintf(stderr,
            "WARNING: descriptor-conditioned directory removal is unavailable; private RPM namespace safely retained: %s/%s\n",
            home_path, private_name);
    result = RETIRE_TREE_RETAINED_STATUS;
    goto cleanup;
#else
    if (visit_retirement_tree(private_fd, private_stat.st_dev, 0U, false) !=
        0) {
        if (errno == EOPNOTSUPP) {
            fprintf(stderr,
                    "WARNING: private RPM namespace safely retained: %s/%s\n",
                    home_path, private_name);
            result = RETIRE_TREE_RETAINED_STATUS;
            goto cleanup;
        }
        fprintf(stderr,
                "ERROR: cannot validate private RPM namespace contents before retirement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (visit_retirement_tree(private_fd, private_stat.st_dev, 0U, true) !=
        0) {
        fprintf(stderr,
                "ERROR: cannot retire private RPM namespace contents: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (fstat(private_fd, &current_private_stat) != 0) {
        fprintf(stderr,
                "ERROR: cannot inspect private RPM namespace during retirement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (!same_directory_identity(&private_stat, &current_private_stat) ||
        current_private_stat.st_uid != geteuid() ||
        (current_private_stat.st_mode & 07777) != 0700) {
        errno = ESTALE;
        fprintf(stderr,
                "ERROR: private RPM namespace changed during retirement\n");
        goto cleanup;
    }
    if (revalidate_directory_entry(home_fd, private_name, private_fd,
                                   &private_stat) != 0) {
        fprintf(stderr,
                "ERROR: private RPM namespace changed during retirement\n");
        goto cleanup;
    }
    if (revalidate_canonical_directory_path(home_path, &home_stat) != 0) {
        fprintf(stderr, "ERROR: canonical HOME changed during retirement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (run_cleanup_race_hook() != 0 ||
        funlinkat(home_fd, private_name, private_fd, AT_REMOVEDIR) != 0) {
        fprintf(stderr,
                "ERROR: private RPM namespace was not removed at final retirement boundary; current name retained: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (full_fsync(home_fd) != 0) {
        fprintf(stderr, "ERROR: cannot sync HOME after RPM retirement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    result = EXIT_SUCCESS;
#endif

cleanup:
    if (private_fd >= 0 && close(private_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (home_fd >= 0 && close(home_fd) != 0) {
        result = EXIT_FAILURE;
    }
    return result;
}

#if defined(GITSWITCH_RELEASE_TEST_DURABILITY)
static int durability_report_fd = -1;
static char durability_fail_stage;

static int configure_durability_test(void)
{
    const char *report_text =
        getenv("GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD"); /* Flawfinder: ignore -- named-fixture-only descriptor number, compiled out of production */
    const char *fail_text =
        getenv("GITSWITCH_RELEASE_TEST_SYNC_FAIL_STAGE"); /* Flawfinder: ignore -- named-fixture-only one-byte fault selector, compiled out of production */

    if (report_text != NULL) {
        char *end = NULL;
        long value;
        int flags;

        errno = 0;
        value = strtol(report_text, &end, 10);
        if (errno != 0 || end == report_text || *end != '\0' ||
            value < 3L || value > (long)INT_MAX) {
            errno = EINVAL;
            return -1;
        }
        flags = fcntl((int)value, F_GETFD);
        if (flags < 0 || fcntl((int)value, F_SETFD, flags | FD_CLOEXEC) != 0) {
            return -1;
        }
        durability_report_fd = (int)value;
    }
    if (fail_text != NULL) {
        if (fail_text[0] == '\0' || fail_text[1] != '\0' ||
            strchr("FADBR", fail_text[0]) == NULL) {
            errno = EINVAL;
            return -1;
        }
        durability_fail_stage = fail_text[0];
    }
    return 0;
}

static int write_durability_report(const char *buffer, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count;

        do {
            count = write(durability_report_fd, buffer + offset,
                          length - offset);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) {
            if (count == 0) {
                errno = EIO;
            }
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}
#endif

static int durability_sync(int fd, char stage)
{
#if defined(GITSWITCH_RELEASE_TEST_DURABILITY)
    if (durability_report_fd >= 0) {
        struct stat identity;
        char report[128];
        int length;

        if (fstat(fd, &identity) != 0) {
            return -1;
        }
        length = snprintf(report, sizeof(report), "%c %" PRIuMAX ":%" PRIuMAX
                          "\n", stage, (uintmax_t)identity.st_dev,
                          (uintmax_t)identity.st_ino);
        if (length < 0 || (size_t)length >= sizeof(report)) {
            errno = EOVERFLOW;
            return -1;
        }
        if (write_durability_report(report, (size_t)length) != 0) {
            return -1;
        }
    }
    if (durability_fail_stage == stage) {
        errno = EIO;
        return -1;
    }
#else
    (void)stage;
#endif
    return full_fsync(fd);
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

static int digest_regular_descriptor(
    int fd, off_t expected_size, mode_t expected_permissions,
    unsigned char digest[SHA256_DIGEST_SIZE])
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
        (expected_permissions != (mode_t)-1 &&
         (before.st_mode & 07777) != expected_permissions)) {
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
        (expected_permissions != (mode_t)-1 &&
         (after.st_mode & 07777) != expected_permissions)) {
        errno = ESTALE;
        return -1;
    }
    return sha256_final(&context, digest);
}

static int digest_read_only_regular_descriptor(
    int fd, off_t expected_size, unsigned char digest[SHA256_DIGEST_SIZE])
{
    return digest_regular_descriptor(
        fd, expected_size, S_IRUSR | S_IRGRP | S_IROTH, digest);
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
    defined(GITSWITCH_RELEASE_TEST_DURABILITY) || \
    defined(GITSWITCH_RELEASE_TEST_RPM_STAGE_RACE) || \
    defined(GITSWITCH_RELEASE_TEST_RELEASE_SOURCE_RACE) || \
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

static int run_final_tree_race_hook(void)
{
#if defined(GITSWITCH_RELEASE_TEST_DURABILITY)
    static bool hook_used;

    return run_test_race_hook("GITSWITCH_RELEASE_TEST_FINAL_TREE_MARKER",
                              "GITSWITCH_RELEASE_TEST_FINAL_TREE_RELEASE",
                              &hook_used);
#else
    return 0;
#endif
}

static int run_rpm_stage_race_hook(const char *name)
{
#if defined(GITSWITCH_RELEASE_TEST_RPM_STAGE_RACE)
    const char *target =
        getenv("GITSWITCH_RELEASE_TEST_RPM_STAGE_TARGET"); /* Flawfinder: ignore -- named-fixture-only leaf selector */
    static bool hook_used;

    if (target != NULL && strcmp(target, name) != 0) {
        return 0;
    }
    return run_test_race_hook("GITSWITCH_RELEASE_TEST_RPM_STAGE_MARKER",
                              "GITSWITCH_RELEASE_TEST_RPM_STAGE_RELEASE",
                              &hook_used);
#else
    (void)name;
    return 0;
#endif
}

static int run_release_source_race_hook(void)
{
#if defined(GITSWITCH_RELEASE_TEST_RELEASE_SOURCE_RACE)
    static bool hook_used;

    return run_test_race_hook(
        "GITSWITCH_RELEASE_TEST_RELEASE_SOURCE_MARKER",
        "GITSWITCH_RELEASE_TEST_RELEASE_SOURCE_RELEASE", &hook_used);
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

/* AR-11 M40: release archive bytes must not cross a mutable pathname between
 * generation and validation. The publisher's internal archive mode therefore
 * uses anonymous pipes for both independent Git/gzip streams and every
 * validator. Only byte-equal spans reach the publisher's still-private output
 * descriptor; the outer publisher cannot create the canonical name until this
 * mode has reaped every child and returned success. */
#define ARCHIVE_STREAM_BUFFER_SIZE (64U * 1024U)
#define ARCHIVE_MANIFEST_MISMATCH_EXIT 42
#define ARCHIVE_MANIFEST_ERROR_EXIT 43
#define ARCHIVE_INTERNAL_TOKEN "--internal-release-archive-v1"

typedef struct archive_byte_buffer {
    unsigned char *bytes;
    size_t size;
    size_t capacity;
} archive_byte_buffer_t;

typedef struct archive_string_list {
    char **items;
    size_t count;
    size_t capacity;
} archive_string_list_t;

typedef struct archive_workspace {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char xdg[PATH_MAX];
    char git[PATH_MAX];
    char git_objects[PATH_MAX];
    char source_objects[PATH_MAX];
    bool active;
    bool home_created;
    bool xdg_created;
    bool git_created;
    bool git_objects_created;
    bool refs_created;
    bool head_created;
    bool config_created;
} archive_workspace_t;

typedef enum archive_object_format {
    ARCHIVE_OBJECT_FORMAT_SHA1 = 0,
    ARCHIVE_OBJECT_FORMAT_SHA256
} archive_object_format_t;

typedef struct archive_child {
    pid_t pid;
    const char *label;
    bool manifest_validator;
} archive_child_t;

static int archive_buffer_append(archive_byte_buffer_t *buffer,
                                 const unsigned char *bytes, size_t size)
{
    size_t required;

    if (size > SIZE_MAX - buffer->size - 1U) {
        errno = EOVERFLOW;
        return -1;
    }
    required = buffer->size + size + 1U;
    if (required > buffer->capacity) {
        size_t capacity = buffer->capacity == 0U ? 4096U : buffer->capacity;
        unsigned char *replacement;

        while (capacity < required) {
            if (capacity > SIZE_MAX / 2U) {
                capacity = required;
                break;
            }
            capacity *= 2U;
        }
        replacement = realloc(buffer->bytes, capacity);
        if (replacement == NULL) {
            return -1;
        }
        buffer->bytes = replacement;
        buffer->capacity = capacity;
    }
    if (size != 0U) {
        memcpy(buffer->bytes + buffer->size, bytes, size);
    }
    buffer->size += size;
    buffer->bytes[buffer->size] = '\0';
    return 0;
}

static void archive_buffer_free(archive_byte_buffer_t *buffer)
{
    free(buffer->bytes);
    memset(buffer, 0, sizeof(*buffer));
}

static int archive_list_add(archive_string_list_t *list, const char *value,
                            size_t length)
{
    char *copy;

    if (length == SIZE_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    if (list->count == list->capacity) {
        size_t capacity = list->capacity == 0U ? 64U : list->capacity * 2U;
        char **replacement;

        if (capacity < list->capacity ||
            capacity > SIZE_MAX / sizeof(*replacement)) {
            errno = EOVERFLOW;
            return -1;
        }
        replacement = realloc(list->items,
                              capacity * sizeof(*replacement));
        if (replacement == NULL) {
            return -1;
        }
        list->items = replacement;
        list->capacity = capacity;
    }
    copy = malloc(length + 1U);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, value, length);
    copy[length] = '\0';
    list->items[list->count++] = copy;
    return 0;
}

static void archive_list_free(archive_string_list_t *list)
{
    size_t index;

    for (index = 0U; index < list->count; index++) {
        free(list->items[index]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int archive_string_compare(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;

    return strcmp(*left_string, *right_string);
}

static void archive_list_sort(archive_string_list_t *list)
{
    qsort(list->items, list->count, sizeof(*list->items),
          archive_string_compare);
}

static void archive_list_deduplicate(archive_string_list_t *list)
{
    size_t read_index;
    size_t write_index = 0U;

    for (read_index = 0U; read_index < list->count; read_index++) {
        if (write_index != 0U &&
            strcmp(list->items[write_index - 1U],
                   list->items[read_index]) == 0) {
            free(list->items[read_index]);
            continue;
        }
        list->items[write_index++] = list->items[read_index];
    }
    list->count = write_index;
}

static bool archive_path_byte_is_portable(unsigned char byte)
{
    return byte != '\0' &&
           ((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
           (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
           (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
           strchr("._/+@%:=,-", (int)byte) != NULL);
}

static bool archive_tree_path_is_portable(const unsigned char *path,
                                          size_t length)
{
    size_t component_start = 0U;
    size_t index;

    if (length == 0U || path[0] == (unsigned char)'/' ||
        path[length - 1U] == (unsigned char)'/') {
        return false;
    }
    for (index = 0U; index <= length; index++) {
        if (index < length && !archive_path_byte_is_portable(path[index])) {
            return false;
        }
        if (index == length || path[index] == (unsigned char)'/') {
            size_t component_length = index - component_start;

            if (component_length == 0U ||
                (component_length == 1U && path[component_start] == '.') ||
                (component_length == 2U && path[component_start] == '.' &&
                 path[component_start + 1U] == '.')) {
                return false;
            }
            component_start = index + 1U;
        }
    }
    return true;
}

static int archive_add_prefixed_path(archive_string_list_t *list,
                                     const char *root,
                                     const unsigned char *path,
                                     size_t path_length)
{
    size_t root_length = strlen(root);
    size_t total;
    char *combined;
    int result;

    if (root_length > SIZE_MAX - path_length - 2U) {
        errno = EOVERFLOW;
        return -1;
    }
    total = root_length + 1U + path_length;
    combined = malloc(total + 1U);
    if (combined == NULL) {
        return -1;
    }
    memcpy(combined, root, root_length);
    combined[root_length] = '/';
    memcpy(combined + root_length + 1U, path, path_length);
    combined[total] = '\0';
    result = archive_list_add(list, combined, total);
    free(combined);
    return result;
}

static int archive_build_expected_members(
    const archive_byte_buffer_t *tree_paths, const char *dist_root,
    archive_string_list_t *expected)
{
    size_t offset = 0U;
    size_t root_length = strlen(dist_root);
    char *root_entry;

    if (tree_paths->size == 0U ||
        tree_paths->bytes[tree_paths->size - 1U] != '\0') {
        errno = EINVAL;
        return -1;
    }
    root_entry = malloc(root_length + 2U);
    if (root_entry == NULL) {
        return -1;
    }
    memcpy(root_entry, dist_root, root_length);
    root_entry[root_length] = '/';
    root_entry[root_length + 1U] = '\0';
    if (archive_list_add(expected, root_entry, root_length + 1U) != 0) {
        free(root_entry);
        return -1;
    }
    free(root_entry);

    while (offset < tree_paths->size) {
        size_t end = offset;
        size_t index;

        while (end < tree_paths->size && tree_paths->bytes[end] != '\0') {
            end++;
        }
        if (end == tree_paths->size ||
            !archive_tree_path_is_portable(tree_paths->bytes + offset,
                                           end - offset)) {
            errno = EINVAL;
            return -1;
        }
        for (index = offset; index < end; index++) {
            if (tree_paths->bytes[index] == (unsigned char)'/' &&
                archive_add_prefixed_path(expected, dist_root,
                    tree_paths->bytes + offset, index - offset + 1U) != 0) {
                return -1;
            }
        }
        if (archive_add_prefixed_path(expected, dist_root,
                                      tree_paths->bytes + offset,
                                      end - offset) != 0) {
            return -1;
        }
        offset = end + 1U;
    }
    archive_list_sort(expected);
    archive_list_deduplicate(expected);
    return 0;
}

static int archive_compare_member_listing(
    const archive_string_list_t *expected)
{
    archive_byte_buffer_t listing = {0};
    archive_string_list_t actual = {0};
    unsigned char buffer[8192];
    size_t offset = 0U;
    ssize_t count;
    int result = ARCHIVE_MANIFEST_ERROR_EXIT;

    do {
        count = read(STDIN_FILENO, buffer, sizeof(buffer));
    } while (count < 0 && errno == EINTR);
    while (count > 0) {
        if (archive_buffer_append(&listing, buffer, (size_t)count) != 0) {
            goto cleanup;
        }
        do {
            count = read(STDIN_FILENO, buffer, sizeof(buffer));
        } while (count < 0 && errno == EINTR);
    }
    if (count < 0 || listing.size == 0U ||
        listing.bytes[listing.size - 1U] != (unsigned char)'\n') {
        goto cleanup;
    }
    while (offset < listing.size) {
        size_t end = offset;
        size_t index;

        while (end < listing.size && listing.bytes[end] != '\n') {
            end++;
        }
        if (end == offset || end == listing.size) {
            goto cleanup;
        }
        for (index = offset; index < end; index++) {
            if (!archive_path_byte_is_portable(listing.bytes[index])) {
                goto cleanup;
            }
        }
        if (archive_list_add(&actual, (const char *)listing.bytes + offset,
                             end - offset) != 0) {
            goto cleanup;
        }
        offset = end + 1U;
    }
    archive_list_sort(&actual);
    if (actual.count != expected->count) {
        result = ARCHIVE_MANIFEST_MISMATCH_EXIT;
        goto cleanup;
    }
    for (offset = 0U; offset < actual.count; offset++) {
        if (strcmp(actual.items[offset], expected->items[offset]) != 0) {
            result = ARCHIVE_MANIFEST_MISMATCH_EXIT;
            goto cleanup;
        }
    }
    result = EXIT_SUCCESS;

cleanup:
    archive_list_free(&actual);
    archive_buffer_free(&listing);
    return result;
}

static int archive_join_path(char destination[PATH_MAX], const char *left,
                             const char *right)
{
    int length = snprintf(destination, PATH_MAX, "%s/%s", left, right);

    if (length < 0 || length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int archive_workspace_create(archive_workspace_t *workspace,
                                    const char *tmp_parent)
{
    char template_path[PATH_MAX];
    int head_fd = -1;
    int length;
    static const unsigned char head_contents[] =
        "ref: refs/heads/unused\n";

    length = snprintf(template_path, sizeof(template_path),
                      "%s/gitswitch-release-archive.XXXXXX", tmp_parent);
    if (length < 0 || (size_t)length >= sizeof(template_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdtemp(template_path) == NULL) {
        return -1;
    }
    length = snprintf(workspace->root, sizeof(workspace->root), "%s",
                      template_path);
    if (length < 0 || (size_t)length >= sizeof(workspace->root)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    workspace->active = true;
    /* mkdtemp(3) creates the private workspace with mode 0700.  Do not
     * re-address that freshly created directory by pathname just to restate
     * the same mode: doing so would add a needless pathname race. */
    if (archive_join_path(workspace->home, workspace->root, "home") != 0 ||
        archive_join_path(workspace->xdg, workspace->root, "xdg") != 0 ||
        archive_join_path(workspace->git, workspace->root, "git") != 0 ||
        archive_join_path(workspace->git_objects, workspace->git, "objects") !=
            0) {
        return -1;
    }
    if (mkdir(workspace->home, S_IRWXU) != 0) {
        return -1;
    }
    workspace->home_created = true;
    if (mkdir(workspace->xdg, S_IRWXU) != 0) {
        return -1;
    }
    workspace->xdg_created = true;
    if (mkdir(workspace->git, S_IRWXU) != 0) {
        return -1;
    }
    workspace->git_created = true;
    if (mkdir(workspace->git_objects, S_IRWXU) != 0) {
        return -1;
    }
    workspace->git_objects_created = true;
    {
        char refs[PATH_MAX];
        char head[PATH_MAX];

        if (archive_join_path(refs, workspace->git, "refs") != 0 ||
            mkdir(refs, S_IRWXU) != 0) {
            return -1;
        }
        workspace->refs_created = true;
        if (archive_join_path(head, workspace->git, "HEAD") != 0) {
            return -1;
        }
        head_fd = open(head, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                            O_CLOEXEC,
                       S_IRUSR | S_IWUSR);
        if (head_fd < 0) {
            return -1;
        }
        workspace->head_created = true;
        if (write_all(head_fd, head_contents,
                      sizeof(head_contents) - 1U) != 0) {
            int saved_errno = errno;

            (void)close(head_fd);
            errno = saved_errno;
            return -1;
        }
        /* AR-12 L26: close() deallocates the descriptor even on failure —
         * never close the same number twice. */
        if (close(head_fd) != 0) {
            return -1;
        }
    }
    return 0;
}

static int archive_workspace_cleanup(archive_workspace_t *workspace)
{
    char path[PATH_MAX];
    int first_errno = 0;

    if (!workspace->active) {
        return 0;
    }
#define ARCHIVE_CLEANUP_OPERATION(operation) \
    do { \
        if ((operation) != 0 && errno != ENOENT && first_errno == 0) { \
            first_errno = errno; \
        } \
    } while (0)
    if (workspace->config_created && workspace->git[0] != '\0') {
        if (archive_join_path(path, workspace->git, "config") == 0) {
            ARCHIVE_CLEANUP_OPERATION(unlink(path));
        } else if (first_errno == 0) {
            first_errno = errno;
        }
    }
    if (workspace->head_created && workspace->git[0] != '\0') {
        if (archive_join_path(path, workspace->git, "HEAD") == 0) {
            ARCHIVE_CLEANUP_OPERATION(unlink(path));
        } else if (first_errno == 0) {
            first_errno = errno;
        }
    }
    if (workspace->refs_created && workspace->git[0] != '\0') {
        if (archive_join_path(path, workspace->git, "refs") == 0) {
            ARCHIVE_CLEANUP_OPERATION(rmdir(path));
        } else if (first_errno == 0) {
            first_errno = errno;
        }
    }
    if (workspace->git_objects_created && workspace->git_objects[0] != '\0') {
        ARCHIVE_CLEANUP_OPERATION(rmdir(workspace->git_objects));
    }
    if (workspace->git_created && workspace->git[0] != '\0') {
        ARCHIVE_CLEANUP_OPERATION(rmdir(workspace->git));
    }
    if (workspace->home_created && workspace->home[0] != '\0') {
        ARCHIVE_CLEANUP_OPERATION(rmdir(workspace->home));
    }
    if (workspace->xdg_created && workspace->xdg[0] != '\0') {
        ARCHIVE_CLEANUP_OPERATION(rmdir(workspace->xdg));
    }
    if (workspace->root[0] != '\0') {
        ARCHIVE_CLEANUP_OPERATION(rmdir(workspace->root));
    }
#undef ARCHIVE_CLEANUP_OPERATION
    workspace->active = false;
    if (first_errno != 0) {
        errno = first_errno;
        return -1;
    }
    return 0;
}

static void report_deferred_fatal_cleanup(void);
static int finish_deferred_fatal_signal(void);
static int run_internal_archive_signal_test_hook(
    const archive_workspace_t *workspace);
static void report_internal_archive_signal_cleanup(
    const archive_workspace_t *workspace, int cleanup_result);

static int archive_write_minimal_git_config(
    const archive_workspace_t *workspace, archive_object_format_t format)
{
    static const unsigned char sha1_config[] =
        "[core]\n"
        "\trepositoryFormatVersion = 0\n";
    static const unsigned char sha256_config[] =
        "[core]\n"
        "\trepositoryFormatVersion = 1\n"
        "[extensions]\n"
        "\tobjectFormat = sha256\n";
    const unsigned char *contents;
    size_t contents_size;
    char temporary[PATH_MAX];
    char destination[PATH_MAX];
    int config_fd = -1;
    int saved_errno;
    int result = -1;

    if (format == ARCHIVE_OBJECT_FORMAT_SHA1) {
        contents = sha1_config;
        contents_size = sizeof(sha1_config) - 1U;
    } else if (format == ARCHIVE_OBJECT_FORMAT_SHA256) {
        contents = sha256_config;
        contents_size = sizeof(sha256_config) - 1U;
    } else {
        errno = EINVAL;
        return -1;
    }
    if (archive_join_path(temporary, workspace->git, "config.tmp") != 0 ||
        archive_join_path(destination, workspace->git, "config") != 0) {
        return -1;
    }
    config_fd = open(temporary,
                     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     S_IRUSR | S_IWUSR);
    if (config_fd < 0) {
        return -1;
    }
    if (write_all(config_fd, contents, contents_size) != 0) {
        goto cleanup;
    }
    if (close(config_fd) != 0) {
        config_fd = -1;
        goto cleanup;
    }
    config_fd = -1;
    if (rename(temporary, destination) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    saved_errno = errno;
    if (config_fd >= 0) {
        (void)close(config_fd);
    }
    if (result != 0) {
        (void)unlink(temporary);
    }
    errno = saved_errno;
    return result;
}

/* Rebuild the producer environment through libc's supported mutation API.
 * Assigning NULL to environ happens to be accepted by glibc's setenv(), but
 * Darwin's setenv() immediately iterates *_NSGetEnviron() and dereferences the
 * null vector.  Remove each inherited name instead, with the entry count as a
 * progress bound, so malformed input fails closed rather than looping. */
static int archive_clear_environment(void)
{
    char **environment = archive_process_environ;
    size_t remaining = 0U;

    if (environment == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        if (remaining > (size_t)PTRDIFF_MAX / sizeof(*environment)) {
            errno = EOVERFLOW;
            return -1;
        }
        if (environment[remaining] == NULL) {
            break;
        }
        remaining++;
    }
    while ((environment = archive_process_environ) != NULL &&
           environment[0] != NULL) {
        const char *entry = environment[0];
        const char *separator = strchr(entry, '=');
        char *name;
        size_t name_length;
        int saved_errno;

        if (remaining == 0U) {
            errno = EIO;
            return -1;
        }
        if (separator == NULL || separator == entry) {
            errno = EINVAL;
            return -1;
        }
        name_length = (size_t)(separator - entry);
        name = malloc(name_length + 1U);
        if (name == NULL) {
            return -1;
        }
        memcpy(name, entry, name_length);
        name[name_length] = '\0';
        if (unsetenv(name) != 0) {
            saved_errno = errno;
            free(name);
            errno = saved_errno;
            return -1;
        }
        free(name);
        remaining--;
    }
    if (archive_process_environ == NULL) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int archive_set_clean_environment(const char *path,
                                         const archive_workspace_t *workspace)
{
    if (archive_clear_environment() != 0 ||
        setenv("PATH", path, 1) != 0 || setenv("LC_ALL", "C", 1) != 0 ||
        setenv("TZ", "UTC", 1) != 0 ||
        setenv("HOME", workspace->home, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", workspace->xdg, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        setenv("GIT_CONFIG_SYSTEM", "/dev/null", 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1) != 0 ||
        setenv("GIT_ATTR_NOSYSTEM", "1", 1) != 0 ||
        setenv("GIT_NO_REPLACE_OBJECTS", "1", 1) != 0 ||
        setenv("GIT_LITERAL_PATHSPECS", "1", 1) != 0 ||
        setenv("GIT_OPTIONAL_LOCKS", "0", 1) != 0) {
        return -1;
    }
    return 0;
}

static int archive_reset_exec_signal_state(void)
{
    static const int reset_signals[] = {
        SIGPIPE, SIGCHLD, SIGINT, SIGTERM, SIGHUP, SIGQUIT
    };
    struct sigaction default_action;
    sigset_t empty_mask;
    size_t index;

    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    if (sigemptyset(&default_action.sa_mask) != 0 ||
        sigemptyset(&empty_mask) != 0) {
        return -1;
    }
    for (index = 0U;
         index < sizeof(reset_signals) / sizeof(reset_signals[0]);
         index++) {
        struct sigaction current;

        if (sigaction(reset_signals[index], NULL, &current) != 0) {
            return -1;
        }
        if (reset_signals[index] != SIGPIPE &&
            current.sa_handler == SIG_IGN) {
            continue;
        }
        if (sigaction(reset_signals[index], &default_action, NULL) != 0) {
            return -1;
        }
    }
    return sigprocmask(SIG_SETMASK, &empty_mask, NULL);
}

static pid_t archive_spawn_exec(char *const arguments[], int input_fd,
                                int output_fd, const int *all_fds,
                                size_t fd_count)
{
    pid_t child = fork();

    if (child != 0) {
        return child;
    }
    if ((input_fd >= 0 && input_fd != STDIN_FILENO &&
         dup2(input_fd, STDIN_FILENO) < 0) ||
        (output_fd >= 0 && output_fd != STDOUT_FILENO &&
         dup2(output_fd, STDOUT_FILENO) < 0)) {
        _exit(126);
    }
    {
        size_t index;

        for (index = 0U; index < fd_count; index++) {
            if (all_fds[index] > STDERR_FILENO) {
                (void)close(all_fds[index]);
            }
        }
    }
    if (archive_reset_exec_signal_state() != 0) {
        _exit(126);
    }
    execvp(arguments[0], arguments); /* Flawfinder: ignore — fixed release-tool argv under a scrubbed environment; PATH is the caller's explicit toolchain selector */
    _exit(errno == ENOENT ? 127 : 126);
}

static void archive_report_child_status(const char *label, int status)
{
    if (WIFEXITED(status)) {
        fprintf(stderr, "release-archive: ERROR: %s exited with status %d\n",
                label, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr,
                "release-archive: ERROR: %s terminated by signal %d\n",
                label, WTERMSIG(status));
    } else {
        fprintf(stderr,
                "release-archive: ERROR: %s did not exit normally\n",
                label);
    }
}

static int archive_wait_exact_child(pid_t child, const char *label)
{
    int status;
    pid_t waited;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        fprintf(stderr, "release-archive: ERROR: cannot wait for %s: %s\n",
                label, strerror(errno));
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        archive_report_child_status(label, status);
        errno = EIO;
        return -1;
    }
    return 0;
}

static int archive_capture_command(char *const arguments[], const char *label,
                                   archive_byte_buffer_t *output)
{
    int pipe_fds[2];
    int all_fds[2];
    unsigned char buffer[8192];
    pid_t child;
    ssize_t count;
    int result = -1;
    int saved_errno = 0;

    if (create_producer_pipe(pipe_fds) != 0) {
        return -1;
    }
    all_fds[0] = pipe_fds[0];
    all_fds[1] = pipe_fds[1];
    child = archive_spawn_exec(arguments, -1, pipe_fds[1], all_fds, 2U);
    if (child < 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    (void)close(pipe_fds[1]);
    do {
        count = read(pipe_fds[0], buffer, sizeof(buffer));
    } while (count < 0 && errno == EINTR);
    while (count > 0) {
        if (archive_buffer_append(output, buffer, (size_t)count) != 0) {
            saved_errno = errno;
            (void)kill(child, SIGKILL);
            (void)close(pipe_fds[0]);
            (void)archive_wait_exact_child(child, label);
            errno = saved_errno;
            return -1;
        }
        do {
            count = read(pipe_fds[0], buffer, sizeof(buffer));
        } while (count < 0 && errno == EINTR);
    }
    saved_errno = errno;
    if (close(pipe_fds[0]) != 0 && count >= 0) {
        count = -1;
        saved_errno = errno;
    }
    if (count < 0) {
        (void)kill(child, SIGKILL);
    }
    if (archive_wait_exact_child(child, label) == 0 && count >= 0) {
        result = 0;
    }
    if (result != 0 && saved_errno != 0) {
        errno = saved_errno;
    }
    return result;
}

static pid_t archive_spawn_manifest_validator(
    int input_fd, const int *all_fds, size_t fd_count,
    const archive_string_list_t *expected)
{
    pid_t child = fork();

    if (child != 0) {
        return child;
    }
    if (input_fd != STDIN_FILENO && dup2(input_fd, STDIN_FILENO) < 0) {
        _exit(ARCHIVE_MANIFEST_ERROR_EXIT);
    }
    {
        size_t index;

        for (index = 0U; index < fd_count; index++) {
            if (all_fds[index] > STDERR_FILENO) {
                (void)close(all_fds[index]);
            }
        }
    }
    if (archive_reset_exec_signal_state() != 0) {
        _exit(ARCHIVE_MANIFEST_ERROR_EXIT);
    }
    _exit(archive_compare_member_listing(expected));
}

static void archive_terminate_children(archive_child_t *children,
                                       size_t child_count)
{
    size_t index;

    for (index = 0U; index < child_count; index++) {
        if (children[index].pid > 0) {
            (void)kill(children[index].pid, SIGKILL);
        }
    }
}

static int archive_wait_children(archive_child_t *children,
                                 size_t child_count)
{
    size_t index;
    int failed = 0;

    for (index = 0U; index < child_count; index++) {
        int status;
        pid_t waited;

        if (children[index].pid <= 0) {
            continue;
        }
        do {
            waited = waitpid(children[index].pid, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != children[index].pid) {
            fprintf(stderr,
                    "release-archive: ERROR: cannot wait for %s: %s\n",
                    children[index].label, strerror(errno));
            failed = 1;
            continue;
        }
        children[index].pid = -1;
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            continue;
        }
        if (children[index].manifest_validator && WIFEXITED(status) &&
            WEXITSTATUS(status) == ARCHIVE_MANIFEST_MISMATCH_EXIT) {
            fprintf(stderr,
                    "release-archive: ERROR: completed archive differs from the exact committed release manifest\n");
        } else {
            archive_report_child_status(children[index].label, status);
        }
        failed = 1;
    }
    return failed == 0 ? 0 : -1;
}

static int archive_stream_equal_bytes(int first_fd, int second_fd,
                                      int integrity_fd, int decoder_fd,
                                      bool *repeat_mismatch)
{
    unsigned char first_buffer[ARCHIVE_STREAM_BUFFER_SIZE];
    unsigned char second_buffer[ARCHIVE_STREAM_BUFFER_SIZE];
    size_t first_offset = 0U;
    size_t first_size = 0U;
    size_t second_offset = 0U;
    size_t second_size = 0U;
    bool first_eof = false;
    bool second_eof = false;

    *repeat_mismatch = false;
    for (;;) {
        if (first_offset == first_size && !first_eof) {
            ssize_t count;

            do {
                count = read(first_fd, first_buffer, sizeof(first_buffer));
            } while (count < 0 && errno == EINTR);
            if (count < 0) {
                return -1;
            }
            first_offset = 0U;
            first_size = (size_t)count;
            first_eof = count == 0;
        }
        if (second_offset == second_size && !second_eof) {
            ssize_t count;

            do {
                count = read(second_fd, second_buffer,
                             sizeof(second_buffer));
            } while (count < 0 && errno == EINTR);
            if (count < 0) {
                return -1;
            }
            second_offset = 0U;
            second_size = (size_t)count;
            second_eof = count == 0;
        }
        if (first_offset == first_size && second_offset == second_size &&
            first_eof && second_eof) {
            return 0;
        }
        if ((first_eof && first_offset == first_size) !=
            (second_eof && second_offset == second_size)) {
            *repeat_mismatch = true;
            errno = EIO;
            return -1;
        }
        if (first_offset < first_size && second_offset < second_size) {
            size_t first_remaining = first_size - first_offset;
            size_t second_remaining = second_size - second_offset;
            size_t matched = first_remaining < second_remaining ?
                                 first_remaining : second_remaining;

            if (memcmp(first_buffer + first_offset,
                       second_buffer + second_offset, matched) != 0) {
                *repeat_mismatch = true;
                errno = EIO;
                return -1;
            }
            if (write_all(STDOUT_FILENO, first_buffer + first_offset,
                          matched) != 0 ||
                write_all(integrity_fd, first_buffer + first_offset,
                          matched) != 0 ||
                write_all(decoder_fd, first_buffer + first_offset,
                          matched) != 0) {
                return -1;
            }
            first_offset += matched;
            second_offset += matched;
        }
    }
}

enum archive_pipe_index {
    ARCHIVE_PIPE_RAW_A = 0,
    ARCHIVE_PIPE_RAW_B,
    ARCHIVE_PIPE_GZIP_A,
    ARCHIVE_PIPE_GZIP_B,
    ARCHIVE_PIPE_INTEGRITY,
    ARCHIVE_PIPE_DECODER,
    ARCHIVE_PIPE_TAR,
    ARCHIVE_PIPE_LISTING,
    ARCHIVE_PIPE_COUNT
};

static void archive_close_graph_pipes(int pipes[ARCHIVE_PIPE_COUNT][2])
{
    size_t pipe_index;

    for (pipe_index = 0U; pipe_index < ARCHIVE_PIPE_COUNT; pipe_index++) {
        size_t endpoint;

        for (endpoint = 0U; endpoint < 2U; endpoint++) {
            if (pipes[pipe_index][endpoint] >= 0) {
                (void)close(pipes[pipe_index][endpoint]);
                pipes[pipe_index][endpoint] = -1;
            }
        }
    }
}

static int archive_create_graph_pipes(int pipes[ARCHIVE_PIPE_COUNT][2],
                                      int all_fds[ARCHIVE_PIPE_COUNT * 2U])
{
    size_t pipe_index;

    for (pipe_index = 0U; pipe_index < ARCHIVE_PIPE_COUNT; pipe_index++) {
        pipes[pipe_index][0] = -1;
        pipes[pipe_index][1] = -1;
    }
    for (pipe_index = 0U; pipe_index < ARCHIVE_PIPE_COUNT; pipe_index++) {
        if (create_producer_pipe(pipes[pipe_index]) != 0) {
            archive_close_graph_pipes(pipes);
            return -1;
        }
        all_fds[pipe_index * 2U] = pipes[pipe_index][0];
        all_fds[(pipe_index * 2U) + 1U] = pipes[pipe_index][1];
    }
    return 0;
}

static bool archive_component_is_safe(const char *component)
{
    size_t index;
    size_t length = strlen(component);

    if (length == 0U || strcmp(component, ".") == 0 ||
        strcmp(component, "..") == 0) {
        return false;
    }
    for (index = 0U; index < length; index++) {
        if (component[index] == '/' ||
            !archive_path_byte_is_portable((unsigned char)component[index])) {
            return false;
        }
    }
    return true;
}

static bool archive_commit_is_hexadecimal(const char *commit)
{
    size_t index;
    size_t length = strlen(commit);

    if (length != 40U && length != 64U) {
        return false;
    }
    for (index = 0U; index < length; index++) {
        char byte = commit[index];

        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'A' && byte <= 'F') ||
              (byte >= 'a' && byte <= 'f'))) {
            return false;
        }
    }
    return true;
}

static int archive_resolve_object_database(const char *project_root,
                                           archive_workspace_t *workspace)
{
    archive_byte_buffer_t common_output = {0};
    archive_byte_buffer_t format_output = {0};
    char common_candidate[PATH_MAX];
    char common_resolved[PATH_MAX];
    char objects_candidate[PATH_MAX];
    char *rev_parse_arguments[] = {
        "git", "-C", (char *)project_root, "rev-parse",
        "--git-common-dir", NULL
    };
    char *format_arguments[] = {
        "git", "-C", (char *)project_root, "rev-parse",
        "--show-object-format=storage", NULL
    };
    archive_object_format_t object_format;
    size_t length;
    struct stat object_stat;
    int result = -1;

    if (archive_capture_command(format_arguments,
                                "project Git object format query",
                                &format_output) != 0 ||
        format_output.size == 0U) {
        goto cleanup;
    }
    length = format_output.size;
    if (format_output.bytes[length - 1U] == (unsigned char)'\n') {
        length--;
    }
    if (length != 0U &&
        format_output.bytes[length - 1U] == (unsigned char)'\r') {
        length--;
    }
    if (length == 4U && memcmp(format_output.bytes, "sha1", 4U) == 0) {
        object_format = ARCHIVE_OBJECT_FORMAT_SHA1;
    } else if (length == 6U &&
               memcmp(format_output.bytes, "sha256", 6U) == 0) {
        object_format = ARCHIVE_OBJECT_FORMAT_SHA256;
    } else {
        errno = EINVAL;
        goto cleanup;
    }
    if (archive_capture_command(rev_parse_arguments,
                                "project Git metadata query",
                                &common_output) != 0 ||
        common_output.size == 0U) {
        goto cleanup;
    }
    length = common_output.size;
    if (common_output.bytes[length - 1U] == (unsigned char)'\n') {
        length--;
    }
    if (length != 0U &&
        common_output.bytes[length - 1U] == (unsigned char)'\r') {
        length--;
    }
    if (length == 0U || length >= PATH_MAX ||
        memchr(common_output.bytes, '\0', length) != NULL ||
        memchr(common_output.bytes, '\n', length) != NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    memcpy(common_candidate, common_output.bytes, length);
    common_candidate[length] = '\0';
    if (common_candidate[0] != '/') {
        char relative[PATH_MAX];

        memcpy(relative, common_candidate, length + 1U);
        if (archive_join_path(common_candidate, project_root, relative) != 0) {
            goto cleanup;
        }
    }
    if (realpath(common_candidate, common_resolved) == NULL ||
        archive_join_path(objects_candidate, common_resolved, "objects") !=
            0 ||
        realpath(objects_candidate, workspace->source_objects) == NULL ||
        stat(workspace->source_objects, &object_stat) != 0 ||
        !S_ISDIR(object_stat.st_mode)) {
        goto cleanup;
    }
    if (archive_write_minimal_git_config(workspace, object_format) != 0) {
        goto cleanup;
    }
    workspace->config_created = true;
    if (setenv("GIT_DIR", workspace->git, 1) != 0 ||
        setenv("GIT_OBJECT_DIRECTORY", workspace->source_objects, 1) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    archive_buffer_free(&common_output);
    archive_buffer_free(&format_output);
    return result;
}

static int archive_run_stream_graph(char *const archive_arguments[],
                                    const archive_string_list_t *expected)
{
    int pipes[ARCHIVE_PIPE_COUNT][2];
    int all_fds[ARCHIVE_PIPE_COUNT * 2U];
    archive_child_t children[8] = {
        {-1, "first sanitized Git archive", false},
        {-1, "second sanitized Git archive", false},
        {-1, "first fixed gzip compressor", false},
        {-1, "second fixed gzip compressor", false},
        {-1, "completed gzip integrity check", false},
        {-1, "completed gzip tar decoder", false},
        {-1, "completed tar member check", false},
        {-1, "completed archive member comparison", true}
    };
    char *gzip_compress_arguments[] = {"gzip", "-n", "-9", NULL};
    char *gzip_integrity_arguments[] = {"gzip", "-t", NULL};
    char *gzip_decoder_arguments[] = {"gzip", "-dc", NULL};
    char *tar_arguments[] = {"tar", "-tf", "-", NULL};
    struct sigaction ignored_pipe;
    bool repeat_mismatch = false;
    int stream_result;
    int stream_errno = 0;
    int child_result;
    size_t child_count = sizeof(children) / sizeof(children[0]);
    size_t index;

    if (archive_create_graph_pipes(pipes, all_fds) != 0) {
        return -1;
    }
    children[7].pid = archive_spawn_manifest_validator(
        pipes[ARCHIVE_PIPE_LISTING][0], all_fds,
        ARCHIVE_PIPE_COUNT * 2U, expected);
    if (children[7].pid < 0) {
        goto spawn_failure;
    }
    children[6].pid = archive_spawn_exec(
        tar_arguments, pipes[ARCHIVE_PIPE_TAR][0],
        pipes[ARCHIVE_PIPE_LISTING][1], all_fds,
        ARCHIVE_PIPE_COUNT * 2U);
    if (children[6].pid < 0) {
        goto spawn_failure;
    }
    children[5].pid = archive_spawn_exec(
        gzip_decoder_arguments, pipes[ARCHIVE_PIPE_DECODER][0],
        pipes[ARCHIVE_PIPE_TAR][1], all_fds, ARCHIVE_PIPE_COUNT * 2U);
    if (children[5].pid < 0) {
        goto spawn_failure;
    }
    children[4].pid = archive_spawn_exec(
        gzip_integrity_arguments, pipes[ARCHIVE_PIPE_INTEGRITY][0],
        STDERR_FILENO, all_fds, ARCHIVE_PIPE_COUNT * 2U);
    if (children[4].pid < 0) {
        goto spawn_failure;
    }
    children[2].pid = archive_spawn_exec(
        gzip_compress_arguments, pipes[ARCHIVE_PIPE_RAW_A][0],
        pipes[ARCHIVE_PIPE_GZIP_A][1], all_fds,
        ARCHIVE_PIPE_COUNT * 2U);
    if (children[2].pid < 0) {
        goto spawn_failure;
    }
    children[3].pid = archive_spawn_exec(
        gzip_compress_arguments, pipes[ARCHIVE_PIPE_RAW_B][0],
        pipes[ARCHIVE_PIPE_GZIP_B][1], all_fds,
        ARCHIVE_PIPE_COUNT * 2U);
    if (children[3].pid < 0) {
        goto spawn_failure;
    }
    children[0].pid = archive_spawn_exec(
        archive_arguments, -1, pipes[ARCHIVE_PIPE_RAW_A][1], all_fds,
        ARCHIVE_PIPE_COUNT * 2U);
    if (children[0].pid < 0) {
        goto spawn_failure;
    }
    children[1].pid = archive_spawn_exec(
        archive_arguments, -1, pipes[ARCHIVE_PIPE_RAW_B][1], all_fds,
        ARCHIVE_PIPE_COUNT * 2U);
    if (children[1].pid < 0) {
        goto spawn_failure;
    }

    for (index = 0U; index < ARCHIVE_PIPE_COUNT; index++) {
        size_t endpoint;

        for (endpoint = 0U; endpoint < 2U; endpoint++) {
            bool keep =
                (index == ARCHIVE_PIPE_GZIP_A && endpoint == 0U) ||
                (index == ARCHIVE_PIPE_GZIP_B && endpoint == 0U) ||
                (index == ARCHIVE_PIPE_INTEGRITY && endpoint == 1U) ||
                (index == ARCHIVE_PIPE_DECODER && endpoint == 1U);

            if (!keep && pipes[index][endpoint] >= 0) {
                (void)close(pipes[index][endpoint]);
                pipes[index][endpoint] = -1;
            }
        }
    }

    memset(&ignored_pipe, 0, sizeof(ignored_pipe));
    ignored_pipe.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored_pipe.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignored_pipe, NULL) != 0) {
        stream_errno = errno;
        stream_result = -1;
    } else {
        stream_result = archive_stream_equal_bytes(
            pipes[ARCHIVE_PIPE_GZIP_A][0],
            pipes[ARCHIVE_PIPE_GZIP_B][0],
            pipes[ARCHIVE_PIPE_INTEGRITY][1],
            pipes[ARCHIVE_PIPE_DECODER][1], &repeat_mismatch);
        stream_errno = errno;
    }
    archive_close_graph_pipes(pipes);
    if (stream_result != 0) {
        if (repeat_mismatch) {
            fprintf(stderr,
                    "release-archive: ERROR: repeated archive byte check exited with status 1\n");
        } else {
            fprintf(stderr,
                    "release-archive: ERROR: cannot fan out validated archive bytes: %s\n",
                    strerror(stream_errno));
        }
        archive_terminate_children(children, child_count);
    }
    child_result = archive_wait_children(children, child_count);
    if (stream_result != 0 || child_result != 0) {
        errno = stream_result != 0 ? stream_errno : EIO;
        return -1;
    }
    return 0;

spawn_failure:
    stream_errno = errno;
    archive_close_graph_pipes(pipes);
    archive_terminate_children(children, child_count);
    (void)archive_wait_children(children, child_count);
    errno = stream_errno;
    return -1;
}

static int run_internal_release_archive(char *const arguments[])
{
    archive_workspace_t workspace;
    archive_byte_buffer_t tree_paths = {0};
    archive_string_list_t expected = {0};
    char resolved_root[PATH_MAX];
    char prefix_argument[PATH_MAX];
    char *path_copy = NULL;
    char *tmp_copy = NULL;
    char **tree_arguments = NULL;
    char **archive_arguments = NULL;
    const char *project_root;
    const char *commit;
    const char *dist_root;
    const char *path;
    const char *tmp_parent;
    size_t manifest_count = 0U;
    size_t index;
    int prefix_length;
    int result = EXIT_FAILURE;
    int cleanup_result;

    memset(&workspace, 0, sizeof(workspace));
    if (arguments[0] == NULL ||
        strcmp(arguments[0], ARCHIVE_INTERNAL_TOKEN) != 0 ||
        arguments[1] == NULL || arguments[2] == NULL ||
        arguments[3] == NULL || arguments[4] == NULL ||
        strcmp(arguments[4], "--") != 0 || arguments[5] == NULL) {
        fprintf(stderr,
                "release-archive: ERROR: invalid internal archive invocation\n");
        goto cleanup;
    }
    project_root = arguments[1];
    commit = arguments[2];
    dist_root = arguments[3];
    for (index = 5U; arguments[index] != NULL; index++) {
        const unsigned char *manifest_path =
            (const unsigned char *)arguments[index];

        if (!archive_tree_path_is_portable(manifest_path,
                                            strlen(arguments[index]))) {
            fprintf(stderr,
                    "release-archive: ERROR: release manifest operand is not portable: %s\n",
                    arguments[index]);
            goto cleanup;
        }
        manifest_count++;
    }
    if (project_root[0] != '/' ||
        realpath(project_root, resolved_root) == NULL ||
        !archive_commit_is_hexadecimal(commit) ||
        !archive_component_is_safe(dist_root)) {
        fprintf(stderr,
                "release-archive: ERROR: invalid archive root, commit, or distribution name\n");
        goto cleanup;
    }
    path = getenv("PATH"); /* Flawfinder: ignore — snapshotted explicit release toolchain path; all other inherited state is cleared below */
    tmp_parent = getenv("TMPDIR"); /* Flawfinder: ignore — validated absolute parent for a private mkdtemp workspace */
    if (path == NULL || path[0] == '\0') {
        fprintf(stderr,
                "release-archive: ERROR: PATH is required to resolve archive tools\n");
        goto cleanup;
    }
    if (tmp_parent == NULL || tmp_parent[0] == '\0') {
        tmp_parent = "/tmp";
    }
    if (tmp_parent[0] != '/') {
        fprintf(stderr,
                "release-archive: ERROR: TMPDIR must be absolute\n");
        goto cleanup;
    }
    path_copy = strdup(path);
    tmp_copy = strdup(tmp_parent);
    if (path_copy == NULL || tmp_copy == NULL) {
        fprintf(stderr,
                "release-archive: ERROR: cannot snapshot archive environment\n");
        goto cleanup;
    }
    (void)umask(S_IRWXG | S_IRWXO);
    if (archive_workspace_create(&workspace, tmp_copy) != 0) {
        fprintf(stderr,
                "release-archive: ERROR: cannot create private archive workspace: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (run_internal_archive_signal_test_hook(&workspace) != 0) {
        fprintf(stderr,
                "release-archive: ERROR: cannot complete internal signal fixture: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (archive_set_clean_environment(path_copy, &workspace) != 0 ||
        archive_resolve_object_database(resolved_root, &workspace) != 0) {
        fprintf(stderr,
                "release-archive: ERROR: cannot establish sanitized Git metadata: %s\n",
                strerror(errno));
        goto cleanup;
    }
    prefix_length = snprintf(prefix_argument, sizeof(prefix_argument),
                             "--prefix=%s/", dist_root);
    if (prefix_length < 0 ||
        (size_t)prefix_length >= sizeof(prefix_argument)) {
        fprintf(stderr,
                "release-archive: ERROR: distribution prefix is too long\n");
        goto cleanup;
    }
    if (manifest_count > (SIZE_MAX / sizeof(*tree_arguments)) - 8U) {
        fprintf(stderr,
                "release-archive: ERROR: release manifest is too large\n");
        goto cleanup;
    }
    tree_arguments = calloc(manifest_count + 7U,
                            sizeof(*tree_arguments));
    archive_arguments = calloc(manifest_count + 7U,
                               sizeof(*archive_arguments));
    if (tree_arguments == NULL || archive_arguments == NULL) {
        fprintf(stderr,
                "release-archive: ERROR: cannot allocate archive arguments\n");
        goto cleanup;
    }
    tree_arguments[0] = "git";
    tree_arguments[1] = "ls-tree";
    tree_arguments[2] = "-rz";
    tree_arguments[3] = "--name-only";
    tree_arguments[4] = (char *)commit;
    tree_arguments[5] = "--";
    archive_arguments[0] = "git";
    archive_arguments[1] = "archive";
    archive_arguments[2] = "--format=tar";
    archive_arguments[3] = prefix_argument;
    archive_arguments[4] = (char *)commit;
    archive_arguments[5] = "--";
    for (index = 0U; index < manifest_count; index++) {
        tree_arguments[index + 6U] = arguments[index + 5U];
        archive_arguments[index + 6U] = arguments[index + 5U];
    }
    if (archive_capture_command(tree_arguments,
                                "exact committed manifest query",
                                &tree_paths) != 0 ||
        archive_build_expected_members(&tree_paths, dist_root, &expected) !=
            0) {
        fprintf(stderr,
                "release-archive: ERROR: cannot derive an exact portable committed release manifest: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (archive_run_stream_graph(archive_arguments, &expected) != 0) {
        fprintf(stderr,
                "release-archive: ERROR: archive generation or validation failed\n");
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    archive_list_free(&expected);
    archive_buffer_free(&tree_paths);
    free(tree_arguments);
    free(archive_arguments);
    free(path_copy);
    free(tmp_copy);
    cleanup_result = archive_workspace_cleanup(&workspace);
    if (cleanup_result != 0) {
        fprintf(stderr,
                "release-archive: ERROR: cannot remove private archive workspace: %s\n",
                strerror(errno));
        result = EXIT_FAILURE;
    }
    report_internal_archive_signal_cleanup(&workspace, cleanup_result);
    report_deferred_fatal_cleanup();
    (void)finish_deferred_fatal_signal();
    return result;
}

/* Keep the direct child PID published until its terminal status has been
 * retained. In particular, a successful direct child can become waitable
 * while a descendant still owns the output pipe. */
static volatile sig_atomic_t fatal_signal_producer = 0;
static volatile sig_atomic_t fatal_signal_producer_defers_cleanup = 0;
static volatile sig_atomic_t fatal_signal_pending = 0;
_Static_assert(sizeof(sig_atomic_t) >= sizeof(pid_t),
               "pid_t must fit in sig_atomic_t for release-child publication");
static const int forwarded_fatal_signals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT
};
static struct sigaction saved_fatal_actions[
    sizeof(forwarded_fatal_signals) / sizeof(forwarded_fatal_signals[0])];
static bool fatal_action_installed[
    sizeof(forwarded_fatal_signals) / sizeof(forwarded_fatal_signals[0])];
static sigset_t saved_fatal_mask;
static bool fatal_signal_state_saved = false;
#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
static char internal_archive_cleanup_report_path[PATH_MAX];
#endif
#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
static volatile sig_atomic_t test_reap_transition_active = 0;
static int test_reap_transition_signal = 0;
static int test_reap_transition_report_fd = -1;
static bool test_reap_transition_enabled = false;
static bool test_reap_transition_used = false;
#endif
#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
typedef enum fork_transition_target {
    FORK_TRANSITION_PRODUCER = 1,
    FORK_TRANSITION_CONSUMER = 2
} fork_transition_target_t;

static int test_fork_transition_signal = 0;
static int test_fork_transition_report_fd = -1;
static fork_transition_target_t test_fork_transition_target =
    FORK_TRANSITION_PRODUCER;
static bool test_fork_transition_enabled = false;
static bool test_fork_transition_used = false;
#endif

typedef enum producer_status_result {
    PRODUCER_STATUS_ERROR = -1,
    PRODUCER_STATUS_RUNNING = 0,
    PRODUCER_STATUS_SUCCESS = 1,
    PRODUCER_STATUS_FAILURE = 2,
    PRODUCER_STATUS_GROUP_ERROR = 3
} producer_status_result_t;

typedef enum producer_stream_result {
    PRODUCER_STREAM_CAPTURE_ERROR = -1,
    PRODUCER_STREAM_COMPLETE = 0,
    PRODUCER_STREAM_FAILURE = 1,
    PRODUCER_STREAM_WAIT_ERROR = 2
} producer_stream_result_t;

typedef struct producer_reap_result {
    pid_t waited;
    int wait_errno;
    int mask_errno;
} producer_reap_result_t;

static int build_forwarded_fatal_signal_set(sigset_t *fatal_set)
{
    size_t index;

    if (sigemptyset(fatal_set) != 0) {
        return -1;
    }
    for (index = 0;
         index < sizeof(forwarded_fatal_signals) /
                     sizeof(forwarded_fatal_signals[0]);
         index++) {
        if (sigaddset(fatal_set, forwarded_fatal_signals[index]) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Fork and handler-visible PID publication are one ownership transition.
 * Keep every signal that can consult fatal_signal_producer blocked until both
 * the child process group and the matching publication exist, then restore
 * the caller's exact entry mask in each process. */
static int begin_fatal_fork_guard(sigset_t *saved_mask)
{
    sigset_t fatal_set;

    if (build_forwarded_fatal_signal_set(&fatal_set) != 0) {
        return -1;
    }
    return sigprocmask(SIG_BLOCK, &fatal_set, saved_mask);
}

static int restore_fatal_fork_guard(const sigset_t *saved_mask)
{
    return sigprocmask(SIG_SETMASK, saved_mask, NULL);
}

#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
/* Named-helper-only checkpoint inside the fork-to-publication critical
 * section. The independent signal list makes an incomplete production guard
 * visible as U. Raising while the selected signal is blocked makes it pending;
 * correct code publishes the child before exact-mask restoration delivers it. */
static int run_fork_transition_test_hook(pid_t child,
                                         fork_transition_target_t target)
{
    static const int expected_fatal_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT
    };
    char report[64];
    char proof = 'B';
    int length;
    sigset_t current;
    size_t index;

    if (!test_fork_transition_enabled || test_fork_transition_used ||
        target != test_fork_transition_target) {
        return 0;
    }
    test_fork_transition_used = true;
    if (sigprocmask(SIG_SETMASK, NULL, &current) != 0) {
        proof = 'U';
    } else {
        for (index = 0;
             index < sizeof(expected_fatal_signals) /
                         sizeof(expected_fatal_signals[0]);
             index++) {
            if (sigismember(&current, expected_fatal_signals[index]) != 1) {
                proof = 'U';
                break;
            }
        }
    }
    length = snprintf(report, sizeof(report), "%c %jd\n", proof,
                      (intmax_t)child);
    if (length < 0 || (size_t)length >= sizeof(report)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (write_all(test_fork_transition_report_fd,
                  (const unsigned char *)report, (size_t)length) != 0) {
        return -1;
    }
    return raise(test_fork_transition_signal);
}
#endif

#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
/* This reporter is also called from the fatal-signal handler. Keep it to one
 * async-signal-safe best-effort write: a failed report already makes the
 * named fixture fail, while consuming the result keeps fortified WERROR
 * builds honest. */
static void report_reap_transition(char report)
{
    ssize_t write_result =
        write(test_reap_transition_report_fd, &report, sizeof(report));

    (void)write_result;
}

/* Named-helper-only one-shot checkpoint. The independent oracle ensures a
 * missing production-set member is reported as 'U' rather than hidden by a
 * collusive test mask. The selected signal is raised only after waitpid has
 * released the PID and before handler-visible ownership is retired. */
static void run_reap_transition_test_hook(void)
{
    static const int expected_fatal_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT
    };
    sigset_t current;
    char proof = 'B';
    size_t index;

    if (!test_reap_transition_enabled || test_reap_transition_used) {
        return;
    }
    test_reap_transition_used = true;
    if (sigprocmask(SIG_SETMASK, NULL, &current) != 0) {
        proof = 'U';
    } else {
        for (index = 0;
             index < sizeof(expected_fatal_signals) /
                         sizeof(expected_fatal_signals[0]);
             index++) {
            if (sigismember(&current, expected_fatal_signals[index]) != 1) {
                proof = 'U';
                break;
            }
        }
    }
    report_reap_transition(proof);
    test_reap_transition_active = 1;
    if (raise(test_reap_transition_signal) != 0) {
        static const char raise_failure = 'R';

        report_reap_transition(raise_failure);
    }
}
#endif

/* Reaping releases a numeric PID for reuse. Keep every signal whose handler
 * can consult fatal_signal_producer blocked across that release and the
 * matching publication retirement, then restore the exact entry mask. Wait
 * and mask outcomes remain separate so callers never retry a kill merely
 * because restoration failed after a successful reap. ECHILD likewise proves
 * that this process no longer owns the published numeric identity. */
static producer_reap_result_t reap_and_retire_producer(pid_t child,
                                                        int *status,
                                                        int options)
{
    producer_reap_result_t result = {
        .waited = -1,
        .wait_errno = 0,
        .mask_errno = 0
    };
    sigset_t fatal_set;
    sigset_t saved_mask;

    if (build_forwarded_fatal_signal_set(&fatal_set) != 0) {
        result.mask_errno = errno;
        return result;
    }
    if (sigprocmask(SIG_BLOCK, &fatal_set, &saved_mask) != 0) {
        result.mask_errno = errno;
        return result;
    }
    do {
        result.waited = waitpid(child, status, options);
    } while (result.waited < 0 && errno == EINTR);
    if (result.waited < 0) {
        result.wait_errno = errno;
    }
#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
    if (result.waited == child) {
        run_reap_transition_test_hook();
    }
#endif
    if ((result.waited == child ||
         (result.waited < 0 && result.wait_errno == ECHILD)) &&
        (pid_t)fatal_signal_producer == child) {
        fatal_signal_producer = 0;
        fatal_signal_producer_defers_cleanup = 0;
    }
    if (sigprocmask(SIG_SETMASK, &saved_mask, NULL) != 0) {
        result.mask_errno = errno;
    }
    return result;
}

#if defined(__APPLE__)
/* XNU's explicit-process-group kill path excludes zombies from its group
 * iteration and returns EPERM, rather than ESRCH, when no signalable live
 * member remains.  Do not broadly forgive EPERM: inspect the still-pinned
 * group through KERN_PROC_PGRP and accept it only when every member is already
 * a zombie and the direct child remains the group leader. */
static int darwin_producer_group_is_zombie_only(pid_t child)
{
    int mib[4];
    struct kinfo_proc *members = NULL;
    size_t member_bytes = 0U;
    size_t member_count;
    size_t index;
    unsigned int attempt;
    bool leader_seen = false;

    if (child <= 0 || (uintmax_t)child > (uintmax_t)INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PGRP;
    mib[3] = (int)child;

    for (attempt = 0U; attempt < 4U; attempt++) {
        size_t capacity = 0U;

        if (sysctl(mib, 4U, NULL, &capacity, NULL, 0U) != 0) {
            return -1;
        }
        if (capacity == 0U || capacity > SIZE_MAX - sizeof(*members)) {
            errno = capacity == 0U ? ESRCH : EOVERFLOW;
            return -1;
        }
        members = malloc(capacity);
        if (members == NULL) {
            return -1;
        }
        member_bytes = capacity;
        if (sysctl(mib, 4U, members, &member_bytes, NULL, 0U) == 0) {
            break;
        }
        {
            int snapshot_errno = errno;

            free(members);
            members = NULL;
            if (snapshot_errno != ENOMEM) {
                errno = snapshot_errno;
                return -1;
            }
        }
    }
    if (members == NULL) {
        errno = EAGAIN;
        return -1;
    }
    if (member_bytes == 0U ||
        member_bytes % sizeof(*members) != 0U) {
        free(members);
        errno = EIO;
        return -1;
    }
    member_count = member_bytes / sizeof(*members);
    for (index = 0U; index < member_count; index++) {
        if (members[index].kp_eproc.e_pgid != child) {
            free(members);
            errno = EIO;
            return -1;
        }
        if (members[index].kp_proc.p_pid == child) {
            leader_seen = true;
        }
        if (members[index].kp_proc.p_stat != SZOMB) {
            free(members);
            errno = EBUSY;
            return -1;
        }
    }
    free(members);
    if (!leader_seen) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}
#endif

static int validate_completed_group_kill_failure(pid_t child,
                                                  int group_errno)
{
#if defined(__APPLE__)
    if (group_errno == EPERM) {
        return darwin_producer_group_is_zombie_only(child);
    }
#else
    (void)child;
#endif
    errno = group_errno;
    return -1;
}

/* Observe without releasing the PID first. A terminal producer's process
 * group must receive group-directed SIGKILL while child still pins that
 * numeric identity: immediately on failure, or after the complete inherited
 * stream on success. Only then may waitpid retain the exact status and make
 * the PID reusable. A successful producer is left waitable when
 * finish_success is false so inherited output can still drain under the same
 * owned lifetime boundary. */
static producer_status_result_t observe_producer_status(pid_t child,
                                                         bool finish_success,
                                                         int *status)
{
    siginfo_t observed;
    producer_reap_result_t reap_result;
    bool failed;
    int waitid_rc;

    do {
        memset(&observed, 0, sizeof(observed));
        waitid_rc = waitid(P_PID, (id_t)child, &observed,
                           WEXITED | WNOHANG | WNOWAIT);
    } while (waitid_rc != 0 && errno == EINTR);
    if (waitid_rc != 0) {
        int waitid_errno = errno;

        if (waitid_errno == ECHILD) {
            /* An inherited or external reaper has already released the
             * numeric identity. Retire the matching publication under the
             * same fatal-signal guard before cleanup can consider a kill. */
            (void)reap_and_retire_producer(child, status, WNOHANG);
        }
        errno = waitid_errno;
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
    if (!failed && !finish_success) {
        return PRODUCER_STATUS_SUCCESS;
    }

    if (failed || finish_success) {
        if (kill(-child, SIGKILL) != 0 && errno != ESRCH && !failed) {
            int group_errno = errno;

            /* Keep the waitable direct child and published identity intact so
             * the caller's failure cleanup can retry before reaping it. */
            if (validate_completed_group_kill_failure(child, group_errno) !=
                0) {
                return PRODUCER_STATUS_GROUP_ERROR;
            }
        }
    }
    reap_result = reap_and_retire_producer(child, status, WNOHANG);
    if (reap_result.waited == 0) {
        if (reap_result.mask_errno != 0) {
            errno = reap_result.mask_errno;
            return PRODUCER_STATUS_ERROR;
        }
        errno = EAGAIN;
        return PRODUCER_STATUS_ERROR;
    }
    if (reap_result.waited < 0) {
        errno = reap_result.wait_errno != 0 ? reap_result.wait_errno
                                            : reap_result.mask_errno;
        return PRODUCER_STATUS_ERROR;
    }
    if (reap_result.waited != child) {
        errno = ECHILD;
        return PRODUCER_STATUS_ERROR;
    }
    if (reap_result.mask_errno != 0) {
        errno = reap_result.mask_errno;
        return PRODUCER_STATUS_ERROR;
    }
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
        /* AR-12 P7: preserve the clock failure's own errno — the
         * supervision below may overwrite it, and the caller's diagnostic
         * would otherwise name an unrelated stale error. */
        int clock_errno = remaining_rc < 0 ? (errno ? errno : EIO) : 0;
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
            errno = remaining_rc == 0 ? ETIMEDOUT : clock_errno;
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

/* AR-10 L30 / AR-14 L21: the producer runs in its own process group as the
 * lifetime boundary — which also removes it from the terminal's foreground
 * group. The handler records only the first fatal signal. The internal archive
 * producer receives that exact signal so its own normal flow can remove its
 * private workspace; an arbitrary external producer/consumer receives SIGKILL
 * because it may ignore the requested fatal signal. The handler then returns:
 * parent-owned staging cleanup and exact signal reproduction belong to normal
 * control flow. */

static void forward_fatal_signal(int signal_number)
{
    int saved_errno = errno;
    pid_t child = (pid_t)fatal_signal_producer;
    int producer_signal =
        fatal_signal_producer_defers_cleanup != 0 ? signal_number : SIGKILL;

    if (fatal_signal_pending != 0) {
        errno = saved_errno;
        return;
    }
    fatal_signal_pending = (sig_atomic_t)signal_number;
    if (child > 0) {
#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
        if (test_reap_transition_active != 0) {
            static const char stale_ownership = 'S';

            report_reap_transition(stale_ownership);
            /* Never let the deliberate test mutant signal a numeric identity
             * after waitpid has made it reusable. */
            errno = saved_errno;
            return;
        }
#endif
        (void)kill(-child, producer_signal);
        (void)kill(child, producer_signal);
    }
    errno = saved_errno;
}

#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
static int write_signal_test_report(const char *path,
                                    const unsigned char *bytes, size_t size)
{
    int report_fd;
    int saved_errno;

    report_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                               O_CLOEXEC,
                     S_IRUSR | S_IWUSR);
    if (report_fd < 0) {
        return -1;
    }
    if (write_all(report_fd, bytes, size) != 0) {
        saved_errno = errno;
        (void)close(report_fd);
        errno = saved_errno;
        return -1;
    }
    return close(report_fd);
}

static int run_internal_archive_signal_test_hook(
    const archive_workspace_t *workspace)
{
    const char *ready_path =
        getenv("GITSWITCH_RELEASE_TEST_INTERNAL_ARCHIVE_READY"); /* Flawfinder: ignore — named-fixture-only report path */
    const char *cleanup_path =
        getenv("GITSWITCH_RELEASE_TEST_INTERNAL_ARCHIVE_CLEANUP_REPORT"); /* Flawfinder: ignore — named-fixture-only report path */
    char report[PATH_MAX + 64U];
    struct timespec interval = {0, 10 * 1000 * 1000};
    int length;
    int attempts;

    if (ready_path == NULL && cleanup_path == NULL) {
        return 0;
    }
    if (ready_path == NULL || ready_path[0] == '\0' ||
        cleanup_path == NULL || cleanup_path[0] == '\0' ||
        strlen(cleanup_path) >= sizeof(internal_archive_cleanup_report_path)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(internal_archive_cleanup_report_path, cleanup_path,
           strlen(cleanup_path) + 1U);
    length = snprintf(report, sizeof(report), "pid=%ld\nworkspace=%s\n",
                      (long)getpid(), workspace->root);
    if (length < 0 || (size_t)length >= sizeof(report) ||
        write_signal_test_report(
            ready_path, (const unsigned char *)report, (size_t)length) != 0) {
        return -1;
    }
    for (attempts = 0; fatal_signal_pending == 0 && attempts < 3000;
         attempts++) {
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) {
            return -1;
        }
    }
    if (fatal_signal_pending == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    return 0;
}

static void report_internal_archive_signal_cleanup(
    const archive_workspace_t *workspace, int cleanup_result)
{
    char report[PATH_MAX + 96U];
    int length;

    if (internal_archive_cleanup_report_path[0] == '\0') {
        return;
    }
    length = snprintf(report, sizeof(report),
                      "pid=%ld\nsignal=%d\ncleanup=%s\nworkspace=%s\n",
                      (long)getpid(), (int)fatal_signal_pending,
                      cleanup_result == 0 ? "ok" : "failed",
                      workspace->root);
    if (length < 0 || (size_t)length >= sizeof(report)) {
        return;
    }
    (void)write_signal_test_report(
        internal_archive_cleanup_report_path,
        (const unsigned char *)report, (size_t)length);
}

/* A shell cannot restore a signal that was ignored when the shell started.
 * The named-temp test helper uses this opt-in seam to give the fatal-signal
 * contract a deterministic default, unblocked starting state in every CI
 * launcher. Production builds compile the seam out. */
static int reset_fatal_signals_for_test(void)
{
    /* This oracle stays independent of the forwarding table so a missing
     * production entry cannot also weaken the fixture's starting state. */
    static const int expected_fatal_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT
    };
    struct sigaction default_action;
    sigset_t fatal_set;
    size_t index;

    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    if (sigemptyset(&default_action.sa_mask) != 0 ||
        sigemptyset(&fatal_set) != 0) {
        return -1;
    }
    for (index = 0;
         index < sizeof(expected_fatal_signals) /
                     sizeof(expected_fatal_signals[0]);
         index++) {
        if (sigaction(expected_fatal_signals[index], &default_action, NULL) !=
                0 ||
            sigaddset(&fatal_set, expected_fatal_signals[index]) != 0) {
            return -1;
        }
    }
    return sigprocmask(SIG_UNBLOCK, &fatal_set, NULL);
}
#else
static int run_internal_archive_signal_test_hook(
    const archive_workspace_t *workspace)
{
    (void)workspace;
    return 0;
}

static void report_internal_archive_signal_cleanup(
    const archive_workspace_t *workspace, int cleanup_result)
{
    (void)workspace;
    (void)cleanup_result;
}
#endif

#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT) || \
    defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION) || \
    defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
static int parse_fatal_test_signal(const char *signal_name,
                                   int *selected_signal)
{
    if (strcmp(signal_name, "HUP") == 0) {
        *selected_signal = SIGHUP;
    } else if (strcmp(signal_name, "INT") == 0) {
        *selected_signal = SIGINT;
    } else if (strcmp(signal_name, "QUIT") == 0) {
        *selected_signal = SIGQUIT;
    } else if (strcmp(signal_name, "TERM") == 0) {
        *selected_signal = SIGTERM;
    } else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}
#endif

#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
static int run_signal_wait_oracle(int argc, char **argv)
{
    const char *pid_report =
        getenv("GITSWITCH_RELEASE_TEST_WAIT_ORACLE_PID_REPORT"); /* Flawfinder: ignore — named-fixture-only report path */
    char report[64];
    int expected_signal;
    int length;
    int status;
    pid_t child;
    pid_t waited;

    if (argc < 5 || strcmp(argv[3], "--") != 0 ||
        parse_fatal_test_signal(argv[2], &expected_signal) != 0) {
        fprintf(stderr,
                "ERROR: signal wait oracle requires SIGNAL -- COMMAND\n");
        return EXIT_FAILURE;
    }
    child = fork();
    if (child < 0) {
        fprintf(stderr, "ERROR: signal wait oracle cannot fork: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
    if (child == 0) {
        execvp(argv[4], &argv[4]); /* Flawfinder: ignore — named-fixture-only exact argv oracle */
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (pid_report != NULL) {
        length = snprintf(report, sizeof(report), "%ld\n", (long)child);
        if (pid_report[0] == '\0' || length < 0 ||
            (size_t)length >= sizeof(report) ||
            write_signal_test_report(
                pid_report, (const unsigned char *)report,
                (size_t)length) != 0) {
            int saved_errno = errno;

            (void)kill(child, SIGKILL);
            do {
                waited = waitpid(child, &status, 0);
            } while (waited < 0 && errno == EINTR);
            fprintf(stderr,
                    "ERROR: signal wait oracle cannot publish child PID: %s\n",
                    strerror(saved_errno));
            return EXIT_FAILURE;
        }
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        fprintf(stderr, "ERROR: signal wait oracle cannot reap child: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != expected_signal) {
        if (WIFEXITED(status)) {
            fprintf(stderr,
                    "ERROR: signal wait oracle observed exit status %d, expected signal %d\n",
                    WEXITSTATUS(status), expected_signal);
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr,
                    "ERROR: signal wait oracle observed signal %d, expected %d\n",
                    WTERMSIG(status), expected_signal);
        } else {
            fprintf(stderr,
                    "ERROR: signal wait oracle observed non-terminal status\n");
        }
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void report_internal_archive_reap(char *const command[], pid_t child,
                                         int status)
{
    const char *report_path =
        getenv("GITSWITCH_RELEASE_TEST_INTERNAL_ARCHIVE_REAP_REPORT"); /* Flawfinder: ignore — named-fixture-only report path */
    char report[96];
    int length;

    if (report_path == NULL ||
        strcmp(command[0], ARCHIVE_INTERNAL_TOKEN) != 0) {
        return;
    }
    length = snprintf(report, sizeof(report),
                      "pid=%ld\nsignaled=%d\nsignal=%d\n",
                      (long)child, WIFSIGNALED(status) ? 1 : 0,
                      WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    if (length < 0 || (size_t)length >= sizeof(report)) {
        return;
    }
    (void)write_signal_test_report(
        report_path, (const unsigned char *)report, (size_t)length);
}
#else
static void report_internal_archive_reap(char *const command[], pid_t child,
                                         int status)
{
    (void)command;
    (void)child;
    (void)status;
}
#endif

#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
static int configure_fork_transition_test(void)
{
    const char *signal_name =
        getenv("GITSWITCH_RELEASE_TEST_FORK_SIGNAL"); /* Flawfinder: ignore — named-fixture-only exact signal selector, compiled out of production */
    const char *report_fd =
        getenv("GITSWITCH_RELEASE_TEST_FORK_REPORT_FD"); /* Flawfinder: ignore — named-fixture-only exact descriptor selector, compiled out of production */
    const char *target =
        getenv("GITSWITCH_RELEASE_TEST_FORK_TARGET"); /* Flawfinder: ignore — named-fixture-only exact transition selector, compiled out of production */
    int descriptor_flags;

    if (signal_name == NULL && report_fd == NULL && target == NULL) {
        return 0;
    }
    if (signal_name == NULL || report_fd == NULL || target == NULL ||
        strcmp(report_fd, "9") != 0 ||
        parse_fatal_test_signal(signal_name,
                                &test_fork_transition_signal) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(target, "producer") == 0) {
        test_fork_transition_target = FORK_TRANSITION_PRODUCER;
    } else if (strcmp(target, "consumer") == 0) {
        test_fork_transition_target = FORK_TRANSITION_CONSUMER;
    } else {
        errno = EINVAL;
        return -1;
    }
    descriptor_flags = fcntl(9, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(9, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    test_fork_transition_report_fd = 9;
    test_fork_transition_enabled = true;
    return 0;
}
#endif

#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
static int configure_reap_transition_test(void)
{
    const char *signal_name =
        getenv("GITSWITCH_RELEASE_TEST_REAP_SIGNAL"); /* Flawfinder: ignore — named-fixture-only exact signal selector, compiled out of production */
    const char *report_fd =
        getenv("GITSWITCH_RELEASE_TEST_REAP_REPORT_FD"); /* Flawfinder: ignore — named-fixture-only exact descriptor selector, compiled out of production */
    const char *preblocked =
        getenv("GITSWITCH_RELEASE_TEST_REAP_PREBLOCKED"); /* Flawfinder: ignore — named-fixture-only boolean mask control, compiled out of production */
    sigset_t selected;
    int descriptor_flags;
    int selected_signal;

    if (signal_name == NULL && report_fd == NULL && preblocked == NULL) {
        return 0;
    }
    if (signal_name == NULL || report_fd == NULL ||
        strcmp(report_fd, "9") != 0 ||
        (preblocked != NULL && strcmp(preblocked, "1") != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (parse_fatal_test_signal(signal_name, &selected_signal) != 0) {
        return -1;
    }
    descriptor_flags = fcntl(9, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(9, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    if (preblocked != NULL) {
        if (sigemptyset(&selected) != 0 ||
            sigaddset(&selected, selected_signal) != 0 ||
            sigprocmask(SIG_BLOCK, &selected, NULL) != 0) {
            return -1;
        }
    }
    test_reap_transition_signal = selected_signal;
    test_reap_transition_report_fd = 9;
    test_reap_transition_enabled = true;
    return 0;
}
#endif

/* exec preserves SIG_IGN, and some inherited SIGCHLD policies auto-reap a
 * producer before waitid/waitpid can pin its numeric identity. This dedicated
 * helper owns and must diagnose its one producer, so establish ordinary
 * waitable-child semantics before any fork. A zeroed action also clears
 * SA_NOCLDWAIT where supported. */
static int establish_producer_wait_ownership(void)
{
    struct sigaction waitable;

    memset(&waitable, 0, sizeof(waitable));
    waitable.sa_handler = SIG_DFL;
    if (sigemptyset(&waitable.sa_mask) != 0) {
        return -1;
    }
    return sigaction(SIGCHLD, &waitable, NULL);
}

/* Preserve an inherited SIG_IGN (nohup semantics); otherwise forward. */
static int install_fatal_signal_forwarding(void)
{
    sigset_t fatal_set;
    size_t index;

    if (build_forwarded_fatal_signal_set(&fatal_set) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &saved_fatal_mask) != 0) {
        return -1;
    }
    fatal_signal_state_saved = true;
    for (index = 0;
         index < sizeof(forwarded_fatal_signals) /
                     sizeof(forwarded_fatal_signals[0]);
         index++) {
        struct sigaction forwarding;

        if (sigaction(forwarded_fatal_signals[index], NULL,
                      &saved_fatal_actions[index]) != 0) {
            break;
        }
        if (saved_fatal_actions[index].sa_handler == SIG_IGN) {
            continue;
        }
        memset(&forwarding, 0, sizeof(forwarding));
        forwarding.sa_handler = forward_fatal_signal;
        forwarding.sa_mask = fatal_set;
        if (sigaction(forwarded_fatal_signals[index], &forwarding, NULL) != 0) {
            break;
        }
        fatal_action_installed[index] = true;
    }
    if (index != sizeof(forwarded_fatal_signals) /
                     sizeof(forwarded_fatal_signals[0])) {
        int saved_errno = errno;

        while (index > 0U) {
            index--;
            if (fatal_action_installed[index]) {
                (void)sigaction(forwarded_fatal_signals[index],
                                &saved_fatal_actions[index], NULL);
                fatal_action_installed[index] = false;
            }
        }
        fatal_signal_state_saved = false;
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int restore_fatal_signal_forwarding(void)
{
    size_t index;
    int first_errno = 0;

    if (!fatal_signal_state_saved) {
        return 0;
    }
    for (index = 0;
         index < sizeof(forwarded_fatal_signals) /
                     sizeof(forwarded_fatal_signals[0]);
         index++) {
        if (fatal_action_installed[index] &&
            sigaction(forwarded_fatal_signals[index],
                      &saved_fatal_actions[index], NULL) != 0 &&
            first_errno == 0) {
            first_errno = errno;
        }
        fatal_action_installed[index] = false;
    }
    fatal_signal_state_saved = false;
    if (first_errno != 0) {
        errno = first_errno;
        return -1;
    }
    return 0;
}

#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
static void report_deferred_fatal_cleanup(void)
{
    static const unsigned char proof[] = "cleanup\n";
    const char *marker =
        getenv("GITSWITCH_RELEASE_TEST_SIGNAL_CLEANUP_MARKER"); /* Flawfinder: ignore — named-fixture-only cleanup proof path */
    int marker_fd;

    if (fatal_signal_pending == 0 || marker == NULL || marker[0] == '\0') {
        return;
    }
    marker_fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                O_CLOEXEC,
                     S_IRUSR | S_IWUSR);
    if (marker_fd < 0) {
        return;
    }
    (void)write_all(marker_fd, proof, sizeof(proof) - 1U);
    (void)close(marker_fd);
}
#else
static void report_deferred_fatal_cleanup(void)
{
}
#endif

/* Block the forwarding set across the final pending-state sample so a signal
 * arriving after cleanup cannot slip between the sample and handler restore.
 * A handler-recorded signal is reproduced with its exact number and default
 * disposition only after the saved dispositions/mask have been restored. */
static int finish_deferred_fatal_signal(void)
{
    sigset_t fatal_set;
    sigset_t blocked_mask;
    sigset_t delivery_mask;
    struct sigaction default_action;
    int signal_number;

    if (!fatal_signal_state_saved) {
        return 0;
    }
    if (build_forwarded_fatal_signal_set(&fatal_set) != 0 ||
        sigprocmask(SIG_BLOCK, &fatal_set, &blocked_mask) != 0) {
        return -1;
    }
    (void)blocked_mask;
    signal_number = (int)fatal_signal_pending;
    if (restore_fatal_signal_forwarding() != 0) {
        return -1;
    }
    if (signal_number == 0) {
        return sigprocmask(SIG_SETMASK, &saved_fatal_mask, NULL);
    }

    delivery_mask = saved_fatal_mask;
    if (sigaddset(&delivery_mask, signal_number) != 0 ||
        sigprocmask(SIG_SETMASK, &delivery_mask, NULL) != 0) {
        _exit(128 + signal_number);
    }
    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    if (sigemptyset(&default_action.sa_mask) != 0 ||
        sigaction(signal_number, &default_action, NULL) != 0 ||
        sigdelset(&delivery_mask, signal_number) != 0 ||
        sigprocmask(SIG_SETMASK, &delivery_mask, NULL) != 0) {
        _exit(128 + signal_number);
    }
    (void)kill(getpid(), signal_number);
    _exit(128 + signal_number);
}

/* Fatal delivery is a publication boundary, not merely an error check. Block
 * the complete forwarding set, reject every signal already recorded by the
 * handler (and every newly pending signal that the caller did not itself keep
 * blocked), then keep the set blocked through the one no-replace namespace
 * syscall. A signal arriving after that sample is delivered only after the
 * canonical commit has linearized. */
static int begin_fatal_publication_guard(sigset_t *saved_mask)
{
    sigset_t fatal_set;
    sigset_t pending_set;
    size_t index;
    int abort_publication;

    if (build_forwarded_fatal_signal_set(&fatal_set) != 0 ||
        sigprocmask(SIG_BLOCK, &fatal_set, saved_mask) != 0) {
        return -1;
    }
#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
    {
        static bool publication_signal_used;
        const char *publication_signal =
            getenv("GITSWITCH_RELEASE_TEST_PUBLICATION_SIGNAL"); /* Flawfinder: ignore — named-fixture-only exact signal selector */

        if (!publication_signal_used && publication_signal != NULL) {
            if (strcmp(publication_signal, "TERM") != 0) {
                int saved_errno = EINVAL;

                (void)sigprocmask(SIG_SETMASK, saved_mask, NULL);
                errno = saved_errno;
                return -1;
            }
            publication_signal_used = true;
            if (raise(SIGTERM) != 0) {
                int saved_errno = errno;

                (void)sigprocmask(SIG_SETMASK, saved_mask, NULL);
                errno = saved_errno;
                return -1;
            }
        }
    }
#endif
    abort_publication = fatal_signal_pending != 0;
    if (sigpending(&pending_set) != 0) {
        int saved_errno = errno;

        (void)sigprocmask(SIG_SETMASK, saved_mask, NULL);
        errno = saved_errno;
        return -1;
    }
    for (index = 0U;
         !abort_publication &&
         index < sizeof(forwarded_fatal_signals) /
                     sizeof(forwarded_fatal_signals[0]);
         index++) {
        int signal_number = forwarded_fatal_signals[index];

        if (sigismember(&saved_fatal_mask, signal_number) == 0 &&
            sigismember(&pending_set, signal_number) == 1) {
            abort_publication = 1;
        }
    }
    if (abort_publication) {
        int restore_result = sigprocmask(SIG_SETMASK, saved_mask, NULL);

        if (restore_result == 0) {
            errno = EINTR;
        }
        return -1;
    }
    return 0;
}

/* Return 1 only when the canonical commit succeeded but exact mask restoration
 * failed, matching publish_output's existing post-commit uncertainty result. */
static int finish_fatal_publication_guard(const sigset_t *saved_mask,
                                          int commit_result,
                                          int commit_errno)
{
    if (sigprocmask(SIG_SETMASK, saved_mask, NULL) != 0) {
        return commit_result == 0 ? 1 : -1;
    }
    errno = commit_errno;
    return commit_result;
}

#if !defined(__APPLE__)
static int commit_linkat_without_pending_fatal(
    int old_directory_fd, const char *old_path, int new_directory_fd,
    const char *new_path, int flags)
{
    sigset_t saved_mask;
    int commit_result;
    int commit_errno;

    if (begin_fatal_publication_guard(&saved_mask) != 0) {
        return -1;
    }
    commit_result = linkat(old_directory_fd, old_path, new_directory_fd,
                           new_path, flags);
    commit_errno = errno;
    return finish_fatal_publication_guard(&saved_mask, commit_result,
                                          commit_errno);
}
#endif

#if defined(__APPLE__)
static int commit_clone_without_pending_fatal(int source_fd, int directory_fd,
                                              const char *final_name)
{
    sigset_t saved_mask;
    int commit_result;
    int commit_errno;

    if (begin_fatal_publication_guard(&saved_mask) != 0) {
        return -1;
    }
    commit_result = fclonefileat(source_fd, directory_fd, final_name, 0);
    commit_errno = errno;
    return finish_fatal_publication_guard(&saved_mask, commit_result,
                                          commit_errno);
}
#endif

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
        if (result == PRODUCER_STATUS_GROUP_ERROR) {
            return 1;
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
    producer_reap_result_t reap_result;
    siginfo_t observed;
    int status;
    int waitid_errno = 0;
    int waitid_rc;

    if ((pid_t)fatal_signal_producer != child) {
        errno = saved_errno;
        return;
    }

    /* Refuse to signal through a publication already proven unowned. The
     * normal SIGCHLD contract keeps a live or waitable child pinned; ECHILD is
     * therefore the only result that makes the numeric identity unsafe. */
    do {
        memset(&observed, 0, sizeof(observed));
        waitid_rc = waitid(P_PID, (id_t)child, &observed,
                           WEXITED | WNOHANG | WNOWAIT);
    } while (waitid_rc != 0 && errno == EINTR);
    if (waitid_rc != 0 && errno == ECHILD) {
        (void)reap_and_retire_producer(child, &status, WNOHANG);
        errno = saved_errno;
        return;
    }

    /* The child creates this process group before it can exec or write output,
     * so ordinary descendants remain inside the lifetime boundary. Killing the
     * direct PID as well covers an early setpgid failure. */
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    /* Keep the blocking wait interruptible. WNOWAIT first pins the terminal
     * identity; only the following guarded WNOHANG reap blocks fatal signals. */
    do {
        memset(&observed, 0, sizeof(observed));
        waitid_rc = waitid(P_PID, (id_t)child, &observed,
                           WEXITED | WNOWAIT);
    } while (waitid_rc != 0 && errno == EINTR);
    if (waitid_rc != 0) {
        waitid_errno = errno;
    }
    if (waitid_rc == 0 || waitid_errno == ECHILD) {
        reap_result = reap_and_retire_producer(child, &status, WNOHANG);
        (void)reap_result;
    }
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

static int run_to_descriptor(int output_fd, int directory_fd,
                             char *const command[], int timeout_ms)
{
    int pipe_fds[2];
    int status;
    int saved_errno;
    int64_t deadline;
    int64_t started;
    int wait_result;
    pid_t child;
    producer_stream_result_t stream_result;
    sigset_t saved_mask;

    if (create_producer_pipe(pipe_fds) != 0) {
        return -1;
    }
    if (begin_fatal_fork_guard(&saved_mask) != 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    child = fork();

    if (child < 0) {
        int restore_errno = 0;

        saved_errno = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        if (restore_fatal_fork_guard(&saved_mask) != 0) {
            restore_errno = errno;
        }
        errno = restore_errno != 0 ? restore_errno : saved_errno;
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
        if (directory_fd > STDERR_FILENO) {
            (void)close(directory_fd);
        }
        if (restore_fatal_fork_guard(&saved_mask) != 0) {
            _exit(126);
        }
        if (strcmp(command[0], ARCHIVE_INTERNAL_TOKEN) == 0) {
            _exit(run_internal_release_archive(command));
        }
        execvp(command[0], command); /* Flawfinder: ignore — argv-vector exec of the operator's archive command; no shell, vector from the Makefile recipe */
        _exit(errno == ENOENT ? 127 : 126);
    }
#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
    if (run_fork_transition_test_hook(child,
                                      FORK_TRANSITION_PRODUCER) != 0) {
        saved_errno = errno;
    } else {
        saved_errno = 0;
    }
#else
    saved_errno = 0;
#endif
    /* Publish the producer while every forwarding signal remains blocked.
     * Exact-mask restoration below is the first point that can deliver one. */
    fatal_signal_producer_defers_cleanup =
        strcmp(command[0], ARCHIVE_INTERNAL_TOKEN) == 0 ? 1 : 0;
    fatal_signal_producer = (sig_atomic_t)child;
    (void)close(pipe_fds[1]);
    /* Close the fork/setpgid race from the parent side as well. EACCES/ESRCH
     * only mean the child already crossed that boundary or exited; the child
     * itself cannot exec until its own setpgid succeeds. */
    (void)setpgid(child, child);
    if (restore_fatal_fork_guard(&saved_mask) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0) {
        (void)close(pipe_fds[0]);
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (monotonic_milliseconds(&started) != 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (started > INT64_MAX - (int64_t)timeout_ms) {
        (void)close(pipe_fds[0]);
        errno = EOVERFLOW;
        terminate_producer(child);
        return -1;
    }
    deadline = started + (int64_t)timeout_ms;
    stream_result = copy_producer_stream(pipe_fds[0], output_fd, child,
                                         deadline, &status);
    if (stream_result != PRODUCER_STREAM_COMPLETE) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        if (stream_result == PRODUCER_STREAM_FAILURE) {
            report_internal_archive_reap(command, child, status);
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
    wait_result = wait_for_producer(child, deadline, &status);
    if (wait_result != 0) {
        saved_errno = errno;
        if (wait_result > 0) {
            fprintf(stderr,
                    "ERROR: cannot terminate archive command process group: %s\n",
                    strerror(saved_errno));
        } else if (saved_errno == ETIMEDOUT) {
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
    report_internal_archive_reap(command, child, status);
    /* The complete inherited stream is captured, group-directed SIGKILL was
     * issued while the direct PID still pinned the owned group identity, and
     * the guarded reap retired handler ownership before making it reusable. */
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
    return commit_linkat_without_pending_fatal(
        directory_fd, source_name, directory_fd, final_name, 0);
#else
    (void)source_name;
#if defined(AT_EMPTY_PATH) && AT_EMPTY_PATH != 0
    {
        int commit_result = commit_linkat_without_pending_fatal(
            source_fd, "", directory_fd, final_name, AT_EMPTY_PATH);

        if (commit_result == 0) {
            return 0;
        }
        if (commit_result > 0) {
            return 1;
        }
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
        return commit_linkat_without_pending_fatal(
            AT_FDCWD, descriptor_path, directory_fd, final_name,
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

static bool valid_directory_component(const char *component)
{
    size_t length;

    if (component == NULL || component[0] == '\0' ||
        strcmp(component, ".") == 0 || strcmp(component, "..") == 0 ||
        strchr(component, '/') != NULL) {
        return false;
    }
    length = strlen(component);
    return length <= (size_t)NAME_MAX;
}

#define RPM_STAGE_MAX_LEAVES 1024U

typedef struct rpm_stage_record {
    char name[NAME_MAX + 1U];
    struct stat identity;
    unsigned char digest[SHA256_DIGEST_SIZE];
} rpm_stage_record_t;

static bool same_directory_generation(const struct stat *before,
                                      const struct stat *after)
{
    if (!same_directory_identity(before, after) ||
        before->st_size != after->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
           before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
           before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static bool valid_rpm_component(const char *component, bool require_suffix)
{
    const unsigned char *cursor = (const unsigned char *)component;
    size_t length;

    if (!valid_directory_component(component)) {
        return false;
    }
    length = strlen(component);
    if (strchr(component, ',') != NULL ||
        (require_suffix &&
         (length < 5U || strcmp(component + length - 4U, ".rpm") != 0))) {
        return false;
    }
    while (*cursor != '\0') {
        if (!((*cursor >= (unsigned char)'a' &&
               *cursor <= (unsigned char)'z') ||
              (*cursor >= (unsigned char)'A' &&
               *cursor <= (unsigned char)'Z') ||
              (*cursor >= (unsigned char)'0' &&
               *cursor <= (unsigned char)'9') ||
              strchr("._+-~", (int)*cursor) != NULL)) {
            return false;
        }
        cursor++;
    }
    return true;
}

static bool source_rpm_name_is_valid(const char *name)
{
    static const char suffix[] = ".src.rpm";
    size_t length = strlen(name);

    return valid_rpm_component(name, true) &&
           length > sizeof(suffix) - 1U &&
           strcmp(name + length - (sizeof(suffix) - 1U), suffix) == 0;
}

static int parse_inherited_fd(const char *text, int *fd)
{
    uintmax_t value;
    int flags;

    if (parse_decimal_identity(text, &value) != 0 ||
        value < 3U || value > (uintmax_t)INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    flags = fcntl((int)value, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    if (fcntl((int)value, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    *fd = (int)value;
    return 0;
}

static int validate_inherited_directory(int fd, struct stat *identity)
{
    if (fstat(fd, identity) != 0) {
        return -1;
    }
    if (!S_ISDIR(identity->st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

/* Internal release-shell ABI: pathname stat(1) cannot portably identify an
 * already-open descriptor. In particular, FreeBSD's /dev/fd is fdescfs and
 * stat(1) reports that vnode rather than the regular file behind the open fd.
 * Keep the output to three bounded canonical decimal fields so the shell can
 * compare it directly with pathname identities without parsing diagnostics. */
static int report_inherited_regular_identity(const char *fd_text)
{
    struct stat identity;
    int fd;

    if (parse_inherited_fd(fd_text, &fd) != 0 ||
        fstat(fd, &identity) != 0) {
        return -1;
    }
    if (!S_ISREG(identity.st_mode) || identity.st_size <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (printf("%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX "\n",
               (uintmax_t)identity.st_dev, (uintmax_t)identity.st_ino,
               (uintmax_t)identity.st_size) < 0 ||
        fflush(stdout) != 0) {
        return -1;
    }
    return 0;
}

static int copy_regular_descriptor(int source_fd, off_t size,
                                   int destination_fd)
{
    unsigned char buffer[64U * 1024U];
    off_t offset = 0;

    while (offset < size) {
        off_t remaining = size - offset;
        size_t wanted = sizeof(buffer);
        ssize_t count;

        if (remaining < (off_t)wanted) {
            wanted = (size_t)remaining;
        }
        do {
            count = pread(source_fd, buffer, wanted, offset);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) {
            if (count == 0) {
                errno = ESTALE;
            }
            return -1;
        }
        if (write_all(destination_fd, buffer, (size_t)count) != 0) {
            return -1;
        }
        offset += count;
    }
    return 0;
}

static bool rpm_record_name_exists(const rpm_stage_record_t *records,
                                   size_t count, const char *name)
{
    size_t index;

    for (index = 0U; index < count; index++) {
        if (strcmp(records[index].name, name) == 0) {
            return true;
        }
    }
    return false;
}

static int stage_rpm_leaf(int source_directory_fd, const char *name,
                          int publish_fd, rpm_stage_record_t *records,
                          size_t *record_count)
{
    struct stat path_before;
    struct stat source_before;
    struct stat source_after;
    struct stat staged_stat;
    struct stat staged_path_stat;
    unsigned char source_digest[SHA256_DIGEST_SIZE];
    int source_fd = -1;
    int staged_fd = -1;
    int saved_errno;
    int result = -1;

    if (!valid_rpm_component(name, true) ||
        *record_count >= RPM_STAGE_MAX_LEAVES ||
        rpm_record_name_exists(records, *record_count, name)) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(source_directory_fd, name, &path_before,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(path_before.st_mode) || path_before.st_size <= 0) {
        if (errno == 0) {
            errno = EINVAL;
        }
        return -1;
    }
    do {
        source_fd = openat(source_directory_fd, name,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (source_fd < 0 && errno == EINTR);
    if (source_fd < 0 || fstat(source_fd, &source_before) != 0 ||
        !same_identity(&path_before, &source_before) ||
        source_before.st_size <= 0) {
        if (errno == 0) {
            errno = ESTALE;
        }
        goto cleanup;
    }
    if (digest_regular_descriptor(source_fd, source_before.st_size,
                                  (mode_t)-1, source_digest) != 0) {
        goto cleanup;
    }
    if (run_rpm_stage_race_hook(name) != 0) {
        goto cleanup;
    }
    do {
        staged_fd = openat(publish_fd, name,
                           O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW |
                               O_CLOEXEC,
                           S_IRUSR);
    } while (staged_fd < 0 && errno == EINTR);
    if (staged_fd < 0 ||
        copy_regular_descriptor(source_fd, source_before.st_size,
                                staged_fd) != 0 ||
        fchmod(staged_fd, S_IRUSR) != 0 ||
        full_fsync(staged_fd) != 0 ||
        fstat(staged_fd, &staged_stat) != 0 ||
        staged_stat.st_size != source_before.st_size ||
        (staged_stat.st_mode & 07777) != S_IRUSR ||
        digest_regular_descriptor(staged_fd, staged_stat.st_size,
                                  S_IRUSR,
                                  records[*record_count].digest) != 0 ||
        memcmp(source_digest, records[*record_count].digest,
               SHA256_DIGEST_SIZE) != 0 ||
        fstatat(publish_fd, name, &staged_path_stat,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_identity(&staged_stat, &staged_path_stat) ||
        fstat(source_fd, &source_after) != 0 ||
        !same_identity(&source_before, &source_after) ||
        source_after.st_size != source_before.st_size ||
        fstatat(source_directory_fd, name, &path_before,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_identity(&source_after, &path_before)) {
        if (errno == 0) {
            errno = ESTALE;
        }
        goto cleanup;
    }
    memcpy(&records[*record_count].identity, &staged_stat,
           sizeof(staged_stat));
    memcpy(records[*record_count].name, name, strlen(name) + 1U);
    (*record_count)++;
    result = 0;

cleanup:
    saved_errno = errno;
    if (staged_fd >= 0 && close(staged_fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (source_fd >= 0 && close(source_fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    errno = saved_errno;
    return result;
}

static int reprove_staged_records(
    int publish_fd, const rpm_stage_record_t *records, size_t count)
{
    bool seen[RPM_STAGE_MAX_LEAVES] = {false};
    struct stat generation_before;
    struct stat generation_after;
    DIR *stream;
    int stream_fd;
    size_t observed_count = 0U;
    size_t index;

    if (count > RPM_STAGE_MAX_LEAVES) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(publish_fd, &generation_before) != 0) {
        return -1;
    }
    if (!S_ISDIR(generation_before.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    do {
        stream_fd = openat(publish_fd, ".",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (stream_fd < 0 && errno == EINTR);
    if (stream_fd < 0) {
        return -1;
    }
    stream = fdopendir(stream_fd);
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(stream_fd);
        errno = saved_errno;
        return -1;
    }
    for (;;) {
        struct dirent *entry;
        struct stat path_stat;
        size_t record_index;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                int saved_errno = errno;
                (void)closedir(stream);
                errno = saved_errno;
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!valid_rpm_component(entry->d_name, true) ||
            fstatat(publish_fd, entry->d_name, &path_stat,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(path_stat.st_mode)) {
            int saved_errno = errno != 0 ? errno : EINVAL;
            (void)closedir(stream);
            errno = saved_errno;
            return -1;
        }
        for (record_index = 0U; record_index < count; record_index++) {
            if (strcmp(records[record_index].name, entry->d_name) == 0) {
                break;
            }
        }
        if (record_index == count || seen[record_index] ||
            !same_identity(&records[record_index].identity, &path_stat)) {
            (void)closedir(stream);
            errno = ESTALE;
            return -1;
        }
        seen[record_index] = true;
        observed_count++;
    }
    if (closedir(stream) != 0) {
        return -1;
    }
    if (observed_count != count) {
        errno = ESTALE;
        return -1;
    }
    for (index = 0U; index < count; index++) {
        struct stat descriptor_stat;
        struct stat path_stat;
        unsigned char digest[SHA256_DIGEST_SIZE];
        int fd;

        do {
            fd = openat(publish_fd, records[index].name,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        } while (fd < 0 && errno == EINTR);
        if (fd < 0 || fstat(fd, &descriptor_stat) != 0 ||
            fstatat(publish_fd, records[index].name, &path_stat,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_identity(&descriptor_stat, &path_stat) ||
            !same_identity(&records[index].identity, &descriptor_stat) ||
            descriptor_stat.st_size != records[index].identity.st_size ||
            (descriptor_stat.st_mode & 07777) != S_IRUSR ||
            digest_regular_descriptor(fd, descriptor_stat.st_size,
                                      S_IRUSR, digest) != 0 ||
            memcmp(digest, records[index].digest,
                   SHA256_DIGEST_SIZE) != 0) {
            int saved_errno = errno != 0 ? errno : ESTALE;
            if (fd >= 0) {
                (void)close(fd);
            }
            errno = saved_errno;
            return -1;
        }
        if (close(fd) != 0) {
            return -1;
        }
    }
    if (fstat(publish_fd, &generation_after) != 0 ||
        !same_directory_generation(&generation_before, &generation_after)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int stage_direct_rpm_directory(int directory_fd, int publish_fd,
                                      rpm_stage_record_t *records,
                                      size_t *record_count,
                                      size_t *leaf_count,
                                      bool source_rpms)
{
    DIR *stream;
    struct stat generation_before;
    struct stat generation_after;
    int stream_fd;
    int result = 0;

    if (fstat(directory_fd, &generation_before) != 0 ||
        !S_ISDIR(generation_before.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    do {
        stream_fd = openat(directory_fd, ".",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (stream_fd < 0 && errno == EINTR);
    if (stream_fd < 0) {
        return -1;
    }
    stream = fdopendir(stream_fd);
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(stream_fd);
        errno = saved_errno;
        return -1;
    }
    for (;;) {
        struct dirent *entry;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                result = -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if ((source_rpms &&
             !source_rpm_name_is_valid(entry->d_name)) ||
            (!source_rpms &&
             source_rpm_name_is_valid(entry->d_name))) {
            errno = EINVAL;
            result = -1;
            break;
        }
        if (stage_rpm_leaf(directory_fd, entry->d_name, publish_fd,
                           records, record_count) != 0) {
            result = -1;
            break;
        }
        (*leaf_count)++;
    }
    {
        int saved_errno = errno;
        if (closedir(stream) != 0 && result == 0) {
            return -1;
        }
        errno = saved_errno;
    }
    if (result == 0 &&
        (fstat(directory_fd, &generation_after) != 0 ||
         !same_directory_generation(&generation_before,
                                    &generation_after))) {
        errno = ESTALE;
        return -1;
    }
    return result;
}

static int stage_binary_rpm_directory(int rpms_fd, int publish_fd,
                                      rpm_stage_record_t *records,
                                      size_t *record_count,
                                      size_t *leaf_count)
{
    DIR *stream;
    struct stat generation_before;
    struct stat generation_after;
    int stream_fd;
    int result = 0;

    if (fstat(rpms_fd, &generation_before) != 0 ||
        !S_ISDIR(generation_before.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    do {
        stream_fd = openat(rpms_fd, ".",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (stream_fd < 0 && errno == EINTR);
    if (stream_fd < 0) {
        return -1;
    }
    stream = fdopendir(stream_fd);
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(stream_fd);
        errno = saved_errno;
        return -1;
    }
    for (;;) {
        struct dirent *entry;
        struct stat path_stat;
        struct stat child_stat;
        size_t before_count;
        int child_fd = -1;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                result = -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!valid_rpm_component(entry->d_name, false) ||
            fstatat(rpms_fd, entry->d_name, &path_stat,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(path_stat.st_mode)) {
            errno = EINVAL;
            result = -1;
            break;
        }
        do {
            child_fd = openat(rpms_fd, entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
        } while (child_fd < 0 && errno == EINTR);
        before_count = *leaf_count;
        if (child_fd < 0 || fstat(child_fd, &child_stat) != 0 ||
            !same_directory_identity(&path_stat, &child_stat) ||
            stage_direct_rpm_directory(child_fd, publish_fd, records,
                                       record_count, leaf_count, false) != 0 ||
            *leaf_count == before_count ||
            revalidate_directory_entry(rpms_fd, entry->d_name, child_fd,
                                       &child_stat) != 0) {
            if (errno == 0) {
                errno = EINVAL;
            }
            result = -1;
        }
        if (child_fd >= 0 && close(child_fd) != 0 && result == 0) {
            result = -1;
        }
        if (result != 0) {
            break;
        }
    }
    {
        int saved_errno = errno;
        if (closedir(stream) != 0 && result == 0) {
            return -1;
        }
        errno = saved_errno;
    }
    if (result == 0 &&
        (fstat(rpms_fd, &generation_after) != 0 ||
         !same_directory_generation(&generation_before,
                                    &generation_after))) {
        errno = ESTALE;
        return -1;
    }
    return result;
}

static int directory_is_empty(int directory_fd)
{
    DIR *stream;
    int stream_fd;
    int result = 1;

    do {
        stream_fd = openat(directory_fd, ".",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (stream_fd < 0 && errno == EINTR);
    if (stream_fd < 0) {
        return -1;
    }
    stream = fdopendir(stream_fd);
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(stream_fd);
        errno = saved_errno;
        return -1;
    }
    for (;;) {
        struct dirent *entry;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                result = -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            errno = EEXIST;
            result = 0;
            break;
        }
    }
    {
        int saved_errno = errno;
        if (closedir(stream) != 0 && result >= 0) {
            return -1;
        }
        errno = saved_errno;
    }
    return result;
}

static int emit_rpm_stage_records(const rpm_stage_record_t *records,
                                  size_t count)
{
    static const char hex[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < count; index++) {
        char line[NAME_MAX + 192U];
        char digest_hex[(SHA256_DIGEST_SIZE * 2U) + 1U];
        size_t digest_index;
        int length;

        for (digest_index = 0U; digest_index < SHA256_DIGEST_SIZE;
             digest_index++) {
            digest_hex[digest_index * 2U] =
                hex[records[index].digest[digest_index] >> 4U];
            digest_hex[(digest_index * 2U) + 1U] =
                hex[records[index].digest[digest_index] & 0x0fU];
        }
        digest_hex[SHA256_DIGEST_SIZE * 2U] = '\0';
        length = snprintf(
            line, sizeof(line), "%s,%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
                                ",%s\n",
            records[index].name,
            (uintmax_t)records[index].identity.st_dev,
            (uintmax_t)records[index].identity.st_ino,
            (uintmax_t)records[index].identity.st_size, digest_hex);
        if (length < 0 || (size_t)length >= sizeof(line) ||
            write_all(STDOUT_FILENO, (const unsigned char *)line,
                      (size_t)length) != 0) {
            return -1;
        }
    }
    return 0;
}

static int parse_sha256_hex(const char *text,
                            unsigned char digest[SHA256_DIGEST_SIZE])
{
    size_t index;

    if (strlen(text) != SHA256_DIGEST_SIZE * 2U) {
        errno = EINVAL;
        return -1;
    }
    for (index = 0U; index < SHA256_DIGEST_SIZE; index++) {
        unsigned char high = (unsigned char)text[index * 2U];
        unsigned char low = (unsigned char)text[(index * 2U) + 1U];
        unsigned int high_value;
        unsigned int low_value;

        if (high >= (unsigned char)'0' && high <= (unsigned char)'9') {
            high_value = (unsigned int)(high - (unsigned char)'0');
        } else if (high >= (unsigned char)'a' &&
                   high <= (unsigned char)'f') {
            high_value = (unsigned int)(high - (unsigned char)'a') + 10U;
        } else {
            errno = EINVAL;
            return -1;
        }
        if (low >= (unsigned char)'0' && low <= (unsigned char)'9') {
            low_value = (unsigned int)(low - (unsigned char)'0');
        } else if (low >= (unsigned char)'a' &&
                   low <= (unsigned char)'f') {
            low_value = (unsigned int)(low - (unsigned char)'a') + 10U;
        } else {
            errno = EINVAL;
            return -1;
        }
        digest[index] = (unsigned char)((high_value << 4U) | low_value);
    }
    return 0;
}

static int run_internal_rpm_stage(char *const arguments[])
{
    rpm_stage_record_t *records = NULL;
    struct stat rpms_stat;
    struct stat rpms_after;
    struct stat srpms_stat;
    struct stat srpms_after;
    struct stat publish_stat;
    struct stat publish_after;
    size_t binary_count = 0U;
    size_t source_count = 0U;
    size_t record_count = 0U;
    uintmax_t expected_rpms_device;
    uintmax_t expected_rpms_inode;
    uintmax_t expected_srpms_device;
    uintmax_t expected_srpms_inode;
    uintmax_t expected_publish_device;
    uintmax_t expected_publish_inode;
    int rpms_fd;
    int srpms_fd;
    int publish_fd;
    int result = EXIT_FAILURE;

    if (parse_inherited_fd(arguments[0], &rpms_fd) != 0 ||
        parse_decimal_identity(arguments[1], &expected_rpms_device) != 0 ||
        parse_decimal_identity(arguments[2], &expected_rpms_inode) != 0 ||
        parse_inherited_fd(arguments[3], &srpms_fd) != 0 ||
        parse_decimal_identity(arguments[4], &expected_srpms_device) != 0 ||
        parse_decimal_identity(arguments[5], &expected_srpms_inode) != 0 ||
        parse_inherited_fd(arguments[6], &publish_fd) != 0 ||
        parse_decimal_identity(arguments[7], &expected_publish_device) != 0 ||
        parse_decimal_identity(arguments[8], &expected_publish_inode) != 0 ||
        rpms_fd == srpms_fd || rpms_fd == publish_fd ||
        srpms_fd == publish_fd ||
        validate_inherited_directory(rpms_fd, &rpms_stat) != 0 ||
        validate_inherited_directory(srpms_fd, &srpms_stat) != 0 ||
        validate_inherited_directory(publish_fd, &publish_stat) != 0 ||
        (uintmax_t)rpms_stat.st_dev != expected_rpms_device ||
        (uintmax_t)rpms_stat.st_ino != expected_rpms_inode ||
        (uintmax_t)srpms_stat.st_dev != expected_srpms_device ||
        (uintmax_t)srpms_stat.st_ino != expected_srpms_inode ||
        (uintmax_t)publish_stat.st_dev != expected_publish_device ||
        (uintmax_t)publish_stat.st_ino != expected_publish_inode ||
        same_directory_identity(&rpms_stat, &srpms_stat) ||
        same_directory_identity(&rpms_stat, &publish_stat) ||
        same_directory_identity(&srpms_stat, &publish_stat) ||
        rpms_stat.st_uid != geteuid() ||
        srpms_stat.st_uid != geteuid() ||
        publish_stat.st_uid != geteuid() ||
        (rpms_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (srpms_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (publish_stat.st_mode & 07777) !=
            (S_IRWXU)) {
        fprintf(stderr, "ERROR: invalid inherited RPM directory descriptors\n");
        return EXIT_FAILURE;
    }
    if (directory_is_empty(publish_fd) != 1) {
        fprintf(stderr, "ERROR: RPM publication staging directory is not empty\n");
        return EXIT_FAILURE;
    }
    records = calloc(RPM_STAGE_MAX_LEAVES, sizeof(*records));
    if (records == NULL) {
        fprintf(stderr, "ERROR: cannot allocate bounded RPM record table\n");
        return EXIT_FAILURE;
    }
    if (stage_binary_rpm_directory(rpms_fd, publish_fd, records,
                                   &record_count, &binary_count) != 0 ||
        stage_direct_rpm_directory(srpms_fd, publish_fd, records,
                                   &record_count, &source_count, true) != 0 ||
        binary_count == 0U || source_count == 0U ||
        fstat(rpms_fd, &rpms_after) != 0 ||
        fstat(srpms_fd, &srpms_after) != 0 ||
        fstat(publish_fd, &publish_after) != 0 ||
        !same_directory_identity(&rpms_stat, &rpms_after) ||
        !same_directory_identity(&srpms_stat, &srpms_after) ||
        !same_directory_identity(&publish_stat, &publish_after) ||
        rpms_after.st_uid != geteuid() ||
        srpms_after.st_uid != geteuid() ||
        publish_after.st_uid != geteuid() ||
        (rpms_after.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (srpms_after.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (publish_after.st_mode & 07777) != S_IRWXU ||
        reprove_staged_records(publish_fd, records, record_count) != 0 ||
        full_fsync(publish_fd) != 0 ||
        emit_rpm_stage_records(records, record_count) != 0) {
        fprintf(stderr, "ERROR: cannot stage and prove RPM output tree: %s\n",
                strerror(errno));
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    memset(records, 0, RPM_STAGE_MAX_LEAVES * sizeof(*records));
    free(records);
    return result;
}

static int verify_directory_entry(int parent_fd, const char *component,
                                  int child_fd)
{
    struct stat child_stat;
    struct stat entry_stat;

    if (fstat(child_fd, &child_stat) != 0 ||
        fstatat(parent_fd, component, &entry_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!same_directory_identity(&child_stat, &entry_stat)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int open_directory_component(int parent_fd, const char *component,
                                    mode_t create_mode)
{
    int child_fd;
    int saved_errno;

    if (!valid_directory_component(component)) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        int mkdir_result;

        do {
            child_fd = openat(parent_fd, component,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
        } while (child_fd < 0 && errno == EINTR);
        if (child_fd >= 0) {
            break;
        }
        if (errno != ENOENT) {
            return -1;
        }
        do {
            mkdir_result = mkdirat(parent_fd, component, create_mode);
        } while (mkdir_result != 0 && errno == EINTR);
        if (mkdir_result == 0) {
            continue;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    if (verify_directory_entry(parent_fd, component, child_fd) != 0) {
        saved_errno = errno;
        (void)close(child_fd);
        errno = saved_errno;
        return -1;
    }
    return child_fd;
}

static int verify_release_tree(int root_fd, const char *root_path,
                               int build_fd, const char *build_component,
                               int dist_fd, const char *dist_component)
{
    if (verify_canonical_directory(root_fd, root_path) != 0 ||
        verify_directory_entry(root_fd, build_component, build_fd) != 0 ||
        verify_directory_entry(build_fd, dist_component, dist_fd) != 0) {
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
    {
        int commit_result = commit_clone_without_pending_fatal(
            source_fd, directory_fd, final_name);

        if (commit_result != 0) {
            saved_errno = errno;
#if defined(GITSWITCH_RELEASE_TEST_FD_PRESSURE)
            (void)setrlimit(RLIMIT_NOFILE, &saved_limit);
#endif
            (void)close(reserve_fd);
            errno = saved_errno;
            return commit_result;
        }
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
    {
        int commit_result = link_descriptor(source_fd, directory_fd,
                                            source_name, final_name);

        if (commit_result != 0) {
            return commit_result;
        }
    }
    *published_fd = source_fd;
    return 0;
#endif
}

static int validate_private_consumer_arguments(char *const arguments[])
{
    size_t matches = 0U;
    size_t index;

    for (index = 0U; arguments[index] != NULL; index++) {
        if (strcmp(arguments[index], PRIVATE_ARCHIVE_ARGUMENT) == 0) {
            matches++;
        }
    }
    if (matches != 1U) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Run the distcheck consumer with the exact private output on descriptor 3.
 * The committed shell validator snapshots fd 3 once and closes it before any
 * build descendant is launched. The descriptor is still O_RDWR internally
 * because portable anonymous-file reopening is unavailable; the post-consumer
 * digest makes any persistent mutation fatal, while no pathname ever becomes
 * public. */
static int run_private_consumer(int archive_fd, int directory_fd,
                                char *const command[])
{
    int status;
    int saved_errno;
    int64_t deadline;
    int64_t started;
    int wait_result;
    pid_t child;
    sigset_t saved_mask;

    if (lseek(archive_fd, 0, SEEK_SET) != 0) {
        return -1;
    }
    if (begin_fatal_fork_guard(&saved_mask) != 0) {
        return -1;
    }
    child = fork();
    if (child < 0) {
        int restore_errno = 0;

        saved_errno = errno;
        if (restore_fatal_fork_guard(&saved_mask) != 0) {
            restore_errno = errno;
        }
        errno = restore_errno != 0 ? restore_errno : saved_errno;
        return -1;
    }
    if (child == 0) {
        int descriptor_flags;

        if (setpgid(0, 0) != 0) {
            _exit(126);
        }
        if (archive_fd == 3) {
            descriptor_flags = fcntl(3, F_GETFD);
            if (descriptor_flags < 0 ||
                fcntl(3, F_SETFD,
                      descriptor_flags & ~FD_CLOEXEC) != 0) {
                _exit(126);
            }
        } else if (dup2(archive_fd, 3) < 0) {
            _exit(126);
        }
        if (archive_fd != 3) {
            (void)close(archive_fd);
        }
        if (directory_fd > STDERR_FILENO && directory_fd != 3) {
            (void)close(directory_fd);
        }
        if (restore_fatal_fork_guard(&saved_mask) != 0) {
            _exit(126);
        }
        execvp(command[0], command); /* Flawfinder: ignore -- exact internal distcheck argv from the Makefile */
        _exit(errno == ENOENT ? 127 : 126);
    }
#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
    if (run_fork_transition_test_hook(child,
                                      FORK_TRANSITION_CONSUMER) != 0) {
        saved_errno = errno;
    } else {
        saved_errno = 0;
    }
#else
    saved_errno = 0;
#endif
    fatal_signal_producer_defers_cleanup = 0;
    fatal_signal_producer = (sig_atomic_t)child;
    (void)setpgid(child, child);
    if (restore_fatal_fork_guard(&saved_mask) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0) {
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (monotonic_milliseconds(&started) != 0) {
        saved_errno = errno;
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (started > INT64_MAX -
                      (int64_t)GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS) {
        errno = EOVERFLOW;
        terminate_producer(child);
        return -1;
    }
    deadline = started + (int64_t)GITSWITCH_RELEASE_CONSUMER_TIMEOUT_MS;
    wait_result = wait_for_producer(child, deadline, &status);
    if (wait_result != 0) {
        saved_errno = errno;
        if (wait_result > 0) {
            fprintf(stderr,
                    "ERROR: cannot terminate distcheck consumer process group: %s\n",
                    strerror(saved_errno));
        } else if (saved_errno == ETIMEDOUT) {
            fprintf(stderr, "ERROR: distcheck consumer timed out\n");
        } else {
            fprintf(stderr, "ERROR: cannot wait for distcheck consumer: %s\n",
                    strerror(saved_errno));
        }
        errno = saved_errno;
        terminate_producer(child);
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFEXITED(status)) {
            fprintf(stderr,
                    "ERROR: distcheck consumer exited with status %d\n",
                    WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr,
                    "ERROR: distcheck consumer terminated by signal %d\n",
                    WTERMSIG(status));
        } else {
            fprintf(stderr,
                    "ERROR: distcheck consumer did not exit normally\n");
        }
        errno = EIO;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char temp_name[NAME_MAX + 1U];
    const char *directory_path = NULL;
    const char *canonical_directory = NULL;
    const char *root_path = NULL;
    const char *build_component = NULL;
    const char *dist_component = NULL;
    const char *final_name = NULL;
    int command_index = -1;
    int consumer_index = -1;
    int root_fd = -1;
    int build_fd = -1;
    int directory_fd = -1;
    int source_directory_fd = -1;
    int source_fd = -1;
    int output_fd = -1;
    int published_fd = -1;
    int publish_rc;
    int retire_rc;
    bool has_name = false;
    unsigned char expected_digest[SHA256_DIGEST_SIZE];
    unsigned char published_digest[SHA256_DIGEST_SIZE];
    struct stat existing;
    struct stat source_directory_stat;
    struct stat source_stat;
    struct stat output_stat;
    int result = EXIT_FAILURE;
    bool consume_mode = false;
    bool source_directory_mode = false;
    bool tree_mode = false;
    uintmax_t expected_source_device = 0U;
    uintmax_t expected_source_inode = 0U;
    uintmax_t expected_source_size = 0U;
    uintmax_t expected_source_directory_device = 0U;
    uintmax_t expected_source_directory_inode = 0U;
    unsigned char source_digest[SHA256_DIGEST_SIZE];
#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
    const char *test_signal_defaults;
#endif

    /* Must precede every other descriptor acquisition; see the helper. On
     * failure there is no guaranteed-safe stderr to report on. */
    if (reserve_standard_descriptors() != 0) {
        return EXIT_FAILURE;
    }
#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
    if (argc >= 2 && strcmp(argv[1], "--test-wait-signal") == 0) {
        return run_signal_wait_oracle(argc, argv);
    }
#endif
    if (argc >= 2 &&
        strcmp(argv[1], "--internal-retire-tree-v1") == 0) {
        if (argc != 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        return run_internal_retire_tree(argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc >= 2 &&
        strcmp(argv[1], "--internal-regular-fd-identity-v1") == 0) {
        if (argc != 3 ||
            report_inherited_regular_identity(argv[2]) != 0) {
            fprintf(stderr,
                    "ERROR: invalid inherited regular-file descriptor\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    if (argc >= 2 && strcmp(argv[1], "--internal-rpm-stage-v1") == 0) {
        if (argc != 11) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        return run_internal_rpm_stage(&argv[2]);
    }
    if (argc >= 2 &&
        strcmp(argv[1], "--internal-release-tree-from-dir-v1") == 0) {
        if (argc != 13 ||
            parse_inherited_fd(argv[6], &source_directory_fd) != 0 ||
            validate_inherited_directory(source_directory_fd,
                                         &source_directory_stat) != 0 ||
            source_directory_stat.st_uid != geteuid() ||
            (source_directory_stat.st_mode & 07777) != S_IRWXU ||
            parse_decimal_identity(
                argv[7], &expected_source_directory_device) != 0 ||
            parse_decimal_identity(
                argv[8], &expected_source_directory_inode) != 0 ||
            (uintmax_t)source_directory_stat.st_dev !=
                expected_source_directory_device ||
            (uintmax_t)source_directory_stat.st_ino !=
                expected_source_directory_inode ||
            parse_decimal_identity(argv[9], &expected_source_device) != 0 ||
            parse_decimal_identity(argv[10], &expected_source_inode) != 0 ||
            parse_decimal_identity(argv[11], &expected_source_size) != 0 ||
            expected_source_size == 0U ||
            expected_source_size > (uintmax_t)INT64_MAX ||
            parse_sha256_hex(argv[12], source_digest) != 0) {
            fprintf(stderr,
                    "ERROR: invalid descriptor-relative release arguments\n");
            return EXIT_FAILURE;
        }
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
#if defined(GITSWITCH_RELEASE_TEST_DURABILITY)
    if (configure_durability_test() != 0) {
        fprintf(stderr,
                "ERROR: cannot configure release durability fixture: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
#endif
#if defined(GITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT)
    test_signal_defaults =
        getenv("GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS"); /* Flawfinder: ignore — named-fixture-only boolean test control, compiled out of production */
    if (test_signal_defaults != NULL &&
        strcmp(test_signal_defaults, "1") == 0 &&
        reset_fatal_signals_for_test() != 0) {
        fprintf(stderr, "ERROR: cannot reset test signal state: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
#endif
#if defined(GITSWITCH_RELEASE_TEST_FORK_TRANSITION)
    if (configure_fork_transition_test() != 0) {
        fprintf(stderr, "ERROR: cannot configure fork-transition test: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
#endif
#if defined(GITSWITCH_RELEASE_TEST_REAP_TRANSITION)
    if (configure_reap_transition_test() != 0) {
        fprintf(stderr, "ERROR: cannot configure reap-transition test: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
#endif
    if (install_fatal_signal_forwarding() != 0) {
        fprintf(stderr, "ERROR: cannot install signal forwarding: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (argc == 13 &&
        strcmp(argv[1], "--internal-release-tree-from-dir-v1") == 0) {
        source_directory_mode = true;
        tree_mode = true;
        root_path = argv[2];
        build_component = argv[3];
        dist_component = argv[4];
        final_name = argv[5];
    } else if (argc >= 11 &&
        strcmp(argv[1], "--internal-release-tree-consume-v1") == 0 &&
        strcmp(argv[6], "--") == 0) {
        int index;

        consume_mode = true;
        tree_mode = true;
        root_path = argv[2];
        build_component = argv[3];
        dist_component = argv[4];
        final_name = argv[5];
        command_index = 7;
        for (index = command_index + 1; index < argc; index++) {
            if (strcmp(argv[index], PRIVATE_CONSUMER_SEPARATOR) == 0) {
                if (consumer_index >= 0 || index == command_index ||
                    index + 1 >= argc) {
                    usage(argv[0]);
                    goto cleanup;
                }
                consumer_index = index + 1;
                argv[index] = NULL;
            }
        }
        if (consumer_index < 0) {
            usage(argv[0]);
            goto cleanup;
        }
    } else if (argc >= 8 &&
        strcmp(argv[1], "--internal-release-tree-v1") == 0 &&
        strcmp(argv[6], "--") == 0) {
        tree_mode = true;
        root_path = argv[2];
        build_component = argv[3];
        dist_component = argv[4];
        final_name = argv[5];
        command_index = 7;
    } else if (argc >= 6 && strcmp(argv[4], "--") == 0) {
        directory_path = argv[1];
        canonical_directory = argv[2];
        final_name = argv[3];
        command_index = 5;
    } else {
        usage(argv[0]);
        goto cleanup;
    }
    if (final_name[0] == '\0' || strcmp(final_name, ".") == 0 ||
        strcmp(final_name, "..") == 0 || strchr(final_name, '/') != NULL) {
        fprintf(stderr, "ERROR: final archive name is not a single component\n");
        goto cleanup;
    }
    if (source_directory_mode &&
        !valid_rpm_component(final_name, true)) {
        fprintf(stderr,
                "ERROR: staged RPM name is not a safe RPM component\n");
        goto cleanup;
    }
    if (!source_directory_mode && establish_producer_wait_ownership() != 0) {
        fprintf(stderr, "ERROR: cannot establish archive-child ownership: %s\n",
                strerror(errno));
        goto cleanup;
    }

    if (tree_mode) {
        if (root_path == NULL || root_path[0] != '/' ||
            !valid_directory_component(build_component) ||
            !valid_directory_component(dist_component)) {
            fprintf(stderr,
                    "ERROR: release root must be absolute and directory names must be single components\n");
            goto cleanup;
        }
        do {
            root_fd = open(root_path,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        } while (root_fd < 0 && errno == EINTR);
        if (root_fd < 0 ||
            verify_canonical_directory(root_fd, root_path) != 0) {
            fprintf(stderr, "ERROR: cannot pin canonical release root: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        /* Release output is private while it is being constructed.  Request
         * the same owner-only upper bound for both fresh namespace components;
         * a stricter caller umask may remove permissions but cannot add them.
         * Existing directories retain their established mode. */
        build_fd = open_directory_component(root_fd, build_component, 0700);
        if (build_fd < 0) {
            fprintf(stderr,
                    "ERROR: cannot open or create pinned build directory: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        directory_fd = open_directory_component(build_fd, dist_component,
                                                0700);
        if (directory_fd < 0) {
            fprintf(stderr,
                    "ERROR: cannot open or create pinned distribution directory: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        if (verify_release_tree(root_fd, root_path, build_fd,
                                build_component, directory_fd,
                                dist_component) != 0) {
            fprintf(stderr,
                    "ERROR: pinned release directory chain changed identity\n");
            goto cleanup;
        }
    } else {
        directory_fd = open(directory_path,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory_fd < 0) {
            fprintf(stderr, "ERROR: cannot open distribution directory: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        if (verify_canonical_directory(directory_fd,
                                       canonical_directory) != 0) {
            fprintf(stderr,
                    "ERROR: canonical distribution directory changed identity\n");
            goto cleanup;
        }
    }
    if (!consume_mode) {
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
    }
    if (source_directory_mode) {
        struct stat source_path_stat;
        unsigned char observed_digest[SHA256_DIGEST_SIZE];

        do {
            source_fd = openat(source_directory_fd, final_name,
                               O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        } while (source_fd < 0 && errno == EINTR);
        if (source_fd < 0 || fstat(source_fd, &source_stat) != 0 ||
            fstatat(source_directory_fd, final_name, &source_path_stat,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_identity(&source_stat, &source_path_stat) ||
            (uintmax_t)source_stat.st_dev != expected_source_device ||
            (uintmax_t)source_stat.st_ino != expected_source_inode ||
            source_stat.st_size <= 0 ||
            (uintmax_t)source_stat.st_size != expected_source_size ||
            (source_stat.st_mode & 07777) != S_IRUSR ||
            digest_regular_descriptor(source_fd, source_stat.st_size,
                                      S_IRUSR, observed_digest) != 0 ||
            memcmp(source_digest, observed_digest,
                   SHA256_DIGEST_SIZE) != 0 ||
            fstat(source_directory_fd, &source_path_stat) != 0 ||
            !same_directory_identity(&source_directory_stat,
                                     &source_path_stat) ||
            source_path_stat.st_uid != geteuid() ||
            (source_path_stat.st_mode & 07777) != S_IRWXU) {
            if (errno == 0) {
                errno = ESTALE;
            }
            fprintf(stderr,
                    "ERROR: staged RPM identity or digest does not match its record: %s\n",
                    strerror(errno));
            goto cleanup;
        }
    }

    output_fd = create_temp(directory_fd, final_name, temp_name,
                            sizeof(temp_name), &has_name);
    if (output_fd < 0) {
        fprintf(stderr, "ERROR: cannot create pinned distribution output: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (source_directory_mode) {
        struct stat source_after;
        struct stat source_directory_after;
        unsigned char observed_digest[SHA256_DIGEST_SIZE];

        if (run_release_source_race_hook() != 0 ||
            copy_regular_descriptor(source_fd, source_stat.st_size,
                                    output_fd) != 0 ||
            digest_regular_descriptor(source_fd, source_stat.st_size,
                                      S_IRUSR, observed_digest) != 0 ||
            memcmp(source_digest, observed_digest,
                   SHA256_DIGEST_SIZE) != 0 ||
            fstat(source_fd, &source_after) != 0 ||
            !same_identity(&source_stat, &source_after) ||
            source_after.st_size != source_stat.st_size ||
            fstat(source_directory_fd, &source_directory_after) != 0 ||
            !same_directory_identity(&source_directory_stat,
                                     &source_directory_after) ||
            source_directory_after.st_uid != geteuid() ||
            (source_directory_after.st_mode & 07777) != S_IRWXU) {
            if (errno == 0) {
                errno = ESTALE;
            }
            fprintf(stderr,
                    "ERROR: staged RPM changed during descriptor copy: %s\n",
                    strerror(errno));
            goto cleanup;
        }
    } else {
        if (run_to_descriptor(output_fd, directory_fd,
                              &argv[command_index],
                              GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS) != 0) {
            goto cleanup;
        }
    }
    if (fatal_signal_pending != 0) {
        errno = EINTR;
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
        durability_sync(output_fd, 'F') != 0) {
        fprintf(stderr,
                "ERROR: cannot sync completed distribution output durability stage F: %s\n",
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
    if (source_directory_mode &&
        memcmp(source_digest, expected_digest, SHA256_DIGEST_SIZE) != 0) {
        errno = ESTALE;
        fprintf(stderr,
                "ERROR: descriptor-copied RPM digest differs from its staged record\n");
        goto cleanup;
    }
    if (has_name &&
        verify_named_temp_identity(directory_fd, temp_name, output_fd) != 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: distribution temporary output changed before publication; replacement retained\n");
        goto cleanup;
    }
    if (consume_mode) {
        if (validate_private_consumer_arguments(
                &argv[consumer_index]) != 0) {
            fprintf(stderr,
                    "ERROR: private distcheck consumer requires exactly one archive-fd sentinel: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        if (run_private_consumer(output_fd, directory_fd,
                                 &argv[consumer_index]) != 0) {
            goto cleanup;
        }
        if (fatal_signal_pending != 0) {
            errno = EINTR;
            goto cleanup;
        }
        if (digest_read_only_regular_descriptor(output_fd,
                                                output_stat.st_size,
                                                published_digest) != 0 ||
            memcmp(expected_digest, published_digest,
                   sizeof(expected_digest)) != 0) {
            fprintf(stderr,
                    "ERROR: private distcheck archive changed during validation; applying safe private cleanup policy\n");
            goto cleanup;
        }
        if (has_name &&
            verify_named_temp_identity(directory_fd, temp_name,
                                       output_fd) != 0) {
            fprintf(stderr,
                    "ERROR: private distcheck archive name changed during validation; replacement retained\n");
            goto cleanup;
        }
        result = EXIT_SUCCESS;
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
    if (published_fd != output_fd &&
        durability_sync(published_fd, 'A') != 0) {
        has_name = false;
        fprintf(stderr,
                "ERROR: cannot sync adopted distribution output durability stage A; artifact and private source retained: %s\n",
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
    if (tree_mode &&
        verify_release_tree(root_fd, root_path, build_fd, build_component,
                            directory_fd, dist_component) != 0) {
        fprintf(stderr,
                "ERROR: pinned release directory chain changed before durability barriers; artifact retained\n");
        goto cleanup;
    }
    if (durability_sync(directory_fd, 'D') != 0) {
        fprintf(stderr,
                "ERROR: cannot sync distribution directory durability stage D; published artifact retained: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (tree_mode) {
        if (verify_release_tree(root_fd, root_path, build_fd,
                                build_component, directory_fd,
                                dist_component) != 0) {
            fprintf(stderr,
                    "ERROR: pinned release directory chain changed before build durability; artifact retained\n");
            goto cleanup;
        }
        if (durability_sync(build_fd, 'B') != 0) {
            fprintf(stderr,
                    "ERROR: cannot sync build directory durability stage B; published artifact retained: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        if (verify_release_tree(root_fd, root_path, build_fd,
                                build_component, directory_fd,
                                dist_component) != 0) {
            fprintf(stderr,
                    "ERROR: pinned release directory chain changed before repository durability; artifact retained\n");
            goto cleanup;
        }
        if (durability_sync(root_fd, 'R') != 0) {
            fprintf(stderr,
                    "ERROR: cannot sync repository directory durability stage R; published artifact retained: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        if (verify_release_tree(root_fd, root_path, build_fd,
                                build_component, directory_fd,
                                dist_component) != 0) {
            fprintf(stderr,
                    "ERROR: pinned release directory chain changed during publication; artifact retained\n");
            goto cleanup;
        }
        if (run_final_tree_race_hook() != 0) {
            fprintf(stderr,
                    "ERROR: cannot complete final release-tree test boundary: %s\n",
                    strerror(errno));
            goto cleanup;
        }
    } else if (verify_canonical_directory(directory_fd,
                                          canonical_directory) != 0) {
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
    if (tree_mode) {
        if (verify_release_tree(root_fd, root_path, build_fd,
                                build_component, directory_fd,
                                dist_component) != 0) {
            fprintf(stderr,
                    "ERROR: pinned release directory chain changed before completion; artifact retained\n");
            goto cleanup;
        }
    } else if (verify_canonical_directory(directory_fd,
                                          canonical_directory) != 0) {
        fprintf(stderr,
                "ERROR: canonical distribution directory changed before completion; artifact retained\n");
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    if (has_name && output_fd >= 0) {
        retire_rc = retire_named_temp(directory_fd, temp_name, output_fd);
        if (retire_rc < 0) {
            if (consume_mode) {
                fprintf(stderr,
                        "ERROR: private distcheck archive cleanup lost ownership; replacement retained\n");
            } else {
                fprintf(stderr,
                        "ERROR: distribution staging name changed; replacement retained\n");
            }
            result = EXIT_FAILURE;
        } else if (retire_rc > 0) {
            if (consume_mode) {
                fprintf(stderr,
                        "WARNING: platform lacks descriptor-conditioned unlink; private distcheck archive safely retained\n");
            } else {
                fprintf(stderr,
                        "WARNING: failed publication retained its private staging name\n");
            }
        }
        if (!consume_mode) {
            result = EXIT_FAILURE;
        }
        has_name = false;
    }
    if (published_fd >= 0 && published_fd != output_fd &&
        close(published_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (output_fd >= 0 && close(output_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (source_fd >= 0 && close(source_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (source_directory_fd >= 0 && close(source_directory_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (directory_fd >= 0 && close(directory_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (build_fd >= 0 && close(build_fd) != 0) {
        result = EXIT_FAILURE;
    }
    if (root_fd >= 0 && close(root_fd) != 0) {
        result = EXIT_FAILURE;
    }
    report_deferred_fatal_cleanup();
    if (finish_deferred_fatal_signal() != 0) {
        result = EXIT_FAILURE;
    }
    return result;
}
