#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#define _GNU_SOURCE 1
#endif

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

static int copy_producer_stream(int input_fd, int output_fd,
                                int64_t deadline)
{
    unsigned char buffer[64U * 1024U];
    struct pollfd input;

    input.fd = input_fd;
    input.events = POLLIN;
    input.revents = 0;
    for (;;) {
        int remaining;
        int remaining_rc = deadline_remaining(deadline, &remaining);
        int poll_rc;
        ssize_t count;

        if (remaining_rc <= 0) {
            if (remaining_rc == 0) {
                errno = ETIMEDOUT;
            }
            return -1;
        }
        input.revents = 0;
        poll_rc = poll(&input, 1, remaining);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (poll_rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if ((input.revents & POLLNVAL) != 0) {
            errno = EBADF;
            return -1;
        }
        if ((input.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            errno = EIO;
            return -1;
        }
        do {
            count = read(input_fd, buffer, sizeof(buffer));
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            return -1;
        }
        if (count == 0) {
            return 0;
        }
        if (write_all(output_fd, buffer, (size_t)count) != 0) {
            return -1;
        }
    }
}

static int wait_for_producer(pid_t child, int64_t deadline, int *status)
{
    for (;;) {
        pid_t waited = waitpid(child, status, WNOHANG);

        if (waited == child) {
            return 0;
        }
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
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
    errno = saved_errno;
}

static int run_to_descriptor(int output_fd, char *const command[])
{
    int pipe_fds[2];
    int status;
    int saved_errno;
    int64_t deadline;
    int64_t started;
    pid_t child;

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
        execvp(command[0], command);
        _exit(errno == ENOENT ? 127 : 126);
    }
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
    if (copy_producer_stream(pipe_fds[0], output_fd, deadline) != 0) {
        saved_errno = errno;
        (void)close(pipe_fds[0]);
        if (saved_errno == ETIMEDOUT) {
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
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFEXITED(status)) {
            fprintf(stderr, "ERROR: archive command exited with status %d\n",
                    WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "ERROR: archive command terminated by signal %d\n",
                    WTERMSIG(status));
        } else {
            fprintf(stderr, "ERROR: archive command did not exit normally\n");
        }
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
                                O_RDWR | O_NOFOLLOW | O_CLOEXEC);
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
    struct stat existing;
    struct stat output_stat;
    int result = EXIT_FAILURE;

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
    if (fchmod(output_fd,
               S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0 ||
        fsync(output_fd) != 0) {
        fprintf(stderr, "ERROR: cannot sync completed distribution output: %s\n",
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
