#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
    int fd;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    while (size > 0U) {
        ssize_t count = read(fd, cursor, size);
        if (count > 0) {
            cursor += (size_t)count;
            size -= (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count == 0) {
            errno = EIO;
        }
        (void)close(fd);
        return -1;
    }
    if (close(fd) != 0) {
        return -1;
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
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
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
#if defined(O_TMPFILE) && O_TMPFILE != 0
    int fd = openat(directory_fd, ".",
                    O_WRONLY | O_TMPFILE | O_CLOEXEC,
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

static int unlink_named_temp_if_owned(int directory_fd, const char *temp_name,
                                      int temp_fd)
{
    struct stat descriptor_stat;
    struct stat path_stat;

    if (fstat(temp_fd, &descriptor_stat) != 0) {
        return -1;
    }
    if (fstatat(directory_fd, temp_name, &path_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!same_identity(&descriptor_stat, &path_stat)) {
        errno = ESTALE;
        return -1;
    }
    return unlinkat(directory_fd, temp_name, 0);
}

static int run_to_descriptor(int output_fd, char *const command[])
{
    int status;
    pid_t waited;
    pid_t child = fork();

    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        if (dup2(output_fd, STDOUT_FILENO) < 0) {
            _exit(126);
        }
        if (output_fd != STDOUT_FILENO) {
            (void)close(output_fd);
        }
        execvp(command[0], command);
        _exit(errno == ENOENT ? 127 : 126);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
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

static int link_descriptor(int source_fd, int directory_fd,
                           const char *final_name)
{
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
}

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

static int unlink_published_if_owned(int source_fd, int directory_fd,
                                     const char *final_name)
{
    if (verify_published_identity(source_fd, directory_fd, final_name) != 0) {
        return -1;
    }
    return unlinkat(directory_fd, final_name, 0);
}

int main(int argc, char **argv)
{
    char temp_name[NAME_MAX + 1U];
    const char *directory_path;
    const char *canonical_directory;
    const char *final_name;
    int directory_fd = -1;
    int output_fd = -1;
    bool has_name = false;
    bool published = false;
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
    if (fchmod(output_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0 ||
        fsync(output_fd) != 0) {
        fprintf(stderr, "ERROR: cannot sync completed distribution output: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (link_descriptor(output_fd, directory_fd, final_name) != 0) {
        fprintf(stderr,
                "ERROR: cannot publish pinned distribution output without replacement: %s\n",
                strerror(errno));
        goto cleanup;
    }
    published = true;
    if (verify_published_identity(output_fd, directory_fd, final_name) != 0) {
        fprintf(stderr, "ERROR: published distribution output changed identity\n");
        goto cleanup;
    }
    if (has_name &&
        unlink_named_temp_if_owned(directory_fd, temp_name, output_fd) != 0) {
        fprintf(stderr, "ERROR: distribution temporary output changed identity\n");
        goto cleanup;
    }
    has_name = false;
    if (fsync(directory_fd) != 0) {
        fprintf(stderr, "ERROR: cannot sync distribution directory: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (verify_canonical_directory(directory_fd, canonical_directory) != 0) {
        fprintf(stderr,
                "ERROR: canonical distribution directory changed during publication\n");
        goto cleanup;
    }
    published = false;
    result = EXIT_SUCCESS;

cleanup:
    if (published &&
        unlink_published_if_owned(output_fd, directory_fd, final_name) != 0 &&
        errno != ENOENT) {
        fprintf(stderr,
                "ERROR: refusing to remove a replaced distribution output\n");
        result = EXIT_FAILURE;
    }
    if (has_name && output_fd >= 0 &&
        unlink_named_temp_if_owned(directory_fd, temp_name, output_fd) != 0 &&
        errno != ENOENT) {
        fprintf(stderr,
                "ERROR: refusing to remove a replaced distribution temporary\n");
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
