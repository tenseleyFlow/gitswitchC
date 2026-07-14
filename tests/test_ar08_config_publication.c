/* AR-08 T6: no-replace defaults, coherent backups, explicit fault seams, and
 * single-owner full-document publication. */
#include "test.h"

#include "config.h"
#include "error.h"
#include "toml_parser.h"

#include <poll.h>
#include <stdint.h>
#include <sys/wait.h>

#define LARGE_CONFIG_SIZE 9000U

static char g_target[1024];
static char g_saved_source[1024];
static char g_version_a[LARGE_CONFIG_SIZE + 1];
static char g_version_b[LARGE_CONFIG_SIZE + 1];
static size_t g_version_length;
static int g_hook_error;
static int g_default_publish_calls;
static int g_backup_chunk_calls;
static int g_document_rename_calls;
static int g_document_dirsync_calls;
static int g_toml_publication_calls;
static bool g_replace_source_name;
static bool g_rewrite_source_after_first_chunk;
static bool g_replace_backup_destination;
static config_io_boundary_t g_backup_replace_boundary;
static int g_backup_replace_calls;
static bool g_have_competitor_identity;
static struct stat g_competitor_identity;
static bool g_have_backup_competitor_identity;
static struct stat g_backup_competitor_identity;
static char g_saved_backup[1024];
static char g_backup_competitor_path[1024];
static bool g_rewrite_backup_destination;
static int g_rewrite_backup_destination_calls;
static int g_backup_clock_calls;
static int g_concurrent_writer_start_fd = -1;
static int g_concurrent_writer_result_fd = -1;

typedef struct {
    int result;
    int result_errno;
    int installed;
} concurrent_writer_result_t;

static concurrent_writer_result_t g_concurrent_writer_result;
static bool g_concurrent_writer_result_received;
static config_io_boundary_t g_concurrent_writer_boundary =
    CONFIG_IO_DOCUMENT_BEFORE_RENAME;

typedef enum {
    SOURCE_AFTER_COPY_NONE = 0,
    SOURCE_AFTER_COPY_CTIME_ONLY,
    SOURCE_AFTER_COPY_REWRITE_PRESERVING_MTIME,
    SOURCE_BEFORE_COPY_VALID_REWRITE_PRESERVING_MTIME
} source_after_copy_action_t;

static source_after_copy_action_t g_source_after_copy_action;
static int g_source_after_copy_calls;

static int private_dir(char *path, size_t size) {
    if ((size_t)snprintf(path, size,
                         "/tmp/gitswitch-ar08-config.XXXXXX") >= size) {
        return -1;
    }
    return ts_mkdtemp(path) ? 0 : -1;
}

static int write_bytes(const char *path, const char *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, data + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (fchmod(fd, 0600) != 0) { close(fd); return -1; }
    return close(fd);
}

static int write_text(const char *path, const char *text) {
    return write_bytes(path, text, strlen(text));
}

static int write_pipe_bytes(int fd, const void *data, size_t length) {
    const unsigned char *bytes = data;
    size_t total = 0;

    while (total < length) {
        ssize_t written = write(fd, bytes + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

static int read_pipe_bytes(int fd, void *data, size_t length) {
    unsigned char *bytes = data;
    size_t total = 0;

    while (total < length) {
        ssize_t received = read(fd, bytes + total, length - total);
        if (received > 0) total += (size_t)received;
        else if (received < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

static bool same_ctime(const struct stat *left, const struct stat *right) {
#if defined(__APPLE__)
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool same_mtime(const struct stat *left, const struct stat *right) {
#if defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static int change_source_after_copy(source_after_copy_action_t action) {
    struct stat before;
    struct stat after;
    int fd = open(g_target, O_RDWR | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0 || fstat(fd, &before) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (action == SOURCE_AFTER_COPY_REWRITE_PRESERVING_MTIME ||
        action == SOURCE_BEFORE_COPY_VALID_REWRITE_PRESERVING_MTIME) {
        struct timespec times[2];
        char prefix[512];
        unsigned char byte;
        off_t offset = 0;

        if (action == SOURCE_BEFORE_COPY_VALID_REWRITE_PRESERVING_MTIME) {
            ssize_t length = pread(fd, prefix, sizeof(prefix) - 1, 0);
            char *assignment;

            if (length <= 0) {
                close(fd);
                return -1;
            }
            prefix[length] = '\0';
            assignment = strstr(prefix, "default_scope =");
            if (!assignment) {
                close(fd);
                errno = EINVAL;
                return -1;
            }
            offset = (off_t)(assignment - prefix) +
                     (off_t)strlen("default_scope");
        }
        if (pread(fd, &byte, 1, offset) != 1) {
            close(fd);
            return -1;
        }
        if (action == SOURCE_BEFORE_COPY_VALID_REWRITE_PRESERVING_MTIME) {
            byte = '\t';
        } else {
            byte ^= 1U;
        }
        if (pwrite(fd, &byte, 1, offset) != 1) {
            close(fd);
            return -1;
        }
#if defined(__APPLE__)
        times[0] = before.st_atimespec;
        times[1] = before.st_mtimespec;
#else
        times[0] = before.st_atim;
        times[1] = before.st_mtim;
#endif
        if (futimens(fd, times) != 0) {
            close(fd);
            return -1;
        }
        for (int attempt = 0; attempt < 10; attempt++) {
            if (fstat(fd, &after) != 0) {
                close(fd);
                return -1;
            }
            if (!same_ctime(&before, &after)) {
                if (fsync(fd) != 0) {
                    close(fd);
                    return -1;
                }
                return close(fd);
            }
            if (fchmod(fd, before.st_mode & 0777) != 0) {
                close(fd);
                return -1;
            }
            (void)poll(NULL, 0, 1);
        }
        close(fd);
        errno = EIO;
        return -1;
    }

    for (int attempt = 0; attempt < 10; attempt++) {
        if (fchmod(fd, before.st_mode & 0777) != 0 ||
            fstat(fd, &after) != 0) {
            close(fd);
            return -1;
        }
        if (!same_ctime(&before, &after)) return close(fd);
        (void)poll(NULL, 0, 1);
    }
    close(fd);
    errno = EIO;
    return -1;
}

static int fixed_backup_clock(uint64_t *seconds, uint32_t *nanoseconds) {
    *seconds = 1234;
    *nanoseconds = 567;
    return 0;
}

static int adversarial_backup_clock(uint64_t *seconds,
                                    uint32_t *nanoseconds) {
    g_backup_clock_calls++;
    if (change_source_after_copy(
            SOURCE_BEFORE_COPY_VALID_REWRITE_PRESERVING_MTIME) != 0) {
        g_hook_error = errno ? errno : EIO;
        return -1;
    }
    return fixed_backup_clock(seconds, nanoseconds);
}

static size_t read_bytes(const char *path, char *data, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;

    if (fd < 0 || size == 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    while (total + 1 < size) {
        ssize_t count = read(fd, data + total, size - total - 1);
        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    data[total] = '\0';
    return total;
}

static int count_prefix(const char *dir, const char *prefix) {
    DIR *stream = opendir(dir);
    struct dirent *entry;
    int count = 0;

    if (!stream) return -1;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) count++;
    }
    closedir(stream);
    return count;
}

static void build_large_config(char *buffer, char generation) {
    int header = snprintf(buffer, LARGE_CONFIG_SIZE + 1,
                          "[settings]\n"
                          "default_scope = \"local\"\n"
                          "# generation-%c\n#", generation);
    size_t position = header > 0 ? (size_t)header : 0;
    size_t tail_offset = 8400;

    while (position < tail_offset) buffer[position++] = generation;
    buffer[position++] = '\n';
    int tail = snprintf(buffer + position, LARGE_CONFIG_SIZE + 1 - position,
                        "[accounts.1]\n"
                        "name = \"alice\"\n"
                        "email = \"alice@example.com\"\n"
                        "description = \"generation-%c\"\n",
                        generation);
    position += tail > 0 ? (size_t)tail : 0;
    while (position < LARGE_CONFIG_SIZE) buffer[position++] = '\n';
    buffer[position] = '\0';
}

static int find_backup_destination(void) {
    char dir[1024];
    char prefix[512];
    char *slash;
    DIR *stream;
    struct dirent *entry;

    if ((size_t)snprintf(dir, sizeof(dir), "%s", g_target) >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    slash = strrchr(dir, '/');
    if (!slash || slash == dir || slash[1] == '\0' ||
        (size_t)snprintf(prefix, sizeof(prefix), "%s.backup.",
                         slash + 1) >= sizeof(prefix)) {
        errno = EINVAL;
        return -1;
    }
    *slash = '\0';
    stream = opendir(dir);
    if (!stream) {
        return -1;
    }
    g_backup_competitor_path[0] = '\0';
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            if ((size_t)snprintf(g_backup_competitor_path,
                                 sizeof(g_backup_competitor_path),
                                 "%s/%s", dir, entry->d_name) >=
                sizeof(g_backup_competitor_path)) {
                errno = ENAMETOOLONG;
                g_backup_competitor_path[0] = '\0';
            }
            break;
        }
    }
    if (closedir(stream) != 0) {
        return -1;
    }
    if (g_backup_competitor_path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

static void substitute_backup_destination(void) {
    if (find_backup_destination() != 0 ||
        rename(g_backup_competitor_path, g_saved_backup) != 0 ||
         write_bytes(g_backup_competitor_path, g_version_b,
                     g_version_length) != 0 ||
         lstat(g_backup_competitor_path,
               &g_backup_competitor_identity) != 0) {
        g_hook_error = errno ? errno : EIO;
    } else {
        g_have_backup_competitor_identity = true;
    }
}

static bool publication_observer(config_io_boundary_t boundary) {
    if (boundary == g_concurrent_writer_boundary &&
        g_concurrent_writer_start_fd >= 0 &&
        g_concurrent_writer_result_fd >= 0 &&
        !g_concurrent_writer_result_received) {
        const unsigned char start = 1;
        concurrent_writer_result_t result;

        if (write_pipe_bytes(g_concurrent_writer_start_fd, &start,
                             sizeof(start)) != 0 ||
            read_pipe_bytes(g_concurrent_writer_result_fd, &result,
                            sizeof(result)) != 0) {
            g_hook_error = errno ? errno : EIO;
        } else {
            g_concurrent_writer_result = result;
            g_concurrent_writer_result_received = true;
        }
    }
    if (boundary == CONFIG_IO_DEFAULT_BEFORE_RENAME) {
        static const char competitor[] = "competitor-wins\n";
        g_default_publish_calls++;
        if (write_text(g_target, competitor) != 0) {
            g_hook_error = errno ? errno : EIO;
        } else if (lstat(g_target, &g_competitor_identity) != 0) {
            g_hook_error = errno ? errno : EIO;
        } else {
            g_have_competitor_identity = true;
        }
    } else if (g_source_after_copy_action != SOURCE_AFTER_COPY_NONE &&
               boundary == CONFIG_IO_BACKUP_BEFORE_DIR_SYNC) {
        g_source_after_copy_calls++;
        if (change_source_after_copy(g_source_after_copy_action) != 0) {
            g_hook_error = errno ? errno : EIO;
        }
    } else if (g_rewrite_backup_destination &&
               boundary == CONFIG_IO_BACKUP_BEFORE_FILE_SYNC) {
        g_rewrite_backup_destination_calls++;
        if (find_backup_destination() != 0 ||
            write_bytes(g_backup_competitor_path, g_version_b,
                        g_version_length) != 0) {
            g_hook_error = errno ? errno : EIO;
        }
    } else if (g_replace_backup_destination &&
               boundary == g_backup_replace_boundary) {
        if (boundary == CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK) {
            g_backup_chunk_calls++;
        }
        g_backup_replace_calls++;
        substitute_backup_destination();
    } else if (boundary == CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK) {
        g_backup_chunk_calls++;
        if (g_replace_backup_destination) {
            /* A later checkpoint owns the requested destination swap. */
        } else if (g_replace_source_name) {
            if (rename(g_target, g_saved_source) != 0 ||
                write_bytes(g_target, g_version_b, g_version_length) != 0) {
                g_hook_error = errno ? errno : EIO;
            }
        } else if (g_rewrite_source_after_first_chunk) {
            int fd = open(g_target, O_WRONLY | O_CLOEXEC);
            size_t total = 0;
            if (fd < 0) {
                g_hook_error = errno ? errno : EIO;
            } else {
                while (total < g_version_length) {
                    ssize_t written = pwrite(fd, g_version_b + total,
                                             g_version_length - total,
                                             (off_t)total);
                    if (written > 0) total += (size_t)written;
                    else if (written < 0 && errno == EINTR) continue;
                    else { g_hook_error = errno ? errno : EIO; break; }
                }
                if (close(fd) != 0 && g_hook_error == 0) {
                    g_hook_error = errno ? errno : EIO;
                }
            }
        }
    } else if (boundary == CONFIG_IO_DOCUMENT_BEFORE_RENAME) {
        g_document_rename_calls++;
    } else if (boundary == CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC) {
        g_document_dirsync_calls++;
    }
    return false;
}

static void toml_publication_observer(toml_writer_test_stage_t stage,
                                      const char *directory,
                                      const char *temp_name) {
    (void)stage;
    (void)directory;
    (void)temp_name;
    g_toml_publication_calls++;
}

TEST(default_creation_never_replaces_a_concurrent_winner) {
    char dir[256];
    char text[128];
    struct stat competitor_after;
    int result;
    int result_errno;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(g_target, sizeof(g_target), "%s/accounts.toml", dir);
    g_hook_error = 0;
    g_default_publish_calls = 0;
    g_have_competitor_identity = false;
    config_set_io_fault_fn(publication_observer);
    errno = 0;
    result = config_create_default(g_target);
    result_errno = errno;
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT(result_errno, EEXIST);
    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_default_publish_calls, 1);
    CHECK(g_have_competitor_identity);
    CHECK(read_bytes(g_target, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "competitor-wins\n");
    CHECK_EQ_INT(lstat(g_target, &competitor_after), 0);
    CHECK(ts_same_identity(&g_competitor_identity, &competitor_after));
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.create."), 0);
}

static void exercise_unstable_backup(bool replace_name) {
    char dir[256];
    char current[LARGE_CONFIG_SIZE + 1];

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(g_target, sizeof(g_target), "%s/accounts.toml", dir);
    snprintf(g_saved_source, sizeof(g_saved_source), "%s/source-before.toml",
             dir);
    build_large_config(g_version_a, 'A');
    build_large_config(g_version_b, 'B');
    g_version_length = strlen(g_version_a);
    CHECK_EQ_INT(g_version_length, strlen(g_version_b));
    CHECK(g_version_length > 8192);
    CHECK_EQ_INT(write_bytes(g_target, g_version_a, g_version_length), 0);

    g_hook_error = 0;
    g_backup_chunk_calls = 0;
    g_replace_source_name = replace_name;
    g_rewrite_source_after_first_chunk = !replace_name;
    clear_error();
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_backup(g_target), -1); /* pre-fix: accepted */
    config_set_io_fault_fn(NULL);
    g_replace_source_name = false;
    g_rewrite_source_after_first_chunk = false;

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_backup_chunk_calls, 1);
    CHECK(strstr(get_last_error()->message, "changed while backup") != NULL);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(read_bytes(g_target, current, sizeof(current)),
                 g_version_length);
    CHECK(memcmp(current, g_version_b, g_version_length) == 0);
}

TEST(backup_rejects_an_in_place_mixed_generation) {
    exercise_unstable_backup(false);
}

TEST(backup_rejects_when_the_parent_name_selects_a_new_inode) {
    exercise_unstable_backup(true);
}

TEST(backup_rejects_in_place_destination_rewrite) {
    char dir[256];
    char current[LARGE_CONFIG_SIZE + 1];

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(g_target, sizeof(g_target), "%s/accounts.toml", dir);
    build_large_config(g_version_a, 'A');
    build_large_config(g_version_b, 'B');
    g_version_length = strlen(g_version_a);
    CHECK_EQ_INT(g_version_length, strlen(g_version_b));
    CHECK_EQ_INT(write_bytes(g_target, g_version_a, g_version_length), 0);

    g_hook_error = 0;
    g_rewrite_backup_destination_calls = 0;
    g_rewrite_backup_destination = true;
    g_replace_backup_destination = false;
    g_replace_source_name = false;
    g_rewrite_source_after_first_chunk = false;
    clear_error();
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_backup(g_target), -1);
    config_set_io_fault_fn(NULL);
    g_rewrite_backup_destination = false;

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_rewrite_backup_destination_calls, 1);
    CHECK(strstr(get_last_error()->message,
                 "does not match its source generation") != NULL);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(read_bytes(g_target, current, sizeof(current)),
                 g_version_length);
    CHECK(memcmp(current, g_version_a, g_version_length) == 0);
}

static void exercise_backup_destination_substitution(
    config_io_boundary_t boundary) {
    char dir[256];
    char current[LARGE_CONFIG_SIZE + 1];
    struct stat competitor_after;
    int result;
    int result_errno;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(g_target, sizeof(g_target), "%s/accounts.toml", dir);
    snprintf(g_saved_backup, sizeof(g_saved_backup), "%s/copied.fd", dir);
    build_large_config(g_version_a, 'A');
    build_large_config(g_version_b, 'B');
    g_version_length = strlen(g_version_a);
    CHECK_EQ_INT(g_version_length, strlen(g_version_b));
    CHECK_EQ_INT(write_bytes(g_target, g_version_a, g_version_length), 0);

    g_hook_error = 0;
    g_backup_chunk_calls = 0;
    g_backup_replace_calls = 0;
    g_replace_source_name = false;
    g_replace_backup_destination = true;
    g_backup_replace_boundary = boundary;
    g_have_backup_competitor_identity = false;
    g_backup_competitor_path[0] = '\0';
    clear_error();
    config_set_io_fault_fn(publication_observer);
    errno = 0;
    result = config_backup(g_target);
    result_errno = errno;
    config_set_io_fault_fn(NULL);
    g_replace_backup_destination = false;

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT(result_errno, ESTALE);
    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_backup_replace_calls, 1);
    CHECK_EQ_INT(g_backup_chunk_calls, 1);
    CHECK(strstr(get_last_error()->message,
                 "Backup destination changed") != NULL);
    CHECK(g_have_backup_competitor_identity);
    CHECK_EQ_INT(lstat(g_backup_competitor_path, &competitor_after), 0);
    CHECK(ts_same_identity(&g_backup_competitor_identity,
                           &competitor_after));
    CHECK_EQ_INT(read_bytes(g_backup_competitor_path, current,
                            sizeof(current)), g_version_length);
    CHECK(memcmp(current, g_version_b, g_version_length) == 0);
    CHECK_EQ_INT(read_bytes(g_saved_backup, current, sizeof(current)),
                 g_version_length);
    CHECK(memcmp(current, g_version_a, g_version_length) == 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 1);
}

TEST(backup_rejects_destination_name_substitution_during_copy) {
    exercise_backup_destination_substitution(
        CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK);
}

TEST(backup_rejects_destination_name_substitution_before_dirsync) {
    exercise_backup_destination_substitution(
        CONFIG_IO_BACKUP_BEFORE_DIR_SYNC);
}

TEST(backup_rejects_destination_name_substitution_before_reopen) {
    exercise_backup_destination_substitution(CONFIG_IO_BACKUP_BEFORE_REOPEN);
}

TEST(backup_rejects_destination_name_substitution_during_verification) {
    exercise_backup_destination_substitution(
        CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ);
}

TEST(descriptor_serializer_cannot_publish_a_path) {
    char dir[256];
    char target[512];
    char temp[512];
    char text[256];
    struct stat before;
    struct stat after;
    toml_document_t *doc = malloc(sizeof(*doc));
    toml_document_t *parsed = malloc(sizeof(*parsed));
    int fd;

    CHECK(doc != NULL);
    CHECK(parsed != NULL);
    if (!doc || !parsed) {
        free(doc);
        free(parsed);
        return;
    }
    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(target, sizeof(target), "%s/published.toml", dir);
    snprintf(temp, sizeof(temp), "%s/prepared.tmp", dir);
    CHECK_EQ_INT(write_text(target, "sentinel\n"), 0);
    CHECK_EQ_INT(lstat(target, &before), 0);
    fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) {
        free(doc);
        free(parsed);
        return;
    }

    toml_init_document(doc);
    CHECK_EQ_INT(toml_set_string(doc, "settings", "default_scope", "local"),
                 0);
    g_toml_publication_calls = 0;
    toml_set_writer_test_hook_fn(toml_publication_observer);
    CHECK_EQ_INT(toml_write_fd(doc, fd), 0);
    toml_set_writer_test_hook_fn(NULL);
    CHECK_EQ_INT(g_toml_publication_calls, 0);
    CHECK(fcntl(fd, F_GETFD) >= 0); /* caller still owns the descriptor */
    CHECK_EQ_INT(lstat(target, &after), 0);
    CHECK(ts_same_identity(&before, &after));
    CHECK(read_bytes(target, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "sentinel\n");
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(toml_parse_file(temp, parsed), 0);
    toml_cleanup_document(parsed);
    toml_cleanup_document(doc);
    free(parsed);
    free(doc);
}

TEST(full_save_accepts_proven_ctime_only_backup_drift) {
    char dir[256];
    char path[512];
    char current[1024];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(g_target, sizeof(g_target), "%s", path);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);

    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    installed = false;
    g_hook_error = 0;
    g_source_after_copy_calls = 0;
    g_source_after_copy_action = SOURCE_AFTER_COPY_CTIME_ONLY;
    g_replace_source_name = false;
    g_replace_backup_destination = false;
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    config_set_io_fault_fn(NULL);
    g_source_after_copy_action = SOURCE_AFTER_COPY_NONE;

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_source_after_copy_calls, 1);
    CHECK(installed);
    CHECK(read_bytes(path, current, sizeof(current)) > 0);
    CHECK(strstr(current, "default_scope = \"global\"") != NULL);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 1);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
}

TEST(full_save_rejects_same_size_rewrite_with_restored_mtime) {
    char dir[256];
    char path[512];
    char before[1024];
    char current[1024];
    size_t before_length;
    size_t current_length;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(g_target, sizeof(g_target), "%s", path);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);
    before_length = read_bytes(path, before, sizeof(before));
    CHECK(before_length > 0);

    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    installed = false;
    g_hook_error = 0;
    g_source_after_copy_calls = 0;
    g_source_after_copy_action =
        SOURCE_AFTER_COPY_REWRITE_PRESERVING_MTIME;
    g_replace_source_name = false;
    g_replace_backup_destination = false;
    clear_error();
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);
    g_source_after_copy_action = SOURCE_AFTER_COPY_NONE;

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_source_after_copy_calls, 1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed while backup was committed") != NULL);
    current_length = read_bytes(path, current, sizeof(current));
    CHECK_EQ_INT(current_length, before_length);
    CHECK(current_length > 0 && current[0] != before[0]);
    CHECK(current_length <= 1 ||
          memcmp(current + 1, before + 1, current_length - 1) == 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
}

TEST(full_save_rejects_pre_copy_rewrite_with_restored_mtime) {
    char dir[256];
    char path[512];
    char before[1024];
    char expected[1024];
    char current[1024];
    char *assignment;
    size_t before_length;
    size_t current_length;
    struct stat before_identity;
    struct stat after_identity;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(g_target, sizeof(g_target), "%s", path);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);
    before_length = read_bytes(path, before, sizeof(before));
    CHECK(before_length > 0);
    CHECK_EQ_INT(lstat(path, &before_identity), 0);
    memcpy(expected, before, before_length + 1);
    assignment = strstr(expected, "default_scope =");
    CHECK(assignment != NULL);
    if (assignment) assignment[strlen("default_scope")] = '\t';

    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    installed = false;
    g_hook_error = 0;
    g_backup_clock_calls = 0;
    g_source_after_copy_action = SOURCE_AFTER_COPY_NONE;
    g_replace_source_name = false;
    g_replace_backup_destination = false;
    clear_error();
    config_set_backup_clock_fn(adversarial_backup_clock);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_backup_clock_fn(NULL);

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_backup_clock_calls, 1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed while backup was committed") != NULL);
    CHECK_EQ_INT(lstat(path, &after_identity), 0);
    CHECK(ts_same_identity(&before_identity, &after_identity));
    CHECK(same_mtime(&before_identity, &after_identity));
    CHECK(!same_ctime(&before_identity, &after_identity));
    current_length = read_bytes(path, current, sizeof(current));
    CHECK_EQ_INT(current_length, before_length);
    CHECK_EQ_INT(current_length, strlen(expected));
    CHECK(memcmp(current, expected, current_length) == 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
}

TEST(rejected_full_save_preserves_five_retained_backups) {
    char dir[256];
    char path[512];
    char before[1024];
    char current[1024];
    size_t before_length;
    size_t current_length;
    struct stat before_identity;
    struct stat after_identity;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(g_target, sizeof(g_target), "%s", path);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);

    config_set_backup_clock_fn(fixed_backup_clock);
    for (int i = 0; i < 5; i++) {
        CHECK_EQ_INT(config_backup(path), 0);
    }
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 5);
    before_length = read_bytes(path, before, sizeof(before));
    CHECK(before_length > 0);
    CHECK_EQ_INT(lstat(path, &before_identity), 0);

    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    installed = false;
    g_hook_error = 0;
    g_source_after_copy_calls = 0;
    g_source_after_copy_action =
        SOURCE_AFTER_COPY_REWRITE_PRESERVING_MTIME;
    g_replace_source_name = false;
    g_replace_backup_destination = false;
    clear_error();
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);
    config_set_backup_clock_fn(NULL);
    g_source_after_copy_action = SOURCE_AFTER_COPY_NONE;

    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_source_after_copy_calls, 1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed while backup was committed") != NULL);
    CHECK_EQ_INT(lstat(path, &after_identity), 0);
    CHECK(ts_same_identity(&before_identity, &after_identity));
    CHECK(same_mtime(&before_identity, &after_identity));
    current_length = read_bytes(path, current, sizeof(current));
    CHECK_EQ_INT(current_length, before_length);
    CHECK(current_length > 0 && current[0] != before[0]);
    CHECK(current_length <= 1 ||
          memcmp(current + 1, before + 1, current_length - 1) == 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 5);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
}

TEST(full_save_has_one_document_publisher_and_ignores_fault_environment) {
    char dir[256];
    char path[512];
    char hint[512];
    char text[512];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;

    g_document_rename_calls = 0;
    g_document_dirsync_calls = 0;
    g_toml_publication_calls = 0;
    config_set_io_fault_fn(publication_observer);
    toml_set_writer_test_hook_fn(toml_publication_observer);
    CHECK_EQ_INT(setenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT", "1", 1), 0);
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK_EQ_INT(unsetenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT"), 0);
    toml_set_writer_test_hook_fn(NULL);
    config_set_io_fault_fn(NULL);

    CHECK(installed);
    CHECK_EQ_INT(g_document_rename_calls, 1);
    CHECK_EQ_INT(g_document_dirsync_calls, 1);
    CHECK_EQ_INT(g_toml_publication_calls, 0); /* pre-fix: nested writer ran */
    CHECK(read_bytes(path, text, sizeof(text)) > 0);
    CHECK(strstr(text, "default_scope = \"local\"") != NULL);
    CHECK(read_bytes(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".gitswitch-toml."), 0);
}

static void initialize_concurrent_writer_context(gitswitch_ctx_t *ctx,
                                                 git_scope_t scope,
                                                 bool with_account,
                                                 bool active) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->config.default_scope = scope;
    if (!with_account) return;

    ctx->account_count = 1;
    ctx->accounts[0].id = 1;
    ctx->accounts[0].preferred_scope = GIT_SCOPE_LOCAL;
    snprintf(ctx->accounts[0].name, sizeof(ctx->accounts[0].name), "alice");
    snprintf(ctx->accounts[0].email, sizeof(ctx->accounts[0].email),
             "alice@example.com");
    if (active) {
        snprintf(ctx->config.active_account,
                 sizeof(ctx->config.active_account), "alice");
    }
}

static void exercise_concurrent_public_save(
    config_io_boundary_t checkpoint, bool active_transition) {
    char dir[256];
    char path[512];
    char hint[512];
    char text[1024];
    int start_pipe[2] = {-1, -1};
    int result_pipe[2] = {-1, -1};
    int status = 0;
    pid_t child = -1;
    gitswitch_ctx_t initial;
    gitswitch_ctx_t first;
    bool installed = false;
    int first_result;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    initialize_concurrent_writer_context(&initial, GIT_SCOPE_LOCAL,
                                         active_transition, false);
    CHECK_EQ_INT(config_save_transactional(&initial, path, &installed), 0);
    CHECK(installed);
    CHECK_EQ_INT(pipe(start_pipe), 0);
    CHECK_EQ_INT(pipe(result_pipe), 0);

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        unsigned char start = 0;
        concurrent_writer_result_t result;
        gitswitch_ctx_t second;
        bool second_installed = false;

        close(start_pipe[1]);
        close(result_pipe[0]);
        config_set_io_fault_fn(NULL);
        if (read_pipe_bytes(start_pipe[0], &start, sizeof(start)) != 0 ||
            start != 1) {
            _exit(2);
        }
        initialize_concurrent_writer_context(&second, GIT_SCOPE_LOCAL,
                                             active_transition, false);
        errno = 0;
        result.result = config_save_transactional(&second, path,
                                                  &second_installed);
        result.result_errno = errno;
        result.installed = second_installed ? 1 : 0;
        if (write_pipe_bytes(result_pipe[1], &result, sizeof(result)) != 0) {
            _exit(3);
        }
        close(start_pipe[0]);
        close(result_pipe[1]);
        _exit(0);
    }
    if (child < 0) {
        if (start_pipe[0] >= 0) close(start_pipe[0]);
        if (start_pipe[1] >= 0) close(start_pipe[1]);
        if (result_pipe[0] >= 0) close(result_pipe[0]);
        if (result_pipe[1] >= 0) close(result_pipe[1]);
        return;
    }

    close(start_pipe[0]);
    close(result_pipe[1]);
    g_concurrent_writer_start_fd = start_pipe[1];
    g_concurrent_writer_result_fd = result_pipe[0];
    g_hook_error = 0;
    g_document_rename_calls = 0;
    g_concurrent_writer_boundary = checkpoint;
    memset(&g_concurrent_writer_result, 0,
           sizeof(g_concurrent_writer_result));
    g_concurrent_writer_result_received = false;
    initialize_concurrent_writer_context(&first, GIT_SCOPE_GLOBAL,
                                         active_transition,
                                         active_transition);
    installed = false;
    config_set_io_fault_fn(publication_observer);
    first_result = config_save_transactional(&first, path, &installed);
    config_set_io_fault_fn(NULL);
    close(start_pipe[1]);
    close(result_pipe[0]);
    g_concurrent_writer_start_fd = -1;
    g_concurrent_writer_result_fd = -1;
    g_concurrent_writer_boundary = CONFIG_IO_DOCUMENT_BEFORE_RENAME;

    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    CHECK(WIFEXITED(status));
    CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(g_document_rename_calls, 1);
    CHECK_EQ_INT(first_result, 0);
    CHECK(installed);
    CHECK(g_concurrent_writer_result_received);
    CHECK_EQ_INT(g_concurrent_writer_result.result, -1);
    CHECK(g_concurrent_writer_result.result_errno == EWOULDBLOCK ||
          g_concurrent_writer_result.result_errno == EAGAIN);
    CHECK_EQ_INT(g_concurrent_writer_result.installed, 0);
    CHECK(read_bytes(path, text, sizeof(text)) > 0);
    CHECK(strstr(text, "default_scope = \"global\"") != NULL);
    CHECK(read_bytes(hint, text, sizeof(text)) > 0);
    if (active_transition) {
        CHECK_STR_EQ(text, "none\nactive=alice\n");
    } else {
        CHECK_STR_EQ(text, "none\ninactive=v1\n");
    }
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
}

TEST(concurrent_public_save_cannot_commit_inside_document_replace_gap) {
    exercise_concurrent_public_save(CONFIG_IO_DOCUMENT_BEFORE_RENAME, false);
}

TEST(concurrent_public_save_cannot_commit_inside_state_replace_gap) {
    exercise_concurrent_public_save(CONFIG_IO_STATE_BEFORE_RENAME, true);
}

TEST_MAIN_BEGIN()
    RUN_TEST(default_creation_never_replaces_a_concurrent_winner);
    RUN_TEST(backup_rejects_an_in_place_mixed_generation);
    RUN_TEST(backup_rejects_when_the_parent_name_selects_a_new_inode);
    RUN_TEST(backup_rejects_in_place_destination_rewrite);
    RUN_TEST(backup_rejects_destination_name_substitution_during_copy);
    RUN_TEST(backup_rejects_destination_name_substitution_before_dirsync);
    RUN_TEST(backup_rejects_destination_name_substitution_before_reopen);
    RUN_TEST(backup_rejects_destination_name_substitution_during_verification);
    RUN_TEST(descriptor_serializer_cannot_publish_a_path);
    RUN_TEST(full_save_accepts_proven_ctime_only_backup_drift);
    RUN_TEST(full_save_rejects_same_size_rewrite_with_restored_mtime);
    RUN_TEST(full_save_rejects_pre_copy_rewrite_with_restored_mtime);
    RUN_TEST(rejected_full_save_preserves_five_retained_backups);
    RUN_TEST(full_save_has_one_document_publisher_and_ignores_fault_environment);
    RUN_TEST(concurrent_public_save_cannot_commit_inside_document_replace_gap);
    RUN_TEST(concurrent_public_save_cannot_commit_inside_state_replace_gap);
TEST_MAIN_END()
