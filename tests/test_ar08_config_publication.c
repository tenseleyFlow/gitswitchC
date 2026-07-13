/* AR-08 T6: no-replace defaults, coherent backups, explicit fault seams, and
 * single-owner full-document publication. */
#include "test.h"

#include "config.h"
#include "error.h"
#include "toml_parser.h"

#include <stdint.h>

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
static bool g_replace_backup_destination;
static config_io_boundary_t g_backup_replace_boundary;
static int g_backup_replace_calls;
static bool g_have_competitor_identity;
static struct stat g_competitor_identity;
static bool g_have_backup_competitor_identity;
static struct stat g_backup_competitor_identity;
static char g_saved_backup[1024];
static char g_backup_competitor_path[1024];

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

static void substitute_backup_destination(void) {
    char dir[1024];
    char prefix[512];
    char *slash;
    DIR *stream;
    struct dirent *entry;

    if ((size_t)snprintf(dir, sizeof(dir), "%s", g_target) >= sizeof(dir)) {
        g_hook_error = ENAMETOOLONG;
        return;
    }
    slash = strrchr(dir, '/');
    if (!slash || slash == dir || slash[1] == '\0' ||
        (size_t)snprintf(prefix, sizeof(prefix), "%s.backup.",
                         slash + 1) >= sizeof(prefix)) {
        g_hook_error = EINVAL;
        return;
    }
    *slash = '\0';
    stream = opendir(dir);
    if (!stream) {
        g_hook_error = errno ? errno : EIO;
        return;
    }
    g_backup_competitor_path[0] = '\0';
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            if ((size_t)snprintf(g_backup_competitor_path,
                                 sizeof(g_backup_competitor_path),
                                 "%s/%s", dir, entry->d_name) >=
                sizeof(g_backup_competitor_path)) {
                g_hook_error = ENAMETOOLONG;
            }
            break;
        }
    }
    if (closedir(stream) != 0 && g_hook_error == 0) {
        g_hook_error = errno ? errno : EIO;
    }
    if (g_hook_error == 0 &&
        (g_backup_competitor_path[0] == '\0' ||
         rename(g_backup_competitor_path, g_saved_backup) != 0 ||
         write_bytes(g_backup_competitor_path, g_version_b,
                     g_version_length) != 0 ||
         lstat(g_backup_competitor_path,
               &g_backup_competitor_identity) != 0)) {
        g_hook_error = errno ? errno : EIO;
    } else if (g_hook_error == 0) {
        g_have_backup_competitor_identity = true;
    }
}

static bool publication_observer(config_io_boundary_t boundary) {
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
        } else {
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
    clear_error();
    config_set_io_fault_fn(publication_observer);
    CHECK_EQ_INT(config_backup(g_target), -1); /* pre-fix: accepted */
    config_set_io_fault_fn(NULL);

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

TEST_MAIN_BEGIN()
    RUN_TEST(default_creation_never_replaces_a_concurrent_winner);
    RUN_TEST(backup_rejects_an_in_place_mixed_generation);
    RUN_TEST(backup_rejects_when_the_parent_name_selects_a_new_inode);
    RUN_TEST(backup_rejects_destination_name_substitution_during_copy);
    RUN_TEST(backup_rejects_destination_name_substitution_before_dirsync);
    RUN_TEST(backup_rejects_destination_name_substitution_before_reopen);
    RUN_TEST(backup_rejects_destination_name_substitution_during_verification);
    RUN_TEST(descriptor_serializer_cannot_publish_a_path);
    RUN_TEST(full_save_has_one_document_publisher_and_ignores_fault_environment);
TEST_MAIN_END()
