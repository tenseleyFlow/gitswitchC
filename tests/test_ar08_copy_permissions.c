/* AR-08 L8: copy_file must secure the opened destination before exposing any
 * copied bytes, for both newly created and pre-existing permissive files. */
#include "test.h"

#include "error.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef void (*copy_file_test_hook_fn)(int stage, const char *dst_path);
copy_file_test_hook_fn gitswitch_test_set_copy_file_hook(
    copy_file_test_hook_fn hook);
typedef void (*read_file_test_hook_fn)(int stage, int file_fd);
read_file_test_hook_fn gitswitch_test_set_read_file_hook(
    read_file_test_hook_fn hook);

enum {
    COPY_FILE_TEST_AFTER_DESTINATION_OPEN = 1,
    COPY_FILE_TEST_AFTER_FIRST_WRITE,
    COPY_FILE_TEST_BEFORE_DESTINATION_OPEN
};

enum {
    READ_FILE_TEST_BEFORE_INITIAL_READ = 1,
    READ_FILE_TEST_BEFORE_EXACT_FIT_PROBE
};

typedef struct {
    char content[128];
    mode_t mode;
    dev_t dev;
    ino_t ino;
} file_state_t;

typedef struct {
    bool saw_open;
    bool saw_payload;
    mode_t open_mode;
    mode_t payload_mode;
    off_t payload_size;
    mode_t final_mode;
    off_t final_size;
    int hook_error;
} copy_observation_t;

static copy_observation_t g_observation;
static const char *g_replacement_source;
static const char *g_replacement_displaced;
static int g_replacement_hook_calls;
static int g_replacement_hook_error;
static int g_read_fault_stage;
static int g_read_hook_calls;
static int g_read_hook_error;

static int write_text_mode(const char *path, const char *content, mode_t mode) {
    size_t length = strlen(content);
    size_t total = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, content + total, length - total);
        if (written > 0) {
            total += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            int saved_errno = errno ? errno : EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    if (fchmod(fd, mode) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int read_file_state(const char *path, file_state_t *state) {
    size_t total = 0;
    int fd;
    struct stat st;

    if (!path || !state) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    while (total + 1 < sizeof(state->content)) {
        ssize_t length = read(fd, state->content + total,
                              sizeof(state->content) - total - 1);
        if (length > 0) {
            total += (size_t)length;
        } else if (length == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    if (total + 1 == sizeof(state->content)) {
        char extra;
        ssize_t length;
        do {
            length = read(fd, &extra, 1);
        } while (length < 0 && errno == EINTR);
        if (length != 0) {
            int saved_errno = length < 0 ? errno : EFBIG;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    if (close(fd) != 0) return -1;
    state->content[total] = '\0';
    state->mode = st.st_mode & 0777;
    state->dev = st.st_dev;
    state->ino = st.st_ino;
    return 0;
}

static bool file_state_matches(const file_state_t *left,
                               const file_state_t *right) {
    return left && right && strcmp(left->content, right->content) == 0 &&
           left->mode == right->mode && left->dev == right->dev &&
           left->ino == right->ino;
}

static void replace_destination_before_open(int stage, const char *dst_path) {
    if (stage != COPY_FILE_TEST_BEFORE_DESTINATION_OPEN) return;
    g_replacement_hook_calls++;
    if (!g_replacement_source || !g_replacement_displaced ||
        rename(dst_path, g_replacement_displaced) != 0 ||
        link(g_replacement_source, dst_path) != 0) {
        g_replacement_hook_error = errno ? errno : EIO;
    }
}

static void replace_read_descriptor_with_write_only(int stage, int file_fd) {
    int replacement_fd;

    if (stage != g_read_fault_stage) return;
    g_read_hook_calls++;
    replacement_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (replacement_fd < 0) {
        g_read_hook_error = errno ? errno : EIO;
        return;
    }
    if (dup2(replacement_fd, file_fd) < 0) {
        g_read_hook_error = errno ? errno : EIO;
    }
    if (close(replacement_fd) != 0 && g_read_hook_error == 0) {
        g_read_hook_error = errno ? errno : EIO;
    }
}

static int write_source(const char *path) {
    unsigned char bytes[4096];
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    memset(bytes, 'S', sizeof(bytes));
    for (int chunk = 0; chunk < 3; chunk++) {
        size_t total = 0;
        while (total < sizeof(bytes)) {
            ssize_t written = write(fd, bytes + total, sizeof(bytes) - total);
            if (written > 0) total += (size_t)written;
            else if (written < 0 && errno == EINTR) continue;
            else { close(fd); return -1; }
        }
    }
    if (fchmod(fd, 0600) != 0) { close(fd); return -1; }
    return close(fd);
}

static int create_permissive_destination(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);

    if (fd < 0) return -1;
    if (fchmod(fd, 0666) != 0 || write(fd, "old", 3) != 3) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static void observe_copy_checkpoint(int stage, const char *dst_path) {
    struct stat st;

    if (g_observation.hook_error != 0) return;
    if (stage != COPY_FILE_TEST_AFTER_DESTINATION_OPEN &&
        stage != COPY_FILE_TEST_AFTER_FIRST_WRITE) {
        return;
    }
    if (stat(dst_path, &st) != 0) {
        g_observation.hook_error = errno ? errno : EIO;
        return;
    }
    if (stage == COPY_FILE_TEST_AFTER_DESTINATION_OPEN) {
        g_observation.saw_open = true;
        g_observation.open_mode = st.st_mode & 0777;
        if (st.st_size != 0) g_observation.hook_error = EPROTO;
        return;
    }
    if (stage == COPY_FILE_TEST_AFTER_FIRST_WRITE) {
        unsigned char prefix[64];
        int fd;
        ssize_t length;

        g_observation.saw_payload = true;
        g_observation.payload_mode = st.st_mode & 0777;
        g_observation.payload_size = st.st_size;
        fd = open(dst_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            g_observation.hook_error = errno ? errno : EIO;
            return;
        }
        length = read(fd, prefix, sizeof(prefix));
        close(fd);
        if (length != (ssize_t)sizeof(prefix)) {
            g_observation.hook_error = EIO;
            return;
        }
        for (size_t i = 0; i < sizeof(prefix); i++) {
            if (prefix[i] != 'S') {
                g_observation.hook_error = EILSEQ;
                return;
            }
        }
    }
}

static int exercise_copy(bool existing_destination) {
    char root[] = "/tmp/gs_copy_permissions_XXXXXX";
    char src[512], dst[512];
    struct stat st;
    mode_t previous_umask;
    int result = -1;

    memset(&g_observation, 0, sizeof(g_observation));
    if (!ts_mkdtemp(root)) return -1;
    if ((size_t)snprintf(src, sizeof(src), "%s/source", root) >= sizeof(src) ||
        (size_t)snprintf(dst, sizeof(dst), "%s/destination", root) >=
            sizeof(dst) ||
        write_source(src) != 0 ||
        (existing_destination && create_permissive_destination(dst) != 0)) {
        goto cleanup;
    }

    previous_umask = umask(0000);
    (void)gitswitch_test_set_copy_file_hook(observe_copy_checkpoint);
    result = copy_file(src, dst);
    (void)gitswitch_test_set_copy_file_hook(NULL);
    (void)umask(previous_umask);
    if (result != 0 || stat(dst, &st) != 0) {
        result = -1;
        goto cleanup;
    }
    g_observation.final_mode = st.st_mode & 0777;
    g_observation.final_size = st.st_size;

cleanup:
    (void)gitswitch_test_set_copy_file_hook(NULL);
    (void)unlink(dst);
    (void)unlink(src);
    (void)rmdir(root);
    return result;
}

TEST(absent_destination_is_born_private_before_any_bytes) {
    CHECK_EQ_INT(exercise_copy(false), 0);
    CHECK(g_observation.saw_open);
    CHECK(g_observation.saw_payload);
    CHECK_EQ_INT(g_observation.hook_error, 0);
    CHECK_EQ_INT(g_observation.open_mode, 0600);
    CHECK_EQ_INT(g_observation.payload_mode, 0600);
    CHECK(g_observation.payload_size >= 4096);
    CHECK_EQ_INT(g_observation.final_mode, 0600);
    CHECK_EQ_INT(g_observation.final_size, 3 * 4096);
}

TEST(permissive_existing_destination_is_secured_before_first_payload) {
    CHECK_EQ_INT(exercise_copy(true), 0);
    CHECK(g_observation.saw_open);
    CHECK(g_observation.saw_payload);
    CHECK_EQ_INT(g_observation.hook_error, 0);
    CHECK_EQ_INT(g_observation.open_mode, 0666);
    CHECK_EQ_INT(g_observation.payload_mode, 0600);
    CHECK(g_observation.payload_size >= 4096);
    CHECK_EQ_INT(g_observation.final_mode, 0600);
    CHECK_EQ_INT(g_observation.final_size, 3 * 4096);
}

TEST(literal_same_path_is_rejected_without_mutation) {
    char root[] = "/tmp/gs_copy_same_path_XXXXXX";
    char path[512];
    file_state_t before;
    file_state_t after;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/file", root) <
          sizeof(path));
    CHECK_EQ_INT(write_text_mode(path, "source-body", 0640), 0);
    CHECK_EQ_INT(read_file_state(path, &before), 0);

    clear_error();
    CHECK_EQ_INT(copy_file(path, path), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(read_file_state(path, &after), 0);
    CHECK(file_state_matches(&before, &after));
}

TEST(hardlink_alias_is_rejected_without_mutation) {
    char root[] = "/tmp/gs_copy_hardlink_XXXXXX";
    char src[512];
    char dst[512];
    file_state_t before;
    file_state_t source_after;
    file_state_t alias_after;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(src, sizeof(src), "%s/source", root) < sizeof(src));
    CHECK((size_t)snprintf(dst, sizeof(dst), "%s/alias", root) < sizeof(dst));
    CHECK_EQ_INT(write_text_mode(src, "hardlink-source", 0644), 0);
    CHECK_EQ_INT(link(src, dst), 0);
    CHECK_EQ_INT(read_file_state(src, &before), 0);

    CHECK_EQ_INT(copy_file(src, dst), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(read_file_state(src, &source_after), 0);
    CHECK_EQ_INT(read_file_state(dst, &alias_after), 0);
    CHECK(file_state_matches(&before, &source_after));
    CHECK(file_state_matches(&before, &alias_after));
}

TEST(symlink_alias_is_rejected_without_mutation) {
    char root[] = "/tmp/gs_copy_symlink_XXXXXX";
    char src[512];
    char dst[512];
    char target[512];
    struct stat link_state;
    file_state_t before;
    file_state_t after;
    ssize_t target_length;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(src, sizeof(src), "%s/source", root) < sizeof(src));
    CHECK((size_t)snprintf(dst, sizeof(dst), "%s/alias", root) < sizeof(dst));
    CHECK_EQ_INT(write_text_mode(src, "symlink-source", 0604), 0);
    CHECK_EQ_INT(symlink("source", dst), 0);
    CHECK_EQ_INT(read_file_state(src, &before), 0);

    CHECK_EQ_INT(copy_file(src, dst), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(lstat(dst, &link_state), 0);
    CHECK(S_ISLNK(link_state.st_mode));
    target[0] = '\0';
    target_length = readlink(dst, target, sizeof(target) - 1);
    CHECK(target_length >= 0);
    if (target_length >= 0) target[target_length] = '\0';
    CHECK_STR_EQ(target, "source");
    CHECK_EQ_INT(read_file_state(src, &after), 0);
    CHECK(file_state_matches(&before, &after));
}

TEST(distinct_existing_destination_is_replaced_in_place) {
    char root[] = "/tmp/gs_copy_distinct_XXXXXX";
    char src[512];
    char dst[512];
    file_state_t source_before;
    file_state_t source_after;
    file_state_t destination_before;
    file_state_t destination_after;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(src, sizeof(src), "%s/source", root) < sizeof(src));
    CHECK((size_t)snprintf(dst, sizeof(dst), "%s/destination", root) <
          sizeof(dst));
    CHECK_EQ_INT(write_text_mode(src, "new-body", 0640), 0);
    CHECK_EQ_INT(write_text_mode(dst, "old-destination-body", 0666), 0);
    CHECK_EQ_INT(read_file_state(src, &source_before), 0);
    CHECK_EQ_INT(read_file_state(dst, &destination_before), 0);

    CHECK_EQ_INT(copy_file(src, dst), 0);
    CHECK_EQ_INT(read_file_state(src, &source_after), 0);
    CHECK_EQ_INT(read_file_state(dst, &destination_after), 0);
    CHECK(file_state_matches(&source_before, &source_after));
    CHECK_STR_EQ(destination_after.content, source_before.content);
    CHECK_EQ_INT(destination_after.mode, source_before.mode);
    CHECK_EQ_INT(destination_after.dev, destination_before.dev);
    CHECK_EQ_INT(destination_after.ino, destination_before.ino);
}

TEST(empty_backup_suffix_is_rejected_without_mutation) {
    char root[] = "/tmp/gs_copy_backup_empty_XXXXXX";
    char path[512];
    file_state_t before;
    file_state_t after;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/file", root) <
          sizeof(path));
    CHECK_EQ_INT(write_text_mode(path, "backup-source", 0600), 0);
    CHECK_EQ_INT(read_file_state(path, &before), 0);

    CHECK_EQ_INT(backup_file(path, ""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(read_file_state(path, &after), 0);
    CHECK(file_state_matches(&before, &after));
}

TEST(destination_replaced_with_alias_before_open_is_rejected) {
    char root[] = "/tmp/gs_copy_preopen_replace_XXXXXX";
    char src[512];
    char dst[512];
    char displaced[512];
    file_state_t source_before;
    file_state_t source_after;
    file_state_t displaced_before;
    file_state_t displaced_after;
    file_state_t alias_after;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(src, sizeof(src), "%s/source", root) < sizeof(src));
    CHECK((size_t)snprintf(dst, sizeof(dst), "%s/destination", root) <
          sizeof(dst));
    CHECK((size_t)snprintf(displaced, sizeof(displaced), "%s/displaced", root) <
          sizeof(displaced));
    CHECK_EQ_INT(write_text_mode(src, "source-before-race", 0640), 0);
    CHECK_EQ_INT(write_text_mode(dst, "destination-before-race", 0604), 0);
    CHECK_EQ_INT(read_file_state(src, &source_before), 0);
    CHECK_EQ_INT(read_file_state(dst, &displaced_before), 0);

    g_replacement_source = src;
    g_replacement_displaced = displaced;
    g_replacement_hook_calls = 0;
    g_replacement_hook_error = 0;
    (void)gitswitch_test_set_copy_file_hook(replace_destination_before_open);
    CHECK_EQ_INT(copy_file(src, dst), -1);
    (void)gitswitch_test_set_copy_file_hook(NULL);
    g_replacement_source = NULL;
    g_replacement_displaced = NULL;

    CHECK_EQ_INT(g_replacement_hook_calls, 1);
    CHECK_EQ_INT(g_replacement_hook_error, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(read_file_state(src, &source_after), 0);
    CHECK_EQ_INT(read_file_state(dst, &alias_after), 0);
    CHECK_EQ_INT(read_file_state(displaced, &displaced_after), 0);
    CHECK(file_state_matches(&source_before, &source_after));
    CHECK(file_state_matches(&source_before, &alias_after));
    CHECK(file_state_matches(&displaced_before, &displaced_after));
}

TEST(read_file_accepts_seven_bytes_in_eight_byte_buffer) {
    char root[] = "/tmp/gs_read_fit_XXXXXX";
    char path[512];
    char content[8];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/file", root) <
          sizeof(path));
    CHECK_EQ_INT(write_text_mode(path, "1234567", 0600), 0);

    CHECK_EQ_INT(read_file_to_string(path, content, sizeof(content)), 7);
    CHECK_STR_EQ(content, "1234567");
    CHECK_EQ_INT(content[7], '\0');
}

TEST(read_file_rejects_eight_bytes_in_eight_byte_buffer) {
    char root[] = "/tmp/gs_read_large_XXXXXX";
    char path[512];
    char content[8];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/file", root) <
          sizeof(path));
    CHECK_EQ_INT(write_text_mode(path, "12345678", 0600), 0);

    clear_error();
    CHECK_EQ_INT(read_file_to_string(path, content, sizeof(content)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, 0);
}

static void exercise_read_error(int fault_stage) {
    char root[] = "/tmp/gs_read_error_XXXXXX";
    char path[512];
    char content[8] = "stale";

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/file", root) <
          sizeof(path));
    CHECK_EQ_INT(write_text_mode(path, "1234567", 0600), 0);

    g_read_fault_stage = fault_stage;
    g_read_hook_calls = 0;
    g_read_hook_error = 0;
    (void)gitswitch_test_set_read_file_hook(
        replace_read_descriptor_with_write_only);
    clear_error();
    CHECK_EQ_INT(read_file_to_string(path, content, sizeof(content)), -1);
    (void)gitswitch_test_set_read_file_hook(NULL);
    g_read_fault_stage = 0;

    CHECK_EQ_INT(g_read_hook_calls, 1);
    CHECK_EQ_INT(g_read_hook_error, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, EBADF);
}

TEST(read_file_reports_injected_initial_read_error) {
    exercise_read_error(READ_FILE_TEST_BEFORE_INITIAL_READ);
}

TEST(read_file_reports_injected_exact_fit_probe_error) {
    exercise_read_error(READ_FILE_TEST_BEFORE_EXACT_FIT_PROBE);
}

int main(void) {
    if (error_init(LOG_LEVEL_ERROR, NULL) != 0) return 1;

    RUN_TEST(absent_destination_is_born_private_before_any_bytes);
    RUN_TEST(permissive_existing_destination_is_secured_before_first_payload);
    RUN_TEST(literal_same_path_is_rejected_without_mutation);
    RUN_TEST(hardlink_alias_is_rejected_without_mutation);
    RUN_TEST(symlink_alias_is_rejected_without_mutation);
    RUN_TEST(distinct_existing_destination_is_replaced_in_place);
    RUN_TEST(empty_backup_suffix_is_rejected_without_mutation);
    RUN_TEST(destination_replaced_with_alias_before_open_is_rejected);
    RUN_TEST(read_file_accepts_seven_bytes_in_eight_byte_buffer);
    RUN_TEST(read_file_rejects_eight_bytes_in_eight_byte_buffer);
    RUN_TEST(read_file_reports_injected_initial_read_error);
    RUN_TEST(read_file_reports_injected_exact_fit_probe_error);

    (void)gitswitch_test_set_read_file_hook(NULL);
    error_cleanup();
    return ts_test_finish();
}
