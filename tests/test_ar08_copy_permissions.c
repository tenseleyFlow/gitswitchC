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

enum {
    COPY_FILE_TEST_AFTER_DESTINATION_OPEN = 1,
    COPY_FILE_TEST_AFTER_FIRST_WRITE
};

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

int main(void) {
    if (error_init(LOG_LEVEL_ERROR, NULL) != 0) return 1;

    RUN_TEST(absent_destination_is_born_private_before_any_bytes);
    RUN_TEST(permissive_existing_destination_is_secured_before_first_payload);

    error_cleanup();
    return ts_test_finish();
}
