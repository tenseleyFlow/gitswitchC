/* AR-08 M3: the login-shell hint probe must reject namespace replacement
 * races without ever blocking on an attacker-controlled special file. */
#include "test.h"

#include "config.h"
#include "error.h"
#include "scratch_registry_test.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef void (*resume_hint_test_hook_fn)(int stage);
resume_hint_test_hook_fn gitswitch_test_set_resume_hint_hook(
    resume_hint_test_hook_fn hook);

enum {
    HINT_TEST_BEFORE_OPEN = 1,
    HINT_TEST_BEFORE_FINAL_REVALIDATE,
    HINT_TEST_BEFORE_SNAPSHOT_OPEN,
    HINT_TEST_BEFORE_SNAPSHOT_FINAL_REVALIDATE,
    HINT_TEST_BEFORE_RESTORE_RENAME
};

enum {
    INJECT_REPLACE_FIFO = 1,
    INJECT_REPLACE_REGULAR,
    INJECT_GROW_ACTIVE,
    INJECT_GROW_SNAPSHOT,
    INJECT_REWRITE_SAME_SIZE,
    INJECT_PAUSE_RESTORE
};

static char g_root[PATH_MAX];
static char g_home[PATH_MAX];
static char g_hint[PATH_MAX];
static char g_saved[PATH_MAX];
static int g_inject_stage;
static int g_inject_action;
static int g_hook_error;
static int g_pause_ready_fd = -1;
static int g_pause_resume_fd = -1;
static int g_io_rewrite_error;
static int g_rollback_dirsync_faults;

static int append_bytes(const char *path, size_t length) {
    char bytes[512];
    size_t total = 0;
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);

    if (fd < 0) return -1;
    memset(bytes, 'x', sizeof(bytes));
    while (total < length) {
        size_t remaining = length - total;
        size_t chunk = remaining < sizeof(bytes) ? remaining : sizeof(bytes);
        ssize_t written = write(fd, bytes, chunk);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    return close(fd);
}

static int write_private(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, text + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (fchmod(fd, 0600) != 0) { close(fd); return -1; }
    return close(fd);
}

static size_t read_private(const char *path, char *text, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;

    if (fd < 0 || size == 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    while (total + 1 < size) {
        ssize_t count = read(fd, text + total, size - total - 1);
        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    text[total] = '\0';
    return total;
}

static size_t count_hint_temps(const char *prefix) {
    char directory[PATH_MAX];
    DIR *stream;
    struct dirent *entry;
    size_t count = 0;

    if ((size_t)snprintf(directory, sizeof(directory),
                         "%s/.config/gitswitch", g_home) >=
        sizeof(directory)) {
        return SIZE_MAX;
    }
    stream = opendir(directory);
    if (!stream) return SIZE_MAX;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) count++;
    }
    closedir(stream);
    return count;
}

static int rewrite_same_inode_and_size(const char *path,
                                       const char *replacement) {
    const struct timespec forced_times[2] = {{1, 0}, {1, 0}};
    struct stat before;
    struct stat after;
    size_t replacement_length;
    size_t total = 0;
    int fd;
    int result = 0;

    if (!replacement) return -1;
    replacement_length = strlen(replacement);
    if (lstat(path, &before) != 0 ||
        before.st_size != (off_t)replacement_length) {
        return -1;
    }
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    while (total < replacement_length) {
        ssize_t written = write(fd, replacement + total,
                                replacement_length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (futimens(fd, forced_times) != 0) result = -1;
    if (fsync(fd) != 0) result = -1;
    if (close(fd) != 0) result = -1;
    if (result != 0) return -1;
    if (lstat(path, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        after.st_mtime != forced_times[1].tv_sec) {
        return -1;
    }
    return 0;
}

static int transfer_byte(int fd, bool write_byte) {
    unsigned char byte = 1;

    for (;;) {
        ssize_t result = write_byte ? write(fd, &byte, 1) : read(fd, &byte, 1);
        if (result == 1) return 0;
        if (result < 0 && errno == EINTR) continue;
        return -1;
    }
}

static bool rewrite_state_during_directory_sync(
    config_io_boundary_t boundary) {
    if (boundary != CONFIG_IO_STATE_BEFORE_DIR_SYNC) return false;
    if (rewrite_same_inode_and_size(g_hint,
                                    "none\nactive=later\n") != 0) {
        g_io_rewrite_error = errno ? errno : EIO;
    }
    return false;
}

static bool fail_rollback_after_directory_sync(
    config_io_boundary_t boundary) {
    if (boundary != CONFIG_IO_STATE_ROLLBACK_AFTER_DIR_SYNC) return false;
    g_rollback_dirsync_faults++;
    return true;
}

static void replace_hint_at_checkpoint(int stage) {
    if (stage != g_inject_stage) return;
    g_inject_stage = 0;

    if (g_inject_action == INJECT_REPLACE_FIFO) {
        if (unlink(g_hint) != 0 || mkfifo(g_hint, 0600) != 0) {
            g_hook_error = errno ? errno : EIO;
        }
        return;
    }

    if (g_inject_action == INJECT_REPLACE_REGULAR) {
        if (rename(g_hint, g_saved) != 0 ||
            write_private(g_hint, "ssh\nactive=replacement\n") != 0) {
            g_hook_error = errno ? errno : EIO;
        }
        return;
    }

    if (g_inject_action == INJECT_REWRITE_SAME_SIZE) {
        if (rewrite_same_inode_and_size(g_hint,
                                        "gpg\nactive=next\n") != 0) {
            g_hook_error = errno ? errno : EIO;
        }
        return;
    }

    if (g_inject_action == INJECT_PAUSE_RESTORE) {
        if (transfer_byte(g_pause_ready_fd, true) != 0 ||
            transfer_byte(g_pause_resume_fd, false) != 0) {
            g_hook_error = errno ? errno : EIO;
        }
        return;
    }

    if (append_bytes(g_hint,
                     g_inject_action == INJECT_GROW_ACTIVE ? 2048U : 8192U) !=
        0) {
        g_hook_error = errno ? errno : EIO;
    }
}

static int wait_bounded(pid_t child, long timeout_ms) {
    struct timespec start;
    struct timespec now;
    struct timespec pause = {0, 10000000L};
    int status = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return -1;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) return -1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
        long elapsed = (now.tv_sec - start.tv_sec) * 1000L +
                       (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed >= timeout_ms) {
            (void)kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            return -2;
        }
        (void)nanosleep(&pause, NULL);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_reader_at_checkpoint(int stage, int action, bool snapshot) {
    pid_t child;

    unlink(g_hint);
    unlink(g_saved);
    if (write_private(g_hint, "ssh\nactive=work\n") != 0) return -1;

    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        char needs[8] = "dirty";
        int rc;

        g_inject_stage = stage;
        g_inject_action = action;
        g_hook_error = 0;
        (void)gitswitch_test_set_resume_hint_hook(
            replace_hint_at_checkpoint);
        if (snapshot) {
            config_resume_hint_snapshot_t saved = {0};
            rc = config_resume_hint_snapshot_capture(&saved);
            config_resume_hint_snapshot_clear(&saved);
            needs[0] = '\0';
        } else {
            rc = config_resume_hint_probe(needs, sizeof(needs));
        }
        if (g_hook_error != 0) _exit(20);
        if (rc == 0) _exit(21);
        if (needs[0] != '\0') _exit(22);
        _exit(0);
    }
    return wait_bounded(child, 1500L);
}

static int fixture_setup(void) {
    char config[PATH_MAX];

    if ((size_t)snprintf(g_root, sizeof(g_root),
                         "/tmp/gitswitch-ar08-hint.XXXXXX") >=
            sizeof(g_root) || !ts_mkdtemp(g_root) ||
        (size_t)snprintf(g_home, sizeof(g_home), "%s/home", g_root) >=
            sizeof(g_home) || mkdir(g_home, 0700) != 0 ||
        (size_t)snprintf(config, sizeof(config), "%s/.config", g_home) >=
            sizeof(config) || mkdir(config, 0700) != 0 ||
        (size_t)snprintf(config, sizeof(config), "%s/.config/gitswitch",
                         g_home) >= sizeof(config) || mkdir(config, 0700) != 0 ||
        (size_t)snprintf(g_hint, sizeof(g_hint), "%s/.resume-hint", config) >=
            sizeof(g_hint) ||
        (size_t)snprintf(g_saved, sizeof(g_saved), "%s/.resume-hint.saved",
                         config) >= sizeof(g_saved) ||
        setenv("HOME", g_home, 1) != 0) {
        return -1;
    }
    return 0;
}

TEST(fifo_replacement_before_open_is_rejected_without_blocking) {
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_OPEN,
                                          INJECT_REPLACE_FIFO, false), 0);
}

TEST(regular_replacement_after_read_is_rejected) {
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_FINAL_REVALIDATE,
                                          INJECT_REPLACE_REGULAR, false), 0);
}

TEST(same_inode_growth_before_open_is_bounded) {
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_OPEN,
                                          INJECT_GROW_ACTIVE, false), 0);
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_SNAPSHOT_OPEN,
                                          INJECT_GROW_SNAPSHOT, true), 0);
}

TEST(same_inode_same_size_rewrites_are_rejected) {
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_OPEN,
                                          INJECT_REWRITE_SAME_SIZE, false), 0);
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_FINAL_REVALIDATE,
                                          INJECT_REWRITE_SAME_SIZE, false), 0);
    CHECK_EQ_INT(run_reader_at_checkpoint(HINT_TEST_BEFORE_SNAPSHOT_OPEN,
                                          INJECT_REWRITE_SAME_SIZE, true), 0);
    CHECK_EQ_INT(run_reader_at_checkpoint(
                     HINT_TEST_BEFORE_SNAPSHOT_FINAL_REVALIDATE,
                     INJECT_REWRITE_SAME_SIZE, true), 0);
}

TEST(testing_object_retains_legacy_fault_seam_before_installation) {
    char config_path[PATH_MAX];
    char text[64];
    gitswitch_ctx_t ctx;
    bool installed = true;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    (void)unlink(g_hint);
    CHECK_EQ_INT(write_private(config_path,
                               "[settings]\ndefault_scope=\"local\"\n"), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    clear_error();
    CHECK_EQ_INT(setenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT", "1", 1), 0);
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, config_path, &installed), -1);
    CHECK_EQ_INT(unsetenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT"), 0);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "Injected resume-hint commit failure") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
}

TEST(unbound_snapshot_cannot_overwrite_a_later_state) {
    config_resume_hint_snapshot_t saved = {0};
    char text[64];

    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\nactive=later\n"), 0);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    CHECK(strstr(get_last_error()->message, "bound snapshot") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=later\n");
    config_resume_hint_snapshot_clear(&saved);
}

TEST(guarded_snapshot_restores_unchanged_post_image_exactly) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    struct stat restored;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    CHECK_EQ_INT(chmod(g_hint, 0640), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(g_hint, &restored), 0);
    CHECK_EQ_INT(restored.st_mode & 0777, 0640);
    config_resume_hint_snapshot_clear(&saved);
}

TEST(guarded_snapshot_accepts_ctime_only_materialization) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);

    /* Model FreeBSD UFS reporting the installed inode's finalized ctime only
     * after the first seal. The exact post-image bytes still authorize the
     * rollback; the adjacent different-byte rewrite test remains fail-closed. */
#ifdef __APPLE__
    saved.post_image.st_ctimespec.tv_nsec ^= 1L;
#else
    saved.post_image.st_ctim.tv_nsec ^= 1L;
#endif
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    config_resume_hint_snapshot_clear(&saved);
}

TEST(guarded_snapshot_rejects_changed_bytes_under_ctime_only_drift) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    struct stat rewritten;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);
    CHECK_EQ_INT(rewrite_same_inode_and_size(g_hint,
                                             "none\nactive=later\n"), 0);
    CHECK_EQ_INT(lstat(g_hint, &rewritten), 0);

    /* Force the metadata predicate down its ctime-only branch. The installed
     * byte witness still describes alice, so the stable read of later must
     * reject rollback rather than laundering the rewrite into ownership. */
    saved.post_image = rewritten;
#ifdef __APPLE__
    saved.post_image.st_ctimespec.tv_nsec ^= 1L;
#else
    saved.post_image.st_ctim.tv_nsec ^= 1L;
#endif
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    CHECK(strstr(get_last_error()->message, "neither") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=later\n");
    config_resume_hint_snapshot_clear(&saved);
}

TEST(snapshot_restore_registration_failure_preserves_post_image_and_retries) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    char scratch[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE];
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    struct stat restored;
    gitswitch_ctx_t ctx;
    size_t registered;
    bool installed = false;
    int before;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    CHECK_EQ_INT(chmod(g_hint, 0640), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);

    before = test_open_fd_count();
    registered = test_scratch_fill(scratch, "restore-full");
    CHECK(registered > 0 && registered < TEST_SCRATCH_PROBE_MAX);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    CHECK(strstr(get_last_error()->message, "register") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);

    test_scratch_release(scratch, registered);
    CHECK_EQ_INT(test_open_fd_count(), before);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(g_hint, &restored), 0);
    CHECK_EQ_INT(restored.st_mode & 0777, 0640);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);
    config_resume_hint_snapshot_clear(&saved);
}

TEST(durable_present_before_image_restore_retry_is_idempotent) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    struct stat restored;
    gitswitch_ctx_t ctx;
    bool installed = false;
    int first_errno;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    CHECK_EQ_INT(chmod(g_hint, 0640), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);

    g_rollback_dirsync_faults = 0;
    (void)config_set_io_fault_fn(fail_rollback_after_directory_sync);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    first_errno = errno;
    (void)config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(first_errno, EIO);
    CHECK_EQ_INT(g_rollback_dirsync_faults, 1);
    CHECK(strstr(get_last_error()->message,
                 "Injected config persistence failure") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(g_hint, &restored), 0);
    CHECK_EQ_INT(restored.st_mode & 0777, 0640);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);

    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(g_hint, &restored), 0);
    CHECK_EQ_INT(restored.st_mode & 0777, 0640);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);

    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(g_hint, &restored), 0);
    CHECK_EQ_INT(restored.st_mode & 0777, 0640);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);
    config_resume_hint_snapshot_clear(&saved);
}

TEST(durable_absent_before_image_restore_retry_is_idempotent) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    struct stat state;
    gitswitch_ctx_t ctx;
    bool installed = false;
    int first_errno;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(unlink(g_hint), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);

    g_rollback_dirsync_faults = 0;
    (void)config_set_io_fault_fn(fail_rollback_after_directory_sync);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    first_errno = errno;
    (void)config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(first_errno, EIO);
    CHECK_EQ_INT(g_rollback_dirsync_faults, 1);
    CHECK(strstr(get_last_error()->message,
                 "Injected config persistence failure") != NULL);
    errno = 0;
    CHECK_EQ_INT(lstat(g_hint, &state), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);

    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    errno = 0;
    CHECK_EQ_INT(lstat(g_hint, &state), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);

    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    errno = 0;
    CHECK_EQ_INT(lstat(g_hint, &state), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);
    config_resume_hint_snapshot_clear(&saved);
}

TEST(equivalent_post_image_replacement_is_not_a_completed_restore) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);

    CHECK_EQ_INT(write_private(g_saved, "none\nactive=alice\n"), 0);
    CHECK_EQ_INT(rename(g_saved, g_hint), 0);
    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 "post-image still durable") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(count_hint_temps(".resume-hint.restore."), 0);
    config_resume_hint_snapshot_clear(&saved);
}

TEST(guarded_save_does_not_adopt_an_in_place_rewrite) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);

    g_io_rewrite_error = 0;
    config_set_io_fault_fn(rewrite_state_during_directory_sync);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), -1);
    config_set_io_fault_fn(NULL);
    CHECK(installed);
    CHECK_EQ_INT(g_io_rewrite_error, 0);
    CHECK(strstr(get_last_error()->message,
                 "changed during durability commit") != NULL);

    clear_error();
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), -1);
    CHECK(strstr(get_last_error()->message, "neither") != NULL);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=later\n");
    config_resume_hint_snapshot_clear(&saved);
}

TEST(public_restore_serializes_its_final_compare_and_rename) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n"
        "[accounts.2]\n"
        "name=\"bob\"\n"
        "email=\"bob@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    int ready[2] = {-1, -1};
    int resume[2] = {-1, -1};
    int child_status;
    pid_t child;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(installed);
    if (pipe(ready) != 0) {
        CHECK_EQ_INT(-1, 0);
        config_resume_hint_snapshot_clear(&saved);
        return;
    }
    if (pipe(resume) != 0) {
        CHECK_EQ_INT(-1, 0);
        close(ready[0]);
        close(ready[1]);
        config_resume_hint_snapshot_clear(&saved);
        return;
    }

    child = fork();
    if (child < 0) {
        CHECK(child >= 0);
        close(ready[0]);
        close(ready[1]);
        close(resume[0]);
        close(resume[1]);
        config_resume_hint_snapshot_clear(&saved);
        return;
    }
    if (child == 0) {
        int save_result;
        int save_errno;

        close(ready[1]);
        close(resume[0]);
        if (transfer_byte(ready[0], false) != 0) _exit(30);
        snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
                 "%s", "bob");
        clear_error();
        save_result = config_save_active_account(&ctx, config_path);
        save_errno = errno;
        if (transfer_byte(resume[1], true) != 0) _exit(31);
        close(ready[0]);
        close(resume[1]);
        if (save_result != -1) _exit(32);
        if (save_errno != EWOULDBLOCK
#if EAGAIN != EWOULDBLOCK
            && save_errno != EAGAIN
#endif
        ) {
            _exit(33);
        }
        _exit(0);
    }

    close(ready[0]);
    close(resume[1]);
    g_pause_ready_fd = ready[1];
    g_pause_resume_fd = resume[0];
    g_inject_stage = HINT_TEST_BEFORE_RESTORE_RENAME;
    g_inject_action = INJECT_PAUSE_RESTORE;
    g_hook_error = 0;
    (void)gitswitch_test_set_resume_hint_hook(replace_hint_at_checkpoint);
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    (void)gitswitch_test_set_resume_hint_hook(NULL);
    close(ready[1]);
    close(resume[0]);
    g_pause_ready_fd = -1;
    g_pause_resume_fd = -1;
    child_status = wait_bounded(child, 1500L);
    CHECK_EQ_INT(g_hook_error, 0);
    CHECK_EQ_INT(child_status, 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    config_resume_hint_snapshot_clear(&saved);
}

TEST(guarded_noop_save_does_not_claim_a_state_generation) {
    static const char config_body[] =
        "[settings]\n"
        "default_scope=\"local\"\n"
        "[accounts.1]\n"
        "name=\"alice\"\n"
        "email=\"alice@example.com\"\n";
    config_resume_hint_snapshot_t saved = {0};
    char config_path[PATH_MAX];
    char text[64];
    gitswitch_ctx_t ctx;
    bool installed = true;

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/.config/gitswitch/accounts.toml", g_home) <
          sizeof(config_path));
    CHECK_EQ_INT(write_private(config_path, config_body), 0);
    CHECK_EQ_INT(write_private(g_hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&saved), 0);
    CHECK_EQ_INT(config_save_active_account_transactional_guarded(
                     &ctx, config_path, &installed, &saved), 0);
    CHECK(!installed);

    CHECK_EQ_INT(write_private(g_hint, "none\nactive=later\n"), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&saved), 0);
    CHECK(read_private(g_hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=later\n");
    config_resume_hint_snapshot_clear(&saved);
}

int main(void) {
    if (error_init(LOG_LEVEL_ERROR, NULL) != 0 || fixture_setup() != 0) {
        fprintf(stderr, "test_ar08_resume_hint_race: fixture setup failed\n");
        return 1;
    }

    RUN_TEST(fifo_replacement_before_open_is_rejected_without_blocking);
    RUN_TEST(regular_replacement_after_read_is_rejected);
    RUN_TEST(same_inode_growth_before_open_is_bounded);
    RUN_TEST(same_inode_same_size_rewrites_are_rejected);
    RUN_TEST(testing_object_retains_legacy_fault_seam_before_installation);
    RUN_TEST(unbound_snapshot_cannot_overwrite_a_later_state);
    RUN_TEST(guarded_snapshot_restores_unchanged_post_image_exactly);
    RUN_TEST(guarded_snapshot_accepts_ctime_only_materialization);
    RUN_TEST(guarded_snapshot_rejects_changed_bytes_under_ctime_only_drift);
    RUN_TEST(snapshot_restore_registration_failure_preserves_post_image_and_retries);
    RUN_TEST(durable_present_before_image_restore_retry_is_idempotent);
    RUN_TEST(durable_absent_before_image_restore_retry_is_idempotent);
    RUN_TEST(equivalent_post_image_replacement_is_not_a_completed_restore);
    RUN_TEST(guarded_save_does_not_adopt_an_in_place_rewrite);
    RUN_TEST(public_restore_serializes_its_final_compare_and_rename);
    RUN_TEST(guarded_noop_save_does_not_claim_a_state_generation);

    ts_rm_rf(g_root);
    error_cleanup();
    return ts_test_finish();
}
