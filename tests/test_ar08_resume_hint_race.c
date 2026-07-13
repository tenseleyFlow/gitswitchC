/* AR-08 M3: the login-shell hint probe must reject namespace replacement
 * races without ever blocking on an attacker-controlled special file. */
#include "test.h"

#include "config.h"
#include "error.h"

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
    HINT_TEST_BEFORE_SNAPSHOT_OPEN
};

enum {
    INJECT_REPLACE_FIFO = 1,
    INJECT_REPLACE_REGULAR,
    INJECT_GROW_ACTIVE,
    INJECT_GROW_SNAPSHOT
};

static char g_root[PATH_MAX];
static char g_home[PATH_MAX];
static char g_hint[PATH_MAX];
static char g_saved[PATH_MAX];
static int g_inject_stage;
static int g_inject_action;
static int g_hook_error;

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

int main(void) {
    if (error_init(LOG_LEVEL_ERROR, NULL) != 0 || fixture_setup() != 0) {
        fprintf(stderr, "test_ar08_resume_hint_race: fixture setup failed\n");
        return 1;
    }

    RUN_TEST(fifo_replacement_before_open_is_rejected_without_blocking);
    RUN_TEST(regular_replacement_after_read_is_rejected);
    RUN_TEST(same_inode_growth_before_open_is_bounded);

    ts_rm_rf(g_root);
    error_cleanup();
    printf("\n%s: %d run, %d failed\n",
           ts_tests_failed ? "RESULT FAIL" : "RESULT OK",
           ts_tests_run, ts_tests_failed);
    return ts_tests_failed ? 1 : 0;
}
