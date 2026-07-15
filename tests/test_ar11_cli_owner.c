/* AR-11 M4: real renamed-CLI coverage for abort-only preparation ownership.
 * A context referenced by process-global rollback state must either be
 * settled in the current entry or retained until the next entry can settle it
 * under the exact configuration lock. */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "signals.h"
#include "utils.h"

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

typedef void (*switch_abort_test_hook_fn)(gitswitch_ctx_t *ctx);
typedef void (*switch_prepare_failure_test_hook_fn)(void);

int gitswitch_cli_main(int argc, char **argv);
switch_abort_test_hook_fn gitswitch_test_set_switch_abort_hook(
    switch_abort_test_hook_fn hook);
switch_prepare_failure_test_hook_fn
gitswitch_test_set_switch_prepare_failure_hook(
    switch_prepare_failure_test_hook_fn hook);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char config_dir[PATH_MAX];
    char config[PATH_MAX];
    char hint[PATH_MAX];
    char gitconfig[PATH_MAX];
    char ssh_config[PATH_MAX];
    char output[PATH_MAX];
} cli_owner_fixture_t;

typedef struct {
    pid_t pid;
    int release_fd;
} runtime_holder_t;

static runtime_holder_t g_runtime_holder = { -1, -1 };
static bool g_hook_should_hold_runtime;
static int g_hook_called;
static int g_hook_commit_rc;
static int g_hook_holder_rc;
static int g_hook_prepare_errno;
static error_context_t g_hook_prepare_error;
static char g_hook_commit_error[512];

static const int guarded_signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };
static const char expected_accounts_config[] =
    "[settings]\n"
    "default_scope = \"global\"\n"
    "\n"
    "[accounts.1]\n"
    "name = \"work\"\n"
    "email = \"work@example.test\"\n"
    "description = \"retained owner fixture\"\n"
    "preferred_scope = \"global\"\n";
static const char expected_gitconfig[] =
    "[user]\n"
    "\tname = Before Name\n"
    "\temail = before@example.test\n";

static int write_private(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, text + total, length - total);

        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
    return close(fd);
}

static size_t read_text(const char *path, char *text, size_t size) {
    int fd;
    size_t total = 0;

    if (!text || size == 0) return 0;
    text[0] = '\0';
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
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

static int fixture_setup(cli_owner_fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    if ((size_t)snprintf(fixture->root, sizeof(fixture->root),
                         "/tmp/gitswitch-ar11-cli-owner.XXXXXX") >=
            sizeof(fixture->root) ||
        !ts_mkdtemp(fixture->root) ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0) {
        return -1;
    }
    if ((size_t)snprintf(fixture->home, sizeof(fixture->home), "%s/home",
                         fixture->root) >= sizeof(fixture->home) ||
        mkdir(fixture->home, 0700) != 0 ||
        (size_t)snprintf(fixture->runtime, sizeof(fixture->runtime),
                         "%s/runtime", fixture->root) >=
            sizeof(fixture->runtime) ||
        mkdir(fixture->runtime, 0700) != 0 ||
        (size_t)snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                         "%s/.config", fixture->home) >=
            sizeof(fixture->config_dir) ||
        mkdir(fixture->config_dir, 0700) != 0 ||
        (size_t)snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                         "%s/.config/gitswitch", fixture->home) >=
            sizeof(fixture->config_dir) ||
        mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(fixture->config, sizeof(fixture->config),
                         "%s/accounts.toml", fixture->config_dir) >=
            sizeof(fixture->config) ||
        (size_t)snprintf(fixture->hint, sizeof(fixture->hint),
                         "%s/.resume-hint", fixture->config_dir) >=
            sizeof(fixture->hint) ||
        (size_t)snprintf(fixture->gitconfig, sizeof(fixture->gitconfig),
                         "%s/.gitconfig", fixture->home) >=
            sizeof(fixture->gitconfig) ||
        (size_t)snprintf(fixture->ssh_config, sizeof(fixture->ssh_config),
                         "%s/.ssh/config", fixture->home) >=
            sizeof(fixture->ssh_config) ||
        (size_t)snprintf(fixture->output, sizeof(fixture->output),
                         "%s/output", fixture->root) >=
            sizeof(fixture->output)) {
        return -1;
    }
    return write_private(fixture->config, expected_accounts_config) == 0 &&
                   write_private(fixture->hint,
                                 "none\ninactive=v1\n") == 0 &&
                   write_private(fixture->gitconfig,
                                 expected_gitconfig) == 0
               ? 0
               : -1;
}

static int redirect_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (fd > STDERR_FILENO) close(fd);
    return 0;
}

static int start_runtime_holder(runtime_holder_t *holder) {
    int ready[2] = { -1, -1 };
    int release[2] = { -1, -1 };
    pid_t child;
    char marker = '\0';
    ssize_t count;

    if (!holder || pipe(ready) != 0 || pipe(release) != 0) {
        int saved_errno = errno;
        if (ready[0] >= 0) close(ready[0]);
        if (ready[1] >= 0) close(ready[1]);
        if (release[0] >= 0) close(release[0]);
        if (release[1] >= 0) close(release[1]);
        errno = saved_errno;
        return -1;
    }
    child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        errno = saved_errno;
        return -1;
    }
    if (child == 0) {
        int lock_fd;

        close(ready[0]);
        close(release[1]);
        lock_fd = runtime_state_lock_acquire();
        marker = lock_fd >= 0 ? 'R' : 'E';
        do {
            count = write(ready[1], &marker, 1);
        } while (count < 0 && errno == EINTR);
        close(ready[1]);
        if (lock_fd < 0 || count != 1) _exit(1);
        do {
            count = read(release[0], &marker, 1);
        } while (count < 0 && errno == EINTR);
        close(release[0]);
        runtime_state_lock_release(lock_fd);
        _exit(count == 1 ? 0 : 2);
    }

    close(ready[1]);
    close(release[0]);
    do {
        count = read(ready[0], &marker, 1);
    } while (count < 0 && errno == EINTR);
    close(ready[0]);
    if (count != 1 || marker != 'R') {
        int status = 0;

        close(release[1]);
        (void)waitpid(child, &status, 0);
        return -1;
    }
    holder->pid = child;
    holder->release_fd = release[1];
    return 0;
}

static int stop_runtime_holder(runtime_holder_t *holder) {
    char marker = 'X';
    ssize_t count;
    pid_t waited;
    int status = 0;

    if (!holder || holder->pid <= 0 || holder->release_fd < 0) return -1;
    do {
        count = write(holder->release_fd, &marker, 1);
    } while (count < 0 && errno == EINTR);
    close(holder->release_fd);
    holder->release_fd = -1;
    do {
        waited = waitpid(holder->pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    holder->pid = -1;
    return count == 1 && waited > 0 && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0
               ? 0
               : -1;
}

static void fail_guard_restore_retry(void) {
    signals_test_fail_sigaction(SIGINT, SIGNALS_TEST_SIGACTION_RESTORE,
                                EAGAIN);
}

static void inspect_abort_owner(gitswitch_ctx_t *ctx) {
    g_hook_called++;
    g_hook_prepare_errno = errno;
    g_hook_prepare_error = *get_last_error();
    g_hook_commit_rc = accounts_switch_commit(ctx);
    (void)snprintf(g_hook_commit_error, sizeof(g_hook_commit_error), "%s",
                   get_last_error()->message);
    if (g_hook_should_hold_runtime) {
        g_hook_holder_rc = start_runtime_holder(&g_runtime_holder);
    }
}

static void clobber_prepare_failure(void) {
    clear_error();
    errno = EOVERFLOW;
}

static void inherited_handler(int signal_number) {
    (void)signal_number;
}

static bool actions_equal(const struct sigaction *left,
                          const struct sigaction *right) {
    static const int mask_members[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM
    };

    if (left->sa_handler != right->sa_handler ||
        left->sa_flags != right->sa_flags) {
        return false;
    }
    for (size_t i = 0;
         i < sizeof(mask_members) / sizeof(mask_members[0]); i++) {
        if (sigismember(&left->sa_mask, mask_members[i]) !=
            sigismember(&right->sa_mask, mask_members[i])) {
            return false;
        }
    }
    return true;
}

static int config_lock_available(void) {
    int lock_fd = config_write_lock();

    if (lock_fd < 0) return 0;
    config_write_unlock(lock_fd);
    return 1;
}

static int run_cli_owner_case(const cli_owner_fixture_t *fixture,
                              bool persist_first_abort) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        struct sigaction expected[sizeof(guarded_signals) /
                                  sizeof(guarded_signals[0])];
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char version[] = "--version";
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        char *version_argv[] = { program, version, NULL };
        int first_rc;
        int second_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(100);
        }
        for (size_t i = 0;
             i < sizeof(guarded_signals) / sizeof(guarded_signals[0]); i++) {
            struct sigaction action;

            memset(&action, 0, sizeof(action));
            action.sa_handler = inherited_handler;
            sigemptyset(&action.sa_mask);
            sigaddset(&action.sa_mask, i == 0 ? SIGUSR1 : SIGUSR2);
            action.sa_flags = i == 1 ? SA_RESTART : 0;
            if (sigaction(guarded_signals[i], &action, NULL) != 0 ||
                sigaction(guarded_signals[i], NULL, &expected[i]) != 0) {
                _exit(101);
            }
        }

        g_hook_should_hold_runtime = persist_first_abort;
        g_hook_called = 0;
        g_hook_commit_rc = 0;
        g_hook_holder_rc = 0;
        g_hook_prepare_errno = 0;
        memset(&g_hook_prepare_error, 0, sizeof(g_hook_prepare_error));
        g_hook_commit_error[0] = '\0';
        signals_test_fail_sigaction(SIGTERM,
                                    SIGNALS_TEST_SIGACTION_INSTALL, EPERM);
        signals_test_fail_sigaction(SIGINT,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        (void)signals_test_set_guard_end_hook(fail_guard_restore_retry);
        (void)gitswitch_test_set_switch_prepare_failure_hook(
            clobber_prepare_failure);
        (void)gitswitch_test_set_switch_abort_hook(inspect_abort_owner);

        optind = 1;
        first_rc = gitswitch_cli_main(4, switch_argv);
        if (first_rc == 0) _exit(102);
        if (g_hook_called != 1 || g_hook_prepare_errno != EAGAIN ||
            g_hook_prepare_error.code != ERR_SYSTEM_CALL ||
            strstr(g_hook_prepare_error.message,
                   "rollback ownership remains published") == NULL ||
            g_hook_commit_rc != -1 ||
            strstr(g_hook_commit_error, "can only be retried") == NULL) {
            fprintf(stderr,
                    "AR-11 CLI owner hook mismatch: called=%d "
                    "prepare_errno=%d prepare_code=%d prepare_error=%s "
                    "commit_rc=%d commit_error=%s\n",
                    g_hook_called, g_hook_prepare_errno,
                    (int)g_hook_prepare_error.code,
                    g_hook_prepare_error.message[0]
                        ? g_hook_prepare_error.message
                        : "(empty)",
                    g_hook_commit_rc,
                    g_hook_commit_error[0] ? g_hook_commit_error : "(empty)");
            _exit(103);
        }
        if (!config_lock_available()) _exit(104);

        if (!persist_first_abort) {
            if (gitswitch_test_context_allocations() != 0 ||
                gitswitch_test_context_allocation_total() != 1 ||
                signals_guard_active() || signals_rollback_active()) {
                _exit(105);
            }
        } else {
            if (g_hook_holder_rc != 0 ||
                gitswitch_test_context_allocations() != 1 ||
                gitswitch_test_context_allocation_total() != 1 ||
                !signals_guard_active() || signals_rollback_active()) {
                fprintf(stderr,
                        "AR-11 retained-owner mismatch: holder_rc=%d "
                        "allocations=%d total=%d guard=%d rollback=%d\n",
                        g_hook_holder_rc,
                        gitswitch_test_context_allocations(),
                        gitswitch_test_context_allocation_total(),
                        signals_guard_active() ? 1 : 0,
                        signals_rollback_active() ? 1 : 0);
                _exit(106);
            }
            if (stop_runtime_holder(&g_runtime_holder) != 0) _exit(107);

            /* Settlement occurs before option parsing and before a second
             * context allocation. Version then proves ordinary dispatch may
             * continue only after the original owner is gone. */
            optind = 1;
            second_rc = gitswitch_cli_main(2, version_argv);
            if (second_rc != 0 ||
                gitswitch_test_context_allocations() != 0 ||
                gitswitch_test_context_allocation_total() != 1 ||
                signals_guard_active() || signals_rollback_active()) {
                _exit(108);
            }
            if (!config_lock_available()) _exit(109);
        }

        for (size_t i = 0;
             i < sizeof(guarded_signals) / sizeof(guarded_signals[0]); i++) {
            struct sigaction observed;

            if (sigaction(guarded_signals[i], NULL, &observed) != 0 ||
                !actions_equal(&observed, &expected[i])) {
                _exit(110);
            }
        }
        if (fflush(NULL) != 0) _exit(111);
        _exit(0);
    }

    {
        int status = 0;
        pid_t waited;

        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        return waited == child ? status : -1;
    }
}

static bool config_dir_has_temporary(const char *path) {
    DIR *directory = opendir(path);
    struct dirent *entry;
    bool found = false;

    if (!directory) return true;
    while ((entry = readdir(directory)) != NULL) {
        if (strstr(entry->d_name, ".tmp.") != NULL) {
            found = true;
            break;
        }
    }
    closedir(directory);
    return found;
}

static void check_case_artifacts(const cli_owner_fixture_t *fixture,
                                 bool persistent) {
    char config[512];
    char gitconfig[256];
    char hint[128];
    char output[8192];
    int status = run_cli_owner_case(fixture, persistent);

    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture->config, config, sizeof(config)) > 0);
    CHECK_STR_EQ(config, expected_accounts_config);
    CHECK(read_text(fixture->gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, expected_gitconfig);
    CHECK(read_text(fixture->hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\ninactive=v1\n");
    errno = 0;
    CHECK(lstat(fixture->ssh_config, &(struct stat){0}) != 0 &&
          errno == ENOENT);
    CHECK(!config_dir_has_temporary(fixture->config_dir));
    CHECK(read_text(fixture->output, output, sizeof(output)) > 0);
    if (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "AR-11 CLI owner captured output:\n%s\n", output);
    }
    CHECK(strstr(output, "Failed to install guarded disposition") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);
    if (persistent) {
        CHECK(strstr(output, "application context was retained") != NULL);
        CHECK(strstr(output, GITSWITCH_VERSION) != NULL);
    } else {
        CHECK(strstr(output, "application context was retained") == NULL);
    }
}

TEST(one_shot_exact_abort_releases_cli_context) {
    cli_owner_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    check_case_artifacts(&fixture, false);
}

TEST(persistent_runtime_lock_retains_then_settles_before_next_entry) {
    cli_owner_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    check_case_artifacts(&fixture, true);
}

TEST_MAIN_BEGIN()
    RUN_TEST(one_shot_exact_abort_releases_cli_context);
    RUN_TEST(persistent_runtime_lock_retains_then_settles_before_next_entry);
TEST_MAIN_END()
