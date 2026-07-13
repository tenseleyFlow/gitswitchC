/* AR-07 T6: constrained-stack entry, reset atomicity, and canonical identity. */
#include "test.h"
#include "signals.h"

#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

typedef void (*reset_test_hook_fn)(int stage);

int gitswitch_cli_main(int argc, char **argv);
reset_test_hook_fn gitswitch_test_set_reset_hook(reset_test_hook_fn hook);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);

enum {
    RESET_TEST_AFTER_SSH = 1,
    RESET_TEST_AFTER_GPG,
    RESET_TEST_AFTER_ACTIVE_CLEAR,
    RESET_TEST_AFTER_ACTIVE_COMMIT
};

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char config_dir[PATH_MAX];
    char config[PATH_MAX];
    char hint[PATH_MAX];
    char output[PATH_MAX];
} reset_fixture_t;

static int g_inject_stage;
static int g_trace_fd = -1;

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
    return close(fd);
}

static int join_path(char *path, size_t size, const char *base,
                     const char *suffix) {
    size_t base_length = strlen(base);
    size_t suffix_length = strlen(suffix);
    if (base_length + suffix_length + 1 > size) return -1;
    memcpy(path, base, base_length);
    memcpy(path + base_length, suffix, suffix_length + 1);
    return 0;
}

static size_t read_text(const char *path, char *text, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;

    if (fd < 0 || size == 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    while (total + 1 < size) {
        ssize_t n = read(fd, text + total, size - total - 1);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    text[total] = '\0';
    return total;
}

static int fixture_setup(reset_fixture_t *fixture) {
    const char config_body[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "[accounts.1]\n"
        "name = \"Work\"\n"
        "email = \"work@example.com\"\n"
        "description = \"case fixture\"\n";

    memset(fixture, 0, sizeof(*fixture));
    if ((size_t)snprintf(fixture->root, sizeof(fixture->root),
                         "/tmp/gitswitch-ar07-reset.XXXXXX") >=
        sizeof(fixture->root) || !ts_mkdtemp(fixture->root)) {
        return -1;
    }
    if ((size_t)snprintf(fixture->home, sizeof(fixture->home), "%s/home",
                         fixture->root) >= sizeof(fixture->home) ||
        mkdir(fixture->home, 0700) != 0) return -1;
    if ((size_t)snprintf(fixture->runtime, sizeof(fixture->runtime),
                         "%s/runtime", fixture->root) >=
        sizeof(fixture->runtime) || mkdir(fixture->runtime, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                         "%s/.config", fixture->home) >=
        sizeof(fixture->config_dir) || mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                         "%s/.config/gitswitch", fixture->home) >=
        sizeof(fixture->config_dir) || mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(fixture->config, sizeof(fixture->config),
                         "%s/accounts.toml", fixture->config_dir) >=
        sizeof(fixture->config) ||
        (size_t)snprintf(fixture->hint, sizeof(fixture->hint),
                         "%s/.resume-hint", fixture->config_dir) >=
        sizeof(fixture->hint) ||
        (size_t)snprintf(fixture->output, sizeof(fixture->output),
                         "%s/output", fixture->root) >=
        sizeof(fixture->output)) {
        return -1;
    }
    if (write_private(fixture->config, config_body) != 0 ||
        write_private(fixture->hint, "none\nactive=work\n") != 0) {
        return -1;
    }
    return 0;
}

static void install_fixture_environment(const reset_fixture_t *fixture) {
    (void)setenv("HOME", fixture->home, 1);
    (void)setenv("XDG_RUNTIME_DIR", fixture->runtime, 1);
    (void)setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    (void)unsetenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT");
}

static void inject_repeated_signal(int stage) {
    char marker = (char)('0' + stage);
    if (g_trace_fd >= 0) {
        int saved_errno = errno;
        ssize_t written;
        do {
            written = write(g_trace_fd, &marker, 1);
        } while (written < 0 && errno == EINTR);
        (void)written;
        errno = saved_errno;
    }
    if (stage == g_inject_stage) {
        (void)raise(SIGTERM);
        (void)raise(SIGTERM);
    }
}

static int wait_status(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

static int redirect_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
        close(fd);
        return -1;
    }
    if (fd > STDERR_FILENO) close(fd);
    return 0;
}

static int run_reset_child(const reset_fixture_t *fixture,
                           const char *selector, int inject_stage,
                           char *trace, size_t trace_size) {
    int trace_pipe[2];
    pid_t child;
    int status;
    size_t total = 0;

    if (pipe(trace_pipe) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(trace_pipe[0]);
        close(trace_pipe[1]);
        return -1;
    }
    if (child == 0) {
        char arg0[] = "gitswitch";
        char arg1[] = "-C";
        char arg2[] = "-y";
        char arg3[] = "reset";
        char *argv[] = { arg0, arg1, arg2, arg3,
                         (char *)selector, NULL };
        int argc = selector ? 5 : 4;
        int rc;

        close(trace_pipe[0]);
        install_fixture_environment(fixture);
        if (redirect_output(fixture->output) != 0) _exit(120);
        g_trace_fd = trace_pipe[1];
        g_inject_stage = inject_stage;
        (void)gitswitch_test_set_reset_hook(inject_repeated_signal);
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        close(trace_pipe[1]);
        if (gitswitch_test_context_allocations() != 0) _exit(121);
        _exit(rc);
    }

    close(trace_pipe[1]);
    if (trace && trace_size > 0) {
        while (total + 1 < trace_size) {
            ssize_t n = read(trace_pipe[0], trace + total,
                             trace_size - total - 1);
            if (n > 0) total += (size_t)n;
            else if (n < 0 && errno == EINTR) continue;
            else break;
        }
        trace[total] = '\0';
    }
    close(trace_pipe[0]);
    status = wait_status(child);
    return status;
}

static int run_simple_child(const reset_fixture_t *fixture,
                            int argc, char **argv,
                            int expected_allocations) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int rc;
        install_fixture_environment(fixture);
        if (redirect_output(fixture->output) != 0) _exit(120);
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        if (gitswitch_test_context_allocations() != 0) _exit(121);
        if (gitswitch_test_context_allocation_total() !=
            expected_allocations) _exit(122);
        _exit(rc);
    }
    return wait_status(child);
}

static int run_add_guard_failure_child(const reset_fixture_t *fixture) {
    static const char answers[] =
        "new\nnew@example.com\n\n\n\nglobal\n";
    int input_pipe[2];
    pid_t child;

    if (pipe(input_pipe) != 0) return -1;
    if (write(input_pipe[1], answers, sizeof(answers) - 1) !=
        (ssize_t)(sizeof(answers) - 1)) {
        close(input_pipe[0]);
        close(input_pipe[1]);
        return -1;
    }
    close(input_pipe[1]);

    child = fork();
    if (child < 0) {
        close(input_pipe[0]);
        return -1;
    }
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char assume_yes[] = "-y";
        char add[] = "add";
        char *argv[] = { program, no_color, assume_yes, add, NULL };
        int rc;

        if (dup2(input_pipe[0], STDIN_FILENO) < 0) _exit(119);
        close(input_pipe[0]);
        install_fixture_environment(fixture);
        if (redirect_output(fixture->output) != 0) _exit(120);
        signals_test_fail_sigaction(SIGTERM,
                                    SIGNALS_TEST_SIGACTION_INSTALL, EPERM);
        optind = 1;
        rc = gitswitch_cli_main(4, argv);
        if (gitswitch_test_context_allocations() != 0) _exit(121);
        _exit(rc);
    }
    close(input_pipe[0]);
    return wait_status(child);
}

/* AR-08 M22: add's first guard is the centralized persistence boundary. A
 * failed guard must reject the command without installing the process-local
 * candidate in accounts.toml or printing a false success. */
TEST(add_persistence_guard_failure_leaves_config_unchanged) {
    reset_fixture_t fixture;
    char before[4096];
    char after[4096];
    char output[4096];
    int status;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK(read_text(fixture.config, before, sizeof(before)) > 0);
    status = run_add_guard_failure_child(&fixture);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK(WEXITSTATUS(status) != 0);
    CHECK(read_text(fixture.config, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);
    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Failed to install guarded disposition") != NULL);
    CHECK(strstr(output, "Account added successfully") == NULL);
}

TEST(informational_and_config_paths_obey_context_lifetime) {
    reset_fixture_t fixture;
    char prog[] = "gitswitch";
    char help[] = "--help";
    char version[] = "--version";
    char config[] = "config";
    char remove[] = "remove";
    char *help_argv[] = { prog, help, NULL };
    char *version_argv[] = { prog, version, NULL };
    char *config_argv[] = { prog, config, NULL };
    char *invalid_argv[] = { prog, remove, NULL };
    int status;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    status = run_simple_child(&fixture, 2, help_argv, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    status = run_simple_child(&fixture, 2, version_argv, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    status = run_simple_child(&fixture, 2, config_argv, 1);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    status = run_simple_child(&fixture, 2, invalid_argv, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) != 0);
}

TEST(empty_reset_selector_is_rejected_before_any_reset_work) {
    const char *modes[] = { "-n", "-y" };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        reset_fixture_t fixture;
        char gpg_base[PATH_MAX];
        char gpg_home[PATH_MAX];
        char marker[PATH_MAX];
        char config_lock[PATH_MAX];
        char hint[128];
        char output[4096];
        char prog[] = "gitswitch";
        char no_color[] = "-C";
        char reset[] = "reset";
        char empty[] = "";
        char *argv[] = {
            prog, no_color, (char *)modes[i], reset, empty, NULL
        };
        int status;

        CHECK_EQ_INT(fixture_setup(&fixture), 0);
        CHECK_EQ_INT(join_path(gpg_base, sizeof(gpg_base), fixture.runtime,
                               "/gitswitch-gpg"), 0);
        CHECK_EQ_INT(mkdir(gpg_base, 0700), 0);
        CHECK_EQ_INT(join_path(gpg_home, sizeof(gpg_home), gpg_base,
                               "/work"), 0);
        CHECK_EQ_INT(mkdir(gpg_home, 0700), 0);
        CHECK_EQ_INT(join_path(marker, sizeof(marker), gpg_home,
                               "/keep"), 0);
        CHECK_EQ_INT(write_private(marker, "preserve\n"), 0);
        CHECK_EQ_INT(join_path(config_lock, sizeof(config_lock),
                               fixture.config_dir, "/.config.lock"), 0);
        CHECK(access(config_lock, F_OK) != 0 && errno == ENOENT);

        status = run_simple_child(&fixture, 5, argv, 0);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
        }
        CHECK(access(marker, F_OK) == 0);
        CHECK(access(config_lock, F_OK) != 0 && errno == ENOENT);
        CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
        CHECK_STR_EQ(hint, "none\nactive=work\n");
        CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
        CHECK(strstr(output, "reset account selector must not be empty") != NULL);
        CHECK(strstr(output, "kill ALL") == NULL);
        CHECK(strstr(output, "delete ALL") == NULL);
        CHECK(strstr(output, "DRY RUN complete") == NULL);
        CHECK(strstr(output, "Reset all gitswitch") == NULL);
    }
}

TEST(repeated_signals_defer_across_every_reset_boundary) {
    const int stages[] = {
        RESET_TEST_AFTER_SSH,
        RESET_TEST_AFTER_GPG,
        RESET_TEST_AFTER_ACTIVE_CLEAR,
        RESET_TEST_AFTER_ACTIVE_COMMIT
    };

    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        reset_fixture_t fixture;
        char trace[16];
        char hint[128];
        char output[4096];
        int status;

        CHECK_EQ_INT(fixture_setup(&fixture), 0);
        status = run_reset_child(&fixture, NULL, stages[i], trace,
                                 sizeof(trace));
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
        CHECK_STR_EQ(trace, "1234");
        CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
        CHECK_STR_EQ(hint, "none\ninactive=v1\n");
        CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
        CHECK(strstr(output, "Reset all gitswitch SSH/GPG state") == NULL);
        CHECK(strstr(output, "reset transaction cleanup completed") != NULL);
    }
}

TEST(manager_failure_keeps_retry_state_while_signal_is_deferred) {
    reset_fixture_t fixture;
    char foreign[PATH_MAX];
    char ssh_base[PATH_MAX];
    char trace[16];
    char hint[128];
    char output[4096];
    int status;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK_EQ_INT(join_path(foreign, sizeof(foreign), fixture.root,
                           "/foreign-ssh"), 0);
    CHECK_EQ_INT(join_path(ssh_base, sizeof(ssh_base), fixture.runtime,
                           "/gitswitch-ssh"), 0);
    CHECK_EQ_INT(mkdir(foreign, 0700), 0);
    CHECK_EQ_INT(symlink(foreign, ssh_base), 0);

    status = run_reset_child(&fixture, NULL, RESET_TEST_AFTER_SSH,
                             trace, sizeof(trace));
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
    CHECK_STR_EQ(trace, "12");
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=work\n");
    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "reset failed; retry metadata was preserved") != NULL);
    CHECK(strstr(output, "Reset all gitswitch SSH/GPG state") == NULL);
}

TEST(case_different_active_account_clears_by_name_id_and_email) {
    const char *selectors[] = { "Work", "1", "work@example.com" };

    for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); i++) {
        reset_fixture_t fixture;
        char trace[16];
        char hint[128];
        int status;

        CHECK_EQ_INT(fixture_setup(&fixture), 0);
        status = run_reset_child(&fixture, selectors[i], 0,
                                 trace, sizeof(trace));
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
        CHECK_STR_EQ(trace, "1234");
        CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
        CHECK_STR_EQ(hint, "none\ninactive=v1\n");
    }
}

int main(void) {
    RUN_TEST(add_persistence_guard_failure_leaves_config_unchanged);
    RUN_TEST(informational_and_config_paths_obey_context_lifetime);
    RUN_TEST(empty_reset_selector_is_rejected_before_any_reset_work);
    RUN_TEST(repeated_signals_defer_across_every_reset_boundary);
    RUN_TEST(manager_failure_keeps_retry_state_while_signal_is_deferred);
    RUN_TEST(case_different_active_account_clears_by_name_id_and_email);
    return ts_test_finish();
}
