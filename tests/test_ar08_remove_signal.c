/* AR-08 M1: account removal is one destructive transaction from confirmation
 * through durable persistence and common cleanup. Repeated termination signals
 * at any teardown boundary must be deferred until that transaction is whole. */
#include "test.h"

#include "accounts.h"
#include "utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

typedef void (*remove_test_hook_fn)(int stage);

int gitswitch_cli_main(int argc, char **argv);
remove_test_hook_fn gitswitch_test_set_remove_hook(remove_test_hook_fn hook);
int gitswitch_test_context_allocations(void);

enum {
    REMOVE_TEST_AFTER_SSH = 1,
    REMOVE_TEST_AFTER_GPG,
    REMOVE_TEST_AFTER_MODEL,
    REMOVE_TEST_AFTER_ALIAS,
    REMOVE_TEST_AFTER_PERSIST,
    REMOVE_TEST_AFTER_CONTEXT_FREE
};

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char config_dir[PATH_MAX];
    char config[PATH_MAX];
    char hint[PATH_MAX];
    char ssh_config[PATH_MAX];
    char ssh_socket[PATH_MAX];
    char ssh_current[PATH_MAX];
    char gpg_home[PATH_MAX];
    char gpg_current[PATH_MAX];
    char output[PATH_MAX];
} remove_fixture_t;

static int g_inject_stage;
static int g_inject_signal;
static int g_trace_fd = -1;

static int path_join(char *path, size_t size, const char *base,
                     const char *suffix) {
    int needed = snprintf(path, size, "%s%s", base, suffix);
    return needed >= 0 && (size_t)needed < size ? 0 : -1;
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
    return close(fd);
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

static int fixture_setup(remove_fixture_t *fixture) {
    char path[PATH_MAX];
    char key[PATH_MAX];
    char config_body[4096];
    const char ssh_body[] =
        "Host user-authored\n"
        "  HostName example.com\n"
        "# >>> gitswitch github-work >>>\n"
        "Host github-work\n"
        "  HostName github.com\n"
        "  IdentityFile /fixture/key\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch github-work <<<\n";

    memset(fixture, 0, sizeof(*fixture));
    if (snprintf(fixture->root, sizeof(fixture->root),
                 "/tmp/gitswitch-ar08-remove.XXXXXX") < 0 ||
        !ts_mkdtemp(fixture->root)) return -1;
    if (path_join(fixture->home, sizeof(fixture->home), fixture->root,
                  "/home") != 0 || mkdir(fixture->home, 0700) != 0 ||
        path_join(fixture->runtime, sizeof(fixture->runtime), fixture->root,
                  "/runtime") != 0 || mkdir(fixture->runtime, 0700) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), fixture->home, "/.config") != 0 ||
        mkdir(path, 0700) != 0 ||
        path_join(fixture->config_dir, sizeof(fixture->config_dir),
                  path, "/gitswitch") != 0 ||
        mkdir(fixture->config_dir, 0700) != 0) return -1;
    if (path_join(fixture->config, sizeof(fixture->config),
                  fixture->config_dir, "/accounts.toml") != 0 ||
        path_join(fixture->hint, sizeof(fixture->hint), fixture->config_dir,
                  "/.resume-hint") != 0 ||
        path_join(key, sizeof(key), fixture->root, "/key") != 0) return -1;
    if (write_private(key,
                      "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") != 0) {
        return -1;
    }
    if ((size_t)snprintf(config_body, sizeof(config_body),
                         "[settings]\n"
                         "default_scope = \"global\"\n"
                         "active_account = \"work\"\n"
                         "[accounts.1]\n"
                         "name = \"work\"\n"
                         "email = \"work@example.com\"\n"
                         "description = \"signal fixture\"\n"
                         "preferred_scope = \"global\"\n"
                         "ssh_key = \"%s\"\n"
                         "ssh_host = \"github-work\"\n"
                         "ssh_hostname = \"github.com\"\n", key) >=
        sizeof(config_body) || write_private(fixture->config, config_body) != 0 ||
        write_private(fixture->hint, "ssh\nactive=work\n") != 0) return -1;

    if (path_join(path, sizeof(path), fixture->home, "/.ssh") != 0 ||
        mkdir(path, 0700) != 0 ||
        path_join(fixture->ssh_config, sizeof(fixture->ssh_config), path,
                  "/config") != 0 ||
        write_private(fixture->ssh_config, ssh_body) != 0) return -1;

    if (path_join(path, sizeof(path), fixture->runtime, "/gitswitch-ssh") != 0 ||
        mkdir(path, 0700) != 0 ||
        path_join(fixture->ssh_socket, sizeof(fixture->ssh_socket), path,
                  "/ssh-agent.work.sock") != 0 ||
        write_private(fixture->ssh_socket, "owned fixture\n") != 0 ||
        path_join(fixture->ssh_current, sizeof(fixture->ssh_current), path,
                  "/current.sock") != 0 ||
        symlink(fixture->ssh_socket, fixture->ssh_current) != 0) return -1;

    if (path_join(path, sizeof(path), fixture->runtime, "/gitswitch-gpg") != 0 ||
        mkdir(path, 0700) != 0 ||
        path_join(fixture->gpg_home, sizeof(fixture->gpg_home), path,
                  "/work") != 0 || mkdir(fixture->gpg_home, 0700) != 0 ||
        path_join(fixture->gpg_current, sizeof(fixture->gpg_current), path,
                  "/current") != 0 ||
        symlink(fixture->gpg_home, fixture->gpg_current) != 0 ||
        path_join(fixture->output, sizeof(fixture->output), fixture->root,
                  "/output") != 0) return -1;
    return 0;
}

static int null_runner(const char *const argv[], const run_opts_t *opts,
                       run_result_t *result) {
    (void)argv;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    return 0;
}

static void inject_repeated_signal(int stage) {
    char marker = (char)('0' + stage);
    if (g_trace_fd >= 0) {
        ssize_t written;
        do {
            written = write(g_trace_fd, &marker, 1);
        } while (written < 0 && errno == EINTR);
        if (written != 1) _exit(121);
    }
    if (stage == REMOVE_TEST_AFTER_CONTEXT_FREE &&
        gitswitch_test_context_allocations() != 0) {
        _exit(122);
    }
    if (stage == g_inject_stage) {
        (void)raise(g_inject_signal);
        (void)raise(g_inject_signal);
    }
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

static int wait_status(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

static int run_remove_child(const remove_fixture_t *fixture, int stage,
                            int signo, char *trace, size_t trace_size) {
    int trace_pipe[2];
    pid_t child;
    size_t total = 0;
    int status;

    if (pipe(trace_pipe) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(trace_pipe[0]);
        close(trace_pipe[1]);
        return -1;
    }
    if (child == 0) {
        struct sigaction action;
        sigset_t unblocked;
        char arg0[] = "gitswitch";
        char arg1[] = "-C";
        char arg2[] = "-y";
        char arg3[] = "remove";
        char arg4[] = "work";
        char *argv[] = { arg0, arg1, arg2, arg3, arg4, NULL };
        int rc;

        close(trace_pipe[0]);
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        (void)sigaction(signo, &action, NULL);
        sigemptyset(&unblocked);
        sigaddset(&unblocked, signo);
        (void)sigprocmask(SIG_UNBLOCK, &unblocked, NULL);
        (void)setenv("HOME", fixture->home, 1);
        (void)setenv("XDG_RUNTIME_DIR", fixture->runtime, 1);
        (void)setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
        (void)run_set_runner(null_runner);
        if (redirect_output(fixture->output) != 0) _exit(120);
        g_trace_fd = trace_pipe[1];
        g_inject_stage = stage;
        g_inject_signal = signo;
        (void)gitswitch_test_set_remove_hook(inject_repeated_signal);
        optind = 1;
        rc = gitswitch_cli_main(5, argv);
        close(trace_pipe[1]);
        if (gitswitch_test_context_allocations() != 0) _exit(121);
        _exit(rc);
    }

    close(trace_pipe[1]);
    while (total + 1 < trace_size) {
        ssize_t n = read(trace_pipe[0], trace + total, trace_size - total - 1);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    trace[total] = '\0';
    close(trace_pipe[0]);
    status = wait_status(child);
    return status;
}

static bool config_dir_has_temp(const char *path) {
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

TEST(repeated_signals_defer_through_complete_removal_transaction) {
    const int stages[] = {
        REMOVE_TEST_AFTER_SSH,
        REMOVE_TEST_AFTER_GPG,
        REMOVE_TEST_AFTER_MODEL,
        REMOVE_TEST_AFTER_ALIAS,
        REMOVE_TEST_AFTER_PERSIST
    };
    const int signals[] = { SIGINT, SIGTERM, SIGHUP };

    for (size_t signal_index = 0;
         signal_index < sizeof(signals) / sizeof(signals[0]); signal_index++) {
        for (size_t stage_index = 0;
             stage_index < sizeof(stages) / sizeof(stages[0]); stage_index++) {
            remove_fixture_t fixture;
            char trace[16];
            char config[4096];
            char hint[128];
            char ssh_config[4096];
            char output[4096];
            int status;

            CHECK_EQ_INT(fixture_setup(&fixture), 0);
            status = run_remove_child(&fixture, stages[stage_index],
                                      signals[signal_index], trace,
                                      sizeof(trace));
            CHECK(WIFSIGNALED(status));
            if (WIFSIGNALED(status)) {
                CHECK_EQ_INT(WTERMSIG(status), signals[signal_index]);
            }
            CHECK_STR_EQ(trace, "123456");
            CHECK(read_text(fixture.config, config, sizeof(config)) > 0);
            CHECK(strstr(config, "name = \"work\"") == NULL);
            CHECK(strstr(config, "active_account") == NULL);
            CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
            CHECK_STR_EQ(hint, "none\ninactive=v1\n");
            CHECK(access(fixture.ssh_socket, F_OK) != 0 && errno == ENOENT);
            CHECK(lstat(fixture.ssh_current, &(struct stat){0}) != 0 &&
                  errno == ENOENT);
            CHECK(access(fixture.gpg_home, F_OK) != 0 && errno == ENOENT);
            CHECK(lstat(fixture.gpg_current, &(struct stat){0}) != 0 &&
                  errno == ENOENT);
            CHECK(read_text(fixture.ssh_config, ssh_config,
                            sizeof(ssh_config)) > 0);
            CHECK(strstr(ssh_config, "github-work") == NULL);
            CHECK(strstr(ssh_config, "HostName example.com") != NULL);
            CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
            CHECK(strstr(output, "Account removed successfully") == NULL);
            CHECK(strstr(output, "command cleanup completed") != NULL);
            CHECK(!config_dir_has_temp(fixture.config_dir));
        }
    }
}

static void custom_handler(int signo) {
    (void)signo;
}

TEST(direct_remove_restores_callers_signal_dispositions) {
    gitswitch_ctx_t ctx;
    struct sigaction original[3];
    struct sigaction installed;
    struct sigaction observed;
    const int signals[] = { SIGINT, SIGTERM, SIGHUP };
    char runtime[PATH_MAX];

    memset(&ctx, 0, sizeof(ctx));
    CHECK(snprintf(runtime, sizeof(runtime),
                   "/tmp/gitswitch-ar08-direct.XXXXXX") > 0);
    CHECK(ts_mkdtemp(runtime) != NULL);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    ctx.config.assume_yes = true;
    ctx.account_count = 1;
    ctx.accounts[0].id = 1;
    snprintf(ctx.accounts[0].name, sizeof(ctx.accounts[0].name), "direct");
    snprintf(ctx.accounts[0].email, sizeof(ctx.accounts[0].email),
             "direct@example.com");

    memset(&installed, 0, sizeof(installed));
    installed.sa_handler = custom_handler;
    sigemptyset(&installed.sa_mask);
    sigaddset(&installed.sa_mask, SIGUSR1);
    installed.sa_flags = SA_RESTART;
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        CHECK_EQ_INT(sigaction(signals[i], NULL, &original[i]), 0);
        CHECK_EQ_INT(sigaction(signals[i], &installed, NULL), 0);
    }
    CHECK_EQ_INT(accounts_remove(&ctx, "direct"), 0);
    CHECK_EQ_INT((int)ctx.account_count, 0);
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        CHECK_EQ_INT(sigaction(signals[i], NULL, &observed), 0);
        CHECK(observed.sa_handler == custom_handler);
        CHECK_EQ_INT(sigismember(&observed.sa_mask, SIGUSR1), 1);
        CHECK((observed.sa_flags & SA_RESTART) != 0);
        CHECK_EQ_INT(sigaction(signals[i], &original[i], NULL), 0);
    }
    (void)unsetenv("XDG_RUNTIME_DIR");
}

int main(void) {
    RUN_TEST(repeated_signals_defer_through_complete_removal_transaction);
    RUN_TEST(direct_remove_restores_callers_signal_dispositions);
    return ts_test_finish();
}
