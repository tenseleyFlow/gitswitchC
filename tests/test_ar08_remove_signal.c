/* AR-08 M1: account removal is one destructive transaction from confirmation
 * through durable persistence and common cleanup. Repeated termination signals
 * at any teardown boundary must be deferred until that transaction is whole. */
#include "test.h"

#include "accounts.h"
#include "config.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

#define REMOVE_INCARNATION \
    "1818181818181818181818181818181818181818181818181818181818181818"

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
    char git_config[PATH_MAX];
    char ssh_key[PATH_MAX];
    char ssh_program[PATH_MAX];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    char ssh_config[PATH_MAX];
    char ssh_socket[PATH_MAX];
    char ssh_current[PATH_MAX];
    char gpg_home[PATH_MAX];
    char gpg_current[PATH_MAX];
    char output[PATH_MAX];
    bool credentialled;
} remove_fixture_t;

static int g_inject_stage;
static int g_inject_signal;
static int g_trace_fd = -1;
static bool g_inject_config_fault;
static config_io_boundary_t g_config_fault_boundary;

static bool fail_config_at_selected_boundary(config_io_boundary_t boundary) {
    return g_inject_config_fault && boundary == g_config_fault_boundary;
}

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

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t total = 0;

    while (total < length) {
        ssize_t written = write(fd, cursor + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

static int write_git_config_value(const char *path, const char *key,
                                  const char *value) {
    const char *argv[] = {
        "git", "config", "--file", path, "--no-includes",
        "--replace-all", key, value, NULL
    };
    run_result_t run;

    memset(&run, 0, sizeof(run));
    return run_argv_real(argv, NULL, &run);
}

static int write_publication_state(const remove_fixture_t *fixture,
                                   const char *header) {
    publication_record_t *record = NULL;
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0;
    struct stat st;
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    record = calloc(1U, sizeof(*record));
    if (!record) return -1;
    publication_record_init(record);
    record->account_id = UINT32_C(1);
    record->scope = PUBLICATION_SCOPE_GLOBAL;
    record->state = PUBLICATION_STATE_PUBLISHED;
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION;
    if ((size_t)snprintf(record->account_incarnation,
                         sizeof(record->account_incarnation), "%s",
                         REMOVE_INCARNATION) >=
            sizeof(record->account_incarnation) ||
        (size_t)snprintf(record->config_path, sizeof(record->config_path),
                         "%s", fixture->git_config) >=
            sizeof(record->config_path) ||
        stat(fixture->home, &st) != 0) {
        goto cleanup;
    }
    publication_identity_from_stat(&record->config_parent, &st);
    if (stat(fixture->git_config, &st) != 0) goto cleanup;
    publication_identity_from_stat(&record->post_config, &st);
    if (fixture->credentialled) {
        record->capabilities |= PUBLICATION_CAP_SSH_COMMAND |
                                PUBLICATION_CAP_SSH_PROGRAM;
        if (safe_strncpy(record->ssh_command, fixture->ssh_command,
                         sizeof(record->ssh_command)) != 0 ||
            safe_strncpy(record->ssh_program, fixture->ssh_program,
                         sizeof(record->ssh_program)) != 0 ||
            stat(fixture->ssh_program, &st) != 0) {
            goto cleanup;
        }
        publication_identity_from_stat(&record->ssh_program_identity, &st);
    }
    if (publication_record_validate(record) != 0 ||
        publication_ledger_upsert(&ledger, record) != 0 ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }
    fd = open(fixture->hint,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write_all(fd, header, strlen(header)) != 0 ||
        write_all(fd, tail, tail_length) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    free(tail);
    free(record);
    publication_ledger_clear(&ledger);
    return result;
}

static bool state_has_header(const char *state, const char *header) {
    return state && strncmp(state, header, strlen(header)) == 0;
}

static bool ledger_has_remove_record(const remove_fixture_t *fixture,
                                     publication_state_t expected_state) {
    publication_ledger_t ledger;
    const publication_record_t *record = NULL;
    publication_lookup_status_t lookup;
    bool matches = false;

    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(fixture->config, &ledger) == 0) {
        lookup = publication_ledger_find(
            &ledger, UINT32_C(1), REMOVE_INCARNATION,
            PUBLICATION_SCOPE_GLOBAL, fixture->git_config, "", &record);
        matches = lookup == PUBLICATION_LOOKUP_FOUND && record &&
                  record->state == expected_state;
        if (matches && fixture->credentialled) {
            matches = (record->capabilities &
                       (PUBLICATION_CAP_SSH_COMMAND |
                        PUBLICATION_CAP_SSH_PROGRAM)) ==
                          (PUBLICATION_CAP_SSH_COMMAND |
                           PUBLICATION_CAP_SSH_PROGRAM) &&
                      strcmp(record->ssh_command,
                             fixture->ssh_command) == 0 &&
                      strcmp(record->ssh_program,
                             fixture->ssh_program) == 0 &&
                      record->ssh_program_identity.present;
        }
    }
    publication_ledger_clear(&ledger);
    return matches;
}

static int fixture_setup(remove_fixture_t *fixture, bool credentialled) {
    char path[PATH_MAX];
    char config_body[4096];
    char ssh_body[2U * PATH_MAX];
    account_t account;

    memset(fixture, 0, sizeof(*fixture));
    fixture->credentialled = credentialled;
    if (snprintf(fixture->root, sizeof(fixture->root),
                 "/tmp/gitswitch-ar08-remove.XXXXXX") < 0 ||
        !ts_mkdtemp(fixture->root) ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0) return -1;
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
        path_join(fixture->ssh_key, sizeof(fixture->ssh_key),
                  fixture->root, "/key") != 0 ||
        path_join(fixture->git_config, sizeof(fixture->git_config),
                  fixture->home, "/.gitconfig-remove") != 0 ||
        path_join(fixture->output, sizeof(fixture->output), fixture->root,
                  "/output") != 0) {
        return -1;
    }
    if (credentialled) {
        if (write_private(fixture->ssh_key,
                          "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") != 0 ||
            (size_t)snprintf(
                config_body, sizeof(config_body),
                "[settings]\n"
                "default_scope = \"global\"\n"
                "active_account = \"work\"\n"
                "[accounts.1]\n"
                "incarnation = \"" REMOVE_INCARNATION "\"\n"
                "name = \"work\"\n"
                "email = \"work@example.com\"\n"
                "description = \"signal fixture\"\n"
                "preferred_scope = \"global\"\n"
                "ssh_key = \"%s\"\n"
                "ssh_host = \"github-work\"\n"
                "ssh_hostname = \"github.com\"\n",
                fixture->ssh_key) >= sizeof(config_body)) {
            return -1;
        }
    } else if ((size_t)snprintf(
                   config_body, sizeof(config_body),
                   "[settings]\n"
                   "default_scope = \"global\"\n"
                   "active_account = \"work\"\n"
                   "[accounts.1]\n"
                   "incarnation = \"" REMOVE_INCARNATION "\"\n"
                   "name = \"work\"\n"
                   "email = \"work@example.com\"\n"
                   "description = \"credentialless negative fixture\"\n"
                   "preferred_scope = \"global\"\n") >=
               sizeof(config_body)) {
        return -1;
    }
    if (write_private(fixture->config, config_body) != 0 ||
        write_private(fixture->git_config,
                      "[fixture]\n\tmarker = keep\n") != 0) {
        return -1;
    }
    if (!credentialled) {
        return write_private(fixture->hint, "none\nactive=work\n");
    }

    memset(&account, 0, sizeof(account));
    account.ssh_enabled = true;
    if (safe_strncpy(account.ssh_key_path, fixture->ssh_key,
                     sizeof(account.ssh_key_path)) != 0 ||
        safe_strncpy(account.ssh_host_alias, "github-work",
                     sizeof(account.ssh_host_alias)) != 0 ||
        safe_strncpy(account.ssh_hostname, "github.com",
                     sizeof(account.ssh_hostname)) != 0 ||
        git_expected_ssh_command(&account, fixture->ssh_command,
                                 sizeof(fixture->ssh_command)) != 0 ||
        publication_extract_ssh_program(
            fixture->ssh_command, fixture->ssh_program,
            sizeof(fixture->ssh_program)) != 0 ||
        write_git_config_value(fixture->git_config,
                               GIT_CONFIG_CORE_SSHCOMMAND,
                               fixture->ssh_command) != 0 ||
        write_publication_state(fixture,
                                "ssh\nactive=work\n") != 0) {
        return -1;
    }

    if ((size_t)snprintf(
            ssh_body, sizeof(ssh_body),
            "Host user-authored\n"
            "  HostName example.com\n"
            "# >>> gitswitch github-work >>>\n"
            "Host github-work\n"
            "  HostName github.com\n"
            "  IdentityFile %s\n"
            "  IdentitiesOnly yes\n"
            "# <<< gitswitch github-work <<<\n",
            fixture->ssh_key) >= sizeof(ssh_body)) {
        return -1;
    }

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
        symlink(fixture->gpg_home, fixture->gpg_current) != 0) return -1;
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
    /* Runtime managers use the deterministic fake. Durable Git retirement
     * starts after the GPG checkpoint and must use the descriptor-pinned real
     * runner so this sealed credential fixture exercises actual file state. */
    if (stage == REMOVE_TEST_AFTER_GPG) {
        (void)run_set_runner(NULL);
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
        if (signo > 0) {
            memset(&action, 0, sizeof(action));
            action.sa_handler = SIG_DFL;
            sigemptyset(&action.sa_mask);
            (void)sigaction(signo, &action, NULL);
            sigemptyset(&unblocked);
            sigaddset(&unblocked, signo);
            (void)sigprocmask(SIG_UNBLOCK, &unblocked, NULL);
        }
        (void)setenv("HOME", fixture->home, 1);
        (void)setenv("XDG_RUNTIME_DIR", fixture->runtime, 1);
        (void)setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
        (void)run_set_runner(null_runner);
        if (g_inject_config_fault) {
            (void)config_set_io_fault_fn(fail_config_at_selected_boundary);
        }
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
    const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };

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

            CHECK_EQ_INT(fixture_setup(&fixture, true), 0);
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
            CHECK(state_has_header(hint, "none\ninactive=v1\n"));
            CHECK(ledger_has_remove_record(
                &fixture, PUBLICATION_STATE_RETIRING));
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

TEST(config_faults_keep_account_and_alias_on_preinstall_failure) {
    static const struct {
        config_io_boundary_t boundary;
        bool config_installed;
    } cases[] = {
        { CONFIG_IO_STATE_AFTER_TEMP, false },
        { CONFIG_IO_STATE_AFTER_WRITE, false },
        { CONFIG_IO_STATE_BEFORE_FILE_SYNC, false },
        { CONFIG_IO_STATE_BEFORE_CLOSE, false },
        { CONFIG_IO_STATE_BEFORE_RENAME, false },
        { CONFIG_IO_STATE_BEFORE_DIR_SYNC, false },
        { CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK, false },
        { CONFIG_IO_BACKUP_BEFORE_FILE_SYNC, false },
        { CONFIG_IO_BACKUP_BEFORE_DIR_SYNC, false },
        { CONFIG_IO_BACKUP_BEFORE_REOPEN, false },
        { CONFIG_IO_DOCUMENT_BEFORE_RENAME, false },
        { CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, true }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        remove_fixture_t fixture;
        char trace[16];
        char config[4096];
        char hint[128];
        char ssh_config[4096];
        char output[4096];
        int status;

        CHECK_EQ_INT(fixture_setup(&fixture, true), 0);
        g_inject_config_fault = true;
        g_config_fault_boundary = cases[i].boundary;
        status = run_remove_child(&fixture, 0, 0, trace, sizeof(trace));
        g_inject_config_fault = false;

        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
        }
        CHECK_STR_EQ(trace, "12346");
        CHECK(read_text(fixture.config, config, sizeof(config)) > 0);
        CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
        CHECK(read_text(fixture.ssh_config, ssh_config,
                        sizeof(ssh_config)) > 0);
        CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
        CHECK(strstr(ssh_config, "HostName example.com") != NULL);
        CHECK(strstr(output, "Account removed successfully") == NULL);
        CHECK(access(fixture.ssh_socket, F_OK) != 0 && errno == ENOENT);
        CHECK(access(fixture.gpg_home, F_OK) != 0 && errno == ENOENT);
        CHECK(!config_dir_has_temp(fixture.config_dir));

        if (cases[i].config_installed) {
            CHECK(strstr(config, "name = \"work\"") == NULL);
            CHECK(state_has_header(hint, "none\ninactive=v1\n"));
            CHECK(ledger_has_remove_record(
                &fixture, PUBLICATION_STATE_RETIRING));
            CHECK(strstr(ssh_config, "github-work") == NULL);
            CHECK(strstr(output, "installed") != NULL);
        } else {
            CHECK(strstr(config, "name = \"work\"") != NULL);
            CHECK(state_has_header(hint, "ssh\nactive=work\n"));
            CHECK(ledger_has_remove_record(
                &fixture, PUBLICATION_STATE_PUBLISHED));
            CHECK(strstr(ssh_config, "github-work") != NULL);
            CHECK(strstr(output, "alias was retained") != NULL);
        }
    }
}

static void custom_handler(int signo) {
    (void)signo;
}

static int initialize_direct_context(gitswitch_ctx_t *ctx,
                                     const remove_fixture_t *fixture,
                                     const char *name,
                                     bool credentialled) {
    if (!ctx || !fixture || !name) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->config.assume_yes = true;
    ctx->account_count = 1;
    ctx->accounts[0].id = UINT32_C(1);
    ctx->accounts[0].incarnation_persisted = true;
    if (safe_strncpy(ctx->config.config_path, fixture->config,
                     sizeof(ctx->config.config_path)) != 0 ||
        safe_strncpy(ctx->accounts[0].incarnation, REMOVE_INCARNATION,
                     sizeof(ctx->accounts[0].incarnation)) != 0 ||
        safe_strncpy(ctx->accounts[0].name, name,
                     sizeof(ctx->accounts[0].name)) != 0 ||
        safe_strncpy(ctx->accounts[0].email, "direct@example.com",
                     sizeof(ctx->accounts[0].email)) != 0) {
        return -1;
    }
    if (credentialled) {
        ctx->accounts[0].ssh_enabled = true;
        if (safe_strncpy(ctx->accounts[0].ssh_key_path,
                         fixture->ssh_key,
                         sizeof(ctx->accounts[0].ssh_key_path)) != 0 ||
            safe_strncpy(ctx->accounts[0].ssh_host_alias,
                         "github-work",
                         sizeof(ctx->accounts[0].ssh_host_alias)) != 0 ||
            safe_strncpy(ctx->accounts[0].ssh_hostname,
                         "github.com",
                         sizeof(ctx->accounts[0].ssh_hostname)) != 0) {
            return -1;
        }
    }
    return 0;
}

TEST(direct_remove_without_publication_retains_retry_metadata) {
    remove_fixture_t fixture;
    gitswitch_ctx_t ctx;
    char incarnation[ACCOUNT_INCARNATION_LEN];

    CHECK_EQ_INT(fixture_setup(&fixture, false), 0);
    CHECK_EQ_INT(setenv("HOME", fixture.home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", fixture.runtime, 1), 0);
    CHECK_EQ_INT(initialize_direct_context(&ctx, &fixture,
                                           "direct-missing", false), 0);
    CHECK_EQ_INT(safe_strncpy(incarnation, ctx.accounts[0].incarnation,
                              sizeof(incarnation)), 0);

    CHECK_EQ_INT(accounts_remove(&ctx, "direct-missing"), -1);
    CHECK_EQ_INT((int)ctx.account_count, 1);
    CHECK_STR_EQ(ctx.accounts[0].name, "direct-missing");
    CHECK_STR_EQ(ctx.accounts[0].incarnation, incarnation);
    CHECK(strstr(get_last_error()->message,
                 "No canonical publication provenance") != NULL);

    (void)unsetenv("HOME");
    (void)unsetenv("XDG_RUNTIME_DIR");
    ts_rm_rf(fixture.root);
}

TEST(direct_remove_restores_callers_signal_dispositions) {
    remove_fixture_t fixture;
    gitswitch_ctx_t ctx;
    struct sigaction original[4];
    struct sigaction installed;
    struct sigaction observed;
    const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };

    CHECK_EQ_INT(fixture_setup(&fixture, true), 0);
    CHECK_EQ_INT(setenv("HOME", fixture.home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", fixture.runtime, 1), 0);
    CHECK_EQ_INT(initialize_direct_context(&ctx, &fixture, "direct", true), 0);

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
    (void)unsetenv("HOME");
    (void)unsetenv("XDG_RUNTIME_DIR");
    ts_rm_rf(fixture.root);
}

int main(void) {
    RUN_TEST(repeated_signals_defer_through_complete_removal_transaction);
    RUN_TEST(config_faults_keep_account_and_alias_on_preinstall_failure);
    RUN_TEST(direct_remove_without_publication_retains_retry_metadata);
    RUN_TEST(direct_remove_restores_callers_signal_dispositions);
    return ts_test_finish();
}
