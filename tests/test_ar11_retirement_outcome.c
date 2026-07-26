/* AR-11 M17: a detected durable-Git retirement failure is a command failure.
 * The account plus its exact PUBLISHED provenance remain the retry handle;
 * only a later verified-clean retry may report success or publish removal
 * tombstones. */
#include "test.h"

#include "config.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "signals.h"
#include "utils.h"

#include <getopt.h>
#include <limits.h>
#include <sys/wait.h>

#define M17_INCARNATION \
    "1717171717171717171717171717171717171717171717171717171717171717"
#define M17_LATER_INCARNATION \
    "2727272727272727272727272727272727272727272727272727272727272727"

typedef enum {
    GIT_RETIREMENT_TEST_LOCKED_READ = 1,
    GIT_RETIREMENT_TEST_BEFORE_REMOVE,
    GIT_RETIREMENT_TEST_BEFORE_PUBLISH,
    GIT_RETIREMENT_TEST_BEFORE_EXCHANGE
} git_retirement_test_stage_t;

typedef bool (*git_retirement_test_hook_fn)(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value);

git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn);
typedef void (*reset_test_hook_fn)(int stage);
reset_test_hook_fn gitswitch_test_set_reset_hook(reset_test_hook_fn hook);
int gitswitch_cli_main(int argc, char **argv);
int gitswitch_test_context_allocations(void);

enum {
    M17_RESET_TEST_AFTER_SSH = 1,
    M17_RESET_TEST_AFTER_GPG
};

typedef enum {
    M17_COMMAND_REMOVE = 0,
    M17_COMMAND_RESET_ONE,
    M17_COMMAND_RESET_ALL,
    /* A genuinely guarded command (switch is an activation command) against an
     * absent account: it traverses the retirement-guard gate before any config
     * load, unlike the exempt recovery remove/reset commands. Used to prove the
     * guard is really clear, not merely that a command bypasses it. */
    M17_COMMAND_SWITCH_ABSENT
} m17_command_t;

typedef enum {
    M17_FAULT_NONE = 0,
    M17_FAULT_LOCKED_READ,
    M17_FAULT_STAGED_REMOVE,
    M17_FAULT_LATE_GENERATION
} m17_fault_t;

typedef enum {
    M17_CLEANUP_NONE = 0,
    M17_CLEANUP_GUARD_RESTORE,
    M17_CLEANUP_OWNERSHIP_RELEASE
} m17_cleanup_fault_t;

typedef struct {
    unsigned char *data;
    size_t length;
} m17_bytes_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char runtime[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    char accounts_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char output_path[MAX_PATH_LEN];
    char git_paths[2][MAX_PATH_LEN];
    char replacement_path[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    publication_record_t records[2];
} m17_fixture_t;

static m17_fault_t m17_fault;
static char m17_fault_path[MAX_PATH_LEN];
static char m17_replacement_path[MAX_PATH_LEN];
static bool m17_fault_observed;
static m17_cleanup_fault_t m17_cleanup_fault;
static volatile sig_atomic_t m17_returning_signal_calls;

static void m17_returning_signal_handler(int signal_number) {
    (void)signal_number;
    m17_returning_signal_calls++;
}

static void m17_reset_cleanup_hook(int stage) {
    if (m17_cleanup_fault == M17_CLEANUP_OWNERSHIP_RELEASE &&
        stage == M17_RESET_TEST_AFTER_GPG) {
        if (signals_rollback_end_owned(UINT64_C(1)) != 0) {
            _exit(124);
        }
        if (signals_rollback_begin_owned(UINT64_C(2)) != 0) {
            _exit(126);
        }
        if (raise(SIGTERM) != 0) _exit(129);
    }
}

static int m17_write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, cursor + written, length - written);

        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int m17_write_file(const char *path, const void *data,
                          size_t length, mode_t mode) {
    int fd;
    int saved_errno;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    if (m17_write_all(fd, data, length) != 0 || fsync(fd) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int m17_write_text(const char *path, const char *text,
                          mode_t mode) {
    return text ? m17_write_file(path, text, strlen(text), mode) : -1;
}

static int m17_read_bytes(const char *path, m17_bytes_t *bytes) {
    struct stat st;
    unsigned char *data = NULL;
    size_t used = 0U;
    int fd;

    if (!path || !bytes || stat(path, &st) != 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
        return -1;
    }
    memset(bytes, 0, sizeof(*bytes));
    if (st.st_size > 0) {
        data = malloc((size_t)st.st_size + 1U);
        if (!data) return -1;
    } else {
        data = malloc(1U);
        if (!data) return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        free(data);
        return -1;
    }
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);

        if (got > 0) {
            used += (size_t)got;
        } else if (got < 0 && errno == EINTR) {
            continue;
        } else {
            (void)close(fd);
            free(data);
            return -1;
        }
    }
    if (close(fd) != 0) {
        free(data);
        return -1;
    }
    data[used] = '\0';
    bytes->data = data;
    bytes->length = used;
    return 0;
}

static void m17_bytes_clear(m17_bytes_t *bytes) {
    if (!bytes) return;
    free(bytes->data);
    memset(bytes, 0, sizeof(*bytes));
}

static bool m17_file_equals(const char *path,
                            const m17_bytes_t *expected) {
    m17_bytes_t observed;
    bool equal;

    if (!expected || m17_read_bytes(path, &observed) != 0) return false;
    equal = observed.length == expected->length &&
            (observed.length == 0U ||
             memcmp(observed.data, expected->data,
                    observed.length) == 0);
    m17_bytes_clear(&observed);
    return equal;
}

static int m17_make_dir(const char *path) {
    return mkdir(path, 0700) == 0 ? 0 : -1;
}

static int m17_git_config(const char *path, const char *operation,
                          const char *key, const char *value) {
    const char *argv[10];
    run_result_t result;
    size_t argc = 0U;

    argv[argc++] = "git";
    argv[argc++] = "config";
    argv[argc++] = "--file";
    argv[argc++] = path;
    argv[argc++] = "--no-includes";
    argv[argc++] = operation;
    argv[argc++] = key;
    if (value) argv[argc++] = value;
    argv[argc] = NULL;
    memset(&result, 0, sizeof(result));
    if (run_argv(argv, NULL, &result) == 0) return 0;
    return result.spawned ? result.exit_code : -1;
}

static int m17_generate_ssh_key(const char *path) {
    const char *argv[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path, NULL
    };
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    return run_argv_real(argv, &opts, &result);
}

static int m17_make_record(m17_fixture_t *fixture, size_t index) {
    publication_record_t *record;
    struct stat st;

    if (!fixture || index >= 2U) return -1;
    record = &fixture->records[index];
    publication_record_init(record);
    record->account_id = UINT32_C(1);
    record->scope = PUBLICATION_SCOPE_GLOBAL;
    record->state = PUBLICATION_STATE_PUBLISHED;
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION |
                           PUBLICATION_CAP_SSH_COMMAND |
                           PUBLICATION_CAP_SSH_PROGRAM;
    if (safe_strncpy(record->account_incarnation, M17_INCARNATION,
                     sizeof(record->account_incarnation)) != 0 ||
        safe_strncpy(record->config_path, fixture->git_paths[index],
                     sizeof(record->config_path)) != 0 ||
        stat(fixture->home, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->config_parent, &st);
    if (stat(record->config_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->post_config, &st);
    if (safe_strncpy(record->ssh_command, fixture->ssh_command,
                     sizeof(record->ssh_command)) != 0 ||
        safe_strncpy(record->ssh_program, fixture->ssh_program,
                     sizeof(record->ssh_program)) != 0 ||
        stat(fixture->ssh_program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->ssh_program_identity, &st);
    return publication_record_validate(record);
}

static int m17_write_state(m17_fixture_t *fixture, bool with_ledger,
                           bool credentialled) {
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    const char *header = credentialled ? "ssh\nactive=work\n"
                                       : "none\nactive=work\n";
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    if (with_ledger) {
        for (size_t i = 0U; i < 2U; i++) {
            if (publication_ledger_upsert(&ledger,
                                          &fixture->records[i]) != 0) {
                goto cleanup;
            }
        }
        if (publication_ledger_serialize(&ledger, &tail,
                                         &tail_length) != 0) {
            goto cleanup;
        }
    }
    fd = open(fixture->state_path,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || m17_write_all(fd, header, strlen(header)) != 0 ||
        (tail_length > 0U &&
         m17_write_all(fd, tail, tail_length) != 0) ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    if (tail) {
        secure_zero_memory(tail, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
}

static int m17_fixture_setup(m17_fixture_t *fixture,
                             bool credentialled, bool with_ledger) {
    static const char ssh_program_body[] = "#!/bin/sh\nexit 0\n";
    static const char git_marker[] = "[fixture]\n\tmarker = keep\n";
    static const char replacement[] =
        "[fixture]\n\tmarker = external-replacement\n";
    char root_template[] = "/tmp/gsw-ar11-m17-XXXXXX";
    char config_body[2U * MAX_PATH_LEN];
    int written;

    if (!fixture || (with_ledger && !credentialled)) return -1;
    memset(fixture, 0, sizeof(*fixture));
    if (!ts_mkdtemp(root_template) ||
        safe_strncpy(fixture->root, root_template,
                     sizeof(fixture->root)) != 0 ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home),
                      "%s/home", fixture->root) != 0 ||
        safe_snprintf(fixture->runtime, sizeof(fixture->runtime),
                      "%s/runtime", fixture->root) != 0 ||
        safe_snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                      "%s/.config/gitswitch", fixture->home) != 0 ||
        safe_snprintf(fixture->accounts_path,
                      sizeof(fixture->accounts_path),
                      "%s/accounts.toml", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->state_path, sizeof(fixture->state_path),
                      "%s/.resume-hint", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->output_path, sizeof(fixture->output_path),
                      "%s/output", fixture->root) != 0 ||
        safe_snprintf(fixture->git_paths[0],
                      sizeof(fixture->git_paths[0]),
                      "%s/.gitconfig-a", fixture->home) != 0 ||
        safe_snprintf(fixture->git_paths[1],
                      sizeof(fixture->git_paths[1]),
                      "%s/.gitconfig-b", fixture->home) != 0 ||
        safe_snprintf(fixture->replacement_path,
                      sizeof(fixture->replacement_path),
                      "%s/.gitconfig-replacement", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_program,
                      sizeof(fixture->ssh_program),
                      "%s/ssh-program", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_key, sizeof(fixture->ssh_key),
                      "%s/id_key", fixture->home) != 0 ||
        m17_make_dir(fixture->home) != 0 ||
        m17_make_dir(fixture->runtime) != 0) {
        return -1;
    }
    {
        char config_parent[MAX_PATH_LEN];

        if (safe_snprintf(config_parent, sizeof(config_parent),
                          "%s/.config", fixture->home) != 0 ||
            m17_make_dir(config_parent) != 0 ||
            m17_make_dir(fixture->config_dir) != 0) {
            return -1;
        }
    }
    if (m17_write_file(fixture->ssh_program, ssh_program_body,
                       sizeof(ssh_program_body) - 1U, 0700) != 0 ||
        (credentialled && m17_generate_ssh_key(fixture->ssh_key) != 0) ||
        safe_snprintf(fixture->ssh_command,
                      sizeof(fixture->ssh_command),
                      "'%s' -i '%s' -o IdentitiesOnly=yes",
                      fixture->ssh_program, fixture->ssh_key) != 0) {
        return -1;
    }
    for (size_t i = 0U; i < 2U; i++) {
        int git_result;

        if (m17_write_file(fixture->git_paths[i], git_marker,
                           sizeof(git_marker) - 1U, 0600) != 0) {
            return -1;
        }
        git_result = credentialled
                         ? m17_git_config(fixture->git_paths[i], "--add",
                                          GIT_CONFIG_CORE_SSHCOMMAND,
                                          fixture->ssh_command)
                         : 0;
        if (git_result != 0) return -1;
    }
    if (m17_write_file(fixture->replacement_path, replacement,
                       sizeof(replacement) - 1U, 0600) != 0) {
        return -1;
    }
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "[accounts.1]\n"
        "incarnation = \"%s\"\n"
        "name = \"work\"\n"
        "email = \"work@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "%s%s%s",
        M17_INCARNATION,
        credentialled ? "ssh_key = \"" : "",
        credentialled ? fixture->ssh_key : "",
        credentialled ? "\"\n" : "");
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        m17_write_text(fixture->accounts_path, config_body, 0600) != 0) {
        return -1;
    }
    if (with_ledger) {
        for (size_t i = 0U; i < 2U; i++) {
            if (m17_make_record(fixture, i) != 0) return -1;
        }
    }
    return m17_write_state(fixture, with_ledger, credentialled);
}

static int m17_multi_account_fixture_setup(m17_fixture_t *fixture) {
    char config_body[3U * MAX_PATH_LEN];
    int written;

    if (m17_fixture_setup(fixture, true, false) != 0 ||
        m17_make_record(fixture, 0U) != 0 ||
        m17_make_record(fixture, 1U) != 0) {
        return -1;
    }
    fixture->records[1].account_id = UINT32_C(2);
    if (safe_strncpy(fixture->records[1].account_incarnation,
                     M17_LATER_INCARNATION,
                     sizeof(fixture->records[1].account_incarnation)) != 0 ||
        publication_record_validate(&fixture->records[1]) != 0) {
        return -1;
    }
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "[accounts.1]\n"
        "incarnation = \"%s\"\n"
        "name = \"work\"\n"
        "email = \"work@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n"
        "[accounts.2]\n"
        "incarnation = \"%s\"\n"
        "name = \"later\"\n"
        "email = \"later@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n",
        M17_INCARNATION, fixture->ssh_key,
        M17_LATER_INCARNATION, fixture->ssh_key);
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        m17_write_text(fixture->accounts_path, config_body, 0600) != 0) {
        return -1;
    }
    return m17_write_state(fixture, true, true);
}

/* Two LEGACY (pre-ledger) accounts: neither carries an incarnation, an ssh_key,
 * or any publication record. The account-document uniformity invariant forbids
 * mixing legacy and incarnation-bound accounts in one config, so this all-legacy
 * shape — not a literal "one bound + one unbound" pair — is the realizable form
 * of the AR-12 H1 record-less case. Each account's retirement leg is vacuously
 * satisfied by the id_records==0 skip. */
static int m17_legacy_pair_fixture_setup(m17_fixture_t *fixture) {
    char config_body[3U * MAX_PATH_LEN];
    int written;

    if (m17_fixture_setup(fixture, false, false) != 0) {
        return -1;
    }
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"work@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "[accounts.2]\n"
        "name = \"later\"\n"
        "email = \"later@example.test\"\n"
        "preferred_scope = \"global\"\n");
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        m17_write_text(fixture->accounts_path, config_body, 0600) != 0) {
        return -1;
    }
    return m17_write_state(fixture, false, false);
}

static bool m17_retirement_hook(git_retirement_test_stage_t stage,
                                const char *path, const char *key,
                                const char *value) {
    (void)value;
    if (!path || strcmp(path, m17_fault_path) != 0) return false;
    if (m17_fault == M17_FAULT_LOCKED_READ &&
        stage == GIT_RETIREMENT_TEST_LOCKED_READ) {
        m17_fault_observed = true;
        return true;
    }
    if (m17_fault == M17_FAULT_STAGED_REMOVE &&
        stage == GIT_RETIREMENT_TEST_BEFORE_REMOVE && key &&
        strcmp(key, GIT_CONFIG_CORE_SSHCOMMAND) == 0) {
        m17_fault_observed = true;
        return true;
    }
    if (m17_fault == M17_FAULT_LATE_GENERATION &&
        stage == GIT_RETIREMENT_TEST_BEFORE_EXCHANGE) {
        if (rename(m17_replacement_path, m17_fault_path) != 0) {
            return true;
        }
        m17_fault_observed = true;
        return false;
    }
    return false;
}

static int m17_redirect_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    if (dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(fd, STDERR_FILENO) < 0) {
        (void)close(fd);
        return -1;
    }
    if (fd > STDERR_FILENO) (void)close(fd);
    return 0;
}

static int m17_wait_status(pid_t child) {
    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

static int m17_run_cli_with_cleanup_fault(
    const m17_fixture_t *fixture, m17_command_t command,
    m17_fault_t fault, size_t fault_path_index,
    m17_cleanup_fault_t cleanup_fault, bool *fault_observed) {
    pid_t child;
    int observed_pipe[2];
    int status;

    if (!fixture || fault_path_index >= 2U) return -1;
    if (fault_observed) *fault_observed = false;
    if (pipe(observed_pipe) != 0) return -1;
    child = fork();
    if (child < 0) {
        (void)close(observed_pipe[0]);
        (void)close(observed_pipe[1]);
        return -1;
    }
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char assume_yes[] = "-y";
        char remove[] = "remove";
        char reset[] = "reset";
        char switch_cmd[] = "switch";
        char work[] = "work";
        char absent[] = "no-such-account";
        char *remove_argv[] = {
            program, no_color, assume_yes, remove, work, NULL
        };
        char *reset_one_argv[] = {
            program, no_color, assume_yes, reset, work, NULL
        };
        char *reset_all_argv[] = {
            program, no_color, assume_yes, reset, NULL
        };
        char *switch_absent_argv[] = {
            program, no_color, assume_yes, switch_cmd, absent, NULL
        };
        char **argv = command == M17_COMMAND_REMOVE
                          ? remove_argv
                          : command == M17_COMMAND_RESET_ONE
                                ? reset_one_argv
                                : command == M17_COMMAND_SWITCH_ABSENT
                                      ? switch_absent_argv
                                      : reset_all_argv;
        int argc = command == M17_COMMAND_RESET_ALL ? 4 : 5;
        int rc;
        char observed = '0';

        (void)close(observed_pipe[0]);
        (void)setenv("HOME", fixture->home, 1);
        (void)setenv("XDG_RUNTIME_DIR", fixture->runtime, 1);
        (void)setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
        (void)unsetenv("GIT_CONFIG_GLOBAL");
        (void)unsetenv("GIT_CONFIG_SYSTEM");
        (void)unsetenv("GIT_CONFIG_COUNT");
        if (m17_redirect_output(fixture->output_path) != 0) _exit(120);
        m17_fault = fault;
        m17_cleanup_fault = cleanup_fault;
        m17_fault_observed = false;
        if (safe_strncpy(m17_fault_path,
                         fixture->git_paths[fault_path_index],
                         sizeof(m17_fault_path)) != 0 ||
            safe_strncpy(m17_replacement_path,
                         fixture->replacement_path,
                         sizeof(m17_replacement_path)) != 0) {
            _exit(121);
        }
        if (fault != M17_FAULT_NONE) {
            (void)git_ops_test_set_retirement_hook(
                m17_retirement_hook);
        }
        if (cleanup_fault == M17_CLEANUP_GUARD_RESTORE) {
            signals_test_fail_sigaction(
                SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        } else if (cleanup_fault == M17_CLEANUP_OWNERSHIP_RELEASE) {
            struct sigaction action;

            memset(&action, 0, sizeof(action));
            action.sa_handler = m17_returning_signal_handler;
            if (sigemptyset(&action.sa_mask) != 0 ||
                sigaction(SIGTERM, &action, NULL) != 0) {
                _exit(130);
            }
            m17_returning_signal_calls = 0;
            (void)gitswitch_test_set_reset_hook(
                m17_reset_cleanup_hook);
        }
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        if (cleanup_fault == M17_CLEANUP_OWNERSHIP_RELEASE) {
            char version[] = "--version";
            char *version_argv[] = {program, version, NULL};

            /* A foreign checked owner forces the first cleanup to retain its
             * exact RESET token and context. Once that foreign owner leaves,
             * a second in-process entry settles the RESET owner and delivers
             * the deferred signal, but an injected caller-mask restoration
             * failure must retain a context-free guard marker. A third entry
             * repairs that exact debt without delivering the signal twice. */
            if (gitswitch_test_context_allocations() != 1) _exit(123);
            signals_test_fail_dispatch(
                SIGNALS_TEST_DISPATCH_MASK_RESTORE, EIO);
            if (signals_rollback_end_owned(UINT64_C(2)) != 0) _exit(127);
            optind = 1;
            if (gitswitch_cli_main(2, version_argv) != EXIT_FAILURE) {
                _exit(125);
            }
            if (m17_returning_signal_calls != 1 ||
                gitswitch_test_context_allocations() != 0 ||
                signals_guard_active() || signals_rollback_active()) {
                _exit(128);
            }
            optind = 1;
            if (gitswitch_cli_main(2, version_argv) != EXIT_SUCCESS) {
                _exit(131);
            }
            if (m17_returning_signal_calls != 1) _exit(132);
            if (signals_guard_begin() != 0) _exit(134);
            if (signals_guard_end() != 0) _exit(135);
            if (signals_guard_active() || signals_rollback_active()) {
                _exit(133);
            }
        }
        if (m17_fault_observed) observed = '1';
        if (write(observed_pipe[1], &observed, 1U) != 1) _exit(122);
        (void)close(observed_pipe[1]);
        if (gitswitch_test_context_allocations() != 0) {
            _exit(123);
        }
        _exit(rc);
    }
    (void)close(observed_pipe[1]);
    {
        char observed = '0';
        ssize_t got;

        do {
            got = read(observed_pipe[0], &observed, 1U);
        } while (got < 0 && errno == EINTR);
        if (fault_observed && got == 1) {
            *fault_observed = observed == '1';
        }
    }
    (void)close(observed_pipe[0]);
    status = m17_wait_status(child);
    return status;
}

static int m17_run_cli_at(const m17_fixture_t *fixture,
                          m17_command_t command, m17_fault_t fault,
                          size_t fault_path_index,
                          bool *fault_observed) {
    return m17_run_cli_with_cleanup_fault(
        fixture, command, fault, fault_path_index,
        M17_CLEANUP_NONE, fault_observed);
}

static int m17_run_cli(const m17_fixture_t *fixture,
                       m17_command_t command, m17_fault_t fault,
                       bool *fault_observed) {
    return m17_run_cli_at(fixture, command, fault, 1U,
                          fault_observed);
}

static bool m17_output_has_no_success(const char *output) {
    return output &&
           strstr(output, "Account removed successfully") == NULL &&
           strstr(output, "Reset gitswitch state for:") == NULL &&
           strstr(output, "Reset all gitswitch SSH/GPG state") == NULL;
}

static const char *m17_success_text(m17_command_t command) {
    switch (command) {
        case M17_COMMAND_REMOVE:
            return "Account removed successfully";
        case M17_COMMAND_RESET_ONE:
            return "Reset gitswitch state for: work";
        case M17_COMMAND_RESET_ALL:
            return "Reset all gitswitch SSH/GPG state";
        default:
            return "";
    }
}

static void m17_check_ledger_state(const m17_fixture_t *fixture,
                                   publication_state_t state) {
    publication_ledger_t ledger;

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(
                     fixture->accounts_path, &ledger), 0);
    CHECK_EQ_INT((long)ledger.count, 2);
    for (size_t i = 0U; i < 2U; i++) {
        const publication_record_t *found = NULL;
        publication_lookup_status_t lookup;

        lookup = publication_ledger_find(
            &ledger, UINT32_C(1), M17_INCARNATION,
            PUBLICATION_SCOPE_GLOBAL,
            fixture->git_paths[i], "", &found);
        CHECK_EQ_INT(lookup, PUBLICATION_LOOKUP_FOUND);
        CHECK(found != NULL);
        if (found) CHECK_EQ_INT(found->state, state);
    }
    publication_ledger_clear(&ledger);
}

static void m17_exercise_failure_and_retry(m17_command_t command,
                                           m17_fault_t fault) {
    m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
    m17_bytes_t accounts_before = {0};
    m17_bytes_t state_before = {0};
    m17_bytes_t output = {0};
    bool fault_observed = false;
    int status;
    int setup_result;

    CHECK(fixture != NULL);
    if (!fixture) return;
    setup_result = m17_fixture_setup(fixture, true, true);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    if (m17_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
        m17_read_bytes(fixture->state_path, &state_before) != 0) {
        CHECK(false);
        goto cleanup;
    }

    status = m17_run_cli(fixture, command, fault, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m17_file_equals(fixture->accounts_path, &accounts_before));
    CHECK(m17_file_equals(fixture->state_path, &state_before));
    m17_check_ledger_state(fixture, PUBLICATION_STATE_PUBLISHED);
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(m17_output_has_no_success((const char *)output.data));
    CHECK(strstr((const char *)output.data, "retirement") != NULL);
    m17_bytes_clear(&output);

    if (fault == M17_FAULT_LATE_GENERATION) {
        CHECK_EQ_INT(m17_git_config(
                         fixture->git_paths[1], "--get-all",
                         GIT_CONFIG_CORE_SSHCOMMAND, NULL), 1);
    } else {
        CHECK_EQ_INT(m17_git_config(
                         fixture->git_paths[1], "--get-all",
                         GIT_CONFIG_CORE_SSHCOMMAND, NULL), 0);
    }

    status = m17_run_cli(fixture, command, M17_FAULT_NONE, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(strstr((const char *)output.data,
                 m17_success_text(command)) != NULL);
    m17_bytes_clear(&output);
    for (size_t i = 0U; i < 2U; i++) {
        CHECK_EQ_INT(m17_git_config(
                         fixture->git_paths[i], "--get-all",
                         GIT_CONFIG_CORE_SSHCOMMAND, NULL), 1);
    }

    CHECK_EQ_INT(m17_read_bytes(fixture->accounts_path, &output), 0);
    if (command == M17_COMMAND_REMOVE) {
        CHECK(strstr((const char *)output.data,
                     "name = \"work\"") == NULL);
        m17_check_ledger_state(fixture, PUBLICATION_STATE_RETIRING);
    } else {
        CHECK(strstr((const char *)output.data,
                     "name = \"work\"") != NULL);
        m17_check_ledger_state(fixture, PUBLICATION_STATE_PUBLISHED);
    }
    m17_bytes_clear(&output);
    CHECK_EQ_INT(m17_read_bytes(fixture->state_path, &output), 0);
    CHECK(output.length >= strlen("none\ninactive=v1\n"));
    if (output.length >= strlen("none\ninactive=v1\n")) {
        CHECK(memcmp(output.data, "none\ninactive=v1\n",
                     strlen("none\ninactive=v1\n")) == 0);
    }
    m17_bytes_clear(&output);

cleanup:
    m17_bytes_clear(&accounts_before);
    m17_bytes_clear(&state_before);
    m17_bytes_clear(&output);
    free(fixture);
}

TEST(remove_retirement_failures_are_nonzero_and_retryable) {
    const m17_fault_t faults[] = {
        M17_FAULT_LOCKED_READ,
        M17_FAULT_STAGED_REMOVE,
        M17_FAULT_LATE_GENERATION
    };

    for (size_t i = 0U; i < sizeof(faults) / sizeof(faults[0]); i++) {
        m17_exercise_failure_and_retry(M17_COMMAND_REMOVE, faults[i]);
    }
}

TEST(targeted_reset_retirement_failures_are_nonzero_and_retryable) {
    const m17_fault_t faults[] = {
        M17_FAULT_LOCKED_READ,
        M17_FAULT_STAGED_REMOVE,
        M17_FAULT_LATE_GENERATION
    };

    for (size_t i = 0U; i < sizeof(faults) / sizeof(faults[0]); i++) {
        m17_exercise_failure_and_retry(M17_COMMAND_RESET_ONE, faults[i]);
    }
}

TEST(all_reset_retirement_failures_are_nonzero_and_retryable) {
    const m17_fault_t faults[] = {
        M17_FAULT_LOCKED_READ,
        M17_FAULT_STAGED_REMOVE,
        M17_FAULT_LATE_GENERATION
    };

    for (size_t i = 0U; i < sizeof(faults) / sizeof(faults[0]); i++) {
        m17_exercise_failure_and_retry(M17_COMMAND_RESET_ALL, faults[i]);
    }
}

TEST(reset_all_continues_after_first_account_retirement_failure) {
    m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
    m17_bytes_t accounts_before = {0};
    m17_bytes_t state_before = {0};
    m17_bytes_t output = {0};
    const char *primary;
    const char *summary;
    const char *batch_summary;
    bool fault_observed = false;
    int setup_result;
    int status;

    CHECK(fixture != NULL);
    if (!fixture) return;
    setup_result = m17_multi_account_fixture_setup(fixture);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    if (m17_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
        m17_read_bytes(fixture->state_path, &state_before) != 0) {
        CHECK(false);
        goto cleanup;
    }

    /* Account order is work, then later. Fail work's sole destination and
     * require the all-account loop to continue through later's independent
     * destination without allowing that success to erase the first cause. */
    status = m17_run_cli_at(
        fixture, M17_COMMAND_RESET_ALL, M17_FAULT_LOCKED_READ, 0U,
        &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m17_file_equals(fixture->accounts_path, &accounts_before));
    CHECK(m17_file_equals(fixture->state_path, &state_before));
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(m17_output_has_no_success((const char *)output.data));
    primary = strstr(
        (const char *)output.data,
        "account 'work' destination 1 preparation (--global): "
        "Injected Git retirement locked-read failure");
    summary = strstr(
        (const char *)output.data,
        "reset failed; account and active-state metadata were preserved for retry");
    batch_summary = strstr((const char *)output.data,
                           "[retirement summary]");
    CHECK(primary != NULL);
    CHECK(summary != NULL);
    CHECK(batch_summary != NULL);
    if (primary && batch_summary) CHECK(primary < batch_summary);
    CHECK(strstr((const char *)output.data,
                 "durable Git retirement failed for reset account 'later'") ==
          NULL);
    m17_bytes_clear(&output);

    /* The failed first account retains its exact value. The later account's
     * value is gone, proving traversal continued after the first failure. */
    CHECK_EQ_INT(m17_git_config(
                     fixture->git_paths[0], "--get-all",
                     GIT_CONFIG_CORE_SSHCOMMAND, NULL), 0);
    CHECK_EQ_INT(m17_git_config(
                     fixture->git_paths[1], "--get-all",
                     GIT_CONFIG_CORE_SSHCOMMAND, NULL), 1);

    /* The unchanged PUBLISHED ledger authorizes an idempotent retry: the
     * stale-but-clean later destination reconciles while work is retired. */
    status = m17_run_cli_at(
        fixture, M17_COMMAND_RESET_ALL, M17_FAULT_NONE, 0U, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(strstr((const char *)output.data,
                 m17_success_text(M17_COMMAND_RESET_ALL)) != NULL);
    m17_bytes_clear(&output);
    for (size_t i = 0U; i < 2U; i++) {
        CHECK_EQ_INT(m17_git_config(
                         fixture->git_paths[i], "--get-all",
                         GIT_CONFIG_CORE_SSHCOMMAND, NULL), 1);
    }
    CHECK_EQ_INT(m17_read_bytes(fixture->state_path, &output), 0);
    CHECK(output.length >= strlen("none\ninactive=v1\n"));
    if (output.length >= strlen("none\ninactive=v1\n")) {
        CHECK(memcmp(output.data, "none\ninactive=v1\n",
                     strlen("none\ninactive=v1\n")) == 0);
    }

cleanup:
    m17_bytes_clear(&accounts_before);
    m17_bytes_clear(&state_before);
    m17_bytes_clear(&output);
    free(fixture);
}

TEST(reset_cleanup_failures_append_without_replacing_retirement_cause) {
    const struct {
        m17_cleanup_fault_t fault;
        const char *first_label;
        const char *second_label;
    } cases[] = {
        {
            M17_CLEANUP_GUARD_RESTORE,
            "[signal guard restoration]",
            NULL
        },
        {
            M17_CLEANUP_OWNERSHIP_RELEASE,
            "[reset transaction ownership release]",
            NULL
        }
    };

    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
        m17_bytes_t accounts_before = {0};
        m17_bytes_t state_before = {0};
        m17_bytes_t output = {0};
        const char *primary;
        const char *first_cleanup;
        const char *summary;
        bool fault_observed = false;
        int setup_result;
        int status;

        CHECK(fixture != NULL);
        if (!fixture) continue;
        setup_result = m17_fixture_setup(fixture, true, true);
        CHECK_EQ_INT(setup_result, 0);
        if (setup_result != 0) goto cleanup_case;
        if (m17_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
            m17_read_bytes(fixture->state_path, &state_before) != 0) {
            CHECK(false);
            goto cleanup_case;
        }

        status = m17_run_cli_with_cleanup_fault(
            fixture, M17_COMMAND_RESET_ONE, M17_FAULT_LOCKED_READ, 1U,
            cases[i].fault, &fault_observed);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
        }
        CHECK(fault_observed);
        CHECK(m17_file_equals(fixture->accounts_path, &accounts_before));
        CHECK(m17_file_equals(fixture->state_path, &state_before));
        m17_check_ledger_state(fixture, PUBLICATION_STATE_PUBLISHED);
        CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
        CHECK(m17_output_has_no_success((const char *)output.data));
        primary = strstr(
            (const char *)output.data,
            "Injected Git retirement locked-read failure");
        first_cleanup = strstr((const char *)output.data,
                               cases[i].first_label);
        summary = strstr(
            (const char *)output.data,
            "reset failed; account and active-state metadata were preserved for retry");
        CHECK(primary != NULL);
        CHECK(first_cleanup != NULL);
        CHECK(summary != NULL);
        if (primary && first_cleanup) CHECK(primary < first_cleanup);
        if (summary && first_cleanup) CHECK(summary < first_cleanup);
        if (cases[i].second_label) {
            const char *second_cleanup = strstr(
                (const char *)output.data, cases[i].second_label);

            CHECK(second_cleanup != NULL);
            if (first_cleanup && second_cleanup) {
                CHECK(first_cleanup < second_cleanup);
            }
        }
        if (cases[i].fault == M17_CLEANUP_OWNERSHIP_RELEASE) {
            CHECK(strstr((const char *)output.data,
                         "[account transaction ownership release]") == NULL);
        }

cleanup_case:
        m17_bytes_clear(&accounts_before);
        m17_bytes_clear(&state_before);
        m17_bytes_clear(&output);
        free(fixture);
    }
}

/* AR-12 H1: a credentialless account with no publication-ledger records has
 * nothing durable to retire. remove and reset must succeed vacuously instead
 * of demanding a switch-first round trip that would publish the identity
 * being torn down. */
TEST(credentialless_no_ledger_retires_vacuously) {
    const m17_command_t commands[] = {
        M17_COMMAND_REMOVE,
        M17_COMMAND_RESET_ONE,
        M17_COMMAND_RESET_ALL
    };

    for (size_t i = 0U; i < sizeof(commands) / sizeof(commands[0]); i++) {
        m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
        m17_bytes_t accounts_after = {0};
        m17_bytes_t output = {0};
        int setup_result;
        int status;

        CHECK(fixture != NULL);
        if (!fixture) continue;
        setup_result = m17_fixture_setup(fixture, false, false);
        CHECK_EQ_INT(setup_result, 0);
        if (setup_result != 0) goto vacuous_cleanup;
        status = m17_run_cli(fixture, commands[i], M17_FAULT_NONE, NULL);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
        }
        CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
        CHECK(strstr((const char *)output.data,
                     m17_success_text(commands[i])) != NULL);
        CHECK(strstr((const char *)output.data,
                     "No canonical publication provenance") == NULL);
        CHECK_EQ_INT(m17_read_bytes(fixture->accounts_path,
                                    &accounts_after), 0);
        if (commands[i] == M17_COMMAND_REMOVE) {
            /* Removal deletes the durable account entry. */
            CHECK(strstr((const char *)accounts_after.data,
                         "name = \"work\"") == NULL);
        } else {
            /* Reset tears down runtime state but keeps the account. */
            CHECK(strstr((const char *)accounts_after.data,
                         "name = \"work\"") != NULL);
        }
        m17_bytes_clear(&output);

vacuous_cleanup:
        m17_bytes_clear(&accounts_after);
        m17_bytes_clear(&output);
        free(fixture);
    }
}

/* AR-12 M4: a recorded destination whose config file was deleted (removed
 * repository, deleted global config) carries none of the published values.
 * Its retirement leg must settle vacuously — remove succeeds, the other
 * live destination is really retired, and no durable .retirement-incomplete
 * fence survives to brick every future command. */
TEST(deleted_destination_retires_vacuously_and_clears_guard) {
    m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
    m17_bytes_t output = {0};
    m17_bytes_t survivor = {0};
    char marker[MAX_PATH_LEN];
    int setup_result;
    int status;

    CHECK(fixture != NULL);
    if (!fixture) return;
    setup_result = m17_fixture_setup(fixture, true, true);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto vacuous_guard_cleanup;
    CHECK_EQ_INT(unlink(fixture->git_paths[0]), 0);
    status = m17_run_cli(fixture, M17_COMMAND_REMOVE, M17_FAULT_NONE, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(strstr((const char *)output.data,
                 m17_success_text(M17_COMMAND_REMOVE)) != NULL);
    /* The guard is settled: an incomplete marker may remain on disk only
     * when paired with its completion certificate, and no fence blocks the
     * next mutating command. */
    CHECK_EQ_INT(safe_snprintf(marker, sizeof(marker), "%s/%s",
                               fixture->config_dir,
                               ".retirement-incomplete"), 0);
    if (access(marker, F_OK) == 0) {
        CHECK_EQ_INT(safe_snprintf(marker, sizeof(marker), "%s/%s",
                                   fixture->config_dir,
                                   ".retirement-complete"), 0);
        CHECK_EQ_INT(access(marker, F_OK), 0);
    }
    CHECK_EQ_INT(m17_read_bytes(fixture->git_paths[1], &survivor), 0);
    CHECK(strstr((const char *)survivor.data, "sshCommand") == NULL);
    CHECK(strstr((const char *)survivor.data, "marker = keep") != NULL);
    /* A genuinely GUARDED command must not be fenced. `reset` is exempt from
     * the retirement gate (it is a recovery command), so a passing reset proves
     * nothing about the guard being cleared. `switch` is an activation command
     * that traverses the gate before config load: with the guard truly clear it
     * reaches normal dispatch and reports the absent account, never the fence
     * rejection. A surviving durable marker would instead stop it at the gate
     * with "Git retirement is incomplete". */
    m17_bytes_clear(&output);
    status = m17_run_cli(fixture, M17_COMMAND_SWITCH_ABSENT, M17_FAULT_NONE,
                         NULL);
    CHECK(WIFEXITED(status));
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    /* Never fenced: the gate rejection message is absent. Positively, the switch
     * handler ran its own dispatch — the gate sits BEFORE config load, so the
     * handler's failure proves the command passed through the cleared guard. */
    CHECK(strstr((const char *)output.data,
                 "Git retirement is incomplete") == NULL);
    CHECK(strstr((const char *)output.data,
                 "Failed to switch account") != NULL);

vacuous_guard_cleanup:
    m17_bytes_clear(&output);
    m17_bytes_clear(&survivor);
    free(fixture);
}

/* AR-13 L41 / AR-12 H1: reset-all over a multi-account LEGACY config (every
 * account record-less and without a persisted incarnation) must settle every
 * retirement leg vacuously and succeed. The id_records==0 `continue` is what
 * lets each legacy account through without demanding a persisted incarnation it
 * never had; removing it turns the skip into a hard ESTALE failure at the first
 * account, bricking reset for the whole config. */
TEST(reset_all_over_legacy_pair_settles_vacuously) {
    m17_fixture_t *fixture = calloc(1U, sizeof(*fixture));
    m17_bytes_t output = {0};
    int status;

    CHECK(fixture != NULL);
    if (!fixture) return;
    CHECK_EQ_INT(m17_legacy_pair_fixture_setup(fixture), 0);

    status = m17_run_cli(fixture, M17_COMMAND_RESET_ALL, M17_FAULT_NONE, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK_EQ_INT(m17_read_bytes(fixture->output_path, &output), 0);
    CHECK(strstr((const char *)output.data,
                 m17_success_text(M17_COMMAND_RESET_ALL)) != NULL);

    m17_bytes_clear(&output);
    free(fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(remove_retirement_failures_are_nonzero_and_retryable);
    RUN_TEST(targeted_reset_retirement_failures_are_nonzero_and_retryable);
    RUN_TEST(all_reset_retirement_failures_are_nonzero_and_retryable);
    RUN_TEST(reset_all_continues_after_first_account_retirement_failure);
    RUN_TEST(reset_cleanup_failures_append_without_replacing_retirement_cause);
    RUN_TEST(credentialless_no_ledger_retires_vacuously);
    RUN_TEST(deleted_destination_retires_vacuously_and_clears_guard);
    RUN_TEST(reset_all_over_legacy_pair_settles_vacuously);
TEST_MAIN_END()
