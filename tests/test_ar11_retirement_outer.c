/* AR-11 M18: durable Git retirement belongs to the outer remove/reset
 * transaction. A proven pre-install persistence failure must restore the exact
 * Git before-image; an installed-but-uncertain state must remain explicitly
 * RETIRING and must make a later resume fail closed. */
#include "test.h"

#include "accounts.h"
#include "config.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "utils.h"

#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <sys/wait.h>

#define M18_INCARNATION \
    "1818181818181818181818181818181818181818181818181818181818181818"
#define M18_SECOND_INCARNATION \
    "2828282828282828282828282828282828282828282828282828282828282828"

int gitswitch_cli_main(int argc, char **argv);
int gitswitch_test_context_allocations(void);

typedef enum {
    M18_COMMAND_REMOVE = 0,
    M18_COMMAND_RESET,
    M18_COMMAND_RESET_ALL,
    M18_COMMAND_RESUME,
    M18_COMMAND_SWITCH
} m18_command_t;

enum {
    M18_FAULT_NONE = 0U,
    M18_FAULT_ONCE = 1U
};

typedef struct {
    unsigned char *data;
    size_t length;
} m18_bytes_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char runtime[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    char accounts_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char guard_path[MAX_PATH_LEN];
    char output_path[MAX_PATH_LEN];
    char git_path[MAX_PATH_LEN];
    char no_op_git_path[MAX_PATH_LEN];
    char shared_repository[MAX_PATH_LEN];
    char git_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    publication_record_t record;
    publication_record_t shared_record;
    publication_record_t no_op_record;
} m18_fixture_t;

static bool m18_guard_is_unblocked_and_bounded(
    const m18_fixture_t *fixture);
static bool m18_guard_is_private_and_blocking(
    const m18_fixture_t *fixture, const char *operation);

static config_io_boundary_t m18_fault_boundary;
static bool m18_fault_observed;
static size_t m18_faults_remaining;
static size_t m18_fault_matches_to_skip;

static bool m18_config_fault(config_io_boundary_t boundary) {
    if (boundary != m18_fault_boundary) return false;
    if (m18_fault_matches_to_skip > 0U) {
        m18_fault_matches_to_skip--;
        return false;
    }
    if (m18_faults_remaining == 0U) return false;
    m18_fault_observed = true;
    if (m18_faults_remaining != SIZE_MAX) m18_faults_remaining--;
    return true;
}

static int m18_write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t total = 0U;

    while (total < length) {
        ssize_t written = write(fd, cursor + total, length - total);

        if (written > 0) {
            total += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int m18_write_file(const char *path, const void *data,
                          size_t length, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    int saved_errno;

    if (fd < 0) return -1;
    if (m18_write_all(fd, data, length) != 0 || fsync(fd) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int m18_write_text(const char *path, const char *text, mode_t mode) {
    return text ? m18_write_file(path, text, strlen(text), mode) : -1;
}

static int m18_read_bytes(const char *path, m18_bytes_t *bytes) {
    struct stat st;
    unsigned char *data;
    size_t used = 0U;
    int fd;

    if (!path || !bytes || stat(path, &st) != 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
        return -1;
    }
    data = malloc((size_t)st.st_size + 1U);
    if (!data) return -1;
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

static void m18_bytes_clear(m18_bytes_t *bytes) {
    if (!bytes) return;
    free(bytes->data);
    memset(bytes, 0, sizeof(*bytes));
}

static bool m18_file_equals(const char *path,
                            const m18_bytes_t *expected) {
    m18_bytes_t observed = {0};
    bool equal;

    if (!expected || m18_read_bytes(path, &observed) != 0) return false;
    equal = observed.length == expected->length &&
            (observed.length == 0U ||
             memcmp(observed.data, expected->data, observed.length) == 0);
    m18_bytes_clear(&observed);
    return equal;
}

static bool m18_git_has_command(const m18_fixture_t *fixture) {
    m18_bytes_t bytes = {0};
    bool found = false;

    if (fixture && m18_read_bytes(fixture->git_path, &bytes) == 0) {
        found = strstr((const char *)bytes.data,
                       fixture->ssh_command) != NULL;
    }
    m18_bytes_clear(&bytes);
    return found;
}

static int m18_write_state(m18_fixture_t *fixture) {
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    static const char header[] = "ssh\nactive=work\n";
    int fd = -1;
    int result = -1;

    publication_ledger_init(&ledger);
    if (publication_ledger_upsert(&ledger, &fixture->record) != 0 ||
        (fixture->shared_record.account_id != 0U &&
         publication_ledger_upsert(&ledger,
                                   &fixture->shared_record) != 0) ||
        (fixture->no_op_record.account_id != 0U &&
         publication_ledger_upsert(&ledger,
                                   &fixture->no_op_record) != 0) ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }
    fd = open(fixture->state_path,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || m18_write_all(fd, header, sizeof(header) - 1U) != 0 ||
        m18_write_all(fd, tail, tail_length) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) {
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

static int m18_fixture_setup(m18_fixture_t *fixture) {
    static const char ssh_program_body[] = "#!/bin/sh\nexit 0\n";
    static const char git_program_body[] =
        "#!/bin/sh\nPATH=/usr/local/bin:/usr/bin:/bin\n"
        "export PATH\nexec git \"$@\"\n";
    static const char key_body[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
    /* The real runner rejects executables below a world-writable /tmp ancestor.
     * Keep this fixture under the checked-out, same-uid workspace so its
     * private git wrapper exercises the production trusted-PATH resolver. */
    char root_template[] = ".gsw-ar11-m18-XXXXXX";
    char config_parent[MAX_PATH_LEN];
    char config_body[2U * MAX_PATH_LEN];
    char git_body[PUBLICATION_SSH_COMMAND_MAX + 128U];
    struct stat st;
    int written;

    if (!fixture) return -1;
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
        safe_snprintf(config_parent, sizeof(config_parent),
                      "%s/.config", fixture->home) != 0 ||
        safe_snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                      "%s/gitswitch", config_parent) != 0 ||
        safe_snprintf(fixture->accounts_path,
                      sizeof(fixture->accounts_path),
                      "%s/accounts.toml", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->state_path, sizeof(fixture->state_path),
                      "%s/.resume-hint", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->guard_path, sizeof(fixture->guard_path),
                      "%s/.retirement-incomplete",
                      fixture->config_dir) != 0 ||
        safe_snprintf(fixture->output_path, sizeof(fixture->output_path),
                      "%s/output", fixture->root) != 0 ||
        safe_snprintf(fixture->git_path, sizeof(fixture->git_path),
                      "%s/.gitconfig", fixture->home) != 0 ||
        safe_snprintf(fixture->git_program,
                      sizeof(fixture->git_program),
                      "%s/git", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_program,
                      sizeof(fixture->ssh_program),
                      "%s/ssh-program", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_key, sizeof(fixture->ssh_key),
                      "%s/id_key", fixture->home) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        mkdir(fixture->runtime, 0700) != 0 ||
        mkdir(config_parent, 0700) != 0 ||
        mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if (m18_write_file(fixture->git_program, git_program_body,
                       sizeof(git_program_body) - 1U, 0700) != 0 ||
        m18_write_file(fixture->ssh_program, ssh_program_body,
                       sizeof(ssh_program_body) - 1U, 0700) != 0 ||
        m18_write_file(fixture->ssh_key, key_body,
                       sizeof(key_body) - 1U, 0600) != 0 ||
        safe_snprintf(fixture->ssh_command,
                      sizeof(fixture->ssh_command),
                      "'%s' -i '%s' -o IdentitiesOnly=yes",
                      fixture->ssh_program, fixture->ssh_key) != 0) {
        return -1;
    }
    written = snprintf(git_body, sizeof(git_body),
                       "[fixture]\n\tmarker = before\n"
                       "[core]\n\tsshCommand = %s\n",
                       fixture->ssh_command);
    if (written < 0 || (size_t)written >= sizeof(git_body) ||
        m18_write_file(fixture->git_path, git_body,
                       (size_t)written, 0600) != 0) {
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
        "ssh_key = \"%s\"\n",
        M18_INCARNATION, fixture->ssh_key);
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        m18_write_text(fixture->accounts_path, config_body, 0600) != 0) {
        return -1;
    }

    publication_record_init(&fixture->record);
    fixture->record.account_id = UINT32_C(1);
    fixture->record.scope = PUBLICATION_SCOPE_GLOBAL;
    fixture->record.state = PUBLICATION_STATE_PUBLISHED;
    fixture->record.capabilities = PUBLICATION_CAP_DESTINATION |
                                   PUBLICATION_CAP_POST_GENERATION |
                                   PUBLICATION_CAP_SSH_COMMAND |
                                   PUBLICATION_CAP_SSH_PROGRAM;
    if (safe_strncpy(fixture->record.account_incarnation, M18_INCARNATION,
                     sizeof(fixture->record.account_incarnation)) != 0 ||
        safe_strncpy(fixture->record.config_path, fixture->git_path,
                     sizeof(fixture->record.config_path)) != 0 ||
        safe_strncpy(fixture->record.ssh_command, fixture->ssh_command,
                     sizeof(fixture->record.ssh_command)) != 0 ||
        safe_strncpy(fixture->record.ssh_program, fixture->ssh_program,
                     sizeof(fixture->record.ssh_program)) != 0 ||
        stat(fixture->home, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&fixture->record.config_parent, &st);
    if (stat(fixture->git_path, &st) != 0) return -1;
    publication_identity_from_stat(&fixture->record.post_config, &st);
    if (stat(fixture->ssh_program, &st) != 0) return -1;
    publication_identity_from_stat(&fixture->record.ssh_program_identity,
                                   &st);
    if (publication_record_validate(&fixture->record) != 0) return -1;
    return m18_write_state(fixture);
}

static int m18_fixture_add_shared_and_no_op_destinations(
    m18_fixture_t *fixture) {
    char config_body[3U * MAX_PATH_LEN];
    static const char no_op_git_body[] =
        "[fixture]\n\tmarker = unchanged\n";
    struct stat st;
    int written;

    if (!fixture ||
        safe_snprintf(fixture->no_op_git_path,
                      sizeof(fixture->no_op_git_path),
                      "%s/.gitconfig-no-op", fixture->home) != 0 ||
        safe_snprintf(fixture->shared_repository,
                      sizeof(fixture->shared_repository),
                      "%s/linked-worktree", fixture->root) != 0 ||
        mkdir(fixture->shared_repository, 0700) != 0 ||
        m18_write_file(fixture->no_op_git_path, no_op_git_body,
                       sizeof(no_op_git_body) - 1U, 0600) != 0) {
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
        "name = \"personal\"\n"
        "email = \"personal@example.test\"\n"
        "preferred_scope = \"global\"\n",
        M18_INCARNATION, fixture->ssh_key,
        M18_SECOND_INCARNATION);
    if (written < 0 || (size_t)written >= sizeof(config_body) ||
        m18_write_file(fixture->accounts_path, config_body,
                       (size_t)written, 0600) != 0) {
        return -1;
    }

    publication_record_init(&fixture->shared_record);
    fixture->shared_record.account_id = UINT32_C(1);
    fixture->shared_record.scope = PUBLICATION_SCOPE_LOCAL;
    fixture->shared_record.state = PUBLICATION_STATE_PUBLISHED;
    fixture->shared_record.capabilities =
        PUBLICATION_CAP_DESTINATION | PUBLICATION_CAP_POST_GENERATION;
    fixture->shared_record.config_parent = fixture->record.config_parent;
    fixture->shared_record.post_config = fixture->record.post_config;
    if (safe_strncpy(fixture->shared_record.account_incarnation,
                     M18_INCARNATION,
                     sizeof(fixture->shared_record.account_incarnation)) != 0 ||
        safe_strncpy(fixture->shared_record.config_path,
                     fixture->git_path,
                     sizeof(fixture->shared_record.config_path)) != 0 ||
        safe_strncpy(fixture->shared_record.repository_path,
                     fixture->shared_repository,
                     sizeof(fixture->shared_record.repository_path)) != 0 ||
        stat(fixture->shared_repository, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&fixture->shared_record.repository, &st);
    if (publication_record_validate(&fixture->shared_record) != 0) {
        return -1;
    }

    publication_record_init(&fixture->no_op_record);
    fixture->no_op_record.account_id = UINT32_C(2);
    fixture->no_op_record.scope = PUBLICATION_SCOPE_GLOBAL;
    fixture->no_op_record.state = PUBLICATION_STATE_PUBLISHED;
    fixture->no_op_record.capabilities =
        PUBLICATION_CAP_DESTINATION | PUBLICATION_CAP_POST_GENERATION;
    fixture->no_op_record.config_parent = fixture->record.config_parent;
    if (safe_strncpy(fixture->no_op_record.account_incarnation,
                     M18_SECOND_INCARNATION,
                     sizeof(fixture->no_op_record.account_incarnation)) != 0 ||
        safe_strncpy(fixture->no_op_record.config_path,
                     fixture->no_op_git_path,
                     sizeof(fixture->no_op_record.config_path)) != 0 ||
        stat(fixture->no_op_git_path, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&fixture->no_op_record.post_config, &st);
    if (publication_record_validate(&fixture->no_op_record) != 0) return -1;
    return m18_write_state(fixture);
}

static void m18_fixture_cleanup(m18_fixture_t *fixture) {
    if (!fixture) return;
    publication_record_init(&fixture->record);
    publication_record_init(&fixture->shared_record);
    publication_record_init(&fixture->no_op_record);
    if (fixture->root[0] != '\0') ts_rm_rf(fixture->root);
    memset(fixture, 0, sizeof(*fixture));
}

static int m18_redirect_output(const char *path) {
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

static int m18_wait_status(pid_t child) {
    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

static int m18_run_cli_after_matches(
    const m18_fixture_t *fixture, m18_command_t command,
    size_t fault_limit, config_io_boundary_t boundary,
    size_t fault_matches_to_skip, bool *fault_observed) {
    int observed_pipe[2];
    pid_t child;

    if (!fixture || pipe(observed_pipe) != 0) return -1;
    if (fault_observed) *fault_observed = false;
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
        char resume[] = "resume";
        char switch_command[] = "switch";
        char work[] = "work";
        char *remove_argv[] = {
            program, no_color, assume_yes, remove, work, NULL
        };
        char *reset_argv[] = {
            program, no_color, assume_yes, reset, work, NULL
        };
        char *reset_all_argv[] = {
            program, no_color, assume_yes, reset, NULL
        };
        char *resume_argv[] = {program, no_color, resume, NULL};
        char *switch_argv[] = {
            program, no_color, assume_yes, switch_command, work, NULL
        };
        char trusted_path[2U * MAX_PATH_LEN];
        char **argv;
        int argc;
        char observed = '0';
        int rc;

        (void)close(observed_pipe[0]);
        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->home) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            m18_redirect_output(fixture->output_path) != 0) {
            _exit(120);
        }
        switch (command) {
            case M18_COMMAND_REMOVE:
                argv = remove_argv;
                argc = 5;
                break;
            case M18_COMMAND_RESET:
                argv = reset_argv;
                argc = 5;
                break;
            case M18_COMMAND_RESET_ALL:
                argv = reset_all_argv;
                argc = 4;
                break;
            case M18_COMMAND_RESUME:
                argv = resume_argv;
                argc = 3;
                break;
            case M18_COMMAND_SWITCH:
                argv = switch_argv;
                argc = 5;
                break;
            default:
                _exit(123);
        }
        m18_fault_boundary = boundary;
        m18_fault_observed = false;
        m18_faults_remaining = fault_limit;
        m18_fault_matches_to_skip = fault_matches_to_skip;
        if (fault_limit != M18_FAULT_NONE) {
            (void)config_set_io_fault_fn(m18_config_fault);
        }
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        if (m18_fault_observed) observed = '1';
        if (write(observed_pipe[1], &observed, 1U) != 1) _exit(121);
        (void)close(observed_pipe[1]);
        if (gitswitch_test_context_allocations() != 0) _exit(122);
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
    {
        int status = m18_wait_status(child);
        const char *debug = getenv("M18_DEBUG");

        if (debug && strcmp(debug, "1") == 0) {
            m18_bytes_t output = {0};
            if (m18_read_bytes(fixture->output_path, &output) == 0) {
                fprintf(stderr, "\n[M18 child output]\n%.*s\n",
                        (int)output.length, (const char *)output.data);
                m18_bytes_clear(&output);
            }
        }
        return status;
    }
}

static int m18_run_cli(const m18_fixture_t *fixture,
                       m18_command_t command, size_t fault_limit,
                       config_io_boundary_t boundary,
                       bool *fault_observed) {
    return m18_run_cli_after_matches(
        fixture, command, fault_limit, boundary, 0U, fault_observed);
}

typedef enum {
    M18_PHASE_COMPLETE = 0,
    M18_PHASE_CANCEL
} m18_phase_mode_t;

/* Exercise the public reset-retirement state machine directly in a child so
 * the process-global transaction owner and signal rollback depth cannot leak
 * into the boundary-matrix cases. Each failed step has a distinct exit code
 * to keep a regression causal even when the parent only observes wait status. */
static int m18_run_phase_contract(const m18_fixture_t *fixture,
                                  m18_phase_mode_t mode) {
    pid_t child;

    if (!fixture) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        char trusted_path[2U * MAX_PATH_LEN];
        size_t cleared = 99U;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->home) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0) {
            _exit(101);
        }
        if (config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 || accounts_transaction_rollback_begin(
                              &ctx, ACCOUNTS_TRANSACTION_RESET,
                              token) != 0) {
            _exit(102);
        }
        if (accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != 0 ||
            !m18_guard_is_private_and_blocking(fixture, "reset") ||
            !m18_git_has_command(fixture)) {
            _exit(103);
        }

        if (mode == M18_PHASE_CANCEL) {
            if (accounts_reset_retirement_cancel(&ctx, token) != 0 ||
                !m18_guard_is_unblocked_and_bounded(fixture) ||
                !m18_git_has_command(fixture)) {
                _exit(104);
            }
        } else {
            /* Finalize-before-publish must leave the PREPARED owner intact so
             * publication remains possible and the blocker remains present. */
            if (accounts_reset_retirement_finalize(
                    &ctx, token,
                    ACCOUNTS_RETIREMENT_SAVE_DURABLE) != -1 ||
                errno != EBUSY ||
                get_last_error()->code != ERR_SYSTEM_CALL ||
                !m18_guard_is_private_and_blocking(fixture, "reset") ||
                !m18_git_has_command(fixture)) {
                _exit(105);
            }
            cleared = 99U;
            if (accounts_reset_retirement_publish(
                    &ctx, token, &cleared) != 0) _exit(110);
            if (cleared != 1U) _exit(111);
            if (m18_git_has_command(fixture)) _exit(112);
            if (!m18_guard_is_private_and_blocking(fixture, "reset"))
                _exit(113);

            /* Invalid outcome classification is a caller error, not a
             * consuming transition. The published Git transaction and its
             * blocker must remain available for a later valid finalization. */
            if (accounts_reset_retirement_finalize(
                    &ctx, token,
                    (accounts_retirement_save_outcome_t)(
                        ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED + 1)) !=
                    -1 ||
                errno != EINVAL ||
                get_last_error()->code != ERR_INVALID_ARGS ||
                m18_git_has_command(fixture) ||
                !m18_guard_is_private_and_blocking(fixture, "reset")) {
                _exit(114);
            }

            /* A repeated publish and a cancel-after-publish are both invalid.
             * Neither may consume the PUBLISHED transaction or remove its
             * blocker; successful finalization below proves ownership survived. */
            cleared = 99U;
            if (accounts_reset_retirement_publish(
                    &ctx, token, &cleared) != -1 || cleared != 0U ||
                errno != EBUSY ||
                get_last_error()->code != ERR_SYSTEM_CALL ||
                accounts_reset_retirement_cancel(&ctx, token) != -1 ||
                errno != EBUSY ||
                get_last_error()->code != ERR_SYSTEM_CALL ||
                m18_git_has_command(fixture) ||
                !m18_guard_is_private_and_blocking(fixture, "reset")) {
                _exit(107);
            }
            if (accounts_reset_retirement_finalize(
                    &ctx, token,
                    ACCOUNTS_RETIREMENT_SAVE_DURABLE) != 0 ||
                !m18_guard_is_unblocked_and_bounded(fixture) ||
                m18_git_has_command(fixture)) {
                _exit(108);
            }
        }

        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(109);
        }
        _exit(0);
    }
    return m18_wait_status(child);
}

static bool m18_state_has_active_work_header(
    const m18_fixture_t *fixture) {
    static const char expected[] = "ssh\nactive=work\n";
    m18_bytes_t state = {0};
    bool matches = false;

    if (fixture && m18_read_bytes(fixture->state_path, &state) == 0) {
        matches = state.length >= sizeof(expected) - 1U &&
                  memcmp(state.data, expected,
                         sizeof(expected) - 1U) == 0;
    }
    m18_bytes_clear(&state);
    return matches;
}

static bool m18_record_equal_except_post_config(
    const publication_record_t *left,
    const publication_record_t *right) {
    publication_record_t left_copy;
    publication_record_t right_copy;

    if (!left || !right) return false;
    left_copy = *left;
    right_copy = *right;
    memset(&left_copy.post_config, 0, sizeof(left_copy.post_config));
    memset(&right_copy.post_config, 0, sizeof(right_copy.post_config));
    return memcmp(&left_copy, &right_copy, sizeof(left_copy)) == 0;
}

static bool m18_ledger_matches_live_restored_git(
    const m18_fixture_t *fixture) {
    publication_ledger_t ledger;
    const publication_record_t *record = NULL;
    const publication_record_t *live_generation = NULL;
    const publication_record_t *generations[1];
    publication_lookup_status_t lookup;
    bool matches = false;

    publication_ledger_init(&ledger);
    if (!fixture ||
        config_load_publication_ledger(fixture->accounts_path, &ledger) != 0) {
        publication_ledger_clear(&ledger);
        return false;
    }
    lookup = publication_ledger_find(
        &ledger, UINT32_C(1), M18_INCARNATION,
        PUBLICATION_SCOPE_GLOBAL, fixture->git_path, "", &record);
    if (lookup == PUBLICATION_LOOKUP_FOUND && record &&
        record->state == PUBLICATION_STATE_PUBLISHED &&
        m18_record_equal_except_post_config(record, &fixture->record)) {
        generations[0] = record;
        matches = publication_record_verify_live_destination(
                      record, generations, 1U, &live_generation) == 0 &&
                  live_generation == record;
    }
    publication_ledger_clear(&ledger);
    return matches;
}

static bool m18_shared_ledger_matches_all_live_destinations(
    const m18_fixture_t *fixture) {
    publication_ledger_t ledger;
    const publication_record_t *generations[
        PUBLICATION_LEDGER_MAX_RECORDS];
    const publication_record_t *observed[3] = {NULL, NULL, NULL};
    const publication_record_t *expected[3];
    const publication_record_t *live_generation = NULL;
    bool matches = false;

    publication_ledger_init(&ledger);
    if (!fixture) return false;
    expected[0] = &fixture->record;
    expected[1] = &fixture->shared_record;
    expected[2] = &fixture->no_op_record;
    if (config_load_publication_ledger(fixture->accounts_path, &ledger) != 0 ||
        ledger.count != 3U) {
        goto cleanup;
    }
    for (size_t i = 0U; i < ledger.count; i++) {
        generations[i] = &ledger.records[i];
    }
    for (size_t i = 0U; i < 3U; i++) {
        if (publication_ledger_find(
                &ledger, expected[i]->account_id,
                expected[i]->account_incarnation,
                expected[i]->scope, expected[i]->config_path,
                expected[i]->repository_path,
                &observed[i]) != PUBLICATION_LOOKUP_FOUND ||
            !observed[i] ||
            observed[i]->state != PUBLICATION_STATE_PUBLISHED ||
            !m18_record_equal_except_post_config(observed[i], expected[i]) ||
            publication_record_verify_live_destination(
                observed[i], generations, ledger.count,
                &live_generation) != 0 ||
            !live_generation ||
            !publication_record_same_config_destination(
                observed[i], live_generation) ||
            !publication_identity_equal(&observed[i]->post_config,
                                        &live_generation->post_config)) {
            goto cleanup;
        }
    }
    /* The shared physical namespace is emitted once by the transaction but
     * must rebind both owners. The independent no-op namespace remains the
     * exact previously sealed generation. */
    matches = publication_identity_equal(&observed[0]->post_config,
                                         &observed[1]->post_config) &&
              publication_identity_equal(&observed[2]->post_config,
                                         &expected[2]->post_config);

cleanup:
    publication_ledger_clear(&ledger);
    return matches;
}

static bool m18_guard_is_unblocked_and_bounded(
    const m18_fixture_t *fixture) {
    static const char clear_prefix[] = ".retirement-incomplete.clear.";
    static const char incomplete_create_prefix[] =
        ".retirement-incomplete.create.";
    static const char complete_create_prefix[] =
        ".retirement-complete.create.";
    static const char transition_stage[] = ".retirement-transition";
    struct dirent *entry;
    DIR *directory;
    bool blocked = true;
    bool bounded = true;
    bool scan_complete;

    if (!fixture ||
        config_retirement_guard_probe(fixture->accounts_path,
                                      &blocked) != 0 || blocked) {
        return false;
    }
    directory = opendir(fixture->config_dir);
    if (!directory) return false;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, clear_prefix,
                    sizeof(clear_prefix) - 1U) == 0 ||
            strncmp(entry->d_name, incomplete_create_prefix,
                    sizeof(incomplete_create_prefix) - 1U) == 0 ||
            strncmp(entry->d_name, complete_create_prefix,
                    sizeof(complete_create_prefix) - 1U) == 0 ||
            strcmp(entry->d_name, transition_stage) == 0) {
            bounded = false;
            break;
        }
    }
    scan_complete = entry != NULL || errno == 0;
    if (closedir(directory) != 0) return false;
    return scan_complete && bounded;
}

static bool m18_backup_absent(const m18_fixture_t *fixture) {
    static const char prefix[] = "accounts.toml.backup.";
    struct dirent *entry;
    DIR *dir;
    bool absent = true;
    bool scan_complete;

    if (!fixture) return false;
    dir = opendir(fixture->config_dir);
    if (!dir) return false;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) == 0) {
            absent = false;
            break;
        }
    }
    scan_complete = entry != NULL || errno == 0;
    if (closedir(dir) != 0) return false;
    return scan_complete && absent;
}

static bool m18_guard_is_private_and_blocking(
    const m18_fixture_t *fixture, const char *operation) {
    struct stat st;
    m18_bytes_t marker = {0};
    char operation_line[64];
    bool blocked = false;
    bool valid = false;

    if (!fixture || !operation ||
        safe_snprintf(operation_line, sizeof(operation_line),
                      "operation=%s\n", operation) != 0 ||
        lstat(fixture->guard_path, &st) != 0 ||
        !S_ISREG(st.st_mode) || (st.st_mode & 0777U) != 0600U ||
        st.st_uid != geteuid() ||
        config_retirement_guard_probe(fixture->accounts_path,
                                      &blocked) != 0 ||
        !blocked || m18_read_bytes(fixture->guard_path, &marker) != 0) {
        m18_bytes_clear(&marker);
        return false;
    }
    valid = strstr((const char *)marker.data,
                   "gitswitch-retirement-incomplete-v1\n") != NULL &&
            strstr((const char *)marker.data, operation_line) != NULL &&
            strstr((const char *)marker.data, "owners=1\n") != NULL &&
            strstr((const char *)marker.data,
                   "owner=1:" M18_INCARNATION "\n") != NULL;
    m18_bytes_clear(&marker);
    return valid;
}

static bool m18_output_contains(const m18_bytes_t *output,
                                const char *expected) {
    const char *text = output && output->data
                           ? (const char *)output->data
                           : "";

    return expected && strstr(text, expected) != NULL;
}

static const char *m18_boundary_name(config_io_boundary_t boundary) {
    switch (boundary) {
        case CONFIG_IO_STATE_AFTER_TEMP:
            return "state-after-temp";
        case CONFIG_IO_STATE_AFTER_WRITE:
            return "state-after-write";
        case CONFIG_IO_STATE_BEFORE_FILE_SYNC:
            return "state-before-file-sync";
        case CONFIG_IO_STATE_BEFORE_CLOSE:
            return "state-before-close";
        case CONFIG_IO_STATE_BEFORE_RENAME:
            return "state-before-rename";
        case CONFIG_IO_STATE_BEFORE_DIR_SYNC:
            return "state-before-dir-sync";
        case CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK:
            return "backup-after-first-chunk";
        case CONFIG_IO_BACKUP_BEFORE_FILE_SYNC:
            return "backup-before-file-sync";
        case CONFIG_IO_BACKUP_BEFORE_DIR_SYNC:
            return "backup-before-dir-sync";
        case CONFIG_IO_BACKUP_BEFORE_REOPEN:
            return "backup-before-reopen";
        case CONFIG_IO_DOCUMENT_BEFORE_RENAME:
            return "document-before-rename";
        case CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC:
            return "document-before-dir-sync";
        case CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ:
            return "backup-verification-after-prefix-read";
        default:
            return "unknown-boundary";
    }
}

#define M18_CASE_CHECK(case_name, condition)                                  \
    do {                                                                      \
        bool m18_case_passed_ = !!(condition);                                \
        if (!m18_case_passed_) {                                              \
            fprintf(stderr, "  M18 case %s failed: %s\n",                  \
                    (case_name), #condition);                                 \
        }                                                                     \
        CHECK(m18_case_passed_);                                              \
    } while (0)

static bool m18_accounts_omit_work(const m18_fixture_t *fixture) {
    m18_bytes_t accounts = {0};
    bool omitted = false;

    if (fixture && m18_read_bytes(fixture->accounts_path, &accounts) == 0) {
        omitted = strstr((const char *)accounts.data,
                         "name = \"work\"") == NULL &&
                  strstr((const char *)accounts.data,
                         "active_account = \"work\"") == NULL;
    }
    m18_bytes_clear(&accounts);
    return omitted;
}

static void m18_exercise_clean_rollback_after_matches(
    m18_command_t command, config_io_boundary_t boundary,
    size_t fault_matches_to_skip, bool require_backup_cleanup) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    const char *case_name = m18_boundary_name(boundary);
    int status;

    if (m18_fixture_setup(&fixture) != 0) {
        M18_CASE_CHECK(case_name, false);
        m18_fixture_cleanup(&fixture);
        return;
    }
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.accounts_path,
                                  &accounts_before) == 0);
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.git_path, &git_before) == 0);
    M18_CASE_CHECK(case_name, m18_git_has_command(&fixture));
    if (require_backup_cleanup) {
        M18_CASE_CHECK(case_name, m18_backup_absent(&fixture));
    }

    status = m18_run_cli_after_matches(
        &fixture, command, M18_FAULT_ONCE, boundary,
        fault_matches_to_skip, &observed);
    M18_CASE_CHECK(case_name,
                   WIFEXITED(status) &&
                   WEXITSTATUS(status) == EXIT_FAILURE);
    M18_CASE_CHECK(case_name, observed);
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.accounts_path,
                                   &accounts_before));
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.git_path, &git_before));
    M18_CASE_CHECK(case_name, m18_git_has_command(&fixture));
    M18_CASE_CHECK(case_name,
                   m18_state_has_active_work_header(&fixture));
    M18_CASE_CHECK(case_name,
                   m18_ledger_matches_live_restored_git(&fixture));
    M18_CASE_CHECK(
        case_name, m18_guard_is_unblocked_and_bounded(&fixture));
    if (require_backup_cleanup) {
        M18_CASE_CHECK(case_name, m18_backup_absent(&fixture));
    }
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.output_path, &output) == 0);
    if (boundary == CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ) {
        M18_CASE_CHECK(
            case_name,
            m18_output_contains(
                &output, "config document consistency checkpoint"));
    }
    M18_CASE_CHECK(case_name,
                   !m18_output_contains(
                       &output, "Cleared ") &&
                   !m18_output_contains(
                       &output, "durable Git identity setting(s)"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

static void m18_exercise_clean_rollback(m18_command_t command,
                                        config_io_boundary_t boundary) {
    m18_exercise_clean_rollback_after_matches(command, boundary, 0U, false);
}

static void m18_exercise_uncertain_install(
    m18_command_t command, config_io_boundary_t boundary,
    const char *operation, bool account_deleted) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t accounts_after_failure = {0};
    m18_bytes_t state_after_failure = {0};
    m18_bytes_t git_after_failure = {0};
    m18_bytes_t marker_after_failure = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    const char *case_name = m18_boundary_name(boundary);
    int status;

    if (m18_fixture_setup(&fixture) != 0) {
        M18_CASE_CHECK(case_name, false);
        m18_fixture_cleanup(&fixture);
        return;
    }
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.accounts_path,
                                  &accounts_before) == 0);

    status = m18_run_cli(&fixture, command, M18_FAULT_ONCE,
                         boundary, &observed);
    M18_CASE_CHECK(case_name,
                   WIFEXITED(status) &&
                   WEXITSTATUS(status) == EXIT_FAILURE);
    M18_CASE_CHECK(case_name, observed);
    if (account_deleted) {
        M18_CASE_CHECK(case_name, m18_accounts_omit_work(&fixture));
    } else {
        M18_CASE_CHECK(case_name,
                       m18_file_equals(fixture.accounts_path,
                                       &accounts_before));
    }
    M18_CASE_CHECK(case_name, !m18_git_has_command(&fixture));
    M18_CASE_CHECK(case_name,
                   m18_guard_is_private_and_blocking(&fixture,
                                                      operation));
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.accounts_path,
                                  &accounts_after_failure) == 0);
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.state_path,
                                  &state_after_failure) == 0);
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.git_path,
                                  &git_after_failure) == 0);
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.guard_path,
                                  &marker_after_failure) == 0);

    status = m18_run_cli(&fixture, M18_COMMAND_RESUME, M18_FAULT_NONE,
                         CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    M18_CASE_CHECK(case_name,
                   WIFEXITED(status) &&
                   WEXITSTATUS(status) == EXIT_FAILURE);
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.accounts_path,
                                   &accounts_after_failure));
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.state_path,
                                   &state_after_failure));
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.git_path,
                                   &git_after_failure));
    M18_CASE_CHECK(case_name,
                   m18_file_equals(fixture.guard_path,
                                   &marker_after_failure));
    M18_CASE_CHECK(case_name, !m18_git_has_command(&fixture));
    M18_CASE_CHECK(case_name,
                   m18_guard_is_private_and_blocking(&fixture,
                                                      operation));
    M18_CASE_CHECK(case_name,
                   m18_read_bytes(fixture.output_path, &output) == 0);
    M18_CASE_CHECK(case_name,
                   m18_output_contains(
                       &output,
                       "Cannot resume while Git retirement is incomplete"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&accounts_after_failure);
    m18_bytes_clear(&state_after_failure);
    m18_bytes_clear(&git_after_failure);
    m18_bytes_clear(&marker_after_failure);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_save_boundary_matrix_preserves_outer_coherence) {
    static const config_io_boundary_t clean_boundaries[] = {
        CONFIG_IO_STATE_AFTER_TEMP,
        CONFIG_IO_STATE_AFTER_WRITE,
        CONFIG_IO_STATE_BEFORE_FILE_SYNC,
        CONFIG_IO_STATE_BEFORE_CLOSE,
        CONFIG_IO_STATE_BEFORE_RENAME,
        CONFIG_IO_STATE_BEFORE_DIR_SYNC,
        CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK,
        CONFIG_IO_BACKUP_BEFORE_FILE_SYNC,
        CONFIG_IO_BACKUP_BEFORE_DIR_SYNC,
        CONFIG_IO_BACKUP_BEFORE_REOPEN,
        CONFIG_IO_DOCUMENT_BEFORE_RENAME
    };

    for (size_t i = 0U;
         i < sizeof(clean_boundaries) / sizeof(clean_boundaries[0]); i++) {
        m18_exercise_clean_rollback(M18_COMMAND_REMOVE,
                                    clean_boundaries[i]);
    }
    m18_exercise_uncertain_install(
        M18_COMMAND_REMOVE, CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC,
        "remove", true);
}

TEST(remove_backup_verification_fault_restores_exact_outer_state) {
    /* The first prefix-read checkpoint belongs to initial accounts.toml load.
     * Let that read succeed, then fail the second occurrence while the
     * post-retirement save verifies its newly copied recovery backup. */
    m18_exercise_clean_rollback_after_matches(
        M18_COMMAND_REMOVE, CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ,
        1U, true);
}

TEST(reset_state_boundary_matrix_preserves_outer_coherence) {
    static const config_io_boundary_t clean_boundaries[] = {
        CONFIG_IO_STATE_AFTER_TEMP,
        CONFIG_IO_STATE_AFTER_WRITE,
        CONFIG_IO_STATE_BEFORE_FILE_SYNC,
        CONFIG_IO_STATE_BEFORE_CLOSE,
        CONFIG_IO_STATE_BEFORE_RENAME
    };

    for (size_t i = 0U;
         i < sizeof(clean_boundaries) / sizeof(clean_boundaries[0]); i++) {
        m18_exercise_clean_rollback(M18_COMMAND_RESET,
                                    clean_boundaries[i]);
    }
    m18_exercise_uncertain_install(
        M18_COMMAND_RESET, CONFIG_IO_STATE_BEFORE_DIR_SYNC,
        "reset", false);
}

TEST(reset_persistent_preinstall_fault_retains_guard_and_blocks_switch) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t state_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t marker_before_switch = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path, &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path, &state_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    status = m18_run_cli(&fixture, M18_COMMAND_RESET, SIZE_MAX,
                         CONFIG_IO_STATE_BEFORE_RENAME, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.state_path, &state_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "reset"));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path,
                                &marker_before_switch), 0);

    status = m18_run_cli(&fixture, M18_COMMAND_SWITCH, M18_FAULT_NONE,
                         CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.state_path, &state_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_file_equals(fixture.guard_path, &marker_before_switch));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "Cannot switch accounts while Git retirement is incomplete"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&state_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&marker_before_switch);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(reset_all_clean_rollback_refreshes_shared_and_no_op_destinations) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t changed_git_before = {0};
    m18_bytes_t no_op_git_before = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &changed_git_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.no_op_git_path,
                                &no_op_git_before), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_RESET_ALL, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &changed_git_before));
    CHECK(m18_file_equals(fixture.no_op_git_path, &no_op_git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_shared_ledger_matches_all_live_destinations(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&changed_git_before);
    m18_bytes_clear(&no_op_git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(reset_retirement_phase_rejections_preserve_pending_owner) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_phase_contract(&fixture, M18_PHASE_COMPLETE);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    m18_fixture_cleanup(&fixture);

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_phase_contract(&fixture, M18_PHASE_CANCEL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK(m18_git_has_command(&fixture));
    m18_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(remove_save_boundary_matrix_preserves_outer_coherence);
    RUN_TEST(remove_backup_verification_fault_restores_exact_outer_state);
    RUN_TEST(reset_state_boundary_matrix_preserves_outer_coherence);
    RUN_TEST(reset_persistent_preinstall_fault_retains_guard_and_blocks_switch);
    RUN_TEST(reset_all_clean_rollback_refreshes_shared_and_no_op_destinations);
    RUN_TEST(reset_retirement_phase_rejections_preserve_pending_owner);
TEST_MAIN_END()
