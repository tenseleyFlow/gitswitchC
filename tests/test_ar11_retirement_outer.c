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
#include "ssh_manager.h"
#include "utils.h"

#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <sys/wait.h>
#include <time.h>

#define M18_INCARNATION \
    "1818181818181818181818181818181818181818181818181818181818181818"
#define M18_SECOND_INCARNATION \
    "2828282828282828282828282828282828282828282828282828282828282828"
#define M24_ALIAS "github.com-work"

int gitswitch_cli_main(int argc, char **argv);
int gitswitch_test_context_allocations(void);

typedef enum {
    GIT_RETIREMENT_TEST_LOCKED_READ = 1,
    GIT_RETIREMENT_TEST_BEFORE_REMOVE,
    GIT_RETIREMENT_TEST_BEFORE_PUBLISH,
    GIT_RETIREMENT_TEST_BEFORE_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_CLEANUP,
    GIT_RETIREMENT_TEST_FORCE_EXCHANGE_FALLBACK,
    GIT_RETIREMENT_TEST_CLEANUP_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH,
    GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE,
    GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE,
    GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF
} git_retirement_test_stage_t;
typedef bool (*git_retirement_test_hook_fn)(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value);
git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn);

typedef enum {
    RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE = 0,
    RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
    RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
    RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
    RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
    RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
    RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC
} retirement_guard_clear_test_stage_t;
typedef int (*retirement_guard_clear_test_hook_fn)(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name);
retirement_guard_clear_test_hook_fn
gitswitch_test_set_retirement_guard_clear_hook(
    retirement_guard_clear_test_hook_fn hook);
typedef void (*remove_test_hook_fn)(int stage);
remove_test_hook_fn gitswitch_test_set_remove_hook(
    remove_test_hook_fn hook);

typedef enum {
    M18_COMMAND_REMOVE = 0,
    M18_COMMAND_REMOVE_NUMERIC,
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
    char config_parent[MAX_PATH_LEN];
    char runtime[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    char accounts_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char guard_path[MAX_PATH_LEN];
    char completion_path[MAX_PATH_LEN];
    char transition_path[MAX_PATH_LEN];
    char output_path[MAX_PATH_LEN];
    char git_trace_path[MAX_PATH_LEN];
    char git_path[MAX_PATH_LEN];
    char no_op_git_path[MAX_PATH_LEN];
    char shared_repository[MAX_PATH_LEN];
    char git_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    char ssh_key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    char ssh_config[MAX_PATH_LEN];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    account_t account;
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
static size_t m18_witness_ctime_drifts_remaining;
static int m18_witness_ctime_drift_error;
static bool m18_clear_after_stage_write_fault;
static bool m18_clear_after_stage_write_observed;
static bool m18_absent_recreation_requested;
static bool m18_absent_recreation_observed;
static bool m18_absent_recreation_guard_observed;
static int m18_absent_recreation_error;
static const m18_fixture_t *m18_absent_recreation_fixture;
static m18_bytes_t m18_absent_recreation_bytes;
static bool m24_alias_postrename_failure;
static bool m24_alias_dirsync_failure;
static bool m24_alias_prerename_failure;
static bool m24_alias_fault_observed;
static bool m24_recovery_claimant_requested;
static bool m24_recovery_claimant_observed;
static int m24_recovery_claimant_error;
static const m18_fixture_t *m24_recovery_claimant_fixture;
static bool m24_recovery_end_failure_requested;
static bool m24_recovery_end_failure_observed;
static char m24_home_override[MAX_PATH_LEN];

static int m18_write_file(const char *path, const void *data,
                          size_t length, mode_t mode);
static int m24_fixture_replace_with_live_alias_claimant(
    const m18_fixture_t *fixture);

static int m24_fail_alias_postrename(int dir_fd) {
    (void)dir_fd;
    m24_alias_fault_observed = true;
    errno = EIO;
    return -1;
}

static int m24_fail_alias_dirsync(int dir_fd) {
    (void)dir_fd;
    m24_alias_fault_observed = true;
    errno = EIO;
    return -1;
}

static int m24_fail_alias_prerename(int dir_fd, const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    m24_alias_fault_observed = true;
    errno = EIO;
    return -1;
}

static void m24_remove_recovery_checkpoint(int stage) {
    if (stage != 5 || !m24_recovery_claimant_requested ||
        m24_recovery_claimant_observed) {
        return;
    }
    m24_recovery_claimant_observed = true;
    if (!m24_recovery_claimant_fixture ||
        m24_fixture_replace_with_live_alias_claimant(
            m24_recovery_claimant_fixture) != 0) {
        m24_recovery_claimant_error = errno ? errno : EIO;
    }
}

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

static int m18_retirement_clear_fault(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name) {
    (void)descriptor;
    (void)marker_name;
    if (!m18_clear_after_stage_write_fault ||
        stage != RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE) {
        return 0;
    }
    m18_clear_after_stage_write_fault = false;
    m18_clear_after_stage_write_observed = true;
    errno = EIO;
    return -1;
}

static bool m18_same_ctime(const struct stat *left,
                           const struct stat *right) {
#if defined(__APPLE__)
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool m18_same_without_ctime(const struct stat *left,
                                   const struct stat *right) {
    if (left->st_dev != right->st_dev ||
        left->st_ino != right->st_ino ||
        left->st_mode != right->st_mode ||
        left->st_uid != right->st_uid ||
        left->st_gid != right->st_gid ||
        left->st_nlink != right->st_nlink ||
        left->st_size != right->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static int m18_force_ctime_only_drift(const char *path) {
    const struct timespec retry = {.tv_sec = 0, .tv_nsec = 1000000L};
    struct stat before;
    struct stat after;
    mode_t original_mode;
    mode_t transient_mode;

    if (!path || lstat(path, &before) != 0) return -1;
    original_mode = before.st_mode & 07777;
    transient_mode = original_mode ^ S_IXUSR;
    for (size_t attempt = 0U; attempt < 128U; attempt++) {
        if (chmod(path, transient_mode) != 0 ||
            chmod(path, original_mode) != 0 ||
            lstat(path, &after) != 0 ||
            !m18_same_without_ctime(&before, &after)) {
            errno = errno ? errno : ESTALE;
            return -1;
        }
        if (!m18_same_ctime(&before, &after)) return 0;
        (void)nanosleep(&retry, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static bool m18_retirement_witness_hook(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value) {
    (void)key;
    (void)value;
    if (stage ==
            GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF &&
        m24_recovery_end_failure_requested) {
        m24_recovery_end_failure_observed = true;
        return true;
    }
    if (stage == GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE &&
        m18_absent_recreation_requested) {
        if (m18_absent_recreation_observed) return false;
        m18_absent_recreation_observed = true;
        if (!m18_absent_recreation_fixture || !path ||
            strcmp(path, m18_absent_recreation_fixture->git_path) != 0) {
            m18_absent_recreation_error = ESTALE;
            return false;
        }
        m18_absent_recreation_guard_observed =
            m18_guard_is_private_and_blocking(
                m18_absent_recreation_fixture, "remove");
        if (!m18_absent_recreation_guard_observed) {
            m18_absent_recreation_error = EPERM;
            return false;
        }
        if (m18_write_file(
                m18_absent_recreation_fixture->git_path,
                m18_absent_recreation_bytes.data,
                m18_absent_recreation_bytes.length, 0600) != 0) {
            m18_absent_recreation_error = errno ? errno : EIO;
        }
        return false;
    }
    if (stage != GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE ||
        m18_witness_ctime_drifts_remaining == 0U) {
        return false;
    }
    if (m18_force_ctime_only_drift(path) != 0) {
        m18_witness_ctime_drift_error = errno ? errno : EIO;
        m18_witness_ctime_drifts_remaining = 0U;
        return false;
    }
    m18_witness_ctime_drifts_remaining--;
    return false;
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

static int m18_generate_ssh_key(const char *path) {
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

static int m18_build_ssh_command(m18_fixture_t *fixture) {
    const char *path = getenv("PATH");
    char *saved_path = path ? strdup(path) : NULL;
    int result = -1;
    int restore_result;

    if (!fixture || (path && !saved_path) ||
        setenv("PATH", fixture->home, 1) != 0) {
        free(saved_path);
        return -1;
    }
    result = git_expected_ssh_command(
        &fixture->account, fixture->ssh_command,
        sizeof(fixture->ssh_command));
    restore_result = path ? setenv("PATH", saved_path, 1)
                          : unsetenv("PATH");
    free(saved_path);
    return restore_result == 0 ? result : -1;
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
        "export PATH\n"
        "if [ -n \"${GITSWITCH_TEST_GIT_TRACE:-}\" ]; then\n"
        "  printf '%s\\n' \"$*\" >> \"$GITSWITCH_TEST_GIT_TRACE\"\n"
        "fi\n"
        "exec git \"$@\"\n";
    char config_body[2U * MAX_PATH_LEN];
    char git_body[PUBLICATION_SSH_COMMAND_MAX + 128U];
    struct stat st;
    int written;

    if (!fixture) return -1;
    memset(fixture, 0, sizeof(*fixture));
    if (!ts_mkdtemp_trusted(fixture->root, sizeof(fixture->root),
                            "gsw-ar11-m18") ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home),
                      "%s/home", fixture->root) != 0 ||
        safe_snprintf(fixture->runtime, sizeof(fixture->runtime),
                      "%s/runtime", fixture->root) != 0 ||
        safe_snprintf(fixture->config_parent,
                      sizeof(fixture->config_parent),
                      "%s/.config", fixture->home) != 0 ||
        safe_snprintf(fixture->config_dir, sizeof(fixture->config_dir),
                      "%s/gitswitch", fixture->config_parent) != 0 ||
        safe_snprintf(fixture->accounts_path,
                      sizeof(fixture->accounts_path),
                      "%s/accounts.toml", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->state_path, sizeof(fixture->state_path),
                      "%s/.resume-hint", fixture->config_dir) != 0 ||
        safe_snprintf(fixture->guard_path, sizeof(fixture->guard_path),
                      "%s/.retirement-incomplete",
                      fixture->config_dir) != 0 ||
        safe_snprintf(fixture->completion_path,
                      sizeof(fixture->completion_path),
                      "%s/.retirement-complete",
                      fixture->config_dir) != 0 ||
        safe_snprintf(fixture->transition_path,
                      sizeof(fixture->transition_path),
                      "%s/.retirement-transition",
                      fixture->config_dir) != 0 ||
        safe_snprintf(fixture->output_path, sizeof(fixture->output_path),
                      "%s/output", fixture->root) != 0 ||
        safe_snprintf(fixture->git_trace_path,
                      sizeof(fixture->git_trace_path),
                      "%s/git.trace", fixture->root) != 0 ||
        safe_snprintf(fixture->git_path, sizeof(fixture->git_path),
                      "%s/.gitconfig", fixture->home) != 0 ||
        safe_snprintf(fixture->git_program,
                      sizeof(fixture->git_program),
                      "%s/git", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_program,
                      sizeof(fixture->ssh_program),
                      "%s/ssh", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_key, sizeof(fixture->ssh_key),
                      "%s/id_key", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_dir, sizeof(fixture->ssh_dir),
                      "%s/.ssh", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_config, sizeof(fixture->ssh_config),
                      "%s/config", fixture->ssh_dir) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        mkdir(fixture->runtime, 0700) != 0 ||
        mkdir(fixture->config_parent, 0700) != 0 ||
        mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if (m18_write_file(fixture->git_program, git_program_body,
                       sizeof(git_program_body) - 1U, 0700) != 0 ||
        m18_write_file(fixture->ssh_program, ssh_program_body,
                       sizeof(ssh_program_body) - 1U, 0700) != 0 ||
        m18_write_file(fixture->git_trace_path, "", 0U, 0600) != 0 ||
        m18_generate_ssh_key(fixture->ssh_key) != 0) {
        return -1;
    }
    fixture->account.ssh_enabled = true;
    if (safe_strncpy(fixture->account.ssh_key_path, fixture->ssh_key,
                     sizeof(fixture->account.ssh_key_path)) != 0 ||
        m18_build_ssh_command(fixture) != 0) {
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

static int m24_fixture_add_managed_alias(m18_fixture_t *fixture) {
    char config_body[2U * MAX_PATH_LEN];
    char ssh_body[2U * MAX_PATH_LEN];
    int config_written;
    int ssh_written;

    if (!fixture || mkdir(fixture->ssh_dir, 0700) != 0) return -1;
    config_written = snprintf(
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
        "ssh_host = \"" M24_ALIAS "\"\n"
        "ssh_hostname = \"github.com\"\n",
        M18_INCARNATION, fixture->ssh_key);
    ssh_written = snprintf(
        ssh_body, sizeof(ssh_body),
        "Host preserved\n"
        "  User git\n"
        "# >>> gitswitch " M24_ALIAS " >>>\n"
        "Host " M24_ALIAS "\n"
        "  HostName github.com\n"
        "  IdentityFile \"%s\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch " M24_ALIAS " <<<\n",
        fixture->ssh_key);
    if (config_written < 0 ||
        (size_t)config_written >= sizeof(config_body) ||
        ssh_written < 0 || (size_t)ssh_written >= sizeof(ssh_body) ||
        m18_write_file(fixture->accounts_path, config_body,
                       (size_t)config_written, 0600) != 0 ||
        m18_write_file(fixture->ssh_config, ssh_body,
                       (size_t)ssh_written, 0600) != 0) {
        return -1;
    }
    return 0;
}

static int m24_fixture_replace_with_live_alias_claimant(
    const m18_fixture_t *fixture) {
    char config_body[2U * MAX_PATH_LEN];
    int written;

    if (!fixture) return -1;
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "[accounts.2]\n"
        "incarnation = \"%s\"\n"
        "name = \"replacement\"\n"
        "email = \"replacement@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n"
        "ssh_host = \"" M24_ALIAS "\"\n"
        "ssh_hostname = \"github.com\"\n",
        M18_SECOND_INCARNATION, fixture->ssh_key);
    if (written < 0 || (size_t)written >= sizeof(config_body)) return -1;
    return m18_write_file(fixture->accounts_path, config_body,
                          (size_t)written, 0600);
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

static int m18_fixture_use_local_repository(m18_fixture_t *fixture) {
    m18_bytes_t global_config = {0};
    char git_dir[MAX_PATH_LEN];
    char local_config[MAX_PATH_LEN];
    struct stat st;
    int result = -1;

    if (!fixture ||
        m18_read_bytes(fixture->git_path, &global_config) != 0 ||
        safe_snprintf(fixture->shared_repository,
                      sizeof(fixture->shared_repository),
                      "%s/repository", fixture->root) != 0 ||
        safe_snprintf(git_dir, sizeof(git_dir), "%s/.git",
                      fixture->shared_repository) != 0 ||
        safe_snprintf(local_config, sizeof(local_config), "%s/config",
                      git_dir) != 0 ||
        mkdir(fixture->shared_repository, 0700) != 0 ||
        mkdir(git_dir, 0700) != 0 ||
        m18_write_file(local_config, global_config.data,
                       global_config.length, 0600) != 0 ||
        safe_strncpy(fixture->git_path, local_config,
                     sizeof(fixture->git_path)) != 0) {
        goto cleanup;
    }

    fixture->record.scope = PUBLICATION_SCOPE_LOCAL;
    if (safe_strncpy(fixture->record.config_path, fixture->git_path,
                     sizeof(fixture->record.config_path)) != 0 ||
        safe_strncpy(fixture->record.repository_path,
                     fixture->shared_repository,
                     sizeof(fixture->record.repository_path)) != 0 ||
        stat(git_dir, &st) != 0) {
        goto cleanup;
    }
    publication_identity_from_stat(&fixture->record.config_parent, &st);
    if (stat(fixture->git_path, &st) != 0) goto cleanup;
    publication_identity_from_stat(&fixture->record.post_config, &st);
    if (stat(fixture->shared_repository, &st) != 0) goto cleanup;
    publication_identity_from_stat(&fixture->record.repository, &st);
    if (publication_record_validate(&fixture->record) != 0 ||
        m18_write_state(fixture) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    m18_bytes_clear(&global_config);
    return result;
}

static int m18_fixture_reintroduce_id_with_new_incarnation(
    const m18_fixture_t *fixture) {
    char config_body[2U * MAX_PATH_LEN];
    int written;

    if (!fixture) return -1;
    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "[accounts.1]\n"
        "incarnation = \"%s\"\n"
        "name = \"replacement\"\n"
        "email = \"replacement@example.test\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n",
        M18_SECOND_INCARNATION, fixture->ssh_key);
    if (written < 0 || (size_t)written >= sizeof(config_body)) return -1;
    return m18_write_file(fixture->accounts_path, config_body,
                          (size_t)written, 0600);
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
        char one[] = "1";
        char *remove_argv[] = {
            program, no_color, assume_yes, remove, work, NULL
        };
        char *remove_numeric_argv[] = {
            program, no_color, assume_yes, remove, one, NULL
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
        unsigned char observed = 0U;
        const char *command_home =
            m24_home_override[0] != '\0'
                ? m24_home_override
                : fixture->home;
        int rc;

        (void)close(observed_pipe[0]);
        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->home) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", command_home, 1) != 0 ||
            (m24_home_override[0] != '\0' &&
             setenv("XDG_CONFIG_HOME", fixture->config_parent, 1) != 0) ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_TEST_GIT_TRACE",
                   fixture->git_trace_path, 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            m18_redirect_output(fixture->output_path) != 0) {
            _exit(120);
        }
        switch (command) {
            case M18_COMMAND_REMOVE:
                argv = remove_argv;
                argc = 5;
                break;
            case M18_COMMAND_REMOVE_NUMERIC:
                argv = remove_numeric_argv;
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
        m18_witness_ctime_drift_error = 0;
        m18_clear_after_stage_write_observed = false;
        m18_absent_recreation_observed = false;
        m18_absent_recreation_guard_observed = false;
        m18_absent_recreation_error = 0;
        m24_alias_fault_observed = false;
        m24_recovery_claimant_observed = false;
        m24_recovery_claimant_error = 0;
        m24_recovery_end_failure_observed = false;
        if (fault_limit != M18_FAULT_NONE) {
            (void)config_set_io_fault_fn(m18_config_fault);
        }
        if (m18_clear_after_stage_write_fault) {
            (void)gitswitch_test_set_retirement_guard_clear_hook(
                m18_retirement_clear_fault);
        }
        if (m18_witness_ctime_drifts_remaining != 0U ||
            m18_absent_recreation_requested ||
            m24_recovery_end_failure_requested) {
            (void)git_ops_test_set_retirement_hook(
                m18_retirement_witness_hook);
        }
        if (m24_recovery_claimant_requested) {
            (void)gitswitch_test_set_remove_hook(
                m24_remove_recovery_checkpoint);
        }
        if (m24_alias_prerename_failure) {
            (void)ssh_manager_set_config_commit_hook_fn(
                m24_fail_alias_prerename);
        }
        if (m24_alias_postrename_failure) {
            (void)ssh_manager_set_config_postrename_hook_fn(
                m24_fail_alias_postrename);
        }
        if (m24_alias_dirsync_failure) {
            (void)ssh_manager_set_dirsync_fn(m24_fail_alias_dirsync);
        }
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        (void)gitswitch_test_set_remove_hook(NULL);
        (void)ssh_manager_set_config_commit_hook_fn(NULL);
        (void)ssh_manager_set_config_postrename_hook_fn(NULL);
        (void)ssh_manager_set_dirsync_fn(NULL);
        (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
        (void)git_ops_test_set_retirement_hook(NULL);
        if (m18_witness_ctime_drift_error != 0 ||
            m18_witness_ctime_drifts_remaining != 0U) {
            fprintf(stderr,
                    "[M18 restored-witness drift incomplete: remaining=%zu error=%d]\n",
                    m18_witness_ctime_drifts_remaining,
                    m18_witness_ctime_drift_error);
            _exit(124);
        }
        if (m18_absent_recreation_requested &&
            (!m18_absent_recreation_observed ||
             !m18_absent_recreation_guard_observed ||
             m18_absent_recreation_error != 0)) {
            fprintf(
                stderr,
                "[H3 absence hook incomplete: observed=%d guard=%d error=%d]\n",
                m18_absent_recreation_observed,
                m18_absent_recreation_guard_observed,
                m18_absent_recreation_error);
            _exit(125);
        }
        if (m24_recovery_claimant_requested &&
            (!m24_recovery_claimant_observed ||
             m24_recovery_claimant_error != 0)) {
            fprintf(
                stderr,
                "[M24 claimant hook incomplete: observed=%d error=%d]\n",
                m24_recovery_claimant_observed,
                m24_recovery_claimant_error);
            _exit(126);
        }
        if (m24_recovery_end_failure_requested &&
            !m24_recovery_end_failure_observed) {
            fprintf(stderr,
                    "[M24 recovery-end hook was not observed]\n");
            _exit(127);
        }
        if (m18_fault_observed ||
            m18_clear_after_stage_write_observed ||
            m18_absent_recreation_observed) {
            observed |= 1U;
        }
        if (m24_alias_fault_observed) observed |= 2U;
        if (m24_recovery_claimant_observed) observed |= 4U;
        if (m24_recovery_end_failure_observed) observed |= 8U;
        if (write(observed_pipe[1], &observed, 1U) != 1) _exit(121);
        (void)close(observed_pipe[1]);
        if (gitswitch_test_context_allocations() != 0) _exit(122);
        _exit(rc);
    }
    (void)close(observed_pipe[1]);
    {
        unsigned char observed = 0U;
        ssize_t got;

        do {
            got = read(observed_pipe[0], &observed, 1U);
        } while (got < 0 && errno == EINTR);
        if (fault_observed && got == 1) {
            *fault_observed = (observed & 1U) != 0U;
        }
        m24_alias_fault_observed =
            got == 1 && (observed & 2U) != 0U;
        m24_recovery_claimant_observed =
            got == 1 && (observed & 4U) != 0U;
        m24_recovery_end_failure_observed =
            got == 1 && (observed & 8U) != 0U;
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

static int m18_run_cli_with_clear_stage_failure(
    const m18_fixture_t *fixture, m18_command_t command,
    bool *fault_observed) {
    int status;

    m18_clear_after_stage_write_fault = true;
    status = m18_run_cli(
        fixture, command, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, fault_observed);
    m18_clear_after_stage_write_fault = false;
    return status;
}

static int m18_run_cli_with_witness_ctime_drifts(
    const m18_fixture_t *fixture, m18_command_t command,
    size_t fault_limit, config_io_boundary_t boundary,
    size_t witness_ctime_drifts, bool *fault_observed) {
    int status;

    m18_witness_ctime_drifts_remaining = witness_ctime_drifts;
    status = m18_run_cli(fixture, command, fault_limit, boundary,
                         fault_observed);
    m18_witness_ctime_drifts_remaining = 0U;
    return status;
}

static int m18_run_cli_with_absent_recreation(
    const m18_fixture_t *fixture, const m18_bytes_t *replacement,
    bool *hook_observed) {
    int status;

    if (!fixture || !replacement || !replacement->data) return -1;
    m18_absent_recreation_requested = true;
    m18_absent_recreation_fixture = fixture;
    m18_absent_recreation_bytes = *replacement;
    status = m18_run_cli(
        fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, hook_observed);
    m18_absent_recreation_requested = false;
    m18_absent_recreation_fixture = NULL;
    memset(&m18_absent_recreation_bytes, 0,
           sizeof(m18_absent_recreation_bytes));
    return status;
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

static bool m18_state_has_inactive_header(
    const m18_fixture_t *fixture) {
    static const char expected[] = "none\ninactive=v1\n";
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

static bool m18_ledger_has_exact_retiring_work(
    const m18_fixture_t *fixture) {
    publication_ledger_t ledger;
    publication_record_t expected;
    const publication_record_t *record = NULL;
    bool matches = false;

    publication_ledger_init(&ledger);
    if (!fixture ||
        config_load_publication_ledger(
            fixture->accounts_path, &ledger) != 0 ||
        ledger.count != 1U ||
        publication_ledger_find(
            &ledger, UINT32_C(1), M18_INCARNATION,
            fixture->record.scope, fixture->git_path,
            fixture->record.repository_path,
            &record) != PUBLICATION_LOOKUP_FOUND ||
        !record) {
        goto cleanup;
    }
    expected = fixture->record;
    expected.state = PUBLICATION_STATE_RETIRING;
    matches = record->state == PUBLICATION_STATE_RETIRING &&
              publication_record_validate(record) == 0 &&
              record->post_config.present &&
              m18_record_equal_except_post_config(record, &expected);

cleanup:
    publication_ledger_clear(&ledger);
    return matches;
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

static bool m18_guard_has_exact_completion_pair(
    const m18_fixture_t *fixture,
    const m18_bytes_t *expected_marker) {
    m18_bytes_t marker = {0};
    m18_bytes_t completion = {0};
    struct stat marker_stat;
    struct stat completion_stat;
    bool blocked = true;
    bool matches = false;

    if (!fixture || !expected_marker ||
        lstat(fixture->guard_path, &marker_stat) != 0 ||
        lstat(fixture->completion_path, &completion_stat) != 0 ||
        !S_ISREG(marker_stat.st_mode) ||
        !S_ISREG(completion_stat.st_mode) ||
        (marker_stat.st_mode & 0777U) != 0600U ||
        (completion_stat.st_mode & 0777U) != 0600U ||
        marker_stat.st_uid != geteuid() ||
        completion_stat.st_uid != geteuid() ||
        marker_stat.st_nlink != 1 ||
        completion_stat.st_nlink != 1 ||
        m18_read_bytes(fixture->guard_path, &marker) != 0 ||
        m18_read_bytes(fixture->completion_path, &completion) != 0 ||
        marker.length != expected_marker->length ||
        completion.length != expected_marker->length ||
        memcmp(marker.data, expected_marker->data, marker.length) != 0 ||
        memcmp(completion.data, expected_marker->data,
               completion.length) != 0 ||
        config_retirement_guard_probe(
            fixture->accounts_path, &blocked) != 0 ||
        blocked) {
        goto cleanup;
    }
    matches = (strstr(
                   (const char *)marker.data,
                   "gitswitch-retirement-incomplete-v1\n") != NULL ||
               strstr(
                   (const char *)marker.data,
                   "gitswitch-retirement-incomplete-v2\n") != NULL) &&
              strstr((const char *)marker.data,
                     "operation=remove\n") != NULL &&
              strstr((const char *)marker.data, "owners=1\n") != NULL &&
              strstr((const char *)marker.data,
                     "owner=1:" M18_INCARNATION "\n") != NULL;

cleanup:
    m18_bytes_clear(&marker);
    m18_bytes_clear(&completion);
    return matches;
}

static bool m18_transition_is_exact_private_marker(
    const m18_fixture_t *fixture,
    const m18_bytes_t *expected_marker) {
    m18_bytes_t transition = {0};
    struct stat transition_stat;
    bool matches = false;

    if (!fixture || !expected_marker ||
        lstat(fixture->transition_path, &transition_stat) != 0 ||
        !S_ISREG(transition_stat.st_mode) ||
        (transition_stat.st_mode & 0777U) != 0600U ||
        transition_stat.st_uid != geteuid() ||
        transition_stat.st_nlink != 1 ||
        m18_read_bytes(fixture->transition_path, &transition) != 0) {
        goto cleanup;
    }
    matches = transition.length == expected_marker->length &&
              memcmp(transition.data, expected_marker->data,
                     transition.length) == 0;

cleanup:
    m18_bytes_clear(&transition);
    return matches;
}

static bool m18_git_trace_has_unset(
    const m18_fixture_t *fixture) {
    m18_bytes_t trace = {0};
    bool found = false;

    if (fixture &&
        m18_read_bytes(fixture->git_trace_path, &trace) == 0) {
        found = strstr((const char *)trace.data, "--unset") != NULL;
    }
    m18_bytes_clear(&trace);
    return found;
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

static bool m18_completion_absent(const m18_fixture_t *fixture) {
    struct stat st;

    if (!fixture) return false;
    errno = 0;
    return lstat(fixture->completion_path, &st) == -1 &&
           errno == ENOENT;
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
    valid = (strstr((const char *)marker.data,
                    "gitswitch-retirement-incomplete-v1\n") != NULL ||
             strstr((const char *)marker.data,
                    "gitswitch-retirement-incomplete-v2\n") != NULL) &&
            strstr((const char *)marker.data, operation_line) != NULL &&
            strstr((const char *)marker.data, "owners=1\n") != NULL &&
            strstr((const char *)marker.data,
                   "owner=1:" M18_INCARNATION "\n") != NULL;
    m18_bytes_clear(&marker);
    return valid;
}

static bool m24_guard_has_exact_alias_obligation(
    const m18_fixture_t *fixture,
    const publication_identity_t *expected_home,
    const publication_identity_t *expected_ssh_directory) {
    config_retirement_recovery_t recovery;

    memset(&recovery, 0, sizeof(recovery));
    if (!fixture || !expected_home || !expected_ssh_directory ||
        config_retirement_guard_recovery_probe(
            fixture->accounts_path, &recovery) != 0 ||
        !recovery.valid || recovery.marker_version != 2U ||
        recovery.kind != CONFIG_RETIREMENT_REMOVE ||
        recovery.owner_count != 1U ||
        recovery.owners[0].account_id != UINT32_C(1) ||
        strcmp(recovery.owners[0].account_incarnation,
               M18_INCARNATION) != 0 ||
        !recovery.ssh_alias_obligation.known ||
        !recovery.ssh_alias_obligation.present ||
        strcmp(recovery.ssh_alias_obligation.ssh_host_alias,
               M24_ALIAS) != 0 ||
        strcmp(recovery.ssh_alias_obligation.home_path,
               fixture->home) != 0) {
        return false;
    }
    return publication_identity_equal(
               &recovery.ssh_alias_obligation.home_identity,
               expected_home) &&
           publication_identity_equal(
               &recovery.ssh_alias_obligation.ssh_directory_identity,
               expected_ssh_directory);
}

static bool m24_alias_is_absent(const m18_fixture_t *fixture) {
    m18_bytes_t config = {0};
    bool absent = false;

    if (fixture && m18_read_bytes(fixture->ssh_config, &config) == 0) {
        absent = strstr((const char *)config.data, M24_ALIAS) == NULL &&
                 strstr((const char *)config.data,
                        "Host preserved\n  User git\n") != NULL;
    }
    m18_bytes_clear(&config);
    return absent;
}

static int m24_capture_alias_namespace(
    const m18_fixture_t *fixture,
    publication_identity_t *home_identity,
    publication_identity_t *ssh_directory_identity) {
    struct stat home_st;
    struct stat ssh_st;

    if (!fixture || !home_identity || !ssh_directory_identity ||
        stat(fixture->home, &home_st) != 0 ||
        stat(fixture->ssh_dir, &ssh_st) != 0) {
        return -1;
    }
    publication_identity_from_stat(home_identity, &home_st);
    publication_identity_from_stat(ssh_directory_identity, &ssh_st);
    return 0;
}

static int m24_remove_publication_ledger(
    const m18_fixture_t *fixture) {
    static const char state[] = "ssh\nactive=work\n";

    if (!fixture) return -1;
    return m18_write_file(fixture->state_path, state,
                          sizeof(state) - 1U, 0600);
}

static int m24_rewrite_marker_as_v1_unknown(
    const m18_fixture_t *fixture) {
    static const char header[] =
        "gitswitch-retirement-incomplete-v2\n";
    static const char obligation[] = "ssh_obligation=none\n";
    m18_bytes_t marker = {0};
    char *obligation_line;
    int result = -1;

    if (!fixture || m18_read_bytes(fixture->guard_path, &marker) != 0 ||
        marker.length < sizeof(header) - 1U ||
        memcmp(marker.data, header, sizeof(header) - 1U) != 0) {
        goto done;
    }
    obligation_line = strstr(
        (char *)marker.data, obligation);
    if (!obligation_line ||
        (size_t)(obligation_line - (char *)marker.data) +
                sizeof(obligation) - 1U !=
            marker.length) {
        goto done;
    }
    marker.data[sizeof(header) - 3U] = '1';
    result = m18_write_file(
        fixture->guard_path, marker.data,
        (size_t)(obligation_line - (char *)marker.data), 0600);

done:
    m18_bytes_clear(&marker);
    return result;
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

TEST(remove_uncertain_install_recovers_in_fresh_process) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_after_failure = {0};
    m18_bytes_t state_after_failure = {0};
    m18_bytes_t git_after_failure = {0};
    m18_bytes_t marker_after_failure = {0};
    m18_bytes_t completion_after_recovery = {0};
    m18_bytes_t output = {0};
    struct stat marker_before_recovery;
    struct stat marker_after_recovery;
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path,
                                &state_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &git_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path,
                                &marker_after_failure), 0);
    CHECK_EQ_INT(lstat(fixture.guard_path, &marker_before_recovery), 0);

    /* This is a genuinely fresh process. The deleted account is no longer in
     * the normal account array, so only the durable remove owner and its
     * RETIRING publication tombstone can authorize exact settlement. */
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_after_failure));
    CHECK(m18_file_equals(fixture.state_path, &state_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK(m18_file_equals(fixture.guard_path, &marker_after_failure));
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK_EQ_INT(lstat(fixture.guard_path, &marker_after_recovery), 0);
    CHECK(m18_same_without_ctime(&marker_before_recovery,
                                 &marker_after_recovery));
    CHECK(m18_same_ctime(&marker_before_recovery,
                         &marker_after_recovery));
    CHECK(m18_guard_has_exact_completion_pair(
        &fixture, &marker_after_failure));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.completion_path,
                                &completion_after_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "Completed interrupted removal for account ID 1."));
    m18_bytes_clear(&output);

    /* Prove the exact pair really released the global retirement gate. An
     * activation command still fails because the requested account is gone,
     * but dispatch reaches that ordinary error instead of the fence. */
    status = m18_run_cli(
        &fixture, M18_COMMAND_SWITCH, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_after_failure));
    CHECK(m18_file_equals(fixture.state_path, &state_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK(m18_file_equals(fixture.guard_path, &marker_after_failure));
    CHECK(m18_file_equals(fixture.completion_path,
                          &completion_after_recovery));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(!m18_output_contains(
        &output, "Git retirement is incomplete"));
    CHECK(m18_output_contains(&output, "Failed to switch account"));

    m18_bytes_clear(&accounts_after_failure);
    m18_bytes_clear(&state_after_failure);
    m18_bytes_clear(&git_after_failure);
    m18_bytes_clear(&marker_after_failure);
    m18_bytes_clear(&completion_after_recovery);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_recovery_reconciles_interrupted_completion_stage) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_after_failure = {0};
    m18_bytes_t state_after_failure = {0};
    m18_bytes_t git_after_failure = {0};
    m18_bytes_t marker_after_failure = {0};
    struct stat marker_before_recovery;
    struct stat marker_after_recovery;
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path,
                                &state_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &git_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path,
                                &marker_after_failure), 0);
    CHECK_EQ_INT(lstat(fixture.guard_path, &marker_before_recovery), 0);

    /* Restart one reaches the completion transition's written-but-unpublished
     * boundary. Its exact private stage must remain a blocker; losing or
     * accepting it would respectively leak recovery or unblock ambiguity. */
    observed = false;
    status = m18_run_cli_with_clear_stage_failure(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(observed);
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_after_failure));
    CHECK(m18_file_equals(fixture.state_path, &state_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK(m18_file_equals(fixture.guard_path, &marker_after_failure));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK(m18_transition_is_exact_private_marker(
        &fixture, &marker_after_failure));

    /* Restart two must reconcile only that exact stage, re-prove the clean
     * Git tombstone, and publish its matching certificate. Trace the real Git
     * subprocess calls so byte stability cannot hide an unset-and-restore. */
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_trace_path, "", 0U, 0600), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_after_failure));
    CHECK(m18_file_equals(fixture.state_path, &state_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK(m18_file_equals(fixture.guard_path, &marker_after_failure));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_has_exact_completion_pair(
        &fixture, &marker_after_failure));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    errno = 0;
    CHECK(access(fixture.transition_path, F_OK) == -1 &&
          errno == ENOENT);
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK_EQ_INT(lstat(fixture.guard_path, &marker_after_recovery), 0);
    CHECK(m18_same_without_ctime(&marker_before_recovery,
                                 &marker_after_recovery));
    CHECK(m18_same_ctime(&marker_before_recovery,
                         &marker_after_recovery));

    m18_bytes_clear(&accounts_after_failure);
    m18_bytes_clear(&state_after_failure);
    m18_bytes_clear(&git_after_failure);
    m18_bytes_clear(&marker_after_failure);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_recovery_rejects_reintroduced_git_identity) {
    m18_fixture_t fixture;
    m18_bytes_t original_git = {0};
    m18_bytes_t accounts_before_recovery = {0};
    m18_bytes_t state_before_recovery = {0};
    m18_bytes_t git_before_recovery = {0};
    m18_bytes_t marker_before_recovery = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &original_git), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));

    /* Reintroduce the exact private-key route after its clean RETIRING
     * tombstone was sealed. Recovery must re-prove the destination under its
     * canonical Git lock; marker ownership alone cannot certify this residue. */
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_path, original_git.data,
                     original_git.length, 0600), 0);
    CHECK(m18_git_has_command(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path,
                                &state_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &git_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path,
                                &marker_before_recovery), 0);
    CHECK(m18_completion_absent(&fixture));

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_before_recovery));
    CHECK(m18_file_equals(fixture.state_path, &state_before_recovery));
    CHECK(m18_file_equals(fixture.git_path, &git_before_recovery));
    CHECK(m18_file_equals(fixture.guard_path, &marker_before_recovery));
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output,
        "Stale Git retirement destination still contains attributed values"));
    CHECK(!m18_output_contains(&output, "Account removed successfully"));

    m18_bytes_clear(&original_git);
    m18_bytes_clear(&accounts_before_recovery);
    m18_bytes_clear(&state_before_recovery);
    m18_bytes_clear(&git_before_recovery);
    m18_bytes_clear(&marker_before_recovery);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_recovery_rejects_reused_id_incarnation) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before_recovery = {0};
    m18_bytes_t state_before_recovery = {0};
    m18_bytes_t git_before_recovery = {0};
    m18_bytes_t marker_before_recovery = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));

    /* Integer IDs are reusable, incarnations are not. A live replacement at
     * ID 1 must never be mistaken for the durable missing owner recorded by
     * the incomplete remove. */
    CHECK_EQ_INT(
        m18_fixture_reintroduce_id_with_new_incarnation(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path,
                                &state_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &git_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path,
                                &marker_before_recovery), 0);
    CHECK(m18_completion_absent(&fixture));

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(m18_file_equals(fixture.accounts_path,
                          &accounts_before_recovery));
    CHECK(m18_file_equals(fixture.state_path, &state_before_recovery));
    CHECK(m18_file_equals(fixture.git_path, &git_before_recovery));
    CHECK(m18_file_equals(fixture.guard_path, &marker_before_recovery));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(&output, "different incarnation"));
    CHECK(!m18_output_contains(&output, "Account removed successfully"));

    m18_bytes_clear(&accounts_before_recovery);
    m18_bytes_clear(&state_before_recovery);
    m18_bytes_clear(&git_before_recovery);
    m18_bytes_clear(&marker_before_recovery);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(absent_destination_recreation_stays_guarded_until_clean_retry) {
    static const char clean_recreated_config[] =
        "[fixture]\n\tmarker = recreated-unmanaged\n";
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t state_before = {0};
    m18_bytes_t original_git = {0};
    m18_bytes_t clean_git = {0};
    m18_bytes_t marker = {0};
    m18_bytes_t output = {0};
    bool hook_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path, &state_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &original_git), 0);
    CHECK(m18_git_has_command(&fixture));
    CHECK_EQ_INT(unlink(fixture.git_path), 0);

    /* The first ENOENT is not settlement authority. Recreate the exact
     * managed vector only after the production transaction has published its
     * durable guard and retained the absent namespace under its canonical
     * lock. The command must fail closed without consuming account or ledger
     * ownership, and the recreated generation must remain visible to the
     * operator. */
    status = m18_run_cli_with_absent_recreation(
        &fixture, &original_git, &hook_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(hook_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.state_path, &state_before));
    CHECK(m18_file_equals(fixture.git_path, &original_git));
    CHECK(m18_git_has_command(&fixture));
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(!m18_output_contains(&output, "Account removed successfully"));
    m18_bytes_clear(&output);

    /* Once the recreated, unsealed generation is explicitly made clean, the
     * same durable owner can adopt the guard, prove the stale generation has
     * no attributed residue, and settle without changing unrelated bytes. */
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_path, clean_recreated_config,
                     sizeof(clean_recreated_config) - 1U, 0600), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &clean_git), 0);
    CHECK(!m18_git_has_command(&fixture));
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(m18_file_equals(fixture.git_path, &clean_git));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(&output, "Account removed successfully"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&state_before);
    m18_bytes_clear(&original_git);
    m18_bytes_clear(&clean_git);
    m18_bytes_clear(&marker);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(same_filesystem_repository_move_retains_guard_and_retry_authority) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t state_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t git_after = {0};
    m18_bytes_t marker = {0};
    m18_bytes_t output = {0};
    char moved_repository[MAX_PATH_LEN];
    char moved_config[MAX_PATH_LEN];
    struct stat st;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_use_local_repository(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(
                     moved_repository, sizeof(moved_repository),
                     "%s/repository-away", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(
                     moved_config, sizeof(moved_config),
                     "%s/.git/config", moved_repository), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path, &state_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);
    CHECK(m18_git_has_command(&fixture));
    CHECK_EQ_INT(rename(fixture.shared_repository, moved_repository), 0);
    CHECK_EQ_INT(stat(moved_repository, &st), 0);
    CHECK((uintmax_t)st.st_dev ==
          fixture.record.repository.device);

    /* Device equality cannot prove deletion: the moved repository retains
     * the exact repository, .git directory, config inode, and managed value.
     * Retirement must preserve both the live account and its durable retry
     * fence while that recorded namespace is unreachable. */
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.state_path, &state_before));
    CHECK(m18_file_equals(moved_config, &git_before));
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(!m18_output_contains(&output, "Account removed successfully"));
    m18_bytes_clear(&output);

    /* Restoring the same directory generations makes the original
     * provenance reachable again. The retained owner must then retire the
     * exact value and settle the same guard. */
    CHECK_EQ_INT(rename(moved_repository, fixture.shared_repository), 0);
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m18_state_has_inactive_header(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_git_trace_has_unset(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_after), 0);
    CHECK(strstr((const char *)git_after.data,
                 "[fixture]\n\tmarker = before\n") != NULL);
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(&output, "Account removed successfully"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&state_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&git_after);
    m18_bytes_clear(&marker);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_backup_verification_fault_restores_exact_outer_state) {
    /* The first prefix-read checkpoint belongs to initial accounts.toml load.
     * Let that read succeed, then fail the second occurrence while the
     * post-retirement save verifies its newly copied recovery backup. */
    m18_exercise_clean_rollback_after_matches(
        M18_COMMAND_REMOVE, CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ,
        1U, true);
}

TEST(restored_witness_retries_multiple_delayed_ctime_steps) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    /* Model several UFS ctime materializations after the restored descriptor
     * closes. Every retry must re-prove the retained bytes, converge on the
     * final named generation, refresh the ledger, and clear the guard. */
    status = m18_run_cli_with_witness_ctime_drifts(
        &fixture, M18_COMMAND_REMOVE, M18_FAULT_ONCE,
        CONFIG_IO_STATE_AFTER_TEMP, 3U, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_ledger_matches_live_restored_git(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "active-state temp creation"));
    CHECK(!m18_output_contains(
        &output, "destination changed after abort"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_alias_postrename_uncertainty_retains_exact_v2_obligation) {
    m18_fixture_t fixture;
    publication_identity_t home_identity;
    publication_identity_t ssh_identity;
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    CHECK_EQ_INT(m24_capture_alias_namespace(
                     &fixture, &home_identity, &ssh_identity), 0);

    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, &observed);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(!observed);
    CHECK(m24_alias_fault_observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m24_guard_has_exact_alias_obligation(
        &fixture, &home_identity, &ssh_identity));
    CHECK(m18_completion_absent(&fixture));

    m18_fixture_cleanup(&fixture);
}

TEST(remove_alias_dirsync_uncertainty_retains_exact_v2_obligation) {
    m18_fixture_t fixture;
    publication_identity_t home_identity;
    publication_identity_t ssh_identity;
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    CHECK_EQ_INT(m24_capture_alias_namespace(
                     &fixture, &home_identity, &ssh_identity), 0);

    m24_alias_dirsync_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, &observed);
    m24_alias_dirsync_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(!observed);
    CHECK(m24_alias_fault_observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m24_guard_has_exact_alias_obligation(
        &fixture, &home_identity, &ssh_identity));
    CHECK(m18_completion_absent(&fixture));

    m18_fixture_cleanup(&fixture);
}

TEST(fresh_remove_recovery_settles_absent_alias_without_rewrite) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    m18_bytes_t ssh_after_failure = {0};
    m18_bytes_t git_after_failure = {0};
    struct stat ssh_before_recovery;
    struct stat ssh_after_recovery;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK(m24_alias_is_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.ssh_config, &ssh_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.git_path, &git_after_failure), 0);
    CHECK_EQ_INT(lstat(fixture.ssh_config, &ssh_before_recovery), 0);
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_trace_path, "", 0U, 0600), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK(m18_file_equals(fixture.ssh_config, &ssh_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK_EQ_INT(lstat(fixture.ssh_config, &ssh_after_recovery), 0);
    CHECK(m18_same_without_ctime(
        &ssh_before_recovery, &ssh_after_recovery));
    CHECK(m18_same_ctime(&ssh_before_recovery, &ssh_after_recovery));
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&marker);
    m18_bytes_clear(&ssh_after_failure);
    m18_bytes_clear(&git_after_failure);
    m18_fixture_cleanup(&fixture);
}

TEST(alias_only_uncertain_removal_keeps_guard_and_recovers_without_git_write) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    m18_bytes_t git_before = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    CHECK_EQ_INT(m24_remove_publication_ledger(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_trace_path, "", 0U, 0600), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(!m18_git_trace_has_unset(&fixture));
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&marker);
    m18_bytes_clear(&git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(alias_recovery_rejects_retargeted_home_without_touching_either_config) {
    static const char alternate_config[] =
        "Host " M24_ALIAS "\n  HostName alternate.invalid\n";
    m18_fixture_t fixture;
    m18_bytes_t original_config = {0};
    m18_bytes_t alternate_before = {0};
    m18_bytes_t marker = {0};
    char alternate_home[MAX_PATH_LEN];
    char alternate_ssh[MAX_PATH_LEN];
    char alternate_path[MAX_PATH_LEN];
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.ssh_config, &original_config), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);

    CHECK_EQ_INT(safe_snprintf(
                     alternate_home, sizeof(alternate_home),
                     "%s/retargeted-home", fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(
                     alternate_ssh, sizeof(alternate_ssh),
                     "%s/.ssh", alternate_home), 0);
    CHECK_EQ_INT(safe_snprintf(
                     alternate_path, sizeof(alternate_path),
                     "%s/config", alternate_ssh), 0);
    CHECK_EQ_INT(mkdir(alternate_home, 0700), 0);
    CHECK_EQ_INT(mkdir(alternate_ssh, 0700), 0);
    CHECK_EQ_INT(m18_write_file(
                     alternate_path, alternate_config,
                     sizeof(alternate_config) - 1U, 0600), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     alternate_path, &alternate_before), 0);
    CHECK_EQ_INT(safe_strncpy(
                     m24_home_override, alternate_home,
                     sizeof(m24_home_override)), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_home_override[0] = '\0';
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m18_file_equals(fixture.ssh_config, &original_config));
    CHECK(m18_file_equals(alternate_path, &alternate_before));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));

    m18_bytes_clear(&original_config);
    m18_bytes_clear(&alternate_before);
    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(alias_recovery_rejects_new_live_claimant_without_mutation) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t ssh_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t marker = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK_EQ_INT(
        m24_fixture_replace_with_live_alias_claimant(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.accounts_path, &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.ssh_config, &ssh_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.ssh_config, &ssh_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&ssh_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_preinstall_save_failure_never_attempts_alias_removal) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t ssh_before = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.accounts_path, &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.ssh_config, &ssh_before), 0);

    m24_alias_postrename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_RENAME, &observed);
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(!m24_alias_fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.ssh_config, &ssh_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&ssh_before);
    m18_fixture_cleanup(&fixture);
}

TEST(remove_outer_uncertainty_retains_marker_after_alias_cleanup_settles) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(!m24_alias_fault_observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK(m18_completion_absent(&fixture));

    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(durable_remove_settles_managed_alias_and_completion_pair) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m24_alias_is_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(v1_remove_recovery_remains_blocked_when_alias_obligation_is_unknown) {
    m18_fixture_t fixture;
    m18_bytes_t accounts = {0};
    m18_bytes_t state = {0};
    m18_bytes_t git = {0};
    m18_bytes_t marker = {0};
    m18_bytes_t output = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(m24_rewrite_marker_as_v1_unknown(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path, &accounts), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.state_path, &state), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts));
    CHECK(m18_file_equals(fixture.state_path, &state));
    CHECK(m18_file_equals(fixture.git_path, &git));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "SSH alias obligation is unknown"));

    m18_bytes_clear(&accounts);
    m18_bytes_clear(&state);
    m18_bytes_clear(&git);
    m18_bytes_clear(&marker);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(recovery_source_change_before_alias_mutation_retains_exact_marker) {
    m18_fixture_t fixture;
    m18_bytes_t ssh_before_recovery = {0};
    m18_bytes_t git_before_recovery = {0};
    m18_bytes_t marker = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);

    /* Leave the alias public while the durable account deletion and Git
     * retirement retain an exact recovery obligation. */
    m24_alias_prerename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_prerename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(!m24_alias_is_absent(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.ssh_config, &ssh_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.git_path, &git_before_recovery), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);

    /* The recovery checkpoint runs after the early source and Git proofs but
     * before alias mutation. Introduce a live claimant there. The subsequent
     * authorization barrier must stop before touching either publication
     * namespace. */
    m24_recovery_claimant_requested = true;
    m24_recovery_claimant_fixture = &fixture;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_recovery_claimant_requested = false;
    m24_recovery_claimant_fixture = NULL;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_recovery_claimant_observed);
    CHECK(m18_file_equals(fixture.ssh_config, &ssh_before_recovery));
    CHECK(m18_file_equals(fixture.git_path, &git_before_recovery));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));

    m18_bytes_clear(&ssh_before_recovery);
    m18_bytes_clear(&git_before_recovery);
    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(git_recovery_end_failure_retains_exact_blocking_marker) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    m18_bytes_t git_before_recovery = {0};
    m18_bytes_t output = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    m24_alias_prerename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_prerename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.git_path, &git_before_recovery), 0);

    m24_recovery_end_failure_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_recovery_end_failure_requested = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_recovery_end_failure_observed);
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_file_equals(fixture.git_path, &git_before_recovery));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "Injected Git retirement recovery final proof failure"));

    m18_bytes_clear(&marker);
    m18_bytes_clear(&git_before_recovery);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(alias_diagnostic_and_git_end_failure_are_both_retained) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
    m18_bytes_t output = {0};
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    m24_alias_prerename_failure = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_prerename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);

    m24_alias_postrename_failure = true;
    m24_recovery_end_failure_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_postrename_failure = false;
    m24_recovery_end_failure_requested = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK(m24_recovery_end_failure_observed);
    CHECK(m24_alias_is_absent(&fixture));
    CHECK(m18_file_equals(fixture.guard_path, &marker));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "SSH config was installed but injected post-rename"));
    CHECK(m18_output_contains(
        &output, "Injected Git retirement recovery final proof failure"));

    m18_bytes_clear(&marker);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
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
    RUN_TEST(remove_uncertain_install_recovers_in_fresh_process);
    RUN_TEST(remove_recovery_reconciles_interrupted_completion_stage);
    RUN_TEST(remove_recovery_rejects_reintroduced_git_identity);
    RUN_TEST(remove_recovery_rejects_reused_id_incarnation);
    RUN_TEST(absent_destination_recreation_stays_guarded_until_clean_retry);
    RUN_TEST(same_filesystem_repository_move_retains_guard_and_retry_authority);
    RUN_TEST(remove_backup_verification_fault_restores_exact_outer_state);
    RUN_TEST(restored_witness_retries_multiple_delayed_ctime_steps);
    RUN_TEST(remove_alias_postrename_uncertainty_retains_exact_v2_obligation);
    RUN_TEST(remove_alias_dirsync_uncertainty_retains_exact_v2_obligation);
    RUN_TEST(fresh_remove_recovery_settles_absent_alias_without_rewrite);
    RUN_TEST(alias_only_uncertain_removal_keeps_guard_and_recovers_without_git_write);
    RUN_TEST(alias_recovery_rejects_retargeted_home_without_touching_either_config);
    RUN_TEST(alias_recovery_rejects_new_live_claimant_without_mutation);
    RUN_TEST(remove_preinstall_save_failure_never_attempts_alias_removal);
    RUN_TEST(remove_outer_uncertainty_retains_marker_after_alias_cleanup_settles);
    RUN_TEST(durable_remove_settles_managed_alias_and_completion_pair);
    RUN_TEST(v1_remove_recovery_remains_blocked_when_alias_obligation_is_unknown);
    RUN_TEST(recovery_source_change_before_alias_mutation_retains_exact_marker);
    RUN_TEST(git_recovery_end_failure_retains_exact_blocking_marker);
    RUN_TEST(alias_diagnostic_and_git_end_failure_are_both_retained);
    RUN_TEST(reset_state_boundary_matrix_preserves_outer_coherence);
    RUN_TEST(reset_persistent_preinstall_fault_retains_guard_and_blocks_switch);
    RUN_TEST(reset_all_clean_rollback_refreshes_shared_and_no_op_destinations);
    RUN_TEST(reset_retirement_phase_rejections_preserve_pending_owner);
TEST_MAIN_END()
