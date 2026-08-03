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
#include "signals.h"
#include "ssh_manager.h"
#include "utils.h"

#include <dirent.h>
#include <ctype.h>
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
void git_ops_test_reset_caches(void);
typedef struct git_retirement_recovery git_retirement_recovery_t;
int git_retirement_transaction_prepare_terminal_commit(
    git_retirement_transaction_t *transaction);
int git_retirement_transaction_finish_terminal_commit(
    git_retirement_transaction_t **transaction);
int git_retirement_transaction_verify_terminal_commit(
    git_retirement_transaction_t *transaction);
size_t git_retirement_transaction_rollback_destination_count(
    const git_retirement_transaction_t *transaction);
int git_retirement_transaction_rollback_destination(
    git_retirement_transaction_t *transaction, size_t index,
    char *config_path, size_t path_size,
    publication_identity_t *post_config);
int git_retirement_transaction_prepare_terminal_rollback(
    git_retirement_transaction_t *transaction);
int git_retirement_transaction_finish_terminal_rollback(
    git_retirement_transaction_t **transaction);
int git_retirement_recovery_begin(
    const publication_record_t *const publications[],
    size_t publication_count, git_retirement_recovery_t **recovery);
int git_retirement_recovery_end(
    git_retirement_recovery_t **recovery);
size_t git_ops_test_retirement_transaction_descriptors(
    const git_retirement_transaction_t *transaction,
    int *fds, size_t capacity);
size_t git_ops_test_retirement_recovery_descriptors(
    const git_retirement_recovery_t *recovery,
    int *fds, size_t capacity);

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
    GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_ORIGINAL_UNLINK,
    GIT_RETIREMENT_TEST_FORCE_FALLBACK_LINK_FAILURE,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_CANONICAL_LINK,
    GIT_RETIREMENT_TEST_AFTER_REVERSE_PUBLISHED_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_AUTHORITY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_CANONICAL_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_TERMINAL_SECOND_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_PUBLISH,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS,
    GIT_RETIREMENT_TEST_AFTER_STABLE_WITNESS_CLOSE,
    GIT_RETIREMENT_TEST_AFTER_RESTORED_WITNESS_READ,
    GIT_RETIREMENT_TEST_AFTER_FINAL_RESTORED_WITNESS_READ
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
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_READ_AFTER_CLOSE,
    RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
    RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
    RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
    RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME
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

#if defined(__FreeBSD__)
typedef enum {
    CONFIG_PUBLISH_TEST_SOURCE_UNLINK = 0,
    CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK,
    CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE,
    CONFIG_PUBLISH_TEST_RETAINED_SOURCE_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_SOURCE_PIN
} config_publish_test_stage_t;
typedef int (*config_publish_test_hook_fn)(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination);
config_publish_test_hook_fn gitswitch_test_set_config_publish_hook(
    config_publish_test_hook_fn hook);
#endif

typedef enum {
    M18_COMMAND_REMOVE = 0,
    M18_COMMAND_REMOVE_NUMERIC,
    M18_COMMAND_RESET,
    M18_COMMAND_RESET_ALL,
    M18_COMMAND_RESUME,
    M18_COMMAND_SWITCH
} m18_command_t;

typedef enum {
    M18_FRESH_FIRST_SET = 0,
    M18_FRESH_FIRST_UNSET
} m18_fresh_first_op_t;

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
    char commands_dir[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char bin_dir[MAX_PATH_LEN];
    char data_dir[MAX_PATH_LEN];
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

typedef struct {
    char root[MAX_PATH_LEN];
    char commands_dir[MAX_PATH_LEN];
    char data_dir[MAX_PATH_LEN];
    char bin_dir[MAX_PATH_LEN];
    char git_program[MAX_PATH_LEN];
    char ssh_program[MAX_PATH_LEN];
    bool ready;
} m18_suite_fixture_t;

static m18_suite_fixture_t m18_suite_fixture;

static bool m18_guard_is_unblocked_and_bounded(
    const m18_fixture_t *fixture);
static bool m18_guard_is_private_and_blocking(
    const m18_fixture_t *fixture, const char *operation);
static bool m18_ledger_matches_live_restored_git(
    const m18_fixture_t *fixture);
static bool m18_completion_absent(const m18_fixture_t *fixture);
static bool m18_git_trace_has_unset(const m18_fixture_t *fixture);

static config_io_boundary_t m18_fault_boundary;
static bool m18_fault_observed;
static size_t m18_faults_remaining;
static size_t m18_fault_matches_to_skip;
static size_t m18_witness_ctime_drifts_remaining;
static int m18_witness_ctime_drift_error;
static git_retirement_test_stage_t m18_witness_ctime_drift_stage =
    GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE;
static bool m18_clear_after_stage_write_fault;
static bool m18_clear_after_stage_write_observed;
static bool m18_prepare_ctime_drift_requested;
static bool m18_prepare_ctime_drift_observed;
static int m18_prepare_ctime_drift_error;
static const m18_fixture_t *m18_prepare_ctime_drift_fixture;
static bool m18_prepublish_ctime_drift_requested;
static const m18_fixture_t *m18_prepublish_ctime_drift_fixture;
static size_t m18_prepublish_ctime_drift_budget;
static size_t m18_prepublish_ctime_drift_calls;
static size_t m18_prepublish_ctime_drift_count;
static size_t m18_prepublish_ctime_drift_expected_calls;
static size_t m18_prepublish_ctime_drift_expected_count;
static size_t m18_prepublish_ctime_drift_expected_remaining;
static int m18_prepublish_ctime_drift_error;
static bool m18_prepublish_byte_rewrite_requested;
static bool m18_prepublish_byte_rewrite_observed;
static int m18_prepublish_byte_rewrite_error;
static const m18_fixture_t *m18_prepublish_byte_rewrite_fixture;
static bool m18_recovery_end_probe_requested;
static bool m18_recovery_end_probe_observed;
static bool m18_prepare_preceded_recovery_end;
static bool m18_final_prepared_read_order_requested;
static bool m18_final_prepared_read_epoch;
static size_t m18_final_prepared_read_count;
static bool m18_recovery_end_after_final_prepared_reads;
static bool m18_prepared_read_after_recovery_end;
static bool m18_absent_recreation_requested;
static bool m18_absent_recreation_observed;
static bool m18_absent_recreation_guard_observed;
static int m18_absent_recreation_error;
static const m18_fixture_t *m18_absent_recreation_fixture;
static const char *m18_absent_recreation_path;
static const char *m18_absent_recreation_operation;
static bool m18_absent_recreation_require_transition;
static m18_bytes_t m18_absent_recreation_bytes;
static bool m24_alias_postrename_failure;
static bool m24_alias_dirsync_failure;
static bool m24_alias_prerename_failure;
static bool m24_alias_fault_observed;
static bool m24_alias_commit_probe_requested;
static bool m24_alias_commit_observed;
static bool m24_recovery_claimant_requested;
static bool m24_recovery_claimant_observed;
static int m24_recovery_claimant_error;
static const m18_fixture_t *m24_recovery_claimant_fixture;
static bool m24_recovery_end_failure_requested;
static bool m24_recovery_end_failure_observed;
static char m24_home_override[MAX_PATH_LEN];
static const m18_fixture_t *m18_terminal_writer_fixture;
static const char *m18_terminal_writer_path;
static bool m18_terminal_writer_requested;
static bool m18_terminal_writer_expect_stage;
static bool m18_terminal_writer_checkpoint_observed;
static int m18_terminal_writer_result;
static bool m18_terminal_precommit_failure_requested;
static bool m18_terminal_precommit_failure_observed;
static const m18_fixture_t *m18_terminal_cleanup_fixture;
static bool m18_terminal_cleanup_failure_requested;
static bool m18_terminal_cleanup_crash_requested;
static bool m18_terminal_cleanup_observed;
static const m18_fixture_t *m18_alias_race_fixture;
static bool m18_alias_race_requested;
static bool m18_alias_race_observed;
static int m18_alias_race_error;
typedef struct {
    const char *name;
    char *value;
    bool present;
} m18_saved_environment_t;
static m18_saved_environment_t m18_parent_environment[] = {
    {"PATH", NULL, false},
    {"HOME", NULL, false},
    {"XDG_RUNTIME_DIR", NULL, false},
    {"GITSWITCH_ALLOW_TMP_GPG", NULL, false},
    {"GIT_CONFIG_GLOBAL", NULL, false},
    {"GIT_CONFIG_NOSYSTEM", NULL, false},
    {"GITSWITCH_TEST_GIT_TRACE", NULL, false},
    {"GIT_CONFIG_COUNT", NULL, false}
};
static bool m18_parent_environment_saved;
#if defined(__FreeBSD__)
static int m18_freebsd_alias_failure_stage = -1;
#endif

static int m18_write_file(const char *path, const void *data,
                          size_t length, mode_t mode);
static int m18_read_bytes(const char *path, m18_bytes_t *bytes);
static void m18_bytes_clear(m18_bytes_t *bytes);
static int m18_force_ctime_only_drift(const char *path);
static int m18_rewrite_marker_byte_preserving_mtime(const char *path);
static int m18_stabilize_command_tree(const m18_fixture_t *fixture);
static int m18_suite_fixture_setup(void);
static int m24_fixture_replace_with_live_alias_claimant(
    const m18_fixture_t *fixture);
static int m18_terminal_writer_hook(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name);

#if defined(__FreeBSD__)
static int m18_fail_freebsd_retained_alias(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    (void)directory_fd;
    (void)source;
    (void)destination;
    if (stage == CONFIG_PUBLISH_TEST_SOURCE_UNLINK ||
        stage == CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK) {
        errno = EIO;
        return -1;
    }
    if (stage == CONFIG_PUBLISH_TEST_RETAINED_SOURCE_RETIRE) {
        signals_test_fail_scratch_unlink(EIO);
        errno = EIO;
        return -1;
    }
    if ((int)stage == m18_freebsd_alias_failure_stage) {
        m18_freebsd_alias_failure_stage = -1;
        errno = EIO;
        return -1;
    }
    return 0;
}
#endif

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

static int m24_observe_alias_commit(int dir_fd, const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    m24_alias_commit_observed = true;
    return 0;
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
    if (stage == RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH &&
        marker_name &&
        strcmp(marker_name, ".retirement-complete") == 0) {
        if (m18_final_prepared_read_order_requested) {
            m18_final_prepared_read_epoch = true;
            m18_final_prepared_read_count = 0U;
        }
        if (m18_prepublish_ctime_drift_requested) {
            m18_prepublish_ctime_drift_calls++;
            if (m18_prepublish_ctime_drift_budget != 0U) {
                if (!m18_prepublish_ctime_drift_fixture ||
                    m18_force_ctime_only_drift(
                        m18_prepublish_ctime_drift_fixture->git_path) != 0) {
                    m18_prepublish_ctime_drift_error =
                        errno ? errno : EIO;
                } else {
                    m18_prepublish_ctime_drift_budget--;
                    m18_prepublish_ctime_drift_count++;
                }
            }
        }
        if (m18_prepublish_byte_rewrite_requested &&
            !m18_prepublish_byte_rewrite_observed) {
            m18_prepublish_byte_rewrite_observed = true;
            if (!m18_prepublish_byte_rewrite_fixture ||
                m18_rewrite_marker_byte_preserving_mtime(
                    m18_prepublish_byte_rewrite_fixture->git_path) != 0) {
                m18_prepublish_byte_rewrite_error =
                    errno ? errno : EIO;
            }
        }
        return 0;
    }
    if (stage ==
            RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK &&
        m18_final_prepared_read_order_requested && marker_name) {
        if (m18_recovery_end_probe_observed) {
            m18_prepared_read_after_recovery_end = true;
        }
        if (m18_final_prepared_read_epoch &&
            (strcmp(marker_name, ".retirement-incomplete") == 0 ||
             strcmp(marker_name, ".retirement-transition") == 0)) {
            m18_final_prepared_read_count++;
        }
        return 0;
    }
    if (stage != RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE) {
        return 0;
    }
    /* A resealable drift belongs before Git terminal preparation. Guard
     * preparation is the last outer metadata flush; mutate immediately after
     * its stage write so terminal preparation can stabilize and witness the
     * successor generation. A later BEFORE_PUBLISH drift deliberately tests
     * rejection by the read-only terminal verifier. */
    if (m18_prepublish_ctime_drift_requested) {
        m18_prepublish_ctime_drift_calls++;
        if (m18_prepublish_ctime_drift_budget != 0U) {
            if (!m18_prepublish_ctime_drift_fixture ||
                m18_force_ctime_only_drift(
                    m18_prepublish_ctime_drift_fixture->git_path) != 0) {
                m18_prepublish_ctime_drift_error =
                    errno ? errno : EIO;
            } else {
                m18_prepublish_ctime_drift_budget--;
                m18_prepublish_ctime_drift_count++;
            }
        }
    }
    if (m18_clear_after_stage_write_fault) {
        m18_clear_after_stage_write_fault = false;
        m18_clear_after_stage_write_observed = true;
        errno = EIO;
        return -1;
    }
    if (!m18_prepare_ctime_drift_requested ||
        m18_prepare_ctime_drift_observed) {
        return 0;
    }
    m18_prepare_ctime_drift_observed = true;
    if (m18_recovery_end_probe_requested) {
        m18_prepare_preceded_recovery_end =
            !m18_recovery_end_probe_observed;
    }
    if (!m18_prepare_ctime_drift_fixture ||
        m18_force_ctime_only_drift(
            m18_prepare_ctime_drift_fixture->git_path) != 0) {
        m18_prepare_ctime_drift_error = errno ? errno : EIO;
    }
    return 0;
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

static int m18_rewrite_marker_byte_preserving_mtime(const char *path) {
    static const char needle[] = "marker = before";
    static const char replacement[] = "marker = xefore";
    m18_bytes_t bytes = {0};
    struct stat before;
    struct stat after;
    struct timespec times[2];
    unsigned char *match;
    size_t offset;
    int fd = -1;
    int saved_errno = 0;
    int result = -1;

    if (!path || m18_read_bytes(path, &bytes) != 0 ||
        lstat(path, &before) != 0 ||
        !S_ISREG(before.st_mode) ||
        bytes.length != (size_t)before.st_size) {
        goto cleanup;
    }
    match = (unsigned char *)strstr(
        (const char *)bytes.data, needle);
    if (!match) {
        errno = ESTALE;
        goto cleanup;
    }
    offset = (size_t)(match - bytes.data);
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 ||
        pwrite(fd, replacement, sizeof(replacement) - 1U,
               (off_t)offset) != (ssize_t)(sizeof(replacement) - 1U) ||
        fsync(fd) != 0) {
        goto cleanup;
    }
#if defined(__APPLE__)
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (futimens(fd, times) != 0 || fsync(fd) != 0 ||
        fstat(fd, &after) != 0 ||
        !m18_same_without_ctime(&before, &after)) {
        errno = errno ? errno : ESTALE;
        goto cleanup;
    }
    result = 0;

cleanup:
    saved_errno = errno;
    if (fd >= 0 && close(fd) != 0 && result == 0) {
        saved_errno = errno;
        result = -1;
    }
    m18_bytes_clear(&bytes);
    errno = saved_errno;
    return result;
}

static bool m18_retirement_witness_hook(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value) {
    if (stage == GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF &&
        m18_alias_race_requested && !m18_alias_race_observed &&
        m18_alias_race_fixture && path && key && value &&
        strcmp(path, m18_alias_race_fixture->git_path) == 0 &&
        strncmp(key, ".gitswitch-finalization-", 24U) == 0) {
        static const char replacement[] =
            "foreign private finalization claimant\n";
        char pending[MAX_PATH_LEN];

        m18_alias_race_observed = true;
        if (safe_snprintf(pending, sizeof(pending), "%s/%s",
                          m18_alias_race_fixture->home, value) != 0 ||
            unlink(pending) != 0 ||
            m18_write_file(pending, replacement,
                           sizeof(replacement) - 1U, 0600) != 0) {
            m18_alias_race_error = errno ? errno : EIO;
        }
        return false;
    }
    if (stage == GIT_RETIREMENT_TEST_CLEANUP_UNLINK &&
        value &&
        (strcmp(value, "terminal rollback recovery marker") == 0 ||
         strcmp(value, "terminal rollback recovery authority") == 0)) {
        if (m18_terminal_cleanup_fixture && path &&
            strcmp(path, m18_terminal_cleanup_fixture->git_path) == 0) {
            m18_terminal_cleanup_observed = true;
            if (m18_terminal_cleanup_crash_requested) _exit(89);
            if (m18_terminal_cleanup_failure_requested) return true;
        }
    }
    (void)key;
    if (stage ==
        GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF) {
        if (m18_recovery_end_probe_requested) {
            m18_recovery_end_probe_observed = true;
            if (m18_final_prepared_read_order_requested) {
                m18_recovery_end_after_final_prepared_reads =
                    m18_final_prepared_read_epoch &&
                    m18_final_prepared_read_count == 2U;
            }
        }
        if (m24_recovery_end_failure_requested) {
            m24_recovery_end_failure_observed = true;
            return true;
        }
    }
    if (stage == GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE &&
        m18_absent_recreation_requested) {
        if (m18_absent_recreation_require_transition) {
            errno = 0;
            if (!m18_absent_recreation_fixture ||
                access(m18_absent_recreation_fixture->transition_path,
                       F_OK) != 0) {
                if (errno != ENOENT) {
                    m18_absent_recreation_error =
                        errno ? errno : EIO;
                }
                return false;
            }
        }
        if (m18_absent_recreation_observed) return false;
        m18_absent_recreation_observed = true;
        if (!m18_absent_recreation_fixture ||
            !m18_absent_recreation_path ||
            !m18_absent_recreation_operation || !path ||
            strcmp(path, m18_absent_recreation_path) != 0) {
            m18_absent_recreation_error = ESTALE;
            return false;
        }
        if (m18_absent_recreation_require_transition) {
            bool blocked = false;

            m18_absent_recreation_guard_observed =
                config_retirement_guard_probe(
                    m18_absent_recreation_fixture->accounts_path,
                    &blocked) == 0 &&
                blocked;
        } else {
            m18_absent_recreation_guard_observed =
                m18_guard_is_private_and_blocking(
                    m18_absent_recreation_fixture,
                    m18_absent_recreation_operation);
        }
        if (!m18_absent_recreation_guard_observed) {
            m18_absent_recreation_error = EPERM;
            return false;
        }
        if (m18_write_file(
                m18_absent_recreation_path,
                m18_absent_recreation_bytes.data,
                m18_absent_recreation_bytes.length, 0600) != 0) {
            m18_absent_recreation_error = errno ? errno : EIO;
        }
        return false;
    }
    if (stage != m18_witness_ctime_drift_stage ||
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

static int m18_sync_directory(const char *path) {
    int fd;
    int result;
    int saved_errno = 0;

    if (!path) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    do {
        result = fsync(fd);
    } while (result != 0 && errno == EINTR);
    if (result != 0) saved_errno = errno;
    if (close(fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    errno = result == 0 ? 0 : saved_errno;
    return result;
}

/* The trusted executable branch is immutable after setup. Flush every
 * directory in that branch and its namespace publication, then require one
 * complete pass in which both absolute wrappers survive the resolver's
 * fail-closed metadata checks. UFS may expose a bounded delayed ctime
 * successor after the flush, so only that transient classification is
 * retried in this otherwise quiescent test tree. */
static int m18_stabilize_command_tree(const m18_fixture_t *fixture) {
    char parent[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    char *slash;

    if (!fixture ||
        safe_strncpy(parent, fixture->root, sizeof(parent)) != 0) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(parent, '/');
    if (!slash) {
        errno = EINVAL;
        return -1;
    }
    if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    if (m18_sync_directory(fixture->bin_dir) != 0 ||
        m18_sync_directory(fixture->commands_dir) != 0 ||
        m18_sync_directory(fixture->root) != 0 ||
        m18_sync_directory(parent) != 0) {
        return -1;
    }
    for (unsigned attempt = 0U; attempt < 16U; attempt++) {
        errno = 0;
        if (find_command_path(fixture->git_program, resolved,
                              sizeof(resolved)) != 0) {
            if (errno == ESTALE || errno == EAGAIN) continue;
            return -1;
        }
        if (strcmp(resolved, fixture->git_program) != 0) {
            errno = EIO;
            return -1;
        }
        errno = 0;
        if (find_command_path(fixture->ssh_program, resolved,
                              sizeof(resolved)) != 0) {
            if (errno == ESTALE || errno == EAGAIN) continue;
            return -1;
        }
        if (strcmp(resolved, fixture->ssh_program) != 0) {
            errno = EIO;
            return -1;
        }
        clear_error();
        errno = 0;
        return 0;
    }
    errno = ESTALE;
    return -1;
}

/* Keep the resolver's entire executable ancestry quiescent for the lifetime
 * of the suite. Per-test fixtures live below the sibling data directory, so
 * creating and removing them cannot change HOME or any commands/bin ancestor
 * while child processes are resolving the trusted git and ssh wrappers. */
static int m18_suite_fixture_setup(void) {
    static const char ssh_program_body[] = "#!/bin/sh\nexit 0\n";
    static const char git_program_body[] =
        "#!/bin/sh\nPATH=/usr/local/bin:/usr/bin:/bin\n"
        "export PATH\n"
        "if [ -n \"${GITSWITCH_TEST_GIT_TRACE:-}\" ]; then\n"
        "  printf '%s\\n' \"$*\" >> \"$GITSWITCH_TEST_GIT_TRACE\"\n"
        "fi\n"
        "exec git \"$@\"\n";
    m18_fixture_t command_fixture;

    if (m18_suite_fixture.ready) return 0;
    memset(&m18_suite_fixture, 0, sizeof(m18_suite_fixture));
    if (!ts_mkdtemp_trusted(m18_suite_fixture.root,
                            sizeof(m18_suite_fixture.root),
                            "gsw-ar11-m18-suite") ||
        ts_canonicalize_dir_path(m18_suite_fixture.root,
                                 sizeof(m18_suite_fixture.root)) != 0 ||
        safe_snprintf(m18_suite_fixture.commands_dir,
                      sizeof(m18_suite_fixture.commands_dir),
                      "%s/commands", m18_suite_fixture.root) != 0 ||
        safe_snprintf(m18_suite_fixture.data_dir,
                      sizeof(m18_suite_fixture.data_dir),
                      "%s/data", m18_suite_fixture.root) != 0 ||
        safe_snprintf(m18_suite_fixture.bin_dir,
                      sizeof(m18_suite_fixture.bin_dir),
                      "%s/bin", m18_suite_fixture.commands_dir) != 0 ||
        safe_snprintf(m18_suite_fixture.git_program,
                      sizeof(m18_suite_fixture.git_program),
                      "%s/git", m18_suite_fixture.bin_dir) != 0 ||
        safe_snprintf(m18_suite_fixture.ssh_program,
                      sizeof(m18_suite_fixture.ssh_program),
                      "%s/ssh", m18_suite_fixture.bin_dir) != 0 ||
        mkdir(m18_suite_fixture.commands_dir, 0700) != 0 ||
        mkdir(m18_suite_fixture.data_dir, 0700) != 0 ||
        mkdir(m18_suite_fixture.bin_dir, 0700) != 0 ||
        m18_write_file(m18_suite_fixture.git_program, git_program_body,
                       sizeof(git_program_body) - 1U, 0700) != 0 ||
        m18_write_file(m18_suite_fixture.ssh_program, ssh_program_body,
                       sizeof(ssh_program_body) - 1U, 0700) != 0) {
        return -1;
    }

    memset(&command_fixture, 0, sizeof(command_fixture));
    if (safe_strncpy(command_fixture.root, m18_suite_fixture.root,
                     sizeof(command_fixture.root)) != 0 ||
        safe_strncpy(command_fixture.commands_dir,
                     m18_suite_fixture.commands_dir,
                     sizeof(command_fixture.commands_dir)) != 0 ||
        safe_strncpy(command_fixture.bin_dir, m18_suite_fixture.bin_dir,
                     sizeof(command_fixture.bin_dir)) != 0 ||
        safe_strncpy(command_fixture.git_program,
                     m18_suite_fixture.git_program,
                     sizeof(command_fixture.git_program)) != 0 ||
        safe_strncpy(command_fixture.ssh_program,
                     m18_suite_fixture.ssh_program,
                     sizeof(command_fixture.ssh_program)) != 0 ||
        m18_stabilize_command_tree(&command_fixture) != 0) {
        return -1;
    }
    m18_suite_fixture.ready = true;
    return 0;
}

static int m18_build_ssh_command(m18_fixture_t *fixture) {
    const char *path = getenv("PATH");
    char *saved_path = path ? strdup(path) : NULL;
    int result = -1;
    int restore_result;

    if (!fixture || (path && !saved_path) ||
        setenv("PATH", fixture->bin_dir, 1) != 0) {
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
    char config_body[2U * MAX_PATH_LEN];
    char git_body[PUBLICATION_SSH_COMMAND_MAX + 128U];
    struct stat st;
    int written;

    if (!fixture) return -1;
    memset(fixture, 0, sizeof(*fixture));
    if (m18_suite_fixture_setup() != 0 ||
        safe_snprintf(fixture->root, sizeof(fixture->root),
                      "%s/case.XXXXXX",
                      m18_suite_fixture.data_dir) != 0 ||
        !mkdtemp(fixture->root) || chmod(fixture->root, 0700) != 0 ||
        safe_strncpy(fixture->commands_dir,
                     m18_suite_fixture.commands_dir,
                     sizeof(fixture->commands_dir)) != 0 ||
        safe_snprintf(fixture->data_dir, sizeof(fixture->data_dir),
                      "%s/data", fixture->root) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home),
                      "%s/home", fixture->data_dir) != 0 ||
        safe_strncpy(fixture->bin_dir, m18_suite_fixture.bin_dir,
                     sizeof(fixture->bin_dir)) != 0 ||
        safe_snprintf(fixture->runtime, sizeof(fixture->runtime),
                      "%s/runtime", fixture->data_dir) != 0 ||
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
                      "%s/output", fixture->data_dir) != 0 ||
        safe_snprintf(fixture->git_trace_path,
                      sizeof(fixture->git_trace_path),
                      "%s/git.trace", fixture->data_dir) != 0 ||
        safe_snprintf(fixture->git_path, sizeof(fixture->git_path),
                      "%s/.gitconfig", fixture->home) != 0 ||
        safe_strncpy(fixture->git_program,
                     m18_suite_fixture.git_program,
                     sizeof(fixture->git_program)) != 0 ||
        safe_strncpy(fixture->ssh_program,
                     m18_suite_fixture.ssh_program,
                     sizeof(fixture->ssh_program)) != 0 ||
        safe_snprintf(fixture->ssh_key, sizeof(fixture->ssh_key),
                      "%s/id_key", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_dir, sizeof(fixture->ssh_dir),
                      "%s/.ssh", fixture->home) != 0 ||
        safe_snprintf(fixture->ssh_config, sizeof(fixture->ssh_config),
                      "%s/config", fixture->ssh_dir) != 0 ||
        mkdir(fixture->data_dir, 0700) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        mkdir(fixture->runtime, 0700) != 0 ||
        mkdir(fixture->config_parent, 0700) != 0 ||
        mkdir(fixture->config_dir, 0700) != 0) {
        return -1;
    }
    if (m18_write_file(fixture->output_path, "", 0U, 0600) != 0 ||
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
                      "%s/linked-worktree", fixture->data_dir) != 0 ||
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
                      "%s/repository", fixture->data_dir) != 0 ||
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

enum {
    M18_TERMINAL_WRITER_NOT_RUN = 0,
    M18_TERMINAL_WRITER_BLOCKED,
    M18_TERMINAL_WRITER_PUBLISHED,
    M18_TERMINAL_WRITER_ERROR,
    M18_TERMINAL_WRITER_INVALID_MARKER,
    M18_TERMINAL_WRITER_STAGE_NOT_SETTLED
};

#if defined(__FreeBSD__)
#define M18_FREEBSD_AUTHORITY_MAGIC "gitswitch-freebsd-authority-v2"
#define M18_RECOVERY_MARKER_MAGIC "gitswitch-recovery-v1"
#define M18_RECOVERY_HEADER_MAX 512U
#define M18_RECOVERY_MAX_BYTES ((8U * 1024U * 1024U) + 512U)
#define M18_FREEBSD_AUTHORITY_MAX_BYTES \
    (M18_RECOVERY_MAX_BYTES + M18_RECOVERY_HEADER_MAX)

typedef struct {
    struct stat lease_stat;
    char stage_leaf[96];
    bool stage_present;
} m18_freebsd_authority_t;

static uint64_t m18_cleanup_leaf_hash(const char *leaf) {
    uint64_t hash = UINT64_C(14695981039346656037);

    if (!leaf) return 0U;
    for (const unsigned char *cursor =
             (const unsigned char *)leaf;
         *cursor; cursor++) {
        hash ^= (uint64_t)*cursor;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t m18_cleanup_leaf_hash_secondary(const char *leaf) {
    uint64_t hash = UINT64_C(7809847782465536322);
    size_t length;

    if (!leaf) return 0U;
    length = strlen(leaf);
    while (length > 0U) {
        hash ^= (uint64_t)(unsigned char)leaf[--length];
        hash *= UINT64_C(1099511628211);
        hash ^= hash >> 32U;
    }
    return hash;
}

static bool m18_next_token(const char **cursor, const char *end,
                           const char **token, size_t *token_length) {
    const char *start;
    const char *separator;

    if (!cursor || !*cursor || !end || !token || !token_length ||
        *cursor >= end || **cursor == ' ') {
        return false;
    }
    start = *cursor;
    separator = memchr(start, ' ', (size_t)(end - start));
    if (!separator) {
        *token = start;
        *token_length = (size_t)(end - start);
        *cursor = end;
        return *token_length != 0U;
    }
    if (separator == start || separator + 1 >= end ||
        separator[1] == ' ') {
        return false;
    }
    *token = start;
    *token_length = (size_t)(separator - start);
    *cursor = separator + 1;
    return true;
}

static bool m18_parse_uintmax(const char *token, size_t token_length,
                              uintmax_t *value) {
    uintmax_t parsed = 0U;

    if (!token || token_length == 0U || !value) return false;
    for (size_t index = 0U; index < token_length; index++) {
        unsigned char byte = (unsigned char)token[index];
        uintmax_t digit;

        if (byte < (unsigned char)'0' ||
            byte > (unsigned char)'9') {
            return false;
        }
        digit = (uintmax_t)(byte - (unsigned char)'0');
        if (parsed > (UINTMAX_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

static bool m18_parse_intmax(const char *token, size_t token_length,
                             intmax_t *value) {
    bool negative;
    uintmax_t magnitude = 0U;
    uintmax_t limit;
    size_t offset;

    if (!token || token_length == 0U || !value) return false;
    negative = token[0] == '-';
    offset = negative ? 1U : 0U;
    if (offset == token_length) return false;
    limit = negative ? (uintmax_t)INTMAX_MAX + 1U
                     : (uintmax_t)INTMAX_MAX;
    for (size_t index = offset; index < token_length; index++) {
        unsigned char byte = (unsigned char)token[index];
        uintmax_t digit;

        if (byte < (unsigned char)'0' ||
            byte > (unsigned char)'9') {
            return false;
        }
        digit = (uintmax_t)(byte - (unsigned char)'0');
        if (magnitude > (limit - digit) / 10U) return false;
        magnitude = magnitude * 10U + digit;
    }
    *value = negative
                 ? (magnitude == (uintmax_t)INTMAX_MAX + 1U
                        ? INTMAX_MIN
                        : -(intmax_t)magnitude)
                 : (intmax_t)magnitude;
    return true;
}

static bool m18_freebsd_stage_leaf_valid(const char *leaf) {
    static const char prefix[] = ".gitswitch-config-v2-";
    const unsigned char *cursor;

    if (!leaf ||
        strncmp(leaf, prefix, sizeof(prefix) - 1U) != 0 ||
        strlen(leaf) >= sizeof(((m18_freebsd_authority_t *)0)
                                   ->stage_leaf)) {
        return false;
    }
    cursor = (const unsigned char *)leaf + sizeof(prefix) - 1U;
    for (size_t index = 0U; index < 32U; index++, cursor++) {
        if (!isxdigit(*cursor) || isupper(*cursor)) return false;
    }
    if (*cursor++ != '-') return false;
    for (size_t index = 0U; index < 8U; index++, cursor++) {
        if (!isxdigit(*cursor) || isupper(*cursor)) return false;
    }
    if (*cursor++ != '-') return false;
    for (size_t index = 0U; index < 4U; index++, cursor++) {
        if (!isdigit(*cursor)) return false;
    }
    return *cursor++ == '-' &&
           (*cursor == 's' || *cursor == 'o') &&
           cursor[1] == '\0';
}

static bool m18_parse_recovery_marker(
    const unsigned char *data, size_t length, char stage_leaf[96],
    bool *stage_present) {
    const unsigned char *newline;
    char header[M18_RECOVERY_HEADER_MAX];
    char canonical[M18_RECOVERY_HEADER_MAX];
    const char *cursor;
    const char *end;
    const char *token;
    size_t token_length;
    size_t header_length;
    size_t marker_offset;
    size_t magic_length = sizeof(M18_RECOVERY_MARKER_MAGIC) - 1U;
    uintmax_t values[7];
    intmax_t mtime_seconds;
    uintmax_t mtime_nanoseconds;
    uintmax_t payload_length;
    struct stat parsed;
    int written;

    if (!data || !stage_leaf || !stage_present || length == 0U ||
        length > M18_RECOVERY_MAX_BYTES) {
        return false;
    }
    newline = memchr(data, '\n', length);
    if (!newline) return false;
    header_length = (size_t)(newline - data);
    marker_offset = header_length + 1U;
    if (header_length <= magic_length ||
        header_length >= sizeof(header) ||
        memchr(data, '\0', header_length) != NULL) {
        return false;
    }
    memcpy(header, data, header_length);
    header[header_length] = '\0';
    if (memcmp(header, M18_RECOVERY_MARKER_MAGIC, magic_length) != 0 ||
        header[magic_length] != ' ') {
        return false;
    }
    cursor = header + magic_length + 1U;
    end = header + header_length;
    if (!m18_next_token(&cursor, end, &token, &token_length) ||
        token_length >= 96U) {
        return false;
    }
    memcpy(stage_leaf, token, token_length);
    stage_leaf[token_length] = '\0';
    for (size_t index = 0U; index < 7U; index++) {
        if (!m18_next_token(&cursor, end, &token, &token_length) ||
            !m18_parse_uintmax(token, token_length, &values[index])) {
            return false;
        }
    }
    if (!m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_intmax(token, token_length, &mtime_seconds) ||
        !m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_uintmax(token, token_length, &mtime_nanoseconds) ||
        !m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_uintmax(token, token_length, &payload_length) ||
        cursor != end || mtime_nanoseconds > 999999999U ||
        payload_length > SIZE_MAX ||
        (size_t)payload_length != length - marker_offset) {
        return false;
    }
    memset(&parsed, 0, sizeof(parsed));
    parsed.st_dev = (dev_t)values[0];
    parsed.st_ino = (ino_t)values[1];
    parsed.st_mode = (mode_t)values[2];
    parsed.st_uid = (uid_t)values[3];
    parsed.st_gid = (gid_t)values[4];
    parsed.st_size = (off_t)values[5];
    parsed.st_nlink = (nlink_t)values[6];
    parsed.st_mtim.tv_sec = (time_t)mtime_seconds;
    parsed.st_mtim.tv_nsec = (long)mtime_nanoseconds;
    if ((uintmax_t)parsed.st_dev != values[0] ||
        (uintmax_t)parsed.st_ino != values[1] ||
        (uintmax_t)parsed.st_mode != values[2] ||
        (uintmax_t)parsed.st_uid != values[3] ||
        (uintmax_t)parsed.st_gid != values[4] ||
        parsed.st_size < 0 ||
        (uintmax_t)parsed.st_size != values[5] ||
        (uintmax_t)parsed.st_nlink != values[6] ||
        (intmax_t)parsed.st_mtim.tv_sec != mtime_seconds ||
        parsed.st_mtim.tv_nsec != (long)mtime_nanoseconds) {
        return false;
    }
    written = snprintf(
        canonical, sizeof(canonical),
        M18_RECOVERY_MARKER_MAGIC
        " %s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIdMAX
        " %ld %" PRIuMAX,
        stage_leaf, values[0], values[1], values[2], values[3],
        values[4], values[5], values[6], mtime_seconds,
        (long)mtime_nanoseconds, payload_length);
    if (written < 0 || (size_t)written >= sizeof(canonical) ||
        strcmp(header, canonical) != 0) {
        return false;
    }
    if (strcmp(stage_leaf, "-") == 0) {
        for (size_t index = 0U; index < 7U; index++) {
            if (values[index] != 0U) return false;
        }
        if (mtime_seconds != 0 || mtime_nanoseconds != 0U ||
            payload_length != 0U) {
            return false;
        }
        *stage_present = false;
        return true;
    }
    if (!m18_freebsd_stage_leaf_valid(stage_leaf) ||
        !S_ISREG(parsed.st_mode) || parsed.st_nlink != 1 ||
        parsed.st_size != (off_t)payload_length) {
        return false;
    }
    *stage_present = true;
    return true;
}

static bool m18_parse_freebsd_authority(
    const unsigned char *data, size_t length,
    m18_freebsd_authority_t *authority) {
    const unsigned char *newline;
    char header[M18_RECOVERY_HEADER_MAX];
    char canonical[M18_RECOVERY_HEADER_MAX];
    const char *cursor;
    const char *end;
    const char *token;
    size_t token_length;
    size_t header_length;
    size_t marker_offset;
    size_t magic_length = sizeof(M18_FREEBSD_AUTHORITY_MAGIC) - 1U;
    uintmax_t values[7];
    intmax_t mtime_seconds;
    uintmax_t mtime_nanoseconds;
    uintmax_t marker_length;
    struct stat parsed;
    int written;

    if (!data || !authority || length == 0U ||
        length > M18_FREEBSD_AUTHORITY_MAX_BYTES) {
        return false;
    }
    newline = memchr(data, '\n', length);
    if (!newline) return false;
    header_length = (size_t)(newline - data);
    marker_offset = header_length + 1U;
    if (header_length <= magic_length ||
        header_length >= sizeof(header) ||
        memchr(data, '\0', header_length) != NULL) {
        return false;
    }
    memcpy(header, data, header_length);
    header[header_length] = '\0';
    if (memcmp(header, M18_FREEBSD_AUTHORITY_MAGIC, magic_length) != 0 ||
        header[magic_length] != ' ') {
        return false;
    }
    cursor = header + magic_length + 1U;
    end = header + header_length;
    for (size_t index = 0U; index < 7U; index++) {
        if (!m18_next_token(&cursor, end, &token, &token_length) ||
            !m18_parse_uintmax(token, token_length, &values[index])) {
            return false;
        }
    }
    if (!m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_intmax(token, token_length, &mtime_seconds) ||
        !m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_uintmax(token, token_length, &mtime_nanoseconds) ||
        !m18_next_token(&cursor, end, &token, &token_length) ||
        !m18_parse_uintmax(token, token_length, &marker_length) ||
        cursor != end || marker_length > SIZE_MAX ||
        (size_t)marker_length != length - marker_offset ||
        mtime_nanoseconds > 999999999U) {
        return false;
    }
    memset(&parsed, 0, sizeof(parsed));
    parsed.st_dev = (dev_t)values[0];
    parsed.st_ino = (ino_t)values[1];
    parsed.st_mode = (mode_t)values[2];
    parsed.st_uid = (uid_t)values[3];
    parsed.st_gid = (gid_t)values[4];
    parsed.st_size = (off_t)values[5];
    parsed.st_nlink = (nlink_t)values[6];
    parsed.st_mtim.tv_sec = (time_t)mtime_seconds;
    parsed.st_mtim.tv_nsec = (long)mtime_nanoseconds;
    if ((uintmax_t)parsed.st_dev != values[0] ||
        (uintmax_t)parsed.st_ino != values[1] ||
        (uintmax_t)parsed.st_mode != values[2] ||
        (uintmax_t)parsed.st_uid != values[3] ||
        (uintmax_t)parsed.st_gid != values[4] ||
        parsed.st_size < 0 ||
        (uintmax_t)parsed.st_size != values[5] ||
        (uintmax_t)parsed.st_nlink != values[6] ||
        (intmax_t)parsed.st_mtim.tv_sec != mtime_seconds ||
        parsed.st_mtim.tv_nsec != (long)mtime_nanoseconds ||
        !S_ISREG(parsed.st_mode) || parsed.st_size != 0 ||
        parsed.st_nlink != 2 || parsed.st_uid != geteuid()) {
        return false;
    }
    written = snprintf(
        canonical, sizeof(canonical),
        M18_FREEBSD_AUTHORITY_MAGIC
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIdMAX
        " %ld %" PRIuMAX,
        values[0], values[1], values[2], values[3], values[4],
        values[5], values[6], mtime_seconds,
        (long)mtime_nanoseconds, marker_length);
    if (written < 0 || (size_t)written >= sizeof(canonical) ||
        strcmp(header, canonical) != 0 ||
        !m18_parse_recovery_marker(
            data + marker_offset, (size_t)marker_length,
            authority->stage_leaf, &authority->stage_present)) {
        return false;
    }
    authority->lease_stat = parsed;
    return true;
}

static int m18_read_fd_bytes(int fd, const struct stat *expected,
                             m18_bytes_t *bytes) {
    unsigned char *data;
    size_t used = 0U;
    struct stat after;

    if (fd < 0 || !expected || !bytes || expected->st_size <= 0 ||
        (uintmax_t)expected->st_size >
            (uintmax_t)M18_FREEBSD_AUTHORITY_MAX_BYTES) {
        return -1;
    }
    data = malloc((size_t)expected->st_size + 1U);
    if (!data) return -1;
    while (used < (size_t)expected->st_size) {
        ssize_t got = pread(
            fd, data + used, (size_t)expected->st_size - used,
            (off_t)used);

        if (got > 0) {
            used += (size_t)got;
        } else if (got < 0 && errno == EINTR) {
            continue;
        } else {
            free(data);
            return -1;
        }
    }
    if (fstat(fd, &after) != 0 ||
        !m18_same_without_ctime(expected, &after)) {
        free(data);
        return -1;
    }
    data[used] = '\0';
    bytes->data = data;
    bytes->length = used;
    return 0;
}

static int m18_freebsd_terminal_marker_checkpoint_status(
    const char *lock_path, const char *config_path, bool expect_stage) {
    m18_freebsd_authority_t authority;
    m18_bytes_t authority_bytes = {0};
    char parent[MAX_PATH_LEN];
    char authority_prefix[80];
    char authority_leaf[96] = "";
    char lease_leaf[96];
    const char *slash;
    const char *lock_leaf;
    const char *slot;
    size_t parent_length;
    size_t prefix_length;
    int parent_fd = -1;
    int scan_fd = -1;
    int authority_fd = -1;
    DIR *directory = NULL;
    struct dirent *entry;
    struct stat canonical;
    struct stat authority_stat;
    struct stat named_authority;
    struct stat lease;
    struct stat stage;
    int matches = 0;
    int result = M18_TERMINAL_WRITER_INVALID_MARKER;

    memset(&authority, 0, sizeof(authority));
    slash = lock_path ? strrchr(lock_path, '/') : NULL;
    if (!slash || !config_path) goto cleanup;
    lock_leaf = slash + 1U;
    if (*lock_leaf == '\0') goto cleanup;
    parent_length = slash == lock_path
                        ? 1U
                        : (size_t)(slash - lock_path);
    if (parent_length >= sizeof(parent)) goto cleanup;
    memcpy(parent, lock_path, parent_length);
    parent[parent_length] = '\0';
    parent_fd = open(
        parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0 ||
        fstatat(parent_fd, lock_leaf, &canonical,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(canonical.st_mode) || canonical.st_size != 0 ||
        canonical.st_nlink != 2 || canonical.st_uid != geteuid() ||
        (canonical.st_mode & 07777) != 0600 ||
        (size_t)snprintf(
            authority_prefix, sizeof(authority_prefix),
            ".gitswitch-recovery-v2-%016" PRIx64
            "%016" PRIx64 "-%08zx-",
            m18_cleanup_leaf_hash(lock_leaf),
            m18_cleanup_leaf_hash_secondary(lock_leaf),
            strlen(lock_leaf)) >= sizeof(authority_prefix)) {
        goto cleanup;
    }
    prefix_length = strlen(authority_prefix);
    scan_fd = openat(
        parent_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        goto cleanup;
    }
    scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, authority_prefix,
                    prefix_length) != 0) {
            continue;
        }
        matches++;
        if (matches != 1 ||
            strlen(entry->d_name) >= sizeof(authority_leaf)) {
            goto cleanup;
        }
        memcpy(authority_leaf, entry->d_name,
               strlen(entry->d_name) + 1U);
    }
    if (errno != 0 || matches != 1) goto cleanup;
    slot = authority_leaf + prefix_length;
    if (strlen(slot) != 4U ||
        !isdigit((unsigned char)slot[0]) ||
        !isdigit((unsigned char)slot[1]) ||
        !isdigit((unsigned char)slot[2]) ||
        !isdigit((unsigned char)slot[3])) {
        goto cleanup;
    }
    authority_fd = openat(
        parent_fd, authority_leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (authority_fd < 0 || fstat(authority_fd, &authority_stat) != 0 ||
        !S_ISREG(authority_stat.st_mode) ||
        authority_stat.st_nlink != 1 ||
        authority_stat.st_uid != geteuid() ||
        (authority_stat.st_mode & 07777) != 0600 ||
        m18_read_fd_bytes(
            authority_fd, &authority_stat, &authority_bytes) != 0 ||
        fstatat(parent_fd, authority_leaf, &named_authority,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !m18_same_without_ctime(&authority_stat, &named_authority) ||
        !m18_parse_freebsd_authority(
            authority_bytes.data, authority_bytes.length, &authority) ||
        !m18_same_without_ctime(&canonical, &authority.lease_stat)) {
        goto cleanup;
    }
    if ((size_t)snprintf(
            lease_leaf, sizeof(lease_leaf),
            ".gitswitch-lease-v2-%016" PRIx64
            "%016" PRIx64 "-%08zx-%s",
            m18_cleanup_leaf_hash(lock_leaf),
            m18_cleanup_leaf_hash_secondary(lock_leaf),
            strlen(lock_leaf), slot) >= sizeof(lease_leaf) ||
        fstatat(parent_fd, lease_leaf, &lease,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !m18_same_without_ctime(&canonical, &lease)) {
        goto cleanup;
    }
    if (authority.stage_present != expect_stage) goto cleanup;
    if (!expect_stage) {
        result = M18_TERMINAL_WRITER_BLOCKED;
        goto cleanup;
    }
    errno = 0;
    if (fstatat(parent_fd, authority.stage_leaf, &stage,
                AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        result = M18_TERMINAL_WRITER_STAGE_NOT_SETTLED;
        goto cleanup;
    }
    result = M18_TERMINAL_WRITER_BLOCKED;

cleanup:
    if (directory) (void)closedir(directory);
    if (scan_fd >= 0) (void)close(scan_fd);
    if (authority_fd >= 0) (void)close(authority_fd);
    if (parent_fd >= 0) (void)close(parent_fd);
    m18_bytes_clear(&authority_bytes);
    return result;
}
#endif

/* Run only in the forked writer probe. Opening and closing the canonical lock
 * in its owner process would release that process's POSIX record locks. */
static int m18_terminal_marker_checkpoint_status(
    const char *lock_path, const char *config_path, bool expect_stage) {
#if defined(__FreeBSD__)
    return m18_freebsd_terminal_marker_checkpoint_status(
        lock_path, config_path, expect_stage);
#else
    static const unsigned char magic[] = "gitswitch-recovery-v1 ";
    static const char stage_prefix[] = ".gitswitch-config-";
    m18_bytes_t marker = {0};
    struct stat before;
    struct stat after;
    const unsigned char *stage_start;
    const unsigned char *stage_end;
    const unsigned char *newline;
    char stage_leaf[96];
    char parent[MAX_PATH_LEN];
    const char *slash;
    size_t parent_length;
    size_t stage_length;
    int parent_fd = -1;
    int result = M18_TERMINAL_WRITER_INVALID_MARKER;

    if (!lock_path || !config_path ||
        lstat(lock_path, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        before.st_uid != geteuid() ||
        (before.st_mode & 07777) != 0600 ||
        before.st_size <= 0 ||
        m18_read_bytes(lock_path, &marker) != 0 ||
        marker.length != (size_t)before.st_size ||
        marker.length <= sizeof(magic) - 1U ||
        memcmp(marker.data, magic, sizeof(magic) - 1U) != 0 ||
        lstat(lock_path, &after) != 0 ||
        !m18_same_without_ctime(&before, &after) ||
        !m18_same_ctime(&before, &after)) {
        goto cleanup;
    }
    newline = memchr(marker.data, '\n', marker.length);
    stage_start = marker.data + sizeof(magic) - 1U;
    if (!newline || newline <= stage_start) goto cleanup;
    stage_end = memchr(
        stage_start, ' ', (size_t)(newline - stage_start));
    if (!stage_end || stage_end == stage_start) goto cleanup;
    stage_length = (size_t)(stage_end - stage_start);
    if (stage_length >= sizeof(stage_leaf)) goto cleanup;
    memcpy(stage_leaf, stage_start, stage_length);
    stage_leaf[stage_length] = '\0';
    if (!expect_stage) {
        result = strcmp(stage_leaf, "-") == 0
                     ? M18_TERMINAL_WRITER_BLOCKED
                     : M18_TERMINAL_WRITER_INVALID_MARKER;
        goto cleanup;
    }
    if (strncmp(stage_leaf, stage_prefix,
                sizeof(stage_prefix) - 1U) != 0) {
        goto cleanup;
    }
    {
        const unsigned char *cursor =
            (const unsigned char *)stage_leaf +
            sizeof(stage_prefix) - 1U;

        if (!isdigit(*cursor)) goto cleanup;
        while (isdigit(*cursor)) cursor++;
        if (*cursor++ != '-' || !isdigit(*cursor)) goto cleanup;
        while (isdigit(*cursor)) cursor++;
        if (*cursor != '\0') goto cleanup;
    }
    slash = strrchr(config_path, '/');
    if (!slash) goto cleanup;
    parent_length = slash == config_path
                        ? 1U
                        : (size_t)(slash - config_path);
    if (parent_length >= sizeof(parent)) goto cleanup;
    memcpy(parent, config_path, parent_length);
    parent[parent_length] = '\0';
    parent_fd = open(
        parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0) goto cleanup;
    errno = 0;
    if (fstatat(parent_fd, stage_leaf, &after,
                AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        result = M18_TERMINAL_WRITER_STAGE_NOT_SETTLED;
        goto cleanup;
    }
    result = M18_TERMINAL_WRITER_BLOCKED;

cleanup:
    if (parent_fd >= 0) (void)close(parent_fd);
    m18_bytes_clear(&marker);
    return result;
#endif
}

/* Model Git's cooperative writer protocol at the last test checkpoint before
 * the retirement completion rename. A writer may publish only after creating
 * the canonical <config>.lock name with O_EXCL. */
static int m18_terminal_writer_hook(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name) {
    static const char replacement[] =
        "[fixture]\n\tmarker = concurrent-writer\n";
    char lock_path[MAX_PATH_LEN];
    pid_t writer;
    int status;

    (void)descriptor;
    if (stage !=
            RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME ||
        !marker_name ||
        strcmp(marker_name, ".retirement-complete") != 0) {
        return 0;
    }
    m18_terminal_writer_checkpoint_observed = true;
    if (!m18_terminal_writer_fixture || !m18_terminal_writer_path ||
        safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                      m18_terminal_writer_path) != 0) {
        m18_terminal_writer_result = M18_TERMINAL_WRITER_ERROR;
        return 0;
    }
    writer = fork();
    if (writer < 0) {
        m18_terminal_writer_result = M18_TERMINAL_WRITER_ERROR;
        return 0;
    }
    if (writer == 0) {
        int directory_fd;
        int checkpoint_status = m18_terminal_marker_checkpoint_status(
            lock_path, m18_terminal_writer_path,
            m18_terminal_writer_expect_stage);
        int lock_fd;

        if (checkpoint_status != M18_TERMINAL_WRITER_BLOCKED) {
            _exit(checkpoint_status);
        }
        lock_fd = open(
            lock_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);

        if (lock_fd < 0) {
            _exit(errno == EEXIST ? M18_TERMINAL_WRITER_BLOCKED
                                 : M18_TERMINAL_WRITER_ERROR);
        }
        if (m18_write_all(
                lock_fd, replacement, sizeof(replacement) - 1U) != 0 ||
            fsync(lock_fd) != 0 || close(lock_fd) != 0 ||
            rename(lock_path, m18_terminal_writer_path) != 0) {
            _exit(M18_TERMINAL_WRITER_ERROR);
        }
        directory_fd = open(
            m18_terminal_writer_fixture->home,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory_fd < 0 || fsync(directory_fd) != 0 ||
            close(directory_fd) != 0) {
            _exit(M18_TERMINAL_WRITER_ERROR);
        }
        _exit(M18_TERMINAL_WRITER_PUBLISHED);
    }
    status = m18_wait_status(writer);
    if (!WIFEXITED(status)) {
        m18_terminal_writer_result = M18_TERMINAL_WRITER_ERROR;
    } else {
        m18_terminal_writer_result = WEXITSTATUS(status);
    }
    if (m18_terminal_precommit_failure_requested) {
        m18_terminal_precommit_failure_observed = true;
        errno = EIO;
        return -1;
    }
    return 0;
}

static int m18_run_cli_after_matches(
    const m18_fixture_t *fixture, m18_command_t command,
    size_t fault_limit, config_io_boundary_t boundary,
    size_t fault_matches_to_skip, bool *fault_observed) {
    int observed_pipe[2];
    bool observation_read_failed = false;
    bool requested_fault_unobserved = false;
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
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
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
        m18_prepare_ctime_drift_observed = false;
        m18_prepare_ctime_drift_error = 0;
        m18_prepublish_ctime_drift_calls = 0U;
        m18_prepublish_ctime_drift_count = 0U;
        m18_prepublish_ctime_drift_error = 0;
        m18_prepublish_byte_rewrite_observed = false;
        m18_prepublish_byte_rewrite_error = 0;
        m18_recovery_end_probe_observed = false;
        m18_prepare_preceded_recovery_end = false;
        m18_final_prepared_read_epoch = false;
        m18_final_prepared_read_count = 0U;
        m18_recovery_end_after_final_prepared_reads = false;
        m18_prepared_read_after_recovery_end = false;
        m18_absent_recreation_observed = false;
        m18_absent_recreation_guard_observed = false;
        m18_absent_recreation_error = 0;
        m18_terminal_writer_checkpoint_observed = false;
        m18_terminal_writer_result = M18_TERMINAL_WRITER_NOT_RUN;
        m18_terminal_cleanup_observed = false;
        m24_alias_fault_observed = false;
        m24_alias_commit_observed = false;
        m24_recovery_claimant_observed = false;
        m24_recovery_claimant_error = 0;
        m24_recovery_end_failure_observed = false;
        if (fault_limit != M18_FAULT_NONE) {
            (void)config_set_io_fault_fn(m18_config_fault);
        }
        if (m18_terminal_writer_requested) {
            (void)gitswitch_test_set_retirement_guard_clear_hook(
                m18_terminal_writer_hook);
        } else if (m18_clear_after_stage_write_fault ||
            m18_prepare_ctime_drift_requested ||
            m18_prepublish_ctime_drift_requested ||
            m18_prepublish_byte_rewrite_requested ||
            m18_final_prepared_read_order_requested) {
            (void)gitswitch_test_set_retirement_guard_clear_hook(
                m18_retirement_clear_fault);
        }
        if (m18_witness_ctime_drifts_remaining != 0U ||
            m18_absent_recreation_requested ||
            m18_recovery_end_probe_requested ||
            m24_recovery_end_failure_requested ||
            m18_terminal_cleanup_failure_requested) {
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
        } else if (m24_alias_commit_probe_requested) {
            (void)ssh_manager_set_config_commit_hook_fn(
                m24_observe_alias_commit);
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
        if (m18_terminal_writer_requested &&
            (!m18_terminal_writer_checkpoint_observed ||
             m18_terminal_writer_result !=
                 M18_TERMINAL_WRITER_BLOCKED)) {
            fprintf(
                stderr,
                "[M18 terminal writer escaped: checkpoint=%d result=%d]\n",
                m18_terminal_writer_checkpoint_observed,
                m18_terminal_writer_result);
            _exit(132);
        }
        if (m18_witness_ctime_drift_error != 0 ||
            m18_witness_ctime_drifts_remaining != 0U) {
            fprintf(stderr,
                    "[M18 restored-witness drift incomplete: remaining=%zu error=%d]\n",
                    m18_witness_ctime_drifts_remaining,
                    m18_witness_ctime_drift_error);
            _exit(124);
        }
        if (m18_prepare_ctime_drift_requested &&
            (!m18_prepare_ctime_drift_observed ||
             m18_prepare_ctime_drift_error != 0)) {
            fprintf(
                stderr,
                "[M18 prepared-stage drift incomplete: observed=%d "
                "error=%d]\n",
                m18_prepare_ctime_drift_observed,
                m18_prepare_ctime_drift_error);
            _exit(128);
        }
        if (m18_prepublish_ctime_drift_requested &&
            (m18_prepublish_ctime_drift_error != 0 ||
             m18_prepublish_ctime_drift_calls !=
                 m18_prepublish_ctime_drift_expected_calls ||
             m18_prepublish_ctime_drift_count !=
                 m18_prepublish_ctime_drift_expected_count ||
             m18_prepublish_ctime_drift_budget !=
                 m18_prepublish_ctime_drift_expected_remaining)) {
            fprintf(
                stderr,
                "[M18 prepublish drift mismatch: calls=%zu/%zu "
                "drifts=%zu/%zu remaining=%zu/%zu error=%d]\n",
                m18_prepublish_ctime_drift_calls,
                m18_prepublish_ctime_drift_expected_calls,
                m18_prepublish_ctime_drift_count,
                m18_prepublish_ctime_drift_expected_count,
                m18_prepublish_ctime_drift_budget,
                m18_prepublish_ctime_drift_expected_remaining,
                m18_prepublish_ctime_drift_error);
            _exit(130);
        }
        if (m18_prepublish_byte_rewrite_requested &&
            (!m18_prepublish_byte_rewrite_observed ||
             m18_prepublish_byte_rewrite_error != 0)) {
            fprintf(
                stderr,
                "[M18 prepublish byte rewrite incomplete: observed=%d "
                "error=%d]\n",
                m18_prepublish_byte_rewrite_observed,
                m18_prepublish_byte_rewrite_error);
            _exit(136);
        }
        if (m18_recovery_end_probe_requested &&
            (!m18_recovery_end_probe_observed ||
             (!m18_final_prepared_read_order_requested &&
              !m18_prepare_preceded_recovery_end))) {
            fprintf(
                stderr,
                "[M18 recovery ordering incomplete: recovery-end=%d "
                "prepare-first=%d]\n",
                m18_recovery_end_probe_observed,
                m18_prepare_preceded_recovery_end);
            _exit(129);
        }
        if (m18_final_prepared_read_order_requested &&
            (!m18_recovery_end_after_final_prepared_reads ||
             m18_final_prepared_read_count != 5U ||
             !m18_prepared_read_after_recovery_end)) {
            fprintf(
                stderr,
                "[M18 terminal verification ordering mismatch: "
                "verify-after-initial=%d reads=%zu post-verify-read=%d]\n",
                m18_recovery_end_after_final_prepared_reads,
                m18_final_prepared_read_count,
                m18_prepared_read_after_recovery_end);
            _exit(131);
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
        if (m24_alias_commit_observed) observed |= 16U;
        if (m18_prepare_ctime_drift_observed) observed |= 32U;
        if (m18_recovery_end_probe_observed) observed |= 64U;
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
        observation_read_failed = got != 1;
        requested_fault_unobserved =
            fault_limit != M18_FAULT_NONE &&
            (got != 1 || (observed & 1U) == 0U);
        if (fault_observed && got == 1) {
            *fault_observed = (observed & 1U) != 0U;
        }
        m24_alias_fault_observed =
            got == 1 && (observed & 2U) != 0U;
        m24_recovery_claimant_observed =
            got == 1 && (observed & 4U) != 0U;
        m24_recovery_end_failure_observed =
            got == 1 && (observed & 8U) != 0U;
        m24_alias_commit_observed =
            got == 1 && (observed & 16U) != 0U;
        m18_prepare_ctime_drift_observed =
            got == 1 && (observed & 32U) != 0U;
        m18_recovery_end_probe_observed =
            got == 1 && (observed & 64U) != 0U;
    }
    (void)close(observed_pipe[0]);
    {
        int status = m18_wait_status(child);
        const char *debug = getenv("M18_DEBUG");
        bool harness_sentinel =
            WIFEXITED(status) && WEXITSTATUS(status) >= 120 &&
            WEXITSTATUS(status) <= 136;

        if (observation_read_failed || requested_fault_unobserved ||
            harness_sentinel || (debug && strcmp(debug, "1") == 0)) {
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

    m18_witness_ctime_drift_stage =
        GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE;
    m18_witness_ctime_drifts_remaining = witness_ctime_drifts;
    status = m18_run_cli(fixture, command, fault_limit, boundary,
                         fault_observed);
    m18_witness_ctime_drifts_remaining = 0U;
    return status;
}

static int m18_run_cli_with_post_read_ctime_drifts(
    const m18_fixture_t *fixture, m18_command_t command,
    size_t fault_limit, config_io_boundary_t boundary,
    size_t witness_ctime_drifts, bool *fault_observed) {
    int status;

    m18_witness_ctime_drift_stage =
        GIT_RETIREMENT_TEST_AFTER_RESTORED_WITNESS_READ;
    m18_witness_ctime_drifts_remaining = witness_ctime_drifts;
    status = m18_run_cli(fixture, command, fault_limit, boundary,
                         fault_observed);
    m18_witness_ctime_drifts_remaining = 0U;
    m18_witness_ctime_drift_stage =
        GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE;
    return status;
}

static int m18_run_cli_with_final_read_ctime_drifts(
    const m18_fixture_t *fixture, m18_command_t command,
    size_t fault_limit, config_io_boundary_t boundary,
    size_t witness_ctime_drifts, bool *fault_observed) {
    int status;

    m18_witness_ctime_drift_stage =
        GIT_RETIREMENT_TEST_AFTER_FINAL_RESTORED_WITNESS_READ;
    m18_witness_ctime_drifts_remaining = witness_ctime_drifts;
    status = m18_run_cli(fixture, command, fault_limit, boundary,
                         fault_observed);
    m18_witness_ctime_drifts_remaining = 0U;
    m18_witness_ctime_drift_stage =
        GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE;
    return status;
}

static int m18_run_cli_with_prepared_stage_ctime_drift(
    const m18_fixture_t *fixture, config_io_boundary_t boundary,
    bool *fault_observed) {
    int status;

    m18_prepare_ctime_drift_requested = true;
    m18_prepare_ctime_drift_observed = false;
    m18_prepare_ctime_drift_error = 0;
    m18_prepare_ctime_drift_fixture = fixture;
    status = m18_run_cli(
        fixture, M18_COMMAND_REMOVE, M18_FAULT_ONCE,
        boundary, fault_observed);
    m18_prepare_ctime_drift_requested = false;
    m18_prepare_ctime_drift_error = 0;
    m18_prepare_ctime_drift_fixture = NULL;
    return status;
}

static int m18_run_cli_with_prepublish_ctime_drifts(
    const m18_fixture_t *fixture, size_t drift_budget,
    size_t expected_calls, size_t expected_drifts,
    size_t expected_remaining, bool *fault_observed) {
    int status;

    m18_prepublish_ctime_drift_requested = true;
    m18_prepublish_ctime_drift_fixture = fixture;
    m18_prepublish_ctime_drift_budget = drift_budget;
    m18_prepublish_ctime_drift_expected_calls = expected_calls;
    m18_prepublish_ctime_drift_expected_count = expected_drifts;
    m18_prepublish_ctime_drift_expected_remaining =
        expected_remaining;
    status = m18_run_cli(
        fixture, M18_COMMAND_REMOVE, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_DIR_SYNC, fault_observed);
    m18_prepublish_ctime_drift_requested = false;
    m18_prepublish_ctime_drift_fixture = NULL;
    m18_prepublish_ctime_drift_budget = 0U;
    m18_prepublish_ctime_drift_expected_calls = 0U;
    m18_prepublish_ctime_drift_expected_count = 0U;
    m18_prepublish_ctime_drift_expected_remaining = 0U;
    m18_prepublish_ctime_drift_error = 0;
    return status;
}

static int m18_run_cli_with_prepublish_byte_rewrite(
    const m18_fixture_t *fixture, bool *fault_observed) {
    int status;

    m18_prepublish_byte_rewrite_requested = true;
    m18_prepublish_byte_rewrite_observed = false;
    m18_prepublish_byte_rewrite_error = 0;
    m18_prepublish_byte_rewrite_fixture = fixture;
    status = m18_run_cli(
        fixture, M18_COMMAND_REMOVE, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_DIR_SYNC, fault_observed);
    m18_prepublish_byte_rewrite_requested = false;
    m18_prepublish_byte_rewrite_observed = false;
    m18_prepublish_byte_rewrite_error = 0;
    m18_prepublish_byte_rewrite_fixture = NULL;
    return status;
}

static int m18_run_cli_with_absent_recreation(
    const m18_fixture_t *fixture, const m18_bytes_t *replacement,
    bool *hook_observed) {
    int status;

    if (!fixture || !replacement || !replacement->data) return -1;
    m18_absent_recreation_requested = true;
    m18_absent_recreation_fixture = fixture;
    m18_absent_recreation_path = fixture->git_path;
    m18_absent_recreation_operation = "remove";
    m18_absent_recreation_require_transition = false;
    m18_absent_recreation_bytes = *replacement;
    status = m18_run_cli(
        fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, hook_observed);
    m18_absent_recreation_requested = false;
    m18_absent_recreation_fixture = NULL;
    m18_absent_recreation_path = NULL;
    m18_absent_recreation_operation = NULL;
    m18_absent_recreation_require_transition = false;
    memset(&m18_absent_recreation_bytes, 0,
           sizeof(m18_absent_recreation_bytes));
    return status;
}

static int m18_run_reset_all_with_terminal_absent_recreation(
    const m18_fixture_t *fixture, const m18_bytes_t *replacement,
    bool *hook_observed) {
    int status;

    if (!fixture || !replacement || !replacement->data) return -1;
    m18_absent_recreation_requested = true;
    m18_absent_recreation_fixture = fixture;
    m18_absent_recreation_path = fixture->no_op_git_path;
    m18_absent_recreation_operation = "reset";
    /* The transition stage is installed before the ledger seal. The next
     * absent revalidation is the guard's final post-ledger barrier. */
    m18_absent_recreation_require_transition = true;
    m18_absent_recreation_bytes = *replacement;
    status = m18_run_cli(
        fixture, M18_COMMAND_RESET_ALL, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, hook_observed);
    m18_absent_recreation_requested = false;
    m18_absent_recreation_fixture = NULL;
    m18_absent_recreation_path = NULL;
    m18_absent_recreation_operation = NULL;
    m18_absent_recreation_require_transition = false;
    memset(&m18_absent_recreation_bytes, 0,
           sizeof(m18_absent_recreation_bytes));
    return status;
}

static int m18_run_reset_all_with_terminal_absent_writer(
    const m18_fixture_t *fixture, bool *fault_observed) {
    int status;

    if (!fixture || fixture->no_op_git_path[0] == '\0') return -1;
    m18_terminal_writer_fixture = fixture;
    m18_terminal_writer_path = fixture->no_op_git_path;
    m18_terminal_writer_expect_stage = false;
    m18_terminal_writer_requested = true;
    status = m18_run_cli(
        fixture, M18_COMMAND_RESET_ALL, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, fault_observed);
    m18_terminal_writer_requested = false;
    m18_terminal_writer_fixture = NULL;
    m18_terminal_writer_path = NULL;
    m18_terminal_writer_expect_stage = false;
    return status;
}

static int m18_run_reset_all_with_prepublish_ctime_drift(
    const m18_fixture_t *fixture, bool *fault_observed) {
    int status;

    m18_prepublish_ctime_drift_requested = true;
    m18_prepublish_ctime_drift_fixture = fixture;
    m18_prepublish_ctime_drift_budget = 1U;
    m18_prepublish_ctime_drift_expected_calls = 3U;
    m18_prepublish_ctime_drift_expected_count = 1U;
    m18_prepublish_ctime_drift_expected_remaining = 0U;
    status = m18_run_cli(
        fixture, M18_COMMAND_RESET_ALL, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, fault_observed);
    m18_prepublish_ctime_drift_requested = false;
    m18_prepublish_ctime_drift_fixture = NULL;
    m18_prepublish_ctime_drift_budget = 0U;
    m18_prepublish_ctime_drift_expected_calls = 0U;
    m18_prepublish_ctime_drift_expected_count = 0U;
    m18_prepublish_ctime_drift_expected_remaining = 0U;
    m18_prepublish_ctime_drift_error = 0;
    return status;
}

typedef enum {
    M18_PHASE_COMPLETE = 0,
    M18_PHASE_CANCEL
} m18_phase_mode_t;

typedef enum {
    M18_PREPARE_GUARD_FRESH = 0,
    M18_PREPARE_GUARD_ADOPTED,
    M18_PREPARE_GUARD_CLEAR_UNCERTAIN
} m18_prepare_guard_mode_t;

typedef enum {
    M18_PUBLISH_GUARD_NO_MUTATION_FRESH = 0,
    M18_PUBLISH_GUARD_MUTATION_CAPABLE_FRESH,
    M18_PUBLISH_GUARD_NO_MUTATION_ADOPTED,
    M18_PUBLISH_GUARD_CLEANUP_UNCERTAIN_FRESH
} m18_publish_guard_mode_t;

static m18_publish_guard_mode_t m18_publish_guard_mode;
static const m18_fixture_t *m18_publish_guard_fixture;
static bool m18_publish_guard_fault_observed;
static bool m18_publish_guard_cleanup_fault_observed;

static bool m18_publish_guard_fault(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value) {
    git_retirement_test_stage_t expected_stage =
        m18_publish_guard_mode ==
                M18_PUBLISH_GUARD_MUTATION_CAPABLE_FRESH
            ? GIT_RETIREMENT_TEST_BEFORE_PUBLISH
            : GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS;

    (void)key;
    (void)value;
    if (!m18_publish_guard_fixture || !path ||
        strcmp(path, m18_publish_guard_fixture->git_path) != 0) {
        return false;
    }
    if (m18_publish_guard_mode ==
        M18_PUBLISH_GUARD_CLEANUP_UNCERTAIN_FRESH) {
        if (stage == GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE) {
            m18_publish_guard_fault_observed = true;
            errno = EIO;
            return true;
        }
        if (stage == GIT_RETIREMENT_TEST_BEFORE_CLEANUP) {
            m18_publish_guard_cleanup_fault_observed = true;
            errno = EIO;
            return true;
        }
        return false;
    }
    if (stage != expected_stage) return false;
    m18_publish_guard_fault_observed = true;
    errno = EIO;
    return true;
}

static int m18_reject_command_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    (void)argv;
    (void)opts;
    if (result) memset(result, 0, sizeof(*result));
    errno = EIO;
    return -1;
}

/* Force the public reset-retirement prepare path to reject its non-default
 * runner after guard installation/adoption. This keeps the regression on the
 * production ordering seam and proves cleanup without any Git/SSH/config
 * mutation. */
static int m18_run_preprepare_guard_cleanup_contract(
    const m18_fixture_t *fixture, m18_prepare_guard_mode_t mode) {
    pid_t child;

    if (!fixture) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        command_runner_fn previous_runner;
        config_retirement_guard_t *installed = NULL;
        config_retirement_owner_t owner;
        error_context_t prepare_error;
        m18_bytes_t accounts_before = {0};
        m18_bytes_t git_before = {0};
        m18_bytes_t ssh_before = {0};
        m18_bytes_t marker_before = {0};
        m18_bytes_t trace = {0};
        char trusted_path[2U * MAX_PATH_LEN];
        int prepare_errno;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_TEST_GIT_TRACE",
                   fixture->git_trace_path, 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            m18_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
            m18_read_bytes(fixture->git_path, &git_before) != 0 ||
            m18_read_bytes(fixture->ssh_config, &ssh_before) != 0) {
            _exit(101);
        }
        if (mode == M18_PREPARE_GUARD_ADOPTED) {
            memset(&owner, 0, sizeof(owner));
            owner.account_id = ctx.accounts[0].id;
            if (safe_strncpy(owner.account_incarnation,
                             ctx.accounts[0].incarnation,
                             sizeof(owner.account_incarnation)) != 0 ||
                config_retirement_guard_install_or_adopt(
                    fixture->accounts_path, CONFIG_RETIREMENT_RESET,
                    &owner, 1U, &installed) != 0 ||
                !config_retirement_guard_was_created(installed)) {
                _exit(102);
            }
            config_retirement_guard_abandon(&installed);
            if (installed ||
                m18_read_bytes(fixture->guard_path,
                               &marker_before) != 0) {
                _exit(103);
            }
        }
        if (accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 || accounts_transaction_rollback_begin(
                              &ctx, ACCOUNTS_TRANSACTION_RESET,
                              token) != 0) {
            _exit(104);
        }
        m18_clear_after_stage_write_fault =
            mode == M18_PREPARE_GUARD_CLEAR_UNCERTAIN;
        m18_clear_after_stage_write_observed = false;
        if (m18_clear_after_stage_write_fault) {
            (void)gitswitch_test_set_retirement_guard_clear_hook(
                m18_retirement_clear_fault);
        }
        previous_runner = run_set_runner(m18_reject_command_runner);
        errno = 0;
        if (accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != -1) {
            _exit(105);
        }
        prepare_error = *get_last_error();
        prepare_errno = errno;
        (void)run_set_runner(previous_runner);
        (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
        m18_clear_after_stage_write_fault = false;

        if (prepare_errno != EINVAL ||
            prepare_error.code != ERR_INVALID_ARGS ||
            strcmp(prepare_error.message,
                   "Invalid outer Git retirement transaction request") != 0 ||
            !m18_file_equals(fixture->accounts_path, &accounts_before) ||
            !m18_file_equals(fixture->git_path, &git_before) ||
            !m18_file_equals(fixture->ssh_config, &ssh_before) ||
            m18_read_bytes(fixture->git_trace_path, &trace) != 0 ||
            trace.length != 0U) {
            _exit(106);
        }
        if (mode == M18_PREPARE_GUARD_FRESH) {
            if (!m18_guard_is_unblocked_and_bounded(fixture)) _exit(107);
        } else if (mode == M18_PREPARE_GUARD_ADOPTED) {
            if (!m18_file_equals(fixture->guard_path, &marker_before) ||
                !m18_guard_is_private_and_blocking(fixture, "reset") ||
                !m18_completion_absent(fixture)) {
                _exit(108);
            }
        } else if (!m18_clear_after_stage_write_observed ||
                   !m18_guard_is_private_and_blocking(fixture, "reset") ||
                   strstr(prepare_error.details,
                          "retirement preparation guard clear") == NULL) {
            _exit(109);
        }
        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(110);
        }
        m18_bytes_clear(&accounts_before);
        m18_bytes_clear(&git_before);
        m18_bytes_clear(&ssh_before);
        m18_bytes_clear(&marker_before);
        m18_bytes_clear(&trace);
        _exit(0);
    }
    return m18_wait_status(child);
}

/* Exercise failures that inner Git preparation deliberately defers until
 * publish. The two hook seams distinguish a proven pre-backend failure from
 * a failure after a mutation-capable publication backend is entered. */
static int m18_run_failed_publish_guard_contract(
    const m18_fixture_t *fixture, m18_publish_guard_mode_t mode) {
    pid_t child;

    if (!fixture) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        config_retirement_guard_t *installed = NULL;
        config_retirement_owner_t owner;
        error_context_t publish_error;
        m18_bytes_t accounts_before = {0};
        m18_bytes_t git_before = {0};
        m18_bytes_t ssh_before = {0};
        m18_bytes_t marker_before = {0};
        char trusted_path[2U * MAX_PATH_LEN];
        char lock_path[MAX_PATH_LEN];
        bool cleanup_mode =
            mode == M18_PUBLISH_GUARD_CLEANUP_UNCERTAIN_FRESH;
        bool git_matches;
        bool lock_absent;
        size_t cleared = 99U;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                          fixture->git_path) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_TEST_GIT_TRACE",
                   fixture->git_trace_path, 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            m18_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
            m18_read_bytes(fixture->git_path, &git_before) != 0 ||
            m18_read_bytes(fixture->ssh_config, &ssh_before) != 0) {
            _exit(111);
        }
        if (mode == M18_PUBLISH_GUARD_NO_MUTATION_ADOPTED) {
            memset(&owner, 0, sizeof(owner));
            owner.account_id = ctx.accounts[0].id;
            if (safe_strncpy(owner.account_incarnation,
                             ctx.accounts[0].incarnation,
                             sizeof(owner.account_incarnation)) != 0 ||
                config_retirement_guard_install_or_adopt(
                    fixture->accounts_path, CONFIG_RETIREMENT_RESET,
                    &owner, 1U, &installed) != 0 ||
                !config_retirement_guard_was_created(installed)) {
                _exit(112);
            }
            config_retirement_guard_abandon(&installed);
            if (installed ||
                m18_read_bytes(fixture->guard_path,
                               &marker_before) != 0) {
                _exit(113);
            }
        }
        if (cleanup_mode && unlink(fixture->git_path) != 0) {
            _exit(114);
        }
        if (accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 ||
            accounts_transaction_rollback_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(114);
        }

        m18_publish_guard_mode = mode;
        m18_publish_guard_fixture = fixture;
        m18_publish_guard_fault_observed = false;
        m18_publish_guard_cleanup_fault_observed = false;
        (void)git_ops_test_set_retirement_hook(
            m18_publish_guard_fault);
        if (accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != 0 ||
            !m18_guard_is_private_and_blocking(fixture, "reset")) {
            _exit(115);
        }
        errno = 0;
        if (accounts_reset_retirement_publish(
                &ctx, token, &cleared) != -1) {
            _exit(116);
        }
        publish_error = *get_last_error();
        (void)git_ops_test_set_retirement_hook(NULL);
        m18_publish_guard_fixture = NULL;

        errno = 0;
        git_matches = cleanup_mode
            ? access(fixture->git_path, F_OK) != 0 && errno == ENOENT
            : m18_file_equals(fixture->git_path, &git_before);
        errno = 0;
        lock_absent = access(lock_path, F_OK) != 0 && errno == ENOENT;
        if (!m18_publish_guard_fault_observed || cleared != 0U ||
            publish_error.code != ERR_GIT_CONFIG_FAILED ||
            strstr(publish_error.details,
                   "Git retirement batch cleared 0 key(s)") == NULL ||
            !m18_file_equals(fixture->accounts_path, &accounts_before) ||
            !git_matches ||
            !m18_file_equals(fixture->ssh_config, &ssh_before) ||
            !lock_absent) {
            _exit(117);
        }
        if (mode == M18_PUBLISH_GUARD_NO_MUTATION_FRESH) {
            if (!m18_guard_is_unblocked_and_bounded(fixture)) _exit(118);
        } else if (mode ==
                   M18_PUBLISH_GUARD_MUTATION_CAPABLE_FRESH) {
            if (!m18_guard_is_private_and_blocking(fixture, "reset") ||
                !m18_completion_absent(fixture)) {
                _exit(119);
            }
        } else if (cleanup_mode) {
            if (!m18_publish_guard_cleanup_fault_observed ||
                strstr(publish_error.details, "cleanup") == NULL ||
                !m18_guard_is_private_and_blocking(fixture, "reset") ||
                !m18_completion_absent(fixture)) {
                _exit(122);
            }
        } else if (!m18_file_equals(
                       fixture->guard_path, &marker_before) ||
                   !m18_guard_is_private_and_blocking(
                       fixture, "reset") ||
                   !m18_completion_absent(fixture)) {
            _exit(120);
        }
        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(121);
        }
        m18_bytes_clear(&accounts_before);
        m18_bytes_clear(&git_before);
        m18_bytes_clear(&ssh_before);
        m18_bytes_clear(&marker_before);
        _exit(0);
    }
    return m18_wait_status(child);
}

/* POSIX record locks are process-owned and are not inherited across fork().
 * Probe from a separate process so the transaction owner cannot accidentally
 * reacquire its own lock and turn this assertion into a false positive. */
static bool m18_canonical_lock_is_held_by_parent(const char *lock_path) {
    pid_t probe;
    int status;

    if (!lock_path) return false;
    probe = fork();
    if (probe < 0) return false;
    if (probe == 0) {
        struct flock claim;
        int fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);

        if (fd < 0) _exit(2);
        memset(&claim, 0, sizeof(claim));
        claim.l_type = F_WRLCK;
        claim.l_whence = SEEK_SET;
        if (fcntl(fd, F_SETLK, &claim) == -1 &&
            (errno == EACCES || errno == EAGAIN)) {
            _exit(0);
        }
        if (claim.l_type == F_WRLCK) {
            claim.l_type = F_UNLCK;
            (void)fcntl(fd, F_SETLK, &claim);
        }
        _exit(1);
    }
    status = m18_wait_status(probe);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Fork exactly after Git retirement publication and before the outer save is
 * classified PREINSTALL_FAILED. The child has inherited pointer/token values,
 * but it does not own the process-scoped transaction or canonical Git lock.
 * Distinct exit codes keep every mutation/release assertion causal. */
static int m18_run_forked_finalization_contract(
    const m18_fixture_t *fixture) {
    pid_t owner;

    if (!fixture) return -1;
    owner = fork();
    if (owner < 0) return -1;
    if (owner == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        m18_bytes_t git_before = {0};
        m18_bytes_t state_before = {0};
        m18_bytes_t accounts_before = {0};
        m18_bytes_t published_git = {0};
        m18_bytes_t published_state = {0};
        m18_bytes_t published_guard = {0};
        struct stat published_lock_stat;
        struct stat after_lock_stat;
        char trusted_path[2U * MAX_PATH_LEN];
        char lock_path[MAX_PATH_LEN];
        size_t cleared = 99U;
        pid_t claimant;
        int claimant_status;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                          fixture->git_path) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            m18_read_bytes(fixture->git_path, &git_before) != 0 ||
            m18_read_bytes(fixture->state_path, &state_before) != 0 ||
            m18_read_bytes(fixture->accounts_path, &accounts_before) != 0) {
            _exit(101);
        }
        if (config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 ||
            accounts_transaction_rollback_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != 0) {
            _exit(102);
        }
        if (accounts_reset_retirement_publish(
                &ctx, token, &cleared) != 0 ||
            cleared != 1U || m18_git_has_command(fixture) ||
            !m18_guard_is_private_and_blocking(fixture, "reset") ||
            !m18_completion_absent(fixture) ||
            m18_read_bytes(fixture->git_path, &published_git) != 0 ||
            m18_read_bytes(fixture->state_path, &published_state) != 0 ||
            m18_read_bytes(fixture->guard_path, &published_guard) != 0 ||
            lstat(lock_path, &published_lock_stat) != 0 ||
            published_lock_stat.st_size != 0) {
            _exit(103);
        }

        claimant = fork();
        if (claimant < 0) _exit(104);
        if (claimant == 0) {
            accounts_transaction_token_t child_token = 0;
            int rc = accounts_reset_retirement_finalize(
                &ctx, token,
                ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED);

            if (rc != -1 || errno != EINVAL ||
                get_last_error()->code != ERR_INVALID_ARGS) {
                _exit(1);
            }
            /* The inherited finalizer is rejected once, but the epoch reset
             * must also unpoison the copied context. A subsequent independent
             * child transaction receives a new monotonic token and completes
             * without consuming any parent-owned namespace state. */
            if (!accounts_transaction_context_release_safe(&ctx) ||
                accounts_transaction_begin(
                    &ctx, ACCOUNTS_TRANSACTION_RESET,
                    &child_token) != 0 ||
                child_token <= token ||
                accounts_transaction_finish(
                    &ctx, ACCOUNTS_TRANSACTION_RESET,
                    child_token) != 0 ||
                !accounts_transaction_context_release_safe(&ctx)) {
                _exit(2);
            }
            _exit(0);
        }
        claimant_status = m18_wait_status(claimant);
        if (!WIFEXITED(claimant_status) ||
            WEXITSTATUS(claimant_status) != 0) {
            _exit(105);
        }

        /* The rejected child must not have reached any Git namespace,
         * retirement-ledger, guard, completion, transition, unlink, or lock
         * release operation. */
        if (!m18_file_equals(fixture->git_path, &published_git))
            _exit(106);
        if (!m18_file_equals(fixture->state_path, &published_state))
            _exit(107);
        if (!m18_file_equals(fixture->accounts_path, &accounts_before))
            _exit(108);
        if (!m18_file_equals(fixture->guard_path, &published_guard))
            _exit(109);
        if (lstat(lock_path, &after_lock_stat) != 0 ||
            after_lock_stat.st_size != 0 ||
            !m18_same_without_ctime(
                &published_lock_stat, &after_lock_stat) ||
            !m18_same_ctime(&published_lock_stat, &after_lock_stat)) {
            _exit(110);
        }
        if (!m18_completion_absent(fixture)) _exit(111);
        if (!m18_guard_is_private_and_blocking(fixture, "reset"))
            _exit(112);
        errno = 0;
        if (access(fixture->transition_path, F_OK) == 0 ||
            errno != ENOENT) {
            _exit(113);
        }
        if (!m18_canonical_lock_is_held_by_parent(lock_path)) {
            _exit(114);
        }

        if (accounts_reset_retirement_finalize(
                &ctx, token,
                ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED) != 0) {
            _exit(115);
        }
        if (!m18_file_equals(fixture->git_path, &git_before) ||
            !m18_file_equals(fixture->accounts_path, &accounts_before) ||
            !m18_ledger_matches_live_restored_git(fixture) ||
            !m18_guard_is_unblocked_and_bounded(fixture)) {
            _exit(116);
        }
        errno = 0;
        if (lstat(lock_path, &after_lock_stat) == 0 || errno != ENOENT) {
            _exit(117);
        }
        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(118);
        }
        m18_bytes_clear(&git_before);
        m18_bytes_clear(&state_before);
        m18_bytes_clear(&accounts_before);
        m18_bytes_clear(&published_git);
        m18_bytes_clear(&published_state);
        m18_bytes_clear(&published_guard);
        _exit(0);
    }
    return m18_wait_status(owner);
}

static int m18_replace_retained_fds(
    const int *retained, size_t count, int *replacements) {
    int maximum = -1;

    if (!retained || !replacements || count == 0U) return -1;
    for (size_t i = 0U; i < count; i++) {
        if (retained[i] < 0) return -1;
        if (retained[i] > maximum) maximum = retained[i];
        errno = 0;
        if (fcntl(retained[i], F_GETFD) != -1 ||
            errno != EBADF) {
            return -1;
        }
    }
    for (size_t i = 0U; i < count; i++) {
        int source = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (source < 0) return -1;
#ifdef F_DUPFD_CLOEXEC
        replacements[i] =
            fcntl(source, F_DUPFD_CLOEXEC, maximum + 1);
#else
        replacements[i] = fcntl(source, F_DUPFD, maximum + 1);
        if (replacements[i] >= 0) {
            int flags = fcntl(replacements[i], F_GETFD);
            if (flags < 0 ||
                fcntl(replacements[i], F_SETFD,
                      flags | FD_CLOEXEC) != 0) {
                close(replacements[i]);
                replacements[i] = -1;
            }
        }
#endif
        close(source);
        if (replacements[i] <= maximum) {
            return -1;
        }
        maximum = replacements[i];
    }
    for (size_t i = 0U; i < count; i++) {
        if (dup2(replacements[i], retained[i]) != retained[i]) {
            return -1;
        }
    }
    return 0;
}

static bool m18_reused_fds_remain_open(
    const int *retained, const int *replacements, size_t count) {
    struct stat expected;
    struct stat observed;

    if (!retained || !replacements || count == 0U) return false;
    for (size_t i = 0U; i < count; i++) {
        if (fstat(replacements[i], &expected) != 0 ||
            fcntl(retained[i], F_GETFD) < 0 ||
            fstat(retained[i], &observed) != 0 ||
            expected.st_dev != observed.st_dev ||
            expected.st_ino != observed.st_ino) {
            return false;
        }
    }
    return true;
}

static void m18_close_reused_fds(
    const int *retained, const int *replacements, size_t count) {
    if (!retained || !replacements) return;
    for (size_t i = 0U; i < count; i++) {
        if (retained[i] >= 0) (void)close(retained[i]);
        if (replacements[i] >= 0) (void)close(replacements[i]);
    }
}

static int m18_run_foreign_git_capability_fd_aba(
    const m18_fixture_t *fixture) {
    pid_t owner;

    if (!fixture) return -1;
    owner = fork();
    if (owner < 0) return -1;
    if (owner == 0) {
        gitswitch_ctx_t ctx;
        const account_t *accounts[1];
        const publication_record_t *publications[1];
        publication_record_t recovery_record;
        git_retirement_transaction_t *transaction = NULL;
        git_retirement_recovery_t *recovery = NULL;
        char trusted_path[2U * MAX_PATH_LEN];
        struct stat live_git;
        size_t cleared = 0U;
        pid_t claimant;
        int claimant_status;
        int retained[12];
        size_t retained_count;

        memset(&ctx, 0, sizeof(ctx));
        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            config_init_readonly(&ctx) != 0 ||
            ctx.account_count != 1U) {
            _exit(121);
        }
        accounts[0] = &ctx.accounts[0];
        publications[0] = &fixture->record;

        /* Prepared transaction: foreign generic commit must consume only the
         * child heap copy and forget every possibly reused descriptor. */
        if (git_retirement_transaction_prepare(
                accounts, publications, 1U, &transaction) != 0 ||
            !transaction) {
            _exit(122);
        }
        retained_count =
            git_ops_test_retirement_transaction_descriptors(
                transaction, retained,
                sizeof(retained) / sizeof(retained[0]));
        if (retained_count == 0U ||
            retained_count >
                sizeof(retained) / sizeof(retained[0])) {
            _exit(122);
        }
        claimant = fork();
        if (claimant < 0) _exit(123);
        if (claimant == 0) {
            int replacements[12];

            memset(replacements, -1, sizeof(replacements));
            if (m18_replace_retained_fds(
                    retained, retained_count, replacements) != 0) {
                _exit(1);
            }
            errno = 0;
            if (git_retirement_transaction_commit(&transaction) != -1 ||
                transaction != NULL || errno != EINVAL ||
                !m18_reused_fds_remain_open(
                    retained, replacements, retained_count)) {
                _exit(2);
            }
            m18_close_reused_fds(
                retained, replacements, retained_count);
            _exit(0);
        }
        claimant_status = m18_wait_status(claimant);
        if (!WIFEXITED(claimant_status) ||
            WEXITSTATUS(claimant_status) != 0 ||
            git_ops_test_retirement_transaction_descriptors(
                transaction, NULL, 0U) == 0U ||
            git_retirement_transaction_commit(&transaction) != 0 ||
            transaction != NULL) {
            _exit(124);
        }

        /* Published terminal transaction: exercise the shared terminal
         * finish path used by rollback, commit, and recovery outcomes. */
        if (git_retirement_transaction_prepare(
                accounts, publications, 1U, &transaction) != 0 ||
            !transaction ||
            git_retirement_transaction_publish(
                transaction, &cleared) != 0 ||
            cleared != 1U ||
            git_retirement_transaction_prepare_terminal_commit(
                transaction) != 0) {
            _exit(125);
        }
        retained_count =
            git_ops_test_retirement_transaction_descriptors(
                transaction, retained,
                sizeof(retained) / sizeof(retained[0]));
        if (retained_count == 0U ||
            retained_count >
                sizeof(retained) / sizeof(retained[0])) {
            _exit(125);
        }
        claimant = fork();
        if (claimant < 0) _exit(126);
        if (claimant == 0) {
            int replacements[12];

            memset(replacements, -1, sizeof(replacements));
            if (m18_replace_retained_fds(
                    retained, retained_count, replacements) != 0) {
                _exit(3);
            }
            errno = 0;
            if (git_retirement_transaction_finish_terminal_commit(
                    &transaction) != -1 ||
                transaction != NULL || errno != EINVAL ||
                !m18_reused_fds_remain_open(
                    retained, replacements, retained_count)) {
                _exit(4);
            }
            m18_close_reused_fds(
                retained, replacements, retained_count);
            _exit(0);
        }
        claimant_status = m18_wait_status(claimant);
        if (!WIFEXITED(claimant_status) ||
            WEXITSTATUS(claimant_status) != 0 ||
            git_ops_test_retirement_transaction_descriptors(
                transaction, NULL, 0U) == 0U ||
            git_retirement_transaction_finish_terminal_commit(
                &transaction) != 0 ||
            transaction != NULL) {
            _exit(127);
        }

        /* A clean retiring record creates the recovery capability without
         * reviving mutation authority. Its foreign end path has the same ABA
         * obligation as a direct transaction. */
        recovery_record = fixture->record;
        recovery_record.state = PUBLICATION_STATE_RETIRING;
        if (lstat(fixture->git_path, &live_git) != 0) _exit(128);
        publication_identity_from_stat(
            &recovery_record.post_config, &live_git);
        publications[0] = &recovery_record;
        if (publication_record_validate(&recovery_record) != 0 ||
            git_retirement_recovery_begin(
                publications, 1U, &recovery) != 0 ||
            !recovery) {
            _exit(129);
        }
        retained_count =
            git_ops_test_retirement_recovery_descriptors(
                recovery, retained,
                sizeof(retained) / sizeof(retained[0]));
        if (retained_count == 0U ||
            retained_count >
                sizeof(retained) / sizeof(retained[0])) {
            _exit(129);
        }
        claimant = fork();
        if (claimant < 0) _exit(130);
        if (claimant == 0) {
            int replacements[12];

            memset(replacements, -1, sizeof(replacements));
            if (m18_replace_retained_fds(
                    retained, retained_count, replacements) != 0) {
                _exit(5);
            }
            errno = 0;
            if (git_retirement_recovery_end(&recovery) != -1 ||
                recovery != NULL || errno != EINVAL ||
                !m18_reused_fds_remain_open(
                    retained, replacements, retained_count)) {
                _exit(6);
            }
            m18_close_reused_fds(
                retained, replacements, retained_count);
            _exit(0);
        }
        claimant_status = m18_wait_status(claimant);
        if (!WIFEXITED(claimant_status) ||
            WEXITSTATUS(claimant_status) != 0 ||
            git_ops_test_retirement_recovery_descriptors(
                recovery, NULL, 0U) == 0U ||
            git_retirement_recovery_end(&recovery) != 0 ||
            recovery != NULL) {
            _exit(131);
        }
        _exit(0);
    }
    return m18_wait_status(owner);
}

/* Run the durable terminal commit in an isolated owner process.
 * The nested writer is triggered synchronously by the exact post-barrier,
 * pre-rename checkpoint, so a failure proves a lock-lifetime defect rather
 * than a scheduler-dependent race. */
static int m18_run_terminal_writer_contract(
    const m18_fixture_t *fixture, bool fail_after_barrier) {
    pid_t owner;

    if (!fixture) return -1;
    owner = fork();
    if (owner < 0) return -1;
    if (owner == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        m18_bytes_t git_before = {0};
        m18_bytes_t accounts_before = {0};
        char trusted_path[2U * MAX_PATH_LEN];
        char lock_path[MAX_PATH_LEN];
        struct stat lock_stat;
        size_t cleared = 99U;
        int finalize_result;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                          fixture->git_path) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            m18_read_bytes(fixture->git_path, &git_before) != 0 ||
            m18_read_bytes(fixture->accounts_path, &accounts_before) != 0) {
            _exit(101);
        }
        if (config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 ||
            accounts_transaction_rollback_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != 0 ||
            accounts_reset_retirement_publish(
                &ctx, token, &cleared) != 0 ||
            cleared != 1U || m18_git_has_command(fixture) ||
            !m18_guard_is_private_and_blocking(fixture, "reset")) {
            _exit(102);
        }

        m18_terminal_writer_fixture = fixture;
        m18_terminal_writer_path = fixture->git_path;
        m18_terminal_writer_expect_stage = true;
        m18_terminal_writer_checkpoint_observed = false;
        m18_terminal_writer_result = M18_TERMINAL_WRITER_NOT_RUN;
        m18_terminal_precommit_failure_requested =
            fail_after_barrier;
        m18_terminal_precommit_failure_observed = false;
        (void)gitswitch_test_set_retirement_guard_clear_hook(
            m18_terminal_writer_hook);
        finalize_result = accounts_reset_retirement_finalize(
            &ctx, token,
            ACCOUNTS_RETIREMENT_SAVE_DURABLE);
        (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
        m18_terminal_writer_fixture = NULL;
        m18_terminal_writer_path = NULL;
        m18_terminal_writer_expect_stage = false;
        m18_terminal_precommit_failure_requested = false;

        if (finalize_result != (fail_after_barrier ? -1 : 0)) _exit(103);
        if (!m18_terminal_writer_checkpoint_observed) _exit(104);
        if (m18_terminal_writer_result !=
            M18_TERMINAL_WRITER_BLOCKED) {
            _exit(105);
        }
        if (m18_terminal_precommit_failure_observed !=
            fail_after_barrier) {
            _exit(109);
        }
        if (fail_after_barrier) {
            if (m18_git_has_command(fixture) ||
                !m18_file_equals(
                    fixture->accounts_path, &accounts_before) ||
                !m18_guard_is_private_and_blocking(
                    fixture, "reset") ||
                m18_terminal_marker_checkpoint_status(
                    lock_path, fixture->git_path, true) !=
                    M18_TERMINAL_WRITER_BLOCKED) {
                _exit(110);
            }
            if (accounts_transaction_rollback_end(
                    &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
                accounts_transaction_finish(
                    &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
                _exit(111);
            }
            m18_bytes_clear(&git_before);
            m18_bytes_clear(&accounts_before);
            _exit(0);
        }
        if (m18_git_has_command(fixture) ||
            !m18_file_equals(fixture->accounts_path, &accounts_before) ||
            !m18_guard_is_unblocked_and_bounded(fixture)) {
            _exit(106);
        }
        errno = 0;
        if (lstat(lock_path, &lock_stat) == 0 ||
            errno != ENOENT) {
            _exit(107);
        }
        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(108);
        }
        m18_bytes_clear(&git_before);
        m18_bytes_clear(&accounts_before);
        _exit(0);
    }
    return m18_wait_status(owner);
}

static int m18_run_terminal_cleanup_contract(
    const m18_fixture_t *fixture, bool crash_before_unlink) {
    pid_t owner;

    if (!fixture) return -1;
    owner = fork();
    if (owner < 0) return -1;
    if (owner == 0) {
        gitswitch_ctx_t ctx;
        accounts_transaction_token_t token = 0;
        m18_bytes_t git_before = {0};
        m18_bytes_t accounts_before = {0};
        char trusted_path[2U * MAX_PATH_LEN];
        char lock_path[MAX_PATH_LEN];
        char foreign_path[MAX_PATH_LEN];
        size_t cleared = 99U;
        int finalize_result;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                          fixture->git_path) != 0 ||
            safe_snprintf(foreign_path, sizeof(foreign_path),
                          "%s/.foreign-terminal-entry",
                          fixture->home) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0 ||
            m18_read_bytes(fixture->git_path, &git_before) != 0 ||
            m18_read_bytes(fixture->accounts_path, &accounts_before) != 0 ||
            m18_write_text(
                foreign_path, "foreign-terminal-entry\n", 0600) != 0) {
            _exit(121);
        }
        if (config_init_readonly(&ctx) != 0 || ctx.account_count != 1U ||
            accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, &token) != 0 ||
            token == 0 ||
            accounts_transaction_rollback_begin(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_reset_retirement_prepare(
                &ctx, token, &ctx.accounts[0]) != 0 ||
            accounts_reset_retirement_publish(
                &ctx, token, &cleared) != 0 ||
            cleared != 1U || m18_git_has_command(fixture) ||
            !m18_guard_is_private_and_blocking(fixture, "reset")) {
            _exit(122);
        }

        m18_terminal_cleanup_fixture = fixture;
        m18_terminal_cleanup_observed = false;
        m18_terminal_cleanup_crash_requested = crash_before_unlink;
        m18_terminal_cleanup_failure_requested =
            !crash_before_unlink;
        (void)git_ops_test_set_retirement_hook(
            m18_retirement_witness_hook);
        finalize_result = accounts_reset_retirement_finalize(
            &ctx, token,
            ACCOUNTS_RETIREMENT_SAVE_DURABLE);
        (void)git_ops_test_set_retirement_hook(NULL);
        m18_terminal_cleanup_fixture = NULL;
        m18_terminal_cleanup_crash_requested = false;
        m18_terminal_cleanup_failure_requested = false;

        if (crash_before_unlink) _exit(123);
        if (finalize_result != 0) {
            _exit(124);
        }
        if (!m18_terminal_cleanup_observed) _exit(128);
        /* The diagnostic does not reopen the business transaction: the
         * durable retirement remains installed and its handle was consumed. */
        if (accounts_reset_retirement_finalize(
                &ctx, token,
                ACCOUNTS_RETIREMENT_SAVE_DURABLE) == 0) {
            _exit(125);
        }
        if (m18_git_has_command(fixture) ||
            !m18_file_equals(fixture->accounts_path, &accounts_before) ||
            !m18_guard_is_unblocked_and_bounded(fixture) ||
            m18_terminal_marker_checkpoint_status(
                lock_path, fixture->git_path, true) !=
                M18_TERMINAL_WRITER_BLOCKED ||
            access(foreign_path, F_OK) != 0) {
            _exit(126);
        }
        if (accounts_transaction_rollback_end(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0 ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET, token) != 0) {
            _exit(127);
        }
        m18_bytes_clear(&git_before);
        m18_bytes_clear(&accounts_before);
        _exit(0);
    }
    return m18_wait_status(owner);
}

static int m18_run_fresh_managed_write(
    const m18_fixture_t *fixture, const char *expected_foreign,
    m18_fresh_first_op_t first_op) {
    pid_t child;

    if (!fixture || !expected_foreign) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        char trusted_path[2U * MAX_PATH_LEN];
        char lock_path[MAX_PATH_LEN];
        char foreign_path[MAX_PATH_LEN];
        char observed_name[128];
        char observed_email[128];
        char listed[2048];
        m18_bytes_t foreign = {0};
        struct stat ignored;

        if (safe_snprintf(trusted_path, sizeof(trusted_path),
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
            safe_snprintf(lock_path, sizeof(lock_path), "%s.lock",
                          fixture->git_path) != 0 ||
            safe_snprintf(foreign_path, sizeof(foreign_path),
                          "%s/.foreign-terminal-entry",
                          fixture->home) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0) {
            _exit(131);
        }
        git_ops_test_reset_caches();
        if (first_op == M18_FRESH_FIRST_UNSET) {
            if (git_unset_config_value(
                    "fixture.marker", GIT_SCOPE_GLOBAL) != 0 ||
                git_list_config(
                    GIT_SCOPE_GLOBAL, listed, sizeof(listed)) != 0 ||
                strstr(listed, "fixture.marker=") != NULL) {
                _exit(132);
            }
        } else if (first_op == M18_FRESH_FIRST_SET) {
            if (git_set_config_value(
                    GIT_CONFIG_USER_NAME, "terminal-self-healed",
                    GIT_SCOPE_GLOBAL) != 0 ||
                git_get_config_value(
                    GIT_CONFIG_USER_NAME, observed_name,
                    sizeof(observed_name),
                    GIT_SCOPE_GLOBAL) != 0 ||
                strcmp(observed_name, "terminal-self-healed") != 0) {
                _exit(132);
            }
        } else {
            _exit(132);
        }
        errno = 0;
        if (lstat(lock_path, &ignored) == 0 || errno != ENOENT ||
            m18_read_bytes(foreign_path, &foreign) != 0 ||
            foreign.length != strlen(expected_foreign) ||
            memcmp(foreign.data, expected_foreign,
                   foreign.length) != 0) {
            _exit(133);
        }
        m18_bytes_clear(&foreign);
        /* Prove self-healing did not leave a poisoned acquisition state: a
         * distinct managed transaction must acquire and release the same
         * canonical lock normally. */
        if (git_set_config_value(
                GIT_CONFIG_USER_EMAIL, "terminal-second@example.test",
                GIT_SCOPE_GLOBAL) != 0 ||
            git_get_config_value(
                GIT_CONFIG_USER_EMAIL, observed_email,
                sizeof(observed_email), GIT_SCOPE_GLOBAL) != 0 ||
            strcmp(observed_email,
                   "terminal-second@example.test") != 0) {
            _exit(134);
        }
        errno = 0;
        if (lstat(lock_path, &ignored) == 0 || errno != ENOENT ||
            m18_read_bytes(foreign_path, &foreign) != 0 ||
            foreign.length != strlen(expected_foreign) ||
            memcmp(foreign.data, expected_foreign,
                   foreign.length) != 0) {
            _exit(135);
        }
        m18_bytes_clear(&foreign);
        _exit(0);
    }
    return m18_wait_status(child);
}

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
                          "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
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
    publication_identity_t live_identity;
    struct stat live_stat;
    int load_errno = 0;
    int load_result;
    int verify_errno = 0;
    int verify_result = -1;
    bool record_matches = false;
    bool matches = false;

    publication_ledger_init(&ledger);
    if (!fixture) {
        fprintf(stderr,
                "  M18 restored-ledger diagnostic: fixture is null\n");
        goto cleanup;
    }
    errno = 0;
    load_result =
        config_load_publication_ledger(fixture->accounts_path, &ledger);
    load_errno = errno;
    if (load_result != 0) {
        fprintf(stderr,
                "  M18 restored-ledger diagnostic: load=%d errno=%d "
                "count=%zu\n",
                load_result, load_errno, ledger.count);
        goto cleanup;
    }
    lookup = publication_ledger_find(
        &ledger, UINT32_C(1), M18_INCARNATION,
        PUBLICATION_SCOPE_GLOBAL, fixture->git_path, "", &record);
    if (record) {
        record_matches =
            m18_record_equal_except_post_config(record, &fixture->record);
    }
    if (lookup == PUBLICATION_LOOKUP_FOUND && record &&
        record->state == PUBLICATION_STATE_PUBLISHED && record_matches) {
        generations[0] = record;
        errno = 0;
        verify_result = publication_record_verify_live_destination(
            record, generations, 1U, &live_generation);
        verify_errno = errno;
        matches = verify_result == 0 &&
                  live_generation == record;
    }
    if (!matches) {
        fprintf(stderr,
                "  M18 restored-ledger diagnostic: count=%zu lookup=%d "
                "record=%p state=%d record-match=%d verify=%d "
                "verify-errno=%d live=%p expected=%p\n",
                ledger.count, (int)lookup, (const void *)record,
                record ? (int)record->state : -1, record_matches,
                verify_result, verify_errno,
                (const void *)live_generation, (const void *)record);
        errno = 0;
        if (!record) {
            fprintf(stderr,
                    "  M18 restored-ledger live lstat: skipped "
                    "(record absent)\n");
        } else if (lstat(fixture->git_path, &live_stat) == 0) {
            publication_identity_from_stat(&live_identity, &live_stat);
            fprintf(stderr,
                    "  M18 restored-ledger post-config: "
                    "recorded={dev=%llu ino=%llu mode=%llo uid=%llu "
                    "gid=%llu nlink=%llu size=%llu "
                    "mtime=%lld.%09u ctime=%lld.%09u} "
                    "live={dev=%llu ino=%llu mode=%llo uid=%llu "
                    "gid=%llu nlink=%llu size=%llu "
                    "mtime=%lld.%09u ctime=%lld.%09u}\n",
                    (unsigned long long)record->post_config.device,
                    (unsigned long long)record->post_config.inode,
                    (unsigned long long)record->post_config.mode,
                    (unsigned long long)record->post_config.uid,
                    (unsigned long long)record->post_config.gid,
                    (unsigned long long)record->post_config.link_count,
                    (unsigned long long)record->post_config.size,
                    (long long)record->post_config.mtime_seconds,
                    record->post_config.mtime_nanoseconds,
                    (long long)record->post_config.ctime_seconds,
                    record->post_config.ctime_nanoseconds,
                    (unsigned long long)live_identity.device,
                    (unsigned long long)live_identity.inode,
                    (unsigned long long)live_identity.mode,
                    (unsigned long long)live_identity.uid,
                    (unsigned long long)live_identity.gid,
                    (unsigned long long)live_identity.link_count,
                    (unsigned long long)live_identity.size,
                    (long long)live_identity.mtime_seconds,
                    live_identity.mtime_nanoseconds,
                    (long long)live_identity.ctime_seconds,
                    live_identity.ctime_nanoseconds);
        } else {
            fprintf(stderr,
                    "  M18 restored-ledger live lstat: errno=%d\n",
                    errno);
        }
    }

cleanup:
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

static bool m18_transition_is_private_and_blocking(
    const m18_fixture_t *fixture, const char *operation) {
    struct stat st;
    m18_bytes_t transition = {0};
    char operation_line[64];
    bool blocked = false;
    bool valid = false;

    if (!fixture || !operation ||
        safe_snprintf(operation_line, sizeof(operation_line),
                      "operation=%s\n", operation) != 0 ||
        lstat(fixture->transition_path, &st) != 0 ||
        !S_ISREG(st.st_mode) || (st.st_mode & 0777U) != 0600U ||
        st.st_uid != geteuid() || st.st_nlink != 1 ||
        config_retirement_guard_probe(fixture->accounts_path,
                                      &blocked) != 0 ||
        !blocked ||
        m18_read_bytes(fixture->transition_path, &transition) != 0) {
        goto cleanup;
    }
    valid =
        (strstr((const char *)transition.data,
                "gitswitch-retirement-incomplete-v1\n") != NULL ||
         strstr((const char *)transition.data,
                "gitswitch-retirement-incomplete-v2\n") != NULL) &&
        strstr((const char *)transition.data, operation_line) != NULL &&
        strstr((const char *)transition.data, "owners=2\n") != NULL &&
        strstr((const char *)transition.data,
               "owner=1:" M18_INCARNATION "\n") != NULL &&
        strstr((const char *)transition.data,
               "owner=2:" M18_SECOND_INCARNATION "\n") != NULL;

cleanup:
    m18_bytes_clear(&transition);
    return valid;
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

static bool m18_mixed_rollback_ledger_is_exact(
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
            !m18_record_equal_except_post_config(observed[i], expected[i])) {
            goto cleanup;
        }
    }
    for (size_t i = 0U; i < 2U; i++) {
        if (publication_record_verify_live_destination(
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
    errno = 0;
    matches =
        publication_identity_equal(&observed[0]->post_config,
                                   &observed[1]->post_config) &&
        memcmp(observed[2], expected[2], sizeof(*observed[2])) == 0 &&
        access(fixture->no_op_git_path, F_OK) != 0 &&
        errno == ENOENT;

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
    int close_errno = 0;
    int close_result;
    int probe_errno = 0;
    int probe_result;
    int scan_errno;

    if (!fixture) {
        fprintf(stderr,
                "  M18 guard-bound diagnostic: fixture is null\n");
        return false;
    }
    errno = 0;
    probe_result = config_retirement_guard_probe(
        fixture->accounts_path, &blocked);
    probe_errno = errno;
    if (probe_result != 0 || blocked) {
        fprintf(stderr,
                "  M18 guard-bound diagnostic: probe=%d errno=%d "
                "blocked=%d\n",
                probe_result, probe_errno, blocked);
        return false;
    }
    errno = 0;
    directory = opendir(fixture->config_dir);
    if (!directory) {
        fprintf(stderr,
                "  M18 guard-bound diagnostic: opendir errno=%d path=%s\n",
                errno, fixture->config_dir);
        return false;
    }
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
            fprintf(stderr,
                    "  M18 guard-bound diagnostic: residue=%s\n",
                    entry->d_name);
            break;
        }
    }
    scan_errno = errno;
    scan_complete = entry != NULL || scan_errno == 0;
    errno = 0;
    close_result = closedir(directory);
    close_errno = errno;
    if (!scan_complete) {
        fprintf(stderr,
                "  M18 guard-bound diagnostic: readdir errno=%d\n",
                scan_errno);
    }
    if (close_result != 0) {
        fprintf(stderr,
                "  M18 guard-bound diagnostic: closedir=%d errno=%d\n",
                close_result, close_errno);
        return false;
    }
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
    m18_prepare_ctime_drift_requested = true;
    m18_prepare_ctime_drift_fixture = &fixture;
    m18_recovery_end_probe_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m18_prepare_ctime_drift_requested = false;
    m18_prepare_ctime_drift_error = 0;
    m18_prepare_ctime_drift_fixture = NULL;
    m18_recovery_end_probe_requested = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_prepare_ctime_drift_observed);
    CHECK(m18_recovery_end_probe_observed);
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

TEST(recovery_terminal_verify_follows_final_prepared_guard_reads) {
    m18_fixture_t fixture;
    m18_bytes_t marker = {0};
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
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);

    m18_final_prepared_read_order_requested = true;
    m18_recovery_end_probe_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m18_recovery_end_probe_requested = false;
    m18_final_prepared_read_order_requested = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    }
    CHECK(m18_recovery_end_probe_observed);
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&marker);
    m18_fixture_cleanup(&fixture);
}

TEST(recovery_post_guard_cleanup_failure_is_success_and_self_heals) {
    static const char foreign[] = "foreign-recovery-terminal-entry\n";
    m18_fixture_t fixture;
    m18_bytes_t accounts_after_failure = {0};
    m18_bytes_t git_after_failure = {0};
    m18_bytes_t marker = {0};
    m18_bytes_t output = {0};
    char lock_path[MAX_PATH_LEN];
    char foreign_path[MAX_PATH_LEN];
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    CHECK_EQ_INT(safe_snprintf(
                     foreign_path, sizeof(foreign_path),
                     "%s/.foreign-terminal-entry",
                     fixture.home), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_ONCE,
        CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.accounts_path, &accounts_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.git_path, &git_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_write_text(
                     foreign_path, foreign, 0600), 0);

    m18_terminal_cleanup_fixture = &fixture;
    m18_terminal_cleanup_failure_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m18_terminal_cleanup_failure_requested = false;
    m18_terminal_cleanup_fixture = NULL;

    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK(m18_file_equals(
        fixture.accounts_path, &accounts_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK(m18_accounts_omit_work(&fixture));
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_ledger_has_exact_retiring_work(&fixture));
    CHECK(m18_guard_has_exact_completion_pair(&fixture, &marker));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_terminal_marker_checkpoint_status(
                     lock_path, fixture.git_path, true),
                 M18_TERMINAL_WRITER_BLOCKED);
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output, "Completed interrupted removal for account ID 1."));

    status = m18_run_fresh_managed_write(
        &fixture, foreign, M18_FRESH_FIRST_SET);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);

    m18_bytes_clear(&accounts_after_failure);
    m18_bytes_clear(&git_after_failure);
    m18_bytes_clear(&marker);
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
                     "%s/repository-away", fixture.data_dir), 0);
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

TEST(restored_witness_flushes_post_read_ctime_before_reset_ledger_seal) {
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

    /* Reproduce the hosted reset failure at its causal seam: the first exact
     * restored-byte read materializes a ctime-only successor that must be
     * flushed and re-proved before its identity reaches the durable ledger. */
    status = m18_run_cli_with_post_read_ctime_drifts(
        &fixture, M18_COMMAND_RESET, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, 1U, &observed);
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
    CHECK(!m18_output_contains(
        &output, "destination changed after abort"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(restored_witness_flushes_final_read_ctime_before_reset_ledger_seal) {
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

    /* Exercise the final byte-read seam that precedes descriptor close.
     * Its ctime successor must be flushed and re-proved before the ledger
     * seal; later terminal marker directory syncs must not advance it. */
    status = m18_run_cli_with_final_read_ctime_drifts(
        &fixture, M18_COMMAND_RESET, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, 1U, &observed);
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
    CHECK(!m18_output_contains(
        &output, "destination changed after abort"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&output);
    m18_fixture_cleanup(&fixture);
}

TEST(prepared_guard_flush_precedes_restored_ledger_seal) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    bool fault_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    /* The first stage write installs the durable blocker. On the rollback
     * completion-stage write, force the restored Git inode to take a
     * ctime-only successor before that stage and its directory are flushed.
     * The later ledger loop must seal this generation; clearing first and
     * syncing afterward would leave an unblocked stale publication record. */
    status = m18_run_cli_with_prepared_stage_ctime_drift(
        &fixture, CONFIG_IO_STATE_BEFORE_DIR_SYNC, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(fault_observed);
    CHECK(m18_prepare_ctime_drift_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_ledger_matches_live_restored_git(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(rollback_prepublish_ctime_drift_reseals_then_clears) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    bool fault_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    /* Drift once after the completion-stage write and once at the first
     * prepublication checkpoint. The terminal read-only proof must surface
     * that second exact successor; the no-drift retry reseals it before the
     * guard is cleared. */
    status = m18_run_cli_with_prepublish_ctime_drifts(
        &fixture, 2U, 3U, 2U, 0U, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_ledger_matches_live_restored_git(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(rollback_prepublish_same_size_rewrite_is_rejected_exactly) {
    static const char needle[] = "marker = before";
    static const char replacement[] = "marker = xefore";
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t git_after = {0};
    struct stat identity_before;
    struct stat identity_after;
    unsigned char *match;
    bool fault_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);
    CHECK_EQ_INT(lstat(fixture.git_path, &identity_before), 0);
    match = (unsigned char *)strstr(
        (const char *)git_before.data, needle);
    CHECK(match != NULL);
    if (match) {
        memcpy(match, replacement, sizeof(replacement) - 1U);
    }

    /* Preserve every ledger-visible field, including size and mtime, while
     * changing the retained bytes at the final publication checkpoint. Exact
     * descriptor proof must reject the replacement and retain both blockers. */
    status = m18_run_cli_with_prepublish_byte_rewrite(
        &fixture, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_after), 0);
    CHECK_EQ_INT(lstat(fixture.git_path, &identity_after), 0);
    CHECK_EQ_INT((int)git_after.length, (int)git_before.length);
    CHECK(git_after.length == git_before.length &&
          memcmp(git_after.data, git_before.data,
                 git_after.length) == 0);
    CHECK(m18_same_without_ctime(
        &identity_before, &identity_after));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(access(fixture.transition_path, F_OK), 0);
    CHECK(m18_completion_absent(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&git_before);
    m18_bytes_clear(&git_after);
    m18_fixture_cleanup(&fixture);
}

TEST(rollback_repeated_prepublish_ctime_drift_is_bounded_and_blocking) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t git_before = {0};
    m18_bytes_t output = {0};
    bool fault_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path, &git_before), 0);

    /* The first drift occurs before terminal preparation. Each later
     * prepublication observation surfaces a new exact successor and consumes
     * one bounded ledger-reseal attempt. Continuous drift must exhaust that
     * budget and leave both durable blockers installed. */
    status = m18_run_cli_with_prepublish_ctime_drifts(
        &fixture, 4U, 4U, 4U, 0U, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &git_before));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "remove"));
    CHECK_EQ_INT(access(fixture.transition_path, F_OK), 0);
    CHECK(m18_completion_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.output_path, &output), 0);
    CHECK(m18_output_contains(
        &output,
        "Restored Git generation did not stabilize across terminal "
        "publication-ledger reconciliation"));

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
    m24_alias_commit_probe_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_commit_probe_requested = false;
    m24_alias_postrename_failure = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(m24_alias_fault_observed);
    CHECK(m24_alias_commit_observed);
    CHECK(m24_alias_is_absent(&fixture));
    CHECK_EQ_INT(m18_read_bytes(fixture.guard_path, &marker), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.ssh_config, &ssh_after_failure), 0);
    CHECK_EQ_INT(m18_read_bytes(
                     fixture.git_path, &git_after_failure), 0);
    CHECK_EQ_INT(lstat(fixture.ssh_config, &ssh_before_recovery), 0);
    CHECK_EQ_INT(m18_write_file(
                     fixture.git_trace_path, "", 0U, 0600), 0);

    m24_alias_commit_probe_requested = true;
    status = m18_run_cli(
        &fixture, M18_COMMAND_REMOVE_NUMERIC, M18_FAULT_NONE,
        CONFIG_IO_DEFAULT_AFTER_TEMP, NULL);
    m24_alias_commit_probe_requested = false;
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_SUCCESS);
    CHECK(m18_file_equals(fixture.ssh_config, &ssh_after_failure));
    CHECK(m18_file_equals(fixture.git_path, &git_after_failure));
    CHECK_EQ_INT(lstat(fixture.ssh_config, &ssh_after_recovery), 0);
    CHECK(m18_same_without_ctime(
        &ssh_before_recovery, &ssh_after_recovery));
    /* FreeBSD/UFS may materialize delayed ctime during recovery fsync.
     * The commit hook directly proves recovery did not rewrite the config. */
    CHECK(!m24_alias_commit_observed);
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
                     "%s/retargeted-home", fixture.data_dir), 0);
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

static int m18_parent_runtime_begin(
    const m18_fixture_t *fixture, gitswitch_ctx_t *ctx) {
    char trusted_path[2U * MAX_PATH_LEN];

    if (!fixture || !ctx) return -1;
    if (!m18_parent_environment_saved) {
        for (size_t i = 0U;
             i < sizeof(m18_parent_environment) /
                     sizeof(m18_parent_environment[0]);
             i++) {
            const char *value = getenv(m18_parent_environment[i].name);

            m18_parent_environment[i].present = value != NULL;
            if (value) {
                m18_parent_environment[i].value = strdup(value);
                if (!m18_parent_environment[i].value) return -1;
            }
        }
        m18_parent_environment_saved = true;
    }
    if (
        safe_snprintf(trusted_path, sizeof(trusted_path),
                      "%s:/usr/bin:/bin", fixture->bin_dir) != 0 ||
        setenv("PATH", trusted_path, 1) != 0 ||
        setenv("HOME", fixture->home, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", fixture->git_path, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        setenv("GITSWITCH_TEST_GIT_TRACE",
               fixture->git_trace_path, 1) != 0 ||
        unsetenv("GIT_CONFIG_COUNT") != 0) {
        return -1;
    }
    git_ops_test_reset_caches();
    memset(ctx, 0, sizeof(*ctx));
    return config_init_readonly(ctx);
}

static void m18_parent_runtime_end(void) {
    if (!m18_parent_environment_saved) return;
    for (size_t i = 0U;
         i < sizeof(m18_parent_environment) /
                 sizeof(m18_parent_environment[0]);
         i++) {
        if (m18_parent_environment[i].present) {
            (void)setenv(m18_parent_environment[i].name,
                         m18_parent_environment[i].value, 1);
        } else {
            (void)unsetenv(m18_parent_environment[i].name);
        }
        free(m18_parent_environment[i].value);
        m18_parent_environment[i].value = NULL;
        m18_parent_environment[i].present = false;
    }
    m18_parent_environment_saved = false;
    git_ops_test_reset_caches();
}

static const account_t *m18_find_account(
    const gitswitch_ctx_t *ctx, uint32_t account_id) {
    if (!ctx) return NULL;
    for (size_t i = 0U; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account_id) {
            return &ctx->accounts[i];
        }
    }
    return NULL;
}

static int m18_prepare_mixed_transaction(
    m18_fixture_t *fixture, gitswitch_ctx_t *ctx,
    git_retirement_transaction_t **transaction) {
    const account_t *work;
    const account_t *personal;
    const account_t *accounts[3];
    const publication_record_t *publications[3];

    if (!fixture || !ctx || !transaction ||
        m18_parent_runtime_begin(fixture, ctx) != 0) {
        return -1;
    }
    work = m18_find_account(ctx, UINT32_C(1));
    personal = m18_find_account(ctx, UINT32_C(2));
    if (!work || !personal) {
        errno = ESTALE;
        return -1;
    }
    accounts[0] = work;
    accounts[1] = work;
    accounts[2] = personal;
    publications[0] = &fixture->record;
    publications[1] = &fixture->shared_record;
    publications[2] = &fixture->no_op_record;
    return git_retirement_transaction_prepare(
        accounts, publications, 3U, transaction);
}

static int m18_prepare_single_terminal_rollback_marker(
    m18_fixture_t *fixture,
    git_retirement_transaction_t **transaction) {
    gitswitch_ctx_t ctx;
    const account_t *account;
    const account_t *accounts[1];
    const publication_record_t *publications[1];
    config_retirement_destination_t destination;
    size_t cleared = 0U;

    if (!fixture || !transaction ||
        m18_parent_runtime_begin(fixture, &ctx) != 0) {
        return -1;
    }
    account = m18_find_account(&ctx, UINT32_C(1));
    if (!account) {
        errno = ESTALE;
        return -1;
    }
    accounts[0] = account;
    publications[0] = &fixture->record;
    memset(&destination, 0, sizeof(destination));
    if (git_retirement_transaction_prepare(
            accounts, publications, 1U, transaction) != 0 ||
        git_retirement_transaction_publish(
            *transaction, &cleared) != 0 ||
        cleared == 0U ||
        git_retirement_transaction_abort(*transaction) != 0 ||
        git_retirement_transaction_rollback_destination_count(
            *transaction) != 1U ||
        git_retirement_transaction_rollback_destination(
            *transaction, 0U, destination.config_path,
            sizeof(destination.config_path),
            &destination.post_config) != 0 ||
        git_retirement_transaction_prepare_terminal_rollback(
            *transaction) != 0) {
        return -1;
    }
    return 0;
}

static int m18_fresh_single_prepare(
    m18_fixture_t *fixture,
    git_retirement_transaction_t **transaction) {
    gitswitch_ctx_t ctx;
    const account_t *account;
    const account_t *accounts[1];
    const publication_record_t *publications[1];

    if (!fixture || !transaction ||
        m18_parent_runtime_begin(fixture, &ctx) != 0) {
        return -1;
    }
    account = m18_find_account(&ctx, UINT32_C(1));
    if (!account) {
        errno = ESTALE;
        return -1;
    }
    accounts[0] = account;
    publications[0] = &fixture->record;
    return git_retirement_transaction_prepare(
        accounts, publications, 1U, transaction);
}

TEST(parent_terminal_clean_settles_present_and_absent_destination_groups) {
    m18_fixture_t fixture;
    gitswitch_ctx_t ctx;
    git_retirement_transaction_t *transaction = NULL;
    char no_op_lock[MAX_PATH_LEN];
    size_t cleared = 0U;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);
    CHECK_EQ_INT(m18_prepare_mixed_transaction(
                     &fixture, &ctx, &transaction), 0);
    CHECK(transaction != NULL);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK(cleared > 0U);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_commit(
                     transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_verify_terminal_commit(
                     transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_commit(
                     &transaction), 0);
    CHECK(transaction == NULL);
    CHECK(!m18_git_has_command(&fixture));
    CHECK_EQ_INT(safe_snprintf(
                     no_op_lock, sizeof(no_op_lock), "%s.lock",
                     fixture.no_op_git_path), 0);
    errno = 0;
    CHECK(access(fixture.no_op_git_path, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(no_op_lock, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(gitswitch_test_context_allocations(), 0);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_terminal_rollback_refreshes_publications_with_clean_absent_group) {
    m18_fixture_t fixture;
    gitswitch_ctx_t ctx;
    git_retirement_transaction_t *transaction = NULL;
    config_retirement_owner_t owners[2];
    config_retirement_destination_t destinations[2];
    size_t destination_count;
    size_t cleared = 0U;
    bool stable = false;

    memset(owners, 0, sizeof(owners));
    memset(destinations, 0, sizeof(destinations));
    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);
    CHECK_EQ_INT(m18_prepare_mixed_transaction(
                     &fixture, &ctx, &transaction), 0);
    CHECK_EQ_INT(git_retirement_transaction_publish(
                     transaction, &cleared), 0);
    CHECK(cleared > 0U);
    CHECK_EQ_INT(git_retirement_transaction_abort(transaction), 0);
    destination_count =
        git_retirement_transaction_rollback_destination_count(transaction);
    CHECK_EQ_INT((long)destination_count, 2);
    for (size_t i = 0U; i < destination_count; i++) {
        CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                         transaction, i, destinations[i].config_path,
                         sizeof(destinations[i].config_path),
                         &destinations[i].post_config), 0);
    }
    owners[0].account_id = UINT32_C(1);
    owners[1].account_id = UINT32_C(2);
    CHECK_EQ_INT(safe_strncpy(
                     owners[0].account_incarnation, M18_INCARNATION,
                     sizeof(owners[0].account_incarnation)), 0);
    CHECK_EQ_INT(safe_strncpy(
                     owners[1].account_incarnation,
                     M18_SECOND_INCARNATION,
                     sizeof(owners[1].account_incarnation)), 0);
    CHECK_EQ_INT(git_retirement_transaction_prepare_terminal_rollback(
                     transaction), 0);
    /* FreeBSD UFS may materialize one final ctime-only successor after the
     * restored descriptor closes or a sibling destination synchronizes the
     * shared parent. Exercise the same bounded reseal loop as accounts.c:
     * publish the complete set, re-query every destination, and replace the
     * complete set before retrying rather than accepting a mixed ledger. */
    for (unsigned attempt = 0U; attempt < 3U; attempt++) {
        bool state_installed = false;
        bool changed = false;

        CHECK_EQ_INT(config_refresh_retirement_publications_transactional(
                         &ctx, fixture.accounts_path, owners, 2U,
                         destinations, destination_count,
                         &state_installed), 0);
        CHECK(state_installed);
        for (size_t i = 0U; i < destination_count; i++) {
            config_retirement_destination_t observed;

            memset(&observed, 0, sizeof(observed));
            CHECK_EQ_INT(git_retirement_transaction_rollback_destination(
                             transaction, i, observed.config_path,
                             sizeof(observed.config_path),
                             &observed.post_config), 0);
            CHECK_STR_EQ(observed.config_path,
                         destinations[i].config_path);
            if (!publication_identity_equal(
                    &observed.post_config,
                    &destinations[i].post_config)) {
                destinations[i].post_config = observed.post_config;
                changed = true;
            }
        }
        if (!changed) {
            stable = true;
            break;
        }
    }
    CHECK(stable);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_mixed_rollback_ledger_is_exact(&fixture));
    CHECK_EQ_INT(gitswitch_test_context_allocations(), 0);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_config_refresh_retires_exact_linked_private_alias) {
    m18_fixture_t fixture;
    gitswitch_ctx_t ctx;
    config_retirement_owner_t owner;
    config_retirement_destination_t destination;
    struct stat state;
    char retained_alias[MAX_PATH_LEN];
    bool state_installed = false;

    memset(&owner, 0, sizeof(owner));
    memset(&destination, 0, sizeof(destination));
    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_parent_runtime_begin(&fixture, &ctx), 0);
    owner.account_id = UINT32_C(1);
    CHECK_EQ_INT(safe_strncpy(
                     owner.account_incarnation, M18_INCARNATION,
                     sizeof(owner.account_incarnation)), 0);
    CHECK_EQ_INT(safe_strncpy(
                     destination.config_path, fixture.git_path,
                     sizeof(destination.config_path)), 0);
    destination.post_config = fixture.record.post_config;
    CHECK_EQ_INT(safe_snprintf(
                     retained_alias, sizeof(retained_alias),
                     "%s/.resume-hint.tmp.A1b2C3",
                     fixture.config_dir), 0);
    CHECK_EQ_INT(link(fixture.state_path, retained_alias), 0);
#if defined(__FreeBSD__)
    /* Descriptor-conditioned unlink retires the exact stale alias in place,
     * so the state returns to one link and the refresh can safely continue. */
    CHECK_EQ_INT(config_refresh_retirement_publications_transactional(
                     &ctx, fixture.accounts_path, &owner, 1U,
                     &destination, 1U, &state_installed), 0);
    CHECK(!state_installed);
    CHECK(m18_ledger_matches_live_restored_git(&fixture));
#else
    /* Portable no-replace quarantine preserves the retired inode until its
     * bounded arena is reclaimed. Its remaining link makes the active-state
     * read fail closed before installation. */
    CHECK_EQ_INT(config_refresh_retirement_publications_transactional(
                     &ctx, fixture.accounts_path, &owner, 1U,
                     &destination, 1U, &state_installed), -1);
    CHECK(!state_installed);
#endif
    errno = 0;
    CHECK(access(retained_alias, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(lstat(fixture.state_path, &state), 0);
#if defined(__FreeBSD__)
    CHECK_EQ_INT((long)state.st_nlink, 1);
#else
    CHECK_EQ_INT((long)state.st_nlink, 2);
#endif
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_freebsd_reproves_and_retires_retained_private_alias) {
#if defined(__FreeBSD__)
    m18_fixture_t fixture;
    gitswitch_ctx_t ctx;
    struct stat hint;
    bool installed = false;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_parent_runtime_begin(&fixture, &ctx), 0);
    CHECK_EQ_INT(unlink(fixture.state_path), 0);
    m18_freebsd_alias_failure_stage =
        CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK;
    (void)gitswitch_test_set_config_publish_hook(
        m18_fail_freebsd_retained_alias);
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, fixture.accounts_path, &installed), -1);
    CHECK(installed);
    CHECK_EQ_INT(lstat(fixture.state_path, &hint), 0);
    CHECK_EQ_INT((long)hint.st_nlink, 3);

    (void)gitswitch_test_set_config_publish_hook(NULL);
    m18_freebsd_alias_failure_stage = -1;
    installed = false;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, fixture.accounts_path, &installed), 0);
    CHECK_EQ_INT(lstat(fixture.state_path, &hint), 0);
    CHECK_EQ_INT((long)hint.st_nlink, 1);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
#else
    TS_SKIP("persistent-fs",
            "FreeBSD retained-source hardlink publication only");
#endif
}

TEST(parent_recovery_classifies_linked_alias_by_marker_shape) {
    m18_fixture_t fixture;
    git_retirement_transaction_t *transaction = NULL;
    git_retirement_transaction_t *fresh = NULL;
    struct stat canonical;
    struct stat alias;
    char lock_path[MAX_PATH_LEN];
    char alias_path[MAX_PATH_LEN];

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_prepare_single_terminal_rollback_marker(
                     &fixture, &transaction), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    CHECK_EQ_INT(safe_snprintf(
                     alias_path, sizeof(alias_path),
                     "%s/.gitswitch-finalization-%ld-1",
                     fixture.home, (long)getpid()), 0);
    CHECK_EQ_INT(link(lock_path, alias_path), 0);
    CHECK_EQ_INT(lstat(lock_path, &canonical), 0);
    CHECK_EQ_INT(lstat(alias_path, &alias), 0);
    CHECK(canonical.st_dev == alias.st_dev);
    CHECK(canonical.st_ino == alias.st_ino);
    CHECK_EQ_INT(m18_fresh_single_prepare(
                     &fixture, &fresh), 0);
    CHECK(fresh != NULL);
    CHECK_EQ_INT(git_retirement_transaction_commit(&fresh), 0);
    CHECK(fresh == NULL);
#if defined(__FreeBSD__)
    /* The canonical FreeBSD transaction lock is a zero-byte lease backed by
     * a separate authority record. A finalization-looking hard link to that
     * lease is foreign, not a crash-retained finalization certificate, and
     * must be preserved. The genuine two-link certificate path is exercised
     * by finalization_sigkill_leaves_complete_self_healing_certificate. */
    CHECK_EQ_INT((long)canonical.st_size, 0);
    CHECK_EQ_INT(lstat(alias_path, &alias), 0);
    CHECK_EQ_INT((long)alias.st_size, 0);
#else
    CHECK(canonical.st_size > 0);
    errno = 0;
    CHECK(access(alias_path, F_OK) != 0 && errno == ENOENT);
#endif
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_recovery_accepts_terminal_marker_with_alias_already_absent) {
    m18_fixture_t fixture;
    git_retirement_transaction_t *transaction = NULL;
    git_retirement_transaction_t *fresh = NULL;
    char lock_path[MAX_PATH_LEN];

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_prepare_single_terminal_rollback_marker(
                     &fixture, &transaction), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    CHECK_EQ_INT(m18_fresh_single_prepare(
                     &fixture, &fresh), 0);
    CHECK_EQ_INT(git_retirement_transaction_commit(&fresh), 0);
    CHECK(fresh == NULL);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_recovery_rejects_wrong_inode_private_alias) {
    static const char foreign[] = "foreign finalization marker\n";
    m18_fixture_t fixture;
    git_retirement_transaction_t *transaction = NULL;
    git_retirement_transaction_t *fresh = NULL;
    char lock_path[MAX_PATH_LEN];
    char extra_link[MAX_PATH_LEN];
    char alias_path[MAX_PATH_LEN];

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_prepare_single_terminal_rollback_marker(
                     &fixture, &transaction), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    CHECK_EQ_INT(safe_snprintf(
                     extra_link, sizeof(extra_link), "%s/marker-extra",
                     fixture.home), 0);
    CHECK_EQ_INT(safe_snprintf(
                     alias_path, sizeof(alias_path),
                     "%s/.gitswitch-finalization-%ld-2",
                     fixture.home, (long)getpid()), 0);
    CHECK_EQ_INT(link(lock_path, extra_link), 0);
    CHECK_EQ_INT(m18_write_file(
                     alias_path, foreign, sizeof(foreign) - 1U, 0600), 0);
    CHECK_EQ_INT(m18_fresh_single_prepare(
                     &fixture, &fresh), 0);
    CHECK(fresh != NULL);
    CHECK(access(lock_path, F_OK) == 0);
    CHECK(access(extra_link, F_OK) == 0);
    CHECK(access(alias_path, F_OK) == 0);
    CHECK_EQ_INT(git_retirement_transaction_commit(&fresh), 0);
    CHECK(fresh == NULL);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
}

TEST(parent_recovery_rejects_private_alias_changed_after_proof) {
#if defined(__FreeBSD__)
    TS_SKIP("persistent-fs",
            "FreeBSD removes exact names through descriptor-conditioned unlink");
#else
    m18_fixture_t fixture;
    git_retirement_transaction_t *transaction = NULL;
    git_retirement_transaction_t *fresh = NULL;
    char lock_path[MAX_PATH_LEN];
    char alias_path[MAX_PATH_LEN];

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_prepare_single_terminal_rollback_marker(
                     &fixture, &transaction), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    CHECK_EQ_INT(safe_snprintf(
                     alias_path, sizeof(alias_path),
                     "%s/.gitswitch-finalization-%ld-3",
                     fixture.home, (long)getpid()), 0);
    CHECK_EQ_INT(link(lock_path, alias_path), 0);

    m18_alias_race_fixture = &fixture;
    m18_alias_race_requested = true;
    m18_alias_race_observed = false;
    m18_alias_race_error = 0;
    (void)git_ops_test_set_retirement_hook(
        m18_retirement_witness_hook);
    CHECK_EQ_INT(m18_fresh_single_prepare(
                     &fixture, &fresh), 0);
    (void)git_ops_test_set_retirement_hook(NULL);
    m18_alias_race_requested = false;
    m18_alias_race_fixture = NULL;
    CHECK(m18_alias_race_observed);
    CHECK_EQ_INT(m18_alias_race_error, 0);
    CHECK(fresh != NULL);
    CHECK(access(lock_path, F_OK) == 0);
    CHECK_EQ_INT(git_retirement_transaction_commit(&fresh), 0);
    CHECK(fresh == NULL);
    CHECK_EQ_INT(git_retirement_transaction_finish_terminal_rollback(
                     &transaction), 0);
    CHECK(transaction == NULL);
    m18_parent_runtime_end();
    m18_fixture_cleanup(&fixture);
#endif
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

TEST(reset_all_preinstall_rollback_settles_restored_and_originally_absent_destinations) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t restored_git_before = {0};
    bool observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &restored_git_before), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);

    status = m18_run_cli(
        &fixture, M18_COMMAND_RESET_ALL, M18_FAULT_ONCE,
        CONFIG_IO_STATE_BEFORE_RENAME, &observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &restored_git_before));
    errno = 0;
    CHECK(access(fixture.no_op_git_path, F_OK) != 0 && errno == ENOENT);
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_mixed_rollback_ledger_is_exact(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&restored_git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(preinstall_terminal_commit_blocks_writer_from_recreating_absent_destination) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t restored_git_before = {0};
    char lock_path[MAX_PATH_LEN];
    bool fault_observed = false;
    int lock_fd = -1;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &restored_git_before), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.no_op_git_path), 0);

    status = m18_run_reset_all_with_terminal_absent_writer(
        &fixture, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) {
        CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    }
    CHECK(fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &restored_git_before));
    errno = 0;
    CHECK(access(fixture.no_op_git_path, F_OK) != 0 && errno == ENOENT);
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_mixed_rollback_ledger_is_exact(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    /* Once finalization has committed, the same cooperative lock acquisition
     * is safe again. Do not publish: preserve the asserted absent generation. */
    lock_fd = open(
        lock_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    CHECK(lock_fd >= 0);
    if (lock_fd >= 0) {
        CHECK_EQ_INT(close(lock_fd), 0);
        CHECK_EQ_INT(unlink(lock_path), 0);
    }

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&restored_git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(reset_all_terminal_recreation_preserves_foreign_file_and_blocker) {
    static const unsigned char foreign_git[] =
        "[foreign]\n\tmarker = terminal-recreation\n";
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t restored_git_before = {0};
    m18_bytes_t replacement = {
        .data = (unsigned char *)foreign_git,
        .length = sizeof(foreign_git) - 1U
    };
    bool hook_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &restored_git_before), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);

    status = m18_run_reset_all_with_terminal_absent_recreation(
        &fixture, &replacement, &hook_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(hook_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &restored_git_before));
    CHECK(m18_file_equals(fixture.no_op_git_path, &replacement));
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_completion_absent(&fixture));
    CHECK(m18_transition_is_private_and_blocking(&fixture, "reset"));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&restored_git_before);
    m18_fixture_cleanup(&fixture);
}

TEST(reset_all_mixed_rollback_reseals_present_ctime_drift_and_preserves_absent_record) {
    m18_fixture_t fixture;
    m18_bytes_t accounts_before = {0};
    m18_bytes_t restored_git_before = {0};
    bool fault_observed = false;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m18_fixture_add_shared_and_no_op_destinations(&fixture), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.accounts_path,
                                &accounts_before), 0);
    CHECK_EQ_INT(m18_read_bytes(fixture.git_path,
                                &restored_git_before), 0);
    CHECK_EQ_INT(unlink(fixture.no_op_git_path), 0);

    status = m18_run_reset_all_with_prepublish_ctime_drift(
        &fixture, &fault_observed);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), EXIT_FAILURE);
    CHECK(fault_observed);
    CHECK(m18_file_equals(fixture.accounts_path, &accounts_before));
    CHECK(m18_file_equals(fixture.git_path, &restored_git_before));
    errno = 0;
    CHECK(access(fixture.no_op_git_path, F_OK) != 0 && errno == ENOENT);
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_state_has_active_work_header(&fixture));
    CHECK(m18_mixed_rollback_ledger_is_exact(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));

    m18_bytes_clear(&accounts_before);
    m18_bytes_clear(&restored_git_before);
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

TEST(forked_child_cannot_finalize_parent_published_retirement) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_forked_finalization_contract(&fixture);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(m18_git_has_command(&fixture));
    CHECK(m18_ledger_matches_live_restored_git(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    m18_fixture_cleanup(&fixture);
}

TEST(foreign_git_capability_disposal_preserves_reused_fds) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_foreign_git_capability_fd_aba(&fixture);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(forked_child_signal_reset_retry_admits_fresh_transaction) {
    gitswitch_ctx_t ctx;
    accounts_transaction_token_t parent_token = 0;
    int status = 0;
    pid_t child;

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(accounts_transaction_begin(
                     &ctx, ACCOUNTS_TRANSACTION_RESET,
                     &parent_token), 0);
    CHECK(parent_token != 0);
    CHECK_EQ_INT(signals_guard_begin(), 0);
    CHECK(signals_guard_active());
    CHECK(!accounts_transaction_context_release_safe(&ctx));

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        accounts_transaction_token_t child_token = 0;

        signals_test_fail_sigaction(
            SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        errno = 0;
        if (accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_RESET,
                parent_token) != -1 ||
            errno != EIO) {
            _exit(1);
        }
        /* The failed inherited entry already disposed the copied account
         * handles. This independent admission retries only the retained
         * signal restoration and must not consume a stale finalizer reject. */
        if (accounts_transaction_begin(
                &ctx, ACCOUNTS_TRANSACTION_INITIALIZE,
                &child_token) != 0 ||
            child_token <= parent_token ||
            accounts_transaction_finish(
                &ctx, ACCOUNTS_TRANSACTION_INITIALIZE,
                child_token) != 0 ||
            !accounts_transaction_context_release_safe(&ctx)) {
            _exit(2);
        }
        _exit(0);
    }
    if (child > 0) {
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }

    /* Child-local restoration and disposal cannot consume the parent's owner
     * or guard. */
    CHECK(signals_guard_active());
    CHECK(!accounts_transaction_context_release_safe(&ctx));
    CHECK_EQ_INT(accounts_transaction_finish(
                     &ctx, ACCOUNTS_TRANSACTION_RESET,
                     parent_token), 0);
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK(accounts_transaction_context_release_safe(&ctx));
}

TEST(preprepare_failure_clears_only_fresh_guard_without_mutation) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_preprepare_guard_cleanup_contract(
        &fixture, M18_PREPARE_GUARD_FRESH);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(preprepare_failure_retains_adopted_guard_without_mutation) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_preprepare_guard_cleanup_contract(
        &fixture, M18_PREPARE_GUARD_ADOPTED);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(preprepare_clear_uncertainty_retains_blocker_and_primary_error) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_preprepare_guard_cleanup_contract(
        &fixture, M18_PREPARE_GUARD_CLEAR_UNCERTAIN);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(deferred_publish_without_mutation_clears_fresh_guard) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_failed_publish_guard_contract(
        &fixture, M18_PUBLISH_GUARD_NO_MUTATION_FRESH);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(mutation_capable_publish_failure_retains_fresh_guard) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_failed_publish_guard_contract(
        &fixture, M18_PUBLISH_GUARD_MUTATION_CAPABLE_FRESH);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(deferred_publish_without_mutation_retains_adopted_guard) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_failed_publish_guard_contract(
        &fixture, M18_PUBLISH_GUARD_NO_MUTATION_ADOPTED);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(failed_publish_cleanup_uncertainty_retains_fresh_guard) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(m24_fixture_add_managed_alias(&fixture), 0);
    status = m18_run_failed_publish_guard_contract(
        &fixture, M18_PUBLISH_GUARD_CLEANUP_UNCERTAIN_FRESH);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(durable_terminal_commit_blocks_git_writer_at_post_barrier_checkpoint) {
    m18_fixture_t fixture;
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    status = m18_run_terminal_writer_contract(&fixture, false);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    m18_fixture_cleanup(&fixture);
}

TEST(durable_terminal_precommit_failure_retains_marker_and_guard) {
    m18_fixture_t fixture;
    char lock_path[MAX_PATH_LEN];
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    status = m18_run_terminal_writer_contract(&fixture, true);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_private_and_blocking(&fixture, "reset"));
    CHECK_EQ_INT(m18_terminal_marker_checkpoint_status(
                     lock_path, fixture.git_path, true),
                 M18_TERMINAL_WRITER_BLOCKED);
    m18_fixture_cleanup(&fixture);
}

TEST(post_guard_terminal_cleanup_failure_is_consumed_and_self_heals) {
    static const char foreign[] = "foreign-terminal-entry\n";
    m18_fixture_t fixture;
    char lock_path[MAX_PATH_LEN];
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    status = m18_run_terminal_cleanup_contract(&fixture, false);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_terminal_marker_checkpoint_status(
                     lock_path, fixture.git_path, true),
                 M18_TERMINAL_WRITER_BLOCKED);

    status = m18_run_fresh_managed_write(
        &fixture, foreign, M18_FRESH_FIRST_UNSET);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST(crash_before_terminal_marker_release_self_heals_in_fresh_writer) {
    static const char foreign[] = "foreign-terminal-entry\n";
    m18_fixture_t fixture;
    char lock_path[MAX_PATH_LEN];
    int status;

    CHECK_EQ_INT(m18_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(safe_snprintf(
                     lock_path, sizeof(lock_path), "%s.lock",
                     fixture.git_path), 0);
    status = m18_run_terminal_cleanup_contract(&fixture, true);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 89);
    CHECK(!m18_git_has_command(&fixture));
    CHECK(m18_guard_is_unblocked_and_bounded(&fixture));
    CHECK_EQ_INT(m18_terminal_marker_checkpoint_status(
                     lock_path, fixture.git_path, true),
                 M18_TERMINAL_WRITER_BLOCKED);

    status = m18_run_fresh_managed_write(
        &fixture, foreign, M18_FRESH_FIRST_SET);
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    m18_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    if (m18_suite_fixture_setup() != 0) {
        fprintf(stderr, "HARNESS FAIL: stable command fixture: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(remove_save_boundary_matrix_preserves_outer_coherence);
    RUN_TEST(remove_uncertain_install_recovers_in_fresh_process);
    RUN_TEST(recovery_terminal_verify_follows_final_prepared_guard_reads);
    RUN_TEST(recovery_post_guard_cleanup_failure_is_success_and_self_heals);
    RUN_TEST(remove_recovery_reconciles_interrupted_completion_stage);
    RUN_TEST(remove_recovery_rejects_reintroduced_git_identity);
    RUN_TEST(remove_recovery_rejects_reused_id_incarnation);
    RUN_TEST(absent_destination_recreation_stays_guarded_until_clean_retry);
    RUN_TEST(same_filesystem_repository_move_retains_guard_and_retry_authority);
    RUN_TEST(remove_backup_verification_fault_restores_exact_outer_state);
    RUN_TEST(restored_witness_retries_multiple_delayed_ctime_steps);
    RUN_TEST(restored_witness_flushes_post_read_ctime_before_reset_ledger_seal);
    RUN_TEST(restored_witness_flushes_final_read_ctime_before_reset_ledger_seal);
    RUN_TEST(prepared_guard_flush_precedes_restored_ledger_seal);
    RUN_TEST(rollback_prepublish_ctime_drift_reseals_then_clears);
    RUN_TEST(rollback_prepublish_same_size_rewrite_is_rejected_exactly);
    RUN_TEST(rollback_repeated_prepublish_ctime_drift_is_bounded_and_blocking);
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
    RUN_TEST(parent_terminal_clean_settles_present_and_absent_destination_groups);
    RUN_TEST(parent_terminal_rollback_refreshes_publications_with_clean_absent_group);
    RUN_TEST(parent_config_refresh_retires_exact_linked_private_alias);
    RUN_TEST(parent_freebsd_reproves_and_retires_retained_private_alias);
    RUN_TEST(parent_recovery_classifies_linked_alias_by_marker_shape);
    RUN_TEST(parent_recovery_accepts_terminal_marker_with_alias_already_absent);
    RUN_TEST(parent_recovery_rejects_wrong_inode_private_alias);
    RUN_TEST(parent_recovery_rejects_private_alias_changed_after_proof);
    RUN_TEST(reset_state_boundary_matrix_preserves_outer_coherence);
    RUN_TEST(reset_persistent_preinstall_fault_retains_guard_and_blocks_switch);
    RUN_TEST(reset_all_clean_rollback_refreshes_shared_and_no_op_destinations);
    RUN_TEST(reset_all_preinstall_rollback_settles_restored_and_originally_absent_destinations);
    RUN_TEST(preinstall_terminal_commit_blocks_writer_from_recreating_absent_destination);
    RUN_TEST(reset_all_terminal_recreation_preserves_foreign_file_and_blocker);
    RUN_TEST(reset_all_mixed_rollback_reseals_present_ctime_drift_and_preserves_absent_record);
    RUN_TEST(reset_retirement_phase_rejections_preserve_pending_owner);
    RUN_TEST(forked_child_cannot_finalize_parent_published_retirement);
    RUN_TEST(foreign_git_capability_disposal_preserves_reused_fds);
    RUN_TEST(forked_child_signal_reset_retry_admits_fresh_transaction);
    RUN_TEST(preprepare_failure_clears_only_fresh_guard_without_mutation);
    RUN_TEST(preprepare_failure_retains_adopted_guard_without_mutation);
    RUN_TEST(preprepare_clear_uncertainty_retains_blocker_and_primary_error);
    RUN_TEST(deferred_publish_without_mutation_clears_fresh_guard);
    RUN_TEST(mutation_capable_publish_failure_retains_fresh_guard);
    RUN_TEST(deferred_publish_without_mutation_retains_adopted_guard);
    RUN_TEST(failed_publish_cleanup_uncertainty_retains_fresh_guard);
    RUN_TEST(durable_terminal_commit_blocks_git_writer_at_post_barrier_checkpoint);
    RUN_TEST(durable_terminal_precommit_failure_retains_marker_and_guard);
    RUN_TEST(post_guard_terminal_cleanup_failure_is_consumed_and_self_heals);
    RUN_TEST(crash_before_terminal_marker_release_self_heals_in_fresh_writer);
TEST_MAIN_END()
