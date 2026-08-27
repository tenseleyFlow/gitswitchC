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
#include "git_ops.h"
#include "gpg_manager.h"
#include "signals.h"
#include "ssh_manager.h"
#include "utils.h"

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

typedef void (*switch_abort_test_hook_fn)(gitswitch_ctx_t *ctx);
typedef void (*switch_prepare_failure_test_hook_fn)(void);
typedef void (*switch_rollback_publish_test_hook_fn)(void);

int gitswitch_cli_main(int argc, char **argv);
switch_abort_test_hook_fn gitswitch_test_set_switch_abort_hook(
    switch_abort_test_hook_fn hook);
switch_prepare_failure_test_hook_fn
gitswitch_test_set_switch_prepare_failure_hook(
    switch_prepare_failure_test_hook_fn hook);
switch_rollback_publish_test_hook_fn
gitswitch_test_set_switch_rollback_publish_hook(
    switch_rollback_publish_test_hook_fn hook);
typedef enum {
    SWITCH_GUARD_INSTALL_BEFORE_INITIAL_FSTAT = 0,
    SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC,
    SWITCH_GUARD_CLEAR_AFTER_UNLINK,
    SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ,
    SWITCH_GUARD_RECONCILE_AFTER_NORMALIZE_SYNC,
    SWITCH_GUARD_RETAIN_AFTER_MARKER_SYNC,
    SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF,
    SWITCH_GUARD_DESTINATION_AFTER_OPEN
} switch_guard_test_stage_t;
typedef int (*switch_guard_test_hook_fn)(
    switch_guard_test_stage_t stage, int directory_fd);
switch_guard_test_hook_fn gitswitch_test_set_switch_guard_hook(
    switch_guard_test_hook_fn hook);
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
unsigned int gitswitch_test_set_retirement_settled_slot_limit(
    unsigned int limit);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);
int gitswitch_test_switch_guard_directory_fd(
    const config_switch_guard_t *guard);

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char config_dir[PATH_MAX];
    char config[PATH_MAX];
    char hint[PATH_MAX];
    char switch_fence[PATH_MAX];
    char switch_stage[PATH_MAX];
    char gitconfig[PATH_MAX];
    char ssh_config[PATH_MAX];
    char output[PATH_MAX];
} cli_owner_fixture_t;

typedef struct {
    pid_t pid;
    int release_fd;
} runtime_holder_t;

typedef struct {
    cli_owner_fixture_t cli;
    char key_path[PATH_MAX];
    char source_home[PATH_MAX];
    char tools[PATH_MAX];
    char gpg_base[PATH_MAX];
    char gpg_home[PATH_MAX];
    char gpg_current[PATH_MAX];
} h5_fixture_t;

typedef struct {
    const char *name;
    char *value;
    bool present;
    bool captured;
} h1_saved_env_t;

typedef struct {
    gitswitch_ctx_t *ctx;
    publication_record_t *destinations;
    size_t destination_count;
    account_t *target;
    config_switch_guard_t *guard;
    h1_saved_env_t environment[6];
} h1_guard_case_t;

typedef enum {
    SWITCH_MARKER_MUTATION_NONE = 0,
    SWITCH_MARKER_MUTATION_CTIME_ONLY,
    SWITCH_MARKER_MUTATION_PARSE_VALID_TOKEN_RESTORED_MTIME
} switch_marker_mutation_t;

static runtime_holder_t g_runtime_holder = { -1, -1 };
static bool g_hook_should_hold_runtime;
static int g_hook_called;
static int g_hook_commit_rc;
static accounts_switch_commit_state_t g_hook_commit_state;
static int g_hook_holder_rc;
static int g_hook_prepare_errno;
static error_context_t g_hook_prepare_error;
static int g_publish_called;
static int g_publish_errno;
static error_context_t g_publish_error;
static char g_hook_commit_error[512];
static cli_owner_fixture_t g_persistence_fault_fixture;
static bool g_persistence_fault_armed;
static int g_persistence_fault_mutation_rc;
static cli_owner_fixture_t g_h1_fault_fixture;
static bool g_h1_fault_armed;
static int g_h1_fault_calls;
static int g_h1_fault_mutation_rc;
static bool g_switch_guard_fail_stage;
static bool g_switch_guard_replace_before_initial_fstat;
static bool g_switch_guard_fail_clear;
static bool g_switch_guard_fail_normalize_sync;
static int g_switch_guard_clear_failures_remaining;
static int g_switch_guard_hook_calls;
static int g_switch_guard_replacement_rc;
static struct stat g_switch_guard_displaced_stage;
static struct stat g_switch_guard_replacement_stage;
static bool g_switch_guard_drift_source_after_stage_sync;
static bool g_switch_guard_drift_source_after_retain_sync;
static int g_switch_guard_source_drift_calls;
static int g_switch_guard_source_drift_rc;
static char g_switch_guard_source_path[PATH_MAX];
static struct stat g_switch_guard_source_before_drift;
static struct stat g_switch_guard_source_after_drift;
static switch_marker_mutation_t g_switch_marker_mutation;
static switch_guard_test_stage_t g_switch_marker_mutation_stage;
static int g_switch_marker_mutation_calls;
static int g_switch_marker_outer_snapshot_calls;
static int g_switch_marker_mutation_rc;
static char g_switch_marker_mutation_path[PATH_MAX];
static struct stat g_switch_marker_before_mutation;
static struct stat g_switch_marker_after_mutation;
static unsigned char g_switch_marker_original_byte;
static unsigned char g_switch_marker_mutated_byte;
static size_t g_switch_marker_mutation_offset;
static bool g_switch_guard_replace_directory_after_read;
static int g_switch_guard_directory_replacement_rc;
static char g_switch_guard_directory_path[PATH_MAX];
static char g_switch_guard_displaced_directory_path[PATH_MAX];
static bool g_switch_guard_churn_destination_directory;
static int g_switch_guard_destination_churn_calls;
static int g_switch_guard_destination_churn_rc;
static struct stat g_switch_guard_destination_before_churn;
static struct stat g_switch_guard_destination_after_churn;
static volatile sig_atomic_t g_returning_signal_calls;

typedef enum {
    SIGNAL_MARKER_GUARD_RESTORE = 0,
    SIGNAL_MARKER_DISPATCH_RESTORE
} signal_marker_case_t;

static const int guarded_signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };
static const char expected_accounts_config[] =
    "[settings]\n"
    "default_scope = \"global\"\n"
    "\n"
    "[accounts.1]\n"
    "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"\n"
    "name = \"work\"\n"
    "email = \"work@example.test\"\n"
    "description = \"retained owner fixture\"\n"
    "preferred_scope = \"global\"\n";
static const char expected_gitconfig[] =
    "[user]\n"
    "\tname = Before Name\n"
    "\temail = before@example.test\n";
static const char concurrent_gitconfig[] =
    "[user]\n"
    "\tname = Concurrent Name\n"
    "\temail = work@example.test\n"
    "[commit]\n"
    "\tgpgsign = false\n"
    "[gpg]\n"
    "\tformat = openpgp\n";
static const char h1_accounts_config[] =
    "[settings]\n"
    "default_scope = \"global\"\n"
    "\n"
    "[accounts.1]\n"
    "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"\n"
    "name = \"old\"\n"
    "email = \"old@example.test\"\n"
    "description = \"H1 prior identity\"\n"
    "preferred_scope = \"global\"\n"
    "\n"
    "[accounts.2]\n"
    "incarnation = \"2222222222222222222222222222222222222222222222222222222222222222\"\n"
    "name = \"work\"\n"
    "email = \"work@example.test\"\n"
    "description = \"H1 switch identity\"\n"
    "preferred_scope = \"global\"\n";
static const char h1_numeric_name_accounts_config[] =
    "[settings]\n"
    "default_scope = \"global\"\n"
    "\n"
    "[accounts.1]\n"
    "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"\n"
    "name = \"old\"\n"
    "email = \"old@example.test\"\n"
    "description = \"H1 prior identity\"\n"
    "preferred_scope = \"global\"\n"
    "\n"
    "[accounts.7]\n"
    "incarnation = \"7777777777777777777777777777777777777777777777777777777777777777\"\n"
    "name = \"id-seven\"\n"
    "email = \"id-seven@example.test\"\n"
    "description = \"numeric ID collision decoy\"\n"
    "preferred_scope = \"global\"\n"
    "\n"
    "[accounts.8]\n"
    "incarnation = \"8888888888888888888888888888888888888888888888888888888888888888\"\n"
    "name = \"7\"\n"
    "email = \"numeric-name@example.test\"\n"
    "description = \"canonical decimal account name\"\n"
    "preferred_scope = \"global\"\n";
static const char h1_old_gitconfig[] =
    "[user]\n"
    "\tname = old\n"
    "\temail = old@example.test\n";
#define H1_WORK_INCARNATION \
    "2222222222222222222222222222222222222222222222222222222222222222"
#define H1_NUMERIC_NAME_INCARNATION \
    "8888888888888888888888888888888888888888888888888888888888888888"
#define H5_GPG_FINGERPRINT \
    "0123456789ABCDEF01234567ABCDEF0123456789"

static const char h5_fake_gpg[] =
    "#!/bin/sh\n"
    "list_secret=\n"
    "show_version=\n"
    "export_secret=\n"
    "for arg in \"$@\"; do\n"
    "    case \"$arg\" in\n"
    "        --list-secret-keys) list_secret=1 ;;\n"
    "        --version) show_version=1 ;;\n"
    "        --export-secret-keys) export_secret=1 ;;\n"
    "    esac\n"
    "done\n"
    "if [ \"$show_version\" = 1 ]; then\n"
    "    printf '%s\\n' 'gpg (GnuPG) 2.4.0'\n"
    "elif [ \"$list_secret\" = 1 ]; then\n"
    "    printf '%s\\n' "
    "'sec:u:4096:1:ABCDEF0123456789:1700000000:::-:::scESC:::+:::23::0:' "
    "'fpr:::::::::" H5_GPG_FINGERPRINT ":'\n"
    "elif [ \"$export_secret\" = 1 ]; then\n"
    "    printf '%s\\n' 'AR14-H5-LOCAL-FIXTURE-BYTES'\n"
    "fi\n"
    "exit 0\n";

static const char h5_fake_gpgconf[] =
    "#!/bin/sh\n"
    "dir=${PATH%%:*}\n"
    "case \"$1:$2\" in\n"
    "    --list-components:)\n"
    "        printf 'gpg:OpenPGP:%s/gpg\\n' \"$dir\"\n"
    "        ;;\n"
    "    --reload:gpg-agent) exit 0 ;;\n"
    "    *) exit 64 ;;\n"
    "esac\n";

static int redirect_output(const char *path);

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

static int sync_directory(const char *path) {
    int fd = open(
        path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int result;
    int saved_errno;

    if (fd < 0) return -1;
    result = fsync(fd);
    saved_errno = errno;
    if (close(fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    errno = saved_errno;
    return result;
}

static int replace_private_bytes_atomically(
    const char *path, const unsigned char *data, size_t length) {
    char directory[PATH_MAX];
    char temp[PATH_MAX] = "";
    const char *slash;
    size_t directory_length;
    size_t total = 0;
    int dir_fd = -1;
    int output_fd = -1;
    int result = -1;
    int saved_errno;

    if (!path || (!data && length != 0U)) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash || slash == path) {
        errno = EINVAL;
        return -1;
    }
    directory_length = (size_t)(slash - path);
    if (directory_length >= sizeof(directory) ||
        (size_t)snprintf(temp, sizeof(temp), "%s.ar14.XXXXXX", path) >=
            sizeof(temp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(directory, path, directory_length);
    directory[directory_length] = '\0';

    output_fd = mkstemp(temp);
    if (output_fd < 0 || fchmod(output_fd, 0600) != 0) goto cleanup;
    while (total < length) {
        ssize_t count = write(output_fd, data + total, length - total);

        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else goto cleanup;
    }
    if (fsync(output_fd) != 0 || close(output_fd) != 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;
    if (rename(temp, path) != 0) goto cleanup;
    temp[0] = '\0';

    dir_fd = open(directory,
                  O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fsync(dir_fd) != 0) goto cleanup;
    result = 0;

cleanup:
    saved_errno = errno;
    if (output_fd >= 0) close(output_fd);
    if (dir_fd >= 0) close(dir_fd);
    if (result != 0 && temp[0] != '\0') (void)unlink(temp);
    errno = saved_errno;
    return result;
}

static int replace_private_atomically(const char *path, const char *text) {
    if (!text) {
        errno = EINVAL;
        return -1;
    }
    return replace_private_bytes_atomically(
        path, (const unsigned char *)text, strlen(text));
}

static bool diverge_persistence_rollback(config_io_boundary_t boundary) {
    int hint_rc;
    int git_rc;

    if (!g_persistence_fault_armed ||
        boundary != CONFIG_IO_STATE_BEFORE_DIR_SYNC) {
        return false;
    }
    g_persistence_fault_armed = false;
    hint_rc = write_private(g_persistence_fault_fixture.hint,
                            "none\nactive=later\n");
    git_rc = write_private(g_persistence_fault_fixture.gitconfig,
                           concurrent_gitconfig);
    g_persistence_fault_mutation_rc = hint_rc == 0 && git_rc == 0 ? 0 : -1;
    return true;
}

static int replace_h1_hint_generation(void) {
    unsigned char *content = NULL;
    char temp[PATH_MAX] = "";
    struct stat st;
    size_t length;
    size_t total = 0;
    int dir_fd = -1;
    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    int saved_errno;

    input_fd = open(g_h1_fault_fixture.hint,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input_fd < 0 || fstat(input_fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uintmax_t)st.st_size > UINTMAX_C(8) * 1024U * 1024U + 4096U) {
        goto cleanup;
    }
    length = (size_t)st.st_size;
    content = malloc(length + 1U);
    if (!content) goto cleanup;
    while (total < length) {
        ssize_t count = read(input_fd, content + total, length - total);

        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else goto cleanup;
    }
    content[length] = '\0';
    if (strncmp((const char *)content, "none\nactive=work\n",
                strlen("none\nactive=work\n")) != 0 ||
        strstr((const char *)content, "publications=v1\n") == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (close(input_fd) != 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if ((size_t)snprintf(temp, sizeof(temp),
                         "%s/.resume-hint.h1.XXXXXX",
                         g_h1_fault_fixture.config_dir) >= sizeof(temp)) {
        errno = ENAMETOOLONG;
        goto cleanup;
    }
    output_fd = mkstemp(temp);
    if (output_fd < 0 || fchmod(output_fd, 0600) != 0) goto cleanup;
    total = 0;
    while (total < length) {
        ssize_t count = write(output_fd, content + total, length - total);

        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else goto cleanup;
    }
    if (fsync(output_fd) != 0 || close(output_fd) != 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;
    if (rename(temp, g_h1_fault_fixture.hint) != 0) goto cleanup;
    temp[0] = '\0';

    dir_fd = open(g_h1_fault_fixture.config_dir,
                  O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fsync(dir_fd) != 0) goto cleanup;
    result = 0;

cleanup:
    saved_errno = errno;
    if (input_fd >= 0) close(input_fd);
    if (output_fd >= 0) close(output_fd);
    if (dir_fd >= 0) close(dir_fd);
    if (result != 0 && temp[0] != '\0') (void)unlink(temp);
    if (content) {
        secure_zero_memory(content, length + 1U);
        free(content);
    }
    errno = saved_errno;
    return result;
}

static bool replace_h1_postimage_and_fail_sync(
    config_io_boundary_t boundary) {
    if (!g_h1_fault_armed ||
        boundary != CONFIG_IO_STATE_BEFORE_DIR_SYNC) {
        return false;
    }
    g_h1_fault_armed = false;
    g_h1_fault_calls++;
    g_h1_fault_mutation_rc = replace_h1_hint_generation();
    return true;
}

static bool replace_h1_with_third_image_and_fail_sync(
    config_io_boundary_t boundary) {
    int hint_rc;
    int git_rc;

    if (!g_h1_fault_armed ||
        boundary != CONFIG_IO_STATE_BEFORE_DIR_SYNC) {
        return false;
    }
    g_h1_fault_armed = false;
    g_h1_fault_calls++;
    hint_rc = replace_private_atomically(
        g_h1_fault_fixture.hint, "none\nactive=later\n");
    git_rc = replace_private_atomically(
        g_h1_fault_fixture.gitconfig, concurrent_gitconfig);
    g_h1_fault_mutation_rc = hint_rc == 0 && git_rc == 0 ? 0 : -1;
    return true;
}

static bool replace_h1_git_during_state_commit_and_allow_sync(
    config_io_boundary_t boundary) {
    if (!g_h1_fault_armed ||
        boundary != CONFIG_IO_STATE_BEFORE_DIR_SYNC) {
        return false;
    }
    g_h1_fault_armed = false;
    g_h1_fault_calls++;
    g_h1_fault_mutation_rc = replace_private_atomically(
        g_h1_fault_fixture.gitconfig, concurrent_gitconfig);

    /* The replacement is the race under test, not an injected durability
     * failure. Let the target active-state save finish successfully so final
     * switch validation must detect the now-divergent Git destination. */
    return false;
}

static int fail_switch_guard_lifecycle(
    switch_guard_test_stage_t stage, int directory_fd) {
    static const char replacement[] = "foreign-switch-transition\n";

    if (stage == SWITCH_GUARD_INSTALL_BEFORE_INITIAL_FSTAT &&
        g_switch_guard_replace_before_initial_fstat) {
        int replacement_fd = -1;
        ssize_t written;

        g_switch_guard_replace_before_initial_fstat = false;
        g_switch_guard_hook_calls++;
        g_switch_guard_replacement_rc = -1;
        if (fstatat(
                directory_fd, ".switch-transition",
                &g_switch_guard_displaced_stage,
                AT_SYMLINK_NOFOLLOW) != 0 ||
            unlinkat(
                directory_fd, ".switch-transition", 0) != 0) {
            errno = EIO;
            return -1;
        }
        replacement_fd = openat(
            directory_fd, ".switch-transition",
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        if (replacement_fd < 0) return -1;
        written = write(
            replacement_fd, replacement, sizeof(replacement) - 1U);
        if (written != (ssize_t)(sizeof(replacement) - 1U) ||
            fsync(replacement_fd) != 0 ||
            fstat(replacement_fd, &g_switch_guard_replacement_stage) != 0 ||
            close(replacement_fd) != 0) {
            if (replacement_fd >= 0) (void)close(replacement_fd);
            errno = EIO;
            return -1;
        }
        g_switch_guard_replacement_rc = 0;
        errno = EIO;
        return -1;
    }
    if ((stage == SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC &&
         g_switch_guard_fail_stage) ||
        (stage == SWITCH_GUARD_RECONCILE_AFTER_NORMALIZE_SYNC &&
         g_switch_guard_fail_normalize_sync) ||
        (stage == SWITCH_GUARD_CLEAR_AFTER_UNLINK &&
         (g_switch_guard_fail_clear ||
          g_switch_guard_clear_failures_remaining > 0))) {
        g_switch_guard_fail_stage = false;
        g_switch_guard_fail_normalize_sync = false;
        g_switch_guard_fail_clear = false;
        if (g_switch_guard_clear_failures_remaining > 0) {
            g_switch_guard_clear_failures_remaining--;
        }
        g_switch_guard_hook_calls++;
        errno = EIO;
        return -1;
    }
    return 0;
}

#if defined(__FreeBSD__)
static int g_freebsd_settlement_stop_stage = -1;
static int g_freebsd_settlement_fail_stage = -1;
static int g_freebsd_fixed_replacement_rc = -1;
static bool g_freebsd_replace_target_with_fixed;
static int g_freebsd_original_pair_fd = -1;
static struct stat g_freebsd_original_pair_identity;
static int g_freebsd_source_fifo_rc = -1;
static char g_freebsd_source_fifo_name[PATH_MAX];

static bool fail_default_before_publication(
    config_io_boundary_t boundary) {
    return boundary == CONFIG_IO_DEFAULT_BEFORE_RENAME;
}

static int fail_freebsd_retained_settlement(
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
    if ((int)stage == g_freebsd_settlement_stop_stage) {
        _exit(0);
    }
    return 0;
}

static int fail_freebsd_retained_settlement_in_process(
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
    if ((int)stage == g_freebsd_settlement_fail_stage) {
        g_freebsd_settlement_fail_stage = -1;
        errno = EIO;
        return -1;
    }
    return 0;
}

static int replace_freebsd_fixed_authority_before_retirement(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    static const char foreign[] = "foreign-fixed\n";
    unsigned char copied[16384];
    const char *settled_name =
        ".gitswitch-resume-hint-settled-0";
    size_t copied_length = 0U;
    size_t written = 0U;
    int fd;

    (void)source;
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
    if (stage != CONFIG_PUBLISH_TEST_BEFORE_FIXED_RETIRE ||
        strcmp(destination, ".resume-hint") != 0) {
        return 0;
    }
    g_freebsd_fixed_replacement_rc = -1;
    if (g_freebsd_replace_target_with_fixed) {
        fd = openat(
            directory_fd, destination,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 0;
        while (copied_length < sizeof(copied)) {
            ssize_t count = read(
                fd, copied + copied_length,
                sizeof(copied) - copied_length);

            if (count > 0) {
                copied_length += (size_t)count;
            } else if (count == 0) {
                break;
            } else if (errno != EINTR) {
                (void)close(fd);
                return 0;
            }
        }
        if (copied_length == sizeof(copied) ||
            fstat(fd, &g_freebsd_original_pair_identity) != 0) {
            (void)close(fd);
            return 0;
        }
        g_freebsd_original_pair_fd = fd;
        if (
            unlinkat(directory_fd, settled_name, 0) != 0 ||
            unlinkat(directory_fd, destination, 0) != 0) {
            return 0;
        }
        fd = openat(
            directory_fd, destination,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        if (fd < 0) return 0;
        while (written < copied_length) {
            ssize_t count =
                write(fd, copied + written, copied_length - written);

            if (count > 0) {
                written += (size_t)count;
            } else if (count < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
        {
            int sync_result =
                written == copied_length ? fsync(fd) : -1;
            int close_result = close(fd);

            if (written == copied_length &&
                sync_result == 0 && close_result == 0 &&
                linkat(
                    directory_fd, destination,
                    directory_fd, settled_name, 0) == 0 &&
                fsync(directory_fd) == 0) {
                g_freebsd_fixed_replacement_rc = 0;
            }
        }
        secure_zero_memory(copied, sizeof(copied));
        return 0;
    }
    if (unlinkat(directory_fd, settled_name, 0) != 0) return 0;
    fd = openat(
        directory_fd, settled_name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600);
    if (fd < 0) return 0;
    while (written < sizeof(foreign) - 1U) {
        ssize_t count =
            write(fd, foreign + written,
                  sizeof(foreign) - 1U - written);

        if (count > 0) {
            written += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    {
        int sync_result =
            written == sizeof(foreign) - 1U ? fsync(fd) : -1;
        int close_result = close(fd);

        if (written == sizeof(foreign) - 1U &&
            sync_result == 0 && close_result == 0) {
            g_freebsd_fixed_replacement_rc = 0;
        }
    }
    return 0;
}

static int replace_freebsd_source_with_fifo_before_pin(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
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
    if (stage != CONFIG_PUBLISH_TEST_BEFORE_SOURCE_PIN ||
        strcmp(destination, ".resume-hint") != 0) {
        return 0;
    }

    g_freebsd_source_fifo_rc = -1;
    if (safe_strncpy(
            g_freebsd_source_fifo_name, source,
            sizeof(g_freebsd_source_fifo_name)) != 0 ||
        unlinkat(directory_fd, source, 0) != 0 ||
        mkfifoat(directory_fd, source, 0600) != 0) {
        return 0;
    }
    g_freebsd_source_fifo_rc = 0;
    errno = EIO;
    return 0;
}

static int fail_both_freebsd_publish_unlinks(
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
    return 0;
}

static int fail_freebsd_resume_hint_publish_unlinks(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    (void)directory_fd;
    (void)source;
    if (strcmp(destination, ".resume-hint") == 0 &&
        (stage == CONFIG_PUBLISH_TEST_SOURCE_UNLINK ||
         stage == CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int fail_freebsd_config_document_publish_unlinks(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    (void)directory_fd;
    (void)source;
    if (strcmp(destination, "accounts.toml") == 0 &&
        (stage == CONFIG_PUBLISH_TEST_SOURCE_UNLINK ||
         stage == CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int make_freebsd_generic_publish_uncertain_for(
    const char *target, config_publish_test_stage_t stage,
    int directory_fd, const char *destination) {
    static const char foreign[] = "foreign-publication\n";
    int fd;

    if (strcmp(destination, target) != 0) return 0;
    if (stage == CONFIG_PUBLISH_TEST_SOURCE_UNLINK ||
        stage == CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK) {
        errno = EIO;
        return -1;
    }
    if (stage != CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE) return 0;
    if (unlinkat(directory_fd, destination, 0) != 0) return -1;
    fd = openat(
        directory_fd, destination,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 ||
        write(fd, foreign, sizeof(foreign) - 1U) !=
            (ssize_t)(sizeof(foreign) - 1U) ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        return -1;
    }
    return 0;
}

static int make_freebsd_config_document_publish_uncertain(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    (void)source;
    return make_freebsd_generic_publish_uncertain_for(
        "accounts.toml", stage, directory_fd, destination);
}

static int make_freebsd_publish_outcome_uncertain(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination) {
    static const char foreign[] = "foreign-switch-marker\n";
    int fd;

    (void)source;
    if (stage == CONFIG_PUBLISH_TEST_SOURCE_UNLINK ||
        stage == CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK) {
        errno = EIO;
        return -1;
    }
    if (stage != CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE) return 0;
    if (unlinkat(directory_fd, destination, 0) != 0) return -1;
    fd = openat(
        directory_fd, destination,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 ||
        write(fd, foreign, sizeof(foreign) - 1U) !=
            (ssize_t)(sizeof(foreign) - 1U) ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        return -1;
    }
    return 0;
}
#endif

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

static size_t h1_read_bounded_file(
    const char *path, unsigned char *data, size_t capacity,
    struct stat *state) {
    struct stat before;
    struct stat after;
    size_t total = 0U;
    int fd;

    if (!path || !data || capacity == 0U ||
        lstat(path, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size <= 0 ||
        (uintmax_t)before.st_size > (uintmax_t)capacity) {
        return 0U;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &after) != 0 ||
        !ts_same_identity(&before, &after) ||
        after.st_size != before.st_size) {
        if (fd >= 0) close(fd);
        return 0U;
    }
    while (total < (size_t)before.st_size) {
        ssize_t count = read(
            fd, data + total, (size_t)before.st_size - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            total = 0U;
            break;
        }
    }
    if (fstat(fd, &after) != 0 ||
        !ts_same_identity(&before, &after) ||
        after.st_size != before.st_size) {
        close(fd);
        return 0U;
    }
    if (close(fd) != 0) {
        return 0U;
    }
    if (state) *state = after;
    return total;
}

typedef struct {
    size_t length_value_offset;
    size_t length_digit_count;
    size_t witness_offset;
    size_t witness_length;
} h1_switch_marker_layout_t;

typedef enum {
    H1_MARKER_TRUNCATED_WITNESS = 0,
    H1_MARKER_TRAILING_BYTE,
    H1_MARKER_DECLARED_SMALLER,
    H1_MARKER_DECLARED_LARGER,
    H1_MARKER_NONCANONICAL_LENGTH,
    H1_MARKER_EMBEDDED_NUL,
    H1_MARKER_OVER_TOTAL_CAP
} h1_switch_marker_malformation_t;

static const unsigned char *h1_find_bytes(
    const unsigned char *data, size_t length,
    const unsigned char *needle, size_t needle_length) {
    if (!data || !needle || needle_length == 0U ||
        needle_length > length) {
        return NULL;
    }
    for (size_t i = 0U; i <= length - needle_length; i++) {
        if (memcmp(data + i, needle, needle_length) == 0) {
            return data + i;
        }
    }
    return NULL;
}

static int h1_switch_marker_layout(
    const unsigned char *marker, size_t marker_length,
    h1_switch_marker_layout_t *layout) {
    static const unsigned char field[] = "source_witness_length=";
    const unsigned char *value;
    const unsigned char *newline;
    uintmax_t parsed = 0U;
    size_t digit_count;

    if (!marker || marker_length == 0U || !layout) return -1;
    value = h1_find_bytes(
        marker, marker_length, field, sizeof(field) - 1U);
    if (!value) return -1;
    value += sizeof(field) - 1U;
    newline = memchr(
        value, '\n', marker_length - (size_t)(value - marker));
    if (!newline || newline == value) return -1;
    digit_count = (size_t)(newline - value);
    for (size_t i = 0U; i < digit_count; i++) {
        if (value[i] < (unsigned char)'0' ||
            value[i] > (unsigned char)'9' ||
            parsed > (UINTMAX_MAX - (uintmax_t)(value[i] - '0')) /
                         10U) {
            return -1;
        }
        parsed = parsed * 10U + (uintmax_t)(value[i] - '0');
    }
    if (parsed == 0U || parsed > SIZE_MAX ||
        (size_t)(marker + marker_length - (newline + 1U)) !=
            (size_t)parsed) {
        return -1;
    }
    layout->length_value_offset = (size_t)(value - marker);
    layout->length_digit_count = digit_count;
    layout->witness_offset = (size_t)(newline + 1U - marker);
    layout->witness_length = (size_t)parsed;
    return 0;
}

static bool h1_same_ctime(
    const struct stat *left, const struct stat *right) {
    if (!left || !right) return false;
#if defined(__APPLE__)
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool h1_same_file_state_without_ctime(
    const struct stat *left, const struct stat *right) {
    if (!left || !right ||
        !ts_same_identity(left, right) ||
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

static bool h1_same_file_state(
    const struct stat *left, const struct stat *right) {
    return h1_same_file_state_without_ctime(left, right) &&
           h1_same_ctime(left, right);
}

static int h1_force_ctime_only_drift(
    const char *path, const struct stat *expected,
    struct stat *current) {
    const struct timespec retry = {
        .tv_sec = 0, .tv_nsec = 1000000L
    };

    if (!path || !expected || !current) {
        errno = EINVAL;
        return -1;
    }
    for (size_t attempt = 0U; attempt < 128U; attempt++) {
        if (lstat(path, current) != 0 ||
            !h1_same_file_state_without_ctime(expected, current)) {
            errno = ESTALE;
            return -1;
        }
        if (!h1_same_ctime(expected, current)) return 0;
        if (chmod(path, 0400) != 0 ||
            chmod(path, 0600) != 0) {
            return -1;
        }
        (void)nanosleep(&retry, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int h1_change_token_byte_restore_mtime(
    const char *path, struct stat *before_out, struct stat *after_out,
    unsigned char *original_byte, unsigned char *mutated_byte,
    size_t *mutation_offset) {
    static const unsigned char token_field[] = "token=";
    const unsigned char *token;
    struct stat before;
    struct stat drift_before;
    struct stat after;
    struct timespec times[2];
    unsigned char *data = NULL;
    unsigned char original;
    unsigned char mutated;
    size_t offset;
    int fd = -1;
    int failure_errno = EIO;

    if (!path || !before_out || !after_out ||
        !original_byte || !mutated_byte || !mutation_offset) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        before.st_size <= 0 ||
        (uintmax_t)before.st_size > SIZE_MAX) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    data = malloc((size_t)before.st_size);
    if (!data ||
        pread(fd, data, (size_t)before.st_size, 0) != before.st_size) {
        failure_errno = data ? (errno ? errno : EIO) : ENOMEM;
        goto mutation_fail;
    }
    token = h1_find_bytes(
        data, (size_t)before.st_size,
        token_field, sizeof(token_field) - 1U);
    if (!token ||
        (size_t)(token - data) + sizeof(token_field) - 1U >=
            (size_t)before.st_size) {
        failure_errno = ESTALE;
        goto mutation_fail;
    }
    offset = (size_t)(token - data) + sizeof(token_field) - 1U;
    original = data[offset];
    if (original == '\n' || original == '\0') {
        failure_errno = ESTALE;
        goto mutation_fail;
    }
#if defined(__APPLE__)
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    mutated = original == (unsigned char)'A'
                  ? (unsigned char)'B'
                  : (unsigned char)'A';
    if (pwrite(fd, &mutated, 1, (off_t)offset) != 1 ||
        futimens(fd, times) != 0 || fsync(fd) != 0) {
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    fd = -1;
    if (lstat(path, &drift_before) != 0 ||
        !h1_same_file_state_without_ctime(&before, &drift_before) ||
        h1_force_ctime_only_drift(
            path, &drift_before, &after) != 0 ||
        !h1_same_file_state_without_ctime(&before, &after) ||
        h1_same_ctime(&before, &after)) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    *before_out = before;
    *after_out = after;
    *original_byte = original;
    *mutated_byte = mutated;
    *mutation_offset = offset;
    secure_zero_memory(data, (size_t)before.st_size);
    free(data);
    return 0;

mutation_fail:
    if (fd >= 0) close(fd);
    if (data) {
        secure_zero_memory(data, (size_t)before.st_size);
        free(data);
    }
    errno = failure_errno;
    return -1;
}

static int h1_change_ignored_whitespace_restore_mtime(
    const char *path, struct stat *before_out,
    struct stat *after_out) {
    static const char field[] = "description =";
    struct stat before;
    struct stat drift_before;
    struct stat after;
    struct timespec times[2];
    unsigned char *data = NULL;
    char *match;
    off_t offset;
    int fd = -1;
    int failure_errno = EIO;

    if (!path || !before_out || !after_out) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        before.st_size <= 0 ||
        (uintmax_t)before.st_size > SIZE_MAX - 1U) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    data = calloc((size_t)before.st_size + 1U, 1U);
    if (!data ||
        pread(fd, data, (size_t)before.st_size, 0) !=
            before.st_size) {
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    match = strstr((char *)data, field);
    if (!match || match[strlen("description")] != ' ') {
        failure_errno = ESTALE;
        goto mutation_fail;
    }
    offset = (off_t)(match - (char *)data) +
             (off_t)strlen("description");
#if defined(__APPLE__)
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (pwrite(fd, "\t", 1, offset) != 1 ||
        futimens(fd, times) != 0 || fsync(fd) != 0) {
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto mutation_fail;
    }
    fd = -1;
    if (lstat(path, &drift_before) != 0 ||
        !h1_same_file_state_without_ctime(&before, &drift_before) ||
        h1_force_ctime_only_drift(
            path, &drift_before, &after) != 0 ||
        !h1_same_file_state_without_ctime(&before, &after) ||
        h1_same_ctime(&before, &after)) {
        failure_errno = errno ? errno : ESTALE;
        goto mutation_fail;
    }
    *before_out = before;
    *after_out = after;
    secure_zero_memory(data, (size_t)before.st_size + 1U);
    free(data);
    return 0;

mutation_fail:
    if (fd >= 0) close(fd);
    if (data) {
        secure_zero_memory(data, (size_t)before.st_size + 1U);
        free(data);
    }
    errno = failure_errno;
    return -1;
}

static int mutate_switch_guard_marker_after_read(
    switch_guard_test_stage_t stage, int directory_fd) {
    switch_marker_mutation_t mutation;

    (void)directory_fd;
    if (stage == SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ) {
        g_switch_marker_outer_snapshot_calls++;
    }
    if (stage != g_switch_marker_mutation_stage ||
        g_switch_marker_mutation == SWITCH_MARKER_MUTATION_NONE) {
        return 0;
    }
    mutation = g_switch_marker_mutation;
    g_switch_marker_mutation = SWITCH_MARKER_MUTATION_NONE;
    g_switch_marker_mutation_calls++;
    if (lstat(
            g_switch_marker_mutation_path,
            &g_switch_marker_before_mutation) != 0) {
        g_switch_marker_mutation_rc = -1;
        return -1;
    }
    if (mutation == SWITCH_MARKER_MUTATION_CTIME_ONLY) {
        g_switch_marker_mutation_rc = h1_force_ctime_only_drift(
            g_switch_marker_mutation_path,
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation);
        return g_switch_marker_mutation_rc;
    }
    if (mutation ==
        SWITCH_MARKER_MUTATION_PARSE_VALID_TOKEN_RESTORED_MTIME) {
        g_switch_marker_mutation_rc =
            h1_change_token_byte_restore_mtime(
            g_switch_marker_mutation_path,
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation,
            &g_switch_marker_original_byte,
            &g_switch_marker_mutated_byte,
            &g_switch_marker_mutation_offset);
        return g_switch_marker_mutation_rc;
    }
    errno = EINVAL;
    g_switch_marker_mutation_rc = -1;
    return -1;
}

static int replace_switch_guard_directory_after_read(
    switch_guard_test_stage_t stage, int directory_fd) {
    (void)directory_fd;

    if (stage != SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF ||
        !g_switch_guard_replace_directory_after_read) {
        return 0;
    }
    g_switch_guard_replace_directory_after_read = false;
    g_switch_guard_directory_replacement_rc = -1;
    if (rename(
            g_switch_guard_directory_path,
            g_switch_guard_displaced_directory_path) != 0 ||
        mkdir(g_switch_guard_directory_path, 0700) != 0) {
        return -1;
    }
    g_switch_guard_directory_replacement_rc = 0;
    return 0;
}

static int churn_switch_guard_destination_directory(
    switch_guard_test_stage_t stage, int directory_fd) {
    static const char churn_name[] =
        ".gitswitch-test-destination-churn";
    struct timespec remaining = {0, 20 * 1000 * 1000};
    int churn_fd = -1;

    if (stage != SWITCH_GUARD_DESTINATION_AFTER_OPEN ||
        !g_switch_guard_churn_destination_directory) {
        return 0;
    }
    g_switch_guard_churn_destination_directory = false;
    g_switch_guard_destination_churn_calls++;
    g_switch_guard_destination_churn_rc = -1;
    if (fstat(
            directory_fd,
            &g_switch_guard_destination_before_churn) != 0) {
        return -1;
    }
    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno != EINTR) return -1;
    }
    churn_fd = openat(
        directory_fd, churn_name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600);
    if (churn_fd < 0) return -1;
    if (close(churn_fd) != 0) {
        churn_fd = -1;
        return -1;
    }
    churn_fd = -1;
    if (
        unlinkat(directory_fd, churn_name, 0) != 0 ||
        fstat(
            directory_fd,
            &g_switch_guard_destination_after_churn) != 0) {
        int saved_errno = errno ? errno : EIO;

        (void)unlinkat(directory_fd, churn_name, 0);
        errno = saved_errno;
        return -1;
    }
    g_switch_guard_destination_churn_rc = 0;
    errno = 0;
    return 0;
}

static int drift_switch_guard_source_after_stage_sync(
    switch_guard_test_stage_t stage, int directory_fd) {
    (void)directory_fd;

    if (!((stage == SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC &&
           g_switch_guard_drift_source_after_stage_sync) ||
          (stage == SWITCH_GUARD_RETAIN_AFTER_MARKER_SYNC &&
           g_switch_guard_drift_source_after_retain_sync))) {
        return 0;
    }
    g_switch_guard_drift_source_after_stage_sync = false;
    g_switch_guard_drift_source_after_retain_sync = false;
    g_switch_guard_source_drift_calls++;
    g_switch_guard_source_drift_rc = lstat(
        g_switch_guard_source_path,
        &g_switch_guard_source_before_drift);
    if (g_switch_guard_source_drift_rc == 0) {
        g_switch_guard_source_drift_rc = h1_force_ctime_only_drift(
            g_switch_guard_source_path,
            &g_switch_guard_source_before_drift,
            &g_switch_guard_source_after_drift);
    }
    return g_switch_guard_source_drift_rc;
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
        (size_t)snprintf(fixture->switch_fence,
                         sizeof(fixture->switch_fence),
                         "%s/.switch-incomplete", fixture->config_dir) >=
            sizeof(fixture->switch_fence) ||
        (size_t)snprintf(fixture->switch_stage,
                         sizeof(fixture->switch_stage),
                         "%s/.switch-transition", fixture->config_dir) >=
            sizeof(fixture->switch_stage) ||
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

static int h1_fixture_setup(cli_owner_fixture_t *fixture) {
    if (fixture_setup(fixture) != 0) return -1;
    return write_private(fixture->config, h1_accounts_config) == 0 &&
                   write_private(fixture->hint,
                                 "none\nactive=old\n") == 0 &&
                   write_private(fixture->gitconfig,
                                 h1_old_gitconfig) == 0
               ? 0
               : -1;
}

static int h1_guard_environment_begin(
    const cli_owner_fixture_t *fixture, h1_guard_case_t *guard_case) {
    static const char *const names[] = {
        "HOME", "XDG_RUNTIME_DIR", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM", "XDG_CONFIG_HOME", "GNUPGHOME"
    };

    if (!fixture || !guard_case) return -1;
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);

        guard_case->environment[i].name = names[i];
        guard_case->environment[i].present = value != NULL;
        if (value) {
            guard_case->environment[i].value = strdup(value);
            if (!guard_case->environment[i].value) return -1;
        }
        guard_case->environment[i].captured = true;
    }
    if (setenv("HOME", fixture->home, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        unsetenv("XDG_CONFIG_HOME") != 0 ||
        unsetenv("GNUPGHOME") != 0) {
        return -1;
    }
    return 0;
}

static void h1_guard_environment_end(h1_guard_case_t *guard_case) {
    if (!guard_case) return;
    for (size_t i = 0U;
         i < sizeof(guard_case->environment) /
                 sizeof(guard_case->environment[0]);
         i++) {
        h1_saved_env_t *saved = &guard_case->environment[i];

        if (!saved->captured) continue;
        if (saved->present && saved->value) {
            (void)setenv(saved->name, saved->value, 1);
        } else {
            (void)unsetenv(saved->name);
        }
        free(saved->value);
        saved->value = NULL;
        saved->captured = false;
    }
}

static int h1_guard_case_begin(
    const cli_owner_fixture_t *fixture, h1_guard_case_t *guard_case) {
    memset(guard_case, 0, sizeof(*guard_case));
    if (h1_guard_environment_begin(fixture, guard_case) != 0) return -1;
    guard_case->ctx = calloc(1U, sizeof(*guard_case->ctx));
    guard_case->destinations = calloc(
        CONFIG_SWITCH_DESTINATION_MAX,
        sizeof(*guard_case->destinations));
    if (!guard_case->ctx || !guard_case->destinations ||
        config_init(guard_case->ctx) != 0) {
        return -1;
    }
    guard_case->target =
        config_find_account_exact(guard_case->ctx, "work");
    if (!guard_case->target ||
        git_config_snapshot(GIT_SCOPE_GLOBAL) != 0 ||
        git_config_snapshot_export_destinations(
            guard_case->destinations,
            CONFIG_SWITCH_DESTINATION_MAX,
            &guard_case->destination_count) != 0) {
        return -1;
    }
    return 0;
}

static void h1_guard_case_end(h1_guard_case_t *guard_case) {
    if (!guard_case) return;
    (void)gitswitch_test_set_switch_guard_hook(NULL);
    (void)gitswitch_test_set_config_publish_hook(NULL);
    g_switch_guard_fail_stage = false;
    g_switch_guard_replace_before_initial_fstat = false;
    g_switch_guard_fail_clear = false;
    g_switch_guard_fail_normalize_sync = false;
    g_switch_guard_clear_failures_remaining = 0;
    g_switch_guard_hook_calls = 0;
    g_switch_guard_replacement_rc = -1;
    memset(&g_switch_guard_displaced_stage, 0,
           sizeof(g_switch_guard_displaced_stage));
    memset(&g_switch_guard_replacement_stage, 0,
           sizeof(g_switch_guard_replacement_stage));
    g_switch_guard_drift_source_after_stage_sync = false;
    g_switch_guard_drift_source_after_retain_sync = false;
    g_switch_guard_source_drift_calls = 0;
    g_switch_guard_source_drift_rc = -1;
    memset(g_switch_guard_source_path, 0,
           sizeof(g_switch_guard_source_path));
    memset(&g_switch_guard_source_before_drift, 0,
           sizeof(g_switch_guard_source_before_drift));
    memset(&g_switch_guard_source_after_drift, 0,
           sizeof(g_switch_guard_source_after_drift));
    g_switch_marker_mutation = SWITCH_MARKER_MUTATION_NONE;
    g_switch_marker_mutation_stage =
        SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ;
    g_switch_marker_mutation_calls = 0;
    g_switch_marker_outer_snapshot_calls = 0;
    g_switch_marker_mutation_rc = -1;
    memset(g_switch_marker_mutation_path, 0,
           sizeof(g_switch_marker_mutation_path));
    memset(&g_switch_marker_before_mutation, 0,
           sizeof(g_switch_marker_before_mutation));
    memset(&g_switch_marker_after_mutation, 0,
           sizeof(g_switch_marker_after_mutation));
    g_switch_marker_original_byte = 0U;
    g_switch_marker_mutated_byte = 0U;
    g_switch_marker_mutation_offset = 0U;
    g_switch_guard_replace_directory_after_read = false;
    g_switch_guard_directory_replacement_rc = -1;
    memset(g_switch_guard_directory_path, 0,
           sizeof(g_switch_guard_directory_path));
    memset(g_switch_guard_displaced_directory_path, 0,
           sizeof(g_switch_guard_displaced_directory_path));
    if (guard_case->guard) {
        config_switch_guard_abandon(&guard_case->guard);
    }
    git_config_commit();
    if (guard_case->destinations) {
        secure_zero_memory(
            guard_case->destinations,
            CONFIG_SWITCH_DESTINATION_MAX *
                sizeof(*guard_case->destinations));
        free(guard_case->destinations);
        guard_case->destinations = NULL;
    }
    if (guard_case->ctx) {
        secure_zero_memory(
            guard_case->ctx, sizeof(*guard_case->ctx));
        free(guard_case->ctx);
        guard_case->ctx = NULL;
    }
    h1_guard_environment_end(guard_case);
}

static int h1_numeric_name_fixture_setup(
    cli_owner_fixture_t *fixture) {
    if (fixture_setup(fixture) != 0) return -1;
    return write_private(
               fixture->config, h1_numeric_name_accounts_config) == 0 &&
                   write_private(fixture->hint,
                                 "none\nactive=old\n") == 0 &&
                   write_private(fixture->gitconfig,
                                 h1_old_gitconfig) == 0
               ? 0
               : -1;
}

static int h1_ssh_fixture_setup(
    cli_owner_fixture_t *fixture, char *key_path,
    size_t key_path_size) {
    char config_body[PATH_MAX + 2048];
    const char *keygen_argv[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
        "-f", key_path, NULL
    };
    run_opts_t opts;
    run_result_t result;
    int written;

    if (!fixture || !key_path || key_path_size == 0U ||
        h1_fixture_setup(fixture) != 0 ||
        (size_t)snprintf(
            key_path, key_path_size, "%s/work-key",
            fixture->root) >= key_path_size) {
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    if (run_argv(keygen_argv, &opts, &result) != 0) return -1;

    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"\n"
        "name = \"old\"\n"
        "email = \"old@example.test\"\n"
        "description = \"H1 prior identity\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "incarnation = \"2222222222222222222222222222222222222222222222222222222222222222\"\n"
        "name = \"work\"\n"
        "email = \"work@example.test\"\n"
        "description = \"H1 SSH recovery identity\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n",
        key_path);
    if (written < 0 || (size_t)written >= sizeof(config_body)) return -1;
    return write_private(fixture->config, config_body);
}

static int h5_fixture_setup(h5_fixture_t *fixture) {
    char config_body[PATH_MAX + 3072U];
    char gpg_path[PATH_MAX];
    char gpgconf_path[PATH_MAX];
    int written;

    if (!fixture) {
        errno = EINVAL;
        return -1;
    }
    memset(fixture, 0, sizeof(*fixture));
    if (h1_ssh_fixture_setup(
            &fixture->cli, fixture->key_path,
            sizeof(fixture->key_path)) != 0 ||
        (size_t)snprintf(
            fixture->source_home, sizeof(fixture->source_home),
            "%s/.gnupg", fixture->cli.home) >=
            sizeof(fixture->source_home) ||
        mkdir(fixture->source_home, 0700) != 0 ||
        !ts_mkdtemp_trusted(
            fixture->tools, sizeof(fixture->tools),
            "gitswitch-ar14-h5-tools") ||
        (size_t)snprintf(
            gpg_path, sizeof(gpg_path), "%s/gpg",
            fixture->tools) >= sizeof(gpg_path) ||
        (size_t)snprintf(
            gpgconf_path, sizeof(gpgconf_path), "%s/gpgconf",
            fixture->tools) >= sizeof(gpgconf_path) ||
        write_private(gpg_path, h5_fake_gpg) != 0 ||
        chmod(gpg_path, 0700) != 0 ||
        write_private(gpgconf_path, h5_fake_gpgconf) != 0 ||
        chmod(gpgconf_path, 0700) != 0 ||
        (size_t)snprintf(
            fixture->gpg_base, sizeof(fixture->gpg_base),
            "%s/gitswitch-gpg", fixture->cli.runtime) >=
            sizeof(fixture->gpg_base) ||
        (size_t)snprintf(
            fixture->gpg_home, sizeof(fixture->gpg_home),
            "%s/work", fixture->gpg_base) >=
            sizeof(fixture->gpg_home) ||
        (size_t)snprintf(
            fixture->gpg_current, sizeof(fixture->gpg_current),
            "%s/current", fixture->gpg_base) >=
            sizeof(fixture->gpg_current)) {
        return -1;
    }

    written = snprintf(
        config_body, sizeof(config_body),
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"\n"
        "name = \"old\"\n"
        "email = \"old@example.test\"\n"
        "description = \"H5 prior identity\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "incarnation = \"2222222222222222222222222222222222222222222222222222222222222222\"\n"
        "name = \"work\"\n"
        "email = \"work@example.test\"\n"
        "description = \"H5 durable runtime recovery identity\"\n"
        "preferred_scope = \"global\"\n"
        "ssh_key = \"%s\"\n"
        "gpg_key = \"" H5_GPG_FINGERPRINT "\"\n"
        "gpg_signing_enabled = true\n",
        fixture->key_path);
    if (written < 0 || (size_t)written >= sizeof(config_body)) return -1;
    return write_private(fixture->cli.config, config_body);
}

static int h5_set_child_environment(
    const h5_fixture_t *fixture, const char *output_name) {
    static const char fallback_path[] =
        "/usr/local/bin:/usr/bin:/bin";
    const char *inherited_path;
    char output[PATH_MAX];
    char *command_path;
    size_t tools_length;
    size_t inherited_length;
    size_t command_path_length;
    int result = -1;

    if (!fixture || !output_name || output_name[0] == '\0' ||
        (size_t)snprintf(
            output, sizeof(output), "%s/%s",
            fixture->cli.root, output_name) >= sizeof(output)) {
        errno = EINVAL;
        return -1;
    }
    inherited_path = getenv("PATH");
    if (!inherited_path || inherited_path[0] == '\0') {
        inherited_path = fallback_path;
    }
    tools_length = strlen(fixture->tools);
    inherited_length = strlen(inherited_path);
    if (inherited_length > SIZE_MAX - tools_length - 2U) {
        errno = EOVERFLOW;
        return -1;
    }
    command_path_length = tools_length + inherited_length + 2U;
    command_path = malloc(command_path_length);
    if (!command_path) return -1;
    if ((size_t)snprintf(
            command_path, command_path_length, "%s:%s",
            fixture->tools, inherited_path) >= command_path_length) {
        errno = EOVERFLOW;
        goto cleanup;
    }

    if (setenv("HOME", fixture->cli.home, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->cli.runtime, 1) != 0 ||
        setenv("GIT_CONFIG_GLOBAL", fixture->cli.gitconfig, 1) != 0 ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        setenv("GNUPGHOME", fixture->source_home, 1) != 0 ||
        setenv("PATH", command_path, 1) != 0 ||
        unsetenv("XDG_CONFIG_HOME") != 0 ||
        unsetenv("GPG_AGENT_INFO") != 0 ||
        unsetenv("SSH_AUTH_SOCK") != 0 ||
        unsetenv("SSH_AGENT_PID") != 0 ||
        unsetenv("GIT_CONFIG_COUNT") != 0 ||
        unsetenv("GIT_DIR") != 0 ||
        unsetenv("GIT_WORK_TREE") != 0 ||
        chdir(fixture->cli.root) != 0 ||
        redirect_output(output) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    free(command_path);
    return result;
}

static int h5_wait_child(pid_t child) {
    int status = 0;
    pid_t waited;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child ? status : -1;
}

static int h5_exit_after_durable_runtime_publish(int base_fd) {
    (void)base_fd;
    _exit(77);
}

static int run_h5_publish_stop_case(const h5_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char *argv[] = {
            program, no_color, force_global, account, NULL
        };

        if (h5_set_child_environment(
                fixture, "h5-publish-stop-output") != 0) {
            _exit(240);
        }
        (void)gpg_manager_set_retarget_commit_hook_fn(
            h5_exit_after_durable_runtime_publish);
        optind = 1;
        (void)gitswitch_cli_main(4, argv);
        _exit(241);
    }
    return h5_wait_child(child);
}

typedef enum {
    H5_CLI_RESUME_HINT = 0,
    H5_CLI_RESUME_CHECK,
    H5_CLI_RESUME
} h5_cli_case_t;

static int run_h5_fresh_cli_case(
    const h5_fixture_t *fixture, h5_cli_case_t cli_case,
    const char *output_name, int expected_exit) {
    pid_t child;

    if (fflush(NULL) != 0) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char resume_hint[] = "--resume-hint-probe";
        char resume_check[] = "--resume-check";
        char resume[] = "resume";
        char *hint_argv[] = { program, resume_hint, NULL };
        char *check_argv[] = { program, resume_check, NULL };
        char *resume_argv[] = { program, no_color, resume, NULL };
        char **argv;
        int argc;
        int rc;

        if (h5_set_child_environment(fixture, output_name) != 0) {
            _exit(245);
        }
        if (cli_case == H5_CLI_RESUME_HINT) {
            argv = hint_argv;
            argc = 2;
        } else if (cli_case == H5_CLI_RESUME_CHECK) {
            argv = check_argv;
            argc = 2;
        } else {
            argv = resume_argv;
            argc = 3;
        }
        optind = 1;
        rc = gitswitch_cli_main(argc, argv);
        if (rc != expected_exit) _exit(246);
        if (fflush(NULL) != 0) _exit(247);
        _exit(0);
    }
    return h5_wait_child(child);
}

static bool h5_symlink_targets(
    const char *link_path, const char *expected_target) {
    char target[PATH_MAX];
    ssize_t length;

    if (!link_path || !expected_target) return false;
    length = readlink(link_path, target, sizeof(target) - 1U);
    if (length <= 0 || (size_t)length >= sizeof(target)) return false;
    target[length] = '\0';
    return strcmp(target, expected_target) == 0;
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

static int run_h1_git_at(
    const cli_owner_fixture_t *fixture, const char *repository,
    const char *const argv[]) {
    static const char *const unset_env[] = {
        "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
        "GIT_DIR", "GIT_WORK_TREE", NULL
    };
    char home_env[PATH_MAX + sizeof("HOME=")];
    char global_env[PATH_MAX + sizeof("GIT_CONFIG_GLOBAL=")];
    const char *extra_env[4];
    run_opts_t opts;
    run_result_t result;
    int cwd_fd;
    int rc;

    if (!fixture || !repository || !argv ||
        (size_t)snprintf(
            home_env, sizeof(home_env), "HOME=%s",
            fixture->home) >= sizeof(home_env) ||
        (size_t)snprintf(
            global_env, sizeof(global_env), "GIT_CONFIG_GLOBAL=%s",
            fixture->gitconfig) >= sizeof(global_env)) {
        errno = EINVAL;
        return -1;
    }
    cwd_fd = open(
        repository,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (cwd_fd < 0) return -1;
    extra_env[0] = home_env;
    extra_env[1] = global_env;
    extra_env[2] = "GIT_CONFIG_NOSYSTEM=1";
    extra_env[3] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.cwd_fd = cwd_fd;
    opts.use_cwd_fd = true;
    opts.stderr_to_devnull = true;
    opts.extra_env = extra_env;
    opts.unset_env = unset_env;
    rc = run_argv(argv, &opts, &result);
    close(cwd_fd);
    return rc;
}

static int h1_repo_setup(
    const cli_owner_fixture_t *fixture, const char *repository,
    const char *label) {
    char local_name[128];
    char local_email[128];
    char worktree_name[128];
    char worktree_email[128];
    const char *init_argv[] = {
        "git", "init", "--quiet", NULL
    };
    const char *extension_argv[] = {
        "git", "config", "--local",
        "extensions.worktreeConfig", "true", NULL
    };
    const char *local_name_argv[] = {
        "git", "config", "--local", "user.name",
        local_name, NULL
    };
    const char *local_email_argv[] = {
        "git", "config", "--local", "user.email",
        local_email, NULL
    };
    const char *worktree_name_argv[] = {
        "git", "config", "--worktree", "user.name",
        worktree_name, NULL
    };
    const char *worktree_email_argv[] = {
        "git", "config", "--worktree", "user.email",
        worktree_email, NULL
    };

    if (!fixture || !repository || !label ||
        mkdir(repository, 0700) != 0 ||
        (size_t)snprintf(
            local_name, sizeof(local_name), "%s local", label) >=
            sizeof(local_name) ||
        (size_t)snprintf(
            local_email, sizeof(local_email), "%s-local@example.test",
            label) >= sizeof(local_email) ||
        (size_t)snprintf(
            worktree_name, sizeof(worktree_name), "%s worktree",
            label) >= sizeof(worktree_name) ||
        (size_t)snprintf(
            worktree_email, sizeof(worktree_email),
            "%s-worktree@example.test", label) >=
            sizeof(worktree_email)) {
        return -1;
    }
    return run_h1_git_at(fixture, repository, init_argv) == 0 &&
                   run_h1_git_at(
                       fixture, repository, extension_argv) == 0 &&
                   run_h1_git_at(
                       fixture, repository, local_name_argv) == 0 &&
                   run_h1_git_at(
                       fixture, repository, local_email_argv) == 0 &&
                   run_h1_git_at(
                       fixture, repository, worktree_name_argv) == 0 &&
                   run_h1_git_at(
                       fixture, repository, worktree_email_argv) == 0
               ? 0
               : -1;
}

static int h1_git_set(
    const cli_owner_fixture_t *fixture, const char *repository,
    const char *scope, const char *key, const char *value) {
    const char *argv[] = {
        "git", "config", scope, key, value, NULL
    };

    return run_h1_git_at(fixture, repository, argv);
}

static bool h1_git_identity_matches(
    const char *path, const char *name, const char *email) {
    char expected_name[256];
    char expected_email[256];
    char contents[4096];

    return path && name && email &&
           (size_t)snprintf(
               expected_name, sizeof(expected_name),
               "name = %s\n", name) < sizeof(expected_name) &&
           (size_t)snprintf(
               expected_email, sizeof(expected_email),
               "email = %s\n", email) < sizeof(expected_email) &&
           read_text(path, contents, sizeof(contents)) > 0 &&
           strstr(contents, expected_name) != NULL &&
           strstr(contents, expected_email) != NULL;
}

static bool h1_git_identity_is_absent(const char *path) {
    char contents[4096];
    struct stat state;

    if (!path) return false;
    if (lstat(path, &state) != 0) return errno == ENOENT;
    if (!S_ISREG(state.st_mode) || state.st_size < 0 ||
        (uintmax_t)state.st_size >= sizeof(contents)) {
        return false;
    }
    if (state.st_size == 0) return true;
    return read_text(path, contents, sizeof(contents)) ==
               (size_t)state.st_size &&
           strstr(contents, "name = ") == NULL &&
           strstr(contents, "email = ") == NULL;
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
    g_hook_commit_rc =
        accounts_switch_commit_result(ctx, &g_hook_commit_state);
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

static void capture_published_rollback(void) {
    g_publish_called++;
    g_publish_errno = errno;
    g_publish_error = *get_last_error();
}

static void inherited_handler(int signal_number) {
    (void)signal_number;
}

static void returning_signal_handler(int signal_number) {
    (void)signal_number;
    g_returning_signal_calls++;
}

static void queue_returning_signal_and_fail_dispatch(void) {
    (void)raise(SIGTERM);
    signals_test_fail_dispatch(SIGNALS_TEST_DISPATCH_MASK_RESTORE, EIO);
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
        g_hook_commit_state = ACCOUNTS_SWITCH_COMMIT_COMPLETE;
        g_hook_holder_rc = 0;
        g_hook_prepare_errno = 0;
        memset(&g_hook_prepare_error, 0, sizeof(g_hook_prepare_error));
        g_publish_called = 0;
        g_publish_errno = 0;
        memset(&g_publish_error, 0, sizeof(g_publish_error));
        g_hook_commit_error[0] = '\0';
        signals_test_fail_sigaction(SIGTERM,
                                    SIGNALS_TEST_SIGACTION_INSTALL, EPERM);
        signals_test_fail_sigaction(SIGINT,
                                    SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        (void)signals_test_set_guard_end_hook(fail_guard_restore_retry);
        (void)gitswitch_test_set_switch_prepare_failure_hook(
            clobber_prepare_failure);
        (void)gitswitch_test_set_switch_abort_hook(inspect_abort_owner);
        (void)gitswitch_test_set_switch_rollback_publish_hook(
            capture_published_rollback);

        optind = 1;
        first_rc = gitswitch_cli_main(4, switch_argv);
        if (first_rc == 0) _exit(102);
        if (g_hook_called != 1 || g_hook_prepare_errno != EPERM ||
            g_hook_prepare_error.code != ERR_SYSTEM_CALL ||
            g_hook_prepare_error.system_errno != EPERM ||
            strstr(g_hook_prepare_error.message,
                   "Failed to install guarded disposition") == NULL ||
            strstr(g_hook_prepare_error.details,
                   "[signal guard release]") == NULL ||
            g_publish_called != 1 || g_publish_errno != EPERM ||
            g_publish_error.code != ERR_SYSTEM_CALL ||
            g_publish_error.system_errno != EPERM ||
            strcmp(g_publish_error.message,
                   g_hook_prepare_error.message) != 0 ||
            g_hook_commit_rc != -1 ||
            g_hook_commit_state !=
                ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED ||
            strstr(g_hook_commit_error, "can only be retried") == NULL) {
            fprintf(stderr,
                    "AR-11 CLI owner hook mismatch: called=%d "
                    "prepare_errno=%d prepare_code=%d prepare_error=%s "
                    "publish_called=%d publish_errno=%d "
                    "publish_code=%d publish_error=%s "
                    "publish_details=%s commit_rc=%d commit_state=%d "
                    "commit_error=%s\n",
                    g_hook_called, g_hook_prepare_errno,
                    (int)g_hook_prepare_error.code,
                    g_hook_prepare_error.message[0]
                        ? g_hook_prepare_error.message
                        : "(empty)",
                    g_publish_called, g_publish_errno,
                    (int)g_publish_error.code,
                    g_publish_error.message[0]
                        ? g_publish_error.message
                        : "(empty)",
                    g_publish_error.details[0]
                        ? g_publish_error.details
                        : "(empty)",
                    g_hook_commit_rc,
                    (int)g_hook_commit_state,
                    g_hook_commit_error[0] ? g_hook_commit_error : "(empty)");
            _exit(103);
        }
        if (persist_first_abort &&
            strstr(g_publish_error.details,
                   "[account switch abort]") == NULL) {
            _exit(112);
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

static int run_cli_aggregate_case(const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char gitconfig[256];
        char hint[128];
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char version[] = "--version";
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        char *version_argv[] = { program, version, NULL };
        const char *settlement_entry;
        int first_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(120);
        }

        g_persistence_fault_fixture = *fixture;
        g_persistence_fault_armed = true;
        g_persistence_fault_mutation_rc = -1;
        g_publish_called = 0;
        g_publish_errno = 0;
        memset(&g_publish_error, 0, sizeof(g_publish_error));
        (void)config_set_io_fault_fn(diverge_persistence_rollback);
        (void)gitswitch_test_set_switch_rollback_publish_hook(
            capture_published_rollback);

        optind = 1;
        first_rc = gitswitch_cli_main(4, switch_argv);
        (void)config_set_io_fault_fn(NULL);
        if (first_rc == 0 || g_persistence_fault_mutation_rc != 0 ||
            g_publish_called != 1 || g_publish_errno != EIO ||
            g_publish_error.code != ERR_FILE_IO ||
            g_publish_error.system_errno != EIO ||
            strstr(g_publish_error.file, "config.c") == NULL ||
            g_publish_error.line <= 0 ||
            g_publish_error.function[0] == '\0') {
            _exit(121);
        }
        settlement_entry = strstr(g_publish_error.details,
                                  "[active-state settlement]");
        if (!settlement_entry ||
            strstr(g_publish_error.details,
                   "[account switch abort]") != NULL) {
            _exit(122);
        }
        if (gitswitch_test_context_allocations() != 1 ||
            gitswitch_test_context_allocation_total() != 1 ||
            !signals_guard_active() || !signals_rollback_active() ||
            !config_lock_available()) {
            _exit(123);
        }

        /* An informational second entry must not blindly abort an unresolved
         * retained switch and overwrite either concurrent artifact. */
        optind = 1;
        (void)gitswitch_cli_main(2, version_argv);
        if (read_text(fixture->hint, hint, sizeof(hint)) == 0 ||
            strcmp(hint, "none\nactive=later\n") != 0 ||
            read_text(fixture->gitconfig, gitconfig,
                      sizeof(gitconfig)) == 0 ||
            strcmp(gitconfig, concurrent_gitconfig) != 0) {
            _exit(125);
        }
        if (fflush(NULL) != 0) _exit(124);
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

static int run_h1_switch_case_at(
    const cli_owner_fixture_t *fixture, const char *working_directory,
    const char *selector, config_io_fault_fn fault,
    bool expect_context_released) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[MAX_EMAIL_LEN];
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        int switch_rc;

        if (safe_strncpy(account, selector, sizeof(account)) != 0 ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            (working_directory &&
             chdir(working_directory) != 0) ||
            redirect_output(fixture->output) != 0) {
            _exit(160);
        }

        g_h1_fault_fixture = *fixture;
        g_h1_fault_armed = true;
        g_h1_fault_calls = 0;
        g_h1_fault_mutation_rc = -1;
        g_publish_called = 0;
        g_publish_errno = 0;
        memset(&g_publish_error, 0, sizeof(g_publish_error));
        (void)config_set_io_fault_fn(fault);
        (void)gitswitch_test_set_switch_rollback_publish_hook(
            capture_published_rollback);

        optind = 1;
        switch_rc = gitswitch_cli_main(4, switch_argv);
        (void)config_set_io_fault_fn(NULL);
        (void)gitswitch_test_set_switch_rollback_publish_hook(NULL);
        if (switch_rc != EXIT_FAILURE ||
            g_h1_fault_calls != 1 ||
            g_h1_fault_mutation_rc != 0 ||
            (expect_context_released &&
             gitswitch_test_context_allocations() != 0)) {
            _exit(161);
        }
        if (fflush(NULL) != 0) _exit(162);
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

static int run_h1_switch_case(
    const cli_owner_fixture_t *fixture, const char *selector,
    config_io_fault_fn fault, bool expect_context_released) {
    return run_h1_switch_case_at(
        fixture, NULL, selector, fault, expect_context_released);
}

static int run_h1_resume_case_at(
    const cli_owner_fixture_t *fixture,
    const char *working_directory, const char *output_name) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char output[PATH_MAX];
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char resume[] = "resume";
        char *resume_argv[] = { program, no_color, resume, NULL };
        int resume_rc;

        if (!output_name || output_name[0] == '\0' ||
            (size_t)snprintf(output, sizeof(output), "%s/%s",
                             fixture->root, output_name) >=
                sizeof(output) ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            (working_directory &&
             chdir(working_directory) != 0) ||
            redirect_output(output) != 0) {
            _exit(170);
        }

        optind = 1;
        resume_rc = gitswitch_cli_main(3, resume_argv);
        if (resume_rc != EXIT_SUCCESS) _exit(171);
        if (fflush(NULL) != 0) _exit(172);
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

static int run_h1_resume_case(const cli_owner_fixture_t *fixture) {
    return run_h1_resume_case_at(
        fixture, NULL, "resume-output");
}

#if !defined(__FreeBSD__)
static int run_h1_normalize_sync_failure_case(
    const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char resume[] = "resume";
        char *resume_argv[] = { program, no_color, resume, NULL };
        int resume_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(173);
        }
        g_switch_guard_fail_normalize_sync = true;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        optind = 1;
        resume_rc = gitswitch_cli_main(3, resume_argv);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        if (resume_rc != EXIT_FAILURE ||
            g_switch_guard_hook_calls != 1 ||
            gitswitch_test_context_allocations() != 0) {
            _exit(174);
        }
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
#endif

static int run_h1_blocked_resume_case_at(
    const cli_owner_fixture_t *fixture,
    const char *working_directory, const char *output_name) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char output[PATH_MAX];
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char resume[] = "resume";
        char *resume_argv[] = { program, no_color, resume, NULL };
        int resume_rc;

        if (!output_name || output_name[0] == '\0' ||
            (size_t)snprintf(output, sizeof(output),
                             "%s/%s", fixture->root,
                             output_name) >= sizeof(output) ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            (working_directory &&
             chdir(working_directory) != 0) ||
            redirect_output(output) != 0) {
            _exit(175);
        }
        optind = 1;
        resume_rc = gitswitch_cli_main(3, resume_argv);
        if (resume_rc != EXIT_FAILURE ||
            gitswitch_test_context_allocations() != 0) {
            _exit(176);
        }
        if (fflush(NULL) != 0) _exit(177);
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

static int run_h1_blocked_resume_case(
    const cli_owner_fixture_t *fixture) {
    return run_h1_blocked_resume_case_at(
        fixture, NULL, "resume-output");
}

static int run_h1_ssh_runtime_case(
    const cli_owner_fixture_t *fixture, const char *key_path,
    bool reset_first, bool expected_live) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        account_t account;
        bool live = !expected_live;

        memset(&account, 0, sizeof(account));
        if (!fixture || !key_path ||
            setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            safe_strncpy(
                account.name, "work", sizeof(account.name)) != 0 ||
            safe_strncpy(
                account.email, "work@example.test",
                sizeof(account.email)) != 0 ||
            safe_strncpy(
                account.ssh_key_path, key_path,
                sizeof(account.ssh_key_path)) != 0) {
            _exit(230);
        }
        account.id = UINT32_C(2);
        account.ssh_enabled = true;
        if (reset_first && ssh_manager_reset("work") != 0) {
            _exit(231);
        }
        if (ssh_manager_current_is_live_for_account(
                &account, &live) != 0 ||
            live != expected_live) {
            _exit(232);
        }
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

static int run_h1_stage_install_failure_case(
    const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        int switch_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(180);
        }

        g_switch_guard_fail_stage = true;
        g_switch_guard_fail_clear = false;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        optind = 1;
        switch_rc = gitswitch_cli_main(4, switch_argv);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        if (switch_rc != EXIT_FAILURE ||
            g_switch_guard_hook_calls != 1 ||
            gitswitch_test_context_allocations() != 0) {
            _exit(181);
        }
        if (fflush(NULL) != 0) _exit(182);
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

static int run_h1_persistent_clear_failure_case(
    const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        int switch_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(185);
        }

        g_switch_guard_fail_stage = false;
        g_switch_guard_fail_clear = false;
        g_switch_guard_clear_failures_remaining = 2;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        optind = 1;
        switch_rc = gitswitch_cli_main(4, switch_argv);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        if (switch_rc != EXIT_FAILURE ||
            g_switch_guard_hook_calls != 2 ||
            g_switch_guard_clear_failures_remaining != 0 ||
            gitswitch_test_context_allocations() != 0) {
            _exit(186);
        }
        if (fflush(NULL) != 0) _exit(187);
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

static int run_h1_guard_clear_retry_case(
    const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        static const char foreign_marker[] =
            "foreign-switch-marker\n";
        gitswitch_ctx_t *ctx = NULL;
        account_t *target;
        publication_record_t *destinations = NULL;
        size_t destination_count = 0U;
        config_switch_guard_t *guard = NULL;
        char observed[64];
        struct stat st;
        int directory_fd = -1;
        int result = 190;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0) {
            _exit(result);
        }
        ctx = calloc(1U, sizeof(*ctx));
        destinations = calloc(
            CONFIG_SWITCH_DESTINATION_MAX,
            sizeof(*destinations));
        if (!ctx || !destinations || config_init(ctx) != 0) goto done;
        target = config_find_account_exact(ctx, "work");
        if (!target ||
            git_config_snapshot(GIT_SCOPE_GLOBAL) != 0 ||
            git_config_snapshot_export_destinations(
                destinations, CONFIG_SWITCH_DESTINATION_MAX,
                &destination_count) != 0 ||
            config_switch_guard_install_or_adopt(
                ctx, target, GIT_SCOPE_GLOBAL,
                destinations, destination_count, &guard) != 0) {
            goto done;
        }

        g_switch_guard_fail_stage = false;
        g_switch_guard_fail_clear = true;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        if (config_switch_guard_clear(&guard) == 0 ||
            !guard || g_switch_guard_hook_calls != 1 ||
            (lstat(fixture->switch_fence, &st) == 0 ||
             errno != ENOENT)) {
            result = 191;
            goto done;
        }

        /* A same-UID foreign replacement cannot inherit the unlinked
         * generation's retry authority. The retry must reject and preserve
         * it byte-for-byte. */
        if (write_private(
                fixture->switch_fence, foreign_marker) != 0 ||
            config_switch_guard_clear(&guard) == 0 ||
            !guard ||
            read_text(fixture->switch_fence, observed,
                      sizeof(observed)) == 0 ||
            strcmp(observed, foreign_marker) != 0) {
            result = 192;
            goto done;
        }
        if (unlink(fixture->switch_fence) != 0) {
            result = 193;
            goto done;
        }
        directory_fd = open(
            fixture->config_dir,
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (directory_fd < 0 || fsync(directory_fd) != 0 ||
            close(directory_fd) != 0) {
            directory_fd = -1;
            result = 194;
            goto done;
        }
        directory_fd = -1;
        if (config_switch_guard_clear(&guard) != 0 || guard) {
            result = 195;
            goto done;
        }

        /* A second complete ownership cycle proves both the process owner and
         * lifecycle lock were released by the successful retry. */
        if (config_switch_guard_install_or_adopt(
                ctx, target, GIT_SCOPE_GLOBAL,
                destinations, destination_count, &guard) != 0 ||
            config_switch_guard_clear(&guard) != 0 || guard) {
            result = 196;
            goto done;
        }
        result = 0;

done:
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        if (guard) config_switch_guard_abandon(&guard);
        if (directory_fd >= 0) close(directory_fd);
        git_config_commit();
        if (destinations) {
            secure_zero_memory(
                destinations,
                CONFIG_SWITCH_DESTINATION_MAX *
                    sizeof(*destinations));
            free(destinations);
        }
        if (ctx) {
            secure_zero_memory(ctx, sizeof(*ctx));
            free(ctx);
        }
        _exit(result);
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

static int run_h1_create_guard_marker_at(
    const cli_owner_fixture_t *fixture, const char *working_directory) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        gitswitch_ctx_t *ctx = NULL;
        account_t *target;
        publication_record_t *destinations = NULL;
        size_t destination_count = 0U;
        config_switch_guard_t *guard = NULL;
        int result = 200;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            (working_directory &&
             chdir(working_directory) != 0)) {
            _exit(result);
        }
        ctx = calloc(1U, sizeof(*ctx));
        destinations = calloc(
            CONFIG_SWITCH_DESTINATION_MAX,
            sizeof(*destinations));
        if (!ctx || !destinations || config_init(ctx) != 0) goto done;
        target = config_find_account_exact(ctx, "work");
        if (!target ||
            git_config_snapshot(GIT_SCOPE_GLOBAL) != 0 ||
            git_config_snapshot_export_destinations(
                destinations, CONFIG_SWITCH_DESTINATION_MAX,
                &destination_count) != 0 ||
            config_switch_guard_install_or_adopt(
                ctx, target, GIT_SCOPE_GLOBAL,
                destinations, destination_count, &guard) != 0) {
            goto done;
        }
        config_switch_guard_abandon(&guard);
        result = 0;

done:
        if (guard) config_switch_guard_abandon(&guard);
        git_config_commit();
        if (destinations) {
            secure_zero_memory(
                destinations,
                CONFIG_SWITCH_DESTINATION_MAX *
                    sizeof(*destinations));
            free(destinations);
        }
        if (ctx) {
            secure_zero_memory(ctx, sizeof(*ctx));
            free(ctx);
        }
        _exit(result);
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

static int run_h1_create_guard_marker(
    const cli_owner_fixture_t *fixture) {
    return run_h1_create_guard_marker_at(fixture, NULL);
}

static int run_h1_plain_switch_case(
    const cli_owner_fixture_t *fixture) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char force_global[] = "-g";
        char account[] = "work";
        char *switch_argv[] = {
            program, no_color, force_global, account, NULL
        };
        int switch_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(210);
        }
        optind = 1;
        switch_rc = gitswitch_cli_main(4, switch_argv);
        if (switch_rc != EXIT_SUCCESS ||
            gitswitch_test_context_allocations() != 0) {
            _exit(211);
        }
        if (fflush(NULL) != 0) _exit(212);
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

static bool h1_work_publication_is_live(
    const cli_owner_fixture_t *fixture) {
    const publication_record_t *record = NULL;
    const publication_record_t *live_generation = NULL;
    const publication_record_t *generations[
        PUBLICATION_LEDGER_MAX_RECORDS];
    publication_ledger_t ledger;
    publication_lookup_status_t lookup;
    bool live = false;

    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(fixture->config, &ledger) != 0 ||
        ledger.count == 0 ||
        ledger.count > PUBLICATION_LEDGER_MAX_RECORDS) {
        goto cleanup;
    }
    for (size_t i = 0; i < ledger.count; i++) {
        generations[i] = &ledger.records[i];
    }
    lookup = publication_ledger_find(
        &ledger, UINT32_C(2), H1_WORK_INCARNATION,
        PUBLICATION_SCOPE_GLOBAL, fixture->gitconfig, "", &record);
    live = lookup == PUBLICATION_LOOKUP_FOUND && record &&
           record->state == PUBLICATION_STATE_PUBLISHED &&
           publication_record_verify_live_destination(
               record, generations, ledger.count, &live_generation) == 0 &&
           live_generation != NULL;

cleanup:
    publication_ledger_clear(&ledger);
    return live;
}

static bool h1_numeric_name_publication_is_live(
    const cli_owner_fixture_t *fixture) {
    const publication_record_t *record = NULL;
    const publication_record_t *live_generation = NULL;
    const publication_record_t *generations[
        PUBLICATION_LEDGER_MAX_RECORDS];
    publication_ledger_t ledger;
    publication_lookup_status_t lookup;
    bool live = false;

    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(fixture->config, &ledger) != 0 ||
        ledger.count == 0 ||
        ledger.count > PUBLICATION_LEDGER_MAX_RECORDS) {
        goto cleanup;
    }
    for (size_t i = 0; i < ledger.count; i++) {
        generations[i] = &ledger.records[i];
    }
    lookup = publication_ledger_find(
        &ledger, UINT32_C(8), H1_NUMERIC_NAME_INCARNATION,
        PUBLICATION_SCOPE_GLOBAL, fixture->gitconfig, "", &record);
    live = lookup == PUBLICATION_LOOKUP_FOUND && record &&
           record->state == PUBLICATION_STATE_PUBLISHED &&
           publication_record_verify_live_destination(
               record, generations, ledger.count, &live_generation) == 0 &&
           live_generation != NULL;

cleanup:
    publication_ledger_clear(&ledger);
    return live;
}

static bool h1_has_published_work_record(
    const cli_owner_fixture_t *fixture) {
    publication_ledger_t ledger;
    bool found = false;

    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(fixture->config, &ledger) != 0) {
        publication_ledger_clear(&ledger);
        return true;
    }
    for (size_t i = 0; i < ledger.count; i++) {
        if (ledger.records[i].account_id == UINT32_C(2) &&
            strcmp(ledger.records[i].account_incarnation,
                   H1_WORK_INCARNATION) == 0 &&
            ledger.records[i].state == PUBLICATION_STATE_PUBLISHED) {
            found = true;
            break;
        }
    }
    publication_ledger_clear(&ledger);
    return found;
}

static int run_signal_marker_case(const cli_owner_fixture_t *fixture,
                                  signal_marker_case_t marker_case) {
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) {
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
        int third_rc;

        if (setenv("HOME", fixture->home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", fixture->gitconfig, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
            unsetenv("XDG_CONFIG_HOME") != 0 ||
            unsetenv("GNUPGHOME") != 0 ||
            redirect_output(fixture->output) != 0) {
            _exit(140);
        }

        g_returning_signal_calls = 0;
        if (signals_reset_inherited_transaction_state() != 0) {
            _exit(141);
        }
        if (marker_case == SIGNAL_MARKER_GUARD_RESTORE) {
            signals_test_fail_sigaction(
                SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EIO);
        } else {
            struct sigaction action;

            memset(&action, 0, sizeof(action));
            action.sa_handler = returning_signal_handler;
            if (sigemptyset(&action.sa_mask) != 0 ||
                sigaction(SIGTERM, &action, NULL) != 0) {
                _exit(141);
            }
            (void)signals_test_set_guard_end_hook(
                queue_returning_signal_and_fail_dispatch);
        }

        optind = 1;
        first_rc = gitswitch_cli_main(4, switch_argv);
        if (first_rc != EXIT_FAILURE ||
            gitswitch_test_context_allocations() != 0 ||
            signals_rollback_active()) {
            _exit(142);
        }
        if (marker_case == SIGNAL_MARKER_GUARD_RESTORE) {
            if (!signals_guard_active() || g_returning_signal_calls != 0) {
                _exit(143);
            }
            signals_test_fail_sigaction(
                SIGTERM, SIGNALS_TEST_SIGACTION_RESTORE, EAGAIN);
        } else {
            if (signals_guard_active() || g_returning_signal_calls != 1) {
                _exit(144);
            }
            signals_test_fail_dispatch(
                SIGNALS_TEST_DISPATCH_MASK_RESTORE, EAGAIN);
        }

        /* The next informational entry must settle the context-free signal
         * obligation before parsing --version. A repeated injected failure
         * proves it cannot silently bypass the retained marker. */
        optind = 1;
        second_rc = gitswitch_cli_main(2, version_argv);
        if (second_rc != EXIT_FAILURE ||
            gitswitch_test_context_allocations() != 0 ||
            g_returning_signal_calls !=
                (marker_case == SIGNAL_MARKER_DISPATCH_RESTORE ? 1 : 0)) {
            _exit(145);
        }

        optind = 1;
        third_rc = gitswitch_cli_main(2, version_argv);
        if (third_rc != EXIT_SUCCESS || signals_guard_active() ||
            signals_rollback_active() ||
            gitswitch_test_context_allocations() != 0 ||
            gitswitch_test_context_allocation_total() != 1 ||
            g_returning_signal_calls !=
                (marker_case == SIGNAL_MARKER_DISPATCH_RESTORE ? 1 : 0)) {
            _exit(146);
        }
        if (fflush(NULL) != 0) _exit(147);
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

#if defined(__FreeBSD__)
static size_t config_dir_count_prefix(
    const char *path, const char *prefix) {
    DIR *directory = opendir(path);
    struct dirent *entry;
    size_t count = 0U;

    if (!directory) return SIZE_MAX;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(
                entry->d_name, prefix,
                strlen(prefix)) == 0) {
            count++;
        }
    }
    closedir(directory);
    return count;
}
#endif

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
    CHECK(strstr(output, "[signal guard release]") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);
    if (persistent) {
        CHECK(strstr(output, "[account switch abort]") != NULL);
        CHECK(strstr(output, "application context was retained") != NULL);
        CHECK(strstr(output, GITSWITCH_VERSION) != NULL);
    } else {
        CHECK(strstr(output, "application context was retained") == NULL);
    }
}

static void check_aggregate_artifacts(const cli_owner_fixture_t *fixture) {
    char config[512];
    char gitconfig[256];
    char hint[128];
    char output[16384];
    int status = run_cli_aggregate_case(fixture);

    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture->config, config, sizeof(config)) > 0);
    CHECK_STR_EQ(config, expected_accounts_config);
    CHECK(read_text(fixture->gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "Concurrent Name") != NULL);
    CHECK(strstr(gitconfig, "work@example.test") != NULL);
    CHECK(strstr(gitconfig, "before@example.test") == NULL);
    CHECK(read_text(fixture->hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=later\n");
    errno = 0;
    CHECK(lstat(fixture->ssh_config, &(struct stat){0}) != 0 &&
          errno == ENOENT);
    CHECK(!config_dir_has_temporary(fixture->config_dir));
    CHECK(read_text(fixture->output, output, sizeof(output)) > 0);
    if (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "AR-11 CLI aggregate captured output:\n%s\n",
                output);
    }
    CHECK(strstr(output, "Cannot durably commit resume hint") != NULL);
    CHECK(strstr(output, "[active-state settlement]") != NULL);
    CHECK(strstr(output, "[account switch abort]") == NULL);
    CHECK(strstr(output, "application context was retained") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);
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

TEST(persistence_and_abort_failures_keep_first_context_and_causal_order) {
    cli_owner_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    check_aggregate_artifacts(&fixture);
}

TEST(restart_resume_converges_after_active_state_restore_conflict) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    bool old_coherent;
    bool work_coherent;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);

    status = run_h1_switch_case(
        &fixture, "work", replace_h1_postimage_and_fail_sync, true);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Account switch committed") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);

    /* Fork from the pristine test parent after the switch child has exited.
     * No process-global pending-switch or retained-CLI context can cross this
     * boundary, so this models the recovery information available after a
     * real process restart. */
    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    old_coherent =
        strncmp(hint, "none\nactive=old\n",
                strlen("none\nactive=old\n")) == 0 &&
        strstr(gitconfig, "name = old\n") != NULL &&
        strstr(gitconfig, "email = old@example.test\n") != NULL &&
        strstr(gitconfig, "work@example.test") == NULL;
    work_coherent =
        strncmp(hint, "none\nactive=work\n",
                strlen("none\nactive=work\n")) == 0 &&
        strstr(gitconfig, "name = work\n") != NULL &&
        strstr(gitconfig, "email = work@example.test\n") != NULL &&
        strstr(gitconfig, "old@example.test") == NULL;
    if (!old_coherent && !work_coherent) {
        fprintf(stderr,
                "AR-14 H1 restart left mixed identity:\n"
                "active-state prefix:\n%.128s\n"
                "global Git config:\n%.512s\n",
                hint, gitconfig);
    }
    CHECK(old_coherent || work_coherent);
    if (old_coherent) {
        CHECK(!h1_has_published_work_record(&fixture));
    }
    if (work_coherent) {
        CHECK(h1_work_publication_is_live(&fixture));
    }
    CHECK(!config_dir_has_temporary(fixture.config_dir));
}

/* AR-17: reproduction of a field failure. An interrupted switch at login
 * (cwd = $HOME, not a repository) records a global-scope fence with ONE
 * destination. The user's later `gitswitch resume` runs from inside some git
 * repository -- any repository -- and git_config_snapshot then exports TWO
 * destinations, because local_also is set purely by git_is_repository().
 * config_switch_same_destinations_authority refuses on the count mismatch
 * with "Switch recovery destinations no longer name the recorded Git
 * namespaces", so recovery depends on the ambient cwd of the retry: the one
 * command allowed to adopt the marker fails from exactly the place a
 * developer usually is. Adoption must reconcile against the RECORDED
 * destination set, not require the ambient recomputation to match it. */
TEST(switch_fence_recorded_outside_repo_adopts_from_inside_repo) {
    cli_owner_fixture_t fixture;
    char repo[PATH_MAX];
    char resume_output[PATH_MAX];
    char output[16384];
    char hint[256];
    struct stat fence;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);

    /* Interrupted switch with a NON-repository cwd: fence records exactly
     * the global destination. */
    status = run_h1_switch_case_at(
        &fixture, fixture.root, "work",
        replace_h1_with_third_image_and_fail_sync, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &fence), 0);

    /* The ambient repository the user happens to be in at retry time. */
    CHECK((size_t)snprintf(repo, sizeof(repo), "%s/ambient-repo",
                           fixture.root) < sizeof(repo));
    CHECK_EQ_INT(mkdir(repo, 0700), 0);
    {
        const char *init_argv[] = { "git", "init", "--quiet", NULL };
        CHECK_EQ_INT(run_h1_git_at(&fixture, repo, init_argv), 0);
    }

    /* Explicit resume from inside that repository must adopt the fence. */
    status = run_h1_resume_case_at(&fixture, repo, "resume-in-repo");
    if ((size_t)snprintf(resume_output, sizeof(resume_output),
                         "%s/resume-in-repo", fixture.root) <
            sizeof(resume_output) &&
        read_text(resume_output, output, sizeof(output)) > 0 &&
        (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "in-repo fenced resume output:\n%s\n", output);
    }
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 && errno == ENOENT);
}

/* AR-17 complement: a fence recorded INSIDE a repository names that
 * repository's local (and worktree) destinations. A resume elsewhere cannot
 * reach them, so adoption must stay fail-closed -- but the refusal must name
 * the recorded repository and the exact retry, not the old generic text. A
 * follow-up resume from inside the repository must then adopt the complete
 * recorded set. */
TEST(switch_fence_recorded_inside_repo_directs_resume_to_that_repo) {
    cli_owner_fixture_t fixture;
    char repo[PATH_MAX];
    char resume_output[PATH_MAX];
    char output[16384];
    struct stat fence;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK((size_t)snprintf(repo, sizeof(repo), "%s/origin-repo",
                           fixture.root) < sizeof(repo));
    CHECK_EQ_INT(h1_repo_setup(&fixture, repo, "origin"), 0);

    status = run_h1_switch_case_at(
        &fixture, repo, "work",
        replace_h1_with_third_image_and_fail_sync, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &fence), 0);

    /* Resume from a non-repository cwd: refuse, and say where to go. */
    status = run_h1_resume_case_at(&fixture, fixture.root,
                                   "resume-outside-repo");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK(WEXITSTATUS(status) != 0);
    }
    CHECK((size_t)snprintf(resume_output, sizeof(resume_output),
                           "%s/resume-outside-repo", fixture.root) <
          sizeof(resume_output));
    CHECK(read_text(resume_output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "rerun `gitswitch resume` from inside that "
                         "repository") != NULL);
    CHECK(strstr(output, "origin-repo") != NULL);
    CHECK_EQ_INT(lstat(fixture.switch_fence, &fence), 0);

    /* From inside the recorded repository the complete set adopts. */
    status = run_h1_resume_case_at(&fixture, repo, "resume-inside-repo");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 && errno == ENOENT);
}

TEST(unresolved_switch_fence_survives_restart_and_resume_reconciles_forward) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    char resume_output[PATH_MAX];
    struct stat fence;
    int fence_rc;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);

    status = run_h1_switch_case(
        &fixture, "work", replace_h1_with_third_image_and_fail_sync,
        false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Switched to:") == NULL);
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=later\n");
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, concurrent_gitconfig);

    memset(&fence, 0, sizeof(fence));
    fence_rc = lstat(fixture.switch_fence, &fence);
    CHECK_EQ_INT(fence_rc, 0);
    if (fence_rc == 0) {
        CHECK(S_ISREG(fence.st_mode));
        CHECK_EQ_INT(fence.st_mode & 0777, 0600);
        CHECK_EQ_INT(fence.st_uid, geteuid());
        CHECK(fence.st_size > 0);
    }

    /* The switch process is gone: only the durable fence can carry exact
     * recovery ownership into this fresh explicit resume process. */
    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if ((size_t)snprintf(resume_output, sizeof(resume_output),
                         "%s/resume-output", fixture.root) <
            sizeof(resume_output) &&
        read_text(resume_output, output, sizeof(output)) > 0 &&
        (status < 0 || !WIFEXITED(status) ||
         WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "AR-14 H1 fenced resume output:\n%s\n", output);
    }

    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(strstr(gitconfig, "old@example.test") == NULL);
    CHECK(strstr(gitconfig, "Concurrent Name") == NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 && errno == ENOENT);
    CHECK(!config_dir_has_temporary(fixture.config_dir));
}

TEST(restart_resume_reconstructs_enabled_ssh_identity) {
    cli_owner_fixture_t fixture;
    char key_path[PATH_MAX] = "";
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    char resume_output[PATH_MAX];
    struct stat fence;
    int status;

    if (!command_exists("ssh-agent") ||
        !command_exists("ssh-add") ||
        !command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "OpenSSH agent tools are unavailable");
    }
    CHECK_EQ_INT(
        h1_ssh_fixture_setup(
            &fixture, key_path, sizeof(key_path)),
        0);

    status = run_h1_switch_case_at(
        &fixture, fixture.root, "work",
        replace_h1_with_third_image_and_fail_sync, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &fence), 0);

    /* Simulate boot-volatile SSH runtime loss after the interrupted switch.
     * The fresh resume process must reconstruct the exact target key from the
     * durable switch owner; a Git-only replay would fail this witness. */
    status = run_h1_ssh_runtime_case(
        &fixture, key_path, true, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    status = run_h1_resume_case_at(
        &fixture, fixture.root, "resume-ssh-output");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if ((size_t)snprintf(
            resume_output, sizeof(resume_output),
            "%s/resume-ssh-output", fixture.root) <
            sizeof(resume_output) &&
        read_text(resume_output, output, sizeof(output)) > 0 &&
        (status < 0 || !WIFEXITED(status) ||
         WEXITSTATUS(status) != 0)) {
        fprintf(stderr,
                "AR-14 H1 SSH fenced resume output:\n%s\n",
                output);
    }

    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "ssh\nactive=work\n",
                  strlen("ssh\nactive=work\n")) == 0);
    CHECK(read_text(
              fixture.gitconfig, gitconfig,
              sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(
              gitconfig,
              "email = work@example.test\n") != NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 &&
          errno == ENOENT);

    status = run_h1_ssh_runtime_case(
        &fixture, key_path, false, true);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    /* Do not leak the real test agent into the developer or CI host. */
    status = run_h1_ssh_runtime_case(
        &fixture, key_path, true, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(durable_gpg_publication_stop_is_reconciled_by_fresh_resume) {
    h5_fixture_t fixture;
    char gitconfig[8192];
    char hint[512];
    char output[16384];
    char output_path[PATH_MAX];
    char expected_program[PATH_MAX + 32U];
    struct stat state;
    int setup_rc;
    int status;

    if (!command_exists("ssh-agent") ||
        !command_exists("ssh-add") ||
        !command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "OpenSSH agent tools are unavailable");
    }
    setup_rc = h5_fixture_setup(&fixture);
    CHECK_EQ_INT(setup_rc, 0);
    if (setup_rc != 0) return;

    /* Stop at the manager's existing post-sync callback: `current` is now a
     * durable target publication, while the later Git and active-state phases
     * have not run. A normal return here would make the fixture invalid. */
    status = run_h5_publish_stop_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 77);
    }
    CHECK_EQ_INT(lstat(fixture.cli.switch_fence, &state), 0);
    CHECK(S_ISREG(state.st_mode));
    CHECK_EQ_INT(state.st_mode & 0777, 0600);
    CHECK_EQ_INT(state.st_uid, geteuid());
    CHECK(state.st_size > 0);
    CHECK(h5_symlink_targets(
        fixture.gpg_current, fixture.gpg_home));
    CHECK_EQ_INT(stat(fixture.gpg_home, &state), 0);
    CHECK(S_ISDIR(state.st_mode));

    /* The stop point is observably before both later durable identity phases. */
    CHECK(read_text(
              fixture.cli.gitconfig, gitconfig,
              sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, h1_old_gitconfig);
    CHECK(read_text(fixture.cli.hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=old\n");

    /* The durable owner, rather than the stale active-state token, drives the
     * shell probe. Without that owner the old core would report "none" and
     * accept readiness for the still-old persisted account. */
    status = run_h5_fresh_cli_case(
        &fixture, H5_CLI_RESUME_HINT,
        "h5-resume-hint-output", EXIT_SUCCESS);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK((size_t)snprintf(
              output_path, sizeof(output_path), "%s/%s",
              fixture.cli.root, "h5-resume-hint-output") <
          sizeof(output_path));
    {
        static const char expected_probe[] = "ssh gpg\n";
        size_t output_length =
            read_text(output_path, output, sizeof(output));

        CHECK(output_length >= sizeof(expected_probe) - 1U);
        if (output_length >= sizeof(expected_probe) - 1U) {
            CHECK(memcmp(
                      output + output_length -
                          (sizeof(expected_probe) - 1U),
                      expected_probe,
                      sizeof(expected_probe) - 1U) == 0);
        }
    }

    status = run_h5_fresh_cli_case(
        &fixture, H5_CLI_RESUME_CHECK,
        "h5-blocked-readiness-output", EXIT_FAILURE);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    /* A hook-free process has no in-memory transaction. It must adopt the
     * exact local marker and converge the complete fixture forward. */
    status = run_h5_fresh_cli_case(
        &fixture, H5_CLI_RESUME,
        "h5-fresh-resume-output", EXIT_SUCCESS);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if (status < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        CHECK((size_t)snprintf(
                  output_path, sizeof(output_path), "%s/%s",
                  fixture.cli.root, "h5-fresh-resume-output") <
              sizeof(output_path));
        if (read_text(output_path, output, sizeof(output)) > 0) {
            fprintf(stderr,
                    "AR-14 H5 fresh resume output:\n%s\n", output);
        }
    }

    CHECK(read_text(fixture.cli.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(
              hint, "ssh gpg\nactive=work\n",
              strlen("ssh gpg\nactive=work\n")) == 0);
    CHECK(read_text(
              fixture.cli.gitconfig, gitconfig,
              sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(strstr(gitconfig, "old@example.test") == NULL);
    CHECK(strstr(
              gitconfig,
              "signingkey = " H5_GPG_FINGERPRINT "\n") != NULL);
    CHECK(strstr(gitconfig, "gpgsign = true\n") != NULL);
    CHECK(strstr(gitconfig, "format = openpgp\n") != NULL);
    CHECK((size_t)snprintf(
              expected_program, sizeof(expected_program),
              "program = %s/gpg\n", fixture.tools) <
          sizeof(expected_program));
    CHECK(strstr(gitconfig, expected_program) != NULL);
    CHECK(h5_symlink_targets(
        fixture.gpg_current, fixture.gpg_home));
    errno = 0;
    CHECK(lstat(fixture.cli.switch_fence, &state) != 0 &&
          errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.cli.switch_stage, &state) != 0 &&
          errno == ENOENT);

    /* The final readiness success is an end-to-end witness for both runtime
     * managers; check the SSH manager directly as a clearer local diagnostic. */
    status = run_h5_fresh_cli_case(
        &fixture, H5_CLI_RESUME_CHECK,
        "h5-ready-output", EXIT_SUCCESS);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    status = run_h1_ssh_runtime_case(
        &fixture.cli, fixture.key_path, false, true);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    /* Do not leave the fixture's local agent behind after the suite exits. */
    status = run_h1_ssh_runtime_case(
        &fixture.cli, fixture.key_path, true, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(finalization_git_replacement_retains_fence_until_fresh_resume) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    char resume_output[PATH_MAX];
    struct stat fence;
    int fence_rc;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);

    status = run_h1_switch_case(
        &fixture, "work",
        replace_h1_git_during_state_commit_and_allow_sync, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Switched to:") == NULL);

    /* The active-state commit itself succeeded, while the independently
     * replaced Git destination no longer publishes the target identity. */
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, concurrent_gitconfig);

    memset(&fence, 0, sizeof(fence));
    fence_rc = lstat(fixture.switch_fence, &fence);
    CHECK_EQ_INT(fence_rc, 0);
    if (fence_rc == 0) {
        CHECK(S_ISREG(fence.st_mode));
        CHECK_EQ_INT(fence.st_mode & 0777, 0600);
        CHECK_EQ_INT(fence.st_uid, geteuid());
        CHECK(fence.st_size > 0);
    }

    /* This process has no in-memory switch owner. Recovery must therefore
     * adopt the durable fence and converge every identity surface forward. */
    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if ((size_t)snprintf(resume_output, sizeof(resume_output),
                         "%s/resume-output", fixture.root) <
            sizeof(resume_output) &&
        read_text(resume_output, output, sizeof(output)) > 0 &&
        (status < 0 || !WIFEXITED(status) ||
         WEXITSTATUS(status) != 0)) {
        fprintf(stderr,
                "AR-14 H1 finalization-race resume output:\n%s\n",
                output);
    }

    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(strstr(gitconfig, "old@example.test") == NULL);
    CHECK(strstr(gitconfig, "Concurrent Name") == NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 &&
          errno == ENOENT);
    CHECK(!config_dir_has_temporary(fixture.config_dir));
}

TEST(fresh_switch_stage_failure_cleans_exact_preintent_before_mutation) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[8192];
    struct stat st;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_stage_install_failure_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=old\n");
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, h1_old_gitconfig);
    errno = 0;
    CHECK(lstat(fixture.switch_stage, &st) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &st) != 0 && errno == ENOENT);
    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Injected switch guard lifecycle failure") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);
}

TEST(switch_guard_clear_retries_after_unlink_and_preserves_foreign_name) {
    cli_owner_fixture_t fixture;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_guard_clear_retry_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(persistent_clear_failure_republishes_restart_callable_fence) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    struct stat marker;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_persistent_clear_failure_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
    CHECK(strstr(output, "Switched to:") == NULL);
    CHECK(strstr(output, "recovery fencing remains") != NULL);
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
    CHECK(S_ISREG(marker.st_mode));
    CHECK_EQ_INT(marker.st_mode & 0777, 0600);

    /* The originating process released every handle. Only the republished,
     * directory-synchronized marker can authorize this fresh recovery. */
    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        char resume_output[16384];
        char resume_path[PATH_MAX];

        if ((size_t)snprintf(
                resume_path, sizeof(resume_path),
                "%s/resume-output", fixture.root) <
                sizeof(resume_path) &&
            read_text(
                resume_path, resume_output,
                sizeof(resume_output)) > 0) {
            fprintf(
                stderr,
                "AR-14 persistent clear recovery output:\n%s\n",
                resume_output);
        }
    }
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &marker) != 0 && errno == ENOENT);
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(h1_work_publication_is_live(&fixture));
}

TEST(restart_guard_binds_complete_repository_destination_set) {
    enum { MARKER_CAPACITY = 64 * 1024 };
    cli_owner_fixture_t fixture;
    char repo_a[PATH_MAX] = "";
    char repo_b[PATH_MAX] = "";
    char repo_a_local[PATH_MAX] = "";
    char repo_a_worktree[PATH_MAX] = "";
    char repo_b_local[PATH_MAX] = "";
    char repo_b_worktree[PATH_MAX] = "";
    unsigned char *marker_before = NULL;
    unsigned char *marker_after = NULL;
    struct stat state_before;
    struct stat state_after;
    size_t marker_before_length = 0U;
    size_t marker_after_length = 0U;
    int status;

    memset(&state_before, 0, sizeof(state_before));
    memset(&state_after, 0, sizeof(state_after));
    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK((size_t)snprintf(
              repo_a, sizeof(repo_a), "%s/repo-a", fixture.root) <
          sizeof(repo_a));
    CHECK((size_t)snprintf(
              repo_b, sizeof(repo_b), "%s/repo-b", fixture.root) <
          sizeof(repo_b));
    CHECK((size_t)snprintf(
              repo_a_local, sizeof(repo_a_local),
              "%s/.git/config", repo_a) < sizeof(repo_a_local));
    CHECK((size_t)snprintf(
              repo_a_worktree, sizeof(repo_a_worktree),
              "%s/.git/config.worktree", repo_a) <
          sizeof(repo_a_worktree));
    CHECK((size_t)snprintf(
              repo_b_local, sizeof(repo_b_local),
              "%s/.git/config", repo_b) < sizeof(repo_b_local));
    CHECK((size_t)snprintf(
              repo_b_worktree, sizeof(repo_b_worktree),
              "%s/.git/config.worktree", repo_b) <
          sizeof(repo_b_worktree));
    CHECK_EQ_INT(h1_repo_setup(&fixture, repo_a, "repo-a"), 0);
    CHECK_EQ_INT(h1_repo_setup(&fixture, repo_b, "repo-b"), 0);

    status = run_h1_create_guard_marker_at(&fixture, repo_a);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    /* Model an abrupt exit after global and local publication but before the
     * worktree destination was rewritten. The durable owner must remember all
     * three destinations, not merely whichever repository the retry sees. */
    CHECK_EQ_INT(h1_git_set(
                     &fixture, repo_a, "--global",
                     "user.name", "work"),
                 0);
    CHECK_EQ_INT(h1_git_set(
                     &fixture, repo_a, "--global",
                     "user.email", "work@example.test"),
                 0);
    CHECK_EQ_INT(h1_git_set(
                     &fixture, repo_a, "--local",
                     "user.name", "work"),
                 0);
    CHECK_EQ_INT(h1_git_set(
                     &fixture, repo_a, "--local",
                     "user.email", "work@example.test"),
                 0);
    CHECK(h1_git_identity_matches(
        fixture.gitconfig, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_local, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_worktree, "repo-a worktree",
        "repo-a-worktree@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_local, "repo-b local",
        "repo-b-local@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_worktree, "repo-b worktree",
        "repo-b-worktree@example.test"));

    marker_before = calloc(1U, MARKER_CAPACITY);
    marker_after = calloc(1U, MARKER_CAPACITY);
    CHECK(marker_before != NULL);
    CHECK(marker_after != NULL);
    if (marker_before && marker_after) {
        marker_before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            MARKER_CAPACITY, &state_before);
        CHECK(marker_before_length > 0U);
    }

    /* A different repository has a distinct local/worktree topology. It may
     * not adopt, rewrite, or normalize repo A's exact recovery owner. */
    status = run_h1_blocked_resume_case_at(
        &fixture, repo_b, "resume-wrong-repo-output");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if (marker_before && marker_after) {
        marker_after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            MARKER_CAPACITY, &state_after);
        CHECK_EQ_INT(marker_after_length, marker_before_length);
        CHECK(marker_after_length > 0U &&
              memcmp(marker_before, marker_after,
                     marker_before_length) == 0);
        /* FreeBSD UFS may materialize a reader-induced ctime update after
         * close. Exact bytes were proved above; retain every other metadata
         * and inode-generation check. */
        CHECK(h1_same_file_state_without_ctime(
            &state_before, &state_after));
    }
    CHECK(h1_git_identity_matches(
        fixture.gitconfig, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_local, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_worktree, "repo-a worktree",
        "repo-a-worktree@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_local, "repo-b local",
        "repo-b-local@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_worktree, "repo-b worktree",
        "repo-b-worktree@example.test"));

    /* An invocation outside every repository exports only the global
     * destination and must fail the same complete-set equality check. */
    status = run_h1_blocked_resume_case_at(
        &fixture, fixture.root, "resume-outside-repo-output");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if (marker_before && marker_after) {
        memset(marker_after, 0, MARKER_CAPACITY);
        memset(&state_after, 0, sizeof(state_after));
        marker_after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            MARKER_CAPACITY, &state_after);
        CHECK_EQ_INT(marker_after_length, marker_before_length);
        CHECK(marker_after_length > 0U &&
              memcmp(marker_before, marker_after,
                     marker_before_length) == 0);
        CHECK(h1_same_file_state_without_ctime(
            &state_before, &state_after));
    }
    CHECK(h1_git_identity_matches(
        fixture.gitconfig, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_local, "work", "work@example.test"));
    CHECK(h1_git_identity_matches(
        repo_a_worktree, "repo-a worktree",
        "repo-a-worktree@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_local, "repo-b local",
        "repo-b-local@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_worktree, "repo-b worktree",
        "repo-b-worktree@example.test"));

    /* Only the exact repository topology can adopt the marker. A global
     * switch completes by clearing both higher-precedence override scopes,
     * leaving the target global publication effective in this worktree. */
    status = run_h1_resume_case_at(
        &fixture, repo_a, "resume-exact-repo-output");
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(h1_git_identity_matches(
        fixture.gitconfig, "work", "work@example.test"));
    CHECK(h1_git_identity_is_absent(repo_a_local));
    CHECK(h1_git_identity_is_absent(repo_a_worktree));
    CHECK(h1_git_identity_matches(
        repo_b_local, "repo-b local",
        "repo-b-local@example.test"));
    CHECK(h1_git_identity_matches(
        repo_b_worktree, "repo-b worktree",
        "repo-b-worktree@example.test"));
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &state_after) != 0 &&
          errno == ENOENT);

    if (marker_before) {
        secure_zero_memory(marker_before, MARKER_CAPACITY);
        free(marker_before);
    }
    if (marker_after) {
        secure_zero_memory(marker_after, MARKER_CAPACITY);
        free(marker_after);
    }
}

TEST(restart_stage_only_preintent_self_heals_before_switch) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    struct stat st;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(rename(fixture.switch_fence, fixture.switch_stage), 0);
    CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &st), 0);
    CHECK_EQ_INT(st.st_nlink, 1);

    status = run_h1_plain_switch_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_stage, &st) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &st) != 0 && errno == ENOENT);
}

static int h1_malformed_marker_case(
    h1_switch_marker_malformation_t malformation) {
    const size_t marker_cap = 2U * CONFIG_DOCUMENT_MAX_SIZE;
    cli_owner_fixture_t fixture;
    config_switch_guard_recovery_t recovery;
    h1_switch_marker_layout_t layout;
    unsigned char *original = NULL;
    unsigned char *mutated = NULL;
    unsigned char *observed = NULL;
    struct stat before;
    struct stat after;
    char hint[256];
    char gitconfig[4096];
    size_t original_length;
    size_t mutated_length = 0U;
    size_t observed_length;
    bool blocked = false;
    int status;
    int result = -1;

    if (h1_fixture_setup(&fixture) != 0) return -1;
    status = run_h1_create_guard_marker(&fixture);
    if (status < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        goto done;
    }
    original = calloc(marker_cap + 1U, 1U);
    mutated = calloc(marker_cap + 1U, 1U);
    observed = calloc(marker_cap + 1U, 1U);
    if (!original || !mutated || !observed) goto done;
    original_length = h1_read_bounded_file(
        fixture.switch_fence, original, marker_cap, NULL);
    if (original_length == 0U ||
        h1_switch_marker_layout(
            original, original_length, &layout) != 0) {
        goto done;
    }

    switch (malformation) {
        case H1_MARKER_TRUNCATED_WITNESS:
            if (original_length <= layout.witness_offset) goto done;
            mutated_length = original_length - 1U;
            memcpy(mutated, original, mutated_length);
            break;
        case H1_MARKER_TRAILING_BYTE:
            if (original_length >= marker_cap) goto done;
            mutated_length = original_length + 1U;
            memcpy(mutated, original, original_length);
            mutated[original_length] = (unsigned char)'X';
            break;
        case H1_MARKER_DECLARED_SMALLER:
        case H1_MARKER_DECLARED_LARGER: {
            char decimal[32];
            size_t replacement;
            int count;

            replacement =
                malformation == H1_MARKER_DECLARED_SMALLER
                    ? layout.witness_length - 1U
                    : layout.witness_length + 1U;
            count = snprintf(
                decimal, sizeof(decimal), "%zu", replacement);
            if (layout.witness_length <= 1U || count <= 0 ||
                (size_t)count != layout.length_digit_count) {
                goto done;
            }
            mutated_length = original_length;
            memcpy(mutated, original, original_length);
            memcpy(
                mutated + layout.length_value_offset,
                decimal, (size_t)count);
            break;
        }
        case H1_MARKER_NONCANONICAL_LENGTH:
            if (original_length >= marker_cap) goto done;
            mutated_length = original_length + 1U;
            memcpy(
                mutated, original, layout.length_value_offset);
            mutated[layout.length_value_offset] =
                (unsigned char)'0';
            memcpy(
                mutated + layout.length_value_offset + 1U,
                original + layout.length_value_offset,
                original_length - layout.length_value_offset);
            break;
        case H1_MARKER_EMBEDDED_NUL:
            mutated_length = original_length;
            memcpy(mutated, original, original_length);
            mutated[
                layout.witness_offset +
                layout.witness_length / 2U] = '\0';
            break;
        case H1_MARKER_OVER_TOTAL_CAP:
            mutated_length = marker_cap + 1U;
            memcpy(mutated, original, original_length);
            memset(
                mutated + original_length, 'X',
                mutated_length - original_length);
            break;
        default:
            goto done;
    }

    if (replace_private_bytes_atomically(
            fixture.switch_fence, mutated, mutated_length) != 0 ||
        lstat(fixture.switch_fence, &before) != 0) {
        goto done;
    }
    memset(&recovery, 0, sizeof(recovery));
    errno = 0;
    if (config_switch_guard_probe(
            fixture.config, &blocked, &recovery) != -1 ||
        !blocked || recovery.valid ||
        lstat(fixture.switch_fence, &after) != 0 ||
        !ts_same_identity(&before, &after) ||
        before.st_size != after.st_size ||
        before.st_mode != after.st_mode) {
        goto done;
    }
    observed_length = h1_read_bounded_file(
        fixture.switch_fence, observed, marker_cap + 1U, NULL);
    if (observed_length != mutated_length ||
        memcmp(observed, mutated, mutated_length) != 0 ||
        read_text(fixture.hint, hint, sizeof(hint)) == 0U ||
        strcmp(hint, "none\nactive=old\n") != 0 ||
        read_text(
            fixture.gitconfig, gitconfig,
            sizeof(gitconfig)) == 0U ||
        strcmp(gitconfig, h1_old_gitconfig) != 0) {
        goto done;
    }
    result = 0;

done:
    if (original) {
        secure_zero_memory(original, marker_cap + 1U);
        free(original);
    }
    if (mutated) {
        secure_zero_memory(mutated, marker_cap + 1U);
        free(mutated);
    }
    if (observed) {
        secure_zero_memory(observed, marker_cap + 1U);
        free(observed);
    }
    ts_rm_rf(fixture.root);
    return result;
}

TEST(restart_rejects_truncated_source_witness) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_TRUNCATED_WITNESS), 0);
}

TEST(restart_rejects_trailing_source_witness_byte) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_TRAILING_BYTE), 0);
}

TEST(restart_rejects_smaller_declared_source_witness_length) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_DECLARED_SMALLER), 0);
}

TEST(restart_rejects_larger_declared_source_witness_length) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_DECLARED_LARGER), 0);
}

TEST(restart_rejects_noncanonical_source_witness_length) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_NONCANONICAL_LENGTH), 0);
}

TEST(restart_rejects_embedded_nul_in_source_witness) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_EMBEDDED_NUL), 0);
}

TEST(restart_rejects_switch_marker_over_total_size_cap) {
    CHECK_EQ_INT(
        h1_malformed_marker_case(H1_MARKER_OVER_TOTAL_CAP), 0);
}

TEST(restart_adopts_exact_maximum_source_witness) {
    const size_t marker_cap = 2U * CONFIG_DOCUMENT_MAX_SIZE;
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    h1_switch_marker_layout_t layout;
    unsigned char *document = NULL;
    unsigned char *marker = NULL;
    struct stat state;
    size_t marker_length = 0U;
    bool blocked = false;
    int fixture_result;
    int begin_result = -1;
    int status = -1;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        document = malloc(CONFIG_DOCUMENT_MAX_SIZE);
        marker = calloc(marker_cap, 1U);
        CHECK(document != NULL);
        CHECK(marker != NULL);
    }
    if (document && marker) {
        memcpy(document, h1_accounts_config, sizeof(h1_accounts_config) - 1U);
        memset(
            document + sizeof(h1_accounts_config) - 1U, '\n',
            CONFIG_DOCUMENT_MAX_SIZE -
                (sizeof(h1_accounts_config) - 1U));
        CHECK_EQ_INT(
            replace_private_bytes_atomically(
                fixture.config, document,
                CONFIG_DOCUMENT_MAX_SIZE),
            0);
        status = run_h1_create_guard_marker(&fixture);
        CHECK(status >= 0);
        if (status >= 0) {
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) {
                CHECK_EQ_INT(WEXITSTATUS(status), 0);
            }
        }
        marker_length = h1_read_bounded_file(
            fixture.switch_fence, marker, marker_cap, NULL);
        CHECK(marker_length > CONFIG_DOCUMENT_MAX_SIZE);
        CHECK_EQ_INT(
            h1_switch_marker_layout(
                marker, marker_length, &layout),
            0);
        if (h1_switch_marker_layout(
                marker, marker_length, &layout) == 0) {
            CHECK_EQ_INT(
                (int)layout.witness_length,
                (int)CONFIG_DOCUMENT_MAX_SIZE);
            CHECK(memcmp(
                      marker + layout.witness_offset, document,
                      CONFIG_DOCUMENT_MAX_SIZE) == 0);
        }

        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(blocked);
        CHECK(recovery.valid);

        begin_result = h1_guard_case_begin(&fixture, &guard_case);
        CHECK_EQ_INT(begin_result, 0);
        if (begin_result == 0) {
            CHECK_EQ_INT(
                config_switch_guard_install_or_adopt(
                    guard_case.ctx, guard_case.target,
                    GIT_SCOPE_GLOBAL, guard_case.destinations,
                    guard_case.destination_count,
                    &guard_case.guard),
                0);
            CHECK(guard_case.guard != NULL);
            CHECK(!config_switch_guard_was_created(
                guard_case.guard));
            CHECK_EQ_INT(
                config_switch_guard_clear(&guard_case.guard), 0);
            CHECK(guard_case.guard == NULL);
            errno = 0;
            CHECK(lstat(fixture.switch_fence, &state) != 0 &&
                  errno == ENOENT);
        }
    }
    h1_guard_case_end(&guard_case);
    if (document) {
        secure_zero_memory(document, CONFIG_DOCUMENT_MAX_SIZE);
        free(document);
    }
    if (marker) {
        secure_zero_memory(marker, marker_cap);
        free(marker);
    }
    ts_rm_rf(fixture.root);
}

TEST(restart_exact_portable_pair_normalizes_then_resumes) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    struct stat marker;
    struct stat stage;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(link(fixture.switch_fence, fixture.switch_stage), 0);
    CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &stage), 0);
    CHECK(marker.st_dev == stage.st_dev && marker.st_ino == stage.st_ino);
    CHECK_EQ_INT(marker.st_nlink, 2);
    CHECK_EQ_INT(stage.st_nlink, 2);

    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = work\n") != NULL);
    CHECK(strstr(gitconfig, "email = work@example.test\n") != NULL);
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_stage, &stage) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &marker) != 0 && errno == ENOENT);
}

#if !defined(__FreeBSD__)
TEST(restart_exact_pair_retries_after_normalize_sync_failure) {
    cli_owner_fixture_t fixture;
    char normalize[PATH_MAX];
    struct stat marker;
    struct stat stage;
    struct stat prepared;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK(
        (size_t)snprintf(
            normalize, sizeof(normalize), "%s/.switch-normalize",
            fixture.config_dir) < sizeof(normalize));
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(link(fixture.switch_fence, fixture.switch_stage), 0);
    CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);

    status = run_h1_normalize_sync_failure_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &stage), 0);
    CHECK_EQ_INT(lstat(normalize, &prepared), 0);
    CHECK(marker.st_dev == stage.st_dev && marker.st_ino == stage.st_ino);
    CHECK_EQ_INT(marker.st_nlink, 2);
    CHECK_EQ_INT(stage.st_nlink, 2);
    CHECK_EQ_INT(prepared.st_nlink, 1);

    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(normalize, &prepared) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_stage, &stage) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &marker) != 0 && errno == ENOENT);
}
#endif

TEST(restart_distinct_equal_normalized_pair_resumes) {
    cli_owner_fixture_t fixture;
    char marker_text[16384] = {0};
    struct stat marker;
    struct stat stage;
    size_t marker_length;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    marker_length = h1_read_bounded_file(
        fixture.switch_fence, (unsigned char *)marker_text,
        sizeof(marker_text) - 1U, &marker);
    CHECK(marker_length > 0U);
    CHECK(memchr(marker_text, '\0', marker_length) == NULL);
    CHECK_EQ_INT(link(fixture.switch_fence, fixture.switch_stage), 0);
    marker_text[marker_length] = '\0';
    CHECK_EQ_INT(
        replace_private_atomically(
            fixture.switch_fence, marker_text),
        0);
    CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &stage), 0);
    CHECK_EQ_INT(marker.st_nlink, 1);
    CHECK_EQ_INT(stage.st_nlink, 1);
    CHECK(marker.st_dev != stage.st_dev || marker.st_ino != stage.st_ino);

    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(h1_work_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_stage, &stage) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &marker) != 0 && errno == ENOENT);
    secure_zero_memory(marker_text, sizeof(marker_text));
}

TEST(restart_distinct_canonical_unequal_pair_fails_closed) {
    const size_t marker_cap = 2U * CONFIG_DOCUMENT_MAX_SIZE;
    static const unsigned char token_field[] = "token=";
    cli_owner_fixture_t fixture;
    config_switch_guard_recovery_t recovery;
    unsigned char *original = NULL;
    unsigned char *mutated = NULL;
    unsigned char *observed_marker = NULL;
    unsigned char *observed_stage = NULL;
    const unsigned char *token;
    struct stat marker_before;
    struct stat marker_after;
    struct stat stage_before;
    struct stat stage_after;
    char gitconfig[4096];
    char hint[256];
    size_t marker_length;
    size_t observed_marker_length;
    size_t observed_stage_length;
    bool blocked = false;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }
    original = calloc(marker_cap, 1U);
    mutated = calloc(marker_cap, 1U);
    observed_marker = calloc(marker_cap, 1U);
    observed_stage = calloc(marker_cap, 1U);
    CHECK(original != NULL);
    CHECK(mutated != NULL);
    CHECK(observed_marker != NULL);
    CHECK(observed_stage != NULL);
    if (original && mutated && observed_marker && observed_stage) {
        marker_length = h1_read_bounded_file(
            fixture.switch_fence, original, marker_cap, NULL);
        CHECK(marker_length > 0U);
        if (marker_length > 0U) {
            memcpy(mutated, original, marker_length);
            token = h1_find_bytes(
                mutated, marker_length, token_field,
                sizeof(token_field) - 1U);
            CHECK(token != NULL);
            if (token &&
                (size_t)(token - mutated) +
                        sizeof(token_field) - 1U <
                    marker_length) {
                size_t token_offset =
                    (size_t)(token - mutated) +
                    sizeof(token_field) - 1U;

                mutated[token_offset] =
                    mutated[token_offset] == (unsigned char)'A'
                        ? (unsigned char)'B'
                        : (unsigned char)'A';
                CHECK_EQ_INT(
                    replace_private_bytes_atomically(
                        fixture.switch_fence, mutated,
                        marker_length),
                    0);

                /* Prove the changed marker is independently canonical
                 * before presenting it beside a different canonical stage. */
                memset(&recovery, 0, sizeof(recovery));
                blocked = false;
                CHECK_EQ_INT(
                    config_switch_guard_probe(
                        fixture.config, &blocked, &recovery),
                    0);
                CHECK(blocked);
                CHECK(recovery.valid);

                CHECK_EQ_INT(
                    replace_private_bytes_atomically(
                        fixture.switch_stage, original,
                        marker_length),
                    0);
                CHECK_EQ_INT(
                    lstat(
                        fixture.switch_fence,
                        &marker_before),
                    0);
                CHECK_EQ_INT(
                    lstat(
                        fixture.switch_stage,
                        &stage_before),
                    0);
                CHECK(
                    marker_before.st_dev != stage_before.st_dev ||
                    marker_before.st_ino != stage_before.st_ino);

                memset(&recovery, 0, sizeof(recovery));
                blocked = false;
                errno = 0;
                CHECK_EQ_INT(
                    config_switch_guard_probe(
                        fixture.config, &blocked, &recovery),
                    0);
                CHECK(blocked);
                CHECK(!recovery.valid);
                errno = 0;
                CHECK_EQ_INT(
                    config_switch_guard_reconcile_preintent(
                        fixture.config),
                    -1);

                CHECK_EQ_INT(
                    lstat(
                        fixture.switch_fence,
                        &marker_after),
                    0);
                CHECK_EQ_INT(
                    lstat(
                        fixture.switch_stage,
                        &stage_after),
                    0);
                CHECK(ts_same_identity(
                    &marker_before, &marker_after));
                CHECK(ts_same_identity(
                    &stage_before, &stage_after));
                observed_marker_length = h1_read_bounded_file(
                    fixture.switch_fence, observed_marker,
                    marker_cap, NULL);
                observed_stage_length = h1_read_bounded_file(
                    fixture.switch_stage, observed_stage,
                    marker_cap, NULL);
                CHECK_EQ_INT(
                    (int)observed_marker_length,
                    (int)marker_length);
                CHECK_EQ_INT(
                    (int)observed_stage_length,
                    (int)marker_length);
                if (observed_marker_length == marker_length) {
                    CHECK(memcmp(
                              observed_marker, mutated,
                              marker_length) == 0);
                }
                if (observed_stage_length == marker_length) {
                    CHECK(memcmp(
                              observed_stage, original,
                              marker_length) == 0);
                }
                CHECK(
                    read_text(
                        fixture.hint, hint,
                        sizeof(hint)) > 0U);
                CHECK_STR_EQ(hint, "none\nactive=old\n");
                CHECK(
                    read_text(
                        fixture.gitconfig, gitconfig,
                        sizeof(gitconfig)) > 0U);
                CHECK_STR_EQ(gitconfig, h1_old_gitconfig);
            }
        }
    }
    if (original) {
        secure_zero_memory(original, marker_cap);
        free(original);
    }
    if (mutated) {
        secure_zero_memory(mutated, marker_cap);
        free(mutated);
    }
    if (observed_marker) {
        secure_zero_memory(observed_marker, marker_cap);
        free(observed_marker);
    }
    if (observed_stage) {
        secure_zero_memory(observed_stage, marker_cap);
        free(observed_stage);
    }
    ts_rm_rf(fixture.root);
}

TEST(restart_distinct_stage_and_marker_pair_fails_closed) {
    cli_owner_fixture_t fixture;
    static const char foreign_stage[] = "foreign-stage\n";
    char gitconfig[4096];
    char hint[256];
    char stage_text[64];
    struct stat marker_before;
    struct stat marker_after;
    struct stat stage_before;
    struct stat stage_after;
    int status;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    status = run_h1_create_guard_marker(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(write_private(fixture.switch_stage, foreign_stage), 0);
    CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker_before), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &stage_before), 0);
    CHECK(marker_before.st_ino != stage_before.st_ino ||
          marker_before.st_dev != stage_before.st_dev);

    status = run_h1_blocked_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &marker_after), 0);
    CHECK_EQ_INT(lstat(fixture.switch_stage, &stage_after), 0);
    CHECK(marker_before.st_dev == marker_after.st_dev &&
          marker_before.st_ino == marker_after.st_ino);
    CHECK(stage_before.st_dev == stage_after.st_dev &&
          stage_before.st_ino == stage_after.st_ino);
    CHECK(read_text(fixture.switch_stage, stage_text,
                    sizeof(stage_text)) > 0);
    CHECK_STR_EQ(stage_text, foreign_stage);
    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK_STR_EQ(hint, "none\nactive=old\n");
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK_STR_EQ(gitconfig, h1_old_gitconfig);
}

TEST(fenced_resume_uses_exact_numeric_account_name_not_colliding_id) {
    cli_owner_fixture_t fixture;
    char gitconfig[4096];
    char hint[256];
    char output[16384];
    struct stat fence;
    int status;

    CHECK_EQ_INT(h1_numeric_name_fixture_setup(&fixture), 0);

    /* Select account id 8 by its unique email so the durable marker records
     * its literal name "7", which deliberately collides with account id 7. */
    status = run_h1_switch_case(
        &fixture, "numeric-name@example.test",
        replace_h1_with_third_image_and_fail_sync, false);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.switch_fence, &fence), 0);

    /* This child starts from the pristine test parent. Recovery receives the
     * marker's name "7"; id-first lookup would select the decoy account and
     * either fail marker adoption or publish the wrong identity. */
    status = run_h1_resume_case(&fixture);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    if (status < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        CHECK(read_text(fixture.output, output, sizeof(output)) > 0);
        fprintf(stderr,
                "AR-14 H1 numeric-name switch output:\n%s\n",
                output);
    }

    CHECK(read_text(fixture.hint, hint, sizeof(hint)) > 0);
    CHECK(strncmp(hint, "none\nactive=7\n",
                  strlen("none\nactive=7\n")) == 0);
    CHECK(read_text(fixture.gitconfig, gitconfig, sizeof(gitconfig)) > 0);
    CHECK(strstr(gitconfig, "name = 7\n") != NULL);
    CHECK(strstr(gitconfig,
                 "email = numeric-name@example.test\n") != NULL);
    CHECK(strstr(gitconfig, "name = id-seven\n") == NULL);
    CHECK(strstr(gitconfig,
                 "email = id-seven@example.test\n") == NULL);
    CHECK(h1_numeric_name_publication_is_live(&fixture));
    errno = 0;
    CHECK(lstat(fixture.switch_fence, &fence) != 0 &&
          errno == ENOENT);
    CHECK(!config_dir_has_temporary(fixture.config_dir));
}

TEST(ordinary_guard_restore_failure_fences_next_cli_entry) {
    cli_owner_fixture_t fixture;
    int status;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    status = run_signal_marker_case(&fixture,
                                    SIGNAL_MARKER_GUARD_RESTORE);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(ordinary_dispatch_restore_failure_fences_next_cli_entry) {
    cli_owner_fixture_t fixture;
    int status;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    status = run_signal_marker_case(&fixture,
                                    SIGNAL_MARKER_DISPATCH_RESTORE);
    CHECK(status >= 0);
    if (status >= 0) {
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
}

TEST(parent_guard_stage_failure_removes_exact_fresh_stage) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    struct stat state;
    bool blocked = true;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        g_switch_guard_fail_stage = true;
        g_switch_guard_fail_clear = false;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK(!guard_case.guard);
        CHECK_EQ_INT(g_switch_guard_hook_calls, 1);
        errno = 0;
        CHECK(lstat(fixture.switch_stage, &state) != 0 &&
              errno == ENOENT);
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);
        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(!blocked);
        CHECK(!recovery.valid);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_initial_fstat_failure_preserves_replacement_for_retry) {
    static const char replacement[] = "foreign-switch-transition\n";
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    const error_context_t *error;
    struct stat retained = {0};
    struct stat state = {0};
    char observed[64] = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        g_switch_guard_fail_stage = false;
        g_switch_guard_replace_before_initial_fstat = true;
        g_switch_guard_fail_clear = false;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        g_switch_guard_replacement_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        (void)gitswitch_test_set_switch_guard_hook(NULL);

        CHECK(!guard_case.guard);
        CHECK_EQ_INT(g_switch_guard_hook_calls, 1);
        CHECK_EQ_INT(g_switch_guard_replacement_rc, 0);
        CHECK(!h1_same_file_state(
            &g_switch_guard_displaced_stage,
            &g_switch_guard_replacement_stage));
        CHECK(read_text(
                  fixture.switch_stage, observed,
                  sizeof(observed)) > 0U);
        CHECK(strcmp(observed, replacement) == 0);
        CHECK_EQ_INT(lstat(fixture.switch_stage, &retained), 0);
        CHECK(h1_same_file_state(
            &retained, &g_switch_guard_replacement_stage));
        error = get_last_error();
        CHECK(error != NULL);
        if (error) {
            CHECK(strstr(error->details,
                         "identity is unknown; retained") != NULL);
        }

        /* The failed call leaves a truthful fixed-stage recovery obligation.
         * A later lock holder first reconciles that stable pre-mutation stage,
         * then creates and publishes a fresh exact generation. */
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        errno = 0;
        CHECK(lstat(fixture.switch_stage, &state) != 0 &&
              errno == ENOENT);
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_clear_accepts_exact_ctime_only_marker_drift) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat before_state = {0};
    struct stat after_state = {0};
    struct stat state = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK_EQ_INT(
            lstat(fixture.switch_fence, &before_state), 0);
        CHECK_EQ_INT(
            h1_force_ctime_only_drift(
                fixture.switch_fence, &before_state, &after_state),
            0);
        CHECK(h1_same_file_state_without_ctime(
            &before_state, &after_state));
        CHECK(!h1_same_ctime(&before_state, &after_state));
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_clear_rejects_same_bytes_on_replacement_inode) {
    char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat before_state = {0};
    struct stat replacement_state = {0};
    struct stat after_state = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        before_length = h1_read_bounded_file(
            fixture.switch_fence,
            (unsigned char *)marker_before,
            sizeof(marker_before) - 1U, &before_state);
        CHECK(before_length > 0U);
        CHECK(memchr(marker_before, '\0', before_length) == NULL);
        if (before_length > 0U &&
            before_length < sizeof(marker_before) &&
            memchr(marker_before, '\0', before_length) == NULL) {
            marker_before[before_length] = '\0';
            CHECK_EQ_INT(
                replace_private_atomically(
                    fixture.switch_fence, marker_before),
                0);
            CHECK_EQ_INT(
                lstat(fixture.switch_fence, &replacement_state), 0);
            CHECK(!ts_same_identity(
                &before_state, &replacement_state));
            CHECK_EQ_INT(
                config_switch_guard_clear(&guard_case.guard), -1);
            CHECK(guard_case.guard != NULL);
            CHECK_EQ_INT(errno, ESTALE);
            after_length = h1_read_bounded_file(
                fixture.switch_fence, marker_after,
                sizeof(marker_after), &after_state);
            CHECK_EQ_INT(
                (int)after_length, (int)before_length);
            if (after_length == before_length) {
                CHECK(memcmp(
                    marker_before, marker_after, after_length) == 0);
            }
            CHECK(ts_same_identity(
                &replacement_state, &after_state));
        }
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_probe_recovers_after_source_ctime_drift_and_abandon) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_guard_source_path, fixture.config,
                sizeof(g_switch_guard_source_path)),
            0);
        g_switch_guard_drift_source_after_stage_sync = true;
        g_switch_guard_source_drift_calls = 0;
        g_switch_guard_source_drift_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            drift_switch_guard_source_after_stage_sync);
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_guard_source_drift_calls, 1);
        CHECK_EQ_INT(g_switch_guard_source_drift_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_guard_source_before_drift,
            &g_switch_guard_source_after_drift));
        CHECK(!h1_same_ctime(
            &g_switch_guard_source_before_drift,
            &g_switch_guard_source_after_drift));
        CHECK(guard_case.guard != NULL);
        if (guard_case.guard) {
            CHECK(config_switch_guard_was_created(guard_case.guard));

            /* Dropping the only live handle models a process stop. The next
             * probe must recover solely from durable namespace state. */
            config_switch_guard_abandon(&guard_case.guard);
            CHECK(!guard_case.guard);
            memset(&recovery, 0, sizeof(recovery));
            CHECK_EQ_INT(
                config_switch_guard_probe(
                    fixture.config, &blocked, &recovery),
                0);
            CHECK(blocked);
            CHECK(recovery.valid);
            CHECK_EQ_INT(
                recovery.target.id, guard_case.target->id);
            CHECK(strcmp(
                recovery.target.incarnation,
                guard_case.target->incarnation) == 0);
            CHECK_EQ_INT(
                recovery.effective_scope, GIT_SCOPE_GLOBAL);
            CHECK_EQ_INT(
                (int)recovery.destination_count,
                (int)guard_case.destination_count);
        }
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_probe_accepts_ctime_only_drift_after_marker_read) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_marker_mutation_path, fixture.switch_fence,
                sizeof(g_switch_marker_mutation_path)),
            0);
        g_switch_marker_mutation =
            SWITCH_MARKER_MUTATION_CTIME_ONLY;
        g_switch_marker_mutation_stage =
            SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ;
        g_switch_marker_mutation_calls = 0;
        g_switch_marker_mutation_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            mutate_switch_guard_marker_after_read);
        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_marker_mutation_calls, 1);
        CHECK_EQ_INT(g_switch_marker_outer_snapshot_calls, 1);
        CHECK_EQ_INT(g_switch_marker_mutation_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(!h1_same_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(blocked);
        CHECK(recovery.valid);
        CHECK_EQ_INT(recovery.target.id, guard_case.target->id);
        CHECK(strcmp(
            recovery.target.incarnation,
            guard_case.target->incarnation) == 0);
        CHECK_EQ_INT(
            recovery.effective_scope, GIT_SCOPE_GLOBAL);
        CHECK_EQ_INT(
            (int)recovery.destination_count,
            (int)guard_case.destination_count);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_probe_reproves_ctime_drift_after_exact_descriptor_proof) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_marker_mutation_path, fixture.switch_fence,
                sizeof(g_switch_marker_mutation_path)),
            0);
        g_switch_marker_mutation =
            SWITCH_MARKER_MUTATION_CTIME_ONLY;
        g_switch_marker_mutation_stage =
            SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF;
        g_switch_marker_mutation_calls = 0;
        g_switch_marker_mutation_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            mutate_switch_guard_marker_after_read);
        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_marker_mutation_calls, 1);
        CHECK_EQ_INT(g_switch_marker_outer_snapshot_calls, 1);
        CHECK_EQ_INT(g_switch_marker_mutation_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(!h1_same_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(blocked);
        CHECK(recovery.valid);
        CHECK_EQ_INT(recovery.target.id, guard_case.target->id);
        CHECK(strcmp(
            recovery.target.incarnation,
            guard_case.target->incarnation) == 0);
        CHECK_EQ_INT(
            recovery.effective_scope, GIT_SCOPE_GLOBAL);
        CHECK_EQ_INT(
            (int)recovery.destination_count,
            (int)guard_case.destination_count);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_probe_rejects_parse_valid_token_mutation_after_exact_proof) {
    unsigned char observed[16384] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    struct stat retained = {0};
    size_t observed_length = 0U;
    bool blocked = false;
    int probe_errno = 0;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_marker_mutation_path, fixture.switch_fence,
                sizeof(g_switch_marker_mutation_path)),
            0);
        g_switch_marker_mutation =
            SWITCH_MARKER_MUTATION_PARSE_VALID_TOKEN_RESTORED_MTIME;
        g_switch_marker_mutation_stage =
            SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF;
        g_switch_marker_mutation_calls = 0;
        g_switch_marker_mutation_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            mutate_switch_guard_marker_after_read);
        memset(&recovery, 0, sizeof(recovery));
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            -1);
        probe_errno = errno;
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(probe_errno, ESTALE);
        CHECK_EQ_INT(g_switch_marker_mutation_calls, 1);
        CHECK_EQ_INT(g_switch_marker_outer_snapshot_calls, 0);
        CHECK_EQ_INT(g_switch_marker_mutation_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(!h1_same_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(g_switch_marker_original_byte !=
              g_switch_marker_mutated_byte);
        CHECK(blocked);
        CHECK(!recovery.valid);

        observed_length = h1_read_bounded_file(
            fixture.switch_fence, observed, sizeof(observed),
            &retained);
        CHECK_EQ_INT(
            (long)observed_length,
            (long)g_switch_marker_after_mutation.st_size);
        CHECK(observed_length > 0U);
        CHECK(g_switch_marker_mutation_offset < observed_length);
        if (g_switch_marker_mutation_offset < observed_length) {
            CHECK_EQ_INT(
                observed[g_switch_marker_mutation_offset],
                g_switch_marker_mutated_byte);
        }
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_after_mutation, &retained));

        /* The altered token remains canonical and parse-valid. A fresh
         * unhooked probe accepts that stable marker, proving the first probe
         * failed because the anchored bytes changed rather than parsing. */
        memset(&recovery, 0, sizeof(recovery));
        blocked = false;
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(blocked);
        CHECK(recovery.valid);
    }
    h1_guard_case_end(&guard_case);
    memset(observed, 0, sizeof(observed));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_abandon_then_adopt_reuses_exact_authority) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat before_state = {0};
    struct stat after_state = {0};
    struct stat state = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), &before_state);
        CHECK(before_length > 0U);
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);

        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), &after_state);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U && after_length == before_length) {
            CHECK(memcmp(marker_before, marker_after, before_length) == 0);
            CHECK(h1_same_file_state_without_ctime(
                &before_state, &after_state));
        }
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_adopt_allows_destination_directory_bookkeeping_churn) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);

        g_switch_guard_churn_destination_directory = true;
        g_switch_guard_destination_churn_calls = 0;
        g_switch_guard_destination_churn_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            churn_switch_guard_destination_directory);
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK(!g_switch_guard_churn_destination_directory);
        CHECK_EQ_INT(g_switch_guard_destination_churn_calls, 1);
        CHECK_EQ_INT(g_switch_guard_destination_churn_rc, 0);
        CHECK(ts_same_identity(
            &g_switch_guard_destination_before_churn,
            &g_switch_guard_destination_after_churn));
        CHECK_EQ_INT(
            g_switch_guard_destination_before_churn.st_mode,
            g_switch_guard_destination_after_churn.st_mode);
        CHECK_EQ_INT(
            g_switch_guard_destination_before_churn.st_uid,
            g_switch_guard_destination_after_churn.st_uid);
        CHECK_EQ_INT(
            g_switch_guard_destination_before_churn.st_gid,
            g_switch_guard_destination_after_churn.st_gid);
        CHECK(!h1_same_ctime(
            &g_switch_guard_destination_before_churn,
            &g_switch_guard_destination_after_churn));
        CHECK(guard_case.guard != NULL);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
    }
    (void)gitswitch_test_set_switch_guard_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

#if !defined(__FreeBSD__)
TEST(parent_guard_adopts_exact_portable_pair_after_normalization) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat marker = {0};
    struct stat stage = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);

        CHECK_EQ_INT(
            link(fixture.switch_fence, fixture.switch_stage), 0);
        CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
        CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
        CHECK_EQ_INT(lstat(fixture.switch_stage, &stage), 0);
        CHECK(ts_same_identity(&marker, &stage));
        CHECK_EQ_INT(marker.st_nlink, 2);

        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        errno = 0;
        CHECK(lstat(fixture.switch_stage, &stage) != 0 &&
              errno == ENOENT);
        CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
        CHECK_EQ_INT(marker.st_nlink, 1);
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}
#endif

TEST(parent_guard_stage_only_preintent_precedes_fresh_publication) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat state = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(!guard_case.guard);
        CHECK_EQ_INT(
            rename(fixture.switch_fence, fixture.switch_stage), 0);
        CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
        CHECK_EQ_INT(lstat(fixture.switch_stage, &state), 0);
        CHECK_EQ_INT(state.st_nlink, 1);

        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        errno = 0;
        CHECK(lstat(fixture.switch_stage, &state) != 0 &&
              errno == ENOENT);
        CHECK_EQ_INT(lstat(fixture.switch_fence, &state), 0);
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_adopt_accepts_ctime_only_canonical_successor) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_marker_mutation_path, fixture.switch_fence,
                sizeof(g_switch_marker_mutation_path)),
            0);
        g_switch_marker_mutation =
            SWITCH_MARKER_MUTATION_CTIME_ONLY;
        g_switch_marker_mutation_stage =
            SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF;
        g_switch_marker_mutation_calls = 0;
        g_switch_marker_mutation_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            mutate_switch_guard_marker_after_read);
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_marker_mutation_calls, 1);
        CHECK_EQ_INT(g_switch_marker_mutation_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(!h1_same_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(guard_case.guard != NULL);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_adopt_rejects_restored_mtime_byte_mutation) {
    unsigned char observed[16384] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat retained = {0};
    size_t observed_length = 0U;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_marker_mutation_path, fixture.switch_fence,
                sizeof(g_switch_marker_mutation_path)),
            0);
        g_switch_marker_mutation =
            SWITCH_MARKER_MUTATION_PARSE_VALID_TOKEN_RESTORED_MTIME;
        g_switch_marker_mutation_stage =
            SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF;
        g_switch_marker_mutation_calls = 0;
        g_switch_marker_mutation_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            mutate_switch_guard_marker_after_read);
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        CHECK_EQ_INT(errno, ESTALE);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_marker_mutation_calls, 1);
        CHECK_EQ_INT(g_switch_marker_mutation_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(!h1_same_ctime(
            &g_switch_marker_before_mutation,
            &g_switch_marker_after_mutation));
        CHECK(guard_case.guard == NULL);
        observed_length = h1_read_bounded_file(
            fixture.switch_fence, observed, sizeof(observed),
            &retained);
        CHECK_EQ_INT(
            (long)observed_length,
            (long)g_switch_marker_after_mutation.st_size);
        CHECK(g_switch_marker_mutation_offset < observed_length);
        if (g_switch_marker_mutation_offset < observed_length) {
            CHECK_EQ_INT(
                observed[g_switch_marker_mutation_offset],
                g_switch_marker_mutated_byte);
        }
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_marker_after_mutation, &retained));
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(observed, sizeof(observed));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_rejects_and_retains_foreign_stage_hardlink) {
    static const char foreign_stage[] = "foreign-stage-hardlink\n";
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char source_path[PATH_MAX] = {0};
    char observed[64] = {0};
    struct stat source_before = {0};
    struct stat source_after = {0};
    struct stat stage_after = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(
            (size_t)snprintf(
                source_path, sizeof(source_path), "%s/foreign-stage",
                fixture.config_dir) < sizeof(source_path));
        CHECK_EQ_INT(write_private(source_path, foreign_stage), 0);
        CHECK_EQ_INT(
            link(source_path, fixture.switch_stage), 0);
        CHECK_EQ_INT(sync_directory(fixture.config_dir), 0);
        CHECK_EQ_INT(lstat(source_path, &source_before), 0);
        CHECK_EQ_INT(source_before.st_nlink, 2);

        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        CHECK_EQ_INT(errno, EACCES);
        CHECK(guard_case.guard == NULL);
        CHECK_EQ_INT(lstat(source_path, &source_after), 0);
        CHECK_EQ_INT(lstat(fixture.switch_stage, &stage_after), 0);
        CHECK(ts_same_identity(&source_before, &source_after));
        CHECK(ts_same_identity(&source_after, &stage_after));
        CHECK_EQ_INT(source_after.st_nlink, 2);
        CHECK(read_text(
                  fixture.switch_stage, observed,
                  sizeof(observed)) > 0U);
        CHECK_STR_EQ(observed, foreign_stage);
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_adopt_rejects_named_directory_replacement) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char displaced_marker[PATH_MAX] = {0};
    struct stat original_directory = {0};
    struct stat replacement_directory = {0};
    struct stat marker = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        config_switch_guard_abandon(&guard_case.guard);
        CHECK_EQ_INT(
            lstat(fixture.config_dir, &original_directory), 0);
        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_guard_directory_path, fixture.config_dir,
                sizeof(g_switch_guard_directory_path)),
            0);
        CHECK(
            (size_t)snprintf(
                g_switch_guard_displaced_directory_path,
                sizeof(g_switch_guard_displaced_directory_path),
                "%s.displaced", fixture.config_dir) <
            sizeof(g_switch_guard_displaced_directory_path));
        CHECK(
            (size_t)snprintf(
                displaced_marker, sizeof(displaced_marker),
                "%s/.switch-incomplete",
                g_switch_guard_displaced_directory_path) <
            sizeof(displaced_marker));
        g_switch_guard_replace_directory_after_read = true;
        g_switch_guard_directory_replacement_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            replace_switch_guard_directory_after_read);
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        CHECK_EQ_INT(errno, ESTALE);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK_EQ_INT(g_switch_guard_directory_replacement_rc, 0);
        CHECK(!g_switch_guard_replace_directory_after_read);
        CHECK(guard_case.guard == NULL);
        CHECK_EQ_INT(
            lstat(fixture.config_dir, &replacement_directory), 0);
        CHECK(!ts_same_identity(
            &original_directory, &replacement_directory));
        CHECK_EQ_INT(lstat(displaced_marker, &marker), 0);
        CHECK(S_ISREG(marker.st_mode));
    }
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

#if defined(__FreeBSD__)
TEST(freebsd_committed_publish_alias_is_restart_reconciled) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat marker = {0};
    struct stat stage = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        (void)gitswitch_test_set_config_publish_hook(
            fail_both_freebsd_publish_unlinks);
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        (void)gitswitch_test_set_config_publish_hook(NULL);
        CHECK(guard_case.guard == NULL);
        CHECK_EQ_INT(lstat(fixture.switch_fence, &marker), 0);
        CHECK_EQ_INT(lstat(fixture.switch_stage, &stage), 0);
        CHECK(marker.st_dev == stage.st_dev &&
              marker.st_ino == stage.st_ino);
        CHECK_EQ_INT(marker.st_nlink, 2);
        CHECK_EQ_INT(stage.st_nlink, 2);

        clear_error();
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(guard_case.guard != NULL);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(guard_case.guard == NULL);
    }
    (void)gitswitch_test_set_config_publish_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_uncertain_publish_outcome_is_not_precommit) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char marker_text[64];
    struct stat state = {0};
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        (void)gitswitch_test_set_config_publish_hook(
            make_freebsd_publish_outcome_uncertain);
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        CHECK_EQ_INT(errno, EINPROGRESS);
        (void)gitswitch_test_set_config_publish_hook(NULL);
        CHECK(guard_case.guard == NULL);
        CHECK(read_text(
                  fixture.switch_fence, marker_text,
                  sizeof(marker_text)) > 0);
        CHECK_STR_EQ(marker_text, "foreign-switch-marker\n");
        errno = 0;
        CHECK(lstat(fixture.switch_stage, &state) != 0 &&
              errno == ENOENT);
    }
    (void)gitswitch_test_set_config_publish_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_absent_resume_hint_retires_retained_random_source) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat hint = {0};
    bool installed = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(unlink(fixture.hint), 0);
        CHECK_EQ_INT(
            safe_strncpy(
                guard_case.ctx->config.active_account, "work",
                sizeof(guard_case.ctx->config.active_account)),
            0);
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_resume_hint_publish_unlinks);
        CHECK_EQ_INT(
            config_save_active_account_transactional(
                guard_case.ctx, fixture.config, &installed),
            0);
        (void)gitswitch_test_set_config_publish_hook(NULL);
        CHECK(installed);
        CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
        CHECK_EQ_INT(hint.st_nlink, 1);
        CHECK(!config_dir_has_temporary(fixture.config_dir));
    }
    (void)gitswitch_test_set_config_publish_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_absent_config_document_retires_retained_random_source) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat document = {0};
    bool installed = false;
    int environment_result = -1;
    int fixture_result;

    fixture_result = fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        CHECK_EQ_INT(unlink(fixture.config), 0);
        memset(&guard_case, 0, sizeof(guard_case));
        environment_result =
            h1_guard_environment_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(environment_result, 0);
    if (environment_result == 0) {
        guard_case.ctx = calloc(1U, sizeof(*guard_case.ctx));
        CHECK(guard_case.ctx != NULL);
    }
    if (guard_case.ctx) {
        CHECK_EQ_INT(config_init(guard_case.ctx), 0);
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_config_document_publish_unlinks);
        CHECK_EQ_INT(
            config_save_transactional(
                guard_case.ctx, fixture.config, &installed),
            0);
        (void)gitswitch_test_set_config_publish_hook(NULL);
        CHECK(installed);
        CHECK_EQ_INT(lstat(fixture.config, &document), 0);
        CHECK_EQ_INT(document.st_nlink, 1);
        CHECK(!config_dir_has_temporary(fixture.config_dir));
    }
    (void)gitswitch_test_set_config_publish_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_uncertain_config_document_tracks_or_retires_source) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    bool installed = false;
    int environment_result = -1;
    int fixture_result;

    fixture_result = fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        CHECK_EQ_INT(unlink(fixture.config), 0);
        memset(&guard_case, 0, sizeof(guard_case));
        environment_result =
            h1_guard_environment_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(environment_result, 0);
    if (environment_result == 0) {
        guard_case.ctx = calloc(1U, sizeof(*guard_case.ctx));
        CHECK(guard_case.ctx != NULL);
    }
    if (guard_case.ctx) {
        CHECK_EQ_INT(config_init(guard_case.ctx), 0);
        (void)gitswitch_test_set_config_publish_hook(
            make_freebsd_config_document_publish_uncertain);
        errno = 0;
        CHECK_EQ_INT(
            config_save_transactional(
                guard_case.ctx, fixture.config, &installed),
            -1);
        CHECK(installed);
        (void)gitswitch_test_set_config_publish_hook(NULL);
        CHECK(!config_dir_has_temporary(fixture.config_dir));
    }
    (void)gitswitch_test_set_config_publish_hook(NULL);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_default_prepublication_cleanup_never_creates_fixed_pair) {
    cli_owner_fixture_t fixture = {0};
    struct stat document = {0};
    int status = 0;
    pid_t child;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK_EQ_INT(unlink(fixture.config), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int result;

        (void)config_set_io_fault_fn(
            fail_default_before_publication);
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement);
        result = config_create_default(fixture.config);
        _exit(
            result == -1 &&
                    access(fixture.config, F_OK) != 0 &&
                    config_dir_count_prefix(
                        fixture.config_dir,
                        ".gitswitch-config-temp-settled-") == 0U
                ? 0
                : 1);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }
    CHECK_EQ_INT(config_create_default(fixture.config), 0);
    CHECK_EQ_INT(lstat(fixture.config, &document), 0);
    CHECK_EQ_INT(document.st_nlink, 1);
    /* With no canonical target proving ownership, the later writer preserves
     * the random-shaped prepublication collision. It must not turn that name
     * into a fixed pair or delete it merely because its spelling is reserved. */
    CHECK_EQ_INT(
        config_dir_count_prefix(
            fixture.config_dir, "accounts.toml.create."),
        1U);
    CHECK_EQ_INT(
        config_dir_count_prefix(
            fixture.config_dir,
            ".gitswitch-config-temp-settled-"),
        0U);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_retained_resume_alias_reconciles_at_every_crash_boundary) {
    static const int stages[] = {
        CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK,
        CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
        CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC
    };

    for (size_t i = 0U;
         i < sizeof(stages) / sizeof(stages[0]); i++) {
        cli_owner_fixture_t fixture = {0};
        h1_guard_case_t guard_case = {0};
        struct stat hint = {0};
        bool installed = false;
        int status = 0;
        pid_t child;

        CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
        CHECK_EQ_INT(
            h1_guard_case_begin(&fixture, &guard_case), 0);
        CHECK_EQ_INT(unlink(fixture.hint), 0);
        CHECK_EQ_INT(
            safe_strncpy(
                guard_case.ctx->config.active_account, "work",
                sizeof(guard_case.ctx->config.active_account)),
            0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            g_freebsd_settlement_stop_stage = stages[i];
            (void)gitswitch_test_set_config_publish_hook(
                fail_freebsd_retained_settlement);
            (void)config_save_active_account_transactional(
                guard_case.ctx, fixture.config,
                &(bool){false});
            _exit(1);
        }
        if (child > 0) {
            CHECK_EQ_INT(waitpid(child, &status, 0), child);
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) {
                CHECK_EQ_INT(WEXITSTATUS(status), 0);
            }
        }
        CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
        CHECK(hint.st_nlink >= 2);
        CHECK_EQ_INT(
            config_save_active_account_transactional(
                guard_case.ctx, fixture.config, &installed),
            0);
        CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
        CHECK_EQ_INT(hint.st_nlink, 1);
        CHECK_EQ_INT(
            config_dir_count_prefix(
                fixture.config_dir, ".resume-hint.tmp."),
            0U);
        CHECK_EQ_INT(
            config_dir_count_prefix(
                fixture.config_dir,
                ".gitswitch-resume-hint-settled-"),
            0U);
        h1_guard_case_end(&guard_case);
        ts_rm_rf(fixture.root);
    }
}

TEST(freebsd_fixed_authority_failures_retry_in_same_process) {
    static const int stages[] = {
        CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
        CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC
    };

    for (size_t i = 0U;
         i < sizeof(stages) / sizeof(stages[0]); i++) {
        cli_owner_fixture_t fixture = {0};
        h1_guard_case_t guard_case = {0};
        char foreign_slot[PATH_MAX];
        char foreign[64];
        struct stat hint = {0};
        bool installed = false;

        CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
        CHECK_EQ_INT(
            h1_guard_case_begin(&fixture, &guard_case), 0);
        CHECK_EQ_INT(unlink(fixture.hint), 0);
        CHECK_EQ_INT(
            safe_strncpy(
                guard_case.ctx->config.active_account, "work",
                sizeof(guard_case.ctx->config.active_account)),
            0);
        CHECK(
            snprintf(
                foreign_slot, sizeof(foreign_slot),
                "%s/.gitswitch-resume-hint-settled-0",
                fixture.config_dir) > 0);
        CHECK_EQ_INT(
            write_private(foreign_slot, "foreign-slot\n"), 0);

        (void)gitswitch_test_set_retirement_settled_slot_limit(2U);
        g_freebsd_settlement_fail_stage = stages[i];
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement_in_process);
        errno = 0;
        CHECK_EQ_INT(
            config_save_active_account_transactional(
                guard_case.ctx, fixture.config, &installed),
            -1);
        CHECK(installed);
        CHECK_EQ_INT(errno, EIO);
        CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
        CHECK_EQ_INT(hint.st_nlink, 3);
        CHECK_EQ_INT(
            config_dir_count_prefix(
                fixture.config_dir, ".resume-hint.tmp."),
            1U);

        (void)gitswitch_test_set_config_publish_hook(NULL);
        g_freebsd_settlement_fail_stage = -1;
        installed = false;
        CHECK_EQ_INT(
            config_save_active_account_transactional(
                guard_case.ctx, fixture.config, &installed),
            0);
        CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
        CHECK_EQ_INT(hint.st_nlink, 1);
        CHECK_EQ_INT(
            config_dir_count_prefix(
                fixture.config_dir, ".resume-hint.tmp."),
            0U);
        CHECK(read_text(foreign_slot, foreign, sizeof(foreign)) > 0);
        CHECK_STR_EQ(foreign, "foreign-slot\n");

        (void)gitswitch_test_set_retirement_settled_slot_limit(0U);
        CHECK_EQ_INT(unlink(foreign_slot), 0);
        h1_guard_case_end(&guard_case);
        ts_rm_rf(fixture.root);
    }
}

TEST(freebsd_substituted_fixed_authority_is_preserved) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char fixed_path[PATH_MAX];
    char foreign[64];
    struct stat hint = {0};
    bool installed = false;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(h1_guard_case_begin(&fixture, &guard_case), 0);
    CHECK_EQ_INT(unlink(fixture.hint), 0);
    CHECK_EQ_INT(
        safe_strncpy(
            guard_case.ctx->config.active_account, "work",
            sizeof(guard_case.ctx->config.active_account)),
        0);
    CHECK(
        snprintf(
            fixed_path, sizeof(fixed_path),
            "%s/.gitswitch-resume-hint-settled-0",
            fixture.config_dir) > 0);

    g_freebsd_fixed_replacement_rc = -1;
    g_freebsd_replace_target_with_fixed = false;
    (void)gitswitch_test_set_config_publish_hook(
        replace_freebsd_fixed_authority_before_retirement);
    errno = 0;
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        -1);
    CHECK(installed);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT(g_freebsd_fixed_replacement_rc, 0);
    CHECK(read_text(fixed_path, foreign, sizeof(foreign)) > 0);
    CHECK_STR_EQ(foreign, "foreign-fixed\n");
    CHECK_EQ_INT(
        config_dir_count_prefix(
            fixture.config_dir, ".resume-hint.tmp."),
        0U);

    (void)gitswitch_test_set_config_publish_hook(NULL);
    installed = false;
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        0);
    CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
    CHECK_EQ_INT(hint.st_nlink, 1);
    CHECK(read_text(fixed_path, foreign, sizeof(foreign)) > 0);
    CHECK_STR_EQ(foreign, "foreign-fixed\n");

    CHECK_EQ_INT(unlink(fixed_path), 0);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_paired_byte_equal_substitution_is_preserved) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char fixed_path[PATH_MAX];
    unsigned char target_bytes[16384];
    unsigned char fixed_bytes[sizeof(target_bytes)];
    struct stat target = {0};
    struct stat fixed = {0};
    size_t target_length;
    size_t fixed_length;
    bool installed = false;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(h1_guard_case_begin(&fixture, &guard_case), 0);
    CHECK_EQ_INT(unlink(fixture.hint), 0);
    CHECK_EQ_INT(
        safe_strncpy(
            guard_case.ctx->config.active_account, "work",
            sizeof(guard_case.ctx->config.active_account)),
        0);
    CHECK(
        snprintf(
            fixed_path, sizeof(fixed_path),
            "%s/.gitswitch-resume-hint-settled-0",
            fixture.config_dir) > 0);

    g_freebsd_fixed_replacement_rc = -1;
    g_freebsd_replace_target_with_fixed = true;
    g_freebsd_original_pair_fd = -1;
    memset(
        &g_freebsd_original_pair_identity, 0,
        sizeof(g_freebsd_original_pair_identity));
    (void)gitswitch_test_set_config_publish_hook(
        replace_freebsd_fixed_authority_before_retirement);
    errno = 0;
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        -1);
    CHECK(installed);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT(g_freebsd_fixed_replacement_rc, 0);
    CHECK_EQ_INT(lstat(fixture.hint, &target), 0);
    CHECK_EQ_INT(lstat(fixed_path, &fixed), 0);
    CHECK(g_freebsd_original_pair_fd >= 0);
    CHECK(target.st_dev == fixed.st_dev);
    CHECK(target.st_ino == fixed.st_ino);
    CHECK(
        target.st_dev != g_freebsd_original_pair_identity.st_dev ||
        target.st_ino != g_freebsd_original_pair_identity.st_ino);
    target_length = h1_read_bounded_file(
        fixture.hint, target_bytes,
        sizeof(target_bytes), NULL);
    fixed_length = h1_read_bounded_file(
        fixed_path, fixed_bytes,
        sizeof(fixed_bytes), NULL);
    CHECK(target_length > 0);
    CHECK_EQ_INT((int)fixed_length, (int)target_length);
    if (target_length > 0 && fixed_length == target_length) {
        CHECK(memcmp(
                  target_bytes, fixed_bytes,
                  (size_t)target_length) == 0);
    }

    (void)gitswitch_test_set_config_publish_hook(NULL);
    g_freebsd_replace_target_with_fixed = false;
    if (g_freebsd_original_pair_fd >= 0) {
        CHECK_EQ_INT(close(g_freebsd_original_pair_fd), 0);
        g_freebsd_original_pair_fd = -1;
    }
    CHECK_EQ_INT(unlink(fixed_path), 0);
    CHECK_EQ_INT(unlink(fixture.hint), 0);
    secure_zero_memory(target_bytes, sizeof(target_bytes));
    secure_zero_memory(fixed_bytes, sizeof(fixed_bytes));
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_fifo_substitution_before_source_pin_fails_without_blocking) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char fixed_path[PATH_MAX];
    char fifo_path[PATH_MAX];
    struct stat hint = {0};
    struct stat fixed = {0};
    struct stat fifo = {0};
    bool installed = false;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(h1_guard_case_begin(&fixture, &guard_case), 0);
    CHECK_EQ_INT(unlink(fixture.hint), 0);
    CHECK_EQ_INT(
        safe_strncpy(
            guard_case.ctx->config.active_account, "work",
            sizeof(guard_case.ctx->config.active_account)),
        0);
    CHECK(
        snprintf(
            fixed_path, sizeof(fixed_path),
            "%s/.gitswitch-resume-hint-settled-0",
            fixture.config_dir) > 0);

    g_freebsd_source_fifo_rc = -1;
    g_freebsd_source_fifo_name[0] = '\0';
    (void)gitswitch_test_set_config_publish_hook(
        replace_freebsd_source_with_fifo_before_pin);
    errno = EIO;
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        -1);
    CHECK(installed);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT(g_freebsd_source_fifo_rc, 0);
    CHECK(g_freebsd_source_fifo_name[0] != '\0');
    CHECK(
        snprintf(
            fifo_path, sizeof(fifo_path), "%s/%s",
            fixture.config_dir, g_freebsd_source_fifo_name) > 0);
    CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
    CHECK_EQ_INT(lstat(fixed_path, &fixed), 0);
    CHECK_EQ_INT(lstat(fifo_path, &fifo), 0);
    CHECK(S_ISREG(hint.st_mode));
    CHECK(S_ISREG(fixed.st_mode));
    CHECK(S_ISFIFO(fifo.st_mode));
    CHECK(hint.st_dev == fixed.st_dev);
    CHECK(hint.st_ino == fixed.st_ino);
    CHECK_EQ_INT(hint.st_nlink, 2);
    CHECK_EQ_INT(fixed.st_nlink, 2);

    (void)gitswitch_test_set_config_publish_hook(NULL);
    CHECK_EQ_INT(unlink(fifo_path), 0);
    CHECK_EQ_INT(unlink(fixed_path), 0);
    CHECK_EQ_INT(lstat(fixture.hint, &hint), 0);
    CHECK(S_ISREG(hint.st_mode));
    CHECK_EQ_INT(hint.st_nlink, 1);
    g_freebsd_source_fifo_rc = -1;
    g_freebsd_source_fifo_name[0] = '\0';
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_retained_alias_arena_preserves_collisions_and_reports_full) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    char slot0[PATH_MAX];
    char foreign[64];
    bool installed = false;
    int status = 0;
    pid_t child;

    CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
    CHECK_EQ_INT(h1_guard_case_begin(&fixture, &guard_case), 0);
    CHECK_EQ_INT(unlink(fixture.hint), 0);
    CHECK_EQ_INT(
        safe_strncpy(
            guard_case.ctx->config.active_account, "work",
            sizeof(guard_case.ctx->config.active_account)),
        0);
    CHECK(
        snprintf(
            slot0, sizeof(slot0),
            "%s/.gitswitch-resume-hint-settled-0",
            fixture.config_dir) > 0);
    CHECK_EQ_INT(write_private(slot0, "foreign-slot\n"), 0);

    (void)gitswitch_test_set_retirement_settled_slot_limit(2U);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        g_freebsd_settlement_stop_stage =
            CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC;
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement);
        (void)config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &(bool){false});
        _exit(1);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK(read_text(slot0, foreign, sizeof(foreign)) > 0);
    CHECK_STR_EQ(foreign, "foreign-slot\n");
    (void)gitswitch_test_set_retirement_settled_slot_limit(0U);
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        0);
    CHECK(read_text(slot0, foreign, sizeof(foreign)) > 0);
    CHECK_STR_EQ(foreign, "foreign-slot\n");
    CHECK_EQ_INT(unlink(slot0), 0);

    CHECK_EQ_INT(unlink(fixture.hint), 0);
    CHECK_EQ_INT(write_private(slot0, "foreign-slot\n"), 0);
    (void)gitswitch_test_set_retirement_settled_slot_limit(1U);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        bool child_installed = false;
        int result;

        g_freebsd_settlement_stop_stage = -1;
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement);
        errno = 0;
        result = config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &child_installed);
        _exit(
            result == -1 && child_installed &&
                    errno == ENOSPC
                ? 0
                : 1);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    (void)gitswitch_test_set_retirement_settled_slot_limit(0U);
    installed = false;
    CHECK_EQ_INT(
        config_save_active_account_transactional(
            guard_case.ctx, fixture.config, &installed),
        0);
    CHECK(read_text(slot0, foreign, sizeof(foreign)) > 0);
    CHECK_STR_EQ(foreign, "foreign-slot\n");
    CHECK_EQ_INT(unlink(slot0), 0);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(freebsd_document_and_default_scanners_close_pre_fixed_crash) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t environment = {0};
    struct stat document = {0};
    int status = 0;
    pid_t child;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK_EQ_INT(unlink(fixture.config), 0);
    CHECK_EQ_INT(
        h1_guard_environment_begin(&fixture, &environment), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        gitswitch_ctx_t *child_ctx =
            calloc(1U, sizeof(*child_ctx));

        if (!child_ctx || config_init(child_ctx) != 0) _exit(2);
        g_freebsd_settlement_stop_stage =
            CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK;
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement);
        (void)config_save_transactional(
            child_ctx, fixture.config, &(bool){false});
        _exit(1);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.config, &document), 0);
    CHECK_EQ_INT(document.st_nlink, 2);
    errno = 0;
    CHECK_EQ_INT(config_create_default(fixture.config), -1);
    CHECK_EQ_INT(errno, EEXIST);
    CHECK_EQ_INT(
        config_dir_count_prefix(
            fixture.config_dir, "accounts.toml.tmp."),
        0U);
    h1_guard_environment_end(&environment);
    ts_rm_rf(fixture.root);

    memset(&fixture, 0, sizeof(fixture));
    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK_EQ_INT(unlink(fixture.config), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        g_freebsd_settlement_stop_stage =
            CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK;
        (void)gitswitch_test_set_config_publish_hook(
            fail_freebsd_retained_settlement);
        (void)config_create_default(fixture.config);
        _exit(1);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }
    CHECK_EQ_INT(lstat(fixture.config, &document), 0);
    CHECK_EQ_INT(document.st_nlink, 2);
    errno = 0;
    CHECK_EQ_INT(config_create_default(fixture.config), -1);
    CHECK_EQ_INT(errno, EEXIST);
    CHECK_EQ_INT(lstat(fixture.config, &document), 0);
    CHECK_EQ_INT(document.st_nlink, 1);
    CHECK_EQ_INT(
        config_dir_count_prefix(
            fixture.config_dir, "accounts.toml.create."),
        0U);
    ts_rm_rf(fixture.root);
}
#endif

TEST(random_shaped_alias_requires_matching_canonical_authority) {
    for (int target_kind = 0; target_kind < 2; target_kind++) {
        cli_owner_fixture_t fixture = {0};
        h1_guard_case_t guard_case = {0};
        char candidate[PATH_MAX];
        char foreign[64];
        bool installed = false;

        CHECK_EQ_INT(h1_fixture_setup(&fixture), 0);
        CHECK_EQ_INT(
            h1_guard_case_begin(&fixture, &guard_case), 0);
        if (target_kind == 0) {
            CHECK_EQ_INT(unlink(fixture.hint), 0);
        }
        CHECK(
            snprintf(
                candidate, sizeof(candidate),
                "%s/.resume-hint.tmp.ABC123",
                fixture.config_dir) > 0);
        CHECK_EQ_INT(write_private(candidate, "foreign-random\n"), 0);
        CHECK_EQ_INT(
            safe_strncpy(
                guard_case.ctx->config.active_account, "work",
                sizeof(guard_case.ctx->config.active_account)),
            0);

        CHECK_EQ_INT(
            config_save_active_account_transactional(
                guard_case.ctx, fixture.config, &installed),
            0);
        CHECK(read_text(candidate, foreign, sizeof(foreign)) > 0);
        CHECK_STR_EQ(foreign, "foreign-random\n");

        CHECK_EQ_INT(unlink(candidate), 0);
        h1_guard_case_end(&guard_case);
        ts_rm_rf(fixture.root);
    }
}

TEST(fork_child_disposal_preserves_parent_switch_lock_then_reacquires) {
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    int ready_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int status = 0;
    int begin_result = -1;
    int fixture_result;
    int directory_fd = -1;
    pid_t child = -1;
    pid_t contender = -1;
    char byte = '\0';

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        directory_fd =
            gitswitch_test_switch_guard_directory_fd(
                guard_case.guard);
        CHECK(directory_fd >= 0);
        CHECK_EQ_INT(pipe(ready_pipe), 0);
        CHECK_EQ_INT(pipe(release_pipe), 0);
        fflush(NULL);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            int sentinel;

            close(ready_pipe[0]);
            close(release_pipe[1]);
            errno = 0;
            if (directory_fd < 0 ||
                fcntl(directory_fd, F_GETFD) != -1 ||
                errno != EBADF) {
                _exit(18);
            }
            sentinel = open(
                fixture.config_dir,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (sentinel < 0 ||
                (sentinel != directory_fd &&
                 dup2(sentinel, directory_fd) != directory_fd)) {
                _exit(19);
            }
            config_switch_guard_abandon(&guard_case.guard);
            if (guard_case.guard != NULL ||
                fcntl(directory_fd, F_GETFD) < 0) {
                _exit(20);
            }
            if (write(ready_pipe[1], "r", 1) != 1 ||
                read(release_pipe[0], &byte, 1) != 1) {
                _exit(22);
            }
            close(directory_fd);
            if (sentinel != directory_fd) close(sentinel);
            _exit(0);
        }
        close(ready_pipe[1]);
        ready_pipe[1] = -1;
        close(release_pipe[0]);
        release_pipe[0] = -1;
        CHECK_EQ_INT((int)read(ready_pipe[0], &byte, 1), 1);
        CHECK(config_switch_guard_was_created(guard_case.guard));
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(guard_case.guard == NULL);
        contender = fork();
        CHECK(contender >= 0);
        if (contender == 0) {
            config_switch_guard_t *independent = NULL;

            close(release_pipe[1]);
            clear_error();
            errno = 0;
            if (config_switch_guard_install_or_adopt(
                    guard_case.ctx, guard_case.target,
                    GIT_SCOPE_GLOBAL, guard_case.destinations,
                    guard_case.destination_count,
                    &independent) != 0 ||
                independent == NULL ||
                config_switch_guard_was_created(independent)) {
                config_switch_guard_abandon(&independent);
                _exit(23);
            }
            config_switch_guard_abandon(&independent);
            _exit(0);
        }
        CHECK_EQ_INT(waitpid(contender, &status, 0), contender);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
        CHECK_EQ_INT((int)write(release_pipe[1], "g", 1), 1);
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) {
            CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }
    if (ready_pipe[0] >= 0) close(ready_pipe[0]);
    if (ready_pipe[1] >= 0) close(ready_pipe[1]);
    if (release_pipe[0] >= 0) close(release_pipe[0]);
    if (release_pipe[1] >= 0) close(release_pipe[1]);
    h1_guard_case_end(&guard_case);
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_retain_republishes_exact_unlinked_marker) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    struct stat before_state = {0};
    struct stat after_state = {0};
    struct stat state = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), &before_state);
        CHECK(before_length > 0U);

        g_switch_guard_fail_stage = false;
        g_switch_guard_fail_clear = true;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), -1);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK(guard_case.guard != NULL);
        CHECK_EQ_INT(g_switch_guard_hook_calls, 1);
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);

        CHECK_EQ_INT(
            config_switch_guard_retain(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), &after_state);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U && after_length == before_length) {
            CHECK(memcmp(marker_before, marker_after, after_length) == 0);
            CHECK(S_ISREG(after_state.st_mode));
            CHECK_EQ_INT(after_state.st_mode & 0777, 0600);
        }

        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(blocked);
        CHECK(recovery.valid);
        CHECK_EQ_INT(recovery.target.id, guard_case.target->id);
        CHECK_EQ_INT(
            (int)recovery.destination_count,
            (int)guard_case.destination_count);

        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        CHECK(!config_switch_guard_was_created(guard_case.guard));
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_retain_republishes_unlinked_marker_after_source_ctime_drift) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    struct stat source_before = {0};
    struct stat source_after = {0};
    struct stat state = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    int begin_result = -1;
    int fixture_result;
    int status = 0;
    pid_t child = -1;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), NULL);
        CHECK(before_length > 0U);
        CHECK_EQ_INT(lstat(fixture.config, &source_before), 0);
        CHECK_EQ_INT(
            h1_force_ctime_only_drift(
                fixture.config, &source_before, &source_after),
            0);
        CHECK(h1_same_file_state_without_ctime(
            &source_before, &source_after));
        CHECK(!h1_same_ctime(&source_before, &source_after));

        g_switch_guard_fail_stage = false;
        g_switch_guard_fail_clear = true;
        g_switch_guard_clear_failures_remaining = 0;
        g_switch_guard_hook_calls = 0;
        (void)gitswitch_test_set_switch_guard_hook(
            fail_switch_guard_lifecycle);
        CHECK_EQ_INT(
            config_switch_guard_clear(&guard_case.guard), -1);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK(guard_case.guard != NULL);
        CHECK_EQ_INT(g_switch_guard_hook_calls, 1);
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);

        CHECK_EQ_INT(
            config_switch_guard_retain(&guard_case.guard), 0);
        CHECK(!guard_case.guard);
        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), NULL);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U &&
            after_length == before_length) {
            CHECK(memcmp(
                      marker_before, marker_after,
                      before_length) == 0);
        }

        fflush(NULL);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            h1_guard_case_t resumed = {0};
            config_switch_guard_recovery_t recovery;
            bool blocked = false;

            memset(&recovery, 0, sizeof(recovery));
            if (config_switch_guard_probe(
                    fixture.config, &blocked, &recovery) != 0 ||
                !blocked || !recovery.valid ||
                recovery.target.id != guard_case.target->id ||
                recovery.destination_count !=
                    guard_case.destination_count) {
                _exit(31);
            }
            if (h1_guard_case_begin(&fixture, &resumed) != 0 ||
                config_switch_guard_install_or_adopt(
                    resumed.ctx, resumed.target, GIT_SCOPE_GLOBAL,
                    resumed.destinations, resumed.destination_count,
                    &resumed.guard) != 0 ||
                resumed.guard == NULL ||
                config_switch_guard_was_created(resumed.guard)) {
                _exit(32);
            }
            if (config_switch_guard_clear(&resumed.guard) != 0 ||
                resumed.guard != NULL) {
                _exit(33);
            }
            _exit(0);
        }
        if (child > 0) {
            CHECK_EQ_INT(waitpid(child, &status, 0), child);
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) {
                CHECK_EQ_INT(WEXITSTATUS(status), 0);
            }
        }
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_retain_preserves_marker_across_source_ctime_drift) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    struct stat source_before = {0};
    struct stat source_after = {0};
    struct stat state = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;
    int status = 0;
    pid_t child = -1;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), NULL);
        CHECK(before_length > 0U);
        CHECK_EQ_INT(lstat(fixture.config, &source_before), 0);
        CHECK_EQ_INT(
            h1_force_ctime_only_drift(
                fixture.config, &source_before, &source_after),
            0);
        CHECK(h1_same_file_state_without_ctime(
            &source_before, &source_after));
        CHECK(!h1_same_ctime(&source_before, &source_after));

        CHECK_EQ_INT(
            config_switch_guard_retain(&guard_case.guard), 0);
        CHECK(guard_case.guard == NULL);
        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), NULL);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U &&
            after_length == before_length) {
            CHECK(memcmp(
                      marker_before, marker_after,
                      before_length) == 0);
        }

        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(blocked);
        CHECK(recovery.valid);

        fflush(NULL);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            h1_guard_case_t resumed = {0};

            if (h1_guard_case_begin(&fixture, &resumed) != 0 ||
                config_switch_guard_install_or_adopt(
                    resumed.ctx, resumed.target, GIT_SCOPE_GLOBAL,
                    resumed.destinations, resumed.destination_count,
                    &resumed.guard) != 0 ||
                resumed.guard == NULL ||
                config_switch_guard_was_created(resumed.guard) ||
                config_switch_guard_clear(&resumed.guard) != 0 ||
                resumed.guard != NULL) {
                _exit(41);
            }
            _exit(0);
        }
        if (child > 0) {
            CHECK_EQ_INT(waitpid(child, &status, 0), child);
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) {
                CHECK_EQ_INT(WEXITSTATUS(status), 0);
            }
        }
        errno = 0;
        CHECK(lstat(fixture.switch_fence, &state) != 0 &&
              errno == ENOENT);
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(parent_guard_retain_accepts_delayed_source_ctime_drift) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    size_t before_length = 0U;
    size_t after_length = 0U;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), NULL);
        CHECK(before_length > 0U);

        CHECK_EQ_INT(
            safe_strncpy(
                g_switch_guard_source_path, fixture.config,
                sizeof(g_switch_guard_source_path)),
            0);
        g_switch_guard_drift_source_after_retain_sync = true;
        g_switch_guard_source_drift_calls = 0;
        g_switch_guard_source_drift_rc = -1;
        (void)gitswitch_test_set_switch_guard_hook(
            drift_switch_guard_source_after_stage_sync);
        CHECK_EQ_INT(
            config_switch_guard_retain(&guard_case.guard), 0);
        (void)gitswitch_test_set_switch_guard_hook(NULL);
        CHECK(guard_case.guard == NULL);
        CHECK_EQ_INT(g_switch_guard_source_drift_calls, 1);
        CHECK_EQ_INT(g_switch_guard_source_drift_rc, 0);
        CHECK(h1_same_file_state_without_ctime(
            &g_switch_guard_source_before_drift,
            &g_switch_guard_source_after_drift));
        CHECK(!h1_same_ctime(
            &g_switch_guard_source_before_drift,
            &g_switch_guard_source_after_drift));

        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), NULL);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U &&
            after_length == before_length) {
            CHECK(memcmp(
                      marker_before, marker_after,
                      before_length) == 0);
        }

        memset(&recovery, 0, sizeof(recovery));
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            0);
        CHECK(blocked);
        CHECK(recovery.valid);
        CHECK_EQ_INT(recovery.target.id, guard_case.target->id);
        CHECK_EQ_INT(
            (int)recovery.destination_count,
            (int)guard_case.destination_count);
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST(fresh_guard_rejects_same_inode_source_mutation_with_restored_mtime) {
    unsigned char marker_before[16384] = {0};
    unsigned char marker_after[sizeof(marker_before)] = {0};
    cli_owner_fixture_t fixture = {0};
    h1_guard_case_t guard_case = {0};
    config_switch_guard_recovery_t recovery;
    struct stat source_before = {0};
    struct stat source_after = {0};
    size_t before_length = 0U;
    size_t after_length = 0U;
    bool blocked = false;
    int begin_result = -1;
    int fixture_result;

    fixture_result = h1_fixture_setup(&fixture);
    CHECK_EQ_INT(fixture_result, 0);
    if (fixture_result == 0) {
        begin_result = h1_guard_case_begin(&fixture, &guard_case);
    }
    CHECK_EQ_INT(begin_result, 0);
    if (begin_result == 0) {
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            0);
        before_length = h1_read_bounded_file(
            fixture.switch_fence, marker_before,
            sizeof(marker_before), NULL);
        CHECK(before_length > 0U);
        config_switch_guard_abandon(&guard_case.guard);
        CHECK(guard_case.guard == NULL);

        CHECK_EQ_INT(
            h1_change_ignored_whitespace_restore_mtime(
                fixture.config, &source_before, &source_after),
            0);
        CHECK(h1_same_file_state_without_ctime(
            &source_before, &source_after));
        CHECK(!h1_same_ctime(&source_before, &source_after));

        memset(&recovery, 0, sizeof(recovery));
        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_probe(
                fixture.config, &blocked, &recovery),
            -1);
        CHECK_EQ_INT(errno, ESTALE);
        CHECK(blocked);
        CHECK(!recovery.valid);

        errno = 0;
        CHECK_EQ_INT(
            config_switch_guard_install_or_adopt(
                guard_case.ctx, guard_case.target, GIT_SCOPE_GLOBAL,
                guard_case.destinations, guard_case.destination_count,
                &guard_case.guard),
            -1);
        CHECK_EQ_INT(errno, ESTALE);
        CHECK(guard_case.guard == NULL);

        after_length = h1_read_bounded_file(
            fixture.switch_fence, marker_after,
            sizeof(marker_after), NULL);
        CHECK_EQ_INT((int)after_length, (int)before_length);
        if (before_length > 0U &&
            after_length == before_length) {
            CHECK(memcmp(
                      marker_before, marker_after,
                      before_length) == 0);
        }
    }
    h1_guard_case_end(&guard_case);
    secure_zero_memory(marker_before, sizeof(marker_before));
    secure_zero_memory(marker_after, sizeof(marker_after));
    ts_rm_rf(fixture.root);
}

TEST_MAIN_BEGIN()
    RUN_TEST(one_shot_exact_abort_releases_cli_context);
    RUN_TEST(persistent_runtime_lock_retains_then_settles_before_next_entry);
    RUN_TEST(persistence_and_abort_failures_keep_first_context_and_causal_order);
    RUN_TEST(restart_resume_converges_after_active_state_restore_conflict);
    RUN_TEST(switch_fence_recorded_outside_repo_adopts_from_inside_repo);
    RUN_TEST(switch_fence_recorded_inside_repo_directs_resume_to_that_repo);
    RUN_TEST(unresolved_switch_fence_survives_restart_and_resume_reconciles_forward);
    RUN_TEST(restart_resume_reconstructs_enabled_ssh_identity);
    RUN_TEST(durable_gpg_publication_stop_is_reconciled_by_fresh_resume);
    RUN_TEST(finalization_git_replacement_retains_fence_until_fresh_resume);
    RUN_TEST(fresh_switch_stage_failure_cleans_exact_preintent_before_mutation);
    RUN_TEST(switch_guard_clear_retries_after_unlink_and_preserves_foreign_name);
    RUN_TEST(persistent_clear_failure_republishes_restart_callable_fence);
    RUN_TEST(restart_guard_binds_complete_repository_destination_set);
    RUN_TEST(restart_stage_only_preintent_self_heals_before_switch);
    RUN_TEST(restart_rejects_truncated_source_witness);
    RUN_TEST(restart_rejects_trailing_source_witness_byte);
    RUN_TEST(restart_rejects_smaller_declared_source_witness_length);
    RUN_TEST(restart_rejects_larger_declared_source_witness_length);
    RUN_TEST(restart_rejects_noncanonical_source_witness_length);
    RUN_TEST(restart_rejects_embedded_nul_in_source_witness);
    RUN_TEST(restart_rejects_switch_marker_over_total_size_cap);
    RUN_TEST(restart_adopts_exact_maximum_source_witness);
    RUN_TEST(restart_exact_portable_pair_normalizes_then_resumes);
#if !defined(__FreeBSD__)
    RUN_TEST(restart_exact_pair_retries_after_normalize_sync_failure);
#endif
    RUN_TEST(restart_distinct_equal_normalized_pair_resumes);
    RUN_TEST(restart_distinct_canonical_unequal_pair_fails_closed);
    RUN_TEST(restart_distinct_stage_and_marker_pair_fails_closed);
    RUN_TEST(fenced_resume_uses_exact_numeric_account_name_not_colliding_id);
    RUN_TEST(ordinary_guard_restore_failure_fences_next_cli_entry);
    RUN_TEST(ordinary_dispatch_restore_failure_fences_next_cli_entry);
    RUN_TEST(parent_guard_stage_failure_removes_exact_fresh_stage);
    RUN_TEST(
        parent_guard_initial_fstat_failure_preserves_replacement_for_retry);
    RUN_TEST(parent_guard_clear_accepts_exact_ctime_only_marker_drift);
    RUN_TEST(parent_guard_clear_rejects_same_bytes_on_replacement_inode);
    RUN_TEST(
        parent_guard_probe_recovers_after_source_ctime_drift_and_abandon);
    RUN_TEST(
        parent_guard_probe_accepts_ctime_only_drift_after_marker_read);
    RUN_TEST(
        parent_guard_probe_reproves_ctime_drift_after_exact_descriptor_proof);
    RUN_TEST(
        parent_guard_probe_rejects_parse_valid_token_mutation_after_exact_proof);
    RUN_TEST(parent_guard_abandon_then_adopt_reuses_exact_authority);
    RUN_TEST(
        parent_guard_adopt_allows_destination_directory_bookkeeping_churn);
#if !defined(__FreeBSD__)
    RUN_TEST(
        parent_guard_adopts_exact_portable_pair_after_normalization);
#endif
    RUN_TEST(
        parent_guard_stage_only_preintent_precedes_fresh_publication);
    RUN_TEST(
        parent_guard_adopt_accepts_ctime_only_canonical_successor);
    RUN_TEST(
        parent_guard_adopt_rejects_restored_mtime_byte_mutation);
    RUN_TEST(
        parent_guard_rejects_and_retains_foreign_stage_hardlink);
    RUN_TEST(
        parent_guard_adopt_rejects_named_directory_replacement);
#if defined(__FreeBSD__)
    RUN_TEST(freebsd_committed_publish_alias_is_restart_reconciled);
    RUN_TEST(freebsd_uncertain_publish_outcome_is_not_precommit);
    RUN_TEST(
        freebsd_absent_resume_hint_retires_retained_random_source);
    RUN_TEST(
        freebsd_absent_config_document_retires_retained_random_source);
    RUN_TEST(
        freebsd_uncertain_config_document_tracks_or_retires_source);
    RUN_TEST(
        freebsd_default_prepublication_cleanup_never_creates_fixed_pair);
    RUN_TEST(
        freebsd_retained_resume_alias_reconciles_at_every_crash_boundary);
    RUN_TEST(
        freebsd_fixed_authority_failures_retry_in_same_process);
    RUN_TEST(
        freebsd_substituted_fixed_authority_is_preserved);
    RUN_TEST(
        freebsd_paired_byte_equal_substitution_is_preserved);
    RUN_TEST(
        freebsd_fifo_substitution_before_source_pin_fails_without_blocking);
    RUN_TEST(
        freebsd_retained_alias_arena_preserves_collisions_and_reports_full);
    RUN_TEST(
        freebsd_document_and_default_scanners_close_pre_fixed_crash);
#endif
    RUN_TEST(
        random_shaped_alias_requires_matching_canonical_authority);
    RUN_TEST(
        fork_child_disposal_preserves_parent_switch_lock_then_reacquires);
    RUN_TEST(parent_guard_retain_republishes_exact_unlinked_marker);
    RUN_TEST(
        parent_guard_retain_republishes_unlinked_marker_after_source_ctime_drift);
    RUN_TEST(
        parent_guard_retain_preserves_marker_across_source_ctime_drift);
    RUN_TEST(
        parent_guard_retain_accepts_delayed_source_ctime_drift);
    RUN_TEST(
        fresh_guard_rejects_same_inode_source_mutation_with_restored_mtime);
TEST_MAIN_END()
