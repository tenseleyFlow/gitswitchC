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
    SWITCH_GUARD_CLEAR_AFTER_UNLINK
} switch_guard_test_stage_t;
typedef int (*switch_guard_test_hook_fn)(
    switch_guard_test_stage_t stage, int directory_fd);
switch_guard_test_hook_fn gitswitch_test_set_switch_guard_hook(
    switch_guard_test_hook_fn hook);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);

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
static int g_switch_guard_clear_failures_remaining;
static int g_switch_guard_hook_calls;
static int g_switch_guard_replacement_rc;
static struct stat g_switch_guard_displaced_stage;
static struct stat g_switch_guard_replacement_stage;
static bool g_switch_guard_drift_source_after_stage_sync;
static int g_switch_guard_source_drift_calls;
static int g_switch_guard_source_drift_rc;
static char g_switch_guard_source_path[PATH_MAX];
static struct stat g_switch_guard_source_before_drift;
static struct stat g_switch_guard_source_after_drift;
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

static int replace_private_atomically(const char *path, const char *text) {
    char directory[PATH_MAX];
    char temp[PATH_MAX] = "";
    const char *slash;
    size_t directory_length;
    size_t length = strlen(text);
    size_t total = 0;
    int dir_fd = -1;
    int output_fd = -1;
    int result = -1;
    int saved_errno;

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
        ssize_t count = write(output_fd, text + total, length - total);

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
        (stage == SWITCH_GUARD_CLEAR_AFTER_UNLINK &&
         (g_switch_guard_fail_clear ||
          g_switch_guard_clear_failures_remaining > 0))) {
        g_switch_guard_fail_stage = false;
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

static int drift_switch_guard_source_after_stage_sync(
    switch_guard_test_stage_t stage, int directory_fd) {
    (void)directory_fd;

    if (stage != SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC ||
        !g_switch_guard_drift_source_after_stage_sync) {
        return 0;
    }
    g_switch_guard_drift_source_after_stage_sync = false;
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
    g_switch_guard_fail_stage = false;
    g_switch_guard_replace_before_initial_fstat = false;
    g_switch_guard_fail_clear = false;
    g_switch_guard_clear_failures_remaining = 0;
    g_switch_guard_hook_calls = 0;
    g_switch_guard_replacement_rc = -1;
    memset(&g_switch_guard_displaced_stage, 0,
           sizeof(g_switch_guard_displaced_stage));
    memset(&g_switch_guard_replacement_stage, 0,
           sizeof(g_switch_guard_replacement_stage));
    g_switch_guard_drift_source_after_stage_sync = false;
    g_switch_guard_source_drift_calls = 0;
    g_switch_guard_source_drift_rc = -1;
    memset(g_switch_guard_source_path, 0,
           sizeof(g_switch_guard_source_path));
    memset(&g_switch_guard_source_before_drift, 0,
           sizeof(g_switch_guard_source_before_drift));
    memset(&g_switch_guard_source_after_drift, 0,
           sizeof(g_switch_guard_source_after_drift));
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

TEST_MAIN_BEGIN()
    RUN_TEST(one_shot_exact_abort_releases_cli_context);
    RUN_TEST(persistent_runtime_lock_retains_then_settles_before_next_entry);
    RUN_TEST(persistence_and_abort_failures_keep_first_context_and_causal_order);
    RUN_TEST(restart_resume_converges_after_active_state_restore_conflict);
    RUN_TEST(unresolved_switch_fence_survives_restart_and_resume_reconciles_forward);
    RUN_TEST(restart_resume_reconstructs_enabled_ssh_identity);
    RUN_TEST(durable_gpg_publication_stop_is_reconciled_by_fresh_resume);
    RUN_TEST(finalization_git_replacement_retains_fence_until_fresh_resume);
    RUN_TEST(fresh_switch_stage_failure_cleans_exact_preintent_before_mutation);
    RUN_TEST(switch_guard_clear_retries_after_unlink_and_preserves_foreign_name);
    RUN_TEST(persistent_clear_failure_republishes_restart_callable_fence);
    RUN_TEST(restart_guard_binds_complete_repository_destination_set);
    RUN_TEST(restart_stage_only_preintent_self_heals_before_switch);
    RUN_TEST(restart_exact_portable_pair_normalizes_then_resumes);
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
    RUN_TEST(parent_guard_abandon_then_adopt_reuses_exact_authority);
    RUN_TEST(parent_guard_retain_republishes_exact_unlinked_marker);
TEST_MAIN_END()
