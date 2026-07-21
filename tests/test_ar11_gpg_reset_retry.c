/* AR-11 M22: reset must recover only its exact durable post-rename state.
 *
 * A full reset deletes the selected home before retiring `current`.  Once
 * `current` has been moved to a private name, every later failure therefore
 * needs a durable identity witness: the next invocation has no home or public
 * link from which to reconstruct ownership.  These tests fault each boundary
 * after the move and require the immediately following reset to finish.  They
 * also replace the retained quarantine with a foreign symlink and prove retry
 * never removes that replacement. */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gpg_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static gpg_reset_quarantine_hook_stage_t g_failure_stage;
static bool g_hook_fired;
static char g_quarantine[GPG_QUARANTINE_NAME_LEN];

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

static int make_reset_fixture(char *xdg, size_t xdg_size,
                              char *base, size_t base_size,
                              char *home, size_t home_size,
                              char *current, size_t current_size) {
    char marker[MAX_PATH_LEN];
    int written;

    written = snprintf(xdg, xdg_size, "/tmp/gswar11m22_XXXXXX");
    if (written < 0 || (size_t)written >= xdg_size ||
        !ts_mkdtemp(xdg) ||
        ts_canonicalize_dir_path(xdg, xdg_size) != 0 ||
        chmod(xdg, 0700) != 0 || setenv("XDG_RUNTIME_DIR", xdg, 1) != 0) {
        return -1;
    }
    written = snprintf(base, base_size, "%s/gitswitch-gpg", xdg);
    if (written < 0 || (size_t)written >= base_size) return -1;
    written = snprintf(home, home_size, "%s/work", base);
    if (written < 0 || (size_t)written >= home_size) return -1;
    written = snprintf(current, current_size, "%s/current", base);
    if (written < 0 || (size_t)written >= current_size) return -1;
    written = snprintf(marker, sizeof(marker), "%s/private.key", home);
    if (written < 0 || (size_t)written >= sizeof(marker)) return -1;
    if (mkdir(base, 0700) != 0 || mkdir(home, 0700) != 0) return -1;
    {
        FILE *stream = fopen(marker, "w");
        if (!stream) return -1;
        if (fclose(stream) != 0) return -1;
    }
    return symlink(home, current);
}

static int fail_selected_quarantine_stage(
    int base_fd, gpg_reset_quarantine_hook_stage_t stage,
    const char *quarantine) {
    (void)base_fd;
    if (g_hook_fired || stage != g_failure_stage) return 0;
    if (!quarantine || !*quarantine ||
        snprintf(g_quarantine, sizeof(g_quarantine), "%s", quarantine) < 0) {
        return -1;
    }
    g_hook_fired = true;
    errno = EIO;
    return -1;
}

static struct stat g_hook_replacement_identity;

static int replace_quarantine_before_unlink(
    int base_fd, gpg_reset_quarantine_hook_stage_t stage,
    const char *quarantine) {
    if (stage != GPG_RESET_QUARANTINE_HOOK_BEFORE_UNLINK) return 0;
    if (!quarantine || !*quarantine ||
        snprintf(g_quarantine, sizeof(g_quarantine), "%s", quarantine) < 0 ||
        unlinkat(base_fd, quarantine, 0) != 0 ||
        symlinkat("foreign-at-unlink", base_fd, quarantine) != 0 ||
        fstatat(base_fd, quarantine, &g_hook_replacement_identity,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    g_hook_fired = true;
    return 0;
}

static void assert_retry_after_stage(
    gpg_reset_quarantine_hook_stage_t stage) {
    char xdg[128];
    char base[256];
    char home[320];
    char current[320];
    char retained[MAX_PATH_LEN];
    char witness_path[MAX_PATH_LEN];
    struct stat retained_st;
    struct stat witness_st;
    command_runner_fn old_runner;
    gpg_reset_quarantine_hook_fn old_hook;

    CHECK_EQ_INT(make_reset_fixture(xdg, sizeof(xdg), base, sizeof(base),
                                    home, sizeof(home), current,
                                    sizeof(current)), 0);
    g_failure_stage = stage;
    g_hook_fired = false;
    g_quarantine[0] = '\0';
    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_reset_quarantine_hook_fn(
        fail_selected_quarantine_stage);

    clear_error();
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(g_hook_fired);
    CHECK(g_quarantine[0] != '\0');
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_STR_EQ(get_last_error()->function,
                 "gpg_remove_captured_current_locked");
    CHECK(strstr(get_last_error()->message, "retry state retained") != NULL);
    CHECK(lstat(home, &retained_st) != 0 && errno == ENOENT);
    CHECK(lstat(current, &retained_st) != 0 && errno == ENOENT);
    CHECK(snprintf(retained, sizeof(retained), "%s/%s", base,
                   g_quarantine) > 0);
    CHECK(snprintf(witness_path, sizeof(witness_path), "%s.witness",
                   retained) > 0);
    CHECK_EQ_INT(lstat(retained, &retained_st), 0);
    CHECK_EQ_INT(lstat(witness_path, &witness_st), 0);
    CHECK_EQ_INT(witness_st.st_dev, retained_st.st_dev);
    CHECK_EQ_INT(witness_st.st_ino, retained_st.st_ino);

    gpg_manager_set_reset_quarantine_hook_fn(NULL);
    clear_error();
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    CHECK(lstat(retained, &retained_st) != 0 && errno == ENOENT);
    CHECK(lstat(witness_path, &witness_st) != 0 && errno == ENOENT);
    run_set_runner(old_runner);
    gpg_manager_set_reset_quarantine_hook_fn(old_hook);
}

TEST(reset_retries_after_post_rename_capture_failure) {
    assert_retry_after_stage(GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME);
}

TEST(reset_retries_after_post_rename_revalidation_failure) {
    assert_retry_after_stage(GPG_RESET_QUARANTINE_HOOK_BEFORE_REVALIDATE);
}

TEST(reset_retries_after_post_rename_unlink_failure) {
    assert_retry_after_stage(GPG_RESET_QUARANTINE_HOOK_BEFORE_UNLINK);
}

TEST(reset_retry_preserves_foreign_quarantine_replacement) {
    char xdg[128];
    char base[256];
    char home[320];
    char current[320];
    char retained[MAX_PATH_LEN];
    char witness_path[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];
    struct stat foreign_before;
    struct stat foreign_after;
    struct stat witness_before;
    struct stat witness_after;
    ssize_t target_len;
    command_runner_fn old_runner;
    gpg_reset_quarantine_hook_fn old_hook;

    CHECK_EQ_INT(make_reset_fixture(xdg, sizeof(xdg), base, sizeof(base),
                                    home, sizeof(home), current,
                                    sizeof(current)), 0);
    g_failure_stage = GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME;
    g_hook_fired = false;
    g_quarantine[0] = '\0';
    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_reset_quarantine_hook_fn(
        fail_selected_quarantine_stage);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(g_hook_fired && g_quarantine[0] != '\0');

    CHECK(snprintf(retained, sizeof(retained), "%s/%s", base,
                   g_quarantine) > 0);
    CHECK(snprintf(witness_path, sizeof(witness_path), "%s.witness",
                   retained) > 0);
    CHECK_EQ_INT(lstat(witness_path, &witness_before), 0);
    CHECK_EQ_INT(unlink(retained), 0);
    CHECK_EQ_INT(symlink("foreign-home", retained), 0);
    CHECK_EQ_INT(lstat(retained, &foreign_before), 0);
    gpg_manager_set_reset_quarantine_hook_fn(NULL);

    clear_error();
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(lstat(retained, &foreign_after), 0);
    CHECK_EQ_INT(foreign_after.st_dev, foreign_before.st_dev);
    CHECK_EQ_INT(foreign_after.st_ino, foreign_before.st_ino);
    CHECK_EQ_INT(lstat(witness_path, &witness_after), 0);
    CHECK_EQ_INT(witness_after.st_dev, witness_before.st_dev);
    CHECK_EQ_INT(witness_after.st_ino, witness_before.st_ino);
    target_len = readlink(retained, target, sizeof(target) - 1U);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, "foreign-home");
    }

    run_set_runner(old_runner);
    gpg_manager_set_reset_quarantine_hook_fn(old_hook);
}

TEST(reset_retry_completes_from_witness_only_retirement_state) {
    char xdg[128];
    char base[256];
    char home[320];
    char current[320];
    char retained[MAX_PATH_LEN];
    char witness_path[MAX_PATH_LEN];
    struct stat st;
    command_runner_fn old_runner;
    gpg_reset_quarantine_hook_fn old_hook;

    CHECK_EQ_INT(make_reset_fixture(xdg, sizeof(xdg), base, sizeof(base),
                                    home, sizeof(home), current,
                                    sizeof(current)), 0);
    g_failure_stage = GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME;
    g_hook_fired = false;
    g_quarantine[0] = '\0';
    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_reset_quarantine_hook_fn(
        fail_selected_quarantine_stage);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(g_hook_fired && g_quarantine[0] != '\0');
    CHECK(snprintf(retained, sizeof(retained), "%s/%s", base,
                   g_quarantine) > 0);
    CHECK(snprintf(witness_path, sizeof(witness_path), "%s.witness",
                   retained) > 0);
    CHECK_EQ_INT(unlink(retained), 0);
    CHECK_EQ_INT(lstat(witness_path, &st), 0);
    gpg_manager_set_reset_quarantine_hook_fn(NULL);

    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    CHECK(lstat(witness_path, &st) != 0 && errno == ENOENT);
    run_set_runner(old_runner);
    gpg_manager_set_reset_quarantine_hook_fn(old_hook);
}

TEST(reset_retry_preserves_unwitnessed_quarantine) {
    char xdg[128];
    char base[256];
    char home[320];
    char current[320];
    char retained[MAX_PATH_LEN];
    char witness_path[MAX_PATH_LEN];
    struct stat before;
    struct stat after;
    command_runner_fn old_runner;
    gpg_reset_quarantine_hook_fn old_hook;

    CHECK_EQ_INT(make_reset_fixture(xdg, sizeof(xdg), base, sizeof(base),
                                    home, sizeof(home), current,
                                    sizeof(current)), 0);
    g_failure_stage = GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME;
    g_hook_fired = false;
    g_quarantine[0] = '\0';
    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_reset_quarantine_hook_fn(
        fail_selected_quarantine_stage);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(g_hook_fired && g_quarantine[0] != '\0');
    CHECK(snprintf(retained, sizeof(retained), "%s/%s", base,
                   g_quarantine) > 0);
    CHECK(snprintf(witness_path, sizeof(witness_path), "%s.witness",
                   retained) > 0);
    CHECK_EQ_INT(lstat(retained, &before), 0);
    CHECK_EQ_INT(unlink(witness_path), 0);
    gpg_manager_set_reset_quarantine_hook_fn(NULL);

    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(strstr(get_last_error()->message, "Unwitnessed") != NULL);
    CHECK_EQ_INT(lstat(retained, &after), 0);
    CHECK_EQ_INT(after.st_dev, before.st_dev);
    CHECK_EQ_INT(after.st_ino, before.st_ino);
    run_set_runner(old_runner);
    gpg_manager_set_reset_quarantine_hook_fn(old_hook);
}

TEST(reset_preserves_replacement_installed_at_unlink_boundary) {
    char xdg[128];
    char base[256];
    char home[320];
    char current[320];
    char retained[MAX_PATH_LEN];
    char witness_path[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];
    struct stat after;
    ssize_t target_len;
    command_runner_fn old_runner;
    gpg_reset_quarantine_hook_fn old_hook;

    CHECK_EQ_INT(make_reset_fixture(xdg, sizeof(xdg), base, sizeof(base),
                                    home, sizeof(home), current,
                                    sizeof(current)), 0);
    g_hook_fired = false;
    g_quarantine[0] = '\0';
    memset(&g_hook_replacement_identity, 0,
           sizeof(g_hook_replacement_identity));
    old_runner = run_set_runner(null_runner);
    old_hook = gpg_manager_set_reset_quarantine_hook_fn(
        replace_quarantine_before_unlink);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK(g_hook_fired && g_quarantine[0] != '\0');
    CHECK(snprintf(retained, sizeof(retained), "%s/%s", base,
                   g_quarantine) > 0);
    CHECK(snprintf(witness_path, sizeof(witness_path), "%s.witness",
                   retained) > 0);
    CHECK_EQ_INT(lstat(retained, &after), 0);
    CHECK_EQ_INT(after.st_dev, g_hook_replacement_identity.st_dev);
    CHECK_EQ_INT(after.st_ino, g_hook_replacement_identity.st_ino);
    CHECK_EQ_INT(lstat(witness_path, &after), 0);
    target_len = readlink(retained, target, sizeof(target) - 1U);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, "foreign-at-unlink");
    }
    gpg_manager_set_reset_quarantine_hook_fn(NULL);

    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(lstat(retained, &after), 0);
    CHECK_EQ_INT(after.st_dev, g_hook_replacement_identity.st_dev);
    CHECK_EQ_INT(after.st_ino, g_hook_replacement_identity.st_ino);
    run_set_runner(old_runner);
    gpg_manager_set_reset_quarantine_hook_fn(old_hook);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(reset_retries_after_post_rename_capture_failure);
    RUN_TEST(reset_retries_after_post_rename_revalidation_failure);
    RUN_TEST(reset_retries_after_post_rename_unlink_failure);
    RUN_TEST(reset_retry_preserves_foreign_quarantine_replacement);
    RUN_TEST(reset_retry_completes_from_witness_only_retirement_state);
    RUN_TEST(reset_retry_preserves_unwitnessed_quarantine);
    RUN_TEST(reset_preserves_replacement_installed_at_unlink_boundary);
TEST_MAIN_END()
