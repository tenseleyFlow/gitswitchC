/* Tests for gpg_manager_reset's deletion guards.
 *
 * `reset <account>` recursively deletes <base>/<account>, and `reset` (all)
 * recursively deletes everything under <base>. Two guards make that safe:
 *   - the account name must be a single safe path component (no separators,
 *     no "..", no leading dot), or a crafted name would escape the base and
 *     wipe an arbitrary tree;
 *   - the base itself is lstat'd and must be a private (0700), self-owned,
 *     non-symlink directory — when XDG_RUNTIME_DIR is unset the base lives at
 *     the predictable /tmp/gitswitch-gpg-<uid>, which a co-located attacker
 *     could pre-create as a symlink into the victim's home.
 * Both guards are on the base branch (earlier audit batch); these tests lock
 * them. gpgconf invocations are swallowed by a recording runner. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp, flock) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "runner_internal.h"
#include "utils.h"
#include "error.h"
#include "trusted_command_fixture.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

static bool unsets_environment(const run_opts_t *opts, const char *name) {
    if (!opts || !opts->unset_env || !name) return false;
    for (size_t i = 0; opts->unset_env[i]; i++) {
        if (strcmp(opts->unset_env[i], name) == 0) return true;
    }
    return false;
}

/* Swallow GnuPG commands without executing them, while modeling the exact
 * launch/toolchain evidence required when isolated homes are created. */
static int null_runner(const char *const argv[], const run_opts_t *opts,
                       run_result_t *result) {
    const char *output = "";
    char metadata[MAX_PATH_LEN + 32U];

    CHECK(unsets_environment(opts, "GPG_AGENT_INFO"));
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        if (argv && argv[0] && argv[0][0] == '/') {
            CHECK(run_launch_witness_capture(
                argv[0], &result->launch_witness));
        }
    }
    if (argv && argv[0] && ts_command_is(argv[0], "gpgconf") &&
        argv[1] && strcmp(argv[1], "--list-components") == 0 &&
        !argv[2]) {
        const char *slash = strrchr(argv[0], '/');
        CHECK(slash != NULL);
        if (slash) {
            int written = snprintf(
                metadata, sizeof(metadata),
                "gpg:OpenPGP:%.*s/gpg:\n",
                (int)(slash - argv[0]), argv[0]);
            CHECK(written > 0 && (size_t)written < sizeof(metadata));
            if (written > 0 && (size_t)written < sizeof(metadata)) {
                output = metadata;
            }
        }
    } else if (argv && argv[0] &&
               ts_command_is(argv[0], "gpgconf") &&
               argv[1] && argv[2] &&
               strcmp(argv[1], "--reload") == 0 &&
               strcmp(argv[2], "gpg-agent") == 0 && !argv[3]) {
        output = "";
    }
    if (opts && opts->out && opts->out_size > 0) {
        size_t output_len = strlen(output);
        CHECK(output_len < opts->out_size);
        if (output_len < opts->out_size) {
            memcpy(opts->out, output, output_len + 1U);
            if (result) result->out_len = output_len;
        }
    }
    return 0;
}

static size_t g_null_runner_calls;

static int counting_null_runner(const char *const argv[],
                                const run_opts_t *opts,
                                run_result_t *result) {
    g_null_runner_calls++;
    return null_runner(argv, opts, result);
}

static const char *extra_env_value(const run_opts_t *opts, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (!opts || !opts->extra_env) return NULL;
    for (size_t i = 0; opts->extra_env[i]; i++) {
        if (strncmp(opts->extra_env[i], prefix, prefix_len) == 0) {
            return opts->extra_env[i] + prefix_len;
        }
    }
    return NULL;
}

/* Deterministically fail gpgconf for every home, or only for a home whose
 * path ends in /bad. This exercises the manager's retry-preservation and
 * all-home aggregation without relying on chmod behavior under root. */
static bool g_fail_only_bad_home;
static dev_t g_bad_home_dev;
static ino_t g_bad_home_ino;
static int failing_gpgconf_runner(const char *const argv[], const run_opts_t *opts,
                                  run_result_t *result) {
    struct stat cwd_st;
    bool is_bad = opts && opts->use_cwd_fd && opts->cwd_fd >= 0 &&
                  fstat(opts->cwd_fd, &cwd_st) == 0 &&
                  cwd_st.st_dev == g_bad_home_dev &&
                  cwd_st.st_ino == g_bad_home_ino;
    bool fail = !g_fail_only_bad_home || is_bad;
    (void)argv;
    CHECK(unsets_environment(opts, "GPG_AGENT_INFO"));
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = fail ? 9 : 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    return fail ? -1 : 0;
}

static struct stat g_causal_homes[2];
static size_t g_causal_order[2];
static size_t g_causal_runner_calls;
static struct stat g_causal_nested_fault;
static bool g_causal_nested_fault_ready;
static size_t g_causal_mount_failures;

/* Create the first failure only after reset's all-home preflight: a nested
 * directory whose mount-identity probe fails with ENOSPC. The next account's
 * agent stop then fails with EBUSY. Recording actual traversal order avoids
 * assuming any filesystem-specific readdir order. */
static int causal_gpgconf_runner(const char *const argv[],
                                 const run_opts_t *opts,
                                 run_result_t *result) {
    struct stat cwd_st;
    size_t home_index = 2U;
    size_t call_index = g_causal_runner_calls;

    (void)argv;
    CHECK(unsets_environment(opts, "GPG_AGENT_INFO"));
    CHECK(opts && opts->use_cwd_fd && opts->cwd_fd >= 0);
    if (opts && opts->use_cwd_fd && opts->cwd_fd >= 0 &&
        fstat(opts->cwd_fd, &cwd_st) == 0) {
        for (size_t i = 0; i < 2U; i++) {
            if (cwd_st.st_dev == g_causal_homes[i].st_dev &&
                cwd_st.st_ino == g_causal_homes[i].st_ino) {
                home_index = i;
                break;
            }
        }
    }
    CHECK(home_index < 2U);
    CHECK(g_causal_runner_calls < 2U);
    if (home_index < 2U && g_causal_runner_calls < 2U) {
        g_causal_order[g_causal_runner_calls] = home_index;
    }
    g_causal_runner_calls++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (call_index == 0U) {
        CHECK_EQ_INT(mkdirat(opts->cwd_fd, "l29-primary-fault", 0700), 0);
        CHECK_EQ_INT(fstatat(opts->cwd_fd, "l29-primary-fault",
                            &g_causal_nested_fault,
                            AT_SYMLINK_NOFOLLOW), 0);
        g_causal_nested_fault_ready = true;
        return 0;
    }
    if (result) result->exit_code = 9;
    errno = EBUSY;
    return -1;
}

static int causal_mount_identity(int fd, uint64_t *identity) {
    struct stat st;

    if (fd < 0 || !identity || fstat(fd, &st) != 0) return -1;
    if (g_causal_nested_fault_ready &&
        st.st_dev == g_causal_nested_fault.st_dev &&
        st.st_ino == g_causal_nested_fault.st_ino) {
        g_causal_mount_failures++;
        errno = ENOSPC;
        return -1;
    }
    *identity = 1U;
    return 0;
}

static const char *g_memory_probe_expected_base;
static const char *g_memory_probe_moved_base;
static size_t g_memory_probe_calls;
static bool g_memory_probe_exact_fd;
static const char *g_warning_probe_expected_base;
static size_t g_warning_probe_calls;
static bool g_warning_probe_exact_path;

static bool positive_base_warning_probe(const char *base_path) {
    g_warning_probe_calls++;
    if (!base_path || !g_warning_probe_expected_base ||
        strcmp(base_path, g_warning_probe_expected_base) != 0) {
        g_warning_probe_exact_path = false;
    }
    return true;
}

static bool memory_probe_fd_names_expected_base(int base_fd) {
    struct stat opened;
    struct stat named;

    return base_fd >= 0 && g_memory_probe_expected_base &&
           fstat(base_fd, &opened) == 0 &&
           lstat(g_memory_probe_expected_base, &named) == 0 &&
           S_ISDIR(opened.st_mode) && S_ISDIR(named.st_mode) &&
           opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

static int sequential_memory_backed_probe(int base_fd,
                                           bool *memory_backed) {
    bool exact = memory_probe_fd_names_expected_base(base_fd);

    g_memory_probe_exact_fd = g_memory_probe_exact_fd && exact;
    if (!memory_backed || g_memory_probe_calls >= 2U) {
        errno = EINVAL;
        return -1;
    }
    *memory_backed = g_memory_probe_calls == 0U;
    g_memory_probe_calls++;
    return 0;
}

static int replacing_memory_backed_probe(int base_fd,
                                         bool *memory_backed) {
    bool exact = memory_probe_fd_names_expected_base(base_fd);

    g_memory_probe_exact_fd = g_memory_probe_exact_fd && exact;
    g_memory_probe_calls++;
    if (!memory_backed || !exact || !g_memory_probe_moved_base ||
        rename(g_memory_probe_expected_base, g_memory_probe_moved_base) != 0 ||
        mkdir(g_memory_probe_expected_base, 0700) != 0) {
        errno = EIO;
        return -1;
    }
    *memory_backed = true;
    return 0;
}

static int failing_memory_backed_probe(int base_fd,
                                       bool *memory_backed) {
    bool exact = memory_probe_fd_names_expected_base(base_fd);

    (void)memory_backed;
    g_memory_probe_exact_fd = g_memory_probe_exact_fd && exact;
    g_memory_probe_calls++;
    errno = EIO;
    return -1;
}

/* Fresh scratch XDG_RUNTIME_DIR; returns 0 on success. */
static int make_xdg(char *dir, size_t size) {
    snprintf(dir, size, "/tmp/gswgpgrst_XXXXXX");
    if (!ts_mkdtemp(dir) || ts_canonicalize_dir_path(dir, size) != 0) {
        return -1;
    }
    if (chmod(dir, 0700) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", dir, 1);
    return 0;
}

static int touch(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fclose(f);
    return 0;
}

static int g_reset_sync_calls;
static bool g_fail_reset_sync;
static int g_reset_sync_errno = EIO;
static bool g_inject_late_reset_sync_residue;
static char g_late_reset_sync_residue[128];

#if !defined(__FreeBSD__)
static int identity_unlink_for_test(int dir_fd, const char *name,
                                    const struct stat *expected) {
    struct stat observed;
    if (!expected ||
        fstatat(dir_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0 ||
        observed.st_dev != expected->st_dev ||
        observed.st_ino != expected->st_ino ||
        observed.st_mode != expected->st_mode ||
        observed.st_uid != expected->st_uid ||
        observed.st_size != expected->st_size) {
        errno = ESTALE;
        return -1;
    }
    return unlinkat(dir_fd, name, 0);
}
#endif

static int record_reset_sync(int base_fd) {
    struct stat st;
    g_reset_sync_calls++;
    if (fstat(base_fd, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    if (g_inject_late_reset_sync_residue) {
        g_inject_late_reset_sync_residue = false;
        if (g_late_reset_sync_residue[0] == '\0' ||
            symlinkat("late-sync-residue", base_fd,
                      g_late_reset_sync_residue) != 0) {
            return -1;
        }
    }
    if (g_fail_reset_sync) {
        errno = g_reset_sync_errno;
        return -1;
    }
    return fsync(base_fd);
}

static void check_reset_witness_sync_failure_chain(void) {
    const error_context_t *error = get_last_error();

    CHECK_EQ_INT(error->code, ERR_FILE_IO);
    CHECK_EQ_INT(error->system_errno, EIO);
    CHECK_STR_EQ(error->function, "gpg_remove_captured_current_locked");
    CHECK(strstr(error->message, "Cannot synchronize GPG reset witness") !=
          NULL);
    CHECK(strstr(error->details, "base directory is not durable") != NULL);
}

static const char *g_reset_replacement_target;
static struct stat g_reset_replacement_identity;

static int replace_current_after_reset_capture(int base_fd) {
    if (!g_reset_replacement_target ||
        unlinkat(base_fd, "current", 0) != 0 ||
        symlinkat(g_reset_replacement_target, base_fd, "current") != 0 ||
        fstatat(base_fd, "current", &g_reset_replacement_identity,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    return 0;
}

static const char *g_reset_entry_replacement_name;
static const char *g_reset_entry_replacement_temp;
static const char *g_reset_entry_replacement_target;
static struct stat g_reset_entry_replacement_identity;

static int replace_reset_entry_after_plan_validation(int base_fd) {
    int saved_errno;

    if (!g_reset_entry_replacement_name ||
        !g_reset_entry_replacement_temp ||
        !g_reset_entry_replacement_target ||
        symlinkat(g_reset_entry_replacement_target, base_fd,
                  g_reset_entry_replacement_temp) != 0 ||
        renameat(base_fd, g_reset_entry_replacement_temp, base_fd,
                 g_reset_entry_replacement_name) != 0 ||
        fstatat(base_fd, g_reset_entry_replacement_name,
                &g_reset_entry_replacement_identity,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
        if (g_reset_entry_replacement_temp) {
            (void)unlinkat(base_fd, g_reset_entry_replacement_temp, 0);
        }
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static const char *g_swap_base;
static const char *g_swap_moved;
static const char *g_swap_replacement_home;
static const char *g_swap_replacement_marker;
static bool g_swap_pending;
static bool g_swap_used_pinned_home;

/* Simulate a same-uid namespace replacement while reset is inside gpgconf.
 * The manager must continue operating only on its already-opened base/home. */
static int swapping_gpgconf_runner(const char *const argv[],
                                   const run_opts_t *opts,
                                   run_result_t *result) {
    struct stat cwd_st;
    struct stat named_st;
    const char *home = extra_env_value(opts, "GNUPGHOME=");
    (void)argv;
    CHECK(unsets_environment(opts, "GPG_AGENT_INFO"));
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (g_swap_pending) {
        g_swap_used_pinned_home = opts && opts->use_cwd_fd &&
            opts->cwd_fd >= 0 && home && strcmp(home, ".") == 0 &&
            fstat(opts->cwd_fd, &cwd_st) == 0 &&
            stat(g_swap_replacement_home, &named_st) == 0 &&
            cwd_st.st_dev == named_st.st_dev && cwd_st.st_ino == named_st.st_ino;
        g_swap_pending = false;
        if (rename(g_swap_base, g_swap_moved) != 0 ||
            mkdir(g_swap_base, 0700) != 0 ||
            mkdir(g_swap_replacement_home, 0700) != 0 ||
            touch(g_swap_replacement_marker) != 0) {
            if (result) result->exit_code = 9;
            return -1;
        }
    }
    return 0;
}

static struct dirent *failing_readdir(DIR *dir) {
    (void)dir;
    errno = EIO;
    return NULL;
}

static bool g_fail_plan_revalidation_scan;

static struct dirent *fail_armed_plan_revalidation_scan(DIR *dir) {
    if (g_fail_plan_revalidation_scan) {
        errno = EIO;
        return NULL;
    }
    return readdir(dir);
}

static int arm_plan_revalidation_scan_failure(int base_fd) {
    (void)base_fd;
    g_fail_plan_revalidation_scan = true;
    return 0;
}

TEST(gpg_manager_reset_rejects_empty_selector_without_mutation) {
    char xdg[128], base[256], work[512], other[512];
    char work_marker[1024], other_marker[1024], current[512], lock_path[512];
    char linked[64];
    ssize_t linked_len;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK(access(base, F_OK) != 0 && errno == ENOENT);
    clear_error();
    CHECK_EQ_INT(gpg_manager_reset(""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(access(base, F_OK) != 0 && errno == ENOENT);

    CHECK_EQ_INT(mkdir(base, 0700), 0);
    snprintf(work, sizeof(work), "%s/work", base);
    snprintf(other, sizeof(other), "%s/other", base);
    CHECK_EQ_INT(mkdir(work, 0700), 0);
    CHECK_EQ_INT(mkdir(other, 0700), 0);
    snprintf(work_marker, sizeof(work_marker), "%s/keep", work);
    snprintf(other_marker, sizeof(other_marker), "%s/keep", other);
    CHECK_EQ_INT(touch(work_marker), 0);
    CHECK_EQ_INT(touch(other_marker), 0);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(symlink("work", current), 0);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);

    prev = run_set_runner(null_runner);
    clear_error();
    CHECK_EQ_INT(gpg_manager_reset(""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK(path_exists(work_marker));
    CHECK(path_exists(other_marker));
    linked_len = readlink(current, linked, sizeof(linked) - 1);
    CHECK(linked_len >= 0);
    if (linked_len >= 0) {
        linked[linked_len] = '\0';
        CHECK_STR_EQ(linked, "work");
    }
    run_set_runner(prev);
}

/* A crafted account name must never become a deletable path component that
 * escapes <base>. The victim dir sits exactly where "../victim" would land. */
TEST(gpg_manager_reset_rejects_traversal) {
    char xdg[128], base[256], home[512], victim[256], marker[512], keep[1024];
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(chmod(base, 0700), 0); /* exact 0700 regardless of umask */

    /* Legit isolated home (positive-control target) + escape-target victim. */
    snprintf(home, sizeof(home), "%s/work", base);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    snprintf(keep, sizeof(keep), "%s/secring", home);
    CHECK_EQ_INT(touch(keep), 0);
    snprintf(victim, sizeof(victim), "%s/victim", xdg);
    CHECK_EQ_INT(mkdir(victim, 0700), 0);
    snprintf(marker, sizeof(marker), "%s/precious", victim);
    CHECK_EQ_INT(touch(marker), 0);

    prev = run_set_runner(null_runner);

    /* Every non-single-component spelling is refused up front... */
    CHECK_EQ_INT(gpg_manager_reset(".."), -1);
    CHECK_EQ_INT(gpg_manager_reset("../victim"), -1);
    CHECK_EQ_INT(gpg_manager_reset("a/b"), -1);
    CHECK_EQ_INT(gpg_manager_reset("a\\b"), -1);
    CHECK_EQ_INT(gpg_manager_reset(".hidden"), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);

    /* ...and nothing outside (or inside) the base was touched by them. */
    CHECK(path_exists(marker));
    CHECK(path_exists(keep));

    /* Positive control: a safe name still resets exactly its own home. */
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    CHECK(!path_exists(home));
    CHECK(path_exists(marker));
    CHECK(path_exists(base));

    run_set_runner(prev);
}

/* A symlinked (or group/other-accessible) base must be refused before any
 * enumeration/deletion happens under it: nftw would follow the symlinked base
 * as an intermediate path component even with FTW_PHYS. */
TEST(gpg_manager_reset_refuses_symlinked_base) {
    char xdg[128], realbase[256], link_path[256], acct[512], marker[1024];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);

    /* The lure: a real, correctly-permissioned tree that only the symlink
     * points at — the guard must trip on the link itself. */
    snprintf(realbase, sizeof(realbase), "%s/victim-tree", xdg);
    CHECK_EQ_INT(mkdir(realbase, 0700), 0);
    snprintf(acct, sizeof(acct), "%s/work", realbase);
    CHECK_EQ_INT(mkdir(acct, 0700), 0);
    snprintf(marker, sizeof(marker), "%s/precious", acct);
    CHECK_EQ_INT(touch(marker), 0);
    snprintf(link_path, sizeof(link_path), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(symlink(realbase, link_path), 0);

    prev = run_set_runner(null_runner);

    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);

    /* Fail closed: the link is intact and the tree behind it untouched. */
    CHECK_EQ_INT(lstat(link_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK(path_exists(marker));

    /* Group-accessible real dir is refused too (mode & 077 gate). */
    CHECK_EQ_INT(unlink(link_path), 0);
    CHECK_EQ_INT(mkdir(link_path, 0700), 0);
    CHECK_EQ_INT(chmod(link_path, 0770), 0);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);

    /* A missing base is simply "nothing to reset", not an error. */
    CHECK_EQ_INT(chmod(link_path, 0700), 0);
    CHECK_EQ_INT(rmdir(link_path), 0);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);

    run_set_runner(prev);
}

/* AR-02 #21: `reset <account>` must refuse a SYMLINKED isolated home with the
 * same lstat guard the all-accounts branch applies to directory entries. The
 * pre-fix path_exists() check followed the link, so gpg_kill_and_remove_home
 * ran `gpgconf --kill all` with GNUPGHOME set through the symlink — e.g. at
 * the user's real ~/.gnupg, killing their login gpg-agent. */
TEST(gpg_manager_reset_single_account_refuses_symlinked_home) {
    char xdg[128], base[256], realtree[256], marker[512], link_path[512];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(chmod(base, 0700), 0);

    /* The lure: a real, correctly-permissioned tree the symlink points at. */
    snprintf(realtree, sizeof(realtree), "%s/real-gnupg", xdg);
    CHECK_EQ_INT(mkdir(realtree, 0700), 0);
    snprintf(marker, sizeof(marker), "%s/precious", realtree);
    CHECK_EQ_INT(touch(marker), 0);
    snprintf(link_path, sizeof(link_path), "%s/work", base);
    CHECK_EQ_INT(symlink(realtree, link_path), 0);

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);   /* pre-fix: 0 */
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    run_set_runner(prev);

    /* Fail closed: the link is intact and the tree behind it untouched. */
    CHECK_EQ_INT(lstat(link_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK(path_exists(marker));
}

/* AR-02 #9: gpg_manager_reset must serialize on the base dir's .lock — the
 * same lock the switch's `current` retarget takes — so home teardown and
 * current-link retirement cannot TOCTOU a concurrent switch. A child holds
 * the lock and writes its "done" marker only after a deliberate delay; a reset
 * that genuinely blocks on the lock returns only after that marker exists, while
 * the pre-fix (lockless) reset returned immediately. */
TEST(gpg_manager_reset_blocks_on_base_lock) {
    char xdg[128], base[256], lock_path[512], held[512], done[512];
    command_runner_fn prev;
    pid_t pid;
    int status = 0, waited = 0;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(chmod(base, 0700), 0);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    snprintf(held, sizeof(held), "%s/lock-held", xdg);
    snprintf(done, sizeof(done), "%s/lock-done", xdg);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 400000000 }; /* 400ms */
        int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || flock(fd, LOCK_EX) != 0) _exit(9);
        if (touch(held) != 0) _exit(9);   /* signal: lock is held */
        nanosleep(&ts, NULL);
        if (touch(done) != 0) _exit(9);   /* written BEFORE releasing */
        flock(fd, LOCK_UN);
        close(fd);
        _exit(0);
    }

    /* Wait until the child provably holds the lock. */
    while (!path_exists(held) && waited < 5000) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; /* 10ms */
        nanosleep(&ts, NULL);
        waited += 10;
    }
    CHECK(path_exists(held));

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(prev);

    /* Blocking on the lock means the child's delayed marker was already
     * written by the time reset returned. */
    CHECK(path_exists(done));   /* pre-fix: reset returned before the child */

    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* AR-04 H3: an existing validated base is never mutated without its lock. A
 * directory at .lock makes open/flock fail deterministically on every uid. */
TEST(gpg_manager_reset_fails_closed_when_lock_unavailable) {
    char xdg[128], base[256], lock_path[320], home[320], marker[384];
    char current[320];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(lock_path, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1); /* pre-fix: 0, unlocked delete */
    run_set_runner(prev);

    CHECK(path_exists(marker));
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

/* A failed gpgconf means the agent stop was not confirmed. Keep the complete
 * home and stable link so a later reset still has an exact retry target. */
TEST(gpg_manager_reset_retains_home_when_agent_stop_fails) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    g_fail_only_bad_home = false;
    prev = run_set_runner(failing_gpgconf_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1); /* pre-fix: 0 + home deleted */
    run_set_runner(prev);

    CHECK(path_exists(marker));
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(gpg_manager_reset_reports_recursive_removal_failure) {
    char xdg[128], base[256], home[320], marker[384];
    command_runner_fn prev;

    if (geteuid() == 0) {
        TS_SKIP("unprivileged",
                "directory permission denial requires an unprivileged uid");
    }
    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(chmod(home, 0500), 0); /* remove(marker) must fail */

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1); /* pre-fix: 0 */
    run_set_runner(prev);

    CHECK(path_exists(marker));
    CHECK_EQ_INT(chmod(home, 0700), 0);
}

/* All-home reset remains progressive: one failure is reported, but it does
 * not prevent independent homes from being stopped and removed. */
TEST(gpg_manager_reset_all_aggregates_failures_and_continues) {
    char xdg[128], base[256], good[320], bad[320];
    char good_marker[384], bad_marker[384], current[320];
    struct stat st;
    struct stat bad_st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(good, sizeof(good), "%s/good", base);
    snprintf(bad, sizeof(bad), "%s/bad", base);
    snprintf(good_marker, sizeof(good_marker), "%s/private.key", good);
    snprintf(bad_marker, sizeof(bad_marker), "%s/private.key", bad);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(good, 0700), 0);
    CHECK_EQ_INT(mkdir(bad, 0700), 0);
    CHECK_EQ_INT(touch(good_marker), 0);
    CHECK_EQ_INT(touch(bad_marker), 0);
    CHECK_EQ_INT(symlink(bad, current), 0);
    CHECK_EQ_INT(stat(bad, &bad_st), 0);

    g_fail_only_bad_home = true;
    g_bad_home_dev = bad_st.st_dev;
    g_bad_home_ino = bad_st.st_ino;
    prev = run_set_runner(failing_gpgconf_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(prev);

    CHECK(!path_exists(good));
    CHECK(path_exists(bad_marker));
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(gpg_manager_reset_all_retains_first_structured_cause) {
    char xdg[128], base[256], homes[2][320], markers[2][384];
    char primary_fault[MAX_PATH_LEN];
    char first_errno_detail[32];
    char sync_errno_detail[32];
    const char *first_home;
    const char *later_home;
    error_context_t error;
    int retained_errno;
    const char *first_errno;
    const char *home_label;
    const char *later_failure;
    const char *sync_label;
    const char *sync_failure;
    const char *sync_errno;
    const char *entry;
    size_t rendered_entries = 0U;
    gpg_mount_identity_probe_fn old_probe;
    gpg_sync_base_fn old_sync;
    command_runner_fn old_runner;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(homes[0], sizeof(homes[0]), "%s/alpha", base);
    snprintf(homes[1], sizeof(homes[1]), "%s/beta", base);
    snprintf(markers[0], sizeof(markers[0]), "%s/private.key", homes[0]);
    snprintf(markers[1], sizeof(markers[1]), "%s/private.key", homes[1]);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    for (size_t i = 0; i < 2U; i++) {
        CHECK_EQ_INT(mkdir(homes[i], 0700), 0);
        CHECK_EQ_INT(touch(markers[i]), 0);
        CHECK_EQ_INT(stat(homes[i], &g_causal_homes[i]), 0);
    }

    memset(g_causal_order, 0, sizeof(g_causal_order));
    memset(&g_causal_nested_fault, 0, sizeof(g_causal_nested_fault));
    g_causal_runner_calls = 0U;
    g_causal_nested_fault_ready = false;
    g_causal_mount_failures = 0U;
    g_reset_sync_calls = 0;
    g_fail_reset_sync = true;
    g_reset_sync_errno = EROFS;
    old_probe = gpg_manager_set_mount_identity_probe_fn(
        causal_mount_identity);
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    old_runner = run_set_runner(causal_gpgconf_runner);

    clear_error();
    errno = 0;
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    memcpy(&error, get_last_error(), sizeof(error));
    retained_errno = errno;
    run_set_runner(old_runner);
    gpg_manager_set_sync_base_fn(old_sync);
    gpg_manager_set_mount_identity_probe_fn(old_probe);
    g_fail_reset_sync = false;
    g_reset_sync_errno = EIO;

    CHECK_EQ_INT(g_causal_runner_calls, 2);
    CHECK_EQ_INT(g_causal_mount_failures, 1);
    CHECK_EQ_INT(g_reset_sync_calls, 1);
    CHECK(g_causal_order[0] < 2U && g_causal_order[1] < 2U);
    CHECK(g_causal_order[0] != g_causal_order[1]);
    first_home = homes[g_causal_order[0]];
    later_home = homes[g_causal_order[1]];
    snprintf(primary_fault, sizeof(primary_fault), "%s/l29-primary-fault",
             first_home);
    snprintf(first_errno_detail, sizeof(first_errno_detail), "errno=%d",
             ENOSPC);
    snprintf(sync_errno_detail, sizeof(sync_errno_detail), "errno=%d",
             EROFS);
    CHECK_EQ_INT(error.code, ERR_PERMISSION_DENIED);
    CHECK_EQ_INT(error.system_errno, ENOSPC);
    CHECK_STR_EQ(error.function, "gpg_walk_tree_contents_fd");
    CHECK(error.line > 0);
    CHECK(strstr(error.file, "gpg_manager.c") != NULL);
    CHECK(strstr(error.message, "Cannot prove GPG reset mount boundary") !=
          NULL);
    CHECK(strstr(error.message, primary_fault) != NULL);
    CHECK(!error.message_truncated);
    CHECK(!error.details_truncated);
    first_errno = strstr(error.details, first_errno_detail);
    home_label = strstr(error.details, "; [GPG home cleanup] ");
    later_failure = strstr(error.details, later_home);
    sync_label = strstr(error.details,
                        "; [GPG base directory synchronization] ");
    sync_failure = strstr(error.details, "base directory is not durable");
    sync_errno = sync_failure ? strstr(sync_failure, sync_errno_detail) : NULL;
    entry = error.details;
    while ((entry = strstr(entry, "; [")) != NULL) {
        rendered_entries++;
        entry += sizeof("; [") - 1U;
    }
    CHECK(first_errno != NULL);
    CHECK(home_label != NULL);
    CHECK(later_failure != NULL);
    CHECK(sync_label != NULL);
    CHECK(sync_failure != NULL);
    CHECK(sync_errno != NULL);
    CHECK_EQ_INT(rendered_entries, 2);
    if (first_errno && home_label && later_failure && sync_label &&
        sync_failure && sync_errno) {
        CHECK(first_errno < home_label);
        CHECK(home_label < later_failure);
        CHECK(later_failure < sync_label);
        CHECK(sync_label < sync_failure);
        CHECK(sync_failure < sync_errno);
    }
    CHECK_EQ_INT(retained_errno, ENOSPC);
    CHECK(path_exists(markers[0]));
    CHECK(path_exists(markers[1]));
}

/* readdir(3) reports EOF and I/O failure through the same NULL return. The
 * manager must clear/check errno or an unreadable tail becomes a false clean
 * reset that can also drop the stable link while homes remain. */
TEST(gpg_manager_reset_all_reports_readdir_failure) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    struct stat st;
    gpg_readdir_fn previous;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    previous = gpg_manager_set_readdir_fn(failing_readdir);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    gpg_manager_set_readdir_fn(previous);

    CHECK(path_exists(marker));
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(full_reset_final_scan_failure_preserves_complete_plan) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    char rollback[416], publish[416], reset[416], witness[448];
    struct stat home_before;
    struct stat marker_before;
    struct stat current_before;
    struct stat rollback_before;
    struct stat publish_before;
    struct stat reset_before;
    struct stat witness_before;
    struct stat observed;
    command_runner_fn old_runner;
    gpg_reset_current_hook_fn old_hook;
    gpg_readdir_fn previous;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(rollback, sizeof(rollback),
             "%s/.gitswitch-gpg-rollback.%ld.4000000000000001",
             base, (long)getpid());
    snprintf(publish, sizeof(publish),
             "%s/.gitswitch-gpg-publish.%ld.4000000000000002",
             base, (long)getpid());
    snprintf(reset, sizeof(reset),
             "%s/.gitswitch-gpg-reset.%ld.4000000000000003",
             base, (long)getpid());
    snprintf(witness, sizeof(witness), "%s.witness", reset);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);
    CHECK_EQ_INT(symlink(home, rollback), 0);
    CHECK_EQ_INT(symlink(home, publish), 0);
    CHECK_EQ_INT(symlink(home, reset), 0);
    CHECK_EQ_INT(link(reset, witness), 0);
    CHECK_EQ_INT(lstat(home, &home_before), 0);
    CHECK_EQ_INT(lstat(marker, &marker_before), 0);
    CHECK_EQ_INT(lstat(current, &current_before), 0);
    CHECK_EQ_INT(lstat(rollback, &rollback_before), 0);
    CHECK_EQ_INT(lstat(publish, &publish_before), 0);
    CHECK_EQ_INT(lstat(reset, &reset_before), 0);
    CHECK_EQ_INT(lstat(witness, &witness_before), 0);

    g_fail_plan_revalidation_scan = false;
    g_null_runner_calls = 0U;
    old_runner = run_set_runner(counting_null_runner);
    previous = gpg_manager_set_readdir_fn(
        fail_armed_plan_revalidation_scan);
    old_hook = gpg_manager_set_reset_current_hook_fn(
        arm_plan_revalidation_scan_failure);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    gpg_manager_set_reset_current_hook_fn(old_hook);
    gpg_manager_set_readdir_fn(previous);
    run_set_runner(old_runner);

    CHECK(g_fail_plan_revalidation_scan);
    CHECK_EQ_INT(g_null_runner_calls, 0);
    CHECK_EQ_INT(lstat(home, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, home_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, home_before.st_ino);
    CHECK_EQ_INT(lstat(marker, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, marker_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, marker_before.st_ino);
    CHECK_EQ_INT(lstat(current, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, current_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, current_before.st_ino);
    CHECK_EQ_INT(lstat(rollback, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, rollback_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, rollback_before.st_ino);
    CHECK_EQ_INT(lstat(publish, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, publish_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, publish_before.st_ino);
    CHECK_EQ_INT(lstat(reset, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, reset_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, reset_before.st_ino);
    CHECK_EQ_INT(lstat(witness, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, witness_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, witness_before.st_ino);
    g_fail_plan_revalidation_scan = false;
}

TEST(full_reset_revalidation_preserves_later_current_and_recovery_plan) {
    char xdg[128], base[256], current[320], rollback[416];
    char target[MAX_PATH_LEN];
    struct stat rollback_before;
    struct stat observed;
    ssize_t target_len;
    command_runner_fn old_runner;
    gpg_reset_current_hook_fn old_hook;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(rollback, sizeof(rollback),
             "%s/.gitswitch-gpg-rollback.%ld.5000000000000001",
             base, (long)getpid());
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(symlink("old-current", current), 0);
    CHECK_EQ_INT(symlink("retired-rollback", rollback), 0);
    CHECK_EQ_INT(lstat(rollback, &rollback_before), 0);

    g_reset_replacement_target = "later-current";
    memset(&g_reset_replacement_identity, 0,
           sizeof(g_reset_replacement_identity));
    old_hook = gpg_manager_set_reset_current_hook_fn(
        replace_current_after_reset_capture);
    g_null_runner_calls = 0U;
    old_runner = run_set_runner(counting_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(old_runner);
    gpg_manager_set_reset_current_hook_fn(old_hook);

    CHECK_EQ_INT(g_null_runner_calls, 0);
    CHECK_EQ_INT(lstat(current, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, g_reset_replacement_identity.st_dev);
    CHECK_EQ_INT(observed.st_ino, g_reset_replacement_identity.st_ino);
    target_len = readlink(current, target, sizeof(target) - 1U);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, "later-current");
    }
    CHECK_EQ_INT(lstat(rollback, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, rollback_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, rollback_before.st_ino);
    g_reset_replacement_target = NULL;
}

TEST(full_reset_revalidation_preserves_later_recovery_entry) {
    char xdg[128], base[256], current[320], rollback[416];
    char target[MAX_PATH_LEN];
    struct stat current_before;
    struct stat observed;
    ssize_t target_len;
    command_runner_fn old_runner;
    gpg_reset_current_hook_fn old_hook;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(rollback, sizeof(rollback),
             "%s/.gitswitch-gpg-rollback.%ld.5000000000000002",
             base, (long)getpid());
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(symlink("old-current", current), 0);
    CHECK_EQ_INT(symlink("old-rollback", rollback), 0);
    CHECK_EQ_INT(lstat(current, &current_before), 0);

    g_reset_entry_replacement_name = strrchr(rollback, '/');
    CHECK(g_reset_entry_replacement_name != NULL);
    if (g_reset_entry_replacement_name) {
        g_reset_entry_replacement_name++;
    }
    g_reset_entry_replacement_temp = ".replacement-under-validation";
    g_reset_entry_replacement_target = "later-rollback";
    memset(&g_reset_entry_replacement_identity, 0,
           sizeof(g_reset_entry_replacement_identity));
    old_hook = gpg_manager_set_reset_current_hook_fn(
        replace_reset_entry_after_plan_validation);
    g_null_runner_calls = 0U;
    old_runner = run_set_runner(counting_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(old_runner);
    gpg_manager_set_reset_current_hook_fn(old_hook);

    CHECK_EQ_INT(g_null_runner_calls, 0);
    CHECK_EQ_INT(lstat(current, &observed), 0);
    CHECK_EQ_INT(observed.st_dev, current_before.st_dev);
    CHECK_EQ_INT(observed.st_ino, current_before.st_ino);
    CHECK_EQ_INT(lstat(rollback, &observed), 0);
    CHECK_EQ_INT(observed.st_dev,
                 g_reset_entry_replacement_identity.st_dev);
    CHECK_EQ_INT(observed.st_ino,
                 g_reset_entry_replacement_identity.st_ino);
    target_len = readlink(rollback, target, sizeof(target) - 1U);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, "later-rollback");
    }
    g_reset_entry_replacement_name = NULL;
    g_reset_entry_replacement_temp = NULL;
    g_reset_entry_replacement_target = NULL;
}

TEST(full_reset_forward_quarantine_sync_failure_is_retryable) {
    char xdg[128], base[256], current[320];
    char candidate[416], witness[416], quarantine[416];
    struct stat st;
    gpg_sync_base_fn old_sync;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(candidate, sizeof(candidate),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000001.p",
             base, (long)getpid());
    snprintf(witness, sizeof(witness),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000001.w",
             base, (long)getpid());
    snprintf(quarantine, sizeof(quarantine),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000001.q",
             base, (long)getpid());
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(symlink("candidate", candidate), 0);
    CHECK_EQ_INT(symlink("expected", witness), 0);
    CHECK_EQ_INT(link(witness, quarantine), 0);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);

    g_reset_sync_calls = 0;
    g_fail_reset_sync = true;
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(g_reset_sync_calls, 1);
    CHECK_EQ_INT(lstat(candidate, &st), 0);
    CHECK_EQ_INT(lstat(witness, &st), 0);
    CHECK(lstat(quarantine, &st) != 0 && errno == ENOENT);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);

    g_fail_reset_sync = false;
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    /* Identity-bound recovery retirement durably publishes each private
     * no-replace quarantine before its final unlink. */
    CHECK_EQ_INT(g_reset_sync_calls, 8);
    gpg_manager_set_sync_base_fn(old_sync);
    CHECK(lstat(candidate, &st) != 0 && errno == ENOENT);
    CHECK(lstat(witness, &st) != 0 && errno == ENOENT);
    CHECK(lstat(quarantine, &st) != 0 && errno == ENOENT);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
}

TEST(full_reset_accepts_displaced_forward_writer_state) {
    char xdg[128], base[256], current[320];
    char candidate_home[320], expected_home[320], displaced_home[320];
    char candidate_marker[384], expected_marker[384], displaced_marker[384];
    char candidate[416], witness[416], quarantine[416];
    struct stat witness_identity;
    struct stat quarantine_identity;
    struct stat st;
    command_runner_fn old_runner;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(candidate_home, sizeof(candidate_home), "%s/candidate", base);
    snprintf(expected_home, sizeof(expected_home), "%s/expected", base);
    snprintf(displaced_home, sizeof(displaced_home), "%s/displaced", base);
    snprintf(candidate_marker, sizeof(candidate_marker),
             "%s/private.key", candidate_home);
    snprintf(expected_marker, sizeof(expected_marker),
             "%s/private.key", expected_home);
    snprintf(displaced_marker, sizeof(displaced_marker),
             "%s/private.key", displaced_home);
    snprintf(candidate, sizeof(candidate),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000002.p",
             base, (long)getpid());
    snprintf(witness, sizeof(witness),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000002.w",
             base, (long)getpid());
    snprintf(quarantine, sizeof(quarantine),
             "%s/.gitswitch-gpg-forward.%ld.6000000000000002.q",
             base, (long)getpid());
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(candidate_home, 0700), 0);
    CHECK_EQ_INT(mkdir(expected_home, 0700), 0);
    CHECK_EQ_INT(mkdir(displaced_home, 0700), 0);
    CHECK_EQ_INT(touch(candidate_marker), 0);
    CHECK_EQ_INT(touch(expected_marker), 0);
    CHECK_EQ_INT(touch(displaced_marker), 0);
    CHECK_EQ_INT(symlink(candidate_home, candidate), 0);
    CHECK_EQ_INT(symlink(expected_home, witness), 0);
    CHECK_EQ_INT(symlink(displaced_home, quarantine), 0);
    CHECK_EQ_INT(lstat(witness, &witness_identity), 0);
    CHECK_EQ_INT(lstat(quarantine, &quarantine_identity), 0);
    CHECK(witness_identity.st_dev != quarantine_identity.st_dev ||
          witness_identity.st_ino != quarantine_identity.st_ino);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);

    g_null_runner_calls = 0U;
    old_runner = run_set_runner(counting_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_null_runner_calls, 3);
    CHECK(lstat(candidate_home, &st) != 0 && errno == ENOENT);
    CHECK(lstat(expected_home, &st) != 0 && errno == ENOENT);
    CHECK(lstat(displaced_home, &st) != 0 && errno == ENOENT);
    CHECK(lstat(candidate, &st) != 0 && errno == ENOENT);
    CHECK(lstat(witness, &st) != 0 && errno == ENOENT);
    CHECK(lstat(quarantine, &st) != 0 && errno == ENOENT);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
}

TEST(gpg_manager_reset_reports_stable_link_cleanup_failure) {
    char xdg[128], base[256], current[320];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(current, 0700), 0); /* not a readable/removable symlink */

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1); /* pre-fix: 0 */
    run_set_runner(prev);

    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
}

/* A stable link to an existing directory outside the managed base is corrupt
 * state, not a live managed home. Full reset removes the link itself without
 * traversing or altering the external target. */
TEST(gpg_manager_reset_all_drops_external_live_target) {
    char xdg[128], base[256], current[320], external[256], marker[320];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(external, sizeof(external), "%s/external-gnupg", xdg);
    snprintf(marker, sizeof(marker), "%s/keep", external);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(external, current), 0);

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(prev);

    CHECK_EQ_INT(lstat(current, &st), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK(path_exists(marker));
}

TEST(gpg_manager_targeted_reset_drops_external_current_target) {
    char xdg[128], base[256], current[320], external[256], marker[320];
    struct stat st;
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(external, sizeof(external), "%s/external-gnupg", xdg);
    snprintf(marker, sizeof(marker), "%s/keep", external);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(external, current), 0);

    prev = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(prev);

    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    CHECK(path_exists(marker));
}

TEST(gpg_manager_reset_deletes_only_pinned_home_after_base_replacement) {
    char xdg[128], base[256], moved[256];
    char original_home[320], original_marker[384], moved_marker[384];
    char replacement_home[320], replacement_marker[384];
    command_runner_fn prev;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(moved, sizeof(moved), "%s/gitswitch-gpg.old", xdg);
    snprintf(original_home, sizeof(original_home), "%s/work", base);
    snprintf(original_marker, sizeof(original_marker), "%s/private.key",
             original_home);
    snprintf(replacement_home, sizeof(replacement_home), "%s/work", base);
    snprintf(replacement_marker, sizeof(replacement_marker), "%s/replacement",
             replacement_home);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(original_home, 0700), 0);
    CHECK_EQ_INT(touch(original_marker), 0);

    g_swap_base = base;
    g_swap_moved = moved;
    g_swap_replacement_home = replacement_home;
    g_swap_replacement_marker = replacement_marker;
    g_swap_pending = true;
    g_swap_used_pinned_home = false;
    prev = run_set_runner(swapping_gpgconf_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    run_set_runner(prev);

    snprintf(original_home, sizeof(original_home), "%s/work", moved);
    snprintf(moved_marker, sizeof(moved_marker), "%s/private.key", original_home);
    CHECK(g_swap_used_pinned_home);
    CHECK(path_exists(moved_marker));
    CHECK(path_exists(replacement_marker));
}

TEST(drop_current_sync_failure_is_retryable) {
    char xdg[128], base[256], home[320], current[320];
    struct stat st;
    gpg_sync_base_fn old_sync;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    g_reset_sync_calls = 0;
    g_fail_reset_sync = true;
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    CHECK_EQ_INT(gpg_manager_drop_current(), -1);
    CHECK_EQ_INT(g_reset_sync_calls, 1);
    CHECK(strstr(get_last_error()->message, "not durable") != NULL);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);

    /* The retry must sync even though the first attempt already unlinked the
     * name; otherwise there is no way to repair an uncertain directory entry. */
    g_fail_reset_sync = false;
    CHECK_EQ_INT(gpg_manager_drop_current(), 0);
    CHECK_EQ_INT(g_reset_sync_calls, 2);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    gpg_manager_set_sync_base_fn(old_sync);
}

TEST(targeted_reset_sync_failure_is_retryable) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    struct stat st;
    gpg_sync_base_fn old_sync;
    command_runner_fn previous;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    g_reset_sync_calls = 0;
    g_fail_reset_sync = true;
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    previous = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    CHECK_EQ_INT(g_reset_sync_calls, 2);
    check_reset_witness_sync_failure_chain();
    CHECK(lstat(home, &st) != 0 && errno == ENOENT);
    /* Reset cannot publish its quarantine until the identity witness is
     * durable, so an early fsync failure deliberately retains `current`. */
    CHECK_EQ_INT(lstat(current, &st), 0);

    g_fail_reset_sync = false;
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    CHECK_EQ_INT(g_reset_sync_calls, 8);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    run_set_runner(previous);
    gpg_manager_set_sync_base_fn(old_sync);
}

TEST(full_reset_sync_failure_is_retryable) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    struct stat st;
    gpg_sync_base_fn old_sync;
    command_runner_fn previous;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    g_reset_sync_calls = 0;
    g_fail_reset_sync = true;
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    previous = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(g_reset_sync_calls, 2);
    check_reset_witness_sync_failure_chain();
    CHECK(lstat(home, &st) != 0 && errno == ENOENT);
    CHECK_EQ_INT(lstat(current, &st), 0);

    g_fail_reset_sync = false;
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    /* Full-reset recovery retirement durably publishes its private
     * no-replace quarantine before final unlink. */
    CHECK_EQ_INT(g_reset_sync_calls, 9);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    run_set_runner(previous);
    gpg_manager_set_sync_base_fn(old_sync);
}

/* AR-14 L25: the authoritative full-reset scan must happen after the final
 * potentially blocking durability barrier. A same-UID writer represented by
 * this sync seam lands a valid recovery entry while that barrier is active.
 * The pre-fix order scanned first and returned success with the late entry. */
TEST(full_reset_rechecks_after_final_sync) {
    char xdg[128], base[256], residue[416];
    struct stat st;
    gpg_sync_base_fn old_sync;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    snprintf(g_late_reset_sync_residue,
             sizeof(g_late_reset_sync_residue),
             ".gitswitch-gpg-rollback.%ld.abcdef0123456789",
             (long)getpid());
    snprintf(residue, sizeof(residue), "%s/%s", base,
             g_late_reset_sync_residue);

    g_reset_sync_calls = 0;
    g_fail_reset_sync = false;
    g_inject_late_reset_sync_residue = true;
    old_sync = gpg_manager_set_sync_base_fn(record_reset_sync);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    CHECK_EQ_INT(g_reset_sync_calls, 1);
    CHECK_EQ_INT(lstat(residue, &st), 0);
    CHECK(S_ISLNK(st.st_mode));

    /* With the one-shot writer disabled, the next reset safely plans and
     * retires the exact late residue before its post-sync final scan. */
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    CHECK(lstat(residue, &st) != 0 && errno == ENOENT);
    gpg_manager_set_sync_base_fn(old_sync);
    g_late_reset_sync_residue[0] = '\0';
}

TEST(targeted_reset_restores_current_replaced_after_capture) {
    char xdg[128], base[256], work[320], other[320], marker[384];
    char current[320], target[MAX_PATH_LEN];
    struct stat survived;
    ssize_t target_len;
    gpg_reset_current_hook_fn old_hook;
    command_runner_fn previous;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(work, sizeof(work), "%s/work", base);
    snprintf(other, sizeof(other), "%s/other", base);
    snprintf(marker, sizeof(marker), "%s/private.key", other);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(work, 0700), 0);
    CHECK_EQ_INT(mkdir(other, 0700), 0);
    CHECK_EQ_INT(touch(marker), 0);
    CHECK_EQ_INT(symlink(work, current), 0);

    g_reset_replacement_target = other;
    memset(&g_reset_replacement_identity, 0,
           sizeof(g_reset_replacement_identity));
    old_hook = gpg_manager_set_reset_current_hook_fn(
        replace_current_after_reset_capture);
    previous = run_set_runner(null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    gpg_manager_set_reset_current_hook_fn(old_hook);

    CHECK(strstr(get_last_error()->message, "later writer preserved") != NULL);
    CHECK_EQ_INT(lstat(current, &survived), 0);
    CHECK_EQ_INT(survived.st_dev, g_reset_replacement_identity.st_dev);
    CHECK_EQ_INT(survived.st_ino, g_reset_replacement_identity.st_ino);
    target_len = readlink(current, target, sizeof(target) - 1);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, other);
    }
    CHECK(path_exists(marker));

    /* The partial result is truthful and leaves no hidden quarantine: a retry
     * sees the unrelated live selection, preserves it, and succeeds. */
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    CHECK_EQ_INT(lstat(current, &survived), 0);
    CHECK_EQ_INT(survived.st_dev, g_reset_replacement_identity.st_dev);
    CHECK_EQ_INT(survived.st_ino, g_reset_replacement_identity.st_ino);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(previous);
    g_reset_replacement_target = NULL;
}

/* Test-local mirror of the manager's tmpfs probe, so the assertions below can
 * adapt to where the suite happens to run instead of hard-assuming /tmp is
 * tmpfs (it isn't on FreeBSD/macOS CI) or the workspace is disk (it usually is). */
static bool test_dir_is_tmpfs(const char *path) {
#ifdef __linux__
    struct statfs sfs;
    return statfs(path, &sfs) == 0 &&
           ((unsigned long)sfs.f_type == 0x01021994UL ||
            (unsigned long)sfs.f_type == 0x858458f6UL);
#else
    struct statfs sfs;
    return statfs(path, &sfs) == 0 && strcmp(sfs.f_fstypename, "tmpfs") == 0;
#endif
}

TEST(create_isolated_home_reprobes_exact_base_fd_each_time) {
    char xdg[128], base[256], alpha[320], beta[320];
    gpg_config_t alpha_config;
    gpg_config_t beta_config;
    account_t alpha_account;
    account_t beta_account;
    gpg_memory_backed_probe_fn old_probe;
    command_runner_fn old_runner;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(alpha, sizeof(alpha), "%s/alpha", base);
    snprintf(beta, sizeof(beta), "%s/beta", base);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    memset(&alpha_config, 0, sizeof(alpha_config));
    memset(&beta_config, 0, sizeof(beta_config));
    memset(&alpha_account, 0, sizeof(alpha_account));
    memset(&beta_account, 0, sizeof(beta_account));
    alpha_config.mode = GPG_MODE_ISOLATED;
    beta_config.mode = GPG_MODE_ISOLATED;
    snprintf(alpha_account.name, sizeof(alpha_account.name), "alpha");
    snprintf(beta_account.name, sizeof(beta_account.name), "beta");

    g_memory_probe_expected_base = base;
    g_memory_probe_calls = 0U;
    g_memory_probe_exact_fd = true;
    old_probe = gpg_manager_set_memory_backed_probe_fn(
        sequential_memory_backed_probe);
    old_runner = run_set_runner(null_runner);

    CHECK_EQ_INT(gpg_create_isolated_home(&alpha_config, &alpha_account), 0);
    CHECK(path_exists(alpha));
    CHECK_EQ_INT(gpg_create_isolated_home(&beta_config, &beta_account), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(!path_exists(beta));
    CHECK_EQ_INT((int)g_memory_probe_calls, 2);
    CHECK(g_memory_probe_exact_fd);

    gpg_manager_set_memory_backed_probe_fn(old_probe);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(old_runner);
    g_memory_probe_expected_base = NULL;
}

TEST(repeated_home_getters_probe_fallback_warning_path_once) {
    char expected[MAX_PATH_LEN];
    char quiet[MAX_PATH_LEN];
    char first[MAX_PATH_LEN];
    char second[MAX_PATH_LEN];
    gpg_base_warning_probe_fn old_probe;

    CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    CHECK_EQ_INT(safe_snprintf(expected, sizeof(expected),
                               "/tmp/gitswitch-gpg-%d", getuid()), 0);
    g_warning_probe_expected_base = expected;
    g_warning_probe_calls = 0U;
    g_warning_probe_exact_path = true;
    old_probe = gpg_manager_set_base_warning_probe_fn(
        positive_base_warning_probe);

    CHECK_EQ_INT(gpg_manager_get_home_path_quiet(quiet, sizeof(quiet)), 0);
    CHECK_EQ_INT((int)g_warning_probe_calls, 0);
    CHECK_EQ_INT(gpg_manager_get_home_path(first, sizeof(first)), 0);
    CHECK_EQ_INT(gpg_manager_get_home_path(second, sizeof(second)), 0);
    CHECK_STR_EQ(first, second);
    CHECK_EQ_INT((int)g_warning_probe_calls, 1);
    CHECK(g_warning_probe_exact_path);

    gpg_manager_set_base_warning_probe_fn(old_probe);
    g_warning_probe_expected_base = NULL;
}

TEST(create_isolated_home_rejects_base_replaced_during_fd_probe) {
    char xdg[128], base[256], moved[256];
    char replacement_home[320], moved_home[320];
    gpg_config_t config;
    account_t account;
    gpg_memory_backed_probe_fn old_probe;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(moved, sizeof(moved), "%s/gitswitch-gpg.probed", xdg);
    snprintf(replacement_home, sizeof(replacement_home), "%s/work", base);
    snprintf(moved_home, sizeof(moved_home), "%s/work", moved);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    memset(&config, 0, sizeof(config));
    memset(&account, 0, sizeof(account));
    config.mode = GPG_MODE_ISOLATED;
    snprintf(account.name, sizeof(account.name), "work");

    g_memory_probe_expected_base = base;
    g_memory_probe_moved_base = moved;
    g_memory_probe_calls = 0U;
    g_memory_probe_exact_fd = true;
    old_probe = gpg_manager_set_memory_backed_probe_fn(
        replacing_memory_backed_probe);

    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(strstr(get_last_error()->message,
                 "no longer names the probed directory") != NULL);
    CHECK_EQ_INT((int)g_memory_probe_calls, 1);
    CHECK(g_memory_probe_exact_fd);
    CHECK(!path_exists(replacement_home));
    CHECK(!path_exists(moved_home));

    gpg_manager_set_memory_backed_probe_fn(old_probe);
    CHECK_EQ_INT(rmdir(base), 0);
    CHECK_EQ_INT(rmdir(moved), 0);
    CHECK_EQ_INT(rmdir(xdg), 0);
    g_memory_probe_expected_base = NULL;
    g_memory_probe_moved_base = NULL;
}

TEST(create_isolated_home_fails_closed_on_fd_probe_error) {
    char xdg[128], base[256], home[320];
    gpg_config_t config;
    account_t account;
    gpg_memory_backed_probe_fn old_probe;

    CHECK_EQ_INT(make_xdg(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    memset(&config, 0, sizeof(config));
    memset(&account, 0, sizeof(account));
    config.mode = GPG_MODE_ISOLATED;
    snprintf(account.name, sizeof(account.name), "work");

    g_memory_probe_expected_base = base;
    g_memory_probe_calls = 0U;
    g_memory_probe_exact_fd = true;
    old_probe = gpg_manager_set_memory_backed_probe_fn(
        failing_memory_backed_probe);

    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK(strstr(get_last_error()->message,
                 "Cannot prove isolated GPG base is memory-backed") != NULL);
    CHECK_EQ_INT((int)g_memory_probe_calls, 1);
    CHECK(g_memory_probe_exact_fd);
    CHECK(!path_exists(home));

    gpg_manager_set_memory_backed_probe_fn(old_probe);
    CHECK_EQ_INT(rmdir(base), 0);
    CHECK_EQ_INT(rmdir(xdg), 0);
    g_memory_probe_expected_base = NULL;
}

/* AR-02 #3/#22: the no-persistent-disk guard must fire on the ACTUAL computed
 * base dir — including one under XDG_RUNTIME_DIR, which used to bypass the
 * check entirely — failing closed without the GITSWITCH_ALLOW_TMP_GPG opt-in
 * and proceeding with it. */
TEST(create_isolated_home_refuses_persistent_xdg_base) {
    char cwd[512], xdg[768], home_expect[1024];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    /* A directory in the build tree: persistent disk in CI and on dev boxes.
     * If this workspace is itself tmpfs-backed, the scenario can't be built
     * here — skip rather than assert a wrong premise. */
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        CHECK(false);
        return;
    }
    if (test_dir_is_tmpfs(cwd)) {
        TS_SKIP("persistent-fs",
                "persistent-filesystem premise unavailable on tmpfs workspace");
    }
    snprintf(xdg, sizeof(xdg), "%s/build/gswgpg-xdg-XXXXXX", cwd);
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "t");

    prev = run_set_runner(null_runner);

    /* Pre-fix this SUCCEEDED, silently placing secret keys on disk. */
    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    snprintf(home_expect, sizeof(home_expect), "%s/gitswitch-gpg/t", xdg);
    CHECK(!path_exists(home_expect));

    /* Explicit opt-in still works (documented escape hatch). */
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), 0);
    CHECK(path_exists(home_expect));

    /* Cleanup through the manager itself (base is valid 0700). */
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    run_set_runner(prev);
}

TEST_MAIN_BEGIN()
    static const char *const trusted_commands[] = {
        "gpg", "gpgconf", NULL
    };
    ts_trusted_command_fixture_t command_fixture = {0};

    error_init(LOG_LEVEL_ERROR, NULL);
#if !defined(__FreeBSD__)
    gpg_manager_set_identity_unlink_fn(identity_unlink_for_test);
#endif
    if (ts_trusted_command_fixture_install(
            &command_fixture, "gsw-ar11-gpg-reset", trusted_commands) != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot install trusted GnuPG fixture\n");
        return 1;
    }
    RUN_TEST(gpg_manager_reset_rejects_empty_selector_without_mutation);
    RUN_TEST(gpg_manager_reset_rejects_traversal);
    RUN_TEST(gpg_manager_reset_refuses_symlinked_base);
    RUN_TEST(gpg_manager_reset_single_account_refuses_symlinked_home);
    RUN_TEST(gpg_manager_reset_blocks_on_base_lock);
    RUN_TEST(gpg_manager_reset_fails_closed_when_lock_unavailable);
    RUN_TEST(gpg_manager_reset_retains_home_when_agent_stop_fails);
    RUN_TEST(gpg_manager_reset_reports_recursive_removal_failure);
    RUN_TEST(gpg_manager_reset_all_aggregates_failures_and_continues);
    RUN_TEST(gpg_manager_reset_all_retains_first_structured_cause);
    RUN_TEST(gpg_manager_reset_all_reports_readdir_failure);
    RUN_TEST(full_reset_final_scan_failure_preserves_complete_plan);
    RUN_TEST(full_reset_revalidation_preserves_later_current_and_recovery_plan);
    RUN_TEST(full_reset_revalidation_preserves_later_recovery_entry);
    RUN_TEST(full_reset_forward_quarantine_sync_failure_is_retryable);
    RUN_TEST(full_reset_accepts_displaced_forward_writer_state);
    RUN_TEST(gpg_manager_reset_reports_stable_link_cleanup_failure);
    RUN_TEST(gpg_manager_reset_all_drops_external_live_target);
    RUN_TEST(gpg_manager_targeted_reset_drops_external_current_target);
    RUN_TEST(gpg_manager_reset_deletes_only_pinned_home_after_base_replacement);
    RUN_TEST(drop_current_sync_failure_is_retryable);
    RUN_TEST(targeted_reset_sync_failure_is_retryable);
    RUN_TEST(full_reset_sync_failure_is_retryable);
    RUN_TEST(full_reset_rechecks_after_final_sync);
    RUN_TEST(targeted_reset_restores_current_replaced_after_capture);
    RUN_TEST(create_isolated_home_reprobes_exact_base_fd_each_time);
    RUN_TEST(repeated_home_getters_probe_fallback_warning_path_once);
    RUN_TEST(create_isolated_home_rejects_base_replaced_during_fd_probe);
    RUN_TEST(create_isolated_home_fails_closed_on_fd_probe_error);
    RUN_TEST(create_isolated_home_refuses_persistent_xdg_base);
    if (ts_trusted_command_fixture_restore(&command_fixture) != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot restore PATH after GPG reset tests\n");
        return 1;
    }
TEST_MAIN_END()
