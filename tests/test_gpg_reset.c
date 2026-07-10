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
#include "utils.h"
#include "error.h"

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

/* Swallow gpgconf --kill (and anything else) without executing it. */
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

/* Fresh scratch XDG_RUNTIME_DIR; returns 0 on success. */
static int make_xdg(char *dir, size_t size) {
    snprintf(dir, size, "/tmp/gswgpgrst_XXXXXX");
    if (!mkdtemp(dir)) return -1;
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

/* A crafted account name must never become a deletable path component that
 * escapes <base>. The victim dir sits exactly where "../victim" would land. */
TEST(gpg_manager_reset_rejects_traversal) {
    char xdg[128], base[256], home[512], victim[256], marker[512], keep[512];
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
    char xdg[128], realbase[256], link_path[256], acct[512], marker[512];
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
 * same lock the switch's `current` retarget takes — so its dangling-symlink
 * cleanup cannot TOCTOU a concurrent switch. A child process holds the lock
 * and only writes its "done" marker after a deliberate delay; a reset that
 * genuinely blocks on the lock returns only after that marker exists, while
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
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    if (test_dir_is_tmpfs(cwd)) {
        return;
    }
    snprintf(xdg, sizeof(xdg), "%s/build/gswgpg-xdg-XXXXXX", cwd);
    CHECK(mkdtemp(xdg) != NULL);
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
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(gpg_manager_reset_rejects_traversal);
    RUN_TEST(gpg_manager_reset_refuses_symlinked_base);
    RUN_TEST(gpg_manager_reset_single_account_refuses_symlinked_home);
    RUN_TEST(gpg_manager_reset_blocks_on_base_lock);
    RUN_TEST(create_isolated_home_refuses_persistent_xdg_base);
TEST_MAIN_END()
