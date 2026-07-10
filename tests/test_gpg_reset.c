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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "test.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(gpg_manager_reset_rejects_traversal);
    RUN_TEST(gpg_manager_reset_refuses_symlinked_base);
TEST_MAIN_END()
