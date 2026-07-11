/* Security regression tests for the config reader/writer:
 * - cfg-symlink-01/02: a symlinked accounts.toml (or backup destination) is
 *   refused on both the read and the write path; normal regular-file
 *   operation is unchanged.
 * - int-id-01/02: account ids are canonical decimals; out-of-range or
 *   non-canonical spellings never wrap/alias onto another account.
 * - tty-escape: terminal control bytes in description/name are stripped or
 *   rejected at config load / account validation, never handed to display. */
#include "test.h"
#include "gitswitch.h"
#include "config.h"
#include "signals.h"
#include "error.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>

/* Minimal valid config: one account, no key material (so no key-permission
 * checks fire in validate_account_security). */
static const char *valid_config =
    "[settings]\n"
    "default_scope = \"local\"\n"
    "\n"
    "[accounts.1]\n"
    "name = \"alice\"\n"
    "email = \"a@b.com\"\n"
    "description = \"day job\"\n";

/* Create a fresh 0700 scratch directory for one test. */
static int make_scratch_dir(char *dir, size_t size) {
    snprintf(dir, size, "/tmp/gswcfgtest.XXXXXX");
    return mkdtemp(dir) ? 0 : -1;
}

/* Write content to path with the 0600 mode the loader requires. */
static int write_config(const char *path, const char *content, size_t len) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (fwrite(content, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return chmod(path, 0600);
}

static size_t slurp(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) return 0;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

static int join_path(char *dest, size_t size, const char *base,
                     const char *suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);

    if (base_len >= size || suffix_len > size - base_len - 1) {
        return -1;
    }
    memcpy(dest, base, base_len);
    memcpy(dest + base_len, suffix, suffix_len + 1);
    return 0;
}

static void save_home_env(char *buf, size_t size) {
    const char *home = getenv("HOME");
    snprintf(buf, size, "%s", home ? home : "");
}

static void restore_home_env(const char *saved) {
    if (saved[0] != '\0') setenv("HOME", saved, 1);
    else unsetenv("HOME");
}

static void fill_account(account_t *a, uint32_t id, const char *name,
                         const char *email, const char *desc) {
    memset(a, 0, sizeof(*a));
    a->id = id;
    strncpy(a->name, name, sizeof(a->name) - 1);
    strncpy(a->email, email, sizeof(a->email) - 1);
    strncpy(a->description, desc, sizeof(a->description) - 1);
    a->preferred_scope = GIT_SCOPE_LOCAL;
}

/* ---- cfg-symlink-01/02: read path ---- */

TEST(load_accepts_regular_file) {
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, valid_config, strlen(valid_config)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].name, "alice");
        CHECK_EQ_INT(ctx.accounts[0].id, 1);
    }
}

TEST(load_rejects_symlinked_config) {
    /* The symlink target is a file that passes every *content* check (ours,
     * 0600, valid TOML), so the old stat()-based validation followed the
     * link and accepted it; the fix must refuse on the link itself. */
    char dir[128], real[256], link[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(real, sizeof(real), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(real, valid_config, strlen(valid_config)), 0);
    CHECK_EQ_INT(symlink(real, link), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, link), -1);
    CHECK_EQ_INT(ctx.account_count, 0);
}

/* ---- AR-04 L2: the final config-directory component is no-follow -------- */

static void check_symlinked_config_directory_refused(mode_t target_mode) {
    char home[128], saved_home[512];
    char dotconfig[256], target[256], link[256], sentinel[512];
    char accounts[512], linked_accounts[512], lock[512], hint[512];
    char before[128], after[128];
    struct stat link_st, target_st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(target, sizeof(target), "%s/config-target", home);
    CHECK_EQ_INT(join_path(link, sizeof(link), dotconfig, "/gitswitch"), 0);
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel", target);
    snprintf(accounts, sizeof(accounts), "%s/accounts.toml", target);
    snprintf(linked_accounts, sizeof(linked_accounts), "%s/accounts.toml", link);
    snprintf(lock, sizeof(lock), "%s/.config.lock", target);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", target);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(target, target_mode), 0);
    CHECK_EQ_INT(chmod(target, target_mode), 0); /* do not let umask alter the case */
    CHECK_EQ_INT(write_config(sentinel, "target-content\n", 15), 0);
    CHECK(slurp(sentinel, before, sizeof(before)) > 0);
    CHECK_EQ_INT(symlink(target, link), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);

    /* Every mutating entry point that prepares the directory must refuse too;
     * no config, lock, or resume marker may appear through the link. */
    int lock_fd = config_write_lock();
    CHECK_EQ_INT(lock_fd, -1);
    if (lock_fd >= 0) config_write_unlock(lock_fd);
    CHECK_EQ_INT(config_create_default(linked_accounts), -1);

    CHECK_EQ_INT(lstat(link, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));
    CHECK_EQ_INT(stat(target, &target_st), 0);
    CHECK_EQ_INT((long)(target_st.st_mode & 0777), (long)target_mode);
    CHECK(slurp(sentinel, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);
    CHECK(access(accounts, F_OK) != 0);
    CHECK(access(lock, F_OK) != 0);
    CHECK(access(hint, F_OK) != 0);

    restore_home_env(saved_home);
}

TEST(config_init_rejects_symlinked_final_directory_without_mutation) {
    check_symlinked_config_directory_refused(0755);
    check_symlinked_config_directory_refused(0700);
}

TEST(config_init_rejects_nondirectory_final_components) {
    char home[128], saved_home[512], dotconfig[256], final[256];
    char before[64], after[64];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    CHECK_EQ_INT(join_path(final, sizeof(final), dotconfig, "/gitswitch"), 0);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(write_config(final, "not-a-directory\n", 16), 0);
    CHECK(slurp(final, before, sizeof(before)) > 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK(slurp(final, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);

    CHECK_EQ_INT(unlink(final), 0);
    CHECK_EQ_INT(mkfifo(final, 0600), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISFIFO(st.st_mode));

    restore_home_env(saved_home);
}

TEST(config_init_secures_real_or_absent_final_directory) {
    char home[128], saved_home[512], dotconfig[256], final[256];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    CHECK_EQ_INT(join_path(final, sizeof(final), dotconfig, "/gitswitch"), 0);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(final, 0755), 0);
    CHECK_EQ_INT(chmod(final, 0755), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);

    /* Absent final component (and parent) is still created normally. */
    char home2[128], final2[256];
    CHECK_EQ_INT(make_scratch_dir(home2, sizeof(home2)), 0);
    CHECK_EQ_INT(setenv("HOME", home2, 1), 0);
    snprintf(final2, sizeof(final2), "%s/.config/gitswitch", home2);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(lstat(final2, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);

    restore_home_env(saved_home);
}

/* ---- AR-04: private metadata nodes are no-follow and nonblocking -------- */

TEST(config_lock_rejects_symlink_fifo_and_unsafe_mode) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char lock[640], victim[640], before[64], after[64];
    struct stat st;
    int fd, fifo_reader;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(lock, sizeof(lock), "%s/.config.lock", config_dir);
    snprintf(victim, sizeof(victim), "%s/lock-victim", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(victim, "victim-content\n", 15), 0);
    CHECK(slurp(victim, before, sizeof(before)) > 0);
    CHECK_EQ_INT(symlink(victim, lock), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1); /* pre-fix: locks the symlink target */
    if (fd >= 0) config_write_unlock(fd);
    CHECK_EQ_INT(lstat(lock, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK(slurp(victim, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);

    CHECK_EQ_INT(unlink(lock), 0);
    CHECK_EQ_INT(mkfifo(lock, 0600), 0);
    /* Keep a nonblocking reader open so the old O_WRONLY path cannot hang the
     * regression process; it would open and incorrectly return a FIFO fd. */
    fifo_reader = open(lock, O_RDONLY | O_NONBLOCK);
    CHECK(fifo_reader >= 0);
    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1);
    if (fd >= 0) config_write_unlock(fd);
    if (fifo_reader >= 0) close(fifo_reader);

    CHECK_EQ_INT(unlink(lock), 0);
    CHECK_EQ_INT(write_config(lock, "", 0), 0);
    CHECK_EQ_INT(chmod(lock, 0660), 0);
    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1);
    if (fd >= 0) config_write_unlock(fd);

    CHECK_EQ_INT(chmod(lock, 0600), 0);
    fd = config_write_lock();
    CHECK(fd >= 0);
    if (fd >= 0) config_write_unlock(fd);

    restore_home_env(saved_home);
}

static int config_lock_child_contended(void) {
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) return -1;
    if (pid == 0) {
        int token = config_write_lock();
        if (token >= 0) {
            config_write_unlock(token);
            _exit(1); /* entered a replacement lock domain */
        }
        if (errno == EWOULDBLOCK
#if EAGAIN != EWOULDBLOCK
            || errno == EAGAIN
#endif
        ) {
            _exit(0);
        }
        _exit(2);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

TEST(config_lock_survives_post_acquisition_namespace_replacement) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char moved_dir[512], lock[640], moved_lock[640];
    int token;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(moved_dir, sizeof(moved_dir), "%s/gitswitch.moved", dotconfig);
    snprintf(lock, sizeof(lock), "%s/.config.lock", config_dir);
    snprintf(moved_lock, sizeof(moved_lock), "%s/.config.lock.old", config_dir);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    token = config_write_lock();
    CHECK(token >= 0);
    CHECK_EQ_INT(rename(lock, moved_lock), 0);
    CHECK_EQ_INT(write_config(lock, "", 0), 0);
    CHECK_EQ_INT(config_lock_child_contended(), 0);
    if (token >= 0) config_write_unlock(token);

    token = config_write_lock();
    CHECK(token >= 0);
    CHECK_EQ_INT(rename(config_dir, moved_dir), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(config_lock_child_contended(), 0);
    if (token >= 0) config_write_unlock(token);

    token = config_write_lock();
    CHECK(token >= 0);
    if (token >= 0) config_write_unlock(token);
    restore_home_env(saved_home);
}

TEST(config_init_preserves_symlinked_parent_policy) {
    char home[128], saved_home[512], parent[256], parent_link[256];
    char final[512], accounts[512];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(parent, sizeof(parent), "%s/config-parent", home);
    snprintf(parent_link, sizeof(parent_link), "%s/.config", home);
    snprintf(final, sizeof(final), "%s/gitswitch", parent);
    CHECK_EQ_INT(join_path(accounts, sizeof(accounts), final,
                           "/accounts.toml"), 0);
    CHECK_EQ_INT(mkdir(parent, 0700), 0);
    CHECK_EQ_INT(mkdir(final, 0755), 0);
    CHECK_EQ_INT(chmod(final, 0755), 0);
    CHECK_EQ_INT(write_config(accounts, valid_config, strlen(valid_config)), 0);
    CHECK_EQ_INT(symlink(parent, parent_link), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(lstat(parent_link, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);

    restore_home_env(saved_home);
}

/* ---- cfg-symlink-01: write + backup path ---- */

TEST(save_refuses_symlinked_config_path) {
    char dir[128], victim[256], link[256], buf[1024];
    const char *secret = "SECRET-VICTIM-CONTENT\n";
    gitswitch_ctx_t ctx;
    struct stat st;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(victim, sizeof(victim), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(victim, secret, strlen(secret)), 0);
    CHECK_EQ_INT(symlink(victim, link), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;

    /* Must fail closed: no write through the link, no backup made of the
     * link target, victim bytes untouched, and the link still a link. */
    CHECK_EQ_INT(config_save(&ctx, link), -1);
    slurp(victim, buf, sizeof(buf));
    CHECK_STR_EQ(buf, secret);
    CHECK_EQ_INT(lstat(link, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(backup_refuses_symlinked_source) {
    /* config_backup on a symlinked config would read *through* the link,
     * copying another user's file into a 0600 backup we own. */
    char dir[128], victim[256], link[256];
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(victim, sizeof(victim), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(victim, "x\n", 2), 0);
    CHECK_EQ_INT(symlink(victim, link), 0);

    CHECK_EQ_INT(config_backup(link), -1);
}

TEST(save_and_reload_regular_path_roundtrip) {
    /* Normal operation must be unchanged: save to a real path, verify the
     * installed file is 0600, reload it and find the account again. Save a
     * second time to exercise the (no-follow) backup branch too. */
    char dir[128], path[256];
    gitswitch_ctx_t ctx, reloaded;
    struct stat st;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;

    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK_EQ_INT(lstat(path, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0600);

    CHECK_EQ_INT(config_save(&ctx, path), 0); /* second save: backup branch */

    memset(&reloaded, 0, sizeof(reloaded));
    CHECK_EQ_INT(config_load(&reloaded, path), 0);
    CHECK_EQ_INT(reloaded.account_count, 1);
    if (reloaded.account_count == 1) {
        CHECK_STR_EQ(reloaded.accounts[0].name, "alice");
    }
}

/* ---- int-id-02: identifier lookup must not wrap ---- */

TEST(find_account_rejects_out_of_range_and_noncanonical_ids) {
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "work", "w@x.com", "day job");
    fill_account(&ctx.accounts[1], 2, "home", "h@x.com", "home");
    ctx.account_count = 2;

    /* 2^32 truncated to uint32_t is 0; 2^32+1 is 1; the unsigned conversion
     * of -4294967295 is also 1. None of these may resolve to an account. */
    CHECK(config_find_account(&ctx, "4294967296") == NULL);
    CHECK(config_find_account(&ctx, "4294967297") == NULL);
    CHECK(config_find_account(&ctx, "-4294967295") == NULL);
    /* Ids are stored canonically, so "01" is not id 1 (and no such name). */
    CHECK(config_find_account(&ctx, "01") == NULL);
    /* Way past ULONG_MAX: strtoul clamps + sets ERANGE; must not match. */
    CHECK(config_find_account(&ctx, "99999999999999999999999999") == NULL);

    /* The canonical spelling still resolves. */
    account_t *a = config_find_account(&ctx, "1");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 1);
}

/* ---- int-id-01/02: load path rejects non-canonical / out-of-range ids ---- */

TEST(load_skips_leading_zero_id_section) {
    /* "accounts.01" used to load as id 1 — an alias of "accounts.1" that
     * dodges the duplicate-id check by spelling. It must be skipped (and
     * counted, so a later save cannot silently erase it). */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.01]\n"
        "name = \"alias\"\n"
        "email = \"a@b.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
}

TEST(load_counts_unknown_keys_in_recognized_sections) {
    /* AR-06 F02: a key gitswitch does not model, sitting inside an otherwise
     * recognized [settings]/[accounts.N] section, is invisible to config_save's
     * rebuild and would be silently erased by the next save. It must be counted
     * so config_check_rewritable refuses the rewrite. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "custom_flag = \"keepme\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "my_note = \"important\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    /* The account still loads; the unknown keys are counted, not dropped. */
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 0);
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 0);
    CHECK_EQ_INT(ctx.unknown_keys_on_load, 2);
    /* A full rewrite is refused so the keys aren't erased. */
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
}

TEST(load_accepts_only_modeled_keys) {
    /* Control: a config with ONLY modeled keys must NOT be flagged. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "active_account = \"alice\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "description = \"d\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.unknown_keys_on_load, 0);
    CHECK_EQ_INT(config_check_rewritable(&ctx), 0);
}

TEST(load_skips_out_of_range_id_section) {
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.4294967296]\n"   /* 2^32: would truncate to id 0 */
        "name = \"wrap\"\n"
        "email = \"a@b.com\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) CHECK_EQ_INT(ctx.accounts[0].id, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
}

/* AR-02 #5: an over-long name is schema-valid (TOML allows values up to 511
 * bytes; MAX_NAME_LEN is 256), so the whole-file parse succeeds and only the
 * per-field toml_get_string copy fails. That failure used to `continue`
 * WITHOUT counting the section as skipped, so config_save's refuse-to-rewrite
 * guard read zero and the next save (e.g. `remove <other>`) permanently
 * erased the over-long account's section. */
TEST(load_counts_overlong_name_as_skipped_and_save_preserves_it) {
    char cfg[1024];
    char longname[300];
    char dir[128], path[256];
    char after[1024];
    gitswitch_ctx_t ctx;
    FILE *f;
    size_t n;

    memset(longname, 'N', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"local\"\n"
             "[accounts.1]\n"
             "name = \"%s\"\n"
             "email = \"long@b.com\"\n"
             "\n"
             "[accounts.2]\n"
             "name = \"alice\"\n"
             "email = \"a@b.com\"\n",
             longname);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);          /* alice still loads */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1); /* pre-fix: 0 */

    /* The save must refuse the rewrite AND say so in its return value
     * (AR-03 M9: the old `return 0` refusal made add/edit report success
     * for a discarded change), keeping the over-long section on disk for
     * the user to repair. */
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    f = fopen(path, "r");
    CHECK(f != NULL);
    n = f ? fread(after, 1, sizeof(after) - 1, f) : 0;
    if (f) fclose(f);
    after[n] = '\0';
    CHECK(strstr(after, longname) != NULL);      /* pre-fix: erased */
}

/* ---- AR-02 #27: config_save's own scratch registration ---- */

TEST(config_save_registers_and_unregisters_its_temp) {
    /* config_save registers "<path>.tmp.<pid>" for signal cleanup for exactly
     * the span the temp exists (the registration accounts_switch used to make
     * never covered the real save — it ran after the registry was torn down).
     * After a completed save the slot must be RELEASED: a stale registration
     * would let a later emergency cleanup unlink an unrelated file that
     * happens to be recreated at that name. */
    char dir[128], path[256], tmp[512];
    gitswitch_ctx_t ctx;
    FILE *f;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    CHECK_EQ_INT(config_save(&ctx, path), 0);

    /* Recreate a file at the temp's deterministic name and run the scratch
     * cleanup: an unreleased registration would delete it. */
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    f = fopen(tmp, "w");
    CHECK(f != NULL);
    if (f) fclose(f);
    signals_scratch_cleanup();
    CHECK(access(tmp, F_OK) == 0); /* untouched: registration was released */
    unlink(tmp);
}

/* ---- tty-escape: control bytes must not survive to display fields ---- */

TEST(load_strips_cr_from_description) {
    /* The classic line-overwrite spoof: an escape-decoded \r renders
     * "[CURRENT] trusted" over the real row. Locks the layered guarantee —
     * whichever layer handles it, no CR may reach the loaded description.
     * Since AR-03 M6 toml_get_string REFUSES a value sanitization would
     * alter instead of repairing it; the loader now treats such a PRESENT-
     * but-unloadable description as a skip of the whole account (counted,
     * so config_save refuses to rewrite) — the old description-absent
     * fallback (name) was a silent alteration the next save persisted over
     * the user's on-disk bytes (AR-03 T4-owner flag (b)). */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "description = \"evil\\r[CURRENT] trusted\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 0);            /* skipped, not repaired */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1); /* save guard covers it */
}

TEST(load_rejects_raw_c1_byte_in_file) {
    /* Raw C1 bytes (0x9B is a one-byte CSI) in the file are refused at the
     * character-set gate before parsing; lock that layered guarantee. */
    char cfg[256];
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    int len = snprintf(cfg, sizeof(cfg),
                       "[accounts.1]\n"
                       "name = \"alice\"\n"
                       "email = \"a@b.com\"\n"
                       "description = \"x%c31mY\"\n", 0x9B);
    CHECK(len > 0);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, (size_t)len), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
}

TEST(add_rejects_c1_and_malformed_utf8_in_name) {
    /* The interactive add/edit path takes raw prompt input; validate_name
     * only rejects C0/DEL, so C1 controls used to pass. The name keys the
     * SSH/GPG isolation paths, so it is rejected, not rewritten. */
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work\xC2\x9B" "31m", "w@x.com", "d"); /* UTF-8 C1 CSI */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work\x9B" "31m", "w@x.com", "d");     /* bare C1 byte */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    /* AR-02 #28: the OVERLONG spellings of the same C1 CSI (U+009B) — the
     * exact smuggling vector utf8_decode's strictness exists to stop, and
     * previously exercised by no test. 3-byte: E0 82 9B; 4-byte: F0 80 82 9B.
     * A lenient decoder normalizes either back to 0x9B and the terminal
     * executes it; the strict decoder must call both malformed. */
    fill_account(&a, 1, "work\xE0\x82\x9B" "31m", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work\xF0\x80\x82\x9B" "31m", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "caf\xC3\xA9", "w@x.com", "d");        /* plain UTF-8 "café" */
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) CHECK_STR_EQ(ctx.accounts[0].name, "caf\xC3\xA9");
}

TEST(add_rejects_escape_in_description) {
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work", "w@x.com", "ok\x1B[31mred");   /* raw ESC */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    /* Overlong-encoded C1 controls in the description (AR-02 #28): the add
     * path fails closed on them just like the raw/2-byte forms. */
    fill_account(&a, 1, "work", "w@x.com", "ok\xE0\x82\x9B" "31m");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);
    fill_account(&a, 1, "work", "w@x.com", "ok\xF0\x80\x82\x9B" "31m");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work", "w@x.com", "caf\xC3\xA9 \xE2\x98\x95"); /* "café ☕" */
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].description, "caf\xC3\xA9 \xE2\x98\x95");
    }
}

/* ---- hostile account rejected by validate_account_security -------------- */

TEST(config_validate_rejects_hostile_account) {
    char dir[128], key[256], missing[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(key, sizeof(key), "%s/id_ed25519", dir);
    snprintf(missing, sizeof(missing), "%s/no_such_key", dir);
    CHECK_EQ_INT(write_config(key, "KEY", 3), 0); /* creates it 0600 */

    /* Baseline: a well-formed account with a 0600 key validates. */
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "work", "w@x.com", "day job");
    ctx.accounts[0].ssh_enabled = true;
    strncpy(ctx.accounts[0].ssh_key_path, key, sizeof(ctx.accounts[0].ssh_key_path) - 1);
    ctx.account_count = 1;
    CHECK_EQ_INT(config_validate(&ctx), 0);

    /* Group/other-readable private key: refused (an attacker who can read
     * the key doesn't need the agent isolation we set up around it). */
    CHECK_EQ_INT(chmod(key, 0644), 0);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_INVALID);
    CHECK_EQ_INT(chmod(key, 0600), 0);

    /* Nonexistent key path: refused, not deferred to a runtime ssh failure. */
    strncpy(ctx.accounts[0].ssh_key_path, missing, sizeof(ctx.accounts[0].ssh_key_path) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    strncpy(ctx.accounts[0].ssh_key_path, key, sizeof(ctx.accounts[0].ssh_key_path) - 1);

    /* Traversal name: it becomes the GNUPGHOME/agent-socket path component. */
    strncpy(ctx.accounts[0].name, "../evil", sizeof(ctx.accounts[0].name) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    strncpy(ctx.accounts[0].name, "work", sizeof(ctx.accounts[0].name) - 1);

    /* Non-hex GPG key id: reaches gpg/git argv, so hex-only is enforced. */
    ctx.accounts[0].gpg_enabled = true;
    strncpy(ctx.accounts[0].gpg_key_id, "DEADBEEF;id", sizeof(ctx.accounts[0].gpg_key_id) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);

    /* And the same gates hold on the add path (the API accounts.c uses). */
    account_t bad;
    gitswitch_ctx_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    fill_account(&bad, 1, "work", "w@x.com", "d");
    bad.gpg_enabled = true;
    strncpy(bad.gpg_key_id, "$(rm -rf ~)", sizeof(bad.gpg_key_id) - 1);
    CHECK_EQ_INT(config_add_account(&fresh, &bad), -1);
    CHECK_EQ_INT(fresh.account_count, 0);
}

/* ---- duplicate name/id guards (isolation is keyed by them) --------------- */

TEST(dup_name_id_rejected_on_load) {
    /* Two accounts sharing a name would share one GNUPGHOME (<base>/<name>)
     * and one ssh-agent.<name>.sock — the isolation would silently collapse.
     * The load path must keep only the FIRST and count the rest as skipped
     * (so config_save refuses to rewrite and erase them). Matching is
     * case-insensitive: the derived paths land on case-insensitive
     * filesystems too. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"Alice\"\n"
        "email = \"first@x.com\"\n"
        "[accounts.2]\n"
        "name = \"alice\"\n"          /* case-insensitive dup of accounts.1 */
        "email = \"second@x.com\"\n"
        "[accounts.3]\n"
        "name = \"bob\"\n"
        "email = \"b@x.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 2);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    if (ctx.account_count == 2) {
        /* First occurrence wins, byte-for-byte. */
        CHECK_STR_EQ(ctx.accounts[0].name, "Alice");
        CHECK_STR_EQ(ctx.accounts[0].email, "first@x.com");
        CHECK_STR_EQ(ctx.accounts[1].name, "bob");
    }

    /* Duplicate ids cannot even be spelled in a file anymore (a repeated
     * [accounts.1] merges into one section; non-canonical alias spellings are
     * rejected — see load_skips_leading_zero_id_section). The id guard is
     * enforced at the API every mutating command uses: */
    gitswitch_ctx_t api;
    account_t a;
    memset(&api, 0, sizeof(api));
    fill_account(&a, 1, "work", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&api, &a), 0);
    fill_account(&a, 1, "other", "o@x.com", "d");   /* same id, new name */
    CHECK_EQ_INT(config_add_account(&api, &a), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_EXISTS);
    fill_account(&a, 2, "WORK", "o@x.com", "d");    /* new id, dup name (case) */
    CHECK_EQ_INT(config_add_account(&api, &a), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_EXISTS);
    fill_account(&a, 2, "other", "o@x.com", "d");   /* both unique: fine */
    CHECK_EQ_INT(config_add_account(&api, &a), 0);
    CHECK_EQ_INT(api.account_count, 2);
}

/* ---- AR-03 M8: unknown sections must block (and survive) a rewrite ------- */

TEST(unknown_section_blocks_rewrite_and_is_preserved) {
    /* A typo'd [account.3] (or any custom section) is invisible to
     * config_save's rebuild — pre-fix it was not counted at load, so the
     * refuse-to-rewrite guard read zero, config_save returned 0, and the
     * section was permanently deleted by the very next save. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "[account.3]\n"          /* typo: singular */
        "name = \"typod\"\n"
        "email = \"t@b.com\"\n";
    char dir[128], path[256], after[1024];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);              /* alice loads fine */
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 1);   /* pre-fix: field absent */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 0);

    /* Both gates must refuse, and the section must survive on disk. */
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
    CHECK_EQ_INT(config_save(&ctx, path), -1);       /* pre-fix: 0 + erased */
    slurp(path, after, sizeof(after));
    CHECK(strstr(after, "[account.3]") != NULL);
    CHECK(strstr(after, "typod") != NULL);
}

/* ---- AR-03 M9(4): settings-only save must work around the skip guard ---- */

TEST(settings_only_save_records_active_and_preserves_sections) {
    /* One healthy account, one skipped (over-long name), one unknown section:
     * the full rewrite is (correctly) refused, but a switch to the healthy
     * account must still persist active_account — pre-fix the switch printed
     * success while active_account stayed stale, so the next boot's resume
     * restored the wrong identity. The write-back must keep BOTH problem
     * sections byte-for-byte-meaningful on disk. */
    char longname[300], cfg[1024], after[2048];
    char dir[128], path[256];
    gitswitch_ctx_t ctx;

    memset(longname, 'N', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"local\"\n"
             "[accounts.1]\n"
             "name = \"alice\"\n"
             "email = \"a@b.com\"\n"
             "[accounts.2]\n"
             "name = \"%s\"\n"
             "email = \"long@b.com\"\n"
             "[account.3]\n"
             "name = \"typod\"\n",
             longname);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 1);

    /* Simulate the switch's bookkeeping, then the targeted save. */
    strncpy(ctx.config.active_account, "alice", sizeof(ctx.config.active_account) - 1);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0); /* succeeds where config_save refuses */

    slurp(path, after, sizeof(after));
    CHECK(strstr(after, "active_account = \"alice\"") != NULL); /* pre-fix: never persisted */
    CHECK(strstr(after, longname) != NULL);                     /* skipped account intact */
    CHECK(strstr(after, "[account.3]") != NULL);                /* unknown section intact */
    CHECK(strstr(after, "typod") != NULL);
    CHECK(strstr(after, "default_scope = \"local\"") != NULL);  /* other settings intact */

    /* And the write-back result must load again with the same view. */
    gitswitch_ctx_t ctx2;
    memset(&ctx2, 0, sizeof(ctx2));
    CHECK_EQ_INT(config_load(&ctx2, path), 0);
    CHECK_EQ_INT(ctx2.account_count, 1);
    CHECK_STR_EQ(ctx2.config.active_account, "alice");
    CHECK_EQ_INT(ctx2.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(ctx2.unknown_sections_on_load, 1);
}

/* ---- AR-03 T4: the resume-hint writer itself ----------------------------- */

TEST(resume_hint_reflects_account_runtime_needs) {
    /* config_update_resume_hint records the active account's boot-volatile
     * runtime needs; the shell snippet branches on this exact content, so a
     * wrong value reintroduces either the doomed per-shell ssh-add probe
     * (AR-02 #23) or a wrongly-skipped resume. Drive it through config_save
     * (its only caller) with HOME pointed at a scratch dir. */
    char dir[128], path[256], hint[512], buf[64];
    char old_home[512];
    const char *home_env = getenv("HOME");
    gitswitch_ctx_t ctx;

    snprintf(old_home, sizeof(old_home), "%s", home_env ? home_env : "");
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("HOME", dir, 1), 0);

    /* The hint lives in <config_dir>; create it like config_init would. */
    snprintf(path, sizeof(path), "%s/.config", dir);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch", dir);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(hint, sizeof(hint), "%s/.config/gitswitch/.resume-hint", dir);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    strncpy(ctx.config.active_account, "alice", sizeof(ctx.config.active_account) - 1);

    /* Identity-only: no boot-volatile state, the snippet must not probe. */
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "none\n");

    /* SSH-only. */
    ctx.accounts[0].ssh_enabled = true;
    strncpy(ctx.accounts[0].ssh_key_path, "/tmp/id_fake",
            sizeof(ctx.accounts[0].ssh_key_path) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "ssh\n");

    /* SSH + GPG. */
    ctx.accounts[0].gpg_enabled = true;
    strncpy(ctx.accounts[0].gpg_key_id, "ABCDEF0123456789",
            sizeof(ctx.accounts[0].gpg_key_id) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "ssh gpg\n");

    /* GPG-only. */
    ctx.accounts[0].ssh_enabled = false;
    ctx.accounts[0].ssh_key_path[0] = '\0';
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "gpg\n");

    /* An UNKNOWN active account (just-removed race) must fall back to the
     * conservative "ssh gpg" so the snippet still probes rather than
     * wrongly skipping a needed resume. */
    strncpy(ctx.config.active_account, "ghost", sizeof(ctx.config.active_account) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "ssh gpg\n");

    /* Cleared active account (reset path): the marker must be REMOVED, or
     * login shells keep probing/resuming state the user tore down. Exercised
     * through the settings-only save, the path `reset` actually takes. */
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(access(hint, F_OK) != 0);

    if (old_home[0]) setenv("HOME", old_home, 1); else unsetenv("HOME");
}

TEST(resume_hint_refuses_unsafe_nodes_and_replaces_regular_file_atomically) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char path[640], hint[640], victim[640], buf[64];
    struct stat before, after;
    gitswitch_ctx_t ctx;
    DIR *stream;
    struct dirent *entry;
    int leaked_temps = 0;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", config_dir);
    snprintf(victim, sizeof(victim), "%s/hint-victim", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(victim, "victim-content\n", 15), 0);
    CHECK_EQ_INT(symlink(victim, hint), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    strncpy(ctx.config.active_account, "alice",
            sizeof(ctx.config.active_account) - 1);

    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(victim, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "victim-content\n"); /* pre-fix: truncated to none */
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISLNK(after.st_mode));

    CHECK_EQ_INT(unlink(hint), 0);
    CHECK_EQ_INT(mkfifo(hint, 0600), 0);
    CHECK_EQ_INT(config_save(&ctx, path), 0); /* never opens/blocks on FIFO */
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISFIFO(after.st_mode));

    CHECK_EQ_INT(unlink(hint), 0);
    CHECK_EQ_INT(write_config(hint, "unsafe\n", 7), 0);
    CHECK_EQ_INT(chmod(hint, 0660), 0);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "unsafe\n");
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK_EQ_INT((long)(after.st_mode & 0777), 0660);

    /* A safe existing marker is replaced, not truncated in place: readers
     * see either complete old or complete new content, never a partial file. */
    CHECK_EQ_INT(chmod(hint, 0600), 0);
    CHECK_EQ_INT(lstat(hint, &before), 0);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK_EQ_INT((long)(after.st_mode & 0777), 0600);
    CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "none\n");

    stream = opendir(config_dir);
    CHECK(stream != NULL);
    if (stream) {
        while ((entry = readdir(stream)) != NULL) {
            if (strncmp(entry->d_name, ".resume-hint.tmp.", 17) == 0) {
                leaked_temps++;
            }
        }
        closedir(stream);
    }
    CHECK_EQ_INT(leaked_temps, 0);

    restore_home_env(saved_home);
}

/* ---- AR-03 M5 (config half): ssh_key length cap at the validation gate --- */

TEST(add_rejects_ssh_key_path_over_256_chars_api) {
    /* The loader skips accounts whose persisted ssh_key exceeds 256 chars, so
     * the programmatic add/update gate must refuse such a path up front —
     * pre-fix config_add_account accepted it (with an existing 0600 key), the
     * save succeeded, and the account vanished on the next invocation. */
    char dir[128], seg[130], dir_a[512], dir_b[1024], key[1300];
    gitswitch_ctx_t ctx;
    account_t a;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    memset(seg, 'd', 120);
    seg[120] = '\0';
    snprintf(dir_a, sizeof(dir_a), "%s/a%s", dir, seg);
    CHECK_EQ_INT(mkdir(dir_a, 0700), 0);
    snprintf(dir_b, sizeof(dir_b), "%s/b%s", dir_a, seg);
    CHECK_EQ_INT(mkdir(dir_b, 0700), 0);
    snprintf(key, sizeof(key), "%s/id_long", dir_b);
    CHECK_EQ_INT(write_config(key, "KEY", 3), 0); /* creates it 0600 */
    CHECK((int)strlen(key) > 256);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&a, 1, "longkey", "l@x.com", "d");
    a.ssh_enabled = true;
    strncpy(a.ssh_key_path, key, sizeof(a.ssh_key_path) - 1);
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_INVALID);
}

/* ---- AR-03 M6 follow-through: the write gate matches the read gate ------- */

TEST(add_rejects_values_that_cannot_roundtrip) {
    /* Since M6 toml_get_string FAILS on any value its sanitizer would alter
     * (quote, backslash, ...). The write side must refuse the same values,
     * or gitswitch persists a name/description its own next load cannot hand
     * back — the account it just created is then skipped with a warning. */
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "Jane \"Work\"", "j@x.com", "d"); /* the M6 repro name */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);       /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    fill_account(&a, 1, "jane", "j@x.com", "back\\slash desc");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);       /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    /* Plain values (including multi-byte UTF-8) still pass. */
    fill_account(&a, 1, "jane", "j@x.com", "caf\xC3\xA9 desk");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
}

/* AR-06 F46/F47: two saves in the same wall-clock second must not collide on
 * the one-second-granularity backup name. The second config_backup must still
 * succeed with a disambiguated name, leaving both backups on disk. */
TEST(back_to_back_backups_in_same_second_both_persist) {
    char dir[128], cfg[256];
    DIR *d;
    struct dirent *ent;
    int backups = 0;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(cfg, sizeof(cfg), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(cfg, "x\n", 2), 0);

    /* Same second (no sleep between): pre-fix the 2nd hit EEXIST and vanished. */
    CHECK_EQ_INT(config_backup(cfg), 0);
    CHECK_EQ_INT(config_backup(cfg), 0);

    d = opendir(dir);
    CHECK(d != NULL);
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            if (strstr(ent->d_name, "accounts.toml.backup.")) backups++;
        }
        closedir(d);
    }
    CHECK_EQ_INT(backups, 2); /* both backups survive */
}

/* AR-06 F50: destructive resolution (remove/reset) accepts only an exact
 * id/name/email, never a substring or description match. */
TEST(destructive_resolution_refuses_substring) {
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work-old", "old@example.com", "primary");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    fill_account(&a, 2, "personal", "me@example.com", "the work laptop");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);

    /* Even an UNAMBIGUOUS substring is refused for destructive ops... */
    CHECK(config_find_account_destructive(&ctx, "person") == NULL); /* in "personal" */
    CHECK(config_find_account_destructive(&ctx, "laptop") == NULL); /* in a description */
    /* ...while the fuzzy resolver still accepts the unambiguous substring. */
    CHECK(config_find_account(&ctx, "person") != NULL);

    /* Exact id / name / email still resolve for destructive ops. */
    CHECK(config_find_account_destructive(&ctx, "1") != NULL);
    CHECK(config_find_account_destructive(&ctx, "work-old") != NULL);
    CHECK(config_find_account_destructive(&ctx, "me@example.com") != NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(back_to_back_backups_in_same_second_both_persist);
    RUN_TEST(destructive_resolution_refuses_substring);
    RUN_TEST(load_accepts_regular_file);
    RUN_TEST(load_rejects_symlinked_config);
    RUN_TEST(config_init_rejects_symlinked_final_directory_without_mutation);
    RUN_TEST(config_init_rejects_nondirectory_final_components);
    RUN_TEST(config_init_secures_real_or_absent_final_directory);
    RUN_TEST(config_lock_rejects_symlink_fifo_and_unsafe_mode);
    RUN_TEST(config_lock_survives_post_acquisition_namespace_replacement);
    RUN_TEST(config_init_preserves_symlinked_parent_policy);
    RUN_TEST(save_refuses_symlinked_config_path);
    RUN_TEST(backup_refuses_symlinked_source);
    RUN_TEST(save_and_reload_regular_path_roundtrip);
    RUN_TEST(find_account_rejects_out_of_range_and_noncanonical_ids);
    RUN_TEST(load_skips_leading_zero_id_section);
    RUN_TEST(load_counts_unknown_keys_in_recognized_sections);
    RUN_TEST(load_accepts_only_modeled_keys);
    RUN_TEST(load_skips_out_of_range_id_section);
    RUN_TEST(load_counts_overlong_name_as_skipped_and_save_preserves_it);
    RUN_TEST(config_save_registers_and_unregisters_its_temp);
    RUN_TEST(load_strips_cr_from_description);
    RUN_TEST(load_rejects_raw_c1_byte_in_file);
    RUN_TEST(add_rejects_c1_and_malformed_utf8_in_name);
    RUN_TEST(add_rejects_escape_in_description);
    RUN_TEST(config_validate_rejects_hostile_account);
    RUN_TEST(dup_name_id_rejected_on_load);
    RUN_TEST(unknown_section_blocks_rewrite_and_is_preserved);
    RUN_TEST(settings_only_save_records_active_and_preserves_sections);
    RUN_TEST(resume_hint_reflects_account_runtime_needs);
    RUN_TEST(resume_hint_refuses_unsafe_nodes_and_replaces_regular_file_atomically);
    RUN_TEST(add_rejects_ssh_key_path_over_256_chars_api);
    RUN_TEST(add_rejects_values_that_cannot_roundtrip);
TEST_MAIN_END()
