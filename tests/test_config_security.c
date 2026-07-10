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
#include "error.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

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

/* ---- tty-escape: control bytes must not survive to display fields ---- */

TEST(load_strips_cr_from_description) {
    /* The classic line-overwrite spoof: an escape-decoded \r renders
     * "[CURRENT] trusted" over the real row. Locks the layered guarantee —
     * whichever of the TOML retrieval sanitizer or the config-load strip
     * handles it, no CR may reach the loaded description. */
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
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK(strchr(ctx.accounts[0].description, '\r') == NULL);
        CHECK_STR_EQ(ctx.accounts[0].description, "evil[CURRENT] trusted");
    }
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

    fill_account(&a, 1, "work", "w@x.com", "caf\xC3\xA9 \xE2\x98\x95"); /* "café ☕" */
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].description, "caf\xC3\xA9 \xE2\x98\x95");
    }
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(load_accepts_regular_file);
    RUN_TEST(load_rejects_symlinked_config);
    RUN_TEST(save_refuses_symlinked_config_path);
    RUN_TEST(backup_refuses_symlinked_source);
    RUN_TEST(save_and_reload_regular_path_roundtrip);
    RUN_TEST(find_account_rejects_out_of_range_and_noncanonical_ids);
    RUN_TEST(load_skips_leading_zero_id_section);
    RUN_TEST(load_skips_out_of_range_id_section);
    RUN_TEST(load_strips_cr_from_description);
    RUN_TEST(load_rejects_raw_c1_byte_in_file);
    RUN_TEST(add_rejects_c1_and_malformed_utf8_in_name);
    RUN_TEST(add_rejects_escape_in_description);
TEST_MAIN_END()
