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
    RUN_TEST(add_rejects_ssh_key_path_over_256_chars_api);
    RUN_TEST(add_rejects_values_that_cannot_roundtrip);
TEST_MAIN_END()
