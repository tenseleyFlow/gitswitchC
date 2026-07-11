/* git_ops tests: SSH key-path injection hardening (ssh-1) and the
 * process-scoped exec caches (perf-1..4).
 *
 * All git invocations are intercepted with a fake runner (run_set_runner)
 * that models an in-memory `git config` store and COUNTS execs, so the perf
 * tests assert the actual subprocess reduction and the security tests assert
 * that a hostile path never reaches a config write at all. */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include "git_ops.h"
#include "gpg_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Test seam from git_ops.c (deliberately not in git_ops.h: the public API is
 * unchanged; only tests need to reset the process-scoped caches). */
void git_ops_test_reset_caches(void);

/* ---- fake git: in-memory config store + exec counters ------------------- */

#define FK_MAX 32
static struct {
    char scope[16];
    char key[64];
    char value[1024];
    bool used;
} fk_store[FK_MAX];

static int fk_execs;           /* every subprocess the code under test spawned */
static int fk_identity_reads;  /* `git config <scope> user.name|user.email` reads */
static bool fk_is_repo;        /* what `git rev-parse --git-dir` reports */

static void fk_reset(void) {
    memset(fk_store, 0, sizeof(fk_store));
    fk_execs = 0;
    fk_identity_reads = 0;
    fk_is_repo = false;
}

static int fk_find(const char *scope, const char *key) {
    for (int i = 0; i < FK_MAX; i++) {
        if (fk_store[i].used && strcmp(fk_store[i].scope, scope) == 0 &&
            strcmp(fk_store[i].key, key) == 0) {
            return i;
        }
    }
    return -1;
}

/* A custom runner fully replaces run_argv, so — like the real run_argv_real —
 * it must publish result->exit_code (WEXITSTATUS), not just a return value:
 * git_unset_config_value now inspects res.exit_code to tell "removed"/"absent"
 * (0/5) from a genuine failure (AR-06 F03). fk_ret() sets it at every exit. */
static int fk_ret(run_result_t *result, int code) {
    if (result) result->exit_code = code;
    /* Mirror run_argv_real's return contract: 0 on clean exit, -1 otherwise. */
    return code == 0 ? 0 : -1;
}

static int fk_emit_effective_listing(const run_opts_t *opts,
                                     run_result_t *result) {
    size_t used = 0;
    if (!opts || !opts->out || opts->out_size == 0) return fk_ret(result, 1);
    for (int i = 0; i < FK_MAX; i++) {
        if (!fk_store[i].used) continue;
        const char *scope = fk_store[i].scope;
        if (scope[0] == '-' && scope[1] == '-') scope += 2;
        const char *origin = "file:/fake/config";
        size_t scope_len = strlen(scope) + 1;
        size_t origin_len = strlen(origin) + 1;
        size_t record_len = strlen(fk_store[i].key) + 1 +
                            strlen(fk_store[i].value) + 1;
        if (used + scope_len + origin_len + record_len > opts->out_size)
            return fk_ret(result, 1);
        memcpy(opts->out + used, scope, scope_len);
        used += scope_len;
        memcpy(opts->out + used, origin, origin_len);
        used += origin_len;
        used += (size_t)snprintf(opts->out + used, opts->out_size - used,
                                 "%s\n%s", fk_store[i].key,
                                 fk_store[i].value) + 1;
    }
    if (result) result->out_len = used;
    return fk_ret(result, 0);
}

static int fake_git_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    fk_execs++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }

    if (strcmp(argv[0], "git") != 0 || !argv[1]) {
        return fk_ret(result, 1);
    }

    if (strcmp(argv[1], "rev-parse") == 0) {
        return fk_ret(result, fk_is_repo ? 0 : 1);
    }

    if (strcmp(argv[1], "config") == 0 && argv[2] && argv[3]) {
        if (strcmp(argv[2], "--show-origin") == 0)
            return fk_emit_effective_listing(opts, result);
        const char *scope = argv[2];

        /* Production emits --unset-all (AR-06 F03); accept the legacy spelling
         * too so the fake stays robust. Removes ALL values of a (possibly
         * multi-valued) key; exit 5 when the key does not exist. */
        if ((strcmp(argv[3], "--unset-all") == 0 || strcmp(argv[3], "--unset") == 0) && argv[4]) {
            int i = fk_find(scope, argv[4]);
            if (i < 0) {
                return fk_ret(result, 5); /* git: option does not exist */
            }
            fk_store[i].used = false;
            return fk_ret(result, 0);
        }

        if (argv[4]) { /* set */
            int i = fk_find(scope, argv[3]);
            if (i < 0) {
                for (i = 0; i < FK_MAX && fk_store[i].used; i++) {}
                if (i == FK_MAX) return fk_ret(result, 1);
            }
            snprintf(fk_store[i].scope, sizeof(fk_store[i].scope), "%s", scope);
            snprintf(fk_store[i].key, sizeof(fk_store[i].key), "%s", argv[3]);
            snprintf(fk_store[i].value, sizeof(fk_store[i].value), "%s", argv[4]);
            fk_store[i].used = true;
            return fk_ret(result, 0);
        }

        /* read */
        if (strcmp(argv[3], "user.name") == 0 || strcmp(argv[3], "user.email") == 0) {
            fk_identity_reads++;
        }
        int i = fk_find(scope, argv[3]);
        if (i < 0) {
            return fk_ret(result, 1);
        }
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size, "%s\n", fk_store[i].value);
            if (result) result->out_len = strlen(opts->out);
        }
        return fk_ret(result, 0);
    }

    return fk_ret(result, 1);
}

/* ---- ssh-1: key path must never carry ssh_config / shell breakouts ------ */

/* Create a real (empty) file so rejection provably comes from the character
 * validation, not from a failed existence check — the pre-fix code let a
 * double-quoted path through to the config write whenever the file existed. */
static bool fk_touch(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fclose(f);
    return true;
}

TEST(git_configure_ssh_rejects_single_quote_in_keypath) {
    char dir[64];
    char quote_path[512], dquote_path[512], newline_path[512], ok_path[512];
    account_t acct;
    command_runner_fn prev;

    snprintf(dir, sizeof(dir), "/tmp/gsw_gitops_XXXXXX");
    CHECK(ts_mkdtemp(dir) != NULL);
    snprintf(quote_path, sizeof(quote_path), "%s/k'ey", dir);
    snprintf(dquote_path, sizeof(dquote_path), "%s/k\"ey", dir);
    /* A single FILE NAME (no '/' after the newline, so it is creatable) that
     * would land as a second ssh_config line if ever written verbatim. */
    snprintf(newline_path, sizeof(newline_path),
             "%s/key\nProxyCommand touch PWNED", dir);
    snprintf(ok_path, sizeof(ok_path), "%s/key_ok", dir);
    CHECK(fk_touch(quote_path));
    CHECK(fk_touch(dquote_path));
    CHECK(fk_touch(newline_path));
    CHECK(fk_touch(ok_path));

    git_ops_test_reset_caches();
    fk_reset();
    prev = run_set_runner(fake_git_runner);

    const char *payloads[] = { quote_path, dquote_path, newline_path };
    for (size_t i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
        memset(&acct, 0, sizeof(acct));
        acct.ssh_enabled = true;
        safe_strncpy(acct.ssh_key_path, payloads[i], sizeof(acct.ssh_key_path));

        fk_execs = 0;
        int rc = git_configure_ssh(&acct, GIT_SCOPE_GLOBAL);
        CHECK_EQ_INT(rc, -1);
        /* Rejected BEFORE any subprocess: nothing may be written to git
         * config. This covers ONLY the core.sshCommand sink — the
         * ~/.ssh/config IdentityFile sink is a separate write site with its
         * own guard, exercised by host_alias_write_rejects_newline_key_path
         * in test_ssh_reuse.c (AR-02 #10). */
        CHECK_EQ_INT(fk_execs, 0);
        CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    }

    /* Control: a benign existing key path still configures core.sshCommand.
     * Two execs: the write plus the AR-05 M5 read-back verification, which
     * must round-trip through git (reads are never served from this
     * process's own writes). */
    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    safe_strncpy(acct.ssh_key_path, ok_path, sizeof(acct.ssh_key_path));
    fk_execs = 0;
    CHECK_EQ_INT(git_configure_ssh(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 2);
    int idx = fk_find("--global", "core.sshcommand");
    CHECK(idx >= 0);
    if (idx >= 0) {
        CHECK(strstr(fk_store[idx].value, ok_path) != NULL);
        CHECK(strstr(fk_store[idx].value, "IdentitiesOnly=yes") != NULL);
    }

    run_set_runner(prev);
    unlink(quote_path);
    unlink(dquote_path);
    unlink(newline_path);
    unlink(ok_path);
    rmdir(dir);
}

/* ---- perf-1: git_ops_init must not spawn a subprocess ------------------- */

TEST(git_ops_init_spawns_no_subprocess) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);

    /* Availability is proven by a $PATH walk (access X_OK), not by execing
     * `git --version`; requires a real git in PATH, as CI has. */
    CHECK_EQ_INT(git_ops_init(), 0);
    CHECK_EQ_INT(fk_execs, 0);

    /* Second init in the same process (switch after resume): still no exec. */
    CHECK_EQ_INT(git_ops_init(), 0);
    CHECK_EQ_INT(fk_execs, 0);

    run_set_runner(prev);
}

/* ---- perf-4: repo-ness is asked several times per switch, exec once ----- */

TEST(git_is_repository_caches_result) {
    git_ops_test_reset_caches();
    fk_reset();
    fk_is_repo = true;
    command_runner_fn prev = run_set_runner(fake_git_runner);

    CHECK(git_is_repository());
    CHECK(git_is_repository());
    CHECK(git_is_repository());
    CHECK_EQ_INT(fk_execs, 1); /* one rev-parse, then served from the cwd cache */

    run_set_runner(prev);
}

/* ---- perf-3: identical managed-key writes collapse to one exec ---------- */

TEST(git_set_config_value_skips_duplicate_managed_write) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);
    char buf[128];

    /* The GPG switch double-write: git_configure_gpg then
     * gpg_configure_git_signing write the same signingkey/gpgsign values. */
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "DEADBEEFCAFE1234", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 1);
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "DEADBEEFCAFE1234", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 1); /* duplicate write skipped */

    CHECK_EQ_INT(git_set_config_value("commit.gpgsign", "true", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value("commit.gpgsign", "true", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 2);

    /* Verification integrity: our own write must NOT satisfy a read — the
     * first read-back after a write has to round-trip through git. */
    CHECK_EQ_INT(git_get_config_value("user.signingkey", buf, sizeof(buf), GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 3);
    CHECK_STR_EQ(buf, "DEADBEEFCAFE1234");

    /* ...but a repeated read of the observed value is served from cache. */
    buf[0] = '\0';
    CHECK_EQ_INT(git_get_config_value("user.signingkey", buf, sizeof(buf), GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 3);
    CHECK_STR_EQ(buf, "DEADBEEFCAFE1234");

    /* Duplicate unsets also collapse; a set after an unset must exec again. */
    CHECK_EQ_INT(git_unset_config_value("user.signingkey", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 4);
    CHECK_EQ_INT(git_unset_config_value("user.signingkey", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 4);
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "DEADBEEFCAFE1234", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 5);

    /* A different value never skips. */
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "0123456789ABCDEF", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 6);
    int idx = fk_find("--global", "user.signingkey");
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_STR_EQ(fk_store[idx].value, "0123456789ABCDEF");

    run_set_runner(prev);
}

/* ---- rollback snapshot: -z listing survives embedded newlines ----------- */
/* Regression lock for the `git config --list -z` snapshot fix: with plain
 * --list, a managed value containing a newline masqueraded as a record
 * boundary, truncating that value in the rollback snapshot AND corrupting the
 * records after it. The -z parser (parse_config_z_value) must keep the full
 * value and still attribute the NEXT record to the right key. */

static char zfk_set_key[16][64], zfk_set_val[16][1024];
static int zfk_sets;
static char zfk_unset_key[16][64];
static int zfk_unsets;
static int zfk_fallback_reads; /* per-key reads => the -z fast path was NOT used */
static const char *zfk_listing_override; /* non-NULL => serve this listing */
static size_t zfk_listing_override_len;  /* instead of the embedded default */

static int zfk_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    /* The -z listing under test: user.name's value spans two lines. The
     * second line deliberately looks like the start of another record. */
    static const char listing[] =
        "user.name\nAlpha\nBeta"          "\0"
        "user.email\nreal@x.com"          "\0"
        "core.sshcommand\nssh -i /k -o IdentitiesOnly=yes" "\0";

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "git") != 0 || !argv[1]) return fk_ret(result, 1);

    if (strcmp(argv[1], "rev-parse") == 0) {
        return fk_ret(result, 1); /* not a repository: snapshot covers global only */
    }

    if (strcmp(argv[1], "config") == 0 && argv[2] && argv[3]) {
        if (strcmp(argv[3], "--list") == 0 && argv[4] && strcmp(argv[4], "-z") == 0) {
            const char *lst = listing;
            size_t n = sizeof(listing) - 1; /* keep interior NULs, drop trailing */
            if (zfk_listing_override) {
                lst = zfk_listing_override;
                n = zfk_listing_override_len;
            }
            if (opts && opts->out && opts->out_size > n) {
                memcpy(opts->out, lst, n);
                opts->out[n] = '\0';
                if (result) result->out_len = n;
                return fk_ret(result, 0);
            }
            return fk_ret(result, 1);
        }
        if ((strcmp(argv[3], "--unset-all") == 0 || strcmp(argv[3], "--unset") == 0) && argv[4]) {
            if (zfk_unsets < 16) {
                snprintf(zfk_unset_key[zfk_unsets], sizeof(zfk_unset_key[0]), "%s", argv[4]);
            }
            zfk_unsets++;
            return fk_ret(result, 0);
        }
        if (argv[4]) { /* set */
            if (zfk_sets < 16) {
                snprintf(zfk_set_key[zfk_sets], sizeof(zfk_set_key[0]), "%s", argv[3]);
                snprintf(zfk_set_val[zfk_sets], sizeof(zfk_set_val[0]), "%s", argv[4]);
            }
            zfk_sets++;
            return fk_ret(result, 0);
        }
        zfk_fallback_reads++; /* per-key read: only the pre-fix fallback path */
        return fk_ret(result, 1);
    }

    return fk_ret(result, 1);
}

static int zfk_find_set(const char *key) {
    for (int i = 0; i < zfk_sets && i < 16; i++) {
        if (strcmp(zfk_set_key[i], key) == 0) return i;
    }
    return -1;
}

static bool zfk_was_unset(const char *key) {
    for (int i = 0; i < zfk_unsets && i < 16; i++) {
        if (strcmp(zfk_unset_key[i], key) == 0) return true;
    }
    return false;
}

static int zfk_count_unsets(const char *key) {
    int c = 0;
    for (int i = 0; i < zfk_unsets && i < 16; i++) {
        if (strcmp(zfk_unset_key[i], key) == 0) c++;
    }
    return c;
}

TEST(rollback_z_parser_survives_embedded_newline) {
    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_restore(), 0);

    run_set_runner(prev);

    /* The snapshot came from the one-exec -z listing, not per-key reads. */
    CHECK_EQ_INT(zfk_fallback_reads, 0);

    /* The record AFTER the multiline value is attributed correctly and
     * restored verbatim — a newline-splitting parser would have read "Beta"
     * as a (separator-less) record and desynced from here on. */
    int ie = zfk_find_set("user.email");
    CHECK(ie >= 0);
    if (ie >= 0) CHECK_STR_EQ(zfk_set_val[ie], "real@x.com");
    int is = zfk_find_set("core.sshcommand");
    CHECK(is >= 0);
    if (is >= 0) CHECK_STR_EQ(zfk_set_val[is], "ssh -i /k -o IdentitiesOnly=yes");

    /* user.name was captured PRESENT with its full two-line value and is now
     * RESTORED verbatim (AR-06 F04): the restore path skips is_valid_git_config
     * _value for snapshot-sourced values, so git's own multi-line value round-
     * trips instead of being silently dropped (which left the failed switch's
     * name over the user's original). A parser truncating at the newline would
     * instead restore just "Alpha"; one that lost the record would `--unset`. */
    int in = zfk_find_set("user.name");
    CHECK(in >= 0);
    if (in >= 0) CHECK_STR_EQ(zfk_set_val[in], "Alpha\nBeta");
    CHECK(!zfk_was_unset("user.name"));

    /* Keys absent from the listing were snapshotted absent AND seeded into
     * the exec cache as proven-absent (AR-02 #15); nothing wrote them after
     * the snapshot, so the restore's unsets are provable no-ops and are
     * elided rather than exec'd. (restore_unsets_keys_written_after_snapshot
     * covers the case where a forward write makes the unset real.) */
    CHECK(!zfk_was_unset("user.signingkey"));
    CHECK(!zfk_was_unset("commit.gpgsign"));
    CHECK(!zfk_was_unset("gpg.program"));
}

/* AR-02 #15: the snapshot's complete -z listing seeds the exec cache, so
 * git_clear_config — run one exec later by every global switch inside a repo
 * — elides the --unset calls the listing just proved were unnecessary and
 * execs only the keys actually present. */
TEST(snapshot_seeds_cache_and_clear_elides_proven_absent) {
    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_clear_config(GIT_SCOPE_GLOBAL), 0);

    run_set_runner(prev);

    /* Present in the listing: really unset. */
    CHECK(zfk_was_unset("user.name"));
    CHECK(zfk_was_unset("user.email"));
    CHECK(zfk_was_unset("core.sshcommand"));
    /* Proven absent by the listing: elided (pre-fix all six exec'd). */
    CHECK(!zfk_was_unset("user.signingkey"));
    CHECK(!zfk_was_unset("commit.gpgsign"));
    CHECK(!zfk_was_unset("gpg.program"));
    CHECK_EQ_INT(zfk_unsets, 3);
}

/* Correctness guard on the elision: a key the snapshot saw absent but that a
 * later write re-created must still be genuinely unset — only PROVABLE
 * no-ops may be skipped. */
TEST(restore_unsets_keys_written_after_snapshot) {
    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    /* Forward switch writes a key the listing showed absent... */
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "AAAA1111BBBB2222",
                                      GIT_SCOPE_GLOBAL), 0);
    /* ...so the rollback's unset of it is real and must exec. */
    CHECK_EQ_INT(git_config_restore(), 0);

    run_set_runner(prev);
    CHECK(zfk_was_unset("user.signingkey"));
}

/* ---- AR-03 M1: overlong values must never snapshot as proven-absent ----- */
/* gitswitch itself writes core.sshCommand values past 512 bytes (~85 bytes of
 * fixed ssh options plus a single-quoted key path of up to MAX_PATH_LEN), and
 * a foreign tool can write one of any length. The pre-fix 512-byte value caps
 * turned "present but long" into found=false: the snapshot recorded
 * present=false, the exec cache was seeded proven-absent, git_clear_config
 * elided the --unset (the foreign SSH identity silently survived the switch),
 * and a failed switch's git_config_restore --unset the user's original value. */

static char blk_listing[8192]; /* bespoke -z listings, built per test */
static size_t blk_listing_len;

static void blk_add(const char *key, const char *val) {
    size_t kl = strlen(key), vl = strlen(val);
    memcpy(blk_listing + blk_listing_len, key, kl);
    blk_listing_len += kl;
    blk_listing[blk_listing_len++] = '\n';
    memcpy(blk_listing + blk_listing_len, val, vl);
    blk_listing_len += vl;
    blk_listing[blk_listing_len++] = '\0';
}

TEST(overlong_sshcommand_snapshots_present_and_restores_verbatim) {
    /* Longer than the old 512-byte cap but within what gitswitch itself
     * writes: must round-trip at full fidelity — the clear really unsets it
     * and the rollback restores the ORIGINAL bytes, not a truncation. */
    static char val[601];
    memset(val, 'k', sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';
    memcpy(val, "ssh -i /", 8); /* shaped like the value gitswitch emits */

    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    blk_listing_len = 0;
    blk_add("user.name", "Real Name");
    blk_add("user.email", "real@x.com");
    blk_add("core.sshcommand", val);
    zfk_listing_override = blk_listing;
    zfk_listing_override_len = blk_listing_len;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    /* The clear must exec a real --unset: pre-fix the seeded cache claimed
     * the PRESENT key was proven absent and elided it. */
    CHECK_EQ_INT(git_clear_config(GIT_SCOPE_GLOBAL), 0);
    CHECK(zfk_was_unset("core.sshcommand"));
    /* A failed switch's rollback restores the original value verbatim —
     * pre-fix the snapshot said present=false, so the restore left the key
     * unset (and the per-key fallback would have written back a silently
     * truncated copy instead). */
    CHECK_EQ_INT(git_config_restore(), 0);
    int is = zfk_find_set("core.sshcommand");
    CHECK(is >= 0);
    if (is >= 0) CHECK_STR_EQ(zfk_set_val[is], val);

    run_set_runner(prev);
    zfk_listing_override = NULL;
    CHECK_EQ_INT(zfk_fallback_reads, 0); /* served by the -z fast path */
}

TEST(oversize_foreign_sshcommand_degrades_to_present_unknown) {
    /* Longer than ANY value gitswitch writes (past MAX_PATH_LEN plus the ssh
     * option overhead): uncapturable, but the key is still PRESENT. The clear
     * must exec its --unset (no proven-absent elision), and the rollback must
     * leave the key alone — a truncated write-back and a destructive --unset
     * are both corruption. */
    static char val[MAX_PATH_LEN + 600];
    memset(val, 'k', sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';

    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    blk_listing_len = 0;
    blk_add("user.name", "Real Name");
    blk_add("user.email", "real@x.com");
    blk_add("core.sshcommand", val);
    zfk_listing_override = blk_listing;
    zfk_listing_override_len = blk_listing_len;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_clear_config(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(zfk_count_unsets("core.sshcommand"), 1);

    CHECK_EQ_INT(git_config_restore(), 0);
    /* Value unknown: no corrupt write-back... */
    CHECK(zfk_find_set("core.sshcommand") < 0);
    /* ...and no second, destructive --unset of the user's original. */
    CHECK_EQ_INT(zfk_count_unsets("core.sshcommand"), 1);
    /* Keys that DID fit still round-trip normally. */
    int in = zfk_find_set("user.name");
    int ie = zfk_find_set("user.email");
    CHECK(in >= 0 && ie >= 0);
    if (in >= 0) CHECK_STR_EQ(zfk_set_val[in], "Real Name");
    if (ie >= 0) CHECK_STR_EQ(zfk_set_val[ie], "real@x.com");

    run_set_runner(prev);
    zfk_listing_override = NULL;
}

/* ---- perf-2: git_test_config reuses git_set_config's read-back ---------- */

TEST(git_test_config_reuses_switch_readback) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);
    account_t acct;

    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "Test User", sizeof(acct.name));
    safe_strncpy(acct.email, "test@example.com", sizeof(acct.email));

    /* Full switch write: sets identity, then verifies by reading it back
     * from git — exactly two identity reads. */
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_identity_reads, 2);

    /* The post-switch validation used to re-exec both reads; it must now be
     * served from the values git reported to the verify step above. */
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_identity_reads, 2);

    /* Outcome unchanged: the fake store holds the switched identity. */
    int in = fk_find("--global", "user.name");
    int ie = fk_find("--global", "user.email");
    CHECK(in >= 0 && ie >= 0);
    if (in >= 0) CHECK_STR_EQ(fk_store[in].value, "Test User");
    if (ie >= 0) CHECK_STR_EQ(fk_store[ie].value, "test@example.com");

    run_set_runner(prev);
}

/* AR-02 #14: git_test_config's GPG availability probe must be skipped when a
 * gpg spawn earlier in this process already proved the key present. The fake
 * runner refuses every non-git argv, so a gpg spawn here FAILS the check —
 * the post-memo success is only reachable via the skip. */
TEST(git_test_config_skips_gpg_probe_when_key_seen) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);
    account_t acct;

    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "GPG User", sizeof(acct.name));
    safe_strncpy(acct.email, "gpg@example.com", sizeof(acct.email));
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    safe_strncpy(acct.gpg_key_id, "0123FEED4567BEEF", sizeof(acct.gpg_key_id));

    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);

    /* Key not yet proven by any gpg spawn: the probe runs, the fake runner
     * refuses it, the check fails — proving the probe is still reachable
     * when nothing vouches for the key. */
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);

    /* Once proven (as every real switch does before its read-back validation),
     * the probe is skipped and the identical call succeeds with no gpg exec. */
    gpg_manager_note_key_available(acct.gpg_key_id);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), 0);

    run_set_runner(prev);
}

/* ---- AR-06 F58: per-key snapshot preserves surrounding whitespace -------- */
static char f58_set_key[16][64], f58_set_val[16][1024];
static int f58_sets;

static int f58_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    if (result) { memset(result, 0, sizeof(*result)); result->spawned = true; }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (strcmp(argv[0], "git") != 0 || !argv[1]) return fk_ret(result, 1);
    if (strcmp(argv[1], "rev-parse") == 0) return fk_ret(result, 1); /* not a repo */
    if (strcmp(argv[1], "config") == 0 && argv[2] && argv[3]) {
        if (strcmp(argv[3], "--list") == 0) return fk_ret(result, 1); /* force per-key */
        if ((strcmp(argv[3], "--unset-all") == 0 || strcmp(argv[3], "--unset") == 0) && argv[4])
            return fk_ret(result, 0);
        if (argv[4]) { /* set (restore write) */
            if (f58_sets < 16) {
                snprintf(f58_set_key[f58_sets], sizeof(f58_set_key[0]), "%s", argv[3]);
                snprintf(f58_set_val[f58_sets], sizeof(f58_set_val[0]), "%s", argv[4]);
            }
            f58_sets++;
            return fk_ret(result, 0);
        }
        /* per-key read: user.name carries leading+trailing spaces; git appends
         * exactly one trailing newline. */
        if (opts && opts->out && opts->out_size > 0) {
            const char *v = NULL;
            if (strcmp(argv[3], "user.name") == 0) v = "  spaced  name  ";
            else if (strcmp(argv[3], "user.email") == 0) v = "e@x.com";
            if (v) {
                snprintf(opts->out, opts->out_size, "%s\n", v);
                if (result) result->out_len = strlen(opts->out);
                return fk_ret(result, 0);
            }
        }
        return fk_ret(result, 1); /* other keys absent */
    }
    return fk_ret(result, 1);
}

static int f58_find_set(const char *key) {
    for (int i = 0; i < f58_sets && i < 16; i++)
        if (strcmp(f58_set_key[i], key) == 0) return i;
    return -1;
}

TEST(per_key_snapshot_preserves_surrounding_whitespace) {
    git_ops_test_reset_caches();
    f58_sets = 0;
    command_runner_fn prev = run_set_runner(f58_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_config_restore(), 0);

    run_set_runner(prev);

    /* Restored byte-for-byte: pre-fix trim_whitespace() ate the surrounding
     * spaces and rollback wrote back "spaced  name". */
    int in = f58_find_set("user.name");
    CHECK(in >= 0);
    if (in >= 0) CHECK_STR_EQ(f58_set_val[in], "  spaced  name  ");
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(per_key_snapshot_preserves_surrounding_whitespace);
    RUN_TEST(git_configure_ssh_rejects_single_quote_in_keypath);
    RUN_TEST(git_ops_init_spawns_no_subprocess);
    RUN_TEST(git_is_repository_caches_result);
    RUN_TEST(git_set_config_value_skips_duplicate_managed_write);
    RUN_TEST(rollback_z_parser_survives_embedded_newline);
    RUN_TEST(snapshot_seeds_cache_and_clear_elides_proven_absent);
    RUN_TEST(restore_unsets_keys_written_after_snapshot);
    RUN_TEST(overlong_sshcommand_snapshots_present_and_restores_verbatim);
    RUN_TEST(oversize_foreign_sshcommand_degrades_to_present_unknown);
    RUN_TEST(git_test_config_reuses_switch_readback);
    RUN_TEST(git_test_config_skips_gpg_probe_when_key_seen);
TEST_MAIN_END()
