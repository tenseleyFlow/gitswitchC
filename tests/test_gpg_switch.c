/* Tests for gpg_switch_account's spawn economy (AR-02 #14): a repeat switch
 * to an account whose key already sits in the isolated home used to spawn gpg
 * separately for the import idempotency check AND the signing-capability
 * test, answering the same "is the secret key here?" question twice. The
 * idempotency probe now asks with --with-colons and its listing doubles as
 * the signing evidence, so the whole ISOLATED switch takes ONE gpg spawn.
 *
 * gpg invocations are intercepted with a counting fake runner; the isolated
 * home lives under a private fake XDG_RUNTIME_DIR, with the tmpfs fail-closed
 * guard opted out via GITSWITCH_ALLOW_TMP_GPG so the test is independent of
 * where the suite's scratch space happens to be mounted. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* A real `sec` line whose capability field (12) contains 's'. */
#define SEC_SIGN "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n"

static int g_gpg_execs;

/* Counts gpg spawns; answers any secret-key listing with a signing-capable
 * record, so the switch's already-present fast path is taken. */
static int counting_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "gpg") == 0) {
        g_gpg_execs++;
        bool listing = false;
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) listing = true;
        }
        if (listing && opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", SEC_SIGN);
            if (result) result->out_len = strlen(opts->out);
        }
    }
    return 0;
}

TEST(repeat_isolated_switch_spawns_gpg_once) {
    char xdg[128], link_path[512], target[512];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    ssize_t n;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "work");
    snprintf(acct.email, sizeof(acct.email), "w@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "FEEDFACE01234567");

    g_gpg_execs = 0;
    prev = run_set_runner(counting_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    /* One spawn proves presence AND signing capability (pre-fix: two — the
     * plain idempotency listing plus gpg_test_signing's --with-colons rerun). */
    CHECK_EQ_INT(g_gpg_execs, 1);

    /* The stable `current` symlink was retargeted at this account's home. */
    CHECK_EQ_INT(gpg_manager_get_home_path(link_path, sizeof(link_path)), 0);
    n = readlink(link_path, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK(strstr(target, "/work") != NULL);
    }

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* AR-04 M2: the stable `current` path is the commit point. A directory there
 * cannot be atomically replaced by a symlink, so the prepared home remains
 * reusable but the switch must fail without publishing active key/env state. */
TEST(isolated_switch_fails_when_current_cannot_be_retargeted) {
    char xdg[128], base[256], current[320], home[320];
    struct stat st;
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    setenv("GNUPGHOME", "/before/gpg-home", 1);

    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(home, sizeof(home), "%s/work", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(current, 0700), 0); /* rename-over-directory fails */

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "work");
    snprintf(acct.email, sizeof(acct.email), "w@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "FEEDFACE01234567");

    g_gpg_execs = 0;
    prev = run_set_runner(counting_runner);
    CHECK_EQ_INT(gpg_switch_account(&cfg, &acct), -1); /* pre-fix: 0 */
    run_set_runner(prev);

    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK(path_exists(home));              /* prepared state is reusable */
    CHECK(cfg.current_key_id[0] == '\0'); /* rejected account not published */
    CHECK(!cfg.signing_enabled);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/before/gpg-home");

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* ---- AR-02 #4 at the switch level: truncated exports never import -------- */

static bool g_import_ran;

/* Key absent from every keyring; the export "succeeds" but overflows the
 * capture (out_truncated) — exactly what a multi-subkey RSA-4096 armor did to
 * the old fixed 8 KB buffer. The import must never see those bytes. */
static int truncating_export_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    bool is_export = false, is_import = false, is_listing = false;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "gpg") == 0) {
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--export-secret-keys") == 0) is_export = true;
            if (strcmp(argv[i], "--import") == 0) is_import = true;
            if (strcmp(argv[i], "--list-secret-keys") == 0) is_listing = true;
        }
    }
    if (is_import) {
        g_import_ran = true;
        return 0;
    }
    if (is_export) {
        if (opts && opts->out && opts->out_size > 0) {
            size_t fill = opts->out_size - 1;
            memset(opts->out, 'A', fill);
            opts->out[fill] = '\0';
            if (result) {
                result->out_len = fill;
                result->out_truncated = true; /* capture is INCOMPLETE */
            }
        }
        return 0;
    }
    if (is_listing) {
        if (result) result->exit_code = 2;
        return -1; /* key present nowhere */
    }
    return 0; /* gpgconf etc. */
}

TEST(truncated_secret_key_export_is_never_imported) {
    char xdg[128];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "bigkey");
    snprintf(acct.email, sizeof(acct.email), "b@x.com");
    acct.gpg_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "DDDDEEEEFFFF0000");

    g_import_ran = false;
    prev = run_set_runner(truncating_export_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    /* The switch fails closed rather than importing corrupt armor. */
    CHECK_EQ_INT(rc, -1);
    CHECK(!g_import_ran);

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* ---- AR-03 T2: the first-time import's DIRECTION is pinned --------------- */

/* The whole point of the export/import pair is directional: export reads the
 * SYSTEM keyring (no GNUPGHOME override — stock env), import writes the
 * ISOLATED home (GNUPGHOME=<base>/<account>). Before this test, neutering the
 * import's gpg_build_env/extra_env plumbing — so the decrypted secret key
 * lands in the user's persistent ~/.gnupg instead of the memory-backed
 * isolated home — passed the entire suite. */

#define FAKE_ARMOR \
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" \
    "RkFLRUFSTU9SREFUQQ==\n" \
    "-----END PGP PRIVATE KEY BLOCK-----\n"

static char   g_imp_base[600];              /* <xdg>/gitswitch-gpg */
static int    g_imp_import_count;
static bool   g_imp_export_had_gnupghome;
static char   g_imp_import_gnupghome[600];  /* GNUPGHOME value at import; "" = absent */
static char   g_imp_import_stdin[512];
static size_t g_imp_import_stdin_len;
static int    g_imp_lock_at_import;         /* 0 unprobed, 1 free, 2 held */

/* Value of "<prefix>..." in a NULL-terminated env vector, or NULL. */
static const char *env_lookup(const char *const *envp, const char *prefix) {
    size_t plen = strlen(prefix);
    if (!envp) return NULL;
    for (size_t i = 0; envp[i]; i++) {
        if (strncmp(envp[i], prefix, plen) == 0) return envp[i] + plen;
    }
    return NULL;
}

/* Drives the full first-time flow: the idempotency probe misses (key not in
 * the isolated home yet), the export hands back a known armor, and the import
 * records everything the assertions need — env direction, stdin bytes, and
 * whether <base>/.lock was held at that moment (flock treats a second fd in
 * the same process as a conflicting locker, so LOCK_NB from inside the fake
 * runner faithfully reports whether gpg_switch_account holds the lock). */
static int import_flow_runner(const char *const argv[], const run_opts_t *opts,
                              run_result_t *result) {
    bool is_export = false, is_import = false, is_listing = false;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "gpg") == 0) {
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--export-secret-keys") == 0) is_export = true;
            if (strcmp(argv[i], "--import") == 0) is_import = true;
            if (strcmp(argv[i], "--list-secret-keys") == 0) is_listing = true;
        }
    }
    if (is_listing) {
        if (result) result->exit_code = 2;
        return -1; /* not in the isolated home: forces the export/import path */
    }
    if (is_export) {
        g_imp_export_had_gnupghome =
            env_lookup(opts ? opts->extra_env : NULL, "GNUPGHOME=") != NULL;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", FAKE_ARMOR);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (is_import) {
        const char *gh = env_lookup(opts ? opts->extra_env : NULL, "GNUPGHOME=");
        char lock_path[700];
        int fd;

        g_imp_import_count++;
        snprintf(g_imp_import_gnupghome, sizeof(g_imp_import_gnupghome),
                 "%s", gh ? gh : "");
        g_imp_import_stdin_len = 0;
        if (opts && opts->input && opts->input_len < sizeof(g_imp_import_stdin)) {
            memcpy(g_imp_import_stdin, opts->input, opts->input_len);
            g_imp_import_stdin_len = opts->input_len;
        }

        /* AR-03 L12 probe: is the base lock held while the import runs? */
        snprintf(lock_path, sizeof(lock_path), "%s/.lock", g_imp_base);
        fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0) {
            if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
                g_imp_lock_at_import = 1;
                flock(fd, LOCK_UN);
            } else if (errno == EWOULDBLOCK) {
                g_imp_lock_at_import = 2;
            }
            close(fd);
        }
        return 0;
    }
    return 0; /* gpgconf etc. */
}

/* Shared setup+run for the two import-flow tests below; returns switch rc. */
static int run_first_time_import(char *home_expect, size_t home_expect_size) {
    char xdg[128];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    if (!mkdtemp(xdg) || chmod(xdg, 0700) != 0) return -99;
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    snprintf(g_imp_base, sizeof(g_imp_base), "%s/gitswitch-gpg", xdg);
    snprintf(home_expect, home_expect_size, "%s/imp", g_imp_base);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "imp");
    snprintf(acct.email, sizeof(acct.email), "i@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = false; /* keep the flow to probe/export/import */
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "AABBCCDD00112233");

    g_imp_import_count = 0;
    g_imp_export_had_gnupghome = true; /* must be proven false */
    g_imp_import_gnupghome[0] = '\0';
    g_imp_import_stdin_len = 0;
    g_imp_lock_at_import = 0;

    prev = run_set_runner(import_flow_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    return rc;
}

TEST(first_time_import_is_directional_and_isolated) {
    char home_expect[720];

    CHECK_EQ_INT(run_first_time_import(home_expect, sizeof(home_expect)), 0);

    /* Import ran exactly once, INTO the isolated home... */
    CHECK_EQ_INT(g_imp_import_count, 1);
    CHECK_STR_EQ(g_imp_import_gnupghome, home_expect);

    /* ...the export read the SYSTEM keyring (no GNUPGHOME override)... */
    CHECK(!g_imp_export_had_gnupghome);

    /* ...and the import's stdin is byte-for-byte the exported armor. */
    CHECK_EQ_INT((long)g_imp_import_stdin_len, (long)strlen(FAKE_ARMOR));
    CHECK(g_imp_import_stdin_len == strlen(FAKE_ARMOR) &&
          memcmp(g_imp_import_stdin, FAKE_ARMOR, g_imp_import_stdin_len) == 0);
}

/* ---- AR-03 L12: create+import run under the base lock -------------------- */

TEST(first_time_import_runs_under_base_lock) {
    char home_expect[720], link_path[512], target[512];
    ssize_t n;

    CHECK_EQ_INT(run_first_time_import(home_expect, sizeof(home_expect)), 0);

    /* The fake runner's flock(LOCK_NB) probe found <base>/.lock HELD while
     * the import executed (pre-fix: free — only the retarget was locked, so
     * a concurrent reset could remove_tree the home mid-import). */
    CHECK_EQ_INT(g_imp_lock_at_import, 2);

    /* And the retarget under that same held lock installed `current`. */
    CHECK_EQ_INT(gpg_manager_get_home_path(link_path, sizeof(link_path)), 0);
    n = readlink(link_path, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK_STR_EQ(target, home_expect);
    }
}

/* ---- AR-03 L12: the retarget re-checks the home before linking ----------- */

TEST(retarget_current_refuses_missing_home) {
    char xdg[128], base[256], ghost[512], real_home[512];
    char link_path[512], target[512];
    struct stat st;
    ssize_t n;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);

    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    snprintf(ghost, sizeof(ghost), "%s/ghost", base);

    /* A home a reset already removed must NOT be linked: pointing every
     * `gitswitch init` shell at a missing keyring is worse than no link. */
    CHECK_EQ_INT(gpg_manager_retarget_current(ghost), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(gpg_manager_get_home_path(link_path, sizeof(link_path)), 0);
    CHECK(lstat(link_path, &st) != 0); /* no dangling link installed */

    /* Positive control: a live home still retargets. */
    snprintf(real_home, sizeof(real_home), "%s/work", base);
    CHECK_EQ_INT(mkdir(real_home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(real_home), 0);
    n = readlink(link_path, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK_STR_EQ(target, real_home);
    }
}

/* ---- AR-03 L4: a truncated colons capture is inconclusive ---------------- */

/* Primary that only certifies — no 's' anywhere in the visible capture. */
#define SEC_CERT_ONLY "sec:-:255:22:1111111111111111:1700000000:::-:::cC:::+:::ed25519::\n"

static int  g_l4_listings;
static bool g_l4_first_truncated;

/* Key present in the isolated home, but the idempotency probe's capture
 * overflows: the visible prefix shows no signing capability because the
 * signing `ssb` fell in the dropped tail. A follow-up listing (smaller key
 * of the same id re-asked by gpg_test_signing) completes and shows 's'. */
static int truncated_probe_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    bool is_listing = false;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "gpg") == 0) {
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) is_listing = true;
        }
    }
    if (!is_listing) {
        return 0;
    }
    g_l4_listings++;
    if (opts && opts->out) {
        if (g_l4_listings == 1 && g_l4_first_truncated) {
            snprintf(opts->out, opts->out_size, "%s", SEC_CERT_ONLY);
            if (result) {
                result->out_len = strlen(opts->out);
                result->out_truncated = true; /* capture is INCOMPLETE */
            }
        } else {
            snprintf(opts->out, opts->out_size, "%s", SEC_SIGN);
            if (result) result->out_len = strlen(opts->out);
        }
    }
    return 0;
}

TEST(truncated_idempotency_probe_is_not_signing_evidence) {
    char xdg[128];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "bigly");
    snprintf(acct.email, sizeof(acct.email), "b@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "FEEDFACE01234567");

    g_l4_listings = 0;
    g_l4_first_truncated = true;
    prev = run_set_runner(truncated_probe_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    /* The truncated probe must NOT be treated as the signing evidence: the
     * switch re-asks with a fresh listing (2 spawns). Pre-fix it answered the
     * capability question from the truncated capture (1 spawn) and warned
     * "GPG signing test failed" for a perfectly good key. */
    CHECK_EQ_INT(g_l4_listings, 2);

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* Fixed listing + truncation flag for driving gpg_test_signing directly. */
static const char *g_sig_listing;
static bool        g_sig_truncated;

static int fixed_listing_runner(const char *const argv[],
                                const run_opts_t *opts,
                                run_result_t *result) {
    (void)argv;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", g_sig_listing);
        if (result) {
            result->out_len = strlen(opts->out);
            result->out_truncated = g_sig_truncated;
        }
    }
    return 0;
}

TEST(gpg_test_signing_treats_truncated_listing_as_inconclusive) {
    gpg_config_t cfg;
    command_runner_fn prev;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_SYSTEM;

    prev = run_set_runner(fixed_listing_runner);

    /* Truncated capture without a visible 's': inconclusive, NOT a failure
     * (pre-fix: -1, surfacing as a spurious switch-time warning). */
    g_sig_listing = SEC_CERT_ONLY;
    g_sig_truncated = true;
    CHECK_EQ_INT(gpg_test_signing(&cfg, "1111111111111111"), 0);

    /* A COMPLETE capture without 's' stays an authoritative failure — the
     * truncation carve-out must not fail open on real capability absence. */
    g_sig_truncated = false;
    CHECK_EQ_INT(gpg_test_signing(&cfg, "1111111111111111"), -1);

    /* Positive control: a complete, capable listing passes. */
    g_sig_listing = SEC_SIGN;
    CHECK_EQ_INT(gpg_test_signing(&cfg, "FEEDFACE01234567"), 0);

    run_set_runner(prev);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(repeat_isolated_switch_spawns_gpg_once);
    RUN_TEST(isolated_switch_fails_when_current_cannot_be_retargeted);
    RUN_TEST(truncated_secret_key_export_is_never_imported);
    RUN_TEST(first_time_import_is_directional_and_isolated);
    RUN_TEST(first_time_import_runs_under_base_lock);
    RUN_TEST(retarget_current_refuses_missing_home);
    RUN_TEST(truncated_idempotency_probe_is_not_signing_evidence);
    RUN_TEST(gpg_test_signing_treats_truncated_listing_as_inconclusive);
TEST_MAIN_END()
