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
#include "signals.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A real `sec` line whose capability field (12) contains 's'. */
#define SEC_SIGN "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n"

static int g_gpg_execs;
static const char *env_lookup(const char *const *envp, const char *prefix);

static int read_link_target(const char *path, char *target, size_t size) {
    ssize_t n;

    if (!path || !target || size < 2) return -1;
    n = readlink(path, target, size - 1);
    if (n <= 0 || (size_t)n == size - 1) return -1;
    target[n] = '\0';
    return 0;
}

static bool has_gpg_config_scratch(const char *home) {
    static const char prefix[] = ".gpg-agent.conf.gitswitch.";
    DIR *dir = opendir(home);
    struct dirent *entry;
    bool found = false;

    if (!dir) return false;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

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

static const char *g_switch_swap_base;
static const char *g_switch_swap_moved;
static const char *g_switch_swap_home;
static const char *g_switch_swap_marker;
static bool g_switch_swap_pending;
static bool g_switch_swap_used_pinned_home;
static bool g_switch_swap_exported_secret;
static bool g_switch_swap_imported_secret;

static int swap_base_after_retarget_commit(int base_fd) {
    (void)base_fd;
    if (!g_switch_swap_base || !g_switch_swap_moved ||
        rename(g_switch_swap_base, g_switch_swap_moved) != 0 ||
        mkdir(g_switch_swap_base, 0700) != 0) {
        return -1;
    }
    return 0;
}

static int swapping_listing_runner(const char *const argv[],
                                   const run_opts_t *opts,
                                   run_result_t *result) {
    bool listing = false;
    struct stat cwd_st;
    struct stat named_st;
    const char *gh = NULL;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (strcmp(argv[0], "gpg") == 0) {
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) listing = true;
            if (strcmp(argv[i], "--export-secret-keys") == 0) {
                g_switch_swap_exported_secret = true;
            }
            if (strcmp(argv[i], "--import") == 0) {
                g_switch_swap_imported_secret = true;
            }
        }
    }
    if (listing && g_switch_swap_pending) {
        gh = env_lookup(opts ? opts->extra_env : NULL, "GNUPGHOME=");
        g_switch_swap_used_pinned_home = opts && opts->use_cwd_fd &&
            opts->cwd_fd >= 0 && gh && strcmp(gh, ".") == 0 &&
            fstat(opts->cwd_fd, &cwd_st) == 0 &&
            stat(g_switch_swap_home, &named_st) == 0 &&
            cwd_st.st_dev == named_st.st_dev && cwd_st.st_ino == named_st.st_ino;
        g_switch_swap_pending = false;
        if (rename(g_switch_swap_base, g_switch_swap_moved) != 0 ||
            mkdir(g_switch_swap_base, 0700) != 0 ||
            mkdir(g_switch_swap_home, 0700) != 0 ||
            write_string_to_file(g_switch_swap_marker, "replacement\n", 0600) != 0) {
            if (result) result->exit_code = 9;
            return -1;
        }
    }
    if (listing && opts && opts->out) {
        snprintf(opts->out, opts->out_size, "%s", SEC_SIGN);
        if (result) result->out_len = strlen(opts->out);
    }
    return 0;
}

static int write_repeated_bytes(const char *path, size_t count) {
    char block[4096];
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    memset(block, 'x', sizeof(block));
    while (count > 0) {
        size_t chunk = count < sizeof(block) ? count : sizeof(block);
        ssize_t written = write(fd, block, chunk);
        if (written > 0) {
            count -= (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return -1;
        }
    }
    return close(fd);
}

TEST(repeat_isolated_switch_spawns_gpg_once) {
    char xdg[128], link_path[512], target[512];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    ssize_t n;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
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
    CHECK(ts_mkdtemp(xdg) != NULL);
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
    CHECK(ts_mkdtemp(xdg) != NULL);
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
static char   g_imp_home[700];
static int    g_imp_import_count;
static bool   g_imp_export_had_gnupghome;
static char   g_imp_export_gnupghome[600];  /* GNUPGHOME override at export; "" = absent */
static char   g_imp_import_gnupghome[600];  /* GNUPGHOME value at import; "" = absent */
static bool   g_imp_import_used_pinned_home;
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
        const char *egh = env_lookup(opts ? opts->extra_env : NULL, "GNUPGHOME=");
        g_imp_export_had_gnupghome = egh != NULL;
        snprintf(g_imp_export_gnupghome, sizeof(g_imp_export_gnupghome),
                 "%s", egh ? egh : "");
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", FAKE_ARMOR);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (is_import) {
        const char *gh = env_lookup(opts ? opts->extra_env : NULL, "GNUPGHOME=");
        char lock_path[700];
        struct stat cwd_st;
        struct stat named_st;
        int fd;

        g_imp_import_count++;
        snprintf(g_imp_import_gnupghome, sizeof(g_imp_import_gnupghome),
                 "%s", gh ? gh : "");
        g_imp_import_used_pinned_home = opts && opts->use_cwd_fd &&
            opts->cwd_fd >= 0 && gh && strcmp(gh, ".") == 0 &&
            fstat(opts->cwd_fd, &cwd_st) == 0 &&
            stat(g_imp_home, &named_st) == 0 &&
            cwd_st.st_dev == named_st.st_dev && cwd_st.st_ino == named_st.st_ino;
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

    char managed_gnupghome[700];
    char *prev_home = getenv("HOME");
    char *prev_gnupghome = getenv("GNUPGHOME");
    char saved_home[600] = "";
    char saved_gnupghome[600] = "";
    bool had_home = prev_home != NULL;
    bool had_gnupghome = prev_gnupghome != NULL;
    if (had_home) snprintf(saved_home, sizeof(saved_home), "%s", prev_home);
    if (had_gnupghome) snprintf(saved_gnupghome, sizeof(saved_gnupghome), "%s", prev_gnupghome);

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    if (!ts_mkdtemp(xdg) || chmod(xdg, 0700) != 0) return -99;
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    snprintf(g_imp_base, sizeof(g_imp_base), "%s/gitswitch-gpg", xdg);
    snprintf(home_expect, home_expect_size, "%s/imp", g_imp_base);
    snprintf(g_imp_home, sizeof(g_imp_home), "%s", home_expect);

    /* AR-06 F05/F06 precondition: an integrated shell exports a gitswitch-
     * managed GNUPGHOME (<base>/current). The system-keyring export must NOT
     * inherit it — it must resolve to the real keyring instead. HOME is set so
     * the fallback ($HOME/.gnupg) is deterministic. */
    setenv("HOME", xdg, 1);
    snprintf(managed_gnupghome, sizeof(managed_gnupghome), "%s/current", g_imp_base);
    setenv("GNUPGHOME", managed_gnupghome, 1);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "imp");
    snprintf(acct.email, sizeof(acct.email), "i@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = false; /* keep the flow to probe/export/import */
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "AABBCCDD00112233");

    g_imp_import_count = 0;
    g_imp_export_had_gnupghome = false;
    g_imp_export_gnupghome[0] = '\0';
    g_imp_import_gnupghome[0] = '\0';
    g_imp_import_used_pinned_home = false;
    g_imp_import_stdin_len = 0;
    g_imp_lock_at_import = 0;

    prev = run_set_runner(import_flow_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
    /* Restore HOME/GNUPGHOME so this shared helper doesn't leak the managed
     * value (or a soon-to-be-removed /tmp HOME) into later tests. */
    if (had_home) setenv("HOME", saved_home, 1); else unsetenv("HOME");
    if (had_gnupghome) setenv("GNUPGHOME", saved_gnupghome, 1); else unsetenv("GNUPGHOME");
    return rc;
}

TEST(first_time_import_is_directional_and_isolated) {
    char home_expect[720];

    CHECK_EQ_INT(run_first_time_import(home_expect, sizeof(home_expect)), 0);

    /* Import ran exactly once, INTO the isolated home... */
    CHECK_EQ_INT(g_imp_import_count, 1);
    CHECK_STR_EQ(g_imp_import_gnupghome, ".");
    CHECK(g_imp_import_used_pinned_home);

    /* ...the export read the SYSTEM keyring via an EXPLICIT GNUPGHOME override
     * that resolves away from the gitswitch-managed home the shell exported
     * (AR-06 F05/F06): the old code passed no override and would have inherited
     * <base>/current, reading the wrong keyring and failing closed. */
    CHECK(g_imp_export_had_gnupghome);
    CHECK(strstr(g_imp_export_gnupghome, "gitswitch-gpg") == NULL);

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
    CHECK(ts_mkdtemp(xdg) != NULL);
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

/* ---- AR-04 GPG config install: inherited 0400 remains usable ------------ */

static char g_fifo_source[MAX_PATH_LEN];
static char g_fifo_backup[MAX_PATH_LEN];
static bool g_fifo_swap_ok;

static void swap_agent_conf_to_fifo(const char *path) {
    g_fifo_swap_ok = path && strcmp(path, g_fifo_source) == 0 &&
        rename(g_fifo_source, g_fifo_backup) == 0 &&
        mkfifo(g_fifo_source, 0600) == 0;
}

static char g_conf_commit_saved[64];
static char g_conf_commit_replacement[64];
static bool g_conf_commit_swap_ok;

static int swap_agent_conf_temp_before_commit(int home_fd,
                                              const char *temp_name) {
    static const char replacement[] = "replacement-not-written-by-gitswitch\n";
    int fd = -1;

    g_conf_commit_swap_ok = false;
    if (home_fd < 0 || !temp_name || !*temp_name || strchr(temp_name, '/')) {
        return -1;
    }
    if (safe_strncpy(g_conf_commit_replacement, temp_name,
                     sizeof(g_conf_commit_replacement)) != 0 ||
        safe_strncpy(g_conf_commit_saved, ".gpg-agent.conf.saved-by-test",
                     sizeof(g_conf_commit_saved)) != 0) {
        return -1;
    }
    (void)unlinkat(home_fd, g_conf_commit_saved, 0);
    if (renameat(home_fd, temp_name, home_fd, g_conf_commit_saved) != 0) {
        return -1;
    }
    fd = openat(home_fd, temp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (fd < 0 || write(fd, replacement, sizeof(replacement) - 1) !=
                        (ssize_t)(sizeof(replacement) - 1)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (close(fd) != 0) return -1;
    g_conf_commit_swap_ok = true;
    return 0;
}

TEST(inherited_readonly_agent_config_is_installed_atomically_at_0600) {
    static const char inherited_conf[] =
        "# user agent settings\n"
        "default-cache-ttl 99\n"
        "pinentry-program /opt/user/pinentry\n";
    char xdg[128], source_home[256], source_conf[320];
    char installed[MAX_PATH_LEN], content[1024];
    struct stat source_st, installed_st;
    gpg_config_t cfg;
    account_t acct;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgconf_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    snprintf(source_home, sizeof(source_home), "%s/user-gnupg", xdg);
    snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf", source_home);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(write_string_to_file(source_conf, inherited_conf, 0600), 0);
    CHECK_EQ_INT(chmod(source_conf, 0400), 0);

    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);
    setenv("GNUPGHOME", source_home, 1);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "readonlyconf");

    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), 0);
    CHECK_EQ_INT(safe_snprintf(installed, sizeof(installed),
                               "%s/gpg-agent.conf", cfg.gnupg_home), 0);
    CHECK_EQ_INT(stat(source_conf, &source_st), 0);
    CHECK_EQ_INT(stat(installed, &installed_st), 0);
    CHECK_EQ_INT(source_st.st_mode & 0777, 0400);
    CHECK_EQ_INT(installed_st.st_mode & 0777, 0600); /* pre-fix: inherited 0400 */
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)strlen(inherited_conf));
    CHECK_STR_EQ(content, inherited_conf);
    CHECK(!has_gpg_config_scratch(cfg.gnupg_home));

    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* The inherited config is first inspected with lstat and then opened. A
 * same-uid swap to a FIFO in that gap must be rejected without waiting for a
 * writer; O_NOFOLLOW alone does not make FIFO open nonblocking. */
TEST(inherited_agent_config_fifo_swap_is_nonblocking_and_rejected) {
    char xdg[128], source_home[256], installed[MAX_PATH_LEN];
    char original[128];
    gpg_config_t cfg;
    account_t acct;
    pid_t pid;
    int status = 0;
    int waited_ms = 0;
    bool finished = false;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgfifo_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    snprintf(source_home, sizeof(source_home), "%s/user-gnupg", xdg);
    snprintf(g_fifo_source, sizeof(g_fifo_source), "%s/gpg-agent.conf",
             source_home);
    snprintf(g_fifo_backup, sizeof(g_fifo_backup), "%s/gpg-agent.conf.old",
             source_home);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(write_string_to_file(g_fifo_source, "cache-ttl 77\n", 0600), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "fifoswap");
    snprintf(installed, sizeof(installed),
             "%s/gitswitch-gpg/fifoswap/gpg-agent.conf", xdg);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) return;
    if (pid == 0) {
        struct stat fifo_st;
        gpg_agent_conf_preopen_fn previous;
        int rc;

        g_fifo_swap_ok = false;
        previous = gpg_manager_set_agent_conf_preopen_fn(
            swap_agent_conf_to_fifo);
        rc = gpg_create_isolated_home(&cfg, &acct);
        gpg_manager_set_agent_conf_preopen_fn(previous);
        if (rc != 0 || !g_fifo_swap_ok || path_exists(installed) ||
            has_gpg_config_scratch(cfg.gnupg_home) ||
            lstat(g_fifo_source, &fifo_st) != 0 || !S_ISFIFO(fifo_st.st_mode)) {
            _exit(9);
        }
        _exit(0);
    }

    while (waited_ms < 2000) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            finished = true;
            break;
        }
        if (waited < 0) break;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
        nanosleep(&pause, NULL);
        waited_ms += 10;
    }
    if (!finished) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
    }
    CHECK(finished);
    if (finished) {
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK_EQ_INT(read_file_to_string(g_fifo_backup, original,
                                     sizeof(original)), 13);
    CHECK_STR_EQ(original, "cache-ttl 77\n");
    CHECK(!path_exists(installed));

    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

TEST(inherited_agent_config_refuses_symlink_and_oversize_source) {
    char xdg[128], source_home[256], source_conf[320], victim[320];
    char installed[MAX_PATH_LEN], content[64];
    struct stat st;
    gpg_config_t cfg;
    account_t acct;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgconf_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    snprintf(source_home, sizeof(source_home), "%s/user-gnupg", xdg);
    snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf", source_home);
    snprintf(victim, sizeof(victim), "%s/precious", xdg);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(write_string_to_file(victim, "do-not-copy\n", 0600), 0);
    CHECK_EQ_INT(symlink(victim, source_conf), 0);

    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "confsymlink");

    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), 0);
    CHECK_EQ_INT(safe_snprintf(installed, sizeof(installed),
                               "%s/gpg-agent.conf", cfg.gnupg_home), 0);
    CHECK(lstat(installed, &st) != 0 && errno == ENOENT);
    CHECK(!has_gpg_config_scratch(cfg.gnupg_home));
    CHECK_EQ_INT(read_file_to_string(victim, content, sizeof(content)), 12);
    CHECK_STR_EQ(content, "do-not-copy\n");

    CHECK_EQ_INT(unlink(source_conf), 0);
    CHECK_EQ_INT(write_repeated_bytes(source_conf, 64U * 1024U + 1U), 0);
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    snprintf(acct.name, sizeof(acct.name), "confoversize");
    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), 0);
    CHECK_EQ_INT(safe_snprintf(installed, sizeof(installed),
                               "%s/gpg-agent.conf", cfg.gnupg_home), 0);
    CHECK(lstat(installed, &st) != 0 && errno == ENOENT);
    CHECK(!has_gpg_config_scratch(cfg.gnupg_home));
    CHECK_EQ_INT(stat(source_conf, &st), 0);
    CHECK_EQ_INT((long long)st.st_size, (long long)(64U * 1024U + 1U));

    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

TEST(agent_config_temp_substitution_is_rejected_without_deleting_replacement) {
    static const char replacement[] = "replacement-not-written-by-gitswitch\n";
    char xdg[128], source_home[256], installed[MAX_PATH_LEN];
    char saved[MAX_PATH_LEN], substitute[MAX_PATH_LEN], content[256];
    struct stat st;
    gpg_agent_conf_precommit_fn previous;
    gpg_config_t cfg;
    account_t acct;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgcommit_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    snprintf(source_home, sizeof(source_home), "%s/source-home", xdg);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "tempswap");

    g_conf_commit_saved[0] = '\0';
    g_conf_commit_replacement[0] = '\0';
    g_conf_commit_swap_ok = false;
    previous = gpg_manager_set_agent_conf_precommit_fn(
        swap_agent_conf_temp_before_commit);
    CHECK_EQ_INT(gpg_create_isolated_home(&cfg, &acct), 0);
    gpg_manager_set_agent_conf_precommit_fn(previous);

    CHECK(g_conf_commit_swap_ok);
    CHECK_EQ_INT(safe_snprintf(installed, sizeof(installed),
                               "%s/gpg-agent.conf", cfg.gnupg_home), 0);
    CHECK_EQ_INT(safe_snprintf(saved, sizeof(saved), "%s/%s",
                               cfg.gnupg_home, g_conf_commit_saved), 0);
    CHECK_EQ_INT(safe_snprintf(substitute, sizeof(substitute), "%s/%s",
                               cfg.gnupg_home,
                               g_conf_commit_replacement), 0);
    CHECK(lstat(installed, &st) != 0 && errno == ENOENT);
    CHECK_EQ_INT(read_file_to_string(substitute, content, sizeof(content)),
                 (int)(sizeof(replacement) - 1));
    CHECK_STR_EQ(content, replacement);
    CHECK_EQ_INT(lstat(saved, &st), 0);
    CHECK(S_ISREG(st.st_mode));

    /* The normal failure cleanup and the signal scratch registry must both
     * refuse to unlink the pathname which no longer names our opened inode. */
    signals_scratch_cleanup();
    CHECK_EQ_INT(read_file_to_string(substitute, content, sizeof(content)),
                 (int)(sizeof(replacement) - 1));
    CHECK_STR_EQ(content, replacement);

    CHECK_EQ_INT(unlink(substitute), 0);
    CHECK_EQ_INT(unlink(saved), 0);
    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

TEST(gpg_switch_refuses_retarget_after_base_namespace_replacement) {
    char xdg[128], base[256], moved[256], replacement_home[320];
    char replacement_marker[384], current[320], moved_current[320];
    struct stat st;
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgswap_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", "/before/gpg-home", 1), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(moved, sizeof(moved), "%s/gitswitch-gpg.old", xdg);
    snprintf(replacement_home, sizeof(replacement_home), "%s/work", base);
    snprintf(replacement_marker, sizeof(replacement_marker), "%s/replacement",
             replacement_home);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(moved_current, sizeof(moved_current), "%s/current", moved);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "work");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "FEEDFACE01234567");

    g_switch_swap_base = base;
    g_switch_swap_moved = moved;
    g_switch_swap_home = replacement_home;
    g_switch_swap_marker = replacement_marker;
    g_switch_swap_pending = true;
    g_switch_swap_used_pinned_home = false;
    g_switch_swap_exported_secret = false;
    g_switch_swap_imported_secret = false;
    prev = run_set_runner(swapping_listing_runner);
    CHECK_EQ_INT(gpg_switch_account(&cfg, &acct), -1);
    run_set_runner(prev);

    CHECK(path_exists(replacement_marker));
    CHECK(g_switch_swap_used_pinned_home);
    CHECK(!g_switch_swap_exported_secret);
    CHECK(!g_switch_swap_imported_secret);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    CHECK(lstat(moved_current, &st) != 0 && errno == ENOENT);
    CHECK(cfg.current_key_id[0] == '\0');
    CHECK(!cfg.signing_enabled);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/before/gpg-home");

    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

/* Revalidate after the atomic current-link rename, not merely before it.  A
 * replacement at the commit breakpoint must fail and remove only the exact
 * link inode installed in the now-moved pinned base. */
TEST(gpg_retarget_revalidates_public_base_after_commit) {
    char xdg[128], base[256], moved[256], home[320];
    char current[320], moved_current[320];
    struct stat st;
    gpg_retarget_commit_hook_fn previous;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgpost_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(moved, sizeof(moved), "%s/gitswitch-gpg.old", xdg);
    snprintf(home, sizeof(home), "%s/work", base);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(moved_current, sizeof(moved_current), "%s/current", moved);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);

    g_switch_swap_base = base;
    g_switch_swap_moved = moved;
    previous = gpg_manager_set_retarget_commit_hook_fn(
        swap_base_after_retarget_commit);
    CHECK_EQ_INT(gpg_manager_retarget_current(home), -1);
    gpg_manager_set_retarget_commit_hook_fn(previous);

    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    CHECK(lstat(moved_current, &st) != 0 && errno == ENOENT);
}

/* ---- AR-04 GPG runtime CAS: exact target + later-writer preservation ----- */

TEST(gpg_current_snapshot_and_conditional_restore_are_compare_and_swap) {
    char xdg[128], base[256], current[320];
    char one[320], two[320], three[320], external[320];
    char snapshot[MAX_PATH_LEN], target[MAX_PATH_LEN];
    struct stat st;
    bool present = false;
    bool changed = false;
    bool live = false;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgcas_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(one, sizeof(one), "%s/one", base);
    snprintf(two, sizeof(two), "%s/two", base);
    snprintf(three, sizeof(three), "%s/three", base);
    snprintf(external, sizeof(external), "%s/external", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(one, 0700), 0);
    CHECK_EQ_INT(mkdir(two, 0700), 0);
    CHECK_EQ_INT(mkdir(three, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    CHECK_EQ_INT(gpg_manager_snapshot_current(snapshot, sizeof(snapshot), &present), 0);
    CHECK(present);
    CHECK_STR_EQ(snapshot, one);
    CHECK_EQ_INT(gpg_manager_current_is_live_for_account("one", &live), 0);
    CHECK(live);
    CHECK_EQ_INT(gpg_manager_current_is_live_for_account("two", &live), 0);
    CHECK(!live);

    /* Simulate a later writer selecting `two`. A rollback still expecting
     * `one` must report a conflict and preserve that later state. */
    CHECK_EQ_INT(gpg_manager_retarget_current(two), 0);
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(one, three, &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_link_target(current, target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* Positive restore: the exact expected state is atomically replaced. */
    CHECK_EQ_INT(gpg_manager_restore_current_if(two, one, &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_link_target(current, target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);

    /* Both the destination and the observed current state must remain exact
     * managed children; an external directory is never accepted by basename. */
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(one, external, &changed), -1);
    CHECK(!changed);
    CHECK_EQ_INT(read_link_target(current, target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);

    CHECK_EQ_INT(gpg_manager_restore_current_if(one, NULL, &changed), 0);
    CHECK(changed);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    present = true;
    CHECK_EQ_INT(gpg_manager_snapshot_current(snapshot, sizeof(snapshot), &present), 0);
    CHECK(!present);
    CHECK_EQ_INT(gpg_manager_restore_current_if(NULL, two, &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_link_target(current, target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* A corrupted current link that escapes the private base is not an
     * ordinary account mismatch: every public reader/CAS fails closed. */
    CHECK_EQ_INT(unlink(current), 0);
    CHECK_EQ_INT(symlink(external, current), 0);
    present = true;
    CHECK_EQ_INT(gpg_manager_snapshot_current(snapshot, sizeof(snapshot), &present), -1);
    CHECK(!present);
    CHECK_EQ_INT(gpg_manager_current_is_live_for_account("one", &live), -1);
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(two, one, &changed), -1);
    CHECK(!changed);
}

/* The public reader must take the same blocking base lock as switch/reset/CAS,
 * otherwise its "snapshot" can race the very retarget it is meant to guard. */
TEST(gpg_current_snapshot_blocks_on_base_lock) {
    char xdg[128], base[256], home[320], lock_path[320];
    char held[320], done[320], snapshot[MAX_PATH_LEN];
    bool present = false;
    pid_t pid;
    int status = 0;
    int waited = 0;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpglock_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/locked", base);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    snprintf(held, sizeof(held), "%s/held", xdg);
    snprintf(done, sizeof(done), "%s/done", xdg);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(home), 0);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) return;
    if (pid == 0) {
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 400000000 };
        int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || flock(fd, LOCK_EX) != 0) _exit(9);
        if (write_string_to_file(held, "held", 0600) != 0) _exit(9);
        nanosleep(&delay, NULL);
        if (write_string_to_file(done, "done", 0600) != 0) _exit(9);
        flock(fd, LOCK_UN);
        close(fd);
        _exit(0);
    }

    while (!path_exists(held) && waited < 5000) {
        struct timespec poll = { .tv_sec = 0, .tv_nsec = 10000000 };
        nanosleep(&poll, NULL);
        waited += 10;
    }
    CHECK(path_exists(held));
    CHECK_EQ_INT(gpg_manager_snapshot_current(snapshot, sizeof(snapshot), &present), 0);
    CHECK(present);
    CHECK_STR_EQ(snapshot, home);
    CHECK(path_exists(done)); /* proves snapshot returned only after lock release */
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
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
    CHECK(ts_mkdtemp(xdg) != NULL);
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
    RUN_TEST(inherited_readonly_agent_config_is_installed_atomically_at_0600);
    RUN_TEST(inherited_agent_config_fifo_swap_is_nonblocking_and_rejected);
    RUN_TEST(inherited_agent_config_refuses_symlink_and_oversize_source);
    RUN_TEST(agent_config_temp_substitution_is_rejected_without_deleting_replacement);
    RUN_TEST(gpg_switch_refuses_retarget_after_base_namespace_replacement);
    RUN_TEST(gpg_retarget_revalidates_public_base_after_commit);
    RUN_TEST(gpg_current_snapshot_and_conditional_restore_are_compare_and_swap);
    RUN_TEST(gpg_current_snapshot_blocks_on_base_lock);
    RUN_TEST(truncated_idempotency_probe_is_not_signing_evidence);
    RUN_TEST(gpg_test_signing_treats_truncated_listing_as_inconclusive);
TEST_MAIN_END()
