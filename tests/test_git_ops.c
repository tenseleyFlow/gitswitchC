/* git_ops tests: SSH key-path injection hardening (ssh-1) and the
 * process-scoped write/snapshot bookkeeping (perf-1, perf-3, perf-4).
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
typedef void *(*git_snapshot_value_malloc_fn)(size_t size);
git_snapshot_value_malloc_fn git_ops_test_set_snapshot_value_malloc_fn(
    git_snapshot_value_malloc_fn fn);

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
static int fk_effective_reads; /* atomic merged managed-key listing reads */
static bool fk_is_repo;        /* what `git rev-parse --git-dir` reports */
static const char *fk_repo_root_output;
static int fk_repo_root_exit;

static void fk_reset(void) {
    memset(fk_store, 0, sizeof(fk_store));
    fk_execs = 0;
    fk_identity_reads = 0;
    fk_effective_reads = 0;
    fk_is_repo = false;
    fk_repo_root_output = NULL;
    fk_repo_root_exit = 1;
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

    if (strcmp(argv[1], "rev-parse") == 0 && argv[2] &&
        strcmp(argv[2], "--show-toplevel") == 0) {
        size_t length;
        size_t copied;

        if (fk_repo_root_exit != 0 || !fk_repo_root_output) {
            return fk_ret(result, fk_repo_root_exit ? fk_repo_root_exit : 1);
        }
        length = strlen(fk_repo_root_output);
        copied = opts && opts->out && opts->out_size > 0
            ? (length < opts->out_size - 1U ? length : opts->out_size - 1U)
            : 0;
        if (copied > 0) memcpy(opts->out, fk_repo_root_output, copied);
        if (opts && opts->out && opts->out_size > 0) opts->out[copied] = '\0';
        if (result) {
            result->out_len = copied;
            result->out_truncated = copied != length;
        }
        return fk_ret(result, 0);
    }

    if (strcmp(argv[1], "rev-parse") == 0) {
        return fk_ret(result, fk_is_repo ? 0 : 1);
    }

    if (strcmp(argv[1], "config") == 0 && argv[2] && argv[3]) {
        if (strcmp(argv[2], "--show-origin") == 0) {
            fk_effective_reads++;
            return fk_emit_effective_listing(opts, result);
        }
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

/* ---- M23: repository root is complete, exact, and fail-cleared ---------- */

TEST(git_get_repo_root_requires_complete_exact_output) {
    char path[64];
    char tiny[5];
    char oversized[MAX_PATH_LEN + 64U];

    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);

    fk_repo_root_exit = 0;
    fk_repo_root_output = "/tmp/project\n";
    memset(path, 'x', sizeof(path));
    CHECK_EQ_INT(git_get_repo_root(path, sizeof(path)), 0);
    CHECK_STR_EQ(path, "/tmp/project");

    /* Only Git's one line ending is removed; a valid trailing path space is
     * data and must not be normalized away. */
    fk_repo_root_output = "/tmp/project \n";
    memset(path, 'x', sizeof(path));
    CHECK_EQ_INT(git_get_repo_root(path, sizeof(path)), 0);
    CHECK_STR_EQ(path, "/tmp/project ");

    /* A complete result that does not fit the caller is an error and cannot
     * leave the caller's prior bytes looking usable. */
    fk_repo_root_output = "/tmp/project\n";
    memcpy(tiny, "old!", sizeof(tiny));
    CHECK_EQ_INT(git_get_repo_root(tiny, sizeof(tiny)), -1);
    CHECK_EQ_INT(tiny[0], '\0');

    fk_repo_root_output = "";
    memcpy(path, "old", sizeof("old"));
    CHECK_EQ_INT(git_get_repo_root(path, sizeof(path)), -1);
    CHECK_EQ_INT(path[0], '\0');

    fk_repo_root_exit = 1;
    fk_repo_root_output = NULL;
    memcpy(path, "old", sizeof("old"));
    CHECK_EQ_INT(git_get_repo_root(path, sizeof(path)), -1);
    CHECK_EQ_INT(path[0], '\0');

    memset(oversized, 'r', sizeof(oversized));
    oversized[sizeof(oversized) - 2U] = '\n';
    oversized[sizeof(oversized) - 1U] = '\0';
    fk_repo_root_exit = 0;
    fk_repo_root_output = oversized;
    memcpy(path, "old", sizeof("old"));
    CHECK_EQ_INT(git_get_repo_root(path, sizeof(path)), -1);
    CHECK_EQ_INT(path[0], '\0');

    run_set_runner(prev);
}

/* ---- L30: effective configuration capture has an operational ceiling --- */

#define TEST_GIT_INSPECTION_MAX_BYTES (8U * 1024U * 1024U)

static bool l30_complete_at_limit;
static size_t l30_largest_capture;
static int l30_capture_calls;

static int l30_effective_runner(const char *const argv[],
                                const run_opts_t *opts,
                                run_result_t *result) {
    static const char large_prefix[] =
        "global\0file:/fake/config\0unrelated.large\n";
    static const char managed_tail[] =
        "\0global\0file:/fake/config\0user.name\nLimit User\0"
        "global\0file:/fake/config\0user.email\nlimit@example.test\0";

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv[0] || strcmp(argv[0], "git") != 0 ||
        !argv[1] || strcmp(argv[1], "config") != 0 ||
        !argv[2] || strcmp(argv[2], "--show-origin") != 0 ||
        !opts || !opts->out || opts->out_size == 0) {
        return fk_ret(result, 1);
    }

    l30_capture_calls++;
    if (opts->out_size > l30_largest_capture)
        l30_largest_capture = opts->out_size;

    /* Prevent the unfixed implementation from growing forever: crossing the
     * documented ceiling becomes an observable runner failure. */
    if (opts->out_size > TEST_GIT_INSPECTION_MAX_BYTES)
        return fk_ret(result, 2);

    if (l30_complete_at_limit &&
        opts->out_size == TEST_GIT_INSPECTION_MAX_BYTES) {
        size_t prefix_length = sizeof(large_prefix) - 1U;
        size_t tail_length = sizeof(managed_tail) - 1U;
        size_t output_length = opts->out_size - 1U;
        size_t filler_length = output_length - prefix_length - tail_length;
        memcpy(opts->out, large_prefix, prefix_length);
        memset(opts->out + prefix_length, 'x', filler_length);
        memcpy(opts->out + prefix_length + filler_length,
               managed_tail, tail_length);
        opts->out[output_length] = '\0';
        if (result) {
            result->out_len = output_length;
            result->out_truncated = false;
        }
        return fk_ret(result, 0);
    }

    if (result) {
        result->out_len = opts->out_size - 1U;
        result->out_truncated = true;
    }
    return fk_ret(result, 0);
}

TEST(effective_config_capture_enforces_maximum) {
    git_current_config_t current;
    command_runner_fn prev;

    git_ops_test_reset_caches();
    unsetenv("GIT_SSH_COMMAND");
    prev = run_set_runner(l30_effective_runner);

    /* A complete result delivered at the ceiling remains valid. */
    l30_complete_at_limit = true;
    l30_largest_capture = 0;
    l30_capture_calls = 0;
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.valid);
    CHECK_STR_EQ(current.name, "Limit User");
    CHECK_STR_EQ(current.email, "limit@example.test");
    CHECK(l30_largest_capture == TEST_GIT_INSPECTION_MAX_BYTES);
    CHECK(l30_capture_calls > 1);

    /* One byte beyond the ceiling fails without exposing partial status. */
    l30_complete_at_limit = false;
    l30_largest_capture = 0;
    l30_capture_calls = 0;
    memset(&current, 'x', sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), -1);
    CHECK(!current.valid);
    CHECK_EQ_INT(current.name[0], '\0');
    CHECK(l30_largest_capture == TEST_GIT_INSPECTION_MAX_BYTES);
    CHECK(strstr(get_last_error()->message, "exceeds") != NULL);

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

    /* A later public read must execute again and observe an external writer,
     * rather than treating the first read as process-lifetime authority. */
    int signing = fk_find("--global", "user.signingkey");
    CHECK(signing >= 0);
    if (signing >= 0) {
        snprintf(fk_store[signing].value, sizeof(fk_store[signing].value),
                 "%s", "EXTERNAL0123456");
    }
    buf[0] = '\0';
    CHECK_EQ_INT(git_get_config_value("user.signingkey", buf, sizeof(buf), GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 4);
    CHECK_STR_EQ(buf, "EXTERNAL0123456");

    /* Duplicate unsets also collapse; a set after an unset must exec again. */
    CHECK_EQ_INT(git_unset_config_value("user.signingkey", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 5);
    CHECK_EQ_INT(git_unset_config_value("user.signingkey", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 5);
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "DEADBEEFCAFE1234", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 6);

    /* A different value never skips. */
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "0123456789ABCDEF", GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_execs, 7);
    int idx = fk_find("--global", "user.signingkey");
    CHECK(idx >= 0);
    if (idx >= 0) CHECK_STR_EQ(fk_store[idx].value, "0123456789ABCDEF");

    run_set_runner(prev);
}

/* ---- rollback snapshot: -z listing survives embedded newlines ----------- */
/* Regression lock for the `git config --list -z` snapshot fix: with plain
 * --list, a managed value containing a newline masqueraded as a record
 * boundary, truncating that value in the rollback snapshot AND corrupting the
 * records after it. The binary snapshot parser must keep the full
 * value and still attribute the NEXT record to the right key. */

static char zfk_set_key[16][64], zfk_set_val[16][8192];
static int zfk_sets;
static int zfk_forward_sets;
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
        if (strcmp(argv[3], "--add") == 0 && argv[4] && argv[5]) {
            if (zfk_sets < 16) {
                snprintf(zfk_set_key[zfk_sets], sizeof(zfk_set_key[0]), "%s", argv[4]);
                snprintf(zfk_set_val[zfk_sets], sizeof(zfk_set_val[0]), "%s", argv[5]);
            }
            zfk_sets++;
            return fk_ret(result, 0);
        }
        if (argv[4]) { /* ordinary forward set */
            zfk_forward_sets++;
            return fk_ret(result, 0);
        }
        zfk_fallback_reads++; /* per-key read: snapshot must never fall back */
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

    /* The snapshot came from exact direct/include -z listings, not per-key reads. */
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
    CHECK(zfk_was_unset("user.name"));

    /* Exact rollback force-clears every key before ordered re-adds. It cannot
     * trust the forward-path scalar cache after a partial restore attempt. */
    CHECK(zfk_was_unset("user.signingkey"));
    CHECK(zfk_was_unset("commit.gpgsign"));
    CHECK(zfk_was_unset("gpg.program"));
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
    static const char forward_listing[] =
        "user.name\nAlpha\nBeta"          "\0"
        "user.email\nreal@x.com"          "\0"
        "user.signingkey\nAAAA1111BBBB2222" "\0"
        "core.sshcommand\nssh -i /k -o IdentitiesOnly=yes" "\0";
    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    /* Forward switch writes a key the listing showed absent... */
    CHECK_EQ_INT(git_set_config_value("user.signingkey", "AAAA1111BBBB2222",
                                      GIT_SCOPE_GLOBAL), 0);
    zfk_listing_override = forward_listing;
    zfk_listing_override_len = sizeof(forward_listing) - 1U;
    /* ...so the rollback's unset of it is real and must exec. */
    CHECK_EQ_INT(git_config_restore(), 0);

    run_set_runner(prev);
    zfk_listing_override = NULL;
    CHECK(zfk_was_unset("user.signingkey"));
}

static void *fail_snapshot_value_malloc(size_t size) {
    (void)size;
    return NULL;
}

/* A managed write must not reach Git until its intended post-image is fully
 * representable in memory. Otherwise the command can succeed while the
 * transaction still expects the old vector, and rollback mistakes its own
 * mutation for an external conflict. The failed attempt must also leave no
 * CFG_WRITTEN cache entry that could suppress a later retry. */
TEST(postimage_value_allocation_failure_precedes_managed_write) {
    git_snapshot_value_malloc_fn previous_malloc;

    git_ops_test_reset_caches();
    zfk_sets = zfk_unsets = zfk_fallback_reads = 0;
    zfk_forward_sets = 0;
    command_runner_fn prev = run_set_runner(zfk_runner);

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    previous_malloc = git_ops_test_set_snapshot_value_malloc_fn(
        fail_snapshot_value_malloc);
    clear_error();

    CHECK_EQ_INT(git_set_config_value("user.name", "Replacement Name",
                                      GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_MEMORY_ALLOCATION);
    CHECK_EQ_INT(zfk_forward_sets, 0);

    git_ops_test_set_snapshot_value_malloc_fn(previous_malloc);
    zfk_forward_sets = 0;
    CHECK_EQ_INT(git_set_config_value("user.name", "Replacement Name",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(zfk_forward_sets, 1);

    git_ops_test_reset_caches();
    run_set_runner(prev);
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
    zfk_listing_override = "";
    zfk_listing_override_len = 0;
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

TEST(oversize_foreign_sshcommand_restores_exactly) {
    /* Longer than ANY value gitswitch writes (past MAX_PATH_LEN plus the ssh
     * option overhead): the dynamic snapshot still captures and restores it
     * exactly rather than degrading the rollback to an unknown value. */
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

    zfk_listing_override = "";
    zfk_listing_override_len = 0;
    CHECK_EQ_INT(git_config_restore(), 0);
    int is = zfk_find_set("core.sshcommand");
    CHECK(is >= 0);
    if (is >= 0) CHECK_STR_EQ(zfk_set_val[is], val);
    /* Clear plus rollback's checked unset-all. */
    CHECK_EQ_INT(zfk_count_unsets("core.sshcommand"), 2);
    /* Keys that DID fit still round-trip normally. */
    int in = zfk_find_set("user.name");
    int ie = zfk_find_set("user.email");
    CHECK(in >= 0 && ie >= 0);
    if (in >= 0) CHECK_STR_EQ(zfk_set_val[in], "Real Name");
    if (ie >= 0) CHECK_STR_EQ(zfk_set_val[ie], "real@x.com");

    run_set_runner(prev);
    zfk_listing_override = NULL;
}

/* ---- M22: public validation never trusts a process-lifetime read -------- */

TEST(git_test_config_rechecks_external_identity) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);
    account_t acct;

    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "Test User", sizeof(acct.name));
    safe_strncpy(acct.email, "test@example.com", sizeof(acct.email));

    /* Full switch write verifies both the selected scope and one fresh merged
     * effective listing. */
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(fk_identity_reads, 2);
    CHECK_EQ_INT(fk_effective_reads, 1);

    /* Model another process changing Git after the forward read-back. The
     * next public validation must execute and reject the new value; the old
     * process-global positive cache incorrectly returned success here. */
    int in = fk_find("--global", "user.name");
    int ie = fk_find("--global", "user.email");
    CHECK(in >= 0 && ie >= 0);
    if (in >= 0) {
        snprintf(fk_store[in].value, sizeof(fk_store[in].value), "%s",
                 "External User");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);
    CHECK_EQ_INT(fk_identity_reads, 2);
    CHECK_EQ_INT(fk_effective_reads, 2);
    if (in >= 0) CHECK_STR_EQ(fk_store[in].value, "External User");
    if (ie >= 0) CHECK_STR_EQ(fk_store[ie].value, "test@example.com");

    run_set_runner(prev);
}

/* ---- L13: public Git validation enforces the selected signing model ----- */

TEST(git_test_config_rejects_wrong_effective_signing_state) {
    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);
    account_t acct;
    int signing_key;
    int signing_enabled;

    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "GPG User", sizeof(acct.name));
    safe_strncpy(acct.email, "gpg@example.com", sizeof(acct.email));
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    safe_strncpy(acct.gpg_key_id, "BEEFCAFE01234567",
                 sizeof(acct.gpg_key_id));

    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    gpg_manager_note_key_available(acct.gpg_key_id);
    signing_key = fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY);
    signing_enabled = fk_find("--global", GIT_CONFIG_COMMIT_GPGSIGN);
    CHECK(signing_key >= 0 && signing_enabled >= 0);

    /* A nonempty key is not sufficient: it must be the selected key. */
    if (signing_key >= 0) {
        snprintf(fk_store[signing_key].value,
                 sizeof(fk_store[signing_key].value), "%s",
                 "AAAAAAAAAAAAAAAA");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);

    /* Signing enabled/disabled is selected account state, not a warning. */
    if (signing_key >= 0) {
        snprintf(fk_store[signing_key].value,
                 sizeof(fk_store[signing_key].value), "%s",
                 acct.gpg_key_id);
    }
    if (signing_enabled >= 0) {
        snprintf(fk_store[signing_enabled].value,
                 sizeof(fk_store[signing_enabled].value), "%s", "false");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);

    acct.gpg_signing_enabled = false;
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    signing_enabled = fk_find("--global", GIT_CONFIG_COMMIT_GPGSIGN);
    CHECK(signing_enabled >= 0);
    if (signing_enabled >= 0) {
        snprintf(fk_store[signing_enabled].value,
                 sizeof(fk_store[signing_enabled].value), "%s", "true");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);

    /* A non-signing account must reject stale signing state as well. */
    acct.gpg_enabled = false;
    acct.gpg_signing_enabled = false;
    acct.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    signing_key = fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY);
    signing_enabled = fk_find("--global", GIT_CONFIG_COMMIT_GPGSIGN);
    CHECK(signing_key < 0 && signing_enabled >= 0);
    if (signing_enabled >= 0) {
        snprintf(fk_store[signing_enabled].value,
                 sizeof(fk_store[signing_enabled].value), "%s", "true");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL), -1);

    run_set_runner(prev);
}

TEST(v5_fingerprint_survives_git_current_config_snapshot) {
    static const char v5_fingerprint[] =
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF";
    git_current_config_t current;

    git_ops_test_reset_caches();
    fk_reset();
    command_runner_fn prev = run_set_runner(fake_git_runner);

    CHECK_EQ_INT((int)strlen(v5_fingerprint), 64);
    CHECK_EQ_INT(git_set_config_value("user.name", "V5 User",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value("user.email", "v5@example.test",
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value("user.signingkey", v5_fingerprint,
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value("commit.gpgsign", "true",
                                      GIT_SCOPE_GLOBAL), 0);
    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(git_get_current_config(&current), 0);
    CHECK(current.valid);
    CHECK_STR_EQ(current.signing_key, v5_fingerprint);
    CHECK_EQ_INT((int)strlen(current.signing_key), 64);

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

/* ---- AR-06 F58: snapshot preserves surrounding whitespace ---------------- */
static char f58_set_key[16][64], f58_set_val[16][1024];
static int f58_sets;

static int f58_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    if (result) { memset(result, 0, sizeof(*result)); result->spawned = true; }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (strcmp(argv[0], "git") != 0 || !argv[1]) return fk_ret(result, 1);
    if (strcmp(argv[1], "rev-parse") == 0) return fk_ret(result, 1); /* not a repo */
    if (strcmp(argv[1], "config") == 0 && argv[2] && argv[3]) {
        if (strcmp(argv[3], "--list") == 0 && argv[4] &&
            strcmp(argv[4], "-z") == 0) {
            static const char listing[] =
                "user.name\n  spaced  name  \0"
                "user.email\ne@x.com\0";
            size_t n = sizeof(listing) - 1U;
            if (!opts || !opts->out || opts->out_size <= n)
                return fk_ret(result, 1);
            memcpy(opts->out, listing, n);
            opts->out[n] = '\0';
            if (result) result->out_len = n;
            return fk_ret(result, 0);
        }
        if ((strcmp(argv[3], "--unset-all") == 0 || strcmp(argv[3], "--unset") == 0) && argv[4])
            return fk_ret(result, 0);
        if (strcmp(argv[3], "--add") == 0 && argv[4] && argv[5]) {
            if (f58_sets < 16) {
                snprintf(f58_set_key[f58_sets], sizeof(f58_set_key[0]), "%s", argv[4]);
                snprintf(f58_set_val[f58_sets], sizeof(f58_set_val[0]), "%s", argv[5]);
            }
            f58_sets++;
            return fk_ret(result, 0);
        }
        return fk_ret(result, 1);
    }
    return fk_ret(result, 1);
}

static int f58_find_set(const char *key) {
    for (int i = 0; i < f58_sets && i < 16; i++)
        if (strcmp(f58_set_key[i], key) == 0) return i;
    return -1;
}

TEST(snapshot_preserves_surrounding_whitespace) {
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

/* ---- AR-10 M1: durable-identity retirement on remove/reset -------------- */

#define RETIRE_FPR "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define RETIRE_FOREIGN_FPR "9999888877776666555544443333222211110000"

static void retire_fill_account(account_t *acct, const char *ssh_key_path) {
    memset(acct, 0, sizeof(*acct));
    acct->id = 1;
    safe_strncpy(acct->name, "retired", sizeof(acct->name));
    safe_strncpy(acct->email, "retired@example.com", sizeof(acct->email));
    acct->gpg_enabled = true;
    acct->gpg_signing_enabled = true;
    /* The saved selector is the short suffix form; the switch published the
     * canonical fingerprint — the retire comparison must bridge the two. */
    safe_strncpy(acct->gpg_key_id, RETIRE_FPR + 24, sizeof(acct->gpg_key_id));
    if (ssh_key_path) {
        acct->ssh_enabled = true;
        safe_strncpy(acct->ssh_key_path, ssh_key_path,
                     sizeof(acct->ssh_key_path));
    }
}

static void fk_seed(const char *scope, const char *key, const char *value) {
    int i;
    for (i = 0; i < FK_MAX && fk_store[i].used; i++) {}
    if (i == FK_MAX) return;
    snprintf(fk_store[i].scope, sizeof(fk_store[i].scope), "%s", scope);
    snprintf(fk_store[i].key, sizeof(fk_store[i].key), "%s", key);
    snprintf(fk_store[i].value, sizeof(fk_store[i].value), "%s", value);
    fk_store[i].used = true;
}

TEST(retire_clears_signing_legs_that_select_the_account) {
    account_t acct;
    size_t cleared = 0;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    fk_seed("--global", "user.name", "Retired User");
    fk_seed("--global", "user.email", "retired@example.com");
    fk_seed("--global", "user.signingkey", RETIRE_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", "gpg.format", "openpgp");
    /* A foreign SSH command must survive: the account is not SSH-enabled, so
     * nothing attributes it. */
    fk_seed("--global", "core.sshcommand", "ssh -i /someone/elses/key");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 3);
    CHECK(fk_find("--global", "user.signingkey") < 0);
    CHECK(fk_find("--global", "commit.gpgsign") < 0);
    CHECK(fk_find("--global", "gpg.format") < 0);
    /* Plain identity and unattributed credentials are left untouched. */
    CHECK(fk_find("--global", "user.name") >= 0);
    CHECK(fk_find("--global", "user.email") >= 0);
    CHECK(fk_find("--global", "core.sshcommand") >= 0);
}

TEST(retire_leaves_foreign_signing_key_in_place) {
    account_t acct;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    fk_seed("--global", "user.signingkey", RETIRE_FOREIGN_FPR);
    fk_seed("--global", "commit.gpgsign", "true");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", "user.signingkey") >= 0);
    CHECK(fk_find("--global", "commit.gpgsign") >= 0);
}

TEST(retire_clears_exactly_matching_ssh_command) {
    char dir[64];
    char key_path[512];
    char expected[GIT_CONFIG_VALUE_MAX];
    account_t acct;
    size_t cleared = 0;

    snprintf(dir, sizeof(dir), "/tmp/gsw_retire_XXXXXX");
    CHECK(ts_mkdtemp(dir) != NULL);
    snprintf(key_path, sizeof(key_path), "%s/id_ed25519", dir);
    CHECK(fk_touch(key_path));

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, key_path);
    acct.gpg_enabled = false;
    acct.gpg_key_id[0] = '\0';

    if (git_expected_ssh_command(&acct, expected, sizeof(expected)) != 0) {
        TS_SKIP("openssh", "no trusted ssh executable on this host");
    }
    fk_seed("--global", "core.sshcommand", expected);
    fk_seed("--global", "user.name", "Retired User");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 1);
    CHECK(fk_find("--global", "core.sshcommand") < 0);
    CHECK(fk_find("--global", "user.name") >= 0);
}

TEST(retire_leaves_foreign_ssh_command_in_place) {
    char dir[64];
    char key_path[512];
    account_t acct;
    size_t cleared = 99;

    snprintf(dir, sizeof(dir), "/tmp/gsw_retire_XXXXXX");
    CHECK(ts_mkdtemp(dir) != NULL);
    snprintf(key_path, sizeof(key_path), "%s/id_ed25519", dir);
    CHECK(fk_touch(key_path));

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, key_path);
    acct.gpg_enabled = false;
    acct.gpg_key_id[0] = '\0';
    fk_seed("--global", "core.sshcommand", "ssh -i /someone/elses/key");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", "core.sshcommand") >= 0);
}

TEST(signing_key_selector_rules_are_strict) {
    account_t acct;

    retire_fill_account(&acct, NULL);
    /* Canonical fingerprint whose suffix is the saved selector: selected. */
    CHECK(git_signing_key_selects_account(&acct, RETIRE_FPR));
    /* 0x prefix on the saved selector is stripped. */
    safe_strncpy(acct.gpg_key_id, "0x22223333", sizeof(acct.gpg_key_id));
    CHECK(git_signing_key_selects_account(&acct, RETIRE_FPR));
    /* Suffix mismatch, noncanonical length, and non-hex are all rejected. */
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FOREIGN_FPR));
    CHECK(!git_signing_key_selects_account(&acct, "22223333"));
    CHECK(!git_signing_key_selects_account(
        &acct, "ZZZZBBBBCCCCDDDDEEEEFFFF0000111122223333"));
    /* An account with no selector attributes nothing. */
    acct.gpg_enabled = false;
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FPR));
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(snapshot_preserves_surrounding_whitespace);
    RUN_TEST(git_configure_ssh_rejects_single_quote_in_keypath);
    RUN_TEST(git_ops_init_spawns_no_subprocess);
    RUN_TEST(git_is_repository_caches_result);
    RUN_TEST(git_get_repo_root_requires_complete_exact_output);
    RUN_TEST(effective_config_capture_enforces_maximum);
    RUN_TEST(git_set_config_value_skips_duplicate_managed_write);
    RUN_TEST(rollback_z_parser_survives_embedded_newline);
    RUN_TEST(snapshot_seeds_cache_and_clear_elides_proven_absent);
    RUN_TEST(restore_unsets_keys_written_after_snapshot);
    RUN_TEST(postimage_value_allocation_failure_precedes_managed_write);
    RUN_TEST(overlong_sshcommand_snapshots_present_and_restores_verbatim);
    RUN_TEST(oversize_foreign_sshcommand_restores_exactly);
    RUN_TEST(git_test_config_rechecks_external_identity);
    RUN_TEST(git_test_config_rejects_wrong_effective_signing_state);
    RUN_TEST(v5_fingerprint_survives_git_current_config_snapshot);
    RUN_TEST(git_test_config_skips_gpg_probe_when_key_seen);
    RUN_TEST(retire_clears_signing_legs_that_select_the_account);
    RUN_TEST(retire_leaves_foreign_signing_key_in_place);
    RUN_TEST(retire_clears_exactly_matching_ssh_command);
    RUN_TEST(retire_leaves_foreign_ssh_command_in_place);
    RUN_TEST(signing_key_selector_rules_are_strict);
TEST_MAIN_END()
