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
static int fk_non_git_execs;
static char fk_last_non_git_program[MAX_PATH_LEN];
static const char *fk_allowed_gpg_program;
static bool fk_is_repo;        /* what `git rev-parse --git-dir` reports */
static const char *fk_repo_root_output;
static int fk_repo_root_exit;
static unsigned int fk_write_attempts;
static unsigned int fk_fail_write_ordinal;
/* Exact-file retirement deliberately ignores the caller's current Git
 * environment. Tests that seed the simple global in-memory store bind its
 * persisted publication path here so the fake can model `git config --file`
 * without weakening the argv assertion. */
static char fk_exact_global_path[MAX_PATH_LEN];

static void fk_reset(void) {
    memset(fk_store, 0, sizeof(fk_store));
    fk_execs = 0;
    fk_identity_reads = 0;
    fk_effective_reads = 0;
    fk_non_git_execs = 0;
    fk_last_non_git_program[0] = '\0';
    fk_allowed_gpg_program = NULL;
    fk_is_repo = false;
    fk_repo_root_output = NULL;
    fk_repo_root_exit = 1;
    fk_write_attempts = 0U;
    fk_fail_write_ordinal = 0U;
    fk_exact_global_path[0] = '\0';
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

static bool fk_unset_all(const char *scope, const char *key) {
    bool found = false;

    for (int i = 0; i < FK_MAX; i++) {
        if (fk_store[i].used && strcmp(fk_store[i].scope, scope) == 0 &&
            strcmp(fk_store[i].key, key) == 0) {
            fk_store[i].used = false;
            found = true;
        }
    }
    return found;
}

static bool fk_unset_exact(const char *scope, const char *key,
                           const char *value) {
    bool found = false;

    for (int i = 0; i < FK_MAX; i++) {
        if (fk_store[i].used && strcmp(fk_store[i].scope, scope) == 0 &&
            strcmp(fk_store[i].key, key) == 0 &&
            strcmp(fk_store[i].value, value) == 0) {
            fk_store[i].used = false;
            found = true;
        }
    }
    return found;
}

static bool fk_is_exact_global_or_stage_path(const char *path) {
    static const char stage_prefix[] = "/.gitswitch-config-";
    const char *slash;
    size_t parent_length;

    if (!path || fk_exact_global_path[0] == '\0') return false;
    if (strcmp(path, fk_exact_global_path) == 0) return true;
    slash = strrchr(fk_exact_global_path, '/');
    if (!slash) return false;
    parent_length = (size_t)(slash - fk_exact_global_path);
    return strncmp(path, fk_exact_global_path, parent_length) == 0 &&
           strncmp(path + parent_length, stage_prefix,
                   sizeof(stage_prefix) - 1U) == 0;
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

static int fk_emit_scope_listing(const char *scope, const run_opts_t *opts,
                                 run_result_t *result) {
    size_t used = 0;

    if (!scope || !opts || !opts->out || opts->out_size == 0) {
        return fk_ret(result, 1);
    }
    for (int i = 0; i < FK_MAX; i++) {
        size_t key_len;
        size_t value_len;

        if (!fk_store[i].used || strcmp(fk_store[i].scope, scope) != 0) {
            continue;
        }
        key_len = strlen(fk_store[i].key);
        value_len = strlen(fk_store[i].value);
        if (used + key_len + 1U + value_len + 1U > opts->out_size) {
            if (result) {
                result->out_len = opts->out_size - 1U;
                result->out_truncated = true;
            }
            return fk_ret(result, 0);
        }
        memcpy(opts->out + used, fk_store[i].key, key_len);
        used += key_len;
        opts->out[used++] = '\n';
        memcpy(opts->out + used, fk_store[i].value, value_len);
        used += value_len;
        opts->out[used++] = '\0';
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

    if (strcmp(argv[0], "git") != 0) {
        fk_non_git_execs++;
        (void)safe_strncpy(fk_last_non_git_program, argv[0],
                           sizeof(fk_last_non_git_program));
        if (fk_allowed_gpg_program &&
            strcmp(argv[0], fk_allowed_gpg_program) == 0 && argv[1] &&
            strcmp(argv[1], "--list-secret-keys") == 0) {
            return fk_ret(result, 0);
        }
        return fk_ret(result, 1);
    }
    if (!argv[1]) {
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
        if (strcmp(argv[2], "--file") == 0 && argv[4] && argv[5] &&
            argv[6] && fk_is_exact_global_or_stage_path(argv[3]) &&
            strcmp(argv[4], "--list") == 0 &&
            strcmp(argv[5], "-z") == 0 &&
            strcmp(argv[6], "--no-includes") == 0) {
            /* Retirement preflights the complete exact file once. Reuse the
             * ordered store emitter so repeated modeled values remain
             * distinct NUL records just as they are in real Git output. */
            return fk_emit_scope_listing("--global", opts, result);
        }
        if (strcmp(argv[2], "--file") == 0 && argv[4] && argv[5] &&
            fk_is_exact_global_or_stage_path(argv[3]) &&
            strcmp(argv[4], "--no-includes") == 0) {
            const char *scope = "--global";

            if (strcmp(argv[5], "--get-all") == 0 && argv[6] &&
                !argv[7]) {
                int i = fk_find(scope, argv[6]);
                if (i < 0) return fk_ret(result, 1);
                if (opts && opts->out && opts->out_size > 0) {
                    (void)snprintf(opts->out, opts->out_size, "%s\n",
                                   fk_store[i].value);
                    if (result) result->out_len = strlen(opts->out);
                }
                return fk_ret(result, 0);
            }
            if (strcmp(argv[5], "--fixed-value") == 0 && argv[6] &&
                strcmp(argv[6], "--unset-all") == 0 && argv[7] &&
                argv[8] && !argv[9]) {
                return fk_ret(result,
                              fk_unset_exact(scope, argv[7], argv[8])
                                  ? 0
                                  : 5);
            }
            return fk_ret(result, 1);
        }
        if (strcmp(argv[2], "--show-origin") == 0) {
            fk_effective_reads++;
            return fk_emit_effective_listing(opts, result);
        }
        const char *scope = argv[2];

        if (strcmp(argv[3], "--list") == 0 && argv[4] &&
            strcmp(argv[4], "-z") == 0) {
            return fk_emit_scope_listing(scope, opts, result);
        }

        /* Production emits --unset-all (AR-06 F03); accept the legacy spelling
         * too so the fake stays robust. Removes ALL values of a (possibly
         * multi-valued) key; exit 5 when the key does not exist. */
        if ((strcmp(argv[3], "--unset-all") == 0 || strcmp(argv[3], "--unset") == 0) && argv[4]) {
            return fk_ret(result,
                          fk_unset_all(scope, argv[4])
                              ? 0
                              : 5); /* git: option does not exist */
        }

        if (argv[4]) { /* set */
            fk_write_attempts++;
            if (fk_fail_write_ordinal != 0U &&
                fk_write_attempts == fk_fail_write_ordinal) {
                return fk_ret(result, 1);
            }
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

/* ---- AR-11 M8: publication completeness is current, never sticky ------- */

static account_t fk_publication_account(void) {
    account_t account;

    memset(&account, 0, sizeof(account));
    account.id = 17U;
    account.incarnation_persisted = true;
    safe_strncpy(account.incarnation,
                 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                 sizeof(account.incarnation));
    safe_strncpy(account.name, "Publication Owner", sizeof(account.name));
    safe_strncpy(account.email, "publication@example.test",
                 sizeof(account.email));
    account.preferred_scope = GIT_SCOPE_GLOBAL;
    return account;
}

TEST(partial_account_writer_failure_invalidates_prior_complete_publication) {
    account_t account;
    command_runner_fn previous;

    git_ops_test_reset_caches();
    fk_reset();
    previous = run_set_runner(fake_git_runner);
    account = fk_publication_account();

    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);

    /* A same-incarnation partial writer changes signingKey, then fails on the
     * following gpgsign write. The historical full-write success must not let
     * this chimera seal as a complete account image. */
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    safe_strncpy(account.gpg_key_id,
                 "0123456789ABCDEF0123456789ABCDEF01234567",
                 sizeof(account.gpg_key_id));
    fk_write_attempts = 0U;
    fk_fail_write_ordinal = 2U;
    CHECK_EQ_INT(git_configure_gpg(&account, GIT_SCOPE_GLOBAL), -1);
    fk_fail_write_ordinal = 0U;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "no complete account post-image") !=
          NULL);
    git_config_commit();

    git_ops_test_reset_caches();
    fk_reset();
    account = fk_publication_account();
    account.incarnation[0] = '\0';
    account.incarnation_persisted = false;
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);

    /* A backward-compatible legacy full write has no immutable owner. Adding
     * a canonical token only at the partial publication follow-up must not
     * relabel that historical image as belonging to the new incarnation. */
    account.incarnation_persisted = true;
    safe_strncpy(account.incarnation,
                 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                 sizeof(account.incarnation));
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    safe_strncpy(account.gpg_key_id,
                 "0123456789ABCDEF0123456789ABCDEF01234567",
                 sizeof(account.gpg_key_id));
    CHECK_EQ_INT(git_configure_openpgp_publication(
                     &account, "/trusted/ar11/gpg", GIT_SCOPE_GLOBAL),
                 0);
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "no complete account post-image") !=
          NULL);
    git_config_commit();

    git_ops_test_reset_caches();
    fk_reset();
    account = fk_publication_account();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);

    /* The canonical completion wrapper may restore completeness only after
     * every credential/program write succeeds. Its first changed key cannot
     * inherit the complete bit when the next managed write fails. */
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    safe_strncpy(account.gpg_key_id,
                 "0123456789ABCDEF0123456789ABCDEF01234567",
                 sizeof(account.gpg_key_id));
    fk_write_attempts = 0U;
    fk_fail_write_ordinal = 2U;
    CHECK_EQ_INT(git_configure_openpgp_publication(
                     &account, "/trusted/ar11/gpg", GIT_SCOPE_GLOBAL),
                 -1);
    fk_fail_write_ordinal = 0U;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "no complete account post-image") !=
          NULL);
    git_config_commit();

    git_ops_test_reset_caches();
    fk_reset();
    account = fk_publication_account();
    CHECK_EQ_INT(git_config_snapshot(GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), 0);

    /* The same rule applies to a repeated full writer: one successful key
     * from the new image followed by a failure cannot inherit the old bit. */
    safe_strncpy(account.name, "Changed Publication Owner",
                 sizeof(account.name));
    safe_strncpy(account.email, "changed-publication@example.test",
                 sizeof(account.email));
    fk_write_attempts = 0U;
    fk_fail_write_ordinal = 2U;
    CHECK_EQ_INT(git_set_config(&account, GIT_SCOPE_GLOBAL), -1);
    fk_fail_write_ordinal = 0U;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(git_config_seal(), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK(strstr(get_last_error()->message, "no complete account post-image") !=
          NULL);
    git_config_commit();

    run_set_runner(previous);
    git_ops_test_reset_caches();
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
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL, NULL), -1);
    CHECK_EQ_INT(fk_identity_reads, 2);
    CHECK_EQ_INT(fk_effective_reads, 2);
    if (in >= 0) CHECK_STR_EQ(fk_store[in].value, "External User");
    if (ie >= 0) CHECK_STR_EQ(fk_store[ie].value, "test@example.com");

    run_set_runner(prev);
}

/* ---- L13: public Git validation enforces the selected signing model ----- */

TEST(git_test_config_rejects_wrong_effective_signing_state) {
    static const char expected_program[] = "/trusted/ar11/gpg";
    static const char wrong_program[] = "/wrong/ar11/gpg";
    static const char *const other_foreign_programs[] = {
        GIT_CONFIG_GPG_X509_PROGRAM,
        GIT_CONFIG_GPG_SSH_PROGRAM
    };
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
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);
    gpg_manager_note_key_available(acct.gpg_key_id);
    signing_key = fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY);
    signing_enabled = fk_find("--global", GIT_CONFIG_COMMIT_GPGSIGN);
    CHECK(signing_key >= 0 && signing_enabled >= 0);

    /* Only the exact OpenPGP selector is the selected program model. Missing
     * or wrong values fail, and the same path under legacy gpg.program is a
     * foreign selector rather than an equivalent spelling. */
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), 0);
    CHECK_EQ_INT(git_unset_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                        GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      wrong_program,
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);
    CHECK_EQ_INT(git_unset_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                        GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);
    CHECK_EQ_INT(git_unset_config_value(GIT_CONFIG_GPG_PROGRAM,
                                        GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), 0);
    for (size_t i = 0;
         i < sizeof(other_foreign_programs) /
                 sizeof(other_foreign_programs[0]);
         i++) {
        CHECK_EQ_INT(git_set_config_value(other_foreign_programs[i],
                                          expected_program,
                                          GIT_SCOPE_GLOBAL), 0);
        CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                     expected_program), -1);
        CHECK_EQ_INT(git_unset_config_value(other_foreign_programs[i],
                                            GIT_SCOPE_GLOBAL), 0);
        CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                     expected_program), 0);
    }

    /* A nonempty key is not sufficient: it must be the selected key. */
    if (signing_key >= 0) {
        snprintf(fk_store[signing_key].value,
                 sizeof(fk_store[signing_key].value), "%s",
                 "AAAAAAAAAAAAAAAA");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);

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
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);

    acct.gpg_signing_enabled = false;
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);
    signing_enabled = fk_find("--global", GIT_CONFIG_COMMIT_GPGSIGN);
    CHECK(signing_enabled >= 0);
    if (signing_enabled >= 0) {
        snprintf(fk_store[signing_enabled].value,
                 sizeof(fk_store[signing_enabled].value), "%s", "true");
    }
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);

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
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL, NULL), -1);

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
    static const char expected_program[] = "/trusted/ar11/cached-gpg";
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
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);

    /* Key not yet proven by any gpg spawn: the probe runs, the fake runner
     * refuses it, the check fails — proving the probe is still reachable
     * when nothing vouches for the key. */
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), -1);

    /* Once proven (as every real switch does before its read-back validation),
     * the probe is skipped and the identical call succeeds with no gpg exec. */
    gpg_manager_note_key_available(acct.gpg_key_id);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), 0);

    run_set_runner(prev);
}

TEST(git_test_config_probes_with_exact_absolute_program) {
    static const char expected_program[] = "/trusted/ar11/exact-gpg";
    account_t acct;
    command_runner_fn prev;

    git_ops_test_reset_caches();
    fk_reset();
    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "AR11 Probe User", sizeof(acct.name));
    safe_strncpy(acct.email, "ar11-probe@example.test", sizeof(acct.email));
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    safe_strncpy(acct.gpg_key_id, "A11000000000BEEF",
                 sizeof(acct.gpg_key_id));

    prev = run_set_runner(fake_git_runner);
    CHECK_EQ_INT(git_set_config(&acct, GIT_SCOPE_GLOBAL), 0);
    CHECK_EQ_INT(git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                                      expected_program,
                                      GIT_SCOPE_GLOBAL), 0);
    fk_allowed_gpg_program = expected_program;
    fk_non_git_execs = 0;
    fk_last_non_git_program[0] = '\0';

    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 expected_program), 0);
    CHECK_EQ_INT(fk_non_git_execs, 1);
    CHECK_STR_EQ(fk_last_non_git_program, expected_program);

    run_set_runner(prev);
}

TEST(git_test_config_rejects_invalid_program_contract_before_exec) {
    account_t acct;
    command_runner_fn prev;

    git_ops_test_reset_caches();
    fk_reset();
    memset(&acct, 0, sizeof(acct));
    safe_strncpy(acct.name, "AR11 Contract User", sizeof(acct.name));
    safe_strncpy(acct.email, "ar11-contract@example.test",
                 sizeof(acct.email));
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    safe_strncpy(acct.gpg_key_id, "A11000000000CAFE",
                 sizeof(acct.gpg_key_id));

    prev = run_set_runner(fake_git_runner);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL, NULL), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL, "gpg"), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);

    acct.gpg_enabled = false;
    acct.gpg_signing_enabled = false;
    acct.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(git_test_config(&acct, GIT_SCOPE_GLOBAL,
                                 "/trusted/ar11/gpg"), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK_EQ_INT(fk_execs, 0);
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
#define RETIRE_SHARED_SUFFIX_FPR \
    "9999888877776666555544440000111122223333"
#define RETIRE_INCARNATION \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

static void retire_fill_account(account_t *acct, const char *ssh_key_path) {
    memset(acct, 0, sizeof(*acct));
    acct->id = 1;
    safe_strncpy(acct->incarnation, RETIRE_INCARNATION,
                 sizeof(acct->incarnation));
    acct->incarnation_persisted = true;
    safe_strncpy(acct->name, "retired", sizeof(acct->name));
    safe_strncpy(acct->email, "retired@example.com", sizeof(acct->email));
    acct->gpg_enabled = true;
    acct->gpg_signing_enabled = true;
    /* Retirement receives only durable canonical ownership evidence. Selector
     * resolution belongs to activation and is never reconstructed here. */
    safe_strncpy(acct->gpg_key_id, RETIRE_FPR, sizeof(acct->gpg_key_id));
    if (ssh_key_path) {
        acct->ssh_enabled = true;
        safe_strncpy(acct->ssh_key_path, ssh_key_path,
                     sizeof(acct->ssh_key_path));
    }
}

static char retire_global_root[MAX_PATH_LEN] =
    "/tmp/gsw-retire-global-XXXXXX";
static char retire_global_config[MAX_PATH_LEN];
static bool retire_global_destination_ready;

static void retire_fill_publication(publication_record_t *publication,
                                    const account_t *acct) {
    struct stat st;
    FILE *file;
    int write_result;
    int close_result;

    publication_record_init(publication);
    if (!retire_global_destination_ready) {
        if (!ts_mkdtemp(retire_global_root) ||
            ts_canonicalize_dir_path(retire_global_root,
                                     sizeof(retire_global_root)) != 0 ||
            (size_t)snprintf(retire_global_config,
                             sizeof(retire_global_config), "%s/config-a",
                             retire_global_root) >=
                sizeof(retire_global_config) ||
            !(file = fopen(retire_global_config, "w"))) {
            CHECK(false);
            return;
        }
        write_result = fputs("[fixture]\n", file);
        close_result = fclose(file);
        if (write_result < 0 || close_result != 0 ||
            chmod(retire_global_config, 0600) != 0) {
            CHECK(false);
            return;
        }
        retire_global_destination_ready = true;
    }
    if (setenv("GIT_CONFIG_GLOBAL", retire_global_config, 1) != 0 ||
        !realpath(retire_global_config, publication->config_path) ||
        stat(retire_global_root, &st) != 0) {
        CHECK(false);
        return;
    }
    CHECK_EQ_INT(safe_strncpy(fk_exact_global_path,
                              publication->config_path,
                              sizeof(fk_exact_global_path)), 0);
    publication->account_id = acct->id;
    safe_strncpy(publication->account_incarnation, acct->incarnation,
                 sizeof(publication->account_incarnation));
    publication->scope = PUBLICATION_SCOPE_GLOBAL;
    publication_identity_from_stat(&publication->config_parent, &st);
    if (stat(publication->config_path, &st) != 0) {
        CHECK(false);
        return;
    }
    publication_identity_from_stat(&publication->post_config, &st);
    publication->capabilities = PUBLICATION_CAP_DESTINATION |
                                PUBLICATION_CAP_POST_GENERATION |
                                PUBLICATION_CAP_GPG_FINGERPRINT |
                                PUBLICATION_CAP_GPG_PROGRAM |
                                PUBLICATION_CAP_GPG_SELECTOR |
                                PUBLICATION_CAP_GPG_SIGNING_STATE;
    publication->gpg_signing_enabled = true;
    safe_strncpy(publication->gpg_fingerprint, RETIRE_FPR,
                 sizeof(publication->gpg_fingerprint));
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     acct->gpg_key_id, publication->gpg_selector), 0);
    safe_strncpy(publication->gpg_program, "/trusted/ar11/gpg",
                 sizeof(publication->gpg_program));
    publication_identity_from_stat(&publication->gpg_program_identity, &st);
    publication->state = PUBLICATION_STATE_PUBLISHED;
}

static void retire_fill_ssh_publication(
    publication_record_t *publication, const account_t *acct,
    const char *ssh_command, const char *ssh_program) {
    struct stat st;

    retire_fill_publication(publication, acct);
    publication->capabilities = PUBLICATION_CAP_DESTINATION |
                                PUBLICATION_CAP_POST_GENERATION |
                                PUBLICATION_CAP_SSH_COMMAND |
                                PUBLICATION_CAP_SSH_PROGRAM;
    publication->gpg_fingerprint[0] = '\0';
    publication->gpg_selector[0] = '\0';
    publication->gpg_program[0] = '\0';
    publication->gpg_signing_enabled = false;
    memset(&publication->gpg_program_identity, 0,
           sizeof(publication->gpg_program_identity));
    CHECK_EQ_INT(safe_strncpy(publication->ssh_command, ssh_command,
                              sizeof(publication->ssh_command)), 0);
    CHECK_EQ_INT(safe_strncpy(publication->ssh_program, ssh_program,
                              sizeof(publication->ssh_program)), 0);
    CHECK_EQ_INT(stat(ssh_program, &st), 0);
    publication_identity_from_stat(&publication->ssh_program_identity, &st);
    CHECK_EQ_INT(publication_record_validate(publication), 0);
}

#define RETIRE_DESTINATION_REPOSITORIES 2
#define RETIRE_DESTINATION_KEYS 4

static char retire_destination_repositories[RETIRE_DESTINATION_REPOSITORIES]
                                           [MAX_PATH_LEN];
static bool retire_destination_values[RETIRE_DESTINATION_REPOSITORIES]
                                     [RETIRE_DESTINATION_KEYS];
static const char *const retire_destination_keys[RETIRE_DESTINATION_KEYS] = {
    GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM
};
static const char *const retire_destination_expected[RETIRE_DESTINATION_KEYS] = {
    RETIRE_FPR, "true", "openpgp", "/trusted/ar11/gpg"
};

static int retire_destination_current_repository(void) {
    char cwd[MAX_PATH_LEN];

    if (!getcwd(cwd, sizeof(cwd))) return -1;
    for (int i = 0; i < RETIRE_DESTINATION_REPOSITORIES; i++) {
        if (strcmp(cwd, retire_destination_repositories[i]) == 0) return i;
    }
    return -1;
}

static int retire_destination_key_index(const char *key) {
    if (!key) return -1;
    for (int i = 0; i < RETIRE_DESTINATION_KEYS; i++) {
        if (strcmp(key, retire_destination_keys[i]) == 0) return i;
    }
    return -1;
}

static int retire_destination_emit(const run_opts_t *opts,
                                   run_result_t *result,
                                   const char *value) {
    size_t length;

    if (!opts || !opts->out || opts->out_size == 0 || !value) {
        return fk_ret(result, 1);
    }
    length = strlen(value);
    if (length + 2U > opts->out_size) {
        if (result) result->out_truncated = true;
        return fk_ret(result, 1);
    }
    memcpy(opts->out, value, length);
    opts->out[length++] = '\n';
    opts->out[length] = '\0';
    if (result) result->out_len = length;
    return fk_ret(result, 0);
}

static int retire_destination_emit_listing(int repository,
                                           const run_opts_t *opts,
                                           run_result_t *result) {
    size_t used = 0U;

    if (repository < 0 || repository >= RETIRE_DESTINATION_REPOSITORIES ||
        !opts || !opts->out || opts->out_size == 0U) {
        return fk_ret(result, 1);
    }
    for (int key = 0; key < RETIRE_DESTINATION_KEYS; key++) {
        size_t key_length;
        size_t value_length;

        if (!retire_destination_values[repository][key]) continue;
        key_length = strlen(retire_destination_keys[key]);
        value_length = strlen(retire_destination_expected[key]);
        if (used + key_length + 1U + value_length + 1U >
            opts->out_size) {
            if (result) {
                result->out_len = opts->out_size - 1U;
                result->out_truncated = true;
            }
            return fk_ret(result, 0);
        }
        memcpy(opts->out + used, retire_destination_keys[key], key_length);
        used += key_length;
        opts->out[used++] = '\n';
        memcpy(opts->out + used, retire_destination_expected[key],
               value_length);
        used += value_length;
        opts->out[used++] = '\0';
    }
    if (result) result->out_len = used;
    return fk_ret(result, 0);
}

/* Model both ordinary cwd-sensitive --local reads used by assertions and the
 * exact-file retirement grammar. Exact retirement must derive its destination
 * only from argv[3], never from cwd or repository discovery. */
static int retire_destination_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    char path[MAX_PATH_LEN];
    int repository;
    int key;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (!argv || !argv[0] || strcmp(argv[0], "git") != 0 || !argv[1]) {
        return fk_ret(result, 1);
    }
    if (strcmp(argv[1], "rev-parse") == 0) {
        return fk_ret(result, 1);
    }
    if (strcmp(argv[1], "config") != 0 || !argv[2] || !argv[3]) {
        return fk_ret(result, 1);
    }
    if (strcmp(argv[2], "--file") == 0 && argv[4] && argv[5] && argv[6]) {
        repository = -1;
        for (int i = 0; i < RETIRE_DESTINATION_REPOSITORIES; i++) {
            if ((size_t)snprintf(path, sizeof(path), "%s/.git/config",
                                 retire_destination_repositories[i]) >=
                sizeof(path)) {
                return fk_ret(result, 1);
            }
            if (strcmp(argv[3], path) == 0) {
                repository = i;
                break;
            }
        }
        if (repository < 0) return fk_ret(result, 1);
        if (strcmp(argv[4], "--list") == 0 &&
            strcmp(argv[5], "-z") == 0 &&
            strcmp(argv[6], "--no-includes") == 0) {
            return retire_destination_emit_listing(repository, opts, result);
        }
        if (strcmp(argv[4], "--no-includes") != 0) {
            return fk_ret(result, 1);
        }
        if (strcmp(argv[5], "--fixed-value") == 0 && argv[6] &&
            strcmp(argv[6], "--unset-all") == 0 && argv[7] && argv[8] &&
            !argv[9]) {
            key = retire_destination_key_index(argv[7]);
            if (key < 0 ||
                strcmp(argv[8], retire_destination_expected[key]) != 0) {
                return fk_ret(result, 1);
            }
            if (!retire_destination_values[repository][key]) {
                return fk_ret(result, 5);
            }
            retire_destination_values[repository][key] = false;
            return fk_ret(result, 0);
        }
        key = retire_destination_key_index(argv[6]);
        if (key < 0) return fk_ret(result, 1);
        if (strcmp(argv[5], "--get-all") != 0 ||
            !retire_destination_values[repository][key]) {
            return fk_ret(result, 1);
        }
        return retire_destination_emit(opts, result,
                                       retire_destination_expected[key]);
    }

    repository = retire_destination_current_repository();
    if (repository < 0 || strcmp(argv[2], "--local") != 0) {
        return fk_ret(result, 1);
    }
    if (strcmp(argv[3], "--unset-all") == 0 && argv[4]) {
        key = retire_destination_key_index(argv[4]);
        if (key < 0 || !retire_destination_values[repository][key]) {
            return fk_ret(result, 5);
        }
        retire_destination_values[repository][key] = false;
        return fk_ret(result, 0);
    }
    key = retire_destination_key_index(argv[3]);
    if (key < 0 || !retire_destination_values[repository][key]) {
        return fk_ret(result, 1);
    }
    return retire_destination_emit(opts, result,
                                   retire_destination_expected[key]);
}

static bool retire_local_signing_leg_equals(const char *fingerprint) {
    char value[GIT_CONFIG_VALUE_MAX];

    return git_get_config_value(GIT_CONFIG_USER_SIGNINGKEY, value,
                                sizeof(value), GIT_SCOPE_LOCAL) == 0 &&
           strcmp(value, fingerprint) == 0 &&
           git_get_config_value(GIT_CONFIG_COMMIT_GPGSIGN, value,
                                sizeof(value), GIT_SCOPE_LOCAL) == 0 &&
           strcmp(value, "true") == 0 &&
           git_get_config_value(GIT_CONFIG_GPG_FORMAT, value,
                                sizeof(value), GIT_SCOPE_LOCAL) == 0 &&
           strcmp(value, "openpgp") == 0 &&
           git_get_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM, value,
                                sizeof(value), GIT_SCOPE_LOCAL) == 0 &&
           strcmp(value, "/trusted/ar11/gpg") == 0;
}

/* M10: a local publication for repository A remains exactly addressable from
 * B. B's identical-looking credential is not owned by A's provenance and
 * survives; no cwd-sensitive --local operation is allowed to substitute B. */
TEST(retire_local_publication_targets_recorded_repository_from_other_repository) {
    char base[128] = "/tmp/gsw-retire-destination-XXXXXX";
    char config_a[MAX_PATH_LEN] = "";
    char config_parent[MAX_PATH_LEN] = "";
    char saved_cwd[MAX_PATH_LEN] = "";
    FILE *config_file = NULL;
    struct stat st;
    account_t acct;
    publication_record_t publication;
    command_runner_fn previous_runner = NULL;
    size_t cleared = 99;
    bool cwd_saved = false;
    int rc;

    if (!getcwd(saved_cwd, sizeof(saved_cwd))) {
        CHECK(false);
        return;
    }
    cwd_saved = true;
    if (!ts_mkdtemp(base) ||
        ts_canonicalize_dir_path(base, sizeof(base)) != 0 ||
        (size_t)snprintf(retire_destination_repositories[0],
                         sizeof(retire_destination_repositories[0]),
                         "%s/repo-a", base) >=
            sizeof(retire_destination_repositories[0]) ||
        (size_t)snprintf(retire_destination_repositories[1],
                         sizeof(retire_destination_repositories[1]),
                         "%s/repo-b", base) >=
            sizeof(retire_destination_repositories[1])) {
        CHECK(false);
        goto cleanup;
    }
    for (int i = 0; i < RETIRE_DESTINATION_REPOSITORIES; i++) {
        char git_dir[MAX_PATH_LEN];
        char git_config[MAX_PATH_LEN];

        int write_result;
        int close_result;

        if (mkdir(retire_destination_repositories[i], 0700) != 0 ||
            (size_t)snprintf(git_dir, sizeof(git_dir), "%s/.git",
                             retire_destination_repositories[i]) >=
                sizeof(git_dir) ||
            mkdir(git_dir, 0700) != 0 ||
            (size_t)snprintf(git_config, sizeof(git_config), "%s/config",
                             git_dir) >= sizeof(git_config) ||
            !(config_file = fopen(git_config, "w"))) {
            CHECK(false);
            goto cleanup;
        }
        write_result = fputs("[fixture]\n", config_file);
        close_result = fclose(config_file);
        config_file = NULL;
        if (write_result < 0 || close_result != 0) {
            CHECK(false);
            goto cleanup;
        }
        for (int k = 0; k < RETIRE_DESTINATION_KEYS; k++) {
            retire_destination_values[i][k] = true;
        }
    }
    previous_runner = run_set_runner(retire_destination_runner);
    git_ops_test_reset_caches();

    retire_fill_account(&acct, NULL);
    if (chdir(retire_destination_repositories[0]) != 0) {
        CHECK(false);
        goto cleanup;
    }

    publication_record_init(&publication);
    publication.account_id = acct.id;
    safe_strncpy(publication.account_incarnation, acct.incarnation,
                 sizeof(publication.account_incarnation));
    publication.scope = PUBLICATION_SCOPE_LOCAL;
    if ((size_t)snprintf(config_a, sizeof(config_a), "%s/.git/config",
                         retire_destination_repositories[0]) >=
            sizeof(config_a) ||
        !realpath(config_a, publication.config_path) ||
        (size_t)snprintf(config_parent, sizeof(config_parent), "%s/.git",
                         retire_destination_repositories[0]) >=
            sizeof(config_parent) ||
        stat(config_parent, &st) != 0) {
        CHECK(false);
        goto cleanup;
    }
    publication_identity_from_stat(&publication.config_parent, &st);
    if (!realpath(retire_destination_repositories[0],
                  publication.repository_path) ||
        stat(publication.repository_path, &st) != 0) {
        CHECK(false);
        goto cleanup;
    }
    publication_identity_from_stat(&publication.repository, &st);
    if (stat(publication.config_path, &st) != 0) {
        CHECK(false);
        goto cleanup;
    }
    publication_identity_from_stat(&publication.post_config, &st);
    publication.capabilities = PUBLICATION_CAP_DESTINATION |
                               PUBLICATION_CAP_POST_GENERATION |
                               PUBLICATION_CAP_GPG_FINGERPRINT |
                               PUBLICATION_CAP_GPG_PROGRAM |
                               PUBLICATION_CAP_GPG_SELECTOR;
    safe_strncpy(publication.gpg_fingerprint, RETIRE_FPR,
                 sizeof(publication.gpg_fingerprint));
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     acct.gpg_key_id, publication.gpg_selector), 0);
    safe_strncpy(publication.gpg_program, "/trusted/ar11/gpg",
                 sizeof(publication.gpg_program));
    publication_identity_from_stat(&publication.gpg_program_identity, &st);
    publication.state = PUBLICATION_STATE_PUBLISHED;
    CHECK_EQ_INT(publication_record_validate(&publication), 0);

    if (chdir(retire_destination_repositories[1]) != 0) {
        CHECK(false);
        goto cleanup;
    }
    git_ops_test_reset_caches();
    clear_error();
    rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 4);
    CHECK(retire_local_signing_leg_equals(RETIRE_FPR));

    /* Repeating from A is idempotent and proves the first call already
     * consumed A rather than accidentally operating on caller repository B. */
    CHECK_EQ_INT(chdir(retire_destination_repositories[0]), 0);
    git_ops_test_reset_caches();
    cleared = 0;
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), 0);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(git_get_config_value(GIT_CONFIG_USER_SIGNINGKEY, config_a,
                               sizeof(config_a), GIT_SCOPE_LOCAL) != 0);

cleanup:
    if (config_file) (void)fclose(config_file);
    git_ops_test_reset_caches();
    if (cwd_saved) CHECK_EQ_INT(chdir(saved_cwd), 0);
    if (previous_runner) run_set_runner(previous_runner);
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

TEST(retire_global_publication_ignores_environment_but_checks_generation) {
    char config_b[MAX_PATH_LEN] = "";
    char config_link[MAX_PATH_LEN] = "";
    FILE *file = NULL;
    account_t acct;
    publication_record_t publication;
    command_runner_fn previous_runner = NULL;
    size_t cleared = 99;
    bool link_created = false;
    int write_result;
    int close_result;
    int rc;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    retire_fill_publication(&publication, &acct);
    if ((size_t)snprintf(config_b, sizeof(config_b), "%s/config-b",
                         retire_global_root) >= sizeof(config_b) ||
        !(file = fopen(config_b, "w"))) {
        CHECK(false);
        goto cleanup;
    }
    write_result = fputs("[fixture]\n", file);
    close_result = fclose(file);
    file = NULL;
    if (write_result < 0 || close_result != 0 || chmod(config_b, 0600) != 0) {
        CHECK(false);
        goto cleanup;
    }
    fk_seed("--global", GIT_CONFIG_USER_SIGNINGKEY, RETIRE_FPR);
    fk_seed("--global", GIT_CONFIG_COMMIT_GPGSIGN, "true");
    fk_seed("--global", GIT_CONFIG_GPG_FORMAT, "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");
    previous_runner = run_set_runner(fake_git_runner);

    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", config_b, 1), 0);
    git_ops_test_reset_caches();
    clear_error();
    rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 4);
    CHECK(fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY) < 0);

    /* Restore the modeled record-owned values before exercising an actual
     * generation change at the persisted path. */
    fk_seed("--global", GIT_CONFIG_USER_SIGNINGKEY, RETIRE_FPR);
    fk_seed("--global", GIT_CONFIG_COMMIT_GPGSIGN, "true");
    fk_seed("--global", GIT_CONFIG_GPG_FORMAT, "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");

    /* Exact path and inode are still insufficient: changing the sealed file's
     * hard-link count keeps its inode, size, and mtime but invalidates the
     * full post-generation witness. This must also fail before an unset. */
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", retire_global_config, 1), 0);
    if ((size_t)snprintf(config_link, sizeof(config_link), "%s/config-link",
                         retire_global_root) >= sizeof(config_link) ||
        link(retire_global_config, config_link) != 0) {
        CHECK(false);
        goto cleanup;
    }
    link_created = true;
    git_ops_test_reset_caches();
    cleared = 99;
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), -1);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY) >= 0);
    CHECK_EQ_INT(unlink(config_link), 0);
    link_created = false;

    /* Refreshing from the now-current exact path/generation authorizes the
     * same in-memory Git state and proves the rejections were destination-
     * causal, not a blanket refusal of global retirement. */
    retire_fill_publication(&publication, &acct);
    git_ops_test_reset_caches();
    cleared = 0;
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), 0);
    CHECK_EQ_INT((int)cleared, 4);
    CHECK(fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY) < 0);

cleanup:
    if (link_created) (void)unlink(config_link);
    if (file) (void)fclose(file);
    (void)setenv("GIT_CONFIG_GLOBAL", retire_global_config, 1);
    git_ops_test_reset_caches();
    if (previous_runner) run_set_runner(previous_runner);
}

TEST(retire_without_publication_record_preserves_signing_leg) {
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
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");
    fk_seed("--global", GIT_CONFIG_GPG_PROGRAM, "/foreign/legacy-gpg");
    fk_seed("--global", GIT_CONFIG_GPG_X509_PROGRAM, "/foreign/x509-gpg");
    fk_seed("--global", GIT_CONFIG_GPG_SSH_PROGRAM, "/foreign/ssh-gpg");
    /* A foreign SSH command must survive: the account is not SSH-enabled, so
     * nothing attributes it. */
    fk_seed("--global", "core.sshcommand", "ssh -i /someone/elses/key");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    errno = 0;
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK_EQ_INT(fk_execs, 0);
    /* Even a full account selector is not durable proof that this process
     * published the signing leg. The compatibility API has no publication
     * record, so every signing key and companion remains untouched. */
    CHECK(fk_find("--global", "user.signingkey") >= 0);
    CHECK(fk_find("--global", "commit.gpgsign") >= 0);
    CHECK(fk_find("--global", "gpg.format") >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM) >= 0);
    /* Plain identity and unattributed credentials are likewise untouched. */
    CHECK(fk_find("--global", "user.name") >= 0);
    CHECK(fk_find("--global", "user.email") >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_PROGRAM) >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_X509_PROGRAM) >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_SSH_PROGRAM) >= 0);
    CHECK(fk_find("--global", "core.sshcommand") >= 0);
}

TEST(retire_exact_published_fingerprint_clears_signing_leg) {
    account_t acct;
    publication_record_t publication;
    size_t cleared = 0;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    retire_fill_publication(&publication, &acct);
    fk_seed("--global", "user.signingkey", RETIRE_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", "gpg.format", "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 4);
    CHECK(fk_find("--global", "user.signingkey") < 0);
    CHECK(fk_find("--global", "commit.gpgsign") < 0);
    CHECK(fk_find("--global", "gpg.format") < 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM) < 0);
}

TEST(retire_legacy_publication_without_selector_uses_exact_fingerprint) {
    account_t acct;
    publication_record_t publication;
    size_t cleared = 0;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    retire_fill_publication(&publication, &acct);
    publication.capabilities &= ~PUBLICATION_CAP_GPG_SELECTOR;
    publication.gpg_selector[0] = '\0';
    CHECK_EQ_INT(publication_record_validate(&publication), 0);
    fk_seed("--global", "user.signingkey", RETIRE_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", "gpg.format", "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");

    command_runner_fn previous = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    run_set_runner(previous);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT((int)cleared, 4);
    CHECK(fk_find("--global", GIT_CONFIG_USER_SIGNINGKEY) < 0);
}

TEST(retire_refuses_foreign_anchor_with_owned_companions) {
    account_t acct;
    publication_record_t publication;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    retire_fill_publication(&publication, &acct);
    fk_seed("--global", "user.signingkey", RETIRE_FOREIGN_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", "user.signingkey") >= 0);
    CHECK(fk_find("--global", "commit.gpgsign") >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM) >= 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
}

TEST(retire_preserves_legacy_selector_without_canonical_record) {
    account_t acct;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    safe_strncpy(acct.gpg_key_id, &RETIRE_FPR[24],
                 sizeof(acct.gpg_key_id));
    fk_seed("--global", "user.signingkey", RETIRE_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", "gpg.format", "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/trusted/ar11/gpg");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    errno = 0;
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK_EQ_INT(fk_execs, 0);
    CHECK(fk_find("--global", "user.signingkey") >= 0);
    CHECK(fk_find("--global", "commit.gpgsign") >= 0);
    CHECK(fk_find("--global", "gpg.format") >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM) >= 0);
}

TEST(retire_refuses_shared_suffix_foreign_anchor_with_owned_companions) {
    account_t acct;
    publication_record_t publication;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, NULL);
    retire_fill_publication(&publication, &acct);
    fk_seed("--global", "user.signingkey", RETIRE_SHARED_SUFFIX_FPR);
    fk_seed("--global", "commit.gpgsign", "true");
    fk_seed("--global", "gpg.format", "openpgp");
    fk_seed("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM,
            "/foreign/shared-suffix/gpg");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    int rc = git_retire_account_identity_published(
        &acct, &publication, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", "user.signingkey") >= 0);
    CHECK(fk_find("--global", "commit.gpgsign") >= 0);
    CHECK(fk_find("--global", "gpg.format") >= 0);
    CHECK(fk_find("--global", GIT_CONFIG_GPG_OPENPGP_PROGRAM) >= 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
}

TEST(retire_without_publication_refuses_matching_ssh_command) {
    static const char historical_command[] =
        "'/historical/bin/ssh' -i '/historical/key' -F '/dev/null'";
    account_t acct;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, "/current/account/key");
    acct.gpg_enabled = false;
    acct.gpg_key_id[0] = '\0';
    fk_seed("--global", "core.sshcommand", historical_command);
    fk_seed("--global", "user.name", "Retired User");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    errno = 0;
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK_EQ_INT(fk_execs, 0);
    CHECK(fk_find("--global", "core.sshcommand") >= 0);
    CHECK(fk_find("--global", "user.name") >= 0);
    CHECK(strstr(get_last_error()->message,
                 "Durable Git publication provenance is required") != NULL);
}

TEST(retire_leaves_foreign_ssh_command_in_place) {
    account_t acct;
    size_t cleared = 99;

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, "/current/account/key");
    acct.gpg_enabled = false;
    acct.gpg_key_id[0] = '\0';
    fk_seed("--global", "core.sshcommand", "ssh -i /someone/elses/key");

    command_runner_fn prev = run_set_runner(fake_git_runner);
    errno = 0;
    int rc = git_retire_account_identity(&acct, &cleared);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK_EQ_INT(fk_execs, 0);
    CHECK(fk_find("--global", "core.sshcommand") >= 0);
}

TEST(published_ssh_retirement_uses_saved_command_after_program_removal) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-retire-published-ssh-XXXXXX";
    char program[MAX_PATH_LEN];
    char command[GIT_CONFIG_VALUE_MAX];
    char *saved_path = NULL;
    const char *path_before = getenv("PATH");
    account_t acct;
    publication_record_t publication;
    command_runner_fn previous;
    size_t cleared = 99;

    if (path_before) {
        saved_path = strdup(path_before);
        CHECK(saved_path != NULL);
        if (!saved_path) return;
    }
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(safe_snprintf(program, sizeof(program), "%s/ssh", root), 0);
    CHECK(fk_touch(program));
    CHECK_EQ_INT(chmod(program, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(
                     command, sizeof(command),
                     "'%s' -i '/historical/key' -F '/dev/null' "
                     "-o IdentitiesOnly=yes",
                     program), 0);

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, "/edited/account/key");
    retire_fill_ssh_publication(&publication, &acct, command, program);
    acct.gpg_enabled = false;
    acct.gpg_signing_enabled = false;
    acct.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(unlink(program), 0);
    CHECK_EQ_INT(setenv("PATH", "/definitely/not/present", 1), 0);
    fk_seed("--global", GIT_CONFIG_CORE_SSHCOMMAND, command);

    previous = run_set_runner(fake_git_runner);
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((int)cleared, 1);
    CHECK_EQ_INT(fk_non_git_execs, 0);
    CHECK(fk_find("--global", GIT_CONFIG_CORE_SSHCOMMAND) < 0);

    /* A later foreign writer is not owned merely because the destination and
     * historical program identity still match the record. */
    fk_seed("--global", GIT_CONFIG_CORE_SSHCOMMAND,
            "'/foreign/ssh' -i '/foreign/key'");
    cleared = 99;
    previous = run_set_runner(fake_git_runner);
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((int)cleared, 0);
    CHECK(fk_find("--global", GIT_CONFIG_CORE_SSHCOMMAND) >= 0);

    if (saved_path) CHECK_EQ_INT(setenv("PATH", saved_path, 1), 0);
    else CHECK_EQ_INT(unsetenv("PATH"), 0);
    free(saved_path);
    ts_rm_rf(root);
}

TEST(published_ssh_retirement_ignores_current_global_override) {
    char program_root[MAX_PATH_LEN] = "/tmp/gsw-retire-ssh-program-XXXXXX";
    char program[MAX_PATH_LEN];
    char command[GIT_CONFIG_VALUE_MAX];
    char foreign_config[MAX_PATH_LEN];
    account_t acct;
    publication_record_t publication;
    command_runner_fn previous;
    size_t cleared = 99;
    int fd = -1;

    CHECK(ts_mkdtemp(program_root) != NULL);
    CHECK_EQ_INT(safe_snprintf(program, sizeof(program), "%s/ssh",
                               program_root), 0);
    CHECK(fk_touch(program));
    CHECK_EQ_INT(chmod(program, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(command, sizeof(command),
                               "'%s' -i '/historical/key'", program), 0);

    git_ops_test_reset_caches();
    fk_reset();
    retire_fill_account(&acct, "/current/key");
    retire_fill_ssh_publication(&publication, &acct, command, program);
    acct.gpg_enabled = false;
    acct.gpg_signing_enabled = false;
    acct.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(safe_snprintf(foreign_config, sizeof(foreign_config),
                               "%s/foreign-config-XXXXXX",
                               retire_global_root), 0);
    fd = mkstemp(foreign_config);
    CHECK(fd >= 0);
    if (fd < 0) goto cleanup;
    CHECK_EQ_INT(close(fd), 0);
    fd = -1;
    CHECK_EQ_INT(chmod(foreign_config, 0600), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", foreign_config, 1), 0);
    git_ops_test_reset_caches();
    fk_seed("--global", GIT_CONFIG_CORE_SSHCOMMAND, command);

    previous = run_set_runner(fake_git_runner);
    clear_error();
    CHECK_EQ_INT(git_retire_account_identity_published(
                     &acct, &publication, &cleared), 0);
    run_set_runner(previous);
    CHECK_EQ_INT((int)cleared, 1);
    /* One exact full-vector preflight plus the attributed unset. */
    CHECK_EQ_INT(fk_execs, 2);
    CHECK(fk_find("--global", GIT_CONFIG_CORE_SSHCOMMAND) < 0);

cleanup:
    if (fd >= 0) CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", retire_global_config, 1), 0);
    git_ops_test_reset_caches();
    ts_rm_rf(program_root);
}

TEST(signing_key_identity_requires_exact_canonical_fingerprint) {
    static const char same_suffix_fingerprint[] =
        "9999888877776666555544440000111122223333";
    static const char lowercase_fingerprint[] =
        "aaaabbbbccccddddeeeeffff0000111122223333";
    account_t acct;

    retire_fill_account(&acct, NULL);
    /* Durable attribution accepts only the account's complete canonical
     * fingerprint. Hexadecimal case is representation, not identity. */
    safe_strncpy(acct.gpg_key_id, RETIRE_FPR, sizeof(acct.gpg_key_id));
    CHECK(git_signing_key_selects_account(&acct, RETIRE_FPR));
    CHECK(git_signing_key_selects_account(&acct, lowercase_fingerprint));

    /* A short selector is not durable identity proof. It must match neither
     * the key that originally resolved it nor a foreign key sharing the same
     * suffix. A suffix-based implementation fails both assertions. */
    safe_strncpy(acct.gpg_key_id, "22223333", sizeof(acct.gpg_key_id));
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FPR));
    CHECK(!git_signing_key_selects_account(&acct, same_suffix_fingerprint));

    /* Canonical persisted fingerprints never carry GnuPG's optional selector
     * prefix; accepting it would silently reintroduce selector semantics. */
    safe_strncpy(acct.gpg_key_id, "0x22223333", sizeof(acct.gpg_key_id));
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FPR));

    /* Full mismatch, noncanonical configured length, and non-hex are rejected. */
    safe_strncpy(acct.gpg_key_id, RETIRE_FPR, sizeof(acct.gpg_key_id));
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FOREIGN_FPR));
    CHECK(!git_signing_key_selects_account(&acct, "22223333"));
    CHECK(!git_signing_key_selects_account(
        &acct, "ZZZZBBBBCCCCDDDDEEEEFFFF0000111122223333"));
    /* An account with no selector attributes nothing. */
    acct.gpg_enabled = false;
    CHECK(!git_signing_key_selects_account(&acct, RETIRE_FPR));
}

TEST(signing_status_requires_exact_published_destination_and_fingerprint) {
    account_t acct;
    publication_record_t publication;
    git_current_config_t current;

    retire_fill_account(&acct, NULL);
    /* Canonical account identity and the exact fingerprint sealed in the
     * publication must agree independently of the effective Git value. */
    retire_fill_publication(&publication, &acct);
    memset(&current, 0, sizeof(current));
    safe_strncpy(current.signing_key, RETIRE_FPR,
                 sizeof(current.signing_key));
    current.effective_signing_key_scope = GIT_CONFIG_ORIGIN_GLOBAL;
    CHECK_EQ_INT(safe_snprintf(current.effective_signing_key_origin,
                               sizeof(current.effective_signing_key_origin),
                               "file:%s", publication.config_path), 0);

    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MATCH);

    /* Malformed current selector input is ERROR once the complete publication
     * belongs to this account, even when another semantic field also differs.
     * The outcome must not depend on comparison order. */
    safe_strncpy(acct.gpg_key_id, "not-hex", sizeof(acct.gpg_key_id));
    safe_strncpy(current.signing_key, RETIRE_FOREIGN_FPR,
                 sizeof(current.signing_key));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_ERROR);
    safe_strncpy(current.signing_key, RETIRE_FPR,
                 sizeof(current.signing_key));
    safe_strncpy(current.effective_signing_key_origin,
                 "file:/tmp/ar11/foreign.gitconfig",
                 sizeof(current.effective_signing_key_origin));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_ERROR);
    safe_strncpy(acct.gpg_key_id, RETIRE_FPR, sizeof(acct.gpg_key_id));
    CHECK_EQ_INT(safe_snprintf(current.effective_signing_key_origin,
                               sizeof(current.effective_signing_key_origin),
                               "file:%s", publication.config_path), 0);

    /* Editing the same immutable account incarnation to another canonical
     * key invalidates attribution even while Git retains the old published
     * fingerprint and destination. */
    safe_strncpy(acct.gpg_key_id, RETIRE_FOREIGN_FPR,
                 sizeof(acct.gpg_key_id));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);
    safe_strncpy(acct.gpg_key_id, RETIRE_FPR, sizeof(acct.gpg_key_id));

    safe_strncpy(acct.gpg_key_id, RETIRE_SHARED_SUFFIX_FPR,
                 sizeof(acct.gpg_key_id));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);
    safe_strncpy(acct.gpg_key_id, RETIRE_FPR, sizeof(acct.gpg_key_id));

    /* A distinct key sharing the selector suffix is foreign, even when every
     * destination and account field still matches. */
    safe_strncpy(current.signing_key, RETIRE_SHARED_SUFFIX_FPR,
                 sizeof(current.signing_key));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);

    safe_strncpy(current.signing_key, RETIRE_FPR,
                 sizeof(current.signing_key));
    publication.capabilities &= ~PUBLICATION_CAP_GPG_FINGERPRINT;
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);
    publication.capabilities |= PUBLICATION_CAP_GPG_FINGERPRINT;

    safe_strncpy(current.effective_signing_key_origin,
                 "file:/tmp/ar11/foreign.gitconfig",
                 sizeof(current.effective_signing_key_origin));
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);

    CHECK_EQ_INT(safe_snprintf(current.effective_signing_key_origin,
                               sizeof(current.effective_signing_key_origin),
                               "file:%s", publication.config_path), 0);
    publication.state = PUBLICATION_STATE_RETIRING;
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);
}

TEST(signing_status_roots_relative_local_origin_at_repository) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-status-origin-XXXXXX";
    char git_dir[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char foreign_path[MAX_PATH_LEN];
    char subdirectory[MAX_PATH_LEN];
    char saved_cwd[MAX_PATH_LEN];
    account_t acct;
    publication_record_t publication;
    git_current_config_t current;
    struct stat st;

    if (!ts_mkdtemp(root) || !getcwd(saved_cwd, sizeof(saved_cwd)) ||
        safe_snprintf(git_dir, sizeof(git_dir), "%s/.git", root) != 0 ||
        safe_snprintf(config_path, sizeof(config_path), "%s/config",
                      git_dir) != 0 ||
        safe_snprintf(foreign_path, sizeof(foreign_path), "%s/foreign",
                      git_dir) != 0 ||
        safe_snprintf(subdirectory, sizeof(subdirectory), "%s/nested",
                      root) != 0 ||
        mkdir(git_dir, 0700) != 0 || mkdir(subdirectory, 0700) != 0 ||
        !fk_touch(config_path) || !fk_touch(foreign_path)) {
        CHECK(false);
        return;
    }

    retire_fill_account(&acct, NULL);
    publication_record_init(&publication);
    publication.account_id = acct.id;
    safe_strncpy(publication.account_incarnation, acct.incarnation,
                 sizeof(publication.account_incarnation));
    publication.scope = PUBLICATION_SCOPE_LOCAL;
    publication.capabilities = PUBLICATION_CAP_DESTINATION |
                               PUBLICATION_CAP_POST_GENERATION |
                               PUBLICATION_CAP_GPG_FINGERPRINT |
                               PUBLICATION_CAP_GPG_PROGRAM |
                               PUBLICATION_CAP_GPG_SELECTOR;
    CHECK(realpath(config_path, publication.config_path) != NULL);
    CHECK(realpath(root, publication.repository_path) != NULL);
    CHECK_EQ_INT(stat(git_dir, &st), 0);
    publication_identity_from_stat(&publication.config_parent, &st);
    CHECK_EQ_INT(stat(root, &st), 0);
    publication_identity_from_stat(&publication.repository, &st);
    CHECK_EQ_INT(stat(config_path, &st), 0);
    publication_identity_from_stat(&publication.post_config, &st);
    CHECK_EQ_INT(safe_strncpy(publication.gpg_fingerprint, RETIRE_FPR,
                              sizeof(publication.gpg_fingerprint)), 0);
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     acct.gpg_key_id, publication.gpg_selector), 0);
    CHECK_EQ_INT(safe_strncpy(publication.gpg_program,
                              "/trusted/ar11/gpg",
                              sizeof(publication.gpg_program)), 0);
    publication_identity_from_stat(&publication.gpg_program_identity, &st);

    memset(&current, 0, sizeof(current));
    CHECK_EQ_INT(safe_strncpy(current.signing_key, RETIRE_FPR,
                              sizeof(current.signing_key)), 0);
    current.effective_signing_key_scope = GIT_CONFIG_ORIGIN_LOCAL;
    CHECK_EQ_INT(safe_strncpy(current.effective_signing_key_origin,
                              "file:.git/config",
                              sizeof(current.effective_signing_key_origin)),
                 0);
    CHECK_EQ_INT(chdir(subdirectory), 0);

    /* Git reports this origin relative to the repository top-level. It must
     * not be interpreted relative to the caller's current subdirectory. */
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MATCH);

    CHECK_EQ_INT(safe_strncpy(current.effective_signing_key_origin,
                              "file:.git/foreign",
                              sizeof(current.effective_signing_key_origin)),
                 0);
    CHECK(git_signing_key_matches_publication(
              &acct, &publication, &current) ==
          GIT_SIGNING_PUBLICATION_MISMATCH);
    CHECK_EQ_INT(chdir(saved_cwd), 0);
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
    RUN_TEST(partial_account_writer_failure_invalidates_prior_complete_publication);
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
    RUN_TEST(git_test_config_probes_with_exact_absolute_program);
    RUN_TEST(git_test_config_rejects_invalid_program_contract_before_exec);
    RUN_TEST(retire_global_publication_ignores_environment_but_checks_generation);
    RUN_TEST(retire_without_publication_record_preserves_signing_leg);
    RUN_TEST(retire_local_publication_targets_recorded_repository_from_other_repository);
    RUN_TEST(retire_exact_published_fingerprint_clears_signing_leg);
    RUN_TEST(retire_legacy_publication_without_selector_uses_exact_fingerprint);
    RUN_TEST(retire_refuses_foreign_anchor_with_owned_companions);
    RUN_TEST(retire_preserves_legacy_selector_without_canonical_record);
    RUN_TEST(retire_refuses_shared_suffix_foreign_anchor_with_owned_companions);
    RUN_TEST(retire_without_publication_refuses_matching_ssh_command);
    RUN_TEST(retire_leaves_foreign_ssh_command_in_place);
    RUN_TEST(published_ssh_retirement_uses_saved_command_after_program_removal);
    RUN_TEST(published_ssh_retirement_ignores_current_global_override);
    RUN_TEST(signing_key_identity_requires_exact_canonical_fingerprint);
    RUN_TEST(signing_status_requires_exact_published_destination_and_fingerprint);
    RUN_TEST(signing_status_roots_relative_local_origin_at_repository);
TEST_MAIN_END()
