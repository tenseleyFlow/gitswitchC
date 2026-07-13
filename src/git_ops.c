/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "git_ops.h"
#include "gpg_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"

/* Internal helper functions */
static int git_run(char *output, size_t output_size, ...);
static int validate_git_installation(void);
static bool is_valid_git_config_value(const char *value);
static int git_set_config_value_impl(const char *key, const char *value,
                                     git_scope_t scope, bool skip_validation);
static int git_unset_config_value_impl(const char *key, git_scope_t scope,
                                       bool force);
static int git_get_config_value_ex(const char *key, char *value,
                                   size_t value_size, git_scope_t scope,
                                   bool *value_too_long);
static int git_detect_managed_worktree_scope(bool *present);
static int git_verify_merged_account(const account_t *account);

/* Snapshot/restore of gitswitch-managed git config keys, for switch rollback. */

/* Value capacity for the effective-status representation and exec cache
 * below. The transactional snapshot is dynamically allocated so it can retain
 * every value of every managed key without truncation. This covers the largest
 * value gitswitch itself writes: git_configure_ssh's core.sshCommand contains
 * a safely quoted canonical SSH executable plus a separately quoted key path.
 * The old 512-byte cap could not hold gitswitch's OWN value for a long key
 * path, and the drop was then recorded as "proven absent" — the AR-03 M1 bug. */
#define GIT_CFG_VALUE_MAX GIT_CONFIG_VALUE_MAX

/* Worktree scope is intentionally internal: accounts may choose local,
 * global, or system persistence, while a pre-existing --worktree value is an
 * override that those choices must snapshot, clear, restore, and attribute.
 * Keeping it out of git_scope_t avoids making "worktree" a writable account
 * preference without a separate product decision. */
#define GIT_SCOPE_WORKTREE_INTERNAL ((git_scope_t)3)

typedef struct {
    const char *key;
    char value[GIT_CFG_VALUE_MAX];
    bool present;
    bool implicit;
    bool value_unknown; /* present, but the value exceeded value[] (a foreign
                         * writer): restore must neither write back a
                         * truncated copy nor --unset the user's original. */
} git_kv_t;

#define GIT_MANAGED_KEY_COUNT 6
static const char *const g_managed_keys[GIT_MANAGED_KEY_COUNT] = {
    GIT_CONFIG_USER_NAME, GIT_CONFIG_USER_EMAIL, GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN, GIT_CONFIG_GPG_PROGRAM, GIT_CONFIG_CORE_SSHCOMMAND
};
static void git_init_kv(git_kv_t out[GIT_MANAGED_KEY_COUNT]);

typedef struct {
    char **values;
    size_t count;
    size_t capacity;
    bool restored;
} git_snapshot_key_t;

typedef struct {
    git_snapshot_key_t keys[GIT_MANAGED_KEY_COUNT];
} git_scope_snapshot_t;

typedef struct {
    git_scope_t scope;
    bool local_also;
    bool worktree_also;
    git_scope_snapshot_t primary;
    git_scope_snapshot_t local;
    git_scope_snapshot_t worktree;
    bool valid;
    bool restore_incomplete;
} git_config_snapshot_t;

static git_config_snapshot_t g_git_snapshot;
static void git_snapshot_clear(git_config_snapshot_t *snapshot);

/* ---- Process-scoped exec caches (perf-1..4) ------------------------------
 *
 * A single switch used to spawn the same git subprocesses several times over:
 * `git --version` on every init, `git rev-parse --git-dir` from every caller
 * that asked "am I in a repo?", the post-switch name/email read-back twice
 * (git_set_config's verify and then git_test_config), and the GPG keys
 * written twice (git_configure_gpg and gpg_manager's
 * gpg_configure_git_signing). On the interactive switch hot path each exec is
 * a fork+execvp round trip, so these are cached for the process lifetime.
 *
 * Invalidation assumptions (documented deliberately — the caches trade a
 * sliver of staleness for the exec reduction, and only where it cannot change
 * the outcome of a switch):
 *  - The CLI is short-lived and single-threaded; a concurrent external
 *    `git config` edit mid-switch was already a lost race before the caches.
 *  - Repo-ness is keyed by cwd (getcwd is one syscall, not a fork), so a
 *    future chdir cannot be served a stale answer; a .git appearing or
 *    vanishing under an unchanged cwd mid-process is not a supported flow.
 *  - Config entries are only trusted in two provable states: a value THIS
 *    process successfully wrote (safe to skip an identical re-write — the
 *    second exec could only repeat the first), and a value actually read back
 *    from git (safe to serve to a later read). A write never satisfies a
 *    read: git_set_config's read-back verification must observe git itself,
 *    not our own write buffer, or the verify would be a self-fulfilling no-op.
 */
typedef enum {
    CFG_UNKNOWN = 0,  /* nothing cacheable known; always exec */
    CFG_WRITTEN,      /* we set/unset this key ourselves (skip duplicate writes only) */
    CFG_READBACK      /* value observed in `git config` output (may serve reads) */
} cfg_state_t;

#define GIT_SCOPE_COUNT 4
static struct {
    cfg_state_t state;
    bool present;      /* false => key known absent (after our own --unset) */
    char value[GIT_CFG_VALUE_MAX];
} g_cfg_cache[GIT_SCOPE_COUNT][GIT_MANAGED_KEY_COUNT];

static bool g_git_validated;                 /* perf-1: git-available check ran */
static struct {                              /* perf-4: repo-ness of cwd */
    bool known;
    bool is_repo;
    char cwd[MAX_PATH_LEN];
} g_repo_cache;

/* Map to cache indices; -1 when the key/scope is not cacheable. */
static int cfg_scope_index(git_scope_t scope) {
    if (scope == GIT_SCOPE_WORKTREE_INTERNAL) return 3;
    switch (scope) {
        case GIT_SCOPE_LOCAL:  return 0;
        case GIT_SCOPE_GLOBAL: return 1;
        case GIT_SCOPE_SYSTEM: return 2;
        default: return -1;
    }
}

static int cfg_key_index(const char *key) {
    for (int i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        /* git config keys are case-insensitive; callers use lowercase
         * constants but don't rely on it. */
        if (strcasecmp(key, g_managed_keys[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/* Record a cache entry; a present value too long to cache degrades to
 * CFG_UNKNOWN with present kept TRUE. Never truncate — a truncated cached
 * value could satisfy or suppress the wrong operation later — and never
 * record the key absent: "proven absent" is exactly what lets
 * git_unset_config_value elide a --unset that is in fact real (AR-03 M1). */
static void cfg_cache_store(int s, int k, cfg_state_t state, bool present,
                            const char *value) {
    if (s < 0 || k < 0) {
        return;
    }
    if (present && strlen(value) >= sizeof(g_cfg_cache[s][k].value)) {
        g_cfg_cache[s][k].state = CFG_UNKNOWN;
        g_cfg_cache[s][k].present = true;
        g_cfg_cache[s][k].value[0] = '\0';
        return;
    }
    g_cfg_cache[s][k].state = state;
    g_cfg_cache[s][k].present = present;
    safe_strncpy(g_cfg_cache[s][k].value, present ? value : "",
                 sizeof(g_cfg_cache[s][k].value));
}

/* Test seam: unit tests exercise first-call behavior of the caches above, so
 * they need a reset between cases. Deliberately NOT in git_ops.h — the public
 * API surface is unchanged; tests declare this prototype locally. */
void git_ops_test_reset_caches(void);
void git_ops_test_reset_caches(void) {
    git_snapshot_clear(&g_git_snapshot);
    memset(g_cfg_cache, 0, sizeof(g_cfg_cache));
    memset(&g_repo_cache, 0, sizeof(g_repo_cache));
    g_git_validated = false;
}

typedef struct {
    git_kv_t keys[GIT_MANAGED_KEY_COUNT];
    char origins[GIT_MANAGED_KEY_COUNT][MAX_PATH_LEN];
    git_config_origin_scope_t scopes[GIT_MANAGED_KEY_COUNT];
} git_effective_listing_t;

/* Single-threaded CLI scratch. Keeping the large status representation in
 * .bss avoids adding it to the already substantial status stack frame. */
static git_effective_listing_t g_effective_listing;

static git_config_origin_scope_t parse_origin_scope(const char *scope,
                                                    size_t scope_len) {
    if (scope_len == 6 && memcmp(scope, "system", 6) == 0)
        return GIT_CONFIG_ORIGIN_SYSTEM;
    if (scope_len == 6 && memcmp(scope, "global", 6) == 0)
        return GIT_CONFIG_ORIGIN_GLOBAL;
    if (scope_len == 5 && memcmp(scope, "local", 5) == 0)
        return GIT_CONFIG_ORIGIN_LOCAL;
    if (scope_len == 8 && memcmp(scope, "worktree", 8) == 0)
        return GIT_CONFIG_ORIGIN_WORKTREE;
    if (scope_len == 7 && memcmp(scope, "command", 7) == 0)
        return GIT_CONFIG_ORIGIN_COMMAND;
    return GIT_CONFIG_ORIGIN_UNKNOWN;
}

const char *git_config_origin_scope_to_string(git_config_origin_scope_t scope) {
    switch (scope) {
        case GIT_CONFIG_ORIGIN_SYSTEM:   return "system";
        case GIT_CONFIG_ORIGIN_GLOBAL:   return "global";
        case GIT_CONFIG_ORIGIN_LOCAL:    return "local";
        case GIT_CONFIG_ORIGIN_WORKTREE: return "worktree";
        case GIT_CONFIG_ORIGIN_COMMAND:  return "command";
        case GIT_CONFIG_ORIGIN_UNKNOWN:
        default:                         return "unknown";
    }
}

/* Parse `git config --show-origin --show-scope -z --list`. Git emits three
 * NUL-terminated fields per record: scope, origin, then "key\nvalue". Last
 * match wins, preserving Git's effective precedence including includes and
 * worktree configuration. */
static int parse_effective_listing(const char *buf, size_t len,
                                   git_effective_listing_t *out) {
    size_t pos = 0;

    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    git_init_kv(out->keys);

    while (pos < len) {
        size_t scope_start = pos;
        while (pos < len && buf[pos] != '\0') pos++;
        if (pos >= len) return -1;
        size_t scope_len = pos - scope_start;
        pos++;

        size_t origin_start = pos;
        while (pos < len && buf[pos] != '\0') pos++;
        if (pos >= len) return -1;
        size_t origin_len = pos - origin_start;
        pos++;

        size_t record_start = pos;
        while (pos < len && buf[pos] != '\0') pos++;
        if (pos >= len) return -1;
        size_t record_len = pos - record_start;
        pos++;

        const char *record = buf + record_start;
        const char *newline = memchr(record, '\n', record_len);
        size_t key_len = newline ? (size_t)(newline - record) : record_len;
        int key_index = -1;
        for (int i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
            size_t managed_len = strlen(g_managed_keys[i]);
            if (key_len == managed_len &&
                strncasecmp(record, g_managed_keys[i], key_len) == 0) {
                key_index = i;
                break;
            }
        }
        if (key_index < 0) continue;

        git_kv_t *entry = &out->keys[key_index];
        entry->present = true;
        entry->implicit = false;
        entry->value_unknown = false;
        entry->value[0] = '\0';
        out->origins[key_index][0] = '\0';
        out->scopes[key_index] = parse_origin_scope(buf + scope_start,
                                                    scope_len);

        if (!newline) {
            /* `key` without `= value` is an implicit Boolean true. Keep that
             * semantic distinct from both an explicit empty value (false for
             * Git Booleans) and an oversized unknown value. */
            entry->implicit = true;
        } else {
            const char *value = newline + 1;
            size_t value_len = record_len - key_len - 1;
            if (value_len >= sizeof(entry->value)) {
                entry->value_unknown = true;
            } else {
                memcpy(entry->value, value, value_len);
                entry->value[value_len] = '\0';
            }
        }

        if (origin_len >= sizeof(out->origins[key_index])) return -1;
        memcpy(out->origins[key_index], buf + origin_start, origin_len);
        out->origins[key_index][origin_len] = '\0';
    }
    return 0;
}

/* Detect whether any managed value is contributed by the distinct worktree
 * scope. We intentionally inspect Git's effective scope attribution instead
 * of blindly issuing --worktree: when extensions.worktreeConfig is disabled,
 * Git aliases --worktree to --local, and treating those as two independent
 * stores would corrupt snapshot/restore semantics. */
static int git_detect_managed_worktree_scope(bool *present) {
    char list[16384];
    run_opts_t opts;
    run_result_t res;
    const char *argv[] = { "git", "config", "--show-scope", "-z", "--list", NULL };
    size_t pos = 0;

    if (!present) return -1;
    *present = false;
    if (!git_is_repository()) return 0;

    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = list;
    opts.out_size = sizeof(list);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &res) != 0 || res.out_truncated) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot inspect Git worktree configuration before switching");
        return -1;
    }

    while (pos < res.out_len) {
        size_t scope_start = pos;
        while (pos < res.out_len && list[pos] != '\0') pos++;
        if (pos >= res.out_len) goto malformed;
        size_t scope_len = pos - scope_start;
        pos++;

        size_t record_start = pos;
        while (pos < res.out_len && list[pos] != '\0') pos++;
        if (pos >= res.out_len) goto malformed;
        size_t record_len = pos - record_start;
        pos++;

        if (scope_len != 8 || memcmp(list + scope_start, "worktree", 8) != 0)
            continue;

        const char *record = list + record_start;
        const char *newline = memchr(record, '\n', record_len);
        size_t key_len = newline ? (size_t)(newline - record) : record_len;
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
            size_t managed_len = strlen(g_managed_keys[i]);
            if (key_len == managed_len &&
                strncasecmp(record, g_managed_keys[i], key_len) == 0) {
                *present = true;
                return 0;
            }
        }
    }
    return 0;

malformed:
    set_error(ERR_GIT_CONFIG_FAILED,
              "Malformed Git scope listing while checking worktree configuration");
    return -1;
}

static void git_init_kv(git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        out[i].key = g_managed_keys[i];
        out[i].present = false;
        out[i].value_unknown = false;
        out[i].value[0] = '\0';
    }
}

/* Transaction snapshots are exact ordered vectors, not last-value-wins
 * scalars. Git permits repeated values for every config key; collapsing those
 * values changes both meaning and rollback fidelity (AR-07 M25). */
#define GIT_SNAPSHOT_INITIAL_BYTES (16U * 1024U)
#define GIT_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)

static void git_scope_snapshot_clear(git_scope_snapshot_t *scope) {
    if (!scope) return;
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        for (size_t j = 0; j < scope->keys[i].count; j++) {
            free(scope->keys[i].values[j]);
        }
        free(scope->keys[i].values);
    }
    memset(scope, 0, sizeof(*scope));
}

static void git_snapshot_clear(git_config_snapshot_t *snapshot) {
    if (!snapshot) return;
    git_scope_snapshot_clear(&snapshot->primary);
    git_scope_snapshot_clear(&snapshot->local);
    git_scope_snapshot_clear(&snapshot->worktree);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int git_managed_key_index_n(const char *key, size_t key_len) {
    for (int i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        size_t managed_len = strlen(g_managed_keys[i]);
        if (key_len == managed_len &&
            strncasecmp(key, g_managed_keys[i], key_len) == 0) {
            return i;
        }
    }
    return -1;
}

static int git_snapshot_key_append(git_snapshot_key_t *key,
                                   const char *value, size_t value_len) {
    char **grown;
    char *copy;

    if (key->count == key->capacity) {
        size_t capacity = key->capacity ? key->capacity * 2U : 2U;
        grown = realloc(key->values, capacity * sizeof(*grown));
        if (!grown) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Out of memory capturing Git configuration snapshot");
            return -1;
        }
        key->values = grown;
        key->capacity = capacity;
    }
    copy = malloc(value_len + 1U);
    if (!copy) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory capturing Git configuration value");
        return -1;
    }
    memcpy(copy, value, value_len);
    copy[value_len] = '\0';
    key->values[key->count++] = copy;
    return 0;
}

/* Parse a complete `git config <scope> --list -z` result. A managed implicit
 * boolean has no key/value separator, so its file spelling cannot be recreated
 * through `git config --add`; refuse it before any mutation instead of
 * guessing. Every record, including the final one, must be NUL terminated. */
static int git_parse_snapshot_listing(const char *buf, size_t len,
                                      git_scope_snapshot_t *out) {
    size_t pos = 0;

    while (pos < len) {
        const char *record = buf + pos;
        const char *end = memchr(record, '\0', len - pos);
        const char *newline;
        size_t record_len;
        int key_index;

        if (!end) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Malformed or truncated Git configuration snapshot");
            return -1;
        }
        record_len = (size_t)(end - record);
        pos += record_len + 1U;
        newline = memchr(record, '\n', record_len);
        if (!newline) {
            key_index = git_managed_key_index_n(record, record_len);
            if (key_index >= 0) {
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Cannot exactly snapshot implicit Git value %s",
                          g_managed_keys[key_index]);
                return -1;
            }
            continue;
        }

        key_index = git_managed_key_index_n(
            record, (size_t)(newline - record));
        if (key_index >= 0 &&
            git_snapshot_key_append(&out->keys[key_index], newline + 1,
                                    record_len -
                                        (size_t)(newline - record) - 1U) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Grow until the complete binary listing fits. A hard cap bounds hostile or
 * corrupt config input; reaching it is a preflight failure, never a partial
 * snapshot followed by mutation (AR-07 M24). */
static int git_read_snapshot_listing(git_scope_t scope, bool includes,
                                     char **out, size_t *out_len) {
    const char *scope_flag = git_scope_to_flag(scope);
    size_t capacity = GIT_SNAPSHOT_INITIAL_BYTES;
    char *buf;

    if (!scope_flag || !out || !out_len) {
        set_error(ERR_INVALID_ARGS, "Invalid Git snapshot scope");
        return -1;
    }
    buf = malloc(capacity);
    if (!buf) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory allocating Git snapshot buffer");
        return -1;
    }

    for (;;) {
        const char *argv[] = {
            "git", "config", scope_flag, "--list", "-z",
            includes ? "--includes" : "--no-includes", NULL
        };
        const char *const diagnostic_env[] = {
            "LC_ALL=C", "LANG=C", NULL
        };
        run_opts_t opts;
        run_result_t res;

        memset(&opts, 0, sizeof(opts));
        memset(&res, 0, sizeof(res));
        opts.out = buf;
        opts.out_size = capacity;
        /* Git reports a genuinely absent explicitly selected scope file as
         * exit 128, not as an empty successful listing. Capture that canonical
         * diagnostic in a stable locale so ENOENT can be distinguished from
         * corruption, permissions, and every other read failure. Merging is
         * safe here: any stderr on a successful binary listing makes parsing
         * fail closed instead of being silently discarded. */
        opts.merge_stderr = true;
        opts.extra_env = diagnostic_env;
        if (run_argv(argv, &opts, &res) != 0) {
            static const char missing_prefix[] =
                "fatal: unable to read config file '";
            static const char missing_suffix[] =
                "': No such file or directory\n";
            size_t prefix_len = sizeof(missing_prefix) - 1U;
            size_t suffix_len = sizeof(missing_suffix) - 1U;
            bool clean_missing =
                res.spawned && res.term_signal == 0 && res.exit_code == 128 &&
                !res.out_truncated && res.out_len > prefix_len + suffix_len &&
                memchr(buf, '\0', res.out_len) == NULL &&
                memcmp(buf, missing_prefix, prefix_len) == 0 &&
                memcmp(buf + res.out_len - suffix_len, missing_suffix,
                       suffix_len) == 0;

            if (clean_missing) {
                /* Missing and empty have the same exact managed-value vector.
                 * Restore remains checked: it unsets any values introduced by
                 * the forward transaction. */
                buf[0] = '\0';
                *out = buf;
                *out_len = 0;
                return 0;
            }
            free(buf);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Failed to read %s Git configuration for rollback",
                      scope_flag);
            return -1;
        }
        if (!res.out_truncated) {
            if (res.out_len >= capacity) {
                free(buf);
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Invalid Git snapshot capture length");
                return -1;
            }
            *out = buf;
            *out_len = res.out_len;
            return 0;
        }
        if (capacity >= GIT_SNAPSHOT_MAX_BYTES) {
            free(buf);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git configuration snapshot exceeds %u bytes",
                      (unsigned)GIT_SNAPSHOT_MAX_BYTES);
            return -1;
        }
        {
            size_t grown_capacity = capacity * 2U;
            char *grown;
            if (grown_capacity > GIT_SNAPSHOT_MAX_BYTES) {
                grown_capacity = GIT_SNAPSHOT_MAX_BYTES;
            }
            grown = realloc(buf, grown_capacity);
            if (!grown) {
                free(buf);
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory growing Git snapshot buffer");
                return -1;
            }
            buf = grown;
            capacity = grown_capacity;
        }
    }
}

static bool git_scope_snapshot_equal(const git_scope_snapshot_t *a,
                                     const git_scope_snapshot_t *b) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (a->keys[i].count != b->keys[i].count) return false;
        for (size_t j = 0; j < a->keys[i].count; j++) {
            if (strcmp(a->keys[i].values[j], b->keys[i].values[j]) != 0)
                return false;
        }
    }
    return true;
}

/* Restore can only write the selected scope's own file. Compare an explicit
 * no-include capture with Git's include-expanded view and refuse before the
 * transaction if an include contributes/reorders any managed value. This is
 * the conservative exactness option permitted by AR-07 M25: never flatten an
 * included value into the including file or pretend its origin was restored. */
static int git_capture_scope_snapshot(git_scope_t scope,
                                      git_scope_snapshot_t *out) {
    char *direct_buf = NULL;
    char *expanded_buf = NULL;
    size_t direct_len = 0;
    size_t expanded_len = 0;
    git_scope_snapshot_t direct;
    git_scope_snapshot_t expanded;
    int rc = -1;

    memset(&direct, 0, sizeof(direct));
    memset(&expanded, 0, sizeof(expanded));
    if (git_read_snapshot_listing(scope, false, &direct_buf, &direct_len) != 0 ||
        git_parse_snapshot_listing(direct_buf, direct_len, &direct) != 0 ||
        git_read_snapshot_listing(scope, true, &expanded_buf,
                                  &expanded_len) != 0 ||
        git_parse_snapshot_listing(expanded_buf, expanded_len, &expanded) != 0) {
        goto done;
    }
    if (!git_scope_snapshot_equal(&direct, &expanded)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Managed Git values from include files cannot be exactly restored in %s scope",
                  git_scope_to_flag(scope));
        goto done;
    }

    *out = direct;
    memset(&direct, 0, sizeof(direct));
    rc = 0;

done:
    free(direct_buf);
    free(expanded_buf);
    git_scope_snapshot_clear(&direct);
    git_scope_snapshot_clear(&expanded);
    return rc;
}

static void git_seed_snapshot_cache(git_scope_t scope,
                                    const git_scope_snapshot_t *snapshot) {
    int s = cfg_scope_index(scope);
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        const git_snapshot_key_t *key = &snapshot->keys[i];
        if (key->count == 0) {
            cfg_cache_store(s, (int)i, CFG_READBACK, false, "");
        } else if (key->count == 1) {
            cfg_cache_store(s, (int)i, CFG_READBACK, true, key->values[0]);
        } else {
            /* A scalar cache cannot faithfully represent multiplicity. */
            cfg_cache_store(s, (int)i, CFG_UNKNOWN, true, "");
        }
    }
}

static int git_add_snapshot_value(git_scope_t scope, const char *key,
                                  const char *value) {
    char output[256] = "";
    const char *scope_flag = git_scope_to_flag(scope);
    const char *argv[] = {
        "git", "config", scope_flag, "--add", key, value, NULL
    };
    run_opts_t opts;
    run_result_t res;

    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    if (run_argv(argv, &opts, &res) != 0) {
        cfg_cache_store(cfg_scope_index(scope), cfg_key_index(key),
                        CFG_UNKNOWN, true, "");
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to restore Git config %s (%s): %s", key,
                  scope_flag, output[0] ? output : "unknown error");
        return -1;
    }
    return 0;
}

/* Each not-yet-complete key is rebuilt as checked unset-all plus ordered adds.
 * A failed key remains armed for retry; completed keys retain an explicit
 * progress bit and are skipped on later idempotent restore attempts (M27). */
static int git_restore_scope_snapshot(git_scope_t scope,
                                      git_scope_snapshot_t *snapshot) {
    int failures = 0;

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        git_snapshot_key_t *key = &snapshot->keys[i];
        bool failed = false;

        if (key->restored) continue;
        if (git_unset_config_value_impl(g_managed_keys[i], scope, true) != 0) {
            log_warning("Rollback failed to clear %s: %s",
                        g_managed_keys[i], get_last_error()->message);
            failures++;
            continue;
        }
        for (size_t j = 0; j < key->count; j++) {
            if (git_add_snapshot_value(scope, g_managed_keys[i],
                                       key->values[j]) != 0) {
                log_warning("Rollback failed to restore %s: %s",
                            g_managed_keys[i], get_last_error()->message);
                failed = true;
                break;
            }
        }
        if (failed) {
            failures++;
            continue;
        }

        if (key->count == 0) {
            cfg_cache_store(cfg_scope_index(scope), (int)i,
                            CFG_WRITTEN, false, "");
        } else if (key->count == 1) {
            cfg_cache_store(cfg_scope_index(scope), (int)i,
                            CFG_WRITTEN, true, key->values[0]);
        } else {
            cfg_cache_store(cfg_scope_index(scope), (int)i,
                            CFG_UNKNOWN, true, "");
        }
        key->restored = true;
    }
    return failures;
}

int git_config_snapshot(git_scope_t scope) {
    git_config_snapshot_t next;
    bool manage_worktree = false;

    memset(&next, 0, sizeof(next));
    /* An ordinary completed transaction may be replaced by the next switch,
     * but an incomplete rollback owns this slot until exact retry succeeds.
     * Allowing a fresh snapshot to consume it would make M27 retention a
     * cosmetic flag rather than a recovery guarantee. */
    if (g_git_snapshot.valid && g_git_snapshot.restore_incomplete) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot start a new Git snapshot while rollback remains incomplete");
        return -1;
    }
    git_snapshot_clear(&g_git_snapshot);
    if (!git_scope_to_flag(scope)) {
        set_error(ERR_INVALID_ARGS, "Invalid Git snapshot scope");
        return -1;
    }

    /* Worktree attribution must be known before any forward mutation. A
     * failed/unsupported scope probe is a hard stop: otherwise a higher
     * precedence identity could survive an apparently successful switch. */
    if ((scope == GIT_SCOPE_GLOBAL || scope == GIT_SCOPE_LOCAL) &&
        git_detect_managed_worktree_scope(&manage_worktree) != 0) {
        return -1;
    }

    next.scope = scope;
    next.local_also = (scope == GIT_SCOPE_GLOBAL && git_is_repository());
    next.worktree_also = manage_worktree;
    if (git_capture_scope_snapshot(scope, &next.primary) != 0 ||
        (next.local_also &&
         git_capture_scope_snapshot(GIT_SCOPE_LOCAL, &next.local) != 0) ||
        (next.worktree_also &&
         git_capture_scope_snapshot(GIT_SCOPE_WORKTREE_INTERNAL,
                                    &next.worktree) != 0)) {
        git_snapshot_clear(&next);
        return -1;
    }

    next.valid = true;
    g_git_snapshot = next;
    git_seed_snapshot_cache(scope, &g_git_snapshot.primary);
    if (g_git_snapshot.local_also) {
        git_seed_snapshot_cache(GIT_SCOPE_LOCAL, &g_git_snapshot.local);
    }
    if (g_git_snapshot.worktree_also) {
        git_seed_snapshot_cache(GIT_SCOPE_WORKTREE_INTERNAL,
                                &g_git_snapshot.worktree);
    }
    return 0;
}

int git_config_restore(void) {
    int failures = 0;

    if (!g_git_snapshot.valid) return 0;
    log_info("Rolling back git configuration after a failed switch");
    /* Restore override scopes before the primary scope. */
    if (g_git_snapshot.worktree_also) {
        failures += git_restore_scope_snapshot(GIT_SCOPE_WORKTREE_INTERNAL,
                                               &g_git_snapshot.worktree);
    }
    if (g_git_snapshot.local_also) {
        failures += git_restore_scope_snapshot(GIT_SCOPE_LOCAL,
                                               &g_git_snapshot.local);
    }
    failures += git_restore_scope_snapshot(g_git_snapshot.scope,
                                           &g_git_snapshot.primary);
    if (failures > 0) {
        /* Retain the exact snapshot and per-key progress until every key has
         * succeeded. Consuming it here made transient lock failures
         * irrecoverable on a second rollback attempt (AR-07 M27). */
        g_git_snapshot.restore_incomplete = true;
        fprintf(stderr,
                "gitswitch: [!!] git rollback incomplete — %d config key(s) could "
                "not be restored; retry after repairing the Git config lock\n",
                failures);
        return -1;
    }
    git_snapshot_clear(&g_git_snapshot);
    return 0;
}

/* Initialize git operations */
int git_ops_init(void) {
    log_debug("Initializing git operations");
    
    /* Validate git installation */
    if (validate_git_installation() != 0) {
        set_error(ERR_SYSTEM_REQUIREMENT, "Git validation failed");
        return -1;
    }
    
    log_info("Git operations initialized successfully");
    return 0;
}

static int git_require_scope_key_absent(const char *key, git_scope_t scope) {
    char value[GIT_CFG_VALUE_MAX];
    bool value_unknown = false;
    int cache_scope = cfg_scope_index(scope);
    int cache_key = cfg_key_index(key);

    if (cache_scope >= 0 && cache_key >= 0 &&
        g_cfg_cache[cache_scope][cache_key].state == CFG_WRITTEN &&
        !g_cfg_cache[cache_scope][cache_key].present) {
        return 0;
    }

    if (git_get_config_value_ex(key, value, sizeof(value), scope,
                                &value_unknown) == 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Stale %s remains effective from %s scope",
                  key, git_scope_to_flag(scope));
        return -1;
    }
    if (value_unknown) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Could not verify that %s is absent from %s scope",
                  key, git_scope_to_flag(scope));
        return -1;
    }
    return 0;
}

static int git_require_scope_key_value(const char *key, const char *expected,
                                       git_scope_t scope) {
    char value[GIT_CFG_VALUE_MAX];
    bool value_unknown = false;

    if (git_get_config_value_ex(key, value, sizeof(value), scope,
                                &value_unknown) != 0 || value_unknown ||
        strcmp(value, expected) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git %s does not match the selected account in %s scope",
                  key, git_scope_to_flag(scope));
        return -1;
    }
    return 0;
}

/* Verify the merged identity without relying on a scope-less read that loses
 * attribution. The selected scope must contain the exact requested values;
 * every higher-precedence scope that this switch cleared must prove absence. */
static int git_verify_effective_account(const account_t *account,
                                        git_scope_t scope,
                                        bool manage_worktree) {
    char expected_ssh[GIT_CFG_VALUE_MAX];
    const char *const managed_keys[] = {
        GIT_CONFIG_USER_NAME, GIT_CONFIG_USER_EMAIL,
        GIT_CONFIG_USER_SIGNINGKEY, GIT_CONFIG_COMMIT_GPGSIGN,
        GIT_CONFIG_GPG_PROGRAM, GIT_CONFIG_CORE_SSHCOMMAND
    };

    if (git_require_scope_key_value(GIT_CONFIG_USER_NAME, account->name,
                                    scope) != 0 ||
        git_require_scope_key_value(GIT_CONFIG_USER_EMAIL, account->email,
                                    scope) != 0) {
        return -1;
    }

    if (account->ssh_enabled && account->ssh_key_path[0] != '\0') {
        if (git_expected_ssh_command(account, expected_ssh,
                                     sizeof(expected_ssh)) != 0) {
            return -1;
        }
        if (git_require_scope_key_value(GIT_CONFIG_CORE_SSHCOMMAND,
                                        expected_ssh, scope) != 0) {
            return -1;
        }
    } else if (git_require_scope_key_absent(GIT_CONFIG_CORE_SSHCOMMAND,
                                             scope) != 0) {
        return -1;
    }

    if (account->gpg_enabled && account->gpg_key_id[0] != '\0') {
        if (git_require_scope_key_value(GIT_CONFIG_USER_SIGNINGKEY,
                                        account->gpg_key_id, scope) != 0 ||
            git_require_scope_key_value(GIT_CONFIG_COMMIT_GPGSIGN,
                                        account->gpg_signing_enabled
                                            ? "true" : "false",
                                        scope) != 0) {
            return -1;
        }
    } else {
        if (git_require_scope_key_absent(GIT_CONFIG_USER_SIGNINGKEY,
                                         scope) != 0 ||
            git_require_scope_key_value(GIT_CONFIG_COMMIT_GPGSIGN,
                                        "false", scope) != 0) {
            return -1;
        }
    }
    if (git_require_scope_key_absent(GIT_CONFIG_GPG_PROGRAM, scope) != 0)
        return -1;

    /* Worktree outranks local; local outranks global. Each scope that should
     * have been cleared must now be authoritatively absent, including values
     * supplied through an include at that scope. */
    if (manage_worktree) {
        for (size_t i = 0; i < sizeof(managed_keys) / sizeof(managed_keys[0]); i++)
            if (git_require_scope_key_absent(managed_keys[i],
                                             GIT_SCOPE_WORKTREE_INTERNAL) != 0)
                return -1;
    }
    if (scope == GIT_SCOPE_GLOBAL && git_is_repository()) {
        for (size_t i = 0; i < sizeof(managed_keys) / sizeof(managed_keys[0]); i++)
            if (git_require_scope_key_absent(managed_keys[i],
                                             GIT_SCOPE_LOCAL) != 0)
                return -1;
    }
    return git_verify_merged_account(account);
}

/* Set git configuration for account */
int git_set_config(const account_t *account, git_scope_t scope) {
    const char *scope_flag;
    bool manage_worktree = false;
    
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to git_set_config");
        return -1;
    }
    
    /* Validate account data */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account name for git config");
        return -1;
    }
    
    if (!validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account email for git config");
        return -1;
    }
    
    /* Get scope flag */
    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }
    
    /* If local scope, ensure we're in a git repository */
    if (scope == GIT_SCOPE_LOCAL && !git_is_repository()) {
        set_error(ERR_GIT_NOT_REPOSITORY, "Not in a git repository, cannot set local config");
        return -1;
    }
    
    /* The caller (accounts_switch) snapshots managed keys via
     * git_config_snapshot() before this point and restores them on failure, so
     * the whole switch is rolled back atomically rather than left half-applied. */

    if (scope == GIT_SCOPE_GLOBAL || scope == GIT_SCOPE_LOCAL) {
        if (g_git_snapshot.valid && g_git_snapshot.scope == scope) {
            manage_worktree = g_git_snapshot.worktree_also;
        } else if (git_detect_managed_worktree_scope(&manage_worktree) != 0) {
            return -1;
        }
    }

    /* Worktree config outranks both local and global. Clear it first only
     * when Git attributed a managed value to the distinct worktree scope;
     * with the extension disabled, --worktree aliases --local. */
    if (manage_worktree) {
        log_info("Clearing worktree git config to prevent stale overrides");
        if (git_clear_config(GIT_SCOPE_WORKTREE_INTERNAL) != 0) return -1;
    }

    /* When setting global scope inside a repo, clear local config so stale
     * values (e.g. signing key from a prior account) don't take precedence. */
    if (scope == GIT_SCOPE_GLOBAL && git_is_repository()) {
        log_info("Clearing local git config to prevent stale overrides");
        if (git_clear_config(GIT_SCOPE_LOCAL) != 0) return -1;
    }

    log_info("Setting git configuration for account: %s (%s scope)", account->name, scope_flag);

    /* Set user.name */
    if (git_set_config_value(GIT_CONFIG_USER_NAME, account->name, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set user.name");
        return -1;
    }
    
    /* Set user.email */
    if (git_set_config_value(GIT_CONFIG_USER_EMAIL, account->email, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set user.email");
        return -1;
    }
    
    /* Configure GPG if enabled */
    if (account->gpg_enabled) {
        if (git_configure_gpg(account, scope) != 0) {
            log_warning("Failed to configure GPG for git");
            /* Don't fail completely, GPG is optional */
        }
    } else {
        /* Disable GPG signing. Check both writes (AR-06 F20): unlike the
         * gpg_enabled branch — compensated by accounts.c's hard-failing
         * gpg_configure_git_signing — nothing downstream re-writes or verifies
         * these, so a silently failed commit.gpgsign=false left the PREVIOUS
         * account's signing ON while the switch reported success, and every
         * commit kept getting signed with the wrong key. Fail so accounts_switch
         * rolls the switch back, mirroring the SSH branch below. A key that was
         * already absent is not a failure (git_unset_config_value returns 0 on
         * exit 5). */
        if (git_unset_config_value(GIT_CONFIG_USER_SIGNINGKEY, scope) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear user.signingkey");
            return -1;
        }
        if (git_set_config_value(GIT_CONFIG_COMMIT_GPGSIGN, "false", scope) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to disable commit.gpgsign");
            return -1;
        }
    }

    /* GPG isolation is selected through GNUPGHOME. A persisted gpg.program
     * belongs to no account in this model and can redirect signing elsewhere. */
    if (git_unset_config_value(GIT_CONFIG_GPG_PROGRAM, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear gpg.program");
        return -1;
    }
    
    /* Configure SSH if enabled. AR-05 M5: SSH identity is NOT optional for
     * an account that declares ssh_enabled. core.sshCommand carries
     * IdentitiesOnly=yes, so the configured key bypasses the isolated agent
     * and is authoritative for every fetch/push — the old warn-only path
     * left the PREVIOUS account's core.sshCommand live while the switch
     * printed success: silent wrong-identity pushes. Unlike the GPG branch
     * above (compensated by accounts.c's hard-failing
     * gpg_configure_git_signing), nothing downstream re-writes or verifies
     * this key, so fail here and let accounts_switch roll the switch back. */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (git_configure_ssh(account, scope) != 0) {
            return -1;
        }
    } else {
        /* Clear SSH configuration */
        if (git_unset_config_value(GIT_CONFIG_CORE_SSHCOMMAND, scope) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear core.sshCommand");
            return -1;
        }
    }
    
    /* Verify configuration was set correctly - check the same scope we just
     * wrote to. A failed read-back of a key we just wrote is itself a
     * verification failure: we cannot confirm the identity was applied, which
     * is the whole point of the check. (Previously a failed read-back short-
     * circuited the && and the function returned success unverified.) */
    if (git_verify_effective_account(account, scope, manage_worktree) != 0) {
        return -1;
    }
    
    log_info("Git configuration set successfully for %s", account->name);
    return 0;
}

/* Preserve a useful Git diagnostic without ever feeding its arbitrary control
 * bytes into a terminal/error string. run_argv has one capture channel, so a
 * successful binary listing keeps stderr separate; only after that read fails
 * do we repeat the same read-only command with stderr merged for diagnostics.
 * The original run_result remains authoritative if the diagnostic retry races
 * with a concurrent repair. */
static void git_set_capture_error(const char *context,
                                  const char *const argv[],
                                  const run_result_t *original) {
    char diagnostic[2048];
    run_opts_t opts;
    run_result_t retry;
    size_t length;

    memset(diagnostic, 0, sizeof(diagnostic));
    memset(&opts, 0, sizeof(opts));
    memset(&retry, 0, sizeof(retry));
    opts.out = diagnostic;
    opts.out_size = sizeof(diagnostic);
    opts.merge_stderr = true;
    (void)run_argv(argv, &opts, &retry);

    length = retry.out_len;
    if (length >= sizeof(diagnostic)) length = sizeof(diagnostic) - 1U;
    {
        size_t read_offset = 0;
        size_t write_offset = 0;

        /* Sanitize before set_error(): it logs immediately, so a later
         * terminal-safe print wrapper cannot protect the log. Strict UTF-8
         * decoding catches encoded C1 controls such as U+009B (CSI); malformed
         * bytes and every unsafe codepoint collapse to one ordinary space.
         * In-place compaction is safe because output never grows. */
        while (read_offset < length) {
            uint32_t codepoint = 0;
            size_t decoded = utf8_decode(
                (const unsigned char *)diagnostic + read_offset,
                length - read_offset, &codepoint);
            if (decoded == 0) {
                diagnostic[write_offset++] = ' ';
                read_offset++;
            } else if (!tty_safe_codepoint(codepoint)) {
                diagnostic[write_offset++] = ' ';
                read_offset += decoded;
            } else {
                memmove(diagnostic + write_offset,
                        diagnostic + read_offset, decoded);
                write_offset += decoded;
                read_offset += decoded;
            }
        }
        length = write_offset;
    }
    while (length > 0 && diagnostic[length - 1U] == ' ') length--;
    diagnostic[length] = '\0';

    if (diagnostic[0] != '\0' &&
        (!retry.spawned || retry.term_signal != 0 || retry.exit_code != 0)) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: %s%s", context, diagnostic,
                  retry.out_truncated ? " [diagnostic truncated]" : "");
    } else if (original && original->term_signal != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git was killed by signal %d",
                  context, original->term_signal);
    } else if (original && original->spawned) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git exited with status %d",
                  context, original->exit_code);
    } else {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git could not be started",
                  context);
    }
}

/* Read effective values and their exact scope/file origins. The complete Git
 * configuration can be much larger than the six managed keys because --list
 * includes unrelated values. Grow and retry until the binary listing is
 * complete instead of converting a fixed-buffer truncation into six absences.
 * Allocation/size overflow is an explicit error, never a clean status. */
static int git_read_effective_keys(git_effective_listing_t **out) {
    size_t capacity = 16384U;
    char *list = NULL;
    const char *argv[] = {
        "git", "config", "--show-origin", "--show-scope", "-z", "--list", NULL
    };

    if (!out) return -1;
    *out = NULL;
    list = malloc(capacity);
    if (!list) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory reading effective Git configuration");
        return -1;
    }

    for (;;) {
        run_opts_t opts;
        run_result_t res;
        memset(&opts, 0, sizeof(opts));
        memset(&res, 0, sizeof(res));
        opts.out = list;
        opts.out_size = capacity;
        opts.stderr_to_devnull = true;

        if (run_argv(argv, &opts, &res) != 0) {
            git_set_capture_error(
                "Could not read effective Git configuration with origins",
                argv, &res);
            free(list);
            return -1;
        }
        if (!res.out_truncated) {
            int parse_rc = parse_effective_listing(
                list, res.out_len, &g_effective_listing);
            free(list);
            if (parse_rc != 0) {
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Malformed effective Git configuration listing");
                return -1;
            }
            *out = &g_effective_listing;
            return 0;
        }

        if (capacity > SIZE_MAX / 2U) {
            free(list);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Effective Git configuration is too large to inspect");
            return -1;
        }
        capacity *= 2U;
        char *grown = realloc(list, capacity);
        if (!grown) {
            free(list);
            set_error(ERR_MEMORY_ALLOCATION,
                      "Out of memory growing effective Git configuration capture");
            return -1;
        }
        list = grown;
    }
}

/* Mirror Git's complete Boolean grammar while retaining the one atomic
 * effective listing: an implicit key is true; empty, false/no/off, and every
 * in-range signed integer equal to zero are false; true/yes/on and nonzero
 * integers are true. Text keywords are case-insensitive. Numeric parsing uses
 * C base detection plus Git's optional k/m/g binary scale suffix, remains
 * within a signed-int result, and rejects trailing bytes/overflow. The focused
 * regression table compares every category to `git config --bool` itself. */
static int git_parse_effective_bool(const git_kv_t *entry, const char *key,
                                    bool *value) {
    char *end = NULL;
    long long number;
    long long multiplier = 1;

    if (!entry || !key || !value || !entry->present) {
        set_error(ERR_INVALID_ARGS, "Invalid Git Boolean query");
        return -1;
    }
    if (entry->implicit) {
        *value = true;
        return 0;
    }
    if (entry->value_unknown) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git Boolean value is too large to inspect");
        return -1;
    }
    if (entry->value[0] == '\0' ||
        strcasecmp(entry->value, "false") == 0 ||
        strcasecmp(entry->value, "no") == 0 ||
        strcasecmp(entry->value, "off") == 0) {
        *value = false;
        return 0;
    }
    if (strcasecmp(entry->value, "true") == 0 ||
        strcasecmp(entry->value, "yes") == 0 ||
        strcasecmp(entry->value, "on") == 0) {
        *value = true;
        return 0;
    }

    errno = 0;
    number = strtoll(entry->value, &end, 0);
    if (errno == 0 && end != entry->value) {
        if (*end != '\0') {
            if (end[1] != '\0') goto invalid;
            switch (*end) {
                case 'k':
                case 'K':
                    multiplier = 1024LL;
                    break;
                case 'm':
                case 'M':
                    multiplier = 1024LL * 1024LL;
                    break;
                case 'g':
                case 'G':
                    multiplier = 1024LL * 1024LL * 1024LL;
                    break;
                default:
                    goto invalid;
            }
        }
        if (number >= (long long)INT_MIN / multiplier &&
            number <= (long long)INT_MAX / multiplier) {
            *value = number != 0;
            return 0;
        }
    }

invalid:
    set_error(ERR_GIT_CONFIG_FAILED,
              "Invalid effective Git Boolean value for %s", key);
    return -1;
}

static int effective_key_matches(const git_effective_listing_t *listing,
                                 const char *key, const char *expected,
                                 bool expected_present) {
    int index = cfg_key_index(key);
    if (index < 0) return -1;
    if (!expected_present)
        return listing->keys[index].present ? -1 : 0;
    if (!listing->keys[index].present || listing->keys[index].value_unknown)
        return -1;
    return strcmp(listing->keys[index].value, expected) == 0 ? 0 : -1;
}

static int git_verify_merged_account(const account_t *account) {
    git_effective_listing_t *effective;
    char expected_ssh[GIT_CFG_VALUE_MAX];
    bool ssh_present = account->ssh_enabled && account->ssh_key_path[0] != '\0';
    bool gpg_present = account->gpg_enabled && account->gpg_key_id[0] != '\0';

    if (git_read_effective_keys(&effective) != 0) return -1;
    if (ssh_present &&
        git_expected_ssh_command(account, expected_ssh,
                                 sizeof(expected_ssh)) != 0)
        return -1;

    if (effective_key_matches(effective, GIT_CONFIG_USER_NAME,
                              account->name, true) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_USER_EMAIL,
                              account->email, true) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_CORE_SSHCOMMAND,
                              ssh_present ? expected_ssh : NULL,
                              ssh_present) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_USER_SIGNINGKEY,
                              gpg_present ? account->gpg_key_id : NULL,
                              gpg_present) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_COMMIT_GPGSIGN,
                              gpg_present && account->gpg_signing_enabled
                                  ? "true" : "false",
                              true) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_GPG_PROGRAM,
                              NULL, false) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective merged Git configuration does not match the selected account");
        return -1;
    }
    return 0;
}

static void copy_effective_value(git_config_effective_value_t *dest,
                                 const git_effective_listing_t *listing,
                                 int key_index) {
    memset(dest, 0, sizeof(*dest));
    dest->present = listing->keys[key_index].present;
    dest->value_unknown = listing->keys[key_index].value_unknown;
    dest->scope = listing->scopes[key_index];
    snprintf(dest->origin, sizeof(dest->origin), "%s",
             listing->origins[key_index]);
    if (dest->present && !dest->value_unknown) {
        snprintf(dest->value, sizeof(dest->value), "%s",
                 listing->keys[key_index].value);
    }
}

int git_get_current_config(git_current_config_t *config) {
    git_effective_listing_t *effective;
    const int k_name = cfg_key_index(GIT_CONFIG_USER_NAME);
    const int k_email = cfg_key_index(GIT_CONFIG_USER_EMAIL);
    const int k_signkey = cfg_key_index(GIT_CONFIG_USER_SIGNINGKEY);
    const int k_gpgsign = cfg_key_index(GIT_CONFIG_COMMIT_GPGSIGN);
    const int k_gpgprogram = cfg_key_index(GIT_CONFIG_GPG_PROGRAM);
    const int k_sshcommand = cfg_key_index(GIT_CONFIG_CORE_SSHCOMMAND);

    if (!config) {
        set_error(ERR_INVALID_ARGS, "NULL config to git_get_current_config");
        return -1;
    }

    /* Initialize structure */
    memset(config, 0, sizeof(git_current_config_t));
    config->valid = false;

    if (k_name < 0 || k_email < 0 || k_signkey < 0 || k_gpgsign < 0 ||
        k_gpgprogram < 0 || k_sshcommand < 0) {
        set_error(ERR_INVALID_ARGS, "Managed git key set is incomplete");
        return -1;
    }
    if (git_read_effective_keys(&effective) != 0) return -1;

    /* Validate every present managed value before classifying a missing
     * identity. Otherwise an absent user.name can hide an invalid Boolean or
     * an unrepresentable SSH/GPG value and status reports a reassuring normal
     * NOT FOUND state even though the effective configuration is malformed. */
    if (effective->keys[k_name].value_unknown ||
        effective->keys[k_email].value_unknown ||
        effective->keys[k_signkey].value_unknown ||
        effective->keys[k_gpgsign].value_unknown ||
        effective->keys[k_sshcommand].value_unknown ||
        effective->keys[k_gpgprogram].value_unknown) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "An effective managed Git value exceeds the supported status representation");
        return -1;
    }

    if ((effective->keys[k_name].present &&
         safe_strncpy(config->name, effective->keys[k_name].value,
                      sizeof(config->name)) != 0) ||
        (effective->keys[k_email].present &&
         safe_strncpy(config->email, effective->keys[k_email].value,
                      sizeof(config->email)) != 0)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git identity exceeds supported field length");
        return -1;
    }
    if (effective->keys[k_signkey].present &&
        safe_strncpy(config->signing_key,
                     effective->keys[k_signkey].value,
                     sizeof(config->signing_key)) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git signing key exceeds supported field length");
        return -1;
    }
    if (effective->keys[k_gpgsign].present &&
        git_parse_effective_bool(&effective->keys[k_gpgsign],
                                 GIT_CONFIG_COMMIT_GPGSIGN,
                                 &config->gpg_signing_enabled) != 0) {
        return -1;
    }
    if (!effective->keys[k_name].present) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.name configured");
        return -1;
    }
    if (!effective->keys[k_email].present) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.email configured");
        return -1;
    }

    config->effective_name_scope = effective->scopes[k_name];
    snprintf(config->effective_name_origin,
             sizeof(config->effective_name_origin), "%s",
             effective->origins[k_name]);
    switch (config->effective_name_scope) {
        case GIT_CONFIG_ORIGIN_GLOBAL: config->scope = GIT_SCOPE_GLOBAL; break;
        case GIT_CONFIG_ORIGIN_SYSTEM: config->scope = GIT_SCOPE_SYSTEM; break;
        case GIT_CONFIG_ORIGIN_LOCAL:
        case GIT_CONFIG_ORIGIN_WORKTREE:
        case GIT_CONFIG_ORIGIN_COMMAND:
        case GIT_CONFIG_ORIGIN_UNKNOWN:
        default: config->scope = GIT_SCOPE_LOCAL; break;
    }

    copy_effective_value(&config->ssh_command, effective, k_sshcommand);
    copy_effective_value(&config->gpg_program, effective, k_gpgprogram);

    config->valid = true;
    return 0;
}

/* Clear git configuration */
int git_clear_config(git_scope_t scope) {
    const char *scope_flag;
    const char *const keys[] = {
        GIT_CONFIG_USER_NAME,
        GIT_CONFIG_USER_EMAIL,
        GIT_CONFIG_USER_SIGNINGKEY,
        GIT_CONFIG_COMMIT_GPGSIGN,
        GIT_CONFIG_GPG_PROGRAM,
        GIT_CONFIG_CORE_SSHCOMMAND
    };
    char first_error[sizeof(g_last_error.message)] = "";
    int failures = 0;
    
    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }
    
    log_info("Clearing git configuration (%s scope)", scope_flag);
    
    /* Attempt every managed unset so one failure cannot hide additional stale
     * identity state. Preserve the first useful diagnostic after the loop. */
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (git_unset_config_value(keys[i], scope) != 0) {
            if (failures == 0) {
                snprintf(first_error, sizeof(first_error), "%s",
                         get_last_error()->message);
            }
            failures++;
        }
    }

    if (failures != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to clear %d Git configuration key(s) in %s scope: %s",
                  failures, scope_flag,
                  first_error[0] ? first_error : "unknown Git error");
        return -1;
    }
    
    log_info("Git configuration cleared");
    return 0;
}

/* AR-06 F59: git_validate_repository() and git_get_config_scope() were removed
 * here — both were public API with zero callers anywhere in the tree (dead
 * code, and git_get_config_scope's system-scope arm implied a scope model the
 * rest of git_ops does not use). */

/* Test git configuration */
int git_test_config(const account_t *account, git_scope_t scope) {
    char verify_name[MAX_NAME_LEN];
    char verify_email[MAX_EMAIL_LEN];

    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to git_test_config");
        return -1;
    }

    log_info("Testing git configuration for account: %s", account->name);

    /* Get configuration from the specified scope and verify it matches */
    if (git_get_config_value(GIT_CONFIG_USER_NAME, verify_name, sizeof(verify_name), scope) != 0 ||
        git_get_config_value(GIT_CONFIG_USER_EMAIL, verify_email, sizeof(verify_email), scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to read git configuration from %s scope",
                  git_scope_to_flag(scope));
        return -1;
    }

    if (strcmp(verify_name, account->name) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Git user.name does not match account: expected '%s', got '%s'",
                  account->name, verify_name);
        return -1;
    }

    if (strcmp(verify_email, account->email) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Git user.email does not match account: expected '%s', got '%s'",
                  account->email, verify_email);
        return -1;
    }
    
    /* Test GPG configuration if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        char signing_key[MAX_GPG_FINGERPRINT_LEN];
        char gpg_sign[16];

        if (git_get_config_value(GIT_CONFIG_USER_SIGNINGKEY, signing_key, sizeof(signing_key), scope) != 0 ||
            strlen(signing_key) == 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "GPG signing key not configured in git");
            return -1;
        }

        if (git_get_config_value(GIT_CONFIG_COMMIT_GPGSIGN, gpg_sign, sizeof(gpg_sign), scope) != 0 ||
            strcmp(gpg_sign, "true") != 0) {
            log_warning("GPG signing is configured but not enabled");
        }

        /* Test GPG key availability (no shell). Which keyring gpg consults is
         * decided by GNUPGHOME — by the time a switch validates itself that is
         * already the account's isolated home, not the system keyring the old
         * comment claimed. Skipped entirely when a gpg spawn earlier in this
         * process already proved the key's presence, which on the switch path
         * is always true (AR-02 #14). */
        if (!gpg_manager_key_available_cached(account->gpg_key_id)) {
            const char *gpg_argv[] = {"gpg", "--list-secret-keys", account->gpg_key_id, NULL};
            run_opts_t gpg_opts;
            memset(&gpg_opts, 0, sizeof(gpg_opts));
            gpg_opts.stderr_to_devnull = true;
            if (run_argv(gpg_argv, &gpg_opts, NULL) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available: %s", account->gpg_key_id);
                return -1;
            }
            gpg_manager_note_key_available(account->gpg_key_id);
        }
    }

    log_info("Git configuration test passed for %s", account->name);
    return 0;
}

/* Set single git configuration value */
/* skip_validation is set ONLY by the rollback restore path (AR-06 F04): the
 * value being written came verbatim from git's own `--list -z` snapshot, so it
 * is by construction representable (git stored it, e.g. a multi-line user.name
 * or a leading-'-' value — both of which is_valid_git_config_value rejects).
 * The old gate silently refused to restore them, and because the restore loop
 * discarded the error, a failed switch left the new account's name over the
 * user's original — a chimera identity the tool exists to prevent. On the argv
 * exec path the value never reaches a shell, so bypassing the gate for a
 * git-sourced value is safe. Normal (user-driven) writes keep the gate. */
static int git_set_config_value_impl(const char *key, const char *value,
                                     git_scope_t scope, bool skip_validation) {
    char output[256];
    const char *scope_flag;

    if (!key || !value) {
        set_error(ERR_INVALID_ARGS, "NULL key or value to git_set_config_value");
        return -1;
    }

    /* Belt-and-suspenders only: argv execution means the value is never parsed
     * by a shell, so this is no longer the security boundary. */
    if (!skip_validation && !is_valid_git_config_value(value)) {
        set_error(ERR_INVALID_ARGS, "Invalid characters in git config value");
        return -1;
    }

    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    /* perf-3: on a GPG switch, user.signingkey and commit.gpgsign are written
     * once by git_configure_gpg and again (same values) by gpg_manager's
     * gpg_configure_git_signing. Skip a write ONLY when this process already
     * ran the identical write successfully — re-execing it could only repeat
     * the first result, so the config outcome is provably unchanged. A value
     * merely read back (CFG_READBACK) never suppresses a write: e.g. on a
     * multi-valued key the read succeeds but the write would fail, and that
     * failure must surface. */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (s >= 0 && k >= 0 && g_cfg_cache[s][k].state == CFG_WRITTEN &&
        g_cfg_cache[s][k].present && strcmp(g_cfg_cache[s][k].value, value) == 0) {
        log_debug("Skipping git config %s: identical value already written by this process", key);
        return 0;
    }

    log_debug("Setting git config: %s = %s (%s)", key, value, scope_flag);

    if (git_run(output, sizeof(output), "config", scope_flag, key, value,
                (const char *)NULL) != 0) {
        /* The key's on-disk state is now uncertain; never skip/serve it. */
        cfg_cache_store(s, k, CFG_UNKNOWN, false, "");
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git config %s: %s", key, output);
        return -1;
    }

    cfg_cache_store(s, k, CFG_WRITTEN, true, value);
    return 0;
}

int git_set_config_value(const char *key, const char *value, git_scope_t scope) {
    return git_set_config_value_impl(key, value, scope, false);
}

/* Get single git configuration value.
 *
 * The _ex form additionally reports "present but too long": git exited 0 for
 * the key, but either the capture itself overflowed (run_result_t.out_truncated
 * — the pre-fix code never checked it, so a silently truncated value was
 * stored as the real one, AR-03 M1) or the full value would not fit the
 * caller's buffer. rc is still -1 either way; *value_too_long lets ordinary
 * scoped verification distinguish an uncapturable value from a genuinely
 * absent key. Transaction snapshots use the separate dynamic listing path. */
static int git_get_config_value_ex(const char *key, char *value,
                                   size_t value_size, git_scope_t scope,
                                   bool *value_too_long) {
    /* Big enough for any value we can cache, plus git's trailing newline —
     * anything larger trips out_truncated below rather than silent loss. */
    char output[GIT_CFG_VALUE_MAX + 8];
    const char *scope_flag;

    if (value_too_long) {
        *value_too_long = false;
    }

    if (!key || !value || value_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_get_config_value");
        return -1;
    }

    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    /* perf-2: after git_set_config's read-back verification, git_test_config
     * re-read the exact same user.name/user.email — two more execs per switch
     * for values git reported moments earlier in this process. Serve reads
     * from values previously OBSERVED in git output (CFG_READBACK only; our
     * own writes never satisfy a read, so read-back verification still
     * genuinely round-trips through git). Only positive observations are
     * cached: a failed read can mean "absent" or "git broke", and caching the
     * ambiguity would be guessing. */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (s >= 0 && k >= 0 && g_cfg_cache[s][k].state == CFG_READBACK &&
        g_cfg_cache[s][k].present &&
        strlen(g_cfg_cache[s][k].value) < value_size) {
        memcpy(value, g_cfg_cache[s][k].value, strlen(g_cfg_cache[s][k].value) + 1);
        return 0;
    }

    /* Direct run_argv (not git_run) so run_result_t.out_truncated is visible
     * — git_run discards the result struct. */
    const char *argv[] = { "git", "config", scope_flag, key, NULL };
    run_opts_t opts;
    run_result_t res;
    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &res) != 0) {
        /* AR-06 F56: distinguish "git ran and the key is genuinely absent"
         * (a clean exit 1 from `git config --get`) from "git could not be run"
         * (spawn failure, killed by signal, or an unexpected non-1 exit such as
         * a bad config file). Only the former is truly absent. The latter leaves
         * the key's presence UNKNOWN — reporting it absent would let the rollback
         * snapshot record it absent and then --unset the user's pre-existing
         * value on a transient failure. Flag it value-unknown (non-destructive),
         * exactly like a too-long value. */
        bool clean_absent = (res.spawned && res.term_signal == 0 &&
                             res.exit_code == 1);
        value[0] = '\0';
        if (!clean_absent && value_too_long) {
            cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
            *value_too_long = true;
        }
        return -1;
    }

    /* git exited 0, so the key IS present; a truncated capture means its
     * value is longer than anything gitswitch itself writes. Never report
     * that as absent, and never trust the partial bytes — the entry can only
     * be cached as "present, value unknown" (AR-03 M1). */
    if (res.out_truncated) {
        cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
        if (value_too_long) {
            *value_too_long = true;
        }
        value[0] = '\0';
        return -1;
    }

    /* AR-06 F58: strip ONLY the single trailing newline git appends, not all
     * surrounding whitespace. trim_whitespace() ate legitimate leading/trailing
     * spaces in a quoted config value, so the rollback wrote back a corrupted
     * (whitespace-stripped) value. Embedded newlines and edge spaces survive. */
    {
        size_t olen = strlen(output);
        if (olen > 0 && output[olen - 1] == '\n') {
            output[--olen] = '\0';
        }
    }
    /* safe_strncpy writes nothing and returns -1 when the value is too long for
     * the caller's buffer. Propagate that as failure (and NUL the buffer) so
     * callers can't read an uninitialized stack buffer while we report success.
     * The FULL value was still observed here, so it is cacheable regardless of
     * the caller's buffer size. */
    if (safe_strncpy(value, output, value_size) != 0) {
        cfg_cache_store(s, k, CFG_READBACK, true, output);
        if (value_too_long) {
            *value_too_long = true;
        }
        value[0] = '\0';
        return -1;
    }

    cfg_cache_store(s, k, CFG_READBACK, true, value);
    return 0;
}

/* Get single git configuration value */
int git_get_config_value(const char *key, char *value, size_t value_size, git_scope_t scope) {
    return git_get_config_value_ex(key, value, value_size, scope, NULL);
}

/* Unset git configuration value. Rollback passes force=true because every
 * restore starts with a checked unset-all even when the forward path's scalar
 * cache says the key is absent; a partial earlier restore or external lock
 * recovery can invalidate that optimization (AR-07 M27). */
static int git_unset_config_value_impl(const char *key, git_scope_t scope,
                                       bool force) {
    char output[256] = "";
    const char *scope_flag;

    if (!key) {
        set_error(ERR_INVALID_ARGS, "NULL key to git_unset_config_value");
        return -1;
    }

    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    /* Skip an unset the cache proves is a no-op: this process already unset
     * the key itself (CFG_WRITTEN/absent — the original duplicate-unset
     * skip), or a complete --list -z snapshot observed the key absent
     * (CFG_READBACK/absent, seeded by exact snapshot capture — AR-02 #15: the
     * global-switch clear-local step used to blindly re-exec six unsets the
     * snapshot one exec earlier had just proved unnecessary). */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (!force && s >= 0 && k >= 0 && !g_cfg_cache[s][k].present &&
        (g_cfg_cache[s][k].state == CFG_WRITTEN ||
         g_cfg_cache[s][k].state == CFG_READBACK)) {
        log_debug("Skipping git config --unset %s: known absent in this process", key);
        return 0;
    }

    log_debug("Unsetting git config: %s (%s)", key, scope_flag);

    /* --unset-all, not --unset (AR-06 F03): `git config --unset` exits 5 and
     * removes NOTHING when the key holds multiple values (hand edits, another
     * tool's --add, an include.path file contributing a second record). A stale
     * multi-valued local core.sshCommand then survived a global switch and,
     * being local scope, shadowed the freshly written global one — pushes kept
     * using the old SSH identity while the switch reported success. --unset-all
     * removes every value atomically. */
    {
        run_opts_t opts;
        run_result_t res;
        const char *argv[] = {"git", "config", scope_flag, "--unset-all", key, NULL};
        memset(&opts, 0, sizeof(opts));
        memset(&res, 0, sizeof(res));
        opts.out = output;
        opts.out_size = sizeof(output);
        opts.merge_stderr = true;
        run_argv(argv, &opts, &res);

        /* exit 0 = removed; exit 5 with --unset-all = the key did not exist.
         * Both prove the key is now absent, so caching CFG_WRITTEN/absent is
         * correct and lets a later duplicate unset be elided (AR-02 #15). Any
         * OTHER status (git error, or death-by-signal -> exit_code -1) means the
         * unset may NOT have happened: record CFG_UNKNOWN so a later corrective
         * unset in this process is not wrongly elided (AR-06 F03 cache
         * poisoning), and surface the failure to the caller. */
        if (res.exit_code == 0 || res.exit_code == 5) {
            cfg_cache_store(s, k, CFG_WRITTEN, false, "");
            return 0;
        }
        cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to unset git config %s (%s): %s", key, scope_flag,
                  output[0] ? output : "unknown error");
        return -1;
    }
}

int git_unset_config_value(const char *key, git_scope_t scope) {
    return git_unset_config_value_impl(key, scope, false);
}

/* List all git configuration values */
int git_list_config(git_scope_t scope, char *output, size_t output_size) {
    const char *scope_flag;

    if (!output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_list_config");
        return -1;
    }

    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    if (git_run(output, output_size, "config", scope_flag, "--list",
                (const char *)NULL) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to list git configuration");
        return -1;
    }

    return 0;
}

/* ssh-1: is_safe_ssh_key_path now lives in utils.c so BOTH of the key path's
 * injection-sensitive sinks apply it themselves: this file's core.sshCommand
 * (below) and ssh_manager.c's ~/.ssh/config IdentityFile write. It used to be
 * static here and guard only core.sshCommand, while comments claimed coverage
 * of the IdentityFile sink too — that sink was in fact protected only by the
 * TOML-load sanitizer stripping newlines/quotes, an incidental, load-time-only
 * defense (AR-02 #10). */

static int ssh_command_append(char *command, size_t command_size,
                              size_t *used, const char *text) {
    size_t length;
    if (!command || command_size == 0 || !used || !text) return -1;
    length = strlen(text);
    if (*used >= command_size || length > command_size - *used - 1U) {
        set_error(ERR_INVALID_ARGS, "SSH command too long");
        return -1;
    }
    memcpy(command + *used, text, length);
    *used += length;
    command[*used] = '\0';
    return 0;
}

/* Quote one argv word for the POSIX shell Git uses to interpret
 * core.sshCommand. Unlike the old key-only serialization, this must support a
 * trusted executable whose canonical path itself contains spaces or quotes.
 * The standard '\'' close/escaped-quote/reopen sequence preserves every byte. */
static int ssh_command_append_quoted(char *command, size_t command_size,
                                     size_t *used, const char *value) {
    if (ssh_command_append(command, command_size, used, "'") != 0) return -1;
    for (const char *cursor = value; *cursor; cursor++) {
        const char *piece = *cursor == '\'' ? "'\\''" : NULL;
        char byte[2] = { *cursor, '\0' };
        if (ssh_command_append(command, command_size, used,
                               piece ? piece : byte) != 0) {
            return -1;
        }
    }
    return ssh_command_append(command, command_size, used, "'");
}

#define SSH_COMMAND_OPTIONS                                                   \
    " -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"             \
    " -o LogLevel=ERROR"

/* GIT_CONFIG_VALUE_MAX reserves 256 bytes beyond the two serialized path
 * payloads. Prove at compile time that the exact fixed spelling, four quote
 * delimiters, and terminating NUL fit inside that reserve. */
_Static_assert((sizeof(" -i ") - 1U) + (sizeof(SSH_COMMAND_OPTIONS) - 1U) +
                       4U + 1U <=
                   256U,
               "GIT_CONFIG_VALUE_MAX fixed SSH command reserve is too small");

static int build_expected_ssh_command(const account_t *account,
                                      char *command, size_t command_size,
                                      char *expanded_path,
                                      size_t expanded_path_size) {
    char ssh_path[MAX_PATH_LEN];
    size_t used = 0;

    if (!account || !account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        set_error(ERR_INVALID_ARGS,
                  "SSH command requested for an account without an SSH key");
        return -1;
    }
    if (!command || command_size == 0 || !expanded_path ||
        expanded_path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH command output buffer");
        return -1;
    }

    /* Expand SSH key path */
    if (expand_path(account->ssh_key_path, expanded_path,
                    expanded_path_size) != 0) {
        set_error(ERR_INVALID_PATH, "Failed to expand SSH key path: %s", account->ssh_key_path);
        return -1;
    }

    /* Reject injection-capable characters BEFORE touching the filesystem:
     * whether such a path exists is irrelevant — it must never reach
     * core.sshCommand or an ~/.ssh/config IdentityFile line (see
     * is_safe_ssh_key_path above for the exact break-out routes). */
    if (!is_safe_ssh_key_path(expanded_path)) {
        set_error(ERR_INVALID_PATH,
                  "SSH key path contains an illegal character (quote/control): %s",
                  expanded_path);
        return -1;
    }

    /* Resolve the executable through the same complete owner/mode/ACL ancestry
     * proof used for immediate helper launches. Persisting a bare `ssh` would
     * make a later Git process repeat PATH lookup under unrelated, possibly
     * writable search directories. The absolute trusted spelling makes that
     * later lookup impossible. */
    if (find_command_path("ssh", ssh_path, sizeof(ssh_path)) != 0) {
        set_error(ERR_SSH_NOT_FOUND,
                  "No trusted SSH executable was found in PATH");
        return -1;
    }
    for (const unsigned char *byte = (const unsigned char *)ssh_path;
         *byte; byte++) {
        if (*byte < 0x20 || *byte == 0x7f) {
            set_error(ERR_INVALID_PATH,
                      "Trusted SSH executable path contains a control character");
            return -1;
        }
    }

    command[0] = '\0';
    if (ssh_command_append_quoted(command, command_size, &used, ssh_path) != 0 ||
        ssh_command_append(command, command_size, &used, " -i ") != 0 ||
        ssh_command_append_quoted(command, command_size, &used,
                                  expanded_path) != 0 ||
        ssh_command_append(command, command_size, &used,
                           SSH_COMMAND_OPTIONS) != 0) {
        return -1;
    }
    return 0;
}

int git_expected_ssh_command(const account_t *account, char *command,
                             size_t command_size) {
    char expanded_path[MAX_PATH_LEN];
    return build_expected_ssh_command(account, command, command_size,
                                      expanded_path, sizeof(expanded_path));
}

/* Configure SSH command for git operations */
int git_configure_ssh(const account_t *account, git_scope_t scope) {
    char ssh_command[GIT_CFG_VALUE_MAX];
    char expanded_key_path[MAX_PATH_LEN];

    if (!account || !account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        return 0; /* Nothing to configure */
    }

    if (build_expected_ssh_command(account, ssh_command, sizeof(ssh_command),
                                   expanded_key_path,
                                   sizeof(expanded_key_path)) != 0) {
        return -1;
    }

    /* Verify SSH key file exists and has correct permissions */
    if (!path_exists(expanded_key_path)) {
        set_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s", expanded_key_path);
        return -1;
    }

    log_debug("Configuring SSH command: %s", ssh_command);
    
    if (git_set_config_value(GIT_CONFIG_CORE_SSHCOMMAND, ssh_command, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set SSH command configuration");
        return -1;
    }

    /* AR-05 M5: round-trip the value through git, matching the user.name/
     * user.email verification in git_set_config. Reads are never served
     * from this process's own writes (only CFG_READBACK entries), so this
     * genuinely re-execs git and proves the authoritative SSH identity is
     * the one just written. */
    char readback[sizeof(ssh_command)];
    if (git_get_config_value(GIT_CONFIG_CORE_SSHCOMMAND, readback,
                             sizeof(readback), scope) != 0 ||
        strcmp(readback, ssh_command) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Could not read back core.sshCommand to verify it");
        return -1;
    }

    return 0;
}

/* Configure GPG for git operations */
int git_configure_gpg(const account_t *account, git_scope_t scope) {
    if (!account || !account->gpg_enabled || strlen(account->gpg_key_id) == 0) {
        return 0; /* Nothing to configure */
    }
    
    log_debug("Configuring GPG signing key: %s", account->gpg_key_id);
    
    /* Set signing key */
    if (git_set_config_value(GIT_CONFIG_USER_SIGNINGKEY, account->gpg_key_id, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set GPG signing key");
        return -1;
    }
    
    /* Enable/disable GPG signing */
    if (git_set_config_value(GIT_CONFIG_COMMIT_GPGSIGN, 
                            account->gpg_signing_enabled ? "true" : "false", scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set GPG signing preference");
        return -1;
    }
    
    return 0;
}

/* Check if current directory is a git repository.
 *
 * perf-4: a single switch asks this several times (scope resolution, the
 * config snapshot, and git_set_config's clear-local decision), and each ask
 * was a `git rev-parse --git-dir` fork+exec. The answer for a given cwd
 * cannot change mid-switch, so cache it per process, keyed by cwd — the key
 * costs one getcwd() syscall and guarantees a future chdir is never served
 * the previous directory's answer. If getcwd() itself fails we skip the cache
 * entirely and exec (fail closed on the cache, not the answer). */
bool git_is_repository(void) {
    char output[256];
    char cwd[MAX_PATH_LEN];
    bool have_cwd = (getcwd(cwd, sizeof(cwd)) != NULL);

    if (have_cwd && g_repo_cache.known && strcmp(cwd, g_repo_cache.cwd) == 0) {
        return g_repo_cache.is_repo;
    }

    /* Use git rev-parse --git-dir to check for repository */
    bool is_repo = (git_run(output, sizeof(output), "rev-parse", "--git-dir",
                            (const char *)NULL) == 0);

    if (have_cwd && safe_strncpy(g_repo_cache.cwd, cwd, sizeof(g_repo_cache.cwd)) == 0) {
        g_repo_cache.known = true;
        g_repo_cache.is_repo = is_repo;
    }

    return is_repo;
}

/* Get repository root directory */
int git_get_repo_root(char *path, size_t path_size) {
    char output[MAX_PATH_LEN];
    
    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_get_repo_root");
        return -1;
    }
    
    if (git_run(output, sizeof(output), "rev-parse", "--show-toplevel",
                (const char *)NULL) != 0) {
        set_error(ERR_GIT_NOT_REPOSITORY, "Not in a git repository");
        return -1;
    }
    
    trim_whitespace(output);
    safe_strncpy(path, output, path_size);
    
    return 0;
}

/* Convert scope enum to git config scope string */
const char *git_scope_to_flag(git_scope_t scope) {
    if (scope == GIT_SCOPE_WORKTREE_INTERNAL) return "--worktree";
    switch (scope) {
        case GIT_SCOPE_LOCAL:  return "--local";
        case GIT_SCOPE_GLOBAL: return "--global";
        case GIT_SCOPE_SYSTEM: return "--system";
        default: return NULL;
    }
}

/* Internal helper functions */

/* Execute git command and capture output */
/* Run `git <args...>` (NULL-terminated varargs), no shell. Captures merged
 * stdout+stderr into output. Returns 0 iff git exits 0. */
static int git_run(char *output, size_t output_size, ...) {
    const char *argv[32];
    size_t n = 0;
    va_list ap;
    const char *a;
    run_opts_t opts;
    run_result_t res;

    argv[n++] = "git";
    va_start(ap, output_size);
    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            va_end(ap);
            set_error(ERR_INVALID_ARGS, "Too many git arguments");
            return -1;
        }
        argv[n++] = a;
    }
    va_end(ap);
    argv[n] = NULL;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = true;

    log_debug("Executing git command: %s %s", argv[1] ? argv[1] : "", argv[2] ? argv[2] : "");
    return run_argv(argv, &opts, &res);
}

/* Validate git installation.
 *
 * perf-1: this runs on every switch AND on the boot-time `resume` that gates
 * the login shell prompt, and it used to fork+exec `git --version` each time
 * just to strstr the banner. command_exists() performs the same parent-side
 * ancestry, permission, format, and shebang eligibility checks as the default
 * runner without spawning a subprocess. A pathological non-git binary with a
 * recognized executable format still fails closed at the first real
 * `git config` invocation (every git_run result is checked).
 * Cached per process: only a positive answer is cached, so a transient PATH
 * problem is re-probed, and git appearing/vanishing mid-process is not a
 * supported flow. */
static int validate_git_installation(void) {
    if (g_git_validated) {
        return 0;
    }

    if (!command_exists("git")) {
        set_error(ERR_SYSTEM_REQUIREMENT, "Git is not installed or not in PATH");
        return -1;
    }

    g_git_validated = true;
    return 0;
}


/* Validate a git config value.
 *
 * Every value is written via git_run -> run_argv (execvp, no shell), so shell
 * metacharacters are NOT dangerous here and must be allowed: a user.name like
 * "Jane Doe (Work)" is common and legitimate, and the old blocklist of
 * ";|&`$(){}[]" rejected it, failing the switch. The only value git itself
 * feeds to a shell is core.sshCommand, whose sole variable component (the key
 * path) is separately validated and single-quoted in git_configure_ssh.
 *
 * So we reject only what is genuinely unsafe for `git config <key> <value>`:
 * control characters (which corrupt the config file / terminal), and a leading
 * '-' (which git could mistake for an option). */
static bool is_valid_git_config_value(const char *value) {
    if (!value) {
        return false;
    }

    if (value[0] == '-') {
        return false;
    }

    for (const char *p = value; *p; p++) {
        if ((unsigned char)*p < 32 && *p != '\t') {
            return false;
        }
    }

    return true;
}

/* Backup git config if needed */
