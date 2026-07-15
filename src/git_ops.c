/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

/* Darwin hides O_NOFOLLOW and its timespec-valued struct stat members when a
 * strict POSIX namespace is selected. Keep POSIX.1-2008 visibility while
 * explicitly restoring those Darwin extensions used by the descriptor-pinned
 * rollback path. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "git_ops.h"
#include "gpg_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "toml_parser.h"

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
static int git_verify_merged_account(const account_t *account,
                                     const char *expected_gpg_program);
static int git_reject_ssh_command_override(void);
static int git_set_config_impl(const account_t *account, git_scope_t scope);
static int git_configure_ssh_impl(const account_t *account,
                                  git_scope_t scope);
static int git_configure_gpg_impl(const account_t *account,
                                  git_scope_t scope);
static int build_expected_ssh_command_with_program(
    const account_t *account, const char *ssh_path, char *command,
    size_t command_size, char *expanded_path, size_t expanded_path_size);

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

static const char *git_scope_diagnostic_label(git_scope_t scope) {
    const char *flag = git_scope_to_flag(scope);
    return flag ? flag : "(invalid scope)";
}

typedef struct {
    const char *key;
    char value[GIT_CFG_VALUE_MAX];
    bool present;
    bool implicit;
    bool value_unknown; /* present, but the value exceeded value[] (a foreign
                         * writer): restore must neither write back a
                         * truncated copy nor --unset the user's original. */
} git_kv_t;

#define GIT_MANAGED_KEY_COUNT 10
static const char *const g_managed_keys[GIT_MANAGED_KEY_COUNT] = {
    GIT_CONFIG_USER_NAME, GIT_CONFIG_USER_EMAIL, GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN, GIT_CONFIG_GPG_PROGRAM,
    GIT_CONFIG_CORE_SSHCOMMAND, GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM, GIT_CONFIG_GPG_X509_PROGRAM,
    GIT_CONFIG_GPG_SSH_PROGRAM
};

static const char *const g_gpg_program_keys[] = {
    GIT_CONFIG_GPG_PROGRAM,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM,
    GIT_CONFIG_GPG_X509_PROGRAM,
    GIT_CONFIG_GPG_SSH_PROGRAM
};

#define GIT_GPG_FORMAT_OPENPGP "openpgp"
/* Git's complete listing includes arbitrary unrelated user configuration, so
 * inspection grows well beyond the managed-value representation. Bound both
 * consumers at 8 MiB: over 30 times the maximum combined size of all managed
 * values, while preventing an attacker-controlled config/include graph from
 * driving unbounded allocation in this single-purpose CLI. */
#define GIT_INSPECTION_INITIAL_BYTES (16U * 1024U)
#define GIT_INSPECTION_MAX_BYTES (8U * 1024U * 1024U)
static void git_init_kv(git_kv_t out[GIT_MANAGED_KEY_COUNT]);

typedef struct {
    char **values;
    size_t count;
    size_t capacity;
    /* Rollback progress is retained across retry. Before restore starts, the
     * transaction owns the sealed post-image. After a successful unset, it
     * owns exactly the prefix of this before-image that has been re-added. */
    size_t restore_prefix;
    bool restore_started;
    bool restored;
} git_snapshot_key_t;

typedef struct {
    git_snapshot_key_t keys[GIT_MANAGED_KEY_COUNT];
} git_scope_snapshot_t;

/* A rollback destination is more than its managed values. Keep the resolved
 * configuration namespace and repository generation pinned for the lifetime
 * of the transaction. The sealed config descriptor identifies the exact
 * post-image that rollback is allowed to replace; Git's normal lock+rename
 * writes legitimately change that file inode before seal, so it is pinned at
 * seal rather than mistaken for an immutable snapshot-time inode. */
typedef struct {
    git_scope_t scope;
    char logical_path[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    char parent[MAX_PATH_LEN];
    char leaf[NAME_MAX + 1U];
    int parent_fd;
    struct stat parent_stat;
    char repository_path[MAX_PATH_LEN];
    int repository_fd;
    struct stat repository_stat;
    bool repository_present;
    int post_config_fd;
    struct stat post_config_stat;
    unsigned char *post_config_data;
    size_t post_config_length;
    bool post_config_identity_valid;
    bool post_config_present;
    bool valid;
} git_scope_generation_t;

typedef struct {
    git_scope_t scope;
    bool local_also;
    bool worktree_also;
    git_scope_snapshot_t primary;
    git_scope_snapshot_t local;
    git_scope_snapshot_t worktree;
    git_scope_snapshot_t post_primary;
    git_scope_snapshot_t post_local;
    git_scope_snapshot_t post_worktree;
    git_scope_generation_t primary_generation;
    git_scope_generation_t local_generation;
    git_scope_generation_t worktree_generation;
    uint32_t publication_account_id;
    char publication_account_incarnation[ACCOUNT_INCARNATION_LEN];
    bool publication_owner_bound;
    bool publication_owner_tainted;
    bool publication_full_image_written;
    bool postimage_sealed;
    bool valid;
    bool restore_incomplete;
} git_config_snapshot_t;

static git_config_snapshot_t g_git_snapshot;
static unsigned int g_git_account_write_depth;
static void git_snapshot_clear(git_config_snapshot_t *snapshot);
static int git_scope_generation_capture(git_scope_t scope,
                                        git_scope_generation_t *generation);
static int git_scope_generation_verify_namespace(
    const git_scope_generation_t *generation);
static int git_scope_generation_pin_post_config(
    git_scope_generation_t *generation);
static int git_scope_generation_verify_post_config(
    const git_scope_generation_t *generation);

typedef void *(*git_snapshot_value_malloc_fn)(size_t size);
static git_snapshot_value_malloc_fn g_git_snapshot_value_malloc = malloc;

typedef void (*git_restore_test_hook_fn)(git_scope_t scope);
static git_restore_test_hook_fn g_restore_prelock_hook;
static git_restore_test_hook_fn g_restore_locked_hook;
static git_restore_test_hook_fn g_restore_postpublish_hook;

typedef enum {
    GIT_METADATA_TEST_SOURCE_PIN = 1,
    GIT_METADATA_TEST_STAGE_REVALIDATE
} git_metadata_test_stage_t;
typedef bool (*git_metadata_test_hook_fn)(git_metadata_test_stage_t stage);
static git_metadata_test_hook_fn g_metadata_test_hook;

/* Test seams for deterministic real-Git race coverage. They are deliberately
 * absent from the installed API; tests declare the prototypes locally. */
void git_ops_test_set_restore_prelock_hook(git_restore_test_hook_fn fn);
void git_ops_test_set_restore_locked_hook(git_restore_test_hook_fn fn);
void git_ops_test_set_restore_postpublish_hook(git_restore_test_hook_fn fn);
git_metadata_test_hook_fn git_ops_test_set_metadata_hook(
    git_metadata_test_hook_fn fn);
git_snapshot_value_malloc_fn git_ops_test_set_snapshot_value_malloc_fn(
    git_snapshot_value_malloc_fn fn);
void git_ops_test_set_restore_prelock_hook(git_restore_test_hook_fn fn) {
    g_restore_prelock_hook = fn;
}
void git_ops_test_set_restore_locked_hook(git_restore_test_hook_fn fn) {
    g_restore_locked_hook = fn;
}
void git_ops_test_set_restore_postpublish_hook(git_restore_test_hook_fn fn) {
    g_restore_postpublish_hook = fn;
}
git_metadata_test_hook_fn git_ops_test_set_metadata_hook(
    git_metadata_test_hook_fn fn) {
    git_metadata_test_hook_fn previous = g_metadata_test_hook;
    g_metadata_test_hook = fn;
    return previous;
}
git_snapshot_value_malloc_fn git_ops_test_set_snapshot_value_malloc_fn(
    git_snapshot_value_malloc_fn fn) {
    git_snapshot_value_malloc_fn previous = g_git_snapshot_value_malloc;
    g_git_snapshot_value_malloc = fn ? fn : malloc;
    return previous;
}

/* ---- Process-scoped write/snapshot bookkeeping (perf-1,3,4) -------------
 *
 * A single switch used to spawn the same git subprocesses several times over:
 * `git --version` on every init, `git rev-parse --git-dir` from every caller
 * that asked "am I in a repo?", and the GPG keys written twice
 * (git_configure_gpg and gpg_manager's
 * gpg_configure_git_signing). On the interactive switch hot path each exec is
 * a fork+execvp round trip, so these are cached for the process lifetime.
 *
 * Invalidation assumptions (documented deliberately — the caches trade a
 * sliver of staleness for the exec reduction, and only where it cannot change
 * the outcome of a switch):
 *  - The CLI is short-lived and single-threaded. Transaction ownership never
 *    relies on these scalar entries: seal uses exact fresh vectors and restore
 *    rechecks under Git's canonical per-file lock, so an external `git config`
 *    writer is either observed as a conflict or serialized after rollback.
 *  - Repo-ness is keyed by cwd (getcwd is one syscall, not a fork), so a
 *    future chdir cannot be served a stale answer; a .git appearing or
 *    vanishing under an unchanged cwd mid-process is not a supported flow.
 *  - Config bookkeeping can suppress only a duplicate write performed by this
 *    process or an unset that an exact transaction snapshot proved absent.
 *    Public reads always execute Git: a process-lifetime positive read cache
 *    cannot detect another process changing the configuration afterward.
 */
typedef enum {
    CFG_UNKNOWN = 0,  /* nothing cacheable known; always exec */
    CFG_WRITTEN,      /* we set/unset this key ourselves (skip duplicate writes only) */
    CFG_OBSERVED      /* exact snapshot observation; only absence may skip unset */
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

/* Record bookkeeping; a present value too long to retain degrades to
 * CFG_UNKNOWN with present kept TRUE. Never truncate — a truncated value
 * could suppress the wrong operation later. Absence may suppress an unset
 * only when its state proves this process wrote it or an exact transaction
 * snapshot observed it. */
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
    g_git_account_write_depth = 0U;
    memset(g_cfg_cache, 0, sizeof(g_cfg_cache));
    memset(&g_repo_cache, 0, sizeof(g_repo_cache));
    g_git_validated = false;
    g_restore_prelock_hook = NULL;
    g_restore_locked_hook = NULL;
    g_restore_postpublish_hook = NULL;
    g_metadata_test_hook = NULL;
    g_git_snapshot_value_malloc = malloc;
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

/* Git gives GIT_SSH_COMMAND higher precedence than core.sshCommand. A switch
 * cannot prove its selected SSH identity while that environment override is
 * present, even when the persisted read-back is exact, so every transaction
 * and status entry point fails closed without reflecting the untrusted value
 * into a diagnostic. Presence matters: Git treats an explicitly empty value
 * as an override too and then attempts to execute an empty command.
 *
 * Legacy GIT_SSH is deliberately not rejected. Real-Git precedence tests prove
 * core.sshCommand outranks it; when gitswitch selects SSH, the persisted
 * absolute core.sshCommand therefore remains authoritative. */
static int git_reject_ssh_command_override(void) {
    if (getenv("GIT_SSH_COMMAND") != NULL) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "GIT_SSH_COMMAND overrides Git core.sshCommand; unset it before switching or checking status");
        return -1;
    }
    return 0;
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

static int git_read_direct_worktree_extension(bool *enabled) {
    const char *argv[] = {
        "git", "config", "--local", "--no-includes", "--bool", "--get",
        "extensions.worktreeConfig", NULL
    };
    char canonical[16];
    run_opts_t opts;
    run_result_t result;
    size_t length;
    int rc;

    if (!enabled) return -1;
    *enabled = false;
    memset(canonical, 0, sizeof(canonical));
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = canonical;
    opts.out_size = sizeof(canonical);
    opts.stderr_to_devnull = true;
    rc = run_argv(argv, &opts, &result);
    if (rc != 0) {
        if (result.spawned && result.term_signal == 0 &&
            result.exit_code == 1) {
            return 0;
        }
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot resolve extensions.worktreeConfig before switching");
        return -1;
    }
    if (result.out_truncated || result.out_len >= sizeof(canonical)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid extensions.worktreeConfig Boolean output");
        return -1;
    }
    length = result.out_len;
    if (length > 0 && canonical[length - 1U] == '\n') length--;
    if (length == sizeof("true") - 1U &&
        memcmp(canonical, "true", length) == 0) {
        *enabled = true;
        return 0;
    }
    if (length == sizeof("false") - 1U &&
        memcmp(canonical, "false", length) == 0) {
        return 0;
    }
    set_error(ERR_GIT_CONFIG_FAILED,
              "Git returned a noncanonical extensions.worktreeConfig Boolean");
    return -1;
}

/* Detect whether Git has a distinct worktree configuration store. A populated
 * managed value proves the store directly. An enabled but empty store is
 * detected from the direct common-config extension value so its empty managed
 * vector still participates in snapshot, seal, and rollback. We do not blindly
 * issue --worktree: when extensions.worktreeConfig is disabled, Git aliases
 * --worktree to --local and treating them as independent stores would corrupt
 * snapshot/restore semantics. */
static int git_detect_managed_worktree_scope(bool *present) {
    const char *argv[] = { "git", "config", "--show-scope", "-z", "--list", NULL };
    size_t capacity = GIT_INSPECTION_INITIAL_BYTES;
    char *list = NULL;
    size_t list_len = 0;
    size_t pos = 0;
    bool extension_record_seen = false;

    if (!present) return -1;
    *present = false;
    if (!git_is_repository()) return 0;

    list = malloc(capacity);
    if (!list) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory inspecting Git worktree configuration");
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
            free(list);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot inspect Git worktree configuration before switching");
            return -1;
        }
        if (!res.out_truncated) {
            if (res.out_len >= capacity) {
                free(list);
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Invalid Git worktree scope capture length");
                return -1;
            }
            list_len = res.out_len;
            break;
        }
        if (capacity >= GIT_INSPECTION_MAX_BYTES) {
            free(list);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git worktree scope listing exceeds %u bytes",
                      (unsigned)GIT_INSPECTION_MAX_BYTES);
            return -1;
        }
        {
            size_t grown_capacity = capacity * 2U;
            char *grown;
            if (grown_capacity > GIT_INSPECTION_MAX_BYTES) {
                grown_capacity = GIT_INSPECTION_MAX_BYTES;
            }
            grown = realloc(list, grown_capacity);
            if (!grown) {
                free(list);
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory growing Git worktree scope capture");
                return -1;
            }
            list = grown;
            capacity = grown_capacity;
        }
    }

    while (pos < list_len) {
        size_t scope_start = pos;
        while (pos < list_len && list[pos] != '\0') pos++;
        if (pos >= list_len) goto malformed;
        size_t scope_len = pos - scope_start;
        pos++;

        size_t record_start = pos;
        while (pos < list_len && list[pos] != '\0') pos++;
        if (pos >= list_len) goto malformed;
        size_t record_len = pos - record_start;
        pos++;

        const char *record = list + record_start;
        const char *newline = memchr(record, '\n', record_len);
        size_t key_len = newline ? (size_t)(newline - record) : record_len;
        if (key_len == sizeof("extensions.worktreeConfig") - 1U &&
            strncasecmp(record, "extensions.worktreeConfig", key_len) == 0) {
            extension_record_seen = true;
        }
        if (scope_len != 8 ||
            memcmp(list + scope_start, "worktree", 8) != 0) {
            continue;
        }
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
            size_t managed_len = strlen(g_managed_keys[i]);
            if (key_len == managed_len &&
                strncasecmp(record, g_managed_keys[i], key_len) == 0) {
                *present = true;
                free(list);
                return 0;
            }
        }
    }
    free(list);
    if (extension_record_seen) {
        return git_read_direct_worktree_extension(present);
    }
    return 0;

malformed:
    free(list);
    set_error(ERR_GIT_CONFIG_FAILED,
              "Malformed Git scope listing while checking worktree configuration");
    return -1;
}

static void git_init_kv(git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        out[i].key = g_managed_keys[i];
        out[i].present = false;
        out[i].implicit = false;
        out[i].value_unknown = false;
        out[i].value[0] = '\0';
    }
}

/* Transaction snapshots are exact ordered vectors, not last-value-wins
 * scalars. Git permits repeated values for every config key; collapsing those
 * values changes both meaning and rollback fidelity (AR-07 M25). */
#define GIT_SNAPSHOT_INITIAL_BYTES (16U * 1024U)
#define GIT_SNAPSHOT_MAX_BYTES (8U * 1024U * 1024U)

static void git_snapshot_key_clear(git_snapshot_key_t *key) {
    if (!key) return;
    for (size_t i = 0; i < key->count; i++) free(key->values[i]);
    free(key->values);
    memset(key, 0, sizeof(*key));
}

static void git_scope_snapshot_clear(git_scope_snapshot_t *scope) {
    if (!scope) return;
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        git_snapshot_key_clear(&scope->keys[i]);
    }
    memset(scope, 0, sizeof(*scope));
}

static void git_scope_generation_clear(git_scope_generation_t *generation) {
    if (!generation) return;
    if (generation->valid && generation->parent_fd >= 0) {
        (void)close(generation->parent_fd);
    }
    if (generation->valid && generation->repository_fd >= 0) {
        (void)close(generation->repository_fd);
    }
    if (generation->post_config_identity_valid &&
        generation->post_config_present &&
        generation->post_config_fd >= 0) {
        (void)close(generation->post_config_fd);
    }
    if (generation->post_config_data) {
        secure_zero_memory(generation->post_config_data,
                           generation->post_config_length);
        free(generation->post_config_data);
    }
    memset(generation, 0, sizeof(*generation));
    generation->parent_fd = -1;
    generation->repository_fd = -1;
    generation->post_config_fd = -1;
}

static void git_snapshot_clear(git_config_snapshot_t *snapshot) {
    if (!snapshot) return;
    git_scope_snapshot_clear(&snapshot->primary);
    git_scope_snapshot_clear(&snapshot->local);
    git_scope_snapshot_clear(&snapshot->worktree);
    git_scope_snapshot_clear(&snapshot->post_primary);
    git_scope_snapshot_clear(&snapshot->post_local);
    git_scope_snapshot_clear(&snapshot->post_worktree);
    git_scope_generation_clear(&snapshot->primary_generation);
    git_scope_generation_clear(&snapshot->local_generation);
    git_scope_generation_clear(&snapshot->worktree_generation);
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
    copy = g_git_snapshot_value_malloc(value_len + 1U);
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

static int git_scope_snapshot_clone(const git_scope_snapshot_t *source,
                                    git_scope_snapshot_t *dest) {
    git_scope_snapshot_t next;

    memset(&next, 0, sizeof(next));
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        for (size_t j = 0; j < source->keys[i].count; j++) {
            const char *value = source->keys[i].values[j];
            if (git_snapshot_key_append(&next.keys[i], value,
                                        strlen(value)) != 0) {
                git_scope_snapshot_clear(&next);
                return -1;
            }
        }
    }
    *dest = next;
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

static bool git_snapshot_key_equal(const git_snapshot_key_t *a,
                                   const git_snapshot_key_t *b) {
    if (a->count != b->count) return false;
    for (size_t i = 0; i < a->count; i++) {
        if (strcmp(a->values[i], b->values[i]) != 0) return false;
    }
    return true;
}

static bool git_scope_snapshot_equal(const git_scope_snapshot_t *a,
                                     const git_scope_snapshot_t *b) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (!git_snapshot_key_equal(&a->keys[i], &b->keys[i])) return false;
    }
    return true;
}

static int git_scope_snapshot_difference_count(
    const git_scope_snapshot_t *expected,
    const git_scope_snapshot_t *observed) {
    int differences = 0;
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (!git_snapshot_key_equal(&expected->keys[i],
                                    &observed->keys[i])) {
            differences++;
        }
    }
    return differences;
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
            cfg_cache_store(s, (int)i, CFG_OBSERVED, false, "");
        } else if (key->count == 1) {
            cfg_cache_store(s, (int)i, CFG_OBSERVED, true, key->values[0]);
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
    /* The ordered vector is in-progress until every --add completes. Do not
     * leave the preceding successful --unset cached as proven absence. */
    cfg_cache_store(cfg_scope_index(scope), cfg_key_index(key),
                    CFG_UNKNOWN, true, "");
    return 0;
}

typedef struct {
    int conflicts;
    int generation_conflicts;
    int write_failures;
} git_restore_result_t;

/* Before its first rollback write, a key is owned only while it still equals
 * the sealed post-image. Once the checked unset succeeds, the owned state is
 * exactly the prefix of the before-image whose --add operations succeeded.
 * Comparing that prefix on retry distinguishes our own partial restore from a
 * later writer without weakening AR-07's retry guarantee. */
static bool git_restore_key_still_owned(const git_snapshot_key_t *current,
                                        const git_snapshot_key_t *before,
                                        const git_snapshot_key_t *post) {
    if (!before->restore_started) {
        return git_snapshot_key_equal(current, post);
    }
    if (current->count != before->restore_prefix) return false;
    for (size_t i = 0; i < before->restore_prefix; i++) {
        if (strcmp(current->values[i], before->values[i]) != 0) return false;
    }
    return true;
}

/* Each not-yet-complete key is compare-checked, then rebuilt as checked
 * unset-all plus ordered adds. Conflicts are preserved byte-for-byte and a
 * failed key remains armed with exact prefix progress for retry. Completed
 * keys are skipped on later attempts, so changes made after that key was
 * successfully rolled back are outside this transaction and survive. */
static git_restore_result_t git_restore_scope_snapshot(
    git_scope_t scope, git_scope_snapshot_t *before,
    const git_scope_snapshot_t *post,
    const git_scope_snapshot_t *current) {
    git_restore_result_t result = {0};

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        git_snapshot_key_t *key = &before->keys[i];
        bool failed = false;

        if (key->restored) {
            /* This key is no longer transaction-owned. If a later writer
             * changed it after the successful partial rollback, invalidate
             * our scalar write cache while deliberately leaving the value
             * untouched. */
            if (!git_snapshot_key_equal(&current->keys[i], key)) {
                cfg_cache_store(cfg_scope_index(scope), (int)i, CFG_UNKNOWN,
                                current->keys[i].count != 0, "");
            }
            continue;
        }
        if (!git_restore_key_still_owned(&current->keys[i], key,
                                         &post->keys[i])) {
            const char *scope_name = git_scope_to_flag(scope);

            log_warning("Rollback preserved externally changed Git config %s (%s)",
                        g_managed_keys[i],
                        scope_name ? scope_name : "invalid scope");
            cfg_cache_store(cfg_scope_index(scope), (int)i, CFG_UNKNOWN,
                            current->keys[i].count != 0, "");
            result.conflicts++;
            continue;
        }
        if (git_unset_config_value_impl(g_managed_keys[i], scope, true) != 0) {
            log_warning("Rollback failed to clear %s: %s",
                        g_managed_keys[i], get_last_error()->message);
            result.write_failures++;
            continue;
        }
        key->restore_started = true;
        key->restore_prefix = 0;
        for (size_t j = 0; j < key->count; j++) {
            if (git_add_snapshot_value(scope, g_managed_keys[i],
                                       key->values[j]) != 0) {
                log_warning("Rollback failed to restore %s: %s",
                            g_managed_keys[i], get_last_error()->message);
                failed = true;
                break;
            }
            key->restore_prefix = j + 1U;
        }
        if (failed) {
            result.write_failures++;
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
    return result;
}

typedef struct {
    char logical_path[MAX_PATH_LEN];
    char logical_parent[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    char parent[MAX_PATH_LEN];
    char leaf[NAME_MAX + 1U];
    char lock_leaf[NAME_MAX + sizeof(".lock")];
    char lock_path[MAX_PATH_LEN];
    char stage_leaf[96];
    char stage_path[MAX_PATH_LEN];
    int dir_fd;
    int original_fd;
    int published_fd;
    struct stat parent_stat;
    struct stat logical_stat;
    struct stat original_stat;
    struct stat published_stat;
    unsigned char *original_data;
    size_t original_length;
    unsigned char *published_data;
    size_t published_length;
    mode_t target_mode;
    uid_t target_uid;
    gid_t target_gid;
    bool logical_present;
    bool logical_final_symlink;
    bool original_present;
    bool original_witness_valid;
    bool lock_created;
    bool stage_created;
    bool published;
    bool published_witness_valid;
    bool generation_conflict;
} git_scope_lock_t;

static int git_absolute_path(const char *path, char *out, size_t out_size) {
    char cwd[MAX_PATH_LEN];

    if (!path || !path[0] || !out || out_size == 0) return -1;
    if (path[0] == '/') {
        return safe_strncpy(out, path, out_size);
    }
    if (!getcwd(cwd, sizeof(cwd)) ||
        (size_t)snprintf(out, out_size, "%s/%s", cwd, path) >= out_size) {
        return -1;
    }
    return 0;
}

static int git_path_presence(const char *path, bool *present) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        *present = true;
        return 0;
    }
    if (errno == ENOENT) {
        *present = false;
        return 0;
    }
    set_system_error(ERR_GIT_CONFIG_FAILED,
                     "Cannot inspect Git configuration candidate: %s", path);
    return -1;
}

/* Match Git's --global write selection: GIT_CONFIG_GLOBAL is authoritative;
 * otherwise ~/.gitconfig wins when present, then the XDG file when present,
 * with ~/.gitconfig as the create target when neither exists. */
static int git_resolve_global_config_path(char *out, size_t out_size) {
    const char *override = getenv("GIT_CONFIG_GLOBAL");
    const char *home = getenv("HOME");
    const char *xdg = getenv("XDG_CONFIG_HOME");
    char home_path[MAX_PATH_LEN] = "";
    char xdg_path[MAX_PATH_LEN] = "";
    char candidate[MAX_PATH_LEN];
    bool home_present = false;
    bool xdg_present = false;

    if (override) {
        if (!override[0] || git_absolute_path(override, out, out_size) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Invalid GIT_CONFIG_GLOBAL path for rollback");
            return -1;
        }
        return 0;
    }
    if (home && home[0] &&
        (size_t)snprintf(candidate, sizeof(candidate), "%s/.gitconfig",
                         home) < sizeof(candidate) &&
        git_absolute_path(candidate, home_path, sizeof(home_path)) != 0) {
        home_path[0] = '\0';
    }
    if (xdg && xdg[0]) {
        if ((size_t)snprintf(candidate, sizeof(candidate), "%s/git/config",
                             xdg) < sizeof(candidate) &&
            git_absolute_path(candidate, xdg_path, sizeof(xdg_path)) != 0) {
            xdg_path[0] = '\0';
        }
    } else if (home && home[0]) {
        if ((size_t)snprintf(candidate, sizeof(candidate),
                             "%s/.config/git/config", home) <
                sizeof(candidate) &&
            git_absolute_path(candidate, xdg_path, sizeof(xdg_path)) != 0) {
            xdg_path[0] = '\0';
        }
    }
    if ((home_path[0] &&
         git_path_presence(home_path, &home_present) != 0) ||
        (xdg_path[0] && git_path_presence(xdg_path, &xdg_present) != 0)) {
        return -1;
    }
    if (home_present) {
        return safe_strncpy(out, home_path, out_size);
    }
    if (xdg_present) {
        return safe_strncpy(out, xdg_path, out_size);
    }
    if (home_path[0]) return safe_strncpy(out, home_path, out_size);
    if (xdg_path[0]) return safe_strncpy(out, xdg_path, out_size);
    set_error(ERR_GIT_CONFIG_FAILED,
              "Cannot resolve the global Git configuration path");
    return -1;
}

static int git_query_single_path(const char *const argv[], char *out,
                                 size_t out_size) {
    char raw[MAX_PATH_LEN];
    run_opts_t opts;
    run_result_t result;
    size_t length;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = raw;
    opts.out_size = sizeof(raw);
    opts.merge_stderr = true;
    if (run_argv(argv, &opts, &result) != 0 || result.out_truncated ||
        result.out_len == 0 || result.out_len >= sizeof(raw)) {
        return -1;
    }
    length = result.out_len;
    if (raw[length - 1U] == '\n') raw[--length] = '\0';
    if (length == 0 || memchr(raw, '\n', length) != NULL ||
        git_absolute_path(raw, out, out_size) != 0) {
        return -1;
    }
    return 0;
}

static int git_resolve_scope_config_path(git_scope_t scope, char *out,
                                         size_t out_size) {
    const char *override;

    if (scope == GIT_SCOPE_GLOBAL) {
        return git_resolve_global_config_path(out, out_size);
    }
    if (scope == GIT_SCOPE_SYSTEM) {
        const char *const argv[] = {
            "git", "var", "GIT_CONFIG_SYSTEM", NULL
        };
        override = getenv("GIT_CONFIG_SYSTEM");
        if (override) {
            if (!override[0] ||
                git_absolute_path(override, out, out_size) != 0) {
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Invalid GIT_CONFIG_SYSTEM path for rollback");
                return -1;
            }
            return 0;
        }
        if (git_query_single_path(argv, out, out_size) == 0) return 0;
        if (git_absolute_path("/etc/gitconfig", out, out_size) == 0) return 0;
    } else if (scope == GIT_SCOPE_LOCAL ||
               scope == GIT_SCOPE_WORKTREE_INTERNAL) {
        const char *leaf = scope == GIT_SCOPE_LOCAL
                               ? "config" : "config.worktree";
        const char *const absolute_argv[] = {
            "git", "rev-parse", "--path-format=absolute", "--git-path",
            leaf, NULL
        };
        const char *const fallback_argv[] = {
            "git", "rev-parse", "--git-path", leaf, NULL
        };
        if (git_query_single_path(absolute_argv, out, out_size) == 0 ||
            git_query_single_path(fallback_argv, out, out_size) == 0) {
            return 0;
        }
    }
    set_error(ERR_GIT_CONFIG_FAILED,
              "Cannot resolve %s Git configuration path for rollback",
              git_scope_to_flag(scope));
    return -1;
}

static bool git_same_file_version(const struct stat *left,
                                  const struct stat *right) {
    if (left->st_dev != right->st_dev || left->st_ino != right->st_ino ||
        left->st_mode != right->st_mode || left->st_uid != right->st_uid ||
        left->st_gid != right->st_gid || left->st_size != right->st_size) {
        return false;
    }
#if defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

/* A retained descriptor makes dev+ino an unambiguous file generation. Keep
 * the link count strict so an external alias can never inherit rollback
 * ownership. Omit only ctime from retry matching because merely renaming that
 * same pinned inode out of the way and reinstating it changes ctime without
 * changing the generation or content that the descriptor names. */
static bool git_same_pinned_file_generation(const struct stat *left,
                                            const struct stat *right) {
    if (left->st_dev != right->st_dev || left->st_ino != right->st_ino ||
        left->st_mode != right->st_mode || left->st_uid != right->st_uid ||
        left->st_gid != right->st_gid || left->st_size != right->st_size ||
        left->st_nlink != right->st_nlink) {
        return false;
    }
#if defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static bool git_same_file_ctime(const struct stat *left,
                                const struct stat *right) {
#if defined(__APPLE__)
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static bool git_same_file_observation(const struct stat *left,
                                      const struct stat *right) {
    return git_same_file_version(left, right) &&
           left->st_nlink == right->st_nlink;
}

/* FreeBSD UFS can expose a rename/link ctime update only after a later sync.
 * This shape is never sufficient by itself: callers may admit it only after
 * an exact byte witness proves that the pinned regular file is unchanged. */
static bool git_metadata_ctime_only_change(const struct stat *before,
                                           const struct stat *after) {
    return git_same_pinned_file_generation(before, after) &&
           before->st_nlink == after->st_nlink &&
           !git_same_file_ctime(before, after) && S_ISREG(after->st_mode);
}

static bool git_pread_full(int fd, unsigned char *buffer, size_t length,
                           off_t offset) {
    size_t total = 0;

    while (total < length) {
        ssize_t got = pread(fd, buffer + total, length - total,
                            offset + (off_t)total);
        if (got > 0) {
            total += (size_t)got;
        } else if (got < 0 && errno == EINTR) {
            continue;
        } else {
            if (got == 0) errno = EAGAIN;
            return false;
        }
    }
    return true;
}

static bool git_fd_matches_bytes(int fd, const unsigned char *expected,
                                 size_t expected_length) {
    unsigned char buffer[4096];
    size_t offset = 0;

    while (offset < expected_length) {
        size_t wanted = expected_length - offset;
        ssize_t got;

        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        do {
            got = pread(fd, buffer, wanted, (off_t)offset);
        } while (got < 0 && errno == EINTR);
        if (got <= 0 || memcmp(buffer, expected + offset, (size_t)got) != 0) {
            if (got >= 0) errno = EAGAIN;
            return false;
        }
        offset += (size_t)got;
    }
    for (;;) {
        ssize_t got = pread(fd, buffer, 1, (off_t)offset);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return false;
        if (got != 0) errno = EAGAIN;
        return got == 0;
    }
}

static int git_capture_fd_bytes_exact(int fd, unsigned char **data,
                                      size_t *length,
                                      struct stat *identity) {
    unsigned char *captured = NULL;

    if (!data || !length || !identity) {
        errno = EINVAL;
        return -1;
    }
    *data = NULL;
    *length = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        struct stat before;
        struct stat after;
        size_t size;

        if (fstat(fd, &before) != 0) return -1;
        if (!S_ISREG(before.st_mode)) {
            errno = EINVAL;
            return -1;
        }
        if (before.st_size < 0 ||
            (uintmax_t)before.st_size > GIT_SNAPSHOT_MAX_BYTES) {
            errno = EFBIG;
            return -1;
        }
        size = (size_t)before.st_size;
        captured = size ? malloc(size) : NULL;
        if (size && !captured) return -1;
        if ((size && !git_pread_full(fd, captured, size, 0)) ||
            !git_fd_matches_bytes(fd, captured, size) ||
            fstat(fd, &after) != 0) {
            if (captured) {
                secure_zero_memory(captured, size);
                free(captured);
                captured = NULL;
            }
            return -1;
        }
        if (git_same_file_observation(&before, &after)) {
            *data = captured;
            *length = size;
            *identity = after;
            return 0;
        }
        if (captured) {
            secure_zero_memory(captured, size);
            free(captured);
            captured = NULL;
        }
        if (attempt != 0 ||
            !git_metadata_ctime_only_change(&before, &after)) {
            errno = EAGAIN;
            return -1;
        }
    }
    errno = EAGAIN;
    return -1;
}

static bool git_fd_matches_witness_stable(
    int fd, const struct stat *baseline, const unsigned char *data,
    size_t length, struct stat *current) {
    for (int attempt = 0; attempt < 2; attempt++) {
        struct stat before;
        struct stat after;

        if (fstat(fd, &before) != 0 ||
            !git_same_pinned_file_generation(baseline, &before) ||
            !git_fd_matches_bytes(fd, data, length) ||
            fstat(fd, &after) != 0 ||
            !git_same_pinned_file_generation(baseline, &after)) {
            return false;
        }
        if (git_same_file_observation(&before, &after)) {
            if (current) *current = after;
            return true;
        }
        if (attempt != 0 ||
            !git_metadata_ctime_only_change(&before, &after)) {
            errno = EAGAIN;
            return false;
        }
    }
    errno = EAGAIN;
    return false;
}

static bool git_file_at_matches_witness(
    int parent_fd, const char *leaf, int fd, const struct stat *baseline,
    const unsigned char *data, size_t length, struct stat *current) {
    for (int attempt = 0; attempt < 2; attempt++) {
        struct stat fd_before;
        struct stat named_before;
        struct stat fd_after;
        struct stat named_after;

        if (fstat(fd, &fd_before) != 0 ||
            fstatat(parent_fd, leaf, &named_before, AT_SYMLINK_NOFOLLOW) != 0 ||
            !git_same_pinned_file_generation(baseline, &fd_before) ||
            !git_same_pinned_file_generation(baseline, &named_before) ||
            !git_same_pinned_file_generation(&fd_before, &named_before) ||
            !git_fd_matches_bytes(fd, data, length) ||
            fstat(fd, &fd_after) != 0 ||
            fstatat(parent_fd, leaf, &named_after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !git_same_pinned_file_generation(baseline, &fd_after) ||
            !git_same_pinned_file_generation(baseline, &named_after)) {
            return false;
        }
        if (git_same_file_observation(&fd_before, &fd_after) &&
            git_same_file_observation(&fd_after, &named_after)) {
            if (current) *current = fd_after;
            return true;
        }
        if (attempt != 0 ||
            (!git_same_file_observation(&fd_before, &fd_after) &&
             !git_metadata_ctime_only_change(&fd_before, &fd_after)) ||
            (!git_same_file_observation(&fd_after, &named_after) &&
             !git_metadata_ctime_only_change(&fd_after, &named_after))) {
            errno = EAGAIN;
            return false;
        }
    }
    errno = EAGAIN;
    return false;
}

static int git_write_all(int fd, const unsigned char *data, size_t length) {
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int git_scope_lock_resolve_paths(git_scope_t scope,
                                        git_scope_lock_t *lock) {
    char resolved_parent[MAX_PATH_LEN];
    char logical_leaf[NAME_MAX + 1U];
    char *logical_slash;
    char *slash;

    if (git_resolve_scope_config_path(scope, lock->logical_path,
                                      sizeof(lock->logical_path)) != 0) {
        return -1;
    }
    logical_slash = strrchr(lock->logical_path, '/');
    if (!logical_slash || !logical_slash[1] ||
        strlen(logical_slash + 1) > NAME_MAX) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid Git configuration path for rollback: %s",
                  lock->logical_path);
        return -1;
    }
    safe_strncpy(logical_leaf, logical_slash + 1, sizeof(logical_leaf));
    if (logical_slash == lock->logical_path) {
        safe_strncpy(lock->logical_parent, "/",
                     sizeof(lock->logical_parent));
    } else {
        size_t parent_len = (size_t)(logical_slash - lock->logical_path);
        if (parent_len >= sizeof(lock->logical_parent)) return -1;
        memcpy(lock->logical_parent, lock->logical_path, parent_len);
        lock->logical_parent[parent_len] = '\0';
    }
    if (lstat(lock->logical_path, &lock->logical_stat) == 0) {
        lock->logical_present = true;
        lock->logical_final_symlink = S_ISLNK(lock->logical_stat.st_mode);
        if (!realpath(lock->logical_path, lock->path)) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot resolve Git configuration target: %s",
                             lock->logical_path);
            return -1;
        }
    } else if (errno == ENOENT) {
        lock->logical_present = false;
        if (!realpath(lock->logical_parent, resolved_parent) ||
            (size_t)snprintf(lock->path, sizeof(lock->path), "%s/%s",
                             resolved_parent, logical_leaf) >=
                sizeof(lock->path)) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot resolve Git configuration directory: %s",
                             lock->logical_parent);
            return -1;
        }
    } else {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot inspect Git configuration path: %s",
                         lock->logical_path);
        return -1;
    }
    slash = strrchr(lock->path, '/');
    if (!slash || !slash[1] || strlen(slash + 1) > NAME_MAX) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid Git configuration path for rollback: %s",
                  lock->path);
        return -1;
    }
    if (slash == lock->path) {
        safe_strncpy(lock->parent, "/", sizeof(lock->parent));
    } else {
        size_t parent_len = (size_t)(slash - lock->path);
        if (parent_len >= sizeof(lock->parent)) return -1;
        memcpy(lock->parent, lock->path, parent_len);
        lock->parent[parent_len] = '\0';
    }
    safe_strncpy(lock->leaf, slash + 1, sizeof(lock->leaf));
    if ((size_t)snprintf(lock->lock_leaf, sizeof(lock->lock_leaf), "%s.lock",
                         lock->leaf) >= sizeof(lock->lock_leaf) ||
        (size_t)snprintf(lock->lock_path, sizeof(lock->lock_path), "%s/%s",
                         lock->parent, lock->lock_leaf) >=
            sizeof(lock->lock_path)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git configuration lock path is too long");
        return -1;
    }
    return 0;
}

static bool git_same_object_identity(const struct stat *left,
                                     const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           ((left->st_mode & S_IFMT) == (right->st_mode & S_IFMT));
}

static int git_dup_cloexec(int fd) {
#if defined(F_DUPFD_CLOEXEC)
    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate >= 0 || errno != EINVAL) return duplicate;
#endif
    {
        int fallback_duplicate = dup(fd);
        if (fallback_duplicate < 0) return -1;
        if (fcntl(fallback_duplicate, F_SETFD, FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            (void)close(fallback_duplicate);
            errno = saved_errno;
            return -1;
        }
        return fallback_duplicate;
    }
}

static int git_resolve_repository_generation_path(char *out,
                                                  size_t out_size) {
    const char *const top_absolute[] = {
        "git", "rev-parse", "--path-format=absolute", "--show-toplevel",
        NULL
    };
    const char *const top_fallback[] = {
        "git", "rev-parse", "--show-toplevel", NULL
    };
    const char *const gitdir_absolute[] = {
        "git", "rev-parse", "--absolute-git-dir", NULL
    };
    const char *const gitdir_fallback[] = {
        "git", "rev-parse", "--git-dir", NULL
    };
    char candidate[MAX_PATH_LEN];
    char canonical[MAX_PATH_LEN];

    if ((git_query_single_path(top_absolute, candidate,
                               sizeof(candidate)) == 0 ||
         git_query_single_path(top_fallback, candidate,
                               sizeof(candidate)) == 0 ||
         git_query_single_path(gitdir_absolute, candidate,
                               sizeof(candidate)) == 0 ||
         git_query_single_path(gitdir_fallback, candidate,
                               sizeof(candidate)) == 0) &&
        realpath(candidate, canonical) != NULL &&
        safe_strncpy(out, canonical, out_size) == 0) {
        return 0;
    }
    set_error(ERR_GIT_CONFIG_FAILED,
              "Cannot resolve repository generation for Git rollback");
    return -1;
}

static int git_scope_generation_verify_namespace_resolved(
    const git_scope_generation_t *generation,
    const git_scope_lock_t *resolved) {
    char repository_path[MAX_PATH_LEN];
    int live_parent_fd = -1;
    int live_repository_fd = -1;
    struct stat pinned_parent;
    struct stat live_parent;
    struct stat pinned_repository;
    struct stat live_repository;
    bool matches = false;

    if (!generation || !generation->valid || !resolved) return 0;
    if (generation->scope != GIT_SCOPE_LOCAL &&
        generation->scope != GIT_SCOPE_GLOBAL &&
        generation->scope != GIT_SCOPE_SYSTEM &&
        generation->scope != GIT_SCOPE_WORKTREE_INTERNAL) {
        goto changed;
    }
    if (strcmp(generation->logical_path, resolved->logical_path) != 0 ||
        strcmp(generation->path, resolved->path) != 0 ||
        strcmp(generation->parent, resolved->parent) != 0 ||
        strcmp(generation->leaf, resolved->leaf) != 0 ||
        fstat(generation->parent_fd, &pinned_parent) != 0 ||
        !git_same_object_identity(&generation->parent_stat, &pinned_parent)) {
        goto changed;
    }
    live_parent_fd = open(resolved->parent,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (live_parent_fd < 0 || fstat(live_parent_fd, &live_parent) != 0 ||
        !git_same_object_identity(&generation->parent_stat, &live_parent)) {
        goto changed;
    }
    if (generation->repository_present) {
        if (fstat(generation->repository_fd, &pinned_repository) != 0 ||
            !git_same_object_identity(&generation->repository_stat,
                                      &pinned_repository) ||
            git_resolve_repository_generation_path(repository_path,
                                                   sizeof(repository_path)) != 0 ||
            strcmp(repository_path, generation->repository_path) != 0) {
            goto changed;
        }
        live_repository_fd = open(
            repository_path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (live_repository_fd < 0 ||
            fstat(live_repository_fd, &live_repository) != 0 ||
            !git_same_object_identity(&generation->repository_stat,
                                      &live_repository)) {
            goto changed;
        }
    }
    matches = true;

changed:
    if (live_parent_fd >= 0) (void)close(live_parent_fd);
    if (live_repository_fd >= 0) (void)close(live_repository_fd);
    if (!matches) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback destination generation changed for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }
    return 0;
}

static int git_scope_generation_verify_namespace(
    const git_scope_generation_t *generation) {
    git_scope_lock_t resolved;

    if (!generation || !generation->valid) return 0;
    memset(&resolved, 0, sizeof(resolved));
    resolved.dir_fd = -1;
    if (git_scope_lock_resolve_paths(generation->scope, &resolved) != 0 ||
        git_scope_generation_verify_namespace_resolved(generation,
                                                       &resolved) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback destination generation changed for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }
    return 0;
}

static int git_scope_generation_capture(git_scope_t scope,
                                        git_scope_generation_t *generation) {
    git_scope_lock_t resolved;

    if (!generation) return -1;
    memset(generation, 0, sizeof(*generation));
    generation->parent_fd = -1;
    generation->repository_fd = -1;
    generation->post_config_fd = -1;
    memset(&resolved, 0, sizeof(resolved));
    resolved.dir_fd = -1;
    if (git_scope_lock_resolve_paths(scope, &resolved) != 0) return -1;
    generation->scope = scope;
    safe_strncpy(generation->logical_path, resolved.logical_path,
                 sizeof(generation->logical_path));
    safe_strncpy(generation->path, resolved.path,
                 sizeof(generation->path));
    safe_strncpy(generation->parent, resolved.parent,
                 sizeof(generation->parent));
    safe_strncpy(generation->leaf, resolved.leaf,
                 sizeof(generation->leaf));
    generation->parent_fd = open(
        generation->parent,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generation->parent_fd < 0 ||
        fstat(generation->parent_fd, &generation->parent_stat) != 0 ||
        !S_ISDIR(generation->parent_stat.st_mode)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot pin Git configuration generation for %s",
                  git_scope_diagnostic_label(scope));
        if (generation->parent_fd >= 0) {
            (void)close(generation->parent_fd);
            generation->parent_fd = -1;
        }
        return -1;
    }
    generation->valid = true;
    if (scope == GIT_SCOPE_LOCAL ||
        scope == GIT_SCOPE_WORKTREE_INTERNAL) {
        if (git_resolve_repository_generation_path(
                generation->repository_path,
                sizeof(generation->repository_path)) != 0) {
            git_scope_generation_clear(generation);
            return -1;
        }
        generation->repository_fd = open(
            generation->repository_path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (generation->repository_fd < 0 ||
            fstat(generation->repository_fd,
                  &generation->repository_stat) != 0 ||
            !S_ISDIR(generation->repository_stat.st_mode)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot pin repository generation for Git rollback");
            git_scope_generation_clear(generation);
            return -1;
        }
        generation->repository_present = true;
    }
    if (git_scope_generation_verify_namespace_resolved(generation,
                                                       &resolved) != 0) {
        git_scope_generation_clear(generation);
        return -1;
    }
    return 0;
}

static int git_scope_generation_pin_post_config_pinned(
    git_scope_generation_t *generation) {
    struct stat named;
    struct stat opened;
    struct stat captured;
    struct stat named_after;
    unsigned char *post_config_data = NULL;
    size_t post_config_length = 0;
    int config_fd = -1;
    bool present;

    if (!generation || !generation->valid) return 0;
    if (fstatat(generation->parent_fd, generation->leaf, &named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        present = true;
        if (!S_ISREG(named.st_mode)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot pin non-regular Git post-image for %s",
                      git_scope_diagnostic_label(generation->scope));
            return -1;
        }
        config_fd = openat(generation->parent_fd, generation->leaf,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (config_fd < 0 || fstat(config_fd, &opened) != 0 ||
            !git_same_file_observation(&named, &opened) ||
            git_capture_fd_bytes_exact(config_fd, &post_config_data,
                                       &post_config_length, &captured) != 0 ||
            (!git_same_file_observation(&opened, &captured) &&
             !git_metadata_ctime_only_change(&opened, &captured)) ||
            fstatat(generation->parent_fd, generation->leaf, &named_after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !git_same_file_observation(&captured, &named_after)) {
            if (config_fd >= 0) (void)close(config_fd);
            if (post_config_data) {
                secure_zero_memory(post_config_data, post_config_length);
                free(post_config_data);
            }
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git post-image changed while it was being pinned for %s",
                      git_scope_diagnostic_label(generation->scope));
            return -1;
        }
        opened = captured;
    } else if (errno == ENOENT) {
        present = false;
        memset(&opened, 0, sizeof(opened));
    } else {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot inspect Git post-image for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }
    if (generation->post_config_identity_valid &&
        generation->post_config_present &&
        generation->post_config_fd >= 0) {
        (void)close(generation->post_config_fd);
    }
    if (generation->post_config_data) {
        secure_zero_memory(generation->post_config_data,
                           generation->post_config_length);
        free(generation->post_config_data);
    }
    generation->post_config_fd = config_fd;
    generation->post_config_stat = opened;
    generation->post_config_data = post_config_data;
    generation->post_config_length = post_config_length;
    generation->post_config_present = present;
    generation->post_config_identity_valid = true;
    return 0;
}

static int git_scope_generation_pin_post_config(
    git_scope_generation_t *generation) {
    if (git_scope_generation_verify_namespace(generation) != 0) return -1;
    return git_scope_generation_pin_post_config_pinned(generation);
}

static int git_scope_generation_adopt_published_config(
    git_scope_generation_t *generation, git_scope_lock_t *lock) {
    struct stat pinned;

    if (!generation || !generation->valid ||
        !generation->post_config_identity_valid) {
        return 0;
    }
    if (!lock || !lock->published || lock->published_fd < 0 ||
        !lock->published_witness_valid ||
        !git_fd_matches_witness_stable(
            lock->published_fd, &lock->published_stat,
            lock->published_data, lock->published_length, &pinned)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot retain the installed Git rollback generation for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }

    if (generation->post_config_present && generation->post_config_fd >= 0) {
        (void)close(generation->post_config_fd);
    }
    if (generation->post_config_data) {
        secure_zero_memory(generation->post_config_data,
                           generation->post_config_length);
        free(generation->post_config_data);
    }
    generation->post_config_fd = lock->published_fd;
    lock->published_fd = -1;
    generation->post_config_stat = pinned;
    generation->post_config_data = lock->published_data;
    generation->post_config_length = lock->published_length;
    lock->published_data = NULL;
    lock->published_length = 0;
    lock->published_witness_valid = false;
    generation->post_config_present = true;
    generation->post_config_identity_valid = true;

    if (!git_file_at_matches_witness(
            generation->parent_fd, generation->leaf,
            generation->post_config_fd, &generation->post_config_stat,
            generation->post_config_data, generation->post_config_length,
            NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback generation changed immediately after publication for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }
    return 0;
}

static int git_scope_generation_verify_post_config(
    const git_scope_generation_t *generation) {
    struct stat named;

    if (!generation || !generation->valid ||
        !generation->post_config_identity_valid) {
        return 0;
    }
    if (generation->post_config_present) {
        if (generation->post_config_fd < 0 ||
            !git_file_at_matches_witness(
                generation->parent_fd, generation->leaf,
                generation->post_config_fd, &generation->post_config_stat,
                generation->post_config_data,
                generation->post_config_length, NULL)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git rollback post-image generation changed for %s",
                      git_scope_diagnostic_label(generation->scope));
            return -1;
        }
    } else if (fstatat(generation->parent_fd, generation->leaf, &named,
                       AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback post-image generation changed for %s",
                  git_scope_diagnostic_label(generation->scope));
        return -1;
    }
    return 0;
}

static void git_scope_lock_close(git_scope_lock_t *lock) {
    if (!lock) return;
    if (lock->stage_created && lock->dir_fd >= 0) {
        (void)unlinkat(lock->dir_fd, lock->stage_leaf, 0);
    }
    if (lock->lock_created && !lock->published && lock->dir_fd >= 0) {
        (void)unlinkat(lock->dir_fd, lock->lock_leaf, 0);
    }
    if (lock->original_fd >= 0) close(lock->original_fd);
    lock->original_fd = -1;
    if (lock->published_fd >= 0) close(lock->published_fd);
    lock->published_fd = -1;
    if (lock->original_data) {
        secure_zero_memory(lock->original_data, lock->original_length);
        free(lock->original_data);
    }
    lock->original_data = NULL;
    lock->original_length = 0;
    if (lock->published_data) {
        secure_zero_memory(lock->published_data, lock->published_length);
        free(lock->published_data);
    }
    lock->published_data = NULL;
    lock->published_length = 0;
    if (lock->dir_fd >= 0) close(lock->dir_fd);
    lock->dir_fd = -1;
}

/* Acquire exactly the lock name used by Git for this config file, then copy
 * the full current file into it. The in-lock copy is the merge base, so every
 * unmanaged edit that completed before lock acquisition survives publication. */
static int git_scope_lock_acquire(git_scope_t scope,
                                  git_scope_lock_t *lock,
                                  const git_scope_generation_t *generation) {
    static unsigned long stage_nonce;
    int lock_fd = -1;
    int source_fd = -1;
    int stage_fd = -1;
    struct stat named;
    struct stat opened;
    struct stat captured;
    struct stat named_after;
    struct stat created;

    memset(lock, 0, sizeof(*lock));
    lock->dir_fd = -1;
    lock->original_fd = -1;
    lock->published_fd = -1;
    if (git_scope_lock_resolve_paths(scope, lock) != 0) {
        if (generation && generation->valid) {
            lock->generation_conflict = true;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git rollback destination generation changed for %s",
                      git_scope_diagnostic_label(scope));
        }
        return -1;
    }
    if (generation && generation->valid) {
        if (git_scope_generation_verify_namespace_resolved(generation,
                                                           lock) != 0) {
            lock->generation_conflict = true;
            return -1;
        }
        lock->dir_fd = git_dup_cloexec(generation->parent_fd);
    } else {
        lock->dir_fd = open(lock->parent,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (lock->dir_fd < 0 || fstat(lock->dir_fd, &lock->parent_stat) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot pin Git configuration directory: %s",
                         lock->parent);
        git_scope_lock_close(lock);
        return -1;
    }
    if (generation && generation->valid &&
        !git_same_object_identity(&generation->parent_stat,
                                  &lock->parent_stat)) {
        lock->generation_conflict = true;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback destination generation changed for %s",
                  git_scope_diagnostic_label(scope));
        git_scope_lock_close(lock);
        return -1;
    }
    if (g_restore_prelock_hook) g_restore_prelock_hook(scope);
    lock_fd = openat(lock->dir_fd, lock->lock_leaf,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (lock_fd < 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot acquire Git configuration lock: %s",
                         lock->lock_path);
        git_scope_lock_close(lock);
        return -1;
    }
    lock->lock_created = true;

    for (unsigned attempt = 0; attempt < 100U; attempt++) {
        unsigned long nonce = ++stage_nonce;
        if ((size_t)snprintf(lock->stage_leaf, sizeof(lock->stage_leaf),
                             ".gitswitch-config-%ld-%lu", (long)getpid(),
                             nonce) >= sizeof(lock->stage_leaf) ||
            (size_t)snprintf(lock->stage_path, sizeof(lock->stage_path),
                             "%s/%s", lock->parent, lock->stage_leaf) >=
                sizeof(lock->stage_path)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git rollback staging path is too long");
            goto fail;
        }
        stage_fd = openat(lock->dir_fd, lock->stage_leaf,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        if (stage_fd >= 0) {
            lock->stage_created = true;
            break;
        }
        if (errno != EEXIST) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot create Git rollback staging file");
            goto fail;
        }
    }
    if (stage_fd < 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot allocate a unique Git rollback staging file");
        goto fail;
    }
    if (close(lock_fd) != 0) {
        lock_fd = -1;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot close Git configuration lock");
        goto fail;
    }
    lock_fd = -1;

    if (fstatat(lock->dir_fd, lock->leaf, &named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        lock->original_present = true;
        if (!S_ISREG(named.st_mode)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Refusing to restore non-regular Git config: %s",
                      lock->path);
            goto fail;
        }
        source_fd = openat(lock->dir_fd, lock->leaf,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (source_fd < 0 || fstat(source_fd, &opened) != 0) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot pin Git configuration for rollback: %s",
                             lock->path);
            goto fail;
        }
        {
            bool forced_mismatch =
                g_metadata_test_hook &&
                g_metadata_test_hook(GIT_METADATA_TEST_SOURCE_PIN);
            errno = 0;
            if (forced_mismatch ||
                !git_same_file_observation(&named, &opened)) {
                errno = EAGAIN;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Git configuration changed while pinning: %s",
                    lock->path);
                goto fail;
            }
        }
        if (opened.st_size < 0 ||
            (uintmax_t)opened.st_size > GIT_SNAPSHOT_MAX_BYTES) {
            errno = EFBIG;
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Git configuration grew beyond rollback bound: %s",
                             lock->path);
            goto fail;
        }
        if (git_capture_fd_bytes_exact(
                source_fd, &lock->original_data, &lock->original_length,
                &captured) != 0 ||
            (!git_same_file_observation(&opened, &captured) &&
             !git_metadata_ctime_only_change(&opened, &captured)) ||
            fstatat(lock->dir_fd, lock->leaf, &named_after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !git_same_file_observation(&captured, &named_after)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git configuration changed while capturing: %s",
                lock->path);
            goto fail;
        }
        lock->original_stat = captured;
        lock->original_fd = source_fd;
        source_fd = -1;
        lock->original_witness_valid = true;
        lock->target_mode = captured.st_mode & 07777;
        lock->target_uid = captured.st_uid;
        lock->target_gid = captured.st_gid;
        if (fstat(stage_fd, &created) != 0 ||
            ((created.st_uid != lock->target_uid ||
              created.st_gid != lock->target_gid) &&
             fchown(stage_fd, lock->target_uid, lock->target_gid) != 0) ||
            fchmod(stage_fd, lock->target_mode) != 0 ||
            git_write_all(stage_fd, lock->original_data,
                          lock->original_length) != 0) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot prepare Git rollback staging file: %s",
                             lock->stage_path);
            goto fail;
        }
    } else if (errno == ENOENT) {
        if (fstat(stage_fd, &opened) != 0) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot inspect new Git rollback staging file");
            goto fail;
        }
        lock->target_mode = opened.st_mode & 07777;
        lock->target_uid = opened.st_uid;
        lock->target_gid = opened.st_gid;
    } else {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot inspect Git configuration: %s", lock->path);
        goto fail;
    }
    if (source_fd >= 0) {
        close(source_fd);
        source_fd = -1;
    }
    if (fsync(stage_fd) != 0) {
        int saved_errno = errno ? errno : EAGAIN;
        (void)close(stage_fd);
        stage_fd = -1;
        errno = saved_errno;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot flush Git rollback staging file: %s",
                         lock->stage_path);
        goto fail;
    }
    if (close(stage_fd) != 0) {
        stage_fd = -1;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot close Git rollback staging file: %s",
                         lock->stage_path);
        goto fail;
    }
    stage_fd = -1;
    return 0;

fail:
    if (source_fd >= 0) close(source_fd);
    if (lock_fd >= 0) close(lock_fd);
    if (stage_fd >= 0) close(stage_fd);
    git_scope_lock_close(lock);
    return -1;
}

static int git_config_file_get_all(const char *path, const char *key,
                                   char *value, size_t value_size) {
    char output[GIT_CFG_VALUE_MAX + 8U];
    const char *const argv[] = {
        "git", "config", "--file", path, "--no-includes", "--get-all",
        key, NULL
    };
    run_opts_t opts;
    run_result_t result;
    size_t length;

    if (!path || path[0] != '/' || !key || !value || value_size == 0U) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid exact-file Git configuration read");
        return -1;
    }
    value[0] = '\0';
    memset(output, 0, sizeof(output));
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &result) != 0 || result.out_truncated ||
        result.out_len >= sizeof(output)) {
        /* M12 owns tri-state retirement reads. Preserve the established
         * present-versus-nonmatching behavior here while M10 changes only the
         * destination authority from caller scope/cwd to the exact ledger
         * path. Unknown reads therefore authorize no mutation. */
        return -1;
    }
    length = result.out_len;
    if (length > 0U && output[length - 1U] == '\n') {
        output[--length] = '\0';
    }
    if (length >= value_size || safe_strncpy(value, output, value_size) != 0) {
        value[0] = '\0';
        return -1;
    }
    return 0;
}

static int git_config_file_unset(const char *path, const char *key,
                                 bool no_includes,
                                 const char *diagnostic_context) {
    char output[256] = "";
    const char *const ordinary_argv[] = {
        "git", "config", "--file", path, "--unset-all", key, NULL
    };
    const char *const exact_argv[] = {
        "git", "config", "--file", path, "--no-includes", "--unset-all",
        key, NULL
    };
    const char *const *argv = no_includes ? exact_argv : ordinary_argv;
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    (void)run_argv(argv, &opts, &result);
    if (result.spawned && result.term_signal == 0 &&
        (result.exit_code == 0 || result.exit_code == 5)) {
        return 0;
    }
    set_error(ERR_GIT_CONFIG_FAILED,
              "Failed to clear Git config %s in %s: %s", key,
              diagnostic_context ? diagnostic_context : "exact file",
              output[0] ? output : "unknown Git error");
    return -1;
}

static int git_config_file_add(const char *path, const char *key,
                               const char *value) {
    char output[256] = "";
    const char *const argv[] = {
        "git", "config", "--file", path, "--add", key, value, NULL
    };
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    if (run_argv(argv, &opts, &result) == 0) return 0;
    set_error(ERR_GIT_CONFIG_FAILED,
              "Failed to add Git config %s in rollback lock: %s", key,
              output[0] ? output : "unknown Git error");
    return -1;
}

static int git_capture_file_snapshot(const char *path,
                                     git_scope_snapshot_t *out) {
    size_t capacity = GIT_SNAPSHOT_INITIAL_BYTES;
    char *buffer = malloc(capacity);
    int rc = -1;

    if (!buffer) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory verifying Git rollback lock");
        return -1;
    }
    for (;;) {
        const char *const argv[] = {
            "git", "config", "--file", path, "--list", "-z",
            "--no-includes", NULL
        };
        run_opts_t opts;
        run_result_t result;
        memset(&opts, 0, sizeof(opts));
        memset(&result, 0, sizeof(result));
        opts.out = buffer;
        opts.out_size = capacity;
        opts.merge_stderr = true;
        if (run_argv(argv, &opts, &result) != 0) break;
        if (!result.out_truncated) {
            rc = git_parse_snapshot_listing(buffer, result.out_len, out);
            break;
        }
        if (capacity >= GIT_SNAPSHOT_MAX_BYTES) break;
        {
            size_t grown_size = capacity * 2U;
            char *grown;
            if (grown_size > GIT_SNAPSHOT_MAX_BYTES) {
                grown_size = GIT_SNAPSHOT_MAX_BYTES;
            }
            grown = realloc(buffer, grown_size);
            if (!grown) break;
            buffer = grown;
            capacity = grown_size;
        }
    }
    free(buffer);
    if (rc != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to verify prepared Git rollback lock");
    }
    return rc;
}

static int git_scope_lock_publish(git_scope_lock_t *lock) {
    char resolved[MAX_PATH_LEN];
    struct stat named_parent;
    struct stat named_original;
    struct stat named_stage;
    struct stat opened_stage;
    struct stat captured_stage;
    struct stat named_lock;
    struct stat opened_lock;
    struct stat logical_now;
    int verify_fd;
    bool original_unchanged;

    verify_fd = openat(lock->dir_fd, lock->stage_leaf,
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (verify_fd < 0 || fstat(verify_fd, &opened_stage) != 0 ||
        fstatat(lock->dir_fd, lock->stage_leaf, &named_stage,
                AT_SYMLINK_NOFOLLOW) != 0) {
        int saved_errno = errno;
        if (verify_fd >= 0) close(verify_fd);
        errno = saved_errno;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot inspect prepared Git rollback staging file: %s",
                         lock->stage_path);
        return -1;
    }
    {
        bool forced_mismatch =
            g_metadata_test_hook &&
            g_metadata_test_hook(GIT_METADATA_TEST_STAGE_REVALIDATE);
        errno = 0;
        if (forced_mismatch || !S_ISREG(opened_stage.st_mode) ||
            opened_stage.st_dev != named_stage.st_dev ||
            opened_stage.st_ino != named_stage.st_ino ||
            (opened_stage.st_mode & 07777) != lock->target_mode ||
            opened_stage.st_uid != lock->target_uid ||
            opened_stage.st_gid != lock->target_gid) {
            if (verify_fd >= 0) close(verify_fd);
            errno = EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Prepared Git rollback staging file changed unexpectedly: %s",
                lock->stage_path);
            return -1;
        }
    }
    errno = 0;
    if (fsync(verify_fd) != 0 ||
        git_capture_fd_bytes_exact(
            verify_fd, &lock->published_data, &lock->published_length,
            &captured_stage) != 0 ||
        !git_same_pinned_file_generation(&opened_stage, &captured_stage) ||
        !git_same_pinned_file_generation(&named_stage, &captured_stage)) {
        int saved_errno = errno ? errno : EAGAIN;
        close(verify_fd);
        errno = saved_errno;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot capture prepared Git rollback staging file: %s",
                         lock->stage_path);
        return -1;
    }
    lock->published_witness_valid = true;
    if (close(verify_fd) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot close prepared Git rollback lock");
        return -1;
    }
    if (lstat(lock->parent, &named_parent) != 0 ||
        named_parent.st_dev != lock->parent_stat.st_dev ||
        named_parent.st_ino != lock->parent_stat.st_ino ||
        !S_ISDIR(named_parent.st_mode)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git configuration directory changed before rollback publication");
        return -1;
    }
    if (lock->logical_present) {
        if (lstat(lock->logical_path, &logical_now) != 0 ||
            S_ISLNK(logical_now.st_mode) != lock->logical_final_symlink ||
            (lock->logical_final_symlink &&
             !git_same_file_version(&lock->logical_stat, &logical_now)) ||
            !realpath(lock->logical_path, resolved) ||
            strcmp(resolved, lock->path) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git configuration symlink/path changed before rollback publication: %s",
                      lock->logical_path);
            return -1;
        }
    } else {
        if (lstat(lock->logical_path, &logical_now) == 0 || errno != ENOENT ||
            !realpath(lock->logical_parent, resolved) ||
            strcmp(resolved, lock->parent) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git configuration path appeared or moved before rollback publication: %s",
                      lock->logical_path);
            return -1;
        }
    }
    if (fstatat(lock->dir_fd, lock->leaf, &named_original,
                AT_SYMLINK_NOFOLLOW) == 0) {
        original_unchanged = lock->original_present &&
                             git_same_file_version(&lock->original_stat,
                                                   &named_original);
        if (!original_unchanged && lock->original_present &&
            lock->original_witness_valid && lock->original_fd >= 0 &&
            git_metadata_ctime_only_change(&lock->original_stat,
                                           &named_original)) {
            struct stat refreshed;

            if (git_file_at_matches_witness(
                    lock->dir_fd, lock->leaf, lock->original_fd,
                    &lock->original_stat, lock->original_data,
                    lock->original_length, &refreshed) &&
                git_metadata_ctime_only_change(&lock->original_stat,
                                               &refreshed)) {
                lock->original_stat = refreshed;
                original_unchanged = true;
            }
        }
    } else {
        original_unchanged = !lock->original_present && errno == ENOENT;
    }
    if (!original_unchanged) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git configuration changed outside its lock before rollback publication: %s",
                  lock->path);
        return -1;
    }
    /* Replace the continuously-held canonical Git lock with the fully edited
     * short staging artifact. renameat is atomic, so an external `git config`
     * never observes the canonical lock name absent. */
    if (renameat(lock->dir_fd, lock->stage_leaf,
                 lock->dir_fd, lock->lock_leaf) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot install prepared Git rollback lock: %s",
                         lock->lock_path);
        return -1;
    }
    lock->stage_created = false;
    verify_fd = openat(lock->dir_fd, lock->lock_leaf,
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (verify_fd < 0 || fstat(verify_fd, &opened_lock) != 0 ||
        fstatat(lock->dir_fd, lock->lock_leaf, &named_lock,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !git_same_pinned_file_generation(&captured_stage, &opened_lock) ||
        !git_same_pinned_file_generation(&captured_stage, &named_lock) ||
        fsync(verify_fd) != 0 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, verify_fd, &captured_stage,
            lock->published_data, lock->published_length, &opened_lock)) {
        int saved_errno = errno ? errno : EAGAIN;
        if (verify_fd >= 0) close(verify_fd);
        errno = saved_errno;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Installed Git rollback lock could not be revalidated: %s",
                         lock->lock_path);
        return -1;
    }
    /* Keep the already-verified descriptor across the publishing rename.
     * Reopening the pathname afterward can fail or race with the next writer,
     * leaving retry ownership stuck on the pre-restore inode. */
    lock->published_fd = verify_fd;
    lock->published_stat = opened_lock;
    verify_fd = -1;
    if (renameat(lock->dir_fd, lock->lock_leaf,
                 lock->dir_fd, lock->leaf) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot publish Git rollback: %s", lock->path);
        return -1;
    }
    lock->published = true;
    if (fsync(lock->dir_fd) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git rollback was installed but its directory sync failed: %s",
                         lock->path);
        return -1;
    }
    return 0;
}

static bool git_scope_snapshot_restore_complete(
    const git_scope_snapshot_t *snapshot) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (!snapshot->keys[i].restored) return false;
    }
    return true;
}

static bool git_scope_lock_matches_post_generation(
    const git_scope_lock_t *lock,
    const git_scope_generation_t *generation) {
    if (!generation || !generation->valid ||
        !generation->post_config_identity_valid) {
        return true;
    }
    if (lock->original_present != generation->post_config_present) {
        return false;
    }
    if (!lock->original_present) return true;
    return generation->post_config_fd >= 0 && lock->original_fd >= 0 &&
           lock->original_witness_valid &&
           git_same_pinned_file_generation(&generation->post_config_stat,
                                           &lock->original_stat) &&
           generation->post_config_length == lock->original_length &&
           (lock->original_length == 0 ||
            memcmp(generation->post_config_data, lock->original_data,
                   lock->original_length) == 0) &&
           git_fd_matches_witness_stable(
               generation->post_config_fd, &generation->post_config_stat,
               generation->post_config_data,
               generation->post_config_length, NULL) &&
           git_file_at_matches_witness(
               lock->dir_fd, lock->leaf, lock->original_fd,
               &lock->original_stat, lock->original_data,
               lock->original_length, NULL);
}

/* Production rollback owns the same per-file lock as `git config`. The fresh
 * ownership read, full-file merge, and atomic publication therefore form one
 * serialized transaction. Custom test runners retain the command-mode helper
 * above because their stores are intentionally in-memory, not filesystem
 * configurations. */
static git_restore_result_t git_restore_scope_snapshot_atomic(
    git_scope_t scope, git_scope_snapshot_t *before,
    const git_scope_snapshot_t *post,
    git_scope_generation_t *generation) {
    git_restore_result_t result = {0};
    git_scope_lock_t lock;
    git_scope_snapshot_t current;
    git_scope_snapshot_t expected;
    git_scope_snapshot_t observed;
    bool restore_key[GIT_MANAGED_KEY_COUNT] = {false};
    bool any_restore = false;
    bool track_post_generation = generation && generation->valid &&
                                 generation->post_config_identity_valid;

    memset(&current, 0, sizeof(current));
    memset(&expected, 0, sizeof(expected));
    memset(&observed, 0, sizeof(observed));
    if (git_scope_snapshot_restore_complete(before)) return result;
    if (git_scope_lock_acquire(scope, &lock, generation) != 0) {
        if (lock.generation_conflict) {
            result.generation_conflicts++;
        } else {
            result.write_failures++;
        }
        return result;
    }
    if (git_capture_scope_snapshot(scope, &current) != 0 ||
        git_scope_snapshot_clone(&current, &expected) != 0) {
        result.write_failures++;
        goto done;
    }
    if (g_restore_locked_hook) g_restore_locked_hook(scope);

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        git_snapshot_key_t *key = &before->keys[i];
        if (key->restored) {
            if (!git_snapshot_key_equal(&current.keys[i], key)) {
                cfg_cache_store(cfg_scope_index(scope), (int)i, CFG_UNKNOWN,
                                current.keys[i].count != 0, "");
            }
            continue;
        }
        if (!git_restore_key_still_owned(&current.keys[i], key,
                                         &post->keys[i])) {
            log_warning("Rollback preserved externally changed Git config %s (%s)",
                        g_managed_keys[i],
                        git_scope_diagnostic_label(scope));
            cfg_cache_store(cfg_scope_index(scope), (int)i, CFG_UNKNOWN,
                            current.keys[i].count != 0, "");
            result.conflicts++;
            continue;
        }
        restore_key[i] = true;
        any_restore = true;
        git_snapshot_key_clear(&expected.keys[i]);
        for (size_t j = 0; j < key->count; j++) {
            if (git_snapshot_key_append(&expected.keys[i], key->values[j],
                                        strlen(key->values[j])) != 0) {
                result.write_failures++;
                goto done;
            }
        }
    }
    /* A value conflict proves only that this transaction does not own that
     * vector. It cannot transfer whole-file ownership to a different inode,
     * either now or on a later retry. */
    if (!git_scope_lock_matches_post_generation(&lock, generation)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback post-image generation changed for %s",
                  git_scope_diagnostic_label(scope));
        result.generation_conflicts++;
        goto done;
    }
    if (!any_restore) goto done;

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (!restore_key[i]) continue;
        if (git_config_file_unset(lock.stage_path, g_managed_keys[i], false,
                                  "rollback lock") != 0) {
            result.write_failures++;
            goto done;
        }
        for (size_t j = 0; j < before->keys[i].count; j++) {
            if (git_config_file_add(lock.stage_path, g_managed_keys[i],
                                    before->keys[i].values[j]) != 0) {
                result.write_failures++;
                goto done;
            }
        }
    }
    if (git_capture_file_snapshot(lock.stage_path, &observed) != 0 ||
        !git_scope_snapshot_equal(&expected, &observed)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Prepared Git rollback does not match its exact target vectors");
        result.write_failures++;
        goto done;
    }
    if (git_scope_lock_publish(&lock) != 0) {
        /* renameat() may already have installed the exact target. Record only
         * prefix ownership, never completion, until the parent directory sync
         * succeeds on a later checked retry. */
        if (lock.published) {
            if (track_post_generation &&
                git_scope_generation_adopt_published_config(generation,
                                                            &lock) != 0) {
                log_warning("Could not retain the installed Git rollback generation: %s",
                            get_last_error()->message);
            }
            for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
                if (!restore_key[i]) continue;
                before->keys[i].restore_started = true;
                before->keys[i].restore_prefix = before->keys[i].count;
            }
        }
        result.write_failures++;
        goto done;
    }
    if (g_restore_postpublish_hook) g_restore_postpublish_hook(scope);
    if (generation && generation->valid &&
        ((track_post_generation &&
          git_scope_generation_adopt_published_config(generation, &lock) != 0) ||
         git_scope_generation_verify_namespace(generation) != 0)) {
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
            if (!restore_key[i]) continue;
            before->keys[i].restore_started = true;
            before->keys[i].restore_prefix = before->keys[i].count;
        }
        result.generation_conflicts++;
        goto done;
    }
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        git_snapshot_key_t *key = &before->keys[i];
        if (!restore_key[i]) continue;
        key->restore_started = true;
        key->restore_prefix = key->count;
        key->restored = true;
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
    }

done:
    git_scope_snapshot_clear(&current);
    git_scope_snapshot_clear(&expected);
    git_scope_snapshot_clear(&observed);
    git_scope_lock_close(&lock);
    return result;
}

static int git_capture_transaction_scopes(git_scope_snapshot_t *primary,
                                          git_scope_snapshot_t *local,
                                          git_scope_snapshot_t *worktree) {
    if (git_capture_scope_snapshot(g_git_snapshot.scope, primary) != 0 ||
        (g_git_snapshot.local_also &&
         git_capture_scope_snapshot(GIT_SCOPE_LOCAL, local) != 0) ||
        (g_git_snapshot.worktree_also &&
         git_capture_scope_snapshot(GIT_SCOPE_WORKTREE_INTERNAL,
                                    worktree) != 0)) {
        git_scope_snapshot_clear(primary);
        git_scope_snapshot_clear(local);
        git_scope_snapshot_clear(worktree);
        return -1;
    }
    return 0;
}

static int git_snapshot_capture_generations(git_config_snapshot_t *snapshot) {
    if (!run_uses_default_runner()) return 0;
    if (git_scope_generation_capture(snapshot->scope,
                                     &snapshot->primary_generation) != 0 ||
        (snapshot->local_also &&
         git_scope_generation_capture(GIT_SCOPE_LOCAL,
                                      &snapshot->local_generation) != 0) ||
        (snapshot->worktree_also &&
         git_scope_generation_capture(GIT_SCOPE_WORKTREE_INTERNAL,
                                      &snapshot->worktree_generation) != 0)) {
        return -1;
    }
    return 0;
}

static int git_snapshot_verify_generations(
    const git_config_snapshot_t *snapshot, bool verify_post_config) {
    const git_scope_generation_t *generations[] = {
        &snapshot->primary_generation,
        &snapshot->local_generation,
        &snapshot->worktree_generation
    };

    for (size_t i = 0; i < sizeof(generations) / sizeof(generations[0]); i++) {
        const git_scope_generation_t *generation = generations[i];
        if (!generation->valid) continue;
        if (git_scope_generation_verify_namespace(generation) != 0 ||
            (verify_post_config &&
             git_scope_generation_verify_post_config(generation) != 0)) {
            return -1;
        }
    }
    return 0;
}

static int git_snapshot_pin_post_configs(git_config_snapshot_t *snapshot) {
    git_scope_generation_t *generations[] = {
        &snapshot->primary_generation,
        &snapshot->local_generation,
        &snapshot->worktree_generation
    };

    for (size_t i = 0; i < sizeof(generations) / sizeof(generations[0]); i++) {
        if (generations[i]->valid &&
            git_scope_generation_pin_post_config(generations[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static void git_snapshot_clear_post_configs(git_config_snapshot_t *snapshot) {
    git_scope_generation_t *generations[] = {
        &snapshot->primary_generation,
        &snapshot->local_generation,
        &snapshot->worktree_generation
    };

    for (size_t i = 0; i < sizeof(generations) / sizeof(generations[0]); i++) {
        git_scope_generation_t *generation = generations[i];
        if (generation->post_config_identity_valid &&
            generation->post_config_present &&
            generation->post_config_fd >= 0) {
            (void)close(generation->post_config_fd);
        }
        if (generation->post_config_data) {
            secure_zero_memory(generation->post_config_data,
                               generation->post_config_length);
            free(generation->post_config_data);
        }
        generation->post_config_fd = -1;
        generation->post_config_data = NULL;
        generation->post_config_length = 0;
        memset(&generation->post_config_stat, 0,
               sizeof(generation->post_config_stat));
        generation->post_config_identity_valid = false;
        generation->post_config_present = false;
    }
}

static git_scope_generation_t *git_transaction_generation(git_scope_t scope) {
    if (!g_git_snapshot.valid) return NULL;
    if (scope == g_git_snapshot.scope) {
        return &g_git_snapshot.primary_generation;
    }
    if (g_git_snapshot.local_also && scope == GIT_SCOPE_LOCAL) {
        return &g_git_snapshot.local_generation;
    }
    if (g_git_snapshot.worktree_also &&
        scope == GIT_SCOPE_WORKTREE_INTERNAL) {
        return &g_git_snapshot.worktree_generation;
    }
    return NULL;
}

static git_scope_snapshot_t *git_transaction_post_scope(git_scope_t scope) {
    if (!g_git_snapshot.valid) return NULL;
    if (scope == g_git_snapshot.scope) return &g_git_snapshot.post_primary;
    if (g_git_snapshot.local_also && scope == GIT_SCOPE_LOCAL) {
        return &g_git_snapshot.post_local;
    }
    if (g_git_snapshot.worktree_also &&
        scope == GIT_SCOPE_WORKTREE_INTERNAL) {
        return &g_git_snapshot.post_worktree;
    }
    return NULL;
}

static int git_transaction_require_write_allowed(git_scope_t scope,
                                                 const char *key) {
    if (cfg_key_index(key) < 0 || !g_git_snapshot.valid) return 0;
    if (!git_transaction_post_scope(scope)) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot write a managed key outside the active Git transaction scopes");
        return -1;
    }
    if (g_git_snapshot.restore_incomplete) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot modify a Git transaction with incomplete rollback");
        return -1;
    }
    if (g_git_snapshot.postimage_sealed) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot modify a sealed Git configuration transaction");
        return -1;
    }
    return 0;
}

/* Bind durable publication ownership to the account that supplied the
 * transaction's managed Git identity. The optional incarnation fields remain
 * backward compatible for direct low-level git_set_config() callers, but a
 * transaction without a canonical persisted owner can never be exported as
 * durable account provenance. Once bound, another account cannot reuse the
 * same snapshot slot to manufacture a post-image attributed to the first. */
static int git_snapshot_bind_publication_owner(const account_t *account,
                                               git_scope_t scope) {
    if (!g_git_snapshot.valid) return 0;
    if (!account) {
        set_error(ERR_INVALID_ARGS,
                  "Cannot bind a NULL Git publication owner");
        return -1;
    }
    /* Account-owned boundaries are always primary-scope operations while a
     * transaction is active. git_set_config_impl() normalizes tracked local
     * and worktree overrides through raw managed-key operations under its
     * authorization depth; it never needs a second account-owned boundary.
     * Reject every other scope before considering whether that store was
     * captured, because an untracked write is outside both rollback and the
     * durable publication destination. */
    if (scope != g_git_snapshot.scope) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot write an account outside the active Git transaction's primary scope");
        return -1;
    }
    if (!git_transaction_post_scope(scope)) return 0;
    if (g_git_snapshot.publication_owner_bound) {
        if (account->id == 0U || !account->incarnation_persisted ||
            !account_incarnation_is_valid(account->incarnation) ||
            g_git_snapshot.publication_account_id != account->id ||
            strcmp(g_git_snapshot.publication_account_incarnation,
                   account->incarnation) != 0) {
            errno = ESTALE;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git transaction is already bound to another account incarnation");
            return -1;
        }
        return 0;
    }
    if (scope != g_git_snapshot.scope) return 0;
    if (!account->incarnation_persisted && account->incarnation[0] == '\0') {
        return 0;
    }
    if (account->id == 0U || !account->incarnation_persisted ||
        !account_incarnation_is_valid(account->incarnation)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Git publication owner has no canonical persisted incarnation");
        return -1;
    }
    g_git_snapshot.publication_account_id = account->id;
    memcpy(g_git_snapshot.publication_account_incarnation,
           account->incarnation, ACCOUNT_INCARNATION_LEN);
    g_git_snapshot.publication_owner_bound = true;
    return 0;
}

static bool git_snapshot_publication_owner_matches(
    const account_t *account) {
    return account && g_git_snapshot.publication_owner_bound &&
           account->id != 0U && account->incarnation_persisted &&
           account_incarnation_is_valid(account->incarnation) &&
           g_git_snapshot.publication_account_id == account->id &&
           strcmp(g_git_snapshot.publication_account_incarnation,
                  account->incarnation) == 0;
}

static bool git_snapshot_publication_is_complete_for(
    const account_t *account, git_scope_t scope) {
    return g_git_snapshot.valid && scope == g_git_snapshot.scope &&
           git_snapshot_publication_owner_matches(account) &&
           !g_git_snapshot.publication_owner_tainted &&
           g_git_snapshot.publication_full_image_written;
}

static int git_account_write_begin(const account_t *account,
                                   git_scope_t scope) {
    if (g_git_account_write_depth == UINT_MAX) {
        errno = EOVERFLOW;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git account-write authorization depth overflow");
        return -1;
    }
    if (git_snapshot_bind_publication_owner(account, scope) != 0) return -1;
    /* Completeness describes the current post-image, not a historical success.
     * Invalidate it before every standalone account-owned mutation. A failed
     * repeated full write or partial writer may already have changed one key;
     * only the successful full writer, or its exact canonical OpenPGP
     * completion, is allowed to restore publication eligibility. */
    if (g_git_account_write_depth == 0U && g_git_snapshot.valid &&
        scope == g_git_snapshot.scope &&
        g_git_snapshot.publication_owner_bound) {
        g_git_snapshot.publication_full_image_written = false;
    }
    g_git_account_write_depth++;
    return 0;
}

static void git_account_write_end(void) {
    if (g_git_account_write_depth > 0U) g_git_account_write_depth--;
}

static void git_taint_publication_after_raw_write(git_scope_t scope,
                                                  const char *key) {
    if (g_git_account_write_depth != 0U || !key ||
        cfg_key_index(key) < 0 || !git_transaction_post_scope(scope)) {
        return;
    }
    g_git_snapshot.publication_owner_tainted = true;
}

typedef struct {
    git_snapshot_key_t *destination;
    git_snapshot_key_t replacement;
} git_transaction_vector_update_t;

/* Construct the complete intended post-image before a managed Git command is
 * allowed to run. Committing the detached replacement is then infallible, so
 * command success can never leave rollback expecting the pre-write vector. */
static int git_transaction_prepare_vector(
    git_scope_t scope, const char *key, bool present, const char *value,
    git_transaction_vector_update_t *update) {
    git_scope_snapshot_t *post = git_transaction_post_scope(scope);
    int key_index = cfg_key_index(key);

    memset(update, 0, sizeof(*update));
    if (!post || key_index < 0) return 0;
    update->destination = &post->keys[key_index];
    if (present &&
        git_snapshot_key_append(&update->replacement, value,
                                strlen(value)) != 0) {
        git_snapshot_key_clear(&update->replacement);
        update->destination = NULL;
        return -1;
    }
    return 0;
}

static void git_transaction_discard_vector(
    git_transaction_vector_update_t *update) {
    git_snapshot_key_clear(&update->replacement);
    update->destination = NULL;
}

static void git_transaction_commit_vector(
    git_transaction_vector_update_t *update) {
    if (update->destination) {
        git_snapshot_key_clear(update->destination);
        *update->destination = update->replacement;
    }
    memset(update, 0, sizeof(*update));
}

/* Record a post-image for paths that perform no external write, such as a
 * proven duplicate set or absent unset. */
static int git_transaction_record_vector(git_scope_t scope, const char *key,
                                         bool present, const char *value) {
    git_transaction_vector_update_t update;

    if (git_transaction_prepare_vector(scope, key, present, value,
                                       &update) != 0) {
        return -1;
    }
    git_transaction_commit_vector(&update);
    return 0;
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
    if (!git_scope_to_flag(scope)) {
        set_error(ERR_INVALID_ARGS, "Invalid Git snapshot scope");
        return -1;
    }
    if (git_reject_ssh_command_override() != 0) return -1;
    git_snapshot_clear(&g_git_snapshot);

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
    if (git_snapshot_capture_generations(&next) != 0 ||
        git_capture_scope_snapshot(scope, &next.primary) != 0 ||
        (next.local_also &&
         git_capture_scope_snapshot(GIT_SCOPE_LOCAL, &next.local) != 0) ||
        (next.worktree_also &&
         git_capture_scope_snapshot(GIT_SCOPE_WORKTREE_INTERNAL,
                                    &next.worktree) != 0) ||
        git_scope_snapshot_clone(&next.primary, &next.post_primary) != 0 ||
        (next.local_also &&
         git_scope_snapshot_clone(&next.local, &next.post_local) != 0) ||
        (next.worktree_also &&
         git_scope_snapshot_clone(&next.worktree,
                                  &next.post_worktree) != 0) ||
        git_snapshot_verify_generations(&next, false) != 0) {
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

int git_config_seal(void) {
    git_scope_snapshot_t observed_primary;
    git_scope_snapshot_t observed_local;
    git_scope_snapshot_t observed_worktree;
    int differences;

    memset(&observed_primary, 0, sizeof(observed_primary));
    memset(&observed_local, 0, sizeof(observed_local));
    memset(&observed_worktree, 0, sizeof(observed_worktree));
    if (!g_git_snapshot.valid) {
        set_error(ERR_INVALID_ARGS, "No Git snapshot to seal");
        return -1;
    }
    if (g_git_snapshot.publication_owner_bound &&
        g_git_snapshot.publication_owner_tainted) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git publication ownership was invalidated by an unowned managed-key write");
        return -1;
    }
    if (g_git_snapshot.publication_owner_bound &&
        !g_git_snapshot.publication_full_image_written) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git publication owner has no complete account post-image");
        return -1;
    }
    if (g_git_snapshot.postimage_sealed) return 0;
    if (git_snapshot_verify_generations(&g_git_snapshot, false) != 0 ||
        git_snapshot_pin_post_configs(&g_git_snapshot) != 0 ||
        git_capture_transaction_scopes(&observed_primary, &observed_local,
                                       &observed_worktree) != 0 ||
        git_snapshot_verify_generations(&g_git_snapshot, true) != 0) {
        git_scope_snapshot_clear(&observed_primary);
        git_scope_snapshot_clear(&observed_local);
        git_scope_snapshot_clear(&observed_worktree);
        git_snapshot_clear_post_configs(&g_git_snapshot);
        return -1;
    }
    differences = git_scope_snapshot_difference_count(
        &g_git_snapshot.post_primary, &observed_primary);
    if (g_git_snapshot.local_also) {
        differences += git_scope_snapshot_difference_count(
            &g_git_snapshot.post_local, &observed_local);
    }
    if (g_git_snapshot.worktree_also) {
        differences += git_scope_snapshot_difference_count(
            &g_git_snapshot.post_worktree, &observed_worktree);
    }
    git_scope_snapshot_clear(&observed_primary);
    git_scope_snapshot_clear(&observed_local);
    git_scope_snapshot_clear(&observed_worktree);
    if (differences != 0) {
        git_snapshot_clear_post_configs(&g_git_snapshot);
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot seal Git transaction: %d managed vector(s) changed outside this transaction before post-image verification",
                  differences);
        return -1;
    }
    g_git_snapshot.postimage_sealed = true;
    return 0;
}

static int git_publication_scope_from_git(git_scope_t scope,
                                          publication_scope_t *publication) {
    if (!publication) return -1;
    if (scope == GIT_SCOPE_WORKTREE_INTERNAL) {
        *publication = PUBLICATION_SCOPE_WORKTREE;
        return 0;
    }
    switch (scope) {
        case GIT_SCOPE_LOCAL:
            *publication = PUBLICATION_SCOPE_LOCAL;
            return 0;
        case GIT_SCOPE_GLOBAL:
            *publication = PUBLICATION_SCOPE_GLOBAL;
            return 0;
        case GIT_SCOPE_SYSTEM:
        default:
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot persist provenance for an unsupported Git publication scope");
            return -1;
    }
}

/* Copy one exact scalar from the sealed primary post-image. Switch writes
 * replace every credential vector, so repetition here is a provenance error,
 * not a value from which the exporter may choose a convenient element. */
static int git_publication_copy_post_value(const char *key, char *out,
                                           size_t out_size, bool *present) {
    const git_snapshot_key_t *post;
    int key_index;

    if (!key || !out || out_size == 0 || !present) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid sealed Git publication value request");
        return -1;
    }
    out[0] = '\0';
    *present = false;
    key_index = cfg_key_index(key);
    if (key_index < 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication requested an unmanaged key");
        return -1;
    }
    post = &g_git_snapshot.post_primary.keys[key_index];
    if (post->count == 0) return 0;
    if (post->count != 1 || !post->values || !post->values[0]) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication contains a repeated %s vector",
                  key);
        return -1;
    }
    if (safe_strncpy(out, post->values[0], out_size) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication %s value exceeds durable storage",
                  key);
        return -1;
    }
    *present = true;
    return 0;
}

/* Re-run the complete executable trust walk against the absolute program
 * stored in Git, and bind the durable identity only while the named object is
 * unchanged across that proof. find_command_path() returns the canonical path
 * but intentionally closes its launch descriptor; the before/after witness
 * prevents a replacement in that gap from inheriting the proof. */
static int git_publication_capture_program_identity(
    const char *program, publication_identity_t *identity,
    const char *diagnostic_name) {
    char canonical[MAX_PATH_LEN];
    struct stat before;
    struct stat after;

    if (!program || program[0] != '/' || !identity ||
        lstat(program, &before) != 0 ||
        find_command_path(program, canonical, sizeof(canonical)) != 0 ||
        strcmp(canonical, program) != 0 || lstat(program, &after) != 0 ||
        !git_same_file_version(&before, &after) ||
        !S_ISREG(after.st_mode)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot bind the sealed %s executable identity",
                  diagnostic_name ? diagnostic_name : "Git helper");
        return -1;
    }
    publication_identity_from_stat(identity, &after);
    return 0;
}

int git_publication_verify_program_identity(
    const char *program, const publication_identity_t *expected,
    const char *diagnostic_name) {
    publication_identity_t observed;

    if (!program || !expected || !expected->present) {
        set_error(ERR_INVALID_ARGS,
                  "Missing persisted %s executable identity",
                  diagnostic_name ? diagnostic_name : "Git helper");
        return -1;
    }
    memset(&observed, 0, sizeof(observed));
    if (git_publication_capture_program_identity(
            program, &observed, diagnostic_name) != 0) {
        return -1;
    }
    if (!publication_identity_equal(expected, &observed)) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Recorded %s executable generation changed",
                  diagnostic_name ? diagnostic_name : "Git helper");
        return -1;
    }
    return 0;
}

int git_config_export_sealed_publication(publication_record_t *out,
                                         const char *gpg_selector) {
    publication_record_t record;
    const git_scope_generation_t *generation;
    char gpg_format[sizeof(GIT_GPG_FORMAT_OPENPGP)];
    char legacy_program[MAX_PATH_LEN];
    bool fingerprint_present = false;
    bool gpg_program_present = false;
    bool ssh_command_present = false;
    bool gpg_format_present = false;
    bool legacy_program_present = false;

    if (!out) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid sealed Git publication export request");
        return -1;
    }
    if (!g_git_snapshot.valid || !g_git_snapshot.postimage_sealed) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "No sealed Git publication is available to export");
        return -1;
    }
    if (!g_git_snapshot.publication_owner_bound ||
        g_git_snapshot.publication_owner_tainted ||
        !g_git_snapshot.publication_full_image_written ||
        g_git_snapshot.publication_account_id == 0U ||
        !account_incarnation_is_valid(
            g_git_snapshot.publication_account_incarnation)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication has no transaction-bound account owner");
        return -1;
    }
    if (git_snapshot_verify_generations(&g_git_snapshot, true) != 0) {
        return -1;
    }
    generation = &g_git_snapshot.primary_generation;
    if (!generation->valid || !generation->post_config_identity_valid ||
        !generation->post_config_present) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication has no durable post-config generation");
        return -1;
    }

    publication_record_init(&record);
    record.account_id = g_git_snapshot.publication_account_id;
    memcpy(record.account_incarnation,
           g_git_snapshot.publication_account_incarnation,
           ACCOUNT_INCARNATION_LEN);
    record.state = PUBLICATION_STATE_PUBLISHED;
    if (git_publication_scope_from_git(g_git_snapshot.scope,
                                       &record.scope) != 0 ||
        safe_strncpy(record.config_path, generation->path,
                     sizeof(record.config_path)) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication destination exceeds durable storage");
        return -1;
    }
    publication_identity_from_stat(&record.config_parent,
                                   &generation->parent_stat);
    publication_identity_from_stat(&record.post_config,
                                   &generation->post_config_stat);
    record.capabilities = PUBLICATION_CAP_DESTINATION |
                          PUBLICATION_CAP_POST_GENERATION;
    if (generation->repository_present) {
        if (safe_strncpy(record.repository_path,
                         generation->repository_path,
                         sizeof(record.repository_path)) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Sealed Git repository path exceeds durable storage");
            return -1;
        }
        publication_identity_from_stat(&record.repository,
                                       &generation->repository_stat);
    }

    if (git_publication_copy_post_value(
            GIT_CONFIG_USER_SIGNINGKEY, record.gpg_fingerprint,
            sizeof(record.gpg_fingerprint), &fingerprint_present) != 0 ||
        git_publication_copy_post_value(
            GIT_CONFIG_GPG_OPENPGP_PROGRAM, record.gpg_program,
            sizeof(record.gpg_program), &gpg_program_present) != 0 ||
        git_publication_copy_post_value(
            GIT_CONFIG_CORE_SSHCOMMAND, record.ssh_command,
            sizeof(record.ssh_command), &ssh_command_present) != 0 ||
        git_publication_copy_post_value(
            GIT_CONFIG_GPG_FORMAT, gpg_format, sizeof(gpg_format),
            &gpg_format_present) != 0) {
        return -1;
    }
    if (!gpg_format_present || strcmp(gpg_format,
                                      GIT_GPG_FORMAT_OPENPGP) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication is not in the managed OpenPGP format");
        return -1;
    }
    for (size_t i = 0;
         i < sizeof(g_gpg_program_keys) / sizeof(g_gpg_program_keys[0]); i++) {
        if (strcmp(g_gpg_program_keys[i],
                   GIT_CONFIG_GPG_OPENPGP_PROGRAM) == 0) {
            continue;
        }
        if (git_publication_copy_post_value(
                g_gpg_program_keys[i], legacy_program,
                sizeof(legacy_program), &legacy_program_present) != 0) {
            return -1;
        }
        if (legacy_program_present) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Sealed Git publication retains a foreign %s selector",
                      g_gpg_program_keys[i]);
            return -1;
        }
    }
    if (fingerprint_present != gpg_program_present ||
        (fingerprint_present &&
         !git_signing_key_matches_fingerprint(record.gpg_fingerprint,
                                              record.gpg_fingerprint))) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication lacks a complete canonical OpenPGP identity");
        return -1;
    }
    if (fingerprint_present) {
        if (publication_normalize_gpg_selector(
                gpg_selector, record.gpg_selector) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Sealed Git publication lacks its original account GPG selector");
            return -1;
        }
        for (char *digit = record.gpg_fingerprint; *digit; digit++) {
            *digit = (char)toupper((unsigned char)*digit);
        }
        if (git_publication_capture_program_identity(
                record.gpg_program, &record.gpg_program_identity,
                "OpenPGP") != 0) {
            return -1;
        }
        record.capabilities |= PUBLICATION_CAP_GPG_FINGERPRINT |
                               PUBLICATION_CAP_GPG_PROGRAM |
                               PUBLICATION_CAP_GPG_SELECTOR;
    } else if (gpg_selector && gpg_selector[0] != '\0') {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Sealed Git publication received a selector without a GPG post-image");
        return -1;
    }
    if (ssh_command_present) {
        if (publication_extract_ssh_program(
                record.ssh_command, record.ssh_program,
                sizeof(record.ssh_program)) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Sealed core.sshCommand has invalid executable provenance");
            return -1;
        }
        if (git_publication_capture_program_identity(
                record.ssh_program, &record.ssh_program_identity,
                "SSH") != 0) {
            return -1;
        }
        record.capabilities |= PUBLICATION_CAP_SSH_COMMAND |
                               PUBLICATION_CAP_SSH_PROGRAM;
    }
    if (publication_record_validate(&record) != 0) return -1;
    *out = record;
    return 0;
}

int git_config_restore(void) {
    git_scope_snapshot_t current_primary;
    git_scope_snapshot_t current_local;
    git_scope_snapshot_t current_worktree;
    git_restore_result_t result = {0};

    if (!g_git_snapshot.valid) return 0;
    memset(&current_primary, 0, sizeof(current_primary));
    memset(&current_local, 0, sizeof(current_local));
    memset(&current_worktree, 0, sizeof(current_worktree));
    log_info("Rolling back git configuration after a failed switch");

    /* Capture every managed scope before writing any of them. A read failure
     * cannot be treated as absence, and it must not leave a new partial
     * rollback merely because a later scope could not be ownership-checked. */
    if (git_capture_transaction_scopes(&current_primary, &current_local,
                                       &current_worktree) != 0) {
        char detail[sizeof(g_last_error.message)];
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        g_git_snapshot.restore_incomplete = true;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback incomplete: could not verify current managed vectors; retry material retained: %s",
                  detail[0] ? detail : "unknown Git inspection error");
        return -1;
    }

    /* Restore override scopes before the primary scope. */
    if (g_git_snapshot.worktree_also) {
        git_restore_result_t scope_result = run_uses_default_runner()
            ? git_restore_scope_snapshot_atomic(
                  GIT_SCOPE_WORKTREE_INTERNAL, &g_git_snapshot.worktree,
                  &g_git_snapshot.post_worktree,
                  git_transaction_generation(GIT_SCOPE_WORKTREE_INTERNAL))
            : git_restore_scope_snapshot(
                  GIT_SCOPE_WORKTREE_INTERNAL, &g_git_snapshot.worktree,
                  &g_git_snapshot.post_worktree, &current_worktree);
        result.conflicts += scope_result.conflicts;
        result.generation_conflicts += scope_result.generation_conflicts;
        result.write_failures += scope_result.write_failures;
    }
    if (g_git_snapshot.local_also) {
        git_restore_result_t scope_result = run_uses_default_runner()
            ? git_restore_scope_snapshot_atomic(
                  GIT_SCOPE_LOCAL, &g_git_snapshot.local,
                  &g_git_snapshot.post_local,
                  git_transaction_generation(GIT_SCOPE_LOCAL))
            : git_restore_scope_snapshot(
                  GIT_SCOPE_LOCAL, &g_git_snapshot.local,
                  &g_git_snapshot.post_local, &current_local);
        result.conflicts += scope_result.conflicts;
        result.generation_conflicts += scope_result.generation_conflicts;
        result.write_failures += scope_result.write_failures;
    }
    {
        git_restore_result_t scope_result = run_uses_default_runner()
            ? git_restore_scope_snapshot_atomic(
                  g_git_snapshot.scope, &g_git_snapshot.primary,
                  &g_git_snapshot.post_primary,
                  git_transaction_generation(g_git_snapshot.scope))
            : git_restore_scope_snapshot(
                  g_git_snapshot.scope, &g_git_snapshot.primary,
                  &g_git_snapshot.post_primary, &current_primary);
        result.conflicts += scope_result.conflicts;
        result.generation_conflicts += scope_result.generation_conflicts;
        result.write_failures += scope_result.write_failures;
    }
    git_scope_snapshot_clear(&current_primary);
    git_scope_snapshot_clear(&current_local);
    git_scope_snapshot_clear(&current_worktree);
    if (result.conflicts > 0 || result.generation_conflicts > 0 ||
        result.write_failures > 0) {
        /* Retain the exact snapshot and per-key progress until every key has
         * succeeded. Consuming it here made transient lock failures
         * irrecoverable on a second rollback attempt (AR-07 M27). */
        g_git_snapshot.restore_incomplete = true;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback incomplete: %d managed vector(s) changed outside this transaction; %d destination generation(s) changed; %d restore operation(s) failed; concurrent changes were preserved and retry material retained",
                  result.conflicts, result.generation_conflicts,
                  result.write_failures);
        fprintf(stderr,
                "gitswitch: [!!] git rollback incomplete — %d managed vector(s) "
                "changed outside this transaction; %d destination generation(s) "
                "changed; %d restore operation(s) failed; "
                "concurrent changes were preserved and retry material retained\n",
                result.conflicts, result.generation_conflicts,
                result.write_failures);
        return -1;
    }
    git_snapshot_clear(&g_git_snapshot);
    return 0;
}

void git_config_commit(void) {
    /* The caller invokes this only after every external transaction commit,
     * including the SSH alias rename, has succeeded. Discarding heap-owned
     * rollback images is infallible and deliberately offers no late error
     * branch that could force an unsafe rollback past that commit point. */
    git_snapshot_clear(&g_git_snapshot);
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

static int git_require_scope_gpg_model(git_scope_t scope) {
    if (git_require_scope_key_value(GIT_CONFIG_GPG_FORMAT,
                                    GIT_GPG_FORMAT_OPENPGP, scope) != 0) {
        return -1;
    }
    for (size_t i = 0;
         i < sizeof(g_gpg_program_keys) / sizeof(g_gpg_program_keys[0]); i++) {
        if (git_require_scope_key_absent(g_gpg_program_keys[i], scope) != 0) {
            return -1;
        }
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
    if (git_require_scope_gpg_model(scope) != 0) return -1;

    /* Worktree outranks local; local outranks global. Each scope that should
     * have been cleared must now be authoritatively absent, including values
     * supplied through an include at that scope. */
    if (manage_worktree) {
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++)
            if (git_require_scope_key_absent(g_managed_keys[i],
                                             GIT_SCOPE_WORKTREE_INTERNAL) != 0)
                return -1;
    }
    if (scope == GIT_SCOPE_GLOBAL && git_is_repository()) {
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++)
            if (git_require_scope_key_absent(g_managed_keys[i],
                                             GIT_SCOPE_LOCAL) != 0)
                return -1;
    }
    /* The manager publishes its retained executable after this staged Git
     * image succeeds. At this boundary every program selector must therefore
     * still be absent; gpg_configure_git_signing() performs the exact final
     * verification before the transaction can be sealed. */
    return git_verify_merged_account(account, NULL);
}

/* Set git configuration for account */
static int git_set_config_impl(const account_t *account, git_scope_t scope) {
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
    if (git_reject_ssh_command_override() != 0) return -1;
    
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

    /* Git interprets user.signingKey through gpg.format. Normalize that format
     * explicitly before verification, then clear every executable selector
     * Git recognizes. GNUPGHOME selects the isolated OpenPGP keyring; a
     * persisted legacy or format-specific program belongs to no account in
     * this model. Unset first so repeated foreign values are handled exactly. */
    if (git_unset_config_value(GIT_CONFIG_GPG_FORMAT, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear gpg.format");
        return -1;
    }
    for (size_t i = 0;
         i < sizeof(g_gpg_program_keys) / sizeof(g_gpg_program_keys[0]); i++) {
        if (git_unset_config_value(g_gpg_program_keys[i], scope) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear %s",
                      g_gpg_program_keys[i]);
            return -1;
        }
    }
    if (git_set_config_value(GIT_CONFIG_GPG_FORMAT,
                             GIT_GPG_FORMAT_OPENPGP, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set gpg.format=openpgp");
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

int git_set_config(const account_t *account, git_scope_t scope) {
    int result;

    if (git_account_write_begin(account, scope) != 0) return -1;
    result = git_set_config_impl(account, scope);
    if (result == 0 && g_git_snapshot.valid &&
        g_git_snapshot.scope == scope &&
        git_snapshot_publication_owner_matches(account)) {
        /* This full account writer normalizes every managed key in the
         * primary and discovered override scopes, so it supersedes any raw
         * pre-binding write observed earlier in the same snapshot. */
        g_git_snapshot.publication_owner_tainted = false;
        g_git_snapshot.publication_full_image_written = true;
    }
    git_account_write_end();
    return result;
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
 * configuration can be much larger than the managed keys because --list
 * includes unrelated values. Grow and retry up to the shared inspection
 * ceiling instead of converting fixed-buffer truncation into false absence or
 * permitting unbounded allocation. Oversize and allocation failures are
 * explicit errors and never publish partial status. */
static int git_read_effective_keys(git_effective_listing_t **out) {
    size_t capacity = GIT_INSPECTION_INITIAL_BYTES;
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
            if (res.out_len >= capacity) {
                free(list);
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Invalid effective Git configuration capture length");
                return -1;
            }
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

        if (capacity >= GIT_INSPECTION_MAX_BYTES) {
            free(list);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Effective Git configuration exceeds the %u-byte inspection limit",
                      (unsigned)GIT_INSPECTION_MAX_BYTES);
            return -1;
        }
        {
            size_t grown_capacity = capacity * 2U;
            char *grown;
            if (grown_capacity > GIT_INSPECTION_MAX_BYTES) {
                grown_capacity = GIT_INSPECTION_MAX_BYTES;
            }
            grown = realloc(list, grown_capacity);
            if (!grown) {
                free(list);
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory growing effective Git configuration capture");
                return -1;
            }
            list = grown;
            capacity = grown_capacity;
        }
    }
}

/* Canonicalize a captured non-text Boolean without rereading the user's
 * configuration. Git's accepted numeric range changed when its historical
 * INT_MIN off-by-one was fixed, and vendor Git builds can lag that change.
 * Supplying the captured bytes as an isolated default delegates only the
 * grammar decision to the same trusted Git selected by run_argv; /dev/null
 * prevents a concurrent config writer from changing the value being parsed. */
static int git_canonicalize_effective_bool(const char *raw, const char *key,
                                           bool *value) {
    char default_arg[sizeof("--default=") + GIT_CFG_VALUE_MAX];
    char canonical[16];
    char context[160];
    const char *argv[] = {
        "git", "config", "--file", "/dev/null", "--bool",
        default_arg, "--get", "gitswitch.boolean", NULL
    };
    run_opts_t opts;
    run_result_t result;

    if (safe_snprintf(default_arg, sizeof(default_arg), "--default=%s",
                      raw) != 0 ||
        safe_snprintf(context, sizeof(context),
                      "Invalid effective Git Boolean value for %s", key) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git Boolean value is too large to canonicalize");
        return -1;
    }
    memset(canonical, 0, sizeof(canonical));
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = canonical;
    opts.out_size = sizeof(canonical);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &result) != 0) {
        git_set_capture_error(context, argv, &result);
        return -1;
    }
    if (!result.out_truncated && result.out_len == sizeof("true\n") - 1U &&
        memcmp(canonical, "true\n", sizeof("true\n") - 1U) == 0) {
        *value = true;
        return 0;
    }
    if (!result.out_truncated && result.out_len == sizeof("false\n") - 1U &&
        memcmp(canonical, "false\n", sizeof("false\n") - 1U) == 0) {
        *value = false;
        return 0;
    }
    set_error(ERR_GIT_CONFIG_FAILED,
              "Git returned a noncanonical Boolean result for %s", key);
    return -1;
}

/* Preserve the atomic effective listing and fast-path Git's stable textual
 * grammar: implicit/true/yes/on and empty/false/no/off. Numeric and otherwise
 * unknown spellings go through Git above, so status follows the executable
 * that will consume commit.gpgsign instead of guessing from a version banner. */
static int git_parse_effective_bool(const git_kv_t *entry, const char *key,
                                    bool *value) {
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
    return git_canonicalize_effective_bool(entry->value, key, value);
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

static int git_verify_merged_account(const account_t *account,
                                     const char *expected_gpg_program) {
    git_effective_listing_t *effective;
    char expected_ssh[GIT_CFG_VALUE_MAX];
    bool ssh_present = account->ssh_enabled && account->ssh_key_path[0] != '\0';
    bool gpg_present = account->gpg_enabled && account->gpg_key_id[0] != '\0';

    if (git_reject_ssh_command_override() != 0) return -1;
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
        effective_key_matches(effective, GIT_CONFIG_GPG_FORMAT,
                              GIT_GPG_FORMAT_OPENPGP, true) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective merged Git configuration does not match the selected account");
        return -1;
    }
    if (effective_key_matches(effective, GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                              expected_gpg_program,
                              expected_gpg_program != NULL) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_GPG_PROGRAM, NULL,
                              false) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_GPG_X509_PROGRAM, NULL,
                              false) != 0 ||
        effective_key_matches(effective, GIT_CONFIG_GPG_SSH_PROGRAM, NULL,
                              false) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective merged Git GPG program configuration does not match the selected account");
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
    const int k_gpgformat = cfg_key_index(GIT_CONFIG_GPG_FORMAT);
    const int k_gpgprogram = cfg_key_index(GIT_CONFIG_GPG_PROGRAM);
    const int k_gpgopenpgp = cfg_key_index(GIT_CONFIG_GPG_OPENPGP_PROGRAM);
    const int k_gpgx509 = cfg_key_index(GIT_CONFIG_GPG_X509_PROGRAM);
    const int k_gpgssh = cfg_key_index(GIT_CONFIG_GPG_SSH_PROGRAM);
    const int k_sshcommand = cfg_key_index(GIT_CONFIG_CORE_SSHCOMMAND);

    if (!config) {
        set_error(ERR_INVALID_ARGS, "NULL config to git_get_current_config");
        return -1;
    }

    /* Initialize structure */
    memset(config, 0, sizeof(git_current_config_t));
    config->valid = false;
    if (git_reject_ssh_command_override() != 0) return -1;

    if (k_name < 0 || k_email < 0 || k_signkey < 0 || k_gpgsign < 0 ||
        k_gpgformat < 0 || k_gpgprogram < 0 || k_gpgopenpgp < 0 ||
        k_gpgx509 < 0 || k_gpgssh < 0 || k_sshcommand < 0) {
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
        effective->keys[k_gpgformat].value_unknown ||
        effective->keys[k_sshcommand].value_unknown ||
        effective->keys[k_gpgprogram].value_unknown ||
        effective->keys[k_gpgopenpgp].value_unknown ||
        effective->keys[k_gpgx509].value_unknown ||
        effective->keys[k_gpgssh].value_unknown) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "An effective managed Git value exceeds the supported status representation");
        return -1;
    }

    /* Absence is Git's OpenPGP default and remains status-compatible before a
     * first switch. Any explicit non-OpenPGP value changes how Git interprets
     * user.signingKey, so report it before a missing identity can disguise the
     * unsafe signing model as a routine NOT FOUND state. */
    if (effective->keys[k_gpgformat].present &&
        (effective->keys[k_gpgformat].implicit ||
         strcmp(effective->keys[k_gpgformat].value,
                GIT_GPG_FORMAT_OPENPGP) != 0)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective gpg.format is not openpgp");
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
    config->effective_signing_key_scope = effective->scopes[k_signkey];
    snprintf(config->effective_signing_key_origin,
             sizeof(config->effective_signing_key_origin), "%s",
             effective->origins[k_signkey]);
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
    copy_effective_value(&config->gpg_openpgp_program, effective,
                         k_gpgopenpgp);
    copy_effective_value(&config->gpg_x509_program, effective, k_gpgx509);
    copy_effective_value(&config->gpg_ssh_program, effective, k_gpgssh);

    config->valid = true;
    return 0;
}

/* Clear git configuration */
int git_clear_config(git_scope_t scope) {
    const char *scope_flag;
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
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (git_unset_config_value(g_managed_keys[i], scope) != 0) {
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

/* See git_ops.h. Selector resolution belongs to activation; ownership checks
 * accept only complete canonical fingerprints. */
bool git_signing_key_matches_fingerprint(const char *fingerprint,
                                         const char *configured) {
    size_t fingerprint_len;
    size_t configured_len;
    size_t i;

    if (!fingerprint || !configured) return false;
    fingerprint_len = strlen(fingerprint);
    configured_len = strlen(configured);
    if ((fingerprint_len != 40 && fingerprint_len != 64) ||
        configured_len != fingerprint_len) {
        return false;
    }
    for (i = 0; i < fingerprint_len; i++) {
        if (!isxdigit((unsigned char)fingerprint[i]) ||
            !isxdigit((unsigned char)configured[i])) {
            return false;
        }
    }
    return strcasecmp(configured, fingerprint) == 0;
}

bool git_signing_key_selects_account(const account_t *account,
                                     const char *configured) {
    if (!account || !account->gpg_enabled) return false;
    return git_signing_key_matches_fingerprint(account->gpg_key_id,
                                               configured);
}

static bool git_publication_scope_matches_origin(
    publication_scope_t publication_scope,
    git_config_origin_scope_t origin_scope) {
    switch (publication_scope) {
        case PUBLICATION_SCOPE_LOCAL:
            return origin_scope == GIT_CONFIG_ORIGIN_LOCAL;
        case PUBLICATION_SCOPE_GLOBAL:
            return origin_scope == GIT_CONFIG_ORIGIN_GLOBAL;
        case PUBLICATION_SCOPE_WORKTREE:
            return origin_scope == GIT_CONFIG_ORIGIN_WORKTREE;
        default:
            return false;
    }
}

static bool git_publication_origin_matches_path(
    const char *origin_path, const publication_record_t *publication) {
    char canonical[MAX_PATH_LEN];
    char repository_relative[MAX_PATH_LEN];
    const char *candidate = origin_path;
    int written;

    if (!origin_path || !publication || publication->config_path[0] != '/') {
        return false;
    }
    if (strcmp(origin_path, publication->config_path) == 0) return true;
    /* Git may report a logical symlink spelling or a repository-relative
     * local origin. Relative local/worktree origins are rooted at Git's
     * canonical repository top level, not at the process's current
     * subdirectory. Global relative origins and resolution failure are
     * unknown provenance, never a match. */
    if (origin_path[0] != '/') {
        if ((publication->scope != PUBLICATION_SCOPE_LOCAL &&
             publication->scope != PUBLICATION_SCOPE_WORKTREE) ||
            publication->repository_path[0] != '/') {
            return false;
        }
        written = snprintf(repository_relative,
                           sizeof(repository_relative), "%s/%s",
                           publication->repository_path, origin_path);
        if (written < 0 || (size_t)written >= sizeof(repository_relative)) {
            return false;
        }
        candidate = repository_relative;
    }
    return realpath(candidate, canonical) != NULL &&
           strcmp(canonical, publication->config_path) == 0;
}

git_signing_publication_result_t git_signing_key_matches_publication(
    const account_t *account, const publication_record_t *publication,
    const git_current_config_t *current) {
    static const char file_origin_prefix[] = "file:";
    char normalized_selector[MAX_GPG_SELECTOR_LEN];
    const char *origin_path;

    if (!account || !publication || !current || !account->gpg_enabled ||
        !account->incarnation_persisted ||
        publication->account_id != account->id ||
        strcmp(publication->account_incarnation,
               account->incarnation) != 0 ||
        publication->state != PUBLICATION_STATE_PUBLISHED ||
        (publication->capabilities &
         (PUBLICATION_CAP_DESTINATION |
          PUBLICATION_CAP_POST_GENERATION |
          PUBLICATION_CAP_GPG_FINGERPRINT |
          PUBLICATION_CAP_GPG_PROGRAM |
          PUBLICATION_CAP_GPG_SELECTOR)) !=
            (PUBLICATION_CAP_DESTINATION |
             PUBLICATION_CAP_POST_GENERATION |
             PUBLICATION_CAP_GPG_FINGERPRINT |
             PUBLICATION_CAP_GPG_PROGRAM |
             PUBLICATION_CAP_GPG_SELECTOR)) {
        return GIT_SIGNING_PUBLICATION_MISMATCH;
    }

    /* Once a complete publication tuple is established for this account,
     * malformed current account input is an operational ERROR regardless of
     * any additional destination or fingerprint mismatch. Otherwise the same
     * invalid selector could be reported as WARN or ERROR merely according to
     * which unrelated comparison happened to run first. */
    if (publication_normalize_gpg_selector(
            account->gpg_key_id, normalized_selector) != 0) {
        return GIT_SIGNING_PUBLICATION_ERROR;
    }
    if (
        !git_publication_scope_matches_origin(
            publication->scope, current->effective_signing_key_scope) ||
        strncmp(current->effective_signing_key_origin, file_origin_prefix,
                sizeof(file_origin_prefix) - 1U) != 0) {
        return GIT_SIGNING_PUBLICATION_MISMATCH;
    }
    origin_path = current->effective_signing_key_origin +
                  sizeof(file_origin_prefix) - 1U;
    if (!git_publication_origin_matches_path(origin_path, publication) ||
        !git_signing_key_matches_fingerprint(
            publication->gpg_fingerprint, current->signing_key)) {
        return GIT_SIGNING_PUBLICATION_MISMATCH;
    }

    /* The switch-time selector is part of the durable tuple precisely so
     * status remains observational when a valid isolated key outlives its
     * source keyring. Only representation-neutral case/0x normalization is
     * allowed; selector length and every digit remain significant. */
    return strcmp(publication->gpg_selector, normalized_selector) == 0
               ? GIT_SIGNING_PUBLICATION_MATCH
               : GIT_SIGNING_PUBLICATION_MISMATCH;
}

git_ssh_publication_result_t git_ssh_command_matches_publication(
    const account_t *account, const publication_record_t *publication,
    const git_current_config_t *current) {
    static const char file_origin_prefix[] = "file:";
    char current_account_command[GIT_CFG_VALUE_MAX];
    char expanded_path[MAX_PATH_LEN];
    const char *origin_path;
    const uint32_t required_capabilities =
        PUBLICATION_CAP_DESTINATION |
        PUBLICATION_CAP_POST_GENERATION |
        PUBLICATION_CAP_SSH_COMMAND |
        PUBLICATION_CAP_SSH_PROGRAM;

    if (!account || !publication || !current || !account->ssh_enabled ||
        account->ssh_key_path[0] == '\0' ||
        !account->incarnation_persisted ||
        publication->account_id != account->id ||
        strcmp(publication->account_incarnation,
               account->incarnation) != 0 ||
        publication->state != PUBLICATION_STATE_PUBLISHED ||
        (publication->capabilities & required_capabilities) !=
            required_capabilities) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Complete SSH publication provenance is unavailable");
        return GIT_SSH_PUBLICATION_ERROR;
    }
    if (publication_record_validate(publication) != 0) {
        return GIT_SSH_PUBLICATION_ERROR;
    }

    if (build_expected_ssh_command_with_program(
            account, publication->ssh_program, current_account_command,
            sizeof(current_account_command), expanded_path,
            sizeof(expanded_path)) != 0 ||
        git_publication_verify_program_identity(
            publication->ssh_program, &publication->ssh_program_identity,
            "SSH") != 0) {
        return GIT_SSH_PUBLICATION_ERROR;
    }

    if (strcmp(current_account_command, publication->ssh_command) != 0 ||
        !current->ssh_command.present ||
        current->ssh_command.value_unknown ||
        strcmp(current->ssh_command.value, publication->ssh_command) != 0 ||
        !git_publication_scope_matches_origin(
            publication->scope, current->ssh_command.scope) ||
        strncmp(current->ssh_command.origin, file_origin_prefix,
                sizeof(file_origin_prefix) - 1U) != 0) {
        return GIT_SSH_PUBLICATION_MISMATCH;
    }
    origin_path = current->ssh_command.origin +
                  sizeof(file_origin_prefix) - 1U;
    return git_publication_origin_matches_path(origin_path, publication)
               ? GIT_SSH_PUBLICATION_MATCH
               : GIT_SSH_PUBLICATION_MISMATCH;
}

/* Unset one attributed credential key for git_retire_account_identity,
 * preserving the first diagnostic and counting only keys that were present.
 * first_error must be larger than an error message plus the "scope key: "
 * prefix (see the caller) so the diagnostic never truncates. */
static void git_retire_unset(const char *path, const char *key,
                             git_scope_t scope,
                             size_t *removed, int *failures,
                             char *first_error, size_t first_error_size) {
    if (git_config_file_unset(path, key, true,
                              "recorded publication destination") != 0) {
        if (*failures == 0) {
            snprintf(first_error, first_error_size, "%s %s: %s",
                     git_scope_diagnostic_label(scope), key,
                     get_last_error()->message);
        }
        (*failures)++;
        return;
    }
    (*removed)++;
}

static int git_retire_account_identity_with_fingerprint(
    const account_t *account, const char *canonical_fingerprint,
    const char *published_ssh_command, git_scope_t published_scope,
    const char *config_path,
    size_t *cleared) {
    char value[GIT_CFG_VALUE_MAX];
    /* Wide enough for a full error message plus the "scope key: " prefix
     * git_retire_unset prepends (gcc's -Wformat-truncation checks this). */
    char first_error[sizeof(g_last_error.message) + 64] = "";
    int failures = 0;
    size_t removed = 0;

    if (cleared) *cleared = 0;
    if (!account) {
        set_error(ERR_INVALID_ARGS,
                  "NULL account to git_retire_account_identity");
        return -1;
    }

    {
        git_scope_t scope = published_scope;

        /* Retirement uses the exact sealed command as a scalar ownership
         * witness. It intentionally does not stat, execute, or re-resolve the
         * recorded SSH program: relocation/removal cannot strand a matching
         * Git value, while an unequal foreign replacement remains untouched. */
        if (published_ssh_command && published_ssh_command[0] != '\0' &&
            git_config_file_get_all(config_path,
                                    GIT_CONFIG_CORE_SSHCOMMAND, value,
                                    sizeof(value)) == 0 &&
            strcmp(value, published_ssh_command) == 0) {
            git_retire_unset(config_path, GIT_CONFIG_CORE_SSHCOMMAND, scope,
                             &removed, &failures, first_error,
                             sizeof(first_error));
        }

        /* The signing key attributes the whole signing leg: its enable flag
         * and the format normalization a switch wrote alongside it belong to
         * the same retired identity, so retire them at the same scope. A
         * foreign or noncanonical value attributes nothing. */
        if (git_config_file_get_all(config_path,
                                    GIT_CONFIG_USER_SIGNINGKEY, value,
                                    sizeof(value)) == 0 &&
            git_signing_key_matches_fingerprint(canonical_fingerprint,
                                                value)) {
            git_retire_unset(config_path, GIT_CONFIG_USER_SIGNINGKEY, scope,
                             &removed, &failures, first_error,
                             sizeof(first_error));
            if (git_config_file_get_all(config_path,
                                        GIT_CONFIG_COMMIT_GPGSIGN, value,
                                        sizeof(value)) == 0) {
                git_retire_unset(config_path, GIT_CONFIG_COMMIT_GPGSIGN,
                                 scope, &removed, &failures, first_error,
                                 sizeof(first_error));
            }
            if (git_config_file_get_all(config_path, GIT_CONFIG_GPG_FORMAT,
                                        value, sizeof(value)) == 0) {
                git_retire_unset(config_path, GIT_CONFIG_GPG_FORMAT, scope,
                                 &removed, &failures, first_error,
                                 sizeof(first_error));
            }
            /* The account-owned signing key is the attribution anchor for
             * the OpenPGP executable published by the same switch. Other
             * format selectors are foreign configuration and must survive. */
            if (git_config_file_get_all(
                    config_path, GIT_CONFIG_GPG_OPENPGP_PROGRAM, value,
                    sizeof(value)) == 0) {
                git_retire_unset(config_path,
                                 GIT_CONFIG_GPG_OPENPGP_PROGRAM, scope,
                                 &removed, &failures, first_error,
                                 sizeof(first_error));
            }
        }
    }

    if (cleared) *cleared = removed;
    if (removed > 0) {
        log_info("Retired %zu durable Git identity key(s) selecting '%s'",
                 removed, account->name);
    }
    if (failures != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to retire %d durable Git identity key(s) for "
                  "'%s': %s",
                  failures, account->name,
                  first_error[0] ? first_error : "unknown Git error");
        return -1;
    }
    return 0;
}

/* See git_ops.h. No credential mutation is attributable without the sealed
 * command/fingerprint, exact destination, and publication generation. */
int git_retire_account_identity(const account_t *account, size_t *cleared) {
    if (cleared) *cleared = 0;
    if (!account) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "NULL account to git_retire_account_identity");
        return -1;
    }
    errno = ESTALE;
    set_error(ERR_GIT_CONFIG_FAILED,
              "Durable Git publication provenance is required for retirement");
    return -1;
}

static int git_scope_from_publication(publication_scope_t publication_scope,
                                      git_scope_t *scope) {
    if (!scope) return -1;
    switch (publication_scope) {
        case PUBLICATION_SCOPE_LOCAL:
            *scope = GIT_SCOPE_LOCAL;
            return 0;
        case PUBLICATION_SCOPE_GLOBAL:
            *scope = GIT_SCOPE_GLOBAL;
            return 0;
        case PUBLICATION_SCOPE_WORKTREE:
            *scope = GIT_SCOPE_WORKTREE_INTERNAL;
            return 0;
        default:
            return -1;
    }
}

static int git_retire_validate_publication(
    const account_t *account, const publication_record_t *publication,
    git_scope_t *scope) {
    if (!account || !publication || !scope ||
        !account->incarnation_persisted) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Account has no exact durable Git publication provenance");
        return -1;
    }
    if (publication_record_validate(publication) != 0) return -1;
    if (publication->account_id != account->id ||
        strcmp(publication->account_incarnation,
               account->incarnation) != 0 ||
        (publication->capabilities &
         (PUBLICATION_CAP_DESTINATION |
          PUBLICATION_CAP_POST_GENERATION)) !=
            (PUBLICATION_CAP_DESTINATION |
             PUBLICATION_CAP_POST_GENERATION) ||
        publication->state != PUBLICATION_STATE_PUBLISHED ||
        git_scope_from_publication(publication->scope, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Account has no exact durable Git publication provenance");
        return -1;
    }
    if ((publication->capabilities &
         PUBLICATION_CAP_GPG_FINGERPRINT) != 0U &&
        !git_signing_key_matches_fingerprint(
            publication->gpg_fingerprint,
            publication->gpg_fingerprint)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Publication record has no canonical signing fingerprint");
        return -1;
    }
    return 0;
}

/* Attribution and destination generations have already been validated by the
 * caller. Keeping this leg free of another generation probe lets linked
 * worktree records sharing one config file contribute every sealed credential
 * witness after the first successful unset rewrites that file. */
static int git_retire_account_identity_publication_unchecked(
    const account_t *account, const publication_record_t *publication,
    size_t *cleared) {
    git_scope_t scope;
    const char *fingerprint = NULL;
    const char *ssh_command = NULL;

    if (git_retire_validate_publication(account, publication, &scope) != 0) {
        if (cleared) *cleared = 0;
        return -1;
    }
    if ((publication->capabilities &
         PUBLICATION_CAP_GPG_FINGERPRINT) != 0U) {
        fingerprint = publication->gpg_fingerprint;
    }
    if ((publication->capabilities & PUBLICATION_CAP_SSH_COMMAND) != 0U) {
        ssh_command = publication->ssh_command;
    }
    return git_retire_account_identity_with_fingerprint(
        account, fingerprint, ssh_command, scope, publication->config_path,
        cleared);
}

int git_retire_account_identity_published(
    const account_t *account, const publication_record_t *publication,
    size_t *cleared) {
    const publication_record_t *records[1];
    git_scope_t scope;

    if (cleared) *cleared = 0;
    if (git_retire_validate_publication(account, publication, &scope) != 0) {
        return -1;
    }
    records[0] = publication;
    if (publication_record_verify_live_destination(
            publication, records, 1U, NULL) != 0) {
        return -1;
    }
    return git_retire_account_identity_publication_unchecked(
        account, publication, cleared);
}

int git_retire_account_identity_publications(
    const account_t *account,
    const publication_record_t *const publications[],
    size_t publication_count, size_t *cleared) {
    error_accumulator_t destination_errors;
    bool ready[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    bool processed[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    size_t total_cleared = 0U;
    size_t failure_count = 0U;

    if (cleared) *cleared = 0;
    if (!account || !publications || publication_count == 0U ||
        publication_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid durable Git publication retirement set");
        return -1;
    }

    /* Reject every malformed, tombstoned, or differently owned record before
     * any filesystem probe or Git subprocess can mutate a destination. */
    for (size_t i = 0; i < publication_count; i++) {
        git_scope_t ignored_scope;

        if (git_retire_validate_publication(
                account, publications[i], &ignored_scope) != 0) {
            return -1;
        }
    }

    error_accumulator_init(&destination_errors);
    /* Preflight every repository witness before the first Git subprocess. A
     * linked-worktree record may use the current generation sealed by another
     * record for the same stable physical config namespace. */
    for (size_t i = 0; i < publication_count; i++) {
        git_scope_t scope = GIT_SCOPE_GLOBAL;
        char label[64];

        (void)git_scope_from_publication(publications[i]->scope, &scope);
        if (publication_record_verify_live_destination(
                publications[i], publications, publication_count,
                NULL) == 0) {
            ready[i] = true;
            continue;
        }
        (void)snprintf(label, sizeof(label), "destination %zu (%s)",
                       i + 1U, git_scope_diagnostic_label(scope));
        (void)error_accumulator_add_last(&destination_errors, label);
        failure_count++;
    }

    for (size_t i = 0; i < publication_count; i++) {
        bool any_ready = false;

        if (processed[i]) continue;
        for (size_t j = i; j < publication_count; j++) {
            if (publication_record_same_config_destination(
                    publications[i], publications[j])) {
                processed[j] = true;
                if (ready[j]) any_ready = true;
            }
        }
        if (!any_ready) continue;

        /* The group has at least one live repository witness and an exact
         * matching config generation. Try every persisted credential witness
         * against that one file without re-preflighting after each rewrite. */
        for (size_t j = i; j < publication_count; j++) {
            git_scope_t scope = GIT_SCOPE_GLOBAL;
            size_t record_cleared = 0U;
            char label[80];

            if (!publication_record_same_config_destination(
                    publications[i], publications[j])) {
                continue;
            }
            (void)git_scope_from_publication(publications[j]->scope, &scope);
            if (git_retire_account_identity_publication_unchecked(
                    account, publications[j], &record_cleared) != 0) {
                (void)snprintf(label, sizeof(label),
                               "destination %zu witness (%s)", j + 1U,
                               git_scope_diagnostic_label(scope));
                (void)error_accumulator_add_last(&destination_errors, label);
                failure_count++;
            }
            total_cleared += record_cleared;
        }
    }

    if (cleared) *cleared = total_cleared;
    if (failure_count != 0U) {
        error_context_t summary;

        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Git retirement for '%s' cleared %zu key(s), but %zu operation(s) across %zu recorded destination(s) failed",
            account->name, total_cleared, failure_count, publication_count);
        summary = *get_last_error();
        (void)error_accumulator_add(&destination_errors,
                                    "retirement summary", &summary);
        (void)error_accumulator_publish(&destination_errors);
        return -1;
    }
    return 0;
}

/* AR-06 F59: git_validate_repository() and git_get_config_scope() were removed
 * here — both were public API with zero callers anywhere in the tree (dead
 * code, and git_get_config_scope's system-scope arm implied a scope model the
 * rest of git_ops does not use). */

/* Validate the account model Git will actually consume. */
int git_test_config(const account_t *account, git_scope_t scope,
                    const char *expected_gpg_program) {
    bool gpg_expected;

    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to git_test_config");
        return -1;
    }
    if (!git_scope_to_flag(scope)) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    gpg_expected = account->gpg_enabled && account->gpg_key_id[0] != '\0';
    if (gpg_expected) {
        if (!expected_gpg_program || expected_gpg_program[0] != '/') {
            set_error(ERR_INVALID_ARGS,
                      "GPG-enabled Git validation requires the bound absolute OpenPGP program");
            return -1;
        }
    } else if (expected_gpg_program && expected_gpg_program[0] != '\0') {
        set_error(ERR_INVALID_ARGS,
                  "Git validation received a GPG program for an account without GPG");
        return -1;
    }

    log_info("Testing git configuration for account: %s", account->name);

    /* Reuse the switch path's strict merged-account model: exact identity,
     * SSH command, signing key/state and format, with the exact bound OpenPGP
     * program and no foreign program selectors. A selected-scope-only read is
     * insufficient because a higher-precedence scope may override the values
     * Git uses. */
    if (git_verify_merged_account(account,
                                  gpg_expected ? expected_gpg_program : NULL) != 0)
        return -1;

    /* Check local key availability when signing is configured. This does not
     * create a commit or signature; functional signing must be tested by a
     * caller that explicitly owns those side effects. Which keyring gpg
     * consults is decided by GNUPGHOME — by the time a switch validates itself
     * that is already the account's isolated home. The probe is skipped when
     * an earlier spawn already proved the key's presence (AR-02 #14). */
    if (gpg_expected &&
        !gpg_manager_key_available_cached(account->gpg_key_id)) {
        const char *gpg_argv[] = {
            expected_gpg_program, "--list-secret-keys",
            account->gpg_key_id, NULL
        };
        run_opts_t gpg_opts;
        memset(&gpg_opts, 0, sizeof(gpg_opts));
        gpg_opts.stderr_to_devnull = true;
        if (run_argv(gpg_argv, &gpg_opts, NULL) != 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available: %s",
                      account->gpg_key_id);
            return -1;
        }
        gpg_manager_note_key_available(account->gpg_key_id);
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
    git_transaction_vector_update_t post_update;

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
    if (git_transaction_require_write_allowed(scope, key) != 0) return -1;

    /* perf-3: on a GPG switch, user.signingkey and commit.gpgsign are written
     * once by git_configure_gpg and again (same values) by gpg_manager's
     * gpg_configure_git_signing. Skip a write ONLY when this process already
     * ran the identical write successfully — re-execing it could only repeat
     * the first result, so the config outcome is provably unchanged. A value
     * merely observed (CFG_OBSERVED) never suppresses a write: e.g. on a
     * multi-valued key the read succeeds but the write would fail, and that
     * failure must surface. */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (s >= 0 && k >= 0 && g_cfg_cache[s][k].state == CFG_WRITTEN &&
        g_cfg_cache[s][k].present && strcmp(g_cfg_cache[s][k].value, value) == 0) {
        log_debug("Skipping git config %s: identical value already written by this process", key);
        return git_transaction_record_vector(scope, key, true, value);
    }

    if (git_transaction_prepare_vector(scope, key, true, value,
                                       &post_update) != 0) {
        return -1;
    }
    log_debug("Setting git config: %s = %s (%s)", key, value, scope_flag);

    if (git_run(output, sizeof(output), "config", scope_flag, key, value,
                (const char *)NULL) != 0) {
        git_transaction_discard_vector(&post_update);
        /* The key's on-disk state is now uncertain; never skip/serve it. */
        cfg_cache_store(s, k, CFG_UNKNOWN, false, "");
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git config %s: %s", key, output);
        return -1;
    }

    git_transaction_commit_vector(&post_update);
    cfg_cache_store(s, k, CFG_WRITTEN, true, value);
    return 0;
}

int git_set_config_value(const char *key, const char *value, git_scope_t scope) {
    int result = git_set_config_value_impl(key, value, scope, false);
    if (result == 0) git_taint_publication_after_raw_write(scope, key);
    return result;
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
    /* Big enough for any managed status value plus git's trailing newline;
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
    /* M22: every public read executes Git. A value observed earlier in this
     * process is not authority after another process can edit the same config
     * file. Keep only conservative write/snapshot bookkeeping, and invalidate
     * it from the result below so a read boundary cannot make a later write or
     * unset skip based on older state. */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);

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
        cfg_cache_store(s, k, CFG_UNKNOWN, !clean_absent, "");
        if (!clean_absent && value_too_long) {
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
     * callers can't read an uninitialized stack buffer while we report success. */
    if (safe_strncpy(value, output, value_size) != 0) {
        cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
        if (value_too_long) {
            *value_too_long = true;
        }
        value[0] = '\0';
        return -1;
    }

    cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
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
    if (!force &&
        git_transaction_require_write_allowed(scope, key) != 0) {
        return -1;
    }

    /* Skip an unset the cache proves is a no-op: this process already unset
     * the key itself (CFG_WRITTEN/absent — the original duplicate-unset
     * skip), or a complete --list -z snapshot observed the key absent
     * (CFG_OBSERVED/absent, seeded by exact snapshot capture — AR-02 #15: the
     * global-switch clear-local step used to blindly re-exec six unsets the
     * snapshot one exec earlier had just proved unnecessary). */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (!force && s >= 0 && k >= 0 && !g_cfg_cache[s][k].present &&
        (g_cfg_cache[s][k].state == CFG_WRITTEN ||
         g_cfg_cache[s][k].state == CFG_OBSERVED)) {
        log_debug("Skipping git config --unset %s: known absent in this process", key);
        return git_transaction_record_vector(scope, key, false, "");
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
            if (!force) {
                return git_transaction_record_vector(scope, key, false, "");
            }
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
    int result = git_unset_config_value_impl(key, scope, false);
    if (result == 0) git_taint_publication_after_raw_write(scope, key);
    return result;
}

/* List all git configuration values */
int git_list_config(git_scope_t scope, char *output, size_t output_size) {
    const char *scope_flag;
    run_opts_t opts;
    run_result_t result;

    if (!output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_list_config");
        return -1;
    }

    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }

    {
        const char *argv[] = {
            "git", "config", scope_flag, "--list", NULL
        };
        memset(&opts, 0, sizeof(opts));
        memset(&result, 0, sizeof(result));
        output[0] = '\0';
        opts.out = output;
        opts.out_size = output_size;
        opts.merge_stderr = true;
        if (run_argv(argv, &opts, &result) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Failed to list git configuration");
            return -1;
        }
    }
    if (result.out_truncated) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git configuration listing was truncated by the %zu-byte output buffer",
                  output_size);
        return -1;
    }
    if (result.out_len >= output_size) {
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
    " -F none -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"     \
    " -o LogLevel=ERROR"
#define SSH_COMMAND_HOSTNAME_OPTION " -o HostName="

/* GIT_CONFIG_VALUE_MAX reserves 256 bytes beyond the serialized path and
 * hostname payloads. Prove at compile time that the exact fixed spelling, six
 * quote delimiters, and terminating NUL fit inside that reserve. */
_Static_assert((sizeof(" -i ") - 1U) + (sizeof(SSH_COMMAND_OPTIONS) - 1U) +
                       (sizeof(SSH_COMMAND_HOSTNAME_OPTION) - 1U) + 6U + 1U <=
                   256U,
               "GIT_CONFIG_VALUE_MAX fixed SSH command reserve is too small");

static int build_expected_ssh_command(const account_t *account,
                                      char *command, size_t command_size,
                                      char *expanded_path,
                                      size_t expanded_path_size) {
    char ssh_path[MAX_PATH_LEN];

    if (find_command_path("ssh", ssh_path, sizeof(ssh_path)) != 0) {
        set_error(ERR_SSH_NOT_FOUND,
                  "No trusted SSH executable was found in PATH");
        return -1;
    }
    return build_expected_ssh_command_with_program(
        account, ssh_path, command, command_size, expanded_path,
        expanded_path_size);
}

/* Serialize the current account model using a previously proven absolute SSH
 * executable. Status uses this path from the publication ledger so account
 * key/hostname edits remain visible without repeating PATH resolution. */
static int build_expected_ssh_command_with_program(
    const account_t *account, const char *ssh_path, char *command,
    size_t command_size, char *expanded_path, size_t expanded_path_size) {
    size_t used = 0;
    bool has_alias;

    if (!account || !account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        set_error(ERR_INVALID_ARGS,
                  "SSH command requested for an account without an SSH key");
        return -1;
    }
    if (!ssh_path || ssh_path[0] != '/' || !command || command_size == 0 ||
        !expanded_path || expanded_path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH command output buffer");
        return -1;
    }
    command[0] = '\0';

    has_alias = account->ssh_host_alias[0] != '\0';
    if (has_alias &&
        (!toml_validate_ssh_host_alias(account->ssh_host_alias) ||
         !toml_validate_ssh_hostname(account->ssh_hostname))) {
        set_error(ERR_INVALID_ARGS,
                  "Managed SSH alias requires a valid alias and canonical "
                  "hostname");
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

    /* The caller either just resolved this executable through the hardened
     * trust walk or loaded the exact switch-time spelling from a validated
     * publication record. Never substitute a new PATH result here. */
    for (const unsigned char *byte = (const unsigned char *)ssh_path;
         *byte; byte++) {
        if (*byte < 0x20 || *byte == 0x7f) {
            set_error(ERR_INVALID_PATH,
                      "Trusted SSH executable path contains a control character");
            return -1;
        }
    }

    if (ssh_command_append_quoted(command, command_size, &used, ssh_path) != 0 ||
        ssh_command_append(command, command_size, &used, " -i ") != 0 ||
        ssh_command_append_quoted(command, command_size, &used,
                                  expanded_path) != 0 ||
        ssh_command_append(command, command_size, &used,
                           SSH_COMMAND_OPTIONS) != 0) {
        return -1;
    }
    if (has_alias &&
        (ssh_command_append(command, command_size, &used,
                            SSH_COMMAND_HOSTNAME_OPTION) != 0 ||
         ssh_command_append_quoted(command, command_size, &used,
                                   account->ssh_hostname) != 0)) {
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
static int git_configure_ssh_impl(const account_t *account,
                                  git_scope_t scope) {
    char ssh_command[GIT_CFG_VALUE_MAX];
    char expanded_key_path[MAX_PATH_LEN];

    if (!account || !account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        return 0; /* Nothing to configure */
    }
    if (git_reject_ssh_command_override() != 0) return -1;

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
     * user.email verification in git_set_config. Public reads always execute
     * Git, so this proves the authoritative SSH identity is the one just
     * written. */
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

int git_configure_ssh(const account_t *account, git_scope_t scope) {
    int result;

    if (git_account_write_begin(account, scope) != 0) return -1;
    result = git_configure_ssh_impl(account, scope);
    git_account_write_end();
    return result;
}

/* Configure GPG for git operations */
static int git_configure_gpg_impl(const account_t *account,
                                  git_scope_t scope) {
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

int git_configure_gpg(const account_t *account, git_scope_t scope) {
    int result;

    if (git_account_write_begin(account, scope) != 0) return -1;
    result = git_configure_gpg_impl(account, scope);
    git_account_write_end();
    return result;
}

int git_configure_openpgp_publication(const account_t *account,
                                      const char *gpg_program,
                                      git_scope_t scope) {
    const char *signing_value;
    bool may_restore_complete_image;
    int result = -1;

    if (!account || !account->gpg_enabled ||
        !git_signing_key_matches_fingerprint(account->gpg_key_id,
                                             account->gpg_key_id) ||
        !gpg_program || gpg_program[0] != '/' ||
        strnlen(gpg_program, MAX_PATH_LEN) >= MAX_PATH_LEN ||
        !is_valid_git_config_value(gpg_program)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid canonical OpenPGP publication request");
        return -1;
    }
    may_restore_complete_image =
        git_snapshot_publication_is_complete_for(account, scope);
    if (git_account_write_begin(account, scope) != 0) return -1;
    signing_value = account->gpg_signing_enabled ? "true" : "false";

    if (git_set_config_value(GIT_CONFIG_USER_SIGNINGKEY,
                             account->gpg_key_id, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git signing key");
        goto cleanup;
    }
    if (git_set_config_value(GIT_CONFIG_COMMIT_GPGSIGN,
                             signing_value, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set commit.gpgsign=%s",
                  signing_value);
        goto cleanup;
    }
    if (git_unset_config_value(GIT_CONFIG_GPG_PROGRAM, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear gpg.program");
        goto cleanup;
    }
    if (git_unset_config_value(GIT_CONFIG_GPG_X509_PROGRAM, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to clear gpg.x509.program");
        goto cleanup;
    }
    if (git_unset_config_value(GIT_CONFIG_GPG_SSH_PROGRAM, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to clear gpg.ssh.program");
        goto cleanup;
    }
    if (git_set_config_value(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                             gpg_program, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to set gpg.openpgp.program");
        goto cleanup;
    }
    result = 0;
    if (may_restore_complete_image &&
        git_snapshot_publication_owner_matches(account) &&
        !g_git_snapshot.publication_owner_tainted) {
        g_git_snapshot.publication_full_image_written = true;
    }

cleanup:
    git_account_write_end();
    return result;
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

/* Get the complete repository root without normalizing valid path bytes. */
int git_get_repo_root(char *path, size_t path_size) {
    char output[MAX_PATH_LEN];
    const char *argv[] = {
        "git", "rev-parse", "--show-toplevel", NULL
    };
    run_opts_t opts;
    run_result_t result;
    size_t length;

    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_get_repo_root");
        return -1;
    }

    /* A failed lookup never leaves prior caller storage looking usable. */
    path[0] = '\0';
    memset(output, 0, sizeof(output));
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;

    if (run_argv(argv, &opts, &result) != 0) {
        set_error(ERR_GIT_NOT_REPOSITORY, "Not in a git repository");
        return -1;
    }

    if (result.out_truncated || result.out_len >= sizeof(output) ||
        memchr(output, '\0', result.out_len) != NULL) {
        set_error(ERR_GIT_REPOSITORY_INVALID,
                  "Git returned an incomplete repository root");
        return -1;
    }

    length = result.out_len;
    if (length > 0 && output[length - 1U] == '\n') {
        length--;
        if (length > 0 && output[length - 1U] == '\r') length--;
    }
    if (length == 0) {
        set_error(ERR_GIT_REPOSITORY_INVALID,
                  "Git returned an empty repository root");
        return -1;
    }
    if (length >= path_size) {
        set_error(ERR_GIT_REPOSITORY_INVALID,
                  "Repository root does not fit the destination buffer");
        return -1;
    }

    memcpy(path, output, length);
    path[length] = '\0';
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
