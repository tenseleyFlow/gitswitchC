/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

/* Select the native namespace needed by descriptor-pinned publication:
 * Darwin's renameatx_np, Linux's renameat2 syscall, and FreeBSD's funlinkat.
 * Strict POSIX feature macros hide the relevant BSD extensions. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#define _GNU_SOURCE 1
#elif !defined(__FreeBSD__)
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "git_ops.h"
#define GITSWITCH_INTERNAL_API
#include "git_ops_internal.h"
#include "git_status_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "error.h"
#include "utils.h"
#include "process_fork_internal.h"
#include "runner_internal.h"
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
/* A restored inode can expose more than one delayed ctime step while FreeBSD
 * UFS closes funlinkat/link/rename witnesses. Every retry below re-proves the
 * complete retained bytes and immutable inode fields; this bound prevents an
 * uncooperative metadata writer from turning reconciliation into a spin. */
#define GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS 8U
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
    pid_t creator_pid;
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

typedef struct {
    char config_leaf[NAME_MAX + 1U];
    char lock_leaf[NAME_MAX + sizeof(".lock")];
    char private_leaf[96];
    int parent_fd;
    int lock_fd;
    struct stat parent_stat;
    struct stat lock_stat;
    unsigned char *marker_data;
    size_t marker_length;
    bool private_created;
    bool canonical_published;
    bool canonical_unlinked;
    bool active;
} git_config_finalization_lock_t;

struct git_config_finalization {
    git_config_finalization_lock_t locks[3];
    size_t count;
    pid_t creator_pid;
    struct git_config_finalization *fork_registry_prev;
    struct git_config_finalization *fork_registry_next;
    bool fork_registry_registered;
};

static git_config_snapshot_t g_git_snapshot;
static git_config_finalization_t *g_git_finalization_registry;
static unsigned int g_git_account_write_depth;
static void git_fork_child_cleanup(void);

static int git_fork_child_cleanup_ensure_registered(void) {
    if (process_fork_child_cleanup_register(git_fork_child_cleanup) == 0) {
        return 0;
    }
    set_system_error(
        ERR_GIT_CONFIG_FAILED,
        "Cannot register Git post-fork descriptor cleanup");
    return -1;
}

static void git_finalization_registry_add(
    git_config_finalization_t *finalization) {
    if (!finalization || finalization->fork_registry_registered) return;
    finalization->fork_registry_prev = NULL;
    finalization->fork_registry_next = g_git_finalization_registry;
    if (g_git_finalization_registry) {
        g_git_finalization_registry->fork_registry_prev = finalization;
    }
    g_git_finalization_registry = finalization;
    finalization->fork_registry_registered = true;
}

static void git_finalization_registry_remove(
    git_config_finalization_t *finalization) {
    if (!finalization || !finalization->fork_registry_registered) return;
    if (finalization->fork_registry_prev) {
        finalization->fork_registry_prev->fork_registry_next =
            finalization->fork_registry_next;
    } else {
        g_git_finalization_registry = finalization->fork_registry_next;
    }
    if (finalization->fork_registry_next) {
        finalization->fork_registry_next->fork_registry_prev =
            finalization->fork_registry_prev;
    }
    finalization->fork_registry_prev = NULL;
    finalization->fork_registry_next = NULL;
    finalization->fork_registry_registered = false;
}
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

typedef enum {
    GIT_RETIREMENT_TEST_LOCKED_READ = 1,
    GIT_RETIREMENT_TEST_BEFORE_REMOVE,
    GIT_RETIREMENT_TEST_BEFORE_PUBLISH,
    GIT_RETIREMENT_TEST_BEFORE_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_CLEANUP,
    GIT_RETIREMENT_TEST_FORCE_EXCHANGE_FALLBACK,
    GIT_RETIREMENT_TEST_CLEANUP_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_EXCHANGE,
    GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH,
    GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE,
    GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE,
    GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE,
    GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_ORIGINAL_UNLINK,
    GIT_RETIREMENT_TEST_FORCE_FALLBACK_LINK_FAILURE,
    GIT_RETIREMENT_TEST_AFTER_FALLBACK_CANONICAL_LINK,
    GIT_RETIREMENT_TEST_AFTER_REVERSE_PUBLISHED_UNLINK,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_AUTHORITY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_TERMINAL_CANONICAL_SYNC,
    GIT_RETIREMENT_TEST_BEFORE_TERMINAL_SECOND_PROOF,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_PUBLISH,
    GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
    GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS,
    GIT_RETIREMENT_TEST_AFTER_STABLE_WITNESS_CLOSE
} git_retirement_test_stage_t;
typedef bool (*git_retirement_test_hook_fn)(
    git_retirement_test_stage_t stage, const char *path,
    const char *key, const char *value);
static git_retirement_test_hook_fn g_retirement_test_hook;
static git_finalization_test_hook_fn g_finalization_test_hook;
static size_t g_terminal_namespace_mutation_count;
static size_t g_terminal_namespace_sync_count;

/* Test seams for deterministic real-Git race coverage. They are deliberately
 * absent from the installed API; tests declare the prototypes locally. */
void git_ops_test_set_restore_prelock_hook(git_restore_test_hook_fn fn);
void git_ops_test_set_restore_locked_hook(git_restore_test_hook_fn fn);
void git_ops_test_set_restore_postpublish_hook(git_restore_test_hook_fn fn);
git_metadata_test_hook_fn git_ops_test_set_metadata_hook(
    git_metadata_test_hook_fn fn);
git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn);
git_finalization_test_hook_fn git_ops_test_set_finalization_hook(
    git_finalization_test_hook_fn fn);
git_snapshot_value_malloc_fn git_ops_test_set_snapshot_value_malloc_fn(
    git_snapshot_value_malloc_fn fn);
size_t git_ops_test_set_cleanup_arena_capacity(size_t capacity);
size_t git_ops_test_set_retirement_prelock_witness_budget(
    size_t capacity);
void git_ops_test_terminal_namespace_activity(
    size_t *mutations, size_t *syncs);
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

git_retirement_test_hook_fn git_ops_test_set_retirement_hook(
    git_retirement_test_hook_fn fn) {
    git_retirement_test_hook_fn previous = g_retirement_test_hook;
    g_retirement_test_hook = fn;
    return previous;
}

git_finalization_test_hook_fn git_ops_test_set_finalization_hook(
    git_finalization_test_hook_fn fn) {
    git_finalization_test_hook_fn previous = g_finalization_test_hook;
    g_finalization_test_hook = fn;
    return previous;
}

void git_ops_test_terminal_namespace_activity(
    size_t *mutations, size_t *syncs) {
    if (mutations) *mutations = g_terminal_namespace_mutation_count;
    if (syncs) *syncs = g_terminal_namespace_sync_count;
}

#define GIT_CLEANUP_ARENA_DEFAULT_SLOTS 4096U
#define GIT_CLEANUP_ARENA_HANDLE_BUDGET 8U
#define GIT_CLEANUP_ARENA_WORD_BITS 64U
#define GIT_CLEANUP_ARENA_WORDS \
    (GIT_CLEANUP_ARENA_DEFAULT_SLOTS / GIT_CLEANUP_ARENA_WORD_BITS)

static size_t g_cleanup_arena_capacity =
    GIT_CLEANUP_ARENA_DEFAULT_SLOTS;

size_t git_ops_test_set_cleanup_arena_capacity(size_t capacity) {
    size_t previous = g_cleanup_arena_capacity;

    g_cleanup_arena_capacity =
        capacity == 0U
            ? GIT_CLEANUP_ARENA_DEFAULT_SLOTS
            : (capacity > GIT_CLEANUP_ARENA_DEFAULT_SLOTS
                   ? GIT_CLEANUP_ARENA_DEFAULT_SLOTS
                   : capacity);
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
    g_finalization_test_hook = NULL;
    g_git_snapshot_value_malloc = malloc;
}

typedef enum {
    GIT_STAGE_WITNESS_CAPTURED = 0,
    GIT_STAGE_WITNESS_ORIGINAL,
    GIT_STAGE_WITNESS_PUBLISHED
} git_stage_witness_kind_t;

typedef struct {
    git_kv_t keys[GIT_MANAGED_KEY_COUNT];
    char origins[GIT_MANAGED_KEY_COUNT][MAX_PATH_LEN];
    git_config_origin_scope_t scopes[GIT_MANAGED_KEY_COUNT];
} git_effective_listing_t;

/* Single-threaded CLI scratch. Keeping the large status representation in
 * .bss avoids adding it to the already substantial status stack frame. */
static git_effective_listing_t g_effective_listing;
static int git_reject_managed_command_overrides(void);

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

/* AR-12 M5: Git's section and variable names are case-insensitive, but the
 * SUBSECTION of a three-part key (gpg.openpgp.program, gpg.ssh.program,
 * gpg.x509.program) is case-sensitive. `[gpg "OpenPGP"] program` is a
 * distinct key Git never consults; folding it into the managed slot made
 * verification and rollback adopt an inert foreign value. Compare the outer
 * parts case-insensitively and the subsection byte-exactly. */
static bool git_managed_key_equals_n(const char *key, size_t key_len,
                                     const char *managed) {
    size_t managed_len = strlen(managed);
    const char *managed_first = strchr(managed, '.');
    const char *managed_last = strrchr(managed, '.');
    const char *key_first;
    const char *key_last = NULL;
    size_t section_len;
    size_t subsection_len;
    size_t variable_len;

    if (key_len != managed_len) return false;
    if (!managed_first || managed_first == managed_last) {
        return strncasecmp(key, managed, key_len) == 0;
    }
    key_first = memchr(key, '.', key_len);
    if (!key_first) return false;
    for (const char *p = key + key_len; p > key;) {
        p--;
        if (*p == '.') {
            key_last = p;
            break;
        }
    }
    if (!key_last || key_first == key_last) return false;
    section_len = (size_t)(managed_first - managed);
    subsection_len = (size_t)(managed_last - managed_first) - 1U;
    variable_len = managed_len - (size_t)(managed_last - managed) - 1U;
    if ((size_t)(key_first - key) != section_len ||
        (size_t)(key_last - key_first) - 1U != subsection_len) {
        return false;
    }
    return strncasecmp(key, managed, section_len) == 0 &&
           strncmp(key_first + 1U, managed_first + 1U,
                   subsection_len) == 0 &&
           strncasecmp(key_last + 1U, managed_last + 1U,
                       variable_len) == 0;
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
            if (git_managed_key_equals_n(record, key_len,
                                         g_managed_keys[i])) {
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
#define GIT_RETIREMENT_PRELOCK_WITNESS_MAX_BYTES (64U * 1024U * 1024U)
static size_t g_retirement_prelock_witness_budget =
    GIT_RETIREMENT_PRELOCK_WITNESS_MAX_BYTES;

size_t git_ops_test_set_retirement_prelock_witness_budget(
    size_t capacity) {
    size_t previous = g_retirement_prelock_witness_budget;

    g_retirement_prelock_witness_budget =
        capacity == 0U
            ? GIT_RETIREMENT_PRELOCK_WITNESS_MAX_BYTES
            : (capacity > GIT_RETIREMENT_PRELOCK_WITNESS_MAX_BYTES
                   ? GIT_RETIREMENT_PRELOCK_WITNESS_MAX_BYTES
                   : capacity);
    return previous;
}

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

static void git_scope_generation_clear_mode(
    git_scope_generation_t *generation, bool inherited) {
    if (!generation) return;
    if (!inherited && generation->valid &&
        generation->parent_fd >= 0) {
        (void)close(generation->parent_fd);
    }
    if (!inherited && generation->valid &&
        generation->repository_fd >= 0) {
        (void)close(generation->repository_fd);
    }
    if (!inherited &&
        generation->post_config_identity_valid &&
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

static void git_scope_generation_clear(git_scope_generation_t *generation) {
    git_scope_generation_clear_mode(generation, false);
}

static void git_snapshot_clear_mode(
    git_config_snapshot_t *snapshot, bool inherited) {
    if (!snapshot) return;
    git_scope_snapshot_clear(&snapshot->primary);
    git_scope_snapshot_clear(&snapshot->local);
    git_scope_snapshot_clear(&snapshot->worktree);
    git_scope_snapshot_clear(&snapshot->post_primary);
    git_scope_snapshot_clear(&snapshot->post_local);
    git_scope_snapshot_clear(&snapshot->post_worktree);
    git_scope_generation_clear_mode(
        &snapshot->primary_generation, inherited);
    git_scope_generation_clear_mode(
        &snapshot->local_generation, inherited);
    git_scope_generation_clear_mode(
        &snapshot->worktree_generation, inherited);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void git_snapshot_clear(git_config_snapshot_t *snapshot) {
    git_snapshot_clear_mode(snapshot, false);
}

static bool git_snapshot_is_inherited(void) {
    return g_git_snapshot.valid &&
           g_git_snapshot.creator_pid != getpid();
}

static int git_snapshot_require_current_owner(const char *operation) {
    if (!git_snapshot_is_inherited()) return 0;
    errno = EINVAL;
    set_error(
        ERR_INVALID_ARGS,
        "Cannot %s an inherited Git configuration transaction",
        operation ? operation : "use");
    return -1;
}

void git_config_abandon_inherited_transaction(void) {
    if (!git_snapshot_is_inherited()) return;
    /* A post-fork child owns copies of descriptors and heap state, never the
     * parent's transaction authority. Forget every raw descriptor number:
     * child code may already have closed and reused it, and inode identity
     * cannot distinguish a same-object reopen from the inherited open file
     * description. Pathname recovery or rollback would mutate namespace
     * owned by the still-live parent. */
    git_snapshot_clear_mode(&g_git_snapshot, true);
    g_git_account_write_depth = 0U;
}

size_t git_ops_test_snapshot_descriptors(int *fds, size_t capacity) {
    const git_scope_generation_t *generations[] = {
        &g_git_snapshot.primary_generation,
        &g_git_snapshot.local_generation,
        &g_git_snapshot.worktree_generation,
    };
    size_t count = 0U;

    for (size_t i = 0U;
         i < sizeof(generations) / sizeof(generations[0]); i++) {
        const git_scope_generation_t *generation = generations[i];
        int retained[3];
        size_t retained_count = 0U;

        if (!generation->valid) continue;
        retained[retained_count++] = generation->parent_fd;
        if (generation->repository_present) {
            retained[retained_count++] = generation->repository_fd;
        }
        if (generation->post_config_identity_valid &&
            generation->post_config_present) {
            retained[retained_count++] = generation->post_config_fd;
        }
        for (size_t j = 0U; j < retained_count; j++) {
            if (retained[j] < 0) continue;
            if (fds && count < capacity) fds[count] = retained[j];
            count++;
        }
    }
    return count;
}

static int git_managed_key_index_n(const char *key, size_t key_len) {
    for (int i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (git_managed_key_equals_n(key, key_len, g_managed_keys[i])) {
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

static size_t git_snapshot_key_exact_count(const git_snapshot_key_t *key,
                                           const char *value) {
    size_t count = 0U;

    if (!key || !value) return 0U;
    for (size_t i = 0U; i < key->count; i++) {
        if (strcmp(key->values[i], value) == 0) count++;
    }
    return count;
}

static int git_snapshot_key_remove_exact_once(git_snapshot_key_t *key,
                                              const char *value) {
    size_t match = SIZE_MAX;

    if (!key || !value) return -1;
    for (size_t i = 0U; i < key->count; i++) {
        if (strcmp(key->values[i], value) != 0) continue;
        if (match != SIZE_MAX) return -1;
        match = i;
    }
    if (match == SIZE_MAX) return -1;
    free(key->values[match]);
    if (match + 1U < key->count) {
        memmove(&key->values[match], &key->values[match + 1U],
                (key->count - match - 1U) * sizeof(*key->values));
    }
    key->count--;
    return 0;
}

/* Parse a complete `git config <scope> --list -z` result. Rollback cannot
 * recreate the spelling of a managed implicit Boolean and therefore rejects
 * it. Retirement edits a copied file in place, so it may retain the occurrence
 * as semantic `true`; that also makes an implicit foreign true conflict with
 * an attributed explicit true before `--fixed-value` could remove both.
 * Every record, including the final one, must be NUL terminated. */
static int git_parse_snapshot_listing(const char *buf, size_t len,
                                      git_scope_snapshot_t *out,
                                      bool retain_implicit) {
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
                if (!retain_implicit) {
                    set_error(ERR_GIT_CONFIG_FAILED,
                              "Cannot exactly snapshot implicit Git value %s",
                              g_managed_keys[key_index]);
                    return -1;
                }
                if (git_snapshot_key_append(&out->keys[key_index],
                                            "true", 4U) != 0) {
                    return -1;
                }
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
        git_parse_snapshot_listing(direct_buf, direct_len, &direct,
                                   false) != 0 ||
        git_read_snapshot_listing(scope, true, &expanded_buf,
                                  &expanded_len) != 0 ||
        git_parse_snapshot_listing(expanded_buf, expanded_len, &expanded,
                                   false) != 0) {
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
    int lock_fd;
    int stage_fd;
    int original_fd;
    int published_fd;
    struct stat parent_stat;
    struct stat logical_stat;
    struct stat lock_stat;
    struct stat stage_stat;
    struct stat original_stat;
    struct stat published_stat;
    unsigned char *stage_data;
    size_t stage_length;
    unsigned char *original_data;
    size_t original_length;
    unsigned char *published_data;
    size_t published_length;
    unsigned char *recovery_marker_data;
    size_t recovery_marker_length;
    char recovery_authority_leaf[96];
    char recovery_lease_leaf[96];
    int recovery_authority_fd;
    struct stat recovery_authority_stat;
    unsigned char *recovery_authority_data;
    size_t recovery_authority_length;
    mode_t target_mode;
    uid_t target_uid;
    gid_t target_gid;
    bool logical_present;
    bool logical_final_symlink;
    bool original_present;
    bool original_witness_valid;
    bool lock_witness_valid;
    bool stage_witness_valid;
    git_stage_witness_kind_t stage_witness_kind;
    bool lock_created;
    bool stage_created;
    bool published;
    bool published_witness_valid;
    bool recovery_marker_published;
    bool recovery_marker_publication_uncertain;
    bool recovery_marker_witness_valid;
    bool recovery_authority_witness_valid;
    bool recovery_lease_created;
    bool detached_original_recovery_required;
    bool freebsd_authority_recovered;
    bool generation_conflict;
} git_scope_lock_t;

static void git_scope_lock_init(git_scope_lock_t *lock) {
    if (!lock) return;
    memset(lock, 0, sizeof(*lock));
    lock->dir_fd = -1;
    lock->lock_fd = -1;
    lock->stage_fd = -1;
    lock->original_fd = -1;
    lock->published_fd = -1;
    lock->recovery_authority_fd = -1;
}

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

    if (fd < 0 || (expected_length > 0U && !expected)) {
        errno = EINVAL;
        return false;
    }
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

static int git_capture_fd_bytes_exact_bounded(
    int fd, unsigned char **data, size_t *length,
    struct stat *identity, uintmax_t max_bytes) {
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
            (uintmax_t)before.st_size > max_bytes) {
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

static int git_capture_fd_bytes_exact(int fd, unsigned char **data,
                                      size_t *length,
                                      struct stat *identity) {
    return git_capture_fd_bytes_exact_bounded(
        fd, data, length, identity, GIT_SNAPSHOT_MAX_BYTES);
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

/* Retirement authority names an already-canonical physical configuration
 * path. Resolve no scope, repository, HOME, or GIT_* state here: doing so
 * could lock a different file from the durable publication destination. */
static int git_scope_lock_resolve_exact_path(const char *path,
                                             git_scope_lock_t *lock) {
    char canonical[MAX_PATH_LEN];
    char *slash;

    if (!path || path[0] != '/' || !lock ||
        safe_strncpy(lock->logical_path, path,
                     sizeof(lock->logical_path)) != 0 ||
        safe_strncpy(lock->path, path, sizeof(lock->path)) != 0 ||
        lstat(path, &lock->logical_stat) != 0 ||
        !S_ISREG(lock->logical_stat.st_mode) ||
        realpath(path, canonical) == NULL || strcmp(canonical, path) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Recorded Git configuration path is no longer canonical: %s",
                  path ? path : "(null)");
        return -1;
    }
    lock->logical_present = true;
    lock->logical_final_symlink = false;
    slash = strrchr(lock->path, '/');
    if (!slash || !slash[1] || strlen(slash + 1U) > NAME_MAX) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid recorded Git configuration path: %s", path);
        return -1;
    }
    if (slash == lock->path) {
        if (safe_strncpy(lock->parent, "/", sizeof(lock->parent)) != 0 ||
            safe_strncpy(lock->logical_parent, "/",
                         sizeof(lock->logical_parent)) != 0) {
            return -1;
        }
    } else {
        size_t parent_length = (size_t)(slash - lock->path);

        if (parent_length >= sizeof(lock->parent)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Recorded Git configuration parent path is too long");
            return -1;
        }
        memcpy(lock->parent, lock->path, parent_length);
        lock->parent[parent_length] = '\0';
        memcpy(lock->logical_parent, lock->path, parent_length);
        lock->logical_parent[parent_length] = '\0';
    }
    if (safe_strncpy(lock->leaf, slash + 1U, sizeof(lock->leaf)) != 0 ||
        (size_t)snprintf(lock->lock_leaf, sizeof(lock->lock_leaf), "%s.lock",
                         lock->leaf) >= sizeof(lock->lock_leaf) ||
        (size_t)snprintf(lock->lock_path, sizeof(lock->lock_path), "%s/%s",
                         lock->parent, lock->lock_leaf) >=
            sizeof(lock->lock_path)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Recorded Git configuration lock path is too long");
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

static void git_scope_lock_clear_stage_witness_mode(
    git_scope_lock_t *lock, bool inherited) {
    if (!lock) return;
    if (!inherited && lock->stage_fd >= 0) {
        (void)close(lock->stage_fd);
    }
    lock->stage_fd = -1;
    if (lock->stage_data) {
        secure_zero_memory(lock->stage_data, lock->stage_length);
        free(lock->stage_data);
    }
    lock->stage_data = NULL;
    lock->stage_length = 0U;
    lock->stage_witness_valid = false;
    lock->stage_witness_kind = GIT_STAGE_WITNESS_CAPTURED;
    memset(&lock->stage_stat, 0, sizeof(lock->stage_stat));
}

static void git_scope_lock_clear_stage_witness(git_scope_lock_t *lock) {
    git_scope_lock_clear_stage_witness_mode(lock, false);
}

static int git_scope_lock_capture_stage_witness(git_scope_lock_t *lock) {
    int stage_fd;
    struct stat named;
    struct stat captured;
    unsigned char *data = NULL;
    size_t length = 0U;

    if (!lock || !lock->stage_created || lock->dir_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    stage_fd = openat(lock->dir_fd, lock->stage_leaf,
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stage_fd < 0 ||
        fstatat(lock->dir_fd, lock->stage_leaf, &named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        git_capture_fd_bytes_exact(stage_fd, &data, &length,
                                   &captured) != 0 ||
        !S_ISREG(captured.st_mode) || captured.st_nlink != 1 ||
        !git_same_file_observation(&named, &captured)) {
        int saved_errno = errno ? errno : EAGAIN;

        if (stage_fd >= 0) (void)close(stage_fd);
        if (data) {
            secure_zero_memory(data, length);
            free(data);
        }
        errno = saved_errno;
        return -1;
    }
    git_scope_lock_clear_stage_witness(lock);
    lock->stage_fd = stage_fd;
    lock->stage_stat = captured;
    lock->stage_data = data;
    lock->stage_length = length;
    lock->stage_witness_valid = true;
    lock->stage_witness_kind = GIT_STAGE_WITNESS_CAPTURED;
    return 0;
}

typedef struct {
    int fd;
    const struct stat *stat;
    const unsigned char *data;
    size_t length;
    bool valid;
} git_cleanup_witness_t;

typedef enum {
    GIT_CLEANUP_RETRY = -1,
    GIT_CLEANUP_SETTLED = 0,
    GIT_CLEANUP_FOREIGN = 1
} git_cleanup_result_t;

#define GIT_RECOVERY_MARKER_MAGIC "gitswitch-recovery-v1"
#define GIT_RECOVERY_HEADER_MAX 512U
#define GIT_RECOVERY_MARKER_MAX_BYTES \
    (GIT_SNAPSHOT_MAX_BYTES + GIT_RECOVERY_HEADER_MAX)

typedef struct {
    bool stage_present;
    char stage_leaf[sizeof(((git_scope_lock_t *)0)->stage_leaf)];
    struct stat stage_stat;
    const unsigned char *stage_data;
    size_t stage_length;
} git_recovery_marker_t;

static int git_scope_lock_claim_fd(int fd) {
    struct flock claim;

    memset(&claim, 0, sizeof(claim));
    claim.l_type = F_WRLCK;
    claim.l_whence = SEEK_SET;
    claim.l_start = 0;
    claim.l_len = 0;
    return fcntl(fd, F_SETLK, &claim);
}

static intmax_t git_stat_mtime_seconds(const struct stat *st) {
#if defined(__APPLE__)
    return (intmax_t)st->st_mtimespec.tv_sec;
#else
    return (intmax_t)st->st_mtim.tv_sec;
#endif
}

static long git_stat_mtime_nanoseconds(const struct stat *st) {
#if defined(__APPLE__)
    return st->st_mtimespec.tv_nsec;
#else
    return st->st_mtim.tv_nsec;
#endif
}

static void git_stat_set_mtime(struct stat *st, intmax_t seconds,
                               long nanoseconds) {
#if defined(__APPLE__)
    st->st_mtimespec.tv_sec = (time_t)seconds;
    st->st_mtimespec.tv_nsec = nanoseconds;
#else
    st->st_mtim.tv_sec = (time_t)seconds;
    st->st_mtim.tv_nsec = nanoseconds;
#endif
}

static bool git_recovery_stage_leaf_valid(const char *leaf) {
    static const char prefix[] = ".gitswitch-config-";
    const unsigned char *cursor;

    if (!leaf || strncmp(leaf, prefix, sizeof(prefix) - 1U) != 0 ||
        strlen(leaf) >= sizeof(((git_scope_lock_t *)0)->stage_leaf)) {
        return false;
    }
    cursor = (const unsigned char *)leaf + sizeof(prefix) - 1U;
#if defined(__FreeBSD__)
    if (strncmp((const char *)cursor, "v2-", 3U) == 0) {
        cursor += 3U;
        for (size_t index = 0U; index < 32U; index++, cursor++) {
            if (!isxdigit(*cursor) || isupper(*cursor)) return false;
        }
        if (*cursor++ != '-') return false;
        for (size_t index = 0U; index < 8U; index++, cursor++) {
            if (!isxdigit(*cursor) || isupper(*cursor)) return false;
        }
        if (*cursor++ != '-') return false;
        for (size_t index = 0U; index < 4U; index++, cursor++) {
            if (!isdigit(*cursor)) return false;
        }
        return *cursor++ == '-' &&
               (*cursor == 's' || *cursor == 'o') &&
               cursor[1] == '\0';
    }
#endif
    if (!isdigit(*cursor)) return false;
    while (isdigit(*cursor)) cursor++;
    if (*cursor++ != '-' || !isdigit(*cursor)) return false;
    while (isdigit(*cursor)) cursor++;
    return *cursor == '\0';
}

static bool git_finalization_private_leaf_valid(const char *leaf) {
    static const char prefix[] = ".gitswitch-finalization-";
    const unsigned char *cursor;

    if (!leaf || strncmp(leaf, prefix, sizeof(prefix) - 1U) != 0 ||
        strlen(leaf) >= sizeof(((git_config_finalization_lock_t *)0)
                                   ->private_leaf)) {
        return false;
    }
    cursor = (const unsigned char *)leaf + sizeof(prefix) - 1U;
    if (!isdigit(*cursor)) return false;
    while (isdigit(*cursor)) cursor++;
    if (*cursor++ != '-' || !isdigit(*cursor)) return false;
    while (isdigit(*cursor)) cursor++;
    return *cursor == '\0';
}

static int git_recovery_format_header(char *header, size_t header_size,
                                      const char *stage_leaf,
                                      const struct stat *stage_stat,
                                      size_t stage_length) {
    int written;

    if (!header || header_size == 0U || !stage_leaf || !stage_stat) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf( /* Flawfinder: ignore — bounded destination and a
                         * compile-time literal assembled from PRI macros. */
        header, header_size,
        GIT_RECOVERY_MARKER_MAGIC
        " %s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIdMAX
        " %ld %" PRIuMAX,
        stage_leaf, (uintmax_t)stage_stat->st_dev,
        (uintmax_t)stage_stat->st_ino, (uintmax_t)stage_stat->st_mode,
        (uintmax_t)stage_stat->st_uid, (uintmax_t)stage_stat->st_gid,
        (uintmax_t)stage_stat->st_size, (uintmax_t)stage_stat->st_nlink,
        git_stat_mtime_seconds(stage_stat),
        git_stat_mtime_nanoseconds(stage_stat), (uintmax_t)stage_length);
    if (written < 0 || (size_t)written >= header_size) {
        errno = EOVERFLOW;
        return -1;
    }
    return written;
}

static bool git_recovery_next_token(const char **cursor, const char *end,
                                    const char **token,
                                    size_t *token_length) {
    const char *start;
    const char *separator;

    if (!cursor || !*cursor || !end || !token || !token_length ||
        *cursor >= end || **cursor == ' ') {
        return false;
    }
    start = *cursor;
    separator = memchr(start, ' ', (size_t)(end - start));
    if (!separator) {
        *token = start;
        *token_length = (size_t)(end - start);
        *cursor = end;
        return *token_length != 0U;
    }
    if (separator == start || separator + 1 >= end || separator[1] == ' ') {
        return false;
    }
    *token = start;
    *token_length = (size_t)(separator - start);
    *cursor = separator + 1;
    return true;
}

static bool git_recovery_parse_uintmax_token(const char *token,
                                             size_t token_length,
                                             uintmax_t *value) {
    uintmax_t parsed = 0U;

    if (!token || token_length == 0U || !value) return false;
    for (size_t i = 0U; i < token_length; i++) {
        unsigned char byte = (unsigned char)token[i];
        uintmax_t digit;

        if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
            return false;
        }
        digit = (uintmax_t)(byte - (unsigned char)'0');
        if (parsed > (UINTMAX_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

static bool git_recovery_parse_intmax_token(const char *token,
                                            size_t token_length,
                                            intmax_t *value) {
    bool negative;
    uintmax_t magnitude = 0U;
    uintmax_t limit;
    size_t offset;

    if (!token || token_length == 0U || !value) return false;
    negative = token[0] == '-';
    offset = negative ? 1U : 0U;
    if (offset == token_length) return false;
    limit = negative ? (uintmax_t)INTMAX_MAX + 1U
                     : (uintmax_t)INTMAX_MAX;
    for (size_t i = offset; i < token_length; i++) {
        unsigned char byte = (unsigned char)token[i];
        uintmax_t digit;

        if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
            return false;
        }
        digit = (uintmax_t)(byte - (unsigned char)'0');
        if (magnitude > (limit - digit) / 10U) return false;
        magnitude = magnitude * 10U + digit;
    }
    if (negative) {
        *value = magnitude == (uintmax_t)INTMAX_MAX + 1U
                     ? INTMAX_MIN
                     : -(intmax_t)magnitude;
    } else {
        *value = (intmax_t)magnitude;
    }
    return true;
}

static bool git_recovery_marker_parse(const unsigned char *data,
                                      size_t length,
                                      git_recovery_marker_t *marker) {
    const unsigned char *newline;
    char header[GIT_RECOVERY_HEADER_MAX];
    char canonical[GIT_RECOVERY_HEADER_MAX];
    char stage_leaf[sizeof(marker->stage_leaf)];
    uintmax_t device;
    uintmax_t inode;
    uintmax_t mode;
    uintmax_t uid;
    uintmax_t gid;
    uintmax_t size;
    uintmax_t links;
    intmax_t mtime_seconds;
    uintmax_t mtime_nanoseconds_value;
    long mtime_nanoseconds;
    uintmax_t data_length;
    size_t header_length;
    size_t data_offset;
    const char *cursor;
    const char *end;
    const char *token;
    size_t token_length;
    size_t magic_length = sizeof(GIT_RECOVERY_MARKER_MAGIC) - 1U;
    struct stat parsed;

    if (!data || !marker || length == 0U ||
        length > GIT_RECOVERY_MARKER_MAX_BYTES) {
        return false;
    }
    newline = memchr(data, '\n', length);
    if (!newline) return false;
    header_length = (size_t)(newline - data);
    data_offset = header_length + 1U;
    if (header_length == 0U || header_length >= sizeof(header) ||
        memchr(data, '\0', header_length) != NULL) {
        return false;
    }
    memcpy(header, data, header_length);
    header[header_length] = '\0';
    if (header_length <= magic_length ||
        memcmp(header, GIT_RECOVERY_MARKER_MAGIC, magic_length) != 0 ||
        header[magic_length] != ' ') {
        return false;
    }
    cursor = header + magic_length + 1U;
    end = header + header_length;
    if (!git_recovery_next_token(&cursor, end, &token, &token_length) ||
        token_length >= sizeof(stage_leaf)) {
        return false;
    }
    memcpy(stage_leaf, token, token_length);
    stage_leaf[token_length] = '\0';
    if (!git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &device) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &inode) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &mode) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &uid) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &gid) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &size) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length, &links) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_intmax_token(token, token_length,
                                         &mtime_seconds) ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(
            token, token_length, &mtime_nanoseconds_value) ||
        mtime_nanoseconds_value > (uintmax_t)LONG_MAX ||
        !git_recovery_next_token(&cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(token, token_length,
                                          &data_length) ||
        cursor != end || data_length > GIT_SNAPSHOT_MAX_BYTES ||
        data_length > SIZE_MAX ||
        (size_t)data_length != length - data_offset) {
        return false;
    }
    mtime_nanoseconds = (long)mtime_nanoseconds_value;
    /* Reject target-type overflow before populating the parsed stat witness.
     * Integer casts themselves are defined or implementation-defined; the
     * exact round trips make every unsupported representation fail closed. */
    if ((uintmax_t)(dev_t)device != device ||
        (uintmax_t)(ino_t)inode != inode ||
        (uintmax_t)(mode_t)mode != mode ||
        (uintmax_t)(uid_t)uid != uid ||
        (uintmax_t)(gid_t)gid != gid ||
        (off_t)size < 0 || (uintmax_t)(off_t)size != size ||
        (uintmax_t)(nlink_t)links != links ||
        (intmax_t)(time_t)mtime_seconds != mtime_seconds ||
        mtime_nanoseconds > 999999999L) {
        return false;
    }
    memset(&parsed, 0, sizeof(parsed));
    parsed.st_dev = (dev_t)device;
    parsed.st_ino = (ino_t)inode;
    parsed.st_mode = (mode_t)mode;
    parsed.st_uid = (uid_t)uid;
    parsed.st_gid = (gid_t)gid;
    parsed.st_size = (off_t)size;
    parsed.st_nlink = (nlink_t)links;
    git_stat_set_mtime(&parsed, mtime_seconds, mtime_nanoseconds);
    if ((uintmax_t)parsed.st_dev != device ||
        (uintmax_t)parsed.st_ino != inode ||
        (uintmax_t)parsed.st_mode != mode ||
        (uintmax_t)parsed.st_uid != uid ||
        (uintmax_t)parsed.st_gid != gid || parsed.st_size < 0 ||
        (uintmax_t)parsed.st_size != size ||
        (uintmax_t)parsed.st_nlink != links ||
        git_stat_mtime_seconds(&parsed) != mtime_seconds ||
        git_stat_mtime_nanoseconds(&parsed) != mtime_nanoseconds ||
        mtime_nanoseconds < 0 || mtime_nanoseconds > 999999999L ||
        git_recovery_format_header(canonical, sizeof(canonical), stage_leaf,
                                   &parsed, (size_t)data_length) < 0 ||
        strcmp(header, canonical) != 0) {
        return false;
    }
    if (strcmp(stage_leaf, "-") == 0) {
        if (device != 0U || inode != 0U || mode != 0U || uid != 0U ||
            gid != 0U || size != 0U || links != 0U || mtime_seconds != 0 ||
            mtime_nanoseconds != 0L || data_length != 0U) {
            return false;
        }
        memset(marker, 0, sizeof(*marker));
        return true;
    }
    if (!git_recovery_stage_leaf_valid(stage_leaf) ||
        !S_ISREG(parsed.st_mode) || parsed.st_nlink != 1 ||
        parsed.st_size != (off_t)data_length) {
        return false;
    }
    memset(marker, 0, sizeof(*marker));
    marker->stage_present = true;
    memcpy(marker->stage_leaf, stage_leaf, strlen(stage_leaf) + 1U);
    marker->stage_stat = parsed;
    marker->stage_data = data + data_offset;
    marker->stage_length = (size_t)data_length;
    return true;
}

#if defined(__FreeBSD__)
#define GIT_FREEBSD_AUTHORITY_MAGIC "gitswitch-freebsd-authority-v2"
#define GIT_FREEBSD_AUTHORITY_HEADER_MAX 512U
#define GIT_FREEBSD_AUTHORITY_MAX_BYTES \
    (GIT_RECOVERY_MARKER_MAX_BYTES + GIT_FREEBSD_AUTHORITY_HEADER_MAX)

typedef struct {
    struct stat lease_stat;
    const unsigned char *marker_data;
    size_t marker_length;
} git_freebsd_authority_t;

static int git_freebsd_authority_format_header(
    char *header, size_t header_size, const struct stat *lease_stat,
    size_t marker_length) {
    int written;

    if (!header || header_size == 0U || !lease_stat) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf( /* Flawfinder: ignore — bounded destination and a
                         * compile-time literal assembled from PRI macros. */
        header, header_size,
        GIT_FREEBSD_AUTHORITY_MAGIC
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
        " %" PRIuMAX " %" PRIuMAX " %" PRIuMAX " %" PRIdMAX
        " %ld %" PRIuMAX,
        (uintmax_t)lease_stat->st_dev,
        (uintmax_t)lease_stat->st_ino,
        (uintmax_t)lease_stat->st_mode,
        (uintmax_t)lease_stat->st_uid,
        (uintmax_t)lease_stat->st_gid,
        (uintmax_t)lease_stat->st_size,
        (uintmax_t)lease_stat->st_nlink,
        git_stat_mtime_seconds(lease_stat),
        git_stat_mtime_nanoseconds(lease_stat),
        (uintmax_t)marker_length);
    if (written < 0 || (size_t)written >= header_size) {
        errno = EOVERFLOW;
        return -1;
    }
    return written;
}

static bool git_freebsd_authority_parse(
    const unsigned char *data, size_t length,
    git_freebsd_authority_t *authority) {
    const unsigned char *newline;
    char header[GIT_FREEBSD_AUTHORITY_HEADER_MAX];
    char canonical[GIT_FREEBSD_AUTHORITY_HEADER_MAX];
    const char *cursor;
    const char *end;
    const char *token;
    size_t token_length;
    size_t header_length;
    size_t marker_offset;
    size_t magic_length =
        sizeof(GIT_FREEBSD_AUTHORITY_MAGIC) - 1U;
    uintmax_t values[8];
    intmax_t mtime_seconds;
    uintmax_t mtime_nanoseconds;
    uintmax_t marker_length;
    struct stat parsed;
    git_recovery_marker_t marker;

    if (!data || !authority || length == 0U ||
        length > GIT_FREEBSD_AUTHORITY_MAX_BYTES) {
        return false;
    }
    newline = memchr(data, '\n', length);
    if (!newline) return false;
    header_length = (size_t)(newline - data);
    marker_offset = header_length + 1U;
    if (header_length <= magic_length ||
        header_length >= sizeof(header) ||
        memchr(data, '\0', header_length) != NULL) {
        return false;
    }
    memcpy(header, data, header_length);
    header[header_length] = '\0';
    if (memcmp(header, GIT_FREEBSD_AUTHORITY_MAGIC,
               magic_length) != 0 ||
        header[magic_length] != ' ') {
        return false;
    }
    cursor = header + magic_length + 1U;
    end = header + header_length;
    for (size_t i = 0U; i < 7U; i++) {
        if (!git_recovery_next_token(
                &cursor, end, &token, &token_length) ||
            !git_recovery_parse_uintmax_token(
                token, token_length, &values[i])) {
            return false;
        }
    }
    if (!git_recovery_next_token(
            &cursor, end, &token, &token_length) ||
        !git_recovery_parse_intmax_token(
            token, token_length, &mtime_seconds) ||
        !git_recovery_next_token(
            &cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(
            token, token_length, &mtime_nanoseconds) ||
        !git_recovery_next_token(
            &cursor, end, &token, &token_length) ||
        !git_recovery_parse_uintmax_token(
            token, token_length, &marker_length) ||
        cursor != end || marker_length > SIZE_MAX ||
        (size_t)marker_length != length - marker_offset ||
        mtime_nanoseconds > 999999999U) {
        return false;
    }
    memset(&parsed, 0, sizeof(parsed));
    parsed.st_dev = (dev_t)values[0];
    parsed.st_ino = (ino_t)values[1];
    parsed.st_mode = (mode_t)values[2];
    parsed.st_uid = (uid_t)values[3];
    parsed.st_gid = (gid_t)values[4];
    parsed.st_size = (off_t)values[5];
    parsed.st_nlink = (nlink_t)values[6];
    git_stat_set_mtime(
        &parsed, mtime_seconds, (long)mtime_nanoseconds);
    if ((uintmax_t)parsed.st_dev != values[0] ||
        (uintmax_t)parsed.st_ino != values[1] ||
        (uintmax_t)parsed.st_mode != values[2] ||
        (uintmax_t)parsed.st_uid != values[3] ||
        (uintmax_t)parsed.st_gid != values[4] ||
        parsed.st_size < 0 ||
        (uintmax_t)parsed.st_size != values[5] ||
        (uintmax_t)parsed.st_nlink != values[6] ||
        !S_ISREG(parsed.st_mode) || parsed.st_size != 0 ||
        parsed.st_nlink != 2 || parsed.st_uid != geteuid() ||
        git_freebsd_authority_format_header(
            canonical, sizeof(canonical), &parsed,
            (size_t)marker_length) < 0 ||
        strcmp(header, canonical) != 0 ||
        !git_recovery_marker_parse(
            data + marker_offset, (size_t)marker_length,
            &marker)) {
        return false;
    }
    memset(authority, 0, sizeof(*authority));
    authority->lease_stat = parsed;
    authority->marker_data = data + marker_offset;
    authority->marker_length = (size_t)marker_length;
    return true;
}
#endif

static bool git_fd_matches_recovery_marker(
    int fd, const char *header, size_t header_length,
    const unsigned char *stage_data, size_t stage_length) {
    unsigned char buffer[4096];
    size_t offset = 0U;
    size_t marker_length = header_length + 1U + stage_length;
    struct stat before;
    struct stat after;

    if (fd < 0 || !header || (stage_length != 0U && !stage_data) ||
        marker_length < stage_length || fstat(fd, &before) != 0 ||
        before.st_size < 0 || (uintmax_t)before.st_size != marker_length) {
        return false;
    }
    while (offset < marker_length) {
        const unsigned char *expected;
        size_t expected_length;
        size_t wanted;
        ssize_t got;

        if (offset < header_length) {
            expected = (const unsigned char *)header + offset;
            expected_length = header_length - offset;
        } else if (offset == header_length) {
            static const unsigned char newline = '\n';
            expected = &newline;
            expected_length = 1U;
        } else {
            size_t data_offset = offset - header_length - 1U;
            expected = stage_data + data_offset;
            expected_length = stage_length - data_offset;
        }
        wanted = expected_length < sizeof(buffer) ? expected_length
                                                   : sizeof(buffer);
        do {
            got = pread(fd, buffer, wanted, (off_t)offset);
        } while (got < 0 && errno == EINTR);
        if (got <= 0 || (size_t)got > expected_length ||
            memcmp(buffer, expected, (size_t)got) != 0) {
            if (got >= 0) errno = EAGAIN;
            return false;
        }
        offset += (size_t)got;
    }
    return fstat(fd, &after) == 0 &&
           git_same_file_observation(&before, &after);
}

static int git_scope_lock_capture_empty_lock_witness(
    git_scope_lock_t *lock) {
    unsigned char *data = NULL;
    size_t length = 0U;
    struct stat captured;
    int result = -1;

    if (!lock || lock->dir_fd < 0 || lock->lock_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (git_capture_fd_bytes_exact(lock->lock_fd, &data, &length,
                                   &captured) == 0 &&
        length == 0U && S_ISREG(captured.st_mode) &&
#if defined(__FreeBSD__)
        captured.st_nlink == 2 &&
#else
        captured.st_nlink == 1 &&
#endif
        git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd, &captured,
            NULL, 0U, &lock->lock_stat)) {
        lock->lock_witness_valid = true;
        result = 0;
    }
    if (data) {
        secure_zero_memory(data, length);
        free(data);
    }
    return result;
}

static git_cleanup_witness_t git_scope_lock_stage_witness(
    const git_scope_lock_t *lock) {
    git_cleanup_witness_t witness = {-1, NULL, NULL, 0U, false};

    if (!lock) return witness;
    switch (lock->stage_witness_kind) {
        case GIT_STAGE_WITNESS_CAPTURED:
            witness.fd = lock->stage_fd;
            witness.stat = &lock->stage_stat;
            witness.data = lock->stage_data;
            witness.length = lock->stage_length;
            witness.valid = lock->stage_witness_valid;
            break;
        case GIT_STAGE_WITNESS_ORIGINAL:
            witness.fd = lock->original_fd;
            witness.stat = &lock->original_stat;
            witness.data = lock->original_data;
            witness.length = lock->original_length;
            witness.valid = lock->original_witness_valid;
            break;
        case GIT_STAGE_WITNESS_PUBLISHED:
            witness.fd = lock->published_fd;
            witness.stat = &lock->published_stat;
            witness.data = lock->published_data;
            witness.length = lock->published_length;
            witness.valid = lock->published_witness_valid;
            break;
        default:
            break;
    }
    return witness;
}

typedef enum {
    GIT_NOREPLACE_MOVE_ERROR = -1,
    GIT_NOREPLACE_MOVE_OK = 0,
    GIT_NOREPLACE_MOVE_UNSUPPORTED = 1
} git_noreplace_move_result_t;

typedef enum {
    GIT_EXCHANGE_ERROR = -1,
    GIT_EXCHANGE_OK = 0,
    GIT_EXCHANGE_UNSUPPORTED = 1
} git_exchange_result_t;

/* Move one directory entry only while the destination name is absent.
 * Cleanup uses this as a compare-after-move primitive on platforms without
 * FreeBSD's descriptor-conditioned funlinkat(2). */
#if !defined(__FreeBSD__)
static git_noreplace_move_result_t git_rename_noreplace_at(
    int dir_fd, const char *source, const char *destination) {
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U)
#endif
    if (syscall(SYS_renameat2, dir_fd, source, dir_fd, destination,
                RENAME_NOREPLACE) == 0) {
        return GIT_NOREPLACE_MOVE_OK;
    }
    if (errno == ENOSYS || errno == EINVAL || errno == ENOTSUP ||
        errno == EOPNOTSUPP) {
        return GIT_NOREPLACE_MOVE_UNSUPPORTED;
    }
    return GIT_NOREPLACE_MOVE_ERROR;
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    if (renameatx_np(dir_fd, source, dir_fd, destination,
                     RENAME_EXCL) == 0) {
        return GIT_NOREPLACE_MOVE_OK;
    }
    if (errno == EINVAL || errno == ENOTSUP ||
        errno == EOPNOTSUPP) {
        return GIT_NOREPLACE_MOVE_UNSUPPORTED;
    }
    return GIT_NOREPLACE_MOVE_ERROR;
#else
    (void)dir_fd;
    (void)source;
    (void)destination;
    errno = ENOTSUP;
    return GIT_NOREPLACE_MOVE_UNSUPPORTED;
#endif
}
#endif

static git_exchange_result_t git_exchange_names_at(
    int dir_fd, const char *left, const char *right) {
    int result = -1;

#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
    result = (int)syscall(SYS_renameat2, dir_fd, left, dir_fd, right,
                          RENAME_EXCHANGE);
#elif defined(__APPLE__) && defined(RENAME_SWAP)
    result = renameatx_np(dir_fd, left, dir_fd, right, RENAME_SWAP);
#else
    (void)dir_fd;
    (void)left;
    (void)right;
    errno = ENOTSUP;
    return GIT_EXCHANGE_UNSUPPORTED;
#endif
    if (result == 0) return GIT_EXCHANGE_OK;
    if (errno == ENOSYS || errno == EINVAL || errno == ENOTSUP ||
        errno == EOPNOTSUPP) {
        return GIT_EXCHANGE_UNSUPPORTED;
    }
    return GIT_EXCHANGE_ERROR;
}

static uint64_t git_cleanup_leaf_hash(const char *leaf) {
    uint64_t hash = UINT64_C(14695981039346656037);

    if (!leaf) return 0U;
    for (const unsigned char *cursor =
             (const unsigned char *)leaf;
         *cursor; cursor++) {
        hash ^= (uint64_t)*cursor;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t git_cleanup_leaf_hash_secondary(const char *leaf) {
    uint64_t hash = UINT64_C(7809847782465536322);
    size_t length;

    if (!leaf) return 0U;
    length = strlen(leaf);
    while (length > 0U) {
        hash ^= (uint64_t)(unsigned char)leaf[--length];
        hash *= UINT64_C(1099511628211);
        hash ^= hash >> 32U;
    }
    return hash;
}

#if !defined(__FreeBSD__)
static int git_cleanup_arena_slot_names(
    const char *leaf, size_t slot,
    char pending[NAME_MAX + 1U],
    char settled[NAME_MAX + 1U]) {
    if (!leaf || !pending || !settled) {
        errno = EINVAL;
        return -1;
    }
    if ((size_t)snprintf(
            pending, NAME_MAX + 1U,
            ".gitswitch-cleanup-v2-%016" PRIx64 "%016" PRIx64
            "-%08zx-pending-%04zu",
            git_cleanup_leaf_hash(leaf),
            git_cleanup_leaf_hash_secondary(leaf), strlen(leaf), slot) >
            NAME_MAX ||
        (size_t)snprintf(
            settled, NAME_MAX + 1U,
            ".gitswitch-cleanup-v2-%016" PRIx64 "%016" PRIx64
            "-%08zx-settled-%04zu",
            git_cleanup_leaf_hash(leaf),
            git_cleanup_leaf_hash_secondary(leaf), strlen(leaf), slot) >
            NAME_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}
#endif

/* Each canonical lock leaf owns an exact, finite v2 arena. Pending entries
 * fail closed only for that leaf. Settled entries are untrusted inert
 * namespace residue: they are never inspected, deleted, reused, or
 * overwritten automatically. Requiring a complete-handle budget before
 * canonical mutation makes later cleanup bounded while the canonical
 * lock/marker serializes cooperative reservations. */
static int git_cleanup_arena_scan(
    int dir_fd, const char *leaf,
    uint64_t occupied[GIT_CLEANUP_ARENA_WORDS],
    size_t *occupied_count) {
    char prefix[96];
    struct dirent *entry;
    DIR *directory = NULL;
    int scan_fd = -1;
    int saved_errno = 0;
    size_t prefix_length;

    if (dir_fd < 0 || !leaf || !occupied || !occupied_count ||
        (size_t)snprintf(
            prefix, sizeof(prefix),
            ".gitswitch-cleanup-v2-%016" PRIx64 "%016" PRIx64
            "-%08zx-",
            git_cleanup_leaf_hash(leaf),
            git_cleanup_leaf_hash_secondary(leaf), strlen(leaf)) >=
            sizeof(prefix)) {
        errno = EINVAL;
        return -1;
    }
    memset(occupied, 0, sizeof(uint64_t) * GIT_CLEANUP_ARENA_WORDS);
    *occupied_count = 0U;
    prefix_length = strlen(prefix);
    scan_fd = openat(dir_fd, ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 ||
        (directory = fdopendir(scan_fd)) == NULL) {
        saved_errno = errno ? errno : EIO;
        if (scan_fd >= 0) (void)close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        const char *state;
        char *end = NULL;
        unsigned long parsed;
        bool is_pending = false;
        size_t slot;
        uint64_t mask;

        if (strncmp(entry->d_name, prefix, prefix_length) != 0) {
            continue;
        }
        state = entry->d_name + prefix_length;
        if (strncmp(state, "pending-", sizeof("pending-") - 1U) == 0) {
            state += sizeof("pending-") - 1U;
            is_pending = true;
        } else if (strncmp(
                       state, "settled-",
                       sizeof("settled-") - 1U) == 0) {
            state += sizeof("settled-") - 1U;
        } else {
            continue;
        }
        errno = 0;
        parsed = strtoul(state, &end, 10);
        if (errno != 0 || end == state || *end != '\0' ||
            parsed >= g_cleanup_arena_capacity) {
            continue;
        }
        if (is_pending) {
            saved_errno = EBUSY;
            break;
        }
        slot = (size_t)parsed;
        mask = UINT64_C(1) <<
               (slot % GIT_CLEANUP_ARENA_WORD_BITS);
        if ((occupied[slot / GIT_CLEANUP_ARENA_WORD_BITS] &
             mask) == 0U) {
            occupied[slot / GIT_CLEANUP_ARENA_WORD_BITS] |= mask;
            (*occupied_count)++;
        }
    }
    if (saved_errno == 0 && errno != 0) saved_errno = errno;
    (void)closedir(directory);
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int git_cleanup_arena_require_budget(
    int dir_fd, const char *leaf, size_t required) {
    uint64_t occupied[GIT_CLEANUP_ARENA_WORDS];
    size_t occupied_count = 0U;

    if (required == 0U ||
        git_cleanup_arena_scan(
            dir_fd, leaf, occupied, &occupied_count) != 0) {
        return -1;
    }
    if (g_cleanup_arena_capacity - occupied_count < required) {
        errno = ENOSPC;
        return -1;
    }
    return 0;
}

/* Linux and Darwin cannot unlink a retained descriptor directly. Atomically
 * move the public name into an exact unused slot in its leaf-associated finite
 * arena, then prove which inode was moved. A raced foreign entry is restored
 * when its public name is still absent and otherwise remains pending. An
 * exact owned entry advances with a second no-replace rename to settled
 * private residue and is re-proved there. Without
 * descriptor-conditioned unlink, physical deletion after a separable
 * pathname proof is not authorized. */
#if !defined(__FreeBSD__)
static git_cleanup_result_t git_scope_lock_quarantine_name_once(
    git_scope_lock_t *lock, const char *leaf, int witness_fd,
    const struct stat *witness_stat, const unsigned char *witness_data,
    size_t witness_length) {
    git_noreplace_move_result_t moved =
        GIT_NOREPLACE_MOVE_ERROR;
    char pending[NAME_MAX + 1U];
    char settled[NAME_MAX + 1U];
    uint64_t occupied[GIT_CLEANUP_ARENA_WORDS];
    size_t occupied_count = 0U;
    int saved_errno = EAGAIN;

    if (!lock || !leaf || lock->dir_fd < 0 || witness_fd < 0 ||
        !witness_stat) {
        errno = EINVAL;
        return GIT_CLEANUP_RETRY;
    }
    if (git_cleanup_arena_scan(
            lock->dir_fd, lock->lock_leaf,
            occupied, &occupied_count) != 0) {
        return GIT_CLEANUP_RETRY;
    }
    for (size_t slot = 0U; slot < g_cleanup_arena_capacity; slot++) {
        uint64_t mask = UINT64_C(1) <<
                        (slot % GIT_CLEANUP_ARENA_WORD_BITS);

        if ((occupied[slot / GIT_CLEANUP_ARENA_WORD_BITS] &
             mask) != 0U) {
            continue;
        }
        if (git_cleanup_arena_slot_names(
                lock->lock_leaf, slot, pending, settled) != 0) {
            return GIT_CLEANUP_RETRY;
        }
        moved = git_rename_noreplace_at(
            lock->dir_fd, leaf, pending);
        if (moved == GIT_NOREPLACE_MOVE_OK) break;
        if (moved == GIT_NOREPLACE_MOVE_ERROR &&
            errno == EEXIST) {
            errno = EBUSY;
        }
        return GIT_CLEANUP_RETRY;
    }
    if (moved != GIT_NOREPLACE_MOVE_OK) {
        errno = ENOSPC;
        return GIT_CLEANUP_RETRY;
    }
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_CLEANUP_QUARANTINE,
            lock->path, leaf, pending)) {
        saved_errno = EIO;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, pending, witness_fd, witness_stat,
            witness_data, witness_length, NULL)) {
        git_noreplace_move_result_t restored;

        if (saved_errno == EAGAIN) {
            saved_errno = errno ? errno : ESTALE;
        }
        restored = git_rename_noreplace_at(
            lock->dir_fd, pending, leaf);
        if (restored == GIT_NOREPLACE_MOVE_OK) {
            (void)fsync(lock->dir_fd);
        }
        /* Whether restored to its public name or retained under quarantine
         * because a newer entry already occupies that name, the raced object
         * is preserved and is never authorized for deletion. */
        errno = saved_errno;
        return GIT_CLEANUP_FOREIGN;
    }
    if (saved_errno == EAGAIN) {
        if (g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_AFTER_CLEANUP_PROOF,
                lock->path, leaf, pending)) {
            saved_errno = EIO;
        }
        moved = git_rename_noreplace_at(
            lock->dir_fd, pending, settled);
        if (moved != GIT_NOREPLACE_MOVE_OK) {
            return GIT_CLEANUP_RETRY;
        }
        if (!git_file_at_matches_witness(
                lock->dir_fd, settled, witness_fd, witness_stat,
                witness_data, witness_length, NULL)) {
            int mismatch_errno = errno ? errno : ESTALE;

            moved = git_rename_noreplace_at(
                lock->dir_fd, settled, pending);
            if (moved != GIT_NOREPLACE_MOVE_OK) {
                errno = errno ? errno : EBUSY;
                return GIT_CLEANUP_RETRY;
            }
            errno = mismatch_errno;
            return GIT_CLEANUP_FOREIGN;
        }
    }
    if (fsync(lock->dir_fd) != 0) {
        if (saved_errno == EAGAIN) saved_errno = errno ? errno : EIO;
    }
    if (saved_errno != EAGAIN) {
        errno = saved_errno;
        return GIT_CLEANUP_RETRY;
    }
    return GIT_CLEANUP_SETTLED;
}
#endif

static git_cleanup_result_t git_scope_lock_cleanup_name_once(
    git_scope_lock_t *lock, const char *leaf, const char *description,
    int witness_fd, const struct stat *witness_stat,
    const unsigned char *witness_data, size_t witness_length,
    bool witness_valid, bool retirement_hook) {
    struct stat named;
    struct stat pinned;
    struct stat remaining;
    int saved_errno;

    if (!lock || !leaf || lock->dir_fd < 0 || witness_fd < 0 ||
        !witness_stat || !witness_valid) {
        errno = EINVAL;
        return GIT_CLEANUP_RETRY;
    }
    errno = 0;
    if (!git_file_at_matches_witness(
            lock->dir_fd, leaf, witness_fd, witness_stat,
            witness_data, witness_length, NULL)) {
        saved_errno = errno ? errno : EAGAIN;
        if (fstatat(lock->dir_fd, leaf, &named,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) return GIT_CLEANUP_SETTLED;
            return GIT_CLEANUP_RETRY;
        }
        if (fstat(witness_fd, &pinned) != 0) {
            return GIT_CLEANUP_RETRY;
        }
        if (named.st_dev != pinned.st_dev || named.st_ino != pinned.st_ino ||
            !git_same_pinned_file_generation(witness_stat, &named) ||
            !git_same_pinned_file_generation(witness_stat, &pinned)) {
            errno = saved_errno;
            return GIT_CLEANUP_FOREIGN;
        }
        errno = saved_errno;
        return GIT_CLEANUP_RETRY;
    }
    if (retirement_hook && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_CLEANUP_UNLINK,
                               lock->path, leaf, description)) {
        errno = EIO;
        return GIT_CLEANUP_RETRY;
    }
#if defined(__FreeBSD__)
    if (funlinkat(lock->dir_fd, leaf, witness_fd, 0) != 0) {
        return GIT_CLEANUP_RETRY;
    }
    errno = 0;
    if (fstatat(lock->dir_fd, leaf, &remaining,
                AT_SYMLINK_NOFOLLOW) == 0) {
        return GIT_CLEANUP_FOREIGN;
    }
    return errno == ENOENT ? GIT_CLEANUP_SETTLED : GIT_CLEANUP_RETRY;
#else
    (void)remaining;
    return git_scope_lock_quarantine_name_once(
        lock, leaf, witness_fd, witness_stat, witness_data,
        witness_length);
#endif
}

static git_cleanup_result_t git_scope_lock_cleanup_name(
    git_scope_lock_t *lock, const char *leaf, const char *description,
    int witness_fd, const struct stat *witness_stat,
    const unsigned char *witness_data, size_t witness_length,
    bool witness_valid, bool retirement_hook) {
    git_cleanup_result_t result = GIT_CLEANUP_RETRY;
    int saved_errno = EAGAIN;

    for (int attempt = 0; attempt < 2; attempt++) {
        result = git_scope_lock_cleanup_name_once(
            lock, leaf, description, witness_fd, witness_stat,
            witness_data, witness_length, witness_valid, retirement_hook);
        if (result != GIT_CLEANUP_RETRY) break;
        saved_errno = errno ? errno : EAGAIN;
    }
    if (result == GIT_CLEANUP_FOREIGN) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git transaction %s changed; preserving the foreign path",
                  description ? description : "artifact");
    } else if (result == GIT_CLEANUP_RETRY) {
        errno = saved_errno;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot remove owned Git transaction %s",
                         description ? description : "artifact");
    }
    return result;
}

static int git_scope_lock_persist_recovery_marker(git_scope_lock_t *lock) {
    static unsigned long marker_nonce;
    static const unsigned char newline = '\n';
    git_cleanup_witness_t stage_witness = {-1, NULL, NULL, 0U, false};
    git_recovery_marker_t parsed_marker;
    const unsigned char *stage_data = NULL;
    unsigned char *marker_data = NULL;
    size_t stage_length = 0U;
    size_t marker_length = 0U;
    size_t expected_length;
    struct stat stage_stat;
    struct stat lock_current;
#if !defined(__FreeBSD__)
    struct stat marker_stat;
    struct stat installed_stat;
    struct stat displaced_lock_stat;
#endif
    char header[GIT_RECOVERY_HEADER_MAX];
    char marker_leaf[96];
    const char *stage_leaf = "-";
    error_accumulator_t failures;
    int header_length;
#if !defined(__FreeBSD__)
    int displaced_lock_fd = -1;
#endif
    int marker_fd = -1;
    int primary_errno = EIO;
    int result = -1;
    bool marker_created = false;
    bool marker_witness_valid = false;
#if defined(__FreeBSD__)
    unsigned char *authority_data = NULL;
    size_t authority_length = 0U;
    struct stat authority_stat;
    git_freebsd_authority_t authority;
    char authority_header[GIT_FREEBSD_AUTHORITY_HEADER_MAX];
    int authority_header_length;
    size_t authority_slot = SIZE_MAX;
#endif

    memset(&stage_stat, 0, sizeof(stage_stat));
    memset(&parsed_marker, 0, sizeof(parsed_marker));
#if !defined(__FreeBSD__)
    memset(&marker_stat, 0, sizeof(marker_stat));
    memset(&displaced_lock_stat, 0, sizeof(displaced_lock_stat));
#endif
    error_accumulator_init(&failures);
    if (!lock || lock->dir_fd < 0 || !lock->lock_created ||
        lock->lock_fd < 0 || !lock->lock_witness_valid) {
        errno = EINVAL;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot retain Git transaction cleanup authority");
        return -1;
    }
    if (lock->stage_created) {
        stage_witness = git_scope_lock_stage_witness(lock);
        if (!stage_witness.valid || stage_witness.fd < 0 ||
            !git_file_at_matches_witness(
                lock->dir_fd, lock->stage_leaf, stage_witness.fd,
                stage_witness.stat, stage_witness.data,
                stage_witness.length, &stage_stat)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot retain exact Git staging cleanup authority");
            return -1;
        }
        stage_leaf = lock->stage_leaf;
        stage_data = stage_witness.data;
        stage_length = stage_witness.length;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, &lock_current)) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot retain exact Git lock cleanup authority");
        return -1;
    }
    header_length = git_recovery_format_header(
        header, sizeof(header), stage_leaf, &stage_stat, stage_length);
    if (header_length < 0 ||
        stage_length > SIZE_MAX - (size_t)header_length - 1U) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot format Git transaction recovery marker");
        goto fail;
    }
    expected_length = (size_t)header_length + 1U + stage_length;
#if defined(__FreeBSD__)
    marker_data = malloc(expected_length);
    if (!marker_data) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate the Git recovery authority image");
        goto fail;
    }
    memcpy(marker_data, header, (size_t)header_length);
    marker_data[header_length] = newline;
    if (stage_length != 0U) {
        memcpy(marker_data + (size_t)header_length + 1U,
               stage_data, stage_length);
    }
    marker_length = expected_length;
    authority_header_length = git_freebsd_authority_format_header(
        authority_header, sizeof(authority_header), &lock_current,
        marker_length);
    if (authority_header_length < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot format the FreeBSD Git recovery authority");
        goto fail;
    }
    {
        const char *slot_text =
            strrchr(lock->recovery_lease_leaf, '-');
        char *slot_end = NULL;
        unsigned long parsed_slot;

        if (!slot_text || !slot_text[1]) {
            errno = ESTALE;
            goto fail;
        }
        errno = 0;
        parsed_slot = strtoul(slot_text + 1U, &slot_end, 10);
        if (errno != 0 || !slot_end || *slot_end != '\0' ||
            parsed_slot >= g_cleanup_arena_capacity) {
            errno = ESTALE;
            goto fail;
        }
        authority_slot = (size_t)parsed_slot;
    }
#endif
    for (unsigned attempt = 0U; attempt < 100U; attempt++) {
        unsigned long nonce = ++marker_nonce;

#if defined(__FreeBSD__)
        (void)nonce;
        if (attempt != 0U ||
            (size_t)snprintf(
                marker_leaf, sizeof(marker_leaf),
                ".gitswitch-recovery-v2-%016" PRIx64
                "%016" PRIx64 "-%08zx-%04zu",
                git_cleanup_leaf_hash(lock->lock_leaf),
                git_cleanup_leaf_hash_secondary(lock->lock_leaf),
                strlen(lock->lock_leaf), authority_slot) >=
                sizeof(marker_leaf)) {
#else
        if ((size_t)snprintf(marker_leaf, sizeof(marker_leaf),
                             ".gitswitch-recovery-%ld-%lu",
                             (long)getpid(), nonce) >= sizeof(marker_leaf)) {
#endif
            errno = ENAMETOOLONG;
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Git recovery marker path is too long");
            goto fail;
        }
        g_terminal_namespace_mutation_count++;
        marker_fd = openat(lock->dir_fd, marker_leaf,
                           O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker_fd >= 0) {
            marker_created = true;
            break;
        }
        if (errno != EEXIST) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot create private Git recovery marker");
            goto fail;
        }
    }
    if (marker_fd < 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot allocate a unique private Git recovery marker");
        goto fail;
    }
    if (git_scope_lock_claim_fd(marker_fd) != 0 ||
        fchmod(marker_fd, 0600) != 0 ||
#if defined(__FreeBSD__)
        git_write_all(
            marker_fd, (const unsigned char *)authority_header,
            (size_t)authority_header_length) != 0 ||
        git_write_all(marker_fd, &newline, 1U) != 0 ||
        git_write_all(marker_fd, marker_data, marker_length) != 0 ||
#else
        git_write_all(marker_fd, (const unsigned char *)header,
                      (size_t)header_length) != 0 ||
        git_write_all(marker_fd, &newline, 1U) != 0 ||
        (stage_length != 0U &&
         git_write_all(marker_fd, stage_data, stage_length) != 0) ||
#endif
        (++g_terminal_namespace_sync_count,
         fsync(marker_fd) != 0)) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot prepare private Git recovery marker");
        goto fail;
    }
#if defined(__FreeBSD__)
    memset(&authority, 0, sizeof(authority));
    memset(&authority_stat, 0, sizeof(authority_stat));
    if (git_capture_fd_bytes_exact_bounded(
            marker_fd, &authority_data, &authority_length,
            &authority_stat, GIT_FREEBSD_AUTHORITY_MAX_BYTES) != 0 ||
        !S_ISREG(authority_stat.st_mode) ||
        authority_stat.st_nlink != 1 ||
        authority_stat.st_uid != geteuid() ||
        (authority_stat.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->dir_fd, marker_leaf, marker_fd, &authority_stat,
            authority_data, authority_length, NULL) ||
        !git_freebsd_authority_parse(
            authority_data, authority_length, &authority) ||
        !git_same_pinned_file_generation(
            &lock_current, &authority.lease_stat) ||
        authority.marker_length != marker_length ||
        memcmp(authority.marker_data, marker_data, marker_length) != 0 ||
        !git_recovery_marker_parse(
            marker_data, marker_length, &parsed_marker)) {
#else
    if (git_capture_fd_bytes_exact_bounded(
            marker_fd, &marker_data, &marker_length, &marker_stat,
            GIT_RECOVERY_MARKER_MAX_BYTES) != 0 ||
        marker_length != expected_length ||
        !S_ISREG(marker_stat.st_mode) || marker_stat.st_nlink != 1 ||
        marker_stat.st_uid != geteuid() ||
        (marker_stat.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->dir_fd, marker_leaf, marker_fd, &marker_stat,
            marker_data, marker_length, NULL) ||
        !git_fd_matches_recovery_marker(
            marker_fd, header, (size_t)header_length,
            stage_data, stage_length) ||
        !git_recovery_marker_parse(marker_data, marker_length,
                                   &parsed_marker)) {
#endif
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot validate private Git recovery marker");
        goto fail;
    }
    marker_witness_valid = true;

    /* Reprove both cleanup authorities immediately before publication. No
     * platform below uses an overwriting rename after this separable proof. */
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, &lock_current) ||
        (lock->stage_created &&
         (!stage_witness.valid || stage_witness.fd < 0 ||
          !git_file_at_matches_witness(
              lock->dir_fd, lock->stage_leaf, stage_witness.fd,
              stage_witness.stat, stage_witness.data,
              stage_witness.length, NULL)))) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git transaction cleanup authority changed before recovery publication");
        goto fail;
    }
    if (g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_MARKER_PUBLISH,
                               lock->path, marker_leaf,
                               "private recovery marker")) {
        errno = EIO;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Injected Git recovery marker publication failure");
        goto fail;
    }
#if defined(__FreeBSD__)
    /* FreeBSD 14 has descriptor-conditioned unlink but no atomic name
     * exchange. Keep the exact empty canonical Git lease continuously
     * present and publish a complete fixed-slot authority beside it. The
     * authority binds the lease generation and nested stage certificate, so
     * restart recovery can prove and settle the pair without ever treating a
     * replacement at either pathname as owned. */
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock_current, NULL, 0U, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, marker_leaf, marker_fd,
            &authority_stat, authority_data, authority_length, NULL)) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot publish the FreeBSD Git recovery authority");
        goto fail;
    }
    /* The A directory entry exists before its parent sync. From this point
     * onward publication is crash/return-uncertain, so failure disposal must
     * retain A beside W/C/T/O for restart classification. */
    lock->recovery_marker_publication_uncertain = true;
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_PUBLISH,
            lock->path, marker_leaf, "FreeBSD recovery authority")) {
        errno = EIO;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected interruption after FreeBSD Git recovery authority publication");
        goto fail;
    }
    if (fsync(lock->dir_fd) != 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "FreeBSD Git recovery authority directory sync failed");
        goto fail;
    }
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_FREEBSD_AUTHORITY_DIRECTORY_SYNC,
            lock->path, marker_leaf, "FreeBSD recovery authority")) {
        errno = EIO;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected interruption after FreeBSD Git recovery authority directory sync");
        goto fail;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock_current, NULL, 0U, &lock->lock_stat) ||
        !git_file_at_matches_witness(
            lock->dir_fd, marker_leaf, marker_fd,
            &authority_stat, authority_data, authority_length,
            &lock->recovery_authority_stat)) {
        errno = errno ? errno : EAGAIN;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "FreeBSD Git recovery authority was not durably verified");
        goto fail;
    }
    lock->recovery_marker_published = true;
    lock->recovery_marker_data = marker_data;
    lock->recovery_marker_length = marker_length;
    lock->recovery_marker_witness_valid = true;
    marker_data = NULL;
    marker_length = 0U;
    if (safe_strncpy(
            lock->recovery_authority_leaf, marker_leaf,
            sizeof(lock->recovery_authority_leaf)) != 0) {
        goto fail;
    }
    lock->recovery_authority_fd = marker_fd;
    marker_fd = -1;
    lock->recovery_authority_data = authority_data;
    lock->recovery_authority_length = authority_length;
    lock->recovery_authority_witness_valid = true;
    lock->recovery_marker_publication_uncertain = false;
    authority_data = NULL;
    authority_length = 0U;
    lock->stage_created = false;
    lock->lock_created = false;
    marker_created = false;
    result = 0;
#else
    {
        git_exchange_result_t exchanged = git_exchange_names_at(
            lock->dir_fd, marker_leaf, lock->lock_leaf);
        bool canonical_marker;
        bool displaced_lock;

        if (exchanged != GIT_EXCHANGE_OK) {
            errno = exchanged == GIT_EXCHANGE_UNSUPPORTED
                        ? ENOTSUP
                        : (errno ? errno : EIO);
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot atomically exchange the Git recovery marker");
            goto fail;
        }
        canonical_marker = git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, marker_fd,
            &marker_stat, marker_data, marker_length, NULL);
        displaced_lock = git_file_at_matches_witness(
            lock->dir_fd, marker_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, &displaced_lock_stat);
        if (!canonical_marker || !displaced_lock) {
            /* If either side is still exactly ours, exchange once more to put
             * that owned entry back on its pre-publication side and preserve
             * the raced entry on the other name. If both names are foreign,
             * neither pathname is mutated again. */
            if (canonical_marker || displaced_lock) {
                (void)git_exchange_names_at(
                    lock->dir_fd, marker_leaf, lock->lock_leaf);
            }
            errno = ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git recovery publication changed at the exchange boundary");
            goto fail;
        }
    }
#endif
#if !defined(__FreeBSD__)
    /* This is the publication linearization point. Even if the following
     * directory sync or exact reproof fails, descriptor disposal must leave
     * the possibly installed complete marker for restart recovery. */
    lock->recovery_marker_published = true;
    displaced_lock_fd = lock->lock_fd;
    lock->lock_fd = marker_fd;
    marker_fd = -1;
    lock->lock_stat = marker_stat;
    lock->lock_witness_valid = false;
    /* Exact cleanup authority is now durable in the canonical lock itself.
     * Resource close must not attempt another pathname mutation. */
    lock->stage_created = false;
    lock->lock_created = false;
    if (git_scope_lock_cleanup_name_once(
            lock, marker_leaf, "displaced empty canonical lock",
            displaced_lock_fd, &displaced_lock_stat, NULL, 0U,
            true, false) != GIT_CLEANUP_SETTLED) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot quarantine the displaced empty Git lock");
        goto fail;
    }
    marker_created = false;
    (void)close(displaced_lock_fd);
    displaced_lock_fd = -1;
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &marker_stat, marker_data, marker_length, &installed_stat) ||
        fsync(lock->dir_fd) != 0 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &installed_stat, marker_data, marker_length, &lock->lock_stat)) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Complete Git recovery marker was installed but not durably verified");
        goto fail;
    }
    lock->recovery_marker_data = marker_data;
    lock->recovery_marker_length = marker_length;
    lock->recovery_marker_witness_valid = true;
    marker_data = NULL;
    marker_length = 0U;
    result = 0;
#endif

fail:
    if (result != 0) {
        error_context_t primary_error = *get_last_error();

        primary_errno = errno ? errno : EIO;
        errno = primary_errno;
        (void)error_accumulator_add(
            &failures, "Git recovery marker publication", &primary_error);
        if (marker_created && marker_fd >= 0 &&
            !lock->recovery_marker_publication_uncertain) {
#if defined(__FreeBSD__)
            if (!marker_witness_valid &&
                git_capture_fd_bytes_exact_bounded(
                    marker_fd, &authority_data, &authority_length,
                    &authority_stat,
                    GIT_FREEBSD_AUTHORITY_MAX_BYTES) == 0 &&
                S_ISREG(authority_stat.st_mode) &&
                authority_stat.st_nlink == 1 &&
                authority_stat.st_uid == geteuid()) {
                marker_witness_valid = true;
            }
            if (marker_witness_valid &&
                git_scope_lock_cleanup_name(
                    lock, marker_leaf, "private recovery authority",
                    marker_fd, &authority_stat, authority_data,
                    authority_length, true, true) !=
                    GIT_CLEANUP_SETTLED) {
                /* A complete, file-synced authority still exists under its
                 * fixed discovery name. Once exact cleanup fails, callers
                 * must preserve W/C/T beside it for restart classification
                 * even though canonical publication never began. */
                lock->recovery_marker_publication_uncertain = true;
                (void)error_accumulator_add_last(
                    &failures, "private recovery authority cleanup");
            }
#else
            if (!marker_witness_valid) {
                if (marker_data) {
                    secure_zero_memory(marker_data, marker_length);
                    free(marker_data);
                    marker_data = NULL;
                    marker_length = 0U;
                }
                if (git_capture_fd_bytes_exact_bounded(
                        marker_fd, &marker_data, &marker_length,
                        &marker_stat, GIT_RECOVERY_MARKER_MAX_BYTES) == 0 &&
                    S_ISREG(marker_stat.st_mode) &&
                    marker_stat.st_nlink == 1 &&
                    marker_stat.st_uid == geteuid()) {
                    marker_witness_valid = true;
                } else {
                    set_system_error(
                        ERR_GIT_CONFIG_FAILED,
                        "Cannot pin failed private Git recovery marker for cleanup");
                    (void)error_accumulator_add_last(
                        &failures, "private recovery marker witness");
                }
            }
            if (marker_witness_valid &&
                git_scope_lock_cleanup_name(
                    lock, marker_leaf, "private recovery marker",
                    marker_fd, &marker_stat, marker_data, marker_length,
                    true, false) != GIT_CLEANUP_SETTLED) {
                (void)error_accumulator_add_last(
                    &failures, "private recovery marker cleanup");
            }
#endif
        }
    }
#if !defined(__FreeBSD__)
    if (displaced_lock_fd >= 0) (void)close(displaced_lock_fd);
#endif
    if (marker_fd >= 0) (void)close(marker_fd);
    if (marker_data) {
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
    }
#if defined(__FreeBSD__)
    if (authority_data) {
        secure_zero_memory(authority_data, authority_length);
        free(authority_data);
    }
#endif
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
        errno = failures.first_errno;
    }
    return result;
}

#if defined(__FreeBSD__)
static int git_freebsd_recovery_slot(const git_scope_lock_t *lock,
                                     size_t *slot_out) {
    const char *slot_text;
    char *slot_end = NULL;
    unsigned long parsed;

    if (!lock || !slot_out ||
        !(slot_text = strrchr(lock->recovery_lease_leaf, '-')) ||
        !slot_text[1]) {
        errno = ESTALE;
        return -1;
    }
    errno = 0;
    parsed = strtoul(slot_text + 1U, &slot_end, 10);
    if (errno != 0 || !slot_end || *slot_end != '\0' ||
        parsed >= g_cleanup_arena_capacity) {
        errno = ESTALE;
        return -1;
    }
    *slot_out = (size_t)parsed;
    return 0;
}

static int git_freebsd_bounded_stage_leaf(
    const git_scope_lock_t *lock, char kind, char leaf[96]) {
    size_t slot;

    if (!lock || !leaf || (kind != 's' && kind != 'o') ||
        git_freebsd_recovery_slot(lock, &slot) != 0 ||
        (size_t)snprintf(
            leaf, 96U,
            ".gitswitch-config-v2-%016" PRIx64
            "%016" PRIx64 "-%08zx-%04zu-%c",
            git_cleanup_leaf_hash(lock->lock_leaf),
            git_cleanup_leaf_hash_secondary(lock->lock_leaf),
            strlen(lock->lock_leaf), slot, kind) >= 96U) {
        errno = errno ? errno : ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int git_scope_lock_recover_freebsd_authority(
    git_scope_lock_t *lock) {
    git_freebsd_authority_t authority;
    git_recovery_marker_t marker;
    git_cleanup_result_t cleanup;
    struct dirent *entry;
    DIR *directory = NULL;
    char prefix[80];
    char authority_leaf[96] = "";
    char lease_leaf[96] = "";
    unsigned char *authority_data = NULL;
    size_t authority_length = 0U;
    struct stat authority_stat;
    struct stat lease_stat;
    struct stat lease_baseline;
    int scan_fd = -1;
    int authority_fd = -1;
    int lease_fd = -1;
    int witness_fd = -1;
    int stage_fd = -1;
    int matches = 0;
    int saved_errno = 0;
    int result = -1;

    memset(&authority, 0, sizeof(authority));
    memset(&marker, 0, sizeof(marker));
    if (!lock || lock->dir_fd < 0 ||
        (size_t)snprintf(
            prefix, sizeof(prefix),
            ".gitswitch-recovery-v2-%016" PRIx64
            "%016" PRIx64 "-%08zx-",
            git_cleanup_leaf_hash(lock->lock_leaf),
            git_cleanup_leaf_hash_secondary(lock->lock_leaf),
            strlen(lock->lock_leaf)) >= sizeof(prefix)) {
        errno = EINVAL;
        return -1;
    }
    scan_fd = openat(
        lock->dir_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        saved_errno = errno ? errno : EIO;
        if (scan_fd >= 0) (void)close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) continue;
        matches++;
        if (matches != 1 ||
            safe_strncpy(authority_leaf, entry->d_name,
                         sizeof(authority_leaf)) != 0) {
            saved_errno = EEXIST;
            goto done;
        }
    }
    if (errno != 0) {
        saved_errno = errno;
        goto done;
    }
    if (matches == 0) {
        char lease_prefix[80];
        char bounded_stage[96];
        char bounded_original[96];
        struct stat witness_stat;
        struct stat residue;

        (void)closedir(directory);
        directory = NULL;
        if ((size_t)snprintf(
                lease_prefix, sizeof(lease_prefix),
                ".gitswitch-lease-v2-%016" PRIx64
                "%016" PRIx64 "-%08zx-",
                git_cleanup_leaf_hash(lock->lock_leaf),
                git_cleanup_leaf_hash_secondary(lock->lock_leaf),
                strlen(lock->lock_leaf)) >= sizeof(lease_prefix)) {
            saved_errno = EINVAL;
            goto done;
        }
        scan_fd = openat(
            lock->dir_fd, ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (scan_fd < 0 ||
            (directory = fdopendir(scan_fd)) == NULL) {
            saved_errno = errno ? errno : EIO;
            if (scan_fd >= 0) (void)close(scan_fd);
            goto done;
        }
        scan_fd = -1;
        matches = 0;
        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
            if (strncmp(entry->d_name, lease_prefix,
                        strlen(lease_prefix)) != 0) {
                continue;
            }
            matches++;
            if (matches != 1 ||
                safe_strncpy(lease_leaf, entry->d_name,
                             sizeof(lease_leaf)) != 0) {
                saved_errno = EEXIST;
                goto done;
            }
        }
        if (errno != 0) {
            saved_errno = errno;
            goto done;
        }
        if (matches == 0) {
            result = 0;
            goto done;
        }
        witness_fd = openat(
            lock->dir_fd, lease_leaf,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (witness_fd < 0 ||
            git_scope_lock_claim_fd(witness_fd) != 0 ||
            fstat(witness_fd, &witness_stat) != 0 ||
            !S_ISREG(witness_stat.st_mode) ||
            witness_stat.st_size != 0 ||
            (witness_stat.st_nlink != 1 &&
             witness_stat.st_nlink != 2) ||
            !git_file_at_matches_witness(
                lock->dir_fd, lease_leaf, witness_fd,
                &witness_stat, NULL, 0U, NULL)) {
            saved_errno = errno ? errno : ESTALE;
            goto done;
        }
        if (safe_strncpy(lock->recovery_lease_leaf, lease_leaf,
                         sizeof(lock->recovery_lease_leaf)) != 0 ||
            git_freebsd_bounded_stage_leaf(
                lock, 's', bounded_stage) != 0 ||
            git_freebsd_bounded_stage_leaf(
                lock, 'o', bounded_original) != 0) {
            saved_errno = errno ? errno : ESTALE;
            goto done;
        }
        errno = 0;
        if (fstatat(lock->dir_fd, bounded_stage, &residue,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            /* Before A exists there is no durable byte witness for T/O.
             * Preserve either fixed-slot entry as potentially foreign and
             * retain W/C so cooperative writers remain excluded. */
            saved_errno = EEXIST;
            goto done;
        }
        if (errno != ENOENT) {
            saved_errno = errno;
            goto done;
        }
        errno = 0;
        if (fstatat(lock->dir_fd, bounded_original, &residue,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            saved_errno = EEXIST;
            goto done;
        }
        if (errno != ENOENT) {
            saved_errno = errno;
            goto done;
        }
        if (witness_stat.st_nlink == 2) {
            lease_fd = openat(
                lock->dir_fd, lock->lock_leaf,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW);
            if (lease_fd < 0 ||
                !git_file_at_matches_witness(
                    lock->dir_fd, lock->lock_leaf, lease_fd,
                    &witness_stat, NULL, 0U, NULL) ||
                funlinkat(lock->dir_fd, lock->lock_leaf,
                          witness_fd, 0) != 0 ||
                fstat(witness_fd, &witness_stat) != 0 ||
                witness_stat.st_nlink != 1) {
                saved_errno = errno ? errno : ESTALE;
                goto done;
            }
        }
        if (funlinkat(lock->dir_fd, lease_leaf,
                      witness_fd, 0) != 0 ||
            fsync(lock->dir_fd) != 0) {
            saved_errno = errno ? errno : EIO;
            goto done;
        }
        result = 1;
        goto done;
    }
    {
        const char *slot = strrchr(authority_leaf, '-');

        if (!slot ||
            (size_t)snprintf(
                lease_leaf, sizeof(lease_leaf),
                ".gitswitch-lease-v2-%016" PRIx64
                "%016" PRIx64 "-%08zx-%s",
                git_cleanup_leaf_hash(lock->lock_leaf),
                git_cleanup_leaf_hash_secondary(lock->lock_leaf),
                strlen(lock->lock_leaf), slot + 1U) >=
                sizeof(lease_leaf)) {
            saved_errno = ESTALE;
            goto done;
        }
    }
    authority_fd = openat(
        lock->dir_fd, authority_leaf,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (authority_fd < 0 ||
        git_scope_lock_claim_fd(authority_fd) != 0 ||
        git_capture_fd_bytes_exact_bounded(
            authority_fd, &authority_data, &authority_length,
            &authority_stat, GIT_FREEBSD_AUTHORITY_MAX_BYTES) != 0 ||
        !S_ISREG(authority_stat.st_mode) ||
        authority_stat.st_nlink != 1 ||
        authority_stat.st_uid != geteuid() ||
        (authority_stat.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->dir_fd, authority_leaf, authority_fd,
            &authority_stat, authority_data, authority_length, NULL) ||
        !git_freebsd_authority_parse(
            authority_data, authority_length, &authority) ||
        !git_recovery_marker_parse(
            authority.marker_data, authority.marker_length, &marker)) {
        saved_errno = errno ? errno : ESTALE;
        goto done;
    }
    witness_fd = openat(
        lock->dir_fd, lease_leaf,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (witness_fd < 0 ||
        git_scope_lock_claim_fd(witness_fd) != 0 ||
        fstat(witness_fd, &lease_stat) != 0 ||
        !S_ISREG(lease_stat.st_mode) || lease_stat.st_size != 0 ||
        (lease_stat.st_nlink != 1 && lease_stat.st_nlink != 2)) {
        saved_errno = errno ? errno : ESTALE;
        goto done;
    }
    lease_baseline = authority.lease_stat;
    lease_baseline.st_nlink = lease_stat.st_nlink;
    if (!git_file_at_matches_witness(
            lock->dir_fd, lease_leaf, witness_fd,
            &lease_baseline, NULL, 0U, &lease_stat)) {
        saved_errno = errno ? errno : ESTALE;
        goto done;
    }
    if (lease_stat.st_nlink == 2) {
        lease_fd = openat(
            lock->dir_fd, lock->lock_leaf,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (lease_fd < 0 ||
            !git_file_at_matches_witness(
                lock->dir_fd, lock->lock_leaf, witness_fd,
                &lease_stat, NULL, 0U, NULL)) {
            saved_errno = errno ? errno : ESTALE;
            goto done;
        }
    }
    if (lease_stat.st_nlink == 1 &&
        !git_file_at_matches_witness(
            lock->dir_fd, lease_leaf, witness_fd,
            &lease_stat, NULL, 0U, NULL)) {
        saved_errno = errno ? errno : ESTALE;
        goto done;
    }
    if (marker.stage_present) {
        stage_fd = openat(
            lock->dir_fd, marker.stage_leaf,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (stage_fd >= 0) {
            cleanup = git_scope_lock_cleanup_name(
                lock, marker.stage_leaf,
                "FreeBSD recovery staging file", stage_fd,
                &marker.stage_stat, marker.stage_data,
                marker.stage_length, true, false);
            if (cleanup != GIT_CLEANUP_SETTLED) {
                saved_errno = errno ? errno : ESTALE;
                goto done;
            }
        } else if (errno != ENOENT) {
            saved_errno = errno;
            goto done;
        }
    }
    if (fsync(lock->dir_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }
    cleanup = git_scope_lock_cleanup_name(
        lock, authority_leaf, "FreeBSD recovery authority",
        authority_fd, &authority_stat, authority_data,
        authority_length, true, false);
    if (cleanup != GIT_CLEANUP_SETTLED ||
        fsync(lock->dir_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }
    if (lease_fd >= 0) {
        cleanup = git_scope_lock_cleanup_name(
            lock, lock->lock_leaf,
            "FreeBSD recovery canonical lease", lease_fd,
            &lease_stat, NULL, 0U, true, false);
        if (cleanup != GIT_CLEANUP_SETTLED ||
            fsync(lock->dir_fd) != 0) {
            saved_errno = errno ? errno : EIO;
            goto done;
        }
    }
    if (fstat(witness_fd, &lease_stat) != 0 ||
        lease_stat.st_nlink != 1) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    cleanup = git_scope_lock_cleanup_name(
        lock, lease_leaf, "FreeBSD recovery lease witness",
        witness_fd, &lease_stat, NULL, 0U, true, false);
    if (cleanup != GIT_CLEANUP_SETTLED ||
        fsync(lock->dir_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }
    result = 1;

done:
    if (stage_fd >= 0) (void)close(stage_fd);
    if (witness_fd >= 0) (void)close(witness_fd);
    if (lease_fd >= 0) (void)close(lease_fd);
    if (authority_fd >= 0) (void)close(authority_fd);
    if (authority_data) {
        secure_zero_memory(authority_data, authority_length);
        free(authority_data);
    }
    if (directory) (void)closedir(directory);
    errno = result >= 0 ? 0 : (saved_errno ? saved_errno : ESTALE);
    return result;
}

static int git_scope_lock_create_freebsd_lease(
    git_scope_lock_t *lock, int *lease_fd_out) {
    char lease_leaf[96];
    struct stat lease_stat;
    int lease_fd = -1;
    bool canonical_linked = false;

    if (!lock || lock->dir_fd < 0 || !lease_fd_out) {
        errno = EINVAL;
        return -1;
    }
    *lease_fd_out = -1;
    for (size_t slot = 0U; slot < g_cleanup_arena_capacity; slot++) {
        if ((size_t)snprintf(
                lease_leaf, sizeof(lease_leaf),
                ".gitswitch-lease-v2-%016" PRIx64
                "%016" PRIx64 "-%08zx-%04zu",
                git_cleanup_leaf_hash(lock->lock_leaf),
                git_cleanup_leaf_hash_secondary(lock->lock_leaf),
                strlen(lock->lock_leaf), slot) >=
                sizeof(lease_leaf)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        lease_fd = openat(
            lock->dir_fd, lease_leaf,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (lease_fd >= 0) break;
        if (errno != EEXIST) return -1;
    }
    if (lease_fd < 0) {
        errno = ENOSPC;
        return -1;
    }
    if (git_scope_lock_claim_fd(lease_fd) != 0 ||
        fstat(lease_fd, &lease_stat) != 0 ||
        !S_ISREG(lease_stat.st_mode) ||
        lease_stat.st_nlink != 1 || lease_stat.st_size != 0 ||
        linkat(lock->dir_fd, lease_leaf, lock->dir_fd,
               lock->lock_leaf, 0) != 0) {
        int saved_errno = errno ? errno : EIO;

        (void)funlinkat(lock->dir_fd, lease_leaf, lease_fd, 0);
        (void)fsync(lock->dir_fd);
        (void)close(lease_fd);
        errno = saved_errno;
        return -1;
    }
    canonical_linked = true;
    if (fstat(lease_fd, &lease_stat) != 0 ||
        lease_stat.st_nlink != 2 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lease_leaf, lease_fd,
            &lease_stat, NULL, 0U, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lease_fd,
            &lease_stat, NULL, 0U, NULL) ||
        fsync(lock->dir_fd) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (funlinkat(lock->dir_fd, lock->lock_leaf,
                      lease_fd, 0) == 0 &&
            fsync(lock->dir_fd) == 0) {
            canonical_linked = false;
            (void)funlinkat(lock->dir_fd, lease_leaf, lease_fd, 0);
            (void)fsync(lock->dir_fd);
        }
        (void)close(lease_fd);
        errno = saved_errno;
        return -1;
    }
    if (safe_strncpy(
            lock->recovery_lease_leaf, lease_leaf,
            sizeof(lock->recovery_lease_leaf)) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (canonical_linked &&
            funlinkat(lock->dir_fd, lock->lock_leaf,
                      lease_fd, 0) == 0 &&
            fsync(lock->dir_fd) == 0) {
            canonical_linked = false;
            (void)funlinkat(lock->dir_fd, lease_leaf, lease_fd, 0);
            (void)fsync(lock->dir_fd);
        }
        (void)close(lease_fd);
        errno = saved_errno;
        return -1;
    }
    lock->recovery_lease_created = true;
    *lease_fd_out = lease_fd;
    return 0;
}
#endif

/* FreeBSD lacks a native no-replace rename for regular files. Finalization
 * therefore publishes a complete private recovery certificate with linkat()
 * and retires the private alias immediately afterward. A crash between those
 * two namespace operations leaves exactly two links to the same complete
 * marker. Recognize only that narrow shape: one canonical name, one strictly
 * named private alias, exact bytes, private ownership, and no third link. */
static int git_recovery_remove_linked_private_alias(
    git_scope_lock_t *lock, int marker_fd, unsigned char *marker_data,
    size_t marker_length, struct stat *marker_stat) {
    char alias_leaf[sizeof(
        ((git_config_finalization_lock_t *)0)->private_leaf)] = "";
    struct stat candidate;
    struct stat updated;
    struct dirent *entry;
    DIR *directory = NULL;
    int alias_fd = -1;
    int directory_scan_fd = -1;
    int saved_errno = EEXIST;
    int matches = 0;
    git_cleanup_result_t cleanup;

    if (!lock || lock->dir_fd < 0 || marker_fd < 0 || !marker_data ||
        !marker_stat || marker_stat->st_nlink != 2) {
        errno = EINVAL;
        return -1;
    }
    directory_scan_fd = openat(
        lock->dir_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_scan_fd < 0 ||
        (directory = fdopendir(directory_scan_fd)) == NULL) {
        saved_errno = errno ? errno : EIO;
        if (directory_scan_fd >= 0) (void)close(directory_scan_fd);
        errno = saved_errno;
        return -1;
    }
    directory_scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!git_finalization_private_leaf_valid(entry->d_name)) continue;
        if (fstatat(lock->dir_fd, entry->d_name, &candidate,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            saved_errno = errno ? errno : EIO;
            goto done;
        }
        if (candidate.st_dev != marker_stat->st_dev ||
            candidate.st_ino != marker_stat->st_ino) {
            continue;
        }
        matches++;
        if (matches != 1 ||
            safe_strncpy(alias_leaf, entry->d_name,
                         sizeof(alias_leaf)) != 0) {
            saved_errno = EEXIST;
            goto done;
        }
        errno = 0;
    }
    if (errno != 0) {
        saved_errno = errno;
        goto done;
    }
    if (matches != 1) {
        saved_errno = EEXIST;
        goto done;
    }
    alias_fd = openat(lock->dir_fd, alias_leaf,
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (alias_fd < 0 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, marker_fd, marker_stat,
            marker_data, marker_length, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, alias_leaf, alias_fd, marker_stat,
            marker_data, marker_length, NULL)) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    cleanup = git_scope_lock_cleanup_name_once(
        lock, alias_leaf, "linked private recovery marker", alias_fd,
        marker_stat, marker_data, marker_length, true, false);
    if (cleanup != GIT_CLEANUP_SETTLED) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    /* Keep the canonical certificate until private-alias retirement is
     * durable. A crash before this sync simply recreates the recognizable
     * two-link state and is safe to retry. */
    if (fsync(lock->dir_fd) != 0 ||
        fstat(marker_fd, &updated) != 0 ||
        !S_ISREG(updated.st_mode) || updated.st_nlink != 1 ||
        updated.st_uid != geteuid() ||
        (updated.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, marker_fd, &updated,
            marker_data, marker_length, NULL)) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    *marker_stat = updated;
    saved_errno = 0;

done:
    if (alias_fd >= 0) (void)close(alias_fd);
    if (directory) (void)closedir(directory);
    errno = saved_errno;
    return saved_errno == 0 ? 0 : -1;
}

static int git_scope_lock_recover_marker(git_scope_lock_t *lock) {
    git_recovery_marker_t marker;
    git_cleanup_result_t cleanup;
    unsigned char *marker_data = NULL;
    size_t marker_length = 0U;
    struct stat marker_stat;
    int marker_fd = -1;
    int stage_fd = -1;
    int result = -1;
    int saved_errno = EEXIST;

    memset(&marker, 0, sizeof(marker));
    if (!lock || lock->dir_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    marker_fd = openat(lock->dir_fd, lock->lock_leaf,
                       O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (marker_fd < 0 ||
        git_scope_lock_claim_fd(marker_fd) != 0 ||
        git_capture_fd_bytes_exact_bounded(
            marker_fd, &marker_data, &marker_length, &marker_stat,
            GIT_RECOVERY_MARKER_MAX_BYTES) != 0) {
        saved_errno = errno ? errno : EEXIST;
        goto done;
    }
    if (!S_ISREG(marker_stat.st_mode) ||
        (marker_stat.st_nlink != 1 && marker_stat.st_nlink != 2) ||
        marker_stat.st_uid != geteuid() ||
        (marker_stat.st_mode & 07777) != 0600) {
        saved_errno = EEXIST;
        goto done;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, marker_fd, &marker_stat,
            marker_data, marker_length, NULL)) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    if (!git_recovery_marker_parse(
            marker_data, marker_length, &marker)) {
        /* A structurally foreign marker is a namespace conflict. Do not leak
         * an unrelated errno left by a successful filesystem observation. */
        saved_errno = EEXIST;
        goto done;
    }
    if (marker_stat.st_nlink == 2 &&
        git_recovery_remove_linked_private_alias(
            lock, marker_fd, marker_data, marker_length,
            &marker_stat) != 0) {
        saved_errno = errno ? errno : EEXIST;
        goto done;
    }
    if (marker.stage_present) {
        stage_fd = openat(lock->dir_fd, marker.stage_leaf,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (stage_fd < 0) {
            if (errno != ENOENT) {
                saved_errno = errno;
                goto done;
            }
        } else {
            cleanup = git_scope_lock_cleanup_name_once(
                lock, marker.stage_leaf, "recovery staging file", stage_fd,
                &marker.stage_stat, marker.stage_data, marker.stage_length,
                true, false);
            if (cleanup != GIT_CLEANUP_SETTLED) {
                saved_errno = errno ? errno : EAGAIN;
                goto done;
            }
        }
        /* Make stage absence durable while the claimed marker still blocks
         * every cooperative writer. A crash can then leave the marker, never
         * lose the only recovery authority while resurrecting the stage. */
        if (fsync(lock->dir_fd) != 0) {
            saved_errno = errno ? errno : EIO;
            goto done;
        }
    }
    cleanup = git_scope_lock_cleanup_name_once(
        lock, lock->lock_leaf, "recovery marker", marker_fd, &marker_stat,
        marker_data, marker_length, true, false);
    if (cleanup != GIT_CLEANUP_SETTLED) {
        saved_errno = errno ? errno : EAGAIN;
        goto done;
    }
    if (fsync(lock->dir_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }
    result = 0;

done:
    if (stage_fd >= 0) (void)close(stage_fd);
    if (marker_fd >= 0) (void)close(marker_fd);
    if (marker_data) {
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
    }
    errno = result == 0 ? 0 : saved_errno;
    return result;
}

/* Remove only exact transaction-owned names. A transient failure retains the
 * ownership bit for the checked retry above; a proven replacement is disowned
 * and preserved. Resource disposal never changes the filesystem. */
static int git_scope_lock_cleanup_owned(git_scope_lock_t *lock,
                                        bool retirement_hook) {
    git_cleanup_witness_t stage_witness;
    git_cleanup_result_t cleanup;
    bool stage_retry = false;
    int result = 0;

    if (!lock) return 0;
    if (retirement_hook && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_CLEANUP,
                               lock->path, NULL, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Injected Git retirement cleanup ownership conflict");
        result = -1;
    }
    if (lock->stage_created && lock->dir_fd >= 0) {
        stage_witness = git_scope_lock_stage_witness(lock);
        cleanup = git_scope_lock_cleanup_name(
            lock, lock->stage_leaf, "staging file",
            stage_witness.fd, stage_witness.stat, stage_witness.data,
            stage_witness.length, stage_witness.valid, retirement_hook);
        if (cleanup != GIT_CLEANUP_SETTLED) {
            result = -1;
        }
        if (cleanup != GIT_CLEANUP_RETRY) {
            lock->stage_created = false;
        } else {
            stage_retry = true;
        }
    }
    if (!stage_retry && lock->lock_created && lock->dir_fd >= 0) {
        cleanup = git_scope_lock_cleanup_name(
            lock, lock->lock_leaf, "canonical lock", lock->lock_fd,
            &lock->lock_stat, NULL, 0U, lock->lock_witness_valid,
            retirement_hook);
        if (cleanup != GIT_CLEANUP_SETTLED) {
            result = -1;
        }
        if (cleanup != GIT_CLEANUP_RETRY) {
            lock->lock_created = false;
        }
#if defined(__FreeBSD__)
        if (cleanup == GIT_CLEANUP_SETTLED &&
            lock->recovery_lease_created) {
            if (fstat(lock->lock_fd, &lock->lock_stat) != 0 ||
                lock->lock_stat.st_nlink != 1) {
                result = -1;
            } else {
                cleanup = git_scope_lock_cleanup_name(
                    lock, lock->recovery_lease_leaf,
                    "private canonical lease", lock->lock_fd,
                    &lock->lock_stat, NULL, 0U, true,
                    retirement_hook);
                if (cleanup != GIT_CLEANUP_SETTLED) result = -1;
                if (cleanup != GIT_CLEANUP_RETRY) {
                    lock->recovery_lease_created = false;
                }
            }
        }
#endif
    }
    return result;
}

static void git_scope_lock_close_mode(
    git_scope_lock_t *lock, bool inherited) {
    if (!lock) return;
    if (!inherited && lock->lock_fd >= 0) close(lock->lock_fd);
    lock->lock_fd = -1;
    if (!inherited && lock->recovery_authority_fd >= 0) {
        (void)close(lock->recovery_authority_fd);
    }
    lock->recovery_authority_fd = -1;
    git_scope_lock_clear_stage_witness_mode(lock, inherited);
    if (!inherited && lock->original_fd >= 0) close(lock->original_fd);
    lock->original_fd = -1;
    if (!inherited && lock->published_fd >= 0) close(lock->published_fd);
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
    if (lock->recovery_marker_data) {
        secure_zero_memory(lock->recovery_marker_data,
                           lock->recovery_marker_length);
        free(lock->recovery_marker_data);
    }
    lock->recovery_marker_data = NULL;
    lock->recovery_marker_length = 0U;
    lock->recovery_marker_published = false;
    lock->recovery_marker_witness_valid = false;
    if (lock->recovery_authority_data) {
        secure_zero_memory(lock->recovery_authority_data,
                           lock->recovery_authority_length);
        free(lock->recovery_authority_data);
    }
    lock->recovery_authority_data = NULL;
    lock->recovery_authority_length = 0U;
    lock->recovery_authority_leaf[0] = '\0';
    lock->recovery_authority_witness_valid = false;
    lock->recovery_lease_leaf[0] = '\0';
    lock->recovery_lease_created = false;
    if (!inherited && lock->dir_fd >= 0) close(lock->dir_fd);
    lock->dir_fd = -1;
}

static void git_scope_lock_close(git_scope_lock_t *lock) {
    git_scope_lock_close_mode(lock, false);
}

/* A finalization lease deliberately occupies Git's canonical lock name with a
 * complete recovery marker. If its owner exits before release, the next
 * gitswitch-managed write gets one exact self-healing retry. Ordinary Git lock
 * files, malformed lookalikes, foreign replacements, and live claimed
 * certificates are all preserved and reported as write failures. */
static int git_recover_scope_finalization_marker(git_scope_t scope) {
    git_scope_lock_t recovery;
    struct stat named;
    int saved_errno;

    git_scope_lock_init(&recovery);
    if (git_scope_lock_resolve_paths(scope, &recovery) != 0) {
        return -1;
    }
    recovery.dir_fd = open(
        recovery.parent,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (recovery.dir_fd < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot inspect the Git configuration lock directory");
        return -1;
    }
    if (fstatat(recovery.dir_fd, recovery.lock_leaf, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = errno;
        git_scope_lock_close(&recovery);
        if (saved_errno == ENOENT) {
            errno = 0;
            return 0;
        }
        errno = saved_errno;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot inspect the Git configuration lock");
        return -1;
    }
#if defined(__FreeBSD__)
    if (S_ISREG(named.st_mode) && named.st_size == 0) {
        int recovered =
            git_scope_lock_recover_freebsd_authority(&recovery);

        if (recovered != 0) {
            saved_errno = errno;
            git_scope_lock_close(&recovery);
            if (recovered > 0) {
                errno = 0;
                return 1;
            }
            errno = saved_errno ? saved_errno : EIO;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot recover the Git configuration lock authority");
            return -1;
        }
    }
#endif
    if (git_scope_lock_recover_marker(&recovery) != 0) {
        saved_errno = errno ? errno : EEXIST;
        git_scope_lock_close(&recovery);
        errno = saved_errno;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Existing Git configuration lock is not an exact recoverable "
            "gitswitch certificate");
        return -1;
    }
    git_scope_lock_close(&recovery);
    return 1;
}

static int git_scope_lock_discard_checked(git_scope_lock_t *lock,
                                          bool retirement_hook) {
    error_accumulator_t failures;
    bool owned_names;
    bool cleanup_allowed = true;
    int entry_errno = errno;
    int result = 0;

    if (!lock) return 0;
    error_accumulator_init(&failures);
    owned_names = lock->stage_created || lock->lock_created;
#if defined(__FreeBSD__)
    /* A detached O alias is the last exact before-image after canonical was
     * removed. Transfer it into the durable A/W/C recovery protocol before
     * any generic cleanup can delete either O or the exclusion lease. */
    if (lock->stage_created &&
        lock->stage_witness_kind == GIT_STAGE_WITNESS_ORIGINAL &&
        lock->detached_original_recovery_required &&
        !lock->recovery_marker_published) {
        if (git_scope_lock_persist_recovery_marker(lock) != 0) {
            (void)error_accumulator_add_last(
                &failures, "detached Git before-image recovery authority");
            result = -1;
            cleanup_allowed = false;
        }
    }
#endif
    if (cleanup_allowed &&
        git_scope_lock_cleanup_owned(lock, retirement_hook) != 0) {
        (void)error_accumulator_add_last(
            &failures, "Git transaction artifact cleanup");
        result = -1;
    }
    if ((lock->stage_created || lock->lock_created) &&
        !lock->recovery_marker_published &&
        git_scope_lock_persist_recovery_marker(lock) != 0) {
        (void)error_accumulator_add_last(
            &failures, "Git transaction recovery marker");
        result = -1;
    }
    if (owned_names && lock->dir_fd >= 0 && fsync(lock->dir_fd) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot durably clean Git transaction artifacts");
        (void)error_accumulator_add_last(
            &failures, "Git transaction artifact directory sync");
        result = -1;
    }
    git_scope_lock_close(lock);
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
        errno = failures.first_errno;
    } else {
        errno = entry_errno;
    }
    return result;
}

/* Acquire exactly the lock name used by Git for this config file, then copy
 * the full current file into it. The in-lock copy is the merge base, so every
 * unmanaged edit that completed before lock acquisition survives publication. */
static int git_scope_lock_acquire(git_scope_t scope, const char *exact_path,
                                  git_scope_lock_t *lock,
                                  const git_scope_generation_t *generation) {
#if !defined(__FreeBSD__)
    static unsigned long stage_nonce;
#endif
    int lock_fd = -1;
    int source_fd = -1;
    int stage_fd = -1;
    struct stat named;
    struct stat opened;
    struct stat captured;
    struct stat named_after;
    struct stat created;

    git_scope_lock_init(lock);
    if ((exact_path
             ? git_scope_lock_resolve_exact_path(exact_path, lock)
             : git_scope_lock_resolve_paths(scope, lock)) != 0) {
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
    if (git_cleanup_arena_require_budget(
            lock->dir_fd, lock->lock_leaf,
            GIT_CLEANUP_ARENA_HANDLE_BUDGET) != 0) {
        int arena_errno = errno;

        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            arena_errno == ENOSPC
                ? "Git cleanup arena is exhausted before lock mutation: %s. Stop all writers and inspect verified .gitswitch-cleanup-v2 artifacts during offline quiescence"
                : "Git configuration lock has pending private cleanup residue: %s. Stop all writers and inspect the associated .gitswitch-cleanup-v2 pending slot during offline quiescence",
            lock->lock_path);
        errno = arena_errno;
        git_scope_lock_close(lock);
        return -1;
    }
#if defined(__FreeBSD__)
    {
        int recovered =
            git_scope_lock_recover_freebsd_authority(lock);
        if (recovered < 0) {
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot reconcile the bounded FreeBSD Git recovery authority");
            git_scope_lock_close(lock);
            return -1;
        }
        lock->freebsd_authority_recovered = recovered > 0;
    }
#endif
    if (g_restore_prelock_hook) g_restore_prelock_hook(scope);
#if defined(__FreeBSD__)
    if (git_scope_lock_create_freebsd_lease(lock, &lock_fd) != 0 &&
        errno == EEXIST &&
        git_scope_lock_recover_marker(lock) == 0) {
        lock_fd = -1;
        (void)git_scope_lock_create_freebsd_lease(lock, &lock_fd);
    }
#else
    lock_fd = openat(lock->dir_fd, lock->lock_leaf,
                     O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (lock_fd < 0 && errno == EEXIST &&
        git_scope_lock_recover_marker(lock) == 0) {
        lock_fd = openat(lock->dir_fd, lock->lock_leaf,
                         O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    }
#endif
    if (lock_fd < 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot acquire Git configuration lock: %s",
                         lock->lock_path);
        git_scope_lock_close(lock);
        return -1;
    }
    lock->lock_created = true;
    lock->lock_fd = lock_fd;
    lock_fd = -1;
    if (git_scope_lock_claim_fd(lock->lock_fd) != 0 ||
        fstat(lock->lock_fd, &lock->lock_stat) != 0 ||
        !S_ISREG(lock->lock_stat.st_mode) ||
#if defined(__FreeBSD__)
        lock->lock_stat.st_nlink != 2) {
#else
        lock->lock_stat.st_nlink != 1) {
#endif
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot pin Git configuration lock: %s",
                         lock->lock_path);
        goto fail;
    }
    lock->lock_witness_valid = true;

#if defined(__FreeBSD__)
    if (git_freebsd_bounded_stage_leaf(
            lock, 's', lock->stage_leaf) != 0 ||
        (size_t)snprintf(lock->stage_path, sizeof(lock->stage_path),
                         "%s/%s", lock->parent, lock->stage_leaf) >=
            sizeof(lock->stage_path)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback staging path is too long");
        goto fail;
    }
    stage_fd = openat(lock->dir_fd, lock->stage_leaf,
                      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (stage_fd >= 0) lock->stage_created = true;
#else
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
                          O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
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
#endif
    if (stage_fd < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot allocate the bounded Git rollback staging file");
        goto fail;
    }
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
    if (git_scope_lock_capture_stage_witness(lock) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot pin Git rollback staging file: %s",
                         lock->stage_path);
        goto fail;
    }
    return 0;

fail:
    {
        error_context_t primary_error = *get_last_error();
        error_accumulator_t failures;
        int primary_errno = errno;
        int cleanup_result;

        error_accumulator_init(&failures);
        errno = primary_errno;
        (void)error_accumulator_add(
            &failures, "Git configuration lock acquisition", &primary_error);
        if (source_fd >= 0) close(source_fd);
        if (lock_fd >= 0) close(lock_fd);
        if (stage_fd >= 0) close(stage_fd);
        if (lock->lock_created && !lock->lock_witness_valid) {
            (void)git_scope_lock_capture_empty_lock_witness(lock);
        }
        if (lock->stage_created && !lock->stage_witness_valid) {
            (void)git_scope_lock_capture_stage_witness(lock);
        }
        cleanup_result = git_scope_lock_discard_checked(lock, false);
        if (cleanup_result != 0) {
            (void)error_accumulator_add_last(
                &failures, "Git configuration lock acquisition cleanup");
        }
        errno = primary_errno;
        (void)error_accumulator_publish(&failures);
        errno = primary_errno;
    }
    return -1;
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

/* Remove the one exact occurrence whose uniqueness was proven from the
 * immutable retirement vector. `--fixed-value` keeps regex metacharacters
 * literal. Exit 5 is a conflict here: the planned occurrence disappeared
 * between verification and the staged command. */
static int git_config_file_unset_exact(const char *path, const char *key,
                                       const char *value,
                                       const char *diagnostic_context) {
    char output[256] = "";
    const char *const argv[] = {
        "git", "config", "--file", path, "--no-includes",
        "--fixed-value", "--unset-all", key, value, NULL
    };
    run_opts_t opts;
    run_result_t result;
    uint64_t prior_error_generation;
    int run_rc;

    if (!path || !key || !value) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid exact Git configuration removal request");
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    prior_error_generation = error_report_generation();
    run_rc = run_argv(argv, &opts, &result);
    if (run_rc == 0 && result.spawned &&
        result.term_signal == 0 && result.exit_code == 0 &&
        !result.out_truncated) {
        return 0;
    }
    if (error_report_generation() != prior_error_generation) return -1;
    set_error(ERR_GIT_CONFIG_FAILED,
              "Failed to remove exact Git config %s value in %s: %s",
              key,
              diagnostic_context ? diagnostic_context : "staged file",
              output[0] ? output : "Git did not remove the planned value");
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

static void git_set_file_snapshot_run_error(const char *context,
                                            const run_result_t *result) {
    const char *operation = context ? context :
        "Could not read exact Git configuration snapshot";

    if (!result || !result->spawned) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git could not be started",
                  operation);
    } else if (result->term_signal != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git was killed by signal %d",
                  operation, result->term_signal);
    } else if (result->exit_code != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "%s: Git exited with status %d",
                  operation, result->exit_code);
    } else {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "%s: Git output capture failed after successful exit",
                  operation);
    }
}

/* Capture every managed vector from one exact physical configuration file.
 * Binary stdout stays isolated from diagnostics: stderr text can otherwise be
 * interleaved with valid NUL records and turn a failed read into a plausible
 * partial snapshot. Each truncated attempt is discarded and retried with a
 * larger buffer. The caller receives state only after the complete listing
 * parses successfully; missing files and every operational failure are errors,
 * while a successful zero-length listing is the exact all-absent vector. */
static int git_capture_file_snapshot(const char *path, const char *context,
                                     git_scope_snapshot_t *out) {
    size_t capacity = GIT_SNAPSHOT_INITIAL_BYTES;
    char *buffer;
    git_scope_snapshot_t next;
    const char *const diagnostic_env[] = {
        "LC_ALL=C", "LANG=C", NULL
    };

    if (!path || path[0] != '/' || !out) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid exact-file Git configuration snapshot request");
        return -1;
    }
    memset(&next, 0, sizeof(next));
    buffer = malloc(capacity);
    if (!buffer) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory reading exact Git configuration snapshot");
        return -1;
    }
    for (;;) {
        const char *const argv[] = {
            "git", "config", "--file", path, "--list", "-z",
            "--no-includes", NULL
        };
        run_opts_t opts;
        run_result_t result;
        uint64_t prior_error_generation;
        int run_rc;

        memset(&opts, 0, sizeof(opts));
        memset(&result, 0, sizeof(result));
        opts.out = buffer;
        opts.out_size = capacity;
        opts.stderr_to_devnull = true;
        opts.extra_env = diagnostic_env;
        /* A runner reports a precise resolver/I/O failure through the global
         * context. Its report generation distinguishes an identical new
         * diagnostic from stale state without erasing an earlier preflight
         * failure that the caller has retained for final aggregation. */
        prior_error_generation = error_report_generation();
        run_rc = run_argv(argv, &opts, &result);
        if (run_rc != 0) {
            /* The production runner can already provide a path-trust or I/O
             * diagnostic more precise than child status. Recording fakes
             * generally publish nothing, so synthesize their causal status. */
            if (error_report_generation() == prior_error_generation) {
                git_set_file_snapshot_run_error(context, &result);
            }
            goto fail;
        }
        if (!result.out_truncated) {
            if (result.out_len >= capacity) {
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Invalid exact Git configuration snapshot length");
                goto fail;
            }
            if (git_parse_snapshot_listing(buffer, result.out_len,
                                           &next, true) != 0) {
                goto fail;
            }
            free(buffer);
            *out = next;
            return 0;
        }
        if (capacity >= GIT_SNAPSHOT_MAX_BYTES) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Exact Git configuration snapshot exceeds %u bytes",
                      (unsigned)GIT_SNAPSHOT_MAX_BYTES);
            goto fail;
        }
        {
            size_t grown_size = capacity * 2U;
            char *grown;
            if (grown_size > GIT_SNAPSHOT_MAX_BYTES) {
                grown_size = GIT_SNAPSHOT_MAX_BYTES;
            }
            grown = realloc(buffer, grown_size);
            if (!grown) {
                set_error(ERR_MEMORY_ALLOCATION,
                          "Out of memory growing exact Git configuration snapshot");
                goto fail;
            }
            buffer = grown;
            capacity = grown_size;
        }
    }

fail:
    free(buffer);
    git_scope_snapshot_clear(&next);
    return -1;
}

static int git_scope_lock_publish_retirement_exchange(
    git_scope_lock_t *lock, const struct stat *captured_stage,
    bool retirement_exact) {
    git_exchange_result_t exchanged;
    bool canonical_prepared;
    bool displaced_original;
    bool stage_prepared;
    bool after_exchange_failure;
    bool force_fallback;

    if (!lock || !captured_stage || !lock->original_present ||
        !lock->original_witness_valid || lock->original_fd < 0 ||
        !lock->published_witness_valid || lock->published_fd < 0 ||
        (lock->published_length != 0U && !lock->published_data)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid exact Git retirement publication state");
        return -1;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->stage_leaf, lock->published_fd,
            captured_stage, lock->published_data,
            lock->published_length, &lock->published_stat)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Prepared Git retirement image changed before exchange");
        return -1;
    }
    if (retirement_exact && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_EXCHANGE,
                               lock->path, NULL, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Injected Git retirement exchange failure");
        return -1;
    }
    force_fallback = retirement_exact && g_retirement_test_hook &&
                     g_retirement_test_hook(
                         GIT_RETIREMENT_TEST_FORCE_EXCHANGE_FALLBACK,
                         lock->path, NULL, NULL);
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->leaf, lock->original_fd,
            &lock->original_stat, lock->original_data,
            lock->original_length, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git retirement destination or canonical lock changed at the publication boundary");
        return -1;
    }
    exchanged = force_fallback
                    ? GIT_EXCHANGE_UNSUPPORTED
                    : git_exchange_names_at(lock->dir_fd, lock->stage_leaf,
                                            lock->leaf);
    if (exchanged != GIT_EXCHANGE_OK) {
        if (exchanged == GIT_EXCHANGE_UNSUPPORTED) {
            return 1;
        }
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot atomically exchange the Git retirement image");
        return -1;
    }
    /* From this point onward, classification is allocation-free and never
     * mutates either published name. A failed observation can disown a
     * foreign pathname, but cannot authorize swapping it into canonical. */
    lock->stage_witness_kind = GIT_STAGE_WITNESS_ORIGINAL;
    after_exchange_failure =
        retirement_exact && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_AFTER_EXCHANGE,
                               lock->path, lock->stage_path, NULL);
    canonical_prepared = git_file_at_matches_witness(
        lock->dir_fd, lock->leaf, lock->published_fd,
        &lock->published_stat, lock->published_data,
        lock->published_length, NULL);
    displaced_original = git_file_at_matches_witness(
        lock->dir_fd, lock->stage_leaf, lock->original_fd,
        &lock->original_stat, lock->original_data,
        lock->original_length, NULL);
    stage_prepared = git_file_at_matches_witness(
        lock->dir_fd, lock->stage_leaf, lock->published_fd,
        &lock->published_stat, lock->published_data,
        lock->published_length, NULL);
    if (after_exchange_failure || !canonical_prepared ||
        !displaced_original) {
        lock->published = canonical_prepared;
        if (displaced_original) {
            lock->stage_witness_kind = GIT_STAGE_WITNESS_ORIGINAL;
        } else if (stage_prepared) {
            lock->stage_witness_kind = GIT_STAGE_WITNESS_PUBLISHED;
        } else {
            /* No retained witness authorizes this stage pathname. Preserve
             * it as foreign and let checked cleanup remove only our lock. */
            lock->stage_created = false;
        }
        set_error(
            ERR_GIT_CONFIG_FAILED,
            after_exchange_failure
                ? "Injected Git retirement post-exchange ownership failure"
                : "Git rollback destination changed at the publication boundary");
        return -1;
    }
    lock->published = true;
    if (retirement_exact && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC,
                               lock->path, NULL, NULL)) {
        errno = EIO;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git retirement was installed but its directory sync failed: %s",
                         lock->path);
        return -1;
    }
    if (fsync(lock->dir_fd) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "%s was installed but its directory sync failed: %s",
                         retirement_exact ? "Git retirement" : "Git rollback",
                         lock->path);
        return -1;
    }
    return 0;
}

/* On filesystems without a native name exchange, retain the original inode
 * under a private checked name before the prepared stage replaces canonical.
 * The extra link is reduced back to one by the replacement rename, leaving an
 * exact original-generation rollback source under the continuously held Git
 * lock. */
#if defined(__FreeBSD__)
static int git_scope_lock_preserve_fallback_original(
    git_scope_lock_t *lock, char backup_leaf[96],
    struct stat *linked_original) {
    if (!lock || !backup_leaf || !linked_original ||
        !lock->original_present || !lock->original_witness_valid ||
        lock->original_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (git_freebsd_bounded_stage_leaf(lock, 'o', backup_leaf) != 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot derive the bounded original Git retirement witness");
        return -1;
    }
    for (unsigned attempt = 0U; attempt < 1U; attempt++) {
        if (linkat(lock->dir_fd, lock->leaf,
                   lock->dir_fd, backup_leaf, 0) == 0) {
            if (fstat(lock->original_fd, linked_original) == 0 &&
                linked_original->st_nlink == 2 &&
                git_file_at_matches_witness(
                    lock->dir_fd, lock->leaf, lock->original_fd,
                    linked_original, lock->original_data,
                    lock->original_length, NULL) &&
                git_file_at_matches_witness(
                    lock->dir_fd, backup_leaf, lock->original_fd,
                    linked_original, lock->original_data,
                    lock->original_length, NULL)) {
                return 0;
            }
            {
                int saved_errno = errno ? errno : EAGAIN;
                int backup_fd = openat(
                    lock->dir_fd, backup_leaf,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
                struct stat backup_stat;

                if (backup_fd >= 0 &&
                    fstat(backup_fd, &backup_stat) == 0) {
                    (void)git_scope_lock_cleanup_name(
                        lock, backup_leaf,
                        "unproven fallback original backup", backup_fd,
                        &backup_stat, NULL, 0U, true, false);
                }
                if (backup_fd >= 0) (void)close(backup_fd);
                errno = saved_errno;
            }
            break;
        }
        if (errno != EEXIST) break;
    }
    set_system_error(ERR_GIT_CONFIG_FAILED,
                     "Cannot preserve the original Git retirement generation for fallback rollback");
    return -1;
}

static int git_freebsd_track_detached_original(
    git_scope_lock_t *lock, const char *original_leaf,
    const struct stat *original_stat, bool recovery_required) {
    if (!lock || !original_leaf || !original_stat ||
        original_stat->st_nlink != 1 ||
        safe_strncpy(lock->stage_leaf, original_leaf,
                     sizeof(lock->stage_leaf)) != 0 ||
        (size_t)snprintf(lock->stage_path, sizeof(lock->stage_path),
                         "%s/%s", lock->parent,
                         original_leaf) >= sizeof(lock->stage_path)) {
        errno = errno ? errno : EINVAL;
        return -1;
    }
    git_scope_lock_clear_stage_witness(lock);
    lock->original_stat = *original_stat;
    lock->stage_created = true;
    lock->stage_witness_kind = GIT_STAGE_WITNESS_ORIGINAL;
    lock->detached_original_recovery_required = recovery_required;
    return 0;
}

static int git_freebsd_restore_detached_original(
    git_scope_lock_t *lock, const char *original_leaf,
    struct stat *restored_stat) {
    struct stat linked;
    struct stat settled;

    if (!lock || !original_leaf || !restored_stat ||
        linkat(lock->dir_fd, original_leaf,
               lock->dir_fd, lock->leaf, 0) != 0 ||
        fstat(lock->original_fd, &linked) != 0 ||
        linked.st_nlink != 2 ||
        !git_file_at_matches_witness(
            lock->dir_fd, original_leaf, lock->original_fd,
            &linked, lock->original_data, lock->original_length, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->leaf, lock->original_fd,
            &linked, lock->original_data, lock->original_length, NULL) ||
        funlinkat(lock->dir_fd, original_leaf,
                  lock->original_fd, 0) != 0 ||
        fstat(lock->original_fd, &settled) != 0 ||
        settled.st_nlink != 1 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->leaf, lock->original_fd,
            &settled, lock->original_data, lock->original_length, NULL)) {
        errno = errno ? errno : EAGAIN;
        return -1;
    }
    *restored_stat = settled;
    return 0;
}
#endif

static int git_scope_lock_publish(git_scope_lock_t *lock,
                                  bool retirement_exact) {
    char resolved[MAX_PATH_LEN];
    struct stat named_parent;
    struct stat named_original;
    struct stat named_stage;
    struct stat opened_stage;
    struct stat captured_stage;
    struct stat logical_now;
    int verify_fd;
    int exchange_result;
    bool original_unchanged;
#if defined(__FreeBSD__)
    char fallback_original_leaf[96] = "";
    struct stat linked_original;
#endif

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
        /* The nested verifier assigns EAGAIN only to ctime-only churn. Seed
         * every otherwise-unclassified witness mismatch as a hard stale
         * generation so an external replacement can never enter this retry
         * path merely because a comparison returned false. */
        errno = ESTALE;
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
    lock->published_fd = verify_fd;
    lock->published_stat = captured_stage;
    lock->stage_witness_kind = GIT_STAGE_WITNESS_PUBLISHED;
    verify_fd = -1;
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
    if (lock->original_present) {
        exchange_result = git_scope_lock_publish_retirement_exchange(
            lock, &captured_stage, retirement_exact);
        if (exchange_result <= 0) return exchange_result;
    }
    /* Native exchange is unavailable on some supported systems/filesystems.
     * Keep Git's exact empty canonical lock continuously held and atomically
     * publish the already-pinned private stage directly over the destination.
     * The lock is removed only by checked cleanup after the directory sync. */
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->stage_leaf, lock->published_fd,
            &lock->published_stat, lock->published_data,
            lock->published_length, NULL) ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, NULL) ||
        (lock->original_present
             ? !git_file_at_matches_witness(
                   lock->dir_fd, lock->leaf, lock->original_fd,
                   &lock->original_stat, lock->original_data,
                   lock->original_length, NULL)
             : (fstatat(lock->dir_fd, lock->leaf, &named_original,
                        AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT))) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git rollback destination or canonical lock changed immediately before publication");
        return -1;
    }
#if defined(__FreeBSD__)
    if (lock->original_present &&
        git_scope_lock_preserve_fallback_original(
            lock, fallback_original_leaf, &linked_original) != 0) {
        return -1;
    }
    if (lock->original_present) {
        if (funlinkat(lock->dir_fd, lock->leaf,
                      lock->original_fd, 0) != 0) {
            int saved_errno = errno;

            (void)git_scope_lock_cleanup_name(
                lock, fallback_original_leaf,
                "fallback original backup", lock->original_fd,
                &linked_original, lock->original_data,
                lock->original_length, true, false);
            errno = saved_errno;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot detach the original Git rollback generation");
            return -1;
        }
        if (fstat(lock->original_fd, &linked_original) != 0 ||
            linked_original.st_nlink != 1 ||
            !git_file_at_matches_witness(
                lock->dir_fd, fallback_original_leaf,
                lock->original_fd, &linked_original,
                lock->original_data, lock->original_length, NULL)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot prove the detached original Git rollback generation");
            return -1;
        }
        lock->original_stat = linked_original;
        if (retirement_exact && g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_AFTER_FALLBACK_ORIGINAL_UNLINK,
                lock->path, fallback_original_leaf, NULL)) {
            int saved_errno = errno ? errno : EIO;
            struct stat restored;

            if (git_freebsd_restore_detached_original(
                    lock, fallback_original_leaf, &restored) == 0) {
                lock->original_stat = restored;
                fallback_original_leaf[0] = '\0';
            } else {
                (void)git_freebsd_track_detached_original(
                    lock, fallback_original_leaf, &linked_original, true);
            }
            errno = saved_errno;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Injected interruption after detaching the original Git rollback generation");
            return -1;
        }
    }
    {
        bool force_link_failure =
            retirement_exact && g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_FORCE_FALLBACK_LINK_FAILURE,
                lock->path, lock->stage_leaf, NULL);

        if (force_link_failure ||
            linkat(lock->dir_fd, lock->stage_leaf,
                   lock->dir_fd, lock->leaf, 0) != 0) {
            int publish_errno =
                force_link_failure ? EIO : (errno ? errno : EIO);

            if (fallback_original_leaf[0] != '\0') {
                struct stat restored;

                if (git_freebsd_restore_detached_original(
                        lock, fallback_original_leaf, &restored) == 0) {
                    lock->original_stat = restored;
                    fallback_original_leaf[0] = '\0';
                } else {
                    (void)git_scope_lock_cleanup_name(
                        lock, lock->stage_leaf,
                        "unpublished fallback image",
                        lock->published_fd, &lock->published_stat,
                        lock->published_data,
                        lock->published_length, true, false);
                    (void)git_freebsd_track_detached_original(
                        lock, fallback_original_leaf,
                        &linked_original, true);
                }
            } else {
                lock->stage_created = true;
            }
            errno = publish_errno;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot publish prepared Git rollback image without overwriting a raced replacement: %s",
                lock->path);
            return -1;
        }
    }
    /* The canonical link is the publication linearization point. Preserve
     * that fact even if the following proof or private-alias retirement
     * fails, so callers never treat an installed post-image as unpublished. */
    lock->published = true;
    {
        struct stat linked_stage;
        struct stat settled_stage;
        bool linked_stage_observed =
            fstat(lock->published_fd, &linked_stage) == 0;
        bool injected_post_link_failure =
            retirement_exact && g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_AFTER_FALLBACK_CANONICAL_LINK,
                lock->path, lock->stage_leaf, NULL);

        if (injected_post_link_failure ||
            !linked_stage_observed ||
            linked_stage.st_nlink != 2 ||
            !git_file_at_matches_witness(
                lock->dir_fd, lock->leaf, lock->published_fd,
                &linked_stage, lock->published_data,
                lock->published_length, NULL)) {
            int saved_errno =
                injected_post_link_failure ? EIO
                                           : (errno ? errno : EAGAIN);

            (void)git_scope_lock_cleanup_name(
                lock, lock->stage_leaf,
                "linked fallback publication alias",
                lock->published_fd,
                linked_stage_observed ? &linked_stage
                                      : &lock->published_stat,
                lock->published_data, lock->published_length,
                true, false);
            if (fallback_original_leaf[0] != '\0') {
                (void)git_freebsd_track_detached_original(
                    lock, fallback_original_leaf, &linked_original, true);
            }
            errno = saved_errno;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot prove the linked FreeBSD Git publication");
            return -1;
        }
        lock->published_stat = linked_stage;
        if (funlinkat(lock->dir_fd, lock->stage_leaf,
                      lock->published_fd, 0) != 0 ||
            fstat(lock->published_fd, &settled_stage) != 0 ||
            settled_stage.st_nlink != 1 ||
            !git_file_at_matches_witness(
                lock->dir_fd, lock->leaf, lock->published_fd,
                &settled_stage, lock->published_data,
                lock->published_length, NULL)) {
            int saved_errno = errno ? errno : EAGAIN;

            if (fallback_original_leaf[0] != '\0') {
                (void)git_freebsd_track_detached_original(
                    lock, fallback_original_leaf, &linked_original, true);
            }
            errno = saved_errno;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot settle the no-replace FreeBSD Git publication");
            return -1;
        }
        lock->published_stat = settled_stage;
    }
    if (fallback_original_leaf[0] != '\0') {
        if (git_freebsd_track_detached_original(
                lock, fallback_original_leaf,
                &linked_original, false) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git retirement fallback lost its exact original rollback witness");
            return -1;
        }
    } else {
        lock->stage_created = false;
    }
#else
    {
        git_noreplace_move_result_t moved;

        if (lock->original_present) {
            errno = ENOTSUP;
            moved = GIT_NOREPLACE_MOVE_UNSUPPORTED;
        } else {
            moved = git_rename_noreplace_at(
                lock->dir_fd, lock->stage_leaf, lock->leaf);
        }
        if (moved != GIT_NOREPLACE_MOVE_OK) {
            if (moved == GIT_NOREPLACE_MOVE_UNSUPPORTED) {
                errno = ENOTSUP;
            }
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot publish prepared Git rollback image without overwriting a raced replacement: %s",
                lock->path);
            return -1;
        }
        lock->stage_created = false;
        if (!git_file_at_matches_witness(
                lock->dir_fd, lock->leaf, lock->published_fd,
                &lock->published_stat, lock->published_data,
                lock->published_length, &lock->published_stat)) {
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Published Git rollback image changed at the no-replace publication boundary");
            return -1;
        }
    }
#endif
    lock->published = true;
    if (retirement_exact && g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_DIRECTORY_SYNC,
                               lock->path, NULL, NULL)) {
        errno = EIO;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git retirement was installed but its directory sync failed: %s",
                         lock->path);
        return -1;
    }
    if (fsync(lock->dir_fd) != 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "%s was installed but its directory sync failed: %s",
                         retirement_exact ? "Git retirement" : "Git rollback",
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
    if (git_scope_lock_acquire(scope, NULL, &lock, generation) != 0) {
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
        if (git_scope_lock_capture_stage_witness(&lock) != 0) {
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Could not retain the edited Git rollback staging generation");
            result.write_failures++;
            goto done;
        }
        for (size_t j = 0; j < before->keys[i].count; j++) {
            if (git_config_file_add(lock.stage_path, g_managed_keys[i],
                                    before->keys[i].values[j]) != 0) {
                result.write_failures++;
                goto done;
            }
            if (git_scope_lock_capture_stage_witness(&lock) != 0) {
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Could not retain the edited Git rollback staging generation");
                result.write_failures++;
                goto done;
            }
        }
    }
    if (git_capture_file_snapshot(
            lock.stage_path, "Could not verify prepared Git rollback lock",
            &observed) != 0) {
        result.write_failures++;
        goto done;
    }
    if (!git_scope_snapshot_equal(&expected, &observed)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Prepared Git rollback does not match its exact target vectors");
        result.write_failures++;
        goto done;
    }
    if (git_scope_lock_publish(&lock, false) != 0) {
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
    {
        error_accumulator_t failures;
        error_context_t primary_error;
        bool primary_failure = result.write_failures != 0U ||
                               result.generation_conflicts != 0U;
        int primary_errno = errno;

        error_accumulator_init(&failures);
        if (primary_failure) {
            primary_error = *get_last_error();
            if (primary_error.code == ERR_SUCCESS) {
                errno = primary_errno ? primary_errno : EIO;
                set_system_error(ERR_GIT_CONFIG_FAILED,
                                 "Git rollback transaction failed");
                primary_error = *get_last_error();
                primary_errno = errno;
            }
            errno = primary_errno;
            (void)error_accumulator_add(
                &failures, "Git rollback transaction", &primary_error);
        }
        git_scope_snapshot_clear(&current);
        git_scope_snapshot_clear(&expected);
        git_scope_snapshot_clear(&observed);
        if (git_scope_lock_discard_checked(&lock, false) != 0) {
            (void)error_accumulator_add_last(
                &failures, "Git rollback artifact cleanup");
            result.write_failures++;
        }
        if (failures.active) (void)error_accumulator_publish(&failures);
    }
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

static int git_snapshot_verify_managed_postimage(
    const git_config_snapshot_t *snapshot,
    bool postimage_was_previously_verified) {
    git_scope_snapshot_t observed_primary;
    git_scope_snapshot_t observed_local;
    git_scope_snapshot_t observed_worktree;
    int differences;

    if (!snapshot) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Missing Git transaction for post-image verification");
        return -1;
    }
    memset(&observed_primary, 0, sizeof(observed_primary));
    memset(&observed_local, 0, sizeof(observed_local));
    memset(&observed_worktree, 0, sizeof(observed_worktree));
    if (git_capture_transaction_scopes(
            &observed_primary, &observed_local,
            &observed_worktree) != 0 ||
        git_snapshot_verify_generations(snapshot, true) != 0) {
        git_scope_snapshot_clear(&observed_primary);
        git_scope_snapshot_clear(&observed_local);
        git_scope_snapshot_clear(&observed_worktree);
        return -1;
    }
    differences = git_scope_snapshot_difference_count(
        &snapshot->post_primary, &observed_primary);
    if (snapshot->local_also) {
        differences += git_scope_snapshot_difference_count(
            &snapshot->post_local, &observed_local);
    }
    if (snapshot->worktree_also) {
        differences += git_scope_snapshot_difference_count(
            &snapshot->post_worktree, &observed_worktree);
    }
    git_scope_snapshot_clear(&observed_primary);
    git_scope_snapshot_clear(&observed_local);
    git_scope_snapshot_clear(&observed_worktree);
    if (differences != 0) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot finalize Git transaction: %d managed vector(s) changed "
            "outside this transaction %s post-image verification",
            differences,
            postimage_was_previously_verified ? "after" : "before");
        return -1;
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

static bool git_finalization_has_destination(
    const git_config_finalization_t *finalization,
    const git_scope_generation_t *generation) {
    if (!finalization || !generation) return false;
    for (size_t i = 0; i < finalization->count; i++) {
        const git_config_finalization_lock_t *lock =
            &finalization->locks[i];
        if (git_same_object_identity(
                &lock->parent_stat, &generation->parent_stat) &&
            strcmp(lock->config_leaf, generation->leaf) == 0) {
            return true;
        }
    }
    return false;
}

typedef enum {
    GIT_FINALIZATION_PUBLISH_ERROR = -1,
    GIT_FINALIZATION_PUBLISH_MOVED = 0,
    GIT_FINALIZATION_PUBLISH_LINKED = 1
} git_finalization_publish_result_t;

typedef enum {
    GIT_FINALIZATION_RELEASE_RETRY = -1,
    GIT_FINALIZATION_RELEASE_OK = 0,
    GIT_FINALIZATION_RELEASE_FOREIGN = 1
} git_finalization_release_result_t;

static void git_finalization_lock_dispose_mode(
    git_config_finalization_lock_t *lock, bool inherited) {
    if (!lock) return;
    if (!inherited && lock->lock_fd >= 0) {
        (void)close(lock->lock_fd);
    }
    if (!inherited && lock->parent_fd >= 0) {
        (void)close(lock->parent_fd);
    }
    if (lock->marker_data) {
        secure_zero_memory(lock->marker_data, lock->marker_length);
        free(lock->marker_data);
    }
    secure_zero_memory(lock, sizeof(*lock));
    lock->parent_fd = -1;
    lock->lock_fd = -1;
}

static void git_finalization_lock_dispose(
    git_config_finalization_lock_t *lock) {
    git_finalization_lock_dispose_mode(lock, false);
}

static git_finalization_publish_result_t
git_finalization_publish_noreplace(
    int directory_fd, const char *source, const char *destination) {
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U)
#endif
    if (syscall(SYS_renameat2, directory_fd, source, directory_fd,
                destination, RENAME_NOREPLACE) == 0) {
        return GIT_FINALIZATION_PUBLISH_MOVED;
    }
    if (errno != ENOSYS && errno != EINVAL && errno != ENOTSUP &&
        errno != EOPNOTSUPP) {
        return GIT_FINALIZATION_PUBLISH_ERROR;
    }
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    if (renameatx_np(directory_fd, source, directory_fd, destination,
                     RENAME_EXCL) == 0) {
        return GIT_FINALIZATION_PUBLISH_MOVED;
    }
    if (errno != EINVAL && errno != ENOTSUP &&
        errno != EOPNOTSUPP) {
        return GIT_FINALIZATION_PUBLISH_ERROR;
    }
#endif
    /* linkat() is itself atomic and no-replace. The complete marker is
     * recoverable during the short two-link interval; recovery accepts only
     * the exact generated private alias plus the canonical name. */
    if (linkat(directory_fd, source, directory_fd, destination, 0) != 0) {
        return GIT_FINALIZATION_PUBLISH_ERROR;
    }
    return GIT_FINALIZATION_PUBLISH_LINKED;
}

static int git_finalization_refresh_canonical(
    git_config_finalization_lock_t *lock, nlink_t expected_links) {
    struct stat current;

    if (!lock || lock->parent_fd < 0 || lock->lock_fd < 0 ||
        !lock->marker_data || lock->marker_length == 0U ||
        fstat(lock->lock_fd, &current) != 0 ||
        !S_ISREG(current.st_mode) ||
        current.st_nlink != expected_links ||
        current.st_uid != geteuid() ||
        (current.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->parent_fd, lock->lock_leaf, lock->lock_fd,
            &current, lock->marker_data, lock->marker_length, NULL)) {
        errno = errno ? errno : EAGAIN;
        return -1;
    }
    lock->lock_stat = current;
    return 0;
}

static int git_finalization_remove_private_alias(
    git_config_finalization_lock_t *lock) {
    git_scope_lock_t cleanup_lock;
    git_cleanup_result_t cleanup;
    struct stat current;

    if (!lock || !lock->private_created) return 0;
    if (lock->parent_fd < 0 || lock->lock_fd < 0 ||
        !lock->marker_data || lock->marker_length == 0U) {
        errno = EINVAL;
        return -1;
    }
    memset(&cleanup_lock, 0, sizeof(cleanup_lock));
    cleanup_lock.dir_fd = lock->parent_fd;
    if (safe_strncpy(cleanup_lock.lock_leaf, lock->lock_leaf,
                     sizeof(cleanup_lock.lock_leaf)) != 0) {
        return -1;
    }
    cleanup = git_scope_lock_cleanup_name_once(
        &cleanup_lock, lock->private_leaf,
        "finalization private recovery marker", lock->lock_fd,
        &lock->lock_stat, lock->marker_data, lock->marker_length,
        true, false);
    if (cleanup == GIT_CLEANUP_RETRY) {
        errno = errno ? errno : EAGAIN;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot retire the private Git finalization certificate");
        return -1;
    }
    if (lock->canonical_published) {
        if (fstat(lock->lock_fd, &current) != 0 ||
            !S_ISREG(current.st_mode) || current.st_nlink != 1 ||
            current.st_uid != geteuid() ||
            (current.st_mode & 07777) != 0600 ||
            !git_file_at_matches_witness(
                lock->parent_fd, lock->lock_leaf, lock->lock_fd,
                &current, lock->marker_data, lock->marker_length, NULL)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot re-prove the canonical Git finalization certificate");
            return -1;
        }
        lock->lock_stat = current;
    }
    /* Keep the retry bit set until directory durability is proven. If the
     * unlink already happened, the checked cleanup above simply observes
     * ENOENT on retry and synchronizes the same transition again. */
    if (fsync(lock->parent_fd) != 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot synchronize private Git finalization-certificate removal");
        return -1;
    }
    lock->private_created = false;
    lock->private_leaf[0] = '\0';
    return 0;
}

static int git_finalization_prepare_private_marker(
    git_config_finalization_lock_t *lock) {
    static unsigned long marker_nonce;
    static const unsigned char newline = '\n';
    git_recovery_marker_t parsed;
    struct stat empty_stage;
    struct stat named;
    char header[GIT_RECOVERY_HEADER_MAX];
    int header_length;

    if (!lock || lock->parent_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    memset(&empty_stage, 0, sizeof(empty_stage));
    memset(&parsed, 0, sizeof(parsed));
    header_length = git_recovery_format_header(
        header, sizeof(header), "-", &empty_stage, 0U);
    if (header_length < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot format the Git finalization recovery certificate");
        return -1;
    }
    for (unsigned attempt = 0U; attempt < 100U; attempt++) {
        unsigned long nonce = ++marker_nonce;

        if ((size_t)snprintf(
                lock->private_leaf, sizeof(lock->private_leaf),
                ".gitswitch-finalization-%ld-%lu", (long)getpid(),
                nonce) >= sizeof(lock->private_leaf)) {
            errno = ENAMETOOLONG;
            break;
        }
        lock->lock_fd = openat(
            lock->parent_fd, lock->private_leaf,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (lock->lock_fd >= 0) {
            lock->private_created = true;
            break;
        }
        if (errno != EEXIST) break;
    }
    if (lock->lock_fd < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot create a private Git finalization certificate");
        return -1;
    }
    if (git_scope_lock_claim_fd(lock->lock_fd) != 0 ||
        fchmod(lock->lock_fd, 0600) != 0 ||
        git_write_all(lock->lock_fd, (const unsigned char *)header,
                      (size_t)header_length) != 0 ||
        git_write_all(lock->lock_fd, &newline, 1U) != 0 ||
        fsync(lock->lock_fd) != 0 ||
        git_capture_fd_bytes_exact_bounded(
            lock->lock_fd, &lock->marker_data, &lock->marker_length,
            &lock->lock_stat, GIT_RECOVERY_MARKER_MAX_BYTES) != 0 ||
        lock->marker_length != (size_t)header_length + 1U ||
        !S_ISREG(lock->lock_stat.st_mode) ||
        lock->lock_stat.st_nlink != 1 ||
        lock->lock_stat.st_uid != geteuid() ||
        (lock->lock_stat.st_mode & 07777) != 0600 ||
        !git_file_at_matches_witness(
            lock->parent_fd, lock->private_leaf, lock->lock_fd,
            &lock->lock_stat, lock->marker_data, lock->marker_length,
            &named) ||
        !git_fd_matches_recovery_marker(
            lock->lock_fd, header, (size_t)header_length, NULL, 0U) ||
        !git_recovery_marker_parse(
            lock->marker_data, lock->marker_length, &parsed) ||
        parsed.stage_present) {
        errno = errno ? errno : EAGAIN;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot validate the private Git finalization certificate");
        return -1;
    }
    lock->lock_stat = named;
    return 0;
}

static int git_finalization_recover_existing_marker(
    const git_config_finalization_lock_t *lock) {
    git_scope_lock_t recovery;

    if (!lock || lock->parent_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    git_scope_lock_init(&recovery);
    recovery.dir_fd = git_dup_cloexec(lock->parent_fd);
    if (recovery.dir_fd < 0 ||
        safe_strncpy(recovery.lock_leaf, lock->lock_leaf,
                     sizeof(recovery.lock_leaf)) != 0) {
        if (recovery.dir_fd >= 0) (void)close(recovery.dir_fd);
        return -1;
    }
    if (git_scope_lock_recover_marker(&recovery) != 0) {
        int saved_errno = errno;
        git_scope_lock_close(&recovery);
        errno = saved_errno;
        return -1;
    }
    git_scope_lock_close(&recovery);
    return 0;
}

static int git_finalization_cleanup_unpublished_private(
    git_config_finalization_lock_t *lock) {
    git_scope_lock_t cleanup_lock;
    git_cleanup_result_t cleanup;

    if (!lock || !lock->private_created || lock->parent_fd < 0 ||
        lock->lock_fd < 0 || !lock->marker_data ||
        lock->marker_length == 0U) {
        return 0;
    }
    memset(&cleanup_lock, 0, sizeof(cleanup_lock));
    cleanup_lock.dir_fd = lock->parent_fd;
    if (safe_strncpy(cleanup_lock.lock_leaf, lock->lock_leaf,
                     sizeof(cleanup_lock.lock_leaf)) != 0) {
        return -1;
    }
    cleanup = git_scope_lock_cleanup_name_once(
        &cleanup_lock, lock->private_leaf,
        "unpublished private finalization certificate", lock->lock_fd,
        &lock->lock_stat, lock->marker_data, lock->marker_length,
        true, false);
    if (cleanup != GIT_CLEANUP_SETTLED) {
        errno = errno ? errno : EAGAIN;
        return -1;
    }
    if (fsync(lock->parent_fd) != 0) return -1;
    lock->private_created = false;
    lock->private_leaf[0] = '\0';
    return 0;
}

/* Finalization-private names are distinct from the older rollback marker
 * staging namespace. That lets a later process remove only a fully formed,
 * unclaimed, no-stage finalization certificate left before canonical
 * publication. Partial files, live claimed files, stage-bearing rollback
 * markers, and foreign replacements remain untouched. */
static int git_finalization_reconcile_private_orphans(
    int directory_fd, const char *lock_leaf) {
    git_scope_lock_t cleanup_lock;
    git_recovery_marker_t parsed;
    git_cleanup_result_t cleanup;
    struct dirent *entry;
    DIR *directory = NULL;
    int scan_fd = -1;
    int marker_fd = -1;
    int saved_errno = 0;
    size_t candidate_count = 0U;

    if (directory_fd < 0 || !lock_leaf) {
        errno = EINVAL;
        return -1;
    }
    /* Admission is deliberately a separate read-only pass. Conservatively
     * budget one fixed cleanup slot for every syntactically private name,
     * including malformed/foreign entries that the proving pass will leave
     * untouched. Therefore no orphan reconciliation can partially mutate the
     * directory and only then discover that the finite arena is exhausted. */
    scan_fd = openat(
        directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        saved_errno = errno ? errno : EIO;
        if (scan_fd >= 0) (void)close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!git_finalization_private_leaf_valid(entry->d_name)) continue;
        if (candidate_count == SIZE_MAX) {
            saved_errno = EOVERFLOW;
            break;
        }
        candidate_count++;
    }
    if (saved_errno == 0 && errno != 0) saved_errno = errno;
    (void)closedir(directory);
    directory = NULL;
    if (saved_errno != 0 ||
        candidate_count >
            SIZE_MAX - GIT_CLEANUP_ARENA_HANDLE_BUDGET) {
        errno = saved_errno != 0 ? saved_errno : EOVERFLOW;
        return -1;
    }
    if (git_cleanup_arena_require_budget(
            directory_fd, lock_leaf,
            candidate_count + GIT_CLEANUP_ARENA_HANDLE_BUDGET) != 0) {
        return -1;
    }
    scan_fd = openat(
        directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        saved_errno = errno ? errno : EIO;
        if (scan_fd >= 0) (void)close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    scan_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        unsigned char *marker_data = NULL;
        size_t marker_length = 0U;
        struct stat marker_stat;

        if (!git_finalization_private_leaf_valid(entry->d_name)) {
            continue;
        }
        marker_fd = openat(
            directory_fd, entry->d_name,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (marker_fd < 0 || git_scope_lock_claim_fd(marker_fd) != 0) {
            if (marker_fd >= 0) (void)close(marker_fd);
            marker_fd = -1;
            errno = 0;
            continue;
        }
        memset(&parsed, 0, sizeof(parsed));
        if (git_capture_fd_bytes_exact_bounded(
                marker_fd, &marker_data, &marker_length, &marker_stat,
                GIT_RECOVERY_MARKER_MAX_BYTES) != 0 ||
            !S_ISREG(marker_stat.st_mode) ||
            marker_stat.st_nlink != 1 ||
            marker_stat.st_uid != geteuid() ||
            (marker_stat.st_mode & 07777) != 0600 ||
            !git_file_at_matches_witness(
                directory_fd, entry->d_name, marker_fd, &marker_stat,
                marker_data, marker_length, NULL) ||
            !git_recovery_marker_parse(
                marker_data, marker_length, &parsed) ||
            parsed.stage_present) {
            if (marker_data) {
                secure_zero_memory(marker_data, marker_length);
                free(marker_data);
            }
            (void)close(marker_fd);
            marker_fd = -1;
            errno = 0;
            continue;
        }
        memset(&cleanup_lock, 0, sizeof(cleanup_lock));
        cleanup_lock.dir_fd = directory_fd;
        if (safe_strncpy(cleanup_lock.lock_leaf, lock_leaf,
                         sizeof(cleanup_lock.lock_leaf)) != 0) {
            saved_errno = errno ? errno : ENAMETOOLONG;
            secure_zero_memory(marker_data, marker_length);
            free(marker_data);
            (void)close(marker_fd);
            marker_fd = -1;
            goto done;
        }
        cleanup = git_scope_lock_cleanup_name_once(
            &cleanup_lock, entry->d_name,
            "orphaned private finalization certificate", marker_fd,
            &marker_stat, marker_data, marker_length, true, false);
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
        (void)close(marker_fd);
        marker_fd = -1;
        if (cleanup == GIT_CLEANUP_RETRY) {
            saved_errno = errno ? errno : EAGAIN;
            goto done;
        }
        if (cleanup == GIT_CLEANUP_SETTLED &&
            fsync(directory_fd) != 0) {
            saved_errno = errno ? errno : EIO;
            goto done;
        }
        errno = 0;
    }
    if (errno != 0) saved_errno = errno;

done:
    if (marker_fd >= 0) (void)close(marker_fd);
    if (directory) (void)closedir(directory);
    if (saved_errno != 0) {
        errno = saved_errno;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot reconcile private Git finalization certificates");
        return -1;
    }
    return 0;
}

static int git_finalization_lock_acquire(
    git_config_finalization_t *finalization,
    const git_scope_generation_t *generation) {
    git_config_finalization_lock_t *lock;
    git_finalization_publish_result_t publication;
    struct stat pinned_parent;

    if (!finalization || !generation || !generation->valid ||
        finalization->count >=
            sizeof(finalization->locks) /
                sizeof(finalization->locks[0])) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git finalization-lock request");
        return -1;
    }
    if (git_finalization_has_destination(finalization, generation)) {
        return 0;
    }
    lock = &finalization->locks[finalization->count];
    memset(lock, 0, sizeof(*lock));
    lock->parent_fd = -1;
    lock->lock_fd = -1;
    if (safe_strncpy(
            lock->config_leaf, generation->leaf,
            sizeof(lock->config_leaf)) != 0 ||
        (size_t)snprintf(
            lock->lock_leaf, sizeof(lock->lock_leaf), "%s.lock",
            generation->leaf) >= sizeof(lock->lock_leaf)) {
        errno = ENAMETOOLONG;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git finalization lock name is too long");
        return -1;
    }
    lock->parent_fd = git_dup_cloexec(generation->parent_fd);
    if (lock->parent_fd < 0 ||
        fstat(lock->parent_fd, &pinned_parent) != 0 ||
        !git_same_object_identity(
            &generation->parent_stat, &pinned_parent)) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot pin the Git finalization-lock directory");
        git_finalization_lock_dispose(lock);
        return -1;
    }
    lock->parent_stat = pinned_parent;
    if (git_cleanup_arena_require_budget(
            lock->parent_fd, lock->lock_leaf,
            GIT_CLEANUP_ARENA_HANDLE_BUDGET) != 0) {
        int arena_errno = errno;

        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            arena_errno == ENOSPC
                ? "Git cleanup arena is exhausted before finalization mutation"
                : "Git finalization lock has pending private cleanup residue");
        errno = arena_errno;
        git_finalization_lock_dispose(lock);
        return -1;
    }
    if (git_finalization_reconcile_private_orphans(
            lock->parent_fd, lock->lock_leaf) != 0 ||
        git_finalization_prepare_private_marker(lock) != 0) {
        error_context_t primary_error = *get_last_error();
        int primary_errno = errno ? errno : EIO;

        (void)git_finalization_cleanup_unpublished_private(lock);
        git_finalization_lock_dispose(lock);
        g_last_error = primary_error;
        errno = primary_errno;
        return -1;
    }
    if (g_finalization_test_hook &&
        g_finalization_test_hook(
            GIT_FINALIZATION_TEST_AFTER_PRIVATE_PREPARE,
            lock->parent_fd, lock->lock_leaf)) {
        error_context_t primary_error;
        int primary_errno;

        errno = EIO;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected private Git finalization-certificate interruption");
        primary_error = *get_last_error();
        primary_errno = errno;
        (void)git_finalization_cleanup_unpublished_private(lock);
        git_finalization_lock_dispose(lock);
        g_last_error = primary_error;
        errno = primary_errno;
        return -1;
    }
    lock->active = true;
    finalization->count++;

    publication = git_finalization_publish_noreplace(
        lock->parent_fd, lock->private_leaf, lock->lock_leaf);
    if (publication == GIT_FINALIZATION_PUBLISH_ERROR &&
        errno == EEXIST &&
        git_finalization_recover_existing_marker(lock) == 0) {
        publication = git_finalization_publish_noreplace(
            lock->parent_fd, lock->private_leaf, lock->lock_leaf);
    }
    if (publication == GIT_FINALIZATION_PUBLISH_ERROR) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot publish the Git finalization recovery certificate");
        return -1;
    }
    lock->canonical_published = true;
    if (publication == GIT_FINALIZATION_PUBLISH_MOVED) {
        lock->private_created = false;
        lock->private_leaf[0] = '\0';
        if (git_finalization_refresh_canonical(lock, 1) != 0) {
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot prove the canonical Git finalization certificate");
            return -1;
        }
    } else if (git_finalization_refresh_canonical(lock, 2) != 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot prove the linked Git finalization certificate");
        return -1;
    }

    if (g_finalization_test_hook &&
        g_finalization_test_hook(
            GIT_FINALIZATION_TEST_AFTER_CANONICAL_PUBLISH,
            lock->parent_fd, lock->lock_leaf)) {
        errno = EIO;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git finalization publication interruption");
        return -1;
    }
    if (lock->private_created &&
        git_finalization_remove_private_alias(lock) != 0) {
        return -1;
    }
    if (fsync(lock->parent_fd) != 0 ||
        git_finalization_refresh_canonical(lock, 1) != 0) {
        errno = errno ? errno : EIO;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot durably prove the Git finalization certificate");
        return -1;
    }
    return 0;
}

static git_finalization_release_result_t
git_finalization_lock_release(git_config_finalization_lock_t *lock) {
    git_scope_lock_t cleanup_lock;
    git_cleanup_result_t cleanup;

    if (!lock || !lock->active) return GIT_FINALIZATION_RELEASE_OK;
    if (lock->private_created &&
        git_finalization_remove_private_alias(lock) != 0) {
        return GIT_FINALIZATION_RELEASE_RETRY;
    }
    if (!lock->canonical_published) {
        lock->active = false;
        git_finalization_lock_dispose(lock);
        return GIT_FINALIZATION_RELEASE_OK;
    }
    if (!lock->canonical_unlinked) {
        if (g_finalization_test_hook &&
            g_finalization_test_hook(
                GIT_FINALIZATION_TEST_BEFORE_RELEASE,
                lock->parent_fd, lock->lock_leaf)) {
            errno = EIO;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Injected Git finalization-certificate release failure");
            return GIT_FINALIZATION_RELEASE_RETRY;
        }
        memset(&cleanup_lock, 0, sizeof(cleanup_lock));
        cleanup_lock.dir_fd = lock->parent_fd;
        if (safe_strncpy(cleanup_lock.lock_leaf, lock->lock_leaf,
                         sizeof(cleanup_lock.lock_leaf)) != 0) {
            return GIT_FINALIZATION_RELEASE_RETRY;
        }
        cleanup = git_scope_lock_cleanup_name_once(
            &cleanup_lock, lock->lock_leaf,
            "finalization recovery certificate", lock->lock_fd,
            &lock->lock_stat, lock->marker_data, lock->marker_length,
            true, false);
        if (cleanup == GIT_CLEANUP_RETRY) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot remove the Git finalization recovery certificate");
            return GIT_FINALIZATION_RELEASE_RETRY;
        }
        if (cleanup == GIT_CLEANUP_FOREIGN) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git finalization certificate changed before release; "
                "foreign namespace entry was preserved");
            lock->active = false;
            git_finalization_lock_dispose(lock);
            return GIT_FINALIZATION_RELEASE_FOREIGN;
        }
        lock->canonical_unlinked = true;
    }
    if (g_finalization_test_hook &&
        g_finalization_test_hook(
            GIT_FINALIZATION_TEST_BEFORE_RELEASE_DIRECTORY_SYNC,
            lock->parent_fd, lock->lock_leaf)) {
        errno = EIO;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git finalization-certificate sync failure");
        return GIT_FINALIZATION_RELEASE_RETRY;
    }
    if (fsync(lock->parent_fd) != 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot synchronize Git finalization-certificate removal");
        return GIT_FINALIZATION_RELEASE_RETRY;
    }
    lock->active = false;
    git_finalization_lock_dispose(lock);
    return GIT_FINALIZATION_RELEASE_OK;
}

static void git_config_finalization_abandon_mode(
    git_config_finalization_t **finalization, bool inherited) {
    git_config_finalization_t *owned;

    if (!finalization || !*finalization) return;
    owned = *finalization;
    *finalization = NULL;
    git_finalization_registry_remove(owned);
    for (size_t i = 0U; i < owned->count; i++) {
        git_finalization_lock_dispose_mode(
            &owned->locks[i], inherited);
    }
    secure_zero_memory(owned, sizeof(*owned));
    free(owned);
}

static void git_config_finalization_abandon(
    git_config_finalization_t **finalization) {
    git_config_finalization_abandon_mode(finalization, false);
}

size_t git_ops_test_finalization_descriptors(
    const git_config_finalization_t *finalization,
    int *fds, size_t capacity) {
    size_t count = 0U;

    if (!finalization) return 0U;
    for (size_t i = 0U; i < finalization->count; i++) {
        const git_config_finalization_lock_t *lock =
            &finalization->locks[i];
        const int retained[] = {lock->parent_fd, lock->lock_fd};

        for (size_t j = 0U;
             j < sizeof(retained) / sizeof(retained[0]); j++) {
            if (retained[j] < 0) continue;
            if (fds && count < capacity) fds[count] = retained[j];
            count++;
        }
    }
    return count;
}

int git_config_finalization_end(
    git_config_finalization_t **finalization) {
    error_accumulator_t failures;
    git_config_finalization_t *owned;
    int result = 0;

    if (!finalization || !*finalization) return 0;
    owned = *finalization;
    if (owned->creator_pid != getpid()) {
        git_config_finalization_abandon_mode(finalization, true);
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot release a Git finalization capability inherited by a different process");
        return -1;
    }
    error_accumulator_init(&failures);
    for (size_t i = owned->count; i > 0U; i--) {
        git_finalization_release_result_t released =
            git_finalization_lock_release(
                &owned->locks[i - 1U]);

        if (released == GIT_FINALIZATION_RELEASE_RETRY) {
            result = -1;
            (void)error_accumulator_add_last(
                &failures, "Git finalization-lock release");
        } else if (released == GIT_FINALIZATION_RELEASE_FOREIGN) {
            result = -1;
            (void)error_accumulator_add_last(
                &failures, "Git finalization-lock ownership");
        }
    }
    /* Failed pathname cleanup retains a complete canonical certificate; a
     * failed post-unlink sync can at worst replay that same certificate after
     * a crash. Release process-local fcntl claims now so an embedded caller,
     * not only a restarted CLI, can self-heal on its next managed write. */
    git_config_finalization_abandon(finalization);
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
    }
    return result;
}

int git_config_finalization_begin(
    git_config_finalization_t **finalization) {
    const git_scope_generation_t *generations[] = {
        &g_git_snapshot.primary_generation,
        &g_git_snapshot.local_generation,
        &g_git_snapshot.worktree_generation
    };
    git_config_finalization_t *owned = NULL;
    error_context_t primary_error;
    int primary_errno;

    if (!finalization || *finalization) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git finalization output handle");
        return -1;
    }
    if (git_snapshot_require_current_owner("finalize") != 0) {
        return -1;
    }
    if (!g_git_snapshot.valid ||
        !g_git_snapshot.postimage_sealed) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "No sealed Git transaction is available to finalize");
        return -1;
    }
    owned = calloc(1U, sizeof(*owned));
    if (!owned) {
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate Git transaction finalization state");
        return -1;
    }
    if (git_fork_child_cleanup_ensure_registered() != 0) {
        free(owned);
        return -1;
    }
    for (size_t i = 0U;
         i < sizeof(owned->locks) / sizeof(owned->locks[0]); i++) {
        owned->locks[i].parent_fd = -1;
        owned->locks[i].lock_fd = -1;
    }
    owned->creator_pid = getpid();
    git_finalization_registry_add(owned);
    for (size_t i = 0;
         i < sizeof(generations) / sizeof(generations[0]); i++) {
        if (generations[i]->valid &&
            (git_scope_generation_verify_namespace(
                 generations[i]) != 0 ||
             git_finalization_lock_acquire(
                 owned, generations[i]) != 0)) {
            goto begin_failed;
        }
    }
    if (git_snapshot_verify_generations(
            &g_git_snapshot, true) != 0 ||
        git_snapshot_verify_managed_postimage(
            &g_git_snapshot, true) != 0 ||
        git_snapshot_verify_generations(
            &g_git_snapshot, true) != 0) {
        goto begin_failed;
    }
    *finalization = owned;
    return 0;

begin_failed:
    primary_error = *get_last_error();
    primary_errno = errno ? errno : EIO;
    if (git_config_finalization_end(&owned) != 0) {
        error_context_t cleanup_error = *get_last_error();
        int cleanup_errno = errno;
        error_accumulator_t failures;

        /* A canonical residue is a complete self-describing recovery
         * certificate, so process-local descriptor ownership may be released
         * after the cleanup failure is captured. A later managed write will
         * claim and remove only that exact marker. */
        git_config_finalization_abandon(&owned);
        error_accumulator_init(&failures);
        errno = primary_errno;
        (void)error_accumulator_add(
            &failures, "Git finalization admission", &primary_error);
        errno = cleanup_errno;
        (void)error_accumulator_add(
            &failures, "Git finalization cleanup", &cleanup_error);
        (void)error_accumulator_publish(&failures);
    } else {
        g_last_error = primary_error;
        errno = primary_errno;
    }
    return -1;
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
    if (git_snapshot_require_current_owner("modify") != 0) return -1;
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
    if (git_snapshot_require_current_owner("write through") != 0) {
        return -1;
    }
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
    git_config_abandon_inherited_transaction();
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
    if (git_fork_child_cleanup_ensure_registered() != 0) return -1;
    if (git_reject_ssh_command_override() != 0) return -1;
    if (git_reject_managed_command_overrides() != 0) return -1;
    git_snapshot_clear(&g_git_snapshot);

    /* Worktree attribution must be known before any forward mutation. A
     * failed/unsupported scope probe is a hard stop: otherwise a higher
     * precedence identity could survive an apparently successful switch. */
    if ((scope == GIT_SCOPE_GLOBAL || scope == GIT_SCOPE_LOCAL) &&
        git_detect_managed_worktree_scope(&manage_worktree) != 0) {
        return -1;
    }

    next.scope = scope;
    next.creator_pid = getpid();
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
    if (git_snapshot_require_current_owner("seal") != 0) return -1;
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
        git_snapshot_verify_managed_postimage(
            &g_git_snapshot, false) != 0) {
        git_snapshot_clear_post_configs(&g_git_snapshot);
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

static int git_snapshot_export_generation_destination(
    const git_scope_generation_t *generation, git_scope_t scope,
    publication_record_t *out) {
    if (!generation || !generation->valid || !out) {
        errno = EINVAL;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git snapshot has no captured destination generation");
        return -1;
    }
    publication_record_init(out);
    if (git_publication_scope_from_git(scope, &out->scope) != 0 ||
        safe_strncpy(out->config_path, generation->path,
                     sizeof(out->config_path)) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git snapshot destination exceeds durable storage");
        return -1;
    }
    publication_identity_from_stat(&out->config_parent,
                                   &generation->parent_stat);
    if (generation->repository_present) {
        if (safe_strncpy(out->repository_path,
                         generation->repository_path,
                         sizeof(out->repository_path)) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git snapshot repository path exceeds durable storage");
            return -1;
        }
        publication_identity_from_stat(&out->repository,
                                       &generation->repository_stat);
    }
    return 0;
}

/* AR-12 H2: expose only the primary destination identity of the active
 * snapshot so publication-capacity preflight can recognize an in-place
 * replacement before any mutation. */
int git_config_snapshot_export_destination(publication_record_t *out) {
    if (!out) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git snapshot destination export request");
        return -1;
    }
    if (git_snapshot_require_current_owner("export from") != 0) {
        return -1;
    }
    if (!g_git_snapshot.valid) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "No Git snapshot is available to export a destination");
        return -1;
    }
    return git_snapshot_export_generation_destination(
        &g_git_snapshot.primary_generation, g_git_snapshot.scope, out);
}

/* AR-14 H1: recovery owns every namespace the transaction can mutate, not
 * only its primary publication scope. The order is a canonical part of the
 * switch marker so a restart from another repository/topology cannot adopt
 * the marker and silently omit or add a secondary scope. */
int git_config_snapshot_export_destinations(
    publication_record_t *out, size_t capacity, size_t *count) {
    const git_scope_generation_t *generations[3];
    git_scope_t scopes[3];
    size_t required = 0U;

    if (!out || !count) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git snapshot destination-set export request");
        return -1;
    }
    if (git_snapshot_require_current_owner("export from") != 0) {
        return -1;
    }
    *count = 0U;
    if (!g_git_snapshot.valid) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "No Git snapshot is available to export destinations");
        return -1;
    }
    generations[required] = &g_git_snapshot.primary_generation;
    scopes[required++] = g_git_snapshot.scope;
    if (g_git_snapshot.local_also) {
        generations[required] = &g_git_snapshot.local_generation;
        scopes[required++] = GIT_SCOPE_LOCAL;
    }
    if (g_git_snapshot.worktree_also) {
        generations[required] = &g_git_snapshot.worktree_generation;
        scopes[required++] = GIT_SCOPE_WORKTREE_INTERNAL;
    }
    *count = required;
    if (capacity < required) {
        errno = ENOSPC;
        set_error(
            ERR_INVALID_ARGS,
            "Git snapshot destination export needs %zu slots, but only %zu were supplied",
            required, capacity);
        return -1;
    }
    for (size_t i = 0U; i < required; i++) {
        if (git_snapshot_export_generation_destination(
                generations[i], scopes[i], &out[i]) != 0) {
            for (size_t j = 0U; j < required; j++) {
                secure_zero_memory(&out[j], sizeof(out[j]));
            }
            *count = 0U;
            return -1;
        }
    }
    return 0;
}

int git_config_export_sealed_publication(publication_record_t *out,
                                         const char *gpg_selector) {
    publication_record_t record;
    const git_scope_generation_t *generation;
    char gpg_format[sizeof(GIT_GPG_FORMAT_OPENPGP)];
    char signing_state[sizeof("false")];
    char legacy_program[MAX_PATH_LEN];
    bool fingerprint_present = false;
    bool gpg_program_present = false;
    bool ssh_command_present = false;
    bool gpg_format_present = false;
    bool signing_state_present = false;
    bool legacy_program_present = false;

    if (!out) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid sealed Git publication export request");
        return -1;
    }
    if (git_snapshot_require_current_owner("export from") != 0) {
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
            &gpg_format_present) != 0 ||
        git_publication_copy_post_value(
            GIT_CONFIG_COMMIT_GPGSIGN, signing_state,
            sizeof(signing_state), &signing_state_present) != 0) {
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
        (fingerprint_present && !signing_state_present) ||
        (fingerprint_present &&
         !git_signing_key_matches_fingerprint(record.gpg_fingerprint,
                                              record.gpg_fingerprint)) ||
        (signing_state_present &&
         strcmp(signing_state, "true") != 0 &&
         strcmp(signing_state, "false") != 0)) {
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
                               PUBLICATION_CAP_GPG_SELECTOR |
                               PUBLICATION_CAP_GPG_SIGNING_STATE;
        record.gpg_signing_enabled = strcmp(signing_state, "true") == 0;
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

    if (git_snapshot_require_current_owner("restore") != 0) return -1;
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
    if (git_snapshot_is_inherited()) {
        git_config_abandon_inherited_transaction();
        return;
    }
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
    if (git_reject_managed_command_overrides() != 0) return -1;
    
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

/* Command-scope configuration is process-local and outranks every persisted
 * scope. Matching bytes therefore do not prove that the selected account was
 * durably published: a later Git process without the override can observe a
 * different identity. Inspect only the winning managed entries from Git's own
 * parser, so both supported command-override environment encodings and their
 * quoting rules share one authority. */
static int git_effective_reject_managed_command_scope(
    const git_effective_listing_t *listing) {
    if (!listing) {
        set_error(ERR_INVALID_ARGS,
                  "Missing effective Git configuration for command-scope validation");
        return -1;
    }
    for (int i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (listing->keys[i].present &&
            listing->scopes[i] == GIT_CONFIG_ORIGIN_COMMAND) {
            errno = ESTALE;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git command-scope override for managed key %s prevents durable account switching",
                      g_managed_keys[i]);
            return -1;
        }
    }
    return 0;
}

/* Preserve the ordinary no-override path: most switch callers and command
 * runner fixtures must not pay for an additional effective-config read.
 * Presence, including an empty value or GIT_CONFIG_COUNT=0, asks Git to parse
 * the environment. Unrelated command-scope keys remain permitted. */
static int git_reject_managed_command_overrides(void) {
    git_effective_listing_t *effective;

    if (getenv("GIT_CONFIG_COUNT") == NULL &&
        getenv("GIT_CONFIG_PARAMETERS") == NULL) {
        return 0;
    }
    if (git_read_effective_keys(&effective) != 0) return -1;
    return git_effective_reject_managed_command_scope(effective);
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
    if (git_effective_reject_managed_command_scope(effective) != 0) {
        return -1;
    }
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

int git_status_snapshot_read(git_status_snapshot_t **snapshot) {
    git_effective_listing_t *effective;
    git_status_snapshot_t *captured;
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

    if (!snapshot) {
        set_error(ERR_INVALID_ARGS, "NULL Git status snapshot output");
        return -1;
    }
    *snapshot = NULL;

    if (git_reject_ssh_command_override() != 0) return -1;

    if (k_name < 0 || k_email < 0 || k_signkey < 0 || k_gpgsign < 0 ||
        k_gpgformat < 0 || k_gpgprogram < 0 || k_gpgopenpgp < 0 ||
        k_gpgx509 < 0 || k_gpgssh < 0 || k_sshcommand < 0) {
        set_error(ERR_INVALID_ARGS, "Managed git key set is incomplete");
        return -1;
    }
    if (git_read_effective_keys(&effective) != 0) return -1;

    captured = calloc(1, sizeof(*captured));
    if (!captured) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory projecting effective Git status");
        return -1;
    }
    *snapshot = captured;

    copy_effective_value(&captured->user_name, effective, k_name);
    copy_effective_value(&captured->user_email, effective, k_email);
    copy_effective_value(&captured->user_signing_key, effective, k_signkey);
    copy_effective_value(&captured->commit_gpgsign, effective, k_gpgsign);
    copy_effective_value(&captured->gpg_format, effective, k_gpgformat);
    copy_effective_value(&captured->ssh_command, effective, k_sshcommand);
    copy_effective_value(&captured->gpg_program, effective, k_gpgprogram);
    copy_effective_value(&captured->gpg_openpgp_program, effective,
                         k_gpgopenpgp);
    copy_effective_value(&captured->gpg_x509_program, effective, k_gpgx509);
    copy_effective_value(&captured->gpg_ssh_program, effective, k_gpgssh);
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (effective->keys[i].present) {
            captured->any_present = true;
            break;
        }
    }

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
        captured->gpg_format_invalid = true;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective gpg.format is not openpgp");
        return -1;
    }
    if (effective->keys[k_gpgsign].present &&
        git_parse_effective_bool(&effective->keys[k_gpgsign],
                                 GIT_CONFIG_COMMIT_GPGSIGN,
                                 &captured->gpg_signing_enabled) != 0) {
        captured->commit_gpgsign_invalid = true;
        return -1;
    }

    captured->valid = true;
    return 0;
}

void git_status_snapshot_free(git_status_snapshot_t *snapshot) {
    if (!snapshot) return;
    secure_zero_memory(snapshot, sizeof(*snapshot));
    free(snapshot);
}

int git_status_snapshot_to_current(const git_status_snapshot_t *snapshot,
                                   git_current_config_t *current) {
    if (!snapshot || !current || !snapshot->valid) {
        set_error(ERR_INVALID_ARGS, "Invalid effective Git status projection");
        return -1;
    }
    memset(current, 0, sizeof(*current));
    if ((snapshot->user_name.present &&
         safe_strncpy(current->name, snapshot->user_name.value,
                      sizeof(current->name)) != 0) ||
        (snapshot->user_email.present &&
         safe_strncpy(current->email, snapshot->user_email.value,
                      sizeof(current->email)) != 0)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git identity exceeds supported field length");
        return -1;
    }
    if (snapshot->user_signing_key.present &&
        safe_strncpy(current->signing_key,
                     snapshot->user_signing_key.value,
                     sizeof(current->signing_key)) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Effective Git signing key exceeds supported field length");
        return -1;
    }
    current->gpg_signing_enabled = snapshot->gpg_signing_enabled;
    if (!snapshot->user_name.present) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.name configured");
        return -1;
    }
    if (!snapshot->user_email.present) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.email configured");
        return -1;
    }
    current->effective_name_scope = snapshot->user_name.scope;
    snprintf(current->effective_name_origin,
             sizeof(current->effective_name_origin), "%s",
             snapshot->user_name.origin);
    current->effective_signing_key_scope = snapshot->user_signing_key.scope;
    snprintf(current->effective_signing_key_origin,
             sizeof(current->effective_signing_key_origin), "%s",
             snapshot->user_signing_key.origin);
    switch (current->effective_name_scope) {
        case GIT_CONFIG_ORIGIN_GLOBAL: current->scope = GIT_SCOPE_GLOBAL; break;
        case GIT_CONFIG_ORIGIN_SYSTEM: current->scope = GIT_SCOPE_SYSTEM; break;
        case GIT_CONFIG_ORIGIN_LOCAL:
        case GIT_CONFIG_ORIGIN_WORKTREE:
        case GIT_CONFIG_ORIGIN_COMMAND:
        case GIT_CONFIG_ORIGIN_UNKNOWN:
        default: current->scope = GIT_SCOPE_LOCAL; break;
    }
    current->ssh_command = snapshot->ssh_command;
    current->gpg_program = snapshot->gpg_program;
    current->gpg_openpgp_program = snapshot->gpg_openpgp_program;
    current->gpg_x509_program = snapshot->gpg_x509_program;
    current->gpg_ssh_program = snapshot->gpg_ssh_program;
    current->valid = true;
    return 0;
}

int git_get_current_config(git_current_config_t *config) {
    git_status_snapshot_t *snapshot = NULL;
    int result;

    if (!config) {
        set_error(ERR_INVALID_ARGS, "NULL config to git_get_current_config");
        return -1;
    }
    memset(config, 0, sizeof(*config));
    if (git_status_snapshot_read(&snapshot) != 0) {
        git_status_snapshot_free(snapshot);
        return -1;
    }
    result = git_status_snapshot_to_current(snapshot, config);
    git_status_snapshot_free(snapshot);
    return result;
}

/* Clear git configuration */
int git_clear_config(git_scope_t scope) {
    const char *scope_flag;
    char first_error[sizeof(g_last_error.message)] = "";
    int failures = 0;
    
    if (git_snapshot_require_current_owner("clear through") != 0) {
        return -1;
    }
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

static bool git_retirement_directory_identity_matches(
    const publication_identity_t *identity, const struct stat *st) {
    return identity && identity->present && st &&
           identity->device == (uintmax_t)st->st_dev &&
           identity->inode == (uintmax_t)st->st_ino &&
           (identity->mode & (uintmax_t)S_IFMT) ==
               ((uintmax_t)st->st_mode & (uintmax_t)S_IFMT);
}

/* A completed atomic retirement necessarily changes the config generation.
 * For retry/idempotence, retain the durable namespace and repository proof
 * while allowing the caller to inspect whether every exact owned value is
 * already absent. This never authorizes mutation of a stale generation. */
static int git_retirement_verify_live_namespace(
    const publication_record_t *publication) {
    char canonical[MAX_PATH_LEN];
    char parent[MAX_PATH_LEN];
    char repository[MAX_PATH_LEN];
    const char *slash;
    const char *leaf;
    struct stat parent_stat;
    struct stat config_stat;
    struct stat repository_stat;
    int parent_fd = -1;
    int config_fd = -1;
    int repository_fd = -1;
    int result = -1;

    if (!publication || publication_record_validate(publication) != 0) {
        return -1;
    }
    slash = strrchr(publication->config_path, '/');
    if (!slash || !slash[1] ||
        realpath(publication->config_path, canonical) == NULL ||
        strcmp(canonical, publication->config_path) != 0) {
        goto mismatch;
    }
    leaf = slash + 1U;
    if (slash == publication->config_path) {
        if (safe_strncpy(parent, "/", sizeof(parent)) != 0) goto mismatch;
    } else {
        size_t length = (size_t)(slash - publication->config_path);

        if (length >= sizeof(parent)) goto mismatch;
        memcpy(parent, publication->config_path, length);
        parent[length] = '\0';
    }
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0 || fstat(parent_fd, &parent_stat) != 0 ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &parent_stat)) {
        goto mismatch;
    }
    config_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (config_fd < 0 || fstat(config_fd, &config_stat) != 0 ||
        !S_ISREG(config_stat.st_mode)) {
        goto mismatch;
    }
    if (publication->scope != PUBLICATION_SCOPE_GLOBAL) {
        if (realpath(publication->repository_path, repository) == NULL ||
            strcmp(repository, publication->repository_path) != 0) {
            goto mismatch;
        }
        repository_fd = open(publication->repository_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                 O_NOFOLLOW);
        if (repository_fd < 0 ||
            fstat(repository_fd, &repository_stat) != 0 ||
            !git_retirement_directory_identity_matches(
                &publication->repository, &repository_stat)) {
            goto mismatch;
        }
    }
    result = 0;
    goto cleanup;

mismatch:
    errno = ESTALE;
    set_error(ERR_GIT_CONFIG_FAILED,
              "Recorded Git retirement namespace is inaccessible or changed");
cleanup:
    if (repository_fd >= 0) (void)close(repository_fd);
    if (config_fd >= 0) (void)close(config_fd);
    if (parent_fd >= 0) (void)close(parent_fd);
    return result;
}

static int git_retire_validate_publication_state(
    const account_t *account, const publication_record_t *publication,
    publication_state_t expected_state, git_scope_t *scope) {
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
        publication->state != expected_state ||
        git_scope_from_publication(publication->scope, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Account has no exact durable Git publication provenance");
        return -1;
    }
    /* AR-12 L9: no fingerprint re-check here — publication_record_validate()
     * above already enforces the canonical 40/64-hex grammar for any record
     * carrying PUBLICATION_CAP_GPG_FINGERPRINT, and record-driven retirement
     * deliberately does not re-bind the record to the account's current
     * gpg_key_id (the incarnation match above is the ownership proof). */
    return 0;
}

typedef struct {
    size_t representative;
    git_scope_t scope;
    const publication_record_t *live_generation;
    git_scope_snapshot_t snapshot;
    struct stat prelock_stat;
    unsigned char *prelock_data;
    size_t prelock_length;
    bool snapshot_ready;
    bool prelock_witness_ready;
    bool stale_generation;
    bool attribution_conflict;
    const char *remove_value[GIT_MANAGED_KEY_COUNT];
    git_scope_lock_t lock;
    size_t planned;
    bool lock_ready;
    bool prepared;
    bool published;
    bool restored;
    bool restored_witness_ready;
    bool settled;
    bool absent_destination;
    bool terminal_witness_enumerated;
    bool absent_witness_ready;
    bool recovery_stage_settled;
    bool terminal_clean_witness_ready;
    bool terminal_clean_uses_published;
    bool terminal_release_only;
} git_retirement_group_t;

typedef struct {
    account_t account;
    publication_record_t publication;
    struct stat prelock_stat;
    unsigned char *prelock_data;
    size_t prelock_length;
    bool ready;
    bool namespace_ready;
    bool absence_candidate;
    bool prelock_witness_ready;
} git_retirement_item_t;

typedef enum {
    GIT_RETIREMENT_TRANSACTION_PREPARED = 0,
    GIT_RETIREMENT_TRANSACTION_PUBLISHED,
    GIT_RETIREMENT_TRANSACTION_ABORTED,
    GIT_RETIREMENT_TRANSACTION_PUBLISH_FAILED
} git_retirement_transaction_state_t;

typedef enum {
    GIT_RETIREMENT_ENUMERATION_NONE = 0,
    GIT_RETIREMENT_ENUMERATION_LEGACY,
    GIT_RETIREMENT_ENUMERATION_TERMINAL
} git_retirement_enumeration_mode_t;

typedef enum {
    GIT_RETIREMENT_TERMINAL_NONE = 0,
    GIT_RETIREMENT_TERMINAL_ROLLBACK,
    GIT_RETIREMENT_TERMINAL_COMMIT,
    GIT_RETIREMENT_TERMINAL_RECOVERY
} git_retirement_terminal_kind_t;

struct git_retirement_transaction {
    git_retirement_item_t *items;
    const publication_record_t **publication_refs;
    git_retirement_group_t *groups;
    size_t item_count;
    size_t group_count;
    size_t failure_count;
    size_t published_cleared;
    pid_t creator_pid;
    error_accumulator_t failures;
    git_retirement_transaction_state_t state;
    git_retirement_enumeration_mode_t enumeration_mode;
    git_retirement_terminal_kind_t terminal_kind;
    bool snapshot_indeterminate;
    bool command_runner;
    bool recovery_proof_only;
    bool terminal_release_only;
    bool terminal_settlement_failed;
    struct git_retirement_transaction *fork_registry_prev;
    struct git_retirement_transaction *fork_registry_next;
    bool fork_registry_registered;
};

struct git_retirement_recovery {
    git_retirement_transaction_t *transaction;
};

static git_retirement_transaction_t *g_git_retirement_registry;

static void git_retirement_registry_add(
    git_retirement_transaction_t *transaction) {
    if (!transaction || transaction->fork_registry_registered) return;
    transaction->fork_registry_prev = NULL;
    transaction->fork_registry_next = g_git_retirement_registry;
    if (g_git_retirement_registry) {
        g_git_retirement_registry->fork_registry_prev = transaction;
    }
    g_git_retirement_registry = transaction;
    transaction->fork_registry_registered = true;
}

static void git_retirement_registry_remove(
    git_retirement_transaction_t *transaction) {
    if (!transaction || !transaction->fork_registry_registered) return;
    if (transaction->fork_registry_prev) {
        transaction->fork_registry_prev->fork_registry_next =
            transaction->fork_registry_next;
    } else {
        g_git_retirement_registry = transaction->fork_registry_next;
    }
    if (transaction->fork_registry_next) {
        transaction->fork_registry_next->fork_registry_prev =
            transaction->fork_registry_prev;
    }
    transaction->fork_registry_prev = NULL;
    transaction->fork_registry_next = NULL;
    transaction->fork_registry_registered = false;
}

static bool git_fork_fd_matches_stat(int fd, const struct stat *expected) {
    struct stat observed;

    return fd >= 0 && expected && fstat(fd, &observed) == 0 &&
           observed.st_dev == expected->st_dev &&
           observed.st_ino == expected->st_ino;
}

static void git_fork_close_fd_if_matches(
    int *fd, const struct stat *expected) {
    int retained;

    if (!fd) return;
    retained = *fd;
    if (git_fork_fd_matches_stat(retained, expected)) {
        (void)close(retained);
    }
    *fd = -1;
}

static void git_fork_cleanup_generation(
    git_scope_generation_t *generation) {
    if (!generation) return;
    if (generation->valid) {
        git_fork_close_fd_if_matches(
            &generation->parent_fd, &generation->parent_stat);
    } else {
        generation->parent_fd = -1;
    }
    if (generation->repository_present) {
        git_fork_close_fd_if_matches(
            &generation->repository_fd, &generation->repository_stat);
    } else {
        generation->repository_fd = -1;
    }
    if (generation->post_config_identity_valid &&
        generation->post_config_present) {
        git_fork_close_fd_if_matches(
            &generation->post_config_fd, &generation->post_config_stat);
    } else {
        generation->post_config_fd = -1;
    }
}

static void git_fork_cleanup_scope_lock(git_scope_lock_t *lock) {
    if (!lock) return;
    git_fork_close_fd_if_matches(&lock->dir_fd, &lock->parent_stat);
    git_fork_close_fd_if_matches(&lock->lock_fd, &lock->lock_stat);
    git_fork_close_fd_if_matches(&lock->stage_fd, &lock->stage_stat);
    git_fork_close_fd_if_matches(&lock->original_fd, &lock->original_stat);
    git_fork_close_fd_if_matches(&lock->published_fd, &lock->published_stat);
    git_fork_close_fd_if_matches(
        &lock->recovery_authority_fd, &lock->recovery_authority_stat);
}

static void git_fork_child_cleanup(void) {
    git_config_finalization_t *finalization;
    git_retirement_transaction_t *transaction;

    git_fork_cleanup_generation(&g_git_snapshot.primary_generation);
    git_fork_cleanup_generation(&g_git_snapshot.local_generation);
    git_fork_cleanup_generation(&g_git_snapshot.worktree_generation);

    finalization = g_git_finalization_registry;
    while (finalization) {
        git_config_finalization_t *next =
            finalization->fork_registry_next;

        for (size_t i = 0U;
             i < sizeof(finalization->locks) /
                     sizeof(finalization->locks[0]);
             i++) {
            git_config_finalization_lock_t *lock =
                &finalization->locks[i];

            git_fork_close_fd_if_matches(
                &lock->parent_fd, &lock->parent_stat);
            git_fork_close_fd_if_matches(
                &lock->lock_fd, &lock->lock_stat);
        }
        finalization->fork_registry_prev = NULL;
        finalization->fork_registry_next = NULL;
        finalization->fork_registry_registered = false;
        finalization = next;
    }
    g_git_finalization_registry = NULL;

    transaction = g_git_retirement_registry;
    while (transaction) {
        git_retirement_transaction_t *next =
            transaction->fork_registry_next;

        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_fork_cleanup_scope_lock(&transaction->groups[i].lock);
        }
        transaction->fork_registry_prev = NULL;
        transaction->fork_registry_next = NULL;
        transaction->fork_registry_registered = false;
        transaction = next;
    }
    g_git_retirement_registry = NULL;
}

/* Capture the complete source generation before canonical-lock recovery can
 * fsync a retained FreeBSD lease. UFS may materialize that lease operation's
 * delayed ctime on the unchanged config inode. The raw witness lets locked
 * preparation distinguish that metadata-only completion from a replacement,
 * without weakening the persisted publication identity check. */
static int git_retirement_capture_prelock_witness(
    const publication_record_t *publication,
    const publication_identity_t *expected,
    struct stat *witness_stat, unsigned char **witness_data,
    size_t *witness_length, size_t max_length) {
    publication_identity_t captured_identity;
    char parent[MAX_PATH_LEN];
    const char *slash;
    const char *leaf;
    struct stat parent_before;
    struct stat parent_after;
    struct stat named_before;
    struct stat opened;
    struct stat captured;
    struct stat named_after;
    unsigned char *data = NULL;
    size_t length = 0U;
    int parent_fd = -1;
    int fd = -1;
    int saved_errno;

    if (!publication || !expected || !witness_stat || !witness_data ||
        !witness_length || *witness_data) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git retirement pre-lock witness request");
        return -1;
    }
    slash = strrchr(publication->config_path, '/');
    if (!slash || !slash[1] || strlen(slash + 1U) > NAME_MAX) {
        saved_errno = EINVAL;
        goto failed;
    }
    leaf = slash + 1U;
    if (slash == publication->config_path) {
        if (safe_strncpy(parent, "/", sizeof(parent)) != 0) {
            saved_errno = ENAMETOOLONG;
            goto failed;
        }
    } else {
        size_t parent_length =
            (size_t)(slash - publication->config_path);

        if (parent_length >= sizeof(parent)) {
            saved_errno = ENAMETOOLONG;
            goto failed;
        }
        memcpy(parent, publication->config_path, parent_length);
        parent[parent_length] = '\0';
    }
    parent_fd = open(
        parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0 ||
        fstat(parent_fd, &parent_before) != 0 ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &parent_before) ||
        fstatat(parent_fd, leaf, &named_before,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named_before.st_mode)) {
        saved_errno = errno ? errno : ESTALE;
        goto failed;
    }
    fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !git_same_file_observation(&named_before, &opened) ||
        git_capture_fd_bytes_exact_bounded(
            fd, &data, &length, &captured, max_length) != 0 ||
        !git_same_file_observation(&opened, &captured) ||
        fstatat(parent_fd, leaf, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !git_same_file_observation(&captured, &named_after) ||
        fstat(parent_fd, &parent_after) != 0 ||
        !git_same_object_identity(&parent_before, &parent_after) ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &parent_after)) {
        saved_errno = errno ? errno : ESTALE;
        goto failed;
    }
    publication_identity_from_stat(&captured_identity, &captured);
    if (!publication_identity_equal(&captured_identity, expected)) {
        saved_errno = ESTALE;
        goto failed;
    }
    (void)close(fd);
    (void)close(parent_fd);
    *witness_stat = captured;
    *witness_data = data;
    *witness_length = length;
    return 0;

failed:
    if (fd >= 0) (void)close(fd);
    if (parent_fd >= 0) (void)close(parent_fd);
    if (data) {
        secure_zero_memory(data, length);
        free(data);
    }
    errno = saved_errno;
    set_system_error(
        ERR_GIT_CONFIG_FAILED,
        saved_errno == EFBIG
            ? "Git retirement pre-lock witness exceeds the bounded transaction budget"
            : "Git retirement source changed while capturing its pre-lock witness");
    errno = saved_errno;
    return -1;
}

static size_t git_ops_test_scope_lock_descriptors(
    const git_scope_lock_t *lock, int *fds, size_t capacity) {
    const int retained[] = {
        lock ? lock->dir_fd : -1,
        lock ? lock->lock_fd : -1,
        lock ? lock->stage_fd : -1,
        lock ? lock->original_fd : -1,
        lock ? lock->published_fd : -1,
        lock ? lock->recovery_authority_fd : -1
    };
    size_t count = 0U;

    for (size_t i = 0U;
         i < sizeof(retained) / sizeof(retained[0]); i++) {
        if (retained[i] < 0) continue;
        if (fds && count < capacity) fds[count] = retained[i];
        count++;
    }
    return count;
}

size_t git_ops_test_retirement_transaction_descriptors(
    const git_retirement_transaction_t *transaction,
    int *fds, size_t capacity) {
    size_t count = 0U;

    if (!transaction) return 0U;
    for (size_t i = 0U; i < transaction->group_count; i++) {
        size_t group_count =
            git_ops_test_scope_lock_descriptors(
                &transaction->groups[i].lock,
                fds && count < capacity ? fds + count : NULL,
                count < capacity ? capacity - count : 0U);

        count += group_count;
    }
    return count;
}

size_t git_ops_test_retirement_recovery_descriptors(
    const git_retirement_recovery_t *recovery,
    int *fds, size_t capacity) {
    return recovery
               ? git_ops_test_retirement_transaction_descriptors(
                     recovery->transaction, fds, capacity)
               : 0U;
}

static int git_retirement_recovery_reprove_transaction(
    git_retirement_transaction_t *transaction);

static int git_retirement_transaction_require_creator(
    const git_retirement_transaction_t *transaction,
    const char *operation) {
    if (!transaction || transaction->creator_pid != getpid()) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot %s a Git retirement capability inherited by a different process",
            operation ? operation : "use");
        return -1;
    }
    return 0;
}

/* AR-14 H3/H4: absence is transaction state, not a scalar path observation.
 * Resolve only the immutable recorded path, pin its exact recorded parent,
 * and occupy Git's canonical lock name before ENOENT can authorize progress.
 * This intentionally does not broaden git_scope_lock_acquire(): ordinary
 * rollback/write locking still requires a live canonical source generation. */
static int git_retirement_resolve_absent_destination(
    const publication_record_t *publication, git_scope_lock_t *lock) {
    const char *slash;

    if (!publication || !lock || publication->config_path[0] != '/') {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid absent Git retirement destination");
        return -1;
    }
    git_scope_lock_init(lock);
    if (safe_strncpy(lock->logical_path, publication->config_path,
                     sizeof(lock->logical_path)) != 0 ||
        safe_strncpy(lock->path, publication->config_path,
                     sizeof(lock->path)) != 0) {
        return -1;
    }
    slash = strrchr(publication->config_path, '/');
    if (!slash || !slash[1] || strlen(slash + 1U) > NAME_MAX) {
        errno = EINVAL;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Invalid recorded Git configuration path: %s",
                  publication->config_path);
        return -1;
    }
    if (slash == publication->config_path) {
        if (safe_strncpy(lock->parent, "/", sizeof(lock->parent)) != 0 ||
            safe_strncpy(lock->logical_parent, "/",
                         sizeof(lock->logical_parent)) != 0) {
            return -1;
        }
    } else {
        size_t parent_length =
            (size_t)(slash - publication->config_path);

        if (parent_length >= sizeof(lock->parent)) {
            errno = ENAMETOOLONG;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Recorded Git configuration parent path is too long");
            return -1;
        }
        memcpy(lock->parent, publication->config_path, parent_length);
        lock->parent[parent_length] = '\0';
        memcpy(lock->logical_parent, publication->config_path,
               parent_length);
        lock->logical_parent[parent_length] = '\0';
    }
    if (safe_strncpy(lock->leaf, slash + 1U, sizeof(lock->leaf)) != 0 ||
        (size_t)snprintf(lock->lock_leaf, sizeof(lock->lock_leaf),
                         "%s.lock", lock->leaf) >=
            sizeof(lock->lock_leaf) ||
        (size_t)snprintf(lock->lock_path, sizeof(lock->lock_path),
                         "%s/%s", lock->parent, lock->lock_leaf) >=
            sizeof(lock->lock_path)) {
        errno = ENAMETOOLONG;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Recorded Git configuration lock path is too long");
        return -1;
    }
    lock->logical_present = false;
    return 0;
}

static bool git_retirement_absent_namespace_matches(
    const publication_record_t *publication,
    const git_retirement_group_t *group) {
    struct stat pinned_parent;
    struct stat live_parent;
    struct stat leaf;
    int live_parent_fd = -1;
    bool matches = false;

    if (!publication || !group || !group->absent_destination ||
        !group->lock_ready || group->lock.dir_fd < 0 ||
        group->lock.lock_fd < 0 || !group->lock.lock_created ||
        !group->lock.lock_witness_valid) {
        errno = EINVAL;
        return false;
    }
    if (fstat(group->lock.dir_fd, &pinned_parent) != 0 ||
        !git_same_object_identity(&group->lock.parent_stat,
                                  &pinned_parent) ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &pinned_parent)) {
        errno = errno ? errno : ESTALE;
        goto done;
    }
    live_parent_fd = open(group->lock.parent,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                              O_NOFOLLOW);
    if (live_parent_fd < 0 ||
        fstat(live_parent_fd, &live_parent) != 0 ||
        !git_same_object_identity(&pinned_parent, &live_parent) ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &live_parent) ||
        !git_file_at_matches_witness(
            group->lock.dir_fd, group->lock.lock_leaf,
            group->lock.lock_fd, &group->lock.lock_stat,
            NULL, 0U, NULL)) {
        errno = errno ? errno : ESTALE;
        goto done;
    }
    errno = 0;
    if (fstatat(group->lock.dir_fd, group->lock.leaf, &leaf,
                AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        goto done;
    }
    if (errno != ENOENT) goto done;
    matches = true;

done:
    if (live_parent_fd >= 0) (void)close(live_parent_fd);
    return matches;
}

static int git_retirement_revalidate_absent_group(
    const publication_record_t *publication,
    git_retirement_group_t *group, bool invoke_test_hook) {
    error_context_t entry_error = *get_last_error();
    int entry_errno = errno;
    int saved_errno;

    if (!publication || !group || !group->absent_destination ||
        !group->prepared || !group->lock_ready) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid absent Git retirement revalidation");
        return -1;
    }
    if (invoke_test_hook && g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE,
            publication->config_path, NULL, NULL)) {
        errno = EIO;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git retirement absent-destination revalidation failure");
        return -1;
    }
    if (!git_retirement_absent_namespace_matches(publication, group) ||
        fsync(group->lock.dir_fd) != 0 ||
        !git_retirement_absent_namespace_matches(publication, group)) {
        saved_errno = errno ? errno : ESTALE;
        errno = saved_errno;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Recorded Git retirement destination reappeared or its exact parent moved: %s",
            publication->config_path);
        errno = saved_errno;
        return -1;
    }
    g_last_error = entry_error;
    errno = entry_errno;
    return 0;
}

static bool git_retirement_retained_marker_matches(
    const git_scope_lock_t *lock) {
    git_recovery_marker_t parsed;
    struct stat pinned_parent;
    struct stat live_parent;
    int live_parent_fd = -1;
    bool matches = false;

    memset(&parsed, 0, sizeof(parsed));
    if (!lock || lock->dir_fd < 0 || lock->lock_fd < 0 ||
        !lock->recovery_marker_witness_valid ||
        !lock->recovery_marker_data ||
        lock->recovery_marker_length == 0U ||
        !git_recovery_marker_parse(lock->recovery_marker_data,
                                   lock->recovery_marker_length,
                                   &parsed) ||
        fstat(lock->dir_fd, &pinned_parent) != 0 ||
        !S_ISDIR(pinned_parent.st_mode) ||
        !git_same_object_identity(&lock->parent_stat, &pinned_parent)) {
        errno = errno ? errno : ESTALE;
        return false;
    }
    live_parent_fd = open(lock->parent,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                              O_NOFOLLOW);
    if (live_parent_fd >= 0 &&
        fstat(live_parent_fd, &live_parent) == 0 &&
        S_ISDIR(live_parent.st_mode) &&
        git_same_object_identity(&pinned_parent, &live_parent) &&
#if defined(__FreeBSD__)
        lock->recovery_authority_witness_valid &&
        lock->recovery_authority_fd >= 0 &&
        lock->recovery_authority_data &&
        lock->recovery_authority_length != 0U &&
        lock->recovery_lease_created &&
        git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, NULL) &&
        git_file_at_matches_witness(
            lock->dir_fd, lock->recovery_lease_leaf,
            lock->lock_fd, &lock->lock_stat, NULL, 0U, NULL) &&
        git_file_at_matches_witness(
            lock->dir_fd, lock->recovery_authority_leaf,
            lock->recovery_authority_fd,
            &lock->recovery_authority_stat,
            lock->recovery_authority_data,
            lock->recovery_authority_length, NULL)) {
#else
        git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, lock->recovery_marker_data,
            lock->recovery_marker_length, NULL)) {
#endif
        matches = true;
    } else {
        errno = errno ? errno : ESTALE;
    }
    if (live_parent_fd >= 0) (void)close(live_parent_fd);
    return matches;
}

#if defined(__FreeBSD__)
/* Terminal release may race with a foreign replacement of the canonical lock
 * name after the W/C/A authority was proved. In that case C is foreign, but
 * descriptor authority over the now-single-link W inode and the exact A file
 * remains sufficient to remove only those two private names. */
static bool git_retirement_freebsd_release_authority_matches(
    const git_scope_lock_t *lock, struct stat *lease_current) {
    git_recovery_marker_t parsed;
    struct stat pinned_parent;
    struct stat live_parent;
    struct stat current;
    struct stat baseline;
    int live_parent_fd = -1;
    bool matches = false;

    memset(&parsed, 0, sizeof(parsed));
    if (!lock || lock->dir_fd < 0 || lock->lock_fd < 0 ||
        !lock->recovery_marker_witness_valid ||
        !lock->recovery_marker_data ||
        lock->recovery_marker_length == 0U ||
        !git_recovery_marker_parse(lock->recovery_marker_data,
                                   lock->recovery_marker_length,
                                   &parsed) ||
        !lock->recovery_authority_witness_valid ||
        lock->recovery_authority_fd < 0 ||
        !lock->recovery_authority_data ||
        lock->recovery_authority_length == 0U ||
        !lock->recovery_lease_created ||
        fstat(lock->dir_fd, &pinned_parent) != 0 ||
        !S_ISDIR(pinned_parent.st_mode) ||
        !git_same_object_identity(&lock->parent_stat, &pinned_parent) ||
        fstat(lock->lock_fd, &current) != 0 ||
        !S_ISREG(current.st_mode) || current.st_size != 0 ||
        (current.st_nlink != 1 && current.st_nlink != 2)) {
        errno = errno ? errno : ESTALE;
        return false;
    }
    baseline = lock->lock_stat;
    baseline.st_nlink = current.st_nlink;
    live_parent_fd = open(lock->parent,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                              O_NOFOLLOW);
    if (live_parent_fd >= 0 &&
        fstat(live_parent_fd, &live_parent) == 0 &&
        S_ISDIR(live_parent.st_mode) &&
        git_same_object_identity(&pinned_parent, &live_parent) &&
        git_file_at_matches_witness(
            lock->dir_fd, lock->recovery_lease_leaf,
            lock->lock_fd, &baseline, NULL, 0U, &current) &&
        git_file_at_matches_witness(
            lock->dir_fd, lock->recovery_authority_leaf,
            lock->recovery_authority_fd,
            &lock->recovery_authority_stat,
            lock->recovery_authority_data,
            lock->recovery_authority_length, NULL) &&
        (current.st_nlink == 1 ||
         git_file_at_matches_witness(
             lock->dir_fd, lock->lock_leaf, lock->lock_fd,
             &current, NULL, 0U, NULL))) {
        if (lease_current) *lease_current = current;
        matches = true;
    } else {
        errno = errno ? errno : ESTALE;
    }
    if (live_parent_fd >= 0) (void)close(live_parent_fd);
    return matches;
}
#endif

/* The recovery marker is the durable cleanup authority for a private stage,
 * but the stage itself must be gone before any restored-config identity is
 * sealed. In particular, a later parent-directory sync can expose a delayed
 * ctime update on FreeBSD UFS. Remove and durably settle the exact encoded
 * stage while the canonical marker still excludes cooperative Git writers;
 * terminal completion can then release only that marker. */
static int git_retirement_group_settle_recovery_stage(
    git_retirement_group_t *group) {
    git_recovery_marker_t marker;
    git_cleanup_result_t cleanup;
    int stage_fd = -1;
    int saved_errno = EAGAIN;

    memset(&marker, 0, sizeof(marker));
    if (!group || group->recovery_stage_settled ||
        !git_retirement_retained_marker_matches(&group->lock) ||
        !git_recovery_marker_parse(
            group->lock.recovery_marker_data,
            group->lock.recovery_marker_length, &marker)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Retained Git rollback stage authority changed before settlement");
        return -1;
    }
    if (marker.stage_present) {
        stage_fd = openat(group->lock.dir_fd, marker.stage_leaf,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (stage_fd < 0) {
            if (errno != ENOENT) {
                saved_errno = errno;
                goto failed;
            }
        } else {
            g_terminal_namespace_mutation_count++;
            cleanup = git_scope_lock_cleanup_name(
                &group->lock, marker.stage_leaf,
                "terminal rollback staging file", stage_fd,
                &marker.stage_stat, marker.stage_data,
                marker.stage_length, true, true);
            if (cleanup != GIT_CLEANUP_SETTLED) {
                saved_errno = errno ? errno : EAGAIN;
                goto failed;
            }
        }
        g_terminal_namespace_sync_count++;
        if (fsync(group->lock.dir_fd) != 0) {
            saved_errno = errno ? errno : EIO;
            goto failed;
        }
    }
    if (!git_retirement_retained_marker_matches(&group->lock)) {
        saved_errno = errno ? errno : ESTALE;
        goto failed;
    }
    if (stage_fd >= 0) (void)close(stage_fd);
    group->recovery_stage_settled = true;
    return 0;

failed:
    if (stage_fd >= 0) (void)close(stage_fd);
    errno = saved_errno;
    set_system_error(
        ERR_GIT_CONFIG_FAILED,
        "Cannot durably settle the retained Git rollback stage");
    return -1;
}

/* A settled absent destination retains the exact canonical recovery marker,
 * not merely a parent descriptor. Re-prove the recorded parent, marker inode
 * and bytes, and continued destination absence immediately before the outer
 * retirement guard commits. */
static int git_retirement_revalidate_settled_absent_group(
    const publication_record_t *publication,
    git_retirement_group_t *group, bool invoke_test_hook) {
    error_context_t entry_error = *get_last_error();
    struct stat pinned_parent;
    struct stat named;
    int entry_errno = errno;
    int saved_errno = ESTALE;

    if (!publication || !group || !group->absent_destination ||
        !group->prepared || !group->settled || group->lock_ready ||
        group->lock.dir_fd < 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid settled absent Git retirement revalidation");
        return -1;
    }
    if (invoke_test_hook && g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_BEFORE_ABSENT_REVALIDATE,
            publication->config_path, NULL, NULL)) {
        errno = EIO;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git retirement absent-destination revalidation failure");
        return -1;
    }
    if (!git_retirement_retained_marker_matches(&group->lock) ||
        fstat(group->lock.dir_fd, &pinned_parent) != 0 ||
        !S_ISDIR(pinned_parent.st_mode) ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &pinned_parent)) {
        saved_errno = errno ? errno : ESTALE;
        goto failed;
    }
    errno = 0;
    if (fstatat(group->lock.dir_fd, group->lock.leaf, &named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        saved_errno = EEXIST;
        goto failed;
    }
    if (errno != ENOENT) {
        saved_errno = errno;
        goto failed;
    }
    g_last_error = entry_error;
    errno = entry_errno;
    return 0;

failed:
    errno = saved_errno;
    set_system_error(
        ERR_GIT_CONFIG_FAILED,
        "Recorded Git retirement destination reappeared or its exact retained lock lease changed: %s",
        publication->config_path);
    errno = saved_errno;
    return -1;
}

static int git_retirement_prepare_absent_group_atomic(
    const publication_record_t *const publications[],
    size_t publication_count, git_retirement_group_t *group) {
    const publication_record_t *publication;
    error_accumulator_t failures;
    int lock_fd = -1;
    int result = -1;

    if (!publications || !group ||
        group->representative >= publication_count ||
        !group->absent_destination) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid absent Git retirement group preparation");
        return -1;
    }
    publication = publications[group->representative];
    error_accumulator_init(&failures);
    if (git_retirement_resolve_absent_destination(
            publication, &group->lock) != 0) {
        return -1;
    }
    group->lock.dir_fd = open(
        group->lock.parent,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (group->lock.dir_fd < 0 ||
        fstat(group->lock.dir_fd, &group->lock.parent_stat) != 0 ||
        !git_retirement_directory_identity_matches(
            &publication->config_parent, &group->lock.parent_stat)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot pin the exact recorded Git configuration parent: %s",
            group->lock.parent);
        goto done;
    }
    if (git_cleanup_arena_require_budget(
            group->lock.dir_fd, group->lock.lock_leaf,
            GIT_CLEANUP_ARENA_HANDLE_BUDGET) != 0) {
        int arena_errno = errno;

        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            arena_errno == ENOSPC
                ? "Git cleanup arena is exhausted before lock mutation: %s. Stop all writers and inspect verified .gitswitch-cleanup-v2 artifacts during offline quiescence"
                : "Git configuration lock has pending private cleanup residue: %s. Stop all writers and inspect the associated .gitswitch-cleanup-v2 pending slot during offline quiescence",
            group->lock.lock_path);
        errno = arena_errno;
        goto done;
    }
#if defined(__FreeBSD__)
    if (git_scope_lock_recover_freebsd_authority(
            &group->lock) < 0) {
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot reconcile the bounded FreeBSD Git recovery authority");
        goto done;
    }
#endif
#if defined(__FreeBSD__)
    if (git_scope_lock_create_freebsd_lease(
            &group->lock, &lock_fd) != 0 &&
        errno == EEXIST &&
        git_scope_lock_recover_marker(&group->lock) == 0) {
        lock_fd = -1;
        (void)git_scope_lock_create_freebsd_lease(
            &group->lock, &lock_fd);
    }
#else
    lock_fd = openat(group->lock.dir_fd, group->lock.lock_leaf,
                     O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (lock_fd < 0 && errno == EEXIST &&
        git_scope_lock_recover_marker(&group->lock) == 0) {
        lock_fd = openat(group->lock.dir_fd, group->lock.lock_leaf,
                         O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    }
#endif
    if (lock_fd < 0) {
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot acquire Git configuration lock: %s",
                         group->lock.lock_path);
        goto done;
    }
    group->lock.lock_created = true;
    group->lock.lock_fd = lock_fd;
    lock_fd = -1;
    if (git_scope_lock_claim_fd(group->lock.lock_fd) != 0 ||
        fstat(group->lock.lock_fd, &group->lock.lock_stat) != 0 ||
        !S_ISREG(group->lock.lock_stat.st_mode) ||
#if defined(__FreeBSD__)
        group->lock.lock_stat.st_nlink != 2 ||
#else
        group->lock.lock_stat.st_nlink != 1 ||
#endif
        git_scope_lock_capture_empty_lock_witness(&group->lock) != 0) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Cannot pin Git configuration lock: %s",
                         group->lock.lock_path);
        goto done;
    }
    group->lock_ready = true;
    group->prepared = true;
    group->planned = 0U;
    if (git_retirement_revalidate_absent_group(
            publication, group, false) != 0) {
        goto done;
    }
    result = 0;

done:
    if (lock_fd >= 0) (void)close(lock_fd);
    if (result != 0) {
        (void)error_accumulator_add_last(
            &failures, "absent Git retirement preparation");
    }
    if (result != 0 && group->lock.lock_created &&
        !group->lock.lock_witness_valid) {
        (void)git_scope_lock_capture_empty_lock_witness(&group->lock);
    }
    if (result != 0 && group->lock.dir_fd >= 0 &&
        git_scope_lock_discard_checked(&group->lock, true) != 0) {
        (void)error_accumulator_add_last(
            &failures, "absent Git retirement cleanup");
    }
    if (result != 0) {
        group->lock_ready = false;
        group->prepared = false;
    }
    if (failures.active) (void)error_accumulator_publish(&failures);
    return result;
}

static const git_snapshot_key_t *git_snapshot_key_by_name(
    const git_scope_snapshot_t *snapshot, const char *name) {
    int index;

    if (!snapshot || !name) return NULL;
    index = git_managed_key_index_n(name, strlen(name));
    return index >= 0 ? &snapshot->keys[index] : NULL;
}

static int git_retirement_schedule_exact(git_retirement_group_t *group,
                                         const char *name,
                                         const char *value) {
    const git_snapshot_key_t *key;
    const char *observed = NULL;
    size_t matches;
    int index;

    if (!group || !name || !value) return -1;
    index = git_managed_key_index_n(name, strlen(name));
    if (index < 0) return -1;
    key = &group->snapshot.keys[index];
    matches = git_snapshot_key_exact_count(key, value);
    if (matches == 0U) return 0;
    if (matches != 1U) {
        group->attribution_conflict = true;
        return -1;
    }
    for (size_t i = 0U; i < key->count; i++) {
        if (strcmp(key->values[i], value) == 0) {
            observed = key->values[i];
            break;
        }
    }
    if (!observed ||
        (group->remove_value[index] &&
         strcmp(group->remove_value[index], observed) != 0)) {
        group->attribution_conflict = true;
        return -1;
    }
    group->remove_value[index] = observed;
    return 0;
}

static const char *git_retirement_unique_fingerprint_value(
    const git_snapshot_key_t *key, const char *fingerprint,
    bool *ambiguous) {
    const char *match = NULL;
    size_t matches = 0U;

    if (ambiguous) *ambiguous = false;
    if (!key || !fingerprint) return NULL;
    for (size_t i = 0U; i < key->count; i++) {
        if (!git_signing_key_matches_fingerprint(
                fingerprint, key->values[i])) {
            continue;
        }
        match = key->values[i];
        matches++;
    }
    if (matches > 1U && ambiguous) *ambiguous = true;
    return matches == 1U ? match : NULL;
}

/* Derive exact occurrence removals from the one immutable preflight image.
 * Only a record whose own post-image equals the selected live generation may
 * authorize credentials; linked-worktree membership records from older
 * generations cannot lend stale values to the current file. */
static void git_retirement_plan_group(
    git_retirement_group_t *group,
    const publication_record_t *const publications[],
    const bool ready[], size_t publication_count) {
    const publication_record_t *representative;
    const git_snapshot_key_t *signing_key;
    const git_snapshot_key_t *signing_enabled;
    const git_snapshot_key_t *gpg_format;
    const git_snapshot_key_t *openpgp_program;

    if (!group || !group->snapshot_ready || !publications || !ready ||
        !group->live_generation ||
        group->representative >= publication_count) {
        return;
    }
    representative = publications[group->representative];
    signing_key = git_snapshot_key_by_name(
        &group->snapshot, GIT_CONFIG_USER_SIGNINGKEY);
    signing_enabled = git_snapshot_key_by_name(
        &group->snapshot, GIT_CONFIG_COMMIT_GPGSIGN);
    gpg_format = git_snapshot_key_by_name(
        &group->snapshot, GIT_CONFIG_GPG_FORMAT);
    openpgp_program = git_snapshot_key_by_name(
        &group->snapshot, GIT_CONFIG_GPG_OPENPGP_PROGRAM);

    for (size_t i = 0U; i < publication_count; i++) {
        const publication_record_t *publication = publications[i];
        const char *anchor;
        const char *signing_state = NULL;
        bool ambiguous_anchor = false;

        if (!ready[i] ||
            !publication_record_same_config_destination(
                representative, publication) ||
            !publication_identity_equal(
                &publication->post_config,
                &group->live_generation->post_config)) {
            continue;
        }
        if ((publication->capabilities & PUBLICATION_CAP_SSH_COMMAND) != 0U) {
            (void)git_retirement_schedule_exact(
                group, GIT_CONFIG_CORE_SSHCOMMAND,
                publication->ssh_command);
        }
        if ((publication->capabilities &
             PUBLICATION_CAP_GPG_FINGERPRINT) == 0U ||
            !signing_key) {
            continue;
        }
        anchor = git_retirement_unique_fingerprint_value(
            signing_key, publication->gpg_fingerprint,
            &ambiguous_anchor);
        if (ambiguous_anchor) {
            group->attribution_conflict = true;
            continue;
        }
        if (!anchor) {
            bool signing_residue;

            if ((publication->capabilities &
                 PUBLICATION_CAP_GPG_SIGNING_STATE) != 0U) {
                const char *expected = publication->gpg_signing_enabled
                                           ? "true" : "false";
                signing_residue = signing_enabled &&
                    git_snapshot_key_exact_count(signing_enabled,
                                                 expected) != 0U;
            } else {
                signing_residue = signing_enabled &&
                                  signing_enabled->count != 0U;
            }
            if (signing_residue ||
                (gpg_format &&
                 git_snapshot_key_exact_count(
                     gpg_format, GIT_GPG_FORMAT_OPENPGP) != 0U) ||
                (openpgp_program &&
                 git_snapshot_key_exact_count(
                     openpgp_program, publication->gpg_program) != 0U)) {
                /* The signing key is the attribution anchor. Never declare
                 * success while an exact companion survives without it. */
                group->attribution_conflict = true;
            }
            continue;
        }

        if ((publication->capabilities &
             PUBLICATION_CAP_GPG_SIGNING_STATE) != 0U) {
            signing_state = publication->gpg_signing_enabled
                                ? "true" : "false";
        } else if (signing_enabled && signing_enabled->count == 1U &&
                   (strcmp(signing_enabled->values[0], "true") == 0 ||
                    strcmp(signing_enabled->values[0], "false") == 0)) {
            /* Legacy internal-v1 records predate the exact bool witness. A
             * scalar canonical bool in the sealed live generation is the
             * only backward-compatible case with unambiguous ownership. */
            signing_state = signing_enabled->values[0];
        } else {
            group->attribution_conflict = true;
        }
        if (signing_state) {
            (void)git_retirement_schedule_exact(
                group, GIT_CONFIG_COMMIT_GPGSIGN, signing_state);
        }
        if (gpg_format) {
            (void)git_retirement_schedule_exact(
                group, GIT_CONFIG_GPG_FORMAT,
                GIT_GPG_FORMAT_OPENPGP);
        }
        if (openpgp_program) {
            (void)git_retirement_schedule_exact(
                group, GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                publication->gpg_program);
        }
        (void)git_retirement_schedule_exact(
            group, GIT_CONFIG_USER_SIGNINGKEY, anchor);
    }
}

static bool git_retirement_stale_snapshot_is_clean(
    const git_retirement_group_t *group,
    const git_scope_snapshot_t *snapshot,
    const publication_record_t *const publications[],
    size_t publication_count) {
    const publication_record_t *representative;
    const git_snapshot_key_t *ssh_command;
    const git_snapshot_key_t *signing_key;

    if (!group || !snapshot || !publications ||
        group->representative >= publication_count) {
        return false;
    }
    representative = publications[group->representative];
    ssh_command = git_snapshot_key_by_name(
        snapshot, GIT_CONFIG_CORE_SSHCOMMAND);
    signing_key = git_snapshot_key_by_name(
        snapshot, GIT_CONFIG_USER_SIGNINGKEY);

    for (size_t i = 0U; i < publication_count; i++) {
        const publication_record_t *publication = publications[i];

        if (!publication_record_same_config_destination(
                representative, publication)) {
            continue;
        }
        if ((publication->capabilities & PUBLICATION_CAP_SSH_COMMAND) != 0U &&
            ssh_command &&
            git_snapshot_key_exact_count(
                ssh_command, publication->ssh_command) != 0U) {
            return false;
        }
        if ((publication->capabilities &
             PUBLICATION_CAP_GPG_FINGERPRINT) == 0U) {
            continue;
        }
        if (signing_key) {
            for (size_t j = 0U; j < signing_key->count; j++) {
                if (git_signing_key_matches_fingerprint(
                        publication->gpg_fingerprint,
                        signing_key->values[j])) {
                    return false;
                }
            }
        }
        /* AR-12 P2: without the live fingerprint anchor, generic companion
         * values — commit.gpgsign, gpg.format=openpgp, a common gpg
         * program path — are not attributable to this record; the planner
         * refuses to remove companions without the anchor for exactly this
         * reason. Treating a user-recreated commit.gpgsign as our residue
         * wedged every guarded retirement retry against values we would
         * never touch. */
    }
    return true;
}

/* A post-rename directory-sync failure leaves the canonical target installed
 * but the publication record naming its old source generation. Prepare an
 * already-clean target under the canonical lock and retain that lock through
 * the outer retirement decision so attributed values cannot reappear between
 * reconciliation and ledger publication. */
static int git_retirement_prepare_stale_group_atomic(
    const publication_record_t *const publications[],
    size_t publication_count, git_retirement_group_t *group) {
    git_scope_snapshot_t locked;
    const publication_record_t *representative;
    error_accumulator_t failures;
    int result = -1;

    if (!publications || !group ||
        group->representative >= publication_count) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid stale Git retirement reconciliation");
        return -1;
    }
    representative = publications[group->representative];
    git_scope_lock_init(&group->lock);
    memset(&locked, 0, sizeof(locked));
    error_accumulator_init(&failures);
    if (git_scope_lock_acquire(group->scope, representative->config_path,
                               &group->lock, NULL) != 0) {
        goto done;
    }
    group->lock_ready = true;
    if (!git_retirement_directory_identity_matches(
            &representative->config_parent, &group->lock.parent_stat)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Stale Git retirement destination parent changed");
        goto done;
    }
    if (git_capture_file_snapshot(
            group->lock.stage_path,
            "Could not re-read stale Git retirement destination",
            &locked) != 0) {
        goto done;
    }
    if (!git_retirement_stale_snapshot_is_clean(
            group, &locked, publications, publication_count)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Stale Git retirement destination still contains attributed values");
        goto done;
    }
    for (size_t i = 0U; i < publication_count; i++) {
        if (publication_record_same_config_destination(
                representative, publications[i]) &&
            git_retirement_verify_live_namespace(publications[i]) != 0) {
            goto done;
        }
    }
    if (!git_file_at_matches_witness(
            group->lock.dir_fd, group->lock.leaf,
            group->lock.original_fd, &group->lock.original_stat,
            group->lock.original_data, group->lock.original_length,
            NULL) ||
        fsync(group->lock.dir_fd) != 0 ||
        !git_file_at_matches_witness(
            group->lock.dir_fd, group->lock.leaf,
            group->lock.original_fd, &group->lock.original_stat,
            group->lock.original_data, group->lock.original_length,
            NULL)) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Could not durably reconcile clean Git retirement destination: %s",
                         representative->config_path);
        goto done;
    }
    result = 0;

done:
    git_scope_snapshot_clear(&locked);
    if (result != 0) {
        (void)error_accumulator_add_last(
            &failures, "stale retirement reconciliation");
    }
    if (result != 0 && group->lock.dir_fd >= 0 &&
        git_scope_lock_discard_checked(&group->lock, true) != 0) {
        (void)error_accumulator_add_last(
            &failures, "stale retirement artifact cleanup");
        result = -1;
    }
    if (result != 0) group->lock_ready = false;
    if (failures.active) (void)error_accumulator_publish(&failures);
    if (result == 0) {
        group->prepared = true;
        group->planned = 0U;
    }
    return result;
}

static size_t git_retirement_planned_count(
    const git_retirement_group_t *group) {
    size_t count = 0U;

    for (size_t i = 0U; group && i < GIT_MANAGED_KEY_COUNT; i++) {
        if (group->remove_value[i]) count++;
    }
    return count;
}

static int git_retirement_execute_group_command(
    const account_t *account,
    const publication_record_t *const publications[],
    git_retirement_group_t *group, size_t *cleared) {
    static const char *const order[] = {
        GIT_CONFIG_CORE_SSHCOMMAND,
        GIT_CONFIG_COMMIT_GPGSIGN,
        GIT_CONFIG_GPG_FORMAT,
        GIT_CONFIG_GPG_OPENPGP_PROGRAM,
        GIT_CONFIG_USER_SIGNINGKEY
    };
    const char *config_path =
        publications[group->representative]->config_path;
    size_t removed = 0U;

    for (size_t i = 0U; i < sizeof(order) / sizeof(order[0]); i++) {
        int index = git_managed_key_index_n(order[i], strlen(order[i]));
        const char *value = index >= 0 ? group->remove_value[index] : NULL;

        if (!value) continue;
        if (g_retirement_test_hook &&
            g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_REMOVE,
                                   config_path, order[i], value)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Injected Git retirement removal failure");
            if (cleared) *cleared = removed;
            return -1;
        }
        if (git_config_file_unset_exact(
                config_path, order[i], value,
                "recorded publication destination") != 0) {
            if (cleared) *cleared = removed;
            return -1;
        }
        removed++;
    }
    if (cleared) *cleared = removed;
    if (removed != 0U) {
        log_info("Retired %zu durable Git identity key(s) selecting '%s'",
                 removed, account->name);
    }
    return 0;
}

static void git_retirement_group_clear_prelock_witness(
    git_retirement_group_t *group) {
    if (!group) return;
    if (group->prelock_data) {
        secure_zero_memory(
            group->prelock_data, group->prelock_length);
        free(group->prelock_data);
    }
    group->prelock_data = NULL;
    group->prelock_length = 0U;
    group->prelock_witness_ready = false;
    memset(&group->prelock_stat, 0, sizeof(group->prelock_stat));
}

static void git_retirement_item_clear_prelock_witness(
    git_retirement_item_t *item) {
    if (!item) return;
    if (item->prelock_data) {
        secure_zero_memory(item->prelock_data, item->prelock_length);
        free(item->prelock_data);
    }
    item->prelock_data = NULL;
    item->prelock_length = 0U;
    item->prelock_witness_ready = false;
    memset(&item->prelock_stat, 0, sizeof(item->prelock_stat));
}

static int git_retirement_prepare_group_atomic(
    const publication_record_t *const publications[],
    const bool ready[], size_t publication_count,
    git_retirement_group_t *group) {
    git_scope_snapshot_t locked;
    git_scope_snapshot_t expected;
    git_scope_snapshot_t observed;
    publication_identity_t original_identity;
    static const char *const order[] = {
        GIT_CONFIG_CORE_SSHCOMMAND,
        GIT_CONFIG_COMMIT_GPGSIGN,
        GIT_CONFIG_GPG_FORMAT,
        GIT_CONFIG_GPG_OPENPGP_PROGRAM,
        GIT_CONFIG_USER_SIGNINGKEY
    };
    const char *config_path;
    error_accumulator_t failures;
    bool publication_identity_admitted;
    int result = -1;

    if (!publications || !ready || !group ||
        !group->snapshot_ready || !group->live_generation) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid exact Git retirement group preparation");
        return -1;
    }
    git_scope_lock_init(&group->lock);
    memset(&locked, 0, sizeof(locked));
    memset(&expected, 0, sizeof(expected));
    memset(&observed, 0, sizeof(observed));
    error_accumulator_init(&failures);
    config_path = publications[group->representative]->config_path;
    group->planned = git_retirement_planned_count(group);
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_PRELOCK_WITNESS,
            config_path, NULL, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Injected Git retirement pre-lock witness failure");
        git_retirement_group_clear_prelock_witness(group);
        return -1;
    }
    if (git_scope_lock_acquire(group->scope, config_path, &group->lock,
                               NULL) != 0) {
        git_retirement_group_clear_prelock_witness(group);
        return -1;
    }
    group->lock_ready = true;
    if (group->lock.original_stat.st_nlink != 1 ||
        !git_retirement_directory_identity_matches(
            &publications[group->representative]->config_parent,
            &group->lock.parent_stat)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Recorded Git retirement destination no longer has one canonical file generation");
        goto done;
    }
    publication_identity_from_stat(&original_identity,
                                   &group->lock.original_stat);
    publication_identity_admitted = publication_identity_equal(
        &original_identity, &group->live_generation->post_config);
#if defined(__FreeBSD__)
    if (!publication_identity_admitted &&
        group->lock.freebsd_authority_recovered &&
        group->prelock_witness_ready &&
        git_metadata_ctime_only_change(
            &group->prelock_stat, &group->lock.original_stat) &&
        group->prelock_length == group->lock.original_length &&
        (group->prelock_length == 0U ||
         memcmp(group->prelock_data, group->lock.original_data,
                group->prelock_length) == 0)) {
        publication_identity_admitted = true;
    }
#endif
    git_retirement_group_clear_prelock_witness(group);
    if (!publication_identity_admitted) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git retirement destination changed before its canonical lock was acquired");
        goto done;
    }
    if (git_capture_file_snapshot(
            group->lock.stage_path,
            "Could not read locked Git retirement source", &locked) != 0) {
        goto done;
    }
    if (!git_scope_snapshot_equal(&group->snapshot, &locked)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git retirement vector changed before its canonical lock was acquired");
        goto done;
    }
    if (group->planned == 0U) {
        result = 0;
        goto done;
    }
    if (g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_LOCKED_READ,
                               config_path, NULL, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Injected Git retirement locked-read failure");
        goto done;
    }
    if (git_scope_snapshot_clone(&locked, &expected) != 0) goto done;
    for (size_t i = 0U; i < sizeof(order) / sizeof(order[0]); i++) {
        int index = git_managed_key_index_n(order[i], strlen(order[i]));
        const char *value = index >= 0 ? group->remove_value[index] : NULL;

        if (!value) continue;
        if (g_retirement_test_hook &&
            g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_REMOVE,
                                   config_path, order[i], value)) {
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Injected Git retirement staged-removal failure");
            goto done;
        }
        if (git_config_file_unset_exact(
                group->lock.stage_path, order[i], value,
                "locked retirement staging file") != 0) {
            goto done;
        }
        if (git_scope_lock_capture_stage_witness(&group->lock) != 0) {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Could not retain the edited Git retirement staging generation");
            goto done;
        }
        if (git_snapshot_key_remove_exact_once(
                &expected.keys[index], value) != 0) {
            goto done;
        }
    }
    if (git_capture_file_snapshot(
            group->lock.stage_path,
            "Could not verify prepared Git retirement staging file",
            &observed) != 0) {
        goto done;
    }
    if (!git_scope_snapshot_equal(&expected, &observed)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Prepared Git retirement vectors do not match the exact survivor plan");
        goto done;
    }
    for (size_t i = 0U; i < publication_count; i++) {
        if (ready[i] &&
            publication_record_same_config_destination(
                publications[group->representative], publications[i]) &&
            git_retirement_verify_live_namespace(publications[i]) != 0) {
            goto done;
        }
    }
    result = 0;

done:
    git_retirement_group_clear_prelock_witness(group);
    git_scope_snapshot_clear(&locked);
    git_scope_snapshot_clear(&expected);
    git_scope_snapshot_clear(&observed);
    if (result != 0) {
        (void)error_accumulator_add_last(
            &failures, "exact Git retirement preparation");
    }
    if (result != 0 && group->lock.dir_fd >= 0 &&
        git_scope_lock_discard_checked(&group->lock, true) != 0) {
        (void)error_accumulator_add_last(
            &failures, "failed Git retirement preparation cleanup");
        result = -1;
    }
    if (result != 0) group->lock_ready = false;
    if (failures.active) (void)error_accumulator_publish(&failures);
    if (result == 0) group->prepared = true;
    return result;
}

static int git_retirement_publish_group_atomic(
    const account_t *account,
    const publication_record_t *const publications[],
    const bool ready[], size_t publication_count,
    git_retirement_group_t *group, size_t *cleared) {
    const char *config_path;

    if (cleared) *cleared = 0U;
    if (!account || !publications || !ready || !group ||
        !group->prepared || !group->lock_ready ||
        group->lock.dir_fd < 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid prepared Git retirement publication");
        return -1;
    }
    config_path = publications[group->representative]->config_path;
    if (group->absent_destination) {
        return git_retirement_revalidate_absent_group(
            publications[group->representative], group, true);
    }
    for (size_t i = 0U; i < publication_count; i++) {
        if (ready[i] &&
            publication_record_same_config_destination(
                publications[group->representative], publications[i]) &&
            git_retirement_verify_live_namespace(publications[i]) != 0) {
            return -1;
        }
    }
    if (group->planned == 0U) return 0;
    if (g_retirement_test_hook &&
        g_retirement_test_hook(GIT_RETIREMENT_TEST_BEFORE_PUBLISH,
                               config_path, NULL, NULL)) {
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Injected Git retirement publication failure");
        return -1;
    }
    if (git_scope_lock_publish(&group->lock, true) != 0) {
        group->published = group->lock.published;
        return -1;
    }
    group->published = group->lock.published;
    if (cleared) *cleared = group->planned;
    log_info("Retired %zu durable Git identity key(s) selecting '%s'",
             group->planned, account->name);
    return 0;
}

static void git_retirement_transaction_release_mode(
    git_retirement_transaction_t *transaction, bool inherited) {
    if (!transaction) return;
    git_retirement_registry_remove(transaction);
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];

        git_scope_lock_close_mode(
            &group->lock, inherited);
        git_scope_snapshot_clear(&group->snapshot);
        git_retirement_group_clear_prelock_witness(group);
    }
    if (transaction->items) {
        for (size_t i = 0U; i < transaction->item_count; i++) {
            git_retirement_item_t *item = &transaction->items[i];

            git_retirement_item_clear_prelock_witness(item);
        }
        secure_zero_memory(transaction->items,
                           transaction->item_count *
                               sizeof(*transaction->items));
        free(transaction->items);
    }
    free(transaction->publication_refs);
    free(transaction->groups);
    secure_zero_memory(transaction, sizeof(*transaction));
    free(transaction);
}

static void git_retirement_transaction_release(
    git_retirement_transaction_t *transaction) {
    git_retirement_transaction_release_mode(transaction, false);
}

static void git_retirement_transaction_add_failure(
    git_retirement_transaction_t *transaction, const char *label) {
    error_context_t contextual;
    int saved_errno;
    int written;

    if (!transaction) return;
    if (get_last_error()->code == ERR_SUCCESS) {
        errno = errno ? errno : EIO;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git retirement operation failed");
    }
    saved_errno = errno ? errno : EIO;
    if (!transaction->failures.active && label && label[0] != '\0') {
        char original[sizeof(contextual.message)];

        contextual = *get_last_error();
        memcpy(original, contextual.message, sizeof(original));
        original[sizeof(original) - 1U] = '\0';
        written = snprintf(contextual.message, sizeof(contextual.message),
                           "%s: %s", label,
                           original[0] != '\0'
                               ? original
                               : "Git retirement operation failed");
        if (written < 0 ||
            (size_t)written >= sizeof(contextual.message)) {
            contextual.message[sizeof(contextual.message) - 1U] = '\0';
            contextual.message_truncated = true;
        }
        errno = saved_errno;
        (void)error_accumulator_add(&transaction->failures, label,
                                    &contextual);
    } else {
        errno = saved_errno;
        (void)error_accumulator_add_last(&transaction->failures, label);
    }
    errno = saved_errno;
    transaction->failure_count++;
}

static int git_retirement_transaction_prepare_internal(
    const account_t *const accounts[],
    const publication_record_t *const publications[], size_t item_count,
    bool allow_command_runner, publication_state_t required_state,
    bool recovery_proof_only,
    git_retirement_transaction_t **out) {
    git_retirement_transaction_t *transaction = NULL;
    bool ready[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    bool processed[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    const publication_record_t *
        live_generations[PUBLICATION_LEDGER_MAX_RECORDS] = {NULL};
    size_t prelock_witness_bytes = 0U;

    if (out) *out = NULL;
    if (!out || !accounts || !publications || item_count == 0U ||
        item_count > PUBLICATION_LEDGER_MAX_RECORDS ||
        (!allow_command_runner && !run_uses_default_runner())) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid outer Git retirement transaction request");
        return -1;
    }
    transaction = calloc(1U, sizeof(*transaction));
    if (!transaction) goto allocation_failed;
    if (git_fork_child_cleanup_ensure_registered() != 0) {
        free(transaction);
        return -1;
    }
    git_retirement_registry_add(transaction);
    transaction->creator_pid = getpid();
    transaction->items = calloc(item_count, sizeof(*transaction->items));
    transaction->publication_refs =
        calloc(item_count, sizeof(*transaction->publication_refs));
    transaction->groups = calloc(item_count, sizeof(*transaction->groups));
    if (!transaction->items || !transaction->publication_refs ||
        !transaction->groups) {
        goto allocation_failed;
    }
    transaction->item_count = item_count;
    transaction->command_runner = !run_uses_default_runner();
    transaction->recovery_proof_only = recovery_proof_only;
    transaction->state = GIT_RETIREMENT_TRANSACTION_PREPARED;
    error_accumulator_init(&transaction->failures);

    /* Reject every malformed, differently owned, or wrong-lifecycle record
     * before any filesystem probe or Git subprocess can mutate a
     * destination. Ordinary retirement requires PUBLISHED; the proof-only
     * restart path requires RETIRING and receives no mutation authority. */
    for (size_t i = 0U; i < item_count; i++) {
        git_scope_t ignored_scope;

        if (!accounts[i] || !publications[i]) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "NULL item in outer Git retirement transaction");
            goto fail;
        }
        transaction->items[i].account = *accounts[i];
        transaction->items[i].publication = *publications[i];
        transaction->publication_refs[i] =
            &transaction->items[i].publication;
        if (git_retire_validate_publication_state(
                &transaction->items[i].account,
                transaction->publication_refs[i], required_state,
                &ignored_scope) != 0) {
            goto fail;
        }
    }

    /* Preflight every repository witness before the first Git subprocess. A
     * linked-worktree record may use the current generation sealed by another
     * record for the same stable physical config namespace. Ordinary
     * unresolved records are classified only after their stable destination
     * group has acquired a transaction-bound absence proof below. */
    for (size_t i = 0U; i < item_count; i++) {
        git_scope_t scope = GIT_SCOPE_GLOBAL;
        char label[MAX_NAME_LEN + 96U];
        error_context_t namespace_error;
        int namespace_errno;
        struct stat ignored;

        (void)git_scope_from_publication(
            transaction->publication_refs[i]->scope, &scope);
        if (!transaction->recovery_proof_only &&
            publication_record_verify_live_destination(
                transaction->publication_refs[i],
                transaction->publication_refs, item_count,
                &live_generations[i]) == 0) {
            bool witness_already_captured = false;

            for (size_t j = 0U; j < i; j++) {
                if (transaction->items[j].prelock_witness_ready &&
                    live_generations[j] &&
                    publication_record_same_config_destination(
                        transaction->publication_refs[i],
                        transaction->publication_refs[j]) &&
                    publication_identity_equal(
                        &live_generations[i]->post_config,
                        &live_generations[j]->post_config)) {
                    witness_already_captured = true;
                    break;
                }
            }
            if (!witness_already_captured &&
                git_retirement_capture_prelock_witness(
                    transaction->publication_refs[i],
                    &live_generations[i]->post_config,
                    &transaction->items[i].prelock_stat,
                    &transaction->items[i].prelock_data,
                    &transaction->items[i].prelock_length,
                    g_retirement_prelock_witness_budget -
                        prelock_witness_bytes) != 0) {
                (void)snprintf(
                    label, sizeof(label),
                    "account '%s' destination %zu source witness (%s)",
                    transaction->items[i].account.name, i + 1U,
                    git_scope_diagnostic_label(scope));
                git_retirement_transaction_add_failure(
                    transaction, label);
                transaction->items[i].namespace_ready = true;
                transaction->snapshot_indeterminate = true;
                continue;
            }
            if (!witness_already_captured) {
                transaction->items[i].prelock_witness_ready = true;
                prelock_witness_bytes +=
                    transaction->items[i].prelock_length;
            }
            ready[i] = true;
            transaction->items[i].ready = true;
            transaction->items[i].namespace_ready = true;
            continue;
        }
        /* The canonical atomic target has a different generation after a
         * successful rename. Keep enough namespace proof to recognize an
         * already-clean retry, but never use a stale generation to authorize
         * another mutation. */
        if (git_retirement_verify_live_namespace(
                transaction->publication_refs[i]) == 0) {
            transaction->items[i].namespace_ready = true;
            clear_error();
            continue;
        }
        if (!transaction->recovery_proof_only) {
            namespace_error = *get_last_error();
            namespace_errno = errno ? errno : ESTALE;
            errno = 0;
            if (lstat(transaction->publication_refs[i]->config_path,
                      &ignored) != 0 &&
                errno == ENOENT) {
                /* H3/H4: this is only an absence candidate. Grouping below
                 * must still pin the exact recorded parent, acquire the
                 * canonical config lock, and reprove ENOENT before it gains
                 * any settlement authority. */
                transaction->items[i].absence_candidate = true;
                clear_error();
                continue;
            }
            g_last_error = namespace_error;
            errno = namespace_errno;
        }
        (void)snprintf(label, sizeof(label),
                       "account '%s' destination %zu (%s)",
                       transaction->items[i].account.name, i + 1U,
                       git_scope_diagnostic_label(scope));
        git_retirement_transaction_add_failure(transaction, label);
    }

    /* Form stable physical groups, including zero-mutation absent groups,
     * then capture every readable group before the first unset. Any
     * indeterminate read blocks the complete mutation phase: no destination
     * may be changed from a partial preflight image. */
    for (size_t i = 0U; i < item_count; i++) {
        size_t representative = SIZE_MAX;
        size_t absent_representative = SIZE_MAX;
        git_retirement_group_t *group;

        if (processed[i]) continue;
        for (size_t j = 0U; j < item_count; j++) {
            if (publication_record_same_config_destination(
                    transaction->publication_refs[i],
                    transaction->publication_refs[j])) {
                processed[j] = true;
                if (transaction->items[j].namespace_ready &&
                    representative == SIZE_MAX) {
                    representative = j;
                }
                if (transaction->items[j].absence_candidate &&
                    absent_representative == SIZE_MAX) {
                    absent_representative = j;
                }
            }
        }
        if (representative == SIZE_MAX) {
            if (transaction->recovery_proof_only ||
                absent_representative == SIZE_MAX) {
                continue;
            }
            representative = absent_representative;
        }
        group = &transaction->groups[transaction->group_count];
        git_scope_lock_init(&group->lock);
        transaction->group_count++;
        group->representative = representative;
        (void)git_scope_from_publication(
            transaction->publication_refs[representative]->scope,
            &group->scope);
        group->absent_destination =
            transaction->items[representative].absence_candidate;
        for (size_t j = 0U; j < item_count; j++) {
            if (!publication_record_same_config_destination(
                    transaction->publication_refs[representative],
                    transaction->publication_refs[j])) {
                continue;
            }
            if (!ready[j] ||
                group->absent_destination) continue;
            if (!group->live_generation) {
                group->live_generation = live_generations[j];
            } else if (!live_generations[j] ||
                       !publication_identity_equal(
                           &group->live_generation->post_config,
                           &live_generations[j]->post_config)) {
                group->attribution_conflict = true;
            }
        }
        group->stale_generation = group->live_generation == NULL;
        if (!group->stale_generation) {
            for (size_t j = 0U; j < item_count; j++) {
                git_retirement_item_t *item = &transaction->items[j];

                if (!item->prelock_witness_ready ||
                    !live_generations[j] ||
                    !publication_record_same_config_destination(
                        transaction->publication_refs[representative],
                        transaction->publication_refs[j]) ||
                    !publication_identity_equal(
                        &group->live_generation->post_config,
                        &live_generations[j]->post_config)) {
                    continue;
                }
                group->prelock_stat = item->prelock_stat;
                group->prelock_data = item->prelock_data;
                group->prelock_length = item->prelock_length;
                group->prelock_witness_ready = true;
                memset(&item->prelock_stat, 0,
                       sizeof(item->prelock_stat));
                item->prelock_data = NULL;
                item->prelock_length = 0U;
                item->prelock_witness_ready = false;
                break;
            }
        }
    }
    for (size_t i = 0U; i < item_count; i++) {
        git_retirement_item_clear_prelock_witness(
            &transaction->items[i]);
    }

    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        const publication_record_t *publication =
            transaction->publication_refs[group->representative];
        char context[128];
        char label[MAX_NAME_LEN + 96U];

        if (group->absent_destination) continue;
        (void)snprintf(context, sizeof(context),
                       "Could not read recorded destination %zu Git configuration",
                       group->representative + 1U);
        if (git_capture_file_snapshot(publication->config_path, context,
                                      &group->snapshot) != 0) {
            (void)snprintf(label, sizeof(label),
                           "account '%s' destination %zu snapshot (%s)",
                           transaction->items[
                               group->representative].account.name,
                           group->representative + 1U,
                           git_scope_diagnostic_label(group->scope));
            git_retirement_transaction_add_failure(transaction, label);
            transaction->snapshot_indeterminate = true;
            continue;
        }
        if (!group->stale_generation &&
            !group->prelock_witness_ready) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement source has no complete pre-lock witness");
            (void)snprintf(
                label, sizeof(label),
                "account '%s' destination %zu source witness (%s)",
                transaction->items[
                    group->representative].account.name,
                group->representative + 1U,
                git_scope_diagnostic_label(group->scope));
            git_retirement_transaction_add_failure(transaction, label);
            transaction->snapshot_indeterminate = true;
            continue;
        }
        group->snapshot_ready = true;
        if (!group->stale_generation) {
            git_retirement_plan_group(
                group, transaction->publication_refs, ready, item_count);
        }
    }

    /* Absence proof acquires and may reconcile the canonical lock namespace.
     * Defer it until every present destination has a complete byte witness
     * and semantic snapshot, so a later bounded-read failure leaves all
     * earlier absent destinations untouched. */
    if (!transaction->snapshot_indeterminate) {
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            const publication_record_t *publication =
                transaction->publication_refs[group->representative];
            char label[MAX_NAME_LEN + 96U];

            if (!group->absent_destination) continue;
            if (git_retirement_prepare_absent_group_atomic(
                    transaction->publication_refs, item_count,
                    group) != 0) {
                (void)snprintf(
                    label, sizeof(label),
                    "account '%s' destination %zu absence proof (%s)",
                    transaction->items[
                        group->representative].account.name,
                    group->representative + 1U,
                    git_scope_diagnostic_label(group->scope));
                git_retirement_transaction_add_failure(transaction, label);
            } else {
                log_warning(
                    "Recorded Git destination %s is absent under its exact "
                    "parent and canonical lock; retaining the proof through "
                    "retirement settlement",
                    publication->config_path);
            }
        }
    }

    /* All attribution above came from immutable original snapshots. Only a
     * complete preflight may enter destructive work. Stale destination
     * witnesses and later mutation failures retain M10's independent-group
     * continuation; snapshot indeterminacy authorizes no mutation anywhere. */
    if (transaction->snapshot_indeterminate) {
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_clear_prelock_witness(
                &transaction->groups[i]);
        }
    }
    if (!transaction->snapshot_indeterminate) {
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            char label[MAX_NAME_LEN + 96U];
            int prepare_result;

            if (group->absent_destination) continue;
            if (!group->snapshot_ready) continue;
            if (group->attribution_conflict) {
                git_retirement_group_clear_prelock_witness(group);
                set_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Git retirement found ambiguous repeated attributed values");
                prepare_result = -1;
            } else if (transaction->command_runner &&
                       !group->stale_generation) {
                git_retirement_group_clear_prelock_witness(group);
                group->planned = git_retirement_planned_count(group);
                group->prepared = true;
                prepare_result = 0;
            } else if (group->stale_generation) {
                prepare_result = git_retirement_prepare_stale_group_atomic(
                    transaction->publication_refs, item_count, group);
            } else {
                prepare_result = git_retirement_prepare_group_atomic(
                    transaction->publication_refs, ready, item_count, group);
            }
            if (prepare_result != 0) {
                (void)snprintf(label, sizeof(label),
                               "account '%s' destination %zu preparation (%s)",
                               transaction->items[
                                   group->representative].account.name,
                               group->representative + 1U,
                               git_scope_diagnostic_label(group->scope));
                git_retirement_transaction_add_failure(transaction, label);
            }
        }
    }

    clear_error();
    *out = transaction;
    return 0;

allocation_failed:
    errno = ENOMEM;
    set_error(ERR_MEMORY_ALLOCATION,
              "Out of memory preparing outer Git retirement transaction");
fail:
    git_retirement_transaction_release(transaction);
    return -1;
}

int git_retirement_transaction_prepare(
    const account_t *const accounts[],
    const publication_record_t *const publications[], size_t item_count,
    git_retirement_transaction_t **transaction) {
    return git_retirement_transaction_prepare_internal(
        accounts, publications, item_count, false,
        PUBLICATION_STATE_PUBLISHED, false, transaction);
}

int git_retirement_transaction_publish(
    git_retirement_transaction_t *transaction, size_t *cleared) {
    bool ready[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    size_t total_cleared = 0U;

    if (cleared) *cleared = 0U;
    if (git_retirement_transaction_require_creator(
            transaction, "publish") != 0) {
        return -1;
    }
    if (transaction->state != GIT_RETIREMENT_TRANSACTION_PREPARED) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid prepared Git retirement transaction");
        return -1;
    }
    for (size_t i = 0U; i < transaction->item_count; i++) {
        ready[i] = transaction->items[i].ready;
    }
    if (transaction->recovery_proof_only &&
        !transaction->snapshot_indeterminate) {
        /* Recovery owns only a proof, never forward mutation authority.
         * Preparation already acquired every canonical lock and ran the
         * stale-clean reconciliation against RETIRING records. Do not call
         * either publication backend here: this branch must remain incapable
         * of issuing an unset even if later code changes a group's plan. */
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            char label[MAX_NAME_LEN + 96U];

            if (group->prepared && group->lock_ready &&
                group->stale_generation && group->planned == 0U) {
                continue;
            }
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Retirement recovery did not retain an exact clean Git destination proof");
            (void)snprintf(
                label, sizeof(label),
                "destination %zu recovery proof (%s)",
                group->representative + 1U,
                git_scope_diagnostic_label(group->scope));
            git_retirement_transaction_add_failure(transaction, label);
        }
    } else if (!transaction->snapshot_indeterminate) {
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            const account_t *account =
                &transaction->items[group->representative].account;
            size_t group_cleared = 0U;
            char label[MAX_NAME_LEN + 96U];
            int publish_result;

            if (!group->prepared) continue;
            if (transaction->command_runner &&
                !group->absent_destination &&
                !group->stale_generation) {
                publish_result = git_retirement_execute_group_command(
                    account, transaction->publication_refs, group,
                    &group_cleared);
            } else {
                publish_result = git_retirement_publish_group_atomic(
                    account, transaction->publication_refs, ready,
                    transaction->item_count, group, &group_cleared);
            }
            if (publish_result != 0) {
                (void)snprintf(label, sizeof(label),
                               "account '%s' destination %zu publication (%s)",
                               account->name,
                               group->representative + 1U,
                               git_scope_diagnostic_label(group->scope));
                git_retirement_transaction_add_failure(transaction, label);
            }
            total_cleared += group_cleared;
        }
    }
    transaction->published_cleared = total_cleared;
    if (cleared) *cleared = total_cleared;
    if (transaction->failure_count == 0U) {
        transaction->state = GIT_RETIREMENT_TRANSACTION_PUBLISHED;
        clear_error();
        return 0;
    }

    /* A partial publication is the historical M17 outcome, not an outer
     * rollback transaction. Accept successful canonical changes and settle
     * every held lock before reporting the aggregate failure. */
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        char label[MAX_NAME_LEN + 96U];

        if (!group->lock_ready || group->settled) continue;
        if (git_scope_lock_discard_checked(&group->lock, true) != 0) {
            (void)snprintf(label, sizeof(label),
                           "account '%s' destination %zu cleanup (%s)",
                           transaction->items[
                               group->representative].account.name,
                           group->representative + 1U,
                           git_scope_diagnostic_label(group->scope));
            git_retirement_transaction_add_failure(transaction, label);
        }
        group->lock_ready = false;
        group->settled = true;
    }
    transaction->state = GIT_RETIREMENT_TRANSACTION_PUBLISH_FAILED;
    {
        error_context_t summary;

        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Git retirement batch cleared %zu key(s), but %zu operation(s) across %zu recorded destination(s) failed",
            total_cleared, transaction->failure_count,
            transaction->item_count);
        summary = *get_last_error();
        (void)error_accumulator_add(&transaction->failures,
                                    "retirement summary", &summary);
        (void)error_accumulator_publish(&transaction->failures);
    }
    return -1;
}

static int git_scope_lock_reverse_retirement(git_scope_lock_t *lock) {
    git_exchange_result_t exchanged;
    struct stat refreshed_original;
    struct stat refreshed_published;
    bool canonical_original;

    if (!lock || lock->dir_fd < 0 || !lock->lock_created ||
        !lock->lock_witness_valid || !lock->original_present ||
        !lock->original_witness_valid || !lock->published_witness_valid) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retained Git retirement rollback state");
        return -1;
    }
    if (!git_file_at_matches_witness(
            lock->dir_fd, lock->lock_leaf, lock->lock_fd,
            &lock->lock_stat, NULL, 0U, NULL)) {
        errno = errno ? errno : EAGAIN;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Git retirement lock changed before outer rollback");
        return -1;
    }

    /* A prior attempt may have restored the canonical inode before its
     * directory sync failed. Reprove and finish that same operation instead
     * of requiring the retired post-image to reappear. */
    canonical_original = git_file_at_matches_witness(
        lock->dir_fd, lock->leaf, lock->original_fd,
        &lock->original_stat, lock->original_data,
        lock->original_length, &refreshed_original);
    if (!canonical_original) {
        bool canonical_published =
            git_file_at_matches_witness(
                lock->dir_fd, lock->leaf, lock->published_fd,
                &lock->published_stat, lock->published_data,
                lock->published_length, NULL);
        bool staged_original =
            lock->stage_created &&
            git_file_at_matches_witness(
                lock->dir_fd, lock->stage_leaf, lock->original_fd,
                &lock->original_stat, lock->original_data,
                lock->original_length, NULL);
#if defined(__FreeBSD__)
        struct stat absent_probe;
        bool canonical_absent;

        errno = 0;
        canonical_absent =
            fstatat(lock->dir_fd, lock->leaf, &absent_probe,
                    AT_SYMLINK_NOFOLLOW) != 0 &&
            errno == ENOENT;
        if ((!canonical_published && !canonical_absent) ||
            !staged_original) {
#else
        if (!canonical_published || !staged_original) {
#endif
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement destination changed before outer rollback");
            return -1;
        }
#if defined(__FreeBSD__)
        exchanged = canonical_absent
                        ? GIT_EXCHANGE_UNSUPPORTED
                        : git_exchange_names_at(
                              lock->dir_fd, lock->stage_leaf,
                              lock->leaf);
#else
        exchanged = git_exchange_names_at(
            lock->dir_fd, lock->stage_leaf, lock->leaf);
#endif
        if (exchanged == GIT_EXCHANGE_OK) {
            lock->stage_witness_kind = GIT_STAGE_WITNESS_PUBLISHED;
            if (!git_file_at_matches_witness(
                    lock->dir_fd, lock->leaf, lock->original_fd,
                    &lock->original_stat, lock->original_data,
                    lock->original_length, &refreshed_original) ||
                !git_file_at_matches_witness(
                    lock->dir_fd, lock->stage_leaf, lock->published_fd,
                    &lock->published_stat, lock->published_data,
                    lock->published_length, &refreshed_published)) {
                errno = errno ? errno : EAGAIN;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Git retirement rollback could not classify exchanged generations");
                return -1;
            }
            lock->published_stat = refreshed_published;
        } else if (exchanged == GIT_EXCHANGE_UNSUPPORTED) {
#if defined(__FreeBSD__)
            struct stat linked_original;
            struct stat named_published;
            bool fallback_canonical_published;
            bool fallback_canonical_absent;

            fallback_canonical_published =
                git_file_at_matches_witness(
                lock->dir_fd, lock->leaf, lock->published_fd,
                &lock->published_stat, lock->published_data,
                lock->published_length, &named_published);
            errno = 0;
            fallback_canonical_absent =
                fstatat(lock->dir_fd, lock->leaf, &named_published,
                        AT_SYMLINK_NOFOLLOW) != 0 &&
                errno == ENOENT;
            if (!fallback_canonical_published &&
                !fallback_canonical_absent) {
                errno = errno ? errno : EAGAIN;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Git retirement rollback destination changed before FreeBSD restoration");
                return -1;
            }
            if (fallback_canonical_published &&
                funlinkat(lock->dir_fd, lock->leaf,
                          lock->published_fd, 0) != 0) {
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Cannot detach the published Git retirement generation");
                return -1;
            }
            lock->detached_original_recovery_required = true;
            if (fallback_canonical_published &&
                g_retirement_test_hook &&
                g_retirement_test_hook(
                    GIT_RETIREMENT_TEST_AFTER_REVERSE_PUBLISHED_UNLINK,
                    lock->path, lock->stage_leaf, NULL)) {
                errno = EIO;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Injected interruption after detaching the published Git retirement generation");
                return -1;
            }
            if (linkat(lock->dir_fd, lock->stage_leaf,
                       lock->dir_fd, lock->leaf, 0) != 0 ||
                fstat(lock->original_fd, &linked_original) != 0 ||
                linked_original.st_nlink != 2 ||
                !git_file_at_matches_witness(
                    lock->dir_fd, lock->leaf, lock->original_fd,
                    &linked_original, lock->original_data,
                    lock->original_length, NULL) ||
                !git_file_at_matches_witness(
                    lock->dir_fd, lock->stage_leaf, lock->original_fd,
                    &linked_original, lock->original_data,
                    lock->original_length, NULL) ||
                funlinkat(lock->dir_fd, lock->stage_leaf,
                          lock->original_fd, 0) != 0 ||
                fstat(lock->original_fd, &refreshed_original) != 0 ||
                refreshed_original.st_nlink != 1 ||
                !git_file_at_matches_witness(
                    lock->dir_fd, lock->leaf, lock->original_fd,
                    &refreshed_original, lock->original_data,
                    lock->original_length, NULL)) {
                errno = errno ? errno : EAGAIN;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Cannot restore the exact original Git retirement generation");
                return -1;
            }
            lock->stage_created = false;
            lock->detached_original_recovery_required = false;
#else
            errno = ENOTSUP;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot restore the exact original Git retirement generation without an atomic exchange");
            return -1;
#endif
        } else {
            set_system_error(ERR_GIT_CONFIG_FAILED,
                             "Cannot exchange the original Git retirement generation back into place");
            return -1;
        }
    }
    lock->original_stat = refreshed_original;
    lock->published = false;
    if (fsync(lock->dir_fd) != 0 ||
        !git_file_at_matches_witness(
            lock->dir_fd, lock->leaf, lock->original_fd,
            &lock->original_stat, lock->original_data,
            lock->original_length, &refreshed_original)) {
        errno = errno ? errno : EIO;
        set_system_error(ERR_GIT_CONFIG_FAILED,
                         "Restored Git retirement generation was not durably verified");
        return -1;
    }
    lock->original_stat = refreshed_original;
    return 0;
}

int git_retirement_transaction_abort(
    git_retirement_transaction_t *transaction) {
    error_accumulator_t failures;
    size_t failure_count = 0U;

    if (git_retirement_transaction_require_creator(
            transaction, "abort") != 0) {
        return -1;
    }
    if (transaction->command_runner ||
        (transaction->state != GIT_RETIREMENT_TRANSACTION_PUBLISHED &&
         transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Git retirement transaction is not abortable");
        return -1;
    }
    if (transaction->state == GIT_RETIREMENT_TRANSACTION_ABORTED) return 0;
    error_accumulator_init(&failures);
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        char label[96];

        if (!group->published || group->restored) continue;
        if (!group->lock_ready ||
            git_scope_lock_reverse_retirement(&group->lock) != 0) {
            (void)snprintf(label, sizeof(label),
                           "destination %zu outer rollback (%s)",
                           group->representative + 1U,
                           git_scope_diagnostic_label(group->scope));
            (void)error_accumulator_add_last(&failures, label);
            failure_count++;
            continue;
        }
        group->restored = true;
    }
    if (failure_count != 0U) {
        error_context_t summary;

        set_error(ERR_GIT_CONFIG_FAILED,
                  "Git retirement outer rollback left %zu destination(s) unsettled",
                  failure_count);
        summary = *get_last_error();
        (void)error_accumulator_add(&failures, "rollback summary",
                                    &summary);
        (void)error_accumulator_publish(&failures);
        return -1;
    }
    transaction->state = GIT_RETIREMENT_TRANSACTION_ABORTED;
    clear_error();
    return 0;
}

static bool git_retirement_group_is_abort_reconciled(
    const git_retirement_group_t *group) {
    bool restored;

    if (!group || !group->prepared || group->absent_destination) {
        return false;
    }
    restored = group->published ? group->restored : group->planned == 0U;
    return restored &&
           (group->restored_witness_ready ||
            (group->lock_ready && !group->settled));
}

size_t git_retirement_transaction_restored_destination_count(
    const git_retirement_transaction_t *transaction) {
    size_t count = 0U;

    if (!transaction || transaction->creator_pid != getpid() ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED) {
        return 0U;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        if (git_retirement_group_is_abort_reconciled(
                &transaction->groups[i])) {
            count++;
        }
    }
    return count;
}

static bool git_retirement_group_is_terminal_reconciled(
    const git_retirement_group_t *group) {
    if (!group || !group->prepared) return false;
    if (group->absent_destination) {
        return group->absent_witness_ready ||
               (group->lock_ready && !group->settled);
    }
    return git_retirement_group_is_abort_reconciled(group);
}

size_t git_retirement_transaction_rollback_destination_count(
    const git_retirement_transaction_t *transaction) {
    size_t count = 0U;

    if (!transaction || transaction->creator_pid != getpid() ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED) {
        return 0U;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        if (git_retirement_group_is_terminal_reconciled(
                &transaction->groups[i])) {
            count++;
        }
    }
    return count;
}

/* Prove exact bytes through a descriptor, flush any delayed inode metadata,
 * close that descriptor, and require the named observation to stabilize. The
 * ctime-only retry is authorized solely by the complete byte proof. */
static bool git_file_at_matches_witness_after_close(
    int parent_fd, const char *path, const char *leaf,
    const struct stat *baseline, const unsigned char *data, size_t length,
    struct stat *current) {
    struct stat accepted;
    unsigned consecutive = 0U;

    if (parent_fd < 0 || !path || path[0] == '\0' ||
        !leaf || leaf[0] == '\0' || !baseline ||
        (length > 0U && !data)) {
        errno = EINVAL;
        return false;
    }
    accepted = *baseline;
    for (unsigned attempt = 0U;
         attempt < GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS;
         attempt++) {
        struct stat opened;
        struct stat named_after;
        struct stat named_after_hook;
        int fd = openat(parent_fd, leaf,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

        if (fd < 0) return false;
        g_terminal_namespace_sync_count++;
        if (fsync(fd) != 0) {
            int saved_errno = errno ? errno : EIO;

            (void)close(fd);
            errno = saved_errno;
            return false;
        }
        errno = 0;
        if (!git_file_at_matches_witness(
                parent_fd, leaf, fd, &accepted, data, length, &opened)) {
            int saved_errno = errno ? errno : EAGAIN;

            if (close(fd) != 0) return false;
            if (saved_errno == EAGAIN &&
                attempt + 1U <
                    GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS) {
                continue;
            }
            errno = saved_errno;
            return false;
        }
        if (close(fd) != 0) return false;
        /* FreeBSD may not expose the last funlinkat/link/rename ctime until
         * the retained descriptor closes. Sync the containing namespace only
         * after that close, then require a stable named observation. */
        if (g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_RESTORED_WITNESS_AFTER_CLOSE,
                path, NULL, NULL)) {
            errno = EIO;
            return false;
        }
        g_terminal_namespace_sync_count++;
        if (fsync(parent_fd) != 0 ||
            fstatat(parent_fd, leaf, &named_after,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            return false;
        }
        if (!git_same_pinned_file_generation(&accepted, &named_after)) {
            errno = EAGAIN;
            return false;
        }
        if (!git_same_file_observation(&opened, &named_after) &&
            !git_metadata_ctime_only_change(&opened, &named_after)) {
            errno = EAGAIN;
            return false;
        }
        if (git_same_file_observation(&accepted, &named_after)) {
            consecutive++;
        } else if (git_metadata_ctime_only_change(
                       &accepted, &named_after)) {
            accepted = named_after;
            consecutive = 0U;
        } else {
            errno = EAGAIN;
            return false;
        }
        if (g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_AFTER_STABLE_WITNESS_CLOSE,
                path, NULL, NULL)) {
            errno = EIO;
            return false;
        }
        if (fstatat(parent_fd, leaf, &named_after_hook,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            return false;
        }
        if (!git_same_pinned_file_generation(
                &accepted, &named_after_hook)) {
            errno = EAGAIN;
            return false;
        }
        if (!git_same_file_observation(
                &named_after, &named_after_hook)) {
            if (!git_metadata_ctime_only_change(
                    &named_after, &named_after_hook)) {
                errno = EAGAIN;
                return false;
            }
            accepted = named_after_hook;
            consecutive = 0U;
            continue;
        }
        if (consecutive >= 2U) {
            if (current) *current = named_after_hook;
            return true;
        }
    }
    errno = EAGAIN;
    return false;
}

/* Terminal guard verification is observation-only. Exact bytes authorize a
 * bounded post-close reproof of a same-generation ctime-only successor so the
 * caller can reseal it; preparation callers without an output must retry.
 * This path never synchronizes or mutates the namespace. */
static bool git_file_at_matches_terminal_witness_readonly(
    int parent_fd, const char *leaf, const struct stat *baseline,
    const unsigned char *data, size_t length, struct stat *current) {
    struct stat accepted;

    if (parent_fd < 0 || !leaf || leaf[0] == '\0' || !baseline ||
        (length > 0U && !data)) {
        errno = EINVAL;
        return false;
    }
    accepted = *baseline;
    for (unsigned attempt = 0U;
         attempt < GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS;
         attempt++) {
        struct stat observed;
        struct stat named_after;
        int fd = openat(parent_fd, leaf,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

        if (fd < 0) return false;
        if (!git_file_at_matches_witness(
                parent_fd, leaf, fd, &accepted, data, length,
                &observed)) {
            int saved_errno = errno ? errno : ESTALE;

            (void)close(fd);
            errno = saved_errno;
            return false;
        }
        if (close(fd) != 0 ||
            fstatat(parent_fd, leaf, &named_after,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            return false;
        }
        if (!git_same_pinned_file_generation(
                &accepted, &named_after)) {
            errno = EAGAIN;
            return false;
        }
        if (git_same_file_observation(&observed, &named_after) &&
            git_same_file_observation(&accepted, &named_after)) {
            if (current) *current = named_after;
            return true;
        }
        if ((!git_same_file_observation(&observed, &named_after) &&
             !git_metadata_ctime_only_change(
                 &observed, &named_after)) ||
            (!git_same_file_observation(&accepted, &named_after) &&
             !git_metadata_ctime_only_change(
                 &accepted, &named_after))) {
            errno = EAGAIN;
            return false;
        }
        if (!current) {
            errno = EAGAIN;
            return false;
        }
        accepted = named_after;
    }
    errno = EAGAIN;
    return false;
}

static int git_retirement_group_finalize_restored_witness(
    git_retirement_group_t *group, struct stat *current_stat) {
    struct stat refreshed;

    if (!group || !current_stat || !group->prepared) {
        errno = EINVAL;
        return -1;
    }
    if (group->restored_witness_ready) {
        if (!git_retirement_retained_marker_matches(&group->lock) ||
            !git_file_at_matches_terminal_witness_readonly(
                group->lock.dir_fd, group->lock.leaf,
                &group->lock.original_stat, group->lock.original_data,
                group->lock.original_length, &refreshed)) {
            errno = errno ? errno : EAGAIN;
            return -1;
        }
        *current_stat = refreshed;
        return 0;
    }
    if (!group->lock_ready || group->settled ||
        !group->lock.original_present ||
        !group->lock.original_witness_valid ||
        group->lock.original_fd < 0 || group->lock.dir_fd < 0 ||
        !git_file_at_matches_witness(
            group->lock.dir_fd, group->lock.leaf,
            group->lock.original_fd, &group->lock.original_stat,
            group->lock.original_data, group->lock.original_length,
            NULL)) {
        errno = errno ? errno : EAGAIN;
        return -1;
    }
    /* Convert the byte-empty canonical lock into the complete, fsynced
     * recovery certificate, then exact-clean and durably settle its encoded
     * private stage before sealing the restored generation. The certificate
     * remains at Git's exact lock name through ledger publication and the
     * terminal guard rename. */
    if (git_scope_lock_persist_recovery_marker(&group->lock) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (group->lock.recovery_marker_published ||
            group->lock.recovery_marker_publication_uncertain) {
            group->terminal_release_only = true;
            group->lock_ready = false;
            group->settled = true;
        }
        errno = saved_errno;
        return -1;
    }
    if (git_retirement_group_settle_recovery_stage(group) != 0) {
        int saved_errno = errno ? errno : EIO;

        group->terminal_release_only = true;
        group->lock_ready = false;
        group->settled = true;
        errno = saved_errno;
        return -1;
    }
    group->lock_ready = false;
    group->settled = true;
    git_scope_lock_clear_stage_witness(&group->lock);
    if (group->lock.original_fd >= 0) {
        (void)close(group->lock.original_fd);
        group->lock.original_fd = -1;
    }
    if (group->lock.published_fd >= 0) {
        (void)close(group->lock.published_fd);
        group->lock.published_fd = -1;
    }
    /* FreeBSD UFS can expose the final exact-byte generation only after the
     * restored descriptor closes. The helper requires two consecutive stable
     * exact-byte observations while admitting only same-inode ctime-only
     * materialization, and the retained marker must still own the name. */
    if (!git_retirement_retained_marker_matches(&group->lock) ||
        !git_file_at_matches_witness_after_close(
            group->lock.dir_fd, group->lock.path, group->lock.leaf,
            &group->lock.original_stat, group->lock.original_data,
            group->lock.original_length, &refreshed)) {
        errno = errno ? errno : EAGAIN;
        return -1;
    }
    group->lock.original_stat = refreshed;
    group->restored_witness_ready = true;
    *current_stat = refreshed;
    return 0;
}

static int git_retirement_transaction_rollback_destination_internal(
    git_retirement_transaction_t *transaction,
    git_retirement_group_t *group,
    char *config_path, size_t path_size,
    publication_identity_t *post_config) {
    const publication_record_t *publication;
    struct stat current_stat;

    if (git_retirement_transaction_require_creator(
            transaction, "query") != 0) {
        return -1;
    }
    if (!group || !config_path || path_size == 0U ||
        !post_config ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED ||
        group->representative >= transaction->item_count) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid reconciled Git retirement destination query");
        return -1;
    }
    publication = transaction->publication_refs[group->representative];
    if (safe_strncpy(config_path, publication->config_path,
                     path_size) != 0) {
        errno = ENAMETOOLONG;
        set_error(ERR_INVALID_ARGS,
                  "Reconciled Git retirement path buffer is too small");
        return -1;
    }
    if (group->absent_destination) {
        if (group->absent_witness_ready) {
            if (git_retirement_revalidate_settled_absent_group(
                    publication, group, true) != 0) {
                return -1;
            }
        } else if (git_retirement_revalidate_absent_group(
                       publication, group, true) != 0) {
            return -1;
        }
        /* Absence is represented only in this transient exact-set query.
         * The config layer preserves each matching durable record's prior
         * post-config identity instead of serializing an invalid absent
         * identity into a PUBLISHED record. */
        publication_identity_from_stat(post_config, NULL);
        group->terminal_witness_enumerated = true;
        clear_error();
        errno = 0;
        return 0;
    }

    /* A changed group was re-proved by abort while an unchanged group never
     * passed through the reverse-exchange path. Publish the complete canonical
     * recovery marker before sealing the restored identity, then retain exact
     * bytes and marker authority for the post-ledger terminal proof. */
    if (git_retirement_group_finalize_restored_witness(
            group, &current_stat) != 0) {
        errno = errno ? errno : EAGAIN;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Git retirement reconciliation destination changed after abort");
        return -1;
    }
    publication_identity_from_stat(post_config, &current_stat);
    group->terminal_witness_enumerated = true;
    return 0;
}

int git_retirement_transaction_restored_destination(
    git_retirement_transaction_t *transaction, size_t index,
    char *config_path, size_t path_size,
    publication_identity_t *post_config) {
    size_t position = 0U;

    if (git_retirement_transaction_require_creator(
            transaction, "query") != 0) {
        return -1;
    }
    if (!config_path || path_size == 0U || !post_config ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED ||
        transaction->enumeration_mode ==
            GIT_RETIREMENT_ENUMERATION_TERMINAL) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid restored Git retirement destination query");
        return -1;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        if (!git_retirement_group_is_abort_reconciled(
                &transaction->groups[i])) {
            continue;
        }
        if (position++ != index) continue;
        transaction->enumeration_mode =
            GIT_RETIREMENT_ENUMERATION_LEGACY;
        return git_retirement_transaction_rollback_destination_internal(
            transaction, &transaction->groups[i],
            config_path, path_size, post_config);
    }
    errno = ERANGE;
    set_error(ERR_INVALID_ARGS,
              "Restored Git retirement destination index is out of range");
    return -1;
}

int git_retirement_transaction_rollback_destination(
    git_retirement_transaction_t *transaction, size_t index,
    char *config_path, size_t path_size,
    publication_identity_t *post_config) {
    size_t position = 0U;

    if (git_retirement_transaction_require_creator(
            transaction, "query") != 0) {
        return -1;
    }
    if (!config_path || path_size == 0U || !post_config ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED ||
        (transaction->terminal_kind != GIT_RETIREMENT_TERMINAL_NONE &&
         transaction->terminal_kind !=
             GIT_RETIREMENT_TERMINAL_ROLLBACK) ||
        transaction->enumeration_mode ==
            GIT_RETIREMENT_ENUMERATION_LEGACY) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid terminal Git rollback destination query");
        return -1;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        if (!git_retirement_group_is_terminal_reconciled(
                &transaction->groups[i])) {
            continue;
        }
        if (position++ != index) continue;
        /* Record terminal intent before the first query can publish a
         * recovery marker. If a later destination fails, generic disposal
         * must preserve every marker already produced by this enumeration. */
        transaction->enumeration_mode =
            GIT_RETIREMENT_ENUMERATION_TERMINAL;
        transaction->terminal_kind =
            GIT_RETIREMENT_TERMINAL_ROLLBACK;
        return git_retirement_transaction_rollback_destination_internal(
            transaction, &transaction->groups[i],
            config_path, path_size, post_config);
    }
    errno = ERANGE;
    set_error(ERR_INVALID_ARGS,
              "Terminal Git rollback destination index is out of range");
    return -1;
}

int git_retirement_transaction_prepare_terminal_rollback(
    git_retirement_transaction_t *transaction) {
    if (git_retirement_transaction_require_creator(
            transaction, "prepare terminal rollback for") != 0) {
        return -1;
    }
    if (transaction->state != GIT_RETIREMENT_TRANSACTION_ABORTED ||
        transaction->recovery_proof_only ||
        transaction->terminal_release_only ||
        transaction->terminal_kind !=
            GIT_RETIREMENT_TERMINAL_ROLLBACK ||
        transaction->enumeration_mode !=
            GIT_RETIREMENT_ENUMERATION_TERMINAL) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Invalid Git retirement terminal rollback preparation");
        return -1;
    }
    if (transaction->terminal_settlement_failed) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Git retirement terminal namespace settlement previously failed");
        return -1;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];

        if (!group->terminal_witness_enumerated) {
            errno = EBUSY;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement rollback has an unenumerated terminal destination");
            return -1;
        }
        if (group->restored_witness_ready) {
            if (!group->settled || group->lock_ready ||
                group->lock.original_fd >= 0 ||
                group->lock.published_fd >= 0 ||
                group->lock.lock_fd < 0 ||
                group->lock.stage_fd >= 0 ||
                group->lock.dir_fd < 0 ||
                !group->lock.original_present ||
                !group->lock.original_witness_valid ||
                !group->recovery_stage_settled ||
                !git_retirement_retained_marker_matches(
                    &group->lock)) {
                errno = ESTALE;
                set_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Restored Git retirement witness is not release-only");
                return -1;
            }
            continue;
        }
        if (!group->absent_destination || !group->prepared) {
            errno = EBUSY;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement rollback has an unsealed destination");
            return -1;
        }
        if (group->lock_ready && !group->settled) {
            if (git_retirement_revalidate_absent_group(
                    transaction->publication_refs[group->representative],
                    group, true) != 0) {
                return -1;
            }
            if (git_scope_lock_persist_recovery_marker(
                    &group->lock) != 0) {
                if (group->lock.recovery_marker_published ||
                    group->lock
                        .recovery_marker_publication_uncertain) {
                    group->terminal_release_only = true;
                    group->lock_ready = false;
                    group->settled = true;
                }
                transaction->terminal_settlement_failed = true;
                return -1;
            }
            if (git_retirement_group_settle_recovery_stage(
                    group) != 0) {
                group->terminal_release_only = true;
                group->lock_ready = false;
                group->settled = true;
                transaction->terminal_settlement_failed = true;
                return -1;
            }
            group->lock_ready = false;
            group->settled = true;
            git_scope_lock_clear_stage_witness(&group->lock);
            if (git_retirement_revalidate_settled_absent_group(
                    transaction->publication_refs[
                        group->representative],
                    group, false) != 0) {
                transaction->terminal_settlement_failed = true;
                return -1;
            }
            group->absent_witness_ready = true;
        }
        if (!group->settled || group->lock_ready ||
            !group->absent_witness_ready ||
            group->lock.dir_fd < 0 || group->lock.lock_fd < 0 ||
            !group->lock.recovery_marker_witness_valid ||
            !group->recovery_stage_settled) {
            errno = EBUSY;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Absent Git retirement destination is not settled");
            return -1;
        }
    }
    /* Other destinations above may synchronize the shared parent after an
     * earlier restored witness was sealed. Materialize every delayed
     * metadata update now, inside preparation, and require one complete
     * read-only pass before exposing the terminal barrier contract. */
    for (unsigned attempt = 0U;
         attempt < GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS;
         attempt++) {
        bool stable = true;

        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group =
                &transaction->groups[i];
            struct stat refreshed;

            if (!group->restored_witness_ready) continue;
            if (!git_retirement_retained_marker_matches(
                    &group->lock) ||
                !git_file_at_matches_witness_after_close(
                    group->lock.dir_fd, group->lock.path,
                    group->lock.leaf, &group->lock.original_stat,
                    group->lock.original_data,
                    group->lock.original_length, &refreshed) ||
                (!git_same_file_observation(
                     &group->lock.original_stat, &refreshed) &&
                 !git_metadata_ctime_only_change(
                     &group->lock.original_stat, &refreshed))) {
                transaction->terminal_settlement_failed = true;
                return -1;
            }
            group->lock.original_stat = refreshed;
        }
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group =
                &transaction->groups[i];

            if (group->restored_witness_ready &&
                (!git_retirement_retained_marker_matches(
                     &group->lock) ||
                 !git_file_at_matches_terminal_witness_readonly(
                     group->lock.dir_fd, group->lock.leaf,
                     &group->lock.original_stat,
                     group->lock.original_data,
                     group->lock.original_length, NULL))) {
                stable = false;
                break;
            }
        }
        if (stable) break;
        if (attempt + 1U ==
            GIT_RESTORED_WITNESS_STABILIZATION_ATTEMPTS) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Restored Git terminal witnesses did not stabilize during preparation");
            transaction->terminal_settlement_failed = true;
            return -1;
        }
    }
    transaction->terminal_release_only = true;
    clear_error();
    errno = 0;
    return 0;
}

static bool git_retirement_group_terminal_clean_matches(
    const git_retirement_transaction_t *transaction,
    git_retirement_group_t *group) {
    const publication_record_t *representative;
    int witness_fd;
    const struct stat *witness_stat;
    const unsigned char *witness_data;
    size_t witness_length;

    if (!transaction || !group || !group->prepared ||
        !group->settled || group->lock_ready ||
        group->representative >= transaction->item_count ||
        !git_retirement_retained_marker_matches(&group->lock)) {
        errno = errno ? errno : ESTALE;
        return false;
    }
    representative =
        transaction->publication_refs[group->representative];
    if (group->absent_destination) {
        return group->absent_witness_ready &&
               git_retirement_revalidate_settled_absent_group(
                   representative, group, false) == 0;
    }
    if (!group->terminal_clean_witness_ready) {
        errno = ESTALE;
        return false;
    }
    if (group->terminal_clean_uses_published) {
        witness_fd = group->lock.published_fd;
        witness_stat = &group->lock.published_stat;
        witness_data = group->lock.published_data;
        witness_length = group->lock.published_length;
    } else {
        witness_fd = group->lock.original_fd;
        witness_stat = &group->lock.original_stat;
        witness_data = group->lock.original_data;
        witness_length = group->lock.original_length;
    }
    if (witness_fd < 0 ||
        !git_file_at_matches_witness(
            group->lock.dir_fd, group->lock.leaf, witness_fd,
            witness_stat, witness_data, witness_length, NULL)) {
        errno = errno ? errno : ESTALE;
        return false;
    }
    for (size_t i = 0U; i < transaction->item_count; i++) {
        if (publication_record_same_config_destination(
                representative, transaction->publication_refs[i]) &&
            git_retirement_verify_live_namespace(
                transaction->publication_refs[i]) != 0) {
            return false;
        }
    }
    return true;
}

static int git_retirement_transaction_prepare_terminal_clean(
    git_retirement_transaction_t *transaction,
    git_retirement_terminal_kind_t kind) {
    git_retirement_group_t *active_group = NULL;

    if (git_retirement_transaction_require_creator(
            transaction, "prepare terminal completion for") != 0) {
        return -1;
    }
    if (transaction->state != GIT_RETIREMENT_TRANSACTION_PUBLISHED ||
        transaction->terminal_release_only ||
        transaction->terminal_kind != GIT_RETIREMENT_TERMINAL_NONE ||
        (kind != GIT_RETIREMENT_TERMINAL_COMMIT &&
         kind != GIT_RETIREMENT_TERMINAL_RECOVERY) ||
        transaction->recovery_proof_only !=
            (kind == GIT_RETIREMENT_TERMINAL_RECOVERY)) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Invalid Git retirement terminal completion preparation");
        return -1;
    }
    if (kind == GIT_RETIREMENT_TERMINAL_RECOVERY &&
        git_retirement_recovery_reprove_transaction(transaction) != 0) {
        return -1;
    }

    /* Complete the read/proof phase before the first marker publication.
     * Ordinary checked cleanup therefore remains available when the initial
     * proof fails, while every subsequent failure occurs after terminal
     * release-only intent has become sticky. */
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        const publication_record_t *publication;
        int witness_fd;
        const struct stat *witness_stat;
        const unsigned char *witness_data;
        size_t witness_length;

        if (!group->prepared || !group->lock_ready || group->settled ||
            group->representative >= transaction->item_count) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement terminal completion lost a prepared destination");
            return -1;
        }
        publication =
            transaction->publication_refs[group->representative];
        if (group->absent_destination) {
            if (git_retirement_revalidate_absent_group(
                    publication, group, true) != 0) {
                return -1;
            }
            continue;
        }
        if (group->published) {
            witness_fd = group->lock.published_fd;
            witness_stat = &group->lock.published_stat;
            witness_data = group->lock.published_data;
            witness_length = group->lock.published_length;
        } else {
            witness_fd = group->lock.original_fd;
            witness_stat = &group->lock.original_stat;
            witness_data = group->lock.original_data;
            witness_length = group->lock.original_length;
        }
        if (witness_fd < 0 ||
            !git_file_at_matches_witness(
                group->lock.dir_fd, group->lock.leaf, witness_fd,
                witness_stat, witness_data, witness_length, NULL)) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement clean post-image changed before terminal preparation");
            return -1;
        }
        for (size_t j = 0U; j < transaction->item_count; j++) {
            if (publication_record_same_config_destination(
                    publication, transaction->publication_refs[j]) &&
                git_retirement_verify_live_namespace(
                    transaction->publication_refs[j]) != 0) {
                return -1;
            }
        }
    }

    /* Terminal intent is transaction-wide, but release-only ownership is
     * recorded per destination. A later group that fails before marker
     * publication can still checked-clean its ordinary empty lock/stage,
     * while earlier complete or uncertain markers remain descriptor-only. */
    transaction->terminal_kind = kind;
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        const publication_record_t *publication;
        bool use_published;
        int witness_fd;
        const struct stat *witness_stat;
        const unsigned char *witness_data;
        size_t witness_length;

        active_group = group;
        if (!group->prepared || !group->lock_ready || group->settled ||
            group->representative >= transaction->item_count) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement terminal completion lost a prepared destination");
            goto failed;
        }
        publication =
            transaction->publication_refs[group->representative];
        if (group->absent_destination) {
            if (git_retirement_revalidate_absent_group(
                    publication, group, true) != 0) {
                goto failed;
            }
            transaction->terminal_release_only = true;
            group->terminal_release_only = true;
            if (git_scope_lock_persist_recovery_marker(
                    &group->lock) != 0) {
                if (!group->lock.recovery_marker_published &&
                    !group->lock.recovery_marker_publication_uncertain) {
                    group->terminal_release_only = false;
                }
                goto uncertain;
            }
            if (git_retirement_group_settle_recovery_stage(
                    group) != 0) {
                goto uncertain;
            }
            group->lock_ready = false;
            group->settled = true;
            git_scope_lock_clear_stage_witness(&group->lock);
            if (git_retirement_revalidate_settled_absent_group(
                    publication, group, false) != 0) {
                goto failed;
            }
            group->absent_witness_ready = true;
            continue;
        }

        use_published = group->published;
        if (use_published) {
            witness_fd = group->lock.published_fd;
            witness_stat = &group->lock.published_stat;
            witness_data = group->lock.published_data;
            witness_length = group->lock.published_length;
        } else {
            witness_fd = group->lock.original_fd;
            witness_stat = &group->lock.original_stat;
            witness_data = group->lock.original_data;
            witness_length = group->lock.original_length;
        }
        if (witness_fd < 0 ||
            !git_file_at_matches_witness(
                group->lock.dir_fd, group->lock.leaf, witness_fd,
                witness_stat, witness_data, witness_length, NULL)) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement clean post-image changed before terminal preparation");
            goto failed;
        }
        for (size_t j = 0U; j < transaction->item_count; j++) {
            if (publication_record_same_config_destination(
                    publication, transaction->publication_refs[j]) &&
                git_retirement_verify_live_namespace(
                    transaction->publication_refs[j]) != 0) {
                goto failed;
            }
        }
        if (fsync(group->lock.dir_fd) != 0) {
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement clean post-image directory sync failed before terminal preparation");
            goto failed;
        }
        if (g_retirement_test_hook &&
            g_retirement_test_hook(
                GIT_RETIREMENT_TEST_BEFORE_TERMINAL_SECOND_PROOF,
                group->lock.path, NULL, NULL)) {
            errno = EIO;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Injected Git retirement terminal second-proof failure");
            goto failed;
        }
        if (!git_file_at_matches_witness(
                group->lock.dir_fd, group->lock.leaf, witness_fd,
                witness_stat, witness_data, witness_length, NULL)) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement clean post-image was not durably stable before terminal preparation");
            goto failed;
        }
        transaction->terminal_release_only = true;
        group->terminal_release_only = true;
        if (git_scope_lock_persist_recovery_marker(
                &group->lock) != 0) {
            if (!group->lock.recovery_marker_published &&
                !group->lock.recovery_marker_publication_uncertain) {
                group->terminal_release_only = false;
            }
            goto uncertain;
        }
        if (git_retirement_group_settle_recovery_stage(group) != 0) {
            goto uncertain;
        }
        group->lock_ready = false;
        group->settled = true;
        git_scope_lock_clear_stage_witness(&group->lock);
        group->terminal_clean_uses_published = use_published;
        group->terminal_clean_witness_ready = true;
        if (!git_retirement_group_terminal_clean_matches(
                transaction, group)) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement clean post-image changed during terminal preparation");
            goto failed;
        }
    }
    clear_error();
    errno = 0;
    return 0;

uncertain:
    /* Marker persistence and stage settlement are multi-sync operations.
     * Preserve their namespace exactly when their outcome is uncertain. */
    if (active_group && active_group->terminal_release_only) {
        active_group->lock_ready = false;
        active_group->settled = true;
    }
failed:
    transaction->terminal_settlement_failed = true;
    return -1;
}

static int git_retirement_transaction_verify_terminal_clean(
    git_retirement_transaction_t *transaction,
    git_retirement_terminal_kind_t kind) {
    if (git_retirement_transaction_require_creator(
            transaction, "verify terminal completion for") != 0) {
        return -1;
    }
    if (transaction->state != GIT_RETIREMENT_TRANSACTION_PUBLISHED ||
        !transaction->terminal_release_only ||
        transaction->terminal_settlement_failed ||
        transaction->terminal_kind != kind ||
        (kind != GIT_RETIREMENT_TERMINAL_COMMIT &&
         kind != GIT_RETIREMENT_TERMINAL_RECOVERY) ||
        transaction->recovery_proof_only !=
            (kind == GIT_RETIREMENT_TERMINAL_RECOVERY)) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Git retirement completion is not terminally prepared");
        return -1;
    }
    for (size_t i = 0U; i < transaction->group_count; i++) {
        if (!git_retirement_group_terminal_clean_matches(
                transaction, &transaction->groups[i])) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement terminal clean witness changed");
            return -1;
        }
    }
    clear_error();
    errno = 0;
    return 0;
}

int git_retirement_transaction_prepare_terminal_commit(
    git_retirement_transaction_t *transaction) {
    return git_retirement_transaction_prepare_terminal_clean(
        transaction, GIT_RETIREMENT_TERMINAL_COMMIT);
}

int git_retirement_transaction_verify_terminal_commit(
    git_retirement_transaction_t *transaction) {
    return git_retirement_transaction_verify_terminal_clean(
        transaction, GIT_RETIREMENT_TERMINAL_COMMIT);
}

static int git_retirement_group_finish_marker(
    git_retirement_group_t *group) {
    git_cleanup_result_t cleanup;
    int saved_errno = EAGAIN;

    if (!group || !group->recovery_stage_settled ||
#if defined(__FreeBSD__)
        !git_retirement_freebsd_release_authority_matches(
            &group->lock, NULL)) {
#else
        !git_retirement_retained_marker_matches(&group->lock)) {
#endif
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_GIT_CONFIG_FAILED,
            "Retained Git rollback lock lease changed before release");
        return -1;
    }
#if defined(__FreeBSD__)
    cleanup = git_scope_lock_cleanup_name(
        &group->lock, group->lock.recovery_authority_leaf,
        "terminal rollback recovery authority",
        group->lock.recovery_authority_fd,
        &group->lock.recovery_authority_stat,
        group->lock.recovery_authority_data,
        group->lock.recovery_authority_length, true, true);
#else
    cleanup = git_scope_lock_cleanup_name(
        &group->lock, group->lock.lock_leaf,
        "terminal rollback recovery marker", group->lock.lock_fd,
        &group->lock.lock_stat, group->lock.recovery_marker_data,
        group->lock.recovery_marker_length, true, true);
#endif
    if (cleanup != GIT_CLEANUP_SETTLED) {
        saved_errno = errno ? errno : EAGAIN;
        goto failed;
    }
    if (fsync(group->lock.dir_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        goto failed;
    }
#if defined(__FreeBSD__)
    group->lock.recovery_authority_witness_valid = false;
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_TERMINAL_AUTHORITY_SYNC,
            group->lock.path, NULL, NULL)) {
        saved_errno = EIO;
        goto failed;
    }
    cleanup = git_scope_lock_cleanup_name(
        &group->lock, group->lock.lock_leaf,
        "terminal rollback recovery marker", group->lock.lock_fd,
        &group->lock.lock_stat, NULL, 0U, true, true);
    if (cleanup != GIT_CLEANUP_SETTLED ||
        fsync(group->lock.dir_fd) != 0) {
        saved_errno = errno ? errno : EAGAIN;
        goto failed;
    }
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_AFTER_TERMINAL_CANONICAL_SYNC,
            group->lock.path, NULL, NULL)) {
        saved_errno = EIO;
        goto failed;
    }
    if (fstat(group->lock.lock_fd,
              &group->lock.lock_stat) != 0 ||
        group->lock.lock_stat.st_nlink != 1) {
        saved_errno = errno ? errno : EAGAIN;
        goto failed;
    }
    cleanup = git_scope_lock_cleanup_name(
        &group->lock, group->lock.recovery_lease_leaf,
        "terminal rollback recovery lease", group->lock.lock_fd,
        &group->lock.lock_stat, NULL, 0U, true, true);
    if (cleanup != GIT_CLEANUP_SETTLED ||
        fsync(group->lock.dir_fd) != 0) {
        saved_errno = errno ? errno : EAGAIN;
        goto failed;
    }
    group->lock.recovery_lease_created = false;
#endif
    /* Do not surrender the exact marker authority until canonical absence
     * (or private quarantine on systems without funlinkat) is durable. */
    group->lock.recovery_marker_witness_valid = false;
    group->lock.recovery_marker_published = false;
    group->recovery_stage_settled = false;
    return 0;

failed:
    errno = saved_errno;
    return -1;
}

static int git_retirement_transaction_finish_terminal(
    git_retirement_transaction_t **transaction_ptr,
    git_retirement_terminal_kind_t kind, const char *outcome_label) {
    git_retirement_transaction_t *transaction;
    error_accumulator_t failures;
    if (!transaction_ptr || !*transaction_ptr) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Missing Git retirement terminal transaction");
        return -1;
    }
    transaction = *transaction_ptr;
    if (transaction->creator_pid != getpid()) {
        git_retirement_transaction_release_mode(transaction, true);
        *transaction_ptr = NULL;
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot finish a Git retirement capability inherited by a different process");
        return -1;
    }
    if (transaction->state !=
            (kind == GIT_RETIREMENT_TERMINAL_ROLLBACK
                 ? GIT_RETIREMENT_TRANSACTION_ABORTED
                 : GIT_RETIREMENT_TRANSACTION_PUBLISHED) ||
        transaction->recovery_proof_only !=
            (kind == GIT_RETIREMENT_TERMINAL_RECOVERY) ||
        !transaction->terminal_release_only ||
        transaction->terminal_settlement_failed ||
        transaction->terminal_kind != kind) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Git retirement outcome is not terminally prepared");
        return -1;
    }
    error_accumulator_init(&failures);
    for (size_t i = 0U; i < transaction->group_count; i++) {
        char label[96];

        if (kind == GIT_RETIREMENT_TERMINAL_ROLLBACK &&
            !transaction->groups[i].terminal_witness_enumerated) {
            continue;
        }
        if (git_retirement_group_finish_marker(
                &transaction->groups[i]) == 0) {
            continue;
        }
        (void)snprintf(
            label, sizeof(label),
            "destination %zu terminal marker cleanup (%s)",
            transaction->groups[i].representative + 1U,
            git_scope_diagnostic_label(transaction->groups[i].scope));
        (void)error_accumulator_add_last(&failures, label);
    }
    git_retirement_transaction_release(transaction);
    *transaction_ptr = NULL;
    if (failures.active) {
        const error_context_t *diagnostic;

        (void)error_accumulator_publish(&failures);
        diagnostic = get_last_error();
        log_warning(
            "Consumed terminal Git %s completed with cleanup diagnostics: %s%s%s",
            outcome_label ? outcome_label : "outcome",
            diagnostic->message,
            diagnostic->details[0] != '\0' ? "; " : "",
            diagnostic->details);
        /* Outer guard commit made rollback terminal. Namespace cleanup,
         * durability, and foreign-entry conflicts are now diagnostics over a
         * consumed outcome, never a request to roll business state back. */
        clear_error();
        errno = 0;
        return 0;
    }
    clear_error();
    errno = 0;
    return 0;
}

int git_retirement_transaction_finish_terminal_rollback(
    git_retirement_transaction_t **transaction_ptr) {
    return git_retirement_transaction_finish_terminal(
        transaction_ptr, GIT_RETIREMENT_TERMINAL_ROLLBACK,
        "rollback");
}

int git_retirement_transaction_finish_terminal_commit(
    git_retirement_transaction_t **transaction_ptr) {
    return git_retirement_transaction_finish_terminal(
        transaction_ptr, GIT_RETIREMENT_TERMINAL_COMMIT,
        "commit");
}

int git_retirement_transaction_commit(
    git_retirement_transaction_t **transaction_ptr) {
    git_retirement_transaction_t *transaction;
    error_accumulator_t failures;
    int result = 0;

    if (!transaction_ptr || !*transaction_ptr) return 0;
    transaction = *transaction_ptr;
    if (transaction->creator_pid != getpid()) {
        git_retirement_transaction_release_mode(transaction, true);
        *transaction_ptr = NULL;
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot commit a Git retirement capability inherited by a different process");
        return -1;
    }
    if (transaction->terminal_release_only) {
        /* A failed guard or ledger settlement leaves every complete or
         * publication-uncertain marker descriptor-only. Destinations that
         * never crossed their marker boundary still own ordinary empty
         * lock/stage pairs and must be checked-cleaned, or they would strand
         * a non-recoverable canonical lock. */
        error_accumulator_init(&failures);
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            char label[96];

            if (group->terminal_release_only ||
                !group->lock_ready || group->settled) {
                continue;
            }
            if (git_scope_lock_discard_checked(
                    &group->lock, true) != 0) {
                (void)snprintf(
                    label, sizeof(label),
                    "destination %zu unmarked terminal cleanup (%s)",
                    group->representative + 1U,
                    git_scope_diagnostic_label(group->scope));
                (void)error_accumulator_add_last(&failures, label);
                result = -1;
            }
            group->lock_ready = false;
            group->settled = true;
        }
        git_retirement_transaction_release(transaction);
        *transaction_ptr = NULL;
        if (failures.active) {
            (void)error_accumulator_publish(&failures);
        } else {
            clear_error();
            errno = 0;
        }
        return result;
    }
    if (transaction->enumeration_mode ==
        GIT_RETIREMENT_ENUMERATION_TERMINAL) {
        /* A terminal query may already have converted an earlier group to a
         * complete canonical marker before a later destination fails. Leave
         * every converted or uncertain group descriptor-only; checked-clean
         * only groups that still hold their original empty lock/stage state,
         * which is not independently recoverable after descriptor release. */
        error_accumulator_init(&failures);
        for (size_t i = 0U; i < transaction->group_count; i++) {
            git_retirement_group_t *group = &transaction->groups[i];
            char label[96];

            if (group->terminal_release_only ||
                group->lock.recovery_marker_published ||
                group->lock.recovery_marker_publication_uncertain ||
                group->lock.recovery_marker_witness_valid ||
                !group->lock_ready || group->settled) {
                continue;
            }
            if (git_scope_lock_discard_checked(
                    &group->lock, true) != 0) {
                (void)snprintf(
                    label, sizeof(label),
                    "destination %zu terminal-failure cleanup (%s)",
                    group->representative + 1U,
                    git_scope_diagnostic_label(group->scope));
                (void)error_accumulator_add_last(&failures, label);
                result = -1;
            }
            group->lock_ready = false;
            group->settled = true;
        }
        git_retirement_transaction_release(transaction);
        *transaction_ptr = NULL;
        if (failures.active) {
            (void)error_accumulator_publish(&failures);
        } else {
            clear_error();
            errno = 0;
        }
        return result;
    }
    error_accumulator_init(&failures);
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        char label[96];

        if (group->absent_destination &&
            group->lock_ready && !group->settled &&
            git_retirement_revalidate_absent_group(
                transaction->publication_refs[group->representative],
                group, true) != 0) {
            (void)snprintf(
                label, sizeof(label),
                "destination %zu absent-settlement proof (%s)",
                group->representative + 1U,
                git_scope_diagnostic_label(group->scope));
            (void)error_accumulator_add_last(&failures, label);
            result = -1;
        }
        if (group->restored_witness_ready) {
            struct stat refreshed;

            if (!git_file_at_matches_witness_after_close(
                    group->lock.dir_fd, group->lock.path,
                    group->lock.leaf,
                    &group->lock.original_stat,
                    group->lock.original_data,
                    group->lock.original_length, &refreshed)) {
                errno = errno ? errno : EAGAIN;
                set_system_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Restored Git destination changed during publication-ledger reconciliation");
                (void)snprintf(
                    label, sizeof(label),
                    "destination %zu post-refresh verification (%s)",
                    group->representative + 1U,
                    git_scope_diagnostic_label(group->scope));
                (void)error_accumulator_add_last(&failures, label);
                result = -1;
                continue;
            }
            if (!git_same_file_observation(
                    &group->lock.original_stat, &refreshed)) {
                if (!git_metadata_ctime_only_change(
                        &group->lock.original_stat, &refreshed)) {
                    errno = EAGAIN;
                    set_system_error(
                        ERR_GIT_CONFIG_FAILED,
                        "Restored Git destination changed during publication-ledger reconciliation");
                    (void)snprintf(
                        label, sizeof(label),
                        "destination %zu post-refresh verification (%s)",
                        group->representative + 1U,
                        git_scope_diagnostic_label(group->scope));
                    (void)error_accumulator_add_last(&failures, label);
                    result = -1;
                    continue;
                }
                group->lock.original_stat = refreshed;
            }
            if (git_retirement_group_finish_marker(group) != 0) {
                (void)snprintf(
                    label, sizeof(label),
                    "destination %zu restored-marker cleanup (%s)",
                    group->representative + 1U,
                    git_scope_diagnostic_label(group->scope));
                (void)error_accumulator_add_last(&failures, label);
                result = -1;
            }
            continue;
        }

        if (!group->lock_ready || group->settled) continue;
        if (git_scope_lock_discard_checked(&group->lock, true) != 0) {
            (void)snprintf(label, sizeof(label),
                           "destination %zu commit cleanup (%s)",
                           group->representative + 1U,
                           git_scope_diagnostic_label(group->scope));
            (void)error_accumulator_add_last(&failures, label);
            result = -1;
        }
        group->lock_ready = false;
        group->settled = true;
    }
    git_retirement_transaction_release(transaction);
    *transaction_ptr = NULL;
    if (failures.active) (void)error_accumulator_publish(&failures);
    return result;
}

static int git_retirement_recovery_reprove_transaction(
    git_retirement_transaction_t *transaction) {
    error_accumulator_t failures;
    size_t failure_count = 0U;

    if (git_retirement_transaction_require_creator(
            transaction, "verify") != 0) {
        return -1;
    }
    if (!transaction->recovery_proof_only ||
        transaction->state != GIT_RETIREMENT_TRANSACTION_PUBLISHED) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retained Git retirement recovery proof");
        return -1;
    }
    error_accumulator_init(&failures);
    for (size_t i = 0U; i < transaction->group_count; i++) {
        git_retirement_group_t *group = &transaction->groups[i];
        git_scope_snapshot_t current;
        const publication_record_t *representative;
        char context[128];
        char label[160];
        bool group_valid = true;

        memset(&current, 0, sizeof(current));
        if (!group->prepared || !group->stale_generation ||
            group->planned != 0U || !group->lock_ready ||
            group->settled || group->lock.dir_fd < 0 ||
            group->representative >= transaction->item_count) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Retirement recovery lost its canonical Git destination proof");
            group_valid = false;
            goto group_done;
        }
        representative =
            transaction->publication_refs[group->representative];
        if (!git_file_at_matches_witness(
                group->lock.dir_fd, group->lock.leaf,
                group->lock.original_fd, &group->lock.original_stat,
                group->lock.original_data, group->lock.original_length,
                NULL)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Retirement recovery Git destination changed while its canonical lock was held");
            group_valid = false;
            goto group_done;
        }
        (void)snprintf(
            context, sizeof(context),
            "Could not re-read retirement recovery destination %zu",
            group->representative + 1U);
        if (git_capture_file_snapshot(
                group->lock.path, context, &current) != 0) {
            group_valid = false;
            goto group_done;
        }
        if (!git_retirement_stale_snapshot_is_clean(
                group, &current, transaction->publication_refs,
                transaction->item_count)) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Retirement recovery destination contains a reintroduced attributed Git value");
            group_valid = false;
            goto group_done;
        }
        for (size_t j = 0U; j < transaction->item_count; j++) {
            if (publication_record_same_config_destination(
                    representative, transaction->publication_refs[j]) &&
                git_retirement_verify_live_namespace(
                    transaction->publication_refs[j]) != 0) {
                group_valid = false;
                goto group_done;
            }
        }
        if (fsync(group->lock.dir_fd) != 0 ||
            !git_file_at_matches_witness(
                group->lock.dir_fd, group->lock.leaf,
                group->lock.original_fd, &group->lock.original_stat,
                group->lock.original_data, group->lock.original_length,
                NULL)) {
            errno = errno ? errno : EAGAIN;
            set_system_error(
                ERR_GIT_CONFIG_FAILED,
                "Retirement recovery Git destination did not remain stable under its canonical lock");
            group_valid = false;
            goto group_done;
        }
        /* Repository/config-parent ownership is not represented by the file
         * witness above. Re-prove it at the last retained-handle boundary as
         * well, so a moved/replaced namespace cannot inherit a clean config
         * proof. */
        for (size_t j = 0U; j < transaction->item_count; j++) {
            if (publication_record_same_config_destination(
                    representative, transaction->publication_refs[j]) &&
                git_retirement_verify_live_namespace(
                    transaction->publication_refs[j]) != 0) {
                group_valid = false;
                goto group_done;
            }
        }

group_done:
        git_scope_snapshot_clear(&current);
        if (!group_valid) {
            (void)snprintf(
                label, sizeof(label),
                "destination %zu retained recovery proof (%s)",
                group->representative + 1U,
                git_scope_diagnostic_label(group->scope));
            (void)error_accumulator_add_last(&failures, label);
            failure_count++;
        }
    }
    if (failure_count != 0U) {
        error_context_t summary;

        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Git retirement recovery could not prove %zu destination(s) clean and stable",
            failure_count);
        summary = *get_last_error();
        (void)error_accumulator_add(
            &failures, "retirement recovery summary", &summary);
        (void)error_accumulator_publish(&failures);
        return -1;
    }
    clear_error();
    return 0;
}

int git_retirement_recovery_begin(
    const publication_record_t *const publications[],
    size_t publication_count, git_retirement_recovery_t **recovery_ptr) {
    git_retirement_recovery_t *recovery = NULL;
    git_retirement_transaction_t *transaction = NULL;
    account_t *accounts = NULL;
    const account_t **account_refs = NULL;
    error_accumulator_t failures;
    int result = -1;

    if (recovery_ptr) *recovery_ptr = NULL;
    if (!recovery_ptr || !publications || publication_count == 0U ||
        publication_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git retirement recovery request");
        return -1;
    }
    accounts = calloc(publication_count, sizeof(*accounts));
    account_refs = calloc(publication_count, sizeof(*account_refs));
    recovery = calloc(1U, sizeof(*recovery));
    if (!accounts || !account_refs || !recovery) {
        errno = ENOMEM;
        set_error(ERR_MEMORY_ALLOCATION,
                  "Out of memory preparing Git retirement recovery");
        goto done;
    }
    for (size_t i = 0U; i < publication_count; i++) {
        int written;

        if (!publications[i]) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "NULL record in Git retirement recovery set");
            goto done;
        }
        accounts[i].id = publications[i]->account_id;
        accounts[i].incarnation_persisted = true;
        if (safe_strncpy(
                accounts[i].incarnation,
                publications[i]->account_incarnation,
                sizeof(accounts[i].incarnation)) != 0) {
            goto done;
        }
        written = snprintf( /* Flawfinder: ignore — bounded destination and
                             * compile-time PRI format. */
            accounts[i].name, sizeof(accounts[i].name),
            "retiring account %" PRIu32, publications[i]->account_id);
        if (written < 0 ||
            (size_t)written >= sizeof(accounts[i].name)) {
            errno = EOVERFLOW;
            set_error(ERR_INVALID_ARGS,
                      "Retiring account diagnostic identity is too large");
            goto done;
        }
        account_refs[i] = &accounts[i];
    }
    if (git_retirement_transaction_prepare_internal(
            account_refs, publications, publication_count, false,
            PUBLICATION_STATE_RETIRING, true, &transaction) != 0) {
        goto done;
    }
    if (git_retirement_transaction_publish(transaction, NULL) != 0) {
        error_context_t proof_error = *get_last_error();
        int proof_errno = errno ? errno : EIO;

        error_accumulator_init(&failures);
        errno = proof_errno;
        (void)error_accumulator_add(
            &failures, "retirement recovery preparation", &proof_error);
        if (git_retirement_transaction_commit(&transaction) != 0) {
            (void)error_accumulator_add_last(
                &failures, "retirement recovery preparation cleanup");
        }
        (void)error_accumulator_publish(&failures);
        goto done;
    }
    recovery->transaction = transaction;
    transaction = NULL;
    if (git_retirement_recovery_reprove_transaction(
            recovery->transaction) != 0) {
        error_context_t proof_error = *get_last_error();
        int proof_errno = errno ? errno : EIO;

        error_accumulator_init(&failures);
        errno = proof_errno;
        (void)error_accumulator_add(
            &failures, "retirement recovery retained proof", &proof_error);
        if (git_retirement_transaction_commit(
                &recovery->transaction) != 0) {
            (void)error_accumulator_add_last(
                &failures, "retirement recovery proof cleanup");
        }
        (void)error_accumulator_publish(&failures);
        goto done;
    }
    *recovery_ptr = recovery;
    recovery = NULL;
    result = 0;

done:
    if (transaction) {
        (void)git_retirement_transaction_commit(&transaction);
    }
    if (accounts) {
        secure_zero_memory(accounts,
                           publication_count * sizeof(*accounts));
        free(accounts);
    }
    free(account_refs);
    if (recovery) {
        secure_zero_memory(recovery, sizeof(*recovery));
        free(recovery);
    }
    return result;
}

int git_retirement_recovery_verify(
    git_retirement_recovery_t *recovery) {
    if (!recovery || !recovery->transaction) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid Git retirement recovery verification");
        return -1;
    }
    return git_retirement_recovery_reprove_transaction(
        recovery->transaction);
}

int git_retirement_recovery_prepare_terminal(
    git_retirement_recovery_t *recovery) {
    if (!recovery || !recovery->transaction) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid terminal Git retirement recovery preparation");
        return -1;
    }
    return git_retirement_transaction_prepare_terminal_clean(
        recovery->transaction, GIT_RETIREMENT_TERMINAL_RECOVERY);
}

int git_retirement_recovery_verify_terminal(
    git_retirement_recovery_t *recovery) {
    if (!recovery || !recovery->transaction) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid terminal Git retirement recovery verification");
        return -1;
    }
    /* Preserve the existing final-proof checkpoint for ordering/fault
     * coverage when callers adopt the terminal prepare/verify/finish split.
     * This hook runs before the read-only proof and cannot mutate authority. */
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF,
            NULL, NULL, NULL)) {
        errno = EIO;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git retirement recovery final proof failure");
        return -1;
    }
    return git_retirement_transaction_verify_terminal_clean(
        recovery->transaction, GIT_RETIREMENT_TERMINAL_RECOVERY);
}

int git_retirement_recovery_finish_terminal(
    git_retirement_recovery_t **recovery_ptr) {
    git_retirement_recovery_t *recovery;
    int result;

    if (!recovery_ptr || !*recovery_ptr ||
        !(*recovery_ptr)->transaction) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Missing terminal Git retirement recovery");
        return -1;
    }
    recovery = *recovery_ptr;
    result = git_retirement_transaction_finish_terminal(
        &recovery->transaction, GIT_RETIREMENT_TERMINAL_RECOVERY,
        "recovery");
    if (!recovery->transaction) {
        secure_zero_memory(recovery, sizeof(*recovery));
        free(recovery);
        *recovery_ptr = NULL;
    }
    return result;
}

int git_retirement_recovery_end(
    git_retirement_recovery_t **recovery_ptr) {
    git_retirement_recovery_t *recovery;
    error_accumulator_t failures;
    int result = 0;

    if (!recovery_ptr || !*recovery_ptr) return 0;
    recovery = *recovery_ptr;
    if (!recovery->transaction ||
        recovery->transaction->creator_pid != getpid()) {
        if (recovery->transaction) {
            git_retirement_transaction_release_mode(
                recovery->transaction, true);
            recovery->transaction = NULL;
        }
        secure_zero_memory(recovery, sizeof(*recovery));
        free(recovery);
        *recovery_ptr = NULL;
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot end a Git retirement recovery capability inherited by a different process");
        return -1;
    }
    if (recovery->transaction->terminal_release_only) {
        /* A guard failure after terminal preparation must not trigger the
         * legacy final proof or remove any retained marker. Generic commit is
         * the descriptor-only abandon path for this sticky state. */
        if (recovery->transaction->terminal_kind !=
            GIT_RETIREMENT_TERMINAL_RECOVERY) {
            errno = EINVAL;
            set_error(
                ERR_INVALID_ARGS,
                "Invalid terminal Git retirement recovery disposal");
            return -1;
        }
        result = git_retirement_transaction_commit(
            &recovery->transaction);
        secure_zero_memory(recovery, sizeof(*recovery));
        free(recovery);
        *recovery_ptr = NULL;
        return result;
    }
    error_accumulator_init(&failures);
    if (g_retirement_test_hook &&
        g_retirement_test_hook(
            GIT_RETIREMENT_TEST_RECOVERY_END_BEFORE_FINAL_PROOF,
            NULL, NULL, NULL)) {
        errno = EIO;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Injected Git retirement recovery final proof failure");
        (void)error_accumulator_add_last(
            &failures, "retirement recovery final proof");
        result = -1;
    } else if (git_retirement_recovery_verify(recovery) != 0) {
        (void)error_accumulator_add_last(
            &failures, "retirement recovery final proof");
        result = -1;
    }
    if (git_retirement_transaction_commit(
            &recovery->transaction) != 0) {
        (void)error_accumulator_add_last(
            &failures, "retirement recovery release");
        result = -1;
    }
    secure_zero_memory(recovery, sizeof(*recovery));
    free(recovery);
    *recovery_ptr = NULL;
    if (failures.active) (void)error_accumulator_publish(&failures);
    return result;
}

int git_retire_account_identity_published(
    const account_t *account, const publication_record_t *publication,
    size_t *cleared) {
    const publication_record_t *records[1] = {publication};

    return git_retire_account_identity_publications(account, records, 1U,
                                                    cleared);
}

int git_retire_account_identity_publications(
    const account_t *account,
    const publication_record_t *const publications[],
    size_t publication_count, size_t *cleared) {
    const account_t *accounts[PUBLICATION_LEDGER_MAX_RECORDS];
    git_retirement_transaction_t *transaction = NULL;
    size_t published_cleared = 0U;
    int publish_result;
    int commit_result;

    if (cleared) *cleared = 0U;
    if (!account || !publications || publication_count == 0U ||
        publication_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid durable Git publication retirement set");
        return -1;
    }
    for (size_t i = 0U; i < publication_count; i++) {
        accounts[i] = account;
    }
    if (git_retirement_transaction_prepare_internal(
            accounts, publications, publication_count, true,
            PUBLICATION_STATE_PUBLISHED, false,
            &transaction) != 0) {
        return -1;
    }
    publish_result = git_retirement_transaction_publish(
        transaction, &published_cleared);
    commit_result = git_retirement_transaction_commit(&transaction);
    if (publish_result != 0) {
        if (cleared) *cleared = published_cleared;
        return -1;
    }
    if (commit_result != 0) return -1;
    if (cleared) *cleared = published_cleared;
    return 0;
}

/* AR-06 F59: git_validate_repository() and git_get_config_scope() were removed
 * here — both were public API with zero callers anywhere in the tree (dead
 * code, and git_get_config_scope's system-scope arm implied a scope model the
 * rest of git_ops does not use). */

static int git_test_config_impl(
    const account_t *account, git_scope_t scope,
    const char *expected_gpg_program,
    const run_launch_witness_t *expected_gpg_witness,
    bool require_gpg_witness) {
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
        if (require_gpg_witness &&
            (!expected_gpg_witness ||
             !run_launch_witness_matches(expected_gpg_witness,
                                         expected_gpg_witness) ||
             strcmp(expected_gpg_witness->executable_path,
                    expected_gpg_program) != 0)) {
            set_error(
                ERR_INVALID_ARGS,
                "GPG-enabled Git validation requires the matching bound OpenPGP launch witness");
            return -1;
        }
    } else if (expected_gpg_program && expected_gpg_program[0] != '\0') {
        set_error(ERR_INVALID_ARGS,
                  "Git validation received a GPG program for an account without GPG");
        return -1;
    } else if (expected_gpg_witness) {
        set_error(
            ERR_INVALID_ARGS,
            "Git validation received a GPG launch witness for an account without GPG");
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
     * that is already the account's isolated home. A selector-only process
     * memo cannot prove this executable/home context, so this deliberately
     * remains an independent raw sanity probe. */
    if (gpg_expected) {
        const char *const gpg_unset_env[] = {
            "GPG_AGENT_INFO",
            "GNUPG_BUILDDIR",
            "GNUPG_BUILD_ROOT",
            NULL
        };
        const char *gpg_argv[] = {
            expected_gpg_program, "--list-secret-keys",
            account->gpg_key_id, NULL
        };
        run_opts_t gpg_opts;
        run_result_t gpg_result;
        int run_result;
        memset(&gpg_opts, 0, sizeof(gpg_opts));
        memset(&gpg_result, 0, sizeof(gpg_result));
        gpg_result.exit_code = -1;
        gpg_opts.stderr_to_devnull = true;
        gpg_opts.unset_env = gpg_unset_env;
        if (require_gpg_witness) {
            run_result = run_argv_with_expected_launch(
                gpg_argv, &gpg_opts, expected_gpg_witness, &gpg_result);
        } else {
            /* Preserve the public API's established custom-runner contract:
             * run_argv's return value is authoritative when no transaction
             * witness was requested. */
            run_result = run_argv(gpg_argv, &gpg_opts, NULL);
        }
        if (require_gpg_witness && run_result != 0) {
            /* The bound runner already classified a pre-spawn trust or
             * generation failure. Preserve that causal diagnostic instead of
             * misreporting executable replacement as an absent key. */
            return -1;
        }
        if (run_result != 0 ||
            (require_gpg_witness &&
             (!gpg_result.spawned || gpg_result.exit_code != 0 ||
              gpg_result.term_signal != 0))) {
            set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available: %s",
                      account->gpg_key_id);
            return -1;
        }
    }

    log_info("Git configuration test passed for %s", account->name);
    return 0;
}

/* Validate the account model Git will actually consume. The public entry point
 * retains its established path-only contract for compatibility; switch
 * transactions call the internal witness-bound entry point below. */
int git_test_config(const account_t *account, git_scope_t scope,
                    const char *expected_gpg_program) {
    return git_test_config_impl(account, scope, expected_gpg_program, NULL,
                                false);
}

int git_test_config_with_gpg_witness(
    const account_t *account, git_scope_t scope,
    const char *expected_gpg_program,
    const run_launch_witness_t *expected_gpg_witness) {
    return git_test_config_impl(
        account, scope, expected_gpg_program, expected_gpg_witness, true);
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
    char output[256] = "";
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

    {
        int write_result = git_run(
            output, sizeof(output), "config", scope_flag, key, value,
            (const char *)NULL);
        int recovery_result = 0;
        int recovery_errno = 0;

        if (write_result != 0) {
            recovery_result =
                git_recover_scope_finalization_marker(scope);
            if (recovery_result < 0) {
                recovery_errno = errno ? errno : EIO;
            }
            if (recovery_result == 1) {
                output[0] = '\0';
                write_result = git_run(
                    output, sizeof(output), "config", scope_flag, key, value,
                    (const char *)NULL);
            }
        }
        if (write_result == 0) {
            git_transaction_commit_vector(&post_update);
            cfg_cache_store(s, k, CFG_WRITTEN, true, value);
            return 0;
        }
        git_transaction_discard_vector(&post_update);
        /* The key's on-disk state is now uncertain; never skip/serve it. */
        cfg_cache_store(s, k, CFG_UNKNOWN, false, "");
        if (recovery_result < 0) {
            errno = recovery_errno;
            return -1;
        }
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Failed to set git config %s: %s", key,
                  output[0] != '\0'
                      ? output
                      : "git produced no diagnostic output");
        return -1;
    }
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
        {
            int recovery_result = 0;
            int recovery_errno = 0;

            if (res.exit_code != 0 && res.exit_code != 5) {
                recovery_result =
                    git_recover_scope_finalization_marker(scope);
                if (recovery_result < 0) {
                    recovery_errno = errno ? errno : EIO;
                }
                if (recovery_result == 1) {
                    memset(&res, 0, sizeof(res));
                    output[0] = '\0';
                    run_argv(argv, &opts, &res);
                }
            }

            /* exit 0 = removed; exit 5 with --unset-all = the key did not
             * exist. Both prove the key is now absent, so caching
             * CFG_WRITTEN/absent is correct and lets a later duplicate unset
             * be elided (AR-02 #15). Any OTHER status (git error, or
             * death-by-signal -> exit_code -1) means the unset may NOT have
             * happened: record CFG_UNKNOWN so a later corrective unset in
             * this process is not wrongly elided (AR-06 F03 cache poisoning),
             * and surface the failure to the caller. */
            if (res.exit_code == 0 || res.exit_code == 5) {
                cfg_cache_store(s, k, CFG_WRITTEN, false, "");
                if (!force) {
                    return git_transaction_record_vector(
                        scope, key, false, "");
                }
                return 0;
            }
            cfg_cache_store(s, k, CFG_UNKNOWN, true, "");
            if (recovery_result < 0) {
                errno = recovery_errno;
                return -1;
            }
        }
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

/* is_safe_ssh_key_path is the conservative admission gate for this
 * shell-interpreted core.sshCommand sink. The ~/.ssh/config IdentityFile sink
 * has a separate OpenSSH-grammar-aware serializer because its safely
 * representable character set differs. */

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

    /* Apply this sink's conservative quote/control gate before touching the
     * filesystem. IdentityFile uses a separate grammar-specific serializer. */
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
