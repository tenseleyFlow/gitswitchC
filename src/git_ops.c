/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
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
static int git_get_config_value_ex(const char *key, char *value,
                                   size_t value_size, git_scope_t scope,
                                   bool *value_too_long);

/* Snapshot/restore of gitswitch-managed git config keys, for switch rollback. */

/* Value capacity for the snapshot and the exec cache below. Sized for the
 * largest value gitswitch itself writes: git_configure_ssh's core.sshCommand
 * is ~85 bytes of fixed ssh options plus a single-quoted key path of up to
 * MAX_PATH_LEN. The old 512-byte cap could not hold gitswitch's OWN value for
 * a long key path, and the drop was then recorded as "proven absent" — the
 * AR-03 M1 bug. Stack note: the two aggregates using this are file-scope
 * statics (.bss, ~127 KB total), not stack; the one per-call buffer this size
 * is git_get_config_value_ex's capture (~4 KB frame at shallow depth). */
#define GIT_CFG_VALUE_MAX (MAX_PATH_LEN + 128)

typedef struct {
    const char *key;
    char value[GIT_CFG_VALUE_MAX];
    bool present;
    bool value_unknown; /* present, but the value exceeded value[] (a foreign
                         * writer): restore must neither write back a
                         * truncated copy nor --unset the user's original. */
} git_kv_t;

#define GIT_MANAGED_KEY_COUNT 6
static const char *const g_managed_keys[GIT_MANAGED_KEY_COUNT] = {
    GIT_CONFIG_USER_NAME, GIT_CONFIG_USER_EMAIL, GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN, GIT_CONFIG_GPG_PROGRAM, GIT_CONFIG_CORE_SSHCOMMAND
};

static struct {
    git_scope_t scope;
    bool local_also;
    git_kv_t primary[GIT_MANAGED_KEY_COUNT];
    git_kv_t local[GIT_MANAGED_KEY_COUNT];
    bool valid;
} g_git_snapshot;

/* ---- Process-scoped exec caches (perf-1..4) ------------------------------
 *
 * A single switch used to spawn the same git subprocesses several times over:
 * `git --version` on every init, `git rev-parse --git-dir` from every caller
 * that asked "am I in a repo?", the post-switch name/email read-back twice
 * (git_set_config's verify and then git_test_config), and the GPG keys
 * written twice (git_configure_gpg and gpg_manager's
 * gpg_configure_git_signing). On the login-shell resume hot path each exec is
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

#define GIT_SCOPE_COUNT 3
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
    memset(g_cfg_cache, 0, sizeof(g_cfg_cache));
    memset(&g_repo_cache, 0, sizeof(g_repo_cache));
    g_git_validated = false;
}

/* Parse a value out of `git config --list -z` output. The listing is a series
 * of NUL-terminated records, each "key\nvalue" (the value itself may contain
 * newlines — that's the whole point of -z over plain --list, which would let a
 * value's embedded newline masquerade as a record boundary and truncate the
 * snapshot). `buf`/`len` are binary (the buffer holds embedded NULs), so we
 * work by length rather than strlen. Last match wins, matching git's own
 * resolution.
 *
 * Tri-state result: found-but-too-long is NOT absent. The pre-fix bool
 * conflated the two, so an overlong (foreign) value was snapshotted and
 * cache-seeded as proven-absent — git_clear_config then elided a real --unset
 * and git_config_restore --unset the user's original value (AR-03 M1). */
typedef enum {
    CFG_Z_ABSENT = 0, /* no record carries the key */
    CFG_Z_FOUND,      /* key found; out[] holds its (last-wins) value */
    CFG_Z_TOO_LONG    /* key PRESENT, but its value cannot fit out[] —
                       * treat as present with an unknown value, never absent */
} cfg_z_result_t;

static cfg_z_result_t parse_config_z_value(const char *buf, size_t len,
                                           const char *key,
                                           char *out, size_t out_size) {
    size_t key_len = strlen(key);
    cfg_z_result_t result = CFG_Z_ABSENT;
    size_t pos = 0;
    while (pos < len) {
        size_t rec_start = pos;
        while (pos < len && buf[pos] != '\0') pos++;
        size_t rec_len = pos - rec_start;
        if (pos < len) pos++; /* step over the record's NUL terminator */

        const char *rec = buf + rec_start;
        const char *nl = memchr(rec, '\n', rec_len);
        if (!nl) {
            /* No key/value separator. `git config --list -z` emits an
             * implicit-boolean key (e.g. `[commit]\n\tgpgsign`, which git
             * defines as true) as "commit.gpgsign\0" with NO newline. Such a
             * key IS present (AR-06 F19); the old blanket skip returned it
             * ABSENT, so git_clear_config elided the --unset and a `true`
             * boolean survived a switch to a non-signing account. Its bare
             * value ("true") cannot be round-tripped by `git config <key>
             * <value>` (writing "" flips --bool semantics to an error), so
             * treat it as present-but-uncapturable — the same value_unknown
             * state CFG_Z_TOO_LONG carries — which makes the caller UNSET it
             * rather than elide. */
            if (rec_len == key_len && memcmp(rec, key, key_len) == 0) {
                out[0] = '\0';
                result = CFG_Z_TOO_LONG;
            }
            continue;
        }
        size_t k_len = (size_t)(nl - rec);
        if (k_len == key_len && memcmp(rec, key, key_len) == 0) {
            const char *val = nl + 1;
            size_t val_len = rec_len - k_len - 1;
            if (val_len < out_size) {
                memcpy(out, val, val_len);
                out[val_len] = '\0';
                result = CFG_Z_FOUND; /* keep scanning: last wins */
            } else {
                /* Clear any earlier occurrence's copy: last wins, and the
                 * winner is uncapturable — a stale earlier value must not
                 * leak out alongside TOO_LONG. */
                out[0] = '\0';
                result = CFG_Z_TOO_LONG;
            }
        }
    }
    return result;
}

/* Run `git config <scope> --list -z`, capturing the NUL-delimited listing into
 * buf and its byte length into *out_len. Returns 0 on success. Kept local (not
 * via git_list_config) so the binary, -z output and its true length stay
 * intact — git_list_config's public contract is a plain C string. */
static int git_list_config_z(git_scope_t scope, char *buf, size_t size, size_t *out_len) {
    const char *scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) return -1;
    const char *argv[] = { "git", "config", scope_flag, "--list", "-z", NULL };
    run_opts_t opts;
    run_result_t res;
    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = buf;
    opts.out_size = size;
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &res) != 0) return -1;
    *out_len = res.out_len;
    return 0;
}

static void git_init_kv(git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        out[i].key = g_managed_keys[i];
        out[i].present = false;
        out[i].value_unknown = false;
        out[i].value[0] = '\0';
    }
}

/* Apply a complete, untruncated `--list -z` capture to the kv array and seed
 * the exec cache from it. Shared by the snapshot path (git_capture_keys) and
 * the status probe (git_probe_keys, AR-05 L14). */
static void git_apply_config_listing(git_scope_t scope, const char *list,
                                     size_t list_len,
                                     git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    int s = cfg_scope_index(scope);
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        cfg_z_result_t zr = parse_config_z_value(list, list_len,
                                                 g_managed_keys[i],
                                                 out[i].value,
                                                 sizeof(out[i].value));
        if (zr == CFG_Z_TOO_LONG) {
            /* The key IS present; only its value is beyond what we can
             * hold (necessarily a foreign writer — everything gitswitch
             * writes fits GIT_CFG_VALUE_MAX). Recording it absent is the
             * AR-03 M1 bug: git_clear_config would elide a real --unset
             * (the foreign SSH identity survives the switch) and the
             * rollback would --unset the user's original value. Degrade
             * to CFG_UNKNOWN/present so nothing is elided or served. */
            out[i].present = true;
            out[i].value_unknown = true;
            cfg_cache_store(s, (int)i, CFG_UNKNOWN, true, "");
            continue;
        }
        out[i].present = (zr == CFG_Z_FOUND);
        /* AR-02 #15: the complete listing is an authoritative read of
         * every managed key — presence AND proven absence — so seed the
         * exec cache instead of discarding it. git_clear_config (run by
         * the very next step of a global switch) then elides the --unset
         * execs this listing just proved were no-ops, and reads of
         * present values are served without a spawn. */
        cfg_cache_store(s, (int)i, CFG_READBACK, out[i].present,
                        out[i].value);
    }
}

/* Per-key snapshot reads, the correctness fallback when a `--list -z` listing
 * failed or was truncated. Factored out (AR-06 F57) so git_probe_keys' truncated
 * branch can reach it WITHOUT re-running git_capture_keys' listing exec (which,
 * being truncated once, is guaranteed to truncate again). */
static void git_capture_keys_per_key(git_scope_t scope,
                                     git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        bool too_long = false;
        if (git_get_config_value_ex(g_managed_keys[i], out[i].value,
                                    sizeof(out[i].value), scope,
                                    &too_long) == 0) {
            out[i].present = true;
        } else if (too_long) {
            /* Present-but-indeterminate: value too long to capture, OR git
             * could not be run cleanly (AR-06 F56). Either way, record it
             * present/value-unknown so rollback leaves it alone instead of
             * --unsetting a value that may exist (AR-03 M1). */
            out[i].present = true;
            out[i].value_unknown = true;
            out[i].value[0] = '\0';
        } else {
            out[i].present = false;
            out[i].value[0] = '\0';
        }
    }
}

static void git_capture_keys(git_scope_t scope, git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    git_init_kv(out);

    /* Fast path: one `git config --list -z` exec instead of one per key. Fall
     * back to per-key reads if the listing failed or looks truncated (buffer
     * full) — a truncated list could miss a pre-existing value and corrupt the
     * rollback snapshot, so correctness wins over the extra execs. */
    char list[16384];
    size_t list_len = 0;
    if (git_list_config_z(scope, list, sizeof(list), &list_len) == 0 &&
        list_len < sizeof(list) - 1) {
        git_apply_config_listing(scope, list, list_len, out);
        return;
    }

    git_capture_keys_per_key(scope, out);
}

/* Status-path probe (AR-05 L14): ONE listing exec per scope, and a FAILED
 * listing simply reports the scope absent. The per-key fallback above exists
 * to protect the rollback snapshot from a truncated listing; for a read-only
 * status probe it turned a scope with no readable config (e.g. --local
 * outside a repo, or no ~/.gitconfig) into six extra guaranteed-miss execs.
 * A truncated listing (data exists but exceeds the buffer) still defers to
 * git_capture_keys for correctness. */
static void git_probe_keys(git_scope_t scope, git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    git_init_kv(out);

    char list[16384];
    size_t list_len = 0;
    if (git_list_config_z(scope, list, sizeof(list), &list_len) != 0) {
        return; /* scope has no readable config: everything stays absent */
    }
    if (list_len >= sizeof(list) - 1) {
        /* Truncated listing: go straight to per-key reads. Calling
         * git_capture_keys here would re-run the identical (still-truncated)
         * listing exec first (AR-06 F57). */
        git_capture_keys_per_key(scope, out);
        return;
    }
    git_apply_config_listing(scope, list, list_len, out);
}

/* Returns the number of managed keys that could NOT be restored (0 = clean
 * rollback). AR-06 F04: the old version discarded every set/unset result, so a
 * rollback that git actually rejected still reported success and left a mixed
 * identity. Values are restored with validation skipped because they came from
 * git's own snapshot. Keys uncapturable at snapshot time count as failures. */
static int git_restore_keys(git_scope_t scope, const git_kv_t in[GIT_MANAGED_KEY_COUNT]) {
    int failures = 0;
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (in[i].value_unknown) {
            /* Present before the switch but too long to snapshot: writing
             * value[] back would install a truncated corruption and --unset
             * would destroy the user's original — leaving whatever is there
             * now is the only non-destructive option, so say so instead of
             * silently pretending the rollback was complete (AR-03 M1). */
            log_warning("Not restoring %s: pre-switch value could not be "
                        "snapshotted (too long, or git config read failed)",
                        in[i].key);
            /* Not counted as a failure: this is the deliberate non-destructive
             * choice (AR-03 M1) — a truncated write-back or a --unset would be
             * worse. F04 targets SWALLOWED git rejections of capturable values,
             * below, not this known-and-warned limitation. */
            continue;
        }
        if (in[i].present) {
            if (git_set_config_value_impl(in[i].key, in[i].value, scope, true) != 0) {
                log_warning("Rollback failed to restore %s: %s",
                            in[i].key, get_last_error()->message);
                failures++;
            }
        } else {
            if (git_unset_config_value(in[i].key, scope) != 0) {
                log_warning("Rollback failed to clear %s: %s",
                            in[i].key, get_last_error()->message);
                failures++;
            }
        }
    }
    return failures;
}

int git_config_snapshot(git_scope_t scope) {
    g_git_snapshot.scope = scope;
    g_git_snapshot.local_also = (scope == GIT_SCOPE_GLOBAL && git_is_repository());
    git_capture_keys(scope, g_git_snapshot.primary);
    if (g_git_snapshot.local_also) {
        git_capture_keys(GIT_SCOPE_LOCAL, g_git_snapshot.local);
    }
    g_git_snapshot.valid = true;
    return 0;
}

int git_config_restore(void) {
    int failures = 0;
    if (!g_git_snapshot.valid) {
        return 0;
    }
    log_info("Rolling back git configuration after a failed switch");
    /* Restore local first (it was cleared earliest), then the primary scope. */
    if (g_git_snapshot.local_also) {
        failures += git_restore_keys(GIT_SCOPE_LOCAL, g_git_snapshot.local);
    }
    failures += git_restore_keys(g_git_snapshot.scope, g_git_snapshot.primary);
    g_git_snapshot.valid = false;
    /* AR-06 F04: an incomplete rollback must not masquerade as clean. Surface
     * it to the user (the switch already failed; this warns their identity may
     * be partially reverted) and report it to the caller. */
    if (failures > 0) {
        fprintf(stderr,
                "gitswitch: [!!] git rollback incomplete — %d config key(s) could "
                "not be restored; check `git config --list` for a mixed identity\n",
                failures);
        return -1;
    }
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

/* Set git configuration for account */
int git_set_config(const account_t *account, git_scope_t scope) {
    const char *scope_flag;
    
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

    /* When setting global scope inside a repo, clear local config so stale
     * values (e.g. signing key from a prior account) don't take precedence */
    if (scope == GIT_SCOPE_GLOBAL && git_is_repository()) {
        log_info("Clearing local git config to prevent stale overrides");
        git_clear_config(GIT_SCOPE_LOCAL);
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
        git_unset_config_value(GIT_CONFIG_CORE_SSHCOMMAND, scope);
    }
    
    /* Verify configuration was set correctly - check the same scope we just
     * wrote to. A failed read-back of a key we just wrote is itself a
     * verification failure: we cannot confirm the identity was applied, which
     * is the whole point of the check. (Previously a failed read-back short-
     * circuited the && and the function returned success unverified.) */
    char verify_name[MAX_NAME_LEN] = {0};
    char verify_email[MAX_EMAIL_LEN] = {0};
    if (git_get_config_value(GIT_CONFIG_USER_NAME, verify_name, sizeof(verify_name), scope) != 0 ||
        git_get_config_value(GIT_CONFIG_USER_EMAIL, verify_email, sizeof(verify_email), scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Could not read back git configuration to verify it");
        return -1;
    }
    if (strcmp(verify_name, account->name) != 0 ||
        strcmp(verify_email, account->email) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Git configuration verification failed");
        return -1;
    }
    
    log_info("Git configuration set successfully for %s", account->name);
    return 0;
}

/* Get current git configuration */
/* Read the EFFECTIVE (merged) config with a single scope-flag-less
 * `git config --list -z` — git resolves per-KEY precedence (local > global >
 * system) internally, so this reports the values a commit would actually use.
 * Read-only status path: does not seed the scope-keyed exec cache. Keys not
 * present stay absent; a too-long value is marked present/value_unknown. */
static void git_read_effective_keys(git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    char list[16384];
    run_opts_t opts;
    run_result_t res;
    const char *argv[] = { "git", "config", "--list", "-z", NULL };

    git_init_kv(out);
    memset(&opts, 0, sizeof(opts));
    memset(&res, 0, sizeof(res));
    opts.out = list;
    opts.out_size = sizeof(list);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &res) != 0 || res.out_truncated) {
        return; /* leave all absent: a truncated/failed read must not lie */
    }
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        cfg_z_result_t zr = parse_config_z_value(list, res.out_len,
                                                 g_managed_keys[i],
                                                 out[i].value, sizeof(out[i].value));
        if (zr == CFG_Z_TOO_LONG) {
            out[i].present = true;
            out[i].value_unknown = true;
        } else {
            out[i].present = (zr == CFG_Z_FOUND);
        }
    }
}

int git_get_current_config(git_current_config_t *config) {
    if (!config) {
        set_error(ERR_INVALID_ARGS, "NULL config to git_get_current_config");
        return -1;
    }

    /* Initialize structure */
    memset(config, 0, sizeof(git_current_config_t));
    config->valid = false;

    /* AR-05 L14: resolve the scope with ONE `git config <scope> --list -z`
     * exec per probed scope (git_capture_keys' fast path) instead of up to
     * three per-key user.name probes plus one exec each for email/
     * signingkey/gpgsign — 4-6 sequential fork+execs per `gitswitch status`,
     * with the guaranteed-miss probes never cached (the exec cache only
     * stores positive observations). The listing also seeds the cache with
     * presence AND proven absence, so any follow-up read spawns nothing.
     * Semantics preserved: a scope counts only when user.name is present
     * with a representable value (a too-long foreign value failed the old
     * per-key read the same way), and email/signingkey/gpgsign come from
     * that same scope. */
    static const git_scope_t probe_order[] = {
        GIT_SCOPE_LOCAL, GIT_SCOPE_GLOBAL, GIT_SCOPE_SYSTEM
    };
    git_kv_t kv[GIT_MANAGED_KEY_COUNT];
    const int k_name = cfg_key_index(GIT_CONFIG_USER_NAME);
    const int k_email = cfg_key_index(GIT_CONFIG_USER_EMAIL);
    const int k_signkey = cfg_key_index(GIT_CONFIG_USER_SIGNINGKEY);
    const int k_gpgsign = cfg_key_index(GIT_CONFIG_COMMIT_GPGSIGN);
    bool found = false;

    if (k_name < 0 || k_email < 0 || k_signkey < 0 || k_gpgsign < 0) {
        set_error(ERR_INVALID_ARGS, "Managed git key set is incomplete");
        return -1;
    }

    for (size_t i = 0; i < sizeof(probe_order) / sizeof(probe_order[0]); i++) {
        /* Outside a repo, --local cannot have config: skip its probe (and
         * the guaranteed listing failure) entirely. rev-parse is cached, and
         * the status path pays it anyway. */
        if (probe_order[i] == GIT_SCOPE_LOCAL && !git_is_repository()) {
            continue;
        }
        git_probe_keys(probe_order[i], kv);
        if (kv[k_name].present && !kv[k_name].value_unknown) {
            config->scope = probe_order[i];
            found = true;
            break;
        }
    }
    if (!found) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.name configured");
        return -1;
    }

    /* Resolve email/signingkey/gpgsign from the EFFECTIVE (merged) config, not
     * from user.name's scope (AR-06 F21). Git resolves each key independently:
     * a repo that overrides only user.email locally would otherwise report the
     * GLOBAL email (with a false "matches account"), and a split where user.name
     * is global but user.email is local reported "No git configuration found".
     * The name scope above stays as the reported Configuration Scope label. */
    git_kv_t eff[GIT_MANAGED_KEY_COUNT];
    git_read_effective_keys(eff);

    if (!eff[k_email].present || eff[k_email].value_unknown) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.email configured");
        return -1;
    }

    /* Prefer the effective name too (identical to the name-scope value in the
     * common case, since the probe order matches git's precedence). */
    if (eff[k_name].present && !eff[k_name].value_unknown) {
        safe_strncpy(config->name, eff[k_name].value, sizeof(config->name));
    } else {
        safe_strncpy(config->name, kv[k_name].value, sizeof(config->name));
    }
    safe_strncpy(config->email, eff[k_email].value, sizeof(config->email));

    if (eff[k_signkey].present && !eff[k_signkey].value_unknown) {
        safe_strncpy(config->signing_key, eff[k_signkey].value,
                     sizeof(config->signing_key));
    }
    if (eff[k_gpgsign].present && !eff[k_gpgsign].value_unknown) {
        config->gpg_signing_enabled = (strcmp(eff[k_gpgsign].value, "true") == 0);
    }

    config->valid = true;
    return 0;
}

/* Clear git configuration */
int git_clear_config(git_scope_t scope) {
    const char *scope_flag;
    
    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }
    
    log_info("Clearing git configuration (%s scope)", scope_flag);
    
    /* Clear basic user configuration */
    git_unset_config_value(GIT_CONFIG_USER_NAME, scope);
    git_unset_config_value(GIT_CONFIG_USER_EMAIL, scope);
    
    /* Clear GPG configuration */
    git_unset_config_value(GIT_CONFIG_USER_SIGNINGKEY, scope);
    git_unset_config_value(GIT_CONFIG_COMMIT_GPGSIGN, scope);
    git_unset_config_value(GIT_CONFIG_GPG_PROGRAM, scope);
    
    /* Clear SSH configuration */
    git_unset_config_value(GIT_CONFIG_CORE_SSHCOMMAND, scope);
    
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
        char signing_key[MAX_KEY_ID_LEN];
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
 * The old gate silently refused to restore them, and because git_restore_keys
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
 * caller's buffer. rc is still -1 either way; *value_too_long lets
 * git_capture_keys tell an uncapturable value apart from a genuinely absent
 * key instead of snapshotting it absent. */
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

/* Unset git configuration value */
int git_unset_config_value(const char *key, git_scope_t scope) {
    char output[256];
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
     * (CFG_READBACK/absent, seeded by git_capture_keys — AR-02 #15: the
     * global-switch clear-local step used to blindly re-exec six unsets the
     * snapshot one exec earlier had just proved unnecessary). */
    int s = cfg_scope_index(scope);
    int k = cfg_key_index(key);
    if (s >= 0 && k >= 0 && !g_cfg_cache[s][k].present &&
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

/* Configure SSH command for git operations */
int git_configure_ssh(const account_t *account, git_scope_t scope) {
    char ssh_command[MAX_PATH_LEN * 2];
    char expanded_key_path[MAX_PATH_LEN];

    if (!account || !account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        return 0; /* Nothing to configure */
    }

    /* Expand SSH key path */
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH, "Failed to expand SSH key path: %s", account->ssh_key_path);
        return -1;
    }

    /* Reject injection-capable characters BEFORE touching the filesystem:
     * whether such a path exists is irrelevant — it must never reach
     * core.sshCommand or an ~/.ssh/config IdentityFile line (see
     * is_safe_ssh_key_path above for the exact break-out routes). */
    if (!is_safe_ssh_key_path(expanded_key_path)) {
        set_error(ERR_INVALID_PATH,
                  "SSH key path contains an illegal character (quote/control): %s",
                  expanded_key_path);
        return -1;
    }

    /* Verify SSH key file exists and has correct permissions */
    if (!path_exists(expanded_key_path)) {
        set_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s", expanded_key_path);
        return -1;
    }

    /* Build SSH command with security options */
    if ((size_t)snprintf(ssh_command, sizeof(ssh_command),
                        "ssh -i '%s' -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR",
                        expanded_key_path) >= sizeof(ssh_command)) {
        set_error(ERR_INVALID_ARGS, "SSH command too long");
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
 * just to strstr the banner. command_exists() is a pure $PATH walk with
 * access(X_OK) — no subprocess — and proves the same thing we act on: an
 * executable git. A pathological non-git `git` binary still fails closed at
 * the first real `git config` invocation (every git_run result is checked).
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
