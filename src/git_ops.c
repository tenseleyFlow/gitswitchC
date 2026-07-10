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
        if (!nl) continue; /* no key/value separator — skip */
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

static void git_capture_keys(git_scope_t scope, git_kv_t out[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        out[i].key = g_managed_keys[i];
        out[i].present = false;
        out[i].value_unknown = false;
        out[i].value[0] = '\0';
    }

    /* Fast path: one `git config --list -z` exec instead of one per key. Fall
     * back to per-key reads if the listing failed or looks truncated (buffer
     * full) — a truncated list could miss a pre-existing value and corrupt the
     * rollback snapshot, so correctness wins over the extra execs. */
    char list[16384];
    size_t list_len = 0;
    if (git_list_config_z(scope, list, sizeof(list), &list_len) == 0 &&
        list_len < sizeof(list) - 1) {
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
        return;
    }

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        bool too_long = false;
        if (git_get_config_value_ex(g_managed_keys[i], out[i].value,
                                    sizeof(out[i].value), scope,
                                    &too_long) == 0) {
            out[i].present = true;
        } else if (too_long) {
            /* Same degradation as the -z path: present, value unknown. The
             * pre-fix code never asked, so a truncated per-key read was
             * snapshotted absent (or worse, a silently truncated value was
             * stored present and written back on rollback — AR-03 M1). */
            out[i].present = true;
            out[i].value_unknown = true;
            out[i].value[0] = '\0';
        } else {
            out[i].present = false;
            out[i].value[0] = '\0';
        }
    }
}

static void git_restore_keys(git_scope_t scope, const git_kv_t in[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (in[i].value_unknown) {
            /* Present before the switch but too long to snapshot: writing
             * value[] back would install a truncated corruption and --unset
             * would destroy the user's original — leaving whatever is there
             * now is the only non-destructive option, so say so instead of
             * silently pretending the rollback was complete (AR-03 M1). */
            log_warning("Not restoring %s: pre-switch value was too long to snapshot",
                        in[i].key);
            continue;
        }
        if (in[i].present) {
            git_set_config_value(in[i].key, in[i].value, scope);
        } else {
            git_unset_config_value(in[i].key, scope);
        }
    }
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
    if (!g_git_snapshot.valid) {
        return 0;
    }
    log_info("Rolling back git configuration after a failed switch");
    /* Restore local first (it was cleared earliest), then the primary scope. */
    if (g_git_snapshot.local_also) {
        git_restore_keys(GIT_SCOPE_LOCAL, g_git_snapshot.local);
    }
    git_restore_keys(g_git_snapshot.scope, g_git_snapshot.primary);
    g_git_snapshot.valid = false;
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
        /* Disable GPG signing */
        git_unset_config_value(GIT_CONFIG_USER_SIGNINGKEY, scope);
        git_set_config_value(GIT_CONFIG_COMMIT_GPGSIGN, "false", scope);
    }
    
    /* Configure SSH if enabled */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (git_configure_ssh(account, scope) != 0) {
            log_warning("Failed to configure SSH for git");
            /* Don't fail completely, SSH config is optional */
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
int git_get_current_config(git_current_config_t *config) {
    char name[MAX_NAME_LEN] = {0};
    char email[MAX_EMAIL_LEN] = {0};
    char signing_key[MAX_KEY_ID_LEN] = {0};
    char gpg_sign[16] = {0};
    
    if (!config) {
        set_error(ERR_INVALID_ARGS, "NULL config to git_get_current_config");
        return -1;
    }
    
    /* Initialize structure */
    memset(config, 0, sizeof(git_current_config_t));
    config->valid = false;
    
    /* Try to get user.name */
    if (git_get_config_value(GIT_CONFIG_USER_NAME, name, sizeof(name), GIT_SCOPE_LOCAL) == 0) {
        config->scope = GIT_SCOPE_LOCAL;
    } else if (git_get_config_value(GIT_CONFIG_USER_NAME, name, sizeof(name), GIT_SCOPE_GLOBAL) == 0) {
        config->scope = GIT_SCOPE_GLOBAL;
    } else if (git_get_config_value(GIT_CONFIG_USER_NAME, name, sizeof(name), GIT_SCOPE_SYSTEM) == 0) {
        config->scope = GIT_SCOPE_SYSTEM;
    } else {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.name configured");
        return -1;
    }
    
    /* Get user.email from same scope */
    if (git_get_config_value(GIT_CONFIG_USER_EMAIL, email, sizeof(email), config->scope) != 0) {
        set_error(ERR_GIT_CONFIG_NOT_FOUND, "No git user.email configured");
        return -1;
    }
    
    /* Copy basic configuration */
    safe_strncpy(config->name, name, sizeof(config->name));
    safe_strncpy(config->email, email, sizeof(config->email));
    
    /* Get GPG configuration if available */
    if (git_get_config_value(GIT_CONFIG_USER_SIGNINGKEY, signing_key, sizeof(signing_key), config->scope) == 0) {
        safe_strncpy(config->signing_key, signing_key, sizeof(config->signing_key));
    }
    
    /* Check if GPG signing is enabled */
    if (git_get_config_value(GIT_CONFIG_COMMIT_GPGSIGN, gpg_sign, sizeof(gpg_sign), config->scope) == 0) {
        config->gpg_signing_enabled = (strcmp(gpg_sign, "true") == 0);
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

/* Validate git repository */
int git_validate_repository(void) {
    char output[256];
    
    if (!git_is_repository()) {
        set_error(ERR_GIT_NOT_REPOSITORY, "Current directory is not a git repository");
        return -1;
    }
    
    /* Check if repository is bare */
    if (git_run(output, sizeof(output), "rev-parse", "--is-bare-repository",
                (const char *)NULL) == 0) {
        trim_whitespace(output);
        if (strcmp(output, "true") == 0) {
            set_error(ERR_GIT_REPOSITORY_INVALID, "Repository is bare");
            return -1;
        }
    }
    
    /* Check repository health - verify we can read HEAD */
    if (git_run(output, sizeof(output), "rev-parse", "--verify", "HEAD",
                (const char *)NULL) != 0) {
        /* This is OK for new repositories with no commits */
        log_debug("Repository has no commits yet (new repository)");
    }
    
    return 0;
}

/* Get git configuration scope */
git_scope_t git_get_config_scope(const char *config_key) {
    char value[512];
    
    if (!config_key) {
        return GIT_SCOPE_GLOBAL; /* Default fallback */
    }
    
    /* Try local scope first if we're in a repository */
    if (git_is_repository()) {
        if (git_get_config_value(config_key, value, sizeof(value), GIT_SCOPE_LOCAL) == 0) {
            return GIT_SCOPE_LOCAL;
        }
    }
    
    /* Try global scope */
    if (git_get_config_value(config_key, value, sizeof(value), GIT_SCOPE_GLOBAL) == 0) {
        return GIT_SCOPE_GLOBAL;
    }
    
    /* Try system scope */
    if (git_get_config_value(config_key, value, sizeof(value), GIT_SCOPE_SYSTEM) == 0) {
        return GIT_SCOPE_SYSTEM;
    }
    
    /* Default to global if not found */
    return GIT_SCOPE_GLOBAL;
}

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
int git_set_config_value(const char *key, const char *value, git_scope_t scope) {
    char output[256];
    const char *scope_flag;

    if (!key || !value) {
        set_error(ERR_INVALID_ARGS, "NULL key or value to git_set_config_value");
        return -1;
    }

    /* Belt-and-suspenders only: argv execution means the value is never parsed
     * by a shell, so this is no longer the security boundary. */
    if (!is_valid_git_config_value(value)) {
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
        /* Config value not found - this is not always an error */
        value[0] = '\0';
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

    /* Remove trailing newline */
    trim_whitespace(output);
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

    /* Ignore errors as the key might not exist */
    git_run(output, sizeof(output), "config", scope_flag, "--unset", key,
            (const char *)NULL);

    /* Unset is best-effort by contract (errors ignored above), so "absent" is
     * the strongest post-state we can record either way. */
    cfg_cache_store(s, k, CFG_WRITTEN, false, "");

    return 0;
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
