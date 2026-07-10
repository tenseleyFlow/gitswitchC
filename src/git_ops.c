/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "git_ops.h"
#include "error.h"
#include "utils.h"
#include "display.h"

/* Internal helper functions */
static int git_run(char *output, size_t output_size, ...);
static int validate_git_installation(void);
static bool is_valid_git_config_value(const char *value);

/* Snapshot/restore of gitswitch-managed git config keys, for switch rollback. */
typedef struct {
    const char *key;
    char value[512];
    bool present;
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

/* Extract the value of a lowercased key from `git config --list` output
 * (lines of the form "key=value"). Returns the LAST occurrence, matching git's
 * last-wins resolution. Returns true and fills out[] if found. */
/* Parse a value out of `git config --list -z` output. The listing is a series
 * of NUL-terminated records, each "key\nvalue" (the value itself may contain
 * newlines — that's the whole point of -z over plain --list, which would let a
 * value's embedded newline masquerade as a record boundary and truncate the
 * snapshot). `buf`/`len` are binary (the buffer holds embedded NULs), so we
 * work by length rather than strlen. Last match wins. */
static bool parse_config_z_value(const char *buf, size_t len, const char *key,
                                 char *out, size_t out_size) {
    size_t key_len = strlen(key);
    bool found = false;
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
                found = true; /* keep scanning: last wins */
            }
        }
    }
    return found;
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
        for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
            if (parse_config_z_value(list, list_len, g_managed_keys[i],
                                     out[i].value, sizeof(out[i].value))) {
                out[i].present = true;
            }
        }
        return;
    }

    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
        if (git_get_config_value(g_managed_keys[i], out[i].value, sizeof(out[i].value), scope) == 0) {
            out[i].present = true;
        } else {
            out[i].present = false;
            out[i].value[0] = '\0';
        }
    }
}

static void git_restore_keys(git_scope_t scope, const git_kv_t in[GIT_MANAGED_KEY_COUNT]) {
    for (size_t i = 0; i < GIT_MANAGED_KEY_COUNT; i++) {
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
    if (git_run(output, sizeof(output), "rev-parse", "--is-bare-repository", NULL) == 0) {
        trim_whitespace(output);
        if (strcmp(output, "true") == 0) {
            set_error(ERR_GIT_REPOSITORY_INVALID, "Repository is bare");
            return -1;
        }
    }
    
    /* Check repository health - verify we can read HEAD */
    if (git_run(output, sizeof(output), "rev-parse", "--verify", "HEAD", NULL) != 0) {
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

        /* Test GPG key availability (system keyring, no shell) */
        const char *gpg_argv[] = {"gpg", "--list-secret-keys", account->gpg_key_id, NULL};
        run_opts_t gpg_opts;
        memset(&gpg_opts, 0, sizeof(gpg_opts));
        gpg_opts.stderr_to_devnull = true;
        if (run_argv(gpg_argv, &gpg_opts, NULL) != 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available: %s", account->gpg_key_id);
            return -1;
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

    log_debug("Setting git config: %s = %s (%s)", key, value, scope_flag);

    if (git_run(output, sizeof(output), "config", scope_flag, key, value, NULL) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git config %s: %s", key, output);
        return -1;
    }

    return 0;
}

/* Get single git configuration value */
int git_get_config_value(const char *key, char *value, size_t value_size, git_scope_t scope) {
    char output[512];
    const char *scope_flag;
    
    if (!key || !value || value_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_get_config_value");
        return -1;
    }
    
    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }
    
    if (git_run(output, sizeof(output), "config", scope_flag, key, NULL) != 0) {
        /* Config value not found - this is not always an error */
        value[0] = '\0';
        return -1;
    }
    
    /* Remove trailing newline */
    trim_whitespace(output);
    /* safe_strncpy writes nothing and returns -1 when the value is too long for
     * the caller's buffer. Propagate that as failure (and NUL the buffer) so
     * callers can't read an uninitialized stack buffer while we report success. */
    if (safe_strncpy(value, output, value_size) != 0) {
        value[0] = '\0';
        return -1;
    }

    return 0;
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

    log_debug("Unsetting git config: %s (%s)", key, scope_flag);

    /* Ignore errors as the key might not exist */
    git_run(output, sizeof(output), "config", scope_flag, "--unset", key, NULL);

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

    if (git_run(output, output_size, "config", scope_flag, "--list", NULL) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to list git configuration");
        return -1;
    }

    return 0;
}

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
    
    /* Verify SSH key file exists and has correct permissions */
    if (!path_exists(expanded_key_path)) {
        set_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s", expanded_key_path);
        return -1;
    }

    /* core.sshCommand is the one value git executes through /bin/sh, so the
     * key path below is wrapped in single quotes. Inside '...' the shell
     * treats every byte literally EXCEPT a single quote, which ends the quote
     * and would let a crafted path inject extra ssh options (e.g.
     * -oProxyCommand=…, i.e. arbitrary code on the next fetch). Reject a path
     * containing a single quote (or a control char/newline) so the quoting
     * cannot be broken. A real SSH key path never needs these. */
    if (strpbrk(expanded_key_path, "'\n\r") != NULL) {
        set_error(ERR_INVALID_PATH,
                  "SSH key path contains an illegal character (quote/newline): %s",
                  expanded_key_path);
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

/* Check if current directory is a git repository */
bool git_is_repository(void) {
    char output[256];
    
    /* Use git rev-parse --git-dir to check for repository */
    if (git_run(output, sizeof(output), "rev-parse", "--git-dir", NULL) == 0) {
        return true;
    }
    
    return false;
}

/* Get repository root directory */
int git_get_repo_root(char *path, size_t path_size) {
    char output[MAX_PATH_LEN];
    
    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to git_get_repo_root");
        return -1;
    }
    
    if (git_run(output, sizeof(output), "rev-parse", "--show-toplevel", NULL) != 0) {
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

/* Validate git installation */
static int validate_git_installation(void) {
    char version_output[256];
    
    /* Check if git is available */
    if (!command_exists("git")) {
        set_error(ERR_SYSTEM_REQUIREMENT, "Git is not installed or not in PATH");
        return -1;
    }
    
    /* Get git version */
    if (git_run(version_output, sizeof(version_output), "--version", NULL) != 0) {
        set_error(ERR_SYSTEM_REQUIREMENT, "Failed to get git version");
        return -1;
    }
    
    log_debug("Git version: %s", version_output);
    
    /* Basic version check - require git 2.0+ */
    if (!strstr(version_output, "git version ")) {
        set_error(ERR_SYSTEM_REQUIREMENT, "Unexpected git version output");
        return -1;
    }
    
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

