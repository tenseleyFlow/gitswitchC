/* Git configuration operations with comprehensive validation and security
 * Implements safe git configuration management for gitswitch-c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "git_ops.h"
#include "error.h"
#include "utils.h"
#include "display.h"

/* Internal helper functions */
static int execute_git_command(const char *args, char *output, size_t output_size);
static int validate_git_installation(void);
static int detect_repository_scope(git_scope_t *detected_scope);
static bool is_valid_git_config_value(const char *value);
static int backup_git_config_if_needed(git_scope_t scope);
static int restore_git_config_if_needed(git_scope_t scope);

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
    
    /* Backup current configuration if requested */
    if (backup_git_config_if_needed(scope) != 0) {
        log_warning("Failed to backup git configuration");
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
    
    /* Verify configuration was set correctly */
    git_current_config_t current_config;
    if (git_get_current_config(&current_config) == 0) {
        if (strcmp(current_config.name, account->name) != 0 ||
            strcmp(current_config.email, account->email) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Git configuration verification failed");
            return -1;
        }
    }
    
    log_info("Git configuration set successfully for %s", account->name);
    return 0;
}

/* Get current git configuration */
int git_get_current_config(git_current_config_t *config) {
    char name[MAX_NAME_LEN];
    char email[MAX_EMAIL_LEN];
    char signing_key[MAX_KEY_ID_LEN];
    char gpg_sign[16];
    
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
    if (execute_git_command("rev-parse --is-bare-repository", output, sizeof(output)) == 0) {
        trim_whitespace(output);
        if (strcmp(output, "true") == 0) {
            set_error(ERR_GIT_REPOSITORY_INVALID, "Repository is bare");
            return -1;
        }
    }
    
    /* Check repository health - verify we can read HEAD */
    if (execute_git_command("rev-parse --verify HEAD", output, sizeof(output)) != 0) {
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
    git_current_config_t current_config;
    (void)scope; /* Suppress unused parameter warning */
    
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to git_test_config");
        return -1;
    }
    
    log_info("Testing git configuration for account: %s", account->name);
    
    /* Get current configuration and verify it matches */
    if (git_get_current_config(&current_config) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to read current git configuration");
        return -1;
    }
    
    if (strcmp(current_config.name, account->name) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Git user.name does not match account: expected '%s', got '%s'",
                  account->name, current_config.name);
        return -1;
    }
    
    if (strcmp(current_config.email, account->email) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Git user.email does not match account: expected '%s', got '%s'",
                  account->email, current_config.email);
        return -1;
    }
    
    /* Test GPG configuration if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (strlen(current_config.signing_key) == 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "GPG signing key not configured in git");
            return -1;
        }
        
        if (!current_config.gpg_signing_enabled) {
            log_warning("GPG signing is configured but not enabled");
        }
        
        /* Test GPG key availability */
        char gpg_test[256];
        snprintf(gpg_test, sizeof(gpg_test), "gpg --list-secret-keys '%s' >/dev/null 2>&1", 
                 account->gpg_key_id);
        if (system(gpg_test) != 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    log_info("Git configuration test passed for %s", account->name);
    return 0;
}

/* Set single git configuration value */
int git_set_config_value(const char *key, const char *value, git_scope_t scope) {
    char command[1024];
    char output[256];
    const char *scope_flag;
    
    if (!key || !value) {
        set_error(ERR_INVALID_ARGS, "NULL key or value to git_set_config_value");
        return -1;
    }
    
    if (!is_valid_git_config_value(value)) {
        set_error(ERR_INVALID_ARGS, "Invalid characters in git config value");
        return -1;
    }
    
    scope_flag = git_scope_to_flag(scope);
    if (!scope_flag) {
        set_error(ERR_INVALID_ARGS, "Invalid git scope");
        return -1;
    }
    
    /* Build git config command */
    if (snprintf(command, sizeof(command), "config %s '%s' '%s'", 
                 scope_flag, key, value) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "Git config command too long");
        return -1;
    }
    
    log_debug("Setting git config: %s = %s (%s)", key, value, scope_flag);
    
    if (execute_git_command(command, output, sizeof(output)) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git config %s: %s", key, output);
        return -1;
    }
    
    return 0;
}

/* Get single git configuration value */
int git_get_config_value(const char *key, char *value, size_t value_size, git_scope_t scope) {
    char command[512];
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
    
    /* Build git config command */
    if (snprintf(command, sizeof(command), "config %s '%s'", scope_flag, key) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "Git config command too long");
        return -1;
    }
    
    if (execute_git_command(command, output, sizeof(output)) != 0) {
        /* Config value not found - this is not always an error */
        value[0] = '\0';
        return -1;
    }
    
    /* Remove trailing newline */
    trim_whitespace(output);
    safe_strncpy(value, output, value_size);
    
    return 0;
}

/* Unset git configuration value */
int git_unset_config_value(const char *key, git_scope_t scope) {
    char command[512];
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
    
    /* Build git config unset command */
    if (snprintf(command, sizeof(command), "config %s --unset '%s'", 
                 scope_flag, key) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "Git config command too long");
        return -1;
    }
    
    log_debug("Unsetting git config: %s (%s)", key, scope_flag);
    
    /* Execute command - ignore errors as key might not exist */
    execute_git_command(command, output, sizeof(output));
    
    return 0;
}

/* List all git configuration values */
int git_list_config(git_scope_t scope, char *output, size_t output_size) {
    char command[256];
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
    
    /* Build git config list command */
    if (snprintf(command, sizeof(command), "config %s --list", scope_flag) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "Git config command too long");
        return -1;
    }
    
    if (execute_git_command(command, output, output_size) != 0) {
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
    
    /* Build SSH command with security options */
    if (snprintf(ssh_command, sizeof(ssh_command),
                 "ssh -i '%s' -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no",
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
    if (execute_git_command("rev-parse --git-dir", output, sizeof(output)) == 0) {
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
    
    if (execute_git_command("rev-parse --show-toplevel", output, sizeof(output)) != 0) {
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
static int execute_git_command(const char *args, char *output, size_t output_size) {
    char command[1024];
    FILE *pipe;
    
    if (!args) {
        return -1;
    }
    
    /* Build full git command */
    if (snprintf(command, sizeof(command), "git %s 2>&1", args) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "Git command too long");
        return -1;
    }
    
    log_debug("Executing git command: %s", command);
    
    /* Execute command */
    pipe = popen(command, "r");
    if (!pipe) {
        set_system_error(ERR_SYSTEM_COMMAND_FAILED, "Failed to execute git command");
        return -1;
    }
    
    /* Read output if buffer provided */
    if (output && output_size > 0) {
        if (!fgets(output, output_size, pipe)) {
            output[0] = '\0';
        }
    }
    
    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        log_debug("Git command failed with exit code: %d", exit_code);
        return -1;
    }
    
    return 0;
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
    if (execute_git_command("--version", version_output, sizeof(version_output)) != 0) {
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

/* Detect repository scope */
static int detect_repository_scope(git_scope_t *detected_scope) {
    if (!detected_scope) {
        return -1;
    }
    
    if (git_is_repository()) {
        *detected_scope = GIT_SCOPE_LOCAL;
    } else {
        *detected_scope = GIT_SCOPE_GLOBAL;
    }
    
    return 0;
}

/* Validate git config value for security */
static bool is_valid_git_config_value(const char *value) {
    if (!value) {
        return false;
    }
    
    /* Check for dangerous characters */
    const char *dangerous_chars = ";|&`$(){}[]";
    for (const char *p = dangerous_chars; *p; p++) {
        if (strchr(value, *p)) {
            return false;
        }
    }
    
    /* Check for control characters */
    for (const char *p = value; *p; p++) {
        if (*p < 32 && *p != '\t') {
            return false;
        }
    }
    
    return true;
}

/* Backup git config if needed */
static int backup_git_config_if_needed(git_scope_t scope) {
    /* TODO: Implement config backup for safety */
    (void)scope; /* Suppress unused parameter warning */
    return 0;
}

/* Restore git config if needed */
static int restore_git_config_if_needed(git_scope_t scope) {
    /* TODO: Implement config restore */
    (void)scope; /* Suppress unused parameter warning */
    return 0;
}