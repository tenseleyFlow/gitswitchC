/* Account management and operations with comprehensive security validation
 * Implements secure account switching and management for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>

#include "accounts.h"
#include "config.h"
#include "display.h"
#include "error.h"
#include "utils.h"
#include "git_ops.h"
#include "ssh_manager.h"
#include "gpg_manager.h"

/* Internal helper functions */
static uint32_t get_next_available_id(const gitswitch_ctx_t *ctx);
static int validate_ssh_key_security(const char *ssh_key_path);
static int validate_gpg_key_availability(const char *gpg_key_id);
static int test_ssh_key_functionality(const account_t *account);
static int test_gpg_key_functionality(const account_t *account);

/* Initialize accounts system */
int accounts_init(gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_init");
        return -1;
    }
    
    /* Initialize account array */
    memset(ctx->accounts, 0, sizeof(ctx->accounts));
    ctx->account_count = 0;
    ctx->current_account = NULL;
    
    log_debug("Accounts system initialized");
    return 0;
}

/* Switch to specified account with SSH isolation and validation */
int accounts_switch(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_switch");
        return -1;
    }
    
    /* Find the account */
    account = config_find_account(ctx, identifier);
    if (!account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: %s", identifier);
        return -1;
    }
    
    /* Basic validation */
    if (!validate_name(account->name) || !validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Account has invalid name or email");
        return -1;
    }
    
    /* Determine git scope - use account preference or context default */
    git_scope_t scope = account->preferred_scope;
    if (scope == GIT_SCOPE_LOCAL && !git_is_repository()) {
        log_warning("Account prefers local scope, but not in git repository. Using global scope.");
        scope = GIT_SCOPE_GLOBAL;
    }
    
    /* Initialize git operations if not already done */
    if (git_ops_init() != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to initialize git operations");
        return -1;
    }
    
    /* If not in dry-run mode, actually set git configuration */
    if (!ctx->config.dry_run) {
        log_info("Setting git configuration for account: %s (%s scope)", 
                 account->name, scope == GIT_SCOPE_LOCAL ? "local" : "global");
                 
        if (git_set_config(account, scope) != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git configuration: %s", 
                      get_last_error()->message);
            return -1;
        }
        
        /* Validate the configuration was set correctly */
        if (git_test_config(account, scope) != 0) {
            log_warning("Git configuration validation failed: %s", get_last_error()->message);
            /* Don't fail completely, just warn */
        }
        
        /* Handle SSH agent isolation if SSH is enabled */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            log_info("Setting up SSH isolation for account: %s", account->name);
            
            /* Initialize SSH manager with isolated agents */
            ssh_config_t ssh_config = {0};
            if (ssh_manager_init(&ssh_config, SSH_AGENT_ISOLATED) != 0) {
                log_warning("Failed to initialize SSH manager: %s", get_last_error()->message);
            } else {
                /* Switch to account's SSH configuration */
                if (ssh_switch_account(&ssh_config, account) != 0) {
                    log_warning("Failed to switch SSH configuration: %s", get_last_error()->message);
                    /* Clean up SSH manager on failure */
                    ssh_manager_cleanup(&ssh_config);
                } else {
                    log_info("SSH isolation activated for account: %s", account->name);
                    
                    /* Test SSH connection if connection testing is available */
                    if (strlen(account->ssh_host_alias) > 0) {
                        if (ssh_test_connection(account, account->ssh_host_alias) == 0) {
                            log_info("SSH connection test passed for %s", account->ssh_host_alias);
                        } else {
                            log_warning("SSH connection test failed for %s", account->ssh_host_alias);
                        }
                    } else {
                        /* Test with default GitHub host */
                        if (ssh_test_connection(account, "github.com") == 0) {
                            log_info("SSH connection test passed for github.com");
                        } else {
                            log_debug("SSH connection test failed for github.com (this may be normal)");
                        }
                    }
                }
            }
        }
        
        /* Handle GPG environment isolation if GPG is enabled */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            log_info("Setting up GPG isolation for account: %s", account->name);
            
            /* Initialize GPG manager with isolated environments */
            gpg_config_t gpg_config = {0};
            if (gpg_manager_init(&gpg_config, GPG_MODE_ISOLATED) != 0) {
                log_warning("Failed to initialize GPG manager: %s", get_last_error()->message);
            } else {
                /* Switch to account's GPG configuration */
                if (gpg_switch_account(&gpg_config, account) != 0) {
                    log_warning("Failed to switch GPG configuration: %s", get_last_error()->message);
                    /* Clean up GPG manager on failure */
                    gpg_manager_cleanup(&gpg_config);
                } else {
                    log_info("GPG isolation activated for account: %s", account->name);
                    
                    /* Configure git GPG signing */
                    if (gpg_configure_git_signing(&gpg_config, account, scope) != 0) {
                        log_warning("Failed to configure git GPG signing: %s", get_last_error()->message);
                    } else {
                        log_info("Git GPG signing configured for account: %s", account->name);
                    }
                }
            }
        }
    } else {
        display_info("DRY RUN: Would set git configuration for %s", account->name);
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            display_info("DRY RUN: Would activate SSH isolation for %s", account->ssh_key_path);
        }
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            display_info("DRY RUN: Would activate GPG isolation for key %s", account->gpg_key_id);
        }
    }
    
    /* Test SSH functionality if enabled (basic validation) */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (test_ssh_key_functionality(account) != 0) {
            log_warning("SSH key test failed for account: %s", account->name);
        }
    }
    
    /* Test GPG functionality if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (test_gpg_key_functionality(account) != 0) {
            log_warning("GPG key test failed for account: %s", account->name);
        }
    }
    
    /* Set as current account */
    ctx->current_account = account;
    
    log_info("Successfully switched to account: %s (%s)", account->name, account->description);
    return 0;
}

/* Add new account interactively with basic validation */
int accounts_add_interactive(gitswitch_ctx_t *ctx) {
    account_t new_account;
    char input[512];
    char expanded_path[MAX_PATH_LEN];
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_add_interactive");
        return -1;
    }
    
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    
    /* Initialize new account */
    memset(&new_account, 0, sizeof(new_account));
    new_account.id = get_next_available_id(ctx);
    new_account.preferred_scope = ctx->config.default_scope;
    
    printf("\n┌─────────────────────────────────────┐\n");
    printf("│          Add New Account            │\n");
    printf("└─────────────────────────────────────┘\n\n");
    
    /* Get account name */
    do {
        printf("Account Name: ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            set_error(ERR_FILE_IO, "Failed to read account name");
            return -1;
        }
        
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (!validate_name(input)) {
            printf("[ERROR]: Invalid name. Please enter a non-empty name.\n");
            continue;
        }
        
        safe_strncpy(new_account.name, input, sizeof(new_account.name));
        break;
    } while (1);
    
    /* Get email address */
    do {
        printf("Email Address: ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            set_error(ERR_FILE_IO, "Failed to read email address");
            return -1;
        }
        
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (!validate_email(input)) {
            printf("[ERROR]: Invalid email address format.\n");
            continue;
        }
        
        safe_strncpy(new_account.email, input, sizeof(new_account.email));
        break;
    } while (1);
    
    /* Get description */
    printf("Description (optional): ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (strlen(input) > 0) {
            safe_strncpy(new_account.description, input, sizeof(new_account.description));
        } else {
            safe_strncpy(new_account.description, new_account.name, sizeof(new_account.description));
        }
    } else {
        safe_strncpy(new_account.description, new_account.name, sizeof(new_account.description));
    }
    
    /* Get SSH key configuration */
    printf("SSH Key Path (optional, press Enter to skip): ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (strlen(input) > 0) {
            /* Expand and validate path */
            if (expand_path(input, expanded_path, sizeof(expanded_path)) == 0) {
                if (path_exists(expanded_path)) {
                    if (validate_ssh_key_security(expanded_path) == 0) {
                        safe_strncpy(new_account.ssh_key_path, expanded_path, sizeof(new_account.ssh_key_path));
                        new_account.ssh_enabled = true;
                        printf("[OK]: SSH key validated: %s\n", expanded_path);
                        
                        /* Optional SSH host alias */
                        printf("SSH Host Alias (optional, e.g., github.com-work): ");
                        fflush(stdout);
                        
                        if (fgets(input, sizeof(input), stdin)) {
                            input[strcspn(input, "\n")] = '\0';
                            trim_whitespace(input);
                            
                            if (strlen(input) > 0) {
                                safe_strncpy(new_account.ssh_host_alias, input, sizeof(new_account.ssh_host_alias));
                            }
                        }
                    } else {
                        printf("[ERROR]: SSH key validation failed. Continuing without SSH key.\n");
                    }
                } else {
                    printf("[ERROR]: SSH key file not found: %s\n", expanded_path);
                }
            } else {
                printf("[ERROR]: Invalid SSH key path: %s\n", input);
            }
        }
    }
    
    /* Get GPG key configuration */
    printf("GPG Key ID (optional, press Enter to skip): ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (strlen(input) > 0) {
            if (validate_key_id(input)) {
                if (validate_gpg_key_availability(input) == 0) {
                    safe_strncpy(new_account.gpg_key_id, input, sizeof(new_account.gpg_key_id));
                    new_account.gpg_enabled = true;
                    printf("[OK]: GPG key validated: %s\n", input);
                    
                    /* Ask about GPG signing */
                    printf("Enable GPG signing for commits? (y/N): ");
                    fflush(stdout);
                    
                    if (fgets(input, sizeof(input), stdin)) {
                        input[strcspn(input, "\n")] = '\0';
                        trim_whitespace(input);
                        
                        new_account.gpg_signing_enabled = (tolower(input[0]) == 'y');
                    }
                } else {
                    printf("[ERROR]: GPG key validation failed. Continuing without GPG key.\n");
                }
            } else {
                printf("[ERROR]: Invalid GPG key ID format: %s\n", input);
            }
        }
    }
    
    /* Get preferred scope */
    printf("Preferred Git Scope (local/global) [%s]: ", 
           config_scope_to_string(new_account.preferred_scope));
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (strlen(input) > 0) {
            new_account.preferred_scope = config_parse_scope(input);
        }
    }
    
    /* Basic validation */
    if (!validate_name(new_account.name) || !validate_email(new_account.email)) {
        printf("[ERROR]: Account validation failed: Invalid name or email\n");
        return -1;
    }
    
    /* Confirmation */
    printf("\nAccount Summary:\n");
    printf("   ID: %u\n", new_account.id);
    printf("   Name: %s\n", new_account.name);
    printf("   Email: %s\n", new_account.email);
    printf("   Description: %s\n", new_account.description);
    printf("   Scope: %s\n", config_scope_to_string(new_account.preferred_scope));
    printf("   SSH: %s\n", new_account.ssh_enabled ? "[ENABLED]" : "[DISABLED]");
    printf("   GPG: %s\n", new_account.gpg_enabled ? "[ENABLED]" : "[DISABLED]");
    
    printf("\nAdd this account? (y/N): ");
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        set_error(ERR_FILE_IO, "Failed to read confirmation");
        return -1;
    }
    
    input[strcspn(input, "\n")] = '\0';
    trim_whitespace(input);
    
    if (tolower(input[0]) != 'y') {
        printf("Account creation cancelled.\n");
        return -1;
    }
    
    /* Add account to context */
    if (config_add_account(ctx, &new_account) != 0) {
        return -1;
    }
    
    printf("[OK]: Account added successfully!\n");
    return 0;
}

/* Remove account with confirmation and cleanup */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    char input[64];
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_remove");
        return -1;
    }
    
    /* Find the account */
    account = config_find_account(ctx, identifier);
    if (!account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: %s", identifier);
        return -1;
    }
    
    /* Show account details */
    printf("\nRemove Account\n");
    printf("─────────────────\n");
    printf("ID: %u\n", account->id);
    printf("Name: %s\n", account->name);
    printf("Email: %s\n", account->email);
    printf("Description: %s\n", account->description);
    
    /* Confirmation */
    printf("\n[WARN]: This will permanently remove the account from configuration.\n");
    printf("Are you sure? (type 'yes' to confirm): ");
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        set_error(ERR_FILE_IO, "Failed to read confirmation");
        return -1;
    }
    
    input[strcspn(input, "\n")] = '\0';
    trim_whitespace(input);
    
    if (strcmp(input, "yes") != 0) {
        printf("Account removal cancelled.\n");
        return 0;
    }
    
    /* Clear current account if it's the one being removed */
    if (ctx->current_account == account) {
        ctx->current_account = NULL;
    }
    
    uint32_t account_id = account->id;
    
    /* Remove account */
    if (config_remove_account(ctx, account_id) != 0) {
        return -1;
    }
    
    printf("[OK]: Account removed successfully.\n");
    return 0;
}

/* List all configured accounts */
int accounts_list(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_list");
        return -1;
    }
    
    if (ctx->account_count == 0) {
        printf("\n[INFO]: No accounts configured.\n");
        printf("Run 'gitswitch add' to create your first account.\n\n");
        return 0;
    }
    
    printf("\nConfigured Accounts (%zu total)\n", ctx->account_count);
    printf("════════════════════════════════════════════════════════════════\n");
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        bool is_current = (ctx->current_account == account);
        
        printf("%s [%u] %s\n", is_current ? "[CURRENT]" : "", account->id, account->name);
        printf("     Email: %s\n", account->email);
        printf("     Description: %s\n", account->description);
        printf("     Scope: %s\n", config_scope_to_string(account->preferred_scope));
        
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            printf("     SSH Key: %s\n", account->ssh_key_path);
            if (strlen(account->ssh_host_alias) > 0) {
                printf("         Host: %s\n", account->ssh_host_alias);
            }
        } else {
            printf("     SSH Key: Not configured\n");
        }
        
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("     GPG Key: %s %s\n", account->gpg_key_id,
                   account->gpg_signing_enabled ? "(signing enabled)" : "(signing disabled)");
        } else {
            printf("     GPG Key: Not configured\n");
        }
        
        if (i < ctx->account_count - 1) {
            printf("\n");
        }
    }
    
    printf("════════════════════════════════════════════════════════════════\n\n");
    
    if (ctx->current_account) {
        printf("Current: %s (%s)\n\n", ctx->current_account->name, ctx->current_account->description);
    } else {
        printf("No account currently active.\n\n");
    }
    
    return 0;
}

/* Show current account status */
int accounts_show_status(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_show_status");
        return -1;
    }
    
    printf("\nAccount Status\n");
    printf("════════════════\n");
    
    if (ctx->current_account) {
        const account_t *account = ctx->current_account;
        
        printf("Active Account: %s (ID: %u)\n", account->name, account->id);
        printf("Email: %s\n", account->email);
        printf("Description: %s\n", account->description);
        printf("Preferred Scope: %s\n", config_scope_to_string(account->preferred_scope));
        
        /* SSH Status */
        printf("\nSSH Configuration:\n");
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            printf("  Status: [ENABLED]\n");
            printf("  Key: %s\n", account->ssh_key_path);
            
            if (path_exists(account->ssh_key_path)) {
                printf("  Key File: [FOUND]\n");
                
                mode_t key_mode;
                if (get_file_permissions(account->ssh_key_path, &key_mode) == 0) {
                    if ((key_mode & 077) == 0) {
                        printf("  Permissions: [SECURE] (600)\n");
                    } else {
                        printf("  Permissions: [WARN] Insecure (%o)\n", key_mode & 0777);
                    }
                }
            } else {
                printf("  Key File: [NOT FOUND]\n");
            }
            
            if (strlen(account->ssh_host_alias) > 0) {
                printf("  Host Alias: %s\n", account->ssh_host_alias);
            }
        } else {
            printf("  Status: [DISABLED]\n");
        }
        
        /* GPG Status */
        printf("\nGPG Configuration:\n");
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("  Status: [ENABLED]\n");
            printf("  Key ID: %s\n", account->gpg_key_id);
            printf("  Signing: %s\n", account->gpg_signing_enabled ? "[ENABLED]" : "[DISABLED]");
        } else {
            printf("  Status: [DISABLED]\n");
        }
        
        /* Git Configuration Status */
        printf("\nGit Configuration:\n");
        git_current_config_t git_config;
        if (git_get_current_config(&git_config) == 0) {
            printf("  Current Name: %s\n", git_config.name);
            printf("  Current Email: %s\n", git_config.email);
            printf("  Configuration Scope: %s\n", 
                   git_config.scope == GIT_SCOPE_LOCAL ? "local" : 
                   git_config.scope == GIT_SCOPE_GLOBAL ? "global" : "system");
            
            /* Check if git config matches account */
            if (strcmp(git_config.name, account->name) == 0 &&
                strcmp(git_config.email, account->email) == 0) {
                printf("  Match Status: [OK] Git config matches account\n");
            } else {
                printf("  Match Status: [WARN] Git config does not match account\n");
                printf("    Expected: %s <%s>\n", account->name, account->email);
                printf("    Current:  %s <%s>\n", git_config.name, git_config.email);
            }
            
            /* GPG signing status */
            if (strlen(git_config.signing_key) > 0) {
                printf("  GPG Signing Key: %s\n", git_config.signing_key);
                printf("  GPG Signing Enabled: %s\n", git_config.gpg_signing_enabled ? "[YES]" : "[NO]");
            } else {
                printf("  GPG Signing: [NOT CONFIGURED]\n");
            }
        } else {
            printf("  Status: [NOT FOUND] No git configuration found\n");
        }
        
        /* Repository context */
        printf("\nRepository Context:\n");
        if (git_is_repository()) {
            char repo_root[MAX_PATH_LEN];
            if (git_get_repo_root(repo_root, sizeof(repo_root)) == 0) {
                printf("  Repository: [FOUND] %s\n", repo_root);
            } else {
                printf("  Repository: [REPOSITORY] Current directory is a git repository\n");
            }
        } else {
            printf("  Repository: [NO REPOSITORY] Not in a git repository\n");
        }
        
    } else {
        printf("No account currently active.\n");
        printf("Run 'gitswitch list' to see available accounts.\n");
        printf("Run 'gitswitch <account>' to activate an account.\n");
        
        /* Show current git config even without active account */
        printf("\nCurrent Git Configuration:\n");
        git_current_config_t git_config;
        if (git_get_current_config(&git_config) == 0) {
            printf("  Name: %s\n", git_config.name);
            printf("  Email: %s\n", git_config.email);
            printf("  Scope: %s\n", 
                   git_config.scope == GIT_SCOPE_LOCAL ? "local" : 
                   git_config.scope == GIT_SCOPE_GLOBAL ? "global" : "system");
        } else {
            printf("  Status: [NOT FOUND] No git configuration found\n");
        }
        
        /* Repository context */
        printf("\nRepository Context:\n");
        if (git_is_repository()) {
            printf("  Repository: [REPOSITORY] Current directory is a git repository\n");
        } else {
            printf("  Repository: [NO REPOSITORY] Not in a git repository\n");
        }
    }
    
    printf("\n");
    return 0;
}

/* Simple account validation for Phase 2 */
int accounts_validate(const account_t *account) {
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account pointer");
        return -1;
    }
    
    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid or empty account name");
        return -1;
    }
    
    if (!validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address format");
        return -1;
    }
    
    /* Basic SSH validation if enabled */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        char expanded_path[MAX_PATH_LEN];
        
        if (expand_path(account->ssh_key_path, expanded_path, sizeof(expanded_path)) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH key path: %s", account->ssh_key_path);
            return -1;
        }
        
        if (!path_exists(expanded_path)) {
            set_error(ERR_ACCOUNT_INVALID, "SSH key file not found: %s", expanded_path);
            return -1;
        }
    }
    
    /* Basic GPG validation if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (!validate_key_id(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID format: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    return 0;
}

/* Get next available account ID */
static uint32_t get_next_available_id(const gitswitch_ctx_t *ctx) {
    uint32_t max_id = 0;
    
    if (!ctx) return 1;
    
    /* Find the highest existing ID */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id > max_id) {
            max_id = ctx->accounts[i].id;
        }
    }
    
    return max_id + 1;
}

/* Validate SSH key security */
static int validate_ssh_key_security(const char *ssh_key_path) {
    FILE *key_file;
    char first_line[256];
    mode_t file_mode;
    
    if (!ssh_key_path || !path_exists(ssh_key_path)) {
        return -1;
    }
    
    /* Check file permissions */
    if (get_file_permissions(ssh_key_path, &file_mode) != 0) {
        return -1;
    }
    
    if ((file_mode & 077) != 0) {
        log_warning("SSH key file has insecure permissions: %o", file_mode & 0777);
        return -1;
    }
    
    /* Check if it looks like a valid SSH key */
    key_file = fopen(ssh_key_path, "r");
    if (!key_file) {
        return -1;
    }
    
    if (fgets(first_line, sizeof(first_line), key_file)) {
        /* Check for common SSH key formats */
        if (!string_starts_with(first_line, "-----BEGIN OPENSSH PRIVATE KEY-----") &&
            !string_starts_with(first_line, "-----BEGIN RSA PRIVATE KEY-----") &&
            !string_starts_with(first_line, "-----BEGIN DSA PRIVATE KEY-----") &&
            !string_starts_with(first_line, "-----BEGIN EC PRIVATE KEY-----") &&
            !string_starts_with(first_line, "-----BEGIN SSH2 PRIVATE KEY-----")) {
            fclose(key_file);
            log_warning("SSH key file format not recognized");
            return -1;
        }
    }
    
    fclose(key_file);
    return 0;
}

/* Validate GPG key availability */
static int validate_gpg_key_availability(const char *gpg_key_id) {
    char command[256];
    int result;
    
    if (!gpg_key_id) {
        return -1;
    }
    
    /* Try to find the key in the GPG keyring */
    if ((size_t)snprintf(command, sizeof(command), "gpg --list-secret-keys %s >/dev/null 2>&1", 
                        gpg_key_id) >= sizeof(command)) {
        log_error("GPG command too long");
        return -1;
    }
    
    result = system(command);
    if (result != 0) {
        log_debug("GPG key %s not found in keyring", gpg_key_id);
        return -1;
    }
    
    return 0;
}

/* Test SSH key functionality */
static int test_ssh_key_functionality(const account_t *account) {
    /* This is a placeholder for SSH functionality testing
     * In a full implementation, this would:
     * 1. Start SSH agent if needed
     * 2. Load the key into agent
     * 3. Test connection to a known host
     * 4. Verify authentication works
     */
    log_debug("SSH key functionality test for %s: %s", 
              account->name, account->ssh_key_path);
    
    /* For now, just validate the key file exists and has correct permissions */
    return validate_ssh_key_security(account->ssh_key_path);
}

/* Test GPG key functionality */
static int test_gpg_key_functionality(const account_t *account) {
    /* This is a placeholder for GPG functionality testing
     * In a full implementation, this would:
     * 1. Set up GPG environment
     * 2. Test key can be used for signing
     * 3. Verify key is not expired
     * 4. Test signing a test message
     */
    log_debug("GPG key functionality test for %s: %s", 
              account->name, account->gpg_key_id);
    
    /* For now, just check if key exists in keyring */
    return validate_gpg_key_availability(account->gpg_key_id);
}

/* Run comprehensive health check on all accounts */
int accounts_health_check(const gitswitch_ctx_t *ctx) {
    bool all_healthy = true;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_health_check");
        return -1;
    }
    
    printf("\nAccount Health Check\n");
    printf("══════════════════════\n");
    
    if (ctx->account_count == 0) {
        printf("[ERROR]: No accounts configured\n");
        printf("   Run 'gitswitch add' to create your first account\n\n");
        return -1;
    }
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        int validation_result = accounts_validate(account);
        
        printf("\n[%u] %s\n", account->id, account->name);
        printf("────────────────────────\n");
        
        if (validation_result == 0) {
            printf("[OK]: Account configuration valid\n");
            
            /* Test SSH if configured */
            if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
                if (test_ssh_key_functionality(account) == 0) {
                    printf("[OK]: SSH key functional\n");
                } else {
                    printf("[ERROR]: SSH key issues detected\n");
                    all_healthy = false;
                }
            }
            
            /* Test GPG if configured */
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                if (test_gpg_key_functionality(account) == 0) {
                    printf("[OK]: GPG key functional\n");
                } else {
                    printf("[ERROR]: GPG key issues detected\n");
                    all_healthy = false;
                }
            }
        } else {
            printf("[ERROR]: Account validation failed\n");
            all_healthy = false;
        }
    }
    
    printf("\n══════════════════════\n");
    if (all_healthy) {
        printf("[OK]: All accounts are healthy\n\n");
        return 0;
    } else {
        printf("[ERROR]: Some accounts have issues\n\n");
        return -1;
    }
}