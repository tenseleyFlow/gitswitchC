/* Configuration file management with comprehensive security validation
 * Implements secure TOML-based configuration for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "toml_parser.h"
#include "error.h"
#include "utils.h"

/* Default configuration template with security-focused defaults */
const char *default_config_template = 
"# gitswitch-c Configuration File\n"
"# This file contains sensitive information - ensure proper permissions (600)\n"
"\n"
"[settings]\n"
"# Default scope for git configuration changes\n"
"# Options: \"local\" (repository-specific) or \"global\" (user-wide)\n"
"default_scope = \"local\"\n"
"\n"
"# Example account configuration\n"
"# Uncomment and modify for your accounts\n"
"\n"
"#[accounts.1]\n"
"#name = \"Your Name\"\n"
"#email = \"your.email@example.com\"\n"
"#description = \"Personal Account\"\n"
"#preferred_scope = \"local\"\n"
"#ssh_key = \"~/.ssh/id_ed25519_personal\"\n"
"#gpg_key = \"1234567890ABCDEF\"\n"
"#gpg_signing_enabled = true\n"
"\n"
"#[accounts.2]\n"
"#name = \"Your Name\"\n"
"#email = \"work@company.com\"\n"
"#description = \"Work Account\"\n"
"#preferred_scope = \"global\"\n"
"#ssh_key = \"~/.ssh/id_rsa_work\"\n"
"#gpg_key = \"ABCDEF1234567890\"\n"
"#gpg_signing_enabled = true\n"
"#ssh_host = \"github.com-work\"\n"
"\n"
"# Security Notes:\n"
"# - SSH keys should have 600 permissions\n"
"# - GPG keys should exist in your keyring\n"
"# - This config file should have 600 permissions\n"
"# - Use absolute paths or ~ expansion for key files\n";

/* Internal helper functions */
static int validate_config_file_security(const char *config_path);
static int create_config_directory_secure(const char *config_dir);
static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc);
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id);
static int validate_account_security(const account_t *account);

/* Initialize configuration system */
int config_init(gitswitch_ctx_t *ctx) {
    char config_path[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_init");
        return -1;
    }
    
    /* Initialize context */
    memset(ctx, 0, sizeof(gitswitch_ctx_t));
    ctx->config.default_scope = GIT_SCOPE_LOCAL;
    ctx->config.verbose = false;
    ctx->config.dry_run = false;
    ctx->config.color_output = true;
    
    /* Get configuration directory path */
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    /* Ensure config directory exists with secure permissions */
    if (create_config_directory_secure(config_dir) != 0) {
        return -1;
    }
    
    /* Build config file path */
    if (join_path(config_path, sizeof(config_path), config_dir, DEFAULT_CONFIG_FILE) != 0) {
        return -1;
    }
    
    /* Store config path in context */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));
    
    /* Load configuration if it exists */
    if (path_exists(config_path)) {
        log_info("Loading configuration from: %s", config_path);
        return config_load(ctx, config_path);
    } else {
        log_info("Configuration file not found, will create default");
        /* Don't automatically create - let user create when needed */
        return 0;
    }
}

/* Load configuration from TOML file */
int config_load(gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    char scope_str[32];
    
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }
    
    /* Validate file security before loading */
    if (validate_config_file_security(config_path) != 0) {
        return -1;
    }
    
    /* Parse TOML configuration */
    toml_init_document(&toml_doc);
    if (toml_parse_file(config_path, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }
    
    /* Load settings section */
    if (toml_get_string(&toml_doc, "settings", "default_scope", 
                        scope_str, sizeof(scope_str)) == 0) {
        ctx->config.default_scope = config_parse_scope(scope_str);
    } else {
        log_warning("No default_scope found in settings, using local");
        ctx->config.default_scope = GIT_SCOPE_LOCAL;
    }
    
    /* Load accounts */
    if (load_accounts_from_toml(ctx, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }
    
    /* Store config path */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));
    
    toml_cleanup_document(&toml_doc);
    
    log_info("Configuration loaded successfully: %zu accounts", ctx->account_count);
    return 0;
}

/* Save configuration to TOML file */
int config_save(const gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    char temp_path[MAX_PATH_LEN];
    int result = -1;
    
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save");
        return -1;
    }
    
    /* Create backup if file exists */
    if (path_exists(config_path)) {
        if (config_backup(config_path) != 0) {
            log_warning("Failed to create backup before saving config");
        }
    }
    
    /* Create temporary file path for atomic write */
    if ((size_t)snprintf(temp_path, sizeof(temp_path), "%s.tmp", config_path) >= sizeof(temp_path)) {
        set_error(ERR_INVALID_ARGS, "Temporary file path too long");
        return -1;
    }
    
    /* Initialize TOML document */
    toml_init_document(&toml_doc);
    
    /* Add settings section */
    if (toml_set_string(&toml_doc, "settings", "default_scope", 
                        config_scope_to_string(ctx->config.default_scope)) != 0) {
        goto cleanup;
    }
    
    /* Add accounts */
    if (save_accounts_to_toml(ctx, &toml_doc) != 0) {
        goto cleanup;
    }
    
    /* Write to temporary file first */
    if (toml_write_file(&toml_doc, temp_path) != 0) {
        goto cleanup;
    }
    
    /* Set secure permissions on temp file */
    if (set_file_permissions(temp_path, PERM_USER_RW) != 0) {
        unlink(temp_path);
        goto cleanup;
    }
    
    /* Atomic move from temp to final location */
    if (rename(temp_path, config_path) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, 
                        "Failed to move temporary config file to final location");
        unlink(temp_path);
        goto cleanup;
    }
    
    log_info("Configuration saved successfully to: %s", config_path);
    result = 0;
    
cleanup:
    toml_cleanup_document(&toml_doc);
    return result;
}

/* Create default configuration file */
int config_create_default(const char *config_path) {
    FILE *file;
    char config_dir[MAX_PATH_LEN];
    char *last_slash;
    
    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_create_default");
        return -1;
    }
    
    /* Extract directory from config path */
    safe_strncpy(config_dir, config_path, sizeof(config_dir));
    last_slash = strrchr(config_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    }
    
    /* Ensure directory exists */
    if (create_config_directory_secure(config_dir) != 0) {
        return -1;
    }
    
    /* Create file with secure permissions */
    file = fopen(config_path, "w");
    if (!file) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to create config file: %s", config_path);
        return -1;
    }
    
    /* Write default template */
    if (fwrite(default_config_template, 1, strlen(default_config_template), file) != 
        strlen(default_config_template)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to write default config content");
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    /* Set secure permissions */
    if (set_file_permissions(config_path, PERM_USER_RW) != 0) {
        return -1;
    }
    
    log_info("Created default configuration file: %s", config_path);
    return 0;
}

/* Validate configuration structure */
int config_validate(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_validate");
        return -1;
    }
    
    /* Validate configuration file security */
    if (path_exists(ctx->config.config_path)) {
        if (validate_config_file_security(ctx->config.config_path) != 0) {
            return -1;
        }
    }
    
    /* Validate each account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (validate_account_security(&ctx->accounts[i]) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Account %u failed security validation", 
                      ctx->accounts[i].id);
            return -1;
        }
    }
    
    log_debug("Configuration validation passed for %zu accounts", ctx->account_count);
    return 0;
}

/* Get configuration file path */
int config_get_path(char *path_buffer, size_t buffer_size) {
    char config_dir[MAX_PATH_LEN];
    
    if (!path_buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_get_path");
        return -1;
    }
    
    /* Get config directory */
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    /* Build full path */
    return join_path(path_buffer, buffer_size, config_dir, DEFAULT_CONFIG_FILE);
}

/* Add new account to configuration */
int config_add_account(gitswitch_ctx_t *ctx, const account_t *account) {
    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_add_account");
        return -1;
    }
    
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    
    /* Validate account security */
    if (validate_account_security(account) != 0) {
        return -1;
    }
    
    /* Check for duplicate IDs */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account->id) {
            set_error(ERR_ACCOUNT_EXISTS, "Account with ID %u already exists", account->id);
            return -1;
        }
    }
    
    /* Add account */
    ctx->accounts[ctx->account_count] = *account;
    ctx->account_count++;
    
    log_info("Added account: %s (%s)", account->name, account->description);
    return 0;
}

/* Remove account from configuration */
int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id) {
    size_t found_index = SIZE_MAX;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_remove_account");
        return -1;
    }
    
    /* Find account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account_id) {
            found_index = i;
            break;
        }
    }
    
    if (found_index == SIZE_MAX) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found", account_id);
        return -1;
    }
    
    /* Clear sensitive data before removing */
    secure_zero_memory(&ctx->accounts[found_index], sizeof(account_t));
    
    /* Shift remaining accounts */
    for (size_t i = found_index; i < ctx->account_count - 1; i++) {
        ctx->accounts[i] = ctx->accounts[i + 1];
    }
    
    ctx->account_count--;
    
    /* Clear the last slot */
    memset(&ctx->accounts[ctx->account_count], 0, sizeof(account_t));
    
    log_info("Removed account with ID: %u", account_id);
    return 0;
}

/* Update existing account */
int config_update_account(gitswitch_ctx_t *ctx, const account_t *account) {
    account_t *existing_account = NULL;
    
    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_update_account");
        return -1;
    }
    
    /* Find existing account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account->id) {
            existing_account = &ctx->accounts[i];
            break;
        }
    }
    
    if (!existing_account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found", account->id);
        return -1;
    }
    
    /* Validate new account data */
    if (validate_account_security(account) != 0) {
        return -1;
    }
    
    /* Clear old sensitive data */
    secure_zero_memory(existing_account, sizeof(account_t));
    
    /* Update with new data */
    *existing_account = *account;
    
    log_info("Updated account: %s (%s)", account->name, account->description);
    return 0;
}

/* Find account by ID or name/description */
account_t *config_find_account(gitswitch_ctx_t *ctx, const char *identifier) {
    char *endptr;
    unsigned long account_id;
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_find_account");
        return NULL;
    }
    
    /* Try to parse as numeric ID */
    account_id = strtoul(identifier, &endptr, 10);
    if (*endptr == '\0') {
        /* It's a number - search by ID */
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id == (uint32_t)account_id) {
                return &ctx->accounts[i];
            }
        }
    } else {
        /* Search by name, email, or description */
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (strstr(ctx->accounts[i].name, identifier) ||
                strstr(ctx->accounts[i].description, identifier) ||
                strcmp(ctx->accounts[i].email, identifier) == 0) {
                return &ctx->accounts[i];
            }
        }
    }
    
    return NULL;
}

/* Parse git scope from string */
git_scope_t config_parse_scope(const char *scope_str) {
    if (!scope_str) return GIT_SCOPE_LOCAL;
    
    if (strcmp(scope_str, "global") == 0) {
        return GIT_SCOPE_GLOBAL;
    } else if (strcmp(scope_str, "system") == 0) {
        return GIT_SCOPE_SYSTEM;
    } else {
        return GIT_SCOPE_LOCAL;
    }
}

/* Convert git scope to string */
const char *config_scope_to_string(git_scope_t scope) {
    switch (scope) {
        case GIT_SCOPE_GLOBAL: return "global";
        case GIT_SCOPE_SYSTEM: return "system";
        case GIT_SCOPE_LOCAL:
        default:
            return "local";
    }
}

/* Backup configuration file with timestamp */
int config_backup(const char *config_path) {
    char backup_path[MAX_PATH_LEN];
    char timestamp[32];
    time_t now;
    struct tm *tm_info;
    
    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_backup");
        return -1;
    }
    
    if (!path_exists(config_path)) {
        log_debug("Config file does not exist, no backup needed");
        return 0;
    }
    
    /* Generate timestamp */
    time(&now);
    tm_info = localtime(&now);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    } else {
        snprintf(timestamp, sizeof(timestamp), "%ld", (long)now);
    }
    
    /* Create backup path */
    if ((size_t)snprintf(backup_path, sizeof(backup_path), "%s.backup.%s", 
                        config_path, timestamp) >= sizeof(backup_path)) {
        set_error(ERR_INVALID_ARGS, "Backup path too long");
        return -1;
    }
    
    /* Copy file */
    if (copy_file(config_path, backup_path) != 0) {
        return -1;
    }
    
    /* Set secure permissions on backup */
    if (set_file_permissions(backup_path, PERM_USER_RW) != 0) {
        return -1;
    }
    
    log_info("Created configuration backup: %s", backup_path);
    return 0;
}

/* Internal helper functions implementation */

/* Validate configuration file security */
static int validate_config_file_security(const char *config_path) {
    struct stat file_stat;
    
    if (stat(config_path, &file_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot access config file: %s", config_path);
        return -1;
    }
    
    /* Check file permissions - must not be readable by group/others */
    if (file_stat.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        set_error(ERR_PERMISSION_DENIED, 
                  "Configuration file has unsafe permissions: %o (should be 600)", 
                  file_stat.st_mode & 0777);
        return -1;
    }
    
    /* Check ownership - must be owned by current user */
    if (file_stat.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED, "Configuration file not owned by current user");
        return -1;
    }
    
    /* Check file size is reasonable */
    if (file_stat.st_size > TOML_MAX_FILE_SIZE) {
        set_error(ERR_CONFIG_INVALID, "Configuration file too large: %ld bytes", file_stat.st_size);
        return -1;
    }
    
    return 0;
}

/* Create config directory with secure permissions */
static int create_config_directory_secure(const char *config_dir) {
    if (!path_exists(config_dir)) {
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        log_info("Created configuration directory: %s", config_dir);
    }
    
    /* Verify directory permissions */
    mode_t dir_mode;
    if (get_file_permissions(config_dir, &dir_mode) == 0) {
        if ((dir_mode & 077) != 0) {
            /* Directory has group/other permissions - fix it */
            if (set_file_permissions(config_dir, PERM_USER_RWX) != 0) {
                return -1;
            }
            log_warning("Fixed configuration directory permissions");
        }
    }
    
    return 0;
}

/* Load accounts from TOML document */
static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc) {
    char sections[TOML_MAX_SECTIONS][TOML_MAX_SECTION_LEN];
    size_t section_count;
    
    if (toml_get_sections(doc, sections, TOML_MAX_SECTIONS, &section_count) != 0) {
        set_error(ERR_CONFIG_INVALID, "Failed to get sections from TOML document");
        return -1;
    }
    
    ctx->account_count = 0;
    
    for (size_t i = 0; i < section_count; i++) {
        if (string_starts_with(sections[i], "accounts.")) {
            account_t account;
            uint32_t account_id;
            char temp_str[256];
            bool temp_bool;
            
            /* Parse account ID from section name */
            if (parse_account_id_from_section(sections[i], &account_id) != 0) {
                log_warning("Invalid account section name: %s", sections[i]);
                continue;
            }
            
            /* Initialize account */
            memset(&account, 0, sizeof(account));
            account.id = account_id;
            account.preferred_scope = GIT_SCOPE_LOCAL; /* Default */
            
            /* Load required fields */
            if (toml_get_string(doc, sections[i], "name", account.name, sizeof(account.name)) != 0) {
                log_error("Account %u missing required 'name' field", account_id);
                continue;
            }
            
            if (toml_get_string(doc, sections[i], "email", account.email, sizeof(account.email)) != 0) {
                log_error("Account %u missing required 'email' field", account_id);
                continue;
            }
            
            /* Load optional fields */
            if (toml_get_string(doc, sections[i], "description", 
                               account.description, sizeof(account.description)) != 0) {
                /* Use name as description if not provided */
                safe_strncpy(account.description, account.name, sizeof(account.description));
            }
            
            if (toml_get_string(doc, sections[i], "preferred_scope", temp_str, sizeof(temp_str)) == 0) {
                account.preferred_scope = config_parse_scope(temp_str);
            }
            
            /* SSH configuration */
            if (toml_get_string(doc, sections[i], "ssh_key", 
                               account.ssh_key_path, sizeof(account.ssh_key_path)) == 0 &&
                strlen(account.ssh_key_path) > 0) {
                account.ssh_enabled = true;
                
                /* Expand path if needed */
                char expanded_path[MAX_PATH_LEN];
                if (expand_path(account.ssh_key_path, expanded_path, sizeof(expanded_path)) == 0) {
                    safe_strncpy(account.ssh_key_path, expanded_path, sizeof(account.ssh_key_path));
                }
                
                /* Optional SSH host alias */
                toml_get_string(doc, sections[i], "ssh_host", 
                               account.ssh_host_alias, sizeof(account.ssh_host_alias));
            }
            
            /* GPG configuration */
            if (toml_get_string(doc, sections[i], "gpg_key", 
                               account.gpg_key_id, sizeof(account.gpg_key_id)) == 0 &&
                strlen(account.gpg_key_id) > 0) {
                account.gpg_enabled = true;
                
                /* GPG signing preference */
                if (toml_get_boolean(doc, sections[i], "gpg_signing_enabled", &temp_bool) == 0) {
                    account.gpg_signing_enabled = temp_bool;
                }
            }
            
            /* Validate and add account */
            if (validate_account_security(&account) == 0) {
                if (ctx->account_count < MAX_ACCOUNTS) {
                    ctx->accounts[ctx->account_count] = account;
                    ctx->account_count++;
                    log_debug("Loaded account: %s (%s)", account.name, account.description);
                } else {
                    log_error("Too many accounts, skipping account %u", account_id);
                }
            } else {
                log_error("Account %u failed security validation", account_id);
            }
        }
    }
    
    log_info("Loaded %zu accounts from configuration", ctx->account_count);
    return 0;
}

/* Parse account ID from section name like "accounts.1" */
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id) {
    const char *dot_pos;
    char *endptr;
    unsigned long parsed_id;
    
    if (!section_name || !account_id) return -1;
    
    dot_pos = strchr(section_name, '.');
    if (!dot_pos || dot_pos == section_name + strlen(section_name) - 1) {
        return -1;
    }
    
    parsed_id = strtoul(dot_pos + 1, &endptr, 10);
    if (*endptr != '\0' || parsed_id == 0 || parsed_id > UINT32_MAX) {
        return -1;
    }
    
    *account_id = (uint32_t)parsed_id;
    return 0;
}

/* Validate account security */
static int validate_account_security(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];
    mode_t file_mode;
    
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to validate");
        return -1;
    }
    
    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account name: %s", account->name);
        return -1;
    }
    
    if (!validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address: %s", account->email);
        return -1;
    }
    
    /* Validate SSH key if configured */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (expand_path(account->ssh_key_path, expanded_path, sizeof(expanded_path)) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH key path: %s", account->ssh_key_path);
            return -1;
        }
        
        if (!path_exists(expanded_path)) {
            set_error(ERR_ACCOUNT_INVALID, "SSH key file not found: %s", expanded_path);
            return -1;
        }
        
        /* Check SSH key file permissions - must be 600 */
        if (get_file_permissions(expanded_path, &file_mode) == 0) {
            if ((file_mode & 077) != 0) {
                set_error(ERR_ACCOUNT_INVALID, 
                          "SSH key file has unsafe permissions: %o (should be 600)", 
                          file_mode & 0777);
                return -1;
            }
        }
    }
    
    /* Validate GPG key if configured */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (!validate_key_id(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    return 0;
}

/* Save accounts to TOML document */
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc) {
    char section_name[64];
    
    if (!ctx || !doc) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to save_accounts_to_toml");
        return -1;
    }
    
    /* Save each account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        
        /* Create section name */
        if ((size_t)snprintf(section_name, sizeof(section_name), "accounts.%u", account->id) >= sizeof(section_name)) {
            set_error(ERR_ACCOUNT_INVALID, "Account ID too large: %u", account->id);
            return -1;
        }
        
        /* Save required fields */
        if (toml_set_string(doc, section_name, "name", account->name) != 0) {
            set_error(ERR_CONFIG_INVALID, "Failed to save account name");
            return -1;
        }
        
        if (toml_set_string(doc, section_name, "email", account->email) != 0) {
            set_error(ERR_CONFIG_INVALID, "Failed to save account email");
            return -1;
        }
        
        /* Save optional fields */
        if (strlen(account->description) > 0) {
            toml_set_string(doc, section_name, "description", account->description);
        }
        
        toml_set_string(doc, section_name, "preferred_scope", 
                       config_scope_to_string(account->preferred_scope));
        
        /* Save SSH configuration */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            toml_set_string(doc, section_name, "ssh_key", account->ssh_key_path);
            
            if (strlen(account->ssh_host_alias) > 0) {
                toml_set_string(doc, section_name, "ssh_host", account->ssh_host_alias);
            }
        }
        
        /* Save GPG configuration */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            toml_set_string(doc, section_name, "gpg_key", account->gpg_key_id);
            toml_set_boolean(doc, section_name, "gpg_signing_enabled", account->gpg_signing_enabled);
        }
    }
    
    return 0;
}