/* Configuration file management and TOML parsing */

#ifndef CONFIG_H
#define CONFIG_H

#include "gitswitch.h"

/* Configuration file format version */
#define CONFIG_FORMAT_VERSION "1.0"

/* Default configuration template */
extern const char *default_config_template;

/* Function prototypes */

/**
 * Initialize configuration system
 * - Locates configuration file
 * - Creates default config if none exists
 * - Validates configuration format
 */
int config_init(gitswitch_ctx_t *ctx);

/**
 * Load configuration from TOML file
 * - Parses TOML configuration
 * - Validates all required fields
 * - Populates gitswitch_ctx_t structure
 */
int config_load(gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Save configuration to TOML file
 * - Creates backup of existing config
 * - Writes updated configuration
 * - Validates written file
 */
int config_save(const gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Create default configuration file
 */
int config_create_default(const char *config_path);

/**
 * Validate configuration structure
 * - Checks all required fields are present
 * - Validates account data integrity
 * - Verifies file paths exist and are accessible
 */
int config_validate(const gitswitch_ctx_t *ctx);

/**
 * Get configuration file path
 * - Checks environment variables
 * - Falls back to default location
 * - Creates directories if needed
 */
int config_get_path(char *path_buffer, size_t buffer_size);

/**
 * Add new account to configuration
 */
int config_add_account(gitswitch_ctx_t *ctx, const account_t *account);

/**
 * Remove account from configuration
 */
int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id);

/**
 * Update existing account in configuration
 */
int config_update_account(gitswitch_ctx_t *ctx, const account_t *account);

/**
 * Find account by ID or name/description
 */
account_t *config_find_account(gitswitch_ctx_t *ctx, const char *identifier);

/**
 * Parse git scope from string
 */
git_scope_t config_parse_scope(const char *scope_str);

/**
 * Convert git scope to string
 */
const char *config_scope_to_string(git_scope_t scope);

/**
 * Backup configuration file with timestamp
 */
int config_backup(const char *config_path);

/**
 * Migrate configuration from older format versions
 */
int config_migrate(const char *config_path);

#endif /* CONFIG_H */