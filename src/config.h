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
 * Returns -1 (with the error set) when it REFUSES to rewrite because the load
 * skipped account sections or found unrecognized ones (AR-03 M9): the refusal
 * must be distinguishable from success or callers report "saved" for a change
 * that was silently discarded.
 */
int config_save(const gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Fail-closed gate shared by config_save and the mutating-command handlers
 * (AR-03 M8/M9): returns 0 when the in-memory account set is a complete view
 * of the on-disk file, or -1 (with the error set to the reason) when sections
 * were skipped or unrecognized at load time — a full rewrite would silently
 * erase them. Check it BEFORE interactive add/edit/remove work so the user is
 * refused with the reason up front, not after answering every prompt.
 */
int config_check_rewritable(const gitswitch_ctx_t *ctx);

/**
 * Persist ONLY settings.active_account (AR-03 M9): parses the on-disk file and
 * writes it back with just that one key updated, so a switch (or a reset that
 * cleared the active account) can record its result even when the load skipped
 * account sections — the write-back re-emits every parsed section, including
 * skipped and unrecognized ones, instead of rebuilding from the in-memory view
 * the way config_save does. Falls back to config_save when no file exists yet.
 */
int config_save_active_account(const gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Write the path of the "resume hint" marker into buf. The marker exists iff
 * there is a saved active account worth resuming after boot; the shell
 * integration tests for it so a machine that has never switched doesn't spawn
 * `gitswitch resume` on every interactive shell. Returns 0 on success.
 */
int config_resume_hint_path(char *buf, size_t size);

/**
 * Acquire an exclusive cross-process lock for a mutating config cycle without
 * waiting for a current holder. Returns an opaque lock token retaining the
 * config parent, directory, and legacy .config.lock inode across the whole
 * load-modify-save cycle so concurrent writers cannot split their lock domain
 * by replacing a pathname. Release it with config_write_unlock(). Returns -1
 * on failure with errno preserved (EAGAIN/EWOULDBLOCK means contention).
 */
int config_write_lock(void);
void config_write_unlock(int token_fd);

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
 * Find account by EXACT name only, for the boot-resume path (AR-06 F22): the
 * persisted active_account is always an exact name and must not be re-resolved
 * through config_find_account's id-first fuzzy matching.
 */
account_t *config_find_account_exact(gitswitch_ctx_t *ctx, const char *name);

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
