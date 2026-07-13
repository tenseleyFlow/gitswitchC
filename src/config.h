/* Configuration file management and TOML parsing */

#ifndef CONFIG_H
#define CONFIG_H

#include "gitswitch.h"

/* Configuration file format version */
#define CONFIG_FORMAT_VERSION "1.0"

/* Default configuration template */
extern const char *default_config_template;

/* Focused allocation seam for the large TOML document. The default is
 * exactly malloc; test allocators must return free-compatible storage. Install
 * a replacement only around a bounded single-threaded test and restore the
 * returned prior function afterwards. */
typedef void *(*config_document_malloc_fn)(size_t size);
config_document_malloc_fn config_set_document_malloc_fn(
    config_document_malloc_fn fn);

/* Deterministic, single-threaded persistence seams used by the AR-07 T12
 * regression matrix. Production leaves both callbacks NULL. A fault callback
 * returns true to fail exactly at the named boundary; the implementation sets
 * errno=EIO and performs the same cleanup as a real syscall failure. */
typedef enum {
    CONFIG_IO_DEFAULT_AFTER_TEMP = 0,
    CONFIG_IO_DEFAULT_AFTER_WRITE,
    CONFIG_IO_DEFAULT_BEFORE_FILE_SYNC,
    CONFIG_IO_DEFAULT_BEFORE_CLOSE,
    CONFIG_IO_DEFAULT_BEFORE_RENAME,
    CONFIG_IO_DEFAULT_BEFORE_DIR_SYNC,
    CONFIG_IO_BACKUP_BEFORE_FILE_SYNC,
    CONFIG_IO_BACKUP_BEFORE_DIR_SYNC,
    CONFIG_IO_BACKUP_BEFORE_REOPEN,
    CONFIG_IO_DOCUMENT_BEFORE_RENAME,
    CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC,
    CONFIG_IO_STATE_AFTER_TEMP,
    CONFIG_IO_STATE_AFTER_WRITE,
    CONFIG_IO_STATE_BEFORE_FILE_SYNC,
    CONFIG_IO_STATE_BEFORE_CLOSE,
    CONFIG_IO_STATE_BEFORE_RENAME,
    CONFIG_IO_STATE_BEFORE_DIR_SYNC
} config_io_boundary_t;

typedef bool (*config_io_fault_fn)(config_io_boundary_t boundary);
config_io_fault_fn config_set_io_fault_fn(config_io_fault_fn fn);

/* Supplies the (seconds,nanoseconds) generation base for backup names. The
 * default reads CLOCK_REALTIME. Tests can pin both values to force collisions;
 * the writer still creates distinct monotonic generations with O_EXCL. */
typedef int (*config_backup_clock_fn)(uint64_t *seconds,
                                      uint32_t *nanoseconds);
config_backup_clock_fn config_set_backup_clock_fn(
    config_backup_clock_fn fn);

/* Function prototypes */

/**
 * Initialize configuration system
 * - Locates configuration file
 * - Creates default config if none exists
 * - Validates configuration format
 */
int config_init(gitswitch_ctx_t *ctx);

/**
 * Initialize configuration for preview-only inspection. Computes the normal
 * config path and loads an existing file, but never creates or chmods the
 * config directory or lock metadata.
 */
int config_init_readonly(gitswitch_ctx_t *ctx);

/**
 * Load the complete account document for `list --names` without creating or
 * chmod'ing configuration state, reading active-state artifacts, discovering
 * SSH/GPG runtime state, taking runtime locks, probing sockets/helpers, or
 * writing any path.
 */
int config_init_names(gitswitch_ctx_t *ctx);

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
/* Full-document transactional save. `config_installed` becomes true once the
 * new accounts.toml inode is renamed into place, including a later directory-
 * sync failure whose visible result must be treated as installed/uncertain. */
int config_save_transactional(const gitswitch_ctx_t *ctx,
                              const char *config_path,
                              bool *config_installed);

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
 * Persist ONLY the small active-state artifact (AR-07 L22). accounts.toml is
 * never reparsed or replaced for an ordinary switch/reset, so its bytes, inode,
 * and mtime remain unchanged. The artifact's first line remains the legacy
 * runtime-needs token consumed by shell integrations; its second line records
 * either the exact active account or a versioned inactive tombstone. Falls back
 * to config_save when no config exists.
 */
int config_save_active_account(const gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Write the path of the consolidated active-state/resume-hint file into buf.
 * Its first line is the shell integration's legacy runtime-needs token; a
 * versioned inactive tombstone uses `none`, so existing snippets remain no-op.
 * Returns 0 on success.
 */
int config_resume_hint_path(char *buf, size_t size);

/* Exact before-image for the consolidated active-state/resume-hint file. A CLI switch captures it
 * before runtime/Git mutation so a failed active-state commit can restore the
 * previous bytes (or previous absence) exactly. Snapshot values must be
 * zero-initialized before their first capture and cleared after final use. */
typedef struct {
    bool valid;
    bool existed;
    unsigned char *data;
    size_t length;
    unsigned int mode;
} config_resume_hint_snapshot_t;

int config_resume_hint_snapshot_capture(config_resume_hint_snapshot_t *snapshot);
int config_resume_hint_snapshot_restore(
    const config_resume_hint_snapshot_t *snapshot);
void config_resume_hint_snapshot_clear(config_resume_hint_snapshot_t *snapshot);

/* Transaction-aware active-account save. config_installed is true once the
 * new state-artifact inode has been renamed into place, even if its subsequent
 * directory sync fails. The rollback variant writes only that artifact;
 * callers may then restore the exact snapshot to recover legacy bytes/mode as
 * well. */
int config_save_active_account_transactional(const gitswitch_ctx_t *ctx,
                                             const char *config_path,
                                             bool *config_installed);
int config_restore_active_account(const gitswitch_ctx_t *ctx,
                                  const char *config_path);

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
 * Get the configuration file path (<config dir>/accounts.toml).
 * Builds the path only — it does NOT read environment variables and does NOT
 * create any directory (AR-06 F53: the old doc claimed both). Directory
 * creation is config_init/config_create_default's job.
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
 * Resolve a destructive command's target (remove/reset) by canonical ID, exact
 * name, or exact email ONLY — never by the substring/description match that
 * config_find_account also accepts (AR-06 F50). Sets a not-found error and
 * returns NULL when nothing matches exactly.
 */
account_t *config_find_account_destructive(gitswitch_ctx_t *ctx, const char *identifier);

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
