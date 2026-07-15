/* Configuration file management and TOML parsing */

#ifndef CONFIG_H
#define CONFIG_H

#include "gitswitch.h"
#include <dirent.h>

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
    /* Copy checkpoint after the first complete source chunk has been written.
     * A test callback may mutate the source and return false; the copy must
     * reject the now-unstable generation during its final descriptor proof. */
    CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK,
    CONFIG_IO_BACKUP_BEFORE_DIR_SYNC,
    CONFIG_IO_BACKUP_BEFORE_REOPEN,
    CONFIG_IO_DOCUMENT_BEFORE_RENAME,
    CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC,
    CONFIG_IO_STATE_AFTER_TEMP,
    CONFIG_IO_STATE_AFTER_WRITE,
    CONFIG_IO_STATE_BEFORE_FILE_SYNC,
    CONFIG_IO_STATE_BEFORE_CLOSE,
    CONFIG_IO_STATE_BEFORE_RENAME,
    CONFIG_IO_STATE_BEFORE_DIR_SYNC,
    /* Read-side consistency checkpoint. A test callback may mutate the
     * descriptor's backing file and return false; production leaves the
     * callback NULL. */
    CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ
} config_io_boundary_t;

typedef bool (*config_io_fault_fn)(config_io_boundary_t boundary);
config_io_fault_fn config_set_io_fault_fn(config_io_fault_fn fn);

/* Focused metadata-mismatch observer for deterministic errno regressions.
 * A callback returns true to model a pure identity mismatch after every
 * required filesystem observation has succeeded. Production leaves it NULL. */
typedef enum {
    CONFIG_METADATA_TEST_REFRESH_INITIAL = 1,
    CONFIG_METADATA_TEST_REFRESH_FINAL,
    CONFIG_METADATA_TEST_DOCUMENT_DIR,
    CONFIG_METADATA_TEST_DEFAULT_DIR
} config_metadata_test_stage_t;
typedef bool (*config_metadata_test_hook_fn)(
    config_metadata_test_stage_t stage);
config_metadata_test_hook_fn config_set_metadata_test_hook_fn(
    config_metadata_test_hook_fn fn);

/* Supplies the (seconds,nanoseconds) generation base for backup names. The
 * default reads CLOCK_REALTIME. Tests can pin both values to force collisions;
 * the writer still creates distinct monotonic generations with O_EXCL. */
typedef int (*config_backup_clock_fn)(uint64_t *seconds,
                                      uint32_t *nanoseconds);
config_backup_clock_fn config_set_backup_clock_fn(
    config_backup_clock_fn fn);

/* Narrow directory-enumeration seam for backup-rotation failure tests. NULL
 * restores libc readdir(). Production callers leave the default installed. */
typedef struct dirent *(*config_backup_readdir_fn)(DIR *dir);
config_backup_readdir_fn config_set_backup_readdir_fn(
    config_backup_readdir_fn fn);

/* Function prototypes */

/**
 * Initialize configuration system
 * - Resolves and stores the normal configuration path
 * - Creates or secures the private configuration directory
 * - Loads and validates accounts.toml when it already exists
 * - Leaves first-file creation to the first successful save
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
 *
 * Every public save acquires a nonblocking, destination-local publication lock
 * before observing or changing the state/config pair and holds it through the
 * final rename, rollback, and durability checks. Concurrent gitswitch/API
 * writers therefore fail with EAGAIN/EWOULDBLOCK instead of losing a committed
 * generation. Same-uid code that writes these paths without using this API is
 * outside the cooperating-writer protocol: strict metadata checks detect such
 * changes through the final pre-rename checkpoint, so the unsupported race is
 * explicitly bounded to the last check-to-rename interval.
 */
int config_save(gitswitch_ctx_t *ctx, const char *config_path);
/* Full-document transactional save. `config_installed` becomes true once the
 * new accounts.toml inode is renamed into place, including a later directory-
 * sync failure whose visible result must be treated as installed/uncertain.
 * On complete durable success, the mutable context is rebound to the exact
 * installed source generation so another save from that context is admitted. */
int config_save_transactional(gitswitch_ctx_t *ctx,
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
 * to config_save when no config exists. For an existing config, the context
 * must come from a successful load of that exact path and the source generation
 * must still be installed; otherwise the save fails closed. If accounts.toml
 * is absent, this entry point performs the required full first save and then
 * binds the mutable context to that newly installed source generation.
 */
int config_save_active_account(gitswitch_ctx_t *ctx, const char *config_path);

/**
 * Write the path of the consolidated active-state/resume-hint file into buf.
 * Its first line is the shell integration's legacy runtime-needs token; a
 * versioned inactive tombstone uses `none`, so existing snippets remain no-op.
 * Returns 0 on success.
 */
int config_resume_hint_path(char *buf, size_t size);

/* Read-only login-shell probe for the consolidated active-state artifact.
 * Missing state normalizes to "none". A safe, self-owned 0600 regular file is
 * parsed with the same exact grammar as config load; unsafe or malformed state
 * fails with no output value. */
int config_resume_hint_probe(char *needs, size_t size);

/* Exact before-image for the consolidated active-state/resume-hint file. A CLI
 * switch captures it before runtime/Git mutation so a failed active-state
 * commit can restore the previous bytes (or previous absence) exactly.
 * Guarded transactional saves also bind the snapshot to the exact post-image
 * they installed; restore then fails closed if any later generation replaced
 * or rewrote that post-image. Snapshot values must be zero-initialized before
 * their first capture and cleared after final use. */
typedef struct {
    bool valid;
    bool existed;
    unsigned char *data;
    size_t length;
    unsigned int mode;
    char config_path[MAX_PATH_LEN];
    bool post_image_bound;
    bool post_image_installed;
    bool post_image_valid;
    struct stat post_image;
    unsigned char post_image_data[MAX_NAME_LEN + 32U];
    size_t post_image_length;
} config_resume_hint_snapshot_t;

int config_resume_hint_snapshot_capture(config_resume_hint_snapshot_t *snapshot);
/* Restore accepts only a snapshot subsequently bound by
 * config_save_active_account_transactional_guarded (or the internal full-save
 * transaction). An unbound snapshot cannot identify which later state belongs
 * to its caller and is rejected instead of overwriting it. */
int config_resume_hint_snapshot_restore(
    const config_resume_hint_snapshot_t *snapshot);
void config_resume_hint_snapshot_clear(config_resume_hint_snapshot_t *snapshot);

/* Transaction-aware active-account save. config_installed is true once the
 * new state-artifact inode has been renamed into place, even if its subsequent
 * directory sync fails. Use the guarded variant when later transaction phases
 * may need to restore an exact snapshot. */
int config_save_active_account_transactional(gitswitch_ctx_t *ctx,
                                             const char *config_path,
                                             bool *config_installed);
/* Switch-transaction variant: rollback_snapshot must be a valid before-image
 * captured for config_path. The save records its installed state generation in
 * that snapshot so config_resume_hint_snapshot_restore can perform a guarded
 * compare-before-restore instead of overwriting a later writer. */
int config_save_active_account_transactional_guarded(
    gitswitch_ctx_t *ctx, const char *config_path,
    bool *config_installed,
    config_resume_hint_snapshot_t *rollback_snapshot);
int config_restore_active_account(gitswitch_ctx_t *ctx,
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
 * Validate only the account model's flag/value relationships. This shared
 * lossless-state gate does not inspect key files or prove key availability.
 */
int config_validate_account_model(const account_t *account);

/**
 * Get the configuration file path (<config dir>/accounts.toml).
 * Resolves the home directory from HOME when it is set, otherwise from the
 * current user's password-database entry, and builds the path only. This query
 * does not create, chmod, or otherwise modify any filesystem object; directory
 * creation and security repair belong to config_init/config_create_default.
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

#endif /* CONFIG_H */
