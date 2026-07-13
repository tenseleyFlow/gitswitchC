/* Git configuration operations */

#ifndef GIT_OPS_H
#define GIT_OPS_H

#include "gitswitch.h"

/* Git configuration keys */
#define GIT_CONFIG_USER_NAME "user.name"
#define GIT_CONFIG_USER_EMAIL "user.email"
#define GIT_CONFIG_USER_SIGNINGKEY "user.signingkey"
#define GIT_CONFIG_COMMIT_GPGSIGN "commit.gpgsign"
#define GIT_CONFIG_GPG_FORMAT "gpg.format"
#define GIT_CONFIG_GPG_PROGRAM "gpg.program"
#define GIT_CONFIG_GPG_OPENPGP_PROGRAM "gpg.openpgp.program"
#define GIT_CONFIG_GPG_X509_PROGRAM "gpg.x509.program"
#define GIT_CONFIG_GPG_SSH_PROGRAM "gpg.ssh.program"
#define GIT_CONFIG_CORE_SSHCOMMAND "core.sshcommand"

/* Largest managed value emitted by gitswitch. core.sshCommand contains two
 * inputs shorter than MAX_PATH_LEN. A canonical executable can consist
 * entirely of apostrophes, so POSIX single-quote serialization needs at most
 * 4 * (MAX_PATH_LEN - 1) bytes for it. is_safe_ssh_key_path() rejects quotes,
 * so its serialized key contributes at most MAX_PATH_LEN - 1 bytes. The 256
 * bytes cover both pairs of quote delimiters, fixed options, and the NUL.
 * Public status records and the scalar cache use this lossless capacity;
 * transactional snapshots remain dynamically allocated for arbitrary foreign
 * values. */
#define GIT_CONFIG_VALUE_MAX (MAX_PATH_LEN * 5 + 256)

typedef enum {
    GIT_CONFIG_ORIGIN_UNKNOWN = 0,
    GIT_CONFIG_ORIGIN_SYSTEM,
    GIT_CONFIG_ORIGIN_GLOBAL,
    GIT_CONFIG_ORIGIN_LOCAL,
    GIT_CONFIG_ORIGIN_WORKTREE,
    GIT_CONFIG_ORIGIN_COMMAND
} git_config_origin_scope_t;

typedef struct {
    char value[GIT_CONFIG_VALUE_MAX];
    char origin[MAX_PATH_LEN];
    git_config_origin_scope_t scope;
    bool present;
    bool value_unknown;
} git_config_effective_value_t;

/* Current git configuration */
typedef struct {
    char name[MAX_NAME_LEN];
    char email[MAX_EMAIL_LEN];
    char signing_key[MAX_GPG_FINGERPRINT_LEN];
    bool gpg_signing_enabled;
    git_scope_t scope;
    git_config_origin_scope_t effective_name_scope;
    char effective_name_origin[MAX_PATH_LEN];
    git_config_effective_value_t ssh_command;
    git_config_effective_value_t gpg_program;
    bool valid;
} git_current_config_t;

/* Function prototypes */

/**
 * Initialize git operations
 * - Verify git is available
 * - Check git version compatibility
 * - Validate current repository if in local scope
 */
int git_ops_init(void);

/**
 * Set git configuration for account
 * - Sets user.name and user.email
 * - Configures GPG signing if enabled
 * - Sets SSH command if custom SSH configuration needed
 * - Validates configuration was set correctly
 */
int git_set_config(const account_t *account, git_scope_t scope);

/**
 * Get current git configuration
 * - Reads current user.name and user.email
 * - Gets GPG signing configuration
 * - Determines configuration scope
 * - Returns structured configuration data
 */
int git_get_current_config(git_current_config_t *config);

/** Return a stable display name for an effective Git configuration scope. */
const char *git_config_origin_scope_to_string(git_config_origin_scope_t scope);

/**
 * Build the exact core.sshCommand expected for an SSH-enabled account.
 * This resolves `ssh` through the hardened executable trust walk, expands the
 * key path, and serializes both absolute arguments safely. It does not require
 * the key file to exist, so read-only status can compare persisted Git state
 * without introducing a filesystem mutation.
 */
int git_expected_ssh_command(const account_t *account, char *command,
                             size_t command_size);

/**
 * Clear git configuration (unset values)
 */
int git_clear_config(git_scope_t scope);

/**
 * Snapshot the gitswitch-managed config keys (identity/signing keys,
 * gpg.format, every Git-supported GPG program selector, and core.sshCommand)
 * at `scope` before a switch mutates them, plus the LOCAL scope when a global
 * write would clear it and any distinct WORKTREE override scope. Every
 * repeated value is retained in order. Included managed values are refused
 * when their origin cannot be restored exactly. Pair with
 * git_config_restore() to roll back on a failed switch. Single snapshot slot
 * (the CLI is single-threaded); a new snapshot replaces the previous.
 */
int git_config_snapshot(git_scope_t scope);

/**
 * Restore the most recent git_config_snapshot(), rebuilding every key with its
 * exact ordered values. A failed restore retains the snapshot and completed
 * per-key progress for retry. No-op if nothing was snapshotted.
 */
int git_config_restore(void);

/* AR-06 F59: git_validate_repository() and git_get_config_scope() were removed
 * — dead public API with zero callers. */

/**
 * Test git configuration
 * - Creates a test commit (dry-run)
 * - Validates signing if enabled
 * - Verifies SSH access to remotes if applicable
 */
int git_test_config(const account_t *account, git_scope_t scope);

/**
 * Set single git configuration value
 */
int git_set_config_value(const char *key, const char *value, git_scope_t scope);

/**
 * Get single git configuration value
 */
int git_get_config_value(const char *key, char *value, size_t value_size, 
                         git_scope_t scope);

/**
 * Unset git configuration value
 */
int git_unset_config_value(const char *key, git_scope_t scope);

/**
 * List all git configuration values for debugging
 */
int git_list_config(git_scope_t scope, char *output, size_t output_size);

/**
 * Configure SSH command for git operations
 * - Sets core.sshCommand to use specific SSH key
 * - Handles SSH agent socket specification
 * - Configures SSH options for security
 */
int git_configure_ssh(const account_t *account, git_scope_t scope);

/**
 * Configure GPG for git operations
 * - Sets user.signingkey
 * - Enables/disables commit.gpgsign
 * - Sets gpg.program if using custom GPG
 */
int git_configure_gpg(const account_t *account, git_scope_t scope);

/**
 * Check if current directory is a git repository
 */
bool git_is_repository(void);

/**
 * Get repository root directory
 */
int git_get_repo_root(char *path, size_t path_size);

/**
 * Convert scope enum to git config scope string
 */
const char *git_scope_to_flag(git_scope_t scope);

#endif /* GIT_OPS_H */
