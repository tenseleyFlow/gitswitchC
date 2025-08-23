/* Git configuration operations */

#ifndef GIT_OPS_H
#define GIT_OPS_H

#include "gitswitch.h"

/* Git configuration keys */
#define GIT_CONFIG_USER_NAME "user.name"
#define GIT_CONFIG_USER_EMAIL "user.email"
#define GIT_CONFIG_USER_SIGNINGKEY "user.signingkey"
#define GIT_CONFIG_COMMIT_GPGSIGN "commit.gpgsign"
#define GIT_CONFIG_GPG_PROGRAM "gpg.program"
#define GIT_CONFIG_CORE_SSHCOMMAND "core.sshcommand"

/* Current git configuration */
typedef struct {
    char name[MAX_NAME_LEN];
    char email[MAX_EMAIL_LEN];
    char signing_key[MAX_KEY_ID_LEN];
    bool gpg_signing_enabled;
    git_scope_t scope;
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

/**
 * Clear git configuration (unset values)
 */
int git_clear_config(git_scope_t scope);

/**
 * Validate git repository
 * - Checks if current directory is a git repository
 * - Verifies repository is not bare
 * - Checks repository health
 */
int git_validate_repository(void);

/**
 * Get git configuration scope (local, global, system)
 * Returns the scope where the configuration is currently set
 */
git_scope_t git_get_config_scope(const char *config_key);

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