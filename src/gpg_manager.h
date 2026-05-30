/* GPG key management with proper isolation and signing configuration */

#ifndef GPG_MANAGER_H
#define GPG_MANAGER_H

#include "gitswitch.h"

/* GPG management modes */
typedef enum {
    GPG_MODE_SYSTEM,       /* Use system GPG configuration */
    GPG_MODE_ISOLATED,     /* Use isolated GNUPGHOME per account */
    GPG_MODE_SHARED        /* Shared GNUPGHOME with key switching */
} gpg_mode_t;

/* GPG configuration structure */
typedef struct {
    gpg_mode_t mode;
    char gnupg_home[MAX_PATH_LEN];    /* GNUPGHOME path */
    char current_key_id[MAX_KEY_ID_LEN];
    bool signing_enabled;
    bool home_owned;       /* Whether we created this GNUPGHOME */
} gpg_config_t;

/* Function prototypes */

/**
 * Initialize GPG manager with specified mode
 */
int gpg_manager_init(gpg_config_t *gpg_config, gpg_mode_t mode);

/**
 * Cleanup GPG manager
 */
void gpg_manager_cleanup(gpg_config_t *gpg_config);

/**
 * Switch to account's GPG configuration with proper isolation
 * - Sets appropriate GNUPGHOME if using isolated mode
 * - Configures git signing key
 * - Enables/disables git commit signing
 * - Validates key exists and is usable
 */
int gpg_switch_account(gpg_config_t *gpg_config, const account_t *account);

/**
 * Create isolated GNUPGHOME for account
 * - Creates directory with proper permissions (700)
 * - Imports account's GPG key if available
 * - Sets up basic GPG configuration
 */
int gpg_create_isolated_home(gpg_config_t *gpg_config, const account_t *account);

/**
 * Import GPG key from file or keyserver
 * - Supports ASCII-armored and binary key formats
 * - Validates key after import
 * - Sets trust level appropriately
 */
int gpg_import_key(gpg_config_t *gpg_config, const char *key_source);

/**
 * Export GPG public key for backup/sharing
 */
int gpg_export_public_key(gpg_config_t *gpg_config, const char *key_id, 
                          char *output, size_t output_size);

/**
 * List available GPG keys
 */
int gpg_list_keys(gpg_config_t *gpg_config, char *output, size_t output_size);

/**
 * Validate GPG key exists and is usable
 * - Checks key exists in keyring
 * - Verifies key is not expired
 * - Tests signing capability if required
 */
int gpg_validate_key(gpg_config_t *gpg_config, const char *key_id);

/**
 * Configure git GPG signing
 * - Sets user.signingkey
 * - Enables/disables commit.gpgsign
 * - Sets gpg.program if needed
 */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, 
                              git_scope_t scope);

/**
 * Test GPG signing by creating a test signature
 */
int gpg_test_signing(gpg_config_t *gpg_config, const char *key_id);

/**
 * Generate new GPG key for account
 * - Creates key with account name and email
 * - Uses secure key parameters
 * - Exports public key for verification
 */
int gpg_generate_key(gpg_config_t *gpg_config, const account_t *account);

/**
 * Set environment variables for GPG operation
 */
int gpg_set_environment(const gpg_config_t *gpg_config);

/**
 * Compute the stable GNUPGHOME path (a `current` symlink under the isolated
 * GPG base directory) that `gitswitch init` exports into the shell and that
 * each switch retargets to the active account's home. Uses
 * $XDG_RUNTIME_DIR/gitswitch-gpg/current, else /tmp/gitswitch-gpg-<uid>/current.
 * Shared by the runtime switch logic and the `init` command so both agree.
 * Returns 0 on success, -1 if the computed path would overflow buf.
 */
int gpg_manager_get_home_path(char *buf, size_t size);

/**
 * Tear down isolated GPG homes (kill per-home gpg-agents and delete the homes,
 * wiping on-disk secret-key copies). Resets a single account when `account` is
 * non-NULL, or all accounts when NULL. Returns 0 on success.
 */
int gpg_manager_reset(const char *account);

#endif /* GPG_MANAGER_H */