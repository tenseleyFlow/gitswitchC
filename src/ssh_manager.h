/* SSH key and agent management with proper isolation */

#ifndef SSH_MANAGER_H
#define SSH_MANAGER_H

#include <sys/types.h> /* pid_t: don't rely on the includer's chain for it */

#include "gitswitch.h"

/* SSH agent management modes */
typedef enum {
    SSH_AGENT_SYSTEM,      /* Use system SSH agent */
    SSH_AGENT_ISOLATED,    /* Use isolated SSH agent per account */
    SSH_AGENT_NONE         /* No SSH agent management */
} ssh_agent_mode_t;

/* SSH configuration structure */
typedef struct {
    ssh_agent_mode_t mode;
    char agent_socket_path[MAX_PATH_LEN];
    pid_t agent_pid;
    bool agent_owned;      /* Whether we started this agent */
    bool key_already_loaded; /* Reused a live agent that already holds the key;
                              * caller can skip ssh_add_key (avoids a passphrase
                              * re-prompt on re-switching to the active account) */
} ssh_config_t;

typedef int (*ssh_setenv_fn)(const char *name, const char *value, int overwrite);

/* Function prototypes */

/**
 * Initialize SSH manager with specified mode
 */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode);

/**
 * Cleanup SSH manager, stopping owned agents
 */
void ssh_manager_cleanup(ssh_config_t *ssh_config);

/**
 * Switch to account's SSH configuration with proper isolation
 * - Clears current SSH agent keys if using isolated mode
 * - Loads account's SSH key into appropriate agent
 * - Updates SSH_AUTH_SOCK environment if needed
 * - Validates key is properly loaded
 */
int ssh_switch_account(ssh_config_t *ssh_config, const account_t *account);

/**
 * Start isolated SSH agent for account
 * Returns socket path and PID for cleanup
 */
int ssh_start_isolated_agent(ssh_config_t *ssh_config, const account_t *account);

/**
 * Replace the environment setter used by the SSH runtime commit and return
 * the previous function. This is a deterministic test seam; pass NULL to
 * restore libc setenv. Runtime rollback itself is not routed through the seam.
 */
ssh_setenv_fn ssh_manager_set_setenv_fn(ssh_setenv_fn fn);

/**
 * Stop SSH agent (only if we own it)
 */
int ssh_stop_agent(ssh_config_t *ssh_config);

/**
 * Clear all keys from SSH agent
 */
int ssh_clear_agent_keys(ssh_config_t *ssh_config);

/**
 * Add key to SSH agent with validation
 * - Verifies key file exists and has correct permissions
 * - Loads key into agent
 * - Confirms key was loaded successfully
 */
int ssh_add_key(ssh_config_t *ssh_config, const char *key_path);

/**
 * List loaded SSH keys for verification
 */
int ssh_list_keys(ssh_config_t *ssh_config, char *output, size_t output_size);

/**
 * Validate SSH key file permissions and format
 */
int ssh_validate_key_file(const char *key_path);

/**
 * Set SSH host alias in ~/.ssh/config if specified
 */
int ssh_configure_host_alias(const account_t *account);

/**
 * Test SSH connection to verify authentication
 */
int ssh_test_connection(const account_t *account, const char *host);

/**
 * Write the stable SSH_AUTH_SOCK symlink path to buf.
 * Uses $XDG_RUNTIME_DIR/gitswitch-ssh/current.sock when XDG_RUNTIME_DIR is set,
 * otherwise /tmp/gitswitch-ssh-<uid>/current.sock. Shared by runtime switch
 * logic and the `init` shell-integration command so both agree on the path.
 * Returns 0 on success, -1 if the computed path would overflow buf.
 */
int ssh_manager_get_auth_sock_path(char *buf, size_t buf_size);

/**
 * Tear down isolated SSH agents (kill by recorded PID and remove sockets/PID
 * sidecars). Resets a single account when `account` is non-NULL, or all
 * accounts when NULL. Returns 0 on success.
 */
int ssh_manager_reset(const char *account);

#endif /* SSH_MANAGER_H */
