/* SSH key and agent management with proper isolation */

#ifndef SSH_MANAGER_H
#define SSH_MANAGER_H

#include <stdint.h>
#include <sys/types.h> /* pid_t: don't rely on the includer's chain for it */

#include "gitswitch.h"

/* AR-06 F29: the host-alias reader/writer once hard-capped ~/.ssh/config at
 * 64 KiB and failed the whole switch for any account with an alias when the
 * user's config was larger. The buffers are now heap-sized to the file; this
 * ceiling only guards against a pathological/hostile giant file and is set well
 * beyond any realistic ssh config. Shared by the writer (ssh_manager.c) and the
 * switch preflight (accounts.c) so the two never disagree. */
#define GITSWITCH_SSH_CONFIG_MAX_BYTES (8u * 1024u * 1024u)

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
    char agent_socket_arg[MAX_PATH_LEN]; /* exact -a argument used to start it */
    pid_t agent_pid;
    bool agent_owned;      /* Whether we started this agent */
    bool key_already_loaded; /* The isolated agent already holds the account key;
                              * reuse avoids a passphrase re-prompt. */
} ssh_config_t;

typedef int (*ssh_setenv_fn)(const char *name, const char *value, int overwrite);
typedef bool (*ssh_reap_fn)(pid_t pid, const char *socket_arg);
typedef int (*ssh_pid_commit_hook_fn)(int dir_fd, const char *temp_name);
typedef int (*ssh_namespace_commit_hook_fn)(int dir_fd);
typedef int (*ssh_dirsync_fn)(int dir_fd);
typedef int (*ssh_config_commit_hook_fn)(int dir_fd, const char *temp_name);
typedef int (*ssh_current_cleanup_hook_fn)(int dir_fd);
typedef int (*ssh_current_precleanup_hook_fn)(int dir_fd);
typedef int (*ssh_current_publish_hook_fn)(int dir_fd);
typedef int (*ssh_quarantine_hook_fn)(int dir_fd, const char *name);
typedef int (*ssh_key_open_fn)(const char *path, int flags);
typedef int64_t (*ssh_probe_clock_fn)(void);
typedef int (*ssh_probe_poll_fn)(int fd, int timeout_ms);

/* One descriptor-backed view of an SSH key file. Status callers can reuse
 * these fields instead of independently resolving, statting, and reopening a
 * pathname that may change between checks. */
typedef struct {
    bool exists;
    bool regular;
    bool owned_by_user;
    bool secure_permissions;
    bool private_key;
    mode_t mode;
} ssh_key_inspection_t;

/* Function prototypes */

/**
 * Initialize SSH manager with specified mode
 */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode);

/**
 * Cleanup SSH manager, stopping owned agents
 */
int ssh_manager_cleanup(ssh_config_t *ssh_config);

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

/* Deterministic failure/race seams used by the adversarial runtime tests. */
ssh_reap_fn ssh_manager_set_reap_fn(ssh_reap_fn fn);
ssh_pid_commit_hook_fn ssh_manager_set_pid_commit_hook_fn(
    ssh_pid_commit_hook_fn fn);
ssh_pid_commit_hook_fn ssh_manager_set_pid_postrename_hook_fn(
    ssh_pid_commit_hook_fn fn);
ssh_namespace_commit_hook_fn ssh_manager_set_namespace_commit_hook_fn(
    ssh_namespace_commit_hook_fn fn);
ssh_dirsync_fn ssh_manager_set_dirsync_fn(ssh_dirsync_fn fn);
/* Test-only pre-rename seam for SSH user-config namespace races. Production
 * leaves it NULL; the callback receives the pinned ~/.ssh fd and temp name. */
ssh_config_commit_hook_fn ssh_manager_set_config_commit_hook_fn(
    ssh_config_commit_hook_fn fn);
ssh_current_cleanup_hook_fn ssh_manager_set_current_cleanup_hook_fn(
    ssh_current_cleanup_hook_fn fn);
ssh_current_precleanup_hook_fn ssh_manager_set_current_precleanup_hook_fn(
    ssh_current_precleanup_hook_fn fn);
ssh_current_publish_hook_fn ssh_manager_set_current_publish_hook_fn(
    ssh_current_publish_hook_fn fn);
ssh_quarantine_hook_fn ssh_manager_set_quarantine_hook_fn(
    ssh_quarantine_hook_fn fn);
ssh_quarantine_hook_fn ssh_manager_set_quarantine_capture_hook_fn(
    ssh_quarantine_hook_fn fn);
bool ssh_manager_set_force_portable_quarantine(bool force);
ssh_key_open_fn ssh_manager_set_key_open_fn(ssh_key_open_fn fn);
ssh_probe_clock_fn ssh_manager_set_probe_clock_fn(ssh_probe_clock_fn fn);
ssh_probe_poll_fn ssh_manager_set_probe_poll_fn(ssh_probe_poll_fn fn);

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
 * Inspect one key through one O_NOFOLLOW descriptor. A missing path is a
 * successful inspection with exists=false; unsafe/unreadable namespace state
 * is an error. The descriptor supplies metadata and content, eliminating
 * path-revalidation races and repeated opens in status/health callers.
 */
int ssh_inspect_key_file(const char *key_path,
                         ssh_key_inspection_t *inspection);

/* Focused adversarial test surfaces. They route through the same internal
 * implementations used by production and do not weaken production defaults. */
bool ssh_manager_test_socket_has_key(int dir_fd, const char *socket_arg,
                                     const char *key_path);
int ssh_manager_test_write_pid_sidecar(int dir_fd, const char *name,
                                       pid_t pid);
int ssh_manager_test_publish_current_link(int dir_fd, const char *target);
int ssh_manager_test_cleanup_current_link(int dir_fd);
int ssh_manager_test_probe_socket(const char *path, bool *reachable);
int ssh_manager_test_probe_deadline(int timeout_ms);

/**
 * Set SSH host alias in ~/.ssh/config if specified. An alias requires a valid
 * account->ssh_hostname canonical destination; it is emitted as HostName.
 */
int ssh_configure_host_alias(const account_t *account);

/**
 * Remove the managed host-alias block for `alias` from ~/.ssh/config (AR-06
 * F15). No-op if the config or the block is absent. Returns 0 on success
 * (including no-op), -1 on I/O failure.
 */
int ssh_remove_host_alias(const char *alias);

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
 * Inspect the stable isolated-agent entry point and return its account name.
 * The private SSH runtime directory is inspected under the manager lock, and
 * current.sock must be a stable symlink to an exact same-directory
 * ssh-agent.<name>.sock entry backed by a live, user-owned 0600 socket.
 *
 * Returns 0 with `*present == false` when the managed directory or current.sock
 * is absent. Returns 0 with `*present == true` and a NUL-terminated name for a
 * valid live account. Unsafe, malformed, stale, changed, or truncated state is
 * an error and returns -1 without publishing a name.
 */
int ssh_manager_get_current_account(char *name, size_t name_size, bool *present);

/**
 * Return whether current.sock names this exact account and its agent holds
 * exactly the configured key (one matching identity, no extras). The complete
 * inspection is performed under the SSH runtime lock. Missing, empty,
 * wrong-account, wrong-key, extra-key, and otherwise unproven identity state
 * returns success with `*live == false` so callers fail closed into a restore.
 * Invalid arguments and unsafe/indeterminate runtime namespace state return
 * -1.
 */
int ssh_manager_current_is_live_for_account(const account_t *account,
                                            bool *live);

/**
 * Tear down isolated SSH agents (kill by recorded PID and remove sockets/PID
 * sidecars). Resets a single account when `account` is a nonempty name
 * accepted by validate_name(); callers must pass the canonical stored account
 * name. Resets all accounts only when `account` is NULL. Invalid non-NULL
 * input fails with ERR_INVALID_ARGS before runtime I/O. Returns 0 on success.
 */
int ssh_manager_reset(const char *account);

#endif /* SSH_MANAGER_H */
