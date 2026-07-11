/* GPG key management with proper isolation and signing configuration */

#ifndef GPG_MANAGER_H
#define GPG_MANAGER_H

#include "gitswitch.h"
#include <dirent.h>

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

/* Narrow dependency seams for deterministic filesystem-race/error tests. The
 * defaults are libc readdir() and no pre-open callback, respectively. */
typedef struct dirent *(*gpg_readdir_fn)(DIR *dir);
typedef void (*gpg_agent_conf_preopen_fn)(const char *path);
typedef int (*gpg_agent_conf_precommit_fn)(int home_fd,
                                            const char *temp_name);
typedef int (*gpg_retarget_commit_hook_fn)(int base_fd);
gpg_readdir_fn gpg_manager_set_readdir_fn(gpg_readdir_fn fn);
gpg_agent_conf_preopen_fn
gpg_manager_set_agent_conf_preopen_fn(gpg_agent_conf_preopen_fn fn);
gpg_agent_conf_precommit_fn
gpg_manager_set_agent_conf_precommit_fn(gpg_agent_conf_precommit_fn fn);
gpg_retarget_commit_hook_fn
gpg_manager_set_retarget_commit_hook_fn(gpg_retarget_commit_hook_fn fn);

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
 * AR-06 F61: gpg_import_key(), gpg_export_public_key() and gpg_list_keys()
 * were removed — dead public API with zero callers.
 */

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

/* AR-06 F61: gpg_generate_key() was removed — dead public API with zero
 * callers. */

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
 * As gpg_manager_get_home_path, but suppresses the "not memory-backed" warning
 * that would otherwise print to stdout. Used by `gitswitch init`, whose stdout
 * is eval'd by the shell (AR-06 F08). Returns 0 on success, -1 on overflow.
 */
int gpg_manager_get_home_path_quiet(char *buf, size_t size);

/**
 * Resolve the user's REAL/system gpg home for operations documented to consult
 * the system keyring (secret-key export, availability probe). Returns the
 * configured $GNUPGHOME when it is NOT one of our managed isolated homes,
 * otherwise $HOME/.gnupg. This exists because `gitswitch init` exports
 * GNUPGHOME=<base>/current into interactive shells; a child that merely
 * inherits it would read the previously-active account's isolated home instead
 * of the real keyring and fail closed (AR-06 F05/F06). Callers pass the result
 * as an explicit GNUPGHOME override so the inherited managed value can't
 * misdirect them. Returns 0 on success, -1 on overflow or missing $HOME.
 */
int gpg_manager_system_keyring_home(char *buf, size_t size);

/**
 * Tear down isolated GPG homes (kill per-home gpg-agents and delete the
 * homes, removing the on-disk secret-key copies). Deletion is unlink, not a
 * secure overwrite: on the default memory-backed storage that destroys the
 * bytes, but on the GITSWITCH_ALLOW_TMP_GPG non-tmpfs opt-in path they may
 * remain forensically recoverable (AR-02 #26). Resets a single account when
 * `account` is non-NULL, or all accounts when NULL. Returns 0 on success.
 */
int gpg_manager_reset(const char *account);

/**
 * Report whether a safe isolated GPG home already exists for `account` (AR-06
 * F17). The switch preflight uses this to treat the system keyring as a key
 * source rather than a hard gate: a present isolated home may hold the only
 * copy of the account's secret key, which gpg_switch_account probes
 * authoritatively. A missing base or missing/unsafe home yields *present=false.
 * Sets *present and returns 0; returns -1 only on a bad argument.
 */
int gpg_manager_isolated_home_present(const char *account, bool *present);

/**
 * Atomically (re)point the stable GNUPGHOME `current` symlink at `real_home`,
 * or drop it entirely — both under the GPG base dir's cross-process lock so
 * neither can interleave with gpg_manager_reset's dangling-link cleanup
 * (AR-02 #9). Used by the switch's rollback/teardown paths; the forward
 * switch retargets internally via the same locked path. Non-fatal helpers:
 * both return 0 on success, -1 otherwise.
 */
int gpg_manager_retarget_current(const char *real_home);
int gpg_manager_drop_current(void);

/**
 * Read the stable isolated-GPG target under the manager lock after validating
 * the private base and the exact managed child. Missing base/link is ordinary
 * success with `*present == false`; unsafe, malformed, dangling, or unreadable
 * state fails closed. On success with `*present == true`, `target` contains a
 * live private per-account home.
 */
int gpg_manager_snapshot_current(char *target, size_t size, bool *present);

/**
 * Report whether `current` names this account's exact live private home.
 * Missing state or a different valid managed account returns 0 with
 * `*live == false`; unsafe/malformed state and lock failures return -1.
 */
int gpg_manager_current_is_live_for_account(const char *account, bool *live);

/**
 * Compare and conditionally restore the stable target while holding the same
 * manager lock. NULL/empty `expected_target` means the link is expected to be
 * absent; NULL/empty `restore_target` means remove it. A compare conflict is
 * ordinary success with `*changed == false` and leaves the later writer's
 * state untouched. A match completes the requested restore and sets
 * `*changed == true`; unsafe/unmanaged state fails closed.
 */
int gpg_manager_restore_current_if(const char *expected_target,
                                   const char *restore_target,
                                   bool *changed);

/**
 * Process-lifetime memo of key ids whose secret-key presence a gpg spawn
 * already proved this run, so later availability sanity checks (e.g.
 * git_test_config's read-back probe) can skip a redundant spawn (AR-02 #14).
 */
void gpg_manager_note_key_available(const char *key_id);
bool gpg_manager_key_available_cached(const char *key_id);

/**
 * Return true if `gpg --with-colons` output contains a secret key (sec/ssb)
 * whose capability field advertises signing ('s' or 'S'). Exposed for testing.
 */
bool gpg_colons_have_sign_capability(const char *colons);

#endif /* GPG_MANAGER_H */
