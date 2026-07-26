/* GPG key management with proper isolation and signing configuration */

#ifndef GPG_MANAGER_H
#define GPG_MANAGER_H

#include "gitswitch.h"
#include "utils.h"
#include <dirent.h>
#include <sys/stat.h>

/* GPG management modes */
typedef enum {
    GPG_MODE_SYSTEM,       /* Use system GPG configuration */
    GPG_MODE_ISOLATED,     /* Use isolated GNUPGHOME per account */
    GPG_MODE_SHARED        /* Shared GNUPGHOME with key switching */
} gpg_mode_t;

/* Keep manager identities on the shared account/Git key-ID contract. */
#define GPG_FINGERPRINT_BUFSIZE MAX_GPG_FINGERPRINT_LEN
#define GPG_QUARANTINE_NAME_LEN 96

typedef struct {
    struct stat st;
    char target[MAX_PATH_LEN];
    bool valid;
} gpg_link_identity_t;

typedef enum {
    GPG_ROLLBACK_NONE,
    GPG_ROLLBACK_EXPECTED_CURRENT,
    GPG_ROLLBACK_OWNED_QUARANTINED,
    GPG_ROLLBACK_FOREIGN_QUARANTINED,
    GPG_ROLLBACK_PUBLIC_DONE
} gpg_rollback_phase_t;

typedef struct {
    gpg_rollback_phase_t phase;
    gpg_link_identity_t published;
    gpg_link_identity_t quarantined;
    gpg_link_identity_t final_link;
    bool final_state_valid;
    bool final_present;
    bool restore_present;
    char restore_target[MAX_PATH_LEN];
    char quarantine[GPG_QUARANTINE_NAME_LEN];
    bool conflict;
} gpg_rollback_token_t;

/* GPG configuration structure */
typedef struct {
    gpg_mode_t mode;
    /* Canonical absolute OpenPGP executable selected by the hardened resolver.
     * One manager transaction keeps this binding even if PATH changes. */
    char executable_path[MAX_PATH_LEN];
    run_launch_witness_t executable_witness;
    char gnupg_home[MAX_PATH_LEN];    /* GNUPGHOME path */
    char current_key_id[GPG_FINGERPRINT_BUFSIZE];
    bool signing_enabled;
    bool home_owned;       /* Whether we created this GNUPGHOME */

    /* Transaction metadata is deliberately retained until cleanup succeeds.
     * This makes an environment or runtime rollback failure observable and
     * retryable rather than erasing evidence of a partially committed switch. */
    char previous_gnupg_home[MAX_PATH_LEN];
    bool previous_gnupg_home_present;
    char previous_gpg_agent_info[MAX_PATH_LEN];
    bool previous_gpg_agent_info_present;
    bool gnupg_home_environment_installed;
    bool gpg_agent_info_suppressed;
    bool environment_installed;
    gpg_link_identity_t published_link;
    bool published_link_valid;
    gpg_rollback_token_t rollback;
    bool runtime_restore_pending;
} gpg_config_t;

/* Narrow dependency seams for deterministic filesystem-race/error tests. The
 * defaults are libc readdir() and no pre-open callback, respectively. */
typedef struct dirent *(*gpg_readdir_fn)(DIR *dir);
typedef void (*gpg_agent_conf_preopen_fn)(const char *path);
typedef int (*gpg_agent_conf_precommit_fn)(int home_fd,
                                            const char *temp_name);
typedef int (*gpg_retarget_commit_hook_fn)(int base_fd);
typedef int (*gpg_retarget_restore_hook_fn)(int base_fd);
typedef enum {
    GPG_RETARGET_FORWARD_AFTER_SNAPSHOT,
    GPG_RETARGET_FORWARD_AFTER_WITNESS_SYNC,
    GPG_RETARGET_FORWARD_AFTER_QUARANTINE_SYNC,
    GPG_RETARGET_FORWARD_AFTER_PUBLICATION_SYNC
} gpg_retarget_forward_hook_stage_t;
typedef int (*gpg_retarget_forward_hook_fn)(
    int base_fd, gpg_retarget_forward_hook_stage_t stage);
typedef enum {
    GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE,
    GPG_ROLLBACK_HOOK_AFTER_QUARANTINE,
    GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE_UNLINK
} gpg_rollback_hook_stage_t;
typedef int (*gpg_rollback_hook_fn)(int base_fd,
                                    gpg_rollback_hook_stage_t stage,
                                    const char *quarantine);
typedef int (*gpg_sync_base_fn)(int base_fd);
typedef int (*gpg_rename_noreplace_fn)(int old_dir_fd, const char *old_name,
                                       int new_dir_fd, const char *new_name);
typedef int (*gpg_setenv_fn)(const char *name, const char *value,
                             int overwrite);
typedef int (*gpg_unsetenv_fn)(const char *name);
/* Test seams around reset's two-pass cleanup. The predelete hook runs only
 * after the complete home has passed its second validation and immediately
 * before destructive traversal. The final hook runs after an all-home reset
 * has removed `current` and immediately before the required final base scan. */
typedef int (*gpg_cleanup_predelete_fn)(int home_fd);
typedef int (*gpg_reset_final_hook_fn)(int base_fd);
/* Runs after reset captures the exact `current` symlink and before it moves
 * that pathname into a private quarantine. Tests use this boundary to prove
 * that a same-uid writer replacing `current` is restored, never unlinked. */
typedef int (*gpg_reset_current_hook_fn)(int base_fd);
typedef enum {
    GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME,
    GPG_RESET_QUARANTINE_HOOK_BEFORE_REVALIDATE,
    GPG_RESET_QUARANTINE_HOOK_BEFORE_UNLINK
} gpg_reset_quarantine_hook_stage_t;
/* Deterministic post-publication failure seam for reset's durable
 * quarantine/witness pair. The named quarantine and its hard-link witness are
 * synchronized before AFTER_RENAME runs; failures retain both for retry. */
typedef int (*gpg_reset_quarantine_hook_fn)(
    int base_fd, gpg_reset_quarantine_hook_stage_t stage,
    const char *quarantine);
/* Deterministic mount-identity and managed-writer durability seams. NULL
 * restores the native statx/fsid and fsync implementations. */
typedef int (*gpg_mount_identity_probe_fn)(int fd, uint64_t *identity);
typedef int (*gpg_agent_conf_sync_fn)(int fd, bool directory);
/* Exact-descriptor probe for the isolated base's storage policy. Return zero
 * and set `memory_backed`, or return -1 with errno on an unknown/error state.
 * NULL restores the native fstatfs implementation. */
typedef int (*gpg_memory_backed_probe_fn)(int base_fd,
                                          bool *memory_backed);
/* Advisory-only pathname probe used to decide whether the fallback warning
 * should be shown. Its result must never authorize secret-key mutation. */
typedef bool (*gpg_base_warning_probe_fn)(const char *base_path);
/* Deterministic cache-hit race seam. It runs after the first recursive home
 * generation and executable witness have been checked, but before the
 * mandatory final generation and public-namespace binding validation. */
typedef int (*gpg_key_cache_post_scan_hook_fn)(const char *home_path,
                                               bool isolated);
gpg_readdir_fn gpg_manager_set_readdir_fn(gpg_readdir_fn fn);
gpg_agent_conf_preopen_fn
gpg_manager_set_agent_conf_preopen_fn(gpg_agent_conf_preopen_fn fn);
gpg_agent_conf_precommit_fn
gpg_manager_set_agent_conf_precommit_fn(gpg_agent_conf_precommit_fn fn);
gpg_retarget_commit_hook_fn
gpg_manager_set_retarget_commit_hook_fn(gpg_retarget_commit_hook_fn fn);
gpg_retarget_restore_hook_fn
gpg_manager_set_retarget_restore_hook_fn(gpg_retarget_restore_hook_fn fn);
gpg_retarget_forward_hook_fn
gpg_manager_set_retarget_forward_hook_fn(gpg_retarget_forward_hook_fn fn);
gpg_rollback_hook_fn
gpg_manager_set_rollback_hook_fn(gpg_rollback_hook_fn fn);
gpg_sync_base_fn gpg_manager_set_sync_base_fn(gpg_sync_base_fn fn);
gpg_rename_noreplace_fn
gpg_manager_set_rename_noreplace_fn(gpg_rename_noreplace_fn fn);
gpg_setenv_fn gpg_manager_set_setenv_fn(gpg_setenv_fn fn);
gpg_unsetenv_fn gpg_manager_set_unsetenv_fn(gpg_unsetenv_fn fn);
gpg_cleanup_predelete_fn
gpg_manager_set_cleanup_predelete_fn(gpg_cleanup_predelete_fn fn);
gpg_reset_final_hook_fn
gpg_manager_set_reset_final_hook_fn(gpg_reset_final_hook_fn fn);
gpg_reset_current_hook_fn
gpg_manager_set_reset_current_hook_fn(gpg_reset_current_hook_fn fn);
gpg_reset_quarantine_hook_fn
gpg_manager_set_reset_quarantine_hook_fn(gpg_reset_quarantine_hook_fn fn);
gpg_mount_identity_probe_fn
gpg_manager_set_mount_identity_probe_fn(gpg_mount_identity_probe_fn fn);
gpg_agent_conf_sync_fn
gpg_manager_set_agent_conf_sync_fn(gpg_agent_conf_sync_fn fn);
gpg_memory_backed_probe_fn
gpg_manager_set_memory_backed_probe_fn(gpg_memory_backed_probe_fn fn);
gpg_base_warning_probe_fn
gpg_manager_set_base_warning_probe_fn(gpg_base_warning_probe_fn fn);
gpg_key_cache_post_scan_hook_fn
gpg_manager_set_key_cache_post_scan_hook_fn(
    gpg_key_cache_post_scan_hook_fn fn);

/* Focused verification entry point for the otherwise-internal managed writer.
 * It stages a durable reload obligation but never launches gpgconf; production
 * prepare owns applying and completing that obligation before activation. */
int gpg_manager_setup_agent_config_for_test(int home_fd,
                                            const char *gnupg_home);

/* Function prototypes */

/**
 * Initialize GPG manager with specified mode
 */
int gpg_manager_init(gpg_config_t *gpg_config, gpg_mode_t mode);

/** Resolve the manager's supported OpenPGP executable names through the same
 * hardened path policy used for launch. `gpg` has deterministic priority over
 * `gpg2`. Returns one canonical absolute path or -1 with a GPG diagnostic. */
int gpg_manager_resolve_executable(char *path, size_t path_size);

/** Restore manager-owned environment/runtime retry state, then clear the
 * transaction configuration. Persistent per-account homes are deliberately
 * retained for switch-back; gpg_manager_reset() owns explicit reclamation.
 * Returns -1 without clearing retry metadata if restoration fails. */
int gpg_manager_cleanup(gpg_config_t *gpg_config);

/**
 * Prepare the account's GPG runtime with proper isolation.
 * - Resolves and validates the account's canonical signing key
 * - Sets and retargets GNUPGHOME when using isolated mode
 * - Records the selected key and signing preference in gpg_config
 * - Does not modify Git configuration; gpg_configure_git_signing() does
 */
int gpg_switch_account(gpg_config_t *gpg_config, const account_t *account);

/**
 * Create or validate an isolated GNUPGHOME for an account.
 * - Creates the directory with private permissions when absent
 * - Sets up the managed GPG agent configuration
 * - Does not import a key; gpg_switch_account() owns key transfer
 */
int gpg_create_isolated_home(gpg_config_t *gpg_config, const account_t *account);

/** AR-06 F61 / AR-08 L17: gpg_import_key(), gpg_export_public_key(),
 * gpg_list_keys(), and gpg_validate_key() were removed — dead public API;
 * gpg_validate_key() also overstated its exit-status-only implementation. */

/**
 * Configure git GPG signing
 * - Sets user.signingkey
 * - Enables/disables commit.gpgsign
 * - Publishes the manager's exact bound path as gpg.openpgp.program
 * - Verifies the complete effective Git/GPG post-image before returning
 */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, 
                              git_scope_t scope);

/* AR-06 F61 / AR-09 L12: gpg_generate_key() and gpg_test_signing() were
 * removed as dead/misleading public APIs. The latter created no signature and
 * accepted incomplete capability output; the switch uses the strict resolver
 * below as its authoritative readiness proof. */

/** Install GNUPGHOME transactionally and retain its previous value for
 * gpg_manager_cleanup(). */
int gpg_set_environment(gpg_config_t *gpg_config);

/** Return whether a failed switch still owns a published runtime entry point
 * that must be restored before the transaction can be forgotten. */
bool gpg_manager_runtime_restore_pending(const gpg_config_t *gpg_config);

/** Strict detached-listing parser exposed for mutation-sensitive colon-record
 * tests. It accepts the documented pre-2.1 empty validity field, but requires
 * explicit modern secret-material evidence because a detached capture cannot
 * prove which helper produced it. The production resolver separately binds
 * an empty field 15 to the same retained executable's verified GnuPG 2.0
 * version contract. Resolves exactly one usable primary secret key, writes its
 * canonical fingerprint, and optionally requires a usable signing record. */
int gpg_manager_resolve_secret_key_listing(const char *listing,
                                           bool require_signing,
                                           char *fingerprint,
                                           size_t fingerprint_size);

/** Resolve a selector against the real/system keyring through a retained,
 * provenance-checked directory descriptor. The helper runs with cwd_fd and
 * GNUPGHOME=. so namespace replacement cannot redirect it. Exactly one
 * currently usable primary secret key is required; when require_signing is
 * true it must also have usable signing capability. A missing selector is
 * recognized only from complete machine-readable no-secret-key status;
 * keyring, helper, malformed-status, and truncated-output failures remain
 * operational errors. On success writes the canonical primary fingerprint. */
int gpg_manager_resolve_system_key(const char *selector,
                                   bool require_signing,
                                   char *fingerprint,
                                   size_t fingerprint_size);

typedef enum {
    GPG_SOURCE_RECOVERY_UNKNOWN = 0,
    GPG_SOURCE_RECOVERY_AVAILABLE,
    GPG_SOURCE_RECOVERY_MISSING,
    GPG_SOURCE_RECOVERY_MISMATCH,
    GPG_SOURCE_RECOVERY_ERROR
} gpg_source_recovery_t;

typedef struct {
    bool retained_home_usable;
    gpg_source_recovery_t source_recovery;
} gpg_account_key_readiness_t;

/** Check an account key without creating, importing, retargeting, or changing
 * process environment. Mirrors isolated activation order: a safe retained
 * account home is authoritative; only an ordinary key miss falls back to the
 * real source keyring, while malformed/unusable/operational retained-home
 * evidence fails closed. When the retained home succeeds, the source is
 * probed separately and must resolve the same canonical fingerprint and
 * configured capability to be considered recoverable. Returns 0 when the
 * account can be activated from either source and fills `readiness`; returns
 * -1 when neither activation path is currently usable. */
int gpg_manager_check_account_key(
    const account_t *account, gpg_account_key_readiness_t *readiness);

/**
 * Compute the stable GNUPGHOME path (a `current` symlink under the isolated
 * GPG base directory) that `gitswitch init` exports into the shell and that
 * each switch retargets to the active account's home. Uses
 * $XDG_RUNTIME_DIR/gitswitch-gpg/current when a nonempty configured root is
 * valid, else /tmp/gitswitch-gpg-<uid>/current only when XDG_RUNTIME_DIR is
 * unset or empty. A configured invalid/missing root is an error.
 * Shared by the runtime switch logic and the `init` command so both agree.
 * Returns 0 on success, -1 if the computed path would overflow buf.
 */
int gpg_manager_get_home_path(char *buf, size_t size);

/**
 * As gpg_manager_get_home_path, but suppresses the "not memory-backed" warning
 * that would otherwise print to stdout. Used by `gitswitch init`, whose stdout
 * is captured and evaluated as a shell program only after successful
 * generation (AR-06 F08). Returns 0 on success, -1 on overflow.
 */
int gpg_manager_get_home_path_quiet(char *buf, size_t size);

/**
 * Tear down isolated GPG homes (kill per-home gpg-agents and delete the
 * homes, removing the on-disk secret-key copies). Deletion is unlink, not a
 * secure overwrite: on the default memory-backed storage that destroys the
 * bytes, but on the GITSWITCH_ALLOW_TMP_GPG non-tmpfs opt-in path they may
 * remain forensically recoverable (AR-02 #26). Cleanup fails closed and keeps
 * the affected home when it cannot prove one mount boundary and one link per
 * non-directory entry. A full reset also rejects unknown base entries and
 * verifies that only its exact lock survives. Namespace changes are synced
 * through the pinned base before success; a failed sync returns nonzero so an
 * otherwise empty retry can repair durability. A successful full reset
 * retires every captured `current` symlink. A targeted or incomplete full
 * reset retires it only when it no longer names a live, safe managed home,
 * preserving an unrelated live selection. Removal uses an identity-aware
 * quarantine, preserving a same-uid writer that replaced the captured link.
 * Resets a single account when
 * `account` is a nonempty name accepted by validate_name(); callers must pass
 * the canonical stored account name. Resets all accounts only when `account`
 * is NULL. Invalid non-NULL input fails with ERR_INVALID_ARGS before any
 * runtime I/O. Returns 0 on success.
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
 * neither can interleave with gpg_manager_reset's home teardown or
 * current-link retirement (AR-02 #9). Used by the switch's rollback/teardown
 * paths; the forward switch retargets internally via the same locked path.
 * Dropping `current` syncs the pinned base before success and re-syncs an
 * already-absent name so a retry can repair a prior durability failure.
 * Non-fatal helpers: both return 0 on success, -1 otherwise.
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
 * manager lock. `gpg_config` carries the exact symlink inode+target installed
 * by the forward transaction; `expected_target` is an additional spelling
 * assertion for legacy/direct callers and may be NULL only when the retained
 * identity is valid. NULL/empty `restore_target` means remove it. A compare
 * conflict is ordinary success with `*changed == false` and preserves the later
 * writer. Native no-replace quarantine or durability uncertainty returns -1
 * with retry state retained in `gpg_config`.
 */
int gpg_manager_restore_current_if(gpg_config_t *gpg_config,
                                   const char *expected_target,
                                   const char *restore_target,
                                   bool *changed);

/**
 * Compatibility memo for callers using an injected test runner. Production
 * callers using the real runner never treat selector-only notes as proof:
 * reusable secret-key evidence is maintained internally and is bound to the
 * canonical fingerprint, requested capability, exact launch witness, and GPG
 * home generation.
 */
void gpg_manager_note_key_available(const char *key_id);
bool gpg_manager_key_available_cached(const char *key_id);

#endif /* GPG_MANAGER_H */
