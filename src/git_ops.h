/* Git configuration operations */

#ifndef GIT_OPS_H
#define GIT_OPS_H

#include "gitswitch.h"
#include "publication.h"

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
 * inputs shorter than MAX_PATH_LEN plus an optional canonical hostname shorter
 * than MAX_NAME_LEN. A canonical executable can consist entirely of
 * apostrophes, so POSIX single-quote serialization needs at most
 * 4 * (MAX_PATH_LEN - 1) bytes for it. is_safe_ssh_key_path() and the hostname
 * validator reject quotes, so their serialized payloads contribute at most
 * MAX_PATH_LEN - 1 and MAX_NAME_LEN - 1 bytes. The 256 bytes cover quote
 * delimiters, fixed options, and the NUL. Public status records and the scalar
 * cache use this lossless capacity; transactional snapshots remain dynamically
 * allocated for arbitrary foreign values. */
#define GIT_CONFIG_VALUE_MAX (MAX_PATH_LEN * 5 + MAX_NAME_LEN + 256)

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
    git_config_origin_scope_t effective_signing_key_scope;
    char effective_signing_key_origin[MAX_PATH_LEN];
    git_config_effective_value_t ssh_command;
    /* Keep every Git-supported program selector distinct. Folding them into
     * one value loses both selector semantics and origin attribution when a
     * foreign format-specific override coexists with the managed OpenPGP
     * program. */
    git_config_effective_value_t gpg_program;
    git_config_effective_value_t gpg_openpgp_program;
    git_config_effective_value_t gpg_x509_program;
    git_config_effective_value_t gpg_ssh_program;
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
 * key path, isolates OpenSSH from shared configuration, and serializes both
 * absolute arguments safely. For a managed alias it also pins the validated
 * canonical hostname. It does not require the key file to exist. Durable
 * status uses the publication-backed matcher below so it never substitutes a
 * newly PATH-resolved executable for the one used at switch time.
 */
int git_expected_ssh_command(const account_t *account, char *command,
                             size_t command_size);

/**
 * Clear git configuration (unset values)
 */
int git_clear_config(git_scope_t scope);

/**
 * Compare two canonical OpenPGP fingerprints. Both values must contain
 * exactly 40 or 64 hexadecimal digits of equal length; comparison is over the
 * complete value and is case-insensitive. Selectors and 0x prefixes never
 * match. The fingerprint must come from proven publication provenance before
 * this result is used for status or mutation ownership.
 */
bool git_signing_key_matches_fingerprint(const char *canonical_fingerprint,
                                         const char *configured);

/**
 * True only when both the account value and `configured` are canonical 40- or
 * 64-hex-digit fingerprints of equal length whose complete values compare
 * case-insensitively equal. Short selectors and 0x-prefixed selectors are
 * resolution inputs, not durable ownership evidence, and never match here.
 * Internal status and retirement additionally require persisted publication
 * provenance before treating a configured value as account-owned.
 */
bool git_signing_key_selects_account(const account_t *account,
                                     const char *configured);

typedef enum {
    GIT_SIGNING_PUBLICATION_ERROR = -1,
    GIT_SIGNING_PUBLICATION_MISMATCH = 0,
    GIT_SIGNING_PUBLICATION_MATCH = 1
} git_signing_publication_result_t;

typedef enum {
    GIT_SSH_PUBLICATION_ERROR = -1,
    GIT_SSH_PUBLICATION_MISMATCH = 0,
    GIT_SSH_PUBLICATION_MATCH = 1
} git_ssh_publication_result_t;

/**
 * Match only when a published provenance record belongs to `account`, names
 * the exact effective signing-key destination reported by `current`, and its
 * canonical fingerprint equals both the complete configured value and the
 * account's normalized current selector. Selector comparison is purely
 * observational against the switch-time persisted selector; it never reads a
 * keyring or re-resolves through a helper. Missing selector provenance is not
 * a match. Invalid current selector input is ERROR; a different valid
 * selector is a semantic mismatch.
 */
git_signing_publication_result_t git_signing_key_matches_publication(
    const account_t *account, const publication_record_t *publication,
    const git_current_config_t *current);

/**
 * Compare SSH status only against a complete publication tuple. The current
 * account model is serialized with the persisted absolute SSH executable (no
 * PATH lookup), then the exact saved command, effective scope/file origin,
 * and persisted executable generation must all agree. Invalid/incomplete
 * provenance or an unverifiable program returns ERROR; ordinary drift returns
 * MISMATCH.
 */
git_ssh_publication_result_t git_ssh_command_matches_publication(
    const account_t *account, const publication_record_t *publication,
    const git_current_config_t *current);

/**
 * Re-run the hardened absolute-executable trust walk and require the complete
 * live file generation to equal a persisted publication identity. Removal,
 * replacement, in-place rewrite, permission/ownership change, and an unsafe
 * path all fail closed with a diagnostic. `diagnostic_name` is an internal
 * human-readable label only.
 */
int git_publication_verify_program_identity(
    const char *program, const publication_identity_t *expected,
    const char *diagnostic_name);

/**
 * Legacy compatibility entry point retained for source compatibility only.
 * Without a sealed publication record it cannot attribute any Git credential
 * leg, so it fails closed before Git/PATH work, leaves all values untouched,
 * and stores zero in `cleared` when provided. Use the record-backed entry
 * point below for retirement.
 */
int git_retire_account_identity(const account_t *account, size_t *cleared);

/**
 * Retire an account identity using a validated durable publication record.
 * Signing attribution is restricted to the record's exact canonical
 * fingerprint and destination. Local/worktree retirement verifies the exact
 * persisted config and repository identities without consulting cwd, HOME,
 * or Git environment overrides. Only PUBLISHED records authorize mutation;
 * RETIRING records are durable deletion tombstones and fail before Git
 * execution. NULL, incomplete, mismatched, or selector-derived records
 * likewise fail before mutation. Retirement consumes the exact persisted SSH
 * command and does not require the recorded executable still to exist.
 */
int git_retire_account_identity_published(
    const account_t *account, const publication_record_t *publication,
    size_t *cleared);

/**
 * Retire every recorded publication for one account incarnation. All records
 * and live destinations are validated before the first mutation, then every
 * live physical destination is captured as one immutable exact-file vector.
 * A read, parse, allocation, or truncation failure authorizes no mutation in
 * any group; clean absence is idempotent. Records for linked worktrees may
 * share one stable config destination; their repository witnesses are checked
 * independently and the physical config is processed as one group using every
 * persisted credential witness. Healthy groups still retire when another
 * record is stale or indeterminate, while the first causal failure and an
 * aggregate summary are returned with the total cleared-key count.
 */
int git_retire_account_identity_publications(
    const account_t *account,
    const publication_record_t *const publications[],
    size_t publication_count, size_t *cleared);

/* Opaque owner of one prepared, descriptor-pinned Git retirement batch. */
typedef struct git_retirement_transaction git_retirement_transaction_t;

/**
 * Prepare one outer Git retirement transaction from aligned account and
 * publication vectors. Every item is copied and validated before filesystem
 * work. Records that share a physical configuration destination are planned
 * and locked as one group, so reset-all cannot overwrite one destination from
 * multiple stale snapshots. Preparation may create checked private staging
 * and canonical-lock artifacts, but never changes a canonical Git config.
 *
 * Operational failures local to one destination are retained inside the
 * transaction so publish can preserve independent-destination progress; an
 * indeterminate preflight snapshot still blocks publication everywhere.
 * Invalid input, malformed provenance, allocation failure, and a non-default
 * command runner fail immediately with `*transaction == NULL`.
 */
int git_retirement_transaction_prepare(
    const account_t *const accounts[],
    const publication_record_t *const publications[], size_t item_count,
    git_retirement_transaction_t **transaction);

/**
 * Publish every healthy prepared destination and retain exact before/post
 * witnesses only when the complete batch succeeds. On any destination
 * failure, healthy destinations retain the historical partial-progress
 * behavior, all transaction artifacts are checked-cleaned, and the returned
 * transaction may only be committed/disposed (not rolled back). `cleared`
 * receives the number of keys installed by fully successful destinations.
 */
int git_retirement_transaction_publish(
    git_retirement_transaction_t *transaction, size_t *cleared);

/**
 * Accept the current transaction state, checked-clean every owned artifact,
 * securely release witnesses, free the transaction, and set the caller's
 * pointer to NULL. This is valid for prepared, fully published, fully
 * aborted, and publish-failed transactions. Cleanup failure is reported
 * after durable recovery authority has been retained where possible; the
 * handle is still consumed.
 */
int git_retirement_transaction_commit(
    git_retirement_transaction_t **transaction);

/**
 * Roll back a completely published batch. Each canonical destination and its
 * held Git lock must still equal the retained post-image witnesses before the
 * original pinned file is restored and the directory is synced. The handle
 * and locks remain owned after success so the caller can durably refresh
 * publication-generation witnesses before commit consumes the transaction.
 * A failed restoration likewise leaves the handle available for retry.
 */
int git_retirement_transaction_abort(
    git_retirement_transaction_t *transaction);

/**
 * Number of canonical destinations reconciled by a successful abort. This
 * includes both changed generations restored from the retained before-image
 * and safely locked no-op destinations whose existing generation must remain
 * represented in the caller's exact publication-refresh set.
 */
size_t git_retirement_transaction_restored_destination_count(
    const git_retirement_transaction_t *transaction);

/**
 * Return one reconciled canonical path and its freshly re-proved exact file
 * identity. The query checked-cleans and syncs that destination's transaction
 * artifacts before sealing the generation, then retains its exact bytes for
 * commit to re-prove after the caller refreshes the publication ledger. This
 * prevents delayed filesystem metadata from making the new ledger stale while
 * still detecting an external Git writer. `index` addresses changed-and-
 * restored and unchanged/no-op destinations exactly once per physical config
 * namespace. The transaction must remain uncommitted and fully aborted.
 */
int git_retirement_transaction_restored_destination(
    git_retirement_transaction_t *transaction, size_t index,
    char *config_path, size_t path_size,
    publication_identity_t *post_config);

/**
 * Snapshot the gitswitch-managed config keys (identity/signing keys,
 * gpg.format, every Git-supported GPG program selector, and core.sshCommand)
 * at `scope` before a switch mutates them, plus the LOCAL scope when a global
 * write would clear it and any distinct WORKTREE override scope. Every
 * repeated value is retained in order. Included managed values are refused
 * when their origin cannot be restored exactly. Real-Git transactions also
 * retain descriptor-backed repository and configuration-namespace
 * generations so a later pathname replacement cannot inherit rollback
 * ownership merely by copying the same values. Pair with git_config_restore()
 * to roll back on a failed switch. Single snapshot slot (the CLI is
 * single-threaded); a new snapshot replaces the previous.
 */
int git_config_snapshot(git_scope_t scope);

/**
 * Verify the active transaction's exact intended post-write vectors against a
 * fresh Git read. The intended image is updated only by this process's
 * successful managed writes, so a concurrent value arriving before this call
 * is rejected rather than adopted. For real Git, sealing also pins the exact
 * installed config-file generation that rollback may replace. A durable
 * publication is eligible only when a complete primary-scope account writer
 * bound the snapshot's immutable account incarnation; standalone account
 * writes into tracked override scopes and partial/failed follow-up writers
 * invalidate that eligibility. Call after all forward Git writes and before
 * later transaction steps can fail. Idempotent after successful seal.
 */
int git_config_seal(void);

/**
 * Copy the active sealed transaction's primary publication destination and
 * exact credential post-image into a durable-record POD. The export
 * revalidates the pinned namespace and post-config generation, accepts only a
 * canonical signing fingerprint/program pair, and uses only the immutable
 * account owner bound by the complete transaction writer. `gpg_selector` is
 * the original persisted account selector captured before the switch target
 * is canonicalized; it is normalized and bound to the fingerprint/program
 * tuple without any keyring lookup. The exporter never consults PATH or the
 * caller's current directory to reconstruct values. `out` is initialized
 * only on success and remains caller-owned.
 */
int git_config_export_sealed_publication(publication_record_t *out,
                                         const char *gpg_selector);

/**
 * Export only the destination identity (scope, config path/parent,
 * repository) of the active snapshot for publication-capacity preflight.
 * Valid from git_config_snapshot() on; no sealed post-image is required.
 * `out` carries no account owner or credential values (AR-12 H2).
 */
int git_config_snapshot_export_destination(publication_record_t *out);

/**
 * Restore the most recent git_config_snapshot(), rebuilding every key with its
 * exact ordered values only while the current vector still matches the sealed
 * transaction-owned state and the repository, config namespace, and sealed
 * config-file generations still identify the original destination. A failed
 * restore preserves concurrent changes and retains the snapshot plus exact
 * per-key progress for retry. Partially failed forward writes are compared
 * against the intended image recorded through the last successful managed
 * operation. No-op if nothing was snapshotted.
 */
int git_config_restore(void);

/**
 * Infallibly commit the active Git transaction by discarding its in-memory
 * rollback images. Call only after every external commit point has succeeded;
 * no-op when no snapshot is active.
 */
void git_config_commit(void);

/* AR-06 F59: git_validate_repository() and git_get_config_scope() were removed
 * — dead public API with zero callers. */

/**
 * Validate that Git's fresh merged effective configuration exactly represents
 * the selected account: identity, managed SSH command, signing key and enabled
 * state, OpenPGP format, the exact bound gpg.openpgp.program, and absence of
 * legacy/X.509/SSH program selectors. `expected_gpg_program` must be a
 * nonempty absolute path when the account enables GPG and NULL or empty when
 * it does not. When GPG is enabled, use that same path for the local secret-key
 * availability probe. `scope` must be a valid public scope but does not limit
 * the effective read. This function creates no commit or signature and
 * performs no remote authentication or other network access.
 */
int git_test_config(const account_t *account, git_scope_t scope,
                    const char *expected_gpg_program);

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
 * - The isolated GPG manager separately publishes gpg.openpgp.program after
 *   canonical key resolution
 */
int git_configure_gpg(const account_t *account, git_scope_t scope);

/**
 * Publish the canonical OpenPGP fingerprint, signing preference, and exact
 * trusted executable as one account-owned transaction step. When a snapshot
 * is active, the account must match its immutable publication owner.
 */
int git_configure_openpgp_publication(const account_t *account,
                                      const char *gpg_program,
                                      git_scope_t scope);

/**
 * Check if current directory is a git repository
 */
bool git_is_repository(void);

/**
 * Get the complete repository root directory, stripping only Git's final line
 * ending. Valid path whitespace is preserved. On failure, path is empty when
 * path/path_size denote writable storage; incomplete or oversized results fail.
 */
int git_get_repo_root(char *path, size_t path_size);

/**
 * Convert scope enum to git config scope string
 */
const char *git_scope_to_flag(git_scope_t scope);

#endif /* GIT_OPS_H */
