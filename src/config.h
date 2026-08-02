/* Configuration file management and TOML parsing */

#ifndef CONFIG_H
#define CONFIG_H

#include "gitswitch.h"
#include "publication.h"
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
    CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ,
    /* Read-side close checkpoint. A test callback may expose a ctime-only
     * close-time metadata step and return false; the loader must bind the
     * generation observed after close. */
    CONFIG_IO_DOCUMENT_AFTER_CLOSE,
    /* Exact-byte reproof checkpoint immediately before its final descriptor
     * generation observation. A test callback may expose a ctime-only step
     * and return false. */
    CONFIG_IO_DOCUMENT_REPROOF_AFTER_BYTES,
    /* Rollback checkpoint after the before-image rename or unlink and the
     * successful parent-directory sync, but before final verification. */
    CONFIG_IO_STATE_ROLLBACK_AFTER_DIR_SYNC
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

/* Focused single-threaded entropy seam for incarnation allocation tests.
 * Production leaves NULL installed and uses generate_random_string(). A test
 * generator must emit one exact ACCOUNT_INCARNATION_LEN token or fail. */
typedef int (*config_incarnation_generate_fn)(
    char incarnation[ACCOUNT_INCARNATION_LEN]);
config_incarnation_generate_fn config_set_incarnation_generate_fn(
    config_incarnation_generate_fn fn);

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
 * Initialize configuration for a read-only command that reports live runtime
 * state. Like config_init_readonly(), this never creates or chmods the config
 * directory or lock metadata, but it may take the existing SSH runtime lock
 * and probe current.sock to attribute the active account.
 */
int config_init_runtime_readonly(gitswitch_ctx_t *ctx);

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

/* Re-prove that the path recorded in `ctx` still names the exact accounts
 * document loaded into it. This is observational: it neither locks nor writes
 * any path. Recovery callers that require serialization must hold the ordinary
 * config write lock across this check and the operation it authorizes. */
int config_revalidate_loaded_source(const gitswitch_ctx_t *ctx);

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
/* Full-document transactional save. `config_installed` latches true when the
 * accounts.toml rename commits and no later canonical reproof, substitution,
 * or directory-sync failure revokes that fact. Such failures distinguish an
 * installed-but-no-longer-current or installed-but-durability-uncertain result
 * from a pre-install failure. Only complete durable success rebinds the mutable
 * context to the exact installed source generation so another save from that
 * context is admitted. */
int config_save_transactional(gitswitch_ctx_t *ctx,
                              const char *config_path,
                              bool *config_installed);

/* Materialize and durably persist every legacy account incarnation in one
 * full transaction. A no-op when every account came from a persisted token.
 * The CLI invokes this under its outer config lock before switch prepare, so
 * entropy or persistence failure precedes all runtime and Git mutation. */
int config_migrate_account_incarnations(gitswitch_ctx_t *ctx,
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

/* Durable fail-closed witness for an outer remove/reset transaction whose Git
 * retirement may no longer agree with the account/active-state document. The
 * marker is a versioned 0600 sibling of accounts.toml and binds one operation
 * kind to an exact canonical owner set. Its handle is intentionally opaque:
 * callers may clear only the exact marker generation they installed/adopted.
 */
typedef enum {
    CONFIG_RETIREMENT_REMOVE = 1,
    CONFIG_RETIREMENT_RESET
} config_retirement_kind_t;

typedef struct {
    uint32_t account_id;
    char account_incarnation[ACCOUNT_INCARNATION_LEN];
} config_retirement_owner_t;

/* Optional, remove-only durable obligation to retire one managed OpenSSH
 * alias from the exact HOME namespace in which it was installed. `known`
 * distinguishes an explicit no-obligation marker (including legacy RESET)
 * from a v1 REMOVE projection whose SSH obligation is unknowable. */
typedef struct {
    bool known;
    bool present;
    char ssh_host_alias[MAX_NAME_LEN];
    char home_path[MAX_PATH_LEN];
    publication_identity_t home_identity;
    publication_identity_t ssh_directory_identity;
} config_retirement_ssh_alias_obligation_t;

typedef struct {
    char config_path[MAX_PATH_LEN];
    /* A present identity replaces matching PUBLISHED records' post_config.
     * A canonical all-zero absent identity participates in exact-set
     * accounting while preserving each matching record's prior identity. */
    publication_identity_t post_config;
} config_retirement_destination_t;

typedef struct config_retirement_guard config_retirement_guard_t;
typedef int (*config_retirement_guard_precommit_fn)(void *context);

/* Token-free projection of one active retirement marker. `valid` is true
 * only for a stable canonical incomplete generation; absent namespaces and
 * exact completed marker/certificate pairs return a zeroed projection. */
typedef struct {
    bool valid;
    unsigned int marker_version;
    config_retirement_kind_t kind;
    config_retirement_owner_t owners[MAX_ACCOUNTS];
    size_t owner_count;
    config_retirement_ssh_alias_obligation_t ssh_alias_obligation;
} config_retirement_recovery_t;

/* Under an internally owned retirement lifecycle lock, install a fresh
 * incomplete generation or adopt an active generation only when its kind and
 * sorted owner set match exactly. Adoption first syncs the pinned directory,
 * then jointly re-reads the same blocking generation, so an earlier
 * rename-without-directory-sync failure cannot authorize Git mutation. A
 * stable exact marker/certificate pair is a completed prior operation and is
 * rotated to a fresh token; its stale certificate then keeps the new
 * generation blocked until clear(). Unsafe, malformed, unstable, or
 * mismatched state fails closed. `owners` may be in any order; duplicate
 * tuples are refused. The returned handle owns the lock and must be passed to
 * clear() or abandon().
 */
int config_retirement_guard_install_or_adopt(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    config_retirement_guard_t **guard);

int config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    config_retirement_guard_t **guard);

/* Read one stable, token-free recovery projection without creating, locking,
 * chmod'ing, synchronizing, or repairing any namespace object. An exact
 * byte-identical transition copy remains projectable so adopt() can converge
 * an interrupted clear; foreign/malformed stages, unsafe or unstable state,
 * and legacy residue fail closed. */
int config_retirement_guard_recovery_probe(
    const char *config_path,
    config_retirement_recovery_t *recovery);

/* Adopt only an already-active canonical marker whose operation and complete
 * canonical owner set match exactly. This entry point never creates or rotates
 * a marker. Its only reconciliation is removing a jointly revalidated stage
 * that is byte-identical to that exact marker under the existing lifecycle
 * lock; foreign/malformed stages remain untouched. Absence, an already-settled
 * pair without such a stage, legacy residue, mismatched state, or namespace
 * replacement fails closed. The returned handle owns the lifecycle lock and
 * must be passed to clear() or abandon(). */
int config_retirement_guard_adopt(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    config_retirement_guard_t **guard);

int config_retirement_guard_adopt_with_ssh_alias_obligation(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    config_retirement_guard_t **guard);

/* Read-only retirement gate. On return 0, `blocked` is false only when both
 * fixed records are absent or one jointly revalidated canonical marker and
 * byte-identical `.retirement-complete` certificate form an exact pair. A
 * lone record, stale/mismatched pair, fixed transition stage, or retained
 * legacy clear witness returns blocked. Unsafe, malformed, unreadable, or
 * unstable state returns -1 with `blocked` still true. The two names are
 * re-statted after both descriptor reads so mixed-generation snapshots cannot
 * unblock. This probe never creates, chmods, or repairs a path.
 */
int config_retirement_guard_probe(const char *config_path, bool *blocked);

/* True only when this invocation installed the marker. A matching retry that
 * adopted a prior marker returns false, allowing pre-install rollback to
 * preserve the older incomplete witness.
 */
bool config_retirement_guard_was_created(
    const config_retirement_guard_t *guard);

/* Re-prove that a lock-owning handle still names its exact incomplete marker
 * generation. This is read-only: it neither reacquires the lifecycle lock nor
 * mutates, clears, or frees the handle or any retirement namespace record.
 * Replacement, byte/token change, stage/certificate insertion, removal or
 * replacement, settlement, or directory namespace replacement fails closed.
 * A pre-existing completion certificate is bound as part of the observed
 * namespace generation, and a handle that successfully prepared its exact
 * completion stage revalidates that stage as part of the owned generation. */
int config_retirement_guard_revalidate(
    const config_retirement_guard_t *guard);

/* Durably materialize and jointly re-prove the exact owned completion stage
 * while the fixed transition name keeps probes blocked. On success the handle
 * is prepared for a final clear whose stage-to-certificate rename is the
 * logical commit. Any failure retains the handle and any created blocking
 * stage for retry or normal fresh-process adoption. */
int config_retirement_guard_prepare_clear(
    config_retirement_guard_t *guard);

/* Complete only the exact owned marker generation (inode, complete bytes, and
 * embedded token) by atomically replacing the fixed completion certificate;
 * the canonical blocker is never renamed or deleted. Before certificate
 * publication every failure retains a blocking marker and the handle. Once a
 * jointly revalidated exact pair is observable, publication is the no-fail
 * logical commit point: a later file/directory sync acknowledgement failure is
 * reported as success because a crash can yield only the exact completed pair
 * or the older blocking state. Success frees and NULLs the lock-owning handle.
 */
int config_retirement_guard_clear(config_retirement_guard_t **guard);

/* As clear(), with an optional prepared-generation commit barrier. A non-NULL
 * barrier is valid only after prepare_clear() succeeds. The exact marker,
 * completion, stage, named lifecycle lock, and pinned-directory proof runs
 * before the callback. Returning zero authorizes the terminal
 * stage-to-certificate rename; returning nonzero preserves the callback's
 * diagnostic and errno and retains the prepared handle and blocking stage for
 * retry. `context` is borrowed only for the synchronous call. The callback
 * must not mutate the retirement namespace, call retirement-guard lifecycle
 * APIs, or retain the borrowed context. A later pre-rename failure can cause a
 * successful callback to be invoked again on retry, so it must be idempotent.
 * After callback success, publication uses a no-overwrite namespace
 * operation and exact generation proof; a raced stage or certificate is
 * preserved and the prepared handle remains blocking. Once that proof
 * succeeds, no additional callback or fallible acknowledgement intervenes
 * before destruction of the in-memory capability. A NULL barrier retains
 * clear() compatibility for both prepared and unprepared handles. */
int config_retirement_guard_clear_with_barrier(
    config_retirement_guard_t **guard,
    config_retirement_guard_precommit_fn barrier, void *context);

/* Release the lifecycle lock and free/NULL the handle without namespace
 * repair. A fork child disposing an inherited handle closes only its
 * descriptor references and child-local owner token; it never unlocks the
 * parent's shared flock description. This foreign-child disposal remains
 * valid when fork occurred inside a commit barrier; the creating process
 * still cannot abandon or reenter its own barrier. clear() never removes the
 * canonical marker; a failed transition may retain the one fixed stage, and
 * both states remain probe-blocking. */
void config_retirement_guard_abandon(config_retirement_guard_t **guard);

/* Durable recovery owner for a switch whose active-state before/post image
 * could not be classified. The canonical private marker binds the exact
 * accounts.toml generation, all target fields that affect Git/SSH/GPG live
 * state, the effective Git scope, and the complete destination set captured
 * by git_config_snapshot_export_destinations(). */
typedef struct config_switch_guard config_switch_guard_t;

#define CONFIG_SWITCH_DESTINATION_MAX 3U

typedef struct {
    bool valid;
    publication_identity_t source_generation;
    account_t target;
    git_scope_t effective_scope;
    publication_record_t destinations[CONFIG_SWITCH_DESTINATION_MAX];
    size_t destination_count;
} config_switch_guard_recovery_t;

/* Install a fresh `.switch-incomplete` generation, or adopt an existing one
 * only when every account/scope/path field matches and the current destination
 * still has the recorded directory authority. Mutable directory timestamps
 * are not identity. `target` must be the exact persisted incarnation in `ctx`;
 * `destinations` must be the complete, canonical pre-mutation Git destination
 * set for `effective_scope`: primary first, then any local and worktree
 * secondary scopes in precedence order. The returned opaque handle owns
 * `.switch.lock` until clear() or abandon(). */
int config_switch_guard_install_or_adopt(
    const gitswitch_ctx_t *ctx, const account_t *target,
    git_scope_t effective_scope,
    const publication_record_t *destinations, size_t destination_count,
    config_switch_guard_t **guard);

/* True only when this invocation durably installed the marker. Adoption of a
 * pre-existing recovery fence returns false, so rollback cannot accidentally
 * clear an older unresolved operation. */
bool config_switch_guard_was_created(
    const config_switch_guard_t *guard);

/* Reconcile only the two restart-safe pre-intent namespace shapes under the
 * private switch lifecycle lock: a lone stable private stage is removed, and
 * an exact stage/marker hard-link pair left by the portable no-replace
 * fallback is reduced to the canonical marker. No live identity mutation can
 * precede either shape. A normalized distinct pair is accepted only when both
 * entries are independently canonical and their complete serialized bytes
 * and decoded models are equal. Unsafe, changing, or unequal pairs fail
 * closed.
 * Callers that mutate account state must serialize this operation with the
 * ordinary configuration write lock and probe again before mutation. */
int config_switch_guard_reconcile_preintent(
    const char *config_path);

/* Read-only, fail-closed startup gate. `blocked` remains true for a canonical
 * marker or malformed/unsafe/unstable state. A stable private stage-only
 * generation, an exact stage/marker hard-link pair, and an independently
 * canonical normalized pair with byte-identical serialized contents and equal
 * decoded models are reported unblocked only so a real mutating entry can
 * acquire the configuration lock, call
 * config_switch_guard_reconcile_preintent(), and probe again; none of these
 * shapes authorizes resume. A stable canonical marker is decoded into
 * `recovery`; absent state returns blocked=false and recovery.valid=false.
 * This call never creates or repairs filesystem state. */
int config_switch_guard_probe(
    const char *config_path, bool *blocked,
    config_switch_guard_recovery_t *recovery);

/* Remove only the exact marker generation owned by `guard`, synchronize the
 * pinned directory, and re-prove marker absence before releasing the lock.
 * Failure retains the handle for checked cleanup or abandon(). */
int config_switch_guard_clear(config_switch_guard_t **guard);

/* Re-establish and durably prove the exact canonical marker owned by `guard`
 * after a failed clear may already have unlinked it, then release and NULL the
 * handle. This is the checked failure-settlement path: success guarantees a
 * restart can adopt the marker; failure retains the callable handle. */
int config_switch_guard_retain(config_switch_guard_t **guard);

/* Release the lifecycle lock and free/NULL the handle without changing either
 * fixed switch-guard namespace entry. A fork child disposing an inherited
 * handle closes only descriptor references and its child-local owner token;
 * it cannot unlock the parent's shared flock description. */
void config_switch_guard_abandon(config_switch_guard_t **guard);

/* Refresh only the Git post-config generation witnesses for PUBLISHED ledger
 * records owned by `owners`. Every matching record must find exactly one
 * destination with the same Git config path; duplicate, missing, or unused
 * destination inputs fail before publication. The active header and all other
 * records are preserved semantically through the ordinary atomic active-state
 * writer. `state_installed` follows the same rename/dir-sync classification as
 * config_save_active_account_transactional().
 */
int config_refresh_retirement_publications_transactional(
    gitswitch_ctx_t *ctx, const char *config_path,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_destination_t *destinations,
    size_t destination_count, bool *state_installed);

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
    bool before_image_valid;
    struct stat before_image;
    char config_path[MAX_PATH_LEN];
    bool post_image_bound;
    bool post_image_installed;
    bool post_image_valid;
    struct stat post_image;
    unsigned char *post_image_data;
    size_t post_image_length;
} config_resume_hint_snapshot_t;

/* A guarded active-state rollback can fail after either image has become the
 * stable namespace occupant.  Callers that also own Git/runtime settlement
 * must branch on the image that is durably current instead of treating every
 * restore error as permission to roll those other layers back. */
typedef enum {
    CONFIG_ACTIVE_ROLLBACK_UNRESOLVED = 0,
    CONFIG_ACTIVE_ROLLBACK_BEFORE_DURABLE,
    CONFIG_ACTIVE_ROLLBACK_POST_DURABLE
} config_active_rollback_state_t;

int config_resume_hint_snapshot_capture(config_resume_hint_snapshot_t *snapshot);
/* Restore accepts only a snapshot subsequently bound by
 * config_save_active_account_transactional_guarded (or the internal full-save
 * transaction). An unbound snapshot cannot identify which later state belongs
 * to its caller and is rejected instead of overwriting it. */
int config_resume_hint_snapshot_restore(
    const config_resume_hint_snapshot_t *snapshot);
/* Attempt the guarded restore, then prove and synchronize whichever complete
 * image is currently installed.  Success means state is BEFORE_DURABLE or
 * POST_DURABLE; UNRESOLVED is always returned with -1 and authorizes neither
 * the matching account abort nor commit. */
int config_resume_hint_snapshot_settle(
    const config_resume_hint_snapshot_t *snapshot,
    config_active_rollback_state_t *state);
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
/* Merge one required, valid sealed Git publication into the same atomic
 * active-state bundle. The exact destination replaces its prior owner; other
 * repositories/scopes remain recorded. Use the ordinary guarded save above
 * when no publication is being merged and the current ledger must be
 * preserved. */
int config_save_active_account_publication_transactional_guarded(
    gitswitch_ctx_t *ctx, const char *config_path,
    const publication_record_t *publication,
    bool *config_installed,
    config_resume_hint_snapshot_t *rollback_snapshot);
/* Read the optional publication ledger from a stable active-state bundle.
 * Historical state returns a successful ledger-absent model. Before its first
 * load, `ledger` must be initialized with publication_ledger_init(); the load
 * clears its prior contents before reading, including on failure. Clear the
 * final model with publication_ledger_clear(). */
int config_load_publication_ledger(const char *config_path,
                                   publication_ledger_t *ledger);
/* Fail-before-mutation capacity gate for one worst-case new publication.
 * This deliberately remains conservative when a later upsert may replace an
 * existing record. */
int config_publication_preflight(const char *config_path);
/* AR-12 H2: destination-aware capacity preflight. A destination that already
 * has a ledger record is admitted as an in-place replacement; NULL falls
 * back to the conservative worst-case-append check. */
int config_publication_preflight_destination(
    const char *config_path, const publication_record_t *destination);
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
 * Serialize generated shell-startup resume operations for one configuration.
 * Unlike config_write_lock(), this typed handoff waits briefly for another
 * startup resume to finish so concurrent shells can recheck the final runtime
 * before refreshing their environment. The wait is bounded because the owner
 * may itself be waiting at a PIN/passphrase prompt. Acquire it before the
 * ordinary config write lock and release it with
 * config_startup_resume_unlock(). EAGAIN/EWOULDBLOCK means the bound expired.
 */
int config_startup_resume_lock(void);
void config_startup_resume_unlock(int token_fd);

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

/* Account-operation capability variants. The token is accepted only for the
 * exact ADD/EDIT/REMOVE owner and context while that transaction is entering;
 * callers cannot query a live token. */
int config_add_account_owned(gitswitch_ctx_t *ctx, const account_t *account,
                             uint64_t transaction_token);

/**
 * Remove account from configuration
 */
int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id);
int config_remove_account_owned(gitswitch_ctx_t *ctx, uint32_t account_id,
                                uint64_t transaction_token);

/**
 * Update existing account in configuration
 */
int config_update_account(gitswitch_ctx_t *ctx, const account_t *account);
int config_update_account_owned(gitswitch_ctx_t *ctx,
                                const account_t *account,
                                uint64_t transaction_token);

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
