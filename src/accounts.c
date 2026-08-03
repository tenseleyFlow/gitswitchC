/* Account management and operations with comprehensive security validation
 * Implements secure account switching and management for gitswitch-c
 */

/* Enable POSIX extensions for setenv/unsetenv and related process APIs.
 * Darwin needs its extension namespace restored before system headers.
 * FreeBSD must retain its default BSD namespace because project headers
 * require O_PATH for descriptor-conditioned retirement. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#if !defined(__FreeBSD__)
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include "accounts.h"
#include "config.h"
#include "display.h"
#include "error.h"
#include "utils.h"
#include "git_ops.h"
#define GITSWITCH_INTERNAL_API
#include "git_ops_internal.h"
#include "git_status_internal.h"
#include "runner_internal.h"
#include "ssh_manager_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "gpg_manager.h"
#include "prompt.h"
#include "signals.h"
#include "toml_parser.h"

#ifdef GITSWITCH_TESTING
void gitswitch_test_remove_checkpoint(int stage);
#define REMOVE_TEST_CHECKPOINT(stage) \
    gitswitch_test_remove_checkpoint((stage))
#else
#define REMOVE_TEST_CHECKPOINT(stage) ((void)(stage))
#endif

/* Active session state - tracks SSH/GPG resources for proper cleanup */
typedef struct {
    ssh_config_t ssh_config;
    gpg_config_t gpg_config;
    bool ssh_active;
    bool gpg_active;
} active_session_t;

/* Static session state - only one active session at a time */
static active_session_t g_session = {0};

/* A CLI switch is not committed until main has durably persisted the matching
 * active-account and resume-hint state. Direct library callers keep the
 * historical one-call behavior through accounts_switch(); the CLI uses the
 * prepare/commit/abort trio so the rollback inputs and runtime lock survive
 * across the configuration commit. */
typedef struct {
    bool active;
    bool abort_only;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    account_t previous_account;
    bool had_previous_account;
    char previous_active[MAX_NAME_LEN];
    char previous_gpg_home[MAX_PATH_LEN];
    bool previous_gpg_present;
    bool git_written;
    bool ssh_dirty;
    bool gpg_dirty;
    int runtime_lock_fd;
    uint32_t target_id;
    account_t frozen_target;
    account_t switch_target;
    git_scope_t scope;
    bool ssh_ok;
    bool gpg_ok;
    bool publication_valid;
    publication_record_t publication;
    config_switch_guard_t *guard;
    bool guard_created;
} pending_switch_t;

static pending_switch_t g_pending_switch = {0};

typedef struct {
    bool active;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    account_t original;
    account_t candidate;
    bool routing_changed;
    bool original_alias_exclusive;
    bool candidate_alias_attempted;
    bool original_alias_remove_attempted;
} pending_edit_t;

static pending_edit_t g_pending_edit = {0};

typedef enum {
    PENDING_RETIREMENT_NONE = 0,
    PENDING_RETIREMENT_PREPARED,
    PENDING_RETIREMENT_PUBLISHED
} pending_retirement_phase_t;

typedef struct {
    git_retirement_transaction_t *git;
    config_retirement_guard_t *guard;
    config_retirement_owner_t owners[MAX_ACCOUNTS];
    size_t owner_count;
    pid_t creator_pid;
    pending_retirement_phase_t phase;
    /* Git and marker ownership are independent: an alias-only REMOVE has a
     * durable guard but no Git transaction, while a truly empty retirement
     * owns neither. */
    bool truly_vacuous;
    bool git_vacuous;
    bool guarded;
    bool has_ssh_alias_obligation;
    config_retirement_ssh_alias_obligation_t ssh_alias_obligation;
} pending_retirement_t;

/* CLI removal cannot retire an exclusive ~/.ssh/config alias until the
 * matching account deletion crosses the accounts.toml publication point.
 * The same retained record owns the descriptor-pinned Git before-images and
 * durable incomplete marker across main's transactional save. Direct library
 * calls keep their historical one-call behavior. */
typedef struct {
    bool active;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    char alias[MAX_NAME_LEN];
    bool alias_exclusive;
    pending_retirement_t retirement;
    /* AR-12 P1: the deleted account's pre-removal snapshot, so a
     * PREINSTALL_FAILED finalize can restore the in-memory model to agree
     * with the durable file it declares the retry handle. */
    account_t removed_account;
    bool removed_valid;
    bool removed_was_active;
    bool removed_was_current;
} pending_remove_t;

static pending_remove_t g_pending_remove = {0};
static account_t g_pending_remove_snapshot;

typedef struct {
    bool active;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    pending_retirement_t retirement;
} pending_reset_t;

static pending_reset_t g_pending_reset = {0};

typedef struct {
    bool active;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    size_t account_count_before;
    uint32_t current_account_id;
    bool had_current_account;
} pending_add_t;

static pending_add_t g_pending_add = {0};

typedef struct {
    accounts_transaction_kind_t kind;
    accounts_transaction_phase_t phase;
    accounts_transaction_token_t token;
    gitswitch_ctx_t *ctx;
    size_t rollback_depth;
    pid_t creator_pid;
} accounts_transaction_owner_t;

static accounts_transaction_owner_t g_transaction_owner = {0};
static accounts_transaction_token_t g_next_transaction_token = 0;
static pid_t g_accounts_process_pid = 0;
static bool g_accounts_epoch_cleanup_pending = false;
static bool g_accounts_signal_reset_pending = false;

/* Process-global account state is copied by fork(), but none of its ownership
 * transfers to the child.  Lazily discard that inherited copy before any
 * account transaction or session entry point can observe it.  Descriptor
 * disposal is deliberately non-unlocking: closing the child's duplicate
 * cannot release the parent's process-owned protocol lock. */
static int accounts_process_epoch_gate(bool inherited_operation) {
    pid_t current_pid = getpid();
    bool epoch_changed = false;

    if (g_accounts_process_pid == 0) {
        g_accounts_process_pid = current_pid;
    } else if (g_accounts_process_pid != current_pid) {
        g_accounts_process_pid = current_pid;
        epoch_changed = true;
        g_accounts_epoch_cleanup_pending = true;
        g_accounts_signal_reset_pending = true;
    }

    if (g_accounts_epoch_cleanup_pending) {
        git_config_abandon_inherited_transaction();
        runtime_state_lock_abandon_inherited();
        g_pending_switch.runtime_lock_fd = -1;
        config_switch_guard_abandon(&g_pending_switch.guard);
        config_retirement_guard_abandon(
            &g_pending_remove.retirement.guard);
        config_retirement_guard_abandon(
            &g_pending_reset.retirement.guard);

        /* commit() has an explicit foreign-creator path which only releases
         * inherited descriptors/storage. abort() would perform namespace
         * rollback and must never be used here. */
        if (g_pending_remove.retirement.git) {
            (void)git_retirement_transaction_commit(
                &g_pending_remove.retirement.git);
        }
        if (g_pending_reset.retirement.git) {
            (void)git_retirement_transaction_commit(
                &g_pending_reset.retirement.git);
        }

        /* Never erase an opaque retry handle. Although each abandon path is
         * expected to consume a foreign-process copy, retain the complete
         * pending containers and retry on the next entry if that invariant is
         * ever violated. */
        if (g_pending_switch.guard ||
            g_pending_remove.retirement.guard ||
            g_pending_reset.retirement.guard ||
            g_pending_remove.retirement.git ||
            g_pending_reset.retirement.git) {
            errno = EIO;
            set_error(
                ERR_SYSTEM_CALL,
                "Failed to release inherited account transaction descriptors");
            return -1;
        }
        memset(&g_pending_switch, 0, sizeof(g_pending_switch));
        memset(&g_pending_edit, 0, sizeof(g_pending_edit));
        memset(&g_pending_add, 0, sizeof(g_pending_add));
        memset(&g_pending_remove, 0, sizeof(g_pending_remove));
        memset(&g_pending_remove_snapshot, 0,
               sizeof(g_pending_remove_snapshot));
        memset(&g_pending_reset, 0, sizeof(g_pending_reset));
        memset(&g_transaction_owner, 0, sizeof(g_transaction_owner));
        memset(&g_session, 0, sizeof(g_session));
        g_accounts_epoch_cleanup_pending = false;
    }

    if (g_accounts_signal_reset_pending) {
        if (signals_reset_inherited_transaction_state() != 0) {
            return -1;
        }
        g_accounts_signal_reset_pending = false;
    }
    if (epoch_changed && inherited_operation) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Inherited account transaction finalization is invalid in the child process");
        return -1;
    }
    return 0;
}

static const char *transaction_kind_name(accounts_transaction_kind_t kind) {
    switch (kind) {
        case ACCOUNTS_TRANSACTION_INITIALIZE: return "initialization";
        case ACCOUNTS_TRANSACTION_SWITCH: return "switch";
        case ACCOUNTS_TRANSACTION_ADD: return "add";
        case ACCOUNTS_TRANSACTION_EDIT: return "edit";
        case ACCOUNTS_TRANSACTION_REMOVE: return "remove";
        case ACCOUNTS_TRANSACTION_RESET: return "reset";
        case ACCOUNTS_TRANSACTION_NONE: return "none";
        default: return "invalid";
    }
}

static bool transaction_kind_valid(accounts_transaction_kind_t kind) {
    return kind >= ACCOUNTS_TRANSACTION_INITIALIZE &&
           kind <= ACCOUNTS_TRANSACTION_RESET;
}

static bool pending_account_record_live(void) {
    return g_pending_switch.active || g_pending_edit.active ||
           g_pending_remove.active || g_pending_add.active ||
           g_pending_reset.active;
}

static int transaction_require(gitswitch_ctx_t *ctx,
                               accounts_transaction_kind_t kind,
                               accounts_transaction_token_t token,
                               const char *operation) {
    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || !transaction_kind_valid(kind) || token == 0 ||
        g_transaction_owner.creator_pid != getpid() ||
        g_transaction_owner.kind != kind ||
        g_transaction_owner.ctx != ctx ||
        g_transaction_owner.token != token) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot %s %s transaction: owner kind, context, or token does not match",
                  operation ? operation : "finalize",
                  transaction_kind_name(kind));
        return -1;
    }
    return 0;
}

static int transaction_require_phase(
    accounts_transaction_kind_t kind,
    accounts_transaction_phase_t first,
    accounts_transaction_phase_t second,
    const char *operation) {
    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (g_transaction_owner.creator_pid == getpid() &&
        g_transaction_owner.kind == kind &&
        (g_transaction_owner.phase == first ||
         g_transaction_owner.phase == second)) {
        return 0;
    }
    errno = EBUSY;
    set_error(ERR_SYSTEM_CALL,
              "Cannot %s %s transaction from phase %d",
              operation ? operation : "finalize",
              transaction_kind_name(kind),
              (int)g_transaction_owner.phase);
    return -1;
}

int accounts_transaction_begin(gitswitch_ctx_t *ctx,
                               accounts_transaction_kind_t kind,
                               accounts_transaction_token_t *token) {
    accounts_transaction_token_t next;

    if (accounts_process_epoch_gate(false) != 0) return -1;

    /* A live process-global owner wins before per-call validation. This is
     * both the serialization boundary and a causal guarantee: even a broken
     * competing request cannot observe a different admission path or consume
     * any pending finalizer state. */
    if (g_transaction_owner.kind != ACCOUNTS_TRANSACTION_NONE ||
        pending_account_record_live()) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot begin %s transaction: %s transaction token %llu is already pending (%s)",
                  transaction_kind_name(kind),
                  transaction_kind_name(g_transaction_owner.kind),
                  (unsigned long long)g_transaction_owner.token,
                  g_transaction_owner.phase == ACCOUNTS_TRANSACTION_ABORT_ONLY
                      ? "awaiting abort retry" : "active");
        return -1;
    }
    if (!ctx || !token || !transaction_kind_valid(kind)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid account transaction admission");
        return -1;
    }
    if (signals_guard_active() || signals_rollback_active()) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot begin %s transaction while signal cleanup or rollback ownership is active",
                  transaction_kind_name(kind));
        return -1;
    }

    if (g_next_transaction_token == UINT64_MAX) {
        errno = EOVERFLOW;
        set_error(ERR_SYSTEM_CALL,
                  "Account transaction token space is exhausted");
        return -1;
    }
    next = g_next_transaction_token + 1;
    g_next_transaction_token = next;
    g_transaction_owner.kind = kind;
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ENTERING;
    g_transaction_owner.token = next;
    g_transaction_owner.ctx = ctx;
    g_transaction_owner.rollback_depth = 0;
    g_transaction_owner.creator_pid = getpid();
    *token = next;
    return 0;
}

int accounts_transaction_rollback_begin(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token) {
    if (transaction_require(ctx, kind, token, "extend rollback for") != 0) {
        return -1;
    }
    if (g_transaction_owner.rollback_depth == SIZE_MAX) {
        errno = EOVERFLOW;
        set_error(ERR_SYSTEM_CALL,
                  "Account transaction rollback nesting depth overflow");
        return -1;
    }
    if (signals_rollback_begin_owned(token) != 0) return -1;
    g_transaction_owner.rollback_depth++;
    return 0;
}

int accounts_transaction_rollback_end(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token) {
    if (transaction_require(ctx, kind, token, "reduce rollback for") != 0) {
        return -1;
    }
    if (g_transaction_owner.rollback_depth == 0) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Account transaction has no rollback depth to release");
        return -1;
    }
    if (signals_rollback_end_owned(token) != 0) return -1;
    g_transaction_owner.rollback_depth--;
    return 0;
}

int accounts_transaction_finish(gitswitch_ctx_t *ctx,
                                accounts_transaction_kind_t kind,
                                accounts_transaction_token_t token) {
    if (transaction_require(ctx, kind, token, "finish") != 0) return -1;
    if (g_transaction_owner.rollback_depth != 0) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot finish %s transaction with rollback depth %zu",
                  transaction_kind_name(kind),
                  g_transaction_owner.rollback_depth);
        return -1;
    }
    memset(&g_transaction_owner, 0, sizeof(g_transaction_owner));
    return 0;
}

int accounts_transaction_authorize_model_mutation(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token) {
    if (accounts_process_epoch_gate(
            !(kind == ACCOUNTS_TRANSACTION_NONE && token == 0)) != 0) {
        return -1;
    }
    if (kind == ACCOUNTS_TRANSACTION_NONE && token == 0) {
        if (g_transaction_owner.kind == ACCOUNTS_TRANSACTION_NONE &&
            !pending_account_record_live()) {
            return 0;
        }
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot mutate the public account model while %s transaction token %llu is active",
                  transaction_kind_name(g_transaction_owner.kind),
                  (unsigned long long)g_transaction_owner.token);
        return -1;
    }
    if (kind != ACCOUNTS_TRANSACTION_ADD &&
        kind != ACCOUNTS_TRANSACTION_EDIT &&
        kind != ACCOUNTS_TRANSACTION_REMOVE) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid account-model transaction authorization");
        return -1;
    }
    if (transaction_require(ctx, kind, token, "authorize model mutation for") !=
        0) {
        return -1;
    }
    if (g_transaction_owner.phase != ACCOUNTS_TRANSACTION_ENTERING) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot mutate the %s account model from transaction phase %d",
                  transaction_kind_name(kind),
                  (int)g_transaction_owner.phase);
        return -1;
    }
    return 0;
}

bool accounts_transaction_context_release_safe(const gitswitch_ctx_t *ctx) {
    if (accounts_process_epoch_gate(false) != 0) return false;
    if (!ctx) return false;

    if (g_transaction_owner.kind != ACCOUNTS_TRANSACTION_NONE &&
        g_transaction_owner.ctx == ctx) {
        return false;
    }
    if ((g_pending_switch.active && g_pending_switch.ctx == ctx) ||
        (g_pending_add.active && g_pending_add.ctx == ctx) ||
        (g_pending_edit.active && g_pending_edit.ctx == ctx) ||
        (g_pending_remove.active && g_pending_remove.ctx == ctx) ||
        (g_pending_reset.active && g_pending_reset.ctx == ctx)) {
        return false;
    }
    return true;
}

static int transaction_mark_phase(gitswitch_ctx_t *ctx,
                                  accounts_transaction_kind_t kind,
                                  accounts_transaction_token_t token,
                                  accounts_transaction_phase_t phase) {
    if (transaction_require(ctx, kind, token, "advance") != 0) return -1;
    g_transaction_owner.phase = phase;
    return 0;
}

static int transaction_ensure_rollback(accounts_transaction_kind_t kind) {
    if (g_transaction_owner.creator_pid != getpid() ||
        g_transaction_owner.kind != kind || !g_transaction_owner.ctx ||
        g_transaction_owner.token == 0) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot arm rollback without the matching %s transaction owner",
                  transaction_kind_name(kind));
        return -1;
    }
    if (g_transaction_owner.rollback_depth != 0) return 0;
    return accounts_transaction_rollback_begin(
        g_transaction_owner.ctx, kind, g_transaction_owner.token);
}

static int transaction_finish_after_call(
    gitswitch_ctx_t *ctx, accounts_transaction_kind_t kind,
    accounts_transaction_token_t token, bool transfer_signal_deferral) {
    if (g_transaction_owner.creator_pid != getpid() ||
        g_transaction_owner.kind != kind ||
        g_transaction_owner.token != token) {
        return 0;
    }
    if (transfer_signal_deferral &&
        g_transaction_owner.rollback_depth > 0) {
        signals_rollback_begin();
    }
    while (g_transaction_owner.rollback_depth > 0) {
        if (accounts_transaction_rollback_end(ctx, kind, token) != 0) {
            return -1;
        }
    }
    return accounts_transaction_finish(ctx, kind, token);
}

/* Internal helper functions */
static int get_next_available_id(const gitswitch_ctx_t *ctx,
                                 uint32_t *account_id);
static int account_incarnation_admits_publication(
    const gitswitch_ctx_t *ctx, const account_t *account);
static bool prompt_host_alias_valid(const char *alias);
static int validate_gpg_key_availability(const char *gpg_key_id);
static int validate_gpg_key_availability_fresh(const char *gpg_key_id);
static void print_terminal_safe(const char *text);
static int check_ssh_key_local_file(const account_t *account);
static int check_gpg_key_local_state(
    const account_t *account, gpg_account_key_readiness_t *readiness);
static int pending_retirement_prepare(
    const gitswitch_ctx_t *ctx, config_retirement_kind_t kind,
    const account_t *const targets[], size_t target_count,
    const config_retirement_ssh_alias_obligation_t *ssh_alias_obligation,
    pending_retirement_t *retirement);
static int pending_retirement_cancel_unpublished(
    pending_retirement_t *retirement);
static int pending_retirement_publish(
    pending_retirement_t *retirement, size_t *cleared);
static int pending_retirement_finalize(
    gitswitch_ctx_t *ctx, pending_retirement_t *retirement,
    accounts_retirement_save_outcome_t outcome);

/* current_account is public context state but, when present, must be an exact
 * interior pointer to one of the currently live fixed-array slots. Compare
 * addresses only until that provenance is proven; dereferencing an arbitrary
 * non-NULL pointer here would recreate the stale/UAF hazard this guard owns. */
static bool accounts_current_pointer_is_live(const gitswitch_ctx_t *ctx) {
    size_t count;

    if (!ctx || !ctx->current_account) return true;
    if (ctx->account_count > MAX_ACCOUNTS) return false;
    count = ctx->account_count;
    for (size_t i = 0; i < count; i++) {
        if (ctx->current_account == &ctx->accounts[i]) return true;
    }
    return false;
}

static int accounts_require_current_pointer_live(
    const gitswitch_ctx_t *ctx, const char *operation) {
    if (accounts_current_pointer_is_live(ctx)) return 0;
    errno = ESTALE;
    set_error(ERR_ACCOUNT_INVALID,
              "Cannot %s with a stale current-account reference",
              operation ? operation : "continue");
    return -1;
}

static bool gpg_session_cleanup_needed(void) {
    return g_session.gpg_active ||
           gpg_manager_runtime_restore_pending(&g_session.gpg_config) ||
           g_session.gpg_config.environment_installed ||
           g_session.gpg_config.current_key_id[0] != '\0';
}

static bool account_session_cleanup_needed(void) {
    return g_session.ssh_active || gpg_session_cleanup_needed();
}

static int accounts_session_cleanup_internal(void);

/* Initialize accounts system */
int accounts_init(gitswitch_ctx_t *ctx) {
    accounts_transaction_token_t token;

    if (accounts_process_epoch_gate(false) != 0) return -1;
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_init");
        return -1;
    }

    /* This API initializes only caller-owned model storage. Process-global
     * session, transaction, guard, and rollback state has an explicit cleanup
     * path and must never disappear behind a convenience initializer. */
    if (account_session_cleanup_needed()) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot initialize accounts while runtime session cleanup is pending");
        return -1;
    }
    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_INITIALIZE,
                                   &token) != 0) {
        return -1;
    }

    /* Initialize account array */
    memset(ctx->accounts, 0, sizeof(ctx->accounts));
    ctx->account_count = 0;
    ctx->current_account = NULL;

    log_debug("Accounts system initialized");
    return accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_INITIALIZE,
                                       token);
}

/* Clean up active session resources. If an owned SSH/GPG side effect survives,
 * retain the complete session as its retry handle; clearing any of it would
 * make the still-live identity/environment untrackable and misreport success. */
int accounts_session_cleanup(void) {
    if (accounts_process_epoch_gate(false) != 0) return -1;
    if (g_transaction_owner.kind != ACCOUNTS_TRANSACTION_NONE) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Cannot clean the account session while %s transaction token %llu is active",
                  transaction_kind_name(g_transaction_owner.kind),
                  (unsigned long long)g_transaction_owner.token);
        return -1;
    }
    return accounts_session_cleanup_internal();
}

static int accounts_session_cleanup_internal(void) {
    log_debug("Cleaning up active session resources");

    /* Clean up SSH agent if we started one */
    if (g_session.ssh_active) {
        log_info("Stopping SSH agent (pid=%d)", g_session.ssh_config.agent_pid);
        if (ssh_manager_cleanup(&g_session.ssh_config) != 0) {
            log_warning("Active SSH session cleanup remains retryable; retaining session state");
            return -1;
        }
        g_session.ssh_active = false;
    }

    /* Clean up GPG environment if we modified it */
    if (gpg_session_cleanup_needed()) {
        log_info("Cleaning up GPG environment");
        if (gpg_manager_cleanup(&g_session.gpg_config) != 0) {
            log_warning("Active GPG session survived cleanup; retaining session for retry");
            return -1;
        }
        g_session.gpg_active = false;
    }

    /* Clear session state */
    memset(&g_session, 0, sizeof(g_session));
    log_debug("Session cleanup complete");
    return 0;
}

/* Deactivate the runtime SSH and/or GPG isolation so the stable entry points
 * (current.sock symlink, GNUPGHOME `current` symlink) no longer point at an
 * account. Used when switching to an account that has SSH/GPG disabled (so the
 * previous account's agent/home doesn't stay live behind the switch) and when
 * rolling back a failed switch. Removing the symlink makes integrated shells
 * fall back to the default agent/keyring rather than silently keep using the
 * old account — the exact mismatch this guards against. */
static int deactivate_runtime_isolation(bool ssh, bool gpg) {
    char ssh_error[sizeof(g_last_error.message)] = "";
    char gpg_error[sizeof(g_last_error.message)] = "";
    int rc = 0;

    if (ssh) {
        /* Reaps every gitswitch agent and removes current.sock. */
        if (ssh_manager_reset(NULL) != 0) {
            snprintf(ssh_error, sizeof(ssh_error), "%s",
                     get_last_error()->message[0] ? get_last_error()->message
                                                  : "unknown SSH teardown error");
            rc = -1;
        } else {
            g_session.ssh_active = false;
        }
    }
    if (gpg) {
        /* Locked drop: a bare unlink here raced a concurrent switch's
         * retarget and could delete its freshly-installed link (AR-02 #9). */
        if (gpg_manager_drop_current() != 0) {
            snprintf(gpg_error, sizeof(gpg_error), "%s",
                     get_last_error()->message[0] ? get_last_error()->message
                                                  : "unknown GPG teardown error");
            rc = -1;
        }
        g_session.gpg_active = false;
    }

    if (rc != 0) {
        if (ssh_error[0] && gpg_error[0]) {
            set_error(ERR_SYSTEM_CALL,
                      "Runtime deactivation incomplete (SSH: %s; GPG: %s)",
                      ssh_error, gpg_error);
        } else if (ssh_error[0]) {
            set_error(ERR_SYSTEM_CALL,
                      "Runtime deactivation incomplete (SSH: %s)", ssh_error);
        } else {
            set_error(ERR_SYSTEM_CALL,
                      "Runtime deactivation incomplete (GPG: %s)", gpg_error);
        }
    }
    return rc;
}

/* F4: starting the new account's agent already reaped the previous one, so a
 * failed switch re-activates that previous SSH agent. This may legitimately
 * re-prompt for a passphrase; a restore failure only warns because the durable
 * Git identity rollback already succeeded. GPG restoration is handled by the
 * conflict-aware helper below. */
static int restore_previous_ssh_isolation(const account_t *prev,
                                          bool ssh_torn_down) {
    if (ssh_torn_down && prev &&
        prev->ssh_enabled && strlen(prev->ssh_key_path) > 0) {
        account_t runtime_target = *prev;

        /* ~/.ssh/config was never changed on a failed transaction: the alias
         * writer is the final success commit. Restore only the agent/key here
         * so rollback cannot rewrite a concurrent user's config update. */
        runtime_target.ssh_host_alias[0] = '\0';
        printf("  [..] Restoring SSH agent for previous account: %s\n", prev->name);
        memset(&g_session.ssh_config, 0, sizeof(g_session.ssh_config));
        if (ssh_manager_init(&g_session.ssh_config, SSH_AGENT_ISOLATED) == 0 &&
            ssh_switch_account(&g_session.ssh_config, &runtime_target) == 0) {
            g_session.ssh_active = true;
            printf("  [OK] Previous SSH agent restored\n");
            return 0;
        } else {
            log_warning("Could not restore SSH agent for previous account: %s",
                        prev->name);
            return -1;
        }
    }
    return 0;
}

/* Restore the GPG link only when it still contains the state installed by
 * this transaction. A separate gitswitch process can share XDG_RUNTIME_DIR
 * while using a different HOME (and therefore a different outer config
 * lock); an unconditional drop+retarget here would overwrite that later
 * writer. NULL means the transaction expected/previously observed no link. */
static int restore_previous_gpg_isolation(const char *prev_gpg_home,
                                          bool prev_gpg_present,
                                          bool gpg_dirty) {
    const char *expected = NULL;
    const char *restore = prev_gpg_present ? prev_gpg_home : NULL;
    bool changed = false;

    if (!gpg_dirty) {
        return 0;
    }

    /* A failed inner retarget owns its own exact publication/restore pair.
     * Let the manager consume that retry record instead of reconstructing an
     * expected target from partial outer state. It also restores GNUPGHOME in
     * the same checked transaction and clears nothing on failure. */
    if (gpg_manager_runtime_restore_pending(&g_session.gpg_config)) {
        if (gpg_manager_cleanup(&g_session.gpg_config) != 0) {
            log_warning("Could not finish the retained GPG rollback: %s",
                        get_last_error()->message);
            return -1;
        }
        g_session.gpg_active = false;
        log_info("Finished the retained GPG runtime rollback");
        return 0;
    }
    if (g_session.gpg_active && g_session.gpg_config.gnupg_home[0] != '\0') {
        expected = g_session.gpg_config.gnupg_home;
    }

    if (gpg_manager_restore_current_if(&g_session.gpg_config, expected,
                                       restore, &changed) != 0) {
        log_warning("Could not restore the previous GPG runtime state safely: %s",
                    get_last_error()->message);
        return -1;
    } else if (!changed) {
        /* The rejected transaction no longer owns current.  This is a
         * successful compare-and-swap outcome: preserve the later writer and
         * retire only our process-local environment/session state. */
        log_warning("GPG runtime state changed concurrently; leaving the later state untouched");
    } else {
        log_info("Restored the previous GPG runtime state");
    }

    if (gpg_session_cleanup_needed() &&
        gpg_manager_cleanup(&g_session.gpg_config) != 0) {
        log_warning("GPG runtime was released but environment cleanup remains pending: %s",
                    get_last_error()->message);
        return -1;
    }
    g_session.gpg_active = false;
    return 0;
}

/* Complete signal ownership with exactly one restoration attempt. A pending
 * signal is dispatched only after every saved disposition is back; on any
 * restoration failure both the guard's failed bitmap and the pending signal
 * remain owned by signals.c for an explicit checked retry. */
static int finish_signal_guard_checked(const char *operation) {
    char detail[sizeof(g_last_error.message)];
    int pending_signal = signals_pending_signal();
    int cleanup_rc;
    int cleanup_errno;

    if (pending_signal != 0) {
        cleanup_rc = signals_dispatch_pending();
    } else {
        cleanup_rc = signals_guard_end();
        /* A guarded signal can land after the initial pending-state read but
         * before guard_end restores its handler. Exact restoration succeeded,
         * so recheck and dispatch that newly recorded signal rather than
         * returning a successful API call with stale pending ownership. */
        if (cleanup_rc == 0 && signals_pending()) {
            cleanup_rc = signals_dispatch_pending();
        }
    }
    if (cleanup_rc == 0) {
        return 0;
    }
    cleanup_errno = errno;
    pending_signal = signals_pending_signal();
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    errno = cleanup_errno;
    if (pending_signal != 0) {
        set_system_error(
            ERR_SYSTEM_CALL,
            "%s; pending signal %d remains deferred and signal-guard "
            "ownership was retained for retry: %s",
            operation, pending_signal,
            detail[0] ? detail : "unknown signal restoration error");
    } else {
        set_system_error(
            ERR_SYSTEM_CALL,
            "%s; signal-guard ownership was retained for retry: %s",
            operation,
            detail[0] ? detail : "unknown signal restoration error");
    }
    errno = cleanup_errno;
    return -1;
}

/* Common exit path for a switch that failed — or was interrupted by a signal —
 * after mutations began. Restores the pre-switch state in dependency order
 * (git identity first, then runtime isolation), cleans scratch files, drops
 * the signal guard, and finally re-raises a pending signal so the process
 * still reports death-by-signal. Returns -1 so callers can
 * `return abort_failed_switch(...)` (callers set their own error afterwards;
 * on the signal path the dispatch terminates the process instead). */
static int abort_failed_switch_checked(const account_t *prev,
                                       const char *prev_gpg_home,
                                       bool prev_gpg_present, bool git_written,
                                       bool ssh_dirty, bool gpg_dirty,
                                       int runtime_lock_fd,
                                       bool end_guard,
                                       bool keep_rollback_active,
                                       bool *git_remaining,
                                       bool *ssh_remaining,
                                       bool *gpg_remaining,
                                       bool *rollback_complete,
                                       char *rollback_detail,
                                       size_t rollback_detail_size,
                                       error_accumulator_t *rollback_errors) {
    error_accumulator_t local_errors;
    error_accumulator_t *errors = rollback_errors;
    bool publish_errors = false;
    bool complete = true;
    bool git_left = git_written;
    bool ssh_left = ssh_dirty;
    bool gpg_left = gpg_dirty;

    if (!errors) {
        error_accumulator_init(&local_errors);
        errors = &local_errors;
        publish_errors = true;
    }

    if (rollback_detail && rollback_detail_size > 0) {
        rollback_detail[0] = '\0';
    }

    /* AR-02 #2: a second guarded signal during this rollback used to take the
     * handler's emergency-kill branch and die mid-git_config_restore, leaving
     * a chimera (or fully-new) identity persisted. Defer the emergency exit
     * until the whole restore sequence has completed. */
    if (transaction_ensure_rollback(ACCOUNTS_TRANSACTION_SWITCH) != 0) {
        complete = false;
        (void)error_accumulator_add_last(errors,
                                         "transaction rollback admission");
    }
    if (git_written) {
        if (git_config_restore() != 0) {
            complete = false;
            (void)error_accumulator_add_last(errors,
                                             "Git configuration restore");
            log_warning("Incomplete rollback of Git configuration: %s",
                        get_last_error()->message);
        } else {
            git_left = false;
        }
    } else {
        /* Snapshot capture precedes the guarded runtime phases.  A failure
         * before the first possible Git write has no post-image to restore,
         * but it must still consume that read-only before-image before this
         * path releases the remaining transaction owners.  commit is an
         * infallible ownership discard and does not disturb the causal error.
         * Written/partially-written paths stay in the restore branch above so
         * an incomplete rollback retains its exact retry image. */
        git_config_commit();
    }
    /* Undo the new account's half-applied SSH/GPG activation: leaving
     * current.sock / GNUPGHOME pointed at the new account while the git
     * identity reverts is exactly the mixed identity the tool prevents. AR-06
     * F42: surface a teardown failure (a surviving new-account agent) instead
     * of discarding it — rollback is best-effort (the durable git identity was
     * already restored), so warn rather than abort. */
    bool ssh_deactivate_failed = false;
    if (deactivate_runtime_isolation(ssh_dirty, false) != 0) {
        complete = false;
        ssh_deactivate_failed = true;
        (void)error_accumulator_add_last(errors, "SSH runtime deactivation");
        log_warning("Incomplete rollback of the new account's SSH state: %s",
                    get_last_error()->message);
    }
    /* Restore GPG with compare-and-swap semantics so rollback cannot clobber
     * a later writer, then reactivate the previous SSH agent (F4). */
    if (restore_previous_gpg_isolation(prev_gpg_home, prev_gpg_present,
                                       gpg_dirty) != 0) {
        complete = false;
        (void)error_accumulator_add_last(errors, "GPG isolation restore");
    } else {
        gpg_left = false;
    }
    /* Do not overwrite the surviving new-agent retry handle when teardown
     * failed.  A later abort retry must first finish deactivating that exact
     * session; only then is it safe to replace g_session with the previous
     * account's restored agent metadata. */
    if (!ssh_deactivate_failed) {
        if (restore_previous_ssh_isolation(prev, ssh_dirty) != 0) {
            complete = false;
            (void)error_accumulator_add_last(errors,
                                             "SSH isolation restore");
        } else {
            ssh_left = false;
        }
    }
    /* SIG-02: drop any registered scratch temp files. */
    signals_scratch_cleanup();
    if (!keep_rollback_active) {
        if (g_transaction_owner.kind == ACCOUNTS_TRANSACTION_SWITCH &&
            g_transaction_owner.rollback_depth > 0 &&
            accounts_transaction_rollback_end(
                g_transaction_owner.ctx, ACCOUNTS_TRANSACTION_SWITCH,
                g_transaction_owner.token) != 0) {
            complete = false;
            (void)error_accumulator_add_last(errors,
                                             "transaction rollback release");
        }
    }
    runtime_state_lock_release(runtime_lock_fd);
    if (signals_pending() && !keep_rollback_active) {
        fprintf(stderr, "\ngitswitch: interrupted — switch rolled back, previous identity kept\n");
        set_error(ERR_SYSTEM_CALL, "Switch interrupted by signal %d",
                  signals_pending_signal());
        if (end_guard &&
            finish_signal_guard_checked("Switch rollback completed") != 0) {
            complete = false;
            (void)error_accumulator_add_last(errors, "signal guard release");
        }
    } else if (signals_pending()) {
        log_warning("Switch interruption remains deferred until config and "
                    "resume-hint rollback completes");
    } else if (end_guard &&
               finish_signal_guard_checked("Switch rollback completed") != 0) {
        complete = false;
        (void)error_accumulator_add_last(errors, "signal guard release");
    }
    if (git_remaining) *git_remaining = git_left;
    if (ssh_remaining) *ssh_remaining = ssh_left;
    if (gpg_remaining) *gpg_remaining = gpg_left;
    if (rollback_complete) {
        *rollback_complete = complete;
    }
    if (rollback_detail && rollback_detail_size > 0 && errors->active) {
        safe_strncpy(rollback_detail, errors->first_error.message,
                     rollback_detail_size);
    }
    if (publish_errors && errors->active) {
        (void)error_accumulator_publish(errors);
    }
    return -1;
}

static int abort_failed_switch(const account_t *prev, const char *prev_gpg_home,
                               bool prev_gpg_present, bool git_written,
                               bool ssh_dirty, bool gpg_dirty,
                               int runtime_lock_fd,
                               bool defer_signal_dispatch) {
    return abort_failed_switch_checked(prev, prev_gpg_home, prev_gpg_present,
                                       git_written, ssh_dirty, gpg_dirty,
                                       runtime_lock_fd,
                                       !defer_signal_dispatch,
                                       defer_signal_dispatch,
                                       NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

static int accounts_switch_abort_accumulated(
    gitswitch_ctx_t *ctx, bool continue_persistence_rollback,
    error_accumulator_t *abort_errors);

/* A failed prepared switch has not handed ownership to its caller. Publish
 * the rollback record first, then drive the same checked abort API a caller
 * would use. A complete abort clears the record synchronously; an incomplete
 * Git/runtime or signal-disposition cleanup leaves an explicit retry handle
 * instead of stranding process-global transaction state. Returns true only
 * when that retry handle remains published. Direct switches retain their
 * historical failure cleanup through abort_failed_switch(). */
static bool abort_switch_failure(pending_switch_t *prepared,
                                 const account_t *prev,
                                 const char *prev_gpg_home,
                                 bool prev_gpg_present, bool git_written,
                                 bool ssh_dirty, bool gpg_dirty,
                                 int runtime_lock_fd,
                                 bool defer_signal_dispatch) {
    error_accumulator_t failures;
    error_context_t failure;
    int failure_errno;

    if (!prepared) {
        abort_failed_switch(prev, prev_gpg_home, prev_gpg_present,
                            git_written, ssh_dirty, gpg_dirty,
                            runtime_lock_fd, defer_signal_dispatch);
        return false;
    }

    /* A restored caller handler is allowed to return from the deferred
     * dispatch.  In that case this prepared API also returns -1, so preserve
     * the interruption itself as the causal failure instead of whatever
     * successful sub-operation happened to touch the error context last. */
    if (signals_pending()) {
        set_error(ERR_SYSTEM_CALL, "Switch interrupted by signal %d",
                  signals_pending_signal());
    }
    failure = *get_last_error();
    failure_errno = errno;
    error_accumulator_init(&failures);
    errno = failure_errno;
    (void)error_accumulator_add(&failures, "switch preparation", &failure);
    prepared->git_written = git_written;
    prepared->ssh_dirty = ssh_dirty;
    prepared->gpg_dirty = gpg_dirty;
    prepared->runtime_lock_fd = runtime_lock_fd;
    prepared->abort_only = true;
    g_pending_switch = *prepared;
    (void)transaction_mark_phase(prepared->ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                 prepared->token,
                                 ACCOUNTS_TRANSACTION_ABORT_ONLY);

    (void)accounts_switch_abort_accumulated(
        prepared->ctx, false, &failures);
    if (!g_pending_switch.active || g_pending_switch.ctx != prepared->ctx) {
        return false;
    }
    return true;
}

/* Keep the manager/preflight diagnostic causal while the checked abort path
 * performs its own fallible cleanup and may publish rollback diagnostics. */
static bool abort_switch_failure_preserving_cause(
    pending_switch_t *prepared, const account_t *prev,
    const char *prev_gpg_home, bool prev_gpg_present, bool git_written,
    bool ssh_dirty, bool gpg_dirty, int runtime_lock_fd,
    bool defer_signal_dispatch) {
    error_context_t cause = *get_last_error();
    int cause_errno = errno;
    bool retained = abort_switch_failure(
        prepared, prev, prev_gpg_home, prev_gpg_present, git_written,
        ssh_dirty, gpg_dirty, runtime_lock_fd, defer_signal_dispatch);

    if (!retained) {
        g_last_error = cause;
        errno = cause_errno;
    }
    return retained;
}

static int observe_git_config_commit(void *context) {
    (void)context;
    git_config_commit();
    return 0;
}

static int observe_ssh_manager_cleanup(void *context) {
    return ssh_manager_cleanup((ssh_config_t *)context);
}

/* Best-effort probes and informational output run only after the switch's
 * required commits are complete. In the CLI transaction that means after the
 * active-account file and resume hint have both committed. */
typedef struct {
    const account_t *account;
    const char *host;
} ssh_probe_observation_t;

static int invoke_ssh_probe_observation(void *context) {
    const ssh_probe_observation_t *probe = context;
    int64_t deadline_millis;

    if (!probe) return -1;
    if (run_deadline_after_millis(7000, &deadline_millis) != 0) return -1;
    return ssh_test_connection_with_deadline(
        probe->account, probe->host, deadline_millis);
}

static int run_informational_ssh_probe(const account_t *account,
                                       const char *host) {
    ssh_probe_observation_t probe = {
        .account = account,
        .host = host,
    };

    /* Resolver, spawn, pipe, and signal-cleanup failures can publish a useful
     * runner diagnostic. This post-commit probe is explicitly observational,
     * so it must not replace or causally advance the operation's pre-existing
     * error contract. */
    return error_run_observational(invoke_ssh_probe_observation, &probe);
}

static void finish_switch_success(gitswitch_ctx_t *ctx, account_t *account,
                                  const account_t *switch_target,
                                  git_scope_t scope, bool write_git,
                                  bool ssh_ok, bool gpg_ok, bool full_success) {
    if (!ctx || !account || !switch_target) {
        return;
    }

    /* AR-13 L7: the affirmative outputs here (the SSH probe [OK]/[--] line, the
     * shell-init Tip, and the 'Successfully switched' log) assert a fully
     * completed switch. On a retained-but-uncertain commit (alias unverified,
     * durability uncertain, or post-commit cleanup failed) the CLI reports
     * failure, so emitting unqualified success would contradict the exit
     * status. Gate them on full_success; the local-validation warnings below
     * are diagnostic and run regardless. */
    if (full_success && !ctx->config.dry_run && account->ssh_enabled &&
        strlen(account->ssh_key_path) > 0 && ssh_ok &&
        !ctx->config.resuming && !ctx->config.recovering_switch &&
        !g_session.ssh_config.reused_existing_agent && !signals_pending()) {
        if (strlen(account->ssh_host_alias) > 0) {
            if (run_informational_ssh_probe(
                    switch_target, account->ssh_host_alias) == 0) {
                printf("  [OK] SSH connection verified (%s)\n",
                       account->ssh_host_alias);
            } else {
                printf("  [--] SSH connection could not be verified (%s)\n",
                       account->ssh_host_alias);
            }
        } else if (ctx->config.verbose &&
                   run_informational_ssh_probe(
                       switch_target, "git@github.com") == 0) {
            printf("  [OK] SSH connection verified (github.com)\n");
        }
    }

    if (!ctx->config.dry_run && write_git) {
        int validation_rc;

        if (switch_target->gpg_enabled &&
            switch_target->gpg_key_id[0] != '\0') {
            validation_rc = git_test_config_with_gpg_witness(
                switch_target, scope,
                g_session.gpg_config.executable_path,
                &g_session.gpg_config.executable_witness);
        } else {
            validation_rc =
                git_test_config(switch_target, scope, NULL);
        }
        if (validation_rc != 0) {
            log_warning("Git configuration validation failed: %s",
                        get_last_error()->message);
        }
    }

    if (!ctx->config.resuming) {
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
            !ssh_ok && check_ssh_key_local_file(account) != 0) {
            log_warning("SSH key local validation failed for account: %s",
                        account->name);
        }
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0 &&
            !gpg_ok) {
            gpg_account_key_readiness_t readiness;

            if (check_gpg_key_local_state(account, &readiness) != 0) {
                log_warning("GPG key local metadata/material check failed for "
                            "account: %s", account->name);
            }
        }
    }

    if (full_success && (ssh_ok || gpg_ok)) {
        printf("\n  Tip: wire your shell once so every switch takes effect transparently:\n");
        printf("    capture `gitswitch init <shell>` first, then evaluate/source it only\n");
        printf("    when generation succeeds (see README: shell integration).\n");
        if (gpg_ok) {
            printf("  Note: this scopes GNUPGHOME to a per-account keyring, so gpg in that\n");
            printf("        shell sees only '%s'. Use a shell without the integration for\n",
                   account->name);
            printf("        general gpg work (other keys, contacts, encryption).\n");
        }
    }

    if (full_success) {
        log_info("Successfully switched to account: %s (%s)", account->name,
                 account->description);
    } else {
        log_info("Account switch for '%s' committed, but post-commit "
                 "verification did not complete; see the command error output",
                 account->name);
    }
}

static bool ssh_alias_publication_is_installed(
    ssh_config_publication_state_t publication) {
    return publication == SSH_CONFIG_PUBLICATION_COMMITTED ||
           publication == SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED ||
           publication == SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN;
}

static accounts_switch_commit_state_t accounts_commit_state_for_alias(
    ssh_config_publication_state_t publication) {
    switch (publication) {
        case SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED:
            return ACCOUNTS_SWITCH_COMMIT_ALIAS_UNVERIFIED;
        case SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN:
            return ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN;
        case SSH_CONFIG_PUBLICATION_COMMITTED:
            return ACCOUNTS_SWITCH_COMMIT_ALIAS_CLEANUP_FAILED;
        case SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED:
        case SSH_CONFIG_PUBLICATION_UNCHANGED:
        default:
            return ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    }
}

static void set_retained_alias_publication_error(
    const char *account_name, ssh_config_publication_state_t publication,
    const char *detail, int system_errno) {
    char causal_detail[sizeof(g_last_error.message)];
    const char *truth;

    switch (publication) {
        case SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED:
            truth = "the installed SSH config public inode could not be "
                    "verified";
            break;
        case SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN:
            truth = "the installed SSH config entry could not be made "
                    "directory-durable";
            break;
        case SSH_CONFIG_PUBLICATION_COMMITTED:
            truth = "post-commit resource cleanup failed";
            break;
        case SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED:
        case SSH_CONFIG_PUBLICATION_UNCHANGED:
        default:
            truth = "publication returned an unexpected installed-state result";
            break;
    }
    safe_strncpy(causal_detail,
                 detail && detail[0] ? detail : "unknown SSH config error",
                 sizeof(causal_detail));
    if (system_errno != 0) {
        char suffix[sizeof(causal_detail)];
        int suffix_length = snprintf(suffix, sizeof(suffix), " (%s)",
                                     strerror(system_errno));
        size_t detail_length = strlen(causal_detail);

        /* Nested set_system_error() already rendered strerror(). Remove that
         * copy before wrapping so the causal errno survives without a
         * duplicate human-readable suffix. */
        if (suffix_length > 0 && (size_t)suffix_length < sizeof(suffix) &&
            detail_length >= (size_t)suffix_length &&
            memcmp(causal_detail + detail_length - (size_t)suffix_length,
                   suffix, (size_t)suffix_length) == 0) {
            causal_detail[detail_length - (size_t)suffix_length] = '\0';
        }
        errno = system_errno;
        set_system_error(
            ERR_FILE_IO,
            "Account switch to '%s' committed and its published SSH config "
            "state was retained, but %s: %s",
            account_name, truth, causal_detail);
    } else {
        set_error(
            ERR_FILE_IO,
            "Account switch to '%s' committed and its published SSH config "
            "state was retained, but %s: %s",
            account_name, truth, causal_detail);
    }
}

/* g_pending_switch owns singleton Git, runtime-lock, and signal-guard state.
 * Admission must precede even public argument validation: an invalid, preview,
 * or resume-style competing call is still forbidden from observing or
 * consuming any part of that transaction.  Only its matching commit/abort
 * APIs may inspect the retained record. */
/* Switch to specified account with SSH isolation and validation. */
static int accounts_switch_impl(gitswitch_ctx_t *ctx, const char *identifier,
                                bool defer_commit,
                                accounts_transaction_token_t token) {
    account_t *account;
    account_t switch_target;
    const char *scope_str;
    bool ssh_ok = false;
    bool gpg_ok = false;
    bool defer_signal_dispatch;
    bool alias_publication_retained = false;
    ssh_config_publication_state_t alias_publication =
        SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED;
    char alias_publication_detail[sizeof(g_last_error.message)] = "";
    int alias_publication_system_errno = 0;

    if (!ctx || !identifier || !*identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_switch");
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "switch accounts") != 0) {
        return -1;
    }
    if (!text_is_tty_safe(identifier)) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Account selector contains terminal control bytes or malformed UTF-8");
        return -1;
    }
    defer_signal_dispatch = defer_commit || ctx->config.defer_signal_cleanup;

    /* Find the account. On the boot-resume path the identifier is the persisted
     * exact name, so resolve it literally (AR-06 F22) — the id-first fuzzy
     * matcher could otherwise re-resolve a legacy all-digit name to a different
     * account whose id matches. Interactive switches keep the fuzzy matcher. */
    account = (ctx->config.resuming || ctx->config.recovering_switch)
        ? config_find_account_exact(ctx, identifier)
        : config_find_account(ctx, identifier);
    if (!account) {
        /* The fuzzy resolver already owns useful ambiguity/candidate detail.
         * Only the exact-name resume path returns NULL without setting it. */
        if (ctx->config.resuming || ctx->config.recovering_switch) {
            set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: %s", identifier);
        }
        return -1;
    }

    /* Basic validation */
    if (!validate_name(account->name) || !validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Account has invalid name or email");
        return -1;
    }
    switch_target = *account;

    /* Boot-time resume restores only the boot-volatile runtime state (SSH
     * agent, GNUPGHOME `current` symlink). The git config the original switch
     * wrote is persistent and survived the reboot, so resume must neither
     * resolve a scope nor rewrite git config — doing so made the shipped
     * default (local scope) hard-fail whenever the login shell wasn't inside
     * the original repo, leaving no agent restored and re-spawning a failing
     * resume before every prompt (AR-02 #8). */
    bool write_git = !ctx->config.resuming;

    if (write_git && !ctx->config.dry_run &&
        account_incarnation_admits_publication(ctx, account) != 0) {
        return -1;
    }

    /* L33: admission must execute the exact NUL/managed-block parser used by
     * the final alias publisher before even read-only Git discovery can spawn
     * a child. This is only a current-snapshot validation: the publisher still
     * locks, rereads, and identity-checks the then-current file at commit. */
    if (write_git && !ctx->config.dry_run &&
        ssh_preflight_host_alias_config(account) != 0) {
        return -1;
    }

    /* Determine git scope. Explicit --global/--local override the account
     * preference. Writing an identity GLOBALLY affects every repository on the
     * machine, so we never silently promote local->global outside a repo:
     * require explicit consent (interactive prompt) or the --global flag. */
    git_scope_t scope = account->preferred_scope;
    if (write_git) {
        if (ctx->config.force_global) {
            scope = GIT_SCOPE_GLOBAL;
        } else if (ctx->config.force_local) {
            scope = GIT_SCOPE_LOCAL;
        }
        if (scope == GIT_SCOPE_LOCAL && !git_is_repository()) {
            if (ctx->config.dry_run) {
                /* AR-06 F44: a preview must not run the interactive
                 * global-scope consent prompt (or abort) — nothing is being
                 * written. State what a real switch would require and preview
                 * the local scope the account actually prefers. */
                printf("Note: not in a git repository — a real switch would prompt to write\n"
                       "      %s's identity to your GLOBAL git config, or require --global.\n",
                       account->name);
            } else if (isatty(STDIN_FILENO)) {
                char resp[16];
                printf("Not in a git repository. Write %s's identity to your GLOBAL git\n"
                       "config (affects every repository on this machine)? [y/N]: ",
                       account->name);
                fflush(stdout);
                if (fgets(resp, sizeof(resp), stdin) && (resp[0] == 'y' || resp[0] == 'Y')) {
                    scope = GIT_SCOPE_GLOBAL;
                } else {
                    set_error(ERR_GIT_NOT_REPOSITORY,
                              "Switch aborted: not in a git repository (pass --global to write global config)");
                    return -1;
                }
            } else {
                set_error(ERR_GIT_NOT_REPOSITORY,
                          "Not in a git repository; pass --global to write global config, or run inside a repo");
                return -1;
            }
        }

        /* Initialize git operations if not already done */
        if (git_ops_init() != 0) {
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to initialize git operations");
            return -1;
        }
    }
    scope_str = (scope == GIT_SCOPE_LOCAL) ? "local" : "global";

    /* Show what we're doing */
    printf("Switching to account: %s <%s>\n", account->name, account->email);

    /* If not in dry-run mode, actually perform the switch.
     *
     * Ordering matters for safety: validate availability and capture the Git
     * before-image first (read-only), then activate SSH/GPG and write Git as
     * recoverable mutations. Required teardown follows, and the atomic
     * ~/.ssh/config host-alias rewrite is the final fallible commit. On any
     * earlier failure the Git/runtime state is restored; because the alias
     * writer has not run yet, rollback never needs to replace a user file.
     *
     * SIG-01: the whole mutation window is guarded against SIGINT/SIGTERM/
     * SIGHUP/SIGQUIT (Ctrl-C at the ssh-add passphrase or GPG pinentry prompt
     * is a normal path). The handler only records the signal; we check between
     * durable steps and run the same rollback as an explicit failure, so a
     * signal can no longer leave user.name=new/user.email=old or repointed
     * SSH/GPG state without the matching git identity. */
    if (!ctx->config.dry_run) {
        int runtime_lock_fd = runtime_state_lock_acquire();
        if (runtime_lock_fd < 0) {
            return -1;
        }

        /* The previously-active account (detected at startup) and the current
         * GNUPGHOME symlink target, captured before any mutation so a failed
         * switch can restore them (F4). */
        const account_t *prev_account = ctx->current_account;
        char prev_active[MAX_NAME_LEN] = "";
        char prev_gpg_home[MAX_PATH_LEN] = "";
        bool prev_gpg_present = false;
        pending_switch_t prepared_owner = {0};
        prepared_owner.token = token;
        safe_strncpy(prev_active, ctx->config.active_account,
                     sizeof(prev_active));
        if (gpg_manager_snapshot_current(prev_gpg_home,
                                         sizeof(prev_gpg_home),
                                         &prev_gpg_present) != 0) {
            runtime_state_lock_release(runtime_lock_fd);
            return -1;
        }
        if (defer_commit) {
            prepared_owner.active = true;
            prepared_owner.ctx = ctx;
            if (prev_account) {
                prepared_owner.previous_account = *prev_account;
                prepared_owner.had_previous_account = true;
            }
            safe_strncpy(prepared_owner.previous_active, prev_active,
                         sizeof(prepared_owner.previous_active));
            safe_strncpy(prepared_owner.previous_gpg_home, prev_gpg_home,
                         sizeof(prepared_owner.previous_gpg_home));
            prepared_owner.previous_gpg_present = prev_gpg_present;
            prepared_owner.target_id = account->id;
            prepared_owner.frozen_target = *account;
            prepared_owner.switch_target = switch_target;
            prepared_owner.scope = scope;
        }
        /* Mutation tracking for rollback: `dirty` means the runtime state was
         * (or may have been) repointed at the NEW account; `deferred` means
         * the target has SSH/GPG disabled and the teardown of the PREVIOUS
         * account's state is postponed past the point of no return (F4). */
        bool ssh_dirty = false, gpg_dirty = false;
        bool ssh_teardown_deferred = false, gpg_teardown_deferred = false;
        ssh_key_admission_t *ssh_admission = NULL;

        /* L17/M22 (accounts half): expand the SSH key path once and prove
         * OpenSSH can parse one bounded descriptor-backed generation before
         * any prior runtime is stopped. Retain that exact generation through
         * the remaining preflight and activation; a final namespace proof
         * immediately before teardown rejects an already-replaced path, while
         * activation consumes the retained bytes even if the source changes
         * later. The copy handed down carries the expanded absolute path. */
        /* --- 1. Validate availability up front (no mutation yet) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            char expanded_key[MAX_PATH_LEN];
            uint64_t validation_generation = error_report_generation();

            if (expand_path(account->ssh_key_path, expanded_key,
                            sizeof(expanded_key)) != 0) {
                if (error_report_generation() == validation_generation) {
                    set_error(ERR_INVALID_PATH,
                              "Cannot resolve SSH key path: %s",
                              account->ssh_key_path);
                }
                runtime_state_lock_release(runtime_lock_fd);
                return -1;
            }
            validation_generation = error_report_generation();
            if (ssh_key_admission_begin(
                    expanded_key, &ssh_admission) != 0) {
                /* Preserve OpenSSH parse/launch/staging diagnostics. A
                 * validation API that ever fails silently still receives a
                 * bounded fallback rather than leaking stale error state. */
                if (error_report_generation() == validation_generation) {
                    set_error(ERR_SSH_KEY_LOAD_FAILED,
                              "SSH key not usable: %s",
                              account->ssh_key_path);
                }
                runtime_state_lock_release(runtime_lock_fd);
                return -1;
            }
            safe_strncpy(switch_target.ssh_key_path, expanded_key,
                         sizeof(switch_target.ssh_key_path));
        }
        /* Skipped on resume: gpg_switch_account revalidates the key inside the
         * isolated home (re-importing from the system keyring if the home was
         * wiped by the reboot), so this probe adds only login latency there —
         * and a login shell may still carry GNUPGHOME pointing at the not-yet-
         * recreated isolated home, which would make this "system keyring"
         * check look inside the missing home and wrongly hard-fail the resume. */
        if (write_git && account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            /* AR-06 F17: the system keyring is a key SOURCE, not the sole gate.
             * When an isolated home already exists for this account the key may
             * live only there (e.g. removed from the system keyring after an
             * earlier switch), and gpg_switch_account probes that home
             * authoritatively. Only require the system keyring when no isolated
             * home is present — preserving the pre-mutation fast-fail for a
             * genuine first-time switch to a key that exists nowhere. */
            if (validate_gpg_key_availability(account->gpg_key_id) != 0) {
                error_context_t source_error = *get_last_error();
                int source_errno = errno;
                bool isolated_present = false;

                if (gpg_manager_isolated_home_present(account->name,
                                                      &isolated_present) != 0) {
                    ssh_key_admission_end(&ssh_admission);
                    runtime_state_lock_release(runtime_lock_fd);
                    return -1;
                }
                if (!isolated_present) {
                    g_last_error = source_error;
                    errno = source_errno;
                    ssh_key_admission_end(&ssh_admission);
                    runtime_state_lock_release(runtime_lock_fd);
                    return -1;
                }
            }
        }

        /* AR-07 M24: snapshot capture is part of read-only preflight, not the
         * later Git-write step. A failed/truncated/oversized config read must
         * stop before an SSH agent is spawned or GNUPGHOME is repointed;
         * runtime rollback after such a rejection is avoidable mutation, not
         * an acceptable substitute for fail-before-mutation. */
        if (write_git && git_config_snapshot(scope) != 0) {
            char detail[sizeof(g_last_error.message)];

            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            ssh_key_admission_end(&ssh_admission);
            runtime_state_lock_release(runtime_lock_fd);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot snapshot Git configuration before switching: %s",
                      detail[0] ? detail : "unknown snapshot error");
            return -1;
        }

        /* The CLI must know that the durable publication bundle can accept a
         * new worst-case record before runtime or Git state starts changing.
         * Direct prepared-library callers retain their explicit two-phase
         * contract and can invoke config_publication_preflight() themselves
         * for the persistence destination they own. */
        if (write_git && defer_commit &&
            ctx->config.defer_signal_cleanup) {
            /* AR-12 H2 / AR-14 H1: the snapshot above pinned the exact
             * destination this switch will publish to. A destination that
             * already has a ledger record is an in-place replacement, which
             * an at-capacity ledger must still admit. The same exact
             * destination generation is now part of the durable incomplete-
             * switch fence, so a CLI transaction may no longer fall back to
             * a destination-less conservative capacity probe. */
            publication_record_t *destination_probes = calloc(
                CONFIG_SWITCH_DESTINATION_MAX,
                sizeof(*destination_probes));
            size_t destination_count = 0U;
            int preflight_result = -1;

            if (!destination_probes) {
                errno = ENOMEM;
                set_error(
                    ERR_MEMORY_ALLOCATION,
                    "Cannot allocate the exact Git destinations for switch recovery");
            } else if (git_config_snapshot_export_destinations(
                           destination_probes,
                           CONFIG_SWITCH_DESTINATION_MAX,
                           &destination_count) != 0) {
                /* Keep the exact export diagnostic: without every generation
                 * neither publication capacity nor recovery ownership can be
                 * bound safely. */
            } else if (config_publication_preflight_destination(
                           ctx->config.config_path,
                           &destination_probes[0]) != 0) {
                /* The preflight owns the useful capacity/model diagnostic. */
            } else if (config_switch_guard_install_or_adopt(
                           ctx, &prepared_owner.frozen_target, scope,
                           destination_probes, destination_count,
                           &prepared_owner.guard) != 0) {
                /* A malformed/mismatched existing fence remains blocking and
                 * no live state has been touched. */
            } else {
                prepared_owner.guard_created =
                    config_switch_guard_was_created(
                        prepared_owner.guard);
                preflight_result = 0;
            }
            if (destination_probes) {
                secure_zero_memory(
                    destination_probes,
                    CONFIG_SWITCH_DESTINATION_MAX *
                        sizeof(*destination_probes));
                free(destination_probes);
            }
            if (preflight_result != 0) {
                error_context_t preflight_error = *get_last_error();
                int preflight_errno = errno;

                git_config_commit();
                ssh_key_admission_end(&ssh_admission);
                runtime_state_lock_release(runtime_lock_fd);
                g_last_error = preflight_error;
                errno = preflight_errno;
                return -1;
            }
        }

        /* Final read-only generation checkpoint. The OpenSSH-parsed bytes
         * remain retained after this proof, so a later pathname rename cannot
         * substitute a key during activation. Rejecting a mismatch here keeps
         * the previous SSH/GPG session untouched. */
        if (ssh_admission &&
            ssh_key_admission_verify_named(ssh_admission) != 0) {
            ssh_key_admission_end(&ssh_admission);
            if (write_git) {
                (void)error_run_observational(
                    observe_git_config_commit, NULL);
            }
            if (defer_commit) {
                if (abort_switch_failure_preserving_cause(
                        &prepared_owner, prev_account, prev_gpg_home,
                        prev_gpg_present, false, false, false,
                        runtime_lock_fd, defer_signal_dispatch)) {
                    return -1;
                }
            } else {
                runtime_state_lock_release(runtime_lock_fd);
            }
            return -1;
        }

        /* The recovery marker installed immediately above is intentionally
         * the only durable change so far: a signal could kill us and leave a
         * fail-closed witness without changing any live identity. From this
         * point on, live Git/SSH/GPG mutations begin under the signal guard.
         * The recovery fence stays owned all the way through main()'s
         * config_save (M3); checked abort/commit settlement either removes
         * the exact marker or deliberately abandons it as a durable blocker.
         *
         * The config-save temp file is NOT registered here: this function's
         * success path still clears the scratch registry, so a registration
         * here would never cover the save (AR-02 #27). config_save registers
         * its own temp path under the guard this function leaves armed. */
        if (signals_guard_begin() != 0) {
            error_context_t guard_error = *get_last_error();
            int guard_errno = errno;

            ssh_key_admission_end(&ssh_admission);
            if (write_git) {
                git_config_commit();
            }
            g_last_error = guard_error;
            errno = guard_errno;
            if (defer_commit) {
                if (abort_switch_failure(
                        &prepared_owner, prev_account, prev_gpg_home,
                        prev_gpg_present, false, false, false,
                        runtime_lock_fd, defer_signal_dispatch)) {
                    return -1;
                }
            } else {
                runtime_state_lock_release(runtime_lock_fd);
            }
            g_last_error = guard_error;
            errno = guard_errno;
            return -1;
        }

        /* AR-08 M4: repeat-signal deferral begins with the first possible
         * mutation, not merely with activation of the new account. A prior
         * successful switch can leave an owned agent in g_session, and the
         * cleanup immediately below reaps that agent before the new runtime
         * is started. A second signal in that cleanup window must remain
         * pending until the old runtime has either been restored or the
         * switch has reached a completed commit/abort. */
        if (accounts_transaction_rollback_begin(
                ctx, ACCOUNTS_TRANSACTION_SWITCH, token) != 0) {
            error_context_t rollback_error = *get_last_error();
            int rollback_errno = errno;

            ssh_key_admission_end(&ssh_admission);
            if (write_git) git_config_commit();
            if (defer_commit) {
                if (abort_switch_failure(
                        &prepared_owner, prev_account, prev_gpg_home,
                        prev_gpg_present, false, false, false,
                        runtime_lock_fd, defer_signal_dispatch)) {
                    return -1;
                }
            } else {
                runtime_state_lock_release(runtime_lock_fd);
                (void)finish_signal_guard_checked(
                    "Switch rollback ownership setup failed");
            }
            g_last_error = rollback_error;
            errno = rollback_errno;
            return -1;
        }

        /* A prior successful accounts_switch() can leave an owned agent in
         * this process's session state. Stopping it is a real mutation: do it
         * only after every read-only validation has passed and the signal
         * guard is armed. If any later step fails, `ssh_dirty` makes rollback
         * restart the previous account's agent. This ordering also means an
         * early failure on a repeated switch leaves the live session entirely
         * untouched. */
        ssh_dirty = g_session.ssh_active;
        if (accounts_session_cleanup_internal() != 0) {
            char detail[sizeof(g_last_error.message)];
            bool rollback_complete = true;

            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            ssh_key_admission_end(&ssh_admission);
            /* Cleanup is ordered SSH then GPG. A GPG restoration failure can
             * therefore arrive after the previous agent was already reaped.
             * Route through the central checked abort path so that exact SSH
             * mutation is reactivated, while the untouched manager-owned GPG
             * retry record remains in g_session for accounts_session_cleanup(). */
            if (defer_commit) {
                if (abort_switch_failure(
                        &prepared_owner, prev_account, prev_gpg_home,
                        prev_gpg_present, false, ssh_dirty, false,
                        runtime_lock_fd, defer_signal_dispatch)) {
                    return -1;
                }
            } else {
                abort_failed_switch_checked(
                    prev_account, prev_gpg_home, prev_gpg_present, false,
                    ssh_dirty, false, runtime_lock_fd,
                    !defer_signal_dispatch, defer_signal_dispatch,
                    NULL, NULL, NULL, &rollback_complete, NULL, 0, NULL);
            }
            set_error(ERR_SYSTEM_CALL,
                      "Cannot switch away from the active runtime session: %s%s",
                      detail[0] ? detail : "cleanup retained for retry",
                      rollback_complete ? "" :
                          "; previous runtime reactivation is incomplete");
            return -1;
        }

        /* A signal may have arrived while the previous owned agent was being
         * stopped. Roll it back before attempting any new activation. */
        if (signals_pending()) {
            ssh_key_admission_end(&ssh_admission);
            (void)abort_switch_failure(
                defer_commit ? &prepared_owner : NULL,
                prev_account, prev_gpg_home, prev_gpg_present, false,
                ssh_dirty, false, runtime_lock_fd, defer_signal_dispatch);
            return -1;
        }

        /* Repeat-signal deferral armed above remains continuous through
         * forward activation, Git publication, deferred teardown, prepared
         * persistence, and the eventual commit or completed abort.
         * Interactive children still receive the repeated signal through the
         * published-child forwarding path, so prompts remain interruptible. */

        /* --- 2. SSH agent isolation (mutation; fatal on failure) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            account_t runtime_target = switch_target;

            /* Agent/key activation must not touch ~/.ssh/config yet. The
             * atomic host-alias write is the transaction's final fallible
             * commit, after Git and deferred teardown are known-good. */
            runtime_target.ssh_host_alias[0] = '\0';
            log_info("Setting up SSH isolation for account: %s", account->name);
            memset(&g_session.ssh_config, 0, sizeof(g_session.ssh_config));
            /* ssh_manager_init only probes PATH for ssh-agent/ssh-add. The
             * dirty bit is still false on a first switch, but can already be
             * true on a repeated switch because guarded session cleanup just
             * stopped the prior owned agent. */
            if (ssh_manager_init(&g_session.ssh_config, SSH_AGENT_ISOLATED) != 0) {
                printf("  [!!] SSH key failed to load\n");
                ssh_key_admission_end(&ssh_admission);
                if (abort_switch_failure_preserving_cause(
                        defer_commit ? &prepared_owner : NULL,
                        prev_account, prev_gpg_home, prev_gpg_present, false,
                        ssh_dirty, false, runtime_lock_fd,
                        defer_signal_dispatch)) {
                    return -1;
                }
                return -1;
            }
            ssh_dirty = true;
            if (ssh_switch_account_admitted(
                    &g_session.ssh_config, &runtime_target,
                    ssh_admission) != 0) {
                printf("  [!!] SSH key failed to load\n");
                ssh_key_admission_end(&ssh_admission);
                (void)error_run_observational(
                    observe_ssh_manager_cleanup,
                    &g_session.ssh_config);
                if (abort_switch_failure_preserving_cause(
                        defer_commit ? &prepared_owner : NULL,
                        prev_account, prev_gpg_home, prev_gpg_present, false,
                        ssh_dirty, false, runtime_lock_fd,
                        defer_signal_dispatch)) {
                    return -1;
                }
                return -1;
            }
            ssh_key_admission_end(&ssh_admission);
            ssh_ok = true;
            g_session.ssh_active = true;
            printf("  [OK] SSH key loaded\n");
        } else {
            /* Target has no SSH: the live gitswitch agent + current.sock must
             * be torn down so shells stop authenticating as the previously-
             * active account — but NOT yet. Defer it past the git-config
             * write (the point of no return) so a switch that fails there
             * leaves the previous account's agent working (F4). */
            ssh_teardown_deferred = true;
        }

        /* A signal during SSH activation: the previous agent may already be
         * gone and current.sock repointed — roll back and restore it. */
        if (signals_pending()) {
            (void)abort_switch_failure(
                defer_commit ? &prepared_owner : NULL,
                prev_account, prev_gpg_home, prev_gpg_present, false,
                ssh_dirty, false, runtime_lock_fd, defer_signal_dispatch);
            return -1;
        }

        /* --- 3. GPG isolated home (mutation; fatal on failure) --- */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            char activation_error[sizeof(g_last_error.message)] = "";
            char cleanup_error[sizeof(g_last_error.message)] = "";
            int activation_rc;
            int cleanup_rc = 0;

            log_info("Setting up GPG isolation for account: %s", account->name);
            memset(&g_session.gpg_config, 0, sizeof(g_session.gpg_config));
            activation_rc = gpg_manager_init(&g_session.gpg_config,
                                             GPG_MODE_ISOLATED);
            if (activation_rc == 0) {
                activation_rc = gpg_switch_account(&g_session.gpg_config,
                                                   account);
            }
            if (activation_rc != 0) {
                safe_strncpy(activation_error, get_last_error()->message,
                             sizeof(activation_error));
                printf("  [!!] GPG key failed to activate\n");
                cleanup_rc = gpg_manager_cleanup(&g_session.gpg_config);
                if (cleanup_rc != 0) {
                    safe_strncpy(cleanup_error, get_last_error()->message,
                                 sizeof(cleanup_error));
                }
                g_session.gpg_active = gpg_session_cleanup_needed();
                gpg_dirty =
                    gpg_manager_runtime_restore_pending(&g_session.gpg_config);
                /* Roll back the SSH activation from step 2 so we don't leave
                 * current.sock pointing at this account with no matching GPG.
                 * A failed retarget may already have published current; its
                 * retained manager record makes that fact explicit here. */
                if (abort_switch_failure(
                        defer_commit ? &prepared_owner : NULL,
                        prev_account, prev_gpg_home, prev_gpg_present, false,
                        ssh_dirty, gpg_dirty, runtime_lock_fd,
                        defer_signal_dispatch)) {
                    return -1;
                }
                if (cleanup_rc != 0 && gpg_session_cleanup_needed()) {
                    set_error(ERR_GPG_KEY_FAILED,
                              "Failed to set up GPG for account %s: %s; "
                              "cleanup remains pending: %s",
                              account->name,
                              activation_error[0] ? activation_error
                                                  : "unknown activation error",
                              cleanup_error[0] ? cleanup_error
                                               : "unknown cleanup error");
                } else {
                    set_error(ERR_GPG_KEY_FAILED,
                              "Failed to set up GPG for account %s: %s",
                              account->name,
                              activation_error[0] ? activation_error
                                                  : "unknown activation error");
                }
                return -1;
            }
            /* gpg_switch_account retargeted the stable GNUPGHOME symlink. */
            gpg_dirty = true;
            g_session.gpg_active = true;
            /* From this point onward Git receives only the canonical primary
             * fingerprint proven by the isolated-home activation. The saved
             * account keeps the user's selector, but effective Git readback and
             * later health checks must validate the resolved identity. */
            if (safe_strncpy(switch_target.gpg_key_id,
                             g_session.gpg_config.current_key_id,
                             sizeof(switch_target.gpg_key_id)) != 0) {
                if (abort_switch_failure(
                        defer_commit ? &prepared_owner : NULL,
                        prev_account, prev_gpg_home, prev_gpg_present, false,
                        ssh_dirty, gpg_dirty, runtime_lock_fd,
                        defer_signal_dispatch)) {
                    return -1;
                }
                set_error(ERR_GPG_KEY_FAILED,
                          "Canonical GPG fingerprint exceeds account runtime storage");
                return -1;
            }
        } else {
            /* Target has no GPG: the stable GNUPGHOME symlink must be dropped
             * so shells stop signing/using the previous account's keyring —
             * deferred past the point of no return, like the SSH side (F4). */
            gpg_teardown_deferred = true;
        }

        /* A signal during GPG activation (Ctrl-C at the pinentry prompt is
         * the classic case): SSH/GPG may already point at the new account
         * while git still names the old one — roll back before that mismatch
         * can outlive the process. */
        if (signals_pending()) {
            (void)abort_switch_failure(
                defer_commit ? &prepared_owner : NULL,
                prev_account, prev_gpg_home, prev_gpg_present, false,
                ssh_dirty, gpg_dirty, runtime_lock_fd,
                defer_signal_dispatch);
            return -1;
        }

        /* --- 4. Git identity (preflight-snapshotted and reversible) --- */
        if (write_git) {
            if (git_set_config(&switch_target, scope) != 0) {
                if (abort_switch_failure(
                        defer_commit ? &prepared_owner : NULL,
                        prev_account, prev_gpg_home, prev_gpg_present, true,
                        ssh_dirty, gpg_dirty, runtime_lock_fd,
                        defer_signal_dispatch)) {
                    return -1;
                }
                set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git configuration");
                return -1;
            }
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                if (gpg_configure_git_signing(&g_session.gpg_config,
                                              &switch_target, scope) != 0) {
                    if (abort_switch_failure(
                            defer_commit ? &prepared_owner : NULL,
                            prev_account, prev_gpg_home, prev_gpg_present,
                            true, ssh_dirty, gpg_dirty, runtime_lock_fd,
                            defer_signal_dispatch)) {
                        return -1;
                    }
                    set_error(ERR_GIT_CONFIG_FAILED, "Failed to configure git GPG signing");
                    return -1;
                }
                gpg_ok = true;
                /* gpg_configure_git_signing sets commit.gpgsign to the account's
                 * preference, which may be OFF. Don't claim signing is enabled
                 * when we just disabled it — report the actual state. */
                if (account->gpg_signing_enabled) {
                    printf("  [OK] GPG signing enabled (key: %s)\n",
                           switch_target.gpg_key_id);
                } else {
                    printf("  [OK] GPG key configured, signing disabled (key: %s)\n",
                           switch_target.gpg_key_id);
                }
            }
            printf("  [OK] Git config set (%s scope)\n", scope_str);
        } else {
            /* Resume: git config was never touched, so the runtime activation
             * above completed the restore. */
            gpg_ok = g_session.gpg_active;
        }

        /* AR-08 M7: close the ownership gap between the last managed Git
         * write and every later fallible transaction step. The Git layer's
         * intended image contains only writes this process completed; a
         * fresh mismatch here is a concurrent writer, never a post-image we
         * may adopt and overwrite during rollback. */
        if (write_git && git_config_seal() != 0) {
            char seal_detail[sizeof(g_last_error.message)];

            safe_strncpy(seal_detail, get_last_error()->message,
                         sizeof(seal_detail));
            if (abort_switch_failure(
                    defer_commit ? &prepared_owner : NULL,
                    prev_account, prev_gpg_home, prev_gpg_present, true,
                    ssh_dirty, gpg_dirty, runtime_lock_fd,
                    defer_signal_dispatch)) {
                return -1;
            }
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Git post-image verification failed; switch was "
                      "rolled back: %s",
                      seal_detail[0] ? seal_detail
                                     : "unknown verification error");
            return -1;
        }

        /* The sealed Git transaction is the only authority for what was
         * actually published. Capture its canonical destination and vectors
         * before any later commit can discard that evidence. Prepared CLI
         * switches carry the record into the atomic active-state bundle; no
         * selector, PATH lookup, or current-directory reconstruction is
         * allowed to substitute for it. Only the CLI-owned prepared cycle
         * persists the active-state bundle; direct prepared API cycles remain
         * commit/abort capable without inventing a publication generation. */
        if (write_git && defer_commit &&
            ctx->config.defer_signal_cleanup) {
            if (git_config_export_sealed_publication(
                    &prepared_owner.publication,
                    prepared_owner.frozen_target.gpg_enabled
                        ? prepared_owner.frozen_target.gpg_key_id
                        : NULL) != 0) {
                char publication_detail[sizeof(g_last_error.message)];

                safe_strncpy(publication_detail,
                             get_last_error()->message,
                             sizeof(publication_detail));
                if (abort_switch_failure(
                        &prepared_owner, prev_account, prev_gpg_home,
                        prev_gpg_present, true, ssh_dirty, gpg_dirty,
                        runtime_lock_fd, defer_signal_dispatch)) {
                    return -1;
                }
                set_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Cannot retain sealed Git publication provenance; switch was rolled back: %s",
                    publication_detail[0]
                        ? publication_detail
                        : "unknown publication export error");
                return -1;
            }
            prepared_owner.publication_valid = true;
        }

        /* Last all-or-nothing checkpoint: a signal up to here rolls the whole
         * switch back (git config, when written, was just written — restore it
         * too; on resume nothing was written, so nothing to restore). */
        if (signals_pending()) {
            (void)abort_switch_failure(
                defer_commit ? &prepared_owner : NULL,
                prev_account, prev_gpg_home, prev_gpg_present, write_git,
                ssh_dirty, gpg_dirty, runtime_lock_fd,
                defer_signal_dispatch);
            return -1;
        }

        /* NOW run the teardown deferred from steps 2-3 — only once the switch
         * is known-good may the previous account's agent / keyring entry
         * point be dropped (F4). The transaction-wide repeat-signal deferral
         * stays armed across this multi-step reap and the prepared handoff. */
        int deactivation_rc = deactivate_runtime_isolation(
            ssh_teardown_deferred, gpg_teardown_deferred);
        if (deactivation_rc != 0) {
            char detail[sizeof(g_last_error.message)];
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            ssh_dirty = ssh_dirty || ssh_teardown_deferred;
            gpg_dirty = gpg_dirty || gpg_teardown_deferred;
            if (abort_switch_failure(
                    defer_commit ? &prepared_owner : NULL,
                    prev_account, prev_gpg_home, prev_gpg_present, write_git,
                    ssh_dirty, gpg_dirty, runtime_lock_fd,
                    defer_signal_dispatch)) {
                return -1;
            }
            set_error(ERR_SYSTEM_CALL,
                      "Failed to deactivate previous runtime state while switching to '%s': %s",
                      account->name, detail[0] ? detail : "unknown teardown error");
            return -1;
        }

        /* Successful deferred teardown is also a mutation rollback must
         * restore if the final host-alias commit now fails. */
        ssh_dirty = ssh_dirty || ssh_teardown_deferred;
        gpg_dirty = gpg_dirty || gpg_teardown_deferred;

        /* Direct callers install the managed host-alias block here as their
         * final fallible commit. A transactional CLI switch defers it to
         * accounts_switch_commit_result(): otherwise a later active/hint save
         * failure could roll Git/runtime back while leaving the new user-file
         * mapping. The writer uses a no-follow read plus atomic rename and
         * makes no durable change when it refuses. Resume skips the persistent
         * file. */
        if (!defer_commit && !ctx->config.resuming &&
            account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
            strlen(account->ssh_host_alias) > 0) {
            if (ssh_configure_host_alias_result(&switch_target,
                                                &alias_publication) != 0) {
                alias_publication_system_errno =
                    get_last_error()->system_errno;
                safe_strncpy(alias_publication_detail,
                             get_last_error()->message,
                             sizeof(alias_publication_detail));
                if (!ssh_alias_publication_is_installed(alias_publication)) {
                    bool rollback_complete = true;
                    bool git_remaining = write_git;
                    bool ssh_remaining = ssh_dirty;
                    bool gpg_remaining = gpg_dirty;
                    char rollback_detail[sizeof(g_last_error.message)] = "";

                    /* Learn completeness before releasing signal ownership.
                     * M7 conflicts deliberately retain their exact Git retry
                     * image; ending the guard here would strand that handle
                     * with no safe way to finish a direct-library abort. */
                    abort_failed_switch_checked(
                        prev_account, prev_gpg_home, prev_gpg_present,
                        write_git, ssh_dirty, gpg_dirty, runtime_lock_fd,
                        false, true, &git_remaining, &ssh_remaining,
                        &gpg_remaining, &rollback_complete, rollback_detail,
                        sizeof(rollback_detail), NULL);
                    if (!rollback_complete) {
                        memset(&g_pending_switch, 0, sizeof(g_pending_switch));
                        g_pending_switch.active = true;
                        g_pending_switch.abort_only = true;
                        g_pending_switch.token = token;
                        g_pending_switch.ctx = ctx;
                        if (prev_account) {
                            g_pending_switch.previous_account = *prev_account;
                            g_pending_switch.had_previous_account = true;
                        }
                        safe_strncpy(g_pending_switch.previous_active,
                                     prev_active,
                                     sizeof(g_pending_switch.previous_active));
                        safe_strncpy(g_pending_switch.previous_gpg_home,
                                     prev_gpg_home,
                                     sizeof(g_pending_switch.previous_gpg_home));
                        g_pending_switch.previous_gpg_present = prev_gpg_present;
                        g_pending_switch.git_written = git_remaining;
                        g_pending_switch.ssh_dirty = ssh_remaining;
                        g_pending_switch.gpg_dirty = gpg_remaining;
                        g_pending_switch.runtime_lock_fd = -1;
                        g_pending_switch.target_id = account->id;
                        g_pending_switch.frozen_target = *account;
                        g_pending_switch.switch_target = switch_target;
                        g_pending_switch.scope = scope;
                        g_pending_switch.ssh_ok = ssh_ok;
                        g_pending_switch.gpg_ok = gpg_ok;
                        (void)transaction_mark_phase(
                            ctx, ACCOUNTS_TRANSACTION_SWITCH, token,
                            ACCOUNTS_TRANSACTION_ABORT_ONLY);
                        set_error(
                            ERR_FILE_IO,
                            "Failed to commit SSH host alias for account '%s' "
                            "(%s), and rollback remains incomplete with retry "
                            "ownership retained; call accounts_switch_abort() "
                            "after resolving the conflict: %s",
                            account->name,
                            alias_publication_detail[0]
                                ? alias_publication_detail
                                : "unknown SSH config error",
                            rollback_detail[0]
                                ? rollback_detail
                                : "unknown rollback error");
                        return -1;
                    }
                    if (!defer_signal_dispatch) {
                        (void)accounts_transaction_rollback_end(
                            ctx, ACCOUNTS_TRANSACTION_SWITCH, token);
                        if (finish_signal_guard_checked(
                                "SSH alias publication failed after the "
                                "switch rollback completed") != 0) {
                            return -1;
                        }
                    }
                    set_error(ERR_FILE_IO,
                              "Failed to commit SSH host alias for account '%s': %s",
                              account->name,
                              alias_publication_detail[0]
                                  ? alias_publication_detail
                                  : "unknown SSH config error");
                    return -1;
                }
                /* renameat() has already made the target alias public. Rolling
                 * Git/runtime back would manufacture the mixed state M5
                 * forbids. Finish the new transaction, then report the exact
                 * verification/durability uncertainty as a committed error. */
                alias_publication_retained = true;
            }
        }

        /* No fallible external commit remains for a direct switch. Once the
         * optional alias writer has succeeded, rollback ownership must be
         * discarded before releasing the cross-manager lock. */
        if (!defer_commit && write_git) {
            git_config_commit();
        }

        signals_scratch_cleanup();
        if (defer_commit) {
            prepared_owner.git_written = write_git;
            prepared_owner.ssh_dirty = ssh_dirty;
            prepared_owner.gpg_dirty = gpg_dirty;
            prepared_owner.runtime_lock_fd = runtime_lock_fd;
            prepared_owner.switch_target = switch_target;
            prepared_owner.ssh_ok = ssh_ok;
            prepared_owner.gpg_ok = gpg_ok;
            g_pending_switch = prepared_owner;
            (void)transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                         token,
                                         ACCOUNTS_TRANSACTION_PREPARED);
        } else {
            /* Direct callers retain the historical one-call commit. Release
             * the cross-manager lock before best-effort probes. */
            runtime_state_lock_release(runtime_lock_fd);
            runtime_lock_fd = -1;
        }

        /* Prepared and CLI-owned flows deliberately retain both the guard and
         * repeat-signal deferral through active-account persistence. A direct
         * library call closes both below after its in-memory commit and
         * best-effort probes are complete. */
        if (signals_pending()) {
            log_warning("Signal received after the switch completed; "
                        "deferring until the new state is persisted");
        }
    } else {
        printf("  [--] DRY RUN: Would set git config (%s scope)\n", scope_str);
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            printf("  [--] DRY RUN: Would load SSH key\n");
        }
        /* AR-06 F44: report the signing state accurately. A GPG account
         * enables commit signing; a non-GPG account DISABLES it (git_set_config
         * writes commit.gpgsign=false), which the old preview never mentioned. */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("  [--] DRY RUN: Would enable GPG commit signing\n");
        } else {
            printf("  [--] DRY RUN: Would disable GPG commit signing\n");
        }
    }

    /* Set as current account, and record it for boot resume. The config is
     * persisted by the save-after-switch path in main(). Skipped under dry-run
     * so a preview mutates no state, in memory or on disk. */
    if (!ctx->config.dry_run) {
        ctx->current_account = account;
        safe_strncpy(ctx->config.active_account, account->name, sizeof(ctx->config.active_account));
    }

    if (defer_commit && !ctx->config.dry_run) {
        log_info("Prepared switch to account '%s'; awaiting active-state commit",
                 account->name);
        return 0;
    }

    finish_switch_success(ctx, account, &switch_target, scope, write_git,
                          ssh_ok, gpg_ok, true);

    /* AR-08 M6: accounts_switch() is a complete one-call API. A successful
     * direct call must not leave this process running gitswitch's handlers or
     * transaction deferral. CLI-owned/resume and prepared flows explicitly
     * retain that ownership for main()'s persistence and common cleanup.
     * Restore failures are reported truthfully after the already-committed
     * switch; the signal layer retains failed entries for a later retry. */
    if (!ctx->config.dry_run && !defer_signal_dispatch) {
        if (accounts_transaction_rollback_end(
                ctx, ACCOUNTS_TRANSACTION_SWITCH, token) != 0) {
            return -1;
        }
        if (finish_signal_guard_checked(
                "Account switch committed, but restoring the caller's "
                "signal dispositions failed") != 0) {
            return -1;
        }
    }
    if (alias_publication_retained) {
        set_retained_alias_publication_error(account->name,
                                             alias_publication,
                                             alias_publication_detail,
                                             alias_publication_system_errno);
        return -1;
    }
    return 0;
}

int accounts_switch(gitswitch_ctx_t *ctx, const char *identifier) {
    accounts_transaction_token_t token;
    int rc;

    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                   &token) != 0) {
        return -1;
    }
    rc = accounts_switch_impl(ctx, identifier, false, token);
    if (g_pending_switch.active && g_pending_switch.token == token) return rc;
    if (transaction_finish_after_call(
            ctx, ACCOUNTS_TRANSACTION_SWITCH, token,
            ctx && ctx->config.defer_signal_cleanup) != 0) {
        return -1;
    }
    return rc;
}

int accounts_switch_prepare_result(gitswitch_ctx_t *ctx,
                                   const char *identifier,
                                   accounts_switch_prepare_state_t *state) {
    accounts_transaction_token_t token;
    int rc;

    if (!state) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "A transactional switch prepare result is required");
        return -1;
    }
    *state = ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE;
    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                   &token) != 0) {
        return -1;
    }
    if (!ctx || ctx->config.dry_run || ctx->config.resuming) {
        set_error(ERR_INVALID_ARGS,
                  "A transactional switch requires a non-preview CLI switch");
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                          token);
        return -1;
    }
    rc = accounts_switch_impl(ctx, identifier, true, token);
    if (g_pending_switch.active && g_pending_switch.token == token &&
        g_pending_switch.ctx == ctx) {
        bool exact_owner =
            g_transaction_owner.kind == ACCOUNTS_TRANSACTION_SWITCH &&
            g_transaction_owner.token == token &&
            g_transaction_owner.ctx == ctx;

        if (exact_owner && !g_pending_switch.abort_only && rc == 0 &&
            g_transaction_owner.phase == ACCOUNTS_TRANSACTION_PREPARED) {
            *state = ACCOUNTS_SWITCH_PREPARE_PREPARED;
        } else if (exact_owner && g_pending_switch.abort_only &&
                   g_transaction_owner.phase ==
                       ACCOUNTS_TRANSACTION_ABORT_ONLY) {
            *state = ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
        } else {
            /* An exact newly-created pending record can never be reported as
             * clean: it still retains ctx. Convert any impossible rc/phase
             * combination to the one fail-closed public settlement state.
             * The matching abort may itself reject a corrupted owner, but the
             * caller will then retain the context instead of freeing it. */
            if (rc == 0) {
                errno = EBUSY;
                set_error(ERR_SYSTEM_CALL,
                          "Account switch preparation retained an inconsistent transaction owner");
                rc = -1;
            }
            g_pending_switch.abort_only = true;
            if (exact_owner) {
                g_transaction_owner.phase =
                    ACCOUNTS_TRANSACTION_ABORT_ONLY;
            }
            *state = ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
        }
        return rc;
    }
    if (transaction_finish_after_call(
            ctx, ACCOUNTS_TRANSACTION_SWITCH, token,
            ctx && ctx->config.defer_signal_cleanup) != 0) {
        return -1;
    }
    return rc;
}

/* Compare semantic account fields one by one. Avoiding a struct memcmp keeps
 * padding out of the generation contract while still binding every persisted
 * field, including metadata and currently-disabled routing selectors. AR-13
 * L22: ssh_key_spelling is persisted too (it is the exact ssh_key text written
 * back), so a spelling-only change is a real on-disk change and must be bound
 * here; the disable paths clear it alongside ssh_key_path so a disabled account
 * never carries stale spelling residue. */
static bool account_fields_equal_exact(const account_t *left,
                                       const account_t *right) {
    return left && right && left->id == right->id &&
           strcmp(left->incarnation, right->incarnation) == 0 &&
           left->incarnation_persisted == right->incarnation_persisted &&
           strcmp(left->name, right->name) == 0 &&
           strcmp(left->email, right->email) == 0 &&
           strcmp(left->description, right->description) == 0 &&
           left->preferred_scope == right->preferred_scope &&
           left->ssh_enabled == right->ssh_enabled &&
           strcmp(left->ssh_key_path, right->ssh_key_path) == 0 &&
           strcmp(left->ssh_key_spelling, right->ssh_key_spelling) == 0 &&
           strcmp(left->ssh_host_alias, right->ssh_host_alias) == 0 &&
           strcmp(left->ssh_hostname, right->ssh_hostname) == 0 &&
           left->gpg_enabled == right->gpg_enabled &&
           left->gpg_signing_enabled == right->gpg_signing_enabled &&
           strcmp(left->gpg_key_id, right->gpg_key_id) == 0;
}

int accounts_switch_commit_result(gitswitch_ctx_t *ctx,
                                  accounts_switch_commit_state_t *state) {
    account_t *target = NULL;
    git_config_finalization_t *git_finalization = NULL;
    ssh_config_publication_state_t alias_publication =
        SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED;
    accounts_switch_commit_state_t final_state =
        ACCOUNTS_SWITCH_COMMIT_COMPLETE;
    error_context_t alias_error = {0};
    int alias_error_errno = 0;
    char alias_publication_detail[sizeof(g_last_error.message)] = "";
    int alias_publication_system_errno = 0;
    error_context_t settlement_error = {0};
    int settlement_error_errno = 0;
    bool settlement_error_captured = false;
    bool fence_retained = false;
    accounts_transaction_token_t token;

    if (state) {
        *state = ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
    }
    if (accounts_process_epoch_gate(true) != 0) return -1;

    if (!g_pending_switch.active || !ctx || g_pending_switch.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account switch to commit");
        return -1;
    }
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                            g_pending_switch.token, "commit") != 0) {
        return -1;
    }
    if (g_pending_switch.abort_only) {
        set_error(ERR_INVALID_ARGS,
                  "A failed switch preparation can only be retried through "
                  "accounts_switch_abort");
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_SWITCH, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_PREPARED, "commit") != 0) {
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == g_pending_switch.target_id) {
            target = &ctx->accounts[i];
            break;
        }
    }
    if (!target) {
        errno = ESTALE;
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Prepared switch target changed or disappeared before commit");
        return -1;
    }
    if (!account_fields_equal_exact(target,
                                    &g_pending_switch.frozen_target)) {
        errno = ESTALE;
        set_error(ERR_ACCOUNT_INVALID,
                  "Prepared switch target changed before commit; abort the retained transaction and retry");
        return -1;
    }
    if (transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                               g_pending_switch.token,
                               ACCOUNTS_TRANSACTION_FINALIZING) != 0) {
        return -1;
    }

    /* AR-14 H1: the seal used by active-state publication is only a snapshot
     * until final commit. Acquire every distinct canonical Git `<config>.lock`
     * and re-prove the exact sealed generations/vectors while those leases
     * exclude supported Git writers. The durable switch fence remains owned
     * until alias settlement and fence clearing both finish under this lease.
     *
     * Once active metadata is durable, a finalization mismatch cannot safely
     * authorize reverse abort: it may describe a concurrent Git writer.
     * Production CLI switches therefore transfer to exact forward recovery,
     * discard stale reverse images, and retain the durable marker. Direct
     * embedders without that marker retain the historic abortable boundary. */
    if (g_pending_switch.git_written &&
        git_config_finalization_begin(&git_finalization) != 0) {
        settlement_error = *get_last_error();
        settlement_error_errno = errno;
        settlement_error_captured = true;
        if (!g_pending_switch.guard) {
            g_transaction_owner.phase = ACCOUNTS_TRANSACTION_PREPARED;
            return -1;
        }
        config_switch_guard_abandon(&g_pending_switch.guard);
        fence_retained = true;
        git_config_commit();
        final_state =
            ACCOUNTS_SWITCH_COMMIT_FORWARD_RECOVERY_REQUIRED;
        goto switch_commit_irreversible;
    }

    /* This is the prepared switch's final required user-file commit. It runs
     * only after active_account and the resume hint are durable, but before
     * pending rollback ownership or the runtime lock is released. Failure
     * therefore lets main reverse every earlier commit as one transaction. */
    if (target->ssh_enabled && target->ssh_key_path[0] != '\0' &&
        target->ssh_host_alias[0] != '\0' &&
        ssh_configure_host_alias_result(&g_pending_switch.switch_target,
                                        &alias_publication) != 0) {
        alias_error = *get_last_error();
        alias_error_errno = errno;
        alias_publication_system_errno = get_last_error()->system_errno;
        safe_strncpy(alias_publication_detail, get_last_error()->message,
                     sizeof(alias_publication_detail));
        if (!ssh_alias_publication_is_installed(alias_publication)) {
            if (git_config_finalization_end(
                    &git_finalization) != 0) {
                settlement_error = *get_last_error();
                settlement_error_errno = errno;
                settlement_error_captured = true;
                if (g_pending_switch.guard) {
                    config_switch_guard_abandon(
                        &g_pending_switch.guard);
                    fence_retained = true;
                    if (g_pending_switch.git_written) {
                        git_config_commit();
                    }
                    final_state =
                        ACCOUNTS_SWITCH_COMMIT_FORWARD_RECOVERY_REQUIRED;
                    goto switch_commit_irreversible;
                }
            } else {
                g_last_error = alias_error;
                errno = alias_error_errno;
            }
            g_transaction_owner.phase = ACCOUNTS_TRANSACTION_PREPARED;
            return -1;
        }
        final_state = accounts_commit_state_for_alias(alias_publication);
    }

    /* AR-14 H1: the durable recovery fence outlives every forward mutation.
     * Remove it only after the caller's active-state save, the alias
     * publication, Git, and runtime all describe the same target while the
     * Git finalization lease is still held. An alias generation that is
     * public but unverified/durability-uncertain is intentionally retained,
     * but not a proven coherent endpoint: release the process-local handles
     * while retaining the durable fence for exact forward recovery.
     */
    if (g_pending_switch.guard) {
        if (final_state == ACCOUNTS_SWITCH_COMMIT_ALIAS_UNVERIFIED ||
            final_state ==
                ACCOUNTS_SWITCH_COMMIT_ALIAS_DURABILITY_UNCERTAIN) {
            config_switch_guard_abandon(&g_pending_switch.guard);
            fence_retained = true;
        } else if (config_switch_guard_clear(
                       &g_pending_switch.guard) != 0) {
            error_context_t first_clear_error = *get_last_error();
            int first_clear_errno = errno ? errno : EIO;

            /* clear() deliberately retains a callable handle after unlink
             * when only the directory durability proof failed. Retry that
             * exact owner before classifying a retained fence; abandoning it
             * immediately would lose the only in-process proof while the
             * canonical name may already be absent. */
            if (config_switch_guard_clear(
                    &g_pending_switch.guard) != 0) {
                error_accumulator_t clear_errors;

                error_accumulator_init(&clear_errors);
                errno = first_clear_errno;
                (void)error_accumulator_add(
                    &clear_errors, "switch fence clear",
                    &first_clear_error);
                (void)error_accumulator_add_last(
                    &clear_errors, "switch fence clear retry");
                (void)error_accumulator_publish(&clear_errors);
                {
                    error_context_t clear_failure =
                        *get_last_error();
                    int clear_failure_errno = errno ? errno : EIO;

                    /* A second clear failure is not proof that the canonical
                     * marker remains: unlink may already have succeeded. Only
                     * release this owner as recoverable after republishing and
                     * durably re-proving the exact marker bytes. */
                    if (config_switch_guard_retain(
                            &g_pending_switch.guard) == 0) {
                        settlement_error = clear_failure;
                        settlement_error_errno =
                            clear_failure_errno;
                        settlement_error_captured = true;
                        fence_retained = true;
                        final_state =
                            ACCOUNTS_SWITCH_COMMIT_RECOVERY_FENCE_RETAINED;
                    } else {
                        error_accumulator_t retain_errors;

                        error_accumulator_init(&retain_errors);
                        errno = clear_failure_errno;
                        (void)error_accumulator_add(
                            &retain_errors,
                            "switch fence clear",
                            &clear_failure);
                        (void)error_accumulator_add_last(
                            &retain_errors,
                            "switch fence retention");
                        (void)error_accumulator_publish(
                            &retain_errors);
                        settlement_error = *get_last_error();
                        settlement_error_errno =
                            errno ? errno : EIO;
                        settlement_error_captured = true;
                        config_switch_guard_abandon(
                            &g_pending_switch.guard);
                        final_state =
                            ACCOUNTS_SWITCH_COMMIT_RECOVERY_FENCE_CLEANUP_FAILED;
                    }
                }
            }
        }
    }
    if (g_pending_switch.git_written) {
        git_config_commit();
    }
    if (git_config_finalization_end(&git_finalization) != 0) {
        settlement_error = *get_last_error();
        settlement_error_errno = errno;
        settlement_error_captured = true;
        final_state = fence_retained
            ? ACCOUNTS_SWITCH_COMMIT_FORWARD_RECOVERY_REQUIRED
            : ACCOUNTS_SWITCH_COMMIT_FINALIZATION_CLEANUP_FAILED;
    }

switch_commit_irreversible:
    /* AR-12 M1/L3: the installed alias publication, Git commit, and checked
     * fence settlement above are past the transaction's point of no return.
     * Report the committed state NOW: a later ownership-release or
     * signal-guard failure returns -1, and NOT_COMMITTED at that point would
     * authorize the caller to restore persistence before-images around a
     * switch that has fully committed (main keys its rollback branch off
     * exactly this state). */
    if (state) {
        *state = final_state;
    }

    token = g_pending_switch.token;
    runtime_state_lock_release(g_pending_switch.runtime_lock_fd);
    g_pending_switch.runtime_lock_fd = -1;
    finish_switch_success(ctx, target, &g_pending_switch.switch_target,
                          g_pending_switch.scope,
                          g_pending_switch.git_written,
                          g_pending_switch.ssh_ok,
                          g_pending_switch.gpg_ok,
                          final_state == ACCOUNTS_SWITCH_COMMIT_COMPLETE);
    memset(&g_pending_switch, 0, sizeof(g_pending_switch));
    if (g_transaction_owner.rollback_depth > 0 &&
        accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_SWITCH, token) != 0) {
        return -1;
    }
    if (accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                    token) != 0) {
        return -1;
    }
    if (!ctx->config.defer_signal_cleanup &&
        finish_signal_guard_checked(
            "Prepared switch committed, but restoring the caller's signal dispositions failed") != 0) {
        return -1;
    }
    if (final_state ==
        ACCOUNTS_SWITCH_COMMIT_RECOVERY_FENCE_RETAINED) {
        const char *detail =
            settlement_error_captured && settlement_error.message[0]
                ? settlement_error.message
                : "unknown recovery-fence cleanup error";

        set_error(
            ERR_FILE_IO,
            "Account switch to '%s' committed, but its durable recovery "
            "fence remains: %s",
            target->name, detail);
        g_last_error.system_errno = settlement_error.system_errno;
        errno = settlement_error_errno;
        return -1;
    }
    if (final_state ==
        ACCOUNTS_SWITCH_COMMIT_FORWARD_RECOVERY_REQUIRED) {
        const char *detail =
            settlement_error_captured && settlement_error.message[0]
                ? settlement_error.message
                : "the final Git/alias image could not be proven";

        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Account switch to '%s' requires exact forward recovery: %s",
            target->name, detail);
        g_last_error.system_errno = settlement_error.system_errno;
        errno = settlement_error_errno;
        return -1;
    }
    if (final_state ==
        ACCOUNTS_SWITCH_COMMIT_RECOVERY_FENCE_CLEANUP_FAILED) {
        const char *detail =
            settlement_error_captured && settlement_error.message[0]
                ? settlement_error.message
                : "the recovery marker could not be durably retained or cleared";

        set_error(
            ERR_FILE_IO,
            "Account switch to '%s' committed coherently, but recovery-fence "
            "cleanup could not be proven: %s",
            target->name, detail);
        g_last_error.system_errno = settlement_error.system_errno;
        errno = settlement_error_errno;
        return -1;
    }
    if (final_state ==
        ACCOUNTS_SWITCH_COMMIT_FINALIZATION_CLEANUP_FAILED) {
        const char *detail =
            settlement_error_captured && settlement_error.message[0]
                ? settlement_error.message
                : "unknown Git finalization cleanup error";

        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Account switch to '%s' committed, but Git finalization cleanup "
            "failed: %s",
            target->name, detail);
        g_last_error.system_errno = settlement_error.system_errno;
        errno = settlement_error_errno;
        return -1;
    }
    if (final_state != ACCOUNTS_SWITCH_COMMIT_COMPLETE) {
        set_retained_alias_publication_error(target->name,
                                             alias_publication,
                                             alias_publication_detail,
                                             alias_publication_system_errno);
        return -1;
    }
    return 0;
}

int accounts_switch_publication(
    const gitswitch_ctx_t *ctx, const publication_record_t **publication) {
    if (accounts_process_epoch_gate(true) != 0) {
        if (publication) *publication = NULL;
        return -1;
    }
    if (publication) *publication = NULL;
    if (!ctx || !publication || !g_pending_switch.active ||
        g_pending_switch.ctx != ctx || g_pending_switch.abort_only ||
        !g_pending_switch.publication_valid ||
        g_transaction_owner.kind != ACCOUNTS_TRANSACTION_SWITCH ||
        g_transaction_owner.ctx != ctx ||
        g_transaction_owner.token != g_pending_switch.token ||
        g_transaction_owner.phase != ACCOUNTS_TRANSACTION_PREPARED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Prepared switch has no exact sealed publication provenance");
        return -1;
    }
    *publication = &g_pending_switch.publication;
    return 0;
}

static int publish_abort_result(error_accumulator_t *errors, int result) {
    if (errors && errors->active) {
        (void)error_accumulator_publish(errors);
    }
    return result;
}

static int accounts_switch_abort_accumulated(
    gitswitch_ctx_t *ctx, bool continue_persistence_rollback,
    error_accumulator_t *abort_errors) {
    error_accumulator_t local_errors;
    error_accumulator_t *errors = abort_errors;
    pending_switch_t pending;
    const account_t *previous = NULL;
    bool rollback_complete = true;
    int guard_rc;
    char rollback_detail[sizeof(g_last_error.message)] = "";

    if (!errors) {
        error_accumulator_init(&local_errors);
        errors = &local_errors;
    }

    if (!g_pending_switch.active || !ctx || g_pending_switch.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account switch to roll back");
        (void)error_accumulator_add_last(errors, "account abort admission");
        return publish_abort_result(errors, -1);
    }
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                            g_pending_switch.token, "abort") != 0) {
        (void)error_accumulator_add_last(errors, "account abort ownership");
        return publish_abort_result(errors, -1);
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_SWITCH, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_ABORT_ONLY, "abort") != 0) {
        (void)error_accumulator_add_last(errors, "account abort phase");
        return publish_abort_result(errors, -1);
    }
    pending = g_pending_switch;
    g_transaction_owner.phase = pending.abort_only
        ? ACCOUNTS_TRANSACTION_ABORT_ONLY
        : ACCOUNTS_TRANSACTION_FINALIZING;
    if (pending.runtime_lock_fd < 0) {
        pending.runtime_lock_fd = runtime_state_lock_acquire();
        if (pending.runtime_lock_fd < 0) {
            /* AR-13 M3: the owner phase was optimistically advanced to
             * FINALIZING just above, but a retry-handle record
             * (runtime_lock_fd < 0) means this abort has not actually run.
             * Restore ABORT_ONLY before returning: abort/commit admission
             * accepts only PREPARED/ABORT_ONLY, so leaving FINALIZING strands
             * the transaction owner forever once the cross-HOME runtime lock
             * contention (which is non-blocking/fail-fast) is merely transient.
             * abort_only stays false so a successful retry still replays the
             * retained dirty rollback. */
            g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
            (void)error_accumulator_add_last(errors,
                                             "runtime lock reacquisition");
            return publish_abort_result(errors, -1);
        }
        g_pending_switch.runtime_lock_fd = pending.runtime_lock_fd;
    }
    if (pending.had_previous_account) {
        previous = &pending.previous_account;
    }
    abort_failed_switch_checked(previous, pending.previous_gpg_home,
                                pending.previous_gpg_present,
                                pending.git_written, pending.ssh_dirty,
                                pending.gpg_dirty, pending.runtime_lock_fd,
                                false,
                                true,
                                &pending.git_written,
                                &pending.ssh_dirty,
                                &pending.gpg_dirty,
                                &rollback_complete,
                                rollback_detail, sizeof(rollback_detail),
                                errors);
    pending.runtime_lock_fd = -1;

    safe_strncpy(ctx->config.active_account, pending.previous_active,
                 sizeof(ctx->config.active_account));
    ctx->current_account = NULL;
    if (pending.had_previous_account) {
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id == pending.previous_account.id) {
                ctx->current_account = &ctx->accounts[i];
                break;
            }
        }
    }

    if (!rollback_complete) {
        /* Retain exactly the unfinished rollback components. A caller may
         * repair a transient Git/runtime failure and retry abort; completed
         * components are not replayed, and the runtime lock is reacquired.
         * The signal guard and repeat-signal deferral deliberately remain
         * armed as part of that retry handle: dropping either before a
         * completed abort would let a repeated signal strand mixed state. */
        g_pending_switch = pending;
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        return publish_abort_result(errors, -1);
    }
    /* Git/runtime are now fully back at the before-image. A normal abort may
     * remove a fence created by this attempt only at this point. An adopted
     * recovery fence can never be removed by reverse abort: its before-image
     * is the unresolved state that required the marker in the first place,
     * so abandoning its handle leaves the marker durable while process-local
     * ownership unwinds. */
    pending.abort_only = true;
    pending.git_written = false;
    pending.ssh_dirty = false;
    pending.gpg_dirty = false;
    pending.runtime_lock_fd = -1;
    if (pending.guard) {
        if (!pending.guard_created) {
            config_switch_guard_abandon(&pending.guard);
        } else if (config_switch_guard_clear(&pending.guard) != 0) {
            (void)error_accumulator_add_last(
                errors, "durable switch recovery-fence removal");
            /* clear() retains the live handle on every failure. Publish a
             * zero-dirty abort-only retry record instead of losing it through
             * the final memset below. */
            g_pending_switch = pending;
            g_transaction_owner.phase =
                ACCOUNTS_TRANSACTION_ABORT_ONLY;
            return publish_abort_result(errors, -1);
        }
    }
    /* main() may still need to reverse its active-account file and resume
     * hint, so CLI-owned abort keeps both layers armed until common cleanup.
     * A standalone prepared-API caller has completed every rollback here:
     * only now is it safe to restore caller dispositions and dispatch. */
    if (continue_persistence_rollback) {
        signals_rollback_begin();
        if (g_transaction_owner.rollback_depth > 0 &&
            accounts_transaction_rollback_end(
                ctx, ACCOUNTS_TRANSACTION_SWITCH, pending.token) != 0) {
            (void)error_accumulator_add_last(
                errors, "transaction rollback release");
            g_pending_switch = pending;
            g_transaction_owner.phase =
                ACCOUNTS_TRANSACTION_ABORT_ONLY;
            return publish_abort_result(errors, -1);
        }
        memset(&g_pending_switch, 0, sizeof(g_pending_switch));
        guard_rc = accounts_transaction_finish(
            ctx, ACCOUNTS_TRANSACTION_SWITCH, pending.token);
        if (guard_rc != 0) {
            (void)error_accumulator_add_last(
                errors, "account transaction finish");
        }
        return publish_abort_result(errors, guard_rc);
    }
    if (g_transaction_owner.rollback_depth > 0 &&
        accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_SWITCH, pending.token) != 0) {
        (void)error_accumulator_add_last(errors,
                                         "transaction rollback release");
        g_pending_switch = pending;
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        return publish_abort_result(errors, -1);
    }
    guard_rc = finish_signal_guard_checked(
        "Prepared switch rolled back, but restoring the caller's signal "
        "dispositions failed");
    if (guard_rc != 0) {
        /* Git/runtime rollback is complete, but signals.c still owns at least
         * one failed disposition (or pending dispatch step). Keep an
         * abort-only zero-dirty record so the caller has a checked API that
         * can retry that final process-global cleanup. */
        g_pending_switch = pending;
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        (void)error_accumulator_add_last(errors, "signal guard release");
        return publish_abort_result(errors, -1);
    }
    memset(&g_pending_switch, 0, sizeof(g_pending_switch));
    guard_rc = accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_SWITCH,
                                           pending.token);
    if (guard_rc != 0) {
        (void)error_accumulator_add_last(errors,
                                         "account transaction finish");
    }
    return publish_abort_result(errors, guard_rc);
}

int accounts_switch_abort(gitswitch_ctx_t *ctx,
                          bool continue_persistence_rollback) {
    if (accounts_process_epoch_gate(true) != 0) return -1;
    return accounts_switch_abort_accumulated(
        ctx, continue_persistence_rollback, NULL);
}

/* Fields whose persisted value must agree with the live Git/SSH/GPG state.
 * Description is intentionally excluded: it is metadata-only and safe to
 * update while the account is active. */
typedef struct {
    const char *left;
    const char *right;
} gpg_selector_comparison_t;

static int compare_gpg_selectors_observational(void *context) {
    const gpg_selector_comparison_t *comparison = context;
    char normalized_left[MAX_GPG_SELECTOR_LEN];
    char normalized_right[MAX_GPG_SELECTOR_LEN];

    if (!comparison) return 0;
    return publication_normalize_gpg_selector(
               comparison->left, normalized_left) == 0 &&
           publication_normalize_gpg_selector(
               comparison->right, normalized_right) == 0 &&
           strcmp(normalized_left, normalized_right) == 0;
}

static bool gpg_selectors_semantically_equal(const char *a, const char *b) {
    gpg_selector_comparison_t comparison;

    if (!a || !b) return false;
    if (strcmp(a, b) == 0) return true;
    comparison.left = a;
    comparison.right = b;
    return error_run_observational(compare_gpg_selectors_observational,
                                   &comparison) == 1;
}

static bool account_live_fields_equal(const account_t *a, const account_t *b) {
    return a && b &&
           strcmp(a->name, b->name) == 0 &&
           strcmp(a->email, b->email) == 0 &&
           a->preferred_scope == b->preferred_scope &&
           a->ssh_enabled == b->ssh_enabled &&
           strcmp(a->ssh_key_path, b->ssh_key_path) == 0 &&
           strcmp(a->ssh_host_alias, b->ssh_host_alias) == 0 &&
           strcmp(a->ssh_hostname, b->ssh_hostname) == 0 &&
           a->gpg_enabled == b->gpg_enabled &&
           a->gpg_signing_enabled == b->gpg_signing_enabled &&
           gpg_selectors_semantically_equal(a->gpg_key_id,
                                            b->gpg_key_id);
}

static account_t *account_by_id(gitswitch_ctx_t *ctx, uint32_t id) {
    for (size_t i = 0; ctx && i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == id) return &ctx->accounts[i];
    }
    return NULL;
}

static bool account_has_managed_alias(const account_t *account) {
    return account && account->ssh_enabled &&
           account->ssh_key_path[0] != '\0' &&
           account->ssh_host_alias[0] != '\0' &&
           account->ssh_hostname[0] != '\0';
}

/* Admission prevents shared aliases, but a hand-constructed/corrupted context
 * must not let removing one account delete another account's only block. */
static bool account_alias_exclusively_owned(const gitswitch_ctx_t *ctx,
                                            uint32_t owner_id,
                                            const char *alias) {
    if (!ctx || !alias || alias[0] == '\0') return false;
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id != owner_id &&
            ctx->accounts[i].ssh_host_alias[0] != '\0' &&
            string_ascii_case_equal(ctx->accounts[i].ssh_host_alias, alias)) {
            return false;
        }
    }
    return true;
}

static bool account_ssh_routing_equal(const account_t *a,
                                      const account_t *b) {
    return a && b && a->ssh_enabled == b->ssh_enabled &&
           strcmp(a->ssh_key_path, b->ssh_key_path) == 0 &&
           strcmp(a->ssh_host_alias, b->ssh_host_alias) == 0 &&
           strcmp(a->ssh_hostname, b->ssh_hostname) == 0;
}

static bool account_ssh_runtime_identity_equal(const account_t *a,
                                               const account_t *b) {
    if (!a || !b || a->ssh_enabled != b->ssh_enabled) return false;
    if (!a->ssh_enabled) return true;
    return strcmp(a->name, b->name) == 0 &&
           strcmp(a->ssh_key_path, b->ssh_key_path) == 0;
}

static bool account_gpg_runtime_identity_equal(const account_t *a,
                                               const account_t *b) {
    if (!a || !b || a->gpg_enabled != b->gpg_enabled) return false;
    if (!a->gpg_enabled) return true;
    return strcmp(a->name, b->name) == 0 &&
           gpg_selectors_semantically_equal(a->gpg_key_id,
                                            b->gpg_key_id);
}

static int restore_pending_edit_alias(void) {
    bool complete = true;
    char detail[sizeof(g_last_error.message)] = "";
    const account_t *original = &g_pending_edit.original;
    const account_t *candidate = &g_pending_edit.candidate;

    if (!g_pending_edit.routing_changed) return 0;

    /* AR-12 L4: both rollback legs may fail in one abort; keep the FIRST
     * failing leg's diagnostic as the published cause instead of letting
     * the second overwrite it. */
    if (g_pending_edit.candidate_alias_attempted) {
        if (account_has_managed_alias(candidate) &&
            account_has_managed_alias(original) &&
            string_ascii_case_equal(candidate->ssh_host_alias,
                                    original->ssh_host_alias) &&
            g_pending_edit.original_alias_exclusive) {
            if (ssh_configure_host_alias(original) != 0) {
                complete = false;
                if (detail[0] == '\0') {
                    safe_strncpy(detail, get_last_error()->message,
                                 sizeof(detail));
                }
            }
        } else if (candidate->ssh_host_alias[0] != '\0' &&
                   ssh_remove_host_alias(candidate->ssh_host_alias) != 0) {
            complete = false;
            if (detail[0] == '\0') {
                safe_strncpy(detail, get_last_error()->message,
                             sizeof(detail));
            }
        }
    }

    if (g_pending_edit.original_alias_remove_attempted &&
        g_pending_edit.original_alias_exclusive &&
        account_has_managed_alias(original) &&
        !(account_has_managed_alias(candidate) &&
          string_ascii_case_equal(candidate->ssh_host_alias,
                                  original->ssh_host_alias))) {
        if (ssh_configure_host_alias(original) != 0) {
            complete = false;
            if (detail[0] == '\0') {
                safe_strncpy(detail, get_last_error()->message,
                             sizeof(detail));
            }
        }
    }

    if (!complete) {
        set_error(ERR_FILE_IO,
                  "Could not restore the original SSH alias routing: %s",
                  detail[0] ? detail : "unknown SSH config error");
        return -1;
    }
    return 0;
}

int accounts_edit_abort(gitswitch_ctx_t *ctx) {
    account_t *slot;
    int alias_rc;
    accounts_transaction_token_t token;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || !g_pending_edit.active || g_pending_edit.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account edit to roll back");
        return -1;
    }
    token = g_pending_edit.token;
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_EDIT, token,
                            "abort") != 0) {
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_EDIT, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_ABORT_ONLY, "abort") != 0) {
        return -1;
    }
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_FINALIZING;

    alias_rc = restore_pending_edit_alias();
    slot = account_by_id(ctx, g_pending_edit.original.id);
    if (!slot) {
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Edited account disappeared before rollback");
        return -1;
    }
    secure_zero_memory(slot, sizeof(*slot));
    *slot = g_pending_edit.original;

    if (alias_rc != 0) {
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        return -1;
    }
    memset(&g_pending_edit, 0, sizeof(g_pending_edit));
    if (ctx->config.defer_signal_cleanup &&
        g_transaction_owner.rollback_depth > 0) {
        signals_rollback_begin();
    }
    if (g_transaction_owner.rollback_depth > 0 &&
        accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_EDIT, token) != 0) {
        return -1;
    }
    if (accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                    token) != 0) {
        return -1;
    }
    if (!ctx->config.defer_signal_cleanup &&
        finish_signal_guard_checked(
            "Account edit rolled back, but restoring the caller's signal dispositions failed") != 0) {
        return -1;
    }
    return 0;
}

int accounts_edit_commit(gitswitch_ctx_t *ctx) {
    accounts_transaction_token_t token;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || !g_pending_edit.active || g_pending_edit.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account edit to commit");
        return -1;
    }
    token = g_pending_edit.token;
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_EDIT, token,
                            "commit") != 0) {
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_EDIT, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_PREPARED, "commit") != 0) {
        return -1;
    }
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_FINALIZING;
    memset(&g_pending_edit, 0, sizeof(g_pending_edit));
    if (ctx->config.defer_signal_cleanup &&
        g_transaction_owner.rollback_depth > 0) {
        signals_rollback_begin();
    }
    if (g_transaction_owner.rollback_depth > 0 &&
        accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_EDIT, token) != 0) {
        return -1;
    }
    if (accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                    token) != 0) {
        return -1;
    }
    if (!ctx->config.defer_signal_cleanup &&
        finish_signal_guard_checked(
            "Account edit committed, but restoring the caller's signal dispositions failed") != 0) {
        return -1;
    }
    return 0;
}

static int accounts_edit_candidate_prepare_owned(
    gitswitch_ctx_t *ctx, const account_t *candidate,
    accounts_transaction_token_t token) {
    account_t edited;
    account_t *existing;
    bool editing_active;
    bool isolated_gpg_home_present = false;
    bool retire_ssh;
    bool retire_gpg;
    int runtime_lock_fd = -1;

    if (!ctx || !candidate) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to account edit prepare");
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "edit an account") != 0) {
        return -1;
    }
    existing = account_by_id(ctx, candidate->id);
    if (!existing) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found",
                  candidate->id);
        return -1;
    }

    edited = *candidate;
    if (!edited.ssh_enabled) {
        edited.ssh_key_path[0] = '\0';
        edited.ssh_key_spelling[0] = '\0'; /* AR-13 L22: no stale spelling */
        edited.ssh_host_alias[0] = '\0';
        edited.ssh_hostname[0] = '\0';
    } else if (edited.ssh_host_alias[0] != '\0' &&
               edited.ssh_hostname[0] == '\0' &&
               toml_validate_ssh_hostname(edited.ssh_host_alias)) {
        if (safe_strncpy(edited.ssh_hostname, edited.ssh_host_alias,
                         sizeof(edited.ssh_hostname)) != 0) return -1;
    }
    if (!edited.gpg_enabled) {
        edited.gpg_key_id[0] = '\0';
        edited.gpg_signing_enabled = false;
    }

    editing_active = (existing == ctx->current_account) ||
                     (ctx->config.active_account[0] != '\0' &&
                      strcasecmp(ctx->config.active_account,
                                 existing->name) == 0);
    if (editing_active && !account_live_fields_equal(existing, &edited)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Cannot change live fields for active account '%s'; "
                  "switch away or reset it, then rerun edit",
                  existing->name);
        return -1;
    }

    memset(&g_pending_edit, 0, sizeof(g_pending_edit));
    g_pending_edit.token = token;
    g_pending_edit.ctx = ctx;
    g_pending_edit.original = *existing;
    g_pending_edit.candidate = edited;
    g_pending_edit.routing_changed =
        !account_ssh_routing_equal(existing, &edited);
    g_pending_edit.original_alias_exclusive =
        account_alias_exclusively_owned(ctx, existing->id,
                                        existing->ssh_host_alias);
    retire_ssh = !account_ssh_runtime_identity_equal(existing, &edited);
    retire_gpg = !account_gpg_runtime_identity_equal(existing, &edited);

    /* config_update_account is the single add/edit admission gate. Nothing
     * externally visible has changed yet, so a validation failure needs no
     * rollback window. */
    if (config_update_account_owned(ctx, &edited, token) != 0) {
        memset(&g_pending_edit, 0, sizeof(g_pending_edit));
        return -1;
    }
    g_pending_edit.active = true;
    (void)transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_EDIT, token,
                                 ACCOUNTS_TRANSACTION_PREPARED);
    if (signals_guard_begin() != 0) {
        error_context_t guard_error = *get_last_error();
        int guard_errno = errno;
        char rollback_error[sizeof(g_last_error.message)] = "";

        /* config_update_account has changed only the process-local slot. No
         * SSH/GPG retirement or alias operation has started, so abort restores
         * the exact before-image without crossing an external boundary. */
        if (accounts_edit_abort(ctx) != 0) {
            safe_strncpy(rollback_error, get_last_error()->message,
                         sizeof(rollback_error));
            set_error(ERR_SYSTEM_CALL,
                      "Signal guard setup failed (%s), and the in-memory "
                      "account before-image could not be restored (%s)",
                      guard_error.message,
                      rollback_error[0] ? rollback_error :
                          "unknown edit rollback error");
        } else {
            g_last_error = guard_error;
        }
        errno = guard_errno;
        return -1;
    }
    if (accounts_transaction_rollback_begin(
            ctx, ACCOUNTS_TRANSACTION_EDIT, token) != 0) {
        error_context_t rollback_error = *get_last_error();
        int rollback_errno = errno;
        (void)accounts_edit_abort(ctx);
        g_last_error = rollback_error;
        errno = rollback_errno;
        return -1;
    }

    if (retire_ssh || retire_gpg) {
        runtime_lock_fd = runtime_state_lock_acquire();
        if (runtime_lock_fd < 0) goto prepare_fail;
    }

    /* An isolated home can contain the only remaining copy of this account's
     * secret key (AR-06 F17). Deleting it during prepare would make a later
     * pre-install config failure impossible to roll back truthfully. Check
     * while holding the cross-manager runtime lock and keep that lock through
     * retirement, so a concurrent switch cannot create the home after the
     * check. The explicit reset command is the user's destructive commit
     * point; after it succeeds, retrying the edit is safe. */
    if (retire_gpg) {
        if (gpg_manager_isolated_home_present(
                g_pending_edit.original.name,
                &isolated_gpg_home_present) != 0) {
            goto prepare_fail;
        }
        if (isolated_gpg_home_present) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Cannot change GPG identity for account '%s' while its "
                      "isolated GPG home exists; it may contain the only secret "
                      "key copy. Run 'gitswitch reset %u' and confirm that "
                      "destructive cleanup, then retry the edit.",
                      g_pending_edit.original.name,
                      g_pending_edit.original.id);
            goto prepare_fail;
        }
        if (strcmp(g_pending_edit.original.name, edited.name) != 0) {
            if (gpg_manager_isolated_home_present(
                    edited.name, &isolated_gpg_home_present) != 0) {
                goto prepare_fail;
            }
            if (isolated_gpg_home_present) {
                set_error(ERR_ACCOUNT_INVALID,
                          "Cannot rename account '%s' to '%s': an isolated GPG "
                          "home already exists for that target name and may "
                          "contain unrelated secret material. Choose another "
                          "name or run 'gitswitch reset' to explicitly clear "
                          "all isolated runtime state, then retry.",
                          g_pending_edit.original.name, edited.name);
                goto prepare_fail;
            }
        }
        if (edited.gpg_enabled &&
            validate_gpg_key_availability_fresh(edited.gpg_key_id) != 0) {
            log_debug("Cannot change GPG identity for account '%s': pinned "
                      "system-source validation of selector '%s' failed: %s",
                      g_pending_edit.original.name, edited.gpg_key_id,
                      get_last_error()->message[0]
                          ? get_last_error()->message
                          : "unknown key resolution error");
            goto prepare_fail;
        }
    }

    if (g_pending_edit.routing_changed) {
        if (account_has_managed_alias(&edited)) {
            g_pending_edit.candidate_alias_attempted = true;
            if (ssh_configure_host_alias(&edited) != 0) goto prepare_fail;
        }
        if (g_pending_edit.original_alias_exclusive &&
            g_pending_edit.original.ssh_host_alias[0] != '\0' &&
            !(account_has_managed_alias(&edited) &&
              string_ascii_case_equal(
                  g_pending_edit.original.ssh_host_alias,
                  edited.ssh_host_alias))) {
            g_pending_edit.original_alias_remove_attempted = true;
            if (ssh_remove_host_alias(
                    g_pending_edit.original.ssh_host_alias) != 0) {
                goto prepare_fail;
            }
        }
    }

    if (retire_ssh || retire_gpg) {
        if (retire_ssh &&
            ssh_manager_reset(g_pending_edit.original.name) != 0) {
            runtime_state_lock_release(runtime_lock_fd);
            runtime_lock_fd = -1;
            goto prepare_fail;
        }
        if (retire_gpg &&
            gpg_manager_reset(g_pending_edit.original.name) != 0) {
            runtime_state_lock_release(runtime_lock_fd);
            runtime_lock_fd = -1;
            goto prepare_fail;
        }
        runtime_state_lock_release(runtime_lock_fd);
        runtime_lock_fd = -1;
    }

    if (signals_pending()) {
        set_error(ERR_SYSTEM_CALL, "Account edit interrupted before persistence");
        goto prepare_fail;
    }
    return 0;

prepare_fail:
    {
        error_context_t cause = *get_last_error();
        char rollback_error[sizeof(g_last_error.message)] = "";
        if (runtime_lock_fd >= 0) runtime_state_lock_release(runtime_lock_fd);
        if (accounts_edit_abort(ctx) != 0) {
            safe_strncpy(rollback_error, get_last_error()->message,
                         sizeof(rollback_error));
            set_error(ERR_SYSTEM_CALL,
                      "Account edit failed (%s), and rollback was incomplete (%s)",
                      cause.message, rollback_error);
        } else {
            g_last_error = cause;
        }
        return -1;
    }
}

int accounts_edit_candidate_prepare(gitswitch_ctx_t *ctx,
                                    const account_t *candidate) {
    accounts_transaction_token_t token;
    int rc;

    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                   &token) != 0) {
        return -1;
    }
    rc = accounts_edit_candidate_prepare_owned(ctx, candidate, token);
    if (g_pending_edit.active && g_pending_edit.token == token) return rc;
    if (transaction_finish_after_call(
            ctx, ACCOUNTS_TRANSACTION_EDIT, token,
            ctx && ctx->config.defer_signal_cleanup) != 0) {
        return -1;
    }
    return rc;
}

/* Shared interactive add/edit flow. `existing` is NULL for add, or points at
 * the account being edited (in which case every prompt shows the current value
 * as the default and an empty answer keeps it). Routes all input through
 * prompt_line so readline builds get line editing and TAB path completion. */
/* AR-10 L19: the label is passed to prompt_line (and thus readline) as the
 * actual prompt instead of being printf'ed separately with an empty readline
 * prompt — the old split broke readline's column accounting, so a TAB
 * completion list, Ctrl-L, or line wrap redisplayed the input without its
 * label. Each retry re-issues the full label for the same reason. */
static int account_prompt_line(const char *prompt_text, char *input,
                               size_t input_size, bool path_completion) {
    int result;

    do {
        result = prompt_line(prompt_text, input, input_size, path_completion);
        if (result == PROMPT_LINE_TRUNCATED) {
            printf("[ERROR]: Input is too long (maximum %zu bytes). "
                   "Please try again.\n", input_size - 1);
        }
    } while (result == PROMPT_LINE_TRUNCATED);

    return result;
}

/* A blank line is a successful answer with field-specific default semantics;
 * EOF and read failures are not answers. Keep that distinction at this shared
 * boundary so no add/edit prompt can accidentally publish a partially filled
 * local candidate after input disappeared. */
static int account_read_prompt(const char *prompt_text, char *input,
                               size_t input_size, bool path_completion,
                               const char *field) {
    int result = account_prompt_line(prompt_text, input, input_size,
                                     path_completion);

    if (result != PROMPT_LINE_OK) {
        if (result == PROMPT_LINE_ERROR) {
            int prompt_errno = errno != 0 ? errno : EIO;

            errno = prompt_errno;
            set_system_error(ERR_FILE_IO, "Failed to display or read %s",
                             field);
            errno = prompt_errno;
        } else {
            set_error(ERR_FILE_IO, "Failed to read %s", field);
        }
        return -1;
    }
    return 0;
}

static int add_or_edit_account(gitswitch_ctx_t *ctx, account_t *existing,
                               accounts_transaction_token_t token) {
    account_t acct;
    char input[512];
    char expanded_path[MAX_PATH_LEN];
    char prompt_text[MAX_PATH_LEN + 64];
    bool edit = (existing != NULL);

    if (edit) {
        acct = *existing;
    } else {
        memset(&acct, 0, sizeof(acct));
        if (get_next_available_id(ctx, &acct.id) != 0) return -1;
        acct.preferred_scope = ctx->config.default_scope;
    }

    printf("\n┌─────────────────────────────────────┐\n");
    printf("│ %-35s │\n", edit ? "Edit Account" : "Add New Account");
    printf("└─────────────────────────────────────┘\n\n");

    /* Name */
    while (1) {
        if (edit) snprintf(prompt_text, sizeof(prompt_text),
                           "Account Name [%s]: ", acct.name);
        else      snprintf(prompt_text, sizeof(prompt_text),
                           "Account Name: ");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "account name") != 0) {
            return -1;
        }
        if (strlen(input) == 0) {
            if (edit) break;            /* keep current */
            printf("[ERROR]: Invalid name. Please enter a non-empty name.\n");
            continue;
        }
        if (!validate_name(input)) {
            printf("[ERROR]: Invalid name (no '/', '\\', '..', or control chars).\n");
            continue;
        }
        safe_strncpy(acct.name, input, sizeof(acct.name));
        break;
    }

    /* Email */
    while (1) {
        if (edit) snprintf(prompt_text, sizeof(prompt_text),
                           "Email Address [%s]: ", acct.email);
        else      snprintf(prompt_text, sizeof(prompt_text),
                           "Email Address: ");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "email address") != 0) {
            return -1;
        }
        if (strlen(input) == 0) {
            if (edit) break;
            printf("[ERROR]: Invalid email address format.\n");
            continue;
        }
        if (!validate_email(input)) {
            printf("[ERROR]: Invalid email address format.\n");
            continue;
        }
        /* L1 (copy half): validate_email's >= bound makes an overlong input
         * unreachable here today, but a silently-failed copy left add
         * aborting late with a misleading message and edit keeping the old
         * email — re-prompt instead of ignoring the return. */
        if (safe_strncpy(acct.email, input, sizeof(acct.email)) != 0) {
            printf("[ERROR]: Email address too long.\n");
            continue;
        }
        break;
    }

    /* Description. It is printed in the summary before config admission, so
     * enforce the same strict UTF-8/terminal policy here and never echo a
     * rejected value in diagnostics. */
    while (1) {
        if (edit) snprintf(prompt_text, sizeof(prompt_text),
                           "Description [%s]: ", acct.description);
        else      snprintf(prompt_text, sizeof(prompt_text),
                           "Description (optional): ");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "account description") != 0) {
            return -1;
        }
        if (input[0] == '\0') {
            if (!edit && safe_strncpy(acct.description, acct.name,
                                      sizeof(acct.description)) != 0) {
                set_error(ERR_ACCOUNT_INVALID,
                          "Default account description is too long");
                return -1;
            }
            break;
        }
        if (!text_is_tty_safe(input)) {
            printf("[ERROR]: Description contains unsafe or malformed Unicode. "
                   "Please try again: ");
            continue;
        }
        if (safe_strncpy(acct.description, input,
                         sizeof(acct.description)) != 0) {
            printf("[ERROR]: Description is too long. Please try again: ");
            continue;
        }
        break;
    }

    /* SSH key. Empty keeps current (edit) or skips (add); 'none' disables.
     * Re-prompt on a bad path rather than silently dropping SSH. */
    while (1) {
        if (edit && acct.ssh_enabled)
            snprintf(prompt_text, sizeof(prompt_text),
                     "SSH Key Path [%s] (Enter to keep, 'none' to disable): ",
                     acct.ssh_key_path);
        else
            snprintf(prompt_text, sizeof(prompt_text),
                     "SSH Key Path (optional, Enter to skip): ");
        if (account_read_prompt(prompt_text, input, sizeof(input), true,
                                "SSH key path") != 0) {
            return -1;
        }

        if (strlen(input) == 0) break;                 /* keep/skip */
        if (strcmp(input, "none") == 0) {              /* disable */
            acct.ssh_enabled = false;
            acct.ssh_key_path[0] = '\0';
            acct.ssh_key_spelling[0] = '\0'; /* AR-13 L22: no stale spelling */
            acct.ssh_host_alias[0] = '\0';
            acct.ssh_hostname[0] = '\0';
            break;
        }
        if (expand_path(input, expanded_path, sizeof(expanded_path)) != 0) {
            printf("[ERROR]: Invalid SSH key path: %s (try again, or Enter to skip)\n", input);
            continue;
        }
        /* M5 (write entry): the loader skips any account whose persisted
         * ssh_key exceeds 256 chars (and the parser hard-fails >=512 at set
         * time), so accepting a longer path here would save an account this
         * same tool then refuses to load back — the add "succeeds" and the
         * account vanishes on the next invocation. Refuse it up front. */
        if (strlen(expanded_path) > 256) {
            printf("[ERROR]: SSH key path too long (%zu chars, max 256): %s "
                   "(try again, or Enter to skip)\n",
                   strlen(expanded_path), expanded_path);
            continue;
        }
        if (!path_exists(expanded_path)) {
            printf("[ERROR]: SSH key file not found: %s (try again, or Enter to skip)\n", expanded_path);
            continue;
        }
        if (ssh_validate_key_file(expanded_path) != 0) {
            printf("[ERROR]: SSH key failed validation: %s (try again, or Enter to skip)\n", expanded_path);
            continue;
        }
        /* AR-12 H4: a path the TOML sanitizer would alter (quote/backslash)
         * would be admitted here but skipped by the loader's schema on the
         * next start. Refuse it up front like the over-long case. */
        {
            char roundtrip_path[MAX_PATH_LEN];

            if (toml_sanitize_string(expanded_path, roundtrip_path,
                                     sizeof(roundtrip_path)) != 0 ||
                strcmp(roundtrip_path, expanded_path) != 0) {
                printf("[ERROR]: SSH key path contains characters that cannot "
                       "be saved faithfully: %s (try again, or Enter to skip)\n",
                       expanded_path);
                continue;
            }
        }
        safe_strncpy(acct.ssh_key_path, expanded_path, sizeof(acct.ssh_key_path));
        /* AR-13 L23: preserve the exact text the user typed (e.g. '~/.ssh/id')
         * so the L8 save guard re-emits that spelling instead of the expanded
         * absolute path. If they typed the absolute path itself, clear any
         * stale spelling so an explicit absolute respelling of the same file
         * wins over an old tilde rather than being overridden by the guard. */
        if (strcmp(input, expanded_path) != 0) {
            safe_strncpy(acct.ssh_key_spelling, input,
                         sizeof(acct.ssh_key_spelling));
        } else {
            acct.ssh_key_spelling[0] = '\0';
        }
        acct.ssh_enabled = true;
        printf("[OK]: SSH key validated: %s\n", expanded_path);

        /* L2: the alias lands verbatim in a "Host <alias>" line of
         * ~/.ssh/config, so gate it here the way the writer will (charset)
         * and to what the account field can hold (length) — the old single-
         * shot prompt let a >=256-char alias fail safe_strncpy silently and
         * reported success with the alias dropped. Re-prompt on rejection. */
        while (1) {
            if (edit && acct.ssh_host_alias[0])
                snprintf(prompt_text, sizeof(prompt_text),
                         "SSH Host Alias [%s] (Enter to keep): ",
                         acct.ssh_host_alias);
            else
                snprintf(prompt_text, sizeof(prompt_text),
                         "SSH Host Alias (optional, e.g., github.com-work): ");
            if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                    "SSH host alias") != 0) {
                return -1;
            }
            if (strlen(input) == 0) {
                break;                              /* keep current / skip */
            }
            if (!prompt_host_alias_valid(input) ||
                safe_strncpy(acct.ssh_host_alias, input,
                             sizeof(acct.ssh_host_alias)) != 0) {
                printf("[ERROR]: Invalid host alias (letters, digits, and "
                       ". - _ * ? only; under %d chars). Try again, or Enter to skip.\n",
                       MAX_NAME_LEN);
                continue;
            }
            break;
        }

        /* AR-12 M2: the alias is not the destination — the suffix style the
         * prompt above suggests ('github.com-work') is not a resolvable DNS
         * name, and admission would otherwise silently pin HostName to it.
         * Ask for the canonical destination whenever an alias is set. */
        while (acct.ssh_host_alias[0] != '\0') {
            if (edit && acct.ssh_hostname[0])
                snprintf(prompt_text, sizeof(prompt_text),
                         "SSH Canonical Hostname [%s] (Enter to keep): ",
                         acct.ssh_hostname);
            else
                snprintf(prompt_text, sizeof(prompt_text),
                         "SSH Canonical Hostname (the real host, e.g. "
                         "github.com; Enter to use the alias): ");
            if (account_read_prompt(prompt_text, input, sizeof(input),
                                    false, "SSH canonical hostname") != 0) {
                return -1;
            }
            if (strlen(input) == 0) {
                if (acct.ssh_hostname[0] == '\0') {
                    printf("[WARNING]: No canonical hostname set; the "
                           "managed ~/.ssh/config block will use HostName "
                           "%s, which must resolve as a real host.\n",
                           acct.ssh_host_alias);
                }
                break;                              /* keep current / skip */
            }
            if (!toml_validate_ssh_hostname(input) ||
                safe_strncpy(acct.ssh_hostname, input,
                             sizeof(acct.ssh_hostname)) != 0) {
                printf("[ERROR]: Invalid canonical hostname (host-only "
                       "ASCII name/IPv4 or unbracketed IPv6; no port). "
                       "Try again, or Enter to skip.\n");
                continue;
            }
            break;
        }
        break;
    }

    /* GPG key. Same empty/'none' semantics as SSH. */
    while (1) {
        if (edit && acct.gpg_enabled)
            snprintf(prompt_text, sizeof(prompt_text),
                     "GPG Key ID [%s] (Enter to keep, 'none' to disable): ",
                     acct.gpg_key_id);
        else
            snprintf(prompt_text, sizeof(prompt_text),
                     "GPG Key ID (optional, Enter to skip): ");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "GPG key ID") != 0) {
            return -1;
        }

        if (strlen(input) == 0) break;
        if (strcmp(input, "none") == 0) {
            acct.gpg_enabled = false;
            acct.gpg_key_id[0] = '\0';
            acct.gpg_signing_enabled = false;
            break;
        }
        if (!validate_key_id(input)) {
            printf("[ERROR]: Invalid GPG key ID format: %s (try again, or Enter to skip)\n", input);
            continue;
        }
        if (validate_gpg_key_availability(input) != 0) {
            error_context_t resolver_error = *get_last_error();
            int resolver_errno = errno;
            const char *diagnostic =
                resolver_error.message[0] != '\0'
                    ? resolver_error.message
                    : error_code_to_string(resolver_error.code);

            fputs("[ERROR]: GPG key validation failed: ", stdout);
            print_terminal_safe(diagnostic);
            if (resolver_error.code == ERR_GPG_KEY_NOT_FOUND) {
                fputs(" (try again, or Enter to skip)\n", stdout);
                g_last_error = resolver_error;
                errno = resolver_errno;
                continue;
            }
            putchar('\n');
            g_last_error = resolver_error;
            errno = resolver_errno;
            return -1;
        }
        safe_strncpy(acct.gpg_key_id, input, sizeof(acct.gpg_key_id));
        acct.gpg_enabled = true;
        printf("[OK]: GPG key validated: %s\n", input);
        break;
    }

    /* Keeping an existing selector is not a request to resolve it again.
     * Signing preference is an independent account field, so an edit must
     * still offer this prompt after Enter-to-keep even when the source keyring
     * is temporarily unavailable. */
    if (acct.gpg_enabled) {
        snprintf(prompt_text, sizeof(prompt_text),
                 "Enable GPG signing for commits? (y/N)%s: ",
                 (edit && acct.gpg_signing_enabled) ? " [Y]" : "");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "GPG signing preference") != 0) {
            return -1;
        }
        if (strlen(input) > 0) {
            acct.gpg_signing_enabled = (tolower((unsigned char)input[0]) == 'y');
        }
    }

    /* Preferred scope. Validate; empty keeps the shown default. */
    while (1) {
        snprintf(prompt_text, sizeof(prompt_text),
                 "Preferred Git Scope (local/global) [%s]: ",
                 config_scope_to_string(acct.preferred_scope));
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "preferred Git scope") != 0) {
            return -1;
        }
        if (strlen(input) == 0) break;
        if (strcasecmp(input, "local") == 0 || strcasecmp(input, "l") == 0) {
            acct.preferred_scope = GIT_SCOPE_LOCAL; break;
        }
        if (strcasecmp(input, "global") == 0 || strcasecmp(input, "g") == 0) {
            acct.preferred_scope = GIT_SCOPE_GLOBAL; break;
        }
        printf("[ERROR]: Please enter 'local' or 'global' (or Enter for %s).\n",
               config_scope_to_string(acct.preferred_scope));
    }

    if (!validate_name(acct.name) || !validate_email(acct.email)) {
        printf("[ERROR]: Account validation failed: Invalid name or email\n");
        return -1;
    }
    /* AR-06 F26: refuse a name that shadows a command keyword or is purely
     * numeric — it could never be switched to by name. */
    if (name_is_reserved_for_commands(acct.name)) {
        printf("[ERROR]: '%s' is a reserved command keyword or a numeric ID and "
               "cannot be used as an account name.\n", acct.name);
        return -1;
    }

    /* Summary + confirm (--yes skips the prompt). */
    printf("\nAccount Summary:\n");
    printf("   ID: %u\n", acct.id);
    printf("   Name: %s\n", acct.name);
    printf("   Email: %s\n", acct.email);
    printf("   Description: %s\n", acct.description);
    printf("   Scope: %s\n", config_scope_to_string(acct.preferred_scope));
    printf("   SSH: %s\n", acct.ssh_enabled ? "[ENABLED]" : "[DISABLED]");
    printf("   GPG: %s\n", acct.gpg_enabled ? "[ENABLED]" : "[DISABLED]");

    if (!ctx->config.assume_yes) {
        printf("\n");
        snprintf(prompt_text, sizeof(prompt_text), "%s this account? (y/N): ",
                 edit ? "Save changes to" : "Add");
        if (account_read_prompt(prompt_text, input, sizeof(input), false,
                                "account confirmation") != 0) {
            return -1;
        }
        if (tolower((unsigned char)input[0]) != 'y') {
            printf("%s cancelled.\n", edit ? "Edit" : "Account creation");
            return -1;
        }
    }

    if (edit) {
        return accounts_edit_candidate_prepare_owned(ctx, &acct, token);
    }

    if (config_add_account_owned(ctx, &acct, token) != 0) {
        return -1;
    }
    return 0;
}

int accounts_add_interactive_prepare(gitswitch_ctx_t *ctx) {
    accounts_transaction_token_t token;
    size_t count_before;
    uint32_t current_id = 0;
    bool had_current;
    int rc;

    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_ADD,
                                   &token) != 0) {
        return -1;
    }
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_add_interactive");
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_ADD,
                                          token);
        return -1;
    }
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_ADD,
                                          token);
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "add an account") != 0) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_ADD,
                                          token);
        return -1;
    }
    count_before = ctx->account_count;
    had_current = ctx->current_account != NULL;
    if (had_current) current_id = ctx->current_account->id;
    rc = add_or_edit_account(ctx, NULL, token);
    if (rc != 0) {
        (void)transaction_finish_after_call(
            ctx, ACCOUNTS_TRANSACTION_ADD, token,
            ctx->config.defer_signal_cleanup);
        return -1;
    }
    memset(&g_pending_add, 0, sizeof(g_pending_add));
    g_pending_add.active = true;
    g_pending_add.token = token;
    g_pending_add.ctx = ctx;
    g_pending_add.account_count_before = count_before;
    g_pending_add.current_account_id = current_id;
    g_pending_add.had_current_account = had_current;
    (void)transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_ADD, token,
                                 ACCOUNTS_TRANSACTION_PREPARED);
    return 0;
}

int accounts_add_commit(gitswitch_ctx_t *ctx) {
    accounts_transaction_token_t token;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || !g_pending_add.active || g_pending_add.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account addition to commit");
        return -1;
    }
    token = g_pending_add.token;
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_ADD, token,
                            "commit") != 0) {
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_ADD, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_PREPARED, "commit") != 0) {
        return -1;
    }
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_FINALIZING;
    memset(&g_pending_add, 0, sizeof(g_pending_add));
    return accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_ADD,
                                       token);
}

int accounts_add_abort(gitswitch_ctx_t *ctx) {
    pending_add_t pending;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || !g_pending_add.active || g_pending_add.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account addition to abort");
        return -1;
    }
    pending = g_pending_add;
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_ADD, pending.token,
                            "abort") != 0) {
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_ADD, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_ABORT_ONLY, "abort") != 0) {
        return -1;
    }
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_FINALIZING;
    if (ctx->account_count < pending.account_count_before) {
        g_transaction_owner.phase = ACCOUNTS_TRANSACTION_ABORT_ONLY;
        set_error(ERR_SYSTEM_CALL,
                  "Account model changed before addition rollback");
        return -1;
    }
    for (size_t i = pending.account_count_before; i < ctx->account_count; i++) {
        secure_zero_memory(&ctx->accounts[i], sizeof(ctx->accounts[i]));
    }
    ctx->account_count = pending.account_count_before;
    ctx->current_account = NULL;
    if (pending.had_current_account) {
        ctx->current_account = account_by_id(ctx, pending.current_account_id);
    }
    memset(&g_pending_add, 0, sizeof(g_pending_add));
    return accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_ADD,
                                       pending.token);
}

/* Add new account interactively with basic validation. Direct/library callers
 * retain the historical one-call model mutation; CLI callers use prepare and
 * settle it after durable persistence. */
int accounts_add_interactive(gitswitch_ctx_t *ctx) {
    if (accounts_add_interactive_prepare(ctx) != 0) return -1;
    return accounts_add_commit(ctx);
}

int accounts_edit_interactive_prepare(gitswitch_ctx_t *ctx,
                                      const char *identifier) {
    accounts_transaction_token_t token;
    account_t *account;
    int rc;

    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                   &token) != 0) {
        return -1;
    }
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to accounts_edit_interactive_prepare");
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                          token);
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "edit an account") != 0) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                          token);
        return -1;
    }
    account = config_find_account(ctx, identifier);
    if (!account) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_EDIT,
                                          token);
        return -1; /* error already set with candidate list */
    }
    rc = add_or_edit_account(ctx, account, token);
    if (g_pending_edit.active && g_pending_edit.token == token) return rc;
    if (transaction_finish_after_call(
            ctx, ACCOUNTS_TRANSACTION_EDIT, token,
            ctx->config.defer_signal_cleanup) != 0) {
        return -1;
    }
    return rc;
}

/* Direct/library compatibility: callers that do not own the CLI persistence
 * transaction retain the historical one-call in-memory edit behavior. */
int accounts_edit_interactive(gitswitch_ctx_t *ctx, const char *identifier) {
    if (accounts_edit_interactive_prepare(ctx, identifier) != 0) {
        return -1;
    }
    if (accounts_edit_commit(ctx) != 0) {
        return -1;
    }
    return 0;
}

int accounts_remove_finalize(
    gitswitch_ctx_t *ctx, accounts_retirement_save_outcome_t outcome) {
    error_accumulator_t failures;
    accounts_transaction_token_t token;
    char alias[MAX_NAME_LEN];
    bool alias_exclusive;
    accounts_retirement_save_outcome_t settlement_outcome;
    ssh_config_publication_state_t alias_publication =
        SSH_CONFIG_PUBLICATION_UNCHANGED;
    int alias_rc = 0;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!g_pending_remove.active || !ctx || g_pending_remove.ctx != ctx ||
        outcome < ACCOUNTS_RETIREMENT_SAVE_DURABLE ||
        outcome > ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED) {
        set_error(ERR_INVALID_ARGS,
                  "No prepared account removal to finalize");
        return -1;
    }
    token = g_pending_remove.token;
    alias_exclusive = g_pending_remove.alias_exclusive;
    memcpy(alias, g_pending_remove.alias, sizeof(alias));
    if (transaction_require(ctx, ACCOUNTS_TRANSACTION_REMOVE, token,
                            "finalize") != 0) {
        return -1;
    }
    if (transaction_require_phase(
            ACCOUNTS_TRANSACTION_REMOVE, ACCOUNTS_TRANSACTION_PREPARED,
            ACCOUNTS_TRANSACTION_ABORT_ONLY, "finalize") != 0) {
        return -1;
    }
    error_accumulator_init(&failures);
    g_transaction_owner.phase = ACCOUNTS_TRANSACTION_FINALIZING;
    settlement_outcome = outcome;

    if (outcome != ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED) {
        if (g_pending_remove.retirement.has_ssh_alias_obligation &&
            g_pending_remove.retirement.ssh_alias_obligation.present) {
            alias_rc = ssh_remove_host_alias_obligation_result(
                &g_pending_remove.retirement.ssh_alias_obligation,
                &alias_publication);
            if (alias_rc != 0) {
                /* Preserve the publication error before finalization touches
                 * the shared error context. Settlement remains a separate
                 * decision derived from the structured state below. */
                (void)error_accumulator_add_last(
                    &failures, "bound SSH alias retirement");
            }
            if (outcome == ACCOUNTS_RETIREMENT_SAVE_DURABLE &&
                alias_publication != SSH_CONFIG_PUBLICATION_COMMITTED &&
                alias_publication != SSH_CONFIG_PUBLICATION_UNCHANGED) {
                settlement_outcome =
                    ACCOUNTS_RETIREMENT_SAVE_UNCERTAIN;
            }
        } else if (alias[0] != '\0' && !alias_exclusive) {
            log_warning(
                "Retaining shared ~/.ssh/config host-alias block for '%s'; another account still claims the same alias",
                alias);
        } else if (alias[0] != '\0' &&
                   ssh_remove_host_alias(alias) != 0) {
            /* The durable account deletion has already crossed its publication
             * point. Keep alias cleanup best-effort and visible rather than
             * inviting a destructive retry of the removed account. */
            log_warning(
                "Could not remove ~/.ssh/config host-alias block for '%s': %s",
                alias, get_last_error()->message);
        }
    }

    if (g_pending_remove.retirement.phase != PENDING_RETIREMENT_NONE &&
        pending_retirement_finalize(
            ctx, &g_pending_remove.retirement, settlement_outcome) != 0) {
        (void)error_accumulator_add_last(
            &failures, "outer retirement finalization");
    }

    /* A pre-install outcome deliberately leaves the durable account/alias
     * pair intact. Runtime teardown cannot be undone, but the account remains
     * the exact supported retry handle after Git/ledger rollback.
     * AR-12 P1: restore the in-memory model to match — a caller that later
     * runs a full save from this context must not erase the preserved
     * account or persist the cleared active name. */
    if (outcome == ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED &&
        g_pending_remove.removed_valid &&
        ctx->account_count < MAX_ACCOUNTS) {
        bool already_present = false;

        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id ==
                g_pending_remove.removed_account.id) {
                already_present = true;
                break;
            }
        }
        if (!already_present) {
            account_t *restored = &ctx->accounts[ctx->account_count];

            *restored = g_pending_remove.removed_account;
            ctx->account_count++;
            if (g_pending_remove.removed_was_active) {
                (void)safe_strncpy(ctx->config.active_account,
                                   restored->name,
                                   sizeof(ctx->config.active_account));
            }
            if (g_pending_remove.removed_was_current) {
                ctx->current_account = restored;
            }
        }
    }
    secure_zero_memory(&g_pending_remove, sizeof(g_pending_remove));
    if (ctx->config.defer_signal_cleanup &&
        g_transaction_owner.rollback_depth > 0) {
        signals_rollback_begin();
    }
    if (g_transaction_owner.rollback_depth > 0 &&
        accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_REMOVE, token) != 0) {
        (void)error_accumulator_add_last(
            &failures, "remove transaction rollback release");
    }
    if (g_transaction_owner.rollback_depth == 0 &&
        accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                    token) != 0) {
        (void)error_accumulator_add_last(
            &failures, "remove transaction ownership release");
    }
    if (!ctx->config.defer_signal_cleanup &&
        finish_signal_guard_checked(
            outcome == ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED
                ? "Account removal aborted, but restoring the caller's signal dispositions failed"
                : "Account removal committed, but restoring the caller's signal dispositions failed") != 0) {
        (void)error_accumulator_add_last(
            &failures, "remove signal-guard release");
    }
    REMOVE_TEST_CHECKPOINT(4);
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
        return -1;
    }
    return 0;
}

int accounts_remove_commit(gitswitch_ctx_t *ctx) {
    return accounts_remove_finalize(
        ctx, ACCOUNTS_RETIREMENT_SAVE_DURABLE);
}

int accounts_remove_abort(gitswitch_ctx_t *ctx) {
    return accounts_remove_finalize(
        ctx, ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED);
}

static bool accounts_parse_canonical_account_id(const char *identifier,
                                                uint32_t *account_id) {
    char *end = NULL;
    unsigned long parsed;

    if (!identifier || !account_id ||
        identifier[0] < '1' || identifier[0] > '9') {
        return false;
    }
    for (const char *cursor = identifier + 1U; *cursor; cursor++) {
        if (!isdigit((unsigned char)*cursor)) return false;
    }
    errno = 0;
    parsed = strtoul(identifier, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        parsed > UINT32_MAX) {
        return false;
    }
    *account_id = (uint32_t)parsed;
    return true;
}

static int accounts_collect_retiring_owner_publications(
    const publication_ledger_t *ledger,
    const config_retirement_owner_t *owner,
    const publication_record_t *records[PUBLICATION_LEDGER_MAX_RECORDS],
    size_t *record_count, bool allow_zero) {
    size_t count = 0U;
    bool saw_id = false;

    if (!ledger || !owner || !records || !record_count) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid incomplete-remove publication recovery state");
        return -1;
    }
    *record_count = 0U;
    if ((ledger->present &&
         ledger->version != PUBLICATION_LEDGER_VERSION) ||
        (!ledger->present && !allow_zero)) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Incomplete removal has no canonical publication tombstone ledger");
        return -1;
    }
    if (!ledger->present) return 0;
    for (size_t i = 0U; i < ledger->count; i++) {
        const publication_record_t *record = &ledger->records[i];

        if (record->account_id != owner->account_id) continue;
        saw_id = true;
        if (strcmp(record->account_incarnation,
                   owner->account_incarnation) != 0) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Incomplete removal owner ID %u has conflicting durable incarnation provenance",
                owner->account_id);
            return -1;
        }
        if (publication_record_validate(record) != 0 ||
            record->state != PUBLICATION_STATE_RETIRING ||
            (record->capabilities &
             (PUBLICATION_CAP_DESTINATION |
              PUBLICATION_CAP_POST_GENERATION)) !=
                (PUBLICATION_CAP_DESTINATION |
                 PUBLICATION_CAP_POST_GENERATION)) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Incomplete removal owner ID %u has incomplete or non-retiring publication provenance",
                owner->account_id);
            return -1;
        }
        if (count == PUBLICATION_LEDGER_MAX_RECORDS) {
            errno = EOVERFLOW;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Incomplete removal publication set is too large");
            return -1;
        }
        records[count++] = record;
    }
    if ((!saw_id || count == 0U) && !allow_zero) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Incomplete removal owner ID %u has no durable publication tombstones",
            owner->account_id);
        return -1;
    }
    *record_count = count;
    return 0;
}

static int accounts_require_no_live_alias_claimant(
    const gitswitch_ctx_t *ctx,
    const config_retirement_ssh_alias_obligation_t *obligation) {
    if (!ctx || !obligation || !obligation->known) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Incomplete v1 REMOVE marker has unknown SSH alias state; rerun with the original account configuration or resolve the retirement marker manually");
        return -1;
    }
    if (!obligation->present) return 0;
    for (size_t i = 0U; i < ctx->account_count; i++) {
        if (ctx->accounts[i].ssh_host_alias[0] != '\0' &&
            string_ascii_case_equal(
                ctx->accounts[i].ssh_host_alias,
                obligation->ssh_host_alias)) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot recover incomplete removal because live account ID %u claims SSH alias '%s'",
                ctx->accounts[i].id, obligation->ssh_host_alias);
            return -1;
        }
    }
    return 0;
}

static int accounts_serialize_recovery_ledger(
    const publication_ledger_t *ledger, unsigned char **serialized,
    size_t *serialized_length) {
    if (!ledger || !serialized || !serialized_length || *serialized) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid publication-ledger recovery snapshot");
        return -1;
    }
    if (publication_ledger_serialize(
            ledger, serialized, serialized_length) != 0) {
        return -1;
    }
    return 0;
}

static int accounts_revalidate_recovery_ledger(
    const char *config_path, const unsigned char *expected,
    size_t expected_length, publication_ledger_t *observed,
    unsigned char **serialized, size_t *serialized_length,
    const char *changed_message) {
    if (!config_path || (!expected && expected_length != 0U) || !observed ||
        !serialized || !serialized_length) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement-ledger revalidation state");
        return -1;
    }
    publication_ledger_clear(observed);
    publication_ledger_init(observed);
    if (*serialized) {
        secure_zero_memory(*serialized, *serialized_length);
        free(*serialized);
        *serialized = NULL;
        *serialized_length = 0U;
    }
    if (config_load_publication_ledger(config_path, observed) != 0 ||
        accounts_serialize_recovery_ledger(
            observed, serialized, serialized_length) != 0) {
        return -1;
    }
    if (expected_length != *serialized_length ||
        (expected_length != 0U &&
         memcmp(expected, *serialized, expected_length) != 0)) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED, "%s",
            changed_message ? changed_message
                            : "Retirement publication tombstones changed");
        return -1;
    }
    return 0;
}

typedef struct {
    gitswitch_ctx_t *ctx;
    const config_retirement_recovery_t *recovery;
    const unsigned char *ledger_bytes;
    size_t ledger_length;
    publication_ledger_t *revalidated_ledger;
    unsigned char **revalidated_bytes;
    size_t *revalidated_length;
    git_retirement_recovery_t **git_recovery;
} accounts_remove_recovery_barrier_t;

/* The prepared guard has already re-proved its complete namespace. Re-check
 * every remaining external authority and the terminal Git witnesses without
 * releasing their retained recovery markers. The callback is read-only and
 * idempotent because the guard may invoke it again after a later failed
 * no-overwrite publication attempt. */
static int accounts_remove_recovery_commit_barrier(void *opaque) {
    accounts_remove_recovery_barrier_t *barrier = opaque;

    if (!barrier || !barrier->ctx || !barrier->recovery ||
        !barrier->revalidated_ledger || !barrier->revalidated_bytes ||
        !barrier->revalidated_length || !barrier->git_recovery) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid incomplete-removal commit barrier");
        return -1;
    }
    if (config_revalidate_loaded_source(barrier->ctx) != 0 ||
        accounts_require_no_live_alias_claimant(
            barrier->ctx,
            &barrier->recovery->ssh_alias_obligation) != 0 ||
        accounts_revalidate_recovery_ledger(
            barrier->ctx->config.config_path,
            barrier->ledger_bytes, barrier->ledger_length,
            barrier->revalidated_ledger,
            barrier->revalidated_bytes,
            barrier->revalidated_length,
            "Retirement publication tombstones changed before incomplete-remove completion") !=
            0 ||
        (barrier->recovery->ssh_alias_obligation.present &&
         ssh_revalidate_host_alias_obligation(
             &barrier->recovery->ssh_alias_obligation) != 0)) {
        return -1;
    }
    return *barrier->git_recovery
               ? git_retirement_recovery_verify_terminal(
                     *barrier->git_recovery)
               : 0;
}

int accounts_remove_recover_incomplete(gitswitch_ctx_t *ctx,
                                       const char *identifier) {
    config_retirement_recovery_t recovery;
    config_retirement_guard_t *guard = NULL;
    git_retirement_recovery_t *git_recovery = NULL;
    accounts_remove_recovery_barrier_t commit_barrier;
    publication_ledger_t ledger;
    publication_ledger_t revalidated_ledger;
    const publication_record_t *records[
        PUBLICATION_LEDGER_MAX_RECORDS];
    unsigned char *ledger_bytes = NULL;
    unsigned char *revalidated_bytes = NULL;
    size_t record_count = 0U;
    size_t ledger_length = 0U;
    size_t revalidated_length = 0U;
    uint32_t requested_id = 0U;
    error_accumulator_t failures;
    int result = -1;
    bool matching_absent_owner = false;
    bool settlement_completed = false;
    bool alias_error_after_install = false;
    bool terminal_failure_accumulated = false;
    ssh_config_publication_state_t alias_publication =
        SSH_CONFIG_PUBLICATION_UNCHANGED;

    if (accounts_process_epoch_gate(false) != 0) return -1;
    memset(&recovery, 0, sizeof(recovery));
    memset(&commit_barrier, 0, sizeof(commit_barrier));
    memset(records, 0, sizeof(records));
    publication_ledger_init(&ledger);
    publication_ledger_init(&revalidated_ledger);
    error_accumulator_init(&failures);
    if (!ctx || !identifier) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid incomplete account-removal recovery request");
        goto done;
    }
    if (!accounts_parse_canonical_account_id(identifier, &requested_id)) {
        result = 0;
        goto done;
    }
    if (config_retirement_guard_recovery_probe(
            ctx->config.config_path, &recovery) != 0) {
        goto done;
    }
    if (!recovery.valid ||
        recovery.kind != CONFIG_RETIREMENT_REMOVE ||
        recovery.owner_count != 1U ||
        recovery.owners[0].account_id != requested_id) {
        result = 0;
        goto done;
    }
    if (recovery.marker_version < 2U ||
        !recovery.ssh_alias_obligation.known) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Cannot recover incomplete v1 REMOVE marker for account ID %u because its SSH alias obligation is unknown; restore the original account and retry removal, or resolve the marker manually",
            requested_id);
        matching_absent_owner = true;
        goto done;
    }

    for (size_t i = 0U; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];

        if (account->id != requested_id) continue;
        if (!account->incarnation_persisted ||
            strcmp(account->incarnation,
                   recovery.owners[0].account_incarnation) != 0) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Cannot recover incomplete removal for account ID %u because the live account uses a different incarnation",
                requested_id);
            matching_absent_owner = true;
            goto done;
        }
        /* The exact owner is still live. This is an ordinary retry, not the
         * installed-but-uncertain missing-owner case handled here. */
        result = 0;
        goto done;
    }
    matching_absent_owner = true;

    if (config_revalidate_loaded_source(ctx) != 0 ||
        accounts_require_no_live_alias_claimant(
            ctx, &recovery.ssh_alias_obligation) != 0 ||
        config_retirement_guard_adopt_with_ssh_alias_obligation(
            ctx->config.config_path, CONFIG_RETIREMENT_REMOVE,
            recovery.owners, recovery.owner_count,
            &recovery.ssh_alias_obligation, &guard) != 0 ||
        config_revalidate_loaded_source(ctx) != 0 ||
        config_load_publication_ledger(
            ctx->config.config_path, &ledger) != 0 ||
        accounts_collect_retiring_owner_publications(
            &ledger, &recovery.owners[0],
            records, &record_count,
            recovery.ssh_alias_obligation.present) != 0 ||
        accounts_serialize_recovery_ledger(
            &ledger, &ledger_bytes, &ledger_length) != 0) {
        goto done;
    }
    if (record_count != 0U &&
        git_retirement_recovery_begin(
            records, record_count, &git_recovery) != 0) {
        goto done;
    }

    /* Keep the loaded account document and complete active-state ledger
     * byte-stable while the canonical Git destination locks remain held.
     * Exact equality prevents a same-owner record replacement from being
     * laundered through the earlier clean-destination proof. */
    if (accounts_revalidate_recovery_ledger(
            ctx->config.config_path, ledger_bytes, ledger_length,
            &revalidated_ledger, &revalidated_bytes,
            &revalidated_length,
            "Retirement publication tombstones changed during incomplete-remove recovery") !=
        0) {
        goto done;
    }
    if (recovery.ssh_alias_obligation.present) {
        int alias_rc;

        REMOVE_TEST_CHECKPOINT(5);
        /* Immediate authorization barrier for the irreversible alias
         * mutation. The owned-marker check uses the already-held lifecycle
         * lock; it neither probes token-free state nor reacquires that lock. */
        if (config_revalidate_loaded_source(ctx) != 0 ||
            accounts_require_no_live_alias_claimant(
                ctx, &recovery.ssh_alias_obligation) != 0 ||
            config_retirement_guard_revalidate(guard) != 0 ||
            accounts_revalidate_recovery_ledger(
                ctx->config.config_path, ledger_bytes, ledger_length,
                &revalidated_ledger, &revalidated_bytes,
                &revalidated_length,
                "Retirement publication tombstones changed before SSH alias recovery") !=
                0 ||
            (git_recovery &&
             git_retirement_recovery_verify(git_recovery) != 0) ||
            ssh_revalidate_host_alias_obligation(
                &recovery.ssh_alias_obligation) != 0) {
            goto done;
        }
        alias_rc = ssh_remove_host_alias_obligation_result(
            &recovery.ssh_alias_obligation, &alias_publication);
        if (alias_rc != 0) {
            (void)error_accumulator_add_last(
                &failures, "bound SSH alias recovery");
            alias_error_after_install = true;
        }
        if (alias_publication != SSH_CONFIG_PUBLICATION_COMMITTED &&
            alias_publication != SSH_CONFIG_PUBLICATION_UNCHANGED) {
            if (alias_rc == 0) {
                errno = EAGAIN;
                set_error(
                    ERR_FILE_IO,
                    "SSH alias recovery did not reach a settled publication state");
            } else {
                terminal_failure_accumulated = true;
            }
            goto done;
        }
    }
    /* Flush and stabilize the outer completion stage while ordinary Git
     * locks are still held, then publish complete self-healing Git recovery
     * markers as the final mutating step. Their authority remains held
     * through the guard's read-only barrier and no-overwrite stage rename. */
    if (config_retirement_guard_prepare_clear(guard) != 0 ||
        (git_recovery &&
         git_retirement_recovery_prepare_terminal(git_recovery) != 0)) {
        goto done;
    }
    commit_barrier.ctx = ctx;
    commit_barrier.recovery = &recovery;
    commit_barrier.ledger_bytes = ledger_bytes;
    commit_barrier.ledger_length = ledger_length;
    commit_barrier.revalidated_ledger = &revalidated_ledger;
    commit_barrier.revalidated_bytes = &revalidated_bytes;
    commit_barrier.revalidated_length = &revalidated_length;
    commit_barrier.git_recovery = &git_recovery;
    if (config_retirement_guard_clear_with_barrier(
            &guard, accounts_remove_recovery_commit_barrier,
            &commit_barrier) != 0) {
        goto done;
    }
    settlement_completed = true;
    if (git_recovery &&
        git_retirement_recovery_finish_terminal(
            &git_recovery) != 0) {
        const error_context_t *diagnostic = get_last_error();

        log_warning(
            "Committed incomplete-remove recovery completed with Git cleanup diagnostics: %s%s%s",
            diagnostic->message,
            diagnostic->details[0] != '\0' ? "; " : "",
            diagnostic->details);
        clear_error();
        errno = 0;
    }
    if (alias_error_after_install) {
        result = -1;
        goto done;
    }
    clear_error();
    errno = 0;
    result = 1;

done:
    if (result < 0 && !settlement_completed &&
        !terminal_failure_accumulated) {
        error_context_t primary = *get_last_error();
        int primary_errno = errno ? errno : EIO;

        errno = primary_errno;
        (void)error_accumulator_add(
            &failures, "incomplete account removal recovery", &primary);
    }
    if (git_recovery &&
        git_retirement_recovery_end(&git_recovery) != 0) {
        if (settlement_completed) {
            const error_context_t *diagnostic = get_last_error();

            log_warning(
                "Committed incomplete-remove recovery retained Git cleanup diagnostics: %s%s%s",
                diagnostic->message,
                diagnostic->details[0] != '\0' ? "; " : "",
                diagnostic->details);
            clear_error();
            errno = 0;
        } else {
            (void)error_accumulator_add_last(
                &failures, "Git retirement recovery cleanup");
            result = -1;
        }
    }
    if (guard) config_retirement_guard_abandon(&guard);
    if (ledger_bytes) {
        secure_zero_memory(ledger_bytes, ledger_length);
        free(ledger_bytes);
    }
    if (revalidated_bytes) {
        secure_zero_memory(revalidated_bytes, revalidated_length);
        free(revalidated_bytes);
    }
    publication_ledger_clear(&ledger);
    publication_ledger_clear(&revalidated_ledger);
    secure_zero_memory(&recovery, sizeof(recovery));
    secure_zero_memory(records, sizeof(records));
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
    } else if (result == 0 && matching_absent_owner) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Incomplete removal recovery did not settle");
        result = -1;
    }
    return result;
}

/* Remove account with confirmation and cleanup. CLI callers prepare the
 * account/model deletion here and finalize its SSH alias only after main has
 * classified config_save_transactional() as pre- or post-install. */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    const account_t *retirement_targets[1];
    pending_retirement_t retirement = {0};
    error_accumulator_t retirement_errors;
    char account_name[MAX_NAME_LEN];
    char ssh_error[sizeof(g_last_error.message)] = "";
    char gpg_error[sizeof(g_last_error.message)] = "";
    uint32_t account_id;
    uint32_t current_id = 0;
    bool had_current;
    bool was_current;
    bool was_active;
    bool removed_alias_exclusive;
    bool bound_alias_exclusive;
    config_retirement_ssh_alias_obligation_t ssh_alias_obligation;
    int ssh_rc;
    int gpg_rc;
    int runtime_lock_fd;
    int result = -1;
    accounts_transaction_token_t token;
    bool guard_started = false;
    bool outer_retirement_prepared = false;
    bool outer_retirement_published = false;

    error_accumulator_init(&retirement_errors);
    memset(&ssh_alias_obligation, 0, sizeof(ssh_alias_obligation));
    if (accounts_transaction_begin(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                   &token) != 0) {
        return -1;
    }
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_remove");
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                          token);
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "remove an account") != 0) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                          token);
        return -1;
    }
    
    /* Find the account. AR-06 F50: destructive resolution (exact id/name/email
     * only) — never a substring, so `remove work` can't delete "work-old". */
    account = config_find_account_destructive(ctx, identifier);
    if (!account) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                          token);
        return -1; /* error already set with an explanatory message */
    }
    
    /* Show account details */
    printf("\nRemove Account\n");
    printf("─────────────────\n");
    printf("ID: %u\n", account->id);
    printf("Name: %s\n", account->name);
    printf("Email: %s\n", account->email);
    printf("Description: %s\n", account->description);
    
    /* Confirmation (--yes skips it for scripting). AR-10 L20: one shared
     * exact-'yes' rule for every destructive confirmation — this site used
     * to discard trim_whitespace's return, so leading-space handling
     * diverged from the sibling prompts. */
    if (!ctx->config.assume_yes) {
        int confirmed;

        confirmed = prompt_confirm_exact_yes_prompt(
            "\n[WARN]: This will permanently remove the account from configuration.\n"
            "Are you sure? (type 'yes' to confirm): ");
        if (confirmed < 0) {
            error_context_t confirmation_error;
            int confirmation_errno;

            if (confirmed == PROMPT_LINE_ERROR) {
                confirmation_errno = errno != 0 ? errno : EIO;
                errno = confirmation_errno;
                set_system_error(
                    ERR_FILE_IO,
                    "Failed to display or read removal confirmation");
                errno = confirmation_errno;
            } else {
                set_error(ERR_FILE_IO, "Failed to read confirmation");
                confirmation_errno = errno;
            }
            confirmation_error = *get_last_error();
            (void)accounts_transaction_finish(
                ctx, ACCOUNTS_TRANSACTION_REMOVE, token);
            g_last_error = confirmation_error;
            errno = confirmation_errno;
            return -1;
        }
        if (confirmed == 0) {
            printf("Account removal cancelled.\n");
            (void)accounts_transaction_finish(
                ctx, ACCOUNTS_TRANSACTION_REMOVE, token);
            return 0;
        }
    }

    /* Confirmation is the destructive commit point. From here through the
     * caller's durable configuration save, config unlock, and secure context
     * cleanup, termination signals must be deferred. Repeats remain deferred
     * as rollback-class work: an emergency exit between SSH/GPG teardown,
     * model deletion, alias removal, and persistence would leave a split
     * identity. CLI callers own the outer transaction tail; direct callers
     * release the guard at remove_done below. */
    if (accounts_transaction_rollback_begin(
            ctx, ACCOUNTS_TRANSACTION_REMOVE, token) != 0) {
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                          token);
        return -1;
    }
    if (signals_guard_begin() != 0) {
        (void)accounts_transaction_rollback_end(
            ctx, ACCOUNTS_TRANSACTION_REMOVE, token);
        (void)accounts_transaction_finish(ctx, ACCOUNTS_TRANSACTION_REMOVE,
                                          token);
        return -1;
    }
    guard_started = true;
    
    if (safe_strncpy(account_name, account->name, sizeof(account_name)) != 0) {
        goto remove_done;
    }
    /* Capture the managed SSH host alias before teardown. Its removal is a
     * post-persistence commit: a pre-install config failure must leave the
     * durable account and this route together. */
    char removed_alias[MAX_NAME_LEN];
    removed_alias[0] = '\0';
    safe_strncpy(removed_alias, account->ssh_host_alias, sizeof(removed_alias));
    removed_alias_exclusive = account_alias_exclusively_owned(
        ctx, account->id, removed_alias);
    bound_alias_exclusive =
        account_has_managed_alias(account) && removed_alias_exclusive;
    ssh_alias_obligation.known = true;
    if (ctx->config.defer_signal_cleanup && bound_alias_exclusive) {
        if (ssh_capture_host_alias_obligation(
                removed_alias, &ssh_alias_obligation) != 0) {
            goto remove_done;
        }
    }
    account_id = account->id;
    had_current = (ctx->current_account != NULL);
    if (had_current) {
        current_id = ctx->current_account->id;
    }
    was_current = (ctx->current_account == account);
    /* AR-06 F45: case-insensitive, matching the name-uniqueness invariant, so
     * removing the active account always clears active_account even when its
     * persisted spelling differs only in case. */
    was_active = (strcasecmp(ctx->config.active_account, account_name) == 0);

    /* CLI removal owns a later accounts.toml save, so prepare exact Git
     * before-images and publish the durable blocker before any runtime or Git
     * mutation.  Direct/library callers keep the historical one-call path.
     *
     * AR-12 L5 (known hold window): preparation acquires Git's own canonical
     * <config>.lock names for every recorded destination and holds them
     * across the SSH/GPG runtime teardown below, so a concurrent `git
     * config` write fails with git's could-not-lock error until finalize.
     * This is deliberate fail-before-mutate ordering: releasing and
     * re-acquiring at publish would let another writer change the sealed
     * generation mid-remove. Teardown is bounded (agent kill/gpgconf
     * timeouts), keeping the window short. */
    if (ctx->config.defer_signal_cleanup) {
        retirement_targets[0] = account;
        if (pending_retirement_prepare(
                ctx, CONFIG_RETIREMENT_REMOVE, retirement_targets, 1U,
                &ssh_alias_obligation,
                &retirement) != 0) {
            goto remove_done;
        }
        outer_retirement_prepared = true;
        /* Test-only stage zero lets the signal fixture swap in deterministic
         * runtime helpers after the production Git transaction has completed
         * its required default-runner preflight. */
        REMOVE_TEST_CHECKPOINT(0);
    }

    /* Tear down while the account name still exists as a retry handle. Both
     * managers are attempted; any failure retains the account/current/active
     * state so `remove` or targeted `reset` can be retried safely. */
    runtime_lock_fd = runtime_state_lock_acquire();
    if (runtime_lock_fd < 0) {
        goto remove_done;
    }
    ssh_rc = ssh_manager_reset(account_name);
    if (ssh_rc != 0) {
        snprintf(ssh_error, sizeof(ssh_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown SSH teardown error");
    }
    REMOVE_TEST_CHECKPOINT(1);
    gpg_rc = gpg_manager_reset(account_name);
    if (gpg_rc != 0) {
        snprintf(gpg_error, sizeof(gpg_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown GPG teardown error");
    }
    REMOVE_TEST_CHECKPOINT(2);
    runtime_state_lock_release(runtime_lock_fd);
    if (ssh_rc != 0 || gpg_rc != 0) {
        if (ssh_rc != 0) {
            fprintf(stderr, "gitswitch: SSH cleanup failed for '%s': %s\n",
                    account_name, ssh_error);
        }
        if (gpg_rc != 0) {
            fprintf(stderr, "gitswitch: GPG cleanup failed for '%s': %s\n",
                    account_name, gpg_error);
        }
        set_error(ERR_SYSTEM_CALL,
                  "Runtime cleanup failed for account '%s'; account retained for retry",
                  account_name);
        goto remove_done;
    }
    
    /* AR-10 M1: a prior switch to this account published durable credential
     * legs (core.sshCommand with IdentitiesOnly=yes, user.signingkey /
     * commit.gpgsign / gpg.format) that git_ops documents as authoritative
     * for every fetch/push and commit. Runtime teardown alone leaves them
     * selecting the retired identity: pushes keep authenticating with the
     * removed account's key and signing config outlives it. Scrub exactly
     * the legs still attributable to this account. A retirement failure is
     * not best-effort: deleting the account would turn its immutable
     * incarnation and PUBLISHED records into a non-authorizing tombstone,
     * destroying the supported retry handle while residue remains live. */
    if (ctx->config.defer_signal_cleanup) {
        size_t identity_cleared = 0U;

        if (pending_retirement_publish(
                &retirement, &identity_cleared) != 0) {
            error_context_t retirement_error = *get_last_error();
            int retirement_errno = errno;

            outer_retirement_prepared = false;
            (void)error_accumulator_add(
                &retirement_errors, "durable Git retirement",
                &retirement_error);
            fprintf(stderr,
                    "gitswitch: durable Git retirement failed for '%s'; "
                    "account metadata was retained for retry: %s\n",
                    account_name,
                    retirement_error.message[0] != '\0'
                        ? retirement_error.message
                        : "unknown Git retirement error");
            if (identity_cleared > 0U) {
                fprintf(stderr,
                        "gitswitch: retired %zu durable Git identity "
                        "setting(s) before the failure; cleanup remains "
                        "incomplete\n",
                        identity_cleared);
            }
            errno = retirement_errno;
            goto remove_done;
        }
        outer_retirement_published = true;
    } else {
        size_t identity_cleared = 0;
        if (accounts_retire_git_identity(ctx, account,
                                         &identity_cleared) != 0) {
            error_context_t retirement_error = *get_last_error();
            int retirement_errno = errno;

            (void)error_accumulator_add(
                &retirement_errors, "durable Git retirement",
                &retirement_error);
            fprintf(stderr,
                    "gitswitch: durable Git retirement failed for '%s'; "
                    "account metadata was retained for retry: %s\n",
                    account_name,
                    retirement_error.message[0] != '\0'
                        ? retirement_error.message
                        : "unknown Git retirement error");
            if (identity_cleared > 0) {
                fprintf(stderr,
                        "gitswitch: retired %zu durable Git identity "
                        "setting(s) before the failure; cleanup remains "
                        "incomplete\n",
                        identity_cleared);
            }
            errno = retirement_errno;
            goto remove_done;
        } else if (identity_cleared > 0) {
            printf("Cleared %zu durable Git identity setting(s) that "
                   "selected '%s'.\n",
                   identity_cleared, account_name);
        }
    }

    /* Only a complete teardown permits deleting the configuration handle.
     * AR-12 P1: snapshot the account first — an aborted (pre-install)
     * finalize restores it so the model cannot diverge from the retained
     * durable file. */
    g_pending_remove_snapshot = *account;
    if (config_remove_account_owned(ctx, account_id, token) != 0) {
        secure_zero_memory(&g_pending_remove_snapshot,
                           sizeof(g_pending_remove_snapshot));
        goto remove_done;
    }

    if (was_current || !had_current) {
        ctx->current_account = NULL;
    } else {
        /* config_remove_account compacts ctx->accounts. A pointer to a later
         * account therefore moves even when the removed account was inactive;
         * re-resolve by stable ID instead of leaving a stale array pointer. */
        ctx->current_account = NULL;
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id == current_id) {
                ctx->current_account = &ctx->accounts[i];
                break;
            }
        }
    }
    if (was_active) {
        ctx->config.active_account[0] = '\0';
    }
    REMOVE_TEST_CHECKPOINT(3);

    secure_zero_memory(&g_pending_remove, sizeof(g_pending_remove));
    g_pending_remove.active = true;
    g_pending_remove.token = token;
    g_pending_remove.ctx = ctx;
    g_pending_remove.alias_exclusive = removed_alias_exclusive;
    if (safe_strncpy(g_pending_remove.alias, removed_alias,
                     sizeof(g_pending_remove.alias)) != 0) {
        secure_zero_memory(&g_pending_remove, sizeof(g_pending_remove));
        /* AR-13 L30: the snapshot still holds the removed account's bytes on
         * this failure path (it is only cleared on the success path below), so
         * scrub it too rather than leaking stale account data in the static. */
        secure_zero_memory(&g_pending_remove_snapshot,
                           sizeof(g_pending_remove_snapshot));
        goto remove_done;
    }
    if (outer_retirement_prepared) {
        g_pending_remove.retirement = retirement;
        memset(&retirement, 0, sizeof(retirement));
        outer_retirement_prepared = false;
        outer_retirement_published = false;
    }
    g_pending_remove.removed_account = g_pending_remove_snapshot;
    g_pending_remove.removed_valid = true;
    g_pending_remove.removed_was_active = was_active;
    g_pending_remove.removed_was_current = was_current;
    secure_zero_memory(&g_pending_remove_snapshot,
                       sizeof(g_pending_remove_snapshot));
    (void)transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_REMOVE, token,
                                 ACCOUNTS_TRANSACTION_PREPARED);

    /* A direct library call has no outer save transaction and retains the
     * historical one-call alias cleanup. The CLI sets defer_signal_cleanup and
     * classifies the transactional persistence result with
     * accounts_remove_finalize(); the commit/abort wrappers are only the
     * proven-durable and proven-pre-install compatibility cases. */
    if (!ctx->config.defer_signal_cleanup &&
        accounts_remove_commit(ctx) != 0) {
        goto remove_done;
    }

    result = 0;

remove_done:
    if (outer_retirement_prepared) {
        error_context_t primary_error = *get_last_error();
        int primary_errno = errno ? errno : EIO;
        int retirement_rc;

        retirement_rc = outer_retirement_published
            ? pending_retirement_finalize(
                  ctx, &retirement,
                  ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED)
            : pending_retirement_cancel_unpublished(&retirement);
        if (retirement_rc != 0) {
            error_context_t cleanup_error = *get_last_error();
            int cleanup_errno = errno ? errno : EIO;

            if (!retirement_errors.active &&
                primary_error.code != ERR_SUCCESS) {
                errno = primary_errno;
                (void)error_accumulator_add(
                    &retirement_errors, "remove operation",
                    &primary_error);
            }
            errno = cleanup_errno;
            (void)error_accumulator_add(
                &retirement_errors,
                outer_retirement_published
                    ? "outer Git retirement rollback"
                    : "outer Git retirement cancellation",
                &cleanup_error);
        } else if (primary_error.code != ERR_SUCCESS) {
            g_last_error = primary_error;
            errno = primary_errno;
        }
        outer_retirement_prepared = false;
        outer_retirement_published = false;
    }
    if (!g_pending_remove.active &&
        g_transaction_owner.kind == ACCOUNTS_TRANSACTION_REMOVE &&
        g_transaction_owner.token == token) {
        if (ctx->config.defer_signal_cleanup &&
            g_transaction_owner.rollback_depth > 0) {
            signals_rollback_begin();
        }
        while (g_transaction_owner.rollback_depth > 0) {
            if (accounts_transaction_rollback_end(
                    ctx, ACCOUNTS_TRANSACTION_REMOVE, token) != 0) {
                if (retirement_errors.active) {
                    (void)error_accumulator_add_last(
                        &retirement_errors,
                        "remove transaction rollback release");
                }
                result = -1;
                break;
            }
        }
        if (g_transaction_owner.rollback_depth == 0 &&
            accounts_transaction_finish(
                ctx, ACCOUNTS_TRANSACTION_REMOVE, token) != 0) {
            if (retirement_errors.active) {
                (void)error_accumulator_add_last(
                    &retirement_errors,
                    "remove transaction ownership release");
            }
            result = -1;
        }
    }
    if (!ctx->config.defer_signal_cleanup && guard_started &&
        !signals_rollback_active()) {
        if (finish_signal_guard_checked(
                "Account removal finished, but restoring the caller's "
                "signal dispositions failed") != 0) {
            if (retirement_errors.active) {
                (void)error_accumulator_add_last(
                    &retirement_errors, "remove signal guard release");
            }
            result = -1;
        }
    }
    if (retirement_errors.active) {
        (void)error_accumulator_publish(&retirement_errors);
        result = -1;
    }
    return result;
}

/* List all configured accounts */
int accounts_list(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_list");
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx, "list accounts") != 0) {
        return -1;
    }
    
    if (ctx->account_count == 0) {
        printf("\n[INFO]: No accounts configured.\n");
        printf("Run 'gitswitch add' to create your first account.\n\n");
        return 0;
    }
    
    printf("\nConfigured Accounts (%zu total)\n", ctx->account_count);
    printf("════════════════════════════════════════════════════════════════\n");
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        bool is_current = (ctx->current_account == account);
        
        printf("%s [%u] %s\n", is_current ? "[CURRENT]" : "", account->id, account->name);
        printf("     Email: %s\n", account->email);
        printf("     Description: %s\n", account->description);
        printf("     Scope: %s\n", config_scope_to_string(account->preferred_scope));
        
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            printf("     SSH Key: %s\n", account->ssh_key_path);
            if (strlen(account->ssh_host_alias) > 0) {
                printf("         Host: %s\n", account->ssh_host_alias);
            }
        } else {
            printf("     SSH Key: Not configured\n");
        }
        
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("     GPG Key: %s %s\n", account->gpg_key_id,
                   account->gpg_signing_enabled ? "(signing enabled)" : "(signing disabled)");
        } else {
            printf("     GPG Key: Not configured\n");
        }
        
        if (i < ctx->account_count - 1) {
            printf("\n");
        }
    }
    
    printf("════════════════════════════════════════════════════════════════\n\n");
    
    if (ctx->current_account) {
        printf("Current: %s (%s)\n\n", ctx->current_account->name, ctx->current_account->description);
    } else {
        printf("No account currently active.\n\n");
    }
    
    return 0;
}

#define STATUS_RENDER_BYTE_LIMIT 512U
#define STATUS_RENDER_TRUNCATION "...[truncated]"

/* Git values, origins, and repository paths are attacker-controlled byte
 * strings. Keep diagnostics single-line and unambiguous by escaping every
 * non-ASCII/backslash byte, and cap consumption so one foreign value cannot
 * create unbounded terminal output. The maximum rendered payload is four
 * times STATUS_RENDER_BYTE_LIMIT plus the fixed truncation marker. */
static void print_terminal_safe(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    size_t consumed = 0;

    if (!cursor) return;
    for (; consumed < STATUS_RENDER_BYTE_LIMIT && cursor[consumed] != '\0';
         consumed++) {
        unsigned char byte = cursor[consumed];

        if (byte >= 0x20 && byte <= 0x7e && byte != '\\') {
            putchar((int)byte);
        } else if (byte == '\\') {
            fputs("\\\\", stdout);
        } else {
            printf("\\x%02X", (unsigned int)byte);
        }
    }
    if (consumed == STATUS_RENDER_BYTE_LIMIT && cursor[consumed] != '\0') {
        fputs(STATUS_RENDER_TRUNCATION, stdout);
    }
}

static void print_git_value_origin(const git_config_effective_value_t *value) {
    if (!value || !value->present) return;
    printf(" (%s scope", git_config_origin_scope_to_string(value->scope));
    if (value->origin[0] != '\0') {
        printf(", ");
        print_terminal_safe(value->origin);
    }
    printf(")");
}

static void print_git_effective_text(
    const git_config_effective_value_t *value) {
    if (!value || !value->present) {
        printf("[ABSENT]");
        return;
    }
    if (value->value_unknown) {
        printf("[ERROR]");
    } else if (value->value[0] == '\0') {
        printf("[EMPTY]");
    } else {
        print_terminal_safe(value->value);
    }
    print_git_value_origin(value);
}

static void print_git_effective_set_value(
    const git_config_effective_value_t *value) {
    if (!value || !value->present) {
        printf("[ABSENT]");
        return;
    }
    if (value->value_unknown) {
        printf("[ERROR]");
    } else {
        printf("[SET] ");
        if (value->value[0] == '\0') {
            printf("[EMPTY]");
        } else {
            print_terminal_safe(value->value);
        }
    }
    print_git_value_origin(value);
}

static bool git_status_snapshot_has_complete_identity(
    const git_status_snapshot_t *snapshot) {
    return snapshot && snapshot->user_name.present &&
           snapshot->user_email.present;
}

static bool git_status_snapshot_has_credential_residue(
    const git_status_snapshot_t *snapshot) {
    return snapshot &&
           (snapshot->ssh_command.present ||
            snapshot->user_signing_key.present ||
            snapshot->commit_gpgsign.present ||
            snapshot->gpg_format.present || snapshot->gpg_program.present ||
            snapshot->gpg_openpgp_program.present ||
            snapshot->gpg_x509_program.present ||
            snapshot->gpg_ssh_program.present);
}

static void print_git_status_snapshot_identity(
    const git_status_snapshot_t *snapshot, bool active_account) {
    fputs(active_account ? "  Current Name: " : "  Name: ", stdout);
    print_git_effective_text(snapshot ? &snapshot->user_name : NULL);
    fputs(active_account ? "\n  Current Email: " : "\n  Email: ", stdout);
    print_git_effective_text(snapshot ? &snapshot->user_email : NULL);
    printf("\n");
}

static void print_git_status_snapshot_credentials(
    const git_status_snapshot_t *snapshot) {
    printf("  Effective SSH Command: ");
    print_git_effective_set_value(snapshot ? &snapshot->ssh_command : NULL);
    printf("\n  GPG Signing Key: ");
    print_git_effective_text(snapshot ? &snapshot->user_signing_key : NULL);
    printf("\n  GPG Signing Enabled: ");
    if (!snapshot || !snapshot->commit_gpgsign.present) {
        printf("[ABSENT]");
    } else if (snapshot->commit_gpgsign_invalid ||
               snapshot->commit_gpgsign.value_unknown) {
        printf("[ERROR]");
        print_git_value_origin(&snapshot->commit_gpgsign);
    } else {
        fputs(snapshot->gpg_signing_enabled ? "[YES]" : "[NO]", stdout);
        print_git_value_origin(&snapshot->commit_gpgsign);
    }
    printf("\n  Effective GPG Format: ");
    if (snapshot && snapshot->gpg_format_invalid) {
        printf("[ERROR]");
        print_git_value_origin(&snapshot->gpg_format);
    } else {
        print_git_effective_set_value(snapshot ? &snapshot->gpg_format : NULL);
    }
    printf("\n  Effective OpenPGP Program: ");
    print_git_effective_set_value(
        snapshot ? &snapshot->gpg_openpgp_program : NULL);
    printf("\n  Effective Legacy GPG Program: ");
    print_git_effective_set_value(snapshot ? &snapshot->gpg_program : NULL);
    printf("\n  Effective X.509 GPG Program: ");
    print_git_effective_set_value(
        snapshot ? &snapshot->gpg_x509_program : NULL);
    printf("\n  Effective SSH Signing Program: ");
    print_git_effective_set_value(snapshot ? &snapshot->gpg_ssh_program : NULL);
    printf("\n");
}

static void print_git_status_captured_state(
    const git_status_snapshot_t *snapshot, bool active_account) {
    if (!snapshot) return;
    printf("  Captured Managed Git State:\n");
    print_git_status_snapshot_identity(snapshot, active_account);
    print_git_status_snapshot_credentials(snapshot);
}

/* Absence is a normal status state; an unreadable, malformed, or invalid Git
 * configuration is not. Keep the distinction visible so status cannot turn a
 * failed/truncated inspection into the reassuring appearance of no config. */
static int print_git_status_read_failure(void) {
    const error_context_t *error = get_last_error();
    if (error && error->code == ERR_GIT_CONFIG_NOT_FOUND) {
        printf("  Status: [NOT FOUND] No git configuration found\n");
        return 0;
    }
    printf("  Status: [ERROR] Unable to determine Git configuration");
    if (error && error->message[0] != '\0') {
        printf(": ");
        print_terminal_safe(error->message);
    }
    printf("\n");
    return -1;
}

static int account_incarnation_admits_publication(
    const gitswitch_ctx_t *ctx, const account_t *account) {
    publication_ledger_t ledger;
    int result = 0;

    if (!ctx || !account || !account->incarnation_persisted ||
        !account_incarnation_is_valid(account->incarnation)) {
        errno = ESTALE;
        set_error(
            ERR_CONFIG_INVALID,
            "Account '%s' has no persisted immutable incarnation; migrate the account document before switching",
            account && account->name[0] ? account->name : "?");
        return -1;
    }
    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(ctx->config.config_path, &ledger) != 0) {
        publication_ledger_clear(&ledger);
        return -1;
    }
    for (size_t i = 0; i < ledger.count; i++) {
        const publication_record_t *record = &ledger.records[i];
        if (record->account_id == account->id &&
            strcmp(record->account_incarnation,
                   account->incarnation) != 0) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Account ID %u is already bound to a different durable incarnation",
                account->id);
            result = -1;
            break;
        }
    }
    publication_ledger_clear(&ledger);
    return result;
}

typedef enum {
    ACCOUNT_PUBLICATION_LOOKUP_ERROR = -1,
    ACCOUNT_PUBLICATION_LOOKUP_ABSENT = 0,
    ACCOUNT_PUBLICATION_LOOKUP_FOUND = 1
} account_publication_lookup_result_t;

static account_publication_lookup_result_t load_account_publications(
    const gitswitch_ctx_t *ctx, const account_t *account,
    uint32_t required_capabilities, bool require_every_candidate,
    publication_ledger_t *ledger,
    size_t *publication_count) {
    size_t matches = 0U;

    if (publication_count) *publication_count = 0U;
    if (!ctx || !account || !ledger || !publication_count) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid durable-publication lookup arguments");
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    publication_ledger_clear(ledger);
    publication_ledger_init(ledger);
    if (config_load_publication_ledger(ctx->config.config_path, ledger) != 0) {
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    /* AR-12 H1: report a record-less account as ABSENT before demanding a
     * persisted incarnation, so never-switched and pre-ledger accounts are
     * distinguishable from provenance corruption. */
    {
        size_t id_records = 0U;

        for (size_t i = 0; i < ledger->count; i++) {
            if (ledger->records[i].account_id == account->id) id_records++;
        }
        if (id_records == 0U) {
            errno = ENOENT;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "No canonical publication provenance exists for account '%s'; switch it again before attributing durable Git credentials",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ABSENT;
        }
    }
    if (!account->incarnation_persisted ||
        !account_incarnation_is_valid(account->incarnation)) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Account '%s' has no persisted immutable incarnation",
                  account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    for (size_t i = 0; i < ledger->count; i++) {
        const publication_record_t *candidate = &ledger->records[i];

        if (candidate->account_id != account->id) continue;
        if (strcmp(candidate->account_incarnation,
                   account->incarnation) != 0) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Durable publication provenance for account '%s' belongs to a different incarnation",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
        }
        if (publication_record_validate(candidate) != 0 ||
            candidate->state != PUBLICATION_STATE_PUBLISHED) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Durable publication provenance for account '%s' is incomplete",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
        }
        if ((candidate->capabilities & required_capabilities) !=
            required_capabilities) {
            if (!require_every_candidate) continue;
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Durable publication provenance for account '%s' is incomplete",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
        }
        matches++;
    }
    if (matches == 0U) {
        errno = ENOENT;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "No canonical publication provenance exists for account '%s'; switch it again before attributing durable Git credentials",
            account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ABSENT;
    }
    *publication_count = matches;
    return ACCOUNT_PUBLICATION_LOOKUP_FOUND;
}

static int pending_retirement_publish_failure(
    pending_retirement_t *retirement, const char *label) {
    error_accumulator_t failures;
    error_context_t primary;
    git_retirement_failed_publish_outcome_t git_outcome =
        GIT_RETIREMENT_FAILED_PUBLISH_MUTATED_OR_UNCERTAIN;
    bool created;
    bool git_unchanged_clean = false;
    int primary_errno;

    if (!retirement) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid pending retirement failure state");
        return -1;
    }
    primary = *get_last_error();
    primary_errno = errno ? errno : EIO;
    created = retirement->guard &&
        config_retirement_guard_was_created(retirement->guard);
    error_accumulator_init(&failures);
    errno = primary_errno;
    (void)error_accumulator_add(&failures,
                                label ? label : "Git retirement",
                                &primary);
    /* A publish failure may have completed independent destinations or lost
     * acknowledgement after canonical mutation. Consume the failed Git
     * capability through the classifier that couples mutation and cleanup
     * proof. Only a fresh guard may be settled, and only when the classifier
     * proves that no mutation-capable backend was entered and every private
     * artifact was checked-cleaned. */
    if (retirement->git) {
        if (git_retirement_transaction_dispose_failed_publish(
                &retirement->git, &git_outcome) != 0) {
            (void)error_accumulator_add_last(
                &failures, "Git retirement artifact cleanup");
        } else if (
            git_outcome ==
            GIT_RETIREMENT_FAILED_PUBLISH_UNCHANGED_CLEAN) {
            git_unchanged_clean = true;
        }
    }
    if (created && git_unchanged_clean && retirement->guard &&
        config_retirement_guard_clear(&retirement->guard) != 0) {
        (void)error_accumulator_add_last(
            &failures, "failed-publication retirement guard clear");
    }
    if (retirement->guard) {
        config_retirement_guard_abandon(&retirement->guard);
    }
    secure_zero_memory(retirement, sizeof(*retirement));
    (void)error_accumulator_publish(&failures);
    return -1;
}

static int pending_retirement_require_creator(
    const pending_retirement_t *retirement, const char *operation) {
    if (!retirement || retirement->creator_pid != getpid()) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot %s a Git retirement capability inherited by a different process",
            operation ? operation : "use");
        return -1;
    }
    return 0;
}

/* Copy and validate the complete aligned retirement set before any canonical
 * Git mutation. Once the complete immutable owner/provenance set is known,
 * publish or adopt the durable guard before Git classifies any destination
 * as absent. Preparation then owns private stages and canonical locks. */
static int pending_retirement_prepare(
    const gitswitch_ctx_t *ctx, config_retirement_kind_t kind,
    const account_t *const targets[], size_t target_count,
    const config_retirement_ssh_alias_obligation_t *ssh_alias_obligation,
    pending_retirement_t *retirement) {
    publication_ledger_t ledger;
    const account_t *account_refs[PUBLICATION_LEDGER_MAX_RECORDS];
    const publication_record_t *publication_refs[
        PUBLICATION_LEDGER_MAX_RECORDS];
    size_t item_count = 0U;
    int result = -1;

    if (!ctx || !targets || target_count == 0U ||
        target_count > MAX_ACCOUNTS || !retirement || retirement->git ||
        retirement->guard || retirement->owner_count != 0U ||
        retirement->creator_pid != 0 ||
        retirement->phase != PENDING_RETIREMENT_NONE) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid outer Git retirement preparation");
        return -1;
    }
    retirement->creator_pid = getpid();
    publication_ledger_init(&ledger);
    if (config_load_publication_ledger(ctx->config.config_path, &ledger) != 0) {
        goto done;
    }
    for (size_t i = 0U; i < target_count; i++) {
        const account_t *account = targets[i];
        size_t id_records = 0U;
        size_t owner_slot;

        if (!account) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "NULL target in outer Git retirement preparation");
            goto done;
        }
        for (size_t j = 0U; j < i; j++) {
            if (targets[j] && targets[j]->id == account->id) {
                errno = EINVAL;
                set_error(ERR_INVALID_ARGS,
                          "Outer Git retirement contains duplicate account ID %u",
                          account->id);
                goto done;
            }
        }
        for (size_t j = 0U; j < ledger.count; j++) {
            if (ledger.records[j].account_id == account->id) id_records++;
        }
        /* A REMOVE alias obligation is independently durable. It needs the
         * exact owner in the marker even when that owner never published Git
         * state and therefore has no ledger record. */
        if (id_records == 0U &&
            !(kind == CONFIG_RETIREMENT_REMOVE &&
              ssh_alias_obligation && ssh_alias_obligation->known &&
              ssh_alias_obligation->present)) {
            continue;
        }
        if (!account->incarnation_persisted ||
            !account_incarnation_is_valid(account->incarnation)) {
            errno = ESTALE;
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Retirement account has no persisted immutable incarnation");
            goto done;
        }
        owner_slot = retirement->owner_count;
        retirement->owners[owner_slot].account_id = account->id;
        if (safe_strncpy(
                retirement->owners[owner_slot].account_incarnation,
                account->incarnation,
                sizeof(retirement->owners[owner_slot].account_incarnation)) !=
            0) {
            goto done;
        }
        retirement->owner_count++;
        for (size_t j = 0U; j < ledger.count; j++) {
            const publication_record_t *publication = &ledger.records[j];

            if (publication->account_id != account->id) continue;
            if (strcmp(publication->account_incarnation,
                       account->incarnation) != 0) {
                errno = ESTALE;
                set_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Durable publication provenance for account '%s' belongs to a different incarnation",
                    account->name);
                goto done;
            }
            if (publication_record_validate(publication) != 0 ||
                publication->state != PUBLICATION_STATE_PUBLISHED ||
                (publication->capabilities &
                 (PUBLICATION_CAP_DESTINATION |
                  PUBLICATION_CAP_POST_GENERATION)) !=
                    (PUBLICATION_CAP_DESTINATION |
                     PUBLICATION_CAP_POST_GENERATION)) {
                errno = ESTALE;
                set_error(
                    ERR_GIT_CONFIG_FAILED,
                    "Durable publication provenance for account '%s' is incomplete",
                    account->name);
                goto done;
            }
            if (item_count == PUBLICATION_LEDGER_MAX_RECORDS) {
                errno = EOVERFLOW;
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Outer Git retirement publication set is too large");
                goto done;
            }
            account_refs[item_count] = account;
            publication_refs[item_count] = publication;
            item_count++;
        }
    }
    if (item_count == 0U) {
        retirement->git_vacuous = true;
        if (!(kind == CONFIG_RETIREMENT_REMOVE &&
              ssh_alias_obligation && ssh_alias_obligation->known &&
              ssh_alias_obligation->present)) {
            /* No canonical Git destination and no SSH namespace obligation. */
            retirement->truly_vacuous = true;
            retirement->phase = PENDING_RETIREMENT_PREPARED;
            result = 0;
            goto done;
        }
    }
    if (kind == CONFIG_RETIREMENT_REMOVE && ssh_alias_obligation) {
        retirement->ssh_alias_obligation = *ssh_alias_obligation;
        retirement->has_ssh_alias_obligation = true;
    }
    if ((kind == CONFIG_RETIREMENT_REMOVE && ssh_alias_obligation
             ? config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
                   ctx->config.config_path, kind, retirement->owners,
                   retirement->owner_count, ssh_alias_obligation,
                   &retirement->guard)
             : config_retirement_guard_install_or_adopt(
                   ctx->config.config_path, kind, retirement->owners,
                   retirement->owner_count, &retirement->guard)) != 0) {
        goto done;
    }
    retirement->guarded = true;
    if (item_count != 0U) {
        if (git_retirement_transaction_prepare(
                account_refs, publication_refs, item_count,
                &retirement->git) != 0) {
            goto done;
        }
    }
    retirement->phase = PENDING_RETIREMENT_PREPARED;
    result = 0;

done:
    if (result != 0) {
        error_accumulator_t failures;
        error_context_t primary = *get_last_error();
        int primary_errno = errno;
        bool created = retirement->guard &&
            config_retirement_guard_was_created(retirement->guard);
        bool git_clean = true;

        publication_ledger_clear(&ledger);
        error_accumulator_init(&failures);
        errno = primary_errno;
        (void)error_accumulator_add(
            &failures, "outer Git retirement preparation", &primary);
        /* Preparation can fail after publishing or adopting the durable
         * blocker and after partially allocating Git transaction artifacts.
         * Dispose the latter with its checked owner API before deciding
         * whether a marker created by this invocation is safe to settle.
         * A NULL transaction is a proven-clean Git preparation failure. */
        if (retirement->git &&
            git_retirement_transaction_commit(&retirement->git) != 0) {
            (void)error_accumulator_add_last(
                &failures, "Git retirement preparation cleanup");
            git_clean = false;
        }
        /* Never consume an adopted recovery authority. A fresh marker is
         * cleared only after Git cleanup is proven clean; clear() failures
         * retain a blocking marker/stage and are aggregated behind the
         * original preparation diagnostic. */
        if (created && git_clean && retirement->guard &&
            config_retirement_guard_clear(&retirement->guard) != 0) {
            (void)error_accumulator_add_last(
                &failures, "retirement preparation guard clear");
        }
        if (retirement->guard) {
            config_retirement_guard_abandon(&retirement->guard);
        }
        secure_zero_memory(retirement, sizeof(*retirement));
        (void)error_accumulator_publish(&failures);
    } else {
        publication_ledger_clear(&ledger);
    }
    return result;
}

static int pending_retirement_cancel_unpublished(
    pending_retirement_t *retirement) {
    error_accumulator_t failures;
    bool created;
    bool git_clean = true;

    if (pending_retirement_require_creator(
            retirement, "cancel") != 0) {
        return -1;
    }
    if (
        (!retirement->truly_vacuous &&
         (!retirement->guarded || !retirement->guard ||
          (!retirement->git_vacuous && !retirement->git)))) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid unpublished Git retirement cancellation");
        return -1;
    }
    if (retirement->phase != PENDING_RETIREMENT_PREPARED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Only a prepared Git retirement can be cancelled");
        return -1;
    }
    if (retirement->truly_vacuous) {
        secure_zero_memory(retirement, sizeof(*retirement));
        return 0;
    }
    error_accumulator_init(&failures);
    created = config_retirement_guard_was_created(retirement->guard);
    if (retirement->git &&
        git_retirement_transaction_commit(&retirement->git) != 0) {
        (void)error_accumulator_add_last(
            &failures, "unpublished Git retirement cleanup");
        git_clean = false;
    }
    if (created && git_clean) {
        if (config_retirement_guard_clear(&retirement->guard) != 0) {
            (void)error_accumulator_add_last(
                &failures, "unpublished retirement guard clear");
        }
    }
    if (retirement->guard) {
        config_retirement_guard_abandon(&retirement->guard);
    }
    secure_zero_memory(retirement, sizeof(*retirement));
    if (failures.active) {
        (void)error_accumulator_publish(&failures);
        return -1;
    }
    return 0;
}

static int pending_retirement_publish(pending_retirement_t *retirement,
                                      size_t *cleared) {
    if (cleared) *cleared = 0U;
    if (pending_retirement_require_creator(
            retirement, "publish") != 0) {
        return -1;
    }
    if (
        (!retirement->truly_vacuous &&
         (!retirement->guarded || !retirement->guard ||
          (!retirement->git_vacuous && !retirement->git)))) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid prepared outer Git retirement");
        return -1;
    }
    if (retirement->phase != PENDING_RETIREMENT_PREPARED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Only a prepared Git retirement can be published");
        return -1;
    }
    if (retirement->truly_vacuous) {
        retirement->phase = PENDING_RETIREMENT_PUBLISHED;
        return 0;
    }
    if (retirement->git &&
        git_retirement_transaction_publish(retirement->git, cleared) != 0) {
        return pending_retirement_publish_failure(
            retirement, "Git retirement publication");
    }
    retirement->phase = PENDING_RETIREMENT_PUBLISHED;
    return 0;
}

enum {
    RETIREMENT_LEDGER_RESEAL_ATTEMPTS = 3
};

typedef struct {
    git_retirement_transaction_t **transaction;
    config_retirement_destination_t *sealed;
    config_retirement_destination_t *observed;
    size_t destination_count;
    bool reseal_required;
} pending_retirement_terminal_barrier_t;

/* Re-prove the complete restored destination set without publishing a partial
 * successor. The terminal rollback query accepts only exact bytes (plus a
 * ctime-only successor) or continued exact absence. If any present successor
 * appears, copy the complete observed set for the next ledger seal and keep
 * the guard blocked. */
static int pending_retirement_revalidate_terminal_destinations(
    pending_retirement_terminal_barrier_t *barrier) {
    bool changed = false;

    if (!barrier || !barrier->transaction ||
        !*barrier->transaction ||
        (barrier->destination_count != 0U &&
         (!barrier->sealed || !barrier->observed))) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid terminal Git retirement barrier");
        return -1;
    }
    barrier->reseal_required = false;
    if (barrier->observed && barrier->destination_count != 0U) {
        memset(barrier->observed, 0,
               barrier->destination_count *
                   sizeof(*barrier->observed));
    }
    for (size_t i = 0U; i < barrier->destination_count; i++) {
        if (git_retirement_transaction_rollback_destination(
                *barrier->transaction, i,
                barrier->observed[i].config_path,
                sizeof(barrier->observed[i].config_path),
                &barrier->observed[i].post_config) != 0) {
            return -1;
        }
        if (strcmp(barrier->observed[i].config_path,
                   barrier->sealed[i].config_path) != 0) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Git retirement destination order changed during terminal ledger proof");
            return -1;
        }
        if (!publication_identity_equal(
                &barrier->observed[i].post_config,
                &barrier->sealed[i].post_config)) {
            changed = true;
        }
    }
    if (changed) {
        for (size_t i = 0U; i < barrier->destination_count; i++) {
            barrier->sealed[i].post_config =
                barrier->observed[i].post_config;
        }
        barrier->reseal_required = true;
        errno = EAGAIN;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Restored Git generation advanced during terminal publication proof");
        return -1;
    }
    clear_error();
    errno = 0;
    return 0;
}

static int pending_retirement_terminal_commit_barrier(void *opaque) {
    return pending_retirement_revalidate_terminal_destinations(
        opaque);
}

static int pending_retirement_terminal_durable_barrier(void *opaque) {
    git_retirement_transaction_t **transaction = opaque;

    if (!transaction || !*transaction) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid durable Git retirement barrier");
        return -1;
    }
    return git_retirement_transaction_verify_terminal_commit(
        *transaction);
}

static int pending_retirement_finalize(
    gitswitch_ctx_t *ctx, pending_retirement_t *retirement,
    accounts_retirement_save_outcome_t outcome) {
    config_retirement_destination_t *destinations = NULL;
    config_retirement_destination_t *observed_destinations = NULL;
    pending_retirement_terminal_barrier_t terminal_barrier;
    error_accumulator_t failures;
    bool created;
    bool refresh_installed = false;
    bool guard_commit_completed = false;
    bool settlement_ok = true;
    size_t destination_count = 0U;

    if (pending_retirement_require_creator(
            retirement, "finalize") != 0) {
        return -1;
    }
    if (!ctx ||
        (!retirement->truly_vacuous &&
         (!retirement->guarded || !retirement->guard ||
          (!retirement->git_vacuous && !retirement->git) ||
          retirement->owner_count == 0U)) ||
        retirement->owner_count > MAX_ACCOUNTS ||
        outcome < ACCOUNTS_RETIREMENT_SAVE_DURABLE ||
        outcome > ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid outer Git retirement finalization");
        return -1;
    }
    if (retirement->phase != PENDING_RETIREMENT_PUBLISHED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Only a published Git retirement can be finalized");
        return -1;
    }
    if (retirement->truly_vacuous) {
        /* No destination was touched and no guard exists; every save
         * outcome settles to the same empty state. */
        secure_zero_memory(retirement, sizeof(*retirement));
        return 0;
    }
    error_accumulator_init(&failures);
    memset(&terminal_barrier, 0, sizeof(terminal_barrier));
    created = config_retirement_guard_was_created(retirement->guard);

    if (outcome == ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED &&
        retirement->git) {
        if (git_retirement_transaction_abort(retirement->git) != 0) {
            (void)error_accumulator_add_last(
                &failures, "exact Git retirement rollback");
            settlement_ok = false;
        } else {
            destination_count =
                git_retirement_transaction_rollback_destination_count(
                    retirement->git);
            if (destination_count > PUBLICATION_LEDGER_MAX_RECORDS) {
                errno = EOVERFLOW;
                set_error(ERR_GIT_CONFIG_FAILED,
                          "Restored Git retirement destination set is too large");
                (void)error_accumulator_add_last(
                    &failures, "Git rollback destination enumeration");
                settlement_ok = false;
            }
            if (settlement_ok && destination_count != 0U) {
                destinations = calloc(destination_count,
                                      sizeof(*destinations));
                observed_destinations =
                    calloc(destination_count,
                           sizeof(*observed_destinations));
                if (!destinations || !observed_destinations) {
                    set_error(
                        ERR_MEMORY_ALLOCATION,
                        "Cannot allocate restored Git destination witnesses");
                    (void)error_accumulator_add_last(
                        &failures,
                        "Git rollback destination allocation");
                    settlement_ok = false;
                }
            }
            for (size_t i = 0U; settlement_ok &&
                                i < destination_count; i++) {
                if (git_retirement_transaction_rollback_destination(
                        retirement->git, i, destinations[i].config_path,
                        sizeof(destinations[i].config_path),
                        &destinations[i].post_config) != 0) {
                    (void)error_accumulator_add_last(
                        &failures, "Git rollback destination witness");
                    settlement_ok = false;
                }
            }
            /* Flush the completion stage while ordinary Git locks still
             * exclude cooperating writers. Its directory sync may materialize
             * delayed Git metadata, so it must precede terminal stabilization
             * and the first ledger seal. */
            if (settlement_ok && created &&
                config_retirement_guard_prepare_clear(
                    retirement->guard) != 0) {
                (void)error_accumulator_add_last(
                    &failures,
                    "retirement completion-stage preparation");
                settlement_ok = false;
            }

            /* Settle every transaction-owned Git namespace only after that
             * outer flush. From this point commit() is release-only, while
             * the retained rollback witnesses remain available to the
             * guard's observation-only terminal proof. */
            if (settlement_ok &&
                git_retirement_transaction_prepare_terminal_rollback(
                    retirement->git) != 0) {
                (void)error_accumulator_add_last(
                    &failures,
                    "Git rollback terminal namespace settlement");
                settlement_ok = false;
            }
            terminal_barrier.transaction = &retirement->git;
            terminal_barrier.sealed = destinations;
            terminal_barrier.observed = observed_destinations;
            terminal_barrier.destination_count = destination_count;

            if (settlement_ok && created) {
                bool completed = false;

                for (unsigned attempt = 0U;
                     attempt <
                         RETIREMENT_LEDGER_RESEAL_ATTEMPTS;
                     attempt++) {
                    if (destination_count != 0U &&
                        config_refresh_retirement_publications_transactional(
                            ctx, ctx->config.config_path,
                            retirement->owners,
                            retirement->owner_count, destinations,
                            destination_count, &refresh_installed) != 0) {
                        (void)error_accumulator_add_last(
                            &failures,
                            refresh_installed
                                ? "installed retirement-ledger reconciliation"
                                : "retirement-ledger reconciliation");
                        settlement_ok = false;
                        break;
                    }
                    terminal_barrier.reseal_required = false;
                    if (config_retirement_guard_clear_with_barrier(
                            &retirement->guard,
                            pending_retirement_terminal_commit_barrier,
                            &terminal_barrier) == 0) {
                        if (git_retirement_transaction_finish_terminal_rollback(
                                &retirement->git) != 0) {
                            (void)error_accumulator_add_last(
                                &failures,
                                "terminal Git rollback capability release");
                            settlement_ok = false;
                        } else {
                            completed = true;
                        }
                        break;
                    }
                    if (errno == EAGAIN &&
                        terminal_barrier.reseal_required) {
                        if (attempt + 1U <
                            RETIREMENT_LEDGER_RESEAL_ATTEMPTS) {
                            clear_error();
                            errno = 0;
                            continue;
                        }
                        errno = EAGAIN;
                        set_error(
                            ERR_GIT_CONFIG_FAILED,
                            "Restored Git generation did not stabilize across terminal publication-ledger reconciliation");
                        (void)error_accumulator_add_last(
                            &failures,
                            "retirement-ledger generation stabilization");
                    } else {
                        (void)error_accumulator_add_last(
                            &failures,
                            "rolled-back retirement guard terminal commit");
                    }
                    settlement_ok = false;
                    break;
                }
                if (settlement_ok && !completed) {
                    errno = EAGAIN;
                    set_error(
                        ERR_GIT_CONFIG_FAILED,
                        "Retirement guard terminal commit did not complete");
                    (void)error_accumulator_add_last(
                        &failures,
                        "rolled-back retirement guard terminal commit");
                    settlement_ok = false;
                }
            } else if (settlement_ok && !created &&
                       destination_count != 0U) {
                bool stable = false;

                for (unsigned attempt = 0U;
                     attempt <
                         RETIREMENT_LEDGER_RESEAL_ATTEMPTS;
                     attempt++) {
                    if (config_refresh_retirement_publications_transactional(
                            ctx, ctx->config.config_path,
                            retirement->owners,
                            retirement->owner_count, destinations,
                            destination_count, &refresh_installed) != 0) {
                        (void)error_accumulator_add_last(
                            &failures,
                            refresh_installed
                                ? "installed retirement-ledger reconciliation"
                                : "retirement-ledger reconciliation");
                        settlement_ok = false;
                        break;
                    }
                    terminal_barrier.reseal_required = false;
                    if (pending_retirement_revalidate_terminal_destinations(
                            &terminal_barrier) == 0) {
                        stable = true;
                        break;
                    }
                    if (errno == EAGAIN &&
                        terminal_barrier.reseal_required &&
                        attempt + 1U <
                            RETIREMENT_LEDGER_RESEAL_ATTEMPTS) {
                        clear_error();
                        errno = 0;
                        continue;
                    }
                    if (errno == EAGAIN &&
                        terminal_barrier.reseal_required) {
                        errno = EAGAIN;
                        set_error(
                            ERR_GIT_CONFIG_FAILED,
                            "Restored Git generation did not stabilize across publication-ledger reconciliation");
                    }
                    (void)error_accumulator_add_last(
                        &failures,
                        "retirement-ledger generation stabilization");
                    settlement_ok = false;
                    break;
                }
                if (settlement_ok && !stable) {
                    errno = EAGAIN;
                    set_error(
                        ERR_GIT_CONFIG_FAILED,
                        "Restored Git generation did not stabilize across publication-ledger reconciliation");
                    (void)error_accumulator_add_last(
                        &failures,
                        "retirement-ledger generation stabilization");
                    settlement_ok = false;
                }
            }
        }
    }

    if (outcome == ACCOUNTS_RETIREMENT_SAVE_DURABLE &&
        settlement_ok) {
        if (config_retirement_guard_prepare_clear(
                retirement->guard) != 0) {
            (void)error_accumulator_add_last(
                &failures,
                "durable retirement completion-stage preparation");
            settlement_ok = false;
        }
        if (settlement_ok && retirement->git &&
            git_retirement_transaction_prepare_terminal_commit(
                retirement->git) != 0) {
            (void)error_accumulator_add_last(
                &failures,
                "Git retirement terminal commit preparation");
            settlement_ok = false;
        }
        if (settlement_ok &&
            config_retirement_guard_clear_with_barrier(
                &retirement->guard,
                retirement->git
                    ? pending_retirement_terminal_durable_barrier
                    : NULL,
                retirement->git ? &retirement->git : NULL) != 0) {
            (void)error_accumulator_add_last(
                &failures, "durable retirement guard terminal commit");
            settlement_ok = false;
        }
        if (settlement_ok) guard_commit_completed = true;
        if (settlement_ok && retirement->git &&
            git_retirement_transaction_finish_terminal_commit(
                &retirement->git) != 0) {
            const error_context_t *diagnostic = get_last_error();

            log_warning(
                "Committed account retirement completed with Git cleanup diagnostics: %s%s%s",
                diagnostic->message,
                diagnostic->details[0] != '\0' ? "; " : "",
                diagnostic->details);
            clear_error();
            errno = 0;
        }
    }

    /* Terminally prepared outcomes are release-only here: their exact Git
     * proof either ran inside the successful guard barrier or the blocker is
     * being retained after a failed settlement. Other outcomes perform their
     * ordinary checked transaction cleanup. */
    if (retirement->git &&
        git_retirement_transaction_commit(&retirement->git) != 0) {
        if (guard_commit_completed) {
            const error_context_t *diagnostic = get_last_error();

            log_warning(
                "Committed account retirement retained Git cleanup diagnostics: %s%s%s",
                diagnostic->message,
                diagnostic->details[0] != '\0' ? "; " : "",
                diagnostic->details);
            clear_error();
            errno = 0;
        } else {
            (void)error_accumulator_add_last(
                &failures, "Git retirement transaction cleanup");
            settlement_ok = false;
        }
    }

    if (outcome ==
                   ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED &&
               settlement_ok && created && retirement->guard) {
        if (config_retirement_guard_clear(&retirement->guard) != 0) {
            (void)error_accumulator_add_last(
                &failures, "rolled-back retirement guard clear");
            settlement_ok = false;
        }
    }
    /* Uncertain saves, failed rollback/reconciliation, and a marker adopted
     * from an older incomplete operation all deliberately persist on disk. */
    if (retirement->guard) {
        config_retirement_guard_abandon(&retirement->guard);
    }
    if (destinations) {
        secure_zero_memory(
            destinations, destination_count * sizeof(*destinations));
        free(destinations);
    }
    if (observed_destinations) {
        secure_zero_memory(
            observed_destinations,
            destination_count * sizeof(*observed_destinations));
        free(observed_destinations);
    }
    secure_zero_memory(retirement, sizeof(*retirement));
    if (!settlement_ok) {
        if (failures.active) (void)error_accumulator_publish(&failures);
        return -1;
    }
    return 0;
}

int accounts_retire_git_identity(const gitswitch_ctx_t *ctx,
                                 const account_t *account,
                                 size_t *cleared) {
    publication_ledger_t ledger;
    account_publication_lookup_result_t lookup_result;
    const publication_record_t *publications[
        PUBLICATION_LEDGER_MAX_RECORDS];
    size_t publication_count = 0U;
    size_t collected = 0U;
    int result;

    if (accounts_process_epoch_gate(false) != 0) {
        if (cleared) *cleared = 0;
        return -1;
    }
    if (cleared) *cleared = 0;
    if (!ctx || !account) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid durable Git retirement arguments");
        return -1;
    }
    publication_ledger_init(&ledger);
    lookup_result = load_account_publications(
        ctx, account,
        PUBLICATION_CAP_DESTINATION | PUBLICATION_CAP_POST_GENERATION,
        true, &ledger, &publication_count);
    if (lookup_result == ACCOUNT_PUBLICATION_LOOKUP_ABSENT) {
        /* AR-12 H1: nothing was ever durably published for this account, so
         * there is nothing to retire — vacuous success, not a demand to
         * switch first. */
        publication_ledger_clear(&ledger);
        clear_error();
        return 0;
    }
    if (lookup_result != ACCOUNT_PUBLICATION_LOOKUP_FOUND) {
        publication_ledger_clear(&ledger);
        return -1;
    }
    for (size_t i = 0; i < ledger.count; i++) {
        const publication_record_t *publication = &ledger.records[i];

        if (publication->account_id != account->id) continue;
        publications[collected++] = publication;
    }
    if (collected != publication_count) {
        publication_ledger_clear(&ledger);
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Durable publication enumeration changed unexpectedly");
        return -1;
    }
    result = git_retire_account_identity_publications(
        account, publications, collected, cleared);
    publication_ledger_clear(&ledger);
    return result;
}

int accounts_reset_retirement_prepare(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    const account_t *target) {
    const account_t *targets[MAX_ACCOUNTS];
    size_t target_count;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || token == 0 || g_pending_reset.active ||
        transaction_require(ctx, ACCOUNTS_TRANSACTION_RESET, token,
                            "prepare Git retirement for") != 0) {
        if (ctx && token != 0 && g_pending_reset.active) {
            errno = EBUSY;
            set_error(ERR_SYSTEM_CALL,
                      "A reset Git retirement is already pending");
        }
        return -1;
    }
    if (target) {
        bool found = false;

        for (size_t i = 0U; i < ctx->account_count; i++) {
            if (&ctx->accounts[i] == target) {
                found = true;
                break;
            }
        }
        if (!found) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "Reset retirement target is not owned by the context");
            return -1;
        }
        targets[0] = target;
        target_count = 1U;
    } else {
        target_count = ctx->account_count;
        if (target_count == 0U) return 0;
        for (size_t i = 0U; i < target_count; i++) {
            targets[i] = &ctx->accounts[i];
        }
    }
    memset(&g_pending_reset, 0, sizeof(g_pending_reset));
    if (pending_retirement_prepare(
            ctx, CONFIG_RETIREMENT_RESET, targets, target_count,
            NULL,
            &g_pending_reset.retirement) != 0) {
        memset(&g_pending_reset, 0, sizeof(g_pending_reset));
        return -1;
    }
    g_pending_reset.active = true;
    g_pending_reset.token = token;
    g_pending_reset.ctx = ctx;
    if (transaction_mark_phase(ctx, ACCOUNTS_TRANSACTION_RESET, token,
                               ACCOUNTS_TRANSACTION_PREPARED) != 0) {
        error_context_t phase_error = *get_last_error();
        int phase_errno = errno ? errno : EIO;

        (void)pending_retirement_cancel_unpublished(
            &g_pending_reset.retirement);
        memset(&g_pending_reset, 0, sizeof(g_pending_reset));
        g_last_error = phase_error;
        errno = phase_errno;
        return -1;
    }
    return 0;
}

int accounts_reset_retirement_publish(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    size_t *cleared) {
    if (accounts_process_epoch_gate(true) != 0) {
        if (cleared) *cleared = 0U;
        return -1;
    }
    if (cleared) *cleared = 0U;
    if (!ctx || token == 0 || !g_pending_reset.active ||
        g_pending_reset.ctx != ctx || g_pending_reset.token != token ||
        transaction_require(ctx, ACCOUNTS_TRANSACTION_RESET, token,
                            "publish Git retirement for") != 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "No prepared reset Git retirement to publish");
        return -1;
    }
    if (g_pending_reset.retirement.phase !=
        PENDING_RETIREMENT_PREPARED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Reset Git retirement is not prepared for publication");
        return -1;
    }
    if (pending_retirement_publish(
            &g_pending_reset.retirement, cleared) != 0) {
        memset(&g_pending_reset, 0, sizeof(g_pending_reset));
        return -1;
    }
    return 0;
}

int accounts_reset_retirement_cancel(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token) {
    int result;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (!ctx || token == 0 || !g_pending_reset.active ||
        g_pending_reset.ctx != ctx || g_pending_reset.token != token ||
        transaction_require(ctx, ACCOUNTS_TRANSACTION_RESET, token,
                            "cancel Git retirement for") != 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "No prepared reset Git retirement to cancel");
        return -1;
    }
    if (g_pending_reset.retirement.phase !=
        PENDING_RETIREMENT_PREPARED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Published reset Git retirement cannot be cancelled");
        return -1;
    }
    result = pending_retirement_cancel_unpublished(
        &g_pending_reset.retirement);
    memset(&g_pending_reset, 0, sizeof(g_pending_reset));
    return result;
}

int accounts_reset_retirement_finalize(
    gitswitch_ctx_t *ctx, accounts_transaction_token_t token,
    accounts_retirement_save_outcome_t outcome) {
    int result;

    if (accounts_process_epoch_gate(true) != 0) return -1;
    if (outcome < ACCOUNTS_RETIREMENT_SAVE_DURABLE ||
        outcome > ACCOUNTS_RETIREMENT_SAVE_PREINSTALL_FAILED) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid reset Git retirement save outcome");
        return -1;
    }
    if (!ctx || token == 0 || !g_pending_reset.active ||
        g_pending_reset.ctx != ctx || g_pending_reset.token != token ||
        transaction_require(ctx, ACCOUNTS_TRANSACTION_RESET, token,
                            "finalize Git retirement for") != 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "No published reset Git retirement to finalize");
        return -1;
    }
    if (g_pending_reset.retirement.phase !=
        PENDING_RETIREMENT_PUBLISHED) {
        errno = EBUSY;
        set_error(ERR_SYSTEM_CALL,
                  "Reset Git retirement has not been published");
        return -1;
    }
    result = pending_retirement_finalize(
        ctx, &g_pending_reset.retirement, outcome);
    memset(&g_pending_reset, 0, sizeof(g_pending_reset));
    return result;
}

static git_signing_publication_result_t status_signing_key_matches(
    const account_t *account, const publication_record_t *publication,
    const git_current_config_t *git_config,
    const git_status_snapshot_t *git_status) {
    if (!account || !git_config || !git_status)
        return GIT_SIGNING_PUBLICATION_MISMATCH;
    if (!account->gpg_enabled || account->gpg_key_id[0] == '\0') {
        return !git_status->user_signing_key.present
                   ? GIT_SIGNING_PUBLICATION_MATCH
                   : GIT_SIGNING_PUBLICATION_MISMATCH;
    }
    return git_signing_key_matches_publication(account, publication,
                                               git_config);
}

static bool account_publication_scope_matches_origin(
    publication_scope_t publication_scope,
    git_config_origin_scope_t origin_scope) {
    return (publication_scope == PUBLICATION_SCOPE_GLOBAL &&
            origin_scope == GIT_CONFIG_ORIGIN_GLOBAL) ||
           (publication_scope == PUBLICATION_SCOPE_LOCAL &&
            origin_scope == GIT_CONFIG_ORIGIN_LOCAL) ||
           (publication_scope == PUBLICATION_SCOPE_WORKTREE &&
            origin_scope == GIT_CONFIG_ORIGIN_WORKTREE);
}

static bool account_publication_origin_matches(
    const publication_record_t *publication, const char *origin) {
    static const char file_prefix[] = "file:";
    char repository_relative[MAX_PATH_LEN];
    char canonical[MAX_PATH_LEN];
    const char *candidate;
    int written;

    if (!publication || !origin ||
        strncmp(origin, file_prefix, sizeof(file_prefix) - 1U) != 0) {
        return false;
    }
    candidate = origin + sizeof(file_prefix) - 1U;
    if (strcmp(candidate, publication->config_path) == 0) return true;
    if (candidate[0] != '/') {
        if (publication->scope == PUBLICATION_SCOPE_GLOBAL ||
            publication->repository_path[0] != '/') {
            return false;
        }
        written = snprintf(repository_relative,
                           sizeof(repository_relative), "%s/%s",
                           publication->repository_path, candidate);
        if (written < 0 || (size_t)written >= sizeof(repository_relative)) {
            return false;
        }
        candidate = repository_relative;
    }
    return realpath(candidate, canonical) != NULL &&
           strcmp(canonical, publication->config_path) == 0;
}

static account_publication_lookup_result_t
select_current_account_publication(
    const account_t *account, const publication_ledger_t *ledger,
    const git_current_config_t *current,
    uint32_t required_capabilities,
    publication_record_t *publication) {
    char reported_repository[MAX_PATH_LEN] = "";
    char current_repository[MAX_PATH_LEN] = "";
    const publication_record_t *generation_records[
        PUBLICATION_LEDGER_MAX_RECORDS];
    const publication_record_t *membership = NULL;
    const publication_record_t *live_generation = NULL;
    const publication_record_t *live_publication = NULL;
    size_t generation_count = 0U;
    size_t origin_matches = 0U;
    bool ignored_probe_failure = false;
    bool repository_required;

    if (!account || !ledger || !current || !publication) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid current publication selection arguments");
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    for (size_t i = 0; i < ledger->count; i++) {
        const publication_record_t *candidate = &ledger->records[i];

        if (candidate->account_id == account->id &&
            strcmp(candidate->account_incarnation,
                   account->incarnation) == 0 &&
            candidate->state == PUBLICATION_STATE_PUBLISHED) {
            generation_records[generation_count++] = candidate;
        }
    }
    if (generation_count == 0U) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "No live publication generation exists for account '%s'",
                  account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    repository_required =
        current->effective_name_scope == GIT_CONFIG_ORIGIN_LOCAL ||
        current->effective_name_scope == GIT_CONFIG_ORIGIN_WORKTREE;
    if (repository_required &&
        (git_get_repo_root(reported_repository,
                           sizeof(reported_repository)) != 0 ||
         realpath(reported_repository, current_repository) == NULL)) {
        errno = ESTALE;
        set_error(ERR_GIT_CONFIG_FAILED,
                  "Cannot prove the current Git repository destination for account '%s'",
                  account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    for (size_t i = 0; i < ledger->count; i++) {
        const publication_record_t *candidate = &ledger->records[i];
        const publication_record_t *candidate_generation = NULL;

        if (candidate->account_id != account->id ||
            strcmp(candidate->account_incarnation,
                   account->incarnation) != 0 ||
            (candidate->capabilities &
             (PUBLICATION_CAP_DESTINATION |
              PUBLICATION_CAP_POST_GENERATION)) !=
                (PUBLICATION_CAP_DESTINATION |
                 PUBLICATION_CAP_POST_GENERATION) ||
            (repository_required &&
             strcmp(candidate->repository_path,
                    current_repository) != 0) ||
            !account_publication_scope_matches_origin(
                candidate->scope, current->effective_name_scope) ||
            !account_publication_origin_matches(
                candidate, current->effective_name_origin)) {
            continue;
        }
        origin_matches++;
        if (publication_record_verify_live_destination(
                candidate, generation_records, generation_count,
                &candidate_generation) != 0) {
            ignored_probe_failure = true;
            continue;
        }
        if (membership) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Durable publication provenance for account '%s' is ambiguous at the current Git destination",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
        }
        membership = candidate;
        live_generation = candidate_generation;
    }
    if (!membership || !live_generation) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            origin_matches > 0U
                ? "Current Git publication destination for account '%s' is inaccessible or changed"
                : "No durable publication provenance for account '%s' applies to the current Git destination",
            account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }

    /* Repository membership and credential generation are separate linked-
     * worktree witnesses. Select the unique complete record that sealed the
     * live shared-config generation, then retain the current repository's
     * origin context for relative Git --show-origin paths. */
    for (size_t i = 0; i < generation_count; i++) {
        const publication_record_t *candidate = generation_records[i];

        if (!publication_record_same_config_destination(
                membership, candidate) ||
            !publication_identity_equal(&candidate->post_config,
                                        &live_generation->post_config) ||
            (candidate->capabilities & required_capabilities) !=
                required_capabilities ||
            !account_publication_scope_matches_origin(
                candidate->scope, current->effective_name_scope)) {
            continue;
        }
        if (live_publication) {
            errno = ESTALE;
            set_error(
                ERR_GIT_CONFIG_FAILED,
                "Durable publication provenance for account '%s' is ambiguous at the live Git config generation",
                account->name);
            return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
        }
        live_publication = candidate;
    }
    if (!live_publication) {
        errno = ESTALE;
        set_error(
            ERR_GIT_CONFIG_FAILED,
            "Live Git config generation for account '%s' lacks complete publication provenance",
            account->name);
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }

    *publication = *live_publication;
    publication->scope = membership->scope;
    publication->config_parent = membership->config_parent;
    publication->repository = membership->repository;
    if (safe_strncpy(publication->config_path, membership->config_path,
                     sizeof(publication->config_path)) != 0 ||
        safe_strncpy(publication->repository_path,
                     membership->repository_path,
                     sizeof(publication->repository_path)) != 0 ||
        publication_record_validate(publication) != 0) {
        return ACCOUNT_PUBLICATION_LOOKUP_ERROR;
    }
    if (ignored_probe_failure) clear_error();
    return ACCOUNT_PUBLICATION_LOOKUP_FOUND;
}

/* Show current account status */
int accounts_show_status(const gitswitch_ctx_t *ctx) {
    int status_result = 0;
    git_current_config_t *git_config = NULL;
    git_status_snapshot_t *git_status = NULL;
    publication_ledger_t publication_ledger;
    bool repository_probe_allowed = true;

    publication_ledger_init(&publication_ledger);

    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_show_status");
        return -1;
    }
    if (accounts_require_current_pointer_live(ctx,
                                              "show account status") != 0) {
        return -1;
    }
    
    printf("\nAccount Status\n");
    printf("════════════════\n");
    
    if (ctx->current_account) {
        const account_t *account = ctx->current_account;
        publication_record_t publication_storage;
        const publication_record_t *publication = NULL;
        char publication_status_error[512] = "";
        size_t account_publication_count = 0U;
        uint32_t publication_capabilities =
            PUBLICATION_CAP_DESTINATION |
            PUBLICATION_CAP_POST_GENERATION;
        bool ssh_expected = account->ssh_enabled &&
                            account->ssh_key_path[0] != '\0';
        bool signing_expected = account->gpg_enabled &&
                                account->gpg_key_id[0] != '\0';
        bool publication_required = ssh_expected || signing_expected;
        bool publication_available = true;

        if (ssh_expected) {
            publication_capabilities |= PUBLICATION_CAP_SSH_COMMAND |
                                        PUBLICATION_CAP_SSH_PROGRAM;
        }
        if (signing_expected) {
            publication_capabilities |= PUBLICATION_CAP_GPG_FINGERPRINT |
                                        PUBLICATION_CAP_GPG_PROGRAM |
                                        PUBLICATION_CAP_GPG_SELECTOR;
        }
        if (publication_required &&
            load_account_publications(
                ctx, account, publication_capabilities,
                false, &publication_ledger, &account_publication_count) !=
                ACCOUNT_PUBLICATION_LOOKUP_FOUND) {
            const error_context_t *error = get_last_error();

            publication_available = false;
            /* Missing SSH provenance must not fall through to any Git/PATH
             * probe: there is no trustworthy command to compare. GPG-only
             * status can still inspect Git and render its established
             * per-field unavailable diagnostics without reconstructing any
             * executable selection. */
            if (ssh_expected) repository_probe_allowed = false;
            status_result = -1;
            if (error && error->message[0] != '\0') {
                (void)snprintf(publication_status_error,
                               sizeof(publication_status_error), "%s",
                               error->message);
            }
        }
        
        printf("Active Account: %s (ID: %u)\n", account->name, account->id);
        printf("Email: %s\n", account->email);
        printf("Description: %s\n", account->description);
        printf("Preferred Scope: %s\n", config_scope_to_string(account->preferred_scope));
        
        /* SSH Status */
        printf("\nSSH Configuration:\n");
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            ssh_key_inspection_t key_inspection;
            int inspection_rc;

            printf("  Status: [ENABLED]\n");
            printf("  Key: %s\n", account->ssh_key_path);

            inspection_rc = ssh_inspect_key_file(account->ssh_key_path,
                                                  &key_inspection);
            if (inspection_rc == 0 && key_inspection.exists) {
                printf("  Key File: [FOUND]\n");

                if (key_inspection.secure_permissions) {
                    printf("  Permissions: [SECURE] (600)\n");
                } else {
                    printf("  Permissions: [WARN] Insecure (%o)\n",
                           key_inspection.mode);
                }
            } else if (inspection_rc == 0) {
                printf("  Key File: [NOT FOUND]\n");
            } else {
                const error_context_t *inspection_error = get_last_error();

                status_result = -1;
                printf("  Key File: [ERROR] Unable to inspect safely");
                if (inspection_error &&
                    inspection_error->message[0] != '\0') {
                    printf(": ");
                    print_terminal_safe(inspection_error->message);
                }
                printf("\n");
            }
            
            if (strlen(account->ssh_host_alias) > 0) {
                printf("  Host Alias: %s\n", account->ssh_host_alias);
            }
        } else {
            printf("  Status: [DISABLED]\n");
        }
        
        /* GPG Status */
        printf("\nGPG Configuration:\n");
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("  Status: [ENABLED]\n");
            printf("  Key ID: %s\n", account->gpg_key_id);
            printf("  Signing: %s\n", account->gpg_signing_enabled ? "[ENABLED]" : "[DISABLED]");
        } else {
            printf("  Status: [DISABLED]\n");
        }
        
        /* Git Configuration Status */
        printf("\nGit Configuration:\n");
        if (!publication_available && ssh_expected) {
            printf("  Match Status: [ERROR] Durable publication provenance unavailable\n");
            printf("    SSH provenance: [UNAVAILABLE] ");
            print_terminal_safe(
                publication_status_error[0] != '\0'
                    ? publication_status_error
                    : "complete switch-time SSH publication is required");
            printf("\n");
            printf("  Effective SSH Command: [ERROR] Publication provenance unavailable\n");
            if (signing_expected) {
                printf("    OpenPGP provenance: [UNAVAILABLE] ");
                print_terminal_safe(
                    publication_status_error[0] != '\0'
                        ? publication_status_error
                        : "complete switch-time OpenPGP publication is required");
                printf("\n");
            }
        } else if (git_status_snapshot_read(&git_status) != 0) {
            if (print_git_status_read_failure() != 0) status_result = -1;
            print_git_status_captured_state(git_status, true);
        } else if (!git_status->any_present) {
            set_error(ERR_GIT_CONFIG_NOT_FOUND,
                      "No managed git configuration found");
            if (print_git_status_read_failure() != 0) status_result = -1;
        } else if (!git_status_snapshot_has_complete_identity(git_status)) {
            print_git_status_snapshot_identity(git_status, true);
            printf("  Match Status: [WARN] Effective Git identity is incomplete\n");
            printf("    Expected: %s <%s>\n", account->name,
                   account->email);
            printf("    Current:  ");
            print_git_effective_text(&git_status->user_name);
            printf(" <");
            print_git_effective_text(&git_status->user_email);
            printf(">\n");
            print_git_status_snapshot_credentials(git_status);
            if (git_status_snapshot_has_credential_residue(git_status)) {
                printf("  [WARN] Durable Git credential configuration is set with an incomplete identity.\n");
            }
        } else if ((git_config = calloc(1, sizeof(*git_config))) == NULL) {
            set_error(ERR_SYSTEM_CALL,
                      "Cannot allocate Git status snapshot: %s",
                      strerror(errno));
            if (print_git_status_read_failure() != 0) status_result = -1;
            print_git_status_captured_state(git_status, true);
        } else if (git_status_snapshot_to_current(git_status, git_config) ==
                   0) {
            char expected_gpg_program[MAX_PATH_LEN] = "";
            char ssh_status_error[512] = "";
            char gpg_program_status_error[512] = "";
            char signing_status_error[512] = "";
            char current_gpg_selector[MAX_GPG_SELECTOR_LEN] = "";
            bool identity_matches;
            bool ssh_matches;
            bool ssh_status_determined = true;
            bool gpg_openpgp_matches;
            bool gpg_programs_match;
            bool gpg_program_status_determined = true;
            bool signing_status_determined = true;
            bool foreign_gpg_program_present;
            bool signing_key_matches;
            bool signing_fingerprint_matches = false;
            bool signing_selector_mismatch = false;
            bool signing_enabled_matches;

            if (publication_required && publication_available &&
                select_current_account_publication(
                    account, &publication_ledger, git_config,
                    publication_capabilities,
                    &publication_storage) !=
                    ACCOUNT_PUBLICATION_LOOKUP_FOUND) {
                const error_context_t *error = get_last_error();

                publication_available = false;
                status_result = -1;
                if (ssh_expected) repository_probe_allowed = false;
                if (error && error->message[0] != '\0') {
                    (void)snprintf(publication_status_error,
                                   sizeof(publication_status_error), "%s",
                                   error->message);
                }
            } else if (publication_required && publication_available) {
                publication = &publication_storage;
            }

            printf("  Current Name: ");
            print_terminal_safe(git_config->name);
            printf("\n  Current Email: ");
            print_terminal_safe(git_config->email);
            printf("\n");
            printf("  Configuration Scope: %s",
                   git_config_origin_scope_to_string(
                       git_config->effective_name_scope));
            if (git_config->effective_name_origin[0] != '\0') {
                printf(" (");
                print_terminal_safe(git_config->effective_name_origin);
                printf(")");
            }
            printf("\n");

            identity_matches =
                strcmp(git_config->name, account->name) == 0 &&
                strcmp(git_config->email, account->email) == 0;
            if (ssh_expected) {
                if (!publication) {
                    ssh_matches = false;
                    ssh_status_determined = false;
                    status_result = -1;
                    (void)snprintf(
                        ssh_status_error, sizeof(ssh_status_error), "%s",
                        publication_status_error[0] != '\0'
                            ? publication_status_error
                            : "complete switch-time SSH publication is required");
                } else {
                    git_ssh_publication_result_t ssh_result =
                        git_ssh_command_matches_publication(
                            account, publication, git_config);

                    ssh_matches =
                        ssh_result == GIT_SSH_PUBLICATION_MATCH;
                    if (ssh_result == GIT_SSH_PUBLICATION_ERROR) {
                        const error_context_t *error = get_last_error();
                        ssh_status_determined = false;
                        status_result = -1;
                        if (error && error->message[0] != '\0') {
                            (void)snprintf(ssh_status_error,
                                           sizeof(ssh_status_error), "%s",
                                           error->message);
                        }
                    }
                }
            } else {
                ssh_matches = !git_config->ssh_command.present;
            }
            foreign_gpg_program_present =
                git_config->gpg_program.present ||
                git_config->gpg_x509_program.present ||
                git_config->gpg_ssh_program.present;
            if (signing_expected) {
                if (!publication) {
                    gpg_program_status_determined = false;
                    gpg_openpgp_matches = false;
                    gpg_programs_match = false;
                    status_result = -1;
                    (void)snprintf(
                        gpg_program_status_error,
                        sizeof(gpg_program_status_error), "%s",
                        publication_status_error[0] != '\0'
                            ? publication_status_error
                            : "complete switch-time OpenPGP publication is required");
                } else if (safe_strncpy(expected_gpg_program,
                                        publication->gpg_program,
                                        sizeof(expected_gpg_program)) != 0 ||
                           git_publication_verify_program_identity(
                               publication->gpg_program,
                               &publication->gpg_program_identity,
                               "OpenPGP") != 0) {
                    const error_context_t *error = get_last_error();

                    gpg_program_status_determined = false;
                    gpg_openpgp_matches = false;
                    gpg_programs_match = false;
                    status_result = -1;
                    if (error && error->message[0] != '\0') {
                        (void)snprintf(gpg_program_status_error,
                                       sizeof(gpg_program_status_error), "%s",
                                       error->message);
                    }
                } else {
                    gpg_openpgp_matches =
                        git_config->gpg_openpgp_program.present &&
                        !git_config->gpg_openpgp_program.value_unknown &&
                        strcmp(git_config->gpg_openpgp_program.value,
                               expected_gpg_program) == 0 &&
                        account_publication_scope_matches_origin(
                            publication->scope,
                            git_config->gpg_openpgp_program.scope) &&
                        account_publication_origin_matches(
                            publication,
                            git_config->gpg_openpgp_program.origin);
                    gpg_programs_match = gpg_openpgp_matches &&
                                         !foreign_gpg_program_present;
                }
            } else {
                gpg_openpgp_matches =
                    !git_config->gpg_openpgp_program.present;
                gpg_programs_match = gpg_openpgp_matches &&
                                     !foreign_gpg_program_present;
            }
            {
                git_signing_publication_result_t signing_result =
                    status_signing_key_matches(account, publication,
                                               git_config, git_status);
                signing_key_matches =
                    signing_result == GIT_SIGNING_PUBLICATION_MATCH;
                if (signing_result == GIT_SIGNING_PUBLICATION_ERROR) {
                    const error_context_t *error = get_last_error();

                    signing_status_determined = false;
                    status_result = -1;
                    if (error && error->message[0] != '\0') {
                        (void)snprintf(signing_status_error,
                                       sizeof(signing_status_error), "%s",
                                       error->message);
                    }
                } else if (signing_result ==
                               GIT_SIGNING_PUBLICATION_MISMATCH &&
                           signing_expected && publication &&
                           (publication->capabilities &
                            PUBLICATION_CAP_GPG_SELECTOR) != 0U) {
                    if (publication_normalize_gpg_selector(
                            account->gpg_key_id,
                            current_gpg_selector) != 0) {
                        const error_context_t *error = get_last_error();

                        signing_status_determined = false;
                        status_result = -1;
                        if (error && error->message[0] != '\0') {
                            (void)snprintf(signing_status_error,
                                           sizeof(signing_status_error),
                                           "%s", error->message);
                        }
                    } else {
                        signing_selector_mismatch =
                            strcmp(publication->gpg_selector,
                                   current_gpg_selector) != 0;
                    }
                }
                signing_fingerprint_matches =
                    signing_expected && publication &&
                    git_signing_key_matches_fingerprint(
                        publication->gpg_fingerprint,
                        git_config->signing_key);
            }
            signing_enabled_matches =
                git_config->gpg_signing_enabled ==
                (signing_expected && account->gpg_signing_enabled);
            
            /* Check if git config matches account */
            if (!ssh_status_determined || !gpg_program_status_determined ||
                !signing_status_determined) {
                printf("  Match Status: [ERROR] Unable to determine trusted expected configuration\n");
                if (!ssh_status_determined) {
                    printf("    SSH command: ");
                    print_terminal_safe(ssh_status_error[0] != '\0'
                                            ? ssh_status_error
                                            : "unknown resolution failure");
                    printf("\n");
                }
                if (!gpg_program_status_determined) {
                    printf("    OpenPGP provenance: [UNAVAILABLE] ");
                    print_terminal_safe(
                        gpg_program_status_error[0] != '\0'
                            ? gpg_program_status_error
                            : "unknown resolution failure");
                    printf("\n");
                }
                if (!signing_status_determined) {
                    printf("    Signing attribution: [UNAVAILABLE] current account GPG selector is invalid\n");
                    printf("    Selector diagnostic: ");
                    print_terminal_safe(
                        signing_status_error[0] != '\0'
                            ? signing_status_error
                            : "invalid current account GPG selector");
                    printf("\n");
                    printf("    Expected Switch-time GPG Selector: ");
                    if (publication &&
                        (publication->capabilities &
                         PUBLICATION_CAP_GPG_SELECTOR) != 0U) {
                        print_terminal_safe(publication->gpg_selector);
                    } else {
                        printf("[PROVENANCE UNAVAILABLE]");
                    }
                    printf("\n");
                    printf("    Current Account GPG Selector:  ");
                    print_terminal_safe(account->gpg_key_id);
                    printf(" [INVALID]\n");
                } else if (!gpg_program_status_determined &&
                           signing_expected) {
                    printf("    Signing attribution: [UNAVAILABLE] complete trusted publication provenance unavailable\n");
                }
                if (!gpg_program_status_determined ||
                    !signing_status_determined) {
                    printf("    Expected GPG Signing Key: ");
                    if (publication) {
                        print_terminal_safe(publication->gpg_fingerprint);
                    } else {
                        printf("[PROVENANCE UNAVAILABLE]");
                    }
                    printf("\n");
                    printf("    Current GPG Signing Key:  ");
                    if (git_config->signing_key[0] != '\0') {
                        print_terminal_safe(git_config->signing_key);
                        printf("\n");
                    } else {
                        printf("[ABSENT]\n");
                    }
                }
            } else if (identity_matches && ssh_matches &&
                       gpg_programs_match && signing_key_matches &&
                       signing_enabled_matches) {
                printf("  Match Status: [OK] Git config matches account\n");
            } else {
                printf("  Match Status: [WARN] Git config does not match account\n");
                if (!identity_matches) {
                    printf("    Expected: %s <%s>\n", account->name, account->email);
                    printf("    Current:  ");
                    print_terminal_safe(git_config->name);
                    printf(" <");
                    print_terminal_safe(git_config->email);
                    printf(">\n");
                }
                if (!signing_key_matches) {
                    if (signing_selector_mismatch) {
                        printf("    Expected Switch-time GPG Selector: ");
                        print_terminal_safe(publication->gpg_selector);
                        printf("\n");
                        printf("    Current Account GPG Selector:  ");
                        print_terminal_safe(current_gpg_selector);
                        printf("\n");
                    }
                    if (!signing_fingerprint_matches) {
                        if (signing_expected) {
                            printf("    Expected GPG Signing Key: ");
                            if (publication) {
                                print_terminal_safe(
                                    publication->gpg_fingerprint);
                            } else {
                                printf("[PROVENANCE UNAVAILABLE]");
                            }
                            printf("\n");
                        } else {
                            printf("    Expected GPG Signing Key: [ABSENT]\n");
                        }
                        printf("    Current GPG Signing Key:  ");
                        if (git_config->signing_key[0] != '\0') {
                            print_terminal_safe(git_config->signing_key);
                            printf("\n");
                        } else {
                            printf("[ABSENT]\n");
                        }
                    } else if (!signing_selector_mismatch) {
                        printf("    Signing attribution: [MISMATCH] configured key came from a different published destination\n");
                    }
                }
                if (!signing_enabled_matches) {
                    printf("    Expected GPG Signing Enabled: %s\n",
                           signing_expected && account->gpg_signing_enabled
                               ? "[YES]" : "[NO]");
                    printf("    Current GPG Signing Enabled:  %s\n",
                           git_config->gpg_signing_enabled
                               ? "[YES]" : "[NO]");
                }
                if (!gpg_openpgp_matches) {
                    printf("    Expected OpenPGP Program: ");
                    if (signing_expected) {
                        print_terminal_safe(expected_gpg_program);
                    } else {
                        printf("[ABSENT]");
                    }
                    printf("\n");
                }
            }

            if (ssh_status_determined) {
                printf("  Effective SSH Command: %s",
                       ssh_matches ? "[MATCH]" : "[MISMATCH]");
            } else {
                printf("  Effective SSH Command: [ERROR] Expected command unavailable");
            }
            print_git_value_origin(&git_config->ssh_command);
            printf("\n");
            printf("  Effective GPG Format: ");
            print_git_effective_set_value(&git_status->gpg_format);
            printf("\n");
            printf("  Effective OpenPGP Program: %s",
                   !gpg_program_status_determined
                       ? "[ERROR]"
                       : (signing_expected
                              ? (gpg_openpgp_matches
                                     ? "[MATCH]" : "[MISMATCH]")
                              : (git_config->gpg_openpgp_program.present
                                     ? "[MISMATCH]" : "[ABSENT]")));
            print_git_value_origin(&git_config->gpg_openpgp_program);
            printf("\n");
            printf("  Effective Legacy GPG Program: %s",
                   git_config->gpg_program.present ? "[FOREIGN]" : "[ABSENT]");
            print_git_value_origin(&git_config->gpg_program);
            printf("\n");
            printf("  Effective X.509 GPG Program: %s",
                   git_config->gpg_x509_program.present
                       ? "[FOREIGN]" : "[ABSENT]");
            print_git_value_origin(&git_config->gpg_x509_program);
            printf("\n");
            printf("  Effective SSH Signing Program: %s",
                   git_config->gpg_ssh_program.present
                       ? "[FOREIGN]" : "[ABSENT]");
            print_git_value_origin(&git_config->gpg_ssh_program);
            printf("\n");
            
            /* Preserve explicit-empty and explicit-false state instead of
             * projecting both onto scalar absence/defaults. */
            printf("  GPG Signing Key: ");
            print_git_effective_text(&git_status->user_signing_key);
            printf("\n  GPG Signing Enabled: ");
            if (!git_status->commit_gpgsign.present) {
                printf("[ABSENT]");
            } else {
                fputs(git_status->gpg_signing_enabled ? "[YES]" : "[NO]",
                      stdout);
                print_git_value_origin(&git_status->commit_gpgsign);
            }
            printf("\n");
        } else {
            if (print_git_status_read_failure() != 0) status_result = -1;
            print_git_status_captured_state(git_status, true);
        }
        
        /* Repository context */
        printf("\nRepository Context:\n");
        if (!repository_probe_allowed) {
            printf("  Repository: [UNAVAILABLE] Publication provenance unavailable\n");
        } else if (git_is_repository()) {
            char repo_root[MAX_PATH_LEN];
            if (git_get_repo_root(repo_root, sizeof(repo_root)) == 0) {
                printf("  Repository: [FOUND] ");
                print_terminal_safe(repo_root);
                printf("\n");
            } else {
                printf("  Repository: [REPOSITORY] Current directory is a git repository\n");
            }
        } else {
            printf("  Repository: [NO REPOSITORY] Not in a git repository\n");
        }
        
    } else {
        printf("No account currently active.\n");
        printf("Run 'gitswitch list' to see available accounts.\n");
        printf("Run 'gitswitch <account>' to activate an account.\n");
        
        /* Show current git config even without active account */
        printf("\nCurrent Git Configuration:\n");
        if (git_status_snapshot_read(&git_status) != 0) {
            if (print_git_status_read_failure() != 0) status_result = -1;
            print_git_status_captured_state(git_status, false);
        } else if (!git_status->any_present) {
            set_error(ERR_GIT_CONFIG_NOT_FOUND,
                      "No managed git configuration found");
            if (print_git_status_read_failure() != 0) status_result = -1;
        } else {
            print_git_status_snapshot_identity(git_status, false);
            /* AR-10 M1: the credential legs stay authoritative for fetch/push
             * and signing even with no active account. Render them here so
             * residue from a removed/reset account cannot hide in exactly the
             * state that retirement produces. */
            print_git_status_snapshot_credentials(git_status);
            if (git_status_snapshot_has_credential_residue(git_status)) {
                printf("  [WARN] Durable Git credential configuration is set "
                       "while no account is active.\n");
            }
        }
        
        /* Repository context */
        printf("\nRepository Context:\n");
        if (git_is_repository()) {
            printf("  Repository: [REPOSITORY] Current directory is a git repository\n");
        } else {
            printf("  Repository: [NO REPOSITORY] Not in a git repository\n");
        }
    }
    
    printf("\n");
    if (git_config) {
        secure_zero_memory(git_config, sizeof(*git_config));
        free(git_config);
    }
    git_status_snapshot_free(git_status);
    publication_ledger_clear(&publication_ledger);
    return status_result;
}

/* Simple account validation for Phase 2 */
int accounts_validate(const account_t *account) {
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account pointer");
        return -1;
    }
    if (config_validate_account_model(account) != 0) return -1;
    
    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid or empty account name");
        return -1;
    }
    
    if (!text_is_tty_safe(account->email) || !validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address format");
        return -1;
    }
    
    /* Basic SSH validation if enabled */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        char expanded_path[MAX_PATH_LEN];

        if (!text_is_tty_safe(account->ssh_key_path)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "SSH key path contains terminal control bytes or malformed UTF-8");
            return -1;
        }
        
        if (expand_path(account->ssh_key_path, expanded_path, sizeof(expanded_path)) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH key path: %s", account->ssh_key_path);
            return -1;
        }
        
        if (ssh_validate_key_file(expanded_path) != 0) return -1;
    }
    
    /* Basic GPG validation if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (!text_is_tty_safe(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "GPG key ID contains terminal control bytes or malformed UTF-8");
            return -1;
        }
        if (!validate_key_id(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID format: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    return 0;
}

static bool account_id_is_live(const gitswitch_ctx_t *ctx,
                               uint32_t account_id) {
    for (size_t i = 0; ctx && i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account_id) return true;
    }
    return false;
}

static bool account_id_has_publication(
    const publication_ledger_t *ledger, uint32_t account_id) {
    for (size_t i = 0; ledger && i < ledger->count; i++) {
        if (ledger->records[i].account_id == account_id) return true;
    }
    return false;
}

/* Publication records are durable ownership tombstones as well as positive
 * attribution. An account ID named by any record cannot be recycled: after a
 * failed retirement, reusing that integer would otherwise let the new account
 * inherit the old account's Git-mutation authority. Include both live and
 * published IDs in the allocator, and fail closed when the persisted ledger
 * cannot be read faithfully. */
static int get_next_available_id(const gitswitch_ctx_t *ctx,
                                 uint32_t *account_id) {
    publication_ledger_t ledger;
    uint32_t max_id = 0;
    uint32_t search_limit;

    if (!ctx || !account_id) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account ID allocation request");
        return -1;
    }
    *account_id = 0;
    publication_ledger_init(&ledger);
    if (ctx->config.config_path[0] != '\0' &&
        config_load_publication_ledger(ctx->config.config_path, &ledger) != 0) {
        publication_ledger_clear(&ledger);
        return -1;
    }

    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id > max_id) {
            max_id = ctx->accounts[i].id;
        }
    }
    for (size_t i = 0; i < ledger.count; i++) {
        if (ledger.records[i].account_id > max_id) {
            max_id = ledger.records[i].account_id;
        }
    }

    if (max_id < UINT32_MAX) {
        *account_id = max_id + 1U;
        publication_ledger_clear(&ledger);
        return 0;
    }

    /* A UINT32_MAX record forbids max+1. At most MAX_ACCOUNTS live IDs and
     * PUBLICATION_LEDGER_MAX_RECORDS durable IDs exist, so one positive ID is
     * guaranteed within this bounded prefix unless the model is corrupt. */
    search_limit = (uint32_t)MAX_ACCOUNTS +
                   (uint32_t)PUBLICATION_LEDGER_MAX_RECORDS + 1U;
    for (uint32_t candidate = 1; candidate <= search_limit; candidate++) {
        if (!account_id_is_live(ctx, candidate) &&
            !account_id_has_publication(&ledger, candidate)) {
            *account_id = candidate;
            publication_ledger_clear(&ledger);
            return 0;
        }
    }
    publication_ledger_clear(&ledger);
    set_error(ERR_ACCOUNT_EXISTS,
              "No account ID is available outside durable publication provenance");
    return -1;
}

/* L2: charset+length gate for the interactive host-alias prompt. Mirrors
 * ssh_manager.c's valid_ssh_host_alias — the alias is written verbatim into a
 * "Host <alias>" line of ~/.ssh/config, where quotes, whitespace, or control
 * bytes would inject config syntax; ssh host patterns need only alphanumerics
 * plus . - _ * ?. The length bound is what account_t.ssh_host_alias can hold:
 * the old prompt accepted up to 511 chars and let the copy fail silently. */
static bool prompt_host_alias_valid(const char *alias) {
    size_t len = strlen(alias);
    if (len == 0 || len >= MAX_NAME_LEN) {
        return false;
    }
    for (const char *p = alias; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' ||
              *p == '_' || *p == '*' || *p == '?')) {
            return false;
        }
    }
    return true;
}

/* Validate GPG key availability through the GPG manager's descriptor-pinned
 * system-source resolver. `gitswitch init` may point inherited GNUPGHOME at a
 * managed isolated home; the resolver chooses and pins the real source,
 * rejects namespace replacement, parses the secret-key inventory, and returns
 * the canonical primary fingerprint rather than treating child exit 0 as
 * sufficient identity proof. */
static int validate_gpg_key_availability_mode(const char *gpg_key_id,
                                              bool allow_cached) {
    char canonical[GPG_FINGERPRINT_BUFSIZE];

    if (!gpg_key_id) {
        return -1;
    }

    /* Mock-runner compatibility only: production reuse is performed inside
     * the structured resolver, where it is bound to the exact executable,
     * capability, keyring context, and home generation. A key-only note must
     * never authorize a production skip. */
    if (allow_cached && !run_uses_default_runner() &&
        gpg_manager_key_available_cached(gpg_key_id)) {
        return 0;
    }

    if (gpg_manager_resolve_system_key(gpg_key_id, false, canonical,
                                       sizeof(canonical)) != 0) {
        log_debug("GPG selector %s is unavailable in the pinned system "
                  "keyring: %s",
                  gpg_key_id,
                  get_last_error()->message[0]
                      ? get_last_error()->message
                      : "unknown resolver error");
        /* Preserve the resolver's exact miss/setup/signal/pipe/GPG failure
         * classification. Recasting every failure as key-not-found would
         * undo T14's result-truth contract at this accounts boundary. */
        return -1;
    }

    if (!run_uses_default_runner()) {
        gpg_manager_note_key_available(canonical);
        gpg_manager_note_key_available(gpg_key_id);
    }
    return 0;
}

static int validate_gpg_key_availability(const char *gpg_key_id) {
    return validate_gpg_key_availability_mode(gpg_key_id, true);
}

/* Destructive edit preflight must re-read the real keyring. A process-local
 * cache only proves that the key existed at some earlier instant and may even
 * have been populated while an isolated home was authoritative. */
static int validate_gpg_key_availability_fresh(const char *gpg_key_id) {
    return validate_gpg_key_availability_mode(gpg_key_id, false);
}

/* Check only the local private-key node and its security properties. This
 * does not contact a server, select a remote username, or prove that any
 * service accepts the corresponding public key. */
static int check_ssh_key_local_file(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];
    log_debug("SSH key local-file check for %s: %s",
              account->name, account->ssh_key_path);

    if (expand_path(account->ssh_key_path, expanded_path,
                    sizeof(expanded_path)) != 0) return -1;
    return ssh_validate_key_file(expanded_path);
}

/* Mirror activation's retained-home-first resolver order and report whether
 * the same key could be recovered from the persistent source keyring. This
 * still does not perform a cryptographic signing operation. */
static int check_gpg_key_local_state(
    const account_t *account, gpg_account_key_readiness_t *readiness) {
    log_debug("GPG key local metadata/material check for %s: %s",
              account->name, account->gpg_key_id);

    return gpg_manager_check_account_key(account, readiness);
}

/* Run bounded local readiness checks on all accounts. */
int accounts_health_check(const gitswitch_ctx_t *ctx) {
    bool all_local_checks_passed = true;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_health_check");
        return -1;
    }
    
    printf("\nAccount Local Readiness Check\n");
    printf("═════════════════════════════\n");
    printf("[INFO]: Local checks only; remote SSH authentication and a test "
           "signature are not attempted.\n");
    
    if (ctx->account_count == 0) {
        printf("[ERROR]: No accounts configured\n");
        printf("   Run 'gitswitch add' to create your first account\n\n");
        return -1;
    }
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        int validation_result = accounts_validate(account);
        
        printf("\n[%u] %s\n", account->id, account->name);
        printf("────────────────────────\n");
        
        if (validation_result == 0) {
            printf("[OK]: Account model and fields are locally valid\n");
            
            /* Validate only the configured local SSH key file. */
            if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
                if (check_ssh_key_local_file(account) == 0) {
                    printf("[OK]: SSH private key file passed local validation "
                           "(authentication not tested)\n");
                } else {
                    printf("[ERROR]: SSH private key file failed local "
                           "validation (authentication not tested)\n");
                    all_local_checks_passed = false;
                }
            }
            
            /* Validate current local GPG metadata/material without signing. */
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                gpg_account_key_readiness_t readiness;

                if (check_gpg_key_local_state(account, &readiness) == 0) {
                    if (account->gpg_signing_enabled) {
                        printf("[OK]: GPG key has current signing-capable "
                               "secret material%s (signature not attempted)\n",
                               readiness.retained_home_usable
                                   ? " in the retained isolated GPG home"
                                   : "");
                    } else {
                        printf("[OK]: GPG secret key is present and locally "
                               "usable%s (signing not tested)\n",
                               readiness.retained_home_usable
                                   ? " in the retained isolated GPG home"
                                   : "");
                    }
                    switch (readiness.source_recovery) {
                        case GPG_SOURCE_RECOVERY_AVAILABLE:
                            printf("[OK]: GPG source keyring currently contains "
                                   "the same locally usable identity for "
                                   "recovery\n");
                            break;
                        case GPG_SOURCE_RECOVERY_MISSING:
                            printf("[WARN]: GPG source keyring does not contain "
                                   "this identity; the retained isolated GPG "
                                   "home is usable, but reset or home loss "
                                   "would leave no recovery source in that "
                                   "keyring\n");
                            break;
                        case GPG_SOURCE_RECOVERY_MISMATCH:
                            printf("[WARN]: GPG source keyring resolves the "
                                   "selector to a different identity; the "
                                   "retained isolated GPG home is usable, but "
                                   "cannot be recovered from that source\n");
                            break;
                        case GPG_SOURCE_RECOVERY_ERROR:
                        case GPG_SOURCE_RECOVERY_UNKNOWN:
                        default:
                            printf("[WARN]: GPG source keyring recoverability "
                                   "could not be verified; the retained "
                                   "isolated GPG home is currently usable\n");
                            break;
                    }
                } else {
                    if (account->gpg_signing_enabled) {
                        printf("[ERROR]: GPG signing-key metadata/material "
                               "check failed (signature not attempted)\n");
                    } else {
                        printf("[ERROR]: GPG secret-key local "
                               "presence/usability check failed (signing not "
                               "tested)\n");
                    }
                    all_local_checks_passed = false;
                }
            }
        } else {
            printf("[ERROR]: Account local validation failed\n");
            all_local_checks_passed = false;
        }
    }
    
    printf("\n═════════════════════════════\n");
    if (all_local_checks_passed) {
        printf("[OK]: All configured accounts passed the reported local "
               "checks\n\n");
        return 0;
    } else {
        printf("[ERROR]: Some configured accounts failed the reported local "
               "checks\n\n");
        return -1;
    }
}

/* Detect current account from SSH socket symlink */
/* Fallback for accounts_detect_current: use the persisted last-active account
 * when no live runtime symlink is available (e.g. right after a boot, before
 * any resume has run). Returns 0 if it set ctx->current_account. */
static int detect_current_from_saved(gitswitch_ctx_t *ctx) {
    if (ctx->config.active_account[0] == '\0') {
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, ctx->config.active_account) == 0) {
            ctx->current_account = &ctx->accounts[i];
            log_debug("Detected current account from saved state: %s",
                      ctx->config.active_account);
            return 0;
        }
    }
    return -1;
}

int accounts_detect_current(gitswitch_ctx_t *ctx) {
    char account_name[MAX_NAME_LEN];
    bool present = false;

    if (!ctx) {
        return -1;
    }

    /* Preserve a proven live selection. A stale public pointer is not a
     * discovery result: clear it without dereferencing and continue through
     * the same trusted runtime/saved-state resolution as an unset context. */
    if (ctx->current_account && accounts_current_pointer_is_live(ctx)) {
        return 0;
    }
    if (ctx->current_account) {
        log_debug("Discarding stale current-account reference before detection");
        ctx->current_account = NULL;
    }

    /* Discovery is serialized with SSH runtime writers and accepts only a
     * stable, live, self-owned managed socket in the verified private tree.
     * A malformed/stale runtime hint must never suppress persisted fallback. */
    if (ssh_manager_get_current_account(account_name, sizeof(account_name),
                                        &present) != 0) {
        log_debug("Cannot trust current.sock; falling back to saved account: %s",
                  get_last_error()->message);
        clear_error();
        return detect_current_from_saved(ctx);
    }
    if (!present) {
        log_debug("No live current.sock found, falling back to saved account");
        return detect_current_from_saved(ctx);
    }

    /* Find matching account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, account_name) == 0) {
            ctx->current_account = &ctx->accounts[i];
            log_debug("Detected current account from symlink: %s", account_name);
            return 0;
        }
    }

    log_debug("No matching account found for name: %s", account_name);
    return detect_current_from_saved(ctx);
}
