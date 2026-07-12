/* Account management and operations with comprehensive security validation
 * Implements secure account switching and management for gitswitch-c
 */

/* Enable POSIX extensions for setenv/unsetenv */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#include "accounts.h"
#include "config.h"
#include "display.h"
#include "error.h"
#include "utils.h"
#include "git_ops.h"
#include "ssh_manager.h"
#include "gpg_manager.h"
#include "prompt.h"
#include "signals.h"
#include "toml_parser.h"

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
    account_t switch_target;
    git_scope_t scope;
    bool ssh_ok;
    bool gpg_ok;
} pending_switch_t;

static pending_switch_t g_pending_switch = {0};

typedef struct {
    bool active;
    gitswitch_ctx_t *ctx;
    account_t original;
    account_t candidate;
    bool routing_changed;
    bool original_alias_exclusive;
    bool candidate_alias_attempted;
    bool original_alias_remove_attempted;
} pending_edit_t;

static pending_edit_t g_pending_edit = {0};

/* Internal helper functions */
static uint32_t get_next_available_id(const gitswitch_ctx_t *ctx);
static bool prompt_host_alias_valid(const char *alias);
static int validate_gpg_key_availability(const char *gpg_key_id);
static int validate_gpg_key_availability_fresh(const char *gpg_key_id);
static int test_ssh_key_functionality(const account_t *account);
static int test_gpg_key_functionality(const account_t *account);

static bool gpg_session_cleanup_needed(void) {
    return g_session.gpg_active ||
           gpg_manager_runtime_restore_pending(&g_session.gpg_config) ||
           g_session.gpg_config.environment_installed ||
           g_session.gpg_config.current_key_id[0] != '\0';
}

/* Initialize accounts system */
int accounts_init(gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_init");
        return -1;
    }

    /* Initialize account array */
    memset(ctx->accounts, 0, sizeof(ctx->accounts));
    ctx->account_count = 0;
    ctx->current_account = NULL;

    /* Initialize session state */
    memset(&g_session, 0, sizeof(g_session));

    log_debug("Accounts system initialized");
    return 0;
}

/* Clean up active session resources. If an owned SSH/GPG side effect survives,
 * retain the complete session as its retry handle; clearing any of it would
 * make the still-live identity/environment untrackable and misreport success. */
int accounts_session_cleanup(void) {
    log_debug("Cleaning up active session resources");

    /* Clean up SSH agent if we started one */
    if (g_session.ssh_active) {
        log_info("Stopping SSH agent (pid=%d)", g_session.ssh_config.agent_pid);
        if (ssh_manager_cleanup(&g_session.ssh_config) != 0) {
            log_warning("Active SSH session survived cleanup; retaining session for retry");
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

/* M4: validate ~/.ssh/config before any runtime/Git mutation, but do not
 * rewrite it yet. The managed alias block is committed only after every step
 * that can still trigger rollback has succeeded, which removes the unsafe
 * check-then-rename restoration path entirely. The final writer repeats these
 * no-follow and identity checks immediately before its atomic rename. */
static int ssh_user_config_preflight(const account_t *account) {
    /* AR-06 F29: the writer now heap-sizes the config, so the preflight ceiling
     * is the same generous shared limit rather than the old 64 KiB cap that
     * failed the whole switch for any larger-but-valid config. */
    const size_t SSH_CONFIG_MAX_BYTES = GITSWITCH_SSH_CONFIG_MAX_BYTES;
    char path[MAX_PATH_LEN];
    char chunk[4096];
    struct stat before;
    struct stat opened;
    const char *home = getenv("HOME");
    size_t total = 0;
    int fd;

    if (!account || !account->ssh_enabled ||
        strlen(account->ssh_key_path) == 0 ||
        strlen(account->ssh_host_alias) == 0) {
        return 0;
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH,
                  "Cannot preflight ~/.ssh/config: HOME is not set");
        return -1;
    }
    if ((size_t)snprintf(path, sizeof(path), "%s/.ssh/config", home) >=
        sizeof(path)) {
        set_error(ERR_INVALID_PATH,
                  "Cannot preflight ~/.ssh/config: path is too long");
        return -1;
    }
    if (lstat(path, &before) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect SSH config before switch: %s", path);
        return -1;
    }
    if (S_ISLNK(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to switch: SSH config is a symlink: %s", path);
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to switch: SSH config is not a regular file: %s", path);
        return -1;
    }
    if (before.st_size < 0 || (size_t)before.st_size > SSH_CONFIG_MAX_BYTES) {
        set_error(ERR_FILE_IO,
                  "Refusing to switch: SSH config is too large to update safely: %s",
                  path);
        return -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot open SSH config safely before switch: %s", path);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "SSH config changed while it was being preflighted: %s", path);
        return -1;
    }
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            total += (size_t)n;
            if (total > SSH_CONFIG_MAX_BYTES) {
                close(fd);
                set_error(ERR_FILE_IO,
                          "SSH config grew too large while being preflighted: %s",
                          path);
                return -1;
            }
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot read SSH config safely before switch: %s", path);
        return -1;
    }
    close(fd);
    return 0;
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
                                       bool *rollback_complete) {
    bool complete = true;
    bool git_left = git_written;
    bool ssh_left = ssh_dirty;
    bool gpg_left = gpg_dirty;

    /* AR-02 #2: a second guarded signal during this rollback used to take the
     * handler's emergency-kill branch and die mid-git_config_restore, leaving
     * a chimera (or fully-new) identity persisted. Defer the emergency exit
     * until the whole restore sequence has completed. */
    signals_rollback_begin();
    if (git_written) {
        if (git_config_restore() != 0) {
            complete = false;
            log_warning("Incomplete rollback of Git configuration: %s",
                        get_last_error()->message);
        } else {
            git_left = false;
        }
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
        log_warning("Incomplete rollback of the new account's SSH state: %s",
                    get_last_error()->message);
    }
    /* Restore GPG with compare-and-swap semantics so rollback cannot clobber
     * a later writer, then reactivate the previous SSH agent (F4). */
    if (restore_previous_gpg_isolation(prev_gpg_home, prev_gpg_present,
                                       gpg_dirty) != 0) {
        complete = false;
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
        } else {
            ssh_left = false;
        }
    }
    /* SIG-02: drop any registered scratch temp files. */
    signals_scratch_cleanup();
    if (!keep_rollback_active) {
        signals_rollback_end();
    }
    if (end_guard) {
        signals_guard_end();
    }
    runtime_state_lock_release(runtime_lock_fd);
    if (git_remaining) *git_remaining = git_left;
    if (ssh_remaining) *ssh_remaining = ssh_left;
    if (gpg_remaining) *gpg_remaining = gpg_left;
    if (rollback_complete) {
        *rollback_complete = complete;
    }
    if (signals_pending() && !keep_rollback_active) {
        fprintf(stderr, "\ngitswitch: interrupted — switch rolled back, previous identity kept\n");
        set_error(ERR_SYSTEM_CALL, "Switch interrupted by signal %d",
                  signals_pending_signal());
        signals_dispatch_pending(); /* terminates via the signal's default action */
    } else if (signals_pending()) {
        log_warning("Switch interruption remains deferred until config and "
                    "resume-hint rollback completes");
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
                                       NULL, NULL, NULL, NULL);
}

/* Best-effort probes and informational output run only after the switch's
 * required commits are complete. In the CLI transaction that means after the
 * active-account file and resume hint have both committed. */
static void finish_switch_success(gitswitch_ctx_t *ctx, account_t *account,
                                  const account_t *switch_target,
                                  git_scope_t scope, bool write_git,
                                  bool ssh_ok, bool gpg_ok) {
    if (!ctx || !account || !switch_target) {
        return;
    }

    if (!ctx->config.dry_run && account->ssh_enabled &&
        strlen(account->ssh_key_path) > 0 && !ctx->config.resuming &&
        !g_session.ssh_config.key_already_loaded && !signals_pending()) {
        if (strlen(account->ssh_host_alias) > 0) {
            if (ssh_test_connection(switch_target,
                                    account->ssh_host_alias) == 0) {
                printf("  [OK] SSH connection verified (%s)\n",
                       account->ssh_host_alias);
            } else {
                printf("  [--] SSH connection test skipped (%s unreachable)\n",
                       account->ssh_host_alias);
            }
        } else if (ctx->config.verbose &&
                   ssh_test_connection(switch_target,
                                       "git@github.com") == 0) {
            printf("  [OK] SSH connection verified (github.com)\n");
        }
    }

    if (!ctx->config.dry_run && write_git &&
        git_test_config(switch_target, scope) != 0) {
        log_warning("Git configuration validation failed: %s",
                    get_last_error()->message);
    }

    if (!ctx->config.resuming) {
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
            !ssh_ok && test_ssh_key_functionality(account) != 0) {
            log_warning("SSH key test failed for account: %s", account->name);
        }
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0 &&
            !gpg_ok && test_gpg_key_functionality(account) != 0) {
            log_warning("GPG key test failed for account: %s", account->name);
        }
    }

    if (ssh_ok || gpg_ok) {
        printf("\n  Tip: wire your shell once so every switch takes effect transparently:\n");
        printf("    bash/zsh: eval \"$(gitswitch init bash)\"\n");
        printf("    fish:     gitswitch init fish | source\n");
        if (gpg_ok) {
            printf("  Note: this scopes GNUPGHOME to a per-account keyring, so gpg in that\n");
            printf("        shell sees only '%s'. Use a shell without the integration for\n",
                   account->name);
            printf("        general gpg work (other keys, contacts, encryption).\n");
        }
    }

    log_info("Successfully switched to account: %s (%s)", account->name,
             account->description);
}

/* Switch to specified account with SSH isolation and validation. */
static int accounts_switch_impl(gitswitch_ctx_t *ctx, const char *identifier,
                                bool defer_commit) {
    account_t *account;
    account_t switch_target;
    const char *scope_str;
    bool ssh_ok = false;
    bool gpg_ok = false;
    bool defer_signal_dispatch;

    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_switch");
        return -1;
    }
    defer_signal_dispatch = defer_commit || ctx->config.defer_signal_cleanup;
    if (defer_commit && g_pending_switch.active) {
        set_error(ERR_SYSTEM_CALL,
                  "A prepared account switch is already awaiting commit");
        return -1;
    }

    /* Find the account. On the boot-resume path the identifier is the persisted
     * exact name, so resolve it literally (AR-06 F22) — the id-first fuzzy
     * matcher could otherwise re-resolve a legacy all-digit name to a different
     * account whose id matches. Interactive switches keep the fuzzy matcher. */
    account = ctx->config.resuming
        ? config_find_account_exact(ctx, identifier)
        : config_find_account(ctx, identifier);
    if (!account) {
        /* The fuzzy resolver already owns useful ambiguity/candidate detail.
         * Only the exact-name resume path returns NULL without setting it. */
        if (ctx->config.resuming) {
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
     * SIGHUP (Ctrl-C at the ssh-add passphrase or GPG pinentry prompt is a
     * normal path). The handler only records the signal; we check between
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
        safe_strncpy(prev_active, ctx->config.active_account,
                     sizeof(prev_active));
        if (gpg_manager_snapshot_current(prev_gpg_home,
                                         sizeof(prev_gpg_home),
                                         &prev_gpg_present) != 0) {
            runtime_state_lock_release(runtime_lock_fd);
            return -1;
        }
        /* Mutation tracking for rollback: `dirty` means the runtime state was
         * (or may have been) repointed at the NEW account; `deferred` means
         * the target has SSH/GPG disabled and the teardown of the PREVIOUS
         * account's state is postponed past the point of no return (F4). */
        bool ssh_dirty = false, gpg_dirty = false;
        bool ssh_teardown_deferred = false, gpg_teardown_deferred = false;

        /* L17 (accounts half): the SSH key path is tilde-expanded and
         * validated exactly ONCE, here. The copy of the account handed to the
         * SSH layer below carries the expanded absolute path, so that layer's
         * internal expand_path calls (switch, host alias, connection test)
         * degrade to plain copies instead of repeating the $HOME resolution.
         * Collapsing the SSH layer's own re-validation of the same file is
         * the ssh_manager.c half of L17 (ticket T1). */
        /* --- 1. Validate availability up front (no mutation yet) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            char expanded_key[MAX_PATH_LEN];
            if (expand_path(account->ssh_key_path, expanded_key, sizeof(expanded_key)) != 0 ||
                ssh_validate_key_file(expanded_key) != 0) {
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "SSH key not usable: %s", account->ssh_key_path);
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
                bool isolated_present = false;
                if (gpg_manager_isolated_home_present(account->name,
                                                      &isolated_present) != 0 ||
                    !isolated_present) {
                    set_error(ERR_GPG_KEY_NOT_FOUND,
                              "GPG key not found in keyring: %s",
                              account->gpg_key_id);
                    runtime_state_lock_release(runtime_lock_fd);
                    return -1;
                }
            }
        }

        /* Prove the host-alias sink is readable and policy-compliant before
         * arming rollback. The actual writer remains the final commit.
         * Skipped on resume for the same reason write_git is forced false:
         * ~/.ssh/config is persistent state the original switch already
         * wrote, so resume has no business reading or rewriting it — and the
         * preflight's symlink refusal (correct for an interactive switch)
         * otherwise aborted resume BEFORE agent restoration for every
         * dotfile-managed ~/.ssh/config (chezmoi/stow/yadm), re-failing on
         * each login shell (AR-05 M1). */
        if (!ctx->config.resuming && ssh_user_config_preflight(account) != 0) {
            runtime_state_lock_release(runtime_lock_fd);
            return -1;
        }

        /* AR-07 M24: snapshot capture is part of read-only preflight, not the
         * later Git-write step. A failed/truncated/oversized config read must
         * stop before an SSH agent is spawned or GNUPGHOME is repointed;
         * runtime rollback after such a rejection is avoidable mutation, not
         * an acceptable substitute for fail-before-mutation. */
        if (write_git && git_config_snapshot(scope) != 0) {
            char detail[sizeof(g_last_error.message)];

            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            runtime_state_lock_release(runtime_lock_fd);
            set_error(ERR_GIT_CONFIG_FAILED,
                      "Cannot snapshot Git configuration before switching: %s",
                      detail[0] ? detail : "unknown snapshot error");
            return -1;
        }

        /* Nothing durable has been touched yet, so a signal up to here could
         * simply kill us. From this point on, mutations begin: guard. On
         * success the guard stays armed all the way through main()'s
         * config_save (M3) — only the failure paths (abort_failed_switch)
         * drop it here in accounts.c.
         *
         * The config-save temp file is NOT registered here: this function's
         * success path still clears the scratch registry, so a registration
         * here would never cover the save (AR-02 #27). config_save registers
         * its own temp path under the guard this function leaves armed. */
        signals_guard_begin();

        /* A prior successful accounts_switch() can leave an owned agent in
         * this process's session state. Stopping it is a real mutation: do it
         * only after every read-only validation has passed and the signal
         * guard is armed. If any later step fails, `ssh_dirty` makes rollback
         * restart the previous account's agent. This ordering also means an
         * early failure on a repeated switch leaves the live session entirely
         * untouched. */
        ssh_dirty = g_session.ssh_active;
        if (accounts_session_cleanup() != 0) {
            char detail[sizeof(g_last_error.message)];
            bool rollback_complete = true;

            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            /* Cleanup is ordered SSH then GPG. A GPG restoration failure can
             * therefore arrive after the previous agent was already reaped.
             * Route through the central checked abort path so that exact SSH
             * mutation is reactivated, while the untouched manager-owned GPG
             * retry record remains in g_session for accounts_session_cleanup(). */
            abort_failed_switch_checked(prev_account, prev_gpg_home,
                                        prev_gpg_present, false, ssh_dirty,
                                        false, runtime_lock_fd,
                                        !defer_signal_dispatch,
                                        defer_signal_dispatch,
                                        NULL, NULL, NULL,
                                        &rollback_complete);
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
            return abort_failed_switch(prev_account, prev_gpg_home,
                                       prev_gpg_present, false, ssh_dirty, false,
                                       runtime_lock_fd,
                                       defer_signal_dispatch);
        }

        /* AR-05 M4: the FORWARD mutation window (SSH agent spawn/repoint, GPG
         * `current` retarget, git identity write) needs the same second-signal
         * deferral the rollback and deferred-teardown blocks already get. A
         * second directed signal here used to take the handler's emergency
         * exit: no git_config_restore, no deactivate_runtime_isolation —
         * current.sock/GNUPGHOME left on the NEW account while git named the
         * OLD one, plus a daemonized ssh-agent holding the freshly-decrypted
         * key leaked until reboot. With the flag up, the repeat signal instead
         * forwards to the in-flight child (killing a stuck ssh-add/pinentry
         * prompt), the blocked step fails or returns, and the mainline reaches
         * its signals_pending() checkpoint and runs abort_failed_switch —
         * which re-arms and then clears the flag itself before returning. */
        signals_rollback_begin();

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
                abort_failed_switch(prev_account, prev_gpg_home,
                                    prev_gpg_present, false, ssh_dirty, false,
                                    runtime_lock_fd,
                                    defer_signal_dispatch);
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "Failed to set up SSH for account: %s", account->name);
                return -1;
            }
            ssh_dirty = true;
            if (ssh_switch_account(&g_session.ssh_config, &runtime_target) != 0) {
                printf("  [!!] SSH key failed to load\n");
                (void)ssh_manager_cleanup(&g_session.ssh_config);
                abort_failed_switch(prev_account, prev_gpg_home,
                                    prev_gpg_present, false, ssh_dirty, false,
                                    runtime_lock_fd,
                                    defer_signal_dispatch);
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "Failed to set up SSH for account: %s", account->name);
                return -1;
            }
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
            return abort_failed_switch(prev_account, prev_gpg_home,
                                       prev_gpg_present, false, ssh_dirty, false,
                                       runtime_lock_fd,
                                       defer_signal_dispatch);
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
                abort_failed_switch(prev_account, prev_gpg_home,
                                    prev_gpg_present, false, ssh_dirty,
                                    gpg_dirty,
                                    runtime_lock_fd,
                                    defer_signal_dispatch);
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
                abort_failed_switch(prev_account, prev_gpg_home,
                                    prev_gpg_present, false, ssh_dirty,
                                    gpg_dirty, runtime_lock_fd,
                                    defer_signal_dispatch);
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
            return abort_failed_switch(prev_account, prev_gpg_home,
                                       prev_gpg_present, false, ssh_dirty, gpg_dirty,
                                       runtime_lock_fd,
                                       defer_signal_dispatch);
        }

        /* --- 4. Git identity (preflight-snapshotted and reversible) --- */
        if (write_git) {
            if (git_set_config(&switch_target, scope) != 0) {
                abort_failed_switch(prev_account, prev_gpg_home,
                                    prev_gpg_present, true, ssh_dirty, gpg_dirty,
                                    runtime_lock_fd,
                                    defer_signal_dispatch);
                set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git configuration");
                return -1;
            }
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                if (gpg_configure_git_signing(&g_session.gpg_config,
                                              &switch_target, scope) != 0) {
                    abort_failed_switch(prev_account, prev_gpg_home,
                                        prev_gpg_present, true, ssh_dirty, gpg_dirty,
                                        runtime_lock_fd,
                                        defer_signal_dispatch);
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

        /* Forward mutations are complete and mutually consistent (runtime and
         * git identity both name the new account), so the M4 deferral window
         * closes here; the deferred-teardown block below re-arms its own. */
        signals_rollback_end();

        /* Last all-or-nothing checkpoint: a signal up to here rolls the whole
         * switch back (git config, when written, was just written — restore it
         * too; on resume nothing was written, so nothing to restore). */
        if (signals_pending()) {
            return abort_failed_switch(prev_account, prev_gpg_home,
                                       prev_gpg_present, write_git,
                                       ssh_dirty, gpg_dirty, runtime_lock_fd,
                                       defer_signal_dispatch);
        }

        /* NOW run the teardown deferred from steps 2-3 — only once the switch
         * is known-good may the previous account's agent / keyring entry
         * point be dropped (F4). L7: the reap is multi-step (identify,
         * SIGTERM, confirm, unlink current.sock/GNUPGHOME current), so a
         * SECOND guarded signal mid-teardown must not take the handler's
         * emergency exit — that leaves the previous account's live agent
         * behind the just-applied new git identity. Same deferral the failed-
         * switch rollback gets. */
        signals_rollback_begin();
        int deactivation_rc = deactivate_runtime_isolation(
            ssh_teardown_deferred, gpg_teardown_deferred);
        signals_rollback_end();
        if (deactivation_rc != 0) {
            char detail[sizeof(g_last_error.message)];
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            ssh_dirty = ssh_dirty || ssh_teardown_deferred;
            gpg_dirty = gpg_dirty || gpg_teardown_deferred;
            abort_failed_switch(prev_account, prev_gpg_home,
                                prev_gpg_present, write_git,
                                ssh_dirty, gpg_dirty, runtime_lock_fd,
                                defer_signal_dispatch);
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
         * accounts_switch_commit(): otherwise a later active/hint save failure
         * could roll Git/runtime back while leaving the new user-file mapping.
         * The writer uses a no-follow read plus atomic rename and makes no
         * durable change when it refuses. Resume skips the persistent file. */
        if (!defer_commit && !ctx->config.resuming &&
            account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
            strlen(account->ssh_host_alias) > 0 &&
            ssh_configure_host_alias(&switch_target) != 0) {
            char detail[sizeof(g_last_error.message)];
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
            abort_failed_switch(prev_account, prev_gpg_home,
                                prev_gpg_present, write_git,
                                ssh_dirty, gpg_dirty, runtime_lock_fd,
                                defer_signal_dispatch);
            set_error(ERR_FILE_IO,
                      "Failed to commit SSH host alias for account '%s': %s",
                      account->name,
                      detail[0] ? detail : "unknown SSH config error");
            return -1;
        }

        signals_scratch_cleanup();
        if (defer_commit) {
            memset(&g_pending_switch, 0, sizeof(g_pending_switch));
            g_pending_switch.active = true;
            g_pending_switch.ctx = ctx;
            if (prev_account) {
                g_pending_switch.previous_account = *prev_account;
                g_pending_switch.had_previous_account = true;
            }
            safe_strncpy(g_pending_switch.previous_active, prev_active,
                         sizeof(g_pending_switch.previous_active));
            safe_strncpy(g_pending_switch.previous_gpg_home, prev_gpg_home,
                         sizeof(g_pending_switch.previous_gpg_home));
            g_pending_switch.previous_gpg_present = prev_gpg_present;
            g_pending_switch.git_written = write_git;
            g_pending_switch.ssh_dirty = ssh_dirty;
            g_pending_switch.gpg_dirty = gpg_dirty;
            g_pending_switch.runtime_lock_fd = runtime_lock_fd;
            g_pending_switch.target_id = account->id;
            g_pending_switch.switch_target = switch_target;
            g_pending_switch.scope = scope;
            g_pending_switch.ssh_ok = ssh_ok;
            g_pending_switch.gpg_ok = gpg_ok;
        } else {
            /* Direct callers retain the historical one-call commit. Release
             * the cross-manager lock before best-effort probes. */
            runtime_state_lock_release(runtime_lock_fd);
            runtime_lock_fd = -1;
        }

        /* M3: the guard deliberately STAYS armed here. Dropping it used to
         * open an unguarded stretch — the tip block below, main()'s
         * active_account bookkeeping, everything up to config_save — where a
         * fresh SIGINT/HUP/TERM killed with the default action: git config
         * and the runtime symlinks named the new account while accounts.toml
         * kept the old active_account, so the next boot's resume restored the
         * wrong identity. The guard now runs continuously from the mutation
         * start through main()'s save-after-switch (its signals_guard_begin
         * is a no-op re-begin that preserves a deferred signal), and main()
         * ends it once the state is persisted. */
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
                          ssh_ok, gpg_ok);
    return 0;
}

int accounts_switch(gitswitch_ctx_t *ctx, const char *identifier) {
    return accounts_switch_impl(ctx, identifier, false);
}

int accounts_switch_prepare(gitswitch_ctx_t *ctx, const char *identifier) {
    if (!ctx || ctx->config.dry_run || ctx->config.resuming) {
        set_error(ERR_INVALID_ARGS,
                  "A transactional switch requires a non-preview CLI switch");
        return -1;
    }
    return accounts_switch_impl(ctx, identifier, true);
}

int accounts_switch_commit(gitswitch_ctx_t *ctx) {
    account_t *target = NULL;

    if (!g_pending_switch.active || !ctx || g_pending_switch.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account switch to commit");
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == g_pending_switch.target_id) {
            target = &ctx->accounts[i];
            break;
        }
    }
    if (!target) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Prepared switch target disappeared before commit");
        return -1;
    }

    /* This is the prepared switch's final required user-file commit. It runs
     * only after active_account and the resume hint are durable, but before
     * pending rollback ownership or the runtime lock is released. Failure
     * therefore lets main reverse every earlier commit as one transaction. */
    if (target->ssh_enabled && target->ssh_key_path[0] != '\0' &&
        target->ssh_host_alias[0] != '\0' &&
        ssh_configure_host_alias(&g_pending_switch.switch_target) != 0) {
        return -1;
    }

    runtime_state_lock_release(g_pending_switch.runtime_lock_fd);
    g_pending_switch.runtime_lock_fd = -1;
    finish_switch_success(ctx, target, &g_pending_switch.switch_target,
                          g_pending_switch.scope,
                          g_pending_switch.git_written,
                          g_pending_switch.ssh_ok,
                          g_pending_switch.gpg_ok);
    memset(&g_pending_switch, 0, sizeof(g_pending_switch));
    return 0;
}

int accounts_switch_abort(gitswitch_ctx_t *ctx,
                          bool continue_persistence_rollback) {
    pending_switch_t pending;
    const account_t *previous = NULL;
    bool rollback_complete = true;

    if (!g_pending_switch.active || !ctx || g_pending_switch.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account switch to roll back");
        return -1;
    }

    pending = g_pending_switch;
    if (pending.runtime_lock_fd < 0) {
        pending.runtime_lock_fd = runtime_state_lock_acquire();
        if (pending.runtime_lock_fd < 0) {
            return -1;
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
                                !continue_persistence_rollback,
                                continue_persistence_rollback,
                                &pending.git_written,
                                &pending.ssh_dirty,
                                &pending.gpg_dirty,
                                &rollback_complete);
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
         * components are not replayed, and the runtime lock is reacquired. */
        g_pending_switch = pending;
        set_error(ERR_SYSTEM_CALL,
                  "The prepared switch could not be rolled back completely; "
                  "inspect Git and runtime state before retrying");
        return -1;
    }
    memset(&g_pending_switch, 0, sizeof(g_pending_switch));
    return 0;
}

/* Fields whose persisted value must agree with the live Git/SSH/GPG state.
 * Description is intentionally excluded: it is metadata-only and safe to
 * update while the account is active. */
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
           strcmp(a->gpg_key_id, b->gpg_key_id) == 0;
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
    return a && b && strcmp(a->name, b->name) == 0 &&
           a->ssh_enabled == b->ssh_enabled &&
           strcmp(a->ssh_key_path, b->ssh_key_path) == 0;
}

static bool account_gpg_runtime_identity_equal(const account_t *a,
                                               const account_t *b) {
    return a && b && strcmp(a->name, b->name) == 0 &&
           a->gpg_enabled == b->gpg_enabled &&
           strcmp(a->gpg_key_id, b->gpg_key_id) == 0;
}

static int restore_pending_edit_alias(void) {
    bool complete = true;
    char detail[sizeof(g_last_error.message)] = "";
    const account_t *original = &g_pending_edit.original;
    const account_t *candidate = &g_pending_edit.candidate;

    if (!g_pending_edit.routing_changed) return 0;

    if (g_pending_edit.candidate_alias_attempted) {
        if (account_has_managed_alias(candidate) &&
            account_has_managed_alias(original) &&
            string_ascii_case_equal(candidate->ssh_host_alias,
                                    original->ssh_host_alias) &&
            g_pending_edit.original_alias_exclusive) {
            if (ssh_configure_host_alias(original) != 0) {
                complete = false;
                safe_strncpy(detail, get_last_error()->message,
                             sizeof(detail));
            }
        } else if (candidate->ssh_host_alias[0] != '\0' &&
                   ssh_remove_host_alias(candidate->ssh_host_alias) != 0) {
            complete = false;
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
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
            safe_strncpy(detail, get_last_error()->message, sizeof(detail));
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

    if (!ctx || !g_pending_edit.active || g_pending_edit.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account edit to roll back");
        return -1;
    }

    alias_rc = restore_pending_edit_alias();
    slot = account_by_id(ctx, g_pending_edit.original.id);
    if (!slot) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Edited account disappeared before rollback");
        return -1;
    }
    secure_zero_memory(slot, sizeof(*slot));
    *slot = g_pending_edit.original;

    if (alias_rc != 0) return -1;
    memset(&g_pending_edit, 0, sizeof(g_pending_edit));
    return 0;
}

int accounts_edit_commit(gitswitch_ctx_t *ctx) {
    if (!ctx || !g_pending_edit.active || g_pending_edit.ctx != ctx) {
        set_error(ERR_INVALID_ARGS, "No prepared account edit to commit");
        return -1;
    }
    memset(&g_pending_edit, 0, sizeof(g_pending_edit));
    return 0;
}

int accounts_edit_candidate_prepare(gitswitch_ctx_t *ctx,
                                    const account_t *candidate) {
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
    if (g_pending_edit.active) {
        set_error(ERR_SYSTEM_CALL,
                  "A prepared account edit is already awaiting completion");
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
    if (config_update_account(ctx, &edited) != 0) {
        memset(&g_pending_edit, 0, sizeof(g_pending_edit));
        return -1;
    }
    g_pending_edit.active = true;
    signals_guard_begin();
    signals_rollback_begin();

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
            error_context_t cause = *get_last_error();
            set_error(ERR_GPG_KEY_NOT_FOUND,
                      "Cannot change GPG identity for account '%s': edited "
                      "key '%s' is not available in the real/system keyring. "
                      "Import its secret key into the system keyring, then "
                      "retry the edit (%s).",
                      g_pending_edit.original.name, edited.gpg_key_id,
                      cause.message[0] ? cause.message : "key probe failed");
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
        /* Transactional callers (main) own the final cleanup and re-raise.
         * Leave a pending signal guarded and rollback-class until that common
         * tail has released the config lock and securely freed its context. */
        if (!ctx->config.defer_signal_cleanup) {
            signals_rollback_end();
            signals_guard_end();
            if (signals_pending()) signals_dispatch_pending();
        }
        return -1;
    }
}

/* Shared interactive add/edit flow. `existing` is NULL for add, or points at
 * the account being edited (in which case every prompt shows the current value
 * as the default and an empty answer keeps it). Routes all input through
 * prompt_line so readline builds get line editing and TAB path completion. */
static int add_or_edit_account(gitswitch_ctx_t *ctx, account_t *existing) {
    account_t acct;
    char input[512];
    char expanded_path[MAX_PATH_LEN];
    bool edit = (existing != NULL);

    if (edit) {
        acct = *existing;
    } else {
        memset(&acct, 0, sizeof(acct));
        acct.id = get_next_available_id(ctx);
        acct.preferred_scope = ctx->config.default_scope;
    }

    printf("\n┌─────────────────────────────────────┐\n");
    printf("│ %-35s │\n", edit ? "Edit Account" : "Add New Account");
    printf("└─────────────────────────────────────┘\n\n");

    /* Name */
    while (1) {
        if (edit) printf("Account Name [%s]: ", acct.name);
        else      printf("Account Name: ");
        if (prompt_line("", input, sizeof(input), false) != 0 && !edit) {
            set_error(ERR_FILE_IO, "Failed to read account name");
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
        if (edit) printf("Email Address [%s]: ", acct.email);
        else      printf("Email Address: ");
        if (prompt_line("", input, sizeof(input), false) != 0 && !edit) {
            set_error(ERR_FILE_IO, "Failed to read email address");
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

    /* Description */
    if (edit) printf("Description [%s]: ", acct.description);
    else      printf("Description (optional): ");
    if (prompt_line("", input, sizeof(input), false) == 0 && strlen(input) > 0) {
        safe_strncpy(acct.description, input, sizeof(acct.description));
    } else if (!edit) {
        safe_strncpy(acct.description, acct.name, sizeof(acct.description));
    }

    /* SSH key. Empty keeps current (edit) or skips (add); 'none' disables.
     * Re-prompt on a bad path rather than silently dropping SSH. */
    while (1) {
        if (edit && acct.ssh_enabled)
            printf("SSH Key Path [%s] (Enter to keep, 'none' to disable): ", acct.ssh_key_path);
        else
            printf("SSH Key Path (optional, Enter to skip): ");
        if (prompt_line("", input, sizeof(input), true) != 0) break;

        if (strlen(input) == 0) break;                 /* keep/skip */
        if (strcmp(input, "none") == 0) {              /* disable */
            acct.ssh_enabled = false;
            acct.ssh_key_path[0] = '\0';
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
        safe_strncpy(acct.ssh_key_path, expanded_path, sizeof(acct.ssh_key_path));
        acct.ssh_enabled = true;
        printf("[OK]: SSH key validated: %s\n", expanded_path);

        /* L2: the alias lands verbatim in a "Host <alias>" line of
         * ~/.ssh/config, so gate it here the way the writer will (charset)
         * and to what the account field can hold (length) — the old single-
         * shot prompt let a >=256-char alias fail safe_strncpy silently and
         * reported success with the alias dropped. Re-prompt on rejection. */
        while (1) {
            if (edit && acct.ssh_host_alias[0])
                printf("SSH Host Alias [%s] (Enter to keep): ", acct.ssh_host_alias);
            else
                printf("SSH Host Alias (optional, e.g., github.com-work): ");
            if (prompt_line("", input, sizeof(input), false) != 0 ||
                strlen(input) == 0) {
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
        break;
    }

    /* GPG key. Same empty/'none' semantics as SSH. */
    while (1) {
        if (edit && acct.gpg_enabled)
            printf("GPG Key ID [%s] (Enter to keep, 'none' to disable): ", acct.gpg_key_id);
        else
            printf("GPG Key ID (optional, Enter to skip): ");
        if (prompt_line("", input, sizeof(input), false) != 0) break;

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
            printf("[ERROR]: GPG key not found in keyring: %s (try again, or Enter to skip)\n", input);
            continue;
        }
        safe_strncpy(acct.gpg_key_id, input, sizeof(acct.gpg_key_id));
        acct.gpg_enabled = true;
        printf("[OK]: GPG key validated: %s\n", input);

        printf("Enable GPG signing for commits? (y/N)%s: ",
               (edit && acct.gpg_signing_enabled) ? " [Y]" : "");
        if (prompt_line("", input, sizeof(input), false) == 0 && strlen(input) > 0) {
            acct.gpg_signing_enabled = (tolower((unsigned char)input[0]) == 'y');
        }
        break;
    }

    /* Preferred scope. Validate; empty keeps the shown default. */
    while (1) {
        printf("Preferred Git Scope (local/global) [%s]: ",
               config_scope_to_string(acct.preferred_scope));
        if (prompt_line("", input, sizeof(input), false) != 0) break;
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
        printf("\n%s this account? (y/N): ", edit ? "Save changes to" : "Add");
        if (prompt_line("", input, sizeof(input), false) != 0 || tolower((unsigned char)input[0]) != 'y') {
            printf("%s cancelled.\n", edit ? "Edit" : "Account creation");
            return -1;
        }
    }

    if (edit) {
        return accounts_edit_candidate_prepare(ctx, &acct);
    }

    if (config_add_account(ctx, &acct) != 0) {
        return -1;
    }
    return 0;
}

/* Add new account interactively with basic validation */
int accounts_add_interactive(gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_add_interactive");
        return -1;
    }
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    return add_or_edit_account(ctx, NULL);
}

int accounts_edit_interactive_prepare(gitswitch_ctx_t *ctx,
                                      const char *identifier) {
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to accounts_edit_interactive_prepare");
        return -1;
    }
    account_t *account = config_find_account(ctx, identifier);
    if (!account) {
        return -1; /* error already set with candidate list */
    }
    return add_or_edit_account(ctx, account);
}

/* Direct/library compatibility: callers that do not own the CLI persistence
 * transaction retain the historical one-call in-memory edit behavior. */
int accounts_edit_interactive(gitswitch_ctx_t *ctx, const char *identifier) {
    if (accounts_edit_interactive_prepare(ctx, identifier) != 0) {
        signals_rollback_end();
        signals_guard_end();
        if (signals_pending()) signals_dispatch_pending();
        return -1;
    }
    if (accounts_edit_commit(ctx) != 0) {
        signals_rollback_end();
        signals_guard_end();
        if (signals_pending()) signals_dispatch_pending();
        return -1;
    }
    signals_rollback_end();
    signals_guard_end();
    if (signals_pending()) signals_dispatch_pending();
    return 0;
}

/* Remove account with confirmation and cleanup */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    char input[64];
    char account_name[MAX_NAME_LEN];
    char ssh_error[sizeof(g_last_error.message)] = "";
    char gpg_error[sizeof(g_last_error.message)] = "";
    uint32_t account_id;
    uint32_t current_id = 0;
    bool had_current;
    bool was_current;
    bool was_active;
    bool removed_alias_exclusive;
    int ssh_rc;
    int gpg_rc;
    int runtime_lock_fd;
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_remove");
        return -1;
    }
    
    /* Find the account. AR-06 F50: destructive resolution (exact id/name/email
     * only) — never a substring, so `remove work` can't delete "work-old". */
    account = config_find_account_destructive(ctx, identifier);
    if (!account) {
        return -1; /* error already set with an explanatory message */
    }
    
    /* Show account details */
    printf("\nRemove Account\n");
    printf("─────────────────\n");
    printf("ID: %u\n", account->id);
    printf("Name: %s\n", account->name);
    printf("Email: %s\n", account->email);
    printf("Description: %s\n", account->description);
    
    /* Confirmation (--yes skips it for scripting). */
    if (!ctx->config.assume_yes) {
        printf("\n[WARN]: This will permanently remove the account from configuration.\n");
        printf("Are you sure? (type 'yes' to confirm): ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) {
            set_error(ERR_FILE_IO, "Failed to read confirmation");
            return -1;
        }

        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);

        if (strcmp(input, "yes") != 0) {
            printf("Account removal cancelled.\n");
            return 0;
        }
    }
    
    if (safe_strncpy(account_name, account->name, sizeof(account_name)) != 0) {
        return -1;
    }
    /* Capture the managed SSH host alias before teardown so it can be removed
     * from ~/.ssh/config after the account is gone (AR-06 F15). */
    char removed_alias[MAX_NAME_LEN];
    removed_alias[0] = '\0';
    safe_strncpy(removed_alias, account->ssh_host_alias, sizeof(removed_alias));
    removed_alias_exclusive = account_alias_exclusively_owned(
        ctx, account->id, removed_alias);
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

    /* Tear down while the account name still exists as a retry handle. Both
     * managers are attempted; any failure retains the account/current/active
     * state so `remove` or targeted `reset` can be retried safely. */
    runtime_lock_fd = runtime_state_lock_acquire();
    if (runtime_lock_fd < 0) {
        return -1;
    }
    ssh_rc = ssh_manager_reset(account_name);
    if (ssh_rc != 0) {
        snprintf(ssh_error, sizeof(ssh_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown SSH teardown error");
    }
    gpg_rc = gpg_manager_reset(account_name);
    if (gpg_rc != 0) {
        snprintf(gpg_error, sizeof(gpg_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown GPG teardown error");
    }
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
        return -1;
    }
    
    /* Only a complete teardown permits deleting the configuration handle. */
    if (config_remove_account(ctx, account_id) != 0) {
        return -1;
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

    /* Remove the managed ~/.ssh/config host-alias block so git traffic no
     * longer routes to the deleted account's key (AR-06 F15). Best-effort: the
     * account is already gone from config, so a failure here only leaves a
     * stale (visible) stanza — warn rather than fail the whole removal. */
    if (removed_alias[0] != '\0' && !removed_alias_exclusive) {
        log_warning("Retaining shared ~/.ssh/config host-alias block for '%s'; "
                    "another account still claims the same alias",
                    removed_alias);
    } else if (removed_alias[0] != '\0' &&
               ssh_remove_host_alias(removed_alias) != 0) {
        log_warning("Could not remove ~/.ssh/config host-alias block for '%s': %s",
                    removed_alias, get_last_error()->message);
    }

    return 0;
}

/* List all configured accounts */
int accounts_list(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_list");
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

/* Git origin strings contain filesystem paths. Keep diagnostics single-line
 * and terminal-safe even when a repository/config filename contains control
 * characters or arbitrary non-UTF-8 bytes. Escaping backslashes as well makes
 * the byte representation unambiguous. */
static void print_terminal_safe(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;

    if (!cursor) return;
    for (; *cursor != '\0'; cursor++) {
        if (*cursor >= 0x20 && *cursor <= 0x7e && *cursor != '\\') {
            putchar((int)*cursor);
        } else if (*cursor == '\\') {
            fputs("\\\\", stdout);
        } else {
            printf("\\x%02X", (unsigned int)*cursor);
        }
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

/* Show current account status */
int accounts_show_status(const gitswitch_ctx_t *ctx) {
    int status_result = 0;
    git_current_config_t *git_config = NULL;

    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_show_status");
        return -1;
    }
    
    printf("\nAccount Status\n");
    printf("════════════════\n");
    
    if (ctx->current_account) {
        const account_t *account = ctx->current_account;
        
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
                printf("  Key File: [ERROR] Unable to inspect safely\n");
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
        git_config = calloc(1, sizeof(*git_config));
        if (!git_config) {
            set_error(ERR_SYSTEM_CALL,
                      "Cannot allocate Git status snapshot: %s",
                      strerror(errno));
            if (print_git_status_read_failure() != 0) status_result = -1;
        } else if (git_get_current_config(git_config) == 0) {
            char expected_ssh[GIT_CONFIG_VALUE_MAX] = "";
            char ssh_status_error[512] = "";
            bool identity_matches;
            bool ssh_matches;
            bool ssh_status_determined = true;
            bool gpg_program_matches;

            printf("  Current Name: %s\n", git_config->name);
            printf("  Current Email: %s\n", git_config->email);
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
            if (account->ssh_enabled && account->ssh_key_path[0] != '\0') {
                if (git_expected_ssh_command(account, expected_ssh,
                                             sizeof(expected_ssh)) != 0) {
                    const error_context_t *error = get_last_error();
                    ssh_status_determined = false;
                    ssh_matches = false;
                    status_result = -1;
                    if (error && error->message[0] != '\0') {
                        (void)snprintf(ssh_status_error,
                                       sizeof(ssh_status_error), "%s",
                                       error->message);
                    }
                } else {
                    ssh_matches =
                        git_config->ssh_command.present &&
                        !git_config->ssh_command.value_unknown &&
                        strcmp(git_config->ssh_command.value, expected_ssh) == 0;
                }
            } else {
                ssh_matches = !git_config->ssh_command.present;
            }
            /* gitswitch selects an isolated keyring through GNUPGHOME and
             * intentionally expects no persisted gpg.program override. */
            gpg_program_matches = !git_config->gpg_program.present;
            
            /* Check if git config matches account */
            if (!ssh_status_determined) {
                printf("  Match Status: [ERROR] Unable to determine trusted expected SSH command");
                if (ssh_status_error[0] != '\0') {
                    printf(": ");
                    print_terminal_safe(ssh_status_error);
                }
                printf("\n");
            } else if (identity_matches && ssh_matches && gpg_program_matches) {
                printf("  Match Status: [OK] Git config matches account\n");
            } else {
                printf("  Match Status: [WARN] Git config does not match account\n");
                if (!identity_matches) {
                    printf("    Expected: %s <%s>\n", account->name, account->email);
                    printf("    Current:  %s <%s>\n", git_config->name, git_config->email);
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
            printf("  Effective GPG Program: %s",
                   gpg_program_matches ? "[ABSENT]" : "[MISMATCH]");
            print_git_value_origin(&git_config->gpg_program);
            printf("\n");
            
            /* GPG signing status */
            if (strlen(git_config->signing_key) > 0) {
                printf("  GPG Signing Key: %s\n", git_config->signing_key);
                printf("  GPG Signing Enabled: %s\n", git_config->gpg_signing_enabled ? "[YES]" : "[NO]");
            } else {
                printf("  GPG Signing: [NOT CONFIGURED]\n");
            }
        } else {
            if (print_git_status_read_failure() != 0) status_result = -1;
        }
        
        /* Repository context */
        printf("\nRepository Context:\n");
        if (git_is_repository()) {
            char repo_root[MAX_PATH_LEN];
            if (git_get_repo_root(repo_root, sizeof(repo_root)) == 0) {
                printf("  Repository: [FOUND] %s\n", repo_root);
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
        git_config = calloc(1, sizeof(*git_config));
        if (!git_config) {
            set_error(ERR_SYSTEM_CALL,
                      "Cannot allocate Git status snapshot: %s",
                      strerror(errno));
            if (print_git_status_read_failure() != 0) status_result = -1;
        } else if (git_get_current_config(git_config) == 0) {
            printf("  Name: %s\n", git_config->name);
            printf("  Email: %s\n", git_config->email);
            printf("  Scope: %s\n",
                   git_config_origin_scope_to_string(
                       git_config->effective_name_scope));
        } else {
            if (print_git_status_read_failure() != 0) status_result = -1;
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
    return status_result;
}

/* Simple account validation for Phase 2 */
int accounts_validate(const account_t *account) {
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account pointer");
        return -1;
    }
    
    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid or empty account name");
        return -1;
    }
    
    if (!validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address format");
        return -1;
    }
    
    /* Basic SSH validation if enabled */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        char expanded_path[MAX_PATH_LEN];
        
        if (expand_path(account->ssh_key_path, expanded_path, sizeof(expanded_path)) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH key path: %s", account->ssh_key_path);
            return -1;
        }
        
        if (ssh_validate_key_file(expanded_path) != 0) return -1;
    }
    
    /* Basic GPG validation if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (!validate_key_id(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID format: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    return 0;
}

/* Get next available account ID */
static uint32_t get_next_available_id(const gitswitch_ctx_t *ctx) {
    uint32_t max_id = 0;

    if (!ctx) return 1;

    /* Find the highest existing ID */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id > max_id) {
            max_id = ctx->accounts[i].id;
        }
    }

    if (max_id < UINT32_MAX) {
        return max_id + 1;
    }

    /* L3: the loader accepts ids up to UINT32_MAX, so a hand-planted
     * [accounts.4294967295] made max_id+1 wrap to 0 — an id the loader
     * rejects, which wedged every future save behind the data-loss guard.
     * Fall back to the lowest unused positive id; with at most MAX_ACCOUNTS
     * entries one always exists in [1, MAX_ACCOUNTS+1]. */
    for (uint32_t candidate = 1; candidate <= (uint32_t)MAX_ACCOUNTS + 1; candidate++) {
        bool used = false;
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].id == candidate) {
                used = true;
                break;
            }
        }
        if (!used) {
            return candidate;
        }
    }
    return 1; /* unreachable: account_count <= MAX_ACCOUNTS */
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

/* Validate GPG key availability.
 * Checks the *system* keyring — but with an explicit GNUPGHOME override to the
 * user's REAL keyring home (AR-06 F05/F06). `gitswitch init` exports
 * GNUPGHOME=<base>/current into interactive shells; without the override this
 * probe would inherit that managed value and list the previously-active
 * account's isolated home, hard-failing every cross-account switch with a
 * misleading "key not found". This is the fallback sanity check run from
 * accounts_switch() when the isolated GPG path did not already confirm the key
 * (gpg_ok), and during health checks. The isolated-home validation lives in
 * gpg_validate_key()/gpg_test_signing(). */
static int validate_gpg_key_availability_mode(const char *gpg_key_id,
                                              bool allow_cached) {
    if (!gpg_key_id) {
        return -1;
    }

    /* A gpg spawn earlier in this process already proved this key's presence
     * — don't fork gpg again just to re-ask (AR-02 #14). */
    if (allow_cached && gpg_manager_key_available_cached(gpg_key_id)) {
        return 0;
    }

    /* Look up the key in the system keyring, no shell. */
    const char *argv[] = {"gpg", "--list-secret-keys", gpg_key_id, NULL};
    run_opts_t opts;
    char source_home[MAX_PATH_LEN];
    char source_env_str[MAX_PATH_LEN + sizeof("GNUPGHOME=")];
    const char *source_env[2] = {NULL, NULL};
    memset(&opts, 0, sizeof(opts));
    opts.stderr_to_devnull = true;
    if (gpg_manager_system_keyring_home(source_home, sizeof(source_home)) != 0) {
        log_debug("Could not resolve the real/system GPG keyring home");
        set_error(ERR_GPG_KEY_NOT_FOUND,
                  "Cannot resolve the real/system GPG keyring home");
        return -1;
    }
    snprintf(source_env_str, sizeof(source_env_str), "GNUPGHOME=%s", source_home);
    source_env[0] = source_env_str;
    opts.extra_env = source_env;

    if (run_argv(argv, &opts, NULL) != 0) {
        log_debug("GPG key %s not found in keyring", gpg_key_id);
        set_error(ERR_GPG_KEY_NOT_FOUND,
                  "GPG secret key not found in the real/system keyring: %s",
                  gpg_key_id);
        return -1;
    }

    gpg_manager_note_key_available(gpg_key_id);
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

/* Test SSH key functionality */
static int test_ssh_key_functionality(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];
    /* This is a placeholder for SSH functionality testing
     * In a full implementation, this would:
     * 1. Start SSH agent if needed
     * 2. Load the key into agent
     * 3. Test connection to a known host
     * 4. Verify authentication works
     */
    log_debug("SSH key functionality test for %s: %s", 
              account->name, account->ssh_key_path);
    
    if (expand_path(account->ssh_key_path, expanded_path,
                    sizeof(expanded_path)) != 0) return -1;
    return ssh_validate_key_file(expanded_path);
}

/* Test GPG key functionality */
static int test_gpg_key_functionality(const account_t *account) {
    /* This is a placeholder for GPG functionality testing
     * In a full implementation, this would:
     * 1. Set up GPG environment
     * 2. Test key can be used for signing
     * 3. Verify key is not expired
     * 4. Test signing a test message
     */
    log_debug("GPG key functionality test for %s: %s", 
              account->name, account->gpg_key_id);
    
    /* For now, just check if key exists in keyring */
    return validate_gpg_key_availability(account->gpg_key_id);
}

/* Run comprehensive health check on all accounts */
int accounts_health_check(const gitswitch_ctx_t *ctx) {
    bool all_healthy = true;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_health_check");
        return -1;
    }
    
    printf("\nAccount Health Check\n");
    printf("══════════════════════\n");
    
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
            printf("[OK]: Account configuration valid\n");
            
            /* Test SSH if configured */
            if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
                if (test_ssh_key_functionality(account) == 0) {
                    printf("[OK]: SSH key functional\n");
                } else {
                    printf("[ERROR]: SSH key issues detected\n");
                    all_healthy = false;
                }
            }
            
            /* Test GPG if configured */
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                if (test_gpg_key_functionality(account) == 0) {
                    printf("[OK]: GPG key functional\n");
                } else {
                    printf("[ERROR]: GPG key issues detected\n");
                    all_healthy = false;
                }
            }
        } else {
            printf("[ERROR]: Account validation failed\n");
            all_healthy = false;
        }
    }
    
    printf("\n══════════════════════\n");
    if (all_healthy) {
        printf("[OK]: All accounts are healthy\n\n");
        return 0;
    } else {
        printf("[ERROR]: Some accounts have issues\n\n");
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

    /* Already have a current account set */
    if (ctx->current_account) {
        return 0;
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
