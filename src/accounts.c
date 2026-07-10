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
#include <sys/stat.h>
#include <unistd.h>

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

/* Active session state - tracks SSH/GPG resources for proper cleanup */
typedef struct {
    ssh_config_t ssh_config;
    gpg_config_t gpg_config;
    bool ssh_active;
    bool gpg_active;
    char original_gnupghome[MAX_PATH_LEN];
    bool had_original_gnupghome;
    bool gnupghome_saved;
} active_session_t;

/* Static session state - only one active session at a time */
static active_session_t g_session = {0};

/* Internal helper functions */
static uint32_t get_next_available_id(const gitswitch_ctx_t *ctx);
static int validate_ssh_key_security(const char *ssh_key_path);
static int validate_gpg_key_availability(const char *gpg_key_id);
static int test_ssh_key_functionality(const account_t *account);
static int test_gpg_key_functionality(const account_t *account);

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

/* Clean up active session resources */
void accounts_session_cleanup(void) {
    log_debug("Cleaning up active session resources");

    /* Clean up SSH agent if we started one */
    if (g_session.ssh_active) {
        log_info("Stopping SSH agent (pid=%d)", g_session.ssh_config.agent_pid);
        ssh_manager_cleanup(&g_session.ssh_config);
        g_session.ssh_active = false;
    }

    /* Clean up GPG environment if we modified it */
    if (g_session.gpg_active) {
        log_info("Cleaning up GPG environment");
        gpg_manager_cleanup(&g_session.gpg_config);
        g_session.gpg_active = false;
    }

    /* Restore original GNUPGHOME environment variable */
    if (g_session.gnupghome_saved) {
        if (g_session.had_original_gnupghome) {
            log_debug("Restoring original GNUPGHOME: %s", g_session.original_gnupghome);
            setenv("GNUPGHOME", g_session.original_gnupghome, 1);
        } else {
            log_debug("Unsetting GNUPGHOME (was not set originally)");
            unsetenv("GNUPGHOME");
        }
        g_session.gnupghome_saved = false;
    }

    /* Clear session state */
    memset(&g_session, 0, sizeof(g_session));
    log_debug("Session cleanup complete");
}

/* Deactivate the runtime SSH and/or GPG isolation so the stable entry points
 * (current.sock symlink, GNUPGHOME `current` symlink) no longer point at an
 * account. Used when switching to an account that has SSH/GPG disabled (so the
 * previous account's agent/home doesn't stay live behind the switch) and when
 * rolling back a failed switch. Removing the symlink makes integrated shells
 * fall back to the default agent/keyring rather than silently keep using the
 * old account — the exact mismatch this guards against. */
static void deactivate_runtime_isolation(bool ssh, bool gpg) {
    if (ssh) {
        /* Reaps every gitswitch agent and removes current.sock. */
        ssh_manager_reset(NULL);
        g_session.ssh_active = false;
    }
    if (gpg) {
        char home_symlink[MAX_PATH_LEN];
        if (gpg_manager_get_home_path(home_symlink, sizeof(home_symlink)) == 0) {
            unlink(home_symlink); /* drop the `current` symlink, not its target */
        }
        g_session.gpg_active = false;
    }
}

/* F4: after a failed switch has torn down the runtime isolation, put the
 * PREVIOUSLY-active account's isolation back so the user is not left with git
 * identity rolled back but no working SSH agent / GPG keyring behind it.
 *
 *   - SSH: starting the new account's agent already reaped the previous one
 *     (ssh_start_isolated_agent kills every other gitswitch agent), so restore
 *     means re-activating: restart the agent and reload the key. This may
 *     legitimately re-prompt for a passphrase — annoying, but strictly better
 *     than silently leaving no agent at all. Best-effort: a restore failure
 *     only warns (the rollback of the git identity already succeeded).
 *   - GPG: isolated homes persist on disk (only the stable `current` symlink
 *     moves), so restore is just re-pointing the symlink at the captured
 *     pre-switch target. Fail closed: if the old target vanished, leave the
 *     symlink absent rather than point shells at a missing keyring. */
static void restore_previous_isolation(const account_t *prev,
                                       const char *prev_gpg_home,
                                       bool ssh_torn_down, bool gpg_torn_down) {
    if (ssh_torn_down && prev &&
        prev->ssh_enabled && strlen(prev->ssh_key_path) > 0) {
        printf("  [..] Restoring SSH agent for previous account: %s\n", prev->name);
        memset(&g_session.ssh_config, 0, sizeof(g_session.ssh_config));
        if (ssh_manager_init(&g_session.ssh_config, SSH_AGENT_ISOLATED) == 0 &&
            ssh_switch_account(&g_session.ssh_config, prev) == 0) {
            g_session.ssh_active = true;
            printf("  [OK] Previous SSH agent restored\n");
        } else {
            log_warning("Could not restore SSH agent for previous account: %s",
                        prev->name);
        }
    }

    if (gpg_torn_down && prev_gpg_home && prev_gpg_home[0] != '\0' &&
        is_directory(prev_gpg_home)) {
        char gpg_link[MAX_PATH_LEN];
        if (gpg_manager_get_home_path(gpg_link, sizeof(gpg_link)) == 0 &&
            atomic_symlink(prev_gpg_home, gpg_link) == 0) {
            log_info("Restored GNUPGHOME symlink to previous account home");
        }
    }
}

/* Common exit path for a switch that failed — or was interrupted by a signal —
 * after mutations began. Restores the pre-switch state in dependency order
 * (git identity first, then runtime isolation), cleans scratch files, drops
 * the signal guard, and finally re-raises a pending signal so the process
 * still reports death-by-signal. Returns -1 so callers can
 * `return abort_failed_switch(...)` (callers set their own error afterwards;
 * on the signal path the dispatch terminates the process instead). */
static int abort_failed_switch(const account_t *prev, const char *prev_gpg_home,
                               bool git_written, bool ssh_dirty, bool gpg_dirty) {
    /* AR-02 #2: a second guarded signal during this rollback used to take the
     * handler's emergency-kill branch and die mid-git_config_restore, leaving
     * a chimera (or fully-new) identity persisted. Defer the emergency exit
     * until the whole restore sequence has completed. */
    signals_rollback_begin();
    if (git_written) {
        git_config_restore();
    }
    /* Undo the new account's half-applied SSH/GPG activation: leaving
     * current.sock / GNUPGHOME pointed at the new account while the git
     * identity reverts is exactly the mixed identity the tool prevents. */
    deactivate_runtime_isolation(ssh_dirty, gpg_dirty);
    /* ...and put the previous account's runtime state back (F4). */
    restore_previous_isolation(prev, prev_gpg_home, ssh_dirty, gpg_dirty);
    /* SIG-02: drop any registered scratch temp files. */
    signals_scratch_cleanup();
    signals_rollback_end();
    signals_guard_end();
    if (signals_pending()) {
        fprintf(stderr, "\ngitswitch: interrupted — switch rolled back, previous identity kept\n");
        set_error(ERR_SYSTEM_CALL, "Switch interrupted by signal %d",
                  signals_pending_signal());
        signals_dispatch_pending(); /* terminates via the signal's default action */
    }
    return -1;
}

/* Switch to specified account with SSH isolation and validation */
int accounts_switch(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    const char *scope_str;
    bool ssh_ok = false;
    bool gpg_ok = false;

    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_switch");
        return -1;
    }

    /* Find the account */
    account = config_find_account(ctx, identifier);
    if (!account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: %s", identifier);
        return -1;
    }

    /* Basic validation */
    if (!validate_name(account->name) || !validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Account has invalid name or email");
        return -1;
    }

    /* Clean up any previous session before starting new one */
    accounts_session_cleanup();

    /* Save original GNUPGHOME if not already saved */
    if (!g_session.gnupghome_saved) {
        const char *orig = getenv("GNUPGHOME");
        if (orig) {
            safe_strncpy(g_session.original_gnupghome, orig, sizeof(g_session.original_gnupghome));
            g_session.had_original_gnupghome = true;
        } else {
            g_session.had_original_gnupghome = false;
        }
        g_session.gnupghome_saved = true;
    }

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
            if (isatty(STDIN_FILENO)) {
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
     * Ordering matters for safety: validate availability first (read-only), then
     * activate SSH and GPG (recoverable mutations), and write git config LAST.
     * git config is snapshotted up front and restored on failure; on that same
     * failure the SSH/GPG runtime state activated in steps 2-3 is also torn
     * down and the previous account's isolation is restored
     * (abort_failed_switch), so a failed switch reverts the git identity AND
     * doesn't leave current.sock / GNUPGHOME pointing at the new account — no
     * half-applied, mismatched identity.
     *
     * SIG-01: the whole mutation window is guarded against SIGINT/SIGTERM/
     * SIGHUP (Ctrl-C at the ssh-add passphrase or GPG pinentry prompt is a
     * normal path). The handler only records the signal; we check between
     * durable steps and run the same rollback as an explicit failure, so a
     * signal can no longer leave user.name=new/user.email=old or repointed
     * SSH/GPG state without the matching git identity. */
    if (!ctx->config.dry_run) {
        /* The previously-active account (detected at startup) and the current
         * GNUPGHOME symlink target, captured before any mutation so a failed
         * switch can restore them (F4). */
        const account_t *prev_account = ctx->current_account;
        char prev_gpg_home[MAX_PATH_LEN] = "";
        {
            char gpg_link[MAX_PATH_LEN];
            if (gpg_manager_get_home_path(gpg_link, sizeof(gpg_link)) == 0) {
                ssize_t n = readlink(gpg_link, prev_gpg_home, sizeof(prev_gpg_home) - 1);
                prev_gpg_home[(n > 0) ? (size_t)n : 0] = '\0';
            }
        }
        /* Mutation tracking for rollback: `dirty` means the runtime state was
         * (or may have been) repointed at the NEW account; `deferred` means
         * the target has SSH/GPG disabled and the teardown of the PREVIOUS
         * account's state is postponed past the point of no return (F4). */
        bool ssh_dirty = false, gpg_dirty = false;
        bool ssh_teardown_deferred = false, gpg_teardown_deferred = false;

        /* --- 1. Validate availability up front (no mutation yet) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            char expanded_key[MAX_PATH_LEN];
            if (expand_path(account->ssh_key_path, expanded_key, sizeof(expanded_key)) != 0 ||
                ssh_validate_key_file(expanded_key) != 0) {
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "SSH key not usable: %s", account->ssh_key_path);
                return -1;
            }
        }
        /* Skipped on resume: gpg_switch_account revalidates the key inside the
         * isolated home (re-importing from the system keyring if the home was
         * wiped by the reboot), so this probe adds only login latency there —
         * and a login shell may still carry GNUPGHOME pointing at the not-yet-
         * recreated isolated home, which would make this "system keyring"
         * check look inside the missing home and wrongly hard-fail the resume. */
        if (write_git && account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            if (validate_gpg_key_availability(account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND,
                          "GPG key not found in keyring: %s", account->gpg_key_id);
                return -1;
            }
        }

        /* Nothing durable has been touched yet, so a signal up to here could
         * simply kill us. From this point on, mutations begin: guard. */
        signals_guard_begin();

        /* SIG-02: register the config-save temp path (written by the
         * save-after-switch step in main()). It is the one scratch path whose
         * name this file can compute; the mkstemp-based scratch files are
         * registered at their creation sites (hook points in signals.h).
         * Unlinking a not-yet-created path on teardown is harmless. */
        {
            char cfg_tmp[MAX_PATH_LEN];
            if ((size_t)snprintf(cfg_tmp, sizeof(cfg_tmp), "%s.tmp.%d",
                                 ctx->config.config_path, (int)getpid())
                < sizeof(cfg_tmp)) {
                signals_scratch_register(cfg_tmp);
            }
        }

        /* --- 2. SSH agent isolation (mutation; fatal on failure) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            log_info("Setting up SSH isolation for account: %s", account->name);
            /* Starting the new agent reaps the previous account's agent, so
             * the runtime SSH state is dirty from the first attempt on. */
            ssh_dirty = true;
            memset(&g_session.ssh_config, 0, sizeof(g_session.ssh_config));
            if (ssh_manager_init(&g_session.ssh_config, SSH_AGENT_ISOLATED) != 0 ||
                ssh_switch_account(&g_session.ssh_config, account) != 0) {
                printf("  [!!] SSH key failed to load\n");
                ssh_manager_cleanup(&g_session.ssh_config);
                abort_failed_switch(prev_account, prev_gpg_home,
                                    false, ssh_dirty, false);
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "Failed to set up SSH for account: %s", account->name);
                return -1;
            }
            ssh_ok = true;
            g_session.ssh_active = true;
            printf("  [OK] SSH key loaded\n");

            /* Connection test is best-effort (network) and never fatal, so we
             * skip it entirely on the boot-time resume path — it would only
             * stall the login shell prompt on a network round trip (up to the
             * ssh ConnectTimeout when github.com is filtered/offline) for a
             * result that just picks a status line. */
            if (!ctx->config.resuming) {
                if (strlen(account->ssh_host_alias) > 0) {
                    if (ssh_test_connection(account, account->ssh_host_alias) == 0) {
                        printf("  [OK] SSH connection verified (%s)\n", account->ssh_host_alias);
                    } else {
                        printf("  [--] SSH connection test skipped (%s unreachable)\n", account->ssh_host_alias);
                    }
                } else if (ssh_test_connection(account, "git@github.com") == 0) {
                    printf("  [OK] SSH connection verified (github.com)\n");
                }
            }
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
                                       false, ssh_dirty, false);
        }

        /* --- 3. GPG isolated home (mutation; fatal on failure) --- */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            log_info("Setting up GPG isolation for account: %s", account->name);
            memset(&g_session.gpg_config, 0, sizeof(g_session.gpg_config));
            if (gpg_manager_init(&g_session.gpg_config, GPG_MODE_ISOLATED) != 0 ||
                gpg_switch_account(&g_session.gpg_config, account) != 0) {
                printf("  [!!] GPG key failed to activate\n");
                gpg_manager_cleanup(&g_session.gpg_config);
                /* Roll back the SSH activation from step 2 so we don't leave
                 * current.sock pointing at this account with no matching GPG.
                 * The GNUPGHOME symlink is only retargeted on gpg_switch_account
                 * success, so the GPG side is still clean here. */
                abort_failed_switch(prev_account, prev_gpg_home,
                                    false, ssh_dirty, false);
                set_error(ERR_GPG_KEY_FAILED,
                          "Failed to set up GPG for account: %s", account->name);
                return -1;
            }
            /* gpg_switch_account retargeted the stable GNUPGHOME symlink. */
            gpg_dirty = true;
            g_session.gpg_active = true;
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
                                       false, ssh_dirty, gpg_dirty);
        }

        /* --- 4. git config LAST, snapshotted for rollback --- */
        if (write_git) {
            git_config_snapshot(scope);
            if (git_set_config(account, scope) != 0) {
                abort_failed_switch(prev_account, prev_gpg_home,
                                    true, ssh_dirty, gpg_dirty);
                set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git configuration");
                return -1;
            }
            if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
                if (gpg_configure_git_signing(&g_session.gpg_config, account, scope) != 0) {
                    abort_failed_switch(prev_account, prev_gpg_home,
                                        true, ssh_dirty, gpg_dirty);
                    set_error(ERR_GIT_CONFIG_FAILED, "Failed to configure git GPG signing");
                    return -1;
                }
                gpg_ok = true;
                /* gpg_configure_git_signing sets commit.gpgsign to the account's
                 * preference, which may be OFF. Don't claim signing is enabled
                 * when we just disabled it — report the actual state. */
                if (account->gpg_signing_enabled) {
                    printf("  [OK] GPG signing enabled (key: %s)\n", account->gpg_key_id);
                } else {
                    printf("  [OK] GPG key configured, signing disabled (key: %s)\n", account->gpg_key_id);
                }
            }
            printf("  [OK] Git config set (%s scope)\n", scope_str);
        } else {
            /* Resume: git config was never touched, so the runtime activation
             * above completed the restore. */
            gpg_ok = g_session.gpg_active;
        }

        /* Last all-or-nothing checkpoint: a signal up to here rolls the whole
         * switch back (git config, when written, was just written — restore it
         * too; on resume nothing was written, so nothing to restore). */
        if (signals_pending()) {
            return abort_failed_switch(prev_account, prev_gpg_home,
                                       write_git, ssh_dirty, gpg_dirty);
        }

        /* Point of no return: the new identity is fully applied and
         * consistent. NOW run the teardown deferred from steps 2-3 — only
         * once the switch is known-good may the previous account's agent /
         * keyring entry point be dropped (F4). */
        if (ssh_teardown_deferred) {
            deactivate_runtime_isolation(true, false);
        }
        if (gpg_teardown_deferred) {
            deactivate_runtime_isolation(false, true);
        }

        /* Read-back validation is best-effort (warn only). Skipped on resume:
         * no git config was written, and the login shell's cwd is usually not
         * the repo the original local-scope write targeted. */
        if (write_git && git_test_config(account, scope) != 0) {
            log_warning("Git configuration validation failed: %s", get_last_error()->message);
        }

        signals_scratch_cleanup();
        signals_guard_end();
        /* A signal that slipped in after the checkpoint above: the switch is
         * fully applied, so honor the all-or-nothing contract by completing
         * normally (main() still records the new active account) instead of
         * dying between "identity applied" and "state persisted". */
        if (signals_pending()) {
            log_warning("Signal received after the switch completed; finishing normally");
        }
    } else {
        printf("  [--] DRY RUN: Would set git config (%s scope)\n", scope_str);
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            printf("  [--] DRY RUN: Would load SSH key\n");
        }
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            printf("  [--] DRY RUN: Would enable GPG signing\n");
        }
    }

    /* Test SSH/GPG functionality if enabled (basic validation). Skipped on
     * resume: the runtime activation above already proved both, and the GPG
     * fallback probes the system keyring, which a login shell's stale
     * GNUPGHOME can misdirect (see the step-1 comment). */
    if (!ctx->config.resuming) {
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0 && !ssh_ok) {
            if (test_ssh_key_functionality(account) != 0) {
                log_warning("SSH key test failed for account: %s", account->name);
            }
        }

        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0 && !gpg_ok) {
            if (test_gpg_key_functionality(account) != 0) {
                log_warning("GPG key test failed for account: %s", account->name);
            }
        }
    }

    /* Set as current account, and record it for boot resume. The config is
     * persisted by the save-after-switch path in main(). Skipped under dry-run
     * so a preview mutates no state, in memory or on disk. */
    if (!ctx->config.dry_run) {
        ctx->current_account = account;
        safe_strncpy(ctx->config.active_account, account->name, sizeof(ctx->config.active_account));
    }

    /* Print shell-integration tip if we set up SSH and/or GPG isolation. The
     * `init` snippet wires SSH_AUTH_SOCK (and, when GPG is used, GNUPGHOME) to
     * the stable symlinks so every subsequent switch takes effect transparently. */
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

    log_info("Successfully switched to account: %s (%s)", account->name, account->description);
    return 0;
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
        safe_strncpy(acct.email, input, sizeof(acct.email));
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
            break;
        }
        if (expand_path(input, expanded_path, sizeof(expanded_path)) != 0) {
            printf("[ERROR]: Invalid SSH key path: %s (try again, or Enter to skip)\n", input);
            continue;
        }
        if (!path_exists(expanded_path)) {
            printf("[ERROR]: SSH key file not found: %s (try again, or Enter to skip)\n", expanded_path);
            continue;
        }
        if (validate_ssh_key_security(expanded_path) != 0) {
            printf("[ERROR]: SSH key failed validation: %s (try again, or Enter to skip)\n", expanded_path);
            continue;
        }
        safe_strncpy(acct.ssh_key_path, expanded_path, sizeof(acct.ssh_key_path));
        acct.ssh_enabled = true;
        printf("[OK]: SSH key validated: %s\n", expanded_path);

        if (edit && acct.ssh_host_alias[0])
            printf("SSH Host Alias [%s] (Enter to keep): ", acct.ssh_host_alias);
        else
            printf("SSH Host Alias (optional, e.g., github.com-work): ");
        if (prompt_line("", input, sizeof(input), false) == 0 && strlen(input) > 0) {
            safe_strncpy(acct.ssh_host_alias, input, sizeof(acct.ssh_host_alias));
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
        /* If the name changed, make sure it doesn't collide with another
         * account (config_add_account's dup check would reject the account's
         * own unchanged name, so we check by-hand here and write in place). */
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (&ctx->accounts[i] != existing &&
                strcasecmp(ctx->accounts[i].name, acct.name) == 0) {
                set_error(ERR_ACCOUNT_EXISTS, "Account named '%s' already exists", acct.name);
                return -1;
            }
        }
        *existing = acct;
        if (strcmp(ctx->config.active_account, existing->name) != 0 &&
            existing == ctx->current_account) {
            safe_strncpy(ctx->config.active_account, acct.name, sizeof(ctx->config.active_account));
        }
        printf("[OK]: Account updated.\n");
        return 0;
    }

    if (config_add_account(ctx, &acct) != 0) {
        return -1;
    }
    printf("[OK]: Account added successfully!\n");
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

/* Edit an existing account interactively. */
int accounts_edit_interactive(gitswitch_ctx_t *ctx, const char *identifier) {
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_edit_interactive");
        return -1;
    }
    account_t *account = config_find_account(ctx, identifier);
    if (!account) {
        return -1; /* error already set with candidate list */
    }
    return add_or_edit_account(ctx, account);
}

/* Remove account with confirmation and cleanup */
int accounts_remove(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *account;
    char input[64];
    
    if (!ctx || !identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to accounts_remove");
        return -1;
    }
    
    /* Find the account */
    account = config_find_account(ctx, identifier);
    if (!account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: %s", identifier);
        return -1;
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
    
    /* Clear current account if it's the one being removed */
    if (ctx->current_account == account) {
        ctx->current_account = NULL;
    }

    /* Drop the persisted boot-resume target if it names this account, so a later
     * resume can't re-activate a deleted (or, worse, a wrongly-matched) account. */
    if (strcmp(ctx->config.active_account, account->name) == 0) {
        ctx->config.active_account[0] = '\0';
    }

    uint32_t account_id = account->id;
    
    /* Remove account */
    if (config_remove_account(ctx, account_id) != 0) {
        return -1;
    }
    
    printf("[OK]: Account removed successfully.\n");
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

/* Show current account status */
int accounts_show_status(const gitswitch_ctx_t *ctx) {
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
            printf("  Status: [ENABLED]\n");
            printf("  Key: %s\n", account->ssh_key_path);
            
            if (path_exists(account->ssh_key_path)) {
                printf("  Key File: [FOUND]\n");
                
                mode_t key_mode;
                if (get_file_permissions(account->ssh_key_path, &key_mode) == 0) {
                    if ((key_mode & 077) == 0) {
                        printf("  Permissions: [SECURE] (600)\n");
                    } else {
                        printf("  Permissions: [WARN] Insecure (%o)\n", key_mode & 0777);
                    }
                }
            } else {
                printf("  Key File: [NOT FOUND]\n");
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
        git_current_config_t git_config;
        if (git_get_current_config(&git_config) == 0) {
            printf("  Current Name: %s\n", git_config.name);
            printf("  Current Email: %s\n", git_config.email);
            printf("  Configuration Scope: %s\n", 
                   git_config.scope == GIT_SCOPE_LOCAL ? "local" : 
                   git_config.scope == GIT_SCOPE_GLOBAL ? "global" : "system");
            
            /* Check if git config matches account */
            if (strcmp(git_config.name, account->name) == 0 &&
                strcmp(git_config.email, account->email) == 0) {
                printf("  Match Status: [OK] Git config matches account\n");
            } else {
                printf("  Match Status: [WARN] Git config does not match account\n");
                printf("    Expected: %s <%s>\n", account->name, account->email);
                printf("    Current:  %s <%s>\n", git_config.name, git_config.email);
            }
            
            /* GPG signing status */
            if (strlen(git_config.signing_key) > 0) {
                printf("  GPG Signing Key: %s\n", git_config.signing_key);
                printf("  GPG Signing Enabled: %s\n", git_config.gpg_signing_enabled ? "[YES]" : "[NO]");
            } else {
                printf("  GPG Signing: [NOT CONFIGURED]\n");
            }
        } else {
            printf("  Status: [NOT FOUND] No git configuration found\n");
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
        git_current_config_t git_config;
        if (git_get_current_config(&git_config) == 0) {
            printf("  Name: %s\n", git_config.name);
            printf("  Email: %s\n", git_config.email);
            printf("  Scope: %s\n", 
                   git_config.scope == GIT_SCOPE_LOCAL ? "local" : 
                   git_config.scope == GIT_SCOPE_GLOBAL ? "global" : "system");
        } else {
            printf("  Status: [NOT FOUND] No git configuration found\n");
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
    return 0;
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
        
        if (!path_exists(expanded_path)) {
            set_error(ERR_ACCOUNT_INVALID, "SSH key file not found: %s", expanded_path);
            return -1;
        }
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
    
    return max_id + 1;
}

/* Validate SSH key security */
static int validate_ssh_key_security(const char *ssh_key_path) {
    FILE *key_file;
    char first_line[256];
    mode_t file_mode;
    
    if (!ssh_key_path || !path_exists(ssh_key_path)) {
        return -1;
    }
    
    /* Check file permissions */
    if (get_file_permissions(ssh_key_path, &file_mode) != 0) {
        return -1;
    }
    
    /* Check if it's a private key (should be 600) or public key (can be 644) */
    if (strstr(ssh_key_path, ".pub") == NULL) {
        /* Private key - should be 600 */
        if ((file_mode & 077) != 0) {
            log_warning("SSH private key file has insecure permissions: %o", file_mode & 0777);
            return -1;
        }
    } else {
        /* Public key - 644 is acceptable */
        if ((file_mode & 022) != 0 && (file_mode & 044) == 0) {
            log_warning("SSH public key file has unusual permissions: %o", file_mode & 0777);
            /* Continue anyway for public keys */
        }
    }
    
    /* Check if it looks like a valid SSH key */
    key_file = fopen(ssh_key_path, "r");
    if (!key_file) {
        return -1;
    }
    
    if (fgets(first_line, sizeof(first_line), key_file)) {
        /* Check for SSH key formats - both public and private */
        bool is_valid_key = false;
        
        /* Private key formats */
        if (string_starts_with(first_line, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
            string_starts_with(first_line, "-----BEGIN RSA PRIVATE KEY-----") ||
            string_starts_with(first_line, "-----BEGIN DSA PRIVATE KEY-----") ||
            string_starts_with(first_line, "-----BEGIN EC PRIVATE KEY-----") ||
            string_starts_with(first_line, "-----BEGIN SSH2 PRIVATE KEY-----")) {
            is_valid_key = true;
        }
        
        /* Public key formats */
        if (string_starts_with(first_line, "ssh-rsa ") ||
            string_starts_with(first_line, "ssh-dss ") ||
            string_starts_with(first_line, "ssh-ed25519 ") ||
            string_starts_with(first_line, "ecdsa-sha2-") ||
            string_starts_with(first_line, "ssh-ecdsa ")) {
            is_valid_key = true;
        }
        
        if (!is_valid_key) {
            fclose(key_file);
            log_warning("SSH key file format not recognized");
            return -1;
        }
    }
    
    fclose(key_file);
    return 0;
}

/* Validate GPG key availability.
 * Deliberately checks the *system* keyring (no GNUPGHOME override): this is the
 * fallback sanity check run from accounts_switch() when the isolated GPG path
 * did not already confirm the key (gpg_ok), and during health checks. The
 * isolated-home validation lives in gpg_validate_key()/gpg_test_signing(). */
static int validate_gpg_key_availability(const char *gpg_key_id) {
    if (!gpg_key_id) {
        return -1;
    }

    /* Look up the key in the system keyring, no shell. */
    const char *argv[] = {"gpg", "--list-secret-keys", gpg_key_id, NULL};
    run_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.stderr_to_devnull = true;

    if (run_argv(argv, &opts, NULL) != 0) {
        log_debug("GPG key %s not found in keyring", gpg_key_id);
        return -1;
    }

    return 0;
}

/* Test SSH key functionality */
static int test_ssh_key_functionality(const account_t *account) {
    /* This is a placeholder for SSH functionality testing
     * In a full implementation, this would:
     * 1. Start SSH agent if needed
     * 2. Load the key into agent
     * 3. Test connection to a known host
     * 4. Verify authentication works
     */
    log_debug("SSH key functionality test for %s: %s", 
              account->name, account->ssh_key_path);
    
    /* For now, just validate the key file exists and has correct permissions */
    return validate_ssh_key_security(account->ssh_key_path);
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
    char symlink_path[MAX_PATH_LEN];
    char target_path[MAX_PATH_LEN];
    ssize_t len;
    const char *runtime_dir;
    const char *account_name_start;
    const char *account_name_end;
    char account_name[MAX_NAME_LEN];
    size_t name_len;

    if (!ctx) {
        return -1;
    }

    /* Already have a current account set */
    if (ctx->current_account) {
        return 0;
    }

    /* Build path to symlink */
    runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (!runtime_dir) {
        log_debug("XDG_RUNTIME_DIR not set, falling back to saved account");
        return detect_current_from_saved(ctx);
    }

    if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                         "%s/gitswitch-ssh/current.sock", runtime_dir) >= sizeof(symlink_path)) {
        return -1;
    }

    /* Read symlink target */
    len = readlink(symlink_path, target_path, sizeof(target_path) - 1);
    if (len < 0) {
        log_debug("No current.sock symlink found, falling back to saved account");
        return detect_current_from_saved(ctx);
    }
    target_path[len] = '\0';

    /* Parse account name from target: ssh-agent.<name>.sock */
    account_name_start = strstr(target_path, "ssh-agent.");
    if (!account_name_start) {
        log_debug("Symlink target doesn't match expected format: %s", target_path);
        return -1;
    }
    account_name_start += strlen("ssh-agent.");

    account_name_end = strstr(account_name_start, ".sock");
    if (!account_name_end) {
        log_debug("Symlink target missing .sock suffix: %s", target_path);
        return -1;
    }

    name_len = (size_t)(account_name_end - account_name_start);
    if (name_len == 0 || name_len >= sizeof(account_name)) {
        log_debug("Invalid account name length in symlink target");
        return -1;
    }

    memcpy(account_name, account_name_start, name_len);
    account_name[name_len] = '\0';

    /* Find matching account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, account_name) == 0) {
            ctx->current_account = &ctx->accounts[i];
            log_debug("Detected current account from symlink: %s", account_name);
            return 0;
        }
    }

    log_debug("No matching account found for name: %s", account_name);
    return -1;
}