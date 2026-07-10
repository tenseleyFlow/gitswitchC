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

    /* Determine git scope. Explicit --global/--local override the account
     * preference. Writing an identity GLOBALLY affects every repository on the
     * machine, so we never silently promote local->global outside a repo:
     * require explicit consent (interactive prompt) or the --global flag. */
    git_scope_t scope = account->preferred_scope;
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
    scope_str = (scope == GIT_SCOPE_LOCAL) ? "local" : "global";

    /* Initialize git operations if not already done */
    if (git_ops_init() != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to initialize git operations");
        return -1;
    }

    /* Show what we're doing */
    printf("Switching to account: %s <%s>\n", account->name, account->email);

    /* If not in dry-run mode, actually perform the switch.
     *
     * Ordering matters for safety: validate availability first (read-only), then
     * activate SSH and GPG (recoverable mutations), and write git config LAST.
     * git config is snapshotted up front and restored on failure; on that same
     * failure the SSH/GPG runtime state activated in steps 2-3 is also torn
     * down (deactivate_runtime_isolation), so a failed switch reverts the git
     * identity AND doesn't leave current.sock / GNUPGHOME pointing at the
     * new account — no half-applied, mismatched identity. */
    if (!ctx->config.dry_run) {
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
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            if (validate_gpg_key_availability(account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND,
                          "GPG key not found in keyring: %s", account->gpg_key_id);
                return -1;
            }
        }

        /* --- 2. SSH agent isolation (mutation; fatal on failure) --- */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            log_info("Setting up SSH isolation for account: %s", account->name);
            memset(&g_session.ssh_config, 0, sizeof(g_session.ssh_config));
            if (ssh_manager_init(&g_session.ssh_config, SSH_AGENT_ISOLATED) != 0 ||
                ssh_switch_account(&g_session.ssh_config, account) != 0) {
                printf("  [!!] SSH key failed to load\n");
                ssh_manager_cleanup(&g_session.ssh_config);
                set_error(ERR_SSH_KEY_LOAD_FAILED,
                          "Failed to set up SSH for account: %s", account->name);
                return -1;
            }
            ssh_ok = true;
            g_session.ssh_active = true;
            printf("  [OK] SSH key loaded\n");

            /* Connection test is best-effort (network) and never fatal. */
            if (strlen(account->ssh_host_alias) > 0) {
                if (ssh_test_connection(account, account->ssh_host_alias) == 0) {
                    printf("  [OK] SSH connection verified (%s)\n", account->ssh_host_alias);
                } else {
                    printf("  [--] SSH connection test skipped (%s unreachable)\n", account->ssh_host_alias);
                }
            } else if (ssh_test_connection(account, "git@github.com") == 0) {
                printf("  [OK] SSH connection verified (github.com)\n");
            }
        } else {
            /* Target has no SSH: tear down any live gitswitch agent + current.sock
             * so shells stop authenticating as the previously-active account. */
            deactivate_runtime_isolation(true, false);
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
                 * current.sock pointing at this account with no matching GPG. */
                deactivate_runtime_isolation(g_session.ssh_active, false);
                set_error(ERR_GPG_KEY_FAILED,
                          "Failed to set up GPG for account: %s", account->name);
                return -1;
            }
            g_session.gpg_active = true;
        } else {
            /* Target has no GPG: drop the stable GNUPGHOME symlink so shells
             * stop signing/using the previous account's keyring. */
            deactivate_runtime_isolation(false, true);
        }

        /* --- 4. git config LAST, snapshotted for rollback --- */
        git_config_snapshot(scope);
        if (git_set_config(account, scope) != 0) {
            git_config_restore();
            /* Also undo the SSH/GPG activation from steps 2-3: leaving
             * current.sock / GNUPGHOME pointed at this account while the git
             * identity reverts to the previous one is exactly the mixed
             * identity the tool exists to prevent. */
            deactivate_runtime_isolation(g_session.ssh_active, g_session.gpg_active);
            set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git configuration");
            return -1;
        }
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            if (gpg_configure_git_signing(&g_session.gpg_config, account, scope) != 0) {
                git_config_restore();
                deactivate_runtime_isolation(g_session.ssh_active, g_session.gpg_active);
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

        /* Read-back validation is best-effort (warn only). */
        if (git_test_config(account, scope) != 0) {
            log_warning("Git configuration validation failed: %s", get_last_error()->message);
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

    /* Test SSH functionality if enabled (basic validation) */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0 && !ssh_ok) {
        if (test_ssh_key_functionality(account) != 0) {
            log_warning("SSH key test failed for account: %s", account->name);
        }
    }

    /* Test GPG functionality if enabled */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0 && !gpg_ok) {
        if (test_gpg_key_functionality(account) != 0) {
            log_warning("GPG key test failed for account: %s", account->name);
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

/* Add new account interactively with basic validation */
int accounts_add_interactive(gitswitch_ctx_t *ctx) {
    account_t new_account;
    char input[512];
    char expanded_path[MAX_PATH_LEN];
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to accounts_add_interactive");
        return -1;
    }
    
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    
    /* Initialize new account */
    memset(&new_account, 0, sizeof(new_account));
    new_account.id = get_next_available_id(ctx);
    new_account.preferred_scope = ctx->config.default_scope;
    
    printf("\n┌─────────────────────────────────────┐\n");
    printf("│          Add New Account            │\n");
    printf("└─────────────────────────────────────┘\n\n");
    
    /* Get account name */
    do {
        printf("Account Name: ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            set_error(ERR_FILE_IO, "Failed to read account name");
            return -1;
        }
        
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (!validate_name(input)) {
            printf("[ERROR]: Invalid name. Please enter a non-empty name.\n");
            continue;
        }
        
        safe_strncpy(new_account.name, input, sizeof(new_account.name));
        break;
    } while (1);
    
    /* Get email address */
    do {
        printf("Email Address: ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            set_error(ERR_FILE_IO, "Failed to read email address");
            return -1;
        }
        
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (!validate_email(input)) {
            printf("[ERROR]: Invalid email address format.\n");
            continue;
        }
        
        safe_strncpy(new_account.email, input, sizeof(new_account.email));
        break;
    } while (1);
    
    /* Get description */
    printf("Description (optional): ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);
        
        if (strlen(input) > 0) {
            safe_strncpy(new_account.description, input, sizeof(new_account.description));
        } else {
            safe_strncpy(new_account.description, new_account.name, sizeof(new_account.description));
        }
    } else {
        safe_strncpy(new_account.description, new_account.name, sizeof(new_account.description));
    }
    
    /* Get SSH key configuration. Re-prompt on a bad path instead of silently
     * dropping SSH: a typo previously scrolled past a one-line error and
     * produced an account that never loads a key (auth failures later). Empty
     * input explicitly skips SSH. */
    while (1) {
        printf("SSH Key Path (optional, press Enter to skip): ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);

        if (strlen(input) == 0) break; /* skip SSH */

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

        safe_strncpy(new_account.ssh_key_path, expanded_path, sizeof(new_account.ssh_key_path));
        new_account.ssh_enabled = true;
        printf("[OK]: SSH key validated: %s\n", expanded_path);

        /* Optional SSH host alias */
        printf("SSH Host Alias (optional, e.g., github.com-work): ");
        fflush(stdout);
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = '\0';
            trim_whitespace(input);
            if (strlen(input) > 0) {
                safe_strncpy(new_account.ssh_host_alias, input, sizeof(new_account.ssh_host_alias));
            }
        }
        break;
    }

    /* Get GPG key configuration. Re-prompt on a bad/unavailable key rather than
     * silently dropping GPG; Enter skips. */
    while (1) {
        printf("GPG Key ID (optional, press Enter to skip): ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);

        if (strlen(input) == 0) break; /* skip GPG */

        if (!validate_key_id(input)) {
            printf("[ERROR]: Invalid GPG key ID format: %s (try again, or Enter to skip)\n", input);
            continue;
        }
        if (validate_gpg_key_availability(input) != 0) {
            printf("[ERROR]: GPG key not found in keyring: %s (try again, or Enter to skip)\n", input);
            continue;
        }

        safe_strncpy(new_account.gpg_key_id, input, sizeof(new_account.gpg_key_id));
        new_account.gpg_enabled = true;
        printf("[OK]: GPG key validated: %s\n", input);

        /* Ask about GPG signing */
        printf("Enable GPG signing for commits? (y/N): ");
        fflush(stdout);
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = '\0';
            trim_whitespace(input);
            new_account.gpg_signing_enabled = (tolower((unsigned char)input[0]) == 'y');
        }
        break;
    }

    /* Get preferred scope. Validate the answer and re-prompt on anything that
     * isn't clearly local/global, instead of silently coercing a typo like
     * 'Global' or 'golbal' to local. Enter keeps the shown default. */
    while (1) {
        printf("Preferred Git Scope (local/global) [%s]: ",
               config_scope_to_string(new_account.preferred_scope));
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        trim_whitespace(input);

        if (strlen(input) == 0) break; /* keep default */
        if (strcasecmp(input, "local") == 0 || strcasecmp(input, "l") == 0) {
            new_account.preferred_scope = GIT_SCOPE_LOCAL;
            break;
        }
        if (strcasecmp(input, "global") == 0 || strcasecmp(input, "g") == 0) {
            new_account.preferred_scope = GIT_SCOPE_GLOBAL;
            break;
        }
        printf("[ERROR]: Please enter 'local' or 'global' (or Enter for %s).\n",
               config_scope_to_string(new_account.preferred_scope));
    }
    
    /* Basic validation */
    if (!validate_name(new_account.name) || !validate_email(new_account.email)) {
        printf("[ERROR]: Account validation failed: Invalid name or email\n");
        return -1;
    }
    
    /* Confirmation */
    printf("\nAccount Summary:\n");
    printf("   ID: %u\n", new_account.id);
    printf("   Name: %s\n", new_account.name);
    printf("   Email: %s\n", new_account.email);
    printf("   Description: %s\n", new_account.description);
    printf("   Scope: %s\n", config_scope_to_string(new_account.preferred_scope));
    printf("   SSH: %s\n", new_account.ssh_enabled ? "[ENABLED]" : "[DISABLED]");
    printf("   GPG: %s\n", new_account.gpg_enabled ? "[ENABLED]" : "[DISABLED]");
    
    printf("\nAdd this account? (y/N): ");
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        set_error(ERR_FILE_IO, "Failed to read confirmation");
        return -1;
    }
    
    input[strcspn(input, "\n")] = '\0';
    trim_whitespace(input);
    
    if (tolower(input[0]) != 'y') {
        printf("Account creation cancelled.\n");
        return -1;
    }
    
    /* Add account to context */
    if (config_add_account(ctx, &new_account) != 0) {
        return -1;
    }
    
    printf("[OK]: Account added successfully!\n");
    return 0;
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
    
    /* Confirmation */
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