/* gitswitch-c: Safe git identity switching with SSH/GPG isolation
 * Complete CLI with account management and authentication isolation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include "gitswitch.h"
#include "config.h"
#include "accounts.h"
#include "display.h"
#include "error.h"
#include "utils.h"
#include "git_ops.h"
#include "ssh_manager.h"
#include "gpg_manager.h"
#include "signals.h"

/* Long-only options (no short form). Values above 0xff avoid colliding with
 * ASCII short options handled by getopt_long. */
#define OPT_SSH_AGENT_INFO 0x100
#define OPT_NAMES 0x101

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] [COMMAND] [ARGS]\n", prog_name);
    printf("\nComplete Git Identity Management\n");
    printf("Safe git identity switching with actual git configuration management\n");
    printf("\nCommands:\n");
    printf("  add                  Add new account interactively\n");
    printf("  edit <account>       Edit an existing account interactively\n");
    printf("  list, ls             List all configured accounts\n");
    printf("  remove, rm, delete <account>  Remove specified account\n");
    printf("  status               Show current account status\n");
    printf("  doctor, health       Run comprehensive health check\n");
    printf("  config               Show configuration file information\n");
    printf("  init <shell>         Emit shell integration (fish|bash|zsh|sh)\n");
    printf("  resume               Re-activate the last-used account (used on login)\n");
    printf("  reset [account]      Kill agents and delete isolated GPG/SSH state (all, or one)\n");
    printf("  <account>            Switch to specified account\n");
    printf("\nOptions:\n");
    printf("  --global, -g         Use global git scope\n");
    printf("  --local, -l          Use local git scope (default)\n");
    printf("  --dry-run, -n        Show what would be done without executing\n");
    printf("  --yes, -y            Assume 'yes' to confirmation prompts (remove/reset)\n");
    printf("  --names              With 'list': print only account names (one per line)\n");
    printf("  --verbose, -V        Enable verbose output\n");
    printf("  --debug, -d          Enable debug logging\n");
    printf("  --color, -c          Force color output\n");
    printf("  --no-color, -C       Disable color output\n");
    printf("  --help, -h           Show this help message\n");
    printf("  --version, -v        Show version information\n");
    printf("\nExamples:\n");
    printf("  %s add                    # Add new account interactively\n", prog_name);
    printf("  %s edit work              # Edit the 'work' account\n", prog_name);
    printf("  %s list                   # List all accounts\n", prog_name);
    printf("  %s list --names           # Print just account names (for scripts/completion)\n", prog_name);
    printf("  %s 1                      # Switch to account ID 1\n", prog_name);
    printf("  %s work                   # Switch to account matching 'work'\n", prog_name);
    printf("  %s remove 2 --yes         # Remove account ID 2 without confirmation\n", prog_name);
    printf("  %s doctor                 # Run health check\n", prog_name);
    printf("\nKey Features:\n");
    printf("- Secure TOML configuration management\n");
    printf("- Interactive account creation with validation\n");
    printf("- Comprehensive account health checking\n");
    printf("- SSH/GPG key validation and security checks\n");
    printf("- Atomic configuration file operations\n");
    printf("- Safe file permission handling\n");
    printf("- Actual git configuration switching\n");
    printf("- Repository detection and scope management\n");
    printf("- Git configuration validation and testing\n");
}
static void print_version(void) {
    printf("%s %s (%s)\n", GITSWITCH_NAME, GITSWITCH_VERSION, GITSWITCH_COMMIT);
}
static int handle_add_command(gitswitch_ctx_t *ctx);
static int handle_edit_command(gitswitch_ctx_t *ctx, const char *identifier);
static int handle_list_command(gitswitch_ctx_t *ctx);
static int handle_list_names(gitswitch_ctx_t *ctx);
static int handle_remove_command(gitswitch_ctx_t *ctx, const char *identifier);
static int handle_status_command(gitswitch_ctx_t *ctx);
static int handle_switch_command(gitswitch_ctx_t *ctx, const char *identifier);
static int handle_doctor_command(gitswitch_ctx_t *ctx);
static int handle_config_command(gitswitch_ctx_t *ctx);
static int handle_init_command(const char *shell);
static int handle_resume_command(gitswitch_ctx_t *ctx);
static int handle_reset_command(gitswitch_ctx_t *ctx, const char *account);
static const char *detect_shell_from_env(void);

int main(int argc, char *argv[]) {
    gitswitch_ctx_t ctx;
    int opt;

    /* Restrict permissions on everything we create (config, keys, agent dirs,
     * gpg homes): files born 0600, dirs 0700, closing fopen-then-chmod windows. */
    umask(077);
    bool force_color = false;
    bool no_color = false;
    bool show_help = false;
    bool show_version = false;
    bool dry_run = false;
    bool force_global = false;
    bool force_local = false;
    bool assume_yes = false;
    bool names_only = false;
    int exit_code = EXIT_SUCCESS;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"color", no_argument, 0, 'c'},
        {"no-color", no_argument, 0, 'C'},
        {"verbose", no_argument, 0, 'V'},
        {"debug", no_argument, 0, 'd'},
        {"dry-run", no_argument, 0, 'n'},
        {"global", no_argument, 0, 'g'},
        {"local", no_argument, 0, 'l'},
        {"yes", no_argument, 0, 'y'},
        {"names", no_argument, 0, OPT_NAMES},
        /* Compat alias for the Python gitswitch era. Dispatches to `init`
         * with shell auto-detected from $SHELL so stale rc lines keep working. */
        {"ssh-agent-info", no_argument, 0, OPT_SSH_AGENT_INFO},
        {0, 0, 0, 0}
    };
    
    /* Initialize error handling - use WARN level for release builds, INFO for debug */
#ifdef DEBUG
    if (error_init(LOG_LEVEL_INFO, NULL) != 0) {
#else
    if (error_init(LOG_LEVEL_WARNING, NULL) != 0) {
#endif
        fprintf(stderr, "Failed to initialize error handling\n");
        return EXIT_FAILURE;
    }
    
    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "hvcCVdngly", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                show_help = true;
                break;
            case 'v':
                show_version = true;
                break;
            case 'c':
                force_color = true;
                break;
            case 'C':
                no_color = true;
                break;
            case 'V':
            case 'd':
                set_log_level(LOG_LEVEL_DEBUG);
                break;
            case 'n':
                dry_run = true;
                break;
            case 'g':
                force_global = true;
                break;
            case 'l':
                force_local = true;
                break;
            case 'y':
                assume_yes = true;
                break;
            case OPT_NAMES:
                names_only = true;
                break;
            case OPT_SSH_AGENT_INFO: {
                int rc = handle_init_command(detect_shell_from_env());
                error_cleanup();
                return rc;
            }
            default:
                print_usage(argv[0]);
                error_cleanup();
                return EXIT_FAILURE;
        }
    }
    
    /* Initialize display system */
    if (display_init(force_color, no_color) != 0) {
        log_error("Failed to initialize display system");
        error_cleanup();
        return EXIT_FAILURE;
    }
    
    /* Handle special commands that don't need config */
    if (show_version) {
        print_version();
        error_cleanup();
        return EXIT_SUCCESS;
    }
    
    if (show_help) {
        print_usage(argv[0]);
        error_cleanup();
        return EXIT_SUCCESS;
    }

    /* `init` needs no config — it only emits shell-integration text derived
     * from env-based paths — and it runs on every interactive shell startup.
     * Dispatch it before config_init so it stays cheap and a broken config
     * (e.g. accounts.toml chmod'd wrong) can't blank the shell integration. */
    if (optind < argc && strcmp(argv[optind], "init") == 0) {
        const char *shell = (optind + 1 < argc) ? argv[optind + 1] : detect_shell_from_env();
        int rc = handle_init_command(shell);
        error_cleanup();
        return rc;
    }

    /* For commands that mutate shared state, hold an exclusive cross-process
     * lock across the WHOLE load->mutate->save cycle. That is not just the
     * config read-modify-writers (add/edit/remove, a bare-account switch that
     * updates active_account): `resume` runs the full mutating accounts_switch
     * (SSH agent retarget, GPG symlink retarget, git config write) and `reset`
     * kills agents and retargets/deletes runtime symlinks, so both must be
     * serialized against a concurrent switch or the final state splits git
     * identity from the live SSH/GPG runtime (AR-02 #1: tmux-restore shells
     * running resume while another shell switches). Acquire before config_init
     * so the load itself happens under the lock. Only genuinely read-only
     * commands (list/status/doctor/config) skip it. Fail closed on lock
     * failure: silently proceeding unlocked would reopen the exact lost-update
     * and split-identity races the lock exists to prevent (AR-02 #17). */
    int config_lock_fd = -1;
    {
        const char *c = (optind < argc) ? argv[optind] : NULL;
        bool read_only = (c == NULL) ||
            strcmp(c, "list") == 0 || strcmp(c, "ls") == 0 ||
            strcmp(c, "status") == 0 || strcmp(c, "doctor") == 0 ||
            strcmp(c, "health") == 0 || strcmp(c, "config") == 0;
        if (!read_only) {
            config_lock_fd = config_write_lock();
            if (config_lock_fd < 0) {
                display_error("Could not acquire the gitswitch config lock",
                              "another gitswitch may be stuck or the config "
                              "directory is not writable; try again");
                error_cleanup();
                return EXIT_FAILURE;
            }
        }
    }

    /* Initialize configuration system */
    log_info("Initializing gitswitch-c configuration system");
    if (config_init(&ctx) != 0) {
        display_error("Configuration initialization failed", get_last_error()->message);
        error_cleanup();
        return EXIT_CONFIG_ERROR;
    }
    
    /* Set dry run mode if requested */
    ctx.config.dry_run = dry_run;
    ctx.config.force_global = force_global;
    ctx.config.force_local = force_local;
    ctx.config.assume_yes = assume_yes;
    ctx.config.verbose = should_log(LOG_LEVEL_DEBUG);
    
    /* Parse command and arguments */
    const char *command = NULL;
    const char *arg1 = NULL;

    if (optind < argc) {
        command = argv[optind];
        if (optind + 1 < argc) {
            arg1 = argv[optind + 1];
        }
    }

    /* Snapshot the active account so a switch that doesn't actually change it
     * (re-switching to the current account) skips config_save below and its
     * backup churn. */
    char prev_active[MAX_NAME_LEN];
    safe_strncpy(prev_active, ctx.config.active_account, sizeof(prev_active));
    
    /* Execute command */
    if (command == NULL) {
        /* No command specified - interactive mode or help */
        if (ctx.account_count == 0) {
            display_header("Welcome to gitswitch-c");
            display_warning("No accounts configured yet");
            printf("\nTo get started:\n");
            printf("  1. Run 'gitswitch add' to create your first account\n");
            printf("  2. Run 'gitswitch list' to see all accounts\n");
            printf("  3. Run 'gitswitch <account>' to switch accounts\n");
            printf("  4. Run 'gitswitch --help' for more options\n\n");
        } else {
            /* Show account list */
            exit_code = handle_list_command(&ctx);
        }
    } else if (strcmp(command, "add") == 0) {
        exit_code = handle_add_command(&ctx);
    } else if (strcmp(command, "edit") == 0) {
        if (!arg1) {
            display_error("Missing account identifier", "Usage: gitswitch edit <account>");
            exit_code = EXIT_FAILURE;
        } else {
            exit_code = handle_edit_command(&ctx, arg1);
        }
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        /* `list --names` is a plumbing mode: one account name per line, no
         * decoration, for shell-completion scripts to consume. */
        exit_code = names_only ? handle_list_names(&ctx) : handle_list_command(&ctx);
    } else if (strcmp(command, "remove") == 0 || strcmp(command, "rm") == 0 || strcmp(command, "delete") == 0) {
        if (!arg1) {
            display_error("Missing account identifier", "Usage: gitswitch remove <account>");
            exit_code = EXIT_FAILURE;
        } else {
            exit_code = handle_remove_command(&ctx, arg1);
        }
    } else if (strcmp(command, "status") == 0) {
        exit_code = handle_status_command(&ctx);
    } else if (strcmp(command, "doctor") == 0 || strcmp(command, "health") == 0) {
        exit_code = handle_doctor_command(&ctx);
    } else if (strcmp(command, "config") == 0) {
        exit_code = handle_config_command(&ctx);
    } else if (strcmp(command, "resume") == 0) {
        exit_code = handle_resume_command(&ctx);
    } else if (strcmp(command, "reset") == 0) {
        exit_code = handle_reset_command(&ctx, arg1);
    } else {
        /* Assume it's an account identifier for switching */
        exit_code = handle_switch_command(&ctx, command);
    }
    
    /* Save configuration only for commands that modify accounts */
    bool should_save = false;
    if (command && exit_code == EXIT_SUCCESS && !dry_run) {
        if (strcmp(command, "add") == 0 ||
            strcmp(command, "edit") == 0 ||
            strcmp(command, "remove") == 0 ||
            strcmp(command, "rm") == 0 ||
            strcmp(command, "delete") == 0) {
            should_save = true;
        } else if (strcmp(command, "list") != 0 &&
                   strcmp(command, "ls") != 0 &&
                   strcmp(command, "status") != 0 &&
                   strcmp(command, "doctor") != 0 &&
                   strcmp(command, "health") != 0 &&
                   strcmp(command, "config") != 0 &&
                   strcmp(command, "init") != 0 &&
                   strcmp(command, "resume") != 0 &&
                   strcmp(command, "reset") != 0) {
            /* A switch: the only durable change is active_account, so save
             * only when it actually changed. Re-switching to the current
             * account rewrites nothing, so we skip the save (and its backup). */
            should_save = (strcmp(prev_active, ctx.config.active_account) != 0);
        }
        /* `resume` re-activates the already-saved account and changes nothing
         * durable, so it is intentionally excluded above to avoid backup churn. */
        
        if (should_save) {
            log_debug("Saving configuration after %s command (account_count=%zu)",
                     command, ctx.account_count);
            /* SIG-02 (AR-02 #27): hold the deferring guard across the save so
             * config_save's scratch registration of its temp file has a live
             * handler behind it — a signal mid-save then defers instead of
             * orphaning accounts.toml.tmp.<pid>. After a switch the guard is
             * ALREADY armed: accounts_switch's success path leaves it up so
             * the stretch between "identity applied" and this save is never
             * signal-killable (M3) — this begin is then a no-op re-begin that
             * preserves any deferred signal. For add/edit/remove it arms
             * fresh. The command's work is already fully applied at this
             * point, so a deferred signal is not re-raised: the process
             * finishes persisting and exits normally moments later. */
            signals_guard_begin();
            if (config_save(&ctx, ctx.config.config_path) != 0) {
                display_warning("Failed to save configuration changes");
                /* Don't fail the command, just warn */
            }
            signals_scratch_cleanup();
        }
    }

    /* M3: drop the guard a successful switch left armed (see above). Done
     * unconditionally — it also closes the save-path guard, and it is an
     * idempotent no-op for every command that never armed one. */
    signals_guard_end();


    /* Release the config write-lock now that load+mutate+save is done (harmless
     * no-op for read-only commands that never took it; the OS would also drop it
     * at exit). */
    if (config_lock_fd >= 0) {
        close(config_lock_fd);
    }

    /* Note: We intentionally do NOT clean up SSH agents on exit.
     * The agent should persist so subsequent git commands can use it.
     * Cleanup happens at the start of the next account switch. */

    /* Cleanup error handling */
    error_cleanup();
    return exit_code == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Command handler implementations */

static int handle_add_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    if (accounts_add_interactive(ctx) != 0) {
        display_error("Failed to add account", get_last_error()->message);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

static int handle_edit_command(gitswitch_ctx_t *ctx, const char *identifier) {
    if (!ctx || !identifier) return EXIT_FAILURE;

    if (accounts_edit_interactive(ctx, identifier) != 0) {
        display_error("Failed to edit account", get_last_error()->message);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int handle_list_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;

    return accounts_list(ctx) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Plumbing for shell completion: one account name per line, nothing else. */
static int handle_list_names(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    for (size_t i = 0; i < ctx->account_count; i++) {
        printf("%s\n", ctx->accounts[i].name);
    }
    return EXIT_SUCCESS;
}

static int handle_remove_command(gitswitch_ctx_t *ctx, const char *identifier) {
    if (!ctx || !identifier) return EXIT_FAILURE;
    
    if (accounts_remove(ctx, identifier) != 0) {
        display_error("Failed to remove account", get_last_error()->message);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

static int handle_status_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    return accounts_show_status(ctx) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int handle_switch_command(gitswitch_ctx_t *ctx, const char *identifier) {
    if (!ctx || !identifier) return EXIT_FAILURE;

    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
    }

    if (accounts_switch(ctx, identifier) != 0) {
        display_error("Failed to switch account", get_last_error()->message);
        return EXIT_FAILURE;
    }

    /* accounts_switch already prints detailed status; confirm success. Under
     * dry-run it mutates nothing (current_account stays unset), so don't deref it. */
    if (ctx->config.dry_run) {
        display_success("DRY RUN complete - no changes were made");
    } else {
        display_success("Switched to: %s", ctx->current_account->name);
    }

    return EXIT_SUCCESS;
}

static int handle_doctor_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    /* Check system requirements */
    printf("[INFO]: Checking system requirements...\n");
    
    if (command_exists("git")) {
        display_success("Git command found");
    } else {
        display_error("Git not found", "Please install git to use gitswitch");
        return EXIT_FAILURE;
    }
    
    if (command_exists("ssh-agent")) {
        display_success("SSH agent found");
    } else {
        display_warning("SSH agent not found - SSH key management may not work");
    }
    
    if (command_exists("gpg") || command_exists("gpg2")) {
        display_success("GPG found");
    } else {
        display_warning("GPG not found - GPG signing will not work");
    }
    
    /* Check configuration */
    printf("\n[INFO]: Checking configuration...\n");
    
    if (config_validate(ctx) == 0) {
        display_success("Configuration validation passed");
    } else {
        display_error("Configuration validation failed", get_last_error()->message);
        return EXIT_FAILURE;
    }
    
    /* Check all accounts */
    return accounts_health_check(ctx) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int handle_config_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    printf("📁 Configuration file: %s\n", ctx->config.config_path);
    
    if (!path_exists(ctx->config.config_path)) {
        display_warning("Configuration file does not exist");
        printf("Create default configuration? (y/N): ");
        fflush(stdout);
        
        char input[64];
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = '\0';
            trim_whitespace(input);
            
            /* Cast to unsigned char first: passing a plain (possibly signed)
             * char to a ctype function is UB for negative values (mem-2). */
            if (tolower((unsigned char)input[0]) == 'y') {
                if (config_create_default(ctx->config.config_path) == 0) {
                    display_success("Default configuration created");
                    printf("Please edit the file to add your accounts.\n");
                } else {
                    display_error("Failed to create default configuration", get_last_error()->message);
                    return EXIT_FAILURE;
                }
            }
        }
        return EXIT_SUCCESS;
    }
    
    /* Show configuration info */
    printf("Accounts: %zu configured\n", ctx->account_count);
    printf("Default scope: %s\n", config_scope_to_string(ctx->config.default_scope));
    
    /* Check permissions */
    mode_t file_mode;
    if (get_file_permissions(ctx->config.config_path, &file_mode) == 0) {
        if ((file_mode & 077) == 0) {
            display_success("Configuration file permissions are secure (600)");
        } else {
            display_warning("Configuration file has unsafe permissions (%o)", file_mode & 0777);
        }
    }

    return EXIT_SUCCESS;
}

/* Return the basename of $SHELL, or NULL if it can't be determined. The
 * pointer aliases into the environment string — callers must not free it. */
static const char *detect_shell_from_env(void) {
    const char *shell = getenv("SHELL");
    if (!shell || !*shell) {
        return NULL;
    }
    const char *slash = strrchr(shell, '/');
    return slash ? slash + 1 : shell;
}

/* Finish a shell-snippet emit: the output of `gitswitch init` is consumed by
 * `eval "$(gitswitch init bash)"`, so a short write (EPIPE, ENOSPC, closed fd)
 * that truncates the snippet mid-construct — an `if` with no `fi`, or an
 * SSH_AUTH_SOCK assignment whose existence guard got cut off — would still be
 * eval'd as-is by the shell. stdio latches every write failure in the stream
 * error flag, so flush and check it here and fail the whole command instead of
 * returning success for half a script. Nothing further is written to stdout
 * after this check, so a detected failure never appends a partial line (SIPW-1). */
static int finish_snippet_emit(void) {
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "gitswitch: failed to write shell integration snippet: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/* Emit shell-integration snippet for `shell` on stdout. The snippet sets
 * SSH_AUTH_SOCK to the stable gitswitch symlink, guarded by a socket test so
 * sourcing before the first switch (or after /tmp is wiped) is silent. */
static int handle_init_command(const char *shell) {
    /* A consumer that stops reading (e.g. `gitswitch init | head`) must surface
     * as EPIPE through the stream error flag checked in finish_snippet_emit,
     * not kill us with SIGPIPE before we can report the failure. Not restored:
     * both callers return from main() immediately after this function (SIPW-1). */
    signal(SIGPIPE, SIG_IGN);

    char sock_path[MAX_PATH_LEN];
    if (ssh_manager_get_auth_sock_path(sock_path, sizeof(sock_path)) != 0) {
        fprintf(stderr, "gitswitch: failed to compute SSH_AUTH_SOCK path: %s\n",
                get_last_error()->message);
        return EXIT_FAILURE;
    }

    /* GPG home is best-effort: if it can't be computed we still emit the SSH
     * wiring rather than failing the whole init. */
    char gpg_home[MAX_PATH_LEN];
    bool have_gpg_home = (gpg_manager_get_home_path(gpg_home, sizeof(gpg_home)) == 0);

    /* The paths are emitted inside single-quoted shell assignments below; a
     * stray single quote would break out of the quoting, so refuse it. */
    if (strchr(sock_path, '\'')) {
        fprintf(stderr, "gitswitch: refusing to emit SSH_AUTH_SOCK path containing a quote\n");
        return EXIT_FAILURE;
    }
    if (have_gpg_home && strchr(gpg_home, '\'')) {
        have_gpg_home = false;
    }

    /* Path of the resume-hint marker, used to gate the per-shell resume probe:
     * with no saved account the marker is absent, so a machine that has never
     * switched skips the ssh-add + `gitswitch resume` spawn on every shell. If
     * the path can't be computed or contains a quote, fall back to the old
     * unconditional probe rather than emitting broken shell. */
    char hint_path[MAX_PATH_LEN];
    bool have_hint = (config_resume_hint_path(hint_path, sizeof(hint_path)) == 0) &&
                     (strchr(hint_path, '\'') == NULL);

    if (!shell || !*shell) {
        fprintf(stderr,
                "gitswitch: could not detect shell; pass one explicitly:\n"
                "  gitswitch init fish | source\n"
                "  eval \"$(gitswitch init bash)\"\n"
                "  eval \"$(gitswitch init zsh)\"\n");
        return EXIT_FAILURE;
    }

    if (strcmp(shell, "fish") == 0) {
        printf("# gitswitch shell integration (fish)\n");
        printf("set -l __gitswitch_auth_sock '%s'\n", sock_path);
        /* First interactive shell after a boot: if no SSH agent is reachable at
         * the stable socket, resume the last account. We probe with `ssh-add -l`
         * (exit > 1 means no agent reachable) rather than `test -S`, because a
         * stale socket file left behind after a reboot — common on macOS, which
         * doesn't wipe /tmp — passes a plain -S test and would silently skip
         * resume. Interactive-gated so pinentry has a user. The "restoring your
         * account" notice is printed by `resume` itself (on stderr, past the
         * stdout suppression) only when it actually has an account to restore —
         * echoing it here would nag on every shell when there is nothing saved,
         * since a no-op resume never creates the socket the probe looks for. */
        printf("if status is-interactive\n");
        if (have_hint) {
            /* Only probe/resume when there's a saved account to resume, and
             * pick the probe by the account's recorded runtime needs (the
             * hint file's content) so an SSH-less active account never spawns
             * a doomed ssh-add + resume on every shell (AR-02 #23). Empty or
             * unrecognized content (a pre-#23 hint written before this field
             * existed) falls back to the ssh-add probe — same behavior as
             * before, no regression on the first post-upgrade shell. */
            printf("    if test -e '%s'\n", hint_path);
            printf("        read -l __gitswitch_needs < '%s'\n", hint_path);
            printf("        switch \"$__gitswitch_needs\"\n");
            printf("            case '' '*ssh*'\n");
            printf("                env SSH_AUTH_SOCK=$__gitswitch_auth_sock ssh-add -l >/dev/null 2>&1\n");
            printf("                if test $status -gt 1\n");
            printf("                    gitswitch resume >/dev/null\n");
            printf("                end\n");
            if (have_gpg_home) {
                /* GPG-only account: the GNUPGHOME `current` symlink is
                 * boot-volatile (XDG_RUNTIME_DIR), so its absence is the
                 * liveness test — a builtin test, no spawn, unlike ssh-add. */
                printf("            case '*gpg*'\n");
                printf("                if not test -d '%s'\n", gpg_home);
                printf("                    gitswitch resume >/dev/null\n");
                printf("                end\n");
            }
            /* 'none' (identity-only): git config is persistent, nothing to
             * restore — no probe, no resume. */
            printf("        end\n");            /* close switch */
            printf("        set -e __gitswitch_needs\n");
            printf("    end\n");                /* close `if test -e <hint>` */
        } else {
            printf("    env SSH_AUTH_SOCK=$__gitswitch_auth_sock ssh-add -l >/dev/null 2>&1\n");
            printf("    if test $status -gt 1\n");
            printf("        gitswitch resume >/dev/null\n");
            printf("    end\n");
        }
        printf("end\n");
        printf("if test -S $__gitswitch_auth_sock\n");
        printf("    set -gx SSH_AUTH_SOCK $__gitswitch_auth_sock\n");
        printf("end\n");
        printf("set -e __gitswitch_auth_sock\n");
        if (have_gpg_home) {
            printf("set -l __gitswitch_gnupghome '%s'\n", gpg_home);
            printf("if test -d $__gitswitch_gnupghome\n");
            printf("    set -gx GNUPGHOME $__gitswitch_gnupghome\n");
            printf("end\n");
            printf("set -e __gitswitch_gnupghome\n");
        }
        return finish_snippet_emit();
    }

    if (strcmp(shell, "bash") == 0 || strcmp(shell, "zsh") == 0 ||
        strcmp(shell, "sh") == 0 || strcmp(shell, "dash") == 0 ||
        strcmp(shell, "ksh") == 0) {
        printf("# gitswitch shell integration (%s)\n", shell);
        printf("__gitswitch_auth_sock='%s'\n", sock_path);
        /* First interactive shell after a boot: if no SSH agent is reachable at
         * the stable socket, resume the last account. We probe with `ssh-add -l`
         * (exit > 1 means no agent reachable) rather than `test -S`, because a
         * stale socket file left behind after a reboot — common on macOS, which
         * doesn't wipe /tmp — passes a plain -S test and would silently skip
         * resume. Interactive-gated so pinentry has a user. The notice comes
         * from `resume` itself (stderr) only when there is an account to
         * restore — see the fish branch above for why. */
        printf("case $- in *i*)\n");
        if (have_hint) {
            /* Pick the probe by the account's recorded runtime needs (hint
             * file content) so an SSH-less active account never spawns a
             * doomed ssh-add + resume every shell (AR-02 #23). Empty/unknown
             * content (a pre-#23 hint) falls back to the ssh-add probe. read
             * and case are shell builtins — no extra process. */
            printf("    if [ -e '%s' ]; then\n", hint_path);
            printf("        IFS= read -r __gitswitch_needs < '%s' 2>/dev/null || __gitswitch_needs=ssh\n", hint_path);
            printf("        case \"$__gitswitch_needs\" in\n");
            printf("        ''|*ssh*)\n");
            printf("            SSH_AUTH_SOCK=\"$__gitswitch_auth_sock\" ssh-add -l >/dev/null 2>&1\n");
            printf("            [ $? -gt 1 ] && gitswitch resume >/dev/null ;;\n");
            if (have_gpg_home) {
                /* GPG-only: the boot-volatile GNUPGHOME symlink's absence is
                 * the liveness test — a builtin, no ssh-add spawn. */
                printf("        *gpg*)\n");
                printf("            [ -d '%s' ] || gitswitch resume >/dev/null ;;\n", gpg_home);
            }
            /* 'none' (identity-only): nothing to restore. */
            printf("        esac\n");
            printf("        unset __gitswitch_needs\n");
            printf("    fi ;;\n");
        } else {
            printf("    SSH_AUTH_SOCK=\"$__gitswitch_auth_sock\" ssh-add -l >/dev/null 2>&1\n");
            printf("    if [ $? -gt 1 ]; then\n");
            printf("        gitswitch resume >/dev/null\n");
            printf("    fi ;;\n");
        }
        printf("esac\n");
        printf("[ -S \"$__gitswitch_auth_sock\" ] && export SSH_AUTH_SOCK=\"$__gitswitch_auth_sock\"\n");
        printf("unset __gitswitch_auth_sock\n");
        if (have_gpg_home) {
            printf("__gitswitch_gnupghome='%s'\n", gpg_home);
            printf("[ -d \"$__gitswitch_gnupghome\" ] && export GNUPGHOME=\"$__gitswitch_gnupghome\"\n");
            printf("unset __gitswitch_gnupghome\n");
        }
        return finish_snippet_emit();
    }

    fprintf(stderr,
            "gitswitch: unsupported shell '%s' (supported: fish, bash, zsh, sh, dash, ksh)\n",
            shell);
    return EXIT_FAILURE;
}

/* True when the saved account's per-boot runtime state is already live, so
 * `resume` can no-op silently. The shell snippet can only probe the SSH agent
 * socket, but a GPG-only account never creates one (its switch tears the SSH
 * side down), so without this check every interactive shell would re-run the
 * whole switch and re-print the restore notice for such accounts (F2).
 * - SSH accounts: never "already applied" here — the snippet's ssh-add probe
 *   IS the liveness test, and when it fails a real re-switch is needed.
 * - GPG-only accounts: live iff the stable GNUPGHOME `current` symlink points
 *   at THIS account's isolated home and that home still exists. The symlink
 *   lives under XDG_RUNTIME_DIR (wiped per boot on Linux) or /tmp; where /tmp
 *   survives a reboot (macOS/BSD), the home it points at survived with it, so
 *   skipping the re-switch there is still correct.
 * - Identity-only accounts: git config is persistent, nothing boot-volatile
 *   exists to restore, so resume is always a silent no-op.
 * Every "can't tell" case returns false (resume runs) — a redundant resume is
 * an annoyance, a wrongly-skipped one leaves the user without their agent. */
static bool resume_already_applied(const account_t *acct) {
    bool wants_ssh = acct->ssh_enabled && acct->ssh_key_path[0] != '\0';
    bool wants_gpg = acct->gpg_enabled && acct->gpg_key_id[0] != '\0';

    if (wants_ssh) {
        return false;
    }

    if (wants_gpg) {
        char link_path[MAX_PATH_LEN];
        char target[MAX_PATH_LEN];
        struct stat st;
        const char *base;
        ssize_t len;

        if (gpg_manager_get_home_path(link_path, sizeof(link_path)) != 0) {
            return false;
        }
        len = readlink(link_path, target, sizeof(target) - 1);
        if (len <= 0 || (size_t)len >= sizeof(target) - 1) {
            return false; /* absent (fresh boot) or possibly truncated */
        }
        target[len] = '\0';

        /* Each switch points <base>/current at <base>/<account-name>; a stale
         * link left at some OTHER account's home must not suppress the resume. */
        base = strrchr(target, '/');
        base = base ? base + 1 : target;
        if (strcmp(base, acct->name) != 0) {
            return false;
        }

        /* stat() follows the symlink: a dangling link (home deleted, e.g. by
         * `gitswitch reset`) means the state is gone and a resume is needed. */
        return stat(link_path, &st) == 0 && S_ISDIR(st.st_mode);
    }

    return true;
}

/* Re-activate the last-active account, recorded in config across reboots. This
 * is what `gitswitch init` auto-runs on the first login after a boot (when the
 * runtime SSH socket is gone), and is also usable manually. It restores only
 * the boot-volatile runtime state — reloads the SSH key into a fresh agent and
 * rebuilds the isolated GPG home + symlinks. It deliberately does NOT touch
 * git config: that is persistent, already correct from the original switch,
 * and the login shell's cwd is rarely the repo a local-scope write would need
 * (AR-02 #8). A no-op (success) when there is no saved account or it no longer
 * exists, so it can never break a login shell. */
static int handle_resume_command(gitswitch_ctx_t *ctx) {
    account_t *acct;

    if (!ctx) return EXIT_FAILURE;

    /* Mark this as a resume so accounts_switch skips the blocking SSH
     * connection test — this runs from the login shell and must not stall the
     * prompt on a network round trip. */
    ctx->config.resuming = true;

    if (ctx->config.active_account[0] == '\0') {
        log_debug("No saved account to resume");
        return EXIT_SUCCESS;
    }

    acct = config_find_account(ctx, ctx->config.active_account);
    if (!acct) {
        log_debug("Saved account no longer exists, skipping resume: %s",
                  ctx->config.active_account);
        return EXIT_SUCCESS;
    }

    /* Already live this boot: exit silently before the notice below. The shell
     * snippet re-invokes resume whenever its ssh-add probe fails, which for a
     * GPG-only account is EVERY interactive shell — re-running the switch and
     * nagging on each one is exactly the F2 bug. */
    if (resume_already_applied(acct)) {
        log_debug("Runtime state for '%s' already live; resume is a no-op",
                  ctx->config.active_account);
        return EXIT_SUCCESS;
    }

    /* Resume must never read stdin: the init snippet invokes it on every
     * interactive shell with stdin attached to the user's TTY and stdout
     * suppressed, so any prompt inside the switch (e.g. the global-scope
     * consent question in accounts_switch) would invisibly block the shell
     * waiting for input the user doesn't know it wants. Point stdin at
     * /dev/null so those paths see a non-TTY and fail closed with a printed
     * error instead of hanging the login; pinentry/ssh passphrase prompts are
     * unaffected (they talk to the TTY directly, not stdin). Fail closed if we
     * can't detach (F2). */
    if (!freopen("/dev/null", "r", stdin)) {
        fprintf(stderr, "gitswitch: cannot detach stdin for resume: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    /* On stderr (the `init` snippet suppresses stdout), and only once we know
     * there is something to resume: the snippet re-runs resume on every shell
     * where the agent probe fails, and a machine with no saved account would
     * otherwise see this notice before every prompt. Printed ahead of the
     * switch so it explains the GPG PIN prompt that may follow (pinentry
     * draws on the TTY directly). */
    fprintf(stderr,
            "gitswitch: restoring your last account (you may be prompted for your GPG PIN)...\n");

    if (accounts_switch(ctx, ctx->config.active_account) != 0) {
        /* Emitted to stderr (not the suppressed stdout) so a failed login-time
         * resume isn't silent: the `init` snippet runs `gitswitch resume
         * >/dev/null`, leaving stderr visible. */
        fprintf(stderr, "gitswitch: failed to resume '%s': %s\n",
                ctx->config.active_account, get_last_error()->message);
        return EXIT_FAILURE;
    }

    display_success("Resumed: %s", ctx->config.active_account);
    return EXIT_SUCCESS;
}

/* Tear down isolated SSH/GPG state: kill the per-account agents and delete
 * (unlink) the isolated GPG homes holding the exported secret-key copies. On
 * the default memory-backed storage that destroys the bytes; on the
 * GITSWITCH_ALLOW_TMP_GPG non-tmpfs opt-in path they may remain forensically
 * recoverable after deletion (AR-02 #26). With an account argument, only that
 * account; otherwise all. Destructive — confirmed. */
static int handle_reset_command(gitswitch_ctx_t *ctx, const char *account) {
    char resp[16];
    const char *target = NULL;

    if (!ctx) return EXIT_FAILURE;

    /* Resolve the argument to a real account first (fuzzy/ID matching for
     * free) so a typo can't report a false success while the intended
     * account's on-disk secret-key copy is left in place. */
    if (account && *account) {
        account_t *acct = config_find_account(ctx, account);
        if (!acct) {
            display_error("Account not found", "%s", account);
            return EXIT_FAILURE;
        }
        target = acct->name;
        printf("This kills the SSH/GPG agents and deletes the isolated GPG home for\n"
               "'%s', removing its on-disk secret-key copy.\n", target);
    } else {
        printf("This kills ALL gitswitch SSH/GPG agents and deletes ALL isolated GPG\n"
               "homes, removing every on-disk secret-key copy.\n");
    }

    /* This is the most destructive operation (it deletes the exported
     * secret-key copies), so require a typed 'yes' — matching remove and
     * stronger than a bare 'y', which is easy to hit by muscle memory. --yes
     * skips the prompt for scripting. */
    if (!ctx->config.assume_yes) {
        printf("Type 'yes' to continue: ");
        fflush(stdout);
        if (!fgets(resp, sizeof(resp), stdin)) {
            printf("Reset cancelled.\n");
            return EXIT_SUCCESS;
        }
        resp[strcspn(resp, "\n")] = '\0';
        if (strcmp(resp, "yes") != 0) {
            printf("Reset cancelled.\n");
            return EXIT_SUCCESS;
        }
    }

    /* ssh_manager_reset already drops the stable current.sock link (under its
     * per-dir lock) when it targets the account being reset. The redundant
     * unlocked readlink/compare/unlink that used to live here raced a
     * concurrent same-account re-switch: reset reaped the agent and unlinked
     * current.sock under the lock, unlocked, the re-switch installed a fresh
     * agent and re-pointed current.sock, and then this now-unlocked block
     * deleted that freshly-installed live link — leaving a working agent with
     * a dangling SSH_AUTH_SOCK (AR-02 #11). Removed; the locked cleanup in
     * ssh_manager_reset is the single source of truth. */
    ssh_manager_reset(target);

    gpg_manager_reset(target);

    if (target) {
        display_success("Reset gitswitch state for: %s", target);
    } else {
        display_success("Reset all gitswitch SSH/GPG state");
    }
    return EXIT_SUCCESS;
}
