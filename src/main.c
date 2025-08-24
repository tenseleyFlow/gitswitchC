/* gitswitch-c: Safe git identity switching with SSH/GPG isolation
 * Complete CLI with account management and authentication isolation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

#include "gitswitch.h"
#include "config.h"
#include "accounts.h"
#include "display.h"
#include "error.h"
#include "utils.h"

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] [COMMAND] [ARGS]\n", prog_name);
    printf("\nComplete Git Identity Management\n");
    printf("Safe git identity switching with actual git configuration management\n");
    printf("\nCommands:\n");
    printf("  add                  Add new account interactively\n");
    printf("  list, ls             List all configured accounts\n");
    printf("  remove <account>     Remove specified account\n");
    printf("  status               Show current account status\n");
    printf("  doctor, health       Run comprehensive health check\n");
    printf("  config               Show configuration file information\n");
    printf("  <account>            Switch to specified account\n");
    printf("\nOptions:\n");
    printf("  --global, -g         Use global git scope\n");
    printf("  --local, -l          Use local git scope (default)\n");
    printf("  --dry-run, -n        Show what would be done without executing\n");
    printf("  --verbose, -V        Enable verbose output\n");
    printf("  --debug, -d          Enable debug logging\n");
    printf("  --color, -c          Force color output\n");
    printf("  --no-color, -C       Disable color output\n");
    printf("  --help, -h           Show this help message\n");
    printf("  --version, -v        Show version information\n");
    printf("\nExamples:\n");
    printf("  %s add                    # Add new account interactively\n", prog_name);
    printf("  %s list                   # List all accounts\n", prog_name);
    printf("  %s 1                      # Switch to account ID 1\n", prog_name);
    printf("  %s work                   # Switch to account matching 'work'\n", prog_name);
    printf("  %s remove 2               # Remove account ID 2\n", prog_name);
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
    printf("%s version %s\n", GITSWITCH_NAME, GITSWITCH_VERSION);
    printf("Safe git identity switching with SSH/GPG isolation\n");
    printf("Built with security and reliability in mind\n\n");
    
    printf("Features:\n");
    printf("• Comprehensive error handling and logging\n");
    printf("• Security-focused utility functions\n");
    printf("• Terminal display with color support\n");
    printf("• Secure TOML configuration management\n");
    printf("• Interactive account creation and management\n");
    printf("• SSH/GPG key validation and security checks\n");
    printf("• Comprehensive health checking system\n");
    printf("• Atomic file operations with backups\n");
    printf("• Git operations and configuration management\n");
    printf("• Repository detection and scope handling\n");
    printf("• Isolated SSH agents per account\n");
    printf("• SSH connection testing and isolation\n");
    printf("• Isolated GPG environments per account\n");
    printf("• Complete GPG signing and key management\n");
    printf("• Production-ready authentication isolation\n");
}
static int handle_add_command(gitswitch_ctx_t *ctx);
static int handle_list_command(gitswitch_ctx_t *ctx);
static int handle_remove_command(gitswitch_ctx_t *ctx, const char *identifier);
static int handle_status_command(gitswitch_ctx_t *ctx);
static int handle_switch_command(gitswitch_ctx_t *ctx, const char *identifier);
static int handle_doctor_command(gitswitch_ctx_t *ctx);
static int handle_config_command(gitswitch_ctx_t *ctx);

int main(int argc, char *argv[]) {
    gitswitch_ctx_t ctx;
    int opt;
    bool force_color = false;
    bool no_color = false;
    bool show_help = false;
    bool show_version = false;
    bool dry_run = false;
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
        {0, 0, 0, 0}
    };
    
    /* Initialize error handling */
    if (error_init(LOG_LEVEL_INFO, NULL) != 0) {
        fprintf(stderr, "Failed to initialize error handling\n");
        return EXIT_FAILURE;
    }
    
    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "hvccVdngl", long_options, NULL)) != -1) {
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
                /* Global scope - will be handled by command handlers */
                break;
            case 'l':
                /* Local scope - will be handled by command handlers */
                break;
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
    
    /* Initialize configuration system */
    log_info("Initializing gitswitch-c configuration system");
    if (config_init(&ctx) != 0) {
        display_error("Configuration initialization failed", get_last_error()->message);
        error_cleanup();
        return EXIT_CONFIG_ERROR;
    }
    
    /* Set dry run mode if requested */
    ctx.config.dry_run = dry_run;
    ctx.config.verbose = (get_last_error() != NULL && should_log(LOG_LEVEL_DEBUG));
    
    /* Parse command and arguments */
    const char *command = NULL;
    const char *arg1 = NULL;
    
    if (optind < argc) {
        command = argv[optind];
        if (optind + 1 < argc) {
            arg1 = argv[optind + 1];
        }
    }
    
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
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        exit_code = handle_list_command(&ctx);
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
    } else {
        /* Assume it's an account identifier for switching */
        exit_code = handle_switch_command(&ctx, command);
    }
    
    /* Save configuration only for commands that modify accounts */
    bool should_save = false;
    if (command && exit_code == EXIT_SUCCESS && !dry_run) {
        if (strcmp(command, "add") == 0 || 
            strcmp(command, "remove") == 0 || 
            strcmp(command, "rm") == 0 || 
            strcmp(command, "delete") == 0) {
            should_save = true;
        } else if (strcmp(command, "list") != 0 && 
                   strcmp(command, "ls") != 0 &&
                   strcmp(command, "status") != 0 &&
                   strcmp(command, "doctor") != 0 &&
                   strcmp(command, "health") != 0 &&
                   strcmp(command, "config") != 0) {
            /* Assume it's a switch command - may have modified default scope */
            should_save = true;
        }
        
        if (should_save) {
            log_debug("Saving configuration after %s command (account_count=%zu)", 
                     command, ctx.account_count);
            if (config_save(&ctx, ctx.config.config_path) != 0) {
                display_warning("Failed to save configuration changes");
                /* Don't fail the command, just warn */
            }
        }
    }
    
    /* Cleanup */
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

static int handle_list_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    return accounts_list(ctx) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
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
    
    display_success("Successfully switched to account: %s", ctx->current_account->name);
    
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
            
            if (tolower(input[0]) == 'y') {
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

