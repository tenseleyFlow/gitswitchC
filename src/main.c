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
#define OPT_RESUME_CHECK 0x102
#define OPT_RESUME_HINT_PROBE 0x103

static const char *const g_supported_shells[] = {
    "bash", "zsh", "fish", "sh", "dash", "ksh"
};

static void print_supported_shells(FILE *stream, const char *separator) {
    size_t count = sizeof(g_supported_shells) / sizeof(g_supported_shells[0]);

    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            fputs(separator, stream);
        }
        fputs(g_supported_shells[i], stream);
    }
}

static bool shell_is_supported(const char *shell) {
    size_t count = sizeof(g_supported_shells) / sizeof(g_supported_shells[0]);

    if (!shell) return false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(shell, g_supported_shells[i]) == 0) return true;
    }
    return false;
}

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
    printf("  init <shell>         Emit shell integration (");
    print_supported_shells(stdout, "|");
    printf(")\n");
    printf("  resume               Restore saved boot-volatile SSH/GPG state (never rewrites Git config)\n");
    printf("  reset [account]      Kill agents and delete isolated GPG/SSH state (all, or one)\n");
    printf("  switch <account>     Switch to specified account\n");
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
typedef enum {
    COMMAND_SAVE_NONE = 0,
    COMMAND_SAVE_FULL,
    COMMAND_SAVE_ACTIVE
} command_save_kind_t;

typedef enum {
    COMMAND_NOTICE_NONE = 0,
    COMMAND_NOTICE_ADD,
    COMMAND_NOTICE_EDIT,
    COMMAND_NOTICE_REMOVE,
    COMMAND_NOTICE_SWITCH,
    COMMAND_NOTICE_RESET_ONE,
    COMMAND_NOTICE_RESET_ALL
} command_notice_kind_t;

/* Mutating handlers describe what they changed; main owns persistence and the
 * final user-visible success. A prepared switch also carries the resume-hint
 * before-image needed to undo a post-mutation commit failure. */
typedef struct {
    int status;
    command_save_kind_t save_kind;
    command_notice_kind_t notice_kind;
    bool switch_prepared;
    bool edit_prepared;
    bool reset_guarded;
    config_resume_hint_snapshot_t hint_snapshot;
    char previous_active[MAX_NAME_LEN];
    char subject[MAX_NAME_LEN];
} command_result_t;

/* Deterministic reset transaction checkpoints used only by the dedicated
 * AR-07 regression binary.  The production main object contains no injectable
 * environment-variable seam and pays only for the no-op calls below. */
enum {
    RESET_TEST_AFTER_SSH = 1,
    RESET_TEST_AFTER_GPG,
    RESET_TEST_AFTER_ACTIVE_CLEAR,
    RESET_TEST_AFTER_ACTIVE_COMMIT
};

#ifdef GITSWITCH_TESTING
typedef void (*reset_test_hook_fn)(int stage);
typedef void (*remove_test_hook_fn)(int stage);
reset_test_hook_fn gitswitch_test_set_reset_hook(reset_test_hook_fn hook);
remove_test_hook_fn gitswitch_test_set_remove_hook(remove_test_hook_fn hook);
void gitswitch_test_remove_checkpoint(int stage);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);

static reset_test_hook_fn g_reset_test_hook;
static remove_test_hook_fn g_remove_test_hook;
static int g_context_allocations;
static int g_context_allocation_total;

reset_test_hook_fn gitswitch_test_set_reset_hook(reset_test_hook_fn hook) {
    reset_test_hook_fn previous = g_reset_test_hook;
    g_reset_test_hook = hook;
    return previous;
}

remove_test_hook_fn gitswitch_test_set_remove_hook(remove_test_hook_fn hook) {
    remove_test_hook_fn previous = g_remove_test_hook;
    g_remove_test_hook = hook;
    return previous;
}

void gitswitch_test_remove_checkpoint(int stage) {
    if (g_remove_test_hook) g_remove_test_hook(stage);
}

int gitswitch_test_context_allocations(void) {
    return g_context_allocations;
}

int gitswitch_test_context_allocation_total(void) {
    return g_context_allocation_total;
}
#endif

static void reset_test_checkpoint(int stage) {
#ifdef GITSWITCH_TESTING
    if (g_reset_test_hook) g_reset_test_hook(stage);
#else
    (void)stage;
#endif
}

static void remove_test_checkpoint(int stage) {
#ifdef GITSWITCH_TESTING
    gitswitch_test_remove_checkpoint(stage);
#else
    (void)stage;
#endif
}

static command_result_t command_result(int status);
static void emit_command_success(const gitswitch_ctx_t *ctx,
                                 const command_result_t *result);
static command_result_t handle_add_command(gitswitch_ctx_t *ctx);
static command_result_t handle_edit_command(gitswitch_ctx_t *ctx,
                                            const char *identifier);
static int handle_list_command(gitswitch_ctx_t *ctx);
static int handle_list_names(gitswitch_ctx_t *ctx);
static command_result_t handle_remove_command(gitswitch_ctx_t *ctx,
                                              const char *identifier);
static int handle_status_command(gitswitch_ctx_t *ctx);
static command_result_t handle_switch_command(gitswitch_ctx_t *ctx,
                                              const char *identifier);
static int handle_doctor_command(gitswitch_ctx_t *ctx);
static int handle_config_command(gitswitch_ctx_t *ctx);
static int handle_init_command(const char *shell);
static int handle_resume_command(gitswitch_ctx_t *ctx);
static int handle_resume_check_command(gitswitch_ctx_t *ctx);
static command_result_t handle_reset_command(gitswitch_ctx_t *ctx,
                                             const char *account);
static const char *detect_shell_from_env(void);

#ifdef GITSWITCH_TESTING
/* `main` is macro-renamed by the focused reset-test object. Keep the renamed
 * external entry under the same missing-prototype gate as every other API. */
int main(int argc, char *argv[]);
#endif

/* Validate the complete positional grammar before any command can acquire the
 * config lock, create ~/.config/gitswitch, or dispatch a handler. Unknown first
 * positionals are the established bare-account switch form and therefore take
 * no additional operands. */
static int validate_command_arity(const char *command, int operand_count,
                                  const char *first_operand) {
    const char *usage = NULL;
    int min_operands = 0;
    int max_operands = 0;

    if (!command) {
        return operand_count == 0 ? 0 : -1;
    }

    if (strcmp(command, "edit") == 0) {
        min_operands = max_operands = 1;
        usage = "gitswitch edit <account>";
    } else if (strcmp(command, "remove") == 0 ||
               strcmp(command, "rm") == 0 ||
               strcmp(command, "delete") == 0) {
        min_operands = max_operands = 1;
        usage = "gitswitch remove <account>";
    } else if (strcmp(command, "switch") == 0) {
        min_operands = max_operands = 1;
        usage = "gitswitch switch <account>";
    } else if (strcmp(command, "reset") == 0) {
        max_operands = 1;
        usage = "gitswitch reset [account]";
    } else if (strcmp(command, "init") == 0) {
        max_operands = 1;
        usage = "gitswitch init [shell]";
    } else if (strcmp(command, "add") == 0 ||
               strcmp(command, "list") == 0 ||
               strcmp(command, "ls") == 0 ||
               strcmp(command, "status") == 0 ||
               strcmp(command, "doctor") == 0 ||
               strcmp(command, "health") == 0 ||
               strcmp(command, "config") == 0 ||
               strcmp(command, "resume") == 0) {
        usage = command;
    } else {
        usage = "gitswitch <account>";
    }

    if (operand_count >= min_operands && operand_count <= max_operands) {
        if (strcmp(command, "reset") == 0 && operand_count == 1 &&
            (!first_operand || first_operand[0] == '\0')) {
            fprintf(stderr,
                    "gitswitch: reset account selector must not be empty\n");
            fprintf(stderr, "Usage: gitswitch reset [account]\n");
            return -1;
        }
        return 0;
    }

    if (text_is_tty_safe(command)) {
        fprintf(stderr, "gitswitch: invalid number of operands for '%s'\n",
                command);
    } else {
        fprintf(stderr, "gitswitch: invalid number of operands\n");
    }
    if (usage == command) {
        fprintf(stderr, "Usage: gitswitch %s\n", usage);
    } else {
        fprintf(stderr, "Usage: %s\n", usage);
    }
    return -1;
}

static command_result_t command_result(int status) {
    command_result_t result;

    memset(&result, 0, sizeof(result));
    result.status = status;
    return result;
}

static void emit_command_success(const gitswitch_ctx_t *ctx,
                                 const command_result_t *result) {
    if (!ctx || !result || result->status != EXIT_SUCCESS) {
        return;
    }
    switch (result->notice_kind) {
        case COMMAND_NOTICE_ADD:
            display_success("Account added successfully!");
            break;
        case COMMAND_NOTICE_EDIT:
            display_success("Account updated.");
            break;
        case COMMAND_NOTICE_REMOVE:
            display_success("Account removed successfully.");
            break;
        case COMMAND_NOTICE_SWITCH:
            display_success("Switched to: %s", result->subject);
            break;
        case COMMAND_NOTICE_RESET_ONE:
            display_success("Reset gitswitch state for: %s", result->subject);
            break;
        case COMMAND_NOTICE_RESET_ALL:
            display_success("Reset all gitswitch SSH/GPG state");
            break;
        case COMMAND_NOTICE_NONE:
        default:
            break;
    }
}

int main(int argc, char *argv[]) {
    gitswitch_ctx_t *ctx = NULL;
    command_result_t mutation = command_result(EXIT_SUCCESS);
    bool has_mutation_result = false;
    bool signal_guard_cleanup_failed = false;
    const char *pending_signal_notice = NULL;
    int config_lock_fd = -1;
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
    bool legacy_agent_info = false;
    bool resume_check = false;
    bool resume_hint_probe = false;
    const char *command = NULL;
    const char *arg1 = NULL;
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
        /* Internal, non-switching shell-integration readiness probe. It may
         * acquire manager runtime locks while inspecting live state, but never
         * changes config, identity, or agent/key routing. It is deliberately
         * unadvertised; `init` uses it to distinguish a status-0 wrong/extra
         * key agent from the exact saved runtime. */
        {"resume-check", no_argument, 0, OPT_RESUME_CHECK},
        /* Internal, read-only parser for the login-shell resume decision. It
         * validates the artifact without letting shell code open it directly. */
        {"resume-hint-probe", no_argument, 0, OPT_RESUME_HINT_PROBE},
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
            case OPT_SSH_AGENT_INFO:
                legacy_agent_info = true;
                break;
            case OPT_RESUME_CHECK:
                resume_check = true;
                break;
            case OPT_RESUME_HINT_PROBE:
                resume_hint_probe = true;
                break;
            default:
                print_usage(argv[0]);
                error_cleanup();
                return EXIT_FAILURE;
        }
    }
    
    /* AR-06 F62: --global and --local are contradictory. Silently letting
     * --global win hid a user's mistake and could write the wrong scope; fail
     * with a clear message instead. */
    if (force_global && force_local) {
        fprintf(stderr, "gitswitch: --global and --local are mutually exclusive\n");
        error_cleanup();
        return EXIT_FAILURE;
    }

    /* getopt_long has already permuted recognized options out of the
     * positional tail, including options written after a command operand. */
    if (optind < argc) {
        command = argv[optind];
        if (optind + 1 < argc) {
            arg1 = argv[optind + 1];
        }
    }

    /* Help/version remain unconditional informational exits. Every executable
     * command form, including the legacy init alias, is otherwise checked here
     * before display/config initialization can cause observable work. */
    if (!show_help && !show_version) {
        int internal_modes = (legacy_agent_info ? 1 : 0) +
                             (resume_check ? 1 : 0) +
                             (resume_hint_probe ? 1 : 0);
        const char *internal_name = legacy_agent_info ? "--ssh-agent-info" :
            (resume_check ? "--resume-check" : "--resume-hint-probe");

        if (internal_modes > 0 && command) {
            fprintf(stderr,
                    "gitswitch: %s does not accept operands\n",
                    internal_name);
            error_cleanup();
            return EXIT_FAILURE;
        }
        if (internal_modes > 1) {
            fprintf(stderr,
                    "gitswitch: internal shell probes are mutually exclusive\n");
            error_cleanup();
            return EXIT_FAILURE;
        }
        if (internal_modes == 0 &&
            validate_command_arity(command,
                                   command ? argc - optind - 1 : 0,
                                   arg1) != 0) {
            error_cleanup();
            return EXIT_FAILURE;
        }
    }

    /* Handle informational commands before display/config initialization and,
     * critically, before allocating the large application context. */
    if (show_version) {
        print_version();
        error_cleanup();
        return EXIT_SUCCESS;
    }

    if (resume_hint_probe && !show_help) {
        char needs[8];
        int rc = config_resume_hint_probe(needs, sizeof(needs));

        if (rc == 0 &&
            (printf("%s\n", needs) < 0 || fflush(stdout) != 0)) {
            rc = -1;
        }
        error_cleanup();
        return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* Initialize display system */
    if (display_init(force_color, no_color) != 0) {
        log_error("Failed to initialize display system");
        error_cleanup();
        return EXIT_FAILURE;
    }
    
    if (show_help) {
        print_usage(argv[0]);
        error_cleanup();
        return EXIT_SUCCESS;
    }

    if (legacy_agent_info) {
        int rc = handle_init_command(detect_shell_from_env());
        error_cleanup();
        return rc;
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

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        display_error("Could not allocate application context", "%s",
                      strerror(errno));
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }
#ifdef GITSWITCH_TESTING
    g_context_allocations++;
    g_context_allocation_total++;
#endif

    /* For commands that mutate shared state, hold an exclusive cross-process
     * lock across the WHOLE load->mutate->save cycle. That is not just the
     * config read-modify-writers (add/edit/remove, a bare-account switch that
     * updates active_account): `resume` mutates only boot-volatile SSH/GPG
     * runtime state (it deliberately leaves Git configuration untouched), and
     * `reset` kills agents and retargets/deletes runtime symlinks. Both must be
     * serialized against a concurrent switch or the final runtime can belong
     * to a different account than the switch's persisted Git identity
     * (AR-02 #1: tmux-restore shells running resume while another shell
     * switches). Acquire before config_init
     * so the load itself happens under the lock. Only genuinely read-only
     * commands (list/status/doctor) skip it; `config` can create accounts.toml,
     * so it belongs to the locked class too (AR-03 L11). Acquisition is
     * nonblocking because the holder may be waiting indefinitely at a prompt;
     * an arbitrary retry window would only turn a clear contention result back
     * into login/command latency (AR-03 L10). Fail closed on other lock errors:
     * silently proceeding unlocked would reopen the exact lost-update and
     * split-identity races the lock exists to prevent (AR-02 #17). */
    {
        const char *c = (optind < argc) ? argv[optind] : NULL;
        bool read_only = resume_check || (c == NULL) ||
            strcmp(c, "list") == 0 || strcmp(c, "ls") == 0 ||
            strcmp(c, "status") == 0 || strcmp(c, "doctor") == 0 ||
            strcmp(c, "health") == 0;
        /* Preview-only work must not create/chmod the config directory or its
         * lock. The read-only initializer below can still inspect an existing
         * config, while a fresh HOME remains byte-for-byte untouched. */
        if (!read_only && !dry_run) {
            config_lock_fd = config_write_lock();
            if (config_lock_fd < 0) {
                int lock_errno = errno;
                bool contended = lock_errno == EWOULDBLOCK;
#if EAGAIN != EWOULDBLOCK
                contended = contended || lock_errno == EAGAIN;
#endif

                /* Shell integration invokes resume during login. A concurrent
                 * switch already owns serialization and will leave a coherent
                 * result, so this redundant restore is a successful no-op and
                 * must not delay or alarm every newly opened shell. */
                if (contended && c && strcmp(c, "resume") == 0) {
                    exit_code = EXIT_SUCCESS;
                    goto cleanup;
                }
                if (contended) {
                    display_error("Another gitswitch holds the config lock",
                                  "try again after that command finishes");
                } else {
                    display_error("Could not acquire the gitswitch config lock",
                                  "the config directory or lock is unavailable; "
                                  "check permissions and try again");
                }
                exit_code = EXIT_FAILURE;
                goto cleanup;
            }
        }
    }

    /* Completion invokes `list --names` on every TAB. Give exactly that
     * grammar a names-only loader which parses the full account document but
     * ignores active/runtime state; other uses of --names retain the ordinary
     * command initialization contract. */
    log_info("Initializing gitswitch-c configuration system");
    bool names_list = names_only && command &&
        (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0);
    int config_rc = names_list ? config_init_names(ctx) :
        ((dry_run || resume_check) ? config_init_readonly(ctx) :
                                     config_init(ctx));
    if (config_rc != 0) {
        display_error("Configuration initialization failed", "%s", get_last_error()->message);
        exit_code = EXIT_CONFIG_ERROR;
        goto cleanup;
    }
    
    /* Set dry run mode if requested */
    ctx->config.dry_run = dry_run;
    ctx->config.force_global = force_global;
    ctx->config.force_local = force_local;
    ctx->config.assume_yes = assume_yes;
    ctx->config.verbose = should_log(LOG_LEVEL_DEBUG);
    /* accounts.c historically re-raised interrupted direct/library calls at
     * its own rollback boundary. The CLI owns additional resources beyond
     * that boundary, so its common tail performs the truthful re-raise only
     * after releasing the config lock and securely freeing this heap context. */
    ctx->config.defer_signal_cleanup = true;

    /* Execute command */
    if (resume_check) {
        exit_code = handle_resume_check_command(ctx);
    } else if (command == NULL) {
        /* No command specified - interactive mode or help */
        if (ctx->account_count == 0) {
            display_header("Welcome to gitswitch-c");
            display_warning("No accounts configured yet");
            printf("\nTo get started:\n");
            printf("  1. Run 'gitswitch add' to create your first account\n");
            printf("  2. Run 'gitswitch list' to see all accounts\n");
            printf("  3. Run 'gitswitch <account>' to switch accounts\n");
            printf("  4. Run 'gitswitch --help' for more options\n\n");
        } else {
            /* Show account list */
            exit_code = handle_list_command(ctx);
        }
    } else if (strcmp(command, "add") == 0) {
        mutation = handle_add_command(ctx);
        has_mutation_result = true;
        exit_code = mutation.status;
    } else if (strcmp(command, "edit") == 0) {
        mutation = handle_edit_command(ctx, arg1);
        has_mutation_result = true;
        exit_code = mutation.status;
    } else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        /* `list --names` is a plumbing mode: one account name per line, no
         * decoration, for shell-completion scripts to consume. */
        exit_code = names_only ? handle_list_names(ctx) : handle_list_command(ctx);
    } else if (strcmp(command, "remove") == 0 || strcmp(command, "rm") == 0 || strcmp(command, "delete") == 0) {
        mutation = handle_remove_command(ctx, arg1);
        has_mutation_result = true;
        exit_code = mutation.status;
    } else if (strcmp(command, "status") == 0) {
        exit_code = handle_status_command(ctx);
    } else if (strcmp(command, "doctor") == 0 || strcmp(command, "health") == 0) {
        exit_code = handle_doctor_command(ctx);
    } else if (strcmp(command, "config") == 0) {
        exit_code = handle_config_command(ctx);
    } else if (strcmp(command, "resume") == 0) {
        exit_code = handle_resume_command(ctx);
    } else if (strcmp(command, "reset") == 0) {
        mutation = handle_reset_command(ctx, arg1);
        has_mutation_result = true;
        exit_code = mutation.status;
    } else if (strcmp(command, "switch") == 0) {
        mutation = handle_switch_command(ctx, arg1);
        has_mutation_result = true;
        exit_code = mutation.status;
    } else {
        /* Assume it's an account identifier for switching */
        mutation = handle_switch_command(ctx, command);
        has_mutation_result = true;
        exit_code = mutation.status;
    }

    /* Mutating handlers never print their final success. This centralized
     * commit path persists their structured outcome first, then either commits
     * a prepared switch or rolls it and the active/hint metadata back. */
    if (has_mutation_result && exit_code == EXIT_SUCCESS && !dry_run) {
        int save_rc = 0;
        bool config_installed = false;
        bool switch_commit_retained = false;
        accounts_switch_commit_state_t switch_commit_state =
            ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
        char save_error[sizeof(g_last_error.message)] = "";

        if (mutation.save_kind != COMMAND_SAVE_NONE) {
            log_debug("Saving configuration after %s command (account_count=%zu)",
                      command, ctx->account_count);
            if (signals_guard_begin() != 0) {
                save_rc = -1;
                safe_strncpy(save_error, get_last_error()->message,
                             sizeof(save_error));
            } else {
                signals_rollback_begin();
                if (mutation.save_kind == COMMAND_SAVE_FULL) {
                    if (mutation.edit_prepared) {
                        save_rc = config_save_transactional(
                            ctx, ctx->config.config_path, &config_installed);
                    } else {
                        save_rc = config_save(ctx, ctx->config.config_path);
                    }
                } else if (mutation.switch_prepared) {
                    save_rc = config_save_active_account_transactional(
                        ctx, ctx->config.config_path, &config_installed);
                } else if (mutation.reset_guarded) {
                    save_rc = config_save_active_account_transactional(
                        ctx, ctx->config.config_path, &config_installed);
                } else {
                    save_rc = config_save_active_account(
                        ctx, ctx->config.config_path);
                }
                if (save_rc != 0) {
                    safe_strncpy(save_error, get_last_error()->message,
                                 sizeof(save_error));
                }
                signals_scratch_cleanup();
            }
        }

        if (mutation.switch_prepared && save_rc == 0) {
            if (accounts_switch_commit_result(ctx, &switch_commit_state) != 0) {
                save_rc = -1;
                config_installed = true;
                safe_strncpy(save_error, get_last_error()->message,
                             sizeof(save_error));
                switch_commit_retained =
                    switch_commit_state !=
                    ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED;
            }
        }

        bool edit_rollback_complete = true;
        char edit_rollback_detail[sizeof(g_last_error.message)] = "";
        if (mutation.edit_prepared) {
            /* A post-rename failure means accounts.toml visibly contains the
             * candidate even though durability is uncertain. Keep its SSH
             * routing too; restoring the old block would create a chimera.
             * Only a proven pre-install failure may restore the before-image. */
            if (save_rc == 0 || config_installed) {
                if (accounts_edit_commit(ctx) != 0) {
                    edit_rollback_complete = false;
                    safe_strncpy(edit_rollback_detail,
                                 get_last_error()->message,
                                 sizeof(edit_rollback_detail));
                    save_rc = -1;
                    config_installed = true;
                }
            } else if (accounts_edit_abort(ctx) != 0) {
                edit_rollback_complete = false;
                safe_strncpy(edit_rollback_detail,
                             get_last_error()->message,
                             sizeof(edit_rollback_detail));
            }
        }

        if (mutation.switch_prepared && save_rc != 0 &&
            !switch_commit_retained) {
            bool rollback_complete = true;
            char rollback_detail[sizeof(g_last_error.message)] = "";

            /* Keep the cross-HOME runtime lock owned by the prepared switch
             * until the persistence before-images are restored. Reversing
             * accounts first released that lock and let another HOME sharing
             * XDG_RUNTIME_DIR interleave between runtime and active/hint
             * rollback. The outer config lock still excludes same-HOME
             * writers while these persisted before-images are installed. */
            safe_strncpy(ctx->config.active_account,
                         mutation.previous_active,
                         sizeof(ctx->config.active_account));
            if (config_installed &&
                config_restore_active_account(ctx,
                                              ctx->config.config_path) != 0) {
                rollback_complete = false;
                safe_strncpy(rollback_detail, get_last_error()->message,
                             sizeof(rollback_detail));
            }
            /* The writer cannot touch the hint before the config rename. When
             * no new config inode was installed the before-image is already
             * intact (and may live in the same unwritable directory that
             * caused the save failure), so do not manufacture a rollback
             * failure by rewriting unchanged state. */
            if (config_installed &&
                config_resume_hint_snapshot_restore(
                    &mutation.hint_snapshot) != 0) {
                rollback_complete = false;
                safe_strncpy(rollback_detail, get_last_error()->message,
                             sizeof(rollback_detail));
            }
            /* accounts_switch_abort is deliberately last: it restores
             * Git/runtime and releases the retained shared-runtime lock only
             * after every config/hint rollback attempt has finished. */
            if (accounts_switch_abort(ctx, true) != 0) {
                rollback_complete = false;
                safe_strncpy(rollback_detail, get_last_error()->message,
                             sizeof(rollback_detail));
            }
            if (rollback_complete) {
                display_error("Failed to save configuration changes; previous switch state restored",
                              "%s", save_error[0] ? save_error :
                              "unknown persistence error");
            } else {
                display_error("Failed to save configuration changes; switch rollback incomplete",
                              "%s; rollback error: %s",
                              save_error[0] ? save_error :
                              "unknown persistence error",
                              rollback_detail[0] ? rollback_detail :
                              "unknown rollback error");
            }
            exit_code = EXIT_FAILURE;
            if (signals_pending()) {
                /* Keep repeats deferred through config unlock and heap cleanup;
                 * the actual re-raise is owned by the common tail. */
                signals_rollback_begin();
                pending_signal_notice =
                    "gitswitch: interrupted — switch rollback attempt completed\n";
            }
        } else if (mutation.switch_prepared && switch_commit_retained) {
            /* The SSH config rename crossed its publication point. The
             * structured account result has already committed Git/runtime and
             * released rollback ownership, so retain the matching active file
             * and resume hint too. Exit nonzero because verification or
             * durability was not proven; never misreport this as success. */
            display_error(
                "Account switch committed, but SSH alias publication is uncertain",
                "%s; active metadata, Git identity, runtime state, and the "
                "installed alias were retained together. Verify ~/.ssh/config "
                "and its filesystem durability before retrying",
                save_error[0] ? save_error :
                                "unknown SSH alias publication error");
            exit_code = EXIT_FAILURE;
            if (signals_pending()) {
                signals_rollback_begin();
                pending_signal_notice =
                    "gitswitch: interrupted — committed switch cleanup completed\n";
            }
        } else if (mutation.edit_prepared && save_rc != 0) {
            if (config_installed) {
                display_error("Configuration installed but durability is uncertain",
                              "%s; the edited account and SSH routing were retained "
                              "together. Verify the file before retrying",
                              save_error[0] ? save_error :
                              "unknown persistence error");
            } else if (edit_rollback_complete) {
                display_error("Failed to save configuration changes; previous edit state restored",
                              "%s", save_error[0] ? save_error :
                              "unknown persistence error");
            } else {
                display_error("Failed to save configuration changes; edit rollback incomplete",
                              "%s; rollback error: %s",
                              save_error[0] ? save_error :
                              "unknown persistence error",
                              edit_rollback_detail[0] ? edit_rollback_detail :
                              "unknown rollback error");
            }
            exit_code = EXIT_FAILURE;
        } else if (save_rc != 0) {
            /* Account edits are process-local until this point. Remove/reset
             * may already have completed runtime cleanup; retain the on-disk
             * account as a retry handle and report the possible partial commit
             * explicitly instead of printing a completed mutation. */
            display_error("Failed to save configuration changes",
                          "%s; no success was recorded. The config rename may "
                          "have completed before a later durability or resume-hint failure",
                          save_error[0] ? save_error :
                          "unknown persistence error");
            exit_code = EXIT_FAILURE;
        }

        if (mutation.edit_prepared && signals_pending()) {
            signals_rollback_begin();
            pending_signal_notice =
                "gitswitch: interrupted — edit transaction completed or rolled back\n";
        }

        if (mutation.reset_guarded &&
            mutation.save_kind == COMMAND_SAVE_ACTIVE && save_rc == 0) {
            reset_test_checkpoint(RESET_TEST_AFTER_ACTIVE_COMMIT);
        }

        if (mutation.notice_kind == COMMAND_NOTICE_REMOVE && save_rc == 0) {
            remove_test_checkpoint(5);
        }

        if (exit_code == EXIT_SUCCESS && !pending_signal_notice &&
            !signals_pending()) {
            emit_command_success(ctx, &mutation);
        }
    }

cleanup:
    /* Any path can arrive here with a mutation guard still armed. Mark cleanup
     * rollback-class before touching snapshots, locks, or heap state so a
     * repeated signal cannot bypass the single secure release path. */
    signals_rollback_begin();
    config_resume_hint_snapshot_clear(&mutation.hint_snapshot);

    /* Release the config write-lock now that load+mutate+save is done (harmless
     * no-op for read-only commands that never took it; the OS would also drop it
     * at exit). */
    if (config_lock_fd >= 0) {
        config_write_unlock(config_lock_fd);
    }

    /* The context can contain key paths and identity metadata.  Zero it before
     * release, including initialization/error exits, and keep a confirmed
     * reset's deferral window armed until both this cleanup and lock release
     * have completed. */
    if (ctx) {
        secure_zero_memory(ctx, sizeof(*ctx));
        free(ctx);
        ctx = NULL;
#ifdef GITSWITCH_TESTING
        g_context_allocations--;
#endif
    }
    if (mutation.notice_kind == COMMAND_NOTICE_REMOVE) {
        remove_test_checkpoint(6);
    }

    /* Note: We intentionally do NOT clean up SSH agents on exit.
     * The agent should persist so subsequent git commands can use it.
     * Cleanup happens at the start of the next account switch. */

    signals_rollback_end();

    /* Restore inherited dispositions only after every owned lock and the heap
     * context have been released. Dispatch owns the sole restoration attempt
     * when a signal is pending; pre-ending here would turn a one-shot restore
     * failure into an unchecked immediate retry that could erase the pending
     * interruption. */
    if (!signals_pending() && signals_guard_end() != 0) {
        int retained_signal = signals_pending_signal();
        const char *restore_detail = get_last_error()->message[0]
                                         ? get_last_error()->message
                                         : "unknown signal restoration error";

        if (retained_signal != 0) {
            fprintf(stderr,
                    "gitswitch: command cleanup completed, but restoring "
                    "signal dispositions failed; pending signal %d and guard "
                    "ownership were retained: %s\n",
                    retained_signal, restore_detail);
        } else {
            fprintf(stderr,
                    "gitswitch: command cleanup completed, but restoring "
                    "signal dispositions failed; guard ownership was "
                    "retained: %s\n",
                    restore_detail);
        }
        signal_guard_cleanup_failed = true;
        exit_code = EXIT_FAILURE;
    }

    /* Recheck after a successful guard_end: a signal may have run our handler
     * between the initial pending test and restoration of its disposition. */
    if (signals_pending() && !pending_signal_notice) {
        pending_signal_notice = mutation.reset_guarded
            ? "gitswitch: interrupted — reset transaction cleanup completed\n"
            : "gitswitch: interrupted — command cleanup completed\n";
    }

    /* Cleanup error handling */
    error_cleanup();

    if (!signal_guard_cleanup_failed && pending_signal_notice &&
        signals_pending()) {
        fputs(pending_signal_notice, stderr);
        if (signals_dispatch_pending() != 0) {
            fprintf(stderr,
                    "gitswitch: deferred signal remains pending because "
                    "restoring its saved disposition failed: %s\n",
                    get_last_error()->message[0]
                        ? get_last_error()->message
                        : "unknown signal restoration error");
            exit_code = EXIT_FAILURE;
        }
    }
    return exit_code;
}

/* Command handler implementations */

static command_result_t handle_add_command(gitswitch_ctx_t *ctx) {
    command_result_t result = command_result(EXIT_FAILURE);

    if (!ctx) return result;

    /* AR-06 F24: add has no meaningful dry-run. The old code ran the full
     * interactive flow, mutated the in-memory context, and printed "Account
     * added successfully!" at exit 0 while main()'s !dry_run save gate silently
     * discarded it. Refuse up front instead of feigning success. */
    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
        display_error("Nothing to preview", "add has no dry-run mode; re-run without --dry-run to add an account");
        return result;
    }

    /* AR-03 M9: refuse BEFORE the interactive work. The save at the end of
     * main() is refused whenever the load skipped or failed to recognize
     * sections (rewriting would erase them), so collecting a full account's
     * worth of answers only to discard them — while pre-fix still printing
     * "Account added successfully!" at exit 0 — helps nobody. Fail up front
     * with the reason instead. */
    if (config_check_rewritable(ctx) != 0) {
        display_error("Cannot add an account right now", "%s", get_last_error()->message);
        return result;
    }

    if (accounts_add_interactive(ctx) != 0) {
        display_error("Failed to add account", "%s", get_last_error()->message);
        return result;
    }

    result.status = EXIT_SUCCESS;
    result.save_kind = COMMAND_SAVE_FULL;
    result.notice_kind = COMMAND_NOTICE_ADD;
    return result;
}

static command_result_t handle_edit_command(gitswitch_ctx_t *ctx,
                                            const char *identifier) {
    command_result_t result = command_result(EXIT_FAILURE);

    if (!ctx || !identifier) return result;

    /* AR-06 F24: edit has no meaningful dry-run either — see handle_add_command. */
    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
        display_error("Nothing to preview", "edit has no dry-run mode; re-run without --dry-run to edit an account");
        return result;
    }

    /* AR-03 M9: same up-front refusal as `add` — see handle_add_command. */
    if (config_check_rewritable(ctx) != 0) {
        display_error("Cannot edit an account right now", "%s", get_last_error()->message);
        return result;
    }

    if (accounts_edit_interactive_prepare(ctx, identifier) != 0) {
        display_error("Failed to edit account", "%s", get_last_error()->message);
        return result;
    }
    result.status = EXIT_SUCCESS;
    result.save_kind = COMMAND_SAVE_FULL;
    result.notice_kind = COMMAND_NOTICE_EDIT;
    result.edit_prepared = true;
    return result;
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

static command_result_t handle_remove_command(gitswitch_ctx_t *ctx,
                                              const char *identifier) {
    command_result_t result = command_result(EXIT_FAILURE);
    size_t previous_count;

    if (!ctx || !identifier) return result;
    previous_count = ctx->account_count;

    /* AR-03 M9: refuse before the confirmation prompt — see handle_add_command.
     * (A remove here could only ever target a HEALTHY account anyway: the
     * skipped ones aren't in memory to be found.) */
    if (config_check_rewritable(ctx) != 0) {
        display_error("Cannot remove an account right now", "%s", get_last_error()->message);
        return result;
    }

    /* AR-06 F07: accounts_remove tears down the SSH/GPG runtime (kills agents,
     * deletes the isolated GPG home with its exported secret-key copy) with no
     * dry_run check of its own — the exact destructive-preview hole AR-05 H1
     * closed for `reset` only. Gate here, before the confirmation prompt, the
     * runtime lock, and the manager teardown, mirroring handle_reset_command. */
    if (ctx->config.dry_run) {
        account_t *acct = config_find_account_destructive(ctx, identifier);
        if (!acct) {
            display_error("Account not found", "%s",
                          get_last_error()->message);
            return result;
        }
        display_info("DRY RUN MODE - No actual changes will be made");
        printf("Would kill the SSH/GPG agents and delete the isolated GPG home for\n"
               "'%s' (removing its on-disk secret-key copy), then remove the account\n"
               "from %s.\n", acct->name, ctx->config.config_path);
        display_success("DRY RUN complete - no changes were made");
        result.status = EXIT_SUCCESS;
        return result;
    }

    if (accounts_remove(ctx, identifier) != 0) {
        display_error("Failed to remove account", "%s", get_last_error()->message);
        return result;
    }

    result.status = EXIT_SUCCESS;
    if (ctx->account_count != previous_count) {
        result.save_kind = COMMAND_SAVE_FULL;
        result.notice_kind = COMMAND_NOTICE_REMOVE;
    }
    return result;
}

static int handle_status_command(gitswitch_ctx_t *ctx) {
    if (!ctx) return EXIT_FAILURE;
    
    return accounts_show_status(ctx) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static command_result_t handle_switch_command(gitswitch_ctx_t *ctx,
                                              const char *identifier) {
    command_result_t result = command_result(EXIT_FAILURE);

    if (!ctx || !identifier) return result;

    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
        if (accounts_switch(ctx, identifier) != 0) {
            display_error("Failed to switch account", "%s",
                          get_last_error()->message);
            return result;
        }
        display_success("DRY RUN complete - no changes were made");
        result.status = EXIT_SUCCESS;
        return result;
    }

    /* The hint before-image must be complete before Git or runtime mutation.
     * The prepare call retains every other rollback input until main has
     * committed both active_account and the new hint. */
    if (config_resume_hint_snapshot_capture(&result.hint_snapshot) != 0) {
        display_error("Cannot prepare account switch", "%s",
                      get_last_error()->message);
        return result;
    }
    safe_strncpy(result.previous_active, ctx->config.active_account,
                 sizeof(result.previous_active));
    if (accounts_switch_prepare(ctx, identifier) != 0) {
        display_error("Failed to switch account", "%s",
                      get_last_error()->message);
        config_resume_hint_snapshot_clear(&result.hint_snapshot);
        return result;
    }

    result.status = EXIT_SUCCESS;
    result.save_kind = COMMAND_SAVE_ACTIVE;
    result.notice_kind = COMMAND_NOTICE_SWITCH;
    result.switch_prepared = true;
    if (ctx->current_account) {
        safe_strncpy(result.subject, ctx->current_account->name,
                     sizeof(result.subject));
    } else {
        safe_strncpy(result.subject, identifier, sizeof(result.subject));
    }
    return result;
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
        display_error("Configuration validation failed", "%s", get_last_error()->message);
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
        /* AR-06 F23: don't prompt-and-create the real config under --dry-run. */
        if (ctx->config.dry_run) {
            display_info("DRY RUN MODE - No actual changes will be made");
            printf("Would offer to create a default configuration at %s.\n",
                   ctx->config.config_path);
            display_success("DRY RUN complete - no changes were made");
            return EXIT_SUCCESS;
        }
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
                    display_error("Failed to create default configuration", "%s", get_last_error()->message);
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

/* Emit the parent-shell state synchronizer. It only restores/unsets a value
 * that still equals the last path gitswitch installed; a user or another tool
 * that replaces either variable keeps ownership. Values present before the
 * first managed assignment are saved and restored when that capability is
 * later switched off or reset. */
static void emit_posix_refresh(const char *sock_path, const char *gpg_home,
                               bool have_gpg_home) {
    printf("__gitswitch_refresh() {\n");
    printf("    __gitswitch_next_auth_sock='%s'\n", sock_path);
    printf("    if [ -S \"$__gitswitch_next_auth_sock\" ]; then\n");
    printf("        if [ \"${__gitswitch_managed_auth_sock+x}\" != x ]; then\n");
    printf("            unset __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("            if [ \"${SSH_AUTH_SOCK+x}\" = x ] && [ \"$SSH_AUTH_SOCK\" != \"$__gitswitch_next_auth_sock\" ]; then\n");
    printf("                __gitswitch_saved_auth_sock=$SSH_AUTH_SOCK\n");
    printf("                __gitswitch_saved_auth_sock_set=1\n");
    printf("            fi\n");
    printf("        elif [ \"${SSH_AUTH_SOCK+x}\" != x ]; then\n");
    printf("            unset __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("        elif [ \"$SSH_AUTH_SOCK\" != \"$__gitswitch_managed_auth_sock\" ]; then\n");
    printf("            __gitswitch_saved_auth_sock=$SSH_AUTH_SOCK\n");
    printf("            __gitswitch_saved_auth_sock_set=1\n");
    printf("        fi\n");
    printf("        SSH_AUTH_SOCK=$__gitswitch_next_auth_sock\n");
    printf("        export SSH_AUTH_SOCK\n");
    printf("        __gitswitch_managed_auth_sock=$__gitswitch_next_auth_sock\n");
    printf("    elif [ \"${__gitswitch_managed_auth_sock+x}\" = x ]; then\n");
    printf("        if [ \"${SSH_AUTH_SOCK+x}\" = x ] && [ \"$SSH_AUTH_SOCK\" = \"$__gitswitch_managed_auth_sock\" ]; then\n");
    printf("            if [ \"${__gitswitch_saved_auth_sock_set-0}\" = 1 ]; then\n");
    printf("                SSH_AUTH_SOCK=$__gitswitch_saved_auth_sock\n");
    printf("                export SSH_AUTH_SOCK\n");
    printf("            else\n");
    printf("                unset SSH_AUTH_SOCK\n");
    printf("            fi\n");
    printf("        fi\n");
    printf("        unset __gitswitch_managed_auth_sock __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("    elif [ \"${SSH_AUTH_SOCK+x}\" = x ] && [ \"$SSH_AUTH_SOCK\" = \"$__gitswitch_next_auth_sock\" ]; then\n");
    printf("        unset SSH_AUTH_SOCK\n");
    printf("    fi\n");
    printf("    unset __gitswitch_next_auth_sock\n");

    if (have_gpg_home) {
        printf("    __gitswitch_next_gnupghome='%s'\n", gpg_home);
        printf("    if [ -d \"$__gitswitch_next_gnupghome\" ]; then\n");
        printf("        if [ \"${__gitswitch_managed_gnupghome+x}\" != x ]; then\n");
        printf("            unset __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("            if [ \"${GNUPGHOME+x}\" = x ] && [ \"$GNUPGHOME\" != \"$__gitswitch_next_gnupghome\" ]; then\n");
        printf("                __gitswitch_saved_gnupghome=$GNUPGHOME\n");
        printf("                __gitswitch_saved_gnupghome_set=1\n");
        printf("            fi\n");
        printf("        elif [ \"${GNUPGHOME+x}\" != x ]; then\n");
        printf("            unset __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("        elif [ \"$GNUPGHOME\" != \"$__gitswitch_managed_gnupghome\" ]; then\n");
        printf("            __gitswitch_saved_gnupghome=$GNUPGHOME\n");
        printf("            __gitswitch_saved_gnupghome_set=1\n");
        printf("        fi\n");
        printf("        GNUPGHOME=$__gitswitch_next_gnupghome\n");
        printf("        export GNUPGHOME\n");
        printf("        __gitswitch_managed_gnupghome=$__gitswitch_next_gnupghome\n");
        printf("    elif [ \"${__gitswitch_managed_gnupghome+x}\" = x ]; then\n");
        printf("        if [ \"${GNUPGHOME+x}\" = x ] && [ \"$GNUPGHOME\" = \"$__gitswitch_managed_gnupghome\" ]; then\n");
        printf("            if [ \"${__gitswitch_saved_gnupghome_set-0}\" = 1 ]; then\n");
        printf("                GNUPGHOME=$__gitswitch_saved_gnupghome\n");
        printf("                export GNUPGHOME\n");
        printf("            else\n");
        printf("                unset GNUPGHOME\n");
        printf("            fi\n");
        printf("        fi\n");
        printf("        unset __gitswitch_managed_gnupghome __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("    elif [ \"${GNUPGHOME+x}\" = x ] && [ \"$GNUPGHOME\" = \"$__gitswitch_next_gnupghome\" ]; then\n");
        printf("        unset GNUPGHOME\n");
        printf("    fi\n");
        printf("    unset __gitswitch_next_gnupghome\n");
    }
    printf("    return 0\n");
    printf("}\n");
    printf("__gitswitch_command_updates_runtime() {\n");
    printf("    __gitswitch_runtime_command=\n");
    printf("    __gitswitch_after_dashdash=0\n");
    printf("    for __gitswitch_arg do\n");
    printf("        if [ \"$__gitswitch_after_dashdash\" = 1 ]; then\n");
    printf("            [ -n \"$__gitswitch_runtime_command\" ] || __gitswitch_runtime_command=$__gitswitch_arg\n");
    printf("        else\n");
    printf("            case $__gitswitch_arg in\n");
    printf("            --) __gitswitch_after_dashdash=1 ;;\n");
    printf("            --h|--he|--hel|--help|--vers*|--dr*) unset __gitswitch_runtime_command __gitswitch_after_dashdash __gitswitch_arg; return 1 ;;\n");
    printf("            --*) : ;;\n");
    printf("            -?*)\n");
    printf("                case $__gitswitch_arg in *n*|*h*|*v*) unset __gitswitch_runtime_command __gitswitch_after_dashdash __gitswitch_arg; return 1 ;; esac ;;\n");
    printf("            *) [ -n \"$__gitswitch_runtime_command\" ] || __gitswitch_runtime_command=$__gitswitch_arg ;;\n");
    printf("            esac\n");
    printf("        fi\n");
    printf("    done\n");
    printf("    case $__gitswitch_runtime_command in\n");
    printf("        switch|resume|reset|remove|rm|delete|edit) __gitswitch_runtime_result=0 ;;\n");
    printf("        ''|add|list|ls|status|doctor|health|config|init) __gitswitch_runtime_result=1 ;;\n");
    printf("        *) __gitswitch_runtime_result=0 ;;\n");
    printf("    esac\n");
    printf("    unset __gitswitch_runtime_command __gitswitch_after_dashdash __gitswitch_arg\n");
    printf("    if [ \"$__gitswitch_runtime_result\" = 0 ]; then\n");
    printf("        unset __gitswitch_runtime_result\n");
    printf("        return 0\n");
    printf("    fi\n");
    printf("    unset __gitswitch_runtime_result\n");
    printf("    return 1\n");
    printf("}\n");
}

static void emit_fish_refresh(const char *sock_path, const char *gpg_home,
                              bool have_gpg_home) {
    printf("function __gitswitch_refresh\n");
    printf("    set -l __gitswitch_next_auth_sock '%s'\n", sock_path);
    printf("    if test -S \"$__gitswitch_next_auth_sock\"\n");
    printf("        if not set -q __gitswitch_managed_auth_sock\n");
    printf("            set -eg __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("            if set -q SSH_AUTH_SOCK; and test \"$SSH_AUTH_SOCK\" != \"$__gitswitch_next_auth_sock\"\n");
    printf("                set -g __gitswitch_saved_auth_sock $SSH_AUTH_SOCK\n");
    printf("                set -g __gitswitch_saved_auth_sock_set 1\n");
    printf("            end\n");
    printf("        else if not set -q SSH_AUTH_SOCK\n");
    printf("            set -eg __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("        else if test \"$SSH_AUTH_SOCK\" != \"$__gitswitch_managed_auth_sock\"\n");
    printf("            set -g __gitswitch_saved_auth_sock $SSH_AUTH_SOCK\n");
    printf("            set -g __gitswitch_saved_auth_sock_set 1\n");
    printf("        end\n");
    printf("        set -gx SSH_AUTH_SOCK $__gitswitch_next_auth_sock\n");
    printf("        set -g __gitswitch_managed_auth_sock $__gitswitch_next_auth_sock\n");
    printf("    else if set -q __gitswitch_managed_auth_sock\n");
    printf("        if set -q SSH_AUTH_SOCK; and test \"$SSH_AUTH_SOCK\" = \"$__gitswitch_managed_auth_sock\"\n");
    printf("            if set -q __gitswitch_saved_auth_sock_set; and test \"$__gitswitch_saved_auth_sock_set\" = 1\n");
    printf("                set -gx SSH_AUTH_SOCK $__gitswitch_saved_auth_sock\n");
    printf("            else\n");
    printf("                set -eg SSH_AUTH_SOCK\n");
    printf("            end\n");
    printf("        end\n");
    printf("        set -eg __gitswitch_managed_auth_sock __gitswitch_saved_auth_sock __gitswitch_saved_auth_sock_set\n");
    printf("    else if set -q SSH_AUTH_SOCK; and test \"$SSH_AUTH_SOCK\" = \"$__gitswitch_next_auth_sock\"\n");
    printf("        set -eg SSH_AUTH_SOCK\n");
    printf("    end\n");

    if (have_gpg_home) {
        printf("    set -l __gitswitch_next_gnupghome '%s'\n", gpg_home);
        printf("    if test -d \"$__gitswitch_next_gnupghome\"\n");
        printf("        if not set -q __gitswitch_managed_gnupghome\n");
        printf("            set -eg __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("            if set -q GNUPGHOME; and test \"$GNUPGHOME\" != \"$__gitswitch_next_gnupghome\"\n");
        printf("                set -g __gitswitch_saved_gnupghome $GNUPGHOME\n");
        printf("                set -g __gitswitch_saved_gnupghome_set 1\n");
        printf("            end\n");
        printf("        else if not set -q GNUPGHOME\n");
        printf("            set -eg __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("        else if test \"$GNUPGHOME\" != \"$__gitswitch_managed_gnupghome\"\n");
        printf("            set -g __gitswitch_saved_gnupghome $GNUPGHOME\n");
        printf("            set -g __gitswitch_saved_gnupghome_set 1\n");
        printf("        end\n");
        printf("        set -gx GNUPGHOME $__gitswitch_next_gnupghome\n");
        printf("        set -g __gitswitch_managed_gnupghome $__gitswitch_next_gnupghome\n");
        printf("    else if set -q __gitswitch_managed_gnupghome\n");
        printf("        if set -q GNUPGHOME; and test \"$GNUPGHOME\" = \"$__gitswitch_managed_gnupghome\"\n");
        printf("            if set -q __gitswitch_saved_gnupghome_set; and test \"$__gitswitch_saved_gnupghome_set\" = 1\n");
        printf("                set -gx GNUPGHOME $__gitswitch_saved_gnupghome\n");
        printf("            else\n");
        printf("                set -eg GNUPGHOME\n");
        printf("            end\n");
        printf("        end\n");
        printf("        set -eg __gitswitch_managed_gnupghome __gitswitch_saved_gnupghome __gitswitch_saved_gnupghome_set\n");
        printf("    else if set -q GNUPGHOME; and test \"$GNUPGHOME\" = \"$__gitswitch_next_gnupghome\"\n");
        printf("        set -eg GNUPGHOME\n");
        printf("    end\n");
    }
    printf("    return 0\n");
    printf("end\n");
    printf("function __gitswitch_command_updates_runtime\n");
    printf("    set -l __gitswitch_runtime_command ''\n");
    printf("    set -l __gitswitch_after_dashdash 0\n");
    printf("    for __gitswitch_arg in $argv\n");
    printf("        if test $__gitswitch_after_dashdash -eq 1\n");
    printf("            if test -z \"$__gitswitch_runtime_command\"\n");
    printf("                set __gitswitch_runtime_command $__gitswitch_arg\n");
    printf("            end\n");
    printf("        else\n");
    printf("            switch $__gitswitch_arg\n");
    printf("                case --\n");
    printf("                    set __gitswitch_after_dashdash 1\n");
    printf("                case --h --he --hel --help '--vers*' '--dr*'\n");
    printf("                    return 1\n");
    printf("                case '--*'\n");
    printf("                case '-*'\n");
    printf("                    if string match -q -- '*n*' $__gitswitch_arg; or string match -q -- '*h*' $__gitswitch_arg; or string match -q -- '*v*' $__gitswitch_arg\n");
    printf("                        return 1\n");
    printf("                    end\n");
    printf("                case '*'\n");
    printf("                    if test -z \"$__gitswitch_runtime_command\"\n");
    printf("                        set __gitswitch_runtime_command $__gitswitch_arg\n");
    printf("                    end\n");
    printf("            end\n");
    printf("        end\n");
    printf("    end\n");
    printf("    switch \"$__gitswitch_runtime_command\"\n");
    printf("        case switch resume reset remove rm delete edit\n");
    printf("            return 0\n");
    printf("        case '' add list ls status doctor health config init\n");
    printf("            return 1\n");
    printf("        case '*'\n");
    printf("            return 0\n");
    printf("    end\n");
    printf("end\n");
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

    if (!shell || !*shell) {
        fprintf(stderr,
                "gitswitch: could not detect shell; pass one explicitly:\n"
                "  gitswitch init fish | source\n"
                "  eval \"$(gitswitch init bash)\"\n"
                "  eval \"$(gitswitch init zsh)\"\n");
        return EXIT_FAILURE;
    }
    if (!shell_is_supported(shell)) {
        fprintf(stderr, "gitswitch: unsupported shell '%s' (supported: ",
                shell);
        print_supported_shells(stderr, ", ");
        fputs(")\n", stderr);
        return EXIT_FAILURE;
    }

    char sock_path[MAX_PATH_LEN];
    if (ssh_manager_get_auth_sock_path(sock_path, sizeof(sock_path)) != 0) {
        fprintf(stderr, "gitswitch: failed to compute SSH_AUTH_SOCK path: %s\n",
                get_last_error()->message);
        return EXIT_FAILURE;
    }

    /* GPG home is best-effort: if it can't be computed we still emit the SSH
     * wiring rather than failing the whole init. The _quiet variant is
     * mandatory here: the plain one prints a not-memory-backed [WARN] to STDOUT
     * on any host with XDG_RUNTIME_DIR unset and a disk-backed /tmp (stock
     * macOS), and this stdout is eval'd by the shell — the warning would become
     * `bash: [WARN]: command not found` at every prompt (AR-06 F08). */
    char gpg_home[MAX_PATH_LEN];
    bool have_gpg_home = (gpg_manager_get_home_path_quiet(gpg_home, sizeof(gpg_home)) == 0);

    /* The paths are emitted inside single-quoted shell assignments below; a
     * stray single quote would break out of the quoting, so refuse it. */
    if (strchr(sock_path, '\'')) {
        fprintf(stderr, "gitswitch: refusing to emit SSH_AUTH_SOCK path containing a quote\n");
        return EXIT_FAILURE;
    }
    if (have_gpg_home && strchr(gpg_home, '\'')) {
        have_gpg_home = false;
    }

    if (strcmp(shell, "fish") == 0) {
        /* AR-06 F63: unlike POSIX single quotes (fully literal), fish single
         * quotes still interpret \\ and \' — a backslash in a single-quoted
         * path could escape the closing quote or alter the path. The up-front
         * check only refused a literal quote. These are gitswitch-controlled
         * runtime paths, so a backslash is pathological: refuse it for the
         * mandatory SSH socket, and drop the optional GPG wiring (mirroring how
         * a quote is handled) rather than emit a subtly wrong path. */
        bool fish_gpg = have_gpg_home && strchr(gpg_home, '\\') == NULL;
        if (strchr(sock_path, '\\')) {
            fprintf(stderr, "gitswitch: refusing to emit SSH_AUTH_SOCK path "
                            "containing a backslash for fish\n");
            return EXIT_FAILURE;
        }
        have_gpg_home = fish_gpg;
        printf("# gitswitch shell integration (fish)\n");
        printf("set -l __gitswitch_auth_sock '%s'\n", sock_path);
        printf("function __gitswitch_ssh_needs_resume\n");
        printf("    env SSH_AUTH_SOCK='%s' ssh-add -l >/dev/null 2>&1\n",
               sock_path);
        printf("    if test $status -ne 0\n");
        printf("        return 0\n");
        printf("    end\n");
        printf("    command gitswitch --resume-check >/dev/null 2>&1\n");
        printf("    test $status -ne 0\n");
        printf("end\n");
        /* First interactive shell after a boot: a nonzero `ssh-add -l` result
         * (including status 1 for an empty agent) resumes directly. Status 0 is
         * followed by the read-only exact-runtime check, which rejects the
         * wrong key or any extra identity. Interactive-gated so pinentry has a
         * user. The "restoring your
         * account" notice is printed by `resume` itself (on stderr, past the
         * stdout suppression) only when it actually has an account to restore —
         * echoing it here would nag on every shell when there is nothing saved,
         * since a no-op resume never creates the socket the probe looks for. */
        printf("if status is-interactive\n");
        printf("    set -l __gitswitch_needs (command gitswitch --resume-hint-probe 2>/dev/null)\n");
        printf("    set -l __gitswitch_probe_status $status\n");
        printf("    if test $__gitswitch_probe_status -eq 0\n");
        printf("        switch \"$__gitswitch_needs\"\n");
        printf("            case none\n");
        printf("            case ssh\n");
        printf("                if __gitswitch_ssh_needs_resume\n");
        printf("                    command gitswitch resume >/dev/null\n");
        printf("                end\n");
        if (have_gpg_home) {
            printf("            case gpg\n");
            printf("                if not test -d '%s'; or not command gitswitch --resume-check >/dev/null 2>&1\n",
                   gpg_home);
            printf("                    command gitswitch resume >/dev/null\n");
            printf("                end\n");
        } else {
            printf("            case gpg\n");
            printf("                command gitswitch resume >/dev/null\n");
        }
        printf("            case 'ssh gpg'\n");
        printf("                set -l __gitswitch_resume 0\n");
        printf("                if __gitswitch_ssh_needs_resume\n");
        printf("                    set __gitswitch_resume 1\n");
        printf("                end\n");
        if (have_gpg_home) {
            printf("                if not test -d '%s'\n", gpg_home);
            printf("                    set __gitswitch_resume 1\n");
            printf("                end\n");
        } else {
            printf("                set __gitswitch_resume 1\n");
        }
        printf("                if test $__gitswitch_resume -eq 1\n");
        printf("                    command gitswitch resume >/dev/null\n");
        printf("                end\n");
        printf("                set -e __gitswitch_resume\n");
        printf("        end\n");
        printf("    end\n");
        printf("    set -e __gitswitch_probe_status\n");
        printf("    set -e __gitswitch_needs\n");
        printf("end\n");
        emit_fish_refresh(sock_path, gpg_home, have_gpg_home);
        printf("__gitswitch_refresh\n");
        printf("function gitswitch\n");
        printf("    command gitswitch $argv\n");
        printf("    set -l __gitswitch_status $status\n");
        printf("    if test $__gitswitch_status -eq 0; and __gitswitch_command_updates_runtime $argv\n");
        printf("        __gitswitch_refresh\n");
        printf("    end\n");
        printf("    return $__gitswitch_status\n");
        printf("end\n");
        printf("set -e __gitswitch_auth_sock\n");
        return finish_snippet_emit();
    }

    {
        printf("# gitswitch shell integration (%s)\n", shell);
        printf("__gitswitch_auth_sock='%s'\n", sock_path);
        printf("__gitswitch_ssh_needs_resume() {\n");
        printf("    SSH_AUTH_SOCK='%s' ssh-add -l >/dev/null 2>&1\n",
               sock_path);
        printf("    [ $? -ne 0 ] && return 0\n");
        printf("    command gitswitch --resume-check >/dev/null 2>&1\n");
        printf("    [ $? -ne 0 ]\n");
        printf("}\n");
        /* First interactive shell after a boot: nonzero/empty agent results
         * resume directly, while status 0 is verified against the saved
         * account's exact single fingerprint by --resume-check. A stale socket
         * or a reachable wrong/extra-key agent therefore cannot suppress the
         * restore. Interactive-gated so pinentry has a user. The notice comes
         * from `resume` itself (stderr) only when there is an account to
         * restore — see the fish branch above for why. */
        printf("case $- in *i*)\n");
        printf("    if __gitswitch_needs=$(command gitswitch --resume-hint-probe 2>/dev/null); then\n");
        printf("        case \"$__gitswitch_needs\" in\n");
        printf("        none) : ;;\n");
        printf("        ssh)\n");
        printf("            __gitswitch_ssh_needs_resume && command gitswitch resume >/dev/null ;;\n");
        if (have_gpg_home) {
            printf("        gpg)\n");
            printf("            [ -d '%s' ] && command gitswitch --resume-check >/dev/null 2>&1 || command gitswitch resume >/dev/null ;;\n",
                   gpg_home);
        } else {
            printf("        gpg) command gitswitch resume >/dev/null ;;\n");
        }
        printf("        'ssh gpg')\n");
        printf("            __gitswitch_resume=0\n");
        printf("            __gitswitch_ssh_needs_resume && __gitswitch_resume=1\n");
        if (have_gpg_home) {
            printf("            [ -d '%s' ] || __gitswitch_resume=1\n", gpg_home);
        } else {
            printf("            __gitswitch_resume=1\n");
        }
        printf("            [ \"$__gitswitch_resume\" -eq 0 ] || command gitswitch resume >/dev/null\n");
        printf("            unset __gitswitch_resume ;;\n");
        printf("        esac\n");
        printf("    fi\n");
        printf("    unset __gitswitch_needs ;;\n");
        printf("esac\n");
        emit_posix_refresh(sock_path, gpg_home, have_gpg_home);
        printf("__gitswitch_refresh\n");
        printf("gitswitch() {\n");
        printf("    command gitswitch \"$@\" || return $?\n");
        printf("    __gitswitch_command_updates_runtime \"$@\" || return 0\n");
        printf("    __gitswitch_refresh\n");
        printf("}\n");
        printf("unset __gitswitch_auth_sock\n");
        return finish_snippet_emit();
    }

}

/* True when the saved account's per-boot runtime state is already live, so
 * `resume` and the shell integration's hidden readiness probe can no-op
 * silently. Both SSH and GPG checks validate the exact saved account; a cheap
 * shell path/socket test is only a negative fast path, never positive proof.
 * - SSH accounts: live only when current.sock names this account and its agent
 *   contains exactly the configured key, with no additional identities.
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
        bool live = false;

        /* Reachability and `ssh-add -l` status 0 are insufficient: the
         * stable agent must belong to this account and contain exactly its
         * configured key. Empty, wrong-key, and extra-key agents all force a
         * bounded resume. The manager keeps the runtime lock across the link,
         * socket, and fingerprint inspection. */
        if (ssh_manager_current_is_live_for_account(acct, &live) != 0 ||
            !live) {
            return false;
        }
    }

    if (wants_gpg) {
        bool live = false;

        /* The manager validates and locks the private base, compares the full
         * managed target (not just its basename), and checks that exact home
         * while locked. Any uncertainty safely forces a real resume. */
        return gpg_manager_current_is_live_for_account(acct->name, &live) == 0 &&
               live;
    }

    return true;
}

/* Non-switching readiness predicate consumed by generated shell integration.
 * Manager inspection may acquire internal runtime locks, but this path never
 * changes config, identity, or agent/key routing. A successful result means
 * every boot-volatile capability requested by the saved account is exact and
 * live; nonzero tells the shell to invoke ordinary `resume` once. Missing
 * accounts and identity-only accounts need no restore. */
static int handle_resume_check_command(gitswitch_ctx_t *ctx) {
    account_t *acct;

    if (!ctx) return EXIT_FAILURE;
    if (ctx->config.active_account[0] == '\0') return EXIT_SUCCESS;

    acct = config_find_account_exact(ctx, ctx->config.active_account);
    if (!acct) {
        clear_error();
        return EXIT_SUCCESS;
    }
    return resume_already_applied(acct) ? EXIT_SUCCESS : EXIT_FAILURE;
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

    /* Exact-name resolution (AR-06 F22): the persisted active_account is a
     * literal name; the id-first fuzzy matcher could resume a different account
     * whose id equals a legacy all-digit name. */
    acct = config_find_account_exact(ctx, ctx->config.active_account);
    if (!acct) {
        log_debug("Saved account no longer exists, skipping resume: %s",
                  ctx->config.active_account);
        return EXIT_SUCCESS;
    }

    /* Preview must stop before the liveness helpers: the GPG check pins and
     * locks runtime metadata and may create/repair its private lock paths.
     * Describe the possible restore without probing or touching them. */
    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
        printf("Would check boot-volatile SSH/GPG state for '%s' and restore "
               "it only if needed.\n", acct->name);
        display_success("DRY RUN complete - no changes were made");
        return EXIT_SUCCESS;
    }

    /* Already live this boot: exit silently before the notice below. The shell
     * integration invokes resume only after its exact readiness probe fails;
     * keep this same check here to close the probe/action race and make manual
     * redundant resume calls quiet. */
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
static command_result_t handle_reset_command(gitswitch_ctx_t *ctx,
                                             const char *account) {
    command_result_t result = command_result(EXIT_FAILURE);
    account_t *target_account = NULL;
    account_t *active_account = NULL;
    char resp[16];
    const char *target = NULL;
    char ssh_error[sizeof(g_last_error.message)] = "";
    char gpg_error[sizeof(g_last_error.message)] = "";
    int ssh_rc;
    int gpg_rc;
    int runtime_lock_fd;

    if (!ctx) return result;

    /* Resolve the argument to a real account first so a typo can't report a
     * false success while the intended account's on-disk secret-key copy is
     * left in place. AR-06 F50: exact id/name/email only — reset destroys
     * secret-key material, so it must never fire on a mere substring match. */
    if (account) {
        target_account = config_find_account_destructive(ctx, account);
        if (!target_account) {
            display_error("Account not found", "%s", get_last_error()->message);
            return result;
        }
        target = target_account->name;
    }
    if (ctx->config.active_account[0] != '\0') {
        active_account = config_find_account_exact(
            ctx, ctx->config.active_account);
    }

    /* Reset deletes secret-key material, so it is exactly the command a
     * cautious user previews with --dry-run first — and neither
     * ssh_manager_reset nor gpg_manager_reset checks dry_run themselves, so
     * this is the single gate (AR-05 H1). Stop before the confirmation
     * prompt, the runtime lock, and both managers. active_account is left
     * untouched on purpose: nothing was destroyed, so the saved resume
     * pointer must keep naming the still-live state. (Clearing it here while
     * main()'s !dry_run save gate skips the persist is how the pre-fix code
     * re-armed auto-resume of torn-down state.) */
    if (ctx->config.dry_run) {
        display_info("DRY RUN MODE - No actual changes will be made");
        if (target) {
            printf("Would kill the SSH/GPG agents and delete the isolated GPG home for\n"
                   "'%s', removing its on-disk secret-key copy.\n", target);
        } else {
            printf("Would kill ALL gitswitch SSH/GPG agents and delete ALL isolated GPG\n"
                   "homes, removing every on-disk secret-key copy.\n");
        }
        if ((!target || (active_account &&
                         active_account == target_account)) &&
            ctx->config.active_account[0] != '\0') {
            printf("Would clear the saved active account '%s' and mark resume state\n"
                   "inactive, so login shells stop auto-resuming it.\n",
                   ctx->config.active_account);
        }
        display_success("DRY RUN complete - no changes were made");
        result.status = EXIT_SUCCESS;
        return result;
    }

    if (target) {
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
            result.status = EXIT_SUCCESS;
            return result;
        }
        resp[strcspn(resp, "\n")] = '\0';
        if (strcmp(resp, "yes") != 0) {
            printf("Reset cancelled.\n");
            result.status = EXIT_SUCCESS;
            return result;
        }
    }

    /* From the instant the destructive operation is confirmed until the
     * active-state artifact is durably committed (or retry metadata is
     * retained on failure), every guarded signal is deferred.  Repeats stay
     * deferred as rollback-class work so they cannot strand a half-reset
     * identity. Main owns the end of this window and truthful re-raise after
     * config unlock plus secure context cleanup. */
    signals_rollback_begin();
    if (signals_guard_begin() != 0) {
        signals_rollback_end();
        display_error("Cannot guard reset transaction", "%s",
                      get_last_error()->message);
        return result;
    }
    result.reset_guarded = true;

    runtime_lock_fd = runtime_state_lock_acquire();
    if (runtime_lock_fd < 0) {
        display_error("Cannot lock shared runtime state", "%s",
                      get_last_error()->message);
        return result;
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
    ssh_rc = ssh_manager_reset(target);
    if (ssh_rc != 0) {
        snprintf(ssh_error, sizeof(ssh_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown SSH teardown error");
    }
    reset_test_checkpoint(RESET_TEST_AFTER_SSH);

    /* Always attempt GPG teardown even after an SSH error: independent
     * resources should be cleaned as far as safely possible, while the saved
     * account remains the retry handle until both managers succeed. */
    gpg_rc = gpg_manager_reset(target);
    if (gpg_rc != 0) {
        snprintf(gpg_error, sizeof(gpg_error), "%s",
                 get_last_error()->message[0] ? get_last_error()->message
                                              : "unknown GPG teardown error");
    }
    reset_test_checkpoint(RESET_TEST_AFTER_GPG);
    runtime_state_lock_release(runtime_lock_fd);

    if (ssh_rc != 0 || gpg_rc != 0) {
        if (ssh_rc != 0) {
            fprintf(stderr, "gitswitch: SSH reset failed: %s\n", ssh_error);
        }
        if (gpg_rc != 0) {
            fprintf(stderr, "gitswitch: GPG reset failed: %s\n", gpg_error);
        }
        fprintf(stderr,
                "gitswitch: reset failed; retry metadata was preserved\n");
        set_error(ERR_SYSTEM_CALL, "SSH/GPG reset did not complete");
        return result;
    }

    /* When the reset covered the saved active account (or everything), clear
     * the persisted active_account: main()'s settings-only save then records
     * the clear with an explicit inactive .resume-hint tombstone (AR-03 T4).
     * Leaving active state in place made every subsequent login shell probe and
     * auto-resume the account the user just tore down — silently re-spawning
     * the agents and re-importing the GPG secret key that this command exists
     * to delete. A
     * targeted reset of a NON-active account changes neither. */
    if (!target || (active_account && active_account == target_account)) {
        ctx->config.active_account[0] = '\0';
        result.save_kind = COMMAND_SAVE_ACTIVE;
        reset_test_checkpoint(RESET_TEST_AFTER_ACTIVE_CLEAR);
    }

    if (target) {
        result.notice_kind = COMMAND_NOTICE_RESET_ONE;
        safe_strncpy(result.subject, target, sizeof(result.subject));
    } else {
        result.notice_kind = COMMAND_NOTICE_RESET_ALL;
    }
    result.status = EXIT_SUCCESS;
    return result;
}
