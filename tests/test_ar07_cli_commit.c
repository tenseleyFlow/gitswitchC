/* AR-07 T5 CLI contract and dry-run purity regressions.
 *
 * main.c is excluded from unit-test links because it owns main(), so these
 * tests execute the built CLI in isolated HOME/XDG_RUNTIME_DIR trees. */
#include "test.h"
#include "gitswitch.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_bin[4096];

typedef enum {
    POSIXLY_INHERIT = 0,
    POSIXLY_ABSENT,
    POSIXLY_EMPTY,
    POSIXLY_SET
} posixly_mode_t;

typedef enum {
    CLI_STDOUT_CAPTURE = 0,
    CLI_STDOUT_CAPTURE_ONLY,
    CLI_STDOUT_READ_ONLY,
    CLI_STDOUT_LIMITED_FILE
} cli_stdout_mode_t;

#define CLI_LATE_FLUSH_LIMIT 8

static int resolve_binary(void) {
    const char *bin = getenv("GITSWITCH_BIN");

    if (!bin || !*bin) {
        bin = "build/bin/gitswitch";
    }
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr,
                "test_ar07_cli_commit: executable not found at '%s'\n", bin);
        return -1;
    }
    return 0;
}

static int make_private_dir(char *path, size_t size, const char *stem) {
    if ((size_t)snprintf(path, size, "/tmp/%s.XXXXXX", stem) >= size) {
        return -1;
    }
    return ts_mkdtemp(path) ? 0 : -1;
}

static int write_text_mode(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t n = write(fd, text + total, length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return -1;
        }
    }
    if (close(fd) != 0) return -1;
    return chmod(path, mode);
}

static int write_account_config(const char *home, bool include_second,
                                char *config_dir, size_t dir_size) {
    char path[4096];
    static const char one_account[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"old\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"old\"\n"
        "email = \"old@example.com\"\n"
        "preferred_scope = \"global\"\n";
    static const char two_accounts[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"old\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"old\"\n"
        "email = \"old@example.com\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"new\"\n"
        "email = \"new@example.com\"\n"
        "preferred_scope = \"global\"\n";

    if ((size_t)snprintf(path, sizeof(path), "%s/.config", home) >=
        sizeof(path) || mkdir(path, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(config_dir, dir_size, "%s/.config/gitswitch",
                         home) >= dir_size || mkdir(config_dir, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(path, sizeof(path), "%s/accounts.toml", config_dir) >=
        sizeof(path) ||
        write_text_mode(path, include_second ? two_accounts : one_account,
                        0600) != 0) {
        return -1;
    }
    if ((size_t)snprintf(path, sizeof(path), "%s/.resume-hint", config_dir) >=
        sizeof(path) || write_text_mode(path, "none\n", 0600) != 0) {
        return -1;
    }
    if ((size_t)snprintf(path, sizeof(path), "%s/.config.lock", config_dir) >=
        sizeof(path) || write_text_mode(path, "", 0600) != 0) {
        return -1;
    }
    if ((size_t)snprintf(path, sizeof(path), "%s/.gitconfig", home) >=
        sizeof(path) ||
        write_text_mode(path,
                        "[user]\n\tname = old\n\temail = old@example.com\n"
                        "[commit]\n\tgpgsign = false\n",
                        0600) != 0) {
        return -1;
    }
    return 0;
}

static bool directory_empty(const char *path) {
    DIR *dir = opendir(path);
    struct dirent *entry;

    if (!dir) {
        return false;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            closedir(dir);
            return false;
        }
    }
    closedir(dir);
    return true;
}

static const char *slurp(const char *path, char *buf, size_t size) {
    FILE *file;
    size_t used;

    if (!buf || size == 0) {
        return "";
    }
    buf[0] = '\0';
    file = fopen(path, "r");
    if (!file) {
        return buf;
    }
    used = fread(buf, 1, size - 1, file);
    buf[used] = '\0';
    fclose(file);
    return buf;
}

/* argv must include argv[0] and its terminating NULL. execv's historical API
 * is mutable even though it does not modify argument strings. */
static int run_cli_input_posixly(const char *home, const char *runtime,
                                 const char *input_path,
                                 const char *const argv[],
                                 posixly_mode_t posixly_mode,
                                 cli_stdout_mode_t stdout_mode,
                                 char *output_path, size_t output_size) {
    char template_path[] = "/tmp/gitswitch-ar07-cli-output.XXXXXX";
    int output_fd;
    int status;
    pid_t child;
    pid_t waited;

    output_fd = mkstemp(template_path);
    if (output_fd < 0) {
        return -1;
    }
    if ((size_t)snprintf(output_path, output_size, "%s", template_path) >=
        output_size) {
        close(output_fd);
        unlink(template_path);
        return -1;
    }

    child = fork();
    if (child < 0) {
        close(output_fd);
        unlink(template_path);
        return -1;
    }
    if (child == 0) {
        char git_config[4096];
        int input_fd = open(input_path ? input_path : "/dev/null", O_RDONLY);
        int stdout_fd = output_fd;
        int stderr_fd = output_fd;
        int posixly_rc = 0;
        int stdout_fault_rc = 0;

        if (stdout_mode != CLI_STDOUT_CAPTURE) {
            stderr_fd = open("/dev/null", O_WRONLY);
            if (stderr_fd < 0) stdout_fault_rc = -1;
        }
        if (stdout_mode == CLI_STDOUT_READ_ONLY) {
            stdout_fd = open("/dev/null", O_RDONLY);
            if (stdout_fd < 0) stdout_fault_rc = -1;
        } else if (stdout_mode == CLI_STDOUT_LIMITED_FILE) {
            struct sigaction ignore_xfsz;
            struct rlimit limit;

            memset(&ignore_xfsz, 0, sizeof(ignore_xfsz));
            ignore_xfsz.sa_handler = SIG_IGN;
            if (sigemptyset(&ignore_xfsz.sa_mask) != 0 ||
                sigaction(SIGXFSZ, &ignore_xfsz, NULL) != 0) {
                stdout_fault_rc = -1;
            }
            limit.rlim_cur = CLI_LATE_FLUSH_LIMIT;
            limit.rlim_max = CLI_LATE_FLUSH_LIMIT;
            if (setrlimit(RLIMIT_FSIZE, &limit) != 0) {
                stdout_fault_rc = -1;
            }
        }

        if (posixly_mode == POSIXLY_ABSENT) {
            posixly_rc = unsetenv("POSIXLY_CORRECT");
        } else if (posixly_mode == POSIXLY_EMPTY) {
            posixly_rc = setenv("POSIXLY_CORRECT", "", 1);
        } else if (posixly_mode == POSIXLY_SET) {
            posixly_rc = setenv("POSIXLY_CORRECT", "1", 1);
        }

        if ((size_t)snprintf(git_config, sizeof(git_config), "%s/.gitconfig",
                             home) >= sizeof(git_config)) {
            _exit(125);
        }

        if (input_fd < 0 || stdout_fd < 0 || stderr_fd < 0 ||
            dup2(input_fd, STDIN_FILENO) < 0 ||
            dup2(stdout_fd, STDOUT_FILENO) < 0 ||
            dup2(stderr_fd, STDERR_FILENO) < 0 ||
            chdir(home) != 0 ||
            setenv("HOME", home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", runtime, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", git_config, 1) != 0 ||
            posixly_rc != 0 || stdout_fault_rc != 0) {
            _exit(125);
        }
        if (input_fd > STDERR_FILENO) {
            close(input_fd);
        }
        if (stdout_fd != output_fd && stdout_fd > STDERR_FILENO) {
            close(stdout_fd);
        }
        if (stderr_fd != output_fd && stderr_fd != stdout_fd &&
            stderr_fd > STDERR_FILENO) {
            close(stderr_fd);
        }
        close(output_fd);
        execv(g_bin, (char *const *)argv);
        _exit(126);
    }

    close(output_fd);
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        return -1;
    }
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    }
    return WEXITSTATUS(status);
}

static int run_cli_input(const char *home, const char *runtime,
                         const char *input_path,
                         const char *const argv[],
                         char *output_path, size_t output_size) {
    return run_cli_input_posixly(home, runtime, input_path, argv,
                                 POSIXLY_INHERIT, CLI_STDOUT_CAPTURE,
                                 output_path, output_size);
}

static int run_cli(const char *home, const char *runtime,
                   const char *const argv[],
                   char *output_path, size_t output_size) {
    return run_cli_input(home, runtime, NULL, argv, output_path, output_size);
}

static int run_cli_stdout_mode(const char *home, const char *runtime,
                               const char *const argv[],
                               cli_stdout_mode_t stdout_mode,
                               char *output_path, size_t output_size) {
    return run_cli_input_posixly(home, runtime, NULL, argv,
                                 POSIXLY_INHERIT, stdout_mode,
                                 output_path, output_size);
}

typedef struct {
    const char *label;
    const char *argv[8];
} cli_case_t;

TEST(option_order_is_independent_of_posixly_correct) {
    struct {
        const char *label;
        posixly_mode_t mode;
    } environments[] = {
        {"absent", POSIXLY_ABSENT},
        {"empty", POSIXLY_EMPTY},
        {"set", POSIXLY_SET},
    };
    struct {
        const char *label;
        const char *argv[8];
        bool valid;
    } cases[] = {
        {"documented names and dry-run options after command",
         {"gitswitch", "list", "--names", "--dry-run", NULL}, true},
        {"long option after command",
         {"gitswitch", "list", "--help", NULL}, true},
        {"short cluster after command operand",
         {"gitswitch", "init", "bash", "-ng", NULL}, true},
        {"long option after command operand",
         {"gitswitch", "init", "bash", "--dry-run", NULL}, true},
        {"double dash preserves option-looking operand",
         {"gitswitch", "init", "bash", "--", "--dry-run", NULL}, false},
        {"lone dash remains an operand",
         {"gitswitch", "init", "bash", "-", "--dry-run", NULL}, false},
        {"invalid extra operand control",
         {"gitswitch", "init", "bash", "extra", "--dry-run", NULL}, false},
    };

    for (size_t e = 0; e < sizeof(environments) / sizeof(environments[0]); e++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char home[128], runtime[128], output_path[128], output[8192];
            int rc;

            CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                          "gitswitch-ar09-home"), 0);
            CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                          "gitswitch-ar09-run"), 0);
            rc = run_cli_input_posixly(home, runtime, NULL, cases[i].argv,
                                       environments[e].mode,
                                       CLI_STDOUT_CAPTURE, output_path,
                                       sizeof(output_path));
            slurp(output_path, output, sizeof(output));
            if (cases[i].valid) {
                if (rc != 0 || strstr(output, "invalid number of operands")) {
                    fprintf(stderr, "  %s / %s returned %d:\n%s\n",
                            environments[e].label, cases[i].label, rc, output);
                }
                CHECK_EQ_INT(rc, 0);
                CHECK(strstr(output, "invalid number of operands") == NULL);
            } else {
                if (!(rc > 0 && rc < 126)) {
                    fprintf(stderr, "  %s / %s returned %d:\n%s\n",
                            environments[e].label, cases[i].label, rc, output);
                }
                CHECK(rc > 0 && rc < 126);
                CHECK(strstr(output,
                             "invalid number of operands for 'init'") != NULL);
                CHECK(strstr(output, "Usage: gitswitch init [shell]") != NULL);
            }
            CHECK(directory_empty(home));
            CHECK(directory_empty(runtime));
            unlink(output_path);
        }
    }
}

TEST(help_names_every_yes_confirmation_bypass) {
    static const char expected[] =
        "  --yes, -y            Assume 'yes' to confirmation prompts "
        "(add/edit/remove/reset)\n";
    const char *argv[] = {"gitswitch", "--help", NULL};
    char home[128], runtime[128], output_path[128], output[8192];
    int rc;

    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar09-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar09-run"), 0);
    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    CHECK_EQ_INT(rc, 0);
    slurp(output_path, output, sizeof(output));
    CHECK(strstr(output, expected) != NULL);
    CHECK(directory_empty(home));
    CHECK(directory_empty(runtime));
    unlink(output_path);
}

TEST(config_command_reports_exact_owner_only_mode) {
    static const struct {
        mode_t mode;
        const char *label;
    } cases[] = {
        {0400, "0400"},
        {0500, "0500"},
        {0600, "0600"},
        {0700, "0700"},
    };
    const char *argv[] = {"gitswitch", "--no-color", "config", NULL};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], config_dir[4096], config_path[4096];
        char output_path[128], output[8192], expected[8192];
        const char *report;
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar09-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar09-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);
        CHECK((size_t)snprintf(config_path, sizeof(config_path),
                               "%s/accounts.toml", config_dir) <
              sizeof(config_path));
        CHECK_EQ_INT(chmod(config_path, cases[i].mode), 0);

        rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
        slurp(output_path, output, sizeof(output));
        report = strstr(output, "\xF0\x9F\x93\x81 Configuration file:");
        CHECK((size_t)snprintf(
                  expected, sizeof(expected),
                  "\xF0\x9F\x93\x81 Configuration file: %s\n"
                  "Accounts: 1 configured\n"
                  "Default scope: global\n"
                  "[OK] Configuration file permissions are secure (%s)\n",
                  config_path, cases[i].label) < sizeof(expected));
        if (rc != 0 || !report || strcmp(report, expected) != 0) {
            fprintf(stderr, "  owner-only mode %s returned %d:\n%s\n",
                    cases[i].label, rc, output);
        }
        CHECK_EQ_INT(rc, 0);
        CHECK_STR_EQ(report, expected);
        unlink(output_path);
    }
}

TEST(informational_output_bytes_are_stable) {
    static const char expected_help[] =
        "Usage: gitswitch [OPTIONS] [COMMAND] [ARGS]\n"
        "\nComplete Git Identity Management\n"
        "Safe git identity switching with actual git configuration management\n"
        "\nCommands:\n"
        "  add                  Add new account interactively\n"
        "  edit <account>       Edit an existing account interactively\n"
        "  list, ls             List all configured accounts\n"
        "  remove, rm, delete <account>  Remove specified account\n"
        "  status               Show current account status\n"
        "  doctor, health       Run local configuration/key readiness checks\n"
        "  config               Show configuration file information\n"
        "  init <shell>         Emit shell integration (bash|zsh|fish|sh|dash|ksh)\n"
        "  resume               Restore saved boot-volatile SSH/GPG state (never rewrites Git config)\n"
        "  reset [account]      Kill agents and delete isolated GPG/SSH state (all, or one)\n"
        "  switch <account>     Switch to specified account\n"
        "  <account>            Switch to specified account\n"
        "\nOptions:\n"
        "  --global, -g         Use global git scope\n"
        "  --local, -l          Use local git scope (default)\n"
        "  --dry-run, -n        Show what would be done without executing\n"
        "  --yes, -y            Assume 'yes' to confirmation prompts (add/edit/remove/reset)\n"
        "  --names              With 'list': print only account names (one per line)\n"
        "  --verbose, -V        Enable verbose output\n"
        "  --debug, -d          Enable debug logging\n"
        "  --color, -c          Force color output\n"
        "  --no-color, -C       Disable color output\n"
        "  --help, -h           Show this help message\n"
        "  --version, -v        Show version information\n"
        "\nExamples:\n"
        "  gitswitch add                    # Add new account interactively\n"
        "  gitswitch edit work              # Edit the 'work' account\n"
        "  gitswitch list                   # List all accounts\n"
        "  gitswitch list --names           # Print just account names (for scripts/completion)\n"
        "  gitswitch 1                      # Switch to account ID 1\n"
        "  gitswitch work                   # Switch to account matching 'work'\n"
        "  gitswitch remove 2 --yes         # Remove account ID 2 without confirmation\n"
        "  gitswitch doctor                 # Run local readiness checks\n"
        "\nKey Features:\n"
        "- Secure TOML configuration management\n"
        "- Interactive account creation with validation\n"
        "- Local account configuration and key readiness checks\n"
        "- SSH/GPG key validation and security checks\n"
        "- Atomic configuration file operations\n"
        "- Safe file permission handling\n"
        "- Actual git configuration switching\n"
        "- Repository detection and scope management\n"
        "- Git configuration validation and testing\n";
    const char *help_argv[] = {"gitswitch", "--help", NULL};
    const char *version_argv[] = {"gitswitch", "--version", NULL};
    char home[128], runtime[128], output_path[128], output[8192];
    char expected_version[256];

    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar09-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar09-run"), 0);
    CHECK_EQ_INT(run_cli_stdout_mode(home, runtime, help_argv,
                                    CLI_STDOUT_CAPTURE_ONLY, output_path,
                                    sizeof(output_path)), 0);
    CHECK_STR_EQ(slurp(output_path, output, sizeof(output)), expected_help);
    unlink(output_path);

    CHECK((size_t)snprintf(expected_version, sizeof(expected_version),
                           "%s %s (%s)\n", GITSWITCH_NAME,
                           GITSWITCH_VERSION, GITSWITCH_COMMIT) <
          sizeof(expected_version));
    CHECK_EQ_INT(run_cli_stdout_mode(home, runtime, version_argv,
                                    CLI_STDOUT_CAPTURE_ONLY, output_path,
                                    sizeof(output_path)), 0);
    CHECK_STR_EQ(slurp(output_path, output, sizeof(output)), expected_version);
    CHECK(directory_empty(home));
    CHECK(directory_empty(runtime));
    unlink(output_path);
}

TEST(informational_output_failures_return_nonzero) {
    struct {
        const char *label;
        const char *argv[3];
        const char *prefix;
    } commands[] = {
        {"help", {"gitswitch", "--help", NULL}, "Usage: g"},
        {"version", {"gitswitch", "--version", NULL}, "gitswitc"},
    };
    struct {
        const char *label;
        cli_stdout_mode_t mode;
        off_t expected_size;
    } faults[] = {
        {"zero-byte read-only descriptor", CLI_STDOUT_READ_ONLY, 0},
        {"late flush after a short write", CLI_STDOUT_LIMITED_FILE,
         CLI_LATE_FLUSH_LIMIT},
    };

    for (size_t c = 0; c < sizeof(commands) / sizeof(commands[0]); c++) {
        for (size_t f = 0; f < sizeof(faults) / sizeof(faults[0]); f++) {
            char home[128], runtime[128], output_path[128], output[64];
            struct stat st;
            int rc;

            CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                          "gitswitch-ar09-home"), 0);
            CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                          "gitswitch-ar09-run"), 0);
            rc = run_cli_stdout_mode(home, runtime, commands[c].argv,
                                     faults[f].mode, output_path,
                                     sizeof(output_path));
            if (!(rc > 0 && rc < 126)) {
                fprintf(stderr, "  %s / %s returned %d\n",
                        commands[c].label, faults[f].label, rc);
            }
            CHECK(rc > 0 && rc < 126);
            CHECK_EQ_INT(stat(output_path, &st), 0);
            CHECK_EQ_INT(st.st_size, faults[f].expected_size);
            if (faults[f].expected_size > 0) {
                slurp(output_path, output, sizeof(output));
                CHECK(memcmp(output, commands[c].prefix,
                             CLI_LATE_FLUSH_LIMIT) == 0);
            }
            CHECK(directory_empty(home));
            CHECK(directory_empty(runtime));
            unlink(output_path);
        }
    }
}

TEST(exact_arity_rejects_invalid_forms_before_state_creation) {
    cli_case_t cases[] = {
        {"add extra", {"gitswitch", "add", "extra", NULL}},
        {"list option then extra", {"gitswitch", "list", "-n", "extra", NULL}},
        {"status extra then option", {"gitswitch", "status", "extra", "--dry-run", NULL}},
        {"config extra", {"gitswitch", "--global", "config", "extra", NULL}},
        {"resume extra", {"gitswitch", "resume", "extra", NULL}},
        {"edit missing", {"gitswitch", "edit", NULL}},
        {"edit extra", {"gitswitch", "edit", "one", "two", NULL}},
        {"remove missing", {"gitswitch", "--yes", "remove", NULL}},
        {"remove extra", {"gitswitch", "remove", "one", "--yes", "two", NULL}},
        {"bare switch extra", {"gitswitch", "account", "extra", NULL}},
        {"literal switch missing", {"gitswitch", "switch", NULL}},
        {"literal switch extra", {"gitswitch", "switch", "account", "extra", NULL}},
        {"reset extra", {"gitswitch", "reset", "one", "two", "-n", NULL}},
        {"init extra", {"gitswitch", "init", "bash", "zsh", NULL}},
        {"doctor extra", {"gitswitch", "doctor", "extra", NULL}},
        {"names list extra", {"gitswitch", "--names", "list", "extra", NULL}},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], output_path[128], output[4096];
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home), "gitswitch-ar07-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime), "gitswitch-ar07-run"), 0);
        rc = run_cli(home, runtime, cases[i].argv,
                     output_path, sizeof(output_path));
        slurp(output_path, output, sizeof(output));
        if (!(rc > 0 && rc < 126)) {
            fprintf(stderr, "  case '%s' returned %d:\n%s\n",
                    cases[i].label, rc, output);
        }
        CHECK(rc > 0 && rc < 126);
        CHECK(strstr(output, "invalid number of operands") != NULL);
        CHECK(directory_empty(home));
        CHECK(directory_empty(runtime));
        unlink(output_path);
    }
}

TEST(unsafe_shorthand_selector_with_extra_operand_is_not_reflected) {
    static const char unsafe_selector[] = "safe\xE2\x80\xAE" "txt";
    const char *argv[] = {"gitswitch", unsafe_selector, "extra", NULL};
    char home[128], runtime[128], output_path[128], output[4096];
    int rc;

    CHECK_EQ_INT(make_private_dir(home, sizeof(home), "gitswitch-ar08-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime), "gitswitch-ar08-run"), 0);
    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    slurp(output_path, output, sizeof(output));
    CHECK(rc > 0 && rc < 126);
    CHECK(strstr(output, "invalid number of operands") != NULL);
    CHECK(strstr(output, unsafe_selector) == NULL);
    CHECK(directory_empty(home));
    CHECK(directory_empty(runtime));
    unlink(output_path);
}

TEST(legacy_init_alias_rejects_operands_without_creating_state) {
    char home[128], runtime[128], output_path[128], output[4096];
    const char *argv[] = {"gitswitch", "--ssh-agent-info", "extra", NULL};
    int rc;

    CHECK_EQ_INT(make_private_dir(home, sizeof(home), "gitswitch-ar07-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime), "gitswitch-ar07-run"), 0);
    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    slurp(output_path, output, sizeof(output));
    CHECK(rc > 0 && rc < 126);
    CHECK(strstr(output, "does not accept operands") != NULL);
    CHECK(directory_empty(home));
    CHECK(directory_empty(runtime));
    unlink(output_path);
}

TEST(valid_dry_run_grammar_is_noncreating_for_every_command_shape) {
    cli_case_t cases[] = {
        {"add", {"gitswitch", "-n", "add", NULL}},
        {"list", {"gitswitch", "list", "--dry-run", NULL}},
        {"status", {"gitswitch", "--dry-run", "status", NULL}},
        {"config", {"gitswitch", "config", "-n", NULL}},
        {"resume", {"gitswitch", "-n", "resume", NULL}},
        {"edit", {"gitswitch", "edit", "missing", "-n", NULL}},
        {"remove", {"gitswitch", "-n", "remove", "missing", NULL}},
        {"bare switch", {"gitswitch", "missing", "--dry-run", NULL}},
        {"literal switch", {"gitswitch", "switch", "missing", "--dry-run", NULL}},
        {"reset all", {"gitswitch", "reset", "-n", NULL}},
        {"reset one", {"gitswitch", "-n", "reset", "missing", NULL}},
        {"init", {"gitswitch", "init", "bash", "-n", NULL}},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], output_path[128], output[8192];
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home), "gitswitch-ar07-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime), "gitswitch-ar07-run"), 0);
        rc = run_cli(home, runtime, cases[i].argv,
                     output_path, sizeof(output_path));
        slurp(output_path, output, sizeof(output));
        if (rc < 0 || rc >= 126) {
            fprintf(stderr, "  dry-run case '%s' returned %d:\n%s\n",
                    cases[i].label, rc, output);
        }
        CHECK(rc >= 0 && rc < 126);
        CHECK(strstr(output, "invalid number of operands") == NULL);
        CHECK(strstr(output, "Account added successfully") == NULL);
        CHECK(strstr(output, "Account updated.") == NULL);
        CHECK(strstr(output, "Account removed successfully") == NULL);
        CHECK(strstr(output, "Switched to:") == NULL);
        CHECK(strstr(output, "Reset all gitswitch SSH/GPG state") == NULL);
        CHECK(directory_empty(home));
        CHECK(directory_empty(runtime));
        unlink(output_path);
    }
}

TEST(dry_run_does_not_repair_existing_config_directory_permissions) {
    char home[128], runtime[128], output_path[128], path[512];
    const char *argv[] = {"gitswitch", "--dry-run", "list", NULL};
    struct stat before, after;
    int rc;

    CHECK_EQ_INT(make_private_dir(home, sizeof(home), "gitswitch-ar07-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime), "gitswitch-ar07-run"), 0);
    snprintf(path, sizeof(path), "%s/.config", home);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    CHECK_EQ_INT(mkdir(path, 0755), 0);
    CHECK_EQ_INT(stat(path, &before), 0);

    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(stat(path, &after), 0);
    CHECK_EQ_INT(after.st_mode & 0777, before.st_mode & 0777);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.config.lock", home);
    CHECK(access(path, F_OK) != 0);
    CHECK(directory_empty(runtime));
    unlink(output_path);
}

TEST(save_failures_never_print_final_mutation_success) {
    cli_case_t cases[] = {
        {"add", {"gitswitch", "--yes", "add", NULL}},
        {"edit", {"gitswitch", "--yes", "edit", "old", NULL}},
        {"remove", {"gitswitch", "--yes", "remove", "old", NULL}},
        {"reset", {"gitswitch", "--yes", "reset", NULL}},
    };
    const char *input[] = {
        "newacct\nnew@example.com\n\n\n\n\n",
        "\n\nmetadata changed\n\n\n\n",
        NULL,
        NULL,
    };
    const char *banner[] = {
        "Account added successfully",
        "Account updated.",
        "Account removed successfully",
        "Reset all gitswitch SSH/GPG state",
    };

    if (getuid() == 0) {
        TS_SKIP("unprivileged",
                "owner-write denial is ineffective as root");
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], config_dir[4096];
        char input_path[4096], output_path[128], output[16384];
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar07-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar07-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);
        input_path[0] = '\0';
        if (input[i]) {
            snprintf(input_path, sizeof(input_path), "%s/input", runtime);
            CHECK_EQ_INT(write_text_mode(input_path, input[i], 0600), 0);
        }
        CHECK_EQ_INT(chmod(config_dir, 0500), 0);

        rc = run_cli_input(home, runtime,
                           input_path[0] ? input_path : NULL,
                           cases[i].argv, output_path,
                           sizeof(output_path));
        slurp(output_path, output, sizeof(output));
        if (!(rc > 0 && rc < 126)) {
            fprintf(stderr, "  save-failure case '%s' returned %d:\n%s\n",
                    cases[i].label, rc, output);
        }
        CHECK(rc > 0 && rc < 126);
        CHECK(strstr(output, "Failed to save configuration changes") != NULL);
        CHECK(strstr(output, banner[i]) == NULL);

        CHECK_EQ_INT(chmod(config_dir, 0700), 0);
        unlink(output_path);
    }
}

TEST(switch_save_failure_restores_git_config_active_and_exact_hint) {
    char home[128], runtime[128], config_dir[4096];
    char output_path[128], output[16384], path[8192], contents[16384];
    const char *argv[] = {
        "gitswitch", "--yes", "switch", "new", NULL
    };
    int rc;

    if (getuid() == 0) {
        TS_SKIP("unprivileged",
                "owner-write denial is ineffective as root");
    }
    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar07-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar07-run"), 0);
    CHECK_EQ_INT(write_account_config(home, true, config_dir,
                                      sizeof(config_dir)), 0);
    CHECK_EQ_INT(chmod(config_dir, 0500), 0);

    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    slurp(output_path, output, sizeof(output));
    CHECK(rc > 0 && rc < 126);
    CHECK(strstr(output, "Failed to save configuration changes") != NULL);
    if (strstr(output, "previous switch state restored") == NULL) {
        fprintf(stderr, "  switch-save rollback output:\n%s\n", output);
    }
    CHECK(strstr(output, "previous switch state restored") != NULL);
    CHECK(strstr(output, "Switched to:") == NULL);

    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "active_account = \"old\"") != NULL);
    CHECK(strstr(contents, "active_account = \"new\"") == NULL);
    snprintf(path, sizeof(path), "%s/.resume-hint", config_dir);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, "none\n");
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "old@example.com") != NULL);
    CHECK(strstr(contents, "new@example.com") == NULL);

    CHECK_EQ_INT(chmod(config_dir, 0700), 0);
    unlink(output_path);
}

TEST(production_ignores_inherited_test_fault_environment) {
    char home[128], runtime[128], config_dir[4096];
    char output_path[128], output[16384], path[8192], contents[16384];
    const char *argv[] = {"gitswitch", "--yes", "new", NULL};
    int rc;

    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar07-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar07-run"), 0);
    CHECK_EQ_INT(write_account_config(home, true, config_dir,
                                      sizeof(config_dir)), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT", "1", 1), 0);
    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    CHECK_EQ_INT(unsetenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT"), 0);

    slurp(output_path, output, sizeof(output));
    CHECK_EQ_INT(rc, 0);
    CHECK(strstr(output, "Injected resume-hint commit failure") == NULL);
    CHECK(strstr(output, "previous switch state restored") == NULL);
    CHECK(strstr(output, "Switched to: new") != NULL);

    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    slurp(path, contents, sizeof(contents));
    /* Switch state lives exclusively in the consolidated state artifact; the
     * legacy settings key is intentionally not rewritten on every switch. */
    CHECK(strstr(contents, "active_account = \"old\"") != NULL);
    CHECK(strstr(contents, "active_account = \"new\"") == NULL);
    snprintf(path, sizeof(path), "%s/.resume-hint", config_dir);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, "none\nactive=new\n");
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "old@example.com") == NULL);
    CHECK(strstr(contents, "new@example.com") != NULL);
    unlink(output_path);
}

TEST_MAIN_BEGIN()
    if (resolve_binary() != 0) {
        fprintf(stderr, "RESULT FAIL: cannot locate gitswitch binary\n");
        return 1;
    }
    RUN_TEST(option_order_is_independent_of_posixly_correct);
    RUN_TEST(help_names_every_yes_confirmation_bypass);
    RUN_TEST(config_command_reports_exact_owner_only_mode);
    RUN_TEST(informational_output_bytes_are_stable);
    RUN_TEST(informational_output_failures_return_nonzero);
    RUN_TEST(exact_arity_rejects_invalid_forms_before_state_creation);
    RUN_TEST(unsafe_shorthand_selector_with_extra_operand_is_not_reflected);
    RUN_TEST(legacy_init_alias_rejects_operands_without_creating_state);
    RUN_TEST(valid_dry_run_grammar_is_noncreating_for_every_command_shape);
    RUN_TEST(dry_run_does_not_repair_existing_config_directory_permissions);
    RUN_TEST(save_failures_never_print_final_mutation_success);
    RUN_TEST(switch_save_failure_restores_git_config_active_and_exact_hint);
    RUN_TEST(production_ignores_inherited_test_fault_environment);
TEST_MAIN_END()
