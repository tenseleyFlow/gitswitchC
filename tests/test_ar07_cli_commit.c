/* AR-07 T5 CLI contract and dry-run purity regressions.
 *
 * main.c is excluded from unit-test links because it owns main(), so these
 * tests execute the built CLI in isolated HOME/XDG_RUNTIME_DIR trees. */
#include "test.h"
#include "gitswitch.h"
#include "publication.h"
#include "toml_parser.h"
#include "utils.h"

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

#define CHECK_LOOKUP_STATUS(call, expected) do {                             \
    publication_lookup_status_t lookup_status_ = (call);                    \
    CHECK(lookup_status_ == (expected));                                     \
} while (0)

#define CLI_ACCOUNT_1_INCARNATION \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define CLI_ACCOUNT_2_INCARNATION \
    "2222222222222222222222222222222222222222222222222222222222222222"

static char g_bin[4096];
static const char *g_cli_path_override;

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
    if (!ts_mkdtemp(path)) return -1;
    return ts_canonicalize_dir_path(path, size);
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

static int install_cli_probe_program(const char *source,
                                     const char *directory, const char *name,
                                     char *path, size_t path_size) {
    int written;

    written = snprintf(path, path_size, "%s/%s", directory, name);
    if (written < 0 || (size_t)written >= path_size) return -1;
    return copy_file(source, path) == 0 && chmod(path, 0700) == 0 ? 0 : -1;
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
        "incarnation = \"" CLI_ACCOUNT_1_INCARNATION "\"\n"
        "name = \"old\"\n"
        "email = \"old@example.com\"\n"
        "preferred_scope = \"global\"\n";
    static const char two_accounts[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"old\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"" CLI_ACCOUNT_1_INCARNATION "\"\n"
        "name = \"old\"\n"
        "email = \"old@example.com\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "incarnation = \"" CLI_ACCOUNT_2_INCARNATION "\"\n"
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

static int write_legacy_two_account_config(const char *home,
                                           char *config_dir,
                                           size_t dir_size) {
    char path[4096];
    static const char legacy_two_accounts[] =
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

    if (write_account_config(home, true, config_dir, dir_size) != 0 ||
        (size_t)snprintf(path, sizeof(path), "%s/accounts.toml",
                         config_dir) >= sizeof(path)) {
        return -1;
    }
    return write_text_mode(path, legacy_two_accounts, 0600);
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

static bool directory_has_only_entry(const char *path,
                                     const char *expected_name) {
    DIR *dir = opendir(path);
    struct dirent *entry;
    bool found = false;
    bool valid = true;

    if (!dir) {
        return false;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (found || strcmp(entry->d_name, expected_name) != 0) {
            valid = false;
        }
        found = true;
    }
    if (closedir(dir) != 0) {
        return false;
    }
    return valid && found;
}

static bool directory_has_exact_entries(const char *path,
                                        const char *const expected[],
                                        size_t expected_count) {
    DIR *dir = opendir(path);
    struct dirent *entry;
    size_t found_count = 0;

    if (!dir) {
        return false;
    }
    while ((entry = readdir(dir)) != NULL) {
        bool matched = false;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        for (size_t i = 0; i < expected_count; i++) {
            if (strcmp(entry->d_name, expected[i]) == 0) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            closedir(dir);
            return false;
        }
        found_count++;
    }
    if (closedir(dir) != 0) {
        return false;
    }
    return found_count == expected_count;
}

static bool modification_timestamp_equal(const struct stat *before,
                                         const struct stat *after) {
#ifdef __APPLE__
    return before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
           before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec;
#else
    return before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec;
#endif
}

static bool mutation_timestamps_equal(const struct stat *before,
                                      const struct stat *after) {
#ifdef __APPLE__
    return modification_timestamp_equal(before, after) &&
           before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return modification_timestamp_equal(before, after) &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
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

static int extract_unique_line(const char *text, const char *prefix,
                               char *line, size_t line_size) {
    const char *cursor = text;
    size_t prefix_length = strlen(prefix);
    bool found = false;

    if (!text || !prefix || !line || line_size == 0) return -1;
    line[0] = '\0';
    while (*cursor) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);

        if (length >= prefix_length &&
            memcmp(cursor, prefix, prefix_length) == 0) {
            if (found || length + 2U > line_size) return -1;
            memcpy(line, cursor, length);
            line[length] = '\n';
            line[length + 1U] = '\0';
            found = true;
        }
        if (!newline) break;
        cursor = newline + 1;
    }
    return found ? 0 : -1;
}

static int extract_unique_section(const char *text, const char *heading,
                                  char *section, size_t section_size) {
    const char *start;
    const char *end;
    size_t heading_length;
    size_t length;

    if (!text || !heading || !section || section_size == 0) return -1;
    section[0] = '\0';
    heading_length = strlen(heading);
    start = strstr(text, heading);
    if (!start || strstr(start + heading_length, heading)) return -1;
    end = strstr(start, "\n\n");
    if (!end) return -1;
    length = (size_t)(end - start) + 1U;
    if (length + 1U > section_size) return -1;
    memcpy(section, start, length);
    section[length] = '\0';
    return 0;
}

static int extract_parenthesized_value(const char *line, const char *prefix,
                                       char *value, size_t value_size) {
    const char *open;
    const char *close;
    size_t length;

    if (!line || !prefix || !value || value_size == 0) return -1;
    value[0] = '\0';
    if (strncmp(line, prefix, strlen(prefix)) != 0) return -1;
    open = strchr(line, '(');
    close = open ? strchr(open + 1, ')') : NULL;
    if (!open || !close || close[1] != '\n' || close[2] != '\0' ||
        strchr(open + 1, '(') || strchr(close + 1, ')')) {
        return -1;
    }
    length = (size_t)(close - (open + 1));
    if (length + 1U > value_size) return -1;
    memcpy(value, open + 1, length);
    value[length] = '\0';
    return 0;
}

typedef struct {
    struct stat home;
    struct stat config_parent;
    struct stat config_dir;
    struct stat accounts;
    struct stat resume_hint;
    struct stat config_lock;
    struct stat git_config;
    char accounts_contents[4096];
    char resume_hint_contents[4096];
    char config_lock_contents[128];
    char git_config_contents[4096];
} persisted_tree_snapshot_t;

static bool preserved_metadata_equal(const struct stat *before,
                                     const struct stat *after) {
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_nlink == after->st_nlink &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           before->st_size == after->st_size &&
           mutation_timestamps_equal(before, after);
}

static bool preserved_file_identity_equal(const struct stat *before,
                                          const struct stat *after) {
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_nlink == after->st_nlink &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           before->st_size == after->st_size &&
           modification_timestamp_equal(before, after);
}

static int snapshot_text_file(const char *path, struct stat *metadata,
                              char *contents, size_t contents_size) {
    if (lstat(path, metadata) != 0 || !S_ISREG(metadata->st_mode) ||
        metadata->st_size < 0 ||
        (uintmax_t)metadata->st_size >= (uintmax_t)contents_size) {
        return -1;
    }
    slurp(path, contents, contents_size);
    return strlen(contents) == (size_t)metadata->st_size ? 0 : -1;
}

static int snapshot_persisted_tree(const char *home, const char *config_dir,
                                   persisted_tree_snapshot_t *snapshot) {
    static const char *const home_entries[] = {".config", ".gitconfig"};
    static const char *const config_parent_entries[] = {"gitswitch"};
    static const char *const config_entries[] = {
        "accounts.toml", ".resume-hint", ".config.lock"
    };
    char path[8192];

    if (!home || !config_dir || !snapshot) return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (!directory_has_exact_entries(
            home, home_entries,
            sizeof(home_entries) / sizeof(home_entries[0])) ||
        lstat(home, &snapshot->home) != 0 ||
        (size_t)snprintf(path, sizeof(path), "%s/.config", home) >=
            sizeof(path) ||
        !directory_has_exact_entries(
            path, config_parent_entries,
            sizeof(config_parent_entries) /
                sizeof(config_parent_entries[0])) ||
        lstat(path, &snapshot->config_parent) != 0 ||
        !directory_has_exact_entries(
            config_dir, config_entries,
            sizeof(config_entries) / sizeof(config_entries[0])) ||
        lstat(config_dir, &snapshot->config_dir) != 0) {
        return -1;
    }

    if ((size_t)snprintf(path, sizeof(path), "%s/accounts.toml",
                         config_dir) >= sizeof(path) ||
        snapshot_text_file(path, &snapshot->accounts,
                           snapshot->accounts_contents,
                           sizeof(snapshot->accounts_contents)) != 0 ||
        (size_t)snprintf(path, sizeof(path), "%s/.resume-hint",
                         config_dir) >= sizeof(path) ||
        snapshot_text_file(path, &snapshot->resume_hint,
                           snapshot->resume_hint_contents,
                           sizeof(snapshot->resume_hint_contents)) != 0 ||
        (size_t)snprintf(path, sizeof(path), "%s/.config.lock",
                         config_dir) >= sizeof(path) ||
        snapshot_text_file(path, &snapshot->config_lock,
                           snapshot->config_lock_contents,
                           sizeof(snapshot->config_lock_contents)) != 0 ||
        (size_t)snprintf(path, sizeof(path), "%s/.gitconfig", home) >=
            sizeof(path) ||
        snapshot_text_file(path, &snapshot->git_config,
                           snapshot->git_config_contents,
                           sizeof(snapshot->git_config_contents)) != 0) {
        return -1;
    }
    return 0;
}

static bool persisted_tree_unchanged(
    const char *home, const char *config_dir,
    const persisted_tree_snapshot_t *before) {
    persisted_tree_snapshot_t after;

    if (!before || snapshot_persisted_tree(home, config_dir, &after) != 0) {
        return false;
    }
    return preserved_metadata_equal(&before->home, &after.home) &&
           preserved_metadata_equal(&before->config_parent,
                                    &after.config_parent) &&
           preserved_metadata_equal(&before->config_dir,
                                    &after.config_dir) &&
           preserved_metadata_equal(&before->accounts, &after.accounts) &&
           preserved_metadata_equal(&before->resume_hint,
                                    &after.resume_hint) &&
           preserved_metadata_equal(&before->config_lock,
                                    &after.config_lock) &&
           preserved_metadata_equal(&before->git_config,
                                    &after.git_config) &&
           strcmp(before->accounts_contents, after.accounts_contents) == 0 &&
           strcmp(before->resume_hint_contents,
                  after.resume_hint_contents) == 0 &&
           strcmp(before->config_lock_contents,
                  after.config_lock_contents) == 0 &&
           strcmp(before->git_config_contents,
                  after.git_config_contents) == 0;
}

/* Mutating command admission revalidates the persistent lock mode before
 * dispatch and can therefore advance only that inode's ctime.  Authorization
 * failure must retain its identity/ownership/mode/size/bytes and preserve all
 * account authority files with exact metadata and contents. */
static bool persisted_authority_unchanged(
    const char *home, const char *config_dir,
    const persisted_tree_snapshot_t *before) {
    persisted_tree_snapshot_t after;

    if (!before || snapshot_persisted_tree(home, config_dir, &after) != 0) {
        return false;
    }
    return preserved_metadata_equal(&before->home, &after.home) &&
           preserved_metadata_equal(&before->config_parent,
                                    &after.config_parent) &&
           preserved_metadata_equal(&before->config_dir,
                                    &after.config_dir) &&
           preserved_metadata_equal(&before->accounts, &after.accounts) &&
           preserved_metadata_equal(&before->resume_hint,
                                    &after.resume_hint) &&
           preserved_file_identity_equal(&before->config_lock,
                                         &after.config_lock) &&
           preserved_metadata_equal(&before->git_config,
                                    &after.git_config) &&
           strcmp(before->accounts_contents, after.accounts_contents) == 0 &&
           strcmp(before->resume_hint_contents,
                  after.resume_hint_contents) == 0 &&
           strcmp(before->config_lock_contents,
                  after.config_lock_contents) == 0 &&
           strcmp(before->git_config_contents,
                  after.git_config_contents) == 0;
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
            (g_cli_path_override &&
             setenv("PATH", g_cli_path_override, 1) != 0) ||
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

static int run_cli_with_path(const char *home, const char *runtime,
                             const char *path,
                             const char *const argv[],
                             char *output_path, size_t output_size) {
    const char *previous_override = g_cli_path_override;
    int rc;

    g_cli_path_override = path;
    rc = run_cli(home, runtime, argv, output_path, output_size);
    g_cli_path_override = previous_override;
    return rc;
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

TEST(readme_and_help_name_every_yes_confirmation_bypass) {
    static const char expected_commands[] = "add/edit/remove/reset";
    const char *argv[] = {"gitswitch", "--help", NULL};
    const char *source_root = getenv("GITSWITCH_SOURCE_ROOT");
    char home[128], runtime[128], output_path[128], output[8192];
    char readme_path[4096], readme[16384], readme_line[256], help_line[256];
    char readme_options[2048], help_options[2048], yes_commands[128];
    int path_length;
    int rc;

    if (!source_root || !*source_root) source_root = ".";
    path_length = snprintf(readme_path, sizeof(readme_path), "%s/README.md",
                           source_root);
    CHECK(path_length > 0 && (size_t)path_length < sizeof(readme_path));
    if (path_length <= 0 || (size_t)path_length >= sizeof(readme_path)) return;
    slurp(readme_path, readme, sizeof(readme));
    CHECK_EQ_INT(extract_unique_line(readme, "  --yes, -y", readme_line,
                                     sizeof(readme_line)), 0);
    CHECK_EQ_INT(extract_unique_section(readme, "Options:\n", readme_options,
                                        sizeof(readme_options)), 0);

    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar09-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar09-run"), 0);
    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    CHECK_EQ_INT(rc, 0);
    slurp(output_path, output, sizeof(output));
    CHECK_EQ_INT(extract_unique_line(output, "  --yes, -y", help_line,
                                     sizeof(help_line)), 0);
    CHECK_EQ_INT(extract_unique_section(output, "Options:\n", help_options,
                                        sizeof(help_options)), 0);
    CHECK_STR_EQ(readme_options, help_options);
    CHECK_STR_EQ(readme_line, help_line);
    CHECK_EQ_INT(extract_parenthesized_value(
                     help_line, "  --yes, -y", yes_commands,
                     sizeof(yes_commands)), 0);
    CHECK_STR_EQ(yes_commands, expected_commands);
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

TEST(doctor_reports_the_bound_gpg_path_and_keeps_absence_optional) {
    const char *argv[] = {"gitswitch", "--no-color", "doctor", NULL};
    char trusted_root[4096], with_gpg[4096], without_gpg[4096];
    char probe_source[4096];
    char git_path[4096], ssh_agent_path[4096], gpg_path[4096];

    CHECK_EQ_INT(find_command_path("true", probe_source,
                                   sizeof(probe_source)), 0);
    CHECK(ts_mkdtemp_trusted(trusted_root, sizeof(trusted_root),
                             "gitswitch-ar11-doctor") != NULL);
    CHECK((size_t)snprintf(with_gpg, sizeof(with_gpg), "%s/with-gpg",
                           trusted_root) < sizeof(with_gpg));
    CHECK((size_t)snprintf(without_gpg, sizeof(without_gpg), "%s/no-gpg",
                           trusted_root) < sizeof(without_gpg));
    CHECK_EQ_INT(mkdir(with_gpg, 0700), 0);
    CHECK_EQ_INT(mkdir(without_gpg, 0700), 0);
    CHECK_EQ_INT(install_cli_probe_program(probe_source, with_gpg, "git",
                                           git_path,
                                           sizeof(git_path)), 0);
    CHECK_EQ_INT(install_cli_probe_program(probe_source, with_gpg,
                                           "ssh-agent",
                                           ssh_agent_path,
                                           sizeof(ssh_agent_path)), 0);
    CHECK_EQ_INT(install_cli_probe_program(probe_source, with_gpg, "gpg",
                                           gpg_path,
                                           sizeof(gpg_path)), 0);
    CHECK_EQ_INT(install_cli_probe_program(probe_source, without_gpg, "git",
                                           git_path,
                                           sizeof(git_path)), 0);
    CHECK_EQ_INT(install_cli_probe_program(probe_source, without_gpg,
                                           "ssh-agent",
                                           ssh_agent_path,
                                           sizeof(ssh_agent_path)), 0);

    for (int gpg_present = 1; gpg_present >= 0; gpg_present--) {
        char home[128], runtime[128], config_dir[4096];
        char output_path[128], output[16384], expected[8192];
        const char *selected_path = gpg_present ? with_gpg : without_gpg;
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar11-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar11-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);
        rc = run_cli_with_path(home, runtime, selected_path, argv,
                               output_path, sizeof(output_path));
        slurp(output_path, output, sizeof(output));
        if (rc != 0) {
            fprintf(stderr, "  doctor GPG-present=%d returned %d:\n%s\n",
                    gpg_present, rc, output);
        }
        CHECK_EQ_INT(rc, 0);
        if (gpg_present) {
            CHECK((size_t)snprintf(expected, sizeof(expected),
                                   "[OK] GPG found: %s", gpg_path) <
                  sizeof(expected));
            CHECK(strstr(output, expected) != NULL);
            CHECK(strstr(output, "GPG not found") == NULL);
        } else {
            CHECK(strstr(output,
                         "[WARN] GPG not found - GPG signing will not work") !=
                  NULL);
            CHECK(strstr(output, "GPG found:") == NULL);
        }
        CHECK(strstr(output,
                     "All configured accounts passed the reported local checks") !=
              NULL);
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

TEST(read_only_commands_never_create_or_repair_runtime_manager_lock) {
    cli_case_t cases[] = {
        {"no command", {"gitswitch", NULL}},
        {"list", {"gitswitch", "list", NULL}},
        {"list alias", {"gitswitch", "ls", NULL}},
        {"status", {"gitswitch", "status", NULL}},
        {"doctor", {"gitswitch", "doctor", NULL}},
        {"health", {"gitswitch", "health", NULL}},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], agent_dir[256], lock_path[320];
        char config_dir[4096];
        char output_path[128];
        persisted_tree_snapshot_t persisted_before;
        struct stat manager_before = {0};
        struct stat manager_after = {0};
        struct stat lock_observed = {0};
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar07-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar07-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);
        CHECK_EQ_INT(snapshot_persisted_tree(home, config_dir,
                                             &persisted_before), 0);
        CHECK((size_t)snprintf(agent_dir, sizeof(agent_dir),
                               "%s/gitswitch-ssh", runtime) <
              sizeof(agent_dir));
        CHECK_EQ_INT(mkdir(agent_dir, 0700), 0);
        CHECK(directory_empty(agent_dir));
        CHECK_EQ_INT(stat(agent_dir, &manager_before), 0);
        CHECK((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock",
                               agent_dir) < sizeof(lock_path));
        errno = 0;
        CHECK(lstat(lock_path, &lock_observed) != 0 && errno == ENOENT);

        rc = run_cli(home, runtime, cases[i].argv,
                     output_path, sizeof(output_path));
        if (rc < 0 || rc >= 126) {
            fprintf(stderr, "  read-only case '%s' returned %d\n",
                    cases[i].label, rc);
        }
        CHECK(rc >= 0 && rc < 126);
        CHECK_EQ_INT(stat(agent_dir, &manager_after), 0);
        CHECK(preserved_metadata_equal(&manager_before, &manager_after));
        CHECK(directory_empty(agent_dir));
        errno = 0;
        CHECK(lstat(lock_path, &lock_observed) != 0 && errno == ENOENT);
        CHECK(persisted_tree_unchanged(home, config_dir,
                                       &persisted_before));
        unlink(output_path);
    }
}

TEST(read_only_commands_never_repair_or_replace_wrong_mode_manager_lock) {
    cli_case_t cases[] = {
        {"no command", {"gitswitch", NULL}},
        {"list", {"gitswitch", "list", NULL}},
        {"list alias", {"gitswitch", "ls", NULL}},
        {"status", {"gitswitch", "status", NULL}},
        {"doctor", {"gitswitch", "doctor", NULL}},
        {"health", {"gitswitch", "health", NULL}},
    };
    static const char lock_sentinel[] = "wrong-mode-lock-sentinel\n";

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], runtime[128], agent_dir[256], lock_path[320];
        char config_dir[4096];
        char output_path[128], lock_contents[128];
        persisted_tree_snapshot_t persisted_before;
        struct stat manager_before = {0}, manager_after = {0};
        struct stat lock_before = {0}, lock_after = {0};
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar07-home"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar07-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);
        CHECK_EQ_INT(snapshot_persisted_tree(home, config_dir,
                                             &persisted_before), 0);
        CHECK((size_t)snprintf(agent_dir, sizeof(agent_dir),
                               "%s/gitswitch-ssh", runtime) <
              sizeof(agent_dir));
        CHECK_EQ_INT(mkdir(agent_dir, 0700), 0);
        CHECK((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock",
                               agent_dir) < sizeof(lock_path));
        CHECK_EQ_INT(write_text_mode(lock_path, lock_sentinel, 0644), 0);
        CHECK(directory_has_only_entry(agent_dir, ".lock"));
        CHECK_STR_EQ(slurp(lock_path, lock_contents, sizeof(lock_contents)),
                     lock_sentinel);
        CHECK_EQ_INT(stat(agent_dir, &manager_before), 0);
        CHECK_EQ_INT(lstat(lock_path, &lock_before), 0);

        rc = run_cli(home, runtime, cases[i].argv,
                     output_path, sizeof(output_path));
        if (rc < 0 || rc >= 126) {
            fprintf(stderr, "  wrong-mode read-only case '%s' returned %d\n",
                    cases[i].label, rc);
        }
        CHECK(rc >= 0 && rc < 126);
        CHECK_EQ_INT(stat(agent_dir, &manager_after), 0);
        CHECK_EQ_INT(lstat(lock_path, &lock_after), 0);

        CHECK(persisted_tree_unchanged(home, config_dir,
                                       &persisted_before));
        CHECK(preserved_metadata_equal(&manager_before, &manager_after));
        CHECK(directory_has_only_entry(agent_dir, ".lock"));

        CHECK(preserved_metadata_equal(&lock_before, &lock_after));
        CHECK_EQ_INT(lock_before.st_mode & 0777, 0644);
        CHECK_EQ_INT(lock_after.st_mode & 0777, 0644);
        CHECK_STR_EQ(slurp(lock_path, lock_contents, sizeof(lock_contents)),
                     lock_sentinel);

        unlink(lock_path);
        unlink(output_path);
    }
}

TEST(mutation_failures_never_print_final_mutation_success) {
    static const char *const publish_old[] = {
        "gitswitch", "--global", "--yes", "switch", "old", NULL
    };
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
    const char *failure_context[] = {
        "Failed to save configuration changes",
        "Failed to save configuration changes",
        "Failed to remove account: Cannot acquire the retirement lifecycle lock",
        ("reset failed; account and active-state metadata were preserved for retry: "
         "Cannot acquire the retirement lifecycle lock"),
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

        /* Remove/reset install their retirement guard before any runtime
         * cleanup or config mutation. The deliberately unwritable directory
         * therefore exercises that fail-closed admission boundary rather than
         * the later save reached by add/edit. Seed publication authority while
         * the fixture is writable so ownership admission is not the failure. */
        if (i >= 2U) {
            rc = run_cli(home, runtime, publish_old,
                         output_path, sizeof(output_path));
            if (rc != 0) {
                slurp(output_path, output, sizeof(output));
                fprintf(stderr,
                        "  publication setup for save-failure case '%s' "
                        "returned %d:\n%s\n",
                        cases[i].label, rc, output);
            }
            CHECK_EQ_INT(rc, 0);
            unlink(output_path);
        }
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
        if (strstr(output, failure_context[i]) == NULL) {
            fprintf(stderr,
                    "  save-failure case '%s' omitted expected context '%s':\n%s\n",
                    cases[i].label, failure_context[i], output);
        }
        CHECK(rc > 0 && rc < 126);
        CHECK(strstr(output, failure_context[i]) != NULL);
        CHECK(strstr(output, banner[i]) == NULL);

        CHECK_EQ_INT(chmod(config_dir, 0700), 0);
        unlink(output_path);
    }
}

TEST(destructive_prompt_output_failure_blocks_authorization) {
    static const char *const publish_old[] = {
        "gitswitch", "--global", "--yes", "switch", "old", NULL
    };
    cli_case_t cases[] = {
        {"remove", {"gitswitch", "remove", "old", NULL}},
        {"reset", {"gitswitch", "reset", NULL}},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char home[128], publish_runtime[128], runtime[128];
        char config_dir[4096], output_path[128];
        char input_path[] = "/tmp/gitswitch-ar11-prompt-input.XXXXXX";
        persisted_tree_snapshot_t persisted_before;
        struct stat runtime_before = {0}, runtime_after = {0};
        bool durable_unchanged;
        int input_fd;
        int rc;

        CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                      "gitswitch-ar11-home"), 0);
        CHECK_EQ_INT(make_private_dir(publish_runtime,
                                      sizeof(publish_runtime),
                                      "gitswitch-ar11-publish-run"), 0);
        CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                      "gitswitch-ar11-run"), 0);
        CHECK_EQ_INT(write_account_config(home, false, config_dir,
                                          sizeof(config_dir)), 0);

        /* Successful remove/reset now requires exact durable publication
         * authority. Seed that authority through the real switch path, but use
         * a separate runtime root so the authorization-failure assertion starts
         * from an exactly empty runtime tree. */
        rc = run_cli(home, publish_runtime, publish_old,
                     output_path, sizeof(output_path));
        if (rc != 0) {
            char output[16384];

            fprintf(stderr,
                    "  publication setup for prompt-output case '%s' "
                    "returned %d:\n%s\n",
                    cases[i].label, rc,
                    slurp(output_path, output, sizeof(output)));
        }
        CHECK_EQ_INT(rc, EXIT_SUCCESS);
        unlink(output_path);

        CHECK_EQ_INT(snapshot_persisted_tree(home, config_dir,
                                             &persisted_before), 0);
        CHECK(directory_empty(runtime));
        CHECK_EQ_INT(stat(runtime, &runtime_before), 0);

        input_fd = mkstemp(input_path);
        CHECK(input_fd >= 0);
        if (input_fd >= 0) {
            CHECK_EQ_INT(close(input_fd), 0);
            CHECK_EQ_INT(write_text_mode(input_path, "yes\n", 0600), 0);
        }

        rc = run_cli_input_posixly(home, runtime, input_path,
                                   cases[i].argv, POSIXLY_INHERIT,
                                   CLI_STDOUT_READ_ONLY, output_path,
                                   sizeof(output_path));
        if (rc != EXIT_FAILURE) {
            fprintf(stderr,
                    "  prompt-output case '%s' returned %d, expected %d\n",
                    cases[i].label, rc, EXIT_FAILURE);
        }
        CHECK_EQ_INT(rc, EXIT_FAILURE);
        durable_unchanged = persisted_authority_unchanged(
            home, config_dir, &persisted_before);
        if (!durable_unchanged) {
            fprintf(stderr,
                    "  prompt-output case '%s' changed durable authority\n",
                    cases[i].label);
        }
        CHECK(durable_unchanged);
        CHECK_EQ_INT(stat(runtime, &runtime_after), 0);
        CHECK(preserved_metadata_equal(&runtime_before, &runtime_after));
        CHECK(directory_empty(runtime));

        unlink(input_path);
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

TEST(valid_legacy_switch_migrates_before_publication) {
    char home[128], runtime[128], config_dir[4096];
    char output_path[128], output[16384], config_path[8192];
    char state_path[8192], state[16384], git_config_path[8192];
    char config_contents[16384];
    char old_incarnation[ACCOUNT_INCARNATION_LEN] = "";
    char new_incarnation[ACCOUNT_INCARNATION_LEN] = "";
    static const char active_prefix[] = "none\nactive=new\n";
    toml_document_t *document = NULL;
    publication_ledger_t ledger;
    const publication_record_t *record = NULL;
    size_t state_length;
    const char *argv[] = {"gitswitch", "--yes", "new", NULL};
    int rc;

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(make_private_dir(home, sizeof(home),
                                  "gitswitch-ar11-home"), 0);
    CHECK_EQ_INT(make_private_dir(runtime, sizeof(runtime),
                                  "gitswitch-ar11-run"), 0);
    CHECK_EQ_INT(write_legacy_two_account_config(
                     home, config_dir, sizeof(config_dir)), 0);

    rc = run_cli(home, runtime, argv, output_path, sizeof(output_path));
    slurp(output_path, output, sizeof(output));
    if (rc != 0) {
        fprintf(stderr, "  valid legacy switch returned %d:\n%s\n", rc,
                output);
    }
    CHECK_EQ_INT(rc, 0);
    CHECK(strstr(output, "Switched to: new") != NULL);

    CHECK((size_t)snprintf(config_path, sizeof(config_path),
                           "%s/accounts.toml", config_dir) <
          sizeof(config_path));
    document = malloc(sizeof(*document));
    CHECK(document != NULL);
    if (document) {
        CHECK_EQ_INT(toml_parse_file(config_path, document), 0);
        if (document->is_valid) {
            CHECK_EQ_INT(toml_get_string(document, "accounts.1",
                                         "incarnation", old_incarnation,
                                         sizeof(old_incarnation)), 0);
            CHECK_EQ_INT(toml_get_string(document, "accounts.2",
                                         "incarnation", new_incarnation,
                                         sizeof(new_incarnation)), 0);
        }
        toml_cleanup_document(document);
        free(document);
    }
    CHECK(account_incarnation_is_valid(old_incarnation));
    CHECK(account_incarnation_is_valid(new_incarnation));
    CHECK(strcmp(old_incarnation, new_incarnation) != 0);
    slurp(config_path, config_contents, sizeof(config_contents));
    CHECK(strstr(config_contents, "active_account") == NULL);

    CHECK((size_t)snprintf(state_path, sizeof(state_path),
                           "%s/.resume-hint", config_dir) <
          sizeof(state_path));
    slurp(state_path, state, sizeof(state));
    state_length = strlen(state);
    CHECK(state_length > sizeof(active_prefix) - 1U);
    if (state_length >= sizeof(active_prefix) - 1U &&
        memcmp(state, active_prefix, sizeof(active_prefix) - 1U) == 0) {
        CHECK_EQ_INT(publication_ledger_parse(
                         (const unsigned char *)state +
                             sizeof(active_prefix) - 1U,
                         state_length - (sizeof(active_prefix) - 1U),
                         &ledger),
                     0);
    }
    CHECK(ledger.present);
    CHECK_EQ_INT((int)ledger.version, (int)PUBLICATION_LEDGER_VERSION);
    CHECK_EQ_INT((int)ledger.count, 1);
    CHECK((size_t)snprintf(git_config_path, sizeof(git_config_path),
                           "%s/.gitconfig", home) <
          sizeof(git_config_path));
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                            &ledger, UINT32_C(2), new_incarnation,
                            PUBLICATION_SCOPE_GLOBAL, git_config_path, "",
                            &record),
                        PUBLICATION_LOOKUP_FOUND);
    CHECK(record != NULL);
    if (record) {
        CHECK_EQ_INT(publication_record_validate(record), 0);
        CHECK_STR_EQ(record->account_incarnation, new_incarnation);
        CHECK_EQ_INT((int)record->state,
                     (int)PUBLICATION_STATE_PUBLISHED);
        CHECK_EQ_INT((int)record->capabilities,
                     (int)(PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION));
        CHECK_STR_EQ(record->config_path, git_config_path);
        CHECK_STR_EQ(record->repository_path, "");
    }
    slurp(git_config_path, config_contents, sizeof(config_contents));
    CHECK(strstr(config_contents, "old@example.com") == NULL);
    CHECK(strstr(config_contents, "new@example.com") != NULL);

    publication_ledger_clear(&ledger);
    unlink(output_path);
}

TEST(production_ignores_inherited_test_fault_environment) {
    char home[128], runtime[128], config_dir[4096];
    char output_path[128], output[16384], path[8192], contents[16384];
    char git_config_path[8192];
    static const char active_prefix[] = "none\nactive=new\n";
    publication_ledger_t ledger;
    const publication_record_t *record = NULL;
    size_t contents_length;
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
    contents_length = strlen(contents);
    CHECK(contents_length > sizeof(active_prefix) - 1U);
    CHECK(contents_length >= sizeof(active_prefix) - 1U &&
          memcmp(contents, active_prefix,
                 sizeof(active_prefix) - 1U) == 0);

    /* The first two lines remain the shell-integration contract. A normal
     * prepared switch now appends its exact sealed Git destination instead of
     * discarding that provenance after commit. Parse the complete tail through
     * the production grammar so an arbitrary suffix cannot satisfy the test. */
    publication_ledger_init(&ledger);
    if (contents_length >= sizeof(active_prefix) - 1U &&
        memcmp(contents, active_prefix, sizeof(active_prefix) - 1U) == 0) {
        CHECK_EQ_INT(publication_ledger_parse(
                         (const unsigned char *)contents +
                             sizeof(active_prefix) - 1U,
                         contents_length - (sizeof(active_prefix) - 1U),
                         &ledger),
                     0);
    }
    CHECK(ledger.present);
    CHECK_EQ_INT((int)ledger.version, (int)PUBLICATION_LEDGER_VERSION);
    CHECK_EQ_INT((int)ledger.count, 1);
    CHECK((size_t)snprintf(git_config_path, sizeof(git_config_path),
                           "%s/.gitconfig", home) <
          sizeof(git_config_path));
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(2), CLI_ACCOUNT_2_INCARNATION,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &record),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(record != NULL);
    if (record) {
        CHECK_EQ_INT(publication_record_validate(record), 0);
        CHECK_STR_EQ(record->account_incarnation,
                     CLI_ACCOUNT_2_INCARNATION);
        CHECK_EQ_INT((int)record->state,
                     (int)PUBLICATION_STATE_PUBLISHED);
        CHECK_EQ_INT((int)record->capabilities,
                     (int)(PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION));
        CHECK_STR_EQ(record->config_path, git_config_path);
        CHECK_STR_EQ(record->repository_path, "");
    }
    publication_ledger_clear(&ledger);
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
    RUN_TEST(readme_and_help_name_every_yes_confirmation_bypass);
    RUN_TEST(config_command_reports_exact_owner_only_mode);
    RUN_TEST(doctor_reports_the_bound_gpg_path_and_keeps_absence_optional);
    RUN_TEST(informational_output_bytes_are_stable);
    RUN_TEST(informational_output_failures_return_nonzero);
    RUN_TEST(exact_arity_rejects_invalid_forms_before_state_creation);
    RUN_TEST(unsafe_shorthand_selector_with_extra_operand_is_not_reflected);
    RUN_TEST(legacy_init_alias_rejects_operands_without_creating_state);
    RUN_TEST(valid_dry_run_grammar_is_noncreating_for_every_command_shape);
    RUN_TEST(dry_run_does_not_repair_existing_config_directory_permissions);
    RUN_TEST(read_only_commands_never_create_or_repair_runtime_manager_lock);
    RUN_TEST(read_only_commands_never_repair_or_replace_wrong_mode_manager_lock);
    RUN_TEST(mutation_failures_never_print_final_mutation_success);
    RUN_TEST(destructive_prompt_output_failure_blocks_authorization);
    RUN_TEST(switch_save_failure_restores_git_config_active_and_exact_hint);
    RUN_TEST(valid_legacy_switch_migrates_before_publication);
    RUN_TEST(production_ignores_inherited_test_fault_environment);
TEST_MAIN_END()
