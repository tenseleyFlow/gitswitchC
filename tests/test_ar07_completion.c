/* AR-07 T16: completion grammar parity and the side-effect-free names loader. */
#include "test.h"
#include "config.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

static char g_root[PATH_MAX];
static char g_binary[PATH_MAX];
static int g_runner_calls;
static int g_probe_calls;

static int write_text(const char *path, const char *text, mode_t mode) {
    FILE *file = fopen(path, "w");
    size_t length = text ? strlen(text) : 0;

    if (!file) return -1;
    if (length > 0 && fwrite(text, 1, length, file) != length) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) return -1;
    return chmod(path, mode);
}

static int read_text(const char *path, char *out, size_t out_size) {
    FILE *file;
    size_t used;

    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    file = fopen(path, "r");
    if (!file) return -1;
    used = fread(out, 1, out_size - 1, file);
    if (ferror(file)) {
        fclose(file);
        return -1;
    }
    out[used] = '\0';
    return fclose(file);
}

static int path_join(char *out, size_t out_size, const char *left,
                     const char *right) {
    int written = snprintf(out, out_size, "%s/%s", left, right);
    return written >= 0 && (size_t)written < out_size ? 0 : -1;
}

static bool directory_empty(const char *path) {
    DIR *dir = opendir(path);
    struct dirent *entry;

    if (!dir) return false;
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

static int directory_entry_count(const char *path) {
    DIR *dir = opendir(path);
    struct dirent *entry;
    int count = 0;

    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            count++;
        }
    }
    closedir(dir);
    return count;
}

static size_t count_occurrences(const char *text, const char *needle) {
    size_t count = 0;
    size_t length = strlen(needle);

    if (length == 0) return 0;
    while ((text = strstr(text, needle)) != NULL) {
        count++;
        text += length;
    }
    return count;
}

static int append_candidate(char *out, size_t out_size, size_t *used,
                            const char *token, size_t token_length,
                            const char *prefix) {
    size_t prefix_length = prefix ? strlen(prefix) : 0;

    if (!out || !used || !token || token_length == 0 ||
        prefix_length + token_length + 1 >= out_size - *used) {
        return -1;
    }
    if (prefix_length > 0) {
        memcpy(out + *used, prefix, prefix_length);
        *used += prefix_length;
    }
    memcpy(out + *used, token, token_length);
    *used += token_length;
    out[(*used)++] = '\n';
    out[*used] = '\0';
    return 0;
}

static bool candidate_set_contains(const char *set, const char *candidate) {
    size_t length = strlen(candidate);
    const char *line = set;

    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t line_length = end ? (size_t)(end - line) : strlen(line);
        if (line_length == length && memcmp(line, candidate, length) == 0) {
            return true;
        }
        line = end ? end + 1 : NULL;
    }
    return false;
}

static bool candidate_set_is_exact(const char *actual,
                                   const char *const expected[],
                                   size_t expected_count) {
    size_t actual_count = count_occurrences(actual, "\n");

    if (actual_count != expected_count) return false;
    for (size_t i = 0; i < expected_count; i++) {
        if (!candidate_set_contains(actual, expected[i])) return false;
    }
    return true;
}

static int extract_bash_assignment(const char *source, const char *name,
                                   char *out, size_t out_size) {
    char marker[64];
    const char *cursor;
    const char *end;
    size_t used = 0;

    if (snprintf(marker, sizeof(marker), "local %s=\"", name) < 0) return -1;
    cursor = strstr(source, marker);
    if (!cursor) return -1;
    cursor += strlen(marker);
    end = strchr(cursor, '"');
    if (!end) return -1;
    out[0] = '\0';
    while (cursor < end) {
        const char *token;
        while (cursor < end && *cursor == ' ') cursor++;
        token = cursor;
        while (cursor < end && *cursor != ' ') cursor++;
        if (cursor > token &&
            append_candidate(out, out_size, &used, token,
                             (size_t)(cursor - token), NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int extract_zsh_block(const char *source, const char *name,
                             char delimiter, char *out, size_t out_size) {
    char marker[64];
    const char *cursor;
    size_t used = 0;

    if (snprintf(marker, sizeof(marker), "%s=(", name) < 0) return -1;
    cursor = strstr(source, marker);
    if (!cursor || !(cursor = strchr(cursor, '\n'))) return -1;
    cursor++;
    out[0] = '\0';
    for (;;) {
        const char *line_end = strchr(cursor, '\n');
        const char *token_end;
        if (!line_end) return -1;
        while (cursor < line_end && (*cursor == ' ' || *cursor == '\t')) {
            cursor++;
        }
        if (cursor < line_end && *cursor == ')') return 0;
        if (cursor >= line_end || *cursor != '\'') return -1;
        cursor++;
        token_end = memchr(cursor, delimiter, (size_t)(line_end - cursor));
        if (!token_end) return -1;
        if (append_candidate(out, out_size, &used, cursor,
                             (size_t)(token_end - cursor), NULL) != 0) {
            return -1;
        }
        cursor = line_end + 1;
    }
}

static int extract_fish_candidates(const char *source, const char *state,
                                   bool options, char *out,
                                   size_t out_size) {
    char marker[96];
    const char *cursor = source;
    size_t used = 0;

    if (snprintf(marker, sizeof(marker),
                 "-n '__gitswitch_state %s'", state) < 0) {
        return -1;
    }
    out[0] = '\0';
    while (*cursor) {
        const char *line_end = strchr(cursor, '\n');
        size_t line_length = line_end ? (size_t)(line_end - cursor)
                                      : strlen(cursor);
        const char *hit = strstr(cursor, marker);
        if (hit && hit < cursor + line_length) {
            if (options) {
                static const struct {
                    const char *flag;
                    const char *prefix;
                } fields[] = {{" -l ", "--"}, {" -s ", "-"}};
                for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
                    const char *value = strstr(cursor, fields[i].flag);
                    if (value && value < cursor + line_length) {
                        const char *end;
                        value += strlen(fields[i].flag);
                        end = value;
                        while (end < cursor + line_length && *end != ' ' &&
                               *end != '\t') {
                            end++;
                        }
                        if (append_candidate(out, out_size, &used, value,
                                             (size_t)(end - value),
                                             fields[i].prefix) != 0) {
                            return -1;
                        }
                    }
                }
            } else {
                const char *value = strstr(cursor, " -a ");
                const char *end;
                if (!value || value >= cursor + line_length) return -1;
                value += sizeof(" -a ") - 1;
                end = value;
                while (end < cursor + line_length && *end != ' ' &&
                       *end != '\t') {
                    end++;
                }
                if (append_candidate(out, out_size, &used, value,
                                     (size_t)(end - value), NULL) != 0) {
                    return -1;
                }
            }
        }
        if (!line_end) break;
        cursor = line_end + 1;
    }
    return 0;
}

static int create_runtime_socket(const char *path, int *fd_out) {
    struct sockaddr_un address;
    int fd;

    if (!path || !fd_out || strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (bind(fd, (struct sockaddr *)(void *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0) {
        close(fd);
        return -1;
    }
    *fd_out = fd;
    return 0;
}

static const char *find_shell(const char *name) {
    static const char *const prefixes[] = {
        "/usr/bin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", NULL
    };
    static char found[PATH_MAX];

    for (size_t i = 0; prefixes[i]; i++) {
        int written = snprintf(found, sizeof(found), "%s%s", prefixes[i], name);
        if (written >= 0 && (size_t)written < sizeof(found) &&
            access(found, X_OK) == 0) {
            return found;
        }
    }
    return NULL;
}

static int capture_child(pid_t child, int read_fd, char *out,
                         size_t out_size) {
    size_t used = 0;
    int status;
    pid_t waited;

    if (!out || out_size == 0) {
        close(read_fd);
        return -1;
    }
    for (;;) {
        char discard[1024];
        char *target = used + 1 < out_size ? out + used : discard;
        size_t available = used + 1 < out_size ? out_size - used - 1
                                               : sizeof(discard);
        ssize_t count = read(read_fd, target, available);
        if (count > 0) {
            if (target != discard) used += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            close(read_fd);
            return -1;
        }
        break;
    }
    close(read_fd);
    out[used] = '\0';
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int run_script(const char *shell, bool fish, const char *script,
                      char *out, size_t out_size) {
    int pipe_fd[2];
    pid_t child;

    if (!shell || pipe(pipe_fd) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }
    if (child == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(pipe_fd[1], STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0) {
            _exit(125);
        }
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        if (null_fd > STDERR_FILENO) close(null_fd);
        if (fish) {
            execl(shell, shell, "--no-config", "-c", script, (char *)NULL);
        } else {
            execl(shell, shell, "-c", script, (char *)NULL);
        }
        _exit(126);
    }
    close(pipe_fd[1]);
    return capture_child(child, pipe_fd[0], out, out_size);
}

static int run_cli(const char *home, const char *runtime,
                   const char *const argv[], bool posixly,
                   char *out, size_t out_size) {
    int pipe_fd[2];
    pid_t child;

    if (pipe(pipe_fd) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }
    if (child == 0) {
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
            dup2(pipe_fd[1], STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0 ||
            setenv("HOME", home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", runtime, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1) != 0) {
            _exit(125);
        }
        if (posixly) {
            if (setenv("POSIXLY_CORRECT", "1", 1) != 0) _exit(125);
        } else {
            unsetenv("POSIXLY_CORRECT");
        }
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        if (null_fd > STDERR_FILENO) close(null_fd);
        execv(g_binary, (char *const *)argv);
        _exit(126);
    }
    close(pipe_fd[1]);
    return capture_child(child, pipe_fd[0], out, out_size);
}

typedef struct {
    bool had_home;
    bool had_runtime;
    char home[PATH_MAX];
    char runtime[PATH_MAX];
} env_snapshot_t;

static void save_environment(env_snapshot_t *snapshot) {
    const char *home = getenv("HOME");
    const char *runtime = getenv("XDG_RUNTIME_DIR");

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->had_home = home != NULL;
    snapshot->had_runtime = runtime != NULL;
    if (home) snprintf(snapshot->home, sizeof(snapshot->home), "%s", home);
    if (runtime) {
        snprintf(snapshot->runtime, sizeof(snapshot->runtime), "%s", runtime);
    }
}

static void restore_environment(const env_snapshot_t *snapshot) {
    if (snapshot->had_home) setenv("HOME", snapshot->home, 1);
    else unsetenv("HOME");
    if (snapshot->had_runtime) {
        setenv("XDG_RUNTIME_DIR", snapshot->runtime, 1);
    } else {
        unsetenv("XDG_RUNTIME_DIR");
    }
}

static int make_home_fixture(char *root, size_t root_size,
                             char *home, size_t home_size,
                             char *runtime, size_t runtime_size,
                             char *config_dir, size_t config_dir_size,
                             char *config_path, size_t config_path_size) {
    char dot_config[PATH_MAX];

    if (snprintf(root, root_size, "/tmp/gitswitch-ar07-completion.XXXXXX") < 0 ||
        !ts_mkdtemp(root) ||
        path_join(home, home_size, root, "home") != 0 ||
        path_join(runtime, runtime_size, root, "runtime") != 0 ||
        mkdir(home, 0700) != 0 || mkdir(runtime, 0700) != 0 ||
        path_join(dot_config, sizeof(dot_config), home, ".config") != 0 ||
        mkdir(dot_config, 0700) != 0 ||
        path_join(config_dir, config_dir_size, dot_config, "gitswitch") != 0 ||
        mkdir(config_dir, 0700) != 0 ||
        path_join(config_path, config_path_size, config_dir, "accounts.toml") != 0) {
        return -1;
    }
    return 0;
}

static int write_valid_config(const char *path, const char *active) {
    char content[4096];
    int written = snprintf(
        content, sizeof(content),
        "[settings]\n"
        "default_scope = \"local\"\n"
        "%s%s%s"
        "\n"
        "[accounts.1]\n"
        "name = \"Alpha\"\n"
        "email = \"alpha@example.com\"\n"
        "description = \"first\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"Beta Space\"\n"
        "email = \"beta@example.com\"\n",
        active ? "active_account = \"" : "",
        active ? active : "",
        active ? "\"\n" : "");
    if (written < 0 || (size_t)written >= sizeof(content)) return -1;
    return write_text(path, content, 0600);
}

static int counting_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    (void)argv;
    (void)opts;
    g_runner_calls++;
    if (result) memset(result, 0, sizeof(*result));
    return -1;
}

static int counting_probe(int fd, int timeout_ms) {
    (void)fd;
    (void)timeout_ms;
    g_probe_calls++;
    return 0;
}

TEST(completion_surfaces_are_exact_and_hidden_options_stay_hidden) {
    static const char *const options[] = {
        "--global", "--local", "--dry-run", "--yes", "--names",
        "--verbose", "--debug", "--color", "--no-color", "--help",
        "--version",
        "-g", "-l", "-n", "-y", "-V", "-d", "-c", "-C", "-h", "-v",
    };
    static const char *const commands[] = {
        "add", "edit", "list", "ls", "remove", "rm", "delete", "status",
        "doctor", "health", "config", "init", "resume", "reset", "switch",
    };
    char bash_path[PATH_MAX], zsh_path[PATH_MAX], fish_path[PATH_MAX];
    char bash[32768], zsh[32768], fish[32768];
    char bash_options[2048], zsh_options[2048], fish_options[2048];
    char bash_commands[1024], zsh_commands[1024], fish_commands[1024];

    CHECK_EQ_INT(path_join(bash_path, sizeof(bash_path), g_root,
                           "completions/gitswitch.bash"), 0);
    CHECK_EQ_INT(path_join(zsh_path, sizeof(zsh_path), g_root,
                           "completions/gitswitch.zsh"), 0);
    CHECK_EQ_INT(path_join(fish_path, sizeof(fish_path), g_root,
                           "completions/gitswitch.fish"), 0);
    CHECK_EQ_INT(read_text(bash_path, bash, sizeof(bash)), 0);
    CHECK_EQ_INT(read_text(zsh_path, zsh, sizeof(zsh)), 0);
    CHECK_EQ_INT(read_text(fish_path, fish, sizeof(fish)), 0);

    CHECK_EQ_INT(extract_bash_assignment(bash, "options", bash_options,
                                         sizeof(bash_options)), 0);
    CHECK_EQ_INT(extract_zsh_block(zsh, "options", '[', zsh_options,
                                   sizeof(zsh_options)), 0);
    CHECK_EQ_INT(extract_fish_candidates(fish, "options", true,
                                         fish_options,
                                         sizeof(fish_options)), 0);
    CHECK(candidate_set_is_exact(bash_options, options,
                                 sizeof(options) / sizeof(options[0])));
    CHECK(candidate_set_is_exact(zsh_options, options,
                                 sizeof(options) / sizeof(options[0])));
    CHECK(candidate_set_is_exact(fish_options, options,
                                 sizeof(options) / sizeof(options[0])));

    CHECK_EQ_INT(extract_bash_assignment(bash, "subcommands", bash_commands,
                                         sizeof(bash_commands)), 0);
    CHECK_EQ_INT(extract_zsh_block(zsh, "subcommands", ':', zsh_commands,
                                   sizeof(zsh_commands)), 0);
    CHECK_EQ_INT(extract_fish_candidates(fish, "command", false,
                                         fish_commands,
                                         sizeof(fish_commands)), 0);
    CHECK(candidate_set_is_exact(bash_commands, commands,
                                 sizeof(commands) / sizeof(commands[0])));
    CHECK(candidate_set_is_exact(zsh_commands, commands,
                                 sizeof(commands) / sizeof(commands[0])));
    CHECK(candidate_set_is_exact(fish_commands, commands,
                                 sizeof(commands) / sizeof(commands[0])));

    CHECK(strstr(bash, "--ssh-agent-info") == NULL);
    CHECK(strstr(zsh, "--ssh-agent-info") == NULL);
    CHECK(strstr(fish, "--ssh-agent-info") == NULL);
    CHECK(strstr(bash, "--resume-check") == NULL);
    CHECK(strstr(zsh, "--resume-check") == NULL);
    CHECK(strstr(fish, "--resume-check") == NULL);
    CHECK(strstr(bash, "--resume-hint-probe") == NULL);
    CHECK(strstr(zsh, "--resume-hint-probe") == NULL);
    CHECK(strstr(fish, "--resume-hint-probe") == NULL);
}

TEST(bash_completion_executes_getopt_style_operand_state) {
    const char *bash = find_shell("bash");
    char output[16384];
    const char *script =
        "_init_completion(){ return 1; }; "
        "source \"$GS_T16_ROOT/completions/gitswitch.bash\"; "
        "_gitswitch_complete_accounts(){ COMPREPLY+=(ACCOUNT); }; "
        "probe(){ COMP_WORDS=(\"$@\"); COMP_CWORD=$((${#COMP_WORDS[@]}-1)); "
        "_gitswitch; printf '<%s>\\n' \"${COMPREPLY[*]}\"; }; "
        "for cmd in edit remove reset switch; do "
        "probe gitswitch -g \"$cmd\" ''; "
        "probe gitswitch \"$cmd\" -gn ''; "
        "probe gitswitch \"$cmd\" Alpha -y ''; done; "
        "probe gitswitch -- edit ''; "
        "probe gitswitch edit -- ''; probe gitswitch edit -- Alpha ''; "
        "probe gitswitch -- -g ''";

    CHECK(bash != NULL);
    if (!bash) return;
    CHECK_EQ_INT(run_script(bash, false, script, output, sizeof(output)), 0);
    CHECK_STR_EQ(output,
                 "<ACCOUNT>\n<ACCOUNT>\n<>\n"
                 "<ACCOUNT>\n<ACCOUNT>\n<>\n"
                 "<ACCOUNT>\n<ACCOUNT>\n<>\n"
                 "<ACCOUNT>\n<ACCOUNT>\n<>\n"
                 "<ACCOUNT>\n<ACCOUNT>\n<>\n<>\n");
}

TEST(zsh_completion_executes_runtime_expansion_and_state_scanner) {
    const char *zsh = find_shell("zsh");
    char output[16384];
    const char *script =
        "_describe(){ print -r -- D:$2; }; _values(){ print -r -- V:$1; }; "
        "commands[gitswitch]=/bin/echo; words=(gitswitch edit ''); CURRENT=3; "
        "source \"$GS_T16_ROOT/completions/gitswitch.zsh\"; print -- READY; "
        "probe(){ words=(\"$@\"); CURRENT=${#words}; _gitswitch; }; "
        "for cmd in edit remove reset switch; do "
        "probe gitswitch -g \"$cmd\" ''; "
        "probe gitswitch \"$cmd\" -gn ''; "
        "probe gitswitch \"$cmd\" Alpha -y ''; done; "
        "scan(){ words=(\"$@\"); local _gitswitch_seen_cmd=''; "
        "local -i _gitswitch_operand_count=0 _gitswitch_options_enabled=1; "
        "_gitswitch_scan ${#words}; print -r -- "
        "S:$_gitswitch_seen_cmd:$_gitswitch_operand_count:$_gitswitch_options_enabled; }; "
        "scan gitswitch -g edit ''; scan gitswitch edit -gn ''; "
        "scan gitswitch edit Alpha -y ''; scan gitswitch -- edit ''; "
        "scan gitswitch edit -- Alpha ''; scan gitswitch switch ''";

    if (!zsh) {
        printf("  (skipped zsh runtime completion: shell unavailable)\n");
        return;
    }
    CHECK_EQ_INT(run_script(zsh, false, script, output, sizeof(output)), 0);
    CHECK(strstr(output, "D:accounts\nREADY\n") != NULL);
    CHECK_EQ_INT(count_occurrences(output, "D:accounts\n"), 9);
    CHECK(strstr(output, "S:edit:0:1\n") != NULL);
    CHECK(strstr(output, "S:edit:1:1\n") != NULL);
    CHECK(strstr(output, "S:edit:0:0\n") != NULL);
    CHECK(strstr(output, "S:edit:1:0\n") != NULL);
    CHECK(strstr(output, "S:switch:0:1\n") != NULL);
}

TEST(fish_completion_executes_getopt_style_operand_state) {
    const char *fish = find_shell("fish");
    char output[16384];
    const char *script =
        "source \"$GS_T16_ROOT/completions/gitswitch.fish\"; "
        "complete -c gitswitch -e; complete -c gitswitch -f; "
        "complete -c gitswitch -f -n '__gitswitch_state account' -a ACCOUNT; "
        "complete -c gitswitch -f -n '__gitswitch_state command' -a COMMAND; "
        "for cmd in edit remove reset switch; "
        "for line in \"gitswitch -g $cmd \" \"gitswitch $cmd -gn \" "
        "\"gitswitch $cmd Alpha -y \"; "
        "echo P; complete -C \"$line\"; echo E; end; end; "
        "for line in 'gitswitch -g ' 'gitswitch -- edit ' "
        "'gitswitch edit -- ' 'gitswitch edit -- Alpha ' "
        "'gitswitch -- -g'; "
        "echo P; complete -C \"$line\"; echo E; end";

    if (!fish) {
        printf("  (skipped fish runtime completion: shell unavailable)\n");
        return;
    }
    CHECK_EQ_INT(run_script(fish, true, script, output, sizeof(output)), 0);
    CHECK_STR_EQ(output,
                 "P\nACCOUNT\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nE\n"
                 "P\nACCOUNT\nCOMMAND\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nACCOUNT\nE\n"
                 "P\nE\n"
                 "P\nE\n");
}

TEST(names_loader_preserves_account_admission_without_runtime_work) {
    char root[PATH_MAX], home[PATH_MAX], runtime[PATH_MAX];
    char config_dir[PATH_MAX], config_path[PATH_MAX], lock_path[PATH_MAX];
    char ssh_dir[PATH_MAX], socket_path[PATH_MAX], current_path[PATH_MAX];
    char agent_lock[PATH_MAX], shared_lock_dir[PATH_MAX];
    gitswitch_ctx_t names_ctx;
    gitswitch_ctx_t full_ctx;
    env_snapshot_t saved;
    command_runner_fn old_runner;
    ssh_probe_poll_fn old_probe;
    struct stat socket_before;
    struct stat socket_after;
    int socket_fd = -1;

    CHECK_EQ_INT(make_home_fixture(root, sizeof(root), home, sizeof(home),
                                   runtime, sizeof(runtime), config_dir,
                                   sizeof(config_dir), config_path,
                                   sizeof(config_path)), 0);
    CHECK_EQ_INT(write_valid_config(config_path, NULL), 0);
    CHECK_EQ_INT(path_join(ssh_dir, sizeof(ssh_dir), runtime,
                           "gitswitch-ssh"), 0);
    CHECK_EQ_INT(mkdir(ssh_dir, 0700), 0);
    CHECK_EQ_INT(path_join(socket_path, sizeof(socket_path), ssh_dir,
                           "ssh-agent.Alpha.sock"), 0);
    CHECK_EQ_INT(create_runtime_socket(socket_path, &socket_fd), 0);
    CHECK_EQ_INT(path_join(current_path, sizeof(current_path), ssh_dir,
                           "current.sock"), 0);
    CHECK_EQ_INT(symlink(socket_path, current_path), 0);
    CHECK_EQ_INT(path_join(agent_lock, sizeof(agent_lock), ssh_dir,
                           ".lock"), 0);
    CHECK_EQ_INT(path_join(shared_lock_dir, sizeof(shared_lock_dir), runtime,
                           "gitswitch-runtime"), 0);
    CHECK_EQ_INT(lstat(socket_path, &socket_before), 0);
    save_environment(&saved);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    g_runner_calls = 0;
    g_probe_calls = 0;
    old_runner = run_set_runner(counting_runner);
    old_probe = ssh_manager_set_probe_poll_fn(counting_probe);
    memset(&names_ctx, 0, sizeof(names_ctx));
    CHECK_EQ_INT(config_init_names(&names_ctx), 0);
    run_set_runner(old_runner);
    ssh_manager_set_probe_poll_fn(old_probe);

    CHECK_EQ_INT(names_ctx.account_count, 2);
    CHECK_STR_EQ(names_ctx.accounts[0].name, "Alpha");
    CHECK_STR_EQ(names_ctx.accounts[1].name, "Beta Space");
    CHECK(names_ctx.current_account == NULL);
    CHECK(names_ctx.config.active_account[0] == '\0');
    CHECK_EQ_INT(g_runner_calls, 0);
    CHECK_EQ_INT(g_probe_calls, 0);
    CHECK_EQ_INT(directory_entry_count(runtime), 1);
    CHECK_EQ_INT(directory_entry_count(ssh_dir), 2);
    CHECK(access(agent_lock, F_OK) != 0);
    CHECK(access(shared_lock_dir, F_OK) != 0);
    CHECK_EQ_INT(lstat(socket_path, &socket_after), 0);
    CHECK_EQ_INT(socket_before.st_dev, socket_after.st_dev);
    CHECK_EQ_INT(socket_before.st_ino, socket_after.st_ino);
    CHECK_EQ_INT(path_join(lock_path, sizeof(lock_path), config_dir,
                           ".config.lock"), 0);
    CHECK(access(lock_path, F_OK) != 0);

    /* Positive control: the ordinary loader must traverse this planted live
     * runtime namespace and therefore create its manager lock. If discovery
     * is accidentally restored to config_init_names(), the assertions above
     * fail even on platforms where connect(2) resolves without poll(2). */
    memset(&full_ctx, 0, sizeof(full_ctx));
    CHECK_EQ_INT(config_load(&full_ctx, config_path), 0);
    CHECK(access(agent_lock, F_OK) == 0);
    CHECK_EQ_INT(full_ctx.account_count, names_ctx.account_count);
    for (size_t i = 0; i < names_ctx.account_count; i++) {
        CHECK_STR_EQ(full_ctx.accounts[i].name, names_ctx.accounts[i].name);
    }
    if (socket_fd >= 0) close(socket_fd);
    restore_environment(&saved);
}

TEST(names_loader_validates_toml_but_ignores_external_active_artifact) {
    char root[PATH_MAX], home[PATH_MAX], runtime[PATH_MAX];
    char config_dir[PATH_MAX], config_path[PATH_MAX], hint[PATH_MAX];
    char before[128], after[128];
    gitswitch_ctx_t ctx;
    env_snapshot_t saved;

    CHECK_EQ_INT(make_home_fixture(root, sizeof(root), home, sizeof(home),
                                   runtime, sizeof(runtime), config_dir,
                                   sizeof(config_dir), config_path,
                                   sizeof(config_path)), 0);
    CHECK_EQ_INT(write_valid_config(config_path, "Alpha"), 0);
    CHECK_EQ_INT(path_join(hint, sizeof(hint), config_dir, ".resume-hint"), 0);
    CHECK_EQ_INT(write_text(hint, "malformed-without-newline", 0600), 0);
    CHECK_EQ_INT(read_text(hint, before, sizeof(before)), 0);
    save_environment(&saved);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init_names(&ctx), 0);
    CHECK_EQ_INT(ctx.account_count, 2);
    CHECK_EQ_INT(read_text(hint, after, sizeof(after)), 0);
    CHECK_STR_EQ(after, before);
    memset(&ctx, 0, sizeof(ctx));
    clear_error();
    CHECK_EQ_INT(config_init_readonly(&ctx), -1);

    CHECK_EQ_INT(write_valid_config(config_path, "-unsafe"), 0);
    memset(&ctx, 0, sizeof(ctx));
    clear_error();
    CHECK_EQ_INT(config_init_names(&ctx), -1);
    restore_environment(&saved);
}

TEST(cli_names_grammar_is_noncreating_nonrepairing_and_runtime_free) {
    char root[PATH_MAX], fresh_home[PATH_MAX], fresh_runtime[PATH_MAX];
    char loose_home[PATH_MAX], loose_runtime[PATH_MAX], dot_config[PATH_MAX];
    char loose_dir[PATH_MAX], output[8192];
    struct stat before, after;
    const char *const names_argv[] = {"gitswitch", "--names", "list", NULL};
    const char *const invalid_argv[] = {
        "gitswitch", "list", "--", "--names", NULL
    };

    snprintf(root, sizeof(root), "/tmp/gitswitch-ar07-completion-cli.XXXXXX");
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(path_join(fresh_home, sizeof(fresh_home), root, "fresh-home"), 0);
    CHECK_EQ_INT(path_join(fresh_runtime, sizeof(fresh_runtime), root,
                           "fresh-runtime"), 0);
    CHECK_EQ_INT(mkdir(fresh_home, 0700), 0);
    CHECK_EQ_INT(mkdir(fresh_runtime, 0700), 0);
    CHECK_EQ_INT(run_cli(fresh_home, fresh_runtime, names_argv, true,
                         output, sizeof(output)), 0);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(path_join(dot_config, sizeof(dot_config), fresh_home,
                           ".config"), 0);
    CHECK(access(dot_config, F_OK) != 0);
    CHECK(directory_empty(fresh_runtime));

    CHECK_EQ_INT(run_cli(fresh_home, fresh_runtime, invalid_argv, false,
                         output, sizeof(output)), EXIT_FAILURE);
    CHECK(access(dot_config, F_OK) != 0);

    CHECK_EQ_INT(path_join(loose_home, sizeof(loose_home), root, "loose-home"), 0);
    CHECK_EQ_INT(path_join(loose_runtime, sizeof(loose_runtime), root,
                           "loose-runtime"), 0);
    CHECK_EQ_INT(mkdir(loose_home, 0700), 0);
    CHECK_EQ_INT(mkdir(loose_runtime, 0700), 0);
    CHECK_EQ_INT(path_join(dot_config, sizeof(dot_config), loose_home,
                           ".config"), 0);
    CHECK_EQ_INT(mkdir(dot_config, 0755), 0);
    CHECK_EQ_INT(path_join(loose_dir, sizeof(loose_dir), dot_config,
                           "gitswitch"), 0);
    CHECK_EQ_INT(mkdir(loose_dir, 0755), 0);
    CHECK_EQ_INT(stat(loose_dir, &before), 0);
    CHECK_EQ_INT(run_cli(loose_home, loose_runtime, names_argv, false,
                         output, sizeof(output)), 0);
    CHECK_EQ_INT(stat(loose_dir, &after), 0);
    CHECK_EQ_INT(before.st_mode & 0777, after.st_mode & 0777);
    CHECK(directory_empty(loose_dir));
    CHECK(directory_empty(loose_runtime));
}

TEST(cli_names_permutations_match_and_switch_is_reserved) {
    char root[PATH_MAX], home[PATH_MAX], runtime[PATH_MAX];
    char config_dir[PATH_MAX], config_path[PATH_MAX], output[8192];
    const char *const cases[][7] = {
        {"gitswitch", "--names", "list", NULL},
        {"gitswitch", "list", "--names", NULL},
        {"gitswitch", "--names", "ls", NULL},
        {"gitswitch", "-g", "list", "--names", NULL},
        {"gitswitch", "--names", "--", "list", NULL}
    };

    CHECK_EQ_INT(make_home_fixture(root, sizeof(root), home, sizeof(home),
                                   runtime, sizeof(runtime), config_dir,
                                   sizeof(config_dir), config_path,
                                   sizeof(config_path)), 0);
    CHECK_EQ_INT(write_valid_config(config_path, NULL), 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool posixly = i == 0;
        CHECK_EQ_INT(run_cli(home, runtime, cases[i], posixly,
                             output, sizeof(output)), 0);
        CHECK_STR_EQ(output, "Alpha\nBeta Space\n");
        CHECK(directory_empty(runtime));
    }
    CHECK(name_is_reserved_for_commands("switch"));
    CHECK(name_is_reserved_for_commands("SWITCH"));
    CHECK(!name_is_reserved_for_commands("switch-work"));
}

TEST_MAIN_BEGIN()
    if (!getcwd(g_root, sizeof(g_root)) ||
        path_join(g_binary, sizeof(g_binary), g_root,
                  "build/bin/gitswitch") != 0 ||
        setenv("GS_T16_ROOT", g_root, 1) != 0 ||
        error_init(LOG_LEVEL_WARNING, NULL) != 0) {
        fprintf(stderr, "RESULT FAIL: T16 test setup failed\n");
        return 1;
    }
    RUN_TEST(completion_surfaces_are_exact_and_hidden_options_stay_hidden);
    RUN_TEST(bash_completion_executes_getopt_style_operand_state);
    RUN_TEST(zsh_completion_executes_runtime_expansion_and_state_scanner);
    RUN_TEST(fish_completion_executes_getopt_style_operand_state);
    RUN_TEST(names_loader_preserves_account_admission_without_runtime_work);
    RUN_TEST(names_loader_validates_toml_but_ignores_external_active_artifact);
    RUN_TEST(cli_names_grammar_is_noncreating_nonrepairing_and_runtime_free);
    RUN_TEST(cli_names_permutations_match_and_switch_is_reserved);
    error_cleanup();
TEST_MAIN_END()
