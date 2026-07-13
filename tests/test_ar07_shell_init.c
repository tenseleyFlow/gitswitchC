/* AR-07 T15: parent-shell refresh, resume liveness, and support-matrix tests.
 *
 * Most cases execute the production CLI in a private HOME/XDG_RUNTIME_DIR.
 * The test binary also has one deliberately tiny helper mode which leaves a
 * bound AF_UNIX socket node behind.  The generated wrappers use `test -S`, so
 * this lets a child shell source the snippet before any runtime exists and
 * then make the runtime appear only when its fake `gitswitch switch` runs. */

#include "test.h"
#include "accounts.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef enum {
    SHELL_POSIX = 0,
    SHELL_FISH
} shell_flavor_t;

typedef struct {
    const char *name;
    shell_flavor_t flavor;
} shell_spec_t;

static const shell_spec_t g_shells[] = {
    {"bash", SHELL_POSIX},
    {"zsh", SHELL_POSIX},
    {"fish", SHELL_FISH},
    {"sh", SHELL_POSIX},
    {"dash", SHELL_POSIX},
    {"ksh", SHELL_POSIX},
};

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char shims[PATH_MAX];
    char hint[PATH_MAX];
    char resume_log[PATH_MAX];
    char argv_log[PATH_MAX];
    char auth_sock[PATH_MAX];
    char gpg_current[PATH_MAX];
    char snippets[sizeof(g_shells) / sizeof(g_shells[0])][PATH_MAX];
} shell_fixture_t;

static char g_bin[PATH_MAX];
static char g_self[PATH_MAX];
static shell_fixture_t g_fixture;

static int test_join_path(char *dest, size_t size, const char *base,
                          const char *suffix) {
    size_t base_length = strlen(base);
    size_t suffix_length = strlen(suffix);

    if (base_length + suffix_length + 1U > size) return -1;
    memcpy(dest, base, base_length);
    memcpy(dest + base_length, suffix, suffix_length + 1U);
    return 0;
}

#define join_path test_join_path

static int mkdir_private(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    return chmod(path, 0700);
}

static int write_text(const char *path, const char *text, mode_t mode) {
    FILE *file = fopen(path, "w");

    if (!file) return -1;
    if (fputs(text, file) == EOF || fclose(file) != 0) return -1;
    return chmod(path, mode);
}

static int write_bytes(const char *path, const void *bytes, size_t length,
                       mode_t mode) {
    const unsigned char *cursor = bytes;
    size_t total = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, cursor + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (fchmod(fd, mode) != 0) { close(fd); return -1; }
    return close(fd);
}

static const char *read_text(const char *path, char *text, size_t size) {
    FILE *file;
    size_t used;

    if (!text || size == 0) return "";
    text[0] = '\0';
    file = fopen(path, "r");
    if (!file) return text;
    used = fread(text, 1, size - 1U, file);
    text[used] = '\0';
    fclose(file);
    return text;
}

static int run_shell(const char *command) {
    int status = system(command);

    if (status == -1) return -1;
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    }
    return WEXITSTATUS(status);
}

static int run_shell_bounded(const char *command, long timeout_ms) {
    struct timespec start;
    struct timespec now;
    struct timespec pause = {0, 10000000L};
    pid_t child = fork();
    int status = 0;

    if (child < 0) return -1;
    if (child == 0) {
        (void)setpgid(0, 0);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(child, child);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) goto timeout;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) return -1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) goto timeout;
        long elapsed = (now.tv_sec - start.tv_sec) * 1000L +
                       (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed >= timeout_ms) goto timeout;
        (void)nanosleep(&pause, NULL);
    }
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    }
    return WEXITSTATUS(status);

timeout:
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return -2;
}

static int make_socket_node(const char *path) {
    struct sockaddr_un address;
    int fd;

    if (!path || strlen(path) >= sizeof(address.sun_path)) return -1;
    (void)unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0) {
        int saved_errno = errno;
        close(fd);
        unlink(path);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int resolve_executable(const char *name, char *path, size_t size) {
    static const char *const prefixes[] = {
        "/usr/bin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/"
    };
    size_t i;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        int written = snprintf(path, size, "%s%s", prefixes[i], name);
        if (written >= 0 && (size_t)written < size && access(path, X_OK) == 0) {
            return 0;
        }
    }
    path[0] = '\0';
    return -1;
}

static int shell_index(const char *name) {
    size_t i;

    for (i = 0; i < sizeof(g_shells) / sizeof(g_shells[0]); i++) {
        if (strcmp(g_shells[i].name, name) == 0) return (int)i;
    }
    return -1;
}

static int resolve_binary_and_self(const char *argv0) {
    const char *binary = getenv("GITSWITCH_BIN");

    if (!binary || !*binary) binary = "build/bin/gitswitch";
    if (!realpath(binary, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_ar07_shell_init: executable not found at %s\n",
                binary);
        return -1;
    }
    if (!argv0 || !realpath(argv0, g_self) || access(g_self, X_OK) != 0) {
        fprintf(stderr, "test_ar07_shell_init: cannot resolve self helper\n");
        return -1;
    }
    return 0;
}

static int generate_snippet(shell_fixture_t *fixture, size_t index) {
    char command[PATH_MAX * 5];
    int written;

    written = snprintf(command, sizeof(command),
                       "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' init '%s' "
                       ">'%s' 2>/dev/null",
                       fixture->home, fixture->runtime, g_bin,
                       g_shells[index].name, fixture->snippets[index]);
    if (written < 0 || (size_t)written >= sizeof(command)) return -1;
    return run_shell(command);
}

static int fixture_setup(shell_fixture_t *fixture) {
    static const char ssh_add_shim[] =
        "#!/bin/sh\n"
        "exit \"${GS_SSH_RC:-2}\"\n";
    static const char gitswitch_shim[] =
        "#!/bin/sh\n"
        "if [ \"${GS_CAPTURE_ARGS-0}\" = 1 ] && [ -n \"${GS_ARGV_LOG-}\" ]; then\n"
        "    for GS_ARG do printf 'arg=<%s>\\n' \"$GS_ARG\" >>\"$GS_ARGV_LOG\"; done\n"
        "fi\n"
        "case ${1-} in\n"
        "    --resume-hint-probe) exec \"$GS_REAL_BIN\" \"$@\" ;;\n"
        "    --resume-check) exit \"${GS_CHECK_RC:-1}\" ;;\n"
        "    resume) printf 'resume\\n' >>\"$GS_RESUME_LOG\"; exit 0 ;;\n"
        "    fail) exit 23 ;;\n"
        "    switch)\n"
        "        umask 077\n"
        "        mkdir -p \"${GS_SOCK%/*}\" \"${GS_GPG%/*}\" || exit 24\n"
        "        \"$GS_HELPER\" --make-socket \"$GS_SOCK\" || exit 25\n"
        "        mkdir -p \"$GS_GPG\" || exit 26 ;;\n"
        "    reset|remove|rm|delete)\n"
        "        rm -f \"$GS_SOCK\"\n"
        "        rm -rf \"$GS_GPG\" ;;\n"
        "esac\n"
        "exit 0\n";
    char path[PATH_MAX];
    size_t i;

    memset(fixture, 0, sizeof(*fixture));
    if ((size_t)snprintf(fixture->root, sizeof(fixture->root),
                         "/tmp/gitswitch-ar07-shell.XXXXXX") >=
            sizeof(fixture->root) ||
        !ts_mkdtemp(fixture->root)) {
        return -1;
    }
    if (join_path(fixture->home, sizeof(fixture->home), fixture->root,
                  "/home") != 0 ||
        join_path(fixture->runtime, sizeof(fixture->runtime), fixture->root,
                  "/runtime") != 0 ||
        mkdir_private(fixture->home) != 0 ||
        mkdir_private(fixture->runtime) != 0) {
        return -1;
    }
    if (join_path(path, sizeof(path), fixture->home, "/.config") != 0 ||
        mkdir_private(path) != 0 ||
        join_path(path, sizeof(path), fixture->home,
                  "/.config/gitswitch") != 0 ||
        mkdir_private(path) != 0 ||
        join_path(fixture->hint, sizeof(fixture->hint), path,
                  "/.resume-hint") != 0 ||
        join_path(fixture->shims, sizeof(fixture->shims), fixture->root,
                  "/shims") != 0 ||
        mkdir_private(fixture->shims) != 0 ||
        join_path(fixture->resume_log, sizeof(fixture->resume_log),
                  fixture->root, "/resume.log") != 0 ||
        join_path(fixture->argv_log, sizeof(fixture->argv_log), fixture->root,
                  "/argv.log") != 0 ||
        join_path(fixture->auth_sock, sizeof(fixture->auth_sock),
                  fixture->runtime, "/gitswitch-ssh/current.sock") != 0 ||
        join_path(fixture->gpg_current, sizeof(fixture->gpg_current),
                  fixture->runtime, "/gitswitch-gpg/current") != 0) {
        return -1;
    }
    if (join_path(path, sizeof(path), fixture->shims, "/ssh-add") != 0 ||
        write_text(path, ssh_add_shim, 0700) != 0 ||
        join_path(path, sizeof(path), fixture->shims, "/gitswitch") != 0 ||
        write_text(path, gitswitch_shim, 0700) != 0) {
        return -1;
    }

    for (i = 0; i < sizeof(g_shells) / sizeof(g_shells[0]); i++) {
        int written = snprintf(fixture->snippets[i],
                               sizeof(fixture->snippets[i]), "%s/init-%s",
                               fixture->root, g_shells[i].name);
        if (written < 0 ||
            (size_t)written >= sizeof(fixture->snippets[i]) ||
            generate_snippet(fixture, i) != 0) {
            return -1;
        }
    }
    return 0;
}

static void clear_managed_runtime(shell_fixture_t *fixture) {
    char path[PATH_MAX];

    unlink(fixture->auth_sock);
    if (join_path(path, sizeof(path), fixture->runtime,
                  "/gitswitch-ssh") == 0) {
        ts_rm_rf(path);
    }
    if (join_path(path, sizeof(path), fixture->runtime,
                  "/gitswitch-gpg") == 0) {
        ts_rm_rf(path);
    }
    unlink(fixture->resume_log);
    unlink(fixture->argv_log);
}

static int count_resume_calls(const char *path) {
    char contents[1024];
    const char *cursor;
    int count = 0;

    read_text(path, contents, sizeof(contents));
    for (cursor = contents; *cursor; cursor++) {
        if (*cursor == '\n') count++;
    }
    return count;
}

static int set_gpg_live(shell_fixture_t *fixture, bool live) {
    char base[PATH_MAX];

    if (join_path(base, sizeof(base), fixture->runtime,
                  "/gitswitch-gpg") != 0) {
        return -1;
    }
    ts_rm_rf(base);
    if (!live) return 0;
    return mkdir_private(base) == 0 && mkdir_private(fixture->gpg_current) == 0
               ? 0
               : -1;
}

static int evaluate_current_hint(size_t shell, int ssh_rc, int check_rc,
                                 bool gpg_live, bool bounded) {
    char shell_path[PATH_MAX];
    char command[PATH_MAX * 10];
    const char *flags;
    const char *source_word;
    int written;

    if (resolve_executable(g_shells[shell].name, shell_path,
                           sizeof(shell_path)) != 0) {
        return -2;
    }
    clear_managed_runtime(&g_fixture);
    if (set_gpg_live(&g_fixture, gpg_live) != 0) {
        return -1;
    }

    if (g_shells[shell].flavor == SHELL_FISH) {
        flags = "--no-config -ic";
        source_word = "source";
    } else if (strcmp(g_shells[shell].name, "bash") == 0) {
        flags = "--noprofile --norc -ic";
        source_word = ".";
    } else if (strcmp(g_shells[shell].name, "zsh") == 0) {
        flags = "-f -ic";
        source_word = ".";
    } else {
        flags = "-ic";
        source_word = ".";
    }
    written = snprintf(
        command, sizeof(command),
        "env HOME='%s' XDG_RUNTIME_DIR='%s' ENV=/dev/null "
        "PATH='%s:/usr/bin:/bin' GS_SSH_RC=%d GS_CHECK_RC=%d "
        "GS_RESUME_LOG='%s' GS_ARGV_LOG='%s' GS_HELPER='%s' "
        "GS_SOCK='%s' GS_GPG='%s' GS_REAL_BIN='%s' "
        "'%s' %s \"%s '%s'\" "
        ">/dev/null 2>&1",
        g_fixture.home, g_fixture.runtime, g_fixture.shims, ssh_rc, check_rc,
        g_fixture.resume_log, g_fixture.argv_log, g_self,
        g_fixture.auth_sock, g_fixture.gpg_current, g_bin, shell_path,
        flags, source_word, g_fixture.snippets[shell]);
    if (written < 0 || (size_t)written >= sizeof(command)) {
        return -1;
    }
    if ((bounded ? run_shell_bounded(command, 1500L) : run_shell(command)) != 0)
        return -1;
    return count_resume_calls(g_fixture.resume_log);
}

static int evaluate_resume_case(size_t shell, const char *hint, int ssh_rc,
                                int check_rc, bool gpg_live) {
    char hint_body[64];

    if (snprintf(hint_body, sizeof(hint_body), "%s\n", hint) < 0 ||
        write_text(g_fixture.hint, hint_body, 0600) != 0) {
        return -1;
    }
    return evaluate_current_hint(shell, ssh_rc, check_rc, gpg_live, false);
}

static int run_wrapper_script(bool fish, const char *script,
                              const char *kind) {
    char shell_path[PATH_MAX];
    char command[PATH_MAX * 12];
    const char *shell_name = fish ? "fish" : "sh";
    int snippet_index = shell_index(shell_name);
    int written;

    if (snippet_index < 0 ||
        resolve_executable(shell_name, shell_path, sizeof(shell_path)) != 0) {
        return -2;
    }
    clear_managed_runtime(&g_fixture);
    if (strcmp(kind, "unset") == 0) {
        written = snprintf(
            command, sizeof(command),
            "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
            "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' ENV=/dev/null "
            "GS_KIND=unset GS_SNIPPET='%s' GS_HELPER='%s' GS_SOCK='%s' "
            "GS_GPG='%s' GS_RESUME_LOG='%s' GS_ARGV_LOG='%s' "
            "GS_REAL_BIN='%s' '%s' %s '%s'",
            g_fixture.home, g_fixture.runtime, g_fixture.shims,
            g_fixture.snippets[snippet_index], g_self, g_fixture.auth_sock,
            g_fixture.gpg_current, g_fixture.resume_log, g_fixture.argv_log,
            g_bin, shell_path, fish ? "--no-config" : "", script);
    } else {
        const char *value = strcmp(kind, "empty") == 0 ? "" : "/foreign/value";
        written = snprintf(
            command, sizeof(command),
            "env SSH_AUTH_SOCK='%s' GNUPGHOME='%s' HOME='%s' "
            "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' ENV=/dev/null "
            "GS_KIND='%s' GS_SNIPPET='%s' GS_HELPER='%s' GS_SOCK='%s' "
            "GS_GPG='%s' GS_RESUME_LOG='%s' GS_ARGV_LOG='%s' "
            "GS_REAL_BIN='%s' '%s' %s '%s'",
            value, value, g_fixture.home, g_fixture.runtime, g_fixture.shims,
            kind, g_fixture.snippets[snippet_index], g_self,
            g_fixture.auth_sock, g_fixture.gpg_current, g_fixture.resume_log,
            g_fixture.argv_log, g_bin, shell_path,
            fish ? "--no-config" : "", script);
    }
    if (written < 0 || (size_t)written >= sizeof(command)) return -1;
    return run_shell(command);
}

static int run_external(const char *const argv[], const char *const env[],
                        char *output, size_t output_size) {
    run_opts_t options;
    run_result_t result;

    memset(&options, 0, sizeof(options));
    options.out = output;
    options.out_size = output_size;
    options.stderr_to_devnull = true;
    options.extra_env = env;
    if (output && output_size > 0) output[0] = '\0';
    return run_argv(argv, &options, &result);
}

static pid_t parse_agent_pid(const char *text) {
    const char *marker = strstr(text, "SSH_AGENT_PID=");
    char *end = NULL;
    long value;

    if (!marker) return -1;
    marker += strlen("SSH_AGENT_PID=");
    errno = 0;
    value = strtol(marker, &end, 10);
    if (errno != 0 || end == marker || value <= 1 || value > INT_MAX) return -1;
    return (pid_t)value;
}

static int generate_key(const char *path) {
    const char *argv[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path, NULL
    };
    char output[2048];

    return run_external(argv, NULL, output, sizeof(output));
}

static int agent_command(const char *socket_path, const char *arg) {
    char environment[PATH_MAX + 32];
    const char *env[] = {environment, NULL};
    const char *argv[] = {"ssh-add", arg, NULL};
    char output[2048];

    if ((size_t)snprintf(environment, sizeof(environment),
                         "SSH_AUTH_SOCK=%s", socket_path) >=
        sizeof(environment)) {
        return -1;
    }
    return run_external(argv, env, output, sizeof(output));
}

TEST(help_and_init_share_the_exact_six_shell_matrix) {
    static const char expected[] = "bash|zsh|fish|sh|dash|ksh";
    char help[PATH_MAX];
    char contents[32768];
    char command[PATH_MAX * 3];
    size_t i;

    CHECK_EQ_INT(join_path(help, sizeof(help), g_fixture.root, "/help.out"), 0);
    snprintf(command, sizeof(command), "'%s' --help >'%s' 2>/dev/null",
             g_bin, help);
    CHECK_EQ_INT(run_shell(command), 0);
    read_text(help, contents, sizeof(contents));
    CHECK(strstr(contents, expected) != NULL);

    for (i = 0; i < sizeof(g_shells) / sizeof(g_shells[0]); i++) {
        read_text(g_fixture.snippets[i], contents, sizeof(contents));
        CHECK(contents[0] != '\0');
        CHECK(strstr(contents, g_shells[i].name) != NULL);
    }
}

TEST(generated_snippets_use_only_the_bounded_resume_hint_probe) {
    char contents[32768];

    for (size_t i = 0; i < sizeof(g_shells) / sizeof(g_shells[0]); i++) {
        read_text(g_fixture.snippets[i], contents, sizeof(contents));
        CHECK(strstr(contents, "command gitswitch --resume-hint-probe") != NULL);
        CHECK(strstr(contents, ".resume-hint") == NULL);
        CHECK(strstr(contents, "read -r __gitswitch_needs") == NULL);
        CHECK(strstr(contents, "read -l __gitswitch_needs") == NULL);
    }
}

static int run_resume_hint_probe(char *output, size_t output_size) {
    char output_path[PATH_MAX];
    char command[PATH_MAX * 5];
    int written;
    int status;

    if (join_path(output_path, sizeof(output_path), g_fixture.root,
                  "/probe.out") != 0) return -1;
    written = snprintf(command, sizeof(command),
                       "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' "
                       "--resume-hint-probe >'%s' 2>/dev/null",
                       g_fixture.home, g_fixture.runtime, g_bin, output_path);
    if (written < 0 || (size_t)written >= sizeof(command)) return -1;
    status = run_shell_bounded(command, 1500L);
    read_text(output_path, output, output_size);
    unlink(output_path);
    return status;
}

TEST(resume_hint_probe_accepts_only_safe_exact_artifacts) {
    static const struct {
        const char *body;
        const char *expected;
    } valid[] = {
        {"none\ninactive=v1\n", "none\n"},
        {"ssh\nactive=work\n", "ssh\n"},
        {"gpg\nactive=work\n", "gpg\n"},
        {"ssh gpg\nactive=work\n", "ssh gpg\n"},
        {"ssh\n", "ssh\n"},
        {"gpg\n", "gpg\n"}
    };
    static const unsigned char with_nul[] = {
        's', 's', 'h', '\n', 'a', 'c', 't', 'i', 'v', 'e', '=',
        'w', 'o', 'r', 'k', '\0', '\n'
    };
    char target[PATH_MAX];
    char output[256];
    char oversized[1026];

    unlink(g_fixture.hint);
    CHECK_EQ_INT(run_resume_hint_probe(output, sizeof(output)), 0);
    CHECK_STR_EQ(output, "none\n");
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        CHECK_EQ_INT(write_text(g_fixture.hint, valid[i].body, 0600), 0);
        CHECK_EQ_INT(run_resume_hint_probe(output, sizeof(output)), 0);
        CHECK_STR_EQ(output, valid[i].expected);
    }
    CHECK_EQ_INT(write_text(g_fixture.hint, "", 0600), 0);
    CHECK_EQ_INT(run_resume_hint_probe(output, sizeof(output)), 0);
    CHECK_STR_EQ(output, "ssh gpg\n");

    CHECK_EQ_INT(write_text(g_fixture.hint, "ssh", 0600), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(write_text(g_fixture.hint,
                            "ssh\nactive=work\ntrailing\n", 0600), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(write_bytes(g_fixture.hint, with_nul, sizeof(with_nul),
                             0600), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    memset(oversized, 'x', sizeof(oversized));
    CHECK_EQ_INT(write_bytes(g_fixture.hint, oversized, sizeof(oversized),
                             0600), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    CHECK_EQ_INT(write_text(g_fixture.hint, "ssh\n", 0644), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");

    CHECK_EQ_INT(join_path(target, sizeof(target), g_fixture.root,
                           "/hint-target"), 0);
    unlink(g_fixture.hint);
    CHECK_EQ_INT(write_text(target, "ssh\n", 0600), 0);
    CHECK_EQ_INT(link(target, g_fixture.hint), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    unlink(g_fixture.hint);
    CHECK_EQ_INT(symlink(target, g_fixture.hint), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    unlink(g_fixture.hint);
    CHECK_EQ_INT(mkfifo(g_fixture.hint, 0600), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    unlink(g_fixture.hint);
    CHECK_EQ_INT(make_socket_node(g_fixture.hint), 0);
    CHECK(run_resume_hint_probe(output, sizeof(output)) != 0);
    CHECK_STR_EQ(output, "");
    unlink(g_fixture.hint);
    unlink(target);
}

TEST(resume_hint_probe_is_noncreating_and_rejects_other_grammar) {
    char home[PATH_MAX];
    char config_dir[PATH_MAX];
    char output_path[PATH_MAX];
    char command[PATH_MAX * 5];
    char output[256];
    int written;

    CHECK_EQ_INT(join_path(home, sizeof(home), g_fixture.root,
                           "/fresh-probe-home"), 0);
    CHECK_EQ_INT(join_path(config_dir, sizeof(config_dir), home,
                           "/.config"), 0);
    CHECK_EQ_INT(join_path(output_path, sizeof(output_path), g_fixture.root,
                           "/fresh-probe.out"), 0);
    CHECK_EQ_INT(mkdir_private(home), 0);

    written = snprintf(command, sizeof(command),
                       "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' "
                       "--resume-hint-probe >'%s' 2>/dev/null",
                       home, g_fixture.runtime, g_bin, output_path);
    CHECK(written >= 0 && (size_t)written < sizeof(command));
    CHECK_EQ_INT(run_shell_bounded(command, 1500L), 0);
    CHECK_STR_EQ(read_text(output_path, output, sizeof(output)), "none\n");
    CHECK(access(config_dir, F_OK) != 0 && errno == ENOENT);

    written = snprintf(command, sizeof(command),
                       "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' "
                       "--resume-hint-probe unexpected >'%s' 2>/dev/null",
                       home, g_fixture.runtime, g_bin, output_path);
    CHECK(written >= 0 && (size_t)written < sizeof(command));
    CHECK(run_shell_bounded(command, 1500L) != 0);
    CHECK_STR_EQ(read_text(output_path, output, sizeof(output)), "");
    CHECK(access(config_dir, F_OK) != 0 && errno == ENOENT);

    written = snprintf(command, sizeof(command),
                       "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' "
                       "--resume-hint-probe --resume-check >'%s' 2>/dev/null",
                       home, g_fixture.runtime, g_bin, output_path);
    CHECK(written >= 0 && (size_t)written < sizeof(command));
    CHECK(run_shell_bounded(command, 1500L) != 0);
    CHECK_STR_EQ(read_text(output_path, output, sizeof(output)), "");
    CHECK(access(config_dir, F_OK) != 0 && errno == ENOENT);
}

static void check_generated_syntax_for_shell(size_t index) {
    char shell_path[PATH_MAX];
    char command[PATH_MAX * 3];
    int resolved;

    resolved = resolve_executable(g_shells[index].name, shell_path,
                                  sizeof(shell_path));
    CHECK_EQ_INT(resolved, 0);
    if (resolved != 0) return;
    int written = snprintf(
        command, sizeof(command), "'%s' %s -n '%s' >/dev/null 2>&1",
        shell_path,
        strcmp(g_shells[index].name, "bash") == 0 ? "--noprofile --norc" :
        strcmp(g_shells[index].name, "zsh") == 0 ? "-f" :
        strcmp(g_shells[index].name, "fish") == 0 ? "--no-config" : "",
        g_fixture.snippets[index]);
    CHECK(written >= 0 && (size_t)written < sizeof(command));
    if (written >= 0 && (size_t)written < sizeof(command)) {
        CHECK_EQ_INT(run_shell(command), 0);
    }
}

static void check_resume_matrix_for_shell(size_t index) {
    CHECK_EQ_INT(evaluate_resume_case(index, "ssh", 1, 0, false), 1);
    CHECK_EQ_INT(evaluate_resume_case(index, "ssh", 0, 1, false), 1);
    CHECK_EQ_INT(evaluate_resume_case(index, "ssh", 0, 1, false), 1);
    CHECK_EQ_INT(evaluate_resume_case(index, "ssh", 0, 0, false), 0);
    CHECK_EQ_INT(evaluate_resume_case(index, "ssh", 2, 0, false), 1);
}

static void check_combined_runtime_misses_for_shell(const char *shell) {
    int index = shell_index(shell);

    CHECK(index >= 0);
    if (index < 0) return;
    CHECK_EQ_INT(evaluate_resume_case((size_t)index, "ssh gpg", 0, 0,
                                      true), 0);
    CHECK_EQ_INT(evaluate_resume_case((size_t)index, "ssh gpg", 0, 0,
                                      false), 1);
    CHECK_EQ_INT(evaluate_resume_case((size_t)index, "ssh gpg", 1, 0,
                                      true), 1);
    CHECK_EQ_INT(evaluate_resume_case((size_t)index, "ssh gpg", 1, 0,
                                      false), 1);
}

static void check_invalid_hints_for_shell(const char *shell) {
    char target[PATH_MAX];
    char oversized[1026];
    int index = shell_index(shell);

    CHECK(index >= 0);
    if (index < 0) return;
    CHECK_EQ_INT(join_path(target, sizeof(target), g_fixture.root,
                           "/shell-hint-target"), 0);
    memset(oversized, 'x', sizeof(oversized));
    CHECK_EQ_INT(write_text(g_fixture.hint,
                            "ssh\nactive=work\n", 0600), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 1);

    unlink(g_fixture.hint);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    CHECK_EQ_INT(write_text(g_fixture.hint, "ssh", 0600), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    CHECK_EQ_INT(write_bytes(g_fixture.hint, oversized,
                             sizeof(oversized), 0600), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    CHECK_EQ_INT(write_text(g_fixture.hint, "ssh\n", 0644), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);

    unlink(g_fixture.hint);
    unlink(target);
    CHECK_EQ_INT(write_text(target, "ssh\n", 0600), 0);
    CHECK_EQ_INT(link(target, g_fixture.hint), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    unlink(g_fixture.hint);
    CHECK_EQ_INT(symlink(target, g_fixture.hint), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    unlink(g_fixture.hint);
    CHECK_EQ_INT(mkfifo(g_fixture.hint, 0600), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    unlink(g_fixture.hint);
    CHECK_EQ_INT(make_socket_node(g_fixture.hint), 0);
    CHECK_EQ_INT(evaluate_current_hint((size_t)index, 1, 1,
                                       false, true), 0);
    unlink(g_fixture.hint);
    unlink(target);
}

#define REQUIRE_NATIVE_SHELL(shell) do {                                    \
    char ts_shell_path[PATH_MAX];                                           \
    if (resolve_executable((shell), ts_shell_path,                          \
                           sizeof(ts_shell_path)) != 0) {                   \
        TS_SKIP((shell), "native shell executable is unavailable");       \
    }                                                                       \
} while (0)

#define DEFINE_SHELL_MATRIX_TESTS(label, index)                              \
    TEST(label##_generated_syntax) {                                        \
        REQUIRE_NATIVE_SHELL(g_shells[index].name);                         \
        check_generated_syntax_for_shell(index);                            \
    }                                                                       \
    TEST(label##_resume_matrix) {                                           \
        REQUIRE_NATIVE_SHELL(g_shells[index].name);                         \
        check_resume_matrix_for_shell(index);                               \
    }

DEFINE_SHELL_MATRIX_TESTS(bash, 0)
DEFINE_SHELL_MATRIX_TESTS(zsh, 1)
DEFINE_SHELL_MATRIX_TESTS(fish, 2)
DEFINE_SHELL_MATRIX_TESTS(sh, 3)
DEFINE_SHELL_MATRIX_TESTS(dash, 4)
DEFINE_SHELL_MATRIX_TESTS(ksh, 5)
#undef DEFINE_SHELL_MATRIX_TESTS

TEST(sh_combined_runtime_misses) {
    REQUIRE_NATIVE_SHELL("sh");
    check_combined_runtime_misses_for_shell("sh");
}

TEST(fish_combined_runtime_misses) {
    REQUIRE_NATIVE_SHELL("fish");
    check_combined_runtime_misses_for_shell("fish");
}

TEST(sh_invalid_hints_are_bounded) {
    REQUIRE_NATIVE_SHELL("sh");
    check_invalid_hints_for_shell("sh");
}

TEST(fish_invalid_hints_are_bounded) {
    REQUIRE_NATIVE_SHELL("fish");
    check_invalid_hints_for_shell("fish");
}

#undef REQUIRE_NATIVE_SHELL

TEST(posix_source_before_runtime_refreshes_then_restores_prior_ownership) {
    char script[PATH_MAX];
    static const char body[] =
        ". \"$GS_SNIPPET\" || exit 10\n"
        "case $GS_KIND in\n"
        "unset) [ \"${SSH_AUTH_SOCK+x}\" != x ] && [ \"${GNUPGHOME+x}\" != x ] || exit 11 ;;\n"
        "empty) [ \"${SSH_AUTH_SOCK+x}:$SSH_AUTH_SOCK\" = x: ] && [ \"${GNUPGHOME+x}:$GNUPGHOME\" = x: ] || exit 12 ;;\n"
        "foreign) [ \"$SSH_AUTH_SOCK\" = /foreign/value ] && [ \"$GNUPGHOME\" = /foreign/value ] || exit 13 ;;\n"
        "esac\n"
        "gitswitch switch work || exit 14\n"
        "[ \"$SSH_AUTH_SOCK\" = \"$GS_SOCK\" ] || exit 15\n"
        "[ \"$GNUPGHOME\" = \"$GS_GPG\" ] || exit 16\n"
        "gitswitch reset || exit 17\n"
        "case $GS_KIND in\n"
        "unset) [ \"${SSH_AUTH_SOCK+x}\" != x ] && [ \"${GNUPGHOME+x}\" != x ] || exit 18 ;;\n"
        "empty) [ \"${SSH_AUTH_SOCK+x}:$SSH_AUTH_SOCK\" = x: ] && [ \"${GNUPGHOME+x}:$GNUPGHOME\" = x: ] || exit 19 ;;\n"
        "foreign) [ \"$SSH_AUTH_SOCK\" = /foreign/value ] && [ \"$GNUPGHOME\" = /foreign/value ] || exit 20 ;;\n"
        "esac\n";

    CHECK_EQ_INT(join_path(script, sizeof(script), g_fixture.root,
                           "/posix-transition.sh"), 0);
    CHECK_EQ_INT(write_text(script, body, 0600), 0);
    CHECK_EQ_INT(run_wrapper_script(false, script, "unset"), 0);
    CHECK_EQ_INT(run_wrapper_script(false, script, "empty"), 0);
    CHECK_EQ_INT(run_wrapper_script(false, script, "foreign"), 0);
}

TEST(fish_source_before_runtime_refreshes_then_restores_prior_ownership) {
    char fish_path[PATH_MAX];
    char script[PATH_MAX];
    static const char body[] =
        "source \"$GS_SNIPPET\"; or exit 10\n"
        "switch $GS_KIND\n"
        "case unset\n"
        "    not set -q SSH_AUTH_SOCK; and not set -q GNUPGHOME; or exit 11\n"
        "case empty\n"
        "    set -q SSH_AUTH_SOCK; and test -z \"$SSH_AUTH_SOCK\"; and set -q GNUPGHOME; and test -z \"$GNUPGHOME\"; or exit 12\n"
        "case foreign\n"
        "    test \"$SSH_AUTH_SOCK\" = /foreign/value; and test \"$GNUPGHOME\" = /foreign/value; or exit 13\n"
        "end\n"
        "gitswitch switch work; or exit 14\n"
        "test \"$SSH_AUTH_SOCK\" = \"$GS_SOCK\"; or exit 15\n"
        "test \"$GNUPGHOME\" = \"$GS_GPG\"; or exit 16\n"
        "gitswitch reset; or exit 17\n"
        "switch $GS_KIND\n"
        "case unset\n"
        "    not set -q SSH_AUTH_SOCK; and not set -q GNUPGHOME; or exit 18\n"
        "case empty\n"
        "    set -q SSH_AUTH_SOCK; and test -z \"$SSH_AUTH_SOCK\"; and set -q GNUPGHOME; and test -z \"$GNUPGHOME\"; or exit 19\n"
        "case foreign\n"
        "    test \"$SSH_AUTH_SOCK\" = /foreign/value; and test \"$GNUPGHOME\" = /foreign/value; or exit 20\n"
        "end\n";

    if (resolve_executable("fish", fish_path, sizeof(fish_path)) != 0) {
        TS_SKIP("fish", "native fish executable is unavailable");
    }
    CHECK_EQ_INT(join_path(script, sizeof(script), g_fixture.root,
                           "/fish-transition.fish"), 0);
    CHECK_EQ_INT(write_text(script, body, 0600), 0);
    CHECK_EQ_INT(run_wrapper_script(true, script, "unset"), 0);
    CHECK_EQ_INT(run_wrapper_script(true, script, "empty"), 0);
    CHECK_EQ_INT(run_wrapper_script(true, script, "foreign"), 0);
}

TEST(posix_wrapper_preserves_manual_overrides_status_argv_and_neuter_paths) {
    char script[PATH_MAX];
    char contents[1024];
    static const char body[] =
        ". \"$GS_SNIPPET\" || exit 10\n"
        ": >\"$GS_ARGV_LOG\"\n"
        "GS_CAPTURE_ARGS=1; export GS_CAPTURE_ARGS\n"
        "gitswitch switch \"two words\" --local || exit 11\n"
        "unset GS_CAPTURE_ARGS\n"
        "rm -f \"$GS_SOCK\"; rm -rf \"$GS_GPG\"\n"
        "gitswitch --hel || exit 12\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\" ] || exit 13\n"
        "gitswitch --vers || exit 14\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\" ] || exit 15\n"
        "gitswitch --dr reset || exit 16\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\" ] || exit 17\n"
        "SSH_AUTH_SOCK=/manual/socket; GNUPGHOME=/manual/gpg\n"
        "export SSH_AUTH_SOCK GNUPGHOME\n"
        "gitswitch status || exit 18\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg ] || exit 19\n"
        "gitswitch --dry-run reset || exit 20\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg ] || exit 21\n"
        "gitswitch -n switch work || exit 22\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg ] || exit 23\n"
        "gitswitch fail \"arg with spaces\"\n"
        "[ $? -eq 23 ] || exit 24\n"
        "[ \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg ] || exit 25\n";

    CHECK_EQ_INT(join_path(script, sizeof(script), g_fixture.root,
                           "/posix-wrapper.sh"), 0);
    CHECK_EQ_INT(write_text(script, body, 0600), 0);
    CHECK_EQ_INT(run_wrapper_script(false, script, "unset"), 0);
    read_text(g_fixture.argv_log, contents, sizeof(contents));
    CHECK_STR_EQ(contents,
                 "arg=<switch>\narg=<two words>\narg=<--local>\n");
}

TEST(fish_wrapper_preserves_manual_overrides_status_argv_and_neuter_paths) {
    char fish_path[PATH_MAX];
    char script[PATH_MAX];
    char contents[1024];
    static const char body[] =
        "source \"$GS_SNIPPET\"; or exit 10\n"
        ": >\"$GS_ARGV_LOG\"\n"
        "set -gx GS_CAPTURE_ARGS 1\n"
        "gitswitch switch \"two words\" --local; or exit 11\n"
        "set -e GS_CAPTURE_ARGS\n"
        "rm -f \"$GS_SOCK\"; rm -rf \"$GS_GPG\"\n"
        "gitswitch --hel; or exit 12\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\"; or exit 13\n"
        "gitswitch --vers; or exit 14\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\"; or exit 15\n"
        "gitswitch --dr reset; or exit 16\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = \"$GS_SOCK:$GS_GPG\"; or exit 17\n"
        "set -gx SSH_AUTH_SOCK /manual/socket\n"
        "set -gx GNUPGHOME /manual/gpg\n"
        "gitswitch status; or exit 18\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg; or exit 19\n"
        "gitswitch --dry-run reset; or exit 20\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg; or exit 21\n"
        "gitswitch -n switch work; or exit 22\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg; or exit 23\n"
        "gitswitch fail \"arg with spaces\"\n"
        "test $status -eq 23; or exit 24\n"
        "test \"$SSH_AUTH_SOCK:$GNUPGHOME\" = /manual/socket:/manual/gpg; or exit 25\n";

    if (resolve_executable("fish", fish_path, sizeof(fish_path)) != 0) {
        TS_SKIP("fish", "native fish executable is unavailable");
    }
    CHECK_EQ_INT(join_path(script, sizeof(script), g_fixture.root,
                           "/fish-wrapper.fish"), 0);
    CHECK_EQ_INT(write_text(script, body, 0600), 0);
    CHECK_EQ_INT(run_wrapper_script(true, script, "unset"), 0);
    read_text(g_fixture.argv_log, contents, sizeof(contents));
    CHECK_STR_EQ(contents,
                 "arg=<switch>\narg=<two words>\narg=<--local>\n");
}

TEST(real_ssh_liveness_requires_current_account_and_exactly_one_key) {
    char root[PATH_MAX] = "/tmp/gitswitch-ar07-live.XXXXXX";
    char runtime[PATH_MAX];
    char agent_dir[PATH_MAX];
    char agent_sock[PATH_MAX];
    char other_sock[PATH_MAX];
    char current[PATH_MAX];
    char expected_key[PATH_MAX];
    char other_key[PATH_MAX];
    char output[4096];
    char *saved_runtime = NULL;
    const char *old_runtime = getenv("XDG_RUNTIME_DIR");
    const char *agent_argv[] = {"ssh-agent", "-a", agent_sock, "-s", NULL};
    account_t account;
    bool live = true;
    pid_t agent_pid = -1;

    if (resolve_executable("ssh-agent", output, sizeof(output)) != 0 ||
        resolve_executable("ssh-add", output, sizeof(output)) != 0 ||
        resolve_executable("ssh-keygen", output, sizeof(output)) != 0) {
        TS_SKIP("openssh", "OpenSSH test tools are unavailable");
    }
    if (old_runtime) saved_runtime = strdup(old_runtime);
    if (!ts_mkdtemp(root) ||
        join_path(runtime, sizeof(runtime), root, "/runtime") != 0 ||
        join_path(agent_dir, sizeof(agent_dir), runtime,
                  "/gitswitch-ssh") != 0 ||
        join_path(agent_sock, sizeof(agent_sock), agent_dir,
                  "/ssh-agent.work.sock") != 0 ||
        join_path(other_sock, sizeof(other_sock), agent_dir,
                  "/ssh-agent.other.sock") != 0 ||
        join_path(current, sizeof(current), agent_dir, "/current.sock") != 0 ||
        join_path(expected_key, sizeof(expected_key), root, "/expected") != 0 ||
        join_path(other_key, sizeof(other_key), root, "/other") != 0 ||
        mkdir_private(runtime) != 0 || mkdir_private(agent_dir) != 0 ||
        setenv("XDG_RUNTIME_DIR", runtime, 1) != 0) {
        CHECK(!"real SSH liveness fixture setup failed");
        free(saved_runtime);
        ts_rm_rf(root);
        return;
    }
    CHECK_EQ_INT(generate_key(expected_key), 0);
    CHECK_EQ_INT(generate_key(other_key), 0);
    CHECK_EQ_INT(run_external(agent_argv, NULL, output, sizeof(output)), 0);
    agent_pid = parse_agent_pid(output);
    CHECK(agent_pid > 1);
    if (agent_pid <= 1) goto done;

    memset(&account, 0, sizeof(account));
    snprintf(account.name, sizeof(account.name), "work");
    account.ssh_enabled = true;
    snprintf(account.ssh_key_path, sizeof(account.ssh_key_path), "%s",
             expected_key);

    live = true;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(!live);

    CHECK_EQ_INT(make_socket_node(other_sock), 0);
    CHECK_EQ_INT(symlink(other_sock, current), 0);
    live = true;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(!live);
    CHECK_EQ_INT(unlink(current), 0);
    CHECK_EQ_INT(unlink(other_sock), 0);

    CHECK_EQ_INT(symlink(agent_sock, current), 0);
    live = true;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(!live);

    CHECK_EQ_INT(agent_command(agent_sock, other_key), 0);
    live = true;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(!live);

    CHECK_EQ_INT(agent_command(agent_sock, "-D"), 0);
    CHECK_EQ_INT(agent_command(agent_sock, expected_key), 0);
    CHECK_EQ_INT(agent_command(agent_sock, other_key), 0);
    live = true;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(!live);

    CHECK_EQ_INT(agent_command(agent_sock, "-D"), 0);
    CHECK_EQ_INT(agent_command(agent_sock, expected_key), 0);
    live = false;
    CHECK_EQ_INT(ssh_manager_current_is_live_for_account(&account, &live), 0);
    CHECK(live);

done:
    if (agent_pid > 1) {
        CHECK_EQ_INT(kill(agent_pid, SIGTERM), 0);
    }
    if (saved_runtime) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_runtime, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
    free(saved_runtime);
    ts_rm_rf(root);
}

TEST(real_resume_leaves_external_git_configuration_byte_identical) {
    static const char git_config_body[] =
        "[user]\n\tname = Outside Owner\n\temail = outside@example.test\n"
        "[core]\n\tsshCommand = /manual/ssh-wrapper\n"
        "[gpg]\n\tprogram = /manual/gpg-wrapper\n"
        "[commit]\n\tgpgsign = true\n";
    char root[PATH_MAX] = "/tmp/gitswitch-ar07-resume.XXXXXX";
    char home[PATH_MAX];
    char runtime[PATH_MAX];
    char config_dir[PATH_MAX];
    char config_path[PATH_MAX];
    char hint[PATH_MAX];
    char key[PATH_MAX];
    char git_config[PATH_MAX];
    char before[4096];
    char after[4096];
    char config_body[PATH_MAX + 512];
    char command[PATH_MAX * 6];

    if (resolve_executable("ssh-agent", after, sizeof(after)) != 0 ||
        resolve_executable("ssh-add", after, sizeof(after)) != 0 ||
        resolve_executable("ssh-keygen", after, sizeof(after)) != 0) {
        TS_SKIP("openssh", "OpenSSH test tools are unavailable");
    }
    if (!ts_mkdtemp(root)) {
        CHECK(!"real resume root setup failed");
        return;
    }
    if (join_path(home, sizeof(home), root, "/home") != 0 ||
        join_path(runtime, sizeof(runtime), root, "/runtime") != 0 ||
        join_path(config_dir, sizeof(config_dir), home,
                  "/.config") != 0 ||
        mkdir_private(home) != 0 || mkdir_private(runtime) != 0 ||
        mkdir_private(config_dir) != 0 ||
        join_path(config_dir, sizeof(config_dir), home,
                  "/.config/gitswitch") != 0 ||
        mkdir_private(config_dir) != 0 ||
        join_path(config_path, sizeof(config_path), config_dir,
                  "/accounts.toml") != 0 ||
        join_path(hint, sizeof(hint), config_dir, "/.resume-hint") != 0 ||
        join_path(key, sizeof(key), root, "/id_resume") != 0 ||
        join_path(git_config, sizeof(git_config), home, "/.gitconfig") != 0) {
        CHECK(!"real resume fixture setup failed");
        ts_rm_rf(root);
        return;
    }
    CHECK_EQ_INT(generate_key(key), 0);
    snprintf(config_body, sizeof(config_body),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "active_account = \"work\"\n\n"
             "[accounts.1]\n"
             "name = \"work\"\n"
             "email = \"work@example.test\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n",
             key);
    CHECK_EQ_INT(write_text(config_path, config_body, 0600), 0);
    CHECK_EQ_INT(write_text(hint, "ssh\nactive=work\n", 0600), 0);
    CHECK_EQ_INT(write_text(git_config, git_config_body, 0600), 0);
    read_text(git_config, before, sizeof(before));

    snprintf(command, sizeof(command),
             "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
             "XDG_RUNTIME_DIR='%s' PATH='/usr/bin:/bin' "
             "GIT_CONFIG_NOSYSTEM=1 '%s' -C resume >/dev/null 2>&1",
             home, runtime, g_bin);
    CHECK_EQ_INT(run_shell(command), 0);
    read_text(git_config, after, sizeof(after));
    CHECK_STR_EQ(after, before);

    snprintf(command, sizeof(command),
             "env HOME='%s' XDG_RUNTIME_DIR='%s' PATH='/usr/bin:/bin' "
             "GIT_CONFIG_NOSYSTEM=1 '%s' -C -y reset >/dev/null 2>&1",
             home, runtime, g_bin);
    CHECK_EQ_INT(run_shell(command), 0);
    ts_rm_rf(root);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--make-socket") == 0) {
        if (make_socket_node(argv[2]) != 0) {
            perror("test_ar07_shell_init: make socket");
            return 1;
        }
        return 0;
    }
    if (resolve_binary_and_self(argc > 0 ? argv[0] : NULL) != 0) return 1;
    if (error_init(LOG_LEVEL_ERROR, NULL) != 0) return 1;
    if (fixture_setup(&g_fixture) != 0) {
        fprintf(stderr, "test_ar07_shell_init: shared fixture setup failed\n");
        if (g_fixture.root[0] != '\0') ts_rm_rf(g_fixture.root);
        error_cleanup();
        return 1;
    }

    RUN_TEST(help_and_init_share_the_exact_six_shell_matrix);
    RUN_TEST(generated_snippets_use_only_the_bounded_resume_hint_probe);
    RUN_TEST(resume_hint_probe_accepts_only_safe_exact_artifacts);
    RUN_TEST(resume_hint_probe_is_noncreating_and_rejects_other_grammar);
    RUN_TEST(bash_generated_syntax);
    RUN_TEST(bash_resume_matrix);
    RUN_TEST(zsh_generated_syntax);
    RUN_TEST(zsh_resume_matrix);
    RUN_TEST(fish_generated_syntax);
    RUN_TEST(fish_resume_matrix);
    RUN_TEST(sh_generated_syntax);
    RUN_TEST(sh_resume_matrix);
    RUN_TEST(dash_generated_syntax);
    RUN_TEST(dash_resume_matrix);
    RUN_TEST(ksh_generated_syntax);
    RUN_TEST(ksh_resume_matrix);
    RUN_TEST(sh_combined_runtime_misses);
    RUN_TEST(fish_combined_runtime_misses);
    RUN_TEST(sh_invalid_hints_are_bounded);
    RUN_TEST(fish_invalid_hints_are_bounded);
    RUN_TEST(posix_source_before_runtime_refreshes_then_restores_prior_ownership);
    RUN_TEST(fish_source_before_runtime_refreshes_then_restores_prior_ownership);
    RUN_TEST(posix_wrapper_preserves_manual_overrides_status_argv_and_neuter_paths);
    RUN_TEST(fish_wrapper_preserves_manual_overrides_status_argv_and_neuter_paths);
    RUN_TEST(real_ssh_liveness_requires_current_account_and_exactly_one_key);
    RUN_TEST(real_resume_leaves_external_git_configuration_byte_identical);

    ts_rm_rf(g_fixture.root);
    error_cleanup();
    return ts_test_finish();
}
