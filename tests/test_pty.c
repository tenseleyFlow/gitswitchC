/* PTY-driven end-to-end tests for the interactive flows (add/edit/remove/
 * reset). The prompt paths behave differently on a real terminal — readline
 * builds go raw, TAB completion is armed only for the SSH key path prompt,
 * and Ctrl-D must cancel via the readline-NULL / bounded-stdio EOF paths — so
 * these tests give the binary an actual PTY, not a pipe.
 *
 * Dependency-free expect-style driver (no pexpect/expect): pty_spawn() forks
 * the built binary onto a fresh PTY slave inside a throwaway HOME +
 * XDG_RUNTIME_DIR sandbox, pty_expect() drains the master continuously while
 * searching for an anchor substring (so the child can never block on a full
 * PTY buffer), pty_send() types, pty_wait_exit() reaps with a deadline and
 * SIGKILLs on timeout so a hang fails the test instead of wedging `make test`.
 *
 * posix_openpt (not forkpty) keeps this portable without -lutil: it lives in
 * libc on Linux/macOS/FreeBSD alike. */
/* glibc hides the PTY helpers (posix_openpt/grantpt/unlockpt/ptsname) behind
 * X/Open feature macros; _GNU_SOURCE exposes them without hiding anything else.
 * macOS and FreeBSD expose them by default, and defining X/Open macros there
 * would instead HIDE other defaults, so guard this per-platform. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"
#include "prompt.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#endif

/* Generous-but-bounded deadlines: normal turnaround is milliseconds, but the
 * debug build runs under ASan/UBSan on possibly loaded CI machines. */
#define EXPECT_TIMEOUT_MS 10000
#define EXIT_TIMEOUT_MS   15000
#define PTY_STARTUP_PROMPT "GITSWITCH-PTY-READY> "

/* Absolute path to the binary under test (the child chdirs into the sandbox). */
static char g_bin[4096];

/* Set when the environment cannot mint PTYs at all (e.g. /dev/pts unmounted
 * in a minimal container); every test then SKIPs rather than fails. */
static int g_no_pty = 0;

#define SKIP_IF_NO_PTY() do {                                                \
    if (g_no_pty) {                                                          \
        TS_SKIP("pty", "PTY allocation is unavailable");                    \
    }                                                                        \
} while (0)

static int resolve_binary(void) {
    const char *bin = getenv("GITSWITCH_BIN");
    if (!bin || !*bin) {
        bin = "build/bin/gitswitch";
    }
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_pty: gitswitch binary not found/executable at '%s' "
                        "(run via `make test`, or set GITSWITCH_BIN)\n", bin);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- sandbox */

/* Short base paths: XDG_RUNTIME_DIR feeds sun_path (108-byte cap), so the
 * sandbox roots stay tiny. */
static const char *make_temp_dir(char *buf, size_t size) {
    snprintf(buf, size, "/tmp/gswpty-XXXXXX");
    if (!ts_mkdtemp(buf)) {
        return NULL;
    }
    return buf;
}

static void remove_tree(const char *path) {
    char cmd[512];
    if (!path || path[0] == '\0' || strstr(path, "'") != NULL) {
        return;
    }
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        fprintf(stderr, "test_pty: failed to remove %s\n", path);
    }
}

/* Throwaway HOME + XDG_RUNTIME_DIR with a hardened config (0600 file inside
 * 0700 dirs — the T5 checks reject anything looser) and a genuine unencrypted
 * Ed25519 private key. Account load now proves OpenSSH usability, so a
 * shape-only armor fixture would fail before the PTY behavior under test. */
typedef struct {
    char home[128];
    char rt[128];
    char cfg[256];
} sandbox_t;

static int write_file_mode(const char *path, const char *body, mode_t mode) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(body, f);
    if (fclose(f) != 0) return -1;
    return chmod(path, mode);
}

enum {
    SANDBOX_SETUP_ERROR = -1,
    SANDBOX_SETUP_OK = 0,
    SANDBOX_SETUP_OPENSSH_UNAVAILABLE = 1
};

static int generate_ed25519_private_key(const char *path) {
    const char *argv[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path, NULL
    };
    run_opts_t opts;
    run_result_t result;

    if (!command_exists("ssh-keygen")) {
        return SANDBOX_SETUP_OPENSSH_UNAVAILABLE;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    return run_argv_real(argv, &opts, &result) == 0
               ? SANDBOX_SETUP_OK
               : SANDBOX_SETUP_ERROR;
}

static int sandbox_setup(sandbox_t *sb) {
    char path[512];
    char cfg[1024];

    if (!make_temp_dir(sb->home, sizeof(sb->home)) ||
        !make_temp_dir(sb->rt, sizeof(sb->rt))) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s/key_ed25519", sb->home);
    {
        int key_rc = generate_ed25519_private_key(path);
        if (key_rc != SANDBOX_SETUP_OK) return key_rc;
    }

    snprintf(path, sizeof(path), "%s/.config", sb->home);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", sb->home);
    if (mkdir(path, 0700) != 0) return -1;

    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"work\"\n"
             "email = \"w@example.com\"\n"
             "description = \"work account\"\n"
             "ssh_key = \"%s/key_ed25519\"\n"
             "gpg_key = \"ABCDEF0123456789\"\n"
             "\n"
             "[accounts.2]\n"
             "name = \"other\"\n"
             "email = \"o@example.com\"\n"
             "description = \"other account\"\n",
             sb->home);
    snprintf(sb->cfg, sizeof(sb->cfg), "%s/.config/gitswitch/accounts.toml", sb->home);
    return write_file_mode(sb->cfg, cfg, 0600);
}

static void sandbox_teardown(sandbox_t *sb) {
    remove_tree(sb->home);
    remove_tree(sb->rt);
}

#define SETUP_SANDBOX_OR_RETURN(sb) do {                                    \
    int _setup_rc = sandbox_setup(&(sb));                                   \
    if (_setup_rc == SANDBOX_SETUP_OPENSSH_UNAVAILABLE) {                   \
        sandbox_teardown(&(sb));                                            \
        TS_SKIP("openssh", "ssh-keygen unavailable in trusted PATH");       \
    }                                                                       \
    if (_setup_rc != SANDBOX_SETUP_OK) {                                    \
        CHECK(!"sandbox setup failed");                                     \
        sandbox_teardown(&(sb));                                            \
        return;                                                             \
    }                                                                       \
} while (0)

/* Read a whole (small) file; returns length, 0 on any failure. */
static size_t slurp(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n = 0;
    buf[0] = '\0';
    if (!f) return 0;
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

/* ---------------------------------------------------------- PTY driver */

#define PTY_OUT_MAX (64 * 1024)

typedef struct {
    int master;
    pid_t pid;
    bool eof;               /* master hit EOF/EIO (slave side fully closed) */
    size_t out_len;
    size_t scan;            /* cursor so sequential expects match in order */
    char out[PTY_OUT_MAX];
} pty_proc_t;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Opening a PTY slave after setsid() implicitly acquires it as the controlling
 * terminal on Linux, but that side effect is not portable to FreeBSD.  Open
 * without implicit acquisition, then request the controlling terminal
 * explicitly so interactive shells have a valid foreground process group on
 * every supported host. */
static int open_controlling_pty_slave(const char *slave_name) {
    int slave_fd;

    if (setsid() < 0) return -1;
    slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave_fd < 0) return -1;
    if (ioctl(slave_fd, TIOCSCTTY, 0) != 0) {
        close(slave_fd);
        return -1;
    }
    return slave_fd;
}

/* Pull whatever the child has written, waiting at most timeout_ms for the
 * first byte. Returns 1 if data arrived, 0 on timeout, -1 on EOF. Always
 * consumes (the child must never block on a full PTY buffer); if the capture
 * buffer is somehow full the extra bytes are drained and dropped. */
static int pty_drain(pty_proc_t *p, int timeout_ms) {
    struct pollfd pfd = { .fd = p->master, .events = POLLIN };
    char tmp[4096];
    ssize_t n;
    int rv;

    if (p->eof) return -1;

    rv = poll(&pfd, 1, timeout_ms);
    if (rv <= 0) return 0; /* timeout (or EINTR: caller loops on deadline) */

    n = read(p->master, tmp, sizeof(tmp));
    if (n <= 0) {
        /* Linux returns EIO on the master once the slave side is gone. */
        p->eof = true;
        return -1;
    }
    if (p->out_len + (size_t)n < PTY_OUT_MAX) {
        memcpy(p->out + p->out_len, tmp, (size_t)n);
        p->out_len += (size_t)n;
        p->out[p->out_len] = '\0';
    }
    return 1;
}

/* Spawn an arbitrary executable on a fresh PTY inside the sandbox, with a
 * scrubbed environment and $HOME as the CWD. Returns 0, or -1
 * (infrastructure failure). */
static int pty_spawn_exec(pty_proc_t *p, const char *executable,
                          const char *const argv[], const sandbox_t *sb) {
    const char *pts;
    char slave_name[256];

    memset(p, 0, sizeof(*p));
    p->master = posix_openpt(O_RDWR | O_NOCTTY);
    if (p->master < 0 || grantpt(p->master) != 0 || unlockpt(p->master) != 0 ||
        (pts = ptsname(p->master)) == NULL) {
        if (p->master >= 0) close(p->master);
        p->master = -1;
        return -1;
    }
    snprintf(slave_name, sizeof(slave_name), "%s", pts);

    p->pid = fork();
    if (p->pid < 0) {
        close(p->master);
        p->master = -1;
        return -1;
    }
    if (p->pid == 0) {
        int sfd;

        sfd = open_controlling_pty_slave(slave_name);
        if (sfd < 0) _exit(126);
        if (dup2(sfd, STDIN_FILENO) < 0 ||
            dup2(sfd, STDOUT_FILENO) < 0 ||
            dup2(sfd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        if (sfd > STDERR_FILENO) close(sfd);
        close(p->master);

        setenv("HOME", sb->home, 1);
        setenv("XDG_RUNTIME_DIR", sb->rt, 1);
        /* T6 pins helper resolution to trusted absolute PATH dirs. */
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
        setenv("TERM", "dumb", 1); /* keep readline's escape output minimal */
        setenv("PS1", PTY_STARTUP_PROMPT, 1);
        /* No ambient state may leak into the sandboxed run. */
        unsetenv("XDG_CONFIG_HOME");
        unsetenv("GNUPGHOME");
        unsetenv("SSH_AUTH_SOCK");
        /* Neither a user nor system inputrc may rebind TAB/C-u. `/dev/null`
         * makes Readline use its built-in keymap instead of consulting either
         * ambient configuration source. */
        setenv("INPUTRC", "/dev/null", 1);
        unsetenv("PROMPT_COMMAND");
        unsetenv("HISTFILE");
        unsetenv("BASH_ENV");
        unsetenv("ENV");
        unsetenv("BASH_COMPLETION_USER_FILE");
        unsetenv("BASH_COMPLETION_USER_DIR");
        unsetenv("BASH_COMPLETION_COMPAT_DIR");
        unsetenv("BASH_COMPLETION_COMPAT_IGNORE");
        unsetenv("BASH_COMPLETION_DEBUG");
        unsetenv("XDG_DATA_HOME");

        if (chdir(sb->home) != 0) _exit(126);
        execv(executable, (char *const *)argv);
        _exit(127);
    }
    return 0;
}

/* Preserve the production-binary call surface used by every existing test. */
static int pty_spawn(pty_proc_t *p, const char *const argv[],
                     const sandbox_t *sb) {
    return pty_spawn_exec(p, g_bin, argv, sb);
}

/* Wait until `substr` appears in the child's output at/after the current
 * scan cursor, draining continuously. 0 on match (cursor advances past it),
 * -1 on timeout/EOF-without-match (buffer tail dumped for diagnosis). */
static int pty_expect(pty_proc_t *p, const char *substr) {
    long long deadline = now_ms() + EXPECT_TIMEOUT_MS;

    for (;;) {
        const char *hit = strstr(p->out + p->scan, substr);
        if (hit) {
            p->scan = (size_t)(hit - p->out) + strlen(substr);
            return 0;
        }
        long long left = deadline - now_ms();
        if (left <= 0 || pty_drain(p, left > 200 ? 200 : (int)left) < 0) {
            /* EOF: one last scan in case the final read carried the match. */
            hit = strstr(p->out + p->scan, substr);
            if (hit) {
                p->scan = (size_t)(hit - p->out) + strlen(substr);
                return 0;
            }
            if (left <= 0) {
                fprintf(stderr, "  expect timed out waiting for \"%s\"; output:\n"
                                "  ----\n%s\n  ----\n", substr, p->out);
                return -1;
            }
            if (p->eof) {
                fprintf(stderr, "  child EOF before \"%s\"; output:\n"
                                "  ----\n%s\n  ----\n", substr, p->out);
                return -1;
            }
        }
    }
}

/* Type into the child's terminal. */
static int pty_send(pty_proc_t *p, const char *s) {
    size_t len = strlen(s), off = 0;
    while (off < len) {
        ssize_t n = write(p->master, s + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Reap the child, draining output while it winds down. Returns the exit code,
 * or -1 for signal/timeout (the child is SIGKILLed on timeout so a wedged
 * binary fails the test instead of hanging make). */
static int pty_wait_exit(pty_proc_t *p) {
    long long deadline = now_ms() + EXIT_TIMEOUT_MS;
    int status = 0;
    bool exited = false;

    while (now_ms() < deadline) {
        pid_t r = waitpid(p->pid, &status, WNOHANG);
        if (r == p->pid) { exited = true; break; }
        if (r < 0) break;
        pty_drain(p, 100);
    }
    if (!exited) {
        kill(p->pid, SIGKILL);
        waitpid(p->pid, &status, 0);
        fprintf(stderr, "  child hung; killed. output:\n  ----\n%s\n  ----\n", p->out);
        p->pid = -1;
        return -1;
    }
    p->pid = -1;
    /* Collect any output that raced the exit. */
    while (!p->eof && pty_drain(p, 100) > 0) {}
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static void pty_close(pty_proc_t *p) {
    if (p->pid > 0) {
        kill(p->pid, SIGKILL);
        waitpid(p->pid, NULL, 0);
        p->pid = -1;
    }
    if (p->master >= 0) {
        close(p->master);
        p->master = -1;
    }
}

#ifdef HAVE_READLINE
/* AR-11 L20: drive prompt_line() through Readline's public input callback so
 * NULL outcomes carry a causal errno instead of depending on host TTY races.
 * Each case runs in a fresh PTY child because Readline's streams, hooks, and
 * terminal state are process-global. */
typedef enum {
    READLINE_CASE_EINTR_THEN_LINE,
    READLINE_CASE_EINTR_THEN_EOF,
    READLINE_CASE_EIO,
    READLINE_CASE_EAGAIN,
    READLINE_CASE_CLEAN_EOF,
    READLINE_CASE_STALE_STDIO_EOF
} readline_case_t;

typedef struct {
    int result;
    int saved_errno;
    int startup_calls;
    int injected_eintr;
    int stdio_error_before;
    int stdio_error_after;
    char buffer[16];
} readline_case_result_t;

static readline_case_t g_readline_case;
static int g_readline_script_offset;
static int g_readline_startup_calls;
static int g_readline_injected_eintr;

static int scripted_readline_startup(void) {
    g_readline_startup_calls++;
    return 0;
}

static int scripted_readline_getc(FILE *stream) {
    static const char successful_line[] = "ok\n";

    (void)stream;
    switch (g_readline_case) {
        case READLINE_CASE_EINTR_THEN_LINE:
        case READLINE_CASE_EINTR_THEN_EOF:
            if (!g_readline_injected_eintr) {
                g_readline_injected_eintr = 1;
                errno = EINTR;
                return READERR;
            }
            if (g_readline_case == READLINE_CASE_EINTR_THEN_EOF) {
                errno = 0;
                return EOF;
            }
            if (g_readline_script_offset >=
                (int)(sizeof(successful_line) - 1U)) {
                errno = EIO;
                return READERR;
            }
            errno = 0;
            return (unsigned char)successful_line[g_readline_script_offset++];
        case READLINE_CASE_EIO:
            errno = EIO;
            return READERR;
        case READLINE_CASE_EAGAIN:
            errno = EAGAIN;
            return READERR;
        case READLINE_CASE_CLEAN_EOF:
        case READLINE_CASE_STALE_STDIO_EOF:
            errno = 0;
            return EOF;
        default:
            errno = EINVAL;
            return READERR;
    }
}

static int write_readline_result(int fd,
                                 const readline_case_result_t *result) {
    size_t written = 0;

    while (written < sizeof(*result)) {
        ssize_t count = write(fd, (const char *)result + written,
                              sizeof(*result) - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        written += (size_t)count;
    }
    return 0;
}

static int run_readline_case(readline_case_t test_case,
                             readline_case_result_t *result) {
    pty_proc_t proc;
    const char *pts;
    char slave_name[256];
    int result_pipe[2] = {-1, -1};
    size_t used = 0;
    int child_rc;

    memset(&proc, 0, sizeof(proc));
    proc.master = -1;
    memset(result, 0, sizeof(*result));

    proc.master = posix_openpt(O_RDWR | O_NOCTTY);
    if (proc.master < 0 || grantpt(proc.master) != 0 ||
        unlockpt(proc.master) != 0 ||
        (pts = ptsname(proc.master)) == NULL) {
        if (proc.master >= 0) close(proc.master);
        return -1;
    }
    snprintf(slave_name, sizeof(slave_name), "%s", pts);
    if (pipe(result_pipe) != 0) {
        close(proc.master);
        return -1;
    }
    if (fflush(NULL) != 0) {
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(proc.master);
        return -1;
    }

    proc.pid = fork();
    if (proc.pid < 0) {
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(proc.master);
        return -1;
    }
    if (proc.pid == 0) {
        readline_case_result_t child_result;
        int slave_fd;

        close(result_pipe[0]);
        slave_fd = open_controlling_pty_slave(slave_name);
        if (slave_fd < 0 || dup2(slave_fd, STDIN_FILENO) < 0 ||
            dup2(slave_fd, STDOUT_FILENO) < 0 ||
            dup2(slave_fd, STDERR_FILENO) < 0) {
            _exit(2);
        }
        if (slave_fd > STDERR_FILENO) close(slave_fd);
        close(proc.master);

        setenv("TERM", "dumb", 1);
        setenv("INPUTRC", "/dev/null", 1);
        memset(&child_result, 0, sizeof(child_result));
        memset(child_result.buffer, 'X', sizeof(child_result.buffer));
        child_result.buffer[sizeof(child_result.buffer) - 1] = '\0';

        rl_instream = stdin;
        rl_outstream = stdout;
        rl_catch_signals = 0;
        rl_catch_sigwinch = 0;
        rl_initialize();
        g_readline_case = test_case;
        g_readline_script_offset = 0;
        g_readline_startup_calls = 0;
        g_readline_injected_eintr = 0;
        rl_startup_hook = scripted_readline_startup;
        rl_getc_function = scripted_readline_getc;

        if (test_case == READLINE_CASE_STALE_STDIO_EOF) {
            int saved_stdin = dup(STDIN_FILENO);

            if (saved_stdin < 0 || close(STDIN_FILENO) != 0) _exit(2);
            errno = 0;
            (void)fgetc(stdin);
            if (!ferror(stdin) || dup2(saved_stdin, STDIN_FILENO) < 0) {
                _exit(2);
            }
            close(saved_stdin);
        }
        child_result.stdio_error_before = ferror(stdin) != 0;

        errno = 0;
        child_result.result = prompt_line(
            "scripted> ", child_result.buffer,
            sizeof(child_result.buffer), false);
        child_result.saved_errno = errno;
        child_result.startup_calls = g_readline_startup_calls;
        child_result.injected_eintr = g_readline_injected_eintr;
        child_result.stdio_error_after = ferror(stdin) != 0;

        if (write_readline_result(result_pipe[1], &child_result) != 0) {
            _exit(3);
        }
        close(result_pipe[1]);
        _exit(0);
    }

    close(result_pipe[1]);
    result_pipe[1] = -1;
    child_rc = pty_wait_exit(&proc);
    if (child_rc == 0) {
        while (used < sizeof(*result)) {
            ssize_t count = read(result_pipe[0], (char *)result + used,
                                 sizeof(*result) - used);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            used += (size_t)count;
        }
    }

    close(result_pipe[0]);
    pty_close(&proc);
    return child_rc == 0 && used == sizeof(*result) ? 0 : -1;
}
#endif

static int sandbox_publish_account(sandbox_t *sb, const char *account) {
    const char *switch_argv[] = {
        "gitswitch", "--global", "--yes", account, NULL
    };
    pty_proc_t publish_proc;
    int exit_code;

    if (pty_spawn(&publish_proc, switch_argv, sb) != 0) {
        return -1;
    }
    exit_code = pty_wait_exit(&publish_proc);
    if (exit_code != 0) {
        fprintf(stderr,
                "  failed to publish account '%s' (exit %d); output:\n"
                "  ----\n%s\n  ----\n",
                account, exit_code, publish_proc.out);
        pty_close(&publish_proc);
        return -1;
    }
    pty_close(&publish_proc);
    return 0;
}

/* The positive half of the reset-consent test needs real durable retirement
 * authority.  Keep that fixture credentialless so a normal switch can publish
 * the exact global Git destination without involving SSH/GPG test doubles. */
static int sandbox_prepare_published_reset_account(sandbox_t *sb) {
    static const char config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"w@example.com\"\n"
        "description = \"credentialless reset fixture\"\n"
        "preferred_scope = \"global\"\n";

    if (write_file_mode(sb->cfg, config, 0600) != 0) {
        return -1;
    }
    return sandbox_publish_account(sb, "work");
}

/* Expect-then-type: every answer is sent only after its prompt is visible,
 * which also guarantees the terminal is in whatever mode the reader uses. */
static int expect_send(pty_proc_t *p, const char *prompt, const char *answer) {
    if (pty_expect(p, prompt) != 0) return -1;
    return pty_send(p, answer);
}

static const char *find_bash(void) {
    static const char *const candidates[] = {
        "/usr/bin/bash",
        "/bin/bash",
        "/usr/local/bin/bash",
        "/opt/homebrew/bin/bash",
        NULL
    };

    for (size_t i = 0; candidates[i] != NULL; i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

static const char *find_bash_with_completion(const char **completion) {
    static const struct {
        const char *bash;
        const char *completion;
    } pairs[] = {
        { "/usr/bin/bash", "/usr/share/bash-completion/bash_completion" },
        { "/bin/bash", "/usr/share/bash-completion/bash_completion" },
        { "/usr/local/bin/bash",
          "/usr/local/share/bash-completion/bash_completion" },
        { "/usr/local/bin/bash",
          "/usr/local/etc/profile.d/bash_completion.sh" },
        { "/opt/homebrew/bin/bash",
          "/opt/homebrew/share/bash-completion/bash_completion" },
        { "/opt/homebrew/bin/bash",
          "/opt/homebrew/etc/profile.d/bash_completion.sh" }
    };

    *completion = NULL;
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        if (access(pairs[i].bash, X_OK) == 0 &&
            access(pairs[i].completion, R_OK) == 0) {
            *completion = pairs[i].completion;
            return pairs[i].bash;
        }
    }
    return NULL;
}

static bool sandbox_files_absent(const sandbox_t *sb,
                                 const char *const names[], size_t count) {
    char path[512];
    struct stat st;

    for (size_t i = 0; i < count; i++) {
        int written = snprintf(path, sizeof(path), "%s/%s", sb->home,
                               names[i]);
        if (written < 0 || (size_t)written >= sizeof(path)) return false;
        errno = 0;
        if (lstat(path, &st) == 0 || errno != ENOENT) return false;
    }
    return true;
}

static int bash_complete_and_capture(pty_proc_t *proc, const sandbox_t *sb,
                                     const char *typed, const char *tail,
                                     const char *stored_name,
                                     const char *const effect_files[],
                                     size_t effect_count) {
    char expected[2048];
    size_t command_start = proc->out_len;
    int written;

    if (pty_send(proc, typed) != 0 || pty_expect(proc, tail) != 0) {
        CHECK(!"TAB completion did not produce the unique candidate");
        return -1;
    }
    CHECK(sandbox_files_absent(sb, effect_files, effect_count));
    if (pty_send(proc, "\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"completed command did not execute");
        return -1;
    }
    written = snprintf(expected, sizeof(expected),
                       "M35-CAPTURE:<2>:<edit>:<%s>", stored_name);
    CHECK(written >= 0 && (size_t)written < sizeof(expected));
    if (written >= 0 && (size_t)written < sizeof(expected)) {
        if (strstr(proc->out + command_start, expected) == NULL) {
            fprintf(stderr, "  expected exact completion capture: %s\n"
                    "  command transcript:\n%s\n",
                    expected, proc->out + command_start);
            CHECK(!"completed argv did not match the stored account name");
        }
    }
    CHECK(sandbox_files_absent(sb, effect_files, effect_count));
    return 0;
}

static int bash_complete_fixed_and_capture(pty_proc_t *proc,
                                           const char *typed,
                                           const char *tail,
                                           int expected_argc,
                                           const char *expected_arg1,
                                           const char *expected_arg2) {
    char expected[1024];
    size_t command_start = proc->out_len;
    int written;

    if (pty_send(proc, typed) != 0 || pty_expect(proc, tail) != 0) {
        CHECK(!"TAB completion did not produce the fixed candidate");
        return -1;
    }
    if (pty_send(proc, "\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"fixed completion command did not execute");
        return -1;
    }
    written = snprintf(expected, sizeof(expected),
                       "M35-CAPTURE:<%d>:<%s>:<%s>", expected_argc,
                       expected_arg1, expected_arg2);
    CHECK(written >= 0 && (size_t)written < sizeof(expected));
    if (written >= 0 && (size_t)written < sizeof(expected)) {
        CHECK(strstr(proc->out + command_start, expected) != NULL);
    }
    return 0;
}

static int bash_complete_redirect_and_cancel(pty_proc_t *proc,
                                             const char *typed,
                                             const char *tail) {
    if (pty_send(proc, typed) != 0 || pty_expect(proc, tail) != 0) {
        CHECK(!"redirect target did not filename-complete");
        return -1;
    }
    if (pty_send(proc, "\x15\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"redirect completion line did not cancel cleanly");
        return -1;
    }
    return 0;
}

static int bash_complete_redirect_and_execute(
    pty_proc_t *proc, const sandbox_t *sb, const char *typed,
    const char *tail, const char *literal_path,
    const char *const effect_files[], size_t effect_count) {
    char contents[2048];

    if (pty_send(proc, typed) != 0 || pty_expect(proc, tail) != 0) {
        CHECK(!"quoted redirect target did not filename-complete");
        return -1;
    }
    CHECK(sandbox_files_absent(sb, effect_files, effect_count));
    if (pty_send(proc, "\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"quoted redirect completion did not execute");
        return -1;
    }
    CHECK(sandbox_files_absent(sb, effect_files, effect_count));
    if (slurp(literal_path, contents, sizeof(contents)) <= 0 ||
        strstr(contents, "M35-CAPTURE:<1>:<edit>:<>") == NULL) {
        CHECK(!"quoted redirect expanded bytes instead of using literal path");
        return -1;
    }
    return 0;
}

static int bash_complete_redirect_directory(pty_proc_t *proc) {
    if (pty_send(proc, "gitswitch edit > m35-redir-d\t") != 0 ||
        pty_expect(proc, "m35-redir-dir/") != 0 ||
        pty_send(proc, "cap\t") != 0 ||
        pty_expect(proc, "capture") != 0) {
        CHECK(!"redirect directory traversal did not filename-complete");
        return -1;
    }
    if (pty_send(proc, "\x15\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"redirect directory completion did not cancel cleanly");
        return -1;
    }
    return 0;
}

static int bash_complete_redirect_wordbreak_directory(pty_proc_t *proc) {
    if (pty_send(proc, "gitswitch edit > m35:redirect-d\t") != 0 ||
        pty_expect(proc, "m35:redirect-dir/") != 0 ||
        pty_send(proc, "cap\t") != 0 ||
        pty_expect(proc, "capture") != 0) {
        CHECK(!"word-break redirect directory did not remain traversable");
        return -1;
    }
    if (pty_send(proc, "\x15\n") != 0 ||
        pty_expect(proc, "M35-PROMPT> ") != 0) {
        CHECK(!"word-break directory completion did not cancel cleanly");
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- tests */

static pty_proc_t g_p; /* tests run sequentially */

/* 1. Editing with an empty answer at every prompt must keep every field. */
TEST(edit_empty_input_keeps_all_fields) {
    sandbox_t sb;
    char cfg[16384];
    const char *argv[] = { "gitswitch", "edit", "work", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }

    CHECK_EQ_INT(expect_send(&g_p, "Account Name [work]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [w@example.com]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [work account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* SSH */
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* GPG */
    CHECK_EQ_INT(expect_send(&g_p, "Enable GPG signing for commits?", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account updated"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* Every field survived the round-trip into the saved config. */
    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "\"work\"") != NULL);
    CHECK(strstr(cfg, "w@example.com") != NULL);
    CHECK(strstr(cfg, "work account") != NULL);
    CHECK(strstr(cfg, "key_ed25519") != NULL);
    CHECK(strstr(cfg, "ABCDEF0123456789") != NULL);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 2. Typing 'none' at the SSH and GPG prompts must disable both. */
TEST(none_disables_ssh_and_gpg) {
    sandbox_t sb;
    char cfg[16384];
    const char *argv[] = { "gitswitch", "edit", "work", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }

    CHECK_EQ_INT(expect_send(&g_p, "Account Name [work]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [w@example.com]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [work account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "none\n"), 0); /* SSH */
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "none\n"), 0); /* GPG */
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account updated"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* The summary printed before the confirm must already show both off. */
    CHECK(strstr(g_p.out, "SSH: [DISABLED]") != NULL);
    CHECK(strstr(g_p.out, "GPG: [DISABLED]") != NULL);

    /* And the saved config must have dropped the key material. */
    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "\"work\"") != NULL);
    CHECK(strstr(cfg, "key_ed25519") == NULL);
    CHECK(strstr(cfg, "ABCDEF0123456789") == NULL);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 3. --yes must skip the add/edit/remove confirmation prompts entirely. */
TEST(yes_flag_skips_confirmation) {
    sandbox_t sb;
    char cfg[16384];
    const char *add_argv[] = { "gitswitch", "-y", "add", NULL };
    const char *edit_argv[] = { "gitswitch", "-y", "edit", "work", NULL };
    const char *rm_argv[] = { "gitswitch", "-y", "remove", "other", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);

    /* add: field prompts still run, the (y/N) confirm must not. */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "newbie\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", "n@example.com\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description (optional):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account added successfully"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    CHECK(strstr(g_p.out, "this account? (y/N)") == NULL);
    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "\"newbie\"") != NULL);
    pty_close(&g_p);

    /* edit: all-empty answers, no confirm prompt. */
    if (pty_spawn(&g_p, edit_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name [work]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [w@example.com]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [work account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* SSH */
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* GPG */
    CHECK_EQ_INT(expect_send(&g_p, "Enable GPG signing for commits?", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account updated"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    CHECK(strstr(g_p.out, "this account? (y/N)") == NULL);
    pty_close(&g_p);

    /* Publish the credentialless removal target through the real switch path;
     * M17 requires exact retirement authority for every successful removal. */
    CHECK_EQ_INT(sandbox_publish_account(&sb, "other"), 0);

    /* remove: no typed-'yes' gate at all. */
    if (pty_spawn(&g_p, rm_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Account removed successfully"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    CHECK(strstr(g_p.out, "Are you sure?") == NULL);
    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "name = \"other\"") == NULL);
    pty_close(&g_p);

    sandbox_teardown(&sb);
}

/* 4. Renaming an account onto an existing name is rejected after the confirm,
 *    and the config file is left byte-identical. */
TEST(duplicate_name_rejected_and_config_unchanged) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "edit", "other", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name [other]:", "work\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [o@example.com]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [other account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "already exists"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 5. Ctrl-D at a prompt cancels cleanly on both input paths: the prompt_line
 *    path (readline NULL in interactive readline builds, bounded-stdio EOF
 *    otherwise) via the add name prompt, and the always-bounded-stdio path via
 *    the remove confirmation. The config must be untouched either way. */
TEST(eof_ctrl_d_cancels_cleanly) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *add_argv[] = { "gitswitch", "add", NULL };
    const char *rm_argv[] = { "gitswitch", "remove", "work", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    /* prompt_line path: EOF at the very first add prompt. */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "\x04"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Failed to add account"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    /* Bounded-stdio path: EOF at the remove typed-'yes' confirmation. */
    if (pty_spawn(&g_p, rm_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Are you sure? (type 'yes' to confirm):", "\x04"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Failed to read confirmation"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    sandbox_teardown(&sb);
}

/* L20: a Readline NULL is clean EOF only when its causal errno is zero.
 * Interrupted reads restart from a fresh Readline attempt; every other error
 * remains observable by the caller. A stale stdio error flag is deliberately
 * unrelated because Readline consumes input through its own callback. */
TEST(readline_null_distinguishes_interrupt_error_and_eof) {
#ifndef HAVE_READLINE
    TS_SKIP("readline", "binary was built without readline support");
#else
    readline_case_result_t result;

    SKIP_IF_NO_PTY();

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_EINTR_THEN_LINE, &result), 0);
    CHECK_EQ_INT(result.result, PROMPT_LINE_OK);
    CHECK_STR_EQ(result.buffer, "ok");
    CHECK_EQ_INT(result.saved_errno, 0);
    CHECK_EQ_INT(result.injected_eintr, 1);
    CHECK_EQ_INT(result.startup_calls, 2);
    CHECK_EQ_INT(result.stdio_error_after, 0);

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_EINTR_THEN_EOF, &result), 0);
    CHECK_EQ_INT(result.result, PROMPT_LINE_EOF);
    CHECK_STR_EQ(result.buffer, "");
    CHECK_EQ_INT(result.saved_errno, 0);
    CHECK_EQ_INT(result.injected_eintr, 1);
    CHECK_EQ_INT(result.startup_calls, 2);
    CHECK_EQ_INT(result.stdio_error_after, 0);

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_EIO, &result), 0);
    CHECK_EQ_INT(result.result, PROMPT_LINE_ERROR);
    CHECK_STR_EQ(result.buffer, "");
    CHECK_EQ_INT(result.saved_errno, EIO);
    CHECK_EQ_INT(result.startup_calls, 1);
    CHECK_EQ_INT(result.stdio_error_after, 0);

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_EAGAIN, &result), 0);
    CHECK_EQ_INT(result.result, PROMPT_LINE_ERROR);
    CHECK_STR_EQ(result.buffer, "");
    CHECK_EQ_INT(result.saved_errno, EAGAIN);
    CHECK_EQ_INT(result.startup_calls, 1);
    CHECK_EQ_INT(result.stdio_error_after, 0);

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_CLEAN_EOF, &result), 0);
    CHECK_EQ_INT(result.result, PROMPT_LINE_EOF);
    CHECK_STR_EQ(result.buffer, "");
    CHECK_EQ_INT(result.saved_errno, 0);
    CHECK_EQ_INT(result.startup_calls, 1);
    CHECK_EQ_INT(result.stdio_error_after, 0);

    CHECK_EQ_INT(run_readline_case(READLINE_CASE_STALE_STDIO_EOF, &result), 0);
    CHECK_EQ_INT(result.stdio_error_before, 1);
    CHECK_EQ_INT(result.result, PROMPT_LINE_EOF);
    CHECK_STR_EQ(result.buffer, "");
    CHECK_EQ_INT(result.saved_errno, 0);
    CHECK_EQ_INT(result.startup_calls, 1);
    CHECK_EQ_INT(result.stdio_error_after, 1);
#endif
}

/* 6. TAB completes filenames only at the SSH key path prompt; at other
 *    prompts completion is inhibited (a stray TAB must not spew the CWD).
 *    Only meaningful in readline builds — HAVE_READLINE comes from the same
 *    CFLAGS the binary was built with. */
TEST(ssh_key_path_tab_completion_and_inhibition) {
#ifndef HAVE_READLINE
    TS_SKIP("readline", "binary was built without readline support");
#else
    sandbox_t sb;
    char path[512];
    const char *argv[] = { "gitswitch", "add", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);

    /* Unique completion target in the child's CWD ($HOME). */
    snprintf(path, sizeof(path), "%s/zzuniq_target_rsa", sb.home);
    CHECK_EQ_INT(write_file_mode(path,
                                 "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                                 0600), 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }

    /* Name prompt: completion inhibited, so TAB is a literal character and
     * the prefix must NOT expand to the target filename. (The literal tab is
     * trimmed as whitespace, leaving a valid name.) */
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "zzuniq_ta\t\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", ""), 0);
    CHECK(strstr(g_p.out, "zzuniq_target_rsa") == NULL);

    CHECK_EQ_INT(pty_send(&g_p, "z@example.com\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description (optional):", "\n"), 0);

    /* SSH key path prompt: completion armed — TAB must expand the unique
     * prefix, echoing the completed filename. */
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "zzuniq_ta\t"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "zzuniq_target_rsa"), 0);

    /* Kill the line (C-u) and skip SSH; finish the flow cancelled. */
    CHECK_EQ_INT(pty_send(&g_p, "\x15\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "n\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account creation cancelled"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);

    pty_close(&g_p);
    sandbox_teardown(&sb);
#endif
}

/* 7. reset demands a typed 'yes': a bare 'y' cancels, 'yes' proceeds. */
TEST(reset_typed_yes_confirmation_semantics) {
    sandbox_t sb;
    const char *argv[] = { "gitswitch", "reset", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);

    /* 'y' is not consent. */
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Type 'yes' to continue:", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Reset cancelled"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    CHECK(strstr(g_p.out, "Reset all gitswitch") == NULL);
    pty_close(&g_p);

    /* A typed 'yes' proceeds against a genuinely published destination, so
     * the success assertion exercises retirement rather than a legacy
     * missing-provenance shortcut. */
    CHECK_EQ_INT(sandbox_prepare_published_reset_account(&sb), 0);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Type 'yes' to continue:", "yes\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Reset all gitswitch SSH/GPG state"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    pty_close(&g_p);

    sandbox_teardown(&sb);
}

/* 8. remove uses the same exact-'yes' rule: a near miss cancels without a
 *    durable config edit, while a visible prompt followed by exact consent
 *    removes a genuinely published destination. */
TEST(remove_typed_yes_confirmation_semantics) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "remove", "other", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);

    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Are you sure? (type 'yes' to confirm):", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account removal cancelled"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    pty_close(&g_p);
    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    CHECK_EQ_INT(sandbox_publish_account(&sb, "other"), 0);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Are you sure? (type 'yes' to confirm):", "yes\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account removed successfully"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    pty_close(&g_p);
    CHECK(slurp(sb.cfg, after, sizeof(after)) > 0);
    CHECK(strstr(after, "name = \"other\"") == NULL);

    sandbox_teardown(&sb);
}

/* 9. Declining the final confirm of add and edit must leave accounts.toml
 *    byte-identical (no save, no backup rewrite of the live file). */
TEST(cancelled_ops_leave_config_byte_identical) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *add_argv[] = { "gitswitch", "add", NULL };
    const char *edit_argv[] = { "gitswitch", "edit", "work", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    /* add … n */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "temp\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", "t@example.com\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description (optional):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "n\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account creation cancelled"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    /* edit (with a changed field) … n */
    if (pty_spawn(&g_p, edit_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name [work]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [w@example.com]:", "changed@example.com\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [work account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* SSH */
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* GPG */
    CHECK_EQ_INT(expect_send(&g_p, "Enable GPG signing for commits?", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "n\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Edit cancelled"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    sandbox_teardown(&sb);
}

/* 10. Invalid name/email/scope answers re-prompt instead of aborting, and the
 *    flow still completes once valid input arrives. */
TEST(invalid_input_reprompt_loops) {
    sandbox_t sb;
    char cfg[16384];
    const char *argv[] = { "gitswitch", "add", NULL };

    SKIP_IF_NO_PTY();
    SETUP_SANDBOX_OR_RETURN(sb);
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }

    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "bad/name\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Invalid name (no"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "goodname\n"), 0);

    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", "not-an-email\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Invalid email address format"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", "g@example.com\n"), 0);

    CHECK_EQ_INT(expect_send(&g_p, "Description (optional):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);

    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "bogus\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Please enter 'local' or 'global'"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "local\n"), 0);

    CHECK_EQ_INT(expect_send(&g_p, "this account? (y/N)", "y\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account added successfully"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "\"goodname\"") != NULL);
    CHECK(strstr(cfg, "g@example.com") != NULL);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 11. A programmable-completion unit test only sees COMPREPLY. Exercise the
 *     missing boundary through native Bash/Readline: TAB-complete
 *     metacharacter-rich account names inside each quote context, then execute
 *     the line and require the stub's parsed argument vector to reproduce the
 *     stored name byte-for-byte. Marker files prove TAB and execution never
 *     evaluate account-name bytes. */
TEST(bash_tab_completion_preserves_active_quote_argv) {
    static const char double_name[] =
        "M35D Space $M35_DOLLAR `touch M35_BT_D` $(touch M35_CS_D) "
        "Back\\Slash \"Double\" O' $(touch M35_SQ_D) ' !M35_HISTORY_D M35DTAIL";
    static const char single_name[] =
        "M35S Space $M35_DOLLAR `touch M35_BT_S` $(touch M35_CS_S) "
        "Back\\Slash \"Double\" O' $(touch M35_SQ_S) ' !M35_HISTORY_S M35STAIL";
    static const char colon_name[] =
        "M35C:Part Space $M35_DOLLAR M35CTAIL";
    static const char equal_name[] =
        "M35E=Part Space $M35_DOLLAR M35ETAIL";
    static const char at_name[] =
        "M35A@Part Space $M35_DOLLAR M35ATAIL";
    static const char mid_quote_name[] =
        "M35MID Prefix$M35_DOLLAR M35MIDTAIL";
    static const char quoted_colon_name[] =
        "M35QC:Part Space $M35_DOLLAR M35QCTAIL";
    static const char quoted_equal_name[] =
        "M35QE=Part Space $M35_DOLLAR M35QETAIL";
    static const char history_name[] =
        "M35H Space ^M35_HISTORY M35HTAIL";
    static const char end_single_name[] = "M35ENDSQTAIL'";
    static const char end_double_quote_name[] = "M35ENDDQTAIL\"";
    static const char end_double_slash_name[] = "M35ENDDBTAIL\\";
    static const char end_double_history_name[] = "M35ENDDHTAIL!";
    static const char end_ansi_slash_name[] = "M35ENDABTAIL\\";
    static const char end_ansi_history_name[] = "M35ENDAHTAIL!";
    static const char quoted_redirect_name[] =
        "m35-quoted $M35_REDIRECT $(touch M35_REDIRECT_CS) "
        "`touch M35_REDIRECT_BT` output";
    static const char *const fallback_compound_lines[] = {
        "gitswitch edit PRIOR;gitswitch edit M35C:Par\t",
        "gitswitch edit PRIOR&&gitswitch edit M35C:Par\t",
        "false||gitswitch edit M35C:Par\t",
        "printf x|gitswitch edit M35C:Par\t",
        "true&gitswitch edit M35C:Par\t",
        "gitswitch edit PRIOR\ngitswitch edit M35C:Par\t",
        "printf '%s' 'old;old&&old||old|old&old';"
        "gitswitch edit M35C:Par\t",
        "printf %s $(if true; then printf y; else printf z; fi);"
        "gitswitch edit M35C:Par\t",
        "printf %s `case x in x) printf y;; esac`;"
        "gitswitch edit M35C:Par\t",
        "printf %s $(printf \"%s\" \"$(date)\");"
        "gitswitch edit M35C:Par\t",
        "printf %s `printf \"%s\" \"\\`date\\`\"`;"
        "gitswitch edit M35C:Par\t"
    };
    static const char stub_body[] =
        "#!/bin/sh\n"
        "if [ \"$#\" -eq 2 ] && [ \"$1\" = --names ] && "
        "[ \"$2\" = list ]; then\n"
        "    while IFS= read -r line || [ -n \"$line\" ]; do\n"
        "        printf '%s\\n' \"$line\"\n"
        "    done < \"$M35_NAMES_FILE\"\n"
        "    exit 0\n"
        "fi\n"
        "printf 'M35-%s:<%s>:<%s>:<%s>\\n' CAPTURE \"$#\" \"$1\" \"$2\"\n";
    static const char fallback_setup[] =
        "PATH=\"$HOME/m35-bin:/usr/local/bin:/usr/bin:/bin\"; export PATH; "
        "M35_NAMES_FILE=\"$HOME/m35-names\"; export M35_NAMES_FILE; "
        "M35_DOLLAR=EXPANDED; export M35_DOLLAR; "
        "M35_REDIRECT=EXPANDED; export M35_REDIRECT; "
        "LC_ALL=C; export LC_ALL; set +o posix; set -H; unset histchars; "
        "HISTFILE=\"$HOME/m35-history\"; export HISTFILE; history -c; "
        "shopt -s progcomp; cd \"$HOME\"; PROMPT_COMMAND=; "
        "bind '\"\\C-i\":complete'; "
        "unset -f gitswitch _init_completion __ltrim_colon_completions "
        "_comp_ltrim_colon_completions 2>/dev/null || :; "
        ". \"$HOME/m35-completion.bash\"; "
        "if ((BASH_VERSINFO[0] > 4 || "
        "(BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 1))); then "
        "printf 'M35-%s\\n' RETRY; else printf 'M35-%s\\n' LEGACY; fi; "
        "PS1='M35-''PROMPT> '; PS2='M35-''CONT> '; "
        "printf 'M35-%s\\n' READY\n";
    static const char installed_setup[] =
        "PATH=\"$HOME/m35-bin:/usr/local/bin:/usr/bin:/bin\"; export PATH; "
        "M35_NAMES_FILE=\"$HOME/m35-names\"; export M35_NAMES_FILE; "
        "M35_DOLLAR=EXPANDED; export M35_DOLLAR; "
        "M35_REDIRECT=EXPANDED; export M35_REDIRECT; "
        "LC_ALL=C; export LC_ALL; set +o posix; set -H; unset histchars; "
        "HISTFILE=\"$HOME/m35-history\"; export HISTFILE; history -c; "
        "shopt -s progcomp; cd \"$HOME\"; PROMPT_COMMAND=; "
        "bind '\"\\C-i\":complete'; "
        ". \"$HOME/m35-bash-completion\"; "
        "declare -F _init_completion >/dev/null || "
        "{ printf 'M35-%s\\n' BC-MISSING; exit 65; }; "
        ". \"$HOME/m35-completion.bash\"; "
        "PS1='M35-''PROMPT> '; PS2='M35-''CONT> '; "
        "printf 'M35-%s\\n' BC-READY\n";
    static const char *const double_effects[] = {
        "M35_BT_D", "M35_CS_D", "M35_SQ_D"
    };
    static const char *const single_effects[] = {
        "M35_BT_S", "M35_CS_S", "M35_SQ_S"
    };
    static const char *const redirect_effects[] = {
        "M35_REDIRECT_CS", "M35_REDIRECT_BT"
    };
    sandbox_t sb = {0};
    pty_proc_t bash_proc = { .master = -1, .pid = -1 };
    const char *bash = find_bash();
    const char *bash_completion = NULL;
    const char *installed_bash = find_bash_with_completion(&bash_completion);
    const char *bash_argv[] = { "bash", "--noprofile", "--norc", "-i", NULL };
    char completion_path[4096];
    char completion_link[512];
    char bash_completion_link[512];
    char bash_completion_body[4096];
    char stub_dir[512];
    char stub_path[512];
    char names_path[512];
    char names_body[4096];
    char redirect_file[512];
    char redirect_colon[512];
    char redirect_equal[512];
    char redirect_at[512];
    char redirect_quoted[512];
    char redirect_dir[512];
    char redirect_nested[512];
    char redirect_colon_dir[512];
    char redirect_colon_nested[512];
    bool sandbox_ready = false;
    bool fallback_retry = false;
    int written;
    int rc;

    SKIP_IF_NO_PTY();
    if (!bash) {
        TS_SKIP("bash", "native Bash executable is unavailable");
    }
    if (!realpath("completions/gitswitch.bash", completion_path)) {
        CHECK(!"cannot resolve Bash completion asset");
        return;
    }
    SETUP_SANDBOX_OR_RETURN(sb);
    sandbox_ready = true;

    written = snprintf(completion_link, sizeof(completion_link),
                       "%s/m35-completion.bash", sb.home);
    if (written < 0 || (size_t)written >= sizeof(completion_link) ||
        symlink(completion_path, completion_link) != 0) {
        CHECK(!"completion fixture setup failed");
        goto cleanup;
    }
    if (bash_completion) {
        written = snprintf(bash_completion_link,
                           sizeof(bash_completion_link),
                           "%s/m35-bash-completion", sb.home);
        if (written < 0 ||
            (size_t)written >= sizeof(bash_completion_link)) {
            CHECK(!"bash-completion fixture setup failed");
            goto cleanup;
        }
        written = snprintf(bash_completion_body,
                           sizeof(bash_completion_body),
                           ". '%s'\n", bash_completion);
        if (written < 0 ||
            (size_t)written >= sizeof(bash_completion_body) ||
            write_file_mode(bash_completion_link,
                            bash_completion_body, 0600) != 0) {
            CHECK(!"bash-completion wrapper setup failed");
            goto cleanup;
        }
    }
    written = snprintf(stub_dir, sizeof(stub_dir), "%s/m35-bin", sb.home);
    if (written < 0 || (size_t)written >= sizeof(stub_dir) ||
        mkdir(stub_dir, 0700) != 0) {
        CHECK(!"stub directory setup failed");
        goto cleanup;
    }
    written = snprintf(stub_path, sizeof(stub_path), "%s/gitswitch", stub_dir);
    if (written < 0 || (size_t)written >= sizeof(stub_path) ||
        write_file_mode(stub_path, stub_body, 0700) != 0) {
        CHECK(!"stub executable setup failed");
        goto cleanup;
    }
    written = snprintf(names_path, sizeof(names_path), "%s/m35-names", sb.home);
    if (written < 0 || (size_t)written >= sizeof(names_path)) {
        CHECK(!"names path setup failed");
        goto cleanup;
    }
    written = snprintf(names_body, sizeof(names_body),
                       "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n"
                       "%s\n%s\n%s\n%s\n%s\n%s\n",
                       double_name, single_name, colon_name, equal_name, at_name,
                       mid_quote_name, quoted_colon_name, quoted_equal_name,
                       history_name, end_single_name, end_double_quote_name,
                       end_double_slash_name, end_double_history_name,
                       end_ansi_slash_name, end_ansi_history_name);
    if (written < 0 || (size_t)written >= sizeof(names_body) ||
        write_file_mode(names_path, names_body, 0600) != 0) {
        CHECK(!"names fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_file, sizeof(redirect_file),
                       "%s/m35-redir-output", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_file) ||
        write_file_mode(redirect_file, "fixture\n", 0600) != 0) {
        CHECK(!"redirect file fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_colon, sizeof(redirect_colon),
                       "%s/m35:redirect-output", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_colon) ||
        write_file_mode(redirect_colon, "fixture\n", 0600) != 0) {
        CHECK(!"colon redirect fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_equal, sizeof(redirect_equal),
                       "%s/m35=redirect-output", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_equal) ||
        write_file_mode(redirect_equal, "fixture\n", 0600) != 0) {
        CHECK(!"equals redirect fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_at, sizeof(redirect_at),
                       "%s/m35@redirect-output", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_at) ||
        write_file_mode(redirect_at, "fixture\n", 0600) != 0) {
        CHECK(!"at-sign redirect fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_quoted, sizeof(redirect_quoted), "%s/%s",
                       sb.home, quoted_redirect_name);
    if (written < 0 || (size_t)written >= sizeof(redirect_quoted) ||
        write_file_mode(redirect_quoted, "fixture\n", 0600) != 0) {
        CHECK(!"quoted redirect fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_dir, sizeof(redirect_dir),
                       "%s/m35-redir-dir", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_dir) ||
        mkdir(redirect_dir, 0700) != 0) {
        CHECK(!"redirect directory fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_nested, sizeof(redirect_nested),
                       "%s/capture", redirect_dir);
    if (written < 0 || (size_t)written >= sizeof(redirect_nested) ||
        write_file_mode(redirect_nested, "fixture\n", 0600) != 0) {
        CHECK(!"nested redirect fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_colon_dir, sizeof(redirect_colon_dir),
                       "%s/m35:redirect-dir", sb.home);
    if (written < 0 || (size_t)written >= sizeof(redirect_colon_dir) ||
        mkdir(redirect_colon_dir, 0700) != 0) {
        CHECK(!"word-break redirect directory fixture setup failed");
        goto cleanup;
    }
    written = snprintf(redirect_colon_nested, sizeof(redirect_colon_nested),
                       "%s/capture", redirect_colon_dir);
    if (written < 0 || (size_t)written >= sizeof(redirect_colon_nested) ||
        write_file_mode(redirect_colon_nested, "fixture\n", 0600) != 0) {
        CHECK(!"word-break nested redirect fixture setup failed");
        goto cleanup;
    }

    if (pty_spawn_exec(&bash_proc, bash, bash_argv, &sb) != 0) {
        CHECK(!"interactive Bash spawn failed");
        goto cleanup;
    }
    if (pty_expect(&bash_proc, PTY_STARTUP_PROMPT) != 0 ||
        pty_send(&bash_proc, fallback_setup) != 0 ||
        pty_expect(&bash_proc, "M35-READY") != 0 ||
        pty_expect(&bash_proc, "M35-PROMPT> ") != 0) {
        CHECK(!"interactive Bash setup failed");
        goto cleanup;
    }
    fallback_retry = strstr(bash_proc.out, "M35-RETRY") != NULL;
    for (size_t i = 0;
         i < sizeof(fallback_compound_lines) /
                 sizeof(fallback_compound_lines[0]);
         i++) {
        if (bash_complete_and_capture(
                &bash_proc, &sb, fallback_compound_lines[i], "M35CTAIL",
                colon_name, NULL, 0) != 0) {
            goto cleanup;
        }
    }
    if (bash_complete_redirect_and_cancel(
            &bash_proc, "gitswitch edit > m35-redir-ou\t",
            "m35-redir-output") != 0 ||
        bash_complete_redirect_and_cancel(
            &bash_proc, "gitswitch edit>m35-redir-ou\t",
            "m35-redir-output") != 0 ||
        bash_complete_redirect_and_cancel(
            &bash_proc, "gitswitch edit > m35:redirect-ou\t",
            "m35:redirect-output") != 0 ||
        bash_complete_redirect_and_cancel(
            &bash_proc, "gitswitch edit > m35=redirect-ou\t",
            "m35=redirect-output") != 0 ||
        bash_complete_redirect_and_cancel(
            &bash_proc, "gitswitch edit > m35@redirect-ou\t",
            "redirect-output") != 0 ||
        bash_complete_redirect_and_execute(
            &bash_proc, &sb, "gitswitch edit > \"m35-quoted \t", "output",
            redirect_quoted, redirect_effects,
            sizeof(redirect_effects) / sizeof(redirect_effects[0])) != 0 ||
        (fallback_retry &&
         (bash_complete_redirect_directory(&bash_proc) != 0 ||
          bash_complete_redirect_wordbreak_directory(&bash_proc) != 0))) {
        goto cleanup;
    }
    if (bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35D\t", "M35DTAIL",
            double_name, double_effects,
            sizeof(double_effects) / sizeof(double_effects[0])) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit 'M35S\t", "M35STAIL",
            single_name, single_effects,
            sizeof(single_effects) / sizeof(single_effects[0])) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit $'M35S\t", "M35STAIL",
            single_name, single_effects,
            sizeof(single_effects) / sizeof(single_effects[0])) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit M35C:Par\t", "M35CTAIL",
            colon_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit M35E=Par\t", "M35ETAIL",
            equal_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit M35A@Par\t", "M35ATAIL",
            at_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit M35MID\" Pre\t", "M35MIDTAIL",
            mid_quote_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35QC:Par\t", "M35QCTAIL",
            quoted_colon_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35QE=Par\t", "M35QETAIL",
            quoted_equal_name, NULL, 0) != 0) {
        goto cleanup;
    }
    if (bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit 'M35ENDSQ\t", "TAIL",
            end_single_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit $'M35ENDSQ\t", "TAIL",
            end_single_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35ENDDQ\t", "TAIL",
            end_double_quote_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35ENDDB\t", "TAIL",
            end_double_slash_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35ENDDH\t", "TAIL",
            end_double_history_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit $'M35ENDAB\t", "TAIL",
            end_ansi_slash_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit $'M35ENDAH\t", "TAIL",
            end_ansi_history_name, NULL, 0) != 0) {
        goto cleanup;
    }
    if (bash_complete_fixed_and_capture(
            &bash_proc, "gitswitch e\"di\t", "dit", 1, "edit", "") != 0 ||
        bash_complete_fixed_and_capture(
            &bash_proc, "gitswitch --\"gl\t", "global", 1, "--global", "") != 0 ||
        bash_complete_fixed_and_capture(
            &bash_proc, "gitswitch init b\"as\t", "ash", 2, "init", "bash") != 0) {
        goto cleanup;
    }
    if (pty_send(&bash_proc, "histchars='^!#'\n") != 0 ||
        pty_expect(&bash_proc, "M35-PROMPT> ") != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit \"M35H\t", "M35HTAIL",
            history_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit $'M35H\t", "M35HTAIL",
            history_name, NULL, 0) != 0 ||
        bash_complete_and_capture(
            &bash_proc, &sb, "gitswitch edit M35H\t", "M35HTAIL",
            history_name, NULL, 0) != 0) {
        goto cleanup;
    }

    if (pty_send(&bash_proc, "exit\n") != 0) {
        CHECK(!"failed to exit interactive Bash");
        goto cleanup;
    }
    rc = pty_wait_exit(&bash_proc);
    CHECK_EQ_INT(rc, 0);
    pty_close(&bash_proc);

    /* When bash-completion is installed, repeat the same Readline witness
     * through its _init_completion -n := reconstruction path. The fallback
     * lane above always runs, so minimal CI/macOS images remain deterministic. */
    if (bash_completion) {
        if (pty_spawn_exec(&bash_proc, installed_bash, bash_argv, &sb) != 0) {
            CHECK(!"bash-completion PTY spawn failed");
            goto cleanup;
        }
        if (pty_expect(&bash_proc, PTY_STARTUP_PROMPT) != 0 ||
            pty_send(&bash_proc, installed_setup) != 0 ||
            pty_expect(&bash_proc, "M35-BC-READY") != 0 ||
            pty_expect(&bash_proc, "M35-PROMPT> ") != 0) {
            CHECK(!"installed bash-completion setup failed");
            goto cleanup;
        }
        if (bash_complete_redirect_and_cancel(
                &bash_proc, "gitswitch edit > m35-redir-ou\t",
                "m35-redir-output") != 0 ||
            bash_complete_redirect_and_cancel(
                &bash_proc, "gitswitch edit>m35-redir-ou\t",
                "m35-redir-output") != 0 ||
            bash_complete_redirect_and_cancel(
                &bash_proc, "gitswitch edit > m35:redirect-ou\t",
                "m35:redirect-output") != 0 ||
            bash_complete_redirect_and_cancel(
                &bash_proc, "gitswitch edit > m35=redirect-ou\t",
                "m35=redirect-output") != 0 ||
            bash_complete_redirect_and_cancel(
                &bash_proc, "gitswitch edit > m35@redirect-ou\t",
                "redirect-output") != 0 ||
            bash_complete_redirect_and_execute(
                &bash_proc, &sb, "gitswitch edit > \"m35-quoted \t",
                "output", redirect_quoted, redirect_effects,
                sizeof(redirect_effects) / sizeof(redirect_effects[0])) != 0 ||
            bash_complete_redirect_directory(&bash_proc) != 0 ||
            bash_complete_redirect_wordbreak_directory(&bash_proc) != 0) {
            goto cleanup;
        }
        if (bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35D\t", "M35DTAIL",
                double_name, double_effects,
                sizeof(double_effects) / sizeof(double_effects[0])) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit 'M35S\t", "M35STAIL",
                single_name, single_effects,
                sizeof(single_effects) / sizeof(single_effects[0])) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit $'M35S\t", "M35STAIL",
                single_name, single_effects,
                sizeof(single_effects) / sizeof(single_effects[0])) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit M35C:Par\t", "M35CTAIL",
                colon_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit M35E=Par\t", "M35ETAIL",
                equal_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit M35A@Par\t", "M35ATAIL",
                at_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit M35MID\" Pre\t", "M35MIDTAIL",
                mid_quote_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35QC:Par\t", "M35QCTAIL",
                quoted_colon_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35QE=Par\t", "M35QETAIL",
                quoted_equal_name, NULL, 0) != 0) {
            goto cleanup;
        }
        if (bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit 'M35ENDSQ\t", "TAIL",
                end_single_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit $'M35ENDSQ\t", "TAIL",
                end_single_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35ENDDQ\t", "TAIL",
                end_double_quote_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35ENDDB\t", "TAIL",
                end_double_slash_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35ENDDH\t", "TAIL",
                end_double_history_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit $'M35ENDAB\t", "TAIL",
                end_ansi_slash_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit $'M35ENDAH\t", "TAIL",
                end_ansi_history_name, NULL, 0) != 0) {
            goto cleanup;
        }
        if (bash_complete_fixed_and_capture(
                &bash_proc, "gitswitch e\"di\t", "dit", 1, "edit", "") != 0 ||
            bash_complete_fixed_and_capture(
                &bash_proc, "gitswitch --\"gl\t", "global", 1,
                "--global", "") != 0 ||
            bash_complete_fixed_and_capture(
                &bash_proc, "gitswitch init b\"as\t", "ash", 2,
                "init", "bash") != 0) {
            goto cleanup;
        }
        if (pty_send(&bash_proc, "histchars='^!#'\n") != 0 ||
            pty_expect(&bash_proc, "M35-PROMPT> ") != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit \"M35H\t", "M35HTAIL",
                history_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit $'M35H\t", "M35HTAIL",
                history_name, NULL, 0) != 0 ||
            bash_complete_and_capture(
                &bash_proc, &sb, "gitswitch edit M35H\t", "M35HTAIL",
                history_name, NULL, 0) != 0) {
            goto cleanup;
        }
        if (pty_send(&bash_proc, "exit\n") != 0) {
            CHECK(!"failed to exit bash-completion session");
            goto cleanup;
        }
        rc = pty_wait_exit(&bash_proc);
        CHECK_EQ_INT(rc, 0);
    } else {
        printf("[info] bash-completion integration unavailable; "
               "fallback Readline lane verified\n");
    }

cleanup:
    pty_close(&bash_proc);
    if (sandbox_ready) sandbox_teardown(&sb);
}

TEST_MAIN_BEGIN()
    if (resolve_binary() != 0) {
        fprintf(stderr, "RESULT FAIL: cannot locate gitswitch binary\n");
        return 1;
    }
    /* Probe once whether this environment can mint PTYs; if not, every test
     * SKIPs (matching the test_cli skip idiom) instead of failing. */
    {
        int probe = posix_openpt(O_RDWR | O_NOCTTY);
        if (probe < 0 || grantpt(probe) != 0 || unlockpt(probe) != 0 ||
            ptsname(probe) == NULL) {
            g_no_pty = 1;
        }
        if (probe >= 0) close(probe);
    }
    RUN_TEST(edit_empty_input_keeps_all_fields);
    RUN_TEST(none_disables_ssh_and_gpg);
    RUN_TEST(yes_flag_skips_confirmation);
    RUN_TEST(duplicate_name_rejected_and_config_unchanged);
    RUN_TEST(eof_ctrl_d_cancels_cleanly);
    RUN_TEST(readline_null_distinguishes_interrupt_error_and_eof);
    RUN_TEST(ssh_key_path_tab_completion_and_inhibition);
    RUN_TEST(reset_typed_yes_confirmation_semantics);
    RUN_TEST(remove_typed_yes_confirmation_semantics);
    RUN_TEST(cancelled_ops_leave_config_byte_identical);
    RUN_TEST(invalid_input_reprompt_loops);
    RUN_TEST(bash_tab_completion_preserves_active_quote_argv);
TEST_MAIN_END()
