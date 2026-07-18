/* PTY-driven end-to-end tests for the interactive flows (add/edit/remove/
 * reset). The prompt paths behave differently on a real terminal — readline
 * builds go raw, TAB completion is armed only for the SSH key path prompt,
 * and Ctrl-D must cancel via the readline-NULL / fgets-EOF paths — so these
 * tests give the binary an actual PTY, not a pipe.
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
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Generous-but-bounded deadlines: normal turnaround is milliseconds, but the
 * debug build runs under ASan/UBSan on possibly loaded CI machines. */
#define EXPECT_TIMEOUT_MS 10000
#define EXIT_TIMEOUT_MS   15000

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
 * 0700 dirs — the T5 checks reject anything looser) and a dummy 0600 SSH key
 * the config references (account load validates existence + permissions). */
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

static int sandbox_setup(sandbox_t *sb) {
    char path[512];
    char cfg[1024];

    if (!make_temp_dir(sb->home, sizeof(sb->home)) ||
        !make_temp_dir(sb->rt, sizeof(sb->rt))) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s/key_ed25519", sb->home);
    if (write_file_mode(path,
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                        0600) != 0) return -1;

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

/* Spawn the binary on a fresh PTY inside the sandbox, with a scrubbed
 * environment and $HOME as the CWD. Returns 0, or -1 (infrastructure
 * failure). */
static int pty_spawn(pty_proc_t *p, const char *const argv[], const sandbox_t *sb) {
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
        setsid();
        sfd = open(slave_name, O_RDWR); /* becomes the controlling TTY */
        if (sfd < 0) _exit(126);
        dup2(sfd, STDIN_FILENO);
        dup2(sfd, STDOUT_FILENO);
        dup2(sfd, STDERR_FILENO);
        if (sfd > STDERR_FILENO) close(sfd);
        close(p->master);

        setenv("HOME", sb->home, 1);
        setenv("XDG_RUNTIME_DIR", sb->rt, 1);
        /* T6 pins helper resolution to trusted absolute PATH dirs. */
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
        setenv("TERM", "dumb", 1); /* keep readline's escape output minimal */
        /* No ambient state may leak into the sandboxed run. */
        unsetenv("XDG_CONFIG_HOME");
        unsetenv("GNUPGHOME");
        unsetenv("SSH_AUTH_SOCK");
        unsetenv("INPUTRC"); /* a user inputrc could rebind TAB/C-u */

        if (chdir(sb->home) != 0) _exit(126);
        execv(g_bin, (char *const *)argv);
        _exit(127);
    }
    return 0;
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

static int sandbox_publish_account(sandbox_t *sb, const char *account) {
    const char *switch_argv[] = {
        "gitswitch", "--global", "--yes", account, NULL
    };
    pty_proc_t publish_proc;

    if (pty_spawn(&publish_proc, switch_argv, sb) != 0) {
        return -1;
    }
    if (pty_wait_exit(&publish_proc) != 0) {
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

/* ---------------------------------------------------------------- tests */

static pty_proc_t g_p; /* tests run sequentially */

/* 1. Editing with an empty answer at every prompt must keep every field. */
TEST(edit_empty_input_keeps_all_fields) {
    sandbox_t sb;
    char cfg[16384];
    const char *argv[] = { "gitswitch", "edit", "work", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }

    CHECK_EQ_INT(expect_send(&g_p, "Account Name [work]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address [w@example.com]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description [work account]:", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* SSH */
    CHECK_EQ_INT(expect_send(&g_p, "'none' to disable):", "\n"), 0); /* GPG */
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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }

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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
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
 *    path (readline NULL in readline builds, fgets EOF otherwise) via the add
 *    name prompt, and the always-fgets path via the remove confirmation. The
 *    config must be untouched either way. */
TEST(eof_ctrl_d_cancels_cleanly) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *add_argv[] = { "gitswitch", "add", NULL };
    const char *rm_argv[] = { "gitswitch", "remove", "work", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    /* prompt_line path: EOF at the very first add prompt. */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "\x04"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Failed to add account"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    /* fgets path: EOF at the remove typed-'yes' confirmation. */
    if (pty_spawn(&g_p, rm_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Are you sure? (type 'yes' to confirm):", "\x04"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Failed to read confirmation"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    pty_close(&g_p);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    sandbox_teardown(&sb);
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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }

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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }

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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }

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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
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
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
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
    RUN_TEST(ssh_key_path_tab_completion_and_inhibition);
    RUN_TEST(reset_typed_yes_confirmation_semantics);
    RUN_TEST(remove_typed_yes_confirmation_semantics);
    RUN_TEST(cancelled_ops_leave_config_byte_identical);
    RUN_TEST(invalid_input_reprompt_loops);
TEST_MAIN_END()
