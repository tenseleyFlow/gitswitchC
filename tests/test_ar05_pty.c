/* AR-05: adversarial PTY / end-to-end CLI tests.
 *
 * Complements tests/test_pty.c (which covers the happy-path interactive
 * add/edit flows) with the flows the existing suites do NOT touch:
 *
 *   - `--yes reset` confirmation bypass, including the persisted
 *     active_account clear + .resume-hint removal, targeted (non-active)
 *     reset leaving the config byte-identical, and reset of an unknown
 *     account failing with a nonzero exit;
 *   - the up-front "Cannot add/edit/remove ... right now" refusal when the
 *     config holds unrecognized sections (AR-03 M9) — asserted to fire
 *     BEFORE any interactive prompt is shown;
 *   - account names with an embedded ".sock" (valid per validate_name)
 *     versus the current.sock symlink parser in accounts_detect_current;
 *   - `status` after a simulated stale/foreign runtime symlink;
 *   - `--dry-run` switch being fully side-effect free (no config rewrite,
 *     no ~/.gitconfig, no runtime dirs, no false success banner);
 *   - `init` snippet emission fed back through real bash and fish shells
 *     against a live AF_UNIX socket, plus the quote-in-XDG_RUNTIME_DIR
 *     refusal path;
 *   - exit-code correctness for switch/remove/reset of unknown accounts.
 *
 * NOTE: embedded_sock_name_status_attribution and
 * stale_runtime_link_falls_back_to_saved were authored claiming live
 * misattribution/fallback defects; AR-05 triage disproved both claims (the
 * detector is suffix-anchored with an exact round-trip check, and
 * accounts_detect_current falls back to the saved account on every
 * parse/shape/validate miss). They are kept as PASSING regression pins of
 * that correct behavior. The embedded-name test binds a LIVE account socket
 * because the detector deliberately attributes only a live, self-owned
 * managed socket — a dangling target takes the saved-account fallback.
 *
 * PTY driver is the same dependency-free expect-style harness as
 * tests/test_pty.c. Everything runs inside throwaway HOME/XDG_RUNTIME_DIR
 * sandboxes; the operator's real git/ssh/gpg state is never touched. */
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EXPECT_TIMEOUT_MS 10000
#define EXIT_TIMEOUT_MS   15000

static char g_bin[4096];
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
        fprintf(stderr, "test_ar05_pty: gitswitch binary not found/executable at '%s' "
                        "(run via `make test`, or set GITSWITCH_BIN)\n", bin);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- sandbox */

static const char *make_temp_dir(char *buf, size_t size) {
    snprintf(buf, size, "/tmp/gswar5-XXXXXX");
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
        fprintf(stderr, "test_ar05_pty: failed to remove %s\n", path);
    }
}

typedef struct {
    char home[128];
    char rt[128];
    char cfg[256];
    char key[192];
} sandbox_t;

static int write_file_mode(const char *path, const char *body, mode_t mode) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(body, f);
    if (fclose(f) != 0) return -1;
    return chmod(path, mode);
}

/* Base sandbox: throwaway HOME (with a dummy 0600 SSH key and 0700 config
 * dirs) + throwaway XDG_RUNTIME_DIR. The accounts.toml body is supplied per
 * test via sandbox_write_cfg (0600). */
static int sandbox_setup(sandbox_t *sb) {
    char path[512];

    if (!make_temp_dir(sb->home, sizeof(sb->home)) ||
        !make_temp_dir(sb->rt, sizeof(sb->rt))) {
        return -1;
    }

    snprintf(sb->key, sizeof(sb->key), "%s/key_ed25519", sb->home);
    if (write_file_mode(sb->key,
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                        0600) != 0) return -1;

    snprintf(path, sizeof(path), "%s/.config", sb->home);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", sb->home);
    if (mkdir(path, 0700) != 0) return -1;

    snprintf(sb->cfg, sizeof(sb->cfg), "%s/.config/gitswitch/accounts.toml", sb->home);
    return 0;
}

static int sandbox_write_cfg(sandbox_t *sb, const char *body) {
    return write_file_mode(sb->cfg, body, 0600);
}

static void sandbox_teardown(sandbox_t *sb) {
    remove_tree(sb->home);
    remove_tree(sb->rt);
}

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

static int file_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* Create $XDG_RUNTIME_DIR/gitswitch-ssh (0700) and point current.sock at
 * an ssh-agent.<name>.sock target inside it (dangling is fine — the
 * detector only readlinks). */
static int plant_runtime_link(const sandbox_t *sb, const char *account_name) {
    char dir[256], link[320], target[448];
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", sb->rt);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
    if (chmod(dir, 0700) != 0) return -1;
    snprintf(link, sizeof(link), "%s/current.sock", dir);
    snprintf(target, sizeof(target), "%s/ssh-agent.%s.sock", dir, account_name);
    unlink(link);
    return symlink(target, link);
}

/* Bind a real AF_UNIX socket at <rt>/gitswitch-ssh/ssh-agent.<name>.sock so
 * the account detector's live-socket validation passes. Returns the bound fd
 * (caller closes) or -1. */
static int bind_account_sock(const sandbox_t *sb, const char *account_name) {
    char dir[256], sock_path[448];
    struct sockaddr_un addr;
    int fd;

    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", sb->rt);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
    if (chmod(dir, 0700) != 0) return -1;
    snprintf(sock_path, sizeof(sock_path), "%s/ssh-agent.%s.sock", dir,
             account_name);
    if (strlen(sock_path) >= sizeof(addr.sun_path)) return -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* length checked against sun_path above; memcpy avoids the
     * format-truncation diagnostic a bounded %s would draw here */
    memcpy(addr.sun_path, sock_path, strlen(sock_path) + 1);
    unlink(sock_path);
    /* listen(): the detector's liveness probe connect()s to the socket, so a
     * bound-but-unlistening inode reads as dead and takes the fallback. */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        chmod(sock_path, 0600) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Bind a real AF_UNIX socket at <rt>/gitswitch-ssh/current.sock so the shell
 * snippet's `-S` test passes. Returns the listening fd (caller closes) or -1. */
static int bind_current_sock(const sandbox_t *sb, char *sock_path, size_t sock_size) {
    char dir[256];
    struct sockaddr_un addr;
    int fd;

    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", sb->rt);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(sock_path, sock_size, "%s/current.sock", dir);
    if (strlen(sock_path) >= sizeof(addr.sun_path)) return -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    unlink(sock_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Run a shell command (built by the caller with sandbox paths — none of which
 * contain quotes or spaces) capturing combined stdout+stderr. Returns the
 * command's exit status via *status (or -1) and the output length. */
static size_t run_capture(const char *cmd, char *out, size_t size, int *status) {
    char full[6144]; /* sized above every caller's cmd buffer + " 2>&1" */
    FILE *p;
    size_t n = 0;
    int rc;

    snprintf(full, sizeof(full), "%s 2>&1", cmd);
    out[0] = '\0';
    *status = -1;
    p = popen(full, "r");
    if (!p) return 0;
    n = fread(out, 1, size - 1, p);
    out[n] = '\0';
    rc = pclose(p);
    if (rc != -1 && WIFEXITED(rc)) *status = WEXITSTATUS(rc);
    return n;
}

/* ---------------------------------------------------------- PTY driver */

#define PTY_OUT_MAX (64 * 1024)

typedef struct {
    int master;
    pid_t pid;
    bool eof;
    size_t out_len;
    size_t scan;
    char out[PTY_OUT_MAX];
} pty_proc_t;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int pty_drain(pty_proc_t *p, int timeout_ms) {
    struct pollfd pfd = { .fd = p->master, .events = POLLIN };
    char tmp[4096];
    ssize_t n;
    int rv;

    if (p->eof) return -1;

    rv = poll(&pfd, 1, timeout_ms);
    if (rv <= 0) return 0;

    n = read(p->master, tmp, sizeof(tmp));
    if (n <= 0) {
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
        sfd = open(slave_name, O_RDWR);
        if (sfd < 0) _exit(126);
        dup2(sfd, STDIN_FILENO);
        dup2(sfd, STDOUT_FILENO);
        dup2(sfd, STDERR_FILENO);
        if (sfd > STDERR_FILENO) close(sfd);
        close(p->master);

        setenv("HOME", sb->home, 1);
        setenv("XDG_RUNTIME_DIR", sb->rt, 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
        setenv("TERM", "dumb", 1);
        unsetenv("XDG_CONFIG_HOME");
        unsetenv("GNUPGHOME");
        unsetenv("SSH_AUTH_SOCK");
        unsetenv("INPUTRC");

        if (chdir(sb->home) != 0) _exit(126);
        execv(g_bin, (char *const *)argv);
        _exit(127);
    }
    return 0;
}

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

static int expect_send(pty_proc_t *p, const char *prompt, const char *answer) {
    if (pty_expect(p, prompt) != 0) return -1;
    return pty_send(p, answer);
}

/* Common config bodies. */
static int write_cfg_work_other(sandbox_t *sb, const char *active) {
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "%s%s%s"
             "\n"
             "[accounts.1]\n"
             "name = \"work\"\n"
             "email = \"w@example.com\"\n"
             "description = \"work account\"\n"
             "ssh_key = \"%s\"\n"
             "\n"
             "[accounts.2]\n"
             "name = \"other\"\n"
             "email = \"o@example.com\"\n"
             "description = \"other account\"\n",
             active ? "active_account = \"" : "",
             active ? active : "",
             active ? "\"\n" : "",
             sb->key);
    return sandbox_write_cfg(sb, cfg);
}

static int write_resume_hint(const sandbox_t *sb, const char *body) {
    char path[300];
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", sb->home);
    return write_file_mode(path, body, 0600);
}

static int resume_hint_exists(const sandbox_t *sb) {
    char path[300];
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", sb->home);
    return file_exists(path);
}

/* ---------------------------------------------------------------- tests */

static pty_proc_t g_p;

/* 1. `--yes reset` must bypass the typed-'yes' confirmation entirely, clear
 *    the persisted active_account (so the next login can't auto-resurrect the
 *    state the user just destroyed — AR-03 T4), and install the explicit
 *    inactive .resume-hint tombstone. */
TEST(reset_yes_bypass_clears_active_state) {
    sandbox_t sb;
    char cfg[16384], hint[300];
    const char *argv[] = { "gitswitch", "-y", "reset", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, "work"), 0);
    CHECK_EQ_INT(write_resume_hint(&sb, "ssh\n"), 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Reset all gitswitch SSH/GPG state"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* The confirmation prompt must never have been shown. */
    CHECK(strstr(g_p.out, "Type 'yes' to continue") == NULL);

    /* The authoritative inactive tombstone leaves the legacy settings key
     * byte-identical without allowing it to be resurrected. */
    CHECK(slurp(sb.cfg, cfg, sizeof(cfg)) > 0);
    CHECK(strstr(cfg, "active_account = \"work\"") != NULL);
    snprintf(hint, sizeof(hint), "%s/.config/gitswitch/.resume-hint", sb.home);
    CHECK(slurp(hint, cfg, sizeof(cfg)) > 0);
    CHECK_STR_EQ(cfg, "none\ninactive=v1\n");

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 2. A targeted `--yes reset <non-active>` must succeed without touching the
 *    persisted config (active_account still names the active account) or the
 *    resume hint. */
TEST(reset_targeted_nonactive_keeps_config) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "-y", "reset", "other", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, "work"), 0);
    CHECK_EQ_INT(write_resume_hint(&sb, "ssh\n"), 0);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Reset gitswitch state for: other"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    CHECK(strstr(g_p.out, "Type 'yes' to continue") == NULL);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);
    CHECK(resume_hint_exists(&sb));

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 3. Reset of an unknown account must fail with a nonzero exit and change
 *    nothing — a typo must not report success while the intended account's
 *    secret-key copy stays on disk. */
TEST(reset_unknown_account_fails_nonzero) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "-y", "reset", "zzz-not-here", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, "work"), 0);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Account not found"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    CHECK(strstr(g_p.out, "Reset gitswitch state") == NULL);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 4. With an unrecognized section in accounts.toml the config is not
 *    rewritable (a rebuild would erase it), so add/edit/remove must refuse
 *    UP FRONT (AR-03 M9) — before showing a single interactive prompt — and
 *    exit nonzero with the config left byte-identical. */
TEST(unrewritable_config_refuses_add_edit_remove_upfront) {
    sandbox_t sb;
    char cfg[1024], before[16384], after[16384];
    size_t before_len, after_len;
    const char *edit_argv[] = { "gitswitch", "edit", "work", NULL };
    const char *add_argv[]  = { "gitswitch", "add", NULL };
    const char *rm_argv[]   = { "gitswitch", "-y", "remove", "work", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"work\"\n"
             "email = \"w@example.com\"\n"
             "description = \"work account\"\n"
             "\n"
             "[custom_junk]\n"
             "foo = \"bar\"\n");
    CHECK_EQ_INT(sandbox_write_cfg(&sb, cfg), 0);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    /* edit: refused before the first prompt. */
    if (pty_spawn(&g_p, edit_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Cannot edit an account right now"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    CHECK(strstr(g_p.out, "Account Name") == NULL);
    CHECK(strstr(g_p.out, "unrecognized section") != NULL);
    pty_close(&g_p);

    /* add: same refusal, no prompts. */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Cannot add an account right now"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    CHECK(strstr(g_p.out, "Account Name") == NULL);
    pty_close(&g_p);

    /* remove --yes: refused before deletion; nothing rewritten. */
    if (pty_spawn(&g_p, rm_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Cannot remove an account right now"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    CHECK(strstr(g_p.out, "Account removed successfully") == NULL);
    pty_close(&g_p);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    sandbox_teardown(&sb);
}

/* 5. Account names may legally embed ".sock" (validate_name allows dots), and
 *    the runtime symlink target is ssh-agent.<name>.sock. The detector must
 *    attribute the active account to the FULL name.
 *
 *    EXPECTED-FAIL on the current tree: accounts_detect_current
 *    (src/accounts.c:1648) finds the FIRST ".sock" in the target, so an
 *    active "alpha.sock.b" is parsed as "alpha" and — because an account
 *    named "alpha" exists — status confidently reports the WRONG account as
 *    active. */
TEST(embedded_sock_name_status_attribution) {
    sandbox_t sb;
    char cfg[1024];
    const char *add_argv[] = { "gitswitch", "-y", "add", NULL };
    const char *st_argv[]  = { "gitswitch", "status", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"alpha\"\n"
             "email = \"a@example.com\"\n"
             "description = \"alpha account\"\n");
    CHECK_EQ_INT(sandbox_write_cfg(&sb, cfg), 0);

    /* The interactive add must accept the embedded-.sock name. */
    if (pty_spawn(&g_p, add_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(expect_send(&g_p, "Account Name:", "alpha.sock.b\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Email Address:", "a2@example.com\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Description (optional):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "SSH Key Path (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "GPG Key ID (optional, Enter to skip):", "\n"), 0);
    CHECK_EQ_INT(expect_send(&g_p, "Preferred Git Scope", "\n"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Account added successfully"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);
    pty_close(&g_p);

    /* Simulate the runtime state a switch to alpha.sock.b leaves behind: a
     * LIVE bound account socket with current.sock pointing at it — the
     * detector deliberately refuses to attribute a dangling target and
     * falls back to saved state instead. */
    int live_sock = bind_account_sock(&sb, "alpha.sock.b");
    CHECK(live_sock >= 0);
    CHECK_EQ_INT(plant_runtime_link(&sb, "alpha.sock.b"), 0);

    if (pty_spawn(&g_p, st_argv, &sb) != 0) {
        CHECK(!"pty_spawn failed");
        if (live_sock >= 0) close(live_sock);
        sandbox_teardown(&sb);
        return;
    }
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* The suffix-anchored detector must attribute the FULL name — the
     * first-.sock misparse this test was authored against would truncate to
     * "alpha" and misattribute the sibling account. */
    CHECK(strstr(g_p.out, "Active Account: alpha.sock.b") != NULL);
    /* And it must NOT claim the sibling account "alpha" is active. */
    CHECK(strstr(g_p.out, "Active Account: alpha (") == NULL);

    if (live_sock >= 0) close(live_sock);
    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 6. A stale current.sock symlink naming a since-removed account must not
 *    erase the user's active-account status: when the symlink can't be
 *    matched to any account, status should fall back to the persisted
 *    active_account exactly as it does when the symlink is absent.
 *
 *    EXPECTED-FAIL on the current tree: accounts_detect_current returns -1
 *    on a parse/match failure WITHOUT calling detect_current_from_saved
 *    (src/accounts.c:1664-1673), so status flips to "No account currently
 *    active" even though settings.active_account = "work" and the git
 *    identity is still work's. */
TEST(stale_runtime_link_falls_back_to_saved) {
    sandbox_t sb;
    const char *st_argv[] = { "gitswitch", "status", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, "work"), 0);
    /* Stale link left behind by an account that no longer exists. */
    CHECK_EQ_INT(plant_runtime_link(&sb, "ghost"), 0);

    if (pty_spawn(&g_p, st_argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* Saved-account fallback, same as a missing symlink — pins the fallback
     * the AR-05 triage verified on every parse/match miss. */
    CHECK(strstr(g_p.out, "Active Account: work") != NULL);
    CHECK(strstr(g_p.out, "No account currently active") == NULL);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 7. `--dry-run` switch must be completely side-effect free: no config
 *    rewrite (active_account untouched), no ~/.gitconfig, no runtime agent
 *    dir, no false "Switched to:" banner — and exit 0 with the DRY RUN
 *    banners present. */
TEST(dry_run_switch_is_side_effect_free) {
    sandbox_t sb;
    char before[16384], after[16384], path[300];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "-n", "-g", "work", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, NULL), 0);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "DRY RUN MODE - No actual changes will be made"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Switching to account: work"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Would set git config (global scope)"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "Would load SSH key"), 0);
    CHECK_EQ_INT(pty_expect(&g_p, "DRY RUN complete - no changes were made"), 0);
    CHECK_EQ_INT(pty_wait_exit(&g_p), 0);

    /* No real-switch success banner. */
    CHECK(strstr(g_p.out, "Switched to:") == NULL);

    /* Config byte-identical (no active_account write, no backup churn). */
    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    /* No git identity written, no agents/sockets minted. */
    snprintf(path, sizeof(path), "%s/.gitconfig", sb.home);
    CHECK(!file_exists(path));
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", sb.rt);
    CHECK(!file_exists(path));
    /* No resume hint either — nothing was activated. */
    CHECK(!resume_hint_exists(&sb));

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 8. Feed `gitswitch init bash` back through a real (non-interactive) bash:
 *    the snippet must be syntactically clean, must NOT export SSH_AUTH_SOCK
 *    when the stable socket is absent, and MUST export it once a real socket
 *    exists at the path. */
TEST(init_bash_snippet_round_trip) {
    sandbox_t sb;
    char cmd[6000], out[8192], sock_path[320], wanted[400];
    int status, sfd;

    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, NULL), 0);

    snprintf(cmd, sizeof(cmd),
             "env -i HOME=%s XDG_RUNTIME_DIR=%s TERM=dumb "
             "PATH=/usr/local/bin:/usr/bin:/bin "
             "bash -c '%s init bash > \"$HOME/snip.sh\" && . \"$HOME/snip.sh\"; "
             "echo SOCK=${SSH_AUTH_SOCK:-unset}'",
             sb.home, sb.rt, g_bin);

    /* Phase A: no socket — SSH_AUTH_SOCK must stay unset, no shell errors. */
    run_capture(cmd, out, sizeof(out), &status);
    CHECK_EQ_INT(status, 0);
    CHECK(strstr(out, "SOCK=unset") != NULL);
    CHECK(strstr(out, "syntax error") == NULL);
    CHECK(strstr(out, "command not found") == NULL);

    /* Phase B: bind a live AF_UNIX socket at the stable path. */
    sfd = bind_current_sock(&sb, sock_path, sizeof(sock_path));
    CHECK(sfd >= 0);
    if (sfd >= 0) {
        run_capture(cmd, out, sizeof(out), &status);
        CHECK_EQ_INT(status, 0);
        snprintf(wanted, sizeof(wanted), "SOCK=%s", sock_path);
        CHECK(strstr(out, wanted) != NULL);
        CHECK(strstr(out, "syntax error") == NULL);
        close(sfd);
    }

    sandbox_teardown(&sb);
}

/* 9. Same round trip through a real fish shell (skipped when fish is not
 *    installed). `status is-interactive` is false under -c, so the resume
 *    probe must not fire; the socket wiring must. */
TEST(init_fish_snippet_round_trip) {
    sandbox_t sb;
    char cmd[6000], out[8192], sock_path[320], wanted[400];
    const char *fish = NULL;
    int status, sfd;

    if (access("/usr/bin/fish", X_OK) == 0) fish = "/usr/bin/fish";
    else if (access("/usr/local/bin/fish", X_OK) == 0) fish = "/usr/local/bin/fish";
    else if (access("/bin/fish", X_OK) == 0) fish = "/bin/fish";
    if (!fish) {
        TS_SKIP("fish", "fish shell is unavailable");
    }

    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, NULL), 0);

    sfd = bind_current_sock(&sb, sock_path, sizeof(sock_path));
    CHECK(sfd >= 0);
    if (sfd < 0) { sandbox_teardown(&sb); return; }

    snprintf(cmd, sizeof(cmd),
             "env -i HOME=%s XDG_RUNTIME_DIR=%s TERM=dumb "
             "PATH=/usr/local/bin:/usr/bin:/bin "
             "%s -c '%s init fish | source; echo RC=$status SOCK=$SSH_AUTH_SOCK'",
             sb.home, sb.rt, fish, g_bin);
    run_capture(cmd, out, sizeof(out), &status);
    CHECK_EQ_INT(status, 0);
    CHECK(strstr(out, "RC=0") != NULL);
    snprintf(wanted, sizeof(wanted), "SOCK=%s", sock_path);
    CHECK(strstr(out, wanted) != NULL);

    close(sfd);
    sandbox_teardown(&sb);
}

/* 10. A quote in XDG_RUNTIME_DIR would break out of the single-quoted shell
 *     assignments `init` emits; the command must refuse (nonzero exit) and
 *     must not emit any partial assignment for a shell to eval. */
TEST(init_refuses_quote_in_runtime_dir) {
    sandbox_t sb;
    sandbox_t qsb;
    const char *argv[] = { "gitswitch", "init", "bash", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }

    /* Point the child's XDG_RUNTIME_DIR at a path containing a single quote.
     * (%.100s: sb.rt is a ~20-char mkdtemp path; the precision only exists to
     * prove to the compiler the suffix always fits.) */
    qsb = sb;
    snprintf(qsb.rt, sizeof(qsb.rt), "%.100s/q'dir", sb.rt);
    CHECK_EQ_INT(mkdir(qsb.rt, 0700), 0);
    if (pty_spawn(&g_p, argv, &qsb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK(pty_wait_exit(&g_p) != 0);
    /* Nothing eval-able may have been emitted. */
    CHECK(strstr(g_p.out, "__gitswitch_auth_sock=") == NULL);
    CHECK(strstr(g_p.out, "SSH_AUTH_SOCK=") == NULL);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

/* 11. Switching to an unknown account must fail with a nonzero exit, print
 *     the failure (no success banner), and leave the config untouched. */
TEST(switch_unknown_account_exit_code) {
    sandbox_t sb;
    char before[16384], after[16384];
    size_t before_len, after_len;
    const char *argv[] = { "gitswitch", "zzz-not-here", NULL };

    SKIP_IF_NO_PTY();
    if (sandbox_setup(&sb) != 0) { CHECK(!"sandbox setup failed"); return; }
    CHECK_EQ_INT(write_cfg_work_other(&sb, NULL), 0);
    before_len = slurp(sb.cfg, before, sizeof(before));
    CHECK(before_len > 0);

    if (pty_spawn(&g_p, argv, &sb) != 0) { CHECK(!"pty_spawn failed"); sandbox_teardown(&sb); return; }
    CHECK_EQ_INT(pty_expect(&g_p, "Failed to switch account"), 0);
    CHECK(pty_wait_exit(&g_p) != 0);
    CHECK(strstr(g_p.out, "Switched to:") == NULL);

    after_len = slurp(sb.cfg, after, sizeof(after));
    CHECK(after_len == before_len && memcmp(before, after, before_len) == 0);

    pty_close(&g_p);
    sandbox_teardown(&sb);
}

TEST_MAIN_BEGIN()
    if (resolve_binary() != 0) {
        fprintf(stderr, "RESULT FAIL: cannot locate gitswitch binary\n");
        return 1;
    }
    {
        int probe = posix_openpt(O_RDWR | O_NOCTTY);
        if (probe < 0 || grantpt(probe) != 0 || unlockpt(probe) != 0 ||
            ptsname(probe) == NULL) {
            g_no_pty = 1;
        }
        if (probe >= 0) close(probe);
    }
    RUN_TEST(reset_yes_bypass_clears_active_state);
    RUN_TEST(reset_targeted_nonactive_keeps_config);
    RUN_TEST(reset_unknown_account_fails_nonzero);
    RUN_TEST(unrewritable_config_refuses_add_edit_remove_upfront);
    RUN_TEST(embedded_sock_name_status_attribution);
    RUN_TEST(stale_runtime_link_falls_back_to_saved);
    RUN_TEST(dry_run_switch_is_side_effect_free);
    RUN_TEST(init_bash_snippet_round_trip);
    RUN_TEST(init_fish_snippet_round_trip);
    RUN_TEST(init_refuses_quote_in_runtime_dir);
    RUN_TEST(switch_unknown_account_exit_code);
TEST_MAIN_END()
