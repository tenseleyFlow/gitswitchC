/* End-to-end CLI regression tests for main.c command behaviors. These freeze
 * the audit fixes F2 (GPG-only resume must not re-run on every shell), F3
 * (`reset <account>` must drop a current.sock pointing at that account) and
 * SIPW-1 (`init` must fail on stdout write errors instead of letting a
 * truncated snippet get eval'd).
 *
 * main.c is deliberately excluded from the test link (it defines main), so
 * these tests drive the built binary itself: each test builds a throwaway
 * HOME + XDG_RUNTIME_DIR and runs $GITSWITCH_BIN (default build/bin/gitswitch,
 * built by the `test` target) through /bin/sh. */
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
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Absolute path to the binary under test (execution may happen after chdir). */
static char g_bin[4096];

static int resolve_binary(void) {
    const char *bin = getenv("GITSWITCH_BIN");
    if (!bin || !*bin) {
        bin = "build/bin/gitswitch";
    }
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_cli: gitswitch binary not found/executable at '%s' "
                        "(run via `make test`, or set GITSWITCH_BIN)\n", bin);
        return -1;
    }
    return 0;
}

/* Fresh throwaway directory under the system temp dir. Returns a pointer to a
 * per-call static buffer (tests are sequential). */
static const char *make_temp_dir(char *buf, size_t size) {
    snprintf(buf, size, "/tmp/gitswitch-test-XXXXXX");
    if (!mkdtemp(buf)) {
        return NULL;
    }
    return buf;
}

static void remove_tree(const char *path) {
    char cmd[4352];
    if (!path || path[0] == '\0' || strstr(path, "'") != NULL) {
        return;
    }
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        fprintf(stderr, "test_cli: failed to remove %s\n", path);
    }
}

/* Write an accounts.toml (0600, inside 0700 dirs) under `home`. */
static int write_config(const char *home, const char *body) {
    char path[4352];
    FILE *f;

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    f = fopen(path, "w");
    if (!f) return -1;
    fputs(body, f);
    if (fclose(f) != 0) return -1;
    return chmod(path, 0600);
}

/* Run a shell command; return the process exit code (or -1 on abnormal exit). */
static int run_shell(const char *cmd) {
    int status = system(cmd);
    if (status == -1 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

/* Read a whole (small) file into buf; returns "" on any failure. */
static const char *slurp(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n = 0;
    buf[0] = '\0';
    if (!f) return buf;
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* ---------- SIPW-1: `init` must detect stdout write failure ---------- */

TEST(init_succeeds_and_emits_full_snippet) {
    char rt[256], out_path[4352], cmd[9000], out[8192];
    int rc;

    if (!make_temp_dir(rt, sizeof(rt))) { CHECK(!"mkdtemp failed"); return; }
    snprintf(out_path, sizeof(out_path), "%s/init.out", rt);
    snprintf(cmd, sizeof(cmd),
             "XDG_RUNTIME_DIR='%s' '%s' init bash >'%s' 2>/dev/null", rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);

    /* The snippet must be complete: the trailing constructs of both the resume
     * probe (esac) and the SSH_AUTH_SOCK wiring must be present. */
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "esac") != NULL);
    CHECK(strstr(out, "unset __gitswitch_auth_sock") != NULL);
    remove_tree(rt);
}

/* AR-02 #23: the init snippet must gate the per-shell resume probe on the
 * hint file's recorded runtime needs, not just its existence, so an SSH-less
 * active account never spawns a doomed ssh-add + resume on every shell. Assert
 * the content-driven branching is emitted: it reads the hint into
 * __gitswitch_needs and has a GPG-only arm that probes the GNUPGHOME symlink
 * with a builtin `test -d` instead of ssh-add. */
TEST(init_snippet_gates_probe_on_hint_content) {
    char rt[256], out_path[4352], cmd[9000], out[8192];

    if (!make_temp_dir(rt, sizeof(rt))) { CHECK(!"mkdtemp failed"); return; }
    snprintf(out_path, sizeof(out_path), "%s/init.out", rt);
    snprintf(cmd, sizeof(cmd),
             "XDG_RUNTIME_DIR='%s' '%s' init bash >'%s' 2>/dev/null", rt, g_bin, out_path);
    CHECK_EQ_INT(run_shell(cmd), 0);

    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "__gitswitch_needs") != NULL);      /* reads the hint content */
    CHECK(strstr(out, "*gpg*)") != NULL);                 /* GPG-only arm exists */
    CHECK(strstr(out, "-d '") != NULL);                   /* builtin symlink test, not ssh-add */
    remove_tree(rt);
}

/* With stdout closed every write fails; before the SIPW-1 fix `init` ignored
 * printf results and still exited 0, handing eval a truncated/empty script
 * with a success status. */
TEST(init_fails_when_stdout_is_closed) {
    char rt[256], cmd[9000];
    int rc;

    if (!make_temp_dir(rt, sizeof(rt))) { CHECK(!"mkdtemp failed"); return; }
    snprintf(cmd, sizeof(cmd),
             "XDG_RUNTIME_DIR='%s' '%s' init bash >&- 2>/dev/null", rt, g_bin);
    rc = run_shell(cmd);
    CHECK(rc != 0);
    remove_tree(rt);
}

/* Same via ENOSPC on flush (Linux's always-full device). Skipped where
 * /dev/full doesn't exist (macOS/FreeBSD CI). */
TEST(init_fails_on_enospc) {
    char rt[256], cmd[9000];
    int rc;

    if (access("/dev/full", W_OK) != 0) {
        fprintf(stderr, "  (skipped: no /dev/full on this platform)\n");
        return;
    }
    if (!make_temp_dir(rt, sizeof(rt))) { CHECK(!"mkdtemp failed"); return; }
    snprintf(cmd, sizeof(cmd),
             "XDG_RUNTIME_DIR='%s' '%s' init bash >/dev/full 2>/dev/null", rt, g_bin);
    rc = run_shell(cmd);
    CHECK(rc != 0);
    remove_tree(rt);
}

/* ---------- F2: resume gating for GPG-only accounts ---------- */

static const char *gpg_only_config(const char *scope, char *buf, size_t size) {
    snprintf(buf, size,
             "[settings]\n"
             "default_scope = \"global\"\n"
             "active_account = \"gpgonly\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"gpgonly\"\n"
             "email = \"gpg@example.com\"\n"
             "description = \"gpg only account\"\n"
             "preferred_scope = \"%s\"\n"
             "gpg_key = \"ABCDEF0123456789\"\n",
             scope);
    return buf;
}

/* A GPG-only account whose isolated home is live this boot (GNUPGHOME `current`
 * symlink resolves to <base>/<name>): `resume` must be a silent success no-op —
 * no restore notice, no switch attempt. This is the F2 acceptance case: the
 * shell snippet's ssh-add probe fails on every shell for such accounts (no SSH
 * socket ever exists), so anything louder nags on every prompt. */
TEST(resume_gpg_only_noops_silently_when_state_live) {
    char home[256], rt[256], path[4352], target[4352], cmd[16384];
    char cfg[1024], err[8192], out[8192], err_path[4352], out_path[4352];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("global", cfg, sizeof(cfg))), 0);

    /* Simulate a completed switch this boot: isolated home + current symlink. */
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", rt);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/gpgonly", rt);
    CHECK_EQ_INT(mkdir(target, 0700), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", rt);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(out_path, sizeof(out_path), "%s/resume.out", rt);
    snprintf(err_path, sizeof(err_path), "%s/resume.err", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume </dev/null >'%s' 2>'%s'",
             home, rt, g_bin, out_path, err_path);
    rc = run_shell(cmd);

    CHECK_EQ_INT(rc, 0);
    /* No restore notice and no switch: both would re-nag on every shell. */
    slurp(err_path, err, sizeof(err));
    CHECK(strstr(err, "restoring") == NULL);
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "Switching to account") == NULL);

    remove_tree(home);
    remove_tree(rt);
}

/* After a boot wipe (no `current` symlink) resume must still attempt the
 * restore — the first-shell-after-boot behavior the feature exists for. The
 * switch itself fails here (key not in any keyring), which is fine: we only
 * assert the attempt happens. */
TEST(resume_gpg_only_attempts_restore_after_boot_wipe) {
    char home[256], rt[256], cmd[16384], cfg[1024], err[8192], err_path[4352];

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("global", cfg, sizeof(cfg))), 0);

    snprintf(err_path, sizeof(err_path), "%s/resume.err", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume </dev/null >/dev/null 2>'%s'",
             home, rt, g_bin, err_path);
    (void)run_shell(cmd); /* exit code irrelevant: no real GPG key exists */

    slurp(err_path, err, sizeof(err));
    CHECK(strstr(err, "restoring") != NULL);

    remove_tree(home);
    remove_tree(rt);
}

/* Resume must never read stdin. Repro of the F2 hang: local-scope account,
 * cwd not a git repo, stdin a TTY — before the fix accounts_switch printed its
 * global-scope consent prompt to the suppressed stdout and blocked on fgets,
 * freezing every new shell. We give the child a real PTY as stdin (never
 * writing to it) and require that it exits on its own. */
TEST(resume_never_blocks_reading_stdin) {
    char home[256], rt[256], cfg[1024], slave_name[256];
    int master;
    const char *pts;
    pid_t pid;
    int waited_ms = 0;
    int status = 0;
    bool exited = false;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("local", cfg, sizeof(cfg))), 0);

    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 ||
        (pts = ptsname(master)) == NULL) {
        fprintf(stderr, "  (skipped: no PTY available: %s)\n", strerror(errno));
        if (master >= 0) close(master);
        remove_tree(home);
        remove_tree(rt);
        return;
    }
    snprintf(slave_name, sizeof(slave_name), "%s", pts);

    pid = fork();
    if (pid == 0) {
        int sfd, devnull;
        setsid();
        sfd = open(slave_name, O_RDWR); /* becomes the child's TTY stdin */
        devnull = open("/dev/null", O_WRONLY);
        if (sfd < 0 || devnull < 0) _exit(126);
        dup2(sfd, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        setenv("HOME", home, 1);
        setenv("XDG_RUNTIME_DIR", rt, 1);
        if (chdir(home) != 0) _exit(126); /* not a git repo: forces the prompt path */
        execl(g_bin, "gitswitch", "resume", (char *)NULL);
        _exit(127);
    }
    CHECK(pid > 0);

    /* The pre-fix binary blocks forever here (fgets on the PTY we never write
     * to). Give the fixed binary ample time to load, fail the switch closed,
     * and exit. */
    while (waited_ms < 15000) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { exited = true; break; }
        if (r < 0) break;
        usleep(100 * 1000);
        waited_ms += 100;
    }
    if (!exited) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    CHECK(exited); /* must not hang waiting for stdin */

    close(master);
    remove_tree(home);
    remove_tree(rt);
}

/* ---------- F3: reset <account> and the stable current.sock ---------- */

static const char *two_ssh_accounts_config(void) {
    return "[settings]\n"
           "default_scope = \"global\"\n"
           "\n"
           "[accounts.1]\n"
           "name = \"work\"\n"
           "email = \"w@example.com\"\n"
           "\n"
           "[accounts.2]\n"
           "name = \"other\"\n"
           "email = \"o@example.com\"\n";
}

/* Lay out a fake agent dir: per-account socket files for work/other and
 * current.sock -> work's socket. Returns 0 on success. */
static int setup_agent_dir(const char *rt, char *cur_link, size_t cur_size) {
    char dir[4352], sock[4352];
    FILE *f;

    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", rt);
    if (mkdir(dir, 0700) != 0) return -1;

    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    f = fopen(sock, "w");
    if (!f) return -1;
    fclose(f);
    if (chmod(sock, 0600) != 0) return -1;

    snprintf(sock, sizeof(sock), "%s/ssh-agent.other.sock", dir);
    f = fopen(sock, "w");
    if (!f) return -1;
    fclose(f);
    if (chmod(sock, 0600) != 0) return -1;

    snprintf(cur_link, cur_size, "%s/current.sock", dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    return symlink(sock, cur_link);
}

/* Resetting the account current.sock points at must remove current.sock too,
 * or integrated shells keep exporting SSH_AUTH_SOCK at a dead socket. */
TEST(reset_account_removes_current_sock_pointing_at_it) {
    char home[256], rt[256], cur[4352], cmd[16384];
    struct stat st;
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, two_ssh_accounts_config()), 0);
    CHECK_EQ_INT(setup_agent_dir(rt, cur, sizeof(cur)), 0);

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y reset work >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);

    /* The symlink must be gone, not left dangling at the reset account. */
    CHECK(lstat(cur, &st) != 0);

    remove_tree(home);
    remove_tree(rt);
}

/* Resetting a DIFFERENT account must leave a current.sock that points at the
 * still-active account untouched. */
TEST(reset_other_account_keeps_current_sock) {
    char home[256], rt[256], cur[4352], cmd[16384], target[4352];
    struct stat st;
    ssize_t len;
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, two_ssh_accounts_config()), 0);
    CHECK_EQ_INT(setup_agent_dir(rt, cur, sizeof(cur)), 0);

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y reset other >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);

    /* current.sock still present and still pointing at work's socket. */
    CHECK_EQ_INT(lstat(cur, &st), 0);
    len = readlink(cur, target, sizeof(target) - 1);
    CHECK(len > 0);
    if (len > 0) {
        target[len] = '\0';
        CHECK(strstr(target, "ssh-agent.work.sock") != NULL);
    }

    remove_tree(home);
    remove_tree(rt);
}

TEST_MAIN_BEGIN()
    if (resolve_binary() != 0) {
        fprintf(stderr, "RESULT FAIL: cannot locate gitswitch binary\n");
        return 1;
    }
    RUN_TEST(init_succeeds_and_emits_full_snippet);
    RUN_TEST(init_snippet_gates_probe_on_hint_content);
    RUN_TEST(init_fails_when_stdout_is_closed);
    RUN_TEST(init_fails_on_enospc);
    RUN_TEST(resume_gpg_only_noops_silently_when_state_live);
    RUN_TEST(resume_gpg_only_attempts_restore_after_boot_wipe);
    RUN_TEST(resume_never_blocks_reading_stdin);
    RUN_TEST(reset_account_removes_current_sock_pointing_at_it);
    RUN_TEST(reset_other_account_keeps_current_sock);
TEST_MAIN_END()
