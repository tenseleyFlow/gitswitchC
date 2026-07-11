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
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
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

/* Run a shell command and return its exit code (0..255). AR-06 F33: a crash or
 * signal-kill (SIGSEGV/SIGABRT/ASan abort) must NOT masquerade as an ordinary
 * nonzero failure, or a negative-path `CHECK(rc != 0)` would pass on a broken
 * binary. Distinguish the outcomes: -(1000+signal) for abnormal termination,
 * -1 for a system() failure. Negative-path tests assert rc is a genuine
 * failure exit code (1..125), never one of these sentinels. */
static int run_shell(const char *cmd) {
    int status = system(cmd);
    if (status == -1) {
        return -1;
    }
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
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

/* AR-02 #23 / AR-04 M1: the init snippet must gate the per-shell resume probe
 * on the hint file's exact recorded runtime needs, not just its existence, so
 * a GPG-only account avoids ssh-add while a combined account checks both
 * resources. Assert both exact arms are emitted; a wildcard GPG arm would
 * swallow "ssh gpg" before the combined probe can run. */
TEST(init_snippet_gates_probe_on_hint_content) {
    char rt[256], out_path[4352], cmd[9000], out[8192];

    if (!make_temp_dir(rt, sizeof(rt))) { CHECK(!"mkdtemp failed"); return; }
    snprintf(out_path, sizeof(out_path), "%s/init.out", rt);
    snprintf(cmd, sizeof(cmd),
             "XDG_RUNTIME_DIR='%s' '%s' init bash >'%s' 2>/dev/null", rt, g_bin, out_path);
    CHECK_EQ_INT(run_shell(cmd), 0);

    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "__gitswitch_needs") != NULL);      /* reads the hint content */
    CHECK(strstr(out, "        gpg)") != NULL);           /* exact GPG-only arm */
    CHECK(strstr(out, "        'ssh gpg')") != NULL);     /* exact combined arm */
    CHECK(strstr(out, "*gpg*)") == NULL);                 /* no overlapping wildcard */
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
             /* Keep fd 1 occupied by a read-only file. A merely closed fd can
              * be reused by the sanitizer/runtime before main(), making the
              * supposed failure sink writable on some platforms. */
             "XDG_RUNTIME_DIR='%s' '%s' init bash 1</dev/null 2>/dev/null", rt, g_bin);
    rc = run_shell(cmd);
    CHECK(rc > 0 && rc < 126);
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
    CHECK(rc > 0 && rc < 126);
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

/* AR-02 #13: the two must-resume safety guards in resume_already_applied.
 * The no-op fast path may only engage when the live GNUPGHOME `current`
 * symlink points at THIS account's real home; a stale link left at some OTHER
 * account's home, or a dangling link after `gitswitch reset`, must not
 * suppress the restore. Both assert the restore is attempted (the "restoring"
 * stderr notice), like resume_gpg_only_attempts_restore_after_boot_wipe. */
TEST(resume_gpg_only_restores_when_current_points_at_other_account) {
    char home[256], rt[256], path[4352], target[4352], cmd[16384];
    char cfg[1024], err[8192], err_path[4352];

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("global", cfg, sizeof(cfg))), 0);

    /* `current` resolves to a REAL isolated home — but a different account's. */
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", rt);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/otheracct", rt);
    CHECK_EQ_INT(mkdir(target, 0700), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", rt);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(err_path, sizeof(err_path), "%s/resume.err", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume </dev/null >/dev/null 2>'%s'",
             home, rt, g_bin, err_path);
    (void)run_shell(cmd); /* the switch itself fails (no real key): irrelevant */

    slurp(err_path, err, sizeof(err));
    CHECK(strstr(err, "restoring") != NULL); /* must NOT silently no-op */

    remove_tree(home);
    remove_tree(rt);
}

/* A live directory outside the managed GPG base is not this account's
 * isolated home merely because its basename matches. The old resume probe
 * compared only "gpgonly" and followed the link, silently accepting this
 * external target. */
TEST(resume_gpg_only_restores_when_same_basename_is_external) {
    char home[256], rt[256], external[256];
    char path[4352], target[4352], cmd[16384];
    char cfg[1024], err[8192], err_path[4352];

    if (!make_temp_dir(home, sizeof(home)) ||
        !make_temp_dir(rt, sizeof(rt)) ||
        !make_temp_dir(external, sizeof(external))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("global", cfg, sizeof(cfg))), 0);

    snprintf(target, sizeof(target), "%s/gpgonly", external);
    CHECK_EQ_INT(mkdir(target, 0700), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", rt);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", rt);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(err_path, sizeof(err_path), "%s/resume.err", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume </dev/null >/dev/null 2>'%s'",
             home, rt, g_bin, err_path);
    (void)run_shell(cmd);

    slurp(err_path, err, sizeof(err));
    CHECK(strstr(err, "restoring") != NULL);

    remove_tree(home);
    remove_tree(rt);
    remove_tree(external);
}

TEST(resume_gpg_only_restores_when_current_dangles) {
    char home[256], rt[256], path[4352], target[4352], cmd[16384];
    char cfg[1024], err[8192], err_path[4352];

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, gpg_only_config("global", cfg, sizeof(cfg))), 0);

    /* `current` names this account's home, but the home is GONE — the state
     * `gitswitch reset gpgonly` leaves behind. */
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", rt);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/gpgonly", rt);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", rt);
    CHECK_EQ_INT(symlink(target, path), 0); /* dangling: target never created */

    snprintf(err_path, sizeof(err_path), "%s/resume.err", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume </dev/null >/dev/null 2>'%s'",
             home, rt, g_bin, err_path);
    (void)run_shell(cmd);

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
    char dir[512], sock[768];
    FILE *f;
    int n;

    n = snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", rt);
    if (n < 0 || (size_t)n >= sizeof(dir)) return -1;
    if (mkdir(dir, 0700) != 0) return -1;

    n = snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    if (n < 0 || (size_t)n >= sizeof(sock)) return -1;
    f = fopen(sock, "w");
    if (!f) return -1;
    fclose(f);
    if (chmod(sock, 0600) != 0) return -1;

    n = snprintf(sock, sizeof(sock), "%s/ssh-agent.other.sock", dir);
    if (n < 0 || (size_t)n >= sizeof(sock)) return -1;
    f = fopen(sock, "w");
    if (!f) return -1;
    fclose(f);
    if (chmod(sock, 0600) != 0) return -1;

    n = snprintf(cur_link, cur_size, "%s/current.sock", dir);
    if (n < 0 || (size_t)n >= cur_size) return -1;
    n = snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    if (n < 0 || (size_t)n >= sizeof(sock)) return -1;
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

/* ---------- AR-02 #1/#17 + AR-03 L10/L11: config-lock behavior ---------- */

/* Mutating commands must fail fast on cross-process config-lock contention;
 * waiting is unbounded because the holder may be stopped at an interactive
 * prompt. `resume` is launched implicitly by shell startup, so contention is
 * instead a silent successful no-op. Genuinely read-only commands still skip
 * the lock, while `config` must take it because it can create accounts.toml.
 *
 * The child releases early when the parent writes `release`; the timeout keeps
 * this test from deadlocking against the pre-L10 blocking implementation and
 * provides fail-before evidence for the new assertions. */
TEST(mutating_commands_fail_fast_on_config_lock_readonly_dont) {
    char home[256], rt[256], lockpath[4352], config_path[4352];
    char held[4352], done[4352], release[4352], out_path[4352];
    char cmd[16384], out[8192];
    pid_t pid;
    int status = 0, waited = 0, rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home, two_ssh_accounts_config()), 0);
    snprintf(lockpath, sizeof(lockpath), "%s/.config/gitswitch/.config.lock", home);
    snprintf(config_path, sizeof(config_path), "%s/.config/gitswitch/accounts.toml", home);
    snprintf(held, sizeof(held), "%s/lock-held", rt);
    snprintf(done, sizeof(done), "%s/lock-done", rt);
    snprintf(release, sizeof(release), "%s/lock-release", rt);
    snprintf(out_path, sizeof(out_path), "%s/command.out", rt);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
        int child_waited = 0;
        FILE *m;
        int fd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || flock(fd, LOCK_EX) != 0) _exit(9);
        m = fopen(held, "w");
        if (!m) _exit(9);
        fclose(m);
        while (access(release, F_OK) != 0 && child_waited < 5000) {
            nanosleep(&ts, NULL);
            child_waited += 10;
        }
        m = fopen(done, "w");   /* written BEFORE releasing the lock */
        if (!m) _exit(9);
        fclose(m);
        flock(fd, LOCK_UN);
        close(fd);
        _exit(0);
    }

    while (access(held, F_OK) != 0 && waited < 5000) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
        nanosleep(&ts, NULL);
        waited += 10;
    }
    CHECK(access(held, F_OK) == 0);

    /* Read-only: list completes while the lock is held (it must not take it). */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' list >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    CHECK(access(done, F_OK) != 0); /* returned before the holder released */

    /* Shell-startup resume: contention is a silent successful no-op. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' resume >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    CHECK(access(done, F_OK) != 0);
    /* Debug builds emit their normal logger-init line; "silent" here means no
     * user-facing contention diagnostic. Release builds emit nothing. */
    CHECK(strstr(slurp(out_path, out, sizeof(out)), "config lock") == NULL);

    /* Ordinary mutating commands report contention and return immediately. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y reset >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK(rc > 0 && rc < 126);
    CHECK(access(done, F_OK) != 0);
    CHECK(strstr(slurp(out_path, out, sizeof(out)),
                 "Another gitswitch holds the config lock") != NULL);

    /* `config` is not purely read-only: when the file is absent it offers to
     * create it. It must therefore contend instead of writing outside the
     * lock, and the piped confirmation must remain unconsumed. */
    CHECK_EQ_INT(unlink(config_path), 0);
    snprintf(cmd, sizeof(cmd),
             "printf 'y\\n' | HOME='%s' XDG_RUNTIME_DIR='%s' '%s' config >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK(rc > 0 && rc < 126);
    CHECK(access(done, F_OK) != 0);
    CHECK(access(config_path, F_OK) != 0);
    CHECK(strstr(slurp(out_path, out, sizeof(out)),
                 "Another gitswitch holds the config lock") != NULL);

    FILE *m = fopen(release, "w");
    CHECK(m != NULL);
    if (m) fclose(m);

    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    remove_tree(home);
    remove_tree(rt);
}

/* ---------- AR-02 #6 end-to-end: UTF-8 names must not brick the config ---- */

/* An accented account name written to accounts.toml must survive the whole
 * CLI round trip: list shows it, remove deletes it, and no command fails the
 * whole-config load. Pre-fix the raw-buffer charset gate rejected every byte
 * >= 0x80, so one such name made every invocation exit 2 — including the
 * remove that could have deleted it. */
TEST(utf8_account_name_cli_round_trip) {
    char home[256], rt[256], cmd[16384], out_path[4352], out[8192];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"Jos\xC3\xA9 Work\"\n"
        "email = \"jose@example.com\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"plain\"\n"
        "email = \"p@example.com\"\n"), 0);

    snprintf(out_path, sizeof(out_path), "%s/list.out", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' list >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "Jos\xC3\xA9 Work") != NULL); /* byte-identical, not "Jos" */

    /* The tool itself can remove the accented account (pre-fix it could not
     * even load the file to try). */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y remove 1 >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    snprintf(out_path, sizeof(out_path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "Jos\xC3\xA9") == NULL);
    CHECK(strstr(out, "plain") != NULL); /* the other account survived the save */

    remove_tree(home);
    remove_tree(rt);
}

/* AR-03 L15: with color disabled (piped stdout, or explicit --no-color) no
 * raw ANSI escape byte may reach the stream. display_header used to append an
 * unconditional COLOR_RESET, so every banner leaked ESC[0m into pipes —
 * display_colorize owns the reset now, and it emits nothing with color off. */
TEST(no_color_output_contains_no_escape_bytes) {
    char home[256], rt[256], cmd[16384], out_path[4352], out[8192];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }

    /* No accounts: the bare invocation renders the welcome banner via
     * display_header. stdout is a file, so color auto-disables. */
    snprintf(out_path, sizeof(out_path), "%s/welcome.out", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "Welcome") != NULL); /* the banner actually rendered */
    CHECK(strchr(out, '\x1b') == NULL);

    /* Same guarantee under explicit --no-color with an account listed. */
    CHECK_EQ_INT(write_config(home,
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"plain\"\n"
        "email = \"p@example.com\"\n"), 0);
    snprintf(out_path, sizeof(out_path), "%s/list.out", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' --no-color list >'%s' 2>&1",
             home, rt, g_bin, out_path);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "plain") != NULL);
    CHECK(strchr(out, '\x1b') == NULL);

    remove_tree(home);
    remove_tree(rt);
}

/* ---------- AR-03 add-flow input validation (L1, L2, L3, M5) ---------- */

/* Write `body` to <rt>/add.stdin for feeding the interactive add flow. */
static int write_stdin_script(const char *rt, const char *body,
                              char *path, size_t path_size) {
    FILE *f;
    snprintf(path, path_size, "%s/add.stdin", rt);
    f = fopen(path, "w");
    if (!f) return -1;
    fputs(body, f);
    return fclose(f);
}

/* Run `gitswitch -y add` with scripted stdin; stdout+stderr land in out_path. */
static int run_add(const char *home, const char *rt, const char *stdin_path,
                   const char *out_path) {
    char cmd[16384];
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y add <'%s' >'%s' 2>&1",
             home, rt, g_bin, stdin_path, out_path);
    return run_shell(cmd);
}

/* Create a 0600 private-key-shaped file so the add flow's key validation
 * passes; returns 0 on success. */
static int write_key_file(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
          "-----END OPENSSH PRIVATE KEY-----\n", f);
    if (fclose(f) != 0) return -1;
    return chmod(path, 0600);
}

/* AR-03 L3: with a hand-planted [accounts.4294967295], `add` used to assign
 * max_id+1 == 0 — an id the loader rejects, so the new account "saved" into a
 * config no later command could load. The add must fall back to the lowest
 * unused id instead. */
TEST(add_after_uint32_max_id_does_not_wrap_to_zero) {
    char home[256], rt[256], stdin_path[4352], out_path[4352], cmd[16384];
    char toml_path[4352], toml[8192];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.4294967295]\n"
        "name = \"maxed\"\n"
        "email = \"m@example.com\"\n"), 0);

    /* name, email, description, SSH skip, GPG skip, scope default. */
    CHECK_EQ_INT(write_stdin_script(rt,
        "newacct\nn@example.com\nnew account\n\n\n\n",
        stdin_path, sizeof(stdin_path)), 0);
    snprintf(out_path, sizeof(out_path), "%s/add.out", rt);
    rc = run_add(home, rt, stdin_path, out_path);
    CHECK_EQ_INT(rc, 0);

    /* The wrapped id 0 must not be persisted; the fallback id 1 must be. */
    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(toml_path, toml, sizeof(toml));
    CHECK(strstr(toml, "[accounts.0]") == NULL);
    CHECK(strstr(toml, "[accounts.1]") != NULL);
    CHECK(strstr(toml, "newacct") != NULL);

    /* And the config is still loadable (pre-fix: bricked by the id-0 entry). */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' list >/dev/null 2>&1",
             home, rt, g_bin);
    CHECK_EQ_INT(run_shell(cmd), 0);

    remove_tree(home);
    remove_tree(rt);
}

/* AR-03 L2: the host-alias prompt must reject aliases the ~/.ssh/config
 * writer can't take verbatim (quotes/control bytes) and aliases too long for
 * the account field (>= 256: safe_strncpy used to fail silently and the alias
 * was dropped while add still reported success), re-prompting each time. */
TEST(add_reprompts_invalid_host_alias_until_valid) {
    char home[256], rt[256], stdin_path[4352], out_path[4352];
    char key_path[512], toml_path[4352], toml[8192], script[1024];
    char long_alias[321];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\ndefault_scope = \"global\"\n"), 0);
    snprintf(key_path, sizeof(key_path), "%s/id_test", home);
    CHECK_EQ_INT(write_key_file(key_path), 0);

    memset(long_alias, 'a', sizeof(long_alias) - 1);
    long_alias[sizeof(long_alias) - 1] = '\0';

    /* name, email, description, SSH key, then three alias answers: a quoted
     * one (charset), an overlong one (length), then a valid one; GPG skip,
     * scope default. */
    snprintf(script, sizeof(script),
             "aliasacct\na@example.com\nalias test\n%s\n"
             "bad\"alias\n%s\ngithub.com-good\n\n\n",
             key_path, long_alias);
    CHECK_EQ_INT(write_stdin_script(rt, script, stdin_path, sizeof(stdin_path)), 0);
    snprintf(out_path, sizeof(out_path), "%s/add.out", rt);
    rc = run_add(home, rt, stdin_path, out_path);
    CHECK_EQ_INT(rc, 0);

    /* Only the valid alias may be persisted — not the quoted one (pre-fix it
     * was accepted verbatim) and not a silent drop of all three. */
    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(toml_path, toml, sizeof(toml));
    CHECK(strstr(toml, "github.com-good") != NULL);
    CHECK(strstr(toml, "bad\"alias") == NULL);

    remove_tree(home);
    remove_tree(rt);
}

/* AR-03 M5 (write entry): the loader skips accounts whose ssh_key exceeds 256
 * chars, so the add prompt must refuse such a path up front with a re-prompt —
 * pre-fix it saved the account and the very next invocation dropped it. */
TEST(add_refuses_ssh_key_path_over_256_chars) {
    char home[256], rt[256], stdin_path[4352], out_path[4352];
    char dir_a[512], dir_b[768], key_path[1024];
    char toml_path[4352], toml[8192], out[8192], script[1280], seg[130];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\ndefault_scope = \"global\"\n"), 0);

    /* Two 120-char directory components push the key path well past 256
     * while every component stays under NAME_MAX. */
    memset(seg, 'd', 120);
    seg[120] = '\0';
    snprintf(dir_a, sizeof(dir_a), "%s/a%s", home, seg);
    CHECK_EQ_INT(mkdir(dir_a, 0700), 0);
    snprintf(dir_b, sizeof(dir_b), "%s/b%s", dir_a, seg);
    CHECK_EQ_INT(mkdir(dir_b, 0700), 0);
    snprintf(key_path, sizeof(key_path), "%s/id_long", dir_b);
    CHECK_EQ_INT(write_key_file(key_path), 0);
    CHECK(strlen(key_path) > 256);

    /* name, email, description, overlong key (refused), Enter to skip SSH,
     * GPG skip, scope default. */
    snprintf(script, sizeof(script),
             "longkey\nl@example.com\nlong key test\n%s\n\n\n\n", key_path);
    CHECK_EQ_INT(write_stdin_script(rt, script, stdin_path, sizeof(stdin_path)), 0);
    snprintf(out_path, sizeof(out_path), "%s/add.out", rt);
    rc = run_add(home, rt, stdin_path, out_path);
    CHECK_EQ_INT(rc, 0);

    slurp(out_path, out, sizeof(out));
    CHECK(strstr(out, "max 256") != NULL); /* the refusal was explicit */

    /* The overlong path must not be persisted (pre-fix it was, and the next
     * load skipped the whole account). */
    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(toml_path, toml, sizeof(toml));
    CHECK(strstr(toml, "id_long") == NULL);
    CHECK(strstr(toml, "longkey") != NULL); /* the account itself saved */

    remove_tree(home);
    remove_tree(rt);
}

/* AR-03 L1 (both halves): an exactly-320-char email must be re-prompted, not
 * accepted. Pre-fix validate_email's `>` bound admitted it, the copy into
 * email[320] failed silently, and the add aborted at the end with a
 * misleading "Invalid name or email" — exit nonzero, nothing saved. */
TEST(add_reprompts_email_at_exact_length_bound) {
    char home[256], rt[256], stdin_path[4352], out_path[4352];
    char toml_path[4352], toml[8192], script[2048], long_email[321];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\ndefault_scope = \"global\"\n"), 0);

    /* 313 a's + "@ex.com" == exactly 320 chars, format-valid. */
    memset(long_email, 'a', 313);
    long_email[313] = '\0';
    strcat(long_email, "@ex.com");
    CHECK_EQ_INT((int)strlen(long_email), 320);

    /* name, overlong email (re-prompted), valid email, description, SSH skip,
     * GPG skip, scope default. */
    snprintf(script, sizeof(script),
             "emailacct\n%s\ne@example.com\nemail test\n\n\n\n", long_email);
    CHECK_EQ_INT(write_stdin_script(rt, script, stdin_path, sizeof(stdin_path)), 0);
    snprintf(out_path, sizeof(out_path), "%s/add.out", rt);
    rc = run_add(home, rt, stdin_path, out_path);
    CHECK_EQ_INT(rc, 0); /* pre-fix: the add aborted with exit 1 */

    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(toml_path, toml, sizeof(toml));
    CHECK(strstr(toml, "e@example.com") != NULL);

    remove_tree(home);
    remove_tree(rt);
}

/* ---------- AR-03 T4: resume-hint writer end-to-end ---------- */

/* A -y switch to an identity-only account must leave .resume-hint with the
 * exact content "none\n" (the snippet's no-probe arm), and a -y reset must
 * remove the marker AND the persisted active_account — pre-fix reset touched
 * neither, so every later login shell auto-resumed (re-created agents,
 * re-imported GPG keys for) the state the user had just torn down. */
TEST(switch_writes_resume_hint_and_reset_clears_it) {
    char home[256], rt[256], cmd[16384], hint[4352], toml_path[4352];
    char buf[8192];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"solo\"\n"
        "email = \"s@example.com\"\n"
        "preferred_scope = \"global\"\n"), 0); /* global: write only $HOME/.gitconfig */
    snprintf(hint, sizeof(hint), "%s/.config/gitswitch/.resume-hint", home);
    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);

    /* Switch: identity-only, global scope — only git config is written. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y solo </dev/null >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);

    /* Exact content: the shell snippet string-matches on it. */
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "none\n");
    slurp(toml_path, buf, sizeof(buf));
    CHECK(strstr(buf, "active_account = \"solo\"") != NULL);

    /* Reset (full): marker gone, active_account cleared. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y reset >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    CHECK(access(hint, F_OK) != 0);                       /* pre-fix: stale marker */
    slurp(toml_path, buf, sizeof(buf));
    CHECK(strstr(buf, "active_account = \"solo\"") == NULL); /* pre-fix: still "solo" */

    remove_tree(home);
    remove_tree(rt);
}

/* ---------- AR-03 M8/M9: partial load must fail closed, loudly ---------- */

/* One healthy account, one section the loader skips (over-long name), one
 * unrecognized section. `add` must refuse up front with a nonzero exit
 * (pre-fix: full interactive flow, "Account added successfully!", exit 0,
 * nothing persisted). A switch to the healthy account must still persist
 * active_account via the settings-only write-back (pre-fix: silently
 * dropped), and both problem sections must survive every step (pre-fix M8:
 * the unrecognized one was erased by any completed save). */
TEST(partial_load_blocks_add_but_switch_persists_active) {
    char home[256], rt[256], cmd[16384], stdin_path[4352], out_path[4352];
    char toml_path[4352], buf[8192], cfg[2048], longname[300];
    int rc;

    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    memset(longname, 'N', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"good\"\n"
             "email = \"g@example.com\"\n"
             "preferred_scope = \"global\"\n"
             "\n"
             "[accounts.2]\n"
             "name = \"%s\"\n"
             "email = \"long@example.com\"\n"
             "\n"
             "[account.3]\n"
             "name = \"typod\"\n"
             "email = \"t@example.com\"\n",
             longname);
    CHECK_EQ_INT(write_config(home, cfg), 0);
    snprintf(toml_path, sizeof(toml_path), "%s/.config/gitswitch/accounts.toml", home);

    /* add: refused before any prompt is consumed, nonzero exit. */
    CHECK_EQ_INT(write_stdin_script(rt,
        "newacct\nn@example.com\ndesc\n\n\n\n", stdin_path, sizeof(stdin_path)), 0);
    snprintf(out_path, sizeof(out_path), "%s/add.out", rt);
    rc = run_add(home, rt, stdin_path, out_path);
    CHECK(rc > 0 && rc < 126);                                /* pre-fix: 0 */
    slurp(toml_path, buf, sizeof(buf));
    CHECK(strstr(buf, "newacct") == NULL);
    slurp(out_path, buf, sizeof(buf));
    CHECK(strstr(buf, "Account added successfully") == NULL); /* pre-fix banner */

    /* remove: same up-front refusal. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y remove good >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK(rc > 0 && rc < 126);
    slurp(toml_path, buf, sizeof(buf));
    CHECK(strstr(buf, "\"good\"") != NULL);        /* nothing was rewritten */

    /* switch: succeeds AND persists active_account without touching the
     * skipped/unknown sections. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y good </dev/null >/dev/null 2>&1",
             home, rt, g_bin);
    rc = run_shell(cmd);
    CHECK_EQ_INT(rc, 0);
    slurp(toml_path, buf, sizeof(buf));
    CHECK(strstr(buf, "active_account = \"good\"") != NULL); /* pre-fix: absent */
    CHECK(strstr(buf, longname) != NULL);                    /* skipped intact */
    CHECK(strstr(buf, "[account.3]") != NULL);               /* unknown intact (M8) */

    remove_tree(home);
    remove_tree(rt);
}

/* ---------- AR-03 M9: save failure must surface in the exit code ---------- */

/* Deny the config directory write permission after load: the switch itself
 * succeeds (git config is written), the save cannot create its temp file, and
 * the command must exit nonzero — pre-fix it warned and exited 0, so scripted
 * callers could not detect that active_account went stale. */
TEST(switch_save_failure_exits_nonzero) {
    char home[256], rt[256], cmd[16384], dir[512], lock[640], err_path[512];
    char buf[8192];
    int rc;

    if (getuid() == 0) {
        fprintf(stderr, "  (skipped: running as root, permission denial won't bite)\n");
        return;
    }
    if (!make_temp_dir(home, sizeof(home)) || !make_temp_dir(rt, sizeof(rt))) {
        CHECK(!"mkdtemp failed");
        return;
    }
    CHECK_EQ_INT(write_config(home,
        "[settings]\n"
        "default_scope = \"global\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"solo\"\n"
        "email = \"s@example.com\"\n"
        "preferred_scope = \"global\"\n"), 0);

    /* Pre-create the lock file (the locked open needs no dir write), then
     * make the config dir read-only so the save's temp create fails. */
    snprintf(dir, sizeof(dir), "%s/.config/gitswitch", home);
    snprintf(lock, sizeof(lock), "%s/.config.lock", dir);
    FILE *f = fopen(lock, "w");
    CHECK(f != NULL);
    if (f) fclose(f);
    CHECK_EQ_INT(chmod(lock, 0600), 0);
    CHECK_EQ_INT(chmod(dir, 0500), 0);

    snprintf(err_path, sizeof(err_path), "%s/switch.out", rt);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -y solo </dev/null >'%s' 2>&1",
             home, rt, g_bin, err_path);
    rc = run_shell(cmd);
    CHECK(rc > 0 && rc < 126);                                 /* pre-fix: 0 */
    slurp(err_path, buf, sizeof(buf));
    CHECK(strstr(buf, "Failed to save configuration changes") != NULL);

    chmod(dir, 0700); /* so remove_tree can clean up */
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
    RUN_TEST(resume_gpg_only_restores_when_current_points_at_other_account);
    RUN_TEST(resume_gpg_only_restores_when_same_basename_is_external);
    RUN_TEST(resume_gpg_only_restores_when_current_dangles);
    RUN_TEST(resume_never_blocks_reading_stdin);
    RUN_TEST(reset_account_removes_current_sock_pointing_at_it);
    RUN_TEST(reset_other_account_keeps_current_sock);
    RUN_TEST(mutating_commands_fail_fast_on_config_lock_readonly_dont);
    RUN_TEST(utf8_account_name_cli_round_trip);
    RUN_TEST(no_color_output_contains_no_escape_bytes);
    RUN_TEST(add_after_uint32_max_id_does_not_wrap_to_zero);
    RUN_TEST(add_reprompts_invalid_host_alias_until_valid);
    RUN_TEST(add_refuses_ssh_key_path_over_256_chars);
    RUN_TEST(add_reprompts_email_at_exact_length_bound);
    RUN_TEST(switch_writes_resume_hint_and_reset_clears_it);
    RUN_TEST(partial_load_blocks_add_but_switch_persists_active);
    RUN_TEST(switch_save_failure_exits_nonzero);
TEST_MAIN_END()
