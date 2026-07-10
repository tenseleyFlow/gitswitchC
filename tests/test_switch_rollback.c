/* Behavioral tests for accounts_switch failure/interrupt handling:
 *
 *   F4     — a switch to an SSH/GPG-disabled target must NOT tear down the
 *            previously-active account's runtime isolation (current.sock,
 *            GNUPGHOME `current` symlink) until the git-config write — the
 *            point of no return — has succeeded. A failure there leaves the
 *            prior state intact; only a successful switch drops it.
 *   SIG-01 — a SIGINT landing mid git-config write must not kill the process
 *            between durable steps: the guard defers it, the rollback runs
 *            (observable as restore commands issued AFTER the signal), and
 *            the process then re-raises so it still dies by SIGINT.
 *
 * External commands are intercepted with the recording-runner pattern from
 * test_security.c; the runtime symlinks live under a private fake
 * XDG_RUNTIME_DIR so no real agents are involved. */

/* Enable POSIX extensions for mkdtemp/symlink/fork. glibc-only: on macOS and
 * the BSDs the strict macros hide default-namespace declarations (mkdtemp,
 * SA_*) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "accounts.h"
#include "git_ops.h"
#include "utils.h"
#include "error.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- fake runtime dir ---------------------------------------------------- */

static char g_xdg[256];
static char g_ssh_sock[512];   /* <xdg>/gitswitch-ssh/current.sock */
static char g_gpg_link[512];   /* <xdg>/gitswitch-gpg/current */

/* Create a fresh fake XDG_RUNTIME_DIR holding the pre-switch runtime state of
 * a "previous" account: a current.sock symlink and a GNUPGHOME `current`
 * symlink pointing at a real (empty) home dir. Returns 0 on success. */
static int setup_runtime_dir(void) {
    char path[512];

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gsw_rollback_XXXXXX");
    if (!mkdtemp(g_xdg)) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(g_ssh_sock, sizeof(g_ssh_sock), "%s/gitswitch-ssh/current.sock", g_xdg);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.prev.sock", g_xdg);
    if (symlink(path, g_ssh_sock) != 0) return -1;

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/prevhome", g_xdg);
    if (mkdir(path, 0700) != 0) return -1;
    snprintf(g_gpg_link, sizeof(g_gpg_link), "%s/gitswitch-gpg/current", g_xdg);
    if (symlink(path, g_gpg_link) != 0) return -1;

    return 0;
}

static bool symlink_present(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* ---- selective runner ---------------------------------------------------- */

/* Behavior knobs for the fake runner. */
static bool g_fail_user_name_set;   /* fail `git config <scope> user.name X` */
static bool g_raise_on_user_name;   /* raise SIGINT during that same command */
static FILE *g_log;                 /* when set, every argv is logged here */

/* Minimal fake config store so git_set_config's read-back verification sees
 * what was "written". Only the two identity keys matter to these tests. */
static char g_store_name[MAX_NAME_LEN];
static char g_store_email[MAX_EMAIL_LEN];

/* True for the 5-element write form {git, config, <scope>, <key>, value}
 * (the --unset form has "--unset" at argv[3], so it never matches). */
static bool is_config_write(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && argv[4] && !argv[5] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[3], key) == 0;
}

/* True for the 4-element read form {git, config, <scope>, <key>}. */
static bool is_config_read(const char *const argv[], const char *key) {
    return argv[0] && argv[1] && argv[2] && argv[3] && !argv[4] &&
           strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
           strcmp(argv[3], key) == 0;
}

static int fake_runner(const char *const argv[], const run_opts_t *opts,
                       run_result_t *result) {
    int exit_code = 0;

    if (g_log) {
        for (int i = 0; argv[i]; i++) fprintf(g_log, "%s ", argv[i]);
        fprintf(g_log, "\n");
        fflush(g_log);
    }

    /* git_ops_init parses the version banner; everything else is happy with
     * empty output unless served from the fake store below. */
    if (opts && opts->out && opts->out_size > 0) {
        opts->out[0] = '\0';
        if (argv[1] && strcmp(argv[1], "--version") == 0) {
            snprintf(opts->out, opts->out_size, "git version 2.40.0\n");
        } else if (is_config_read(argv, "user.name") && g_store_name[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_name);
        } else if (is_config_read(argv, "user.email") && g_store_email[0]) {
            snprintf(opts->out, opts->out_size, "%s\n", g_store_email);
        }
    }

    if (is_config_write(argv, "user.name")) {
        if (g_raise_on_user_name) {
            g_raise_on_user_name = false; /* once */
            if (g_log) { fprintf(g_log, "MARK-RAISE\n"); fflush(g_log); }
            raise(SIGINT); /* signal lands mid durable-write window */
        }
        if (g_fail_user_name_set) {
            exit_code = 1;
        } else {
            safe_strncpy(g_store_name, argv[4], sizeof(g_store_name));
        }
    } else if (is_config_write(argv, "user.email")) {
        safe_strncpy(g_store_email, argv[4], sizeof(g_store_email));
    } else if (is_config_read(argv, "user.name") && !g_store_name[0]) {
        exit_code = 1; /* not set: git reports failure */
    } else if (is_config_read(argv, "user.email") && !g_store_email[0]) {
        exit_code = 1;
    }

    if (result) {
        result->spawned = true;
        result->exit_code = exit_code;
        result->term_signal = 0;
        result->out_len = (opts && opts->out) ? strlen(opts->out) : 0;
    }
    return exit_code == 0 ? 0 : -1;
}

/* ---- ctx factory ---------------------------------------------------------- */

/* One SSH/GPG-disabled account with global preferred scope (avoids both real
 * agent startup and the not-in-a-repo consent prompt). */
static gitswitch_ctx_t make_ctx(void) {
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    account_t *a = &ctx.accounts[0];
    a->id = 1;
    safe_strncpy(a->name, "testacct", sizeof(a->name));
    safe_strncpy(a->email, "test@example.com", sizeof(a->email));
    safe_strncpy(a->description, "test account", sizeof(a->description));
    a->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx.account_count = 1;
    safe_strncpy(ctx.config.config_path, "/tmp/gsw_rollback_accounts.toml",
                 sizeof(ctx.config.config_path));
    return ctx;
}

/* ---- tests ---------------------------------------------------------------- */

/* F4: a switch that fails AT the git-config step must leave the previous
 * account's current.sock and GNUPGHOME symlink untouched (teardown of the
 * previous runtime isolation is deferred past the point of no return). */
TEST(failed_git_config_keeps_previous_runtime_isolation) {
    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    g_fail_user_name_set = true;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);
    g_fail_user_name_set = false;

    CHECK_EQ_INT(rc, -1);
    /* The previous account's entry points must still be there. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* The deferred teardown must still HAPPEN on success — otherwise the original
 * mixed-identity hazard (old agent live behind a new git identity) returns. */
TEST(successful_switch_still_tears_down_previous_isolation) {
    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    /* Target has SSH/GPG disabled: the previous entry points must be gone. */
    CHECK(!symlink_present(g_ssh_sock));
    CHECK(!symlink_present(g_gpg_link));
}

/* AR-02 #12: a switch to an SSH-enabled target whose SSH setup fails at
 * ssh_manager_init — which only PATH-probes ssh-agent/ssh-add and touches no
 * agent — must NOT tear down the previous account's runtime isolation. The
 * pre-fix code marked the SSH state dirty before init ran, so this pure
 * lookup failure reaped the previous account's healthy agent and unlinked
 * current.sock for a switch that never started. */
TEST(ssh_init_failure_keeps_previous_runtime_isolation) {
    char key_path[512], emptybin[512], saved_path[4096];
    const char *env_path;
    FILE *kf;

    CHECK_EQ_INT(setup_runtime_dir(), 0);

    gitswitch_ctx_t ctx = make_ctx();
    account_t *a = &ctx.accounts[0];
    a->ssh_enabled = true;
    /* A real 0600 private-key-shaped file so the step-1 key validation
     * (stat/mode/header — no PATH involved) passes and the switch reaches
     * ssh_manager_init. */
    snprintf(key_path, sizeof(key_path), "%s/key_ed25519", g_xdg);
    kf = fopen(key_path, "w");
    CHECK(kf != NULL);
    if (kf) {
        fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
              "-----END OPENSSH PRIVATE KEY-----\n", kf);
        fclose(kf);
    }
    CHECK_EQ_INT(chmod(key_path, 0600), 0);
    safe_strncpy(a->ssh_key_path, key_path, sizeof(a->ssh_key_path));

    /* Warm the process-wide git-availability cache BEFORE crippling PATH, so
     * the switch fails exactly at ssh_manager_init's ssh-agent probe and not
     * earlier at git_ops_init. */
    CHECK_EQ_INT(git_ops_init(), 0);

    /* Cripple PATH: an empty (but trusted) dir makes command_exists fail for
     * ssh-agent/ssh-add without any agent operation being attempted. */
    env_path = getenv("PATH");
    snprintf(saved_path, sizeof(saved_path), "%s", env_path ? env_path : "");
    snprintf(emptybin, sizeof(emptybin), "%s/emptybin", g_xdg);
    CHECK_EQ_INT(mkdir(emptybin, 0755), 0);
    setenv("PATH", emptybin, 1);

    g_fail_user_name_set = false;
    g_raise_on_user_name = false;
    g_log = NULL;
    command_runner_fn prev = run_set_runner(fake_runner);
    int rc = accounts_switch(&ctx, "testacct");
    run_set_runner(prev);
    setenv("PATH", saved_path, 1);

    CHECK_EQ_INT(rc, -1);
    /* The previous account's entry points were never disturbed and must
     * survive; pre-fix the abort path reaped them. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));
}

/* SIG-01: a SIGINT during the git-config write must be deferred, the rollback
 * must run (restore commands appear in the log AFTER the signal), and the
 * process must then die by SIGINT. Without the guard the raise() kills the
 * child on the spot: no log lines after MARK-RAISE and no rollback. */
TEST(sigint_mid_git_config_rolls_back_then_reraises) {
    char log_path[512];
    int status = 0;
    pid_t pid;

    CHECK_EQ_INT(setup_runtime_dir(), 0);
    snprintf(log_path, sizeof(log_path), "%s/runner.log", g_xdg);

    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        gitswitch_ctx_t ctx = make_ctx();
        g_fail_user_name_set = false;
        g_raise_on_user_name = true;
        g_log = fopen(log_path, "w");
        if (!g_log) _exit(9);
        run_set_runner(fake_runner);
        (void)accounts_switch(&ctx, "testacct");
        _exit(42); /* must NOT be reached: the deferred SIGINT re-raises */
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ_INT(WTERMSIG(status), SIGINT);

    /* The runtime symlinks of the previous account survive the rollback. */
    CHECK(symlink_present(g_ssh_sock));
    CHECK(symlink_present(g_gpg_link));

    /* The log must show the switch surviving the signal and rolling back:
     * at least one `git config ... --unset` restore command after MARK-RAISE. */
    {
        char line[1024];
        bool seen_mark = false, rollback_after_mark = false;
        FILE *f = fopen(log_path, "r");
        CHECK(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "MARK-RAISE")) {
                    seen_mark = true;
                } else if (seen_mark && strstr(line, "--unset")) {
                    rollback_after_mark = true;
                }
            }
            fclose(f);
        }
        CHECK(seen_mark);
        CHECK(rollback_after_mark);
    }
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(failed_git_config_keeps_previous_runtime_isolation);
    RUN_TEST(successful_switch_still_tears_down_previous_isolation);
    RUN_TEST(ssh_init_failure_keeps_previous_runtime_isolation);
    RUN_TEST(sigint_mid_git_config_rolls_back_then_reraises);
TEST_MAIN_END()
