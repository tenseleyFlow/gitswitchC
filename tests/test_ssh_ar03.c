/* AR-03 T1 coverage for src/ssh_manager.c:
 *   H1  — ssh-agent must be spawned with an explicit -s so a csh/tcsh $SHELL
 *         can't flip its output format past the Bourne-only parser, and a
 *         just-spawned agent that fails the post-spawn checks (parse or
 *         socket validation) must be reaped, not leaked holding the key.
 *   M2  — the reuse fast path adopts an agent only when it holds EXACTLY the
 *         account's key: one identity, fingerprint compared as a whole token.
 *   T3  — reap_ssh_agent's positive kill path against a REAL ssh-agent
 *         (Linux-gated: the identity check needs /proc).
 *   T5  — ssh_configure_host_alias preserve/splice/malformed branches with
 *         user stanzas above AND below the managed block.
 *   L6  — ssh_manager_reset refuses a symlinked/shared /tmp socket base.
 *   L16 — an identical ~/.ssh/config is not rewritten (no inode churn).
 *   L18 — the agent is probed (ssh-add -l) BEFORE ssh-keygen computes the
 *         expected fingerprint, so a stale socket costs no extra fork+exec.
 *
 * Same seams as tests/test_ssh_reuse.c: ssh-keygen/ssh-add/ssh-agent are
 * intercepted with run_set_runner fakes; "agents" are real bound-but-unserved
 * unix sockets under a private fake XDG_RUNTIME_DIR. The one exception is the
 * Linux-gated T3 test, which drives a REAL ssh-agent end to end. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp, sockets) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <signal.h>
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

/* Fingerprints: fakes report FP by key-file basename (keyB -> FP_B). */
#define FP_A "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define FP_B "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

static char g_xdg[64]; /* short: socket paths must fit sun_path (~108) */

static int  g_agent_start_attempts;   /* execs of ssh-agent */
static bool g_agent_argv_had_dash_s;  /* H1: -s present in the spawn argv */
static char g_first_probe[32];        /* L18: first ssh-add/ssh-keygen exec */

/* Find "-a <path>" wherever it sits in argv: the H1 fix inserts -s ahead of
 * it, so fakes must not assume a fixed position (and pre-fix argv still
 * matches, which is what makes the fail-before runs meaningful). */
static const char *argv_sock_path(const char *const argv[]) {
    for (size_t i = 1; argv[i]; i++) {
        if (strcmp(argv[i], "-a") == 0 && argv[i + 1]) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool argv_has(const char *const argv[], const char *flag) {
    for (size_t i = 1; argv[i]; i++) {
        if (strcmp(argv[i], flag) == 0) {
            return true;
        }
    }
    return false;
}

/* Bind a real unix socket at `path` with the given mode (0600 = passes
 * validate_ssh_agent_socket; anything else = fails it). */
static int bind_sock(const char *path, mode_t mode) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || strlen(path) >= sizeof(addr.sun_path)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd); /* the socket inode persists; nobody needs to accept() */
    return chmod(path, mode);
}

/* Scratch XDG_RUNTIME_DIR + the gitswitch-ssh dir under it. */
static int make_xdg_agent_dir(char *dir_out, size_t size) {
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswar03XXXXXX");
    if (!mkdtemp(g_xdg)) return -1;
    if (chmod(g_xdg, 0700) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    if ((size_t)snprintf(dir_out, size, "%s/gitswitch-ssh", g_xdg) >= size) {
        return -1;
    }
    return mkdir(dir_out, 0700);
}

static void make_account(account_t *a, const char *key_basename) {
    memset(a, 0, sizeof(*a));
    a->id = 1;
    safe_strncpy(a->name, "work", sizeof(a->name));
    safe_strncpy(a->email, "w@x.com", sizeof(a->email));
    a->ssh_enabled = true;
    snprintf(a->ssh_key_path, sizeof(a->ssh_key_path), "%s/%s", g_xdg, key_basename);
}

static int count_substr(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle)) n++;
    return n;
}

static int read_all(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) return -1;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return 0;
}

/* ---- H1: csh/tcsh output format + leak-on-failure ------------------------ */

/* Fake ssh-agent that genuinely binds the -a socket, then reports in CSH
 * syntax — what a tcsh $SHELL provokes from a real ssh-agent spawned without
 * -s. This is exactly the half-alive state the audit's PoC leaked: agent up,
 * output unparseable, no PID sidecar yet. */
static int fake_csh_agent_runner(const char *const argv[], const run_opts_t *opts,
                                 run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-agent") == 0) {
        const char *sock = argv_sock_path(argv);
        g_agent_start_attempts++;
        g_agent_argv_had_dash_s = argv_has(argv, "-s");
        if (!sock || bind_sock(sock, 0600) != 0) return -1;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "setenv SSH_AUTH_SOCK %s;\n"
                     "setenv SSH_AGENT_PID 4242;\n"
                     "echo Agent pid 4242;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return 0; /* no reusable socket exists: ssh-keygen/ssh-add are irrelevant */
}

TEST(agent_spawn_pins_bourne_format_and_reaps_on_parse_failure) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_agent_argv_had_dash_s = false;
    prev = run_set_runner(fake_csh_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    /* The spawn must pin the output format regardless of $SHELL. */
    CHECK(g_agent_argv_had_dash_s);
    /* csh-format text stays unparseable (the parser is Bourne-only by
     * design), so the switch fails cleanly... */
    CHECK_EQ_INT(rc, -1);
    /* ...and the just-spawned agent must not be left adoptable: the failure
     * happens BEFORE the PID sidecar exists, so nothing else could ever reap
     * it. The socket is the only remaining handle on it. */
    CHECK(!path_exists(sock));
}

/* Fake ssh-agent whose socket fails validate_ssh_agent_socket (0644): the
 * parsed PID is known on this path, so the reap must target it directly. */
static int fake_badperm_agent_runner(const char *const argv[], const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-agent") == 0) {
        const char *sock = argv_sock_path(argv);
        g_agent_start_attempts++;
        if (!sock || bind_sock(sock, 0644) != 0) return -1;
        if (opts && opts->out) {
            /* PID far above any pid_max: reap_ssh_agent's identity check can
             * never find (let alone signal) a real process behind it. */
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=1073741824; export SSH_AGENT_PID;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return 0;
}

TEST(socket_validation_failure_reaps_spawned_agent) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_badperm_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK_EQ_INT(rc, -1);
    /* Same leak shape as the parse failure: alive agent, no sidecar yet.
     * The wrong-mode socket must not survive as a future adoption target. */
    CHECK(!path_exists(sock));
}

/* ---- M2: reuse exclusivity + L18 probe order ------------------------------ */

/* Fake agent that holds TWO identities: the account's own key AND a foreign
 * one (the contamination scenario: `SSH_AUTH_SOCK=current.sock ssh-add
 * ~/.ssh/personal_key` while `work` is active). */
static int fake_two_key_agent_runner(const char *const argv[], const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        const char *fp = strstr(argv[2], "keyB") ? FP_B : FP_A;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "256 %s work (ED25519)\n"
                     "256 %s personal (ED25519)\n", FP_A, FP_B);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1; /* end the test deterministically at the restart */
    }
    return 0;
}

TEST(reuse_refuses_contaminated_agent) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    make_account(&acct, "keyA"); /* the agent DOES hold FP_A — but not alone */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_two_key_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    /* Presence of the right key is NOT enough: a second identity means a
     * foreign key would ride along into the "isolated" session. The reuse
     * must be refused and a fresh single-key agent started. */
    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    /* ...whose (fake-injected) start failure fails the switch instead of
     * silently adopting the two-key agent. */
    CHECK_EQ_INT(rc, -1);
    /* The contaminated agent was reaped, not left adoptable. */
    CHECK(!path_exists(sock));
}

/* Single identity whose fingerprint merely CONTAINS ours as a prefix: a
 * substring match (strstr) would adopt it; a token compare must not. */
static int fake_prefix_token_agent_runner(const char *const argv[], const run_opts_t *opts,
                                          run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %sXY other (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }
    return 0;
}

TEST(reuse_requires_exact_fingerprint_token) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_prefix_token_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(g_agent_start_attempts, 1); /* refused, restarted */
    CHECK(!cfg.key_already_loaded);
    CHECK_EQ_INT(rc, -1);
}

/* Recording adoption runner: single matching identity (reuse succeeds), and
 * the first ssh-add/ssh-keygen exec is captured to pin the probe order. */
static int fake_recording_adopt_runner(const char *const argv[], const run_opts_t *opts,
                                       run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (!g_first_probe[0] &&
        (strcmp(argv[0], "ssh-add") == 0 || strcmp(argv[0], "ssh-keygen") == 0)) {
        snprintf(g_first_probe, sizeof(g_first_probe), "%s", argv[0]);
    }

    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s agent-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }
    return 0;
}

TEST(agent_probe_precedes_fingerprint_computation) {
    char dir[128], sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    CHECK_EQ_INT(bind_sock(sock, 0600), 0);
    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    g_first_probe[0] = '\0';
    prev = run_set_runner(fake_recording_adopt_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(cfg.key_already_loaded); /* single exact match: adopted */
    /* L18: the cheap liveness probe must come first — a stale socket (dead
     * agent, the common miss) must not cost an ssh-keygen fork+exec. */
    CHECK_STR_EQ(g_first_probe, "ssh-add");
}

/* ---- T3: reap_ssh_agent positive kill path (real agent, Linux-gated) ------ */

#if defined(__linux__)
/* Every prior test approaches reap_ssh_agent from the refusal side (bystander
 * PID, above-pid_max PID, no sidecar). This drives the positive path end to
 * end: real ssh-agent, real sidecar, ssh_manager_reset — the agent must be
 * verified (comm + socket argv via /proc, hence Linux-gated), signaled, and
 * confirmed dead, with sidecar and socket removed. An always-refuse
 * regression in pid_is_our_ssh_agent fails this test instead of shipping
 * green while leaking live key-holding agents. */
TEST(reset_reaps_real_recorded_agent) {
    char dir[128], sock[256], pidp[256], out[2048];
    run_opts_t opts;
    run_result_t res;
    struct timespec t0, t1;
    long ms;
    FILE *pf;
    char *p;
    pid_t pid;

    if (!command_exists("ssh-agent")) {
        fprintf(stderr, "  (skipped: no ssh-agent in PATH)\n");
        return;
    }

    CHECK_EQ_INT(make_xdg_agent_dir(dir, sizeof(dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", dir);
    snprintf(pidp, sizeof(pidp), "%s/ssh-agent.work.pid", dir);

    const char *argv[] = { "ssh-agent", "-s", "-a", sock, NULL };
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);

    p = strstr(out, "SSH_AGENT_PID=");
    CHECK(p != NULL);
    if (!p) return;
    pid = (pid_t)atol(p + strlen("SSH_AGENT_PID="));
    CHECK(pid > 1);
    CHECK_EQ_INT(kill(pid, 0), 0); /* the daemonized agent is alive */

    pf = fopen(pidp, "w");
    CHECK(pf != NULL);
    if (pf) {
        fprintf(pf, "%d\n", (int)pid);
        fclose(pf);
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    /* L19 evidence (informational, not asserted: timing thresholds flake
     * under CI load): the fixed 50ms post-SIGTERM poll used to floor this. */
    fprintf(stderr, "  (info: real-agent reap took %ld ms)\n", ms);

    errno = 0;
    CHECK(kill(pid, 0) != 0);       /* reaped: ESRCH, not just signaled */
    CHECK_EQ_INT(errno, ESRCH);
    CHECK(!path_exists(pidp));      /* sidecar dropped once confirmed gone */
    CHECK(!path_exists(sock));

    if (kill(pid, 0) == 0) {
        kill(pid, SIGKILL); /* never leak a real agent on test failure */
    }
}
#endif

/* ---- L6: /tmp socket base hardening --------------------------------------- */

TEST(reset_refuses_unsafe_socket_dir) {
    char dir[192], real[192], pidfile[256];
    FILE *pf;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswar03XXXXXX");
    CHECK(mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    /* A planted symlink base: everything reachable through it must stay
     * untouched, mirroring gpg_manager_reset's refusal. */
    snprintf(real, sizeof(real), "%s/realbase", g_xdg);
    CHECK_EQ_INT(mkdir(real, 0700), 0);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", real);
    pf = fopen(pidfile, "w");
    CHECK(pf != NULL);
    if (pf) {
        fprintf(pf, "0\n");
        fclose(pf);
    }
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    CHECK_EQ_INT(symlink(real, dir), 0);

    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK(path_exists(pidfile)); /* nothing reaped/unlinked through the link */

    /* A group-accessible base is just as disqualifying (predictable name in
     * sticky /tmp when XDG_RUNTIME_DIR is unset). */
    CHECK_EQ_INT(unlink(dir), 0);
    CHECK_EQ_INT(mkdir(dir, 0700), 0);
    CHECK_EQ_INT(chmod(dir, 0770), 0);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);

    /* Control: the genuine private dir proceeds. */
    CHECK_EQ_INT(chmod(dir, 0700), 0);
    CHECK_EQ_INT(ssh_manager_reset(NULL), 0);
}

/* ---- T5 / L16: host-alias config round-trip ------------------------------- */

#define USER_STANZA_ABOVE \
    "Host personal\n  User alice\n  IdentityFile ~/.ssh/personal\n"
#define USER_STANZA_BELOW \
    "Host other.example.com\n  User bob\n  Port 2222\n"
#define ALIAS "github.com-work"
#define BEGIN_MARK "# >>> gitswitch " ALIAS " >>>"
#define END_MARK   "# <<< gitswitch " ALIAS " <<<"

/* Scratch HOME with ~/.ssh/config pre-seeded to `content`. */
static int setup_home_with_ssh_config(char *home, size_t home_size,
                                      const char *content) {
    char sshdir[256], cfgp[320];
    FILE *f;

    snprintf(home, home_size, "/tmp/gswar03hXXXXXX");
    if (!mkdtemp(home)) return -1;
    setenv("HOME", home, 1);
    snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
    if (mkdir(sshdir, 0700) != 0) return -1;
    if (!content) return 0;
    snprintf(cfgp, sizeof(cfgp), "%s/config", sshdir);
    f = fopen(cfgp, "w");
    if (!f) return -1;
    fputs(content, f);
    return fclose(f) == 0 ? 0 : -1;
}

/* Splice/preserve: user stanzas above AND below an existing managed block
 * must survive byte-for-byte, and repeated calls must leave exactly one
 * managed block (no duplication, no drift). */
TEST(host_alias_preserves_user_stanzas_around_managed_block) {
    char home[128], cfgp[256], buf[8192];
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home),
        USER_STANZA_ABOVE
        BEGIN_MARK "\n"
        "Host " ALIAS "\n"
        "  IdentityFile /stale/key\n"
        "  IdentitiesOnly yes\n"
        END_MARK "\n"
        USER_STANZA_BELOW), 0);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0); /* idempotent re-run */

    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);

    CHECK(strstr(buf, USER_STANZA_ABOVE) != NULL); /* byte-for-byte survival */
    CHECK(strstr(buf, USER_STANZA_BELOW) != NULL);
    CHECK_EQ_INT(count_substr(buf, BEGIN_MARK), 1); /* exactly one block */
    CHECK_EQ_INT(count_substr(buf, END_MARK), 1);
    CHECK(strstr(buf, "/stale/key") == NULL);       /* old block spliced out */
    CHECK(strstr(buf, "key1") != NULL);
}

/* Malformed managed block (begin marker, no end marker): only OUR recognizable
 * stanza may be dropped — user stanzas below the damaged block must survive
 * the rewrite instead of being silently truncated away. */
TEST(host_alias_malformed_block_keeps_trailing_user_content) {
    char home[128], cfgp[256], buf[8192];
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home),
        USER_STANZA_ABOVE
        BEGIN_MARK "\n"
        "Host " ALIAS "\n"
        "  IdentityFile /stale/key\n"
        "  IdentitiesOnly yes\n"
        /* end marker missing: truncated/hand-damaged block */
        USER_STANZA_BELOW), 0);

    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);

    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);

    CHECK(strstr(buf, USER_STANZA_ABOVE) != NULL);
    CHECK(strstr(buf, USER_STANZA_BELOW) != NULL); /* NOT truncated away */
    CHECK_EQ_INT(count_substr(buf, BEGIN_MARK), 1);
    CHECK_EQ_INT(count_substr(buf, END_MARK), 1);  /* fresh block is complete */
    CHECK(strstr(buf, "/stale/key") == NULL);
    CHECK(strstr(buf, "key1") != NULL);
}

/* L16: a byte-identical result must not be rewritten — mkstemp+rename churns
 * the inode (breaking hard links, waking dotfile sync) on every switch. */
TEST(host_alias_skips_rewrite_when_content_identical) {
    char home[128], cfgp[256], buf[8192];
    struct stat st1, st2, st3;
    account_t acct;

    CHECK_EQ_INT(setup_home_with_ssh_config(home, sizeof(home), NULL), 0);
    memset(&acct, 0, sizeof(acct));
    acct.ssh_enabled = true;
    snprintf(acct.ssh_host_alias, sizeof(acct.ssh_host_alias), ALIAS);
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key1", home);

    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    snprintf(cfgp, sizeof(cfgp), "%s/.ssh/config", home);
    CHECK_EQ_INT(stat(cfgp, &st1), 0);

    /* Same account, same content: the file must not be replaced. */
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(stat(cfgp, &st2), 0);
    CHECK(st1.st_ino == st2.st_ino);

    /* Control: a real change still rewrites atomically. */
    snprintf(acct.ssh_key_path, sizeof(acct.ssh_key_path), "%s/key2", home);
    CHECK_EQ_INT(ssh_configure_host_alias(&acct), 0);
    CHECK_EQ_INT(stat(cfgp, &st3), 0);
    CHECK(st2.st_ino != st3.st_ino);
    CHECK_EQ_INT(read_all(cfgp, buf, sizeof(buf)), 0);
    CHECK(strstr(buf, "key2") != NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(agent_spawn_pins_bourne_format_and_reaps_on_parse_failure);
    RUN_TEST(socket_validation_failure_reaps_spawned_agent);
    RUN_TEST(reuse_refuses_contaminated_agent);
    RUN_TEST(reuse_requires_exact_fingerprint_token);
    RUN_TEST(agent_probe_precedes_fingerprint_computation);
#if defined(__linux__)
    RUN_TEST(reset_reaps_real_recorded_agent);
#endif
    RUN_TEST(reset_refuses_unsafe_socket_dir);
    RUN_TEST(host_alias_preserves_user_stanzas_around_managed_block);
    RUN_TEST(host_alias_malformed_block_keeps_trailing_user_content);
    RUN_TEST(host_alias_skips_rewrite_when_content_identical);
TEST_MAIN_END()
