/* Tests for the SSH agent reuse fast path in ssh_start_isolated_agent:
 * a live per-account agent is adopted ONLY when it already holds the exact
 * key the account is configured with (ssh_key_fingerprint/ssh_socket_has_key
 * match by fingerprint). Reusing on socket liveness alone would keep serving
 * a stale key after `gitswitch edit` changed the account's key path — the
 * wrong identity would keep authenticating silently.
 *
 * All ssh-keygen/ssh-add/ssh-agent invocations are intercepted with a fake
 * runner; the "agent" is a real (bound but unserved) unix socket under a
 * private fake XDG_RUNTIME_DIR so validate_ssh_agent_socket sees a genuine
 * 0600 socket. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "test.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Fingerprints: the fake agent holds KEYA; accounts point at keyA or keyB. */
#define FP_A "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define FP_B "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

static int g_agent_start_attempts; /* execs of ssh-agent (i.e. reuse REFUSED) */

static int fake_ssh_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    /* ssh-keygen -lf <key>: fingerprint derives from the key file name. */
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0 && argv[2]) {
        const char *fp = strstr(argv[2], "keyB") ? FP_B : FP_A;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s user@host (ED25519)\n", fp);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-add -l (against the socket in opts->extra_env): agent holds keyA. */
    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] && strcmp(argv[1], "-l") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "256 %s agent-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }

    /* ssh-agent: reaching this means reuse was refused. Fail the start so the
     * test ends here deterministically. */
    if (strcmp(argv[0], "ssh-agent") == 0) {
        g_agent_start_attempts++;
        if (result) result->exit_code = 1;
        return -1;
    }

    return 0;
}

/* Scratch runtime dir + a real 0600 unix socket standing in for the agent.
 * Returns 0 on success; sock_out receives the per-account socket path. */
static char g_xdg[64]; /* short: the socket path must fit sun_path (~108) */

static int setup_agent_socket(const char *account, char *sock_out, size_t size) {
    char dir[128];
    struct sockaddr_un addr;
    int fd;

    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    if (!mkdtemp(g_xdg)) return -1;
    if (chmod(g_xdg, 0700) != 0) return -1;
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);

    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", g_xdg);
    if (mkdir(dir, 0700) != 0) return -1;

    if ((size_t)snprintf(sock_out, size, "%s/ssh-agent.%s.sock", dir, account)
        >= size) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_out) >= sizeof(addr.sun_path)) { close(fd); return -1; }
    strcpy(addr.sun_path, sock_out);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd); /* the socket inode persists; nobody needs to accept() */
    return chmod(sock_out, 0600);
}

static void make_account(account_t *a, const char *key_basename) {
    memset(a, 0, sizeof(*a));
    a->id = 1;
    safe_strncpy(a->name, "work", sizeof(a->name));
    safe_strncpy(a->email, "w@x.com", sizeof(a->email));
    a->ssh_enabled = true;
    snprintf(a->ssh_key_path, sizeof(a->ssh_key_path), "%s/%s", g_xdg, key_basename);
}

/* Adoption control: agent holds the account's own key -> reused in place
 * (no ssh-agent exec, key marked already loaded, current.sock retargeted). */
TEST(ssh_fingerprint_reuse_adopts_matching_key) {
    char sock[256], cur[256];
    struct stat st;
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    make_account(&acct, "keyA"); /* matches the FP_A the fake agent reports */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(cfg.key_already_loaded);       /* caller skips ssh_add_key */
    CHECK_EQ_INT(g_agent_start_attempts, 0); /* no restart, no re-prompt */
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
    CHECK(path_exists(sock));            /* the live agent was not reaped */

    /* current.sock points at the adopted agent's socket. */
    snprintf(cur, sizeof(cur), "%s/gitswitch-ssh/current.sock", g_xdg);
    CHECK_EQ_INT(lstat(cur, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

/* The guard itself: same live socket, but the account's key changed (edit) —
 * the fingerprint mismatch must REFUSE reuse, reap the stale agent, and go
 * start a fresh one (which the fake runner fails, ending the test there). */
TEST(ssh_fingerprint_reuse_rejects_different_key) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    CHECK_EQ_INT(setup_agent_socket("work", sock, sizeof(sock)), 0);
    make_account(&acct, "keyB"); /* FP_B: NOT what the fake agent holds */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    g_agent_start_attempts = 0;
    prev = run_set_runner(fake_ssh_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    /* Reuse refused: the code moved on to a fresh agent start... */
    CHECK_EQ_INT(g_agent_start_attempts, 1);
    CHECK(!cfg.key_already_loaded);
    /* ...whose (fake-injected) failure fails the switch instead of silently
     * keeping the wrong key active. */
    CHECK_EQ_INT(rc, -1);
    /* The stale wrong-key agent socket was reaped, not left adoptable. */
    CHECK(!path_exists(sock));
}

/* T1 (AR-01-T1, separate ticket): parse_ssh_agent_output must unwrap a quoted
 * SSH_AUTH_SOCK="..." value and cap the socket length. The fix has NOT landed
 * in this branch's ssh_manager.c (the parser still copies the quotes, so this
 * test fails today by design). Flip to #if 1 when AR-01-T1 merges. */
#if 0 /* enable when AR-01-T1 lands */

/* Runner variant whose fake ssh-agent SUCCEEDS: it binds a real socket at the
 * requested -a path and reports it QUOTED, the way some ssh-agent builds and
 * wrappers do. Only a parser that strips the quotes can then validate it. */
static int fake_quoting_agent_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-agent") == 0 && argv[1] &&
        strcmp(argv[1], "-a") == 0 && argv[2]) {
        struct sockaddr_un addr;
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0 || strlen(argv[2]) >= sizeof(addr.sun_path)) return -1;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, argv[2]);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close(fd);
            return -1;
        }
        close(fd);
        if (chmod(argv[2], 0600) != 0) return -1;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=\"%s\"; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=12345; export SSH_AGENT_PID;\n"
                     "echo Agent pid 12345;\n", argv[2]);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    /* No reusable socket exists in this test, so ssh-keygen/ssh-add answers
     * are irrelevant; succeed quietly. */
    return 0;
}

TEST(agent_output_quoted_auth_sock_is_unwrapped) {
    char sock[256];
    ssh_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    int rc;

    /* Runtime dir only — deliberately NO pre-existing per-account socket, so
     * the reuse fast path is skipped and a fresh agent is "started". */
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswsraXXXXXX");
    CHECK(mkdtemp(g_xdg) != NULL);
    CHECK_EQ_INT(chmod(g_xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", g_xdg, 1);
    snprintf(sock, sizeof(sock), "%s/gitswitch-ssh/ssh-agent.work.sock", g_xdg);

    make_account(&acct, "keyA");
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;

    prev = run_set_runner(fake_quoting_agent_runner);
    rc = ssh_start_isolated_agent(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK(strchr(cfg.agent_socket_path, '"') == NULL); /* quotes stripped */
    CHECK_STR_EQ(cfg.agent_socket_path, sock);
}
#endif /* AR-01-T1 */

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(ssh_fingerprint_reuse_adopts_matching_key);
    RUN_TEST(ssh_fingerprint_reuse_rejects_different_key);
#if 0 /* enable when AR-01-T1 lands */
    RUN_TEST(agent_output_quoted_auth_sock_is_unwrapped);
#endif
TEST_MAIN_END()
