/* AR-04 T2 regressions: stable current.sock is a required commit point and
 * ~/.ssh/config's final component is never followed/replaced when unsafe. */

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
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FP_A "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static char g_xdg[64]; /* keep AF_UNIX paths below sun_path's small cap */
static int g_runner_calls;

static int test_write_exact(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) {
            p += (size_t)n;
            len -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int test_read_exact(int fd, void *buf, size_t len) {
    unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n > 0) {
            p += (size_t)n;
            len -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

#ifdef __APPLE__
static const char *g_test_executable_path;

static int darwin_write_exact(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) {
            p += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int darwin_read_exact(int fd, void *buf, size_t len) {
    unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n > 0) {
            p += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int darwin_copy_test_executable(const char *destination) {
    unsigned char buf[16384];
    FILE *in;
    FILE *out;
    bool failed = false;

    if (!g_test_executable_path) return -1;
    in = fopen(g_test_executable_path, "rb");
    if (!in) return -1;
    out = fopen(destination, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), in);
        if (n > 0 && fwrite(buf, 1, n, out) != n) {
            failed = true;
            break;
        }
        if (n < sizeof(buf)) {
            if (ferror(in)) failed = true;
            break;
        }
    }
    if (fclose(in) != 0) failed = true;
    if (fclose(out) != 0) failed = true;
    if (!failed && chmod(destination, 0700) != 0) failed = true;
    if (failed) (void)unlink(destination);
    return failed ? -1 : 0;
}

/* Entry point used after execing an unrestricted copy of this test binary as
 * `ssh-agent -a <managed socket>`. It owns a real listening socket and keeps
 * the large inherited environment, making KERN_PROCARGS2 truncation fully
 * deterministic without relying on Apple ssh-agent's restricted-env policy. */
static int darwin_agent_helper_main(void) {
    const char *sock = getenv("GITSWITCH_TEST_AGENT_HELPER_SOCK");
    const char *ready_text = getenv("GITSWITCH_TEST_AGENT_HELPER_READY_FD");
    struct sockaddr_un addr;
    char ready = 'R';
    int ready_fd;
    int listener;

    if (!sock || !ready_text || strlen(sock) >= sizeof(addr.sun_path)) return 2;
    ready_fd = (int)strtol(ready_text, NULL, 10);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return 2;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        chmod(sock, 0600) != 0 || listen(listener, 4) != 0 ||
        darwin_write_exact(ready_fd, &ready, sizeof(ready)) != 0) {
        close(listener);
        close(ready_fd);
        (void)unlink(sock);
        return 2;
    }
    close(ready_fd);
    for (;;) pause();
}

/* Double-fork so the managed helper is reparented before reset. Otherwise a
 * killed direct child remains a zombie until waitpid(), and kill(pid, 0) would
 * make the production death-confirmation loop correctly report it as alive. */
static int start_darwin_unrestricted_agent(const char *helper_path,
                                           const char *sock, pid_t *pid_out) {
    int pid_pipe[2];
    int ready_pipe[2];
    pid_t launcher;
    int launcher_status = 0;
    char ready = '\0';
    bool failed = false;

    *pid_out = -1;
    if (pipe(pid_pipe) != 0) return -1;
    if (pipe(ready_pipe) != 0) {
        close(pid_pipe[0]);
        close(pid_pipe[1]);
        return -1;
    }
    launcher = fork();
    if (launcher < 0) {
        close(pid_pipe[0]);
        close(pid_pipe[1]);
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }
    if (launcher == 0) {
        pid_t daemon_pid;

        close(pid_pipe[0]);
        close(ready_pipe[0]);
        daemon_pid = fork();
        if (daemon_pid != 0) {
            close(ready_pipe[1]);
            (void)darwin_write_exact(pid_pipe[1], &daemon_pid,
                                     sizeof(daemon_pid));
            close(pid_pipe[1]);
            _exit(daemon_pid > 0 ? 0 : 2);
        }

        close(pid_pipe[1]);
        (void)setsid();
        char ready_fd_text[32];
        char large_environment[16385];
        char arg0[] = "ssh-agent";
        char socket_option[] = "-a";
        char *helper_argv[] = {arg0, socket_option, (char *)sock, NULL};

        memset(large_environment, 'x', sizeof(large_environment) - 1);
        large_environment[sizeof(large_environment) - 1] = '\0';
        snprintf(ready_fd_text, sizeof(ready_fd_text), "%d", ready_pipe[1]);
        if (setenv("GITSWITCH_TEST_AGENT_HELPER", "1", 1) != 0 ||
            setenv("GITSWITCH_TEST_AGENT_HELPER_SOCK", sock, 1) != 0 ||
            setenv("GITSWITCH_TEST_AGENT_HELPER_READY_FD", ready_fd_text, 1) != 0 ||
            setenv("GITSWITCH_TEST_LARGE_AGENT_ENV", large_environment, 1) != 0) {
            _exit(2);
        }
        execv(helper_path, helper_argv);
        _exit(2);
    }

    close(pid_pipe[1]);
    close(ready_pipe[1]);
    if (darwin_read_exact(pid_pipe[0], pid_out, sizeof(*pid_out)) != 0) {
        failed = true;
    }
    pid_t waited;
    do {
        waited = waitpid(launcher, &launcher_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != launcher || !WIFEXITED(launcher_status) ||
        WEXITSTATUS(launcher_status) != 0 || *pid_out <= 1) {
        failed = true;
    }
    if (!failed &&
        (darwin_read_exact(ready_pipe[0], &ready, sizeof(ready)) != 0 ||
         ready != 'R')) {
        failed = true;
    }
    close(pid_pipe[0]);
    close(ready_pipe[0]);
    if (failed && *pid_out > 1) (void)kill(*pid_out, SIGKILL);
    return failed ? -1 : 0;
}
#endif

static const char *agent_socket_arg(const char *const argv[]) {
    for (size_t i = 1; argv[i]; i++) {
        if (strcmp(argv[i], "-a") == 0 && argv[i + 1]) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static int bind_socket(const char *path) {
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
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    close(fd);
    return chmod(path, 0600);
}

static int bind_socket_for_runner(const char *path, const run_opts_t *opts) {
    int saved_cwd;
    int rc;

    if (!opts || !opts->use_cwd_fd) return bind_socket(path);
    saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
    if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) {
        if (saved_cwd >= 0) close(saved_cwd);
        return -1;
    }
    rc = bind_socket(path);
    if (fchdir(saved_cwd) != 0) rc = -1;
    close(saved_cwd);
    return rc;
}

static int listen_socket(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0 || strlen(path) >= sizeof(addr.sun_path)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (bind(fd, (struct sockaddr *)(void *)&addr, sizeof(addr)) != 0 ||
        chmod(path, 0600) != 0 || listen(fd, 8) != 0) {
        int saved_errno = errno;
        close(fd);
        (void)unlink(path);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static bool unix_socket_bind_available(const char *agent_dir) {
    char probe[192];
    snprintf(probe, sizeof(probe), "%s/probe.sock", agent_dir);
    if (bind_socket(probe) == 0) {
        unlink(probe);
        return true;
    }
    if (errno == EPERM || errno == EACCES) {
        fprintf(stderr, "  (skip: sandbox forbids AF_UNIX bind)\n");
        return false;
    }
    CHECK(false);
    return false;
}

static int fake_agent_runner(const char *const argv[], const run_opts_t *opts,
                             run_result_t *result) {
    g_runner_calls++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-agent") == 0) {
        const char *sock = agent_socket_arg(argv);
        if (!sock || bind_socket_for_runner(sock, opts) != 0) return -1;
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
                     "SSH_AGENT_PID=1073741824; export SSH_AGENT_PID;\n", sock);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-add") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "256 %s account-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-keygen") == 0) {
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "256 %s account-key (ED25519)\n", FP_A);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return 0;
}

/* Fail only the second environment write so the test proves that a partially
 * mutated process environment is restored, not merely that an early failure
 * is propagated. */
static int fail_agent_pid_setenv(const char *name, const char *value,
                                 int overwrite) {
    if (strcmp(name, "SSH_AGENT_PID") == 0) {
        errno = ENOMEM;
        return -1;
    }
    return setenv(name, value, overwrite);
}

static int setup_runtime(char *agent_dir, size_t size) {
    snprintf(g_xdg, sizeof(g_xdg), "/tmp/gswssh4XXXXXX");
    if (!mkdtemp(g_xdg) || chmod(g_xdg, 0700) != 0) return -1;
    if (setenv("XDG_RUNTIME_DIR", g_xdg, 1) != 0) return -1;
    if ((size_t)snprintf(agent_dir, size, "%s/gitswitch-ssh", g_xdg) >= size) {
        return -1;
    }
    return mkdir(agent_dir, 0700);
}

static int make_live_current(const char *agent_dir, const char *account,
                             char *sock, size_t sock_size,
                             char *current, size_t current_size) {
    int listener;

    if ((size_t)snprintf(sock, sock_size, "%s/ssh-agent.%s.sock",
                         agent_dir, account) >= sock_size ||
        (size_t)snprintf(current, current_size, "%s/current.sock",
                         agent_dir) >= current_size) {
        return -1;
    }
    listener = listen_socket(sock);
    if (listener < 0) {
        return -1;
    }
    if (symlink(sock, current) != 0) {
        close(listener);
        (void)unlink(sock);
        return -1;
    }
    return listener;
}

static void check_current_account_rejected(void) {
    char name[MAX_NAME_LEN] = "unchanged";
    bool present = true;

    CHECK_EQ_INT(ssh_manager_get_current_account(name, sizeof(name), &present), -1);
    CHECK(!present);
    CHECK(name[0] == '\0');
}

static int write_text_file(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return -1;
    if (fputs(text, file) == EOF || fclose(file) != 0) return -1;
    return 0;
}

static bool entry_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* Start a real listener so missing-sidecar reset coverage cannot false-pass on
 * a dead socket inode. Returns 1 for an explicit environment skip, 0 on
 * success, and -1 for an unexpected setup failure. */
static int start_real_agent_without_sidecar(const char *agent_dir,
                                            const char *account,
                                            char *sock, size_t sock_size,
                                            char *current, size_t current_size,
                                            pid_t *pid_out) {
    char output[2048];
    run_opts_t opts;
    run_result_t result;
    char *pid_text;

    if (!command_exists("ssh-agent")) {
        fprintf(stderr, "  (skip: ssh-agent not available)\n");
        return 1;
    }
    if (!unix_socket_bind_available(agent_dir)) {
        return 1;
    }
    if ((size_t)snprintf(sock, sock_size, "%s/ssh-agent.%s.sock",
                         agent_dir, account) >= sock_size ||
        (size_t)snprintf(current, current_size, "%s/current.sock",
                         agent_dir) >= current_size) {
        return -1;
    }

    const char *argv[] = {"ssh-agent", "-s", "-a", sock, NULL};
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &result) != 0) {
        return -1;
    }
    pid_text = strstr(output, "SSH_AGENT_PID=");
    if (!pid_text) {
        return -1;
    }
    *pid_out = (pid_t)strtol(pid_text + strlen("SSH_AGENT_PID="), NULL, 10);
    if (*pid_out <= 1 || symlink(sock, current) != 0) {
        if (*pid_out > 1) (void)kill(*pid_out, SIGTERM);
        return -1;
    }
    return 0;
}

static void stop_real_agent(pid_t pid, const char *sock, const char *current) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};

    if (pid > 1) {
        (void)kill(pid, SIGTERM);
        for (int i = 0; i < 50 && kill(pid, 0) == 0; i++) {
            nanosleep(&delay, NULL);
        }
        if (kill(pid, 0) == 0) {
            (void)kill(pid, SIGKILL);
        }
    }
    (void)unlink(current);
    (void)unlink(sock);
}

static void make_account(account_t *account) {
    memset(account, 0, sizeof(*account));
    account->id = 1;
    snprintf(account->name, sizeof(account->name), "work");
    snprintf(account->email, sizeof(account->email), "w@x.com");
    account->ssh_enabled = true;
    snprintf(account->ssh_key_path, sizeof(account->ssh_key_path), "%s/key", g_xdg);
}

TEST(current_account_reports_absent_and_valid_live_socket) {
    char agent_dir[128], sock[192], current[192], name[MAX_NAME_LEN];
    bool present = true;
    int listener;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    name[0] = 'x';
    CHECK_EQ_INT(ssh_manager_get_current_account(name, sizeof(name), &present), 0);
    CHECK(!present);
    CHECK(name[0] == '\0');

    listener = make_live_current(agent_dir, "alice.sock.work",
                                 sock, sizeof(sock), current, sizeof(current));
    CHECK(listener >= 0);
    if (listener < 0) return;

    CHECK_EQ_INT(ssh_manager_get_current_account(name, sizeof(name), &present), 0);
    CHECK(present);
    CHECK_STR_EQ(name, "alice.sock.work");

    close(listener);
    (void)unlink(current);
    (void)unlink(sock);
}

TEST(current_account_rejects_unsafe_malformed_and_stale_state) {
    char agent_dir[128], current[192], sock[192], target[MAX_PATH_LEN];
    char *long_target;
    int listener;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);

    CHECK_EQ_INT(chmod(agent_dir, 0755), 0);
    check_current_account_rejected();
    CHECK_EQ_INT(chmod(agent_dir, 0700), 0);

    CHECK_EQ_INT(write_text_file(current, "not a symlink\n"), 0);
    check_current_account_rejected();
    CHECK_EQ_INT(unlink(current), 0);

    CHECK_EQ_INT(symlink("ssh-agent.work.sock", current), 0);
    check_current_account_rejected();
    CHECK_EQ_INT(unlink(current), 0);

    snprintf(target, sizeof(target), "%s/nested/ssh-agent.work.sock", agent_dir);
    CHECK_EQ_INT(symlink(target, current), 0);
    check_current_account_rejected();
    CHECK_EQ_INT(unlink(current), 0);

    CHECK_EQ_INT(bind_socket(sock), 0); /* socket inode with no live listener */
    CHECK_EQ_INT(symlink(sock, current), 0);
    check_current_account_rejected();
    CHECK_EQ_INT(unlink(current), 0);
    CHECK_EQ_INT(unlink(sock), 0);

    listener = make_live_current(agent_dir, "work", sock, sizeof(sock),
                                 current, sizeof(current));
    CHECK(listener >= 0);
    if (listener >= 0) {
        CHECK_EQ_INT(chmod(sock, 0660), 0);
        check_current_account_rejected();
        close(listener);
        (void)unlink(current);
        (void)unlink(sock);
    }

    /* Exercise the readlink-cap rejection where the host filesystem permits a
     * target this large. Hosts with a smaller native symlink cap reject the
     * fixture before the API can observe it. */
    long_target = malloc(MAX_PATH_LEN);
    CHECK(long_target != NULL);
    if (long_target) {
        memset(long_target, 'x', MAX_PATH_LEN - 1);
        long_target[0] = '/';
        long_target[MAX_PATH_LEN - 1] = '\0';
        if (symlink(long_target, current) == 0) {
            check_current_account_rejected();
            (void)unlink(current);
        }
        free(long_target);
    }
}

TEST(current_account_accepts_longest_bindable_name_without_truncation) {
    char agent_dir[128], sock[192], current[192];
    char account[MAX_NAME_LEN], actual[MAX_NAME_LEN], short_output[MAX_NAME_LEN];
    size_t socket_limit = sizeof(((struct sockaddr_un *)0)->sun_path) - 1;
    size_t fixed_len;
    size_t account_len;
    bool present = true;
    int listener;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    fixed_len = strlen(agent_dir) + strlen("/ssh-agent.") + strlen(".sock");
    CHECK(fixed_len < socket_limit);
    if (fixed_len >= socket_limit) return;
    account_len = socket_limit - fixed_len;
    CHECK(account_len > 0 && account_len < sizeof(account));
    if (account_len >= sizeof(account)) return;
    memset(account, 'a', account_len);
    account[account_len] = '\0';

    listener = make_live_current(agent_dir, account, sock, sizeof(sock),
                                 current, sizeof(current));
    CHECK(listener >= 0);
    if (listener < 0) return;
    CHECK_EQ_INT(strlen(sock), socket_limit);

    CHECK_EQ_INT(ssh_manager_get_current_account(short_output, account_len,
                                                  &present), -1);
    CHECK(!present);
    CHECK(short_output[0] == '\0');

    CHECK_EQ_INT(ssh_manager_get_current_account(actual, sizeof(actual), &present), 0);
    CHECK(present);
    CHECK_STR_EQ(actual, account);

    close(listener);
    (void)unlink(current);
    (void)unlink(sock);
}

TEST(current_account_fails_fast_when_manager_lock_held) {
    typedef struct {
        int rc;
        int present;
        char name[MAX_NAME_LEN];
    } query_result_t;
    char agent_dir[128], sock[192], current[192], lock_path[192];
    int ready_pipe[2] = {-1, -1};
    int result_pipe[2] = {-1, -1};
    int listener = -1;
    int lock_fd = -1;
    pid_t child = -1;
    char ready = '\0';
    struct pollfd pfd;
    query_result_t result;
    int status = 0;
    int poll_rc;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    listener = make_live_current(agent_dir, "locked", sock, sizeof(sock),
                                 current, sizeof(current));
    CHECK(listener >= 0);
    if (listener < 0) return;
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", agent_dir);
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    CHECK(lock_fd >= 0);
    CHECK(lock_fd >= 0 && flock(lock_fd, LOCK_EX) == 0);
    CHECK_EQ_INT(pipe(ready_pipe), 0);
    CHECK_EQ_INT(pipe(result_pipe), 0);
    if (lock_fd < 0 || ready_pipe[0] < 0 || result_pipe[0] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        bool child_present = false;

        close(ready_pipe[0]);
        close(result_pipe[0]);
        close(lock_fd);
        if (test_write_exact(ready_pipe[1], "R", 1) != 0) _exit(2);
        memset(&result, 0, sizeof(result));
        result.rc = ssh_manager_get_current_account(result.name,
                                                     sizeof(result.name),
                                                     &child_present);
        result.present = child_present ? 1 : 0;
        if (test_write_exact(result_pipe[1], &result, sizeof(result)) != 0) {
            _exit(2);
        }
        _exit(0);
    }
    if (child < 0) goto cleanup;

    close(ready_pipe[1]);
    ready_pipe[1] = -1;
    close(result_pipe[1]);
    result_pipe[1] = -1;
    CHECK_EQ_INT(test_read_exact(ready_pipe[0], &ready, 1), 0);
    CHECK_EQ_INT(ready, 'R');

    /* AR-05 H2: discovery must NOT wait for the writer lock — a switch holds
     * it across the interactive ssh-add passphrase prompt, so a blocking
     * reader froze every read-only command and shell tab-completion for
     * unbounded human latency. The query must complete promptly WITH THE
     * LOCK STILL HELD, reporting contention (rc=-1, present=false) so
     * accounts_detect_current serves the saved-account fallback instead. */
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = result_pipe[0];
    pfd.events = POLLIN;
    do {
        poll_rc = poll(&pfd, 1, 2000);
    } while (poll_rc < 0 && errno == EINTR);
    CHECK(poll_rc > 0 && (pfd.revents & POLLIN) != 0);
    if (poll_rc > 0 && (pfd.revents & POLLIN) != 0) {
        CHECK_EQ_INT(test_read_exact(result_pipe[0], &result, sizeof(result)), 0);
        CHECK_EQ_INT(result.rc, -1);
        CHECK_EQ_INT(result.present, 0);
        CHECK(result.name[0] == '\0');
    } else {
        (void)kill(child, SIGKILL);
    }
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Once the writer releases the lock, the same query must succeed and
     * attribute the live socket — contention degrades discovery, never
     * disables it. */
    CHECK_EQ_INT(flock(lock_fd, LOCK_UN), 0);
    close(lock_fd);
    lock_fd = -1;
    {
        bool present_after = false;
        char name_after[MAX_NAME_LEN];
        CHECK_EQ_INT(ssh_manager_get_current_account(name_after,
                                                     sizeof(name_after),
                                                     &present_after), 0);
        CHECK(present_after);
        CHECK_STR_EQ(name_after, "locked");
    }

cleanup:
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    for (size_t i = 0; i < 2; i++) {
        if (ready_pipe[i] >= 0) close(ready_pipe[i]);
        if (result_pipe[i] >= 0) close(result_pipe[i]);
    }
    close(listener);
    (void)unlink(current);
    (void)unlink(sock);
}

TEST(fresh_agent_retarget_failure_reaps_and_restores_environment) {
    char agent_dir[128], current[192], sock[192], pidfile[192];
    struct stat st;
    ssh_config_t cfg;
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    if (!unix_socket_bind_available(agent_dir)) return;
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    CHECK_EQ_INT(mkdir(current, 0700), 0); /* rename-over-directory => EISDIR */
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", "/before/agent.sock", 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "321", 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    make_account(&account);

    previous = run_set_runner(fake_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &account), -1); /* pre-fix: 0 */
    run_set_runner(previous);

    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK(!path_exists(sock));
    CHECK(!path_exists(pidfile));
    CHECK(!cfg.agent_owned);
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), "/before/agent.sock");
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "321");
}

TEST(fresh_agent_environment_failure_reaps_and_restores_partial_mutation) {
    char agent_dir[128], current[192], sock[192], pidfile[192];
    ssh_config_t cfg;
    account_t account;
    command_runner_fn previous_runner;
    ssh_setenv_fn previous_setenv;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    if (!unix_socket_bind_available(agent_dir)) return;
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", "/before/env.sock", 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "777", 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    make_account(&account);

    previous_runner = run_set_runner(fake_agent_runner);
    previous_setenv = ssh_manager_set_setenv_fn(fail_agent_pid_setenv);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &account), -1);
    ssh_manager_set_setenv_fn(previous_setenv);
    run_set_runner(previous_runner);

    CHECK(!entry_exists(current));
    CHECK(!entry_exists(sock));
    CHECK(!entry_exists(pidfile));
    CHECK(!cfg.agent_owned);
    CHECK_EQ_INT(cfg.agent_pid, -1);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), "/before/env.sock");
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "777");
}

TEST(fresh_agent_aborts_when_orphan_cleanup_is_incomplete) {
    char agent_dir[128], stale_pid[192], stale_sock[192], new_sock[192];
    ssh_config_t cfg;
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(stale_pid, sizeof(stale_pid), "%s/ssh-agent.personal.pid", agent_dir);
    snprintf(stale_sock, sizeof(stale_sock), "%s/ssh-agent.personal.sock", agent_dir);
    snprintf(new_sock, sizeof(new_sock), "%s/ssh-agent.work.sock", agent_dir);
    CHECK_EQ_INT(write_text_file(stale_pid, "not-a-pid\n"), 0);
    CHECK_EQ_INT(write_text_file(stale_sock, "retained runtime\n"), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    make_account(&account);

    g_runner_calls = 0;
    previous = run_set_runner(fake_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &account), -1);
    run_set_runner(previous);

    CHECK_EQ_INT(g_runner_calls, 0); /* no replacement agent was started */
    CHECK(entry_exists(stale_pid));
    CHECK(entry_exists(stale_sock));
    CHECK(!entry_exists(new_sock));
    CHECK(!cfg.agent_owned);
}

TEST(reused_agent_retarget_failure_does_not_adopt_or_reap) {
    char agent_dir[128], current[192], sock[192];
    struct stat st;
    ssh_config_t cfg;
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    if (!unix_socket_bind_available(agent_dir)) return;
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    CHECK_EQ_INT(bind_socket(sock), 0);
    CHECK_EQ_INT(mkdir(current, 0700), 0);
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", "/before/reuse.sock", 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "654", 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    make_account(&account);

    previous = run_set_runner(fake_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &account), -1); /* pre-fix: 0 */
    run_set_runner(previous);

    CHECK(path_exists(sock)); /* existing live agent was not discarded */
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK(!cfg.agent_owned);
    CHECK(!cfg.key_already_loaded);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), "/before/reuse.sock");
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "654");
}

TEST(reused_agent_aborts_when_other_orphan_cleanup_is_incomplete) {
    char agent_dir[128], current[192], work_sock[192];
    char stale_pid[192], stale_sock[192], target[192];
    ssh_config_t cfg;
    account_t account;
    command_runner_fn previous;
    ssize_t target_len;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    if (!unix_socket_bind_available(agent_dir)) return;
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(work_sock, sizeof(work_sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(stale_pid, sizeof(stale_pid), "%s/ssh-agent.personal.pid", agent_dir);
    snprintf(stale_sock, sizeof(stale_sock), "%s/ssh-agent.personal.sock", agent_dir);
    CHECK_EQ_INT(bind_socket(work_sock), 0);
    CHECK_EQ_INT(symlink(work_sock, current), 0);
    CHECK_EQ_INT(write_text_file(stale_pid, "invalid\n"), 0);
    CHECK_EQ_INT(write_text_file(stale_sock, "retained runtime\n"), 0);
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", "/before/reuse-cleanup.sock", 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "987", 1), 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = SSH_AGENT_ISOLATED;
    cfg.agent_pid = -1;
    make_account(&account);

    previous = run_set_runner(fake_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&cfg, &account), -1);
    run_set_runner(previous);

    target_len = readlink(current, target, sizeof(target) - 1);
    CHECK(target_len > 0);
    if (target_len > 0) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, work_sock);
    }
    CHECK(entry_exists(work_sock));
    CHECK(entry_exists(stale_pid));
    CHECK(entry_exists(stale_sock));
    CHECK(!cfg.agent_owned);
    CHECK(!cfg.key_already_loaded);
    CHECK(cfg.agent_socket_path[0] == '\0');
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), "/before/reuse-cleanup.sock");
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "987");
}

static int setup_home(char *home, size_t size, char *config, size_t config_size) {
    char ssh_dir[256];
    snprintf(home, size, "/tmp/gswssh4homeXXXXXX");
    if (!mkdtemp(home) || setenv("HOME", home, 1) != 0) return -1;
    if ((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) >= sizeof(ssh_dir) ||
        mkdir(ssh_dir, 0700) != 0) {
        return -1;
    }
    if ((size_t)snprintf(config, config_size, "%s/config", ssh_dir) >= config_size) {
        return -1;
    }
    return 0;
}

static void make_alias_account(account_t *account, const char *home) {
    memset(account, 0, sizeof(*account));
    account->ssh_enabled = true;
    snprintf(account->ssh_host_alias, sizeof(account->ssh_host_alias), "github-work");
    snprintf(account->ssh_key_path, sizeof(account->ssh_key_path), "%s/id_ed25519", home);
}

TEST(host_alias_refuses_symlinked_config_without_touching_target) {
    char home[128], config[256], target[256], buf[128], link_target[256];
    const char *original = "Host preserved\n  User alice\n";
    struct stat before, after, link_st;
    account_t account;
    FILE *file;
    ssize_t n;

    CHECK_EQ_INT(setup_home(home, sizeof(home), config, sizeof(config)), 0);
    snprintf(target, sizeof(target), "%s/dotfiles-ssh-config", home);
    file = fopen(target, "w");
    CHECK(file != NULL);
    if (file) {
        fputs(original, file);
        fclose(file);
    }
    CHECK_EQ_INT(chmod(target, 0640), 0);
    CHECK_EQ_INT(stat(target, &before), 0);
    CHECK_EQ_INT(symlink(target, config), 0);
    make_alias_account(&account, home);

    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1); /* pre-fix: 0 */

    CHECK_EQ_INT(lstat(config, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));
    n = readlink(config, link_target, sizeof(link_target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        link_target[n] = '\0';
        CHECK_STR_EQ(link_target, target);
    }
    CHECK_EQ_INT(stat(target, &after), 0);
    CHECK(before.st_ino == after.st_ino);
    CHECK((before.st_mode & 0777) == (after.st_mode & 0777));
    file = fopen(target, "r");
    CHECK(file != NULL);
    if (file) {
        size_t got = fread(buf, 1, sizeof(buf) - 1, file);
        buf[got] = '\0';
        fclose(file);
        CHECK_STR_EQ(buf, original);
    }
}

TEST(host_alias_refuses_non_regular_config_components) {
    char home[128], config[256];
    struct stat st;
    account_t account;

    CHECK_EQ_INT(setup_home(home, sizeof(home), config, sizeof(config)), 0);
    make_alias_account(&account, home);
    CHECK_EQ_INT(mkdir(config, 0700), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
    CHECK_EQ_INT(lstat(config, &st), 0);
    CHECK(S_ISDIR(st.st_mode));

    CHECK_EQ_INT(rmdir(config), 0);
    CHECK_EQ_INT(mkfifo(config, 0600), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1); /* must not block */
    CHECK_EQ_INT(lstat(config, &st), 0);
    CHECK(S_ISFIFO(st.st_mode));
}

TEST(host_alias_updates_regular_and_creates_absent_config) {
    char home[128], config[256], buf[2048];
    struct stat st;
    account_t account;
    FILE *file;

    /* Absent final component is created as a private regular file. */
    CHECK_EQ_INT(setup_home(home, sizeof(home), config, sizeof(config)), 0);
    make_alias_account(&account, home);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    CHECK_EQ_INT(lstat(config, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0600);

    /* Existing regular content survives the managed-block splice. */
    CHECK_EQ_INT(setup_home(home, sizeof(home), config, sizeof(config)), 0);
    file = fopen(config, "w");
    CHECK(file != NULL);
    if (file) {
        fputs("Host personal\n  User alice\n", file);
        fclose(file);
    }
    CHECK_EQ_INT(chmod(config, 0600), 0);
    make_alias_account(&account, home);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    file = fopen(config, "r");
    CHECK(file != NULL);
    if (file) {
        size_t got = fread(buf, 1, sizeof(buf) - 1, file);
        buf[got] = '\0';
        fclose(file);
        CHECK(strstr(buf, "Host personal\n  User alice\n") != NULL);
        CHECK(strstr(buf, "# >>> gitswitch github-work >>>") != NULL);
    }
    CHECK_EQ_INT(lstat(config, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0600);
}

/* AR-04 H2/H3 manager truthfulness: a validated existing base that cannot be
 * locked must be left byte-for-byte untouched and reported as failure. */
TEST(reset_fails_closed_when_lock_is_unavailable) {
    char agent_dir[128], lock[192], pidfile[192], sock[192], current[192];

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(lock, sizeof(lock), "%s/.lock", agent_dir);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    CHECK_EQ_INT(mkdir(lock, 0700), 0); /* open(O_RDWR) must fail */
    CHECK_EQ_INT(write_text_file(pidfile, "424242\n"), 0);
    CHECK_EQ_INT(write_text_file(sock, "socket marker\n"), 0);
    CHECK_EQ_INT(symlink(sock, current), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 */
    CHECK(entry_exists(pidfile));
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
}

/* If a sidecar cannot establish a valid target PID, reset cannot confirm the
 * agent stopped. Retain the complete pid/socket/current retry tuple. */
TEST(reset_retains_artifacts_when_agent_stop_is_unconfirmed) {
    char agent_dir[128], pidfile[192], sock[192], current[192];

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    CHECK_EQ_INT(write_text_file(pidfile, "not-a-pid\n"), 0);
    CHECK_EQ_INT(write_text_file(sock, "socket marker\n"), 0);
    CHECK_EQ_INT(symlink(sock, current), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 + artifacts lost */
    CHECK(entry_exists(pidfile));
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
    CHECK(strstr(get_last_error()->message, "retained state for retry") != NULL);
}

/* Socket removal precedes stable-link removal. If the socket final component
 * cannot be unlinked, current.sock remains usable/inspectable and failure is
 * surfaced instead of reporting a completed teardown. */
TEST(reset_reports_socket_unlink_failure_and_retains_current) {
    char agent_dir[128], sock[192], current[192];

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    CHECK_EQ_INT(mkdir(sock, 0700), 0); /* unlink => EISDIR */
    CHECK_EQ_INT(symlink(sock, current), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 */
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
}

/* A malformed current.sock final component is itself an incomplete cleanup.
 * Independent removable state is still cleared to maximize progress. */
TEST(reset_reports_stable_link_cleanup_failure) {
    char agent_dir[128], sock[192], current[192];

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    CHECK_EQ_INT(write_text_file(sock, "stale socket\n"), 0);
    CHECK_EQ_INT(mkdir(current, 0700), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 */
    CHECK(!entry_exists(sock));
    CHECK(entry_exists(current));
}

/* All-account reset continues independent cleanup but returns aggregate
 * failure and preserves the failed account's complete retry tuple. */
TEST(reset_all_aggregates_failures_and_continues) {
    char agent_dir[128], bad_pid[192], bad_sock[192], good_sock[192], current[192];

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    snprintf(bad_pid, sizeof(bad_pid), "%s/ssh-agent.work.pid", agent_dir);
    snprintf(bad_sock, sizeof(bad_sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(good_sock, sizeof(good_sock), "%s/ssh-agent.personal.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    CHECK_EQ_INT(write_text_file(bad_pid, "invalid\n"), 0);
    CHECK_EQ_INT(write_text_file(bad_sock, "bad socket\n"), 0);
    CHECK_EQ_INT(write_text_file(good_sock, "stale socket\n"), 0);
    CHECK_EQ_INT(symlink(bad_sock, current), 0);

    CHECK_EQ_INT(ssh_manager_reset(NULL), -1); /* pre-fix: 0 */
    CHECK(entry_exists(bad_pid));
    CHECK(entry_exists(bad_sock));
    CHECK(entry_exists(current));
    CHECK(!entry_exists(good_sock)); /* independent cleanup continued */
}

/* HIGH regression: the absence of a sidecar does not prove an agent is dead.
 * A real reachable listener must survive targeted reset together with the
 * stable link, and the nonzero result preserves CLI retry metadata. */
TEST(targeted_reset_preserves_live_agent_when_sidecar_is_missing) {
    char agent_dir[128], sock[192], current[192], pidfile[192];
    pid_t pid = -1;
    int start_rc;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    start_rc = start_real_agent_without_sidecar(agent_dir, "work",
                                                 sock, sizeof(sock),
                                                 current, sizeof(current), &pid);
    if (start_rc == 1) return;
    CHECK_EQ_INT(start_rc, 0);
    if (start_rc != 0) return;
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    CHECK(!entry_exists(pidfile));

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(kill(pid, 0), 0);
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
    CHECK(strstr(get_last_error()->message, "no safely matched PID") != NULL);

    stop_real_agent(pid, sock, current);
}

/* A syntactically valid sidecar can be stale while another agent owns the
 * managed socket. Identity-refusing the bystander PID is not proof the socket
 * is dead: preserve the reachable runtime and leave both processes alive. */
TEST(targeted_reset_preserves_live_socket_when_sidecar_pid_is_bystander) {
    char agent_dir[128], sock[192], current[192], pidfile[192], pid_text[64];
    pid_t agent_pid = -1;
    pid_t bystander_pid = -1;
    int start_rc;
    int status = 0;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    start_rc = start_real_agent_without_sidecar(agent_dir, "work",
                                                 sock, sizeof(sock),
                                                 current, sizeof(current),
                                                 &agent_pid);
    if (start_rc == 1) return;
    CHECK_EQ_INT(start_rc, 0);
    if (start_rc != 0) return;

    fflush(NULL);
    bystander_pid = fork();
    CHECK(bystander_pid >= 0);
    if (bystander_pid == 0) {
        for (;;) pause();
    }
    if (bystander_pid < 0) {
        stop_real_agent(agent_pid, sock, current);
        return;
    }

    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)bystander_pid);
    CHECK_EQ_INT(write_text_file(pidfile, pid_text), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(kill(agent_pid, 0), 0);          /* socket owner untouched */
    CHECK_EQ_INT(kill(bystander_pid, 0), 0);      /* stale PID never signaled */
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
    CHECK(!entry_exists(pidfile)); /* safely-classified garbage record dropped */
    CHECK(strstr(get_last_error()->message, "no safely matched PID") != NULL);

    (void)kill(bystander_pid, SIGKILL);
    (void)waitpid(bystander_pid, &status, 0);
    stop_real_agent(agent_pid, sock, current);
}

/* The all-account path must make the same fail-closed classification instead
 * of treating a listening, sidecar-less agent as a stale socket. */
TEST(reset_all_preserves_live_agent_when_sidecar_is_missing) {
    char agent_dir[128], sock[192], current[192], pidfile[192];
    pid_t pid = -1;
    int start_rc;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    start_rc = start_real_agent_without_sidecar(agent_dir, "personal",
                                                 sock, sizeof(sock),
                                                 current, sizeof(current), &pid);
    if (start_rc == 1) return;
    CHECK_EQ_INT(start_rc, 0);
    if (start_rc != 0) return;
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.personal.pid", agent_dir);
    CHECK(!entry_exists(pidfile));

    CHECK_EQ_INT(ssh_manager_reset(NULL), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(kill(pid, 0), 0);
    CHECK(entry_exists(sock));
    CHECK(entry_exists(current));
    CHECK(strstr(get_last_error()->message, "no PID sidecar") != NULL);

    stop_real_agent(pid, sock, current);
}

#ifdef __APPLE__
/* Darwin's KERN_PROCARGS2 payload includes the environment after argv. The
 * identity check must size that payload from KERN_ARGMAX and still parse only
 * the kernel-reported argc entries; a >4 KiB environment used to truncate the
 * fixed buffer and make a managed agent permanently unreapable. */
TEST(darwin_reset_reaps_managed_agent_with_large_environment) {
    char agent_dir[128], sock[192], current[192], pidfile[192], pid_text[64];
    char *large_environment;
    char *saved_environment = NULL;
    const char *old_environment;
    bool had_environment;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
    pid_t pid = -1;
    int start_rc;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    large_environment = malloc(16385);
    CHECK(large_environment != NULL);
    if (!large_environment) return;
    memset(large_environment, 'x', 16384);
    large_environment[16384] = '\0';
    old_environment = getenv("GITSWITCH_TEST_LARGE_AGENT_ENV");
    had_environment = old_environment != NULL;
    if (had_environment) {
        saved_environment = strdup(old_environment);
        CHECK(saved_environment != NULL);
        if (!saved_environment) {
            free(large_environment);
            return;
        }
    }
    CHECK_EQ_INT(setenv("GITSWITCH_TEST_LARGE_AGENT_ENV",
                        large_environment, 1), 0);

    start_rc = start_real_agent_without_sidecar(agent_dir, "work",
                                                 sock, sizeof(sock),
                                                 current, sizeof(current), &pid);
    if (had_environment) {
        (void)setenv("GITSWITCH_TEST_LARGE_AGENT_ENV", saved_environment, 1);
    } else {
        (void)unsetenv("GITSWITCH_TEST_LARGE_AGENT_ENV");
    }
    free(saved_environment);
    free(large_environment);
    if (start_rc == 1) return;
    CHECK_EQ_INT(start_rc, 0);
    if (start_rc != 0) return;

    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)pid);
    CHECK_EQ_INT(write_text_file(pidfile, pid_text), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    for (int i = 0; i < 50 && kill(pid, 0) == 0; i++) {
        nanosleep(&delay, NULL);
    }
    CHECK(kill(pid, 0) != 0 && errno == ESRCH);
    CHECK(!entry_exists(pidfile));
    CHECK(!entry_exists(sock));
    CHECK(!entry_exists(current));

    if (kill(pid, 0) == 0) {
        stop_real_agent(pid, sock, current);
    }
}

/* Deterministic companion to the real-agent case above. Apple may omit the
 * environment of its restricted system ssh-agent from KERN_PROCARGS2, so run
 * an unrestricted copy of this test binary as an ssh-agent-shaped daemon.
 * Its 16 KiB environment makes the old 4096-byte retrieval fail every time. */
TEST(darwin_kern_procargs_reaps_unrestricted_large_environment_agent) {
    char agent_dir[128], helper[192], sock[192], current[192];
    char pidfile[192], pid_text[64];
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
    pid_t pid = -1;

    CHECK_EQ_INT(setup_runtime(agent_dir, sizeof(agent_dir)), 0);
    if (!unix_socket_bind_available(agent_dir)) return;
    snprintf(helper, sizeof(helper), "%s/ssh-agent", agent_dir);
    snprintf(sock, sizeof(sock), "%s/ssh-agent.work.sock", agent_dir);
    snprintf(current, sizeof(current), "%s/current.sock", agent_dir);
    snprintf(pidfile, sizeof(pidfile), "%s/ssh-agent.work.pid", agent_dir);
    CHECK_EQ_INT(darwin_copy_test_executable(helper), 0);
    if (!entry_exists(helper)) return;
    CHECK_EQ_INT(start_darwin_unrestricted_agent(helper, sock, &pid), 0);
    if (pid <= 1) {
        (void)unlink(helper);
        return;
    }
    CHECK_EQ_INT(symlink(sock, current), 0);
    snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)pid);
    CHECK_EQ_INT(write_text_file(pidfile, pid_text), 0);

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    for (int i = 0; i < 50 && kill(pid, 0) == 0; i++) {
        nanosleep(&delay, NULL);
    }
    CHECK(kill(pid, 0) != 0 && errno == ESRCH);
    CHECK(!entry_exists(pidfile));
    CHECK(!entry_exists(sock));
    CHECK(!entry_exists(current));

    if (kill(pid, 0) == 0) (void)kill(pid, SIGKILL);
    (void)unlink(helper);
}
#endif

int main(int argc, char **argv) {
    (void)argc;
#ifdef __APPLE__
    if (getenv("GITSWITCH_TEST_AGENT_HELPER")) {
        return darwin_agent_helper_main();
    }
    g_test_executable_path = argv[0];
#else
    (void)argv;
#endif
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(current_account_reports_absent_and_valid_live_socket);
    RUN_TEST(current_account_rejects_unsafe_malformed_and_stale_state);
    RUN_TEST(current_account_accepts_longest_bindable_name_without_truncation);
    RUN_TEST(current_account_fails_fast_when_manager_lock_held);
    RUN_TEST(fresh_agent_retarget_failure_reaps_and_restores_environment);
    RUN_TEST(fresh_agent_environment_failure_reaps_and_restores_partial_mutation);
    RUN_TEST(fresh_agent_aborts_when_orphan_cleanup_is_incomplete);
    RUN_TEST(reused_agent_retarget_failure_does_not_adopt_or_reap);
    RUN_TEST(reused_agent_aborts_when_other_orphan_cleanup_is_incomplete);
    RUN_TEST(host_alias_refuses_symlinked_config_without_touching_target);
    RUN_TEST(host_alias_refuses_non_regular_config_components);
    RUN_TEST(host_alias_updates_regular_and_creates_absent_config);
    RUN_TEST(reset_fails_closed_when_lock_is_unavailable);
    RUN_TEST(reset_retains_artifacts_when_agent_stop_is_unconfirmed);
    RUN_TEST(reset_reports_socket_unlink_failure_and_retains_current);
    RUN_TEST(reset_reports_stable_link_cleanup_failure);
    RUN_TEST(reset_all_aggregates_failures_and_continues);
    RUN_TEST(targeted_reset_preserves_live_agent_when_sidecar_is_missing);
    RUN_TEST(targeted_reset_preserves_live_socket_when_sidecar_pid_is_bystander);
    RUN_TEST(reset_all_preserves_live_agent_when_sidecar_is_missing);
#ifdef __APPLE__
    RUN_TEST(darwin_reset_reaps_managed_agent_with_large_environment);
    RUN_TEST(darwin_kern_procargs_reaps_unrestricted_large_environment_agent);
#endif
    printf("\n%s: %d run, %d failed\n",
           ts_tests_failed ? "RESULT FAIL" : "RESULT OK",
           ts_tests_run, ts_tests_failed);
    return ts_tests_failed == 0 ? 0 : 1;
}
