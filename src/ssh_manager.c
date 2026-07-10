/* SSH key and agent management with comprehensive isolation and security
 * Implements per-account SSH agents to prevent key leakage between accounts
 */

/* flock()/LOCK_EX are BSD extensions, not POSIX, and syscall()/pidfd need the
 * GNU namespace on glibc. On macOS they need _DARWIN_C_SOURCE; on the BSDs they
 * need the default fully-visible namespace, so defining _POSIX_C_SOURCE there
 * (strict POSIX) hides them and the build fails. On Linux use _GNU_SOURCE (a
 * superset of _POSIX_C_SOURCE) so flock AND syscall()/SYS_pidfd_* are visible. */
#if defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#elif defined(__linux__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <poll.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#include "ssh_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "signals.h"

/* Internal helper functions */
static int ssh_run(char *output, size_t output_size, bool merge_stderr, ...);
static int setup_ssh_environment(ssh_config_t *ssh_config);
static int create_isolated_agent_socket_dir(char *socket_dir, size_t socket_dir_size);
static int validate_ssh_agent_socket(const char *socket_path);
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config);
static int kill_orphaned_gitswitch_agents(const char *keep_account);

typedef struct {
    char *auth_sock;
    char *agent_pid;
} ssh_env_snapshot_t;

/* Narrow dependency seam for exercising partial setenv failures. Production
 * always uses libc setenv; tests can replace it temporarily and must restore
 * the returned previous function. Snapshot rollback deliberately keeps using
 * libc directly so an injected failure cannot disable recovery itself. */
static ssh_setenv_fn g_ssh_setenv = setenv;

ssh_setenv_fn ssh_manager_set_setenv_fn(ssh_setenv_fn fn) {
    ssh_setenv_fn previous = g_ssh_setenv;
    g_ssh_setenv = fn ? fn : setenv;
    return previous;
}

/* setup_ssh_environment mutates the process environment before the stable
 * current.sock link is committed. Preserve the old values so a failed commit
 * does not leave this process pointed at an account it rejected. */
static int ssh_env_snapshot_take(ssh_env_snapshot_t *snapshot) {
    const char *value;

    memset(snapshot, 0, sizeof(*snapshot));
    value = getenv("SSH_AUTH_SOCK");
    if (value) {
        snapshot->auth_sock = strdup(value);
        if (!snapshot->auth_sock) {
            set_error(ERR_MEMORY_ALLOCATION, "Failed to snapshot SSH_AUTH_SOCK");
            return -1;
        }
    }
    value = getenv("SSH_AGENT_PID");
    if (value) {
        snapshot->agent_pid = strdup(value);
        if (!snapshot->agent_pid) {
            free(snapshot->auth_sock);
            snapshot->auth_sock = NULL;
            set_error(ERR_MEMORY_ALLOCATION, "Failed to snapshot SSH_AGENT_PID");
            return -1;
        }
    }
    return 0;
}

static void ssh_env_snapshot_restore(ssh_env_snapshot_t *snapshot) {
    if (snapshot->auth_sock) {
        (void)setenv("SSH_AUTH_SOCK", snapshot->auth_sock, 1);
    } else {
        (void)unsetenv("SSH_AUTH_SOCK");
    }
    if (snapshot->agent_pid) {
        (void)setenv("SSH_AGENT_PID", snapshot->agent_pid, 1);
    } else {
        (void)unsetenv("SSH_AGENT_PID");
    }
    free(snapshot->auth_sock);
    free(snapshot->agent_pid);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ssh_env_snapshot_discard(ssh_env_snapshot_t *snapshot) {
    free(snapshot->auth_sock);
    free(snapshot->agent_pid);
    memset(snapshot, 0, sizeof(*snapshot));
}

/* Return true only for a NUL-separated argv whose executable is ssh-agent and
 * whose `-a` value is the exact managed socket. Requiring the option/value
 * pair, rather than a substring anywhere in the command line, avoids adopting
 * or signaling another ssh-agent whose unrelated argument merely mentions the
 * same path. */
static bool argv_is_our_ssh_agent(const char *argv, size_t argv_len,
                                  const char *expected_sock) {
    bool expect_socket = false;
    bool matched_socket = false;
    size_t offset = 0;
    size_t index = 0;

    if (!argv || argv_len == 0 || !expected_sock || !*expected_sock) {
        return false;
    }

    while (offset < argv_len) {
        const char *token = argv + offset;
        size_t token_len = strnlen(token, argv_len - offset);
        if (token_len == argv_len - offset) {
            return false; /* truncated/non-terminated process arguments */
        }
        if (token_len == 0) {
            offset++;
            continue;
        }

        if (index == 0) {
            const char *basename = strrchr(token, '/');
            basename = basename ? basename + 1 : token;
            if (strcmp(basename, "ssh-agent") != 0) {
                return false;
            }
        } else if (expect_socket) {
            if (strcmp(token, expected_sock) != 0) {
                return false;
            }
            matched_socket = true;
            expect_socket = false;
        } else if (strcmp(token, "-a") == 0) {
            if (matched_socket) {
                return false; /* ambiguous duplicate socket option */
            }
            expect_socket = true;
        }

        index++;
        offset += token_len + 1;
    }
    return matched_socket && !expect_socket;
}

#ifdef __APPLE__
/* KERN_PROCARGS2 includes the environment after argv. Parse exactly the argc
 * entries reported by the kernel so an environment variable that happens to
 * contain "-a" and a managed socket can never authorize signaling a process.
 * Empty argv entries still count toward argc, as they do in the kernel's
 * flattened representation. */
static bool counted_argv_is_our_ssh_agent(const char *argv, size_t argv_len,
                                          int argc,
                                          const char *expected_sock) {
    bool expect_socket = false;
    bool matched_socket = false;
    size_t offset = 0;

    if (!argv || argv_len == 0 || argc <= 0 ||
        !expected_sock || !*expected_sock) {
        return false;
    }

    for (int index = 0; index < argc; index++) {
        const char *token;
        size_t token_len;

        if (offset >= argv_len) {
            return false;
        }
        token = argv + offset;
        token_len = strnlen(token, argv_len - offset);
        if (token_len == argv_len - offset) {
            return false; /* truncated/non-terminated argv entry */
        }

        if (index == 0) {
            const char *basename = strrchr(token, '/');
            basename = basename ? basename + 1 : token;
            if (strcmp(basename, "ssh-agent") != 0) {
                return false;
            }
        } else if (expect_socket) {
            if (strcmp(token, expected_sock) != 0) {
                return false;
            }
            matched_socket = true;
            expect_socket = false;
        } else if (strcmp(token, "-a") == 0) {
            if (matched_socket) {
                return false; /* ambiguous duplicate socket option */
            }
            expect_socket = true;
        }

        offset += token_len + 1;
    }
    return matched_socket && !expect_socket;
}
#endif

/* Best-effort check that a PID recorded in a sidecar still belongs to OUR
 * ssh-agent before we SIGTERM it. Sidecars can outlive their agent (crash,
 * logout, reboot on a /tmp-preserving distro); once the kernel recycles that
 * PID, a blind kill would terminate an unrelated process. Checking only that
 * the PID is *an* ssh-agent is not enough: the recycled PID may belong to the
 * user's OWN login/session ssh-agent (comm is also "ssh-agent"), and killing it
 * drops every key they had loaded. Require BOTH the ssh-agent executable and
 * our exact `-a <expected_sock>` argv pair. Linux exposes argv through procfs;
 * Darwin and FreeBSD expose it through their native process sysctl APIs. Any
 * unavailable, truncated, or unparseable identity fails closed. */
static bool pid_is_our_ssh_agent(pid_t pid, const char *expected_sock) {
    if (pid <= 1) {
        return false;
    }
#ifdef __linux__
    char path[64];
    char comm[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return false; /* no such process (or no /proc entry) — don't kill */
    }
    bool is_agent = false;
    if (fgets(comm, sizeof(comm), f)) {
        comm[strcspn(comm, "\n")] = '\0';
        is_agent = (strcmp(comm, "ssh-agent") == 0);
    }
    fclose(f);
    if (!is_agent) {
        return false;
    }

    /* Require our exact socket option in the process's argv to defeat PID reuse. */
    if (!expected_sock || !*expected_sock) {
        return false;
    }
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    char cmd[4096];
    ssize_t n = read(fd, cmd, sizeof(cmd));
    close(fd);
    if (n <= 0) {
        return false;
    }
    return argv_is_our_ssh_agent(cmd, (size_t)n, expected_sock);
#elif defined(__APPLE__)
    /* KERN_PROCARGS2 begins with argc, then the executable path, alignment
     * NULs, the NUL-separated argv vector, then the environment. A fixed
     * buffer is unsafe here: when argv+environment exceeds it, XNU may not
     * return the prefix containing argc/executable/argv. KERN_ARGMAX is the
     * kernel's upper bound for the complete process argument area. */
    int argmax_mib[2] = {CTL_KERN, KERN_ARGMAX};
    int process_mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    int argmax = 0;
    int argc = 0;
    size_t argmax_len = sizeof(argmax);
    char *process_args;
    bool matched;

    if (sysctl(argmax_mib, 2, &argmax, &argmax_len, NULL, 0) != 0 ||
        argmax_len != sizeof(argmax) || argmax <= (int)sizeof(int)) {
        return false;
    }
    size_t process_args_len = (size_t)argmax;
    process_args = malloc(process_args_len);
    if (!process_args) {
        return false;
    }
    if (sysctl(process_mib, 3, process_args, &process_args_len, NULL, 0) != 0 ||
        process_args_len <= sizeof(argc)) {
        free(process_args);
        return false;
    }
    memcpy(&argc, process_args, sizeof(argc));
    if (argc <= 0) {
        free(process_args);
        return false;
    }
    size_t offset = sizeof(int);
    size_t executable_len = strnlen(process_args + offset,
                                    process_args_len - offset);
    if (executable_len == 0 || executable_len == process_args_len - offset) {
        free(process_args);
        return false;
    }
    const char *executable = process_args + offset;
    const char *executable_basename = strrchr(executable, '/');
    executable_basename = executable_basename ? executable_basename + 1
                                              : executable;
    if (strcmp(executable_basename, "ssh-agent") != 0) {
        free(process_args);
        return false;
    }
    offset += executable_len + 1;
    while (offset < process_args_len && process_args[offset] == '\0') {
        offset++;
    }
    matched = offset < process_args_len &&
              counted_argv_is_our_ssh_agent(process_args + offset,
                                             process_args_len - offset,
                                             argc, expected_sock);
    free(process_args);
    return matched;
#elif defined(__FreeBSD__)
    /* FreeBSD's KERN_PROC_ARGS result is already a flattened NUL-separated
     * argv vector for the requested PID. */
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ARGS, (int)pid};
    char process_args[4096];
    size_t process_args_len = sizeof(process_args);
    if (sysctl(mib, 4, process_args, &process_args_len, NULL, 0) != 0) {
        return false;
    }
    return argv_is_our_ssh_agent(process_args, process_args_len, expected_sock);
#else
    /* Unknown platforms have no proven PID ownership mechanism here. Never
     * turn mere liveness into authority to signal the process. */
    (void)expected_sock;
    return false;
#endif
}

/* Wait up to `total_ms` for `pid` to disappear. ssh-agent daemonizes (it is
 * reparented to init, not our child), so kill(pid, 0) flips to ESRCH as soon
 * as init reaps it — no waitpid involved. Poll with exponential backoff
 * (1ms doubling to a 50ms cap) inside the same total budget: the very first
 * liveness check runs before the just-signaled agent has even been scheduled,
 * so a fixed 50ms interval used to stack ~50ms of dead time per reaped agent
 * — all of it under the held agent-dir lock (AR-03 L19). A healthy agent
 * exits within the first millisecond or two. */
static bool wait_pid_gone(pid_t pid, int total_ms) {
    int waited = 0;
    int delay = 1;
    while (waited < total_ms) {
        if (kill(pid, 0) != 0) {
            return true;
        }
        int slice = delay < total_ms - waited ? delay : total_ms - waited;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = slice * 1000000L };
        nanosleep(&ts, NULL);
        waited += slice;
        if (delay < 50) {
            delay = delay * 2 < 50 ? delay * 2 : 50;
        }
    }
    return kill(pid, 0) != 0;
}

/* Verify a recorded PID is our agent (holding `sock`), SIGTERM it, confirm
 * death, and escalate to SIGKILL if it lingers (AR-02 #20 — a single fired-
 * and-forgotten SIGTERM let a stopped/stuck agent survive teardown holding
 * the decrypted key, while both callers unlinked its sidecar immediately,
 * leaving it permanently unreapable). Returns true when the recorded agent is
 * GONE — killed and confirmed dead, already dead, or the PID isn't our agent
 * at all (stale record, safe to drop) — so callers may remove the sidecar.
 * Returns false when our agent is still alive despite SIGKILL (e.g. wedged in
 * uninterruptible I/O): the caller must then KEEP the sidecar so a future run
 * can retry the reap.
 *
 * On Linux, pin the process with a pidfd BEFORE verifying+signaling so a PID
 * recycled in the check-then-signal window (CONC-4 TOCTOU) cannot receive
 * either signal — the pidfd refers to a specific process instance, not a
 * reusable number. Where pidfd is unavailable (older kernels, non-Linux) fall
 * back to plain kill guarded by the identity check, re-verified before the
 * SIGKILL escalation. */
static bool reap_ssh_agent(pid_t pid, const char *sock) {
    if (pid <= 1) {
        return true;
    }
#if defined(__linux__) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    int pidfd = (int)syscall(SYS_pidfd_open, (long)pid, 0L);
    if (pidfd >= 0) {
        bool gone = true;
        if (pid_is_our_ssh_agent(pid, sock)) {
            syscall(SYS_pidfd_send_signal, (long)pidfd, (long)SIGTERM, (void *)0, 0L);
            gone = wait_pid_gone(pid, 500);
            if (!gone) {
                log_warning("ssh-agent PID %ld ignored SIGTERM; escalating to SIGKILL",
                            (long)pid);
                syscall(SYS_pidfd_send_signal, (long)pidfd, (long)SIGKILL, (void *)0, 0L);
                gone = wait_pid_gone(pid, 500);
            }
        }
        close(pidfd);
        return gone;
    }
    /* pidfd_open unsupported/failed (ENOSYS on <5.3): fall through. */
#endif
    if (pid_is_our_ssh_agent(pid, sock)) {
        if (kill(pid, SIGTERM) != 0) {
            return kill(pid, 0) != 0; /* raced its exit, or EPERM (not ours) */
        }
        bool gone = wait_pid_gone(pid, 500);
        /* Re-verify identity before the harder signal: without a pidfd the
         * PID could have been recycled during the wait. */
        if (!gone && pid_is_our_ssh_agent(pid, sock)) {
            log_warning("ssh-agent PID %ld ignored SIGTERM; escalating to SIGKILL",
                        (long)pid);
            kill(pid, SIGKILL);
            gone = wait_pid_gone(pid, 500);
        }
        return gone;
    }
    return true; /* recorded PID is not our agent: the record itself is garbage */
}

/* Best-effort teardown of a just-spawned agent that failed the post-spawn
 * checks (output parse, socket validation) BEFORE its PID sidecar was
 * written. Such an agent is invisible to the sidecar-driven reaper forever,
 * so it either dies here or holds the account's decrypted key until reboot
 * (AR-03 H1). When the parsed PID is unknown (unparseable output), fall back
 * to scanning /proc for an ssh-agent whose argv carries our exact socket
 * path — the same identity proof pid_is_our_ssh_agent demands of sidecar
 * PIDs. Where /proc is unavailable (BSD/macOS) no safe scan exists; unlinking
 * the socket at least guarantees no future run can validate/adopt the
 * orphan, and -s (see the spawn site) makes the PID-less case unreachable
 * there in practice. */
static void reap_unrecorded_agent(pid_t pid, const char *sock) {
    if (pid > 1) {
        reap_ssh_agent(pid, sock);
    }
#ifdef __linux__
    else {
        DIR *d = opendir("/proc");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                char *end = NULL;
                long scan = strtol(ent->d_name, &end, 10);
                if (end && *end == '\0' && scan > 1 &&
                    pid_is_our_ssh_agent((pid_t)scan, sock)) {
                    reap_ssh_agent((pid_t)scan, sock);
                }
            }
            closedir(d);
        }
    }
#endif
    unlink(sock);
}

/* Guard the agent socket base before scanning/locking/unlinking under it.
 * When XDG_RUNTIME_DIR is unset the base is the predictable
 * /tmp/gitswitch-ssh-<uid> in world-writable, sticky /tmp, so a co-located
 * user could pre-create it — or swap it for a symlink — and steer the
 * unlinks and the .lock open somewhere else entirely. The create path
 * already enforces this shape via ensure_private_dir(); the reset/orphan-
 * reap paths were asymmetric with the hardened gpg_manager_reset (AR-03 L6).
 * lstat (no follow) and refuse a symlink, a non-dir, a foreign owner, or any
 * group/other access. Returns 0 = safe, 1 = absent (nothing to do there),
 * -1 = unsafe (fail closed). */
static int agent_dir_is_safe(const char *dir) {
    struct stat st;
    if (lstat(dir, &st) != 0) {
        return 1;
    }
    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode) ||
        st.st_uid != getuid() || (st.st_mode & 077) != 0) {
        return -1;
    }
    return 0;
}

/* Acquire an exclusive, blocking flock on <dir>/.lock, serializing the
 * reap/start/symlink sequence against other gitswitch processes sharing this
 * directory. Returns the held fd (>=0) or -1; pass it to unlock_agent_dir when
 * the critical section ends. The lock is advisory but every writer takes it.
 * O_NOFOLLOW: the lock lives in a dir an attacker can pre-create under /tmp;
 * never follow a planted symlink to open (and flock, holding it open) an
 * arbitrary file elsewhere (AR-03 L6). */
static int lock_agent_dir(const char *dir) {
    char lock_path[MAX_PATH_LEN];
    if ((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock", dir) >= sizeof(lock_path)) {
        return -1;
    }
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void unlock_agent_dir(int fd) {
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

/* Copy the SHA256:... fingerprint token of the key at `key_path` into `buf`.
 * Uses `ssh-keygen -lf`, which reads the fingerprint from the key's public
 * portion without needing the passphrase. Returns 0 on success. */
static int ssh_key_fingerprint(const char *key_path, char *buf, size_t size) {
    char out[1024];
    const char *argv[] = { "ssh-keygen", "-lf", key_path, NULL };
    run_opts_t opts;
    run_result_t res;

    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    if (run_argv(argv, &opts, &res) != 0) {
        return -1;
    }

    /* Output: "<bits> SHA256:<hash> <comment> (<type>)". Extract the token
     * that starts with "SHA256:" (or "MD5:" on legacy setups). */
    const char *fp = strstr(out, "SHA256:");
    if (!fp) fp = strstr(out, "MD5:");
    if (!fp) return -1;

    size_t i = 0;
    while (fp[i] && fp[i] != ' ' && fp[i] != '\t' && fp[i] != '\n' && i + 1 < size) {
        buf[i] = fp[i];
        i++;
    }
    buf[i] = '\0';
    return i > 0 ? 0 : -1;
}

/* True if an ssh-agent is answering on `sock` AND holds EXACTLY the key at
 * `key_path` — one identity, fingerprint compared as a whole token — so
 * adopting it is safe and skips a passphrase re-prompt. Presence alone is not
 * enough (AR-03 M2): a foreign key injected into the per-account agent
 * (`SSH_AUTH_SOCK=current.sock ssh-add ~/.ssh/other_key`) would ride along
 * into the "isolated" session and let a push authenticate as the wrong
 * identity, so any extra identity refuses the reuse — the caller then kills
 * and restarts, loading only the account's key. A live agent holding a
 * *different* key — e.g. after `gitswitch edit` changed the key path — is
 * refused for the same reason. The agent is probed FIRST and the expected
 * fingerprint computed only once the probe answers (AR-03 L18): a stale
 * socket (dead agent) is the common miss, and running ssh-keygen before
 * knowing the agent is alive wasted a fork+exec on every such miss. Anything
 * indeterminate falls back to false (restart + load) rather than risk
 * adopting the wrong agent. */
static bool ssh_socket_has_key(const char *sock, const char *key_path) {
    char want_fp[256];
    char envbuf[MAX_PATH_LEN + 20];
    char out[2048];
    const char *env[2] = { NULL, NULL };
    const char *argv[] = { "ssh-add", "-l", NULL };
    run_opts_t opts;
    run_result_t res;

    if ((size_t)snprintf(envbuf, sizeof(envbuf), "SSH_AUTH_SOCK=%s", sock) >= sizeof(envbuf)) {
        return false;
    }
    env[0] = envbuf;
    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    opts.stderr_to_devnull = true;
    opts.extra_env = env;
    if (run_argv(argv, &opts, &res) != 0) {
        return false; /* exit 1 (no identities) / 2 (no agent) */
    }
    if (ssh_key_fingerprint(key_path, want_fp, sizeof(want_fp)) != 0) {
        return false;
    }

    /* Each `ssh-add -l` line is "<bits> <fingerprint> <comment> (<type>)".
     * Token-compare field 2 of every line: a substring search would accept a
     * prefix of a longer fingerprint or a match buried in a multi-key
     * listing. Adopt only a single-identity agent whose one fingerprint is
     * exactly ours. */
    int identities = 0;
    bool ours = false;
    char *saveptr = NULL;
    for (char *line = strtok_r(out, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *fsave = NULL;
        char *field = strtok_r(line, " \t", &fsave);          /* bits */
        field = field ? strtok_r(NULL, " \t", &fsave) : NULL; /* fingerprint */
        if (!field) {
            continue; /* blank line: not an identity */
        }
        identities++;
        if (strcmp(field, want_fp) == 0) {
            ours = true;
        }
    }
    return identities == 1 && ours;
}


/* Initialize SSH manager */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL ssh_config to ssh_manager_init");
        return -1;
    }
    
    log_debug("Initializing SSH manager with mode: %d", mode);
    
    /* Initialize structure */
    memset(ssh_config, 0, sizeof(ssh_config_t));
    ssh_config->mode = mode;
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    
    /* Validate the binaries this manager actually execs are available:
     * ssh-agent and ssh-add. `ssh` itself is deliberately NOT probed here
     * (AR-02 #24): only the best-effort connection test uses it — which
     * degrades gracefully through run_argv's own resolution failure — and
     * the boot-time resume path never execs it at all, so a missing `ssh`
     * was hard-failing resumes it could never affect. The probes themselves
     * are near-free now that find_command_path memoizes: the same resolution
     * is reused by every subsequent run_argv spawn. */
    if (!command_exists("ssh-agent")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-agent command not found in PATH");
        return -1;
    }

    if (!command_exists("ssh-add")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-add command not found in PATH");
        return -1;
    }
    
    /* Set up based on mode */
    switch (mode) {
        case SSH_AGENT_SYSTEM:
            /* Use existing SSH_AUTH_SOCK */
            if (getenv("SSH_AUTH_SOCK")) {
                safe_strncpy(ssh_config->agent_socket_path, getenv("SSH_AUTH_SOCK"),
                           sizeof(ssh_config->agent_socket_path));
                log_info("Using system SSH agent at: %s", ssh_config->agent_socket_path);
            } else {
                log_warning("No system SSH agent found (SSH_AUTH_SOCK not set)");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Will create isolated agents on demand */
            log_info("Initialized for isolated SSH agent mode");
            break;
            
        case SSH_AGENT_NONE:
            log_info("SSH agent management disabled");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode: %d", mode);
            return -1;
    }
    
    /* NB: the started agent is intentionally left running after this process
     * exits — shells export SSH_AUTH_SOCK=<dir>/current.sock and must keep
     * reaching it — so there is deliberately no atexit/signal teardown here.
     * A half-configured agent from a failed switch is reaped inline on the
     * error paths (ssh_manager_cleanup) instead. */
    log_info("SSH manager initialized successfully");
    return 0;
}

/* Cleanup SSH manager */
void ssh_manager_cleanup(ssh_config_t *ssh_config) {
    if (!ssh_config) {
        return;
    }
    
    log_debug("Cleaning up SSH manager");
    
    /* Stop agent if we own it */
    if (ssh_config->agent_owned && ssh_config->agent_pid > 0) {
        log_info("Stopping owned SSH agent (PID: %d)", ssh_config->agent_pid);
        ssh_stop_agent(ssh_config);
    }
    
    /* Clear sensitive data */
    secure_zero_memory(ssh_config, sizeof(ssh_config_t));
    
    log_debug("SSH manager cleanup complete");
}

/* Switch to account's SSH configuration */
int ssh_switch_account(ssh_config_t *ssh_config, const account_t *account) {
    char expanded_key_path[MAX_PATH_LEN];
    
    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_switch_account");
        return -1;
    }
    
    /* Skip if SSH not enabled for this account */
    if (!account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        log_debug("SSH not enabled for account: %s", account->name);
        return 0;
    }
    
    log_info("Switching SSH configuration for account: %s", account->name);
    
    /* Validate and expand key path */
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH, "Failed to expand SSH key path: %s", account->ssh_key_path);
        return -1;
    }
    
    /* Validate key file */
    if (ssh_validate_key_file(expanded_key_path) != 0) {
        return -1; /* Error already set */
    }
    
    /* Handle based on mode */
    switch (ssh_config->mode) {
        case SSH_AGENT_SYSTEM:
            /* Clear existing keys and add new one to system agent */
            if (strlen(ssh_config->agent_socket_path) > 0) {
                log_debug("Clearing system SSH agent keys");
                ssh_clear_agent_keys(ssh_config);
                
                log_debug("Adding key to system SSH agent: %s", expanded_key_path);
                if (ssh_add_key(ssh_config, expanded_key_path) != 0) {
                    set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to load key into system SSH agent");
                    return -1;
                }
            } else {
                log_warning("No system SSH agent available");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Start isolated agent for this account */
            if (ssh_start_isolated_agent(ssh_config, account) != 0) {
                return -1; /* Error already set */
            }

            /* Add key to isolated agent — unless we reused a live agent that
             * already holds it (skips a passphrase re-prompt). */
            if (!ssh_config->key_already_loaded &&
                ssh_add_key(ssh_config, expanded_key_path) != 0) {
                set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to load key into isolated SSH agent");
                return -1;
            }
            break;
            
        case SSH_AGENT_NONE:
            /* No agent management - just validate key */
            log_info("SSH agent management disabled - key validated but not loaded");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode");
            return -1;
    }
    
    /* A requested alias is part of the account's SSH routing contract. If the
     * managed block cannot be installed safely, fail the switch so the account
     * layer rolls back the agent/runtime commit instead of claiming success
     * with stale user SSH configuration. */
    if (strlen(account->ssh_host_alias) > 0) {
        if (ssh_configure_host_alias(account) != 0) {
            log_warning("Failed to configure SSH host alias: %s", account->ssh_host_alias);
            return -1;
        }
    }
    
    log_info("SSH configuration switched successfully for account: %s", account->name);
    return 0;
}

/* Start isolated SSH agent */
int ssh_start_isolated_agent(ssh_config_t *ssh_config, const account_t *account) {
    char output[1024];
    char socket_dir[MAX_PATH_LEN];
    char socket_path[MAX_PATH_LEN];
    char symlink_path[MAX_PATH_LEN];
    char pid_path[MAX_PATH_LEN] = "";
    ssh_env_snapshot_t env_snapshot;
    bool env_snapshot_taken = false;
    bool pid_recorded = false;

    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_start_isolated_agent");
        return -1;
    }

    log_info("Starting isolated SSH agent for account: %s", account->name);

    /* Create secure socket directory first, then take an exclusive lock on it
     * for the whole reap/start/symlink sequence. Without this, two concurrent
     * gitswitch invocations race: one's reaper SIGTERMs the agent the other
     * just started and unlinks its socket + current.sock, so shells briefly
     * see a dangling current.sock and one switch fails to load its key. */
    if (create_isolated_agent_socket_dir(socket_dir, sizeof(socket_dir)) != 0) {
        return -1;
    }
    int lock_fd = lock_agent_dir(socket_dir);
    if (lock_fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to lock SSH agent directory");
        return -1;
    }

    int rc = -1;
    memset(&env_snapshot, 0, sizeof(env_snapshot));
    ssh_config->key_already_loaded = false;

    /* Build this account's per-account socket path up front. Guard against the
     * kernel's sockaddr_un.sun_path cap (108 on Linux, 104 on the BSDs), NOT
     * just the 4096 buffer: validate_name permits long names (up to 255 bytes),
     * and a name long enough to push the socket path past sun_path makes
     * `ssh-agent -a` fail to bind with a confusing error. Reject early with a
     * clear message instead. */
    int spn = snprintf(socket_path, sizeof(socket_path),
                       "%s/ssh-agent.%s.sock", socket_dir, account->name);
    if (spn < 0 || (size_t)spn >= sizeof(socket_path)) {
        set_error(ERR_INVALID_ARGS, "SSH socket path too long");
        goto done;
    }
    if ((size_t)spn >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        set_error(ERR_INVALID_ARGS,
                  "Account name too long: the SSH agent socket path (%d bytes) "
                  "exceeds the %zu-byte UNIX socket limit. Use a shorter name.",
                  spn, sizeof(((struct sockaddr_un *)0)->sun_path));
        goto done;
    }

    /* Reuse fast path: if this account's agent is already alive and holds
     * EXACTLY this key (single identity, fingerprint token match — see
     * ssh_socket_has_key), adopt it instead of killing and restarting
     * (which forces a fresh ssh-add and, for a passphrase-protected key, a
     * PIN/passphrase re-prompt on every re-switch to the already-active
     * account). Matching the specific key means that after `gitswitch edit`
     * changes the key path, the stale agent is NOT reused and the new key gets
     * loaded. We still reap every OTHER account's agent so only this one stays
     * live. The key path is expanded (~ etc.) for the fingerprint lookup. */
    char reuse_key_path[MAX_PATH_LEN];
    bool have_reuse_key =
        account->ssh_enabled && strlen(account->ssh_key_path) > 0 &&
        expand_path(account->ssh_key_path, reuse_key_path, sizeof(reuse_key_path)) == 0;
    if (validate_ssh_agent_socket(socket_path) == 0 && have_reuse_key &&
        ssh_socket_has_key(socket_path, reuse_key_path)) {
        ssh_config_t adopted = *ssh_config;
        safe_strncpy(adopted.agent_socket_path, socket_path,
                     sizeof(adopted.agent_socket_path));
        adopted.agent_pid = -1;
        adopted.agent_owned = true;
        adopted.key_already_loaded = true;

        /* Recover the PID from the sidecar so cleanup/stop can still target
         * it — but only after verifying it is genuinely OUR agent on this
         * socket (AR-02 #18). The sidecar can be stale (crash, reboot on a
         * /tmp-preserving distro) with its PID since recycled; trusting it
         * blindly would mark an unrelated process agent_owned=true and feed
         * it into the kill path later. The socket itself was already
         * fingerprint-verified, so a rejected PID only costs precise
         * stop-by-pid targeting, not the reuse. */
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            FILE *pf = fopen(pid_path, "r");
            if (pf) {
                long pid = 0;
                if (fscanf(pf, "%ld", &pid) == 1 && pid > 1 &&
                    pid_is_our_ssh_agent((pid_t)pid, socket_path)) {
                    adopted.agent_pid = (pid_t)pid;
                }
                fclose(pf);
            }
        }

        /* Enforce one-account isolation before publishing this reused agent.
         * Cleanup failures are retained-state failures, not warnings: adopting
         * this agent while another managed listener cannot be classified or
         * reaped would violate the isolation promise. Running this before the
         * environment/link commit also leaves the prior stable link untouched
         * on failure. */
        if (kill_orphaned_gitswitch_agents(account->name) != 0) {
            goto done;
        }

        /* The stable link is the commit point. Environment and retarget errors
         * remain fatal and restore the caller's environment; the account-level
         * transaction restores any previous runtime that the successful orphan
         * cleanup above had to retire. */
        if (ssh_env_snapshot_take(&env_snapshot) != 0) {
            goto done;
        }
        env_snapshot_taken = true;
        if (setup_ssh_environment(&adopted) != 0) {
            ssh_env_snapshot_restore(&env_snapshot);
            env_snapshot_taken = false;
            set_error(ERR_SSH_AGENT_START_FAILED,
                      "Failed to set up SSH environment for reused agent");
            goto done;
        }
        if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                             "%s/current.sock", socket_dir) >= sizeof(symlink_path)) {
            ssh_env_snapshot_restore(&env_snapshot);
            env_snapshot_taken = false;
            set_error(ERR_INVALID_PATH, "Stable SSH socket path too long");
            goto done;
        }
        if (atomic_symlink(socket_path, symlink_path) != 0) {
            ssh_env_snapshot_restore(&env_snapshot);
            env_snapshot_taken = false;
            goto done;
        }

        ssh_env_snapshot_discard(&env_snapshot);
        env_snapshot_taken = false;
        *ssh_config = adopted;
        log_info("Reusing live SSH agent for account: %s", account->name);
        rc = 0;
        goto done;
    }

    /* Kill any orphaned gitswitch agents from previous runs (including a stale
     * agent for this same account, which we're about to replace). */
    if (kill_orphaned_gitswitch_agents(NULL) != 0) {
        goto done;
    }

    /* Stop any existing agent we own */
    if (ssh_config->agent_owned && ssh_config->agent_pid > 0) {
        log_debug("Stopping existing SSH agent");
        ssh_stop_agent(ssh_config);
    }

    /* Remove stale socket if it exists */
    if (path_exists(socket_path)) {
        log_debug("Removing stale SSH agent socket: %s", socket_path);
        if (unlink(socket_path) != 0) {
            set_system_error(ERR_FILE_IO, "Failed to remove stale SSH socket");
            goto done;
        }
    }

    /* Start ssh-agent on the per-account socket (no shell). `-s` pins the
     * output to Bourne syntax: without it ssh-agent guesses the format from
     * the inherited $SHELL, and a csh/tcsh login shell made it emit
     * `setenv SSH_AUTH_SOCK ...` lines the (deliberately Bourne-only) parser
     * below cannot read — so every switch failed AFTER the agent was already
     * alive but BEFORE its PID sidecar existed, leaking one unreapable
     * key-holding agent per attempt (AR-03 H1). Capture its stdout (the eval
     * script) only; stderr stays on the terminal. */
    log_debug("Starting SSH agent on socket: %s", socket_path);
    if (ssh_run(output, sizeof(output), false, "ssh-agent", "-s", "-a", socket_path, NULL) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to start SSH agent");
        goto done;
    }

    /* Parse ssh-agent output for the PID. Do NOT trust the echoed SSH_AUTH_SOCK
     * path: modern OpenSSH ssh-agent double-quotes it when the path contains
     * shell-special characters — which validate_name permits in account names
     * (spaces/parens, e.g. "Jane Doe (Work)") — so the quotes would be taken
     * literally and the socket "not found", silently breaking SSH for that
     * account. We passed `-a socket_path`, so that is the authoritative path;
     * use it directly and keep only the parsed PID. */
    if (parse_ssh_agent_output(output, ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        /* The agent is typically already alive and bound to socket_path here,
         * but its PID sidecar does not exist yet, so the sidecar-driven
         * reaper could never find it: reap it now while we still know the
         * socket it was started on, or it holds the key until reboot
         * (AR-03 H1). The parsed PID may be unknown on this path. */
        reap_unrecorded_agent(ssh_config->agent_pid, socket_path);
        ssh_config->agent_pid = -1;
        goto done;
    }
    safe_strncpy(ssh_config->agent_socket_path, socket_path,
                 sizeof(ssh_config->agent_socket_path));

    /* Validate the agent is working */
    if (validate_ssh_agent_socket(ssh_config->agent_socket_path) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "SSH agent socket validation failed");
        /* Same pre-sidecar leak shape as the parse failure above, but the
         * parsed PID is known here, so the reap targets it directly. */
        reap_unrecorded_agent(ssh_config->agent_pid, socket_path);
        ssh_config->agent_pid = -1;
        goto done;
    }

    /* Mark as owned */
    ssh_config->agent_owned = true;

    /* Record the agent PID in a sidecar file so a later invocation can reap
     * this agent precisely by PID. This is FATAL on failure: the reaper only
     * kills PIDs it finds in sidecars, so an agent with no record would
     * outlive every future cleanup holding the account's decrypted key. If we
     * can't record it, stop the agent and fail the switch. */
    {
        bool recorded = false;
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            int pfd = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (pfd >= 0) {
                char pidbuf[32];
                int len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)ssh_config->agent_pid);
                if (len > 0 && write(pfd, pidbuf, (size_t)len) == (ssize_t)len) {
                    recorded = true;
                }
                close(pfd);
            }
        }
        pid_recorded = recorded;
        if (!recorded) {
            set_system_error(ERR_FILE_IO, "Failed to record SSH agent PID; stopping agent");
            ssh_stop_agent(ssh_config);
            if (pid_path[0]) {
                (void)unlink(pid_path);
            }
            goto done;
        }
    }

    /* Set up the process environment, but retain its prior values until the
     * stable-link commit succeeds so any failure is fully reversible. */
    if (ssh_env_snapshot_take(&env_snapshot) != 0) {
        goto fresh_commit_failed;
    }
    env_snapshot_taken = true;
    if (setup_ssh_environment(ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to set up SSH environment");
        goto fresh_commit_failed;
    }

    /* Atomically (re)point the stable current.sock at this agent's socket. It
     * is required, not warning-only: shells use this path, so without it the
     * new agent is not an active account. */
    if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                         "%s/current.sock", socket_dir) >= sizeof(symlink_path)) {
        set_error(ERR_INVALID_PATH, "Stable SSH socket path too long");
        goto fresh_commit_failed;
    }
    if (atomic_symlink(socket_path, symlink_path) != 0) {
        goto fresh_commit_failed;
    }
    log_debug("Created symlink: %s -> %s", symlink_path, socket_path);

    ssh_env_snapshot_discard(&env_snapshot);
    env_snapshot_taken = false;
    log_info("Isolated SSH agent started successfully (PID: %d, Socket: %s)",
             ssh_config->agent_pid, ssh_config->agent_socket_path);

    rc = 0;
    goto done;

fresh_commit_failed:
    if (env_snapshot_taken) {
        ssh_env_snapshot_restore(&env_snapshot);
        env_snapshot_taken = false;
    }
    if (ssh_config->agent_owned) {
        bool agent_gone = reap_ssh_agent(ssh_config->agent_pid, socket_path);
        if (agent_gone) {
            if (pid_recorded) {
                (void)unlink(pid_path);
            }
            (void)unlink(socket_path);
        } else {
            /* Preserve the sidecar/socket when a process survives: deleting
             * its only targeting information would make a future retry
             * impossible and leak a key-holding agent until reboot. */
            log_warning("SSH agent survived failed stable-link commit; keeping sidecar for retry");
        }
    }
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    ssh_config->key_already_loaded = false;
    ssh_config->agent_socket_path[0] = '\0';
done:
    if (env_snapshot_taken) {
        ssh_env_snapshot_discard(&env_snapshot);
    }
    unlock_agent_dir(lock_fd);
    return rc;
}

/* Stop SSH agent */
int ssh_stop_agent(ssh_config_t *ssh_config) {
    if (!ssh_config || ssh_config->agent_pid <= 0) {
        return 0; /* Nothing to stop */
    }
    
    if (!ssh_config->agent_owned) {
        log_debug("Not stopping SSH agent - we don't own it");
        return 0;
    }
    
    log_info("Stopping SSH agent (PID: %d)", ssh_config->agent_pid);

    /* Route through the same hardened reaper as every other kill path
     * (AR-02 #19): identity-verify the PID (comm + our socket in argv) and
     * pidfd-pin it before signaling, so a recorded PID that was recycled to
     * an unrelated same-uid process — or to the user's own login ssh-agent —
     * is never signaled. The old path gated only on kill(pid, 0) liveness. */
    if (reap_ssh_agent(ssh_config->agent_pid, ssh_config->agent_socket_path)) {
        log_debug("SSH agent stopped");
    } else {
        log_warning("SSH agent did not exit after SIGTERM/SIGKILL");
    }
    
    /* Clean up socket file */
    if (strlen(ssh_config->agent_socket_path) > 0) {
        if (unlink(ssh_config->agent_socket_path) == 0) {
            log_debug("Removed SSH agent socket: %s", ssh_config->agent_socket_path);
        } else {
            log_debug("Could not remove SSH agent socket (may already be gone)");
        }
    }
    
    /* Reset state */
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    ssh_config->agent_socket_path[0] = '\0';
    
    /* Clear environment */
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    
    return 0;
}

/* Clear all keys from SSH agent */
int ssh_clear_agent_keys(ssh_config_t *ssh_config) {
    char output[512];
    
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        log_debug("No SSH agent available to clear keys");
        return 0;
    }
    
    log_debug("Clearing all keys from SSH agent");
    
    /* Set up environment for ssh-add */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -D to delete all keys */
    if (ssh_run(output, sizeof(output), false, "ssh-add", "-D", NULL) != 0) {
        log_warning("Failed to clear SSH agent keys (agent may be empty)");
        /* This is not necessarily an error - agent might be empty */
    } else {
        log_debug("SSH agent keys cleared successfully");
    }
    
    return 0;
}

/* Add key to SSH agent */
int ssh_add_key(ssh_config_t *ssh_config, const char *key_path) {
    char output[512];

    if (!ssh_config || !key_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_add_key");
        return -1;
    }

    if (strlen(ssh_config->agent_socket_path) == 0) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "No SSH agent available");
        return -1;
    }

    log_debug("Adding SSH key to agent: %s", key_path);

    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }

    /* Execute ssh-add with the key path as a distinct argv element (no shell):
     * a path containing shell metacharacters can no longer be interpreted. */
    if (ssh_run(output, sizeof(output), false, "ssh-add", key_path, NULL) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s", output);
        return -1;
    }

    log_info("SSH key added successfully: %s", key_path);
    return 0;
}

/* List loaded SSH keys */
int ssh_list_keys(ssh_config_t *ssh_config, char *output, size_t output_size) {
    if (!ssh_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_list_keys");
        return -1;
    }
    
    if (strlen(ssh_config->agent_socket_path) == 0) {
        safe_strncpy(output, "No SSH agent available", output_size);
        return -1;
    }
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -l */
    if (ssh_run(output, output_size, false, "ssh-add", "-l", NULL) != 0) {
        safe_strncpy(output, "No keys loaded in SSH agent", output_size);
        return -1;
    }
    
    return 0;
}

/* Validate SSH key file */
int ssh_validate_key_file(const char *key_path) {
    struct stat key_stat;
    mode_t key_mode;
    
    if (!key_path) {
        set_error(ERR_INVALID_ARGS, "NULL key_path to ssh_validate_key_file");
        return -1;
    }
    
    /* Check if file exists */
    if (stat(key_path, &key_stat) != 0) {
        set_system_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s", key_path);
        return -1;
    }
    
    /* Check if it's a regular file */
    if (!S_ISREG(key_stat.st_mode)) {
        set_error(ERR_SSH_KEY_INVALID, "SSH key path is not a regular file: %s", key_path);
        return -1;
    }
    
    /* Check permissions - should be 600 (readable only by owner) */
    key_mode = key_stat.st_mode & 0777;
    if (key_mode != 0600) {
        set_error(ERR_SSH_KEY_PERMISSIONS, 
                  "SSH key file has unsafe permissions: %o (should be 600): %s",
                  key_mode, key_path);
        return -1;
    }
    
    /* Check ownership - should be owned by current user */
    if (key_stat.st_uid != getuid()) {
        set_error(ERR_SSH_KEY_OWNERSHIP, "SSH key file not owned by current user: %s", key_path);
        return -1;
    }
    
    /* Basic content validation - check it looks like a private key */
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        set_system_error(ERR_SSH_KEY_INVALID, "Cannot read SSH key file: %s", key_path);
        return -1;
    }
    
    char first_line[256];
    bool valid_key = false;
    
    if (fgets(first_line, sizeof(first_line), key_file)) {
        /* Check for common private key headers */
        if (strstr(first_line, "-----BEGIN") && 
            (strstr(first_line, "PRIVATE KEY") || 
             strstr(first_line, "RSA PRIVATE KEY") ||
             strstr(first_line, "OPENSSH PRIVATE KEY") ||
             strstr(first_line, "EC PRIVATE KEY"))) {
            valid_key = true;
        }
    }
    
    fclose(key_file);
    
    if (!valid_key) {
        set_error(ERR_SSH_KEY_INVALID, "File does not appear to be a valid SSH private key: %s", key_path);
        return -1;
    }
    
    log_debug("SSH key validation passed: %s", key_path);
    return 0;
}

/* A host alias is written verbatim into ~/.ssh/config, so restrict it to a
 * single line of safe characters (no whitespace/newlines/directive injection). */
static bool valid_ssh_host_alias(const char *alias) {
    if (!alias || !*alias) {
        return false;
    }
    for (const char *p = alias; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' ||
              *p == '_' || *p == '*' || *p == '?')) {
            return false;
        }
    }
    return true;
}

/* Read ~/.ssh/config without following its final component. The lstat/open/
 * fstat identity check closes the obvious symlink swap between policy check
 * and read; the caller re-checks the same inode immediately before rename. */
static int read_ssh_config_nofollow(const char *path, char *buf, size_t size,
                                    bool *existed, struct stat *identity) {
    struct stat before;
    struct stat opened;
    size_t used = 0;
    int fd;

    *existed = false;
    memset(identity, 0, sizeof(*identity));
    buf[0] = '\0';

    if (lstat(path, &before) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect SSH config: %s", path);
        return -1;
    }
    if (S_ISLNK(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to update symlinked SSH config: %s", path);
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to update non-regular SSH config: %s", path);
        return -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to open SSH config safely: %s", path);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        close(fd);
        set_error(ERR_FILE_IO, "SSH config changed while it was being opened: %s", path);
        return -1;
    }

    while (used < size - 1) {
        ssize_t n = read(fd, buf + used, size - 1 - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        set_system_error(ERR_FILE_IO, "Failed to read SSH config: %s", path);
        return -1;
    }
    if (used == size - 1) {
        char extra;
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            close(fd);
            if (n < 0) {
                set_system_error(ERR_FILE_IO, "Failed to read SSH config: %s", path);
            } else {
                set_error(ERR_FILE_IO, "SSH config too large to update safely");
            }
            return -1;
        }
    }
    close(fd);
    buf[used] = '\0';
    *existed = true;
    *identity = opened;
    return 0;
}

/* Refuse to rename over a path whose final component changed after the safe
 * read. For a previously absent config, any newly-created entry is a conflict;
 * for an existing config, only the exact regular-file inode may be replaced. */
static int ssh_config_recheck_before_rename(const char *path, bool existed,
                                            const struct stat *identity) {
    struct stat now;

    if (lstat(path, &now) != 0) {
        if (!existed && errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "SSH config changed before update: %s", path);
        return -1;
    }
    if (!existed || !S_ISREG(now.st_mode) ||
        now.st_dev != identity->st_dev || now.st_ino != identity->st_ino) {
        set_error(ERR_FILE_IO,
                  "SSH config changed before update; refusing to replace it: %s", path);
        return -1;
    }
    return 0;
}

/* Configure an SSH host alias in ~/.ssh/config. The block is delimited by
 * gitswitch markers and rewritten idempotently (no unbounded appending), and
 * deliberately does NOT weaken host-key checking. Written atomically at 0600. */
int ssh_configure_host_alias(const account_t *account) {
    char ssh_config_dir[MAX_PATH_LEN];
    char ssh_config_path[MAX_PATH_LEN];
    char tmp_path[MAX_PATH_LEN];
    char expanded_key_path[MAX_PATH_LEN];
    char begin_marker[MAX_NAME_LEN + 32];
    char end_marker[MAX_NAME_LEN + 32];
    char buf[65536];   /* on-disk content, prior managed block spliced out */
    char orig[65536];  /* untouched on-disk content (identical-rewrite check) */
    /* buf + fresh managed block: markers, Host line, IdentityFile path. */
    char newbuf[sizeof(buf) + MAX_PATH_LEN + 2 * (MAX_NAME_LEN + 32) + 64];
    const char *home = getenv("HOME");
    struct stat config_identity;
    bool config_existed;
    int fd;
    FILE *out;

    if (!account || strlen(account->ssh_host_alias) == 0) {
        return 0; /* Nothing to configure */
    }
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH, "HOME not set");
        return -1;
    }
    if (!valid_ssh_host_alias(account->ssh_host_alias)) {
        set_error(ERR_INVALID_ARGS, "Invalid SSH host alias: %s", account->ssh_host_alias);
        return -1;
    }

    log_debug("Configuring SSH host alias: %s", account->ssh_host_alias);

    if ((size_t)snprintf(ssh_config_dir, sizeof(ssh_config_dir), "%s/.ssh", home) >= sizeof(ssh_config_dir) ||
        (size_t)snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config", ssh_config_dir) >= sizeof(ssh_config_path) ||
        /* Unique temp template for mkstemp — never a fixed name. A shared
         * name let a concurrent writer's unlink()-and-recreate orphan this
         * process's in-progress temp, so our rename() could install the other
         * writer's partial file over the user's whole ~/.ssh/config. */
        (size_t)snprintf(tmp_path, sizeof(tmp_path), "%s/config.gitswitch.XXXXXX", ssh_config_dir) >= sizeof(tmp_path)) {
        set_error(ERR_INVALID_PATH, "SSH config path too long");
        return -1;
    }
    if (!path_exists(ssh_config_dir) && create_directory_recursive(ssh_config_dir, 0700) != 0) {
        return -1;
    }
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        return -1;
    }
    /* The expanded path is written below as an "IdentityFile <path>" line; a
     * newline/CR in it would inject an arbitrary ssh_config directive
     * (ProxyCommand => code execution on the next connect). This sink used to
     * rely entirely on the TOML-load sanitizer having stripped such bytes — an
     * incidental, load-time-only defense — so guard the write site itself
     * (AR-02 #10). */
    if (!is_safe_ssh_key_path(expanded_key_path)) {
        set_error(ERR_INVALID_PATH,
                  "SSH key path contains an illegal character (quote/control): %s",
                  expanded_key_path);
        return -1;
    }

    snprintf(begin_marker, sizeof(begin_marker), "# >>> gitswitch %s >>>", account->ssh_host_alias);
    snprintf(end_marker, sizeof(end_marker), "# <<< gitswitch %s <<<", account->ssh_host_alias);

    /* Load the existing config (if any), preserving all bytes except a prior
     * managed block for this alias, which we splice out. */
    buf[0] = '\0';
    orig[0] = '\0';
    if (read_ssh_config_nofollow(ssh_config_path, buf, sizeof(buf),
                                 &config_existed, &config_identity) != 0) {
        return -1;
    }
    if (config_existed) {
        memcpy(orig, buf, strlen(buf) + 1);
        char *bstart = strstr(buf, begin_marker);
        if (bstart) {
            char *bend = strstr(bstart, end_marker);
            /* back up to the start of the begin-marker line */
            char *line_start = bstart;
            while (line_start > buf && line_start[-1] != '\n') line_start--;
            if (bend) {
                char *after = strchr(bend, '\n');
                after = after ? after + 1 : bend + strlen(bend);
                memmove(line_start, after, strlen(after) + 1);
            } else {
                /* Malformed block: begin marker with no end marker. The old
                 * behavior truncated from the marker — which silently
                 * destroyed every USER stanza below the damaged block once
                 * the rename installed the result (AR-03 T5). Instead drop
                 * only the lines that are recognizably ours — the marker
                 * line, our "Host <alias>" line, and the indented options
                 * under it — and keep everything after: when in doubt about
                 * attribution, preserving user bytes is the safe direction
                 * (the worst case is a leftover stanza the user can see,
                 * never lost content). */
                char *p = strchr(line_start, '\n');
                p = p ? p + 1 : line_start + strlen(line_start);
                char hostline[MAX_NAME_LEN + 8];
                int hn = snprintf(hostline, sizeof(hostline), "Host %s",
                                  account->ssh_host_alias);
                if (hn > 0 && (size_t)hn < sizeof(hostline) &&
                    strncmp(p, hostline, (size_t)hn) == 0 &&
                    (p[hn] == '\n' || p[hn] == '\0')) {
                    char *q = strchr(p, '\n');
                    p = q ? q + 1 : p + strlen(p);
                    while (*p == ' ' || *p == '\t') { /* our option lines */
                        q = strchr(p, '\n');
                        p = q ? q + 1 : p + strlen(p);
                    }
                }
                memmove(line_start, p, strlen(p) + 1);
            }
        }
    }

    /* Assemble the final content and skip the whole write when it is
     * byte-identical to what is already on disk: the mkstemp+rename below
     * otherwise churned ~/.ssh/config's inode and mtime on every switch and
     * every boot-time resume — breaking hard links and waking dotfile-sync
     * watchers — for a no-op (AR-03 L16). */
    int need = snprintf(newbuf, sizeof(newbuf),
                        "%s%s%s\nHost %s\n  IdentityFile %s\n  IdentitiesOnly yes\n%s\n",
                        buf,
                        (buf[0] != '\0' && buf[strlen(buf) - 1] != '\n') ? "\n" : "",
                        begin_marker, account->ssh_host_alias,
                        expanded_key_path, end_marker);
    if (need < 0 || (size_t)need >= sizeof(newbuf)) {
        set_error(ERR_FILE_IO, "SSH config too large to update safely");
        return -1;
    }
    if (strcmp(newbuf, orig) == 0) {
        log_debug("SSH host alias block already current; skipping rewrite");
        return 0;
    }

    /* Write existing content + a fresh managed block, atomically at 0600.
     * mkstemp creates a fresh unique file (no collision with a concurrent
     * writer) and returns its fd; fchmod guarantees 0600 regardless of the
     * platform's mkstemp default. */
    fd = mkstemp(tmp_path);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to create temp SSH config");
        return -1;
    }
    /* mkstemp resolved the XXXXXX: register the temp with the emergency-
     * signal scratch table so a second Ctrl-C mid-write unlinks it instead
     * of stranding ~/.ssh/config.gitswitch.XXXXXX — this was the "remaining
     * hook point" acknowledged in signals.h (AR-03 L9). A failed
     * registration (full table) is tolerable: every exit path below still
     * unlinks the temp itself. */
    (void)signals_scratch_register(tmp_path);
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmp_path);
        signals_scratch_unregister(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to secure temp SSH config");
        return -1;
    }
    out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        unlink(tmp_path);
        signals_scratch_unregister(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to open temp SSH config");
        return -1;
    }
    fputs(newbuf, out);
    if (fclose(out) != 0) {
        unlink(tmp_path);
        signals_scratch_unregister(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to write SSH config");
        return -1;
    }
    if (ssh_config_recheck_before_rename(ssh_config_path, config_existed,
                                         &config_identity) != 0) {
        unlink(tmp_path);
        signals_scratch_unregister(tmp_path);
        return -1;
    }
    if (rename(tmp_path, ssh_config_path) != 0) {
        unlink(tmp_path);
        signals_scratch_unregister(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to install SSH config");
        return -1;
    }
    signals_scratch_unregister(tmp_path); /* temp renamed away: record done */

    log_info("SSH host alias configured: %s -> %s", account->ssh_host_alias, expanded_key_path);
    return 0;
}

/* Test SSH connection */
int ssh_test_connection(const account_t *account, const char *host) {
    char output[1024];

    if (!account || !host) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_test_connection");
        return -1;
    }
    
    log_debug("Testing SSH connection to: %s", host);
    
    /* Build SSH test command using -T (no TTY) for git hosting services
     * GitHub/GitLab/Bitbucket don't allow shell commands, they return a
     * greeting message on successful auth (exit code 1 but with success message) */
    /* Execute SSH test (merged stderr: git hosts print their greeting there)
     * with each option as a distinct argv element — no shell.
     * Note: GitHub returns exit code 1 even on success (no shell access). */
    if (strlen(account->ssh_host_alias) > 0) {
        (void)ssh_run(output, sizeof(output), true,
                      "ssh", "-T", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                      account->ssh_host_alias, NULL);
    } else {
        char expanded_key_path[MAX_PATH_LEN];
        if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
            return -1;
        }
        (void)ssh_run(output, sizeof(output), true,
                      "ssh", "-T", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                      "-i", expanded_key_path, host, NULL);
    }

    /* Check for authentication success messages from common git hosting services */
    if (strstr(output, "successfully authenticated") ||  /* GitHub */
        strstr(output, "Welcome to GitLab") ||           /* GitLab */
        strstr(output, "logged in as") ||                /* Bitbucket */
        strstr(output, "Hi ") ||                         /* GitHub greeting */
        strstr(output, "authentication successful")) {   /* Generic */
        log_debug("SSH authentication successful to %s", host);
        return 0;
    }

    log_debug("SSH connection test failed to %s: %s", host, output);
    return -1;
}

/* Internal helper functions */

/* Run an ssh/ssh-add/ssh-agent command (NULL-terminated varargs argv, argv[0]
 * is the first vararg), no shell. SSH_AUTH_SOCK/SSH_AGENT_PID are inherited from
 * the process env (set by setup_ssh_environment). When merge_stderr is false,
 * the child's stderr is left attached to the terminal so ssh-add's "Identity
 * added" message still reaches the user (preserving prior behavior). Trailing
 * newline in captured stdout is trimmed. Returns 0 iff the child exits 0. */
static int ssh_run(char *output, size_t output_size, bool merge_stderr, ...) {
    const char *argv[16];
    size_t n = 0;
    va_list ap;
    const char *a;
    run_opts_t opts;
    run_result_t res;
    int rc;

    va_start(ap, merge_stderr);
    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            va_end(ap);
            set_error(ERR_INVALID_ARGS, "Too many ssh arguments");
            return -1;
        }
        argv[n++] = a;
    }
    va_end(ap);
    argv[n] = NULL;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = merge_stderr;

    rc = run_argv(argv, &opts, &res);

    if (output && output_size > 0 && res.out_len > 0 && output[res.out_len - 1] == '\n') {
        output[res.out_len - 1] = '\0';
    }
    if (rc != 0) {
        return -1;
    }

    return 0;
}

/* Set up SSH environment variables */
static int setup_ssh_environment(ssh_config_t *ssh_config) {
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        return -1;
    }
    
    /* Set SSH_AUTH_SOCK */
    if (g_ssh_setenv("SSH_AUTH_SOCK", ssh_config->agent_socket_path, 1) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AUTH_SOCK");
        return -1;
    }
    
    /* Set SSH_AGENT_PID if we have it */
    if (ssh_config->agent_pid > 0) {
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", ssh_config->agent_pid);
        if (g_ssh_setenv("SSH_AGENT_PID", pid_str, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AGENT_PID");
            return -1;
        }
    }
    
    log_debug("SSH environment configured: SSH_AUTH_SOCK=%s, SSH_AGENT_PID=%d",
              ssh_config->agent_socket_path, ssh_config->agent_pid);
    return 0;
}

/* Public: compute the stable SSH_AUTH_SOCK symlink path.
 * Mirrors the selection done by create_isolated_agent_socket_dir() so shell
 * integration emitted by `gitswitch init` points at the same socket the
 * runtime maintains. */
int ssh_manager_get_auth_sock_path(char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        set_error(ERR_INVALID_ARGS, "NULL/empty buffer to ssh_manager_get_auth_sock_path");
        return -1;
    }

    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    int written;
    if (runtime_dir && *runtime_dir && path_exists(runtime_dir)) {
        written = snprintf(buf, buf_size, "%s/gitswitch-ssh/current.sock", runtime_dir);
    } else {
        written = snprintf(buf, buf_size, "/tmp/gitswitch-ssh-%d/current.sock", getuid());
    }

    if (written < 0 || (size_t)written >= buf_size) {
        set_error(ERR_INVALID_PATH, "SSH auth sock path too long");
        return -1;
    }
    return 0;
}

/* Create isolated agent socket directory */
static int create_isolated_agent_socket_dir(char *socket_dir, size_t socket_dir_size) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *tmp_dir = "/tmp";
    
    /* Prefer XDG_RUNTIME_DIR if available */
    if (runtime_dir && path_exists(runtime_dir)) {
        if ((size_t)snprintf(socket_dir, socket_dir_size, "%s/gitswitch-ssh", runtime_dir) >= socket_dir_size) {
            set_error(ERR_INVALID_PATH, "Socket directory path too long");
            return -1;
        }
    } else {
        if ((size_t)snprintf(socket_dir, socket_dir_size, "%s/gitswitch-ssh-%d", tmp_dir, getuid()) >= socket_dir_size) {
            set_error(ERR_INVALID_PATH, "Socket directory path too long");
            return -1;
        }
    }
    
    /* Create + verify the directory is a real, user-owned, 0700 dir (not a
     * symlink, not pre-created by another user in a shared /tmp). */
    if (ensure_private_dir(socket_dir) != 0) {
        return -1;
    }

    return 0;
}

/* kill_ssh_agent_gracefully and its bare-liveness is_ssh_agent_running are
 * gone (AR-02 #19): they SIGTERM'd/SIGKILL'd a recorded PID on nothing more
 * than kill(pid, 0) — the exact blind kill reap_ssh_agent was hardened
 * against. ssh_stop_agent now routes through reap_ssh_agent, which identity-
 * verifies and pidfd-pins the PID and already escalates with death polling. */

/* Validate SSH agent socket */
static int validate_ssh_agent_socket(const char *socket_path) {
    struct stat socket_stat;
    
    if (!socket_path) {
        return -1;
    }
    
    /* Check if socket exists */
    if (stat(socket_path, &socket_stat) != 0) {
        set_system_error(ERR_SSH_AGENT_SOCKET_INVALID, "SSH agent socket not found: %s", socket_path);
        return -1;
    }
    
    /* Check if it's a socket */
    if (!S_ISSOCK(socket_stat.st_mode)) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID, "Path is not a socket: %s", socket_path);
        return -1;
    }
    
    /* Check permissions */
    if ((socket_stat.st_mode & 0777) != 0600) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID, "SSH agent socket has wrong permissions: %s", socket_path);
        return -1;
    }
    
    return 0;
}

/* Parse ssh-agent output */
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config) {
    char *line;
    char *output_copy;
    char *saveptr;
    
    if (!output || !ssh_config) {
        return -1;
    }
    
    /* Make a copy of output for parsing */
    output_copy = strdup(output);
    if (!output_copy) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate memory for parsing");
        return -1;
    }
    
    /* Parse line by line */
    line = strtok_r(output_copy, "\n", &saveptr);
    while (line) {
        /* Look for SSH_AUTH_SOCK */
        if (strstr(line, "SSH_AUTH_SOCK=")) {
            char *socket_start = strchr(line, '=') + 1;
            char *socket_end = strchr(socket_start, ';');
            if (socket_end) {
                *socket_end = '\0';
            }
            /* ssh-agent quotes the value when the path has shell-special chars
             * (spaces/parens). Trim surrounding whitespace and a matching pair
             * of single/double quotes so the stored path is the real one. */
            while (*socket_start == ' ' || *socket_start == '\t') socket_start++;
            size_t slen = strlen(socket_start);
            while (slen > 0 && (socket_start[slen - 1] == ' ' ||
                                socket_start[slen - 1] == '\t')) {
                socket_start[--slen] = '\0';
            }
            if (slen >= 2 &&
                ((socket_start[0] == '"' && socket_start[slen - 1] == '"') ||
                 (socket_start[0] == '\'' && socket_start[slen - 1] == '\''))) {
                socket_start[slen - 1] = '\0';
                socket_start++;
            }
            safe_strncpy(ssh_config->agent_socket_path, socket_start,
                        sizeof(ssh_config->agent_socket_path));
        }
        
        /* Look for SSH_AGENT_PID */
        if (strstr(line, "SSH_AGENT_PID=")) {
            char *pid_start = strchr(line, '=') + 1;
            char *pid_end = strchr(pid_start, ';');
            if (pid_end) {
                *pid_end = '\0';
            }
            ssh_config->agent_pid = (pid_t)strtol(pid_start, NULL, 10);
        }
        
        line = strtok_r(NULL, "\n", &saveptr);
    }
    
    free(output_copy);
    
    /* Validate we got the required information */
    if (strlen(ssh_config->agent_socket_path) == 0 || ssh_config->agent_pid <= 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        return -1;
    }

    return 0;
}

/* Classify whether a sidecar-less socket path still has a live listener.
 * Merely finding the filesystem socket is insufficient: a dead ssh-agent
 * leaves the inode behind. A successful nonblocking connect proves a listener
 * is reachable; ECONNREFUSED/ENOENT proves the artifact is stale. Every other
 * outcome is indeterminate and therefore fail-closed. */
static int probe_ssh_agent_socket(const char *path, bool *reachable) {
    struct stat st;
    struct sockaddr_un addr;
    struct pollfd pfd;
    socklen_t err_len;
    int fd;
    int flags;
    int socket_error = 0;

    *reachable = false;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect sidecar-less SSH socket: %s", path);
        return -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        return 0; /* provably not a live UNIX-domain socket */
    }
    if (strlen(path) >= sizeof(addr.sun_path)) {
        set_error(ERR_INVALID_PATH,
                  "Cannot probe overlong sidecar-less SSH socket: %s", path);
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot create probe for sidecar-less SSH socket: %s", path);
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        set_system_error(ERR_SYSTEM_CALL,
                         "Cannot configure probe for sidecar-less SSH socket: %s", path);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_strncpy(addr.sun_path, path, sizeof(addr.sun_path));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        *reachable = true;
        close(fd);
        return 0;
    }
    if (errno == ECONNREFUSED || errno == ENOENT) {
        close(fd);
        return 0;
    }
    if (errno != EINPROGRESS && errno != EAGAIN && errno != EWOULDBLOCK) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Cannot prove sidecar-less SSH socket is unreachable: %s", path);
        return -1;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int poll_rc;
    do {
        poll_rc = poll(&pfd, 1, 100);
    } while (poll_rc < 0 && errno == EINTR);
    if (poll_rc <= 0) {
        int saved_errno = poll_rc < 0 ? errno : ETIMEDOUT;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Timed out probing sidecar-less SSH socket: %s", path);
        return -1;
    }

    err_len = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &err_len) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_SSH_AGENT_FAILED,
                         "Cannot finish probing sidecar-less SSH socket: %s", path);
        return -1;
    }
    close(fd);
    if (socket_error == 0) {
        *reachable = true;
        return 0;
    }
    if (socket_error == ECONNREFUSED || socket_error == ENOENT) {
        return 0;
    }
    errno = socket_error;
    set_system_error(ERR_SSH_AGENT_FAILED,
                     "Cannot prove sidecar-less SSH socket is unreachable: %s", path);
    return -1;
}

/* Read a PID sidecar without following or accepting a swapped final
 * component. Missing is reported as 1; a validated PID as 0; every state in
 * which reset cannot prove what it is targeting is an error and leaves the
 * sidecar in place for inspection/retry. */
static int read_ssh_agent_pid(const char *path, pid_t *pid_out) {
    struct stat before;
    struct stat opened;
    char buf[64];
    size_t used = 0;
    int fd;

    if (lstat(path, &before) != 0) {
        if (errno == ENOENT) {
            return 1;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect SSH agent PID sidecar: %s", path);
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing non-regular SSH agent PID sidecar: %s", path);
        return -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot open SSH agent PID sidecar safely: %s", path);
        return -1;
    }
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        close(fd);
        set_error(ERR_FILE_IO, "SSH agent PID sidecar changed while opening: %s", path);
        return -1;
    }
    while (used < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        set_system_error(ERR_FILE_IO, "Cannot read SSH agent PID sidecar: %s", path);
        return -1;
    }
    if (used == sizeof(buf) - 1) {
        char extra;
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            close(fd);
            set_error(ERR_FILE_IO, "SSH agent PID sidecar is too large: %s", path);
            return -1;
        }
    }
    close(fd);
    buf[used] = '\0';

    errno = 0;
    char *end = NULL;
    long parsed = strtol(buf, &end, 10);
    while (end && isspace((unsigned char)*end)) {
        end++;
    }
    if (errno != 0 || end == buf || !end || *end != '\0' || parsed <= 1 ||
        (long)(pid_t)parsed != parsed) {
        set_error(ERR_FILE_IO, "Invalid SSH agent PID sidecar; retained for retry: %s", path);
        return -1;
    }
    *pid_out = (pid_t)parsed;
    return 0;
}

static int unlink_ssh_reset_path(const char *path, const char *description) {
    if (unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }
    set_system_error(ERR_FILE_IO, "Failed to remove %s: %s", description, path);
    return -1;
}

/* Inspect current.sock without following it. Missing is success with
 * matches=false; a non-symlink or unreadable/truncated link is a cleanup
 * failure because reset cannot truthfully claim that the stable entry point
 * is in a known state. */
static int ssh_current_matches_socket(const char *current, const char *socket,
                                      bool *matches) {
    struct stat st;
    char target[MAX_PATH_LEN];
    ssize_t n;

    *matches = false;
    if (lstat(current, &st) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect stable SSH socket: %s", current);
        return -1;
    }
    if (!S_ISLNK(st.st_mode)) {
        set_error(ERR_FILE_IO, "Stable SSH socket is not a symlink: %s", current);
        return -1;
    }
    n = readlink(current, target, sizeof(target) - 1);
    if (n < 0) {
        set_system_error(ERR_FILE_IO, "Cannot read stable SSH socket: %s", current);
        return -1;
    }
    if ((size_t)n == sizeof(target) - 1) {
        set_error(ERR_INVALID_PATH, "Stable SSH socket target is too long: %s", current);
        return -1;
    }
    target[n] = '\0';
    *matches = strcmp(target, socket) == 0;
    return 0;
}

static int ssh_reset_incomplete(void) {
    char detail[sizeof(g_last_error.message)];
    safe_strncpy(detail, get_last_error()->message, sizeof(detail));
    if (detail[0]) {
        set_error(ERR_FILE_IO,
                  "SSH reset incomplete; retained state for retry: %s", detail);
    } else {
        set_error(ERR_FILE_IO,
                  "SSH reset incomplete; retained remaining state for retry");
    }
    return -1;
}

/* Tear down isolated SSH agents: one account, or all when account is NULL.
 * Kills the agent(s) by recorded PID and removes their sockets/sidecars. Every
 * lock, identity/reap, and relevant unlink failure is fatal to the caller;
 * missing owned state remains idempotent success. */
int ssh_manager_reset(const char *account) {
    char socket_dir[MAX_PATH_LEN];
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");

    /* Validate the name up front (the single-account branch uses it as a path
     * component). Every loaded account already passed validate_name, so this is
     * unreachable in practice — but guard it symmetrically with gpg_manager_reset(). */
    if (account && *account &&
        (strpbrk(account, "/\\") != NULL || strstr(account, "..") != NULL ||
         account[0] == '.')) {
        set_error(ERR_INVALID_ARGS, "Invalid account name for reset: %s", account);
        return -1;
    }

    if (runtime_dir && *runtime_dir && path_exists(runtime_dir)) {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "%s/gitswitch-ssh", runtime_dir) >= sizeof(socket_dir)) {
            set_error(ERR_INVALID_PATH, "SSH agent directory path too long");
            return -1;
        }
    } else {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "/tmp/gitswitch-ssh-%d", getuid()) >= sizeof(socket_dir)) {
            set_error(ERR_INVALID_PATH, "SSH agent directory path too long");
            return -1;
        }
    }

    /* Guard the base before locking/scanning/unlinking under it (AR-03 L6):
     * a symlinked, foreign, or group/other-accessible dir at the predictable
     * /tmp name must fail closed, exactly like gpg_manager_reset. Absent
     * means there is simply nothing to reset. */
    int dir_safe = agent_dir_is_safe(socket_dir);
    if (dir_safe > 0) {
        return 0;
    }
    if (dir_safe < 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to reset: SSH agent dir is a symlink, foreign-owned, "
                  "or not private: %s", socket_dir);
        return -1;
    }

    /* A validated existing base must never be mutated unlocked. A failed lock
     * is actionable retained state, not evidence that the base disappeared. */
    int lock_fd = lock_agent_dir(socket_dir);
    if (lock_fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to lock SSH agent directory: %s", socket_dir);
        return -1;
    }

    if (!account || !*account) {
        int all_rc = kill_orphaned_gitswitch_agents(NULL);
        unlock_agent_dir(lock_fd);
        return all_rc == 0 ? 0 : ssh_reset_incomplete();
    }

    char pid_path[MAX_PATH_LEN];
    char sock_path[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    bool current_matches = false;
    bool failed = false;
    bool can_remove_runtime = true;
    pid_t pid = -1;

    if ((size_t)snprintf(sock_path, sizeof(sock_path),
                         "%s/ssh-agent.%s.sock", socket_dir, account) >= sizeof(sock_path) ||
        (size_t)snprintf(pid_path, sizeof(pid_path),
                         "%s/ssh-agent.%s.pid", socket_dir, account) >= sizeof(pid_path) ||
        (size_t)snprintf(current, sizeof(current),
                         "%s/current.sock", socket_dir) >= sizeof(current)) {
        set_error(ERR_INVALID_PATH, "SSH reset artifact path too long");
        unlock_agent_dir(lock_fd);
        return -1;
    }

    int pid_rc = read_ssh_agent_pid(pid_path, &pid);
    if (pid_rc < 0) {
        failed = true;
        can_remove_runtime = false;
    } else if (pid_rc == 0) {
        if (!reap_ssh_agent(pid, sock_path)) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "SSH agent PID %ld survived teardown; retained for retry",
                      (long)pid);
            failed = true;
            can_remove_runtime = false;
        } else if (unlink_ssh_reset_path(pid_path, "SSH agent PID sidecar") != 0) {
            failed = true;
        }
    }

    /* A missing sidecar is idempotent only when the socket is absent or
     * provably stale. Apply the same proof after a recorded PID was classified
     * dead/not-ours: a stale sidecar can coexist with a different live agent
     * on the managed socket, so reap_ssh_agent()==true alone is insufficient
     * authority to unlink the runtime entry point. */
    if (can_remove_runtime) {
        bool reachable = false;
        if (probe_ssh_agent_socket(sock_path, &reachable) != 0) {
            failed = true;
            can_remove_runtime = false;
        } else if (reachable) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "Reachable SSH agent socket has no safely matched PID; "
                      "retained for retry: %s", sock_path);
            failed = true;
            can_remove_runtime = false;
        }
    }

    if (can_remove_runtime) {
        /* Inspect the stable link before removing its target, then delete the
         * target first. If socket removal fails, retain current.sock so the
         * still-live/inspectable runtime entry point is not destroyed. */
        if (ssh_current_matches_socket(current, sock_path, &current_matches) != 0) {
            failed = true;
        }
        if (unlink_ssh_reset_path(sock_path, "SSH agent socket") != 0) {
            failed = true;
        } else if (current_matches &&
                   unlink_ssh_reset_path(current, "stable SSH socket") != 0) {
            failed = true;
        }
    }

    unlock_agent_dir(lock_fd);
    return failed ? ssh_reset_incomplete() : 0;
}

/* Kill orphaned gitswitch ssh-agents from previous runs and remove stale
 * sockets. Shell-free: agents are reaped precisely by the PID recorded in their
 * sidecar (ssh-agent.<name>.pid) rather than a pkill pattern match, and stale
 * sockets are unlinked via readdir. Only operates inside our own 0700 dir.
 * If keep_account is non-NULL, that account's live agent + sidecar are left
 * intact (used when reusing it), while every other account is still reaped. */
static int kill_orphaned_gitswitch_agents(const char *keep_account) {
    char socket_dir[MAX_PATH_LEN];
    char keep_pid[MAX_NAME_LEN + 16];
    char keep_sock[MAX_NAME_LEN + 16];
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    DIR *d;
    struct dirent *ent;
    bool failed = false;

    keep_pid[0] = keep_sock[0] = '\0';
    if (keep_account && *keep_account) {
        snprintf(keep_pid, sizeof(keep_pid), "ssh-agent.%s.pid", keep_account);
        snprintf(keep_sock, sizeof(keep_sock), "ssh-agent.%s.sock", keep_account);
    }

    if (runtime_dir && *runtime_dir && path_exists(runtime_dir)) {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "%s/gitswitch-ssh", runtime_dir) >= sizeof(socket_dir)) {
            set_error(ERR_INVALID_PATH, "SSH agent directory path too long");
            return -1;
        }
    } else {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "/tmp/gitswitch-ssh-%d", getuid()) >= sizeof(socket_dir)) {
            set_error(ERR_INVALID_PATH, "SSH agent directory path too long");
            return -1;
        }
    }

    /* Same base-dir guard as ssh_manager_reset (AR-03 L6): when the caller is
     * ssh_start_isolated_agent the dir was just created/validated, but the
     * reset path reaches here too, and opendir on its own would happily
     * follow a planted symlink and unlink "ssh-agent.*" names elsewhere. */
    int dir_safe = agent_dir_is_safe(socket_dir);
    if (dir_safe > 0) {
        return 0;
    }
    if (dir_safe < 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to clean unsafe SSH agent directory: %s", socket_dir);
        return -1;
    }

    d = opendir(socket_dir);
    if (!d) {
        set_system_error(ERR_FILE_IO, "Cannot enumerate SSH agent directory: %s", socket_dir);
        return -1;
    }

    /* Pass 1: process sidecars first. A sidecar is removed only after its PID
     * is safely classified/reaped. Failed or malformed sidecars remain, which
     * lets pass 2 retain the corresponding socket as retry evidence. */
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) {
            if (errno != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed while enumerating SSH PID sidecars: %s",
                                 socket_dir);
                failed = true;
            }
            break;
        }
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        char full[MAX_PATH_LEN];

        if (strncmp(name, "ssh-agent.", 10) != 0 ||
            nlen <= 4 || strcmp(name + nlen - 4, ".pid") != 0) {
            continue;
        }
        if (keep_pid[0] && strcmp(name, keep_pid) == 0) {
            continue;
        }
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", socket_dir, name) >= sizeof(full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup artifact path too long: %s", name);
            failed = true;
            continue;
        }

        /* The socket this agent was started on (ssh-agent.<name>.sock), used
         * to confirm the recorded PID is genuinely our agent. */
        char sock_full[MAX_PATH_LEN];
        int sw = snprintf(sock_full, sizeof(sock_full), "%s/%.*ssock",
                          socket_dir, (int)(nlen - 3), name);
        if (sw <= 0 || (size_t)sw >= sizeof(sock_full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup socket path too long: %s", name);
            failed = true;
            continue;
        }

        pid_t pid = -1;
        int pid_rc = read_ssh_agent_pid(full, &pid);
        if (pid_rc != 0) {
            if (pid_rc > 0) {
                set_error(ERR_FILE_IO,
                          "SSH PID sidecar disappeared during cleanup: %s", full);
            }
            failed = true;
            continue;
        }
        if (!reap_ssh_agent(pid, sock_full)) {
            set_error(ERR_SSH_AGENT_FAILED,
                      "SSH agent PID %ld survived teardown; retained for retry",
                      (long)pid);
            failed = true;
            continue;
        }
        log_debug("Reaped orphaned ssh-agent PID %ld", (long)pid);
        if (unlink_ssh_reset_path(full, "SSH agent PID sidecar") != 0) {
            failed = true;
        }
    }
    if (closedir(d) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to close SSH agent directory: %s", socket_dir);
        failed = true;
    }

    /* Pass 2: remove sockets and other managed artifacts only when no sidecar
     * remains for that socket. This preserves the full retry tuple when an
     * agent could not be confirmed dead. current.sock is handled last. */
    d = opendir(socket_dir);
    if (!d) {
        set_system_error(ERR_FILE_IO, "Cannot re-enumerate SSH agent directory: %s", socket_dir);
        return -1;
    }
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) {
            if (errno != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed while enumerating SSH agent sockets: %s",
                                 socket_dir);
                failed = true;
            }
            break;
        }
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        char full[MAX_PATH_LEN];

        if (strncmp(name, "ssh-agent.", 10) != 0 ||
            (nlen > 4 && strcmp(name + nlen - 4, ".pid") == 0)) {
            continue;
        }
        if (keep_sock[0] && strcmp(name, keep_sock) == 0) {
            continue;
        }
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", socket_dir, name) >= sizeof(full)) {
            set_error(ERR_INVALID_PATH, "SSH cleanup artifact path too long: %s", name);
            failed = true;
            continue;
        }

        if (nlen > 5 && strcmp(name + nlen - 5, ".sock") == 0) {
            char pid_full[MAX_PATH_LEN];
            int pw = snprintf(pid_full, sizeof(pid_full), "%s/%.*spid",
                              socket_dir, (int)(nlen - 4), name);
            struct stat pst;
            if (pw <= 0 || (size_t)pw >= sizeof(pid_full)) {
                set_error(ERR_INVALID_PATH, "SSH cleanup PID path too long: %s", name);
                failed = true;
                continue;
            }
            if (lstat(pid_full, &pst) == 0) {
                continue; /* survivor/invalid sidecar: retain its socket */
            }
            if (errno != ENOENT) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot inspect SSH cleanup sidecar: %s", pid_full);
                failed = true;
                continue;
            }

            /* No sidecar: remove only a socket proven dead/unreachable. A
             * reachable listener cannot be reaped safely without its PID, and
             * an indeterminate probe is equally non-destructive. */
            bool reachable = false;
            if (probe_ssh_agent_socket(full, &reachable) != 0) {
                failed = true;
                continue;
            }
            if (reachable) {
                set_error(ERR_SSH_AGENT_FAILED,
                          "Live SSH agent socket has no PID sidecar; retained for retry: %s",
                          full);
                failed = true;
                continue;
            }
        }
        if (unlink_ssh_reset_path(full, "SSH agent artifact") != 0) {
            failed = true;
        }
    }
    if (closedir(d) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to close SSH agent directory: %s", socket_dir);
        failed = true;
    }

    /* Remove current.sock only when it does not still name a retained live
     * artifact. The reuse path's kept account remains untouched; an all-reset
     * failure likewise keeps a usable stable entry point for the retry. */
    char current[MAX_PATH_LEN];
    if ((size_t)snprintf(current, sizeof(current), "%s/current.sock", socket_dir) >= sizeof(current)) {
        set_error(ERR_INVALID_PATH, "Stable SSH socket path too long during cleanup");
        return -1;
    }
    struct stat cst;
    if (lstat(current, &cst) == 0) {
        bool retain_current = false;
        if (S_ISLNK(cst.st_mode)) {
            char target[MAX_PATH_LEN];
            ssize_t tn = readlink(current, target, sizeof(target) - 1);
            if (tn < 0) {
                set_system_error(ERR_FILE_IO, "Cannot read stable SSH socket: %s", current);
                failed = true;
                retain_current = true;
            } else if ((size_t)tn == sizeof(target) - 1) {
                set_error(ERR_INVALID_PATH, "Stable SSH socket target is too long: %s", current);
                failed = true;
                retain_current = true;
            } else {
                const char *base;
                struct stat tst;
                target[tn] = '\0';
                base = strrchr(target, '/');
                base = base ? base + 1 : target;
                if (keep_sock[0] && strcmp(base, keep_sock) == 0) {
                    retain_current = true;
                } else if (failed && lstat(target, &tst) == 0) {
                    retain_current = true;
                }
            }
        }
        if (!retain_current &&
            unlink_ssh_reset_path(current, "stable SSH socket") != 0) {
            failed = true;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_FILE_IO, "Cannot inspect stable SSH socket: %s", current);
        failed = true;
    }

    return failed ? -1 : 0;
}
