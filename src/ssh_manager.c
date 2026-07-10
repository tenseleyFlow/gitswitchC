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
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

#include "ssh_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"

/* Internal helper functions */
static int ssh_run(char *output, size_t output_size, bool merge_stderr, ...);
static int setup_ssh_environment(ssh_config_t *ssh_config);
static int create_isolated_agent_socket_dir(char *socket_dir, size_t socket_dir_size);
static int validate_ssh_agent_socket(const char *socket_path);
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config);
static void kill_orphaned_gitswitch_agents(const char *keep_account);

/* Best-effort check that a PID recorded in a sidecar still belongs to OUR
 * ssh-agent before we SIGTERM it. Sidecars can outlive their agent (crash,
 * logout, reboot on a /tmp-preserving distro); once the kernel recycles that
 * PID, a blind kill would terminate an unrelated process. Checking only that
 * the PID is *an* ssh-agent is not enough: the recycled PID may belong to the
 * user's OWN login/session ssh-agent (comm is also "ssh-agent"), and killing it
 * drops every key they had loaded. So on Linux we require BOTH comm=="ssh-agent"
 * AND that our exact per-account socket path (which we passed as `ssh-agent -a
 * <expected_sock>`) appears among the process's argv — proving it's the agent we
 * started, not a same-uid impostor. Where /proc is unavailable (BSD/macOS) we
 * cannot verify argv cheaply and fall back to a liveness check; the per-dir lock
 * and pid-scoped sidecars shrink the window that produces stale sidecars. */
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

    /* Require our exact socket path in the process's argv to defeat PID reuse. */
    if (!expected_sock || !*expected_sock) {
        return false;
    }
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    char cmd[4096];
    ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);
    if (n <= 0) {
        return false;
    }
    /* /proc/<pid>/cmdline is NUL-separated argv; require an exact token match. */
    size_t exp_len = strlen(expected_sock);
    for (ssize_t i = 0; i < n; ) {
        const char *tok = cmd + i;
        size_t tlen = strnlen(tok, (size_t)(n - i));
        if (tlen == exp_len && memcmp(tok, expected_sock, exp_len) == 0) {
            return true;
        }
        i += (ssize_t)tlen + 1;
    }
    return false;
#else
    (void)expected_sock;
    return (kill(pid, 0) == 0);
#endif
}

/* Wait up to `total_ms` for `pid` to disappear. ssh-agent daemonizes (it is
 * reparented to init, not our child), so kill(pid, 0) flips to ESRCH as soon
 * as init reaps it — no waitpid involved. The common case exits within the
 * first poll interval. */
static bool wait_pid_gone(pid_t pid, int total_ms) {
    for (int waited = 0; waited < total_ms; waited += 50) {
        if (kill(pid, 0) != 0) {
            return true;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 }; /* 50ms */
        nanosleep(&ts, NULL);
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

/* Acquire an exclusive, blocking flock on <dir>/.lock, serializing the
 * reap/start/symlink sequence against other gitswitch processes sharing this
 * directory. Returns the held fd (>=0) or -1; pass it to unlock_agent_dir when
 * the critical section ends. The lock is advisory but every writer takes it. */
static int lock_agent_dir(const char *dir) {
    char lock_path[MAX_PATH_LEN];
    if ((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock", dir) >= sizeof(lock_path)) {
        return -1;
    }
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
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

/* True if an ssh-agent is answering on `sock` AND already holds the key at
 * `key_path` specifically (matched by fingerprint), so adopting it is safe and
 * skips a passphrase re-prompt. A live agent holding a *different* key — e.g.
 * after `gitswitch edit` changed the key path — returns false so the caller
 * loads the current key. If the fingerprint can't be determined we fall back to
 * false (load the key) rather than risk reusing a stale one. */
static bool ssh_socket_has_key(const char *sock, const char *key_path) {
    char want_fp[256];
    char envbuf[MAX_PATH_LEN + 20];
    char out[2048];
    const char *env[2] = { NULL, NULL };
    const char *argv[] = { "ssh-add", "-l", NULL };
    run_opts_t opts;
    run_result_t res;

    if (ssh_key_fingerprint(key_path, want_fp, sizeof(want_fp)) != 0) {
        return false;
    }
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
    return strstr(out, want_fp) != NULL;
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
    
    /* Configure host alias if specified */
    if (strlen(account->ssh_host_alias) > 0) {
        if (ssh_configure_host_alias(account) != 0) {
            log_warning("Failed to configure SSH host alias: %s", account->ssh_host_alias);
            /* Don't fail completely for host alias issues */
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

    /* Reuse fast path: if this account's agent is already alive and holds THIS
     * key (matched by fingerprint), adopt it instead of killing and restarting
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
        log_info("Reusing live SSH agent for account: %s", account->name);
        safe_strncpy(ssh_config->agent_socket_path, socket_path,
                     sizeof(ssh_config->agent_socket_path));
        ssh_config->agent_owned = true;
        ssh_config->key_already_loaded = true;

        /* Recover the PID from the sidecar so cleanup/stop can still target
         * it — but only after verifying it is genuinely OUR agent on this
         * socket (AR-02 #18). The sidecar can be stale (crash, reboot on a
         * /tmp-preserving distro) with its PID since recycled; trusting it
         * blindly would mark an unrelated process agent_owned=true and feed
         * it into the kill path later. The socket itself was already
         * fingerprint-verified, so a rejected PID only costs precise
         * stop-by-pid targeting, not the reuse. */
        char pid_path[MAX_PATH_LEN];
        if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid",
                             socket_dir, account->name) < sizeof(pid_path)) {
            FILE *pf = fopen(pid_path, "r");
            if (pf) {
                long pid = 0;
                if (fscanf(pf, "%ld", &pid) == 1 && pid > 1 &&
                    pid_is_our_ssh_agent((pid_t)pid, socket_path)) {
                    ssh_config->agent_pid = (pid_t)pid;
                }
                fclose(pf);
            }
        }

        kill_orphaned_gitswitch_agents(account->name); /* reap others, keep this */
        (void)setup_ssh_environment(ssh_config);

        if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                            "%s/current.sock", socket_dir) < sizeof(symlink_path)) {
            atomic_symlink(socket_path, symlink_path);
        }
        rc = 0;
        goto done;
    }

    /* Kill any orphaned gitswitch agents from previous runs (including a stale
     * agent for this same account, which we're about to replace). */
    kill_orphaned_gitswitch_agents(NULL);

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

    /* Start ssh-agent on the per-account socket (no shell). Capture its stdout
     * (the eval script) only; stderr stays on the terminal. */
    log_debug("Starting SSH agent on socket: %s", socket_path);
    if (ssh_run(output, sizeof(output), false, "ssh-agent", "-a", socket_path, NULL) != 0) {
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
        goto done;
    }
    safe_strncpy(ssh_config->agent_socket_path, socket_path,
                 sizeof(ssh_config->agent_socket_path));

    /* Validate the agent is working */
    if (validate_ssh_agent_socket(ssh_config->agent_socket_path) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "SSH agent socket validation failed");
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
        char pid_path[MAX_PATH_LEN];
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
        if (!recorded) {
            set_system_error(ERR_FILE_IO, "Failed to record SSH agent PID; stopping agent");
            ssh_stop_agent(ssh_config);
            goto done;
        }
    }

    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to set up SSH environment");
        goto done;
    }

    log_info("Isolated SSH agent started successfully (PID: %d, Socket: %s)",
             ssh_config->agent_pid, ssh_config->agent_socket_path);

    /* Atomically (re)point the stable current.sock at this agent's socket. */
    if ((size_t)snprintf(symlink_path, sizeof(symlink_path),
                        "%s/current.sock", socket_dir) < sizeof(symlink_path)) {
        if (atomic_symlink(socket_path, symlink_path) == 0) {
            log_debug("Created symlink: %s -> %s", symlink_path, socket_path);
        } else {
            log_warning("Failed to create socket symlink: %s", strerror(errno));
        }
    }

    rc = 0;
done:
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
    char buf[65536];
    const char *home = getenv("HOME");
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
    if (path_exists(ssh_config_path)) {
        if (get_file_size(ssh_config_path) >= sizeof(buf)) {
            set_error(ERR_FILE_IO, "SSH config too large to update safely");
            return -1;
        }
        if (read_file_to_string(ssh_config_path, buf, sizeof(buf)) < 0) {
            set_error(ERR_FILE_IO, "Failed to read SSH config");
            return -1;
        }
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
                *line_start = '\0'; /* malformed: truncate from the marker */
            }
        }
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
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to secure temp SSH config");
        return -1;
    }
    out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        unlink(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to open temp SSH config");
        return -1;
    }
    fputs(buf, out);
    if (buf[0] != '\0' && buf[strlen(buf) - 1] != '\n') {
        fputc('\n', out);
    }
    fprintf(out, "%s\n", begin_marker);
    fprintf(out, "Host %s\n", account->ssh_host_alias);
    fprintf(out, "  IdentityFile %s\n", expanded_key_path);
    fprintf(out, "  IdentitiesOnly yes\n");
    fprintf(out, "%s\n", end_marker);
    if (fclose(out) != 0) {
        unlink(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to write SSH config");
        return -1;
    }
    if (rename(tmp_path, ssh_config_path) != 0) {
        unlink(tmp_path);
        set_system_error(ERR_FILE_IO, "Failed to install SSH config");
        return -1;
    }

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
    if (setenv("SSH_AUTH_SOCK", ssh_config->agent_socket_path, 1) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AUTH_SOCK");
        return -1;
    }
    
    /* Set SSH_AGENT_PID if we have it */
    if (ssh_config->agent_pid > 0) {
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", ssh_config->agent_pid);
        if (setenv("SSH_AGENT_PID", pid_str, 1) != 0) {
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

/* Tear down isolated SSH agents: one account, or all when account is NULL.
 * Kills the agent(s) by recorded PID and removes their sockets/sidecars. */
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
            return -1;
        }
    } else {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "/tmp/gitswitch-ssh-%d", getuid()) >= sizeof(socket_dir)) {
            return -1;
        }
    }

    /* Take the per-dir lock for the whole reap/unlink sequence. Without it, this
     * writer races a concurrent ssh_start_isolated_agent (which holds the same
     * lock): we would reap its freshly-started agent and unlink current.sock
     * while its switch reports success. lock_agent_dir returns -1 if the dir
     * doesn't exist yet — in that case there is nothing to reset, so proceeding
     * without a lock is harmless (all operations below are no-ops on a missing
     * dir). kill_orphaned_gitswitch_agents deliberately does NOT self-lock
     * because ssh_start_isolated_agent already calls it under this same lock. */
    int lock_fd = lock_agent_dir(socket_dir);

    if (!account || !*account) {
        /* All: reuse the orphan reaper (kills every recorded PID, unlinks
         * sockets/pids/current.sock). */
        kill_orphaned_gitswitch_agents(NULL);
        unlock_agent_dir(lock_fd);
        return 0;
    }

    char pid_path[MAX_PATH_LEN];
    char sock_path[MAX_PATH_LEN];
    bool have_sock = (size_t)snprintf(sock_path, sizeof(sock_path),
                                      "%s/ssh-agent.%s.sock", socket_dir, account) < sizeof(sock_path);
    if ((size_t)snprintf(pid_path, sizeof(pid_path), "%s/ssh-agent.%s.pid", socket_dir, account) < sizeof(pid_path)) {
        /* Drop the sidecar only once the agent is confirmed gone (AR-02 #20)
         * — it is the only record a future run can retry the reap against. */
        bool agent_gone = true;
        FILE *pf = fopen(pid_path, "r");
        if (pf) {
            long pid = 0;
            if (fscanf(pf, "%ld", &pid) == 1 && pid > 1 && have_sock) {
                agent_gone = reap_ssh_agent((pid_t)pid, sock_path);
                if (!agent_gone) {
                    log_warning("ssh-agent PID %ld survived teardown; keeping "
                                "its sidecar for a future reap", pid);
                }
            }
            fclose(pf);
        }
        if (agent_gone) {
            unlink(pid_path);
        }
    }
    if (have_sock) {
        /* F3: if the stable current.sock symlink points at the account we're
         * resetting, drop it too — otherwise shells keep SSH_AUTH_SOCK pointing
         * at the socket we just removed (a dangling link), mirroring the GPG
         * side's dangling-symlink cleanup. current.sock is an absolute symlink
         * to the per-account socket (see ssh_start_isolated_agent). */
        char current[MAX_PATH_LEN];
        if ((size_t)snprintf(current, sizeof(current), "%s/current.sock", socket_dir) < sizeof(current)) {
            char target[MAX_PATH_LEN];
            ssize_t tn = readlink(current, target, sizeof(target) - 1);
            if (tn > 0) {
                target[tn] = '\0';
                if (strcmp(target, sock_path) == 0) {
                    unlink(current);
                }
            }
        }
        unlink(sock_path);
    }
    unlock_agent_dir(lock_fd);
    return 0;
}

/* Kill orphaned gitswitch ssh-agents from previous runs and remove stale
 * sockets. Shell-free: agents are reaped precisely by the PID recorded in their
 * sidecar (ssh-agent.<name>.pid) rather than a pkill pattern match, and stale
 * sockets are unlinked via readdir. Only operates inside our own 0700 dir.
 * If keep_account is non-NULL, that account's live agent + sidecar are left
 * intact (used when reusing it), while every other account is still reaped. */
static void kill_orphaned_gitswitch_agents(const char *keep_account) {
    char socket_dir[MAX_PATH_LEN];
    char keep_pid[MAX_NAME_LEN + 16];
    char keep_sock[MAX_NAME_LEN + 16];
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    DIR *d;
    struct dirent *ent;

    keep_pid[0] = keep_sock[0] = '\0';
    if (keep_account && *keep_account) {
        snprintf(keep_pid, sizeof(keep_pid), "ssh-agent.%s.pid", keep_account);
        snprintf(keep_sock, sizeof(keep_sock), "ssh-agent.%s.sock", keep_account);
    }

    if (runtime_dir && *runtime_dir && path_exists(runtime_dir)) {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "%s/gitswitch-ssh", runtime_dir) >= sizeof(socket_dir)) {
            return;
        }
    } else {
        if ((size_t)snprintf(socket_dir, sizeof(socket_dir), "/tmp/gitswitch-ssh-%d", getuid()) >= sizeof(socket_dir)) {
            return;
        }
    }

    d = opendir(socket_dir);
    if (!d) {
        return; /* nothing to clean up */
    }

    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        char full[MAX_PATH_LEN];

        if (strncmp(name, "ssh-agent.", 10) != 0 && strcmp(name, "current.sock") != 0) {
            continue;
        }
        /* Preserve the account we're reusing (its live agent + sidecar). */
        if (keep_pid[0] && (strcmp(name, keep_pid) == 0 || strcmp(name, keep_sock) == 0)) {
            continue;
        }
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", socket_dir, name) >= sizeof(full)) {
            continue;
        }

        if (nlen > 4 && strcmp(name + nlen - 4, ".pid") == 0) {
            /* The socket this agent was started on (ssh-agent.<name>.sock),
             * used to confirm the recorded PID is genuinely our agent. */
            char sock_full[MAX_PATH_LEN];
            int sw = snprintf(sock_full, sizeof(sock_full), "%s/%.*ssock",
                              socket_dir, (int)(nlen - 3), name);
            /* Reap the recorded agent PID; drop the sidecar only once the
             * agent is confirmed gone (AR-02 #20). Unlinking it while the
             * agent survives (stopped/wedged, still holding the decrypted
             * key) would erase the only record any future gitswitch run has
             * to retry the reap against. An unopenable/unparseable sidecar
             * is garbage either way and is dropped. */
            bool agent_gone = true;
            FILE *pf = fopen(full, "r");
            if (pf) {
                long pid = 0;
                if (fscanf(pf, "%ld", &pid) == 1 && pid > 1 &&
                    sw > 0 && (size_t)sw < sizeof(sock_full)) {
                    agent_gone = reap_ssh_agent((pid_t)pid, sock_full);
                    if (agent_gone) {
                        log_debug("Reaped orphaned ssh-agent PID %ld", pid);
                    } else {
                        log_warning("ssh-agent PID %ld survived teardown; keeping "
                                    "its sidecar for a future reap", pid);
                    }
                }
                fclose(pf);
            }
            if (agent_gone) {
                unlink(full);
            }
        } else {
            /* Stale socket (ssh-agent.<name>.sock or current.sock). But do
             * not churn a current.sock that already targets the account we
             * are keeping (AR-02 #18): the reuse path would recreate it via
             * atomic_symlink moments later, and a shell reading
             * SSH_AUTH_SOCK=current.sock in that unlink-to-recreate window
             * gets ENOENT and silently loses agent access for that session. */
            if (keep_sock[0] && strcmp(name, "current.sock") == 0) {
                char target[MAX_PATH_LEN];
                ssize_t tn = readlink(full, target, sizeof(target) - 1);
                if (tn > 0) {
                    const char *base;
                    target[tn] = '\0';
                    base = strrchr(target, '/');
                    base = base ? base + 1 : target;
                    if (strcmp(base, keep_sock) == 0) {
                        continue;
                    }
                }
            }
            unlink(full);
        }
    }
    closedir(d);
}