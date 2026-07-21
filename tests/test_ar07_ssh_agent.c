/* AR-07 T8: adversarial SSH agent publication, probe, cleanup, and key status. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"
#include "accounts.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FP_EXPECTED "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

typedef enum {
    IDENTITY_LIST_RAW = 0,
    IDENTITY_LIST_CERTIFICATE,
    IDENTITY_LIST_RAW_AND_CERTIFICATE,
    IDENTITY_LIST_MALFORMED,
    IDENTITY_LIST_EMBEDDED_NUL,
    IDENTITY_LIST_TRUNCATED
} identity_listing_mode_t;

typedef enum {
    KEYGEN_LISTING_COMPLETE = 0,
    KEYGEN_LISTING_OVERSIZED_OUTPUT,
    KEYGEN_LISTING_TRUNCATED_FINGERPRINT,
    KEYGEN_LISTING_UNTERMINATED_FINGERPRINT,
    KEYGEN_LISTING_SHORT_FINGERPRINT,
    KEYGEN_LISTING_MISPLACED_FINGERPRINT,
    KEYGEN_LISTING_EMBEDDED_NUL
} keygen_listing_mode_t;

static identity_listing_mode_t g_identity_listing_mode;
static keygen_listing_mode_t g_keygen_listing_mode;
static int g_dirsync_calls;
static int g_dirsync_fail_call;
static int g_key_open_calls;
static int g_key_open_flags;
static int64_t g_probe_now;
static int g_probe_poll_calls;
static int g_probe_timeouts[16];
static char g_quarantine_name[96];
#ifdef __linux__
static volatile sig_atomic_t g_alarm_count;
#endif

static int fake_identity_runner(const char *const argv[],
                                const run_opts_t *opts,
                                run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (!opts || !opts->out || opts->out_size == 0) return -1;
    opts->out[0] = '\0';

    if (strcmp(argv[0], "ssh-add") == 0 && argv[1] &&
        strcmp(argv[1], "-l") == 0) {
        if (g_identity_listing_mode == IDENTITY_LIST_TRUNCATED) {
            int prefix = snprintf(opts->out, opts->out_size,
                                  "256 %s ", FP_EXPECTED);
            if (prefix < 0 || (size_t)prefix >= opts->out_size) return -1;
            memset(opts->out + prefix, 'x',
                   opts->out_size - (size_t)prefix - 1U);
            opts->out[opts->out_size - 1U] = '\0';
            if (result) {
                result->out_len = opts->out_size - 1U;
                /* A second foreign identity exists beyond this visible long
                 * first line; the runner contract reports that fact here. */
                result->out_truncated = true;
            }
        } else if (g_identity_listing_mode == IDENTITY_LIST_EMBEDDED_NUL) {
            static const char suffix[] = "hidden expected (ED25519)\n";
            int prefix = snprintf(opts->out, opts->out_size,
                                  "256 %s ", FP_EXPECTED);
            size_t required;

            if (prefix < 0) return -1;
            required = (size_t)prefix + 1U + sizeof(suffix);
            if (required > opts->out_size) return -1;
            opts->out[prefix] = '\0';
            memcpy(opts->out + (size_t)prefix + 1U, suffix, sizeof(suffix));
            if (result) {
                result->out_len = (size_t)prefix + 1U + sizeof(suffix) - 1U;
            }
        } else {
            if (g_identity_listing_mode == IDENTITY_LIST_CERTIFICATE) {
                snprintf(opts->out, opts->out_size,
                         "256 %s misleading (ED25519) comment "
                         "(ED25519-CERT)\n",
                         FP_EXPECTED);
            } else if (g_identity_listing_mode ==
                       IDENTITY_LIST_RAW_AND_CERTIFICATE) {
                snprintf(opts->out, opts->out_size,
                         "256 %s expected (ED25519)\n"
                         "256 %s expected (ED25519-CERT)\n",
                         FP_EXPECTED, FP_EXPECTED);
            } else if (g_identity_listing_mode == IDENTITY_LIST_MALFORMED) {
                snprintf(opts->out, opts->out_size,
                         "256 %s expected ED25519\n", FP_EXPECTED);
            } else {
                snprintf(opts->out, opts->out_size,
                         "256 %s misleading (ED25519-CERT) comment "
                         "(ED25519)\n",
                         FP_EXPECTED);
            }
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (strcmp(argv[0], "ssh-keygen") == 0 && argv[1] &&
        strcmp(argv[1], "-lf") == 0) {
        if (g_keygen_listing_mode == KEYGEN_LISTING_OVERSIZED_OUTPUT) {
            int prefix = snprintf(opts->out, opts->out_size,
                                  "256 %s ", FP_EXPECTED);
            if (prefix < 0 || (size_t)prefix >= opts->out_size) return -1;
            memset(opts->out + prefix, 'c',
                   opts->out_size - (size_t)prefix - 1U);
            opts->out[opts->out_size - 1U] = '\0';
            if (result) {
                result->out_len = opts->out_size - 1U;
                result->out_truncated = true;
            }
        } else if (g_keygen_listing_mode ==
                   KEYGEN_LISTING_TRUNCATED_FINGERPRINT) {
            int prefix = snprintf(opts->out, opts->out_size, "256 SHA256:");
            if (prefix < 0 || (size_t)prefix >= opts->out_size) return -1;
            memset(opts->out + prefix, 'A',
                   opts->out_size - (size_t)prefix - 1U);
            opts->out[opts->out_size - 1U] = '\0';
            if (result) {
                result->out_len = opts->out_size - 1U;
                result->out_truncated = true;
            }
        } else if (g_keygen_listing_mode ==
                   KEYGEN_LISTING_UNTERMINATED_FINGERPRINT) {
            snprintf(opts->out, opts->out_size, "256 %s", FP_EXPECTED);
            if (result) result->out_len = strlen(opts->out);
        } else if (g_keygen_listing_mode ==
                   KEYGEN_LISTING_SHORT_FINGERPRINT) {
            snprintf(opts->out, opts->out_size,
                     "256 SHA256:A expected (ED25519)\n");
            if (result) result->out_len = strlen(opts->out);
        } else if (g_keygen_listing_mode ==
                   KEYGEN_LISTING_MISPLACED_FINGERPRINT) {
            snprintf(opts->out, opts->out_size,
                     "comment %s expected (ED25519)\n", FP_EXPECTED);
            if (result) result->out_len = strlen(opts->out);
        } else if (g_keygen_listing_mode == KEYGEN_LISTING_EMBEDDED_NUL) {
            static const char hidden[] = " hidden (ED25519)\n";
            int prefix = snprintf(opts->out, opts->out_size,
                                  "256 %s ", FP_EXPECTED);
            size_t required;

            if (prefix < 0) return -1;
            required = (size_t)prefix + 1501U + sizeof(hidden);
            if (required > opts->out_size) return -1;
            memset(opts->out + prefix, 'c', 1500U);
            opts->out[(size_t)prefix + 1500U] = '\0';
            memcpy(opts->out + (size_t)prefix + 1501U,
                   hidden, sizeof(hidden));
            if (result) {
                result->out_len = (size_t)prefix + 1501U +
                                  sizeof(hidden) - 1U;
            }
        } else {
            snprintf(opts->out, opts->out_size,
                     "256 %s expected (ED25519)\n", FP_EXPECTED);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    return -1;
}

static int counting_dirsync(int dir_fd) {
    g_dirsync_calls++;
    if (g_dirsync_fail_call > 0 &&
        g_dirsync_calls == g_dirsync_fail_call) {
        errno = EIO;
        return -1;
    }
    return fsync(dir_fd);
}

static int counting_key_open(const char *path, int flags) {
    g_key_open_calls++;
    g_key_open_flags = flags;
    return open(path, flags);
}

static ssh_process_outcome_t classify_recorded_agent_gone(
    pid_t pid, const char *socket_arg, int runtime_dir_fd) {
    (void)pid;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_GONE;
}

static int replace_current_during_cleanup(int dir_fd) {
    if (unlinkat(dir_fd, "current.sock", 0) != 0) return -1;
    return symlinkat("replacement.sock", dir_fd, "current.sock");
}

static int replace_current_equal_length(int dir_fd) {
    if (unlinkat(dir_fd, "current.sock", 0) != 0) return -1;
    return symlinkat("other.sock", dir_fd, "current.sock");
}

static int close_current_dir_before_cleanup(int dir_fd) {
    return close(dir_fd);
}

static int occupy_quarantine_destination(int dir_fd, const char *name) {
    snprintf(g_quarantine_name, sizeof(g_quarantine_name), "%s", name);
    return symlinkat("raced-quarantine.sock", dir_fd, name);
}

static int record_quarantine_destination(int dir_fd, const char *name) {
    (void)dir_fd;
    snprintf(g_quarantine_name, sizeof(g_quarantine_name), "%s", name);
    return 0;
}

static int replace_quarantine_with_regular(int dir_fd, const char *name) {
    int fd;

    snprintf(g_quarantine_name, sizeof(g_quarantine_name), "%s", name);
    if (unlinkat(dir_fd, name, 0) != 0) return -1;
    fd = openat(dir_fd, name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write(fd, "foreign\n", 8) != 8) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int replace_pid_after_rename(int dir_fd, const char *name) {
    int fd;

    if (unlinkat(dir_fd, name, 0) != 0) return -1;
    fd = openat(dir_fd, name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write(fd, "54321\n", 6) != 6) {
        close(fd);
        return -1;
    }
    return close(fd);
}

#ifdef __linux__
static void alarm_handler(int signal_number) {
    (void)signal_number;
    g_alarm_count++;
}
#endif

static int64_t real_monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

#ifdef __linux__
typedef struct {
    int setup_rc;
    int cleanup_rc;
    int probe_rc;
    int reachable;
    int alarm_count;
    int64_t elapsed_ms;
} real_probe_result_t;

static int write_all_test_bytes(int fd, const void *data, size_t size) {
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < size) {
        ssize_t written = write(fd, bytes + offset, size - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void run_finite_alarm_sender(pid_t target) {
    const struct timespec interval = {.tv_sec = 0, .tv_nsec = 5000000L};

    /* Roughly 800 ms of interrupts exceeds the accepted probe bound. Correct
     * absolute-deadline code still returns near 100 ms; a timeout-reset mutant
     * runs through the storm plus its final full timeout and fails the bound. */
    for (int i = 0; i < 160; i++) {
        struct timespec remaining = interval;

        while (nanosleep(&remaining, &remaining) != 0) {
            if (errno != EINTR) _exit(2);
        }
        if (kill(target, SIGALRM) != 0) {
            if (errno == ESRCH) break;
            _exit(3);
        }
    }
    _exit(0);
}

static int drain_blocked_alarms(const sigset_t *alarm_set) {
    const struct timespec no_wait = {.tv_sec = 0, .tv_nsec = 0};

    for (;;) {
        int signal_number = sigtimedwait(alarm_set, NULL, &no_wait);
        if (signal_number == SIGALRM) continue;
        if (signal_number < 0 && errno == EINTR) continue;
        if (signal_number < 0 && errno == EAGAIN) return 0;
        return -1;
    }
}

/* Run the potentially regressed probe outside the test-suite process. A
 * finite sender supplies repeated EINTR, while the original parent retains a
 * hard wall-clock kill boundary around this entire child process group. */
static void run_real_probe_child(int result_fd) {
    real_probe_result_t result;
    struct sigaction action;
    struct sigaction old_action;
    struct itimerval old_timer;
    struct itimerval stopped_timer;
    sigset_t alarm_set;
    sigset_t old_mask;
    sigset_t run_mask;
    pid_t sender = -1;
    bool have_action = false;
    bool have_mask = false;
    bool have_timer = false;
    int sender_status = 0;
    int64_t started;

    memset(&result, 0, sizeof(result));
    result.setup_rc = -1;
    result.cleanup_rc = 0;
    result.probe_rc = -2;
    result.elapsed_ms = -1;
    memset(&stopped_timer, 0, sizeof(stopped_timer));
    sigemptyset(&alarm_set);
    sigaddset(&alarm_set, SIGALRM);

    if (sigprocmask(SIG_BLOCK, &alarm_set, &old_mask) != 0) goto report;
    have_mask = true;
    if (sigaction(SIGALRM, NULL, &old_action) != 0) goto cleanup;
    have_action = true;
    if (getitimer(ITIMER_REAL, &old_timer) != 0) goto cleanup;
    have_timer = true;
    if (setitimer(ITIMER_REAL, &stopped_timer, NULL) != 0) goto cleanup;

    memset(&action, 0, sizeof(action));
    action.sa_handler = alarm_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) != 0) goto cleanup;

    g_alarm_count = 0;
    sender = fork();
    if (sender < 0) goto cleanup;
    if (sender == 0) run_finite_alarm_sender(getppid());

    run_mask = old_mask;
    sigdelset(&run_mask, SIGALRM);
    if (sigprocmask(SIG_SETMASK, &run_mask, NULL) != 0) goto cleanup;
    result.setup_rc = 0;
    started = real_monotonic_ms();
    if (started >= 0) {
        /* fd=-1 is ignored by poll(2), so this exercises the production
         * absolute-deadline loop with a real blocking poll and real EINTRs
         * without relying on kernel-specific UNIX backlog behavior. */
        result.probe_rc = ssh_manager_test_probe_deadline(100);
        result.elapsed_ms = real_monotonic_ms() - started;
        result.alarm_count = (int)g_alarm_count;
    }

cleanup:
    /* No test alarm may reach the restored action. Block first, reap the finite
     * sender, stop the timer, drain pending SIGALRM, and only then restore the
     * prior action/timer/mask in that order. */
    if (have_mask && sigprocmask(SIG_BLOCK, &alarm_set, NULL) != 0) {
        result.cleanup_rc = -1;
    }
    if (sender > 0) {
        while (waitpid(sender, &sender_status, 0) < 0) {
            if (errno != EINTR) {
                result.cleanup_rc = -1;
                break;
            }
        }
        if (!WIFEXITED(sender_status) || WEXITSTATUS(sender_status) != 0) {
            result.cleanup_rc = -1;
        }
    }
    if (have_timer && setitimer(ITIMER_REAL, &stopped_timer, NULL) != 0) {
        result.cleanup_rc = -1;
    }
    if (have_mask && drain_blocked_alarms(&alarm_set) != 0) {
        result.cleanup_rc = -1;
    }
    if (have_action && sigaction(SIGALRM, &old_action, NULL) != 0) {
        result.cleanup_rc = -1;
    }
    if (have_timer && setitimer(ITIMER_REAL, &old_timer, NULL) != 0) {
        result.cleanup_rc = -1;
    }
    if (have_mask && sigprocmask(SIG_SETMASK, &old_mask, NULL) != 0) {
        result.cleanup_rc = -1;
    }

report:
    (void)write_all_test_bytes(result_fd, &result, sizeof(result));
    close(result_fd);
    _exit(0);
}

static int read_real_probe_result(int fd, real_probe_result_t *result,
                                  int timeout_ms) {
    unsigned char *bytes = (unsigned char *)(void *)result;
    size_t offset = 0;
    int64_t started = real_monotonic_ms();
    int64_t deadline;

    if (started < 0 || timeout_ms < 0 ||
        started > INT64_MAX - timeout_ms) {
        return -1;
    }
    deadline = started + timeout_ms;
    while (offset < sizeof(*result)) {
        struct pollfd descriptor;
        int64_t now = real_monotonic_ms();
        int poll_rc;
        int remaining;
        ssize_t count;

        if (now < 0) return -1;
        if (now >= deadline) return 0;
        remaining = (int)(deadline - now);
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = fd;
        descriptor.events = POLLIN;
        poll_rc = poll(&descriptor, 1, remaining);
        if (poll_rc == 0) return 0;
        if (poll_rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        count = read(fd, bytes + offset, sizeof(*result) - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            return -1;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return 1;
}
#endif

static int64_t fake_probe_clock(void) {
    return g_probe_now;
}

static int fake_eintr_probe_poll(int fd, int timeout_ms) {
    (void)fd;
    if (g_probe_poll_calls <
        (int)(sizeof(g_probe_timeouts) / sizeof(g_probe_timeouts[0]))) {
        g_probe_timeouts[g_probe_poll_calls] = timeout_ms;
    }
    g_probe_poll_calls++;
    /* Keep the adversary finite: the correct absolute deadline exits after
     * five calls, while a mutant that restarts the full timeout reaches this
     * sentinel and returns with observably wrong call/timeout evidence. */
    if (g_probe_poll_calls > 8) return 0;
    g_probe_now += 20;
    errno = EINTR;
    return -1;
}

static int unavailable_git_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    (void)argv;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 1;
    }
    return -1;
}

static int make_private_dir(char *path, size_t path_size) {
    if (path_size < sizeof("/tmp/gswar07sshXXXXXX")) return -1;
    snprintf(path, path_size, "/tmp/gswar07sshXXXXXX");
    if (!ts_mkdtemp(path) ||
        ts_canonicalize_dir_path(path, path_size) != 0 ||
        chmod(path, 0700) != 0) return -1;
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int make_runtime_dir(char *xdg, size_t xdg_size,
                            char *runtime, size_t runtime_size,
                            int *parent_fd) {
    int dir_fd;

    *parent_fd = make_private_dir(xdg, xdg_size);
    if (*parent_fd < 0) return -1;
    if ((size_t)snprintf(runtime, runtime_size, "%s/gitswitch-ssh", xdg) >=
            runtime_size ||
        mkdir(runtime, 0700) != 0 || setenv("XDG_RUNTIME_DIR", xdg, 1) != 0) {
        close(*parent_fd);
        *parent_fd = -1;
        return -1;
    }
    dir_fd = open(runtime, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        close(*parent_fd);
        *parent_fd = -1;
    }
    return dir_fd;
}

TEST(truncated_identity_listing_never_proves_exclusivity) {
    command_runner_fn previous = run_set_runner(fake_identity_runner);

    g_identity_listing_mode = IDENTITY_LIST_RAW;
    CHECK(ssh_manager_test_socket_has_key(-1, "agent.sock",
                                          "/tmp/key-expected"));
    g_identity_listing_mode = IDENTITY_LIST_TRUNCATED;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));
    g_identity_listing_mode = IDENTITY_LIST_RAW;

    run_set_runner(previous);
}

TEST(identity_listing_requires_one_well_formed_raw_record) {
    command_runner_fn previous = run_set_runner(fake_identity_runner);

    g_identity_listing_mode = IDENTITY_LIST_RAW;
    CHECK(ssh_manager_test_socket_has_key(-1, "agent.sock",
                                          "/tmp/key-expected"));

    g_identity_listing_mode = IDENTITY_LIST_CERTIFICATE;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    g_identity_listing_mode = IDENTITY_LIST_RAW_AND_CERTIFICATE;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    g_identity_listing_mode = IDENTITY_LIST_MALFORMED;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    g_identity_listing_mode = IDENTITY_LIST_EMBEDDED_NUL;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));
    g_identity_listing_mode = IDENTITY_LIST_RAW;

    run_set_runner(previous);
}

TEST(keygen_fingerprint_requires_one_complete_leading_token) {
    command_runner_fn previous = run_set_runner(fake_identity_runner);

    g_identity_listing_mode = IDENTITY_LIST_RAW;
    g_keygen_listing_mode = KEYGEN_LISTING_COMPLETE;
    CHECK(ssh_manager_test_socket_has_key(-1, "agent.sock",
                                          "/tmp/key-expected"));

    /* Whole-output capture remains bounded: an output larger than the
     * admitted-file-derived cap is indeterminate even if field two fits. */
    g_keygen_listing_mode = KEYGEN_LISTING_OVERSIZED_OUTPUT;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    /* Truncation cannot manufacture a token boundary, and even a complete
     * token without its following delimiter is not a complete field. */
    g_keygen_listing_mode = KEYGEN_LISTING_TRUNCATED_FINGERPRINT;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));
    g_keygen_listing_mode = KEYGEN_LISTING_UNTERMINATED_FINGERPRINT;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));
    g_keygen_listing_mode = KEYGEN_LISTING_SHORT_FINGERPRINT;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    /* A fingerprint-looking comment or binary capture must not be searched
     * as a substitute for canonical leading fields. */
    g_keygen_listing_mode = KEYGEN_LISTING_MISPLACED_FINGERPRINT;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));
    g_keygen_listing_mode = KEYGEN_LISTING_EMBEDDED_NUL;
    CHECK(!ssh_manager_test_socket_has_key(-1, "agent.sock",
                                           "/tmp/key-expected"));

    g_keygen_listing_mode = KEYGEN_LISTING_COMPLETE;
    run_set_runner(previous);
}

TEST(pid_sidecar_sync_failure_retains_complete_recovery_record) {
    char xdg[64];
    char dir[96];
    char sidecar[160];
    char content[32];
    int parent_fd = make_private_dir(xdg, sizeof(xdg));
    int dir_fd;
    ssh_dirsync_fn previous;
    ssh_reap_fn previous_reap;

    CHECK(parent_fd >= 0);
    if (parent_fd < 0) return;
    snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", xdg);
    CHECK_EQ_INT(mkdir(dir, 0700), 0);
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) {
        close(parent_fd);
        return;
    }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 1;
    previous = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     dir_fd, "ssh-agent.work.pid", (pid_t)12345),
                 -1);
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(g_dirsync_calls, 1);
    snprintf(sidecar, sizeof(sidecar), "%s/ssh-agent.work.pid", dir);
    CHECK_EQ_INT(read_file_to_string(sidecar, content, sizeof(content)), 6);
    CHECK_STR_EQ(content, "12345\n");
    close(dir_fd);
    close(parent_fd);

    /* Crash recovery sees either this complete record or no commit; it never
     * has to interpret a partial PID. Once the recorded process is classified
     * gone, normal reset durably consumes the retained sidecar. */
    previous_reap = ssh_manager_set_reap_fn(classify_recorded_agent_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    errno = 0;
    CHECK_EQ_INT(access(sidecar, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
}

TEST(pid_postrename_identity_failure_is_synced_and_explicitly_uncertain) {
    char dir[64];
    char sidecar[128];
    char content[32];
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_pid_commit_hook_fn previous_hook;
    ssh_dirsync_fn previous_sync;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 0;
    previous_hook = ssh_manager_set_pid_postrename_hook_fn(
        replace_pid_after_rename);
    previous_sync = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     dir_fd, "ssh-agent.work.pid", (pid_t)12345),
                 -1);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_pid_postrename_hook_fn(previous_hook);

    CHECK_EQ_INT(g_dirsync_calls, 1);
    CHECK(strstr(get_last_error()->message, "publication is uncertain") != NULL);
    snprintf(sidecar, sizeof(sidecar), "%s/ssh-agent.work.pid", dir);
    CHECK_EQ_INT(read_file_to_string(sidecar, content, sizeof(content)), 6);
    CHECK_STR_EQ(content, "54321\n");
    close(dir_fd);
}

TEST(equal_length_substitution_survives_restoration_sync_failure_and_resets) {
    char xdg[64];
    char runtime[96];
    char target[64];
    struct stat st;
    int parent_fd;
    int dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                                   sizeof(runtime), &parent_fd);
    ssh_current_cleanup_hook_fn previous_cleanup;
    ssh_quarantine_hook_fn previous_quarantine;
    ssh_dirsync_fn previous_sync;
    ssize_t n;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    g_quarantine_name[0] = '\0';
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 2;
    previous_cleanup = ssh_manager_set_current_cleanup_hook_fn(
        replace_current_equal_length);
    previous_quarantine = ssh_manager_set_quarantine_hook_fn(
        record_quarantine_destination);
    previous_sync = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_quarantine_hook_fn(previous_quarantine);
    ssh_manager_set_current_cleanup_hook_fn(previous_cleanup);

    /* Native no-replace rename reaches the retained duplicate in two
     * barriers.  The portable link/re-prove/unlink protocol performs one
     * additional preservation sync after detecting the substitution. */
    CHECK(g_dirsync_calls == 2 || g_dirsync_calls == 3);
    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "other.sock");
    }
    CHECK(g_quarantine_name[0] != '\0');
    n = readlinkat(dir_fd, g_quarantine_name, target,
                   sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "other.sock");
    }

    /* The first reset reconciles the duplicate quarantine but cannot claim
     * success; subsequent resets keep rejecting the foreign current target. */
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    errno = 0;
    CHECK_EQ_INT(fstatat(dir_fd, g_quarantine_name, &st,
                         AT_SYMLINK_NOFOLLOW),
                 -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "other.sock");
    }
    close(dir_fd);
    close(parent_fd);
}

TEST(quarantine_capture_failure_is_synced_and_discoverable_to_reset) {
    char xdg[64];
    char runtime[96];
    struct stat st;
    int parent_fd;
    int dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                                   sizeof(runtime), &parent_fd);
    ssh_quarantine_hook_fn previous_capture;
    ssh_dirsync_fn previous_sync;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    g_quarantine_name[0] = '\0';
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 0;
    previous_capture = ssh_manager_set_quarantine_capture_hook_fn(
        replace_quarantine_with_regular);
    previous_sync = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_quarantine_capture_hook_fn(previous_capture);

    CHECK(g_dirsync_calls >= 3);
    CHECK(g_quarantine_name[0] != '\0');
    CHECK_EQ_INT(fstatat(dir_fd, g_quarantine_name, &st,
                         AT_SYMLINK_NOFOLLOW),
                 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK_EQ_INT(fstatat(dir_fd, g_quarantine_name, &st,
                         AT_SYMLINK_NOFOLLOW),
                 0);
    CHECK(S_ISREG(st.st_mode));
    close(dir_fd);
    close(parent_fd);
}

TEST(current_link_publication_is_synced_and_sync_failure_unpublishes) {
    char dir[64];
    char current[128];
    struct stat st;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_dirsync_fn previous;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(current, sizeof(current), "%s/current.sock", dir);
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 1;
    previous = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_publish_current_link(
                     dir_fd, "ssh-agent.work.sock"),
                 -1);
    ssh_manager_set_dirsync_fn(previous);
    CHECK(g_dirsync_calls >= 2); /* failed publish sync + durable cleanup */
    CHECK_EQ_INT(lstat(current, &st), -1);
    CHECK_EQ_INT(errno, ENOENT);

    g_dirsync_calls = 0;
    g_dirsync_fail_call = 0;
    previous = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_publish_current_link(
                     dir_fd, "ssh-agent.work.sock"),
                 0);
    ssh_manager_set_dirsync_fn(previous);
    CHECK_EQ_INT(g_dirsync_calls, 1);
    CHECK_EQ_INT(lstat(current, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    close(dir_fd);
}

TEST(post_rename_publication_verification_preserves_replacement) {
    char dir[64];
    char target[64];
    ssize_t n;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_current_publish_hook_fn previous_hook;
    ssh_dirsync_fn previous_sync;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 0;
    previous_hook = ssh_manager_set_current_publish_hook_fn(
        replace_current_during_cleanup);
    previous_sync = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_publish_current_link(
                     dir_fd, "ssh-agent.work.sock"),
                 -1);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_current_publish_hook_fn(previous_hook);

    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "replacement.sock");
    }
    CHECK(g_dirsync_calls >= 1);
    close(dir_fd);
}

TEST(current_link_substitution_is_preserved_not_unlinked) {
    char dir[64];
    char target[64];
    ssize_t n;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_current_cleanup_hook_fn previous;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    previous = ssh_manager_set_current_cleanup_hook_fn(
        replace_current_during_cleanup);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_current_cleanup_hook_fn(previous);

    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "replacement.sock");
    }

    CHECK_EQ_INT(unlinkat(dir_fd, "current.sock", 0), 0);
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 0;
    {
        ssh_dirsync_fn previous_sync =
            ssh_manager_set_dirsync_fn(counting_dirsync);
        CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), 0);
        ssh_manager_set_dirsync_fn(previous_sync);
    }
    /* Native rename needs publication+cleanup barriers; the portable
     * quarantine additionally syncs its hard-link publication and public-name
     * removal.  Both must durably remove the exact captured link. */
    CHECK(g_dirsync_calls == 2 || g_dirsync_calls == 4);
    {
        struct stat absent;
        errno = 0;
        CHECK_EQ_INT(fstatat(dir_fd, "current.sock", &absent,
                             AT_SYMLINK_NOFOLLOW),
                     -1);
    }
    CHECK_EQ_INT(errno, ENOENT);
    close(dir_fd);
}

TEST(precleanup_substitution_and_non_enoent_inspection_fail_truthfully) {
    char dir[64];
    char target[64];
    ssize_t n;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_current_precleanup_hook_fn previous;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    previous = ssh_manager_set_current_precleanup_hook_fn(
        replace_current_during_cleanup);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_current_precleanup_hook_fn(previous);
    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "replacement.sock");
    }

    previous = ssh_manager_set_current_precleanup_hook_fn(
        close_current_dir_before_cleanup);
    errno = 0;
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    CHECK_EQ_INT(errno, EBADF);
    ssh_manager_set_current_precleanup_hook_fn(previous);
    /* The hook closed dir_fd: a non-ENOENT fstatat failure must not be
     * mistaken for an already-complete cleanup. */
}

TEST(quarantine_destination_race_never_overwrites_existing_entry) {
    char dir[64];
    char target[64];
    struct stat current_identity;
    struct stat quarantine_identity;
    ssize_t n;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    ssh_quarantine_hook_fn previous;
    ssh_dirsync_fn previous_sync;
    bool previous_force;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    CHECK_EQ_INT(symlinkat("owned.sock", dir_fd, "current.sock"), 0);
    g_quarantine_name[0] = '\0';
    previous_force = ssh_manager_set_force_portable_quarantine(true);
    previous = ssh_manager_set_quarantine_hook_fn(
        occupy_quarantine_destination);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_quarantine_hook_fn(previous);

    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "owned.sock");
    }
    CHECK(g_quarantine_name[0] != '\0');
    n = readlinkat(dir_fd, g_quarantine_name, target,
                   sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "raced-quarantine.sock");
    }

    /* A portable publication barrier failure must occur while both exact hard
     * links are still present. This catches deleting, ignoring, or moving the
     * first directory sync until after current.sock has been unlinked. */
    CHECK_EQ_INT(unlinkat(dir_fd, g_quarantine_name, 0), 0);
    g_quarantine_name[0] = '\0';
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 1;
    previous = ssh_manager_set_quarantine_hook_fn(
        record_quarantine_destination);
    previous_sync = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), -1);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_quarantine_hook_fn(previous);

    CHECK_EQ_INT(g_dirsync_calls, 2);
    CHECK(g_quarantine_name[0] != '\0');
    CHECK_EQ_INT(fstatat(dir_fd, "current.sock", &current_identity,
                         AT_SYMLINK_NOFOLLOW),
                 0);
    CHECK_EQ_INT(fstatat(dir_fd, g_quarantine_name, &quarantine_identity,
                         AT_SYMLINK_NOFOLLOW),
                 0);
    CHECK(S_ISLNK(current_identity.st_mode));
    CHECK(S_ISLNK(quarantine_identity.st_mode));
    CHECK(current_identity.st_dev == quarantine_identity.st_dev);
    CHECK(current_identity.st_ino == quarantine_identity.st_ino);
    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "owned.sock");
    }
    n = readlinkat(dir_fd, g_quarantine_name, target,
                   sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "owned.sock");
    }

    /* The lock-boundary fallback also completes normally when its
     * no-overwrite destination is free. */
    CHECK_EQ_INT(unlinkat(dir_fd, g_quarantine_name, 0), 0);
    CHECK_EQ_INT(ssh_manager_test_cleanup_current_link(dir_fd), 0);
    ssh_manager_set_force_portable_quarantine(previous_force);
    {
        struct stat absent;
        errno = 0;
        CHECK_EQ_INT(fstatat(dir_fd, "current.sock", &absent,
                             AT_SYMLINK_NOFOLLOW),
                     -1);
        CHECK_EQ_INT(errno, ENOENT);
    }
    close(dir_fd);
}

TEST(reset_all_rejects_regular_current_socket_replacement) {
    char xdg[64];
    char runtime[96];
    struct stat st;
    int parent_fd;
    int fd;
    int dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                                   sizeof(runtime), &parent_fd);

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    fd = openat(dir_fd, "current.sock",
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK_EQ_INT(fstatat(dir_fd, "current.sock", &st,
                         AT_SYMLINK_NOFOLLOW),
                 0);
    CHECK(S_ISREG(st.st_mode));
    close(dir_fd);
    close(parent_fd);
}

TEST(reset_all_preserves_precleanup_replacement_and_reports_failure) {
    char xdg[64];
    char runtime[96];
    char managed_target[160];
    char target[64];
    int parent_fd;
    int dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                                   sizeof(runtime), &parent_fd);
    ssh_current_precleanup_hook_fn previous;
    ssize_t n;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(managed_target, sizeof(managed_target),
             "%s/ssh-agent.work.sock", runtime);
    CHECK_EQ_INT(symlinkat(managed_target, dir_fd,
                           "current.sock"),
                 0);
    previous = ssh_manager_set_current_precleanup_hook_fn(
        replace_current_during_cleanup);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    ssh_manager_set_current_precleanup_hook_fn(previous);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    n = readlinkat(dir_fd, "current.sock", target, sizeof(target) - 1U);
    CHECK(n > 0 && (size_t)n < sizeof(target));
    if (n > 0 && (size_t)n < sizeof(target)) {
        target[n] = '\0';
        CHECK_STR_EQ(target, "replacement.sock");
    }
    close(dir_fd);
    close(parent_fd);
}

TEST(reset_retry_confirms_empty_and_newly_absent_namespaces) {
    char xdg[64];
    char runtime[96];
    char managed_target[160];
    int parent_fd;
    int dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                                   sizeof(runtime), &parent_fd);
    ssh_dirsync_fn previous;
    bool previous_force;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 1;
    previous = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK_EQ_INT(ssh_manager_reset(NULL), 0);
    ssh_manager_set_dirsync_fn(previous);
    CHECK_EQ_INT(g_dirsync_calls, 2);
    close(dir_fd);
    close(parent_fd);

    dir_fd = make_runtime_dir(xdg, sizeof(xdg), runtime,
                               sizeof(runtime), &parent_fd);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(managed_target, sizeof(managed_target),
             "%s/ssh-agent.work.sock", runtime);
    CHECK_EQ_INT(symlinkat(managed_target, dir_fd,
                           "current.sock"),
                 0);
    g_dirsync_calls = 0;
    g_dirsync_fail_call = 1;
    previous_force = ssh_manager_set_force_portable_quarantine(true);
    previous = ssh_manager_set_dirsync_fn(counting_dirsync);
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    /* A failed portable quarantine publication leaves its exact hard-linked
     * retry name discoverable.  The next reset reconciles that evidence but
     * deliberately remains nonzero; only a fresh pass may confirm the clean
     * namespace. */
    CHECK_EQ_INT(ssh_manager_reset(NULL), -1);
    CHECK_EQ_INT(ssh_manager_reset(NULL), 0);
    ssh_manager_set_dirsync_fn(previous);
    ssh_manager_set_force_portable_quarantine(previous_force);
    CHECK(g_dirsync_calls >= 2);
    errno = 0;
    CHECK_EQ_INT(faccessat(dir_fd, "current.sock", F_OK,
                           AT_SYMLINK_NOFOLLOW),
                 -1);
    CHECK_EQ_INT(errno, ENOENT);
    close(dir_fd);
    close(parent_fd);
}

TEST(key_inspection_opens_once_and_refuses_symlink_following) {
    static const char key_data[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
    char dir[64];
    char key[128];
    char link[128];
    ssh_key_inspection_t inspection;
    ssh_key_open_fn previous;
    int dir_fd;
    int fd;

    dir_fd = make_private_dir(dir, sizeof(dir));
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(key, sizeof(key), "%s/id_test", dir);
    snprintf(link, sizeof(link), "%s/id_link", dir);
    fd = open(key, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(write(fd, key_data, sizeof(key_data) - 1U),
                 (ssize_t)(sizeof(key_data) - 1U));
    CHECK_EQ_INT(close(fd), 0);

    g_key_open_calls = 0;
    previous = ssh_manager_set_key_open_fn(counting_key_open);
    CHECK_EQ_INT(ssh_inspect_key_file(key, &inspection), 0);
    ssh_manager_set_key_open_fn(previous);
    CHECK_EQ_INT(g_key_open_calls, 1);
    CHECK((g_key_open_flags & O_NONBLOCK) != 0);
    CHECK(inspection.exists);
    CHECK(inspection.regular);
    CHECK(inspection.owned_by_user);
    CHECK(inspection.secure_permissions);
    CHECK(inspection.private_key);
    CHECK_EQ_INT(inspection.mode, 0600);

    g_key_open_calls = 0;
    previous = ssh_manager_set_key_open_fn(counting_key_open);
    CHECK_EQ_INT(ssh_validate_key_file(key), 0);
    ssh_manager_set_key_open_fn(previous);
    CHECK_EQ_INT(g_key_open_calls, 1);

    CHECK_EQ_INT(symlink(key, link), 0);
    g_key_open_calls = 0;
    previous = ssh_manager_set_key_open_fn(counting_key_open);
    CHECK_EQ_INT(ssh_inspect_key_file(link, &inspection), -1);
    ssh_manager_set_key_open_fn(previous);
    CHECK_EQ_INT(g_key_open_calls, 1);
    close(dir_fd);
}

TEST(key_inspection_classifies_fifo_without_blocking) {
    char dir[64];
    char fifo[128];
    ssh_key_inspection_t inspection;
    int64_t started;
    int64_t elapsed;
    int dir_fd = make_private_dir(dir, sizeof(dir));

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(fifo, sizeof(fifo), "%s/id_fifo", dir);
    CHECK_EQ_INT(mkfifo(fifo, 0600), 0);
    started = real_monotonic_ms();
    CHECK(started >= 0);
    CHECK_EQ_INT(ssh_inspect_key_file(fifo, &inspection), 0);
    elapsed = real_monotonic_ms() - started;
    CHECK(inspection.exists);
    CHECK(!inspection.regular);
    CHECK(elapsed >= 0 && elapsed < 500);
    close(dir_fd);
}

TEST(repeated_eintr_consumes_one_absolute_probe_deadline) {
    ssh_probe_clock_fn previous_clock;
    ssh_probe_poll_fn previous_poll;

    g_probe_now = 0;
    g_probe_poll_calls = 0;
    memset(g_probe_timeouts, 0, sizeof(g_probe_timeouts));
    previous_clock = ssh_manager_set_probe_clock_fn(fake_probe_clock);
    previous_poll = ssh_manager_set_probe_poll_fn(fake_eintr_probe_poll);
    CHECK_EQ_INT(ssh_manager_test_probe_deadline(100), 0);
    ssh_manager_set_probe_poll_fn(previous_poll);
    ssh_manager_set_probe_clock_fn(previous_clock);

    CHECK_EQ_INT(g_probe_poll_calls, 5);
    CHECK_EQ_INT(g_probe_timeouts[0], 100);
    CHECK_EQ_INT(g_probe_timeouts[1], 80);
    CHECK_EQ_INT(g_probe_timeouts[2], 60);
    CHECK_EQ_INT(g_probe_timeouts[3], 40);
    CHECK_EQ_INT(g_probe_timeouts[4], 20);
}

#ifdef __linux__
TEST(real_probe_signal_storm_respects_wall_deadline) {
    real_probe_result_t result;
    int result_pipe[2] = {-1, -1};
    int child_status = 0;
    int watchdog_rc;
    pid_t probe_pid;
    pid_t waited_pid;

    CHECK_EQ_INT(pipe(result_pipe), 0);
    if (result_pipe[0] < 0 || result_pipe[1] < 0) {
        return;
    }
    probe_pid = fork();
    CHECK(probe_pid >= 0);
    if (probe_pid < 0) {
        close(result_pipe[0]);
        close(result_pipe[1]);
        return;
    }
    if (probe_pid == 0) {
        close(result_pipe[0]);
        (void)setpgid(0, 0);
        run_real_probe_child(result_pipe[1]);
    }
    close(result_pipe[1]);
    result_pipe[1] = -1;
    (void)setpgid(probe_pid, probe_pid);
    memset(&result, 0, sizeof(result));

    /* This is the hard suite-level watchdog: even a historical infinite-EINTR
     * regression is killed outside the process running the remaining tests. */
    watchdog_rc = read_real_probe_result(result_pipe[0], &result, 2000);
    if (watchdog_rc != 1) {
        (void)kill(-probe_pid, SIGKILL);
        (void)kill(probe_pid, SIGKILL);
    }
    do {
        waited_pid = waitpid(probe_pid, &child_status, 0);
    } while (waited_pid < 0 && errno == EINTR);
    close(result_pipe[0]);

    CHECK_EQ_INT(watchdog_rc, 1);
    CHECK(waited_pid == probe_pid);
    if (watchdog_rc == 1) {
        CHECK(WIFEXITED(child_status));
        CHECK_EQ_INT(WEXITSTATUS(child_status), 0);
        CHECK_EQ_INT(result.setup_rc, 0);
        CHECK_EQ_INT(result.cleanup_rc, 0);
        CHECK_EQ_INT(result.probe_rc, 0);
        CHECK_EQ_INT(result.reachable, 0);
        CHECK(result.alarm_count >= 5);
        CHECK(result.elapsed_ms >= 70 && result.elapsed_ms < 500);
    }
}
#endif

TEST(account_status_reuses_one_descriptor_backed_key_inspection) {
    static const char key_data[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
    char dir[64];
    char key[128];
    char output[8192];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    ssh_key_open_fn previous_open;
    FILE *capture;
    size_t captured;
    int saved_stdout;
    int dir_fd = make_private_dir(dir, sizeof(dir));
    int fd;

    CHECK(dir_fd >= 0);
    if (dir_fd < 0) return;
    snprintf(key, sizeof(key), "%s/id_status", dir);
    fd = open(key, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) {
        close(dir_fd);
        return;
    }
    CHECK_EQ_INT(write(fd, key_data, sizeof(key_data) - 1U),
                 (ssize_t)(sizeof(key_data) - 1U));
    CHECK_EQ_INT(close(fd), 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.account_count = 1;
    ctx.accounts[0].id = 7;
    snprintf(ctx.accounts[0].name, sizeof(ctx.accounts[0].name), "status");
    snprintf(ctx.accounts[0].email, sizeof(ctx.accounts[0].email),
             "status@example.test");
    ctx.accounts[0].ssh_enabled = true;
    snprintf(ctx.accounts[0].ssh_key_path,
             sizeof(ctx.accounts[0].ssh_key_path), "%s", key);
    ctx.current_account = &ctx.accounts[0];

    capture = tmpfile();
    CHECK(capture != NULL);
    if (!capture) {
        close(dir_fd);
        return;
    }
    saved_stdout = dup(STDOUT_FILENO);
    CHECK(saved_stdout >= 0);
    if (saved_stdout < 0) {
        fclose(capture);
        close(dir_fd);
        return;
    }
    previous_runner = run_set_runner(unavailable_git_runner);
    g_key_open_calls = 0;
    previous_open = ssh_manager_set_key_open_fn(counting_key_open);
    fflush(stdout);
    CHECK_EQ_INT(dup2(fileno(capture), STDOUT_FILENO), STDOUT_FILENO);
    CHECK_EQ_INT(accounts_show_status(&ctx), -1);
    fflush(stdout);
    CHECK_EQ_INT(dup2(saved_stdout, STDOUT_FILENO), STDOUT_FILENO);
    ssh_manager_set_key_open_fn(previous_open);
    run_set_runner(previous_runner);
    close(saved_stdout);
    rewind(capture);
    memset(output, 0, sizeof(output));
    captured = fread(output, 1, sizeof(output) - 1U, capture);
    CHECK(!ferror(capture));
    output[captured] = '\0';
    fclose(capture);

    CHECK_EQ_INT(g_key_open_calls, 1);
    CHECK(strstr(output, "Key File: [FOUND]") != NULL);
    CHECK(strstr(output, "Permissions: [SECURE] (600)") != NULL);
    close(dir_fd);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(truncated_identity_listing_never_proves_exclusivity);
    RUN_TEST(identity_listing_requires_one_well_formed_raw_record);
    RUN_TEST(keygen_fingerprint_requires_one_complete_leading_token);
    RUN_TEST(pid_sidecar_sync_failure_retains_complete_recovery_record);
    RUN_TEST(pid_postrename_identity_failure_is_synced_and_explicitly_uncertain);
    RUN_TEST(equal_length_substitution_survives_restoration_sync_failure_and_resets);
    RUN_TEST(quarantine_capture_failure_is_synced_and_discoverable_to_reset);
    RUN_TEST(current_link_publication_is_synced_and_sync_failure_unpublishes);
    RUN_TEST(post_rename_publication_verification_preserves_replacement);
    RUN_TEST(current_link_substitution_is_preserved_not_unlinked);
    RUN_TEST(precleanup_substitution_and_non_enoent_inspection_fail_truthfully);
    RUN_TEST(quarantine_destination_race_never_overwrites_existing_entry);
    RUN_TEST(reset_all_rejects_regular_current_socket_replacement);
    RUN_TEST(reset_all_preserves_precleanup_replacement_and_reports_failure);
    RUN_TEST(reset_retry_confirms_empty_and_newly_absent_namespaces);
    RUN_TEST(key_inspection_opens_once_and_refuses_symlink_following);
    RUN_TEST(key_inspection_classifies_fifo_without_blocking);
    RUN_TEST(repeated_eintr_consumes_one_absolute_probe_deadline);
#ifdef __linux__
    RUN_TEST(real_probe_signal_storm_respects_wall_deadline);
#endif
    RUN_TEST(account_status_reuses_one_descriptor_backed_key_inspection);
TEST_MAIN_END()
