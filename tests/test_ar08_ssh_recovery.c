/* AR-08 T10 causal coverage for SSH process provenance and recovery:
 *
 * M39: OWNED, UNRELATED, GONE, and INDETERMINATE remain distinct through
 *      identity inspection, pidfd signaling/fail-closed recovery, and
 *      sidecar cleanup.
 * M40: an ssh-agent launched from one pinned runtime root cannot be reaped by
 *      an identically named sidecar in a different runtime root.
 * M41: repeated EINTR during both observation windows cannot consume time
 *      that did not actually elapse.
 * L25: a failed pre-sidecar reap publishes a durable retry tuple instead of
 *      unlinking the surviving runtime's final discovery handle.
 */

/* Keep strict feature selection glibc-only: Darwin and the BSDs hide
 * default-namespace test helpers such as mkdtemp() when it is enabled. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "scratch_registry_test.h"
#include "ssh_manager.h"
#include "runner_internal.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
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

#define TEST_PID ((pid_t)1073741824)
#define TEST_FP "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define TEST_RECORD_TEXT                                                   \
    "v1 1073741824 1 01020304050607081112131415161718 "                   \
    "00000000000000002122232425262728\n"

static const ssh_process_generation_t g_test_generation = {
    .kind = SSH_PROCESS_GENERATION_LINUX,
    .boot_hi = UINT64_C(0x0102030405060708),
    .boot_lo = UINT64_C(0x1112131415161718),
    .start_hi = 0,
    .start_lo = UINT64_C(0x2122232425262728)
};
static pid_t g_runner_server_pid = -1;
static int g_runner_server_trace_fd = -1;

static void stop_runner_server(void) {
    if (g_runner_server_pid > 1) {
        int status;

        (void)kill(g_runner_server_pid, SIGKILL);
        while (waitpid(g_runner_server_pid, &status, 0) < 0 &&
               errno == EINTR) {
        }
    }
    if (g_runner_server_trace_fd >= 0) {
        close(g_runner_server_trace_fd);
    }
    g_runner_server_pid = -1;
    g_runner_server_trace_fd = -1;
}

static bool is_ssh_agent_command(const char *path) {
    const char *base;

    if (!path || !*path) return false;
    base = strrchr(path, '/');
    return strcmp(base ? base + 1 : path, "ssh-agent") == 0;
}

static int certify_agent_launch(const char *path, run_result_t *result) {
    if (!path || !result ||
        !run_launch_witness_capture(path, &result->launch_witness)) {
        return -1;
    }
    return 0;
}

static bool is_v2_test_record(const char *text) {
    const char *path;
    const char *base;

    if (!text ||
        strncmp(text, "v2 1073741824 ",
                strlen("v2 1073741824 ")) != 0) {
        return false;
    }
    path = strchr(text, '\n');
    if (!path || path[1] != '/') return false;
    base = strrchr(path + 1, '/');
    return base && strcmp(base + 1, "ssh-agent\n") == 0;
}

typedef struct {
    char xdg[64];
    char runtime[128];
    char socket[192];
    char sidecar[192];
    char current[192];
    int dir_fd;
} ssh_fixture_t;

static int make_fixture(ssh_fixture_t *fixture, const char *stem) {
    static const char private_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "recovery-fixture\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char key[128];
    int written;

    if (!fixture || !stem) return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->dir_fd = -1;
    written = snprintf(fixture->xdg, sizeof(fixture->xdg),
                       "/tmp/%sXXXXXX", stem);
    if (written < 0 || (size_t)written >= sizeof(fixture->xdg) ||
        !ts_mkdtemp(fixture->xdg) ||
        ts_canonicalize_dir_path(fixture->xdg,
                                 sizeof(fixture->xdg)) != 0 ||
        chmod(fixture->xdg, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->xdg, 1) != 0) {
        return -1;
    }
    written = snprintf(key, sizeof(key), "%s/key", fixture->xdg);
    if (written < 0 || (size_t)written >= sizeof(key) ||
        write_string_to_file(key, private_key, 0600) != 0) {
        return -1;
    }
    written = snprintf(fixture->runtime, sizeof(fixture->runtime),
                       "%s/gitswitch-ssh", fixture->xdg);
    if (written < 0 || (size_t)written >= sizeof(fixture->runtime) ||
        mkdir(fixture->runtime, 0700) != 0) {
        return -1;
    }
    fixture->dir_fd = open(fixture->runtime,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->dir_fd < 0) return -1;
    written = snprintf(fixture->socket, sizeof(fixture->socket),
                       "%s/ssh-agent.work.sock", fixture->runtime);
    if (written < 0 || (size_t)written >= sizeof(fixture->socket)) return -1;
    written = snprintf(fixture->sidecar, sizeof(fixture->sidecar),
                       "%s/ssh-agent.work.pid", fixture->runtime);
    if (written < 0 || (size_t)written >= sizeof(fixture->sidecar)) return -1;
    written = snprintf(fixture->current, sizeof(fixture->current),
                       "%s/current.sock", fixture->runtime);
    if (written < 0 || (size_t)written >= sizeof(fixture->current)) return -1;
    return 0;
}

static int complete_synthetic_record_image(ssh_agent_record_t *record) {
    run_launch_witness_t witness;
    char agent_path[MAX_PATH_LEN];

    if (!record || record->pid <= 1) return -1;
    memset(&witness, 0, sizeof(witness));
    if (find_command_path("ssh-agent", agent_path,
                          sizeof(agent_path)) != 0 ||
        !run_launch_witness_capture(agent_path, &witness) ||
        !witness.valid || witness.is_script ||
        safe_strncpy(record->image.executable_path,
                     witness.executable_path,
                     sizeof(record->image.executable_path)) != 0) {
        return -1;
    }
    record->image.valid = true;
    record->image.executable_identity = witness.executable_identity;
    record->image.effective_uid = geteuid();
    record->image.socket_peer_pid = record->pid;
    record->image.socket_peer_uid = geteuid();
    return 0;
}

static int publish_sidecar(const ssh_fixture_t *fixture, pid_t pid) {
    ssh_agent_record_t record = {
        .pid = pid,
        .generation = g_test_generation
    };

    if (complete_synthetic_record_image(&record) != 0) return -1;
    return ssh_manager_test_write_pid_sidecar(
        fixture->dir_fd, "ssh-agent.work.pid", &record);
}

static int publish_sidecar_for_process(const ssh_fixture_t *fixture,
                                       pid_t pid) {
    ssh_agent_record_t record = {.pid = pid};
    if (ssh_manager_test_capture_process_generation(
            pid, &record.generation) != 0) {
        return -1;
    }
    return ssh_manager_test_write_pid_sidecar(
        fixture->dir_fd, "ssh-agent.work.pid", &record);
}

static ssh_process_outcome_t reap_gone(const ssh_agent_record_t *record,
                                       const char *socket_arg,
                                       int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    stop_runner_server();
    return SSH_PROCESS_GONE;
}

static ssh_process_outcome_t reap_indeterminate(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t reap_unrelated(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_UNRELATED;
}

static ssh_process_outcome_t reap_replaced(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_REPLACED;
}

static char g_race_runtime[192];
static char g_race_moved_runtime[192];
static char g_race_socket[256];
static char g_race_sidecar[256];
static bool g_race_hook_succeeded;
static char g_retire_quarantine[128];
static const char *g_retire_replacement;
static int g_retire_hook_calls;
static int g_retire_mutations;
static int g_retire_replace_on_call;
static bool g_retire_replacement_captured;
static struct stat g_retire_replacement_identity;
static int g_reset_dirsync_calls;
static int g_stop_dirsync_calls;
static ssh_metadata_test_stage_t g_metadata_mismatch_stage;
static int g_metadata_mismatch_calls;

static bool force_ssh_metadata_mismatch(ssh_metadata_test_stage_t stage) {
    if (stage != g_metadata_mismatch_stage) return false;
    g_metadata_mismatch_calls++;
    errno = E2BIG;
    return true;
}

static int bind_stale_socket(const char *path) {
    struct sockaddr_un address;
    int fd;

    if (!path || strlen(path) >= sizeof(address.sun_path)) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(fd, (struct sockaddr *)(void *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int bind_live_socket(const char *path) {
    struct sockaddr_un address;
    int fd;

    if (!path || strlen(path) >= sizeof(address.sun_path)) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(fd, (struct sockaddr *)(void *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 || listen(fd, 8) != 0) {
        int saved_errno = errno;
        close(fd);
        (void)unlink(path);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

enum {
    TEST_AGENT_REQUEST_IDENTITIES = 11,
    TEST_AGENT_IDENTITIES_ANSWER = 12,
    TEST_AGENT_REMOVE_ALL_IDENTITIES = 19,
    TEST_AGENT_REMOVE_ALL_RSA_IDENTITIES = 9,
    TEST_AGENT_FAILURE = 5,
    TEST_AGENT_SUCCESS = 6
};

typedef enum {
    TEST_AGENT_IDENTITIES_ONE = 0,
    TEST_AGENT_WRONG_TYPE,
    TEST_AGENT_MALFORMED_IDENTITIES,
    TEST_AGENT_TRUNCATED,
    TEST_AGENT_OVERSIZED,
    TEST_AGENT_TIMEOUT,
    TEST_AGENT_CLEAR_EMPTY,
    TEST_AGENT_CLEAR_FAILURE,
    TEST_AGENT_CLEAR_NONEMPTY
} test_agent_mode_t;

typedef struct {
    pid_t pid;
    int trace_fd;
} test_agent_server_t;

static void test_agent_write_u32(unsigned char *bytes, uint32_t value) {
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static int test_agent_read_exact(int fd, void *buffer, size_t size) {
    unsigned char *cursor = buffer;
    size_t offset = 0;

    while (offset < size) {
        ssize_t n = read(fd, cursor + offset, size - offset);
        if (n > 0) {
            offset += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int test_agent_write_exact(int fd, const void *buffer, size_t size) {
    const unsigned char *cursor = buffer;
    size_t offset = 0;

    while (offset < size) {
        ssize_t n = write(fd, cursor + offset, size - offset);
        if (n > 0) {
            offset += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static void test_agent_wait_for_peer_close(int fd) {
    unsigned char discarded[64];

    for (;;) {
        ssize_t n = read(fd, discarded, sizeof(discarded));
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        return;
    }
}

static int test_agent_read_request(int fd, unsigned char *type) {
    unsigned char frame[5];

    if (!type || test_agent_read_exact(fd, frame, sizeof(frame)) != 0 ||
        frame[0] != 0 || frame[1] != 0 || frame[2] != 0 ||
        frame[3] != 1) {
        return -1;
    }
    *type = frame[4];
    return 0;
}

static int test_agent_write_message(int fd, const unsigned char *payload,
                                    size_t payload_size) {
    unsigned char header[4];

    if (!payload || payload_size > UINT32_MAX) return -1;
    test_agent_write_u32(header, (uint32_t)payload_size);
    return test_agent_write_exact(fd, header, sizeof(header)) == 0 &&
                   test_agent_write_exact(fd, payload, payload_size) == 0
               ? 0
               : -1;
}

static int test_agent_write_identities(int fd, bool nonempty) {
    static const unsigned char empty[] = {
        TEST_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0
    };
    static const unsigned char one[] = {
        TEST_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1,
        0, 0, 0, 3, 'k', 'e', 'y',
        0, 0, 0, 5, 'p', 'r', 'o', 'x', 'y'
    };

    return nonempty
               ? test_agent_write_message(fd, one, sizeof(one))
               : test_agent_write_message(fd, empty, sizeof(empty));
}

static void test_agent_serve_connection(int fd, int trace_fd,
                                        test_agent_mode_t mode) {
    unsigned char type;

    if (test_agent_read_request(fd, &type) != 0) return;
    if (test_agent_write_exact(trace_fd, &type, sizeof(type)) != 0) return;

    switch (mode) {
        case TEST_AGENT_IDENTITIES_ONE:
            if (type == TEST_AGENT_REQUEST_IDENTITIES) {
                if (test_agent_write_identities(fd, true) == 0) {
                    /* Darwin authenticates the socket peer again after the
                     * protocol response. A real ssh-agent keeps this
                     * connection open until its client closes it; doing the
                     * same here prevents the post-response LOCAL_PEERPID
                     * proof from racing a synthetic server exit. */
                    test_agent_wait_for_peer_close(fd);
                }
            }
            return;
        case TEST_AGENT_WRONG_TYPE: {
            static const unsigned char failure[] = {TEST_AGENT_FAILURE};
            (void)test_agent_write_message(fd, failure, sizeof(failure));
            return;
        }
        case TEST_AGENT_MALFORMED_IDENTITIES: {
            static const unsigned char malformed[] = {
                TEST_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1
            };
            (void)test_agent_write_message(
                fd, malformed, sizeof(malformed));
            return;
        }
        case TEST_AGENT_TRUNCATED: {
            unsigned char partial[5];
            test_agent_write_u32(partial, 5);
            partial[4] = TEST_AGENT_IDENTITIES_ANSWER;
            (void)test_agent_write_exact(fd, partial, sizeof(partial));
            return;
        }
        case TEST_AGENT_OVERSIZED: {
            unsigned char header[4];
            test_agent_write_u32(header, (256U * 1024U) + 1U);
            (void)test_agent_write_exact(fd, header, sizeof(header));
            return;
        }
        case TEST_AGENT_TIMEOUT:
            for (;;) pause();
        case TEST_AGENT_CLEAR_FAILURE:
        case TEST_AGENT_CLEAR_EMPTY:
        case TEST_AGENT_CLEAR_NONEMPTY: {
            static const unsigned char failure[] = {TEST_AGENT_FAILURE};
            static const unsigned char success[] = {TEST_AGENT_SUCCESS};

            if (type == TEST_AGENT_REQUEST_IDENTITIES) {
                if (test_agent_write_identities(fd, true) != 0 ||
                    test_agent_read_request(fd, &type) != 0 ||
                    test_agent_write_exact(trace_fd, &type,
                                           sizeof(type)) != 0) {
                    return;
                }
            }
            if (type != TEST_AGENT_REMOVE_ALL_IDENTITIES) return;
            if (mode == TEST_AGENT_CLEAR_FAILURE) {
                (void)test_agent_write_message(
                    fd, failure, sizeof(failure));
                return;
            }
            if (test_agent_write_message(
                    fd, success, sizeof(success)) != 0 ||
                test_agent_read_request(fd, &type) != 0 ||
                test_agent_write_exact(trace_fd, &type,
                                       sizeof(type)) != 0 ||
                type != TEST_AGENT_REQUEST_IDENTITIES) {
                return;
            }
            (void)test_agent_write_identities(
                fd, mode == TEST_AGENT_CLEAR_NONEMPTY);
            return;
        }
        default:
            return;
    }
}

static void test_agent_server_main(const char *path, test_agent_mode_t mode,
                                   int ready_fd, int trace_fd) {
    struct sockaddr_un address;
    char ready = 'E';
    int listener;

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || strlen(path) >= sizeof(address.sun_path)) {
        (void)test_agent_write_exact(ready_fd, &ready, sizeof(ready));
        _exit(2);
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(listener, (struct sockaddr *)(void *)&address,
             sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 || listen(listener, 8) != 0) {
        (void)test_agent_write_exact(ready_fd, &ready, sizeof(ready));
        close(listener);
        _exit(2);
    }
    ready = 'R';
    if (test_agent_write_exact(ready_fd, &ready, sizeof(ready)) != 0) {
        close(listener);
        _exit(2);
    }
    close(ready_fd);

    for (;;) {
        int connection = accept(listener, NULL, NULL);
        if (connection < 0) {
            if (errno == EINTR) continue;
            _exit(2);
        }
        test_agent_serve_connection(connection, trace_fd, mode);
        close(connection);
    }
}

static int start_test_agent_server(const char *path, test_agent_mode_t mode,
                                   test_agent_server_t *server) {
    int ready_pipe[2];
    int trace_pipe[2];
    char ready = '\0';
    pid_t child;
    int flags;

    if (!path || !server || pipe(ready_pipe) != 0) return -1;
    if (pipe(trace_pipe) != 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }
    child = fork();
    if (child < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        close(trace_pipe[0]);
        close(trace_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(trace_pipe[0]);
        test_agent_server_main(path, mode, ready_pipe[1], trace_pipe[1]);
        _exit(2);
    }
    close(ready_pipe[1]);
    close(trace_pipe[1]);
    if (test_agent_read_exact(ready_pipe[0], &ready, sizeof(ready)) != 0 ||
        close(ready_pipe[0]) != 0 || ready != 'R') {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        close(trace_pipe[0]);
        return -1;
    }
    flags = fcntl(trace_pipe[0], F_GETFL, 0);
    if (flags < 0 ||
        fcntl(trace_pipe[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        close(trace_pipe[0]);
        return -1;
    }
    server->pid = child;
    server->trace_fd = trace_pipe[0];
    return 0;
}

static int query_test_agent_identity_count(const char *path,
                                           uint32_t *identity_count) {
    static const unsigned char request[] = {
        0, 0, 0, 1, TEST_AGENT_REQUEST_IDENTITIES
    };
    struct sockaddr_un address;
    unsigned char response[256];
    unsigned char header[4];
    uint32_t payload_size;
    int fd;
    int rc = -1;

    if (!path || !identity_count ||
        strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (connect(fd, (struct sockaddr *)(void *)&address,
                sizeof(address)) != 0 ||
        test_agent_write_exact(fd, request, sizeof(request)) != 0 ||
        test_agent_read_exact(fd, header, sizeof(header)) != 0) {
        goto out;
    }
    payload_size = ((uint32_t)header[0] << 24) |
                   ((uint32_t)header[1] << 16) |
                   ((uint32_t)header[2] << 8) |
                   (uint32_t)header[3];
    if (payload_size < 5U || payload_size > sizeof(response) ||
        test_agent_read_exact(fd, response, payload_size) != 0 ||
        response[0] != TEST_AGENT_IDENTITIES_ANSWER) {
        goto out;
    }
    *identity_count = ((uint32_t)response[1] << 24) |
                      ((uint32_t)response[2] << 16) |
                      ((uint32_t)response[3] << 8) |
                      (uint32_t)response[4];
    rc = 0;
out:
    if (close(fd) != 0) rc = -1;
    return rc;
}

static size_t collect_test_agent_trace(test_agent_server_t *server,
                                       unsigned char *trace,
                                       size_t trace_size) {
    size_t used = 0;

    if (!server || !trace) return 0;
    while (used < trace_size) {
        ssize_t n = read(server->trace_fd, trace + used, trace_size - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    return used;
}

static void stop_test_agent_server(test_agent_server_t *server) {
    if (!server) return;
    if (server->pid > 1) {
        (void)kill(server->pid, SIGKILL);
        (void)waitpid(server->pid, NULL, 0);
    }
    if (server->trace_fd >= 0) close(server->trace_fd);
    server->pid = -1;
    server->trace_fd = -1;
}

static int write_sidecar_bytes(const ssh_fixture_t *fixture,
                               const void *content, size_t content_len,
                               mode_t mode) {
    const unsigned char *cursor = content;
    size_t remaining = content_len;
    int fd;

    if (!fixture || (!content && content_len != 0U)) return -1;
    (void)unlinkat(fixture->dir_fd, "ssh-agent.work.pid", 0);
    fd = openat(fixture->dir_fd, "ssh-agent.work.pid",
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return -1;
    while (remaining > 0U) {
        ssize_t written = write(fd, cursor, remaining);
        if (written > 0) {
            cursor += (size_t)written;
            remaining -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        close(fd);
        return -1;
    }
    return close(fd);
}

static bool entry_exists(const char *path) {
    struct stat st;
    return path && lstat(path, &st) == 0;
}

#define TEST_ARTIFACT_DATA_MAX 512U

typedef struct {
    struct stat identity;
    unsigned char data[TEST_ARTIFACT_DATA_MAX];
    size_t data_len;
    bool has_data;
} artifact_snapshot_t;

static bool same_artifact_identity(const struct stat *before,
                                   const struct stat *after) {
    return before && after && before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           before->st_nlink == after->st_nlink &&
           before->st_rdev == after->st_rdev &&
           before->st_size == after->st_size;
}

static int capture_artifact_snapshot(const char *path,
                                     artifact_snapshot_t *snapshot) {
    ssize_t captured;

    if (!path || !snapshot || lstat(path, &snapshot->identity) != 0) {
        return -1;
    }
    snapshot->data_len = 0U;
    snapshot->has_data = false;
    if (S_ISLNK(snapshot->identity.st_mode)) {
        captured = readlink(path, (char *)snapshot->data,
                            sizeof(snapshot->data));
        if (captured < 0 || (size_t)captured >= sizeof(snapshot->data)) {
            return -1;
        }
        snapshot->data_len = (size_t)captured;
        snapshot->has_data = true;
        return 0;
    }
    if (S_ISREG(snapshot->identity.st_mode)) {
        int flags = O_RDONLY | O_CLOEXEC;
        int fd;
        unsigned char extra;

#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        fd = open(path, flags);
        if (fd < 0) return -1;
        while (snapshot->data_len < sizeof(snapshot->data)) {
            captured = read(fd, snapshot->data + snapshot->data_len,
                            sizeof(snapshot->data) - snapshot->data_len);
            if (captured > 0) {
                snapshot->data_len += (size_t)captured;
                continue;
            }
            if (captured < 0 && errno == EINTR) continue;
            if (captured < 0) {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
                return -1;
            }
            break;
        }
        do {
            captured = read(fd, &extra, 1U);
        } while (captured < 0 && errno == EINTR);
        if (close(fd) != 0 || captured != 0) return -1;
        snapshot->has_data = true;
    }
    return 0;
}

static bool artifact_matches_snapshot(const char *path,
                                      const artifact_snapshot_t *expected) {
    artifact_snapshot_t observed;

    return expected && capture_artifact_snapshot(path, &observed) == 0 &&
           same_artifact_identity(&expected->identity,
                                  &observed.identity) &&
           expected->has_data == observed.has_data &&
           expected->data_len == observed.data_len &&
           (!expected->has_data ||
            memcmp(expected->data, observed.data,
                   expected->data_len) == 0);
}

static bool reset_scratch_is_absent(int dir_fd) {
    static const char *const prefixes[] = {
        ".runtime.pin.",
        ".reset.cleanup.",
        ".current.sock.cleanup.",
        ".ssh-agent."
    };
    int flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *directory;
    struct dirent *entry;
    bool clean = true;

#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(dir_fd, ".", flags);
    if (scan_fd < 0) return false;
    directory = fdopendir(scan_fd);
    if (!directory) {
        close(scan_fd);
        return false;
    }
    for (;;) {
        size_t i;

        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) clean = false;
            break;
        }
        for (i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
            size_t prefix_len = strlen(prefixes[i]);
            if (strncmp(entry->d_name, prefixes[i], prefix_len) == 0) {
                clean = false;
                break;
            }
        }
        if (!clean) break;
    }
    if (closedir(directory) != 0) clean = false;
    return clean;
}

static int malformed_probe_indeterminate(const char *path,
                                         bool *reachable) {
    (void)path;
    if (!reachable) {
        errno = EINVAL;
        set_system_error(ERR_INVALID_ARGS,
                         "Injected malformed PID probe lacks output");
        return -1;
    }
    *reachable = false;
    errno = EIO;
    set_system_error(ERR_SSH_AGENT_FAILED,
                     "Injected malformed PID socket probe failure");
    return -1;
}

static int replace_unrecorded_socket_before_cleanup(int dir_fd,
                                                    const char *name) {
    g_race_hook_succeeded =
        unlinkat(dir_fd, name, 0) == 0 &&
        bind_stale_socket(g_race_socket) == 0;
    return g_race_hook_succeeded ? 0 : -1;
}

static int fail_retry_pid_sidecar_publication(int dir_fd,
                                              const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    errno = EIO;
    return -1;
}

static int fail_exact_pid_postrename_verification(int dir_fd,
                                                  const char *name) {
    (void)dir_fd;
    (void)name;
    errno = EIO;
    return -1;
}

static int g_exact_recovery_reap_calls;

static ssh_process_outcome_t exact_recovery_reap_must_not_run(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_exact_recovery_reap_calls++;
    return SSH_PROCESS_INDETERMINATE;
}

static int replace_reset_retirement_entry(int dir_fd, const char *name) {
    int fd;
    size_t content_len;
    ssize_t written;

    g_retire_hook_calls++;
    if (g_retire_hook_calls != g_retire_replace_on_call) return 0;
    g_retire_mutations++;
    if (safe_strncpy(g_retire_quarantine, name,
                     sizeof(g_retire_quarantine)) != 0 ||
        unlinkat(dir_fd, name, 0) != 0 || !g_retire_replacement) {
        return -1;
    }
    fd = openat(dir_fd, name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    content_len = strlen(g_retire_replacement);
    written = write(fd, g_retire_replacement, content_len);
    if (written < 0 || (size_t)written != content_len) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0) return -1;
    if (fstatat(dir_fd, name, &g_retire_replacement_identity,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    g_retire_replacement_captured = true;
    return 0;
}

static int fail_third_reset_dirsync(int dir_fd) {
    g_reset_dirsync_calls++;
    if (g_reset_dirsync_calls == 3) {
        errno = EIO;
        return -1;
    }
    return fsync(dir_fd);
}

static int fail_first_stop_dirsync(int dir_fd) {
    g_stop_dirsync_calls++;
    if (g_stop_dirsync_calls == 1) {
        errno = EIO;
        return -1;
    }
    return fsync(dir_fd);
}

static ssh_process_outcome_t swap_runtime_namespace_then_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    char replacement_socket[256];
    char replacement_sidecar[256];
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;

    g_race_hook_succeeded =
        rename(g_race_runtime, g_race_moved_runtime) == 0 &&
        mkdir(g_race_runtime, 0700) == 0 &&
        (size_t)snprintf(replacement_socket, sizeof(replacement_socket),
                         "%s/ssh-agent.work.sock", g_race_runtime) <
            sizeof(replacement_socket) &&
        (size_t)snprintf(replacement_sidecar, sizeof(replacement_sidecar),
                         "%s/ssh-agent.work.pid", g_race_runtime) <
            sizeof(replacement_sidecar) &&
        write_string_to_file(replacement_socket, "foreign socket\n", 0600) ==
            0 &&
        write_string_to_file(replacement_sidecar, "31337\n", 0600) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t replace_sidecar_then_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_race_hook_succeeded =
        unlink(g_race_sidecar) == 0 &&
        write_string_to_file(g_race_sidecar, "424242\n", 0600) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t replace_socket_then_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_race_hook_succeeded =
        unlink(g_race_socket) == 0 && bind_stale_socket(g_race_socket) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t remove_socket_then_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    g_race_hook_succeeded =
        unlinkat(runtime_dir_fd, "ssh-agent.work.sock", 0) == 0;
    return g_race_hook_succeeded ? SSH_PROCESS_GONE
                                 : SSH_PROCESS_INDETERMINATE;
}

static void cleanup_retained_fixture(const ssh_fixture_t *fixture) {
    ssh_reap_fn previous = ssh_manager_set_reap_fn(reap_gone);
    (void)setenv("XDG_RUNTIME_DIR", fixture->xdg, 1);
    (void)ssh_manager_reset("work");
    ssh_manager_set_reap_fn(previous);
}

static int pidfd_unavailable(pid_t pid) {
    (void)pid;
    errno = ENOSYS;
    return -1;
}

static int g_pidfd_open_errno = ENOSYS;

static int pidfd_open_configured_failure(pid_t pid) {
    (void)pid;
    errno = g_pidfd_open_errno;
    return -1;
}

static int pidfd_open_esrch(pid_t pid) {
    (void)pid;
    errno = ESRCH;
    return -1;
}

static int pidfd_signal_unused(int pidfd, int signal_number) {
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
}

static int g_signal_calls;
static int g_last_signal;

static int signal_must_not_run(pid_t pid, int signal_number) {
    (void)pid;
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = EACCES;
    return -1;
}

static int generation_matches_record(
    pid_t pid, ssh_process_generation_t *generation) {
    if (pid <= 1 || !generation) {
        errno = EINVAL;
        return -1;
    }
    *generation = g_test_generation;
    return 0;
}

static ssh_process_generation_t g_observed_generation;
static int g_generation_calls;
static int g_term_calls;
static int g_kill_calls;
static int g_presence_calls;
static int g_numeric_calls_after_term;
static bool g_replace_generation_after_term;
static bool g_die_during_generation;
static int g_pidfd_keepalive = -1;
static bool g_pidfd_open_saw_generation;
static int g_protocol_identity_calls;

static ssh_process_generation_t replacement_generation(void) {
    ssh_process_generation_t generation = g_test_generation;
    generation.start_lo++;
    return generation;
}

static int generation_from_fixture(
    pid_t pid, ssh_process_generation_t *generation) {
    if (pid != TEST_PID || !generation) {
        errno = EINVAL;
        return -1;
    }
    g_generation_calls++;
    *generation = g_observed_generation;
    if (g_term_calls > 0) g_numeric_calls_after_term++;
    if (g_die_during_generation && g_generation_calls == 2) {
        *generation = replacement_generation();
        if (g_pidfd_keepalive >= 0) {
            close(g_pidfd_keepalive);
            g_pidfd_keepalive = -1;
        }
    }
    return 0;
}

static int generation_inspection_fails(
    pid_t pid, ssh_process_generation_t *generation) {
    (void)pid;
    (void)generation;
    g_generation_calls++;
    errno = EIO;
    return -1;
}

static int generation_disappears_after_pidfd_open(
    pid_t pid, ssh_process_generation_t *generation) {
    if (pid != TEST_PID || !generation) {
        errno = EINVAL;
        return -1;
    }
    g_generation_calls++;
    if (g_generation_calls == 1) {
        *generation = g_test_generation;
        return 0;
    }
    errno = ESRCH;
    return -1;
}

static int numeric_presence_reports_gone(pid_t pid, int signal_number) {
    if (pid != TEST_PID || signal_number != 0) {
        errno = EINVAL;
        return -1;
    }
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = ESRCH;
    return -1;
}

static int record_generation_signal(pid_t pid, int signal_number) {
    if (pid != TEST_PID) {
        errno = ESRCH;
        return -1;
    }
    if (signal_number == 0) {
        g_presence_calls++;
        return 0;
    }
    if (signal_number == SIGTERM) {
        g_term_calls++;
        if (g_replace_generation_after_term) {
            g_observed_generation = replacement_generation();
        }
        return 0;
    }
    if (signal_number == SIGKILL) {
        g_kill_calls++;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static int record_generation_pidfd_signal(int pidfd, int signal_number) {
    (void)pidfd;
    return record_generation_signal(TEST_PID, signal_number);
}

static int pidfd_open_pipe(pid_t pid) {
    int fds[2];
    if (pid != TEST_PID || pipe(fds) != 0) return -1;
    g_pidfd_keepalive = fds[1];
    return fds[0];
}

static short g_pidfd_poll_failure_revents;

static int pidfd_poll_failure(int pidfd, int timeout_ms, short *revents) {
    (void)timeout_ms;
    if (pidfd < 0 || !revents) {
        errno = EINVAL;
        return -1;
    }
    *revents = g_pidfd_poll_failure_revents;
    return 1;
}

static int pidfd_pollerr_after_term(int pidfd, int timeout_ms,
                                    short *revents) {
    (void)timeout_ms;
    if (pidfd < 0 || !revents) {
        errno = EINVAL;
        return -1;
    }
    if (g_term_calls == 0) {
        *revents = 0;
        return 0;
    }
    *revents = POLLERR;
    return 1;
}

static int pidfd_open_flips_numeric_generation(pid_t pid) {
    if (pid != TEST_PID) {
        errno = ESRCH;
        return -1;
    }
    g_pidfd_open_saw_generation = g_generation_calls > 0;
    g_observed_generation = replacement_generation();
    return pidfd_open_pipe(pid);
}

static void reset_generation_harness(void) {
    g_observed_generation = g_test_generation;
    g_generation_calls = 0;
    g_signal_calls = 0;
    g_last_signal = -1;
    g_term_calls = 0;
    g_kill_calls = 0;
    g_presence_calls = 0;
    g_numeric_calls_after_term = 0;
    g_replace_generation_after_term = false;
    g_die_during_generation = false;
    g_pidfd_open_saw_generation = false;
    g_protocol_identity_calls = 0;
    if (g_pidfd_keepalive >= 0) {
        close(g_pidfd_keepalive);
        g_pidfd_keepalive = -1;
    }
}

static ssh_process_outcome_t identity_indeterminate(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t identity_indeterminate_once_then_owned(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_protocol_identity_calls++;
    return g_protocol_identity_calls == 1
               ? SSH_PROCESS_INDETERMINATE
               : SSH_PROCESS_OWNED;
}

static ssh_process_outcome_t identity_always_indeterminate_counted(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_protocol_identity_calls++;
    return SSH_PROCESS_INDETERMINATE;
}

static ssh_process_outcome_t identity_owned(const ssh_agent_record_t *record,
                                            const char *socket_arg,
                                            int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_OWNED;
}

static ssh_process_outcome_t identity_owned_counted(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    if (g_term_calls > 0) g_numeric_calls_after_term++;
    return identity_owned(record, socket_arg, runtime_dir_fd);
}

static ssh_process_outcome_t identity_reports_gone(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    return SSH_PROCESS_GONE;
}

typedef enum {
    MALFORMED_SOCKET_ABSENT = 0,
    MALFORMED_SOCKET_STALE,
    MALFORMED_SOCKET_LIVE,
    MALFORMED_SOCKET_INDETERMINATE
} malformed_socket_state_t;

typedef struct {
    const char *stem;
    const unsigned char *content;
    size_t content_len;
} malformed_sidecar_case_t;

static const unsigned char g_malformed_empty[] = "";
static const unsigned char g_malformed_text[] = "not-a-pid\n";
static const unsigned char g_malformed_embedded_nul[] =
    "1073741824\0trailing-data\n";
static const unsigned char g_malformed_oversized[] =
    "9999999999999999999999999999999999999999999999999999999999999999"
    "9999999999999999999999999999999999999999999999999999999999999999\n";
static const unsigned char g_malformed_version[] =
    "v2 1073741824 1 01020304050607081112131415161718 "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_missing_field[] =
    "v1 1073741824 1 01020304050607081112131415161718\n";
static const unsigned char g_malformed_extra_field[] =
    "v1 1073741824 1 01020304050607081112131415161718 "
    "00000000000000002122232425262728 extra\n";
static const unsigned char g_malformed_pid_overflow[] =
    "v1 9999999999999999999999999999999999999999 1 "
    "01020304050607081112131415161718 "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_kind_overflow[] =
    "v1 1073741824 18446744073709551616 "
    "01020304050607081112131415161718 "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_short_generation[] =
    "v1 1073741824 1 0102030405060708111213141516171 "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_long_generation[] =
    "v1 1073741824 1 010203040506070811121314151617180 "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_nonhex_generation[] =
    "v1 1073741824 1 0102030405060708111213141516171g "
    "00000000000000002122232425262728\n";
static const unsigned char g_malformed_record_embedded_nul[] =
    "v1 1073741824 1 01020304050607081112131415161718 "
    "00000000000000002122232425262728\0trailing\n";

static const malformed_sidecar_case_t g_malformed_sidecars[] = {
    {"gsar11pidempty", g_malformed_empty, 0U},
    {"gsar11pidtext", g_malformed_text, sizeof(g_malformed_text) - 1U},
    {"gsar11pidnul", g_malformed_embedded_nul,
     sizeof(g_malformed_embedded_nul) - 1U},
    {"gsar11pidlarge", g_malformed_oversized,
     sizeof(g_malformed_oversized) - 1U},
    {"gsar14pidversion", g_malformed_version,
     sizeof(g_malformed_version) - 1U},
    {"gsar14pidmissing", g_malformed_missing_field,
     sizeof(g_malformed_missing_field) - 1U},
    {"gsar14pidextra", g_malformed_extra_field,
     sizeof(g_malformed_extra_field) - 1U},
    {"gsar14pidoverflow", g_malformed_pid_overflow,
     sizeof(g_malformed_pid_overflow) - 1U},
    {"gsar14kindoverflow", g_malformed_kind_overflow,
     sizeof(g_malformed_kind_overflow) - 1U},
    {"gsar14genshort", g_malformed_short_generation,
     sizeof(g_malformed_short_generation) - 1U},
    {"gsar14genlong", g_malformed_long_generation,
     sizeof(g_malformed_long_generation) - 1U},
    {"gsar14gennonhex", g_malformed_nonhex_generation,
     sizeof(g_malformed_nonhex_generation) - 1U},
    {"gsar14recordnul", g_malformed_record_embedded_nul,
     sizeof(g_malformed_record_embedded_nul) - 1U}
};

static int g_malformed_reap_calls;

static ssh_process_outcome_t malformed_reap_must_not_run(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_malformed_reap_calls++;
    return SSH_PROCESS_INDETERMINATE;
}

static void exercise_malformed_sidecar_matrix(bool reset_all,
                                              malformed_socket_state_t state) {
    size_t case_count = sizeof(g_malformed_sidecars) /
                        sizeof(g_malformed_sidecars[0]);

    for (size_t i = 0; i < case_count; i++) {
        const malformed_sidecar_case_t *test_case = &g_malformed_sidecars[i];
        ssh_fixture_t fixture;
        ssh_reap_fn previous_reap;
        ssh_socket_probe_fn previous_probe = NULL;
        artifact_snapshot_t sidecar_before = {0};
        artifact_snapshot_t socket_before = {0};
        artifact_snapshot_t current_before = {0};
        bool retained_state = state == MALFORMED_SOCKET_LIVE ||
                              state == MALFORMED_SOCKET_INDETERMINATE;
        bool have_sidecar_snapshot;
        bool have_socket_snapshot;
        bool have_current_snapshot;
        int expected_fds;
        int listener = -1;

        CHECK_EQ_INT(make_fixture(&fixture, test_case->stem), 0);
        if (fixture.dir_fd < 0) continue;
        CHECK_EQ_INT(write_sidecar_bytes(&fixture, test_case->content,
                                         test_case->content_len, 0600), 0);
        if (state == MALFORMED_SOCKET_STALE ||
            state == MALFORMED_SOCKET_INDETERMINATE) {
            CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
        } else if (state == MALFORMED_SOCKET_LIVE) {
            listener = bind_live_socket(fixture.socket);
            CHECK(listener >= 0);
        }
        CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
        have_sidecar_snapshot =
            capture_artifact_snapshot(fixture.sidecar,
                                      &sidecar_before) == 0;
        have_socket_snapshot =
            state != MALFORMED_SOCKET_ABSENT &&
            capture_artifact_snapshot(fixture.socket,
                                      &socket_before) == 0;
        have_current_snapshot =
            capture_artifact_snapshot(fixture.current,
                                      &current_before) == 0;
        CHECK(have_sidecar_snapshot);
        CHECK(state == MALFORMED_SOCKET_ABSENT || have_socket_snapshot);
        CHECK(have_current_snapshot);
        expected_fds = test_open_fd_count();

        g_malformed_reap_calls = 0;
        previous_reap = ssh_manager_set_reap_fn(
            malformed_reap_must_not_run);
        if (state == MALFORMED_SOCKET_INDETERMINATE) {
            previous_probe = ssh_manager_set_socket_probe_fn(
                malformed_probe_indeterminate);
        }
        if (retained_state) {
            for (int attempt = 0; attempt < 2; attempt++) {
                clear_error();
                CHECK_EQ_INT(
                    ssh_manager_reset(reset_all ? NULL : "work"), -1);
                if (state == MALFORMED_SOCKET_INDETERMINATE) {
                    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
                }
                CHECK(!have_sidecar_snapshot ||
                      artifact_matches_snapshot(fixture.sidecar,
                                                &sidecar_before));
                CHECK(!have_socket_snapshot ||
                      artifact_matches_snapshot(fixture.socket,
                                                &socket_before));
                CHECK(!have_current_snapshot ||
                      artifact_matches_snapshot(fixture.current,
                                                &current_before));
                CHECK_EQ_INT(test_open_fd_count(), expected_fds);
                CHECK(reset_scratch_is_absent(fixture.dir_fd));
            }
            if (state == MALFORMED_SOCKET_INDETERMINATE) {
                ssh_manager_set_socket_probe_fn(previous_probe);
                previous_probe = NULL;
            }
            if (listener >= 0) {
                CHECK_EQ_INT(close(listener), 0);
                listener = -1;
                expected_fds--;
            }
        }

        CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), 0);
        CHECK(!entry_exists(fixture.sidecar));
        CHECK(!entry_exists(fixture.socket));
        CHECK(!entry_exists(fixture.current));
        CHECK_EQ_INT(test_open_fd_count(), expected_fds);
        CHECK(reset_scratch_is_absent(fixture.dir_fd));
        CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), 0);
        CHECK_EQ_INT(test_open_fd_count(), expected_fds);
        CHECK(reset_scratch_is_absent(fixture.dir_fd));
        CHECK_EQ_INT(g_malformed_reap_calls, 0);
        ssh_manager_set_reap_fn(previous_reap);

        if (listener >= 0) close(listener);
        close(fixture.dir_fd);
        ts_rm_rf(fixture.xdg);
    }
}

TEST(targeted_reset_cleans_malformed_sidecars_when_socket_is_absent) {
    exercise_malformed_sidecar_matrix(false, MALFORMED_SOCKET_ABSENT);
}

TEST(reset_all_cleans_malformed_sidecars_when_socket_is_absent) {
    exercise_malformed_sidecar_matrix(true, MALFORMED_SOCKET_ABSENT);
}

TEST(targeted_reset_cleans_malformed_sidecars_when_socket_is_stale) {
    exercise_malformed_sidecar_matrix(false, MALFORMED_SOCKET_STALE);
}

TEST(reset_all_cleans_malformed_sidecars_when_socket_is_stale) {
    exercise_malformed_sidecar_matrix(true, MALFORMED_SOCKET_STALE);
}

TEST(targeted_reset_retains_malformed_sidecars_while_socket_is_live) {
    exercise_malformed_sidecar_matrix(false, MALFORMED_SOCKET_LIVE);
}

TEST(reset_all_retains_malformed_sidecars_while_socket_is_live) {
    exercise_malformed_sidecar_matrix(true, MALFORMED_SOCKET_LIVE);
}

TEST(targeted_reset_retains_malformed_sidecars_when_probe_is_indeterminate) {
    exercise_malformed_sidecar_matrix(false,
                                      MALFORMED_SOCKET_INDETERMINATE);
}

TEST(reset_all_retains_malformed_sidecars_when_probe_is_indeterminate) {
    exercise_malformed_sidecar_matrix(true,
                                      MALFORMED_SOCKET_INDETERMINATE);
}

static void exercise_unsafe_sidecar_without_socket(bool reset_all) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t current_before = {0};
    bool have_sidecar_snapshot;
    bool have_current_snapshot;
    int expected_fds;

    CHECK_EQ_INT(make_fixture(&fixture,
                              reset_all ? "gsar11unsafeall"
                                        : "gsar11unsafetarget"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(write_sidecar_bytes(&fixture, g_malformed_text,
                                     sizeof(g_malformed_text) - 1U, 0600), 0);
    CHECK_EQ_INT(chmod(fixture.sidecar, 0666), 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    have_sidecar_snapshot =
        capture_artifact_snapshot(fixture.sidecar, &sidecar_before) == 0;
    have_current_snapshot =
        capture_artifact_snapshot(fixture.current, &current_before) == 0;
    CHECK(have_sidecar_snapshot);
    CHECK(have_current_snapshot);
    expected_fds = test_open_fd_count();

    g_malformed_reap_calls = 0;
    previous_reap = ssh_manager_set_reap_fn(malformed_reap_must_not_run);
    for (int attempt = 0; attempt < 2; attempt++) {
        CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
        CHECK(!have_sidecar_snapshot ||
              artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
        if (reset_all) {
            CHECK(!entry_exists(fixture.current));
        } else {
            CHECK(!have_current_snapshot ||
                  artifact_matches_snapshot(fixture.current,
                                            &current_before));
        }
        CHECK_EQ_INT(test_open_fd_count(), expected_fds);
        CHECK(reset_scratch_is_absent(fixture.dir_fd));
    }
    CHECK_EQ_INT(g_malformed_reap_calls, 0);
    ssh_manager_set_reap_fn(previous_reap);

    if (!reset_all) CHECK_EQ_INT(unlink(fixture.current), 0);
    CHECK_EQ_INT(unlink(fixture.sidecar), 0);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(targeted_reset_retains_unsafe_sidecar_without_socket) {
    exercise_unsafe_sidecar_without_socket(false);
}

TEST(reset_all_retains_unsafe_sidecar_without_socket) {
    exercise_unsafe_sidecar_without_socket(true);
}

TEST(indeterminate_identity_retains_retry_sidecar) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_indeterminate,
        .generation = generation_matches_record,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08id"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK(path_exists(fixture.sidecar));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

static int signal_permission_denied(pid_t pid, int signal_number) {
    (void)pid;
    g_signal_calls++;
    g_last_signal = signal_number;
    errno = EPERM;
    return -1;
}

TEST(permission_denied_presence_probe_is_indeterminate) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = NULL, /* production inspection begins with kill(pid, 0) */
        .generation = generation_matches_record,
        .signal = signal_permission_denied,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08perm"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_signal_calls, 1);
    CHECK_EQ_INT(g_last_signal, 0);
    CHECK(path_exists(fixture.sidecar));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static int pidfd_signal_permission_denied(int pidfd, int signal_number) {
    (void)pidfd;
    g_signal_calls++;
    g_last_signal = signal_number;
    if (signal_number == 0) return 0;
    errno = EPERM;
    return -1;
}

static int g_pidfd_term_attempts;

static int pidfd_signal_eintr_then_esrch(int pidfd, int signal_number) {
    (void)pidfd;
    if (signal_number == 0) return 0;
    if (signal_number != SIGTERM) {
        errno = EINVAL;
        return -1;
    }
    g_pidfd_term_attempts++;
    errno = g_pidfd_term_attempts == 1 ? EINTR : ESRCH;
    return -1;
}

TEST(failed_pidfd_signal_retains_retry_sidecar) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_matches_record,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = pidfd_signal_permission_denied
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08pidfd"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_signal_calls = 0;
    g_last_signal = -1;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }

    CHECK_EQ_INT(g_signal_calls, 7);
    CHECK_EQ_INT(g_last_signal, SIGTERM);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(interrupted_pidfd_term_retries_and_esrch_cleans) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_matches_record,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = pidfd_signal_eintr_then_esrch
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdeintr"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);

    reset_generation_harness();
    g_pidfd_term_attempts = 0;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_pidfd_term_attempts, 2);
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!entry_exists(fixture.socket));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

static void exercise_preterm_generation_mismatch(bool reset_all) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(
                     &fixture,
                     reset_all ? "gsar14genmismatchall"
                               : "gsar14genmismatch"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.current,
                                           &current_before), 0);

    reset_generation_harness();
    g_observed_generation = replacement_generation();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK(g_generation_calls > 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK_EQ_INT(g_presence_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));

    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(targeted_generation_mismatch_before_pidfd_preserves_retry_tuple) {
    exercise_preterm_generation_mismatch(false);
}

TEST(reset_all_generation_mismatch_before_pidfd_preserves_retry_tuple) {
    exercise_preterm_generation_mismatch(true);
}

TEST(generation_is_verified_before_pidfd_open_and_reverified_afterward) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_flips_numeric_generation,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14genpidfdopen"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK(g_pidfd_open_saw_generation);
    CHECK(g_generation_calls >= 2);
    CHECK_EQ_INT(g_presence_calls, 2);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(pidfd_death_during_numeric_inspection_discards_replacement_result) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14genpidfddeath"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);

    reset_generation_harness();
    g_die_during_generation = true;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 2);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(!path_exists(fixture.sidecar));
    CHECK(!path_exists(fixture.socket));
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(live_pidfd_rejects_contradictory_numeric_generation_gone) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_disappears_after_pidfd_open,
        .signal = numeric_presence_reports_gone,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdgencontradiction"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 2);
    CHECK_EQ_INT(g_signal_calls, 1);
    CHECK_EQ_INT(g_last_signal, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(live_pidfd_rejects_contradictory_numeric_identity_gone) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_reports_gone,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdidcontradiction"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 2);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static void exercise_pidfd_poll_failure_retains_retry_tuple(
    const char *fixture_stem, short failure_revents) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal,
        .pidfd_poll = pidfd_poll_failure
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, fixture_stem), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    g_pidfd_poll_failure_revents = failure_revents;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 1);
    CHECK_EQ_INT(g_presence_calls, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(pidfd_pollerr_dominates_hup_and_retains_retry_tuple) {
    exercise_pidfd_poll_failure_retains_retry_tuple(
        "gsar14pidfdpollerr", POLLERR | POLLHUP);
}

TEST(pidfd_pollnval_dominates_hup_and_retains_retry_tuple) {
    exercise_pidfd_poll_failure_retains_retry_tuple(
        "gsar14pidfdpollnval", POLLNVAL | POLLHUP);
}

TEST(pidfd_pollerr_after_term_retains_retry_tuple) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal,
        .pidfd_poll = pidfd_pollerr_after_term
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdwaitpollerr"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 3);
    CHECK_EQ_INT(g_presence_calls, 6);
    CHECK_EQ_INT(g_term_calls, 1);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static void exercise_pidfd_generation_change_after_term(void) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned_counted,
        .generation = generation_from_fixture,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14genaftertermpidfd"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    g_replace_generation_after_term = true;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }

    CHECK(g_generation_calls >= 2);
    CHECK_EQ_INT(g_term_calls, 1);
    CHECK_EQ_INT(g_kill_calls, 1);
    CHECK_EQ_INT(g_numeric_calls_after_term, 0);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));

    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(pidfd_escalation_never_returns_to_numeric_process_inspection) {
    exercise_pidfd_generation_change_after_term();
}

static void exercise_unsupported_pidfd_retains_exact_tuple(bool reset_all) {
    static const int unavailable_errnos[] = {
        ENOSYS,
        EINVAL,
        EOPNOTSUPP,
        EPERM
    };

    for (size_t i = 0;
         i < sizeof(unavailable_errnos) / sizeof(unavailable_errnos[0]);
         i++) {
        ssh_fixture_t fixture;
        artifact_snapshot_t sidecar_before = {0};
        artifact_snapshot_t socket_before = {0};
        artifact_snapshot_t current_before = {0};
        ssh_reap_test_ops_t ops = {
            .identity = identity_owned,
            .generation = generation_from_fixture,
            .signal = signal_must_not_run,
            .pidfd_open = pidfd_open_configured_failure,
            .pidfd_signal = pidfd_signal_unused
        };
        ssh_reap_test_ops_t previous;
        char stem[48];

        CHECK(snprintf(stem, sizeof(stem), "gsar14nopidfd%s%d",
                       reset_all ? "all" : "one",
                       unavailable_errnos[i]) > 0);
        CHECK_EQ_INT(make_fixture(&fixture, stem), 0);
        if (fixture.dir_fd < 0) continue;
        CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
        CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
        CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
        CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                               &sidecar_before), 0);
        CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                               &socket_before), 0);
        CHECK_EQ_INT(capture_artifact_snapshot(fixture.current,
                                               &current_before), 0);

        reset_generation_harness();
        g_pidfd_open_errno = unavailable_errnos[i];
        previous = ssh_manager_set_reap_test_ops(&ops);
        CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
        ssh_manager_set_reap_test_ops(&previous);

        CHECK_EQ_INT(g_generation_calls, 1);
        CHECK_EQ_INT(g_signal_calls, 0);
        CHECK_EQ_INT(g_term_calls, 0);
        CHECK_EQ_INT(g_kill_calls, 0);
        CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
        CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
        CHECK(artifact_matches_snapshot(fixture.current, &current_before));

        cleanup_retained_fixture(&fixture);
        close(fixture.dir_fd);
    }
}

TEST(targeted_reset_retains_exact_tuple_when_pidfd_is_unsupported) {
    exercise_unsupported_pidfd_retains_exact_tuple(false);
}

TEST(reset_all_retains_exact_tuple_when_pidfd_is_unsupported) {
    exercise_unsupported_pidfd_retains_exact_tuple(true);
}

static void exercise_sidecarless_live_agent_retention(bool reset_all) {
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    artifact_snapshot_t sibling_before = {0};
    unsigned char trace[8];
    char sibling[256];
    size_t trace_size;
    uint32_t identity_count = 0;

    CHECK_EQ_INT(make_fixture(
                     &fixture,
                     reset_all ? "gsar14sidecarlessall"
                               : "gsar14sidecarlessone"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(start_test_agent_server(
                     fixture.socket, TEST_AGENT_IDENTITIES_ONE, &server), 0);
    if (server.pid <= 1) {
        close(fixture.dir_fd);
        return;
    }
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.socket, &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.current, &current_before), 0);
    if (!reset_all) {
        CHECK(snprintf(sibling, sizeof(sibling),
                       "%s/unrelated-artifact", fixture.runtime) > 0);
        CHECK_EQ_INT(write_string_to_file(sibling, "keep\n", 0600), 0);
        CHECK_EQ_INT(capture_artifact_snapshot(
                         sibling, &sibling_before), 0);
    }

    CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
    trace_size = collect_test_agent_trace(
        &server, trace, sizeof(trace));

    CHECK_EQ_INT((int)trace_size, 0);
    CHECK_EQ_INT(kill(server.pid, 0), 0);
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));
    CHECK(strstr(get_last_error()->message,
                 "no safely matched PID") != NULL);
    CHECK_EQ_INT(query_test_agent_identity_count(
                     fixture.socket, &identity_count), 0);
    CHECK_EQ_INT((int)identity_count, 1);
    if (!reset_all) {
        CHECK(artifact_matches_snapshot(sibling, &sibling_before));
    }

    stop_test_agent_server(&server);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(sidecarless_targeted_retains_loaded_live_agent_and_exact_evidence) {
    exercise_sidecarless_live_agent_retention(false);
}

TEST(sidecarless_reset_all_retains_loaded_live_agent_and_exact_evidence) {
    exercise_sidecarless_live_agent_retention(true);
}

static void exercise_sidecarless_protocol_failure(
    const char *stem, test_agent_mode_t mode, bool reset_all) {
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    unsigned char trace[8];
    size_t trace_size;

    CHECK_EQ_INT(make_fixture(&fixture, stem), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(start_test_agent_server(fixture.socket, mode, &server), 0);
    if (server.pid <= 1) {
        close(fixture.dir_fd);
        return;
    }
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.socket, &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.current, &current_before), 0);

    CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
    trace_size = collect_test_agent_trace(
        &server, trace, sizeof(trace));

    CHECK_EQ_INT((int)trace_size, 0);
    CHECK_EQ_INT(kill(server.pid, 0), 0);
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));
    CHECK(!entry_exists(fixture.sidecar));

    stop_test_agent_server(&server);
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(sidecarless_wrong_protocol_type_retains_exact_artifacts) {
    exercise_sidecarless_protocol_failure(
        "gsar14agentwrong", TEST_AGENT_WRONG_TYPE, false);
}

TEST(sidecarless_malformed_identity_answer_retains_exact_artifacts) {
    exercise_sidecarless_protocol_failure(
        "gsar14agentmalformed", TEST_AGENT_MALFORMED_IDENTITIES, false);
}

TEST(sidecarless_truncated_protocol_frame_retains_exact_artifacts) {
    exercise_sidecarless_protocol_failure(
        "gsar14agenttruncated", TEST_AGENT_TRUNCATED, false);
}

TEST(sidecarless_oversized_protocol_frame_retains_exact_artifacts) {
    exercise_sidecarless_protocol_failure(
        "gsar14agentoversized", TEST_AGENT_OVERSIZED, true);
}

TEST(sidecarless_protocol_timeout_retains_exact_artifacts) {
    exercise_sidecarless_protocol_failure(
        "gsar14agenttimeout", TEST_AGENT_TIMEOUT, true);
}

static int publish_protocol_sidecar(
    const ssh_fixture_t *fixture, pid_t peer_pid,
    ssh_process_generation_kind_t kind, ssh_agent_record_t *published) {
    ssh_agent_record_t record = {
        .pid = TEST_PID,
        .generation = g_test_generation
    };

    record.generation.kind = kind;
    if (complete_synthetic_record_image(&record) != 0) return -1;
    record.image.socket_peer_pid = peer_pid;
    record.image.socket_peer_uid = geteuid();
    if (ssh_manager_test_write_pid_sidecar(
            fixture->dir_fd, "ssh-agent.work.pid", &record) != 0) {
        return -1;
    }
    if (published) *published = record;
    return 0;
}

static void exercise_recorded_protocol_retirement(
    const char *stem, ssh_process_generation_kind_t kind,
    test_agent_mode_t mode, bool reset_all, bool expect_success,
    bool peer_mismatch,
    const unsigned char *expected_trace, size_t expected_trace_size,
    ssh_process_identity_fn identity, int expected_identity_calls,
    const char *expected_error) {
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t current_before = {0};
    ssh_agent_record_t record;
    ssh_reap_test_ops_t ops = {
        .identity = identity ? identity : identity_owned,
        .generation = generation_from_fixture,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;
    unsigned char trace[8];
    size_t trace_size;
    int reset_rc;

    CHECK_EQ_INT(make_fixture(&fixture, stem), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(start_test_agent_server(fixture.socket, mode, &server), 0);
    if (server.pid <= 1) {
        close(fixture.dir_fd);
        return;
    }
    CHECK_EQ_INT(publish_protocol_sidecar(
                     &fixture, peer_mismatch ? server.pid + 1 : server.pid,
                     kind, &record), 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.socket, &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.sidecar, &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.current, &current_before), 0);

    reset_generation_harness();
    g_observed_generation = record.generation;
    previous = ssh_manager_set_reap_test_ops(&ops);
    clear_error();
    reset_rc = ssh_manager_reset(reset_all ? NULL : "work");
    ssh_manager_set_reap_test_ops(&previous);
    trace_size = collect_test_agent_trace(
        &server, trace, sizeof(trace));

    CHECK_EQ_INT(reset_rc, expect_success ? 0 : -1);
    CHECK_EQ_INT((int)trace_size, (int)expected_trace_size);
    CHECK(trace_size != expected_trace_size ||
          expected_trace_size == 0U ||
          memcmp(trace, expected_trace, expected_trace_size) == 0);
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    if (expected_identity_calls >= 0) {
        CHECK_EQ_INT(g_protocol_identity_calls, expected_identity_calls);
    }
    CHECK_EQ_INT(kill(server.pid, 0), 0);
    if (expected_error) {
        CHECK(strstr(get_last_error()->message, expected_error) != NULL);
    }
    if (expect_success) {
        CHECK(!entry_exists(fixture.socket));
        CHECK(!entry_exists(fixture.sidecar));
        CHECK(!entry_exists(fixture.current));
    } else {
        CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
        CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
        CHECK(artifact_matches_snapshot(fixture.current, &current_before));
    }

    stop_test_agent_server(&server);
    if (!expect_success) cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(recorded_darwin_and_freebsd_endpoints_clear_then_verify_without_signals) {
    static const unsigned char darwin_expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES,
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    static const unsigned char freebsd_expected[] = {
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    static const ssh_process_generation_kind_t kinds[] = {
        SSH_PROCESS_GENERATION_DARWIN,
        SSH_PROCESS_GENERATION_FREEBSD
    };

    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        exercise_recorded_protocol_retirement(
            i == 0 ? "gsar14darwinprotocol" : "gsar14freebsdprotocol",
            kinds[i], TEST_AGENT_CLEAR_EMPTY, i != 0, true,
            false,
            i == 0 ? darwin_expected : freebsd_expected,
            i == 0 ? sizeof(darwin_expected) : sizeof(freebsd_expected),
            NULL, -1, NULL);
    }
}

TEST(recorded_endpoint_retries_indeterminate_identity_once_then_retires) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES,
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    exercise_recorded_protocol_retirement(
        "gsar14identityretry", SSH_PROCESS_GENERATION_DARWIN,
        TEST_AGENT_CLEAR_EMPTY, false, true, false,
        expected, sizeof(expected),
        identity_indeterminate_once_then_owned, 3, NULL);
}

TEST(recorded_endpoint_indeterminate_identity_retains_exact_tuple_and_cause) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES
    };
    exercise_recorded_protocol_retirement(
        "gsar14identityindeterminate", SSH_PROCESS_GENERATION_DARWIN,
        TEST_AGENT_CLEAR_EMPTY, false, false, false,
        expected, sizeof(expected),
        identity_always_indeterminate_counted, 2,
        "process identity outcome INDETERMINATE");
}

TEST(recorded_endpoint_remove_failure_retains_exact_tuple) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES,
        TEST_AGENT_REMOVE_ALL_IDENTITIES
    };
    exercise_recorded_protocol_retirement(
        "gsar14removefail", SSH_PROCESS_GENERATION_DARWIN,
        TEST_AGENT_CLEAR_FAILURE, false, false, false,
        expected, sizeof(expected), NULL, -1, NULL);
}

TEST(recorded_endpoint_nonempty_verification_retains_exact_tuple) {
    static const unsigned char expected[] = {
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    exercise_recorded_protocol_retirement(
        "gsar14verifyfull", SSH_PROCESS_GENERATION_FREEBSD,
        TEST_AGENT_CLEAR_NONEMPTY, false, false, false,
        expected, sizeof(expected), NULL, -1, NULL);
}

TEST(recorded_darwin_preflight_failure_retains_exact_tuple_without_remove) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES
    };

    exercise_recorded_protocol_retirement(
        "gsar14preflightfail", SSH_PROCESS_GENERATION_DARWIN,
        TEST_AGENT_WRONG_TYPE, false, false, false,
        expected, sizeof(expected), NULL, 0,
        "preflight could not be authenticated");
}

TEST(recorded_darwin_preflight_peer_mismatch_retains_exact_tuple_without_remove) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES
    };

    exercise_recorded_protocol_retirement(
        "gsar14preflightpeer", SSH_PROCESS_GENERATION_DARWIN,
        TEST_AGENT_CLEAR_EMPTY, false, false, true,
        expected, sizeof(expected), NULL, 0,
        "socket peer mismatch");
}

static void configure_owned_protocol_agent(
    const ssh_fixture_t *fixture, const ssh_agent_record_t *record,
    ssh_config_t *config) {
    memset(config, 0, sizeof(*config));
    config->mode = SSH_AGENT_ISOLATED;
    config->agent_pid = record->pid;
    config->agent_generation = record->generation;
    config->agent_image = record->image;
    config->agent_owned = true;
    config->key_already_loaded = true;
    config->reused_existing_agent = true;
    CHECK_EQ_INT(safe_strncpy(
                     config->agent_socket_path, fixture->socket,
                     sizeof(config->agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(
                     config->agent_socket_arg, fixture->socket,
                     sizeof(config->agent_socket_arg)), 0);
}

TEST(stop_owned_bsd_endpoint_clears_then_detaches_without_signals) {
    static const unsigned char expected[] = {
        TEST_AGENT_REQUEST_IDENTITIES,
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    ssh_agent_record_t record;
    ssh_config_t config;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;
    unsigned char trace[8];
    size_t trace_size;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14stopbsd"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(start_test_agent_server(
                     fixture.socket, TEST_AGENT_CLEAR_EMPTY, &server), 0);
    if (server.pid <= 1) {
        close(fixture.dir_fd);
        return;
    }
    CHECK_EQ_INT(publish_protocol_sidecar(
                     &fixture, server.pid,
                     SSH_PROCESS_GENERATION_DARWIN, &record), 0);
    configure_owned_protocol_agent(&fixture, &record, &config);
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", fixture.socket, 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "1073741824", 1), 0);

    reset_generation_harness();
    g_observed_generation = record.generation;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_stop_agent(&config), 0);
    ssh_manager_set_reap_test_ops(&previous);
    trace_size = collect_test_agent_trace(
        &server, trace, sizeof(trace));

    CHECK_EQ_INT((int)trace_size, (int)sizeof(expected));
    CHECK(trace_size != sizeof(expected) ||
          memcmp(trace, expected, sizeof(expected)) == 0);
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK_EQ_INT(kill(server.pid, 0), 0);
    CHECK(!entry_exists(fixture.socket));
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!config.agent_owned);
    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK_EQ_INT((int)config.agent_generation.kind,
                 SSH_PROCESS_GENERATION_NONE);
    CHECK(!config.agent_image.valid);
    CHECK(!config.key_already_loaded);
    CHECK(!config.reused_existing_agent);
    CHECK(config.agent_socket_path[0] == '\0');
    CHECK(config.agent_socket_arg[0] == '\0');
    CHECK(getenv("SSH_AUTH_SOCK") == NULL);
    CHECK(getenv("SSH_AGENT_PID") == NULL);

    stop_test_agent_server(&server);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(stop_owned_bsd_endpoint_cleanup_failure_preserves_observable_retry_state) {
    static const unsigned char expected[] = {
        TEST_AGENT_REMOVE_ALL_IDENTITIES,
        TEST_AGENT_REQUEST_IDENTITIES
    };
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    ssh_agent_record_t record;
    ssh_config_t config;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous_reap;
    ssh_dirsync_fn previous_dirsync;
    unsigned char trace[8];
    size_t trace_size;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14stopbsdfail"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(start_test_agent_server(
                     fixture.socket, TEST_AGENT_CLEAR_EMPTY, &server), 0);
    if (server.pid <= 1) {
        close(fixture.dir_fd);
        return;
    }
    CHECK_EQ_INT(publish_protocol_sidecar(
                     &fixture, server.pid,
                     SSH_PROCESS_GENERATION_FREEBSD, &record), 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.socket, &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(
                     fixture.current, &current_before), 0);
    configure_owned_protocol_agent(&fixture, &record, &config);
    CHECK_EQ_INT(setenv("SSH_AUTH_SOCK", fixture.socket, 1), 0);
    CHECK_EQ_INT(setenv("SSH_AGENT_PID", "1073741824", 1), 0);

    reset_generation_harness();
    g_observed_generation = record.generation;
    g_stop_dirsync_calls = 0;
    previous_reap = ssh_manager_set_reap_test_ops(&ops);
    previous_dirsync = ssh_manager_set_dirsync_fn(fail_first_stop_dirsync);
    CHECK_EQ_INT(ssh_stop_agent(&config), -1);
    ssh_manager_set_dirsync_fn(previous_dirsync);
    ssh_manager_set_reap_test_ops(&previous_reap);
    trace_size = collect_test_agent_trace(
        &server, trace, sizeof(trace));

    CHECK_EQ_INT((int)trace_size, (int)sizeof(expected));
    CHECK(trace_size != sizeof(expected) ||
          memcmp(trace, expected, sizeof(expected)) == 0);
    /* Darwin pins filesystem sockets with a private hard link because it has
     * no O_PATH equivalent. The injected sidecar-unlink sync fails first;
     * releasing that pin then performs its own successful directory sync.
     * Descriptor-pin platforms have no namespace entry to retire. */
#ifdef __APPLE__
    CHECK_EQ_INT(g_stop_dirsync_calls, 2);
#else
    CHECK_EQ_INT(g_stop_dirsync_calls, 1);
#endif
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK_EQ_INT(kill(server.pid, 0), 0);
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));
    CHECK(config.agent_owned);
    CHECK_EQ_INT(config.agent_pid, record.pid);
    CHECK(config.agent_generation.kind == record.generation.kind);
    CHECK(config.agent_image.valid);
    CHECK(!config.key_already_loaded);
    CHECK(config.reused_existing_agent);
    CHECK_STR_EQ(config.agent_socket_path, fixture.socket);
    CHECK_STR_EQ(config.agent_socket_arg, fixture.socket);
    CHECK_STR_EQ(getenv("SSH_AUTH_SOCK"), fixture.socket);
    CHECK_STR_EQ(getenv("SSH_AGENT_PID"), "1073741824");

    (void)unsetenv("SSH_AUTH_SOCK");
    (void)unsetenv("SSH_AGENT_PID");
    stop_test_agent_server(&server);
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(linux_pidfd_unavailable_never_uses_agent_protocol) {
    exercise_recorded_protocol_retirement(
        "gsar14linuxnoprotocol", SSH_PROCESS_GENERATION_LINUX,
        TEST_AGENT_CLEAR_EMPTY, false, false, false,
        NULL, 0, NULL, -1, NULL);
}

TEST(pidfd_open_esrch_cleans_exact_tuple_without_numeric_termination) {
    ssh_fixture_t fixture;
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_from_fixture,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_esrch,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdesrch"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK_EQ_INT(g_generation_calls, 1);
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!entry_exists(fixture.socket));
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(generation_inspection_error_never_terminates_or_consumes_tuple) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_inspection_fails,
        .signal = record_generation_signal,
        .pidfd_open = pidfd_unavailable,
        .pidfd_signal = pidfd_signal_unused
    };
    ssh_reap_test_ops_t previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14generror"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    reset_generation_harness();
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_test_ops(&previous);

    CHECK(g_generation_calls > 0);
    CHECK_EQ_INT(g_term_calls, 0);
    CHECK_EQ_INT(g_kill_calls, 0);
    CHECK_EQ_INT(g_presence_calls, 1);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

/* AR-15 H2: after an in-place upgrade from a release that wrote bare-PID
 * sidecars, a legacy record names a still-running managed agent. The reachable
 * socket used to make retirement impossible, permanently locking switch and
 * reset. The fix reconstructs a record from the kernel socket peer and runs the
 * standard reap; when it proves OWNED and terminates the agent, the socket goes
 * dead and reset converges with no manual kill. reap_gone models that proven
 * termination by stopping the live agent server exactly when the migration
 * reaps. With the migration reverted, the still-live socket keeps reset at -1,
 * so this test fails closed on the old behavior. */
TEST(legacy_live_owned_sidecar_is_migrated_and_reset_converges) {
    static const char legacy[] = "1073741824\n";
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    ssh_reap_fn previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar15legacymig"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(write_sidecar_bytes(&fixture, legacy,
                                     sizeof(legacy) - 1U, 0600), 0);
    CHECK_EQ_INT(start_test_agent_server(
                     fixture.socket, TEST_AGENT_IDENTITIES_ONE, &server), 0);
    g_runner_server_pid = server.pid;
    g_runner_server_trace_fd = server.trace_fd;

    previous = ssh_manager_set_reap_fn(reap_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous);
    stop_runner_server();

    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!entry_exists(fixture.socket));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

/* Safety complement: a legacy record whose live socket peer cannot be proven to
 * be our agent (the reap returns a non-cleanup outcome) must NOT be signaled,
 * and the reachable socket must keep reset fail-closed. */
TEST(legacy_live_unprovable_sidecar_stays_fail_closed) {
    static const char legacy[] = "1073741824\n";
    ssh_fixture_t fixture;
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    ssh_reap_fn previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar15legacyfc"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(write_sidecar_bytes(&fixture, legacy,
                                     sizeof(legacy) - 1U, 0600), 0);
    CHECK_EQ_INT(start_test_agent_server(
                     fixture.socket, TEST_AGENT_IDENTITIES_ONE, &server), 0);
    g_runner_server_pid = server.pid;
    g_runner_server_trace_fd = server.trace_fd;

    previous = ssh_manager_set_reap_fn(reap_replaced);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);
    stop_runner_server();

    CHECK(entry_exists(fixture.sidecar));
    CHECK(entry_exists(fixture.socket));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

TEST(legacy_dead_sidecar_is_cleaned_without_reap) {
    static const char legacy[] = "1073741824\n";
    ssh_fixture_t fixture;
    ssh_reap_fn previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14legacydead"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(write_sidecar_bytes(&fixture, legacy,
                                     sizeof(legacy) - 1U, 0600), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    g_malformed_reap_calls = 0;
    previous = ssh_manager_set_reap_fn(malformed_reap_must_not_run);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous);

    CHECK_EQ_INT(g_malformed_reap_calls, 0);
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!entry_exists(fixture.socket));
    close(fixture.dir_fd);
}

TEST(stopped_session_preserves_same_pid_replacement_generation) {
    ssh_fixture_t fixture;
    ssh_config_t config;
    ssh_agent_record_t replacement = {
        .pid = TEST_PID,
        .generation = {
            .kind = SSH_PROCESS_GENERATION_LINUX,
            .boot_hi = UINT64_C(0x0102030405060708),
            .boot_lo = UINT64_C(0x1112131415161718),
            .start_hi = 0,
            .start_lo = UINT64_C(0x2122232425262729)
        }
    };
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    ssh_reap_fn previous;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14stopreplacement"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(complete_synthetic_record_image(&replacement), 0);
    CHECK_EQ_INT(ssh_manager_test_write_pid_sidecar(
                     fixture.dir_fd, "ssh-agent.work.pid",
                     &replacement), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.current,
                                           &current_before), 0);

    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = TEST_PID;
    config.agent_generation = g_test_generation;
    config.agent_owned = true;
    CHECK_EQ_INT(safe_strncpy(config.agent_socket_path, fixture.socket,
                              sizeof(config.agent_socket_path)), 0);
    CHECK_EQ_INT(safe_strncpy(config.agent_socket_arg, fixture.socket,
                              sizeof(config.agent_socket_arg)), 0);

    g_malformed_reap_calls = 0;
    previous = ssh_manager_set_reap_fn(malformed_reap_must_not_run);
    CHECK_EQ_INT(ssh_stop_agent(&config), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK_EQ_INT(g_malformed_reap_calls, 0);
    CHECK(config.agent_owned);
    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));
    cleanup_retained_fixture(&fixture);
    if (entry_exists(fixture.current)) CHECK_EQ_INT(unlink(fixture.current), 0);
    close(fixture.dir_fd);
}

static void exercise_stale_process_outcome_with_live_replacement(
    ssh_process_outcome_t outcome, bool reset_all) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    artifact_snapshot_t current_before = {0};
    ssh_reap_fn previous;
    int listener;

    CHECK_EQ_INT(make_fixture(
                     &fixture,
                     outcome == SSH_PROCESS_GONE
                         ? "gsar14gonelivesocket"
                         : "gsar14unrelatedlivesocket"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    listener = bind_live_socket(fixture.socket);
    CHECK(listener >= 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.current,
                                           &current_before), 0);

    previous = ssh_manager_set_reap_fn(
        outcome == SSH_PROCESS_GONE ? reap_gone : reap_unrelated);
    CHECK_EQ_INT(ssh_manager_reset(reset_all ? NULL : "work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    CHECK(artifact_matches_snapshot(fixture.current, &current_before));

    if (listener >= 0) CHECK_EQ_INT(close(listener), 0);
    cleanup_retained_fixture(&fixture);
    if (entry_exists(fixture.current)) CHECK_EQ_INT(unlink(fixture.current), 0);
    close(fixture.dir_fd);
}

TEST(gone_record_with_live_replacement_preserves_complete_tuple) {
    exercise_stale_process_outcome_with_live_replacement(
        SSH_PROCESS_GONE, false);
}

TEST(unrelated_record_with_live_replacement_preserves_complete_tuple) {
    exercise_stale_process_outcome_with_live_replacement(
        SSH_PROCESS_UNRELATED, true);
}

TEST(real_kernel_esrch_consumes_stale_sidecar) {
    ssh_fixture_t fixture;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08esrch"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(runtime_namespace_replacement_fails_without_mutating_either_tree) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char moved_socket[256];
    char moved_sidecar[256];
    char content[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08namespace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_runtime, fixture.runtime,
                              sizeof(g_race_runtime)), 0);
    CHECK_EQ_INT(safe_snprintf(g_race_moved_runtime,
                               sizeof(g_race_moved_runtime), "%s.pinned",
                               fixture.runtime), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(swap_runtime_namespace_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(safe_snprintf(moved_socket, sizeof(moved_socket),
                               "%s/ssh-agent.work.sock",
                               g_race_moved_runtime), 0);
    CHECK_EQ_INT(safe_snprintf(moved_sidecar, sizeof(moved_sidecar),
                               "%s/ssh-agent.work.pid",
                               g_race_moved_runtime), 0);
    CHECK(path_exists(moved_socket));
    CHECK(path_exists(moved_sidecar));
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.socket, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "foreign socket\n");
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "31337\n");
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(sidecar_replacement_before_cleanup_is_restored_and_retained) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08pidrace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_sidecar, fixture.sidecar,
                              sizeof(g_race_sidecar)), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(replace_sidecar_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "424242\n");
    CHECK(strstr(get_last_error()->message, "retained state for retry") !=
          NULL);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(socket_replacement_before_cleanup_survives_with_stable_link) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char current[256];
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08sockrace"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_snprintf(current, sizeof(current), "%s/current.sock",
                               fixture.runtime), 0);
    CHECK_EQ_INT(symlink(fixture.socket, current), 0);
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(replace_socket_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK(path_exists(current));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message, "retained state for retry") !=
          NULL);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(reaped_agent_socket_self_removal_is_idempotent) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous;
    char current[256];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08selfunlink"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(safe_snprintf(current, sizeof(current), "%s/current.sock",
                               fixture.runtime), 0);
    CHECK_EQ_INT(symlink(fixture.socket, current), 0);
    g_race_hook_succeeded = false;
    previous = ssh_manager_set_reap_fn(remove_socket_then_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous);

    CHECK(g_race_hook_succeeded);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(!path_exists(current));
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

static void check_malformed_quarantine_substitution_is_preserved(
    bool force_portable) {
    static const char replacement_bytes[] =
        "foreign malformed-retirement replacement\n";
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    ssh_quarantine_hook_fn previous_retire;
    bool previous_portable;
    artifact_snapshot_t current_before = {0};
    artifact_snapshot_t public_replacement = {0};
    bool have_current_snapshot;
    bool have_public_replacement;
    int expected_fds;

    CHECK_EQ_INT(make_fixture(
                     &fixture, force_portable ? "gsar11malport"
                                              : "gsar11malnative"),
                 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(write_sidecar_bytes(&fixture, g_malformed_text,
                                     sizeof(g_malformed_text) - 1U, 0600),
                 0);
    CHECK_EQ_INT(symlink(fixture.socket, fixture.current), 0);
    have_current_snapshot =
        capture_artifact_snapshot(fixture.current, &current_before) == 0;
    CHECK(have_current_snapshot);
    expected_fds = test_open_fd_count();

    g_retire_quarantine[0] = '\0';
    g_retire_replacement = replacement_bytes;
    g_retire_hook_calls = 0;
    g_retire_mutations = 0;
    g_retire_replace_on_call = 1;
    g_retire_replacement_captured = false;
    memset(&g_retire_replacement_identity, 0,
           sizeof(g_retire_replacement_identity));
    g_malformed_reap_calls = 0;
    previous_portable =
        ssh_manager_set_force_portable_quarantine(force_portable);
    previous_reap = ssh_manager_set_reap_fn(
        malformed_reap_must_not_run);
    previous_retire = ssh_manager_set_reset_retire_hook_fn(
        replace_reset_retirement_entry);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reset_retire_hook_fn(previous_retire);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    have_public_replacement =
        capture_artifact_snapshot(fixture.sidecar,
                                  &public_replacement) == 0;
    CHECK(g_retire_hook_calls >= (force_portable ? 2 : 1));
    CHECK_EQ_INT(g_retire_mutations, 1);
    CHECK(g_retire_replacement_captured);
    CHECK(have_public_replacement);
    CHECK(!have_public_replacement ||
          same_artifact_identity(&g_retire_replacement_identity,
                                 &public_replacement.identity));
    CHECK(!have_public_replacement || public_replacement.has_data);
    CHECK(!have_public_replacement ||
          public_replacement.data_len == sizeof(replacement_bytes) - 1U);
    CHECK(!have_public_replacement ||
          memcmp(public_replacement.data, replacement_bytes,
                 sizeof(replacement_bytes) - 1U) == 0);
    CHECK(!have_public_replacement ||
          (public_replacement.identity.st_mode & 0777) == 0600);
    CHECK(!have_current_snapshot ||
          artifact_matches_snapshot(fixture.current, &current_before));
    CHECK(!entry_exists(fixture.socket));
    CHECK_EQ_INT(g_malformed_reap_calls, 0);
    CHECK_EQ_INT(test_open_fd_count(), expected_fds);
    CHECK(reset_scratch_is_absent(fixture.dir_fd));

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK(!entry_exists(fixture.sidecar));
    CHECK(!entry_exists(fixture.current));
    CHECK_EQ_INT(test_open_fd_count(), expected_fds);
    CHECK(reset_scratch_is_absent(fixture.dir_fd));
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK_EQ_INT(test_open_fd_count(), expected_fds);
    CHECK(reset_scratch_is_absent(fixture.dir_fd));

    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST(malformed_quarantine_substitution_is_preserved) {
    check_malformed_quarantine_substitution_is_preserved(false);
}

TEST(portable_malformed_quarantine_substitution_is_preserved) {
    check_malformed_quarantine_substitution_is_preserved(true);
}

static void check_final_quarantine_substitution_is_not_deleted(
    bool force_portable) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    ssh_quarantine_hook_fn previous_retire;
    bool previous_portable;
    char content[64];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08retire"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_retire_quarantine[0] = '\0';
    g_retire_replacement = "foreign final-delete replacement\n";
    g_retire_hook_calls = 0;
    g_retire_mutations = 0;
    g_retire_replace_on_call = 1;
    previous_portable =
        ssh_manager_set_force_portable_quarantine(force_portable);
    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    previous_retire = ssh_manager_set_reset_retire_hook_fn(
        replace_reset_retirement_entry);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_reset_retire_hook_fn(previous_retire);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    CHECK(g_retire_hook_calls >= (force_portable ? 2 : 1));
    CHECK_EQ_INT(g_retire_mutations, 1);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content, "foreign final-delete replacement\n");
    close(fixture.dir_fd);
}

TEST(final_quarantine_substitution_is_not_deleted) {
    check_final_quarantine_substitution_is_not_deleted(false);
}

TEST(portable_final_quarantine_substitution_is_not_deleted) {
    check_final_quarantine_substitution_is_not_deleted(true);
}

TEST(portable_restore_retirement_substitution_is_preserved) {
    ssh_fixture_t fixture;
    ssh_reap_fn previous_reap;
    ssh_quarantine_hook_fn previous_retire;
    ssh_dirsync_fn previous_dirsync;
    bool previous_portable;
    char quarantine_path[320];
    char content[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08restore"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_retire_quarantine[0] = '\0';
    g_retire_replacement = "foreign restoration-retirement replacement\n";
    g_retire_hook_calls = 0;
    g_retire_mutations = 0;
    g_retire_replace_on_call = 1;
    g_reset_dirsync_calls = 0;
    previous_portable = ssh_manager_set_force_portable_quarantine(true);
    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    previous_retire = ssh_manager_set_reset_retire_hook_fn(
        replace_reset_retirement_entry);
    previous_dirsync = ssh_manager_set_dirsync_fn(fail_third_reset_dirsync);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    ssh_manager_set_dirsync_fn(previous_dirsync);
    ssh_manager_set_reset_retire_hook_fn(previous_retire);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    CHECK(g_reset_dirsync_calls >= 4);
    CHECK_EQ_INT(g_retire_hook_calls, 1);
    CHECK_EQ_INT(g_retire_mutations, 1);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, content, sizeof(content)) > 0);
    CHECK(is_v2_test_record(content));
    CHECK_EQ_INT(safe_snprintf(quarantine_path, sizeof(quarantine_path),
                               "%s/%s", fixture.runtime,
                               g_retire_quarantine), 0);
    CHECK(path_exists(quarantine_path));
    CHECK(read_file_to_string(quarantine_path, content, sizeof(content)) > 0);
    CHECK_STR_EQ(content,
                 "foreign restoration-retirement replacement\n");
    close(fixture.dir_fd);
}

TEST(unrelated_live_pid_is_not_signaled) {
    ssh_fixture_t fixture;
    char legacy_pid[64];
    pid_t child;
    int status = 0;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08other"), 0);
    if (fixture.dir_fd < 0) return;
    child = fork();
    CHECK(child >= 0);
    if (child < 0) {
        close(fixture.dir_fd);
        return;
    }
    if (child == 0) {
        for (;;) pause();
    }

    CHECK(snprintf(legacy_pid, sizeof(legacy_pid), "%ld\n",
                   (long)child) > 0);
    CHECK_EQ_INT(write_sidecar_bytes(
                     &fixture, legacy_pid, strlen(legacy_pid), 0600), 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    CHECK_EQ_INT(kill(child, 0), 0);
    CHECK(!path_exists(fixture.sidecar));

    (void)kill(child, SIGKILL);
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    CHECK(WIFSIGNALED(status));
    close(fixture.dir_fd);
}

static volatile sig_atomic_t g_alarm_count;

static void record_alarm(int signal_number) {
    (void)signal_number;
    g_alarm_count++;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

TEST(signal_storm_preserves_pidfd_term_and_kill_deadlines) {
    ssh_fixture_t fixture;
    artifact_snapshot_t sidecar_before = {0};
    artifact_snapshot_t socket_before = {0};
    ssh_reap_test_ops_t ops = {
        .identity = identity_owned,
        .generation = generation_matches_record,
        .signal = signal_must_not_run,
        .pidfd_open = pidfd_open_pipe,
        .pidfd_signal = record_generation_pidfd_signal
    };
    ssh_reap_test_ops_t previous;
    struct sigaction action;
    struct sigaction old_action;
    struct itimerval timer;
    struct itimerval old_timer;
    struct itimerval disabled;
    int64_t started;
    int64_t elapsed;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14pidfdstorm"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.sidecar,
                                           &sidecar_before), 0);
    CHECK_EQ_INT(capture_artifact_snapshot(fixture.socket,
                                           &socket_before), 0);

    memset(&action, 0, sizeof(action));
    action.sa_handler = record_alarm;
    CHECK_EQ_INT(sigemptyset(&action.sa_mask), 0);
    CHECK_EQ_INT(sigaction(SIGALRM, &action, &old_action), 0);
    CHECK_EQ_INT(getitimer(ITIMER_REAL, &old_timer), 0);
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
    reset_generation_harness();
    g_alarm_count = 0;
    previous = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &timer, NULL), 0);
    started = monotonic_ms();
    CHECK(started >= 0);
    CHECK_EQ_INT(ssh_manager_reset("work"), -1);
    elapsed = monotonic_ms() - started;
    memset(&disabled, 0, sizeof(disabled));
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &disabled, NULL), 0);
    ssh_manager_set_reap_test_ops(&previous);
    CHECK_EQ_INT(sigaction(SIGALRM, &old_action, NULL), 0);
    CHECK_EQ_INT(setitimer(ITIMER_REAL, &old_timer, NULL), 0);

    CHECK(g_alarm_count > 100);
    CHECK_EQ_INT(g_signal_calls, 0);
    CHECK_EQ_INT(g_term_calls, 1);
    CHECK_EQ_INT(g_kill_calls, 1);
    CHECK(elapsed >= 900);
    CHECK(elapsed <= 3000);
    CHECK(artifact_matches_snapshot(fixture.sidecar, &sidecar_before));
    CHECK(artifact_matches_snapshot(fixture.socket, &socket_before));
    if (g_pidfd_keepalive >= 0) {
        CHECK_EQ_INT(close(g_pidfd_keepalive), 0);
        g_pidfd_keepalive = -1;
    }
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
}

static void stop_process(pid_t pid) {
    struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 10000000L};

    if (pid <= 1) return;
    if (kill(pid, 0) != 0) return;
    (void)kill(pid, SIGTERM);
    for (int attempts = 0; attempts < 50 && kill(pid, 0) == 0; attempts++) {
        (void)nanosleep(&pause_time, NULL);
    }
    if (kill(pid, 0) == 0) (void)kill(pid, SIGKILL);
}

#ifdef __linux__
static int wait_process_absent(pid_t pid) {
    struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 10000000L};

    for (int attempts = 0; attempts < 100; attempts++) {
        if (kill(pid, 0) != 0) return errno == ESRCH ? 0 : -1;
        (void)nanosleep(&pause_time, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}
#endif

TEST(runtime_root_provenance_prevents_cross_root_reap) {
    ssh_fixture_t first;
    ssh_fixture_t second;
    struct stat runtime_identity;
    char marker[80];
    char socket_arg[160];
    char output[2048];
    const char *argv[6];
    run_opts_t opts;
    run_result_t result;
    char *pid_text;
    pid_t pid = -1;
    int marker_created = 0;

    if (!command_exists("ssh-agent")) {
        TS_SKIP("openssh", "ssh-agent unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_fixture(&first, "gsar08roota"), 0);
    CHECK_EQ_INT(make_fixture(&second, "gsar08rootb"), 0);
    if (first.dir_fd < 0 || second.dir_fd < 0) return;
    CHECK_EQ_INT(fstat(first.dir_fd, &runtime_identity), 0);
    CHECK((size_t)snprintf(marker, sizeof(marker), ".gsp-%jx-%jx",
                           (uintmax_t)runtime_identity.st_dev,
                           (uintmax_t)runtime_identity.st_ino) <
          sizeof(marker));
    CHECK((size_t)snprintf(socket_arg, sizeof(socket_arg),
                           "%s/../ssh-agent.work.sock", marker) <
          sizeof(socket_arg));
    if (mkdirat(first.dir_fd, marker, 0700) == 0) marker_created = 1;
    CHECK(marker_created);
    if (!marker_created) {
        close(first.dir_fd);
        close(second.dir_fd);
        return;
    }

    argv[0] = "ssh-agent";
    argv[1] = "-s";
    argv[2] = "-a";
    argv[3] = socket_arg;
    argv[4] = NULL;
    argv[5] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    opts.cwd_fd = first.dir_fd;
    opts.use_cwd_fd = true;
    CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    CHECK_EQ_INT(unlinkat(first.dir_fd, marker, AT_REMOVEDIR), 0);
    marker_created = 0;
    pid_text = strstr(output, "SSH_AGENT_PID=");
    CHECK(pid_text != NULL);
    if (pid_text) {
        pid = (pid_t)strtol(pid_text + strlen("SSH_AGENT_PID="), NULL, 10);
    }
    CHECK(pid > 1);
    CHECK(path_exists(first.socket));

    if (pid > 1) {
        char legacy_pid[64];
        CHECK(snprintf(legacy_pid, sizeof(legacy_pid), "%ld\n",
                       (long)pid) > 0);
        CHECK_EQ_INT(write_sidecar_bytes(
                         &second, legacy_pid, strlen(legacy_pid), 0600), 0);
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", second.xdg, 1), 0);
        CHECK_EQ_INT(ssh_manager_reset("work"), 0);
        CHECK_EQ_INT(kill(pid, 0), 0);
        CHECK(!path_exists(second.sidecar));

        CHECK_EQ_INT(publish_sidecar_for_process(&first, pid), 0);
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", first.xdg, 1), 0);
        CHECK_EQ_INT(ssh_manager_reset("work"), 0);
#ifdef __linux__
        CHECK_EQ_INT(wait_process_absent(pid), 0);
#else
        CHECK_EQ_INT(kill(pid, 0), 0);
#endif
        CHECK(!path_exists(first.sidecar));
        CHECK(!path_exists(first.socket));
    }

    if (marker_created) (void)unlinkat(first.dir_fd, marker, AT_REMOVEDIR);
    stop_process(pid);
    close(first.dir_fd);
    close(second.dir_fd);
}

static const char *runner_socket_arg(const char *const argv[]) {
    for (size_t index = 1; argv && argv[index]; index++) {
        if (strcmp(argv[index], "-a") == 0 && argv[index + 1]) {
            return argv[index + 1];
        }
    }
    return NULL;
}

static int bind_runner_socket(const char *path, mode_t mode,
                              const run_opts_t *opts) {
    test_agent_server_t server = {.pid = -1, .trace_fd = -1};
    int saved_cwd = -1;
    int rc = -1;

    if (!path ||
        strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return -1;
    }
    if (opts && opts->use_cwd_fd) {
        saved_cwd = open(".", O_RDONLY | O_CLOEXEC);
        if (saved_cwd < 0 || fchdir(opts->cwd_fd) != 0) goto done;
    }
    stop_runner_server();
    if (start_test_agent_server(
            path, TEST_AGENT_IDENTITIES_ONE, &server) != 0) {
        goto done;
    }
    g_runner_server_pid = server.pid;
    g_runner_server_trace_fd = server.trace_fd;
    if (chmod(path, mode) != 0) {
        stop_runner_server();
        goto done;
    }
    rc = 0;

done:
    if (saved_cwd >= 0) {
        if (fchdir(saved_cwd) != 0) rc = -1;
        close(saved_cwd);
    }
    return rc;
}

static void make_runner_socket_stale(void) {
    stop_runner_server();
}

static bool is_key_fingerprint_command(const char *const argv[]) {
    return argv && argv[0] && argv[1] &&
           strcmp(argv[0], "ssh-keygen") == 0 &&
           strcmp(argv[1], "-lf") == 0;
}

static int emit_fixture_key_fingerprint(const run_opts_t *opts,
                                        run_result_t *result) {
    int written;

    if (!opts || !opts->out || opts->out_size == 0U) return -1;
    written = snprintf(opts->out, opts->out_size,
                       "256 %s account-key (ED25519)\n", TEST_FP);
    if (written < 0 || (size_t)written >= opts->out_size) return -1;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
        result->out_len = (size_t)written;
    }
    return 0;
}

static int bad_permission_agent_runner(const char *const argv[],
                                       const run_opts_t *opts,
                                       run_result_t *result) {
    const char *socket_arg;

    if (is_key_fingerprint_command(argv)) {
        return emit_fixture_key_fingerprint(opts, result);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !is_ssh_agent_command(argv[0])) return 0;
    if (certify_agent_launch(argv[0], result) != 0) return -1;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0644, opts) != 0) {
        return -1;
    }
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld; export SSH_AGENT_PID;\n"
            "echo Agent pid %ld;\n",
            socket_arg, (long)TEST_PID, (long)TEST_PID);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return 0;
}

static int missing_pid_agent_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    const char *socket_arg;

    if (is_key_fingerprint_command(argv)) {
        return emit_fixture_key_fingerprint(opts, result);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !is_ssh_agent_command(argv[0])) return 0;
    if (certify_agent_launch(argv[0], result) != 0) return -1;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
        return -1;
    }
    make_runner_socket_stale();
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "echo Agent pid unavailable;\n",
            socket_arg);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return 0;
}

static int failed_after_agent_spawn_runner(const char *const argv[],
                                           const run_opts_t *opts,
                                           run_result_t *result) {
    const char *socket_arg;

    if (is_key_fingerprint_command(argv)) {
        return emit_fixture_key_fingerprint(opts, result);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !is_ssh_agent_command(argv[0])) return 0;
    if (certify_agent_launch(argv[0], result) != 0) return -1;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
        return -1;
    }
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld; export SSH_AGENT_PID;\n",
            socket_arg, (long)TEST_PID);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return -1;
}

static int failed_with_truncated_pid_and_socket_runner(
    const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    const char *socket_arg;

    if (is_key_fingerprint_command(argv)) {
        return emit_fixture_key_fingerprint(opts, result);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->exit_code = -1;
        result->out_truncated = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !is_ssh_agent_command(argv[0])) return 0;
    if (certify_agent_launch(argv[0], result) != 0) return -1;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
        return -1;
    }
    make_runner_socket_stale();
    if (opts && opts->out) {
        int written = snprintf(opts->out, opts->out_size,
                               "SSH_AGENT_PID=%ld",
                               (long)TEST_PID);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return -1;
}

static int successful_with_truncated_pid_and_socket_runner(
    const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    const char *socket_arg;

    if (is_key_fingerprint_command(argv)) {
        return emit_fixture_key_fingerprint(opts, result);
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
        result->out_truncated = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !is_ssh_agent_command(argv[0])) return 0;
    if (certify_agent_launch(argv[0], result) != 0) return -1;

    socket_arg = runner_socket_arg(argv);
    if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
        return -1;
    }
    make_runner_socket_stale();
    if (opts && opts->out) {
        int written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld",
            socket_arg, (long)TEST_PID);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    return 0;
}

static int successful_agent_runner(const char *const argv[],
                                   const run_opts_t *opts,
                                   run_result_t *result) {
    const char *socket_arg;
    int written;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv || !argv[0] || !opts || !opts->out || opts->out_size == 0U) {
        return -1;
    }
    if (is_ssh_agent_command(argv[0])) {
        if (certify_agent_launch(argv[0], result) != 0) return -1;
        socket_arg = runner_socket_arg(argv);
        if (!socket_arg || bind_runner_socket(socket_arg, 0600, opts) != 0) {
            return -1;
        }
        written = snprintf(
            opts->out, opts->out_size,
            "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=%ld; export SSH_AGENT_PID;\n",
            socket_arg, (long)TEST_PID);
    } else if (strcmp(argv[0], "ssh-add") == 0 ||
               strcmp(argv[0], "ssh-keygen") == 0) {
        written = snprintf(opts->out, opts->out_size,
                           "256 %s account-key (ED25519)\n", TEST_FP);
    } else {
        return 0;
    }
    if (written < 0 || (size_t)written >= opts->out_size) return -1;
    if (result) result->out_len = (size_t)written;
    return 0;
}

static int g_launch_generation_calls;
static int g_captured_unrecorded_reap_calls;
static ssh_agent_record_t g_captured_unrecorded_record;

static int generation_replaced_after_launch_capture(
    pid_t pid, ssh_process_generation_t *generation) {
    if (pid != TEST_PID || !generation) {
        errno = EINVAL;
        return -1;
    }
    g_launch_generation_calls++;
    *generation = g_launch_generation_calls == 1
                      ? g_test_generation
                      : replacement_generation();
    return 0;
}

static ssh_process_outcome_t capture_unrecorded_reap_generation(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)socket_arg;
    (void)runtime_dir_fd;
    g_captured_unrecorded_reap_calls++;
    if (record) g_captured_unrecorded_record = *record;
    return SSH_PROCESS_INDETERMINATE;
}

TEST(unrecorded_launch_cleanup_keeps_original_captured_generation) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {
        .generation = generation_replaced_after_launch_capture
    };
    ssh_reap_test_ops_t previous_ops;
    char sidecar_text[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14launchgeneration"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    g_launch_generation_calls = 0;
    g_captured_unrecorded_reap_calls = 0;
    memset(&g_captured_unrecorded_record, 0,
           sizeof(g_captured_unrecorded_record));
    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(
        capture_unrecorded_reap_generation);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_test_ops(&previous_ops);
    run_set_runner(previous_runner);
    ssh_manager_set_reap_fn(previous_reap);

    CHECK_EQ_INT(g_captured_unrecorded_reap_calls, 1);
    CHECK_EQ_INT(g_captured_unrecorded_record.pid, TEST_PID);
    CHECK(g_captured_unrecorded_record.generation.start_lo ==
          g_test_generation.start_lo);
    CHECK(config.agent_generation.start_lo ==
          g_test_generation.start_lo);
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, sidecar_text,
                              sizeof(sidecar_text)) > 0);
    CHECK(is_v2_test_record(sidecar_text));

    ssh_manager_set_reap_fn(reap_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    close(fixture.dir_fd);
}

TEST(runner_failure_indeterminate_reap_publishes_retry_tuple) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;
    char current[192];
    char sidecar_text[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar11runretry"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(failed_after_agent_spawn_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(config.agent_owned);
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, sidecar_text,
                              sizeof(sidecar_text)) > 0);
    CHECK(is_v2_test_record(sidecar_text));
    CHECK(strstr(get_last_error()->message,
                 "runtime durably retained for retry") != NULL);
    CHECK((size_t)snprintf(current, sizeof(current), "%s/current.sock",
                           fixture.runtime) < sizeof(current));
    CHECK(!path_exists(current));

    ssh_manager_set_reap_fn(reap_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));

    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;
    previous_runner = run_set_runner(successful_agent_runner);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), 0);
    run_set_runner(previous_runner);
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(path_exists(current));
    make_runner_socket_stale();
    ssh_manager_set_reap_fn(reap_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(!path_exists(current));
    ssh_manager_set_reap_test_ops(&previous_ops);
    close(fixture.dir_fd);
}

TEST(socket_evidence_recovers_without_trusting_truncated_pid) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar11runsock"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(
        failed_with_truncated_pid_and_socket_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message,
                 "spawned runtime removed") != NULL);
    close(fixture.dir_fd);
}

TEST(successful_launch_rejects_truncated_pid_capture) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14runtruncated"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(
        successful_with_truncated_pid_and_socket_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(!path_exists(fixture.current));
    CHECK(strstr(get_last_error()->message,
                 "spawned runtime removed") != NULL);
    close(fixture.dir_fd);
}

TEST(pre_sidecar_failed_reap_publishes_retry_tuple) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;
    char sidecar_text[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08retry"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    safe_strncpy(account.name, "work", sizeof(account.name));
    safe_strncpy(account.email, "work@example.invalid", sizeof(account.email));
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key", fixture.xdg) <
          sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_test_ops(&previous_ops);
    run_set_runner(previous_runner);
    ssh_manager_set_reap_fn(reap_gone);

    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(config.agent_owned);
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(read_file_to_string(fixture.sidecar, sidecar_text,
                              sizeof(sidecar_text)) > 0);
    CHECK(is_v2_test_record(sidecar_text));

    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(pre_sidecar_replaced_generation_retains_socket_unowned) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14replacedlaunch"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_replaced);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_test_ops(&previous_ops);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK_EQ_INT(config.agent_generation.kind,
                 SSH_PROCESS_GENERATION_NONE);
    CHECK(path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message, "artifact retained") != NULL);
    CHECK(strstr(get_last_error()->message,
                 "durably retained") == NULL);

    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST(failed_retry_sidecar_publication_retains_artifact_without_ownership) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;
    ssh_pid_commit_hook_fn previous_commit;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14retrypublication"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(reap_indeterminate);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    previous_commit = ssh_manager_set_pid_commit_hook_fn(
        fail_retry_pid_sidecar_publication);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_pid_commit_hook_fn(previous_commit);
    ssh_manager_set_reap_test_ops(&previous_ops);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message, "artifact retained") != NULL);
    CHECK(strstr(get_last_error()->message, "runtime removed") == NULL);

    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST(exact_durable_sidecar_recovery_retains_agent_ownership) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;
    ssh_pid_commit_hook_fn previous_postrename;
    char sidecar_text[512];

    CHECK_EQ_INT(make_fixture(&fixture, "gsar14exactrecovery"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;

    g_exact_recovery_reap_calls = 0;
    previous_runner = run_set_runner(successful_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(
        exact_recovery_reap_must_not_run);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    previous_postrename = ssh_manager_set_pid_postrename_hook_fn(
        fail_exact_pid_postrename_verification);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_pid_postrename_hook_fn(previous_postrename);
    ssh_manager_set_reap_test_ops(&previous_ops);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(g_exact_recovery_reap_calls, 0);
    CHECK_EQ_INT(config.agent_pid, TEST_PID);
    CHECK(config.agent_owned);
    CHECK(config.agent_generation.start_lo ==
          g_test_generation.start_lo);
    CHECK(path_exists(fixture.socket));
    CHECK(path_exists(fixture.sidecar));
    CHECK(!path_exists(fixture.current));
    CHECK(read_file_to_string(fixture.sidecar, sidecar_text,
                              sizeof(sidecar_text)) > 0);
    CHECK(is_v2_test_record(sidecar_text));
    CHECK(strstr(get_last_error()->message,
                 "exact durable record recovered") != NULL);

    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    CHECK_EQ_INT(ssh_manager_reset("work"), 0);
    ssh_manager_set_reap_fn(previous_reap);
    CHECK(!path_exists(fixture.socket));
    CHECK(!path_exists(fixture.sidecar));
    close(fixture.dir_fd);
}

TEST(pre_sidecar_cleanup_preserves_reaped_socket_replacement) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_reap_fn previous_reap;
    ssh_reap_test_ops_t ops = {.generation = generation_matches_record};
    ssh_reap_test_ops_t previous_ops;
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08prerace"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;

    previous_runner = run_set_runner(bad_permission_agent_runner);
    previous_reap = ssh_manager_set_reap_fn(replace_socket_then_gone);
    previous_ops = ssh_manager_set_reap_test_ops(&ops);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_reap_test_ops(&previous_ops);
    ssh_manager_set_reap_fn(previous_reap);
    run_set_runner(previous_runner);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(!path_exists(fixture.sidecar));
    CHECK(strstr(get_last_error()->message, "artifact retained") != NULL);
    CHECK(strstr(get_last_error()->message, "runtime removed") == NULL);
    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST(pre_sidecar_probe_cleanup_preserves_socket_replacement) {
    ssh_fixture_t fixture;
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_quarantine_hook_fn previous_hook;
    struct stat replacement;

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08proberace"), 0);
    if (fixture.dir_fd < 0) return;
    memset(&account, 0, sizeof(account));
    account.id = 1;
    CHECK_EQ_INT(safe_strncpy(account.name, "work",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "work@example.invalid",
                              sizeof(account.email)), 0);
    account.ssh_enabled = true;
    CHECK((size_t)snprintf(account.ssh_key_path,
                           sizeof(account.ssh_key_path), "%s/key",
                           fixture.xdg) < sizeof(account.ssh_key_path));
    memset(&config, 0, sizeof(config));
    config.mode = SSH_AGENT_ISOLATED;
    config.agent_pid = -1;
    CHECK_EQ_INT(safe_strncpy(g_race_socket, fixture.socket,
                              sizeof(g_race_socket)), 0);
    g_race_hook_succeeded = false;

    previous_runner = run_set_runner(missing_pid_agent_runner);
    previous_hook = ssh_manager_set_unrecorded_cleanup_hook_fn(
        replace_unrecorded_socket_before_cleanup);
    CHECK_EQ_INT(ssh_start_isolated_agent(&config, &account), -1);
    ssh_manager_set_unrecorded_cleanup_hook_fn(previous_hook);
    run_set_runner(previous_runner);

    CHECK(g_race_hook_succeeded);
    CHECK_EQ_INT(lstat(fixture.socket, &replacement), 0);
    CHECK(S_ISSOCK(replacement.st_mode));
    CHECK_EQ_INT(config.agent_pid, -1);
    CHECK(!config.agent_owned);
    CHECK(!path_exists(fixture.sidecar));
    CHECK_EQ_INT(unlink(fixture.socket), 0);
    close(fixture.dir_fd);
}

TEST(runtime_metadata_mismatches_use_stable_estale_diagnostics) {
    ssh_fixture_t fixture;
    ssh_metadata_test_hook_fn previous_metadata;
    ssh_reap_fn previous_reap;
    bool previous_portable;
    char diagnostic_suffix[128];
    const char *first_suffix;
    int reset_rc;
    int diagnostic_errno;

    CHECK(snprintf(diagnostic_suffix, sizeof(diagnostic_suffix), " (%s)",
                   strerror(ESTALE)) > 0);

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08pinerrno"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(bind_stale_socket(fixture.socket), 0);
    g_metadata_mismatch_stage = SSH_METADATA_TEST_RUNTIME_PIN;
    g_metadata_mismatch_calls = 0;
    previous_metadata = ssh_manager_set_metadata_test_hook_fn(
        force_ssh_metadata_mismatch);
    clear_error();
    reset_rc = ssh_manager_reset("work");
    diagnostic_errno = get_last_error()->system_errno;
    ssh_manager_set_metadata_test_hook_fn(previous_metadata);

    CHECK_EQ_INT(reset_rc, -1);
    CHECK_EQ_INT(g_metadata_mismatch_calls, 1);
    CHECK_EQ_INT(diagnostic_errno, ESTALE);
    first_suffix = strstr(get_last_error()->message, diagnostic_suffix);
    CHECK(first_suffix != NULL);
    CHECK(first_suffix == NULL ||
          strstr(first_suffix + strlen(diagnostic_suffix),
                 diagnostic_suffix) == NULL);
    CHECK(path_exists(fixture.socket));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);

    CHECK_EQ_INT(make_fixture(&fixture, "gsar08quarerrno"), 0);
    if (fixture.dir_fd < 0) return;
    CHECK_EQ_INT(publish_sidecar(&fixture, TEST_PID), 0);
    g_metadata_mismatch_stage = SSH_METADATA_TEST_RESET_QUARANTINE;
    g_metadata_mismatch_calls = 0;
    previous_portable = ssh_manager_set_force_portable_quarantine(true);
    previous_reap = ssh_manager_set_reap_fn(reap_gone);
    previous_metadata = ssh_manager_set_metadata_test_hook_fn(
        force_ssh_metadata_mismatch);
    clear_error();
    reset_rc = ssh_manager_reset("work");
    diagnostic_errno = get_last_error()->system_errno;
    ssh_manager_set_metadata_test_hook_fn(previous_metadata);
    ssh_manager_set_reap_fn(previous_reap);
    ssh_manager_set_force_portable_quarantine(previous_portable);

    CHECK_EQ_INT(reset_rc, -1);
    CHECK_EQ_INT(g_metadata_mismatch_calls, 1);
    CHECK_EQ_INT(diagnostic_errno, ESTALE);
    first_suffix = strstr(get_last_error()->message, diagnostic_suffix);
    CHECK(first_suffix != NULL);
    CHECK(first_suffix == NULL ||
          strstr(first_suffix + strlen(diagnostic_suffix),
                 diagnostic_suffix) == NULL);
    CHECK(path_exists(fixture.sidecar));
    cleanup_retained_fixture(&fixture);
    close(fixture.dir_fd);
    ts_rm_rf(fixture.xdg);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(targeted_reset_cleans_malformed_sidecars_when_socket_is_absent);
    RUN_TEST(reset_all_cleans_malformed_sidecars_when_socket_is_absent);
    RUN_TEST(targeted_reset_cleans_malformed_sidecars_when_socket_is_stale);
    RUN_TEST(reset_all_cleans_malformed_sidecars_when_socket_is_stale);
    RUN_TEST(targeted_reset_retains_malformed_sidecars_while_socket_is_live);
    RUN_TEST(reset_all_retains_malformed_sidecars_while_socket_is_live);
    RUN_TEST(targeted_reset_retains_malformed_sidecars_when_probe_is_indeterminate);
    RUN_TEST(reset_all_retains_malformed_sidecars_when_probe_is_indeterminate);
    RUN_TEST(targeted_reset_retains_unsafe_sidecar_without_socket);
    RUN_TEST(reset_all_retains_unsafe_sidecar_without_socket);
    RUN_TEST(indeterminate_identity_retains_retry_sidecar);
    RUN_TEST(permission_denied_presence_probe_is_indeterminate);
    RUN_TEST(failed_pidfd_signal_retains_retry_sidecar);
    RUN_TEST(interrupted_pidfd_term_retries_and_esrch_cleans);
    RUN_TEST(targeted_generation_mismatch_before_pidfd_preserves_retry_tuple);
    RUN_TEST(reset_all_generation_mismatch_before_pidfd_preserves_retry_tuple);
    RUN_TEST(generation_is_verified_before_pidfd_open_and_reverified_afterward);
    RUN_TEST(pidfd_death_during_numeric_inspection_discards_replacement_result);
    RUN_TEST(live_pidfd_rejects_contradictory_numeric_generation_gone);
    RUN_TEST(live_pidfd_rejects_contradictory_numeric_identity_gone);
    RUN_TEST(pidfd_pollerr_dominates_hup_and_retains_retry_tuple);
    RUN_TEST(pidfd_pollnval_dominates_hup_and_retains_retry_tuple);
    RUN_TEST(pidfd_pollerr_after_term_retains_retry_tuple);
    RUN_TEST(pidfd_escalation_never_returns_to_numeric_process_inspection);
    RUN_TEST(targeted_reset_retains_exact_tuple_when_pidfd_is_unsupported);
    RUN_TEST(reset_all_retains_exact_tuple_when_pidfd_is_unsupported);
    RUN_TEST(sidecarless_targeted_retains_loaded_live_agent_and_exact_evidence);
    RUN_TEST(sidecarless_reset_all_retains_loaded_live_agent_and_exact_evidence);
    RUN_TEST(sidecarless_wrong_protocol_type_retains_exact_artifacts);
    RUN_TEST(sidecarless_malformed_identity_answer_retains_exact_artifacts);
    RUN_TEST(sidecarless_truncated_protocol_frame_retains_exact_artifacts);
    RUN_TEST(sidecarless_oversized_protocol_frame_retains_exact_artifacts);
    RUN_TEST(sidecarless_protocol_timeout_retains_exact_artifacts);
    RUN_TEST(recorded_darwin_and_freebsd_endpoints_clear_then_verify_without_signals);
    RUN_TEST(recorded_endpoint_retries_indeterminate_identity_once_then_retires);
    RUN_TEST(recorded_endpoint_indeterminate_identity_retains_exact_tuple_and_cause);
    RUN_TEST(recorded_endpoint_remove_failure_retains_exact_tuple);
    RUN_TEST(recorded_endpoint_nonempty_verification_retains_exact_tuple);
    RUN_TEST(recorded_darwin_preflight_failure_retains_exact_tuple_without_remove);
    RUN_TEST(recorded_darwin_preflight_peer_mismatch_retains_exact_tuple_without_remove);
    RUN_TEST(stop_owned_bsd_endpoint_clears_then_detaches_without_signals);
    RUN_TEST(stop_owned_bsd_endpoint_cleanup_failure_preserves_observable_retry_state);
    RUN_TEST(linux_pidfd_unavailable_never_uses_agent_protocol);
    RUN_TEST(pidfd_open_esrch_cleans_exact_tuple_without_numeric_termination);
    RUN_TEST(generation_inspection_error_never_terminates_or_consumes_tuple);
    RUN_TEST(legacy_live_owned_sidecar_is_migrated_and_reset_converges);
    RUN_TEST(legacy_live_unprovable_sidecar_stays_fail_closed);
    RUN_TEST(legacy_dead_sidecar_is_cleaned_without_reap);
    RUN_TEST(stopped_session_preserves_same_pid_replacement_generation);
    RUN_TEST(gone_record_with_live_replacement_preserves_complete_tuple);
    RUN_TEST(unrelated_record_with_live_replacement_preserves_complete_tuple);
    RUN_TEST(real_kernel_esrch_consumes_stale_sidecar);
    RUN_TEST(signal_storm_preserves_pidfd_term_and_kill_deadlines);
    RUN_TEST(runtime_namespace_replacement_fails_without_mutating_either_tree);
    RUN_TEST(sidecar_replacement_before_cleanup_is_restored_and_retained);
    RUN_TEST(socket_replacement_before_cleanup_survives_with_stable_link);
    RUN_TEST(reaped_agent_socket_self_removal_is_idempotent);
    RUN_TEST(malformed_quarantine_substitution_is_preserved);
    RUN_TEST(portable_malformed_quarantine_substitution_is_preserved);
    RUN_TEST(final_quarantine_substitution_is_not_deleted);
    RUN_TEST(portable_final_quarantine_substitution_is_not_deleted);
    RUN_TEST(portable_restore_retirement_substitution_is_preserved);
    RUN_TEST(unrelated_live_pid_is_not_signaled);
    RUN_TEST(runtime_root_provenance_prevents_cross_root_reap);
    RUN_TEST(unrecorded_launch_cleanup_keeps_original_captured_generation);
    RUN_TEST(runner_failure_indeterminate_reap_publishes_retry_tuple);
    RUN_TEST(socket_evidence_recovers_without_trusting_truncated_pid);
    RUN_TEST(successful_launch_rejects_truncated_pid_capture);
    RUN_TEST(pre_sidecar_failed_reap_publishes_retry_tuple);
    RUN_TEST(pre_sidecar_replaced_generation_retains_socket_unowned);
    RUN_TEST(failed_retry_sidecar_publication_retains_artifact_without_ownership);
    RUN_TEST(exact_durable_sidecar_recovery_retains_agent_ownership);
    RUN_TEST(pre_sidecar_cleanup_preserves_reaped_socket_replacement);
    RUN_TEST(pre_sidecar_probe_cleanup_preserves_socket_replacement);
    RUN_TEST(runtime_metadata_mismatches_use_stable_estale_diagnostics);
TEST_MAIN_END()
