/* SSH exact-set loading and admitted-key snapshot lifecycle regressions. */

#if defined(__linux__)
#  define _GNU_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "ssh_manager.h"
#define GITSWITCH_INTERNAL_API
#include "ssh_manager_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_snapshot_clear_calls;
static bool g_snapshot_clear_was_zero;
static bool g_snapshot_clear_fd_was_open;
static int g_snapshot_cleared_fd;
static int g_rejected_commands;

#if defined(__linux__) && defined(F_GET_SEALS) && \
    defined(F_SEAL_WRITE) && defined(F_SEAL_GROW) && \
    defined(F_SEAL_SHRINK) && defined(F_SEAL_SEAL)
static const char *g_mutable_key_path;
static const char *g_admitted_key_bytes;
static const char *g_replacement_key_bytes;
static size_t g_mutable_key_length;
static bool g_fingerprint_saw_distinct_inode;
static bool g_fingerprint_saw_required_seals;
static bool g_fingerprint_snapshot_stayed_admitted;
static bool g_original_key_was_restored;

static int sealed_snapshot_fingerprint_runner(const char *const argv[],
                                              const run_opts_t *opts,
                                              run_result_t *result) {
    static const char listing[] =
        "256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
        "fixture (ED25519)\n";
    const int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat source_stat;
    struct stat snapshot_stat;
    char snapshot_bytes[256];
    char restored_bytes[256];
    int source_fd = -1;
    int seals;

    if (result) memset(result, 0, sizeof(*result));
    if (!argv || !argv[0] || strcmp(argv[0], "ssh-keygen") != 0 ||
        !argv[1] || strcmp(argv[1], "-lf") != 0 ||
        !opts || !opts->use_stdin_fd || opts->stdin_fd < 0 ||
        !g_mutable_key_path || !g_admitted_key_bytes ||
        !g_replacement_key_bytes ||
        g_mutable_key_length >= sizeof(snapshot_bytes)) {
        return -1;
    }

    source_fd = open(g_mutable_key_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (source_fd < 0 ||
        fstat(source_fd, &source_stat) != 0 ||
        fstat(opts->stdin_fd, &snapshot_stat) != 0) {
        if (source_fd >= 0) close(source_fd);
        return -1;
    }
    g_fingerprint_saw_distinct_inode =
        source_stat.st_dev != snapshot_stat.st_dev ||
        source_stat.st_ino != snapshot_stat.st_ino;
    seals = fcntl(opts->stdin_fd, F_GET_SEALS);
    g_fingerprint_saw_required_seals =
        seals >= 0 && (seals & required_seals) == required_seals;

    if (pwrite(source_fd, g_replacement_key_bytes, g_mutable_key_length, 0) ==
            (ssize_t)g_mutable_key_length &&
        pread(opts->stdin_fd, snapshot_bytes, g_mutable_key_length, 0) ==
            (ssize_t)g_mutable_key_length) {
        g_fingerprint_snapshot_stayed_admitted =
            memcmp(snapshot_bytes, g_admitted_key_bytes,
                   g_mutable_key_length) == 0;
    }
    if (pwrite(source_fd, g_admitted_key_bytes, g_mutable_key_length, 0) ==
            (ssize_t)g_mutable_key_length &&
        pread(source_fd, restored_bytes, g_mutable_key_length, 0) ==
            (ssize_t)g_mutable_key_length) {
        g_original_key_was_restored =
            memcmp(restored_bytes, g_admitted_key_bytes,
                   g_mutable_key_length) == 0;
    }
    close(source_fd);

    if (opts->out && opts->out_size > 0) {
        int written = snprintf(opts->out, opts->out_size, "%s", listing);
        if (written < 0 || (size_t)written >= opts->out_size) return -1;
        if (result) result->out_len = (size_t)written;
    }
    if (result) {
        result->spawned = true;
        result->exit_code = 0;
    }
    return 0;
}
#endif

static void observe_cleared_snapshot(const void *data, size_t length,
                                     int retained_fd) {
    const unsigned char *bytes = data;

    g_snapshot_clear_calls++;
    g_snapshot_clear_was_zero = data != NULL && length > 0;
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] != 0) g_snapshot_clear_was_zero = false;
    }
    g_snapshot_clear_fd_was_open =
        retained_fd >= 0 && fcntl(retained_fd, F_GETFD, 0) >= 0;
    g_snapshot_cleared_fd = retained_fd;
}

static int reject_every_command_runner(const char *const argv[],
                                       const run_opts_t *opts,
                                       run_result_t *result) {
    (void)argv;
    g_rejected_commands++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 1;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    return -1;
}

static int fail_before_spawn_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    (void)argv;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->exit_code = -1;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    set_error(ERR_SYSTEM_COMMAND_FAILED,
              "causal ssh-keygen launch failure");
    return -1;
}

static int make_snapshot_fixture(char *root, size_t root_size,
                                 char *key, size_t key_size,
                                 account_t *account,
                                 ssh_config_t *config) {
    const char *keygen[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key, NULL
    };
    run_opts_t opts;
    run_result_t result;

    if (root_size < sizeof("/tmp/gsw-ar09-ssh-snapshot.XXXXXX")) return -1;
    snprintf(root, root_size, "/tmp/gsw-ar09-ssh-snapshot.XXXXXX");
    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        safe_snprintf(key, key_size, "%s/id_test", root) != 0) {
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    if (run_argv_real(keygen, &opts, &result) != 0) return -1;
    memset(account, 0, sizeof(*account));
    account->id = 1;
    account->ssh_enabled = true;
    if (safe_strncpy(account->name, "snapshot", sizeof(account->name)) != 0 ||
        safe_strncpy(account->email, "snapshot@example.test",
                     sizeof(account->email)) != 0 ||
        safe_strncpy(account->ssh_key_path, key,
                     sizeof(account->ssh_key_path)) != 0) {
        return -1;
    }
    memset(config, 0, sizeof(*config));
    config->agent_pid = -1;
    return 0;
}

TEST(snapshot_is_wiped_and_descriptor_closed_on_postcapture_exits) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_key_snapshot_clear_hook_fn previous_hook;

    if (!command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "ssh-keygen unavailable");
    }
    previous_hook = ssh_manager_set_key_snapshot_clear_hook_fn(
        observe_cleared_snapshot);
    g_snapshot_clear_calls = 0;

    /* An isolated activation failure after capture still scrubs and closes
     * the retained generation. */
    CHECK_EQ_INT(make_snapshot_fixture(root, sizeof(root), key, sizeof(key),
                                       &account, &config), 0);
    config.mode = SSH_AGENT_ISOLATED;
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", root, 1), 0);
    g_rejected_commands = 0;
    previous_runner = run_set_runner(reject_every_command_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    run_set_runner(previous_runner);
    CHECK(g_rejected_commands > 0);
    CHECK_EQ_INT(g_snapshot_clear_calls, 1);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
    unsetenv("XDG_RUNTIME_DIR");
    ts_rm_rf(root);

    /* After the final pathname proof, admission closes the mutable source
     * descriptor before dispatch. The later scrub hook therefore receives no
     * still-open source handle on either invalid dispatch or success. */
    CHECK_EQ_INT(make_snapshot_fixture(root, sizeof(root), key, sizeof(key),
                                       &account, &config), 0);
    config.mode = (ssh_agent_mode_t)99;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    CHECK_EQ_INT(g_snapshot_clear_calls, 2);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(!g_snapshot_clear_fd_was_open);
    CHECK_EQ_INT(g_snapshot_cleared_fd, -1);
    ts_rm_rf(root);

    CHECK_EQ_INT(make_snapshot_fixture(root, sizeof(root), key, sizeof(key),
                                       &account, &config), 0);
    config.mode = SSH_AGENT_NONE;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    CHECK_EQ_INT(g_snapshot_clear_calls, 3);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(!g_snapshot_clear_fd_was_open);
    CHECK_EQ_INT(g_snapshot_cleared_fd, -1);
    ts_rm_rf(root);

    ssh_manager_set_key_snapshot_clear_hook_fn(previous_hook);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
}

static int run_quiet_real(const char *const argv[]) {
    run_opts_t opts;
    run_result_t result;

    memset(&opts, 0, sizeof(opts));
    opts.stderr_to_devnull = true;
    return run_argv_real(argv, &opts, &result);
}

TEST(secure_private_key_envelope_with_unusable_payload_is_rejected) {
    static const char malformed_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "this-is-not-an-openssh-private-key\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char root[128] = "/tmp/gsw-ar14-ssh-malformed.XXXXXX";
    char key[MAX_PATH_LEN];
    account_t account;
    ssh_config_t config;

    if (!command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "ssh-keygen unavailable");
    }
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(write_string_to_file(key, malformed_key, 0600), 0);

    CHECK_EQ_INT(ssh_validate_key_file(key), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_KEY_INVALID);

    memset(&account, 0, sizeof(account));
    account.id = 1;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "malformed",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "malformed@example.test",
                              sizeof(account.email)), 0);
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key,
                              sizeof(account.ssh_key_path)), 0);
    memset(&config, 0, sizeof(config));
    config.agent_pid = -1;
    config.mode = SSH_AGENT_NONE;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_KEY_INVALID);

    ts_rm_rf(root);
}

TEST(ssh_keygen_launch_failure_preserves_causal_diagnostic) {
    static const char shaped_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "fixture\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char root[128] = "/tmp/gsw-ar14-ssh-launch.XXXXXX";
    char key[MAX_PATH_LEN];
    command_runner_fn previous_runner;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(write_string_to_file(key, shaped_key, 0600), 0);

    previous_runner = run_set_runner(fail_before_spawn_runner);
    CHECK_EQ_INT(ssh_validate_key_file(key), -1);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_COMMAND_FAILED);
    CHECK(strstr(get_last_error()->message,
                 "causal ssh-keygen launch failure") != NULL);

    ts_rm_rf(root);
}

TEST(fingerprint_helper_reads_distinct_sealed_snapshot_during_source_rewrite) {
#if defined(__linux__) && defined(F_GET_SEALS) && \
    defined(F_SEAL_WRITE) && defined(F_SEAL_GROW) && \
    defined(F_SEAL_SHRINK) && defined(F_SEAL_SEAL)
    static const char admitted_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "fixture\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    static const char replacement_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "mutated\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char root[128] = "/tmp/gsw-ar14-ssh-sealed.XXXXXX";
    char key[MAX_PATH_LEN];
    command_runner_fn previous_runner;

    CHECK_EQ_INT(sizeof(admitted_key), sizeof(replacement_key));
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(write_string_to_file(key, admitted_key, 0600), 0);

    g_mutable_key_path = key;
    g_admitted_key_bytes = admitted_key;
    g_replacement_key_bytes = replacement_key;
    g_mutable_key_length = sizeof(admitted_key) - 1U;
    g_fingerprint_saw_distinct_inode = false;
    g_fingerprint_saw_required_seals = false;
    g_fingerprint_snapshot_stayed_admitted = false;
    g_original_key_was_restored = false;
    previous_runner = run_set_runner(sealed_snapshot_fingerprint_runner);
    CHECK_EQ_INT(ssh_validate_key_file(key), 0);
    run_set_runner(previous_runner);

    CHECK(g_fingerprint_saw_distinct_inode);
    CHECK(g_fingerprint_saw_required_seals);
    CHECK(g_fingerprint_snapshot_stayed_admitted);
    CHECK(g_original_key_was_restored);
    ts_rm_rf(root);
#else
    /* The portable staging-file path has separate platform contract tests. */
#endif
}

TEST(real_unencrypted_private_key_is_accepted_by_public_validation) {
    char root[128] = "/tmp/gsw-ar14-ssh-unencrypted.XXXXXX";
    char key[MAX_PATH_LEN];
    const char *keygen[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key, NULL
    };

    if (!command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "ssh-keygen unavailable");
    }
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(run_quiet_real(keygen), 0);

    CHECK_EQ_INT(ssh_validate_key_file(key), 0);

    ts_rm_rf(root);
}

TEST(verified_admission_uses_retained_generation_after_source_replacement) {
    char root[128] = "/tmp/gsw-ar14-ssh-admission.XXXXXX";
    char key[MAX_PATH_LEN];
    char replacement[MAX_PATH_LEN];
    account_t account;
    ssh_config_t config;
    ssh_key_admission_t *admission = NULL;

    if (!command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "ssh-keygen unavailable");
    }
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_original", root), 0);
    CHECK_EQ_INT(safe_snprintf(replacement, sizeof(replacement),
                               "%s/id_replacement", root), 0);
    {
        const char *original_keygen[] = {
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
            key, NULL
        };
        const char *replacement_keygen[] = {
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
            replacement, NULL
        };

        CHECK_EQ_INT(run_quiet_real(original_keygen), 0);
        CHECK_EQ_INT(run_quiet_real(replacement_keygen), 0);
    }

    CHECK_EQ_INT(ssh_key_admission_begin(key, &admission), 0);
    CHECK(admission != NULL);
    if (!admission) {
        ts_rm_rf(root);
        return;
    }
    CHECK_EQ_INT(ssh_key_admission_verify_named(admission), 0);
    CHECK_EQ_INT(rename(replacement, key), 0);

    memset(&account, 0, sizeof(account));
    account.id = 1;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "retained",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "retained@example.test",
                              sizeof(account.email)), 0);
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key,
                              sizeof(account.ssh_key_path)), 0);
    memset(&config, 0, sizeof(config));
    config.agent_pid = -1;
    config.mode = SSH_AGENT_NONE;

    /* The final namespace proof is a point-in-time admission boundary.
     * Replacing the configured name afterward must neither substitute the
     * replacement key nor cause a fresh path parse during activation. */
    CHECK_EQ_INT(ssh_switch_account_admitted(
                     &config, &account, admission), 0);

    ssh_key_admission_end(&admission);
    CHECK(admission == NULL);
    ts_rm_rf(root);
}

static int copy_file_bytes(const char *source, const char *destination) {
    unsigned char buffer[4096];
    int source_fd = -1;
    int destination_fd = -1;
    int rc = -1;

    source_fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_fd < 0) goto done;
    destination_fd = open(destination,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (destination_fd < 0) goto done;
    for (;;) {
        ssize_t count = read(source_fd, buffer, sizeof(buffer));
        size_t offset = 0U;

        if (count == 0) {
            rc = 0;
            break;
        }
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        while (offset < (size_t)count) {
            ssize_t written = write(destination_fd, buffer + offset,
                                    (size_t)count - offset);
            if (written > 0) {
                offset += (size_t)written;
            } else if (written < 0 && errno == EINTR) {
                continue;
            } else {
                goto done;
            }
        }
    }

done:
    if (destination_fd >= 0 && close(destination_fd) != 0) rc = -1;
    if (source_fd >= 0 && close(source_fd) != 0) rc = -1;
    return rc;
}

/* On Darwin/FreeBSD the admitted private bytes are staged in the locked
 * runtime directory. OpenSSH always probes `<path>.pub` first, so the scratch
 * component deliberately consumes the filesystem's complete NAME_MAX budget:
 * the private path works, while the appended sibling is kernel-rejected. */
TEST(real_name_max_private_component_blocks_pub_sibling_lookup) {
    static const char prefix[] = ".key-fingerprint.";
    char root[128] = "/tmp/gsw-ar11-ssh-namemax.XXXXXX";
    char source[MAX_PATH_LEN];
    char component[MAX_PATH_LEN];
    char scratch[MAX_PATH_LEN];
    char sidecar[MAX_PATH_LEN];
    char source_listing[1024];
    char scratch_listing[1024];
    long name_max;
    int sidecar_fd;
    const char *keygen[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
        "name-max", "-f", source, NULL
    };
    const char *source_fingerprint[] = {"ssh-keygen", "-lf", source, NULL};
    const char *scratch_fingerprint[] = {"ssh-keygen", "-lf", scratch, NULL};
    run_opts_t opts;
    run_result_t result;

    if (!command_exists("ssh-keygen")) {
        TS_SKIP("openssh", "ssh-keygen unavailable");
    }
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(source, sizeof(source), "%s/source", root), 0);
    errno = 0;
    name_max = pathconf(root, _PC_NAME_MAX);
    CHECK(name_max >= (long)(sizeof(prefix) - 1U + 16U));
    CHECK(name_max > 0 &&
          (size_t)name_max < sizeof(component) &&
          strlen(root) + 1U + (size_t)name_max + 1U < sizeof(scratch));
    if (name_max <= 0 || (size_t)name_max >= sizeof(component) ||
        strlen(root) + 1U + (size_t)name_max + 1U >= sizeof(scratch)) {
        ts_rm_rf(root);
        return;
    }
    memcpy(component, prefix, sizeof(prefix) - 1U);
    memset(component + sizeof(prefix) - 1U, 'x',
           (size_t)name_max - (sizeof(prefix) - 1U));
    component[name_max] = '\0';
    CHECK_EQ_INT(safe_snprintf(scratch, sizeof(scratch), "%s/%s", root,
                               component), 0);
    CHECK_EQ_INT(safe_snprintf(sidecar, sizeof(sidecar), "%s.pub", scratch),
                 0);
    CHECK_EQ_INT(run_quiet_real(keygen), 0);
    CHECK_EQ_INT(copy_file_bytes(source, scratch), 0);

    sidecar_fd = open(sidecar, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(sidecar_fd < 0);
    CHECK_EQ_INT(errno, ENAMETOOLONG);
    if (sidecar_fd >= 0) close(sidecar_fd);

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = source_listing;
    opts.out_size = sizeof(source_listing);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv_real(source_fingerprint, &opts, &result), 0);
    CHECK(!result.out_truncated);
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = scratch_listing;
    opts.out_size = sizeof(scratch_listing);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv_real(scratch_fingerprint, &opts, &result), 0);
    CHECK(!result.out_truncated);
    CHECK_STR_EQ(scratch_listing, source_listing);
    ts_rm_rf(root);
}

TEST(portable_fingerprint_slot_recovers_regular_stale_file_and_rejects_hardlink) {
    static const char stale_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "stale-fixed-slot-fixture\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    char root[128] = "/tmp/gsw-ar14-ssh-slot.XXXXXX";
    char slot_name[NAME_MAX + 1U];
    char slot_path[MAX_PATH_LEN];
    char target_path[MAX_PATH_LEN];
    char observed[sizeof(stale_key) + 8U];
    struct stat target_stat;
    struct stat slot_stat;
    int dir_fd = -1;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) {
        ts_rm_rf(root);
        return;
    }
    CHECK_EQ_INT(ssh_manager_test_fingerprint_slot_name(
                     dir_fd, slot_name, sizeof(slot_name)), 0);
    CHECK(strlen(slot_name) == (size_t)pathconf(root, _PC_NAME_MAX));
    CHECK_EQ_INT(safe_snprintf(slot_path, sizeof(slot_path), "%s/%s",
                               root, slot_name), 0);
    CHECK_EQ_INT(safe_snprintf(target_path, sizeof(target_path),
                               "%s/unsafe-target", root), 0);

    /* A crash-left private regular file is scrubbed and unlinked. Repeating
     * the recovery through the same fixed component proves bounded reuse. */
    CHECK_EQ_INT(write_string_to_file(slot_path, stale_key, 0600), 0);
    CHECK_EQ_INT(ssh_manager_test_recover_fingerprint_slot(dir_fd), 0);
    errno = 0;
    CHECK(lstat(slot_path, &slot_stat) != 0 && errno == ENOENT);
    CHECK_EQ_INT(write_string_to_file(slot_path, stale_key, 0600), 0);
    CHECK_EQ_INT(ssh_manager_test_recover_fingerprint_slot(dir_fd), 0);
    errno = 0;
    CHECK(lstat(slot_path, &slot_stat) != 0 && errno == ENOENT);

    /* A multiply linked entry is not exclusively owned by the slot. Recovery
     * must fail closed without scrubbing or unlinking either name. */
    CHECK_EQ_INT(write_string_to_file(target_path, stale_key, 0600), 0);
    CHECK_EQ_INT(link(target_path, slot_path), 0);
    CHECK_EQ_INT(stat(target_path, &target_stat), 0);
    CHECK_EQ_INT(stat(slot_path, &slot_stat), 0);
    CHECK_EQ_INT((long)target_stat.st_nlink, 2);
    CHECK(target_stat.st_dev == slot_stat.st_dev &&
          target_stat.st_ino == slot_stat.st_ino);
    clear_error();
    CHECK_EQ_INT(ssh_manager_test_recover_fingerprint_slot(dir_fd), -1);
    CHECK_EQ_INT(stat(target_path, &target_stat), 0);
    CHECK_EQ_INT(stat(slot_path, &slot_stat), 0);
    CHECK_EQ_INT((long)target_stat.st_nlink, 2);
    CHECK_EQ_INT(read_file_to_string(target_path, observed,
                                     sizeof(observed)),
                 (int)(sizeof(stale_key) - 1U));
    CHECK_STR_EQ(observed, stale_key);

    close(dir_fd);
    ts_rm_rf(root);
}

TEST(real_isolated_agent_does_not_autoload_a_sibling_certificate) {
    char root[128], key[MAX_PATH_LEN], key_pub[MAX_PATH_LEN];
    char key_cert[MAX_PATH_LEN], ca[MAX_PATH_LEN];
    char runtime[MAX_PATH_LEN], socket_name[MAX_PATH_LEN];
    char envbuf[MAX_PATH_LEN + 20], identities[8192];
    const char *env[2] = {envbuf, NULL};
    const char *keygen_key[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key,
        NULL
    };
    const char *keygen_ca[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ca,
        NULL
    };
    const char *sign_key[] = {
        "ssh-keygen", "-q", "-s", ca, "-I", "gitswitch-ar08",
        "-n", "git", key_pub, NULL
    };
    const char *list_argv[] = {"ssh-add", "-L", NULL};
    run_opts_t opts;
    run_result_t result;
    account_t account;
    ssh_config_t config;
    int runtime_fd = -1;
    int switch_rc;

    if (!command_exists("ssh-keygen") || !command_exists("ssh-agent") ||
        !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-keygen/ssh-agent/ssh-add unavailable");
    }
    snprintf(root, sizeof(root), "/tmp/gsw-ar08-ssh-cert.XXXXXX");
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(safe_snprintf(key_pub, sizeof(key_pub), "%s.pub", key), 0);
    CHECK_EQ_INT(safe_snprintf(key_cert, sizeof(key_cert), "%s-cert.pub",
                               key), 0);
    CHECK_EQ_INT(safe_snprintf(ca, sizeof(ca), "%s/ca", root), 0);
    CHECK_EQ_INT(safe_snprintf(runtime, sizeof(runtime), "%s/gitswitch-ssh",
                               root), 0);
    CHECK_EQ_INT(run_quiet_real(keygen_key), 0);
    CHECK_EQ_INT(run_quiet_real(keygen_ca), 0);
    CHECK_EQ_INT(run_quiet_real(sign_key), 0);
    CHECK(path_exists(key_cert));
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", root, 1), 0);

    memset(&account, 0, sizeof(account));
    account.id = 1;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "cert",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "cert@example.test",
                              sizeof(account.email)), 0);
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key,
                              sizeof(account.ssh_key_path)), 0);
    CHECK_EQ_INT(ssh_manager_init(&config, SSH_AGENT_ISOLATED), 0);
    switch_rc = ssh_switch_account(&config, &account);
    CHECK_EQ_INT(switch_rc, 0);

    if (switch_rc == 0) {
        const char *slash = strrchr(config.agent_socket_path, '/');
        CHECK(slash != NULL && slash[1] != '\0');
        if (slash && slash[1]) {
            CHECK_EQ_INT(safe_strncpy(socket_name, slash + 1,
                                      sizeof(socket_name)), 0);
            runtime_fd = open(runtime, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            CHECK(runtime_fd >= 0);
            if (runtime_fd >= 0) {
                CHECK(ssh_manager_test_socket_has_key(runtime_fd, socket_name,
                                                      key));
                CHECK((size_t)snprintf(envbuf, sizeof(envbuf),
                                       "SSH_AUTH_SOCK=%s", socket_name) <
                      sizeof(envbuf));
                memset(&opts, 0, sizeof(opts));
                opts.out = identities;
                opts.out_size = sizeof(identities);
                opts.stderr_to_devnull = true;
                opts.extra_env = env;
                opts.cwd_fd = runtime_fd;
                opts.use_cwd_fd = true;
                CHECK_EQ_INT(run_argv_real(list_argv, &opts, &result), 0);
                CHECK(!result.out_truncated);
                CHECK(strstr(identities, "-cert-v01@openssh.com") == NULL);
                close(runtime_fd);
                runtime_fd = -1;
            }
        }
    }

    CHECK_EQ_INT(ssh_manager_cleanup(&config), 0);
    unsetenv("XDG_RUNTIME_DIR");
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    ts_rm_rf(root);
}

/* Fingerprinting through the retained seekable descriptor must not decrypt or
 * prompt. Loading the encrypted snapshot through ssh-add stdin prompts once on
 * SSH_ASKPASS and succeeds, preserving the pre-M14 interaction contract. */
TEST(real_encrypted_snapshot_uses_askpass_exactly_once) {
    static const char passphrase[] = "gitswitch-m14-passphrase";
    char root[128], key[MAX_PATH_LEN], askpass[MAX_PATH_LEN];
    char count[MAX_PATH_LEN], script[2 * MAX_PATH_LEN], observed[64];
    const char *keygen[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase,
        "-f", key, NULL
    };
    account_t account;
    ssh_config_t config;

    if (!command_exists("ssh-keygen") || !command_exists("ssh-agent") ||
        !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-keygen/ssh-agent/ssh-add unavailable");
    }
    snprintf(root, sizeof(root), "/tmp/gsw-ar09-ssh-askpass.XXXXXX");
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(safe_snprintf(askpass, sizeof(askpass), "%s/askpass", root),
                 0);
    CHECK_EQ_INT(safe_snprintf(count, sizeof(count), "%s/count", root), 0);
    CHECK((size_t)snprintf(script, sizeof(script),
                           "#!/bin/sh\n"
                           "printf '1\\n' >> '%s'\n"
                           "printf '%%s\\n' '%s'\n",
                           count, passphrase) < sizeof(script));
    CHECK_EQ_INT(write_string_to_file(askpass, script, 0700), 0);
    CHECK_EQ_INT(run_quiet_real(keygen), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", root, 1), 0);
    CHECK_EQ_INT(setenv("DISPLAY", ":gitswitch-m14", 1), 0);
    CHECK_EQ_INT(setenv("SSH_ASKPASS", askpass, 1), 0);
    CHECK_EQ_INT(setenv("SSH_ASKPASS_REQUIRE", "force", 1), 0);

    /* Format validation must prove OpenSSH usability without attempting to
     * decrypt the key or consuming the user's passphrase interaction. */
    errno = 0;
    CHECK_EQ_INT(ssh_validate_key_file(key), 0);
    CHECK(access(count, F_OK) != 0 && errno == ENOENT);

    memset(&account, 0, sizeof(account));
    account.id = 1;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "encrypted",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email, "encrypted@example.test",
                              sizeof(account.email)), 0);
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key,
                              sizeof(account.ssh_key_path)), 0);
    CHECK_EQ_INT(ssh_manager_init(&config, SSH_AGENT_ISOLATED), 0);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    CHECK_EQ_INT(read_file_to_string(count, observed, sizeof(observed)), 2);
    CHECK_STR_EQ(observed, "1\n");
    CHECK_EQ_INT(ssh_manager_cleanup(&config), 0);

    unsetenv("XDG_RUNTIME_DIR");
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    unsetenv("DISPLAY");
    unsetenv("SSH_ASKPASS");
    unsetenv("SSH_ASKPASS_REQUIRE");
    ts_rm_rf(root);
}

/* OpenSSH stores key-generation comments in a 1024-byte buffer, so 1023
 * bytes is the largest comment its ordinary `ssh-keygen -C` path persists.
 * The resulting `ssh-keygen -lf` record exceeds the former 1024-byte capture
 * even though its fingerprint is valid. Verification must capture the whole
 * bounded listing in one execution without relaxing the independent rule
 * that an incomplete agent identity listing cannot prove exclusivity. */
TEST(real_maximum_stored_comment_verifies_exact_fingerprint) {
    char root[128], key[MAX_PATH_LEN], comment[1024];
    char listing[1024];
    char complete_listing[8192];
    const char *fingerprint_field;
    const char *comment_field;
    const char *type_field;
    const char *keygen[] = {
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment,
        "-f", key, NULL
    };
    const char *fingerprint[] = {"ssh-keygen", "-lf", key, NULL};
    run_opts_t opts;
    run_result_t result;
    account_t account;
    ssh_config_t config;
    int switch_rc;

    if (!command_exists("ssh-keygen") || !command_exists("ssh-agent") ||
        !command_exists("ssh-add")) {
        TS_SKIP("openssh", "ssh-keygen/ssh-agent/ssh-add unavailable");
    }
    memset(comment, 'c', sizeof(comment) - 1U);
    comment[sizeof(comment) - 1U] = '\0';
    snprintf(root, sizeof(root), "/tmp/gsw-ar11-ssh-comment.XXXXXX");
    CHECK(ts_mkdtemp(root) != NULL);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(safe_snprintf(key, sizeof(key), "%s/id_test", root), 0);
    CHECK_EQ_INT(run_quiet_real(keygen), 0);

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = complete_listing;
    opts.out_size = sizeof(complete_listing);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv_real(fingerprint, &opts, &result), 0);
    CHECK(!result.out_truncated);
    CHECK(result.out_len > sizeof(listing) - 1U);
    CHECK(result.out_len < 2048U);
    fingerprint_field = strstr(complete_listing, "SHA256:");
    CHECK(fingerprint_field != NULL);
    comment_field = fingerprint_field ? strchr(fingerprint_field, ' ') : NULL;
    CHECK(comment_field != NULL);
    if (comment_field) comment_field++;
    type_field = comment_field ? strstr(comment_field, " (ED25519)\n") : NULL;
    CHECK(type_field != NULL);
    if (comment_field && type_field) {
        CHECK_EQ_INT((long)(type_field - comment_field),
                     (long)sizeof(comment) - 1L);
        CHECK(memcmp(comment_field, comment, sizeof(comment) - 1U) == 0);
    }

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = listing;
    opts.out_size = sizeof(listing);
    opts.stderr_to_devnull = true;
    CHECK_EQ_INT(run_argv_real(fingerprint, &opts, &result), 0);
    CHECK(result.out_truncated);
    CHECK_EQ_INT((long)result.out_len, (long)sizeof(listing) - 1L);
    CHECK(strstr(listing, "256 SHA256:") == listing);

    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", root, 1), 0);
    memset(&account, 0, sizeof(account));
    account.id = 1;
    account.ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(account.name, "long-comment",
                              sizeof(account.name)), 0);
    CHECK_EQ_INT(safe_strncpy(account.email,
                              "long-comment@example.test",
                              sizeof(account.email)), 0);
    CHECK_EQ_INT(safe_strncpy(account.ssh_key_path, key,
                              sizeof(account.ssh_key_path)), 0);
    CHECK_EQ_INT(ssh_manager_init(&config, SSH_AGENT_ISOLATED), 0);
    switch_rc = ssh_switch_account(&config, &account);
    CHECK_EQ_INT(switch_rc, 0);
    CHECK_EQ_INT(ssh_manager_cleanup(&config), 0);

    unsetenv("XDG_RUNTIME_DIR");
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    ts_rm_rf(root);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(snapshot_is_wiped_and_descriptor_closed_on_postcapture_exits);
    RUN_TEST(secure_private_key_envelope_with_unusable_payload_is_rejected);
    RUN_TEST(ssh_keygen_launch_failure_preserves_causal_diagnostic);
    RUN_TEST(
        fingerprint_helper_reads_distinct_sealed_snapshot_during_source_rewrite);
    RUN_TEST(real_unencrypted_private_key_is_accepted_by_public_validation);
    RUN_TEST(
        verified_admission_uses_retained_generation_after_source_replacement);
    RUN_TEST(real_name_max_private_component_blocks_pub_sibling_lookup);
    RUN_TEST(
        portable_fingerprint_slot_recovers_regular_stale_file_and_rejects_hardlink);
    RUN_TEST(real_isolated_agent_does_not_autoload_a_sibling_certificate);
    RUN_TEST(real_encrypted_snapshot_uses_askpass_exactly_once);
    RUN_TEST(real_maximum_stored_comment_verifies_exact_fingerprint);
TEST_MAIN_END()
