/* SSH exact-set loading and admitted-key snapshot lifecycle regressions. */

#include "test.h"
#include "error.h"
#include "ssh_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
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

static int make_snapshot_fixture(char *root, size_t root_size,
                                 char *key, size_t key_size,
                                 account_t *account,
                                 ssh_config_t *config) {
    static const char private_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "generation-a\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

    if (root_size < sizeof("/tmp/gsw-ar09-ssh-snapshot.XXXXXX")) return -1;
    snprintf(root, root_size, "/tmp/gsw-ar09-ssh-snapshot.XXXXXX");
    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        safe_snprintf(key, key_size, "%s/id_test", root) != 0 ||
        write_string_to_file(key, private_key, 0600) != 0) {
        return -1;
    }
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

    /* Invalid post-capture dispatch and the normal success exit share the
     * same scrub-and-close funnel. */
    CHECK_EQ_INT(make_snapshot_fixture(root, sizeof(root), key, sizeof(key),
                                       &account, &config), 0);
    config.mode = (ssh_agent_mode_t)99;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    CHECK_EQ_INT(g_snapshot_clear_calls, 2);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
    ts_rm_rf(root);

    CHECK_EQ_INT(make_snapshot_fixture(root, sizeof(root), key, sizeof(key),
                                       &account, &config), 0);
    config.mode = SSH_AGENT_NONE;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    CHECK_EQ_INT(g_snapshot_clear_calls, 3);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
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
    RUN_TEST(real_name_max_private_component_blocks_pub_sibling_lookup);
    RUN_TEST(real_isolated_agent_does_not_autoload_a_sibling_certificate);
    RUN_TEST(real_encrypted_snapshot_uses_askpass_exactly_once);
    RUN_TEST(real_maximum_stored_comment_verifies_exact_fingerprint);
TEST_MAIN_END()
