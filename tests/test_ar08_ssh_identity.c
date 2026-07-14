/* AR-08 T11: exact SSH identity-set and truthful system-agent replacement. */

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

#define SYSTEM_FP "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define FOREIGN_FP "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

typedef enum {
    SYSTEM_RUN_EXACT,
    SYSTEM_RUN_CLEAR_FAILURE,
    SYSTEM_RUN_EXTRA_IDENTITY
} system_run_mode_t;

static system_run_mode_t g_system_mode;
static int g_system_clear_calls;
static int g_system_load_calls;
static int g_system_list_calls;
static bool g_system_load_used_key_only;
static const char *g_system_loaded_fp;
static bool g_swap_key_after_load;
static bool g_swap_key_on_open;
static char g_swap_key_path[MAX_PATH_LEN];
static char g_swap_key_replacement[MAX_PATH_LEN];
static int g_snapshot_clear_calls;
static bool g_snapshot_clear_was_zero;
static bool g_snapshot_clear_fd_was_open;
static int g_snapshot_cleared_fd;

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

static const char *generation_fingerprint(const char *const argv[],
                                          const run_opts_t *opts) {
    char data[256];
    size_t length = 0;

    memset(data, 0, sizeof(data));
    if (opts && opts->input && opts->input_len > 0) {
        length = opts->input_len < sizeof(data) - 1
                     ? opts->input_len
                     : sizeof(data) - 1;
        memcpy(data, opts->input, length);
    } else if (opts && opts->use_stdin_fd && opts->stdin_fd >= 0) {
        ssize_t n = pread(opts->stdin_fd, data, sizeof(data) - 1, 0);
        if (n > 0) length = (size_t)n;
    } else if (argv && argv[2]) {
        FILE *stream = fopen(argv[2], "r");
        if (stream) {
            length = fread(data, 1, sizeof(data) - 1, stream);
            fclose(stream);
        }
    }
    data[length] = '\0';
    return strstr(data, "generation-b") ? FOREIGN_FP : SYSTEM_FP;
}

static int swapping_key_open(const char *path, int flags) {
    int fd = open(path, flags);

    if (fd >= 0 && g_swap_key_on_open &&
        strcmp(path, g_swap_key_path) == 0) {
        g_swap_key_on_open = false;
        if (rename(g_swap_key_replacement, g_swap_key_path) != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void runner_output(const run_opts_t *opts, run_result_t *result,
                          const char *text) {
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", text ? text : "");
        if (result) result->out_len = strlen(opts->out);
    }
}

static int system_identity_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (argv && argv[0] && strcmp(argv[0], "ssh-add") == 0) {
        if (argv[1] && strcmp(argv[1], "-D") == 0) {
            g_system_clear_calls++;
            if (g_system_mode == SYSTEM_RUN_CLEAR_FAILURE) {
                runner_output(opts, result, "agent refused clear\n");
                if (result) result->exit_code = 1;
                return -1;
            }
            return 0;
        }
        if (argv[1] && strcmp(argv[1], "-l") == 0) {
            g_system_list_calls++;
            if (g_system_mode == SYSTEM_RUN_EXTRA_IDENTITY) {
                runner_output(
                    opts, result,
                    "256 " SYSTEM_FP " requested (ED25519)\n"
                    "256 " FOREIGN_FP " foreign (ED25519)\n");
            } else {
                char listing[512];
                snprintf(listing, sizeof(listing),
                         "256 %s requested (ED25519)\n",
                         g_system_loaded_fp ? g_system_loaded_fp : SYSTEM_FP);
                runner_output(opts, result, listing);
            }
            return 0;
        }

        /* Recognize both the historical `ssh-add path` call and the remediated
         * `ssh-add -k path` call so this regression fails causally on argv. */
        if (argv[1] && strcmp(argv[1], "-k") == 0 && argv[2]) {
            g_system_load_used_key_only = true;
            g_system_load_calls++;
            g_system_loaded_fp = generation_fingerprint(argv, opts);
            if (g_swap_key_after_load) {
                g_swap_key_after_load = false;
                if (rename(g_swap_key_replacement, g_swap_key_path) != 0) {
                    return -1;
                }
            }
            return 0;
        }
        if (argv[1] && argv[1][0] != '-') {
            g_system_load_used_key_only = false;
            g_system_load_calls++;
            return 0;
        }
    }
    if (argv && argv[0] && strcmp(argv[0], "ssh-keygen") == 0 &&
        argv[1] && strcmp(argv[1], "-lf") == 0) {
        char fingerprint[512];
        snprintf(fingerprint, sizeof(fingerprint),
                 "256 %s requested (ED25519)\n",
                 generation_fingerprint(argv, opts));
        runner_output(opts, result, fingerprint);
        return 0;
    }
    if (result) result->exit_code = 1;
    return -1;
}

static int make_system_fixture(char *root, size_t root_size,
                               char *key, size_t key_size,
                               account_t *account,
                               ssh_config_t *config) {
    static const char private_key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "generation-a\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

    if (root_size < sizeof("/tmp/gsw-ar08-ssh-system.XXXXXX")) return -1;
    snprintf(root, root_size, "/tmp/gsw-ar08-ssh-system.XXXXXX");
    if (!ts_mkdtemp(root) || chmod(root, 0700) != 0 ||
        safe_snprintf(key, key_size, "%s/id_test", root) != 0 ||
        write_string_to_file(key, private_key, 0600) != 0) {
        return -1;
    }
    memset(account, 0, sizeof(*account));
    account->id = 1;
    account->ssh_enabled = true;
    if (safe_strncpy(account->name, "system", sizeof(account->name)) != 0 ||
        safe_strncpy(account->email, "system@example.test",
                     sizeof(account->email)) != 0 ||
        safe_strncpy(account->ssh_key_path, key,
                     sizeof(account->ssh_key_path)) != 0) {
        return -1;
    }
    memset(config, 0, sizeof(*config));
    config->mode = SSH_AGENT_SYSTEM;
    config->agent_pid = -1;
    return safe_strncpy(config->agent_socket_path,
                        "/tmp/gitswitch-ar08-system-agent.sock",
                        sizeof(config->agent_socket_path));
}

static void reset_system_runner(system_run_mode_t mode) {
    g_system_mode = mode;
    g_system_clear_calls = 0;
    g_system_load_calls = 0;
    g_system_list_calls = 0;
    g_system_load_used_key_only = false;
    g_system_loaded_fp = SYSTEM_FP;
    g_swap_key_after_load = false;
    g_swap_key_on_open = false;
    g_swap_key_path[0] = '\0';
    g_swap_key_replacement[0] = '\0';
}

TEST(system_clear_failure_stops_before_key_load) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous;

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_CLEAR_FAILURE);
    previous = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    run_set_runner(previous);

    CHECK_EQ_INT(g_system_clear_calls, 1);
    CHECK_EQ_INT(g_system_load_calls, 0);
    CHECK_EQ_INT(g_system_list_calls, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_KEY_LOAD_FAILED);
    CHECK(strstr(get_last_error()->message, "Failed to clear SSH agent") !=
          NULL);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
}

TEST(system_switch_requires_key_only_argv_and_exact_final_set) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous;

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_EXACT);
    previous = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    run_set_runner(previous);

    CHECK_EQ_INT(g_system_clear_calls, 1);
    CHECK_EQ_INT(g_system_load_calls, 1);
    CHECK(g_system_load_used_key_only);
    CHECK_EQ_INT(g_system_list_calls, 1);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
}

TEST(system_switch_rejects_a_contaminated_post_load_identity_set) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous;

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_EXTRA_IDENTITY);
    previous = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    run_set_runner(previous);

    CHECK_EQ_INT(g_system_clear_calls, 1);
    CHECK_EQ_INT(g_system_load_calls, 1);
    CHECK(g_system_load_used_key_only);
    CHECK_EQ_INT(g_system_list_calls, 1);
    CHECK_EQ_INT(get_last_error()->code, ERR_SSH_KEY_LOAD_FAILED);
    CHECK(strstr(get_last_error()->message, "exactly the requested key") !=
          NULL);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
}

static int prepare_key_replacement(const char *key) {
    static const char replacement[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "generation-b\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

    if (safe_strncpy(g_swap_key_path, key,
                     sizeof(g_swap_key_path)) != 0 ||
        safe_snprintf(g_swap_key_replacement,
                      sizeof(g_swap_key_replacement), "%s.replacement",
                      key) != 0) {
        return -1;
    }
    return write_string_to_file(g_swap_key_replacement, replacement, 0600);
}

/* The open seam swaps the configured name after open() returns. Admission
 * must retain the opened generation; loading by the pathname would silently
 * put generation B in the agent while claiming generation A was validated. */
TEST(system_switch_loads_the_descriptor_admitted_generation) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;
    ssh_key_open_fn previous_open;

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_EXACT);
    CHECK_EQ_INT(prepare_key_replacement(key), 0);
    g_swap_key_on_open = true;
    previous_open = ssh_manager_set_key_open_fn(swapping_key_open);
    previous_runner = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    run_set_runner(previous_runner);
    ssh_manager_set_key_open_fn(previous_open);

    CHECK(!g_swap_key_on_open);
    CHECK_EQ_INT(g_system_load_calls, 1);
    CHECK_STR_EQ(g_system_loaded_fp, SYSTEM_FP);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    ts_rm_rf(root);
}

/* Replacing the public name after ssh-add consumed generation A must not make
 * post-load verification fingerprint generation B or reject the good load. */
TEST(system_switch_verifies_the_loaded_descriptor_generation) {
    char root[128], key[256];
    account_t account;
    ssh_config_t config;
    command_runner_fn previous_runner;

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_EXACT);
    CHECK_EQ_INT(prepare_key_replacement(key), 0);
    g_swap_key_after_load = true;
    previous_runner = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    run_set_runner(previous_runner);

    CHECK(!g_swap_key_after_load);
    CHECK_EQ_INT(g_system_load_calls, 1);
    CHECK_EQ_INT(g_system_list_calls, 1);
    CHECK_STR_EQ(g_system_loaded_fp, SYSTEM_FP);
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    ts_rm_rf(root);
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

    /* Failure before load. */
    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_CLEAR_FAILURE);
    previous_runner = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(g_snapshot_clear_calls, 1);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
    ts_rm_rf(root);

    /* Failure after load and fingerprint/list verification. */
    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    reset_system_runner(SYSTEM_RUN_EXTRA_IDENTITY);
    previous_runner = run_set_runner(system_identity_runner);
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    run_set_runner(previous_runner);
    CHECK_EQ_INT(g_snapshot_clear_calls, 2);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
    ts_rm_rf(root);

    /* Invalid post-capture dispatch and the normal success exit share the
     * same scrub-and-close funnel. */
    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    config.mode = (ssh_agent_mode_t)99;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), -1);
    CHECK_EQ_INT(g_snapshot_clear_calls, 3);
    CHECK(g_snapshot_clear_was_zero);
    CHECK(g_snapshot_clear_fd_was_open);
    CHECK(fcntl(g_snapshot_cleared_fd, F_GETFD, 0) < 0 && errno == EBADF);
    ts_rm_rf(root);

    CHECK_EQ_INT(make_system_fixture(root, sizeof(root), key, sizeof(key),
                                     &account, &config), 0);
    config.mode = SSH_AGENT_NONE;
    CHECK_EQ_INT(ssh_switch_account(&config, &account), 0);
    CHECK_EQ_INT(g_snapshot_clear_calls, 4);
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

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(system_clear_failure_stops_before_key_load);
    RUN_TEST(system_switch_requires_key_only_argv_and_exact_final_set);
    RUN_TEST(system_switch_rejects_a_contaminated_post_load_identity_set);
    RUN_TEST(system_switch_loads_the_descriptor_admitted_generation);
    RUN_TEST(system_switch_verifies_the_loaded_descriptor_generation);
    RUN_TEST(snapshot_is_wiped_and_descriptor_closed_on_postcapture_exits);
    RUN_TEST(real_isolated_agent_does_not_autoload_a_sibling_certificate);
    RUN_TEST(real_encrypted_snapshot_uses_askpass_exactly_once);
TEST_MAIN_END()
