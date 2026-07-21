/* AR-11 M11a: one trusted OpenPGP executable per manager transaction. */
#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TEST_GPG_FINGERPRINT "0123456789ABCDEF0123456789ABCDEF01234567"
#define TEST_GPG_LISTING                                                     \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" TEST_GPG_FINGERPRINT ":\n"

typedef struct {
    char *value;
    bool present;
} saved_environment_t;

static char g_observed_program[MAX_PATH_LEN];
static int g_observed_listing_calls;

static int save_environment(const char *name, saved_environment_t *saved) {
    const char *value;

    if (!name || !saved) return -1;
    memset(saved, 0, sizeof(*saved));
    value = getenv(name);
    saved->present = value != NULL;
    if (value) {
        saved->value = strdup(value);
        if (!saved->value) return -1;
    }
    return 0;
}

static int restore_environment(const char *name, saved_environment_t *saved) {
    int rc;

    if (!name || !saved) return -1;
    rc = saved->present ? setenv(name, saved->value, 1) : unsetenv(name);
    free(saved->value);
    memset(saved, 0, sizeof(*saved));
    return rc;
}

static bool make_program_fixture(char *root, size_t root_size,
                                 char *bin, size_t bin_size) {
    char template_path[MAX_PATH_LEN];
    int written;

    if (!ts_mkdtemp_trusted(template_path, sizeof(template_path),
                            "gitswitch-ar11-gpg")) {
        return false;
    }
    written = snprintf(root, root_size, "%s", template_path);
    if (written < 0 || (size_t)written >= root_size) return false;
    written = snprintf(bin, bin_size, "%s/bin", root);
    if (written < 0 || (size_t)written >= bin_size) return false;
    return mkdir(bin, 0700) == 0;
}

static int install_program(const char *bin, const char *name,
                           char *path, size_t path_size) {
    int written;

    written = snprintf(path, path_size, "%s/%s", bin, name);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return write_string_to_file(path, "#!/bin/sh\nexit 0\n", 0700);
}

static bool argv_contains(const char *const argv[], const char *value) {
    size_t i;

    if (!argv || !value) return false;
    for (i = 0; argv[i]; i++) {
        if (strcmp(argv[i], value) == 0) return true;
    }
    return false;
}

static int recording_listing_runner(const char *const argv[],
                                    const run_opts_t *opts,
                                    run_result_t *result) {
    size_t listing_size = sizeof(TEST_GPG_LISTING) - 1U;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    /* The switch may grow adjacent Git publication calls. They are outside
     * this test's boundary and must neither fail nor replace the observed GPG
     * executable. Record only the causal secret-key listing invocation. */
    if (!argv_contains(argv, "--list-secret-keys")) return 0;
    if (!argv || !argv[0] ||
        snprintf(g_observed_program, sizeof(g_observed_program), "%s",
                 argv[0]) < 0) {
        return -1;
    }
    if (!opts || !opts->out || opts->out_size <= listing_size) {
        return -1;
    }
    memcpy(opts->out, TEST_GPG_LISTING, listing_size + 1U);
    g_observed_listing_calls++;
    if (result) {
        result->exit_code = 0;
        result->out_len = listing_size;
    }
    return 0;
}

TEST(resolver_prefers_trusted_gpg_over_gpg2) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char gpg[MAX_PATH_LEN];
    char gpg2[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    saved_environment_t path_environment;

    if (save_environment("PATH", &path_environment) != 0) {
        CHECK(!"failed to save PATH");
        return;
    }
    if (!make_program_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        install_program(bin, "gpg", gpg, sizeof(gpg)) != 0 ||
        install_program(bin, "gpg2", gpg2, sizeof(gpg2)) != 0 ||
        setenv("PATH", bin, 1) != 0) {
        CHECK(!"failed to prepare trusted GPG priority fixture");
        CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
        return;
    }

    CHECK_EQ_INT(gpg_manager_resolve_executable(resolved, sizeof(resolved)),
                 0);
    CHECK_STR_EQ(resolved, gpg);
    CHECK(strcmp(resolved, gpg2) != 0);
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST(resolver_accepts_trusted_gpg2_when_gpg_is_absent) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char gpg2[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    saved_environment_t path_environment;

    if (save_environment("PATH", &path_environment) != 0) {
        CHECK(!"failed to save PATH");
        return;
    }
    if (!make_program_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        install_program(bin, "gpg2", gpg2, sizeof(gpg2)) != 0 ||
        setenv("PATH", bin, 1) != 0) {
        CHECK(!"failed to prepare trusted gpg2-only fixture");
        CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
        return;
    }

    CHECK_EQ_INT(gpg_manager_resolve_executable(resolved, sizeof(resolved)),
                 0);
    CHECK_STR_EQ(resolved, gpg2);
    CHECK(resolved[0] == '/');
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST(resolver_skips_launch_ineligible_gpg_for_gpg2) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char gpg[MAX_PATH_LEN];
    char gpg2[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    saved_environment_t path_environment;

    if (save_environment("PATH", &path_environment) != 0) {
        CHECK(!"failed to save PATH");
        return;
    }
    if (!make_program_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        install_program(bin, "gpg", gpg, sizeof(gpg)) != 0 ||
        install_program(bin, "gpg2", gpg2, sizeof(gpg2)) != 0 ||
        write_string_to_file(gpg, "not an executable format\n", 0700) != 0 ||
        setenv("PATH", bin, 1) != 0) {
        CHECK(!"failed to prepare ineligible-gpg fallback fixture");
        CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
        return;
    }

    CHECK_EQ_INT(gpg_manager_resolve_executable(resolved, sizeof(resolved)),
                 0);
    CHECK_STR_EQ(resolved, gpg2);
    CHECK(strcmp(resolved, gpg) != 0);
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST(system_key_rejects_invalid_selector_before_dependency_lookup) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE] = "sentinel";
    saved_environment_t path_environment;

    if (save_environment("PATH", &path_environment) != 0) {
        CHECK(!"failed to save PATH");
        return;
    }
    if (!make_program_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        setenv("PATH", bin, 1) != 0) {
        CHECK(!"failed to prepare dependency-free argument fixture");
        CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
        return;
    }

    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     NULL, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(fingerprint[0] == '\0');

    memcpy(fingerprint, "sentinel", sizeof("sentinel"));
    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "", true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    CHECK(fingerprint[0] == '\0');
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST(fatal_gpg_probe_does_not_fall_back_to_gpg2) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char gpg2[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN] = "sentinel";
    saved_environment_t path_environment;
    int rc;

    if (save_environment("PATH", &path_environment) != 0) {
        CHECK(!"failed to save PATH");
        return;
    }
    if (!make_program_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        install_program(bin, "gpg2", gpg2, sizeof(gpg2)) != 0 ||
        setenv("PATH", bin, 1) != 0) {
        CHECK(!"failed to prepare fatal-probe fixture");
        CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
        return;
    }

    clear_error();
    errno = 0;
    run_test_set_path_candidate_failure(1, EIO);
    rc = gpg_manager_resolve_executable(resolved, sizeof(resolved));
    run_test_set_path_candidate_failure(0, 0);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(errno, EIO);
    CHECK(resolved[0] == '\0');
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_NOT_FOUND);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST(manager_uses_retained_program_after_path_changes) {
    char root[MAX_PATH_LEN];
    char bin_a[MAX_PATH_LEN];
    char bin_b[MAX_PATH_LEN];
    char program_a[MAX_PATH_LEN];
    char program_b[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    char runtime_home[MAX_PATH_LEN];
    char current_resolution[MAX_PATH_LEN];
    saved_environment_t path_environment;
    saved_environment_t gnupg_environment;
    saved_environment_t runtime_environment;
    gpg_config_t config;
    account_t account;
    command_runner_fn previous_runner;
    int written;
    int switch_rc;

    if (save_environment("PATH", &path_environment) != 0 ||
        save_environment("GNUPGHOME", &gnupg_environment) != 0 ||
        save_environment("XDG_RUNTIME_DIR", &runtime_environment) != 0) {
        CHECK(!"failed to save manager environment");
        return;
    }
    if (!ts_mkdtemp_trusted(root, sizeof(root), "gitswitch-ar11-gpg-use")) {
        CHECK(!"failed to create trusted manager fixture");
        goto restore_environment;
    }
    written = snprintf(bin_a, sizeof(bin_a), "%s/bin-a", root);
    if (written < 0 || (size_t)written >= sizeof(bin_a) ||
        mkdir(bin_a, 0700) != 0) {
        CHECK(!"failed to create first trusted PATH directory");
        goto restore_environment;
    }
    written = snprintf(bin_b, sizeof(bin_b), "%s/bin-b", root);
    if (written < 0 || (size_t)written >= sizeof(bin_b) ||
        mkdir(bin_b, 0700) != 0) {
        CHECK(!"failed to create second trusted PATH directory");
        goto restore_environment;
    }
    written = snprintf(source_home, sizeof(source_home), "%s/source", root);
    if (written < 0 || (size_t)written >= sizeof(source_home) ||
        mkdir(source_home, 0700) != 0) {
        CHECK(!"failed to create source keyring fixture");
        goto restore_environment;
    }
    written = snprintf(runtime_home, sizeof(runtime_home), "%s/runtime", root);
    if (written < 0 || (size_t)written >= sizeof(runtime_home) ||
        mkdir(runtime_home, 0700) != 0 ||
        install_program(bin_a, "gpg", program_a, sizeof(program_a)) != 0 ||
        install_program(bin_b, "gpg", program_b, sizeof(program_b)) != 0 ||
        setenv("PATH", bin_a, 1) != 0 ||
        setenv("GNUPGHOME", source_home, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", runtime_home, 1) != 0) {
        CHECK(!"failed to complete manager fixture");
        goto restore_environment;
    }

    memset(&config, 0, sizeof(config));
    CHECK_EQ_INT(gpg_manager_init(&config, GPG_MODE_SYSTEM), 0);
    CHECK_STR_EQ(config.executable_path, program_a);
    if (config.executable_path[0] == '\0') goto restore_environment;

    CHECK_EQ_INT(setenv("PATH", bin_b, 1), 0);
    CHECK_EQ_INT(gpg_manager_resolve_executable(
                     current_resolution, sizeof(current_resolution)),
                 0);
    CHECK_STR_EQ(current_resolution, program_b);
    CHECK_STR_EQ(config.executable_path, program_a);

    memset(&account, 0, sizeof(account));
    (void)snprintf(account.name, sizeof(account.name), "retained-program");
    (void)snprintf(account.email, sizeof(account.email),
                   "retained-program@example.test");
    (void)snprintf(account.gpg_key_id, sizeof(account.gpg_key_id), "01234567");
    account.gpg_enabled = true;
    account.gpg_signing_enabled = true;
    g_observed_program[0] = '\0';
    g_observed_listing_calls = 0;
    clear_error();
    previous_runner = run_set_runner(recording_listing_runner);
    switch_rc = gpg_switch_account(&config, &account);
    run_set_runner(previous_runner);

    CHECK_EQ_INT(switch_rc, 0);
    CHECK_EQ_INT(g_observed_listing_calls, 1);
    CHECK_STR_EQ(g_observed_program, program_a);
    CHECK(strcmp(g_observed_program, program_b) != 0);
    CHECK_STR_EQ(config.executable_path, program_a);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);

restore_environment:
    CHECK_EQ_INT(restore_environment("XDG_RUNTIME_DIR",
                                     &runtime_environment), 0);
    CHECK_EQ_INT(restore_environment("GNUPGHOME", &gnupg_environment), 0);
    CHECK_EQ_INT(restore_environment("PATH", &path_environment), 0);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(resolver_prefers_trusted_gpg_over_gpg2);
    RUN_TEST(resolver_accepts_trusted_gpg2_when_gpg_is_absent);
    RUN_TEST(resolver_skips_launch_ineligible_gpg_for_gpg2);
    RUN_TEST(system_key_rejects_invalid_selector_before_dependency_lookup);
    RUN_TEST(fatal_gpg_probe_does_not_fall_back_to_gpg2);
    RUN_TEST(manager_uses_retained_program_after_path_changes);
TEST_MAIN_END()
