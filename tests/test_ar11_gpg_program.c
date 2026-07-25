/* AR-11 M11a: one trusted OpenPGP executable per manager transaction. */
#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "runner_internal.h"
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
static char g_m15_self_path[MAX_PATH_LEN];
static char g_m15_rebind_source[MAX_PATH_LEN];
static char g_m15_rebind_old[MAX_PATH_LEN];
static int g_m15_rebind_hook_calls;
static int g_m15_rebind_hook_result;
static char g_m20_mutate_path[MAX_PATH_LEN];
static int g_m20_mutate_hook_calls;
static int g_m20_mutate_hook_result;
static run_launch_witness_t g_m20_injected_witness;
static bool g_m20_injected_returns_witness;
static bool g_m20_injected_returns_mismatch;

static int m15_binary_helper_run(void) {
    const char *counter = getenv("GPG_M15_COUNTER");
    int fd;

    if (!counter || !*counter) return 120;
    fd = open(counter, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return 121;
    if (write(fd, "x", 1U) != 1) {
        close(fd);
        return 122;
    }
    if (close(fd) != 0) return 123;
    if (fputs(TEST_GPG_LISTING, stdout) == EOF || fflush(stdout) != 0) {
        return 124;
    }
    return 0;
}

static int m15_rebind_post_scan_hook(const char *home_path,
                                     bool isolated) {
    if (isolated || !home_path ||
        strcmp(home_path, g_m15_rebind_source) != 0) {
        errno = EINVAL;
        return -1;
    }
    g_m15_rebind_hook_calls++;
    if (g_m15_rebind_hook_calls != 1) return 0;
    g_m15_rebind_hook_result =
        rename(g_m15_rebind_source, g_m15_rebind_old);
    if (g_m15_rebind_hook_result == 0) {
        g_m15_rebind_hook_result = mkdir(g_m15_rebind_source, 0700);
    }
    return g_m15_rebind_hook_result;
}

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

typedef struct {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char program[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    char runtime_home[MAX_PATH_LEN];
    char counter[MAX_PATH_LEN];
    saved_environment_t path_environment;
    saved_environment_t gnupg_environment;
    saved_environment_t runtime_environment;
    saved_environment_t counter_environment;
    bool environment_saved;
} m15_fixture_t;

static void m15_fixture_cleanup(m15_fixture_t *fixture) {
    if (!fixture) return;
    if (fixture->environment_saved) {
        CHECK_EQ_INT(restore_environment("GPG_M15_COUNTER",
                                         &fixture->counter_environment), 0);
        CHECK_EQ_INT(restore_environment("XDG_RUNTIME_DIR",
                                         &fixture->runtime_environment), 0);
        CHECK_EQ_INT(restore_environment("GNUPGHOME",
                                         &fixture->gnupg_environment), 0);
        CHECK_EQ_INT(restore_environment("PATH",
                                         &fixture->path_environment), 0);
        fixture->environment_saved = false;
    }
    if (fixture->root[0]) {
        ts_rm_rf(fixture->root);
        fixture->root[0] = '\0';
    }
}

static bool m15_fixture_setup(m15_fixture_t *fixture, const char *stem) {
    if (!fixture || !stem) return false;
    memset(fixture, 0, sizeof(*fixture));
    if (save_environment("PATH", &fixture->path_environment) != 0 ||
        save_environment("GNUPGHOME", &fixture->gnupg_environment) != 0 ||
        save_environment("XDG_RUNTIME_DIR",
                         &fixture->runtime_environment) != 0 ||
        save_environment("GPG_M15_COUNTER",
                         &fixture->counter_environment) != 0) {
        return false;
    }
    fixture->environment_saved = true;
    if (!ts_mkdtemp_trusted(fixture->root, sizeof(fixture->root), stem) ||
        safe_snprintf(fixture->bin, sizeof(fixture->bin), "%s/bin",
                      fixture->root) != 0 ||
        safe_snprintf(fixture->program, sizeof(fixture->program), "%s/gpg",
                      fixture->bin) != 0 ||
        safe_snprintf(fixture->source_home, sizeof(fixture->source_home),
                      "%s/source", fixture->root) != 0 ||
        safe_snprintf(fixture->runtime_home, sizeof(fixture->runtime_home),
                      "%s/runtime", fixture->root) != 0 ||
        safe_snprintf(fixture->counter, sizeof(fixture->counter), "%s/counter",
                      fixture->root) != 0 ||
        mkdir(fixture->bin, 0700) != 0 ||
        mkdir(fixture->source_home, 0700) != 0 ||
        mkdir(fixture->runtime_home, 0700) != 0 ||
        write_string_to_file(fixture->counter, "", 0600) != 0 ||
        setenv("PATH", fixture->bin, 1) != 0 ||
        setenv("GNUPGHOME", fixture->source_home, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->runtime_home, 1) != 0 ||
        setenv("GPG_M15_COUNTER", fixture->counter, 1) != 0) {
        m15_fixture_cleanup(fixture);
        return false;
    }
    return true;
}

static int m15_write_program_output_at(const char *path,
                                       const char *interpreter,
                                       const char *interpreter_arg,
                                       const char *tag,
                                       const char *listing) {
    char program[4096];
    int written;

    if (!path || !interpreter || !tag || !listing) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf(
        program, sizeof(program),
        "#!%s%s%s\n"
        "# generation: %s\n"
        "printf x >> \"$GPG_M15_COUNTER\"\n"
        "printf '%%s' '%s'\n"
        "exit 0\n",
        interpreter, interpreter_arg && *interpreter_arg ? " " : "",
        interpreter_arg && *interpreter_arg ? interpreter_arg : "", tag,
        listing);
    if (written < 0 || (size_t)written >= sizeof(program)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return write_string_to_file(path, program, 0700);
}

static int m15_write_program_at(const char *path, const char *interpreter,
                                const char *interpreter_arg,
                                const char *tag, bool valid_listing) {
    return m15_write_program_output_at(
        path, interpreter, interpreter_arg, tag,
        valid_listing ? TEST_GPG_LISTING : "not-a-secret-key-listing\\n");
}

static int m15_replace_program(const m15_fixture_t *fixture,
                               const char *interpreter,
                               const char *interpreter_arg,
                               const char *tag, bool valid_listing) {
    char replacement[MAX_PATH_LEN];

    if (!fixture ||
        safe_snprintf(replacement, sizeof(replacement), "%s.replacement",
                      fixture->program) != 0) {
        errno = EINVAL;
        return -1;
    }
    (void)unlink(replacement);
    if (m15_write_program_at(replacement, interpreter, interpreter_arg, tag,
                             valid_listing) != 0 ||
        rename(replacement, fixture->program) != 0) {
        int saved_errno = errno;

        (void)unlink(replacement);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m15_install_binary_program(const char *source,
                                      const char *destination) {
    if (!source || !*source || !destination || !*destination) {
        errno = EINVAL;
        return -1;
    }
    if (copy_file(source, destination) != 0 ||
        chmod(destination, 0700) != 0) {
        return -1;
    }
    return 0;
}

static int m15_replace_binary_program(const m15_fixture_t *fixture) {
    char replacement[MAX_PATH_LEN];

    if (!fixture ||
        safe_snprintf(replacement, sizeof(replacement), "%s.replacement",
                      fixture->program) != 0) {
        errno = EINVAL;
        return -1;
    }
    (void)unlink(replacement);
    if (m15_install_binary_program(g_m15_self_path, replacement) != 0 ||
        rename(replacement, fixture->program) != 0) {
        int saved_errno = errno;

        (void)unlink(replacement);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static bool m20_capture_program(const char *path, char *canonical,
                                size_t canonical_size,
                                run_launch_witness_t *witness) {
    char resolved[MAX_PATH_LEN];

    if (!path || !canonical || canonical_size == 0 || !witness ||
        !realpath(path, resolved) ||
        safe_strncpy(canonical, resolved, canonical_size) != 0) {
        return false;
    }
    return run_launch_witness_capture(canonical, witness);
}

static int m20_replace_interpreter(const char *source,
                                   const char *interpreter) {
    char replacement[MAX_PATH_LEN];

    if (!source || !interpreter ||
        safe_snprintf(replacement, sizeof(replacement), "%s.replacement",
                      interpreter) != 0) {
        errno = EINVAL;
        return -1;
    }
    (void)unlink(replacement);
    if (copy_file(source, replacement) != 0 ||
        chmod(replacement, 0700) != 0 ||
        rename(replacement, interpreter) != 0) {
        int saved_errno = errno;

        (void)unlink(replacement);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void m20_mutate_opened_program_hook(const char *resolved_path) {
    if (!resolved_path || strcmp(resolved_path, g_m20_mutate_path) != 0) {
        return;
    }
    g_m20_mutate_hook_calls++;
    g_m20_mutate_hook_result = chmod(resolved_path, 0600);
}

static int m20_injected_runner(const char *const argv[],
                               const run_opts_t *opts,
                               run_result_t *result) {
    (void)argv;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        result->spawned = true;
        result->exit_code = 0;
        if (g_m20_injected_returns_witness) {
            result->launch_witness = g_m20_injected_witness;
            if (g_m20_injected_returns_mismatch) {
                result->launch_witness.executable_identity.st_ino++;
            }
        }
    }
    return 0;
}

static int m15_create_deep_home(const m15_fixture_t *fixture,
                                unsigned int depth) {
    char parent[MAX_PATH_LEN];
    unsigned int level;

    if (!fixture ||
        safe_strncpy(parent, fixture->source_home, sizeof(parent)) != 0) {
        errno = EINVAL;
        return -1;
    }
    for (level = 0; level < depth; level++) {
        char child[MAX_PATH_LEN];

        if (safe_snprintf(child, sizeof(child), "%s/d%02u", parent,
                          level) != 0 ||
            mkdir(child, 0700) != 0 ||
            safe_strncpy(parent, child, sizeof(parent)) != 0) {
            return -1;
        }
    }
    return 0;
}

static int m15_create_many_home_entries(const m15_fixture_t *fixture,
                                        unsigned int count) {
    unsigned int index;

    if (!fixture) {
        errno = EINVAL;
        return -1;
    }
    for (index = 0; index < count; index++) {
        char entry[MAX_PATH_LEN];

        if (safe_snprintf(entry, sizeof(entry), "%s/entry-%03u",
                          fixture->source_home, index) != 0 ||
            write_string_to_file(entry, "x", 0600) != 0) {
            return -1;
        }
    }
    return 0;
}

static off_t m15_listing_call_count(const m15_fixture_t *fixture) {
    struct stat counter;

    if (!fixture || stat(fixture->counter, &counter) != 0) return -1;
    return counter.st_size;
}

static int m15_resolve(bool require_signing, char *fingerprint,
                       size_t fingerprint_size) {
    return gpg_manager_resolve_system_key(
        TEST_GPG_FINGERPRINT, require_signing, fingerprint,
        fingerprint_size);
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
        if (!argv || !argv[0] ||
            !run_launch_witness_capture(
                argv[0], &result->launch_witness)) {
            return -1;
        }
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

TEST(proof_cache_reuses_unchanged_real_listing) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-hit")) {
        CHECK(!"failed to prepare M15 unchanged fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "unchanged", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, TEST_GPG_FINGERPRINT);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);

    memset(fingerprint, 0, sizeof(fingerprint));
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, TEST_GPG_FINGERPRINT);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    m15_fixture_cleanup(&fixture);
}

TEST(proof_cache_rejects_same_path_program_replacement) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-exec")) {
        CHECK(!"failed to prepare M15 executable fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "generation-h1", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_replace_program(&fixture, "/bin/sh", NULL,
                                     "generation-h2", true), 0);

    memset(fingerprint, 0, sizeof(fingerprint));
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, TEST_GPG_FINGERPRINT);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(proof_cache_rejects_untrusted_same_path_program) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-unsafe")) {
        CHECK(!"failed to prepare M15 unsafe fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "trusted-h1", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(chmod(fixture.program, 0777), 0);

    clear_error();
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_NOT_FOUND);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    m15_fixture_cleanup(&fixture);
}

TEST(proof_cache_rejects_same_path_home_replacement) {
    m15_fixture_t fixture;
    char old_home[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-home")) {
        CHECK(!"failed to prepare M15 home fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "home-generation", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK(snprintf(old_home, sizeof(old_home), "%s.old",
                   fixture.source_home) > 0);
    CHECK_EQ_INT(rename(fixture.source_home, old_home), 0);
    CHECK_EQ_INT(mkdir(fixture.source_home, 0700), 0);

    memset(fingerprint, 0, sizeof(fingerprint));
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, TEST_GPG_FINGERPRINT);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(system_proof_does_not_satisfy_isolated_home) {
    m15_fixture_t fixture;
    char base[MAX_PATH_LEN];
    char isolated_home[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    account_t account;
    gpg_account_key_readiness_t readiness;

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-context")) {
        CHECK(!"failed to prepare M15 context fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "context", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK(snprintf(base, sizeof(base), "%s/gitswitch-gpg",
                   fixture.runtime_home) > 0);
    CHECK(snprintf(isolated_home, sizeof(isolated_home), "%s/account",
                   base) > 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(isolated_home, 0700), 0);

    memset(&account, 0, sizeof(account));
    (void)snprintf(account.name, sizeof(account.name), "account");
    (void)snprintf(account.email, sizeof(account.email),
                   "account@example.test");
    (void)snprintf(account.gpg_key_id, sizeof(account.gpg_key_id), "%s",
                   TEST_GPG_FINGERPRINT);
    account.gpg_enabled = true;
    memset(&readiness, 0, sizeof(readiness));
    CHECK_EQ_INT(gpg_manager_check_account_key(&account, &readiness), 0);
    CHECK(readiness.retained_home_usable);
    CHECK_EQ_INT(readiness.source_recovery,
                 GPG_SOURCE_RECOVERY_AVAILABLE);
    /* One initial system listing plus one isolated listing. The final source
     * check may reuse the original system proof, but that proof cannot skip
     * the distinct isolated-home invocation. */
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(signing_capability_requires_its_own_proof) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-cap")) {
        CHECK(!"failed to prepare M15 capability fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "capability", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_resolve(true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(failed_listing_never_promotes_cache_entry) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-fail")) {
        CHECK(!"failed to prepare M15 failed-probe fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "malformed", false), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    CHECK_EQ_INT(m15_replace_program(&fixture, "/bin/sh", NULL,
                                     "recovered", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 3);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 3);
    m15_fixture_cleanup(&fixture);
}

TEST(unexpected_structured_listing_never_promotes_cache_entry) {
    static const char listing[] =
        TEST_GPG_LISTING
        "[GNUPG:] ERROR keybox.search 14\n";
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m19-status")) {
        CHECK(!"failed to prepare M19 structured-status fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_output_at(
                     fixture.program, "/bin/sh", NULL,
                     "unexpected-status", listing), 0);
    clear_error();
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    clear_error();
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);

    CHECK_EQ_INT(m15_replace_program(&fixture, "/bin/sh", NULL,
                                     "recovered", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, TEST_GPG_FINGERPRINT);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 3);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 3);
    m15_fixture_cleanup(&fixture);
}

TEST(expected_launch_rejects_binary_replacement_before_fork) {
    m15_fixture_t fixture;
    saved_environment_t helper_environment;
    run_launch_witness_t expected;
    run_launch_witness_t replacement;
    run_result_t result;
    char canonical[MAX_PATH_LEN];
    const char *argv[2];
    bool helper_saved = false;

    if (!g_m15_self_path[0]) {
        TS_SKIP("exec", "cannot resolve the compiled binary fixture");
    }
    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m20-binary")) {
        CHECK(!"failed to prepare M20 binary fixture");
        return;
    }
    if (save_environment("GITSWITCH_TEST_M15_BINARY_HELPER",
                         &helper_environment) != 0) {
        CHECK(!"failed to save binary-helper environment");
        m15_fixture_cleanup(&fixture);
        return;
    }
    helper_saved = true;
    if (setenv("GITSWITCH_TEST_M15_BINARY_HELPER", "1", 1) != 0 ||
        m15_install_binary_program(g_m15_self_path, fixture.program) != 0 ||
        !m20_capture_program(fixture.program, canonical,
                             sizeof(canonical), &expected) ||
        m15_replace_binary_program(&fixture) != 0 ||
        !run_launch_witness_capture(canonical, &replacement)) {
        CHECK(!"failed to prepare M20 binary replacement");
        goto cleanup;
    }

    CHECK(!run_launch_witness_matches(&expected, &replacement));
    argv[0] = canonical;
    argv[1] = NULL;
    memset(&result, 0xa5, sizeof(result));
    clear_error();
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(!result.spawned);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 0);

cleanup:
    if (helper_saved) {
        CHECK_EQ_INT(restore_environment(
                         "GITSWITCH_TEST_M15_BINARY_HELPER",
                         &helper_environment), 0);
    }
    m15_fixture_cleanup(&fixture);
}

TEST(expected_launch_rejects_script_replacement_before_fork) {
    m15_fixture_t fixture;
    run_launch_witness_t expected;
    run_launch_witness_t replacement;
    run_result_t result;
    char canonical[MAX_PATH_LEN];
    const char *argv[2];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m20-script")) {
        CHECK(!"failed to prepare M20 script fixture");
        return;
    }
    if (m15_write_program_at(fixture.program, "/bin/sh", NULL,
                             "script-generation-a", true) != 0 ||
        !m20_capture_program(fixture.program, canonical,
                             sizeof(canonical), &expected) ||
        m15_replace_program(&fixture, "/bin/sh", NULL,
                            "script-generation-b", true) != 0 ||
        !run_launch_witness_capture(canonical, &replacement)) {
        CHECK(!"failed to prepare M20 script replacement");
        m15_fixture_cleanup(&fixture);
        return;
    }

    CHECK(expected.is_script);
    CHECK(!run_launch_witness_matches(&expected, &replacement));
    errno = 0;
    CHECK(!run_launch_witness_revalidate(canonical, &expected));
    CHECK_EQ_INT(errno, ESTALE);
    argv[0] = canonical;
    argv[1] = NULL;
    memset(&result, 0xa5, sizeof(result));
    clear_error();
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(!result.spawned);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 0);
    m15_fixture_cleanup(&fixture);
}

TEST(expected_launch_rejects_interpreter_replacement_before_fork) {
    m15_fixture_t fixture;
    run_launch_witness_t expected;
    run_launch_witness_t replacement;
    run_result_t result;
    char shell[MAX_PATH_LEN];
    char interpreter[MAX_PATH_LEN];
    char canonical[MAX_PATH_LEN];
    const char *argv[2];

    if (!m15_fixture_setup(&fixture,
                           "gitswitch-ar14-m20-interpreter")) {
        CHECK(!"failed to prepare M20 interpreter fixture");
        return;
    }
    if (find_command_path("/bin/sh", shell, sizeof(shell)) != 0 ||
        safe_snprintf(interpreter, sizeof(interpreter), "%s/interpreter",
                      fixture.bin) != 0 ||
        strlen(interpreter) >= 240U) {
        m15_fixture_cleanup(&fixture);
        TS_SKIP("exec", "trusted interpreter fixture is unavailable");
    }
    if (copy_file(shell, interpreter) != 0 ||
        chmod(interpreter, 0700) != 0 ||
        m15_write_program_at(fixture.program, interpreter, "-e",
                             "interpreter-generation", true) != 0 ||
        !m20_capture_program(fixture.program, canonical,
                             sizeof(canonical), &expected) ||
        m20_replace_interpreter(shell, interpreter) != 0 ||
        !run_launch_witness_capture(canonical, &replacement)) {
        CHECK(!"failed to prepare M20 interpreter replacement");
        m15_fixture_cleanup(&fixture);
        return;
    }

    CHECK(expected.is_script);
    CHECK(expected.has_interpreter_arg);
    CHECK_STR_EQ(expected.interpreter_arg, "-e");
    CHECK(!run_launch_witness_matches(&expected, &replacement));
    argv[0] = canonical;
    argv[1] = NULL;
    memset(&result, 0xa5, sizeof(result));
    clear_error();
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(!result.spawned);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 0);
    m15_fixture_cleanup(&fixture);
}

TEST(expected_launch_rechecks_opened_generation_before_fork) {
    m15_fixture_t fixture;
    run_launch_witness_t expected;
    run_result_t result;
    char canonical[MAX_PATH_LEN];
    const char *argv[2];
    int run_rc;

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m20-opened")) {
        CHECK(!"failed to prepare M20 opened-generation fixture");
        return;
    }
    if (m15_write_program_at(fixture.program, "/bin/sh", NULL,
                             "opened-generation", true) != 0 ||
        !m20_capture_program(fixture.program, canonical,
                             sizeof(canonical), &expected) ||
        safe_strncpy(g_m20_mutate_path, canonical,
                     sizeof(g_m20_mutate_path)) != 0) {
        CHECK(!"failed to prepare M20 opened-generation witness");
        m15_fixture_cleanup(&fixture);
        return;
    }

    g_m20_mutate_hook_calls = 0;
    g_m20_mutate_hook_result = -1;
    argv[0] = canonical;
    argv[1] = NULL;
    memset(&result, 0xa5, sizeof(result));
    clear_error();
    run_test_set_exec_resolved_hook(m20_mutate_opened_program_hook);
    run_rc = run_argv_with_expected_launch(
        argv, NULL, &expected, &result);
    run_test_set_exec_resolved_hook(NULL);

    CHECK_EQ_INT(g_m20_mutate_hook_calls, 1);
    CHECK_EQ_INT(g_m20_mutate_hook_result, 0);
    CHECK_EQ_INT(run_rc, -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(!result.spawned);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 0);
    m15_fixture_cleanup(&fixture);
}

TEST(injected_expected_launch_requires_matching_witness) {
    m15_fixture_t fixture;
    run_launch_witness_t expected;
    run_result_t result;
    command_runner_fn previous_runner;
    char canonical[MAX_PATH_LEN];
    const char *argv[2];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m20-injected")) {
        CHECK(!"failed to prepare M20 injected-runner fixture");
        return;
    }
    if (m15_write_program_at(fixture.program, "/bin/sh", NULL,
                             "injected-runner", true) != 0 ||
        !m20_capture_program(fixture.program, canonical,
                             sizeof(canonical), &expected)) {
        CHECK(!"failed to capture M20 injected-runner witness");
        m15_fixture_cleanup(&fixture);
        return;
    }

    argv[0] = canonical;
    argv[1] = NULL;
    g_m20_injected_witness = expected;
    g_m20_injected_returns_witness = false;
    g_m20_injected_returns_mismatch = false;
    previous_runner = run_set_runner(m20_injected_runner);

    memset(&result, 0, sizeof(result));
    CHECK_EQ_INT(run_argv(argv, NULL, &result), 0);
    CHECK(!result.launch_witness.valid);

    memset(&result, 0, sizeof(result));
    clear_error();
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);

    g_m20_injected_returns_witness = true;
    g_m20_injected_returns_mismatch = true;
    memset(&result, 0, sizeof(result));
    clear_error();
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);

    g_m20_injected_returns_mismatch = false;
    memset(&result, 0, sizeof(result));
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, &result), 0);
    CHECK(run_launch_witness_matches(
        &expected, &result.launch_witness));
    CHECK_EQ_INT(run_argv_with_expected_launch(
                     argv, NULL, &expected, NULL), 0);

    run_set_runner(previous_runner);
    m15_fixture_cleanup(&fixture);
}

TEST(script_cache_binds_same_path_interpreter_generation) {
    m15_fixture_t fixture;
    char shell[MAX_PATH_LEN];
    char interpreter[MAX_PATH_LEN];
    char replacement[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-script")) {
        CHECK(!"failed to prepare M15 script fixture");
        return;
    }
    CHECK_EQ_INT(find_command_path("/bin/sh", shell, sizeof(shell)), 0);
    CHECK(snprintf(interpreter, sizeof(interpreter), "%s/interpreter",
                   fixture.bin) > 0);
    CHECK(snprintf(replacement, sizeof(replacement), "%s.replacement",
                   interpreter) > 0);
    if (strlen(interpreter) >= 240U) {
        m15_fixture_cleanup(&fixture);
        TS_SKIP("exec", "trusted fixture path is too long for a shebang");
    }
    CHECK_EQ_INT(copy_file(shell, interpreter), 0);
    CHECK_EQ_INT(chmod(interpreter, 0700), 0);
    CHECK_EQ_INT(m15_write_program_at(fixture.program, interpreter, "-e",
                                      "script-interpreter", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);

    (void)unlink(replacement);
    CHECK_EQ_INT(copy_file(shell, replacement), 0);
    CHECK_EQ_INT(chmod(replacement, 0700), 0);
    CHECK_EQ_INT(rename(replacement, interpreter), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(selector_only_note_never_authorizes_production_cache) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-note")) {
        CHECK(!"failed to prepare M15 selector-note fixture");
        return;
    }
    CHECK(run_uses_default_runner());
    gpg_manager_note_key_available(TEST_GPG_FINGERPRINT);
    CHECK(!gpg_manager_key_available_cached(TEST_GPG_FINGERPRINT));
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "selector-note", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    m15_fixture_cleanup(&fixture);
}

TEST(cache_hit_revalidates_public_source_binding_after_final_scan) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    gpg_key_cache_post_scan_hook_fn previous_hook;
    int resolve_rc;

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-rebind")) {
        CHECK(!"failed to prepare M15 source-rebind fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "source-rebind", true), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(safe_strncpy(g_m15_rebind_source, fixture.source_home,
                              sizeof(g_m15_rebind_source)), 0);
    CHECK_EQ_INT(safe_snprintf(g_m15_rebind_old,
                               sizeof(g_m15_rebind_old), "%s.old",
                               fixture.source_home), 0);
    g_m15_rebind_hook_calls = 0;
    g_m15_rebind_hook_result = -1;
    previous_hook = gpg_manager_set_key_cache_post_scan_hook_fn(
        m15_rebind_post_scan_hook);
    clear_error();
    resolve_rc = m15_resolve(false, fingerprint, sizeof(fingerprint));
    gpg_manager_set_key_cache_post_scan_hook_fn(previous_hook);

    CHECK_EQ_INT(g_m15_rebind_hook_calls, 1);
    CHECK_EQ_INT(g_m15_rebind_hook_result, 0);
    CHECK_EQ_INT(resolve_rc, -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    m15_fixture_cleanup(&fixture);
}

TEST(symlink_backed_home_content_is_never_cached) {
    m15_fixture_t fixture;
    char target[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-symlink")) {
        CHECK(!"failed to prepare M15 symlink fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "symlink-home", true), 0);
    CHECK_EQ_INT(safe_snprintf(target, sizeof(target), "%s/linked-content",
                               fixture.root), 0);
    CHECK_EQ_INT(safe_snprintf(link_path, sizeof(link_path), "%s/keybox-link",
                               fixture.source_home), 0);
    CHECK_EQ_INT(write_string_to_file(target, "keybox-content", 0600), 0);
    CHECK_EQ_INT(symlink(target, link_path), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    m15_fixture_cleanup(&fixture);
}

TEST(binary_cache_binds_same_path_executable_generation) {
    m15_fixture_t fixture;
    saved_environment_t helper_environment;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!g_m15_self_path[0]) {
        TS_SKIP("exec", "cannot resolve the compiled test helper");
    }
    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-binary")) {
        CHECK(!"failed to prepare M15 binary fixture");
        return;
    }
    if (save_environment("GITSWITCH_TEST_M15_BINARY_HELPER",
                         &helper_environment) != 0) {
        m15_fixture_cleanup(&fixture);
        CHECK(!"failed to save binary-helper environment");
        return;
    }
    if (setenv("GITSWITCH_TEST_M15_BINARY_HELPER", "1", 1) != 0 ||
        m15_install_binary_program(g_m15_self_path, fixture.program) != 0) {
        CHECK(!"failed to install compiled GPG fixture");
        CHECK_EQ_INT(restore_environment("GITSWITCH_TEST_M15_BINARY_HELPER",
                                         &helper_environment), 0);
        m15_fixture_cleanup(&fixture);
        return;
    }
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_replace_binary_program(&fixture), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 2);
    CHECK_EQ_INT(restore_environment("GITSWITCH_TEST_M15_BINARY_HELPER",
                                     &helper_environment), 0);
    m15_fixture_cleanup(&fixture);
}

TEST(signing_proof_satisfies_later_general_lookup) {
    m15_fixture_t fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&fixture, "gitswitch-ar14-m15-strong-weak")) {
        CHECK(!"failed to prepare M15 strong-to-weak fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(fixture.program, "/bin/sh", NULL,
                                      "strong-to-weak", true), 0);
    CHECK_EQ_INT(m15_resolve(true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&fixture), 1);
    m15_fixture_cleanup(&fixture);
}

TEST(cache_bounds_fall_back_to_authoritative_listing) {
    m15_fixture_t depth_fixture;
    m15_fixture_t entry_fixture;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!m15_fixture_setup(&depth_fixture,
                           "gitswitch-ar14-m15-depth")) {
        CHECK(!"failed to prepare M15 depth-bound fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(depth_fixture.program, "/bin/sh", NULL,
                                      "depth-bound", true), 0);
    CHECK_EQ_INT(m15_create_deep_home(&depth_fixture, 18U), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&depth_fixture), 2);
    m15_fixture_cleanup(&depth_fixture);

    if (!m15_fixture_setup(&entry_fixture,
                           "gitswitch-ar14-m15-entries")) {
        CHECK(!"failed to prepare M15 entry-bound fixture");
        return;
    }
    CHECK_EQ_INT(m15_write_program_at(entry_fixture.program, "/bin/sh", NULL,
                                      "entry-bound", true), 0);
    CHECK_EQ_INT(m15_create_many_home_entries(&entry_fixture, 520U), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT(m15_resolve(false, fingerprint, sizeof(fingerprint)), 0);
    CHECK_EQ_INT((int)m15_listing_call_count(&entry_fixture), 2);
    m15_fixture_cleanup(&entry_fixture);
}

int main(int argc, char *argv[]) {
    char *resolved;

    if (argc > 0 && argv && argv[0] &&
        getenv("GITSWITCH_TEST_M15_BINARY_HELPER")) {
        const char *base = strrchr(argv[0], '/');

        if (strcmp(base ? base + 1 : argv[0], "gpg") == 0) {
            return m15_binary_helper_run();
        }
    }
    (void)unsetenv("GNUPGHOME");
    resolved = argc > 0 && argv && argv[0]
                   ? realpath(argv[0], g_m15_self_path)
                   : NULL;
    if (!resolved) g_m15_self_path[0] = '\0';
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(resolver_prefers_trusted_gpg_over_gpg2);
    RUN_TEST(resolver_accepts_trusted_gpg2_when_gpg_is_absent);
    RUN_TEST(resolver_skips_launch_ineligible_gpg_for_gpg2);
    RUN_TEST(system_key_rejects_invalid_selector_before_dependency_lookup);
    RUN_TEST(fatal_gpg_probe_does_not_fall_back_to_gpg2);
    RUN_TEST(manager_uses_retained_program_after_path_changes);
    RUN_TEST(proof_cache_reuses_unchanged_real_listing);
    RUN_TEST(proof_cache_rejects_same_path_program_replacement);
    RUN_TEST(proof_cache_rejects_untrusted_same_path_program);
    RUN_TEST(proof_cache_rejects_same_path_home_replacement);
    RUN_TEST(system_proof_does_not_satisfy_isolated_home);
    RUN_TEST(signing_capability_requires_its_own_proof);
    RUN_TEST(failed_listing_never_promotes_cache_entry);
    RUN_TEST(unexpected_structured_listing_never_promotes_cache_entry);
    RUN_TEST(expected_launch_rejects_binary_replacement_before_fork);
    RUN_TEST(expected_launch_rejects_script_replacement_before_fork);
    RUN_TEST(expected_launch_rejects_interpreter_replacement_before_fork);
    RUN_TEST(expected_launch_rechecks_opened_generation_before_fork);
    RUN_TEST(injected_expected_launch_requires_matching_witness);
    RUN_TEST(script_cache_binds_same_path_interpreter_generation);
    RUN_TEST(selector_only_note_never_authorizes_production_cache);
    RUN_TEST(cache_hit_revalidates_public_source_binding_after_final_scan);
    RUN_TEST(symlink_backed_home_content_is_never_cached);
    RUN_TEST(binary_cache_binds_same_path_executable_generation);
    RUN_TEST(signing_proof_satisfies_later_general_lookup);
    RUN_TEST(cache_bounds_fall_back_to_authoritative_listing);
    return ts_test_finish();
}
