/* AR-11 M21: version-bound GnuPG 2.0 secret-material evidence. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "error.h"
#include "gpg_manager.h"
#include "utils.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define SUBKEY_FPR  "FEDCBA9876543210FEDCBA9876543210FEDCBA98"

/* These records follow GnuPG 2.0.30 g10/keylist.c exactly: field 2 is
 * unset for secret records and ordinary disk-backed material leaves field 15
 * empty. A simple stub writes '#', while a token-backed record writes its
 * serial number there. */
#define GPG20_PRIMARY_SIGN                                                   \
    "sec::4096:1:0123456789ABCDEF:1700000000::::::scESC:::\n"             \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define GPG20_PRIMARY_CERT                                                   \
    "sec::4096:1:0123456789ABCDEF:1700000000::::::cC:::\n"                \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define GPG20_SIGNING_SUBKEY                                                 \
    "ssb::2048:1:FEDCBA9876543210:1700000000::::::s:::\n"                \
    "fpr:::::::::" SUBKEY_FPR ":\n"
#define GPG20_PRIMARY_STUB                                                   \
    "sec::4096:1:0123456789ABCDEF:1700000000::::::scESC:::#:\n"            \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define GPG20_PRIMARY_EXPIRED                                                \
    "sec::4096:1:0123456789ABCDEF:1700000000:1:::::scESC:::\n"             \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define GPG20_PRIMARY_DISABLED                                               \
    "sec::4096:1:0123456789ABCDEF:1700000000::::::scESCD:::\n"             \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define MODERN_EMPTY_MATERIAL                                                \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::\n"            \
    "fpr:::::::::" PRIMARY_FPR ":\n"

typedef struct {
    char *value;
    bool present;
} saved_environment_t;

typedef enum {
    FIXTURE_GPG20_PRIMARY,
    FIXTURE_GPG20_SUBKEY,
    FIXTURE_GPG20_STUB,
    FIXTURE_GPG20_EXPIRED,
    FIXTURE_GPG20_DISABLED,
    FIXTURE_MODERN_EMPTY,
    FIXTURE_MALFORMED_VERSION,
    FIXTURE_VERSION_FAILURE
} fixture_mode_t;

static fixture_mode_t g_fixture_mode;
static int g_listing_calls;
static int g_version_calls;

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

static bool argv_contains(const char *const argv[], const char *value) {
    size_t i;

    if (!argv || !value) return false;
    for (i = 0; argv[i]; i++) {
        if (strcmp(argv[i], value) == 0) return true;
    }
    return false;
}

static int emit_output(const run_opts_t *opts, run_result_t *result,
                       const char *output) {
    size_t length;

    if (!opts || !opts->out || opts->out_size == 0 || !output) return -1;
    length = strlen(output);
    if (length >= opts->out_size) {
        if (result) result->out_truncated = true;
        return -1;
    }
    memcpy(opts->out, output, length + 1U);
    if (result) result->out_len = length;
    return 0;
}

static const char *fixture_listing(void) {
    switch (g_fixture_mode) {
        case FIXTURE_GPG20_PRIMARY:
            return GPG20_PRIMARY_SIGN;
        case FIXTURE_GPG20_SUBKEY:
            return GPG20_PRIMARY_CERT GPG20_SIGNING_SUBKEY;
        case FIXTURE_GPG20_STUB:
            return GPG20_PRIMARY_STUB;
        case FIXTURE_GPG20_EXPIRED:
            return GPG20_PRIMARY_EXPIRED;
        case FIXTURE_GPG20_DISABLED:
            return GPG20_PRIMARY_DISABLED;
        case FIXTURE_MODERN_EMPTY:
        case FIXTURE_MALFORMED_VERSION:
        case FIXTURE_VERSION_FAILURE:
            return MODERN_EMPTY_MATERIAL;
        default:
            return "";
    }
}

static int legacy_listing_runner(const char *const argv[],
                                 const run_opts_t *opts,
                                 run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (argv_contains(argv, "--list-secret-keys")) {
        g_listing_calls++;
        return emit_output(opts, result, fixture_listing());
    }
    if (argv && argv[0] && argv[1] && !argv[2] &&
        strcmp(argv[1], "--version") == 0) {
        g_version_calls++;
        if (g_fixture_mode == FIXTURE_VERSION_FAILURE) {
            if (result) result->exit_code = 1;
            return -1;
        }
        if (g_fixture_mode == FIXTURE_MALFORMED_VERSION) {
            return emit_output(opts, result, "gpg (GnuPG) unknown\n");
        }
        if (g_fixture_mode == FIXTURE_MODERN_EMPTY) {
            return emit_output(opts, result, "gpg (GnuPG) 2.4.9\n");
        }
        return emit_output(opts, result, "gpg (GnuPG) 2.0.30\n");
    }
    if (result) result->exit_code = 2;
    return -1;
}

static int run_fixture(fixture_mode_t mode, bool require_signing,
                       char *fingerprint, size_t fingerprint_size,
                       error_code_t *error_code, char *diagnostic,
                       size_t diagnostic_size) {
    char root[MAX_PATH_LEN];
    char bin[MAX_PATH_LEN];
    char program[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    saved_environment_t path_environment;
    saved_environment_t gnupg_environment;
    command_runner_fn previous_runner;
    int rc = -2;

    if (save_environment("PATH", &path_environment) != 0 ||
        save_environment("GNUPGHOME", &gnupg_environment) != 0) {
        return -2;
    }
    if (!ts_mkdtemp_trusted(root, sizeof(root), "gitswitch-ar11-gpg20") ||
        safe_snprintf(bin, sizeof(bin), "%s/bin", root) != 0 ||
        mkdir(bin, 0700) != 0 ||
        safe_snprintf(program, sizeof(program), "%s/gpg", bin) != 0 ||
        write_string_to_file(program, "#!/bin/sh\nexit 0\n", 0700) != 0 ||
        safe_snprintf(source_home, sizeof(source_home), "%s/source", root) != 0 ||
        mkdir(source_home, 0700) != 0 || setenv("PATH", bin, 1) != 0 ||
        setenv("GNUPGHOME", source_home, 1) != 0) {
        goto restore;
    }

    g_fixture_mode = mode;
    g_listing_calls = 0;
    g_version_calls = 0;
    clear_error();
    previous_runner = run_set_runner(legacy_listing_runner);
    rc = gpg_manager_resolve_system_key(
        "01234567", require_signing, fingerprint, fingerprint_size);
    run_set_runner(previous_runner);
    if (error_code) *error_code = get_last_error()->code;
    if (diagnostic && diagnostic_size > 0) {
        (void)safe_strncpy(diagnostic, get_last_error()->message,
                           diagnostic_size);
    }

restore:
    if (restore_environment("GNUPGHOME", &gnupg_environment) != 0) rc = -2;
    if (restore_environment("PATH", &path_environment) != 0) rc = -2;
    return rc;
}

TEST(genuine_gnupg_2_0_disk_material_resolves_with_version_proof) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(run_fixture(FIXTURE_GPG20_PRIMARY, true, fingerprint,
                             sizeof(fingerprint), NULL, NULL, 0), 0);
    CHECK_EQ_INT(g_listing_calls, 1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);

    CHECK_EQ_INT(run_fixture(FIXTURE_GPG20_SUBKEY, true, fingerprint,
                             sizeof(fingerprint), NULL, NULL, 0), 0);
    CHECK_EQ_INT(g_listing_calls, 1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

TEST(empty_material_is_not_a_general_modern_availability_marker) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    error_code_t error_code = ERR_SUCCESS;

    CHECK_EQ_INT(run_fixture(FIXTURE_MODERN_EMPTY, true, fingerprint,
                             sizeof(fingerprint), &error_code, NULL, 0), -1);
    CHECK_EQ_INT(g_listing_calls, 1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(fingerprint[0] == '\0');

    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     GPG20_PRIMARY_SIGN, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK(fingerprint[0] == '\0');
}

TEST(legacy_stubs_expiry_and_disablement_remain_unusable) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(run_fixture(FIXTURE_GPG20_STUB, false, fingerprint,
                             sizeof(fingerprint), NULL, NULL, 0), -1);
    CHECK_EQ_INT(g_version_calls, 0);
    CHECK(fingerprint[0] == '\0');

    CHECK_EQ_INT(run_fixture(FIXTURE_GPG20_EXPIRED, false, fingerprint,
                             sizeof(fingerprint), NULL, NULL, 0), -1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK(fingerprint[0] == '\0');

    CHECK_EQ_INT(run_fixture(FIXTURE_GPG20_DISABLED, false, fingerprint,
                             sizeof(fingerprint), NULL, NULL, 0), -1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK(fingerprint[0] == '\0');
}

TEST(unprovable_legacy_version_contract_fails_closed) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char diagnostic[256];
    error_code_t error_code = ERR_SUCCESS;

    CHECK_EQ_INT(run_fixture(FIXTURE_MALFORMED_VERSION, true, fingerprint,
                             sizeof(fingerprint), &error_code, diagnostic,
                             sizeof(diagnostic)), -1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(diagnostic, "version") != NULL);
    CHECK(fingerprint[0] == '\0');

    CHECK_EQ_INT(run_fixture(FIXTURE_VERSION_FAILURE, true, fingerprint,
                             sizeof(fingerprint), &error_code, diagnostic,
                             sizeof(diagnostic)), -1);
    CHECK_EQ_INT(g_version_calls, 1);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(diagnostic, "version") != NULL);
    CHECK(fingerprint[0] == '\0');
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(genuine_gnupg_2_0_disk_material_resolves_with_version_proof);
    RUN_TEST(empty_material_is_not_a_general_modern_availability_marker);
    RUN_TEST(legacy_stubs_expiry_and_disablement_remain_unusable);
    RUN_TEST(unprovable_legacy_version_contract_fails_closed);
TEST_MAIN_END()
