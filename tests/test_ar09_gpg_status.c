/* AR-09 M15: real-GnuPG evidence that exit status 2 is not a result type. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "error.h"
#include "gpg_manager.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int make_gpg_home(char *home, size_t size) {
    if (safe_snprintf(home, size, "/tmp/gswar09gpg_XXXXXX") != 0 ||
        !ts_mkdtemp(home) || chmod(home, 0700) != 0 ||
        setenv("GNUPGHOME", home, 1) != 0) {
        return -1;
    }
    return 0;
}

TEST(real_gpg_absent_selector_has_structured_miss_evidence) {
    char home[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!command_exists("gpg")) {
        TS_SKIP("gpg", "gpg unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_gpg_home(home, sizeof(home)), 0);
    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "0123456789ABCDEF", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_NOT_FOUND);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "resolved no secret key") != NULL);
    unsetenv("GNUPGHOME");
}

TEST(real_gpg_corrupt_keybox_is_an_operational_failure) {
    char home[MAX_PATH_LEN];
    char keybox[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    if (!command_exists("gpg")) {
        TS_SKIP("gpg", "gpg unavailable in trusted PATH");
    }
    CHECK_EQ_INT(make_gpg_home(home, sizeof(home)), 0);
    CHECK_EQ_INT(safe_snprintf(keybox, sizeof(keybox), "%s/pubring.kbx",
                               home), 0);
    CHECK_EQ_INT(write_string_to_file(
                     keybox, "not a valid OpenPGP keybox\n", 0600), 0);
    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "0123456789ABCDEF", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "error code") != NULL);
    unsetenv("GNUPGHOME");
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(real_gpg_absent_selector_has_structured_miss_evidence);
    RUN_TEST(real_gpg_corrupt_keybox_is_an_operational_failure);
TEST_MAIN_END()
