/* Strict GPG signing-readiness inventory regressions. */
#include "test.h"
#include "gpg_manager.h"
#include "error.h"

#include <string.h>

#define PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define OTHER_FPR   "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define PRIMARY_SIGN \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define PRIMARY_CERT \
    "sec:u:255:22:0123456789ABCDEF:1700000000:::-:::cC:::+:::ed25519::\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define SIGNING_SUBKEY \
    "ssb:u:255:22:FEDCBA9876543210:1700000000:::-:::s:::+:::ed25519::\n" \
    "fpr:::::::::FEDCBA9876543210FEDCBA9876543210FEDCBA98:\n"
#define LEGACY_PRIMARY_SIGN \
    "sec::4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define LEGACY_PRIMARY_CERT \
    "sec::255:22:0123456789ABCDEF:1700000000:::-:::cC:::+:::ed25519::\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define LEGACY_SIGNING_SUBKEY \
    "ssb::255:22:FEDCBA9876543210:1700000000:::-:::s:::+:::ed25519::\n" \
    "fpr:::::::::FEDCBA9876543210FEDCBA9876543210FEDCBA98:\n"

TEST(resolves_current_primary_signing_key) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_SIGN, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

TEST(resolves_current_signing_subkey_to_primary_identity) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_CERT SIGNING_SUBKEY, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

TEST(supports_pre_2_1_empty_secret_validity_contract) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     LEGACY_PRIMARY_SIGN, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     LEGACY_PRIMARY_CERT LEGACY_SIGNING_SUBKEY, true,
                     fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

TEST(rejects_unusable_legacy_records_despite_empty_validity) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *expired =
        "sec::4096:1:0123456789ABCDEF:1700000000:1::-:::scESC:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *disabled =
        "sec::4096:1:0123456789ABCDEF:1700000000:::-:::scESCD:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *missing_material =
        "sec::4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::#:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     disabled, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     missing_material, true, fingerprint,
                     sizeof(fingerprint)), -1);
}

TEST(rejects_expired_disabled_and_missing_material) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *expired =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:1::-:::scESC:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *disabled =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESCD:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *missing_material =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::#:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     disabled, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     missing_material, true, fingerprint,
                     sizeof(fingerprint)), -1);
}

TEST(rejects_complete_non_signing_inventory) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *encryption_only =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::eE:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     encryption_only, true, fingerprint,
                     sizeof(fingerprint)), -1);
}

TEST(reports_canonical_identity_for_exact_mismatch_detection) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *other =
        "sec:u:4096:1:89ABCDEF01234567:1700000000:::-:::scESC:::+:::23::0:\n"
        "fpr:::::::::" OTHER_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     other, true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, OTHER_FPR);
    CHECK(strcmp(fingerprint, PRIMARY_FPR) != 0);
}

TEST(rejects_incomplete_and_non_key_evidence) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *missing_fingerprint =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     missing_fingerprint, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     "uid:u::::::::Signer <s@example.test>::::::::::\n",
                     true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     "", true, fingerprint, sizeof(fingerprint)), -1);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(resolves_current_primary_signing_key);
    RUN_TEST(resolves_current_signing_subkey_to_primary_identity);
    RUN_TEST(supports_pre_2_1_empty_secret_validity_contract);
    RUN_TEST(rejects_unusable_legacy_records_despite_empty_validity);
    RUN_TEST(rejects_expired_disabled_and_missing_material);
    RUN_TEST(rejects_complete_non_signing_inventory);
    RUN_TEST(reports_canonical_identity_for_exact_mismatch_detection);
    RUN_TEST(rejects_incomplete_and_non_key_evidence);
TEST_MAIN_END()
