/* Tests for the gpg --with-colons signing-capability parser. */
#include "test.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "error.h"

/* A real `sec` line; field 12 (capabilities) = "scESC" contains 's'. */
#define SEC_SIGN "sec:-:4096:1:ABCDEF0123456789:1700000000:::-:::scESC:::+:::23::0:\n"
/* Primary that only certifies; a signing subkey on the ssb line. */
#define SEC_CERT "sec:-:255:22:1111111111111111:1700000000:::-:::cC:::+:::ed25519::\n"
#define SSB_SIGN "ssb:-:255:22:2222222222222222:1700000000::::::s:::+:::ed25519:\n"
/* Encryption-only key: no 's' anywhere. */
#define SEC_ENC  "sec:-:4096:1:3333333333333333:1700000000:::-:::eE:::+:::23::0:\n"

TEST(detects_sign_on_sec_line) {
    CHECK(gpg_colons_have_sign_capability(SEC_SIGN));
}

TEST(detects_sign_on_subkey) {
    CHECK(gpg_colons_have_sign_capability(SEC_CERT SSB_SIGN));
}

TEST(rejects_encryption_only) {
    CHECK(!gpg_colons_have_sign_capability(SEC_ENC));
}

TEST(rejects_empty_and_null) {
    CHECK(!gpg_colons_have_sign_capability(""));
    CHECK(!gpg_colons_have_sign_capability(NULL));
}

TEST(ignores_non_key_records) {
    /* uid/fpr lines must not be mistaken for signing capability. */
    CHECK(!gpg_colons_have_sign_capability("uid:-::::::::Some signer <s@x>::::::::::\n"
                                           "fpr:::::::::ABCDEF::::\n"));
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(detects_sign_on_sec_line);
    RUN_TEST(detects_sign_on_subkey);
    RUN_TEST(rejects_encryption_only);
    RUN_TEST(rejects_empty_and_null);
    RUN_TEST(ignores_non_key_records);
TEST_MAIN_END()
