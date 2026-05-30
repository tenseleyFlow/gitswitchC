/* Tests for the hand-rolled TOML parser: valid parse, limits reject (not
 * truncate), and the injection/safe-character guards. */
#include "test.h"
#include "gitswitch.h"
#include "toml_parser.h"
#include "error.h"
#include <string.h>

static int parse(const char *s, toml_document_t *doc) {
    toml_init_document(doc);
    return toml_parse_string(s, strlen(s), doc);
}

TEST(parses_valid_config) {
    toml_document_t doc;
    char buf[64];
    int rc = parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n", &doc);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, "alice");
    toml_cleanup_document(&doc);
}

TEST(rejects_overlong_string_value) {
    toml_document_t doc;
    char big[700];
    char src[800];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    snprintf(src, sizeof(src), "[accounts.1]\nname = \"%s\"\n", big); /* > TOML_MAX_VALUE_LEN */
    CHECK_EQ_INT(parse(src, &doc), -1);
    toml_cleanup_document(&doc);
}

TEST(rejects_overlong_section_name) {
    toml_document_t doc;
    char name[128];
    char src[256];
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    snprintf(src, sizeof(src), "[%s]\nname = \"x\"\n", name); /* > TOML_MAX_SECTION_LEN */
    CHECK_EQ_INT(parse(src, &doc), -1);
    toml_cleanup_document(&doc);
}

TEST(get_string_rejects_value_too_long_for_dest) {
    toml_document_t doc;
    char small[16];
    int rc = parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "description = \"a description that is longer than sixteen bytes\"\n", &doc);
    CHECK_EQ_INT(rc, 0);
    /* Value is longer than the 16-byte destination: must reject, not truncate. */
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "description", small, sizeof(small)), -1);
    toml_cleanup_document(&doc);
}

/* toml_check_injection_patterns returns true when the input is SAFE (no
 * dangerous pattern) and false when a pattern is found. */
TEST(injection_patterns_detected) {
    CHECK(!toml_check_injection_patterns("x$(whoami)", 10));
    CHECK(!toml_check_injection_patterns("a`id`b", 6));
    CHECK(toml_check_injection_patterns("clean value 123", 15));
}

TEST(safe_characters_reject_control) {
    char ctrl[4] = { 'a', 0x01, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(ctrl, 3));
    CHECK(toml_validate_safe_characters("ok text", 7));
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(parses_valid_config);
    RUN_TEST(rejects_overlong_string_value);
    RUN_TEST(rejects_overlong_section_name);
    RUN_TEST(get_string_rejects_value_too_long_for_dest);
    RUN_TEST(injection_patterns_detected);
    RUN_TEST(safe_characters_reject_control);
TEST_MAIN_END()
