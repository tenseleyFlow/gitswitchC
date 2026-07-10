/* Tests for the hand-rolled TOML parser: valid parse, limits reject (not
 * truncate), and the injection/safe-character guards. */
#include "test.h"
#include "gitswitch.h"
#include "toml_parser.h"
#include "error.h"
#include <string.h>
#include <sys/stat.h>

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

/* toml_check_injection_patterns is now only a structural (nesting/DoS) guard:
 * shell metacharacters are ordinary data under argv-based execution, so they
 * must NOT be rejected here (that only corrupted valid configs). It still
 * returns false on excessive bracket nesting. */
TEST(injection_patterns_structural_only) {
    CHECK(toml_check_injection_patterns("x$(whoami)", 10));
    CHECK(toml_check_injection_patterns("a`id`b", 6));
    CHECK(toml_check_injection_patterns("clean value 123", 15));
    char nested[64];
    memset(nested, '[', sizeof(nested) - 1);
    nested[sizeof(nested) - 1] = '\0';
    CHECK(!toml_check_injection_patterns(nested, sizeof(nested) - 1));
}

TEST(safe_characters_reject_control) {
    char ctrl[4] = { 'a', 0x01, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(ctrl, 3));
    CHECK(toml_validate_safe_characters("ok text", 7));
}

/* A raw control character inside a quoted basic string is rejected at parse
 * time (regression guard for the smuggled-newline bypass). */
TEST(rejects_control_char_in_string) {
    toml_document_t doc;
    CHECK_EQ_INT(parse("[accounts.1]\nname = \"a\nb\"\n", &doc), -1);
    toml_cleanup_document(&doc);
}

/* A value containing a double quote is written escaped so the file re-parses
 * cleanly instead of bricking the config (regression guard for unescaped
 * write). The reader's sanitizer separately strips the quote, so we assert the
 * file parses and the key is retrievable — not byte-identity. */
TEST(quote_in_value_round_trips) {
    toml_document_t doc;
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "Work \"GmbH\""), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@b.com"), 0);
    char path[] = "/tmp/gitswitch_toml_rt_test.toml";
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    chmod(path, 0600); /* toml_parse_file requires 0600, like config_save sets */
    toml_cleanup_document(&doc);

    toml_document_t doc2;
    toml_init_document(&doc2);
    CHECK_EQ_INT(toml_parse_file(path, &doc2), 0); /* must NOT fail to parse */
    char buf[64];
    CHECK_EQ_INT(toml_get_string(&doc2, "accounts.1", "name", buf, sizeof(buf)), 0);
    toml_cleanup_document(&doc2);
    remove(path);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(parses_valid_config);
    RUN_TEST(rejects_overlong_string_value);
    RUN_TEST(rejects_overlong_section_name);
    RUN_TEST(get_string_rejects_value_too_long_for_dest);
    RUN_TEST(injection_patterns_structural_only);
    RUN_TEST(safe_characters_reject_control);
    RUN_TEST(rejects_control_char_in_string);
    RUN_TEST(quote_in_value_round_trips);
TEST_MAIN_END()
