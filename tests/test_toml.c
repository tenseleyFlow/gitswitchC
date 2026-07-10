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

/* Brackets inside quoted values and comments are data, not structure: the
 * guard must not count them, or it rejects files the writer itself produces
 * (toml F1). Structural bracket floods are still rejected (previous test). */
TEST(injection_guard_ignores_brackets_in_strings_and_comments) {
    char src[256];
    char many[64];
    memset(many, '[', sizeof(many) - 1);
    many[sizeof(many) - 1] = '\0';
    snprintf(src, sizeof(src), "description = \"%s\"\n", many);
    CHECK(toml_check_injection_patterns(src, strlen(src)));
    snprintf(src, sizeof(src), "# comment %s\nname = \"x\"\n", many);
    CHECK(toml_check_injection_patterns(src, strlen(src)));
    /* An escaped quote must not end the string early and expose the
     * brackets as structural. */
    snprintf(src, sizeof(src), "d = \"a\\\"%s\"\n", many);
    CHECK(toml_check_injection_patterns(src, strlen(src)));
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

/* Write→read round-trip with a bracket-heavy description: the injection guard
 * used to count these data brackets and refuse to reload a config the tool
 * had just written (toml F1). */
TEST(bracket_heavy_value_round_trips) {
    toml_document_t doc;
    char desc[48];
    memset(desc, '[', sizeof(desc) - 1);
    desc[sizeof(desc) - 1] = '\0';
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "alice"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@b.com"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "description", desc), 0);
    char path[] = "/tmp/gitswitch_toml_bracket_rt_test.toml";
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    chmod(path, 0600); /* toml_parse_file requires 0600, like config_save sets */
    toml_cleanup_document(&doc);

    toml_document_t doc2;
    toml_init_document(&doc2);
    CHECK_EQ_INT(toml_parse_file(path, &doc2), 0); /* must NOT be rejected */
    char buf[64];
    CHECK_EQ_INT(toml_get_string(&doc2, "accounts.1", "description", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, desc);
    toml_cleanup_document(&doc2);
    remove(path);
}

/* A bare relative ssh_key would resolve against the invocation CWD, making
 * key selection CWD-dependent (toml F3): schema validation must reject it. */
TEST(rejects_relative_ssh_key) {
    toml_document_t doc;
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"keys/id_ed25519\"\n", &doc), -1);
    toml_cleanup_document(&doc);
}

/* Absolute and ~-anchored ssh_key paths are CWD-independent and stay valid. */
TEST(accepts_anchored_ssh_key) {
    toml_document_t doc;
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"~/.ssh/id_ed25519\"\n", &doc), 0);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"/home/alice/.ssh/id_ed25519\"\n", &doc), 0);
    toml_cleanup_document(&doc);
}

/* AR-02 #6: well-formed UTF-8 in values must parse and round-trip through
 * toml_get_string byte-identical. Pre-fix, the raw-buffer charset gate
 * rejected every byte >= 0x80, so one accented character (accepted by the
 * interactive add and written verbatim by toml_write_file) bricked the whole
 * config on the next load. */
TEST(utf8_value_parses_and_round_trips) {
    toml_document_t doc;
    char buf[64];
    /* "Jos\xC3\xA9 Work" — José, 2-byte UTF-8; plus a 3-byte CJK char. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"Jos\xC3\xA9 \xE4\xBB\x95\xE4\xBA\x8B\"\n"
        "email = \"a@b.com\"\n";
    CHECK_EQ_INT(parse(cfg, &doc), 0);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, "Jos\xC3\xA9 \xE4\xBB\x95\xE4\xBA\x8B");
    toml_cleanup_document(&doc);
}

/* The gate stays strict about what >= 0x80 may BE: raw C1 bytes (malformed as
 * UTF-8), 2-byte-encoded C1 controls, and overlong encodings (the C1-smuggling
 * vector the strict decoder exists for) are all still whole-file rejections. */
TEST(safe_characters_reject_c1_and_overlong_utf8) {
    /* Raw C1 byte 0x9B (one-byte CSI). */
    char raw_c1[] = { 'a', (char)0x9B, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(raw_c1, 3));
    /* 2-byte UTF-8 form of U+009B: 0xC2 0x9B. */
    char enc_c1[] = { 'a', (char)0xC2, (char)0x9B, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(enc_c1, 4));
    /* Overlong 3-byte encoding of U+009B: 0xE0 0x82 0x9B. */
    char overlong3[] = { 'a', (char)0xE0, (char)0x82, (char)0x9B, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(overlong3, 5));
    /* Overlong 4-byte encoding of U+009B: 0xF0 0x80 0x82 0x9B (AR-02 #28). */
    char overlong4[] = { 'a', (char)0xF0, (char)0x80, (char)0x82, (char)0x9B, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(overlong4, 6));
    /* Bare continuation byte. */
    char bare_cont[] = { 'a', (char)0x80, 'b', '\0' };
    CHECK(!toml_validate_safe_characters(bare_cont, 3));
    /* Well-formed 2-byte é still passes. */
    char ok_utf8[] = { 'J', 'o', 's', (char)0xC3, (char)0xA9, '\0' };
    CHECK(toml_validate_safe_characters(ok_utf8, 5));
}

/* AR-02 #6: the read-path sanitizer must pass valid UTF-8 through untouched
 * (it used to strip every byte >= 0x80, so "José" retrieved as "Jos") while
 * still dropping C0/C1 controls and malformed bytes. */
TEST(sanitize_preserves_utf8_strips_controls) {
    char out[64];
    /* é passes through byte-identical. */
    CHECK_EQ_INT(toml_sanitize_string("Jos\xC3\xA9", out, sizeof(out)), 0);
    CHECK_STR_EQ(out, "Jos\xC3\xA9");
    /* Newline and raw C1 byte are dropped; the quote is dropped too. */
    CHECK_EQ_INT(toml_sanitize_string("a\nb\x9B\"c", out, sizeof(out)), 0);
    CHECK_STR_EQ(out, "abc");
    /* 2-byte-encoded C1 control is dropped as a unit. */
    CHECK_EQ_INT(toml_sanitize_string("a\xC2\x9B" "b", out, sizeof(out)), 0);
    CHECK_STR_EQ(out, "ab");
}

/* AR-02 #7: absolute key paths outside the old /home,/Users,/tmp allowlist
 * (NFS /export/home, systemd-homed /var/home, ...) are legitimate and must
 * load — pre-fix, ONE such path was a fatal whole-config failure taking every
 * unrelated account with it. Ownership/permission enforcement happens at use
 * (validate_account_security, ssh_validate_key_file), not by path prefix. */
TEST(accepts_non_allowlisted_absolute_ssh_key) {
    toml_document_t doc;
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"/export/home/alice/.ssh/id_ed25519\"\n", &doc), 0);
    toml_cleanup_document(&doc);
}

/* Traversal is a property of the path, not its prefix, and stays fatal —
 * including the backslash-resynthesis spelling: ".\./id" contains no ".."
 * substring, but the sanitizer strips the backslash and would hand callers
 * "../id", which is why validation runs on the SANITIZED bytes (AR-02 #29). */
TEST(rejects_traversal_and_resynthesized_traversal_ssh_key) {
    toml_document_t doc;
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"/home/alice/../../etc/key\"\n", &doc), -1);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"/home/alice/.\\\\./id_ed25519\"\n", &doc), -1);
    toml_cleanup_document(&doc);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(parses_valid_config);
    RUN_TEST(rejects_overlong_string_value);
    RUN_TEST(rejects_overlong_section_name);
    RUN_TEST(get_string_rejects_value_too_long_for_dest);
    RUN_TEST(injection_patterns_structural_only);
    RUN_TEST(injection_guard_ignores_brackets_in_strings_and_comments);
    RUN_TEST(safe_characters_reject_control);
    RUN_TEST(rejects_control_char_in_string);
    RUN_TEST(quote_in_value_round_trips);
    RUN_TEST(bracket_heavy_value_round_trips);
    RUN_TEST(rejects_relative_ssh_key);
    RUN_TEST(accepts_anchored_ssh_key);
    RUN_TEST(utf8_value_parses_and_round_trips);
    RUN_TEST(safe_characters_reject_c1_and_overlong_utf8);
    RUN_TEST(sanitize_preserves_utf8_strips_controls);
    RUN_TEST(accepts_non_allowlisted_absolute_ssh_key);
    RUN_TEST(rejects_traversal_and_resynthesized_traversal_ssh_key);
TEST_MAIN_END()
