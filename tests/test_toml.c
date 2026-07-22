/* Tests for the hand-rolled TOML parser: valid parse, limits reject (not
 * truncate), and the injection/safe-character guards. */
#include "test.h"
#include "gitswitch.h"
#include "toml_parser.h"
#include "error.h"
#include <string.h>
#include <sys/stat.h>

static int parse(const char *s, toml_document_t *doc) {
    return toml_parse_string(s, strlen(s), doc);
}

/* Every file-backed parser test gets a private, tracked directory. Fixed
 * names directly under /tmp let concurrent suites truncate one another and
 * followed attacker-planted symlinks before AR-07 L20. */
static int make_temp_toml_path(char *dir, size_t dir_size,
                               char *path, size_t path_size) {
    int written = snprintf(dir, dir_size, "/tmp/gitswitch-toml-XXXXXX");
    if (written < 0 || (size_t)written >= dir_size || !ts_mkdtemp(dir)) {
        return -1;
    }
    written = snprintf(path, path_size, "%s/fixture.toml", dir);
    if (written < 0 || (size_t)written >= path_size) return -1;
    return 0;
}

static int write_exact_toml_bytes(const char *path, const char *contents,
                                  size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, contents + total, length - total);
        if (written > 0) {
            total += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            (void)close(fd);
            return -1;
        }
    }
    return close(fd);
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

/* AR-09 L3: LF and CRLF are the only physical line endings admitted by TOML.
 * A valid CRLF or mixed-ending document must describe the same model as its
 * LF spelling, with CRLF counted as one line rather than two tokens. */
TEST(accepts_lf_crlf_and_mixed_line_endings_equivalently) {
    static const char lf[] =
        "[settings]\n"
        "default_scope = \"local\" # inline comment\n"
        "# final comment\n";
    static const char crlf[] =
        "[settings]\r\n"
        "default_scope = \"local\" # inline comment\r\n"
        "# final comment\r\n";
    static const char mixed[] =
        "[settings]\r\n"
        "default_scope = \"local\" # inline comment\n"
        "# final comment";
    static toml_document_t lf_doc, crlf_doc, mixed_doc;

    CHECK_EQ_INT(toml_parse_string(lf, sizeof(lf) - 1U, &lf_doc), 0);
    CHECK_EQ_INT(toml_parse_string(crlf, sizeof(crlf) - 1U, &crlf_doc), 0);
    CHECK_EQ_INT(toml_parse_string(mixed, sizeof(mixed) - 1U, &mixed_doc), 0);
    CHECK_EQ_INT((int)crlf_doc.section_count, (int)lf_doc.section_count);
    CHECK_EQ_INT((int)mixed_doc.section_count, (int)lf_doc.section_count);
    CHECK(memcmp(crlf_doc.sections, lf_doc.sections,
                 sizeof(lf_doc.sections)) == 0);
    CHECK(memcmp(mixed_doc.sections, lf_doc.sections,
                 sizeof(lf_doc.sections)) == 0);
    toml_cleanup_document(&mixed_doc);
    toml_cleanup_document(&crlf_doc);
    toml_cleanup_document(&lf_doc);
}

/* A CR not immediately paired with LF is malformed in every physical-line
 * context. Keep the diagnostic anchored on that CR so a swallowed comment or
 * miscounted line cannot decay into an unrelated schema error. */
TEST(rejects_bare_carriage_return_line_endings) {
    static const struct {
        const char *input;
        const char *location;
    } invalid[] = {
        { "[settings]\rdefault_scope = \"local\"\n",
          "line 1, column 11" },
        { "[settings]\ndefault_scope = \"local\"\r",
          "line 2, column 24" },
        { "[settings]\n\rdefault_scope = \"local\"\n",
          "line 2, column 1" },
        { "[settings]\n# comment\rdefault_scope = \"local\"\n",
          "line 2, column 10" },
        { "[settings]\ndefault_scope = \"local\" # comment\r",
          "line 2, column 34" }
    };
    static toml_document_t doc;

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        clear_error();
        CHECK_EQ_INT(toml_parse_string(invalid[i].input,
                                       strlen(invalid[i].input), &doc), -1);
        CHECK(strstr(get_last_error()->message, "carriage return") != NULL);
        CHECK(strstr(get_last_error()->message, invalid[i].location) != NULL);
        toml_cleanup_document(&doc);
    }
}

TEST(crlf_diagnostics_and_escaped_cr_remain_distinct) {
    static const char malformed[] =
        "[settings]\r\n"
        "default_scope = \"local\"\r\n"
        "?";
    static const char escaped[] =
        "[settings]\r\n"
        "default_scope = \"local\"\r\n"
        "[custom]\r\n"
        "value = \"a\\rb\"\r\n";
    static const char raw_cr[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "value = \"a\rb\"\n";
    static toml_document_t doc;

    CHECK_EQ_INT(toml_parse_string(malformed, sizeof(malformed) - 1U, &doc),
                 -1);
    CHECK(strstr(get_last_error()->message, "line 3, column 1") != NULL);
    toml_cleanup_document(&doc);

    CHECK_EQ_INT(toml_parse_string(escaped, sizeof(escaped) - 1U, &doc), 0);
    CHECK_EQ_INT((int)doc.section_count, 2);
    CHECK_EQ_INT((int)doc.sections[1].key_count, 1);
    CHECK_EQ_INT((int)strlen(doc.sections[1].keys[0].value), 3);
    CHECK(doc.sections[1].keys[0].value[0] == 'a');
    CHECK(doc.sections[1].keys[0].value[1] == '\r');
    CHECK(doc.sections[1].keys[0].value[2] == 'b');
    toml_cleanup_document(&doc);

    CHECK_EQ_INT(toml_parse_string(raw_cr, sizeof(raw_cr) - 1U, &doc), -1);
    CHECK(strstr(get_last_error()->message,
                 "Control character in string value") != NULL);
    toml_cleanup_document(&doc);
}

TEST(file_parser_enforces_the_same_line_ending_grammar) {
    static const char valid[] =
        "[settings]\r\n"
        "default_scope = \"local\"\r\n";
    static const char invalid[] =
        "[settings]\rdefault_scope = \"local\"\n";
    static toml_document_t doc;
    char valid_dir[128], valid_path[192];
    char invalid_dir[128], invalid_path[192];

    if (make_temp_toml_path(valid_dir, sizeof(valid_dir), valid_path,
                            sizeof(valid_path)) != 0 ||
        write_exact_toml_bytes(valid_path, valid, sizeof(valid) - 1U) != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(toml_parse_file(valid_path, &doc), 0);
    toml_cleanup_document(&doc);

    if (make_temp_toml_path(invalid_dir, sizeof(invalid_dir), invalid_path,
                            sizeof(invalid_path)) != 0 ||
        write_exact_toml_bytes(invalid_path, invalid,
                               sizeof(invalid) - 1U) != 0) {
        CHECK(0);
        return;
    }
    clear_error();
    CHECK_EQ_INT(toml_parse_file(invalid_path, &doc), -1);
    CHECK(strstr(get_last_error()->message, "carriage return") != NULL);
    CHECK(strstr(get_last_error()->message, "line 1, column 11") != NULL);
    toml_cleanup_document(&doc);
}

/* AR-12 L23: duplicate/collision diagnostics anchor at the offending
 * construct's start, not one past its end. */
TEST(duplicate_diagnostics_anchor_at_construct_start) {
    static const char dup_key[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "default_scope = \"local\"\n";
    static const char dup_section[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[settings]\n";
    toml_document_t doc;

    clear_error();
    CHECK_EQ_INT(toml_parse_string(dup_key, sizeof(dup_key) - 1U, &doc), -1);
    CHECK(strstr(get_last_error()->message, "Duplicate key") != NULL);
    CHECK(strstr(get_last_error()->message, "line 3, column 1") != NULL);
    toml_cleanup_document(&doc);

    clear_error();
    CHECK_EQ_INT(toml_parse_string(dup_section, sizeof(dup_section) - 1U,
                                   &doc), -1);
    CHECK(strstr(get_last_error()->message, "Duplicate section") != NULL);
    CHECK(strstr(get_last_error()->message, "line 3, column 1") != NULL);
    toml_cleanup_document(&doc);
}

/* AR-12 L22: the permission gate must reject group/other WRITE access, not
 * just read — a writing peer can redirect ssh_key and alter the identity. */
TEST(file_parser_rejects_group_or_other_writable_configs) {
    static const mode_t unsafe_modes[] = {0620, 0602, 0622};
    static const char body[] =
        "[settings]\n"
        "default_scope = \"local\"\n";
    toml_document_t doc;
    char dir[128], path[192];

    for (size_t i = 0; i < sizeof(unsafe_modes) / sizeof(unsafe_modes[0]);
         i++) {
        if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0 ||
            write_exact_toml_bytes(path, body, sizeof(body) - 1U) != 0) {
            CHECK(0);
            return;
        }
        CHECK_EQ_INT(chmod(path, unsafe_modes[i]), 0);
        clear_error();
        CHECK_EQ_INT(toml_parse_file(path, &doc), -1);
        CHECK(strstr(get_last_error()->message, "unsafe permissions") !=
              NULL);
        toml_cleanup_document(&doc);
        remove(path);
    }
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
 * returns false on excessive bracket nesting (the flood must exceed
 * TOML_MAX_SECTIONS, which M7 raised to 65). */
TEST(injection_patterns_structural_only) {
    CHECK(toml_check_injection_patterns("x$(whoami)", 10));
    CHECK(toml_check_injection_patterns("a`id`b", 6));
    CHECK(toml_check_injection_patterns("clean value 123", 15));
    char nested[TOML_MAX_SECTIONS + 32];
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
 * write). Retrieval is a different story since M6: the sanitizer would strip
 * the quote, so toml_get_string must now FAIL rather than silently hand back
 * mutated bytes (pre-fix it returned 0 with `Work GmbH`, desyncing every
 * name-keyed resource — sockets, GNUPGHOME, active_account — on first
 * reload). The file itself must still parse: the failure is per-value, and
 * config.c's loader turns it into a counted skip, never whole-file loss. */
TEST(quote_in_value_round_trips) {
    toml_document_t doc;
    char dir[128];
    char path[192];
    if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "Work \"GmbH\""), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@b.com"), 0);
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    toml_cleanup_document(&doc);

    toml_document_t doc2;
    CHECK_EQ_INT(toml_parse_file(path, &doc2), 0); /* must NOT fail to parse */
    char buf[64];
    CHECK_EQ_INT(toml_get_string(&doc2, "accounts.1", "name", buf, sizeof(buf)), -1);
    toml_cleanup_document(&doc2);
    remove(path);
}

/* M6: toml_get_string is the single choke point for values the sanitizer
 * would alter — it must FAIL (like its too-long case) instead of silently
 * stripping bytes. validate_name admits `"`, the writer escapes it
 * faithfully, the parser unescapes it; pre-fix the getter then dropped it,
 * so disk and memory disagreed at first reload and the stripped spelling
 * was persisted by the next save. */
TEST(get_string_fails_when_sanitization_would_alter_value) {
    toml_document_t doc;
    char buf[64];
    int rc = parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"Jane \\\"Work\\\"\"\n"
        "email = \"a@b.com\"\n", &doc);
    CHECK_EQ_INT(rc, 0); /* the FILE stays loadable; only the value fails */
    memset(buf, 'X', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", buf, sizeof(buf)), -1);
    /* Fail closed: the caller's buffer must not retain the altered bytes the
     * sanitizer produced on the way to detecting the mismatch. */
    CHECK_STR_EQ(buf, "");
    /* A value the sanitizer passes through byte-identical is unaffected. */
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "email", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, "a@b.com");
    toml_cleanup_document(&doc);
}

/* M5 (writer half): toml_set_string used to ignore safe_strncpy's failure on
 * a value >= TOML_MAX_VALUE_LEN, leaving value="" with is_set=true — so
 * config_save persisted `ssh_key = ""` at exit 0, silently erasing the key
 * from the account. It must propagate the failure and leave no ghost key. */
TEST(set_string_rejects_overlong_value_instead_of_erasing) {
    toml_document_t doc;
    char big[TOML_MAX_VALUE_LEN + 64];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "ssh_key", big), -1);
    /* No half-created `ssh_key = ""` may remain behind the failure. */
    CHECK(doc.section_count == 0 || doc.sections[0].key_count == 0);
    /* Overwriting an existing key with an overlong value must also fail
     * loudly (pre-fix: returned 0 while silently keeping the old value). */
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "ssh_key", "/ok/key"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "ssh_key", big), -1);
    CHECK_STR_EQ(doc.sections[0].keys[0].value, "/ok/key");
    toml_cleanup_document(&doc);
}

/* AR-09 M12: the public setter must reject every decoded byte sequence that
 * the writer would emit but the parser's raw-buffer gate refuses on reload.
 * Rejection precedes both overwrite and new-section mutation. */
TEST(set_string_rejects_unroundtrippable_values_without_mutation) {
    static const char c0[] = { 'a', 0x01, 'b', '\0' };
    static const char escape[] = { 'a', 0x1B, 'b', '\0' };
    static const char del[] = { 'a', 0x7F, 'b', '\0' };
    static const char raw_c1[] = { 'a', (char)0x9B, 'b', '\0' };
    static const char encoded_c1[] = {
        'a', (char)0xC2, (char)0x9B, 'b', '\0'
    };
    static const char truncated_2[] = { 'a', (char)0xC2, '\0' };
    static const char truncated_3[] = {
        'a', (char)0xE2, (char)0x82, '\0'
    };
    static const char truncated_4[] = {
        'a', (char)0xF0, (char)0x9F, (char)0x92, '\0'
    };
    static const char bare_continuation[] = {
        'a', (char)0x80, 'b', '\0'
    };
    static const char bad_continuation[] = {
        'a', (char)0xE2, '(', (char)0xA1, '\0'
    };
    static const char overlong[] = {
        'a', (char)0xE0, (char)0x80, (char)0xAF, '\0'
    };
    static const char surrogate[] = {
        'a', (char)0xED, (char)0xA0, (char)0x80, '\0'
    };
    static const char out_of_range[] = {
        'a', (char)0xF4, (char)0x90, (char)0x80, (char)0x80, '\0'
    };
    static const char zero_width_space[] = {
        'a', (char)0xE2, (char)0x80, (char)0x8B, 'b', '\0'
    };
    static const char bidi_override[] = {
        'a', (char)0xE2, (char)0x80, (char)0xAE, 'b', '\0'
    };
    static const char line_separator[] = {
        'a', (char)0xE2, (char)0x80, (char)0xA8, 'b', '\0'
    };
    static toml_document_t doc;
    static toml_document_t before;
    char too_long[TOML_MAX_VALUE_LEN + 1];
    const char *invalid[] = {
        c0, escape, del, raw_c1, encoded_c1, truncated_2, truncated_3,
        truncated_4, bare_continuation, bad_continuation, overlong, surrogate,
        out_of_range, zero_width_space, bidi_override, line_separator, too_long
    };

    memset(too_long, 'x', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"),
                 0);
    CHECK_EQ_INT(toml_set_string(&doc, "custom", "value", "stable"), 0);
    memcpy(&before, &doc, sizeof(before));

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        memcpy(&doc, &before, sizeof(doc));
        CHECK_EQ_INT(toml_set_string(&doc, "custom", "value", invalid[i]),
                     -1);
        CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);

        memcpy(&doc, &before, sizeof(doc));
        CHECK_EQ_INT(toml_set_string(&doc, "new_section", "value",
                                     invalid[i]), -1);
        CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    }

    toml_cleanup_document(&doc);
    toml_cleanup_document(&before);
}

TEST(set_string_admitted_values_round_trip_byte_exact) {
    static toml_document_t doc;
    static toml_document_t loaded;
    char max_backslashes[TOML_MAX_VALUE_LEN];
    char max_utf8_4[TOML_MAX_VALUE_LEN];
    char dir[128];
    char path[192];

    memset(max_backslashes, '\\', sizeof(max_backslashes) - 1);
    max_backslashes[sizeof(max_backslashes) - 1] = '\0';
    memset(max_utf8_4, 'x', sizeof(max_utf8_4) - 5);
    max_utf8_4[sizeof(max_utf8_4) - 5] = (char)0xF0;
    max_utf8_4[sizeof(max_utf8_4) - 4] = (char)0x9F;
    max_utf8_4[sizeof(max_utf8_4) - 3] = (char)0x92;
    max_utf8_4[sizeof(max_utf8_4) - 2] = (char)0xA9;
    max_utf8_4[sizeof(max_utf8_4) - 1] = '\0';
    const char *accepted[] = {
        "",
        "plain ASCII",
        "quote \" and backslash \\",
        "line\ncarriage\rtab\t",
        "Jos\xC3\xA9",
        "\xE4\xBB\x95\xE4\xBA\x8B",
        "\xF0\x9F\x92\xA9",
        max_backslashes,
        max_utf8_4
    };

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"),
                 0);
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        char key[16];
        CHECK((size_t)snprintf(key, sizeof(key), "value%zu", i) < sizeof(key));
        CHECK_EQ_INT(toml_set_string(&doc, "custom", key, accepted[i]), 0);
    }

    if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        toml_cleanup_document(&doc);
        return;
    }
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    CHECK_EQ_INT(toml_parse_file(path, &loaded), 0);
    CHECK_EQ_INT((int)loaded.section_count, 2);
    CHECK_EQ_INT((int)loaded.sections[1].key_count,
                 (int)(sizeof(accepted) / sizeof(accepted[0])));

    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        const char *actual = loaded.sections[1].keys[i].value;
        CHECK_EQ_INT((int)strlen(actual), (int)strlen(accepted[i]));
        CHECK(memcmp(actual, accepted[i], strlen(accepted[i])) == 0);
    }

    toml_cleanup_document(&loaded);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(unlink(path), 0);
}

/* AR-09 L2: is_valid describes the current model, not whether some earlier
 * version once validated. Rejected no-op setters preserve the state exactly;
 * every successful mutation revokes it until a complete schema pass succeeds. */
TEST(validity_tracks_mutation_and_complete_schema_validation) {
    static const char unsafe[] = { 'x', 0x01, 'y', '\0' };
    static toml_document_t doc;
    static toml_document_t before;
    char value[32] = "unchanged";
    bool enabled = false;

    CHECK_EQ_INT(parse("[settings]\n"
                       "default_scope = \"local\"\n"
                       "[accounts.1]\n"
                       "name = \"alice\"\n"
                       "email = \"alice@example.com\"\n",
                       &doc), 0);
    CHECK(doc.is_valid);

    memcpy(&before, &doc, sizeof(before));
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", unsafe),
                 -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK(doc.is_valid);
    CHECK_EQ_INT(toml_set_boolean(&doc, "bad section", "enabled", true), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK(doc.is_valid);

    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "global"),
                 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_get_string(&doc, "settings", "default_scope", value,
                                 sizeof(value)), -1);
    CHECK_STR_EQ(value, "unchanged");
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK(doc.is_valid);
    CHECK_EQ_INT(toml_get_string(&doc, "settings", "default_scope", value,
                                 sizeof(value)), 0);
    CHECK_STR_EQ(value, "global");

    CHECK_EQ_INT(toml_set_boolean(&doc, "custom", "enabled", true), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK(doc.is_valid);
    CHECK_EQ_INT(toml_get_boolean(&doc, "custom", "enabled", &enabled), 0);
    CHECK(enabled);

    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "system"),
                 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), -1);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_get_string(&doc, "settings", "default_scope", value,
                                 sizeof(value)), -1);

    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"),
                 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK(doc.is_valid);

    /* The public validator also clears a stale flag when a caller has edited
     * the public model directly instead of using a setter. */
    memcpy(doc.sections[0].keys[0].value, "system", sizeof("system"));
    CHECK(doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), -1);
    CHECK(!doc.is_valid);

    toml_cleanup_document(&doc);
}

/* M5 (loader half): a 257-511 char ssh_key passed the writer's cap, so it can
 * be the tool's OWN prior output — the schema's path-length failure must skip
 * that one account, not brick the entire config (pre-fix, every command died
 * until the file was hand-edited). The skipped section stays enumerable so
 * config.c's accounts_skipped_on_load guard sees it and refuses the next
 * save: skip must never become silent erasure. */
TEST(overlong_ssh_key_skips_account_not_whole_file) {
    toml_document_t doc;
    char longpath[302];
    char src[1024];
    char buf[64];
    longpath[0] = '/';
    memset(longpath + 1, 'a', sizeof(longpath) - 2);
    longpath[sizeof(longpath) - 1] = '\0'; /* 301 chars: > 256, < 512 */
    snprintf(src, sizeof(src),
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "ssh_key = \"%s\"\n"
        "[accounts.2]\n"
        "name = \"bob\"\n"
        "email = \"b@b.com\"\n", longpath);
    CHECK_EQ_INT(parse(src, &doc), 0); /* pre-fix: -1, whole file bricked */
    /* The poisoned account reads as absent, so the loader skips it whole
     * instead of loading it with a silently different ssh_key. */
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", buf, sizeof(buf)), -1);
    /* The healthy account is unaffected. */
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.2", "name", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, "bob");
    /* Still enumerable: the data-loss guard depends on seeing the section. */
    char sections[TOML_MAX_SECTIONS][TOML_MAX_SECTION_LEN];
    size_t n = 0;
    CHECK_EQ_INT(toml_get_sections(&doc, sections, TOML_MAX_SECTIONS, &n), 0);
    CHECK_EQ_INT((int)n, 3);
    toml_cleanup_document(&doc);
}

/* AR-08 L5: section visibility is derived state, not a permanent tombstone.
 * The overlong key initially hides this account before the deliberately bad
 * preferred_scope later in the section is examined. Repairing only the key
 * must not expose the still-invalid account; after the remaining field is
 * repaired, a complete validation pass must make the same section visible. */
TEST(repaired_skipped_account_revalidates_visibility_atomically) {
    static toml_document_t doc;
    char longpath[302];
    char src[1024];
    char value[64] = "";

    longpath[0] = '/';
    memset(longpath + 1, 'a', sizeof(longpath) - 2);
    longpath[sizeof(longpath) - 1] = '\0';
    CHECK(snprintf(src, sizeof(src),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"alice\"\n"
                   "email = \"alice@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "preferred_scope = \"system\"\n",
                   longpath) < (int)sizeof(src));

    CHECK_EQ_INT(parse(src, &doc), 0);
    CHECK(doc.is_valid);
    CHECK(!doc.sections[1].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), -1);

    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "ssh_key",
                                 "/tmp/repaired-key"), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), -1);
    CHECK(!doc.is_valid);
    CHECK(!doc.sections[1].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), -1);

    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "preferred_scope",
                                 "local"), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK(doc.is_valid);
    CHECK(doc.sections[1].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), 0);
    CHECK_STR_EQ(value, "alice");
    memset(value, 0, sizeof(value));
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "ssh_key", value,
                                 sizeof(value)), 0);
    CHECK_STR_EQ(value, "/tmp/repaired-key");

    /* Visibility must also be revoked when a later pass finds a previously
     * visible account invalid; publishing at validation entry would expose
     * this bad value after the error return. */
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "preferred_scope",
                                 "system"), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), -1);
    CHECK(!doc.is_valid);
    CHECK(!doc.sections[1].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), -1);

    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "preferred_scope",
                                 "global"), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK(doc.is_valid);
    CHECK(doc.sections[1].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), 0);
    CHECK_STR_EQ(value, "alice");

    toml_cleanup_document(&doc);
}

/* AR-08 L5: validation can fail before reaching every account. Visibility
 * therefore has to be revoked for the entire candidate set before validating
 * the first section, or an invalid later account remains readable after an
 * earlier account aborts the pass. */
TEST(validation_preclear_hides_later_account_on_early_failure) {
    static toml_document_t doc;
    char value[64] = "";

    CHECK_EQ_INT(parse("[settings]\n"
                       "default_scope = \"local\"\n"
                       "[accounts.1]\n"
                       "name = \"alice\"\n"
                       "email = \"alice@example.com\"\n"
                       "preferred_scope = \"local\"\n"
                       "[accounts.2]\n"
                       "name = \"bob\"\n"
                       "email = \"bob@example.com\"\n"
                       "preferred_scope = \"global\"\n",
                       &doc), 0);
    CHECK(doc.is_valid);
    CHECK(doc.sections[1].is_set);
    CHECK(doc.sections[2].is_set);

    /* Account 2 is invalid too, but validation returns while processing the
     * earlier account 1. Both were visible before this failed pass. */
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.2", "preferred_scope",
                                 "system"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "preferred_scope",
                                 "system"), 0);
    CHECK(!doc.is_valid);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), -1);
    CHECK(!doc.is_valid);

    CHECK(!doc.sections[1].is_set);
    CHECK(!doc.sections[2].is_set);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", value,
                                 sizeof(value)), -1);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.2", "name", value,
                                 sizeof(value)), -1);

    toml_cleanup_document(&doc);
}

/* M7: TOML_MAX_SECTIONS(32) contradicted MAX_ACCOUNTS(64) — config_save
 * writes [settings] first, so only 31 accounts fit; the 32nd reported
 * success in memory and silently never reached disk, and a hand-config with
 * 32+ sections failed to load. All 64 accounts plus settings must fit and
 * round-trip. */
TEST(max_accounts_plus_settings_fit_and_round_trip) {
    /* ~600KB each after the M7 bump: static keeps them off the test stack. */
    static toml_document_t doc, doc2;
    char sec[32], name[32], email[64], buf[64];
    char dir[128];
    char path[192];
    if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    int failed_sets = 0;
    for (int i = 1; i <= MAX_ACCOUNTS; i++) {
        snprintf(sec, sizeof(sec), "accounts.%d", i);
        snprintf(name, sizeof(name), "user%d", i);
        snprintf(email, sizeof(email), "u%d@example.com", i);
        if (toml_set_string(&doc, sec, "name", name) != 0) failed_sets++;
        if (toml_set_string(&doc, sec, "email", email) != 0) failed_sets++;
    }
    CHECK_EQ_INT(failed_sets, 0); /* pre-fix: fails from the 32nd section on */
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    toml_cleanup_document(&doc);

    CHECK_EQ_INT(toml_parse_file(path, &doc2), 0);
    CHECK_EQ_INT((int)doc2.section_count, MAX_ACCOUNTS + 1);
    CHECK_EQ_INT(toml_get_string(&doc2, "accounts.64", "name", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, "user64");
    toml_cleanup_document(&doc2);
    remove(path);
}

/* L13: a 0-byte accounts.toml (crashed editor, interrupted copy) bricked
 * every command with the internal "Invalid arguments to toml_parse_string" —
 * indistinguishable from a gitswitch bug. It must fail with a targeted
 * diagnostic that names the actual problem. */
TEST(empty_config_reports_targeted_error) {
    char dir[128];
    char path[192];
    if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f) fclose(f);
    chmod(path, 0600);
    toml_document_t doc;
    CHECK_EQ_INT(toml_parse_file(path, &doc), -1); /* still fails closed... */
    /* ...but says WHAT is wrong, not "Invalid arguments". */
    CHECK(strstr(get_last_error()->message, "empty") != NULL);
    toml_cleanup_document(&doc);
    remove(path);
}

/* L14: duplicate keys in a section were silently accepted first-wins, so a
 * hand-appended `email = ...` override was dead with no diagnostic. TOML
 * requires an error; reject with a line-anchored parse error (see the parser
 * comment for why reject beats last-wins here). */
TEST(rejects_duplicate_key_in_section) {
    toml_document_t doc;
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "email = \"override@b.com\"\n", &doc), -1);
    toml_cleanup_document(&doc);
}

/* AR-05 L10: a repeated table header must be rejected like a repeated key,
 * not silently merged. Merging collapsed an apparent second account into the
 * first and let an appended duplicate block inject keys (ssh_key, ssh_host)
 * into an existing section with no diagnostics — the duplicate-KEY guard
 * only fires when the two blocks share a literal key name. */
TEST(rejects_duplicate_section_header) {
    toml_document_t doc;
    /* Non-overlapping keys: the old parser merged this with no error. */
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "[accounts.1]\n"
        "description = \"injected via appended duplicate table\"\n", &doc), -1);
    toml_cleanup_document(&doc);

    /* Same for a repeated [settings] block. */
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "[settings]\n"
        "active_account = \"alice\"\n", &doc), -1);
    toml_cleanup_document(&doc);

    /* Positive control: DISTINCT sections still parse. */
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "[accounts.2]\n"
        "name = \"bob\"\n"
        "email = \"b@b.com\"\n", &doc), 0);
    toml_cleanup_document(&doc);
}

/* AR-06 F70: the tokenizer consumed one value then returned to line scanning,
 * so trailing content on the same line ("a = 1 b = 2", or a key/value after a
 * section header) was silently swallowed — a second pair on a line was dropped
 * with no diagnostic. Enforce one key/value or one section header per line. */
TEST(rejects_multiple_pairs_per_line) {
    toml_document_t doc;

    /* Two key/value pairs on one line: the second used to be discarded. */
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\" active_account = \"alice\"\n", &doc), -1);
    toml_cleanup_document(&doc);

    /* A key/value trailing a section header on the same line. */
    CHECK_EQ_INT(parse(
        "[accounts.1] name = \"alice\"\n"
        "email = \"a@b.com\"\n", &doc), -1);
    toml_cleanup_document(&doc);

    /* Bare token after a quoted value (not a comment). */
    CHECK_EQ_INT(parse(
        "[settings]\n"
        "default_scope = \"local\" garbage\n", &doc), -1);
    toml_cleanup_document(&doc);

    /* Positive control: a trailing comment and surrounding whitespace parse. */
    CHECK_EQ_INT(parse(
        "[settings]  \n"
        "default_scope = \"local\"   # inline comment\n"
        "active_account = \"alice\"\t\n", &doc), 0);
    toml_cleanup_document(&doc);
}

/* Write→read round-trip with a bracket-heavy description: the injection guard
 * used to count these data brackets and refuse to reload a config the tool
 * had just written (toml F1). */
TEST(bracket_heavy_value_round_trips) {
    toml_document_t doc;
    char desc[48];
    char dir[128];
    char path[192];
    if (make_temp_toml_path(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    memset(desc, '[', sizeof(desc) - 1);
    desc[sizeof(desc) - 1] = '\0';
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "alice"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@b.com"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "description", desc), 0);
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    toml_cleanup_document(&doc);

    toml_document_t doc2;
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

/* Plain traversal is a property of the path and stays whole-file fatal. The
 * backslash-resynthesis spelling (".\./id" has no ".." substring, but
 * sanitizing resynthesizes "../id", AR-02 #29) is caught by the sanitized ==
 * raw round-trip gate; since AR-12 H4 that gate SKIPS the section (hidden
 * from getters, counted, rewrites blocked) instead of failing the parse, so
 * one unloadable value cannot brick every command. The hostile bytes are
 * never handed to any caller either way. */
TEST(rejects_traversal_and_resynthesized_traversal_ssh_key) {
    toml_document_t doc;
    char buf[64];
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
        "ssh_key = \"/home/alice/.\\\\./id_ed25519\"\n", &doc), 0);
    /* The skipped section is hidden from the getters entirely. */
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "ssh_key", buf,
                                 sizeof(buf)), -1);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", buf,
                                 sizeof(buf)), -1);
    toml_cleanup_document(&doc);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(parses_valid_config);
    RUN_TEST(accepts_lf_crlf_and_mixed_line_endings_equivalently);
    RUN_TEST(rejects_bare_carriage_return_line_endings);
    RUN_TEST(crlf_diagnostics_and_escaped_cr_remain_distinct);
    RUN_TEST(file_parser_enforces_the_same_line_ending_grammar);
    RUN_TEST(duplicate_diagnostics_anchor_at_construct_start);
    RUN_TEST(file_parser_rejects_group_or_other_writable_configs);
    RUN_TEST(rejects_overlong_string_value);
    RUN_TEST(rejects_overlong_section_name);
    RUN_TEST(get_string_rejects_value_too_long_for_dest);
    RUN_TEST(injection_patterns_structural_only);
    RUN_TEST(injection_guard_ignores_brackets_in_strings_and_comments);
    RUN_TEST(safe_characters_reject_control);
    RUN_TEST(rejects_control_char_in_string);
    RUN_TEST(quote_in_value_round_trips);
    RUN_TEST(get_string_fails_when_sanitization_would_alter_value);
    RUN_TEST(set_string_rejects_overlong_value_instead_of_erasing);
    RUN_TEST(set_string_rejects_unroundtrippable_values_without_mutation);
    RUN_TEST(set_string_admitted_values_round_trip_byte_exact);
    RUN_TEST(validity_tracks_mutation_and_complete_schema_validation);
    RUN_TEST(overlong_ssh_key_skips_account_not_whole_file);
    RUN_TEST(repaired_skipped_account_revalidates_visibility_atomically);
    RUN_TEST(validation_preclear_hides_later_account_on_early_failure);
    RUN_TEST(max_accounts_plus_settings_fit_and_round_trip);
    RUN_TEST(empty_config_reports_targeted_error);
    RUN_TEST(rejects_duplicate_key_in_section);
    RUN_TEST(rejects_duplicate_section_header);
    RUN_TEST(rejects_multiple_pairs_per_line);
    RUN_TEST(bracket_heavy_value_round_trips);
    RUN_TEST(rejects_relative_ssh_key);
    RUN_TEST(accepts_anchored_ssh_key);
    RUN_TEST(utf8_value_parses_and_round_trips);
    RUN_TEST(safe_characters_reject_c1_and_overlong_utf8);
    RUN_TEST(sanitize_preserves_utf8_strips_controls);
    RUN_TEST(accepts_non_allowlisted_absolute_ssh_key);
    RUN_TEST(rejects_traversal_and_resynthesized_traversal_ssh_key);
TEST_MAIN_END()
