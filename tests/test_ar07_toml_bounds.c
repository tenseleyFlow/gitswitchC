/* AR-07 T3 regression witnesses:
 * - exact, non-NUL-terminated UTF-8 buffers never read past their length;
 * - file and string parser entry points apply the same raw-byte policy; and
 * - a config parse performs exactly one full document initialization clear. */
#include "test.h"
#include "config.h"
#include "error.h"
#include "gitswitch.h"
#include "toml_parser.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static size_t init_observer_calls;
static bool init_observer_mutates_first;
static size_t document_malloc_calls;

static void *counting_document_malloc(size_t size) {
    document_malloc_calls++;
    return malloc(size);
}

static void observe_document_init(toml_document_t *doc) {
    init_observer_calls++;
    if (init_observer_mutates_first && init_observer_calls == 1) {
        /* This field is unused by direct string parsing. A second full
         * initializer would erase the marker, making the count witness
         * sensitive to the actual mutation rather than a call log alone. */
        doc->file_path[sizeof(doc->file_path) - 1] = 'Z';
    }
}

static bool document_is_all_zero(const toml_document_t *doc) {
    const unsigned char *bytes = (const unsigned char *)doc;

    for (size_t i = 0; i < sizeof(*doc); i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

static bool validate_exact(const unsigned char *bytes, size_t length) {
    unsigned char *exact = malloc(length);
    bool valid;

    if (!exact) return false;
    memcpy(exact, bytes, length);
    valid = toml_validate_safe_characters((const char *)exact, length);
    free(exact);
    return valid;
}

TEST(exact_utf8_bounds_reject_truncation_and_keep_valid_endings) {
    static const unsigned char truncated_2[] = {0xC2};
    static const unsigned char truncated_3[] = {0xE2, 0x82};
    static const unsigned char truncated_4[] = {0xF0, 0x9F, 0x92};
    static const unsigned char valid_2[] = {0xC2, 0xA2};       /* U+00A2 */
    static const unsigned char valid_3[] = {0xE2, 0x82, 0xAC}; /* U+20AC */
    static const unsigned char valid_4[] = {0xF0, 0x9F, 0x92, 0xA9}; /* U+1F4A9 */
    static const unsigned char overlong[] = {0xE0, 0x80, 0xAF};
    static const unsigned char surrogate[] = {0xED, 0xA0, 0x80};
    static const unsigned char out_of_range[] = {0xF4, 0x90, 0x80, 0x80};
    static const unsigned char bad_continuation[] = {0xE2, 0x28, 0xA1};
    uint32_t cp = 0;

    CHECK(!validate_exact(truncated_2, sizeof(truncated_2)));
    CHECK(!validate_exact(truncated_3, sizeof(truncated_3)));
    CHECK(!validate_exact(truncated_4, sizeof(truncated_4)));
    CHECK(validate_exact(valid_2, sizeof(valid_2)));
    CHECK(validate_exact(valid_3, sizeof(valid_3)));
    CHECK(validate_exact(valid_4, sizeof(valid_4)));

    CHECK_EQ_INT(utf8_decode(truncated_2, sizeof(truncated_2), &cp), 0);
    CHECK_EQ_INT(utf8_decode(truncated_3, sizeof(truncated_3), &cp), 0);
    CHECK_EQ_INT(utf8_decode(truncated_4, sizeof(truncated_4), &cp), 0);
    CHECK_EQ_INT(utf8_decode(valid_2, sizeof(valid_2), &cp), 2);
    CHECK_EQ_INT(cp, 0x00A2);
    CHECK_EQ_INT(utf8_decode(valid_3, sizeof(valid_3), &cp), 3);
    CHECK_EQ_INT(cp, 0x20AC);
    CHECK_EQ_INT(utf8_decode(valid_4, sizeof(valid_4), &cp), 4);
    CHECK_EQ_INT(cp, 0x1F4A9);

    CHECK(!validate_exact(overlong, sizeof(overlong)));
    CHECK(!validate_exact(surrogate, sizeof(surrogate)));
    CHECK(!validate_exact(out_of_range, sizeof(out_of_range)));
    CHECK(!validate_exact(bad_continuation, sizeof(bad_continuation)));
}

static int write_exact_file(const char *path, const unsigned char *bytes,
                            size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t written = 0;

    if (fd < 0) return -1;
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        return -1;
    }
    while (written < length) {
        ssize_t n = write(fd, bytes + written, length - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    return close(fd);
}

static int parse_string_bytes(const unsigned char *bytes, size_t length) {
    toml_document_t *doc = malloc(sizeof(*doc));
    int result;

    if (!doc) return -2;
    result = toml_parse_string((const char *)bytes, length, doc);
    toml_cleanup_document(doc);
    free(doc);
    return result;
}

static int parse_file_bytes(const char *dir, size_t case_number,
                            const unsigned char *bytes, size_t length) {
    toml_document_t *doc = malloc(sizeof(*doc));
    char path[256];
    int result;

    if (!doc) return -2;
    if ((size_t)snprintf(path, sizeof(path), "%s/case-%zu.toml", dir,
                         case_number) >= sizeof(path) ||
        write_exact_file(path, bytes, length) != 0) {
        free(doc);
        return -2;
    }
    result = toml_parse_file(path, doc);
    toml_cleanup_document(doc);
    free(doc);
    unlink(path);
    return result;
}

typedef struct {
    const char *name;
    const unsigned char *bytes;
    size_t length;
    bool accepted;
} parity_case_t;

#define CASE_BYTES(name, expected) \
    {#name, name, sizeof(name) - 1, expected}

TEST(file_and_string_entry_points_have_identical_byte_gates) {
    static const unsigned char valid_ascii[] =
        "[settings]\ndefault_scope = \"local\"\n";
    static const unsigned char valid_2[] =
        "[settings]\ndefault_scope = \"local\"\n# \xC2\xA2";
    static const unsigned char valid_3[] =
        "[settings]\ndefault_scope = \"local\"\n# \xE2\x82\xAC";
    static const unsigned char valid_4[] =
        "[settings]\ndefault_scope = \"local\"\n# \xF0\x9F\x92\xA9";
    static const unsigned char del[] =
        "[settings]\ndefault_scope = \"local\"\n# \x7F";
    static const unsigned char raw_c1[] =
        "[settings]\ndefault_scope = \"local\"\n# \x9B";
    static const unsigned char encoded_c1[] =
        "[settings]\ndefault_scope = \"local\"\n# \xC2\x9B";
    static const unsigned char malformed[] =
        "[settings]\ndefault_scope = \"local\"\n# \xE2\x28\xA1";
    static const unsigned char truncated_2[] =
        "[settings]\ndefault_scope = \"local\"\n# \xC2";
    static const unsigned char truncated_3[] =
        "[settings]\ndefault_scope = \"local\"\n# \xE2\x82";
    static const unsigned char truncated_4[] =
        "[settings]\ndefault_scope = \"local\"\n# \xF0\x9F\x92";
    static const unsigned char c0_control[] =
        "[settings]\ndefault_scope = \"local\"\n# \x01";
    static const unsigned char embedded_nul[] =
        "[settings]\ndefault_scope = \"local\"\n# \0tail";
    static const unsigned char structural_newline[] =
        "[settings]\ndefault_scope = \"lo\ncal\"\n";
    static const parity_case_t cases[] = {
        CASE_BYTES(valid_ascii, true),
        CASE_BYTES(valid_2, true),
        CASE_BYTES(valid_3, true),
        CASE_BYTES(valid_4, true),
        CASE_BYTES(del, false),
        CASE_BYTES(raw_c1, false),
        CASE_BYTES(encoded_c1, false),
        CASE_BYTES(malformed, false),
        CASE_BYTES(truncated_2, false),
        CASE_BYTES(truncated_3, false),
        CASE_BYTES(truncated_4, false),
        CASE_BYTES(c0_control, false),
        CASE_BYTES(embedded_nul, false),
        CASE_BYTES(structural_newline, false),
    };
    char dir[] = "/tmp/gitswitch-ar07-toml-parity.XXXXXX";

    CHECK(ts_mkdtemp(dir) != NULL);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int string_result = parse_string_bytes(cases[i].bytes,
                                               cases[i].length);
        int file_result = parse_file_bytes(dir, i, cases[i].bytes,
                                           cases[i].length);
        bool string_accepted = string_result == 0;
        bool file_accepted = file_result == 0;

        if (string_accepted != file_accepted ||
            string_accepted != cases[i].accepted) {
            fprintf(stderr,
                    "  parity case %s: string=%d file=%d expected=%d\n",
                    cases[i].name, string_result, file_result,
                    cases[i].accepted ? 0 : -1);
        }
        CHECK(string_accepted == file_accepted);
        CHECK(string_accepted == cases[i].accepted);
    }
}

TEST(public_parse_early_errors_initialize_exactly_once) {
    static const unsigned char valid[] =
        "[settings]\ndefault_scope = \"local\"\n";
    toml_document_t *doc = malloc(sizeof(*doc));
    toml_document_init_hook_fn previous;
    char dir[] = "/tmp/gitswitch-ar07-toml-entry.XXXXXX";
    char path[256];

    CHECK(doc != NULL);
    if (!doc) return;

    memset(doc, 0xA5, sizeof(*doc));
    init_observer_calls = 0;
    init_observer_mutates_first = true;
    previous = toml_set_document_init_hook_fn(observe_document_init);
    CHECK_EQ_INT(toml_parse_string((const char *)valid, sizeof(valid) - 1,
                                   doc), 0);
    toml_set_document_init_hook_fn(previous);
    CHECK_EQ_INT(init_observer_calls, 1);
    CHECK_EQ_INT(doc->file_path[sizeof(doc->file_path) - 1], 'Z');
    toml_cleanup_document(doc);

    memset(doc, 0xA5, sizeof(*doc));
    init_observer_calls = 0;
    init_observer_mutates_first = false;
    previous = toml_set_document_init_hook_fn(observe_document_init);
    CHECK_EQ_INT(toml_parse_string(NULL, 7, doc), -1);
    toml_set_document_init_hook_fn(previous);
    CHECK_EQ_INT(init_observer_calls, 1);
    CHECK(document_is_all_zero(doc));

    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/valid.toml", dir) <
          sizeof(path));
    CHECK_EQ_INT(write_exact_file(path, valid, sizeof(valid) - 1), 0);
    memset(doc, 0xA5, sizeof(*doc));
    init_observer_calls = 0;
    previous = toml_set_document_init_hook_fn(observe_document_init);
    CHECK_EQ_INT(toml_parse_file(path, doc), 0);
    toml_set_document_init_hook_fn(previous);
    CHECK_EQ_INT(init_observer_calls, 1);
    CHECK(doc->is_valid);
    toml_cleanup_document(doc);

    unlink(path);
    memset(doc, 0xA5, sizeof(*doc));
    init_observer_calls = 0;
    previous = toml_set_document_init_hook_fn(observe_document_init);
    CHECK_EQ_INT(toml_parse_file(path, doc), -1);
    toml_set_document_init_hook_fn(previous);
    CHECK_EQ_INT(init_observer_calls, 1);
    CHECK(document_is_all_zero(doc));
    free(doc);
}

static int make_config_tree(char *home, size_t home_size,
                            char *config_path, size_t config_path_size) {
    char dot_config[256];
    char config_dir[256];

    if (home_size < sizeof("/tmp/gitswitch-ar07-toml-init.XXXXXX")) return -1;
    snprintf(home, home_size, "/tmp/gitswitch-ar07-toml-init.XXXXXX");
    if (!ts_mkdtemp(home)) return -1;
    if ((size_t)snprintf(dot_config, sizeof(dot_config), "%s/.config", home) >=
            sizeof(dot_config) ||
        (size_t)snprintf(config_dir, sizeof(config_dir), "%s/gitswitch",
                         dot_config) >= sizeof(config_dir) ||
        (size_t)snprintf(config_path, config_path_size, "%s/accounts.toml",
                         config_dir) >= config_path_size) {
        return -1;
    }
    if (mkdir(dot_config, 0700) != 0 || mkdir(config_dir, 0700) != 0) {
        return -1;
    }
    return 0;
}

TEST(config_parse_has_one_full_initialization_owner) {
    static const unsigned char valid[] =
        "[settings]\ndefault_scope = \"local\"\n";
    toml_document_init_hook_fn previous;
    config_document_malloc_fn previous_malloc;
    gitswitch_ctx_t *ctx = calloc(1, sizeof(*ctx));
    const char *old_home = getenv("HOME");
    char *saved_home = old_home ? strdup(old_home) : NULL;
    char home[128];
    char config_path[256];
    bool home_changed = false;
    int setup_result;

    CHECK(ctx != NULL);
    CHECK(!old_home || saved_home != NULL);
    if (!ctx || (old_home && !saved_home)) {
        free(ctx);
        free(saved_home);
        return;
    }
    setup_result = make_config_tree(home, sizeof(home), config_path,
                                    sizeof(config_path));
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    setup_result = write_exact_file(config_path, valid, sizeof(valid) - 1);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    setup_result = setenv("HOME", home, 1);
    CHECK_EQ_INT(setup_result, 0);
    if (setup_result != 0) goto cleanup;
    home_changed = true;

    init_observer_calls = 0;
    init_observer_mutates_first = false;
    document_malloc_calls = 0;
    previous_malloc = config_set_document_malloc_fn(counting_document_malloc);
    CHECK(previous_malloc == malloc);
    previous = toml_set_document_init_hook_fn(observe_document_init);
    CHECK_EQ_INT(config_init_readonly(ctx), 0);
    toml_set_document_init_hook_fn(previous);
    CHECK(config_set_document_malloc_fn(previous_malloc) ==
          counting_document_malloc);
    CHECK_EQ_INT(document_malloc_calls, 1);
    CHECK_EQ_INT(init_observer_calls, 1);

cleanup:
    if (home_changed) {
        if (saved_home) {
            CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
        } else {
            CHECK_EQ_INT(unsetenv("HOME"), 0);
        }
    }
    free(saved_home);
    free(ctx);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(exact_utf8_bounds_reject_truncation_and_keep_valid_endings);
    RUN_TEST(file_and_string_entry_points_have_identical_byte_gates);
    RUN_TEST(public_parse_early_errors_initialize_exactly_once);
    RUN_TEST(config_parse_has_one_full_initialization_owner);
TEST_MAIN_END()
