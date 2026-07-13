/* AR-07 T20: public TOML setter, grammar, writer, and failure-atomicity
 * regressions. */
#include "test.h"

#include "signals.h"
#include "toml_parser.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

static int make_fixture(char *dir, size_t dir_size,
                        char *path, size_t path_size) {
    int written = snprintf(dir, dir_size, "/tmp/gitswitch-ar07-toml-XXXXXX");
    if (written < 0 || (size_t)written >= dir_size || !ts_mkdtemp(dir)) {
        return -1;
    }
    written = snprintf(path, path_size, "%s/config.toml", dir);
    if (written < 0 || (size_t)written >= path_size) return -1;
    return 0;
}

static int write_exact_file(const char *path, const char *contents) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    size_t length = strlen(contents);
    size_t total = 0;
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
    int result = fchmod(fd, 0600);
    int saved_errno = errno;
    if (close(fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result != 0) errno = saved_errno;
    return result;
}

static int read_exact_file(const char *path, char *buffer, size_t size) {
    FILE *file = fopen(path, "rb");
    if (!file || size == 0) {
        if (file) (void)fclose(file);
        return -1;
    }

    size_t length = fread(buffer, 1, size - 1, file);
    bool read_failed = ferror(file) != 0;
    bool complete = feof(file) != 0;
    int close_result = fclose(file);
    if (read_failed || !complete || close_result != 0) return -1;
    buffer[length] = '\0';
    return 0;
}

static int read_file_bytes(const char *path, unsigned char *buffer,
                           size_t capacity, size_t *length) {
    int fd;
    size_t total = 0;
    unsigned char extra;
    ssize_t result;

    if (!path || !buffer || capacity == 0 || !length) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    while (total < capacity) {
        result = read(fd, buffer + total, capacity - total);
        if (result > 0) {
            total += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else if (result == 0) {
            break;
        } else {
            (void)close(fd);
            return -1;
        }
    }

    do {
        result = read(fd, &extra, sizeof(extra));
    } while (result < 0 && errno == EINTR);
    if (result != 0 || close(fd) != 0) return -1;

    *length = total;
    return 0;
}

static int count_writer_temps(const char *dir) {
    DIR *stream = opendir(dir);
    if (!stream) return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strstr(entry->d_name, ".gitswitch-toml.") != NULL) count++;
    }
    if (closedir(stream) != 0) return -1;
    return count;
}

static int parse_named_section(const char *name, const char *trailing,
                               toml_document_t *doc) {
    char source[256];
    int written = snprintf(source, sizeof(source),
                           "[settings]\n"
                           "default_scope = \"local\"\n"
                           "[%s%s]\n",
                           name, trailing);
    if (written < 0 || (size_t)written >= sizeof(source)) return -1;
    return toml_parse_string(source, (size_t)written, doc);
}

static int parse_integer_literal(const char *literal, toml_document_t *doc) {
    char source[160];
    int written = snprintf(source, sizeof(source),
                           "[settings]\n"
                           "default_scope = \"local\"\n"
                           "[numbers]\n"
                           "value = %s\n",
                           literal);
    if (written < 0 || (size_t)written >= sizeof(source)) return -1;
    return toml_parse_string(source, (size_t)written, doc);
}

static int parse_named_key(const char *key, toml_document_t *doc) {
    char source[512];
    int written = snprintf(source, sizeof(source),
                           "[settings]\n"
                           "default_scope = \"local\"\n"
                           "%s = \"value\"\n",
                           key);
    if (written < 0 || (size_t)written >= sizeof(source)) return -1;
    return toml_parse_string(source, (size_t)written, doc);
}

static char g_hook_original[192];
static char g_hook_moved[192];
static char g_hook_replacement_file[256];
static char g_hook_temp_path[256];
static bool g_hook_succeeded;

static void replace_writer_parent(toml_writer_test_stage_t stage,
                                  const char *directory,
                                  const char *temp_name) {
    (void)temp_name;
    g_hook_succeeded = false;
    if (stage != TOML_WRITER_TEST_AFTER_TEMP_CREATE ||
        strcmp(directory, g_hook_original) != 0) {
        return;
    }
    if (rename(g_hook_original, g_hook_moved) != 0 ||
        mkdir(g_hook_original, 0700) != 0 ||
        write_exact_file(g_hook_replacement_file, "REPLACEMENT\n") != 0) {
        return;
    }
    g_hook_succeeded = true;
}

static void replace_writer_temp(toml_writer_test_stage_t stage,
                                const char *directory,
                                const char *temp_name) {
    g_hook_succeeded = false;
    if (stage != TOML_WRITER_TEST_AFTER_TEMP_CREATE) return;
    int written = snprintf(g_hook_temp_path, sizeof(g_hook_temp_path),
                           "%s/%s", directory, temp_name);
    if (written < 0 || (size_t)written >= sizeof(g_hook_temp_path) ||
        unlink(g_hook_temp_path) != 0 ||
        write_exact_file(g_hook_temp_path, "ATTACKER\n") != 0) {
        return;
    }
    g_hook_succeeded = true;
}

/* Build exactly the largest document both parser entry points admit. There are
 * 65 sections (settings + s00..s63), 16 three-byte keys per bulk section, and
 * 64 inter-section blank lines. Headers, key syntax, and separators therefore
 * consume 9,699 bytes. Serialized values consume the remaining 55,837 bytes:
 * one raw backslash expands to two bytes, 593 values use 55 bytes, and 430 use
 * 54 bytes. Keeping an escaped byte in the fixture prevents a raw strlen-based
 * approximation from satisfying the writer/parser boundary contract. */
static int build_maximum_reloadable_document(toml_document_t *doc) {
    size_t value_index = 0;
    char section[8];
    char key[8];
    char value[TOML_MAX_VALUE_LEN];

    if (!doc || TOML_MAX_SECTIONS != 65 ||
        TOML_MAX_KEYS_PER_SECTION != 16 || TOML_MAX_FILE_SIZE != 65536) {
        return -1;
    }

    toml_init_document(doc);
    if (toml_set_string(doc, "settings", "default_scope", "local") != 0) {
        return -1;
    }

    for (size_t section_index = 0; section_index < 64; section_index++) {
        if (snprintf(section, sizeof(section), "s%02zu", section_index) != 3) {
            return -1;
        }
        for (size_t key_index = 0; key_index < 16; key_index++, value_index++) {
            if (snprintf(key, sizeof(key), "k%02zu", key_index) != 3) {
                return -1;
            }
            if (value_index == 0) {
                value[0] = '\\';
                value[1] = '\0';
            } else {
                size_t value_length = value_index <= 593 ? 55 : 54;
                memset(value, 'v', value_length);
                value[value_length] = '\0';
            }
            if (toml_set_string(doc, section, key, value) != 0) return -1;
        }
    }

    return value_index == 1024 ? 0 : -1;
}

TEST(setters_reject_invalid_sections_without_mutating_document) {
    static toml_document_t doc;
    static toml_document_t before;
    char legal[TOML_MAX_SECTION_LEN];
    char oversized[TOML_MAX_SECTION_LEN + 1];
    char dir[128];
    char path[192];
    char serialized[1024];

    memset(legal, 'a', sizeof(legal) - 1);
    legal[sizeof(legal) - 1] = '\0';
    memset(oversized, 'b', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    memcpy(&before, &doc, sizeof(before));

    CHECK_EQ_INT(toml_set_string(&doc, oversized, "value", "x"), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK_EQ_INT(toml_set_boolean(&doc, oversized, "enabled", true), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);

    CHECK_EQ_INT(toml_set_string(&doc, "bad section", "value", "x"), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK_EQ_INT(toml_set_boolean(&doc, "bad]section", "enabled", true), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);

    CHECK_EQ_INT(toml_set_string(&doc, legal, "value", "x"), 0);
    CHECK_EQ_INT(toml_set_boolean(&doc, legal, "enabled", true), 0);
    CHECK_EQ_INT((int)doc.section_count, 2);
    CHECK_STR_EQ(doc.sections[1].name, legal);

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
    } else {
        CHECK_EQ_INT(toml_write_file(&doc, path), 0);
        CHECK_EQ_INT(read_exact_file(path, serialized, sizeof(serialized)), 0);
        CHECK(strstr(serialized, "[]") == NULL);
        CHECK_EQ_INT(count_writer_temps(dir), 0);
    }
    toml_cleanup_document(&doc);
    toml_cleanup_document(&before);
}

TEST(key_name_grammar_rejects_invalid_setters_without_mutation) {
    static const char *const invalid_keys[] = {
        "",
        "1lead",
        "has space",
        "has-hyphen",
        "has.dot",
        "\xC3\xA9" "key"
    };
    static toml_document_t doc;
    static toml_document_t before;
    toml_document_t parsed;

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    memcpy(&before, &doc, sizeof(before));

    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); i++) {
        memcpy(&doc, &before, sizeof(doc));
        CHECK_EQ_INT(toml_set_string(&doc, "new_section", invalid_keys[i],
                                     "value"), -1);
        CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);

        memcpy(&doc, &before, sizeof(doc));
        CHECK_EQ_INT(toml_set_boolean(&doc, "new_section", invalid_keys[i],
                                      true), -1);
        CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);

        CHECK_EQ_INT(parse_named_key(invalid_keys[i], &parsed), -1);
        toml_cleanup_document(&parsed);
    }

    toml_cleanup_document(&doc);
    toml_cleanup_document(&before);
}

TEST(key_name_grammar_accepts_ascii_boundaries_and_round_trips) {
    static const char spaced_source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "  _under \t= \"spaced\"\n"
        "alpha123 = true\n";
    static toml_document_t doc;
    static toml_document_t before;
    static toml_document_t loaded;
    char max_key[TOML_MAX_KEY_LEN];
    char oversized[TOML_MAX_KEY_LEN + 1];
    char dir[128];
    char path[192];
    char value[32] = "";
    bool enabled = false;

    max_key[0] = 'k';
    memset(max_key + 1, 'a', sizeof(max_key) - 2);
    max_key[sizeof(max_key) - 1] = '\0';
    oversized[0] = 'k';
    memset(oversized + 1, 'b', sizeof(oversized) - 2);
    oversized[sizeof(oversized) - 1] = '\0';

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "_under", "value"), 0);
    CHECK_EQ_INT(toml_set_boolean(&doc, "settings", "alpha123", true), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", max_key, "boundary"), 0);
    memcpy(&before, &doc, sizeof(before));

    CHECK_EQ_INT(toml_set_string(&doc, "new_section", oversized, "value"), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK_EQ_INT(toml_set_boolean(&doc, "new_section", oversized, true), -1);
    CHECK(memcmp(&doc, &before, sizeof(doc)) == 0);
    CHECK_EQ_INT(parse_named_key(oversized, &loaded), -1);
    toml_cleanup_document(&loaded);

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
    } else {
        CHECK_EQ_INT(toml_write_file(&doc, path), 0);
        CHECK_EQ_INT(toml_parse_file(path, &loaded), 0);
        CHECK_EQ_INT(toml_get_string(&loaded, "settings", "_under", value,
                                     sizeof(value)), 0);
        CHECK_STR_EQ(value, "value");
        CHECK_EQ_INT(toml_get_boolean(&loaded, "settings", "alpha123",
                                      &enabled), 0);
        CHECK(enabled);
        memset(value, 0, sizeof(value));
        CHECK_EQ_INT(toml_get_string(&loaded, "settings", max_key, value,
                                     sizeof(value)), 0);
        CHECK_STR_EQ(value, "boundary");
        CHECK_EQ_INT(count_writer_temps(dir), 0);
        toml_cleanup_document(&loaded);
        CHECK_EQ_INT(unlink(path), 0);
    }

    CHECK_EQ_INT(toml_parse_string(spaced_source, sizeof(spaced_source) - 1,
                                   &loaded), 0);
    memset(value, 0, sizeof(value));
    CHECK_EQ_INT(toml_get_string(&loaded, "settings", "_under", value,
                                 sizeof(value)), 0);
    CHECK_STR_EQ(value, "spaced");
    enabled = false;
    CHECK_EQ_INT(toml_get_boolean(&loaded, "settings", "alpha123", &enabled), 0);
    CHECK(enabled);

    toml_cleanup_document(&loaded);
    toml_cleanup_document(&doc);
    toml_cleanup_document(&before);
}

TEST(section_boundary_classifies_trailing_whitespace_before_overflow) {
    toml_document_t doc;
    char max_name[TOML_MAX_SECTION_LEN];
    char too_long[TOML_MAX_SECTION_LEN + 1];
    char interior[TOML_MAX_SECTION_LEN];

    memset(max_name, 'a', sizeof(max_name) - 1);
    max_name[sizeof(max_name) - 1] = '\0';
    memset(too_long, 'b', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    memcpy(interior, max_name, sizeof(interior));
    interior[17] = ' ';

    CHECK_EQ_INT(parse_named_section(max_name, "", &doc), 0);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse_named_section(max_name, " ", &doc), 0);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse_named_section(max_name, "\t", &doc), 0);
    toml_cleanup_document(&doc);

    CHECK_EQ_INT(parse_named_section(too_long, "", &doc), -1);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse_named_section(too_long, " ", &doc), -1);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(parse_named_section(too_long, "\t", &doc), -1);
    toml_cleanup_document(&doc);

    CHECK_EQ_INT(parse_named_section(interior, "", &doc), -1);
    toml_cleanup_document(&doc);
}

TEST(integer_grammar_rejects_leading_zero_magnitudes) {
    static const char *const rejected[] = {"00", "01", "+01", "-01"};
    static const struct {
        const char *literal;
        int expected;
    } accepted[] = {
        {"0", 0}, {"+0", 0}, {"-0", 0},
        {"10", 10}, {"+10", 10}, {"-10", -10}
    };
    toml_document_t doc;

    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        CHECK_EQ_INT(parse_integer_literal(rejected[i], &doc), -1);
        CHECK(!doc.is_valid);
        toml_cleanup_document(&doc);
    }
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        int value = 999;
        CHECK_EQ_INT(parse_integer_literal(accepted[i].literal, &doc), 0);
        CHECK_EQ_INT(toml_get_integer(&doc, "numbers", "value", &value), 0);
        CHECK_EQ_INT(value, accepted[i].expected);
        toml_cleanup_document(&doc);
    }
}

TEST(writer_enforces_the_inclusive_parser_file_size_boundary) {
    static toml_document_t doc;
    static toml_document_t loaded;
    static unsigned char before_bytes[TOML_MAX_FILE_SIZE + 1];
    static unsigned char after_bytes[TOML_MAX_FILE_SIZE + 1];
    char dir[128];
    char path[192];
    char over_value[56];
    char loaded_value[64] = "";
    struct stat before_identity;
    struct stat after_identity;
    size_t before_length = 0;
    size_t after_length = 0;

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(build_maximum_reloadable_document(&doc), 0);
    CHECK_EQ_INT((int)doc.section_count, TOML_MAX_SECTIONS);

    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    CHECK_EQ_INT(lstat(path, &before_identity), 0);
    CHECK_EQ_INT((int)before_identity.st_size, TOML_MAX_FILE_SIZE);
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    CHECK_EQ_INT(read_file_bytes(path, before_bytes, sizeof(before_bytes),
                                 &before_length), 0);
    CHECK_EQ_INT((int)before_length, TOML_MAX_FILE_SIZE);
    CHECK_EQ_INT(toml_parse_file(path, &loaded), 0);
    CHECK_EQ_INT(toml_get_string(&loaded, "s63", "k15", loaded_value,
                                 sizeof(loaded_value)), 0);
    CHECK_EQ_INT((int)strlen(loaded_value), 54);
    toml_cleanup_document(&loaded);

    /* Grow only the final plain value. The serialized document is now exactly
     * one byte beyond the shared parser limit. A failed publication must leave
     * the prior inode and every prior byte intact. */
    memset(over_value, 'v', sizeof(over_value) - 1);
    over_value[sizeof(over_value) - 1] = '\0';
    CHECK_EQ_INT(toml_set_string(&doc, "s63", "k15", over_value), 0);
    CHECK_EQ_INT(toml_write_file(&doc, path), -1);

    CHECK_EQ_INT(lstat(path, &after_identity), 0);
    CHECK(before_identity.st_dev == after_identity.st_dev);
    CHECK(before_identity.st_ino == after_identity.st_ino);
    CHECK_EQ_INT((int)after_identity.st_size, TOML_MAX_FILE_SIZE);
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    CHECK_EQ_INT(read_file_bytes(path, after_bytes, sizeof(after_bytes),
                                 &after_length), 0);
    CHECK_EQ_INT((int)after_length, TOML_MAX_FILE_SIZE);
    if (before_length == after_length) {
        CHECK(memcmp(before_bytes, after_bytes, before_length) == 0);
    } else {
        CHECK(0);
    }

    memset(loaded_value, 0, sizeof(loaded_value));
    CHECK_EQ_INT(toml_parse_file(path, &loaded), 0);
    CHECK_EQ_INT(toml_get_string(&loaded, "s63", "k15", loaded_value,
                                 sizeof(loaded_value)), 0);
    CHECK_EQ_INT((int)strlen(loaded_value), 54);
    toml_cleanup_document(&loaded);
    toml_cleanup_document(&doc);
    CHECK_EQ_INT(unlink(path), 0);
}

TEST(rlimit_write_failure_preserves_destination_and_removes_temp) {
    static const char original[] = "ORIGINAL-CONTENT\n";
    static toml_document_t doc;
    char dir[128];
    char path[192];
    char contents[256];

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0 ||
        write_exact_file(path, original) != 0) {
        CHECK(0);
        return;
    }
    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "alice"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@example.com"), 0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct rlimit limit = {16, 16};
        if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR ||
            setrlimit(RLIMIT_FSIZE, &limit) != 0) {
            _exit(2);
        }
        _exit(toml_write_file(&doc, path) == -1 ? 0 : 3);
    }
    if (child > 0) {
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        CHECK_EQ_INT(waited, child);
        if (waited == child) {
            CHECK(WIFEXITED(status));
            if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
        }
    }

    CHECK_EQ_INT(read_exact_file(path, contents, sizeof(contents)), 0);
    CHECK_STR_EQ(contents, original);
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    toml_cleanup_document(&doc);
}

TEST(normal_atomic_replacement_reloads_and_does_not_follow_symlink) {
    static toml_document_t doc;
    toml_document_t loaded;
    char dir[128];
    char path[192];
    char sentinel[192];
    char link_path[192];
    char contents[512];
    char value[64];
    struct stat metadata;

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(write_exact_file(path, "old\n"), 0);
    CHECK((size_t)snprintf(sentinel, sizeof(sentinel), "%s/sentinel", dir) <
          sizeof(sentinel));
    CHECK((size_t)snprintf(link_path, sizeof(link_path), "%s/link.toml", dir) <
          sizeof(link_path));
    CHECK_EQ_INT(write_exact_file(sentinel, "DO-NOT-TOUCH\n"), 0);
    CHECK_EQ_INT(symlink("sentinel", link_path), 0);

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "global"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "name", "alice"), 0);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "email", "a@example.com"), 0);

    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    CHECK_EQ_INT(lstat(path, &metadata), 0);
    CHECK(S_ISREG(metadata.st_mode));
    CHECK_EQ_INT((int)(metadata.st_mode & 0777), 0600);
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    CHECK_EQ_INT(toml_parse_file(path, &loaded), 0);
    CHECK_EQ_INT(toml_get_string(&loaded, "accounts.1", "name",
                                 value, sizeof(value)), 0);
    CHECK_STR_EQ(value, "alice");
    toml_cleanup_document(&loaded);

    /* rename replaces the link itself; it never opens/truncates the target. */
    CHECK_EQ_INT(toml_write_file(&doc, link_path), 0);
    CHECK_EQ_INT(lstat(link_path, &metadata), 0);
    CHECK(S_ISREG(metadata.st_mode));
    CHECK_EQ_INT(read_exact_file(sentinel, contents, sizeof(contents)), 0);
    CHECK_STR_EQ(contents, "DO-NOT-TOUCH\n");
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    toml_cleanup_document(&doc);
}

TEST(parent_namespace_replacement_fails_and_cleans_pinned_temp) {
    static toml_document_t doc;
    char dir[128];
    char path[192];
    char moved_path[256];
    char original_contents[64];
    char replacement_contents[64];

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0 ||
        write_exact_file(path, "ORIGINAL\n") != 0) {
        CHECK(0);
        return;
    }
    CHECK((size_t)snprintf(moved_path, sizeof(moved_path), "%s.moved", dir) <
          sizeof(moved_path));
    CHECK((size_t)snprintf(g_hook_original, sizeof(g_hook_original), "%s", dir) <
          sizeof(g_hook_original));
    CHECK((size_t)snprintf(g_hook_moved, sizeof(g_hook_moved), "%s", moved_path) <
          sizeof(g_hook_moved));
    CHECK((size_t)snprintf(g_hook_replacement_file,
                           sizeof(g_hook_replacement_file), "%s/config.toml",
                           dir) < sizeof(g_hook_replacement_file));

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    toml_writer_test_hook_fn previous =
        toml_set_writer_test_hook_fn(replace_writer_parent);
    g_hook_succeeded = false;
    CHECK_EQ_INT(toml_write_file(&doc, path), -1);
    CHECK(toml_set_writer_test_hook_fn(previous) == replace_writer_parent);
    CHECK(g_hook_succeeded);

    CHECK_EQ_INT(read_exact_file(g_hook_replacement_file, replacement_contents,
                                 sizeof(replacement_contents)), 0);
    CHECK_STR_EQ(replacement_contents, "REPLACEMENT\n");
    CHECK((size_t)snprintf(path, sizeof(path), "%s/config.toml", moved_path) <
          sizeof(path));
    CHECK_EQ_INT(read_exact_file(path, original_contents,
                                 sizeof(original_contents)), 0);
    CHECK_STR_EQ(original_contents, "ORIGINAL\n");
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    CHECK_EQ_INT(count_writer_temps(moved_path), 0);

    /* Restore the tracked fixture name so test.h's atexit sweep removes the
     * original directory as usual. */
    ts_rm_rf(dir);
    CHECK_EQ_INT(rename(moved_path, dir), 0);
    toml_cleanup_document(&doc);
}

TEST(temp_namespace_replacement_is_never_published_or_unlinked) {
    static toml_document_t doc;
    char dir[128];
    char path[192];
    char original_contents[64];
    char replacement_contents[64];

    if (make_fixture(dir, sizeof(dir), path, sizeof(path)) != 0 ||
        write_exact_file(path, "ORIGINAL\n") != 0) {
        CHECK(0);
        return;
    }

    toml_init_document(&doc);
    CHECK_EQ_INT(toml_set_string(&doc, "settings", "default_scope", "local"), 0);
    toml_writer_test_hook_fn previous =
        toml_set_writer_test_hook_fn(replace_writer_temp);
    g_hook_succeeded = false;
    g_hook_temp_path[0] = '\0';
    CHECK_EQ_INT(toml_write_file(&doc, path), -1);
    CHECK(toml_set_writer_test_hook_fn(previous) == replace_writer_temp);
    CHECK(g_hook_succeeded);

    CHECK_EQ_INT(read_exact_file(path, original_contents,
                                 sizeof(original_contents)), 0);
    CHECK_STR_EQ(original_contents, "ORIGINAL\n");
    CHECK_EQ_INT(read_exact_file(g_hook_temp_path, replacement_contents,
                                 sizeof(replacement_contents)), 0);
    CHECK_STR_EQ(replacement_contents, "ATTACKER\n");
    CHECK_EQ_INT(count_writer_temps(dir), 1);

    /* Writer cleanup must neither unlink the substituted inode nor retain a
     * path-only scratch slot that could delete it later. */
    signals_scratch_cleanup();
    CHECK_EQ_INT(read_exact_file(g_hook_temp_path, replacement_contents,
                                 sizeof(replacement_contents)), 0);
    CHECK_STR_EQ(replacement_contents, "ATTACKER\n");
    CHECK_EQ_INT(unlink(g_hook_temp_path), 0);
    CHECK_EQ_INT(count_writer_temps(dir), 0);
    toml_cleanup_document(&doc);
}

TEST_MAIN_BEGIN()
    RUN_TEST(setters_reject_invalid_sections_without_mutating_document);
    RUN_TEST(key_name_grammar_rejects_invalid_setters_without_mutation);
    RUN_TEST(key_name_grammar_accepts_ascii_boundaries_and_round_trips);
    RUN_TEST(section_boundary_classifies_trailing_whitespace_before_overflow);
    RUN_TEST(integer_grammar_rejects_leading_zero_magnitudes);
    RUN_TEST(writer_enforces_the_inclusive_parser_file_size_boundary);
    RUN_TEST(rlimit_write_failure_preserves_destination_and_removes_temp);
    RUN_TEST(normal_atomic_replacement_reloads_and_does_not_follow_symlink);
    RUN_TEST(parent_namespace_replacement_fails_and_cleans_pinned_temp);
    RUN_TEST(temp_namespace_replacement_is_never_published_or_unlinked);
TEST_MAIN_END()
