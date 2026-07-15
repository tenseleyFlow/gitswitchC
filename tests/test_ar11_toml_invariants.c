/* AR-11 T4: TOML path parity, public-model invariants, namespace integrity,
 * required-set semantics, exact diagnostics, and implicit-root round trips. */
#include "test.h"

#include "error.h"
#include "toml_parser.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_bytes(const char *path, const char *contents) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(contents);
    size_t offset = 0;

    if (fd < 0) return -1;
    while (offset < length) {
        ssize_t written = write(fd, contents + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            (void)close(fd);
            return -1;
        }
    }
    return close(fd);
}

static int read_bytes(const char *path, char *contents, size_t capacity) {
    int fd;
    size_t offset = 0;

    if (!contents || capacity == 0) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    while (offset + 1 < capacity) {
        ssize_t count = read(fd, contents + offset, capacity - offset - 1);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            (void)close(fd);
            return -1;
        }
    }
    contents[offset] = '\0';
    return close(fd);
}

static int count_writer_temps(const char *directory) {
    DIR *stream = opendir(directory);
    struct dirent *entry;
    int count = 0;

    if (!stream) return -1;
    while ((entry = readdir(stream)) != NULL) {
        if (strstr(entry->d_name, ".gitswitch-toml.") != NULL) count++;
    }
    if (closedir(stream) != 0) return -1;
    return count;
}

static toml_document_t *new_document(void) {
    toml_document_t *doc = malloc(sizeof(*doc));
    if (doc) toml_init_document(doc);
    return doc;
}

static int add_minimum_settings(toml_document_t *doc) {
    return toml_set_string(doc, "settings", "default_scope", "local");
}

static toml_section_t *mutable_section(toml_document_t *doc,
                                       const char *name) {
    if (!doc || doc->section_count > TOML_MAX_SECTIONS) return NULL;
    for (size_t i = 0; i < doc->section_count; i++) {
        if (strcmp(doc->sections[i].name, name) == 0) {
            return &doc->sections[i];
        }
    }
    return NULL;
}

static toml_keyvalue_t *mutable_key(toml_document_t *doc,
                                    const char *section_name,
                                    const char *key_name) {
    toml_section_t *section = mutable_section(doc, section_name);
    if (!section || section->key_count > TOML_MAX_KEYS_PER_SECTION) return NULL;
    for (size_t i = 0; i < section->key_count; i++) {
        if (strcmp(section->keys[i].key, key_name) == 0) {
            return &section->keys[i];
        }
    }
    return NULL;
}

static int call_typed_getter(const toml_document_t *doc, size_t route) {
    char string_value[32];
    int integer_value = 0;
    bool boolean_value = false;

    switch (route) {
        case 0:
            return toml_get_string(doc, "custom", "text", string_value,
                                   sizeof(string_value));
        case 1:
            return toml_get_integer(doc, "custom", "number", &integer_value);
        case 2:
            return toml_get_boolean(doc, "custom", "enabled", &boolean_value);
        default:
            return 0;
    }
}

static size_t g_model_preflight_calls;

static bool count_model_preflight(toml_metadata_test_stage_t stage) {
    if (stage == TOML_METADATA_TEST_MODEL_PREFLIGHT) {
        g_model_preflight_calls++;
    }
    return false;
}

/* Construct a non-existent final path with an exact total byte length. Every
 * component remains below common NAME_MAX limits; intermediate directories
 * are created as needed. */
static int make_sized_path(const char *base, size_t target_length,
                           char *path, size_t capacity) {
    size_t length = strlen(base);

    if (target_length <= length + 1 || target_length >= capacity) return -1;
    memcpy(path, base, length + 1);
    while (target_length - length > 256) {
        size_t component = target_length - length - 2;
        if (component > 120) component = 120;
        path[length++] = '/';
        memset(path + length, 'd', component);
        length += component;
        path[length] = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    }
    path[length++] = '/';
    memset(path + length, 'f', target_length - length);
    path[target_length] = '\0';
    return strlen(path) == target_length ? 0 : -1;
}

TEST(config_file_paths_follow_filesystem_limits_not_ssh_data_policy) {
    static const size_t accepted_lengths[] = {256, 257, 700};
    char directory[] = "/tmp/gitswitch-ar11-toml-path.XXXXXX";
    char path[MAX_PATH_LEN];
    char lexical[MAX_PATH_LEN];
    char child[MAX_PATH_LEN];
    toml_document_t *source = new_document();
    toml_document_t *loaded = new_document();

    CHECK(source != NULL);
    CHECK(loaded != NULL);
    CHECK(ts_mkdtemp(directory) != NULL);
    if (!source || !loaded) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(source), 0);

    for (size_t i = 0; i < sizeof(accepted_lengths) / sizeof(accepted_lengths[0]); i++) {
        CHECK_EQ_INT(make_sized_path(directory, accepted_lengths[i], path,
                                     sizeof(path)), 0);
        CHECK_EQ_INT((int)strlen(path), (int)accepted_lengths[i]);
        CHECK_EQ_INT(toml_write_file(source, path), 0);
        CHECK_EQ_INT(toml_parse_file(path, loaded), 0);
        CHECK_STR_EQ(loaded->file_path, path);
        CHECK_EQ_INT(unlink(path), 0);
    }

    CHECK((size_t)snprintf(child, sizeof(child), "%s/child", directory) <
          sizeof(child));
    CHECK_EQ_INT(mkdir(child, 0700), 0);
    CHECK((size_t)snprintf(lexical, sizeof(lexical), "%s/child/../dotdot.toml",
                           directory) < sizeof(lexical));
    CHECK_EQ_INT(toml_write_file(source, lexical), 0);
    CHECK_EQ_INT(toml_parse_file(lexical, loaded), 0);
    CHECK_STR_EQ(loaded->file_path, lexical);
    CHECK(!toml_validate_file_path(lexical));

cleanup:
    free(loaded);
    free(source);
    ts_rm_rf(directory);
}

TEST(config_file_path_shape_rejections_are_symmetric) {
    char directory[] = "/tmp/gitswitch-ar11-toml-shape.XXXXXX";
    char trailing[MAX_PATH_LEN];
    char *over_limit = NULL;
    toml_document_t *source = new_document();
    toml_document_t *loaded = new_document();

    CHECK(source != NULL);
    CHECK(loaded != NULL);
    CHECK(ts_mkdtemp(directory) != NULL);
    if (!source || !loaded) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(source), 0);

    clear_error();
    CHECK_EQ_INT(toml_write_file(source, ""), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "empty") != NULL);
    clear_error();
    CHECK_EQ_INT(toml_parse_file("", loaded), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "empty") != NULL);

    CHECK((size_t)snprintf(trailing, sizeof(trailing), "%s/", directory) <
          sizeof(trailing));
    clear_error();
    CHECK_EQ_INT(toml_write_file(source, trailing), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "not a directory") != NULL);
    clear_error();
    CHECK_EQ_INT(toml_parse_file(trailing, loaded), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "not a directory") != NULL);

    over_limit = malloc(MAX_PATH_LEN + 1U);
    CHECK(over_limit != NULL);
    if (!over_limit) goto cleanup;
    memset(over_limit, 'x', MAX_PATH_LEN);
    over_limit[MAX_PATH_LEN] = '\0';
    memcpy(over_limit, directory, strlen(directory));
    over_limit[strlen(directory)] = '/';
    CHECK_EQ_INT((int)strlen(over_limit), MAX_PATH_LEN);

    clear_error();
    CHECK_EQ_INT(toml_write_file(source, over_limit), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "application limit") != NULL);
    CHECK_EQ_INT(count_writer_temps(directory), 0);
    clear_error();
    CHECK_EQ_INT(toml_parse_file(over_limit, loaded), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_PATH);
    CHECK(strstr(get_last_error()->message, "application limit") != NULL);

cleanup:
    free(over_limit);
    free(loaded);
    free(source);
    ts_rm_rf(directory);
}

TEST(stored_ssh_path_validator_keeps_its_256_byte_and_traversal_contract) {
    char at_limit[257];
    char over_limit[258];

    at_limit[0] = '/';
    memset(at_limit + 1, 'a', sizeof(at_limit) - 2);
    at_limit[sizeof(at_limit) - 1] = '\0';
    over_limit[0] = '/';
    memset(over_limit + 1, 'b', sizeof(over_limit) - 2);
    over_limit[sizeof(over_limit) - 1] = '\0';

    CHECK_EQ_INT((int)strlen(at_limit), 256);
    CHECK_EQ_INT((int)strlen(over_limit), 257);
    CHECK(toml_validate_file_path(at_limit));
    CHECK(!toml_validate_file_path(over_limit));
    CHECK(!toml_validate_file_path("/home/user/../other/key"));
}

TEST(platform_component_limit_fails_through_filesystem_errors) {
    char directory[] = "/tmp/gitswitch-ar11-toml-name.XXXXXX";
    char *path = NULL;
    long name_max;
    toml_document_t *doc = new_document();
    toml_document_t *loaded = new_document();

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK(loaded != NULL);
    if (!doc || !loaded) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    errno = 0;
    name_max = pathconf(directory, _PC_NAME_MAX);
    if (name_max < 1 || name_max > 1024) name_max = 255;
    path = malloc(strlen(directory) + (size_t)name_max + 3);
    CHECK(path != NULL);
    if (!path) goto cleanup;
    memcpy(path, directory, strlen(directory));
    path[strlen(directory)] = '/';
    memset(path + strlen(directory) + 1, 'x', (size_t)name_max + 1);
    path[strlen(directory) + 1 + (size_t)name_max + 1] = '\0';

    clear_error();
    CHECK_EQ_INT(toml_write_file(doc, path), -1);
    CHECK_EQ_INT(get_last_error()->system_errno, ENAMETOOLONG);
    CHECK_EQ_INT(count_writer_temps(directory), 0);
    clear_error();
    CHECK_EQ_INT(toml_parse_file(path, loaded), -1);
    CHECK_EQ_INT(get_last_error()->system_errno, ENAMETOOLONG);

cleanup:
    free(path);
    free(loaded);
    free(doc);
    ts_rm_rf(directory);
}

TEST(parser_rejects_scalar_table_namespace_collisions_in_both_orders) {
    static const char *const invalid[] = {
        "a = 1\n[settings]\ndefault_scope = \"local\"\n[a]\nx = 1\n",
        "a = 1\n[settings]\ndefault_scope = \"local\"\n[a.b]\nx = 1\n",
        "[settings]\ndefault_scope = \"local\"\n[a]\nb = 1\n[a.b]\nx = 1\n",
        "[settings]\ndefault_scope = \"local\"\n[a.b]\nx = 1\n[a]\nb = 1\n",
        "[settings]\ndefault_scope = \"local\"\n[a.b.c]\nx = 1\n[a]\nb = 1\n",
        "settings = \"scalar\"\n[settings]\ndefault_scope = \"local\"\n"
    };
    static const char valid[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[a.b]\n"
        "x = 1\n"
        "[a.c]\n"
        "y = 2\n";
    toml_document_t *doc = new_document();

    CHECK(doc != NULL);
    if (!doc) return;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK_EQ_INT(toml_parse_string(invalid[i], strlen(invalid[i]), doc), -1);
        CHECK(!doc->is_valid);
    }
    CHECK_EQ_INT(toml_parse_string(valid, sizeof(valid) - 1, doc), 0);
    free(doc);
}

TEST(setters_reject_namespace_collisions_without_mutation) {
    static const char table_first[] =
        "[settings]\ndefault_scope = \"local\"\n[a.b]\nx = 1\n";
    static const char root_first[] =
        "a = \"root\"\n[settings]\ndefault_scope = \"local\"\n";
    toml_document_t *doc = new_document();
    toml_document_t *before = new_document();

    CHECK(doc != NULL);
    CHECK(before != NULL);
    if (!doc || !before) goto cleanup;

    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    CHECK_EQ_INT(toml_set_string(doc, "a", "b", "scalar"), 0);
    memcpy(before, doc, sizeof(*before));
    CHECK_EQ_INT(toml_set_boolean(doc, "a.b", "enabled", true), -1);
    CHECK(memcmp(doc, before, sizeof(*doc)) == 0);
    CHECK_EQ_INT(toml_set_string(doc, "a", "c", "sibling"), 0);

    CHECK_EQ_INT(toml_parse_string(table_first, sizeof(table_first) - 1, doc), 0);
    memcpy(before, doc, sizeof(*before));
    CHECK_EQ_INT(toml_set_string(doc, "a", "b", "scalar"), -1);
    CHECK(memcmp(doc, before, sizeof(*doc)) == 0);

    CHECK_EQ_INT(toml_parse_string(root_first, sizeof(root_first) - 1, doc), 0);
    memcpy(before, doc, sizeof(*before));
    CHECK_EQ_INT(toml_set_string(doc, "a.b", "x", "value"), -1);
    CHECK(memcmp(doc, before, sizeof(*doc)) == 0);

    /* An omitted public-model record is not a scalar declaration. It may
     * share the fully-qualified name of a real table without a false clash. */
    toml_init_document(doc);
    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    CHECK_EQ_INT(toml_set_string(doc, "a", "b", "omitted"), 0);
    mutable_key(doc, "a", "b")->is_set = false;
    CHECK_EQ_INT(toml_set_string(doc, "a.b", "x", "table-value"), 0);

cleanup:
    free(before);
    free(doc);
}

static void append_manual_string(toml_document_t *doc, const char *section_name,
                                 const char *key_name, const char *value) {
    toml_section_t *section = &doc->sections[doc->section_count++];
    toml_keyvalue_t *kv;

    memset(section, 0, sizeof(*section));
    (void)snprintf(section->name, sizeof(section->name), "%s", section_name);
    section->is_set = true;
    section->key_count = 1;
    kv = &section->keys[0];
    (void)snprintf(kv->key, sizeof(kv->key), "%s", key_name);
    (void)snprintf(kv->value, sizeof(kv->value), "%s", value);
    kv->type = TOML_TYPE_STRING;
    kv->is_set = true;
}

static void expect_no_new_file(const toml_document_t *doc, const char *path,
                               const char *directory) {
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(toml_write_file(doc, path), -1);
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(count_writer_temps(directory), 0);
}

static void expect_every_publication_boundary_to_reject(
    const toml_document_t *doc, const char *directory, size_t case_number) {
    static const char sentinel[] = "UNCHANGED\n";
    char destination[256];
    char descriptor_path[256];
    char contents[64];
    struct stat before;
    struct stat after;
    struct stat descriptor_metadata;
    toml_document_t *schema_copy = malloc(sizeof(*schema_copy));
    int fd = -1;

    CHECK(schema_copy != NULL);
    CHECK((size_t)snprintf(destination, sizeof(destination),
                           "%s/existing-%zu.toml", directory, case_number) <
          sizeof(destination));
    CHECK((size_t)snprintf(descriptor_path, sizeof(descriptor_path),
                           "%s/fd-%zu.toml", directory, case_number) <
          sizeof(descriptor_path));
    if (!schema_copy) return;
    memcpy(schema_copy, doc, sizeof(*schema_copy));

    CHECK_EQ_INT(toml_validate_gitswitch_schema(schema_copy), -1);
    CHECK_EQ_INT(write_bytes(destination, sentinel), 0);
    CHECK_EQ_INT(lstat(destination, &before), 0);
    CHECK_EQ_INT(toml_write_file(doc, destination), -1);
    CHECK_EQ_INT(lstat(destination, &after), 0);
    CHECK(before.st_dev == after.st_dev);
    CHECK(before.st_ino == after.st_ino);
    CHECK_EQ_INT(read_bytes(destination, contents, sizeof(contents)), 0);
    CHECK_STR_EQ(contents, sentinel);
    CHECK_EQ_INT(count_writer_temps(directory), 0);

    fd = open(descriptor_path,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK_EQ_INT(toml_write_fd(doc, fd), -1);
        CHECK_EQ_INT(fstat(fd, &descriptor_metadata), 0);
        CHECK_EQ_INT((int)descriptor_metadata.st_size, 0);
        CHECK_EQ_INT(close(fd), 0);
        fd = -1;
    }

    free(schema_copy);
}

TEST(direct_models_with_namespace_collisions_fail_preflight) {
    char directory[] = "/tmp/gitswitch-ar11-toml-fqn.XXXXXX";
    char path[256];
    toml_document_t *doc = new_document();
    toml_document_t *schema_copy = new_document();

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK(schema_copy != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/rejected.toml", directory) <
          sizeof(path));
    if (!doc || !schema_copy) goto cleanup;

    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    CHECK_EQ_INT(toml_set_string(doc, "a", "b", "scalar"), 0);
    append_manual_string(doc, "a.b", "x", "table");
    memcpy(schema_copy, doc, sizeof(*schema_copy));
    expect_no_new_file(doc, path, directory);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(schema_copy), -1);

    toml_init_document(doc);
    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    CHECK_EQ_INT(toml_set_string(doc, "a.b", "x", "table"), 0);
    append_manual_string(doc, "a", "b", "scalar");
    expect_no_new_file(doc, path, directory);

cleanup:
    free(schema_copy);
    free(doc);
    ts_rm_rf(directory);
}

TEST(public_model_bounds_and_terminators_fail_before_publication) {
    char directory[] = "/tmp/gitswitch-ar11-toml-model.XXXXXX";
    char path[256];
    toml_document_t *valid = new_document();
    toml_document_t *candidate = new_document();

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(valid != NULL);
    CHECK(candidate != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/rejected.toml", directory) <
          sizeof(path));
    if (!valid || !candidate) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(valid), 0);

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = TOML_MAX_SECTIONS + 1U;
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = 2;
    memset(&candidate->sections[1], 0, sizeof(candidate->sections[1]));
    (void)snprintf(candidate->sections[1].name,
                   sizeof(candidate->sections[1].name), "future");
    candidate->sections[1].key_count = TOML_MAX_KEYS_PER_SECTION + 1U;
    expect_no_new_file(candidate, path, directory);

    /* A later section has already-valid outer bounds, but its key is not
     * terminated. The invariant checker must finish proving all reachable
     * names before any whole-document FQN scan. */
    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = 2;
    memset(&candidate->sections[1], 0, sizeof(candidate->sections[1]));
    (void)snprintf(candidate->sections[1].name,
                   sizeof(candidate->sections[1].name), "future");
    candidate->sections[1].key_count = 1;
    memset(candidate->sections[1].keys[0].key, 'k',
           sizeof(candidate->sections[1].keys[0].key));
    expect_no_new_file(candidate, path, directory);

    /* Same future-section witness with a valid key and a reachable, set value
     * whose backing array has no NUL. */
    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = 2;
    memset(&candidate->sections[1], 0, sizeof(candidate->sections[1]));
    (void)snprintf(candidate->sections[1].name,
                   sizeof(candidate->sections[1].name), "future");
    candidate->sections[1].key_count = 1;
    (void)snprintf(candidate->sections[1].keys[0].key,
                   sizeof(candidate->sections[1].keys[0].key), "value");
    memset(candidate->sections[1].keys[0].value, 'v',
           sizeof(candidate->sections[1].keys[0].value));
    candidate->sections[1].keys[0].type = TOML_TYPE_STRING;
    candidate->sections[1].keys[0].is_set = true;
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = 2;
    memset(&candidate->sections[1], 0, sizeof(candidate->sections[1]));
    memset(candidate->sections[1].name, 'n',
           sizeof(candidate->sections[1].name));
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    memset(candidate->sections[0].keys[0].key, 'k',
           sizeof(candidate->sections[0].keys[0].key));
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    memset(candidate->sections[0].keys[0].value, 'v',
           sizeof(candidate->sections[0].keys[0].value));
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = 2;
    memcpy(&candidate->sections[1], &candidate->sections[0],
           sizeof(candidate->sections[1]));
    expect_no_new_file(candidate, path, directory);

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->sections[0].key_count = 2;
    memcpy(&candidate->sections[0].keys[1],
           &candidate->sections[0].keys[0],
           sizeof(candidate->sections[0].keys[1]));
    expect_no_new_file(candidate, path, directory);

cleanup:
    free(candidate);
    free(valid);
    ts_rm_rf(directory);
}

TEST(noncanonical_and_invalid_typed_values_fail_closed) {
    static const struct {
        toml_value_type_t type;
        const char *value;
    } invalid[] = {
        { TOML_TYPE_BOOLEAN, "" },
        { TOML_TYPE_BOOLEAN, "TRUE" },
        { TOML_TYPE_BOOLEAN, "truth" },
        { TOML_TYPE_BOOLEAN, "false " },
        { TOML_TYPE_BOOLEAN, "true\n[evil]" },
        { TOML_TYPE_INTEGER, "+1" },
        { TOML_TYPE_INTEGER, "-0" },
        { TOML_TYPE_INTEGER, "01" },
        { TOML_TYPE_INTEGER, " 1" },
        { TOML_TYPE_INTEGER, "1x" },
        { TOML_TYPE_INTEGER, "1\nother = 2" },
        { TOML_TYPE_INTEGER, "2147483648" },
        { TOML_TYPE_STRING, "lo\x01\x63\x61l" },
        { TOML_TYPE_INVALID, "local" },
        { (toml_value_type_t)99, "local" }
    };
    char directory[] = "/tmp/gitswitch-ar11-toml-types.XXXXXX";
    char path[256];
    toml_document_t *valid = new_document();
    toml_document_t *candidate = new_document();
    toml_keyvalue_t *kv;

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(valid != NULL);
    CHECK(candidate != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/rejected.toml", directory) <
          sizeof(path));
    if (!valid || !candidate) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(valid), 0);

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, "settings", "default_scope");
        CHECK(kv != NULL);
        if (!kv) continue;
        kv->type = invalid[i].type;
        (void)snprintf(kv->value, sizeof(kv->value), "%s", invalid[i].value);
        expect_every_publication_boundary_to_reject(candidate, directory, i);
    }

    /* Unterminated typed values are distinct from bad textual spellings: the
     * safe ordering must reject the backing store before canonical parsers or
     * error formatting can inspect it as a C string. */
    memcpy(candidate, valid, sizeof(*candidate));
    kv = mutable_key(candidate, "settings", "default_scope");
    CHECK(kv != NULL);
    if (kv) {
        kv->type = TOML_TYPE_BOOLEAN;
        memset(kv->value, 't', sizeof(kv->value));
        expect_every_publication_boundary_to_reject(
            candidate, directory, sizeof(invalid) / sizeof(invalid[0]));
    }

    memcpy(candidate, valid, sizeof(*candidate));
    kv = mutable_key(candidate, "settings", "default_scope");
    CHECK(kv != NULL);
    if (kv) {
        kv->type = TOML_TYPE_INTEGER;
        memset(kv->value, '1', sizeof(kv->value));
        expect_every_publication_boundary_to_reject(
            candidate, directory,
            sizeof(invalid) / sizeof(invalid[0]) + 1U);
    }

    /* Byte-mutated public objects must be rejected without evaluating an
     * invalid _Bool representation in either validation or serialization. */
    memcpy(candidate, valid, sizeof(*candidate));
    kv = mutable_key(candidate, "settings", "default_scope");
    CHECK(kv != NULL);
    if (kv) {
        memset(&kv->is_set, 0xff, sizeof(kv->is_set));
        expect_every_publication_boundary_to_reject(
            candidate, directory,
            sizeof(invalid) / sizeof(invalid[0]) + 2U);
    }

cleanup:
    free(candidate);
    free(valid);
    ts_rm_rf(directory);
}

TEST(getters_reject_invalid_public_bool_representations_without_ub) {
    static const char source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "text = \"value\"\n"
        "number = 7\n"
        "enabled = true\n";
    static const char *const keys[] = { "text", "number", "enabled" };
    toml_document_t *valid = new_document();
    toml_document_t *candidate = new_document();
    toml_section_t *section;
    toml_keyvalue_t *kv;

    CHECK(valid != NULL);
    CHECK(candidate != NULL);
    if (!valid || !candidate) goto cleanup;
    CHECK_EQ_INT(toml_parse_string(source, sizeof(source) - 1, valid), 0);

    for (size_t route = 0; route < 3; route++) {
        memcpy(candidate, valid, sizeof(*candidate));
        memset(&candidate->is_valid, 0xff, sizeof(candidate->is_valid));
        clear_error();
        CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);

        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "custom");
        CHECK(section != NULL);
        if (section) {
            memset(&section->is_set, 0xff, sizeof(section->is_set));
            clear_error();
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
            CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);
        }

        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, "custom", keys[route]);
        CHECK(kv != NULL);
        if (kv) {
            memset(&kv->is_set, 0xff, sizeof(kv->is_set));
            clear_error();
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
            CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);
        }
    }

    /* Schema revokes document validity before its first possible read, so a
     * corrupt prior validity byte is safely overwritten and validation may
     * republish the canonical true representation. */
    memcpy(candidate, valid, sizeof(*candidate));
    memset(&candidate->is_valid, 0xff, sizeof(candidate->is_valid));
    CHECK_EQ_INT(toml_validate_gitswitch_schema(candidate), 0);
    CHECK(candidate->is_valid);

cleanup:
    free(candidate);
    free(valid);
}

TEST(public_readers_preflight_counts_names_and_values_before_lookup) {
    static const char source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "text = \"value\"\n"
        "number = 7\n"
        "enabled = true\n"
        "[tail]\n"
        "marker = \"unrelated\"\n";
    static const char *const keys[] = { "text", "number", "enabled" };
    char sections[TOML_MAX_SECTIONS + 1U][TOML_MAX_SECTION_LEN];
    size_t section_count = 0;
    toml_document_t *valid = new_document();
    toml_document_t *candidate = new_document();
    toml_section_t *section;
    toml_keyvalue_t *kv;

    CHECK(valid != NULL);
    CHECK(candidate != NULL);
    if (!valid || !candidate) goto cleanup;
    CHECK_EQ_INT(toml_parse_string(source, sizeof(source) - 1, valid), 0);

    for (size_t route = 0; route < 3; route++) {
        /* Existing-target lookups used to return success before observing the
         * corrupt outer count; a missing target walked beyond sections[64]. */
        memcpy(candidate, valid, sizeof(*candidate));
        candidate->section_count = SIZE_MAX;
        CHECK_EQ_INT(call_typed_getter(candidate, route), -1);

        /* The requested key is physically inside the target section, so each
         * old lookup could likewise succeed despite an impossible key_count. */
        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "custom");
        CHECK(section != NULL);
        if (section) section->key_count = SIZE_MAX;
        CHECK_EQ_INT(call_typed_getter(candidate, route), -1);

        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "custom");
        CHECK(section != NULL);
        if (section) {
            memset(section->name, 's', sizeof(section->name));
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, "custom", keys[route]);
        CHECK(kv != NULL);
        if (kv) {
            memset(kv->key, 'k', sizeof(kv->key));
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, "custom", keys[route]);
        CHECK(kv != NULL);
        if (kv) {
            memset(kv->value, 'v', sizeof(kv->value));
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "custom");
        kv = mutable_key(candidate, "custom", keys[route]);
        CHECK(section != NULL);
        CHECK(kv != NULL);
        if (section && kv) {
            memcpy(&section->keys[section->key_count], kv, sizeof(*kv));
            section->key_count++;
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        /* Later section names and visibility flags must still be safe because
         * the resolver scans them to rule out a duplicate target route. */
        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "tail");
        CHECK(section != NULL);
        if (section) {
            memset(section->name, 't', sizeof(section->name));
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "tail");
        CHECK(section != NULL);
        if (section) {
            memset(&section->is_set, 0xff, sizeof(section->is_set));
            CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
        }

        /* Unrelated key arrays and payloads are never dereferenced. Corrupting
         * them cannot cause UB or turn a bounded target read into a global
         * model scan. */
        memcpy(candidate, valid, sizeof(*candidate));
        section = mutable_section(candidate, "tail");
        CHECK(section != NULL);
        if (section) section->key_count = SIZE_MAX;
        CHECK_EQ_INT(call_typed_getter(candidate, route), 0);

        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, "tail", "marker");
        CHECK(kv != NULL);
        if (kv) memset(kv->value, 'u', sizeof(kv->value));
        CHECK_EQ_INT(call_typed_getter(candidate, route), 0);
    }

    memcpy(candidate, valid, sizeof(*candidate));
    CHECK(candidate->section_count < TOML_MAX_SECTIONS);
    if (candidate->section_count < TOML_MAX_SECTIONS) {
        section = mutable_section(candidate, "custom");

        CHECK(section != NULL);
        if (section) {
            memcpy(&candidate->sections[candidate->section_count], section,
                   sizeof(candidate->sections[0]));
            candidate->section_count++;
            for (size_t route = 0; route < 3; route++) {
                CHECK_EQ_INT(call_typed_getter(candidate, route), -1);
            }
        }
    }

    memcpy(candidate, valid, sizeof(*candidate));
    candidate->section_count = SIZE_MAX;
    section_count = 99;
    CHECK_EQ_INT(toml_get_sections(candidate, sections,
                                   TOML_MAX_SECTIONS + 1U,
                                   &section_count), -1);
    CHECK_EQ_INT((int)section_count, 0);

    memcpy(candidate, valid, sizeof(*candidate));
    section = mutable_section(candidate, "custom");
    CHECK(section != NULL);
    if (section) memset(section->name, 's', sizeof(section->name));
    section_count = 99;
    CHECK_EQ_INT(toml_get_sections(candidate, sections,
                                   TOML_MAX_SECTIONS + 1U,
                                   &section_count), -1);
    CHECK_EQ_INT((int)section_count, 0);

    memcpy(candidate, valid, sizeof(*candidate));
    section = mutable_section(candidate, "custom");
    CHECK(section != NULL);
    if (section) section->key_count = SIZE_MAX;
    section_count = 99;
    CHECK_EQ_INT(toml_get_sections(candidate, sections,
                                   TOML_MAX_SECTIONS + 1U,
                                   &section_count), -1);
    CHECK_EQ_INT((int)section_count, 0);

cleanup:
    free(candidate);
    free(valid);
}

TEST(typed_getters_never_invoke_the_full_model_preflight) {
    static const char source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "text = \"value\"\n"
        "number = 7\n"
        "enabled = true\n";
    char sections[TOML_MAX_SECTIONS][TOML_MAX_SECTION_LEN];
    size_t section_count = 0;
    toml_document_t *doc = new_document();
    toml_metadata_test_hook_fn previous = NULL;
    bool hook_installed = false;

    CHECK(doc != NULL);
    if (!doc) return;
    CHECK_EQ_INT(toml_parse_string(source, sizeof(source) - 1, doc), 0);

    g_model_preflight_calls = 0;
    previous = toml_set_metadata_test_hook_fn(count_model_preflight);
    hook_installed = true;
    for (size_t i = 0; i < 1024; i++) {
        CHECK_EQ_INT(call_typed_getter(doc, i % 3U), 0);
    }
    CHECK_EQ_INT((int)g_model_preflight_calls, 0);

    /* The seam is live, and the infrequent section-enumeration API retains
     * the complete public-model invariant scan. */
    CHECK_EQ_INT(toml_get_sections(doc, sections, TOML_MAX_SECTIONS,
                                   &section_count), 0);
    CHECK_EQ_INT((int)g_model_preflight_calls, 1);

    if (hook_installed) toml_set_metadata_test_hook_fn(previous);
    free(doc);
}

TEST(write_fd_preflight_leaves_fresh_descriptor_empty) {
    char directory[] = "/tmp/gitswitch-ar11-toml-fd.XXXXXX";
    char path[256];
    struct stat metadata;
    toml_document_t *doc = new_document();
    int fd = -1;

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/output.toml", directory) <
          sizeof(path));
    if (!doc) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    mutable_key(doc, "settings", "default_scope")->type = TOML_TYPE_INVALID;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) goto cleanup;
    CHECK_EQ_INT(toml_write_fd(doc, fd), -1);
    CHECK_EQ_INT(fstat(fd, &metadata), 0);
    CHECK_EQ_INT((int)metadata.st_size, 0);

cleanup:
    if (fd >= 0) (void)close(fd);
    free(doc);
    ts_rm_rf(directory);
}

TEST(required_fields_must_be_set_for_validation_and_writers) {
    static const struct {
        const char *section;
        const char *key;
    } required[] = {
        { "settings", "default_scope" },
        { "accounts.1", "name" },
        { "accounts.1", "email" }
    };
    static const char sentinel[] = "SENTINEL\n";
    char directory[] = "/tmp/gitswitch-ar11-toml-required.XXXXXX";
    char path[256];
    char contents[512];
    toml_document_t *valid = new_document();
    toml_document_t *candidate = new_document();
    toml_document_t *schema_copy = new_document();
    toml_keyvalue_t *kv;

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(valid != NULL);
    CHECK(candidate != NULL);
    CHECK(schema_copy != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/output.toml", directory) <
          sizeof(path));
    if (!valid || !candidate || !schema_copy) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(valid), 0);
    CHECK_EQ_INT(toml_set_string(valid, "accounts.1", "name", "alice"), 0);
    CHECK_EQ_INT(toml_set_string(valid, "accounts.1", "email",
                                 "alice@example.com"), 0);
    CHECK_EQ_INT(toml_set_string(valid, "accounts.1", "description",
                                 "optional"), 0);

    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        memcpy(candidate, valid, sizeof(*candidate));
        kv = mutable_key(candidate, required[i].section, required[i].key);
        CHECK(kv != NULL);
        if (!kv) continue;
        kv->is_set = false;
        memcpy(schema_copy, candidate, sizeof(*schema_copy));
        CHECK_EQ_INT(toml_validate_gitswitch_schema(schema_copy), -1);

        CHECK_EQ_INT(write_bytes(path, sentinel), 0);
        CHECK_EQ_INT(toml_write_file(candidate, path), -1);
        CHECK_EQ_INT(read_bytes(path, contents, sizeof(contents)), 0);
        CHECK_STR_EQ(contents, sentinel);
        CHECK_EQ_INT(count_writer_temps(directory), 0);
    }

    memcpy(candidate, valid, sizeof(*candidate));
    kv = mutable_key(candidate, "accounts.1", "description");
    CHECK(kv != NULL);
    if (kv) kv->is_set = false;
    CHECK_EQ_INT(toml_validate_gitswitch_schema(candidate), 0);
    CHECK_EQ_INT(toml_write_file(candidate, path), 0);
    CHECK_EQ_INT(read_bytes(path, contents, sizeof(contents)), 0);
    CHECK(strstr(contents, "description") == NULL);
    CHECK_EQ_INT(toml_parse_file(path, schema_copy), 0);

cleanup:
    free(schema_copy);
    free(candidate);
    free(valid);
    ts_rm_rf(directory);
}

TEST(section_capacity_failures_refresh_error_and_preserve_every_byte) {
    toml_document_t *doc = new_document();
    toml_document_t *before = new_document();
    char section[32];

    CHECK(doc != NULL);
    CHECK(before != NULL);
    if (!doc || !before) goto cleanup;
    CHECK_EQ_INT(add_minimum_settings(doc), 0);
    for (size_t i = 0; i < TOML_MAX_SECTIONS - 1U; i++) {
        CHECK((size_t)snprintf(section, sizeof(section), "custom%zu", i) <
              sizeof(section));
        CHECK_EQ_INT(toml_set_boolean(doc, section, "enabled", true), 0);
    }
    CHECK_EQ_INT((int)doc->section_count, TOML_MAX_SECTIONS);
    memcpy(before, doc, sizeof(*before));

    (void)set_error(ERR_FILE_IO, "stale error");
    CHECK_EQ_INT(toml_set_string(doc, "overflow", "value", "x"), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);
    CHECK(memcmp(doc, before, sizeof(*doc)) == 0);

    clear_error();
    CHECK_EQ_INT(toml_set_boolean(doc, "overflow", "enabled", true), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);
    CHECK(memcmp(doc, before, sizeof(*doc)) == 0);

cleanup:
    free(before);
    free(doc);
}

TEST(raw_string_controls_report_the_exact_offending_byte) {
    static const struct {
        const char *source;
        const char *location;
    } invalid[] = {
        { "[settings]\ndefault_scope = \"local\"\n[custom]\nvalue = \"a\nb\"\n",
          "line 4, column 11" },
        { "[settings]\ndefault_scope = \"local\"\n[custom]\nvalue = \"a\rb\"\n",
          "line 4, column 11" },
        { "[settings]\ndefault_scope = \"local\"\n[custom]\nvalue = \"a\tb\"\n",
          "line 4, column 11" },
        { "[settings]\ndefault_scope = \"local\"\n[custom]\nvalue = \"a\\\nb\"\n",
          "line 4, column 12" }
    };
    static const char escaped[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "newline = \"a\\nb\"\n"
        "carriage = \"a\\rb\"\n"
        "tab = \"a\\tb\"\n";
    toml_document_t *doc = new_document();

    CHECK(doc != NULL);
    if (!doc) return;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        clear_error();
        CHECK_EQ_INT(toml_parse_string(invalid[i].source,
                                       strlen(invalid[i].source), doc), -1);
        CHECK(strstr(get_last_error()->message, invalid[i].location) != NULL);
        CHECK(strstr(get_last_error()->message,
                     "Control character in string value") != NULL);
    }
    CHECK_EQ_INT(toml_parse_string(escaped, sizeof(escaped) - 1, doc), 0);
    free(doc);
}

TEST(implicit_root_serializes_without_an_empty_table_header) {
    static const char source[] =
        "title = \"root\"\n"
        "enabled = true\n"
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "value = 7\n";
    char directory[] = "/tmp/gitswitch-ar11-toml-root.XXXXXX";
    char path[256];
    char contents[1024];
    char title[64];
    bool enabled = false;
    int value = 0;
    toml_document_t *doc = new_document();
    toml_document_t *loaded = new_document();

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK(loaded != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/root.toml", directory) <
          sizeof(path));
    if (!doc || !loaded) goto cleanup;

    CHECK_EQ_INT(toml_parse_string(source, sizeof(source) - 1, doc), 0);
    CHECK_EQ_INT(toml_write_file(doc, path), 0);
    CHECK_EQ_INT(read_bytes(path, contents, sizeof(contents)), 0);
    CHECK(strstr(contents, "[]") == NULL);
    CHECK(strncmp(contents, "title = \"root\"\n", 15) == 0);
    CHECK_EQ_INT(toml_parse_file(path, loaded), 0);
    CHECK_EQ_INT(toml_get_string(loaded, "", "title", title,
                                 sizeof(title)), 0);
    CHECK_STR_EQ(title, "root");
    CHECK_EQ_INT(toml_get_boolean(loaded, "", "enabled", &enabled), 0);
    CHECK(enabled);
    CHECK_EQ_INT(toml_get_integer(loaded, "custom", "value", &value), 0);
    CHECK_EQ_INT(value, 7);

cleanup:
    free(loaded);
    free(doc);
    ts_rm_rf(directory);
}

TEST(generic_writer_accepts_a_root_only_public_model) {
    char directory[] = "/tmp/gitswitch-ar11-toml-root-only.XXXXXX";
    char path[256];
    char contents[256];
    toml_document_t *doc = new_document();

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/root.toml", directory) <
          sizeof(path));
    if (!doc) goto cleanup;

    append_manual_string(doc, "", "title", "standalone");
    CHECK_EQ_INT(toml_write_file(doc, path), 0);
    CHECK_EQ_INT(read_bytes(path, contents, sizeof(contents)), 0);
    CHECK_STR_EQ(contents, "title = \"standalone\"\n");

cleanup:
    free(doc);
    ts_rm_rf(directory);
}

TEST(parser_produced_integer_and_boolean_values_round_trip_canonically) {
    static const char source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[custom]\n"
        "number = -7\n"
        "enabled = false\n";
    char directory[] = "/tmp/gitswitch-ar11-toml-canonical.XXXXXX";
    char path[256];
    toml_document_t *doc = new_document();
    toml_document_t *loaded = new_document();
    int number = 0;
    bool enabled = true;

    CHECK(ts_mkdtemp(directory) != NULL);
    CHECK(doc != NULL);
    CHECK(loaded != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/output.toml", directory) <
          sizeof(path));
    if (!doc || !loaded) goto cleanup;

    CHECK_EQ_INT(toml_parse_string(source, sizeof(source) - 1, doc), 0);
    CHECK_EQ_INT(toml_write_file(doc, path), 0);
    CHECK_EQ_INT(toml_parse_file(path, loaded), 0);
    CHECK_EQ_INT(toml_get_integer(loaded, "custom", "number", &number), 0);
    CHECK_EQ_INT(number, -7);
    CHECK_EQ_INT(toml_get_boolean(loaded, "custom", "enabled", &enabled), 0);
    CHECK(!enabled);

    (void)snprintf(mutable_key(loaded, "custom", "number")->value,
                   TOML_MAX_VALUE_LEN, "+7");
    CHECK_EQ_INT(toml_get_integer(loaded, "custom", "number", &number), -1);
    (void)snprintf(mutable_key(loaded, "custom", "enabled")->value,
                   TOML_MAX_VALUE_LEN, "not-false");
    CHECK_EQ_INT(toml_get_boolean(loaded, "custom", "enabled", &enabled), -1);

cleanup:
    free(loaded);
    free(doc);
    ts_rm_rf(directory);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(config_file_paths_follow_filesystem_limits_not_ssh_data_policy);
    RUN_TEST(config_file_path_shape_rejections_are_symmetric);
    RUN_TEST(stored_ssh_path_validator_keeps_its_256_byte_and_traversal_contract);
    RUN_TEST(platform_component_limit_fails_through_filesystem_errors);
    RUN_TEST(parser_rejects_scalar_table_namespace_collisions_in_both_orders);
    RUN_TEST(setters_reject_namespace_collisions_without_mutation);
    RUN_TEST(direct_models_with_namespace_collisions_fail_preflight);
    RUN_TEST(public_model_bounds_and_terminators_fail_before_publication);
    RUN_TEST(noncanonical_and_invalid_typed_values_fail_closed);
    RUN_TEST(getters_reject_invalid_public_bool_representations_without_ub);
    RUN_TEST(public_readers_preflight_counts_names_and_values_before_lookup);
    RUN_TEST(typed_getters_never_invoke_the_full_model_preflight);
    RUN_TEST(write_fd_preflight_leaves_fresh_descriptor_empty);
    RUN_TEST(required_fields_must_be_set_for_validation_and_writers);
    RUN_TEST(section_capacity_failures_refresh_error_and_preserve_every_byte);
    RUN_TEST(raw_string_controls_report_the_exact_offending_byte);
    RUN_TEST(implicit_root_serializes_without_an_empty_table_header);
    RUN_TEST(generic_writer_accepts_a_root_only_public_model);
    RUN_TEST(parser_produced_integer_and_boolean_values_round_trip_canonically);
TEST_MAIN_END()
