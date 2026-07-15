/* Minimal, security-focused TOML parser implementation
 * Built specifically for gitswitch-c with comprehensive input validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "toml_parser.h"
#include "error.h"
#include "signals.h"
#include "utils.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/* Every account gets one section and config_save always writes [settings]
 * first; if this ever regresses the writer reports success for accounts that
 * silently never reach disk (AR-03 M7). */
_Static_assert(TOML_MAX_SECTIONS >= MAX_ACCOUNTS + 1,
               "TOML_MAX_SECTIONS must fit every account plus [settings]");

/* Internal parsing helper functions */
static int parse_section_header(toml_parser_state_t *state, char *section_name);
static int parse_key_value_pair(toml_parser_state_t *state, toml_keyvalue_t *kv);
static int parse_string_value(toml_parser_state_t *state, char *value, size_t value_size);
static int parse_integer_value(toml_parser_state_t *state, int *value);
static int parse_boolean_value(toml_parser_state_t *state, bool *value);
static void skip_whitespace(toml_parser_state_t *state);
static int consume_line_ending(toml_parser_state_t *state);
static int require_line_end(toml_parser_state_t *state);
static int skip_comment(toml_parser_state_t *state);
static bool is_at_end(const toml_parser_state_t *state);
static char current_char(const toml_parser_state_t *state);
static char advance_char(toml_parser_state_t *state);
static bool match_char(toml_parser_state_t *state, char expected);
static void set_parser_error(toml_parser_state_t *state, const char *message);
static toml_section_t *find_section(toml_document_t *doc, const char *section_name);
static toml_section_t *find_or_create_section(toml_document_t *doc, const char *section_name);
static toml_keyvalue_t *find_key(toml_section_t *section, const char *key_name);
static bool section_name_is_valid(const char *section_name);
static bool decoded_string_value_is_valid(const char *value, size_t length);
static int toml_validate_config_file_path(const char *file_path,
                                          const char *path_role);
static bool toml_table_namespace_is_available(const toml_document_t *doc,
                                              const char *table_name);
static bool toml_scalar_namespace_is_available(const toml_document_t *doc,
                                               const char *section_name,
                                               const char *key_name);
static int toml_validate_model_invariants(const toml_document_t *doc,
                                          bool require_schema_fields);
static int toml_resolve_getter_value(const toml_document_t *doc,
                                     const char *section_name,
                                     const char *key_name,
                                     toml_value_type_t expected_type,
                                     const toml_keyvalue_t **resolved);
static bool toml_bool_object_value(const bool *object, bool *value);
static bool toml_canonical_integer(const char *value, int *parsed);
static bool toml_canonical_boolean(const char *value, bool *parsed);
static bool toml_same_file(const struct stat *left, const struct stat *right);
static bool toml_temp_identity_is_private(const struct stat *identity);
static toml_document_init_hook_fn g_document_init_hook;
static toml_writer_test_hook_fn g_writer_test_hook;
static toml_metadata_test_hook_fn g_metadata_test_hook;

static bool ascii_key_initial_is_valid(unsigned char c) {
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool ascii_key_continuation_is_valid(unsigned char c) {
    return ascii_key_initial_is_valid(c) || (c >= '0' && c <= '9');
}

static bool ascii_section_segment_byte_is_valid(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

/* This intentionally implements the application's narrower key contract, not
 * TOML's full bare-key grammar. Keep parser and setter-created documents on
 * the same ASCII-only, round-trippable surface. */
static bool key_name_is_valid(const char *key_name) {
    if (!key_name || !ascii_key_initial_is_valid((unsigned char)key_name[0])) {
        return false;
    }

    for (size_t i = 1; i < TOML_MAX_KEY_LEN; i++) {
        unsigned char c = (unsigned char)key_name[i];
        if (c == '\0') return true;
        if (!ascii_key_continuation_is_valid(c)) return false;
    }
    return false;
}

/* Config file paths are operating-system objects, not stored SSH-key data.
 * The one application limit is the public document's source-path capacity;
 * lstat/open and openat/rename remain authoritative for smaller component or
 * platform limits. Keep this admission pass shared by reader and writer. */
static int toml_validate_config_file_path(const char *file_path,
                                          const char *path_role) {
    size_t length;

    if (!file_path || file_path[0] == '\0') {
        set_error(ERR_INVALID_PATH, "TOML %s path is empty", path_role);
        return -1;
    }
    length = strnlen(file_path, MAX_PATH_LEN);
    if (length == MAX_PATH_LEN) {
        set_error(ERR_INVALID_PATH,
                  "TOML %s path exceeds the application limit of %d bytes",
                  path_role, MAX_PATH_LEN - 1);
        return -1;
    }
    if (file_path[length - 1] == '/') {
        set_error(ERR_INVALID_PATH,
                  "TOML %s path must name a file, not a directory", path_role);
        return -1;
    }
    return 0;
}

toml_document_init_hook_fn toml_set_document_init_hook_fn(
    toml_document_init_hook_fn fn) {
    toml_document_init_hook_fn previous = g_document_init_hook;
    g_document_init_hook = fn;
    return previous;
}

toml_writer_test_hook_fn toml_set_writer_test_hook_fn(
    toml_writer_test_hook_fn fn) {
    toml_writer_test_hook_fn previous = g_writer_test_hook;
    g_writer_test_hook = fn;
    return previous;
}

toml_metadata_test_hook_fn toml_set_metadata_test_hook_fn(
    toml_metadata_test_hook_fn fn) {
    toml_metadata_test_hook_fn previous = g_metadata_test_hook;
    g_metadata_test_hook = fn;
    return previous;
}

/* Initialize TOML document structure */
void toml_init_document(toml_document_t *doc) {
    if (!doc) return;

    memset(doc, 0, sizeof(toml_document_t));
    if (g_document_init_hook) {
        g_document_init_hook(doc);
    }
}

/* Parse TOML from file with comprehensive security validation */
int toml_parse_file(const char *file_path, toml_document_t *doc) {
    FILE *file = NULL;
    struct stat path_stat, file_stat;
    char *buffer = NULL;
    size_t file_size = 0;
    size_t bytes_read;
    int fd = -1;
    int result = -1;
    bool delegated_to_string_parser = false;

    if (!doc) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to toml_parse_file");
        return -1;
    }
    if (!file_path) {
        toml_init_document(doc);
        set_error(ERR_INVALID_ARGS, "NULL arguments to toml_parse_file");
        return -1;
    }

    if (toml_validate_config_file_path(file_path, "source") != 0) {
        goto cleanup;
    }
    
    /* Refuse a named symlink before open for a precise diagnostic. O_NOFOLLOW
     * below is still authoritative against replacement in this gap. */
    if (lstat(file_path, &path_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot access config file: %s", file_path);
        goto cleanup;
    }
    if (S_ISLNK(path_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file is a symlink; refusing to follow it: %s",
                  file_path);
        goto cleanup;
    }
    if (!S_ISREG(path_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file is not a regular file: %s", file_path);
        goto cleanup;
    }

    /* Open once and validate the exact descriptor that will be read.
     * O_NONBLOCK protects the replacement race after the path-level type gate;
     * the identity comparison also preserves no-follow behavior on platforms
     * where O_NOFOLLOW is unavailable. */
    fd = open(file_path,
              O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND,
                         "Failed to open config file: %s", file_path);
        goto cleanup;
    }
    if (fstat(fd, &file_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND,
                         "Failed to stat opened config file: %s", file_path);
        goto cleanup;
    }
    if (!S_ISREG(file_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file is not a regular file: %s", file_path);
        goto cleanup;
    }
    if (path_stat.st_dev != file_stat.st_dev ||
        path_stat.st_ino != file_stat.st_ino) {
        errno = ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Configuration file changed before open: %s",
                         file_path);
        goto cleanup;
    }

    /* Security: Check file size limit */
    if (file_stat.st_size < 0 ||
        file_stat.st_size > (off_t)TOML_MAX_FILE_SIZE) {
        /* Cast to long: off_t is long long on macOS/clang (Wformat error under
         * -Werror) but long on Linux; the value is bounded small here (just
         * over the max), so no truncation. Mirrors config.c's size check. */
        set_error(ERR_CONFIG_INVALID, "Configuration file too large: %ld bytes (max: %d)",
                  (long)file_stat.st_size, TOML_MAX_FILE_SIZE);
        goto cleanup;
    }
    
    /* Security: Check file permissions (should not be world-readable) */
    if (file_stat.st_mode & (S_IRGRP | S_IROTH)) {
        set_error(ERR_PERMISSION_DENIED, "Configuration file has unsafe permissions: %o", 
                  file_stat.st_mode & 0777);
        goto cleanup;
    }
    
    file_size = (size_t)file_stat.st_size;
    
    /* fdopen takes ownership of the already-validated descriptor. */
    file = fdopen(fd, "r");
    if (!file) {
        set_system_error(ERR_CONFIG_NOT_FOUND,
                         "Failed to stream config file: %s", file_path);
        goto cleanup;
    }
    fd = -1;
    
    /* Allocate buffer for file content */
    buffer = safe_malloc(file_size + 1);
    if (!buffer) {
        goto cleanup;
    }
    
    /* Read file content */
    bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != file_size) {
        set_system_error(ERR_FILE_IO, "Failed to read complete config file: %s", file_path);
        goto cleanup;
    }
    
    buffer[file_size] = '\0';
    fclose(file);
    file = NULL;
    
    /* The public string entry point owns raw-byte validation and the one full
     * document initialization. File parsing delegates to it so the two APIs
     * cannot drift into different character/injection policies (AR-07 L29). */
    delegated_to_string_parser = true;
    result = toml_parse_string(buffer, file_size, doc);
    if (result == 0 &&
        safe_strncpy(doc->file_path, file_path, sizeof(doc->file_path)) != 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration file path exceeded its validated capacity");
        doc->is_valid = false;
        result = -1;
    }
    
cleanup:
    if (file) fclose(file);
    if (fd >= 0) close(fd);
    if (buffer) {
        secure_zero_memory(buffer, file_size + 1);
        free(buffer);
    }

    /* If failure happened before a buffer reached toml_parse_string, that
     * parser could not establish the normal invalid/empty document state.
     * Initialize it here exactly once so every public early-error path is
     * safe to inspect and clean up. */
    if (!delegated_to_string_parser) {
        toml_init_document(doc);
    }
    
    return result;
}

/* Parse TOML from string buffer */
int toml_parse_string(const char *toml_string, size_t length, toml_document_t *doc) {
    toml_parser_state_t state;
    char section_name[TOML_MAX_SECTION_LEN] = ""; /* Default to root section */
    toml_section_t *current_section = NULL;
    
    if (!doc) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_parse_string");
        return -1;
    }

    /* This is the sole full initialization owner for buffer parses. It must
     * precede every content gate so invalid input leaves a safe, invalid
     * document rather than stale caller data (AR-07 L27). */
    toml_init_document(doc);

    if (!toml_string) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_parse_string");
        return -1;
    }

    /* A 0-byte config is a real-world state (crashed editor, interrupted
     * copy, truncated restore), not a programming error: reporting it as
     * "Invalid arguments" made every command look like a gitswitch bug with
     * no way out short of reading the source (AR-03 L13). Still fail closed
     * — an empty file has no [settings] section — but name the actual
     * problem and the remedy. */
    if (length == 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration file is empty (0 bytes); delete it and gitswitch "
                  "will recreate the default, or restore it from a backup");
        return -1;
    }

    if (length > TOML_MAX_FILE_SIZE) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration buffer too large: %zu bytes (max: %d)",
                  length, TOML_MAX_FILE_SIZE);
        return -1;
    }

    /* Keep the complete raw-buffer trust boundary here, not only in the file
     * wrapper. Callers that already hold validated descriptors use this API
     * directly, so bypassing either gate would recreate the file/string
     * policy split (AR-07 L29). */
    if (!toml_validate_safe_characters(toml_string, length)) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration buffer contains unsafe characters");
        return -1;
    }
    if (!toml_check_injection_patterns(toml_string, length)) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration buffer contains potentially malicious patterns");
        return -1;
    }
    
    /* Initialize parser state */
    memset(&state, 0, sizeof(state));
    state.input = toml_string;
    state.input_length = length;
    state.position = 0;
    state.line_number = 1;
    state.column_number = 1;
    state.has_error = false;
    
    /* Parse line by line */
    while (!is_at_end(&state) && !state.has_error) {
        skip_whitespace(&state);
        
        if (is_at_end(&state)) {
            break;
        }
        
        char c = current_char(&state);
        
        /* Skip comments */
        if (c == '#') {
            if (skip_comment(&state) != 0) {
                break;
            }
            continue;
        }
        
        /* Parse section header */
        if (c == '[') {
            if (parse_section_header(&state, section_name) == 0) {
                /* Reject a repeated table header per the TOML spec (AR-05
                 * L10), matching the duplicate-KEY rejection below. Silently
                 * merging meant two [accounts.1] blocks collapsed into one
                 * account (an apparent second account dropped) and an
                 * appended duplicate block could inject keys (ssh_key,
                 * ssh_host, ...) into an existing section with zero
                 * diagnostics. The writer emits each section once, so this
                 * only fires on hand edits — where a line-anchored error is
                 * the diagnostic the user needs. Only the parse path checks:
                 * find_or_create_section stays fetch-or-create for the
                 * writer/setter paths. */
                if (find_section(doc, section_name)) {
                    char dup_msg[sizeof(state.error_message)];
                    snprintf(dup_msg, sizeof(dup_msg),
                             "Duplicate section [%s] (TOML forbids defining "
                             "a table twice)", section_name);
                    set_parser_error(&state, dup_msg);
                    break;
                }
                if (!toml_table_namespace_is_available(doc, section_name)) {
                    set_parser_error(
                        &state,
                        "Table name collides with an existing scalar value");
                    break;
                }
                current_section = find_or_create_section(doc, section_name);
                if (!current_section) {
                    set_parser_error(&state, "Failed to create section");
                    break;
                }
                /* Nothing but whitespace/comment may follow `]` (AR-06 F70). */
                if (require_line_end(&state) != 0) {
                    break;
                }
            }
            continue;
        }
        
        /* Parse key-value pair */
        if (ascii_key_initial_is_valid((unsigned char)c)) {
            if (!current_section) {
                /* Create default section if none exists */
                current_section = find_or_create_section(doc, "");
                if (!current_section) {
                    set_parser_error(&state, "Failed to create default section");
                    break;
                }
            }
            
            if (current_section->key_count >= TOML_MAX_KEYS_PER_SECTION) {
                set_parser_error(&state, "Too many keys in section");
                break;
            }
            
            toml_keyvalue_t *kv = &current_section->keys[current_section->key_count];
            if (parse_key_value_pair(&state, kv) == 0) {
                /* Reject duplicate keys per the TOML spec (AR-03 L14) rather
                 * than pick a winner. First-wins (the old behavior) made a
                 * hand-appended `email = ...` override silently dead;
                 * last-wins would give the file a meaning that depends on a
                 * nonstandard tiebreak of ours — bad for an identity-bearing
                 * config where "which email signs my commits?" must have
                 * exactly one answer. The writer never emits duplicates
                 * (toml_set_string overwrites in place), so this only fires
                 * on hand edits, where a line-anchored parse error is the
                 * diagnostic the user needs. find_key scans only the
                 * key_count committed entries, so it cannot match the pair
                 * just parsed into the uncommitted slot. */
                if (find_key(current_section, kv->key)) {
                    char dup_msg[sizeof(state.error_message)];
                    snprintf(dup_msg, sizeof(dup_msg),
                             "Duplicate key '%s' in section [%s] (TOML forbids "
                             "defining a key twice)", kv->key, current_section->name);
                    set_parser_error(&state, dup_msg);
                    break;
                }
                if (!toml_scalar_namespace_is_available(
                        doc, current_section->name, kv->key)) {
                    set_parser_error(
                        &state,
                        "Scalar key collides with an existing table namespace");
                    break;
                }
                /* Nothing but whitespace/comment may follow the value — no
                 * second `key = value` on the same physical line (AR-06 F70).
                 * Checked before committing the pair so a trailing-junk line is
                 * rejected wholesale. */
                if (require_line_end(&state) != 0) {
                    break;
                }
                current_section->key_count++;
            }
            continue;
        }
        
        /* Consume valid physical line endings atomically. A bare CR is an
         * error, not an alternate newline spelling. */
        int line_ending = consume_line_ending(&state);
        if (line_ending < 0) {
            break;
        }
        if (line_ending > 0) {
            continue;
        }
        
        /* Unknown character */
        set_parser_error(&state, "Unexpected character");
        break;
    }
    
    if (state.has_error) {
        set_error(ERR_CONFIG_INVALID, "TOML parsing failed at line %zu, column %zu: %s",
                  state.line_number, state.column_number, state.error_message);
        return -1;
    }
    
    /* Validate the parsed document against our schema */
    if (toml_validate_gitswitch_schema(doc) != 0) {
        return -1;
    }
    
    log_debug("TOML document parsed successfully: %zu sections", doc->section_count);
    
    return 0;
}

/* Get string value from TOML document */
int toml_get_string(const toml_document_t *doc, const char *section,
                    const char *key, char *value, size_t value_size) {
    const toml_keyvalue_t *kv;

    if (!doc || !section || !key || !value || value_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_string");
        return -1;
    }
    if (toml_resolve_getter_value(doc, section, key, TOML_TYPE_STRING,
                                  &kv) != 0) {
        return -1;
    }

    /* Reject rather than truncate when the value won't fit the destination, so
     * the bytes the caller validates are exactly the bytes it stores (the
     * value buffer is larger than some account fields, e.g. email/key id). */
    if (strlen(kv->value) >= value_size) {
        set_error(ERR_CONFIG_INVALID, "Value for %s.%s is too long (max %zu bytes)",
                  section, key, value_size - 1);
        return -1;
    }

    /* Reject, like the too-long case above, when sanitization would ALTER
     * the value (AR-03 M6): this getter is the campaign's single choke
     * point for byte fidelity. validate_name admits '"', the writer escapes
     * it faithfully and the parser unescapes it — silently stripping it
     * here meant disk and memory disagreed at first reload, desyncing every
     * name-keyed resource (agent socket, GNUPGHOME, active_account) and
     * persisting the mutated spelling on the next save. Callers now get the
     * on-disk bytes verbatim or an error, never a repaired value. */
    if (toml_sanitize_string(kv->value, value, value_size) != 0) {
        return -1;
    }
    if (strcmp(value, kv->value) != 0) {
        value[0] = '\0'; /* fail closed: don't hand back the altered bytes */
        set_error(ERR_CONFIG_INVALID,
                  "Value for %s.%s contains characters that cannot round-trip "
                  "(quote, backslash, control byte, or malformed UTF-8); refusing "
                  "to silently alter it — fix the value in the config file",
                  section, key);
        return -1;
    }
    return 0;
}

/* Get integer value from TOML document */
int toml_get_integer(const toml_document_t *doc, const char *section,
                     const char *key, int *value) {
    const toml_keyvalue_t *kv;
    int parsed_value;

    if (!doc || !section || !key || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_integer");
        return -1;
    }
    if (toml_resolve_getter_value(doc, section, key, TOML_TYPE_INTEGER,
                                  &kv) != 0) {
        return -1;
    }

    if (!toml_canonical_integer(kv->value, &parsed_value)) {
        set_error(ERR_CONFIG_INVALID,
                  "Integer value for %s.%s is not canonical", section, key);
        return -1;
    }

    *value = parsed_value;
    return 0;
}

/* Get boolean value from TOML document */
int toml_get_boolean(const toml_document_t *doc, const char *section,
                     const char *key, bool *value) {
    const toml_keyvalue_t *kv;

    if (!doc || !section || !key || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_boolean");
        return -1;
    }
    if (toml_resolve_getter_value(doc, section, key, TOML_TYPE_BOOLEAN,
                                  &kv) != 0) {
        return -1;
    }

    if (!toml_canonical_boolean(kv->value, value)) {
        set_error(ERR_CONFIG_INVALID,
                  "Boolean value for %s.%s is not canonical", section, key);
        return -1;
    }
    return 0;
}

static bool ascii_alphanumeric(unsigned char c) {
    return (c >= (unsigned char)'A' && c <= (unsigned char)'Z') ||
           (c >= (unsigned char)'a' && c <= (unsigned char)'z') ||
           (c >= (unsigned char)'0' && c <= (unsigned char)'9');
}

/* `ssh_host` is the owned OpenSSH Host pattern. Keep its historical wildcard
 * support, but make the grammar locale-independent and single-token. */
bool toml_validate_ssh_host_alias(const char *alias) {
    size_t len;

    if (!alias) {
        return false;
    }
    len = strlen(alias);
    if (len == 0 || len >= MAX_NAME_LEN) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)alias; *p; p++) {
        if (!(ascii_alphanumeric(*p) || *p == (unsigned char)'.' ||
              *p == (unsigned char)'-' || *p == (unsigned char)'_' ||
              *p == (unsigned char)'*' || *p == (unsigned char)'?')) {
            return false;
        }
    }
    return true;
}

/* `ssh_hostname` is emitted as a literal HostName destination. In particular,
 * it is not an OpenSSH pattern and cannot carry '%' token expansion. This
 * conservative ASCII grammar covers DNS names and unbracketed IPv4/IPv6
 * literals without admitting whitespace, quoting, escapes, or wildcards. */
bool toml_validate_ssh_hostname(const char *hostname) {
    size_t len;

    if (!hostname) {
        return false;
    }
    len = strlen(hostname);
    if (len == 0 || len >= MAX_NAME_LEN) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)hostname; *p; p++) {
        if (!(ascii_alphanumeric(*p) || *p == (unsigned char)'.' ||
              *p == (unsigned char)'-' || *p == (unsigned char)'_' ||
              *p == (unsigned char)':')) {
            return false;
        }
    }
    return true;
}

static int toml_validate_account_incarnation_uniformity(
    const toml_document_t *doc) {
    bool found_bound_account = false;
    bool found_legacy_account = false;

    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];
        bool has_incarnation = false;

        if (!string_starts_with(section->name, "accounts.")) continue;
        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            if (kv->is_set && strcmp(kv->key, "incarnation") == 0) {
                has_incarnation = true;
                break;
            }
        }
        found_bound_account |= has_incarnation;
        found_legacy_account |= !has_incarnation;
    }

    if (found_bound_account && found_legacy_account) {
        set_error(
            ERR_CONFIG_INVALID,
            "Account document mixes legacy accounts without incarnations and incarnation-bound accounts");
        return -1;
    }
    return 0;
}

/* Validate TOML document structure for gitswitch schema.
 *
 * Failure granularity matters here (AR-03 M5): this runs inside
 * toml_parse_string, so a `return -1` bricks the ENTIRE config — every
 * account, every command — until the file is hand-edited. That is the right
 * response to attack-shaped input (traversal, unsanitizable bytes) but not
 * to a value the tool's own writer used to produce: those mark just their
 * section skipped (is_set cleared) so the rest of the config still loads,
 * the getters treat the section as absent, and config.c's
 * accounts_skipped_on_load guard keeps the next save from erasing it. */
int toml_validate_gitswitch_schema(toml_document_t *doc) {
    if (!doc) {
        set_error(ERR_INVALID_ARGS, "NULL document to validate");
        return -1;
    }

    /* Validity belongs to this complete model version. Revoke it before any
     * derived visibility changes or early return, and publish it again only
     * after the whole schema pass succeeds. */
    doc->is_valid = false;

    if (toml_validate_model_invariants(doc, true) != 0) {
        return -1;
    }

    /* Account visibility is derived from this complete validation attempt.
     * Revoke every candidate before validating settings or any account: an
     * earlier fatal error may return before the main pass reaches a later
     * account, and that later section must not retain stale visibility from a
     * previous successful pass. Each account is published again only after
     * all of its fields and dependencies below succeed. */
    for (size_t i = 0; i < doc->section_count; i++) {
        if (string_starts_with(doc->sections[i].name, "accounts.")) {
            doc->sections[i].is_set = false;
        }
    }

    /* Check for required sections */
    bool has_settings = false;
    bool has_accounts = false;

    for (size_t i = 0; i < doc->section_count; i++) {
        toml_section_t *section = &doc->sections[i];
        
        if (strcmp(section->name, "settings") == 0) {
            has_settings = true;
            
            /* Validate settings section */
            bool has_default_scope = false;
            for (size_t j = 0; j < section->key_count; j++) {
                const toml_keyvalue_t *kv = &section->keys[j];

                if (!kv->is_set) continue;
                
                if (strcmp(kv->key, "default_scope") == 0) {
                    has_default_scope = true;
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "default_scope must be a string");
                        return -1;
                    }
                    if (strcmp(kv->value, "local") != 0 && strcmp(kv->value, "global") != 0) {
                        set_error(ERR_CONFIG_INVALID, "default_scope must be 'local' or 'global'");
                        return -1;
                    }
                }

                /* active_account is a legacy migration source after AR-07
                 * T12 moved live state into .resume-hint.  It remains modeled
                 * so an older file can be read, but a present wrong-typed
                 * value is never allowed to masquerade as "absent" and then
                 * disappear on the next reconstructive save. */
                if (strcmp(kv->key, "active_account") == 0 &&
                    kv->type != TOML_TYPE_STRING) {
                    set_error(ERR_CONFIG_INVALID,
                              "settings.active_account must be a string");
                    return -1;
                }
            }
            
            if (!has_default_scope) {
                set_error(ERR_CONFIG_INVALID, "settings section missing required default_scope");
                return -1;
            }
        }
        
        if (string_starts_with(section->name, "accounts.")) {
            has_accounts = true;

            /* Validate account section */
            bool has_name = false, has_email = false;
            bool skip_section = false;
            bool has_nonempty_ssh_key = false;
            bool has_ssh_host = false;
            bool has_ssh_hostname = false;
            bool has_nonempty_gpg_key = false;
            bool has_gpg_signing_enabled = false;

            for (size_t j = 0; j < section->key_count; j++) {
                const toml_keyvalue_t *kv = &section->keys[j];

                if (!kv->is_set) continue;
                
                if (strcmp(kv->key, "name") == 0) {
                    has_name = true;
                    if (kv->type != TOML_TYPE_STRING || strlen(kv->value) == 0) {
                        set_error(ERR_CONFIG_INVALID, "Account name must be a non-empty string");
                        return -1;
                    }
                }
                
                if (strcmp(kv->key, "email") == 0) {
                    has_email = true;
                    if (kv->type != TOML_TYPE_STRING || !validate_email(kv->value)) {
                        set_error(ERR_CONFIG_INVALID, "Account email must be a valid email address");
                        return -1;
                    }
                }

                if (strcmp(kv->key, "incarnation") == 0) {
                    if (kv->type != TOML_TYPE_STRING ||
                        !account_incarnation_is_valid(kv->value)) {
                        set_error(
                            ERR_CONFIG_INVALID,
                            "%s.incarnation must be exactly 64 uppercase hexadecimal digits",
                            section->name);
                        return -1;
                    }
                }

                if (strcmp(kv->key, "description") == 0 &&
                    kv->type != TOML_TYPE_STRING) {
                    set_error(ERR_CONFIG_INVALID,
                              "%s.description must be a string",
                              section->name);
                    return -1;
                }

                if (strcmp(kv->key, "preferred_scope") == 0) {
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID,
                                  "%s.preferred_scope must be a string",
                                  section->name);
                        return -1;
                    }
                    if (strcmp(kv->value, "local") != 0 &&
                        strcmp(kv->value, "global") != 0) {
                        set_error(ERR_CONFIG_INVALID,
                                  "%s.preferred_scope must be 'local' or 'global'",
                                  section->name);
                        return -1;
                    }
                }
                
                if (strcmp(kv->key, "ssh_key") == 0) {
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "ssh_key must be a string");
                        return -1;
                    }
                    char sanitized[MAX_PATH_LEN];
                    if (strlen(kv->value) > 0) {
                        has_nonempty_ssh_key = true;
                        /* Reject a value the sanitizer would ALTER: since M6,
                         * toml_get_string refuses to hand such a value to
                         * callers at all, so admitting it here would load an
                         * account whose ssh_key then reads as "absent" —
                         * silent identity mutation. This also keeps the
                         * backslash-resynthesis traversal spelling fatal:
                         * `.\./id_rsa` has no ".." substring, but stripping
                         * the backslash resynthesizes "../id_rsa", so any
                         * byte the sanitizer touches is treated as hostile
                         * (AR-02 #29). Past this check, sanitized bytes ==
                         * raw bytes, so the guards below see exactly what
                         * callers would receive. */
                        if (toml_sanitize_string(kv->value, sanitized, sizeof(sanitized)) != 0 ||
                            strcmp(sanitized, kv->value) != 0) {
                            set_error(ERR_CONFIG_INVALID,
                                      "SSH key path contains characters that cannot "
                                      "round-trip: %s", kv->value);
                            return -1;
                        }
                        /* Over-long path: skip THIS account, not the file
                         * (AR-03 M5). The writer historically accepted up to
                         * TOML_MAX_VALUE_LEN-1 (511) bytes, so a 257-511
                         * char ssh_key can be gitswitch's own prior output —
                         * failing the whole parse bricked every command over
                         * one account's field. The path-length cap is
                         * checked before toml_validate_file_path because
                         * that guard folds length and traversal together and
                         * only traversal deserves the whole-file response. */
                        if (strlen(kv->value) > 256) {
                            log_warning("Account section [%s]: ssh_key is %zu bytes "
                                        "(max 256); skipping this account, the rest "
                                        "of the config still loads",
                                        section->name, strlen(kv->value));
                            skip_section = true;
                            break;
                        }
                        if (!toml_validate_file_path(kv->value)) {
                            set_error(ERR_CONFIG_INVALID, "Invalid SSH key path: %s", kv->value);
                            return -1;
                        }
                        /* Require an anchored path: a bare relative ssh_key
                         * resolves against whatever directory gitswitch was
                         * invoked from, so which key gets loaded would depend
                         * on the CWD — an attacker-plantable "keys/id_rsa" in
                         * a shared directory could silently win. '/' and '~'
                         * (expanded against HOME by expand_path downstream)
                         * are both CWD-independent. gpg_key is exempt: it is
                         * a key ID, not a filesystem path. */
                        if (kv->value[0] != '/' && kv->value[0] != '~') {
                            set_error(ERR_CONFIG_INVALID,
                                      "ssh_key must be an absolute or ~-anchored path, not relative: %s",
                                      kv->value);
                            return -1;
                        }
                    }
                }

                if (strcmp(kv->key, "ssh_host") == 0) {
                    has_ssh_host = true;
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "ssh_host must be a string");
                        return -1;
                    }
                    if (!toml_validate_ssh_host_alias(kv->value)) {
                        set_error(ERR_CONFIG_INVALID,
                                  "ssh_host must contain only ASCII letters, digits, "
                                  "'.', '-', '_', '*', or '?'");
                        return -1;
                    }
                }

                if (strcmp(kv->key, "ssh_hostname") == 0) {
                    has_ssh_hostname = true;
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID,
                                  "ssh_hostname must be a string");
                        return -1;
                    }
                    if (!toml_validate_ssh_hostname(kv->value)) {
                        set_error(ERR_CONFIG_INVALID,
                                  "ssh_hostname must contain only ASCII letters, "
                                  "digits, '.', '-', '_', or ':'");
                        return -1;
                    }
                }
                
                if (strcmp(kv->key, "gpg_key") == 0) {
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "gpg_key must be a string");
                        return -1;
                    }
                    if (strlen(kv->value) > 0 && !validate_key_id(kv->value)) {
                        set_error(ERR_CONFIG_INVALID, "Invalid GPG key ID: %s", kv->value);
                        return -1;
                    }
                    has_nonempty_gpg_key = strlen(kv->value) > 0;
                }

                if (strcmp(kv->key, "gpg_signing_enabled") == 0) {
                    has_gpg_signing_enabled = true;
                    if (kv->type != TOML_TYPE_BOOLEAN) {
                        set_error(ERR_CONFIG_INVALID,
                                  "%s.gpg_signing_enabled must be a boolean",
                                  section->name);
                        return -1;
                    }
                }
            }
            
            if (skip_section) {
                /* Hide the section from the getters but keep it enumerable:
                 * toml_get_sections must still report it so config.c's
                 * loader counts it in accounts_skipped_on_load and
                 * config_save refuses to rewrite the file — a skip must
                 * never decay into silent erasure. toml_write_file likewise
                 * still emits its keys, so a document written back preserves
                 * the section byte-for-byte for the user to fix. */
                section->is_set = false;
                continue;
            }

            if (!has_name || !has_email) {
                set_error(ERR_CONFIG_INVALID, "Account section %s missing required name or email",
                          section->name);
                return -1;
            }


            /* These keys are emitted only for an enabled subsystem.  A
             * present dependent without its enabling key used to load as an
             * innocuous disabled account and vanish on the next save.  Reject
             * every such combination at admission with a field-specific
             * diagnostic, before any in-memory mutation can be persisted. */
            if (has_ssh_host && !has_nonempty_ssh_key) {
                set_error(ERR_CONFIG_INVALID,
                          "%s.ssh_host requires a non-empty ssh_key",
                          section->name);
                return -1;
            }
            if (has_ssh_hostname && !has_nonempty_ssh_key) {
                set_error(ERR_CONFIG_INVALID,
                          "%s.ssh_hostname requires a non-empty ssh_key",
                          section->name);
                return -1;
            }
            if (has_gpg_signing_enabled && !has_nonempty_gpg_key) {
                set_error(ERR_CONFIG_INVALID,
                          "%s.gpg_signing_enabled requires a non-empty gpg_key",
                          section->name);
                return -1;
            }

            section->is_set = true;
        }
    }
    
    if (!has_settings) {
        set_error(ERR_CONFIG_INVALID, "Configuration missing required [settings] section");
        return -1;
    }
    
    if (!has_accounts) {
        log_info("Configuration has no account sections yet - this is normal for new installations");
        /* This is not an error - allow empty configurations */
    }

    doc->is_valid = true;
    log_debug("TOML document schema validation passed");
    return 0;
}

/* Security validation: Check for safe characters only.
 *
 * UTF-8-aware (AR-02 #6): this gate runs on the raw file buffer before any
 * parsing, and it used to reject every byte >= 0x80 — so one accented
 * character in a name (which validate_name and the interactive add happily
 * accept, and toml_write_file writes verbatim) bricked the ENTIRE config on
 * the next load, unreachable even by `gitswitch remove`. Well-formed
 * multi-byte UTF-8 with terminal-safe codepoints now passes; what stays
 * rejected is exactly the dangerous residue: C0 controls (other than
 * \n\r\t), DEL, raw C1 bytes (malformed as UTF-8), C1 controls in their
 * 2-byte form, and overlong/surrogate encodings (utf8_decode is strict) —
 * the terminal-escape-smuggling vectors the old byte filter was after. */
bool toml_validate_safe_characters(const char *input, size_t length) {
    if (!input) return false;

    size_t i = 0;
    while (i < length) {
        unsigned char c = (unsigned char)input[i];

        /* Printable ASCII, newlines, tabs, and carriage returns */
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
            i++;
            continue;
        }
        if (c < 0x80) {
            /* Other C0 control or DEL — includes an embedded NUL. Multi-byte
             * reads below are independently bounded by the exact remaining
             * length; input is not required to have a byte at input[length]. */
            log_warning("Unsafe character found at position %zu: 0x%02x", i, c);
            return false;
        }

        uint32_t cp;
        size_t len = utf8_decode((const unsigned char *)input + i,
                                 length - i, &cp);
        if (len == 0 || !tty_safe_codepoint(cp)) {
            log_warning("Malformed or unsafe UTF-8 sequence at position %zu: 0x%02x", i, c);
            return false;
        }
        i += len;
    }

    return true;
}

/* A stored string is already decoded: quotes, backslashes, and the three
 * supported escaped controls are data, while every other byte must satisfy
 * the same strict UTF-8 and terminal-safety contract as the raw document.
 * Keep this length-aware so parser output and public setters share one rule. */
static bool decoded_string_value_is_valid(const char *value, size_t length) {
    return value && length < TOML_MAX_VALUE_LEN &&
           toml_validate_safe_characters(value, length);
}

static bool toml_canonical_integer(const char *value, int *parsed) {
    char canonical[32];
    char *end = NULL;
    long number;
    int written;

    if (!value || strnlen(value, TOML_MAX_VALUE_LEN) == TOML_MAX_VALUE_LEN) {
        return false;
    }
    errno = 0;
    number = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        number < INT_MIN || number > INT_MAX) {
        return false;
    }
    written = snprintf(canonical, sizeof(canonical), "%d", (int)number);
    if (written < 0 || (size_t)written >= sizeof(canonical) ||
        strcmp(canonical, value) != 0) {
        return false;
    }
    if (parsed) *parsed = (int)number;
    return true;
}

static bool toml_canonical_boolean(const char *value, bool *parsed) {
    if (!value || strnlen(value, TOML_MAX_VALUE_LEN) == TOML_MAX_VALUE_LEN) {
        return false;
    }
    if (strcmp(value, "true") == 0) {
        if (parsed) *parsed = true;
        return true;
    }
    if (strcmp(value, "false") == 0) {
        if (parsed) *parsed = false;
        return true;
    }
    return false;
}

/* The public model is caller-mutable, including through byte-oriented APIs.
 * Inspect a _Bool's representation without evaluating a possibly-invalid
 * typed value (which is itself undefined behavior under UBSan). Comparing to
 * representations produced by this implementation also avoids assuming that
 * sizeof(bool) is one. */
static bool toml_bool_object_value(const bool *object, bool *value) {
    unsigned char raw[sizeof(bool)];
    unsigned char false_raw[sizeof(bool)];
    unsigned char true_raw[sizeof(bool)];
    bool false_value = false;
    bool true_value = true;

    if (!object) return false;
    memcpy(raw, object, sizeof(raw));
    memcpy(false_raw, &false_value, sizeof(false_raw));
    memcpy(true_raw, &true_value, sizeof(true_raw));
    if (memcmp(raw, false_raw, sizeof(raw)) == 0) {
        if (value) *value = false;
        return true;
    }
    if (memcmp(raw, true_raw, sizeof(raw)) == 0) {
        if (value) *value = true;
        return true;
    }
    return false;
}

/* Resolve one getter route without turning a hot read into a whole-document
 * schema/namespace scan. The outer section count is bounded before iteration;
 * every inspected section name and visibility flag is proved safe so a later
 * duplicate or malformed entry cannot hide behind an early match. Only the
 * matching section's key array and matching value payload are inspected.
 * Thus the work is O(section_count + matching_key_count + value_length), while
 * still failing closed on every object the requested lookup would rely on. */
static int toml_resolve_getter_value(const toml_document_t *doc,
                                     const char *section_name,
                                     const char *key_name,
                                     toml_value_type_t expected_type,
                                     const toml_keyvalue_t **resolved) {
    const toml_section_t *matched_section = NULL;
    const toml_keyvalue_t *matched_key = NULL;
    bool document_is_valid;
    bool matched_section_is_set = false;
    bool matched_key_is_set = false;
    size_t value_length;

    if (!toml_bool_object_value(&doc->is_valid, &document_is_valid)) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML document has an invalid validity representation");
        return -1;
    }
    if (!document_is_valid) {
        set_error(ERR_CONFIG_INVALID, "TOML document is not valid");
        return -1;
    }
    if (doc->section_count > TOML_MAX_SECTIONS) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML section count exceeds the public model capacity");
        return -1;
    }

    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *candidate = &doc->sections[i];
        bool candidate_is_set;

        if (!memchr(candidate->name, '\0', sizeof(candidate->name))) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has no terminating NUL", i);
            return -1;
        }
        if (candidate->name[0] == '\0') {
            if (i != 0) {
                set_error(ERR_CONFIG_INVALID,
                          "The implicit TOML root section must be first");
                return -1;
            }
        } else if (!section_name_is_valid(candidate->name)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has an invalid name", i);
            return -1;
        }
        if (!toml_bool_object_value(&candidate->is_set,
                                    &candidate_is_set)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has an invalid visibility representation",
                      i);
            return -1;
        }
        if (strcmp(candidate->name, section_name) != 0) continue;
        if (matched_section) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML getter route has duplicate section [%s]",
                      section_name);
            return -1;
        }
        matched_section = candidate;
        matched_section_is_set = candidate_is_set;
    }

    /* Missing, or schema-invalidated (is_set cleared): callers intentionally
     * treat a skipped account as wholly absent instead of loading it partly. */
    if (!matched_section || !matched_section_is_set) return -1;
    if (matched_section->key_count > TOML_MAX_KEYS_PER_SECTION) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML section [%s] key count exceeds capacity",
                  section_name);
        return -1;
    }

    for (size_t i = 0; i < matched_section->key_count; i++) {
        const toml_keyvalue_t *candidate = &matched_section->keys[i];
        bool candidate_is_set;

        if (!memchr(candidate->key, '\0', sizeof(candidate->key)) ||
            !key_name_is_valid(candidate->key)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML key %zu in section [%s] has an invalid name", i,
                      section_name);
            return -1;
        }
        if (!toml_bool_object_value(&candidate->is_set,
                                    &candidate_is_set)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML key %zu in section [%s] has an invalid set-state representation",
                      i, section_name);
            return -1;
        }
        if (strcmp(candidate->key, key_name) != 0) continue;
        if (matched_key) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML getter route has duplicate key %s.%s",
                      section_name, key_name);
            return -1;
        }
        matched_key = candidate;
        matched_key_is_set = candidate_is_set;
    }

    if (!matched_key || !matched_key_is_set) return -1;
    value_length = strnlen(matched_key->value, sizeof(matched_key->value));
    if (value_length == sizeof(matched_key->value)) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML value for %s.%s has no terminating NUL", section_name,
                  key_name);
        return -1;
    }
    if (matched_key->type != expected_type) {
        const char *expected_name =
            expected_type == TOML_TYPE_STRING ? "string" :
            expected_type == TOML_TYPE_INTEGER ? "integer" : "boolean";
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not a %s", section_name,
                  key_name, expected_name);
        return -1;
    }
    switch (expected_type) {
        case TOML_TYPE_STRING:
            if (!decoded_string_value_is_valid(matched_key->value,
                                               value_length)) {
                set_error(ERR_CONFIG_INVALID,
                          "String value for %s.%s is invalid", section_name,
                          key_name);
                return -1;
            }
            break;
        case TOML_TYPE_INTEGER:
            if (!toml_canonical_integer(matched_key->value, NULL)) {
                set_error(ERR_CONFIG_INVALID,
                          "Integer value for %s.%s is not canonical",
                          section_name, key_name);
                return -1;
            }
            break;
        case TOML_TYPE_BOOLEAN:
            if (!toml_canonical_boolean(matched_key->value, NULL)) {
                set_error(ERR_CONFIG_INVALID,
                          "Boolean value for %s.%s is not canonical",
                          section_name, key_name);
                return -1;
            }
            break;
        case TOML_TYPE_INVALID:
        default:
            set_error(ERR_CONFIG_INVALID,
                      "TOML getter requested an invalid value type");
            return -1;
    }
    *resolved = matched_key;
    return 0;
}

#define TOML_MAX_FQN_LEN (TOML_MAX_SECTION_LEN + TOML_MAX_KEY_LEN)

static bool toml_make_scalar_fqn(const char *section_name,
                                 const char *key_name,
                                 char fqn[TOML_MAX_FQN_LEN]) {
    int written;

    if (section_name[0] == '\0') {
        written = snprintf(fqn, TOML_MAX_FQN_LEN, "%s", key_name);
    } else {
        written = snprintf(fqn, TOML_MAX_FQN_LEN, "%s.%s", section_name,
                           key_name);
    }
    return written >= 0 && (size_t)written < TOML_MAX_FQN_LEN;
}

/* A scalar may be below a table (the ordinary `[table] key = value` case),
 * but it may never be the table itself or an ancestor that a later table
 * would need to reinterpret. */
static bool toml_fqn_is_equal_or_ancestor(const char *possible_ancestor,
                                          const char *candidate) {
    size_t ancestor_length = strlen(possible_ancestor);
    size_t candidate_length = strlen(candidate);

    return ancestor_length <= candidate_length &&
           memcmp(possible_ancestor, candidate, ancestor_length) == 0 &&
           (candidate[ancestor_length] == '\0' ||
            candidate[ancestor_length] == '.');
}

static bool toml_table_namespace_is_available(const toml_document_t *doc,
                                              const char *table_name) {
    char scalar[TOML_MAX_FQN_LEN];

    if (!doc || !table_name) return false;
    if (table_name[0] == '\0') return true; /* implicit root, not a table */

    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];
        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            if (!kv->is_set ||
                !toml_make_scalar_fqn(section->name, kv->key, scalar)) {
                continue;
            }
            if (toml_fqn_is_equal_or_ancestor(scalar, table_name)) {
                return false;
            }
        }
    }
    return true;
}

static bool toml_scalar_namespace_is_available(const toml_document_t *doc,
                                               const char *section_name,
                                               const char *key_name) {
    char scalar[TOML_MAX_FQN_LEN];

    if (!doc || !section_name || !key_name ||
        !toml_make_scalar_fqn(section_name, key_name, scalar)) {
        return false;
    }
    for (size_t i = 0; i < doc->section_count; i++) {
        const char *table = doc->sections[i].name;
        if (table[0] != '\0' &&
            toml_fqn_is_equal_or_ancestor(scalar, table)) {
            return false;
        }
    }
    return true;
}

/* Validate public, caller-mutable model storage without changing it. Every
 * bound is proved before an array element or string is inspected, so corrupt
 * counts and missing terminators fail closed under ASan instead of becoming a
 * writer-side memory walk. Writers additionally request the required-set
 * contract, but deliberately do not run mutating gitswitch schema semantics. */
static int toml_validate_model_invariants(const toml_document_t *doc,
                                          bool require_schema_fields) {
    bool model_flag;

    if (!doc) {
        set_error(ERR_INVALID_ARGS, "NULL TOML document");
        return -1;
    }
    if (g_metadata_test_hook) {
        (void)g_metadata_test_hook(TOML_METADATA_TEST_MODEL_PREFLIGHT);
    }
    if (doc->section_count > TOML_MAX_SECTIONS) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML section count exceeds the public model capacity");
        return -1;
    }
    if (!toml_bool_object_value(&doc->is_valid, &model_flag)) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML document has an invalid validity representation");
        return -1;
    }

    /* Pass one proves every bound and terminator. No helper that scans the
     * complete model is called until this pass has made that scan safe. */
    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];

        if (!memchr(section->name, '\0', sizeof(section->name))) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has no terminating NUL", i);
            return -1;
        }
        if (section->name[0] == '\0') {
            if (i != 0) {
                set_error(ERR_CONFIG_INVALID,
                          "The implicit TOML root section must be first");
                return -1;
            }
        } else if (!section_name_is_valid(section->name)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has an invalid name", i);
            return -1;
        }
        if (!toml_bool_object_value(&section->is_set, &model_flag)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu has an invalid visibility representation",
                      i);
            return -1;
        }
        for (size_t prior = 0; prior < i; prior++) {
            if (strcmp(doc->sections[prior].name, section->name) == 0) {
                set_error(ERR_CONFIG_INVALID,
                          "TOML section %zu duplicates section %zu", i,
                          prior);
                return -1;
            }
        }
        if (section->key_count > TOML_MAX_KEYS_PER_SECTION) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML section %zu key count exceeds capacity", i);
            return -1;
        }

        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            size_t value_length;
            bool is_set;

            if (!memchr(kv->key, '\0', sizeof(kv->key)) ||
                !key_name_is_valid(kv->key)) {
                set_error(ERR_CONFIG_INVALID,
                          "TOML key %zu in section %zu has an invalid name",
                          j, i);
                return -1;
            }
            for (size_t prior = 0; prior < j; prior++) {
                if (strcmp(section->keys[prior].key, kv->key) == 0) {
                    set_error(ERR_CONFIG_INVALID,
                              "TOML key %zu in section %zu is duplicated", j,
                              i);
                    return -1;
                }
            }
            if (!toml_bool_object_value(&kv->is_set, &is_set)) {
                set_error(ERR_CONFIG_INVALID,
                          "TOML key %zu in section %zu has an invalid set-state representation",
                          j, i);
                return -1;
            }
            if (!is_set) continue;

            value_length = strnlen(kv->value, sizeof(kv->value));
            if (value_length == sizeof(kv->value)) {
                set_error(ERR_CONFIG_INVALID,
                          "TOML value %zu in section %zu has no terminating NUL",
                          j, i);
                return -1;
            }
            switch (kv->type) {
                case TOML_TYPE_STRING:
                    if (!decoded_string_value_is_valid(kv->value,
                                                       value_length)) {
                        set_error(ERR_CONFIG_INVALID,
                                  "TOML string %zu in section %zu is invalid",
                                  j, i);
                        return -1;
                    }
                    break;
                case TOML_TYPE_INTEGER:
                    if (!toml_canonical_integer(kv->value, NULL)) {
                        set_error(ERR_CONFIG_INVALID,
                                  "TOML integer %zu in section %zu is not canonical",
                                  j, i);
                        return -1;
                    }
                    break;
                case TOML_TYPE_BOOLEAN:
                    if (!toml_canonical_boolean(kv->value, NULL)) {
                        set_error(ERR_CONFIG_INVALID,
                                  "TOML boolean %zu in section %zu is not canonical",
                                  j, i);
                        return -1;
                    }
                    break;
                case TOML_TYPE_INVALID:
                default:
                    set_error(ERR_CONFIG_INVALID,
                              "TOML value %zu in section %zu has an invalid type",
                              j, i);
                    return -1;
            }
        }
    }

    /* Incarnation migration is document-atomic. Pass one proved the raw
     * section/key bounds, so inspect every account now, before pass two can
     * reject a missing required field and before schema semantics can hide a
     * recoverably skipped section. Otherwise a mixed generation can evade
     * the loader's later live-account count. */
    if (require_schema_fields &&
        toml_validate_account_incarnation_uniformity(doc) != 0) {
        return -1;
    }

    /* Pass two may safely scan the complete model for namespace and required
     * key relationships. Unset scalars remain structurally present records,
     * but they occupy neither a namespace nor a required-field slot. */
    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];
        bool has_default_scope = false;
        bool has_name = false;
        bool has_email = false;

        if (section->name[0] != '\0' &&
            !toml_table_namespace_is_available(doc, section->name)) {
            set_error(ERR_CONFIG_INVALID,
                      "TOML table namespace at section %zu collides with a scalar",
                      i);
            return -1;
        }
        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            bool is_set;

            /* Pass one proved this representation. Decode it again without a
             * typed read so the proof remains local and sanitizer-clean. */
            if (!toml_bool_object_value(&kv->is_set, &is_set) || !is_set) {
                continue;
            }
            if (!toml_scalar_namespace_is_available(doc, section->name,
                                                    kv->key)) {
                set_error(ERR_CONFIG_INVALID,
                          "TOML scalar namespace at section %zu key %zu collides with a table",
                          i, j);
                return -1;
            }
            if (strcmp(section->name, "settings") == 0 &&
                strcmp(kv->key, "default_scope") == 0) {
                has_default_scope = true;
            }
            if (string_starts_with(section->name, "accounts.")) {
                if (strcmp(kv->key, "name") == 0) has_name = true;
                if (strcmp(kv->key, "email") == 0) has_email = true;
            }
        }

        if (strcmp(section->name, "settings") == 0) {
            if (require_schema_fields && !has_default_scope) {
                set_error(ERR_CONFIG_INVALID,
                          "settings section missing set required default_scope");
                return -1;
            }
        }
        if (require_schema_fields &&
            string_starts_with(section->name, "accounts.") &&
            (!has_name || !has_email)) {
            set_error(ERR_CONFIG_INVALID,
                      "Account section missing set required name or email");
            return -1;
        }
    }
    return 0;
}

/* Sanitize string value. Strips what a value must never carry into callers:
 * C0 controls (incl. newline/CR — the ~/.ssh/config IdentityFile sink and
 * core.sshCommand depend on values staying single-line), DEL, quotes and
 * backslashes (quote-breakout in single-quoted emissions), raw C1 bytes, and
 * malformed/overlong UTF-8. Well-formed multi-byte UTF-8 with terminal-safe
 * codepoints passes through byte-identical (AR-02 #6) — previously every
 * byte >= 0x80 was dropped, so "José" retrieved as "Jos" and no non-ASCII
 * value could ever round-trip. */
int toml_sanitize_string(const char *input, char *output, size_t output_size) {
    size_t input_len, output_pos = 0;

    if (!input || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_sanitize_string");
        return -1;
    }

    input_len = strlen(input);

    for (size_t i = 0; i < input_len && output_pos < output_size - 1; ) {
        unsigned char c = (unsigned char)input[i];

        if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
            output[output_pos++] = (char)c;
            i++;
        } else if (c == '\t') {
            output[output_pos++] = (char)c;
            i++;
        } else if (c >= 0x80) {
            uint32_t cp;
            size_t len = utf8_decode((const unsigned char *)input + i,
                                     input_len - i, &cp);
            if (len > 0 && tty_safe_codepoint(cp) &&
                output_pos + len <= output_size - 1) {
                memcpy(output + output_pos, input + i, len);
                output_pos += len;
                i += len;
            } else {
                /* Malformed byte, C1 control, or a sequence that won't fit
                 * whole — drop it (never emit a partial sequence). */
                i += (len > 0) ? len : 1;
            }
        } else {
            i++; /* C0 control or DEL: drop */
        }
    }

    output[output_pos] = '\0';
    return 0;
}

/* Validate file path for security. Property-based, not location-based
 * (AR-02 #7): this used to allowlist /home, /Users, and /tmp prefixes, which
 * rejected every legitimate enterprise home layout (/export/home NFS,
 * /var/home systemd-homed, /data, ...) — and because it runs inside schema
 * validation, one such path was a fatal WHOLE-config load failure taking
 * every unrelated account down with it. A prefix list adds no protection the
 * real guards don't already provide: the schema caller requires the path to
 * be '/'- or '~'-anchored (CWD-independent), validate_account_security
 * lstats/permission-checks it at load, and ssh_validate_key_file enforces
 * ownership and mode before any key is actually handed to an agent. What
 * remains here are the structural properties of a sane key path. */
bool toml_validate_file_path(const char *path) {
    if (!path || strlen(path) == 0) return true; /* Empty path is allowed */

    /* Check for directory traversal attempts */
    if (strstr(path, "..") != NULL) {
        log_warning("Directory traversal attempt in path: %s", path);
        return false;
    }

    /* Check path length */
    if (strlen(path) > 256) {
        log_warning("Path too long: %zu characters", strlen(path));
        return false;
    }

    return true;
}

/* Structural sanity check on the raw config buffer.
 *
 * This used to also reject any file containing shell metacharacters ("$(",
 * backtick, "${", "\x", "\u"). That was a relic of a shell-based execution
 * model: every subprocess now runs via run_argv (execvp, no shell), so those
 * substrings carry no injection risk here — while they legitimately appear in
 * names, descriptions, and passphrases, so the scan only corrupted valid
 * configs. Per-field validation plus argv execution is the real boundary; the
 * one remaining shell-interpolated sink (core.sshCommand) is guarded at its
 * own call site. We keep only the cheap nesting/DoS guard. */
bool toml_check_injection_patterns(const char *input, size_t length) {
    if (!input) return false;

    /* Count '[' only in structural positions. Brackets inside quoted string
     * values are ordinary data that toml_write_file emits verbatim, so
     * counting them made this guard reject configs the writer itself produced
     * (a bracket-heavy description bricked the config on the next reload).
     * Brackets in comments are likewise inert. Structural '[' only appears in
     * section headers, which the parser caps at TOML_MAX_SECTIONS anyway, so
     * exceeding that here is only ever pathological input ("[[[[[..."). */
    size_t bracket_count = 0;
    bool in_string = false;
    bool in_comment = false;
    for (size_t i = 0; i < length; i++) {
        char c = input[i];

        if (in_string) {
            if (c == '\\' && i + 1 < length) {
                i++; /* skip the escaped char so \" does not end the string */
            } else if (c == '"' || c == '\n') {
                /* A raw newline cannot occur inside a TOML basic string (the
                 * parser rejects it), so treat it as terminating — an
                 * unterminated quote must not blind this guard to structural
                 * brackets in the rest of the file. */
                in_string = false;
            }
            continue;
        }
        if (in_comment) {
            if (c == '\n') in_comment = false;
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == '#') { in_comment = true; continue; }
        if (c == '[') {
            bracket_count++;
            if (bracket_count > TOML_MAX_SECTIONS) {
                log_warning("Excessive bracket nesting detected");
                return false;
            }
        }
    }

    return true;
}

/* Internal helper functions implementation continues... */

/* Find section in document */
/* No logging here: this runs on the hot config-load path (once per key
 * lookup), and per-iteration log_debug calls dominated load time; callers
 * already report a miss where it matters. */
static toml_section_t *find_section(toml_document_t *doc, const char *section_name) {
    if (!doc || !section_name) return NULL;

    for (size_t i = 0; i < doc->section_count; i++) {
        if (strcmp(doc->sections[i].name, section_name) == 0) {
            return &doc->sections[i];
        }
    }

    return NULL;
}

/* Public setters and explicit headers share one narrow, locale-independent
 * grammar: nonempty dot-separated ASCII bare-key segments. Keep the empty root
 * section as an internal parser-only state. */
static bool section_name_is_valid(const char *section_name) {
    size_t length = 0;
    bool segment_has_byte = false;

    if (!section_name) return false;
    while (length < TOML_MAX_SECTION_LEN && section_name[length] != '\0') {
        length++;
    }
    if (length == 0 || length >= TOML_MAX_SECTION_LEN) return false;

    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)section_name[i];
        if (c == '.') {
            if (!segment_has_byte) return false;
            segment_has_byte = false;
        } else {
            if (!ascii_section_segment_byte_is_valid(c)) return false;
            segment_has_byte = true;
        }
    }
    return segment_has_byte;
}

/* Find or create section */
static toml_section_t *find_or_create_section(toml_document_t *doc, const char *section_name) {
    toml_section_t *section;
    
    if (!doc || !section_name) return NULL;
    
    /* Try to find existing section */
    section = find_section(doc, section_name);
    if (section) return section;
    
    /* Create new section */
    if (doc->section_count >= TOML_MAX_SECTIONS) {
        set_error(ERR_CONFIG_INVALID,
                  "Maximum number of TOML sections exceeded (%d)",
                  TOML_MAX_SECTIONS);
        log_error("Maximum number of sections exceeded: %d", TOML_MAX_SECTIONS);
        return NULL;
    }
    
    section = &doc->sections[doc->section_count];

    /* Copy into a detached zeroed value, then publish the whole section and
     * advance section_count. A failed copy cannot leave a reachable empty
     * section that toml_write_file() serializes as `[]` (AR-07 L30). */
    toml_section_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    if (safe_strncpy(candidate.name, section_name, sizeof(candidate.name)) != 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Section name is too long (max %d bytes)",
                  TOML_MAX_SECTION_LEN - 1);
        return NULL;
    }
    candidate.is_set = true;
    *section = candidate;
    doc->section_count++;
    
    return section;
}

/* Find key in section */
/* No logging: hot path, see find_section. */
static toml_keyvalue_t *find_key(toml_section_t *section, const char *key_name) {
    if (!section || !key_name) return NULL;

    for (size_t i = 0; i < section->key_count; i++) {
        if (strcmp(section->keys[i].key, key_name) == 0) {
            return &section->keys[i];
        }
    }

    return NULL;
}

/* Parse section header [section.name] */
static int parse_section_header(toml_parser_state_t *state, char *section_name) {
    size_t name_pos = 0;
    
    if (!match_char(state, '[')) {
        set_parser_error(state, "Expected '[' at start of section");
        return -1;
    }
    
    skip_whitespace(state);
    
    /* Parse section name. Examine a delimiter before declaring overflow: at
     * exactly 63 bytes, a space/tab is legal trailing whitespace, whereas a
     * 64th name byte is a real overflow (AR-07 L31). */
    while (!is_at_end(state) && current_char(state) != ']') {
        char c = current_char(state);

        /* Stop at trailing whitespace and let the skip_whitespace + ']' below
         * consume it (AR-06 F71): leading whitespace after '[' was already
         * accepted by the skip above, but a trailing space (`[settings ]`) hit
         * the isalnum check and was a fatal error — an asymmetry. Interior
         * whitespace (`[set tings]`) still fails at the ']' match. */
        if (c == ' ' || c == '\t') {
            break;
        }
        if (name_pos >= TOML_MAX_SECTION_LEN - 1) {
            set_parser_error(state, "Section name too long");
            return -1;
        }
        if (c != '.' &&
            !ascii_section_segment_byte_is_valid((unsigned char)c)) {
            set_parser_error(
                state,
                "Invalid section name: expected dot-separated ASCII bare-key segments");
            return -1;
        }
        section_name[name_pos++] = advance_char(state);
    }
    
    section_name[name_pos] = '\0';

    if (!section_name_is_valid(section_name)) {
        set_parser_error(
            state,
            "Invalid section name: segments must be nonempty ASCII bare keys");
        return -1;
    }

    skip_whitespace(state);

    if (!match_char(state, ']')) {
        set_parser_error(state, "Expected ']' at end of section");
        return -1;
    }
    
    return 0;
}

/* Parse key-value pair */
static int parse_key_value_pair(toml_parser_state_t *state, toml_keyvalue_t *kv) {
    size_t key_pos = 0;
    
    memset(kv, 0, sizeof(toml_keyvalue_t));
    
    /* Parse key name */
    while (!is_at_end(state) && current_char(state) != '=' && 
           key_pos < TOML_MAX_KEY_LEN - 1) {
        char c = current_char(state);
        
        if (ascii_key_continuation_is_valid((unsigned char)c)) {
            kv->key[key_pos++] = advance_char(state);
        } else if (c == ' ' || c == '\t') {
            advance_char(state);
            break;
        } else {
            set_parser_error(state, "Invalid character in key name");
            return -1;
        }
    }
    
    kv->key[key_pos] = '\0';

    /* Stopped because the key buffer filled, with more key text remaining? Too long. */
    if (key_pos >= TOML_MAX_KEY_LEN - 1 && !is_at_end(state) &&
        ascii_key_continuation_is_valid((unsigned char)current_char(state))) {
        set_parser_error(state, "Key name too long");
        return -1;
    }

    if (!key_name_is_valid(kv->key)) {
        set_parser_error(state, "Invalid key name");
        return -1;
    }

    skip_whitespace(state);

    if (!match_char(state, '=')) {
        set_parser_error(state, "Expected '=' after key name");
        return -1;
    }
    
    skip_whitespace(state);
    
    /* Determine value type and parse */
    char c = current_char(state);
    
    if (c == '"') {
        /* String value */
        kv->type = TOML_TYPE_STRING;
        if (parse_string_value(state, kv->value, sizeof(kv->value)) == 0) {
            kv->is_set = true;
            return 0;
        }
        return -1;
    } else if (c == 't' || c == 'f') {
        /* Boolean value */
        kv->type = TOML_TYPE_BOOLEAN;
        bool bool_val;
        if (parse_boolean_value(state, &bool_val) == 0) {
            snprintf(kv->value, sizeof(kv->value), "%s", bool_val ? "true" : "false");
            kv->is_set = true;
            return 0;
        }
        return -1;
    } else if (isdigit(c) || c == '-' || c == '+') {
        /* Integer value */
        kv->type = TOML_TYPE_INTEGER;
        int int_val;
        if (parse_integer_value(state, &int_val) == 0) {
            snprintf(kv->value, sizeof(kv->value), "%d", int_val);
            kv->is_set = true;
            return 0;
        }
        return -1;
    } else {
        set_parser_error(state, "Invalid value type");
        return -1;
    }
}

/* Parse string value "..." */
static int parse_string_value(toml_parser_state_t *state, char *value, size_t value_size) {
    size_t value_pos = 0;
    
    if (!match_char(state, '"')) {
        set_parser_error(state, "Expected '\"' at start of string");
        return -1;
    }
    
    while (!is_at_end(state) && current_char(state) != '"' && 
           value_pos < value_size - 1) {
        char c = current_char(state);

        /* Diagnose raw controls at the byte that violates the grammar. In
         * particular, do not advance a newline to the next line/column before
         * publishing the error location. */
        if ((unsigned char)c < 0x20) {
            set_parser_error(state, "Control character in string value");
            return -1;
        }
        c = advance_char(state);
        
        /* Handle escape sequences */
        if (c == '\\' && !is_at_end(state)) {
            char next = current_char(state);
            if ((unsigned char)next < 0x20) {
                set_parser_error(state, "Control character in string value");
                return -1;
            }
            next = advance_char(state);
            switch (next) {
                case 'n': value[value_pos++] = '\n'; break;
                case 't': value[value_pos++] = '\t'; break;
                case 'r': value[value_pos++] = '\r'; break;
                case '\\': value[value_pos++] = '\\'; break;
                case '"': value[value_pos++] = '"'; break;
                default:
                    set_parser_error(state, "Invalid escape sequence");
                    return -1;
            }
        } else {
            value[value_pos++] = c;
        }
    }

    value[value_pos] = '\0';

    /* Stopped because the value buffer filled, with more content before the
     * closing quote? Too long — error rather than silently truncate. */
    if (value_pos >= value_size - 1 && !is_at_end(state) && current_char(state) != '"') {
        set_parser_error(state, "String value too long");
        return -1;
    }

    if (!match_char(state, '"')) {
        set_parser_error(state, "Expected '\"' at end of string");
        return -1;
    }

    if (!decoded_string_value_is_valid(value, value_pos)) {
        set_parser_error(state,
                         "String value contains invalid control or UTF-8 data");
        return -1;
    }

    return 0;
}

/* Parse boolean value true/false */
static int parse_boolean_value(toml_parser_state_t *state, bool *value) {
    /* Bound the compare by the bytes actually remaining (AR-06 F69): the input
     * is not guaranteed NUL-terminated at input_length, so a bare strncmp of 4
     * or 5 bytes near the end over-read the heap (ASAN-confirmed). A literal
     * that can't fit in the remainder simply isn't a match. */
    size_t remaining = state->input_length - state->position;
    if (remaining >= 4 && strncmp(&state->input[state->position], "true", 4) == 0) {
        state->position += 4;
        state->column_number += 4; /* AR-06 F72: keep column in sync (no newline) */
        *value = true;
        return 0;
    } else if (remaining >= 5 && strncmp(&state->input[state->position], "false", 5) == 0) {
        state->position += 5;
        state->column_number += 5; /* AR-06 F72 */
        *value = false;
        return 0;
    } else {
        set_parser_error(state, "Invalid boolean value");
        return -1;
    }
}

/* Parse integer value */
static int parse_integer_value(toml_parser_state_t *state, int *value) {
    char num_str[32];
    size_t num_pos = 0;
    char *endptr;
    long parsed_value;
    
    /* Handle optional sign */
    char c = current_char(state);
    if (c == '+' || c == '-') {
        num_str[num_pos++] = advance_char(state);
    }
    size_t digit_start = num_pos;
    
    /* Parse digits */
    while (!is_at_end(state) &&
           isdigit((unsigned char)current_char(state)) &&
           num_pos < sizeof(num_str) - 1) {
        num_str[num_pos++] = advance_char(state);
    }
    
    num_str[num_pos] = '\0';
    
    if (num_pos == 0 || (num_pos == 1 && (num_str[0] == '+' || num_str[0] == '-'))) {
        set_parser_error(state, "Invalid integer format");
        return -1;
    }

    /* TOML decimal integers may be zero, but a multi-digit magnitude may not
     * start with zero. Reject before strtol canonicalizes malformed `01` into
     * an apparently valid `1` that the writer would then preserve (L32). */
    if (num_pos - digit_start > 1 && num_str[digit_start] == '0') {
        set_parser_error(state, "Leading zeros are not allowed in integers");
        return -1;
    }
    
    errno = 0;
    parsed_value = strtol(num_str, &endptr, 10);
    
    if (errno != 0 || *endptr != '\0') {
        set_parser_error(state, "Integer parsing error");
        return -1;
    }
    
    if (parsed_value < INT_MIN || parsed_value > INT_MAX) {
        set_parser_error(state, "Integer out of range");
        return -1;
    }
    
    *value = (int)parsed_value;
    return 0;
}

/* Parsing helper functions */

static void skip_whitespace(toml_parser_state_t *state) {
    while (!is_at_end(state)) {
        char c = current_char(state);
        if (c == ' ' || c == '\t') {
            advance_char(state);
        } else {
            break;
        }
    }
}

/* Consume one physical TOML line ending. LF and CRLF both advance exactly one
 * line; a bare CR is rejected without moving past the offending byte so the
 * reported line and column remain precise. Returns 1 when an ending was
 * consumed, 0 when the current byte is not an ending, and -1 on bare CR. */
static int consume_line_ending(toml_parser_state_t *state) {
    if (is_at_end(state)) return 0;

    if (current_char(state) == '\n') {
        state->position++;
        state->line_number++;
        state->column_number = 1;
        return 1;
    }

    if (current_char(state) == '\r') {
        size_t remaining = state->input_length - state->position;
        if (remaining < 2 || state->input[state->position + 1] != '\n') {
            set_parser_error(
                state,
                "Bare carriage return; TOML line endings must be LF or CRLF");
            return -1;
        }
        state->position += 2;
        state->line_number++;
        state->column_number = 1;
        return 1;
    }

    return 0;
}

/* AR-06 F70: after a value or a section header, the rest of the physical line
 * must be nothing but optional trailing whitespace and an optional comment.
 * Without this the tokenizer silently accepted multiple pairs on one line
 * (`a = 1 b = 2`) and content after `]` (`[accounts.1] name = "x"`), giving a
 * malformed config a meaning the writer never produces. Returns 0 when the line
 * ends cleanly, -1 (with a parser error set) when trailing content remains. */
static int require_line_end(toml_parser_state_t *state) {
    int line_ending;

    skip_whitespace(state); /* trailing spaces/tabs only (not newlines) */
    if (is_at_end(state)) {
        return 0;
    }

    if (current_char(state) == '#') {
        return skip_comment(state);
    }

    line_ending = consume_line_ending(state);
    if (line_ending > 0) {
        return 0;
    }
    if (line_ending < 0) return -1;

    set_parser_error(state,
                     "Unexpected content after value/section header on the "
                     "same line (one key/value or section header per line)");
    return -1;
}

static int skip_comment(toml_parser_state_t *state) {
    while (!is_at_end(state) && current_char(state) != '\n' &&
           current_char(state) != '\r') {
        advance_char(state);
    }
    if (is_at_end(state)) return 0;

    return consume_line_ending(state) < 0 ? -1 : 0;
}

static bool is_at_end(const toml_parser_state_t *state) {
    return state->position >= state->input_length;
}

static char current_char(const toml_parser_state_t *state) {
    if (is_at_end(state)) return '\0';
    return state->input[state->position];
}

static char advance_char(toml_parser_state_t *state) {
    if (is_at_end(state)) return '\0';
    
    char c = state->input[state->position++];
    
    if (c == '\n') {
        state->line_number++;
        state->column_number = 1;
    } else {
        state->column_number++;
    }
    
    return c;
}

static bool match_char(toml_parser_state_t *state, char expected) {
    if (is_at_end(state) || current_char(state) != expected) {
        return false;
    }
    advance_char(state);
    return true;
}

static void set_parser_error(toml_parser_state_t *state, const char *message) {
    state->has_error = true;
    safe_strncpy(state->error_message, message, sizeof(state->error_message));
}

/* Get all sections from document */
int toml_get_sections(const toml_document_t *doc, char sections[][TOML_MAX_SECTION_LEN],
                      size_t max_sections, size_t *section_count) {
    if (!doc || !sections || !section_count) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_sections");
        return -1;
    }

    *section_count = 0;
    if (toml_validate_model_invariants(doc, false) != 0) {
        return -1;
    }

    for (size_t i = 0; i < doc->section_count && *section_count < max_sections; i++) {
        safe_strncpy(sections[*section_count], doc->sections[i].name, TOML_MAX_SECTION_LEN);
        (*section_count)++;
    }
    
    return 0;
}

/* Set string value in document */
int toml_set_string(toml_document_t *doc, const char *section_name, 
                    const char *key_name, const char *value) {
    toml_section_t *section;
    toml_keyvalue_t *kv;
    size_t value_length;
    
    if (!doc || !section_name || !key_name || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_set_string");
        return -1;
    }

    if (!section_name_is_valid(section_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "Invalid TOML section name (1-%d ASCII bytes in nonempty "
                  "dot-separated bare-key segments): %s",
                  TOML_MAX_SECTION_LEN - 1, section_name);
        return -1;
    }

    /* Bound-check BEFORE mutating the document (AR-03 M5, writer half).
     * safe_strncpy fails without writing on an oversized source, and this
     * function used to ignore that: a >= TOML_MAX_VALUE_LEN value left the
     * key freshly created with value="" and is_set=true, so config_save
     * wrote `ssh_key = ""` to disk and exited 0 — the account's key silently
     * erased by the very save that claimed success. Checking up front also
     * means a failed set leaves no half-built key behind. */
    if (!key_name_is_valid(key_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "Invalid TOML key name for %s (1-%d ASCII bytes; first "
                  "[A-Za-z_], remaining [A-Za-z0-9_])",
                  section_name, TOML_MAX_KEY_LEN - 1);
        return -1;
    }
    value_length = strnlen(value, TOML_MAX_VALUE_LEN);
    if (value_length == TOML_MAX_VALUE_LEN) {
        set_error(ERR_CONFIG_INVALID,
                  "Value for %s.%s is too long (at least %d bytes, max %d); "
                  "refusing to store it truncated or empty",
                  section_name, key_name, TOML_MAX_VALUE_LEN,
                  TOML_MAX_VALUE_LEN - 1);
        return -1;
    }
    if (!decoded_string_value_is_valid(value, value_length)) {
        set_error(ERR_CONFIG_INVALID,
                  "Value for %s.%s contains an unsupported control byte or "
                  "malformed/unsafe UTF-8",
                  section_name, key_name);
        return -1;
    }

    if (toml_validate_model_invariants(doc, false) != 0) {
        return -1;
    }
    if (!toml_table_namespace_is_available(doc, section_name) ||
        !toml_scalar_namespace_is_available(doc, section_name, key_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML namespace for %s.%s collides with an existing scalar or table",
                  section_name, key_name);
        return -1;
    }

    /* Find or create section */
    section = find_or_create_section(doc, section_name);
    if (!section) {
        return -1;
    }

    /* Find or create key */
    kv = find_key(section, key_name);
    if (!kv) {
        /* Create new key-value pair */
        if (section->key_count >= TOML_MAX_KEYS_PER_SECTION) {
            set_error(ERR_CONFIG_INVALID, "Too many key-value pairs in section: %s", section_name);
            return -1;
        }

        kv = &section->keys[section->key_count];
        /* Cannot fail after the length check above, but stay fail-closed:
         * the copy runs before key_count++ so a failure leaves no ghost key. */
        if (safe_strncpy(kv->key, key_name, sizeof(kv->key)) != 0) {
            return -1;
        }
        section->key_count++;
    }

    /* Set string value; propagate the copy result instead of assuming it. */
    if (safe_strncpy(kv->value, value, sizeof(kv->value)) != 0) {
        return -1;
    }
    kv->type = TOML_TYPE_STRING;
    kv->is_set = true;
    doc->is_valid = false;

    return 0;
}

/* Set boolean value in document */
int toml_set_boolean(toml_document_t *doc, const char *section_name, 
                     const char *key_name, bool value) {
    toml_section_t *section;
    toml_keyvalue_t *kv;
    
    if (!doc || !section_name || !key_name) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_set_boolean");
        return -1;
    }

    if (!section_name_is_valid(section_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "Invalid TOML section name (1-%d ASCII bytes in nonempty "
                  "dot-separated bare-key segments): %s",
                  TOML_MAX_SECTION_LEN - 1, section_name);
        return -1;
    }

    /* Validate the full parser grammar before section lookup/creation. This
     * also retains the old oversized-name guard: safe_strncpy fails without
     * writing, which otherwise left a newly published ghost section behind. */
    if (!key_name_is_valid(key_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "Invalid TOML key name for %s (1-%d ASCII bytes; first "
                  "[A-Za-z_], remaining [A-Za-z0-9_])",
                  section_name, TOML_MAX_KEY_LEN - 1);
        return -1;
    }

    if (toml_validate_model_invariants(doc, false) != 0) {
        return -1;
    }
    if (!toml_table_namespace_is_available(doc, section_name) ||
        !toml_scalar_namespace_is_available(doc, section_name, key_name)) {
        set_error(ERR_CONFIG_INVALID,
                  "TOML namespace for %s.%s collides with an existing scalar or table",
                  section_name, key_name);
        return -1;
    }

    /* Find or create section */
    section = find_or_create_section(doc, section_name);
    if (!section) {
        return -1;
    }

    /* Find or create key */
    kv = find_key(section, key_name);
    if (!kv) {
        /* Create new key-value pair */
        if (section->key_count >= TOML_MAX_KEYS_PER_SECTION) {
            set_error(ERR_CONFIG_INVALID, "Too many key-value pairs in section: %s", section_name);
            return -1;
        }

        kv = &section->keys[section->key_count];
        if (safe_strncpy(kv->key, key_name, sizeof(kv->key)) != 0) {
            return -1; /* copy precedes key_count++: no ghost key on failure */
        }
        section->key_count++;
    }

    /* Set boolean value ("true"/"false" always fits; propagate anyway). */
    if (safe_strncpy(kv->value, value ? "true" : "false", sizeof(kv->value)) != 0) {
        return -1;
    }
    kv->type = TOML_TYPE_BOOLEAN;
    kv->is_set = true;
    doc->is_valid = false;

    return 0;
}

/* Emit a TOML basic-string value, escaping the bytes that parse_string_value
 * treats specially on read. Without this a value containing '"' or '\' round-
 * trips to a file that the parser then rejects (unbalanced quote / bad escape),
 * bricking the config until it is hand-edited. Mirror the read-side escape
 * table exactly. Returns <0 on write error. */
static int write_escaped_string_value(FILE *file, const char *key, const char *value) {
    if (fprintf(file, "%s = \"", key) < 0) return -1;
    for (const char *p = value; *p; p++) {
        int rc;
        switch (*p) {
            case '\\': rc = fputs("\\\\", file); break;
            case '"':  rc = fputs("\\\"", file); break;
            case '\n': rc = fputs("\\n", file); break;
            case '\r': rc = fputs("\\r", file); break;
            case '\t': rc = fputs("\\t", file); break;
            default:   rc = fputc((unsigned char)*p, file);
        }
        if (rc < 0) return -1;
    }
    if (fputs("\"\n", file) < 0) return -1;
    return 0;
}

/* Serialize, size-check, and durably flush one already-open stream. Keeping
 * this stream-only work separate from publication lets config.c own exactly one
 * final rename and directory fsync while toml_write_file retains its standalone
 * atomic API. */
static int toml_serialize_stream(const toml_document_t *doc, FILE *file,
                                 const char **failure_context,
                                 int *saved_errno) {
    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];

        /* Root keys precede every named table and have no table header. */
        if (section->name[0] != '\0') {
            if (fprintf(file, "[%s]\n", section->name) < 0) {
                *failure_context = "Failed to write TOML section header";
                *saved_errno = errno ? errno : EIO;
                return -1;
            }
        }

        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            if (!kv->is_set) continue;

            switch (kv->type) {
                case TOML_TYPE_STRING:
                    if (write_escaped_string_value(file, kv->key,
                                                   kv->value) < 0) {
                        *failure_context = "Failed to write TOML string value";
                        *saved_errno = errno ? errno : EIO;
                        return -1;
                    }
                    break;
                case TOML_TYPE_INTEGER:
                case TOML_TYPE_BOOLEAN:
                    if (fprintf(file, "%s = %s\n", kv->key, kv->value) < 0) {
                        *failure_context = "Failed to write TOML value";
                        *saved_errno = errno ? errno : EIO;
                        return -1;
                    }
                    break;
                case TOML_TYPE_INVALID:
                default:
                    break;
            }
        }

        if (i < doc->section_count - 1 && fputc('\n', file) == EOF) {
            *failure_context = "Failed to write TOML section separator";
            *saved_errno = errno ? errno : EIO;
            return -1;
        }
    }

    /* stdio may defer EFBIG/ENOSPC/EIO until flush or close. The parser accepts
     * exactly TOML_MAX_FILE_SIZE bytes, so measure the escaped output itself. */
    if (fflush(file) != 0) {
        *failure_context = "Failed to flush temporary TOML file";
        *saved_errno = errno ? errno : EIO;
        return -1;
    }
    struct stat serialized;
    if (fstat(fileno(file), &serialized) != 0) {
        *failure_context = "Failed to measure serialized TOML file";
        *saved_errno = errno ? errno : EIO;
        return -1;
    }
    if (serialized.st_size > (off_t)TOML_MAX_FILE_SIZE) {
        *failure_context = "Serialized TOML file exceeds parser size limit";
        *saved_errno = EFBIG;
        return -1;
    }
    if (fsync(fileno(file)) != 0) {
        *failure_context = "Failed to sync temporary TOML file";
        *saved_errno = errno ? errno : EIO;
        return -1;
    }
    return 0;
}

int toml_write_fd(const toml_document_t *doc, int fd) {
    const char *failure_context = NULL;
    struct stat before;
    struct stat after;
    FILE *file = NULL;
    int stream_fd = -1;
    int saved_errno = 0;
    int result = -1;

    if (!doc || fd < 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_write_fd");
        return -1;
    }
    if (toml_validate_model_invariants(doc, true) != 0) {
        return -1;
    }
    if (fstat(fd, &before) != 0) {
        saved_errno = errno ? errno : EIO;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot identify TOML output descriptor");
        errno = saved_errno;
        return -1;
    }
    errno = 0;
    off_t offset = lseek(fd, 0, SEEK_CUR);
    if (offset < 0) {
        saved_errno = errno ? errno : EIO;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot inspect TOML output descriptor offset");
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
        before.st_nlink != 1 ||
        (before.st_mode & 07777) != (S_IRUSR | S_IWUSR) ||
        before.st_size != 0 || offset != 0) {
        saved_errno = EINVAL;
        errno = saved_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "TOML descriptor is not a fresh private file");
        errno = saved_errno;
        return -1;
    }

    stream_fd = dup(fd);
    if (stream_fd < 0 || fcntl(stream_fd, F_SETFD, FD_CLOEXEC) != 0) {
        saved_errno = errno ? errno : EIO;
        failure_context = "Failed to duplicate TOML output descriptor";
        goto cleanup;
    }
    file = fdopen(stream_fd, "w");
    if (!file) {
        saved_errno = errno ? errno : EIO;
        failure_context = "Failed to open TOML output stream";
        goto cleanup;
    }
    stream_fd = -1;

    if (toml_serialize_stream(doc, file, &failure_context, &saved_errno) != 0) {
        goto cleanup;
    }
    if (fclose(file) != 0) {
        file = NULL;
        saved_errno = errno ? errno : EIO;
        failure_context = "Failed to close TOML output stream";
        goto cleanup;
    }
    file = NULL;

    if (fstat(fd, &after) != 0) {
        saved_errno = errno;
        failure_context = "Cannot revalidate TOML output descriptor";
        goto cleanup;
    }
    {
        bool forced_mismatch =
            g_metadata_test_hook &&
            g_metadata_test_hook(TOML_METADATA_TEST_FD_REVALIDATE);
        errno = 0;
        if (forced_mismatch || !toml_same_file(&before, &after) ||
            !toml_temp_identity_is_private(&after) || after.st_size < 0 ||
            after.st_size > (off_t)TOML_MAX_FILE_SIZE) {
            saved_errno = ESTALE;
            failure_context =
                "TOML output descriptor changed during serialization";
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    if (file) {
        if (fclose(file) != 0 && !failure_context) {
            saved_errno = errno ? errno : EIO;
            failure_context = "Failed to close TOML output stream";
        }
    } else if (stream_fd >= 0) {
        (void)close(stream_fd);
    }
    if (failure_context) {
        errno = saved_errno ? saved_errno : EIO;
        set_system_error(ERR_CONFIG_WRITE_FAILED, "%s", failure_context);
        result = -1;
    }
    return result;
}

static bool toml_same_file(const struct stat *left, const struct stat *right) {
    return left && right && left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino;
}

static bool toml_named_directory_matches(const char *dir_path,
                                         const struct stat *pinned) {
    struct stat named;
    if (stat(dir_path, &named) != 0) return false;
    if (!toml_same_file(&named, pinned)) {
        errno = ESTALE;
        return false;
    }
    return true;
}

static bool toml_temp_identity_is_private(const struct stat *identity) {
    return identity && S_ISREG(identity->st_mode) &&
           identity->st_uid == getuid() && identity->st_nlink == 1 &&
           (identity->st_mode & 07777) == (S_IRUSR | S_IWUSR);
}

static bool toml_temp_matches_created(const struct stat *created,
                                      const struct stat *current) {
    return toml_same_file(created, current) &&
           toml_temp_identity_is_private(current);
}

/* mkstemp() cannot create relative to a pinned directory descriptor. Generate
 * collision-resistant names and let O_CREAT|O_EXCL provide the authoritative
 * uniqueness/symlink guarantee inside the exact opened parent instead. */
static int toml_create_temp_at(int dir_fd, char *temp_name,
                               size_t temp_name_size) {
    static const char random_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char suffix[17];

    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        if (generate_random_string(suffix, sizeof(suffix), random_chars) != 0) {
            if (errno == 0) errno = EIO;
            return -1;
        }
        int written = snprintf(temp_name, temp_name_size,
                               ".gitswitch-toml.%s.tmp", suffix);
        if (written < 0 || (size_t)written >= temp_name_size) {
            errno = ENAMETOOLONG;
            return -1;
        }

        int fd = openat(dir_fd, temp_name,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        S_IRUSR | S_IWUSR);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

/* Write document to a fresh same-directory inode and publish only after every
 * serialization and payload durability boundary succeeds (AR-07 L33). The
 * destination is never opened for writing, so a short write cannot truncate a
 * previously valid configuration. */
int toml_write_file(const toml_document_t *doc, const char *file_path) {
    const char *failure_context = NULL;
    const char *slash;
    const char *target_name;
    char *dir_path = NULL;
    char *temp_path = NULL;
    char temp_name[128] = "";
    FILE *file = NULL;
    size_t dir_length;
    struct stat pinned_dir;
    struct stat temp_identity;
    struct stat current_temp;
    struct stat installed_temp;
    int dir_fd = -1;
    int temp_fd = -1;
    int identity_fd = -1;
    int saved_errno = 0;
    int result = -1;
    bool temp_registered = false;
    bool temp_created = false;
    bool have_temp_identity = false;

    if (!doc || !file_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_write_file");
        return -1;
    }
    if (toml_validate_config_file_path(file_path, "destination") != 0) {
        return -1;
    }
    if (toml_validate_model_invariants(doc, true) != 0) {
        return -1;
    }

    slash = strrchr(file_path, '/');
    target_name = slash ? slash + 1 : file_path;
    if (!slash) {
        dir_length = 1; /* "." */
    } else if (slash == file_path) {
        dir_length = 1; /* "/" */
    } else {
        dir_length = (size_t)(slash - file_path);
    }

    dir_path = safe_malloc(dir_length + 1);
    if (!dir_path) goto cleanup;

    if (!slash) {
        memcpy(dir_path, ".", 2);
    } else {
        memcpy(dir_path, file_path, dir_length);
        dir_path[dir_length] = '\0';
    }
    /* Open the parent before publishing anything. The descriptor remains open
     * through rename so the exact directory can be fsynced before success is
     * reported. */
    dir_fd = open(dir_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (dir_fd < 0) {
        failure_context = "Failed to open TOML destination directory";
        saved_errno = errno;
        goto cleanup;
    }
    if (fstat(dir_fd, &pinned_dir) != 0) {
        failure_context = "Failed to pin TOML destination directory";
        saved_errno = errno;
        goto cleanup;
    }
    if (!S_ISDIR(pinned_dir.st_mode)) {
        failure_context = "TOML destination parent is not a directory";
        saved_errno = ENOTDIR;
        goto cleanup;
    }

    temp_fd = toml_create_temp_at(dir_fd, temp_name, sizeof(temp_name));
    if (temp_fd < 0) {
        failure_context = "Failed to create temporary TOML file";
        saved_errno = errno;
        goto cleanup;
    }
    temp_created = true;

    /* Capture the inode immediately, then force and re-check the complete
     * private-file contract before exposing a test/signal interleaving point.
     * The identity is retained for both pre-rename sealing and safe cleanup. */
    if (fstat(temp_fd, &temp_identity) != 0) {
        failure_context = "Failed to identify temporary TOML file";
        saved_errno = errno;
        goto cleanup;
    }
    have_temp_identity = true;
    if (!S_ISREG(temp_identity.st_mode) ||
        temp_identity.st_uid != getuid() || temp_identity.st_nlink != 1) {
        failure_context = "Temporary TOML file has an unsafe identity";
        saved_errno = EPERM;
        goto cleanup;
    }
    if (fchmod(temp_fd, S_IRUSR | S_IWUSR) != 0) {
        failure_context = "Failed to secure temporary TOML file";
        saved_errno = errno;
        goto cleanup;
    }
    errno = 0;
    if (fstat(temp_fd, &current_temp) != 0 ||
        !toml_temp_matches_created(&temp_identity, &current_temp)) {
        failure_context = "Temporary TOML file failed its creation seal";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }

    size_t temp_name_length = strlen(temp_name);
    size_t separator_length = strcmp(dir_path, "/") == 0 ? 0 : 1;
    if (dir_length > SIZE_MAX - separator_length - temp_name_length - 1) {
        set_error(ERR_INVALID_PATH, "TOML temporary path is too long");
        goto cleanup;
    }
    size_t temp_path_size = dir_length + separator_length + temp_name_length + 1;
    temp_path = safe_malloc(temp_path_size);
    if (!temp_path) goto cleanup;
    int temp_path_written = snprintf(temp_path, temp_path_size, "%s%s%s",
                                     dir_path, separator_length ? "/" : "",
                                     temp_name);
    if (temp_path_written < 0 || (size_t)temp_path_written >= temp_path_size) {
        set_error(ERR_INVALID_PATH, "Could not construct TOML temporary path");
        goto cleanup;
    }
    if (signals_scratch_register(temp_path) != 0) {
        failure_context = "Failed to register temporary TOML file for signal cleanup";
        saved_errno = ENOSPC;
        goto cleanup;
    }
    temp_registered = true;

    if (g_writer_test_hook) {
        g_writer_test_hook(TOML_WRITER_TEST_AFTER_TEMP_CREATE,
                           dir_path, temp_name);
    }
    if (!toml_named_directory_matches(dir_path, &pinned_dir)) {
        failure_context = "TOML destination directory changed during write";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }

    file = fdopen(temp_fd, "w");
    if (!file) {
        failure_context = "Failed to open temporary TOML stream";
        saved_errno = errno;
        goto cleanup;
    }
    temp_fd = -1; /* owned by file */

    if (toml_serialize_stream(doc, file, &failure_context, &saved_errno) != 0) {
        goto cleanup;
    }

    /* Refuse to publish if the pathname stopped selecting the pinned parent,
     * then perform both source and destination lookup relative to that exact
     * descriptor. This prevents a directory rename/replacement from making us
     * publish in one directory and fsync/clean another. */
    if (!toml_named_directory_matches(dir_path, &pinned_dir)) {
        failure_context = "TOML destination directory changed before commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }
    identity_fd = dup(fileno(file));
    if (identity_fd < 0 ||
        fcntl(identity_fd, F_SETFD, FD_CLOEXEC) != 0) {
        failure_context = "Failed to pin temporary TOML file for commit";
        saved_errno = errno;
        goto cleanup;
    }
    errno = 0;
    if (fstat(identity_fd, &current_temp) != 0 ||
        fstatat(dir_fd, temp_name, &installed_temp,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !toml_temp_matches_created(&temp_identity, &current_temp) ||
        !toml_temp_matches_created(&temp_identity, &installed_temp)) {
        failure_context = "Temporary TOML file changed before atomic commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }
    if (fclose(file) != 0) {
        file = NULL; /* fclose consumes the stream even when it reports EOF */
        failure_context = "Failed to close temporary TOML file";
        saved_errno = errno;
        goto cleanup;
    }
    file = NULL;

    /* Re-check after fclose and immediately before rename: a same-uid peer may
     * unlink/recreate the random name at any point during serialization. */
    if (!toml_named_directory_matches(dir_path, &pinned_dir)) {
        failure_context = "TOML destination directory changed before commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }
    errno = 0;
    if (fstat(identity_fd, &current_temp) != 0 ||
        fstatat(dir_fd, temp_name, &installed_temp,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !toml_temp_matches_created(&temp_identity, &current_temp) ||
        !toml_temp_matches_created(&temp_identity, &installed_temp)) {
        failure_context = "Temporary TOML file changed before atomic commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }
    if (renameat(dir_fd, temp_name, dir_fd, target_name) != 0) {
        failure_context = "Failed to atomically replace TOML destination";
        saved_errno = errno;
        goto cleanup;
    }
    temp_created = false;
    signals_scratch_unregister(temp_path);
    temp_registered = false;

    errno = 0;
    if (fstat(identity_fd, &current_temp) != 0 ||
        fstatat(dir_fd, target_name, &installed_temp,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !toml_temp_matches_created(&temp_identity, &current_temp) ||
        !toml_temp_matches_created(&temp_identity, &installed_temp)) {
        failure_context = "Installed TOML file changed during atomic commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }

    if (close(identity_fd) != 0) {
        identity_fd = -1;
        failure_context = "Failed to close installed TOML identity handle";
        saved_errno = errno;
        goto cleanup;
    }
    identity_fd = -1;

    if (!toml_named_directory_matches(dir_path, &pinned_dir)) {
        failure_context = "TOML destination directory changed during commit";
        saved_errno = errno ? errno : ESTALE;
        goto cleanup;
    }

    if (fsync(dir_fd) != 0) {
        failure_context = "Failed to sync TOML destination directory";
        saved_errno = errno;
        goto cleanup;
    }

    result = 0;

cleanup:
    if (file) {
        if (fclose(file) != 0 && !failure_context) {
            failure_context = "Failed to close temporary TOML file";
            saved_errno = errno;
        }
    } else if (temp_fd >= 0) {
        if (close(temp_fd) != 0 && !failure_context) {
            failure_context = "Failed to close temporary TOML file";
            saved_errno = errno;
        }
    }
    if (identity_fd >= 0 && close(identity_fd) != 0 && !failure_context) {
        failure_context = "Failed to close temporary TOML identity handle";
        saved_errno = errno;
    }
    if (temp_created && dir_fd >= 0 && temp_name[0] != '\0') {
        bool cleanup_resolved = false;
        bool pathname_substituted = false;
        int cleanup_errno = 0;

        if (fstatat(dir_fd, temp_name, &current_temp,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            cleanup_errno = errno;
            cleanup_resolved = cleanup_errno == ENOENT;
        } else if (!have_temp_identity) {
            /* Without the created fd snapshot, neither unlink nor unregister
             * is safe: inspection cannot identify whose pathname this is. */
            cleanup_errno = EIO;
        } else if (!toml_same_file(&temp_identity, &current_temp)) {
            /* The pathname provably names somebody else's inode. Do not unlink
             * it, and drop our path-only scratch slot so a later signal cleanup
             * cannot become an attacker-file deletion primitive. */
            pathname_substituted = true;
            cleanup_resolved = true;
        } else if (unlinkat(dir_fd, temp_name, 0) == 0) {
            cleanup_resolved = true;
        } else {
            cleanup_errno = errno;
            cleanup_resolved = cleanup_errno == ENOENT;
        }

        if (cleanup_resolved) {
            temp_created = false;
            if (temp_registered) {
                signals_scratch_unregister(temp_path);
                temp_registered = false;
            }
            if (pathname_substituted) {
                log_warning("Temporary TOML pathname was substituted; refusing "
                            "to unlink replacement %s",
                            temp_path ? temp_path : temp_name);
            }
        } else {
            if (!failure_context) {
                failure_context = "Failed to safely remove temporary TOML file";
                saved_errno = cleanup_errno ? cleanup_errno : EIO;
            } else {
                log_warning("Temporary TOML cleanup refused/failed for %s: "
                            "%s (errno=%d); retaining signal-cleanup registration",
                            temp_path ? temp_path : temp_name,
                            strerror(cleanup_errno ? cleanup_errno : EIO),
                            cleanup_errno ? cleanup_errno : EIO);
            }
            /* Retain the slot only when inspection was indeterminate or
             * unlinking the exact created inode failed. */
        }
    }
    if (dir_fd >= 0) (void)close(dir_fd);

    if (failure_context) {
        errno = saved_errno ? saved_errno : EIO;
        set_system_error(ERR_CONFIG_WRITE_FAILED, "%s: %s",
                         failure_context, file_path);
        result = -1;
    }
    free(temp_path);
    free(dir_path);
    return result;
}

/* Cleanup TOML document */
void toml_cleanup_document(toml_document_t *doc) {
    if (!doc) return;
    
    /* Clear sensitive data */
    secure_zero_memory(doc, sizeof(toml_document_t));
}
