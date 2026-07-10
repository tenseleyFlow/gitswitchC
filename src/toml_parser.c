/* Minimal, security-focused TOML parser implementation
 * Built specifically for gitswitch-c with comprehensive input validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "toml_parser.h"
#include "error.h"
#include "utils.h"

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
static void skip_comment(toml_parser_state_t *state);
static bool is_at_end(const toml_parser_state_t *state);
static char current_char(const toml_parser_state_t *state);
static char advance_char(toml_parser_state_t *state);
static bool match_char(toml_parser_state_t *state, char expected);
static void set_parser_error(toml_parser_state_t *state, const char *message);
static toml_section_t *find_section(toml_document_t *doc, const char *section_name);
static toml_section_t *find_or_create_section(toml_document_t *doc, const char *section_name);
static toml_keyvalue_t *find_key(toml_section_t *section, const char *key_name);

/* Initialize TOML document structure */
void toml_init_document(toml_document_t *doc) {
    if (!doc) return;
    
    memset(doc, 0, sizeof(toml_document_t));
    doc->is_valid = false;
    doc->section_count = 0;
}

/* Parse TOML from file with comprehensive security validation */
int toml_parse_file(const char *file_path, toml_document_t *doc) {
    FILE *file;
    struct stat file_stat;
    char *buffer = NULL;
    size_t file_size;
    size_t bytes_read;
    int result = -1;
    
    if (!file_path || !doc) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to toml_parse_file");
        return -1;
    }
    
    /* Security: Validate file path */
    if (!toml_validate_file_path(file_path)) {
        set_error(ERR_CONFIG_INVALID, "Invalid file path: %s", file_path);
        return -1;
    }
    
    /* Get file statistics for security checks */
    if (stat(file_path, &file_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot access config file: %s", file_path);
        return -1;
    }
    
    /* Security: Check file size limit */
    if (file_stat.st_size > TOML_MAX_FILE_SIZE) {
        /* Cast to long: off_t is long long on macOS/clang (Wformat error under
         * -Werror) but long on Linux; the value is bounded small here (just
         * over the max), so no truncation. Mirrors config.c's size check. */
        set_error(ERR_CONFIG_INVALID, "Configuration file too large: %ld bytes (max: %d)",
                  (long)file_stat.st_size, TOML_MAX_FILE_SIZE);
        return -1;
    }
    
    /* Security: Check file permissions (should not be world-readable) */
    if (file_stat.st_mode & (S_IRGRP | S_IROTH)) {
        set_error(ERR_PERMISSION_DENIED, "Configuration file has unsafe permissions: %o", 
                  file_stat.st_mode & 0777);
        return -1;
    }
    
    file_size = (size_t)file_stat.st_size;
    
    /* Open file for reading */
    file = fopen(file_path, "r");
    if (!file) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Failed to open config file: %s", file_path);
        return -1;
    }
    
    /* Allocate buffer for file content */
    buffer = safe_malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return -1;
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
    
    /* Security: Validate character set */
    if (!toml_validate_safe_characters(buffer, file_size)) {
        set_error(ERR_CONFIG_INVALID, "Configuration file contains unsafe characters");
        goto cleanup;
    }
    
    /* Security: Check for injection patterns */
    if (!toml_check_injection_patterns(buffer, file_size)) {
        set_error(ERR_CONFIG_INVALID, "Configuration file contains potentially malicious patterns");
        goto cleanup;
    }
    
    /* Store file path in document */
    safe_strncpy(doc->file_path, file_path, sizeof(doc->file_path));
    
    /* Parse the TOML content */
    result = toml_parse_string(buffer, file_size, doc);
    
cleanup:
    if (file) fclose(file);
    if (buffer) {
        secure_zero_memory(buffer, file_size + 1);
        free(buffer);
    }
    
    return result;
}

/* Parse TOML from string buffer */
int toml_parse_string(const char *toml_string, size_t length, toml_document_t *doc) {
    toml_parser_state_t state;
    char section_name[TOML_MAX_SECTION_LEN] = ""; /* Default to root section */
    toml_section_t *current_section = NULL;
    
    if (!toml_string || !doc) {
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
    
    /* Initialize parser state */
    memset(&state, 0, sizeof(state));
    state.input = toml_string;
    state.input_length = length;
    state.position = 0;
    state.line_number = 1;
    state.column_number = 1;
    state.has_error = false;
    
    /* Initialize document */
    toml_init_document(doc);
    
    /* Parse line by line */
    while (!is_at_end(&state) && !state.has_error) {
        skip_whitespace(&state);
        
        if (is_at_end(&state)) {
            break;
        }
        
        char c = current_char(&state);
        
        /* Skip comments */
        if (c == '#') {
            skip_comment(&state);
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
                current_section = find_or_create_section(doc, section_name);
                if (!current_section) {
                    set_parser_error(&state, "Failed to create section");
                    break;
                }
            }
            continue;
        }
        
        /* Parse key-value pair */
        if (isalpha(c) || c == '_') {
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
                current_section->key_count++;
            }
            continue;
        }
        
        /* Skip empty lines */
        if (c == '\n' || c == '\r') {
            advance_char(&state);
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
    
    doc->is_valid = true;
    log_debug("TOML document parsed successfully: %zu sections", doc->section_count);
    
    return 0;
}

/* Get string value from TOML document */
int toml_get_string(const toml_document_t *doc, const char *section,
                    const char *key, char *value, size_t value_size) {
    const toml_section_t *sec;
    const toml_keyvalue_t *kv;

    if (!doc || !section || !key || !value || value_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_string");
        return -1;
    }

    if (!doc->is_valid) {
        set_error(ERR_CONFIG_INVALID, "TOML document is not valid");
        return -1;
    }

    sec = find_section((toml_document_t *)doc, section);
    if (!sec || !sec->is_set) {
        /* Section not found — or schema-invalidated (is_set cleared, AR-03
         * M5): a skipped-on-load account must read as absent in every field
         * so the loader skips it whole instead of loading a partial account.
         * Return silently, caller handles missing data. */
        return -1;
    }

    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        /* Key not found - return silently, caller handles missing data */
        return -1;
    }

    if (kv->type != TOML_TYPE_STRING) {
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not a string", section, key);
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
    const toml_section_t *sec;
    const toml_keyvalue_t *kv;
    char *endptr;
    long parsed_value;

    if (!doc || !section || !key || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_integer");
        return -1;
    }

    if (!doc->is_valid) {
        set_error(ERR_CONFIG_INVALID, "TOML document is not valid");
        return -1;
    }

    sec = find_section((toml_document_t *)doc, section);
    if (!sec || !sec->is_set) {
        /* Not found, or schema-invalidated (see toml_get_string) - return
         * silently, caller handles missing data */
        return -1;
    }

    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        /* Key not found - return silently, caller handles missing data */
        return -1;
    }

    if (kv->type != TOML_TYPE_INTEGER) {
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not an integer", section, key);
        return -1;
    }
    
    errno = 0;
    parsed_value = strtol(kv->value, &endptr, 10);
    
    if (errno != 0 || *endptr != '\0') {
        set_error(ERR_CONFIG_INVALID, "Invalid integer value: %s", kv->value);
        return -1;
    }
    
    if (parsed_value < INT_MIN || parsed_value > INT_MAX) {
        set_error(ERR_CONFIG_INVALID, "Integer value out of range: %ld", parsed_value);
        return -1;
    }
    
    *value = (int)parsed_value;
    return 0;
}

/* Get boolean value from TOML document */
int toml_get_boolean(const toml_document_t *doc, const char *section,
                     const char *key, bool *value) {
    const toml_section_t *sec;
    const toml_keyvalue_t *kv;

    if (!doc || !section || !key || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_get_boolean");
        return -1;
    }

    if (!doc->is_valid) {
        set_error(ERR_CONFIG_INVALID, "TOML document is not valid");
        return -1;
    }

    sec = find_section((toml_document_t *)doc, section);
    if (!sec || !sec->is_set) {
        /* Not found, or schema-invalidated (see toml_get_string) - return
         * silently, caller handles missing data */
        return -1;
    }

    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        /* Key not found - return silently, caller handles missing data */
        return -1;
    }

    if (kv->type != TOML_TYPE_BOOLEAN) {
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not a boolean", section, key);
        return -1;
    }
    
    *value = (strcmp(kv->value, "true") == 0);
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

            for (size_t j = 0; j < section->key_count; j++) {
                const toml_keyvalue_t *kv = &section->keys[j];
                
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
                
                if (strcmp(kv->key, "ssh_key") == 0) {
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "ssh_key must be a string");
                        return -1;
                    }
                    char sanitized[MAX_PATH_LEN];
                    if (strlen(kv->value) > 0) {
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
                
                if (strcmp(kv->key, "gpg_key") == 0) {
                    if (kv->type != TOML_TYPE_STRING) {
                        set_error(ERR_CONFIG_INVALID, "gpg_key must be a string");
                        return -1;
                    }
                    if (strlen(kv->value) > 0 && !validate_key_id(kv->value)) {
                        set_error(ERR_CONFIG_INVALID, "Invalid GPG key ID: %s", kv->value);
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
            /* Other C0 control or DEL — includes an embedded NUL, which also
             * means a multi-byte sequence can never run past `length` below
             * (the buffer is NUL-terminated at input[length]). */
            log_warning("Unsafe character found at position %zu: 0x%02x", i, c);
            return false;
        }

        uint32_t cp;
        size_t len = utf8_decode((const unsigned char *)input + i, &cp);
        if (len == 0 || !tty_safe_codepoint(cp)) {
            log_warning("Malformed or unsafe UTF-8 sequence at position %zu: 0x%02x", i, c);
            return false;
        }
        i += len;
    }

    return true;
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
            size_t len = utf8_decode((const unsigned char *)input + i, &cp);
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

/* Find or create section */
static toml_section_t *find_or_create_section(toml_document_t *doc, const char *section_name) {
    toml_section_t *section;
    
    if (!doc || !section_name) return NULL;
    
    /* Try to find existing section */
    section = find_section(doc, section_name);
    if (section) return section;
    
    /* Create new section */
    if (doc->section_count >= TOML_MAX_SECTIONS) {
        log_error("Maximum number of sections exceeded: %d", TOML_MAX_SECTIONS);
        return NULL;
    }
    
    section = &doc->sections[doc->section_count];
    memset(section, 0, sizeof(toml_section_t));
    
    safe_strncpy(section->name, section_name, sizeof(section->name));
    section->is_set = true;
    section->key_count = 0;
    
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
    
    /* Parse section name */
    while (!is_at_end(state) && current_char(state) != ']' &&
           name_pos < TOML_MAX_SECTION_LEN - 1) {
        char c = current_char(state);

        /* Stop at trailing whitespace and let the skip_whitespace + ']' below
         * consume it (AR-06 F71): leading whitespace after '[' was already
         * accepted by the skip above, but a trailing space (`[settings ]`) hit
         * the isalnum check and was a fatal error — an asymmetry. Interior
         * whitespace (`[set tings]`) still fails at the ']' match. */
        if (c == ' ' || c == '\t') {
            break;
        }
        c = advance_char(state);

        if (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-') {
            section_name[name_pos++] = c;
        } else {
            set_parser_error(state, "Invalid character in section name");
            return -1;
        }
    }
    
    section_name[name_pos] = '\0';

    /* If we stopped because the buffer filled (not because of ']'), the section
     * name is too long — error rather than silently truncate (which could
     * collide two distinct [accounts.<id>] sections into one). */
    if (name_pos >= TOML_MAX_SECTION_LEN - 1 && !is_at_end(state) && current_char(state) != ']') {
        set_parser_error(state, "Section name too long");
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
        
        if (isalnum(c) || c == '_') {
            kv->key[key_pos++] = advance_char(state);
        } else if (isspace(c)) {
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
        (isalnum((unsigned char)current_char(state)) || current_char(state) == '_')) {
        set_parser_error(state, "Key name too long");
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
        char c = advance_char(state);
        
        /* Handle escape sequences */
        if (c == '\\' && !is_at_end(state)) {
            char next = advance_char(state);
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
        } else if ((unsigned char)c < 0x20) {
            /* TOML basic strings may not contain literal control characters
             * (newline, CR, tab, ...); they must be escaped. Rejecting them
             * here keeps the validated value identical to the byte string
             * toml_get_string later hands to callers, so schema validation
             * cannot be bypassed by smuggling in a raw newline. */
            set_parser_error(state, "Control character in string value");
            return -1;
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
    
    /* Parse digits */
    while (!is_at_end(state) && isdigit(current_char(state)) && 
           num_pos < sizeof(num_str) - 1) {
        num_str[num_pos++] = advance_char(state);
    }
    
    num_str[num_pos] = '\0';
    
    if (num_pos == 0 || (num_pos == 1 && (num_str[0] == '+' || num_str[0] == '-'))) {
        set_parser_error(state, "Invalid integer format");
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

static void skip_comment(toml_parser_state_t *state) {
    while (!is_at_end(state) && current_char(state) != '\n') {
        advance_char(state);
    }
    if (!is_at_end(state)) {
        advance_char(state); /* Skip the newline */
    }
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
    
    if (!doc || !section_name || !key_name || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_set_string");
        return -1;
    }

    /* Bound-check BEFORE mutating the document (AR-03 M5, writer half).
     * safe_strncpy fails without writing on an oversized source, and this
     * function used to ignore that: a >= TOML_MAX_VALUE_LEN value left the
     * key freshly created with value="" and is_set=true, so config_save
     * wrote `ssh_key = ""` to disk and exited 0 — the account's key silently
     * erased by the very save that claimed success. Checking up front also
     * means a failed set leaves no half-built key behind. */
    if (strlen(key_name) >= TOML_MAX_KEY_LEN) {
        set_error(ERR_CONFIG_INVALID, "Key name too long for %s (max %d bytes): %s",
                  section_name, TOML_MAX_KEY_LEN - 1, key_name);
        return -1;
    }
    if (strlen(value) >= TOML_MAX_VALUE_LEN) {
        set_error(ERR_CONFIG_INVALID,
                  "Value for %s.%s is too long (%zu bytes, max %d); refusing to "
                  "store it truncated or empty",
                  section_name, key_name, strlen(value), TOML_MAX_VALUE_LEN - 1);
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

    /* Same up-front bound as toml_set_string: an oversized key name used to
     * leave a ghost key with key="" behind (safe_strncpy fails without
     * writing) while still reporting success. */
    if (strlen(key_name) >= TOML_MAX_KEY_LEN) {
        set_error(ERR_CONFIG_INVALID, "Key name too long for %s (max %d bytes): %s",
                  section_name, TOML_MAX_KEY_LEN - 1, key_name);
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

/* Write document to file */
int toml_write_file(const toml_document_t *doc, const char *file_path) {
    FILE *file;

    if (!doc || !file_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_write_file");
        return -1;
    }

    file = fopen(file_path, "w");
    if (!file) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to open file for writing: %s", file_path);
        return -1;
    }
    
    /* Write sections */
    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];
        
        /* Write section header */
        if (fprintf(file, "[%s]\n", section->name) < 0) {
            fclose(file);
            set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to write section header");
            return -1;
        }
        
        /* Write key-value pairs */
        for (size_t j = 0; j < section->key_count; j++) {
            const toml_keyvalue_t *kv = &section->keys[j];
            
            if (!kv->is_set) continue;
            
            switch (kv->type) {
                case TOML_TYPE_STRING:
                    if (write_escaped_string_value(file, kv->key, kv->value) < 0) {
                        fclose(file);
                        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to write string value");
                        return -1;
                    }
                    break;
                    
                case TOML_TYPE_INTEGER:
                case TOML_TYPE_BOOLEAN:
                    if (fprintf(file, "%s = %s\n", kv->key, kv->value) < 0) {
                        fclose(file);
                        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to write value");
                        return -1;
                    }
                    break;
                    
                case TOML_TYPE_INVALID:
                default:
                    break;
            }
        }
        
        /* Add blank line between sections */
        if (i < doc->section_count - 1) {
            fprintf(file, "\n");
        }
    }

    /* Durably close: stdio buffers writes, so ENOSPC/EIO/quota failures often
     * surface only at the final flush. Flush + fsync + a *checked* fclose so a
     * truncated temp file is reported as failure and never renamed over the
     * real config by config_save. */
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to flush config to disk");
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to close config file");
        return -1;
    }
    return 0;
}

/* Cleanup TOML document */
void toml_cleanup_document(toml_document_t *doc) {
    if (!doc) return;
    
    /* Clear sensitive data */
    secure_zero_memory(doc, sizeof(toml_document_t));
}
