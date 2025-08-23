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

#include "toml_parser.h"
#include "error.h"
#include "utils.h"

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
        set_error(ERR_CONFIG_INVALID, "Configuration file too large: %ld bytes (max: %d)", 
                  file_stat.st_size, TOML_MAX_FILE_SIZE);
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
    
    if (!toml_string || !doc || length == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_parse_string");
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
    if (!sec) {
        set_error(ERR_CONFIG_INVALID, "Section not found: %s", section);
        return -1;
    }
    
    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        set_error(ERR_CONFIG_INVALID, "Key not found: %s.%s", section, key);
        return -1;
    }
    
    if (kv->type != TOML_TYPE_STRING) {
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not a string", section, key);
        return -1;
    }
    
    /* Sanitize the value before returning */
    return toml_sanitize_string(kv->value, value, value_size);
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
    if (!sec) {
        set_error(ERR_CONFIG_INVALID, "Section not found: %s", section);
        return -1;
    }
    
    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        set_error(ERR_CONFIG_INVALID, "Key not found: %s.%s", section, key);
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
    if (!sec) {
        set_error(ERR_CONFIG_INVALID, "Section not found: %s", section);
        return -1;
    }
    
    kv = find_key((toml_section_t *)sec, key);
    if (!kv || !kv->is_set) {
        set_error(ERR_CONFIG_INVALID, "Key not found: %s.%s", section, key);
        return -1;
    }
    
    if (kv->type != TOML_TYPE_BOOLEAN) {
        set_error(ERR_CONFIG_INVALID, "Key %s.%s is not a boolean", section, key);
        return -1;
    }
    
    *value = (strcmp(kv->value, "true") == 0);
    return 0;
}

/* Validate TOML document structure for gitswitch schema */
int toml_validate_gitswitch_schema(const toml_document_t *doc) {
    if (!doc) {
        set_error(ERR_INVALID_ARGS, "NULL document to validate");
        return -1;
    }
    
    /* Check for required sections */
    bool has_settings = false;
    bool has_accounts = false;
    
    for (size_t i = 0; i < doc->section_count; i++) {
        const toml_section_t *section = &doc->sections[i];
        
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
                    if (strlen(kv->value) > 0 && !toml_validate_file_path(kv->value)) {
                        set_error(ERR_CONFIG_INVALID, "Invalid SSH key path: %s", kv->value);
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
                }
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

/* Security validation: Check for safe characters only */
bool toml_validate_safe_characters(const char *input, size_t length) {
    if (!input) return false;
    
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)input[i];
        
        /* Allow printable ASCII, newlines, tabs, and carriage returns */
        if (!(c >= 32 && c <= 126) && c != '\n' && c != '\r' && c != '\t') {
            log_warning("Unsafe character found at position %zu: 0x%02x", i, c);
            return false;
        }
    }
    
    return true;
}

/* Sanitize string value */
int toml_sanitize_string(const char *input, char *output, size_t output_size) {
    size_t input_len, output_pos = 0;
    
    if (!input || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to toml_sanitize_string");
        return -1;
    }
    
    input_len = strlen(input);
    
    for (size_t i = 0; i < input_len && output_pos < output_size - 1; i++) {
        char c = input[i];
        
        /* Remove or escape potentially dangerous characters */
        if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
            output[output_pos++] = c;
        }
        /* Allow some whitespace */
        else if (c == ' ' || c == '\t') {
            output[output_pos++] = c;
        }
        /* Skip other characters */
    }
    
    output[output_pos] = '\0';
    return 0;
}

/* Validate file path for security */
bool toml_validate_file_path(const char *path) {
    if (!path || strlen(path) == 0) return true; /* Empty path is allowed */
    
    /* Check for directory traversal attempts */
    if (strstr(path, "..") != NULL) {
        log_warning("Directory traversal attempt in path: %s", path);
        return false;
    }
    
    /* Check for absolute paths outside user home */
    if (path[0] == '/' && !string_starts_with(path, "/home/") && 
        !string_starts_with(path, "/tmp/")) {
        log_warning("Suspicious absolute path: %s", path);
        return false;
    }
    
    /* Check path length */
    if (strlen(path) > 256) {
        log_warning("Path too long: %zu characters", strlen(path));
        return false;
    }
    
    return true;
}

/* Check for TOML injection patterns */
bool toml_check_injection_patterns(const char *input, size_t length) {
    const char *dangerous_patterns[] = {
        "$(", "`", "${", "\\x", "\\u", NULL
    };
    
    if (!input) return false;
    
    for (int i = 0; dangerous_patterns[i] != NULL; i++) {
        if (strstr(input, dangerous_patterns[i]) != NULL) {
            log_warning("Potentially dangerous pattern found: %s", dangerous_patterns[i]);
            return false;
        }
    }
    
    /* Check for excessive nesting or repetition */
    size_t bracket_count = 0;
    for (size_t i = 0; i < length; i++) {
        if (input[i] == '[') {
            bracket_count++;
            if (bracket_count > 32) {
                log_warning("Excessive bracket nesting detected");
                return false;
            }
        }
    }
    
    return true;
}

/* Internal helper functions implementation continues... */

/* Find section in document */
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
        char c = advance_char(state);
        
        if (isalnum(c) || c == '.' || c == '_' || c == '-') {
            section_name[name_pos++] = c;
        } else {
            set_parser_error(state, "Invalid character in section name");
            return -1;
        }
    }
    
    section_name[name_pos] = '\0';
    
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
        return parse_string_value(state, kv->value, sizeof(kv->value));
    } else if (c == 't' || c == 'f') {
        /* Boolean value */
        kv->type = TOML_TYPE_BOOLEAN;
        bool bool_val;
        if (parse_boolean_value(state, &bool_val) == 0) {
            strcpy(kv->value, bool_val ? "true" : "false");
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
        } else {
            value[value_pos++] = c;
        }
    }
    
    value[value_pos] = '\0';
    
    if (!match_char(state, '"')) {
        set_parser_error(state, "Expected '\"' at end of string");
        return -1;
    }
    
    return 0;
}

/* Parse boolean value true/false */
static int parse_boolean_value(toml_parser_state_t *state, bool *value) {
    if (strncmp(&state->input[state->position], "true", 4) == 0) {
        state->position += 4;
        *value = true;
        return 0;
    } else if (strncmp(&state->input[state->position], "false", 5) == 0) {
        state->position += 5;
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
        safe_strncpy(kv->key, key_name, sizeof(kv->key));
        section->key_count++;
    }
    
    /* Set string value */
    kv->type = TOML_TYPE_STRING;
    safe_strncpy(kv->value, value, sizeof(kv->value));
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
        safe_strncpy(kv->key, key_name, sizeof(kv->key));
        section->key_count++;
    }
    
    /* Set boolean value */
    kv->type = TOML_TYPE_BOOLEAN;
    safe_strncpy(kv->value, value ? "true" : "false", sizeof(kv->value));
    kv->is_set = true;
    
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
                    if (fprintf(file, "%s = \"%s\"\n", kv->key, kv->value) < 0) {
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
    
    fclose(file);
    return 0;
}

/* Cleanup TOML document */
void toml_cleanup_document(toml_document_t *doc) {
    if (!doc) return;
    
    /* Clear sensitive data */
    secure_zero_memory(doc, sizeof(toml_document_t));
}