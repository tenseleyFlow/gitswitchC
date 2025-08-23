/* Minimal, security-focused TOML parser for gitswitch-c configuration
 * Designed specifically for our configuration structure with extensive validation
 */

#ifndef TOML_PARSER_H
#define TOML_PARSER_H

#include <stdbool.h>
#include <stddef.h>

/* Maximum limits for security */
#define TOML_MAX_KEY_LEN 64
#define TOML_MAX_VALUE_LEN 512
#define TOML_MAX_SECTION_LEN 64
#define TOML_MAX_SECTIONS 32
#define TOML_MAX_KEYS_PER_SECTION 16
#define TOML_MAX_FILE_SIZE (64 * 1024)  /* 64KB max config file */

/* TOML value types */
typedef enum {
    TOML_TYPE_STRING,
    TOML_TYPE_INTEGER,
    TOML_TYPE_BOOLEAN,
    TOML_TYPE_INVALID
} toml_value_type_t;

/* TOML key-value pair */
typedef struct {
    char key[TOML_MAX_KEY_LEN];
    char value[TOML_MAX_VALUE_LEN];
    toml_value_type_t type;
    bool is_set;
} toml_keyvalue_t;

/* TOML section */
typedef struct {
    char name[TOML_MAX_SECTION_LEN];
    toml_keyvalue_t keys[TOML_MAX_KEYS_PER_SECTION];
    size_t key_count;
    bool is_set;
} toml_section_t;

/* TOML document structure */
typedef struct {
    toml_section_t sections[TOML_MAX_SECTIONS];
    size_t section_count;
    char file_path[512];
    bool is_valid;
} toml_document_t;

/* Parser state for security tracking */
typedef struct {
    const char *input;
    size_t input_length;
    size_t position;
    size_t line_number;
    size_t column_number;
    bool has_error;
    char error_message[256];
} toml_parser_state_t;

/* Function prototypes */

/**
 * Initialize a TOML document structure
 */
void toml_init_document(toml_document_t *doc);

/**
 * Parse TOML from file with comprehensive security validation
 * - Validates file size limits
 * - Sanitizes all input
 * - Checks for malicious patterns
 * - Validates UTF-8 encoding
 */
int toml_parse_file(const char *file_path, toml_document_t *doc);

/**
 * Parse TOML from string buffer with security validation
 */
int toml_parse_string(const char *toml_string, size_t length, toml_document_t *doc);

/**
 * Get string value from TOML document with validation
 * Returns validated and sanitized string value
 */
int toml_get_string(const toml_document_t *doc, const char *section, 
                    const char *key, char *value, size_t value_size);

/**
 * Get integer value from TOML document with range validation
 */
int toml_get_integer(const toml_document_t *doc, const char *section, 
                     const char *key, int *value);

/**
 * Get boolean value from TOML document
 */
int toml_get_boolean(const toml_document_t *doc, const char *section, 
                     const char *key, bool *value);

/**
 * Set string value in TOML document with validation
 */
int toml_set_string(toml_document_t *doc, const char *section, 
                    const char *key, const char *value);

/**
 * Set integer value in TOML document
 */
int toml_set_integer(toml_document_t *doc, const char *section, 
                     const char *key, int value);

/**
 * Set boolean value in TOML document  
 */
int toml_set_boolean(toml_document_t *doc, const char *section, 
                     const char *key, bool value);

/**
 * Write TOML document to file with atomic operations
 * - Creates backup of existing file
 * - Uses temporary file for atomic write
 * - Validates written content
 */
int toml_write_file(const toml_document_t *doc, const char *file_path);

/**
 * Generate TOML string from document
 */
int toml_generate_string(const toml_document_t *doc, char *buffer, size_t buffer_size);

/**
 * Validate TOML document structure for our specific config schema
 */
int toml_validate_gitswitch_schema(const toml_document_t *doc);

/**
 * Check if section exists in document
 */
bool toml_has_section(const toml_document_t *doc, const char *section);

/**
 * Check if key exists in section
 */
bool toml_has_key(const toml_document_t *doc, const char *section, const char *key);

/**
 * Get list of all sections in document
 */
int toml_get_sections(const toml_document_t *doc, char sections[][TOML_MAX_SECTION_LEN], 
                      size_t max_sections, size_t *section_count);

/**
 * Get list of all keys in a section
 */
int toml_get_keys(const toml_document_t *doc, const char *section, 
                  char keys[][TOML_MAX_KEY_LEN], size_t max_keys, size_t *key_count);

/**
 * Security validation functions
 */

/**
 * Validate that input contains only safe characters
 */
bool toml_validate_safe_characters(const char *input, size_t length);

/**
 * Sanitize string value removing potentially dangerous content
 */
int toml_sanitize_string(const char *input, char *output, size_t output_size);

/**
 * Validate file path for security (no directory traversal, etc.)
 */
bool toml_validate_file_path(const char *path);

/**
 * Check for TOML injection patterns
 */
bool toml_check_injection_patterns(const char *input, size_t length);

/**
 * Cleanup and free TOML document resources
 */
void toml_cleanup_document(toml_document_t *doc);

/**
 * Get last parser error message
 */
const char *toml_get_error_message(const toml_parser_state_t *state);

#endif /* TOML_PARSER_H */