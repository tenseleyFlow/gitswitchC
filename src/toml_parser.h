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
/* One section per account plus the always-written [settings] section. This
 * must be at least MAX_ACCOUNTS (64, gitswitch.h) + 1: at the old value of 32
 * config_add_account reported success for the 32nd account while config_save
 * could never persist it (main.c treats save failure as a warning), and a
 * hand-written 32+-section config failed to load outright (AR-03 M7). The
 * relationship is pinned by a _Static_assert in toml_parser.c. */
#define TOML_MAX_SECTIONS 65
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
    bool is_set;    /* Cleared by schema validation when the section is
                     * skipped-on-load (AR-03 M5): the getters then treat it
                     * as absent, while toml_get_sections still enumerates it
                     * (so config.c counts it in accounts_skipped_on_load and
                     * config_save refuses to rewrite — skip, never erase). */
} toml_section_t;

/* TOML document structure */
typedef struct {
    toml_section_t sections[TOML_MAX_SECTIONS];
    size_t section_count;
    char file_path[512];
    bool is_valid;
} toml_document_t;

/* Focused initialization observer used by regression tests. The parser is
 * single-threaded; install an observer only around a bounded test operation
 * and restore the previous value afterwards. Returning the previous observer
 * makes nesting safe. */
typedef void (*toml_document_init_hook_fn)(toml_document_t *doc);
toml_document_init_hook_fn toml_set_document_init_hook_fn(
    toml_document_init_hook_fn fn);

/* Focused writer observer for deterministic namespace-race regression tests.
 * The parser/writer is single-threaded; restore the previous hook immediately
 * after the bounded test operation. */
typedef enum {
    TOML_WRITER_TEST_AFTER_TEMP_CREATE = 1
} toml_writer_test_stage_t;
typedef void (*toml_writer_test_hook_fn)(toml_writer_test_stage_t stage,
                                        const char *directory,
                                        const char *temp_name);
toml_writer_test_hook_fn toml_set_writer_test_hook_fn(
    toml_writer_test_hook_fn fn);

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
 * - Initializes and replaces *doc exactly once; callers must not pre-initialize
 * - A non-NULL doc is left invalid but safe to clean up on every failure
 * - Validates file size limits
 * - Sanitizes all input
 * - Checks for malicious patterns
 * - Validates UTF-8 encoding
 */
int toml_parse_file(const char *file_path, toml_document_t *doc);

/**
 * Parse TOML from string buffer with security validation
 * - Initializes and replaces *doc exactly once; callers must not pre-initialize
 * - A non-NULL doc is left invalid but safe to clean up on every failure
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
 * Set boolean value in TOML document  
 */
int toml_set_boolean(toml_document_t *doc, const char *section, 
                     const char *key, bool value);

/**
 * Atomically and durably replace a TOML file.
 * - Serializes into a private 0600 same-directory temporary file
 * - Checks flush, payload fsync, and close before atomic rename
 * - Fsyncs the parent directory before reporting success
 * - Leaves an existing destination unchanged on pre-rename failure
 */
int toml_write_file(const toml_document_t *doc, const char *file_path);


/**
 * Validate TOML document structure for our specific config schema.
 * Non-const: an account section whose ssh_key is over-long is marked
 * skipped (is_set cleared) instead of failing the whole document (AR-03 M5).
 */
int toml_validate_gitswitch_schema(toml_document_t *doc);

/**
 * Validate the two distinct SSH host fields used by the config schema.
 * `ssh_host` is a managed OpenSSH Host pattern and may contain '*'/'?'.
 * `ssh_hostname` is a literal canonical destination and never may.
 */
bool toml_validate_ssh_host_alias(const char *alias);
bool toml_validate_ssh_hostname(const char *hostname);


/**
 * Get list of all sections in document
 */
int toml_get_sections(const toml_document_t *doc, char sections[][TOML_MAX_SECTION_LEN], 
                      size_t max_sections, size_t *section_count);


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

#endif /* TOML_PARSER_H */
