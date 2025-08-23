/* Error handling and logging utilities */

#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>

/* Error codes */
typedef enum {
    ERR_SUCCESS = 0,
    ERR_INVALID_ARGS = 1,
    ERR_CONFIG_NOT_FOUND = 2,
    ERR_CONFIG_INVALID = 3,
    ERR_CONFIG_WRITE_FAILED = 4,
    ERR_ACCOUNT_NOT_FOUND = 5,
    ERR_ACCOUNT_INVALID = 6,
    ERR_ACCOUNT_EXISTS = 7,
    ERR_GIT_NOT_FOUND = 8,
    ERR_GIT_CONFIG_FAILED = 9,
    ERR_GIT_NOT_REPO = 10,
    ERR_GIT_NOT_REPOSITORY = 10, /* Alias for consistency */
    ERR_GIT_CONFIG_NOT_FOUND = 11,
    ERR_GIT_REPOSITORY_INVALID = 12,
    ERR_SSH_AGENT_FAILED = 13,
    ERR_SSH_KEY_FAILED = 14,
    ERR_SSH_KEY_NOT_FOUND = 15,
    ERR_SSH_CONNECTION_FAILED = 16,
    ERR_SSH_NOT_FOUND = 29,
    ERR_SSH_AGENT_NOT_FOUND = 30,
    ERR_SSH_KEY_LOAD_FAILED = 31,
    ERR_SSH_AGENT_START_FAILED = 32,
    ERR_SSH_KEY_INVALID = 33,
    ERR_SSH_KEY_PERMISSIONS = 34,
    ERR_SSH_KEY_OWNERSHIP = 35,
    ERR_SSH_AGENT_SOCKET_INVALID = 36,
    ERR_GPG_NOT_FOUND = 37,
    ERR_GPG_KEY_FAILED = 38,
    ERR_GPG_KEY_NOT_FOUND = 39,
    ERR_GPG_SIGNING_FAILED = 40,
    ERR_MEMORY_ALLOCATION = 41,
    ERR_FILE_IO = 42,
    ERR_PERMISSION_DENIED = 43,
    ERR_NETWORK_ERROR = 44,
    ERR_SYSTEM_CALL = 45,
    ERR_SYSTEM_REQUIREMENT = 46,
    ERR_SYSTEM_COMMAND_FAILED = 47,
    ERR_INVALID_PATH = 48,
    ERR_UNKNOWN = 99
} error_code_t;

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

/* Error context for detailed error reporting */
typedef struct {
    error_code_t code;
    char message[512];
    char details[1024];
    const char *file;
    int line;
    const char *function;
    int system_errno;
} error_context_t;

/* Global error context */
extern error_context_t g_last_error;

/* Logging configuration */
extern log_level_t g_log_level;
extern FILE *g_log_file;
extern bool g_log_to_stderr;

/* Macros for error reporting with context */
#define set_error(code, fmt, ...) \
    set_error_context((code), __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define set_system_error(code, fmt, ...) \
    set_system_error_context((code), __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

/* Logging macros */
#define log_debug(fmt, ...) \
    log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define log_info(fmt, ...) \
    log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define log_warning(fmt, ...) \
    log_message(LOG_LEVEL_WARNING, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define log_error(fmt, ...) \
    log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define log_critical(fmt, ...) \
    log_message(LOG_LEVEL_CRITICAL, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

/* Function prototypes */

/**
 * Initialize error handling and logging system
 */
int error_init(log_level_t level, const char *log_file_path);

/**
 * Cleanup error handling system
 */
void error_cleanup(void);

/**
 * Set error context with detailed information
 */
void set_error_context(error_code_t code, const char *file, int line,
                       const char *function, const char *fmt, ...);

/**
 * Set error context including system errno
 */
void set_system_error_context(error_code_t code, const char *file, int line,
                              const char *function, const char *fmt, ...);

/**
 * Get last error information
 */
const error_context_t *get_last_error(void);

/**
 * Clear last error
 */
void clear_error(void);

/**
 * Convert error code to human-readable string
 */
const char *error_code_to_string(error_code_t code);

/**
 * Log message with context information
 */
void log_message(log_level_t level, const char *file, int line,
                 const char *function, const char *fmt, ...);

/**
 * Set logging level
 */
void set_log_level(log_level_t level);

/**
 * Set log output file (NULL for stderr)
 */
int set_log_file(const char *file_path);

/**
 * Enable/disable logging to stderr
 */
void set_log_to_stderr(bool enable);

/**
 * Format error message for user display
 */
void format_error_message(char *buffer, size_t buffer_size, 
                          const error_context_t *error);

/**
 * Print formatted error to stderr
 */
void print_error(const char *prefix);

/**
 * Check if error level should be logged
 */
bool should_log(log_level_t level);

/**
 * Get current timestamp for logging
 */
void get_timestamp(char *buffer, size_t buffer_size);

/**
 * Safe string functions that set error context on failure
 */
int safe_strncpy(char *dest, const char *src, size_t dest_size);
int safe_strncat(char *dest, const char *src, size_t dest_size);
int safe_snprintf(char *buffer, size_t buffer_size, const char *fmt, ...);

/**
 * Memory allocation functions that set error context on failure
 */
void *safe_malloc(size_t size);
void *safe_calloc(size_t nmemb, size_t size);
void *safe_realloc(void *ptr, size_t size);

#endif /* ERROR_H */