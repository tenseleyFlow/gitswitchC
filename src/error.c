/* Error handling and logging utilities
 * Provides comprehensive error tracking and safe logging for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "error.h"
#include "gitswitch.h"

/* Global error context */
error_context_t g_last_error = {0};

/* Logging configuration */
log_level_t g_log_level = LOG_LEVEL_INFO;
FILE *g_log_file = NULL;
bool g_log_to_stderr = true;

/* Error code to string mapping */
static const struct {
    error_code_t code;
    const char *message;
} error_messages[] = {
    {ERR_SUCCESS, "Success"},
    {ERR_INVALID_ARGS, "Invalid arguments"},
    {ERR_CONFIG_NOT_FOUND, "Configuration file not found"},
    {ERR_CONFIG_INVALID, "Configuration file is invalid"},
    {ERR_CONFIG_WRITE_FAILED, "Failed to write configuration"},
    {ERR_ACCOUNT_NOT_FOUND, "Account not found"},
    {ERR_ACCOUNT_INVALID, "Account configuration is invalid"},
    {ERR_ACCOUNT_EXISTS, "Account already exists"},
    {ERR_GIT_NOT_FOUND, "Git command not found"},
    {ERR_GIT_CONFIG_FAILED, "Git configuration operation failed"},
    {ERR_GIT_NOT_REPO, "Not a git repository"},
    {ERR_GIT_CONFIG_NOT_FOUND, "Git configuration not found"},
    {ERR_GIT_REPOSITORY_INVALID, "Git repository is invalid"},
    {ERR_SSH_AGENT_FAILED, "SSH agent operation failed"},
    {ERR_SSH_KEY_FAILED, "SSH key operation failed"},
    {ERR_SSH_KEY_NOT_FOUND, "SSH key not found"},
    {ERR_SSH_CONNECTION_FAILED, "SSH connection test failed"},
    {ERR_SSH_NOT_FOUND, "SSH command not found"},
    {ERR_SSH_AGENT_NOT_FOUND, "SSH agent command not found"},
    {ERR_SSH_KEY_LOAD_FAILED, "Failed to load SSH key"},
    {ERR_SSH_AGENT_START_FAILED, "Failed to start SSH agent"},
    {ERR_SSH_KEY_INVALID, "SSH key file is invalid"},
    {ERR_SSH_KEY_PERMISSIONS, "SSH key file has wrong permissions"},
    {ERR_SSH_KEY_OWNERSHIP, "SSH key file has wrong ownership"},
    {ERR_SSH_AGENT_SOCKET_INVALID, "SSH agent socket is invalid"},
    {ERR_GPG_NOT_FOUND, "GPG command not found"},
    {ERR_GPG_KEY_FAILED, "GPG key operation failed"},
    {ERR_GPG_KEY_NOT_FOUND, "GPG key not found"},
    {ERR_GPG_SIGNING_FAILED, "GPG signing operation failed"},
    {ERR_MEMORY_ALLOCATION, "Memory allocation failed"},
    {ERR_FILE_IO, "File I/O operation failed"},
    {ERR_PERMISSION_DENIED, "Permission denied"},
    {ERR_NETWORK_ERROR, "Network operation failed"},
    {ERR_SYSTEM_CALL, "System call failed"},
    {ERR_SYSTEM_REQUIREMENT, "System requirement not met"},
    {ERR_SYSTEM_COMMAND_FAILED, "System command execution failed"},
    {ERR_INVALID_PATH, "Invalid file path"},
    {ERR_UNKNOWN, "Unknown error"}
};

/* Log level to string mapping */
static const char* log_level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "CRIT"
};

/* Initialize error handling and logging system */
int error_init(log_level_t level, const char *log_file_path) {
    g_log_level = level;
    
    /* Close existing log file if open */
    if (g_log_file && g_log_file != stderr) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    /* Open new log file if specified */
    if (log_file_path) {
        g_log_file = fopen(log_file_path, "a");
        if (!g_log_file) {
            /* Fall back to stderr if file can't be opened */
            g_log_file = stderr;
            set_error(ERR_FILE_IO, "Failed to open log file: %s", log_file_path);
            return -1;
        }
        /* Set log file to line buffered for immediate output */
        setvbuf(g_log_file, NULL, _IOLBF, 0);
    } else {
        g_log_file = stderr;
    }
    
    /* Clear any existing error */
    clear_error();
    
    log_info("Error handling system initialized (level=%s)", 
             log_level_strings[level]);
    
    return 0;
}

/* Cleanup error handling system */
void error_cleanup(void) {
    if (g_log_file && g_log_file != stderr) {
        log_info("Error handling system shutting down");
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    /* Clear error context */
    clear_error();
}

/* Set error context with detailed information */
void set_error_context(error_code_t code, const char *file, int line,
                       const char *function, const char *fmt, ...) {
    va_list args;
    
    /* Clear previous error */
    memset(&g_last_error, 0, sizeof(g_last_error));
    
    g_last_error.code = code;
    g_last_error.file = file;
    g_last_error.line = line;
    g_last_error.function = function;
    g_last_error.system_errno = 0;
    
    /* Format the error message */
    if (fmt) {
        va_start(args, fmt);
        vsnprintf(g_last_error.message, sizeof(g_last_error.message), fmt, args);
        va_end(args);
    } else {
        strncpy(g_last_error.message, error_code_to_string(code), 
                sizeof(g_last_error.message) - 1);
    }
    
    /* Log the error */
    log_error("Error set: %s (%s:%d in %s)", 
              g_last_error.message, file, line, function);
}

/* Set error context including system errno */
void set_system_error_context(error_code_t code, const char *file, int line,
                              const char *function, const char *fmt, ...) {
    va_list args;
    int saved_errno = errno; /* Save errno before any other operations */
    
    /* Clear previous error */
    memset(&g_last_error, 0, sizeof(g_last_error));
    
    g_last_error.code = code;
    g_last_error.file = file;
    g_last_error.line = line;
    g_last_error.function = function;
    g_last_error.system_errno = saved_errno;
    
    /* Format the error message */
    if (fmt) {
        va_start(args, fmt);
        vsnprintf(g_last_error.message, sizeof(g_last_error.message), fmt, args);
        va_end(args);
    } else {
        strncpy(g_last_error.message, error_code_to_string(code), 
                sizeof(g_last_error.message) - 1);
    }
    
    /* Add system error details */
    if (saved_errno != 0) {
        int msg_len = strlen(g_last_error.message);
        snprintf(g_last_error.details, sizeof(g_last_error.details),
                 "System error: %s (errno=%d)", strerror(saved_errno), saved_errno);
        
        /* Append system error to message if there's room */
        if (msg_len < sizeof(g_last_error.message) - 50) {
            snprintf(g_last_error.message + msg_len, 
                    sizeof(g_last_error.message) - msg_len,
                    " (%s)", strerror(saved_errno));
        }
    }
    
    /* Log the error with system details */
    log_error("System error: %s [errno=%d: %s] (%s:%d in %s)", 
              g_last_error.message, saved_errno, strerror(saved_errno),
              file, line, function);
}

/* Get last error information */
const error_context_t *get_last_error(void) {
    return &g_last_error;
}

/* Clear last error */
void clear_error(void) {
    memset(&g_last_error, 0, sizeof(g_last_error));
}

/* Convert error code to human-readable string */
const char *error_code_to_string(error_code_t code) {
    for (size_t i = 0; i < sizeof(error_messages) / sizeof(error_messages[0]); i++) {
        if (error_messages[i].code == code) {
            return error_messages[i].message;
        }
    }
    return "Unknown error code";
}

/* Log message with context information */
void log_message(log_level_t level, const char *file, int line,
                 const char *function, const char *fmt, ...) {
    va_list args;
    char timestamp[32];
    char message[1024];
    
    /* Check if this level should be logged */
    if (!should_log(level)) {
        return;
    }
    
    /* Format the message */
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    /* Get timestamp */
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Format complete log entry */
    const char *level_str = (level < LOG_LEVEL_CRITICAL) ? 
        log_level_strings[level] : "UNKNOWN";
    
    /* Log to file/stderr */
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s %s:%d (%s) - %s\n",
                timestamp, level_str, file, line, function, message);
        fflush(g_log_file);
    }
    
    /* Also log to stderr if enabled and not already logging there */
    if (g_log_to_stderr && g_log_file != stderr) {
        fprintf(stderr, "[%s] %s - %s\n", timestamp, level_str, message);
    }
}

/* Set logging level */
void set_log_level(log_level_t level) {
    g_log_level = level;
    log_info("Log level changed to %s", log_level_strings[level]);
}

/* Set log output file */
int set_log_file(const char *file_path) {
    FILE *new_file = NULL;
    
    if (file_path) {
        new_file = fopen(file_path, "a");
        if (!new_file) {
            set_system_error(ERR_FILE_IO, "Failed to open log file: %s", file_path);
            return -1;
        }
        setvbuf(new_file, NULL, _IOLBF, 0);
    } else {
        new_file = stderr;
    }
    
    /* Close old file if it's not stderr */
    if (g_log_file && g_log_file != stderr) {
        fclose(g_log_file);
    }
    
    g_log_file = new_file;
    log_info("Log output changed to %s", file_path ? file_path : "stderr");
    
    return 0;
}

/* Enable/disable logging to stderr */
void set_log_to_stderr(bool enable) {
    g_log_to_stderr = enable;
}

/* Format error message for user display */
void format_error_message(char *buffer, size_t buffer_size, 
                          const error_context_t *error) {
    if (!buffer || buffer_size == 0 || !error) {
        return;
    }
    
    if (error->system_errno != 0) {
        snprintf(buffer, buffer_size, 
                "Error: %s\nDetails: %s\nLocation: %s:%d in %s()",
                error->message, error->details, 
                error->file, error->line, error->function);
    } else {
        snprintf(buffer, buffer_size,
                "Error: %s\nLocation: %s:%d in %s()",
                error->message, error->file, error->line, error->function);
    }
}

/* Print formatted error to stderr */
void print_error(const char *prefix) {
    char error_msg[2048];
    
    if (g_last_error.code == ERR_SUCCESS) {
        return; /* No error to print */
    }
    
    format_error_message(error_msg, sizeof(error_msg), &g_last_error);
    
    if (prefix) {
        fprintf(stderr, "%s: %s\n", prefix, error_msg);
    } else {
        fprintf(stderr, "%s\n", error_msg);
    }
}

/* Check if error level should be logged */
bool should_log(log_level_t level) {
    return level >= g_log_level;
}

/* Get current timestamp for logging */
void get_timestamp(char *buffer, size_t buffer_size) {
    time_t now;
    struct tm *tm_info;
    
    if (!buffer || buffer_size == 0) {
        return;
    }
    
    time(&now);
    tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "UNKNOWN-TIME", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
}

/* Safe string copy with error context */
int safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_strncpy");
        return -1;
    }
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        set_error(ERR_INVALID_ARGS, "String too long for destination buffer");
        return -1;
    }
    
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return 0;
}

/* Safe string concatenation with error context */
int safe_strncat(char *dest, const char *src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_strncat");
        return -1;
    }
    
    size_t dest_len = strlen(dest);
    size_t src_len = strlen(src);
    
    if (dest_len + src_len >= dest_size) {
        set_error(ERR_INVALID_ARGS, "String concatenation would overflow buffer");
        return -1;
    }
    
    strncat(dest, src, dest_size - dest_len - 1);
    return 0;
}

/* Safe snprintf with error context */
int safe_snprintf(char *buffer, size_t buffer_size, const char *fmt, ...) {
    va_list args;
    int result;
    
    if (!buffer || !fmt || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_snprintf");
        return -1;
    }
    
    va_start(args, fmt);
    result = vsnprintf(buffer, buffer_size, fmt, args);
    va_end(args);
    
    if (result < 0) {
        set_error(ERR_INVALID_ARGS, "snprintf formatting error");
        return -1;
    }
    
    if ((size_t)result >= buffer_size) {
        set_error(ERR_INVALID_ARGS, "snprintf output truncated");
        return -1;
    }
    
    return result;
}

/* Safe memory allocation with error context */
void *safe_malloc(size_t size) {
    void *ptr;
    
    if (size == 0) {
        set_error(ERR_INVALID_ARGS, "Attempted to allocate zero bytes");
        return NULL;
    }
    
    ptr = malloc(size);
    if (!ptr) {
        set_system_error(ERR_MEMORY_ALLOCATION, "Failed to allocate %zu bytes", size);
        return NULL;
    }
    
    return ptr;
}

/* Safe calloc with error context */
void *safe_calloc(size_t nmemb, size_t size) {
    void *ptr;
    
    if (nmemb == 0 || size == 0) {
        set_error(ERR_INVALID_ARGS, "Attempted to allocate zero elements");
        return NULL;
    }
    
    ptr = calloc(nmemb, size);
    if (!ptr) {
        set_system_error(ERR_MEMORY_ALLOCATION, 
                        "Failed to allocate %zu elements of %zu bytes", nmemb, size);
        return NULL;
    }
    
    return ptr;
}

/* Safe realloc with error context */
void *safe_realloc(void *ptr, size_t size) {
    void *new_ptr;
    
    if (size == 0) {
        set_error(ERR_INVALID_ARGS, "Attempted to reallocate to zero bytes");
        return NULL;
    }
    
    new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        set_system_error(ERR_MEMORY_ALLOCATION, "Failed to reallocate to %zu bytes", size);
        return NULL;
    }
    
    return new_ptr;
}