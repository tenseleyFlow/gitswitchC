/* Utility functions and helpers with security focus
 * Provides secure, validated utility functions for gitswitch-c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <regex.h>

#if defined(__linux__)
#include <sys/mman.h>
#include <linux/random.h>
#include <sys/syscall.h>
#endif

#include "utils.h"
#include "error.h"

/* Static variables for terminal state management */
static struct termios g_original_termios;
static bool g_echo_disabled = false;

/* Cleanup handlers registry */
static void (*g_cleanup_handlers[16])(void);
static size_t g_cleanup_handler_count = 0;

/* String utilities */

char *trim_whitespace(char *str) {
    char *end;
    
    if (!str) return NULL;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    /* All spaces? */
    if (*str == '\0') return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    end[1] = '\0';
    
    return str;
}

bool string_empty(const char *str) {
    return !str || *str == '\0';
}

bool string_equals(const char *a, const char *b) {
    if (!a && !b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

bool string_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return false;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool string_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

int string_replace(char *str, size_t str_size, const char *old, const char *new) {
    if (!str || !old || !new) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to string_replace");
        return -1;
    }
    
    char *pos = strstr(str, old);
    if (!pos) return 0; /* No replacement needed */
    
    size_t old_len = strlen(old);
    size_t new_len = strlen(new);
    size_t str_len = strlen(str);
    
    /* Check if replacement would overflow buffer */
    if (str_len - old_len + new_len >= str_size) {
        set_error(ERR_INVALID_ARGS, "String replacement would overflow buffer");
        return -1;
    }
    
    /* Move the rest of the string */
    memmove(pos + new_len, pos + old_len, strlen(pos + old_len) + 1);
    
    /* Copy new string */
    memcpy(pos, new, new_len);
    
    return 1;
}

/* Path utilities */

int expand_path(const char *path, char *expanded_path, size_t path_size) {
    if (!path || !expanded_path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to expand_path");
        return -1;
    }
    
    /* Handle tilde expansion */
    if (path[0] == '~') {
        char home_path[MAX_PATH_LEN];
        
        if (get_home_directory(home_path, sizeof(home_path)) != 0) {
            return -1;
        }
        
        /* Handle ~/path and ~/ cases */
        const char *rest = (path[1] == '/') ? path + 2 : path + 1;
        
        if (snprintf(expanded_path, path_size, "%s/%s", home_path, rest) >= (int)path_size) {
            set_error(ERR_INVALID_ARGS, "Expanded path too long");
            return -1;
        }
    } else {
        /* Path doesn't need expansion */
        if (strlen(path) >= path_size) {
            set_error(ERR_INVALID_ARGS, "Path too long for buffer");
            return -1;
        }
        strcpy(expanded_path, path);
    }
    
    return 0;
}

int get_home_directory(char *home_path, size_t path_size) {
    const char *home = getenv("HOME");
    
    if (!home) {
        /* Fall back to password database */
        struct passwd *pw = getpwuid(getuid());
        if (!pw) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to get user home directory");
            return -1;
        }
        home = pw->pw_dir;
    }
    
    if (strlen(home) >= path_size) {
        set_error(ERR_INVALID_ARGS, "Home directory path too long");
        return -1;
    }
    
    strcpy(home_path, home);
    return 0;
}

int join_path(char *result, size_t result_size, const char *base, const char *component) {
    if (!result || !base || !component || result_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to join_path");
        return -1;
    }
    
    size_t base_len = strlen(base);
    size_t comp_len = strlen(component);
    bool needs_separator = (base_len > 0 && base[base_len - 1] != '/') && 
                          (comp_len > 0 && component[0] != '/');
    
    size_t total_len = base_len + comp_len + (needs_separator ? 1 : 0);
    
    if (total_len >= result_size) {
        set_error(ERR_INVALID_ARGS, "Joined path too long for buffer");
        return -1;
    }
    
    strcpy(result, base);
    if (needs_separator) {
        strcat(result, "/");
    }
    strcat(result, component);
    
    return 0;
}

bool path_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

bool is_directory(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int create_directory_recursive(const char *path, mode_t mode) {
    if (!path) {
        set_error(ERR_INVALID_ARGS, "NULL path to create_directory_recursive");
        return -1;
    }
    
    char temp_path[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;
    
    if (SAFE_SNPRINTF(temp_path, sizeof(temp_path), "%s", path) != 0) {
        set_error(ERR_INVALID_ARGS, "Path too long");
        return -1;
    }
    
    len = strlen(temp_path);
    if (temp_path[len - 1] == '/') {
        temp_path[len - 1] = '\0';
    }
    
    for (p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
                set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
        set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
        return -1;
    }
    
    return 0;
}

int get_file_permissions(const char *path, mode_t *mode) {
    struct stat st;
    
    if (!path || !mode) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_file_permissions");
        return -1;
    }
    
    if (stat(path, &st) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to stat file: %s", path);
        return -1;
    }
    
    *mode = st.st_mode & 07777; /* Only permission bits */
    return 0;
}

int set_file_permissions(const char *path, mode_t mode) {
    if (!path) {
        set_error(ERR_INVALID_ARGS, "NULL path to set_file_permissions");
        return -1;
    }
    
    if (chmod(path, mode) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set permissions on: %s", path);
        return -1;
    }
    
    return 0;
}

/* File utilities */

int read_file_to_string(const char *file_path, char *buffer, size_t buffer_size) {
    FILE *file;
    size_t bytes_read;
    
    if (!file_path || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to read_file_to_string");
        return -1;
    }
    
    file = fopen(file_path, "r");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for reading: %s", file_path);
        return -1;
    }
    
    bytes_read = fread(buffer, 1, buffer_size - 1, file);
    if (ferror(file)) {
        set_system_error(ERR_FILE_IO, "Failed to read from file: %s", file_path);
        fclose(file);
        return -1;
    }
    
    buffer[bytes_read] = '\0';
    fclose(file);
    
    return (int)bytes_read;
}

int write_string_to_file(const char *file_path, const char *content, mode_t mode) {
    FILE *file;
    size_t content_len, bytes_written;
    
    if (!file_path || !content) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to write_string_to_file");
        return -1;
    }
    
    file = fopen(file_path, "w");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for writing: %s", file_path);
        return -1;
    }
    
    content_len = strlen(content);
    bytes_written = fwrite(content, 1, content_len, file);
    
    if (bytes_written != content_len) {
        set_system_error(ERR_FILE_IO, "Failed to write complete content to: %s", file_path);
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    /* Set file permissions */
    if (set_file_permissions(file_path, mode) != 0) {
        return -1;
    }
    
    return 0;
}

int copy_file(const char *src_path, const char *dst_path) {
    FILE *src, *dst;
    char buffer[4096];
    size_t bytes;
    int result = 0;
    
    if (!src_path || !dst_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_file");
        return -1;
    }
    
    src = fopen(src_path, "rb");
    if (!src) {
        set_system_error(ERR_FILE_IO, "Failed to open source file: %s", src_path);
        return -1;
    }
    
    dst = fopen(dst_path, "wb");
    if (!dst) {
        set_system_error(ERR_FILE_IO, "Failed to open destination file: %s", dst_path);
        fclose(src);
        return -1;
    }
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            set_system_error(ERR_FILE_IO, "Failed to write to destination file: %s", dst_path);
            result = -1;
            break;
        }
    }
    
    if (ferror(src)) {
        set_system_error(ERR_FILE_IO, "Error reading source file: %s", src_path);
        result = -1;
    }
    
    fclose(src);
    fclose(dst);
    
    /* Copy permissions from source to destination */
    if (result == 0) {
        struct stat src_stat;
        if (stat(src_path, &src_stat) == 0) {
            chmod(dst_path, src_stat.st_mode);
        }
    }
    
    return result;
}

int backup_file(const char *file_path, const char *backup_suffix) {
    char backup_path[MAX_PATH_LEN];
    
    if (!file_path || !backup_suffix) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to backup_file");
        return -1;
    }
    
    if (SAFE_SNPRINTF(backup_path, sizeof(backup_path), "%s%s", 
                     file_path, backup_suffix) != 0) {
        set_error(ERR_INVALID_ARGS, "Backup path too long");
        return -1;
    }
    
    return copy_file(file_path, backup_path);
}

bool file_is_readable(const char *file_path) {
    return file_path && access(file_path, R_OK) == 0;
}

bool file_is_writable(const char *file_path) {
    return file_path && access(file_path, W_OK) == 0;
}

size_t get_file_size(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return (size_t)st.st_size;
}

time_t get_file_mtime(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return st.st_mtime;
}

/* Process utilities */

int execute_command(const char *command, char *output, size_t output_size) {
    return execute_command_with_input(command, NULL, output, output_size);
}

int execute_command_with_input(const char *command, const char *input,
                               char *output, size_t output_size) {
    FILE *pipe;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    int status;
    
    if (!command) {
        set_error(ERR_INVALID_ARGS, "NULL command to execute_command_with_input");
        return -1;
    }
    
    /* Clear output buffer */
    if (output && output_size > 0) {
        output[0] = '\0';
    }
    
    pipe = popen(command, "r");
    if (!pipe) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to execute command: %s", command);
        return -1;
    }
    
    /* Write input to command if provided */
    if (input) {
        /* Note: This is simplified - full implementation would need bidirectional pipes */
        log_warning("Input to command not fully implemented yet");
    }
    
    /* Read output */
    if (output && output_size > 0) {
        size_t total_read = 0;
        
        while ((read_len = getline(&line, &len, pipe)) != -1 && 
               total_read < output_size - 1) {
            
            size_t to_copy = (size_t)read_len;
            if (total_read + to_copy >= output_size) {
                to_copy = output_size - total_read - 1;
            }
            
            memcpy(output + total_read, line, to_copy);
            total_read += to_copy;
        }
        
        output[total_read] = '\0';
        
        /* Remove trailing newline if present */
        if (total_read > 0 && output[total_read - 1] == '\n') {
            output[total_read - 1] = '\0';
        }
    }
    
    free(line);
    status = pclose(pipe);
    
    if (status == -1) {
        set_system_error(ERR_SYSTEM_CALL, "pclose failed for command: %s", command);
        return -1;
    }
    
    return WEXITSTATUS(status);
}

bool command_exists(const char *command) {
    char test_command[256];
    int result;
    
    if (!command) return false;
    
    if (SAFE_SNPRINTF(test_command, sizeof(test_command), 
                     "command -v %s >/dev/null 2>&1", command) != 0) {
        return false;
    }
    
    result = system(test_command);
    return result == 0;
}

pid_t start_background_process(const char *command, char *pidfile_path) {
    pid_t pid;
    FILE *pidfile;
    
    if (!command) {
        set_error(ERR_INVALID_ARGS, "NULL command to start_background_process");
        return -1;
    }
    
    pid = fork();
    if (pid == -1) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to fork process");
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        setsid(); /* Create new session */
        
        /* Redirect standard streams */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
        
        /* Execute command */
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127); /* If exec fails */
    }
    
    /* Parent process */
    if (pidfile_path) {
        pidfile = fopen(pidfile_path, "w");
        if (pidfile) {
            fprintf(pidfile, "%d\n", pid);
            fclose(pidfile);
        }
    }
    
    return pid;
}

int kill_process_by_pidfile(const char *pidfile_path) {
    FILE *pidfile;
    pid_t pid;
    
    if (!pidfile_path) {
        set_error(ERR_INVALID_ARGS, "NULL pidfile path");
        return -1;
    }
    
    pidfile = fopen(pidfile_path, "r");
    if (!pidfile) {
        set_system_error(ERR_FILE_IO, "Failed to open pidfile: %s", pidfile_path);
        return -1;
    }
    
    if (fscanf(pidfile, "%d", &pid) != 1) {
        set_error(ERR_FILE_IO, "Failed to read PID from file: %s", pidfile_path);
        fclose(pidfile);
        return -1;
    }
    
    fclose(pidfile);
    
    if (pid <= 0) {
        set_error(ERR_INVALID_ARGS, "Invalid PID in file: %d", pid);
        return -1;
    }
    
    if (kill(pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            /* Process doesn't exist - clean up pidfile */
            unlink(pidfile_path);
            return 0;
        }
        set_system_error(ERR_SYSTEM_CALL, "Failed to kill process %d", pid);
        return -1;
    }
    
    /* Clean up pidfile */
    unlink(pidfile_path);
    
    return 0;
}

bool process_is_running(pid_t pid) {
    if (pid <= 0) return false;
    return kill(pid, 0) == 0;
}

/* Environment utilities */

int get_env_var(const char *name, char *buffer, size_t buffer_size) {
    const char *value;
    
    if (!name || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_env_var");
        return -1;
    }
    
    value = getenv(name);
    if (!value) {
        buffer[0] = '\0';
        return 1; /* Not an error, just not found */
    }
    
    if (strlen(value) >= buffer_size) {
        set_error(ERR_INVALID_ARGS, "Environment variable value too long");
        return -1;
    }
    
    strcpy(buffer, value);
    return 0;
}

int set_env_var(const char *name, const char *value, bool overwrite) {
    if (!name || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to set_env_var");
        return -1;
    }
    
    if (setenv(name, value, overwrite ? 1 : 0) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

int unset_env_var(const char *name) {
    if (!name) {
        set_error(ERR_INVALID_ARGS, "NULL name to unset_env_var");
        return -1;
    }
    
    if (unsetenv(name) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unset environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

/* Validation utilities */

bool validate_email(const char *email) {
    regex_t regex;
    int result;
    
    if (!email || strlen(email) > MAX_EMAIL_LEN) {
        return false;
    }
    
    /* Basic email regex - not RFC compliant but good enough for git configs */
    const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    
    result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result) return false;
    
    result = regexec(&regex, email, 0, NULL, 0);
    regfree(&regex);
    
    return result == 0;
}

bool validate_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) >= MAX_NAME_LEN) {
        return false;
    }
    
    /* Name should contain at least one non-whitespace character */
    for (const char *p = name; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            return true;
        }
    }
    
    return false;
}

bool validate_key_id(const char *key_id) {
    if (!key_id || strlen(key_id) == 0 || strlen(key_id) >= MAX_KEY_ID_LEN) {
        return false;
    }
    
    /* Key ID should be hexadecimal */
    for (const char *p = key_id; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return false;
        }
    }
    
    return true;
}

bool validate_file_path(const char *path) {
    char expanded[MAX_PATH_LEN];
    
    if (!path || strlen(path) == 0 || strlen(path) >= MAX_PATH_LEN) {
        return false;
    }
    
    /* Expand path and check if it exists */
    if (expand_path(path, expanded, sizeof(expanded)) != 0) {
        return false;
    }
    
    return path_exists(expanded);
}

/* Security utilities */

void secure_zero_memory(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    /* Use explicit_bzero if available, otherwise volatile memset */
#ifdef __GLIBC__
    explicit_bzero(ptr, size);
#else
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
#endif
}

int generate_random_string(char *buffer, size_t buffer_size, const char *charset) {
    size_t charset_len;
    size_t i;
    FILE *urandom;
    
    if (!buffer || buffer_size == 0 || !charset) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to generate_random_string");
        return -1;
    }
    
    charset_len = strlen(charset);
    if (charset_len == 0) {
        set_error(ERR_INVALID_ARGS, "Empty charset");
        return -1;
    }
    
    urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        set_system_error(ERR_FILE_IO, "Failed to open /dev/urandom");
        return -1;
    }
    
    for (i = 0; i < buffer_size - 1; i++) {
        unsigned char rand_byte;
        if (fread(&rand_byte, 1, 1, urandom) != 1) {
            set_system_error(ERR_FILE_IO, "Failed to read random data");
            fclose(urandom);
            return -1;
        }
        buffer[i] = charset[rand_byte % charset_len];
    }
    
    buffer[buffer_size - 1] = '\0';
    fclose(urandom);
    
    return 0;
}

bool check_file_permissions_safe(const char *file_path, mode_t expected_mode) {
    mode_t actual_mode;
    
    if (!file_path) return false;
    
    if (get_file_permissions(file_path, &actual_mode) != 0) {
        return false;
    }
    
    /* Check if permissions are as expected or more restrictive */
    return (actual_mode & 07777) == expected_mode;
}

/* Configuration utilities */

int get_config_directory(char *config_dir, size_t dir_size) {
    char home[MAX_PATH_LEN];
    
    if (!config_dir || dir_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_config_directory");
        return -1;
    }
    
    if (get_home_directory(home, sizeof(home)) != 0) {
        return -1;
    }
    
    if (snprintf(config_dir, dir_size, "%s/%s", home, DEFAULT_CONFIG_DIR) >= (int)dir_size) {
        set_error(ERR_INVALID_ARGS, "Config directory path too long");
        return -1;
    }
    
    return 0;
}

int ensure_config_directory_exists(void) {
    char config_dir[MAX_PATH_LEN];
    
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    if (!is_directory(config_dir)) {
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        log_info("Created config directory: %s", config_dir);
    }
    
    return 0;
}

/* Terminal utilities */

bool is_terminal(int fd) {
    return isatty(fd) == 1;
}

int get_terminal_size(int *width, int *height) {
    struct winsize ws;
    
    if (!width || !height) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to get_terminal_size");
        return -1;
    }
    
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to get terminal size");
        return -1;
    }
    
    *width = ws.ws_col;
    *height = ws.ws_row;
    
    return 0;
}

void disable_echo(void) {
    struct termios new_termios;
    
    if (g_echo_disabled) return;
    
    if (tcgetattr(STDIN_FILENO, &g_original_termios) != 0) {
        return; /* Can't save original, don't disable echo */
    }
    
    new_termios = g_original_termios;
    new_termios.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_termios) == 0) {
        g_echo_disabled = true;
    }
}

void enable_echo(void) {
    if (!g_echo_disabled) return;
    
    tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
    g_echo_disabled = false;
}

/* Time utilities */

void get_current_time_string(char *buffer, size_t buffer_size) {
    time_t now;
    struct tm *tm_info;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "UNKNOWN", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
}

void get_timestamp_string(char *buffer, size_t buffer_size) {
    time_t now;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    snprintf(buffer, buffer_size, "%ld", (long)now);
}

bool is_timestamp_expired(time_t timestamp, int max_age_seconds) {
    time_t now;
    time(&now);
    return (now - timestamp) > max_age_seconds;
}

/* Comparison utilities */

int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int compare_accounts_by_id(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    if (acc_a->id < acc_b->id) return -1;
    if (acc_a->id > acc_b->id) return 1;
    return 0;
}

int compare_accounts_by_name(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    return strcmp(acc_a->name, acc_b->name);
}

/* Array utilities */

void sort_accounts(account_t *accounts, size_t count, 
                   int (*compare)(const void *, const void *)) {
    if (accounts && count > 1 && compare) {
        qsort(accounts, count, sizeof(account_t), compare);
    }
}

account_t *find_account_in_array(account_t *accounts, size_t count, 
                                 const char *identifier) {
    if (!accounts || !identifier || count == 0) {
        return NULL;
    }
    
    /* Try numeric ID first */
    char *endptr;
    unsigned long id = strtoul(identifier, &endptr, 10);
    if (*endptr == '\0') {
        /* It's a number - search by ID */
        for (size_t i = 0; i < count; i++) {
            if (accounts[i].id == (uint32_t)id) {
                return &accounts[i];
            }
        }
    }
    
    /* Search by name or description */
    for (size_t i = 0; i < count; i++) {
        if (strstr(accounts[i].name, identifier) ||
            strstr(accounts[i].description, identifier) ||
            strcmp(accounts[i].email, identifier) == 0) {
            return &accounts[i];
        }
    }
    
    return NULL;
}

/* Memory utilities */

void *safe_memset(void *ptr, int value, size_t size) {
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memset");
        return NULL;
    }
    
    return memset(ptr, value, size);
}

void *safe_memcpy(void *dest, const void *src, size_t size) {
    if (!dest || !src || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memcpy");
        return NULL;
    }
    
    return memcpy(dest, src, size);
}

int safe_mlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_mlock");
        return -1;
    }
    
    if (mlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to lock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

int safe_munlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_munlock");
        return -1;
    }
    
    if (munlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unlock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

/* Cleanup utilities */

void cleanup_temporary_files(void) {
    /* Implementation would clean up any temporary files created */
    log_debug("Cleaning up temporary files");
}

int register_cleanup_handler(void (*handler)(void)) {
    if (!handler) {
        set_error(ERR_INVALID_ARGS, "NULL handler to register_cleanup_handler");
        return -1;
    }
    
    if (g_cleanup_handler_count >= sizeof(g_cleanup_handlers) / sizeof(g_cleanup_handlers[0])) {
        set_error(ERR_INVALID_ARGS, "Too many cleanup handlers registered");
        return -1;
    }
    
    g_cleanup_handlers[g_cleanup_handler_count++] = handler;
    return 0;
}

/* Debug utilities */

void dump_account(const account_t *account) {
    if (!account) {
        log_debug("Account: NULL");
        return;
    }
    
    log_debug("Account dump:");
    log_debug("  ID: %u", account->id);
    log_debug("  Name: %s", account->name);
    log_debug("  Email: %s", account->email);
    log_debug("  Description: %s", account->description);
    log_debug("  SSH enabled: %s", account->ssh_enabled ? "yes" : "no");
    log_debug("  SSH key: %s", account->ssh_key_path);
    log_debug("  GPG enabled: %s", account->gpg_enabled ? "yes" : "no");
    log_debug("  GPG signing: %s", account->gpg_signing_enabled ? "yes" : "no");
    log_debug("  GPG key: %s", account->gpg_key_id);
}

void dump_config(const config_t *config) {
    if (!config) {
        log_debug("Config: NULL");
        return;
    }
    
    log_debug("Config dump:");
    log_debug("  Default scope: %d", config->default_scope);
    log_debug("  Config path: %s", config->config_path);
    log_debug("  Verbose: %s", config->verbose ? "yes" : "no");
    log_debug("  Dry run: %s", config->dry_run ? "yes" : "no");
    log_debug("  Color output: %s", config->color_output ? "yes" : "no");
}

void dump_context(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        log_debug("Context: NULL");
        return;
    }
    
    log_debug("Context dump:");
    log_debug("  Account count: %zu", ctx->account_count);
    log_debug("  Current account: %s", 
              ctx->current_account ? ctx->current_account->name : "none");
    
    dump_config(&ctx->config);
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        dump_account(&ctx->accounts[i]);
    }
}