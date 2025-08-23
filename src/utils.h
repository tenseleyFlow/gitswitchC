/* Utility functions and helpers */

#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <stdbool.h>
#include <time.h>

#include "gitswitch.h"

/* File permissions */
#define PERM_USER_RWX   0700
#define PERM_USER_RW    0600
#define PERM_USER_R     0400

/* Path manipulation constants */
#define PATH_SEPARATOR "/"
#define HOME_PREFIX    "~/"

/* Function prototypes */


/**
 * String utilities
 */
char *trim_whitespace(char *str);
bool string_empty(const char *str);
bool string_equals(const char *a, const char *b);
bool string_starts_with(const char *str, const char *prefix);
bool string_ends_with(const char *str, const char *suffix);
int string_replace(char *str, size_t str_size, const char *old, const char *new);

/**
 * Path utilities
 */
int expand_path(const char *path, char *expanded_path, size_t path_size);
int get_home_directory(char *home_path, size_t path_size);
int join_path(char *result, size_t result_size, const char *base, const char *component);
bool path_exists(const char *path);
bool is_directory(const char *path);
bool is_regular_file(const char *path);
int create_directory_recursive(const char *path, mode_t mode);
int get_file_permissions(const char *path, mode_t *mode);
int set_file_permissions(const char *path, mode_t mode);

/**
 * File utilities
 */
int read_file_to_string(const char *file_path, char *buffer, size_t buffer_size);
int write_string_to_file(const char *file_path, const char *content, mode_t mode);
int copy_file(const char *src_path, const char *dst_path);
int backup_file(const char *file_path, const char *backup_suffix);
bool file_is_readable(const char *file_path);
bool file_is_writable(const char *file_path);
size_t get_file_size(const char *file_path);
time_t get_file_mtime(const char *file_path);

/**
 * Process utilities
 */
int execute_command(const char *command, char *output, size_t output_size);
int execute_command_with_input(const char *command, const char *input,
                               char *output, size_t output_size);
bool command_exists(const char *command);
pid_t start_background_process(const char *command, char *pidfile_path);
int kill_process_by_pidfile(const char *pidfile_path);
bool process_is_running(pid_t pid);

/**
 * Environment utilities
 */
int get_env_var(const char *name, char *buffer, size_t buffer_size);
int set_env_var(const char *name, const char *value, bool overwrite);
int unset_env_var(const char *name);

/**
 * Validation utilities
 */
bool validate_email(const char *email);
bool validate_name(const char *name);
bool validate_key_id(const char *key_id);
bool validate_file_path(const char *path);

/**
 * Security utilities
 */
void secure_zero_memory(void *ptr, size_t size);
int generate_random_string(char *buffer, size_t buffer_size, const char *charset);
bool check_file_permissions_safe(const char *file_path, mode_t expected_mode);

/**
 * Configuration utilities
 */
int get_config_directory(char *config_dir, size_t dir_size);
int ensure_config_directory_exists(void);

/**
 * Terminal utilities
 */
bool is_terminal(int fd);
int get_terminal_size(int *width, int *height);
void disable_echo(void);
void enable_echo(void);

/**
 * Time utilities
 */
void get_current_time_string(char *buffer, size_t buffer_size);
void get_timestamp_string(char *buffer, size_t buffer_size);
bool is_timestamp_expired(time_t timestamp, int max_age_seconds);

/**
 * Comparison utilities
 */
int compare_strings(const void *a, const void *b);
int compare_accounts_by_id(const void *a, const void *b);
int compare_accounts_by_name(const void *a, const void *b);

/**
 * Array utilities
 */
void sort_accounts(account_t *accounts, size_t count, 
                   int (*compare)(const void *, const void *));
account_t *find_account_in_array(account_t *accounts, size_t count, 
                                 const char *identifier);

/**
 * Memory utilities
 */
void *safe_memset(void *ptr, int value, size_t size);
void *safe_memcpy(void *dest, const void *src, size_t size);
int safe_mlock(void *ptr, size_t size);
int safe_munlock(void *ptr, size_t size);

/**
 * Cleanup utilities
 */
void cleanup_temporary_files(void);
int register_cleanup_handler(void (*handler)(void));

/**
 * Debug utilities
 */
void dump_account(const account_t *account);
void dump_config(const config_t *config);
void dump_context(const gitswitch_ctx_t *ctx);

#endif /* UTILS_H */