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
 *
 * All external commands are run via run_argv(), which spawns a child with
 * execvp() and an explicit argv vector — NO shell is involved, so command
 * arguments (account names, key paths, etc.) can never be interpreted as shell
 * syntax. This is the structural defense against command injection.
 */

/* Options for a single child invocation. Any field may be left zero/NULL. */
typedef struct {
    char       *out;                /* stdout capture buffer; NULL/0 => discard */
    size_t      out_size;           /* size of out; output is NUL-terminated, truncated to fit */
    const char *input;              /* bytes written to child stdin; NULL => stdin is /dev/null */
    size_t      input_len;          /* length of input (not strlen; binary-safe) */
    bool        merge_stderr;       /* true => child stderr merged into captured stdout (2>&1) */
    bool        stderr_to_devnull;  /* when !merge_stderr: silence child stderr */
    const char *const *extra_env;   /* NULL-terminated "KEY=VALUE" entries set in the child (e.g. GNUPGHOME) */
} run_opts_t;

/* Result of a child invocation. */
typedef struct {
    int    exit_code;    /* WEXITSTATUS on normal exit; -1 if killed by signal or spawn failed */
    int    term_signal;  /* signal number if killed by signal, else 0 */
    bool   spawned;      /* true if the child actually started */
    size_t out_len;      /* bytes captured into out (excluding the NUL) */
} run_result_t;

/* Pluggable runner (tests install a recording fake via run_set_runner). */
typedef int (*command_runner_fn)(const char *const argv[],
                                 const run_opts_t *opts, run_result_t *result);

/* Install a runner; returns the previous one (NULL means the default). */
command_runner_fn run_set_runner(command_runner_fn fn);

/* Run argv[0] (resolved via PATH by execvp), argv NULL-terminated, through the
 * active runner. Returns 0 iff the child spawned and exited 0. opts/result may
 * be NULL. */
int run_argv(const char *const argv[], const run_opts_t *opts, run_result_t *result);

/* The real fork+execvp implementation; normally reached via run_argv(). */
int run_argv_real(const char *const argv[], const run_opts_t *opts, run_result_t *result);

/* True if an executable named `command` is found in PATH. */
bool command_exists(const char *command);

/**
 * Resolve the absolute path of an executable found in PATH by walking $PATH
 * entries and testing X_OK — no shell involved. Portable across Linux, macOS,
 * and the BSDs. Returns 0 and writes the path into buf on success; -1 otherwise.
 */
int find_command_path(const char *name, char *buf, size_t size);
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