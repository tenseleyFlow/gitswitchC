/* Utility functions and helpers */

#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
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
/* Locale-independent ASCII case folding for protocol/config identifiers whose
 * admitted grammar is ASCII. */
bool string_ascii_case_equal(const char *a, const char *b);
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

/**
 * Ensure the final component of `path` names a real directory owned by the
 * real uid with no group/other permission bits. An absent path is requested at
 * mode 0700. Where no-follow directory descriptors are available, a
 * self-owned existing directory with unsafe permission bits is pinned,
 * identity-checked, tightened to 0700 through that descriptor, and revalidated
 * against the pathname. Platforms without those primitives refuse a
 * permissive existing directory instead of chmodding by pathname. Final
 * symlinks, non-directories, foreign-owned entries, detected replacement, and
 * open/chmod/verification failures return -1. Returns 0 only after successful
 * creation or validation; parent-component symlinks are outside this helper's
 * contract.
 */
int ensure_private_dir(const char *path);

/**
 * Open and pin the runtime parent used by SSH/GPG state.  A configured
 * XDG_RUNTIME_DIR is accepted only when it is absolute, every component can
 * be opened descriptor-relative without following links, and the leaf is a
 * self-owned 0700 directory.  The system-owned /tmp alias is canonicalized on
 * platforms that provide one; no component below it is resolved. The returned
 * descriptor names the validated inode even if its pathname is subsequently
 * renamed.  When XDG_RUNTIME_DIR is absent or empty, the system /tmp target is
 * opened and the absolute /tmp spelling is returned for the uid-specific
 * fallback directories.
 */
int open_runtime_parent(char *path, size_t path_size);

/**
 * Open one private child directory relative to a pinned parent descriptor.
 * When create is true, an absent child is created at 0700.  Existing children
 * are never followed through symlinks and must be self-owned/private.  On an
 * absent non-creating lookup, *absent is true and -1 is returned without
 * installing an error.
 */
int open_private_subdir_at(int parent_fd, const char *name, bool create,
                           bool *absent);

/**
 * Acquire the replace-resistant private lock domain for dir_fd.  The returned
 * descriptor is an opaque token, not the legacy lock-file descriptor; release
 * it with unlock_private_file().  Acquisition retains locks on the pinned
 * parent directory, the leaf directory, and the validated legacy lock file so
 * replacing either named entry cannot create a concurrent lock domain.
 */
int lock_private_file_at(int dir_fd, const char *name);
int try_lock_private_file_at(int dir_fd, const char *name);
void unlock_private_file(int token_fd);

/**
 * Serialize cross-manager SSH/GPG runtime transactions for processes sharing
 * XDG_RUNTIME_DIR (or the same uid-specific /tmp fallback), even when their
 * different HOME values give them different configuration locks. Configured
 * paths retain a lock on their first user-replaceable ancestor so renaming and
 * recreating a lower directory cannot create a second lock namespace. The
 * caller owns the returned descriptor until runtime_state_lock_release().
 */
int runtime_state_lock_acquire(void);
void runtime_state_lock_release(int fd);

/* Test-only one-shot fault selector for the four release-time namespace
 * probes. Production code leaves this at NONE. The hook exists because the
 * two pinned fstat() calls cannot be made to fail through namespace mutation
 * without corrupting an unrelated descriptor in the process. */
typedef enum {
    RUNTIME_LOCK_RELEASE_STAT_NONE = 0,
    RUNTIME_LOCK_RELEASE_STAT_PINNED_PARENT,
    RUNTIME_LOCK_RELEASE_STAT_NAMED_PARENT,
    RUNTIME_LOCK_RELEASE_STAT_PINNED_DIRECTORY,
    RUNTIME_LOCK_RELEASE_STAT_NAMED_DIRECTORY
} runtime_lock_release_stat_probe_t;

void runtime_lock_test_fail_release_stat(
    runtime_lock_release_stat_probe_t probe, int system_errno);

/**
 * Atomically (re)point a symlink: create a temp link to `target` then rename it
 * over `linkpath`, so a follower never observes a missing/half-updated link.
 * Returns 0 on success.
 */
int atomic_symlink(const char *target, const char *linkpath);
int atomic_symlink_at(int dir_fd, const char *target, const char *link_name);

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
 * All external commands are run via run_argv(), which resolves a trusted,
 * readable executable descriptor and uses descriptor execution where
 * supported. Recognized native binaries execute directly. A script is
 * accepted only with a bounded, well-formed shebang naming an absolute direct
 * interpreter (never env); that interpreter is independently trust-walked,
 * pinned, and required to be a recognized native binary. The script is passed
 * through /proc/self/fd or /dev/fd after proving that mapping names the pinned
 * inode, so platforms without that descriptor filesystem fail closed. On
 * macOS, which lacks descriptor execution, the binary/interpreter pathname is
 * descriptor-rewalked and exact-identity-proved immediately before execve.
 * An explicit argv vector is always used: the runner never inserts a shell or
 * interpolates caller arguments into a command string. A caller may still
 * explicitly request a shell executable, in which case its argv is deliberate
 * caller policy rather than runner-side interpretation.
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
    int         cwd_fd;             /* pinned directory inherited across fork; ignored unless use_cwd_fd */
    bool        use_cwd_fd;         /* fchdir(cwd_fd) in the child before closing inherited descriptors */
} run_opts_t;

/* Result of a child invocation. */
typedef struct {
    int    exit_code;     /* WEXITSTATUS on normal exit; -1 if killed by signal or spawn failed */
    int    term_signal;   /* signal number if killed by signal, else 0 */
    bool   spawned;       /* true if the child actually started */
    size_t out_len;       /* bytes captured into out (excluding the NUL) */
    bool   out_truncated; /* true if the child wrote more than out could hold —
                           * the capture is INCOMPLETE, not just short. Callers
                           * feeding `out` onward (e.g. a gpg key export into an
                           * import) must treat this as an error (AR-02 #4). */
} run_result_t;

/* Pluggable runner (tests install a recording fake via run_set_runner). */
typedef int (*command_runner_fn)(const char *const argv[],
                                 const run_opts_t *opts, run_result_t *result);

/* Install a runner; returns the previous one (NULL means the default). */
command_runner_fn run_set_runner(command_runner_fn fn);

/* True only when commands execute through the production descriptor-pinned
 * runner. Filesystem transactions must not mix real path mutation with a
 * test runner that models command side effects only in memory. */
bool run_uses_default_runner(void);

/* Run argv[0] (opened through the sanitized PATH walk, format/shebang checked,
 * then launched from a verified descriptor), argv NULL-terminated, through
 * the active runner. Returns 0 iff the child spawned and exited 0. opts/result
 * may be NULL. An untrusted path, unknown format, malformed/indirect shebang,
 * recursive script interpreter, or unavailable script-descriptor filesystem
 * fails closed; pre-fork rejection leaves result->spawned false. Child
 * setup/exec failures, incomplete stdin delivery, subprocess pipe errors, and
 * a capture pipe held open by descendants are runner failures even if the
 * direct child exits 0. */
int run_argv(const char *const argv[], const run_opts_t *opts, run_result_t *result);

/* The real fork+verified-exec implementation; normally reached via run_argv(). */
int run_argv_real(const char *const argv[], const run_opts_t *opts, run_result_t *result);

/* Test-only child-FD cleanup selector. Production code must leave this at
 * RUN_TEST_FD_CLOSE_AUTO; the default is zero so normal behavior is unchanged.
 * Forced strategies are strict: BULK reports a child setup failure if its
 * primitive cannot run, and SNAPSHOT fails in the parent if enumeration was
 * incomplete. AUTO requires either a supported bulk primitive or a complete
 * parent snapshot: an incomplete snapshot fails before fork, and an unexpected
 * bulk failure fails child setup because that branch has no snapshot. */
typedef enum {
    RUN_TEST_FD_CLOSE_AUTO = 0,
    RUN_TEST_FD_CLOSE_SNAPSHOT,
    RUN_TEST_FD_CLOSE_NUMERIC,
    RUN_TEST_FD_CLOSE_BULK
} run_test_fd_close_strategy_t;

typedef enum {
    RUN_TEST_FD_METHOD_NONE = 0,
    RUN_TEST_FD_METHOD_BULK,
    RUN_TEST_FD_METHOD_SNAPSHOT,
    RUN_TEST_FD_METHOD_NUMERIC
} run_test_fd_close_method_t;

typedef struct {
    run_test_fd_close_method_t method;
    uint64_t close_syscalls;
} run_test_fd_close_observation_t;

int run_test_set_fd_close_strategy(run_test_fd_close_strategy_t strategy);
bool run_test_fd_close_bulk_supported(void);
void run_test_set_fd_close_observation(bool enabled);
bool run_test_get_fd_close_observation(run_test_fd_close_observation_t *out);
void run_test_set_bulk_close_failure(int system_errno);
/* Force AUTO to exercise its portable parent-snapshot selection even when the
 * host normally provides a bulk-close primitive. */
void run_test_set_auto_bulk_close_unavailable(bool unavailable);

/* Test-only deterministic race seam.  The callback runs in the parent after
 * the helper file is verified and pinned but before fork; production leaves
 * it NULL.  It lets regression tests replace/chmod the pathname and prove the
 * child never reopens it. */
typedef void (*run_test_exec_resolved_hook_fn)(const char *resolved_path);
void run_test_set_exec_resolved_hook(run_test_exec_resolved_hook_fn hook);

/* Test-only deterministic signal-publication seam. The callback runs in the
 * parent after fork returns but before the new child PID is published to the
 * rollback signal handler. Production leaves it NULL. */
typedef void (*run_test_post_fork_pre_publish_hook_fn)(void);
void run_test_set_post_fork_pre_publish_hook(
    run_test_post_fork_pre_publish_hook_fn hook);

/* One-shot parent-side fork failure used to prove the pre-fork signal mask is
 * restored without replacing the primary system errno. Zero disables it. */
void run_test_set_fork_failure(int system_errno);

/* True if `command` is currently eligible for the default runner; does not
 * execute it. */
bool command_exists(const char *command);

/**
 * Resolve the canonical absolute path of an executable by walking $PATH — no
 * shell involved. Supply-chain hardened (PS-1/PS-2, AR-07 M28/M29): only
 * absolute paths whose complete root-to-leaf ancestry is owned by root/the
 * current user and has no group/other-writable or ACL-mutable directory may
 * supply a file.
 * The resolved leaf must be a root/current-user-owned regular file, have no
 * group/other write bits or ACL mutation grants, and be both readable and
 * executable through the caller's effective permission class. Execute-only
 * leaves are deliberately rejected because their format/shebang cannot be
 * validated safely. A final
 * descriptor-relative X_OK probe also enforces ACL and noexec-mount policy,
 * then is identity-sealed to the pinned leaf. Before success, the same
 * parent-side format/shebang validator as the default runner requires either
 * recognized binary magic or a bounded direct shebang to a separately trusted
 * binary interpreter; env, recursive, unsupported, and untrusted interpreter
 * forms are rejected. Relative/"."/empty and unsafe entries are skipped. A
 * `name` containing a slash bypasses the PATH search but not the checks. Every
 * call reopens and revalidates the chain; positive pathnames are not cached
 * across inode or metadata replacement. This is point-in-time launch
 * eligibility, not proof of compatible architecture, loader availability, or
 * successful execution; run_argv reopens and revalidates before launch.
 * Returns 0 and writes the canonical path into buf on success; -1 otherwise.
 */
int find_command_path(const char *name, char *buf, size_t size);
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
/* True if `name` collides with a command keyword or is purely numeric — such a
 * name can never be switched to and must be refused at account creation/rename
 * (AR-06 F26). Not folded into validate_name: that also gates loads and runtime
 * teardown of already-existing accounts. */
bool name_is_reserved_for_commands(const char *name);
bool validate_key_id(const char *key_id);
bool validate_file_path(const char *path);

/* True if an SSH key path is free of quote/control bytes and thus safe for
 * BOTH injection-sensitive sinks it reaches: git's shell-interpolated
 * core.sshCommand and the ~/.ssh/config "IdentityFile <path>" line. Every
 * sink calls this itself immediately before writing (AR-02 #10) — see the
 * ssh-1 rationale at the definition in utils.c. */
bool is_safe_ssh_key_path(const char *path);

/**
 * UTF-8 / terminal-safety utilities (shared by the config trust boundary and
 * the TOML parser's charset gate, so both layers apply the SAME strict
 * decoding policy — AR-02 #6).
 *
 * utf8_decode: decode one UTF-8 sequence starting at s, where available is the
 * exact number of readable bytes, writing the codepoint to *cp_out and
 * returning the number of bytes consumed, or 0 if the sequence is truncated
 * or malformed. Deliberately strict: overlong encodings and surrogates are
 * rejected, because an overlong form (e.g. 0xE0 0x80 0x9B) is exactly how a
 * C1 terminal control sneaks past a naive byte filter into a lenient terminal
 * decoder. Callers handling NUL-terminated text still pass their known
 * remaining strlen so a truncated final sequence can never be over-read.
 *
 * tty_safe_codepoint: true if the codepoint is safe to echo to a terminal.
 * C0 controls (including ESC 0x1B and CR), DEL 0x7F, C1 controls
 * U+0080-U+009F (0x9B is a one-byte CSI), Unicode line separators, and the
 * Unicode 16.0 Default_Ignorable_Code_Point set are rejected. The latter
 * includes bidi marks/embeddings/overrides/isolates, zero-width controls,
 * joiners, fillers, tags, and variation selectors: any can hide, reorder, or
 * ambiguously render identity text in list/status/whoami output. Visible
 * Unicode and ordinary combining marks remain valid.
 */
size_t utf8_decode(const unsigned char *s, size_t available,
                   uint32_t *cp_out);
bool tty_safe_codepoint(uint32_t cp);
/* Validate an entire NUL-terminated string under tty_safe_codepoint(),
 * rejecting malformed or truncated UTF-8 without rewriting identity text. */
bool text_is_tty_safe(const char *text);

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
/* Echo transitions are bound to the terminal currently installed as standard
 * input. disable_echo() retains a close-on-exec descriptor above the three
 * standard-stream slots and records the terminal's device/inode identity
 * before changing it. Repeated disable on that same terminal is idempotent.
 * While a restore is pending, either operation rejects a different/reused
 * standard-input descriptor without changing either terminal. enable_echo()
 * restores only through the retained descriptor after validating both
 * identities; a failed restore keeps ownership for retry and closes the
 * retained descriptor only after success. Failures return -1 with errno
 * mirrored in the global error context. */
int disable_echo(void);
int enable_echo(void);

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
 * Debug utilities
 */
void dump_account(const account_t *account);
void dump_config(const config_t *config);
void dump_context(const gitswitch_ctx_t *ctx);

#endif /* UTILS_H */
