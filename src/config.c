/* Configuration file management with comprehensive security validation
 * Implements secure TOML-based configuration for gitswitch-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* Linux, macOS and FreeBSD provide both flags. Record their availability
 * before supplying compile-only fallbacks so directory setup can use a
 * descriptor-pinned no-follow path on supported platforms. */
#ifndef GITSWITCH_HAVE_DIRECTORY_NOFOLLOW
# if defined(O_NOFOLLOW) && defined(O_DIRECTORY)
#  define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 1
# else
#  define GITSWITCH_HAVE_DIRECTORY_NOFOLLOW 0
# endif
#endif

/* Keep guards for exotic libcs so the file still compiles there. Refusing
 * symlinks is load-bearing for the config reader/writer (cfg-symlink-01/02),
 * so every open below is additionally paired with explicit lstat()/fstat()
 * checks rather than relying on a flag alone. */
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#include "accounts.h"
#include "config.h"
#include "toml_parser.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "signals.h"
#include "ssh_manager.h"

#ifdef GITSWITCH_TESTING
typedef void (*resume_hint_test_hook_fn)(int stage);
resume_hint_test_hook_fn gitswitch_test_set_resume_hint_hook(
    resume_hint_test_hook_fn hook);

static resume_hint_test_hook_fn g_resume_hint_test_hook;

resume_hint_test_hook_fn gitswitch_test_set_resume_hint_hook(
    resume_hint_test_hook_fn hook) {
    resume_hint_test_hook_fn previous = g_resume_hint_test_hook;
    g_resume_hint_test_hook = hook;
    return previous;
}

#define RESUME_HINT_TEST_CHECKPOINT(stage) \
    do { \
        if (g_resume_hint_test_hook) g_resume_hint_test_hook((stage)); \
    } while (0)
#else
#define RESUME_HINT_TEST_CHECKPOINT(stage) ((void)(stage))
#endif

/* Default configuration template with security-focused defaults */
const char *default_config_template = 
"# gitswitch-c Configuration File\n"
"# This file contains sensitive information - ensure proper permissions (600)\n"
"\n"
"[settings]\n"
"# Default scope for git configuration changes\n"
"# Options: \"local\" (repository-specific) or \"global\" (user-wide)\n"
"default_scope = \"local\"\n"
"\n"
"# Example account configuration\n"
"# Uncomment and modify for your accounts\n"
"\n"
"#[accounts.1]\n"
"#name = \"Your Name\"\n"
"#email = \"your.email@example.com\"\n"
"#description = \"Personal Account\"\n"
"#preferred_scope = \"local\"\n"
"#ssh_key = \"~/.ssh/id_ed25519_personal\"\n"
"#gpg_key = \"1234567890ABCDEF\"\n"
"#gpg_signing_enabled = true\n"
"\n"
"#[accounts.2]\n"
"#name = \"Your Name\"\n"
"#email = \"work@company.com\"\n"
"#description = \"Work Account\"\n"
"#preferred_scope = \"global\"\n"
"#ssh_key = \"~/.ssh/id_rsa_work\"\n"
"#gpg_key = \"ABCDEF1234567890\"\n"
"#gpg_signing_enabled = true\n"
"# ssh_host is the alias used in Git remotes; ssh_hostname is its real destination\n"
"#ssh_host = \"github.com-work\"\n"
"#ssh_hostname = \"github.com\"\n"
"\n"
"# Security Notes:\n"
"# - SSH keys should have 600 permissions\n"
"# - GPG keys should exist in your keyring\n"
"# - This config file should have 600 permissions\n"
"# - Use absolute paths or ~ expansion for key files\n";

/* Internal helper functions */
static int open_config_validated(const char *config_path);
static int validate_config_file_security(const char *config_path);
static int validate_config_write_destination(const char *config_path);
static int copy_file_nofollow(const char *src_path, const char *dst_path);
static bool sanitize_tty_text(char *text);
static int create_config_directory_secure(const char *config_dir);
static int config_load_mode(gitswitch_ctx_t *ctx, const char *config_path,
                            bool apply_active_state, bool detect_runtime);
static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static void count_unknown_keys(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc);
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id);
static int validate_account_security(const account_t *account);
static bool config_scope_is_persistable(git_scope_t scope);
static bool config_account_id_is_valid(uint32_t account_id);
static bool config_capture_current_id(const gitswitch_ctx_t *ctx,
                                      uint32_t *account_id);
static void config_rebind_current_id(gitswitch_ctx_t *ctx,
                                     bool had_current,
                                     uint32_t account_id);
static int validate_account_uniqueness(const gitswitch_ctx_t *ctx,
                                       const account_t *account,
                                       size_t ignore_index);
static int config_update_resume_hint(const gitswitch_ctx_t *ctx,
                                     const char *config_path,
                                     bool *state_installed);
static bool config_metadata_same_file(const struct stat *a,
                                      const struct stat *b);
static bool config_metadata_snapshot_same(const struct stat *a,
                                          const struct stat *b);
static bool config_metadata_dir_is_safe(const struct stat *st);
static bool config_metadata_file_is_safe(const struct stat *st,
                                         bool require_private_mode);
static bool config_named_directory_matches(const char *path,
                                           const struct stat *pinned);
static int config_create_private_temp_at(int dir_fd, const char *target_name,
                                         char *temp_name,
                                         size_t temp_name_size);
static int config_publish_noreplace_at(int dir_fd, const char *source,
                                       const char *destination);

typedef struct {
    bool exists;
    bool legacy_needs_only;
    bool inactive_tombstone;
    char needs[8];
    char active_account[MAX_NAME_LEN];
} config_active_state_t;

static int config_read_active_state(const char *config_path,
                                    config_active_state_t *state,
                                    bool require_private_mode);

typedef enum {
    CONFIG_INIT_NORMAL = 0,
    CONFIG_INIT_READONLY,
    CONFIG_INIT_NAMES
} config_init_kind_t;

/* Shared initializer. Preview-only commands use a non-creating form so merely
 * inspecting a fresh HOME cannot mkdir or chmod configuration state. The
 * completion-specific names form goes one step further: it parses the same
 * account document, but never consults persisted active state or live runtime
 * state. */
static int config_init_mode(gitswitch_ctx_t *ctx, config_init_kind_t kind) {
    char config_path[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    bool create_directory = kind == CONFIG_INIT_NORMAL;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_init");
        return -1;
    }
    
    /* Initialize context */
    memset(ctx, 0, sizeof(gitswitch_ctx_t));
    ctx->config.default_scope = GIT_SCOPE_LOCAL;
    ctx->config.verbose = false;
    ctx->config.dry_run = false;
    ctx->config.color_output = true;
    
    /* Get configuration directory path */
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    /* A normal command secures/creates the directory before use. A dry-run is
     * observational: it may read an existing config, but must not create the
     * directory or repair its mode as a side effect of previewing a command. */
    if (create_directory && create_config_directory_secure(config_dir) != 0) {
        return -1;
    }
    
    /* Build config file path */
    if (join_path(config_path, sizeof(config_path), config_dir, DEFAULT_CONFIG_FILE) != 0) {
        return -1;
    }
    
    /* Store config path in context */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));
    
    /* Load configuration if it exists */
    if (path_exists(config_path)) {
        log_info("Loading configuration from: %s", config_path);
        return config_load_mode(ctx, config_path,
                                kind != CONFIG_INIT_NAMES,
                                kind == CONFIG_INIT_NORMAL);
    } else {
        log_info("Configuration file not found: %s", config_path);
        /* File creation remains deferred to a command that actually needs it. */
        return 0;
    }
}

/* Initialize configuration system for an ordinary command. */
int config_init(gitswitch_ctx_t *ctx) {
    return config_init_mode(ctx, CONFIG_INIT_NORMAL);
}

/* Initialize enough state to inspect an existing configuration without
 * creating or chmod'ing any path. This is intentionally a separate API rather
 * than a flag in gitswitch_ctx_t: the context does not exist until this call,
 * and setting dry_run afterwards is the ordering bug this entry point fixes. */
int config_init_readonly(gitswitch_ctx_t *ctx) {
    return config_init_mode(ctx, CONFIG_INIT_READONLY);
}

/* Load only the account document needed by `list --names`. It still validates
 * the legacy field in that document for schema compatibility, but deliberately
 * does not apply legacy/versioned active-account state and never reaches
 * accounts_detect_current(), whose socket inspection takes a runtime lock and
 * may probe a live agent. */
int config_init_names(gitswitch_ctx_t *ctx) {
    return config_init_mode(ctx, CONFIG_INIT_NAMES);
}

static config_document_malloc_fn g_config_document_malloc = malloc;
static config_io_fault_fn g_config_io_fault;
static config_backup_clock_fn g_config_backup_clock;

config_document_malloc_fn config_set_document_malloc_fn(
    config_document_malloc_fn fn) {
    config_document_malloc_fn previous = g_config_document_malloc;
    g_config_document_malloc = fn ? fn : malloc;
    return previous;
}

config_io_fault_fn config_set_io_fault_fn(config_io_fault_fn fn) {
    config_io_fault_fn previous = g_config_io_fault;
    g_config_io_fault = fn;
    return previous;
}

config_backup_clock_fn config_set_backup_clock_fn(
    config_backup_clock_fn fn) {
    config_backup_clock_fn previous = g_config_backup_clock;
    g_config_backup_clock = fn;
    return previous;
}

static bool config_io_fault(config_io_boundary_t boundary,
                            const char *operation) {
    if (!g_config_io_fault || !g_config_io_fault(boundary)) {
        return false;
    }
    errno = EIO;
    set_system_error(ERR_FILE_IO, "Injected config persistence failure: %s",
                     operation);
    return true;
}

/* AR-06 F48/F52/F73: toml_document_t is ~600 KiB (MAX_SECTIONS section structs
 * each carrying MAX_KEYS_PER_SECTION inline key/value buffers). Placing one on
 * the stack put a single frame within striking distance of the default 8 MiB
 * thread stack and blew past smaller ulimits outright. Every config path now
 * allocates the document on the heap via these helpers. Allocation deliberately
 * does not clear the block: toml_parse_string or the save-path initializer owns
 * the one full initialization clear (AR-07 L27). Cleanup still securely clears
 * the contents, including on read failures before parsing begins. */
static toml_document_t *config_document_alloc(void) {
    toml_document_t *doc = g_config_document_malloc(sizeof(*doc));
    if (!doc) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate TOML document");
    }
    return doc;
}

static void config_document_free(toml_document_t *doc) {
    if (!doc) {
        return;
    }
    toml_cleanup_document(doc);
    free(doc);
}

/* Read config_path through a validated fd and parse it into doc
 * (cfg-symlink-01/02). The old flow validated the path with stat() and then
 * had the parser fopen() the path a second time, so a symlinked accounts.toml
 * passed validation against its target and, worse, the file validated and the
 * file parsed could differ (TOCTOU). Parsing the bytes read from the validated
 * fd removes the second path lookup entirely. Shared by config_load and the
 * settings-only write-back (config_save_active_account), which must edit the
 * on-disk document rather than rebuild it (AR-03 M9). The caller owns doc
 * cleanup on both success and failure. */
static int config_read_document(const char *config_path, toml_document_t *doc) {
    char *buffer = NULL;
    struct stat before, after, path_after;
    size_t file_size, total = 0;
    int parse_result;
    int fd;

    fd = open_config_validated(config_path);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &before) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot stat config file: %s", config_path);
        close(fd);
        return -1;
    }
    if (before.st_size < 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration file has an invalid negative size: %s",
                  config_path);
        close(fd);
        return -1;
    }
    if (before.st_size > (off_t)TOML_MAX_FILE_SIZE) {
        set_error(ERR_CONFIG_INVALID,
                  "Configuration file too large: %ld bytes",
                  (long)before.st_size);
        close(fd);
        return -1;
    }
    file_size = (size_t)before.st_size;
    buffer = malloc(file_size + 1);
    if (!buffer) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate config read buffer");
        close(fd);
        return -1;
    }
    while (total < file_size) {
        ssize_t n = read(fd, buffer + total, file_size - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        total += (size_t)n;
    }
    if (config_io_fault(CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ,
                        "config document consistency checkpoint")) {
        close(fd);
        goto fail_buffer;
    }
    if (total != file_size) {
        set_system_error(ERR_FILE_IO, "Failed to read complete config file: %s", config_path);
        close(fd);
        goto fail_buffer;
    }
    buffer[file_size] = '\0';

    /* The parser entry point owns character/injection validation and the one
     * document initialization, matching toml_parse_file exactly. */
    parse_result = toml_parse_string(buffer, file_size, doc);

    /* Keep the exact opened object pinned until parsing finishes. A writer may
     * append or replace accounts.toml after the initial size snapshot; without
     * this post-parse check we would accept a valid stale prefix and a later
     * reconstructive save could erase the unseen suffix. Require EOF, stable
     * descriptor metadata, and the same inode still installed at config_path. */
    {
        unsigned char trailing;
        ssize_t extra;

        do {
            extra = read(fd, &trailing, 1);
        } while (extra < 0 && errno == EINTR);

        if (extra < 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot verify complete config read: %s",
                             config_path);
            close(fd);
            goto fail_buffer;
        }
        if (fstat(fd, &after) != 0 || lstat(config_path, &path_after) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot verify config identity after read: %s",
                             config_path);
            close(fd);
            goto fail_buffer;
        }

        bool metadata_stable =
            config_metadata_same_file(&before, &after) &&
            config_metadata_same_file(&before, &path_after) &&
            before.st_uid == after.st_uid &&
            after.st_uid == path_after.st_uid &&
            before.st_gid == after.st_gid &&
            after.st_gid == path_after.st_gid &&
            before.st_mode == after.st_mode &&
            after.st_mode == path_after.st_mode &&
            before.st_size == after.st_size &&
            after.st_size == path_after.st_size;
#if defined(__APPLE__)
        metadata_stable = metadata_stable &&
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
            before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
            after.st_mtimespec.tv_sec == path_after.st_mtimespec.tv_sec &&
            after.st_mtimespec.tv_nsec == path_after.st_mtimespec.tv_nsec &&
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
            before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec &&
            after.st_ctimespec.tv_sec == path_after.st_ctimespec.tv_sec &&
            after.st_ctimespec.tv_nsec == path_after.st_ctimespec.tv_nsec;
#else
        metadata_stable = metadata_stable &&
            before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
            before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
            after.st_mtim.tv_sec == path_after.st_mtim.tv_sec &&
            after.st_mtim.tv_nsec == path_after.st_mtim.tv_nsec &&
            before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
            before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
            after.st_ctim.tv_sec == path_after.st_ctim.tv_sec &&
            after.st_ctim.tv_nsec == path_after.st_ctim.tv_nsec;
#endif
        if (extra != 0 || !metadata_stable) {
            set_error(ERR_FILE_IO,
                      "Configuration changed while it was being read; retry: %s",
                      config_path);
            close(fd);
            goto fail_buffer;
        }
    }
    close(fd);
    if (parse_result != 0) {
        goto fail_buffer;
    }

    /* Config content can reference key material paths; don't leave a stray
     * copy on the heap (mirrors toml_parse_file's cleanup discipline). */
    secure_zero_memory(buffer, file_size + 1);
    free(buffer);
    return 0;

fail_buffer:
    secure_zero_memory(buffer, file_size + 1);
    free(buffer);
    return -1;
}

#define CONFIG_ACTIVE_STATE_MAX 1024U

static bool config_state_needs_valid(const char *line, size_t length) {
    return (length == 3 && memcmp(line, "ssh", 3) == 0) ||
           (length == 3 && memcmp(line, "gpg", 3) == 0) ||
           (length == 4 && memcmp(line, "none", 4) == 0) ||
           (length == 7 && memcmp(line, "ssh gpg", 7) == 0);
}

/* Read the consolidated .resume-hint state without following either the leaf
 * or an unsafe final config directory. Missing, zero-byte, and one-line state
 * artifacts are admitted only as historical migration input. New artifacts
 * are exactly two lines: an active record
 *   <none|ssh|gpg|ssh gpg>\nactive=<validated account name>\n
 * or the explicit inactive tombstone
 *   none\ninactive=v1\n
 * Any other bytes are a hard load error, never an implicit "no active state". */
static int config_state_path_for_config(const char *config_path,
                                        char *state_path,
                                        size_t state_path_size) {
    const char *slash;
    size_t dir_length;

    if (!config_path || !state_path || state_path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid active-state path arguments");
        return -1;
    }
    slash = strrchr(config_path, '/');
    if (!slash) {
        if ((size_t)snprintf(state_path, state_path_size, ".resume-hint") >=
            state_path_size) {
            set_error(ERR_INVALID_PATH, "Active-state path is too long");
            return -1;
        }
        return 0;
    }
    dir_length = (size_t)(slash - config_path);
    if (dir_length == 0) dir_length = 1;
    if (dir_length + sizeof("/.resume-hint") > state_path_size) {
        set_error(ERR_INVALID_PATH, "Active-state path is too long");
        return -1;
    }
    memcpy(state_path, config_path, dir_length);
    if (dir_length > 1 || state_path[0] != '/') {
        state_path[dir_length++] = '/';
    }
    memcpy(state_path + dir_length, ".resume-hint",
           sizeof(".resume-hint"));
    return 0;
}

static int config_read_active_state(const char *config_path,
                                    config_active_state_t *state,
                                    bool require_private_mode) {
    char hint[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    char buffer[CONFIG_ACTIVE_STATE_MAX + 1];
    struct stat before;
    struct stat opened;
    struct stat after;
    const char *first_newline;
    const char *active;
    size_t first_length;
    size_t active_length;
    size_t total = 0;
    int fd = -1;

    if (!state) {
        set_error(ERR_INVALID_ARGS, "NULL active-state output");
        return -1;
    }
    memset(state, 0, sizeof(*state));
    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0) {
        return -1;
    }
    if (lstat(hint, &before) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect active-state artifact: %s", hint);
        return -1;
    }

    if (safe_strncpy(dir, hint, sizeof(dir)) != 0) {
        return -1;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        if (safe_strncpy(dir, ".", sizeof(dir)) != 0) return -1;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    if (lstat(dir, &after) != 0 || !config_metadata_dir_is_safe(&after)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Active-state parent is not a private owned directory: %s",
                  dir);
        return -1;
    }
    if (!config_metadata_file_is_safe(&before, require_private_mode) ||
        before.st_size < 0 ||
        (uintmax_t)before.st_size > CONFIG_ACTIVE_STATE_MAX) {
        set_error(ERR_PERMISSION_DENIED,
                  "Active-state artifact is not a small stable owned file: %s",
                  hint);
        return -1;
    }

    RESUME_HINT_TEST_CHECKPOINT(1);
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, require_private_mode) ||
        !config_metadata_same_file(&before, &opened) || opened.st_size < 0 ||
        (uintmax_t)opened.st_size > CONFIG_ACTIVE_STATE_MAX) {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot open stable active-state artifact: %s", hint);
        return -1;
    }
    while (total < (size_t)opened.st_size) {
        ssize_t n = read(fd, buffer + total, (size_t)opened.st_size - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_error(ERR_FILE_IO,
                      "Cannot read complete active-state artifact: %s", hint);
            close(fd);
            return -1;
        }
    }
    RESUME_HINT_TEST_CHECKPOINT(2);
    if (fstat(fd, &after) != 0 ||
        !config_metadata_file_is_safe(&after, require_private_mode) ||
        !config_metadata_same_file(&opened, &after) ||
        after.st_size != opened.st_size || lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, require_private_mode) ||
        !config_metadata_same_file(&opened, &after) ||
        after.st_size != opened.st_size) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "Active-state artifact changed while being read: %s", hint);
        return -1;
    }
    close(fd);
    buffer[total] = '\0';

    if (memchr(buffer, '\0', total) != NULL) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: embedded NUL byte",
                  hint);
        return -1;
    }

    /* The first resume-hint implementation wrote a zero-byte marker. It still
     * proves that the legacy settings.active_account was intentionally active,
     * but carries no runtime-needs token. Admit it only as migration input; the
     * next serialized state save replaces it with the versioned format. */
    if (total == 0) {
        state->exists = true;
        state->legacy_needs_only = true;
        return 0;
    }

    first_newline = memchr(buffer, '\n', total);
    if (!first_newline) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: missing first newline",
                  hint);
        return -1;
    }
    first_length = (size_t)(first_newline - buffer);
    if (!config_state_needs_valid(buffer, first_length)) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: invalid runtime-needs token",
                  hint);
        return -1;
    }
    memcpy(state->needs, buffer, first_length);
    state->needs[first_length] = '\0';
    state->exists = true;
    if ((size_t)(first_newline - buffer) + 1 == total) {
        state->legacy_needs_only = true;
        return 0;
    }

    /* Versioned inactive tombstone. Keeping the first line as "none" makes
     * every already-generated shell snippet take its no-op arm, while the
     * second line disambiguates a deliberate reset from a pre-state-artifact
     * configuration whose legacy active_account must still migrate. */
    if (first_length == 4 && memcmp(buffer, "none", 4) == 0 &&
        total - ((size_t)(first_newline - buffer) + 1) ==
            sizeof("inactive=v1\n") - 1 &&
        memcmp(first_newline + 1, "inactive=v1\n",
               sizeof("inactive=v1\n") - 1) == 0) {
        state->inactive_tombstone = true;
        return 0;
    }

    active = first_newline + 1;
    if ((size_t)(active - buffer) + 7 > total ||
        memcmp(active, "active=", 7) != 0 || buffer[total - 1] != '\n') {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: expected active=<name>",
                  hint);
        return -1;
    }
    active += 7;
    active_length = total - (size_t)(active - buffer) - 1;
    if (active_length == 0 || active_length >= sizeof(state->active_account) ||
        memchr(active, '\n', active_length) != NULL ||
        memchr(active, '\r', active_length) != NULL) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: invalid active name length",
                  hint);
        return -1;
    }
    memcpy(state->active_account, active, active_length);
    state->active_account[active_length] = '\0';
    if (!validate_name(state->active_account) ||
        !text_is_tty_safe(state->active_account)) {
        memset(state->active_account, 0, sizeof(state->active_account));
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: unsafe active account name",
                  hint);
        return -1;
    }
    return 0;
}

static const char *config_account_runtime_needs(const account_t *account) {
    bool wants_ssh;
    bool wants_gpg;

    if (!account) return NULL;
    wants_ssh = account->ssh_enabled && account->ssh_key_path[0] != '\0';
    wants_gpg = account->gpg_enabled && account->gpg_key_id[0] != '\0';
    if (wants_ssh && wants_gpg) return "ssh gpg";
    if (wants_ssh) return "ssh";
    if (wants_gpg) return "gpg";
    return "none";
}

/* Load configuration from TOML file. Preview-only callers skip live-runtime
 * discovery because its cross-process lock may create/chmod a lock inode. */
static int config_load_mode(gitswitch_ctx_t *ctx, const char *config_path,
                            bool apply_active_state, bool detect_runtime) {
    toml_document_t *toml_doc;
    config_active_state_t active_state;
    char legacy_active[MAX_NAME_LEN] = "";
    char scope_str[32];
    uint32_t current_id = 0;
    bool had_current;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }

    toml_doc = config_document_alloc();
    if (!toml_doc) {
        return -1;
    }

    /* AR-06 F49: these are cumulative counters that load_accounts_from_toml and
     * count_unknown_keys only ever increment. A reload on an already-populated
     * ctx (e.g. after a save, or a second config_load) would otherwise carry the
     * previous load's counts forward and wrongly refuse a rewrite. Reset them
     * for this fresh load. */
    ctx->accounts_skipped_on_load = 0;
    ctx->unknown_sections_on_load = 0;
    ctx->unknown_keys_on_load = 0;

    if (config_read_document(config_path, toml_doc) != 0) {
        config_document_free(toml_doc);
        return -1;
    }

    /* Load settings section */
    clear_error();
    if (toml_get_string(toml_doc, "settings", "default_scope",
                        scope_str, sizeof(scope_str)) != 0) {
        /* The schema requires this key. A getter failure therefore means the
         * present representation cannot be handed over faithfully, not a
         * benign omission. Never normalize it into the local default. */
        if (get_last_error()->code == ERR_SUCCESS) {
            set_error(ERR_CONFIG_INVALID,
                      "settings.default_scope is required");
        }
        config_document_free(toml_doc);
        return -1;
    }
    ctx->config.default_scope = config_parse_scope(scope_str);

    /* Last-active account for boot resume (optional; absent on older configs).
     * Sanitized like the other untrusted display fields; a name that needed
     * sanitizing can no longer match any (validated) account name, which is
     * the correct fail-closed outcome for resume. */
    clear_error();
    if (toml_get_string(toml_doc, "settings", "active_account",
                        legacy_active, sizeof(legacy_active)) != 0) {
        if (get_last_error()->code != ERR_SUCCESS) {
            config_document_free(toml_doc);
            return -1;
        }
        legacy_active[0] = '\0';
    } else if (legacy_active[0] != '\0' &&
               (!validate_name(legacy_active) ||
                !text_is_tty_safe(legacy_active))) {
        set_error(ERR_CONFIG_INVALID,
                  "settings.active_account is not a safe account name");
        config_document_free(toml_doc);
        return -1;
    }

    /* load_accounts_from_toml rebuilds the fixed array from index zero. Never
     * let an interior pointer survive that rebuild by address: section order
     * can move the same account to a different slot, or put a different
     * account at the old address. Capture only a pointer proven to name a
     * current array element, clear it before mutation, then rebind by the
     * unique stable ID. */
    had_current = config_capture_current_id(ctx, &current_id);
    ctx->current_account = NULL;

    /* Load accounts */
    if (load_accounts_from_toml(ctx, toml_doc) != 0) {
        config_document_free(toml_doc);
        return -1;
    }
    config_rebind_current_id(ctx, had_current, current_id);

    /* AR-06 F02: also detect unmodeled KEYS inside recognized sections, so a
     * full rewrite is refused before it silently erases them. */
    count_unknown_keys(ctx, toml_doc);

    /* Store config path */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));

    config_document_free(toml_doc);

    if (!apply_active_state) {
        log_info("Configuration names loaded successfully: %zu accounts",
                 ctx->account_count);
        return 0;
    }

    /* A versioned tombstone is authoritative inactive state. Otherwise a
     * two-line artifact supplies the active name directly, while every historic
     * representation (no marker, the original zero-byte marker, or a one-line
     * runtime-needs marker) migrates from settings.active_account. Reset writes
     * the tombstone atomically, so absence can safely retain its pre-T12 meaning
     * without resurrecting a post-T12 reset. */
    if (config_read_active_state(config_path, &active_state, false) != 0) {
        return -1;
    }
    if (active_state.exists && active_state.inactive_tombstone) {
        ctx->config.active_account[0] = '\0';
    } else if (active_state.exists && !active_state.legacy_needs_only) {
        if (safe_strncpy(ctx->config.active_account,
                         active_state.active_account,
                         sizeof(ctx->config.active_account)) != 0) {
            return -1;
        }
    } else if (legacy_active[0] != '\0') {
        if (safe_strncpy(ctx->config.active_account, legacy_active,
                         sizeof(ctx->config.active_account)) != 0) {
            return -1;
        }
    } else if (active_state.exists) {
        set_error(ERR_CONFIG_INVALID,
                  "Legacy active-state marker has no settings.active_account migration source");
        return -1;
    } else {
        ctx->config.active_account[0] = '\0';
    }
    if (ctx->config.active_account[0] != '\0') {
        account_t *state_account = config_find_account_exact(
            ctx, ctx->config.active_account);
        if (!state_account) {
            if (ctx->accounts_skipped_on_load > 0) {
                set_error(ERR_CONFIG_INVALID,
                          "Active-state account '%s' could not be validated because account sections were skipped",
                          ctx->config.active_account);
                return -1;
            }
            /* A crash after accounts.toml removed/renamed the active account
             * but before the state phase completed leaves a syntactically
             * valid stale artifact. Resolve that state deterministically to
             * inactive. Loading stays observational: read-only commands do
             * not own the mutation lock, so cleanup is deferred to the next
             * already-serialized active/full save. */
            display_warning("Ignoring stale active-state account '%s': it is not present in %s",
                            ctx->config.active_account, config_path);
            ctx->config.active_account[0] = '\0';
        } else if (active_state.exists &&
                   !active_state.legacy_needs_only &&
                   strcmp(active_state.needs,
                          config_account_runtime_needs(state_account)) != 0) {
            set_error(ERR_CONFIG_INVALID,
                      "Active-state runtime needs '%s' do not match account '%s' (expected '%s')",
                      active_state.needs, ctx->config.active_account,
                      config_account_runtime_needs(state_account));
            return -1;
        }
    }

    /* Detect current account from SSH socket symlink for ordinary commands.
     * A dry-run remains observational and uses the persisted active_account
     * already loaded above rather than acquiring a runtime lock. */
    if (detect_runtime) {
        accounts_detect_current(ctx);
    } else if (ctx->config.active_account[0] != '\0') {
        ctx->current_account = config_find_account_exact(
            ctx, ctx->config.active_account);
    }

    log_info("Configuration loaded successfully: %zu accounts", ctx->account_count);
    return 0;
}

int config_load(gitswitch_ctx_t *ctx, const char *config_path) {
    return config_load_mode(ctx, config_path, true, true);
}

/* Acquire an exclusive, cross-process lock for a mutating config cycle. Returns
 * an open fd holding flock(LOCK_EX) on <config_dir>/.config.lock; hold it across
 * the whole load-modify-save so concurrent add/edit/remove/switch cannot
 * lost-update each other. The acquisition is deliberately nonblocking: the
 * holder may be stopped indefinitely at an interactive prompt, so waiting here
 * can hang another command (including login-time resume) with no useful bound.
 * The atomic temp+rename in config_save only prevents a torn file, not a lost
 * update: two processes that each load, mutate, and rename would have the second
 * silently discard the first's changes. Close the fd to release. Returns -1 on
 * failure with errno preserved; callers must treat that as fatal for a mutating
 * command — proceeding unlocked reopens the lost-update race (AR-02 #17,
 * AR-03 L10). */
static bool config_metadata_same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* A stable descriptor generation requires more than an unchanged inode: an
 * in-place writer preserves dev/ino while changing the bytes. Size plus mtime
 * and ctime catches both ordinary rewrites and same-size restoration attempts;
 * ownership/mode/link-count keep the security contract stable too. */
static bool config_metadata_snapshot_same(const struct stat *a,
                                          const struct stat *b) {
    bool same = config_metadata_same_file(a, b) &&
                a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
                a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
                a->st_size == b->st_size;
#if defined(__APPLE__)
    return same &&
           a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return same &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static bool config_metadata_dir_is_safe(const struct stat *st) {
    return S_ISDIR(st->st_mode) && st->st_uid == getuid() &&
           (st->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool config_metadata_file_is_safe(const struct stat *st,
                                         bool require_private_mode) {
    mode_t mode = st->st_mode & 0777;

    if (!S_ISREG(st->st_mode) || st->st_uid != getuid() || st->st_nlink != 1) {
        return false;
    }
    if (require_private_mode) {
        return mode == PERM_USER_RW;
    }
    /* Older resume markers were created by fopen() and commonly inherited
     * 0644 from the user's umask. Reading the marker is harmless; only reject
     * modes that let another principal alter it. A successful refresh
     * replaces the legacy inode with a fresh 0600 file below. */
    return (mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool config_named_directory_matches(const char *path,
                                           const struct stat *pinned) {
    struct stat named;
    if (lstat(path, &named) != 0) {
        return false;
    }
    if (!config_metadata_dir_is_safe(&named) ||
        !config_metadata_same_file(&named, pinned)) {
        errno = ESTALE;
        return false;
    }
    return true;
}

/* Build a collision-resistant scratch name inside the already-pinned parent.
 * openat()+O_EXCL is the authoritative creation step: a pathname replacement
 * of the parent cannot redirect the descriptor we later write or publish. */
static int config_create_private_temp_at(int dir_fd, const char *target_name,
                                         char *temp_name,
                                         size_t temp_name_size) {
    static const char random_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char suffix[17];

    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        int written;

        if (generate_random_string(suffix, sizeof(suffix), random_chars) != 0) {
            if (errno == 0) errno = EIO;
            return -1;
        }
        written = snprintf(temp_name, temp_name_size, "%s.create.%s",
                           target_name, suffix);
        if (written < 0 || (size_t)written >= temp_name_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int fd = openat(dir_fd, temp_name,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        PERM_USER_RW);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

/* Atomically publish source only if destination is absent. Linux's native
 * renameat2 operation gives a one-step move. linkat+unlinkat is the portable
 * same-directory fallback: link creation itself is atomic and no-replace, so
 * a competing destination is never overwritten. */
static int config_publish_noreplace_at(int dir_fd, const char *source,
                                       const char *destination) {
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
    if (syscall(SYS_renameat2, dir_fd, source, dir_fd, destination,
                RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP) {
        return -1;
    }
#endif

    if (linkat(dir_fd, source, dir_fd, destination, 0) != 0) {
        return -1;
    }
    if (unlinkat(dir_fd, source, 0) != 0) {
        int saved_errno = errno;
        struct stat source_identity;
        struct stat destination_identity;

        /* Roll back only when the destination still names the exact hard link
         * we just created. Never delete a concurrently substituted name. */
        if (fstatat(dir_fd, source, &source_identity,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            fstatat(dir_fd, destination, &destination_identity,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            config_metadata_same_file(&source_identity,
                                      &destination_identity)) {
            (void)unlinkat(dir_fd, destination, 0);
        }
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int config_lock_reject(int token_fd, const char *lockpath) {
    if (token_fd >= 0) unlock_private_file(token_fd);
    set_error(ERR_PERMISSION_DENIED,
              "Config lock is not a stable, private regular file: %s",
              lockpath);
    errno = EACCES;
    return -1;
}

int config_write_lock(void) {
    char dir[MAX_PATH_LEN];
    char lockpath[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat before;
    struct stat after;
    int dir_fd = -1;
    int token_fd = -1;

    errno = 0; /* Never misclassify a validation failure using stale errno. */
    if (get_config_directory(dir, sizeof(dir)) != 0) return -1;
    if (create_config_directory_secure(dir) != 0) return -1;
    if (lstat(dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Config directory is not a stable private directory: %s", dir);
        errno = EACCES;
        return -1;
    }
    if ((size_t)snprintf(lockpath, sizeof(lockpath), "%s/.config.lock", dir) >= sizeof(lockpath)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Reject hostile legacy metadata before entering the shared lock helper.
     * The helper repeats descriptor-level validation and acquires, in order,
     * the pinned parent directory, this leaf directory, and the legacy lock
     * file. Keeping all three locked for the returned token's lifetime means
     * replacing .config.lock (or the whole gitswitch directory) cannot create
     * a second lock domain after this function returns. */
    if (lstat(lockpath, &before) == 0) {
        if (!config_metadata_file_is_safe(&before, true)) {
            return config_lock_reject(-1, lockpath);
        }
    } else if (errno != ENOENT) {
        return -1;
    }

    dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &after) != 0 ||
        !config_metadata_dir_is_safe(&after) ||
        !config_metadata_same_file(&dir_identity, &after)) {
        if (dir_fd >= 0) close(dir_fd);
        return config_lock_reject(-1, lockpath);
    }

    token_fd = try_lock_private_file_at(dir_fd, ".config.lock");
    close(dir_fd);
    if (token_fd < 0) return -1;

    /* The helper pins and locks the original namespace. The public path must
     * still select that validated directory before the caller mutates state;
     * a hostile replacement is a hard failure, never a successful lock on an
     * unreachable inode. */
    if (lstat(dir, &after) != 0 ||
        !config_metadata_dir_is_safe(&after) ||
        !config_metadata_same_file(&dir_identity, &after)) {
        return config_lock_reject(token_fd, lockpath);
    }
    return token_fd;
}

void config_write_unlock(int token_fd) {
    unlock_private_file(token_fd);
}

/* Compute the resume-hint marker path (<config_dir>/.resume-hint). */
int config_resume_hint_path(char *buf, size_t size) {
    char dir[MAX_PATH_LEN];
    if (!buf || size == 0) return -1;
    if (get_config_directory(dir, sizeof(dir)) != 0) return -1;
    if ((size_t)snprintf(buf, size, "%s/.resume-hint", dir) >= size) return -1;
    return 0;
}

int config_resume_hint_probe(char *needs, size_t size) {
    config_active_state_t state;
    char config_path[MAX_PATH_LEN];
    const char *normalized;

    if (!needs || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid resume-hint probe output");
        return -1;
    }
    needs[0] = '\0';
    if (config_get_path(config_path, sizeof(config_path)) != 0 ||
        config_read_active_state(config_path, &state, true) != 0) {
        return -1;
    }
    if (!state.exists) {
        normalized = "none";
    } else if (state.legacy_needs_only && state.needs[0] == '\0') {
        /* The zero-byte historical marker did not encode which runtime was
         * active. Preserve migration behavior without letting the shell read
         * the artifact itself: conservatively inspect both managers. */
        normalized = "ssh gpg";
    } else {
        normalized = state.needs;
    }
    return safe_strncpy(needs, normalized, size);
}

#define CONFIG_RESUME_HINT_SNAPSHOT_MAX 4096U

void config_resume_hint_snapshot_clear(
    config_resume_hint_snapshot_t *snapshot) {
    if (!snapshot) {
        return;
    }
    if (snapshot->data) {
        secure_zero_memory(snapshot->data, snapshot->length);
        free(snapshot->data);
    }
    memset(snapshot, 0, sizeof(*snapshot));
}

static int config_resume_hint_snapshot_capture_at(
    const char *config_path, config_resume_hint_snapshot_t *snapshot) {
    char hint[MAX_PATH_LEN];
    struct stat before;
    struct stat opened;
    struct stat after;
    unsigned char *data = NULL;
    size_t total = 0;
    int fd = -1;

    if (!config_path || !snapshot) {
        set_error(ERR_INVALID_ARGS, "NULL resume-hint snapshot");
        return -1;
    }
    config_resume_hint_snapshot_clear(snapshot);
    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0) {
        return -1;
    }
    if (lstat(hint, &before) != 0) {
        if (errno == ENOENT) {
            snapshot->valid = true;
            return 0;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect resume hint before switch: %s", hint);
        return -1;
    }
    if (!config_metadata_file_is_safe(&before, false) || before.st_size < 0 ||
        (uintmax_t)before.st_size > CONFIG_RESUME_HINT_SNAPSHOT_MAX) {
        set_error(ERR_PERMISSION_DENIED,
                  "Resume hint is not a small, stable, self-owned regular file: %s",
                  hint);
        return -1;
    }

    RESUME_HINT_TEST_CHECKPOINT(3);
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, false) ||
        !config_metadata_same_file(&before, &opened) || opened.st_size < 0 ||
        (uintmax_t)opened.st_size > CONFIG_RESUME_HINT_SNAPSHOT_MAX) {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot open a stable resume hint before switch: %s",
                         hint);
        return -1;
    }

    snapshot->length = (size_t)opened.st_size;
    data = malloc(snapshot->length == 0 ? 1 : snapshot->length);
    if (!data) {
        close(fd);
        snapshot->length = 0;
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate resume-hint before-image");
        return -1;
    }
    while (total < snapshot->length) {
        ssize_t n = read(fd, data + total, snapshot->length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            free(data);
            snapshot->length = 0;
            set_error(ERR_FILE_IO,
                      "Cannot read the complete resume hint before switch: %s",
                      hint);
            return -1;
        }
    }
    if (fstat(fd, &after) != 0 ||
        !config_metadata_file_is_safe(&after, false) ||
        !config_metadata_same_file(&opened, &after) ||
        after.st_size != opened.st_size || lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, false) ||
        !config_metadata_same_file(&opened, &after) ||
        after.st_size != opened.st_size) {
        close(fd);
        free(data);
        snapshot->length = 0;
        set_error(ERR_FILE_IO,
                  "Resume hint changed while its before-image was captured: %s",
                  hint);
        return -1;
    }
    close(fd);

    snapshot->data = data;
    snapshot->mode = (unsigned int)(opened.st_mode & 0777);
    snapshot->existed = true;
    snapshot->valid = true;
    return 0;
}

int config_resume_hint_snapshot_capture(
    config_resume_hint_snapshot_t *snapshot) {
    char config_path[MAX_PATH_LEN];

    if (config_get_path(config_path, sizeof(config_path)) != 0) {
        return -1;
    }
    return config_resume_hint_snapshot_capture_at(config_path, snapshot);
}

static int config_resume_hint_snapshot_restore_at(
    const char *config_path,
    const config_resume_hint_snapshot_t *snapshot) {
    char dir[MAX_PATH_LEN];
    char hint[MAX_PATH_LEN];
    char temp[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat current;
    struct stat installed;
    size_t total = 0;
    int dir_fd = -1;
    int fd = -1;

    if (!config_path || !snapshot || !snapshot->valid) {
        set_error(ERR_INVALID_ARGS, "Invalid resume-hint snapshot");
        return -1;
    }
    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0 ||
        safe_strncpy(dir, hint, sizeof(dir)) != 0) {
        return -1;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        if (safe_strncpy(dir, ".", sizeof(dir)) != 0) return -1;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }

    if (lstat(dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Cannot restore resume hint: config directory is unsafe: %s",
                  dir);
        return -1;
    }
    dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &current) != 0 ||
        !config_metadata_dir_is_safe(&current) ||
        !config_metadata_same_file(&dir_identity, &current)) {
        if (dir_fd >= 0) close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot pin config directory while restoring resume hint");
        return -1;
    }

    if (!snapshot->existed) {
        if (unlink(hint) != 0 && errno != ENOENT) {
            close(dir_fd);
            set_system_error(ERR_FILE_IO,
                             "Cannot restore prior resume-hint absence: %s",
                             hint);
            return -1;
        }
        if (fsync(dir_fd) != 0) {
            close(dir_fd);
            set_system_error(ERR_FILE_IO,
                             "Cannot durably restore prior resume-hint absence");
            return -1;
        }
        close(dir_fd);
        return 0;
    }
    if (lstat(hint, &current) == 0) {
        if (!config_metadata_file_is_safe(&current, false)) {
            close(dir_fd);
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to replace unsafe resume hint during rollback: %s",
                      hint);
            return -1;
        }
    } else if (errno != ENOENT) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect resume hint during rollback: %s", hint);
        return -1;
    }

    if ((size_t)snprintf(temp, sizeof(temp), "%s.restore.XXXXXX", hint) >=
        sizeof(temp)) {
        close(dir_fd);
        set_error(ERR_INVALID_PATH, "Resume-hint rollback path is too long");
        return -1;
    }
    fd = mkstemp(temp);
    if (fd < 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot create resume-hint rollback file: %s", temp);
        return -1;
    }
    (void)signals_scratch_register(temp);
    if (fchmod(fd, (mode_t)snapshot->mode) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot restore resume-hint permissions: %s", temp);
        goto restore_fail;
    }
    while (total < snapshot->length) {
        ssize_t n = write(fd, snapshot->data + total,
                          snapshot->length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_system_error(ERR_FILE_IO,
                             "Cannot restore resume-hint contents: %s", temp);
            goto restore_fail;
        }
    }
    if (fsync(fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot flush restored resume hint: %s", temp);
        goto restore_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO,
                         "Cannot close restored resume hint: %s", temp);
        goto restore_fail;
    }
    fd = -1;
    if (rename(temp, hint) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot install restored resume hint: %s", hint);
        goto restore_fail;
    }
    signals_scratch_unregister(temp);
    if (fsync(dir_fd) != 0 || lstat(hint, &installed) != 0 ||
        !config_metadata_file_is_safe(&installed, false) ||
        (installed.st_mode & 0777) != (mode_t)snapshot->mode ||
        (size_t)installed.st_size != snapshot->length) {
        close(dir_fd);
        set_error(ERR_FILE_IO,
                  "Cannot verify restored resume hint: %s", hint);
        return -1;
    }
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot reopen restored resume hint: %s", hint);
        return -1;
    }
    total = 0;
    while (total < snapshot->length) {
        unsigned char verify[512];
        size_t wanted = snapshot->length - total;
        ssize_t n;

        if (wanted > sizeof(verify)) wanted = sizeof(verify);
        n = read(fd, verify, wanted);
        if (n > 0 &&
            memcmp(verify, snapshot->data + total, (size_t)n) == 0) {
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        close(fd);
        close(dir_fd);
        set_error(ERR_FILE_IO,
                  "Restored resume hint does not match its before-image: %s",
                  hint);
        return -1;
    }
    {
        unsigned char extra;
        ssize_t n;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            close(fd);
            close(dir_fd);
            set_error(ERR_FILE_IO,
                      "Restored resume hint has unexpected trailing data: %s",
                      hint);
            return -1;
        }
    }
    close(fd);
    close(dir_fd);
    return 0;

restore_fail:
    if (fd >= 0) close(fd);
    unlink(temp);
    signals_scratch_unregister(temp);
    close(dir_fd);
    return -1;
}

int config_resume_hint_snapshot_restore(
    const config_resume_hint_snapshot_t *snapshot) {
    char config_path[MAX_PATH_LEN];

    if (config_get_path(config_path, sizeof(config_path)) != 0) {
        return -1;
    }
    return config_resume_hint_snapshot_restore_at(config_path, snapshot);
}

/* Atomically replace the consolidated active-state artifact. Its first line
 * keeps the exact legacy runtime-needs contract consumed by generated shell
 * code; its second line records either active=<name> or the versioned inactive
 * tombstone that prevents a stale legacy settings key from being resurrected. */
static int config_update_resume_hint(const gitswitch_ctx_t *ctx,
                                     const char *config_path,
                                     bool *state_installed) {
    config_active_state_t existing_state;
    const account_t *active_account = NULL;
    const char *needs;
    char content[MAX_NAME_LEN + 32];
    char dir[MAX_PATH_LEN];
    char hint[MAX_PATH_LEN];
    char temp[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat before;
    struct stat temp_identity;
    struct stat after;
    bool existed = false;
    int fd = -1;

    if (state_installed) {
        *state_installed = false;
    }
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to active-state commit");
        return -1;
    }

    /* The inherited environment must never steer release behavior. Keep the
     * historical CLI regression seam only in the dedicated testing object;
     * ordinary unit tests use config_set_io_fault_fn's explicit pre/post-
     * installation boundaries instead. */
#ifdef GITSWITCH_TESTING
    const char *fault = getenv("GITSWITCH_TEST_FAIL_RESUME_HINT_COMMIT");
    if (fault && strcmp(fault, "1") == 0) {
        set_error(ERR_FILE_IO, "Injected resume-hint commit failure");
        return -1;
    }
#endif

    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0 ||
        safe_strncpy(dir, hint, sizeof(dir)) != 0) {
        return -1;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        if (safe_strncpy(dir, ".", sizeof(dir)) != 0) return -1;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    if (create_config_directory_secure(dir) != 0 ||
        lstat(dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Cannot safely update the resume hint: config directory is unavailable");
        return -1;
    }
    if (config_read_active_state(config_path, &existing_state, false) != 0) {
        return -1;
    }
    if (ctx->config.active_account[0] == '\0') {
        if (safe_strncpy(content, "none\ninactive=v1\n",
                         sizeof(content)) != 0) {
            return -1;
        }
        if (existing_state.exists && existing_state.inactive_tombstone) {
            return 0;
        }
    } else {

        /* Resolve with the same case-insensitive exact-name semantics used by
         * config_load. Persisting a guessed conservative token for a genuinely
         * absent account would make a successful save advertise an identity the
         * just-written account model cannot resolve. */
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (strcasecmp(ctx->accounts[i].name,
                           ctx->config.active_account) == 0) {
                active_account = &ctx->accounts[i];
                break;
            }
        }

        if (!validate_name(ctx->config.active_account) ||
            !text_is_tty_safe(ctx->config.active_account)) {
            set_error(ERR_CONFIG_INVALID,
                      "Refusing to persist unsafe active account name");
            return -1;
        }
        if (!active_account) {
            set_error(ERR_CONFIG_INVALID,
                      "Refusing to persist missing active account '%s'",
                      ctx->config.active_account);
            return -1;
        }
        bool wants_ssh = active_account->ssh_enabled &&
                         active_account->ssh_key_path[0] != '\0';
        bool wants_gpg = active_account->gpg_enabled &&
                         active_account->gpg_key_id[0] != '\0';
        if (wants_ssh && wants_gpg)      needs = "ssh gpg";
        else if (wants_ssh)              needs = "ssh";
        else if (wants_gpg)              needs = "gpg";
        else                             needs = "none";
        if ((size_t)snprintf(content, sizeof(content), "%s\nactive=%s\n",
                             needs, ctx->config.active_account) >= sizeof(content)) {
            set_error(ERR_CONFIG_INVALID, "Active-state content is too long");
            return -1;
        }
        if (existing_state.exists && !existing_state.legacy_needs_only &&
            !existing_state.inactive_tombstone &&
            strcmp(existing_state.needs, needs) == 0 &&
            strcmp(existing_state.active_account,
                   ctx->config.active_account) == 0) {
            return 0;
        }
    }

    /* Never open the destination for writing. Capture its exact identity (or
     * absence), build a fresh 0600 inode beside it, then verify that neither
     * the destination nor its private directory changed before rename. */
    if (lstat(hint, &before) == 0) {
        existed = true;
        if (!config_metadata_file_is_safe(&before, false)) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to replace unsafe resume hint metadata: %s", hint);
            return -1;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect resume hint before update: %s", hint);
        return -1;
    }
    if ((size_t)snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", hint) >= sizeof(temp)) {
        set_error(ERR_INVALID_PATH, "Resume hint temporary path is too long");
        return -1;
    }

    fd = mkstemp(temp);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot create temporary resume hint: %s", hint);
        return -1;
    }
    (void)signals_scratch_register(temp);
    if (config_io_fault(CONFIG_IO_STATE_AFTER_TEMP,
                        "active-state temp creation")) {
        goto hint_fail;
    }
    if (fchmod(fd, PERM_USER_RW) != 0 ||
        fstat(fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        set_system_error(ERR_FILE_IO,
                         "Cannot secure temporary resume hint: %s", temp);
        goto hint_fail;
    }

    size_t total = 0;
    size_t length = strlen(content);
    while (total < length) {
        ssize_t n = write(fd, content + total, length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_system_error(ERR_FILE_IO,
                             "Cannot write temporary resume hint: %s", temp);
            goto hint_fail;
        }
    }
    if (config_io_fault(CONFIG_IO_STATE_AFTER_WRITE,
                        "active-state write") ||
        config_io_fault(CONFIG_IO_STATE_BEFORE_FILE_SYNC,
                        "active-state payload sync") ||
        fsync(fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot flush temporary resume hint: %s", temp);
        goto hint_fail;
    }
    if (config_io_fault(CONFIG_IO_STATE_BEFORE_CLOSE,
                        "active-state close")) {
        goto hint_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO,
                         "Cannot finalize temporary resume hint: %s", temp);
        goto hint_fail;
    }
    fd = -1;

    if (lstat(temp, &after) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_same_file(&temp_identity, &after) ||
        lstat(dir, &after) != 0 ||
        !config_metadata_dir_is_safe(&after) ||
        !config_metadata_same_file(&dir_identity, &after)) {
        set_error(ERR_FILE_IO,
                  "Resume hint metadata changed before installation: %s", hint);
        goto hint_fail;
    }
    if (lstat(hint, &after) == 0) {
        if (!existed || !config_metadata_file_is_safe(&after, false) ||
            !config_metadata_same_file(&before, &after)) {
            set_error(ERR_FILE_IO,
                      "Resume hint changed before update; refusing replacement: %s",
                      hint);
            goto hint_fail;
        }
    } else if (existed || errno != ENOENT) {
        set_error(ERR_FILE_IO,
                  "Resume hint changed before update; refusing replacement: %s",
                  hint);
        goto hint_fail;
    }

    if (config_io_fault(CONFIG_IO_STATE_BEFORE_RENAME,
                        "active-state rename") || rename(temp, hint) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot install resume hint atomically: %s", hint);
        goto hint_fail;
    }
    signals_scratch_unregister(temp);
    if (state_installed) {
        *state_installed = true;
    }

    if (lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_same_file(&temp_identity, &after)) {
        set_error(ERR_FILE_IO,
                  "Cannot verify installed resume hint: %s", hint);
        return -1;
    }
    {
        int dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY |
                               O_NOFOLLOW);
        if (dir_fd < 0 ||
            config_io_fault(CONFIG_IO_STATE_BEFORE_DIR_SYNC,
                            "active-state directory sync") ||
            fsync(dir_fd) != 0) {
            int saved_errno = errno;
            if (dir_fd >= 0) close(dir_fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot durably commit resume hint: %s", hint);
            return -1;
        }
        close(dir_fd);
    }
    return 0;

hint_fail:
    if (fd >= 0) close(fd);
    unlink(temp);
    signals_scratch_unregister(temp);
    return -1;
}

/* Shared atomic-write tail for config_save and config_save_active_account:
 * validate the destination, back up the existing file, write doc to a fresh
 * 0600 temp, rename it into place, refresh the resume hint. */
static int config_write_document_atomic(const gitswitch_ctx_t *ctx,
                                        const toml_document_t *doc,
                                        const char *config_path,
                                        bool make_backup,
                                        bool update_hint,
                                        bool *config_installed) {
    char dir_path[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN];
    char temp_name[MAX_PATH_LEN];
    const char *slash;
    const char *target_name;
    struct stat pinned_dir;
    struct stat destination_before;
    struct stat destination_now;
    struct stat temp_identity;
    struct stat temp_now;
    bool destination_existed = false;
    bool temp_exists = false;
    bool temp_registered = false;
    bool have_temp_identity = false;
    int dir_fd = -1;
    int temp_fd = -1;

    if (config_installed) {
        *config_installed = false;
    }

    /* Refuse to write through or next to a symlink (cfg-symlink-01). rename()
     * would replace a symlinked accounts.toml with a real file, but the
     * backup step reads through the link (exfiltrating the target into a
     * 0600 backup we own) and a symlinked/foreign parent directory lets an
     * attacker choose where the temp+rename lands. Fail closed instead. */
    if (validate_config_write_destination(config_path) != 0) {
        return -1;
    }

    slash = strrchr(config_path, '/');
    target_name = slash ? slash + 1 : config_path;
    if (target_name[0] == '\0') {
        set_error(ERR_INVALID_PATH, "Config destination has no file name");
        return -1;
    }
    if (!slash) {
        if (safe_strncpy(dir_path, ".", sizeof(dir_path)) != 0) return -1;
    } else {
        size_t dir_length = (size_t)(slash - config_path);
        if (dir_length == 0) dir_length = 1;
        if (dir_length >= sizeof(dir_path)) {
            set_error(ERR_INVALID_PATH, "Config directory path is too long");
            return -1;
        }
        memcpy(dir_path, config_path, dir_length);
        dir_path[dir_length] = '\0';
    }
    dir_fd = open(dir_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &pinned_dir) != 0 ||
        !config_metadata_dir_is_safe(&pinned_dir) ||
        !config_named_directory_matches(dir_path, &pinned_dir)) {
        int saved_errno = errno ? errno : ESTALE;
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot pin config destination directory: %s",
                         dir_path);
        return -1;
    }
    errno = 0;
    if (fstatat(dir_fd, target_name, &destination_before,
                AT_SYMLINK_NOFOLLOW) == 0) {
        destination_existed = true;
        if (!config_metadata_file_is_safe(&destination_before, false)) {
            errno = EPERM;
            set_error(ERR_PERMISSION_DENIED,
                      "Config destination is not a safe owned regular file: %s",
                      config_path);
            goto document_fail;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot identify config destination: %s", config_path);
        goto document_fail;
    }

    /* Create backup if file exists. AR-06 F51: skip it for a settings-only
     * write-back (just active_account), which happens on EVERY switch — the
     * account DATA is unchanged, the write is atomic (temp+rename), and backing
     * up on each switch churned five backups for five switches, rotating real
     * account-edit backups out of the bounded set. */
    if (make_backup && destination_existed) {
        if (config_backup(config_path) != 0) {
            /* A successful save promises a durable, parseable recovery copy.
             * If that promise cannot be established, the config replacement
             * must not begin. */
            goto document_fail;
        }
    }

    /* Create temporary file path for atomic write. Include the pid so two
     * concurrent gitswitch processes never share a temp file — a shared
     * deterministic name lets one process truncate/rewrite the temp while the
     * other is mid-write, so the loser's rename() installs a partial config. */
    if ((size_t)snprintf(temp_name, sizeof(temp_name), "%s.tmp.%d",
                         target_name, (int)getpid()) >= sizeof(temp_name) ||
        (size_t)snprintf(temp_path, sizeof(temp_path), "%s%s%s", dir_path,
                         strcmp(dir_path, "/") == 0 ? "" : "/",
                         temp_name) >= sizeof(temp_path)) {
        set_error(ERR_INVALID_ARGS, "Temporary file path too long");
        goto document_fail;
    }

    /* Retire only a provably private stale inode from a crashed reuse of this
     * pid. Never unlink a symlink or foreign/substituted pathname. */
    errno = 0;
    if (fstatat(dir_fd, temp_name, &temp_now, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!config_metadata_file_is_safe(&temp_now, true) ||
            unlinkat(dir_fd, temp_name, 0) != 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing unsafe stale config temporary file: %s",
                      temp_path);
            goto document_fail;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot inspect config temporary file: %s", temp_path);
        goto document_fail;
    }
    temp_fd = openat(dir_fd, temp_name,
                     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     PERM_USER_RW);
    if (temp_fd < 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to create private temporary config file: %s",
                         temp_path);
        goto document_fail;
    }
    temp_exists = true;
    if (fchmod(temp_fd, PERM_USER_RW) != 0 ||
        fstat(temp_fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to create private temporary config file: %s",
                         temp_path);
        goto document_fail;
    }
    have_temp_identity = true;

    /* SIG-02 (AR-02 #27): register the temp for signal cleanup for the span
     * it exists. Only effective while a guard handler is installed (main()
     * holds one across the save-after-switch); otherwise it is an inert no-op
     * — the atomic temp+rename below protects the real file either way, this
     * only prevents an orphaned .tmp when a signal lands mid-save. */
    if (signals_scratch_register(temp_path) != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot register config temporary file for cleanup");
        goto document_fail;
    }
    temp_registered = true;

    /* The TOML layer serializes and fsyncs this exact descriptor but cannot
     * publish it. Config remains the sole owner of rename and directory sync. */
    if (toml_write_fd(doc, temp_fd) != 0) {
        goto document_fail;
    }
    errno = 0;
    if (fstat(temp_fd, &temp_now) != 0 ||
        !config_metadata_file_is_safe(&temp_now, true) ||
        !config_metadata_same_file(&temp_identity, &temp_now) ||
        fstatat(dir_fd, temp_name, &temp_now, AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&temp_now, true) ||
        !config_metadata_same_file(&temp_identity, &temp_now)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Temporary config changed before publication: %s",
                         temp_path);
        goto document_fail;
    }
    if (close(temp_fd) != 0) {
        temp_fd = -1;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to close temporary config file: %s",
                         temp_path);
        goto document_fail;
    }
    temp_fd = -1;

    if (!config_named_directory_matches(dir_path, &pinned_dir)) {
        errno = ESTALE;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Config destination directory changed before publication: %s",
                         dir_path);
        goto document_fail;
    }
    errno = 0;
    if (fstatat(dir_fd, target_name, &destination_now,
                AT_SYMLINK_NOFOLLOW) == 0) {
        if (!destination_existed ||
            !config_metadata_snapshot_same(&destination_before,
                                           &destination_now)) {
            errno = destination_existed ? ESTALE : EEXIST;
            set_system_error(ERR_CONFIG_WRITE_FAILED,
                             "Config destination changed before publication: %s",
                             config_path);
            goto document_fail;
        }
    } else if (destination_existed || errno != ENOENT) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Config destination changed before publication: %s",
                         config_path);
        goto document_fail;
    }

    /* Atomic move from temp to final location */
    if (config_io_fault(CONFIG_IO_DOCUMENT_BEFORE_RENAME,
                        "config document rename")) {
        goto document_fail;
    }
    if ((destination_existed &&
         renameat(dir_fd, temp_name, dir_fd, target_name) != 0) ||
        (!destination_existed &&
         config_publish_noreplace_at(dir_fd, temp_name, target_name) != 0)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                        "Failed to move temporary config file to final location");
        goto document_fail;
    }
    temp_exists = false;
    signals_scratch_unregister(temp_path);
    temp_registered = false;
    if (config_installed) {
        *config_installed = true;
    }

    errno = 0;
    if (fstatat(dir_fd, target_name, &destination_now,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&destination_now, true) ||
        !config_metadata_same_file(&temp_identity, &destination_now)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Installed config failed identity verification: %s",
                         config_path);
        goto document_fail;
    }

    /* AR-05 L11: per POSIX a rename() is only durable once the directory
     * holding the new entry is itself fsynced. toml_write_fd already fsyncs
     * the payload, but without this a crash right after a
     * reported-successful save could silently revert the directory entry to
     * the pre-rename config (lost-but-acknowledged update; never a torn
     * file). It is a required commit now: a caller must not print success for
     * an update the filesystem has not made durable. O_NOFOLLOW matches the
     * directory validation above. */
    if (!config_named_directory_matches(dir_path, &pinned_dir) ||
        config_io_fault(CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC,
                        "config document directory sync") ||
        fsync(dir_fd) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Could not durably commit config directory: %s",
                         dir_path);
        goto document_fail;
    }

    if (update_hint &&
        config_update_resume_hint(ctx, config_path, NULL) != 0) {
        goto document_fail;
    }
    close(dir_fd);
    log_info("Configuration document committed to: %s", config_path);
    return 0;

document_fail:
    {
        int saved_errno = errno ? errno : EIO;
        if (temp_exists && !have_temp_identity && temp_fd >= 0 &&
            fstat(temp_fd, &temp_identity) == 0) {
            have_temp_identity = true;
        }
        if (temp_fd >= 0) close(temp_fd);
        if (temp_exists && dir_fd >= 0) {
            struct stat cleanup_identity;
            if (have_temp_identity &&
                fstatat(dir_fd, temp_name, &cleanup_identity,
                        AT_SYMLINK_NOFOLLOW) == 0 &&
                config_metadata_same_file(&temp_identity,
                                          &cleanup_identity) &&
                config_metadata_file_is_safe(&cleanup_identity, true)) {
                if (unlinkat(dir_fd, temp_name, 0) == 0) {
                    temp_exists = false;
                }
            } else if (temp_registered) {
                /* A substituted pathname is not ours and must never remain in
                 * the path-only emergency cleanup registry. */
                signals_scratch_unregister(temp_path);
                temp_registered = false;
            }
        }
        if (temp_registered && !temp_exists) {
            signals_scratch_unregister(temp_path);
        }
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
    }
    return -1;
}

/* Fail-closed gate for full-config rewrites (AR-03 M8/M9): the on-disk file
 * may hold more than the in-memory view — account sections the load skipped
 * (bad key permissions, an unloadable field) and sections we don't model at
 * all (a typo'd [account.3], custom sections). config_save rebuilds from
 * settings + in-memory accounts only, so a rewrite while any exist would
 * silently erase them. Public so the add/edit/remove handlers can refuse
 * BEFORE their interactive work instead of discarding it at save time. */
int config_check_rewritable(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_check_rewritable");
        return -1;
    }
    if (ctx->accounts_skipped_on_load == 0 && ctx->unknown_sections_on_load == 0 &&
        ctx->unknown_keys_on_load == 0) {
        return 0;
    }
    /* AR-06 F02: unmodeled keys inside recognized sections are erased by a full
     * rewrite too. Report them explicitly; they can coexist with the other two
     * conditions, so handle them first. */
    if (ctx->unknown_keys_on_load > 0 &&
        ctx->accounts_skipped_on_load == 0 && ctx->unknown_sections_on_load == 0) {
        set_error(ERR_CONFIG_INVALID,
                  "%zu unrecognized key(s) inside recognized section(s) of %s would be lost "
                  "by a rewrite (gitswitch re-emits only the keys it models). Remove or fix "
                  "them, then retry.",
                  ctx->unknown_keys_on_load, ctx->config.config_path);
        return -1;
    }
    if (ctx->unknown_keys_on_load > 0) {
        set_error(ERR_CONFIG_INVALID,
                  "%zu account section(s) failed to load, %zu unrecognized section(s), and "
                  "%zu unrecognized key(s) exist in %s; rewriting the file would erase them. "
                  "Fix or remove them, then retry.",
                  ctx->accounts_skipped_on_load, ctx->unknown_sections_on_load,
                  ctx->unknown_keys_on_load, ctx->config.config_path);
        return -1;
    }
    if (ctx->accounts_skipped_on_load > 0 && ctx->unknown_sections_on_load > 0) {
        set_error(ERR_CONFIG_INVALID,
                  "%zu account section(s) failed to load and %zu unrecognized section(s) "
                  "exist in %s; rewriting the file would erase them. Fix them (or the "
                  "accounts' key files/permissions), then retry.",
                  ctx->accounts_skipped_on_load, ctx->unknown_sections_on_load,
                  ctx->config.config_path);
    } else if (ctx->accounts_skipped_on_load > 0) {
        set_error(ERR_CONFIG_INVALID,
                  "%zu account section(s) failed to load and would be lost by a rewrite "
                  "of %s. Fix them (or their key files/permissions), then retry.",
                  ctx->accounts_skipped_on_load, ctx->config.config_path);
    } else {
        set_error(ERR_CONFIG_INVALID,
                  "%zu unrecognized section(s) in %s would be lost by a rewrite "
                  "(gitswitch only understands [settings] and [accounts.<id>]). "
                  "Fix or remove them, then retry.",
                  ctx->unknown_sections_on_load, ctx->config.config_path);
    }
    return -1;
}

/* Save configuration to TOML file */
static int config_save_mode(const gitswitch_ctx_t *ctx,
                            const char *config_path,
                            bool update_hint,
                            bool *config_installed) {
    config_resume_hint_snapshot_t state_before = {0};
    toml_document_t *toml_doc;
    bool document_installed = false;
    bool state_installed = false;
    int result = -1;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save");
        return -1;
    }
    if (config_installed) {
        *config_installed = false;
    }

    /* GIT_SCOPE_SYSTEM remains part of the public observation model because
     * Git may report values originating there. It is not a persistable
     * gitswitch preference: the TOML schema and switch transaction support
     * only local/global. Reject the whole model before resume-state capture,
     * backup creation, or any document mutation. */
    if (!config_scope_is_persistable(ctx->config.default_scope)) {
        set_error(ERR_CONFIG_INVALID,
                  "settings.default_scope must be local or global");
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (!config_account_id_is_valid(ctx->accounts[i].id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account ID must be in 1..%u", UINT32_MAX);
            return -1;
        }
        if (!config_scope_is_persistable(ctx->accounts[i].preferred_scope)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account %u preferred scope must be local or global",
                      ctx->accounts[i].id);
            return -1;
        }
    }

    /* Refuse to rewrite the file when the load produced an incomplete view:
     * a full rewrite would silently erase the skipped/unknown sections.
     * Preserve the on-disk file and tell the user to fix them first. The
     * refusal returns -1, NOT the old 0 (AR-03 M9): an undifferentiated
     * success return made add/edit report "Account added successfully!"
     * at exit 0 while the change was discarded — scripted callers had no
     * way to detect the silent drop. */
    if (config_check_rewritable(ctx) != 0) {
        display_warning("Not saving config: %s", get_last_error()->message);
        return -1;
    }

    /* Initialize the heap-allocated TOML document exactly once. */
    toml_doc = config_document_alloc();
    if (!toml_doc) {
        return -1;
    }
    toml_init_document(toml_doc);

    /* Add/update settings section */
    if (toml_set_string(toml_doc, "settings", "default_scope",
                        config_scope_to_string(ctx->config.default_scope)) != 0) {
        goto cleanup;
    }

    /* Add current accounts */
    log_debug("About to save accounts to TOML doc with %zu sections", toml_doc->section_count);
    if (save_accounts_to_toml(ctx, toml_doc) != 0) {
        goto cleanup;
    }
    log_debug("After saving accounts, TOML doc has %zu sections", toml_doc->section_count);

    /* Multi-file commit order: install the small state first under an exact
     * before-image, then replace accounts.toml. If the config never installs,
     * restore the state bytes exactly. If config rename does install but its
     * directory sync reports uncertainty, retain matching new state so the two
     * visible files never disagree about the installed account model. */
    if (update_hint) {
        if (config_resume_hint_snapshot_capture_at(config_path,
                                                    &state_before) != 0) {
            goto cleanup;
        }
        if (config_update_resume_hint(ctx, config_path,
                                      &state_installed) != 0) {
            if (state_installed) {
                error_context_t state_error = *get_last_error();
                if (config_resume_hint_snapshot_restore_at(config_path,
                                                           &state_before) != 0) {
                    char restore_error[sizeof(g_last_error.message)];
                    safe_strncpy(restore_error, get_last_error()->message,
                                 sizeof(restore_error));
                    set_error(ERR_FILE_IO,
                              "Active-state commit failed after installation (%s), and rollback failed (%s)",
                              state_error.message, restore_error);
                } else {
                    g_last_error = state_error;
                }
            }
            goto cleanup;
        }
    }
    result = config_write_document_atomic(ctx, toml_doc, config_path, true,
                                          false, &document_installed);
    if (config_installed) {
        *config_installed = document_installed;
    }
    if (result != 0 && update_hint && state_installed &&
        !document_installed) {
        error_context_t write_error = *get_last_error();
        if (config_resume_hint_snapshot_restore_at(config_path,
                                                   &state_before) != 0) {
            char restore_error[sizeof(g_last_error.message)];
            safe_strncpy(restore_error, get_last_error()->message,
                         sizeof(restore_error));
            set_error(ERR_FILE_IO,
                      "Config write failed before installation (%s), and active-state rollback failed (%s)",
                      write_error.message, restore_error);
        } else {
            g_last_error = write_error;
        }
    }

cleanup:
    config_resume_hint_snapshot_clear(&state_before);
    config_document_free(toml_doc);
    return result;
}

int config_save(const gitswitch_ctx_t *ctx, const char *config_path) {
    return config_save_mode(ctx, config_path, true, NULL);
}

int config_save_transactional(const gitswitch_ctx_t *ctx,
                              const char *config_path,
                              bool *config_installed) {
    if (!config_installed) {
        set_error(ERR_INVALID_ARGS,
                  "NULL install-state output for transactional config save");
        return -1;
    }
    *config_installed = false;
    return config_save_mode(ctx, config_path, true, config_installed);
}

/* Persist only the consolidated state artifact. This intentionally does not
 * parse or replace accounts.toml: switch/reset state is orthogonal to the
 * account schema and remains writable even when a healthy subset was loaded
 * from a non-reconstructable config. */
static int config_save_active_account_mode(const gitswitch_ctx_t *ctx,
                                           const char *config_path,
                                           bool *config_installed) {
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save_active_account");
        return -1;
    }

    /* No file yet: nothing to preserve, and the write-back needs a document
     * to edit — the full rebuild is both safe and required to create one. */
    if (!path_exists(config_path)) {
        return config_save_mode(ctx, config_path, true,
                                config_installed);
    }
    return config_update_resume_hint(ctx, config_path, config_installed);
}

int config_save_active_account(const gitswitch_ctx_t *ctx,
                               const char *config_path) {
    return config_save_active_account_mode(ctx, config_path, NULL);
}

int config_save_active_account_transactional(const gitswitch_ctx_t *ctx,
                                             const char *config_path,
                                             bool *config_installed) {
    if (!config_installed) {
        set_error(ERR_INVALID_ARGS,
                  "NULL install-state output for transactional active save");
        return -1;
    }
    *config_installed = false;
    return config_save_active_account_mode(ctx, config_path,
                                           config_installed);
}

int config_restore_active_account(const gitswitch_ctx_t *ctx,
                                  const char *config_path) {
    return config_save_active_account_mode(ctx, config_path, NULL);
}

/* Create default configuration file */
int config_create_default(const char *config_path) {
    char config_dir[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN] = "";
    char temp_name[MAX_PATH_LEN] = "";
    const char *last_slash;
    const char *target_name;
    struct stat dir_identity;
    struct stat temp_identity;
    struct stat installed;
    size_t total = 0;
    size_t length = strlen(default_config_template);
    int dir_fd = -1;
    int fd = -1;
    bool registered = false;
    bool temp_exists = false;
    bool have_temp_identity = false;
    
    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_create_default");
        return -1;
    }
    
    last_slash = strrchr(config_path, '/');
    target_name = last_slash ? last_slash + 1 : config_path;
    if (target_name[0] == '\0') {
        set_error(ERR_INVALID_PATH, "Default config path has no file name");
        return -1;
    }
    if (!last_slash) {
        if (safe_strncpy(config_dir, ".", sizeof(config_dir)) != 0) {
            return -1;
        }
    } else {
        size_t dir_length = (size_t)(last_slash - config_path);
        if (dir_length == 0) dir_length = 1;
        if (dir_length >= sizeof(config_dir)) {
            set_error(ERR_INVALID_PATH, "Default config parent path is too long");
            return -1;
        }
        memcpy(config_dir, config_path, dir_length);
        config_dir[dir_length] = '\0';
    }
    
    /* Ensure directory exists */
    if (create_config_directory_secure(config_dir) != 0) {
        return -1;
    }

    if (validate_config_write_destination(config_path) != 0) {
        return -1;
    }
    if (lstat(config_path, &installed) == 0) {
        errno = EEXIST;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Configuration file already exists: %s", config_path);
        return -1;
    }
    if (errno != ENOENT || lstat(config_dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Default config parent is not a stable private directory: %s",
                  config_dir);
        return -1;
    }
    dir_fd = open(config_dir,
                  O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &installed) != 0 ||
        !config_metadata_dir_is_safe(&installed) ||
        !config_metadata_same_file(&dir_identity, &installed)) {
        int saved_errno = errno ? errno : ESTALE;
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot pin default config parent: %s", config_dir);
        return -1;
    }
    fd = config_create_private_temp_at(dir_fd, target_name, temp_name,
                                       sizeof(temp_name));
    if (fd < 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to create default config temporary file");
        goto default_fail;
    }
    temp_exists = true;
    if ((size_t)snprintf(temp_path, sizeof(temp_path), "%s%s%s", config_dir,
                         strcmp(config_dir, "/") == 0 ? "" : "/",
                         temp_name) >= sizeof(temp_path)) {
        set_error(ERR_INVALID_PATH, "Default config temporary path is too long");
        goto default_fail;
    }
    if (signals_scratch_register(temp_path) != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot register default config temporary file for cleanup");
        goto default_fail;
    }
    registered = true;
    if (fchmod(fd, PERM_USER_RW) != 0 || fstat(fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to secure default config temporary file");
        goto default_fail;
    }
    have_temp_identity = true;
    if (config_io_fault(CONFIG_IO_DEFAULT_AFTER_TEMP,
                        "default config temp creation")) {
        goto default_fail;
    }
    while (total < length) {
        ssize_t n = write(fd, default_config_template + total, length - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            set_system_error(ERR_CONFIG_WRITE_FAILED,
                             "Failed to write complete default config");
            goto default_fail;
        }
    }
    if (config_io_fault(CONFIG_IO_DEFAULT_AFTER_WRITE,
                        "default config write") ||
        config_io_fault(CONFIG_IO_DEFAULT_BEFORE_FILE_SYNC,
                        "default config payload sync") || fsync(fd) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to sync default config payload");
        goto default_fail;
    }
    if (config_io_fault(CONFIG_IO_DEFAULT_BEFORE_CLOSE,
                        "default config close")) {
        goto default_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to close default config temporary file");
        goto default_fail;
    }
    fd = -1;

    if (fstatat(dir_fd, temp_name, &installed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&installed, true) ||
        !config_metadata_same_file(&temp_identity, &installed) ||
        (size_t)installed.st_size != length ||
        !config_named_directory_matches(config_dir, &dir_identity) ||
        fstatat(dir_fd, target_name, &installed, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        set_error(ERR_CONFIG_WRITE_FAILED,
                  "Default config destination changed before installation");
        goto default_fail;
    }
    if (config_io_fault(CONFIG_IO_DEFAULT_BEFORE_RENAME,
                        "default config no-replace publication")) {
        goto default_fail;
    }
    if (config_publish_noreplace_at(dir_fd, temp_name, target_name) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to install default config without replacement");
        goto default_fail;
    }
    temp_exists = false;
    signals_scratch_unregister(temp_path);
    registered = false;

    if (fstatat(dir_fd, target_name, &installed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&installed, true) ||
        !config_metadata_same_file(&temp_identity, &installed) ||
        (size_t)installed.st_size != length) {
        set_error(ERR_CONFIG_WRITE_FAILED,
                  "Installed default config failed verification");
        goto default_fail;
    }
    if (!config_named_directory_matches(config_dir, &dir_identity) ||
        config_io_fault(CONFIG_IO_DEFAULT_BEFORE_DIR_SYNC,
                        "default config directory sync") ||
        fsync(dir_fd) != 0) {
        int saved_errno = errno;
        close(dir_fd);
        dir_fd = -1;
        errno = saved_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to sync default config directory");
        return -1;
    }
    close(dir_fd);
    dir_fd = -1;

    log_info("Created default configuration file: %s", config_path);
    return 0;

default_fail:
    {
        int saved_errno = errno ? errno : EIO;
        if (temp_exists && !have_temp_identity && fd >= 0 &&
            fstat(fd, &temp_identity) == 0) {
            have_temp_identity = true;
        }
        if (fd >= 0) close(fd);
        if (temp_exists && dir_fd >= 0 && have_temp_identity) {
            struct stat current_temp;
            if (fstatat(dir_fd, temp_name, &current_temp,
                        AT_SYMLINK_NOFOLLOW) == 0 &&
                config_metadata_file_is_safe(&current_temp, true) &&
                config_metadata_same_file(&temp_identity, &current_temp)) {
                (void)unlinkat(dir_fd, temp_name, 0);
            }
        }
        if (registered) signals_scratch_unregister(temp_path);
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
    }
    return -1;
}

/* Validate configuration structure */
static int validate_account_uniqueness(const gitswitch_ctx_t *ctx,
                                       const account_t *account,
                                       size_t ignore_index) {
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *other;

        if (i == ignore_index) continue;
        other = &ctx->accounts[i];
        if (other->id == account->id) {
            set_error(ERR_ACCOUNT_EXISTS,
                      "Account with ID %u already exists", account->id);
            return -1;
        }
        /* Isolation homes/sockets are name-keyed, including on filesystems
         * that fold ASCII case. */
        if (strcasecmp(other->name, account->name) == 0) {
            set_error(ERR_ACCOUNT_EXISTS,
                      "Account named '%s' already exists", account->name);
            return -1;
        }
        /* OpenSSH Host aliases are one shared user namespace. Their admitted
         * grammar is ASCII, so use a locale-independent case fold everywhere
         * admission or managed-block ownership is decided. */
        if (account->ssh_host_alias[0] != '\0' &&
            other->ssh_host_alias[0] != '\0' &&
            string_ascii_case_equal(other->ssh_host_alias,
                                    account->ssh_host_alias)) {
            set_error(ERR_ACCOUNT_EXISTS,
                      "SSH host alias '%s' is already owned by account '%s' "
                      "(aliases are case-insensitive)",
                      account->ssh_host_alias, other->name);
            return -1;
        }
    }
    return 0;
}

/* current_account is an optional interior pointer into the fixed account
 * array. Capture it only after proving address equality with a live slot; this
 * avoids dereferencing an already-stale external pointer. Rebinding by the
 * unique account ID keeps compaction/reload from silently retargeting it. */
static bool config_capture_current_id(const gitswitch_ctx_t *ctx,
                                      uint32_t *account_id) {
    size_t count;

    if (!ctx || !account_id || !ctx->current_account) return false;
    count = ctx->account_count < MAX_ACCOUNTS
        ? ctx->account_count : MAX_ACCOUNTS;
    for (size_t i = 0; i < count; i++) {
        if (ctx->current_account == &ctx->accounts[i]) {
            *account_id = ctx->accounts[i].id;
            return true;
        }
    }
    return false;
}

static void config_rebind_current_id(gitswitch_ctx_t *ctx,
                                     bool had_current,
                                     uint32_t account_id) {
    size_t count;

    if (!ctx) return;
    ctx->current_account = NULL;
    if (!had_current) return;
    count = ctx->account_count < MAX_ACCOUNTS
        ? ctx->account_count : MAX_ACCOUNTS;
    for (size_t i = 0; i < count; i++) {
        if (ctx->accounts[i].id == account_id) {
            ctx->current_account = &ctx->accounts[i];
            return;
        }
    }
}

int config_validate(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_validate");
        return -1;
    }
    if (!config_scope_is_persistable(ctx->config.default_scope)) {
        set_error(ERR_CONFIG_INVALID,
                  "settings.default_scope must be local or global");
        return -1;
    }
    
    /* Validate configuration file security */
    if (path_exists(ctx->config.config_path)) {
        if (validate_config_file_security(ctx->config.config_path) != 0) {
            return -1;
        }
    }
    
    /* Validate each account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (validate_account_security(&ctx->accounts[i]) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Account %u failed security validation", 
                      ctx->accounts[i].id);
            return -1;
        }
        if (validate_account_uniqueness(ctx, &ctx->accounts[i], i) != 0) {
            return -1;
        }
    }
    
    log_debug("Configuration validation passed for %zu accounts", ctx->account_count);
    return 0;
}

/* Get configuration file path */
int config_get_path(char *path_buffer, size_t buffer_size) {
    char config_dir[MAX_PATH_LEN];
    
    if (!path_buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_get_path");
        return -1;
    }
    
    /* Get config directory */
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    /* Build full path */
    return join_path(path_buffer, buffer_size, config_dir, DEFAULT_CONFIG_FILE);
}

/* Add new account to configuration */
int config_add_account(gitswitch_ctx_t *ctx, const account_t *account) {
    uint32_t current_id = 0;
    bool had_current;

    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_add_account");
        return -1;
    }
    
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    
    /* Validate account security */
    if (validate_account_security(account) != 0) {
        return -1;
    }
    
    if (validate_account_uniqueness(ctx, account, SIZE_MAX) != 0) return -1;

    had_current = config_capture_current_id(ctx, &current_id);

    /* Add account */
    ctx->accounts[ctx->account_count] = *account;
    ctx->account_count++;
    config_rebind_current_id(ctx, had_current, current_id);
    
    log_info("Added account: %s (%s)", account->name, account->description);
    return 0;
}

/* Remove account from configuration */
int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id) {
    size_t found_index = SIZE_MAX;
    uint32_t current_id = 0;
    bool had_current;
    
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_remove_account");
        return -1;
    }
    
    /* Find account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account_id) {
            found_index = i;
            break;
        }
    }
    
    if (found_index == SIZE_MAX) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found", account_id);
        return -1;
    }

    had_current = config_capture_current_id(ctx, &current_id);

    /* Clear sensitive data before removing */
    secure_zero_memory(&ctx->accounts[found_index], sizeof(account_t));
    
    /* Shift remaining accounts */
    for (size_t i = found_index; i < ctx->account_count - 1; i++) {
        ctx->accounts[i] = ctx->accounts[i + 1];
    }
    
    ctx->account_count--;
    
    /* Clear the last slot */
    memset(&ctx->accounts[ctx->account_count], 0, sizeof(account_t));
    config_rebind_current_id(ctx, had_current, current_id);
    
    log_info("Removed account with ID: %u", account_id);
    return 0;
}

/* Update existing account */
int config_update_account(gitswitch_ctx_t *ctx, const account_t *account) {
    account_t *existing_account = NULL;
    account_t replacement;
    size_t existing_index = SIZE_MAX;
    uint32_t current_id = 0;
    bool had_current;
    
    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_update_account");
        return -1;
    }
    if (!config_account_id_is_valid(account->id)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account ID must be in 1..%u", UINT32_MAX);
        return -1;
    }
    replacement = *account;
    
    /* Find existing account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account->id) {
            existing_account = &ctx->accounts[i];
            existing_index = i;
            break;
        }
    }
    
    if (!existing_account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found", account->id);
        return -1;
    }
    
    /* Validate new account data */
    if (validate_account_security(&replacement) != 0) {
        return -1;
    }
    if (validate_account_uniqueness(ctx, &replacement, existing_index) != 0) {
        return -1;
    }

    had_current = config_capture_current_id(ctx, &current_id);

    /* Clear old sensitive data */
    secure_zero_memory(existing_account, sizeof(account_t));
    
    /* Update with new data */
    *existing_account = replacement;
    config_rebind_current_id(ctx, had_current, current_id);
    
    log_info("Updated account: %s (%s)", replacement.name,
             replacement.description);
    return 0;
}

/* Find account by identifier, exact matches first to avoid selecting the wrong
 * identity. Precedence: numeric id -> exact name -> exact email -> unambiguous
 * substring of name/description. A substring that matches more than one account
 * is rejected as ambiguous (rather than silently returning the first). */
/* Exact-name lookup only (AR-06 F22). config.active_account is always stored as
 * an exact account name, but config_find_account resolves numeric-ID FIRST — so
 * a legacy all-digit account name (e.g. "2") persisted as the active account
 * would resume a DIFFERENT account whose id is 2. The boot-resume path must
 * resolve the persisted name literally, never through the id-first fuzzy
 * matcher. */
account_t *config_find_account_exact(gitswitch_ctx_t *ctx, const char *name) {
    if (!ctx || !name || !*name) {
        return NULL;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        /* AR-06 F45: account-name uniqueness is enforced case-INsensitively
         * (config_add_account), so the active-account resolve must match the
         * same way. A hand-edited active_account differing only in case (e.g.
         * "work" vs "Work") is still an unambiguous reference to the one
         * account, and strcmp would wrongly fail the resume. */
        if (strcasecmp(ctx->accounts[i].name, name) == 0) {
            return &ctx->accounts[i];
        }
    }
    return NULL;
}

/* Exact resolution only: canonical numeric ID -> exact name -> exact email.
 * Returns NULL if none match. Shared by config_find_account (which then falls
 * back to a substring search) and config_find_account_destructive (which does
 * NOT — AR-06 F50). */
typedef enum {
    EXACT_NONE = 0,
    EXACT_FOUND,
    EXACT_AMBIGUOUS
} exact_resolution_t;

static exact_resolution_t config_resolve_exact(gitswitch_ctx_t *ctx,
                                               const char *identifier,
                                               account_t **resolved) {
    char *endptr;
    unsigned long account_id;

    *resolved = NULL;

    /* 1. Exact numeric ID (only when the whole identifier is a canonical
     * decimal in range, int-id-02). The old bare strtoul + (uint32_t) cast
     * silently wrapped: "4294967297" truncated to 1 and "-4294967295"
     * converted to 1, so an out-of-range spelling could select an unrelated
     * account. Ids are stored canonically ([1-9][0-9]*), so anything else —
     * leading zero/sign/whitespace, out of range — is treated as a possible
     * name instead, never coerced onto an id. */
    if (identifier[0] >= '1' && identifier[0] <= '9') {
        bool all_digits = true;
        for (const char *p = identifier + 1; *p; p++) {
            if (!isdigit((unsigned char)*p)) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) {
            errno = 0;
            account_id = strtoul(identifier, &endptr, 10);
            if (errno == 0 && *endptr == '\0' && account_id <= UINT32_MAX) {
                for (size_t i = 0; i < ctx->account_count; i++) {
                    if (ctx->accounts[i].id == (uint32_t)account_id) {
                        *resolved = &ctx->accounts[i];
                        return EXACT_FOUND;
                    }
                }
            }
            /* No (valid) id match — fall through; may be a literal name. */
        }
    }

    /* 2. Exact name. */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, identifier) == 0) {
            *resolved = &ctx->accounts[i];
            return EXACT_FOUND;
        }
    }

    /* 3. Exact email. Emails are deliberately not unique account identity,
     * so collect every match and reject a selector that names more than one
     * account instead of silently choosing array order. */
    size_t email_matches = 0;
    char candidates[256] = "";
    size_t off = 0;
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].email, identifier) == 0) {
            if (email_matches == 0) *resolved = &ctx->accounts[i];
            email_matches++;
            if (off < sizeof(candidates) - 1) {
                int wrote = snprintf(candidates + off, sizeof(candidates) - off,
                                     "%s%s (id %u)", off ? ", " : "",
                                     ctx->accounts[i].name, ctx->accounts[i].id);
                if (wrote > 0) {
                    size_t available = sizeof(candidates) - off;
                    off += (size_t)wrote < available ? (size_t)wrote
                                                     : available - 1;
                }
            }
        }
    }
    if (email_matches == 1) return EXACT_FOUND;
    if (email_matches > 1) {
        *resolved = NULL;
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Email '%s' is ambiguous between %s; use an exact account "
                  "name or numeric id",
                  identifier, candidates);
        return EXACT_AMBIGUOUS;
    }
    return EXACT_NONE;
}

/* AR-06 F50: destructive resolution (remove/reset) — id/exact-name/exact-email
 * ONLY, never the substring arm. `remove work` must not delete an account whose
 * name or description merely CONTAINS "work" (e.g. "work-old", or a description
 * mentioning work) just because it happens to be the sole substring match. */
account_t *config_find_account_destructive(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *acct;
    exact_resolution_t resolution;
    if (!ctx || !identifier || !*identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_find_account_destructive");
        return NULL;
    }
    resolution = config_resolve_exact(ctx, identifier, &acct);
    if (resolution == EXACT_AMBIGUOUS) return NULL;
    if (resolution == EXACT_NONE) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "No account matches '%s' by ID, exact name, or exact email "
                  "(substring matching is disabled for destructive commands)",
                  identifier);
    }
    return acct;
}

account_t *config_find_account(gitswitch_ctx_t *ctx, const char *identifier) {
    account_t *match = NULL;
    size_t match_count = 0;
    exact_resolution_t resolution;

    if (!ctx || !identifier || !*identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_find_account");
        return NULL;
    }

    resolution = config_resolve_exact(ctx, identifier, &match);
    if (resolution == EXACT_FOUND) return match;
    if (resolution == EXACT_AMBIGUOUS) return NULL;
    match_count = 0;

    /* 4. Unambiguous substring of name or description. */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strstr(ctx->accounts[i].name, identifier) ||
            strstr(ctx->accounts[i].description, identifier)) {
            match = &ctx->accounts[i];
            match_count++;
        }
    }
    if (match_count == 1) {
        return match;
    }
    if (match_count > 1) {
        /* Show the matching candidates so the user can disambiguate. */
        char cands[256];
        size_t off = 0;
        for (size_t i = 0; i < ctx->account_count && off < sizeof(cands) - 1; i++) {
            if (strstr(ctx->accounts[i].name, identifier) ||
                strstr(ctx->accounts[i].description, identifier)) {
                off += (size_t)snprintf(cands + off, sizeof(cands) - off, "%s%s",
                                        off ? ", " : "", ctx->accounts[i].name);
            }
        }
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Ambiguous identifier '%s' matches: %s (use the exact name or numeric id)",
                  identifier, cands);
        return NULL;
    }

    /* No match at all — list what IS available as a hint. */
    {
        char avail[256];
        size_t off = 0;
        for (size_t i = 0; i < ctx->account_count && off < sizeof(avail) - 1; i++) {
            off += (size_t)snprintf(avail + off, sizeof(avail) - off, "%s%s",
                                    off ? ", " : "", ctx->accounts[i].name);
        }
        if (ctx->account_count == 0) {
            set_error(ERR_ACCOUNT_NOT_FOUND, "No accounts configured; run 'gitswitch add'");
        } else {
            set_error(ERR_ACCOUNT_NOT_FOUND, "Account not found: '%s'. Available: %s",
                      identifier, avail);
        }
    }
    return NULL;
}

/* Parse git scope from string */
git_scope_t config_parse_scope(const char *scope_str) {
    if (!scope_str) return GIT_SCOPE_LOCAL;
    
    if (strcmp(scope_str, "global") == 0) {
        return GIT_SCOPE_GLOBAL;
    } else if (strcmp(scope_str, "system") == 0) {
        return GIT_SCOPE_SYSTEM;
    } else {
        return GIT_SCOPE_LOCAL;
    }
}

/* Convert git scope to string */
const char *config_scope_to_string(git_scope_t scope) {
    switch (scope) {
        case GIT_SCOPE_GLOBAL: return "global";
        case GIT_SCOPE_SYSTEM: return "system";
        case GIT_SCOPE_LOCAL:
        default:
            return "local";
    }
}

/* Persisted account preferences and defaults intentionally support only the
 * two scopes the switch transaction can apply and roll back exactly. Keep the
 * system enum for observed Git origins, but never admit it into gitswitch's
 * own account model. */
static bool config_scope_is_persistable(git_scope_t scope) {
    return scope == GIT_SCOPE_LOCAL || scope == GIT_SCOPE_GLOBAL;
}

static bool config_account_id_is_valid(uint32_t account_id) {
    return account_id != 0;
}

typedef struct {
    char name[256];
    bool legacy;
    uint64_t seconds;
    uint32_t nanoseconds;
    uint64_t generation;
} config_backup_entry_t;

#define CONFIG_BACKUP_SCAN_MAX 128U

static int config_backup_split_path(const char *config_path, char *dir,
                                    size_t dir_size, char *prefix,
                                    size_t prefix_size) {
    const char *slash = strrchr(config_path, '/');
    const char *base = config_path;

    if (slash) {
        size_t dir_length = (size_t)(slash - config_path);
        if (dir_length == 0) dir_length = 1;
        if (dir_length >= dir_size) return -1;
        memcpy(dir, config_path, dir_length);
        dir[dir_length] = '\0';
        base = slash + 1;
    } else if (safe_strncpy(dir, ".", dir_size) != 0) {
        return -1;
    }
    if ((size_t)snprintf(prefix, prefix_size, "%s.backup.", base) >=
        prefix_size) {
        return -1;
    }
    return 0;
}

static bool config_parse_fixed_decimal(const char **cursor, size_t digits,
                                       uint64_t *value) {
    uint64_t parsed = 0;
    const char *p = *cursor;

    for (size_t i = 0; i < digits; i++) {
        unsigned int digit;
        if (p[i] < '0' || p[i] > '9') return false;
        digit = (unsigned int)(p[i] - '0');
        if (parsed > (UINT64_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *cursor = p + digits;
    *value = parsed;
    return true;
}

static bool config_backup_parse_new(const char *suffix,
                                    config_backup_entry_t *entry) {
    const char *p = suffix;
    uint64_t nanoseconds;

    if (!config_parse_fixed_decimal(&p, 20, &entry->seconds) || *p++ != '.' ||
        !config_parse_fixed_decimal(&p, 9, &nanoseconds) || *p++ != '.' ||
        !config_parse_fixed_decimal(&p, 20, &entry->generation) || *p != '\0' ||
        nanoseconds >= 1000000000ULL) {
        return false;
    }
    entry->nanoseconds = (uint32_t)nanoseconds;
    entry->legacy = false;
    return true;
}

static bool config_backup_parse_legacy(const char *suffix,
                                       config_backup_entry_t *entry) {
    const char *p = suffix;
    uint64_t date;
    uint64_t clock;
    uint64_t generation = 0;

    if (!config_parse_fixed_decimal(&p, 8, &date) || *p++ != '_' ||
        !config_parse_fixed_decimal(&p, 6, &clock)) {
        return false;
    }
    if (*p == '_') {
        const char *start = ++p;
        while (*p >= '0' && *p <= '9') p++;
        if (p == start || (size_t)(p - start) > 20) return false;
        p = start;
        if (!config_parse_fixed_decimal(&p,
                                        (size_t)(strchr(start, '\0') - start),
                                        &generation)) {
            return false;
        }
    }
    if (*p != '\0') return false;
    entry->legacy = true;
    entry->seconds = date * 1000000ULL + clock;
    entry->nanoseconds = 0;
    entry->generation = generation;
    return true;
}

static int config_backup_entry_cmp(const void *left, const void *right) {
    const config_backup_entry_t *a = left;
    const config_backup_entry_t *b = right;

    if (a->legacy != b->legacy) return a->legacy ? -1 : 1;
    if (a->seconds != b->seconds) return a->seconds < b->seconds ? -1 : 1;
    if (a->nanoseconds != b->nanoseconds) {
        return a->nanoseconds < b->nanoseconds ? -1 : 1;
    }
    if (a->generation != b->generation) {
        return a->generation < b->generation ? -1 : 1;
    }
    return strcmp(a->name, b->name);
}

static int config_backup_collect(const char *config_path,
                                 config_backup_entry_t *entries,
                                 size_t capacity, size_t *count,
                                 char *dir, size_t dir_size) {
    char prefix[256];
    size_t prefix_length;
    DIR *stream;
    struct dirent *item;

    *count = 0;
    if (config_backup_split_path(config_path, dir, dir_size, prefix,
                                 sizeof(prefix)) != 0) {
        set_error(ERR_INVALID_PATH, "Backup directory or prefix is too long");
        return -1;
    }
    prefix_length = strlen(prefix);
    stream = opendir(dir);
    if (!stream) {
        set_system_error(ERR_FILE_IO, "Cannot enumerate config backups");
        return -1;
    }
    while ((item = readdir(stream)) != NULL) {
        config_backup_entry_t parsed = {0};
        const char *suffix;
        struct stat st;
        if (strncmp(item->d_name, prefix, prefix_length) != 0) continue;
        suffix = item->d_name + prefix_length;
        if (!config_backup_parse_new(suffix, &parsed) &&
            !config_backup_parse_legacy(suffix, &parsed)) {
            continue; /* never delete an unrecognized same-prefix user file */
        }
        if (fstatat(dirfd(stream), item->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !config_metadata_file_is_safe(&st, true)) {
            closedir(stream);
            set_error(ERR_PERMISSION_DENIED,
                      "Config backup candidate is not a private owned regular file: %s",
                      item->d_name);
            return -1;
        }
        if (*count >= capacity ||
            safe_strncpy(parsed.name, item->d_name,
                         sizeof(parsed.name)) != 0) {
            closedir(stream);
            set_error(ERR_FILE_IO,
                      "Too many configuration backups to rotate safely");
            return -1;
        }
        entries[(*count)++] = parsed;
    }
    if (closedir(stream) != 0) {
        set_system_error(ERR_FILE_IO, "Cannot close config backup directory");
        return -1;
    }
    return 0;
}

static int config_backup_prune(const char *config_path, size_t keep) {
    config_backup_entry_t entries[CONFIG_BACKUP_SCAN_MAX];
    char dir[MAX_PATH_LEN];
    size_t count;
    int dir_fd;

    if (config_backup_collect(config_path, entries,
                              CONFIG_BACKUP_SCAN_MAX, &count,
                              dir, sizeof(dir)) != 0) {
        return -1;
    }
    if (count <= keep) return 0;
    qsort(entries, count, sizeof(entries[0]), config_backup_entry_cmp);
    dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot pin config backup directory");
        return -1;
    }
    for (size_t i = 0; i < count - keep; i++) {
        struct stat st;
        if (fstatat(dir_fd, entries[i].name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !config_metadata_file_is_safe(&st, true) ||
            unlinkat(dir_fd, entries[i].name, 0) != 0) {
            close(dir_fd);
            set_error(ERR_FILE_IO,
                      "Cannot safely prune old config backup: %s",
                      entries[i].name);
            return -1;
        }
    }
    if (fsync(dir_fd) != 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot durably prune config backups");
        return -1;
    }
    close(dir_fd);
    return 0;
}

static int config_backup_default_clock(uint64_t *seconds,
                                       uint32_t *nanoseconds) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) {
        return -1;
    }
    *seconds = (uint64_t)now.tv_sec;
    *nanoseconds = (uint32_t)now.tv_nsec;
    return 0;
}

/* Backup configuration file with a persisted monotonic generation. */
int config_backup(const char *config_path) {
    config_backup_entry_t entries[CONFIG_BACKUP_SCAN_MAX];
    toml_document_t *verify_doc = NULL;
    char backup_path[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    uint64_t seconds;
    uint32_t nanoseconds;
    uint64_t generation = 0;
    size_t count;
    int dir_fd = -1;
    int rc = -1;

    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_backup");
        return -1;
    }
    if (!path_exists(config_path)) {
        log_debug("Config file does not exist, no backup needed");
        return 0;
    }
    if ((g_config_backup_clock ? g_config_backup_clock(&seconds, &nanoseconds)
                               : config_backup_default_clock(&seconds,
                                                             &nanoseconds)) != 0 ||
        nanoseconds >= 1000000000U) {
        set_error(ERR_FILE_IO, "Cannot obtain a valid config backup clock");
        return -1;
    }
    if (config_backup_collect(config_path, entries,
                              CONFIG_BACKUP_SCAN_MAX, &count,
                              dir, sizeof(dir)) != 0) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        if (entries[i].legacy) continue;
        if (entries[i].seconds > seconds ||
            (entries[i].seconds == seconds &&
             entries[i].nanoseconds > nanoseconds)) {
            if (entries[i].generation == UINT64_MAX) {
                set_error(ERR_FILE_IO, "Config backup generation exhausted");
                return -1;
            }
            seconds = entries[i].seconds;
            nanoseconds = entries[i].nanoseconds;
            generation = entries[i].generation + 1;
        } else if (entries[i].seconds == seconds &&
                   entries[i].nanoseconds == nanoseconds &&
                   entries[i].generation >= generation) {
            if (entries[i].generation == UINT64_MAX) {
                set_error(ERR_FILE_IO, "Config backup generation exhausted");
                return -1;
            }
            generation = entries[i].generation + 1;
        }
    }

    for (;;) {
        int needed = snprintf(backup_path, sizeof(backup_path),
                              "%s.backup.%020llu.%09u.%020llu",
                              config_path, (unsigned long long)seconds,
                              nanoseconds,
                              (unsigned long long)generation);
        if (needed < 0 || (size_t)needed >= sizeof(backup_path)) {
            set_error(ERR_INVALID_PATH, "Config backup path is too long");
            return -1;
        }
        errno = 0;
        if (copy_file_nofollow(config_path, backup_path) == 0) break;
        if (errno != EEXIST || generation == UINT64_MAX) return -1;
        generation++;
    }

    dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 ||
        config_io_fault(CONFIG_IO_BACKUP_BEFORE_DIR_SYNC,
                        "config backup directory sync") ||
        fsync(dir_fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot durably commit config backup directory");
        goto backup_fail;
    }
    close(dir_fd);
    dir_fd = -1;

    if (config_io_fault(CONFIG_IO_BACKUP_BEFORE_REOPEN,
                        "config backup reopen verification")) {
        goto backup_fail;
    }
    verify_doc = config_document_alloc();
    if (!verify_doc || config_read_document(backup_path, verify_doc) != 0) {
        if (!verify_doc && get_last_error()->code == ERR_SUCCESS) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot allocate config backup verification document");
        }
        goto backup_fail;
    }
    config_document_free(verify_doc);
    verify_doc = NULL;

    if (config_backup_prune(config_path, 5) != 0) {
        return -1;
    }
    log_info("Created durable configuration backup: %s", backup_path);
    return 0;

backup_fail:
    if (verify_doc) config_document_free(verify_doc);
    if (dir_fd >= 0) close(dir_fd);
    if (unlink(backup_path) == 0) {
        int cleanup_fd = open(dir,
                              O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (cleanup_fd >= 0) {
            (void)fsync(cleanup_fd);
            close(cleanup_fd);
        }
    }
    return rc;
}

/* Internal helper functions implementation */

/* Open the config file for reading and validate the opened fd
 * (cfg-symlink-01/02). The previous implementation stat()'d the path — which
 * follows symlinks, so a symlinked accounts.toml was validated against its
 * (possibly foreign) target — and the eventual open happened later on the
 * same path, leaving a classic TOCTOU. Here: lstat() first to refuse a
 * symlink with a precise message, open with O_NOFOLLOW to close the race at
 * the syscall level, and check every security property with fstat() on the
 * fd the caller will actually read. Returns the open fd, or -1. */
static int open_config_validated(const char *config_path) {
    struct stat link_stat, file_stat;
    int fd;

    if (lstat(config_path, &link_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot access config file: %s", config_path);
        return -1;
    }
    if (S_ISLNK(link_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file is a symlink; refusing to follow it: %s", config_path);
        return -1;
    }

    fd = open(config_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot open config file: %s", config_path);
        return -1;
    }
    if (fstat(fd, &file_stat) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot stat config file: %s", config_path);
        goto fail;
    }

    /* Must be a plain regular file (not a fifo/device that could stall or
     * feed us attacker-timed content) */
    if (!S_ISREG(file_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED, "Configuration file is not a regular file: %s", config_path);
        goto fail;
    }

    /* Check file permissions - must not be readable by group/others */
    if (file_stat.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file has unsafe permissions: %o (should be 600)",
                  file_stat.st_mode & 0777);
        goto fail;
    }

    /* Check ownership - must be owned by current user */
    if (file_stat.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED, "Configuration file not owned by current user");
        goto fail;
    }

    /* Check file size is reasonable */
    if (file_stat.st_size > TOML_MAX_FILE_SIZE) {
        set_error(ERR_CONFIG_INVALID, "Configuration file too large: %ld bytes",
                  (long)file_stat.st_size);
        goto fail;
    }

    return fd;

fail:
    close(fd);
    return -1;
}

/* Validate configuration file security (path-level check for callers that do
 * not read the file themselves; config_load keeps and uses the fd instead) */
static int validate_config_file_security(const char *config_path) {
    int fd = open_config_validated(config_path);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

/* Validate the destination of a config write (cfg-symlink-01): the final
 * path, if present, must be a real regular file we own — never a symlink —
 * and the parent directory must be a non-symlink directory owned by us that
 * nobody else can write. The directory check is what makes the temp+rename
 * in config_save sound: rename() gives no O_NOFOLLOW-style protection, so
 * the only defense is ensuring no other principal can plant or retarget
 * names inside the directory between our checks and the rename. */
static int validate_config_write_destination(const char *config_path) {
    char dir[MAX_PATH_LEN];
    struct stat st;
    const char *slash;

    /* Final path: allow "absent" (first save), refuse symlinks and files we
     * don't own. lstat (not stat) so the link itself is what we judge. */
    if (lstat(config_path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to write config through a symlink: %s", config_path);
            return -1;
        }
        if (!S_ISREG(st.st_mode)) {
            set_error(ERR_PERMISSION_DENIED,
                      "Config path exists but is not a regular file: %s", config_path);
            return -1;
        }
        if (st.st_uid != getuid()) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to overwrite a config file owned by another user: %s", config_path);
            return -1;
        }
    } else if (errno != ENOENT) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Cannot examine config path: %s", config_path);
        return -1;
    }

    /* Parent directory: must be ours, a real directory, and not writable by
     * group/others (a foreign-writable directory defeats every per-file
     * check above) */
    slash = strrchr(config_path, '/');
    if (slash) {
        size_t dir_len = (size_t)(slash - config_path);
        if (dir_len == 0) {
            dir_len = 1; /* config directly under "/" — keep the root slash */
        }
        if (dir_len >= sizeof(dir)) {
            set_error(ERR_INVALID_ARGS, "Config directory path too long");
            return -1;
        }
        memcpy(dir, config_path, dir_len);
        dir[dir_len] = '\0';
    } else {
        strcpy(dir, ".");
    }

    if (lstat(dir, &st) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Cannot examine config directory: %s", dir);
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Config directory is a symlink; refusing to write into it: %s", dir);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        set_error(ERR_PERMISSION_DENIED, "Config directory is not a directory: %s", dir);
        return -1;
    }
    if (st.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED,
                  "Config directory not owned by current user: %s", dir);
        return -1;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Config directory is writable by group/others: %s", dir);
        return -1;
    }

    return 0;
}

/* Copy src to dst without following symlinks on either side, creating dst
 * O_EXCL with mode 0600 (cfg-symlink-01). utils' copy_file() open()s both
 * paths plainly, which follows symlinks; for config backups both ends are
 * attacker-influenceable names, so this local variant is used instead. */
static int copy_file_nofollow(const char *src_path, const char *dst_path) {
    struct stat before;
    struct stat after;
    struct stat named;
    struct stat destination_identity;
    char buf[4096];
    int sfd = -1;
    int dfd = -1;
    ssize_t n;
    bool destination_created = false;
    bool have_destination_identity = false;
    bool copied_first_chunk = false;
    bool failure_reported = false;

    if (lstat(src_path, &named) != 0 ||
        !config_metadata_file_is_safe(&named, true)) {
        set_system_error(ERR_FILE_IO,
                         "Cannot identify private backup source: %s", src_path);
        return -1;
    }
    sfd = open(src_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot open backup source (symlink?): %s", src_path);
        return -1;
    }
    if (fstat(sfd, &before) != 0 ||
        !config_metadata_file_is_safe(&before, true) ||
        !config_metadata_snapshot_same(&before, &named)) {
        errno = ESTALE;
        set_error(ERR_FILE_IO,
                  "Backup source changed before copying: %s", src_path);
        failure_reported = true;
        goto fail;
    }

    /* O_EXCL never follows a symlink and fails if the name exists at all, so
     * a pre-planted backup destination cannot redirect the write. */
    dfd = open(dst_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (dfd < 0) {
        /* Preserve the create errno (esp. EEXIST) across set_system_error/close
         * so callers can distinguish a name collision from a real failure and
         * retry with a fresh name (AR-06 F46/F47). */
        int saved = errno;
        set_system_error(ERR_FILE_IO, "Cannot create backup file: %s", dst_path);
        close(sfd);
        errno = saved;
        return -1;
    }
    destination_created = true;
    if (fchmod(dfd, PERM_USER_RW) != 0 ||
        fstat(dfd, &destination_identity) != 0 ||
        !config_metadata_file_is_safe(&destination_identity, true)) {
        goto fail;
    }
    have_destination_identity = true;

    while ((n = read(sfd, buf, sizeof(buf))) != 0) {
        ssize_t off = 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            goto fail;
        }
        while (off < n) {
            ssize_t w = write(dfd, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                goto fail;
            }
            if (w == 0) {
                errno = EIO;
                goto fail;
            }
            off += w;
        }
        if (!copied_first_chunk) {
            copied_first_chunk = true;
            if (config_io_fault(CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK,
                                "config backup source consistency checkpoint")) {
                failure_reported = true;
                goto fail;
            }
        }
    }

    errno = 0;
    if (fstat(sfd, &after) != 0 || lstat(src_path, &named) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_file_is_safe(&named, true) ||
        !config_metadata_snapshot_same(&before, &after) ||
        !config_metadata_snapshot_same(&before, &named)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Configuration changed while backup was copied: %s",
                         src_path);
        failure_reported = true;
        goto fail;
    }
    if (close(sfd) != 0) {
        sfd = -1;
        goto fail;
    }
    sfd = -1;
    if (config_io_fault(CONFIG_IO_BACKUP_BEFORE_FILE_SYNC,
                        "config backup payload sync")) {
        failure_reported = true;
        goto fail;
    }
    if (fsync(dfd) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to sync backup file: %s",
                         dst_path);
        failure_reported = true;
        goto fail;
    }
    if (close(dfd) != 0) {
        dfd = -1;
        set_system_error(ERR_FILE_IO, "Failed to finalize backup file: %s", dst_path);
        failure_reported = true;
        goto fail;
    }
    dfd = -1;
    return 0;

fail:
    {
        int saved_errno = errno ? errno : EIO;
        if (!failure_reported) {
            set_system_error(ERR_FILE_IO, "Failed to copy backup: %s -> %s",
                             src_path, dst_path);
        }
        if (sfd >= 0) close(sfd);
        if (destination_created && !have_destination_identity && dfd >= 0 &&
            fstat(dfd, &destination_identity) == 0 &&
            config_metadata_file_is_safe(&destination_identity, true)) {
            have_destination_identity = true;
        }
        if (dfd >= 0) close(dfd);
        if (destination_created && have_destination_identity) {
            struct stat current_destination;
            if (lstat(dst_path, &current_destination) == 0 &&
                config_metadata_same_file(&destination_identity,
                                          &current_destination)) {
                (void)unlink(dst_path);
            }
        }
        errno = saved_errno;
    }
    return -1;
}

/* Create config directory with secure permissions */
static int create_config_directory_secure(const char *config_dir) {
    struct stat path_st;

    if (!config_dir || config_dir[0] == '\0') {
        set_error(ERR_INVALID_ARGS, "Invalid configuration directory path");
        return -1;
    }

    /* Inspect the final component without following it. Parent symlinks (for
     * example a user-managed ~/.config link) remain supported deliberately;
     * only the final gitswitch component is subject to this policy. */
    if (lstat(config_dir, &path_st) != 0) {
        if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect configuration directory: %s",
                             config_dir);
            return -1;
        }
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        if (lstat(config_dir, &path_st) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect created configuration directory: %s",
                             config_dir);
            return -1;
        }
        log_info("Created configuration directory: %s", config_dir);
    }

    if (S_ISLNK(path_st.st_mode) || !S_ISDIR(path_st.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing non-directory or symlinked configuration directory: %s",
                  config_dir);
        return -1;
    }

#if GITSWITCH_HAVE_DIRECTORY_NOFOLLOW
    /* Pin the verified final directory before correcting its mode. O_NOFOLLOW
     * prevents a final-component swap to a symlink; fstat plus the identity
     * comparison also detects replacement by a different real directory. */
    int fd = open(config_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot open configuration directory safely: %s",
                         config_dir);
        return -1;
    }

    struct stat fd_st;
    if (fstat(fd, &fd_st) != 0) {
        close(fd);
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot verify configuration directory: %s",
                         config_dir);
        return -1;
    }
    if (!S_ISDIR(fd_st.st_mode) || fd_st.st_dev != path_st.st_dev ||
        fd_st.st_ino != path_st.st_ino) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration directory changed while being verified: %s",
                  config_dir);
        return -1;
    }

    if ((fd_st.st_mode & 077) != 0) {
        if (fchmod(fd, PERM_USER_RWX) != 0) {
            close(fd);
            set_system_error(ERR_PERMISSION_DENIED,
                             "Failed to secure configuration directory: %s",
                             config_dir);
            return -1;
        }
        if (fstat(fd, &fd_st) != 0) {
            close(fd);
            set_system_error(ERR_PERMISSION_DENIED,
                             "Cannot verify secured configuration directory: %s",
                             config_dir);
            return -1;
        }
        if (!S_ISDIR(fd_st.st_mode) || (fd_st.st_mode & 077) != 0) {
            close(fd);
            set_error(ERR_PERMISSION_DENIED,
                      "Configuration directory permissions remain unsafe: %s",
                      config_dir);
            return -1;
        }
        log_warning("Fixed configuration directory permissions");
    }

    /* Ensure the pathname still names the descriptor we verified. */
    struct stat final_st;
    if (lstat(config_dir, &final_st) != 0) {
        close(fd);
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot re-check configuration directory: %s",
                         config_dir);
        return -1;
    }
    if (!S_ISDIR(final_st.st_mode) || final_st.st_dev != fd_st.st_dev ||
        final_st.st_ino != fd_st.st_ino) {
        close(fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration directory changed while being secured: %s",
                  config_dir);
        return -1;
    }
    close(fd);
#else
    /* Without a descriptor-based no-follow open, a pathname chmod could be
     * redirected between validation and mutation. Newly-created directories
     * already use 0700; fail closed for a loose pre-existing directory. */
    if ((path_st.st_mode & 077) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration directory permissions are unsafe and this "
                  "platform cannot tighten them without following paths: %s",
                  config_dir);
        return -1;
    }

    struct stat final_st;
    if (lstat(config_dir, &final_st) != 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot re-check configuration directory: %s",
                         config_dir);
        return -1;
    }
    if (!S_ISDIR(final_st.st_mode) || final_st.st_dev != path_st.st_dev ||
        final_st.st_ino != path_st.st_ino) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration directory changed while being secured: %s",
                  config_dir);
        return -1;
    }
#endif

    return 0;
}

/* Tri-state fetch for one account field. toml_get_string returns -1 both for
 * an ABSENT key and for a present value it refuses to hand over (too long for
 * the destination, or bytes its sanitizer would alter — AR-03 M6). The two
 * must not be conflated: "absent" takes the field's benign default, while
 * "present but unloadable" means the in-memory account is no longer a
 * faithful view of the file — treating it as absent silently drops the field
 * and the next full save persists the default over the user's bytes. The
 * getter sets an error exactly in its refusal cases and stays silent for
 * absent keys, so the error state disambiguates. */
typedef enum {
    FIELD_ABSENT = 0,
    FIELD_LOADED,
    FIELD_UNLOADABLE
} field_state_t;

static field_state_t get_account_field(const toml_document_t *doc, const char *section,
                                       const char *key, char *out, size_t out_size) {
    clear_error();
    if (toml_get_string(doc, section, key, out, out_size) == 0) {
        return FIELD_LOADED;
    }
    if (get_last_error()->code == ERR_SUCCESS) {
        return FIELD_ABSENT;
    }
    return FIELD_UNLOADABLE;
}

/* Load accounts from TOML document */
/* AR-06 F02: is `key` one gitswitch models inside recognized `section`? Keys
 * that aren't are re-emitted by nothing on the next config_save (which rebuilds
 * from settings + the in-memory accounts), so an unmodeled key — a typo like
 * `ssh_kye`, or a key a newer version wrote before a downgrade — is silently
 * dropped. The set mirrors exactly what load_accounts_from_toml and the
 * settings loader read. */
static bool config_key_is_modeled(const char *section, const char *key) {
    if (strcmp(section, "settings") == 0) {
        return strcmp(key, "default_scope") == 0 ||
               strcmp(key, "active_account") == 0;
    }
    /* An [accounts.<id>] section. */
    static const char *const account_keys[] = {
        "name", "email", "description", "preferred_scope",
        "ssh_key", "ssh_host", "ssh_hostname", "gpg_key",
        "gpg_signing_enabled", NULL
    };
    for (size_t i = 0; account_keys[i]; i++) {
        if (strcmp(key, account_keys[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Count unmodeled keys inside recognized sections into unknown_keys_on_load and
 * warn per key, so config_check_rewritable blocks a full rewrite that would
 * erase them — symmetric with the AR-03 M8 unknown-SECTION treatment, one level
 * down (AR-06 F02). Unknown SECTIONS are handled separately in
 * load_accounts_from_toml. */
static void count_unknown_keys(gitswitch_ctx_t *ctx, const toml_document_t *doc) {
    for (size_t s = 0; s < doc->section_count; s++) {
        const toml_section_t *sec = &doc->sections[s];
        bool recognized = (strcmp(sec->name, "settings") == 0) ||
                          string_starts_with(sec->name, "accounts.");
        if (!recognized) {
            continue; /* an unknown section: already counted elsewhere */
        }
        for (size_t k = 0; k < sec->key_count && k < TOML_MAX_KEYS_PER_SECTION; k++) {
            if (!sec->keys[k].is_set) {
                continue;
            }
            if (!config_key_is_modeled(sec->name, sec->keys[k].key)) {
                ctx->unknown_keys_on_load++;
                display_warning("Unrecognized key '%s' in section [%s] of the config file. "
                                "It is preserved for now, but account changes are blocked "
                                "until you remove it — a full save would erase it.",
                                sec->keys[k].key, sec->name);
            }
        }
    }
}

static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc) {
    char sections[TOML_MAX_SECTIONS][TOML_MAX_SECTION_LEN];
    size_t section_count;

    if (toml_get_sections(doc, sections, TOML_MAX_SECTIONS, &section_count) != 0) {
        set_error(ERR_CONFIG_INVALID, "Failed to get sections from TOML document");
        return -1;
    }

    ctx->account_count = 0;

    for (size_t i = 0; i < section_count; i++) {
        if (string_starts_with(sections[i], "accounts.")) {
            account_t account;
            uint32_t account_id;
            char temp_str[256];
            bool temp_bool;
            field_state_t fs;

            /* Parse account ID from section name. Count a bad section as
             * skipped-on-load (not just logged): config_save refuses to
             * rewrite when sections were skipped, so a section with a
             * non-canonical id ("accounts.01") or an out-of-range id is
             * surfaced to the user instead of being silently erased by the
             * next save (int-id-01/02). */
            if (parse_account_id_from_section(sections[i], &account_id) != 0) {
                ctx->accounts_skipped_on_load++;
                display_warning("Invalid account section [%s] was skipped: the id must be "
                                "a canonical decimal in 1..%u (no leading zeros or signs).",
                                sections[i], UINT32_MAX);
                continue;
            }

            /* Initialize account */
            memset(&account, 0, sizeof(account));
            account.id = account_id;
            account.preferred_scope = GIT_SCOPE_LOCAL; /* Default */

            /* Load required fields. Skipped, not dropped: whether the field
             * is MISSING or present-but-refused by the getter (a name over
             * MAX_NAME_LEN, or bytes that cannot round-trip — both schema-
             * valid, so the whole-file parse succeeded), the in-memory set
             * is now an incomplete view of the file. Without the skip count,
             * config_save's refuse-to-rewrite guard read zero and the very
             * next save permanently erased this section (AR-02 #5). Warn on
             * stderr with the getter's own reason so the ACTUAL cause —
             * missing vs too long vs unrepresentable bytes — is visible. */
            fs = get_account_field(doc, sections[i], "name", account.name, sizeof(account.name));
            if (fs != FIELD_LOADED) {
                ctx->accounts_skipped_on_load++;
                if (fs == FIELD_ABSENT) {
                    display_warning("Account section [%s] was skipped: 'name' is missing. "
                                    "Fix it in the config file.", sections[i]);
                } else {
                    display_warning("Account section [%s] was skipped: %s",
                                    sections[i], get_last_error()->message);
                }
                continue;
            }

            fs = get_account_field(doc, sections[i], "email", account.email, sizeof(account.email));
            if (fs != FIELD_LOADED) {
                ctx->accounts_skipped_on_load++;
                if (fs == FIELD_ABSENT) {
                    display_warning("Account section [%s] ('%s') was skipped: 'email' is "
                                    "missing. Fix it in the config file.",
                                    sections[i], account.name);
                } else {
                    display_warning("Account section [%s] ('%s') was skipped: %s",
                                    sections[i], account.name, get_last_error()->message);
                }
                continue;
            }

            /* Optional fields: absent is fine (benign default), but a value
             * that EXISTS and cannot be loaded faithfully skips the whole
             * account (counted, like name/email above). The old code treated
             * both outcomes as "absent", so an unloadable description
             * silently became the name — and the next save persisted that
             * fallback over the user's bytes — while an unloadable ssh_host
             * silently dropped the alias that decides which ~/.ssh/config
             * Host entry a switch rewrites. */
            fs = get_account_field(doc, sections[i], "description",
                                   account.description, sizeof(account.description));
            if (fs == FIELD_ABSENT) {
                /* Use name as description if not provided */
                safe_strncpy(account.description, account.name, sizeof(account.description));
            } else if (fs == FIELD_UNLOADABLE) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) was skipped: %s",
                                account.name, account_id, get_last_error()->message);
                continue;
            }

            /* The description is printed raw by list/status/whoami. Today
             * toml_get_string's own round-trip check refuses control and
             * non-ASCII-hostile bytes, but that is a retrieval-layer detail
             * of another module — the config layer must guarantee for itself
             * that nothing it hands to display can drive the terminal
             * (tty-escape). The description is display-only, so strip here
             * at the trust boundary; the identity-bearing name is instead
             * *rejected* by validate_account_security below if it is unsafe. */
            if (sanitize_tty_text(account.description)) {
                display_warning("Account '%s' (id %u): removed terminal control bytes "
                                "from description.",
                                account.name[0] ? account.name : "?", account_id);
            }

            fs = get_account_field(doc, sections[i], "preferred_scope", temp_str, sizeof(temp_str));
            if (fs == FIELD_LOADED) {
                account.preferred_scope = config_parse_scope(temp_str);
            } else if (fs == FIELD_UNLOADABLE) {
                /* Falling back to the local default would silently change
                 * WHICH git config (repo vs user-wide) a switch writes. */
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) was skipped: %s",
                                account.name, account_id, get_last_error()->message);
                continue;
            }

            /* SSH configuration */
            fs = get_account_field(doc, sections[i], "ssh_key",
                                   account.ssh_key_path, sizeof(account.ssh_key_path));
            if (fs == FIELD_UNLOADABLE) {
                /* Loading the account WITHOUT its key would switch git
                 * identity while leaving the previous account's agent live. */
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) was skipped: %s",
                                account.name, account_id, get_last_error()->message);
                continue;
            }
            if (fs == FIELD_LOADED && strlen(account.ssh_key_path) > 0) {
                account.ssh_enabled = true;

                /* Expand path if needed */
                char expanded_path[MAX_PATH_LEN];
                if (expand_path(account.ssh_key_path, expanded_path, sizeof(expanded_path)) == 0) {
                    safe_strncpy(account.ssh_key_path, expanded_path, sizeof(account.ssh_key_path));
                }

                /* `ssh_host` remains the managed OpenSSH Host alias. The
                 * canonical destination is modeled separately so the writer
                 * can emit HostName instead of trying to resolve the alias
                 * literally (AR-07 M13). */
                field_state_t alias_state = get_account_field(
                    doc, sections[i], "ssh_host", account.ssh_host_alias,
                    sizeof(account.ssh_host_alias));
                if (alias_state == FIELD_UNLOADABLE) {
                    ctx->accounts_skipped_on_load++;
                    display_warning("Account '%s' (id %u) was skipped: %s",
                                    account.name, account_id, get_last_error()->message);
                    continue;
                }

                field_state_t hostname_state = get_account_field(
                    doc, sections[i], "ssh_hostname", account.ssh_hostname,
                    sizeof(account.ssh_hostname));
                if (hostname_state == FIELD_UNLOADABLE) {
                    ctx->accounts_skipped_on_load++;
                    display_warning("Account '%s' (id %u) was skipped: %s",
                                    account.name, account_id,
                                    get_last_error()->message);
                    continue;
                }

                /* Backward compatibility for files written before M13:
                 * an ordinary literal alias was also the only available
                 * destination, so preserve it byte-for-byte as HostName and
                 * surface the migration. A wildcard Host pattern does not
                 * name one destination and must never be copied into the
                 * literal HostName slot. Skip it and engage the existing
                 * no-rewrite guard until the user adds ssh_hostname. */
                if (hostname_state == FIELD_ABSENT &&
                    alias_state == FIELD_LOADED &&
                    account.ssh_host_alias[0] != '\0') {
                    if (!toml_validate_ssh_hostname(account.ssh_host_alias)) {
                        ctx->accounts_skipped_on_load++;
                        display_warning(
                            "Account '%s' (id %u) was skipped: legacy ssh_host "
                            "'%s' is a Host pattern, not one canonical destination; "
                            "add ssh_hostname to this account.",
                            account.name, account_id,
                            account.ssh_host_alias);
                        continue;
                    }
                    if (safe_strncpy(account.ssh_hostname,
                                     account.ssh_host_alias,
                                     sizeof(account.ssh_hostname)) != 0) {
                        ctx->accounts_skipped_on_load++;
                        display_warning(
                            "Account '%s' (id %u) was skipped: legacy ssh_host "
                            "is too long to preserve as ssh_hostname.",
                            account.name, account_id);
                        continue;
                    }
                    display_warning(
                        "Account '%s' (id %u) uses legacy ssh_host without "
                        "ssh_hostname; treating '%s' as the canonical "
                        "destination. Save the account to persist the new key.",
                        account.name, account_id, account.ssh_hostname);
                }
            }

            /* GPG configuration */
            fs = get_account_field(doc, sections[i], "gpg_key",
                                   account.gpg_key_id, sizeof(account.gpg_key_id));
            if (fs == FIELD_UNLOADABLE) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) was skipped: %s",
                                account.name, account_id, get_last_error()->message);
                continue;
            }
            if (fs == FIELD_LOADED && strlen(account.gpg_key_id) > 0) {
                account.gpg_enabled = true;

                /* GPG signing preference */
                if (toml_get_boolean(doc, sections[i], "gpg_signing_enabled", &temp_bool) != 0) {
                    clear_error();
                } else {
                    account.gpg_signing_enabled = temp_bool;
                }
            }

            /* Reject duplicate name (case-insensitive), id, or managed SSH
             * alias against already-
             * loaded accounts. config_add_account enforces this for the
             * interactive path, but the load path bypassed it entirely — and a
             * hand-edited accounts.toml is fully user-controlled. Two accounts
             * sharing a name would share one GNUPGHOME (<base>/<name>) and one
             * ssh-agent.<name>.sock, silently collapsing the very isolation the
             * tool exists to provide; a shared id breaks id-based lookup. Skip
             * (not drop) so config_save refuses to rewrite and erase the file. */
            bool dup = false;
            for (size_t j = 0; j < ctx->account_count; j++) {
                if (ctx->accounts[j].id == account.id ||
                    strcasecmp(ctx->accounts[j].name, account.name) == 0 ||
                    (ctx->accounts[j].ssh_host_alias[0] != '\0' &&
                     account.ssh_host_alias[0] != '\0' &&
                     string_ascii_case_equal(
                         ctx->accounts[j].ssh_host_alias,
                         account.ssh_host_alias))) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) duplicates the name, id, or SSH "
                                "host alias of an earlier account and was skipped; those "
                                "identifiers must be unique because SSH/GPG isolation and "
                                "the managed SSH config namespace are keyed by them.",
                                account.name[0] ? account.name : "?", account_id);
            }
            /* Validate and add account */
            else if (validate_account_security(&account) == 0) {
                if (ctx->account_count < MAX_ACCOUNTS) {
                    ctx->accounts[ctx->account_count] = account;
                    ctx->account_count++;
                    log_debug("Loaded account: %s (%s)", account.name, account.description);
                } else {
                    log_error("Too many accounts, skipping account %u", account_id);
                    ctx->accounts_skipped_on_load++;
                }
            } else {
                /* Skipped, not dropped: record it so config_save refuses to
                 * rewrite the file and silently erase this section. Warn on
                 * stderr (not just the log filter) so the transient cause —
                 * e.g. an unmounted key path or a key chmod'd to 644 — is
                 * visible rather than turning into quiet data loss. */
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) in the config failed validation and was "
                                "skipped: %s", account.name[0] ? account.name : "?",
                                account_id, get_last_error()->message);
            }
        } else if (strcmp(sections[i], "settings") != 0) {
            /* AR-03 M8: a section we don't model — a typo'd [account.3] or
             * [Accounts.3], a custom section, keys before the first header —
             * is invisible to config_save's rebuild (settings + in-memory
             * accounts only), so the next full save would silently delete it
             * and five saves later the rotating backups age out too. Count
             * it so the refuse-to-rewrite guard covers it exactly like a
             * skipped account section. */
            ctx->unknown_sections_on_load++;
            display_warning("Unrecognized section [%s] in the config file (gitswitch only "
                            "understands [settings] and [accounts.<id>]). It is preserved, "
                            "but account changes are blocked until you fix or remove it.",
                            sections[i]);
        }
    }

    log_info("Loaded %zu accounts from configuration", ctx->account_count);
    return 0;
}

/* Parse account ID from section name like "accounts.1" */
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id) {
    const char *dot_pos, *id_str;
    char *endptr;
    unsigned long parsed_id;

    if (!section_name || !account_id) return -1;

    dot_pos = strchr(section_name, '.');
    if (!dot_pos || dot_pos == section_name + strlen(section_name) - 1) {
        return -1;
    }
    id_str = dot_pos + 1;

    /* Canonical decimal only (int-id-01/02). Bare strtoul also accepts
     * leading whitespace and a sign — "-4294967295" wraps to 1 via unsigned
     * conversion — and leading zeros let "accounts.01" alias "accounts.1",
     * so two visually distinct sections could collide on one id. Requiring
     * [1-9][0-9]* gives every id exactly one on-disk spelling. */
    if (*id_str < '1' || *id_str > '9') {
        return -1;
    }
    for (const char *p = id_str + 1; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            return -1;
        }
    }

    /* Range-check before narrowing: an id like 4294967296 must be rejected,
     * not truncated to 0/onto another account. errno catches overflow past
     * ULONG_MAX (where strtoul clamps and the > UINT32_MAX test alone would
     * still fire on LP64 but not on ILP32). */
    errno = 0;
    parsed_id = strtoul(id_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || parsed_id == 0 || parsed_id > UINT32_MAX) {
        return -1;
    }

    *account_id = (uint32_t)parsed_id;
    return 0;
}

/* utf8_decode and tty_safe_codepoint moved to utils.c so the TOML parser's
 * raw-buffer charset gate shares the exact same strict decoding policy as
 * this trust boundary (AR-02 #6). Declared in utils.h. */

/* tty-escape policy for untrusted strings that reach the terminal, applied
 * at the trust boundary (config load) rather than in the display layer:
 * keep only well-formed UTF-8 whose codepoints pass tty_safe_codepoint().
 * Dropped: C0 controls, DEL, C1 controls whether spelled as a raw
 * 0x80-0x9F byte or as their two-byte UTF-8 form (0xC2 0x80-0x9F), and any
 * byte that is not part of a well-formed sequence — malformed bytes are
 * exactly where raw C1 controls hide in non-UTF-8 data, and a terminal in a
 * legacy single-byte locale interprets them directly. Legitimate multi-byte
 * UTF-8 (accented letters, CJK, emoji) passes through byte-identical.
 *
 * sanitize_tty_text strips in place (display-only fields); returns true if
 * anything was removed. The shared text_is_tty_safe utility merely reports
 * for identity-bearing fields, where silent rewriting would change which
 * key/socket paths the name maps to. */
static bool sanitize_tty_text(char *text) {
    unsigned char *src = (unsigned char *)text;
    unsigned char *dst = (unsigned char *)text;
    size_t remaining = strlen(text);
    bool modified = false;

    while (remaining > 0) {
        uint32_t cp;
        size_t len = utf8_decode(src, remaining, &cp);
        if (len == 0) {
            src++; /* malformed byte: drop it and resync */
            remaining--;
            modified = true;
        } else if (!tty_safe_codepoint(cp)) {
            src += len;
            remaining -= len;
            modified = true;
        } else {
            if (dst != src) memmove(dst, src, len);
            dst += len;
            src += len;
            remaining -= len;
        }
    }
    *dst = '\0';
    return modified;
}

/* Reject a value that cannot survive the config round trip: since AR-03 M6,
 * toml_get_string FAILS (rather than repairs) any value its sanitizer would
 * alter — a quote, backslash, control byte, or malformed UTF-8. The writer
 * escapes such bytes faithfully, so without this write-side gate gitswitch
 * could persist a name or description that its own next load then refuses to
 * hand back, skipping the account it just created. Refuse at the API every
 * add/edit passes through instead, naming the field. */
static int validate_field_roundtrips(const char *field_name, const char *value) {
    char sanitized[MAX_DESC_LEN];

    if (toml_sanitize_string(value, sanitized, sizeof(sanitized)) != 0 ||
        strcmp(sanitized, value) != 0) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account %s contains characters that cannot round-trip through "
                  "the config file (quote, backslash, control, or invisible byte)",
                  field_name);
        return -1;
    }
    return 0;
}

/* Validate account security */
static int validate_account_security(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];

    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to validate");
        return -1;
    }

    if (!config_account_id_is_valid(account->id)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account ID must be in 1..%u", UINT32_MAX);
        return -1;
    }

    if (!config_scope_is_persistable(account->preferred_scope)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account preferred scope must be local or global");
        return -1;
    }

    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account name");
        return -1;
    }

    if (validate_field_roundtrips("name", account->name) != 0 ||
        validate_field_roundtrips("description", account->description) != 0 ||
        validate_field_roundtrips("SSH host alias", account->ssh_host_alias) != 0 ||
        validate_field_roundtrips("SSH canonical hostname",
                                  account->ssh_hostname) != 0) {
        return -1;
    }

    if (account->ssh_host_alias[0] != '\0' &&
        !toml_validate_ssh_host_alias(account->ssh_host_alias)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Invalid SSH host alias (ASCII letters, digits, '.', '-', "
                  "'_', '*', and '?' only): %s",
                  account->ssh_host_alias);
        return -1;
    }
    if (account->ssh_hostname[0] != '\0' &&
        !toml_validate_ssh_hostname(account->ssh_hostname)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Invalid SSH canonical hostname (ASCII letters, digits, "
                  "'.', '-', '_', and ':' only): %s",
                  account->ssh_hostname);
        return -1;
    }
    if (account->ssh_host_alias[0] != '\0' &&
        account->ssh_hostname[0] == '\0' &&
        !toml_validate_ssh_hostname(account->ssh_host_alias)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Wildcard SSH host alias '%s' requires an explicit "
                  "ssh_hostname canonical destination",
                  account->ssh_host_alias);
        return -1;
    }

    /* validate_name rejects C0 controls and DEL but deliberately permits
     * bytes >= 0x80 so international names work — and that range is exactly
     * where C1 terminal controls (0x9B one-byte CSI, ...) live. The name is
     * echoed raw by list/status/whoami, so additionally require well-formed
     * UTF-8 free of C1 controls (tty-escape). Unlike the display-only
     * description, the name is rejected rather than silently rewritten:
     * it keys the SSH/GPG isolation paths, so a rewrite would change which
     * GNUPGHOME/agent socket the account maps to.
     *
     * Known limitation (locale-unicode-identity-2): no Unicode NFC/NFD
     * normalization is performed — "é" (U+00E9) and "e" + combining accent
     * (U+0065 U+0301) are treated as distinct names and produce distinct
     * isolation paths. Only byte-wise plus ASCII case-insensitive
     * uniqueness is guaranteed; proper normalization needs Unicode tables
     * we won't take a dependency for. */
    if (!text_is_tty_safe(account->name)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account name contains terminal control bytes or malformed UTF-8");
        return -1;
    }

    /* The description is sanitized (stripped) at config load; anything that
     * still carries control bytes here came from a programmatic caller, so
     * fail closed rather than let it reach the terminal (tty-escape). */
    if (!text_is_tty_safe(account->description)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "Account description contains terminal control bytes or malformed UTF-8");
        return -1;
    }

    if (!validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address: %s", account->email);
        return -1;
    }
    
    /* Validate SSH key if configured */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (expand_path(account->ssh_key_path, expanded_path, sizeof(expanded_path)) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH key path: %s", account->ssh_key_path);
            return -1;
        }

        /* M5 (write entry, config half): the loader skips any account whose
         * persisted ssh_key exceeds 256 chars, so admitting a longer path
         * through this gate — which every add/edit/load passes — would save
         * an account this same tool then refuses to load back. accounts.c's
         * prompts enforce the identical cap interactively; this covers the
         * programmatic path, and the ~-stored key whose $HOME expansion
         * pushes the persisted absolute path past the cap. */
        if (strlen(expanded_path) > 256) {
            set_error(ERR_ACCOUNT_INVALID,
                      "SSH key path too long (%zu chars, max 256): %s",
                      strlen(expanded_path), expanded_path);
            return -1;
        }

        /* One authoritative descriptor-backed validator owns the admission
         * contract for load/add/edit/switch: regular file, current uid,
         * owner-only mode, and private-key content from the same open object. */
        if (ssh_validate_key_file(expanded_path) != 0) return -1;
    }
    
    /* Validate GPG key if configured */
    if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
        if (!validate_key_id(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID: %s", account->gpg_key_id);
            return -1;
        }
    }
    
    return 0;
}

/* Save accounts to TOML document */
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc) {
    char section_name[64];
    
    if (!ctx || !doc) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to save_accounts_to_toml");
        return -1;
    }
    
    log_debug("Saving %zu accounts to TOML (doc has %zu sections before save)", 
              ctx->account_count, doc->section_count);
    
    /* Save each account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];
        const char *ssh_hostname = account->ssh_hostname;

        if (!config_account_id_is_valid(account->id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account ID must be in 1..%u", UINT32_MAX);
            return -1;
        }
        if (!config_scope_is_persistable(account->preferred_scope)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account %u preferred scope must be local or global",
                      account->id);
            return -1;
        }
        
        log_debug("Saving account %zu: ID=%u, name='%s', email='%s'", 
                  i, account->id, account->name, account->email);
        
        /* Create section name */
        if ((size_t)snprintf(section_name, sizeof(section_name), "accounts.%u", account->id) >= sizeof(section_name)) {
            set_error(ERR_ACCOUNT_INVALID, "Account ID too large: %u", account->id);
            return -1;
        }
        
        log_debug("Creating/updating section: %s", section_name);
        
        /* Save required fields */
        if (toml_set_string(doc, section_name, "name", account->name) != 0) {
            set_error(ERR_CONFIG_INVALID, "Failed to save account name");
            return -1;
        }
        
        if (toml_set_string(doc, section_name, "email", account->email) != 0) {
            set_error(ERR_CONFIG_INVALID, "Failed to save account email");
            return -1;
        }
        
        /* Save optional fields */
        if (strlen(account->description) > 0) {
            toml_set_string(doc, section_name, "description", account->description);
        }
        
        toml_set_string(doc, section_name, "preferred_scope", 
                       config_scope_to_string(account->preferred_scope));
        
        /* Save SSH configuration. Alias-only in-memory callers are treated
         * like legacy files when the alias is one literal destination; the
         * save canonicalizes them by emitting ssh_hostname. Wildcard aliases
         * cannot be inferred and fail before writing a misleading HostName. */
        if (account->ssh_host_alias[0] != '\0' &&
            !toml_validate_ssh_host_alias(account->ssh_host_alias)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH host alias: %s",
                      account->ssh_host_alias);
            return -1;
        }
        if (ssh_hostname[0] == '\0' &&
            account->ssh_host_alias[0] != '\0') {
            if (!toml_validate_ssh_hostname(account->ssh_host_alias)) {
                set_error(ERR_ACCOUNT_INVALID,
                          "Wildcard SSH host alias '%s' requires an explicit "
                          "ssh_hostname canonical destination",
                          account->ssh_host_alias);
                return -1;
            }
            ssh_hostname = account->ssh_host_alias;
        }
        if (ssh_hostname[0] != '\0' &&
            !toml_validate_ssh_hostname(ssh_hostname)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Invalid SSH canonical hostname: %s", ssh_hostname);
            return -1;
        }

        /* Save SSH configuration */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            if (toml_set_string(doc, section_name, "ssh_key",
                                account->ssh_key_path) != 0) {
                set_error(ERR_CONFIG_INVALID, "Failed to save SSH key path");
                return -1;
            }
            
            if (strlen(account->ssh_host_alias) > 0) {
                if (toml_set_string(doc, section_name, "ssh_host",
                                    account->ssh_host_alias) != 0) {
                    set_error(ERR_CONFIG_INVALID,
                              "Failed to save SSH host alias");
                    return -1;
                }
            }
            if (ssh_hostname[0] != '\0') {
                if (toml_set_string(doc, section_name, "ssh_hostname",
                                    ssh_hostname) != 0) {
                    set_error(ERR_CONFIG_INVALID,
                              "Failed to save SSH canonical hostname");
                    return -1;
                }
            }
        }
        
        /* Save GPG configuration */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
            /* The selector field is intentionally large enough for `0x` plus
             * a 64-hex v5 fingerprint.  Validate the semantic digit bound at
             * the persistence boundary as well as add/edit/load so an
             * in-memory caller cannot write a file the next load rejects. */
            if (!validate_key_id(account->gpg_key_id)) {
                set_error(ERR_ACCOUNT_INVALID, "Invalid GPG key ID: %s",
                          account->gpg_key_id);
                return -1;
            }
            toml_set_string(doc, section_name, "gpg_key", account->gpg_key_id);
            toml_set_boolean(doc, section_name, "gpg_signing_enabled", account->gpg_signing_enabled);
        }
    }
    
    log_debug("Completed saving %zu accounts. TOML doc now has %zu sections", 
              ctx->account_count, doc->section_count);
    
    /* Debug: List all sections in the document */
    for (size_t i = 0; i < doc->section_count; i++) {
        log_debug("TOML section %zu: '%s' (is_set=%s)", 
                  i, doc->sections[i].name, doc->sections[i].is_set ? "true" : "false");
    }
    
    return 0;
}
