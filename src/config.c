/* Configuration file management with comprehensive security validation
 * Implements secure TOML-based configuration for gitswitch-c
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

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
#include <stdarg.h>
#include <limits.h>
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
#include "freebsd_compat.h"
#include "toml_parser.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "signals.h"
#include "ssh_manager.h"

#define CONFIG_RETIREMENT_SETTLED_SLOTS 4096U
#define CONFIG_SWITCH_SETTLED_PREFIX ".gitswitch-switch-settled-"
#define CONFIG_RESUME_HINT_SETTLED_PREFIX \
    ".gitswitch-resume-hint-settled-"
#define CONFIG_DOCUMENT_SETTLED_PREFIX ".gitswitch-config-temp-settled-"
#define CONFIG_BACKUP_SETTLED_PREFIX ".gitswitch-backup-settled-"
#define CONFIG_REPLACE_BEFORE_FINAL_PROOF 1
#define CONFIG_REPLACE_AFTER_EXCHANGE 2

#ifdef GITSWITCH_TESTING
typedef void (*resume_hint_test_hook_fn)(int stage);
resume_hint_test_hook_fn gitswitch_test_set_resume_hint_hook(
    resume_hint_test_hook_fn hook);
int gitswitch_test_retirement_guard_directory_fd(
    const config_retirement_guard_t *guard);
int gitswitch_test_switch_guard_directory_fd(
    const config_switch_guard_t *guard);

static resume_hint_test_hook_fn g_resume_hint_test_hook;

typedef int (*config_replace_test_hook_fn)(
    int stage, int directory_fd, const char *destination);
config_replace_test_hook_fn gitswitch_test_set_config_replace_hook(
    config_replace_test_hook_fn hook);
static config_replace_test_hook_fn g_config_replace_test_hook;

config_replace_test_hook_fn gitswitch_test_set_config_replace_hook(
    config_replace_test_hook_fn hook) {
    config_replace_test_hook_fn previous = g_config_replace_test_hook;

    g_config_replace_test_hook = hook;
    return previous;
}

#define CONFIG_REPLACE_TEST_CHECKPOINT(stage, fd, destination) \
    (g_config_replace_test_hook                                \
         ? g_config_replace_test_hook((stage), (fd), (destination)) \
         : 0)

typedef enum {
    CONFIG_PUBLISH_TEST_SOURCE_UNLINK = 0,
    CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK,
    CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE,
    CONFIG_PUBLISH_TEST_RETAINED_SOURCE_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_SOURCE_PIN
} config_publish_test_stage_t;
typedef int (*config_publish_test_hook_fn)(
    config_publish_test_stage_t stage, int directory_fd,
    const char *source, const char *destination);
config_publish_test_hook_fn gitswitch_test_set_config_publish_hook(
    config_publish_test_hook_fn hook);
static config_publish_test_hook_fn g_config_publish_test_hook;

config_publish_test_hook_fn gitswitch_test_set_config_publish_hook(
    config_publish_test_hook_fn hook) {
    config_publish_test_hook_fn previous = g_config_publish_test_hook;

    g_config_publish_test_hook = hook;
    return previous;
}

#define CONFIG_PUBLISH_TEST_CHECKPOINT(stage, fd, source, destination) \
    (g_config_publish_test_hook                                      \
         ? g_config_publish_test_hook(                              \
               (stage), (fd), (source), (destination))              \
         : 0)

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

#ifdef GITSWITCH_TESTING
typedef enum {
    RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE = 0,
    RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
    RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
    RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
    RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
    RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
    RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_READ_AFTER_CLOSE,
    RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
    RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
    RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
    RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
    RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
    RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
    RETIREMENT_GUARD_CLEAR_AFTER_PREPARED_PUBLISH
} retirement_guard_clear_test_stage_t;
typedef int (*retirement_guard_clear_test_hook_fn)(
    retirement_guard_clear_test_stage_t stage, int directory_fd,
    const char *marker_name);
retirement_guard_clear_test_hook_fn
gitswitch_test_set_retirement_guard_clear_hook(
    retirement_guard_clear_test_hook_fn hook);
unsigned int gitswitch_test_set_retirement_settled_slot_limit(
    unsigned int limit);
static retirement_guard_clear_test_hook_fn
    g_retirement_guard_clear_test_hook;
static unsigned int g_retirement_settled_slot_limit =
    CONFIG_RETIREMENT_SETTLED_SLOTS;

unsigned int gitswitch_test_set_retirement_settled_slot_limit(
    unsigned int limit) {
    unsigned int previous = g_retirement_settled_slot_limit;

    g_retirement_settled_slot_limit =
        limit > 0U && limit <= CONFIG_RETIREMENT_SETTLED_SLOTS
            ? limit
            : CONFIG_RETIREMENT_SETTLED_SLOTS;
    return previous;
}

retirement_guard_clear_test_hook_fn
gitswitch_test_set_retirement_guard_clear_hook(
    retirement_guard_clear_test_hook_fn hook) {
    retirement_guard_clear_test_hook_fn previous =
        g_retirement_guard_clear_test_hook;
    g_retirement_guard_clear_test_hook = hook;
    return previous;
}

static int config_retirement_guard_clear_test_checkpoint(
    retirement_guard_clear_test_stage_t stage, int directory_fd,
    const char *marker_name) {
    if (!g_retirement_guard_clear_test_hook) return 0;
    if (g_retirement_guard_clear_test_hook(
            stage, directory_fd, marker_name) == 0) {
        return 0;
    }
    if (errno == 0) errno = EIO;
    return -1;
}

#define RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(stage, fd, name)             \
    config_retirement_guard_clear_test_checkpoint((stage), (fd), (name))
#define CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT() \
    g_retirement_settled_slot_limit
#else
#define CONFIG_REPLACE_TEST_CHECKPOINT(stage, fd, destination) \
    ((void)(stage), (void)(fd), (void)(destination), 0)
enum {
    CONFIG_PUBLISH_TEST_SOURCE_UNLINK = 0,
    CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK,
    CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE,
    CONFIG_PUBLISH_TEST_RETAINED_SOURCE_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
    CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC,
    CONFIG_PUBLISH_TEST_BEFORE_FIXED_RETIRE,
    CONFIG_PUBLISH_TEST_BEFORE_SOURCE_PIN
};
#define CONFIG_PUBLISH_TEST_CHECKPOINT(stage, fd, source, destination) \
    ((void)(stage), (void)(fd), (void)(source),                       \
     (void)(destination), 0)
enum {
    RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE = 0,
    RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
    RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
    RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
    RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
    RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
    RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_READ_AFTER_CLOSE,
    RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
    RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
    RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
    RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
    RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
    RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
    RETIREMENT_GUARD_CLEAR_AFTER_PREPARED_PUBLISH
};
#define RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(stage, fd, name)             \
    ((void)(stage), (void)(fd), (void)(name), 0)
#define CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT() \
    CONFIG_RETIREMENT_SETTLED_SLOTS
#endif

#ifdef GITSWITCH_TESTING
typedef enum {
    SWITCH_GUARD_INSTALL_BEFORE_INITIAL_FSTAT = 0,
    SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC,
    SWITCH_GUARD_CLEAR_AFTER_UNLINK,
    SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ,
    SWITCH_GUARD_RECONCILE_AFTER_NORMALIZE_SYNC,
    SWITCH_GUARD_RETAIN_AFTER_MARKER_SYNC,
    SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF
} switch_guard_test_stage_t;
typedef int (*switch_guard_test_hook_fn)(
    switch_guard_test_stage_t stage, int directory_fd);
switch_guard_test_hook_fn gitswitch_test_set_switch_guard_hook(
    switch_guard_test_hook_fn hook);
static switch_guard_test_hook_fn g_switch_guard_test_hook;

switch_guard_test_hook_fn gitswitch_test_set_switch_guard_hook(
    switch_guard_test_hook_fn hook) {
    switch_guard_test_hook_fn previous =
        g_switch_guard_test_hook;
    g_switch_guard_test_hook = hook;
    return previous;
}

static int config_switch_guard_test_checkpoint(
    switch_guard_test_stage_t stage, int directory_fd) {
    if (!g_switch_guard_test_hook) return 0;
    if (g_switch_guard_test_hook(stage, directory_fd) == 0) {
        return 0;
    }
    if (errno == 0) errno = EIO;
    set_system_error(
        ERR_FILE_IO,
        "Injected switch guard lifecycle failure");
    return -1;
}

#define SWITCH_GUARD_TEST_CHECKPOINT(stage, fd) \
    config_switch_guard_test_checkpoint((stage), (fd))
#else
enum {
    SWITCH_GUARD_INSTALL_BEFORE_INITIAL_FSTAT = 0,
    SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC,
    SWITCH_GUARD_CLEAR_AFTER_UNLINK,
    SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ,
    SWITCH_GUARD_RECONCILE_AFTER_NORMALIZE_SYNC,
    SWITCH_GUARD_RETAIN_AFTER_MARKER_SYNC,
    SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF
};
#define SWITCH_GUARD_TEST_CHECKPOINT(stage, fd) \
    ((void)(stage), (void)(fd), 0)
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
"# ssh_host is the Git remote alias; ssh_hostname is its host-only destination\n"
"# Use unbracketed IPv6 when needed; appended ports are not supported\n"
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
static int copy_file_nofollow(const char *src_path, const char *dst_path,
                              struct stat *created_identity,
                              struct stat *source_identity);
static int config_backup_internal(const char *config_path,
                                  struct stat *publication_identity);
static bool sanitize_tty_text(char *text);
static int create_config_directory_secure(const char *config_dir);
static int config_load_mode(gitswitch_ctx_t *ctx, const char *config_path,
                            bool apply_active_state, bool detect_runtime);
static int config_load_mode_inplace(gitswitch_ctx_t *ctx,
                                    const char *config_path,
                                    bool apply_active_state,
                                    bool detect_runtime);
static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static void count_unknown_keys(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc);
static int config_materialize_missing_incarnations(
    gitswitch_ctx_t *ctx, const publication_ledger_t *publications);
static int config_validate_live_publication_bindings(
    const gitswitch_ctx_t *ctx,
    const publication_ledger_t *publications);
static int config_generate_incarnation(
    const gitswitch_ctx_t *ctx, const publication_ledger_t *publications,
    char generated[MAX_ACCOUNTS][ACCOUNT_INCARNATION_LEN],
    size_t generated_count, char out[ACCOUNT_INCARNATION_LEN]);
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id);
static int validate_account_security(const account_t *account);
static int normalize_account_model_for_admission(account_t *account);
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
typedef enum {
    CONFIG_SOURCE_GENERATION_UNBOUND = 0,
    CONFIG_SOURCE_GENERATION_REQUIRE_LOADED,
    CONFIG_SOURCE_GENERATION_REQUIRE_FULL_SAVE
} config_source_generation_requirement_t;

typedef struct {
    const config_retirement_owner_t *owners;
    size_t owner_count;
    const config_retirement_destination_t *destinations;
    size_t destination_count;
} config_retirement_refresh_request_t;

static int config_update_resume_hint(const gitswitch_ctx_t *ctx,
                                     const char *config_path,
                                     bool *state_installed,
                                     config_source_generation_requirement_t
                                         generation_requirement,
                                     config_resume_hint_snapshot_t *rollback_snapshot,
                                     const publication_record_t *publication,
                                     const config_retirement_refresh_request_t
                                         *retirement_refresh);
static bool config_metadata_same_file(const struct stat *a,
                                      const struct stat *b);
static void config_unlink_created_temp(const char *path,
                                       const struct stat *created,
                                       bool have_created_identity);
static bool config_metadata_snapshot_same(const struct stat *a,
                                          const struct stat *b);
static bool config_is_namespace_change_errno(int error);
static int config_require_loaded_source_generation(
    const gitswitch_ctx_t *ctx, const char *config_path,
    struct stat *accepted_generation);
static int config_reprove_loaded_source(
    const char *config_path, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_generation);
static int config_admit_full_save_generation(const gitswitch_ctx_t *ctx,
                                             const char *config_path);
static int config_require_full_save_generation_snapshot(
    const gitswitch_ctx_t *ctx, const char *config_path,
    bool destination_existed, const struct stat *destination);
static bool config_metadata_ctime_only_change(const struct stat *before,
                                              const struct stat *after);
static int config_resume_hint_snapshot_classify_at(
    const char *config_path,
    const config_resume_hint_snapshot_t *snapshot,
    config_active_rollback_state_t *state);
static bool config_refresh_publication_identity(
    const char *config_path, const char *backup_path,
    const struct stat *copied_source, const struct stat *backup_identity,
    struct stat *publication_identity);
static bool config_metadata_dir_is_safe(const struct stat *st);
static bool config_metadata_file_is_safe(const struct stat *st,
                                         bool require_private_mode);
static bool config_named_directory_matches(const char *path,
                                           const struct stat *pinned);
static int config_create_private_temp_at(int dir_fd, const char *target_name,
                                         char *temp_name,
                                         size_t temp_name_size);
typedef enum {
    CONFIG_PUBLISH_MOVED = 0,
    CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED = 1,
    CONFIG_PUBLISH_OUTCOME_UNCERTAIN = 2
} config_publish_outcome_t;
static int config_publish_noreplace_at(
    int dir_fd, const char *source, const char *destination,
    const struct stat *expected_source,
    struct stat *retained_source);
static int config_reprove_published_file_at(
    int directory_fd, const char *name,
    const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_identity);
static int config_reprove_existing_file_at(
    int directory_fd, const char *name,
    const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_identity);
static bool config_alias_metadata_is_safe(const struct stat *st);
static bool config_reconcile_target_is_safe(const struct stat *st);
static int config_reprove_private_alias_at(
    int directory_fd, const char *name,
    const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_identity);
static bool config_pread_full(int fd, unsigned char *buffer, size_t length,
                              off_t offset);

typedef struct {
    bool exists;
    bool legacy_needs_only;
    bool inactive_tombstone;
    char needs[8];
    char active_account[MAX_NAME_LEN];
} config_active_state_t;

#define CONFIG_ACTIVE_STATE_HEADER_MAX (MAX_NAME_LEN + 64U)
#define CONFIG_ACTIVE_STATE_MAX \
    (PUBLICATION_LEDGER_MAX_BYTES + CONFIG_ACTIVE_STATE_HEADER_MAX)
/* Hex encoding can double every bounded string. Two complete record structs
 * plus fixed grammar/identity overhead is therefore a conservative upper
 * bound for one additional canonical record. */
#define CONFIG_PUBLICATION_RECORD_RESERVE \
    (sizeof(publication_record_t) * 2U + 8192U)

typedef struct {
    bool existed;
    struct stat metadata;
    unsigned char *data;
    size_t length;
} config_active_state_generation_t;

static void config_active_state_generation_clear(
    config_active_state_generation_t *generation);

static int config_read_active_state(const char *config_path,
                                    config_active_state_t *state,
                                    bool require_private_mode,
                                    config_active_state_generation_t *generation,
                                    publication_ledger_t *publications);

typedef enum {
    CONFIG_INIT_NORMAL = 0,
    CONFIG_INIT_READONLY,
    CONFIG_INIT_RUNTIME_READONLY,
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
                                kind == CONFIG_INIT_NORMAL ||
                                    kind == CONFIG_INIT_RUNTIME_READONLY);
    } else {
        log_info("Configuration file not found: %s", config_path);
        /* File creation remains deferred to a command that actually needs it. */
        return 0;
    }
}

#if !defined(__FreeBSD__)
static int config_select_settled_name_at(
    int dir_fd, const char *prefix, unsigned int slots,
    char *selected, size_t selected_size) {
    if (dir_fd < 0 || !prefix || !selected || selected_size == 0U ||
        slots == 0U) {
        errno = EINVAL;
        return -1;
    }
    selected[0] = '\0';
    for (unsigned int slot = 0U; slot < slots; slot++) {
        struct stat named;
        int written = snprintf(
            selected, selected_size, "%s%u", prefix, slot);

        if (written < 0 || (size_t)written >= selected_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        errno = 0;
        if (fstatat(
                dir_fd, selected, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) return 0;
            return -1;
        }
    }
    selected[0] = '\0';
    errno = ENOSPC;
    return -1;
}
#endif

/* Retire one exact pathname generation without ever deleting a later
 * replacement. FreeBSD can remove the vnode named by a pinned descriptor.
 * Linux and Darwin instead move the candidate into a finite inert arena and
 * reprove what moved; a raced replacement is restored no-replace when the
 * canonical name remains absent, and otherwise remains preserved in the
 * arena while the new canonical generation continues to block. */
static int config_retire_exact_name_at(
    int dir_fd, const char *source, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    const char *settled_prefix) {
#if defined(__FreeBSD__)
    struct stat pinned;
    int fd;
    int saved_errno;

    (void)settled_prefix;
    (void)expected_data;
    (void)expected_length;
    fd = openat(
        dir_fd, source, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &pinned) != 0 ||
        !config_metadata_snapshot_same(expected, &pinned) ||
        funlinkat(dir_fd, source, fd, 0) != 0) {
        saved_errno = errno ? errno : ESTALE;
        if (fd >= 0) (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    (void)close(fd);
    return 0;
#else
    char settled[96];
    struct stat moved;

    if (config_select_settled_name_at(
            dir_fd, settled_prefix,
            CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT(),
            settled, sizeof(settled)) != 0 ||
        config_publish_noreplace_at(
            dir_fd, source, settled, expected, NULL) !=
            CONFIG_PUBLISH_MOVED ||
        fstatat(
            dir_fd, settled, &moved,
            AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (expected_data && expected_length > 0U) {
        int proof_result =
            (expected->st_mode & 0777) == PERM_USER_RW
                ? config_reprove_published_file_at(
                      dir_fd, settled, expected, expected_data,
                      expected_length, &moved)
                : config_reprove_existing_file_at(
                      dir_fd, settled, expected, expected_data,
                      expected_length, &moved);

        if (proof_result == 0) {
            return 0;
        }
    } else if (config_metadata_same_file(expected, &moved) &&
               ((expected->st_nlink == 1 &&
                 config_metadata_file_is_safe(&moved, true)) ||
                (expected->st_nlink >= 2 && expected->st_nlink <= 3 &&
                 moved.st_nlink == expected->st_nlink &&
                 config_alias_metadata_is_safe(&moved) &&
                 (config_metadata_snapshot_same(expected, &moved) ||
                  config_metadata_ctime_only_change(expected, &moved))))) {
        return 0;
    }
    {
        int saved_errno = ESTALE;

        (void)config_publish_noreplace_at(
            dir_fd, settled, source, &moved, NULL);
        errno = saved_errno;
        return -1;
    }
#endif
}

static int config_retire_exact_path(
    const char *path, const struct stat *created,
    const unsigned char *expected_data, size_t expected_length,
    const char *settled_prefix) {
    char directory[MAX_PATH_LEN];
    char leaf[MAX_PATH_LEN];
    struct stat named;
    const char *slash;
    size_t directory_length;
    int directory_fd;
    int result;
    int saved_errno;

    if (!path || !created || !settled_prefix || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        if (safe_strncpy(directory, ".", sizeof(directory)) != 0 ||
            safe_strncpy(leaf, path, sizeof(leaf)) != 0) {
            return -1;
        }
    } else {
        if (slash[1] == '\0') {
            errno = EINVAL;
            return -1;
        }
        directory_length = slash == path ? 1U : (size_t)(slash - path);
        if (directory_length >= sizeof(directory) ||
            safe_strncpy(leaf, slash + 1, sizeof(leaf)) != 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(directory, path, directory_length);
        directory[directory_length] = '\0';
    }
    directory_fd = open(
        directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory_fd < 0) return -1;
    if (fstatat(
            directory_fd, leaf, &named,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named, false) ||
        !config_metadata_same_file(created, &named)) {
        saved_errno = errno ? errno : ESTALE;
        (void)close(directory_fd);
        errno = saved_errno;
        return -1;
    }
    result = config_retire_exact_name_at(
        directory_fd, leaf, &named, expected_data, expected_length,
        settled_prefix);
    saved_errno = errno;
    (void)close(directory_fd);
    errno = saved_errno;
    return result;
}

static int config_reprove_pinned_private_fd(
    int fd, const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_identity) {
    unsigned char observed[4096];
    struct stat before;
    struct stat after;
    size_t offset = 0U;

    if (fd < 0 || !expected_identity ||
        (!expected_data && expected_length != 0U)) {
        errno = EINVAL;
        goto fail;
    }
    if (fstat(fd, &before) != 0) goto fail;
    if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
        (before.st_mode & 0777) != PERM_USER_RW ||
        before.st_nlink > 3 ||
        !config_metadata_same_file(expected_identity, &before) ||
        (expected_data &&
         (before.st_size < 0 ||
          (uintmax_t)before.st_size != expected_length))) {
        errno = ESTALE;
        goto fail;
    }
    while (expected_data && offset < expected_length) {
        size_t chunk = expected_length - offset;

        if (chunk > sizeof(observed)) chunk = sizeof(observed);
        if (!config_pread_full(
                fd, observed, chunk, (off_t)offset)) {
            goto fail;
        }
        if (memcmp(
                observed, expected_data + offset, chunk) != 0) {
            errno = ESTALE;
            goto fail;
        }
        offset += chunk;
    }
    if (fstat(fd, &after) != 0) goto fail;
    if (!config_metadata_snapshot_same(&before, &after)) {
        errno = ESTALE;
        goto fail;
    }
    if (accepted_identity) *accepted_identity = after;
    secure_zero_memory(observed, sizeof(observed));
    return 0;

fail:
    {
        int saved_errno = errno;

        secure_zero_memory(observed, sizeof(observed));
        errno = saved_errno;
    }
    return -1;
}

/* A no-replace publication can commit the canonical name while retaining the
 * random source alias. Retire that exact post-link generation while the
 * caller still owns the directory writer boundary. If direct retirement is
 * transiently unavailable, atomically upgrade the legacy signal scratch slot
 * to identity-bound tracking and make one serialized cleanup attempt. Before
 * the link count changes, a failed cleanup remains identity-tracked. Once a
 * fixed recovery hardlink is established, cleanup authority transfers to that
 * restart-visible name and the stale random-path registry record is withdrawn;
 * a later writer reconciles the exact fixed/random pair under its lock. */
static int config_retire_or_track_scratch_at(
    int dir_fd, const char *dir_path, const char *source_name,
    const char *source_path, const char *target_name,
    const struct stat *retained_source,
    const unsigned char *expected_data, size_t expected_length,
    const char *settled_prefix) {
    char settled_name[96];
    struct stat source_now;
    struct stat source_pinned;
    struct stat settled_now;
    struct stat target_now;
    int settlement_errno;
    int source_pin = -1;
    bool fixed_linked = false;

    if (dir_fd < 0 || !dir_path || !source_name || !source_path ||
        !target_name || !retained_source || !settled_prefix) {
        errno = EINVAL;
        return -1;
    }
    if (CONFIG_PUBLISH_TEST_CHECKPOINT(
            CONFIG_PUBLISH_TEST_RETAINED_SOURCE_RETIRE,
            dir_fd, source_name, target_name) == 0 &&
        config_retire_exact_name_at(
            dir_fd, source_name, retained_source,
            expected_data, expected_length, settled_prefix) == 0) {
        signals_scratch_unregister(source_path);
        return 0;
    }
    settlement_errno = errno ? errno : EIO;
    if (signals_scratch_register_identity(
            source_path, retained_source) != 0) {
        errno = settlement_errno;
        return -1;
    }
    if (signals_scratch_cleanup_identities_at(
            dir_fd, dir_path) == 0) {
        return 0;
    }
    /* A fixed authority is valid only for a source already published as the
     * current canonical generation. Prove that before creating another link;
     * pre-publication cleanup failures and uncertain foreign destinations must
     * never manufacture an unreconcilable random+fixed pair. */
    if (fstatat(
            dir_fd, source_name, &source_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, target_name, &target_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_same_file(&source_now, &target_now) ||
        config_reprove_private_alias_at(
            dir_fd, source_name, &source_now,
            expected_data, expected_length, NULL) != 0 ||
        config_reprove_private_alias_at(
            dir_fd, target_name, &target_now,
            expected_data, expected_length, NULL) != 0) {
        return -1;
    }
    /* Leave an unambiguous restart-visible authority without ever replacing a
     * collided slot. The random alias remains in place until the fixed link is
     * durable, closing the crash window in which moving it could lose the only
     * cleanup name. */
    for (unsigned int slot = 0U;
         slot < CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT(); slot++) {
        int written = snprintf(
            settled_name, sizeof(settled_name),
            "%s%u", settled_prefix, slot);

        if (written < 0 || (size_t)written >= sizeof(settled_name)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (CONFIG_PUBLISH_TEST_CHECKPOINT(
                CONFIG_PUBLISH_TEST_BEFORE_FIXED_LINK,
                dir_fd, source_name, target_name) != 0) {
            return -1;
        }
        if (linkat(
                dir_fd, source_name, dir_fd, settled_name, 0) == 0) {
            /* linkat() ran inside the exclusive directory-writer boundary,
             * after both the random source and canonical target were proved
             * to name the same owned generation. The new fixed name is now
             * the restart-visible cleanup authority. Drop the random path's
             * old nlink=2 registry record before any later checkpoint can
             * return: the successful hardlink changed that generation to
             * nlink=3, so retaining the old record would make the next
             * same-process writer fail ESTALE before its fixed-name
             * reconciliation can run. This only withdraws unlink authority;
             * it never authorizes removal of either pathname. */
            signals_scratch_unregister(source_path);
            fixed_linked = true;
            break;
        }
        if (errno != EEXIST) return -1;
    }
    if (!fixed_linked) {
        errno = ENOSPC;
        return -1;
    }
    if (CONFIG_PUBLISH_TEST_CHECKPOINT(
            CONFIG_PUBLISH_TEST_AFTER_FIXED_LINK,
            dir_fd, source_name, target_name) != 0) {
        return -1;
    }
    if (fstatat(
            dir_fd, source_name, &source_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, settled_name, &settled_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, target_name, &target_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_same_file(&source_now, &settled_now) ||
        !config_metadata_same_file(&source_now, &target_now) ||
        config_reprove_private_alias_at(
            dir_fd, source_name, &source_now,
            expected_data, expected_length, NULL) != 0 ||
        config_reprove_private_alias_at(
            dir_fd, settled_name, &settled_now,
            expected_data, expected_length, NULL) != 0 ||
        config_reprove_private_alias_at(
            dir_fd, target_name, &target_now,
            expected_data, expected_length, NULL) != 0) {
        return -1;
    }
    if (fsync(dir_fd) != 0) return -1;
    if (CONFIG_PUBLISH_TEST_CHECKPOINT(
            CONFIG_PUBLISH_TEST_AFTER_FIXED_SYNC,
            dir_fd, source_name, target_name) != 0) {
        return -1;
    }
    if (fstatat(
            dir_fd, source_name, &source_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, settled_name, &settled_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, target_name, &target_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_same_file(&source_now, &settled_now) ||
        !config_metadata_same_file(&source_now, &target_now) ||
        config_reprove_private_alias_at(
            dir_fd, source_name, &source_now,
            expected_data, expected_length, NULL) != 0 ||
        config_reprove_private_alias_at(
            dir_fd, target_name, &target_now,
            expected_data, expected_length, NULL) != 0) {
        return -1;
    }

    /* Once the fixed authority is durable, pin the exact owned source vnode
     * before retiring its random name. The descriptor keeps that inode alive
     * across the test seam and final namespace proofs, so a same-UID actor
     * cannot recycle dev/ino and turn a fresh byte-identical target+fixed pair
     * into cleanup authority. If retirement still fails, preserve that errno
     * and the remaining names for the next writer's causal scan. */
    if (CONFIG_PUBLISH_TEST_CHECKPOINT(
            CONFIG_PUBLISH_TEST_BEFORE_SOURCE_PIN,
            dir_fd, source_name, target_name) != 0) {
        return -1;
    }
    source_pin = openat(
        dir_fd, source_name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source_pin < 0 ||
        config_reprove_pinned_private_fd(
            source_pin, &source_now,
            expected_data, expected_length,
            &source_pinned) != 0) {
        int pin_errno = errno ? errno : ESTALE;

        if (source_pin >= 0) (void)close(source_pin);
        errno = pin_errno;
        return -1;
    }
    if (config_retire_exact_name_at(
            dir_fd, source_name, &source_now,
            expected_data, expected_length, settled_prefix) != 0) {
        goto pinned_fail;
    }
    signals_scratch_unregister(source_path);
    if (fsync(dir_fd) != 0) goto pinned_fail;
    if (CONFIG_PUBLISH_TEST_CHECKPOINT(
            CONFIG_PUBLISH_TEST_BEFORE_FIXED_RETIRE,
            dir_fd, source_name, target_name) != 0) {
        goto pinned_fail;
    }
    if (config_reprove_pinned_private_fd(
            source_pin, &source_pinned,
            expected_data, expected_length,
            &source_pinned) != 0) {
        goto pinned_fail;
    }
    if (fstatat(
            dir_fd, target_name, &target_now,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            dir_fd, settled_name, &settled_now,
            AT_SYMLINK_NOFOLLOW) != 0) {
        goto pinned_fail;
    }
    if (!config_metadata_same_file(&source_pinned, &target_now) ||
        !config_metadata_same_file(&source_pinned, &settled_now) ||
        !config_metadata_same_file(&target_now, &settled_now)) {
        errno = ESTALE;
        goto pinned_fail;
    }
    if (config_reprove_private_alias_at(
            dir_fd, target_name, &target_now,
            expected_data, expected_length, NULL) != 0 ||
        config_reprove_private_alias_at(
            dir_fd, settled_name, &settled_now,
            expected_data, expected_length, NULL) != 0 ||
        config_retire_exact_name_at(
            dir_fd, settled_name, &settled_now,
            expected_data, expected_length, settled_prefix) != 0) {
        goto pinned_fail;
    }
    if (fsync(dir_fd) != 0 ||
        config_reprove_pinned_private_fd(
            source_pin, &source_pinned,
            expected_data, expected_length, NULL) != 0) {
        goto pinned_fail;
    }
    if (close(source_pin) != 0) return -1;
    return 0;

pinned_fail:
    {
        int pinned_errno = errno ? errno : ESTALE;

        (void)close(source_pin);
        errno = pinned_errno;
        return -1;
    }
}

static bool config_retained_temp_name_is_exact(
    const char *name, const char *prefix, size_t fixed_suffix_length) {
    size_t prefix_length;
    size_t suffix_length;

    if (!name || !prefix) return false;
    prefix_length = strlen(prefix);
    if (strncmp(name, prefix, prefix_length) != 0) return false;
    suffix_length = strlen(name + prefix_length);
    if (suffix_length == 0U ||
        (fixed_suffix_length != 0U &&
         suffix_length != fixed_suffix_length)) {
        return false;
    }
    for (size_t i = 0U; i < suffix_length; i++) {
        unsigned char c =
            (unsigned char)name[prefix_length + i];

        if (fixed_suffix_length != 0U) {
            if (!((c >= (unsigned char)'0' &&
                   c <= (unsigned char)'9') ||
                  (c >= (unsigned char)'A' &&
                   c <= (unsigned char)'Z') ||
                  (c >= (unsigned char)'a' &&
                   c <= (unsigned char)'z'))) {
                return false;
            }
        } else if (c < (unsigned char)'0' ||
                   c > (unsigned char)'9') {
            return false;
        }
    }
    return true;
}

/* Reconcile random and fixed aliases left by a prior process. The random scan
 * is unconditional so it also closes a crash before the fixed link's directory
 * fsync. Enumeration completes within fixed bounds before any deletion. Only
 * safe reserved names hard-linked to the current canonical generation are
 * cleanup authority; foreign generations and collided fixed slots stay inert. */
static int config_reconcile_settled_aliases_at(
    int dir_fd, const char *target_name, const char *settled_prefix,
    const char *temp_prefix, size_t fixed_suffix_length) {
    enum {
        CONFIG_ALIAS_SCAN_MAX_ENTRIES = 4096,
        CONFIG_ALIAS_SCAN_MAX_CANDIDATES = 64
    };
    char candidates[CONFIG_ALIAS_SCAN_MAX_CANDIDATES][NAME_MAX + 1U];
    struct stat target;
    DIR *stream = NULL;
    struct dirent *entry;
    size_t entry_count = 0U;
    size_t candidate_count = 0U;
    bool removed_random = false;
    bool target_exists = false;
    int scan_fd;
    int scan_errno;
    int close_result;

    errno = 0;
    if (fstatat(
            dir_fd, target_name, &target,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT) return -1;
    } else if (!config_reconcile_target_is_safe(&target)) {
        errno = ESTALE;
        return -1;
    } else {
        target_exists = true;
    }

    scan_fd = openat(
        dir_fd, ".",
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (scan_fd < 0) return -1;
    stream = fdopendir(scan_fd);
    if (!stream) {
        scan_errno = errno ? errno : EIO;
        close(scan_fd);
        errno = scan_errno;
        return -1;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        entry_count++;
        if (entry_count > CONFIG_ALIAS_SCAN_MAX_ENTRIES) {
            scan_errno = E2BIG;
            goto scan_done;
        }
        if (!config_retained_temp_name_is_exact(
                entry->d_name, temp_prefix,
                fixed_suffix_length)) {
            continue;
        }
        if (candidate_count >=
            CONFIG_ALIAS_SCAN_MAX_CANDIDATES) {
            scan_errno = E2BIG;
            goto scan_done;
        }
        if (safe_strncpy(
                candidates[candidate_count], entry->d_name,
                sizeof(candidates[candidate_count])) != 0) {
            scan_errno = errno ? errno : ENAMETOOLONG;
            goto scan_done;
        }
        candidate_count++;
    }
    scan_errno = errno;

scan_done:
    close_result = closedir(stream);
    stream = NULL;
    if (scan_errno != 0 || close_result != 0) {
        errno = scan_errno != 0 ? scan_errno : (errno ? errno : EIO);
        return -1;
    }
    for (size_t i = 0U; i < candidate_count; i++) {
        struct stat candidate;

        if (fstatat(
                dir_fd, candidates[i], &candidate,
                AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;
            return -1;
        }
        if (!config_alias_metadata_is_safe(&candidate)) {
            continue;
        }
        if (!target_exists ||
            !config_metadata_same_file(&target, &candidate)) {
            continue;
        }
        if (config_retire_exact_name_at(
                dir_fd, candidates[i], &candidate,
                NULL, 0U, settled_prefix) != 0) {
            return -1;
        }
        removed_random = true;
        if (target_exists) {
            if (fstatat(
                    dir_fd, target_name, &target,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
                !config_reconcile_target_is_safe(&target)) {
                return -1;
            }
        }
    }
    if (removed_random && fsync(dir_fd) != 0) return -1;
    if (!target_exists) return 0;

#if defined(__FreeBSD__)
    for (unsigned int slot = 0U;
         slot < CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT();
         slot++) {
        char settled_name[96];
        struct stat settled;
        int written = snprintf(
            settled_name, sizeof(settled_name),
            "%s%u", settled_prefix, slot);

        if (written < 0 || (size_t)written >= sizeof(settled_name)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        errno = 0;
        if (fstatat(
                dir_fd, settled_name, &settled,
                AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;
            return -1;
        }
        if (!config_metadata_same_file(&target, &settled)) continue;
        if (config_retire_exact_name_at(
                dir_fd, settled_name, &settled,
                NULL, 0U, settled_prefix) != 0) {
            return -1;
        }
        if (fsync(dir_fd) != 0) return -1;
        if (fstatat(
                dir_fd, target_name, &target,
                AT_SYMLINK_NOFOLLOW) != 0 ||
            !config_reconcile_target_is_safe(&target)) {
            return -1;
        }
    }
#endif
    return 0;
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

/* Read-only commands still need truthful live-account attribution. Inspect the
 * existing runtime namespace without creating or repairing the configuration
 * directory; unlike preview mode, this deliberately takes the SSH manager's
 * read-side lock and probes an existing current.sock target. */
int config_init_runtime_readonly(gitswitch_ctx_t *ctx) {
    return config_init_mode(ctx, CONFIG_INIT_RUNTIME_READONLY);
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
static config_metadata_test_hook_fn g_config_metadata_test_hook;
static config_backup_clock_fn g_config_backup_clock;
static config_backup_readdir_fn g_config_backup_readdir = readdir;
static config_incarnation_generate_fn g_config_incarnation_generate;

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

config_metadata_test_hook_fn config_set_metadata_test_hook_fn(
    config_metadata_test_hook_fn fn) {
    config_metadata_test_hook_fn previous = g_config_metadata_test_hook;
    g_config_metadata_test_hook = fn;
    return previous;
}

config_backup_clock_fn config_set_backup_clock_fn(
    config_backup_clock_fn fn) {
    config_backup_clock_fn previous = g_config_backup_clock;
    g_config_backup_clock = fn;
    return previous;
}

config_backup_readdir_fn config_set_backup_readdir_fn(
    config_backup_readdir_fn fn) {
    config_backup_readdir_fn previous = g_config_backup_readdir;
    g_config_backup_readdir = fn ? fn : readdir;
    return previous;
}

config_incarnation_generate_fn config_set_incarnation_generate_fn(
    config_incarnation_generate_fn fn) {
    config_incarnation_generate_fn previous =
        g_config_incarnation_generate;
    g_config_incarnation_generate = fn;
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
static int config_read_document_expected(const char *config_path,
                                         toml_document_t *doc,
                                         const struct stat *expected_identity,
                                         struct stat *loaded_identity,
                                         unsigned char *loaded_bytes,
                                         size_t loaded_capacity,
                                         size_t *loaded_length) {
    char *buffer = NULL;
    struct stat before, after, path_after;
    size_t file_size, total = 0;
    int parse_result;
    int fd;

    if ((loaded_bytes && !loaded_length) ||
        (!loaded_bytes && loaded_length)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid configuration read-witness arguments");
        return -1;
    }
    if (loaded_length) *loaded_length = 0U;

    fd = open_config_validated(config_path);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &before) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot stat config file: %s", config_path);
        close(fd);
        return -1;
    }
    if (expected_identity &&
        !config_metadata_snapshot_same(expected_identity, &before)) {
        errno = ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Backup destination changed before verification: %s",
                         config_path);
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
        if (expected_identity) {
            metadata_stable = metadata_stable &&
                config_metadata_snapshot_same(expected_identity, &after) &&
                config_metadata_snapshot_same(expected_identity, &path_after);
        }
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
            if (expected_identity) {
                errno = ESTALE;
                set_system_error(
                    ERR_FILE_IO,
                    "Backup destination changed during verification: %s",
                    config_path);
            } else {
                set_error(
                    ERR_FILE_IO,
                    "Configuration changed while it was being read; retry: %s",
                    config_path);
            }
            close(fd);
            goto fail_buffer;
        }
    }
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO,
                         "Cannot close config after complete read: %s",
                         config_path);
        goto fail_buffer;
    }
    fd = -1;
    if (config_io_fault(CONFIG_IO_DOCUMENT_AFTER_CLOSE,
                        "config document close checkpoint")) {
        goto fail_buffer;
    }

    /* FreeBSD UFS may expose a reader-induced ctime step only when the
     * descriptor closes. The complete bytes, EOF, descriptor generation, and
     * installed inode were proved immediately above, so admit only that
     * ctime-only transition and bind callers to the post-close generation.
     * Any later ctime-only transition still requires a caller-retained exact
     * byte witness and a fresh descriptor proof. */
    errno = 0;
    if (lstat(config_path, &path_after) != 0 ||
        (!config_metadata_snapshot_same(&after, &path_after) &&
         !config_metadata_ctime_only_change(&after, &path_after))) {
        int close_observation_errno = errno ? errno : ESTALE;

        errno = config_is_namespace_change_errno(close_observation_errno)
                    ? ESTALE
                    : close_observation_errno;
        set_system_error(
            ERR_FILE_IO,
            "Configuration changed while its completed read was closing: %s",
            config_path);
        goto fail_buffer;
    }
    after = path_after;
    if (parse_result != 0) {
        goto fail_buffer;
    }

    if (loaded_identity) {
        *loaded_identity = after;
    }
    if (loaded_bytes) {
        if (file_size > loaded_capacity) {
            errno = EOVERFLOW;
            set_system_error(
                ERR_CONFIG_INVALID,
                "Configuration exceeds read-witness capacity: %s",
                config_path);
            goto fail_buffer;
        }
        if (file_size != 0U) memcpy(loaded_bytes, buffer, file_size);
        *loaded_length = file_size;
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

static int config_read_document(
    const char *config_path, toml_document_t *doc,
    struct stat *loaded_identity, unsigned char *loaded_bytes,
    size_t loaded_capacity, size_t *loaded_length) {
    return config_read_document_expected(config_path, doc, NULL,
                                         loaded_identity, loaded_bytes,
                                         loaded_capacity, loaded_length);
}

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

static void config_active_state_generation_clear(
    config_active_state_generation_t *generation) {
    if (!generation) return;
    if (generation->data) {
        secure_zero_memory(generation->data, generation->length);
        free(generation->data);
    }
    memset(generation, 0, sizeof(*generation));
}

static int config_read_active_state(const char *config_path,
                                    config_active_state_t *state,
                                    bool require_private_mode,
                                    config_active_state_generation_t *generation,
                                    publication_ledger_t *publications) {
    char hint[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    unsigned char *buffer = NULL;
    struct stat before;
    struct stat opened;
    struct stat after;
    const unsigned char *first_newline;
    const unsigned char *second_newline;
    const unsigned char *second;
    const unsigned char *active;
    publication_ledger_t parsed_publications;
    size_t first_length;
    size_t second_length;
    size_t active_length;
    size_t tail_offset;
    size_t total = 0;
    int result = -1;
    int fd = -1;

    if (!state) {
        set_error(ERR_INVALID_ARGS, "NULL active-state output");
        return -1;
    }
    memset(state, 0, sizeof(*state));
    publication_ledger_init(&parsed_publications);
    if (publications) publication_ledger_clear(publications);
    if (generation) {
        config_active_state_generation_clear(generation);
    }
    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0) {
        goto cleanup;
    }
    if (lstat(hint, &before) != 0) {
        if (errno == ENOENT) {
            result = 0;
            goto cleanup;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect active-state artifact: %s", hint);
        goto cleanup;
    }

    if (safe_strncpy(dir, hint, sizeof(dir)) != 0) {
        goto cleanup;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        if (safe_strncpy(dir, ".", sizeof(dir)) != 0) goto cleanup;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    if (lstat(dir, &after) != 0 || !config_metadata_dir_is_safe(&after)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Active-state parent is not a private owned directory: %s",
                  dir);
        goto cleanup;
    }
    if (!config_metadata_file_is_safe(&before, require_private_mode) ||
        before.st_size < 0 ||
        (uintmax_t)before.st_size > CONFIG_ACTIVE_STATE_MAX) {
        set_error(ERR_PERMISSION_DENIED,
                  "Active-state artifact is not a small stable owned file: %s",
                  hint);
        goto cleanup;
    }

    buffer = malloc((size_t)before.st_size + 1U);
    if (!buffer) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate active-state bundle");
        goto cleanup;
    }

    RESUME_HINT_TEST_CHECKPOINT(1);
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, require_private_mode) ||
        !config_metadata_snapshot_same(&before, &opened) ||
        opened.st_size < 0 ||
        (uintmax_t)opened.st_size > CONFIG_ACTIVE_STATE_MAX) {
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot open stable active-state artifact: %s", hint);
        fd = -1;
        goto cleanup;
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
            goto cleanup;
        }
    }
    RESUME_HINT_TEST_CHECKPOINT(2);
    if (fstat(fd, &after) != 0 ||
        !config_metadata_file_is_safe(&after, require_private_mode) ||
        !config_metadata_snapshot_same(&opened, &after) ||
        lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, require_private_mode) ||
        !config_metadata_snapshot_same(&opened, &after)) {
        set_error(ERR_FILE_IO,
                  "Active-state artifact changed while being read: %s", hint);
        goto cleanup;
    }
    close(fd);
    fd = -1;
    buffer[total] = '\0';

    if (generation) {
        generation->data = malloc(total == 0U ? 1U : total);
        if (!generation->data) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot allocate active-state generation witness");
            goto cleanup;
        }
        generation->existed = true;
        generation->metadata = opened;
        memcpy(generation->data, buffer, total);
        generation->length = total;
    }

    if (memchr(buffer, '\0', total) != NULL) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: embedded NUL byte",
                  hint);
        goto cleanup;
    }

    /* The first resume-hint implementation wrote a zero-byte marker. It still
     * proves that the legacy settings.active_account was intentionally active,
     * but carries no runtime-needs token. Admit it only as migration input; the
     * next serialized state save replaces it with the versioned format. */
    if (total == 0) {
        state->exists = true;
        state->legacy_needs_only = true;
        result = 0;
        goto publish;
    }

    first_newline = memchr(buffer, '\n', total);
    if (!first_newline) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: missing first newline",
                  hint);
        goto cleanup;
    }
    first_length = (size_t)(first_newline - buffer);
    if (!config_state_needs_valid((const char *)buffer, first_length)) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: invalid runtime-needs token",
                  hint);
        goto cleanup;
    }
    memcpy(state->needs, buffer, first_length);
    state->needs[first_length] = '\0';
    state->exists = true;
    if ((size_t)(first_newline - buffer) + 1 == total) {
        state->legacy_needs_only = true;
        result = 0;
        goto publish;
    }

    second = first_newline + 1;
    second_newline = memchr(second, '\n', total - (size_t)(second - buffer));
    if (!second_newline) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: missing second newline",
                  hint);
        goto cleanup;
    }
    second_length = (size_t)(second_newline - second);
    tail_offset = (size_t)(second_newline - buffer) + 1U;

    /* Versioned inactive tombstone. Keeping the first line as "none" makes
     * every already-generated shell snippet take its no-op arm, while the
     * second line disambiguates a deliberate reset from a pre-state-artifact
     * configuration whose legacy active_account must still migrate. */
    if (first_length == 4U && memcmp(buffer, "none", 4U) == 0 &&
        second_length == sizeof("inactive=v1") - 1U &&
        memcmp(second, "inactive=v1", second_length) == 0) {
        state->inactive_tombstone = true;
    } else if (second_length < sizeof("active=") - 1U ||
               memcmp(second, "active=", sizeof("active=") - 1U) != 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Malformed active-state artifact %s: expected active=<name>",
                  hint);
        goto cleanup;
    } else {
        active = second + sizeof("active=") - 1U;
        active_length = second_length - (sizeof("active=") - 1U);
        if (active_length == 0U ||
            active_length >= sizeof(state->active_account) ||
            memchr(active, '\r', active_length) != NULL) {
            set_error(ERR_CONFIG_INVALID,
                      "Malformed active-state artifact %s: invalid active name length",
                      hint);
            goto cleanup;
        }
        memcpy(state->active_account, active, active_length);
        state->active_account[active_length] = '\0';
        if (!validate_name(state->active_account) ||
            !text_is_tty_safe(state->active_account)) {
            memset(state->active_account, 0,
                   sizeof(state->active_account));
            set_error(ERR_CONFIG_INVALID,
                      "Malformed active-state artifact %s: unsafe active account name",
                      hint);
            goto cleanup;
        }
    }
    if (publication_ledger_parse(buffer + tail_offset,
                                 total - tail_offset,
                                 &parsed_publications) != 0) {
        goto cleanup;
    }
    result = 0;

publish:
    if (result == 0 && publications) {
        *publications = parsed_publications;
        publication_ledger_init(&parsed_publications);
    }

cleanup:
    if (fd >= 0) close(fd);
    if (buffer) {
        secure_zero_memory(buffer, (size_t)before.st_size + 1U);
        free(buffer);
    }
    publication_ledger_clear(&parsed_publications);
    if (result != 0 && generation) {
        config_active_state_generation_clear(generation);
    }
    return result;
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

/* Reload into a private context and publish the complete replacement only
 * after document, account, active-state, and runtime reconciliation all
 * succeed. In particular, a late validation failure must not pair the old
 * account model with freshly reset rewrite guards. The context is too large
 * for the product's bounded stack policy, so stage it on the heap. */
static int config_load_mode(gitswitch_ctx_t *ctx, const char *config_path,
                            bool apply_active_state, bool detect_runtime) {
    gitswitch_ctx_t *staged;
    uint32_t current_id = 0;
    bool had_current;
    int result;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }

    staged = malloc(sizeof(*staged));
    if (!staged) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Failed to allocate staged configuration context");
        return -1;
    }

    had_current = config_capture_current_id(ctx, &current_id);
    memcpy(staged, ctx, sizeof(*staged));
    config_rebind_current_id(staged, had_current, current_id);

    result = config_load_mode_inplace(staged, config_path,
                                      apply_active_state, detect_runtime);
    if (result != 0) {
        secure_zero_memory(staged, sizeof(*staged));
        free(staged);
        return -1;
    }

    had_current = config_capture_current_id(staged, &current_id);
    memcpy(ctx, staged, sizeof(*ctx));
    config_rebind_current_id(ctx, had_current, current_id);
    secure_zero_memory(staged, sizeof(*staged));
    free(staged);
    return 0;
}

/* Load configuration from TOML file. Preview-only callers skip live-runtime
 * discovery because its cross-process lock may create/chmod a lock inode. */
static int config_load_mode_inplace(gitswitch_ctx_t *ctx,
                                    const char *config_path,
                                    bool apply_active_state,
                                    bool detect_runtime) {
    toml_document_t *toml_doc;
    config_active_state_t active_state;
    struct stat loaded_identity;
    size_t loaded_length = 0U;
    char legacy_active[MAX_NAME_LEN] = "";
    char scope_str[32];

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }

    toml_doc = config_document_alloc();
    if (!toml_doc) {
        return -1;
    }

    secure_zero_memory(ctx->config.source_witness,
                       sizeof(ctx->config.source_witness));
    ctx->config.source_witness_length = 0U;
    ctx->config.source_witness_valid = false;
    ctx->config.source_read_witness_valid = false;
    if (config_read_document(
            config_path, toml_doc, &loaded_identity,
            ctx->config.source_witness,
            sizeof(ctx->config.source_witness), &loaded_length) != 0) {
        config_document_free(toml_doc);
        return -1;
    }

    /* AR-06 F49: these are cumulative counters that load_accounts_from_toml and
     * count_unknown_keys only ever increment. Reset them only after the new
     * document is completely read: an entry-boundary rejection must leave the
     * caller's existing context byte-for-byte untouched. */
    ctx->accounts_skipped_on_load = 0;
    ctx->unknown_sections_on_load = 0;
    ctx->unknown_keys_on_load = 0;

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

    /* The pre-reload current pointer is not runtime evidence. Clear it before
     * rebuilding the fixed array and leave it clear until live current.sock or
     * validated persisted active state selects an account below. Rebinding by
     * the old stable ID here would make accounts_detect_current() take its
     * already-set fast path and silently ignore a different live account, a
     * renamed identity, or complete runtime absence. The outer transaction
     * still preserves the old pointer exactly if any reload phase fails. */
    ctx->current_account = NULL;

    /* Load accounts */
    if (load_accounts_from_toml(ctx, toml_doc) != 0) {
        config_document_free(toml_doc);
        return -1;
    }

    /* AR-06 F02: also detect unmodeled KEYS inside recognized sections, so a
     * full rewrite is refused before it silently erases them. */
    count_unknown_keys(ctx, toml_doc);

    /* Store config path */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));
    ctx->config.source_generation = loaded_identity;
    ctx->config.source_generation_valid = true;
    ctx->config.source_witness_valid = false;
    ctx->config.source_read_witness_valid = true;
    ctx->config.source_witness_length = loaded_length;

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
    if (config_read_active_state(config_path, &active_state, false, NULL,
                                 NULL) != 0) {
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
                /* AR-12 H3: the active account's own section was skipped —
                 * commonly a deleted, rotated, or chmod'd key file. One
                 * unloadable account must not take down every command:
                 * degrade to inactive-with-warning like the stale-name
                 * branch below, so list/status/reset/switch keep running as
                 * repair paths. Full-document saves stay blocked by the
                 * skip counters, preserving the on-disk section. */
                /* AR-13 L16: do not assert the active account's OWN section was
                 * the skipped one — an unrelated section may have been skipped
                 * while the active name is merely a stale artifact. State what
                 * is actually known: the active account could not be resolved
                 * and N sections were skipped. */
                display_warning(
                    "Active-state account '%s' could not be loaded and %zu "
                    "account section(s) were skipped on load; treating the "
                    "session as inactive until the config is repaired",
                    ctx->config.active_account,
                    (size_t)ctx->accounts_skipped_on_load);
                ctx->config.active_account[0] = '\0';
            } else {
                /* A crash after accounts.toml removed/renamed the active
                 * account but before the state phase completed leaves a
                 * syntactically valid stale artifact. Resolve that state
                 * deterministically to inactive. Loading stays
                 * observational: read-only commands do not own the mutation
                 * lock, so cleanup is deferred to the next
                 * already-serialized active/full save. */
                display_warning("Ignoring stale active-state account '%s': it is not present in %s",
                                ctx->config.active_account, config_path);
                ctx->config.active_account[0] = '\0';
            }
        } else if (active_state.exists &&
                   active_state.needs[0] != '\0' &&
                   strcmp(active_state.needs,
                          config_account_runtime_needs(state_account)) != 0) {
            /* AR-12 M3: a stale needs token is repairable staleness, not
             * corruption. Two supported producers exist: a hand edit that
             * changed the active account's ssh/gpg features, and gitswitch's
             * own crash window between state install and document rename.
             * Hard-failing here bricked every command including the repair
             * paths; degrade to inactive like the branches above and let the
             * next serialized save rewrite the artifact. */
            display_warning(
                "Active-state runtime needs '%s' do not match account '%s' (expected '%s'); treating the session as inactive until the next switch",
                active_state.needs, ctx->config.active_account,
                config_account_runtime_needs(state_account));
            ctx->config.active_account[0] = '\0';
        } else if (safe_strncpy(ctx->config.active_account,
                                state_account->name,
                                sizeof(ctx->config.active_account)) != 0) {
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

/* Error cleanup must not remove a same-UID process's replacement merely
 * because it reused our private temporary pathname.  Every caller captures
 * the created descriptor's identity before registration and reaches this
 * helper while the surrounding publication lock is still held. */
static void config_unlink_created_temp(const char *path,
                                       const struct stat *created,
                                       bool have_created_identity) {
    if (!path || !created || !have_created_identity) return;
    (void)config_retire_exact_path(
        path, created, NULL, 0U, CONFIG_DOCUMENT_SETTLED_PREFIX);
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

/* Active-state-only saves describe the account model already loaded into the
 * context; unlike a full save, they do not replace that model. Require the
 * same strict source snapshot (and the same caller path spelling) so an
 * intervening valid accounts.toml generation is preserved as a conflict. */
static int config_require_loaded_source_generation(
    const gitswitch_ctx_t *ctx, const char *config_path,
    struct stat *accepted_generation) {
    struct stat current;
    struct stat reproved;
    int lookup_errno;

    if (!ctx || !config_path || !ctx->config.source_generation_valid ||
        strcmp(ctx->config.config_path, config_path) != 0) {
        set_error(ERR_CONFIG_INVALID,
                  "Active-state publication requires a context loaded from the exact config path");
        return -1;
    }
    errno = 0;
    if (lstat(config_path, &current) != 0) {
        lookup_errno = errno ? errno : EIO;
        errno = config_is_namespace_change_errno(lookup_errno)
                    ? ESTALE
                    : lookup_errno;
        set_system_error(
            ERR_FILE_IO,
            "Configuration changed since it was loaded; refusing active-state publication: %s",
            config_path);
        return -1;
    }
    if (!config_metadata_file_is_safe(&current, true) ||
        !config_metadata_snapshot_same(&ctx->config.source_generation,
                                       &current)) {
        lookup_errno = ESTALE;
        if (config_metadata_file_is_safe(&current, true) &&
            config_metadata_ctime_only_change(
                &ctx->config.source_generation, &current) &&
            (ctx->config.source_witness_valid ||
             ctx->config.source_read_witness_valid) &&
            ctx->config.source_generation.st_size >= 0 &&
            ctx->config.source_witness_length <=
                sizeof(ctx->config.source_witness) &&
            (uintmax_t)ctx->config.source_generation.st_size ==
                ctx->config.source_witness_length) {
            errno = 0;
            if (config_reprove_loaded_source(
                    config_path, &ctx->config.source_generation,
                    ctx->config.source_witness,
                    ctx->config.source_witness_length,
                    &reproved) == 0) {
                if (accepted_generation) {
                    *accepted_generation = reproved;
                }
                return 0;
            }
            lookup_errno = errno ? errno : ESTALE;
        }
        errno = config_is_namespace_change_errno(lookup_errno)
                    ? ESTALE
                    : lookup_errno;
        set_system_error(
            ERR_FILE_IO,
            "Configuration changed since it was loaded; refusing active-state publication: %s",
            config_path);
        return -1;
    }
    if (accepted_generation) {
        *accepted_generation = current;
    }
    return 0;
}

int config_revalidate_loaded_source(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid loaded source revalidation context");
        return -1;
    }
    return config_require_loaded_source_generation(
        ctx, ctx->config.config_path, NULL);
}

static int config_require_full_save_generation_snapshot(
    const gitswitch_ctx_t *ctx, const char *config_path,
    bool destination_existed, const struct stat *destination) {
    if (!ctx || !config_path || (destination_existed && !destination)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid full-save generation proof arguments");
        return -1;
    }
    if (strnlen(config_path, sizeof(ctx->config.config_path)) >=
        sizeof(ctx->config.config_path)) {
        set_error(ERR_INVALID_PATH, "Config path is too long");
        return -1;
    }

    if (ctx->config.source_generation_valid) {
        if (strcmp(ctx->config.config_path, config_path) != 0) {
            set_error(
                ERR_CONFIG_INVALID,
                "Full save requires the exact path from the loaded configuration generation");
            return -1;
        }
        if (!destination_existed ||
            !config_metadata_file_is_safe(destination, true) ||
            !config_metadata_snapshot_same(&ctx->config.source_generation,
                                           destination)) {
            int proof_errno = ESTALE;

            /* A completed stable load or preceding successful full save may
             * leave FreeBSD UFS with a reader-induced ctime update that
             * materializes only after the captured generation. Admit it for
             * a later full save only after re-proving every retained byte. */
            if (destination_existed &&
                config_metadata_file_is_safe(destination, true) &&
                config_metadata_ctime_only_change(
                    &ctx->config.source_generation, destination) &&
                (ctx->config.source_witness_valid ||
                 ctx->config.source_read_witness_valid) &&
                ctx->config.source_generation.st_size >= 0 &&
                ctx->config.source_witness_length <=
                    sizeof(ctx->config.source_witness) &&
                (uintmax_t)ctx->config.source_generation.st_size ==
                    ctx->config.source_witness_length) {
                errno = 0;
                if (config_reprove_loaded_source(
                        config_path, &ctx->config.source_generation,
                        ctx->config.source_witness,
                        ctx->config.source_witness_length,
                        NULL) == 0) {
                    return 0;
                }
                proof_errno = errno ? errno : ESTALE;
            }
            errno = config_is_namespace_change_errno(proof_errno)
                        ? ESTALE
                        : proof_errno;
            set_system_error(
                ERR_FILE_IO,
                "Configuration changed since it was loaded; refusing full-document save: %s",
                config_path);
            return -1;
        }
        return 0;
    }

    if (destination_existed) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Refusing generationless overwrite of existing configuration; load it before saving: %s",
            config_path);
        return -1;
    }
    return 0;
}

/* A full rebuild is allowed to create a genuinely absent first document, but
 * it may replace an existing document only when the caller presents the exact
 * generation admitted by config_load or by its own last durable full save.
 * Run this immediately after taking the destination lock, before allocating or
 * mutating the serialized model, capturing resume state, or creating backups. */
static int config_admit_full_save_generation(const gitswitch_ctx_t *ctx,
                                             const char *config_path) {
    struct stat current;
    bool existed = false;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid full-save generation admission arguments");
        return -1;
    }
    errno = 0;
    if (lstat(config_path, &current) == 0) {
        existed = true;
    } else if (errno == ENOENT ||
               (ctx->config.source_generation_valid &&
                config_is_namespace_change_errno(errno))) {
        existed = false;
    } else {
        set_system_error(ERR_FILE_IO,
                         "Cannot establish configuration generation: %s",
                         config_path);
        return -1;
    }
    return config_require_full_save_generation_snapshot(
        ctx, config_path, existed, existed ? &current : NULL);
}

/* FreeBSD UFS may materialize a ctime update only when a related directory is
 * synced. Do not weaken the normal generation comparator: callers may use
 * this predicate only when an independent exact-content proof binds the file
 * to the generation they already captured. */
static bool config_metadata_ctime_only_change(const struct stat *before,
                                              const struct stat *after) {
    bool same_without_ctime = config_metadata_same_file(before, after) &&
        before->st_uid == after->st_uid && before->st_gid == after->st_gid &&
        before->st_mode == after->st_mode &&
        before->st_nlink == after->st_nlink &&
        before->st_size == after->st_size;
#if defined(__APPLE__)
    bool same_mtime =
        before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
        before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec;
    bool same_ctime =
        before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
        before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    bool same_mtime = before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
                      before->st_mtim.tv_nsec == after->st_mtim.tv_nsec;
    bool same_ctime = before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
                      before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
    return same_without_ctime && same_mtime && !same_ctime;
}

/* Use only after a complete, independently bounded byte comparison has
 * proved the file contents. This admits FreeBSD UFS's delayed ctime
 * materialization without accepting a replacement inode or any ownership,
 * mode, link-count, size, or mtime change. */
static bool config_metadata_matches_after_exact_content_proof(
    const struct stat *before, const struct stat *after) {
    return config_metadata_snapshot_same(before, after) ||
           config_metadata_ctime_only_change(before, after);
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

static bool config_pread_full(int fd, unsigned char *buffer, size_t length,
                              off_t offset) {
    size_t total = 0;

    while (total < length) {
        ssize_t count = pread(fd, buffer + total, length - total,
                              offset + (off_t)total);
        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            if (count == 0) errno = ESTALE;
            return false;
        }
    }
    return true;
}

static bool config_alias_metadata_is_safe(const struct stat *st) {
    return st && S_ISREG(st->st_mode) && st->st_uid == getuid() &&
           (st->st_mode & 0777) == PERM_USER_RW &&
           st->st_nlink >= 1 && st->st_nlink <= 3;
}

static bool config_reconcile_target_is_safe(const struct stat *st) {
    return config_metadata_file_is_safe(st, false) ||
           config_alias_metadata_is_safe(st);
}

/* Exact proof for the short interval where a successfully published private
 * file intentionally has two or three names. The ordinary publication proof
 * correctly requires nlink==1 and therefore cannot authorize cleanup here. */
static int config_reprove_private_alias_at(
    int dir_fd, const char *name, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted) {
    unsigned char observed[4096];
    struct stat named_before;
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    size_t offset = 0U;
    int fd = -1;
    int failure_errno = ESTALE;

    if (dir_fd < 0 || !name || !expected ||
        (!expected_data && expected_length != 0U)) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(
            dir_fd, name, &named_before,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_alias_metadata_is_safe(&named_before) ||
        !config_metadata_same_file(expected, &named_before) ||
        (expected_data &&
         (named_before.st_size < 0 ||
          (uintmax_t)named_before.st_size != expected_length))) {
        failure_errno = errno ? errno : ESTALE;
        goto alias_fail;
    }
    fd = openat(
        dir_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_alias_metadata_is_safe(&opened) ||
        !config_metadata_snapshot_same(&named_before, &opened)) {
        failure_errno = errno ? errno : ESTALE;
        goto alias_fail;
    }
    while (expected_data && offset < expected_length) {
        size_t chunk = expected_length - offset;

        if (chunk > sizeof(observed)) chunk = sizeof(observed);
        if (!config_pread_full(
                fd, observed, chunk, (off_t)offset) ||
            memcmp(observed, expected_data + offset, chunk) != 0) {
            failure_errno = errno ? errno : ESTALE;
            goto alias_fail;
        }
        offset += chunk;
    }
    if (fstat(fd, &descriptor_after) != 0 ||
        fstatat(
            dir_fd, name, &named_after,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_alias_metadata_is_safe(&descriptor_after) ||
        !config_alias_metadata_is_safe(&named_after) ||
        !config_metadata_snapshot_same(&opened, &descriptor_after) ||
        !config_metadata_snapshot_same(
            &descriptor_after, &named_after)) {
        failure_errno = errno ? errno : ESTALE;
        goto alias_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        return -1;
    }
    if (accepted) *accepted = named_after;
    return 0;

alias_fail:
    if (fd >= 0) (void)close(fd);
    errno = failure_errno;
    return -1;
}

/* A no-follow lookup reports namespace replacement differently across the
 * supported platforms: Linux/macOS commonly use ELOOP or ENOTDIR, while
 * FreeBSD may report EMLINK for the terminal symlink. These all mean that the
 * expected pathname generation disappeared; unrelated syscall failures retain
 * their original errno. */
static bool config_is_namespace_change_errno(int error) {
    if (error == ENOENT || error == ELOOP || error == ENOTDIR) return true;
#ifdef EMLINK
    if (error == EMLINK) return true;
#endif
    return false;
}

/* Re-prove a published regular-file generation against both strict metadata
 * and an independent byte snapshot captured before publication. FreeBSD may
 * materialize only ctime when the containing directory is synced; admit that
 * narrow metadata transition only when the complete bytes still match. */
static int config_reprove_published_file_at(
    int dir_fd, const char *name, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *current_generation) {
    unsigned char observed[4096];
    struct stat named_before;
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    unsigned char trailing;
    ssize_t trailing_count;
    off_t offset = 0;
    int fd = -1;
    int failure_errno = ESTALE;

    if (dir_fd < 0 || !name || !expected ||
        (!expected_data && expected_length != 0) || !current_generation) {
        errno = EINVAL;
        return -1;
    }

    errno = 0;
    if (fstatat(dir_fd, name, &named_before, AT_SYMLINK_NOFOLLOW) != 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto proof_fail;
    }
    if (!config_metadata_file_is_safe(&named_before, true) ||
        named_before.st_size < 0 ||
        (uintmax_t)named_before.st_size != expected_length ||
        (!config_metadata_snapshot_same(expected, &named_before) &&
         !config_metadata_ctime_only_change(expected, &named_before))) {
        failure_errno = ESTALE;
        goto proof_fail;
    }

    errno = 0;
    fd = openat(dir_fd, name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto proof_fail;
    }
    if (fstat(fd, &opened) != 0) {
        failure_errno = errno ? errno : EIO;
        goto proof_fail;
    }
    if (!config_metadata_file_is_safe(&opened, true) ||
        opened.st_size < 0 ||
        (uintmax_t)opened.st_size != expected_length ||
        (!config_metadata_snapshot_same(expected, &opened) &&
         !config_metadata_ctime_only_change(expected, &opened))) {
        failure_errno = ESTALE;
        goto proof_fail;
    }

    while ((size_t)offset < expected_length) {
        size_t remaining = expected_length - (size_t)offset;
        size_t chunk = remaining < sizeof(observed)
                           ? remaining
                           : sizeof(observed);
        errno = 0;
        if (!config_pread_full(fd, observed, chunk, offset)) {
            failure_errno = errno ? errno : EIO;
            goto proof_fail;
        }
        if (memcmp(observed, expected_data + (size_t)offset, chunk) != 0) {
            failure_errno = ESTALE;
            goto proof_fail;
        }
        offset += (off_t)chunk;
    }
    errno = 0;
    do {
        trailing_count = pread(fd, &trailing, 1, (off_t)expected_length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count < 0) {
        failure_errno = errno ? errno : EIO;
        goto proof_fail;
    }
    if (trailing_count != 0) {
        failure_errno = ESTALE;
        goto proof_fail;
    }

    errno = 0;
    if (fstat(fd, &descriptor_after) != 0) {
        failure_errno = errno ? errno : EIO;
        goto proof_fail;
    }
    if (!config_metadata_file_is_safe(&descriptor_after, true) ||
        (!config_metadata_snapshot_same(&opened, &descriptor_after) &&
         !config_metadata_ctime_only_change(&opened,
                                            &descriptor_after))) {
        failure_errno = ESTALE;
        goto proof_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto proof_fail;
    }
    fd = -1;

    /* FreeBSD UFS can defer the reader-induced ctime materialization until
     * the proof descriptor closes. Snapshot the pathname only after that
     * close, admitting solely this ctime-only step because the complete bytes
     * and all other metadata were just proved on the same inode. */
    errno = 0;
    if (fstatat(dir_fd, name, &named_after, AT_SYMLINK_NOFOLLOW) != 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto proof_fail;
    }
    if (!config_metadata_file_is_safe(&named_after, true) ||
        (!config_metadata_snapshot_same(&descriptor_after, &named_after) &&
         !config_metadata_ctime_only_change(&descriptor_after,
                                            &named_after))) {
        failure_errno = ESTALE;
        goto proof_fail;
    }

    *current_generation = named_after;
    secure_zero_memory(observed, sizeof(observed));
    return 0;

proof_fail:
    if (fd >= 0) close(fd);
    secure_zero_memory(observed, sizeof(observed));
    errno = failure_errno;
    return -1;
}

/* Re-prove an admitted before-image without imposing the 0600 requirement
 * used for newly published files. Historical resume hints may legitimately
 * retain a stricter group-readable mode that rollback must preserve. */
static int config_reprove_existing_file_at(
    int dir_fd, const char *name, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *current_generation) {
    unsigned char observed[4096];
    struct stat named_before;
    struct stat opened;
    struct stat after;
    struct stat named_after;
    unsigned char trailing;
    ssize_t trailing_count;
    size_t offset = 0U;
    int fd = -1;
    int saved_errno = ESTALE;

    if (dir_fd < 0 || !name || !expected ||
        (!expected_data && expected_length != 0U) ||
        !current_generation) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(
            dir_fd, name, &named_before,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named_before, false) ||
        named_before.st_size < 0 ||
        (uintmax_t)named_before.st_size != expected_length ||
        (!config_metadata_snapshot_same(expected, &named_before) &&
         !config_metadata_ctime_only_change(expected, &named_before))) {
        goto existing_fail;
    }
    fd = openat(
        dir_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, false) ||
        (!config_metadata_snapshot_same(&named_before, &opened) &&
         !config_metadata_ctime_only_change(&named_before, &opened))) {
        goto existing_fail;
    }
    while (offset < expected_length) {
        size_t remaining = expected_length - offset;
        size_t chunk =
            remaining < sizeof(observed) ? remaining : sizeof(observed);

        if (!config_pread_full(
                fd, observed, chunk, (off_t)offset) ||
            memcmp(observed, expected_data + offset, chunk) != 0) {
            goto existing_fail;
        }
        offset += chunk;
    }
    do {
        errno = 0;
        trailing_count =
            pread(fd, &trailing, 1, (off_t)expected_length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count != 0 ||
        fstat(fd, &after) != 0 ||
        fstatat(
            dir_fd, name, &named_after,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        (!config_metadata_snapshot_same(&opened, &after) &&
         !config_metadata_ctime_only_change(&opened, &after)) ||
        (!config_metadata_snapshot_same(&after, &named_after) &&
         !config_metadata_ctime_only_change(&after, &named_after))) {
        goto existing_fail;
    }
    *current_generation = named_after;
    (void)close(fd);
    secure_zero_memory(observed, sizeof(observed));
    return 0;

existing_fail:
    saved_errno = errno ? errno : ESTALE;
    if (fd >= 0) (void)close(fd);
    secure_zero_memory(observed, sizeof(observed));
    errno = saved_errno;
    return -1;
}

/* Re-prove a stable loaded or self-published source through a pinned, private
 * parent directory. Callers must carry the exact bounded document witness. */
static int config_reprove_loaded_source(
    const char *config_path, const struct stat *expected,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *accepted_generation) {
    char dir_path[MAX_PATH_LEN];
    const char *slash;
    const char *target_name;
    struct stat pinned_dir;
    struct stat current_generation;
    size_t dir_length;
    int dir_fd = -1;
    int failure_errno = ESTALE;

    if (!config_path || !config_path[0] || !expected ||
        (!expected_data && expected_length != 0U)) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(config_path, '/');
    target_name = slash ? slash + 1 : config_path;
    if (target_name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    if (!slash) {
        if (safe_strncpy(dir_path, ".", sizeof(dir_path)) != 0) {
            return -1;
        }
    } else {
        dir_length = (size_t)(slash - config_path);
        if (dir_length == 0U) dir_length = 1U;
        if (dir_length >= sizeof(dir_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(dir_path, config_path, dir_length);
        dir_path[dir_length] = '\0';
    }

    errno = 0;
    dir_fd = open(dir_path,
                  O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto reproof_fail;
    }
    if (fstat(dir_fd, &pinned_dir) != 0) {
        failure_errno = errno ? errno : EIO;
        goto reproof_fail;
    }
    if (!config_metadata_dir_is_safe(&pinned_dir) ||
        !config_named_directory_matches(dir_path, &pinned_dir)) {
        failure_errno = ESTALE;
        goto reproof_fail;
    }
    if (config_reprove_published_file_at(
            dir_fd, target_name, expected, expected_data, expected_length,
            &current_generation) != 0) {
        failure_errno = errno ? errno : ESTALE;
        goto reproof_fail;
    }
    if (!config_named_directory_matches(dir_path, &pinned_dir)) {
        failure_errno = ESTALE;
        goto reproof_fail;
    }
    if (close(dir_fd) != 0) {
        dir_fd = -1;
        errno = errno ? errno : EIO;
        return -1;
    }
    if (accepted_generation) {
        *accepted_generation = current_generation;
    }
    return 0;

reproof_fail:
    if (dir_fd >= 0) close(dir_fd);
    errno = failure_errno;
    return -1;
}

/* Re-prove the exact bounded active-state before-image immediately before its
 * replacement. Strict metadata catches ordinary edits, while the byte proof
 * also rejects an in-place same-length rewrite even if timestamp evidence is
 * unavailable or has been restored. */
static int config_require_active_state_generation(
    const char *hint, const config_active_state_generation_t *expected) {
    unsigned char observed[4096];
    struct stat named_before;
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    unsigned char trailing;
    ssize_t trailing_count;
    int fd = -1;
    int failure_errno = ESTALE;
    size_t offset = 0;

    if (!hint || !expected || expected->length > CONFIG_ACTIVE_STATE_MAX ||
        (expected->length != 0U && !expected->data)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid active-state generation proof arguments");
        return -1;
    }

    if (!expected->existed) {
        errno = 0;
        if (lstat(hint, &named_before) != 0) {
            if (errno == ENOENT) return 0;
            failure_errno = config_is_namespace_change_errno(errno)
                                ? ESTALE
                                : (errno ? errno : EIO);
        }
        errno = failure_errno;
        set_system_error(
            ERR_FILE_IO,
            "Resume hint changed before update; refusing replacement: %s",
            hint);
        return -1;
    }

    errno = 0;
    if (lstat(hint, &named_before) != 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto generation_mismatch;
    }
    if (!config_metadata_file_is_safe(&named_before, false) ||
        (!config_metadata_snapshot_same(&expected->metadata, &named_before) &&
         !config_metadata_ctime_only_change(&expected->metadata,
                                            &named_before))) {
        failure_errno = ESTALE;
        goto generation_mismatch;
    }
    errno = 0;
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto generation_mismatch;
    }
    errno = 0;
    if (fstat(fd, &opened) != 0) {
        failure_errno = errno ? errno : EIO;
        goto generation_mismatch;
    }
    if (!config_metadata_file_is_safe(&opened, false) ||
        (!config_metadata_snapshot_same(&named_before, &opened) &&
         !config_metadata_ctime_only_change(&named_before, &opened)) ||
        (!config_metadata_snapshot_same(&expected->metadata, &opened) &&
         !config_metadata_ctime_only_change(&expected->metadata, &opened)) ||
        opened.st_size < 0 ||
        (uintmax_t)opened.st_size != expected->length) {
        failure_errno = ESTALE;
        goto generation_mismatch;
    }
    while (offset < expected->length) {
        size_t wanted = expected->length - offset;
        if (wanted > sizeof(observed)) wanted = sizeof(observed);
        errno = 0;
        if (!config_pread_full(fd, observed, wanted, (off_t)offset)) {
            failure_errno = errno ? errno : EIO;
            goto generation_mismatch;
        }
        if (memcmp(observed, expected->data + offset, wanted) != 0) {
            failure_errno = ESTALE;
            goto generation_mismatch;
        }
        offset += wanted;
    }
    errno = 0;
    do {
        trailing_count = pread(fd, &trailing, 1, (off_t)expected->length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count < 0) {
        failure_errno = errno ? errno : EIO;
        goto generation_mismatch;
    }
    if (trailing_count != 0) {
        failure_errno = ESTALE;
        goto generation_mismatch;
    }
    errno = 0;
    if (fstat(fd, &descriptor_after) != 0) {
        failure_errno = errno ? errno : EIO;
        goto generation_mismatch;
    }
    if (!config_metadata_file_is_safe(&descriptor_after, false) ||
        (!config_metadata_snapshot_same(&opened, &descriptor_after) &&
         !config_metadata_ctime_only_change(&opened, &descriptor_after))) {
        failure_errno = ESTALE;
        goto generation_mismatch;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto generation_mismatch;
    }
    fd = -1;
    errno = 0;
    if (lstat(hint, &named_after) != 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto generation_mismatch;
    }
    if (!config_metadata_file_is_safe(&named_after, false) ||
        (!config_metadata_snapshot_same(&descriptor_after, &named_after) &&
         !config_metadata_ctime_only_change(&descriptor_after,
                                            &named_after))) {
        failure_errno = ESTALE;
        goto generation_mismatch;
    }

    secure_zero_memory(observed, sizeof(observed));
    return 0;

generation_mismatch:
    {
        if (fd >= 0) close(fd);
        secure_zero_memory(observed, sizeof(observed));
        errno = failure_errno;
        set_system_error(
            ERR_FILE_IO,
            "Resume hint changed before update; refusing replacement: %s",
            hint);
    }
    return -1;
}

/* Refresh a publication baseline only when the new durable backup proves the
 * original strict generation was copied and the currently named source still
 * contains those exact bytes. This admits FreeBSD's delayed ctime-only update
 * without admitting a same-size in-place rewrite whose mtime was restored. */
static bool config_refresh_publication_identity(
    const char *config_path, const char *backup_path,
    const struct stat *copied_source, const struct stat *backup_identity,
    struct stat *publication_identity) {
    unsigned char source_buffer[4096];
    unsigned char backup_buffer[4096];
    struct stat source_before;
    struct stat source_after;
    struct stat source_named;
    struct stat backup_before;
    struct stat backup_after;
    struct stat backup_named;
    off_t offset = 0;
    int source_fd = -1;
    int backup_fd = -1;
    bool matches = false;

    /* This ordering is load-bearing: a source edit before the backup starts
     * changes ctime and must be rejected before backup bytes can be a witness. */
    if (copied_source &&
        !config_metadata_snapshot_same(publication_identity, copied_source)) {
        errno = ESTALE;
        return false;
    }
    if (lstat(config_path, &source_before) != 0) return false;
    if (config_metadata_snapshot_same(publication_identity, &source_before)) {
        return true;
    }
    if (!config_metadata_ctime_only_change(publication_identity,
                                           &source_before)) {
        errno = ESTALE;
        return false;
    }

    /* AR-12 L6: O_NONBLOCK is inert for regular files and prevents a
     * raced-in FIFO from wedging while the publication lock is held; the
     * fstat/S_ISREG checks below reject the non-regular descriptor. */
    source_fd = open(config_path,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (source_fd < 0) goto refresh_done;
    backup_fd = open(backup_path,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (backup_fd < 0 || fstat(source_fd, &source_after) != 0 ||
        fstat(backup_fd, &backup_before) != 0) {
        goto refresh_done;
    }
    {
        bool forced_mismatch =
            g_config_metadata_test_hook &&
            g_config_metadata_test_hook(
                CONFIG_METADATA_TEST_REFRESH_INITIAL);
        errno = 0;
        if (forced_mismatch ||
            !config_metadata_file_is_safe(&source_after, true) ||
            !config_metadata_file_is_safe(&backup_before, true) ||
            !config_metadata_snapshot_same(&source_before, &source_after) ||
            !config_metadata_snapshot_same(backup_identity, &backup_before) ||
            source_after.st_size < 0 ||
            source_after.st_size > (off_t)TOML_MAX_FILE_SIZE ||
            source_after.st_size != backup_before.st_size) {
            errno = ESTALE;
            goto refresh_done;
        }
    }

    while (offset < source_after.st_size) {
        off_t remaining = source_after.st_size - offset;
        size_t chunk = remaining < (off_t)sizeof(source_buffer)
            ? (size_t)remaining : sizeof(source_buffer);
        if (!config_pread_full(source_fd, source_buffer, chunk, offset) ||
            !config_pread_full(backup_fd, backup_buffer, chunk, offset) ||
            memcmp(source_buffer, backup_buffer, chunk) != 0) {
            errno = ESTALE;
            goto refresh_done;
        }
        offset += (off_t)chunk;
    }

    if (fstat(source_fd, &source_after) != 0 ||
        lstat(config_path, &source_named) != 0 ||
        fstat(backup_fd, &backup_after) != 0 ||
        lstat(backup_path, &backup_named) != 0) {
        goto refresh_done;
    }
    {
        bool forced_mismatch =
            g_config_metadata_test_hook &&
            g_config_metadata_test_hook(CONFIG_METADATA_TEST_REFRESH_FINAL);
        errno = 0;
        if (forced_mismatch ||
            !config_metadata_snapshot_same(&source_before, &source_after) ||
            !config_metadata_snapshot_same(&source_before, &source_named) ||
            !config_metadata_snapshot_same(backup_identity, &backup_after) ||
            !config_metadata_snapshot_same(backup_identity, &backup_named)) {
            errno = ESTALE;
            goto refresh_done;
        }
    }

    *publication_identity = source_after;
    matches = true;

refresh_done:
    {
        int saved_errno = matches ? 0 : (errno ? errno : ESTALE);
        if (source_fd >= 0) close(source_fd);
        if (backup_fd >= 0) close(backup_fd);
        if (!matches) errno = saved_errno;
    }
    secure_zero_memory(source_buffer, sizeof(source_buffer));
    secure_zero_memory(backup_buffer, sizeof(backup_buffer));
    return matches;
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

/* Re-open the canonical parent after publication and prove that it still
 * selects both the pinned directory and the exact generation installed
 * through that directory. A descriptor-pinned rename can succeed after the
 * parent pathname is detached; proving only through the original descriptor
 * would then misreport a file that is no longer canonical as installed. */
static int config_reprove_canonical_publication(
    const char *dir_path, const struct stat *pinned_dir,
    const char *target_name, const struct stat *installed_generation,
    const unsigned char *document_bytes, size_t document_length,
    struct stat *canonical_generation) {
    struct stat reopened_dir;
    int canonical_dir_fd = -1;
    int failure_errno = ESTALE;

    errno = 0;
    canonical_dir_fd = open(dir_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY |
                                          O_NOFOLLOW);
    if (canonical_dir_fd < 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto canonical_fail;
    }
    if (fstat(canonical_dir_fd, &reopened_dir) != 0) {
        failure_errno = errno ? errno : EIO;
        goto canonical_fail;
    }
    if (!config_metadata_dir_is_safe(&reopened_dir) ||
        !config_metadata_same_file(pinned_dir, &reopened_dir)) {
        failure_errno = ESTALE;
        goto canonical_fail;
    }

    errno = 0;
    if (!config_named_directory_matches(dir_path, &reopened_dir)) {
        failure_errno = errno ? errno : ESTALE;
        if (config_is_namespace_change_errno(failure_errno)) {
            failure_errno = ESTALE;
        }
        goto canonical_fail;
    }
    if (config_reprove_published_file_at(
            canonical_dir_fd, target_name, installed_generation,
            document_bytes, document_length, canonical_generation) != 0) {
        failure_errno = errno ? errno : EIO;
        goto canonical_fail;
    }
    errno = 0;
    if (!config_named_directory_matches(dir_path, &reopened_dir)) {
        failure_errno = errno ? errno : ESTALE;
        if (config_is_namespace_change_errno(failure_errno)) {
            failure_errno = ESTALE;
        }
        goto canonical_fail;
    }
    if (close(canonical_dir_fd) != 0) {
        canonical_dir_fd = -1;
        failure_errno = errno ? errno : EIO;
        goto canonical_fail;
    }
    return 0;

canonical_fail:
    if (canonical_dir_fd >= 0) close(canonical_dir_fd);
    errno = failure_errno;
    return -1;
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

/* Atomically publish one proved source generation only if destination is
 * absent. Every supported platform either provides a one-step no-replace move
 * or a descriptor-conditioned way to retire the exact source and rollback
 * alias. Unsupported platforms fail before changing the namespace. */
static int config_publish_noreplace_at(
    int dir_fd, const char *source, const char *destination,
    const struct stat *expected_source,
    struct stat *retained_source) {
    struct stat source_now;

    if (retained_source) memset(retained_source, 0, sizeof(*retained_source));
    if (dir_fd < 0 || !source || !destination || !expected_source ||
        fstatat(dir_fd, source, &source_now, AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_snapshot_same(expected_source, &source_now)) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
    if (syscall(SYS_renameat2, dir_fd, source, dir_fd, destination,
                RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP) {
        errno = ENOTSUP;
    }
    return -1;
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    return renameatx_np(
        dir_fd, source, dir_fd, destination, RENAME_EXCL);
#elif defined(__FreeBSD__)
    {
        struct stat pinned;
        struct stat destination_now;
        int source_fd = openat(
            dir_fd, source,
            O_PATH | O_CLOEXEC | O_NOFOLLOW);
        int saved_errno;

        if (source_fd < 0 || fstat(source_fd, &pinned) != 0 ||
            !config_metadata_snapshot_same(expected_source, &pinned)) {
            saved_errno = errno ? errno : ESTALE;
            if (source_fd >= 0) (void)close(source_fd);
            errno = saved_errno;
            return -1;
        }
        if (linkat(dir_fd, source, dir_fd, destination, 0) != 0) {
            saved_errno = errno;
            (void)close(source_fd);
            errno = saved_errno;
            return -1;
        }
        if (fstatat(
                dir_fd, destination, &destination_now,
                AT_SYMLINK_NOFOLLOW) != 0 ||
            !config_metadata_same_file(&pinned, &destination_now)) {
            saved_errno = errno ? errno : ESTALE;
            /* Remove only the alias to the pinned intended source. If either
             * source or destination was replaced after linkat(), preserve the
             * occupant rather than authorizing it through a fresh open. */
            (void)funlinkat(
                dir_fd, destination, source_fd, 0);
            (void)close(source_fd);
            errno = saved_errno;
            return -1;
        }
        if (CONFIG_PUBLISH_TEST_CHECKPOINT(
                CONFIG_PUBLISH_TEST_SOURCE_UNLINK,
                dir_fd, source, destination) != 0 ||
            funlinkat(dir_fd, source, source_fd, 0) != 0) {
            saved_errno = errno ? errno : EIO;
            if (CONFIG_PUBLISH_TEST_CHECKPOINT(
                    CONFIG_PUBLISH_TEST_ROLLBACK_UNLINK,
                    dir_fd, source, destination) != 0 ||
                funlinkat(
                    dir_fd, destination, source_fd, 0) != 0) {
                struct stat source_retained;
                struct stat destination_retained;

                (void)CONFIG_PUBLISH_TEST_CHECKPOINT(
                    CONFIG_PUBLISH_TEST_AFTER_ROLLBACK_FAILURE,
                    dir_fd, source, destination);
                /* The canonical destination is now committed. Never report
                 * this as a pre-publication failure merely because both
                 * descriptor-conditioned cleanup attempts failed. Reprove
                 * both aliases against the pinned inode and return the
                 * distinct positive outcome; callers treat it as installed
                 * and later fixed-name reconciliation can retire the source.
                 */
                bool source_is_retained =
                    fstatat(
                        dir_fd, source, &source_retained,
                        AT_SYMLINK_NOFOLLOW) == 0 &&
                    config_metadata_same_file(
                        &pinned, &source_retained);

                if (source_is_retained && retained_source) {
                    *retained_source = source_retained;
                }
                if (source_is_retained &&
                    fstatat(
                        dir_fd, destination, &destination_retained,
                        AT_SYMLINK_NOFOLLOW) == 0 &&
                    config_metadata_same_file(
                        &pinned, &destination_retained)) {
                    (void)close(source_fd);
                    errno = 0;
                    return CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED;
                }
                (void)close(source_fd);
                errno = EINPROGRESS;
                return CONFIG_PUBLISH_OUTCOME_UNCERTAIN;
            }
            (void)close(source_fd);
            errno = saved_errno;
            return -1;
        }
        (void)close(source_fd);
        return 0;
    }
#else
    errno = ENOTSUP;
    return -1;
#endif
}

#if !defined(__FreeBSD__)
typedef enum {
    CONFIG_EXCHANGE_ERROR = -1,
    CONFIG_EXCHANGE_OK = 0,
    CONFIG_EXCHANGE_UNSUPPORTED = 1
} config_exchange_result_t;

static config_exchange_result_t config_exchange_names_at(
    int dir_fd, const char *left, const char *right) {
    int result = -1;

#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
    result = (int)syscall(SYS_renameat2, dir_fd, left, dir_fd, right,
                          RENAME_EXCHANGE);
#elif defined(__APPLE__) && defined(RENAME_SWAP)
    result = renameatx_np(dir_fd, left, dir_fd, right, RENAME_SWAP);
#else
    (void)dir_fd;
    (void)left;
    (void)right;
    errno = ENOTSUP;
    return CONFIG_EXCHANGE_UNSUPPORTED;
#endif
    if (result == 0) return CONFIG_EXCHANGE_OK;
    if (errno == ENOSYS || errno == EINVAL || errno == ENOTSUP ||
        errno == EOPNOTSUPP) {
        return CONFIG_EXCHANGE_UNSUPPORTED;
    }
    return CONFIG_EXCHANGE_ERROR;
}
#endif

static int config_lock_reject(int token_fd, const char *lockpath) {
    if (token_fd >= 0) unlock_private_file(token_fd);
    set_error(ERR_PERMISSION_DENIED,
              "Config lock is not a stable, private regular file: %s",
              lockpath);
    errno = EACCES;
    return -1;
}

static int config_directory_for_path(const char *config_path, char *dir,
                                     size_t dir_size) {
    const char *slash;
    size_t dir_length;

    if (!config_path || !config_path[0] || !dir || dir_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid config path for write locking");
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(config_path, '/');
    if (!slash) {
        return safe_strncpy(dir, ".", dir_size);
    }
    dir_length = (size_t)(slash - config_path);
    if (dir_length == 0) dir_length = 1;
    if (dir_length >= dir_size) {
        set_error(ERR_INVALID_PATH, "Config directory path is too long");
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(dir, config_path, dir_length);
    dir[dir_length] = '\0';
    return 0;
}

#define CONFIG_RETIREMENT_GUARD_NAME ".retirement-incomplete"
#define CONFIG_RETIREMENT_COMPLETE_NAME ".retirement-complete"
#define CONFIG_RETIREMENT_STAGE_NAME ".retirement-transition"
#define CONFIG_RETIREMENT_LOCK_NAME ".retirement.lock"
#define CONFIG_RETIREMENT_SETTLED_PREFIX \
    ".gitswitch-retirement-settled-"
#define CONFIG_RETIREMENT_GUARD_HEADER_V1 \
    "gitswitch-retirement-incomplete-v1"
#define CONFIG_RETIREMENT_GUARD_HEADER_V2 \
    "gitswitch-retirement-incomplete-v2"
#define CONFIG_RETIREMENT_GUARD_MAX_BYTES 32768U

typedef struct {
    unsigned int version;
    config_retirement_kind_t kind;
    config_retirement_owner_t owners[MAX_ACCOUNTS];
    size_t owner_count;
    config_retirement_ssh_alias_obligation_t ssh_alias_obligation;
    char token[ACCOUNT_INCARNATION_LEN];
} config_retirement_guard_model_t;

static int config_switch_parse_identity(
    const unsigned char *value, size_t length,
    publication_identity_t *identity);
static int config_switch_decode_hex(
    const unsigned char *value, size_t length, char *out,
    size_t out_size);
static int config_retirement_guard_move_noreplace_at(
    int directory_fd, const char *source, const char *destination,
    const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *published_identity, bool *committed);

struct config_retirement_guard {
    int directory_fd;
    int lock_fd;
    pid_t owner_pid;
    char directory[MAX_PATH_LEN];
    struct stat directory_identity;
    struct stat marker_identity;
    struct stat prepared_stage_identity;
    unsigned char *marker_data;
    size_t marker_length;
    struct stat completion_identity;
    unsigned char *completion_data;
    size_t completion_length;
    char prepared_slot_name[64];
    char token[ACCOUNT_INCARNATION_LEN];
    bool completion_absent;
    bool created;
    bool prepared;
    bool barrier_active;
};

#ifdef GITSWITCH_TESTING
int gitswitch_test_retirement_guard_directory_fd(
    const config_retirement_guard_t *guard) {
    return guard ? guard->directory_fd : -1;
}
#endif

/* The application is single-threaded and owns at most one outer retirement
 * transaction. The filesystem lock serializes independent processes; this
 * process-local owner closes its intentionally re-entrant lock helper's
 * second-handle loophole and also rejects a fork child that inherited an
 * unfinished parent transaction. */
static pid_t g_retirement_guard_owner_pid;

static const char *config_retirement_kind_name(
    config_retirement_kind_t kind) {
    switch (kind) {
        case CONFIG_RETIREMENT_REMOVE:
            return "remove";
        case CONFIG_RETIREMENT_RESET:
            return "reset";
        default:
            return NULL;
    }
}

static int config_retirement_owner_compare(const void *left,
                                           const void *right) {
    const config_retirement_owner_t *a = left;
    const config_retirement_owner_t *b = right;

    if (a->account_id < b->account_id) return -1;
    if (a->account_id > b->account_id) return 1;
    return strcmp(a->account_incarnation, b->account_incarnation);
}

static int config_retirement_canonicalize_owners(
    const config_retirement_owner_t *owners, size_t owner_count,
    config_retirement_owner_t canonical[MAX_ACCOUNTS]) {
    if (!owners || owner_count == 0U || owner_count > MAX_ACCOUNTS ||
        !canonical) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "A retirement guard requires one bounded owner set");
        return -1;
    }
    for (size_t i = 0; i < owner_count; i++) {
        if (!config_account_id_is_valid(owners[i].account_id) ||
            !account_incarnation_is_valid(
                owners[i].account_incarnation)) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "Retirement guard owner %zu is not an exact account incarnation",
                      i);
            return -1;
        }
        canonical[i] = owners[i];
    }
    qsort(canonical, owner_count, sizeof(canonical[0]),
          config_retirement_owner_compare);
    for (size_t i = 1; i < owner_count; i++) {
        if (config_retirement_owner_compare(&canonical[i - 1],
                                            &canonical[i]) == 0) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "Retirement guard owner set contains a duplicate");
            return -1;
        }
    }
    return 0;
}

static bool config_retirement_identity_is_zero(
    const publication_identity_t *identity) {
    return identity && !identity->present &&
           identity->device == 0U && identity->inode == 0U &&
           identity->mode == 0U && identity->uid == 0U &&
           identity->gid == 0U && identity->link_count == 0U &&
           identity->size == 0U && identity->mtime_seconds == 0 &&
           identity->mtime_nanoseconds == 0U &&
           identity->ctime_seconds == 0 &&
           identity->ctime_nanoseconds == 0U;
}

static bool config_retirement_path_is_canonical_absolute(
    const char *path, size_t size) {
    const char *component;

    if (!path || !memchr(path, '\0', size) || path[0] != '/') {
        return false;
    }
    if (path[1] == '\0') return true;
    if (path[strlen(path) - 1U] == '/') return false;
    component = path + 1U;
    while (*component) {
        const char *separator = strchr(component, '/');
        size_t length = separator ? (size_t)(separator - component)
                                  : strlen(component);

        if (length == 0U ||
            (length == 1U && component[0] == '.') ||
            (length == 2U && component[0] == '.' &&
             component[1] == '.')) {
            return false;
        }
        if (!separator) break;
        component = separator + 1U;
    }
    return true;
}

static bool config_retirement_directory_identity_valid(
    const publication_identity_t *identity, bool optional) {
    mode_t mode;

    if (!identity) return false;
    if (!identity->present) {
        return optional && config_retirement_identity_is_zero(identity);
    }
    mode = (mode_t)identity->mode;
    return (uintmax_t)mode == identity->mode && S_ISDIR(mode) &&
           identity->link_count > 0U &&
           identity->mtime_nanoseconds <= UINT32_C(999999999) &&
           identity->ctime_nanoseconds <= UINT32_C(999999999);
}

static bool config_retirement_obligation_valid(
    config_retirement_kind_t kind,
    const config_retirement_ssh_alias_obligation_t *obligation,
    size_t owner_count, bool allow_unknown) {
    if (!obligation) return false;
    if (!obligation->known) {
        return allow_unknown && !obligation->present &&
               obligation->ssh_host_alias[0] == '\0' &&
               obligation->home_path[0] == '\0' &&
               config_retirement_identity_is_zero(
                   &obligation->home_identity) &&
               config_retirement_identity_is_zero(
                   &obligation->ssh_directory_identity);
    }
    if (!obligation->present) {
        return obligation->ssh_host_alias[0] == '\0' &&
               obligation->home_path[0] == '\0' &&
               config_retirement_identity_is_zero(
                   &obligation->home_identity) &&
               config_retirement_identity_is_zero(
                   &obligation->ssh_directory_identity);
    }
    return kind == CONFIG_RETIREMENT_REMOVE && owner_count == 1U &&
           memchr(obligation->ssh_host_alias, '\0',
                  sizeof(obligation->ssh_host_alias)) != NULL &&
           toml_validate_ssh_host_alias(obligation->ssh_host_alias) &&
           config_retirement_path_is_canonical_absolute(
               obligation->home_path,
               sizeof(obligation->home_path)) &&
           config_retirement_directory_identity_valid(
               &obligation->home_identity, false) &&
           config_retirement_directory_identity_valid(
               &obligation->ssh_directory_identity, true);
}

static bool config_retirement_obligations_equal(
    const config_retirement_ssh_alias_obligation_t *left,
    const config_retirement_ssh_alias_obligation_t *right) {
    return left && right && left->known == right->known &&
           left->present == right->present &&
           strcmp(left->ssh_host_alias, right->ssh_host_alias) == 0 &&
           strcmp(left->home_path, right->home_path) == 0 &&
           publication_identity_equal(
               &left->home_identity, &right->home_identity) &&
           publication_identity_equal(
               &left->ssh_directory_identity,
               &right->ssh_directory_identity);
}

static bool config_retirement_next_line(const unsigned char **cursor,
                                        const unsigned char *end,
                                        const unsigned char **line,
                                        size_t *line_length) {
    const unsigned char *newline;

    if (!cursor || !*cursor || !end || !line || !line_length ||
        *cursor >= end) {
        return false;
    }
    newline = memchr(*cursor, '\n', (size_t)(end - *cursor));
    if (!newline) return false;
    *line = *cursor;
    *line_length = (size_t)(newline - *cursor);
    *cursor = newline + 1;
    return true;
}

static bool config_retirement_line_equals(const unsigned char *line,
                                          size_t line_length,
                                          const char *expected) {
    size_t expected_length = strlen(expected);
    return line_length == expected_length &&
           memcmp(line, expected, expected_length) == 0;
}

static bool config_retirement_parse_uint(const unsigned char *value,
                                         size_t length,
                                         uint32_t *parsed) {
    uint32_t result = 0;

    if (!value || length == 0U || !parsed ||
        (length > 1U && value[0] == (unsigned char)'0')) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        uint32_t digit;
        if (value[i] < (unsigned char)'0' ||
            value[i] > (unsigned char)'9') {
            return false;
        }
        digit = (uint32_t)(value[i] - (unsigned char)'0');
        if (result > (UINT32_MAX - digit) / 10U) return false;
        result = result * 10U + digit;
    }
    if (!config_account_id_is_valid(result)) return false;
    *parsed = result;
    return true;
}

static bool config_retirement_parse_count(const unsigned char *value,
                                          size_t length,
                                          size_t *parsed) {
    size_t result = 0;

    if (!value || length == 0U || !parsed ||
        (length > 1U && value[0] == (unsigned char)'0')) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        size_t digit;
        if (value[i] < (unsigned char)'0' ||
            value[i] > (unsigned char)'9') {
            return false;
        }
        digit = (size_t)(value[i] - (unsigned char)'0');
        if (result > (SIZE_MAX - digit) / 10U) return false;
        result = result * 10U + digit;
    }
    if (result == 0U || result > MAX_ACCOUNTS) return false;
    *parsed = result;
    return true;
}

static int config_retirement_guard_parse(
    const unsigned char *data, size_t length,
    config_retirement_guard_model_t *model) {
    static const char token_prefix[] = "token=";
    static const char operation_prefix[] = "operation=";
    static const char owners_prefix[] = "owners=";
    static const char owner_prefix[] = "owner=";
    static const char obligation_prefix[] = "ssh_obligation=";
    static const char alias_prefix[] = "ssh_alias=";
    static const char home_path_prefix[] = "home_path=";
    static const char home_identity_prefix[] = "home_identity=";
    static const char ssh_identity_prefix[] = "ssh_directory_identity=";
    const unsigned char *cursor = data;
    const unsigned char *end;
    const unsigned char *line;
    size_t line_length;

    if (!data || length == 0U ||
        length > CONFIG_RETIREMENT_GUARD_MAX_BYTES || !model) {
        goto malformed;
    }
    memset(model, 0, sizeof(*model));
    end = data + length;

    if (!config_retirement_next_line(&cursor, end, &line, &line_length)) {
        goto malformed;
    }
    if (config_retirement_line_equals(
            line, line_length, CONFIG_RETIREMENT_GUARD_HEADER_V1)) {
        model->version = 1U;
    } else if (config_retirement_line_equals(
                   line, line_length,
                   CONFIG_RETIREMENT_GUARD_HEADER_V2)) {
        model->version = 2U;
        model->ssh_alias_obligation.known = true;
    } else {
        goto malformed;
    }
    if (!config_retirement_next_line(&cursor, end, &line, &line_length) ||
        line_length != sizeof(token_prefix) - 1U +
                           ACCOUNT_INCARNATION_HEX_LEN ||
        memcmp(line, token_prefix, sizeof(token_prefix) - 1U) != 0) {
        goto malformed;
    }
    memcpy(model->token, line + sizeof(token_prefix) - 1U,
           ACCOUNT_INCARNATION_HEX_LEN);
    model->token[ACCOUNT_INCARNATION_HEX_LEN] = '\0';
    if (!account_incarnation_is_valid(model->token)) goto malformed;

    if (!config_retirement_next_line(&cursor, end, &line, &line_length) ||
        line_length <= sizeof(operation_prefix) - 1U ||
        memcmp(line, operation_prefix,
               sizeof(operation_prefix) - 1U) != 0) {
        goto malformed;
    }
    line += sizeof(operation_prefix) - 1U;
    line_length -= sizeof(operation_prefix) - 1U;
    if (config_retirement_line_equals(line, line_length, "remove")) {
        model->kind = CONFIG_RETIREMENT_REMOVE;
    } else if (config_retirement_line_equals(line, line_length, "reset")) {
        model->kind = CONFIG_RETIREMENT_RESET;
        /* RESET has never carried an SSH-alias cleanup obligation. Preserve
         * pre-v2 recovery by projecting that historical invariant as an
         * explicit known-none obligation; only a v1 REMOVE is unknowable. */
        if (model->version == 1U) {
            model->ssh_alias_obligation.known = true;
        }
    } else {
        goto malformed;
    }

    if (!config_retirement_next_line(&cursor, end, &line, &line_length) ||
        line_length <= sizeof(owners_prefix) - 1U ||
        memcmp(line, owners_prefix, sizeof(owners_prefix) - 1U) != 0 ||
        !config_retirement_parse_count(
            line + sizeof(owners_prefix) - 1U,
            line_length - (sizeof(owners_prefix) - 1U),
            &model->owner_count)) {
        goto malformed;
    }

    for (size_t i = 0; i < model->owner_count; i++) {
        const unsigned char *colon;
        size_t id_length;
        const unsigned char *incarnation;

        if (!config_retirement_next_line(&cursor, end, &line,
                                         &line_length) ||
            line_length <= sizeof(owner_prefix) - 1U ||
            memcmp(line, owner_prefix, sizeof(owner_prefix) - 1U) != 0) {
            goto malformed;
        }
        line += sizeof(owner_prefix) - 1U;
        line_length -= sizeof(owner_prefix) - 1U;
        colon = memchr(line, ':', line_length);
        if (!colon) goto malformed;
        id_length = (size_t)(colon - line);
        incarnation = colon + 1;
        if (!config_retirement_parse_uint(
                line, id_length, &model->owners[i].account_id) ||
            (size_t)((line + line_length) - incarnation) !=
                ACCOUNT_INCARNATION_HEX_LEN) {
            goto malformed;
        }
        memcpy(model->owners[i].account_incarnation, incarnation,
               ACCOUNT_INCARNATION_HEX_LEN);
        model->owners[i]
            .account_incarnation[ACCOUNT_INCARNATION_HEX_LEN] = '\0';
        if (!account_incarnation_is_valid(
                model->owners[i].account_incarnation) ||
            (i > 0U &&
             config_retirement_owner_compare(&model->owners[i - 1],
                                             &model->owners[i]) >= 0)) {
            goto malformed;
        }
    }
    if (model->version == 2U) {
        if (!config_retirement_next_line(
                &cursor, end, &line, &line_length) ||
            line_length <= sizeof(obligation_prefix) - 1U ||
            memcmp(line, obligation_prefix,
                   sizeof(obligation_prefix) - 1U) != 0) {
            goto malformed;
        }
        line += sizeof(obligation_prefix) - 1U;
        line_length -= sizeof(obligation_prefix) - 1U;
        if (config_retirement_line_equals(
                line, line_length, "none")) {
            model->ssh_alias_obligation.present = false;
        } else if (config_retirement_line_equals(
                       line, line_length, "present")) {
            model->ssh_alias_obligation.present = true;
#define CONFIG_RETIREMENT_PARSE_FIELD(prefix, action)                    \
            do {                                                          \
                if (!config_retirement_next_line(                         \
                        &cursor, end, &line, &line_length) ||              \
                    line_length <= sizeof(prefix) - 1U ||                 \
                    memcmp(line, prefix, sizeof(prefix) - 1U) != 0 ||      \
                    (action) != 0) {                                      \
                    goto malformed;                                       \
                }                                                         \
            } while (0)
            CONFIG_RETIREMENT_PARSE_FIELD(
                alias_prefix,
                config_switch_decode_hex(
                    line + sizeof(alias_prefix) - 1U,
                    line_length - (sizeof(alias_prefix) - 1U),
                    model->ssh_alias_obligation.ssh_host_alias,
                    sizeof(model->ssh_alias_obligation.ssh_host_alias)));
            CONFIG_RETIREMENT_PARSE_FIELD(
                home_path_prefix,
                config_switch_decode_hex(
                    line + sizeof(home_path_prefix) - 1U,
                    line_length - (sizeof(home_path_prefix) - 1U),
                    model->ssh_alias_obligation.home_path,
                    sizeof(model->ssh_alias_obligation.home_path)));
            CONFIG_RETIREMENT_PARSE_FIELD(
                home_identity_prefix,
                config_switch_parse_identity(
                    line + sizeof(home_identity_prefix) - 1U,
                    line_length -
                        (sizeof(home_identity_prefix) - 1U),
                    &model->ssh_alias_obligation.home_identity));
            CONFIG_RETIREMENT_PARSE_FIELD(
                ssh_identity_prefix,
                config_switch_parse_identity(
                    line + sizeof(ssh_identity_prefix) - 1U,
                    line_length -
                        (sizeof(ssh_identity_prefix) - 1U),
                    &model->ssh_alias_obligation
                         .ssh_directory_identity));
#undef CONFIG_RETIREMENT_PARSE_FIELD
        } else {
            goto malformed;
        }
        if (!config_retirement_obligation_valid(
                model->kind, &model->ssh_alias_obligation,
                model->owner_count, false)) {
            goto malformed;
        }
    }
    if (cursor != end) goto malformed;
    return 0;

malformed:
    if (model) secure_zero_memory(model, sizeof(*model));
    errno = EINVAL;
    set_error(ERR_CONFIG_INVALID,
              "Retirement-incomplete marker is malformed");
    return -1;
}

static int config_retirement_guard_serialize(
    config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    const char token[ACCOUNT_INCARNATION_LEN],
    unsigned char **serialized, size_t *serialized_length) {
    unsigned char *data;
    size_t used = 0;
    const char *kind_name = config_retirement_kind_name(kind);
    int written;

    if (!kind_name || !owners || owner_count == 0U ||
        owner_count > MAX_ACCOUNTS ||
        !config_retirement_obligation_valid(
            kind, obligation, owner_count, false) ||
        !account_incarnation_is_valid(token) || !serialized ||
        !serialized_length) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard serialization arguments");
        return -1;
    }
    *serialized = NULL;
    *serialized_length = 0;
    data = malloc(CONFIG_RETIREMENT_GUARD_MAX_BYTES);
    if (!data) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate retirement guard marker");
        return -1;
    }
#define CONFIG_RETIREMENT_ACCEPT_WRITE()                                   \
    do {                                                                   \
        if (written < 0 ||                                                 \
            (size_t)written >=                                             \
                CONFIG_RETIREMENT_GUARD_MAX_BYTES - used) {                \
            secure_zero_memory(data, CONFIG_RETIREMENT_GUARD_MAX_BYTES);   \
            free(data);                                                    \
            errno = EOVERFLOW;                                             \
            set_error(ERR_CONFIG_INVALID,                                  \
                      "Retirement guard marker exceeds its byte limit");  \
            return -1;                                                     \
        }                                                                  \
        used += (size_t)written;                                           \
    } while (0)

    written = snprintf((char *)data + used,
                       CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                       "%s\n", CONFIG_RETIREMENT_GUARD_HEADER_V2);
    CONFIG_RETIREMENT_ACCEPT_WRITE();
    written = snprintf((char *)data + used,
                       CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                       "token=%s\n", token);
    CONFIG_RETIREMENT_ACCEPT_WRITE();
    written = snprintf((char *)data + used,
                       CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                       "operation=%s\n", kind_name);
    CONFIG_RETIREMENT_ACCEPT_WRITE();
    written = snprintf((char *)data + used,
                       CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                       "owners=%zu\n", owner_count);
    CONFIG_RETIREMENT_ACCEPT_WRITE();
    for (size_t i = 0; i < owner_count; i++) {
        written = snprintf((char *)data + used,
                           CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                           "owner=%u:%s\n",
                           (unsigned int)owners[i].account_id,
                           owners[i].account_incarnation);
        CONFIG_RETIREMENT_ACCEPT_WRITE();
    }
    written = snprintf(
        (char *)data + used,
        CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
        "ssh_obligation=%s\n",
        obligation->present ? "present" : "none");
    CONFIG_RETIREMENT_ACCEPT_WRITE();
    if (obligation->present) {
        static const char digits[] = "0123456789ABCDEF";
        const char *names[2] = {"ssh_alias=", "home_path="};
        const char *values[2] = {
            obligation->ssh_host_alias, obligation->home_path
        };
        const publication_identity_t *identities[2] = {
            &obligation->home_identity,
            &obligation->ssh_directory_identity
        };
        const char *identity_names[2] = {
            "home_identity=", "ssh_directory_identity="
        };

        for (size_t field = 0U; field < 2U; field++) {
            written = snprintf(
                (char *)data + used,
                CONFIG_RETIREMENT_GUARD_MAX_BYTES - used, "%s",
                names[field]);
            CONFIG_RETIREMENT_ACCEPT_WRITE();
            for (const unsigned char *value =
                     (const unsigned char *)values[field];
                 *value; value++) {
                written = snprintf(
                    (char *)data + used,
                    CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                    "%c%c", digits[*value >> 4U],
                    digits[*value & 0x0fU]);
                CONFIG_RETIREMENT_ACCEPT_WRITE();
            }
            written = snprintf(
                (char *)data + used,
                CONFIG_RETIREMENT_GUARD_MAX_BYTES - used, "\n");
            CONFIG_RETIREMENT_ACCEPT_WRITE();
        }
        for (size_t field = 0U; field < 2U; field++) {
            const publication_identity_t *identity = identities[field];

            written = snprintf(
                (char *)data + used,
                CONFIG_RETIREMENT_GUARD_MAX_BYTES - used, "%s",
                identity_names[field]);
            CONFIG_RETIREMENT_ACCEPT_WRITE();
            if (!identity->present) {
                written = snprintf(
                    (char *)data + used,
                    CONFIG_RETIREMENT_GUARD_MAX_BYTES - used, "-\n");
            } else {
                written = snprintf(
                    (char *)data + used,
                    CONFIG_RETIREMENT_GUARD_MAX_BYTES - used,
                    "%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
                    ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
                    ":%" PRIuMAX ":%" PRId64 ":%" PRIu32
                    ":%" PRId64 ":%" PRIu32 "\n",
                    identity->device, identity->inode, identity->mode,
                    identity->uid, identity->gid,
                    identity->link_count, identity->size,
                    identity->mtime_seconds,
                    identity->mtime_nanoseconds,
                    identity->ctime_seconds,
                    identity->ctime_nanoseconds);
            }
            CONFIG_RETIREMENT_ACCEPT_WRITE();
        }
    }
#undef CONFIG_RETIREMENT_ACCEPT_WRITE
    *serialized = data;
    *serialized_length = used;
    return 0;
}

/* Open only an already-existing private config directory. Probe uses the
 * `allow_absent` result to report a cleanly absent marker without creating or
 * repairing any namespace object. */
static int config_retirement_open_directory(
    const char *config_path, bool allow_absent, char directory[MAX_PATH_LEN],
    struct stat *directory_identity, int *directory_fd) {
    struct stat opened;
    int fd;

    if (!config_path || !directory || !directory_identity || !directory_fd) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard directory arguments");
        return -1;
    }
    *directory_fd = -1;
    if (config_directory_for_path(config_path, directory, MAX_PATH_LEN) != 0) {
        return -1;
    }
    errno = 0;
    if (lstat(directory, directory_identity) != 0) {
        if (allow_absent && errno == ENOENT) return 1;
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect retirement guard directory: %s",
                         directory);
        return -1;
    }
    if (!config_metadata_dir_is_safe(directory_identity)) {
        errno = EACCES;
        set_error(ERR_PERMISSION_DENIED,
                  "Retirement guard directory is not private and self-owned: %s",
                  directory);
        return -1;
    }
    fd = open(directory,
              O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_dir_is_safe(&opened) ||
        !config_metadata_same_file(directory_identity, &opened) ||
        !config_named_directory_matches(directory, directory_identity)) {
        int saved_errno = errno ? errno : ESTALE;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot pin retirement guard directory: %s",
                         directory);
        return -1;
    }
    *directory_fd = fd;
    return 0;
}

static int config_retirement_guard_read_named_at(
    int directory_fd, const char *name, bool *absent, unsigned char **data,
    size_t *length, struct stat *identity,
    config_retirement_guard_model_t *model) {
    struct stat named_before;
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    struct stat named_closed;
    struct stat reproved;
    unsigned char *buffer = NULL;
    unsigned char extra;
    ssize_t extra_count;
    int fd = -1;
    int failure_errno = EIO;
    bool exact_reproof_required = false;

    if (directory_fd < 0 || !name || name[0] == '\0' || !absent || !data ||
        !length || !identity || !model) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard read arguments");
        return -1;
    }
    *absent = false;
    *data = NULL;
    *length = 0;
    memset(identity, 0, sizeof(*identity));
    memset(model, 0, sizeof(*model));

    errno = 0;
    if (fstatat(directory_fd, name, &named_before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *absent = true;
            return 0;
        }
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&named_before, true) ||
        named_before.st_size <= 0 ||
        (uintmax_t)named_before.st_size >
            CONFIG_RETIREMENT_GUARD_MAX_BYTES) {
        failure_errno = EACCES;
        goto read_fail;
    }
    fd = openat(directory_fd, name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&opened, true) ||
        opened.st_size <= 0 ||
        (uintmax_t)opened.st_size > CONFIG_RETIREMENT_GUARD_MAX_BYTES) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    if (!config_metadata_snapshot_same(&named_before, &opened)) {
        if (!config_metadata_ctime_only_change(
                &named_before, &opened)) {
            failure_errno = ESTALE;
            goto read_fail;
        }
        exact_reproof_required = true;
    }
    *length = (size_t)opened.st_size;
    buffer = malloc(*length);
    if (!buffer) {
        failure_errno = ENOMEM;
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate retirement guard read buffer");
        goto read_fail_preserve_error;
    }
    if (!config_pread_full(fd, buffer, *length, 0)) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    do {
        errno = 0;
        extra_count = pread(fd, &extra, 1, (off_t)*length);
    } while (extra_count < 0 && errno == EINTR);
    if (extra_count != 0 ||
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_READ_BEFORE_FINAL_METADATA_CHECK,
            directory_fd, name) != 0 ||
        fstat(fd, &descriptor_after) != 0 ||
        fstatat(directory_fd, name, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0) {
        failure_errno = errno ? errno : ESTALE;
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&descriptor_after, true) ||
        !config_metadata_file_is_safe(&named_after, true)) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    if (!config_metadata_snapshot_same(&opened, &descriptor_after)) {
        if (!config_metadata_ctime_only_change(
                &opened, &descriptor_after)) {
            failure_errno = ESTALE;
            goto read_fail;
        }
        exact_reproof_required = true;
    }
    if (!config_metadata_snapshot_same(&opened, &named_after)) {
        if (!config_metadata_ctime_only_change(
                &opened, &named_after)) {
            failure_errno = ESTALE;
            goto read_fail;
        }
        exact_reproof_required = true;
    }
    if (config_retirement_guard_parse(buffer, *length, model) != 0) {
        failure_errno = errno ? errno : EINVAL;
        goto read_fail_preserve_error;
    }

    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    fd = -1;

    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_READ_AFTER_CLOSE,
            directory_fd, name) != 0) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }

    /* FreeBSD UFS may materialize a reader-induced ctime update only after
     * close. The complete marker bytes and canonical model were just proved
     * through this descriptor, so refresh the pathname generation while
     * admitting only that narrow metadata transition. */
    errno = 0;
    if (fstatat(directory_fd, name, &named_closed,
                AT_SYMLINK_NOFOLLOW) != 0) {
        failure_errno = config_is_namespace_change_errno(errno)
                            ? ESTALE
                            : (errno ? errno : EIO);
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&named_closed, true) ||
        !config_metadata_matches_after_exact_content_proof(
            &descriptor_after, &named_closed)) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    if (exact_reproof_required &&
        config_reprove_published_file_at(
            directory_fd, name, &named_closed, buffer, *length,
            &reproved) != 0) {
        failure_errno = errno ? errno : ESTALE;
        goto read_fail;
    }
    if (exact_reproof_required) named_closed = reproved;
    *identity = named_closed;
    *data = buffer;
    return 0;

read_fail:
    errno = failure_errno;
    set_system_error(ERR_FILE_IO,
                     "Cannot read a stable private retirement-incomplete marker");
read_fail_preserve_error:
    if (fd >= 0) close(fd);
    if (buffer) {
        secure_zero_memory(buffer, *length);
        free(buffer);
    }
    *data = NULL;
    *length = 0;
    secure_zero_memory(model, sizeof(*model));
    errno = failure_errno;
    return -1;
}

/* Earlier M18 builds could retain random clear witnesses. They are never
 * silently reclaimed: any such residue remains a fail-closed compatibility
 * blocker until an operator inspects it. New transitions use one fixed stage
 * name and therefore cannot grow this namespace. */
static int config_retirement_guard_legacy_residue_present_at(
    int directory_fd, bool *present) {
    static const char prefix[] = CONFIG_RETIREMENT_GUARD_NAME ".clear.";
    DIR *stream;
    struct dirent *entry;
    int scan_fd;
    int scan_errno;
    int close_result;

    if (directory_fd < 0 || !present) {
        errno = EINVAL;
        return -1;
    }
    *present = true;
    scan_fd = openat(directory_fd, ".",
                     O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (scan_fd < 0) return -1;
    stream = fdopendir(scan_fd);
    if (!stream) {
        int saved_errno = errno ? errno : EIO;
        close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    *present = false;
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1U) == 0 &&
            entry->d_name[sizeof(prefix) - 1U] != '\0') {
            *present = true;
            break;
        }
    }
    scan_errno = errno;
    close_result = closedir(stream);
    if (scan_errno != 0 || close_result != 0) {
        errno = scan_errno != 0 ? scan_errno : (errno ? errno : EIO);
        *present = true;
        return -1;
    }
    return 0;
}

typedef struct {
    bool marker_absent;
    bool completion_absent;
    bool stage_present;
    unsigned char *marker_data;
    size_t marker_length;
    struct stat marker_identity;
    config_retirement_guard_model_t marker_model;
    unsigned char *completion_data;
    size_t completion_length;
    struct stat completion_identity;
    config_retirement_guard_model_t completion_model;
} config_retirement_guard_pair_t;

static void config_retirement_guard_pair_clear(
    config_retirement_guard_pair_t *pair) {
    if (!pair) return;
    if (pair->marker_data) {
        secure_zero_memory(pair->marker_data, pair->marker_length);
        free(pair->marker_data);
    }
    if (pair->completion_data) {
        secure_zero_memory(pair->completion_data,
                           pair->completion_length);
        free(pair->completion_data);
    }
    secure_zero_memory(pair, sizeof(*pair));
}

static int config_retirement_guard_stage_state_at(
    int directory_fd, bool *present, struct stat *identity) {
    struct stat named;

    if (directory_fd < 0 || !present) {
        errno = EINVAL;
        return -1;
    }
    *present = true;
    if (identity) memset(identity, 0, sizeof(*identity));
    errno = 0;
    if (fstatat(directory_fd, CONFIG_RETIREMENT_STAGE_NAME, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *present = false;
            return 0;
        }
        return -1;
    }
    if (!config_metadata_file_is_safe(&named, true) ||
        named.st_size < 0 ||
        (uintmax_t)named.st_size > CONFIG_RETIREMENT_GUARD_MAX_BYTES) {
        errno = EACCES;
        return -1;
    }
    if (identity) *identity = named;
    return 0;
}

static int config_retirement_guard_name_stable_at(
    int directory_fd, const char *name, bool absent,
    struct stat *expected, const unsigned char *expected_data,
    size_t expected_length) {
    struct stat named;
    struct stat reproved;

    errno = 0;
    if (fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (absent && errno == ENOENT) return 0;
        errno = errno ? errno : ESTALE;
        return -1;
    }
    if (absent || !expected || !expected_data || expected_length == 0U ||
        !config_metadata_file_is_safe(&named, true)) {
        errno = ESTALE;
        return -1;
    }
    if (config_metadata_snapshot_same(expected, &named)) {
        *expected = named;
        return 0;
    }
    if (!config_metadata_ctime_only_change(expected, &named) ||
        config_reprove_published_file_at(
            directory_fd, name, expected, expected_data, expected_length,
            &reproved) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    *expected = reproved;
    return 0;
}

/* Read C and S as one generation. Each individual reader pins and re-proves
 * its descriptor; the final name reproof closes the mixed-generation window
 * across the two reads. A transition stage is part of the snapshot and always
 * blocks probe, even if C/S otherwise form an exact completed pair. */
static int config_retirement_guard_pair_read_at(
    int directory_fd, config_retirement_guard_pair_t *pair) {
    struct stat stage_before;
    struct stat stage_after;
    bool stage_after_present = false;

    if (directory_fd < 0 || !pair) {
        errno = EINVAL;
        return -1;
    }
    memset(pair, 0, sizeof(*pair));
    if (config_retirement_guard_stage_state_at(
            directory_fd, &pair->stage_present, &stage_before) != 0 ||
        config_retirement_guard_read_named_at(
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME,
            &pair->marker_absent, &pair->marker_data,
            &pair->marker_length, &pair->marker_identity,
            &pair->marker_model) != 0) {
        goto pair_fail;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME) != 0 ||
        config_retirement_guard_read_named_at(
            directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
            &pair->completion_absent, &pair->completion_data,
            &pair->completion_length, &pair->completion_identity,
            &pair->completion_model) != 0 ||
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_PAIR_AFTER_COMPLETION_READ,
            directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME) != 0 ||
        config_retirement_guard_name_stable_at(
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME,
            pair->marker_absent, &pair->marker_identity,
            pair->marker_data, pair->marker_length) != 0 ||
        config_retirement_guard_name_stable_at(
            directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
            pair->completion_absent, &pair->completion_identity,
            pair->completion_data, pair->completion_length) != 0 ||
        config_retirement_guard_stage_state_at(
            directory_fd, &stage_after_present, &stage_after) != 0) {
        goto pair_fail;
    }
    if (pair->stage_present != stage_after_present ||
        (pair->stage_present &&
         !config_metadata_snapshot_same(&stage_before, &stage_after))) {
        errno = ESTALE;
        goto pair_fail;
    }
    errno = 0;
    return 0;

pair_fail:
    config_retirement_guard_pair_clear(pair);
    return -1;
}

static bool config_retirement_guard_pair_exact(
    const config_retirement_guard_pair_t *pair) {
    return pair && !pair->marker_absent && !pair->completion_absent &&
           !pair->stage_present &&
           pair->marker_length == pair->completion_length &&
           memcmp(pair->marker_data, pair->completion_data,
                  pair->marker_length) == 0;
}

static bool config_retirement_owner_sets_equal(
    const config_retirement_guard_model_t *model,
    config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation) {
    if (!model || model->kind != kind ||
        model->owner_count != owner_count || !obligation ||
        !config_retirement_obligations_equal(
            &model->ssh_alias_obligation, obligation)) {
        return false;
    }
    for (size_t i = 0; i < owner_count; i++) {
        if (model->owners[i].account_id != owners[i].account_id ||
            strcmp(model->owners[i].account_incarnation,
                   owners[i].account_incarnation) != 0) {
            return false;
        }
    }
    return true;
}

static bool config_retirement_guard_record_same(
    bool left_absent, const struct stat *left_identity,
    const unsigned char *left_data, size_t left_length,
    bool right_absent, const struct stat *right_identity,
    const unsigned char *right_data, size_t right_length) {
    if (left_absent != right_absent) return false;
    if (left_absent) return true;
    return left_identity && right_identity && left_data && right_data &&
           left_length == right_length &&
           memcmp(left_data, right_data, left_length) == 0 &&
           config_metadata_matches_after_exact_content_proof(
               left_identity, right_identity);
}

static bool config_retirement_guard_pair_records_same(
    const config_retirement_guard_pair_t *left,
    const config_retirement_guard_pair_t *right) {
    return left && right &&
           config_retirement_guard_record_same(
               left->marker_absent, &left->marker_identity,
               left->marker_data, left->marker_length,
               right->marker_absent, &right->marker_identity,
               right->marker_data, right->marker_length) &&
           config_retirement_guard_record_same(
               left->completion_absent, &left->completion_identity,
               left->completion_data, left->completion_length,
               right->completion_absent, &right->completion_identity,
               right->completion_data, right->completion_length);
}

static bool config_retirement_guard_pairs_same(
    const config_retirement_guard_pair_t *left,
    const config_retirement_guard_pair_t *right) {
    return left && right &&
           left->stage_present == right->stage_present &&
           config_retirement_guard_pair_records_same(left, right);
}

/* A clear transition is recoverable only when the fixed stage is a complete
 * byte-for-byte copy of the canonical marker. Parsing the stage independently
 * also rejects a safe-looking but malformed or foreign generation. */
static int config_retirement_guard_exact_stage_at(
    int directory_fd, const config_retirement_guard_pair_t *pair,
    struct stat *stage_identity) {
    config_retirement_guard_model_t stage_model;
    unsigned char *stage_data = NULL;
    size_t stage_length = 0U;
    struct stat identity;
    bool absent = false;
    int result = -1;
    int saved_errno = EIO;

    memset(&stage_model, 0, sizeof(stage_model));
    memset(&identity, 0, sizeof(identity));
    if (directory_fd < 0 || !pair || !pair->stage_present ||
        pair->marker_absent || !pair->marker_data || !stage_identity) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement transition reconciliation state");
        return -1;
    }
    if (config_retirement_guard_read_named_at(
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            &absent, &stage_data, &stage_length, &identity,
            &stage_model) != 0) {
        goto stage_done;
    }
    if (absent || stage_length != pair->marker_length ||
        memcmp(stage_data, pair->marker_data, stage_length) != 0) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "Retirement transition stage is not the exact active marker generation");
        goto stage_done;
    }
    *stage_identity = identity;
    result = 0;

stage_done:
    if (result != 0) saved_errno = errno ? errno : EIO;
    if (stage_data) {
        secure_zero_memory(stage_data, stage_length);
        free(stage_data);
    }
    secure_zero_memory(&stage_model, sizeof(stage_model));
    if (result != 0) errno = saved_errno;
    return result;
}

static int config_retirement_guard_settled_slot_name(
    unsigned int slot, char *name, size_t name_size) {
    int written;

    if (!name || slot >= CONFIG_RETIREMENT_SETTLED_SLOTS) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf(
        name, name_size, "%s%u",
        CONFIG_RETIREMENT_SETTLED_PREFIX, slot);
    if (written < 0 || (size_t)written >= name_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int config_retirement_guard_prepare_settled_slot_at(
    config_retirement_guard_t *guard,
    config_retirement_guard_pair_t *pair) {
    if (!guard || !pair || pair->marker_absent ||
        !pair->marker_data || guard->completion_absent) {
        errno = EINVAL;
        return -1;
    }
    guard->prepared_slot_name[0] = '\0';
    for (unsigned int slot = 0U;
         slot < CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT(); slot++) {
        char name[sizeof(guard->prepared_slot_name)];
        struct stat named;

        if (config_retirement_guard_settled_slot_name(
                slot, name, sizeof(name)) != 0) {
            return -1;
        }
        errno = 0;
        if (fstatat(
                guard->directory_fd, name, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) return -1;
            memcpy(
                guard->prepared_slot_name, name,
                strlen(name) + 1U);
            return 0;
        }
    }
    errno = ENOSPC;
    set_error(
        ERR_FILE_IO,
        "Retirement settled arena is full; perform offline quiescent cleanup before retrying");
    return -1;
}

static int config_retirement_guard_select_settled_slot_at(
    int directory_fd, char *selected, size_t selected_size) {
    if (directory_fd < 0 || !selected || selected_size == 0U) {
        errno = EINVAL;
        return -1;
    }
    selected[0] = '\0';
    for (unsigned int slot = 0U;
         slot < CONFIG_RETIREMENT_SETTLED_SLOT_LIMIT(); slot++) {
        char name[64];
        struct stat named;

        if (config_retirement_guard_settled_slot_name(
                slot, name, sizeof(name)) != 0) {
            return -1;
        }
        if (strlen(name) + 1U > selected_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        errno = 0;
        if (fstatat(
                directory_fd, name, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) return -1;
            memcpy(selected, name, strlen(name) + 1U);
            return 0;
        }
    }
    errno = ENOSPC;
    set_error(
        ERR_FILE_IO,
        "Retirement settled arena is full; perform offline quiescent cleanup before retrying");
    return -1;
}

/* Remove only a jointly revalidated exact marker copy. This is the sole
 * mutation admitted by adopt-only recovery: it cannot create or rotate a
 * generation and leaves foreign/malformed stage residue untouched. */
static int config_retirement_guard_reconcile_exact_stage_at(
    int directory_fd, const char *directory,
    const struct stat *directory_identity,
    const config_retirement_guard_pair_t *observed,
    config_retirement_guard_pair_t *after) {
    config_retirement_guard_pair_t revalidated;
    struct stat stage_identity;
    int saved_errno = EIO;

    memset(&revalidated, 0, sizeof(revalidated));
    memset(&stage_identity, 0, sizeof(stage_identity));
    if (directory_fd < 0 || !directory || !directory_identity ||
        !observed || !after || !observed->stage_present ||
        config_retirement_guard_exact_stage_at(
            directory_fd, observed, &stage_identity) != 0) {
        return -1;
    }
    if (config_retirement_guard_pair_read_at(
            directory_fd, &revalidated) != 0 ||
        !config_retirement_guard_pairs_same(
            observed, &revalidated) ||
        config_retirement_guard_name_stable_at(
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            false, &stage_identity, observed->marker_data,
            observed->marker_length) != 0 ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        saved_errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement transition changed during exact recovery proof");
        goto reconcile_fail;
    }
    if (config_reprove_published_file_at(
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            &stage_identity, observed->marker_data,
            observed->marker_length, &stage_identity) != 0 ||
        config_retire_exact_name_at(
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            &stage_identity, observed->marker_data,
            observed->marker_length,
            CONFIG_RETIREMENT_SETTLED_PREFIX) != 0 ||
        fsync(directory_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        set_system_error(
            ERR_FILE_IO,
            "Cannot durably remove the exact retirement transition");
        goto reconcile_fail;
    }
    if (config_retirement_guard_pair_read_at(
            directory_fd, after) != 0 ||
        after->stage_present ||
        !config_retirement_guard_pair_records_same(
            observed, after) ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        saved_errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement transition cleanup changed the guarded generation");
        goto reconcile_fail;
    }
    config_retirement_guard_pair_clear(&revalidated);
    return 0;

reconcile_fail:
    config_retirement_guard_pair_clear(&revalidated);
    config_retirement_guard_pair_clear(after);
    errno = saved_errno;
    return -1;
}

/* Both install-or-adopt and strict recovery adoption use the same durability
 * proof. The first pair remains pinned in memory while the directory is synced
 * and the complete fixed namespace is jointly re-read. */
static int config_retirement_guard_revalidate_adoption_at(
    int directory_fd, const char *directory,
    const struct stat *directory_identity,
    config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    const config_retirement_guard_pair_t *observed,
    config_retirement_guard_pair_t *revalidated) {
    if (directory_fd < 0 || !directory || !directory_identity ||
        !owners || owner_count == 0U || !obligation ||
        !observed || !revalidated ||
        observed->marker_absent || observed->stage_present ||
        config_retirement_guard_pair_exact(observed) ||
        !config_retirement_owner_sets_equal(
            &observed->marker_model, kind, owners, owner_count,
            obligation)) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "No exact active retirement marker matches the requested recovery");
        return -1;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME) != 0 ||
        fsync(directory_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot prove the retained retirement guard generation durable");
        return -1;
    }
    if (config_retirement_guard_pair_read_at(
            directory_fd, revalidated) != 0 ||
        revalidated->marker_absent ||
        revalidated->stage_present ||
        config_retirement_guard_pair_exact(revalidated) ||
        !config_retirement_guard_pairs_same(observed, revalidated) ||
        !config_retirement_owner_sets_equal(
            &revalidated->marker_model, kind, owners, owner_count,
            obligation) ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retained retirement guard changed during durability proof");
        return -1;
    }
    return 0;
}

static int config_retirement_guard_stage_write_at(
    int directory_fd, const unsigned char *data, size_t length,
    bool clear_transition, struct stat *stage_identity) {
    struct stat opened;
    struct stat named;
    size_t total = 0U;
    int fd = -1;
    int saved_errno;

    if (directory_fd < 0 || !data || length == 0U ||
        length > CONFIG_RETIREMENT_GUARD_MAX_BYTES || !stage_identity) {
        errno = EINVAL;
        return -1;
    }
    if (clear_transition &&
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE,
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Retirement completion failed before stage creation");
        return -1;
    }
    fd = openat(directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                PERM_USER_RW);
    if (fd < 0 || fchmod(fd, PERM_USER_RW) != 0 ||
        fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, true)) {
        saved_errno = errno ? errno : EIO;
        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot create private retirement transition stage");
        return -1;
    }
    while (total < length) {
        ssize_t count = write(fd, data + total, length - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            saved_errno = errno ? errno : EIO;
            close(fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot write retirement transition stage");
            return -1;
        }
    }
    if (clear_transition &&
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME) != 0) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Retirement completion failed after stage write");
        return -1;
    }
    if (clear_transition &&
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
            fd, CONFIG_RETIREMENT_STAGE_NAME) != 0) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Retirement completion stage sync was interrupted");
        return -1;
    }
    if (fsync(fd) != 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, true) ||
        opened.st_size < 0 || (uintmax_t)opened.st_size != length) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot sync retirement transition stage");
        return -1;
    }
    if (close(fd) != 0) {
        saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot close retirement transition stage");
        return -1;
    }
    /* FreeBSD/UFS may materialize a reader-induced ctime successor only
     * after this writer closes. Bind publication to that post-close
     * generation, but admit it only after independently proving every byte
     * through the pinned parent. */
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_STAGE_AFTER_CLOSE,
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME) != 0 ||
        config_reprove_published_file_at(
            directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            &opened, data, length, &named) != 0) {
        saved_errno = errno ? errno : ESTALE;
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Retirement transition stage changed before publication");
        errno = saved_errno;
        return -1;
    }
    *stage_identity = named;
    return 0;
}

static int config_retirement_guard_stage_publish_at(
    int directory_fd, const char *destination,
    const struct stat *stage_identity,
    const unsigned char *stage_data, size_t stage_length,
    struct stat *published_identity) {
    struct stat named = {0};
    struct stat retained_source;
    int publish_outcome;

    if (directory_fd < 0 || !destination || !stage_identity ||
        (!stage_data && stage_length != 0U) ||
        !published_identity) {
        errno = EINVAL;
        return -1;
    }
    publish_outcome = config_publish_noreplace_at(
        directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
        destination, stage_identity, &retained_source);
    if (publish_outcome == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
        errno = EINPROGRESS;
        set_system_error(
            ERR_FILE_IO,
            "Retirement guard publication outcome is uncertain");
        return -1;
    }
    if (publish_outcome ==
        CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED) {
        errno = EINPROGRESS;
        set_system_error(
            ERR_FILE_IO,
            "Retirement guard was installed with its exact fixed recovery stage retained");
        return -1;
    }
    if (publish_outcome < 0 ||
        fstatat(directory_fd, destination, &named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named, true) ||
        !config_metadata_same_file(stage_identity, &named)) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    *published_identity = named;
    return 0;
}

#if defined(__FreeBSD__)
static bool config_retirement_guard_exact_hardlink_at(
    int directory_fd, const char *name, int fd,
    const unsigned char *expected, size_t expected_length) {
    unsigned char observed[CONFIG_RETIREMENT_GUARD_MAX_BYTES];
    unsigned char extra;
    struct stat opened;
    struct stat named;
    struct stat after;
    struct stat named_after;
    ssize_t extra_count;

    if (directory_fd < 0 || !name || fd < 0 || !expected ||
        expected_length == 0U ||
        expected_length > sizeof(observed) ||
        fstat(fd, &opened) != 0 ||
        fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        (opened.st_mode & 0777) != PERM_USER_RW ||
        opened.st_nlink != 2 ||
        opened.st_size < 0 ||
        (uintmax_t)opened.st_size != expected_length ||
        !config_metadata_snapshot_same(&opened, &named) ||
        !config_pread_full(fd, observed, expected_length, 0) ||
        memcmp(observed, expected, expected_length) != 0) {
        return false;
    }
    do {
        errno = 0;
        extra_count = pread(fd, &extra, 1, (off_t)expected_length);
    } while (extra_count < 0 && errno == EINTR);
    return extra_count == 0 &&
           fstat(fd, &after) == 0 &&
           fstatat(directory_fd, name, &named_after,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
           config_metadata_snapshot_same(&opened, &after) &&
           config_metadata_snapshot_same(&opened, &named_after);
}
#endif

static int config_retirement_guard_move_noreplace_at(
    int directory_fd, const char *source, const char *destination,
    const struct stat *expected_identity,
    const unsigned char *expected_data, size_t expected_length,
    struct stat *published_identity, bool *committed) {
    struct stat source_now;

    if (committed) *committed = false;
    if (directory_fd < 0 || !source || !destination ||
        !expected_identity || !expected_data ||
        expected_length == 0U || !published_identity ||
        config_reprove_published_file_at(
            directory_fd, source, expected_identity, expected_data,
            expected_length, &source_now) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U)
#endif
    if (syscall(
            SYS_renameat2, directory_fd, source, directory_fd,
            destination, RENAME_NOREPLACE) != 0) {
        return -1;
    }
    if (committed) *committed = true;
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    if (renameatx_np(
            directory_fd, source, directory_fd, destination,
            RENAME_EXCL) != 0) {
        return -1;
    }
    if (committed) *committed = true;
#elif defined(__FreeBSD__)
    {
        struct stat opened;
        int source_fd = openat(
            directory_fd, source,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        int saved_errno;

        if (source_fd < 0 || fstat(source_fd, &opened) != 0 ||
            !config_metadata_matches_after_exact_content_proof(
                &source_now, &opened) ||
            linkat(
                directory_fd, source, directory_fd,
                destination, 0) != 0 ||
            !config_retirement_guard_exact_hardlink_at(
                directory_fd, destination, source_fd,
                expected_data, expected_length)) {
            saved_errno = errno ? errno : ESTALE;
            if (source_fd >= 0) {
                (void)funlinkat(
                    directory_fd, destination, source_fd, 0);
                (void)close(source_fd);
            }
            errno = saved_errno;
            return -1;
        }
        if (funlinkat(
                directory_fd, source, source_fd, 0) != 0 ||
            fstat(source_fd, &source_now) != 0) {
            saved_errno = errno ? errno : EIO;
            (void)funlinkat(
                directory_fd, destination, source_fd, 0);
            (void)close(source_fd);
            errno = saved_errno;
            return -1;
        }
        if (committed) *committed = true;
        (void)close(source_fd);
    }
#else
    errno = ENOTSUP;
    return -1;
#endif
    if (strcmp(destination, CONFIG_RETIREMENT_COMPLETE_NAME) == 0 &&
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
            directory_fd, destination) != 0) {
        errno = errno ? errno : EIO;
        return -1;
    }
    if (config_reprove_published_file_at(
            directory_fd, destination, &source_now, expected_data,
            expected_length, published_identity) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    return 0;
}

/* Existing-destination publication is serialized by the authoritative
 * config API lock. POSIX rename is the only cross-platform atomic replacement
 * primitive; Linux/Darwin provide no inode-conditioned CAS form. The syscall
 * is therefore the commit boundary for cooperating writers. Once it succeeds,
 * `committed` remains true even if an independent post-commit proof faults or
 * a same-UID process outside the supported writer protocol supersedes it. */
static int config_replace_exact_name_at(
    int directory_fd, const char *source,
    const struct stat *source_identity,
    const unsigned char *source_data, size_t source_length,
    const char *destination,
    const struct stat *destination_identity,
    const unsigned char *destination_data, size_t destination_length,
    const char *settled_prefix, struct stat *published_identity,
    bool *committed) {
    struct stat source_now;
    struct stat destination_now;
    int checkpoint_result;

    (void)settled_prefix;
    if (committed) *committed = false;
    if (directory_fd < 0 || !source || !source_identity ||
        !source_data || !destination || !destination_identity ||
        !published_identity || !committed ||
        (((source_identity->st_mode & 0777) == PERM_USER_RW)
             ? config_reprove_published_file_at(
                   directory_fd, source, source_identity, source_data,
                   source_length, &source_now)
             : config_reprove_existing_file_at(
                   directory_fd, source, source_identity, source_data,
                   source_length, &source_now)) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    if (destination_data) {
        if (config_reprove_existing_file_at(
                directory_fd, destination, destination_identity,
                destination_data, destination_length,
                &destination_now) != 0) {
            return -1;
        }
    } else if (fstatat(
                   directory_fd, destination, &destination_now,
                   AT_SYMLINK_NOFOLLOW) != 0 ||
               !config_metadata_file_is_safe(&destination_now, false) ||
               !config_metadata_snapshot_same(
                   destination_identity, &destination_now)) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    if (CONFIG_REPLACE_TEST_CHECKPOINT(
            CONFIG_REPLACE_BEFORE_FINAL_PROOF,
            directory_fd, destination) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    if (destination_data) {
        if (config_reprove_existing_file_at(
                directory_fd, destination, &destination_now,
                destination_data, destination_length,
                &destination_now) != 0) {
            return -1;
        }
    } else if (fstatat(
                   directory_fd, destination, &destination_now,
                   AT_SYMLINK_NOFOLLOW) != 0 ||
               !config_metadata_snapshot_same(
                   destination_identity, &destination_now)) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    if (renameat(
            directory_fd, source,
            directory_fd, destination) != 0) {
        return -1;
    }
    *committed = true;
    checkpoint_result = CONFIG_REPLACE_TEST_CHECKPOINT(
        CONFIG_REPLACE_AFTER_EXCHANGE,
        directory_fd, destination);
    if (((source_now.st_mode & 0777) == PERM_USER_RW
             ? config_reprove_published_file_at(
                   directory_fd, destination, &source_now,
                   source_data, source_length, published_identity)
             : config_reprove_existing_file_at(
                   directory_fd, destination, &source_now,
                   source_data, source_length, published_identity)) == 0 ||
        config_reprove_existing_file_at(
            directory_fd, destination, &source_now,
            source_data, source_length, published_identity) == 0) {
        return 0;
    }
    errno = checkpoint_result != 0 && errno == 0 ? EIO : ESTALE;
    return -1;
}


/* Publish a prepared terminal stage without overwriting an unproved pathname
 * generation. The namespace syscall is the terminal commit point: after the
 * business barrier has run, a lost proof or bypass-writer supersession must
 * consume the guard instead of granting retry authority. */
static int config_retirement_guard_publish_prepared_at(
    config_retirement_guard_t *guard,
    struct stat *published_identity, bool *committed) {
    struct stat stage_now;
    struct stat published_now;
    const char *source_name = CONFIG_RETIREMENT_STAGE_NAME;

    if (committed) *committed = false;
    if (!guard || !published_identity || !committed ||
        !guard->prepared || !guard->marker_data) {
        errno = EINVAL;
        return -1;
    }
    if (config_reprove_published_file_at(
            guard->directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
            &guard->prepared_stage_identity, guard->marker_data,
            guard->marker_length, &stage_now) != 0) {
#if !defined(__FreeBSD__)
        if (guard->completion_absent ||
            guard->prepared_slot_name[0] == '\0' ||
            config_reprove_published_file_at(
                guard->directory_fd, guard->prepared_slot_name,
                &guard->prepared_stage_identity, guard->marker_data,
                guard->marker_length, &stage_now) != 0) {
            errno = errno ? errno : ESTALE;
            return -1;
        }
        source_name = guard->prepared_slot_name;
#else
        errno = errno ? errno : ESTALE;
        return -1;
#endif
    }
    if (guard->completion_absent) {
        if (config_retirement_guard_move_noreplace_at(
                guard->directory_fd, source_name,
                CONFIG_RETIREMENT_COMPLETE_NAME, &stage_now,
                guard->marker_data, guard->marker_length,
                &published_now, committed) != 0) {
            return -1;
        }
        *published_identity = published_now;
        return 0;
    }

    if (!guard->completion_data ||
        config_reprove_published_file_at(
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
            &guard->completion_identity, guard->completion_data,
            guard->completion_length, &published_now) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }

#if defined(__FreeBSD__)
    {
        struct stat backup_identity;
        struct stat marker_now;
        int completion_fd = -1;
        int saved_errno = ESTALE;
        bool backup_created = false;
        bool completion_removed = false;
        bool marker_published = false;
        bool marker_committed = false;

        if (guard->prepared_slot_name[0] == '\0') {
            errno = ENOSPC;
            return -1;
        }
        completion_fd = openat(
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (completion_fd < 0 ||
            fstat(completion_fd, &backup_identity) != 0 ||
            !config_metadata_matches_after_exact_content_proof(
                &guard->completion_identity, &backup_identity)) {
            goto freebsd_fail;
        }
        if (linkat(
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME,
                guard->directory_fd,
                guard->prepared_slot_name, 0) != 0) {
            goto freebsd_fail;
        }
        backup_created = true;
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
                guard->directory_fd,
                guard->prepared_slot_name) != 0) {
            goto freebsd_fail;
        }
        if (!config_retirement_guard_exact_hardlink_at(
                guard->directory_fd, guard->prepared_slot_name,
                completion_fd,
                guard->completion_data, guard->completion_length) ||
            funlinkat(
                guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
                completion_fd, 0) != 0) {
            goto freebsd_fail;
        }
        completion_removed = true;
        if (fstat(completion_fd, &backup_identity) != 0 ||
            config_retirement_guard_move_noreplace_at(
                guard->directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
                CONFIG_RETIREMENT_COMPLETE_NAME,
                &stage_now, guard->marker_data, guard->marker_length,
                &published_now, &marker_committed) != 0) {
            saved_errno = errno ? errno : ESTALE;
            if (marker_committed) *committed = true;
            goto freebsd_fail_saved;
        }
        marker_published = true;
        *committed = true;
        if (config_reprove_published_file_at(
                guard->directory_fd,
                CONFIG_RETIREMENT_GUARD_NAME,
                &guard->marker_identity, guard->marker_data,
                guard->marker_length, &marker_now) != 0 ||
            config_reprove_published_file_at(
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME, &stage_now,
                guard->marker_data, guard->marker_length,
                &published_now) != 0 ||
            !config_named_directory_matches(
                guard->directory, &guard->directory_identity) ||
            verify_private_lock_file_at(
                guard->lock_fd, guard->directory_fd,
                CONFIG_RETIREMENT_LOCK_NAME) != 0) {
            saved_errno = errno ? errno : ESTALE;
            goto freebsd_fail_saved;
        }
        if (funlinkat(
                guard->directory_fd, guard->prepared_slot_name,
                completion_fd, 0) != 0) {
            log_warning(
                "Retirement completion committed but prior-certificate slot cleanup failed: %s",
                strerror(errno ? errno : EIO));
        }
        (void)close(completion_fd);
        *published_identity = published_now;
        return 0;

freebsd_fail:
        saved_errno = errno ? errno : ESTALE;
freebsd_fail_saved:
        if ((marker_published || marker_committed) &&
            config_reprove_existing_file_at(
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME, &stage_now,
                guard->marker_data, guard->marker_length,
                &published_now) == 0) {
            if (funlinkat(
                    guard->directory_fd, guard->prepared_slot_name,
                    completion_fd, 0) != 0) {
                log_warning(
                    "Retirement completion committed but prior-certificate slot cleanup failed: %s",
                    strerror(errno ? errno : EIO));
            }
            (void)close(completion_fd);
            *published_identity = published_now;
            return 0;
        }
        if (completion_removed &&
            fstat(completion_fd, &backup_identity) == 0) {
            (void)config_retirement_guard_move_noreplace_at(
                guard->directory_fd, guard->prepared_slot_name,
                CONFIG_RETIREMENT_COMPLETE_NAME, &backup_identity,
                guard->completion_data, guard->completion_length,
                &backup_identity, NULL);
        } else if (backup_created && completion_fd >= 0) {
            (void)funlinkat(
                guard->directory_fd, guard->prepared_slot_name,
                completion_fd, 0);
        }
        if (completion_fd >= 0) (void)close(completion_fd);
        errno = saved_errno;
        return -1;
    }
#else
    {
        config_exchange_result_t exchanged;
        struct stat displaced_now;
        struct stat slot_now;
        bool published_exact;
        bool displaced_exact;

        if (guard->prepared_slot_name[0] == '\0') {
            errno = ENOSPC;
            return -1;
        }
        if (strcmp(source_name, guard->prepared_slot_name) != 0 &&
            config_retirement_guard_move_noreplace_at(
                guard->directory_fd, source_name,
                guard->prepared_slot_name, &stage_now,
                guard->marker_data, guard->marker_length,
                &slot_now, NULL) != 0) {
            return -1;
        }
        if (strcmp(source_name, guard->prepared_slot_name) == 0) {
            slot_now = stage_now;
        }
        guard->prepared_stage_identity = slot_now;
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_AFTER_SETTLED_SLOT_MOVE,
                guard->directory_fd,
                guard->prepared_slot_name) != 0 ||
            config_reprove_published_file_at(
                guard->directory_fd, guard->prepared_slot_name,
                &slot_now, guard->marker_data, guard->marker_length,
                &slot_now) != 0 ||
            config_reprove_published_file_at(
                guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
                &guard->completion_identity, guard->completion_data,
                guard->completion_length, &published_now) != 0) {
            errno = errno ? errno : ESTALE;
            return -1;
        }
        exchanged = config_exchange_names_at(
            guard->directory_fd, guard->prepared_slot_name,
            CONFIG_RETIREMENT_COMPLETE_NAME);
        if (exchanged != CONFIG_EXCHANGE_OK) {
            errno = exchanged == CONFIG_EXCHANGE_UNSUPPORTED
                        ? ENOTSUP
                        : (errno ? errno : EIO);
            return -1;
        }
        *committed = true;
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_AFTER_NAMESPACE_COMMIT,
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
            errno = errno ? errno : EIO;
            return -1;
        }
        published_exact =
            config_reprove_published_file_at(
                guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME,
                &stage_now, guard->marker_data, guard->marker_length,
                &published_now) == 0;
        if (!published_exact) {
            published_exact =
                config_reprove_existing_file_at(
                    guard->directory_fd,
                    CONFIG_RETIREMENT_COMPLETE_NAME,
                    &stage_now, guard->marker_data,
                    guard->marker_length, &published_now) == 0;
        }
        displaced_exact =
            config_reprove_published_file_at(
                guard->directory_fd, guard->prepared_slot_name,
                &guard->completion_identity, guard->completion_data,
                guard->completion_length, &displaced_now) == 0;
        if (!published_exact) {
            /* Never exchange on rollback after losing exact authority over
             * the canonical side. A cooperating writer cannot enter here;
             * preserving a detectable bypass-writer substitution is safer
             * than moving it through an unconditional SWAP. */
            errno = ESTALE;
            return -1;
        }
        if (!displaced_exact) {
            log_warning(
                "Retirement completion committed while its prior-certificate slot changed");
        }
        *published_identity = published_now;
        return 0;
    }
#endif
}

static void config_retirement_guard_free(
    config_retirement_guard_t *guard) {
    bool owned_here;

    if (!guard) return;
    owned_here = guard->owner_pid == getpid() &&
                 g_retirement_guard_owner_pid == getpid();
    if (owned_here) {
        g_retirement_guard_owner_pid = 0;
    } else if (g_retirement_guard_owner_pid != getpid()) {
        /* Discard the fork child's inherited process-local ownership token;
         * only the parent's copy remains authoritative. */
        g_retirement_guard_owner_pid = 0;
    }
    /* The opaque token is not the descriptor that carries flock: the private
     * lock registry retains that inode descriptor. In a fork child, discard
     * the entire inherited registry epoch without LOCK_UN, then never close
     * the stale numeric token separately (the reset may already have closed
     * it, and its number can subsequently be reused). */
    if (guard->lock_fd >= 0) {
        if (owned_here) {
            unlock_private_file(guard->lock_fd);
        } else {
            runtime_state_lock_abandon_inherited();
        }
    }
    /* A foreign process cannot prove that this number still denotes the
     * inherited open file description, even when fstat reports the same
     * directory inode after close/reopen ABA. Forget it without closing. */
    if (owned_here && guard->directory_fd >= 0) {
        close(guard->directory_fd);
    }
    if (guard->marker_data) {
        secure_zero_memory(guard->marker_data, guard->marker_length);
        free(guard->marker_data);
    }
    if (guard->completion_data) {
        secure_zero_memory(
            guard->completion_data, guard->completion_length);
        free(guard->completion_data);
    }
    secure_zero_memory(guard, sizeof(*guard));
    free(guard);
}

static bool config_retirement_guard_handle_is_structurally_valid(
    const config_retirement_guard_t *guard) {
    return guard && guard->directory_fd >= 0 && guard->lock_fd >= 0 &&
           guard->directory_fd != guard->lock_fd &&
           guard->owner_pid == getpid() &&
           g_retirement_guard_owner_pid == getpid() &&
           memchr(guard->directory, '\0', sizeof(guard->directory)) &&
           guard->directory[0] == '/' &&
           config_metadata_dir_is_safe(&guard->directory_identity) &&
           guard->marker_data && guard->marker_length > 0U &&
           guard->marker_length <= CONFIG_RETIREMENT_GUARD_MAX_BYTES &&
           config_metadata_file_is_safe(&guard->marker_identity, true) &&
           account_incarnation_is_valid(guard->token) &&
           ((guard->completion_absent && !guard->completion_data &&
             guard->completion_length == 0U) ||
            (!guard->completion_absent && guard->completion_data &&
             guard->completion_length > 0U &&
             guard->completion_length <=
                 CONFIG_RETIREMENT_GUARD_MAX_BYTES &&
             config_metadata_file_is_safe(
                 &guard->completion_identity, true))) &&
           (!guard->prepared ||
            config_metadata_file_is_safe(
                &guard->prepared_stage_identity, true));
}

static int config_retirement_guard_require_live_handle(
    const config_retirement_guard_t *guard, const char *operation) {
    if (!config_retirement_guard_handle_is_structurally_valid(guard) ||
        guard->barrier_active) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid or re-entrant retirement guard %s handle",
                  operation);
        return -1;
    }
    if (verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_RETIREMENT_LOCK_NAME) != 0) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement lifecycle lock changed before %s",
            operation);
        return -1;
    }
    return 0;
}

static int config_retirement_guard_make_handle(
    int directory_fd, int lock_fd, const char *directory,
    const struct stat *directory_identity, const struct stat *marker_identity,
    unsigned char *marker_data, size_t marker_length,
    bool completion_absent, const struct stat *completion_identity,
    unsigned char *completion_data, size_t completion_length,
    const char token[ACCOUNT_INCARNATION_LEN], bool created,
    config_retirement_guard_t **out) {
    config_retirement_guard_t *guard;

    if ((!completion_absent &&
         (!completion_identity || !completion_data ||
          completion_length == 0U)) ||
        (completion_absent &&
         (completion_data || completion_length != 0U))) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard completion generation");
        return -1;
    }
    guard = calloc(1, sizeof(*guard));
    if (!guard) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate retirement guard handle");
        return -1;
    }
    guard->directory_fd = directory_fd;
    guard->lock_fd = lock_fd;
    guard->owner_pid = getpid();
    guard->directory_identity = *directory_identity;
    guard->marker_identity = *marker_identity;
    guard->marker_data = marker_data;
    guard->marker_length = marker_length;
    guard->completion_absent = completion_absent;
    if (!completion_absent) {
        guard->completion_identity = *completion_identity;
        guard->completion_data = completion_data;
        guard->completion_length = completion_length;
    }
    memcpy(guard->token, token, sizeof(guard->token));
    guard->created = created;
    if (safe_strncpy(guard->directory, directory,
                     sizeof(guard->directory)) != 0) {
        /* Ownership of fd/data transfers only after the handle is complete. */
        guard->directory_fd = -1;
        guard->lock_fd = -1;
        guard->marker_data = NULL;
        guard->completion_data = NULL;
        free(guard);
        return -1;
    }
    g_retirement_guard_owner_pid = getpid();
    *out = guard;
    return 0;
}

int config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    config_retirement_guard_t **guard) {
    static const char hexadecimal[] = "0123456789ABCDEF";
    config_retirement_owner_t canonical[MAX_ACCOUNTS];
    config_retirement_guard_pair_t pair;
    config_retirement_guard_pair_t revalidated_pair;
    char directory[MAX_PATH_LEN];
    char settled_slot[64] = "";
    char token[ACCOUNT_INCARNATION_LEN];
    struct stat directory_identity;
    struct stat published_identity;
    struct stat prior_settled_identity;
    struct stat stage_identity;
    unsigned char *marker_data = NULL;
    size_t marker_length = 0U;
    int directory_fd = -1;
    int lock_fd = -1;
    int result = -1;
    int saved_errno = EIO;
    bool legacy_residue = false;
    bool prior_marker_moved = false;

    if (!guard || *guard || !config_path ||
        !config_retirement_kind_name(kind) ||
        !config_retirement_obligation_valid(
            kind, obligation, owner_count, false)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard installation arguments");
        return -1;
    }
    if (g_retirement_guard_owner_pid != 0) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "This process already owns a retirement lifecycle transaction");
        return -1;
    }
    memset(canonical, 0, sizeof(canonical));
    memset(&pair, 0, sizeof(pair));
    memset(&revalidated_pair, 0, sizeof(revalidated_pair));
    memset(token, 0, sizeof(token));
    if (config_retirement_canonicalize_owners(
            owners, owner_count, canonical) != 0) {
        goto install_done;
    }
    result = config_retirement_open_directory(
        config_path, false, directory, &directory_identity, &directory_fd);
    if (result != 0) goto install_done;
    /* From here onward only the two handle-publication paths may report
     * success. Keep every validation, lock, sync, and reproof failure at -1
     * instead of leaking the directory-open success code with a NULL handle. */
    result = -1;

    lock_fd = try_lock_private_file_at(
        directory_fd, CONFIG_RETIREMENT_LOCK_NAME);
    if (lock_fd < 0) {
        saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot acquire the retirement lifecycle lock");
        goto install_done;
    }
    if (config_retirement_guard_legacy_residue_present_at(
            directory_fd, &legacy_residue) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot inspect legacy retirement guard residue");
        goto install_done;
    }
    if (legacy_residue) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "A retained retirement guard clear witness blocks configuration mutation");
        goto install_done;
    }
    if (config_retirement_guard_pair_read_at(
            directory_fd, &pair) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    if (pair.stage_present) {
        if (config_retirement_guard_reconcile_exact_stage_at(
                directory_fd, directory, &directory_identity,
                &pair, &revalidated_pair) != 0) {
            goto install_done;
        }
        config_retirement_guard_pair_clear(&pair);
        pair = revalidated_pair;
        memset(&revalidated_pair, 0, sizeof(revalidated_pair));
    }

    if (!pair.marker_absent &&
        !config_retirement_guard_pair_exact(&pair)) {
        if (!config_retirement_owner_sets_equal(
                &pair.marker_model, kind, canonical, owner_count,
                obligation)) {
            errno = EBUSY;
            set_error(
                ERR_CONFIG_INVALID,
                "A different retirement-incomplete operation already blocks configuration mutation");
            goto install_done;
        }
        if (config_retirement_guard_revalidate_adoption_at(
                directory_fd, directory, &directory_identity,
                kind, canonical, owner_count, obligation, &pair,
                &revalidated_pair) != 0) {
            goto install_done;
        }
        memcpy(token, revalidated_pair.marker_model.token, sizeof(token));
        if (config_retirement_guard_make_handle(
                directory_fd, lock_fd, directory, &directory_identity,
                &revalidated_pair.marker_identity,
                revalidated_pair.marker_data,
                revalidated_pair.marker_length,
                revalidated_pair.completion_absent,
                &revalidated_pair.completion_identity,
                revalidated_pair.completion_data,
                revalidated_pair.completion_length,
                token, false, guard) != 0) {
            goto install_done;
        }
        revalidated_pair.marker_data = NULL;
        revalidated_pair.marker_length = 0U;
        revalidated_pair.completion_data = NULL;
        revalidated_pair.completion_length = 0U;
        directory_fd = -1;
        lock_fd = -1;
        result = 0;
        goto install_done;
    }
    if (pair.marker_absent && !pair.completion_absent) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "A lone retirement completion certificate blocks configuration mutation");
        goto install_done;
    }
    if (config_retirement_guard_pair_exact(&pair) &&
        config_retirement_guard_select_settled_slot_at(
            directory_fd, settled_slot,
            sizeof(settled_slot)) != 0) {
        goto install_done;
    }

    for (unsigned int attempt = 0U; attempt < 16U; attempt++) {
        if (generate_random_string(
                token, sizeof(token), hexadecimal) != 0 ||
            !account_incarnation_is_valid(token) ||
            config_retirement_guard_serialize(
                kind, canonical, owner_count, obligation, token,
                &marker_data,
                &marker_length) != 0) {
            goto install_done;
        }
        if (pair.completion_absent ||
            marker_length != pair.completion_length ||
            memcmp(marker_data, pair.completion_data,
                   marker_length) != 0) {
            break;
        }
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
        marker_data = NULL;
        marker_length = 0U;
        secure_zero_memory(token, sizeof(token));
    }
    if (!marker_data) {
        errno = EEXIST;
        set_error(
            ERR_FILE_IO,
            "Cannot generate a fresh retirement guard generation");
        goto install_done;
    }
    if (config_retirement_guard_stage_write_at(
            directory_fd, marker_data, marker_length, false,
            &stage_identity) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    if (config_retirement_guard_pair_exact(&pair)) {
        if (config_retirement_guard_move_noreplace_at(
                directory_fd, CONFIG_RETIREMENT_GUARD_NAME,
                settled_slot, &pair.marker_identity,
                pair.marker_data, pair.marker_length,
                &prior_settled_identity, NULL) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Cannot preserve the prior retirement guard generation");
            goto install_done;
        }
        prior_marker_moved = true;
    }
    if (config_retirement_guard_stage_publish_at(
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME,
            &stage_identity, marker_data, marker_length,
            &published_identity) != 0) {
        if (prior_marker_moved) {
            struct stat settled_identity;

            if (config_reprove_published_file_at(
                    directory_fd, settled_slot,
                    &pair.marker_identity, pair.marker_data,
                    pair.marker_length, &settled_identity) == 0) {
                (void)config_retirement_guard_move_noreplace_at(
                    directory_fd, settled_slot,
                    CONFIG_RETIREMENT_GUARD_NAME,
                    &settled_identity, pair.marker_data,
                    pair.marker_length, &settled_identity, NULL);
            }
        }
        set_system_error(
            ERR_FILE_IO,
            "Cannot publish the fresh retirement guard generation");
        goto install_done;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC,
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME) != 0 ||
        fsync(directory_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot durably publish the fresh retirement guard generation");
        goto install_done;
    }
    if (config_reprove_published_file_at(
            directory_fd, CONFIG_RETIREMENT_GUARD_NAME,
            &published_identity, marker_data, marker_length,
            &published_identity) != 0) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Fresh retirement guard changed during commit");
        goto install_done;
    }

    config_retirement_guard_pair_clear(&pair);
    if (config_retirement_guard_pair_read_at(
            directory_fd, &pair) != 0 ||
        pair.marker_absent || pair.stage_present ||
        !config_metadata_same_file(
            &published_identity, &pair.marker_identity) ||
        pair.marker_length != marker_length ||
        memcmp(pair.marker_data, marker_data, marker_length) != 0 ||
        config_retirement_guard_pair_exact(&pair) ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Fresh retirement guard is not a stable blocking generation");
        goto install_done;
    }
#if defined(__FreeBSD__)
    if (prior_marker_moved &&
        config_retire_exact_name_at(
            directory_fd, settled_slot, &prior_settled_identity,
            pair.completion_data, pair.completion_length,
            CONFIG_RETIREMENT_SETTLED_PREFIX) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot retire the prior FreeBSD guard generation");
        goto install_done;
    }
#endif
    if (config_retirement_guard_make_handle(
            directory_fd, lock_fd, directory, &directory_identity,
            &pair.marker_identity, marker_data, marker_length,
            pair.completion_absent, &pair.completion_identity,
            pair.completion_data, pair.completion_length,
            token, true, guard) != 0) {
        goto install_done;
    }
    marker_data = NULL;
    marker_length = 0U;
    pair.completion_data = NULL;
    pair.completion_length = 0U;
    directory_fd = -1;
    lock_fd = -1;
    result = 0;

install_done:
    if (result != 0) saved_errno = errno ? errno : EIO;
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&revalidated_pair);
    if (marker_data) {
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
    }
    secure_zero_memory(canonical, sizeof(canonical));
    secure_zero_memory(token, sizeof(token));
    if (result != 0) errno = saved_errno;
    return result;
}

int config_retirement_guard_install_or_adopt(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    config_retirement_guard_t **guard) {
    config_retirement_ssh_alias_obligation_t obligation;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    return config_retirement_guard_install_or_adopt_with_ssh_alias_obligation(
        config_path, kind, owners, owner_count, &obligation, guard);
}

int config_retirement_guard_recovery_probe(
    const char *config_path,
    config_retirement_recovery_t *recovery) {
    config_retirement_guard_pair_t pair;
    config_retirement_guard_pair_t stage_pair;
    char directory[MAX_PATH_LEN];
    struct stat directory_identity;
    struct stat stage_identity;
    int directory_fd = -1;
    int result;
    bool legacy_residue = false;

    if (!config_path || !recovery) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement recovery probe arguments");
        return -1;
    }
    memset(recovery, 0, sizeof(*recovery));
    memset(&pair, 0, sizeof(pair));
    memset(&stage_pair, 0, sizeof(stage_pair));
    memset(&stage_identity, 0, sizeof(stage_identity));
    result = config_retirement_open_directory(
        config_path, true, directory, &directory_identity, &directory_fd);
    if (result == 1) return 0;
    if (result != 0) return -1;

    if (config_retirement_guard_pair_read_at(
            directory_fd, &pair) != 0 ||
        config_retirement_guard_legacy_residue_present_at(
            directory_fd, &legacy_residue) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        result = -1;
        goto recovery_probe_done;
    }
    if (legacy_residue) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "Retirement recovery is blocked by legacy transition residue");
        result = -1;
        goto recovery_probe_done;
    }
    if (pair.stage_present) {
        if (config_retirement_guard_exact_stage_at(
                directory_fd, &pair, &stage_identity) != 0 ||
            config_retirement_guard_pair_read_at(
                directory_fd, &stage_pair) != 0 ||
            !config_retirement_guard_pairs_same(
                &pair, &stage_pair) ||
            config_retirement_guard_name_stable_at(
                directory_fd, CONFIG_RETIREMENT_STAGE_NAME,
                false, &stage_identity, pair.marker_data,
                pair.marker_length) != 0 ||
            !config_named_directory_matches(
                directory, &directory_identity)) {
            if (errno == 0) errno = ESTALE;
            if (get_last_error()->message[0] == '\0') {
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot project an exact retirement transition");
            }
            result = -1;
            goto recovery_probe_done;
        }
        config_retirement_guard_pair_clear(&pair);
        pair = stage_pair;
        memset(&stage_pair, 0, sizeof(stage_pair));
    }
    if (pair.marker_absent) {
        if (!pair.completion_absent) {
            errno = EBUSY;
            set_error(
                ERR_CONFIG_INVALID,
                "A lone retirement completion certificate has no recoverable owner");
            result = -1;
            goto recovery_probe_done;
        }
        result = 0;
        goto recovery_probe_done;
    }
    if (config_retirement_guard_pair_exact(&pair)) {
        result = 0;
        goto recovery_probe_done;
    }

    recovery->marker_version = pair.marker_model.version;
    recovery->kind = pair.marker_model.kind;
    recovery->owner_count = pair.marker_model.owner_count;
    memcpy(recovery->owners, pair.marker_model.owners,
           recovery->owner_count * sizeof(recovery->owners[0]));
    recovery->ssh_alias_obligation =
        pair.marker_model.ssh_alias_obligation;
    recovery->valid = true;
    result = 0;

recovery_probe_done:
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&stage_pair);
    close(directory_fd);
    if (result != 0) {
        secure_zero_memory(recovery, sizeof(*recovery));
    }
    return result;
}

int config_retirement_guard_adopt_with_ssh_alias_obligation(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_ssh_alias_obligation_t *obligation,
    config_retirement_guard_t **guard) {
    config_retirement_owner_t canonical[MAX_ACCOUNTS];
    config_retirement_guard_pair_t pair;
    config_retirement_guard_pair_t reconciled_pair;
    config_retirement_guard_pair_t revalidated_pair;
    config_retirement_guard_pair_t *adopted_pair = NULL;
    char directory[MAX_PATH_LEN];
    char token[ACCOUNT_INCARNATION_LEN];
    struct stat directory_identity;
    int directory_fd = -1;
    int lock_fd = -1;
    int result = -1;
    int saved_errno = EIO;
    bool exact_stage_reconciled = false;
    bool legacy_residue = false;

    if (!guard || *guard || !config_path ||
        !config_retirement_kind_name(kind) ||
        !config_retirement_obligation_valid(
            kind, obligation, owner_count, false)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard adoption arguments");
        return -1;
    }
    if (g_retirement_guard_owner_pid != 0) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "This process already owns a retirement lifecycle transaction");
        return -1;
    }
    memset(canonical, 0, sizeof(canonical));
    memset(&pair, 0, sizeof(pair));
    memset(&reconciled_pair, 0, sizeof(reconciled_pair));
    memset(&revalidated_pair, 0, sizeof(revalidated_pair));
    memset(token, 0, sizeof(token));
    if (config_retirement_canonicalize_owners(
            owners, owner_count, canonical) != 0) {
        goto adopt_done;
    }
    if (config_retirement_open_directory(
            config_path, false, directory, &directory_identity,
            &directory_fd) != 0) {
        goto adopt_done;
    }

    /* A marker installed by this implementation always has the fixed lock
     * inode beside it. Recovery opens that inode only; absence must not create
     * even a lock file while proving there is nothing to adopt. */
    lock_fd = try_lock_existing_private_file_at(
        directory_fd, CONFIG_RETIREMENT_LOCK_NAME);
    if (lock_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot acquire the existing retirement lifecycle lock");
        goto adopt_done;
    }
    if (config_retirement_guard_legacy_residue_present_at(
            directory_fd, &legacy_residue) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot inspect legacy retirement guard residue");
        goto adopt_done;
    }
    if (legacy_residue) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "Legacy retirement guard residue cannot be adopted");
        goto adopt_done;
    }
    if (config_retirement_guard_pair_read_at(
            directory_fd, &pair) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        goto adopt_done;
    }
    if (pair.marker_absent) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "No active retirement marker is available for adoption");
        goto adopt_done;
    }
    if (!config_retirement_owner_sets_equal(
            &pair.marker_model, kind, canonical, owner_count,
            obligation)) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "The active retirement marker does not match the requested recovery");
        goto adopt_done;
    }
    if (pair.stage_present) {
        if (config_retirement_guard_reconcile_exact_stage_at(
                directory_fd, directory, &directory_identity,
                &pair, &reconciled_pair) != 0) {
            goto adopt_done;
        }
        config_retirement_guard_pair_clear(&pair);
        pair = reconciled_pair;
        memset(&reconciled_pair, 0, sizeof(reconciled_pair));
        exact_stage_reconciled = true;
    }
    if (config_retirement_guard_pair_exact(&pair)) {
        if (!exact_stage_reconciled) {
            errno = EBUSY;
            set_error(
                ERR_CONFIG_INVALID,
                "No active retirement marker is available for adoption");
            goto adopt_done;
        }
        adopted_pair = &pair;
    } else {
        if (config_retirement_guard_revalidate_adoption_at(
                directory_fd, directory, &directory_identity,
                kind, canonical, owner_count, obligation, &pair,
                &revalidated_pair) != 0) {
            goto adopt_done;
        }
        adopted_pair = &revalidated_pair;
    }

    memcpy(token, adopted_pair->marker_model.token, sizeof(token));
    if (config_retirement_guard_make_handle(
            directory_fd, lock_fd, directory, &directory_identity,
            &adopted_pair->marker_identity,
            adopted_pair->marker_data,
            adopted_pair->marker_length,
            adopted_pair->completion_absent,
            &adopted_pair->completion_identity,
            adopted_pair->completion_data,
            adopted_pair->completion_length,
            token, false, guard) != 0) {
        goto adopt_done;
    }
    adopted_pair->marker_data = NULL;
    adopted_pair->marker_length = 0U;
    adopted_pair->completion_data = NULL;
    adopted_pair->completion_length = 0U;
    directory_fd = -1;
    lock_fd = -1;
    result = 0;

adopt_done:
    if (result != 0) saved_errno = errno ? errno : EIO;
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&reconciled_pair);
    config_retirement_guard_pair_clear(&revalidated_pair);
    secure_zero_memory(canonical, sizeof(canonical));
    secure_zero_memory(token, sizeof(token));
    if (result != 0) errno = saved_errno;
    return result;
}

int config_retirement_guard_adopt(
    const char *config_path, config_retirement_kind_t kind,
    const config_retirement_owner_t *owners, size_t owner_count,
    config_retirement_guard_t **guard) {
    config_retirement_ssh_alias_obligation_t obligation;

    memset(&obligation, 0, sizeof(obligation));
    obligation.known = true;
    return config_retirement_guard_adopt_with_ssh_alias_obligation(
        config_path, kind, owners, owner_count, &obligation, guard);
}

int config_retirement_guard_probe(
    const char *config_path, bool *blocked) {
    config_retirement_guard_pair_t pair;
    char directory[MAX_PATH_LEN];
    struct stat directory_identity;
    int directory_fd = -1;
    int result;
    bool legacy_residue = false;

    if (!config_path || !blocked) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard probe arguments");
        return -1;
    }
    *blocked = true;
    memset(&pair, 0, sizeof(pair));
    result = config_retirement_open_directory(
        config_path, true, directory, &directory_identity, &directory_fd);
    if (result == 1) {
        *blocked = false;
        return 0;
    }
    if (result != 0) return -1;

    if (config_retirement_guard_pair_read_at(
            directory_fd, &pair) != 0 ||
        config_retirement_guard_legacy_residue_present_at(
            directory_fd, &legacy_residue) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        result = -1;
        goto probe_done;
    }
    if (!pair.stage_present && !legacy_residue &&
        ((pair.marker_absent && pair.completion_absent) ||
         config_retirement_guard_pair_exact(&pair))) {
        *blocked = false;
    }
    result = 0;

probe_done:
    config_retirement_guard_pair_clear(&pair);
    close(directory_fd);
    return result;
}
bool config_retirement_guard_was_created(
    const config_retirement_guard_t *guard) {
    return guard && guard->created;
}

/* Bind completion to the exact canonical blocker generation held by this
 * handle.  Both inode identity and complete serialized bytes must still match;
 * a replaced, rewritten, or mixed-generation marker cannot be certified. */
static bool config_retirement_guard_pair_matches_handle(
    const config_retirement_guard_t *guard,
    const config_retirement_guard_pair_t *pair) {
    return guard && pair && !pair->marker_absent &&
           config_metadata_same_file(
               &guard->marker_identity, &pair->marker_identity) &&
           guard->marker_length == pair->marker_length &&
           memcmp(guard->marker_data, pair->marker_data,
                  guard->marker_length) == 0 &&
           strcmp(guard->token, pair->marker_model.token) == 0;
}

/* A handle authorizes replacement only of the completion namespace generation
 * it originally observed. Exact bytes permit a ctime-only UFS successor, but
 * insertion, removal, inode replacement, or content change fails closed. */
static bool config_retirement_guard_completion_matches_handle(
    const config_retirement_guard_t *guard,
    const config_retirement_guard_pair_t *pair) {
    return guard && pair &&
           config_retirement_guard_record_same(
               guard->completion_absent, &guard->completion_identity,
               guard->completion_data, guard->completion_length,
               pair->completion_absent, &pair->completion_identity,
               pair->completion_data, pair->completion_length);
}

static int config_retirement_guard_prepared_source_exact_at(
    const config_retirement_guard_t *guard,
    const config_retirement_guard_pair_t *pair,
    struct stat *identity) {
    if (!guard || !pair || !identity) {
        errno = EINVAL;
        return -1;
    }
    if (pair->stage_present) {
        if (config_retirement_guard_exact_stage_at(
                guard->directory_fd, pair, identity) != 0) {
            return -1;
        }
    } else {
#if !defined(__FreeBSD__)
        if (guard->prepared_slot_name[0] == '\0' ||
            config_reprove_published_file_at(
                guard->directory_fd, guard->prepared_slot_name,
                &guard->prepared_stage_identity, guard->marker_data,
                guard->marker_length, identity) != 0) {
            errno = errno ? errno : ESTALE;
            return -1;
        }
#else
        errno = ESTALE;
        return -1;
#endif
    }
    return config_metadata_matches_after_exact_content_proof(
               &guard->prepared_stage_identity, identity)
               ? 0
               : (errno = ESTALE, -1);
}

int config_retirement_guard_revalidate(
    const config_retirement_guard_t *guard) {
    config_retirement_guard_pair_t pair;
    struct stat stage_identity;
    int result = -1;
    int saved_errno = EIO;

    if (config_retirement_guard_require_live_handle(
            guard, "revalidation") != 0) {
        return -1;
    }
    memset(&pair, 0, sizeof(pair));
    memset(&stage_identity, 0, sizeof(stage_identity));
    errno = 0;
    if (config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) != 0) {
        saved_errno = errno ? errno : EIO;
        goto revalidate_done;
    }
    if ((guard->prepared &&
         (!config_retirement_guard_pair_matches_handle(guard, &pair) ||
          !config_retirement_guard_completion_matches_handle(
              guard, &pair) ||
          config_retirement_guard_prepared_source_exact_at(
              guard, &pair, &stage_identity) != 0)) ||
        (!guard->prepared &&
         (pair.stage_present ||
          !config_retirement_guard_completion_matches_handle(
              guard, &pair) ||
          !config_retirement_guard_pair_matches_handle(guard, &pair))) ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_RETIREMENT_LOCK_NAME) != 0) {
        saved_errno = ESTALE;
        errno = saved_errno;
        set_error(
            ERR_CONFIG_INVALID,
            "Retirement guard is no longer the exact active generation");
        goto revalidate_done;
    }
    result = 0;

revalidate_done:
    if (result != 0 && saved_errno == EIO && errno != 0) {
        saved_errno = errno;
    }
    config_retirement_guard_pair_clear(&pair);
    if (result != 0) errno = saved_errno;
    return result;
}

int config_retirement_guard_prepare_clear(
    config_retirement_guard_t *guard) {
    config_retirement_guard_pair_t pair;
    config_retirement_guard_pair_t reconciled_pair;
    struct stat stage_identity;
    int saved_errno = EIO;

    if (config_retirement_guard_require_live_handle(
            guard, "clear preparation") != 0) {
        return -1;
    }
    if (guard->prepared) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard clear preparation handle");
        return -1;
    }
    memset(&pair, 0, sizeof(pair));
    memset(&reconciled_pair, 0, sizeof(reconciled_pair));
    memset(&stage_identity, 0, sizeof(stage_identity));

    if (!config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) != 0 ||
        !config_retirement_guard_pair_matches_handle(guard, &pair) ||
        !config_retirement_guard_completion_matches_handle(
            guard, &pair) ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        saved_errno = errno ? errno : ESTALE;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Retirement guard generation changed before clear preparation");
        }
        goto prepare_fail;
    }
    if (!guard->completion_absent &&
        config_retirement_guard_prepare_settled_slot_at(
            guard, &pair) != 0) {
        saved_errno = errno ? errno : ENOSPC;
        goto prepare_fail;
    }
    if (pair.stage_present) {
        if (config_retirement_guard_reconcile_exact_stage_at(
                guard->directory_fd, guard->directory,
                &guard->directory_identity, &pair,
                &reconciled_pair) != 0) {
            saved_errno = errno ? errno : ESTALE;
            goto prepare_fail;
        }
        config_retirement_guard_pair_clear(&pair);
        pair = reconciled_pair;
        memset(&reconciled_pair, 0, sizeof(reconciled_pair));
        if (pair.stage_present ||
            !config_retirement_guard_pair_matches_handle(
                guard, &pair) ||
            !config_retirement_guard_completion_matches_handle(
                guard, &pair)) {
            saved_errno = ESTALE;
            errno = saved_errno;
            set_error(
                ERR_CONFIG_INVALID,
                "Retirement transition cleanup changed the owned generation");
            goto prepare_fail;
        }
    }
    config_retirement_guard_pair_clear(&pair);

    if (config_retirement_guard_stage_write_at(
            guard->directory_fd, guard->marker_data,
            guard->marker_length, true, &stage_identity) != 0 ||
        RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
            guard->directory_fd, CONFIG_RETIREMENT_STAGE_NAME) != 0 ||
        fsync(guard->directory_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Cannot durably prepare retirement completion stage");
        }
        goto prepare_fail;
    }
    if (config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) != 0 ||
        !pair.stage_present ||
        !config_retirement_guard_pair_matches_handle(guard, &pair) ||
        !config_retirement_guard_completion_matches_handle(
            guard, &pair) ||
        config_retirement_guard_exact_stage_at(
            guard->directory_fd, &pair, &stage_identity) != 0 ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_RETIREMENT_LOCK_NAME) != 0) {
        saved_errno = errno ? errno : ESTALE;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Prepared retirement completion stage changed during durability proof");
        }
        goto prepare_fail;
    }

    guard->prepared_stage_identity = stage_identity;
    if (!guard->completion_absent) {
        guard->completion_identity = pair.completion_identity;
    }
    guard->prepared = true;
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&reconciled_pair);
    clear_error();
    errno = 0;
    return 0;

prepare_fail:
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&reconciled_pair);
    errno = saved_errno;
    return -1;
}

/* Once the prepared stage rename succeeds, no filesystem observation may
 * intervene before the in-memory capability is destroyed. Descriptor cleanup
 * follows only after the handle and its marker copy no longer exist. */
static void config_retirement_guard_finish_prepared_commit(
    config_retirement_guard_t **guard_ptr) {
    config_retirement_guard_t *guard = *guard_ptr;
    unsigned char *marker_data = guard->marker_data;
    size_t marker_length = guard->marker_length;
    unsigned char *completion_data = guard->completion_data;
    size_t completion_length = guard->completion_length;
    int directory_fd = guard->directory_fd;
    int lock_fd = guard->lock_fd;

    if (g_retirement_guard_owner_pid == getpid()) {
        g_retirement_guard_owner_pid = 0;
    }
    *guard_ptr = NULL;
    secure_zero_memory(marker_data, marker_length);
    free(marker_data);
    if (completion_data) {
        secure_zero_memory(completion_data, completion_length);
        free(completion_data);
    }
    secure_zero_memory(guard, sizeof(*guard));
    free(guard);

    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
}

int config_retirement_guard_clear_with_barrier(
    config_retirement_guard_t **guard_ptr,
    config_retirement_guard_precommit_fn barrier, void *context) {
    config_retirement_guard_t *guard;
    config_retirement_guard_pair_t pair;
    config_retirement_guard_pair_t reconciled_pair;
    struct stat published_identity;
    struct stat stage_identity;
    struct stat revalidated_stage_identity;
    error_context_t primary_error;
    int primary_errno = 0;
    bool have_primary = false;
    bool publication_attempted = false;
    bool publication_committed = false;

    if (!guard_ptr || !*guard_ptr) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement guard clear handle");
        return -1;
    }
    guard = *guard_ptr;
    if (config_retirement_guard_require_live_handle(
            guard, "clear") != 0) {
        return -1;
    }
    if (barrier && !guard->prepared) {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Retirement guard commit barrier requires a prepared handle");
        return -1;
    }
    memset(&pair, 0, sizeof(pair));
    memset(&reconciled_pair, 0, sizeof(reconciled_pair));
    memset(&revalidated_stage_identity, 0,
           sizeof(revalidated_stage_identity));
    memset(&primary_error, 0, sizeof(primary_error));

    if (guard->prepared) {
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Prepared retirement completion failed before commit");
            goto clear_fail;
        }
        if (config_retirement_guard_pair_read_at(
                guard->directory_fd, &pair) != 0 ||
            !config_retirement_guard_pair_matches_handle(guard, &pair) ||
            !config_retirement_guard_completion_matches_handle(
                guard, &pair) ||
            config_retirement_guard_prepared_source_exact_at(
                guard, &pair, &stage_identity) != 0 ||
            !config_named_directory_matches(
                guard->directory, &guard->directory_identity) ||
            verify_private_lock_file_at(
                guard->lock_fd, guard->directory_fd,
                CONFIG_RETIREMENT_LOCK_NAME) != 0) {
            if (errno == 0) errno = ESTALE;
            if (get_last_error()->message[0] == '\0') {
                set_system_error(
                    ERR_FILE_IO,
                    "Prepared retirement completion generation changed before commit");
            }
            goto clear_fail;
        }
        config_retirement_guard_pair_clear(&pair);
        if (barrier) {
            int barrier_result;

            guard->barrier_active = true;
            barrier_result = barrier(context);
            guard->barrier_active = false;
            if (barrier_result != 0) {
                error_context_t barrier_error = *get_last_error();
                int barrier_errno = errno;

                g_last_error = barrier_error;
                errno = barrier_errno;
                goto clear_fail;
            }
        }
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_AFTER_BARRIER_BEFORE_RENAME,
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Prepared retirement completion failed after commit barrier");
            goto clear_fail;
        }
        /* The barrier may execute arbitrary retirement bookkeeping and is
         * therefore a proof-separation boundary. Revalidate every capability
         * immediately afterward: canonical marker, prior completion,
         * prepared source, pinned directory, and named lifecycle lock. */
        if (config_retirement_guard_revalidate(guard) != 0) {
            if (errno == 0) errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Prepared retirement completion changed after commit barrier");
            goto clear_fail;
        }
        if (config_retirement_guard_publish_prepared_at(
                guard, &published_identity,
                &publication_committed) != 0) {
            if (publication_committed) {
                log_warning(
                    "Retirement completion committed after the barrier but its acknowledgement was lost");
                config_retirement_guard_finish_prepared_commit(
                    guard_ptr);
                clear_error();
                errno = 0;
                return 0;
            }
            set_system_error(
                ERR_FILE_IO,
                "Cannot commit prepared retirement completion");
            goto clear_fail;
        }
        if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
                RETIREMENT_GUARD_CLEAR_AFTER_PREPARED_PUBLISH,
                guard->directory_fd,
                CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
            log_warning(
                "Retirement completion post-publication acknowledgement was lost");
        }
        if (config_retirement_guard_pair_read_at(
                guard->directory_fd, &pair) != 0 ||
            pair.stage_present ||
            !config_retirement_guard_pair_matches_handle(
                guard, &pair) ||
            !config_retirement_guard_pair_exact(&pair) ||
            !config_metadata_same_file(
                &published_identity, &pair.completion_identity) ||
            !config_named_directory_matches(
                guard->directory, &guard->directory_identity) ||
            verify_private_lock_file_at(
                guard->lock_fd, guard->directory_fd,
                CONFIG_RETIREMENT_LOCK_NAME) != 0) {
            config_retirement_guard_pair_clear(&pair);
            log_warning(
                "Retirement completion committed while its final canonical proof was superseded or unavailable");
            config_retirement_guard_finish_prepared_commit(
                guard_ptr);
            clear_error();
            errno = 0;
            return 0;
        }
        config_retirement_guard_pair_clear(&pair);
        config_retirement_guard_finish_prepared_commit(guard_ptr);
        clear_error();
        errno = 0;
        return 0;
    }

    if (!config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement guard directory changed before completion");
        goto clear_fail;
    }

    if (config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) != 0 ||
        !config_retirement_guard_pair_matches_handle(
            guard, &pair) ||
        !config_retirement_guard_completion_matches_handle(
            guard, &pair) ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        if (errno == 0) errno = ESTALE;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Retirement guard generation changed before completion");
        }
        goto clear_fail;
    }
    if (pair.stage_present) {
        if (config_retirement_guard_reconcile_exact_stage_at(
                guard->directory_fd, guard->directory,
                &guard->directory_identity, &pair,
                &reconciled_pair) != 0) {
            primary_error = *get_last_error();
            primary_errno = errno ? errno : EIO;
            have_primary = true;
            goto classify_commit;
        }
        config_retirement_guard_pair_clear(&pair);
        pair = reconciled_pair;
        memset(&reconciled_pair, 0, sizeof(reconciled_pair));
        if (pair.stage_present ||
            !config_retirement_guard_pair_matches_handle(
                guard, &pair) ||
            !config_retirement_guard_completion_matches_handle(
                guard, &pair)) {
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "Retirement transition cleanup changed the owned generation");
            goto clear_fail;
        }
    }
    if (config_retirement_guard_pair_exact(&pair)) {
        if (verify_private_lock_file_at(
                guard->lock_fd, guard->directory_fd,
                CONFIG_RETIREMENT_LOCK_NAME) != 0) {
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Retirement lifecycle lock changed before completion");
            goto clear_fail;
        }
        goto clear_success;
    }
    if (!guard->completion_absent &&
        config_retirement_guard_prepare_settled_slot_at(
            guard, &pair) != 0) {
        goto clear_fail;
    }
    config_retirement_guard_pair_clear(&pair);

    if (config_retirement_guard_stage_write_at(
            guard->directory_fd, guard->marker_data,
            guard->marker_length, true, &stage_identity) != 0) {
        goto clear_fail;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Retirement completion failed before certificate publication");
        goto clear_fail;
    }
    if (config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) != 0 ||
        !pair.stage_present ||
        !config_retirement_guard_pair_matches_handle(guard, &pair) ||
        !config_retirement_guard_completion_matches_handle(
            guard, &pair) ||
        config_retirement_guard_exact_stage_at(
            guard->directory_fd, &pair,
            &revalidated_stage_identity) != 0 ||
        !config_metadata_matches_after_exact_content_proof(
            &stage_identity, &revalidated_stage_identity) ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        if (errno == 0) errno = ESTALE;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Retirement completion generation changed before publication");
        }
        goto clear_fail;
    }
    stage_identity = revalidated_stage_identity;
    config_retirement_guard_pair_clear(&pair);

    if (verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_RETIREMENT_LOCK_NAME) != 0) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement lifecycle lock changed before certificate publication");
        goto clear_fail;
    }
    guard->prepared_stage_identity = stage_identity;
    guard->prepared = true;
    publication_attempted = true;
    if (config_retirement_guard_publish_prepared_at(
            guard, &published_identity,
            &publication_committed) != 0) {
        if (publication_committed) {
            log_warning(
                "Retirement completion committed but its acknowledgement was lost");
            goto clear_success;
        }
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
        if (primary_error.message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Cannot publish retirement completion certificate");
            primary_error = *get_last_error();
        }
        have_primary = true;
        goto classify_commit;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Retirement completion acknowledgement failed after publication");
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
        have_primary = true;
        goto classify_commit;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Retirement completion directory sync was interrupted");
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
        have_primary = true;
        goto classify_commit;
    }
    if (fsync(guard->directory_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot sync retirement completion certificate");
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
        have_primary = true;
        goto classify_commit;
    }
    if (RETIREMENT_GUARD_CLEAR_TEST_CHECKPOINT(
            RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
            guard->directory_fd, CONFIG_RETIREMENT_COMPLETE_NAME) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Retirement completion directory sync acknowledgement was lost");
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
        have_primary = true;
    }

classify_commit:
    config_retirement_guard_pair_clear(&pair);
    if (config_retirement_guard_pair_read_at(
            guard->directory_fd, &pair) == 0 &&
        config_retirement_guard_pair_matches_handle(
            guard, &pair) &&
        config_retirement_guard_pair_exact(&pair) &&
        config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        if (have_primary || publication_attempted) {
            if (have_primary) {
                log_warning(
                    "Retirement completion is exact despite a lost filesystem acknowledgement: %s",
                    primary_error.message[0]
                        ? primary_error.message
                        : "unknown completion acknowledgement");
            }
        }
        goto clear_success;
    }
    if (have_primary) {
        g_last_error = primary_error;
        errno = primary_errno;
    } else {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retirement completion certificate is not an exact stable pair");
    }
    goto clear_fail;

clear_success:
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&reconciled_pair);
    config_retirement_guard_free(guard);
    *guard_ptr = NULL;
    clear_error();
    errno = 0;
    return 0;

clear_fail:
    config_retirement_guard_pair_clear(&pair);
    config_retirement_guard_pair_clear(&reconciled_pair);
    return -1;
}

int config_retirement_guard_clear(
    config_retirement_guard_t **guard_ptr) {
    return config_retirement_guard_clear_with_barrier(
        guard_ptr, NULL, NULL);
}

void config_retirement_guard_abandon(
    config_retirement_guard_t **guard) {
    if (!guard || !*guard) return;
    if ((*guard)->barrier_active &&
        (*guard)->owner_pid == getpid()) {
        errno = EBUSY;
        set_error(
            ERR_INVALID_ARGS,
            "Cannot abandon a retirement guard from its commit barrier");
        return;
    }
    /* A fork taken inside the barrier inherits barrier_active but never
     * inherits its creator's authority. The child must still be able to
     * discard that copied handle: free() closes only its descriptor copies
     * for a foreign owner and clears the child-local singleton without
     * unlocking or mutating the parent's namespace. */
    /* clear() never removes or renames the canonical blocker. A failed
     * transition may retain the one fixed stage, which probe also classifies
     * as blocked; releasing the lifecycle lock cannot reopen mutation. */
    config_retirement_guard_free(*guard);
    *guard = NULL;
}

#define CONFIG_SWITCH_GUARD_NAME ".switch-incomplete"
#define CONFIG_SWITCH_STAGE_NAME ".switch-transition"
#define CONFIG_SWITCH_NORMALIZE_NAME ".switch-normalize"
#define CONFIG_SWITCH_LOCK_NAME ".switch.lock"
#define CONFIG_SWITCH_GUARD_HEADER "gitswitch-switch-incomplete-v3"
#define CONFIG_SWITCH_GUARD_METADATA_MAX_BYTES (64U * 1024U)
#define CONFIG_SWITCH_GUARD_MAX_BYTES \
    (CONFIG_SWITCH_GUARD_METADATA_MAX_BYTES + CONFIG_DOCUMENT_MAX_SIZE)
#define CONFIG_SWITCH_SOURCE_CONVERGENCE_MAX 3U

typedef struct {
    char token[ACCOUNT_INCARNATION_LEN];
    publication_identity_t source_generation;
    account_t target;
    git_scope_t effective_scope;
    publication_record_t destinations[CONFIG_SWITCH_DESTINATION_MAX];
    size_t destination_count;
} config_switch_guard_model_t;

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
} config_switch_guard_writer_t;

typedef struct {
    bool stage_present;
    bool marker_absent;
    struct stat stage_identity;
    struct stat marker_identity;
    unsigned char *marker_data;
    size_t marker_length;
    unsigned char *source_witness;
    size_t source_witness_length;
    config_switch_guard_model_t marker_model;
} config_switch_guard_snapshot_t;

typedef enum {
    CONFIG_SWITCH_PREINTENT_NONE = 0,
    CONFIG_SWITCH_PREINTENT_STAGE_ONLY,
    CONFIG_SWITCH_PREINTENT_EXACT_PAIR,
    CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR
} config_switch_preintent_kind_t;

typedef struct {
    config_switch_preintent_kind_t kind;
    struct stat stage_identity;
    struct stat marker_identity;
} config_switch_preintent_snapshot_t;

struct config_switch_guard {
    int directory_fd;
    int lock_fd;
    pid_t owner_pid;
    char directory[MAX_PATH_LEN];
    char config_name[MAX_PATH_LEN];
    struct stat directory_identity;
    struct stat marker_identity;
    unsigned char *marker_data;
    size_t marker_length;
    unsigned char *source_witness;
    size_t source_witness_length;
    config_switch_guard_model_t model;
    char token[ACCOUNT_INCARNATION_LEN];
    bool created;
    bool marker_unlinked;
};

#ifdef GITSWITCH_TESTING
int gitswitch_test_switch_guard_directory_fd(
    const config_switch_guard_t *guard) {
    return guard ? guard->directory_fd : -1;
}
#endif

static pid_t g_switch_guard_owner_pid;

static int config_switch_guard_stage_write_at(
    int directory_fd, const unsigned char *data, size_t length,
    struct stat *stage_identity, bool *stage_created,
    bool *stage_identity_known);
static int config_switch_guard_named_write_at(
    int directory_fd, const char *name,
    const unsigned char *data, size_t length,
    struct stat *identity, bool *created,
    bool *identity_known);
static int config_switch_guard_cleanup_owned_stage_at(
    int directory_fd, int lock_fd, const char *directory,
    const struct stat *directory_identity,
    const struct stat *stage_identity, bool *stage_created);

static bool config_switch_string_terminated(const char *value, size_t size) {
    return value && memchr(value, '\0', size) != NULL;
}

static bool config_switch_identity_is_zero(
    const publication_identity_t *identity) {
    return identity && !identity->present && identity->device == 0U &&
           identity->inode == 0U && identity->mode == 0U &&
           identity->uid == 0U && identity->gid == 0U &&
           identity->link_count == 0U && identity->size == 0U &&
           identity->mtime_seconds == 0 &&
           identity->mtime_nanoseconds == 0U &&
           identity->ctime_seconds == 0 &&
           identity->ctime_nanoseconds == 0U;
}

static bool config_switch_identity_is_type(
    const publication_identity_t *identity, bool directory) {
    mode_t mode;

    if (!identity || !identity->present || identity->link_count == 0U) {
        return false;
    }
    mode = (mode_t)identity->mode;
    if ((uintmax_t)mode != identity->mode ||
        identity->mtime_nanoseconds > UINT32_C(999999999) ||
        identity->ctime_nanoseconds > UINT32_C(999999999)) {
        return false;
    }
    return directory ? S_ISDIR(mode) : S_ISREG(mode);
}

/* Directory size, link count, and timestamps legitimately change when Git
 * atomically replaces its config or updates repository metadata. Recovery
 * authority is the same named directory object under the same ownership/mode
 * policy, not an impossible byte-generation comparison of mutable directory
 * bookkeeping. */
static bool config_switch_same_directory_authority(
    const publication_identity_t *recorded,
    const publication_identity_t *observed) {
    return config_switch_identity_is_type(recorded, true) &&
           config_switch_identity_is_type(observed, true) &&
           recorded->device == observed->device &&
           recorded->inode == observed->inode &&
           recorded->mode == observed->mode &&
           recorded->uid == observed->uid &&
           recorded->gid == observed->gid;
}

static const char *config_switch_git_scope_name(git_scope_t scope) {
    switch (scope) {
        case GIT_SCOPE_LOCAL:
            return "local";
        case GIT_SCOPE_GLOBAL:
            return "global";
        case GIT_SCOPE_SYSTEM:
        default:
            return NULL;
    }
}

static const char *config_switch_publication_scope_name(
    publication_scope_t scope) {
    switch (scope) {
        case PUBLICATION_SCOPE_LOCAL:
            return "local";
        case PUBLICATION_SCOPE_GLOBAL:
            return "global";
        case PUBLICATION_SCOPE_WORKTREE:
            return "worktree";
        default:
            return NULL;
    }
}

static bool config_switch_target_live_fields_equal(
    const account_t *left, const account_t *right) {
    return left && right && left->id == right->id &&
           strcmp(left->incarnation, right->incarnation) == 0 &&
           strcmp(left->name, right->name) == 0 &&
           strcmp(left->email, right->email) == 0 &&
           left->preferred_scope == right->preferred_scope &&
           left->ssh_enabled == right->ssh_enabled &&
           strcmp(left->ssh_key_path, right->ssh_key_path) == 0 &&
           strcmp(left->ssh_host_alias, right->ssh_host_alias) == 0 &&
           strcmp(left->ssh_hostname, right->ssh_hostname) == 0 &&
           left->gpg_enabled == right->gpg_enabled &&
           left->gpg_signing_enabled == right->gpg_signing_enabled &&
           strcmp(left->gpg_key_id, right->gpg_key_id) == 0;
}

static bool config_switch_destination_record_valid(
    const publication_record_t *destination) {
    bool repository_present;

    if (!destination ||
        !config_switch_publication_scope_name(destination->scope) ||
        !config_switch_string_terminated(
            destination->config_path, sizeof(destination->config_path)) ||
        !config_switch_string_terminated(
            destination->repository_path,
            sizeof(destination->repository_path)) ||
        destination->config_path[0] != '/' ||
        !config_switch_identity_is_type(
            &destination->config_parent, true)) {
        return false;
    }
    repository_present = destination->repository_path[0] != '\0';
    if (repository_present != destination->repository.present ||
        (repository_present &&
         (destination->repository_path[0] != '/' ||
          !config_switch_identity_is_type(
              &destination->repository, true))) ||
        (!repository_present &&
         !config_switch_identity_is_zero(&destination->repository))) {
        return false;
    }
    if (destination->scope == PUBLICATION_SCOPE_GLOBAL) {
        return !repository_present;
    }
    return repository_present;
}

static bool config_switch_destinations_valid(
    git_scope_t effective_scope,
    const publication_record_t *destinations, size_t destination_count) {
    publication_scope_t expected[CONFIG_SWITCH_DESTINATION_MAX];
    size_t expected_count = 0U;

    if (!destinations || destination_count == 0U ||
        destination_count > CONFIG_SWITCH_DESTINATION_MAX ||
        !config_scope_is_persistable(effective_scope)) {
        return false;
    }
    expected[expected_count++] =
        effective_scope == GIT_SCOPE_GLOBAL
            ? PUBLICATION_SCOPE_GLOBAL
            : PUBLICATION_SCOPE_LOCAL;
    for (size_t i = 1U; i < destination_count; i++) {
        publication_scope_t scope = destinations[i].scope;

        if (scope == PUBLICATION_SCOPE_LOCAL &&
            effective_scope == GIT_SCOPE_GLOBAL &&
            expected_count == 1U) {
            expected[expected_count++] = scope;
        } else if (scope == PUBLICATION_SCOPE_WORKTREE &&
                   expected_count == i &&
                   expected[expected_count - 1U] !=
                       PUBLICATION_SCOPE_WORKTREE) {
            expected[expected_count++] = scope;
        } else {
            return false;
        }
    }
    if (expected_count != destination_count) return false;
    for (size_t i = 0U; i < destination_count; i++) {
        if (destinations[i].scope != expected[i] ||
            !config_switch_destination_record_valid(
                &destinations[i])) {
            return false;
        }
    }
    return true;
}

static bool config_switch_same_destination_authority(
    const publication_record_t *recorded,
    const publication_record_t *observed) {
    return recorded && observed &&
           recorded->scope == observed->scope &&
           strcmp(
               recorded->config_path,
               observed->config_path) == 0 &&
           strcmp(
               recorded->repository_path,
               observed->repository_path) == 0 &&
           config_switch_same_directory_authority(
               &recorded->config_parent,
               &observed->config_parent) &&
           ((recorded->repository_path[0] == '\0' &&
             config_switch_identity_is_zero(
                 &recorded->repository) &&
             config_switch_identity_is_zero(
                 &observed->repository)) ||
            (recorded->repository_path[0] != '\0' &&
             config_switch_same_directory_authority(
                 &recorded->repository,
                 &observed->repository)));
}

static bool config_switch_same_destinations_authority(
    const publication_record_t *recorded, size_t recorded_count,
    const publication_record_t *observed, size_t observed_count) {
    if (!recorded || !observed || recorded_count != observed_count ||
        recorded_count == 0U ||
        recorded_count > CONFIG_SWITCH_DESTINATION_MAX) {
        return false;
    }
    for (size_t i = 0U; i < recorded_count; i++) {
        if (!config_switch_same_destination_authority(
                &recorded[i], &observed[i])) {
            return false;
        }
    }
    return true;
}

static int config_switch_directory_authority_live(
    const char *path, const publication_identity_t *recorded,
    const char *diagnostic) {
    struct stat before;
    struct stat opened;
    struct stat after;
    publication_identity_t observed;
    int fd = -1;
    int saved_errno = ESTALE;

    if (!path || path[0] == '\0' || !recorded) {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &before) != 0 || !S_ISDIR(before.st_mode)) {
        saved_errno = errno ? errno : ESTALE;
        goto authority_fail;
    }
    fd = open(
        path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !S_ISDIR(opened.st_mode) ||
        !config_metadata_snapshot_same(&before, &opened)) {
        saved_errno = errno ? errno : ESTALE;
        goto authority_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        saved_errno = errno ? errno : EIO;
        goto authority_fail;
    }
    fd = -1;
    if (lstat(path, &after) != 0 || !S_ISDIR(after.st_mode) ||
        !config_metadata_snapshot_same(&opened, &after)) {
        saved_errno = errno ? errno : ESTALE;
        goto authority_fail;
    }
    publication_identity_from_stat(&observed, &after);
    if (!config_switch_same_directory_authority(
            recorded, &observed)) {
        saved_errno = ESTALE;
        goto authority_fail;
    }
    return 0;

authority_fail:
    if (fd >= 0) close(fd);
    errno = saved_errno;
    set_system_error(
        ERR_FILE_IO, "Switch recovery %s is no longer current",
        diagnostic ? diagnostic : "directory authority");
    return -1;
}

static int config_switch_destination_live(
    const publication_record_t *recorded) {
    char parent[MAX_PATH_LEN];

    if (!recorded ||
        config_directory_for_path(
            recorded->config_path, parent, sizeof(parent)) != 0 ||
        config_switch_directory_authority_live(
            parent, &recorded->config_parent,
            "Git config parent") != 0) {
        return -1;
    }
    if (recorded->repository_path[0] == '\0') return 0;
    return config_switch_directory_authority_live(
        recorded->repository_path, &recorded->repository,
        "repository");
}

static int config_switch_destinations_live(
    const publication_record_t *destinations, size_t destination_count) {
    if (!destinations || destination_count == 0U ||
        destination_count > CONFIG_SWITCH_DESTINATION_MAX) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch recovery destination set");
        return -1;
    }
    for (size_t i = 0U; i < destination_count; i++) {
        if (config_switch_destination_live(&destinations[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static bool config_switch_guard_model_valid(
    const config_switch_guard_model_t *model) {
    const account_t *target;
    mode_t source_mode;

    if (!model || !account_incarnation_is_valid(model->token) ||
        !config_switch_identity_is_type(
            &model->source_generation, false)) {
        return false;
    }
    source_mode = (mode_t)model->source_generation.mode;
    if (model->source_generation.uid != (uintmax_t)getuid() ||
        model->source_generation.link_count != 1U ||
        (source_mode & 0777) != PERM_USER_RW) {
        return false;
    }
    target = &model->target;
    if (!config_account_id_is_valid(target->id) ||
        !account_incarnation_is_valid(target->incarnation) ||
        !target->incarnation_persisted ||
        !config_scope_is_persistable(target->preferred_scope) ||
        !config_switch_string_terminated(target->name,
                                         sizeof(target->name)) ||
        !config_switch_string_terminated(target->email,
                                         sizeof(target->email)) ||
        !config_switch_string_terminated(target->ssh_key_path,
                                         sizeof(target->ssh_key_path)) ||
        !config_switch_string_terminated(
            target->ssh_host_alias, sizeof(target->ssh_host_alias)) ||
        !config_switch_string_terminated(
            target->ssh_hostname, sizeof(target->ssh_hostname)) ||
        !config_switch_string_terminated(target->gpg_key_id,
                                         sizeof(target->gpg_key_id)) ||
        !config_scope_is_persistable(model->effective_scope)) {
        return false;
    }
    return config_switch_destinations_valid(
        model->effective_scope, model->destinations,
        model->destination_count);
}

static int config_switch_writer_append(
    config_switch_guard_writer_t *writer, const void *data, size_t length) {
    if (!writer || !writer->data || writer->length > writer->capacity ||
        length > writer->capacity - writer->length ||
        (length != 0U && !data)) {
        errno = EOVERFLOW;
        set_error(ERR_CONFIG_INVALID,
                  "Switch guard marker exceeds its byte limit");
        return -1;
    }
    if (length != 0U) {
        memcpy(writer->data + writer->length, data, length);
        writer->length += length;
    }
    return 0;
}

static int config_switch_writer_printf(
    config_switch_guard_writer_t *writer, const char *format, ...)
    GS_PRINTF_FMT(2, 3);

static int config_switch_writer_printf(
    config_switch_guard_writer_t *writer, const char *format, ...) {
    va_list args;
    size_t remaining;
    int written;

    if (!writer || !writer->data || !format ||
        writer->length > writer->capacity) {
        errno = EINVAL;
        return -1;
    }
    remaining = writer->capacity - writer->length;
    va_start(args, format);
    /* All callers below use fixed format strings and bounded values. */
    // flawfinder: ignore
    written = vsnprintf(
        (char *)writer->data + writer->length, remaining, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= remaining) {
        errno = EOVERFLOW;
        set_error(ERR_CONFIG_INVALID,
                  "Switch guard marker exceeds its byte limit");
        return -1;
    }
    writer->length += (size_t)written;
    return 0;
}

static int config_switch_writer_hex(
    config_switch_guard_writer_t *writer, const char *value) {
    static const char digits[] = "0123456789ABCDEF";

    if (!value || value[0] == '\0') {
        return config_switch_writer_append(writer, "-", 1U);
    }
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor; cursor++) {
        char encoded[2] = {
            digits[*cursor >> 4U], digits[*cursor & 0x0fU]
        };
        if (config_switch_writer_append(
                writer, encoded, sizeof(encoded)) != 0) {
            return -1;
        }
    }
    return 0;
}

static int config_switch_writer_named_hex(
    config_switch_guard_writer_t *writer, const char *name,
    const char *value) {
    return config_switch_writer_printf(writer, "%s=", name) == 0 &&
                   config_switch_writer_hex(writer, value) == 0 &&
                   config_switch_writer_append(writer, "\n", 1U) == 0
               ? 0
               : -1;
}

static int config_switch_writer_identity(
    config_switch_guard_writer_t *writer,
    const publication_identity_t *identity) {
    if (!identity || !identity->present) {
        return config_switch_writer_append(writer, "-", 1U);
    }
    return config_switch_writer_printf(
        writer,
        "%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
        ":%" PRIuMAX ":%" PRIuMAX ":%" PRId64 ":%" PRIu32
        ":%" PRId64 ":%" PRIu32,
        identity->device, identity->inode, identity->mode, identity->uid,
        identity->gid, identity->link_count, identity->size,
        identity->mtime_seconds, identity->mtime_nanoseconds,
        identity->ctime_seconds, identity->ctime_nanoseconds);
}

static int config_switch_writer_named_identity(
    config_switch_guard_writer_t *writer, const char *name,
    const publication_identity_t *identity) {
    return config_switch_writer_printf(writer, "%s=", name) == 0 &&
                   config_switch_writer_identity(writer, identity) == 0 &&
                   config_switch_writer_append(writer, "\n", 1U) == 0
               ? 0
               : -1;
}

static int config_switch_guard_serialize(
    const config_switch_guard_model_t *model,
    const unsigned char *source_witness, size_t source_witness_length,
    unsigned char **serialized, size_t *serialized_length) {
    config_switch_guard_writer_t writer;
    unsigned char *data;
    const char *preferred_scope;
    const char *effective_scope;

    if (!serialized || !serialized_length || !source_witness ||
        source_witness_length == 0U ||
        source_witness_length > CONFIG_DOCUMENT_MAX_SIZE ||
        !config_switch_guard_model_valid(model) ||
        model->source_generation.size != source_witness_length) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard serialization arguments");
        return -1;
    }
    *serialized = NULL;
    *serialized_length = 0U;
    preferred_scope =
        config_switch_git_scope_name(model->target.preferred_scope);
    effective_scope =
        config_switch_git_scope_name(model->effective_scope);
    if (!preferred_scope || !effective_scope) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Switch guard contains an unsupported scope");
        return -1;
    }
    data = calloc(1U, CONFIG_SWITCH_GUARD_MAX_BYTES);
    if (!data) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate switch guard marker");
        return -1;
    }
    writer.data = data;
    writer.length = 0U;
    writer.capacity = CONFIG_SWITCH_GUARD_MAX_BYTES;

    if (config_switch_writer_printf(
            &writer, "%s\n", CONFIG_SWITCH_GUARD_HEADER) != 0 ||
        config_switch_writer_printf(
            &writer, "token=%s\n", model->token) != 0 ||
        config_switch_writer_named_identity(
            &writer, "source_generation",
            &model->source_generation) != 0 ||
        config_switch_writer_printf(
            &writer, "target_id=%" PRIu32 "\n",
            model->target.id) != 0 ||
        config_switch_writer_printf(
            &writer, "target_incarnation=%s\n",
            model->target.incarnation) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_name", model->target.name) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_email", model->target.email) != 0 ||
        config_switch_writer_printf(
            &writer, "target_preferred_scope=%s\n",
            preferred_scope) != 0 ||
        config_switch_writer_printf(
            &writer, "target_ssh_enabled=%u\n",
            model->target.ssh_enabled ? 1U : 0U) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_ssh_key_path",
            model->target.ssh_key_path) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_ssh_host_alias",
            model->target.ssh_host_alias) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_ssh_hostname",
            model->target.ssh_hostname) != 0 ||
        config_switch_writer_printf(
            &writer, "target_gpg_enabled=%u\n",
            model->target.gpg_enabled ? 1U : 0U) != 0 ||
        config_switch_writer_printf(
            &writer, "target_gpg_signing_enabled=%u\n",
            model->target.gpg_signing_enabled ? 1U : 0U) != 0 ||
        config_switch_writer_named_hex(
            &writer, "target_gpg_key_id",
            model->target.gpg_key_id) != 0 ||
        config_switch_writer_printf(
            &writer, "effective_scope=%s\n",
            effective_scope) != 0 ||
        config_switch_writer_printf(
            &writer, "destination_count=%zu\n",
            model->destination_count) != 0) {
        secure_zero_memory(data, CONFIG_SWITCH_GUARD_MAX_BYTES);
        free(data);
        return -1;
    }
    for (size_t i = 0U; i < model->destination_count; i++) {
        const publication_record_t *destination =
            &model->destinations[i];
        const char *destination_scope =
            config_switch_publication_scope_name(destination->scope);
        char field[64];

        if (!destination_scope ||
            (size_t)snprintf(
                field, sizeof(field), "destination_%zu_scope", i) >=
                sizeof(field) ||
            config_switch_writer_printf(
                &writer, "%s=%s\n", field,
                destination_scope) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_config_path", i) >= sizeof(field) ||
            config_switch_writer_named_hex(
                &writer, field, destination->config_path) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_config_parent", i) >= sizeof(field) ||
            config_switch_writer_named_identity(
                &writer, field, &destination->config_parent) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_repository_path", i) >= sizeof(field) ||
            config_switch_writer_named_hex(
                &writer, field, destination->repository_path) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_repository", i) >= sizeof(field) ||
            config_switch_writer_named_identity(
                &writer, field, &destination->repository) != 0) {
            secure_zero_memory(data, CONFIG_SWITCH_GUARD_MAX_BYTES);
            free(data);
            return -1;
        }
    }
    if (writer.length > CONFIG_SWITCH_GUARD_METADATA_MAX_BYTES ||
        config_switch_writer_printf(
            &writer, "source_witness_length=%zu\n",
            source_witness_length) != 0 ||
        writer.length > CONFIG_SWITCH_GUARD_METADATA_MAX_BYTES ||
        config_switch_writer_append(
            &writer, source_witness, source_witness_length) != 0) {
        secure_zero_memory(data, CONFIG_SWITCH_GUARD_MAX_BYTES);
        free(data);
        return -1;
    }
    *serialized = data;
    *serialized_length = writer.length;
    return 0;
}

static int config_switch_guard_malformed(const char *detail) {
    errno = EINVAL;
    set_error(ERR_CONFIG_INVALID,
              "Switch-incomplete marker is malformed%s%s",
              detail && detail[0] ? ": " : "",
              detail && detail[0] ? detail : "");
    return -1;
}

static int config_switch_read_field(
    const unsigned char **cursor, const unsigned char *end,
    const char *name, const unsigned char **value,
    size_t *value_length) {
    const unsigned char *line;
    size_t line_length;
    size_t name_length;

    if (!cursor || !*cursor || !end || !name || !value ||
        !value_length ||
        !config_retirement_next_line(
            cursor, end, &line, &line_length)) {
        return config_switch_guard_malformed(
            "missing canonical field");
    }
    name_length = strlen(name);
    if (line_length <= name_length ||
        memcmp(line, name, name_length) != 0 ||
        line[name_length] != '=') {
        return config_switch_guard_malformed(
            "unexpected canonical field");
    }
    *value = line + name_length + 1U;
    *value_length = line_length - name_length - 1U;
    return 0;
}

static int config_switch_copy_token(
    const unsigned char *value, size_t length, char *out,
    size_t out_size) {
    if (!value || !out || out_size == 0U || length >= out_size ||
        memchr(value, '\0', length) != NULL) {
        return config_switch_guard_malformed("invalid token");
    }
    memcpy(out, value, length);
    out[length] = '\0';
    return 0;
}

static int config_switch_parse_uintmax(
    const unsigned char *value, size_t length, uintmax_t maximum,
    uintmax_t *out) {
    char token[64];
    char canonical[64];
    char *end = NULL;
    uintmax_t parsed;
    int written;

    if (!out ||
        config_switch_copy_token(
            value, length, token, sizeof(token)) != 0 ||
        token[0] == '\0') {
        return config_switch_guard_malformed("invalid unsigned integer");
    }
    errno = 0;
    parsed = strtoumax(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' ||
        parsed > maximum) {
        return config_switch_guard_malformed("invalid unsigned integer");
    }
    written = snprintf( /* Flawfinder: ignore — bounded destination and
                         * compile-time PRI format. */
        canonical, sizeof(canonical), "%" PRIuMAX, parsed);
    if (written < 0 || (size_t)written != length ||
        memcmp(canonical, value, length) != 0) {
        return config_switch_guard_malformed(
            "noncanonical unsigned integer");
    }
    *out = parsed;
    return 0;
}

static int config_switch_parse_int64(
    const unsigned char *value, size_t length, int64_t *out) {
    char token[64];
    char canonical[64];
    char *end = NULL;
    intmax_t parsed;
    int written;

    if (!out ||
        config_switch_copy_token(
            value, length, token, sizeof(token)) != 0 ||
        token[0] == '\0') {
        return config_switch_guard_malformed("invalid signed integer");
    }
    errno = 0;
    parsed = strtoimax(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' ||
        parsed < INT64_MIN || parsed > INT64_MAX) {
        return config_switch_guard_malformed("invalid signed integer");
    }
    written = snprintf( /* Flawfinder: ignore — bounded destination and
                         * compile-time PRI format. */
        canonical, sizeof(canonical), "%" PRId64, (int64_t)parsed);
    if (written < 0 || (size_t)written != length ||
        memcmp(canonical, value, length) != 0) {
        return config_switch_guard_malformed(
            "noncanonical signed integer");
    }
    *out = (int64_t)parsed;
    return 0;
}

static int config_switch_parse_identity(
    const unsigned char *value, size_t length,
    publication_identity_t *identity) {
    const unsigned char *fields[11];
    size_t field_lengths[11];
    const unsigned char *cursor;
    const unsigned char *end;
    uintmax_t device;
    uintmax_t inode;
    uintmax_t mode;
    uintmax_t uid;
    uintmax_t gid;
    uintmax_t link_count;
    uintmax_t size;
    uintmax_t mtime_nanoseconds;
    uintmax_t ctime_nanoseconds;
    int64_t mtime_seconds;
    int64_t ctime_seconds;

    if (!value || !identity) {
        return config_switch_guard_malformed("invalid identity");
    }
    memset(identity, 0, sizeof(*identity));
    if (length == 1U && value[0] == '-') return 0;
    cursor = value;
    end = value + length;
    for (size_t i = 0U; i < 11U; i++) {
        const unsigned char *separator =
            memchr(cursor, ':', (size_t)(end - cursor));

        if (i < 10U) {
            if (!separator || separator == cursor) {
                return config_switch_guard_malformed(
                    "invalid identity field count");
            }
            fields[i] = cursor;
            field_lengths[i] = (size_t)(separator - cursor);
            cursor = separator + 1U;
        } else {
            if (separator || cursor == end) {
                return config_switch_guard_malformed(
                    "invalid identity field count");
            }
            fields[i] = cursor;
            field_lengths[i] = (size_t)(end - cursor);
        }
    }
    if (config_switch_parse_uintmax(
            fields[0], field_lengths[0], UINTMAX_MAX, &device) != 0 ||
        config_switch_parse_uintmax(
            fields[1], field_lengths[1], UINTMAX_MAX, &inode) != 0 ||
        config_switch_parse_uintmax(
            fields[2], field_lengths[2], UINTMAX_MAX, &mode) != 0 ||
        config_switch_parse_uintmax(
            fields[3], field_lengths[3], UINTMAX_MAX, &uid) != 0 ||
        config_switch_parse_uintmax(
            fields[4], field_lengths[4], UINTMAX_MAX, &gid) != 0 ||
        config_switch_parse_uintmax(
            fields[5], field_lengths[5], UINTMAX_MAX,
            &link_count) != 0 ||
        config_switch_parse_uintmax(
            fields[6], field_lengths[6], UINTMAX_MAX, &size) != 0 ||
        config_switch_parse_int64(
            fields[7], field_lengths[7], &mtime_seconds) != 0 ||
        config_switch_parse_uintmax(
            fields[8], field_lengths[8], UINTMAX_C(999999999),
            &mtime_nanoseconds) != 0 ||
        config_switch_parse_int64(
            fields[9], field_lengths[9], &ctime_seconds) != 0 ||
        config_switch_parse_uintmax(
            fields[10], field_lengths[10], UINTMAX_C(999999999),
            &ctime_nanoseconds) != 0) {
        return -1;
    }
    identity->present = true;
    identity->device = device;
    identity->inode = inode;
    identity->mode = mode;
    identity->uid = uid;
    identity->gid = gid;
    identity->link_count = link_count;
    identity->size = size;
    identity->mtime_seconds = mtime_seconds;
    identity->mtime_nanoseconds = (uint32_t)mtime_nanoseconds;
    identity->ctime_seconds = ctime_seconds;
    identity->ctime_nanoseconds = (uint32_t)ctime_nanoseconds;
    return 0;
}

static int config_switch_decode_hex(
    const unsigned char *value, size_t length, char *out,
    size_t out_size) {
    size_t decoded;

    if (!out || out_size == 0U) {
        return config_switch_guard_malformed("invalid hex output");
    }
    out[0] = '\0';
    if (length == 1U && value[0] == '-') return 0;
    if (!value || length == 0U || (length & 1U) != 0U) {
        return config_switch_guard_malformed("invalid hex length");
    }
    decoded = length / 2U;
    if (decoded >= out_size) {
        return config_switch_guard_malformed(
            "hex field exceeds its bound");
    }
    for (size_t i = 0U; i < decoded; i++) {
        unsigned char high = value[i * 2U];
        unsigned char low = value[i * 2U + 1U];
        unsigned int hi;
        unsigned int lo;

        if (high >= '0' && high <= '9') {
            hi = (unsigned int)(high - '0');
        } else if (high >= 'A' && high <= 'F') {
            hi = (unsigned int)(high - 'A') + 10U;
        } else {
            return config_switch_guard_malformed(
                "hex field is not uppercase");
        }
        if (low >= '0' && low <= '9') {
            lo = (unsigned int)(low - '0');
        } else if (low >= 'A' && low <= 'F') {
            lo = (unsigned int)(low - 'A') + 10U;
        } else {
            return config_switch_guard_malformed(
                "hex field is not uppercase");
        }
        out[i] = (char)((hi << 4U) | lo);
        if (out[i] == '\0') {
            secure_zero_memory(out, out_size);
            return config_switch_guard_malformed(
                "hex field contains NUL");
        }
    }
    out[decoded] = '\0';
    return 0;
}

static int config_switch_parse_scope(
    const unsigned char *value, size_t length, git_scope_t *scope) {
    if (!scope) return config_switch_guard_malformed("missing Git scope");
    if (config_retirement_line_equals(value, length, "local")) {
        *scope = GIT_SCOPE_LOCAL;
        return 0;
    }
    if (config_retirement_line_equals(value, length, "global")) {
        *scope = GIT_SCOPE_GLOBAL;
        return 0;
    }
    return config_switch_guard_malformed("unsupported Git scope");
}

static int config_switch_parse_publication_scope(
    const unsigned char *value, size_t length,
    publication_scope_t *scope) {
    if (!scope) {
        return config_switch_guard_malformed(
            "missing destination scope");
    }
    if (config_retirement_line_equals(value, length, "local")) {
        *scope = PUBLICATION_SCOPE_LOCAL;
        return 0;
    }
    if (config_retirement_line_equals(value, length, "global")) {
        *scope = PUBLICATION_SCOPE_GLOBAL;
        return 0;
    }
    if (config_retirement_line_equals(value, length, "worktree")) {
        *scope = PUBLICATION_SCOPE_WORKTREE;
        return 0;
    }
    return config_switch_guard_malformed(
        "unsupported destination scope");
}

static int config_switch_parse_bool(
    const unsigned char *value, size_t length, bool *parsed) {
    if (!parsed || length != 1U ||
        (value[0] != '0' && value[0] != '1')) {
        return config_switch_guard_malformed("invalid boolean");
    }
    *parsed = value[0] == '1';
    return 0;
}

static int config_switch_guard_parse(
    const unsigned char *data, size_t length,
    config_switch_guard_model_t *model,
    unsigned char **source_witness, size_t *source_witness_length) {
    const unsigned char *cursor = data;
    const unsigned char *end;
    const unsigned char *line;
    const unsigned char *value;
    size_t line_length;
    size_t value_length;
    uintmax_t account_id;
    uintmax_t destination_count;
    uintmax_t witness_length;
    unsigned char *canonical = NULL;
    size_t canonical_length = 0U;

    if (!data || length == 0U ||
        length > CONFIG_SWITCH_GUARD_MAX_BYTES || !model ||
        !source_witness || !source_witness_length) {
        return config_switch_guard_malformed("invalid marker size");
    }
    *source_witness = NULL;
    *source_witness_length = 0U;
    memset(model, 0, sizeof(*model));
    end = data + length;
    if (!config_retirement_next_line(
            &cursor, end, &line, &line_length) ||
        !config_retirement_line_equals(
            line, line_length, CONFIG_SWITCH_GUARD_HEADER) ||
        config_switch_read_field(
            &cursor, end, "token", &value, &value_length) != 0 ||
        config_switch_copy_token(
            value, value_length, model->token,
            sizeof(model->token)) != 0 ||
        !account_incarnation_is_valid(model->token) ||
        config_switch_read_field(
            &cursor, end, "source_generation",
            &value, &value_length) != 0 ||
        config_switch_parse_identity(
            value, value_length, &model->source_generation) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_id", &value, &value_length) != 0 ||
        config_switch_parse_uintmax(
            value, value_length, UINT32_MAX, &account_id) != 0 ||
        account_id == 0U ||
        config_switch_read_field(
            &cursor, end, "target_incarnation",
            &value, &value_length) != 0 ||
        config_switch_copy_token(
            value, value_length, model->target.incarnation,
            sizeof(model->target.incarnation)) != 0 ||
        !account_incarnation_is_valid(model->target.incarnation) ||
        config_switch_read_field(
            &cursor, end, "target_name",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.name,
            sizeof(model->target.name)) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_email",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.email,
            sizeof(model->target.email)) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_preferred_scope",
            &value, &value_length) != 0 ||
        config_switch_parse_scope(
            value, value_length,
            &model->target.preferred_scope) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_ssh_enabled",
            &value, &value_length) != 0 ||
        config_switch_parse_bool(
            value, value_length,
            &model->target.ssh_enabled) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_ssh_key_path",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.ssh_key_path,
            sizeof(model->target.ssh_key_path)) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_ssh_host_alias",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.ssh_host_alias,
            sizeof(model->target.ssh_host_alias)) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_ssh_hostname",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.ssh_hostname,
            sizeof(model->target.ssh_hostname)) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_gpg_enabled",
            &value, &value_length) != 0 ||
        config_switch_parse_bool(
            value, value_length,
            &model->target.gpg_enabled) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_gpg_signing_enabled",
            &value, &value_length) != 0 ||
        config_switch_parse_bool(
            value, value_length,
            &model->target.gpg_signing_enabled) != 0 ||
        config_switch_read_field(
            &cursor, end, "target_gpg_key_id",
            &value, &value_length) != 0 ||
        config_switch_decode_hex(
            value, value_length, model->target.gpg_key_id,
            sizeof(model->target.gpg_key_id)) != 0 ||
        config_switch_read_field(
            &cursor, end, "effective_scope",
            &value, &value_length) != 0 ||
        config_switch_parse_scope(
            value, value_length, &model->effective_scope) != 0 ||
        config_switch_read_field(
            &cursor, end, "destination_count",
            &value, &value_length) != 0 ||
        config_switch_parse_uintmax(
            value, value_length, CONFIG_SWITCH_DESTINATION_MAX,
            &destination_count) != 0 ||
        destination_count == 0U) {
        secure_zero_memory(model, sizeof(*model));
        config_switch_guard_malformed(
            "noncanonical or incomplete fields");
        return -1;
    }
    model->destination_count = (size_t)destination_count;
    for (size_t i = 0U; i < model->destination_count; i++) {
        publication_record_t *destination = &model->destinations[i];
        char field[64];

        publication_record_init(destination);
        if ((size_t)snprintf(
                field, sizeof(field), "destination_%zu_scope", i) >=
                sizeof(field) ||
            config_switch_read_field(
                &cursor, end, field, &value, &value_length) != 0 ||
            config_switch_parse_publication_scope(
                value, value_length, &destination->scope) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_config_path", i) >= sizeof(field) ||
            config_switch_read_field(
                &cursor, end, field, &value, &value_length) != 0 ||
            config_switch_decode_hex(
                value, value_length, destination->config_path,
                sizeof(destination->config_path)) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_config_parent", i) >= sizeof(field) ||
            config_switch_read_field(
                &cursor, end, field, &value, &value_length) != 0 ||
            config_switch_parse_identity(
                value, value_length,
                &destination->config_parent) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_repository_path", i) >= sizeof(field) ||
            config_switch_read_field(
                &cursor, end, field, &value, &value_length) != 0 ||
            config_switch_decode_hex(
                value, value_length, destination->repository_path,
                sizeof(destination->repository_path)) != 0 ||
            (size_t)snprintf(
                field, sizeof(field),
                "destination_%zu_repository", i) >= sizeof(field) ||
            config_switch_read_field(
                &cursor, end, field, &value, &value_length) != 0 ||
            config_switch_parse_identity(
                value, value_length,
                &destination->repository) != 0) {
            secure_zero_memory(model, sizeof(*model));
            return config_switch_guard_malformed(
                "noncanonical or incomplete destination fields");
        }
    }
    if (config_switch_read_field(
            &cursor, end, "source_witness_length",
            &value, &value_length) != 0 ||
        config_switch_parse_uintmax(
            value, value_length, CONFIG_DOCUMENT_MAX_SIZE,
            &witness_length) != 0 ||
        witness_length == 0U ||
        witness_length != model->source_generation.size ||
        witness_length > (uintmax_t)(end - cursor)) {
        secure_zero_memory(model, sizeof(*model));
        return config_switch_guard_malformed(
            "invalid source witness length");
    }
    *source_witness_length = (size_t)witness_length;
    if ((size_t)(end - cursor) != *source_witness_length) {
        secure_zero_memory(model, sizeof(*model));
        *source_witness_length = 0U;
        return config_switch_guard_malformed(
            "noncanonical or trailing source witness");
    }
    *source_witness = malloc(*source_witness_length);
    if (!*source_witness) {
        secure_zero_memory(model, sizeof(*model));
        *source_witness_length = 0U;
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch guard source witness");
        return -1;
    }
    memcpy(*source_witness, cursor, *source_witness_length);
    model->target.id = (uint32_t)account_id;
    model->target.incarnation_persisted = true;
    if (!config_switch_guard_model_valid(model) ||
        config_switch_guard_serialize(
            model, *source_witness, *source_witness_length,
            &canonical, &canonical_length) != 0 ||
        canonical_length != length ||
        memcmp(canonical, data, length) != 0) {
        if (canonical) {
            secure_zero_memory(canonical, canonical_length);
            free(canonical);
        }
        secure_zero_memory(
            *source_witness, *source_witness_length);
        free(*source_witness);
        *source_witness = NULL;
        *source_witness_length = 0U;
        secure_zero_memory(model, sizeof(*model));
        return config_switch_guard_malformed(
            "noncanonical field value");
    }
    secure_zero_memory(canonical, canonical_length);
    free(canonical);
    return 0;
}

static int config_switch_guard_open_directory(
    const char *config_path, bool allow_absent,
    char directory[MAX_PATH_LEN], struct stat *directory_identity,
    int *directory_fd) {
    struct stat opened;
    int fd;

    if (!config_path || !directory || !directory_identity ||
        !directory_fd) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard directory arguments");
        return -1;
    }
    *directory_fd = -1;
    if (config_directory_for_path(
            config_path, directory, MAX_PATH_LEN) != 0) {
        return -1;
    }
    errno = 0;
    if (lstat(directory, directory_identity) != 0) {
        if (allow_absent && errno == ENOENT) return 1;
        set_system_error(
            ERR_FILE_IO,
            "Cannot inspect switch guard directory: %s", directory);
        return -1;
    }
    if (!config_metadata_dir_is_safe(directory_identity)) {
        errno = EACCES;
        set_error(
            ERR_PERMISSION_DENIED,
            "Switch guard directory is not private and self-owned: %s",
            directory);
        return -1;
    }
    fd = open(
        directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_dir_is_safe(&opened) ||
        !config_metadata_same_file(directory_identity, &opened) ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        int saved_errno = errno ? errno : ESTALE;

        if (fd >= 0) close(fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot pin switch guard directory: %s", directory);
        return -1;
    }
    *directory_fd = fd;
    return 0;
}

static int config_switch_guard_config_name(
    const char *config_path, const char **config_name) {
    const char *slash;

    if (!config_path || !config_path[0] || !config_name) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(config_path, '/');
    *config_name = slash ? slash + 1U : config_path;
    if ((*config_name)[0] == '\0' || strchr(*config_name, '/')) {
        errno = EINVAL;
        set_error(ERR_INVALID_PATH,
                  "Cannot derive the switch guard config filename");
        return -1;
    }
    return 0;
}

static bool config_switch_source_identity_matches_after_exact_proof(
    const publication_identity_t *before,
    const publication_identity_t *after) {
    return before && after &&
           (publication_identity_equal(before, after) ||
            (before->present && after->present &&
             before->device == after->device &&
             before->inode == after->inode &&
             before->mode == after->mode &&
             before->uid == after->uid &&
             before->gid == after->gid &&
             before->link_count == after->link_count &&
             before->size == after->size &&
             before->mtime_seconds == after->mtime_seconds &&
             before->mtime_nanoseconds == after->mtime_nanoseconds &&
             (before->ctime_seconds != after->ctime_seconds ||
              before->ctime_nanoseconds != after->ctime_nanoseconds)));
}

static int config_switch_guard_source_observe_at(
    int directory_fd, const char *config_name,
    publication_identity_t *observed) {
    struct stat named;
    int saved_errno = ESTALE;

    if (directory_fd < 0 || !config_name || !observed) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(
            directory_fd, config_name, &named,
            AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = config_is_namespace_change_errno(errno)
                          ? ESTALE
                          : (errno ? errno : EIO);
        goto observe_fail;
    }
    if (!config_metadata_file_is_safe(&named, true)) {
        saved_errno = ESTALE;
        goto observe_fail;
    }
    publication_identity_from_stat(observed, &named);
    return 0;

observe_fail:
    errno = saved_errno;
    set_system_error(
        ERR_FILE_IO,
        "Switch recovery source generation is no longer current");
    return -1;
}

static int config_switch_guard_source_matches_at(
    int directory_fd, const char *config_name,
    const publication_identity_t *expected,
    const unsigned char *expected_data, size_t expected_length,
    publication_identity_t *accepted) {
    struct stat named_before;
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    struct stat named_final;
    publication_identity_t observed;
    unsigned char buffer[4096];
    unsigned char trailing;
    ssize_t trailing_count;
    size_t offset = 0U;
    int fd = -1;
    int saved_errno = ESTALE;

    if (directory_fd < 0 || !config_name || !expected ||
        !expected->present ||
        (!expected_data && expected_length != 0U)) {
        errno = EINVAL;
        return -1;
    }
    if (!expected_data) {
        if (config_switch_guard_source_observe_at(
                directory_fd, config_name, &observed) != 0) {
            return -1;
        }
        if (!publication_identity_equal(expected, &observed)) {
            goto source_fail;
        }
        if (accepted) *accepted = observed;
        secure_zero_memory(buffer, sizeof(buffer));
        return 0;
    }
    if (fstatat(
            directory_fd, config_name, &named_before,
            AT_SYMLINK_NOFOLLOW) != 0) {
        saved_errno = config_is_namespace_change_errno(errno)
                          ? ESTALE
                          : (errno ? errno : EIO);
        goto source_fail;
    }
    if (!config_metadata_file_is_safe(&named_before, true)) {
        saved_errno = ESTALE;
        goto source_fail;
    }
    publication_identity_from_stat(&observed, &named_before);
    if (!config_switch_source_identity_matches_after_exact_proof(
            expected, &observed) ||
        observed.size != expected_length) {
        goto source_fail;
    }
    fd = openat(
        directory_fd, config_name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0) {
        saved_errno = config_is_namespace_change_errno(errno)
                          ? ESTALE
                          : (errno ? errno : EIO);
        goto source_fail;
    }
    if (!config_metadata_file_is_safe(&opened, true) ||
        !config_metadata_matches_after_exact_content_proof(
            &named_before, &opened)) {
        saved_errno = errno ? errno : ESTALE;
        goto source_fail;
    }
    while (offset < expected_length) {
        size_t length = expected_length - offset;

        if (length > sizeof(buffer)) length = sizeof(buffer);
        if (!config_pread_full(
                fd, buffer, length, (off_t)offset) ||
            memcmp(buffer, expected_data + offset, length) != 0) {
            saved_errno = errno ? errno : ESTALE;
            goto source_fail;
        }
        offset += length;
    }
    do {
        trailing_count = pread(
            fd, &trailing, 1, (off_t)expected_length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count != 0) {
        saved_errno = trailing_count < 0
                          ? (errno ? errno : EIO)
                          : ESTALE;
        goto source_fail;
    }
    if (fstat(fd, &descriptor_after) != 0 ||
        fstatat(
            directory_fd, config_name, &named_after,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&descriptor_after, true) ||
        !config_metadata_file_is_safe(&named_after, true) ||
        !config_metadata_matches_after_exact_content_proof(
            &opened, &descriptor_after) ||
        !config_metadata_matches_after_exact_content_proof(
            &opened, &named_after) ||
        !config_metadata_matches_after_exact_content_proof(
            &descriptor_after, &named_after)) {
        saved_errno = errno ? errno : ESTALE;
        goto source_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        saved_errno = errno ? errno : EIO;
        goto source_fail;
    }
    fd = -1;
    if (fstatat(
            directory_fd, config_name, &named_final,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named_final, true) ||
        !config_metadata_matches_after_exact_content_proof(
            &named_after, &named_final)) {
        saved_errno = errno ? errno : ESTALE;
        goto source_fail;
    }
    publication_identity_from_stat(&observed, &named_final);
    if (!config_switch_source_identity_matches_after_exact_proof(
            expected, &observed)) {
        saved_errno = ESTALE;
        goto source_fail;
    }
    if (accepted) *accepted = observed;
    secure_zero_memory(buffer, sizeof(buffer));
    return 0;

source_fail:
    if (fd >= 0) close(fd);
    secure_zero_memory(buffer, sizeof(buffer));
    errno = saved_errno;
    set_system_error(
        ERR_FILE_IO,
        "Switch recovery source generation is no longer current");
    return -1;
}

static int config_switch_guard_stage_state_at(
    int directory_fd, bool *present, struct stat *identity) {
    struct stat named;

    if (directory_fd < 0 || !present) {
        errno = EINVAL;
        return -1;
    }
    *present = true;
    if (identity) memset(identity, 0, sizeof(*identity));
    errno = 0;
    if (fstatat(
            directory_fd, CONFIG_SWITCH_STAGE_NAME, &named,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *present = false;
            return 0;
        }
        return -1;
    }
    if (!config_metadata_file_is_safe(&named, true) ||
        named.st_size < 0 ||
        (uintmax_t)named.st_size >
            CONFIG_SWITCH_GUARD_MAX_BYTES) {
        errno = EACCES;
        return -1;
    }
    if (identity) *identity = named;
    return 0;
}

static int config_switch_guard_optional_stat_at(
    int directory_fd, const char *name, bool *present,
    struct stat *identity) {
    if (directory_fd < 0 || !name || !present || !identity) {
        errno = EINVAL;
        return -1;
    }
    *present = true;
    memset(identity, 0, sizeof(*identity));
    errno = 0;
    if (fstatat(
            directory_fd, name, identity,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *present = false;
            return 0;
        }
        return -1;
    }
    return 0;
}

static bool config_switch_guard_file_has_link_count(
    const struct stat *identity, nlink_t link_count) {
    return identity && S_ISREG(identity->st_mode) &&
           identity->st_uid == getuid() &&
           (identity->st_mode & 0777) == PERM_USER_RW &&
           identity->st_nlink == link_count;
}

/* A fixed stage can exist only before accounts_switch_impl() is allowed to
 * mutate Git/SSH/GPG. The portable no-replace fallback can also be interrupted
 * between linkat(stage, marker) and unlinkat(stage), producing two names for
 * the same private inode. Classify only stable, exact namespace shapes here;
 * every unsafe, changing, or distinct-name pair remains fail-closed. */
static int config_switch_guard_preintent_snapshot_at(
    int directory_fd, config_switch_preintent_snapshot_t *snapshot) {
    bool stage_before_present;
    bool marker_before_present;
    bool stage_after_present;
    bool marker_after_present;
    struct stat stage_before;
    struct stat marker_before;
    struct stat stage_after;
    struct stat marker_after;

    if (directory_fd < 0 || !snapshot) {
        errno = EINVAL;
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    if (config_switch_guard_optional_stat_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            &stage_before_present, &stage_before) != 0 ||
        config_switch_guard_optional_stat_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &marker_before_present, &marker_before) != 0 ||
        config_switch_guard_optional_stat_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            &stage_after_present, &stage_after) != 0 ||
        config_switch_guard_optional_stat_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &marker_after_present, &marker_after) != 0) {
        goto preintent_fail;
    }
    if (stage_before_present != stage_after_present ||
        marker_before_present != marker_after_present ||
        (stage_before_present &&
         !config_metadata_snapshot_same(
             &stage_before, &stage_after)) ||
        (marker_before_present &&
         !config_metadata_snapshot_same(
             &marker_before, &marker_after))) {
        errno = ESTALE;
        goto preintent_fail;
    }
    if (!stage_before_present) {
        snapshot->kind = CONFIG_SWITCH_PREINTENT_NONE;
        return 0;
    }
    if (!marker_before_present) {
        if (!config_switch_guard_file_has_link_count(
                &stage_before, (nlink_t)1)) {
            errno = EACCES;
            goto preintent_fail;
        }
        snapshot->kind =
            CONFIG_SWITCH_PREINTENT_STAGE_ONLY;
        snapshot->stage_identity = stage_before;
        return 0;
    }
    if (config_switch_guard_file_has_link_count(
            &stage_before, (nlink_t)2) &&
        config_switch_guard_file_has_link_count(
            &marker_before, (nlink_t)2) &&
        config_metadata_same_file(
            &stage_before, &marker_before)) {
        snapshot->kind = CONFIG_SWITCH_PREINTENT_EXACT_PAIR;
    } else if (config_switch_guard_file_has_link_count(
                   &stage_before, (nlink_t)1) &&
               config_switch_guard_file_has_link_count(
                   &marker_before, (nlink_t)1) &&
               !config_metadata_same_file(
                   &stage_before, &marker_before)) {
        /* Crash-safe portable normalization replaces the canonical marker
         * before retiring the old linked stage. The resulting distinct,
         * private one-link pair is admitted only as a candidate; reconciliation
         * still proves the complete byte image equal before deleting stage. */
        snapshot->kind =
            CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR;
    } else {
        errno = EACCES;
        goto preintent_fail;
    }
    snapshot->stage_identity = stage_before;
    snapshot->marker_identity = marker_before;
    return 0;

preintent_fail:
    if (errno == 0) errno = ESTALE;
    set_system_error(
        ERR_FILE_IO,
        "Switch transition namespace is unsafe or changed");
    return -1;
}

#if !defined(__FreeBSD__)
/* Linux and Darwin cannot unlink one pathname through a pinned descriptor.
 * Before replacing the portable linkat() interruption pair, copy only a
 * stable, exact two-link marker generation. The lifecycle lock excludes
 * cooperating writers; repeated pathname proofs reject namespace
 * substitution by a bypassing writer. */
static int config_switch_guard_read_exact_pair_at(
    int directory_fd,
    const config_switch_preintent_snapshot_t *expected,
    unsigned char **data, size_t *length) {
    config_switch_guard_model_t model;
    struct stat opened;
    struct stat descriptor_after;
    struct stat stage_after;
    struct stat marker_after;
    unsigned char *buffer = NULL;
    unsigned char *source_witness = NULL;
    size_t source_witness_length = 0U;
    unsigned char trailing;
    ssize_t trailing_count;
    int fd = -1;
    int failure_errno = ESTALE;

    if (directory_fd < 0 || !expected ||
        expected->kind != CONFIG_SWITCH_PREINTENT_EXACT_PAIR ||
        !data || !length) {
        errno = EINVAL;
        return -1;
    }
    *data = NULL;
    *length = 0U;
    memset(&model, 0, sizeof(model));
    if (expected->marker_identity.st_size <= 0 ||
        (uintmax_t)expected->marker_identity.st_size >
            CONFIG_SWITCH_GUARD_MAX_BYTES) {
        failure_errno = EACCES;
        goto pair_fail;
    }
    *length = (size_t)expected->marker_identity.st_size;
    buffer = malloc(*length);
    if (!buffer) {
        failure_errno = ENOMEM;
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch pre-intent recovery buffer");
        goto pair_fail_preserve_error;
    }
    fd = openat(
        directory_fd, CONFIG_SWITCH_GUARD_NAME,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_switch_guard_file_has_link_count(
            &opened, (nlink_t)2) ||
        !config_metadata_snapshot_same(
            &expected->marker_identity, &opened) ||
        !config_pread_full(fd, buffer, *length, 0)) {
        failure_errno = errno ? errno : ESTALE;
        goto pair_fail;
    }
    do {
        errno = 0;
        trailing_count = pread(fd, &trailing, 1, (off_t)*length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count != 0 ||
        fstat(fd, &descriptor_after) != 0 ||
        fstatat(
            directory_fd, CONFIG_SWITCH_STAGE_NAME, &stage_after,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(
            directory_fd, CONFIG_SWITCH_GUARD_NAME, &marker_after,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_snapshot_same(&opened, &descriptor_after) ||
        !config_metadata_snapshot_same(&opened, &stage_after) ||
        !config_metadata_snapshot_same(&opened, &marker_after) ||
        config_switch_guard_parse(
            buffer, *length, &model, &source_witness,
            &source_witness_length) != 0) {
        failure_errno = errno ? errno : ESTALE;
        goto pair_fail_preserve_error;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto pair_fail;
    }
    fd = -1;
    secure_zero_memory(source_witness, source_witness_length);
    free(source_witness);
    source_witness = NULL;
    source_witness_length = 0U;
    *data = buffer;
    secure_zero_memory(&model, sizeof(model));
    return 0;

pair_fail:
    set_system_error(
        ERR_FILE_IO,
        "Cannot read the exact switch pre-intent recovery pair");
pair_fail_preserve_error:
    if (fd >= 0) (void)close(fd);
    if (buffer) {
        secure_zero_memory(buffer, *length);
        free(buffer);
    }
    if (source_witness) {
        secure_zero_memory(source_witness, source_witness_length);
        free(source_witness);
    }
    *data = NULL;
    *length = 0U;
    secure_zero_memory(&model, sizeof(model));
    errno = failure_errno;
    return -1;
}

#endif

static int config_switch_guard_name_stable_at(
    int directory_fd, const char *name, bool absent,
    struct stat *expected, const unsigned char *expected_data,
    size_t expected_length) {
    struct stat named;
    struct stat reproved;

    errno = 0;
    if (fstatat(
            directory_fd, name, &named,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (absent && errno == ENOENT) return 0;
        errno = config_is_namespace_change_errno(errno)
                    ? ESTALE
                    : (errno ? errno : EIO);
        return -1;
    }
    if (absent || !expected || !expected_data || expected_length == 0U ||
        !config_metadata_file_is_safe(&named, true)) {
        errno = ESTALE;
        return -1;
    }
    if (config_metadata_snapshot_same(expected, &named)) {
        *expected = named;
        return 0;
    }
    if (!config_metadata_ctime_only_change(expected, &named) ||
        config_reprove_published_file_at(
            directory_fd, name, expected, expected_data, expected_length,
            &reproved) != 0) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    *expected = reproved;
    return 0;
}

static int config_switch_guard_read_named_at(
    int directory_fd, const char *name, bool *absent,
    unsigned char **data, size_t *length, struct stat *identity,
    config_switch_guard_model_t *model,
    unsigned char **source_witness, size_t *source_witness_length) {
    struct stat opened;
    struct stat descriptor_after;
    struct stat named_after;
    struct stat proof_expected;
    struct stat reproved;
    unsigned char *buffer = NULL;
    unsigned char trailing;
    ssize_t trailing_count;
    int fd = -1;
    int failure_errno = ESTALE;
    bool proof_converged = false;

    if (directory_fd < 0 || !name || name[0] == '\0' ||
        strchr(name, '/') || !absent || !data || !length ||
        !identity || !model || !source_witness ||
        !source_witness_length) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard read arguments");
        return -1;
    }
    *absent = false;
    *data = NULL;
    *length = 0U;
    *source_witness = NULL;
    *source_witness_length = 0U;
    memset(identity, 0, sizeof(*identity));
    memset(model, 0, sizeof(*model));

    fd = openat(
        directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            *absent = true;
            return 0;
        }
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    if (fstat(fd, &opened) != 0) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&opened, true) ||
        opened.st_size <= 0 ||
        (uintmax_t)opened.st_size >
            CONFIG_SWITCH_GUARD_MAX_BYTES) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    *length = (size_t)opened.st_size;
    buffer = malloc(*length);
    if (!buffer) {
        failure_errno = ENOMEM;
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate switch guard read buffer");
        goto read_fail_preserve_error;
    }
    if (!config_pread_full(fd, buffer, *length, 0)) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    do {
        errno = 0;
        trailing_count = pread(fd, &trailing, 1, (off_t)*length);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count != 0 ||
        fstat(fd, &descriptor_after) != 0 ||
        fstatat(
            directory_fd, name, &named_after,
            AT_SYMLINK_NOFOLLOW) != 0) {
        failure_errno = errno ? errno : ESTALE;
        goto read_fail;
    }
    if (!config_metadata_file_is_safe(&descriptor_after, true) ||
        !config_metadata_file_is_safe(&named_after, true) ||
        !config_metadata_snapshot_same(&opened, &descriptor_after) ||
        !config_metadata_snapshot_same(
            &descriptor_after, &named_after)) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    if (config_switch_guard_parse(
            buffer, *length, model, source_witness,
            source_witness_length) != 0) {
        failure_errno = errno ? errno : EINVAL;
        goto read_fail_preserve_error;
    }
    if (SWITCH_GUARD_TEST_CHECKPOINT(
            SWITCH_GUARD_READ_AFTER_EXACT_DESCRIPTOR_PROOF,
            directory_fd) != 0) {
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        failure_errno = errno ? errno : EIO;
        goto read_fail;
    }
    fd = -1;

    /* Anchor every post-close refresh to the exact bytes read through the
     * original descriptor. FreeBSD UFS may reveal ctime in more than one
     * delayed step, so converge only across ctime-only successors and repeat
     * the complete byte proof at each step. */
    proof_expected = descriptor_after;
    for (size_t attempt = 0U;
         attempt < CONFIG_SWITCH_SOURCE_CONVERGENCE_MAX;
         attempt++) {
        if (config_reprove_published_file_at(
                directory_fd, name, &proof_expected,
                buffer, *length, &reproved) != 0) {
            failure_errno = errno ? errno : ESTALE;
            goto read_fail;
        }
        if (config_metadata_snapshot_same(
                &proof_expected, &reproved)) {
            proof_converged = true;
            break;
        }
        if (!config_metadata_ctime_only_change(
                &proof_expected, &reproved)) {
            failure_errno = ESTALE;
            goto read_fail;
        }
        proof_expected = reproved;
    }
    if (!proof_converged) {
        failure_errno = ESTALE;
        goto read_fail;
    }
    *identity = reproved;
    *data = buffer;
    return 0;

read_fail:
    errno = failure_errno;
    set_system_error(
        ERR_FILE_IO,
        "Cannot read a stable private switch recovery name: %s",
        name);
read_fail_preserve_error:
    if (fd >= 0) close(fd);
    if (buffer) {
        secure_zero_memory(buffer, *length);
        free(buffer);
    }
    if (*source_witness) {
        secure_zero_memory(
            *source_witness, *source_witness_length);
        free(*source_witness);
    }
    *source_witness = NULL;
    *source_witness_length = 0U;
    *data = NULL;
    *length = 0U;
    secure_zero_memory(model, sizeof(*model));
    errno = failure_errno;
    return -1;
}

static void config_switch_guard_snapshot_clear(
    config_switch_guard_snapshot_t *snapshot) {
    if (!snapshot) return;
    if (snapshot->marker_data) {
        secure_zero_memory(
            snapshot->marker_data, snapshot->marker_length);
        free(snapshot->marker_data);
    }
    if (snapshot->source_witness) {
        secure_zero_memory(
            snapshot->source_witness,
            snapshot->source_witness_length);
        free(snapshot->source_witness);
    }
    secure_zero_memory(snapshot, sizeof(*snapshot));
}

static int config_switch_guard_snapshot_read_at(
    int directory_fd, config_switch_guard_snapshot_t *snapshot) {
    struct stat stage_after;
    bool stage_after_present = false;

    if (directory_fd < 0 || !snapshot) {
        errno = EINVAL;
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    if (config_switch_guard_stage_state_at(
            directory_fd, &snapshot->stage_present,
            &snapshot->stage_identity) != 0 ||
        config_switch_guard_read_named_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &snapshot->marker_absent,
            &snapshot->marker_data, &snapshot->marker_length,
            &snapshot->marker_identity,
            &snapshot->marker_model,
            &snapshot->source_witness,
            &snapshot->source_witness_length) != 0 ||
        SWITCH_GUARD_TEST_CHECKPOINT(
            SWITCH_GUARD_SNAPSHOT_AFTER_MARKER_READ,
            directory_fd) != 0 ||
        config_switch_guard_name_stable_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            snapshot->marker_absent,
            &snapshot->marker_identity, snapshot->marker_data,
            snapshot->marker_length) != 0 ||
        config_switch_guard_stage_state_at(
            directory_fd, &stage_after_present,
            &stage_after) != 0) {
        goto snapshot_fail;
    }
    if (snapshot->stage_present != stage_after_present ||
        (snapshot->stage_present &&
         !config_metadata_snapshot_same(
             &snapshot->stage_identity, &stage_after))) {
        errno = ESTALE;
        goto snapshot_fail;
    }
    /* Expected-absent namespace probes use ENOENT internally. Do not leak
     * that stale success-path value into a later generation-mismatch error. */
    errno = 0;
    return 0;

snapshot_fail:
    config_switch_guard_snapshot_clear(snapshot);
    return -1;
}

static int config_switch_guard_normalized_pair_equal_at(
    int directory_fd,
    const config_switch_preintent_snapshot_t *expected,
    bool *equal) {
    config_switch_guard_model_t *stage_model = NULL;
    config_switch_guard_model_t *marker_model = NULL;
    struct stat stage_identity;
    struct stat marker_identity;
    unsigned char *stage_data = NULL;
    unsigned char *marker_data = NULL;
    unsigned char *stage_witness = NULL;
    unsigned char *marker_witness = NULL;
    size_t stage_length = 0U;
    size_t marker_length = 0U;
    size_t stage_witness_length = 0U;
    size_t marker_witness_length = 0U;
    bool stage_absent = false;
    bool marker_absent = false;
    int result = -1;

    if (directory_fd < 0 || !expected || !equal ||
        expected->kind != CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR) {
        errno = EINVAL;
        return -1;
    }
    *equal = false;
    stage_model = calloc(1U, sizeof(*stage_model));
    marker_model = calloc(1U, sizeof(*marker_model));
    if (!stage_model || !marker_model) {
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch normalization proof state");
        goto pair_done;
    }
    if (config_switch_guard_read_named_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            &stage_absent, &stage_data, &stage_length,
            &stage_identity, stage_model,
            &stage_witness, &stage_witness_length) != 0 ||
        config_switch_guard_read_named_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &marker_absent, &marker_data, &marker_length,
            &marker_identity, marker_model,
            &marker_witness, &marker_witness_length) != 0 ||
        stage_absent || marker_absent ||
        !config_metadata_matches_after_exact_content_proof(
            &expected->stage_identity, &stage_identity) ||
        !config_metadata_matches_after_exact_content_proof(
            &expected->marker_identity, &marker_identity)) {
        if (errno == 0) errno = ESTALE;
        goto pair_done;
    }
    *equal = stage_length == marker_length &&
             memcmp(stage_data, marker_data, stage_length) == 0;
    result = 0;

pair_done:
    if (stage_data) {
        secure_zero_memory(stage_data, stage_length);
        free(stage_data);
    }
    if (marker_data) {
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
    }
    if (stage_witness) {
        secure_zero_memory(stage_witness, stage_witness_length);
        free(stage_witness);
    }
    if (marker_witness) {
        secure_zero_memory(marker_witness, marker_witness_length);
        free(marker_witness);
    }
    if (stage_model) {
        secure_zero_memory(stage_model, sizeof(*stage_model));
        free(stage_model);
    }
    if (marker_model) {
        secure_zero_memory(marker_model, sizeof(*marker_model));
        free(marker_model);
    }
    return result;
}

static int config_switch_guard_reconcile_distinct_pair_at(
    int directory_fd,
    const config_switch_preintent_snapshot_t *expected,
    struct stat *marker_identity) {
    config_switch_guard_model_t *stage_model = NULL;
    config_switch_guard_model_t *marker_model = NULL;
    struct stat stage_identity;
    struct stat current_marker_identity;
    unsigned char *stage_data = NULL;
    unsigned char *marker_data = NULL;
    unsigned char *stage_witness = NULL;
    unsigned char *marker_witness = NULL;
    size_t stage_length = 0U;
    size_t marker_length = 0U;
    size_t stage_witness_length = 0U;
    size_t marker_witness_length = 0U;
    bool stage_absent = false;
    bool marker_absent = false;
    int failure_errno = ESTALE;
    int result = -1;

    if (directory_fd < 0 || !expected ||
        expected->kind != CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR ||
        !marker_identity) {
        errno = EINVAL;
        return -1;
    }
    stage_model = calloc(1U, sizeof(*stage_model));
    marker_model = calloc(1U, sizeof(*marker_model));
    if (!stage_model || !marker_model) {
        failure_errno = ENOMEM;
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch pre-intent reconciliation state");
        goto distinct_done;
    }
    memset(&stage_identity, 0, sizeof(stage_identity));
    memset(&current_marker_identity, 0, sizeof(current_marker_identity));
    if (config_switch_guard_read_named_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            &stage_absent, &stage_data, &stage_length,
            &stage_identity, stage_model,
            &stage_witness, &stage_witness_length) != 0 ||
        config_switch_guard_read_named_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &marker_absent, &marker_data, &marker_length,
            &current_marker_identity, marker_model,
            &marker_witness, &marker_witness_length) != 0 ||
        stage_absent || marker_absent ||
        !config_metadata_matches_after_exact_content_proof(
            &expected->stage_identity, &stage_identity) ||
        !config_metadata_matches_after_exact_content_proof(
            &expected->marker_identity,
            &current_marker_identity) ||
        stage_length != marker_length ||
        memcmp(stage_data, marker_data, stage_length) != 0) {
        goto distinct_fail;
    }

    if (config_retire_exact_name_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            &stage_identity, stage_data, stage_length,
            CONFIG_SWITCH_SETTLED_PREFIX) != 0) {
        goto distinct_fail;
    }
    *marker_identity = current_marker_identity;
    result = 0;
    goto distinct_done;

distinct_fail:
    failure_errno = errno ? errno : ESTALE;
    errno = failure_errno;
    set_system_error(
        ERR_FILE_IO,
        "Cannot reconcile the exact switch normalization pair");

distinct_done:
    if (stage_data) {
        secure_zero_memory(stage_data, stage_length);
        free(stage_data);
    }
    if (marker_data) {
        secure_zero_memory(marker_data, marker_length);
        free(marker_data);
    }
    if (stage_witness) {
        secure_zero_memory(stage_witness, stage_witness_length);
        free(stage_witness);
    }
    if (marker_witness) {
        secure_zero_memory(marker_witness, marker_witness_length);
        free(marker_witness);
    }
    if (stage_model) {
        secure_zero_memory(stage_model, sizeof(*stage_model));
        free(stage_model);
    }
    if (marker_model) {
        secure_zero_memory(marker_model, sizeof(*marker_model));
        free(marker_model);
    }
    if (result != 0) errno = failure_errno;
    return result;
}

static int config_switch_guard_reconcile_preintent_at(
    int directory_fd, int lock_fd, const char *directory,
    const struct stat *directory_identity) {
    config_switch_preintent_snapshot_t before;
    config_switch_preintent_snapshot_t after;
    struct stat marker_after;
#if !defined(__FreeBSD__)
    struct stat normalize_identity;
    struct stat normalize_named;
    unsigned char *pair_data = NULL;
    size_t pair_length = 0U;
    bool normalize_present = false;
    bool normalize_created = false;
    bool normalize_identity_known = false;
#endif
    bool marker_after_present = false;
    int failure_errno = ESTALE;

    if (directory_fd < 0 || lock_fd < 0 || !directory ||
        !directory_identity) {
        errno = EINVAL;
        return -1;
    }
    if (config_switch_guard_preintent_snapshot_at(
            directory_fd, &before) != 0) {
        return -1;
    }
    if (before.kind == CONFIG_SWITCH_PREINTENT_NONE) return 0;
    if (verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Cannot prove switch pre-intent cleanup authority");
        return -1;
    }
#if !defined(__FreeBSD__)
    if (before.kind == CONFIG_SWITCH_PREINTENT_EXACT_PAIR &&
        config_switch_guard_read_exact_pair_at(
            directory_fd, &before, &pair_data, &pair_length) != 0) {
        return -1;
    }
#endif
#if !defined(__FreeBSD__)
    if (before.kind == CONFIG_SWITCH_PREINTENT_EXACT_PAIR) {
        if (config_switch_guard_optional_stat_at(
                directory_fd, CONFIG_SWITCH_NORMALIZE_NAME,
                &normalize_present, &normalize_named) != 0) {
            failure_errno = errno ? errno : EIO;
            goto reconcile_fail;
        }
        if (!normalize_present) {
            if (config_switch_guard_named_write_at(
                    directory_fd, CONFIG_SWITCH_NORMALIZE_NAME,
                    pair_data, pair_length, &normalize_identity,
                    &normalize_created,
                    &normalize_identity_known) != 0 ||
                !normalize_identity_known) {
                failure_errno = errno ? errno : EIO;
                goto reconcile_fail;
            }
        } else {
            normalize_identity = normalize_named;
            normalize_identity_known = true;
            if (!config_switch_guard_file_has_link_count(
                    &normalize_identity, (nlink_t)1) ||
                config_reprove_published_file_at(
                    directory_fd, CONFIG_SWITCH_NORMALIZE_NAME,
                    &normalize_identity, pair_data, pair_length,
                    &normalize_identity) != 0) {
                failure_errno = errno ? errno : ESTALE;
                goto reconcile_fail;
            }
        }
        if (fsync(directory_fd) != 0 ||
            SWITCH_GUARD_TEST_CHECKPOINT(
                SWITCH_GUARD_RECONCILE_AFTER_NORMALIZE_SYNC,
                directory_fd) != 0 ||
            config_switch_guard_preintent_snapshot_at(
                directory_fd, &after) != 0 ||
            after.kind != CONFIG_SWITCH_PREINTENT_EXACT_PAIR ||
            !config_metadata_same_file(
                &before.stage_identity, &after.stage_identity) ||
            !config_metadata_same_file(
                &before.marker_identity, &after.marker_identity) ||
            renameat(
                directory_fd, CONFIG_SWITCH_NORMALIZE_NAME,
                directory_fd, CONFIG_SWITCH_GUARD_NAME) != 0) {
            failure_errno = errno ? errno : ESTALE;
            goto reconcile_fail;
        }
        normalize_created = false;
        if (fsync(directory_fd) != 0 ||
            config_switch_guard_preintent_snapshot_at(
                directory_fd, &after) != 0 ||
            after.kind != CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR ||
            config_switch_guard_reconcile_distinct_pair_at(
                directory_fd, &after, &marker_after) != 0) {
            failure_errno = errno ? errno : ESTALE;
            goto reconcile_fail;
        }
    } else
#endif
    if (before.kind == CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR) {
        if (config_switch_guard_reconcile_distinct_pair_at(
                directory_fd, &before, &marker_after) != 0) {
            failure_errno = errno ? errno : ESTALE;
            goto reconcile_fail;
        }
    } else {
        if (config_retire_exact_name_at(
                directory_fd, CONFIG_SWITCH_STAGE_NAME,
                &before.stage_identity, NULL, 0U,
                CONFIG_SWITCH_SETTLED_PREFIX) != 0) {
            failure_errno = errno ? errno : EIO;
            goto reconcile_fail;
        }
    }
    if (fsync(directory_fd) != 0 ||
        config_switch_guard_preintent_snapshot_at(
            directory_fd, &after) != 0 ||
        after.kind != CONFIG_SWITCH_PREINTENT_NONE ||
        config_switch_guard_optional_stat_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &marker_after_present, &marker_after) != 0 ||
        verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        failure_errno = errno ? errno : ESTALE;
        goto reconcile_fail;
    }
    if (before.kind == CONFIG_SWITCH_PREINTENT_STAGE_ONLY) {
        if (marker_after_present) {
            failure_errno = ESTALE;
            goto reconcile_fail;
        }
    } else {
        bool marker_matches;

        if (before.kind == CONFIG_SWITCH_PREINTENT_EXACT_PAIR) {
#if !defined(__FreeBSD__)
            marker_matches = config_metadata_same_file(
                &normalize_identity, &marker_after);
#else
            marker_matches = config_metadata_same_file(
                &before.marker_identity, &marker_after);
#endif
        } else {
            marker_matches = config_metadata_same_file(
                &before.marker_identity, &marker_after);
        }

        if (!marker_after_present ||
            !config_switch_guard_file_has_link_count(
                &marker_after, (nlink_t)1) ||
            !marker_matches) {
            failure_errno = ESTALE;
            goto reconcile_fail;
        }
    }
#if !defined(__FreeBSD__)
    if (pair_data) {
        secure_zero_memory(pair_data, pair_length);
        free(pair_data);
    }
#endif
    return 0;

reconcile_fail:
#if !defined(__FreeBSD__)
    /* A durable normalize file is intentional retry state. If failure occurs
     * before rename, the original linked pair remains untouched and the next
     * lock holder reproves and reuses this exact byte image. */
    if (pair_data) {
        secure_zero_memory(pair_data, pair_length);
        free(pair_data);
    }
#endif
    errno = failure_errno;
    set_system_error(
        ERR_FILE_IO,
        "Cannot reconcile the exact switch pre-intent namespace");
    return -1;
}

static bool config_switch_destination_is_probe(
    const publication_record_t *destination) {
    return destination && destination->account_id == 0U &&
           destination->account_incarnation[0] == '\0' &&
           destination->capabilities == 0U &&
           config_switch_identity_is_zero(
               &destination->post_config) &&
           destination->gpg_fingerprint[0] == '\0' &&
           destination->gpg_selector[0] == '\0' &&
           destination->gpg_program[0] == '\0' &&
           config_switch_identity_is_zero(
               &destination->gpg_program_identity) &&
           !destination->gpg_signing_enabled &&
           destination->ssh_command[0] == '\0' &&
           destination->ssh_program[0] == '\0' &&
           config_switch_identity_is_zero(
               &destination->ssh_program_identity) &&
           destination->state == PUBLICATION_STATE_PUBLISHED;
}

static bool config_switch_destinations_are_probes(
    const publication_record_t *destinations, size_t destination_count) {
    if (!destinations || destination_count == 0U ||
        destination_count > CONFIG_SWITCH_DESTINATION_MAX) {
        return false;
    }
    for (size_t i = 0U; i < destination_count; i++) {
        if (!config_switch_destination_is_probe(&destinations[i])) {
            return false;
        }
    }
    return true;
}

static int config_switch_guard_model_from_request(
    const gitswitch_ctx_t *ctx, const account_t *target,
    git_scope_t effective_scope,
    const publication_record_t *destinations,
    size_t destination_count,
    config_switch_guard_model_t *model) {
    const account_t *loaded_target = NULL;
    struct stat current_source;
    size_t matches = 0U;

    if (!ctx || !target || !destinations || !model ||
        !ctx->config.source_generation_valid ||
        !config_switch_string_terminated(
            ctx->config.config_path,
            sizeof(ctx->config.config_path)) ||
        ctx->config.config_path[0] == '\0' ||
        ctx->account_count > MAX_ACCOUNTS ||
        !config_switch_string_terminated(
            target->incarnation, sizeof(target->incarnation)) ||
        !config_switch_string_terminated(target->name,
                                         sizeof(target->name)) ||
        !config_switch_string_terminated(target->email,
                                         sizeof(target->email)) ||
        !config_switch_string_terminated(target->ssh_key_path,
                                         sizeof(target->ssh_key_path)) ||
        !config_switch_string_terminated(
            target->ssh_host_alias, sizeof(target->ssh_host_alias)) ||
        !config_switch_string_terminated(
            target->ssh_hostname, sizeof(target->ssh_hostname)) ||
        !config_switch_string_terminated(target->gpg_key_id,
                                         sizeof(target->gpg_key_id)) ||
        !target->incarnation_persisted ||
        !config_scope_is_persistable(effective_scope) ||
        !config_switch_destinations_valid(
            effective_scope, destinations, destination_count) ||
        !config_switch_destinations_are_probes(
            destinations, destination_count) ||
        !config_metadata_file_is_safe(
            &ctx->config.source_generation, true) ||
        (!ctx->config.source_witness_valid &&
         !ctx->config.source_read_witness_valid) ||
        ctx->config.source_generation.st_size < 0 ||
        ctx->config.source_witness_length >
            sizeof(ctx->config.source_witness) ||
        (uintmax_t)ctx->config.source_generation.st_size !=
            ctx->config.source_witness_length) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard installation request");
        return -1;
    }
    /* Reuse the sole established ctime-only admission path: it re-proves every
     * retained source byte before accepting that narrow metadata step and
     * returns the exact generation observed by that proof. Do not perform a
     * second path lookup here: a replacement in that gap could otherwise bind
     * an unproved source generation to the already-loaded account model. */
    if (config_require_loaded_source_generation(
            ctx, ctx->config.config_path, &current_source) != 0) {
        if (errno == 0) errno = ESTALE;
        if (get_last_error()->message[0] == '\0') {
            set_system_error(
                ERR_FILE_IO,
                "Cannot bind switch recovery to the loaded accounts source");
        }
        return -1;
    }
    for (size_t i = 0U; i < ctx->account_count; i++) {
        if (config_switch_target_live_fields_equal(
                &ctx->accounts[i], target)) {
            loaded_target = &ctx->accounts[i];
            matches++;
        }
    }
    if (matches != 1U || !loaded_target ||
        !loaded_target->incarnation_persisted) {
        errno = ESTALE;
        set_error(
            ERR_CONFIG_INVALID,
            "Switch guard target is not one exact persisted account incarnation in the loaded source");
        return -1;
    }

    memset(model, 0, sizeof(*model));
    publication_identity_from_stat(
        &model->source_generation, &current_source);
    model->target.id = loaded_target->id;
    model->target.incarnation_persisted = true;
    model->target.preferred_scope = loaded_target->preferred_scope;
    model->target.ssh_enabled = loaded_target->ssh_enabled;
    model->target.gpg_enabled = loaded_target->gpg_enabled;
    model->target.gpg_signing_enabled =
        loaded_target->gpg_signing_enabled;
    if (safe_strncpy(
            model->target.incarnation, loaded_target->incarnation,
            sizeof(model->target.incarnation)) != 0 ||
        safe_strncpy(
            model->target.name, loaded_target->name,
            sizeof(model->target.name)) != 0 ||
        safe_strncpy(
            model->target.email, loaded_target->email,
            sizeof(model->target.email)) != 0 ||
        safe_strncpy(
            model->target.ssh_key_path,
            loaded_target->ssh_key_path,
            sizeof(model->target.ssh_key_path)) != 0 ||
        safe_strncpy(
            model->target.ssh_host_alias,
            loaded_target->ssh_host_alias,
            sizeof(model->target.ssh_host_alias)) != 0 ||
        safe_strncpy(
            model->target.ssh_hostname,
            loaded_target->ssh_hostname,
            sizeof(model->target.ssh_hostname)) != 0 ||
        safe_strncpy(
            model->target.gpg_key_id, loaded_target->gpg_key_id,
            sizeof(model->target.gpg_key_id)) != 0) {
        secure_zero_memory(model, sizeof(*model));
        return -1;
    }
    model->effective_scope = effective_scope;
    model->destination_count = destination_count;
    for (size_t i = 0U; i < destination_count; i++) {
        publication_record_t *stored = &model->destinations[i];
        const publication_record_t *destination = &destinations[i];

        publication_record_init(stored);
        stored->scope = destination->scope;
        stored->config_parent = destination->config_parent;
        stored->repository = destination->repository;
        if (safe_strncpy(
                stored->config_path, destination->config_path,
                sizeof(stored->config_path)) != 0 ||
            safe_strncpy(
                stored->repository_path,
                destination->repository_path,
                sizeof(stored->repository_path)) != 0) {
            secure_zero_memory(model, sizeof(*model));
            return -1;
        }
    }
    return 0;
}

static bool config_switch_guard_matches_handle(
    const config_switch_guard_t *guard,
    const config_switch_guard_snapshot_t *snapshot) {
    return guard && snapshot && !snapshot->stage_present &&
           !snapshot->marker_absent &&
           guard->marker_length == snapshot->marker_length &&
           memcmp(
               guard->marker_data, snapshot->marker_data,
               guard->marker_length) == 0 &&
           strcmp(
               guard->token,
               snapshot->marker_model.token) == 0 &&
           config_metadata_matches_after_exact_content_proof(
               &guard->marker_identity,
               &snapshot->marker_identity);
}

static void config_switch_guard_free(config_switch_guard_t *guard) {
    bool owned_here;

    if (!guard) return;
    owned_here = guard->owner_pid == getpid() &&
                 g_switch_guard_owner_pid == getpid();
    if (owned_here) {
        g_switch_guard_owner_pid = 0;
    } else if (g_switch_guard_owner_pid != getpid()) {
        /* A fork child must retire its inherited process-local owner token so
         * it can later acquire an independent guard. */
        g_switch_guard_owner_pid = 0;
    }
    /* The private-lock registry, not this opaque token alone, retains the
     * flock-bearing descriptor. A foreign-PID disposal resets that complete
     * inherited registry epoch without LOCK_UN and must not raw-close the
     * now-stale numeric token afterward. */
    if (guard->lock_fd >= 0) {
        if (owned_here) {
            unlock_private_file(guard->lock_fd);
        } else {
            runtime_state_lock_abandon_inherited();
        }
    }
    /* A same-directory reopen has identical inode metadata but is already
     * child-owned state. Only the creator process may raw-close this number. */
    if (owned_here && guard->directory_fd >= 0) {
        close(guard->directory_fd);
    }
    if (guard->marker_data) {
        secure_zero_memory(
            guard->marker_data, guard->marker_length);
        free(guard->marker_data);
    }
    if (guard->source_witness) {
        secure_zero_memory(
            guard->source_witness, guard->source_witness_length);
        free(guard->source_witness);
    }
    secure_zero_memory(guard, sizeof(*guard));
    free(guard);
}

static int config_switch_guard_make_handle(
    int directory_fd, int lock_fd, const char *directory,
    const char *config_name,
    const struct stat *directory_identity,
    const struct stat *marker_identity,
    unsigned char *marker_data, size_t marker_length,
    const unsigned char *source_witness, size_t source_witness_length,
    const config_switch_guard_model_t *model,
    const char token[ACCOUNT_INCARNATION_LEN], bool created,
    config_switch_guard_t **out) {
    config_switch_guard_t *guard;

    if (directory_fd < 0 || lock_fd < 0 || !directory || !config_name ||
        !directory_identity || !marker_identity || !marker_data ||
        marker_length == 0U || !source_witness ||
        source_witness_length == 0U ||
        source_witness_length > CONFIG_DOCUMENT_MAX_SIZE || !model ||
        model->source_generation.size != source_witness_length ||
        !account_incarnation_is_valid(token) ||
        !out || *out) {
        errno = EINVAL;
        return -1;
    }
    guard = calloc(1U, sizeof(*guard));
    if (!guard) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate switch guard handle");
        return -1;
    }
    guard->directory_fd = -1;
    guard->lock_fd = -1;
    guard->source_witness = malloc(source_witness_length);
    if (!guard->source_witness) {
        free(guard);
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot retain switch guard source witness");
        return -1;
    }
    memcpy(
        guard->source_witness, source_witness,
        source_witness_length);
    guard->source_witness_length = source_witness_length;
    if (safe_strncpy(
            guard->directory, directory,
            sizeof(guard->directory)) != 0 ||
        safe_strncpy(
            guard->config_name, config_name,
            sizeof(guard->config_name)) != 0) {
        secure_zero_memory(
            guard->source_witness, guard->source_witness_length);
        free(guard->source_witness);
        free(guard);
        return -1;
    }
    guard->directory_fd = directory_fd;
    guard->lock_fd = lock_fd;
    guard->owner_pid = getpid();
    guard->directory_identity = *directory_identity;
    guard->marker_identity = *marker_identity;
    guard->marker_data = marker_data;
    guard->marker_length = marker_length;
    guard->model = *model;
    memcpy(guard->token, token, sizeof(guard->token));
    guard->created = created;
    g_switch_guard_owner_pid = getpid();
    *out = guard;
    return 0;
}

static int config_switch_guard_named_write_at(
    int directory_fd, const char *name,
    const unsigned char *data, size_t length,
    struct stat *stage_identity, bool *stage_created,
    bool *stage_identity_known) {
    struct stat opened;
    struct stat after_write;
    struct stat named;
    size_t total = 0U;
    int fd = -1;
    int saved_errno;

    if (directory_fd < 0 || !name || name[0] == '\0' ||
        strchr(name, '/') != NULL || !data || length == 0U ||
        length > CONFIG_SWITCH_GUARD_MAX_BYTES || !stage_identity ||
        !stage_created || !stage_identity_known) {
        errno = EINVAL;
        return -1;
    }
    memset(stage_identity, 0, sizeof(*stage_identity));
    *stage_created = false;
    *stage_identity_known = false;
    fd = openat(
        directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        PERM_USER_RW);
    if (fd < 0) {
        saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot create private switch transition stage");
        return -1;
    }
    /* O_EXCL establishes that this call created one generation, but the
     * pathname is not cleanup authority until its descriptor identity has
     * been captured. If that first observation fails, retain the fixed stage
     * for the next lock-held reconciliation rather than risking deletion of
     * a same-UID replacement. */
    *stage_created = true;
    if (SWITCH_GUARD_TEST_CHECKPOINT(
            SWITCH_GUARD_INSTALL_BEFORE_INITIAL_FSTAT,
            directory_fd) != 0 ||
        fstat(fd, &opened) != 0) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot identify private switch transition stage");
        return -1;
    }
    *stage_identity = opened;
    *stage_identity_known = true;
    if (fchmod(fd, PERM_USER_RW) != 0 ||
        fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, true)) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot create private switch transition stage");
        return -1;
    }
    while (total < length) {
        ssize_t count = write(fd, data + total, length - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            saved_errno = errno ? errno : EIO;
            close(fd);
            errno = saved_errno;
            set_system_error(
                ERR_FILE_IO,
                "Cannot write switch transition stage");
            return -1;
        }
    }
    if (fsync(fd) != 0 || fstat(fd, &after_write) != 0 ||
        !config_metadata_file_is_safe(&after_write, true) ||
        after_write.st_size < 0 ||
        (uintmax_t)after_write.st_size != length) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot synchronize switch transition stage");
        return -1;
    }
    if (close(fd) != 0) {
        saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot close switch transition stage");
        return -1;
    }
    if (fstatat(
            directory_fd, name, &named,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named, true) ||
        (!config_metadata_snapshot_same(&after_write, &named) &&
         !config_metadata_ctime_only_change(
             &after_write, &named))) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Switch transition stage changed before publication");
        return -1;
    }
    *stage_identity = named;
    return 0;
}

static int config_switch_guard_stage_write_at(
    int directory_fd, const unsigned char *data, size_t length,
    struct stat *stage_identity, bool *stage_created,
    bool *stage_identity_known) {
    return config_switch_guard_named_write_at(
        directory_fd, CONFIG_SWITCH_STAGE_NAME, data, length,
        stage_identity, stage_created, stage_identity_known);
}

/* A switch stage is strictly pre-mutation: the caller cannot receive a live
 * guard handle until the stage has been renamed to the canonical marker and
 * durably re-proved. On an installation error, remove only the exact inode
 * created by this call while its lifecycle lock and parent directory are
 * still pinned. A successful rename may already have moved the inode to the
 * canonical marker; in that case there is no uncallable stage to clean and
 * the marker remains available for explicit recovery. */
static int config_switch_guard_cleanup_owned_stage_at(
    int directory_fd, int lock_fd, const char *directory,
    const struct stat *directory_identity,
    const struct stat *stage_identity, bool *stage_created) {
    struct stat named;
    int failure_errno = ESTALE;

    if (directory_fd < 0 || lock_fd < 0 || !directory ||
        !directory_identity || !stage_identity || !stage_created) {
        errno = EINVAL;
        return -1;
    }
    if (!*stage_created) return 0;
    if (verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Cannot prove switch stage cleanup authority");
        return -1;
    }

    errno = 0;
    if (fstatat(
            directory_fd, CONFIG_SWITCH_STAGE_NAME, &named,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *stage_created = false;
            return 0;
        }
        failure_errno = errno ? errno : EIO;
        goto cleanup_fail;
    }
    if (!config_metadata_file_is_safe(&named, true) ||
        !config_metadata_same_file(stage_identity, &named)) {
        failure_errno = ESTALE;
        goto cleanup_fail;
    }
    if (config_retire_exact_name_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME, &named,
            NULL, 0U,
            CONFIG_SWITCH_SETTLED_PREFIX) != 0) {
        failure_errno = errno ? errno : EIO;
        goto cleanup_fail;
    }
    *stage_created = false;
    if (fsync(directory_fd) != 0 ||
        config_switch_guard_name_stable_at(
            directory_fd, CONFIG_SWITCH_STAGE_NAME,
            true, NULL, NULL, 0U) != 0 ||
        verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, directory_identity)) {
        failure_errno = errno ? errno : ESTALE;
        goto cleanup_fail;
    }
    return 0;

cleanup_fail:
    errno = failure_errno;
    set_system_error(
        ERR_FILE_IO,
        "Cannot remove the exact fresh switch transition stage");
    return -1;
}

static int config_switch_guard_publish_stage_at(
    int directory_fd, const struct stat *stage_identity,
    const unsigned char *stage_data, size_t stage_length,
    struct stat *published_identity) {
    struct stat named = {0};
    struct stat retained_source;
    int publish_outcome;

    if (directory_fd < 0 || !stage_identity ||
        (!stage_data && stage_length != 0U) ||
        !published_identity) {
        errno = EINVAL;
        return -1;
    }
    publish_outcome = config_publish_noreplace_at(
        directory_fd, CONFIG_SWITCH_STAGE_NAME,
        CONFIG_SWITCH_GUARD_NAME, stage_identity,
        &retained_source);
    if (publish_outcome == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
        errno = EINPROGRESS;
        set_system_error(
            ERR_FILE_IO,
            "Switch guard publication outcome is uncertain");
        return -1;
    }
    if (publish_outcome ==
        CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED) {
        errno = EINPROGRESS;
        set_system_error(
            ERR_FILE_IO,
            "Switch guard was installed with its exact fixed recovery stage retained");
        return -1;
    }
    if (publish_outcome < 0 ||
        fstatat(
            directory_fd, CONFIG_SWITCH_GUARD_NAME, &named,
            AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&named, true) ||
        !config_metadata_same_file(stage_identity, &named)) {
        errno = errno ? errno : ESTALE;
        return -1;
    }
    *published_identity = named;
    return 0;
}

int config_switch_guard_install_or_adopt(
    const gitswitch_ctx_t *ctx, const account_t *target,
    git_scope_t effective_scope,
    const publication_record_t *destinations,
    size_t destination_count,
    config_switch_guard_t **guard) {
    static const char hexadecimal[] = "0123456789ABCDEF";
    config_switch_guard_model_t *expected = NULL;
    config_switch_guard_snapshot_t *snapshot = NULL;
    config_switch_guard_snapshot_t *revalidated = NULL;
    char directory[MAX_PATH_LEN];
    const char *config_name = NULL;
    struct stat directory_identity;
    struct stat stage_identity;
    struct stat published_identity;
    publication_identity_t accepted_source;
    publication_identity_t settled_source;
    unsigned char *expected_data = NULL;
    size_t expected_length = 0U;
    size_t convergence_attempt;
    int directory_fd = -1;
    int lock_fd = -1;
    int result = -1;
    int saved_errno = EIO;
    bool stage_created = false;
    bool stage_identity_known = false;
    bool source_converged = false;

    if (!guard || *guard) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard output handle");
        return -1;
    }
    if (g_switch_guard_owner_pid != 0) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "This process already owns a switch recovery transaction");
        return -1;
    }
    expected = calloc(1U, sizeof(*expected));
    snapshot = calloc(1U, sizeof(*snapshot));
    revalidated = calloc(1U, sizeof(*revalidated));
    if (!expected || !snapshot || !revalidated) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate switch guard revalidation state");
        goto install_done;
    }
    if (config_switch_guard_model_from_request(
            ctx, target, effective_scope, destinations,
            destination_count,
            expected) != 0 ||
        config_switch_guard_config_name(
            ctx->config.config_path, &config_name) != 0) {
        goto install_done;
    }
    result = config_switch_guard_open_directory(
        ctx->config.config_path, false, directory,
        &directory_identity, &directory_fd);
    if (result != 0) goto install_done;
    result = -1;
    lock_fd = try_lock_private_file_at(
        directory_fd, CONFIG_SWITCH_LOCK_NAME);
    if (lock_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot acquire the switch lifecycle lock");
        goto install_done;
    }
    if (verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        config_switch_guard_reconcile_preintent_at(
            directory_fd, lock_fd, directory,
            &directory_identity) != 0) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    if (config_switch_destinations_live(
            expected->destinations,
            expected->destination_count) != 0 ||
        config_switch_guard_snapshot_read_at(
            directory_fd, snapshot) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    if (snapshot->stage_present) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "A retained switch transition stage blocks recovery");
        goto install_done;
    }

    if (!snapshot->marker_absent) {
        if (!config_switch_same_destinations_authority(
                snapshot->marker_model.destinations,
                snapshot->marker_model.destination_count,
                expected->destinations,
                expected->destination_count)) {
            errno = EBUSY;
            set_error(
                ERR_CONFIG_INVALID,
                "Switch recovery destinations no longer name the recorded Git namespaces");
            goto install_done;
        }
        /* The current probe proves stable destination authority. Preserve the
         * pre-mutation directory witnesses stored in the marker so mutable
         * directory timestamps cannot defeat canonical adoption equality. */
        for (size_t i = 0U;
             i < expected->destination_count; i++) {
            expected->destinations[i].config_parent =
                snapshot->marker_model.destinations[i].config_parent;
            expected->destinations[i].repository =
                snapshot->marker_model.destinations[i].repository;
        }
        memcpy(
            expected->token, snapshot->marker_model.token,
            sizeof(expected->token));
        if (config_switch_guard_source_matches_at(
                directory_fd, config_name,
                &snapshot->marker_model.source_generation,
                snapshot->source_witness,
                snapshot->source_witness_length,
                &accepted_source) != 0) {
            goto install_done;
        }
        expected->source_generation =
            snapshot->marker_model.source_generation;
        if (config_switch_guard_serialize(
                expected, snapshot->source_witness,
                snapshot->source_witness_length,
                &expected_data, &expected_length) != 0) {
            goto install_done;
        }
        expected->source_generation = accepted_source;
        if (
            expected_length != snapshot->marker_length ||
            memcmp(
                expected_data, snapshot->marker_data,
                expected_length) != 0) {
            errno = EBUSY;
            set_error(
                ERR_CONFIG_INVALID,
                "A different switch-incomplete operation already blocks configuration mutation");
            goto install_done;
        }
        if (fsync(directory_fd) != 0 ||
            config_switch_guard_snapshot_read_at(
                directory_fd, revalidated) != 0 ||
            revalidated->stage_present ||
            revalidated->marker_absent ||
            revalidated->marker_length != expected_length ||
            memcmp(
                revalidated->marker_data, expected_data,
                expected_length) != 0 ||
            !config_metadata_matches_after_exact_content_proof(
                &snapshot->marker_identity,
                &revalidated->marker_identity) ||
            config_switch_guard_source_matches_at(
                directory_fd, config_name,
                &snapshot->marker_model.source_generation,
                snapshot->source_witness,
                snapshot->source_witness_length,
                &accepted_source) != 0 ||
            config_switch_destinations_live(
                expected->destinations,
                expected->destination_count) != 0 ||
            verify_private_lock_file_at(
                lock_fd, directory_fd,
                CONFIG_SWITCH_LOCK_NAME) != 0 ||
            !config_named_directory_matches(
                directory, &directory_identity)) {
            if (errno == 0) errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Retained switch guard changed during adoption");
            goto install_done;
        }
        expected->source_generation = accepted_source;
        if (config_switch_guard_make_handle(
                directory_fd, lock_fd, directory, config_name,
                &directory_identity,
                &revalidated->marker_identity,
                revalidated->marker_data,
                revalidated->marker_length,
                revalidated->source_witness,
                revalidated->source_witness_length,
                expected,
                expected->token, false,
                guard) != 0) {
            goto install_done;
        }
        revalidated->marker_data = NULL;
        revalidated->marker_length = 0U;
        directory_fd = -1;
        lock_fd = -1;
        result = 0;
        goto install_done;
    }

    if (config_switch_guard_source_matches_at(
            directory_fd, config_name,
            &expected->source_generation,
            ctx->config.source_witness,
            ctx->config.source_witness_length,
            &accepted_source) != 0) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    expected->source_generation = accepted_source;
    if (generate_random_string(
            expected->token, sizeof(expected->token),
            hexadecimal) != 0 ||
        !account_incarnation_is_valid(expected->token)) {
        goto install_done;
    }
    for (convergence_attempt = 0U;
         convergence_attempt < CONFIG_SWITCH_SOURCE_CONVERGENCE_MAX;
         convergence_attempt++) {
        if (config_switch_guard_serialize(
                expected, ctx->config.source_witness,
                ctx->config.source_witness_length,
                &expected_data, &expected_length) != 0 ||
            config_switch_guard_stage_write_at(
                directory_fd, expected_data, expected_length,
                &stage_identity, &stage_created,
                &stage_identity_known) != 0 ||
            SWITCH_GUARD_TEST_CHECKPOINT(
                SWITCH_GUARD_INSTALL_AFTER_STAGE_SYNC,
                directory_fd) != 0 ||
            config_switch_guard_source_matches_at(
                directory_fd, config_name,
                &expected->source_generation,
                ctx->config.source_witness,
                ctx->config.source_witness_length,
                &accepted_source) != 0 ||
            fsync(directory_fd) != 0 ||
            config_switch_guard_source_observe_at(
                directory_fd, config_name,
                &settled_source) != 0) {
            goto install_done;
        }
        if (!config_switch_source_identity_matches_after_exact_proof(
                &accepted_source, &settled_source)) {
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Switch recovery source changed while settling its durable generation");
            goto install_done;
        }
        accepted_source = settled_source;
        if (publication_identity_equal(
                &expected->source_generation,
                &accepted_source)) {
            source_converged = true;
            break;
        }
        if (config_switch_guard_cleanup_owned_stage_at(
                directory_fd, lock_fd, directory,
                &directory_identity, &stage_identity,
                &stage_created) != 0) {
            goto install_done;
        }
        expected->source_generation = accepted_source;
        secure_zero_memory(expected_data, expected_length);
        free(expected_data);
        expected_data = NULL;
        expected_length = 0U;
    }
    if (!source_converged) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Switch recovery source generation did not converge before publication");
        goto install_done;
    }
    if (config_switch_destinations_live(
            expected->destinations,
            expected->destination_count) != 0 ||
        verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        goto install_done;
    }
    if (config_switch_guard_publish_stage_at(
            directory_fd, &stage_identity,
            expected_data, expected_length,
            &published_identity) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot publish the fresh switch guard generation");
        goto install_done;
    }
    stage_created = false;
    if (fsync(directory_fd) != 0 ||
        config_reprove_published_file_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME,
            &published_identity, expected_data, expected_length,
            &published_identity) != 0 ||
        config_switch_guard_snapshot_read_at(
            directory_fd, revalidated) != 0 ||
        revalidated->stage_present ||
        revalidated->marker_absent ||
        revalidated->marker_length != expected_length ||
        memcmp(
            revalidated->marker_data, expected_data,
            expected_length) != 0 ||
        !publication_identity_equal(
            &revalidated->marker_model.source_generation,
            &expected->source_generation) ||
        config_switch_guard_source_matches_at(
            directory_fd, config_name,
            &expected->source_generation,
            revalidated->source_witness,
            revalidated->source_witness_length,
            &accepted_source) != 0 ||
        config_switch_destinations_live(
            expected->destinations,
            expected->destination_count) != 0 ||
        verify_private_lock_file_at(
            lock_fd, directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Fresh switch guard is not one durable stable generation");
        goto install_done;
    }
    expected->source_generation = accepted_source;
    if (config_switch_guard_make_handle(
            directory_fd, lock_fd, directory, config_name,
            &directory_identity, &revalidated->marker_identity,
            revalidated->marker_data, revalidated->marker_length,
            revalidated->source_witness,
            revalidated->source_witness_length,
            expected, expected->token, true, guard) != 0) {
        goto install_done;
    }
    revalidated->marker_data = NULL;
    revalidated->marker_length = 0U;
    directory_fd = -1;
    lock_fd = -1;
    result = 0;

install_done:
    if (result != 0) {
        error_accumulator_t failures;
        error_context_t primary_error = *get_last_error();

        saved_errno = errno ? errno : EIO;
        if (primary_error.code == ERR_SUCCESS) {
            errno = saved_errno;
            set_system_error(
                ERR_FILE_IO,
                "Switch recovery guard installation failed");
            primary_error = *get_last_error();
            saved_errno = errno ? errno : saved_errno;
        }
        error_accumulator_init(&failures);
        errno = saved_errno;
        (void)error_accumulator_add(
            &failures, "switch guard installation",
            &primary_error);
        if (stage_created && !stage_identity_known) {
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Switch transition stage identity is unknown; retained "
                "'.switch-transition' for locked recovery rather than risk "
                "deleting a replacement generation");
            (void)error_accumulator_add_last(
                &failures, "switch stage cleanup");
        } else if (stage_created && directory_fd >= 0 && lock_fd >= 0 &&
            config_switch_guard_cleanup_owned_stage_at(
                directory_fd, lock_fd, directory,
                &directory_identity, &stage_identity,
                &stage_created) != 0) {
            (void)error_accumulator_add_last(
                &failures, "switch stage cleanup");
        }
        (void)error_accumulator_publish(&failures);
        saved_errno = errno ? errno : saved_errno;
    }
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
    if (snapshot) {
        config_switch_guard_snapshot_clear(snapshot);
        free(snapshot);
    }
    if (revalidated) {
        config_switch_guard_snapshot_clear(revalidated);
        free(revalidated);
    }
    if (expected_data) {
        secure_zero_memory(expected_data, expected_length);
        free(expected_data);
    }
    if (expected) {
        secure_zero_memory(expected, sizeof(*expected));
        free(expected);
    }
    if (result != 0) {
        errno = saved_errno;
    }
    return result;
}

bool config_switch_guard_was_created(
    const config_switch_guard_t *guard) {
    return guard && guard->owner_pid == getpid() &&
           g_switch_guard_owner_pid == getpid() &&
           guard->created;
}

int config_switch_guard_reconcile_preintent(
    const char *config_path) {
    config_switch_preintent_snapshot_t snapshot;
    char directory[MAX_PATH_LEN];
    const char *config_name = NULL;
    struct stat directory_identity;
    int directory_fd = -1;
    int lock_fd = -1;
    int result;
    int saved_errno = EIO;

    if (!config_path || config_path[0] == '\0') {
        errno = EINVAL;
        set_error(
            ERR_INVALID_ARGS,
            "Invalid switch pre-intent reconciliation path");
        return -1;
    }
    if (g_switch_guard_owner_pid != 0) {
        errno = EBUSY;
        set_error(
            ERR_CONFIG_INVALID,
            "This process already owns a switch recovery transaction");
        return -1;
    }
    if (config_switch_guard_config_name(
            config_path, &config_name) != 0) {
        return -1;
    }
    result = config_switch_guard_open_directory(
        config_path, true, directory, &directory_identity,
        &directory_fd);
    if (result == 1) return 0;
    if (result != 0) return -1;
    result = -1;
    if (config_switch_guard_preintent_snapshot_at(
            directory_fd, &snapshot) != 0) {
        goto reconcile_done;
    }
    if (snapshot.kind == CONFIG_SWITCH_PREINTENT_NONE) {
        close(directory_fd);
        return 0;
    }
    lock_fd = try_lock_private_file_at(
        directory_fd, CONFIG_SWITCH_LOCK_NAME);
    if (lock_fd < 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot acquire the switch lifecycle lock for pre-intent reconciliation");
        goto reconcile_done;
    }
    if (config_switch_guard_reconcile_preintent_at(
            directory_fd, lock_fd, directory,
            &directory_identity) != 0) {
        goto reconcile_done;
    }
    result = 0;

reconcile_done:
    if (result != 0) saved_errno = errno ? errno : EIO;
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    close(directory_fd);
    if (result != 0) errno = saved_errno;
    return result;
}

int config_switch_guard_probe(
    const char *config_path, bool *blocked,
    config_switch_guard_recovery_t *recovery) {
    config_switch_guard_snapshot_t snapshot;
    config_switch_preintent_snapshot_t preintent;
    char directory[MAX_PATH_LEN];
    const char *config_name = NULL;
    struct stat directory_identity;
    int directory_fd = -1;
    int result;
    bool normalized_pair_equal = false;

    if (!config_path || !blocked || !recovery) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard probe arguments");
        return -1;
    }
    *blocked = true;
    memset(recovery, 0, sizeof(*recovery));
    memset(&snapshot, 0, sizeof(snapshot));
    if (config_switch_guard_config_name(
            config_path, &config_name) != 0) {
        return -1;
    }
    result = config_switch_guard_open_directory(
        config_path, true, directory, &directory_identity,
        &directory_fd);
    if (result == 1) {
        *blocked = false;
        return 0;
    }
    if (result != 0) return -1;
    if (config_switch_guard_preintent_snapshot_at(
            directory_fd, &preintent) != 0) {
        result = -1;
        goto probe_done;
    }
    if (preintent.kind != CONFIG_SWITCH_PREINTENT_NONE) {
        /* A recognized stage-only or exact portable hard-link pair exists
         * strictly before live mutation. Let a real mutating entry acquire
         * `.config.lock`, reconcile it under `.switch.lock`, and probe again.
         * The stage itself never authorizes resume. */
        if (preintent.kind ==
                CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR &&
            config_switch_guard_normalized_pair_equal_at(
                directory_fd, &preintent,
                &normalized_pair_equal) != 0) {
            result = -1;
            goto probe_done;
        }
        *blocked =
            preintent.kind ==
                CONFIG_SWITCH_PREINTENT_NORMALIZED_PAIR &&
            !normalized_pair_equal;
        result = 0;
        goto probe_done;
    }
    if (config_switch_guard_snapshot_read_at(
            directory_fd, &snapshot) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        result = -1;
        goto probe_done;
    }
    if (snapshot.stage_present) {
        result = 0;
        goto probe_done;
    }
    if (snapshot.marker_absent) {
        *blocked = false;
        result = 0;
        goto probe_done;
    }
    if (config_switch_guard_source_matches_at(
            directory_fd, config_name,
            &snapshot.marker_model.source_generation,
            snapshot.source_witness,
            snapshot.source_witness_length, NULL) != 0 ||
        config_switch_destinations_live(
            snapshot.marker_model.destinations,
            snapshot.marker_model.destination_count) != 0 ||
        config_switch_guard_name_stable_at(
            directory_fd, CONFIG_SWITCH_GUARD_NAME, false,
            &snapshot.marker_identity, snapshot.marker_data,
            snapshot.marker_length) != 0 ||
        !config_named_directory_matches(
            directory, &directory_identity)) {
        if (errno == 0) errno = ESTALE;
        result = -1;
        goto probe_done;
    }
    recovery->source_generation =
        snapshot.marker_model.source_generation;
    recovery->target = snapshot.marker_model.target;
    recovery->effective_scope =
        snapshot.marker_model.effective_scope;
    recovery->destination_count =
        snapshot.marker_model.destination_count;
    memcpy(
        recovery->destinations,
        snapshot.marker_model.destinations,
        sizeof(recovery->destinations));
    recovery->valid = true;
    result = 0;

probe_done:
    config_switch_guard_snapshot_clear(&snapshot);
    close(directory_fd);
    return result;
}

int config_switch_guard_clear(config_switch_guard_t **guard_ptr) {
    config_switch_guard_t *guard;
    config_switch_guard_snapshot_t *snapshot = NULL;
    config_switch_guard_snapshot_t *after = NULL;
    int saved_errno;

    if (!guard_ptr || !*guard_ptr) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard clear handle");
        return -1;
    }
    guard = *guard_ptr;
    clear_error();
    errno = 0;
    snapshot = calloc(1U, sizeof(*snapshot));
    after = calloc(1U, sizeof(*after));
    if (!snapshot || !after) {
        free(snapshot);
        free(after);
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch guard clear verification state");
        return -1;
    }
    if (guard->owner_pid != getpid() ||
        g_switch_guard_owner_pid != getpid() ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        config_switch_guard_snapshot_read_at(
            guard->directory_fd, snapshot) != 0 ||
        config_switch_guard_source_matches_at(
            guard->directory_fd, guard->config_name,
            &guard->model.source_generation,
            guard->source_witness, guard->source_witness_length,
            NULL) != 0 ||
        config_switch_destinations_live(
            guard->model.destinations,
            guard->model.destination_count) != 0 ||
        (guard->marker_unlinked
             ? (snapshot->stage_present ||
                !snapshot->marker_absent)
             : !config_switch_guard_matches_handle(
                   guard, snapshot))) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Switch guard generation changed before clear");
        goto clear_fail;
    }
    if (!guard->marker_unlinked) {
        if (config_retire_exact_name_at(
                guard->directory_fd,
                CONFIG_SWITCH_GUARD_NAME,
                &snapshot->marker_identity,
                snapshot->marker_data,
                snapshot->marker_length,
                CONFIG_SWITCH_SETTLED_PREFIX) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Cannot remove the owned switch guard generation");
            goto clear_fail;
        }
        /* From here onward the callable handle represents a pending
         * durability proof for an already-unlinked exact marker. A failed
         * directory sync must be retryable without requiring the absent name
         * to match its old inode again. */
        guard->marker_unlinked = true;
    }
    if (SWITCH_GUARD_TEST_CHECKPOINT(
            SWITCH_GUARD_CLEAR_AFTER_UNLINK,
            guard->directory_fd) != 0 ||
        fsync(guard->directory_fd) != 0) {
        saved_errno = errno ? errno : EIO;
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot synchronize switch guard removal");
        goto clear_fail;
    }
    if (config_switch_guard_snapshot_read_at(
            guard->directory_fd, after) != 0 ||
        after->stage_present || !after->marker_absent ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity)) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Switch guard removal is not a stable absent generation");
        goto clear_fail;
    }
    config_switch_guard_snapshot_clear(snapshot);
    config_switch_guard_snapshot_clear(after);
    free(snapshot);
    free(after);
    config_switch_guard_free(guard);
    *guard_ptr = NULL;
    clear_error();
    errno = 0;
    return 0;

clear_fail:
    config_switch_guard_snapshot_clear(snapshot);
    config_switch_guard_snapshot_clear(after);
    free(snapshot);
    free(after);
    return -1;
}

int config_switch_guard_retain(
    config_switch_guard_t **guard_ptr) {
    config_switch_guard_t *guard;
    config_switch_guard_snapshot_t *snapshot = NULL;
    config_switch_guard_snapshot_t *after = NULL;
    struct stat stage_identity;
    struct stat published_identity;
    publication_identity_t accepted_source;
    error_accumulator_t failures;
    error_context_t primary_error;
    int primary_errno = 0;
    bool stage_created = false;
    bool stage_identity_known = false;
    bool primary_failure = false;

    if (!guard_ptr || !*guard_ptr) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid switch guard retain handle");
        return -1;
    }
    guard = *guard_ptr;
    clear_error();
    errno = 0;
    snapshot = calloc(1U, sizeof(*snapshot));
    after = calloc(1U, sizeof(*after));
    if (!snapshot || !after) {
        free(snapshot);
        free(after);
        set_error(
            ERR_MEMORY_ALLOCATION,
            "Cannot allocate switch guard retain verification state");
        return -1;
    }
    memset(&stage_identity, 0, sizeof(stage_identity));
    memset(&published_identity, 0, sizeof(published_identity));
    error_accumulator_init(&failures);

    if (guard->owner_pid != getpid() ||
        g_switch_guard_owner_pid != getpid() ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        config_switch_guard_source_matches_at(
            guard->directory_fd, guard->config_name,
            &guard->model.source_generation,
            guard->source_witness, guard->source_witness_length,
            &accepted_source) != 0 ||
        config_switch_destinations_live(
            guard->model.destinations,
            guard->model.destination_count) != 0 ||
        config_switch_guard_snapshot_read_at(
            guard->directory_fd, snapshot) != 0) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Cannot prove switch guard authority before retaining recovery");
        goto retain_fail;
    }

    guard->model.source_generation = accepted_source;
    if (guard->marker_unlinked) {
        if (snapshot->stage_present || !snapshot->marker_absent) {
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "Cannot republish switch recovery over a changed guard namespace");
            goto retain_fail;
        }
    } else {
        if (!config_switch_guard_matches_handle(guard, snapshot)) {
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "Owned switch recovery marker changed before retention");
            goto retain_fail;
        }
    }

    if (guard->marker_unlinked) {
        if (config_switch_guard_stage_write_at(
                guard->directory_fd, guard->marker_data,
                guard->marker_length, &stage_identity,
                &stage_created, &stage_identity_known) != 0 ||
            fsync(guard->directory_fd) != 0 ||
            config_switch_guard_source_matches_at(
                guard->directory_fd, guard->config_name,
                &guard->model.source_generation,
                guard->source_witness,
                guard->source_witness_length,
                &accepted_source) != 0) {
            primary_failure = true;
            primary_error = *get_last_error();
            primary_errno = errno ? errno : EIO;
            goto retain_fail;
        }
        guard->model.source_generation = accepted_source;
        if (config_switch_guard_publish_stage_at(
                guard->directory_fd, &stage_identity,
                guard->marker_data, guard->marker_length,
                &published_identity) != 0) {
            primary_failure = true;
            primary_error = *get_last_error();
            primary_errno = errno ? errno : EIO;
            goto retain_recheck;
        }
        stage_created = false;
        guard->marker_identity = published_identity;
        guard->marker_unlinked = false;
    }

retain_recheck:
    config_switch_guard_snapshot_clear(after);
    if (config_switch_guard_snapshot_read_at(
            guard->directory_fd, after) != 0) {
        goto retain_fail;
    }
    /* A no-replace publication can install the exact canonical name and then
     * report an uncertain post-install check. Adopt only the byte-identical
     * marker generation; a foreign or malformed name remains untouched. */
    if (guard->marker_unlinked && !after->stage_present &&
        !after->marker_absent &&
        after->marker_length == guard->marker_length &&
        memcmp(
            after->marker_data, guard->marker_data,
            guard->marker_length) == 0 &&
        strcmp(
            after->marker_model.token, guard->token) == 0) {
        guard->marker_identity = after->marker_identity;
        guard->marker_unlinked = false;
        stage_created = false;
    }
    if (guard->marker_unlinked || after->stage_present ||
        !config_switch_guard_matches_handle(guard, after) ||
        fsync(guard->directory_fd) != 0 ||
        SWITCH_GUARD_TEST_CHECKPOINT(
            SWITCH_GUARD_RETAIN_AFTER_MARKER_SYNC,
            guard->directory_fd) != 0) {
        if (errno == 0) errno = ESTALE;
        if (get_last_error()->code == ERR_SUCCESS) {
            set_system_error(
                ERR_FILE_IO,
                "Cannot prove the retained switch recovery marker");
        }
        goto retain_fail;
    }
    config_switch_guard_snapshot_clear(snapshot);
    if (config_switch_guard_snapshot_read_at(
            guard->directory_fd, snapshot) != 0 ||
        snapshot->stage_present ||
        !config_switch_guard_matches_handle(guard, snapshot) ||
        verify_private_lock_file_at(
            guard->lock_fd, guard->directory_fd,
            CONFIG_SWITCH_LOCK_NAME) != 0 ||
        !config_named_directory_matches(
            guard->directory, &guard->directory_identity) ||
        config_switch_guard_source_matches_at(
            guard->directory_fd, guard->config_name,
            &guard->model.source_generation,
            guard->source_witness,
            guard->source_witness_length,
            &accepted_source) != 0 ||
        config_switch_destinations_live(
            guard->model.destinations,
            guard->model.destination_count) != 0) {
        if (errno == 0) errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Retained switch recovery marker is not one durable stable generation");
        goto retain_fail;
    }

    config_switch_guard_snapshot_clear(snapshot);
    config_switch_guard_snapshot_clear(after);
    free(snapshot);
    free(after);
    config_switch_guard_free(guard);
    *guard_ptr = NULL;
    if (primary_failure) {
        g_last_error = primary_error;
        errno = primary_errno;
    } else {
        clear_error();
        errno = 0;
    }
    return 0;

retain_fail:
    if (!primary_failure) {
        primary_error = *get_last_error();
        primary_errno = errno ? errno : EIO;
    }
    errno = primary_errno;
    (void)error_accumulator_add(
        &failures, "switch recovery retention",
        &primary_error);
    if (stage_created && !stage_identity_known) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Switch transition stage identity is unknown; retained "
            "'.switch-transition' for locked recovery rather than risk "
            "deleting a replacement generation");
        (void)error_accumulator_add_last(
            &failures, "switch recovery stage cleanup");
    } else if (stage_created &&
        config_switch_guard_cleanup_owned_stage_at(
            guard->directory_fd, guard->lock_fd,
            guard->directory, &guard->directory_identity,
            &stage_identity, &stage_created) != 0) {
        (void)error_accumulator_add_last(
            &failures, "switch recovery stage cleanup");
    }
    (void)error_accumulator_publish(&failures);
    primary_errno = errno ? errno : primary_errno;
    config_switch_guard_snapshot_clear(snapshot);
    config_switch_guard_snapshot_clear(after);
    free(snapshot);
    free(after);
    errno = primary_errno;
    return -1;
}

void config_switch_guard_abandon(
    config_switch_guard_t **guard) {
    if (!guard || !*guard) return;
    config_switch_guard_free(*guard);
    *guard = NULL;
}

#define CONFIG_RESUME_HINT_TEMP_PREFIX ".resume-hint.tmp."
#define CONFIG_RESUME_HINT_TEMP_SUFFIX_LENGTH 6U

static int config_write_lock_directory(const char *dir) {
    char lockpath[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat before;
    struct stat after;
    int dir_fd = -1;
    int token_fd = -1;

    errno = 0; /* Never misclassify a validation failure using stale errno. */
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
    if (token_fd < 0) {
        close(dir_fd);
        return -1;
    }

    if (config_reconcile_settled_aliases_at(
            dir_fd, ".resume-hint",
            CONFIG_RESUME_HINT_SETTLED_PREFIX,
            CONFIG_RESUME_HINT_TEMP_PREFIX,
            CONFIG_RESUME_HINT_TEMP_SUFFIX_LENGTH) != 0) {
        int saved_errno = errno ? errno : EIO;

        close(dir_fd);
        unlock_private_file(token_fd);
        errno = saved_errno;
        return -1;
    }
    close(dir_fd);

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

static int config_write_lock_path(const char *config_path) {
    char dir[MAX_PATH_LEN];
    int token_fd;

    if (config_directory_for_path(config_path, dir, sizeof(dir)) != 0) {
        return -1;
    }
    token_fd = config_write_lock_directory(dir);
    if (token_fd < 0) {
        int saved_errno = errno;
        bool contended = saved_errno == EWOULDBLOCK;
#if EAGAIN != EWOULDBLOCK
        contended = contended || saved_errno == EAGAIN;
#endif
        if (contended) {
            set_error(ERR_CONFIG_WRITE_FAILED,
                      "Another writer is committing configuration state for %s",
                      config_path);
        } else {
            errno = saved_errno;
            set_system_error(ERR_CONFIG_WRITE_FAILED,
                             "Cannot acquire the configuration publication lock for %s",
                             config_path);
        }
        errno = saved_errno;
    }
    return token_fd;
}

int config_write_lock(void) {
    char dir[MAX_PATH_LEN];

    if (get_config_directory(dir, sizeof(dir)) != 0) return -1;
    return config_write_lock_directory(dir);
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
    config_switch_guard_recovery_t switch_recovery;
    char config_path[MAX_PATH_LEN];
    const char *normalized;
    bool switch_blocked = true;

    if (!needs || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid resume-hint probe output");
        return -1;
    }
    needs[0] = '\0';
    memset(&switch_recovery, 0, sizeof(switch_recovery));
    if (config_get_path(config_path, sizeof(config_path)) != 0 ||
        config_switch_guard_probe(
            config_path, &switch_blocked, &switch_recovery) != 0) {
        return -1;
    }
    if (switch_blocked) {
        if (!switch_recovery.valid) {
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "An incomplete switch transition blocks shell recovery");
            return -1;
        }
        /* The unresolved generation may own either runtime manager. The shell
         * must invoke full resume reconciliation rather than trust the stale
         * active-state needs token. */
        return safe_strncpy(needs, "ssh gpg", size);
    }
    if (
        config_read_active_state(config_path, &state, true, NULL, NULL) != 0) {
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

#define CONFIG_RESUME_HINT_SNAPSHOT_MAX CONFIG_ACTIVE_STATE_MAX

void config_resume_hint_snapshot_clear(
    config_resume_hint_snapshot_t *snapshot) {
    if (!snapshot) {
        return;
    }
    if (snapshot->data) {
        secure_zero_memory(snapshot->data, snapshot->length);
        free(snapshot->data);
    }
    if (snapshot->post_image_data) {
        secure_zero_memory(snapshot->post_image_data,
                           snapshot->post_image_length);
        free(snapshot->post_image_data);
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
    if (safe_strncpy(snapshot->config_path, config_path,
                     sizeof(snapshot->config_path)) != 0) {
        return -1;
    }
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
        !config_metadata_snapshot_same(&before, &opened) ||
        opened.st_size < 0 ||
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
    RESUME_HINT_TEST_CHECKPOINT(4);
    if (fstat(fd, &after) != 0 ||
        !config_metadata_file_is_safe(&after, false) ||
        !config_metadata_snapshot_same(&opened, &after) ||
        lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, false) ||
        !config_metadata_snapshot_same(&opened, &after)) {
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
    snapshot->before_image = opened;
    snapshot->before_image_valid = true;
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

static int config_resume_hint_snapshot_bind_post_image(
    const char *config_path, config_resume_hint_snapshot_t *snapshot) {
    if (!snapshot || !snapshot->valid ||
        strcmp(snapshot->config_path, config_path) != 0) {
        set_error(ERR_INVALID_ARGS,
                  "Rollback snapshot does not belong to the config path being saved");
        errno = EINVAL;
        return -1;
    }
    snapshot->post_image_bound = true;
    snapshot->post_image_installed = false;
    snapshot->post_image_valid = false;
    memset(&snapshot->post_image, 0, sizeof(snapshot->post_image));
    if (snapshot->post_image_data) {
        secure_zero_memory(snapshot->post_image_data,
                           snapshot->post_image_length);
        free(snapshot->post_image_data);
        snapshot->post_image_data = NULL;
    }
    snapshot->post_image_length = 0;
    return 0;
}

/* A guarded transaction starts from a before-image captured before its
 * surrounding mutation. Re-read the state only after entering the
 * destination's write lock, then prove that no cooperating state writer
 * committed in the gap.
 * The complete bytes distinguish same-inode rewrites; the captured metadata
 * distinguishes atomic replacement even when a later writer restored the
 * same bytes. FreeBSD may materialize ctime during a directory sync, so admit
 * only that narrow metadata drift when the independent byte witness matches. */
static int config_resume_hint_snapshot_require_before_image(
    const char *hint, const config_resume_hint_snapshot_t *snapshot,
    const config_active_state_generation_t *current) {
    bool content_same;
    bool metadata_same;

    if (!hint || !snapshot || !snapshot->valid || !current ||
        snapshot->length > CONFIG_ACTIVE_STATE_MAX ||
        (snapshot->length != 0U && !snapshot->data)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid active-state rollback before-image proof");
        return -1;
    }
    if (snapshot->existed != current->existed) {
        goto conflict;
    }
    if (!snapshot->existed) {
        return 0;
    }
    if (!snapshot->before_image_valid || !current->data ||
        snapshot->length != current->length) {
        goto conflict;
    }
    content_same = snapshot->length == 0U ||
                   memcmp(snapshot->data, current->data,
                          snapshot->length) == 0;
    metadata_same =
        config_metadata_snapshot_same(&snapshot->before_image,
                                      &current->metadata) ||
        config_metadata_ctime_only_change(&snapshot->before_image,
                                          &current->metadata);
    if (!content_same || !metadata_same) {
        goto conflict;
    }
    return 0;

conflict:
    set_error(ERR_FILE_IO,
              "Active-state before-image changed after rollback snapshot capture; refusing publication: %s",
              hint);
    return -1;
}

static bool config_resume_hint_post_image_content_same(
    const char *hint, const config_resume_hint_snapshot_t *snapshot,
    const struct stat *current) {
    struct stat opened;
    struct stat after;
    struct stat named;
    unsigned char data[4096];
    unsigned char extra;
    ssize_t extra_count;
    size_t offset = 0;
    int fd = -1;
    bool matches = false;

    if (!hint || !snapshot || !current || !snapshot->post_image_valid ||
        (snapshot->post_image_length != 0U &&
         !snapshot->post_image_data) ||
        snapshot->post_image_length > CONFIG_ACTIVE_STATE_MAX ||
        current->st_size < 0 ||
        (uintmax_t)current->st_size != snapshot->post_image_length) {
        return false;
    }
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, true) ||
        !config_metadata_snapshot_same(current, &opened)) {
        goto cleanup;
    }
    while (offset < snapshot->post_image_length) {
        size_t wanted = snapshot->post_image_length - offset;
        if (wanted > sizeof(data)) wanted = sizeof(data);
        if (!config_pread_full(fd, data, wanted, (off_t)offset) ||
            memcmp(data, snapshot->post_image_data + offset, wanted) != 0) {
            goto cleanup;
        }
        offset += wanted;
    }
    do {
        extra_count = pread(fd, &extra, 1,
                            (off_t)snapshot->post_image_length);
    } while (extra_count < 0 && errno == EINTR);
    if (extra_count == 0 && fstat(fd, &after) == 0 &&
        lstat(hint, &named) == 0 &&
        config_metadata_file_is_safe(&after, true) &&
        config_metadata_file_is_safe(&named, true) &&
        config_metadata_snapshot_same(&opened, &after) &&
        config_metadata_snapshot_same(&opened, &named)) {
        matches = true;
    }

cleanup:
    secure_zero_memory(data, sizeof(data));
    if (fd >= 0) close(fd);
    return matches;
}

static bool config_resume_hint_post_image_is_current(
    const char *hint, const config_resume_hint_snapshot_t *snapshot) {
    struct stat current;

    if (lstat(hint, &current) != 0 ||
        !config_metadata_file_is_safe(&current, true)) {
        return false;
    }
    if (config_metadata_snapshot_same(&snapshot->post_image, &current)) {
        return true;
    }
    /* FreeBSD UFS can materialize the ctime of a freshly renamed file after
     * the first lstat. Preserve the strict generation guard for every other
     * metadata change, and admit that one transition only after a stable,
     * descriptor-bound comparison proves the complete installed bytes. */
    return config_metadata_ctime_only_change(&snapshot->post_image, &current) &&
           config_resume_hint_post_image_content_same(hint, snapshot,
                                                       &current);
}

static int config_resume_hint_snapshot_require_post_image(
    const char *hint, const config_resume_hint_snapshot_t *snapshot) {
    if (!snapshot->post_image_bound) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Resume-hint rollback snapshot has no bound post-image");
        return -1;
    }
    if (!snapshot->post_image_installed || !snapshot->post_image_valid) {
        errno = ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Active-state rollback has no verified installed generation: %s",
            hint);
        return -1;
    }
    errno = 0;
    if (!config_resume_hint_post_image_is_current(hint, snapshot)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_FILE_IO,
            "Active-state rollback conflict; installed generation is no longer current: %s",
            hint);
        return -1;
    }
    return 0;
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
    struct stat temp_identity;
    size_t total = 0;
    int dir_fd = -1;
    int fd = -1;
    bool have_temp_identity = false;
    bool temp_registered = false;
    bool replacement_committed = false;

    if (!config_path || !snapshot || !snapshot->valid ||
        !snapshot->post_image_bound ||
        strcmp(snapshot->config_path, config_path) != 0) {
        set_error(ERR_INVALID_ARGS,
                  "Resume-hint rollback requires a bound snapshot for this config path");
        return -1;
    }
    /* A guarded save that did not install a state inode has nothing to undo.
     * In particular, do not turn a later independent write into rollback input
     * merely because a downstream transaction phase failed. */
    if (snapshot->post_image_bound && !snapshot->post_image_installed) {
        return 0;
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

    if (config_resume_hint_snapshot_require_post_image(hint, snapshot) != 0) {
        config_active_rollback_state_t state =
            CONFIG_ACTIVE_ROLLBACK_UNRESOLVED;

        close(dir_fd);
        if (config_resume_hint_snapshot_classify_at(
                config_path, snapshot, &state) == 0) {
            if (state == CONFIG_ACTIVE_ROLLBACK_BEFORE_DURABLE) {
                return 0;
            }
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Active-state rollback retry found the post-image still durable: %s",
                hint);
        }
        return -1;
    }

    if (!snapshot->existed) {
        if (config_retire_exact_path(
                hint, &snapshot->post_image, NULL, 0U,
                CONFIG_RESUME_HINT_SETTLED_PREFIX) != 0 &&
            errno != ENOENT) {
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
        if (config_io_fault(
                CONFIG_IO_STATE_ROLLBACK_AFTER_DIR_SYNC,
                "active-state rollback directory sync")) {
            close(dir_fd);
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
    if (fstat(fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        set_system_error(ERR_FILE_IO,
                         "Cannot identify resume-hint rollback file: %s", temp);
        goto restore_fail;
    }
    have_temp_identity = true;
    if (signals_scratch_register(temp) != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot register resume-hint rollback file for cleanup");
        goto restore_fail;
    }
    temp_registered = true;
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
    /* Recheck after preparing and syncing the before-image. Unlike the entry
     * proof above, a failure here is a namespace change during this call, not
     * evidence that a prior retry already completed. */
    if (config_resume_hint_snapshot_require_post_image(hint, snapshot) != 0) {
        goto restore_fail;
    }
    RESUME_HINT_TEST_CHECKPOINT(5);
    if (lstat(temp, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, false) ||
        config_replace_exact_name_at(
            dir_fd, strrchr(temp, '/') ? strrchr(temp, '/') + 1 : temp,
            &temp_identity, snapshot->data, snapshot->length,
            strrchr(hint, '/') ? strrchr(hint, '/') + 1 : hint,
            &snapshot->post_image, snapshot->post_image_data,
            snapshot->post_image_length,
            CONFIG_RESUME_HINT_SETTLED_PREFIX, &installed,
            &replacement_committed) != 0) {
        if (replacement_committed && temp_registered) {
            signals_scratch_unregister(temp);
            temp_registered = false;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot install restored resume hint: %s", hint);
        goto restore_fail;
    }
    signals_scratch_unregister(temp);
    temp_registered = false;
    if (fsync(dir_fd) != 0) {
        close(dir_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot durably restore resume hint: %s", hint);
        return -1;
    }
    if (config_io_fault(
            CONFIG_IO_STATE_ROLLBACK_AFTER_DIR_SYNC,
            "active-state rollback directory sync")) {
        close(dir_fd);
        return -1;
    }
    if (lstat(hint, &installed) != 0 ||
        !config_metadata_file_is_safe(&installed, false) ||
        (installed.st_mode & 0777) != (mode_t)snapshot->mode ||
        (size_t)installed.st_size != snapshot->length) {
        close(dir_fd);
        set_error(ERR_FILE_IO,
                  "Cannot verify restored resume hint: %s", hint);
        return -1;
    }
    fd = open(hint, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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
    config_unlink_created_temp(temp, &temp_identity, have_temp_identity);
    if (temp_registered) signals_scratch_unregister(temp);
    close(dir_fd);
    return -1;
}

int config_resume_hint_snapshot_restore(
    const config_resume_hint_snapshot_t *snapshot) {
    char config_path[MAX_PATH_LEN];
    int write_lock_fd;
    int result;

    if (config_get_path(config_path, sizeof(config_path)) != 0) {
        return -1;
    }
    write_lock_fd = config_write_lock_path(config_path);
    if (write_lock_fd < 0) {
        return -1;
    }
    result = config_resume_hint_snapshot_restore_at(config_path, snapshot);
    config_write_unlock(write_lock_fd);
    return result;
}

/* Re-prove a complete before/post image through one descriptor, then sync both
 * that inode and its pinned parent before reporting a durable settlement
 * direction.  This is deliberately content-aware: an equivalent replacement
 * inode is safe to reconcile forward or backward, while a third byte image
 * remains unowned and unresolved. */
static int config_resume_hint_snapshot_classify_at(
    const char *config_path,
    const config_resume_hint_snapshot_t *snapshot,
    config_active_rollback_state_t *state) {
    unsigned char buffer[512];
    char directory[MAX_PATH_LEN];
    char hint[MAX_PATH_LEN];
    struct stat directory_identity;
    struct stat directory_opened;
    struct stat named_before;
    struct stat opened;
    struct stat opened_after;
    struct stat named_after;
    struct stat directory_named_after;
    const char *hint_name;
    size_t offset = 0U;
    bool before_matches;
    bool post_matches;
    int directory_fd = -1;
    int fd = -1;

    if (state) *state = CONFIG_ACTIVE_ROLLBACK_UNRESOLVED;
    if (!config_path || !snapshot || !snapshot->valid || !state ||
        strcmp(snapshot->config_path, config_path) != 0 ||
        snapshot->length > CONFIG_RESUME_HINT_SNAPSHOT_MAX ||
        snapshot->post_image_length > CONFIG_RESUME_HINT_SNAPSHOT_MAX ||
        (snapshot->length != 0U && !snapshot->data) ||
        (snapshot->post_image_length != 0U &&
         !snapshot->post_image_data)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid active-state settlement snapshot");
        return -1;
    }
    if (config_state_path_for_config(config_path, hint, sizeof(hint)) != 0 ||
        safe_strncpy(directory, hint, sizeof(directory)) != 0) {
        return -1;
    }
    {
        char *slash = strrchr(directory, '/');

        if (!slash) {
            if (safe_strncpy(directory, ".", sizeof(directory)) != 0) {
                return -1;
            }
        } else if (slash == directory) {
            slash[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
    hint_name = strrchr(hint, '/');
    hint_name = hint_name ? hint_name + 1 : hint;
    if (hint_name[0] == '\0' || strchr(hint_name, '/')) {
        errno = EINVAL;
        set_error(ERR_INVALID_PATH,
                  "Cannot derive the active-state settlement filename");
        return -1;
    }
    if (lstat(directory, &directory_identity) != 0 ||
        !config_metadata_dir_is_safe(&directory_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Cannot classify active-state settlement: config directory is unsafe");
        return -1;
    }
    directory_fd = open(directory,
                        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory_fd < 0 ||
        fstat(directory_fd, &directory_opened) != 0 ||
        !config_metadata_dir_is_safe(&directory_opened) ||
        !config_metadata_same_file(&directory_identity,
                                   &directory_opened)) {
        int saved_errno = errno;
        if (directory_fd >= 0) close(directory_fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot pin config directory while classifying active-state settlement");
        return -1;
    }

    if (fstatat(directory_fd, hint_name, &named_before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT && !snapshot->existed) {
            if (fsync(directory_fd) == 0) {
                errno = 0;
                if (fstatat(directory_fd, hint_name, &named_after,
                            AT_SYMLINK_NOFOLLOW) != 0 &&
                    errno == ENOENT &&
                    lstat(directory, &directory_named_after) == 0 &&
                    config_metadata_dir_is_safe(&directory_named_after) &&
                    config_metadata_same_file(
                        &directory_identity, &directory_named_after)) {
                    close(directory_fd);
                    *state = CONFIG_ACTIVE_ROLLBACK_BEFORE_DURABLE;
                    clear_error();
                    errno = 0;
                    return 0;
                }
            }
        }
        {
            int saved_errno = errno ? errno : ESTALE;
            close(directory_fd);
            errno = saved_errno;
            set_system_error(
                ERR_FILE_IO,
                "Active-state settlement cannot prove the current namespace entry: %s",
                hint);
            return -1;
        }
    }
    if (!config_metadata_file_is_safe(&named_before, false) ||
        named_before.st_size < 0 ||
        (uintmax_t)named_before.st_size >
            CONFIG_RESUME_HINT_SNAPSHOT_MAX) {
        close(directory_fd);
        errno = ESTALE;
        set_error(
            ERR_PERMISSION_DENIED,
            "Active-state settlement found an unsafe or oversized state file: %s",
            hint);
        return -1;
    }

    before_matches =
        snapshot->existed &&
        (size_t)named_before.st_size == snapshot->length &&
        (named_before.st_mode & 0777) == (mode_t)snapshot->mode;
    post_matches =
        snapshot->post_image_bound &&
        snapshot->post_image_installed &&
        snapshot->post_image_valid &&
        (size_t)named_before.st_size == snapshot->post_image_length &&
        (named_before.st_mode & 0777) ==
            (snapshot->post_image.st_mode & 0777);
    if (!before_matches && !post_matches) {
        close(directory_fd);
        errno = ESTALE;
        set_error(
            ERR_FILE_IO,
            "Active-state settlement found neither the before-image nor the post-image: %s",
            hint);
        return -1;
    }

    fd = openat(directory_fd, hint_name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !config_metadata_file_is_safe(&opened, false) ||
        !config_metadata_snapshot_same(&named_before, &opened)) {
        int saved_errno = errno ? errno : ESTALE;
        if (fd >= 0) close(fd);
        close(directory_fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Cannot open a stable active-state settlement image: %s", hint);
        return -1;
    }
    while (offset < (size_t)opened.st_size) {
        size_t wanted = (size_t)opened.st_size - offset;
        ssize_t count;

        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        do {
            count = pread(fd, buffer, wanted, (off_t)offset);
        } while (count < 0 && errno == EINTR);
        if (count != (ssize_t)wanted) {
            before_matches = false;
            post_matches = false;
            break;
        }
        if (before_matches &&
            memcmp(buffer, snapshot->data + offset, wanted) != 0) {
            before_matches = false;
        }
        if (post_matches &&
            memcmp(buffer, snapshot->post_image_data + offset, wanted) != 0) {
            post_matches = false;
        }
        if (!before_matches && !post_matches) break;
        offset += wanted;
    }
    secure_zero_memory(buffer, sizeof(buffer));
    if (!before_matches && !post_matches) {
        close(fd);
        close(directory_fd);
        errno = ESTALE;
        set_error(
            ERR_FILE_IO,
            "Active-state settlement bytes match neither owned image: %s",
            hint);
        return -1;
    }
    if (fsync(fd) != 0 || fsync(directory_fd) != 0 ||
        fstat(fd, &opened_after) != 0 ||
        fstatat(directory_fd, hint_name, &named_after,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        lstat(directory, &directory_named_after) != 0 ||
        !config_metadata_file_is_safe(&opened_after, false) ||
        !config_metadata_file_is_safe(&named_after, false) ||
        !config_metadata_dir_is_safe(&directory_named_after) ||
        (!config_metadata_snapshot_same(&opened, &opened_after) &&
         !config_metadata_ctime_only_change(&opened, &opened_after)) ||
        (!config_metadata_snapshot_same(&opened, &named_after) &&
         !config_metadata_ctime_only_change(&opened, &named_after)) ||
        !config_metadata_same_file(
            &directory_identity, &directory_named_after)) {
        int saved_errno = errno ? errno : ESTALE;
        close(fd);
        close(directory_fd);
        errno = saved_errno;
        set_system_error(
            ERR_FILE_IO,
            "Active-state settlement changed while being synchronized: %s",
            hint);
        return -1;
    }
    close(fd);
    close(directory_fd);

    /* Identical images are a no-op rollback. Prefer the before side so the
     * caller releases its prepared account transaction through abort. */
    *state = before_matches ? CONFIG_ACTIVE_ROLLBACK_BEFORE_DURABLE
                            : CONFIG_ACTIVE_ROLLBACK_POST_DURABLE;
    clear_error();
    errno = 0;
    return 0;
}

int config_resume_hint_snapshot_settle(
    const config_resume_hint_snapshot_t *snapshot,
    config_active_rollback_state_t *state) {
    char config_path[MAX_PATH_LEN];
    int write_lock_fd;
    int restore_result;
    int classify_result;

    if (state) *state = CONFIG_ACTIVE_ROLLBACK_UNRESOLVED;
    if (!snapshot || !state) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Active-state settlement requires a snapshot and result");
        return -1;
    }
    if (config_get_path(config_path, sizeof(config_path)) != 0) {
        return -1;
    }
    write_lock_fd = config_write_lock_path(config_path);
    if (write_lock_fd < 0) {
        return -1;
    }

    restore_result = snapshot->post_image_bound
        ? config_resume_hint_snapshot_restore_at(config_path, snapshot)
        : 0;
    classify_result = config_resume_hint_snapshot_classify_at(
        config_path, snapshot, state);
    config_write_unlock(write_lock_fd);

    if (classify_result == 0 &&
        *state != CONFIG_ACTIVE_ROLLBACK_UNRESOLVED) {
        /* The classifier re-proved and synchronized a complete owned image.
         * A preceding restore diagnostic is no longer an unresolved state. */
        (void)restore_result;
        clear_error();
        errno = 0;
        return 0;
    }
    *state = CONFIG_ACTIVE_ROLLBACK_UNRESOLVED;
    return -1;
}

static bool config_retirement_refresh_owns_record(
    const config_retirement_refresh_request_t *request,
    const publication_record_t *record) {
    for (size_t i = 0; i < request->owner_count; i++) {
        if (request->owners[i].account_id == record->account_id &&
            strcmp(request->owners[i].account_incarnation,
                   record->account_incarnation) == 0) {
            return true;
        }
    }
    return false;
}

static bool config_retirement_identity_is_canonical_absence(
    const publication_identity_t *identity) {
    return identity && !identity->present &&
           identity->device == 0U && identity->inode == 0U &&
           identity->mode == 0U && identity->uid == 0U &&
           identity->gid == 0U && identity->link_count == 0U &&
           identity->size == 0U && identity->mtime_seconds == 0 &&
           identity->mtime_nanoseconds == 0U &&
           identity->ctime_seconds == 0 &&
           identity->ctime_nanoseconds == 0U;
}

/* A reverse retirement publish can restore the exact prior Git bytes through
 * a newly materialized inode generation. Refresh only that generation field.
 * A canonical absent input is an exact-set witness rather than a serializable
 * generation; preserve each matching record's prior post_config identity.
 * The owner/destination witnesses and every unrelated record remain intact.
 * Inputs are treated as an exact set so a truncated caller result cannot make
 * a partially refreshed ledger look complete. */
static int config_apply_retirement_publication_refresh(
    publication_ledger_t *publications,
    const config_retirement_refresh_request_t *request) {
    bool destination_used[PUBLICATION_LEDGER_MAX_RECORDS] = {false};
    size_t matching_records = 0;

    if (!publications || !request || !request->owners ||
        request->owner_count == 0U ||
        request->owner_count > MAX_ACCOUNTS || !request->destinations ||
        request->destination_count == 0U ||
        request->destination_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid retirement publication refresh set");
        return -1;
    }
    for (size_t i = 0; i < request->destination_count; i++) {
        size_t path_length = strnlen(request->destinations[i].config_path,
                                    MAX_PATH_LEN);
        if (path_length == 0U || path_length >= MAX_PATH_LEN) {
            errno = EINVAL;
            set_error(ERR_INVALID_ARGS,
                      "Retirement publication destination %zu has an invalid config path",
                      i);
            return -1;
        }
        if (!request->destinations[i].post_config.present &&
            !config_retirement_identity_is_canonical_absence(
                &request->destinations[i].post_config)) {
            errno = EINVAL;
            set_error(
                ERR_INVALID_ARGS,
                "Retirement publication destination %zu has a noncanonical absent identity",
                i);
            return -1;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(request->destinations[i].config_path,
                       request->destinations[j].config_path) == 0) {
                errno = EINVAL;
                set_error(ERR_INVALID_ARGS,
                          "Retirement publication refresh contains duplicate config path %s",
                          request->destinations[i].config_path);
                return -1;
            }
        }
    }

    for (size_t i = 0; i < publications->count; i++) {
        publication_record_t *record = &publications->records[i];
        size_t destination_index = request->destination_count;

        if (record->state != PUBLICATION_STATE_PUBLISHED ||
            !config_retirement_refresh_owns_record(request, record)) {
            continue;
        }
        for (size_t j = 0; j < request->destination_count; j++) {
            if (strcmp(record->config_path,
                       request->destinations[j].config_path) == 0) {
                destination_index = j;
                break;
            }
        }
        if (destination_index == request->destination_count) {
            errno = ESTALE;
            set_error(ERR_CONFIG_INVALID,
                      "Retirement publication refresh is missing Git config destination %s",
                      record->config_path);
            return -1;
        }
        if (request->destinations[
                destination_index].post_config.present) {
            record->post_config =
                request->destinations[
                    destination_index].post_config;
        }
        if (publication_record_validate(record) != 0) {
            return -1;
        }
        destination_used[destination_index] = true;
        matching_records++;
    }
    if (matching_records == 0U) {
        errno = ESTALE;
        set_error(ERR_CONFIG_INVALID,
                  "Retirement publication refresh found no matching PUBLISHED owner records");
        return -1;
    }
    for (size_t i = 0; i < request->destination_count; i++) {
        if (!destination_used[i]) {
            errno = ESTALE;
            set_error(ERR_CONFIG_INVALID,
                      "Retirement publication refresh destination is not owned by the requested records: %s",
                      request->destinations[i].config_path);
            return -1;
        }
    }
    return 0;
}

/* Active-state publication admission retains the caller-selected
 * accounts.toml generation policy, then re-proves the exact active-state
 * before-image. The replacement path uses this shared contract at its final
 * pre-rename boundary; the byte-identical durability retry invokes it on both
 * sides of its directory sync so that no-op can report success only for the
 * same source and state generations it admitted. */
static int config_require_resume_hint_generations(
    const gitswitch_ctx_t *ctx, const char *config_path,
    config_source_generation_requirement_t generation_requirement,
    const char *hint, const config_active_state_generation_t *state_before) {
    if (generation_requirement == CONFIG_SOURCE_GENERATION_REQUIRE_LOADED) {
        if (config_require_loaded_source_generation(
                ctx, config_path, NULL) != 0) {
            return -1;
        }
    } else if (generation_requirement ==
               CONFIG_SOURCE_GENERATION_REQUIRE_FULL_SAVE) {
        if (config_admit_full_save_generation(ctx, config_path) != 0) {
            return -1;
        }
    } else if (generation_requirement != CONFIG_SOURCE_GENERATION_UNBOUND) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid source-generation requirement for active-state commit");
        return -1;
    }
    return config_require_active_state_generation(hint, state_before);
}

/* Atomically replace the consolidated active-state artifact. Its first line
 * keeps the exact legacy runtime-needs contract consumed by generated shell
 * code; its second line records either active=<name> or the versioned inactive
 * tombstone that prevents a stale legacy settings key from being resurrected. */
static int config_update_resume_hint(const gitswitch_ctx_t *ctx,
                                     const char *config_path,
                                     bool *state_installed,
                                     config_source_generation_requirement_t
                                         generation_requirement,
                                     config_resume_hint_snapshot_t *rollback_snapshot,
                                     const publication_record_t *publication,
                                     const config_retirement_refresh_request_t
                                         *retirement_refresh) {
    config_active_state_t existing_state;
    config_active_state_generation_t state_before = {0};
    publication_ledger_t publications;
    const account_t *active_account = NULL;
    const char *needs;
    char header[MAX_NAME_LEN + 32U];
    unsigned char *ledger_bytes = NULL;
    size_t ledger_length = 0U;
    unsigned char *content = NULL;
    size_t length = 0U;
    char dir[MAX_PATH_LEN];
    char hint[MAX_PATH_LEN];
    char temp[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat temp_identity;
    struct stat after;
    bool have_temp_identity = false;
    bool temp_registered = false;
    int result = -1;
    int fd = -1;

    publication_ledger_init(&publications);

    if (state_installed) {
        *state_installed = false;
    }
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to active-state commit");
        return -1;
    }
    if (rollback_snapshot &&
        config_resume_hint_snapshot_bind_post_image(
            config_path, rollback_snapshot) != 0) {
        return -1;
    }
    if (generation_requirement == CONFIG_SOURCE_GENERATION_REQUIRE_LOADED) {
        if (config_require_loaded_source_generation(
                ctx, config_path, NULL) != 0) {
            return -1;
        }
    } else if (generation_requirement ==
               CONFIG_SOURCE_GENERATION_REQUIRE_FULL_SAVE) {
        if (config_admit_full_save_generation(ctx, config_path) != 0) {
            return -1;
        }
    } else if (generation_requirement != CONFIG_SOURCE_GENERATION_UNBOUND) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid source-generation requirement for active-state commit");
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
    {
        const char *cleanup_target =
            strrchr(hint, '/') ? strrchr(hint, '/') + 1 : hint;
        int cleanup_fd = open(
            dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        int cleanup_errno;

        if (cleanup_fd < 0 ||
            signals_scratch_cleanup_identities_at(
                cleanup_fd, dir) != 0 ||
            config_reconcile_settled_aliases_at(
                cleanup_fd, cleanup_target,
                CONFIG_RESUME_HINT_SETTLED_PREFIX,
                CONFIG_RESUME_HINT_TEMP_PREFIX,
                CONFIG_RESUME_HINT_TEMP_SUFFIX_LENGTH) != 0) {
            cleanup_errno = errno ? errno : EIO;
            if (cleanup_fd >= 0) (void)close(cleanup_fd);
            errno = cleanup_errno;
            set_system_error(
                ERR_FILE_IO,
                "Cannot settle tracked config temporary aliases");
            return -1;
        }
        (void)close(cleanup_fd);
    }
    if (config_read_active_state(config_path, &existing_state, false,
                                 &state_before, &publications) != 0) {
        goto state_cleanup;
    }
    if (rollback_snapshot &&
        config_resume_hint_snapshot_require_before_image(
            hint, rollback_snapshot, &state_before) != 0) {
        goto state_cleanup;
    }

    /* A full account-model save is the causal boundary that makes deletion
     * durable. Preserve every deleted account's record as a non-authorizing
     * tombstone instead of leaving it published under a reusable integer. The
     * state file is installed first and restored from its exact before-image
     * when accounts.toml does not install, so this transition commits or rolls
     * back with the deletion. A load that skipped account sections is not a
     * complete ownership view and therefore cannot classify any record as
     * orphaned. */
    if (generation_requirement == CONFIG_SOURCE_GENERATION_REQUIRE_FULL_SAVE &&
        ctx->accounts_skipped_on_load == 0U) {
        for (size_t i = 0; i < publications.count; i++) {
            bool account_present = false;
            for (size_t j = 0; j < ctx->account_count; j++) {
                if (ctx->accounts[j].incarnation_persisted &&
                    ctx->accounts[j].id ==
                        publications.records[i].account_id &&
                    strcmp(ctx->accounts[j].incarnation,
                           publications.records[i].account_incarnation) == 0) {
                    account_present = true;
                    break;
                }
            }
            if (!account_present) {
                publications.records[i].state = PUBLICATION_STATE_RETIRING;
            }
        }
    }
    if (retirement_refresh &&
        config_apply_retirement_publication_refresh(
            &publications, retirement_refresh) != 0) {
        goto state_cleanup;
    }
    if (retirement_refresh) {
        /* Git rollback reconciliation runs after the caller has already
         * mutated its in-memory remove/reset model.  Rebuilding this header
         * from `ctx` would therefore publish that uncommitted model even
         * though the outer save failed before installation.  Preserve the
         * stable on-disk header semantically and change only the matching
         * publication generations below. */
        if (!existing_state.exists || existing_state.legacy_needs_only) {
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "Retirement publication refresh requires a versioned active-state header");
            goto state_cleanup;
        }
        if (existing_state.inactive_tombstone) {
            if (safe_strncpy(header, "none\ninactive=v1\n",
                             sizeof(header)) != 0) {
                goto state_cleanup;
            }
        } else if (existing_state.active_account[0] == '\0' ||
                   (size_t)snprintf(header, sizeof(header),
                                    "%s\nactive=%s\n",
                                    existing_state.needs,
                                    existing_state.active_account) >=
                       sizeof(header)) {
            errno = ESTALE;
            set_error(ERR_CONFIG_INVALID,
                      "Retirement publication refresh found an invalid active-state header");
            goto state_cleanup;
        }
    } else if (ctx->config.active_account[0] == '\0') {
        if (safe_strncpy(header, "none\ninactive=v1\n",
                         sizeof(header)) != 0) {
            goto state_cleanup;
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
            goto state_cleanup;
        }
        if (!active_account) {
            set_error(ERR_CONFIG_INVALID,
                      "Refusing to persist missing active account '%s'",
                      ctx->config.active_account);
            goto state_cleanup;
        }
        bool wants_ssh = active_account->ssh_enabled &&
                         active_account->ssh_key_path[0] != '\0';
        bool wants_gpg = active_account->gpg_enabled &&
                         active_account->gpg_key_id[0] != '\0';
        if (wants_ssh && wants_gpg)      needs = "ssh gpg";
        else if (wants_ssh)              needs = "ssh";
        else if (wants_gpg)              needs = "gpg";
        else                             needs = "none";
        if ((size_t)snprintf(header, sizeof(header), "%s\nactive=%s\n",
                             needs, active_account->name) >= sizeof(header)) {
            set_error(ERR_CONFIG_INVALID, "Active-state content is too long");
            goto state_cleanup;
        }
    }

    if (publication) {
        /* An at-capacity ledger blocks only genuinely new destinations. An
         * exact destination replacement never grows the ledger.  v1 records
         * are not automatically reclaimed from filesystem observations:
         * rename-away/restore is indistinguishable from permanent removal.
         * This enforces the same RECORD-count cap the preflight
         * (config_publication_preflight_check) admits against; it does not
         * re-run the preflight's byte-reserve check here, because the count cap
         * and PUBLICATION_LEDGER_MAX_BYTES are jointly satisfiable (the P4
         * dismissal), so an admitted count can always be serialized. The byte
         * reserve remains a conservative capacity gate. */
        if (!publication_ledger_destination_present(&publications,
                                                    publication)) {
            bool exhausted =
                publications.count >= PUBLICATION_LEDGER_MAX_RECORDS;

            if (!exhausted) {
                unsigned char *trial = NULL;
                size_t trial_length = 0U;

                if (publication_ledger_serialize(&publications, &trial,
                                                 &trial_length) != 0) {
                    goto state_cleanup;
                }
                exhausted =
                    CONFIG_PUBLICATION_RECORD_RESERVE >
                        PUBLICATION_LEDGER_MAX_BYTES ||
                    trial_length > PUBLICATION_LEDGER_MAX_BYTES -
                                       CONFIG_PUBLICATION_RECORD_RESERVE;
                secure_zero_memory(trial, trial_length);
                free(trial);
            }
            if (exhausted) {
                errno = ENOSPC;
                set_error(
                    ERR_CONFIG_INVALID,
                    "Publication ledger has no capacity for a new destination");
                goto state_cleanup;
            }
        }
        if (publication_ledger_upsert(&publications, publication) != 0) {
            goto state_cleanup;
        }
    }
    if (publication_ledger_serialize(&publications, &ledger_bytes,
                                     &ledger_length) != 0) {
        goto state_cleanup;
    }
    if (strlen(header) > CONFIG_ACTIVE_STATE_MAX ||
        ledger_length > CONFIG_ACTIVE_STATE_MAX - strlen(header)) {
        set_error(ERR_CONFIG_INVALID,
                  "Active-state publication bundle exceeds byte limit");
        goto state_cleanup;
    }
    length = strlen(header) + ledger_length;
    content = malloc(length == 0U ? 1U : length);
    if (!content) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate active-state publication bundle");
        goto state_cleanup;
    }
    memcpy(content, header, strlen(header));
    if (ledger_length != 0U) {
        memcpy(content + strlen(header), ledger_bytes, ledger_length);
    }
    if (state_before.existed && state_before.length == length &&
        memcmp(state_before.data, content, length) == 0) {
        /* AR-13 M1 (AR-12 M6 class): the on-disk bytes already match, but a
         * prior write may have installed them and then failed its directory
         * fsync — returning -1 with the content cache-visible yet not durable.
         * Returning success here without re-proving durability would convert
         * that uncertain state into a reported-durable success on retry. Re-sync
         * the parent directory (the same commit the mutation path performs)
         * before treating the no-op as committed. Re-prove both retained
         * generations on each side of the sync because the public fault
         * boundary may expose a later writer. */
        if (config_require_resume_hint_generations(
                ctx, config_path, generation_requirement, hint,
                &state_before) != 0) {
            goto state_cleanup;
        }
        int dir_fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (dir_fd < 0 ||
            config_io_fault(CONFIG_IO_STATE_BEFORE_DIR_SYNC,
                            "active-state directory sync") ||
            fsync(dir_fd) != 0) {
            int saved_errno = errno;
            if (dir_fd >= 0) close(dir_fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot durably commit resume hint: %s", hint);
            goto state_cleanup;
        }
        close(dir_fd);
        if (config_require_resume_hint_generations(
                ctx, config_path, generation_requirement, hint,
                &state_before) != 0) {
            goto state_cleanup;
        }
        result = 0;
        goto state_cleanup;
    }
    /* Reserve the exact post-image before entering the mutation phase. A
     * post-rename allocation failure would otherwise leave an installed state
     * that the guarded rollback snapshot could not identify safely. */
    if (rollback_snapshot) {
        rollback_snapshot->post_image_data = malloc(length == 0U ? 1U : length);
        if (!rollback_snapshot->post_image_data) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot allocate active-state post-image witness");
            goto state_cleanup;
        }
        memcpy(rollback_snapshot->post_image_data, content, length);
        rollback_snapshot->post_image_length = length;
    }

    /* Never open the destination for writing. The validated reader above
     * retained strict metadata plus every bounded before-image byte. Build a
     * fresh inode beside it, then re-prove that exact generation after the
     * public pre-rename checkpoint. */
    if ((size_t)snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", hint) >= sizeof(temp)) {
        set_error(ERR_INVALID_PATH, "Resume hint temporary path is too long");
        goto state_cleanup;
    }

    fd = mkstemp(temp);
    if (fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot create temporary resume hint: %s", hint);
        goto state_cleanup;
    }
    if (fchmod(fd, PERM_USER_RW) != 0 ||
        fstat(fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        set_system_error(ERR_FILE_IO,
                         "Cannot secure temporary resume hint: %s", temp);
        goto hint_fail;
    }
    have_temp_identity = true;
    if (signals_scratch_register(temp) != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot register active-state temporary file for cleanup");
        goto hint_fail;
    }
    temp_registered = true;
    if (config_io_fault(CONFIG_IO_STATE_AFTER_TEMP,
                        "active-state temp creation")) {
        goto hint_fail;
    }

    size_t total = 0;
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
    if (config_io_fault(CONFIG_IO_STATE_BEFORE_RENAME,
                        "active-state rename")) {
        set_system_error(ERR_FILE_IO,
                         "Cannot install resume hint atomically: %s", hint);
        goto hint_fail;
    }
    if (config_require_resume_hint_generations(
            ctx, config_path, generation_requirement, hint,
            &state_before) != 0) {
        goto hint_fail;
    }
    {
        const char *temp_name =
            strrchr(temp, '/') ? strrchr(temp, '/') + 1 : temp;
        const char *hint_name =
            strrchr(hint, '/') ? strrchr(hint, '/') + 1 : hint;
        int directory_fd = open(
            dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        int publish_result = -1;
        struct stat retained_source = {0};
        bool publish_committed = false;

        if (directory_fd >= 0 &&
            fstatat(
                directory_fd, temp_name, &temp_identity,
                AT_SYMLINK_NOFOLLOW) == 0 &&
            config_metadata_file_is_safe(&temp_identity, true)) {
            if (state_before.existed) {
                publish_result = config_replace_exact_name_at(
                    directory_fd, temp_name, &temp_identity,
                    content, length, hint_name,
                    &state_before.metadata, state_before.data,
                    state_before.length,
                    CONFIG_RESUME_HINT_SETTLED_PREFIX, &after,
                    &publish_committed);
            } else {
                publish_result = config_publish_noreplace_at(
                    directory_fd, temp_name, hint_name,
                    &temp_identity, &retained_source);
                if ((publish_result ==
                         CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED ||
                     publish_result ==
                         CONFIG_PUBLISH_OUTCOME_UNCERTAIN) &&
                    retained_source.st_nlink != 0 &&
                    config_retire_or_track_scratch_at(
                        directory_fd, dir, temp_name, temp,
                        hint_name, &retained_source, content, length,
                        CONFIG_RESUME_HINT_SETTLED_PREFIX) != 0) {
                    int retirement_errno = errno ? errno : EIO;

                    publish_committed = true;
                    if (directory_fd >= 0) (void)close(directory_fd);
                    if (state_installed) *state_installed = true;
                    if (rollback_snapshot) {
                        rollback_snapshot->post_image_installed = true;
                    }
                    errno = retirement_errno;
                    set_system_error(
                        ERR_FILE_IO,
                        "Resume hint was installed but its exact temporary alias could not be retired: %s",
                        temp);
                    /* Identity-bound cleanup remains registered if the
                     * serialized retry also failed. */
                    goto state_cleanup;
                }
                if (publish_result ==
                        CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED ||
                    (publish_result ==
                         CONFIG_PUBLISH_OUTCOME_UNCERTAIN &&
                     retained_source.st_nlink != 0)) {
                    temp_registered = false;
                }
            }
        }
        {
            int publish_errno = errno;

            if (directory_fd >= 0) (void)close(directory_fd);
            errno = publish_errno;
        }
        if (publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
            publish_committed = true;
            errno = EINPROGRESS;
            if (temp_registered) {
                /* No exact source alias survived publication. A substituted
                 * random pathname is not cleanup authority. */
                signals_scratch_unregister(temp);
                temp_registered = false;
            }
        }
        if (publish_result < 0 ||
            publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
            if (publish_committed) {
                if (state_installed) *state_installed = true;
                if (rollback_snapshot) {
                    rollback_snapshot->post_image_installed = true;
                }
            }
            set_system_error(
                ERR_FILE_IO,
                "Cannot install resume hint atomically: %s", hint);
            if (publish_committed) goto state_cleanup;
            goto hint_fail;
        }
    }
    signals_scratch_unregister(temp);
    temp_registered = false;
    if (state_installed) {
        *state_installed = true;
    }
    if (rollback_snapshot) {
        rollback_snapshot->post_image_installed = true;
    }

    if (lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_same_file(&temp_identity, &after)) {
        set_error(ERR_FILE_IO,
                  "Cannot verify installed resume hint: %s", hint);
        goto state_cleanup;
    }
    if (rollback_snapshot) {
        rollback_snapshot->post_image = after;
        rollback_snapshot->post_image_valid = true;
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
            goto state_cleanup;
        }
        close(dir_fd);
    }
    if (rollback_snapshot) {
        if (!config_resume_hint_post_image_is_current(hint,
                                                      rollback_snapshot)) {
            set_error(ERR_FILE_IO,
                      "Installed resume-hint generation changed during durability commit: %s",
                      hint);
            goto state_cleanup;
        }
    }
    result = 0;
    goto state_cleanup;

hint_fail:
    if (fd >= 0) close(fd);
    config_unlink_created_temp(temp, &temp_identity, have_temp_identity);
    if (temp_registered) signals_scratch_unregister(temp);

state_cleanup:
    if (content) {
        secure_zero_memory(content, length);
        free(content);
    }
    if (ledger_bytes) {
        secure_zero_memory(ledger_bytes, ledger_length);
        free(ledger_bytes);
    }
    publication_ledger_clear(&publications);
    config_active_state_generation_clear(&state_before);
    return result;
}

/* Shared atomic-write tail for config_save and config_save_active_account:
 * validate the destination, back up the existing file, write doc to a fresh
 * 0600 temp, rename it into place, refresh the resume hint. */
/* AR-12 L7: the former make_backup/update_hint parameters are gone — every
 * caller passed true/false, and the dead update_hint branch was the only
 * site publishing CONFIG_SOURCE_GENERATION_UNBOUND state, a latent bypass
 * of the M5/M6 generation binding waiting for a future caller to flip it. */
static int config_write_document_atomic(gitswitch_ctx_t *ctx,
                                        const toml_document_t *doc,
                                        const char *config_path,
                                        bool *config_installed,
                                        struct stat *committed_generation) {
    char dir_path[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN];
    char temp_name[MAX_PATH_LEN];
    char temp_prefix[MAX_PATH_LEN];
    char create_prefix[MAX_PATH_LEN];
    const char *slash;
    const char *target_name;
    struct stat pinned_dir;
    struct stat destination_before;
    struct stat destination_now;
    struct stat installed_generation;
    struct stat temp_identity;
    struct stat temp_generation;
    struct stat temp_now;
    struct stat retained_source;
    unsigned char *document_bytes = NULL;
    size_t document_length = 0;
    bool destination_existed = false;
    bool temp_exists = false;
    bool temp_registered = false;
    bool have_temp_identity = false;
    bool directory_sync_failed = false;
    bool document_committed = false;
    int publish_result = CONFIG_PUBLISH_MOVED;
    int directory_sync_errno = 0;
    int dir_fd = -1;
    int temp_fd = -1;

    if (config_installed) {
        *config_installed = false;
    }
    if (committed_generation) {
        memset(committed_generation, 0, sizeof(*committed_generation));
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
    if ((size_t)snprintf(
            temp_prefix, sizeof(temp_prefix), "%s.tmp.",
            target_name) >= sizeof(temp_prefix)) {
        errno = ENAMETOOLONG;
        set_error(
            ERR_INVALID_PATH,
            "Config temporary prefix is too long");
        return -1;
    }
    if ((size_t)snprintf(
            create_prefix, sizeof(create_prefix), "%s.create.",
            target_name) >= sizeof(create_prefix)) {
        errno = ENAMETOOLONG;
        set_error(
            ERR_INVALID_PATH,
            "Config creation prefix is too long");
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
    if (dir_fd < 0 || fstat(dir_fd, &pinned_dir) != 0) {
        int saved_errno = errno;
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot pin config destination directory: %s",
                         dir_path);
        return -1;
    }
    {
        bool forced_mismatch =
            g_config_metadata_test_hook &&
            g_config_metadata_test_hook(CONFIG_METADATA_TEST_DOCUMENT_DIR);
        errno = 0;
        if (forced_mismatch || !config_metadata_dir_is_safe(&pinned_dir) ||
            !config_named_directory_matches(dir_path, &pinned_dir)) {
            int saved_errno = errno ? errno : ESTALE;
            close(dir_fd);
            errno = saved_errno;
            set_system_error(ERR_CONFIG_WRITE_FAILED,
                             "Cannot pin config destination directory: %s",
                             dir_path);
            return -1;
        }
    }
    if (signals_scratch_cleanup_identities_at(
            dir_fd, dir_path) != 0 ||
        config_reconcile_settled_aliases_at(
            dir_fd, target_name,
            CONFIG_DOCUMENT_SETTLED_PREFIX,
            temp_prefix, 0U) != 0 ||
        config_reconcile_settled_aliases_at(
            dir_fd, target_name,
            CONFIG_DOCUMENT_SETTLED_PREFIX,
            create_prefix, 16U) != 0) {
        int saved_errno = errno ? errno : EIO;

        close(dir_fd);
        errno = saved_errno;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Cannot settle tracked config document aliases");
        return -1;
    }
    errno = 0;
    if (fstatat(dir_fd, target_name, &destination_before,
                AT_SYMLINK_NOFOLLOW) == 0) {
        destination_existed = true;
    } else if (errno != ENOENT) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot identify config destination: %s", config_path);
        goto document_fail;
    }
    /* The state publisher may have run callbacks and a directory sync since
     * full-save admission. Tie this first pinned-directory destination snapshot
     * back to the caller's loaded generation (or proven first-save absence)
     * before backups or document temporaries create any side effects. */
    if (config_require_full_save_generation_snapshot(
            ctx, config_path, destination_existed,
            destination_existed ? &destination_before : NULL) != 0) {
        goto document_fail;
    }
    if (destination_existed &&
        !config_metadata_file_is_safe(&destination_before, false)) {
        errno = EPERM;
        set_error(ERR_PERMISSION_DENIED,
                  "Config destination is not a safe owned regular file: %s",
                  config_path);
        goto document_fail;
    }

    /* Create backup if file exists. AR-06 F51: skip it for a settings-only
     * write-back (just active_account), which happens on EVERY switch — the
     * account DATA is unchanged, the write is atomic (temp+rename), and backing
     * up on each switch churned five backups for five switches, rotating real
     * account-edit backups out of the bounded set. */
    if (destination_existed) {
        if (config_backup_internal(config_path, &destination_before) != 0) {
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
            config_retire_exact_name_at(
                dir_fd, temp_name, &temp_now,
                NULL, 0U,
                CONFIG_DOCUMENT_SETTLED_PREFIX) != 0) {
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
                     O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
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
    if (fstat(temp_fd, &temp_generation) != 0 ||
        !config_metadata_file_is_safe(&temp_generation, true) ||
        !config_metadata_same_file(&temp_identity, &temp_generation) ||
        fstatat(dir_fd, temp_name, &temp_now, AT_SYMLINK_NOFOLLOW) != 0 ||
        !config_metadata_file_is_safe(&temp_now, true) ||
        !config_metadata_snapshot_same(&temp_generation, &temp_now) ||
        temp_generation.st_size < 0 ||
        temp_generation.st_size > (off_t)TOML_MAX_FILE_SIZE) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Temporary config changed before publication: %s",
                         temp_path);
        goto document_fail;
    }
    document_length = (size_t)temp_generation.st_size;
    document_bytes = malloc(document_length ? document_length : 1U);
    if (!document_bytes) {
        errno = ENOMEM;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot snapshot temporary config before publication: %s",
                         temp_path);
        goto document_fail;
    }
    if (!config_pread_full(temp_fd, document_bytes, document_length, 0)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Cannot snapshot temporary config before publication: %s",
                         temp_path);
        goto document_fail;
    }
    {
        unsigned char trailing;
        ssize_t trailing_count;

        errno = 0;
        do {
            trailing_count = pread(temp_fd, &trailing, 1,
                                   (off_t)document_length);
        } while (trailing_count < 0 && errno == EINTR);
        if (trailing_count != 0 ||
            fstat(temp_fd, &temp_now) != 0 ||
            !config_metadata_snapshot_same(&temp_generation, &temp_now) ||
            fstatat(dir_fd, temp_name, &temp_now,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !config_metadata_snapshot_same(&temp_generation, &temp_now)) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_CONFIG_WRITE_FAILED,
                "Temporary config changed while snapshotting publication bytes: %s",
                temp_path);
            goto document_fail;
        }
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

    /* The internal destination lock serializes every supported writer. After
     * the final exact before-image proof, renameat is the cross-platform
     * commit point. Its success is latched separately from later proof and
     * durability state so a completed install is never reported as absent. */
    if (config_io_fault(CONFIG_IO_DOCUMENT_BEFORE_RENAME,
                        "config document rename")) {
        goto document_fail;
    }
    if (destination_existed) {
        publish_result = config_replace_exact_name_at(
            dir_fd, temp_name, &temp_generation,
            document_bytes, document_length, target_name,
            &destination_before, NULL, 0U,
            CONFIG_DOCUMENT_SETTLED_PREFIX,
            &destination_now, &document_committed);
    } else {
        publish_result = config_publish_noreplace_at(
            dir_fd, temp_name, target_name, &temp_generation,
            &retained_source);
        if (publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
            document_committed = true;
            errno = EINPROGRESS;
        }
    }
    if ((publish_result ==
             CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED ||
         publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) &&
        retained_source.st_nlink != 0 &&
        config_retire_or_track_scratch_at(
            dir_fd, dir_path, temp_name, temp_path,
            target_name, &retained_source,
            document_bytes, document_length,
            CONFIG_DOCUMENT_SETTLED_PREFIX) != 0) {
        document_committed = true;
        if (config_installed) *config_installed = true;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Config document was installed but its exact temporary alias could not be retired");
        /* temp_exists and temp_registered deliberately remain true. The
         * failure path retries exact retirement and otherwise preserves
         * tracked cleanup ownership for the installed random alias. */
        goto document_fail;
    }
    if (publish_result ==
            CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED ||
        (publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN &&
         retained_source.st_nlink != 0)) {
        temp_exists = false;
        temp_registered = false;
    }
    if (publish_result < 0 ||
        publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                        "Failed to move temporary config file to final location");
        if (document_committed) {
            if (config_installed) *config_installed = true;
        }
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
        int proof_errno = errno ? errno : ESTALE;
        if (config_is_namespace_change_errno(proof_errno)) {
            proof_errno = ESTALE;
        }
        errno = proof_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Installed config failed identity verification: %s",
                         config_path);
        goto document_fail;
    }
    installed_generation = destination_now;

    /* AR-05 L11: per POSIX a rename() is only durable once the directory
     * holding the new entry is itself fsynced. Keep the sync result separate
     * from the final canonical proof: even when fsync fails, callers need to
     * know whether the exact renamed generation remains selected at
     * config_path. */
    if (config_io_fault(CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC,
                        "config document directory sync")) {
        directory_sync_failed = true;
        directory_sync_errno = errno ? errno : EIO;
    } else if (fsync(dir_fd) != 0) {
        directory_sync_failed = true;
        directory_sync_errno = errno ? errno : EIO;
    }

    /* The original descriptor may now name a detached directory. Re-open the
     * canonical parent and prove that it still selects the pinned parent and
     * the exact installed file generation. A later namespace mismatch means
     * the committed generation is no longer current; it does not undo the
     * rename commit or authorize outer rollback. */
    if (config_io_fault(
            CONFIG_IO_DOCUMENT_REPROOF_AFTER_BYTES,
            "config document exact-byte reproof")) {
        errno = errno ? errno : EIO;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Canonical config generation could not be re-proved: %s",
            config_path);
        goto document_fail;
    }
    errno = 0;
    if (config_reprove_canonical_publication(
            dir_path, &pinned_dir, target_name, &installed_generation,
            document_bytes, document_length, &destination_now) != 0) {
        int proof_errno = errno ? errno : EIO;
        if (proof_errno == ESTALE && config_installed) {
            *config_installed = false;
        }
        errno = proof_errno;
        set_system_error(
            proof_errno == ESTALE ? ERR_FILE_IO : ERR_CONFIG_WRITE_FAILED,
            "Canonical config generation changed before context refresh: %s",
            config_path);
        goto document_fail;
    }

    /* A pure sync failure leaves an exact canonical generation visible but
     * with uncertain crash durability. Preserve installed=true so outer
     * settlement retains the matching state and requires a reload/retry. */
    if (directory_sync_failed) {
        errno = directory_sync_errno;
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Could not durably commit config directory: %s",
                         dir_path);
        goto document_fail;
    }

    /* Capture the context's next admission generation only after the payload
     * and directory entry are both durable and canonically selected. A sync
     * failure or later canonical mismatch preserves the latched install
     * disposition but deliberately leaves the caller bound to its old
     * generation until it reloads. */
    if (committed_generation) {
        *committed_generation = destination_now;
    }
    secure_zero_memory(ctx->config.source_witness,
                       sizeof(ctx->config.source_witness));
    if (document_length != 0U) {
        memcpy(ctx->config.source_witness, document_bytes, document_length);
    }
    ctx->config.source_witness_length = document_length;
    ctx->config.source_witness_valid = true;
    ctx->config.source_read_witness_valid = false;
    secure_zero_memory(document_bytes, document_length);
    free(document_bytes);
    document_bytes = NULL;
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
                if (config_retire_exact_name_at(
                        dir_fd, temp_name, &cleanup_identity,
                        NULL, 0U,
                        CONFIG_DOCUMENT_SETTLED_PREFIX) == 0) {
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
        if (document_bytes) {
            secure_zero_memory(document_bytes, document_length);
            free(document_bytes);
        }
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
static int config_save_mode(gitswitch_ctx_t *ctx,
                            const char *config_path,
                            bool update_hint,
                            bool *config_installed,
                            config_resume_hint_snapshot_t *rollback_snapshot,
                            const publication_record_t *publication) {
    config_resume_hint_snapshot_t local_state_before = {0};
    config_resume_hint_snapshot_t *state_before = rollback_snapshot
        ? rollback_snapshot : &local_state_before;
    toml_document_t *toml_doc = NULL;
    publication_ledger_t incarnation_reservations;
    char incarnation_before[MAX_ACCOUNTS][ACCOUNT_INCARNATION_LEN] = {{0}};
    bool incarnation_persisted_before[MAX_ACCOUNTS] = {false};
    size_t incarnation_before_count = 0U;
    bool incarnation_before_valid = false;
    bool document_installed = false;
    bool state_installed = false;
    struct stat committed_generation;
    int write_lock_fd = -1;
    int result = -1;

    publication_ledger_init(&incarnation_reservations);

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save");
        return -1;
    }
    if (ctx->account_count > MAX_ACCOUNTS) {
        set_error(ERR_CONFIG_INVALID,
                  "Account model exceeds the supported account limit");
        return -1;
    }
    incarnation_before_count = ctx->account_count;
    for (size_t i = 0; i < incarnation_before_count; i++) {
        memcpy(incarnation_before[i], ctx->accounts[i].incarnation,
               ACCOUNT_INCARNATION_LEN);
        incarnation_persisted_before[i] =
            ctx->accounts[i].incarnation_persisted;
    }
    incarnation_before_valid = true;
    if (config_installed) {
        *config_installed = false;
    }
    write_lock_fd = config_write_lock_path(config_path);
    if (write_lock_fd < 0) {
        return -1;
    }

    if (config_admit_full_save_generation(ctx, config_path) != 0) {
        goto cleanup;
    }

    /* GIT_SCOPE_SYSTEM remains part of the public observation model because
     * Git may report values originating there. It is not a persistable
     * gitswitch preference: the TOML schema and switch transaction support
     * only local/global. Reject the whole model before resume-state capture,
     * backup creation, or any document mutation. */
    if (!config_scope_is_persistable(ctx->config.default_scope)) {
        set_error(ERR_CONFIG_INVALID,
                  "settings.default_scope must be local or global");
        goto cleanup;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (!config_account_id_is_valid(ctx->accounts[i].id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account ID must be in 1..%u", UINT32_MAX);
            goto cleanup;
        }
        if (!config_scope_is_persistable(ctx->accounts[i].preferred_scope)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account %u preferred scope must be local or global",
                      ctx->accounts[i].id);
            goto cleanup;
        }
        if (config_validate_account_model(&ctx->accounts[i]) != 0) {
            goto cleanup;
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
        goto cleanup;
    }

    /* Full account-model publication is the only point that materializes a
     * legacy token. Run every model/rewrite admission first, reserve every
     * incarnation already named by durable Git provenance, and generate all
     * missing candidates off-model before installing the complete set. The
     * cleanup path restores this function's exact in-memory before-image when
     * the account document never installs. */
    if (config_load_publication_ledger(
            config_path, &incarnation_reservations) != 0 ||
        config_validate_live_publication_bindings(
            ctx, &incarnation_reservations) != 0 ||
        config_materialize_missing_incarnations(
            ctx, &incarnation_reservations) != 0) {
        goto cleanup;
    }

    /* Initialize the heap-allocated TOML document exactly once. */
    toml_doc = config_document_alloc();
    if (!toml_doc) {
        goto cleanup;
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
        if ((!rollback_snapshot &&
             config_resume_hint_snapshot_capture_at(config_path,
                                                     state_before) != 0) ||
            (rollback_snapshot &&
             (!rollback_snapshot->valid ||
              strcmp(rollback_snapshot->config_path, config_path) != 0))) {
            if (rollback_snapshot) {
                set_error(ERR_INVALID_ARGS,
                          "Rollback snapshot does not belong to the config path being saved");
            }
            goto cleanup;
        }
        if (config_update_resume_hint(ctx, config_path,
                                      &state_installed,
                                      CONFIG_SOURCE_GENERATION_REQUIRE_FULL_SAVE,
                                      state_before, publication, NULL) != 0) {
            if (state_installed) {
                error_context_t state_error = *get_last_error();
                if (config_resume_hint_snapshot_restore_at(config_path,
                                                           state_before) != 0) {
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
    result = config_write_document_atomic(ctx, toml_doc, config_path,
                                          &document_installed,
                                          &committed_generation);
    if (config_installed) {
        *config_installed = document_installed;
    }
    if (result != 0 && update_hint && state_installed &&
        !document_installed) {
        error_context_t write_error = *get_last_error();
        if (config_resume_hint_snapshot_restore_at(config_path,
                                                   state_before) != 0) {
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
    if (result == 0) {
        memmove(ctx->config.config_path, config_path,
                strlen(config_path) + 1U);
        ctx->config.source_generation = committed_generation;
        ctx->config.source_generation_valid = true;
        for (size_t i = 0; i < ctx->account_count; i++) {
            ctx->accounts[i].incarnation_persisted = true;
        }
    }

cleanup:
    if (result != 0 && !document_installed && incarnation_before_valid) {
        for (size_t i = 0; i < incarnation_before_count; i++) {
            memcpy(ctx->accounts[i].incarnation, incarnation_before[i],
                   ACCOUNT_INCARNATION_LEN);
            ctx->accounts[i].incarnation_persisted =
                incarnation_persisted_before[i];
        }
    }
    secure_zero_memory(incarnation_before, sizeof(incarnation_before));
    if (!rollback_snapshot) {
        config_resume_hint_snapshot_clear(&local_state_before);
    }
    config_document_free(toml_doc);
    publication_ledger_clear(&incarnation_reservations);
    if (write_lock_fd >= 0) {
        config_write_unlock(write_lock_fd);
    }
    return result;
}

int config_save(gitswitch_ctx_t *ctx, const char *config_path) {
    return config_save_mode(ctx, config_path, true, NULL, NULL, NULL);
}

int config_save_transactional(gitswitch_ctx_t *ctx,
                              const char *config_path,
                              bool *config_installed) {
    if (!config_installed) {
        set_error(ERR_INVALID_ARGS,
                  "NULL install-state output for transactional config save");
        return -1;
    }
    *config_installed = false;
    return config_save_mode(ctx, config_path, true, config_installed, NULL,
                            NULL);
}

int config_migrate_account_incarnations(gitswitch_ctx_t *ctx,
                                        const char *config_path,
                                        bool *config_installed) {
    bool migration_required = false;

    if (config_installed) *config_installed = false;
    if (!ctx || !config_path || !config_installed) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account incarnation migration request");
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (!ctx->accounts[i].incarnation_persisted) {
            migration_required = true;
            continue;
        }
        if (!account_incarnation_is_valid(ctx->accounts[i].incarnation)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account %u has invalid persisted incarnation state",
                      ctx->accounts[i].id);
            return -1;
        }
    }
    if (!migration_required) return 0;
    return config_save_transactional(ctx, config_path, config_installed);
}

/* Persist only the consolidated state artifact. This intentionally does not
 * parse or replace accounts.toml: switch/reset state is orthogonal to the
 * account schema and remains writable even when a healthy subset was loaded
 * from a non-reconstructable config. */
static int config_save_active_account_mode(gitswitch_ctx_t *ctx,
                                           const char *config_path,
                                           bool *config_installed,
                                           config_resume_hint_snapshot_t *rollback_snapshot,
                                           const publication_record_t *publication) {
    int write_lock_fd;
    int result;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save_active_account");
        return -1;
    }
    if (config_installed) {
        *config_installed = false;
    }
    write_lock_fd = config_write_lock_path(config_path);
    if (write_lock_fd < 0) {
        return -1;
    }

    /* No file yet: nothing to preserve, and the write-back needs a document
     * to edit — the full rebuild is both safe and required to create one. */
    if (!path_exists(config_path)) {
        result = config_save_mode(ctx, config_path, true,
                                  config_installed, rollback_snapshot,
                                  publication);
    } else {
        result = config_update_resume_hint(ctx, config_path, config_installed,
                                           CONFIG_SOURCE_GENERATION_REQUIRE_LOADED,
                                           rollback_snapshot, publication,
                                           NULL);
    }
    config_write_unlock(write_lock_fd);
    return result;
}

int config_save_active_account(gitswitch_ctx_t *ctx,
                               const char *config_path) {
    return config_save_active_account_mode(ctx, config_path, NULL, NULL,
                                           NULL);
}

int config_save_active_account_transactional(gitswitch_ctx_t *ctx,
                                             const char *config_path,
                                             bool *config_installed) {
    if (!config_installed) {
        set_error(ERR_INVALID_ARGS,
                  "NULL install-state output for transactional active save");
        return -1;
    }
    *config_installed = false;
    return config_save_active_account_mode(ctx, config_path,
                                           config_installed, NULL, NULL);
}

int config_refresh_retirement_publications_transactional(
    gitswitch_ctx_t *ctx, const char *config_path,
    const config_retirement_owner_t *owners, size_t owner_count,
    const config_retirement_destination_t *destinations,
    size_t destination_count, bool *state_installed) {
    config_retirement_owner_t canonical[MAX_ACCOUNTS];
    config_retirement_refresh_request_t request;
    int write_lock_fd;
    int result;
    int saved_errno;

    if (state_installed) *state_installed = false;
    if (!ctx || !config_path || !state_installed || !destinations ||
        destination_count == 0U ||
        destination_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid transactional retirement publication refresh");
        return -1;
    }
    memset(canonical, 0, sizeof(canonical));
    if (config_retirement_canonicalize_owners(
            owners, owner_count, canonical) != 0) {
        secure_zero_memory(canonical, sizeof(canonical));
        return -1;
    }
    request.owners = canonical;
    request.owner_count = owner_count;
    request.destinations = destinations;
    request.destination_count = destination_count;

    write_lock_fd = config_write_lock_path(config_path);
    if (write_lock_fd < 0) {
        secure_zero_memory(canonical, sizeof(canonical));
        return -1;
    }
    result = config_update_resume_hint(
        ctx, config_path, state_installed,
        CONFIG_SOURCE_GENERATION_REQUIRE_LOADED, NULL, NULL, &request);
    saved_errno = result == 0 ? 0 : (errno ? errno : EIO);
    config_write_unlock(write_lock_fd);
    secure_zero_memory(canonical, sizeof(canonical));
    if (result != 0) errno = saved_errno;
    return result;
}

int config_save_active_account_transactional_guarded(
    gitswitch_ctx_t *ctx, const char *config_path,
    bool *config_installed,
    config_resume_hint_snapshot_t *rollback_snapshot) {
    if (!config_installed || !rollback_snapshot ||
        !rollback_snapshot->valid) {
        set_error(ERR_INVALID_ARGS,
                  "Guarded active save requires install state and a valid rollback snapshot");
        return -1;
    }
    *config_installed = false;
    return config_save_active_account_mode(ctx, config_path,
                                           config_installed,
                                           rollback_snapshot, NULL);
}

/* A durable publication record may be installed only for the exact live
 * account selected by the prepared switch. Validate pointer provenance before
 * dereferencing current_account, then bind both the numeric ID and immutable
 * incarnation. This prevents a caller from relabelling a sealed Git post-image
 * as another account or as a later account that reused the same numeric ID. */
static int config_validate_publication_owner(
    const gitswitch_ctx_t *ctx, const publication_record_t *publication) {
    const account_t *owner = NULL;
    size_t pair_matches = 0U;

    if (!ctx || !publication || !ctx->current_account ||
        ctx->account_count > MAX_ACCOUNTS) {
        errno = ESTALE;
        set_error(ERR_CONFIG_INVALID,
                  "Publication save has no live current account owner");
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *candidate = &ctx->accounts[i];

        if (ctx->current_account == candidate) owner = candidate;
        if (candidate->id == publication->account_id &&
            account_incarnation_is_valid(candidate->incarnation) &&
            strcmp(candidate->incarnation,
                   publication->account_incarnation) == 0) {
            pair_matches++;
        }
    }
    if (!owner || pair_matches != 1U || !owner->incarnation_persisted ||
        !account_incarnation_is_valid(owner->incarnation) ||
        owner->id != publication->account_id ||
        strcmp(owner->incarnation,
               publication->account_incarnation) != 0 ||
        ctx->config.active_account[0] == '\0' ||
        strcmp(ctx->config.active_account, owner->name) != 0 ||
        publication->state != PUBLICATION_STATE_PUBLISHED) {
        errno = ESTALE;
        set_error(ERR_CONFIG_INVALID,
                  "Publication record does not belong to the exact live active account incarnation");
        return -1;
    }
    return 0;
}

int config_save_active_account_publication_transactional_guarded(
    gitswitch_ctx_t *ctx, const char *config_path,
    const publication_record_t *publication, bool *config_installed,
    config_resume_hint_snapshot_t *rollback_snapshot) {
    if (config_installed) {
        *config_installed = false;
    }
    if (!publication || !config_installed || !rollback_snapshot ||
        !rollback_snapshot->valid) {
        set_error(
            ERR_INVALID_ARGS,
            "Guarded publication save requires a record, install state, and valid rollback snapshot");
        return -1;
    }
    if (publication_record_validate(publication) != 0) {
        return -1;
    }
    if (config_validate_publication_owner(ctx, publication) != 0) {
        return -1;
    }
    return config_save_active_account_mode(ctx, config_path,
                                           config_installed,
                                           rollback_snapshot, publication);
}

int config_load_publication_ledger(const char *config_path,
                                   publication_ledger_t *ledger) {
    config_active_state_t state;

    if (!config_path || !ledger) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid publication-ledger load arguments");
        return -1;
    }
    return config_read_active_state(config_path, &state, false, NULL,
                                    ledger);
}

/* One worst-case record must fit after the upsert. A destination that already
 * has a ledger record is replaced in place, so its existing record is excluded
 * from the simulation. v1 records are never reclaimed from observational
 * filesystem state; exhaustion therefore fails closed with ENOSPC. */
static int config_publication_preflight_check(
    const char *config_path, const publication_record_t *destination) {
    config_active_state_t state;
    publication_ledger_t ledger;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;
    int result = -1;

    if (!config_path) {
        set_error(ERR_INVALID_ARGS,
                  "NULL config path for publication capacity preflight");
        return -1;
    }
    publication_ledger_init(&ledger);
    if (config_read_active_state(config_path, &state, false, NULL,
                                 &ledger) != 0) {
        goto cleanup;
    }
    if (destination &&
        publication_ledger_destination_present(&ledger, destination)) {
        /* The upsert will replace this record without growing the ledger;
         * remove it from the capacity simulation. */
        size_t kept = 0U;

        for (size_t i = 0U; i < ledger.count; i++) {
            if (publication_record_same_destination(&ledger.records[i],
                                                    destination)) {
                continue;
            }
            if (kept != i) ledger.records[kept] = ledger.records[i];
            kept++;
        }
        if (kept != ledger.count) {
            secure_zero_memory(&ledger.records[kept],
                               (ledger.count - kept) *
                                   sizeof(*ledger.records));
            ledger.count = kept;
        }
    }
    if (publication_ledger_serialize(&ledger, &serialized,
                                     &serialized_length) != 0) {
        goto cleanup;
    }
    if (ledger.count >= PUBLICATION_LEDGER_MAX_RECORDS ||
        CONFIG_PUBLICATION_RECORD_RESERVE > PUBLICATION_LEDGER_MAX_BYTES ||
        serialized_length > PUBLICATION_LEDGER_MAX_BYTES -
                                CONFIG_PUBLICATION_RECORD_RESERVE) {
        errno = ENOSPC;
        set_error(ERR_CONFIG_INVALID,
                  "Publication ledger has no capacity for another worst-case record");
        goto cleanup;
    }
    result = 0;

cleanup:
    if (serialized) {
        secure_zero_memory(serialized, serialized_length);
        free(serialized);
    }
    publication_ledger_clear(&ledger);
    return result;
}

int config_publication_preflight(const char *config_path) {
    return config_publication_preflight_check(config_path, NULL);
}

int config_publication_preflight_destination(
    const char *config_path, const publication_record_t *destination) {
    return config_publication_preflight_check(config_path, destination);
}

int config_restore_active_account(gitswitch_ctx_t *ctx,
                                  const char *config_path) {
    return config_save_active_account_mode(ctx, config_path, NULL, NULL,
                                           NULL);
}

/* Create default configuration file */
int config_create_default(const char *config_path) {
    char config_dir[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN] = "";
    char temp_name[MAX_PATH_LEN] = "";
    char temp_prefix[MAX_PATH_LEN] = "";
    char document_temp_prefix[MAX_PATH_LEN] = "";
    const char *last_slash;
    const char *target_name;
    struct stat dir_identity;
    struct stat temp_identity;
    struct stat temp_generation;
    struct stat retained_source = {0};
    struct stat installed;
    size_t total = 0;
    size_t length = strlen(default_config_template);
    int dir_fd = -1;
    int fd = -1;
    int lock_fd = -1;
    int publish_result = CONFIG_PUBLISH_MOVED;
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
    lock_fd = config_write_lock_directory(config_dir);
    if (lock_fd < 0) return -1;

    if (validate_config_write_destination(config_path) != 0) {
        goto default_fail;
    }
    if (lstat(config_dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Default config parent is not a stable private directory: %s",
                  config_dir);
        goto default_fail;
    }
    dir_fd = open(config_dir,
                  O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dir_fd < 0 || fstat(dir_fd, &installed) != 0) {
        int saved_errno = errno;
        if (dir_fd >= 0) close(dir_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot pin default config parent: %s", config_dir);
        goto default_fail;
    }
    {
        bool forced_mismatch =
            g_config_metadata_test_hook &&
            g_config_metadata_test_hook(CONFIG_METADATA_TEST_DEFAULT_DIR);
        errno = 0;
        if (forced_mismatch || !config_metadata_dir_is_safe(&installed) ||
            !config_metadata_same_file(&dir_identity, &installed)) {
            close(dir_fd);
            errno = ESTALE;
            set_system_error(ERR_PERMISSION_DENIED,
                             "Cannot pin default config parent: %s",
                             config_dir);
            dir_fd = -1;
            goto default_fail;
        }
    }
    if ((size_t)snprintf(
            temp_prefix, sizeof(temp_prefix), "%s.create.",
            target_name) >= sizeof(temp_prefix) ||
        (size_t)snprintf(
            document_temp_prefix, sizeof(document_temp_prefix),
            "%s.tmp.", target_name) >=
            sizeof(document_temp_prefix) ||
        signals_scratch_cleanup_identities_at(
            dir_fd, config_dir) != 0 ||
        config_reconcile_settled_aliases_at(
            dir_fd, target_name,
            CONFIG_DOCUMENT_SETTLED_PREFIX,
            temp_prefix, 16U) != 0 ||
        config_reconcile_settled_aliases_at(
            dir_fd, target_name,
            CONFIG_DOCUMENT_SETTLED_PREFIX,
            document_temp_prefix, 0U) != 0) {
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Cannot settle tracked default config aliases");
        goto default_fail;
    }
    errno = 0;
    if (fstatat(
            dir_fd, target_name, &installed,
            AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Configuration file already exists: %s",
            config_path);
        goto default_fail;
    }
    if (errno != ENOENT) {
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Cannot inspect default config destination: %s",
            config_path);
        goto default_fail;
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
    temp_generation = installed;
    if (config_io_fault(CONFIG_IO_DEFAULT_BEFORE_RENAME,
                        "default config no-replace publication")) {
        goto default_fail;
    }
    publish_result = config_publish_noreplace_at(
        dir_fd, temp_name, target_name, &temp_generation,
        &retained_source);
    if (publish_result < 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                         "Failed to install default config without replacement");
        goto default_fail;
    }
    if ((publish_result ==
             CONFIG_PUBLISH_INSTALLED_SOURCE_RETAINED ||
         publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) &&
        retained_source.st_nlink != 0 &&
        config_retire_or_track_scratch_at(
            dir_fd, config_dir, temp_name, temp_path,
            target_name, &retained_source,
            (const unsigned char *)default_config_template, length,
            CONFIG_DOCUMENT_SETTLED_PREFIX) != 0) {
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Default config was installed but its exact temporary alias could not be retired");
        goto default_fail;
    }
    temp_exists = false;
    signals_scratch_unregister(temp_path);
    registered = false;
    if (publish_result == CONFIG_PUBLISH_OUTCOME_UNCERTAIN) {
        errno = EINPROGRESS;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Default config publication outcome is uncertain");
        goto default_fail;
    }

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
        goto default_fail;
    }
    close(dir_fd);
    dir_fd = -1;
    config_write_unlock(lock_fd);
    lock_fd = -1;

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
                ((retained_source.st_nlink != 0 &&
                  config_metadata_same_file(
                      &retained_source, &current_temp)) ||
                 config_metadata_same_file(
                     &temp_identity, &current_temp))) {
                const struct stat *cleanup_identity =
                    retained_source.st_nlink != 0
                        ? &retained_source
                        : &current_temp;
                if (config_retire_or_track_scratch_at(
                        dir_fd, config_dir, temp_name, temp_path,
                        target_name, cleanup_identity, NULL, 0U,
                        CONFIG_DOCUMENT_SETTLED_PREFIX) == 0) {
                    temp_exists = false;
                    registered = false;
                }
            } else if (registered) {
                signals_scratch_unregister(temp_path);
                registered = false;
            }
        }
        if (registered && !temp_exists) {
            signals_scratch_unregister(temp_path);
        }
        if (dir_fd >= 0) close(dir_fd);
        if (lock_fd >= 0) config_write_unlock(lock_fd);
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

/* Add new account to configuration. The shared implementation admits either
 * a globally idle public call or the exact ADD owner capability. */
static int config_add_account_impl(gitswitch_ctx_t *ctx,
                                   const account_t *account,
                                   bool operation_owned,
                                   uint64_t transaction_token) {
    account_t candidate;
    publication_ledger_t publications;
    uint32_t current_id = 0;
    bool had_current;
    bool publication_reserved = false;

    if (accounts_transaction_authorize_model_mutation(
            ctx,
            operation_owned ? ACCOUNTS_TRANSACTION_ADD
                            : ACCOUNTS_TRANSACTION_NONE,
            operation_owned ? transaction_token : 0) != 0) {
        return -1;
    }
    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_add_account");
        return -1;
    }
    
    if (ctx->account_count >= MAX_ACCOUNTS) {
        set_error(ERR_ACCOUNT_EXISTS, "Maximum number of accounts reached: %d", MAX_ACCOUNTS);
        return -1;
    }
    candidate = *account;
    secure_zero_memory(candidate.incarnation,
                       sizeof(candidate.incarnation));
    candidate.incarnation_persisted = false;
    if (normalize_account_model_for_admission(&candidate) != 0) return -1;
    
    /* Validate account security */
    if (validate_account_security(&candidate) != 0) {
        return -1;
    }
    
    if (validate_account_uniqueness(ctx, &candidate, SIZE_MAX) != 0) return -1;

    /* Account IDs are publication ownership identities, not merely current
     * array keys. A record survives failed retirement so a later retry can
     * still describe the residue; recycling its integer would let an unrelated
     * account inherit that authority. Empty/unbound contexts have no durable
     * namespace, while a bound context must read the ledger exactly or fail
     * before model mutation. */
    publication_ledger_init(&publications);
    if (ctx->config.config_path[0] != '\0' &&
        config_load_publication_ledger(ctx->config.config_path,
                                       &publications) != 0) {
        publication_ledger_clear(&publications);
        return -1;
    }
    for (size_t i = 0; i < publications.count; i++) {
        if (publications.records[i].account_id == candidate.id) {
            publication_reserved = true;
            break;
        }
    }
    if (publication_reserved) {
        publication_ledger_clear(&publications);
        set_error(
            ERR_ACCOUNT_EXISTS,
            "Account ID %u is reserved by durable Git publication provenance",
            candidate.id);
        return -1;
    }
    if (config_generate_incarnation(ctx, &publications, NULL, 0U,
                                    candidate.incarnation) != 0) {
        publication_ledger_clear(&publications);
        return -1;
    }
    publication_ledger_clear(&publications);

    had_current = config_capture_current_id(ctx, &current_id);

    /* Add account */
    ctx->accounts[ctx->account_count] = candidate;
    ctx->account_count++;
    config_rebind_current_id(ctx, had_current, current_id);
    
    log_info("Added account: %s (%s)", candidate.name,
             candidate.description);
    return 0;
}

int config_add_account(gitswitch_ctx_t *ctx, const account_t *account) {
    return config_add_account_impl(ctx, account, false, 0);
}

int config_add_account_owned(gitswitch_ctx_t *ctx, const account_t *account,
                             uint64_t transaction_token) {
    return config_add_account_impl(ctx, account, true, transaction_token);
}

/* Remove account from configuration */
static int config_remove_account_impl(gitswitch_ctx_t *ctx,
                                      uint32_t account_id,
                                      bool operation_owned,
                                      uint64_t transaction_token) {
    size_t found_index = SIZE_MAX;
    uint32_t current_id = 0;
    bool had_current;
    
    if (accounts_transaction_authorize_model_mutation(
            ctx,
            operation_owned ? ACCOUNTS_TRANSACTION_REMOVE
                            : ACCOUNTS_TRANSACTION_NONE,
            operation_owned ? transaction_token : 0) != 0) {
        return -1;
    }
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

int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id) {
    return config_remove_account_impl(ctx, account_id, false, 0);
}

int config_remove_account_owned(gitswitch_ctx_t *ctx, uint32_t account_id,
                                uint64_t transaction_token) {
    return config_remove_account_impl(ctx, account_id, true,
                                      transaction_token);
}

/* Update existing account */
static int config_update_account_impl(gitswitch_ctx_t *ctx,
                                      const account_t *account,
                                      bool operation_owned,
                                      uint64_t transaction_token) {
    account_t *existing_account = NULL;
    account_t replacement;
    size_t existing_index = SIZE_MAX;
    uint32_t current_id = 0;
    bool had_current;
    
    if (accounts_transaction_authorize_model_mutation(
            ctx,
            operation_owned ? ACCOUNTS_TRANSACTION_EDIT
                            : ACCOUNTS_TRANSACTION_NONE,
            operation_owned ? transaction_token : 0) != 0) {
        return -1;
    }
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
    if (normalize_account_model_for_admission(&replacement) != 0) return -1;
    
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

    /* Incarnation is immutable account authority, not an editable field.
     * Empty means an older/source-compatible caller omitted the field and
     * inherits it. A nonempty value must name the exact current incarnation;
     * silently accepting a different token would mask a stale or misbound
     * edit request. Durability state always comes from the live model. */
    if (existing_account->incarnation[0] != '\0' &&
        !account_incarnation_is_valid(existing_account->incarnation)) {
        errno = ESTALE;
        set_error(
            ERR_ACCOUNT_INVALID,
            "Account %u has a corrupted immutable incarnation",
            account->id);
        return -1;
    }
    if (replacement.incarnation[0] != '\0' &&
        (!account_incarnation_is_valid(replacement.incarnation) ||
         strcmp(replacement.incarnation,
                existing_account->incarnation) != 0)) {
        errno = ESTALE;
        set_error(
            ERR_ACCOUNT_INVALID,
            "Account %u edit attempted to replace its immutable incarnation",
            account->id);
        return -1;
    }
    memcpy(replacement.incarnation, existing_account->incarnation,
           sizeof(replacement.incarnation));
    replacement.incarnation_persisted =
        existing_account->incarnation_persisted;
    
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

int config_update_account(gitswitch_ctx_t *ctx, const account_t *account) {
    return config_update_account_impl(ctx, account, false, 0);
}

int config_update_account_owned(gitswitch_ctx_t *ctx,
                                const account_t *account,
                                uint64_t transaction_token) {
    return config_update_account_impl(ctx, account, true, transaction_token);
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
    if (!text_is_tty_safe(identifier)) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Account selector contains terminal control bytes or malformed UTF-8");
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
    if (!text_is_tty_safe(identifier)) {
        set_error(ERR_ACCOUNT_NOT_FOUND,
                  "Account selector contains terminal control bytes or malformed UTF-8");
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

static bool config_incarnation_reserved(
    const gitswitch_ctx_t *ctx, const publication_ledger_t *publications,
    char generated[MAX_ACCOUNTS][ACCOUNT_INCARNATION_LEN],
    size_t generated_count, const char *candidate) {
    for (size_t i = 0; ctx && i < ctx->account_count; i++) {
        if (account_incarnation_is_valid(ctx->accounts[i].incarnation) &&
            strcmp(ctx->accounts[i].incarnation, candidate) == 0) {
            return true;
        }
    }
    for (size_t i = 0; i < generated_count; i++) {
        if (generated[i][0] != '\0' &&
            strcmp(generated[i], candidate) == 0) {
            return true;
        }
    }
    for (size_t i = 0; publications && i < publications->count; i++) {
        if (strcmp(publications->records[i].account_incarnation,
                   candidate) == 0) {
            return true;
        }
    }
    return false;
}

/* An integer mentioned by durable Git provenance is already an ownership
 * namespace. A full save may remove its exact account (the state phase then
 * tombstones the record), but it may not install a different live account at
 * the same integer. Reject before entropy generation or any state write so a
 * hand-edited legacy/mismatched document cannot be normalized into a binding
 * that every later switch must reject. */
static int config_validate_live_publication_bindings(
    const gitswitch_ctx_t *ctx,
    const publication_ledger_t *publications) {
    if (!ctx || !publications) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account publication binding model");
        return -1;
    }
    for (size_t i = 0; i < ctx->account_count; i++) {
        const account_t *account = &ctx->accounts[i];

        for (size_t j = 0; j < publications->count; j++) {
            const publication_record_t *record = &publications->records[j];

            if (record->account_id != account->id) continue;
            if (account->incarnation_persisted &&
                account_incarnation_is_valid(account->incarnation) &&
                strcmp(account->incarnation,
                       record->account_incarnation) == 0) {
                continue;
            }
            errno = ESTALE;
            set_error(
                ERR_CONFIG_INVALID,
                "Account ID %u is bound to a different durable incarnation",
                account->id);
            return -1;
        }
    }
    return 0;
}

static int config_generate_incarnation(
    const gitswitch_ctx_t *ctx, const publication_ledger_t *publications,
    char generated[MAX_ACCOUNTS][ACCOUNT_INCARNATION_LEN],
    size_t generated_count, char out[ACCOUNT_INCARNATION_LEN]) {
    static const char hexadecimal[] = "0123456789ABCDEF";

    if (!out) {
        set_error(ERR_INVALID_ARGS, "NULL account incarnation output");
        return -1;
    }
    out[0] = '\0';
    for (size_t attempt = 0; attempt < 128U; attempt++) {
        int result = g_config_incarnation_generate
            ? g_config_incarnation_generate(out)
            : generate_random_string(out, ACCOUNT_INCARNATION_LEN,
                                     hexadecimal);
        if (result != 0) {
            secure_zero_memory(out, ACCOUNT_INCARNATION_LEN);
            return -1;
        }
        if (!account_incarnation_is_valid(out)) {
            secure_zero_memory(out, ACCOUNT_INCARNATION_LEN);
            set_error(
                ERR_CONFIG_INVALID,
                "Account incarnation generator returned a noncanonical token");
            return -1;
        }
        if (!config_incarnation_reserved(ctx, publications, generated,
                                         generated_count, out)) {
            return 0;
        }
        secure_zero_memory(out, ACCOUNT_INCARNATION_LEN);
    }
    set_error(ERR_CONFIG_INVALID,
              "Cannot allocate a unique account incarnation");
    return -1;
}

/* Generate every missing token off-model first. Entropy failure at any point
 * therefore leaves the complete in-memory account array unchanged; only once
 * the full candidate set is valid and collision-free are values installed. */
static int config_materialize_missing_incarnations(
    gitswitch_ctx_t *ctx, const publication_ledger_t *publications) {
    char generated[MAX_ACCOUNTS][ACCOUNT_INCARNATION_LEN] = {{0}};
    size_t count;

    if (!ctx || ctx->account_count > MAX_ACCOUNTS) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account incarnation migration model");
        return -1;
    }
    count = ctx->account_count;
    for (size_t i = 0; i < count; i++) {
        const char *incarnation = ctx->accounts[i].incarnation;

        if (incarnation[0] != '\0') {
            if (!account_incarnation_is_valid(incarnation)) {
                set_error(
                    ERR_ACCOUNT_INVALID,
                    "Account %u has a noncanonical incarnation",
                    ctx->accounts[i].id);
                goto fail;
            }
            for (size_t j = 0; j < i; j++) {
                const char *prior = generated[j][0] != '\0'
                    ? generated[j] : ctx->accounts[j].incarnation;
                if (strcmp(prior, incarnation) == 0) {
                    set_error(
                        ERR_ACCOUNT_INVALID,
                        "Accounts %u and %u share one incarnation",
                        ctx->accounts[j].id, ctx->accounts[i].id);
                    goto fail;
                }
            }
            continue;
        }
        if (ctx->accounts[i].incarnation_persisted ||
            config_generate_incarnation(ctx, publications, generated, i,
                                        generated[i]) != 0) {
            if (ctx->accounts[i].incarnation_persisted) {
                set_error(ERR_ACCOUNT_INVALID,
                          "Account %u has no persisted incarnation",
                          ctx->accounts[i].id);
            }
            goto fail;
        }
    }
    for (size_t i = 0; i < count; i++) {
        if (generated[i][0] != '\0') {
            memcpy(ctx->accounts[i].incarnation, generated[i],
                   ACCOUNT_INCARNATION_LEN);
            ctx->accounts[i].incarnation_persisted = false;
        }
    }
    secure_zero_memory(generated, sizeof(generated));
    return 0;

fail:
    secure_zero_memory(generated, sizeof(generated));
    return -1;
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
    for (;;) {
        config_backup_entry_t parsed = {0};
        const char *suffix;
        struct stat st;

        /* readdir() uses NULL for both EOF and failure. Clear errno for every
         * call and preserve an enumeration failure across closedir(): rotation
         * must never prune from a partial candidate set. */
        errno = 0;
        item = g_config_backup_readdir(stream);
        if (!item) {
            int enumeration_errno = errno;
            if (enumeration_errno != 0) {
                (void)closedir(stream);
                errno = enumeration_errno;
                set_system_error(
                    ERR_FILE_IO,
                    "Failed while enumerating config backup directory");
                return -1;
            }
            break;
        }
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

static int config_backup_prune(const char *config_path, size_t keep,
                               bool *pruned) {
    config_backup_entry_t entries[CONFIG_BACKUP_SCAN_MAX];
    char dir[MAX_PATH_LEN];
    size_t count;
    int dir_fd;

    if (pruned) *pruned = false;
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
            config_retire_exact_name_at(
                dir_fd, entries[i].name, &st,
                NULL, 0U,
                CONFIG_BACKUP_SETTLED_PREFIX) != 0) {
            close(dir_fd);
            set_error(ERR_FILE_IO,
                      "Cannot safely prune old config backup: %s",
                      entries[i].name);
            return -1;
        }
        if (pruned) *pruned = true;
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

/* Backup configuration file with a persisted monotonic generation. A full
 * document publisher may additionally supply the strict identity it captured
 * before backup so FreeBSD's delayed ctime materialization can be proven
 * against this exact recovery copy. */
int config_backup(const char *config_path) {
    return config_backup_internal(config_path, NULL);
}

static int config_backup_internal(const char *config_path,
                                  struct stat *publication_identity) {
    config_backup_entry_t entries[CONFIG_BACKUP_SCAN_MAX];
    toml_document_t *verify_doc = NULL;
    char backup_path[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    uint64_t seconds;
    uint32_t nanoseconds;
    uint64_t generation = 0;
    size_t count;
    struct stat backup_identity;
    struct stat copied_source;
    struct stat named_backup;
    bool backup_created = false;
    bool backup_pruned = false;
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
        if (copy_file_nofollow(config_path, backup_path, &backup_identity,
                               &copied_source) == 0) {
            backup_created = true;
            break;
        }
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
    if (!verify_doc ||
        config_read_document_expected(backup_path, verify_doc,
                                      &backup_identity, NULL,
                                      NULL, 0U, NULL) != 0) {
        if (!verify_doc && get_last_error()->code == ERR_SUCCESS) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot allocate config backup verification document");
        }
        goto backup_fail;
    }
    config_document_free(verify_doc);
    verify_doc = NULL;

    errno = 0;
    if (lstat(backup_path, &named_backup) != 0 ||
        !config_metadata_snapshot_same(&backup_identity, &named_backup)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Backup destination changed before completion: %s",
                         backup_path);
        goto backup_fail;
    }
    /* Reject a stale full-document publication before rotation can destroy an
     * older recovery point. With five retained backups, removing the oldest
     * and then unlinking this new backup on rejection would leave only four. */
    errno = 0;
    if (publication_identity &&
        !config_refresh_publication_identity(
            config_path, backup_path, &copied_source, &backup_identity,
            publication_identity)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Config destination changed while backup was committed: %s",
            config_path);
        goto backup_fail;
    }
    if (config_backup_prune(config_path, 5, &backup_pruned) != 0) {
        goto backup_fail;
    }
    errno = 0;
    if (lstat(backup_path, &named_backup) != 0 ||
        !config_metadata_snapshot_same(&backup_identity, &named_backup)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Backup destination changed before completion: %s",
                         backup_path);
        goto backup_fail;
    }
    /* Rotation's directory sync can materialize another delayed UFS ctime
     * update. Re-prove only that narrow drift against the still-identity-
     * pinned backup; the first witness above already tied it to the original
     * publication snapshot. */
    errno = 0;
    if (publication_identity &&
        !config_refresh_publication_identity(
            config_path, backup_path, NULL, &backup_identity,
            publication_identity)) {
        errno = errno ? errno : ESTALE;
        set_system_error(
            ERR_CONFIG_WRITE_FAILED,
            "Config destination changed while backup was committed: %s",
            config_path);
        goto backup_fail;
    }
    log_info("Created durable configuration backup: %s", backup_path);
    return 0;

backup_fail:
    {
        int saved_errno = errno ? errno : EIO;

        if (verify_doc) config_document_free(verify_doc);
        if (dir_fd >= 0) close(dir_fd);
        /* Once rotation deleted an older entry, this durable, parseable,
         * identity-verified backup is part of the retained history. Removing
         * it on a later error would shrink a five-entry history to four. */
        if (backup_created && !backup_pruned &&
            lstat(backup_path, &named_backup) == 0 &&
            config_metadata_snapshot_same(&backup_identity, &named_backup) &&
            config_retire_exact_path(
                backup_path, &named_backup, NULL, 0U,
                CONFIG_BACKUP_SETTLED_PREFIX) == 0) {
            int cleanup_fd = open(
                dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
            if (cleanup_fd >= 0) {
                (void)fsync(cleanup_fd);
                close(cleanup_fd);
            }
        }
        errno = saved_errno;
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
    if (!S_ISREG(link_stat.st_mode)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Configuration file is not a regular file: %s",
                  config_path);
        return -1;
    }

    /* Stable nonregular nodes were rejected before open. O_NONBLOCK is inert
     * for regular files and prevents a raced FIFO/device from wedging before
     * the replacement descriptor type can be rejected by fstat(). */
    fd = open(config_path,
              O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
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
static int copy_file_nofollow(const char *src_path, const char *dst_path,
                              struct stat *created_identity,
                              struct stat *source_identity) {
    struct stat before;
    struct stat after;
    struct stat named;
    struct stat destination_identity;
    struct stat destination_after;
    struct stat destination_verified;
    struct stat destination_named;
    char buf[4096];
    unsigned char source_verify[4096];
    unsigned char destination_verify[4096];
    unsigned char *source_snapshot = NULL;
    size_t snapshot_length = 0;
    off_t verify_offset = 0;
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
    sfd = open(src_path,
               O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
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
    if (before.st_size < 0 || before.st_size > (off_t)TOML_MAX_FILE_SIZE) {
        errno = EFBIG;
        set_error(ERR_FILE_IO,
                  "Backup source is outside the supported config size: %s",
                  src_path);
        failure_reported = true;
        goto fail;
    }
    source_snapshot = malloc(before.st_size > 0 ? (size_t)before.st_size : 1U);
    if (!source_snapshot) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate exact config backup snapshot");
        failure_reported = true;
        goto fail;
    }

    /* O_EXCL never follows a symlink and fails if the name exists at all, so
     * a pre-planted backup destination cannot redirect the write. */
    dfd = open(dst_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
               0600);
    if (dfd < 0) {
        /* Preserve the create errno (esp. EEXIST) across set_system_error/close
         * so callers can distinguish a name collision from a real failure and
         * retry with a fresh name (AR-06 F46/F47). */
        int saved = errno;
        set_system_error(ERR_FILE_IO, "Cannot create backup file: %s", dst_path);
        failure_reported = true;
        errno = saved;
        goto fail;
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
        if ((size_t)n > (size_t)before.st_size - snapshot_length) {
            errno = ESTALE;
            goto fail;
        }
        memcpy(source_snapshot + snapshot_length, buf, (size_t)n);
        snapshot_length += (size_t)n;
        if (!copied_first_chunk) {
            copied_first_chunk = true;
            if (config_io_fault(CONFIG_IO_BACKUP_AFTER_FIRST_CHUNK,
                                "config backup source consistency checkpoint")) {
                failure_reported = true;
                goto fail;
            }
        }
    }
    if (snapshot_length != (size_t)before.st_size) {
        errno = ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Configuration size changed while backup was copied: %s",
                         src_path);
        failure_reported = true;
        goto fail;
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
    errno = 0;
    if (fstat(dfd, &destination_after) != 0 ||
        lstat(dst_path, &destination_named) != 0 ||
        !config_metadata_file_is_safe(&destination_after, true) ||
        !config_metadata_file_is_safe(&destination_named, true) ||
        !config_metadata_same_file(&destination_identity,
                                   &destination_after) ||
        !config_metadata_same_file(&destination_identity,
                                   &destination_named) ||
        destination_after.st_size != before.st_size ||
        destination_named.st_size != before.st_size) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Backup destination changed while being copied: %s",
                         dst_path);
        failure_reported = true;
        goto fail;
    }

    /* The backup becomes a publication witness, so write counts and size are
     * not enough: while both objects are descriptor-pinned, prove that the
     * durable destination contains the exact strict source generation. */
    while (verify_offset < before.st_size) {
        off_t remaining = before.st_size - verify_offset;
        size_t chunk = remaining < (off_t)sizeof(source_verify)
            ? (size_t)remaining : sizeof(source_verify);
        const unsigned char *expected =
            source_snapshot + (size_t)verify_offset;
        if (!config_pread_full(sfd, source_verify, chunk, verify_offset) ||
            !config_pread_full(dfd, destination_verify, chunk,
                               verify_offset) ||
            memcmp(source_verify, expected, chunk) != 0 ||
            memcmp(destination_verify, expected, chunk) != 0) {
            errno = ESTALE;
            set_system_error(
                ERR_FILE_IO,
                "Backup destination does not match its source generation: %s",
                dst_path);
            failure_reported = true;
            goto fail;
        }
        verify_offset += (off_t)chunk;
    }
    errno = 0;
    if (fstat(sfd, &after) != 0 || lstat(src_path, &named) != 0 ||
        fstat(dfd, &destination_verified) != 0 ||
        lstat(dst_path, &destination_named) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_file_is_safe(&named, true) ||
        !config_metadata_file_is_safe(&destination_verified, true) ||
        !config_metadata_file_is_safe(&destination_named, true) ||
        (!config_metadata_snapshot_same(&before, &after) &&
         !config_metadata_ctime_only_change(&before, &after)) ||
        (!config_metadata_snapshot_same(&before, &named) &&
         !config_metadata_ctime_only_change(&before, &named)) ||
        !config_metadata_snapshot_same(&after, &named) ||
        !config_metadata_snapshot_same(&destination_after,
                                       &destination_verified) ||
        !config_metadata_snapshot_same(&destination_after,
                                       &destination_named)) {
        errno = errno ? errno : ESTALE;
        set_system_error(ERR_FILE_IO,
                         "Backup source or destination changed during exact verification: %s",
                         dst_path);
        failure_reported = true;
        goto fail;
    }
    if (close(sfd) != 0) {
        sfd = -1;
        set_system_error(ERR_FILE_IO,
                         "Failed to finalize backup source: %s", src_path);
        failure_reported = true;
        goto fail;
    }
    sfd = -1;
    if (close(dfd) != 0) {
        dfd = -1;
        set_system_error(ERR_FILE_IO, "Failed to finalize backup file: %s", dst_path);
        failure_reported = true;
        goto fail;
    }
    dfd = -1;
    if (created_identity) {
        *created_identity = destination_after;
    }
    if (source_identity) {
        *source_identity = before;
    }
    secure_zero_memory(buf, sizeof(buf));
    secure_zero_memory(source_verify, sizeof(source_verify));
    secure_zero_memory(destination_verify, sizeof(destination_verify));
    secure_zero_memory(source_snapshot,
                       before.st_size > 0 ? (size_t)before.st_size : 1U);
    free(source_snapshot);
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
            (void)config_retire_exact_path(
                dst_path, &destination_identity, NULL, 0U,
                CONFIG_BACKUP_SETTLED_PREFIX);
        }
        secure_zero_memory(buf, sizeof(buf));
        secure_zero_memory(source_verify, sizeof(source_verify));
        secure_zero_memory(destination_verify, sizeof(destination_verify));
        if (source_snapshot) {
            secure_zero_memory(
                source_snapshot,
                before.st_size > 0 ? (size_t)before.st_size : 1U);
            free(source_snapshot);
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
        "incarnation", "name", "email", "description", "preferred_scope",
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

            /* Optional only for pre-incarnation account documents. Never
             * generate entropy during load: readonly/names/status must remain
             * observational. A real mutation materializes every missing token
             * together before its full transactional save. */
            fs = get_account_field(
                doc, sections[i], "incarnation", account.incarnation,
                sizeof(account.incarnation));
            if (fs == FIELD_UNLOADABLE) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account section [%s] was skipped: %s",
                                sections[i], get_last_error()->message);
                continue;
            }
            account.incarnation_persisted = fs == FIELD_LOADED;

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
                if (toml_section_is_hidden(doc, sections[i])) {
                    /* AR-13 L15: the schema hid this whole section (a bad
                     * ssh_key/ssh_hostname/dependency gap), so every field
                     * reads absent — do not misreport it as a missing 'name'.
                     * The offending field was already warned about at parse. */
                    display_warning("Account section [%s] was skipped by schema "
                                    "validation; see the preceding parser "
                                    "warning for the offending field.",
                                    sections[i]);
                } else if (fs == FIELD_ABSENT) {
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

                /* Expand path if needed. AR-12 L8: retain the persisted
                 * spelling first so a later save can re-emit the user's
                 * portable '~/...' form instead of the expanded path. */
                char expanded_path[MAX_PATH_LEN];
                if (expand_path(account.ssh_key_path, expanded_path, sizeof(expanded_path)) == 0 &&
                    strcmp(expanded_path, account.ssh_key_path) != 0) {
                    if (safe_strncpy(account.ssh_key_spelling,
                                     account.ssh_key_path,
                                     sizeof(account.ssh_key_spelling)) != 0) {
                        /* Preservation is best-effort; the expanded path
                         * remains authoritative. */
                        account.ssh_key_spelling[0] = '\0';
                    }
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
                    (account.incarnation[0] != '\0' &&
                     strcmp(ctx->accounts[j].incarnation,
                            account.incarnation) == 0) ||
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

    /* The writer emits incarnations for every account in one generation.
     * A mixture of present and absent tokens cannot be its output: treat that
     * shape as a manual same-ID replacement/partial rewrite, not as legacy.
     * Pure legacy documents (all absent) remain readable and unmaterialized. */
    {
        size_t persisted = 0U;
        for (size_t i = 0; i < ctx->account_count; i++) {
            if (ctx->accounts[i].incarnation_persisted) persisted++;
        }
        if (persisted != 0U && persisted != ctx->account_count) {
            set_error(
                ERR_CONFIG_INVALID,
                "Account document mixes legacy accounts without incarnations and incarnation-bound accounts");
            return -1;
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

int config_validate_account_model(const account_t *account) {
    bool has_ssh_key;
    bool has_ssh_alias;
    bool has_ssh_hostname;
    bool has_gpg_key;

    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account model to validate");
        return -1;
    }

    has_ssh_key = account->ssh_key_path[0] != '\0';
    has_ssh_alias = account->ssh_host_alias[0] != '\0';
    has_ssh_hostname = account->ssh_hostname[0] != '\0';
    has_gpg_key = account->gpg_key_id[0] != '\0';

    if (account->ssh_enabled && !has_ssh_key) {
        set_error(ERR_ACCOUNT_INVALID,
                  "SSH is enabled but ssh_key_path is empty");
        return -1;
    }
    if (!account->ssh_enabled &&
        (has_ssh_key || has_ssh_alias || has_ssh_hostname)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "SSH is disabled but SSH key or routing fields are still set");
        return -1;
    }
    if (has_ssh_alias && !has_ssh_hostname) {
        set_error(ERR_ACCOUNT_INVALID,
                  "SSH host alias requires an explicit canonical hostname");
        return -1;
    }

    if (account->gpg_enabled && !has_gpg_key) {
        set_error(ERR_ACCOUNT_INVALID,
                  "GPG is enabled but gpg_key_id is empty");
        return -1;
    }
    if (!account->gpg_enabled &&
        (has_gpg_key || account->gpg_signing_enabled)) {
        set_error(ERR_ACCOUNT_INVALID,
                  "GPG is disabled but a key or signing preference is still set");
        return -1;
    }

    return 0;
}

/* Before admission, canonicalize the one supported legacy shorthand: a
 * literal ssh_host historically doubled as its destination. Disabled states
 * and missing key identifiers are rejected rather than silently erased. */
static int normalize_account_model_for_admission(account_t *account) {
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account model to normalize");
        return -1;
    }
    if (account->ssh_enabled && account->ssh_host_alias[0] != '\0' &&
        account->ssh_hostname[0] == '\0' &&
        toml_validate_ssh_hostname(account->ssh_host_alias)) {
        return safe_strncpy(account->ssh_hostname, account->ssh_host_alias,
                            sizeof(account->ssh_hostname));
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

    /* AR-12 H4: the ssh_key path is included so admission can never write a
     * document whose bytes the loader's schema refuses (write-accepts /
     * load-rejects asymmetry). */
    if (validate_field_roundtrips("name", account->name) != 0 ||
        validate_field_roundtrips("description", account->description) != 0 ||
        validate_field_roundtrips("SSH key path",
                                  account->ssh_key_path) != 0 ||
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
                  "Invalid SSH canonical hostname (host-only ASCII name/IPv4 "
                  "or unbracketed IPv6; embedded ports are unsupported): %s",
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
    if (config_validate_account_model(account) != 0) return -1;

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

    if (!text_is_tty_safe(account->email) || !validate_email(account->email)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid email address");
        return -1;
    }
    
    /* Validate SSH key if configured */
    if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
        if (!text_is_tty_safe(account->ssh_key_path)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "SSH key path contains terminal control bytes or malformed UTF-8");
            return -1;
        }

        /* AR-13 R0 (config-selfbrick): the loader's schema
         * (toml_validate_gitswitch_schema) hard-fails the WHOLE file — not the
         * per-account skip_section — when a persisted ssh_key contains ".."
         * (toml_parser.c toml_validate_file_path) or is not '/'- or
         * '~'-anchored (toml_parser.c). Admission historically enforced only
         * the sanitizer round-trip and the 256-byte expanded cap; expand_path
         * passes ".." through untouched and ssh_validate_key_file open()s the
         * path, so the kernel resolves ".."/CWD-relative segments and the key
         * validates — letting an account this tool admits and saves be one the
         * same tool then refuses to load, bricking every command on next start.
         * The AR-12 H4 comment above claims admission is symmetric with the
         * loader; these two checks are what actually make it so. They run on
         * the persisted spelling(s), before expand_path collapses '~'. */
        if (!toml_validate_file_path(account->ssh_key_path) ||
            (account->ssh_key_spelling[0] != '\0' &&
             !toml_validate_file_path(account->ssh_key_spelling))) {
            set_error(ERR_ACCOUNT_INVALID,
                      "SSH key path may not contain '..': %s", account->ssh_key_path);
            return -1;
        }
        if ((account->ssh_key_path[0] != '/' && account->ssh_key_path[0] != '~') ||
            (account->ssh_key_spelling[0] != '\0' &&
             account->ssh_key_spelling[0] != '/' &&
             account->ssh_key_spelling[0] != '~')) {
            set_error(ERR_ACCOUNT_INVALID,
                      "ssh_key must be an absolute or ~-anchored path, not relative: %s",
                      account->ssh_key_path);
            return -1;
        }

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
        if (!text_is_tty_safe(account->gpg_key_id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "GPG key ID contains terminal control bytes or malformed UTF-8");
            return -1;
        }
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

        if (!config_account_id_is_valid(account->id)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account ID must be in 1..%u", UINT32_MAX);
            return -1;
        }
        if (!account_incarnation_is_valid(account->incarnation)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Account %u has no canonical incarnation",
                      account->id);
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
        if (toml_set_string(doc, section_name, "incarnation",
                            account->incarnation) != 0) {
            set_error(ERR_CONFIG_INVALID,
                      "Failed to save account incarnation");
            return -1;
        }

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
        
        /* Admission and the save preflight require a lossless model. Legacy
         * literal alias shorthand is normalized before admission, never while
         * serializing a caller-owned context. */
        if (account->ssh_host_alias[0] != '\0' &&
            !toml_validate_ssh_host_alias(account->ssh_host_alias)) {
            set_error(ERR_ACCOUNT_INVALID, "Invalid SSH host alias: %s",
                      account->ssh_host_alias);
            return -1;
        }
        if (account->ssh_hostname[0] != '\0' &&
            !toml_validate_ssh_hostname(account->ssh_hostname)) {
            set_error(ERR_ACCOUNT_INVALID,
                      "Invalid SSH canonical hostname: %s",
                      account->ssh_hostname);
            return -1;
        }

        /* Save SSH configuration */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            /* AR-12 L8: re-emit the user's persisted spelling while it
             * still expands to the live model value; an edited path (stale
             * spelling) falls back to the expanded bytes. */
            const char *ssh_key_value = account->ssh_key_path;
            char respelled[MAX_PATH_LEN];

            if (account->ssh_key_spelling[0] != '\0' &&
                expand_path(account->ssh_key_spelling, respelled,
                            sizeof(respelled)) == 0 &&
                strcmp(respelled, account->ssh_key_path) == 0) {
                ssh_key_value = account->ssh_key_spelling;
            }
            if (toml_set_string(doc, section_name, "ssh_key",
                                ssh_key_value) != 0) {
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
            if (account->ssh_hostname[0] != '\0') {
                if (toml_set_string(doc, section_name, "ssh_hostname",
                                    account->ssh_hostname) != 0) {
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
