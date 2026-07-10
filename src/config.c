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
"#ssh_host = \"github.com-work\"\n"
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
static bool text_is_tty_safe(const char *text);
static int create_config_directory_secure(const char *config_dir);
static int load_accounts_from_toml(gitswitch_ctx_t *ctx, const toml_document_t *doc);
static int save_accounts_to_toml(const gitswitch_ctx_t *ctx, toml_document_t *doc);
static int parse_account_id_from_section(const char *section_name, uint32_t *account_id);
static int validate_account_security(const account_t *account);

/* Initialize configuration system */
int config_init(gitswitch_ctx_t *ctx) {
    char config_path[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];
    
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
    
    /* Ensure config directory exists with secure permissions */
    if (create_config_directory_secure(config_dir) != 0) {
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
        return config_load(ctx, config_path);
    } else {
        log_info("Configuration file not found, will create default");
        /* Don't automatically create - let user create when needed */
        return 0;
    }
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
    struct stat fst;
    size_t file_size, total = 0;
    int fd;

    fd = open_config_validated(config_path);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &fst) != 0) {
        set_system_error(ERR_CONFIG_NOT_FOUND, "Cannot stat config file: %s", config_path);
        close(fd);
        return -1;
    }
    file_size = (size_t)fst.st_size;
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
    close(fd);
    if (total != file_size) {
        set_system_error(ERR_FILE_IO, "Failed to read complete config file: %s", config_path);
        goto fail_buffer;
    }
    buffer[file_size] = '\0';

    /* Same content vetting toml_parse_file applied before it parsed. */
    if (!toml_validate_safe_characters(buffer, file_size)) {
        set_error(ERR_CONFIG_INVALID, "Configuration file contains unsafe characters");
        goto fail_buffer;
    }
    if (!toml_check_injection_patterns(buffer, file_size)) {
        set_error(ERR_CONFIG_INVALID, "Configuration file contains potentially malicious patterns");
        goto fail_buffer;
    }

    /* Parse TOML configuration */
    toml_init_document(doc);
    if (toml_parse_string(buffer, file_size, doc) != 0) {
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

/* Load configuration from TOML file */
int config_load(gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    char scope_str[32];

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }

    if (config_read_document(config_path, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }

    /* Load settings section */
    if (toml_get_string(&toml_doc, "settings", "default_scope",
                        scope_str, sizeof(scope_str)) == 0) {
        ctx->config.default_scope = config_parse_scope(scope_str);
    } else {
        log_warning("No default_scope found in settings, using local");
        ctx->config.default_scope = GIT_SCOPE_LOCAL;
    }

    /* Last-active account for boot resume (optional; absent on older configs).
     * Sanitized like the other untrusted display fields; a name that needed
     * sanitizing can no longer match any (validated) account name, which is
     * the correct fail-closed outcome for resume. */
    if (toml_get_string(&toml_doc, "settings", "active_account",
                        ctx->config.active_account, sizeof(ctx->config.active_account)) != 0) {
        ctx->config.active_account[0] = '\0';
    } else if (sanitize_tty_text(ctx->config.active_account)) {
        log_warning("Removed terminal control bytes from active_account setting");
    }

    /* Load accounts */
    if (load_accounts_from_toml(ctx, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }

    /* Store config path */
    safe_strncpy(ctx->config.config_path, config_path, sizeof(ctx->config.config_path));

    toml_cleanup_document(&toml_doc);

    /* Detect current account from SSH socket symlink */
    accounts_detect_current(ctx);

    log_info("Configuration loaded successfully: %zu accounts", ctx->account_count);
    return 0;
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

/* Create or remove the resume-hint marker so the shell integration knows
 * whether a boot-time resume is worth attempting. The marker's CONTENT records
 * the active account's boot-volatile runtime needs as a space-separated token
 * set ("ssh", "gpg", or "none"), so the shell snippet can skip the per-shell
 * ssh-add liveness probe entirely for an SSH-less active account — otherwise a
 * GPG-only or identity-only account made every new interactive shell spawn
 * ssh-add (exit 2) plus a `gitswitch resume` in perpetuity (AR-02 #23). Cheap
 * and best-effort. */
static void config_update_resume_hint(const gitswitch_ctx_t *ctx) {
    const char *content;
    char dir[MAX_PATH_LEN];
    char hint[MAX_PATH_LEN];
    char temp[MAX_PATH_LEN];
    struct stat dir_identity;
    struct stat before;
    struct stat temp_identity;
    struct stat after;
    bool existed = false;
    int fd = -1;

    if (get_config_directory(dir, sizeof(dir)) != 0 ||
        create_config_directory_secure(dir) != 0 ||
        lstat(dir, &dir_identity) != 0 ||
        !config_metadata_dir_is_safe(&dir_identity)) {
        log_warning("Cannot safely update the resume hint: config directory is unavailable");
        return;
    }
    if (config_resume_hint_path(hint, sizeof(hint)) != 0) return;
    if (ctx->config.active_account[0] == '\0') {
        /* unlink() removes only the directory entry and never follows a final
         * symlink, so reset cannot alter a symlink target. */
        unlink(hint);
        return;
    }

    /* Resolve the active account to read its ssh/gpg flags. If it can't be
     * found (shouldn't happen — it was just saved), fall back to the
     * conservative "ssh gpg" so the snippet still probes rather than wrongly
     * skipping a needed resume. */
    bool wants_ssh = true, wants_gpg = true;
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, ctx->config.active_account) == 0) {
            wants_ssh = ctx->accounts[i].ssh_enabled &&
                        ctx->accounts[i].ssh_key_path[0] != '\0';
            wants_gpg = ctx->accounts[i].gpg_enabled &&
                        ctx->accounts[i].gpg_key_id[0] != '\0';
            break;
        }
    }

    if (wants_ssh && wants_gpg)      content = "ssh gpg\n";
    else if (wants_ssh)              content = "ssh\n";
    else if (wants_gpg)              content = "gpg\n";
    else                             content = "none\n";

    /* Never open the destination for writing. Capture its exact identity (or
     * absence), build a fresh 0600 inode beside it, then verify that neither
     * the destination nor its private directory changed before rename. */
    if (lstat(hint, &before) == 0) {
        existed = true;
        if (!config_metadata_file_is_safe(&before, false)) {
            log_warning("Refusing to replace unsafe resume hint metadata: %s", hint);
            return;
        }
    } else if (errno != ENOENT) {
        log_warning("Cannot inspect resume hint before update: %s", hint);
        return;
    }
    if ((size_t)snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", hint) >= sizeof(temp)) {
        log_warning("Resume hint temporary path is too long");
        return;
    }

    fd = mkstemp(temp);
    if (fd < 0) {
        log_warning("Cannot create temporary resume hint: %s", hint);
        return;
    }
    (void)signals_scratch_register(temp);
    if (fchmod(fd, PERM_USER_RW) != 0 ||
        fstat(fd, &temp_identity) != 0 ||
        !config_metadata_file_is_safe(&temp_identity, true)) {
        log_warning("Cannot secure temporary resume hint: %s", temp);
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
            log_warning("Cannot write temporary resume hint: %s", temp);
            goto hint_fail;
        }
    }
    if (fsync(fd) != 0) {
        log_warning("Cannot flush temporary resume hint: %s", temp);
        goto hint_fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        log_warning("Cannot finalize temporary resume hint: %s", temp);
        goto hint_fail;
    }
    fd = -1;

    if (lstat(temp, &after) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_same_file(&temp_identity, &after) ||
        lstat(dir, &after) != 0 ||
        !config_metadata_dir_is_safe(&after) ||
        !config_metadata_same_file(&dir_identity, &after)) {
        log_warning("Resume hint metadata changed before installation: %s", hint);
        goto hint_fail;
    }
    if (lstat(hint, &after) == 0) {
        if (!existed || !config_metadata_file_is_safe(&after, false) ||
            !config_metadata_same_file(&before, &after)) {
            log_warning("Resume hint changed before update; refusing replacement: %s", hint);
            goto hint_fail;
        }
    } else if (existed || errno != ENOENT) {
        log_warning("Resume hint changed before update; refusing replacement: %s", hint);
        goto hint_fail;
    }

    if (rename(temp, hint) != 0) {
        log_warning("Cannot install resume hint atomically: %s", hint);
        goto hint_fail;
    }
    signals_scratch_unregister(temp);

    if (lstat(hint, &after) != 0 ||
        !config_metadata_file_is_safe(&after, true) ||
        !config_metadata_same_file(&temp_identity, &after)) {
        log_warning("Cannot verify installed resume hint: %s", hint);
    }
    return;

hint_fail:
    if (fd >= 0) close(fd);
    unlink(temp);
    signals_scratch_unregister(temp);
}

/* Shared atomic-write tail for config_save and config_save_active_account:
 * validate the destination, back up the existing file, write doc to a fresh
 * 0600 temp, rename it into place, refresh the resume hint. */
static int config_write_document_atomic(const gitswitch_ctx_t *ctx, const toml_document_t *doc,
                                        const char *config_path) {
    char temp_path[MAX_PATH_LEN];

    /* Refuse to write through or next to a symlink (cfg-symlink-01). rename()
     * would replace a symlinked accounts.toml with a real file, but the
     * backup step reads through the link (exfiltrating the target into a
     * 0600 backup we own) and a symlinked/foreign parent directory lets an
     * attacker choose where the temp+rename lands. Fail closed instead. */
    if (validate_config_write_destination(config_path) != 0) {
        return -1;
    }

    /* Create backup if file exists */
    if (path_exists(config_path)) {
        if (config_backup(config_path) != 0) {
            log_warning("Failed to create backup before saving config");
        }
    }

    /* Create temporary file path for atomic write. Include the pid so two
     * concurrent gitswitch processes never share a temp file — a shared
     * deterministic name lets one process truncate/rewrite the temp while the
     * other is mid-write, so the loser's rename() installs a partial config. */
    if ((size_t)snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", config_path, (int)getpid())
        >= sizeof(temp_path)) {
        set_error(ERR_INVALID_ARGS, "Temporary file path too long");
        return -1;
    }

    /* Pre-create the temp file with O_CREAT|O_EXCL (which never follows
     * symlinks) and mode 0600, so the name is guaranteed to be a fresh
     * regular file we own before toml_write_file() reopens it by path. The
     * destination directory was validated above as a user-owned, non-symlink
     * directory that nobody else can write, so no other principal can swap
     * the name between the two opens (cfg-symlink-01). */
    unlink(temp_path); /* clear any stale temp from a crashed run of this pid */
    {
        int tfd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (tfd < 0) {
            set_system_error(ERR_CONFIG_WRITE_FAILED,
                             "Failed to create temporary config file: %s", temp_path);
            return -1;
        }
        close(tfd);
    }
    /* SIG-02 (AR-02 #27): register the temp for signal cleanup for the span
     * it exists. Only effective while a guard handler is installed (main()
     * holds one across the save-after-switch); otherwise it is an inert no-op
     * — the atomic temp+rename below protects the real file either way, this
     * only prevents an orphaned .tmp when a signal lands mid-save. */
    signals_scratch_register(temp_path);

    /* Write to temporary file first (already created 0600 above, so the
     * content is never observable with looser permissions) */
    if (toml_write_file(doc, temp_path) != 0) {
        unlink(temp_path); /* don't leave a stale/partial .tmp behind */
        signals_scratch_unregister(temp_path);
        return -1;
    }

    /* Atomic move from temp to final location */
    if (rename(temp_path, config_path) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED,
                        "Failed to move temporary config file to final location");
        unlink(temp_path);
        signals_scratch_unregister(temp_path);
        return -1;
    }
    signals_scratch_unregister(temp_path); /* renamed away: nothing to clean */

    log_info("Configuration saved successfully to: %s", config_path);
    config_update_resume_hint(ctx);
    return 0;
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
    if (ctx->accounts_skipped_on_load == 0 && ctx->unknown_sections_on_load == 0) {
        return 0;
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
int config_save(const gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    int result = -1;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save");
        return -1;
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

    /* Initialize TOML document */
    toml_init_document(&toml_doc);

    /* Add/update settings section */
    if (toml_set_string(&toml_doc, "settings", "default_scope",
                        config_scope_to_string(ctx->config.default_scope)) != 0) {
        goto cleanup;
    }

    /* Persist the last-active account for boot resume (when one is set) */
    if (ctx->config.active_account[0] != '\0') {
        if (toml_set_string(&toml_doc, "settings", "active_account",
                            ctx->config.active_account) != 0) {
            goto cleanup;
        }
    }

    /* Add current accounts */
    log_debug("About to save accounts to TOML doc with %zu sections", toml_doc.section_count);
    if (save_accounts_to_toml(ctx, &toml_doc) != 0) {
        goto cleanup;
    }
    log_debug("After saving accounts, TOML doc has %zu sections", toml_doc.section_count);

    result = config_write_document_atomic(ctx, &toml_doc, config_path);

cleanup:
    toml_cleanup_document(&toml_doc);
    return result;
}

/* Persist only settings.active_account via parse -> edit -> write-back of the
 * on-disk document (AR-03 M9). The full config_save is (correctly) refused
 * when the load skipped sections — but a switch between the HEALTHY accounts
 * must still record active_account, or the next boot's resume restores the
 * wrong identity while the switch reported success. The write-back path is
 * safe where the rebuild is not: toml_write_file re-emits every parsed
 * section, including schema-skipped account sections (their keys stay set;
 * only the section's is_set is cleared) and unrecognized sections, so nothing
 * the loader couldn't model is lost. Comments are not preserved — same as
 * every existing save path. */
int config_save_active_account(const gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    int result;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save_active_account");
        return -1;
    }

    /* No file yet: nothing to preserve, and the write-back needs a document
     * to edit — the full rebuild is both safe and required to create one. */
    if (!path_exists(config_path)) {
        return config_save(ctx, config_path);
    }

    if (config_read_document(config_path, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }

    /* Keys before the first section header parse into a section with an empty
     * name; toml_write_file would emit that as a bare "[]" header the next
     * load then rejects. Refuse rather than corrupt (the loader already warned
     * about the unrecognized section; the user has to fix the file anyway). */
    for (size_t i = 0; i < toml_doc.section_count; i++) {
        if (toml_doc.sections[i].name[0] == '\0' && toml_doc.sections[i].key_count > 0) {
            set_error(ERR_CONFIG_INVALID,
                      "Config file %s has keys before its first [section] header; "
                      "they cannot be written back faithfully — fix the file first",
                      config_path);
            toml_cleanup_document(&toml_doc);
            return -1;
        }
    }

    /* An empty active_account (e.g. after `reset`) is stored as "" — there is
     * no key-removal primitive, and the loader treats "" as "none saved". */
    if (toml_set_string(&toml_doc, "settings", "active_account",
                        ctx->config.active_account) != 0) {
        toml_cleanup_document(&toml_doc);
        return -1;
    }

    result = config_write_document_atomic(ctx, &toml_doc, config_path);
    toml_cleanup_document(&toml_doc);
    return result;
}

/* Create default configuration file */
int config_create_default(const char *config_path) {
    FILE *file;
    char config_dir[MAX_PATH_LEN];
    char *last_slash;
    
    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_create_default");
        return -1;
    }
    
    /* Extract directory from config path */
    safe_strncpy(config_dir, config_path, sizeof(config_dir));
    last_slash = strrchr(config_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    }
    
    /* Ensure directory exists */
    if (create_config_directory_secure(config_dir) != 0) {
        return -1;
    }
    
    /* Create the file with O_CREAT|O_EXCL (never follows symlinks) and mode
     * 0600 directly, instead of fopen("w") + chmod afterwards: fopen would
     * happily truncate-through an attacker-planted symlink, and the old
     * create-then-chmod left a window where the file existed with the
     * (potentially loose) umask permissions (cfg-symlink-01). */
    int fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to create config file: %s", config_path);
        return -1;
    }
    file = fdopen(fd, "w");
    if (!file) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to open config file stream: %s", config_path);
        close(fd);
        unlink(config_path);
        return -1;
    }

    /* Write default template */
    if (fwrite(default_config_template, 1, strlen(default_config_template), file) != 
        strlen(default_config_template)) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, "Failed to write default config content");
        fclose(file);
        return -1;
    }
    
    fclose(file);

    log_info("Created default configuration file: %s", config_path);
    return 0;
}

/* Validate configuration structure */
int config_validate(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        set_error(ERR_INVALID_ARGS, "NULL context to config_validate");
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
    
    /* Check for duplicate IDs and names. All per-account isolation state is
     * keyed by name — GNUPGHOME <base>/<name>, ssh-agent.<name>.sock,
     * active_account, current-account detection — so two accounts sharing a
     * name would share one GPG home and socket, defeating the isolation the
     * tool exists to provide. Names are matched case-insensitively because the
     * paths they build live on case-insensitive filesystems too. */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account->id) {
            set_error(ERR_ACCOUNT_EXISTS, "Account with ID %u already exists", account->id);
            return -1;
        }
        if (strcasecmp(ctx->accounts[i].name, account->name) == 0) {
            set_error(ERR_ACCOUNT_EXISTS, "Account named '%s' already exists", account->name);
            return -1;
        }
    }
    
    /* Add account */
    ctx->accounts[ctx->account_count] = *account;
    ctx->account_count++;
    
    log_info("Added account: %s (%s)", account->name, account->description);
    return 0;
}

/* Remove account from configuration */
int config_remove_account(gitswitch_ctx_t *ctx, uint32_t account_id) {
    size_t found_index = SIZE_MAX;
    
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
    
    /* Clear sensitive data before removing */
    secure_zero_memory(&ctx->accounts[found_index], sizeof(account_t));
    
    /* Shift remaining accounts */
    for (size_t i = found_index; i < ctx->account_count - 1; i++) {
        ctx->accounts[i] = ctx->accounts[i + 1];
    }
    
    ctx->account_count--;
    
    /* Clear the last slot */
    memset(&ctx->accounts[ctx->account_count], 0, sizeof(account_t));
    
    log_info("Removed account with ID: %u", account_id);
    return 0;
}

/* Update existing account */
int config_update_account(gitswitch_ctx_t *ctx, const account_t *account) {
    account_t *existing_account = NULL;
    
    if (!ctx || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_update_account");
        return -1;
    }
    
    /* Find existing account */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->accounts[i].id == account->id) {
            existing_account = &ctx->accounts[i];
            break;
        }
    }
    
    if (!existing_account) {
        set_error(ERR_ACCOUNT_NOT_FOUND, "Account with ID %u not found", account->id);
        return -1;
    }
    
    /* Validate new account data */
    if (validate_account_security(account) != 0) {
        return -1;
    }
    
    /* Clear old sensitive data */
    secure_zero_memory(existing_account, sizeof(account_t));
    
    /* Update with new data */
    *existing_account = *account;
    
    log_info("Updated account: %s (%s)", account->name, account->description);
    return 0;
}

/* Find account by identifier, exact matches first to avoid selecting the wrong
 * identity. Precedence: numeric id -> exact name -> exact email -> unambiguous
 * substring of name/description. A substring that matches more than one account
 * is rejected as ambiguous (rather than silently returning the first). */
account_t *config_find_account(gitswitch_ctx_t *ctx, const char *identifier) {
    char *endptr;
    unsigned long account_id;
    account_t *match = NULL;
    size_t match_count = 0;

    if (!ctx || !identifier || !*identifier) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_find_account");
        return NULL;
    }

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
                        return &ctx->accounts[i];
                    }
                }
            }
            /* No (valid) id match — fall through; may be a literal name. */
        }
    }

    /* 2. Exact name. */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].name, identifier) == 0) {
            return &ctx->accounts[i];
        }
    }

    /* 3. Exact email. */
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (strcmp(ctx->accounts[i].email, identifier) == 0) {
            return &ctx->accounts[i];
        }
    }

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

static int prune_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* Keep only the newest `keep` timestamped backups of config_path; delete older
 * ones so they don't accumulate unbounded (each holds account metadata). The
 * "%Y%m%d_%H%M%S" timestamp sorts lexicographically == chronologically. */
static void prune_old_backups(const char *config_path, size_t keep) {
    char dir[MAX_PATH_LEN];
    char prefix[MAX_PATH_LEN];
    const char *slash = strrchr(config_path, '/');
    const char *base;
    char names[64][256];
    size_t n = 0, plen;
    DIR *d;
    struct dirent *e;

    if (slash) {
        size_t dl = (size_t)(slash - config_path);
        if (dl >= sizeof(dir)) return;
        memcpy(dir, config_path, dl);
        dir[dl] = '\0';
        base = slash + 1;
    } else {
        strcpy(dir, ".");
        base = config_path;
    }
    if ((size_t)snprintf(prefix, sizeof(prefix), "%s.backup.", base) >= sizeof(prefix)) return;
    plen = strlen(prefix);

    d = opendir(dir);
    if (!d) return;
    while ((e = readdir(d)) != NULL && n < 64) {
        if (strncmp(e->d_name, prefix, plen) == 0) {
            snprintf(names[n], sizeof(names[n]), "%s", e->d_name);
            n++;
        }
    }
    closedir(d);
    if (n <= keep) return;

    qsort(names, n, sizeof(names[0]), prune_cmp);
    for (size_t i = 0; i < n - keep; i++) {
        char full[MAX_PATH_LEN];
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", dir, names[i]) < sizeof(full)) {
            unlink(full);
        }
    }
}

/* Backup configuration file with timestamp */
int config_backup(const char *config_path) {
    char backup_path[MAX_PATH_LEN];
    char timestamp[32];
    time_t now;
    struct tm *tm_info;
    
    if (!config_path) {
        set_error(ERR_INVALID_ARGS, "NULL config path to config_backup");
        return -1;
    }
    
    if (!path_exists(config_path)) {
        log_debug("Config file does not exist, no backup needed");
        return 0;
    }
    
    /* Generate timestamp */
    time(&now);
    tm_info = localtime(&now);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    } else {
        snprintf(timestamp, sizeof(timestamp), "%ld", (long)now);
    }
    
    /* Create backup path */
    if ((size_t)snprintf(backup_path, sizeof(backup_path), "%s.backup.%s", 
                        config_path, timestamp) >= sizeof(backup_path)) {
        set_error(ERR_INVALID_ARGS, "Backup path too long");
        return -1;
    }
    
    /* Copy without following symlinks on either end (cfg-symlink-01): a
     * symlinked accounts.toml would otherwise be read through (copying
     * another user's file into a backup we own), and the timestamped backup
     * name is predictable enough for an attacker to plant a symlink at it and
     * redirect the write. The destination is created O_EXCL with mode 0600,
     * so no separate chmod (and no loose-permission window) is needed. */
    if (copy_file_nofollow(config_path, backup_path) != 0) {
        return -1;
    }

    log_info("Created configuration backup: %s", backup_path);

    /* Keep the backup set bounded. */
    prune_old_backups(config_path, 5);
    return 0;
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
    struct stat st;
    char buf[4096];
    int sfd, dfd;
    ssize_t n;

    sfd = open(src_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot open backup source (symlink?): %s", src_path);
        return -1;
    }
    if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) {
        set_error(ERR_FILE_IO, "Backup source is not a regular file: %s", src_path);
        close(sfd);
        return -1;
    }

    /* O_EXCL never follows a symlink and fails if the name exists at all, so
     * a pre-planted backup destination cannot redirect the write. */
    dfd = open(dst_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (dfd < 0) {
        set_system_error(ERR_FILE_IO, "Cannot create backup file: %s", dst_path);
        close(sfd);
        return -1;
    }

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
            off += w;
        }
    }

    close(sfd);
    if (close(dfd) != 0) {
        unlink(dst_path);
        set_system_error(ERR_FILE_IO, "Failed to finalize backup file: %s", dst_path);
        return -1;
    }
    return 0;

fail:
    set_system_error(ERR_FILE_IO, "Failed to copy backup: %s -> %s", src_path, dst_path);
    close(sfd);
    close(dfd);
    unlink(dst_path);
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

                /* Optional SSH host alias */
                fs = get_account_field(doc, sections[i], "ssh_host",
                                       account.ssh_host_alias, sizeof(account.ssh_host_alias));
                if (fs == FIELD_UNLOADABLE) {
                    ctx->accounts_skipped_on_load++;
                    display_warning("Account '%s' (id %u) was skipped: %s",
                                    account.name, account_id, get_last_error()->message);
                    continue;
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

            /* Reject duplicate name (case-insensitive) or id against already-
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
                    strcasecmp(ctx->accounts[j].name, account.name) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account '%s' (id %u) duplicates the name or id of an "
                                "earlier account and was skipped; names and ids must be "
                                "unique because SSH/GPG isolation is keyed by them.",
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
 * anything was removed. text_is_tty_safe merely reports (identity-bearing
 * fields, where silent rewriting would change which key/socket paths the
 * name maps to). */
static bool sanitize_tty_text(char *text) {
    unsigned char *src = (unsigned char *)text;
    unsigned char *dst = (unsigned char *)text;
    bool modified = false;

    while (*src) {
        uint32_t cp;
        size_t len = utf8_decode(src, &cp);
        if (len == 0) {
            src++; /* malformed byte: drop it and resync */
            modified = true;
        } else if (!tty_safe_codepoint(cp)) {
            src += len;
            modified = true;
        } else {
            if (dst != src) memmove(dst, src, len);
            dst += len;
            src += len;
        }
    }
    *dst = '\0';
    return modified;
}

static bool text_is_tty_safe(const char *text) {
    const unsigned char *p = (const unsigned char *)text;

    while (*p) {
        uint32_t cp;
        size_t len = utf8_decode(p, &cp);
        if (len == 0 || !tty_safe_codepoint(cp)) {
            return false;
        }
        p += len;
    }
    return true;
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
                  "the config file (quote, backslash, or control byte): %s",
                  field_name, value);
        return -1;
    }
    return 0;
}

/* Validate account security */
static int validate_account_security(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];
    struct stat key_stat;

    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to validate");
        return -1;
    }

    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account name: %s", account->name);
        return -1;
    }

    if (validate_field_roundtrips("name", account->name) != 0 ||
        validate_field_roundtrips("description", account->description) != 0 ||
        validate_field_roundtrips("SSH host alias", account->ssh_host_alias) != 0) {
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

        /* One stat answers both the existence and the permission question
         * (AR-03 L17: this was a back-to-back path_exists +
         * get_file_permissions, two stats of the same path). Must be 600. */
        if (stat(expanded_path, &key_stat) != 0) {
            set_error(ERR_ACCOUNT_INVALID, "SSH key file not found: %s", expanded_path);
            return -1;
        }
        if ((key_stat.st_mode & 077) != 0) {
            set_error(ERR_ACCOUNT_INVALID,
                      "SSH key file has unsafe permissions: %o (should be 600)",
                      key_stat.st_mode & 0777);
            return -1;
        }
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
        
        /* Save SSH configuration */
        if (account->ssh_enabled && strlen(account->ssh_key_path) > 0) {
            toml_set_string(doc, section_name, "ssh_key", account->ssh_key_path);
            
            if (strlen(account->ssh_host_alias) > 0) {
                toml_set_string(doc, section_name, "ssh_host", account->ssh_host_alias);
            }
        }
        
        /* Save GPG configuration */
        if (account->gpg_enabled && strlen(account->gpg_key_id) > 0) {
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
