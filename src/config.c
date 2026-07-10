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

/* Linux, macOS and FreeBSD all provide O_NOFOLLOW; keep a guard for exotic
 * libcs so the file still compiles there. Refusing symlinks is load-bearing
 * for the config reader/writer (cfg-symlink-01/02), so every open below is
 * additionally paired with an explicit lstat()/fstat() check rather than
 * relying on the flag alone. */
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#include "accounts.h"
#include "config.h"
#include "toml_parser.h"
#include "error.h"
#include "utils.h"
#include "display.h"

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

/* Load configuration from TOML file */
int config_load(gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    char scope_str[32];
    char *buffer = NULL;
    struct stat fst;
    size_t file_size, total = 0;
    int fd;

    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_load");
        return -1;
    }

    /* Open with O_NOFOLLOW and validate the fd, then read and parse from that
     * same fd (cfg-symlink-01/02). The old flow validated the path with
     * stat() and then had the parser fopen() the path a second time, so a
     * symlinked accounts.toml passed validation against its target and,
     * worse, the file validated and the file parsed could differ (TOCTOU).
     * Parsing the bytes read from the validated fd removes the second
     * path lookup entirely. */
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
    toml_init_document(&toml_doc);
    if (toml_parse_string(buffer, file_size, &toml_doc) != 0) {
        toml_cleanup_document(&toml_doc);
        goto fail_buffer;
    }

    /* Config content can reference key material paths; don't leave a stray
     * copy on the heap (mirrors toml_parse_file's cleanup discipline). */
    secure_zero_memory(buffer, file_size + 1);
    free(buffer);
    buffer = NULL;

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

fail_buffer:
    if (buffer) {
        secure_zero_memory(buffer, file_size + 1);
        free(buffer);
    }
    return -1;
}

/* Acquire an exclusive, cross-process lock for a mutating config cycle. Returns
 * an open fd holding flock(LOCK_EX) on <config_dir>/.config.lock; hold it across
 * the whole load-modify-save so concurrent add/edit/remove/switch cannot
 * lost-update each other. The atomic temp+rename in config_save only prevents a
 * torn file, not a lost update: two processes that each load, mutate, and rename
 * would have the second silently discard the first's changes. Close the fd to
 * release. Returns -1 on failure; callers must treat that as fatal for a
 * mutating command — proceeding unlocked reopens the lost-update race
 * (AR-02 #17). */
int config_write_lock(void) {
    char dir[MAX_PATH_LEN];
    char lockpath[MAX_PATH_LEN];
    if (get_config_directory(dir, sizeof(dir)) != 0) return -1;
    if (create_config_directory_secure(dir) != 0) return -1;
    if ((size_t)snprintf(lockpath, sizeof(lockpath), "%s/.config.lock", dir) >= sizeof(lockpath)) {
        return -1;
    }
    int fd = open(lockpath, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
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
 * whether a boot-time resume is worth attempting. Cheap and best-effort. */
static void config_update_resume_hint(const gitswitch_ctx_t *ctx) {
    char hint[MAX_PATH_LEN];
    if (config_resume_hint_path(hint, sizeof(hint)) != 0) return;
    if (ctx->config.active_account[0] != '\0') {
        FILE *f = fopen(hint, "w");
        if (f) fclose(f);
    } else {
        unlink(hint);
    }
}

/* Save configuration to TOML file */
int config_save(const gitswitch_ctx_t *ctx, const char *config_path) {
    toml_document_t toml_doc;
    char temp_path[MAX_PATH_LEN];
    int result = -1;
    
    if (!ctx || !config_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to config_save");
        return -1;
    }

    /* Refuse to rewrite the file when the load dropped one or more account
     * sections: the in-memory set is an incomplete view, and a full rewrite
     * would silently erase the skipped accounts. Preserve the on-disk file
     * (including those sections) and tell the user to fix them first. */
    if (ctx->accounts_skipped_on_load > 0) {
        display_warning("Not saving config: %zu account(s) failed to load and would be lost. "
                        "Fix them in %s (or their key files/permissions), then retry.",
                        ctx->accounts_skipped_on_load, config_path);
        return 0;
    }

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
    
    /* Write to temporary file first (already created 0600 above, so the
     * content is never observable with looser permissions) */
    if (toml_write_file(&toml_doc, temp_path) != 0) {
        unlink(temp_path); /* don't leave a stale/partial .tmp behind */
        goto cleanup;
    }

    /* Atomic move from temp to final location */
    if (rename(temp_path, config_path) != 0) {
        set_system_error(ERR_CONFIG_WRITE_FAILED, 
                        "Failed to move temporary config file to final location");
        unlink(temp_path);
        goto cleanup;
    }
    
    log_info("Configuration saved successfully to: %s", config_path);
    config_update_resume_hint(ctx);
    result = 0;

cleanup:
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
    if (!path_exists(config_dir)) {
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        log_info("Created configuration directory: %s", config_dir);
    }
    
    /* Verify directory permissions */
    mode_t dir_mode;
    if (get_file_permissions(config_dir, &dir_mode) == 0) {
        if ((dir_mode & 077) != 0) {
            /* Directory has group/other permissions - fix it */
            if (set_file_permissions(config_dir, PERM_USER_RWX) != 0) {
                return -1;
            }
            log_warning("Fixed configuration directory permissions");
        }
    }
    
    return 0;
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
            
            /* Load required fields. Skipped, not dropped: toml_get_string
             * fails here both for a MISSING field and for a value too long
             * for the destination (e.g. a name over MAX_NAME_LEN — schema-
             * valid, so the whole-file parse succeeded), and either way the
             * in-memory set is now an incomplete view of the file. Without
             * the skip count, config_save's refuse-to-rewrite guard read
             * zero and the very next save permanently erased this section
             * (AR-02 #5). Warn on stderr so the cause is visible. */
            if (toml_get_string(doc, sections[i], "name", account.name, sizeof(account.name)) != 0) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account section [%s] was skipped: 'name' is missing or "
                                "too long (max %d bytes). Fix it in the config file.",
                                sections[i], MAX_NAME_LEN - 1);
                continue;
            }

            if (toml_get_string(doc, sections[i], "email", account.email, sizeof(account.email)) != 0) {
                ctx->accounts_skipped_on_load++;
                display_warning("Account section [%s] ('%s') was skipped: 'email' is "
                                "missing or too long (max %d bytes). Fix it in the config file.",
                                sections[i], account.name[0] ? account.name : "?",
                                MAX_EMAIL_LEN - 1);
                continue;
            }
            
            /* Load optional fields - clear errors after each since missing optional fields are not errors */
            if (toml_get_string(doc, sections[i], "description",
                               account.description, sizeof(account.description)) != 0) {
                /* Use name as description if not provided */
                safe_strncpy(account.description, account.name, sizeof(account.description));
                clear_error();
            }

            /* The description is printed raw by list/status/whoami. Today
             * toml_get_string's own sanitize pass happens to strip control
             * and non-ASCII bytes, but that is a retrieval-layer detail of
             * another module — the config layer must guarantee for itself
             * that nothing it hands to display can drive the terminal
             * (tty-escape). The description is display-only, so strip here
             * at the trust boundary instead of rejecting the account; the
             * identity-bearing name is instead *rejected* by
             * validate_account_security below if it is unsafe. */
            if (sanitize_tty_text(account.description)) {
                display_warning("Account '%s' (id %u): removed terminal control bytes "
                                "from description.",
                                account.name[0] ? account.name : "?", account_id);
            }

            if (toml_get_string(doc, sections[i], "preferred_scope", temp_str, sizeof(temp_str)) == 0) {
                account.preferred_scope = config_parse_scope(temp_str);
            } else {
                clear_error();
            }

            /* SSH configuration */
            if (toml_get_string(doc, sections[i], "ssh_key",
                               account.ssh_key_path, sizeof(account.ssh_key_path)) == 0 &&
                strlen(account.ssh_key_path) > 0) {
                account.ssh_enabled = true;

                /* Expand path if needed */
                char expanded_path[MAX_PATH_LEN];
                if (expand_path(account.ssh_key_path, expanded_path, sizeof(expanded_path)) == 0) {
                    safe_strncpy(account.ssh_key_path, expanded_path, sizeof(account.ssh_key_path));
                }

                /* Optional SSH host alias */
                if (toml_get_string(doc, sections[i], "ssh_host",
                                   account.ssh_host_alias, sizeof(account.ssh_host_alias)) != 0) {
                    clear_error();
                }
            } else {
                clear_error();
            }

            /* GPG configuration */
            if (toml_get_string(doc, sections[i], "gpg_key",
                               account.gpg_key_id, sizeof(account.gpg_key_id)) == 0 &&
                strlen(account.gpg_key_id) > 0) {
                account.gpg_enabled = true;

                /* GPG signing preference */
                if (toml_get_boolean(doc, sections[i], "gpg_signing_enabled", &temp_bool) != 0) {
                    clear_error();
                } else {
                    account.gpg_signing_enabled = temp_bool;
                }
            } else {
                clear_error();
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

/* Decode one UTF-8 sequence starting at s, writing the codepoint to *cp_out
 * and returning the number of bytes consumed, or 0 if the sequence is
 * malformed. Deliberately strict: overlong encodings and surrogates are
 * rejected, because an overlong form (e.g. 0xE0 0x80 0x9B) is exactly how a
 * C1 terminal control sneaks past a naive byte filter into a lenient
 * terminal decoder. NUL and stray continuation bytes fail the
 * (b & 0xC0) == 0x80 test, so NUL-terminated strings need no length bound. */
static size_t utf8_decode(const unsigned char *s, uint32_t *cp_out) {
    unsigned char b0 = s[0];

    if (b0 < 0x80) {
        *cp_out = b0;
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if ((s[1] & 0xC0) != 0x80) return 0;
        *cp_out = ((uint32_t)(b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (b0 == 0xE0 && s[1] < 0xA0) return 0;              /* overlong */
        if (b0 == 0xED && s[1] >= 0xA0) return 0;             /* surrogate */
        *cp_out = ((uint32_t)(b0 & 0x0F) << 12) |
                  ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        if (b0 == 0xF0 && s[1] < 0x90) return 0;              /* overlong */
        if (b0 == 0xF4 && s[1] > 0x8F) return 0;              /* > U+10FFFF */
        *cp_out = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
                  ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0; /* 0x80-0xC1 lead (bare continuation/overlong) or 0xF5+ */
}

/* True if the codepoint is safe to echo to a terminal. C0 controls
 * (including ESC 0x1B and CR), DEL 0x7F, and C1 controls U+0080-U+009F
 * (0x9B is a one-byte CSI) can move the cursor, recolor output, or
 * \r-overwrite the line — enough for a hostile config field to render
 * itself as "[CURRENT] trusted-account" in list/status/whoami output. */
static bool tty_safe_codepoint(uint32_t cp) {
    return cp >= 0x20 && cp != 0x7F && !(cp >= 0x80 && cp <= 0x9F);
}

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

/* Validate account security */
static int validate_account_security(const account_t *account) {
    char expanded_path[MAX_PATH_LEN];
    mode_t file_mode;
    
    if (!account) {
        set_error(ERR_INVALID_ARGS, "NULL account to validate");
        return -1;
    }
    
    /* Validate required fields */
    if (!validate_name(account->name)) {
        set_error(ERR_ACCOUNT_INVALID, "Invalid account name: %s", account->name);
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
        
        if (!path_exists(expanded_path)) {
            set_error(ERR_ACCOUNT_INVALID, "SSH key file not found: %s", expanded_path);
            return -1;
        }
        
        /* Check SSH key file permissions - must be 600 */
        if (get_file_permissions(expanded_path, &file_mode) == 0) {
            if ((file_mode & 077) != 0) {
                set_error(ERR_ACCOUNT_INVALID, 
                          "SSH key file has unsafe permissions: %o (should be 600)", 
                          file_mode & 0777);
                return -1;
            }
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