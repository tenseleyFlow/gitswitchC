/* GPG key and environment management with comprehensive isolation and security
 * Implements per-account GNUPGHOME environments to prevent GPG key mixing
 */

/* _XOPEN_SOURCE 700 (implies POSIX.1-2008) exposes nftw()/FTW_* from <ftw.h>
 * on glibc, which _POSIX_C_SOURCE alone does not. */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ftw.h>

#include "gpg_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "git_ops.h"

/* Internal helper functions */
static int gpg_get_base_dir(char *buf, size_t size);
static int update_current_symlink(const char *real_home);
static int create_isolated_gnupg_home_dir(const char *gnupg_home);
static void gpg_build_env(const gpg_config_t *cfg, char *envbuf, size_t envbuf_size,
                          const char *env_out[2]);
static int gpg_run(const gpg_config_t *cfg, char *output, size_t output_size, ...);
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id);
static int setup_gpg_agent_config(const char *gnupg_home);

/* Initialize GPG manager with specified mode */
int gpg_manager_init(gpg_config_t *gpg_config, gpg_mode_t mode) {
    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_manager_init");
        return -1;
    }
    
    log_debug("Initializing GPG manager with mode: %d", mode);
    
    /* Initialize GPG configuration */
    memset(gpg_config, 0, sizeof(gpg_config_t));
    gpg_config->mode = mode;
    gpg_config->signing_enabled = false;
    gpg_config->home_owned = false;
    
    /* Initialize based on mode */
    switch (mode) {
        case GPG_MODE_SYSTEM:
            /* Use system GNUPGHOME */
            log_debug("Using system GPG environment");
            break;
            
        case GPG_MODE_ISOLATED:
            /* Will create isolated GNUPGHOME per account */
            log_debug("GPG manager initialized for isolated environments");
            break;
            
        case GPG_MODE_SHARED:
            /* Shared GNUPGHOME with key switching */
            log_debug("GPG manager initialized for shared environment");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", mode);
            return -1;
    }
    
    /* Verify GPG is available */
    if (!command_exists("gpg")) {
        set_error(ERR_GPG_NOT_FOUND, "GPG command not found in PATH");
        return -1;
    }
    
    log_info("GPG manager initialized successfully");
    return 0;
}

/* Cleanup GPG manager */
void gpg_manager_cleanup(gpg_config_t *gpg_config) {
    if (!gpg_config) {
        return;
    }
    
    log_debug("Cleaning up GPG manager");

    /* Intentionally NOT deleting the isolated GNUPGHOME. Isolated homes are
     * keyed by account and persist across switches (mirroring how the SSH agent
     * persists): the user's shell points GNUPGHOME at the <base>/current
     * symlink, so removing a home could pull the rug out from under a shell
     * still pointed at it. Homes are reused on switch-back, and re-import is
     * skipped when the key is already present. A deliberate teardown command
     * (not yet implemented) is the right place to reclaim them. */

    /* Clear configuration */
    memset(gpg_config, 0, sizeof(gpg_config_t));
    
    log_debug("GPG manager cleanup completed");
}

/* Switch to account's GPG configuration with complete isolation */
int gpg_switch_account(gpg_config_t *gpg_config, const account_t *account) {
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_switch_account");
        return -1;
    }
    
    /* Skip if GPG not enabled for account */
    if (!account->gpg_enabled || strlen(account->gpg_key_id) == 0) {
        log_debug("GPG not enabled for account: %s", account->name);
        return 0;
    }
    
    log_info("Switching to GPG configuration for account: %s", account->name);
    log_debug("Account GPG key ID: %s", account->gpg_key_id);
    
    /* Handle different GPG modes */
    switch (gpg_config->mode) {
        case GPG_MODE_SYSTEM:
            /* Just validate key exists in system keyring */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found in system keyring: %s", 
                         account->gpg_key_id);
                return -1;
            }
            break;
            
        case GPG_MODE_ISOLATED:
            /* Create isolated GNUPGHOME for account */
            if (gpg_create_isolated_home(gpg_config, account) != 0) {
                set_error(ERR_GPG_KEY_FAILED, "Failed to create isolated GPG environment: %s", 
                         get_last_error()->message);
                return -1;
            }
            
            /* Copy key from system keyring to isolated environment */
            if (copy_key_from_system_keyring(gpg_config, account->gpg_key_id) != 0) {
                log_warning("Failed to copy GPG key to isolated environment: %s", 
                           get_last_error()->message);
                /* Continue anyway - maybe key is already there */
            }
            
            /* Validate key is available in isolated environment */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available in isolated environment: %s", 
                         account->gpg_key_id);
                return -1;
            }
            break;
            
        case GPG_MODE_SHARED:
            /* Validate key exists and switch to it */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", account->gpg_key_id);
                return -1;
            }
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", gpg_config->mode);
            return -1;
    }
    
    /* Update GPG configuration */
    safe_strncpy(gpg_config->current_key_id, account->gpg_key_id, sizeof(gpg_config->current_key_id));
    gpg_config->signing_enabled = account->gpg_signing_enabled;
    
    /* Set environment variable if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED) {
        if (gpg_set_environment(gpg_config) != 0) {
            log_warning("Failed to set GPG environment variable: %s", get_last_error()->message);
        }
    }
    
    /* Test GPG signing if enabled */
    if (account->gpg_signing_enabled) {
        if (gpg_test_signing(gpg_config, account->gpg_key_id) != 0) {
            log_warning("GPG signing test failed for key: %s", account->gpg_key_id);
            /* Don't fail completely, just warn */
        } else {
            log_info("GPG signing test passed for key: %s", account->gpg_key_id);
        }
    }

    /* Retarget the stable GNUPGHOME symlink to this account's now-ready home so
     * a shell exporting GNUPGHOME=<base>/current follows the switch. Done last,
     * after the key is imported and validated. Isolated mode only; non-fatal. */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        update_current_symlink(gpg_config->gnupg_home);
    }

    log_info("Successfully switched to GPG configuration for account: %s", account->name);
    return 0;
}

/* Compute the base directory that holds per-account isolated GNUPGHOMEs and the
 * stable `current` symlink. Two-way like the SSH side: prefer XDG_RUNTIME_DIR,
 * else /tmp/gitswitch-gpg-<uid>. There is deliberately no HOME fallback: that
 * branch would place secret-key material on persistent disk, and its longer
 * paths risk overrunning the gpg-agent socket sun_path limit. Returns 0 on
 * success. */
static int gpg_get_base_dir(char *buf, size_t size) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    int written;

    if (!buf || size == 0) {
        set_error(ERR_INVALID_ARGS, "NULL/empty buffer to gpg_get_base_dir");
        return -1;
    }

    if (runtime_dir && *runtime_dir && path_exists(runtime_dir)) {
        written = snprintf(buf, size, "%s/gitswitch-gpg", runtime_dir);
    } else {
        written = snprintf(buf, size, "/tmp/gitswitch-gpg-%d", getuid());
    }

    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG base directory path too long");
        return -1;
    }
    return 0;
}

/* Public: compute the stable GNUPGHOME path that `gitswitch init` exports and
 * that the per-switch symlink points at. Shared with gpg_get_base_dir so the
 * symlink location and the shell-integration path never disagree. Mirrors
 * ssh_manager_get_auth_sock_path(). Returns 0 on success, -1 on overflow. */
int gpg_manager_get_home_path(char *buf, size_t size) {
    char base_dir[MAX_PATH_LEN];
    int written;

    if (!buf || size == 0) {
        set_error(ERR_INVALID_ARGS, "NULL/empty buffer to gpg_manager_get_home_path");
        return -1;
    }

    if (gpg_get_base_dir(base_dir, sizeof(base_dir)) != 0) {
        return -1;
    }

    written = snprintf(buf, size, "%s/current", base_dir);
    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG home path too long");
        return -1;
    }
    return 0;
}

/* Point the stable <base>/current symlink at the active account's real
 * GNUPGHOME so a shell that exports GNUPGHOME=<base>/current (via
 * `gitswitch init`) transparently follows each switch. Mirrors the SSH
 * current.sock retargeting in ssh_manager.c. Non-fatal on failure. */
static int update_current_symlink(const char *real_home) {
    char link_path[MAX_PATH_LEN];

    if (!real_home || strlen(real_home) == 0) {
        return -1;
    }

    if (gpg_manager_get_home_path(link_path, sizeof(link_path)) != 0) {
        return -1;
    }

    /* Atomically retarget (temp symlink + rename) so a follower never sees a
     * missing or half-updated link. */
    if (atomic_symlink(real_home, link_path) != 0) {
        log_warning("Failed to create GNUPGHOME symlink %s -> %s",
                    link_path, real_home);
        return -1;
    }

    log_debug("Created GNUPGHOME symlink: %s -> %s", link_path, real_home);
    return 0;
}

/* nftw callback: remove a single path (depth-first, so children precede dirs). */
static int rm_tree_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

/* Recursively remove a directory tree (no shell). */
static int remove_tree(const char *path) {
    return nftw(path, rm_tree_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* Kill the gpg-agent in an isolated home (best-effort) and delete the home. */
static void gpg_kill_and_remove_home(const char *home) {
    const char *argv[] = {"gpgconf", "--kill", "all", NULL};
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2] = {NULL, NULL};
    run_opts_t opts;

    memset(&opts, 0, sizeof(opts));
    if ((size_t)snprintf(envbuf, sizeof(envbuf), "GNUPGHOME=%s", home) < sizeof(envbuf)) {
        env[0] = envbuf;
        opts.extra_env = env;
    }
    opts.stderr_to_devnull = true;
    run_argv(argv, &opts, NULL); /* best-effort; gpgconf may be absent */
    remove_tree(home);
    log_debug("Removed isolated GPG home: %s", home);
}

/* Tear down isolated GPG homes: one account, or all when account is NULL.
 * Kills the per-home gpg-agents and deletes the homes (wiping the on-disk
 * secret-key copies), then drops the stable `current` symlink if it dangles. */
int gpg_manager_reset(const char *account) {
    char base[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];

    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }

    if (account && *account) {
        char home[MAX_PATH_LEN];
        if ((size_t)snprintf(home, sizeof(home), "%s/%s", base, account) >= sizeof(home)) {
            return -1;
        }
        if (path_exists(home)) {
            gpg_kill_and_remove_home(home);
        }
    } else {
        DIR *d = opendir(base);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                char home[MAX_PATH_LEN];
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0 ||
                    strcmp(ent->d_name, "current") == 0) {
                    continue;
                }
                if ((size_t)snprintf(home, sizeof(home), "%s/%s", base, ent->d_name) < sizeof(home)) {
                    gpg_kill_and_remove_home(home);
                }
            }
            closedir(d);
        }
    }

    /* Drop the stable symlink if it no longer points at a live home. */
    if (gpg_manager_get_home_path(current, sizeof(current)) == 0) {
        char target[MAX_PATH_LEN];
        ssize_t n = readlink(current, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            if (!path_exists(target)) {
                unlink(current);
            }
        }
    }
    return 0;
}

/* Create isolated GNUPGHOME for account */
int gpg_create_isolated_home(gpg_config_t *gpg_config, const account_t *account) {
    char gnupg_base_dir[MAX_PATH_LEN];
    char gnupg_home[MAX_PATH_LEN];

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_create_isolated_home");
        return -1;
    }

    /* Determine base directory for isolated GNUPGHOME (shared with the stable
     * `current` symlink path so the two never disagree). */
    if (gpg_get_base_dir(gnupg_base_dir, sizeof(gnupg_base_dir)) != 0) {
        return -1;
    }

    /* Create + verify the base directory (real, user-owned, 0700; not a
     * symlink or a dir pre-created by another user in a shared /tmp). */
    if (ensure_private_dir(gnupg_base_dir) != 0) {
        return -1;
    }
    
    /* Create account-specific GNUPGHOME */
    if (safe_snprintf(gnupg_home, sizeof(gnupg_home), "%s/%s", gnupg_base_dir, account->name) != 0) {
        set_error(ERR_INVALID_PATH, "GNUPGHOME path too long");
        return -1;
    }
    
    /* Create isolated GNUPGHOME directory */
    if (create_isolated_gnupg_home_dir(gnupg_home) != 0) {
        return -1;
    }
    
    /* Set up GPG agent configuration */
    if (setup_gpg_agent_config(gnupg_home) != 0) {
        log_warning("Failed to set up GPG agent config: %s", get_last_error()->message);
        /* Continue anyway */
    }
    
    /* Update GPG configuration */
    safe_strncpy(gpg_config->gnupg_home, gnupg_home, sizeof(gpg_config->gnupg_home));
    gpg_config->home_owned = true;
    
    log_info("Created isolated GNUPGHOME: %s", gnupg_home);
    return 0;
}

/* Import GPG key from file or keyserver */
int gpg_import_key(gpg_config_t *gpg_config, const char *key_source) {
    char output[1024];
    int result;
    
    if (!gpg_config || !key_source) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_import_key");
        return -1;
    }
    
    log_debug("Importing GPG key from: %s", key_source);

    /* Import from a key file, or fetch by id from the keyserver. */
    if (path_exists(key_source)) {
        result = gpg_run(gpg_config, output, sizeof(output),
                         "gpg", "--import", key_source, NULL);
    } else {
        result = gpg_run(gpg_config, output, sizeof(output),
                         "gpg", "--keyserver", "hkps://keys.openpgp.org",
                         "--recv-keys", key_source, NULL);
    }
    if (result != 0) {
        set_error(ERR_GPG_KEY_FAILED, "Failed to import GPG key: %s", output);
        return -1;
    }
    
    log_info("Successfully imported GPG key from: %s", key_source);
    return 0;
}

/* Export GPG public key for backup/sharing */
int gpg_export_public_key(gpg_config_t *gpg_config, const char *key_id,
                          char *output, size_t output_size) {
    if (!gpg_config || !key_id || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_export_public_key");
        return -1;
    }

    return gpg_run(gpg_config, output, output_size,
                   "gpg", "--armor", "--export", key_id, NULL);
}

/* List available GPG keys */
int gpg_list_keys(gpg_config_t *gpg_config, char *output, size_t output_size) {
    if (!gpg_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_list_keys");
        return -1;
    }
    
    return gpg_run(gpg_config, output, output_size,
                   "gpg", "--list-keys", "--with-colons", NULL);
}

/* Validate GPG key exists and is usable */
int gpg_validate_key(gpg_config_t *gpg_config, const char *key_id) {
    char output[512];
    int result;

    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_validate_key");
        return -1;
    }

    log_debug("Validating GPG key: %s", key_id);

    result = gpg_run(gpg_config, output, sizeof(output),
                     "gpg", "--list-secret-keys", key_id, NULL);
    if (result != 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", key_id);
        return -1;
    }
    
    log_debug("GPG key validation passed: %s", key_id);
    return 0;
}

/* Configure git GPG signing */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, git_scope_t scope) {
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_configure_git_signing");
        return -1;
    }
    
    /* Skip if GPG signing not enabled */
    if (!account->gpg_signing_enabled) {
        log_debug("GPG signing not enabled for account: %s", account->name);
        
        /* Disable git signing */
        if (git_set_config_value("commit.gpgsign", "false", scope) != 0) {
            log_warning("Failed to disable git GPG signing");
        }
        return 0;
    }
    
    log_info("Configuring git GPG signing for account: %s", account->name);
    
    /* Set signing key */
    if (git_set_config_value("user.signingkey", account->gpg_key_id, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git signing key");
        return -1;
    }
    
    /* Enable GPG signing */
    if (git_set_config_value("commit.gpgsign", "true", scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to enable git GPG signing");
        return -1;
    }
    
    /* GNUPGHOME is already set via gpg_set_environment() - no need to override
     * gpg.program. git inherits the env var and gpg uses it automatically.
     * Setting gpg.program to "gpg --homedir ..." breaks because git execs it
     * as a single binary path, not a shell command. */
    git_unset_config_value("gpg.program", scope);
    
    log_info("Git GPG signing configured successfully for account: %s", account->name);
    return 0;
}

/* Return true if `gpg --with-colons` output contains a secret-key record
 * (primary `sec` or subkey `ssb`) whose capability field (field 12, the 12th
 * ':'-separated field) advertises signing. Lowercase 's' means this key can
 * sign; uppercase 'S' on a primary means a signing-capable subkey exists. */
bool gpg_colons_have_sign_capability(const char *colons) {
    const char *line;

    if (!colons) {
        return false;
    }

    for (line = colons; line && *line; ) {
        const char *eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line) : strlen(line);

        if (line_len >= 3 &&
            (strncmp(line, "sec", 3) == 0 || strncmp(line, "ssb", 3) == 0)) {
            const char *line_end = line + line_len;
            const char *field_start = line;
            const char *p;
            int field = 0;

            for (p = line; p <= line_end; p++) {
                if (p == line_end || *p == ':') {
                    if (field == 11) {  /* field 12, 0-indexed: capabilities */
                        const char *c;
                        for (c = field_start; c < p; c++) {
                            if (*c == 's' || *c == 'S') {
                                return true;
                            }
                        }
                        break;
                    }
                    field++;
                    field_start = p + 1;
                }
            }
        }

        if (!eol) {
            break;
        }
        line = eol + 1;
    }

    return false;
}

/* Verify the isolated keyring can sign for key_id, without unlocking the key.
 * The previous implementation ran an interactive `gpg --clearsign`, which
 * forced a pinentry PIN prompt on every switch and failed outright when the
 * configured pinentry path was wrong. Instead, confirm a signing-capable secret
 * key is present via the colon-delimited listing: PIN-free, pinentry-free, and
 * sufficient — real signing is exercised when the user actually commits. */
int gpg_test_signing(gpg_config_t *gpg_config, const char *key_id) {
    char output[4096];
    int result;

    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_test_signing");
        return -1;
    }

    log_debug("Verifying signing capability for key: %s", key_id);

    result = gpg_run(gpg_config, output, sizeof(output),
                     "gpg", "--list-secret-keys", "--with-colons", key_id, NULL);
    if (result != 0) {
        set_error(ERR_GPG_SIGNING_FAILED, "No secret key available for signing: %s", key_id);
        return -1;
    }

    if (!gpg_colons_have_sign_capability(output)) {
        set_error(ERR_GPG_SIGNING_FAILED, "Key has no signing-capable secret key: %s", key_id);
        return -1;
    }

    log_debug("Signing capability confirmed for key: %s", key_id);
    return 0;
}

/* Generate new GPG key for account */
int gpg_generate_key(gpg_config_t *gpg_config, const account_t *account) {
    char key_params[512];
    char output[2048];
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2];
    run_opts_t opts;
    const char *argv[] = {"gpg", "--batch", "--generate-key", NULL};

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_generate_key");
        return -1;
    }

    log_info("Generating new GPG key for account: %s", account->name);

    /* Key-generation parameters are fed to gpg on stdin (no shell). */
    if (safe_snprintf(key_params, sizeof(key_params),
                     "Key-Type: RSA\n"
                     "Key-Length: 4096\n"
                     "Subkey-Type: RSA\n"
                     "Subkey-Length: 4096\n"
                     "Name-Real: %s\n"
                     "Name-Email: %s\n"
                     "Expire-Date: 2y\n"
                     "%%commit\n"
                     "%%echo done\n",
                     account->name, account->email) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG key parameters too long");
        return -1;
    }

    gpg_build_env(gpg_config, envbuf, sizeof(envbuf), env);
    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.input = key_params;
    opts.input_len = strlen(key_params);
    opts.merge_stderr = true;
    if (env[0]) opts.extra_env = env;

    if (run_argv(argv, &opts, NULL) != 0) {
        set_error(ERR_GPG_KEY_FAILED, "Failed to generate GPG key: %s", output);
        return -1;
    }

    log_info("Successfully generated GPG key for account: %s", account->name);
    return 0;
}

/* Set environment variables for GPG operation */
int gpg_set_environment(const gpg_config_t *gpg_config) {
    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_set_environment");
        return -1;
    }
    
    /* Set GNUPGHOME if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        if (setenv("GNUPGHOME", gpg_config->gnupg_home, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set GNUPGHOME environment variable");
            return -1;
        }
        
        log_debug("Set GNUPGHOME environment variable: %s", gpg_config->gnupg_home);
    }
    
    return 0;
}

/* Internal helper functions */

/* Create isolated GNUPGHOME directory with proper permissions */
static int create_isolated_gnupg_home_dir(const char *gnupg_home) {
    if (!gnupg_home) {
        set_error(ERR_INVALID_ARGS, "NULL gnupg_home path");
        return -1;
    }

    /* Create + verify: real dir, owned by us, 0700, not a symlink. This holds
     * exported secret-key material, so a hostile pre-created/redirected dir
     * must be refused. */
    if (ensure_private_dir(gnupg_home) != 0) {
        return -1;
    }

    log_debug("Created isolated GNUPGHOME directory: %s", gnupg_home);
    return 0;
}

/* Build a one-entry GNUPGHOME extra-env array for isolated mode (else empty). */
static void gpg_build_env(const gpg_config_t *cfg, char *envbuf, size_t envbuf_size,
                          const char *env_out[2]) {
    env_out[0] = NULL;
    env_out[1] = NULL;
    if (cfg && cfg->mode == GPG_MODE_ISOLATED && strlen(cfg->gnupg_home) > 0) {
        if ((size_t)snprintf(envbuf, envbuf_size, "GNUPGHOME=%s", cfg->gnupg_home) < envbuf_size) {
            env_out[0] = envbuf;
        }
    }
}

/* Run `gpg`/argv (NULL-terminated varargs, argv[0] is the first vararg), no
 * shell, with GNUPGHOME set from cfg in isolated mode. Captures merged
 * stdout+stderr. Returns 0 iff the child exits 0. */
static int gpg_run(const gpg_config_t *cfg, char *output, size_t output_size, ...) {
    const char *argv[24];
    size_t n = 0;
    va_list ap;
    const char *a;
    run_opts_t opts;
    run_result_t res;
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2];

    va_start(ap, output_size);
    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            va_end(ap);
            set_error(ERR_INVALID_ARGS, "Too many gpg arguments");
            return -1;
        }
        argv[n++] = a;
    }
    va_end(ap);
    argv[n] = NULL;

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = true;
    gpg_build_env(cfg, envbuf, sizeof(envbuf), env);
    if (env[0]) opts.extra_env = env;

    return run_argv(argv, &opts, &res);
}

/* Copy GPG key from system keyring to isolated environment */
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id) {
    char key_data[8192];
    char check_output[1024];
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2];
    run_opts_t opts;
    run_result_t res;

    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_key_from_system_keyring");
        return -1;
    }

    log_debug("Copying GPG key from system keyring: %s", key_id);

    /* Idempotency: if the secret key is already present in the isolated home
     * (e.g. switching back to an account whose home persists from an earlier
     * switch), skip the export/import. The export step prompts the system
     * agent's PIN, so skipping it avoids a PIN prompt on every switch. */
    if (gpg_run(gpg_config, check_output, sizeof(check_output),
                "gpg", "--list-secret-keys", key_id, NULL) == 0) {
        log_debug("Secret key already present in isolated home; skipping import: %s", key_id);
        return 0;
    }

    /* Export the secret key from the SYSTEM keyring (no GNUPGHOME override). */
    {
        const char *export_argv[] = {"gpg", "--armor", "--export-secret-keys", key_id, NULL};
        memset(&opts, 0, sizeof(opts));
        opts.out = key_data;
        opts.out_size = sizeof(key_data);
        opts.stderr_to_devnull = true;
        if (run_argv(export_argv, &opts, &res) != 0 || res.out_len == 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND, "Failed to export GPG key from system keyring");
            return -1;
        }
    }

    /* Import into the isolated GNUPGHOME by feeding the key on stdin. */
    {
        const char *import_argv[] = {"gpg", "--batch", "--import", NULL};
        gpg_build_env(gpg_config, envbuf, sizeof(envbuf), env);
        memset(&opts, 0, sizeof(opts));
        opts.input = key_data;
        opts.input_len = res.out_len;
        opts.stderr_to_devnull = true;
        if (env[0]) opts.extra_env = env;
        if (run_argv(import_argv, &opts, NULL) != 0) {
            set_error(ERR_GPG_KEY_FAILED, "Failed to import GPG key into isolated environment");
            return -1;
        }
    }

    log_info("Successfully copied GPG key to isolated environment: %s", key_id);
    return 0;
}

/* Set up GPG agent configuration for isolated environment */
static int setup_gpg_agent_config(const char *gnupg_home) {
    char gpg_agent_conf_path[MAX_PATH_LEN];
    FILE *conf_file;
    
    if (!gnupg_home) {
        set_error(ERR_INVALID_ARGS, "NULL gnupg_home path");
        return -1;
    }
    
    /* Create gpg-agent.conf path */
    if (safe_snprintf(gpg_agent_conf_path, sizeof(gpg_agent_conf_path), 
                     "%s/gpg-agent.conf", gnupg_home) != 0) {
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        return -1;
    }
    
    /* Create basic gpg-agent.conf */
    conf_file = fopen(gpg_agent_conf_path, "w");
    if (!conf_file) {
        set_system_error(ERR_FILE_IO, "Failed to create gpg-agent.conf");
        return -1;
    }
    
    fprintf(conf_file, "# GPG Agent configuration for gitswitch isolated environment\n");
    fprintf(conf_file, "default-cache-ttl 3600\n");
    fprintf(conf_file, "max-cache-ttl 7200\n");

    /* Detect a pinentry program rather than hardcoding a path: it lives in
     * different locations per platform (/usr/bin on Linux, /usr/local/bin on
     * the BSDs, /opt/homebrew/bin or /usr/local/bin on macOS). Prefer the
     * generic `pinentry` symlink, then common flavors including macOS's
     * pinentry-mac. If none is found, omit the directive entirely and let
     * gpg-agent fall back to its compiled-in default. */
    {
        static const char *const pinentry_candidates[] = {
            "pinentry", "pinentry-curses", "pinentry-mac", "pinentry-tty"
        };
        char pinentry_path[MAX_PATH_LEN];
        bool wrote_pinentry = false;
        for (size_t i = 0; i < sizeof(pinentry_candidates) / sizeof(pinentry_candidates[0]); i++) {
            if (find_command_path(pinentry_candidates[i], pinentry_path, sizeof(pinentry_path)) == 0) {
                fprintf(conf_file, "pinentry-program %s\n", pinentry_path);
                wrote_pinentry = true;
                break;
            }
        }
        if (!wrote_pinentry) {
            log_debug("No pinentry program found in PATH; relying on gpg-agent default");
        }
    }

    fclose(conf_file);
    
    /* Set proper permissions */
    if (chmod(gpg_agent_conf_path, 0600) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set gpg-agent.conf permissions");
        return -1;
    }
    
    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;
}