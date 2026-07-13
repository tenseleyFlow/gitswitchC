/* GPG key and environment management with comprehensive isolation and security
 * Implements per-account GNUPGHOME environments to prevent GPG key mixing
 */

/* _GNU_SOURCE exposes both nftw()/FTW_* from <ftw.h> (X/Open) and flock()/
 * LOCK_EX from <sys/file.h> (BSD) on glibc — _XOPEN_SOURCE 700 alone would
 * give us nftw while HIDING flock, needed for the per-dir lock (AR-02 #9).
 * Scope it to Linux: on macOS and the BSDs both are visible in the default
 * namespace, and defining strict feature macros there hides the u_int/u_char
 * typedefs that <sys/mount.h>/<sys/ucred.h> (needed below for the tmpfs
 * check) rely on — the same trap documented in ssh_manager.c. */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/stat.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include "gpg_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "git_ops.h"
#include "signals.h"

/* When set, gpg_get_base_dir suppresses the "XDG_RUNTIME_DIR unset / not
 * memory-backed" display_warning. `gitswitch init` toggles this while it
 * computes the GNUPGHOME path, because that warning goes to STDOUT and would
 * otherwise be eval'd by the shell as a command (AR-06 F08). The warning still
 * fires on a real switch (a separate process; the latch is per-process). */
static bool g_gpg_suppress_base_warning = false;

/* Internal helper functions */
static int gpg_get_base_dir(char *buf, size_t size);
static int gpg_prepare_base_dir(char *base, size_t size);
typedef struct {
    bool publication_occurred;
    bool restoration_succeeded;
    bool previous_present;
    char previous_target[MAX_PATH_LEN];
    char published_target[MAX_PATH_LEN];
    gpg_link_identity_t published_link;
    gpg_rollback_token_t rollback;
} gpg_retarget_result_t;
static int gpg_retarget_current_locked(int base_fd, const char *base,
                                       const char *real_home,
                                       gpg_retarget_result_t *result);
static void gpg_build_env(const gpg_config_t *cfg, char *envbuf, size_t envbuf_size,
                          const char *env_out[2]);
static int gpg_run(const gpg_config_t *cfg, run_result_t *res_out,
                   char *output, size_t output_size, ...);
typedef struct {
    int base_fd;
    int home_fd;
    const char *base;
    const char *name;
    const char *path;
} gpg_pinned_home_t;
static int gpg_run_pinned(const gpg_pinned_home_t *home,
                          const gpg_config_t *cfg, run_result_t *res_out,
                          char *output, size_t output_size, ...);
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config,
                                        const gpg_pinned_home_t *home,
                                        const char *selector,
                                        bool require_signing,
                                        char *fingerprint,
                                        size_t fingerprint_size);
static int setup_gpg_agent_config(int home_fd, const char *gnupg_home);
static int gpg_prepare_isolated_home_at(gpg_config_t *gpg_config,
                                        const account_t *account,
                                        int base_fd, const char *base,
                                        int *home_fd_out);
static int gpg_validate_pinned_home(const gpg_pinned_home_t *home);
static int gpg_user_source_home(char *buf, size_t size);
static int gpg_resolve_source_key(const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size);
static int gpg_resolve_pinned_key(const gpg_config_t *gpg_config,
                                  const gpg_pinned_home_t *home,
                                  const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size);
static int gpg_open_base_dir(char *base, size_t size, bool create,
                             bool *absent);
static int lock_gpg_dir(int base_fd);
static void unlock_gpg_dir(int base_fd, int lock_fd);
static int gpg_native_rename_noreplace(int old_dir_fd, const char *old_name,
                                       int new_dir_fd, const char *new_name);
static int gpg_default_sync_base(int base_fd);
static int gpg_default_agent_conf_sync(int fd, bool directory);

static gpg_readdir_fn g_gpg_readdir = readdir;
static gpg_agent_conf_preopen_fn g_agent_conf_preopen;
static gpg_agent_conf_precommit_fn g_agent_conf_precommit;
static gpg_retarget_commit_hook_fn g_retarget_commit_hook;
static gpg_retarget_restore_hook_fn g_retarget_restore_hook;
static gpg_rollback_hook_fn g_rollback_hook;
static gpg_sync_base_fn g_sync_base = gpg_default_sync_base;
static gpg_rename_noreplace_fn g_rename_noreplace =
    gpg_native_rename_noreplace;
static gpg_setenv_fn g_gpg_setenv = setenv;
static gpg_unsetenv_fn g_gpg_unsetenv = unsetenv;
static gpg_cleanup_predelete_fn g_cleanup_predelete;
static gpg_reset_final_hook_fn g_reset_final_hook;
static gpg_mount_identity_probe_fn g_mount_identity_probe;
static gpg_agent_conf_sync_fn g_agent_conf_sync =
    gpg_default_agent_conf_sync;

gpg_readdir_fn gpg_manager_set_readdir_fn(gpg_readdir_fn fn) {
    gpg_readdir_fn previous = g_gpg_readdir;
    g_gpg_readdir = fn ? fn : readdir;
    return previous;
}

gpg_agent_conf_preopen_fn
gpg_manager_set_agent_conf_preopen_fn(gpg_agent_conf_preopen_fn fn) {
    gpg_agent_conf_preopen_fn previous = g_agent_conf_preopen;
    g_agent_conf_preopen = fn;
    return previous;
}

gpg_agent_conf_precommit_fn
gpg_manager_set_agent_conf_precommit_fn(gpg_agent_conf_precommit_fn fn) {
    gpg_agent_conf_precommit_fn previous = g_agent_conf_precommit;
    g_agent_conf_precommit = fn;
    return previous;
}

gpg_retarget_commit_hook_fn
gpg_manager_set_retarget_commit_hook_fn(gpg_retarget_commit_hook_fn fn) {
    gpg_retarget_commit_hook_fn previous = g_retarget_commit_hook;
    g_retarget_commit_hook = fn;
    return previous;
}

gpg_retarget_restore_hook_fn
gpg_manager_set_retarget_restore_hook_fn(gpg_retarget_restore_hook_fn fn) {
    gpg_retarget_restore_hook_fn previous = g_retarget_restore_hook;
    g_retarget_restore_hook = fn;
    return previous;
}

gpg_rollback_hook_fn
gpg_manager_set_rollback_hook_fn(gpg_rollback_hook_fn fn) {
    gpg_rollback_hook_fn previous = g_rollback_hook;
    g_rollback_hook = fn;
    return previous;
}

gpg_sync_base_fn gpg_manager_set_sync_base_fn(gpg_sync_base_fn fn) {
    gpg_sync_base_fn previous = g_sync_base;
    g_sync_base = fn ? fn : gpg_default_sync_base;
    return previous;
}

gpg_rename_noreplace_fn
gpg_manager_set_rename_noreplace_fn(gpg_rename_noreplace_fn fn) {
    gpg_rename_noreplace_fn previous = g_rename_noreplace;
    g_rename_noreplace = fn ? fn : gpg_native_rename_noreplace;
    return previous;
}

gpg_setenv_fn gpg_manager_set_setenv_fn(gpg_setenv_fn fn) {
    gpg_setenv_fn previous = g_gpg_setenv;
    g_gpg_setenv = fn ? fn : setenv;
    return previous;
}

gpg_unsetenv_fn gpg_manager_set_unsetenv_fn(gpg_unsetenv_fn fn) {
    gpg_unsetenv_fn previous = g_gpg_unsetenv;
    g_gpg_unsetenv = fn ? fn : unsetenv;
    return previous;
}

gpg_cleanup_predelete_fn
gpg_manager_set_cleanup_predelete_fn(gpg_cleanup_predelete_fn fn) {
    gpg_cleanup_predelete_fn previous = g_cleanup_predelete;
    g_cleanup_predelete = fn;
    return previous;
}

gpg_reset_final_hook_fn
gpg_manager_set_reset_final_hook_fn(gpg_reset_final_hook_fn fn) {
    gpg_reset_final_hook_fn previous = g_reset_final_hook;
    g_reset_final_hook = fn;
    return previous;
}

gpg_mount_identity_probe_fn
gpg_manager_set_mount_identity_probe_fn(gpg_mount_identity_probe_fn fn) {
    gpg_mount_identity_probe_fn previous = g_mount_identity_probe;
    g_mount_identity_probe = fn;
    return previous;
}

gpg_agent_conf_sync_fn
gpg_manager_set_agent_conf_sync_fn(gpg_agent_conf_sync_fn fn) {
    gpg_agent_conf_sync_fn previous = g_agent_conf_sync;
    g_agent_conf_sync = fn ? fn : gpg_default_agent_conf_sync;
    return previous;
}

/* Process-lifetime memo of GPG key ids whose secret-key presence a gpg spawn
 * already proved this run (AR-02 #14). A single GPG switch used to spawn gpg
 * 4-6 times re-proving the same key — the up-front availability probe, the
 * import idempotency check, the signing-capability test, and git_test_config's
 * read-back check each ran their own listing. The memo lets the later sanity
 * checks reuse the earlier proof. Deliberately coarse: it says "a keyring this
 * process consulted holds the secret key", which is exactly the availability
 * question those redundant spawns re-asked; the strict per-home validation on
 * the switch path still runs against the isolated home itself. Same
 * short-lived, single-threaded caching assumptions as git_ops.c's exec caches. */
#define GPG_SEEN_KEYS_MAX 8
static char g_seen_keys[GPG_SEEN_KEYS_MAX][GPG_FINGERPRINT_BUFSIZE];
static size_t g_seen_key_count;

void gpg_manager_note_key_available(const char *key_id) {
    if (!key_id || !*key_id || strlen(key_id) >= GPG_FINGERPRINT_BUFSIZE ||
        gpg_manager_key_available_cached(key_id)) {
        return;
    }
    if (g_seen_key_count < GPG_SEEN_KEYS_MAX) {
        safe_strncpy(g_seen_keys[g_seen_key_count], key_id,
                     sizeof(g_seen_keys[0]));
        g_seen_key_count++;
    }
}

bool gpg_manager_key_available_cached(const char *key_id) {
    if (!key_id) {
        return false;
    }
    for (size_t i = 0; i < g_seen_key_count; i++) {
        if (strcmp(g_seen_keys[i], key_id) == 0) {
            return true;
        }
    }
    return false;
}

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

static int gpg_restore_environment(gpg_config_t *gpg_config) {
    int env_rc;

    if (!gpg_config || !gpg_config->environment_installed) {
        return 0;
    }
    if (gpg_config->previous_gnupg_home_present) {
        env_rc = g_gpg_setenv("GNUPGHOME", gpg_config->previous_gnupg_home, 1);
    } else {
        env_rc = g_gpg_unsetenv("GNUPGHOME");
    }
    if (env_rc != 0) {
        set_system_error(ERR_SYSTEM_CALL,
                         "Failed to restore GNUPGHOME environment variable");
        return -1;
    }
    gpg_config->environment_installed = false;
    gpg_config->previous_gnupg_home_present = false;
    gpg_config->previous_gnupg_home[0] = '\0';
    return 0;
}

bool gpg_manager_runtime_restore_pending(const gpg_config_t *gpg_config) {
    return gpg_config && gpg_config->runtime_restore_pending;
}

/* Cleanup is a transaction completion step, not a blind memset.  A failed
 * compare-and-restore or unsetenv leaves the metadata intact so the caller can
 * retry without guessing what was published. */
int gpg_manager_cleanup(gpg_config_t *gpg_config) {
    char first_error[sizeof(g_last_error.message)] = "";
    bool changed = false;
    bool failed = false;

    if (!gpg_config) {
        return 0;
    }
    
    log_debug("Cleaning up GPG manager");

    /* Intentionally NOT deleting the isolated GNUPGHOME. Isolated homes are
     * keyed by account and persist across switches (mirroring how the SSH agent
     * persists): the user's shell points GNUPGHOME at the <base>/current
     * symlink, so removing a home could pull the rug out from under a shell
     * still pointed at it. Homes are reused on switch-back, and re-import is
     * skipped when the key is already present. A deliberate teardown command
     * (not yet implemented) is the right place to reclaim them. */

    if (gpg_config->runtime_restore_pending) {
        const char *expected = gpg_config->rollback.published.valid
                                   ? gpg_config->rollback.published.target
                                   : NULL;
        const char *restore = gpg_config->rollback.restore_present
                                  ? gpg_config->rollback.restore_target
                                  : NULL;
        if (gpg_manager_restore_current_if(gpg_config, expected, restore,
                                           &changed) != 0) {
            safe_strncpy(first_error, get_last_error()->message,
                         sizeof(first_error));
            failed = true;
        } else {
            /* A compare conflict also proves our failed transaction no longer
             * owns current, so it is safe to retire its retry record. */
            gpg_config->runtime_restore_pending = false;
            memset(&gpg_config->rollback, 0, sizeof(gpg_config->rollback));
        }
    }

    if (gpg_restore_environment(gpg_config) != 0) {
        if (failed) {
            char env_error[sizeof(g_last_error.message)];
            safe_strncpy(env_error, get_last_error()->message,
                         sizeof(env_error));
            set_error(ERR_FILE_IO, "%s; environment rollback failed: %s",
                      first_error, env_error);
        }
        failed = true;
    } else if (failed) {
        set_error(ERR_FILE_IO, "%s", first_error);
    }

    if (failed) {
        return -1;
    }

    /* Clear configuration only after every owned side effect is restored. */
    memset(gpg_config, 0, sizeof(gpg_config_t));
    
    log_debug("GPG manager cleanup completed");
    return 0;
}

/* Switch to account's GPG configuration with complete isolation */
int gpg_switch_account(gpg_config_t *gpg_config, const account_t *account) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE] = "";
    char locked_base[MAX_PATH_LEN] = "";
    gpg_retarget_result_t retarget = {0};
    int base_fd = -1;
    int home_fd = -1;
    int lock_fd = -1;
    int rc = -1;
    gpg_pinned_home_t pinned_home = {
        .base_fd = -1,
        .home_fd = -1,
        .base = NULL,
        .name = NULL,
        .path = NULL
    };

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_switch_account");
        return -1;
    }
    if (gpg_config->runtime_restore_pending ||
        gpg_config->environment_installed ||
        gpg_config->current_key_id[0] != '\0') {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG manager has an active or incomplete transaction; "
                  "cleanup must succeed before another switch");
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
            if (gpg_resolve_source_key(account->gpg_key_id,
                                       account->gpg_signing_enabled,
                                       fingerprint, sizeof(fingerprint)) != 0) {
                goto out;
            }
            break;

        case GPG_MODE_ISOLATED: {
            /* Establish the base first so there is a lock file to take, then
             * hold <base>/.lock across the WHOLE create+import sequence and
             * the final `current` retarget, mirroring ssh_start_isolated_agent
             * (AR-03 L12). Only the retarget used to be locked: a concurrent
             * `gitswitch reset` — same uid but a divergent $HOME defeats the
             * coarse .config.lock while a shared XDG_RUNTIME_DIR still lands
             * both on this base — could remove_tree() the home BETWEEN the
             * import and the retarget, leaving a dangling `current` behind a
             * switch that reported success. Fail closed if the lock cannot be
             * taken: proceeding unlocked would reopen exactly that window. */
            if (gpg_prepare_base_dir(locked_base, sizeof(locked_base)) != 0) {
                set_error(ERR_GPG_KEY_FAILED, "Failed to create isolated GPG environment: %s",
                         get_last_error()->message);
                goto out;
            }
            base_fd = gpg_open_base_dir(locked_base, sizeof(locked_base),
                                        false, NULL);
            if (base_fd < 0) {
                goto out;
            }
            lock_fd = lock_gpg_dir(base_fd);
            if (lock_fd < 0) {
                set_system_error(ERR_FILE_IO, "Failed to lock GPG base directory: %s",
                                 locked_base);
                goto out;
            }

            /* Create and retain an open descriptor for the isolated home.
             * Every GPG child below enters that pinned directory and uses
             * GNUPGHOME=. so replacing the public base pathname cannot
             * redirect a listing/import into replacement state. */
            if (gpg_prepare_isolated_home_at(gpg_config, account, base_fd,
                                             locked_base, &home_fd) != 0) {
                set_error(ERR_GPG_KEY_FAILED, "Failed to create isolated GPG environment: %s",
                         get_last_error()->message);
                goto out;
            }
            pinned_home.base_fd = base_fd;
            pinned_home.home_fd = home_fd;
            pinned_home.base = locked_base;
            pinned_home.name = account->name;
            pinned_home.path = gpg_config->gnupg_home;

            if (copy_key_from_system_keyring(gpg_config, &pinned_home,
                                             account->gpg_key_id,
                                             account->gpg_signing_enabled,
                                             fingerprint,
                                             sizeof(fingerprint)) != 0) {
                goto out;
            }
            break;
        }

        case GPG_MODE_SHARED:
            if (gpg_resolve_source_key(account->gpg_key_id,
                                       account->gpg_signing_enabled,
                                       fingerprint, sizeof(fingerprint)) != 0) {
                goto out;
            }
            break;

        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", gpg_config->mode);
            goto out;
    }

    if (fingerprint[0] == '\0') {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG selector did not resolve to a canonical fingerprint: %s",
                  account->gpg_key_id);
        goto out;
    }

    /* Environment installation is itself a commit operation.  Make it fatal
     * before publishing current, so a setenv failure can never leave a shell-
     * facing runtime that the process did not successfully adopt. */
    if (gpg_config->mode == GPG_MODE_ISOLATED &&
        gpg_set_environment(gpg_config) != 0) {
        goto out;
    }

    /* Retarget the stable GNUPGHOME symlink to this account's now-ready home so
     * a shell exporting GNUPGHOME=<base>/current follows the switch. Done last,
     * after the key is imported and validated, and still under the lock taken
     * before the home was created (AR-03 L12) — the locked helper, not the
     * public wrapper, which would flock the same lock file on a second fd and
     * self-deadlock. Isolated mode only. This stable link is the runtime commit
     * point used by every integrated shell, so failure is fatal: the prepared
     * home remains reusable, but the account is not claimed active. */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        if (gpg_validate_pinned_home(&pinned_home) != 0 ||
            gpg_retarget_current_locked(base_fd, locked_base,
                                        gpg_config->gnupg_home,
                                        &retarget) != 0) {
            char original[sizeof(g_last_error.message)];
            safe_strncpy(original, get_last_error()->message,
                         sizeof(original));
            if (retarget.publication_occurred &&
                !retarget.restoration_succeeded &&
                retarget.rollback.phase != GPG_ROLLBACK_NONE) {
                gpg_config->published_link = retarget.published_link;
                gpg_config->published_link_valid =
                    retarget.published_link.valid;
                gpg_config->rollback = retarget.rollback;
                gpg_config->runtime_restore_pending = true;
            }
            set_error(ERR_GPG_KEY_FAILED,
                      "Failed to install stable GNUPGHOME for account %s: %s",
                      account->name, original);
            goto out;
        }
    }

    /* Only publish the selected key/configuration after the runtime entry
     * point has committed. A failed retarget must not leave an in-memory or
     * process-environment claim that the rejected account is active. */
    safe_strncpy(gpg_config->current_key_id, fingerprint,
                 sizeof(gpg_config->current_key_id));
    if (gpg_config->mode == GPG_MODE_ISOLATED) {
        gpg_config->published_link = retarget.published_link;
        gpg_config->published_link_valid = retarget.published_link.valid;
    }
    gpg_config->signing_enabled = account->gpg_signing_enabled;
    gpg_manager_note_key_available(fingerprint);
    /* The selector is now an alias backed by the strict fingerprint proof.
     * Memoizing it prevents downstream validation from re-running gpg with
     * the less-specific account input. */
    gpg_manager_note_key_available(account->gpg_key_id);

    log_info("Successfully switched to GPG configuration for account: %s", account->name);
    rc = 0;

out:
    if (rc != 0 && gpg_config && gpg_config->environment_installed) {
        char original[sizeof(g_last_error.message)];
        safe_strncpy(original, get_last_error()->message, sizeof(original));
        if (gpg_restore_environment(gpg_config) != 0) {
            char rollback[sizeof(g_last_error.message)];
            safe_strncpy(rollback, get_last_error()->message,
                         sizeof(rollback));
            set_error(ERR_GPG_KEY_FAILED,
                      "%s; environment rollback failed: %s",
                      original, rollback);
        } else {
            set_error(ERR_GPG_KEY_FAILED, "%s", original);
        }
    }
    if (home_fd >= 0) close(home_fd);
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

/* Best-effort check whether `path` lives on a memory-backed filesystem
 * (tmpfs/ramfs). Used to decide whether exported secret-key material may safely
 * be written there. Returns true ONLY on positive confirmation; unknown => false
 * so callers fail safe. Cross-platform: statfs magic on Linux, f_fstypename on
 * the BSDs/macOS. */
static bool path_is_memory_backed(const char *path) {
#ifdef __linux__
    struct statfs sfs;
    if (statfs(path, &sfs) == 0) {
        unsigned long t = (unsigned long)sfs.f_type;
        return t == 0x01021994UL /* TMPFS_MAGIC */ || t == 0x858458f6UL /* RAMFS_MAGIC */;
    }
#else
    struct statfs sfs;
    if (statfs(path, &sfs) == 0) {
        return strcmp(sfs.f_fstypename, "tmpfs") == 0;
    }
#endif
    return false;
}

/* Memory-backed-ness of the directory that will actually hold the isolated
 * homes. Probes the base itself, not a hardcoded parent: the base may be a
 * distinct mount from its parent (admin bind-mount or per-user quota mount at
 * exactly /tmp/gitswitch-gpg-<uid> — AR-02 #22), and on the XDG branch the
 * parent is whatever the user exported, tmpfs or not (AR-02 #3). On the first
 * switch the base does not exist yet, so fall back to the nearest existing
 * ancestor — the mount the base would be created on. Unknown => false, so
 * callers fail safe. */
static bool base_is_memory_backed(const char *base) {
    char probe[MAX_PATH_LEN];
    if (!base || safe_strncpy(probe, base, sizeof(probe)) != 0) {
        return false;
    }
    for (;;) {
        if (path_exists(probe)) {
            return path_is_memory_backed(probe);
        }
        char *slash = strrchr(probe, '/');
        if (!slash || slash == probe) {
            return path_is_memory_backed("/");
        }
        *slash = '\0';
    }
}

/* Process-lifetime memo of base_is_memory_backed(), keyed by the base path
 * (AR-03 L20). The probe walks statfs over the base's nearest existing
 * ancestor, and gpg_get_base_dir + gpg_create_isolated_home together re-ran it
 * on every call — 4-6 ancestor walks per GPG switch — because the old
 * warn-once latch only latched when the answer was BAD; the good/tmpfs path
 * re-probed forever. A mount's memory-backed-ness cannot change under us for
 * a fixed path within one short-lived invocation (the base, once created by
 * ensure_private_dir, stays on the mount the first probe saw), so one answer
 * per base path is authoritative. Keyed rather than a bare boolean because
 * the base path itself CAN change within a process when XDG_RUNTIME_DIR
 * changes (the test suite does exactly that); a stale answer for a different
 * base would defeat the no-persistent-disk fail-closed guard. Same
 * single-threaded, process-lifetime caching assumptions as g_seen_keys. */
static bool base_memory_backed_cached(const char *base) {
    static int cached = -1; /* -1 unknown; else the 0/1 answer for cached_base */
    static char cached_base[MAX_PATH_LEN];

    if (cached < 0 || strcmp(cached_base, base) != 0) {
        if (safe_strncpy(cached_base, base, sizeof(cached_base)) != 0) {
            return base_is_memory_backed(base); /* unkeyable: answer uncached */
        }
        cached = base_is_memory_backed(base) ? 1 : 0;
    }
    return cached == 1;
}

/* Compute the base directory that holds per-account isolated GNUPGHOMEs and the
 * stable `current` symlink. Two-way like the SSH side: prefer XDG_RUNTIME_DIR,
 * else /tmp/gitswitch-gpg-<uid>. There is deliberately no HOME fallback: that
 * branch would place secret-key material on persistent disk, and its longer
 * paths risk overrunning the gpg-agent socket sun_path limit. Returns 0 on
 * success. */
static int gpg_get_base_dir(char *buf, size_t size) {
    char runtime_parent[MAX_PATH_LEN];
    char child[64];
    int parent_fd;
    int written;

    if (!buf || size == 0) {
        set_error(ERR_INVALID_ARGS, "NULL/empty buffer to gpg_get_base_dir");
        return -1;
    }

    parent_fd = open_runtime_parent(runtime_parent, sizeof(runtime_parent));
    if (parent_fd < 0) {
        return -1;
    }
    close(parent_fd);

    if (strcmp(runtime_parent, "/tmp") != 0) {
        written = snprintf(child, sizeof(child), "gitswitch-gpg");
    } else {
        /* Fallback: XDG_RUNTIME_DIR is unset (cron, minimal login, some SSH
         * sessions). /tmp is a tmpfs on most Linux desktops, but on many
         * servers and default FreeBSD/macOS it is persistent disk — where the
         * isolated home's exported secret keys would then live, contradicting
         * this function's own no-persistent-disk intent. Warn once (per process)
         * when we can't confirm the fallback is memory-backed, so the user can
         * export XDG_RUNTIME_DIR or accept the risk knowingly. Probes the
         * actual base (nearest existing ancestor when absent), not a hardcoded
         * "/tmp": the base could be a distinct persistent mount under a tmpfs
         * /tmp (AR-02 #22). The probe result is memoized per base path
         * (AR-03 L20): this function runs 4-6 times per switch, and the
         * statfs ancestor walk used to repeat on every call whenever the
         * answer was GOOD (the warn latch below only stops repeat WARNINGS).
         * The create path (gpg_prepare_base_dir) additionally refuses to
         * write secret material to any non-memory-backed base unless the
         * user opts in, sharing the same memoized answer. */
        written = snprintf(child, sizeof(child), "gitswitch-gpg-%d", getuid());
    }
    if (written < 0 || (size_t)written >= sizeof(child)) {
        set_error(ERR_INVALID_PATH, "GPG base directory name too long");
        return -1;
    }
    written = snprintf(buf, size, "%s/%s", runtime_parent, child);
    if (strcmp(runtime_parent, "/tmp") == 0) {
        static bool warned = false;
        if (!warned && !g_gpg_suppress_base_warning && written > 0 &&
            (size_t)written < size && !base_memory_backed_cached(buf)) {
            warned = true;
            display_warning("XDG_RUNTIME_DIR is unset; isolated GPG homes will use "
                            "%s, which is not memory-backed. Exported "
                            "secret keys could remain recoverable on disk after exit. Set "
                            "XDG_RUNTIME_DIR to a memory-backed dir to avoid this.",
                            buf);
        }
    }

    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG base directory path too long");
        return -1;
    }
    return 0;
}

static int gpg_open_base_dir(char *base, size_t size, bool create,
                             bool *absent) {
    char parent[MAX_PATH_LEN];
    char child[64];
    int parent_fd;
    int base_fd;
    int written;

    parent_fd = open_runtime_parent(parent, sizeof(parent));
    if (parent_fd < 0) {
        return -1;
    }
    if (strcmp(parent, "/tmp") == 0) {
        written = snprintf(child, sizeof(child), "gitswitch-gpg-%d", getuid());
    } else {
        written = snprintf(child, sizeof(child), "gitswitch-gpg");
    }
    if (written < 0 || (size_t)written >= sizeof(child) ||
        (size_t)snprintf(base, size, "%s/%s", parent, child) >= size) {
        close(parent_fd);
        set_error(ERR_INVALID_PATH, "GPG base directory path too long");
        return -1;
    }
    base_fd = open_private_subdir_at(parent_fd, child, create, absent);
    close(parent_fd);
    return base_fd;
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

/* Same as gpg_manager_get_home_path but suppresses the not-memory-backed
 * stdout warning (AR-06 F08): `gitswitch init`'s stdout is a serialization
 * boundary consumed by `eval`, so any diagnostic printed there becomes a bogus
 * shell command. The warning is still emitted on real GPG operations. */
int gpg_manager_get_home_path_quiet(char *buf, size_t size) {
    bool prev = g_gpg_suppress_base_warning;
    int rc;
    g_gpg_suppress_base_warning = true;
    rc = gpg_manager_get_home_path(buf, size);
    g_gpg_suppress_base_warning = prev;
    return rc;
}

/* Acquire an exclusive, blocking flock on <base>/.lock, serializing every
 * writer of the GPG runtime state — the `current` symlink retarget/drop and
 * gpg_manager_reset's enumeration + dangling-link cleanup — against each
 * other across processes (AR-02 #9: an unlocked reset's cleanup could TOCTOU
 * a concurrent switch and unlink the live link it had just installed).
 * Mirrors ssh_manager.c's lock_agent_dir. Returns the held fd, or -1; callers
 * that found an existing validated base must fail rather than mutate it
 * unlocked. Dotfile names cannot collide with an account home: validate_name
 * rejects a leading '.'. */
static int lock_gpg_dir(int base_fd) {
    return lock_private_file_at(base_fd, ".lock");
}

/* Non-blocking variant: -1 with errno==EWOULDBLOCK when another holder (a
 * concurrent switch) has the base lock. Used by the login-shell resume liveness
 * check so it never hangs the shell (AR-06 F60). */
static int try_lock_gpg_dir(int base_fd) {
    return try_lock_private_file_at(base_fd, ".lock");
}

static void unlock_gpg_dir(int base_fd, int lock_fd) {
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (base_fd >= 0) close(base_fd);
}

static int gpg_native_rename_noreplace(int old_dir_fd, const char *old_name,
                                       int new_dir_fd, const char *new_name) {
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U)
#endif
    return (int)syscall(SYS_renameat2, old_dir_fd, old_name, new_dir_fd,
                        new_name, RENAME_NOREPLACE);
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    return renameatx_np(old_dir_fd, old_name, new_dir_fd, new_name,
                        RENAME_EXCL);
#elif defined(__FreeBSD__)
    int old_fd;
    int saved_errno;

    /* FreeBSD 14.x does not provide Darwin's renameatx_np(2) or a native
     * no-replace rename.  Every caller moves a symlink inside the same pinned,
     * private directory.  linkat(2) without AT_SYMLINK_FOLLOW hard-links the
     * symlink itself and atomically fails with EEXIST when the destination is
     * occupied; only after that compare-and-publish succeeds do we retire the
     * old name.  Pinning that source with O_PATH lets funlinkat(2) retire only
     * the directory entry still associated with the opened vnode; it returns
     * EDEADLK instead of deleting a same-uid racer's replacement.  Thus
     * `current` is never absent and a later writer is never overwritten.
     *
     * Once linkat succeeds, publication has happened and must be reported as
     * success even if retirement fails: all three callers re-prove the
     * published identity and safely handle the retained alias (the prepared-
     * publication caller also removes its private alias below). */
    old_fd = openat(old_dir_fd, old_name,
                    O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (old_fd < 0) return -1;
    if (linkat(old_dir_fd, old_name, new_dir_fd, new_name, 0) != 0) {
        saved_errno = errno;
        close(old_fd);
        errno = saved_errno;
        return -1;
    }
    (void)funlinkat(old_dir_fd, old_name, old_fd, 0);
    close(old_fd);
    return 0;
#else
    (void)old_dir_fd;
    (void)old_name;
    (void)new_dir_fd;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
#endif
}

static int gpg_default_sync_base(int base_fd) {
    return fsync(base_fd);
}

static int gpg_default_agent_conf_sync(int fd, bool directory) {
    (void)directory;
    return fsync(fd);
}

static int gpg_current_path_from_base(const char *base, char *buf, size_t size) {
    int written;

    if (!base || !*base || !buf || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG current-path arguments");
        return -1;
    }
    written = snprintf(buf, size, "%s/current", base);
    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG home path too long");
        return -1;
    }
    return 0;
}

#define GPG_ROLLBACK_PREFIX ".gitswitch-gpg-rollback."
#define GPG_PUBLISH_PREFIX ".gitswitch-gpg-publish."

/* Capture a symlink as one indivisible logical identity. The two stat calls
 * make a concurrent replacement observable; the target alone is insufficient
 * because a same-target replacement is still a different writer. Return 1 for
 * absence, 0 for a stable capture, and -1 for malformed or uncertain state. */
static int gpg_capture_link_at(int dir_fd, const char *name,
                               gpg_link_identity_t *identity) {
    struct stat before;
    struct stat after;
    ssize_t target_len;
    int readlink_errno;

    if (dir_fd < 0 || !name || !*name || strchr(name, '/') || !identity) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG symlink capture arguments");
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    if (fstatat(dir_fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 1;
        set_system_error(ERR_FILE_IO, "Cannot inspect GPG runtime link: %s",
                         name);
        return -1;
    }
    if (!S_ISLNK(before.st_mode) || before.st_uid != getuid()) {
        set_error(ERR_FILE_IO, "GPG runtime entry is not an owned symlink: %s",
                  name);
        return -1;
    }
    if (before.st_size < 0 ||
        (uintmax_t)before.st_size >= (uintmax_t)(sizeof(identity->target) - 1U)) {
        set_error(ERR_INVALID_PATH, "GPG runtime link target is too long: %s",
                  name);
        return -1;
    }
    target_len = readlinkat(dir_fd, name, identity->target,
                            sizeof(identity->target) - 1U);
    readlink_errno = errno;
    if (fstatat(dir_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(after.st_mode) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_size != after.st_size) {
        set_error(ERR_FILE_IO,
                  "GPG runtime link changed while being inspected: %s", name);
        return -1;
    }
    if (target_len < 0) {
        errno = readlink_errno;
        set_system_error(ERR_FILE_IO, "Cannot read GPG runtime link: %s", name);
        return -1;
    }
    if (target_len == 0 ||
        (size_t)target_len >= sizeof(identity->target) - 1U) {
        set_error(ERR_INVALID_PATH, "Invalid GPG runtime link target: %s", name);
        return -1;
    }
    identity->target[target_len] = '\0';
    identity->st = after;
    identity->valid = true;
    return 0;
}

static bool gpg_same_link(const gpg_link_identity_t *left,
                          const gpg_link_identity_t *right) {
    return left && right && left->valid && right->valid &&
           left->st.st_dev == right->st.st_dev &&
           left->st.st_ino == right->st.st_ino &&
           left->st.st_mode == right->st.st_mode &&
           left->st.st_uid == right->st.st_uid &&
           left->st.st_size == right->st.st_size &&
           strcmp(left->target, right->target) == 0;
}

static bool gpg_name_has_prefix(const char *name, const char *prefix) {
    return name && prefix && strncmp(name, prefix, strlen(prefix)) == 0;
}

/* A quarantine without an in-memory transaction token may contain a symlink
 * displaced by an interrupted process. Never guess at its ownership. */
static int gpg_reject_stale_quarantines_locked(int base_fd,
                                               const char *allowed_name) {
    int scan_flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;

#ifdef O_DIRECTORY
    scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    scan_flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(base_fd, ".", scan_flags);
    if (scan_fd < 0 || !(dir = fdopendir(scan_fd))) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect GPG rollback retry state");
        return -1;
    }
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Cannot enumerate GPG rollback retry state");
                return -1;
            }
            break;
        }
        if ((gpg_name_has_prefix(entry->d_name, GPG_ROLLBACK_PREFIX) ||
             gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX)) &&
            (!allowed_name || strcmp(entry->d_name, allowed_name) != 0)) {
            char stale[GPG_QUARANTINE_NAME_LEN];
            safe_strncpy(stale, entry->d_name, sizeof(stale));
            closedir(dir);
            set_error(ERR_FILE_IO,
                      "Unresolved GPG runtime quarantine blocks mutation: %s",
                      stale);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}

static int gpg_make_private_name(char *name, size_t size,
                                 const char *prefix) {
    char random[17];
    int written;

    if (!name || size == 0 || !prefix ||
        generate_random_string(random, sizeof(random),
                               "0123456789abcdef") != 0) {
        return -1;
    }
    written = snprintf(name, size, "%s%ld.%s", prefix, (long)getpid(), random);
    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG private runtime name is too long");
        return -1;
    }
    return 0;
}

/* Validate an existing base before taking its lock, then verify that the path
 * still names the same private directory after the lock is held. Return 1 for
 * an absent base, 0 with a held lock, and -1 for every unsafe/unknown state. */
/* Returns 1 for an absent base, 0 with a held lock, -1 for an unsafe/unknown
 * state, and (when nonblocking) 2 when the base lock is currently held by
 * another holder — the caller decides what "busy" means (AR-06 F60). */
static int gpg_lock_private_base(const char *base, int *base_fd_out,
                                 int *lock_out, bool nonblocking) {
    char opened_base[MAX_PATH_LEN];
    bool absent = false;
    int base_fd;
    int lock_fd;

    if (!base || !*base || !base_fd_out || !lock_out) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG base-lock arguments");
        return -1;
    }
    *base_fd_out = -1;
    *lock_out = -1;
    base_fd = gpg_open_base_dir(opened_base, sizeof(opened_base), false,
                                &absent);
    if (base_fd < 0) {
        return absent ? 1 : -1;
    }
    if (strcmp(opened_base, base) != 0) {
        close(base_fd);
        set_error(ERR_INVALID_PATH, "GPG base path changed unexpectedly");
        return -1;
    }
    lock_fd = nonblocking ? try_lock_gpg_dir(base_fd) : lock_gpg_dir(base_fd);
    if (lock_fd < 0) {
        if (nonblocking && (errno == EWOULDBLOCK
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
                            || errno == EAGAIN
#endif
                            )) {
            close(base_fd);
            return 2; /* busy: another holder (a switch) has the lock */
        }
        close(base_fd);
        set_system_error(ERR_FILE_IO, "Failed to lock GPG base directory: %s", base);
        return -1;
    }
    *base_fd_out = base_fd;
    *lock_out = lock_fd;
    return 0;
}

/* A managed home is exactly one validated account-name component under the
 * computed base. Prefix-only checks are insufficient: /base2/x must never be
 * accepted for /base, nor may redundant separators/traversal be normalized. */
static bool gpg_target_is_managed_child(const char *base, const char *target) {
    size_t base_len;
    size_t target_len;
    const char *account;

    if (!base || !*base || !target) {
        return false;
    }
    base_len = strlen(base);
    target_len = strlen(target);
    if (target_len <= base_len + 1) {
        return false;
    }
    if (strncmp(target, base, base_len) != 0 || target[base_len] != '/') {
        return false;
    }
    account = target + base_len + 1;
    return validate_name(account);
}

static const char *gpg_managed_component(const char *base,
                                         const char *target) {
    return gpg_target_is_managed_child(base, target)
               ? target + strlen(base) + 1
               : NULL;
}

/* Return 0 for a live private managed-home directory, 1 when it is absent,
 * and -1 when the path exists but is unsafe or cannot be inspected. */
static int gpg_live_private_home(int base_fd, const char *base,
                                 const char *path) {
    const char *component = gpg_managed_component(base, path);
    struct stat pinned;
    struct stat named;

    if (!component) {
        set_error(ERR_INVALID_PATH, "Refusing unmanaged GPG home: %s", path);
        return -1;
    }
    if (fstatat(base_fd, component, &pinned, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return 1;
        }
        set_system_error(ERR_FILE_IO, "Cannot inspect isolated GPG home: %s", path);
        return -1;
    }
    if (S_ISLNK(pinned.st_mode) || !S_ISDIR(pinned.st_mode) ||
        pinned.st_uid != getuid() || (pinned.st_mode & 077) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe isolated GPG home: %s", path);
        return -1;
    }
    if (lstat(path, &named) != 0 || !S_ISDIR(named.st_mode) ||
        named.st_dev != pinned.st_dev || named.st_ino != pinned.st_ino) {
        set_error(ERR_PERMISSION_DENIED,
                  "Isolated GPG home path no longer names the pinned home: %s",
                  path);
        return -1;
    }
    return 0;
}

/* Confirm that both public names still resolve to the exact directories the
 * caller pinned. Descriptor-relative mutation protects the original objects;
 * this check additionally makes a namespace replacement a truthful failure
 * instead of letting a switch/reset claim it updated the replacement tree. */
static int gpg_validate_pinned_home(const gpg_pinned_home_t *home) {
    struct stat base_opened;
    struct stat base_named;
    struct stat child_named;
    struct stat home_opened;
    struct stat home_named;

    if (!home || home->base_fd < 0 || home->home_fd < 0 ||
        !home->base || !*home->base || !home->name || !*home->name ||
        !home->path || !*home->path || !validate_name(home->name)) {
        set_error(ERR_INVALID_ARGS, "Invalid pinned GPG home");
        return -1;
    }
    if (fstat(home->base_fd, &base_opened) != 0 ||
        !S_ISDIR(base_opened.st_mode) || base_opened.st_uid != getuid() ||
        (base_opened.st_mode & 077) != 0 ||
        lstat(home->base, &base_named) != 0 ||
        !S_ISDIR(base_named.st_mode) ||
        base_named.st_dev != base_opened.st_dev ||
        base_named.st_ino != base_opened.st_ino) {
        set_error(ERR_PERMISSION_DENIED,
                  "GPG base pathname no longer names the pinned directory: %s",
                  home->base);
        return -1;
    }
    if (fstat(home->home_fd, &home_opened) != 0 ||
        !S_ISDIR(home_opened.st_mode) || home_opened.st_uid != getuid() ||
        (home_opened.st_mode & 077) != 0 ||
        fstatat(home->base_fd, home->name, &child_named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(child_named.st_mode) ||
        child_named.st_dev != home_opened.st_dev ||
        child_named.st_ino != home_opened.st_ino ||
        lstat(home->path, &home_named) != 0 ||
        !S_ISDIR(home_named.st_mode) ||
        home_named.st_dev != home_opened.st_dev ||
        home_named.st_ino != home_opened.st_ino) {
        set_error(ERR_PERMISSION_DENIED,
                  "GPG home pathname no longer names the pinned directory: %s",
                  home->path);
        return -1;
    }
    return 0;
}

/* Read the stable link while the caller holds the verified base's lock.
 * This is the sole GPG readlink boundary: callers separately decide whether
 * a raw target must be a managed child or may merely be unlinked by reset.
 * Return 1 when `current` is absent, 0 when target is populated, and -1 for
 * malformed/unknown state. */
static int gpg_read_current_locked(int base_fd, const char *base,
                                   char *target, size_t size) {
    char current[MAX_PATH_LEN];
    struct stat before;
    struct stat after;
    ssize_t n;
    int readlink_errno;

    if (!target || size < 2 ||
        gpg_current_path_from_base(base, current, sizeof(current)) != 0) {
        return -1;
    }
    target[0] = '\0';
    if (fstatat(base_fd, "current", &before, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return 1;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect stable GNUPGHOME link: %s", current);
        return -1;
    }
    if (!S_ISLNK(before.st_mode) || before.st_uid != getuid()) {
        set_error(ERR_FILE_IO, "Stable GNUPGHOME entry is not a symlink: %s",
                  current);
        return -1;
    }
    if (before.st_size > 0 && (uintmax_t)before.st_size >= (uintmax_t)(size - 1)) {
        set_error(ERR_INVALID_PATH,
                  "Stable GNUPGHOME link target is too long: %s", current);
        return -1;
    }

    /* The caller holds the manager lock and the link is inside the verified
     * private base. Length and exact managed-child checks stay explicit. */
    // flawfinder: ignore
    n = readlinkat(base_fd, "current", target, size - 1);
    readlink_errno = errno;
    if (fstatat(base_fd, "current", &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(after.st_mode) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_uid != after.st_uid || before.st_size != after.st_size) {
        set_error(ERR_FILE_IO,
                  "Stable GNUPGHOME link changed while being inspected: %s",
                  current);
        return -1;
    }
    if (n < 0) {
        errno = readlink_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot read stable GNUPGHOME link: %s", current);
        return -1;
    }
    if (n == 0) {
        set_error(ERR_FILE_IO, "GNUPGHOME link has an empty target: %s", current);
        return -1;
    }
    if ((size_t)n == size - 1) {
        set_error(ERR_INVALID_PATH,
                  "Stable GNUPGHOME link target is too long: %s", current);
        return -1;
    }
    target[n] = '\0';
    return 0;
}

static int gpg_discard_prepared_link_locked(
    int base_fd, const char *name, const gpg_link_identity_t *expected) {
#if defined(__FreeBSD__)
    struct stat pinned;
    int pinned_fd;
    int saved_errno;

    if (!expected || !expected->valid) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid prepared GPG runtime link identity");
        return -1;
    }
    pinned_fd = openat(base_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (pinned_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot pin prepared GPG runtime link: %s", name);
        return -1;
    }
    if (fstat(pinned_fd, &pinned) != 0) {
        saved_errno = errno;
        close(pinned_fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot inspect prepared GPG runtime link: %s", name);
        return -1;
    }
    if (pinned.st_dev != expected->st.st_dev ||
        pinned.st_ino != expected->st.st_ino ||
        pinned.st_mode != expected->st.st_mode ||
        pinned.st_uid != expected->st.st_uid ||
        pinned.st_size != expected->st.st_size) {
        close(pinned_fd);
        set_error(ERR_FILE_IO,
                  "Prepared GPG runtime link changed; preserving it: %s", name);
        return -1;
    }
    if (funlinkat(base_fd, name, pinned_fd, 0) != 0) {
        saved_errno = errno;
        close(pinned_fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot remove prepared GPG runtime link: %s", name);
        return -1;
    }
    close(pinned_fd);
#else
    gpg_link_identity_t current;

    if (gpg_capture_link_at(base_fd, name, &current) != 0 ||
        !gpg_same_link(&current, expected)) {
        set_error(ERR_FILE_IO,
                  "Prepared GPG runtime link changed; preserving it: %s", name);
        return -1;
    }
    if (unlinkat(base_fd, name, 0) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot remove prepared GPG runtime link: %s", name);
        return -1;
    }
#endif
    if (g_sync_base(base_fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot synchronize prepared GPG link cleanup");
        return -1;
    }
    return 0;
}

/* Prepare the intended symlink under an unpredictable private name, capture
 * its inode before publication, and use native no-replace to make it public.
 * The caller can therefore retain an exact final-state witness before its
 * first directory fsync. Return 0 for both publication and a compare conflict;
 * `conflict` distinguishes the two. */
static int gpg_publish_link_noreplace_locked(
    int base_fd, const char *base, const char *target,
    gpg_link_identity_t *published, bool *conflict) {
    char publish_name[GPG_QUARANTINE_NAME_LEN] = "";
    gpg_link_identity_t committed;
    gpg_link_identity_t prepared;
    int live_rc;

    if (base_fd < 0 || !base || !*base || !target || !*target ||
        !published || !conflict) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG restoration publication");
        return -1;
    }
    memset(published, 0, sizeof(*published));
    *conflict = false;
    live_rc = gpg_live_private_home(base_fd, base, target);
    if (live_rc != 0) {
        if (live_rc > 0) {
            set_error(ERR_INVALID_PATH,
                      "Cannot restore missing isolated GPG home: %s", target);
        }
        return -1;
    }
    if (gpg_make_private_name(publish_name, sizeof(publish_name),
                              GPG_PUBLISH_PREFIX) != 0 ||
        symlinkat(target, base_fd, publish_name) != 0) {
        if (publish_name[0] != '\0') {
            set_system_error(ERR_FILE_IO,
                             "Cannot prepare previous GNUPGHOME target");
        }
        return -1;
    }
    if (gpg_capture_link_at(base_fd, publish_name, &prepared) != 0) {
        return -1;
    }
    if (g_rename_noreplace(base_fd, publish_name, base_fd, "current") != 0) {
        int saved_errno = errno;

        if (gpg_discard_prepared_link_locked(base_fd, publish_name,
                                             &prepared) != 0) {
            return -1;
        }
        if (saved_errno == EEXIST) {
            *conflict = true;
            return 0;
        }
        errno = saved_errno;
        if (saved_errno == ENOTSUP ||
#if EOPNOTSUPP != ENOTSUP
            saved_errno == EOPNOTSUPP ||
#endif
            saved_errno == ENOSYS || saved_errno == EINVAL) {
            set_error(ERR_FILE_IO,
                      "Platform lacks atomic no-replace GPG restoration");
        } else {
            set_system_error(ERR_FILE_IO,
                             "Cannot publish previous GNUPGHOME target");
        }
        return -1;
    }
    /* FreeBSD's linkat-based fallback publishes by pathname, so a same-uid
     * replacement of the private source must not be accepted as the link we
     * prepared.  Native rename implementations also benefit from this final
     * identity proof before the result becomes rollback state. */
    if (gpg_capture_link_at(base_fd, "current", &committed) != 0 ||
        !gpg_same_link(&committed, &prepared)) {
        set_error(ERR_FILE_IO,
                  "Published GPG runtime link does not match prepared identity");
        return -1;
    }
    /* FreeBSD's linkat-based no-replace fallback can leave the private source
     * alias behind when its retirement unlink fails after publication.  Reap
     * it through the exact-identity cleanup above; a replacement is preserved
     * and turns this into a fail-closed error while the published `current`
     * remains available for retry-state discovery. */
    {
        gpg_link_identity_t leftover;
        int leftover_rc = gpg_capture_link_at(base_fd, publish_name,
                                              &leftover);

        if (leftover_rc < 0) return -1;
        if (leftover_rc == 0) {
            if (gpg_discard_prepared_link_locked(base_fd, publish_name,
                                                 &prepared) != 0) {
                return -1;
            }
        }
    }
    *published = committed;
    return 0;
}

static void gpg_record_final_link(gpg_rollback_token_t *token,
                                  const gpg_link_identity_t *identity) {
    token->final_link = *identity;
    token->final_present = true;
    token->final_state_valid = true;
}

static void gpg_record_final_absence(gpg_rollback_token_t *token) {
    memset(&token->final_link, 0, sizeof(token->final_link));
    token->final_present = false;
    token->final_state_valid = true;
}

/* A failed PUBLIC_DONE fsync leaves a retry token. Before that retry can claim
 * success, prove that `current` is still the exact captured inode (not merely
 * the same target spelling) or is still absent. A later managed writer is a
 * compare conflict; malformed or unmanaged state fails closed. */
static int gpg_reprove_final_state_locked(int base_fd, const char *base,
                                          gpg_rollback_token_t *token) {
    gpg_link_identity_t current;
    int current_rc;

    if (!token || !token->final_state_valid ||
        (token->final_present && !token->final_link.valid)) {
        set_error(ERR_INVALID_ARGS, "Invalid final GPG rollback state");
        return -1;
    }
    current_rc = gpg_capture_link_at(base_fd, "current", &current);
    if (current_rc < 0) return -1;
    if (current_rc == 0 &&
        !gpg_target_is_managed_child(base, current.target)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Stable GNUPGHOME changed to an unmanaged target: %s",
                  current.target);
        return -1;
    }
    if ((token->final_present &&
         (current_rc != 0 ||
          !gpg_same_link(&current, &token->final_link))) ||
        (!token->final_present && current_rc == 0)) {
        token->conflict = true;
    }
    return 0;
}

/* Complete a compare-and-restore without ever unlinking `current` by pathname.
 * Native rename-no-replace moves whichever inode is current at the atomic
 * instant to an unpredictable quarantine. If a same-uid writer won the race,
 * that foreign inode is restored with native no-replace and retained on any
 * collision. Every phase is retryable and advances before its fsync, so a sync
 * failure never makes the caller guess which namespace mutation happened. */
static int gpg_finish_rollback_locked(int base_fd, const char *base,
                                      gpg_rollback_token_t *token,
                                      bool *changed) {
    gpg_link_identity_t current;
    gpg_link_identity_t quarantined;
    int current_rc;
    int quarantine_rc;

    if (base_fd < 0 || !base || !*base || !token || !changed ||
        token->phase == GPG_ROLLBACK_NONE ||
        (token->phase != GPG_ROLLBACK_PUBLIC_DONE &&
         !token->published.valid) ||
        (token->phase == GPG_ROLLBACK_PUBLIC_DONE &&
         !token->final_state_valid)) {
        set_error(ERR_INVALID_ARGS, "Invalid retained GPG rollback state");
        return -1;
    }
    *changed = false;

    if (token->phase == GPG_ROLLBACK_EXPECTED_CURRENT) {
        /* A successful move followed by a capture/sync failure is represented
         * by the quarantine name while the phase remains EXPECTED_CURRENT. */
        if (token->quarantine[0] != '\0') {
            quarantine_rc = gpg_capture_link_at(base_fd, token->quarantine,
                                                &quarantined);
            if (quarantine_rc < 0) return -1;
            if (quarantine_rc == 0) {
                token->quarantined = quarantined;
                token->phase = gpg_same_link(&quarantined, &token->published)
                                   ? GPG_ROLLBACK_OWNED_QUARANTINED
                                   : GPG_ROLLBACK_FOREIGN_QUARANTINED;
                if (g_sync_base(base_fd) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot synchronize GPG rollback quarantine");
                    return -1;
                }
                if (g_rollback_hook &&
                    g_rollback_hook(base_fd,
                                      GPG_ROLLBACK_HOOK_AFTER_QUARANTINE,
                                      token->quarantine) != 0) {
                    set_error(ERR_FILE_IO,
                              "GPG rollback post-quarantine hook failed");
                    return -1;
                }
            } else {
                token->quarantine[0] = '\0';
            }
        }

        if (token->phase == GPG_ROLLBACK_EXPECTED_CURRENT) {
            current_rc = gpg_capture_link_at(base_fd, "current", &current);
            if (current_rc < 0) return -1;
            if (current_rc != 0 ||
                !gpg_same_link(&current, &token->published)) {
                if (current_rc == 0 &&
                    !gpg_target_is_managed_child(base, current.target)) {
                    set_error(ERR_PERMISSION_DENIED,
                              "Stable GNUPGHOME changed to an unmanaged target: %s",
                              current.target);
                    return -1;
                }
                /* The exact publication is already gone. Preserve the later
                 * writer (including a same-target/different-inode writer). */
                if (g_sync_base(base_fd) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot synchronize GPG rollback conflict");
                    return -1;
                }
                memset(token, 0, sizeof(*token));
                *changed = false;
                return 0;
            }
            if (g_retarget_restore_hook &&
                g_retarget_restore_hook(base_fd) != 0) {
                set_error(ERR_FILE_IO, "GPG retarget restoration hook failed");
                return -1;
            }
            if (gpg_make_private_name(token->quarantine,
                                      sizeof(token->quarantine),
                                      GPG_ROLLBACK_PREFIX) != 0 ||
                gpg_reject_stale_quarantines_locked(base_fd,
                                                     token->quarantine) != 0) {
                token->quarantine[0] = '\0';
                return -1;
            }
            if (g_rollback_hook &&
                g_rollback_hook(base_fd,
                                  GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE,
                                  token->quarantine) != 0) {
                token->quarantine[0] = '\0';
                set_error(ERR_FILE_IO,
                          "GPG rollback pre-quarantine hook failed");
                return -1;
            }
            if (g_rename_noreplace(base_fd, "current", base_fd,
                                   token->quarantine) != 0) {
                int saved_errno = errno;
                token->quarantine[0] = '\0';
                errno = saved_errno;
                if (saved_errno == ENOTSUP ||
#if EOPNOTSUPP != ENOTSUP
                    saved_errno == EOPNOTSUPP ||
#endif
                    saved_errno == ENOSYS || saved_errno == EINVAL) {
                    set_error(ERR_FILE_IO,
                              "Platform lacks atomic no-replace GPG rollback quarantine");
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot quarantine stable GNUPGHOME before rollback");
                }
                return -1;
            }
            quarantine_rc = gpg_capture_link_at(base_fd, token->quarantine,
                                                &quarantined);
            if (quarantine_rc != 0) {
                set_error(ERR_FILE_IO,
                          "Cannot capture the GPG rollback quarantine; retry state retained");
                return -1;
            }
            token->quarantined = quarantined;
            token->phase = gpg_same_link(&quarantined, &token->published)
                               ? GPG_ROLLBACK_OWNED_QUARANTINED
                               : GPG_ROLLBACK_FOREIGN_QUARANTINED;
            if (g_sync_base(base_fd) != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot synchronize GPG rollback quarantine");
                return -1;
            }
            if (g_rollback_hook &&
                g_rollback_hook(base_fd, GPG_ROLLBACK_HOOK_AFTER_QUARANTINE,
                                  token->quarantine) != 0) {
                set_error(ERR_FILE_IO,
                          "GPG rollback post-quarantine hook failed");
                return -1;
            }
        }
    }

    if (token->phase == GPG_ROLLBACK_OWNED_QUARANTINED) {
        gpg_link_identity_t restored;
        bool publish_conflict = false;

        quarantine_rc = gpg_capture_link_at(base_fd, token->quarantine,
                                            &quarantined);
        if (quarantine_rc != 0) {
            set_error(ERR_FILE_IO,
                      "Owned GPG rollback quarantine is missing or unreadable");
            return -1;
        }
        if (!gpg_same_link(&quarantined, &token->quarantined)) {
            set_error(ERR_FILE_IO,
                      "Owned GPG rollback quarantine changed; preserving replacement");
            return -1;
        }
        current_rc = gpg_capture_link_at(base_fd, "current", &current);
        if (current_rc < 0) return -1;
        if (current_rc == 0) {
            if (!gpg_target_is_managed_child(base, current.target)) {
                set_error(ERR_PERMISSION_DENIED,
                          "Stable GNUPGHOME changed to an unmanaged target: %s",
                          current.target);
                return -1;
            }
            token->conflict = true;
            gpg_record_final_link(token, &current);
        } else if (token->restore_present) {
            if (gpg_publish_link_noreplace_locked(
                    base_fd, base, token->restore_target, &restored,
                    &publish_conflict) != 0) {
                return -1;
            }
            if (publish_conflict) {
                current_rc = gpg_capture_link_at(base_fd, "current", &current);
                if (current_rc < 0) return -1;
                if (current_rc == 0) {
                    if (!gpg_target_is_managed_child(base, current.target)) {
                        set_error(
                            ERR_PERMISSION_DENIED,
                            "Stable GNUPGHOME changed to an unmanaged target: %s",
                            current.target);
                        return -1;
                    }
                    gpg_record_final_link(token, &current);
                } else {
                    gpg_record_final_absence(token);
                }
                token->conflict = true;
            } else {
                gpg_record_final_link(token, &restored);
            }
        } else {
            gpg_record_final_absence(token);
        }
        token->phase = GPG_ROLLBACK_PUBLIC_DONE;
        if (g_sync_base(base_fd) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot synchronize restored GNUPGHOME state");
            return -1;
        }
    }

    if (token->phase == GPG_ROLLBACK_FOREIGN_QUARANTINED) {
        quarantine_rc = gpg_capture_link_at(base_fd, token->quarantine,
                                            &quarantined);
        if (quarantine_rc != 0 ||
            !gpg_same_link(&quarantined, &token->quarantined)) {
            set_error(ERR_FILE_IO,
                      "Foreign GPG rollback quarantine changed; preserving it");
            return -1;
        }
        current_rc = gpg_capture_link_at(base_fd, "current", &current);
        if (current_rc < 0) return -1;
        if (current_rc > 0) {
            if (g_rename_noreplace(base_fd, token->quarantine, base_fd,
                                   "current") != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot restore raced GNUPGHOME writer");
                return -1;
            }
            token->conflict = true;
            gpg_record_final_link(token, &token->quarantined);
            token->phase = GPG_ROLLBACK_PUBLIC_DONE;
        } else if (!gpg_same_link(&current, &token->quarantined)) {
            set_error(ERR_FILE_IO,
                      "A later GNUPGHOME writer blocks quarantine restoration");
            return -1;
        } else {
            token->conflict = true;
            gpg_record_final_link(token, &current);
            token->phase = GPG_ROLLBACK_PUBLIC_DONE;
        }
        if (g_sync_base(base_fd) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot synchronize raced GNUPGHOME restoration");
            return -1;
        }
    }

    if (token->phase == GPG_ROLLBACK_PUBLIC_DONE) {
        bool conflict;

        if (gpg_reprove_final_state_locked(base_fd, base, token) != 0) {
            return -1;
        }

        if (token->quarantine[0] == '\0') {
            if (g_sync_base(base_fd) != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot synchronize completed GPG restoration");
                return -1;
            }
            if (gpg_reprove_final_state_locked(base_fd, base, token) != 0) {
                return -1;
            }
            conflict = token->conflict;
            memset(token, 0, sizeof(*token));
            *changed = !conflict;
            return 0;
        }
        quarantine_rc = gpg_capture_link_at(base_fd, token->quarantine,
                                            &quarantined);
        if (quarantine_rc < 0) return -1;
        if (quarantine_rc == 0) {
            if (!gpg_same_link(&quarantined, &token->quarantined)) {
                set_error(ERR_FILE_IO,
                          "GPG rollback quarantine changed before cleanup");
                return -1;
            }
            if (g_rollback_hook &&
                g_rollback_hook(base_fd,
                                  GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE_UNLINK,
                                  token->quarantine) != 0) {
                set_error(ERR_FILE_IO,
                          "GPG rollback quarantine cleanup hook failed");
                return -1;
            }
            if (gpg_capture_link_at(base_fd, token->quarantine,
                                    &current) != 0 ||
                !gpg_same_link(&current, &token->quarantined)) {
                set_error(ERR_FILE_IO,
                          "GPG rollback quarantine raced before cleanup");
                return -1;
            }
            if (unlinkat(base_fd, token->quarantine, 0) != 0 && errno != ENOENT) {
                set_system_error(ERR_FILE_IO,
                                 "Cannot remove completed GPG rollback quarantine");
                return -1;
            }
        }
        if (g_sync_base(base_fd) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot synchronize GPG quarantine cleanup");
            return -1;
        }
        if (gpg_reprove_final_state_locked(base_fd, base, token) != 0) {
            return -1;
        }
        conflict = token->conflict;
        memset(token, 0, sizeof(*token));
        *changed = !conflict;
        return 0;
    }

    set_error(ERR_FILE_IO, "Unrecognized GPG rollback phase");
    return -1;
}

static int gpg_finish_failed_retarget(int base_fd, const char *base,
                                      gpg_retarget_result_t *result) {
    char primary[sizeof(g_last_error.message)];
    char rollback[sizeof(g_last_error.message)];
    bool changed = false;

    safe_strncpy(primary, get_last_error()->message, sizeof(primary));
    if (gpg_finish_rollback_locked(base_fd, base, &result->rollback,
                                   &changed) == 0) {
        result->restoration_succeeded = true;
        set_error(ERR_FILE_IO, "%s", primary);
        return -1;
    }
    safe_strncpy(rollback, get_last_error()->message, sizeof(rollback));
    set_error(ERR_FILE_IO, "%s; rollback failed: %s", primary, rollback);
    return -1;
}

static int gpg_retarget_current_locked(int base_fd, const char *base,
                                       const char *real_home,
                                       gpg_retarget_result_t *result) {
    char link_path[MAX_PATH_LEN];
    char prev_target[MAX_PATH_LEN];
    char publish_name[GPG_QUARANTINE_NAME_LEN] = "";
    gpg_link_identity_t prepared;
    gpg_link_identity_t committed;
    gpg_retarget_result_t local_result;
    bool prev_existed;
    int prev_rc;
    int live_rc;

    if (!result) {
        result = &local_result;
    }
    memset(result, 0, sizeof(*result));

    if (!gpg_target_is_managed_child(base, real_home)) {
        set_error(ERR_INVALID_PATH,
                  "Refusing unmanaged GNUPGHOME target: %s",
                  real_home ? real_home : "(null)");
        return -1;
    }
    live_rc = gpg_live_private_home(base_fd, base, real_home);
    if (live_rc != 0) {
        if (live_rc > 0) {
            set_error(ERR_INVALID_PATH,
                      "Not retargeting GNUPGHOME: home is missing: %s", real_home);
        }
        log_warning("Not retargeting GNUPGHOME symlink: home is missing: %s",
                    real_home);
        return -1;
    }
    if (gpg_current_path_from_base(base, link_path, sizeof(link_path)) != 0) {
        return -1;
    }
    if (gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        return -1;
    }

    /* Capture the target `current` names right now, before the atomic rename
     * overwrites it, so a failed retarget can restore it (AR-06 F41). A
     * malformed/absent link means there is nothing to restore. */
    prev_rc = gpg_read_current_locked(base_fd, base, prev_target,
                                      sizeof(prev_target));
    if (prev_rc < 0) {
        return -1;
    }
    prev_existed = prev_rc == 0;
    if (prev_existed &&
        (!gpg_target_is_managed_child(base, prev_target) ||
         gpg_live_private_home(base_fd, base, prev_target) != 0)) {
        set_error(ERR_INVALID_PATH,
                  "Refusing to replace unsafe previous GNUPGHOME target: %s",
                  prev_target);
        return -1;
    }
    result->previous_present = prev_existed;
    if (prev_existed) {
        safe_strncpy(result->previous_target, prev_target,
                     sizeof(result->previous_target));
    }
    safe_strncpy(result->published_target, real_home,
                 sizeof(result->published_target));

    /* Capture the private symlink inode BEFORE rename makes it public. A stat
     * performed only after rename cannot distinguish our link from a same-
     * target replacement installed by another same-uid process (ABA). */
    if (gpg_make_private_name(publish_name, sizeof(publish_name),
                              GPG_PUBLISH_PREFIX) != 0 ||
        symlinkat(real_home, base_fd, publish_name) != 0) {
        if (publish_name[0] != '\0') {
            set_system_error(ERR_FILE_IO,
                             "Failed to prepare stable GNUPGHOME symlink");
        }
        return -1;
    }
    if (gpg_capture_link_at(base_fd, publish_name, &prepared) != 0) {
        /* Without the first stable capture there is no ownership proof for
         * unlinking this path. Leave the unpredictable private name visible
         * for diagnosis rather than risk deleting a raced replacement. */
        return -1;
    }
    if (renameat(base_fd, publish_name, base_fd, "current") != 0) {
        int saved_errno = errno;
        gpg_link_identity_t retry;
        if (gpg_capture_link_at(base_fd, publish_name, &retry) == 0 &&
            gpg_same_link(&retry, &prepared)) {
            (void)unlinkat(base_fd, publish_name, 0);
            (void)g_sync_base(base_fd);
        }
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Failed to install stable GNUPGHOME symlink: %s",
                         link_path);
        log_warning("Failed to create GNUPGHOME symlink %s -> %s",
                    link_path, real_home);
        return -1;
    }
    result->publication_occurred = true;
    result->published_link = prepared;
    result->rollback.phase = GPG_ROLLBACK_EXPECTED_CURRENT;
    result->rollback.published = prepared;
    result->rollback.restore_present = prev_existed;
    if (prev_existed) {
        safe_strncpy(result->rollback.restore_target, prev_target,
                     sizeof(result->rollback.restore_target));
    }

    if (gpg_capture_link_at(base_fd, "current", &committed) != 0 ||
        !gpg_same_link(&committed, &prepared)) {
        set_error(ERR_FILE_IO,
                  "Cannot verify committed GNUPGHOME link: %s", link_path);
        return gpg_finish_failed_retarget(base_fd, base, result);
    }
    if (g_sync_base(base_fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot synchronize stable GNUPGHOME publication");
        return gpg_finish_failed_retarget(base_fd, base, result);
    }
    if (g_retarget_commit_hook && g_retarget_commit_hook(base_fd) != 0) {
        set_error(ERR_FILE_IO, "GPG retarget commit hook failed");
        return gpg_finish_failed_retarget(base_fd, base, result);
    }
    if (gpg_live_private_home(base_fd, base, real_home) != 0) {
        return gpg_finish_failed_retarget(base_fd, base, result);
    }

    log_debug("Created GNUPGHOME symlink: %s -> %s", link_path, real_home);
    return 0;
}

/* Point the stable <base>/current symlink at the active account's real
 * GNUPGHOME so a shell that exports GNUPGHOME=<base>/current (via
 * `gitswitch init`) transparently follows each switch. Mirrors the SSH
 * current.sock retargeting in ssh_manager.c. Held under the per-dir lock so
 * the retarget cannot interleave with a concurrent reset's dangling-link
 * cleanup (AR-02 #9). The forward switch does NOT come through here: it
 * retargets via gpg_retarget_current_locked under the lock it already holds
 * across create+import (AR-03 L12) — flock on a second fd for the same lock
 * file would self-deadlock. Returns failure rather than retargeting unlocked. */
int gpg_manager_retarget_current(const char *real_home) {
    char base[MAX_PATH_LEN];
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int rc;

    if (!real_home || strlen(real_home) == 0) {
        return -1;
    }

    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd, false);
    if (base_rc != 0) {
        if (base_rc > 0) {
            set_error(ERR_INVALID_PATH, "GPG base directory is missing: %s", base);
        }
        return -1;
    }
    rc = gpg_retarget_current_locked(base_fd, base, real_home, NULL);
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

/* Drop the stable `current` symlink (switching to a GPG-less account, or
 * rolling one back). Locked for the same reason as the retarget: an unlocked
 * unlink could delete the fresh link a concurrent switch just installed. */
int gpg_manager_drop_current(void) {
    char base[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN];
    struct stat link_st;
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int rc = 0;

    if (gpg_get_base_dir(base, sizeof(base)) != 0 ||
        gpg_current_path_from_base(base, link_path, sizeof(link_path)) != 0) {
        return -1;
    }

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd, false);
    if (base_rc != 0) {
        return base_rc > 0 ? 0 : -1;
    }
    if (gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if (fstatat(base_fd, "current", &link_st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO, "Cannot inspect stable GNUPGHOME link: %s",
                             link_path);
            rc = -1;
        }
    } else if (!S_ISLNK(link_st.st_mode)) {
        set_error(ERR_FILE_IO, "Stable GNUPGHOME entry is not a symlink: %s",
                  link_path);
        rc = -1;
    } else if (unlinkat(base_fd, "current", 0) != 0 && errno != ENOENT) {
        set_system_error(ERR_FILE_IO, "Failed to remove stable GNUPGHOME link: %s",
                         link_path);
        rc = -1;
    }
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

int gpg_manager_snapshot_current(char *target, size_t size, bool *present) {
    char base[MAX_PATH_LEN];
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int current_rc;
    int live_rc;

    if (!target || size == 0 || !present) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG snapshot arguments");
        return -1;
    }
    target[0] = '\0';
    *present = false;
    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd, false);
    if (base_rc != 0) {
        return base_rc > 0 ? 0 : -1;
    }
    current_rc = gpg_read_current_locked(base_fd, base, target, size);
    if (current_rc > 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return 0;
    }
    if (current_rc < 0 || !gpg_target_is_managed_child(base, target)) {
        if (current_rc == 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "Stable GNUPGHOME points outside the managed GPG base: %s",
                      target);
        }
        unlock_gpg_dir(base_fd, lock_fd);
        target[0] = '\0';
        return -1;
    }
    live_rc = gpg_live_private_home(base_fd, base, target);
    if (live_rc != 0) {
        if (live_rc > 0) {
            set_error(ERR_FILE_IO,
                      "Stable GNUPGHOME points at a missing managed home: %s",
                      target);
        }
        unlock_gpg_dir(base_fd, lock_fd);
        target[0] = '\0';
        return -1;
    }
    *present = true;
    unlock_gpg_dir(base_fd, lock_fd);
    return 0;
}

int gpg_manager_current_is_live_for_account(const char *account, bool *live) {
    char base[MAX_PATH_LEN];
    char expected[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int current_rc;
    int live_rc;

    if (!account || !live || !validate_name(account)) {
        set_error(ERR_INVALID_ARGS, "Invalid account for GPG liveness check");
        return -1;
    }
    *live = false;
    if (gpg_get_base_dir(base, sizeof(base)) != 0 ||
        safe_snprintf(expected, sizeof(expected), "%s/%s", base, account) != 0) {
        return -1;
    }
    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd, true);
    if (base_rc != 0) {
        /* Contention is evidence only that some transaction owns the base; it
         * says nothing about which account current names.  Preserve the fast
         * nonblocking check, but surface busy as unknown/failure so callers can
         * defer or retry without inventing account-specific liveness. */
        if (base_rc == 2) {
            set_error(ERR_FILE_IO,
                      "GPG runtime is busy; account liveness is unknown: %s",
                      account);
            return -1;
        }
        return base_rc > 0 ? 0 : -1;
    }
    current_rc = gpg_read_current_locked(base_fd, base, target, sizeof(target));
    if (current_rc > 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return 0;
    }
    if (current_rc < 0 || !gpg_target_is_managed_child(base, target)) {
        if (current_rc == 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "Stable GNUPGHOME points outside the managed GPG base: %s",
                      target);
        }
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if (strcmp(target, expected) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return 0;
    }
    live_rc = gpg_live_private_home(base_fd, base, target);
    if (live_rc < 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    *live = live_rc == 0;
    unlock_gpg_dir(base_fd, lock_fd);
    return 0;
}

int gpg_manager_restore_current_if(gpg_config_t *gpg_config,
                                   const char *expected_target,
                                   const char *restore_target,
                                   bool *changed) {
    char base[MAX_PATH_LEN];
    gpg_link_identity_t actual;
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int actual_rc;
    int rc = -1;
    bool expect_present = expected_target && *expected_target;
    bool restore_present = restore_target && *restore_target;

    if (!gpg_config || !changed) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG restore arguments");
        return -1;
    }
    *changed = false;
    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    if ((expect_present && !gpg_target_is_managed_child(base, expected_target)) ||
        (restore_present && !gpg_target_is_managed_child(base, restore_target))) {
        set_error(ERR_INVALID_PATH,
                  "Refusing unmanaged GPG compare-and-restore target");
        return -1;
    }

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd, false);
    if (base_rc > 0) {
        if (gpg_config->runtime_restore_pending) {
            set_error(ERR_FILE_IO,
                      "Managed GPG base disappeared with rollback pending");
            return -1;
        }
        if (!expect_present && !restore_present) {
            *changed = true;
            return 0;
        }
        if (!expect_present && restore_present) {
            set_error(ERR_INVALID_PATH,
                      "Cannot restore a GPG home from an absent managed base");
            return -1;
        }
        return 0; /* expected present cannot match an absent base */
    }
    if (base_rc < 0) {
        return -1;
    }

    if (gpg_config->runtime_restore_pending) {
        if (gpg_config->rollback.phase == GPG_ROLLBACK_NONE ||
            (gpg_config->rollback.phase != GPG_ROLLBACK_PUBLIC_DONE &&
             !gpg_config->rollback.published.valid) ||
            (gpg_config->rollback.phase == GPG_ROLLBACK_PUBLIC_DONE &&
             !gpg_config->rollback.final_state_valid) ||
            (expect_present &&
             (!gpg_config->rollback.published.valid ||
              strcmp(expected_target,
                     gpg_config->rollback.published.target) != 0)) ||
            (restore_present != gpg_config->rollback.restore_present) ||
            (restore_present &&
             strcmp(restore_target,
                    gpg_config->rollback.restore_target) != 0)) {
            set_error(ERR_INVALID_ARGS,
                      "GPG restore arguments do not match retained rollback state");
            goto out;
        }
        rc = gpg_finish_rollback_locked(base_fd, base,
                                        &gpg_config->rollback, changed);
        if (rc == 0) {
            gpg_config->runtime_restore_pending = false;
            gpg_config->published_link_valid = false;
            memset(&gpg_config->published_link, 0,
                   sizeof(gpg_config->published_link));
        }
        goto out;
    }
    if (gpg_config->rollback.phase != GPG_ROLLBACK_NONE) {
        set_error(ERR_FILE_IO,
                  "GPG rollback token exists without pending ownership");
        goto out;
    }
    if (gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        goto out;
    }

    actual_rc = gpg_capture_link_at(base_fd, "current", &actual);
    if (actual_rc < 0) {
        goto out;
    }
    if (actual_rc == 0 &&
        !gpg_target_is_managed_child(base, actual.target)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Stable GNUPGHOME points outside the managed GPG base: %s",
                  actual.target);
        goto out;
    }

    if ((expect_present &&
         (actual_rc != 0 || strcmp(actual.target, expected_target) != 0)) ||
        (!expect_present && actual_rc == 0)) {
        rc = 0; /* compare-and-swap conflict: leave the later state untouched */
        goto out;
    }

    if (expect_present) {
        if (gpg_config->published_link_valid &&
            (!gpg_config->published_link.valid ||
             strcmp(gpg_config->published_link.target, expected_target) != 0)) {
            set_error(ERR_INVALID_ARGS,
                      "Retained GPG publication does not match expected target");
            goto out;
        }
        memset(&gpg_config->rollback, 0, sizeof(gpg_config->rollback));
        gpg_config->rollback.phase = GPG_ROLLBACK_EXPECTED_CURRENT;
        gpg_config->rollback.published =
            gpg_config->published_link_valid ? gpg_config->published_link
                                             : actual;
        gpg_config->rollback.restore_present = restore_present;
        if (restore_present) {
            safe_strncpy(gpg_config->rollback.restore_target, restore_target,
                         sizeof(gpg_config->rollback.restore_target));
        }
        gpg_config->runtime_restore_pending = true;
        rc = gpg_finish_rollback_locked(base_fd, base,
                                        &gpg_config->rollback, changed);
        if (rc == 0) {
            gpg_config->runtime_restore_pending = false;
            gpg_config->published_link_valid = false;
            memset(&gpg_config->published_link, 0,
                   sizeof(gpg_config->published_link));
        }
        goto out;
    }

    if (restore_present) {
        gpg_link_identity_t restored;
        bool publish_conflict = false;

        if (gpg_publish_link_noreplace_locked(
                base_fd, base, restore_target, &restored,
                &publish_conflict) != 0) {
            goto out;
        }
        if (publish_conflict) {
            actual_rc = gpg_capture_link_at(base_fd, "current", &actual);
            if (actual_rc < 0) goto out;
            if (actual_rc == 0 &&
                !gpg_target_is_managed_child(base, actual.target)) {
                set_error(
                    ERR_PERMISSION_DENIED,
                    "Stable GNUPGHOME changed to an unmanaged target: %s",
                    actual.target);
                goto out;
            }
            rc = 0;
            goto out;
        }
        memset(&gpg_config->rollback, 0, sizeof(gpg_config->rollback));
        gpg_config->rollback.published = restored;
        gpg_record_final_link(&gpg_config->rollback, &restored);
        gpg_config->rollback.phase = GPG_ROLLBACK_PUBLIC_DONE;
        gpg_config->rollback.restore_present = true;
        safe_strncpy(gpg_config->rollback.restore_target, restore_target,
                     sizeof(gpg_config->rollback.restore_target));
        gpg_config->runtime_restore_pending = true;
        rc = gpg_finish_rollback_locked(base_fd, base,
                                        &gpg_config->rollback, changed);
        if (rc == 0) {
            gpg_config->runtime_restore_pending = false;
        }
        goto out;
    }

    memset(&gpg_config->rollback, 0, sizeof(gpg_config->rollback));
    gpg_record_final_absence(&gpg_config->rollback);
    gpg_config->rollback.phase = GPG_ROLLBACK_PUBLIC_DONE;
    gpg_config->runtime_restore_pending = true;
    rc = gpg_finish_rollback_locked(base_fd, base,
                                    &gpg_config->rollback, changed);
    if (rc == 0) {
        gpg_config->runtime_restore_pending = false;
    }

out:
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

typedef struct {
    bool injected;
    uint64_t injected_id;
#ifdef __linux__
    unsigned long long mount_id;
#elif defined(__APPLE__) || defined(__FreeBSD__)
    fsid_t fsid;
#else
    int unsupported;
#endif
} gpg_mount_identity_t;

/* Capture the kernel mount identity for a pinned directory. Linux st_dev is
 * deliberately not used: a bind mount of the same filesystem (or even the
 * same inode) keeps st_dev while crossing into a distinct mount. statx's mount
 * ID closes that gap. macOS and FreeBSD expose the corresponding filesystem
 * identity through fstatfs; uncertainty on an unsupported platform fails
 * closed instead of silently weakening reset. */
static int gpg_mount_identity_fd(int fd, gpg_mount_identity_t *identity) {
    if (fd < 0 || !identity) {
        errno = EINVAL;
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    if (g_mount_identity_probe) {
        if (g_mount_identity_probe(fd, &identity->injected_id) != 0) {
            return -1;
        }
        identity->injected = true;
        return 0;
    }
#ifdef __linux__
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif
#if defined(SYS_statx) && defined(STATX_MNT_ID)
    struct statx stx;
    memset(&stx, 0, sizeof(stx));
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_NO_AUTOMOUNT,
                STATX_MNT_ID, &stx) != 0) {
        return -1;
    }
    if ((stx.stx_mask & STATX_MNT_ID) == 0) {
        errno = ENOTSUP;
        return -1;
    }
    identity->mount_id = stx.stx_mnt_id;
    return 0;
#else
    errno = ENOTSUP;
    return -1;
#endif
#elif defined(__APPLE__) || defined(__FreeBSD__)
    struct statfs mounted;
    if (fstatfs(fd, &mounted) != 0) return -1;
    identity->fsid = mounted.f_fsid;
    return 0;
#else
    (void)identity;
    errno = ENOTSUP;
    return -1;
#endif
}

static bool gpg_same_mount(const gpg_mount_identity_t *left,
                           const gpg_mount_identity_t *right) {
    if (!left || !right) return false;
    if (left->injected || right->injected) {
        return left->injected && right->injected &&
               left->injected_id == right->injected_id;
    }
#ifdef __linux__
    return left->mount_id == right->mount_id;
#elif defined(__APPLE__) || defined(__FreeBSD__)
    return memcmp(&left->fsid, &right->fsid, sizeof(left->fsid)) == 0;
#else
    return false;
#endif
}

static bool gpg_same_reset_entry(const struct stat *left,
                                 const struct stat *right) {
    return left && right && left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino && left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid;
}

static bool gpg_same_file_version(const struct stat *left,
                                  const struct stat *right) {
    if (!gpg_same_reset_entry(left, right) ||
        left->st_nlink != right->st_nlink ||
        left->st_size != right->st_size) {
        return false;
    }
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

/* Validate, or validate and empty, an already-opened directory without
 * re-resolving any ancestor pathname. Each home is walked once in validation
 * mode before any deletion, then again in destructive mode. Both passes pin
 * every directory with O_NOFOLLOW, enforce the root mount identity on every
 * descent, and require a unique link immediately before every non-directory
 * unlink. Thus a pre-existing hardlink leaves the entire home untouched, while
 * a link or mount introduced between passes is still caught before that entry
 * is removed. */
static int gpg_walk_tree_contents_fd(
    int dir_fd, const char *display_path,
    const gpg_mount_identity_t *root_mount, bool remove_entries) {
    int scan_flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;

#ifdef O_DIRECTORY
    scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    scan_flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(dir_fd, ".", scan_flags);
    dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot enumerate isolated GPG home: %s",
                         display_path);
        return -1;
    }

    for (;;) {
        struct stat before;
        struct stat opened;
        char child_display[MAX_PATH_LEN];
        errno = 0;
        entry = g_gpg_readdir(dir);
        if (!entry) {
            if (errno != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed while enumerating GPG home: %s",
                                 display_path);
                closedir(dir);
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if ((size_t)snprintf(child_display, sizeof(child_display), "%s/%s",
                             display_path, entry->d_name) >=
            sizeof(child_display)) {
            set_error(ERR_INVALID_PATH,
                      "GPG reset child path is too long: %s", entry->d_name);
            closedir(dir);
            return -1;
        }
        if (fstatat(dir_fd, entry->d_name, &before,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect GPG reset entry: %s",
                             child_display);
            closedir(dir);
            return -1;
        }
        if (S_ISDIR(before.st_mode)) {
            gpg_mount_identity_t child_mount;
            int child_fd = openat(dir_fd, entry->d_name, scan_flags);
            if (child_fd < 0 || fstat(child_fd, &opened) != 0 ||
                !S_ISDIR(opened.st_mode) ||
                opened.st_dev != before.st_dev ||
                opened.st_ino != before.st_ino ||
                opened.st_uid != getuid() || (opened.st_mode & 077) != 0) {
                if (child_fd >= 0) close(child_fd);
                set_error(ERR_PERMISSION_DENIED,
                          "GPG reset directory changed while opening: %s",
                          child_display);
                closedir(dir);
                return -1;
            }
            if (gpg_mount_identity_fd(child_fd, &child_mount) != 0) {
                int saved_errno = errno;
                close(child_fd);
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_PERMISSION_DENIED,
                                 "Cannot prove GPG reset mount boundary: %s",
                                 child_display);
                return -1;
            }
            if (!gpg_same_mount(root_mount, &child_mount)) {
                close(child_fd);
                closedir(dir);
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing to cross nested mount during GPG reset: %s",
                          child_display);
                return -1;
            }
            if (gpg_walk_tree_contents_fd(child_fd, child_display, root_mount,
                                          remove_entries) != 0) {
                close(child_fd);
                closedir(dir);
                return -1;
            }
            close(child_fd);
            if (remove_entries) {
                if (fstatat(dir_fd, entry->d_name, &opened,
                            AT_SYMLINK_NOFOLLOW) != 0 ||
                    !gpg_same_reset_entry(&before, &opened) ||
                    unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to remove GPG directory: %s",
                                     child_display);
                    closedir(dir);
                    return -1;
                }
            }
        } else {
            if (before.st_uid != getuid() || before.st_nlink != 1) {
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing linked or unowned GPG reset entry: %s",
                          child_display);
                closedir(dir);
                return -1;
            }
            if (remove_entries) {
                struct stat revalidated;
                if (fstatat(dir_fd, entry->d_name, &revalidated,
                            AT_SYMLINK_NOFOLLOW) != 0 ||
                    !gpg_same_reset_entry(&before, &revalidated) ||
                    revalidated.st_nlink != 1) {
                    set_error(ERR_PERMISSION_DENIED,
                              "GPG reset entry changed or gained a link: %s",
                              child_display);
                    closedir(dir);
                    return -1;
                }
                if (unlinkat(dir_fd, entry->d_name, 0) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to remove GPG reset entry: %s",
                                     child_display);
                    closedir(dir);
                    return -1;
                }
            }
        }
    }
    if (closedir(dir) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close isolated GPG home: %s",
                         display_path);
        return -1;
    }
    return 0;
}

/* Validate one account home without running gpgconf or deleting anything.
 * Full reset applies this to every named home before beginning the destructive
 * pass, so a hazard in a later account cannot be discovered only after an
 * earlier account has already been erased. */
static int gpg_preflight_home_at(int base_fd, const char *base,
                                 const char *name) {
    char home[MAX_PATH_LEN];
    struct stat named;
    struct stat opened;
    gpg_mount_identity_t base_mount;
    gpg_mount_identity_t home_mount;
    int flags = O_RDONLY | O_CLOEXEC;
    int home_fd;

#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    if (!validate_name(name) ||
        (size_t)snprintf(home, sizeof(home), "%s/%s", base, name) >=
            sizeof(home)) {
        set_error(ERR_INVALID_PATH, "Invalid GPG home during reset: %s", name);
        return -1;
    }
    if (fstatat(base_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(named.st_mode) || named.st_uid != getuid() ||
        (named.st_mode & 077) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe GPG home during reset: %s", home);
        return -1;
    }
    home_fd = openat(base_fd, name, flags);
    if (home_fd < 0 || fstat(home_fd, &opened) != 0 ||
        !S_ISDIR(opened.st_mode) || !gpg_same_reset_entry(&named, &opened)) {
        if (home_fd >= 0) close(home_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "GPG home changed during reset preflight: %s", home);
        return -1;
    }
    if (gpg_mount_identity_fd(base_fd, &base_mount) != 0 ||
        gpg_mount_identity_fd(home_fd, &home_mount) != 0) {
        int saved_errno = errno;
        close(home_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot prove GPG reset mount boundary: %s", home);
        return -1;
    }
    if (!gpg_same_mount(&base_mount, &home_mount)) {
        close(home_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing mounted isolated GPG home during reset: %s", home);
        return -1;
    }
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false) != 0) {
        close(home_fd);
        return -1;
    }
    if (close(home_fd) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close GPG home after preflight: %s", home);
        return -1;
    }
    return 0;
}

static int gpg_preflight_reset_all_locked(int base_fd, const char *base) {
    int flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;

#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(base_fd, ".", flags);
    dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot preflight GPG base directory: %s", base);
        return -1;
    }
    for (;;) {
        errno = 0;
        entry = g_gpg_readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Failed while preflighting GPG base: %s", base);
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, ".lock") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, "current") == 0) {
            gpg_link_identity_t current;
            if (gpg_capture_link_at(base_fd, "current", &current) != 0) {
                closedir(dir);
                return -1;
            }
            continue;
        }
        if (gpg_name_has_prefix(entry->d_name, GPG_ROLLBACK_PREFIX) ||
            gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX)) {
            char residue[GPG_QUARANTINE_NAME_LEN];
            safe_strncpy(residue, entry->d_name, sizeof(residue));
            closedir(dir);
            set_error(ERR_FILE_IO,
                      "Unresolved GPG runtime quarantine blocks reset: %s",
                      residue);
            return -1;
        }
        if (entry->d_name[0] == '.' || !validate_name(entry->d_name)) {
            char residue[MAX_PATH_LEN];
            safe_strncpy(residue, entry->d_name, sizeof(residue));
            closedir(dir);
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing unmanaged GPG reset entry: %s", residue);
            return -1;
        }
        if (gpg_preflight_home_at(base_fd, base, entry->d_name) != 0) {
            closedir(dir);
            return -1;
        }
    }
    if (closedir(dir) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close GPG reset preflight: %s", base);
        return -1;
    }
    return 0;
}

/* Success for a full reset means the held private lock is the sole remaining
 * base entry. This catches a same-uid late writer and prevents an unknown
 * survivor from accompanying exit zero. */
static int gpg_verify_reset_all_final_locked(int base_fd, int lock_fd,
                                             const char *base) {
    int flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;
    struct stat held;
    struct stat named;
    bool saw_lock = false;

    if (fstat(lock_fd, &held) != 0 ||
        fstatat(base_fd, ".lock", &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named.st_mode) || named.st_uid != getuid() ||
        named.st_nlink != 1 || (named.st_mode & 0777) != 0600 ||
        !gpg_same_reset_entry(&held, &named)) {
        set_error(ERR_FILE_IO,
                  "GPG reset lock changed before final verification: %s", base);
        return -1;
    }
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    scan_fd = openat(base_fd, ".", flags);
    dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        if (scan_fd >= 0) close(scan_fd);
        set_system_error(ERR_FILE_IO,
                         "Cannot verify final GPG reset state: %s", base);
        return -1;
    }
    for (;;) {
        errno = 0;
        entry = g_gpg_readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Failed final GPG reset enumeration: %s", base);
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, ".lock") == 0 && !saw_lock) {
            saw_lock = true;
            continue;
        }
        {
            char residue[MAX_PATH_LEN];
            safe_strncpy(residue, entry->d_name, sizeof(residue));
            closedir(dir);
            set_error(ERR_FILE_IO,
                      "GPG reset left or raced with base entry: %s", residue);
            return -1;
        }
    }
    if (closedir(dir) != 0 || !saw_lock ||
        fstatat(base_fd, ".lock", &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named.st_mode) || named.st_uid != getuid() ||
        named.st_nlink != 1 || (named.st_mode & 0777) != 0600 ||
        !gpg_same_reset_entry(&held, &named)) {
        set_error(ERR_FILE_IO,
                  "GPG reset final state lacks its exact lock: %s", base);
        return -1;
    }
    return 0;
}

/* Stop the gpg-agent and only then delete its isolated home. The home is the
 * retry handle for both the agent and its secret-key material, so an
 * unconfirmed stop must retain it rather than erase the only targeting state. */
static int gpg_kill_and_remove_home(int base_fd, const char *base,
                                    const char *name) {
    const char *argv[] = {"gpgconf", "--kill", "all", NULL};
    char home[MAX_PATH_LEN];
    const char *env[2] = {"GNUPGHOME=.", NULL};
    run_opts_t opts;
    run_result_t result;
    struct stat entry_before;
    struct stat opened;
    struct stat entry_after;
    gpg_pinned_home_t pinned;
    gpg_mount_identity_t base_mount;
    gpg_mount_identity_t home_mount;
    int home_flags = O_RDONLY | O_CLOEXEC;
    int home_fd = -1;
    int run_rc;

#ifdef O_DIRECTORY
    home_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    home_flags |= O_NOFOLLOW;
#endif
    if ((size_t)snprintf(home, sizeof(home), "%s/%s", base, name) >=
        sizeof(home)) {
        set_error(ERR_INVALID_PATH, "GPG home path too long for reset");
        return -1;
    }
    if (fstatat(base_fd, name, &entry_before, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(entry_before.st_mode) || entry_before.st_uid != getuid() ||
        (entry_before.st_mode & 077) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe isolated GPG home: %s", home);
        return -1;
    }
    home_fd = openat(base_fd, name, home_flags);
    if (home_fd < 0 || fstat(home_fd, &opened) != 0 ||
        opened.st_dev != entry_before.st_dev ||
        opened.st_ino != entry_before.st_ino || !S_ISDIR(opened.st_mode)) {
        if (home_fd >= 0) close(home_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Isolated GPG home changed while opening: %s", home);
        return -1;
    }
    pinned.base_fd = base_fd;
    pinned.home_fd = home_fd;
    pinned.base = base;
    pinned.name = name;
    pinned.path = home;
    if (gpg_validate_pinned_home(&pinned) != 0) {
        close(home_fd);
        return -1;
    }
    if (gpg_mount_identity_fd(base_fd, &base_mount) != 0 ||
        gpg_mount_identity_fd(home_fd, &home_mount) != 0) {
        int saved_errno = errno;
        close(home_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot prove isolated GPG home mount boundary: %s",
                         home);
        return -1;
    }
    if (!gpg_same_mount(&base_mount, &home_mount)) {
        close(home_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing mounted isolated GPG home during reset: %s", home);
        return -1;
    }
    /* Preflight the complete tree before stopping the agent or unlinking any
     * state. This makes a pre-existing mount or hardlink an all-or-nothing
     * refusal for this home. */
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false) != 0) {
        close(home_fd);
        return -1;
    }

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.extra_env = env;
    opts.stderr_to_devnull = true;
    opts.cwd_fd = home_fd;
    opts.use_cwd_fd = true;
    run_rc = run_argv(argv, &opts, &result);
    if (gpg_validate_pinned_home(&pinned) != 0) {
        close(home_fd);
        return -1;
    }
    if (run_rc != 0 || !result.spawned || result.exit_code != 0 ||
        result.term_signal != 0) {
        set_error(ERR_SYSTEM_COMMAND_FAILED,
                  "Failed to stop GPG agent for %s; home retained for retry", home);
        close(home_fd);
        return -1;
    }
    if (fstatat(base_fd, name, &entry_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        entry_after.st_dev != opened.st_dev ||
        entry_after.st_ino != opened.st_ino) {
        close(home_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "GPG home changed while its agent was stopping: %s", home);
        return -1;
    }
    /* gpgconf may have changed sockets or files while shutting down. Validate
     * its final tree as a whole, then give tests a deterministic race seam;
     * destructive traversal independently revalidates every entry. */
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false) != 0) {
        close(home_fd);
        return -1;
    }
    if (g_cleanup_predelete && g_cleanup_predelete(home_fd) != 0) {
        close(home_fd);
        set_error(ERR_FILE_IO, "GPG cleanup pre-delete hook failed: %s", home);
        return -1;
    }
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, true) != 0) {
        close(home_fd);
        return -1;
    }
    close(home_fd);
    if (fstatat(base_fd, name, &entry_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        entry_after.st_dev != opened.st_dev ||
        entry_after.st_ino != opened.st_ino ||
        unlinkat(base_fd, name, AT_REMOVEDIR) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to remove isolated GPG home directory: %s",
                         home);
        return -1;
    }
    log_debug("Removed isolated GPG home: %s", home);
    return 0;
}

/* Tear down isolated GPG homes: one account, or all when account is NULL.
 * Kills the per-home gpg-agents and deletes (unlinks) the homes, then drops
 * the stable `current` symlink if it dangles. NB: deletion is remove(), not a
 * secure overwrite — on the memory-backed storage the create path requires by
 * default, unlinking genuinely destroys the bytes, but on the explicitly
 * opted-in non-tmpfs path (GITSWITCH_ALLOW_TMP_GPG) the secret-key bytes may
 * remain recoverable on disk after deletion (AR-02 #26). */
int gpg_manager_reset(const char *account) {
    char base[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    bool absent = false;
    int base_fd = -1;
    int lock_fd = -1;
    bool failed = false;

    if (account && *account && !validate_name(account)) {
        set_error(ERR_INVALID_ARGS, "Invalid account name for reset: %s", account);
        return -1;
    }
    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    base_fd = gpg_open_base_dir(base, sizeof(base), false, &absent);
    if (base_fd < 0) {
        return absent ? 0 : -1;
    }
    lock_fd = lock_gpg_dir(base_fd);
    if (lock_fd < 0) {
        close(base_fd);
        set_system_error(ERR_FILE_IO, "Failed to lock GPG base directory: %s", base);
        return -1;
    }
    if (gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if ((!account || !*account) &&
        gpg_preflight_reset_all_locked(base_fd, base) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }

    if (account && *account) {
        struct stat hst;
        if (fstatat(base_fd, account, &hst, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISDIR(hst.st_mode) || hst.st_uid != getuid() ||
                (hst.st_mode & 077) != 0) {
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing unsafe isolated GPG home: %s/%s",
                          base, account);
                unlock_gpg_dir(base_fd, lock_fd);
                return -1;
            } else if (gpg_kill_and_remove_home(base_fd, base, account) != 0) {
                failed = true;
            }
        } else if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect isolated GPG home: %s/%s",
                             base, account);
            failed = true;
        }
    } else {
        int scan_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
        scan_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
        scan_flags |= O_NOFOLLOW;
#endif
        int scan_fd = openat(base_fd, ".", scan_flags);
        DIR *d = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
        if (!d) {
            if (scan_fd >= 0) close(scan_fd);
            set_system_error(ERR_FILE_IO, "Cannot enumerate GPG base directory: %s", base);
            failed = true;
        } else {
            struct dirent *ent;
            for (;;) {
                errno = 0;
                ent = g_gpg_readdir(d);
                if (!ent) {
                    if (errno != 0) {
                        set_system_error(ERR_FILE_IO,
                                         "Failed while enumerating GPG base directory: %s",
                                         base);
                        failed = true;
                    }
                    break;
                }
                /* Only the exact lock and deferred stable link are manager
                 * metadata. Every other hidden name is an unknown survivor,
                 * not a broad dotfile exemption. */
                if (strcmp(ent->d_name, ".") == 0 ||
                    strcmp(ent->d_name, "..") == 0 ||
                    strcmp(ent->d_name, ".lock") == 0 ||
                    strcmp(ent->d_name, "current") == 0) {
                    continue;
                }
                if (!validate_name(ent->d_name)) {
                    set_error(ERR_PERMISSION_DENIED,
                              "Refusing unmanaged GPG reset entry: %s",
                              ent->d_name);
                    failed = true;
                    continue;
                }
                struct stat est;
                if (fstatat(base_fd, ent->d_name, &est,
                            AT_SYMLINK_NOFOLLOW) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot inspect GPG home during reset: %s/%s",
                                     base, ent->d_name);
                    failed = true;
                    continue;
                }
                if (!S_ISDIR(est.st_mode) || est.st_uid != getuid() ||
                    (est.st_mode & 077) != 0) {
                    set_error(ERR_PERMISSION_DENIED,
                              "Refusing unsafe GPG home during reset: %s/%s",
                              base, ent->d_name);
                    failed = true;
                    continue;
                }
                if (gpg_kill_and_remove_home(base_fd, base, ent->d_name) != 0) {
                    failed = true;
                }
            }
            if (closedir(d) != 0) {
                set_system_error(ERR_FILE_IO, "Failed to close GPG base directory: %s", base);
                failed = true;
            }
        }
    }

    /* A successful all-home reset must always drop the stable entry point,
     * even when a corrupted link points at an existing directory outside the
     * managed base. Only the link is removed; its target is never traversed.
     * On an incomplete reset retain a live target so the failed managed home
     * remains addressable for retry. Targeted reset keeps an unrelated live
     * account selected and removes only stale/invalid links. */
    if (gpg_current_path_from_base(base, current, sizeof(current)) != 0) {
        failed = true;
    } else {
        char target[MAX_PATH_LEN];
        int current_rc = gpg_read_current_locked(base_fd, base, target,
                                                  sizeof(target));
        if (current_rc == 0) {
            if ((!account || !*account) && !failed) {
                if (unlinkat(base_fd, "current", 0) != 0 && errno != ENOENT) {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to remove stable GNUPGHOME link: %s",
                                     current);
                    failed = true;
                }
                goto reset_finalize;
            }
            const char *component = gpg_managed_component(base, target);
            struct stat target_st;
            bool remove_current = component == NULL;
            if (component &&
                fstatat(base_fd, component, &target_st,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT) {
                    remove_current = true;
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot inspect managed GNUPGHOME target: %s",
                                     target);
                    failed = true;
                }
            } else if (component &&
                       (!S_ISDIR(target_st.st_mode) ||
                        target_st.st_uid != getuid() ||
                        (target_st.st_mode & 077) != 0)) {
                remove_current = true;
            }
            if (remove_current &&
                unlinkat(base_fd, "current", 0) != 0 && errno != ENOENT) {
                set_system_error(ERR_FILE_IO,
                                 "Failed to remove invalid GNUPGHOME link: %s",
                                 current);
                failed = true;
            }
        } else if (current_rc < 0) {
            failed = true;
        }
    }
reset_finalize:
    if ((!account || !*account) && !failed) {
        if (g_reset_final_hook && g_reset_final_hook(base_fd) != 0) {
            set_error(ERR_FILE_IO, "GPG reset final-verification hook failed");
            failed = true;
        } else if (gpg_verify_reset_all_final_locked(base_fd, lock_fd,
                                                     base) != 0) {
            failed = true;
        }
    }
    unlock_gpg_dir(base_fd, lock_fd);
    if (failed) {
        char detail[sizeof(g_last_error.message)];
        safe_strncpy(detail, get_last_error()->message, sizeof(detail));
        if (detail[0]) {
            set_error(ERR_FILE_IO,
                      "GPG reset incomplete; retained state for retry: %s", detail);
        } else {
            set_error(ERR_FILE_IO,
                      "GPG reset incomplete; retained remaining state for retry");
        }
        return -1;
    }
    return 0;
}

/* AR-06 F17: report whether a safe isolated GPG home already exists for
 * `account`. The switch preflight uses this to treat the system keyring as a
 * key SOURCE, not a hard gate: when the isolated home is present, the account's
 * secret key may live only there (e.g. the user deleted it from the system
 * keyring after a prior switch), and gpg_switch_account probes that home
 * authoritatively. A missing base or missing/unsafe child home reports
 * *present=false so a first-time switch still requires the system keyring. */
int gpg_manager_isolated_home_present(const char *account, bool *present) {
    char base[MAX_PATH_LEN];
    bool absent = false;
    int base_fd;
    struct stat st;

    if (!account || !*account || !present) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to gpg_manager_isolated_home_present");
        return -1;
    }
    *present = false;
    if (!validate_name(account)) {
        set_error(ERR_INVALID_ARGS, "Invalid account name: %s", account);
        return -1;
    }
    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    base_fd = gpg_open_base_dir(base, sizeof(base), false, &absent);
    if (base_fd < 0) {
        /* No base yet is a normal first-run state, not an error. */
        return absent ? 0 : -1;
    }
    if (fstatat(base_fd, account, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
        (st.st_mode & 077) == 0) {
        *present = true;
    }
    close(base_fd);
    return 0;
}

/* Compute, policy-check, and create the base directory for isolated
 * GNUPGHOMEs (shared with the stable `current` symlink path so the two never
 * disagree). Split out of gpg_create_isolated_home so gpg_switch_account can
 * establish the base — and take its lock — BEFORE the create+import sequence
 * that lock must cover (AR-03 L12); the create path below then re-runs it
 * idempotently (the memory-backed probe is memoized, ensure_private_dir is a
 * create-or-verify). Returns 0 with the base path in `base`. */
static int gpg_prepare_base_dir(char *base, size_t size) {
    if (gpg_get_base_dir(base, size) != 0) {
        return -1;
    }

    /* Refuse to export secret-key material onto persistent disk, wherever the
     * base came from. XDG_RUNTIME_DIR is only USUALLY a tmpfs — rootless
     * containers, NFS-homed logins, or a hand-exported disk path are not — and
     * the /tmp fallback (or even a bind/quota mount at exactly the base path
     * under a tmpfs /tmp) can be persistent too, so probe the actual computed
     * base rather than trusting its source or a hardcoded parent (AR-02 #3,
     * #22; probe memoized per base path — AR-03 L20). Fail closed unless the
     * user explicitly opts in with GITSWITCH_ALLOW_TMP_GPG=1 (or, better,
     * points XDG_RUNTIME_DIR at a tmpfs); on opt-in, remind them once per
     * process what they accepted. */
    if (!base_memory_backed_cached(base)) {
        const char *optin = getenv("GITSWITCH_ALLOW_TMP_GPG");
        if (!optin || strcmp(optin, "1") != 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to write GPG secret keys to non-memory-backed %s. "
                      "Set XDG_RUNTIME_DIR to a tmpfs, or GITSWITCH_ALLOW_TMP_GPG=1 "
                      "to accept on-disk secret-key persistence.", base);
            return -1;
        }
        static bool warned_optin = false;
        if (!warned_optin) {
            warned_optin = true;
            display_warning("GITSWITCH_ALLOW_TMP_GPG=1: writing GPG secret keys to "
                            "non-memory-backed %s; they may remain recoverable on "
                            "disk after deletion.", base);
        }
    }

    /* Create + verify the base directory (real, user-owned, 0700; not a
     * symlink or a dir pre-created by another user in a shared /tmp). */
    if (ensure_private_dir(base) != 0) {
        return -1;
    }
    return 0;
}

/* Create and pin one account home relative to an already-opened, locked base.
 * Configuration installation is intentionally best effort as before, but a
 * public namespace replacement is fatal even when the descriptor-relative
 * installation itself safely wrote only to the original directory. */
static int gpg_prepare_isolated_home_at(gpg_config_t *gpg_config,
                                        const account_t *account,
                                        int base_fd, const char *base,
                                        int *home_fd_out) {
    char gnupg_home[MAX_PATH_LEN];
    gpg_pinned_home_t pinned;
    int home_fd;

    if (!gpg_config || !account || base_fd < 0 || !base || !*base ||
        !home_fd_out || !validate_name(account->name)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to create isolated GPG home");
        return -1;
    }
    *home_fd_out = -1;
    if (safe_snprintf(gnupg_home, sizeof(gnupg_home), "%s/%s",
                      base, account->name) != 0) {
        set_error(ERR_INVALID_PATH, "GNUPGHOME path too long");
        return -1;
    }
    home_fd = open_private_subdir_at(base_fd, account->name, true, NULL);
    if (home_fd < 0) {
        return -1;
    }
    pinned.base_fd = base_fd;
    pinned.home_fd = home_fd;
    pinned.base = base;
    pinned.name = account->name;
    pinned.path = gnupg_home;
    if (gpg_validate_pinned_home(&pinned) != 0) {
        close(home_fd);
        return -1;
    }

    if (setup_gpg_agent_config(home_fd, gnupg_home) != 0) {
        log_warning("Failed to set up GPG agent config: %s",
                    get_last_error()->message);
    }
    if (gpg_validate_pinned_home(&pinned) != 0) {
        close(home_fd);
        return -1;
    }
    if (safe_strncpy(gpg_config->gnupg_home, gnupg_home,
                     sizeof(gpg_config->gnupg_home)) != 0) {
        close(home_fd);
        set_error(ERR_INVALID_PATH, "GNUPGHOME path too long");
        return -1;
    }
    gpg_config->home_owned = true;
    *home_fd_out = home_fd;
    log_info("Created isolated GNUPGHOME: %s", gnupg_home);
    return 0;
}

/* Public create wrapper: serialize and pin the base for the whole operation.
 * gpg_switch_account already holds this lock and therefore calls the internal
 * helper directly to avoid self-deadlocking on a second flock descriptor. */
int gpg_create_isolated_home(gpg_config_t *gpg_config, const account_t *account) {
    char base[MAX_PATH_LEN];
    int base_fd = -1;
    int home_fd = -1;
    int lock_fd = -1;
    int rc = -1;

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to gpg_create_isolated_home");
        return -1;
    }
    if (gpg_prepare_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    base_fd = gpg_open_base_dir(base, sizeof(base), false, NULL);
    if (base_fd < 0) {
        return -1;
    }
    lock_fd = lock_gpg_dir(base_fd);
    if (lock_fd < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to lock GPG base directory: %s", base);
        goto out;
    }
    rc = gpg_prepare_isolated_home_at(gpg_config, account, base_fd, base,
                                      &home_fd);

out:
    if (home_fd >= 0) close(home_fd);
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

/* AR-06 F61: gpg_import_key(), gpg_export_public_key() and gpg_list_keys() were
 * removed here — dead public API with zero callers anywhere in the tree. */

/* Validate GPG key exists and is usable */
int gpg_validate_key(gpg_config_t *gpg_config, const char *key_id) {
    char output[512];
    int result;

    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_validate_key");
        return -1;
    }

    log_debug("Validating GPG key: %s", key_id);

    result = gpg_run(gpg_config, NULL, output, sizeof(output),
                     "gpg", "--list-secret-keys", key_id, (const char *)NULL);
    if (result != 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", key_id);
        return -1;
    }

    log_debug("GPG key validation passed: %s", key_id);
    gpg_manager_note_key_available(key_id);
    return 0;
}

/* Configure git GPG signing */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, git_scope_t scope) {
    const char *signing_value;

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_configure_git_signing");
        return -1;
    }

    if (gpg_config->current_key_id[0] == '\0') {
        set_error(ERR_GPG_KEY_FAILED,
                  "Cannot configure Git signing before canonical GPG key resolution");
        return -1;
    }

    log_info("Configuring git GPG identity for account: %s", account->name);
    signing_value = account->gpg_signing_enabled ? "true" : "false";

    /* The canonical primary fingerprint remains configured even when automatic
     * commit signing is disabled. This keeps manual signing deterministic and
     * prevents a short/prefixed selector from becoming Git's effective identity. */
    if (git_set_config_value(GIT_CONFIG_USER_SIGNINGKEY,
                             gpg_config->current_key_id,
                             scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git signing key");
        return -1;
    }

    if (git_set_config_value(GIT_CONFIG_COMMIT_GPGSIGN, signing_value,
                             scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set commit.gpgsign=%s",
                  signing_value);
        return -1;
    }

    /* GNUPGHOME is already set via gpg_set_environment() - no need to override
     * gpg.program. git inherits the env var and gpg uses it automatically.
     * Setting gpg.program to "gpg --homedir ..." breaks because git execs it
     * as a single binary path, not a shell command. */
    if (git_unset_config_value(GIT_CONFIG_GPG_PROGRAM, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to clear gpg.program");
        return -1;
    }

    log_info("Git GPG identity configured successfully for account: %s",
             account->name);
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
    run_result_t res;
    int result;

    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_test_signing");
        return -1;
    }

    log_debug("Verifying signing capability for key: %s", key_id);

    result = gpg_run(gpg_config, &res, output, sizeof(output),
                     "gpg", "--list-secret-keys", "--with-colons", key_id,
                     (const char *)NULL);
    if (result != 0) {
        set_error(ERR_GPG_SIGNING_FAILED, "No secret key available for signing: %s", key_id);
        return -1;
    }

    if (!gpg_colons_have_sign_capability(output)) {
        /* A truncated capture is INCOMPLETE evidence, not proof of absence
         * (AR-03 L4): a large multi-uid/multi-subkey key can armor its
         * signing `ssb` record past the capture buffer, into the dropped
         * tail. The listing's exit 0 already proved the secret key is
         * present, and this capability check is advisory — real signing is
         * exercised when the user actually commits — so treat truncation as
         * inconclusive rather than report a spurious failure. */
        if (res.out_truncated) {
            log_debug("Signing-capability listing truncated for key %s; "
                      "treating as inconclusive, not a failure", key_id);
            gpg_manager_note_key_available(key_id);
            return 0;
        }
        set_error(ERR_GPG_SIGNING_FAILED, "Key has no signing-capable secret key: %s", key_id);
        return -1;
    }

    log_debug("Signing capability confirmed for key: %s", key_id);
    gpg_manager_note_key_available(key_id);
    return 0;
}

/* AR-06 F61: gpg_generate_key() was removed here — dead public API with zero
 * callers (gitswitch never generated keys; it isolates existing ones). */

/* Set environment variables for GPG operation */
int gpg_set_environment(gpg_config_t *gpg_config) {
    const char *previous;

    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_set_environment");
        return -1;
    }
    
    /* Set GNUPGHOME if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        if (!gpg_config->environment_installed) {
            previous = getenv("GNUPGHOME");
            /* Preserve presence separately from contents: an explicitly empty
             * value must be restored as empty, not converted into absence. */
            if (previous) {
                if (safe_strncpy(gpg_config->previous_gnupg_home, previous,
                                 sizeof(gpg_config->previous_gnupg_home)) != 0) {
                    set_error(ERR_INVALID_PATH,
                              "Existing GNUPGHOME is too long to restore safely");
                    return -1;
                }
                gpg_config->previous_gnupg_home_present = true;
            } else {
                gpg_config->previous_gnupg_home[0] = '\0';
                gpg_config->previous_gnupg_home_present = false;
            }
        }
        if (g_gpg_setenv("GNUPGHOME", gpg_config->gnupg_home, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set GNUPGHOME environment variable");
            return -1;
        }
        gpg_config->environment_installed = true;
        
        log_debug("Set GNUPGHOME environment variable: %s", gpg_config->gnupg_home);
    }
    
    return 0;
}

/* Internal helper functions */

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
 * stdout+stderr. Returns 0 iff the child exits 0. res_out (optional, may be
 * NULL) receives the full run_result_t — callers that parse the capture as
 * evidence must check its out_truncated flag, since a truncated listing is
 * INCOMPLETE, not authoritative (AR-03 L4). */
static int gpg_runv(const gpg_pinned_home_t *home,
                    const gpg_config_t *cfg, run_result_t *res_out,
                    char *output, size_t output_size, va_list ap) {
    const char *argv[24];
    size_t n = 0;
    const char *a;
    run_opts_t opts;
    run_result_t res;
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2];
    int rc;

    while ((a = va_arg(ap, const char *)) != NULL) {
        if (n >= sizeof(argv) / sizeof(argv[0]) - 1) {
            set_error(ERR_INVALID_ARGS, "Too many gpg arguments");
            return -1;
        }
        argv[n++] = a;
    }
    argv[n] = NULL;

    if (home && gpg_validate_pinned_home(home) != 0) {
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = output_size;
    opts.merge_stderr = true;
    if (home) {
        env[0] = "GNUPGHOME=.";
        env[1] = NULL;
        opts.cwd_fd = home->home_fd;
        opts.use_cwd_fd = true;
    } else {
        gpg_build_env(cfg, envbuf, sizeof(envbuf), env);
    }
    if (env[0]) opts.extra_env = env;

    rc = run_argv(argv, &opts, res_out ? res_out : &res);
    if (home && gpg_validate_pinned_home(home) != 0) {
        return -1;
    }
    return rc;
}

static int gpg_run(const gpg_config_t *cfg, run_result_t *res_out,
                   char *output, size_t output_size, ...) {
    va_list ap;
    int rc;

    va_start(ap, output_size);
    rc = gpg_runv(NULL, cfg, res_out, output, output_size, ap);
    va_end(ap);
    return rc;
}

static int gpg_run_pinned(const gpg_pinned_home_t *home,
                          const gpg_config_t *cfg, run_result_t *res_out,
                          char *output, size_t output_size, ...) {
    va_list ap;
    int rc;

    va_start(ap, output_size);
    rc = gpg_runv(home, cfg, res_out, output, output_size, ap);
    va_end(ap);
    return rc;
}

static bool gpg_colon_field(const char *line, size_t line_len, size_t wanted,
                            const char **field, size_t *field_len) {
    const char *start = line;
    size_t index = 0;
    size_t i;

    for (i = 0; i <= line_len; i++) {
        if (i == line_len || line[i] == ':') {
            if (index == wanted) {
                *field = start;
                *field_len = (size_t)(line + i - start);
                return true;
            }
            index++;
            start = line + i + 1;
        }
    }
    return false;
}

static bool gpg_record_is_currently_usable(const char *line, size_t line_len) {
    const char *field;
    size_t field_len;
    time_t now = time(NULL);

    if (!gpg_colon_field(line, line_len, 1, &field, &field_len) ||
        field_len == 0 || strchr("redin?", field[0]) != NULL) {
        return false;
    }
    if (gpg_colon_field(line, line_len, 6, &field, &field_len) &&
        field_len > 0) {
        char expiry[32];
        char *end = NULL;
        unsigned long long value;
        size_t i;

        if (field_len >= sizeof(expiry)) {
            return false;
        }
        for (i = 0; i < field_len; i++) {
            if (!isdigit((unsigned char)field[i])) {
                return false;
            }
        }
        memcpy(expiry, field, field_len);
        expiry[field_len] = '\0';
        errno = 0;
        value = strtoull(expiry, &end, 10);
        if (errno != 0 || !end || *end != '\0' || value == 0 ||
            (now != (time_t)-1 && value <= (unsigned long long)now)) {
            return false;
        }
    }
    if (gpg_colon_field(line, line_len, 11, &field, &field_len) &&
        memchr(field, 'D', field_len) != NULL) {
        return false;
    }
    return true;
}

static bool gpg_record_has_direct_signing(const char *line, size_t line_len) {
    const char *field;
    size_t field_len;

    return gpg_colon_field(line, line_len, 11, &field, &field_len) &&
           memchr(field, 's', field_len) != NULL;
}

static bool gpg_record_has_secret_material(const char *line, size_t line_len) {
    const char *field;
    size_t field_len;
    size_t i;

    if (!gpg_colon_field(line, line_len, 14, &field, &field_len)) {
        return false;
    }
    if (field_len == 1 && field[0] == '+') {
        return true;
    }

    /* Field 15 is either the exact availability marker '+' or a token serial
     * encoded as whole bytes in hexadecimal. '#' is explicitly a simple stub;
     * empty, odd-length, decorated, or non-hex strings are not usable secret
     * material. Substring tests (the old '+'/'>' check) accepted malformed
     * records and rejected real smartcard-backed signing keys. */
    if (field_len == 0 || (field_len % 2) != 0) {
        return false;
    }
    for (i = 0; i < field_len; i++) {
        if (!isxdigit((unsigned char)field[i])) {
            return false;
        }
    }
    return true;
}

int gpg_manager_resolve_secret_key_listing(const char *listing,
                                           bool require_signing,
                                           char *fingerprint,
                                           size_t fingerprint_size) {
    const char *line;
    size_t primary_count = 0;
    bool primary_usable = false;
    bool signing_usable = false;
    bool have_secret_material = false;
    bool awaiting_primary_fingerprint = false;
    bool have_fingerprint = false;

    if (!listing || !fingerprint || fingerprint_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG key-listing arguments");
        return -1;
    }
    fingerprint[0] = '\0';

    for (line = listing; *line; ) {
        const char *eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line) : strlen(line);
        const char *record;
        size_t record_len;

        if (gpg_colon_field(line, line_len, 0, &record, &record_len)) {
            /* The canonical primary fpr immediately follows sec in GnuPG's
             * fixed colon listing.  Never carry this expectation across an
             * intervening uid/ssb/other record: a later subkey fpr must not be
             * accepted as the missing primary fingerprint. */
            if (awaiting_primary_fingerprint &&
                !(record_len == 3 && memcmp(record, "fpr", 3) == 0)) {
                fingerprint[0] = '\0';
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG primary key fingerprint is missing or out of order");
                return -1;
            }
            if (record_len == 3 && memcmp(record, "sec", 3) == 0) {
                primary_count++;
                if (primary_count == 1) {
                    primary_usable =
                        gpg_record_is_currently_usable(line, line_len);
                    signing_usable = primary_usable &&
                        gpg_record_has_direct_signing(line, line_len) &&
                        gpg_record_has_secret_material(line, line_len);
                    have_secret_material =
                        gpg_record_has_secret_material(line, line_len);
                    awaiting_primary_fingerprint = true;
                }
            } else if (record_len == 3 &&
                       memcmp(record, "fpr", 3) == 0 &&
                       primary_count == 1 &&
                       awaiting_primary_fingerprint) {
                const char *value;
                size_t value_len;
                size_t i;

                if (!gpg_colon_field(line, line_len, 9, &value, &value_len) ||
                    (value_len != 40 && value_len != 64) ||
                    value_len + 1 > fingerprint_size) {
                    set_error(ERR_GPG_KEY_FAILED,
                              "GPG primary key has no complete canonical fingerprint");
                    return -1;
                }
                for (i = 0; i < value_len; i++) {
                    if (!isxdigit((unsigned char)value[i])) {
                        set_error(ERR_GPG_KEY_FAILED,
                                  "GPG primary fingerprint is malformed");
                        return -1;
                    }
                    fingerprint[i] =
                        (char)toupper((unsigned char)value[i]);
                }
                fingerprint[value_len] = '\0';
                have_fingerprint = true;
                awaiting_primary_fingerprint = false;
            } else if (record_len == 3 &&
                       memcmp(record, "ssb", 3) == 0 &&
                       primary_count == 1) {
                bool subkey_secret =
                    gpg_record_has_secret_material(line, line_len);
                have_secret_material = have_secret_material || subkey_secret;
                if (primary_usable && subkey_secret &&
                    gpg_record_is_currently_usable(line, line_len) &&
                    gpg_record_has_direct_signing(line, line_len)) {
                    signing_usable = true;
                }
            }
        }
        if (!eol) {
            break;
        }
        line = eol + 1;
    }

    if (primary_count == 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND,
                  "GPG selector resolved no primary secret key");
        return -1;
    }
    if (primary_count != 1) {
        fingerprint[0] = '\0';
        set_error(ERR_GPG_KEY_FAILED,
                  "Ambiguous GPG selector resolved %zu primary secret keys",
                  primary_count);
        return -1;
    }
    if (!have_fingerprint) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG primary key has no canonical fingerprint");
        return -1;
    }
    if (!primary_usable) {
        fingerprint[0] = '\0';
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG primary secret key is revoked, expired, disabled, or unusable");
        return -1;
    }
    if (!have_secret_material) {
        fingerprint[0] = '\0';
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG key inventory contains no usable secret-key material");
        return -1;
    }
    if (require_signing && !signing_usable) {
        fingerprint[0] = '\0';
        set_error(ERR_GPG_SIGNING_FAILED,
                  "GPG key has no currently usable signing-capable secret key");
        return -1;
    }
    return 0;
}

/* Return 0 for one validated key, 1 for an ordinary listing miss, and -1 for
 * incomplete or ambiguous evidence. */
static int gpg_capture_secret_listing(const gpg_config_t *gpg_config,
                                      const gpg_pinned_home_t *home,
                                      const char *source_home,
                                      const char *selector,
                                      bool require_signing,
                                      char *fingerprint,
                                      size_t fingerprint_size) {
    enum { KEY_LISTING_CAP = 512 * 1024 };
    char source_env[MAX_PATH_LEN + sizeof("GNUPGHOME=")];
    const char *env[2] = {NULL, NULL};
    const char *argv[] = {
        "gpg", "--batch", "--with-colons", "--fixed-list-mode",
        "--list-secret-keys", "--fingerprint", "--fingerprint", selector,
        NULL
    };
    char *listing = malloc(KEY_LISTING_CAP);
    int attempt;

    if (!listing) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Failed to allocate GPG key-listing buffer");
        return -1;
    }
    for (attempt = 0; attempt < 2; attempt++) {
        run_result_t res;
        int run_rc;

        memset(&res, 0, sizeof(res));
        if (home) {
            run_rc = gpg_run_pinned(home, gpg_config, &res, listing,
                                    KEY_LISTING_CAP,
                                    "gpg", "--batch", "--with-colons",
                                    "--fixed-list-mode", "--list-secret-keys",
                                    "--fingerprint", "--fingerprint", selector,
                                    (const char *)NULL);
        } else {
            run_opts_t opts;
            memset(&opts, 0, sizeof(opts));
            opts.out = listing;
            opts.out_size = KEY_LISTING_CAP;
            opts.stderr_to_devnull = true;
            if (safe_snprintf(source_env, sizeof(source_env),
                              "GNUPGHOME=%s", source_home) != 0) {
                free(listing);
                set_error(ERR_INVALID_PATH, "GPG source home is too long");
                return -1;
            }
            env[0] = source_env;
            opts.extra_env = env;
            run_rc = run_argv(argv, &opts, &res);
        }
        if (run_rc != 0) {
            secure_zero_memory(listing, KEY_LISTING_CAP);
            free(listing);
            return 1;
        }
        if (!res.out_truncated) {
            int parse_rc = gpg_manager_resolve_secret_key_listing(
                listing, require_signing, fingerprint, fingerprint_size);
            secure_zero_memory(listing, KEY_LISTING_CAP);
            free(listing);
            return parse_rc;
        }
    }
    secure_zero_memory(listing, KEY_LISTING_CAP);
    free(listing);
    set_error(ERR_GPG_KEY_FAILED,
              "GPG secret-key inventory is too large to resolve safely");
    return -1;
}

static int gpg_resolve_source_key(const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size) {
    char source_home[MAX_PATH_LEN];
    int rc;

    if (!selector || !*selector ||
        gpg_user_source_home(source_home, sizeof(source_home)) != 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND,
                  "Cannot resolve GPG selector in the system keyring");
        return -1;
    }
    rc = gpg_capture_secret_listing(NULL, NULL, source_home, selector,
                                    require_signing, fingerprint,
                                    fingerprint_size);
    if (rc == 1) {
        set_error(ERR_GPG_KEY_NOT_FOUND,
                  "GPG selector resolved no secret key: %s", selector);
        return -1;
    }
    return rc;
}

static int gpg_resolve_pinned_key(const gpg_config_t *gpg_config,
                                  const gpg_pinned_home_t *home,
                                  const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size) {
    return gpg_capture_secret_listing(gpg_config, home, NULL, selector,
                                      require_signing, fingerprint,
                                      fingerprint_size);
}

/* Resolve a selector to exactly one canonical fingerprint before exporting
 * any secret material.  The same fingerprint then drives export, post-import
 * validation, capability checks, the availability memo, and Git publication. */
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config,
                                        const gpg_pinned_home_t *home,
                                        const char *selector,
                                        bool require_signing,
                                        char *fingerprint,
                                        size_t fingerprint_size) {
    /* Generous heap capacity for the armored export: a multi-subkey RSA-4096
     * key armors to ~15 KB and photo-ID-bearing keys to far more, so the old
     * fixed 8 KB stack buffer routinely truncated real keys — and run_argv's
     * silent cap then fed the corrupt armor straight to `gpg --import`
     * (AR-02 #4). Truncation is detected and refused explicitly below. */
    enum { KEY_DATA_CAP = 512 * 1024 };
    char import_diag[1024];
    const char *env[2] = {"GNUPGHOME=.", NULL};
    char *key_data;
    char imported_fingerprint[GPG_FINGERPRINT_BUFSIZE];
    run_opts_t opts;
    run_result_t res;
    int present_rc;

    if (!gpg_config || !home || !selector || !*selector || !fingerprint ||
        fingerprint_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_key_from_system_keyring");
        return -1;
    }
    fingerprint[0] = '\0';

    log_debug("Copying GPG key from system keyring: %s", selector);

    /* Idempotency: if the secret key is already present in the isolated home
     * (e.g. switching back to an account whose home persists from an earlier
     * switch), skip the export/import. The export step prompts the system
     * agent's PIN, so skipping it avoids a PIN prompt on every switch. The
     * probe asks with --with-colons so its output doubles as the caller's
     * signing-capability evidence (AR-02 #14). */
    present_rc = gpg_resolve_pinned_key(gpg_config, home, selector,
                                        require_signing, fingerprint,
                                        fingerprint_size);
    if (present_rc == 0) {
        log_debug("Secret key already present in isolated home; skipping import: %s",
                  fingerprint);
        gpg_manager_note_key_available(fingerprint);
        return 0;
    }
    if (present_rc < 0) {
        return -1;
    }
    /* A listing miss is an ordinary first-import case; a changed public
     * namespace is not. Refuse before exporting any secret material. */
    if (gpg_validate_pinned_home(home) != 0) {
        return -1;
    }

    if (gpg_resolve_source_key(selector, require_signing, fingerprint,
                               fingerprint_size) != 0) {
        return -1;
    }

    key_data = malloc(KEY_DATA_CAP);
    if (!key_data) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate GPG export buffer");
        return -1;
    }

    /* Export the secret key from the SYSTEM keyring. GNUPGHOME is overridden to
     * the user's REAL keyring home (AR-06 F05/F06): `gitswitch init` exports
     * GNUPGHOME=<base>/current into interactive shells, and a bare export would
     * inherit that managed value and read the previously-active account's
     * isolated home — where a different account's key does not exist — failing
     * closed with a misleading "key not found". gpg_user_source_home() rejects a
     * managed GNUPGHOME and falls back to $HOME/.gnupg.
     * key_data now holds unencrypted armored private-key material, so every
     * exit below must scrub it (secure_zero_memory) before freeing — a plain
     * free would leave the key in heap memory for a later allocation, core
     * dump, or memory-disclosure bug to recover. (The same bytes also transit
     * run_argv_real's read buffer; that copy is scrubbed there — AR-02 #25 —
     * so this scrub genuinely closes the exposure rather than half of it.)
     * Export stderr stays discarded: stdout IS the key, so merging would
     * corrupt it. */
    {
        const char *export_argv[] = {"gpg", "--armor", "--export-secret-keys",
                                     fingerprint, NULL};
        char source_home[MAX_PATH_LEN];
        char source_env_str[MAX_PATH_LEN + sizeof("GNUPGHOME=")];
        const char *export_env[2] = {NULL, NULL};
        memset(&opts, 0, sizeof(opts));
        opts.out = key_data;
        opts.out_size = KEY_DATA_CAP;
        opts.stderr_to_devnull = true;
        if (gpg_user_source_home(source_home, sizeof(source_home)) == 0) {
            snprintf(source_env_str, sizeof(source_env_str), "GNUPGHOME=%s", source_home);
            export_env[0] = source_env_str;
            opts.extra_env = export_env;
        }
        if (run_argv(export_argv, &opts, &res) != 0 || res.out_len == 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            set_error(ERR_GPG_KEY_NOT_FOUND, "Failed to export GPG key from system keyring");
            return -1;
        }
        /* An incomplete armor must never reach the import: gpg would reject
         * it ('Invalid packet', zero keys processed) and the whole switch
         * would abort with a misleading key-not-found error (AR-02 #4). */
        if (res.out_truncated) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key export for %s exceeds %d bytes; refusing to "
                      "import a truncated key", fingerprint,
                      (int)KEY_DATA_CAP);
            return -1;
        }
    }

    /* The system export can block on pinentry. Re-check the public namespace
     * before handing those now-decrypted bytes to an import process. */
    if (gpg_validate_pinned_home(home) != 0) {
        secure_zero_memory(key_data, KEY_DATA_CAP);
        free(key_data);
        return -1;
    }

    /* Import into the isolated GNUPGHOME by feeding the key on stdin. Capture
     * merged stdout+stderr so a failure surfaces gpg's real diagnostic
     * instead of a generic message with the cause thrown away (AR-02 #4). */
    {
        const char *import_argv[] = {"gpg", "--batch", "--import", NULL};
        int import_rc;
        memset(&opts, 0, sizeof(opts));
        opts.input = key_data;
        opts.input_len = res.out_len;
        opts.out = import_diag;
        opts.out_size = sizeof(import_diag);
        opts.merge_stderr = true;
        opts.extra_env = env;
        opts.cwd_fd = home->home_fd;
        opts.use_cwd_fd = true;
        import_rc = run_argv(import_argv, &opts, NULL);
        if (gpg_validate_pinned_home(home) != 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            return -1;
        }
        if (import_rc != 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            set_error(ERR_GPG_KEY_FAILED,
                      "Failed to import GPG key into isolated environment: %s",
                      import_diag);
            return -1;
        }
    }

    secure_zero_memory(key_data, KEY_DATA_CAP);
    free(key_data);
    if (gpg_resolve_pinned_key(gpg_config, home, fingerprint,
                               require_signing, imported_fingerprint,
                               sizeof(imported_fingerprint)) != 0 ||
        strcmp(imported_fingerprint, fingerprint) != 0) {
        set_error(ERR_GPG_KEY_FAILED,
                  "Imported GPG key did not validate as fingerprint %s",
                  fingerprint);
        return -1;
    }
    log_info("Successfully copied GPG key to isolated environment: %s",
             fingerprint);
    gpg_manager_note_key_available(fingerprint);
    return 0;
}

enum { GPG_AGENT_CONF_MAX = 64 * 1024 };

static bool conf_bytes_have_pinentry(const unsigned char *bytes, size_t len) {
    size_t offset = 0;

    while (offset < len) {
        size_t line_end = offset;
        size_t p;
        while (line_end < len && bytes[line_end] != '\n') line_end++;
        p = offset;
        while (p < line_end && (bytes[p] == ' ' || bytes[p] == '\t')) p++;
        if (line_end - p >= 16 &&
            memcmp(bytes + p, "pinentry-program", 16) == 0 &&
            (line_end - p == 16 || bytes[p + 16] == ' ' ||
             bytes[p + 16] == '\t' || bytes[p + 16] == '\r')) {
            return true;
        }
        offset = line_end < len ? line_end + 1 : len;
    }
    return false;
}

static int read_conf_fd(int source_fd, unsigned char *dest, size_t capacity,
                        size_t *bytes_out) {
    size_t total = 0;
    ssize_t n;

    if (source_fd < 0 || !dest || capacity < GPG_AGENT_CONF_MAX ||
        !bytes_out) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        size_t available = GPG_AGENT_CONF_MAX - total;
        if (available == 0) {
            unsigned char extra;
            n = read(source_fd, &extra, 1);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) return -1;
            if (n > 0) {
                errno = EFBIG;
                return -1;
            }
            break;
        }
        n = read(source_fd, dest + total, available);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (n == 0) break;
        total += (size_t)n;
    }
    *bytes_out = total;
    return 0;
}

static int append_conf_bytes(unsigned char *dest, size_t capacity,
                             size_t *used, const void *source, size_t count) {
    if (!dest || !used || !source || *used > capacity ||
        count > capacity - *used) {
        errno = EOVERFLOW;
        return -1;
    }
    memcpy(dest + *used, source, count);
    *used += count;
    return 0;
}

/* Return 1 only for a byte-identical, private regular destination; 0 means a
 * safe atomic replacement is needed, and -1 means comparison raced or failed.
 * The match path opens no write descriptor and performs no fsync or rename. */
static int gpg_agent_conf_matches(int home_fd, const unsigned char *desired,
                                  size_t desired_len) {
    struct stat before;
    struct stat opened;
    struct stat after;
    unsigned char buf[4096];
    size_t offset = 0;
    int fd;
    int result = 0;

    if (fstatat(home_fd, "gpg-agent.conf", &before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 0;
        set_system_error(ERR_FILE_IO,
                         "Failed to inspect installed gpg-agent.conf");
        return -1;
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
        before.st_nlink != 1 || (before.st_mode & 0777) != 0600) {
        return 0;
    }
    fd = openat(home_fd, "gpg-agent.conf",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !gpg_same_file_version(&before, &opened) ||
        opened.st_nlink != 1 || !S_ISREG(opened.st_mode)) {
        if (fd >= 0) close(fd);
        set_error(ERR_FILE_IO,
                  "Installed gpg-agent.conf changed while opening");
        return -1;
    }
    if ((uintmax_t)opened.st_size == (uintmax_t)desired_len) {
        result = 1;
        while (offset < desired_len) {
            size_t want = desired_len - offset;
            ssize_t n;
            if (want > sizeof(buf)) want = sizeof(buf);
            n = read(fd, buf, want);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || memcmp(buf, desired + offset, (size_t)n) != 0) {
                result = n < 0 ? -1 : 0;
                break;
            }
            offset += (size_t)n;
        }
        if (result == 1) {
            unsigned char extra;
            ssize_t n;
            do {
                n = read(fd, &extra, 1);
            } while (n < 0 && errno == EINTR);
            if (n != 0) result = n < 0 ? -1 : 0;
        }
    }
    if (fstat(fd, &after) != 0 ||
        fstatat(home_fd, "gpg-agent.conf", &before,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(&opened, &after) ||
        !gpg_same_file_version(&opened, &before) ||
        after.st_nlink != 1 || before.st_nlink != 1) {
        result = -1;
    }
    if (close(fd) != 0) result = -1;
    if (result < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to compare installed gpg-agent.conf safely");
    }
    return result;
}

static int gpg_write_all(int fd, const unsigned char *bytes, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = write(fd, bytes + offset, len - offset);
        if (n > 0) {
            offset += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int gpg_normalize_path(const char *input, char *output,
                              size_t output_size) {
    char absolute[MAX_PATH_LEN];
    char component[MAX_PATH_LEN];
    size_t component_len = 0;
    size_t output_len = 1;
    const char *p;

    if (!input || !*input || !output || output_size < 2) {
        return -1;
    }
    if (input[0] == '/') {
        if (safe_strncpy(absolute, input, sizeof(absolute)) != 0) {
            return -1;
        }
    } else {
        char cwd[MAX_PATH_LEN];
        if (!getcwd(cwd, sizeof(cwd)) ||
            safe_snprintf(absolute, sizeof(absolute), "%s/%s", cwd, input) != 0) {
            return -1;
        }
    }

    output[0] = '/';
    output[1] = '\0';
    for (p = absolute + 1; ; p++) {
        if (*p != '/' && *p != '\0') {
            if (component_len + 1 >= sizeof(component)) {
                return -1;
            }
            component[component_len++] = *p;
            continue;
        }
        component[component_len] = '\0';
        if (component_len > 0 && strcmp(component, ".") != 0) {
            if (strcmp(component, "..") == 0) {
                if (output_len > 1) {
                    char *slash;
                    output[output_len] = '\0';
                    slash = strrchr(output, '/');
                    output_len = slash == output ? 1 : (size_t)(slash - output);
                    output[output_len] = '\0';
                }
            } else {
                size_t needed = component_len + (output_len > 1 ? 1 : 0);
                if (output_len + needed >= output_size) {
                    return -1;
                }
                if (output_len > 1) {
                    output[output_len++] = '/';
                }
                memcpy(output + output_len, component, component_len);
                output_len += component_len;
                output[output_len] = '\0';
            }
        }
        component_len = 0;
        if (*p == '\0') {
            break;
        }
    }
    return 0;
}

/* Resolve every existing symlink component while preserving a lexical suffix
 * once the first nonexistent component is reached.  Unlike realpath(), this
 * still exposes a dangling alias such as /external/home -> <base>/current,
 * which must be classified as managed before a later switch makes its target
 * exist.  The resolved spelling is also what the child receives, so a mutable
 * external alias is not re-followed after the classification decision. */
static int gpg_resolve_path_aliases(const char *input, char *output,
                                    size_t output_size) {
    char work[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN] = "/";
    char probe[MAX_PATH_LEN];
    char target[MAX_PATH_LEN];
    char rebound[MAX_PATH_LEN];
    const char *cursor;
    unsigned int symlink_hops = 0;

    if (!output || output_size == 0 ||
        gpg_normalize_path(input, work, sizeof(work)) != 0) {
        return -1;
    }
    cursor = work + 1;
    for (;;) {
        const char *end;
        const char *tail;
        size_t component_len;
        struct stat before;

        while (*cursor == '/') cursor++;
        if (*cursor == '\0') {
            return safe_strncpy(output, resolved, output_size);
        }
        end = strchr(cursor, '/');
        component_len = end ? (size_t)(end - cursor) : strlen(cursor);
        if (component_len == 0 ||
            (strcmp(resolved, "/") == 0
                 ? safe_snprintf(probe, sizeof(probe), "/%.*s",
                                 (int)component_len, cursor)
                 : safe_snprintf(probe, sizeof(probe), "%s/%.*s", resolved,
                                 (int)component_len, cursor)) != 0) {
            return -1;
        }
        tail = end ? end : "";
        if (lstat(probe, &before) != 0) {
            if (errno != ENOENT ||
                safe_snprintf(rebound, sizeof(rebound), "%s%s", probe,
                              tail) != 0) {
                return -1;
            }
            return gpg_normalize_path(rebound, output, output_size);
        }
        if (S_ISLNK(before.st_mode)) {
            struct stat after;
            ssize_t n;
            int read_error;

            if (++symlink_hops > 40) {
                errno = ELOOP;
                return -1;
            }
            /* Classification-only read: lstat identity is rechecked below;
             * bounds, truncation, and termination are handled explicitly. */
            n = readlink(probe, target, sizeof(target) - 1); /* Flawfinder: ignore */
            read_error = errno;
            if (lstat(probe, &after) != 0 ||
                before.st_dev != after.st_dev ||
                before.st_ino != after.st_ino ||
                before.st_uid != after.st_uid ||
                before.st_size != after.st_size ||
                !S_ISLNK(after.st_mode)) {
                return -1;
            }
            if (n <= 0 || (size_t)n >= sizeof(target) - 1) {
                errno = read_error;
                return -1;
            }
            target[n] = '\0';
            if ((target[0] == '/' &&
                 safe_snprintf(rebound, sizeof(rebound), "%s%s", target,
                               tail) != 0) ||
                (target[0] != '/' && strcmp(resolved, "/") == 0 &&
                 safe_snprintf(rebound, sizeof(rebound), "/%s%s", target,
                               tail) != 0) ||
                (target[0] != '/' && strcmp(resolved, "/") != 0 &&
                 safe_snprintf(rebound, sizeof(rebound), "%s/%s%s", resolved,
                               target, tail) != 0) ||
                gpg_normalize_path(rebound, work, sizeof(work)) != 0) {
                return -1;
            }
            safe_strncpy(resolved, "/", sizeof(resolved));
            cursor = work + 1;
            continue;
        }
        if (safe_strncpy(resolved, probe, sizeof(resolved)) != 0) {
            return -1;
        }
        cursor = end ? end + 1 : cursor + component_len;
    }
}

static bool gpg_path_is_managed(const char *base, const char *candidate) {
    char current[MAX_PATH_LEN];

    return strcmp(base, candidate) == 0 ||
           (gpg_current_path_from_base(base, current, sizeof(current)) == 0 &&
            strcmp(current, candidate) == 0) ||
           gpg_target_is_managed_child(base, candidate);
}

static bool gpg_source_path_is_managed(const char *candidate,
                                       char *resolved_out,
                                       size_t resolved_out_size) {
    char base[MAX_PATH_LEN];
    char normalized_base[MAX_PATH_LEN];
    char normalized_candidate[MAX_PATH_LEN];
    char resolved_base[MAX_PATH_LEN];
    char resolved_candidate[MAX_PATH_LEN];

    if (!resolved_out || resolved_out_size == 0 ||
        gpg_get_base_dir(base, sizeof(base)) != 0 ||
        gpg_normalize_path(base, normalized_base, sizeof(normalized_base)) != 0 ||
        gpg_normalize_path(candidate, normalized_candidate,
                           sizeof(normalized_candidate)) != 0) {
        return true; /* classification uncertainty fails closed */
    }
    if (gpg_path_is_managed(normalized_base, normalized_candidate)) {
        return true;
    }

    /* Resolve aliases even when their final targets do not exist yet.  Any
     * uncertainty fails closed instead of letting an alias become managed
     * between classification and the GPG child spawn. */
    if (gpg_resolve_path_aliases(normalized_base, resolved_base,
                                 sizeof(resolved_base)) != 0 ||
        gpg_resolve_path_aliases(normalized_candidate, resolved_candidate,
                                 sizeof(resolved_candidate)) != 0) {
        return true;
    }
    if (gpg_path_is_managed(resolved_base, resolved_candidate)) return true;
    if (safe_strncpy(resolved_out, resolved_candidate,
                     resolved_out_size) != 0) return true;
    return false;
}

/* Resolve the user's real gpg home to inherit agent settings from: their
 * configured GNUPGHOME when it isn't one of our isolated homes (avoids reading
 * our own generated conf), otherwise ~/.gnupg. Returns 0 on success. */
static int gpg_user_source_home(char *buf, size_t size) {
    const char *env_gh = getenv("GNUPGHOME");
    const char *home;
    char fallback[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];

    if (env_gh && *env_gh &&
        !gpg_source_path_is_managed(env_gh, resolved, sizeof(resolved))) {
        return safe_strncpy(buf, resolved, size);
    }
    home = getenv("HOME");
    if (!home || !*home) {
        return -1;
    }
    if (safe_snprintf(fallback, sizeof(fallback), "%s/.gnupg", home) != 0 ||
        gpg_source_path_is_managed(fallback, resolved, sizeof(resolved))) {
        set_error(ERR_INVALID_PATH,
                  "Refusing managed or unresolvable HOME/.gnupg as a system keyring");
        return -1;
    }
    return safe_strncpy(buf, resolved, size);
}

/* Public wrapper (AR-06 F05/F06): callers outside this TU (accounts.c's
 * system-keyring availability probe) need the same real-home resolution the
 * export path uses, so they can override an inherited managed GNUPGHOME. */
int gpg_manager_system_keyring_home(char *buf, size_t size) {
    if (!buf || size == 0) {
        return -1;
    }
    return gpg_user_source_home(buf, size);
}

/* Set up gpg-agent.conf for the isolated environment.
 *
 * Inherits the user's real gpg-agent.conf (their pinentry choice — e.g. a GUI
 * pinentry — plus cache settings) so isolation never silently downgrades their
 * pinentry. Only when the user has no config of their own do we write minimal
 * defaults, and a *detected* pinentry is appended only if none is already set
 * (the compiled-in default can be wrong, e.g. on FreeBSD). Re-run each switch,
 * so edits to the user's real config propagate. */
static int setup_gpg_agent_config(int home_fd, const char *gnupg_home) {
    static const char default_conf[] =
        "# GPG Agent configuration for gitswitch isolated environment\n"
        "default-cache-ttl 3600\n"
        "max-cache-ttl 7200\n";
    enum {
        GPG_AGENT_CONF_DESIRED_MAX =
            GPG_AGENT_CONF_MAX + MAX_PATH_LEN + 64
    };
    char gpg_agent_conf_path[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN] = "";
    char temp_name[64] = "";
    char suffix[13];
    char source_home[MAX_PATH_LEN];
    char source_conf[MAX_PATH_LEN];
    unsigned char *desired = NULL;
    size_t desired_len = 0;
    bool inherited = false;
    struct stat created;
    struct stat fd_now;
    struct stat entry;
    bool have_created_identity = false;
    bool installed = false;
    int source_fd = -1;
    int fd = -1;
    int match;
    
    if (home_fd < 0 || !gnupg_home) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent config destination");
        return -1;
    }
    if (safe_snprintf(gpg_agent_conf_path, sizeof(gpg_agent_conf_path),
                      "%s/gpg-agent.conf", gnupg_home) != 0) {
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        return -1;
    }

    desired = malloc(GPG_AGENT_CONF_DESIRED_MAX);
    if (!desired) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Failed to allocate desired gpg-agent.conf");
        return -1;
    }

    /* Compose the exact desired bytes in memory before creating any scratch
     * file. This is what makes the byte-identical path genuinely zero-write. */
    if (gpg_user_source_home(source_home, sizeof(source_home)) == 0 &&
        safe_snprintf(source_conf, sizeof(source_conf),
                      "%s/gpg-agent.conf", source_home) == 0) {
        struct stat before;
        struct stat opened;
        struct stat after;
        if (lstat(source_conf, &before) == 0) {
            if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
                before.st_nlink != 1 || (before.st_mode & 022) != 0) {
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing unsafe inherited gpg-agent.conf: %s",
                          source_conf);
                goto fail;
            }
            if (g_agent_conf_preopen) g_agent_conf_preopen(source_conf);
            source_fd = open(source_conf,
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (source_fd < 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed to open inherited gpg-agent.conf safely: %s",
                                 source_conf);
                goto fail;
            }
            if (fstat(source_fd, &opened) != 0 ||
                !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
                opened.st_nlink != 1 || (opened.st_mode & 022) != 0 ||
                !gpg_same_file_version(&before, &opened)) {
                set_error(ERR_PERMISSION_DENIED,
                          "Inherited gpg-agent.conf changed to an unsafe file: %s",
                          source_conf);
                goto fail;
            }
            if (read_conf_fd(source_fd, desired,
                             GPG_AGENT_CONF_DESIRED_MAX,
                             &desired_len) != 0) {
                if (errno == EFBIG) {
                    set_error(ERR_FILE_IO,
                              "Inherited gpg-agent.conf exceeds %d bytes: %s",
                              GPG_AGENT_CONF_MAX, source_conf);
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to inherit gpg-agent.conf: %s",
                                     source_conf);
                }
                goto fail;
            }
            if (lstat(source_conf, &after) != 0 ||
                !gpg_same_file_version(&opened, &after) ||
                !S_ISREG(after.st_mode) || after.st_uid != getuid() ||
                after.st_nlink != 1 || (after.st_mode & 022) != 0) {
                set_error(ERR_FILE_IO,
                          "Inherited gpg-agent.conf changed while being read: %s",
                          source_conf);
                goto fail;
            }
            if (close(source_fd) != 0) {
                source_fd = -1;
                set_system_error(ERR_FILE_IO,
                                 "Failed to close inherited gpg-agent.conf: %s",
                                 source_conf);
                goto fail;
            }
            source_fd = -1;
            inherited = true;
            log_debug("Inherited gpg-agent.conf from %s", source_conf);
        } else if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Failed to inspect inherited gpg-agent.conf: %s",
                             source_conf);
            goto fail;
        }
    }

    if (!inherited &&
        append_conf_bytes(desired, GPG_AGENT_CONF_DESIRED_MAX,
                          &desired_len, default_conf,
                          sizeof(default_conf) - 1) != 0) {
        set_error(ERR_FILE_IO, "Failed to compose gpg-agent.conf defaults");
        goto fail;
    }

    if (!conf_bytes_have_pinentry(desired, desired_len)) {
        static const char *const pinentry_candidates[] = {
            "pinentry", "pinentry-curses", "pinentry-mac", "pinentry-tty"
        };
        char pinentry_path[MAX_PATH_LEN];
        for (size_t i = 0;
             i < sizeof(pinentry_candidates) / sizeof(pinentry_candidates[0]);
             i++) {
            if (find_command_path(pinentry_candidates[i], pinentry_path,
                                  sizeof(pinentry_path)) == 0) {
                char directive[MAX_PATH_LEN + 32];
                int written;
                if (inherited && desired_len > 0 &&
                    desired[desired_len - 1] != '\n' &&
                    append_conf_bytes(desired, GPG_AGENT_CONF_DESIRED_MAX,
                                      &desired_len, "\n", 1) != 0) {
                    set_error(ERR_FILE_IO,
                              "Failed to delimit inherited gpg-agent.conf");
                    goto fail;
                }
                written = snprintf(directive, sizeof(directive),
                                   "pinentry-program %s\n", pinentry_path);
                if (written < 0 || (size_t)written >= sizeof(directive) ||
                    append_conf_bytes(desired, GPG_AGENT_CONF_DESIRED_MAX,
                                      &desired_len, directive,
                                      (size_t)written) != 0) {
                    set_error(ERR_FILE_IO,
                              "Failed to append pinentry to gpg-agent.conf");
                    goto fail;
                }
                break;
            }
        }
    }

    match = gpg_agent_conf_matches(home_fd, desired, desired_len);
    if (match < 0) goto fail;
    if (match > 0) {
        free(desired);
        log_debug("Reused unchanged GPG agent configuration: %s",
                  gpg_agent_conf_path);
        return 0;
    }

    /* Build the replacement relative to the already-pinned home descriptor.
     * The random O_EXCL name preserves mkstemp's collision properties without
     * ever resolving the public GNUPGHOME pathname for a write. */
    for (int attempt = 0; attempt < 16; attempt++) {
        if (generate_random_string(suffix, sizeof(suffix),
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "0123456789") != 0 ||
            safe_snprintf(temp_name, sizeof(temp_name),
                          ".gpg-agent.conf.gitswitch.%s", suffix) != 0) {
            goto fail;
        }
        fd = openat(home_fd, temp_name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to create temporary gpg-agent.conf");
        goto fail;
    }
    if (fstat(fd, &created) != 0 || !S_ISREG(created.st_mode) ||
        created.st_uid != getuid() || created.st_nlink != 1 ||
        (created.st_mode & 0777) != 0600) {
        set_error(ERR_PERMISSION_DENIED,
                  "Temporary gpg-agent.conf is not the private file just created");
        goto fail;
    }
    have_created_identity = true;
    if (fchmod(fd, 0600) != 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to secure temporary gpg-agent.conf");
        goto fail;
    }
    if (safe_snprintf(temp_path, sizeof(temp_path), "%s/%s",
                      gnupg_home, temp_name) != 0) {
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        goto fail;
    }
    (void)signals_scratch_register(temp_path);
    if (gpg_write_all(fd, desired, desired_len) != 0 ||
        g_agent_conf_sync(fd, false) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to flush temporary gpg-agent.conf");
        goto fail;
    }
    if (g_agent_conf_precommit &&
        g_agent_conf_precommit(home_fd, temp_name) != 0) {
        set_error(ERR_FILE_IO, "GPG agent config pre-commit hook failed");
        goto fail;
    }

    /* Keep the stream's descriptor open and prove immediately before rename
     * that the random temp pathname still names the exact inode we populated.
     * O_EXCL prevents an initial collision, but a same-uid process can unlink
     * and replace that pathname while the file is being prepared. */
    if (fstat(fd, &fd_now) != 0 ||
        fstatat(home_fd, temp_name, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        fd_now.st_dev != created.st_dev || fd_now.st_ino != created.st_ino ||
        entry.st_dev != created.st_dev || entry.st_ino != created.st_ino ||
        !S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        fd_now.st_nlink != 1 || entry.st_nlink != 1 ||
        (entry.st_mode & 0777) != 0600) {
        set_error(ERR_FILE_IO,
                  "Temporary gpg-agent.conf changed before atomic commit");
        goto fail;
    }
    if (renameat(home_fd, temp_name, home_fd, "gpg-agent.conf") != 0) {
        set_system_error(ERR_FILE_IO, "Failed to install gpg-agent.conf atomically");
        goto fail;
    }
    installed = true;
    signals_scratch_unregister(temp_path);
    if (fstatat(home_fd, "gpg-agent.conf", &entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        entry.st_dev != created.st_dev || entry.st_ino != created.st_ino ||
        !S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        entry.st_nlink != 1 || (entry.st_mode & 0777) != 0600) {
        set_error(ERR_FILE_IO,
                  "gpg-agent.conf changed during atomic commit");
        goto fail;
    }
    if (g_agent_conf_sync(home_fd, true) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to synchronize installed gpg-agent.conf");
        goto fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        free(desired);
        set_system_error(ERR_FILE_IO,
                         "Failed to close installed gpg-agent.conf");
        return -1;
    }
    fd = -1;

    free(desired);
    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;

fail:
    if (source_fd >= 0) close(source_fd);
    if (fd >= 0) close(fd);
    /* A failed commit must never delete a pathname another process substituted.
     * Remove only names which still resolve to the inode created above. */
    if (!installed && have_created_identity && temp_name[0] &&
        fstatat(home_fd, temp_name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        entry.st_dev == created.st_dev && entry.st_ino == created.st_ino) {
        (void)unlinkat(home_fd, temp_name, 0);
    }
    if (temp_path[0]) signals_scratch_unregister(temp_path);
    free(desired);
    return -1;
}

int gpg_manager_setup_agent_config_for_test(int home_fd,
                                            const char *gnupg_home) {
    return setup_gpg_agent_config(home_fd, gnupg_home);
}
