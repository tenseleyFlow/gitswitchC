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
#ifdef __linux__
#include <sys/vfs.h>
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
static int gpg_retarget_current_locked(int base_fd, const char *base,
                                       const char *real_home);
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
                                        const char *key_id,
                                        char *colons, size_t colons_size,
                                        bool *colons_valid);
static int setup_gpg_agent_config(int home_fd, const char *gnupg_home);
static int gpg_prepare_isolated_home_at(gpg_config_t *gpg_config,
                                        const account_t *account,
                                        int base_fd, const char *base,
                                        int *home_fd_out);
static int gpg_validate_pinned_home(const gpg_pinned_home_t *home);
static int gpg_user_source_home(char *buf, size_t size);
static int gpg_validate_key_pinned(gpg_config_t *gpg_config,
                                   const gpg_pinned_home_t *home,
                                   const char *key_id);
static int gpg_test_signing_pinned(gpg_config_t *gpg_config,
                                   const gpg_pinned_home_t *home,
                                   const char *key_id);
static int gpg_open_base_dir(char *base, size_t size, bool create,
                             bool *absent);
static int lock_gpg_dir(int base_fd);
static void unlock_gpg_dir(int base_fd, int lock_fd);

static gpg_readdir_fn g_gpg_readdir = readdir;
static gpg_agent_conf_preopen_fn g_agent_conf_preopen;
static gpg_agent_conf_precommit_fn g_agent_conf_precommit;
static gpg_retarget_commit_hook_fn g_retarget_commit_hook;

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
static char g_seen_keys[GPG_SEEN_KEYS_MAX][MAX_KEY_ID_LEN];
static size_t g_seen_key_count;

void gpg_manager_note_key_available(const char *key_id) {
    if (!key_id || !*key_id || strlen(key_id) >= MAX_KEY_ID_LEN ||
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
    char colons[4096];
    char locked_base[MAX_PATH_LEN] = "";
    bool colons_valid = false;
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

            /* Copy key from system keyring to isolated environment. On success
             * the key is provably present in the isolated home (the copy step
             * either found it already there or imported it), so we skip the
             * follow-up validation — it would just re-run the same
             * `gpg --list-secret-keys`, spawning another gpg (and agent). Only
             * when the copy fails do we validate, to see if a prior switch
             * already left the key in the isolated home. On the already-
             * present path the probe's colons listing is kept so the signing
             * test below needs no spawn of its own (AR-02 #14). */
            if (copy_key_from_system_keyring(gpg_config, &pinned_home,
                                             account->gpg_key_id,
                                             colons, sizeof(colons),
                                             &colons_valid) != 0) {
                log_warning("Failed to copy GPG key to isolated environment: %s",
                           get_last_error()->message);
                if (gpg_validate_key_pinned(gpg_config, &pinned_home,
                                            account->gpg_key_id) != 0) {
                    set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available in isolated environment: %s",
                             account->gpg_key_id);
                    goto out;
                }
            }
            break;
        }

        case GPG_MODE_SHARED:
            /* Validate key exists and switch to it */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", account->gpg_key_id);
                goto out;
            }
            break;

        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", gpg_config->mode);
            goto out;
    }

    /* Test GPG signing if enabled. When the idempotency probe above already
     * captured this key's colons listing, answer from it — gpg_test_signing
     * would spawn gpg only to re-run the identical listing (AR-02 #14). */
    if (account->gpg_signing_enabled) {
        int sign_rc;
        if (colons_valid) {
            sign_rc = gpg_colons_have_sign_capability(colons) ? 0 : -1;
        } else if (gpg_config->mode == GPG_MODE_ISOLATED) {
            sign_rc = gpg_test_signing_pinned(gpg_config, &pinned_home,
                                              account->gpg_key_id);
        } else {
            sign_rc = gpg_test_signing(gpg_config, account->gpg_key_id);
        }
        if (sign_rc != 0) {
            log_warning("GPG signing test failed for key: %s", account->gpg_key_id);
            /* Don't fail completely, just warn */
        } else {
            log_info("GPG signing test passed for key: %s", account->gpg_key_id);
        }
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
                                        gpg_config->gnupg_home) != 0) {
            set_error(ERR_GPG_KEY_FAILED,
                      "Failed to install stable GNUPGHOME for account: %s",
                      account->name);
            goto out;
        }
    }

    /* Only publish the selected key/configuration after the runtime entry
     * point has committed. A failed retarget must not leave an in-memory or
     * process-environment claim that the rejected account is active. */
    safe_strncpy(gpg_config->current_key_id, account->gpg_key_id,
                 sizeof(gpg_config->current_key_id));
    gpg_config->signing_enabled = account->gpg_signing_enabled;
    if (gpg_config->mode == GPG_MODE_ISOLATED) {
        if (gpg_set_environment(gpg_config) != 0) {
            log_warning("Failed to set GPG environment variable: %s", get_last_error()->message);
        }
    }

    log_info("Successfully switched to GPG configuration for account: %s", account->name);
    rc = 0;

out:
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

static void unlock_gpg_dir(int base_fd, int lock_fd) {
    if (lock_fd >= 0) unlock_private_file(lock_fd);
    if (base_fd >= 0) close(base_fd);
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

/* Validate an existing base before taking its lock, then verify that the path
 * still names the same private directory after the lock is held. Return 1 for
 * an absent base, 0 with a held lock, and -1 for every unsafe/unknown state. */
static int gpg_lock_private_base(const char *base, int *base_fd_out,
                                 int *lock_out) {
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
    lock_fd = lock_gpg_dir(base_fd);
    if (lock_fd < 0) {
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

/* Core of the `current` retarget; the CALLER must hold the base dir's lock.
 * Re-checks that the target home still exists (is a real directory) before
 * installing the link (AR-03 L12): the home was validated when it was
 * created/imported, but a reset — a concurrent one before the create+import
 * lock existed, or simply an earlier `gitswitch reset` on the rollback path —
 * may have remove_tree'd it since. Installing the link anyway would point
 * every `gitswitch init` shell at a missing keyring while the switch reports
 * success; fail closed and leave the link alone instead. */
/* AR-06 F41: revert a failed retarget without destroying the previous entry
 * point. The atomic rename already replaced `current`, so a bare unlink would
 * leave every GNUPGHOME=<base>/current shell dangling while the caller (seeing
 * failure with gpg_dirty=false) never restores it. Instead, when `current` is
 * still the exact link this call installed, put back the target that was there
 * before the retarget (or drop it if there was none). dev/ino-guarded so a
 * racing same-uid writer's replacement is never clobbered. */
static void gpg_revert_retarget(int base_fd, const struct stat *installed,
                                bool prev_existed, const char *prev_target) {
    struct stat now;

    if (fstatat(base_fd, "current", &now, AT_SYMLINK_NOFOLLOW) != 0 ||
        now.st_dev != installed->st_dev || now.st_ino != installed->st_ino ||
        !S_ISLNK(now.st_mode)) {
        return; /* someone else owns `current` now; leave their state */
    }
    if (prev_existed) {
        (void)atomic_symlink_at(base_fd, prev_target, "current");
    } else {
        (void)unlinkat(base_fd, "current", 0);
    }
}

static int gpg_retarget_current_locked(int base_fd, const char *base,
                                       const char *real_home) {
    char link_path[MAX_PATH_LEN];
    char committed_target[MAX_PATH_LEN];
    char prev_target[MAX_PATH_LEN];
    struct stat committed;
    bool prev_existed;
    int live_rc;

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

    /* Capture the target `current` names right now, before the atomic rename
     * overwrites it, so a failed retarget can restore it (AR-06 F41). A
     * malformed/absent link means there is nothing to restore. */
    prev_existed = (gpg_read_current_locked(base_fd, base, prev_target,
                                            sizeof(prev_target)) == 0);

    /* Atomically retarget (temp symlink + rename) so a follower never sees a
     * missing or half-updated link. */
    if (atomic_symlink_at(base_fd, real_home, "current") != 0) {
        log_warning("Failed to create GNUPGHOME symlink %s -> %s",
                    link_path, real_home);
        return -1;
    }

    /* Identity of the link this call just installed, captured before any
     * post-install verification so EVERY failure path below can revert it.
     * The readback-verification block used to return -1 without unlinking —
     * the lone exception among the three post-install checks — so a failed
     * retarget could leave the shell-facing `current` entry point already
     * moved while gpg_switch_account reported failure (AR-05 L12). */
    struct stat installed;
    bool have_installed =
        fstatat(base_fd, "current", &installed, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISLNK(installed.st_mode) && installed.st_uid == getuid();

    /* The atomic rename is not the end of the trust decision: a same-uid
     * process can replace the public base immediately after the pre-commit
     * validation. Capture the link inode we installed, run the deterministic
     * race seam, then prove the public base/home still name the pinned objects. */
    if (gpg_read_current_locked(base_fd, base, committed_target,
                                sizeof(committed_target)) != 0 ||
        strcmp(committed_target, real_home) != 0 ||
        fstatat(base_fd, "current", &committed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(committed.st_mode) || committed.st_uid != getuid()) {
        /* Restore the pre-retarget target so a reported-failure retarget never
         * leaves the stable entry point moved OR destroyed (AR-06 F41). */
        if (have_installed) {
            gpg_revert_retarget(base_fd, &installed, prev_existed, prev_target);
        }
        set_error(ERR_FILE_IO,
                  "Cannot verify committed GNUPGHOME link: %s", link_path);
        return -1;
    }
    if (g_retarget_commit_hook && g_retarget_commit_hook(base_fd) != 0) {
        set_error(ERR_FILE_IO, "GPG retarget commit hook failed");
        gpg_revert_retarget(base_fd, &committed, prev_existed, prev_target);
        return -1;
    }
    if (gpg_live_private_home(base_fd, base, real_home) != 0) {
        gpg_revert_retarget(base_fd, &committed, prev_existed, prev_target);
        return -1;
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

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd);
    if (base_rc != 0) {
        if (base_rc > 0) {
            set_error(ERR_INVALID_PATH, "GPG base directory is missing: %s", base);
        }
        return -1;
    }
    rc = gpg_retarget_current_locked(base_fd, base, real_home);
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

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd);
    if (base_rc != 0) {
        return base_rc > 0 ? 0 : -1;
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
    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd);
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
    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd);
    if (base_rc != 0) {
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

int gpg_manager_restore_current_if(const char *expected_target,
                                   const char *restore_target,
                                   bool *changed) {
    char base[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    char actual[MAX_PATH_LEN];
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int actual_rc;
    int rc = -1;
    bool expect_present = expected_target && *expected_target;
    bool restore_present = restore_target && *restore_target;

    if (!changed) {
        set_error(ERR_INVALID_ARGS, "NULL GPG restore result");
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

    base_rc = gpg_lock_private_base(base, &base_fd, &lock_fd);
    if (base_rc > 0) {
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
    actual_rc = gpg_read_current_locked(base_fd, base, actual, sizeof(actual));
    if (actual_rc < 0) {
        goto out;
    }
    if (actual_rc == 0 && !gpg_target_is_managed_child(base, actual)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Stable GNUPGHOME points outside the managed GPG base: %s",
                  actual);
        goto out;
    }

    if ((expect_present && (actual_rc != 0 || strcmp(actual, expected_target) != 0)) ||
        (!expect_present && actual_rc == 0)) {
        rc = 0; /* compare-and-swap conflict: leave the later state untouched */
        goto out;
    }

    if (restore_present) {
        int live_rc = gpg_live_private_home(base_fd, base, restore_target);
        if (live_rc != 0) {
            if (live_rc > 0) {
                set_error(ERR_INVALID_PATH,
                          "Cannot restore missing isolated GPG home: %s",
                          restore_target);
            }
            goto out;
        }
        if (!(actual_rc == 0 && strcmp(actual, restore_target) == 0) &&
            gpg_retarget_current_locked(base_fd, base, restore_target) != 0) {
            goto out;
        }
    } else if (actual_rc == 0) {
        if (gpg_current_path_from_base(base, current, sizeof(current)) != 0) {
            goto out;
        }
        if (unlinkat(base_fd, "current", 0) != 0 && errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Failed to remove stable GNUPGHOME link: %s",
                             current);
            goto out;
        }
    }
    *changed = true;
    rc = 0;

out:
    unlock_gpg_dir(base_fd, lock_fd);
    return rc;
}

/* Recursively empty an already-opened directory without re-resolving any
 * pathname component.  Every descent is openat(O_NOFOLLOW)+fstat identity
 * checked and every deletion is unlinkat relative to the pinned parent. */
static int remove_tree_contents_fd(int dir_fd, const char *display_path) {
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
            int child_fd = openat(dir_fd, entry->d_name, scan_flags);
            if (child_fd < 0 || fstat(child_fd, &opened) != 0 ||
                !S_ISDIR(opened.st_mode) ||
                opened.st_dev != before.st_dev ||
                opened.st_ino != before.st_ino) {
                if (child_fd >= 0) close(child_fd);
                set_error(ERR_PERMISSION_DENIED,
                          "GPG reset directory changed while opening: %s",
                          child_display);
                closedir(dir);
                return -1;
            }
            if (remove_tree_contents_fd(child_fd, child_display) != 0) {
                close(child_fd);
                closedir(dir);
                return -1;
            }
            close(child_fd);
            if (fstatat(dir_fd, entry->d_name, &opened,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                opened.st_dev != before.st_dev ||
                opened.st_ino != before.st_ino ||
                unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR) != 0) {
                set_system_error(ERR_FILE_IO,
                                 "Failed to remove GPG directory: %s",
                                 child_display);
                closedir(dir);
                return -1;
            }
        } else if (unlinkat(dir_fd, entry->d_name, 0) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to remove GPG reset entry: %s",
                             child_display);
            closedir(dir);
            return -1;
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
    if (remove_tree_contents_fd(home_fd, home) != 0) {
        close(home_fd);
        set_system_error(ERR_FILE_IO,
                         "Failed to remove isolated GPG home; retained remainder: %s",
                         home);
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
                /* Dotfiles cover "."/".." plus our own .lock; account homes
                 * can never start with '.' (validate_name rejects it). */
                if (ent->d_name[0] == '.' ||
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
                goto reset_unlock;
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
reset_unlock:
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
        result = gpg_run(gpg_config, NULL, output, sizeof(output),
                         "gpg", "--import", key_source, (const char *)NULL);
    } else {
        result = gpg_run(gpg_config, NULL, output, sizeof(output),
                         "gpg", "--keyserver", "hkps://keys.openpgp.org",
                         "--recv-keys", key_source, (const char *)NULL);
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

    return gpg_run(gpg_config, NULL, output, output_size,
                   "gpg", "--armor", "--export", key_id, (const char *)NULL);
}

/* List available GPG keys */
int gpg_list_keys(gpg_config_t *gpg_config, char *output, size_t output_size) {
    if (!gpg_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_list_keys");
        return -1;
    }
    
    return gpg_run(gpg_config, NULL, output, output_size,
                   "gpg", "--list-keys", "--with-colons", (const char *)NULL);
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

static int gpg_validate_key_pinned(gpg_config_t *gpg_config,
                                   const gpg_pinned_home_t *home,
                                   const char *key_id) {
    char output[512];

    if (!gpg_config || !home || !key_id) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to pinned GPG key validation");
        return -1;
    }
    if (gpg_run_pinned(home, gpg_config, NULL, output, sizeof(output),
                       "gpg", "--list-secret-keys", key_id,
                       (const char *)NULL) != 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", key_id);
        return -1;
    }
    gpg_manager_note_key_available(key_id);
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

static int gpg_test_signing_pinned(gpg_config_t *gpg_config,
                                   const gpg_pinned_home_t *home,
                                   const char *key_id) {
    char output[4096];
    run_result_t res;

    if (!gpg_config || !home || !key_id) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid arguments to pinned GPG signing test");
        return -1;
    }
    if (gpg_run_pinned(home, gpg_config, &res, output, sizeof(output),
                       "gpg", "--list-secret-keys", "--with-colons", key_id,
                       (const char *)NULL) != 0) {
        set_error(ERR_GPG_SIGNING_FAILED,
                  "No secret key available for signing: %s", key_id);
        return -1;
    }
    if (!gpg_colons_have_sign_capability(output)) {
        if (res.out_truncated) {
            gpg_manager_note_key_available(key_id);
            return 0;
        }
        set_error(ERR_GPG_SIGNING_FAILED,
                  "Key has no signing-capable secret key: %s", key_id);
        return -1;
    }
    gpg_manager_note_key_available(key_id);
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

/* Copy GPG key from system keyring to isolated environment.
 *
 * The idempotency probe runs `--with-colons` and, when the key is already
 * present, hands the listing back via colons/colons_valid so the caller's
 * signing-capability test can parse it instead of spawning another gpg for
 * the identical question (AR-02 #14). On the import path (key not yet in the
 * isolated home) colons_valid stays false — a listing from before the import
 * would prove nothing about it. */
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config,
                                        const gpg_pinned_home_t *home,
                                        const char *key_id,
                                        char *colons, size_t colons_size,
                                        bool *colons_valid) {
    /* Generous heap capacity for the armored export: a multi-subkey RSA-4096
     * key armors to ~15 KB and photo-ID-bearing keys to far more, so the old
     * fixed 8 KB stack buffer routinely truncated real keys — and run_argv's
     * silent cap then fed the corrupt armor straight to `gpg --import`
     * (AR-02 #4). Truncation is detected and refused explicitly below. */
    enum { KEY_DATA_CAP = 512 * 1024 };
    char import_diag[1024];
    const char *env[2] = {"GNUPGHOME=.", NULL};
    char *key_data;
    run_opts_t opts;
    run_result_t res;

    if (!gpg_config || !home || !key_id || !colons || !colons_valid) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_key_from_system_keyring");
        return -1;
    }
    *colons_valid = false;

    log_debug("Copying GPG key from system keyring: %s", key_id);

    /* Idempotency: if the secret key is already present in the isolated home
     * (e.g. switching back to an account whose home persists from an earlier
     * switch), skip the export/import. The export step prompts the system
     * agent's PIN, so skipping it avoids a PIN prompt on every switch. The
     * probe asks with --with-colons so its output doubles as the caller's
     * signing-capability evidence (AR-02 #14). */
    if (gpg_run_pinned(home, gpg_config, &res, colons, colons_size,
                       "gpg", "--list-secret-keys", "--with-colons", key_id,
                       (const char *)NULL) == 0) {
        log_debug("Secret key already present in isolated home; skipping import: %s", key_id);
        /* Hand the listing back as signing evidence only when the capture is
         * complete (AR-03 L4). Exit 0 alone proves the key is present, so
         * skipping the import stays correct either way — but a TRUNCATED
         * listing may have dropped the very `ssb` record that carries the
         * signing capability, and treating it as authoritative made the
         * caller warn "GPG signing test failed" for perfectly good big keys.
         * Left invalid, the caller re-asks via gpg_test_signing, which does
         * its own truncation handling. */
        *colons_valid = !res.out_truncated;
        gpg_manager_note_key_available(key_id);
        return 0;
    }
    /* A listing miss is an ordinary first-import case; a changed public
     * namespace is not. Refuse before exporting any secret material. */
    if (gpg_validate_pinned_home(home) != 0) {
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
        const char *export_argv[] = {"gpg", "--armor", "--export-secret-keys", key_id, NULL};
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
                      "import a truncated key", key_id, (int)KEY_DATA_CAP);
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
    log_info("Successfully copied GPG key to isolated environment: %s", key_id);
    gpg_manager_note_key_available(key_id);
    return 0;
}

/* Scan the pinned temporary stream for an active (non-comment)
 * pinentry-program directive, then leave it positioned for appending. */
static int conf_stream_has_pinentry(FILE *f, bool *found) {
    char line[1024];

    if (!f || !found || fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0) {
        return -1;
    }
    *found = false;
    while (fgets(line, sizeof(line), f)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "pinentry-program", 16) == 0 &&
            (p[16] == '\0' || p[16] == ' ' || p[16] == '\t' ||
             p[16] == '\r' || p[16] == '\n')) {
            *found = true;
            break;
        }
    }
    if (ferror(f)) {
        return -1;
    }
    clearerr(f);
    return fseek(f, 0, SEEK_END) == 0 ? 0 : -1;
}

enum { GPG_AGENT_CONF_MAX = 64 * 1024 };

static int copy_conf_fd(int source_fd, FILE *dest,
                        size_t *bytes_out, bool *ends_with_newline) {
    char buf[4096];
    size_t total = 0;
    bool newline = true;
    ssize_t n;

    for (;;) {
        n = read(source_fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (n == 0) break;
        if (total + (size_t)n > GPG_AGENT_CONF_MAX) {
            errno = EFBIG;
            return -1;
        }
        if (fwrite(buf, 1, (size_t)n, dest) != (size_t)n) return -1;
        total += (size_t)n;
        newline = buf[n - 1] == '\n';
    }
    *bytes_out = total;
    *ends_with_newline = newline;
    return 0;
}

/* Resolve the user's real gpg home to inherit agent settings from: their
 * configured GNUPGHOME when it isn't one of our isolated homes (avoids reading
 * our own generated conf), otherwise ~/.gnupg. Returns 0 on success. */
static int gpg_user_source_home(char *buf, size_t size) {
    const char *env_gh = getenv("GNUPGHOME");
    const char *home;
    if (env_gh && *env_gh && strstr(env_gh, "gitswitch-gpg") == NULL) {
        return safe_strncpy(buf, env_gh, size);
    }
    home = getenv("HOME");
    if (!home || !*home) {
        return -1;
    }
    return ((size_t)snprintf(buf, size, "%s/.gnupg", home) < size) ? 0 : -1;
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
    char gpg_agent_conf_path[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN] = "";
    char temp_name[64] = "";
    char suffix[13];
    char source_home[MAX_PATH_LEN];
    char source_conf[MAX_PATH_LEN];
    bool inherited = false;
    bool has_pinentry = false;
    bool ends_with_newline = true;
    size_t inherited_bytes = 0;
    FILE *conf_file = NULL;
    struct stat created;
    struct stat fd_now;
    struct stat entry;
    bool have_created_identity = false;
    int source_fd = -1;
    int fd = -1;
    
    if (home_fd < 0 || !gnupg_home) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent config destination");
        return -1;
    }
    
    /* Create gpg-agent.conf path */
    if (safe_snprintf(gpg_agent_conf_path, sizeof(gpg_agent_conf_path),
                      "%s/gpg-agent.conf", gnupg_home) != 0) {
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        return -1;
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
            return -1;
        }
        fd = openat(home_fd, temp_name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) {
        set_system_error(ERR_FILE_IO, "Failed to create temporary gpg-agent.conf");
        return -1;
    }
    if (safe_snprintf(temp_path, sizeof(temp_path), "%s/%s",
                      gnupg_home, temp_name) != 0) {
        close(fd);
        (void)unlinkat(home_fd, temp_name, 0);
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        return -1;
    }
    (void)signals_scratch_register(temp_path);
    if (fchmod(fd, 0600) != 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Failed to secure temporary gpg-agent.conf");
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
    conf_file = fdopen(fd, "w+b");
    if (!conf_file) {
        set_system_error(ERR_FILE_IO, "Failed to open temporary gpg-agent.conf");
        goto fail;
    }
    fd = -1; /* conf_file owns it */

    /* Inherit the user's real gpg-agent.conf verbatim when present, so their
     * pinentry choice and cache settings carry into the isolated home. Copy
     * from a read descriptor into our fresh 0600 temp: a legitimate inherited
     * source may itself be 0400, so never copy its mode onto a destination and
     * then attempt to reopen that destination for append. */
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
            if (g_agent_conf_preopen) {
                g_agent_conf_preopen(source_conf);
            }
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
                opened.st_dev != before.st_dev ||
                opened.st_ino != before.st_ino) {
                close(source_fd);
                source_fd = -1;
                set_error(ERR_PERMISSION_DENIED,
                          "Inherited gpg-agent.conf changed to an unsafe file: %s",
                          source_conf);
                goto fail;
            }
            if (copy_conf_fd(source_fd, conf_file, &inherited_bytes,
                             &ends_with_newline) != 0) {
                if (errno == EFBIG) {
                    set_error(ERR_FILE_IO,
                              "Inherited gpg-agent.conf exceeds %d bytes: %s",
                              GPG_AGENT_CONF_MAX, source_conf);
                } else {
                set_system_error(ERR_FILE_IO,
                                 "Failed to inherit gpg-agent.conf: %s", source_conf);
                }
                goto fail;
            }
            if (lstat(source_conf, &after) != 0 ||
                after.st_dev != opened.st_dev ||
                after.st_ino != opened.st_ino ||
                after.st_size != opened.st_size) {
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

    /* No user config to inherit: write minimal defaults. */
    if (!inherited) {
        if (fprintf(conf_file,
                    "# GPG Agent configuration for gitswitch isolated environment\n"
                    "default-cache-ttl 3600\n"
                    "max-cache-ttl 7200\n") < 0) {
            set_system_error(ERR_FILE_IO, "Failed to write gpg-agent.conf");
            goto fail;
        }
    }

    if (conf_stream_has_pinentry(conf_file, &has_pinentry) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to inspect temporary gpg-agent.conf");
        goto fail;
    }

    /* Ensure a pinentry-program is set: honor the user's if one was inherited,
     * otherwise append a detected one (the compiled-in default can be wrong,
     * e.g. on FreeBSD). Prefer the generic `pinentry`, then common flavors. */
    if (!has_pinentry) {
        static const char *const pinentry_candidates[] = {
            "pinentry", "pinentry-curses", "pinentry-mac", "pinentry-tty"
        };
        char pinentry_path[MAX_PATH_LEN];
        for (size_t i = 0; i < sizeof(pinentry_candidates) / sizeof(pinentry_candidates[0]); i++) {
            if (find_command_path(pinentry_candidates[i], pinentry_path, sizeof(pinentry_path)) == 0) {
                if (inherited && inherited_bytes > 0 && !ends_with_newline &&
                    fputc('\n', conf_file) == EOF) {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to delimit inherited gpg-agent.conf");
                    goto fail;
                }
                if (fprintf(conf_file, "pinentry-program %s\n", pinentry_path) < 0) {
                    set_system_error(ERR_FILE_IO, "Failed to append pinentry to gpg-agent.conf");
                    goto fail;
                }
                break;
            }
        }
    }

    if (fflush(conf_file) != 0 || fsync(fileno(conf_file)) != 0) {
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
    if (fstat(fileno(conf_file), &fd_now) != 0 ||
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
    if (fstatat(home_fd, "gpg-agent.conf", &entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        entry.st_dev != created.st_dev || entry.st_ino != created.st_ino ||
        !S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        entry.st_nlink != 1 || (entry.st_mode & 0777) != 0600) {
        set_error(ERR_FILE_IO,
                  "gpg-agent.conf changed during atomic commit");
        goto fail;
    }
    signals_scratch_unregister(temp_path);
    {
        FILE *closing = conf_file;
        conf_file = NULL;
        if (fclose(closing) != 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to close installed gpg-agent.conf");
            goto fail;
        }
    }

    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;

fail:
    if (source_fd >= 0) close(source_fd);
    if (conf_file) {
        fclose(conf_file);
    } else if (fd >= 0) {
        close(fd);
    }
    /* A failed commit must never delete a pathname another process substituted.
     * Remove only names which still resolve to the inode created above. */
    if (have_created_identity && temp_name[0] &&
        fstatat(home_fd, temp_name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        entry.st_dev == created.st_dev && entry.st_ino == created.st_ino) {
        (void)unlinkat(home_fd, temp_name, 0);
    }
    if (have_created_identity &&
        fstatat(home_fd, "gpg-agent.conf", &entry,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        entry.st_dev == created.st_dev && entry.st_ino == created.st_ino) {
        (void)unlinkat(home_fd, "gpg-agent.conf", 0);
    }
    if (temp_path[0]) signals_scratch_unregister(temp_path);
    return -1;
}
