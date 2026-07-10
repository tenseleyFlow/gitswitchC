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
#include <ftw.h>
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

/* Internal helper functions */
static int gpg_get_base_dir(char *buf, size_t size);
static int create_isolated_gnupg_home_dir(const char *gnupg_home);
static void gpg_build_env(const gpg_config_t *cfg, char *envbuf, size_t envbuf_size,
                          const char *env_out[2]);
static int gpg_run(const gpg_config_t *cfg, char *output, size_t output_size, ...);
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id,
                                        char *colons, size_t colons_size,
                                        bool *colons_valid);
static int setup_gpg_agent_config(const char *gnupg_home);

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
    bool colons_valid = false;

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
            
            /* Copy key from system keyring to isolated environment. On success
             * the key is provably present in the isolated home (the copy step
             * either found it already there or imported it), so we skip the
             * follow-up validation — it would just re-run the same
             * `gpg --list-secret-keys`, spawning another gpg (and agent). Only
             * when the copy fails do we validate, to see if a prior switch
             * already left the key in the isolated home. On the already-
             * present path the probe's colons listing is kept so the signing
             * test below needs no spawn of its own (AR-02 #14). */
            if (copy_key_from_system_keyring(gpg_config, account->gpg_key_id,
                                             colons, sizeof(colons),
                                             &colons_valid) != 0) {
                log_warning("Failed to copy GPG key to isolated environment: %s",
                           get_last_error()->message);
                if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                    set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available in isolated environment: %s",
                             account->gpg_key_id);
                    return -1;
                }
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
    
    /* Test GPG signing if enabled. When the idempotency probe above already
     * captured this key's colons listing, answer from it — gpg_test_signing
     * would spawn gpg only to re-run the identical listing (AR-02 #14). */
    if (account->gpg_signing_enabled) {
        int sign_rc;
        if (colons_valid) {
            sign_rc = gpg_colons_have_sign_capability(colons) ? 0 : -1;
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
     * after the key is imported and validated. Isolated mode only; non-fatal. */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        gpg_manager_retarget_current(gpg_config->gnupg_home);
    }

    log_info("Successfully switched to GPG configuration for account: %s", account->name);
    return 0;
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
        /* Fallback: XDG_RUNTIME_DIR is unset (cron, minimal login, some SSH
         * sessions). /tmp is a tmpfs on most Linux desktops, but on many
         * servers and default FreeBSD/macOS it is persistent disk — where the
         * isolated home's exported secret keys would then live, contradicting
         * this function's own no-persistent-disk intent. Warn once (per process)
         * when we can't confirm the fallback is memory-backed, so the user can
         * export XDG_RUNTIME_DIR or accept the risk knowingly. Probes the
         * actual base (nearest existing ancestor when absent), not a hardcoded
         * "/tmp": the base could be a distinct persistent mount under a tmpfs
         * /tmp (AR-02 #22). The create path (gpg_create_isolated_home)
         * additionally refuses to write secret material to any non-memory-
         * backed base unless the user opts in. */
        written = snprintf(buf, size, "/tmp/gitswitch-gpg-%d", getuid());
        static bool warned = false;
        if (!warned && written > 0 && (size_t)written < size &&
            !base_is_memory_backed(buf)) {
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

/* Acquire an exclusive, blocking flock on <base>/.lock, serializing every
 * writer of the GPG runtime state — the `current` symlink retarget/drop and
 * gpg_manager_reset's enumeration + dangling-link cleanup — against each
 * other across processes (AR-02 #9: an unlocked reset's cleanup could TOCTOU
 * a concurrent switch and unlink the live link it had just installed).
 * Mirrors ssh_manager.c's lock_agent_dir. Returns the held fd, or -1 (base
 * absent/unlockable — callers proceed unlocked, matching the SSH side, since
 * a missing base means there is no runtime state to race over). Dotfile names
 * cannot collide with an account home: validate_name rejects a leading '.'. */
static int lock_gpg_dir(const char *base) {
    char lock_path[MAX_PATH_LEN];
    if ((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock", base) >= sizeof(lock_path)) {
        return -1;
    }
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void unlock_gpg_dir(int fd) {
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

/* Point the stable <base>/current symlink at the active account's real
 * GNUPGHOME so a shell that exports GNUPGHOME=<base>/current (via
 * `gitswitch init`) transparently follows each switch. Mirrors the SSH
 * current.sock retargeting in ssh_manager.c. Held under the per-dir lock so
 * the retarget cannot interleave with a concurrent reset's dangling-link
 * cleanup (AR-02 #9). Non-fatal on failure. */
int gpg_manager_retarget_current(const char *real_home) {
    char base[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN];
    int lock_fd;
    int rc;

    if (!real_home || strlen(real_home) == 0) {
        return -1;
    }

    if (gpg_get_base_dir(base, sizeof(base)) != 0 ||
        gpg_manager_get_home_path(link_path, sizeof(link_path)) != 0) {
        return -1;
    }

    lock_fd = lock_gpg_dir(base);

    /* Atomically retarget (temp symlink + rename) so a follower never sees a
     * missing or half-updated link. */
    rc = atomic_symlink(real_home, link_path);
    unlock_gpg_dir(lock_fd);
    if (rc != 0) {
        log_warning("Failed to create GNUPGHOME symlink %s -> %s",
                    link_path, real_home);
        return -1;
    }

    log_debug("Created GNUPGHOME symlink: %s -> %s", link_path, real_home);
    return 0;
}

/* Drop the stable `current` symlink (switching to a GPG-less account, or
 * rolling one back). Locked for the same reason as the retarget: an unlocked
 * unlink could delete the fresh link a concurrent switch just installed. */
int gpg_manager_drop_current(void) {
    char base[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN];
    int lock_fd;

    if (gpg_get_base_dir(base, sizeof(base)) != 0 ||
        gpg_manager_get_home_path(link_path, sizeof(link_path)) != 0) {
        return -1;
    }
    lock_fd = lock_gpg_dir(base);
    unlink(link_path); /* drop the `current` symlink, not its target */
    unlock_gpg_dir(lock_fd);
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
 * Kills the per-home gpg-agents and deletes (unlinks) the homes, then drops
 * the stable `current` symlink if it dangles. NB: deletion is remove(), not a
 * secure overwrite — on the memory-backed storage the create path requires by
 * default, unlinking genuinely destroys the bytes, but on the explicitly
 * opted-in non-tmpfs path (GITSWITCH_ALLOW_TMP_GPG) the secret-key bytes may
 * remain recoverable on disk after deletion (AR-02 #26). */
int gpg_manager_reset(const char *account) {
    char base[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    int lock_fd;

    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }

    /* Guard the base before we opendir/recursively remove under it. When
     * XDG_RUNTIME_DIR is unset the base is the predictable path
     * /tmp/gitswitch-gpg-<uid> in world-writable, sticky /tmp, so a co-located
     * user could pre-create it as a symlink to, e.g., the victim's home —
     * turning `reset` into an arbitrary recursive delete (nftw follows the
     * symlinked base as an intermediate path component; FTW_PHYS only governs
     * leaf traversal). The create path already validates the base via
     * ensure_private_dir(); reset must be at least as strict. lstat (no follow)
     * and refuse a symlink, a foreign owner, or any group/other access. A
     * missing base means there is simply nothing to reset. */
    struct stat bst;
    if (lstat(base, &bst) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        set_system_error(ERR_FILE_IO, "Cannot stat GPG base dir: %s", base);
        return -1;
    }
    if (S_ISLNK(bst.st_mode) || !S_ISDIR(bst.st_mode) ||
        bst.st_uid != getuid() || (bst.st_mode & 077)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing to reset: GPG base dir is a symlink, foreign-owned, "
                  "or not private: %s", base);
        return -1;
    }

    /* Hold the per-dir lock across the whole kill/remove sequence AND the
     * dangling-symlink cleanup below, so a concurrent switch's locked
     * retarget cannot interleave: without it, reset could read a dangling
     * `current`, the switch could install a fresh live link, and reset's
     * unlink would then delete that freshly-installed link (AR-02 #9). */
    lock_fd = lock_gpg_dir(base);

    if (account && *account) {
        char home[MAX_PATH_LEN];
        struct stat hst;
        /* The account name becomes a path component under a directory we then
         * recursively delete. Reject anything that isn't a safe single
         * component so `reset ..` (or a crafted name) can't escape base and
         * wipe, e.g., the whole runtime dir. */
        if (strpbrk(account, "/\\") != NULL || strstr(account, "..") != NULL ||
            account[0] == '.') {
            set_error(ERR_INVALID_ARGS, "Invalid account name for reset: %s", account);
            unlock_gpg_dir(lock_fd);
            return -1;
        }
        if ((size_t)snprintf(home, sizeof(home), "%s/%s", base, account) >= sizeof(home)) {
            unlock_gpg_dir(lock_fd);
            return -1;
        }
        /* lstat, not path_exists: a symlinked home must be refused, exactly
         * like the all-accounts branch skips symlinked entries. Following it
         * would run `gpgconf --kill all` with GNUPGHOME set through the link
         * — e.g. at the user's real ~/.gnupg, killing their login gpg-agent
         * (AR-02 #21). The absent case is simply nothing to reset. */
        if (lstat(home, &hst) == 0) {
            if (S_ISLNK(hst.st_mode)) {
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing to reset: isolated GPG home is a symlink: %s", home);
                unlock_gpg_dir(lock_fd);
                return -1;
            }
            gpg_kill_and_remove_home(home);
        }
    } else {
        DIR *d = opendir(base);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                char home[MAX_PATH_LEN];
                /* Dotfiles cover "."/".." plus our own .lock; account homes
                 * can never start with '.' (validate_name rejects it). */
                if (ent->d_name[0] == '.' ||
                    strcmp(ent->d_name, "current") == 0) {
                    continue;
                }
                if ((size_t)snprintf(home, sizeof(home), "%s/%s", base, ent->d_name) < sizeof(home)) {
                    /* Base is validated private+owned above, so entries are ours;
                     * still refuse to recurse into a symlinked entry as belt-and-
                     * suspenders against a symlink planted inside the base. */
                    struct stat est;
                    if (lstat(home, &est) == 0 && !S_ISLNK(est.st_mode)) {
                        gpg_kill_and_remove_home(home);
                    }
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
    unlock_gpg_dir(lock_fd);
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

    /* Refuse to export secret-key material onto persistent disk, wherever the
     * base came from. XDG_RUNTIME_DIR is only USUALLY a tmpfs — rootless
     * containers, NFS-homed logins, or a hand-exported disk path are not — and
     * the /tmp fallback (or even a bind/quota mount at exactly the base path
     * under a tmpfs /tmp) can be persistent too, so probe the actual computed
     * base rather than trusting its source or a hardcoded parent (AR-02 #3,
     * #22). Fail closed unless the user explicitly opts in with
     * GITSWITCH_ALLOW_TMP_GPG=1 (or, better, points XDG_RUNTIME_DIR at a
     * tmpfs); on opt-in, remind them once per process what they accepted. */
    if (!base_is_memory_backed(gnupg_base_dir)) {
        const char *optin = getenv("GITSWITCH_ALLOW_TMP_GPG");
        if (!optin || strcmp(optin, "1") != 0) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing to write GPG secret keys to non-memory-backed %s. "
                      "Set XDG_RUNTIME_DIR to a tmpfs, or GITSWITCH_ALLOW_TMP_GPG=1 "
                      "to accept on-disk secret-key persistence.", gnupg_base_dir);
            return -1;
        }
        static bool warned_optin = false;
        if (!warned_optin) {
            warned_optin = true;
            display_warning("GITSWITCH_ALLOW_TMP_GPG=1: writing GPG secret keys to "
                            "non-memory-backed %s; they may remain recoverable on "
                            "disk after deletion.", gnupg_base_dir);
        }
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

/* Copy GPG key from system keyring to isolated environment.
 *
 * The idempotency probe runs `--with-colons` and, when the key is already
 * present, hands the listing back via colons/colons_valid so the caller's
 * signing-capability test can parse it instead of spawning another gpg for
 * the identical question (AR-02 #14). On the import path (key not yet in the
 * isolated home) colons_valid stays false — a listing from before the import
 * would prove nothing about it. */
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id,
                                        char *colons, size_t colons_size,
                                        bool *colons_valid) {
    /* Generous heap capacity for the armored export: a multi-subkey RSA-4096
     * key armors to ~15 KB and photo-ID-bearing keys to far more, so the old
     * fixed 8 KB stack buffer routinely truncated real keys — and run_argv's
     * silent cap then fed the corrupt armor straight to `gpg --import`
     * (AR-02 #4). Truncation is detected and refused explicitly below. */
    enum { KEY_DATA_CAP = 512 * 1024 };
    char import_diag[1024];
    char envbuf[MAX_PATH_LEN + 16];
    const char *env[2];
    char *key_data;
    run_opts_t opts;
    run_result_t res;

    if (!gpg_config || !key_id || !colons || !colons_valid) {
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
    if (gpg_run(gpg_config, colons, colons_size,
                "gpg", "--list-secret-keys", "--with-colons", key_id, NULL) == 0) {
        log_debug("Secret key already present in isolated home; skipping import: %s", key_id);
        *colons_valid = true;
        gpg_manager_note_key_available(key_id);
        return 0;
    }

    key_data = malloc(KEY_DATA_CAP);
    if (!key_data) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate GPG export buffer");
        return -1;
    }

    /* Export the secret key from the SYSTEM keyring (no GNUPGHOME override).
     * key_data now holds unencrypted armored private-key material, so every
     * exit below must scrub it (secure_zero_memory) before freeing — a plain
     * free would leave the key in heap memory for a later allocation, core
     * dump, or memory-disclosure bug to recover. Export stderr stays
     * discarded: stdout IS the key, so merging would corrupt it. */
    {
        const char *export_argv[] = {"gpg", "--armor", "--export-secret-keys", key_id, NULL};
        memset(&opts, 0, sizeof(opts));
        opts.out = key_data;
        opts.out_size = KEY_DATA_CAP;
        opts.stderr_to_devnull = true;
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

    /* Import into the isolated GNUPGHOME by feeding the key on stdin. Capture
     * merged stdout+stderr so a failure surfaces gpg's real diagnostic
     * instead of a generic message with the cause thrown away (AR-02 #4). */
    {
        const char *import_argv[] = {"gpg", "--batch", "--import", NULL};
        gpg_build_env(gpg_config, envbuf, sizeof(envbuf), env);
        memset(&opts, 0, sizeof(opts));
        opts.input = key_data;
        opts.input_len = res.out_len;
        opts.out = import_diag;
        opts.out_size = sizeof(import_diag);
        opts.merge_stderr = true;
        if (env[0]) opts.extra_env = env;
        if (run_argv(import_argv, &opts, NULL) != 0) {
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

/* True if the file has an active (non-comment) pinentry-program directive. */
static bool conf_has_pinentry(const char *path) {
    FILE *f = fopen(path, "r");
    char line[1024];
    bool found = false;
    if (!f) {
        return false;
    }
    while (fgets(line, sizeof(line), f)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "pinentry-program", 16) == 0) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
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

/* Set up gpg-agent.conf for the isolated environment.
 *
 * Inherits the user's real gpg-agent.conf (their pinentry choice — e.g. a GUI
 * pinentry — plus cache settings) so isolation never silently downgrades their
 * pinentry. Only when the user has no config of their own do we write minimal
 * defaults, and a *detected* pinentry is appended only if none is already set
 * (the compiled-in default can be wrong, e.g. on FreeBSD). Re-run each switch,
 * so edits to the user's real config propagate. */
static int setup_gpg_agent_config(const char *gnupg_home) {
    char gpg_agent_conf_path[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    char source_conf[MAX_PATH_LEN];
    bool inherited = false;
    bool has_pinentry = false;
    
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
    
    /* Inherit the user's real gpg-agent.conf verbatim when present, so their
     * pinentry choice and cache settings carry into the isolated home. */
    if (gpg_user_source_home(source_home, sizeof(source_home)) == 0 &&
        safe_snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf", source_home) == 0 &&
        path_exists(source_conf)) {
        if (copy_file(source_conf, gpg_agent_conf_path) == 0) {
            inherited = true;
            has_pinentry = conf_has_pinentry(gpg_agent_conf_path);
            log_debug("Inherited gpg-agent.conf from %s", source_conf);
        }
    }

    /* No user config to inherit: write minimal defaults. */
    if (!inherited) {
        FILE *conf_file = fopen(gpg_agent_conf_path, "w");
        if (!conf_file) {
            set_system_error(ERR_FILE_IO, "Failed to create gpg-agent.conf");
            return -1;
        }
        fprintf(conf_file, "# GPG Agent configuration for gitswitch isolated environment\n");
        fprintf(conf_file, "default-cache-ttl 3600\n");
        fprintf(conf_file, "max-cache-ttl 7200\n");
        fclose(conf_file);
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
                FILE *cf = fopen(gpg_agent_conf_path, "a");
                if (cf) {
                    fprintf(cf, "pinentry-program %s\n", pinentry_path);
                    fclose(cf);
                }
                break;
            }
        }
    }
    
    /* Set proper permissions */
    if (chmod(gpg_agent_conf_path, 0600) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set gpg-agent.conf permissions");
        return -1;
    }
    
    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;
}