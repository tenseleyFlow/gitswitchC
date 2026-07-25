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
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
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
#include "runner_internal.h"
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
typedef struct {
    int base_fd;
    int home_fd;
    const char *base;
    const char *name;
    const char *path;
} gpg_pinned_home_t;
typedef struct {
    bool reload_required;
    int config_fd;
    struct stat config_identity;
    unsigned char *config_witness;
    size_t config_witness_length;
    int marker_fd;
    struct stat marker_identity;
    char gpgconf_path[MAX_PATH_LEN];
} gpg_agent_config_update_t;
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
typedef struct gpg_source_proof gpg_source_proof_t;
typedef struct {
    int fd;
    char path[MAX_PATH_LEN];
    struct stat identity;
    gpg_mount_identity_t mount;
    gpg_source_proof_t *proof;
} gpg_source_home_t;
typedef enum {
    GPG_SOURCE_PATH_EXTERNAL = 0,
    GPG_SOURCE_PATH_MANAGED_CANONICAL = 1,
    GPG_SOURCE_PATH_MANAGED_DESCENDANT = 2
} gpg_source_path_class_t;
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config,
                                        const gpg_pinned_home_t *home,
                                        const char *selector,
                                        bool require_signing,
                                        char *fingerprint,
                                        size_t fingerprint_size);
static int setup_gpg_agent_config(int home_fd, const char *gnupg_home,
                                  gpg_agent_config_update_t *update);
static int gpg_reload_agent_config(const gpg_pinned_home_t *home,
                                   gpg_agent_config_update_t *update);
static int gpg_prepare_isolated_home_at(gpg_config_t *gpg_config,
                                        const account_t *account,
                                        int base_fd, const char *base,
                                        int *home_fd_out);
static int gpg_validate_pinned_home(const gpg_pinned_home_t *home);
static int gpg_mount_identity_fd(int fd, gpg_mount_identity_t *identity);
static bool gpg_same_mount(const gpg_mount_identity_t *left,
                           const gpg_mount_identity_t *right);
static bool gpg_same_file_version(const struct stat *left,
                                  const struct stat *right);
static int gpg_user_source_home(char *buf, size_t size);
static int gpg_open_user_source_home(gpg_source_home_t *source);
static int gpg_validate_source_home(const gpg_source_home_t *source);
static int gpg_validate_source_home_binding(
    const gpg_source_home_t *source);
static void gpg_close_source_home(gpg_source_home_t *source);
static int gpg_resolve_source_key(const gpg_config_t *gpg_config,
                                  const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size);
static int gpg_resolve_pinned_key(const gpg_config_t *gpg_config,
                                  const gpg_pinned_home_t *home,
                                  const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size);
static int gpg_open_base_dir(char *base, size_t size, bool create,
                             bool *absent);
static int gpg_default_memory_backed_probe(int base_fd,
                                           bool *memory_backed);
static bool base_is_memory_backed(const char *base);
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
static const char *const g_gpg_child_unset_env[] = {
    "GPG_AGENT_INFO",
    NULL
};
static gpg_cleanup_predelete_fn g_cleanup_predelete;
static gpg_reset_final_hook_fn g_reset_final_hook;
static gpg_reset_current_hook_fn g_reset_current_hook;
static gpg_reset_quarantine_hook_fn g_reset_quarantine_hook;
static gpg_mount_identity_probe_fn g_mount_identity_probe;
static gpg_agent_conf_sync_fn g_agent_conf_sync =
    gpg_default_agent_conf_sync;
static gpg_memory_backed_probe_fn g_memory_backed_probe =
    gpg_default_memory_backed_probe;
static gpg_base_warning_probe_fn g_base_warning_probe =
    base_is_memory_backed;
static bool g_base_warning_probe_checked;
static bool g_base_warning_memory_backed;
static bool g_base_warning_emitted;
static gpg_key_cache_post_scan_hook_fn g_key_cache_post_scan_hook;

static void gpg_agent_config_update_init(gpg_agent_config_update_t *update) {
    if (!update) return;
    memset(update, 0, sizeof(*update));
    update->config_fd = -1;
    update->marker_fd = -1;
}

static int gpg_agent_config_update_close(gpg_agent_config_update_t *update) {
    int saved_errno = 0;

    if (!update) return 0;
    if (update->config_fd >= 0 && close(update->config_fd) != 0) {
        saved_errno = errno;
    }
    if (update->marker_fd >= 0 && close(update->marker_fd) != 0 &&
        saved_errno == 0) {
        saved_errno = errno;
    }
    if (update->config_witness) {
        secure_zero_memory(update->config_witness,
                           update->config_witness_length);
        free(update->config_witness);
    }
    gpg_agent_config_update_init(update);
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

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

gpg_reset_current_hook_fn
gpg_manager_set_reset_current_hook_fn(gpg_reset_current_hook_fn fn) {
    gpg_reset_current_hook_fn previous = g_reset_current_hook;
    g_reset_current_hook = fn;
    return previous;
}

gpg_reset_quarantine_hook_fn
gpg_manager_set_reset_quarantine_hook_fn(gpg_reset_quarantine_hook_fn fn) {
    gpg_reset_quarantine_hook_fn previous = g_reset_quarantine_hook;
    g_reset_quarantine_hook = fn;
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

gpg_memory_backed_probe_fn
gpg_manager_set_memory_backed_probe_fn(gpg_memory_backed_probe_fn fn) {
    gpg_memory_backed_probe_fn previous = g_memory_backed_probe;
    g_memory_backed_probe = fn ? fn : gpg_default_memory_backed_probe;
    return previous;
}

gpg_base_warning_probe_fn
gpg_manager_set_base_warning_probe_fn(gpg_base_warning_probe_fn fn) {
    gpg_base_warning_probe_fn previous = g_base_warning_probe;

    g_base_warning_probe = fn ? fn : base_is_memory_backed;
    g_base_warning_probe_checked = false;
    g_base_warning_memory_backed = false;
    g_base_warning_emitted = false;
    return previous;
}

gpg_key_cache_post_scan_hook_fn
gpg_manager_set_key_cache_post_scan_hook_fn(
    gpg_key_cache_post_scan_hook_fn fn) {
    gpg_key_cache_post_scan_hook_fn previous =
        g_key_cache_post_scan_hook;
    g_key_cache_post_scan_hook = fn;
    return previous;
}

/* The original AR-02 availability memo retained only caller-supplied key
 * spellings. It remains as a compatibility surface for deterministic mock
 * runners, but a production runner must never treat a post-hoc note as
 * executable, home, capability, or key evidence. Real reuse is owned by the
 * proof cache below and can be produced only by a successful structured
 * secret-key listing. */
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
    if (!key_id || run_uses_default_runner()) {
        return false;
    }
    for (size_t i = 0; i < g_seen_key_count; i++) {
        if (strcmp(g_seen_keys[i], key_id) == 0) {
            return true;
        }
    }
    return false;
}

typedef enum {
    GPG_KEY_CACHE_HOME_SYSTEM = 1,
    GPG_KEY_CACHE_HOME_ISOLATED = 2
} gpg_key_cache_home_kind_t;

typedef struct {
    char *relative_path;
    struct stat identity;
} gpg_key_cache_home_entry_t;

typedef struct {
    bool valid;
    gpg_key_cache_home_kind_t kind;
    char path[MAX_PATH_LEN];
    struct stat root_identity;
    gpg_mount_identity_t root_mount;
    gpg_key_cache_home_entry_t *entries;
    size_t count;
    size_t capacity;
} gpg_key_cache_home_generation_t;

typedef struct {
    bool valid;
    bool signing_capability;
    uint64_t sequence;
    uint32_t listing_contract;
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char program[MAX_PATH_LEN];
    run_launch_witness_t launch;
    gpg_key_cache_home_generation_t home;
} gpg_key_cache_entry_t;

enum {
    GPG_KEY_CACHE_MAX = 8,
    GPG_KEY_CACHE_MAX_DEPTH = 16,
    GPG_KEY_CACHE_MAX_HOME_ENTRIES = 512,
    GPG_KEY_CACHE_LISTING_CONTRACT = 1
};

static gpg_key_cache_entry_t g_key_cache[GPG_KEY_CACHE_MAX];
static uint64_t g_key_cache_sequence;

static void gpg_key_cache_home_generation_clear(
    gpg_key_cache_home_generation_t *generation) {
    size_t index;

    if (!generation) return;
    for (index = 0; index < generation->count; index++) {
        free(generation->entries[index].relative_path);
    }
    free(generation->entries);
    memset(generation, 0, sizeof(*generation));
}

static bool gpg_key_cache_stat_equal(const struct stat *left,
                                     const struct stat *right) {
    return left && right && gpg_same_file_version(left, right) &&
           left->st_gid == right->st_gid &&
           left->st_rdev == right->st_rdev;
}

static int gpg_key_cache_home_entry_compare(const void *left,
                                            const void *right) {
    const gpg_key_cache_home_entry_t *a = left;
    const gpg_key_cache_home_entry_t *b = right;

    return strcmp(a->relative_path, b->relative_path);
}

static int gpg_key_cache_home_generation_append(
    gpg_key_cache_home_generation_t *generation, const char *relative_path,
    const struct stat *identity) {
    gpg_key_cache_home_entry_t *grown;
    gpg_key_cache_home_entry_t *entry;
    size_t capacity;

    if (!generation || !relative_path || !*relative_path || !identity) {
        errno = EINVAL;
        return -1;
    }
    if (generation->count >= GPG_KEY_CACHE_MAX_HOME_ENTRIES) {
        errno = E2BIG;
        return -1;
    }
    if (generation->count == generation->capacity) {
        capacity = generation->capacity == 0
                       ? 32U
                       : generation->capacity * 2U;
        if (capacity > GPG_KEY_CACHE_MAX_HOME_ENTRIES) {
            capacity = GPG_KEY_CACHE_MAX_HOME_ENTRIES;
        }
        grown = realloc(generation->entries,
                        capacity * sizeof(*generation->entries));
        if (!grown) return -1;
        generation->entries = grown;
        generation->capacity = capacity;
    }
    entry = &generation->entries[generation->count];
    memset(entry, 0, sizeof(*entry));
    entry->relative_path = strdup(relative_path);
    if (!entry->relative_path) return -1;
    entry->identity = *identity;
    generation->count++;
    return 0;
}

static int gpg_key_cache_capture_directory(
    int directory_fd, const char *relative_prefix, unsigned int depth,
    const gpg_mount_identity_t *root_mount,
    gpg_key_cache_home_generation_t *generation) {
    struct stat directory_before;
    struct stat directory_after;
    gpg_mount_identity_t directory_mount;
    int scan_fd;
    DIR *directory;
    struct dirent *dirent;

    if (directory_fd < 0 || !relative_prefix || !root_mount || !generation ||
        depth > GPG_KEY_CACHE_MAX_DEPTH ||
        fstat(directory_fd, &directory_before) != 0 ||
        !S_ISDIR(directory_before.st_mode) ||
        gpg_mount_identity_fd(directory_fd, &directory_mount) != 0 ||
        !gpg_same_mount(root_mount, &directory_mount)) {
        if (errno == 0) errno = depth > GPG_KEY_CACHE_MAX_DEPTH ? E2BIG : EXDEV;
        return -1;
    }
    scan_fd = openat(directory_fd, ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0) return -1;
    directory = fdopendir(scan_fd);
    if (!directory) {
        int saved_errno = errno;

        close(scan_fd);
        errno = saved_errno;
        return -1;
    }
    for (;;) {
        char relative_path[MAX_PATH_LEN];
        struct stat named_before;
        struct stat named_after;

        errno = 0;
        dirent = readdir(directory);
        if (!dirent) {
            if (errno != 0) {
                int saved_errno = errno;

                closedir(directory);
                errno = saved_errno;
                return -1;
            }
            break;
        }
        if (strcmp(dirent->d_name, ".") == 0 ||
            strcmp(dirent->d_name, "..") == 0) {
            continue;
        }
        if ((relative_prefix[0]
                 ? safe_snprintf(relative_path, sizeof(relative_path),
                                 "%s/%s", relative_prefix, dirent->d_name)
                 : safe_snprintf(relative_path, sizeof(relative_path), "%s",
                                 dirent->d_name)) != 0 ||
            fstatat(directory_fd, dirent->d_name, &named_before,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            int saved_errno = errno;

            closedir(directory);
            errno = saved_errno;
            return -1;
        }
        /* A symlink's inode metadata does not bind the content reached by
         * GnuPG. Decline caching instead of turning an unobserved target into
         * reusable key evidence; the authoritative listing still runs. */
        if (S_ISLNK(named_before.st_mode)) {
            closedir(directory);
            errno = ELOOP;
            return -1;
        }
        if (gpg_key_cache_home_generation_append(
                generation, relative_path, &named_before) != 0) {
            int saved_errno = errno;

            closedir(directory);
            errno = saved_errno;
            return -1;
        }
        if (S_ISDIR(named_before.st_mode)) {
            struct stat opened;
            gpg_mount_identity_t child_mount;
            int child_fd = openat(
                directory_fd, dirent->d_name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

            if (child_fd < 0 || fstat(child_fd, &opened) != 0 ||
                gpg_mount_identity_fd(child_fd, &child_mount) != 0 ||
                !gpg_same_mount(root_mount, &child_mount) ||
                !gpg_key_cache_stat_equal(&named_before, &opened) ||
                gpg_key_cache_capture_directory(
                    child_fd, relative_path, depth + 1U, root_mount,
                    generation) != 0 ||
                fstatat(directory_fd, dirent->d_name, &named_after,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                !gpg_key_cache_stat_equal(&opened, &named_after)) {
                int saved_errno = errno ? errno : ESTALE;

                if (child_fd >= 0) close(child_fd);
                closedir(directory);
                errno = saved_errno;
                return -1;
            }
            close(child_fd);
        } else {
            if (fstatat(directory_fd, dirent->d_name, &named_after,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                !gpg_key_cache_stat_equal(&named_before, &named_after)) {
                int saved_errno = errno ? errno : ESTALE;

                closedir(directory);
                errno = saved_errno;
                return -1;
            }
        }
    }
    if (fstat(directory_fd, &directory_after) != 0 ||
        !gpg_key_cache_stat_equal(&directory_before, &directory_after)) {
        int saved_errno = errno ? errno : ESTALE;

        closedir(directory);
        errno = saved_errno;
        return -1;
    }
    closedir(directory);
    return 0;
}

static int gpg_key_cache_home_generation_capture_once(
    int home_fd, const char *path, gpg_key_cache_home_kind_t kind,
    gpg_key_cache_home_generation_t *generation) {
    struct stat root_after;

    if (home_fd < 0 || !path || path[0] != '/' || !generation) {
        errno = EINVAL;
        return -1;
    }
    memset(generation, 0, sizeof(*generation));
    generation->kind = kind;
    if (safe_strncpy(generation->path, path,
                     sizeof(generation->path)) != 0 ||
        fstat(home_fd, &generation->root_identity) != 0 ||
        !S_ISDIR(generation->root_identity.st_mode) ||
        gpg_mount_identity_fd(home_fd, &generation->root_mount) != 0 ||
        gpg_key_cache_capture_directory(
            home_fd, "", 0, &generation->root_mount, generation) != 0 ||
        fstat(home_fd, &root_after) != 0 ||
        !gpg_key_cache_stat_equal(&generation->root_identity, &root_after)) {
        int saved_errno = errno ? errno : ESTALE;

        gpg_key_cache_home_generation_clear(generation);
        errno = saved_errno;
        return -1;
    }
    if (generation->count > 1) {
        qsort(generation->entries, generation->count,
              sizeof(*generation->entries),
              gpg_key_cache_home_entry_compare);
    }
    generation->valid = true;
    return 0;
}

static bool gpg_key_cache_home_generation_equal(
    const gpg_key_cache_home_generation_t *left,
    const gpg_key_cache_home_generation_t *right) {
    size_t index;

    if (!left || !right || !left->valid || !right->valid ||
        left->kind != right->kind || strcmp(left->path, right->path) != 0 ||
        !gpg_key_cache_stat_equal(&left->root_identity,
                                  &right->root_identity) ||
        !gpg_same_mount(&left->root_mount, &right->root_mount) ||
        left->count != right->count) {
        return false;
    }
    for (index = 0; index < left->count; index++) {
        if (strcmp(left->entries[index].relative_path,
                   right->entries[index].relative_path) != 0 ||
            !gpg_key_cache_stat_equal(&left->entries[index].identity,
                                      &right->entries[index].identity)) {
            return false;
        }
    }
    return true;
}

static int gpg_key_cache_home_generation_capture(
    int home_fd, const char *path, gpg_key_cache_home_kind_t kind,
    gpg_key_cache_home_generation_t *generation) {
    gpg_key_cache_home_generation_t first;
    gpg_key_cache_home_generation_t second;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    if (gpg_key_cache_home_generation_capture_once(
            home_fd, path, kind, &first) != 0 ||
        gpg_key_cache_home_generation_capture_once(
            home_fd, path, kind, &second) != 0 ||
        !gpg_key_cache_home_generation_equal(&first, &second)) {
        int saved_errno = errno ? errno : ESTALE;

        gpg_key_cache_home_generation_clear(&first);
        gpg_key_cache_home_generation_clear(&second);
        errno = saved_errno;
        return -1;
    }
    gpg_key_cache_home_generation_clear(&second);
    *generation = first;
    return 0;
}

static bool gpg_key_cache_normalize_fingerprint(
    const char *selector, char fingerprint[GPG_FINGERPRINT_BUFSIZE]) {
    const char *digits;
    size_t length;
    size_t index;

    if (!selector || !fingerprint) return false;
    digits = selector;
    if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits += 2;
    }
    length = strlen(digits);
    if (length != 40 && length != 64) return false;
    for (index = 0; index < length; index++) {
        if (!isxdigit((unsigned char)digits[index])) return false;
        fingerprint[index] =
            (char)toupper((unsigned char)digits[index]);
    }
    fingerprint[length] = '\0';
    return true;
}

static int gpg_key_cache_home_coordinates(
    const gpg_pinned_home_t *home, const gpg_source_home_t *source,
    int *home_fd, const char **path, gpg_key_cache_home_kind_t *kind) {
    if (!home_fd || !path || !kind || (!home && !source) ||
        (home && source)) {
        errno = EINVAL;
        return -1;
    }
    if (home) {
        *home_fd = home->home_fd;
        *path = home->path;
        *kind = GPG_KEY_CACHE_HOME_ISOLATED;
    } else {
        *home_fd = source->fd;
        *path = source->path;
        *kind = GPG_KEY_CACHE_HOME_SYSTEM;
    }
    if (*home_fd < 0 || !*path || (*path)[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Return 1 for a reusable proof, 0 for an ordinary cache miss, and -1 when a
 * candidate's final public namespace binding changed during lookup. */
static int gpg_key_cache_lookup(
    const gpg_config_t *gpg_config, const gpg_pinned_home_t *home,
    const gpg_source_home_t *source, const char *selector,
    bool require_signing, char *fingerprint, size_t fingerprint_size) {
    error_context_t prior_error = g_last_error;
    int prior_errno = errno;
    char canonical[GPG_FINGERPRINT_BUFSIZE];
    gpg_key_cache_home_generation_t current;
    gpg_key_cache_home_generation_t confirmed;
    gpg_key_cache_home_kind_t kind;
    const char *path;
    int home_fd;
    size_t index;
    bool have_candidate = false;
    bool matched = false;
    bool fatal_binding = false;
    error_context_t fatal_error;
    int fatal_errno = 0;
    bool post_scan_checked = false;
    bool post_scan_failed = false;

    memset(&current, 0, sizeof(current));
    memset(&confirmed, 0, sizeof(confirmed));
    if (!gpg_config || gpg_config->executable_path[0] != '/' ||
        !fingerprint || fingerprint_size == 0 ||
        !gpg_key_cache_normalize_fingerprint(selector, canonical) ||
        strlen(canonical) + 1U > fingerprint_size ||
        gpg_key_cache_home_coordinates(home, source, &home_fd, &path,
                                       &kind) != 0) {
        g_last_error = prior_error;
        errno = prior_errno;
        return 0;
    }
    for (index = 0; index < GPG_KEY_CACHE_MAX; index++) {
        const gpg_key_cache_entry_t *entry = &g_key_cache[index];

        if (entry->valid &&
            entry->listing_contract == GPG_KEY_CACHE_LISTING_CONTRACT &&
            strcmp(entry->fingerprint, canonical) == 0 &&
            strcmp(entry->program, gpg_config->executable_path) == 0 &&
            entry->home.kind == kind &&
            strcmp(entry->home.path, path) == 0 &&
            (!require_signing || entry->signing_capability)) {
            have_candidate = true;
            break;
        }
    }
    if (have_candidate &&
        gpg_key_cache_home_generation_capture(home_fd, path, kind,
                                              &current) == 0) {
        for (index = 0; index < GPG_KEY_CACHE_MAX; index++) {
            gpg_key_cache_entry_t *entry = &g_key_cache[index];

            if (!entry->valid ||
                entry->listing_contract !=
                    GPG_KEY_CACHE_LISTING_CONTRACT ||
                strcmp(entry->fingerprint, canonical) != 0 ||
                strcmp(entry->program,
                       gpg_config->executable_path) != 0 ||
                entry->home.kind != kind ||
                strcmp(entry->home.path, path) != 0 ||
                (require_signing && !entry->signing_capability)) {
                continue;
            }
            if (!gpg_key_cache_home_generation_equal(&entry->home,
                                                     &current) ||
                !run_launch_witness_revalidate(
                    gpg_config->executable_path, &entry->launch)) {
                gpg_key_cache_home_generation_clear(&entry->home);
                memset(entry, 0, sizeof(*entry));
                continue;
            }
            if (!post_scan_checked) {
                post_scan_checked = true;
                post_scan_failed =
                    g_key_cache_post_scan_hook &&
                    g_key_cache_post_scan_hook(
                        path,
                        kind == GPG_KEY_CACHE_HOME_ISOLATED) != 0;
            }
            /* The executable check above is deliberately not the last proof:
             * recapture the complete home generation afterwards, then bind
             * the public source/managed-home namespace to the retained fd.
             * A rename/rebind during the first scan therefore cannot be
             * erased by the unchanged descriptor-backed tree. */
            {
                int generation_rc =
                    gpg_key_cache_home_generation_capture(
                        home_fd, path, kind, &confirmed);
                int binding_rc =
                    home ? gpg_validate_pinned_home(home)
                         : gpg_validate_source_home_binding(source);

                if (binding_rc != 0) {
                    fatal_error = g_last_error;
                    fatal_errno = errno;
                    fatal_binding = true;
                    gpg_key_cache_home_generation_clear(&confirmed);
                    gpg_key_cache_home_generation_clear(&entry->home);
                    memset(entry, 0, sizeof(*entry));
                    break;
                }
                if (post_scan_failed || generation_rc != 0 ||
                    !gpg_key_cache_home_generation_equal(
                        &entry->home, &confirmed)) {
                    gpg_key_cache_home_generation_clear(&confirmed);
                    gpg_key_cache_home_generation_clear(&entry->home);
                    memset(entry, 0, sizeof(*entry));
                    continue;
                }
            }
            gpg_key_cache_home_generation_clear(&confirmed);
            memcpy(fingerprint, canonical, strlen(canonical) + 1U);
            entry->sequence = ++g_key_cache_sequence;
            matched = true;
            break;
        }
    }
    gpg_key_cache_home_generation_clear(&current);
    gpg_key_cache_home_generation_clear(&confirmed);
    if (fatal_binding) {
        g_last_error = fatal_error;
        errno = fatal_errno;
        return -1;
    }
    g_last_error = prior_error;
    errno = prior_errno;
    return matched ? 1 : 0;
}

static void gpg_key_cache_store(
    const gpg_config_t *gpg_config, const gpg_pinned_home_t *home,
    const gpg_source_home_t *source, const char *fingerprint,
    bool require_signing, const run_launch_witness_t *launch) {
    error_context_t prior_error = g_last_error;
    int prior_errno = errno;
    char canonical[GPG_FINGERPRINT_BUFSIZE];
    gpg_key_cache_home_generation_t generation;
    gpg_key_cache_home_kind_t kind;
    const char *path;
    int home_fd;
    size_t selected = 0;
    uint64_t oldest = UINT64_MAX;
    size_t index;

    memset(&generation, 0, sizeof(generation));
    if (!run_uses_default_runner() || !launch || !launch->valid ||
        !gpg_config || gpg_config->executable_path[0] != '/' ||
        !gpg_key_cache_normalize_fingerprint(fingerprint, canonical) ||
        gpg_key_cache_home_coordinates(home, source, &home_fd, &path,
                                       &kind) != 0 ||
        gpg_key_cache_home_generation_capture(
            home_fd, path, kind, &generation) != 0) {
        gpg_key_cache_home_generation_clear(&generation);
        g_last_error = prior_error;
        errno = prior_errno;
        return;
    }
    for (index = 0; index < GPG_KEY_CACHE_MAX; index++) {
        if (!g_key_cache[index].valid) {
            selected = index;
            oldest = 0;
            break;
        }
        if (g_key_cache[index].sequence < oldest) {
            selected = index;
            oldest = g_key_cache[index].sequence;
        }
    }
    gpg_key_cache_home_generation_clear(&g_key_cache[selected].home);
    memset(&g_key_cache[selected], 0, sizeof(g_key_cache[selected]));
    g_key_cache[selected].valid = true;
    g_key_cache[selected].signing_capability = require_signing;
    g_key_cache[selected].sequence = ++g_key_cache_sequence;
    g_key_cache[selected].listing_contract =
        GPG_KEY_CACHE_LISTING_CONTRACT;
    memcpy(g_key_cache[selected].fingerprint, canonical,
           strlen(canonical) + 1U);
    if (safe_strncpy(g_key_cache[selected].program,
                     gpg_config->executable_path,
                     sizeof(g_key_cache[selected].program)) != 0) {
        gpg_key_cache_home_generation_clear(&generation);
        memset(&g_key_cache[selected], 0, sizeof(g_key_cache[selected]));
        g_last_error = prior_error;
        errno = prior_errno;
        return;
    }
    g_key_cache[selected].launch = *launch;
    g_key_cache[selected].home = generation;
    g_last_error = prior_error;
    errno = prior_errno;
}

static bool gpg_executable_may_try_compat_name(int resolve_errno) {
    switch (resolve_errno) {
        case ENOENT:
        case ENOTDIR:
        case EACCES:
        case EPERM:
        case ELOOP:
        case EINVAL:
        case ENAMETOOLONG:
        case ENOEXEC:
        case E2BIG:
        case ENOTSUP:
            return true;
        default:
            return false;
    }
}

/* Resolve one OpenPGP program spelling for every GPG-facing subsystem. A
 * missing or launch-policy-ineligible `gpg` permits the documented `gpg2`
 * compatibility name; an operational failure does not get hidden by a
 * successful fallback. */
int gpg_manager_resolve_executable(char *path, size_t path_size) {
    int resolve_errno;

    if (!path || path_size == 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG executable path destination");
        return -1;
    }
    path[0] = '\0';

    if (find_command_path("gpg", path, path_size) == 0) {
        return 0;
    }
    resolve_errno = errno;
    if (!gpg_executable_may_try_compat_name(resolve_errno)) {
        path[0] = '\0';
        errno = resolve_errno;
        set_system_error(ERR_GPG_NOT_FOUND,
                         "Failed to validate trusted GPG executable 'gpg'");
        errno = resolve_errno;
        return -1;
    }
    path[0] = '\0';

    if (find_command_path("gpg2", path, path_size) == 0) {
        return 0;
    }
    resolve_errno = errno;
    path[0] = '\0';
    if (!gpg_executable_may_try_compat_name(resolve_errno)) {
        errno = resolve_errno;
        set_system_error(ERR_GPG_NOT_FOUND,
                         "Failed to validate trusted GPG executable 'gpg2'");
    } else {
        set_error(ERR_GPG_NOT_FOUND,
                  "No trusted GPG executable ('gpg' or 'gpg2') found in PATH");
    }
    errno = resolve_errno;
    return -1;
}

static int gpg_bind_executable_if_needed(gpg_config_t *gpg_config) {
    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Missing GPG manager configuration");
        return -1;
    }
    if (gpg_config->executable_path[0] != '\0') {
        if (gpg_config->executable_path[0] != '/') {
            set_error(ERR_GPG_NOT_FOUND,
                      "GPG manager executable binding is not absolute");
            return -1;
        }
        return 0;
    }
    return gpg_manager_resolve_executable(gpg_config->executable_path,
                                          sizeof(gpg_config->executable_path));
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
    
    /* Bind the exact trusted executable spelling for this transaction. Every
     * manager helper below receives this absolute path instead of consulting
     * a possibly changed PATH again. */
    if (gpg_bind_executable_if_needed(gpg_config) != 0) {
        return -1;
    }
    
    log_info("GPG manager initialized successfully");
    return 0;
}

static void gpg_clear_environment_snapshot(gpg_config_t *gpg_config) {
    if (!gpg_config) return;
    gpg_config->previous_gnupg_home_present = false;
    gpg_config->previous_gnupg_home[0] = '\0';
    gpg_config->previous_gpg_agent_info_present = false;
    gpg_config->previous_gpg_agent_info[0] = '\0';
}

static int gpg_restore_environment(gpg_config_t *gpg_config) {
    int env_rc;

    if (!gpg_config || !gpg_config->environment_installed) {
        return 0;
    }

    /* Restore the home before reintroducing a legacy agent selector. If the
     * home leg fails, leaving GPG_AGENT_INFO suppressed is the only safe
     * retryable state: a managed home must never be paired with an unrelated
     * inherited GnuPG 2.0 agent. */
    if (gpg_config->gnupg_home_environment_installed) {
        if (gpg_config->previous_gnupg_home_present) {
            env_rc = g_gpg_setenv("GNUPGHOME",
                                  gpg_config->previous_gnupg_home, 1);
        } else {
            env_rc = g_gpg_unsetenv("GNUPGHOME");
        }
        if (env_rc != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to restore GNUPGHOME environment variable");
            return -1;
        }
        gpg_config->gnupg_home_environment_installed = false;
        gpg_config->previous_gnupg_home_present = false;
        gpg_config->previous_gnupg_home[0] = '\0';
    }

    if (gpg_config->gpg_agent_info_suppressed) {
        if (gpg_config->previous_gpg_agent_info_present) {
            env_rc = g_gpg_setenv("GPG_AGENT_INFO",
                                  gpg_config->previous_gpg_agent_info, 1);
        } else {
            env_rc = g_gpg_unsetenv("GPG_AGENT_INFO");
        }
        if (env_rc != 0) {
            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to restore GPG_AGENT_INFO environment variable");
            return -1;
        }
        gpg_config->gpg_agent_info_suppressed = false;
        gpg_config->previous_gpg_agent_info_present = false;
        gpg_config->previous_gpg_agent_info[0] = '\0';
    }

    gpg_config->environment_installed =
        gpg_config->gnupg_home_environment_installed ||
        gpg_config->gpg_agent_info_suppressed;
    if (!gpg_config->environment_installed) {
        gpg_clear_environment_snapshot(gpg_config);
    }
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

    /* This cleanup completes one switch transaction; it deliberately does not
     * delete persistent per-account GNUPGHOMEs. The user's shell may still
     * resolve GNUPGHOME through <base>/current, and switch-back reuses an
     * existing validated home without re-importing its key. Explicit
     * `gitswitch reset [account]` invokes gpg_manager_reset(), which owns agent
     * shutdown, home deletion, stable-link retirement, and durability. */

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
    if (gpg_bind_executable_if_needed(gpg_config) != 0) {
        return -1;
    }

    log_info("Switching to GPG configuration for account: %s", account->name);
    log_debug("Account GPG key ID: %s", account->gpg_key_id);

    /* Handle different GPG modes */
    switch (gpg_config->mode) {
        case GPG_MODE_SYSTEM:
            if (gpg_resolve_source_key(gpg_config, account->gpg_key_id,
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
            base_fd = gpg_prepare_base_dir(locked_base,
                                           sizeof(locked_base));
            if (base_fd < 0) {
                set_error(ERR_GPG_KEY_FAILED, "Failed to create isolated GPG environment: %s",
                         get_last_error()->message);
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
            if (gpg_resolve_source_key(gpg_config, account->gpg_key_id,
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

/* Compute the base directory that holds per-account isolated GNUPGHOMEs and the
 * stable `current` symlink. Two-way like the SSH side: use a configured,
 * valid XDG_RUNTIME_DIR, or /tmp/gitswitch-gpg-<uid> only when that variable
 * is unset/empty. A configured missing/invalid root fails closed. There is
 * deliberately no HOME fallback: that
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
         * /tmp (AR-02 #22). This pathname probe is diagnostic only. The
         * create path separately enforces policy from the exact retained base
         * descriptor and never treats this warning latch as authorization. */
        written = snprintf(child, sizeof(child), "gitswitch-gpg-%d", getuid());
    }
    if (written < 0 || (size_t)written >= sizeof(child)) {
        set_error(ERR_INVALID_PATH, "GPG base directory name too long");
        return -1;
    }
    written = snprintf(buf, size, "%s/%s", runtime_parent, child);
    if (strcmp(runtime_parent, "/tmp") == 0) {
        if (!g_gpg_suppress_base_warning && written > 0 &&
            (size_t)written < size && !g_base_warning_probe_checked) {
            g_base_warning_memory_backed = g_base_warning_probe(buf);
            g_base_warning_probe_checked = true;
        }
        if (!g_gpg_suppress_base_warning &&
            g_base_warning_probe_checked &&
            !g_base_warning_memory_backed &&
            !g_base_warning_emitted) {
            g_base_warning_emitted = true;
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

/* Determine the storage type of the exact directory descriptor that will
 * contain isolated secret-key material. Unknown platforms and syscall errors
 * fail closed; pathname observations are intentionally not accepted here. */
static int gpg_default_memory_backed_probe(int base_fd,
                                           bool *memory_backed) {
    struct statfs mounted;

    if (base_fd < 0 || !memory_backed) {
        errno = EINVAL;
        return -1;
    }
    *memory_backed = false;
    if (fstatfs(base_fd, &mounted) != 0) {
        return -1;
    }
#ifdef __linux__
    {
        unsigned long type = (unsigned long)mounted.f_type;
        *memory_backed =
            type == 0x01021994UL /* TMPFS_MAGIC */ ||
            type == 0x858458f6UL /* RAMFS_MAGIC */;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    *memory_backed =
        memchr(mounted.f_fstypename, '\0',
               sizeof(mounted.f_fstypename)) != NULL &&
        strcmp(mounted.f_fstypename, "tmpfs") == 0;
#else
    (void)mounted;
    errno = ENOTSUP;
    return -1;
#endif
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
 * writer of the GPG runtime state — `current` retarget/drop and reset's home
 * enumeration, teardown, and current-link retirement — against each other
 * across processes (AR-02 #9: an unlocked reset could TOCTOU a concurrent
 * switch and unlink the live link it had just installed).
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

enum {
    GPG_SOURCE_PROOF_MAX_DEPTH = 64,
    GPG_SOURCE_PROOF_MAX_DIRECTORIES = 16384,
    GPG_SOURCE_PROOF_MAX_ENTRIES = 65536,
    GPG_SOURCE_PROOF_MAX_NULLFS_HOPS = 32
};

#define GPG_ROLLBACK_PREFIX ".gitswitch-gpg-rollback."
#define GPG_PUBLISH_PREFIX ".gitswitch-gpg-publish."
#define GPG_RESET_PREFIX ".gitswitch-gpg-reset."
#define GPG_RESET_WITNESS_SUFFIX ".witness"

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
             gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX) ||
             gpg_name_has_prefix(entry->d_name, GPG_RESET_PREFIX)) &&
            (!allowed_name || strcmp(entry->d_name, allowed_name) != 0)) {
            char stale[GPG_QUARANTINE_NAME_LEN];
            safe_strncpy(stale, entry->d_name, sizeof(stale));
            closedir(dir);
            /* AR-13 L24: only a FULL reset (no account argument) retires this
             * residue, and a full reset rebuilds every account's isolated GPG
             * home — say so rather than implying a cheap targeted fix. */
            set_error(ERR_FILE_IO,
                      "Unresolved GPG runtime quarantine blocks mutation: %s "
                      "(run 'gitswitch reset' with no account to retire it; "
                      "note a full reset rebuilds every account's isolated GPG "
                      "home)",
                      stale);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}

/* AR-12 L11: a SIGKILL/power loss between quarantine creation and its
 * unlink orphans a .gitswitch-gpg-rollback.* / .gitswitch-gpg-publish.*
 * symlink with no in-memory token, and the stale-quarantine gate then
 * blocks every switch, drop, AND reset forever. Full reset deletes every
 * managed home anyway, so an owned orphaned quarantine SYMLINK preserves
 * nothing — retire it. Anything that is not an owned symlink stays fatal. */
static int gpg_retire_orphan_quarantines_locked(int base_fd) {
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
                         "Cannot inspect GPG quarantine residue");
        return -1;
    }
    for (;;) {
        struct stat orphan;

        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Cannot enumerate GPG quarantine residue");
                return -1;
            }
            break;
        }
        /* AR-13 L4: also retire orphaned reset-prefix residue. Full reset runs
         * gpg_reconcile_reset_retry_locked first (and fails closed if it does
         * not succeed), which retires every VALID witnessed reset retry, so any
         * reset-prefix name still present here is a malformed or unwitnessed
         * orphan — previously it had no auto-clear path and bricked switch,
         * drop AND reset via the stale-quarantine gate. The S_ISLNK/uid gate
         * and the live-owner (pid) guard below apply to it exactly as to the
         * rollback/publish residue. */
        if (!gpg_name_has_prefix(entry->d_name, GPG_ROLLBACK_PREFIX) &&
            !gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX) &&
            !gpg_name_has_prefix(entry->d_name, GPG_RESET_PREFIX)) {
            continue;
        }
        if (fstatat(base_fd, entry->d_name, &orphan,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect GPG quarantine residue: %s",
                             entry->d_name);
            closedir(dir);
            return -1;
        }
        if (!S_ISLNK(orphan.st_mode) || orphan.st_uid != getuid()) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing foreign GPG quarantine residue: %s",
                      entry->d_name);
            closedir(dir);
            return -1;
        }
        /* AR-13 M8: a quarantine name is {prefix}{pid}.{16-hex}. If that pid is
         * a DIFFERENT still-live process of ours, this is not a crash orphan
         * but the live retry handle of a concurrent gitswitch (a rollback token
         * retained across lock releases after an I/O/hook failure). Retiring it
         * here — before the destructive pass, and even if the all-or-nothing
         * preflight later aborts and deletes nothing else — would strand that
         * owner's recovery. Fail the reset instead of deleting live-owned state;
         * the user can retry once the other process completes. A genuine crash
         * orphan has a dead pid (kill -> ESRCH), and this process's own residue
         * (pid == getpid()) is still cleared, so L11's wedge-clearing holds. */
        {
            const char *pid_str = entry->d_name +
                (gpg_name_has_prefix(entry->d_name, GPG_ROLLBACK_PREFIX)
                     ? strlen(GPG_ROLLBACK_PREFIX)
                 : gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX)
                     ? strlen(GPG_PUBLISH_PREFIX)
                     : strlen(GPG_RESET_PREFIX));

            if (*pid_str >= '1' && *pid_str <= '9') {
                long pid = 0;
                bool parsed = true;

                for (; *pid_str && *pid_str != '.'; pid_str++) {
                    if (!isdigit((unsigned char)*pid_str) ||
                        pid > (LONG_MAX - 9) / 10) {
                        parsed = false;
                        break;
                    }
                    pid = pid * 10 + (*pid_str - '0');
                }
                if (parsed && pid > 0 && (pid_t)pid != getpid()) {
                    errno = 0;
                    if (kill((pid_t)pid, 0) == 0 || errno == EPERM) {
                        set_error(ERR_FILE_IO,
                                  "Refusing to retire a GPG quarantine held by "
                                  "a live gitswitch process (pid %ld): %s; "
                                  "retry reset after it completes",
                                  pid, entry->d_name);
                        closedir(dir);
                        return -1;
                    }
                }
            }
        }
        if (unlinkat(base_fd, entry->d_name, 0) != 0 && errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot retire orphaned GPG quarantine: %s",
                             entry->d_name);
            closedir(dir);
            return -1;
        }
        log_warning("Retired orphaned GPG quarantine residue: %s",
                    entry->d_name);
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

typedef struct {
    bool quarantine_present;
    bool witness_present;
    char quarantine[GPG_QUARANTINE_NAME_LEN];
    char witness[GPG_QUARANTINE_NAME_LEN];
} gpg_reset_retry_state_t;

static bool gpg_valid_private_name(const char *name, const char *prefix) {
    const char *cursor;
    const char *random;
    size_t prefix_len;

    if (!name || !prefix) return false;
    prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) != 0) return false;
    cursor = name + prefix_len;
    if (*cursor < '1' || *cursor > '9') return false;
    while (isdigit((unsigned char)*cursor)) cursor++;
    if (*cursor != '.') return false;
    random = ++cursor;
    if (strlen(random) != 16U) return false;
    for (size_t i = 0; i < 16U; i++) {
        if (!strchr("0123456789abcdef", random[i])) return false;
    }
    return true;
}

static int gpg_reset_witness_name(const char *quarantine,
                                  char *witness, size_t size) {
    int written;

    if (!quarantine || !witness || size == 0 ||
        !gpg_valid_private_name(quarantine, GPG_RESET_PREFIX)) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG reset retry name");
        return -1;
    }
    written = snprintf(witness, size, "%s%s", quarantine,
                       GPG_RESET_WITNESS_SUFFIX);
    if (written < 0 || (size_t)written >= size) {
        set_error(ERR_INVALID_PATH, "GPG reset witness name is too long");
        return -1;
    }
    return 0;
}

static int gpg_scan_reset_retry_locked(int base_fd,
                                       gpg_reset_retry_state_t *state) {
    int flags = O_RDONLY | O_CLOEXEC;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;
    size_t suffix_len = strlen(GPG_RESET_WITNESS_SUFFIX);

    if (base_fd < 0 || !state) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG reset retry scan");
        return -1;
    }
    memset(state, 0, sizeof(*state));
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
                         "Cannot inspect GPG reset retry state");
        return -1;
    }
    for (;;) {
        bool witness_entry;
        char quarantine[GPG_QUARANTINE_NAME_LEN];
        size_t name_len;
        size_t quarantine_len;

        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(ERR_FILE_IO,
                                 "Cannot enumerate GPG reset retry state");
                return -1;
            }
            break;
        }
        if (!gpg_name_has_prefix(entry->d_name, GPG_RESET_PREFIX)) continue;
        name_len = strlen(entry->d_name);
        witness_entry = name_len > suffix_len &&
            strcmp(entry->d_name + name_len - suffix_len,
                   GPG_RESET_WITNESS_SUFFIX) == 0;
        quarantine_len = witness_entry ? name_len - suffix_len : name_len;
        if (quarantine_len == 0 || quarantine_len >= sizeof(quarantine) ||
            (witness_entry && name_len >= sizeof(state->witness))) {
            char residue[GPG_QUARANTINE_NAME_LEN];
            safe_strncpy(residue, entry->d_name, sizeof(residue));
            closedir(dir);
            set_error(ERR_FILE_IO,
                      "Malformed GPG reset retry entry blocks mutation: %s",
                      residue);
            return -1;
        }
        memcpy(quarantine, entry->d_name, quarantine_len);
        quarantine[quarantine_len] = '\0';
        if (!gpg_valid_private_name(quarantine, GPG_RESET_PREFIX) ||
            (witness_entry && state->witness_present) ||
            (!witness_entry && state->quarantine_present)) {
            char residue[GPG_QUARANTINE_NAME_LEN];
            safe_strncpy(residue, entry->d_name, sizeof(residue));
            closedir(dir);
            set_error(ERR_FILE_IO,
                      "Ambiguous GPG reset retry entry blocks mutation: %s",
                      residue);
            return -1;
        }
        if (witness_entry) {
            safe_strncpy(state->witness, entry->d_name,
                         sizeof(state->witness));
            state->witness_present = true;
            if (state->quarantine_present &&
                strcmp(state->quarantine, quarantine) != 0) {
                closedir(dir);
                set_error(ERR_FILE_IO,
                          "Multiple GPG reset retry transactions block mutation");
                return -1;
            }
            if (!state->quarantine_present) {
                safe_strncpy(state->quarantine, quarantine,
                             sizeof(state->quarantine));
            }
        } else {
            safe_strncpy(state->quarantine, entry->d_name,
                         sizeof(state->quarantine));
            state->quarantine_present = true;
            if (state->witness_present) {
                char expected[GPG_QUARANTINE_NAME_LEN];
                if (gpg_reset_witness_name(quarantine, expected,
                                           sizeof(expected)) != 0 ||
                    strcmp(expected, state->witness) != 0) {
                    closedir(dir);
                    set_error(ERR_FILE_IO,
                              "Multiple GPG reset retry transactions block mutation");
                    return -1;
                }
            }
        }
    }
    if (closedir(dir) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Cannot close GPG reset retry scan");
        return -1;
    }
    return 0;
}

static int gpg_retire_reset_link_locked(
    int base_fd, const char *name, const gpg_link_identity_t *expected,
    const char *description) {
    gpg_link_identity_t observed;

    if (gpg_capture_link_at(base_fd, name, &observed) != 0 ||
        !gpg_same_link(&observed, expected)) {
        set_error(ERR_FILE_IO,
                  "%s changed; preserving replacement: %s", description,
                  name);
        return -1;
    }
    if (unlinkat(base_fd, name, 0) != 0) {
        set_system_error(ERR_FILE_IO, "Cannot remove %s: %s", description,
                         name);
        return -1;
    }
    if (g_sync_base(base_fd) != 0) {
        set_system_error(ERR_FILE_IO, "Cannot synchronize %s", description);
        return -1;
    }
    return 0;
}

/* A reset publishes a hard-link witness before moving `current`.  The witness
 * name encodes the generated quarantine name and its inode is the captured
 * symlink identity, so a later process can recover without guessing from an
 * untrusted serialized record.  Retirement is ordered quarantine -> fsync ->
 * witness -> fsync: no durable state can expose an unauthenticated quarantine
 * after the last identity witness has disappeared. */
static int gpg_reconcile_reset_retry_locked(int base_fd) {
    gpg_reset_retry_state_t state;
    gpg_link_identity_t quarantine;
    gpg_link_identity_t witness;

    if (gpg_scan_reset_retry_locked(base_fd, &state) != 0) return -1;
    if (!state.quarantine_present && !state.witness_present) return 0;
    if (!state.witness_present) {
        set_error(ERR_FILE_IO,
                  "Unwitnessed GPG reset quarantine preserved: %s",
                  state.quarantine);
        return -1;
    }
    if (gpg_capture_link_at(base_fd, state.witness, &witness) != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot identify GPG reset retry witness: %s",
                  state.witness);
        return -1;
    }
    if (state.quarantine_present) {
        if (gpg_capture_link_at(base_fd, state.quarantine, &quarantine) != 0 ||
            !gpg_same_link(&quarantine, &witness)) {
            set_error(ERR_FILE_IO,
                      "GPG reset quarantine differs from its witness; replacement preserved: %s",
                      state.quarantine);
            return -1;
        }
        if (gpg_retire_reset_link_locked(
                base_fd, state.quarantine, &witness,
                "witnessed GPG reset quarantine") != 0) {
            return -1;
        }
    }
    return gpg_retire_reset_link_locked(
        base_fd, state.witness, &witness, "GPG reset retry witness");
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
    gpg_mount_identity_t base_mount;
    gpg_mount_identity_t home_mount;

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
    if (gpg_mount_identity_fd(home->base_fd, &base_mount) != 0 ||
        gpg_mount_identity_fd(home->home_fd, &home_mount) != 0) {
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot prove isolated GPG home mount boundary: %s",
                         home->path);
        return -1;
    }
    if (!gpg_same_mount(&base_mount, &home_mount)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing isolated GPG home mounted outside its memory-backed base: %s",
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
    if (prev_existed) {
        int prev_live = -1;

        if (gpg_target_is_managed_child(base, prev_target)) {
            prev_live = gpg_live_private_home(base_fd, base, prev_target);
        }
        if (prev_live == 1) {
            /* AR-12 L10: `current` dangles — a crash between home removal
             * and current retirement (or a manual rm of one home) leaves
             * current -> <deleted-account>. There is no home to preserve,
             * so proceed and let a failed retarget restore ABSENCE rather
             * than the dangling spelling. */
            log_warning(
                "Previous GNUPGHOME target no longer exists; replacing the dangling current link: %s",
                prev_target);
            clear_error();
            prev_existed = false;
        } else if (prev_live != 0) {
            set_error(
                ERR_INVALID_PATH,
                "Refusing to replace unsafe previous GNUPGHOME target: %s",
                prev_target);
            return -1;
        }
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
 * the retarget cannot interleave with a concurrent reset's home teardown or
 * current-link retirement (AR-02 #9). The forward switch does NOT come through
 * here: it retargets via gpg_retarget_current_locked under the lock it already
 * holds across create+import (AR-03 L12) — flock on a second fd for the same lock
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
 * unlink could delete the fresh link a concurrent switch just installed.
 * Success proves the directory entry durable; an already-absent retry syncs
 * the base again so it can repair a prior unlink whose sync failed. */
int gpg_manager_drop_current(void) {
    char base[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN];
    struct stat link_st;
    int base_fd = -1;
    int lock_fd = -1;
    int base_rc;
    int rc = 0;
    bool current_absent = false;

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
        } else {
            current_absent = true;
        }
    } else if (!S_ISLNK(link_st.st_mode)) {
        set_error(ERR_FILE_IO, "Stable GNUPGHOME entry is not a symlink: %s",
                  link_path);
        rc = -1;
    } else if (unlinkat(base_fd, "current", 0) != 0) {
        if (errno == ENOENT) {
            current_absent = true;
        } else {
            set_system_error(ERR_FILE_IO,
                             "Failed to remove stable GNUPGHOME link: %s",
                             link_path);
            rc = -1;
        }
    } else {
        current_absent = true;
    }
    if (rc == 0 && current_absent && g_sync_base(base_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Stable GNUPGHOME removal is not durable; retry runtime deactivation");
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

/* Capture the kernel mount identity for a pinned directory. Linux st_dev is
 * deliberately not used: a bind mount of the same filesystem (or even the
 * same inode) keeps st_dev while crossing into a distinct mount. statx's mount
 * ID closes that gap. macOS and FreeBSD expose the corresponding filesystem
 * identity through fstatfs; uncertainty on an unsupported platform fails
 * closed instead of silently weakening reset.
 *
 * AR-12 P10 (documented floor): STATX_MNT_ID needs Linux kernel >= 5.8
 * (stx_mask leaves the bit clear on older kernels), so ISOLATED-mode GPG
 * operations fail closed with ENOTSUP there. Shared-mode GPG is unaffected.
 * 5.8 predates every supported distribution's floor; raising a clearer
 * diagnostic below keeps the constraint visible rather than silent. */
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
/* AR-12 P3: bounded like the twin source-proof walk — each frame holds a
 * DIR stream and a child fd, so unbounded recursion is both a stack and an
 * fd-exhaustion hazard on an adversarially deep tree. */
static int gpg_walk_tree_contents_fd(
    int dir_fd, const char *display_path,
    const gpg_mount_identity_t *root_mount, bool remove_entries,
    unsigned int depth) {
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
    if (depth > GPG_SOURCE_PROOF_MAX_DEPTH) {
        errno = ELOOP;
        set_error(ERR_INVALID_PATH,
                  "Isolated GPG home exceeds the bounded reset walk depth: %s",
                  display_path);
        return -1;
    }
    scan_fd = openat(dir_fd, ".", scan_flags);
    dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        int saved_errno = errno;
        if (scan_fd >= 0) close(scan_fd);
        errno = saved_errno;
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
                                          remove_entries, depth + 1U) != 0) {
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
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false, 0U) != 0) {
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
            gpg_name_has_prefix(entry->d_name, GPG_PUBLISH_PREFIX) ||
            gpg_name_has_prefix(entry->d_name, GPG_RESET_PREFIX)) {
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
    bool saw_lock = false;

    if (verify_private_lock_file_at(lock_fd, base_fd, ".lock") != 0) {
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
        int saved_errno = errno;
        if (scan_fd >= 0) close(scan_fd);
        errno = saved_errno;
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
        verify_private_lock_file_at(lock_fd, base_fd, ".lock") != 0) {
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
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false, 0U) != 0) {
        close(home_fd);
        return -1;
    }

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.unset_env = g_gpg_child_unset_env;
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
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, false, 0U) != 0) {
        close(home_fd);
        return -1;
    }
    if (g_cleanup_predelete && g_cleanup_predelete(home_fd) != 0) {
        close(home_fd);
        set_error(ERR_FILE_IO, "GPG cleanup pre-delete hook failed: %s", home);
        return -1;
    }
    if (gpg_walk_tree_contents_fd(home_fd, home, &base_mount, true, 0U) != 0) {
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

/* Remove only the exact `current` inode reset inspected. Before moving the
 * public name, publish and synchronize a private hard-link witness whose name
 * encodes the destination quarantine. Both names then carry the same symlink
 * inode and target. A later reset can retire that exact pair without relying
 * on the already-deleted home or on unauthenticated serialized metadata. */
static int gpg_remove_captured_current_locked(
    int base_fd, const char *base, const gpg_link_identity_t *captured,
    bool *changed) {
    char quarantine[GPG_QUARANTINE_NAME_LEN] = "";
    char witness_name[GPG_QUARANTINE_NAME_LEN] = "";
    gpg_link_identity_t moved;
    gpg_link_identity_t current;
    gpg_link_identity_t witness;
    int current_rc;
    int quarantine_rc;
    int witness_rc;

    if (base_fd < 0 || !base || !*base || !captured || !captured->valid ||
        !changed) {
        set_error(ERR_INVALID_ARGS, "Invalid captured GNUPGHOME reset state");
        return -1;
    }
    *changed = false;
    if (gpg_make_private_name(quarantine, sizeof(quarantine),
                              GPG_RESET_PREFIX) != 0 ||
        gpg_reset_witness_name(quarantine, witness_name,
                               sizeof(witness_name)) != 0 ||
        gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        return -1;
    }
    if (g_reset_current_hook && g_reset_current_hook(base_fd) != 0) {
        set_error(ERR_FILE_IO, "GPG reset current-link hook failed");
        return -1;
    }
    if (linkat(base_fd, "current", base_fd, witness_name, 0) != 0) {
        int saved_errno = errno;
        if (saved_errno == ENOENT) {
            *changed = true;
            set_error(ERR_FILE_IO,
                      "Stable GNUPGHOME changed during reset; later absence preserved");
        } else {
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot publish GPG reset identity witness");
        }
        return -1;
    }
    witness_rc = gpg_capture_link_at(base_fd, witness_name, &witness);
    if (witness_rc != 0) {
        (void)g_sync_base(base_fd);
        set_error(ERR_FILE_IO,
                  "Cannot identify GPG reset witness; retry state retained");
        return -1;
    }
    if (!gpg_same_link(&witness, captured)) {
        if (gpg_retire_reset_link_locked(
                base_fd, witness_name, &witness,
                "superseded GPG reset witness") != 0) {
            return -1;
        }
        *changed = true;
        set_error(ERR_FILE_IO,
                  "Stable GNUPGHOME changed during reset; later writer preserved: %s",
                  witness.target);
        return 0;
    }
    if (g_sync_base(base_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot synchronize GPG reset witness; retry state retained");
        return -1;
    }
    if (g_rename_noreplace(base_fd, "current", base_fd, quarantine) != 0) {
        int saved_errno = errno;
        if (gpg_retire_reset_link_locked(
                base_fd, witness_name, &witness,
                "unpublished GPG reset witness") != 0) {
            return -1;
        }
        if (saved_errno == ENOENT) {
            *changed = true;
            set_error(ERR_FILE_IO,
                      "Stable GNUPGHOME changed during reset; later absence preserved");
        } else if (saved_errno == ENOTSUP ||
#if EOPNOTSUPP != ENOTSUP
                   saved_errno == EOPNOTSUPP ||
#endif
                   saved_errno == ENOSYS || saved_errno == EINVAL) {
            set_error(ERR_FILE_IO,
                      "Platform lacks atomic no-replace GPG reset quarantine");
        } else {
            errno = saved_errno;
            set_system_error(ERR_FILE_IO,
                             "Cannot quarantine stable GNUPGHOME during reset");
        }
        return -1;
    }
    if (g_sync_base(base_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "Cannot synchronize GPG reset quarantine; retry state retained");
        return -1;
    }
    if (g_reset_quarantine_hook &&
        g_reset_quarantine_hook(
            base_fd, GPG_RESET_QUARANTINE_HOOK_AFTER_RENAME,
            quarantine) != 0) {
        set_error(ERR_FILE_IO,
                  "GPG reset quarantine capture hook failed; retry state retained");
        return -1;
    }
    quarantine_rc = gpg_capture_link_at(base_fd, quarantine, &moved);
    witness_rc = gpg_capture_link_at(base_fd, witness_name, &current);
    if (quarantine_rc != 0 || witness_rc != 0) {
        set_error(ERR_FILE_IO,
                  "Cannot identify witnessed GNUPGHOME quarantine; reset state retained for retry");
        return -1;
    }

    if (!gpg_same_link(&current, captured)) {
        set_error(ERR_FILE_IO,
                  "GPG reset identity witness changed; preserving retry state");
        return -1;
    }
    if (!gpg_same_link(&moved, &current)) {
        current_rc = gpg_capture_link_at(base_fd, "current", &current);
        if (current_rc < 0) return -1;
        if (current_rc == 0) {
            set_error(ERR_FILE_IO,
                      "A newer GNUPGHOME writer blocks restoration; foreign quarantine retained: %s",
                      quarantine);
            return -1;
        }
        if (g_rename_noreplace(base_fd, quarantine, base_fd, "current") != 0) {
            set_system_error(ERR_FILE_IO,
                             "Cannot restore GNUPGHOME link replaced during reset");
            return -1;
        }
        current_rc = gpg_capture_link_at(base_fd, "current", &current);
        if (current_rc != 0 || !gpg_same_link(&current, &moved)) {
            set_error(ERR_FILE_IO,
                      "Restored GNUPGHOME link changed during reset recovery");
            return -1;
        }
        /* FreeBSD's no-replace fallback may retain the private hard-link alias.
         * Remove it only while it is still the exact foreign inode restored. */
        quarantine_rc = gpg_capture_link_at(base_fd, quarantine, &current);
        if (quarantine_rc < 0) return -1;
        if (quarantine_rc == 0) {
            if (!gpg_same_link(&current, &moved) ||
                unlinkat(base_fd, quarantine, 0) != 0) {
                set_error(ERR_FILE_IO,
                          "Restored GNUPGHOME quarantine changed; preserving it");
                return -1;
            }
        }
        if (g_sync_base(base_fd) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Cannot synchronize restored GNUPGHOME replacement");
            return -1;
        }
        if (gpg_retire_reset_link_locked(
                base_fd, witness_name, &witness,
                "restored-writer GPG reset witness") != 0) {
            return -1;
        }
        *changed = true;
        set_error(ERR_FILE_IO,
                  "Stable GNUPGHOME changed during reset; later writer preserved: %s",
                  moved.target);
        return 0;
    }

    if (g_reset_quarantine_hook &&
        g_reset_quarantine_hook(
            base_fd, GPG_RESET_QUARANTINE_HOOK_BEFORE_REVALIDATE,
            quarantine) != 0) {
        set_error(ERR_FILE_IO,
                  "GPG reset quarantine revalidation hook failed; retry state retained");
        return -1;
    }
    quarantine_rc = gpg_capture_link_at(base_fd, quarantine, &current);
    witness_rc = gpg_capture_link_at(base_fd, witness_name, &witness);
    if (quarantine_rc != 0 || witness_rc != 0 ||
        !gpg_same_link(&current, &moved) ||
        !gpg_same_link(&witness, &moved)) {
        set_error(ERR_FILE_IO,
                  "Witnessed GNUPGHOME quarantine changed; preserving replacement");
        return -1;
    }
    if (g_reset_quarantine_hook &&
        g_reset_quarantine_hook(
            base_fd, GPG_RESET_QUARANTINE_HOOK_BEFORE_UNLINK,
            quarantine) != 0) {
        set_error(ERR_FILE_IO,
                  "GPG reset quarantine unlink hook failed; retry state retained");
        return -1;
    }
    quarantine_rc = gpg_capture_link_at(base_fd, quarantine, &current);
    witness_rc = gpg_capture_link_at(base_fd, witness_name, &witness);
    if (quarantine_rc != 0 || witness_rc != 0 ||
        !gpg_same_link(&current, &moved) ||
        !gpg_same_link(&witness, &moved)) {
        set_error(ERR_FILE_IO,
                  "Witnessed GNUPGHOME quarantine changed; preserving replacement");
        return -1;
    }
    if (gpg_retire_reset_link_locked(
            base_fd, quarantine, &moved,
            "witnessed GPG reset quarantine") != 0) {
        return -1;
    }
    if (gpg_retire_reset_link_locked(
            base_fd, witness_name, &witness,
            "GPG reset identity witness") != 0) {
        return -1;
    }
    current_rc = gpg_capture_link_at(base_fd, "current", &current);
    if (current_rc < 0) return -1;
    if (current_rc == 0) {
        *changed = true;
        set_error(ERR_FILE_IO,
                  "Stable GNUPGHOME changed during reset; later writer preserved: %s",
                  current.target);
    }
    return 0;
}

/* Snapshot each progressive reset failure before another cleanup step can
 * replace the global context. The accumulator owns the complete first cause
 * and renders later causes in the order they occur. */
static void gpg_record_reset_failure(error_accumulator_t *failures,
                                     bool *failed, const char *label) {
    (void)error_accumulator_add_last(failures, label);
    *failed = true;
}

/* Tear down isolated GPG homes: one account, or all when account is NULL.
 * Each removable home has its agent stopped before its contents are unlinked.
 * A successful full reset retires every captured `current` symlink, regardless
 * of target. A targeted or incomplete full reset retires `current` only when
 * its target is no longer a live, safe managed home (including a home just
 * deleted); it preserves another live managed selection and retains a failed
 * home as an exact retry target. Identity-aware quarantine preserves a later
 * writer in either scope. Deletion is unlink, not a secure overwrite:
 * memory-backed storage destroys the bytes, while the opted-in non-tmpfs path
 * (GITSWITCH_ALLOW_TMP_GPG) may leave secret-key bytes forensically
 * recoverable after deletion (AR-02 #26). */
int gpg_manager_reset(const char *account) {
    char base[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    error_accumulator_t failures;
    bool absent = false;
    int base_fd = -1;
    int lock_fd = -1;
    bool failed = false;

    error_accumulator_init(&failures);

    if (account && !validate_name(account)) {
        set_error(ERR_INVALID_ARGS, "Invalid account name for reset");
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
    if (gpg_reconcile_reset_retry_locked(base_fd) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if (!account && gpg_retire_orphan_quarantines_locked(base_fd) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if (gpg_reject_stale_quarantines_locked(base_fd, NULL) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }
    if (!account &&
        gpg_preflight_reset_all_locked(base_fd, base) != 0) {
        unlock_gpg_dir(base_fd, lock_fd);
        return -1;
    }

    if (account) {
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
                gpg_record_reset_failure(&failures, &failed,
                                         "target GPG home cleanup");
            }
        } else if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Cannot inspect isolated GPG home: %s/%s",
                             base, account);
            gpg_record_reset_failure(&failures, &failed,
                                     "target GPG home inspection");
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
            int saved_errno = errno;
            if (scan_fd >= 0) close(scan_fd);
            errno = saved_errno;
            set_system_error(ERR_FILE_IO, "Cannot enumerate GPG base directory: %s", base);
            gpg_record_reset_failure(&failures, &failed,
                                     "GPG base enumeration");
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
                        gpg_record_reset_failure(
                            &failures, &failed, "GPG base enumeration read");
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
                    gpg_record_reset_failure(
                        &failures, &failed, "unmanaged GPG base entry");
                    continue;
                }
                struct stat est;
                if (fstatat(base_fd, ent->d_name, &est,
                            AT_SYMLINK_NOFOLLOW) != 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Cannot inspect GPG home during reset: %s/%s",
                                     base, ent->d_name);
                    gpg_record_reset_failure(
                        &failures, &failed, "GPG home inspection");
                    continue;
                }
                if (!S_ISDIR(est.st_mode) || est.st_uid != getuid() ||
                    (est.st_mode & 077) != 0) {
                    set_error(ERR_PERMISSION_DENIED,
                              "Refusing unsafe GPG home during reset: %s/%s",
                              base, ent->d_name);
                    gpg_record_reset_failure(
                        &failures, &failed, "unsafe GPG home");
                    continue;
                }
                if (gpg_kill_and_remove_home(base_fd, base, ent->d_name) != 0) {
                    gpg_record_reset_failure(&failures, &failed,
                                             "GPG home cleanup");
                }
            }
            if (closedir(d) != 0) {
                set_system_error(ERR_FILE_IO, "Failed to close GPG base directory: %s", base);
                gpg_record_reset_failure(&failures, &failed,
                                         "GPG base enumeration close");
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
        gpg_record_reset_failure(&failures, &failed,
                                 "stable GNUPGHOME path");
    } else {
        gpg_link_identity_t captured_current;
        int current_rc = gpg_capture_link_at(base_fd, "current",
                                             &captured_current);
        if (current_rc == 0) {
            if (!account && !failed) {
                bool current_changed = false;
                if (gpg_remove_captured_current_locked(
                        base_fd, base, &captured_current,
                        &current_changed) != 0 || current_changed) {
                    gpg_record_reset_failure(
                        &failures, &failed, "stable GNUPGHOME retirement");
                }
                goto reset_finalize;
            }
            const char *component = gpg_managed_component(
                base, captured_current.target);
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
                                     captured_current.target);
                    gpg_record_reset_failure(
                        &failures, &failed, "stable GNUPGHOME target inspection");
                }
            } else if (component &&
                       (!S_ISDIR(target_st.st_mode) ||
                        target_st.st_uid != getuid() ||
                        (target_st.st_mode & 077) != 0)) {
                remove_current = true;
            }
            if (remove_current) {
                bool current_changed = false;
                if (gpg_remove_captured_current_locked(
                        base_fd, base, &captured_current,
                        &current_changed) != 0 || current_changed) {
                    gpg_record_reset_failure(
                        &failures, &failed, "stable GNUPGHOME retirement");
                }
            }
        } else if (current_rc < 0) {
            gpg_record_reset_failure(&failures, &failed,
                                     "stable GNUPGHOME capture");
        }
    }
reset_finalize:
    if (!account && !failed) {
        if (g_reset_final_hook && g_reset_final_hook(base_fd) != 0) {
            set_error(ERR_FILE_IO, "GPG reset final-verification hook failed");
            gpg_record_reset_failure(&failures, &failed,
                                     "GPG reset final verification");
        } else if (gpg_verify_reset_all_final_locked(base_fd, lock_fd,
                                                     base) != 0) {
            gpg_record_reset_failure(&failures, &failed,
                                     "GPG reset final verification");
        }
    }

    /* Every successful reset — including an otherwise byte-for-byte retry
     * after an earlier fsync failure — repairs the durability boundary of
     * home/current namespace changes before releasing the manager lock. */
    if (g_sync_base(base_fd) != 0) {
        set_system_error(
            ERR_FILE_IO,
            "GPG reset changed the namespace but the base directory is not durable; retry reset");
        gpg_record_reset_failure(&failures, &failed,
                                 "GPG base directory synchronization");
    }
    unlock_gpg_dir(base_fd, lock_fd);
    if (failed) {
        if (!error_accumulator_publish(&failures)) {
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

/* Create/open, policy-check, and retain the exact base directory for isolated
 * GNUPGHOMEs. The memory-backed decision is made from this descriptor, then
 * its public name is rebound before any account home is created. Returns the
 * retained descriptor and base path; callers lock and mutate through this
 * same descriptor without reopening it. */
static int gpg_prepare_base_dir(char *base, size_t size) {
    struct stat opened;
    struct stat named;
    bool memory_backed = false;
    int base_fd;

    base_fd = gpg_open_base_dir(base, size, true, NULL);
    if (base_fd < 0) {
        return -1;
    }
    if (g_memory_backed_probe(base_fd, &memory_backed) != 0) {
        int saved_errno = errno ? errno : EIO;

        close(base_fd);
        errno = saved_errno;
        set_system_error(
            ERR_PERMISSION_DENIED,
            "Cannot prove isolated GPG base is memory-backed: %s", base);
        return -1;
    }
    errno = 0;
    if (fstat(base_fd, &opened) != 0 || lstat(base, &named) != 0 ||
        !S_ISDIR(opened.st_mode) || !S_ISDIR(named.st_mode) ||
        opened.st_uid != getuid() || (opened.st_mode & 077) != 0 ||
        named.st_dev != opened.st_dev || named.st_ino != opened.st_ino) {
        int saved_errno = errno ? errno : ESTALE;

        close(base_fd);
        errno = saved_errno;
        set_system_error(
            ERR_PERMISSION_DENIED,
            "GPG base pathname no longer names the probed directory: %s",
            base);
        return -1;
    }

    /* Refuse persistent storage unless the user knowingly opts in. The
     * process-wide warning latch is diagnostic only; every prepare call
     * independently re-probes its exact retained descriptor. */
    if (!memory_backed) {
        const char *optin = getenv("GITSWITCH_ALLOW_TMP_GPG");
        if (!optin || strcmp(optin, "1") != 0) {
            close(base_fd);
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
    return base_fd;
}

/* Create and pin one account home relative to an already-opened, locked base.
 * Agent configuration is part of activation, not a cosmetic best effort:
 * changed bytes must be made visible to a retained agent before any account
 * identity can be published. */
static int gpg_prepare_isolated_home_at(gpg_config_t *gpg_config,
                                        const account_t *account,
                                        int base_fd, const char *base,
                                        int *home_fd_out) {
    char gnupg_home[MAX_PATH_LEN];
    gpg_pinned_home_t pinned;
    gpg_agent_config_update_t update;
    int home_fd;

    gpg_agent_config_update_init(&update);

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

    if (setup_gpg_agent_config(home_fd, gnupg_home, &update) != 0) {
        gpg_agent_config_update_close(&update);
        close(home_fd);
        return -1;
    }
    if (update.reload_required &&
        gpg_reload_agent_config(&pinned, &update) != 0) {
        gpg_agent_config_update_close(&update);
        close(home_fd);
        return -1;
    }
    if (gpg_agent_config_update_close(&update) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close applied GPG agent configuration");
        close(home_fd);
        return -1;
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
    base_fd = gpg_prepare_base_dir(base, sizeof(base));
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

/* AR-06 F61 / AR-08 L17: gpg_import_key(), gpg_export_public_key(),
 * gpg_list_keys(), and gpg_validate_key() were removed here. They had no
 * callers, and the latter's name promised strict usability/capability checks
 * while its implementation only observed a helper exit status. */

/* Configure git GPG signing */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, git_scope_t scope) {
    account_t configured_account;

    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_configure_git_signing");
        return -1;
    }

    if (gpg_config->current_key_id[0] == '\0') {
        set_error(ERR_GPG_KEY_FAILED,
                  "Cannot configure Git signing before canonical GPG key resolution");
        return -1;
    }
    if (gpg_bind_executable_if_needed(gpg_config) != 0) {
        return -1;
    }
    configured_account = *account;
    if (safe_strncpy(configured_account.gpg_key_id,
                     gpg_config->current_key_id,
                     sizeof(configured_account.gpg_key_id)) != 0) {
        set_error(ERR_GPG_KEY_FAILED,
                  "Canonical GPG fingerprint exceeds account runtime storage");
        return -1;
    }

    log_info("Configuring git GPG identity for account: %s", account->name);
    /* Publish the canonical fingerprint, preference, and trusted executable
     * through one owner-checked Git boundary. A second account incarnation
     * cannot replace the post-image while it remains attributed to the first. */
    if (git_configure_openpgp_publication(
            &configured_account, gpg_config->executable_path, scope) != 0) {
        return -1;
    }

    /* This is the last publication step before accounts.c seals the generic
     * managed-key transaction. Require the fresh merged image to select the
     * same executable and use it for any uncached secret-key probe. */
    if (git_test_config(&configured_account, scope,
                        gpg_config->executable_path) != 0) {
        return -1;
    }

    log_info("Git GPG identity configured successfully for account: %s",
             account->name);
    return 0;
}

/* AR-06 F61 / AR-09 L12: gpg_generate_key(), gpg_test_signing(), and the
 * loose capability-letter parser were removed as dead or misleading public
 * APIs. The switch's one authoritative inventory path uses
 * gpg_manager_resolve_secret_key_listing(), rejects incomplete evidence, and
 * verifies the canonical fingerprint again after import. */

/* Set environment variables for GPG operation */
int gpg_set_environment(gpg_config_t *gpg_config) {
    const char *previous_home;
    const char *previous_agent;
    bool beginning_transaction;

    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_set_environment");
        return -1;
    }
    if (gpg_config->environment_installed &&
        (!gpg_config->gnupg_home_environment_installed ||
         !gpg_config->gpg_agent_info_suppressed)) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG environment restoration is incomplete; cleanup must "
                  "succeed before it can be installed again");
        return -1;
    }
    beginning_transaction = !gpg_config->environment_installed;
    
    /* Set GNUPGHOME if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED &&
        strlen(gpg_config->gnupg_home) > 0) {
        if (!gpg_config->environment_installed) {
            previous_home = getenv("GNUPGHOME");
            previous_agent = getenv("GPG_AGENT_INFO");
            /* Preserve presence separately from contents: an explicitly empty
             * value must be restored as empty, not converted into absence. */
            if (previous_home) {
                if (safe_strncpy(gpg_config->previous_gnupg_home,
                                 previous_home,
                                 sizeof(gpg_config->previous_gnupg_home)) != 0) {
                    set_error(ERR_INVALID_PATH,
                              "Existing GNUPGHOME is too long to restore safely");
                    gpg_clear_environment_snapshot(gpg_config);
                    return -1;
                }
                gpg_config->previous_gnupg_home_present = true;
            } else {
                gpg_config->previous_gnupg_home[0] = '\0';
                gpg_config->previous_gnupg_home_present = false;
            }
            if (previous_agent) {
                if (safe_strncpy(
                        gpg_config->previous_gpg_agent_info,
                        previous_agent,
                        sizeof(gpg_config->previous_gpg_agent_info)) != 0) {
                    set_error(
                        ERR_INVALID_PATH,
                        "Existing GPG_AGENT_INFO is too long to restore safely");
                    gpg_clear_environment_snapshot(gpg_config);
                    return -1;
                }
                gpg_config->previous_gpg_agent_info_present = true;
            } else {
                gpg_config->previous_gpg_agent_info[0] = '\0';
                gpg_config->previous_gpg_agent_info_present = false;
            }
        }
        if (g_gpg_setenv("GNUPGHOME", gpg_config->gnupg_home, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL,
                             "Failed to set GNUPGHOME environment variable");
            if (beginning_transaction) {
                gpg_clear_environment_snapshot(gpg_config);
            }
            return -1;
        }
        gpg_config->gnupg_home_environment_installed = true;
        gpg_config->environment_installed = true;

        /* Publish rollback ownership before the call: an injected or platform
         * failure may be reported after the environment was already changed. */
        gpg_config->gpg_agent_info_suppressed = true;
        if (g_gpg_unsetenv("GPG_AGENT_INFO") != 0) {
            char original[sizeof(g_last_error.message)];
            char rollback[sizeof(g_last_error.message)];

            set_system_error(
                ERR_SYSTEM_CALL,
                "Failed to suppress GPG_AGENT_INFO environment variable");
            safe_strncpy(original, get_last_error()->message,
                         sizeof(original));
            if (gpg_restore_environment(gpg_config) != 0) {
                safe_strncpy(rollback, get_last_error()->message,
                             sizeof(rollback));
                set_error(ERR_SYSTEM_CALL,
                          "%s; environment rollback failed: %s",
                          original, rollback);
            } else {
                set_error(ERR_SYSTEM_CALL, "%s", original);
            }
            return -1;
        }
        gpg_config->environment_installed = true;

        log_debug("Set GNUPGHOME environment variable and suppressed "
                  "GPG_AGENT_INFO: %s",
                  gpg_config->gnupg_home);
    }
    
    return 0;
}

int gpg_manager_resolve_system_key(const char *selector,
                                   bool require_signing,
                                   char *fingerprint,
                                   size_t fingerprint_size) {
    gpg_config_t resolver_config;

    if (fingerprint && fingerprint_size > 0) {
        fingerprint[0] = '\0';
    }
    if (!selector || !*selector || !fingerprint || fingerprint_size == 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG system-key resolution arguments");
        return -1;
    }
    memset(&resolver_config, 0, sizeof(resolver_config));
    resolver_config.mode = GPG_MODE_SYSTEM;
    if (gpg_bind_executable_if_needed(&resolver_config) != 0) {
        return -1;
    }
    return gpg_resolve_source_key(&resolver_config, selector,
                                  require_signing, fingerprint,
                                  fingerprint_size);
}

int gpg_manager_check_account_key(
    const account_t *account, gpg_account_key_readiness_t *readiness) {
    char base[MAX_PATH_LEN];
    char home_path[MAX_PATH_LEN];
    char retained_fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char source_fingerprint[GPG_FINGERPRINT_BUFSIZE];
    gpg_config_t resolver_config;
    gpg_pinned_home_t pinned_home = {
        .base_fd = -1,
        .home_fd = -1,
        .base = NULL,
        .name = NULL,
        .path = NULL
    };
    bool base_absent = false;
    bool home_absent = false;
    int base_fd = -1;
    int home_fd = -1;
    int retained_rc = 1;

    if (readiness) {
        memset(readiness, 0, sizeof(*readiness));
    }
    if (!account || !readiness || !account->gpg_enabled ||
        !validate_name(account->name) || account->gpg_key_id[0] == '\0') {
        set_error(ERR_INVALID_ARGS,
                  "Invalid account GPG-readiness arguments");
        return -1;
    }
    memset(&resolver_config, 0, sizeof(resolver_config));
    resolver_config.mode = GPG_MODE_ISOLATED;
    if (gpg_bind_executable_if_needed(&resolver_config) != 0 ||
        gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }

    base_fd = gpg_open_base_dir(base, sizeof(base), false, &base_absent);
    if (base_fd < 0 && !base_absent) {
        return -1;
    }
    if (base_fd >= 0) {
        if (safe_snprintf(home_path, sizeof(home_path), "%s/%s", base,
                          account->name) != 0) {
            close(base_fd);
            set_error(ERR_INVALID_PATH, "GNUPGHOME path too long");
            return -1;
        }
        home_fd = open_private_subdir_at(base_fd, account->name, false,
                                         &home_absent);
        if (home_fd < 0 && !home_absent) {
            close(base_fd);
            return -1;
        }
        if (home_fd >= 0) {
            pinned_home.base_fd = base_fd;
            pinned_home.home_fd = home_fd;
            pinned_home.base = base;
            pinned_home.name = account->name;
            pinned_home.path = home_path;
            if (gpg_validate_pinned_home(&pinned_home) != 0) {
                close(home_fd);
                close(base_fd);
                return -1;
            }
            retained_rc = gpg_resolve_pinned_key(
                &resolver_config, &pinned_home, account->gpg_key_id,
                account->gpg_signing_enabled, retained_fingerprint,
                sizeof(retained_fingerprint));
            close(home_fd);
        }
        close(base_fd);
    }

    if (retained_rc < 0) {
        return -1;
    }
    if (retained_rc == 0) {
        error_context_t prior_error = g_last_error;
        int prior_errno = errno;
        int source_rc;

        readiness->retained_home_usable = true;
        source_rc = gpg_resolve_source_key(
            &resolver_config, account->gpg_key_id,
            account->gpg_signing_enabled, source_fingerprint,
            sizeof(source_fingerprint));
        if (source_rc == 0) {
            readiness->source_recovery =
                strcmp(source_fingerprint, retained_fingerprint) == 0
                    ? GPG_SOURCE_RECOVERY_AVAILABLE
                    : GPG_SOURCE_RECOVERY_MISMATCH;
        } else if (get_last_error()->code == ERR_GPG_KEY_NOT_FOUND) {
            readiness->source_recovery = GPG_SOURCE_RECOVERY_MISSING;
        } else {
            readiness->source_recovery = GPG_SOURCE_RECOVERY_ERROR;
        }
        g_last_error = prior_error;
        errno = prior_errno;
        return 0;
    }

    if (gpg_resolve_source_key(
            &resolver_config, account->gpg_key_id,
            account->gpg_signing_enabled, source_fingerprint,
            sizeof(source_fingerprint)) != 0) {
        return -1;
    }
    readiness->source_recovery = GPG_SOURCE_RECOVERY_AVAILABLE;
    return 0;
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

    if (!gpg_colon_field(line, line_len, 1, &field, &field_len)) {
        return false;
    }
    /* GnuPG's stable colon-format contract explicitly leaves field 2 empty
     * for secret-key listings before 2.1. Empty therefore means that this
     * particular validity signal is unavailable, not that the key is
     * unusable. Explicit failure codes still fail closed, while expiry,
     * disabled capability, and secret-material availability are validated
     * independently below and by the caller. */
    if (field_len > 0 && strchr("redin?", field[0]) != NULL) {
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

typedef enum {
    GPG_SECRET_LISTING_MODERN,
    GPG_SECRET_LISTING_20
} gpg_secret_listing_contract_t;

static bool gpg_record_has_secret_material(
    const char *line, size_t line_len,
    gpg_secret_listing_contract_t contract) {
    const char *field;
    size_t field_len;
    size_t i;

    if (!gpg_colon_field(line, line_len, 14, &field, &field_len)) {
        return false;
    }
    if (field_len == 1 && field[0] == '+') {
        return true;
    }

    /* GnuPG 2.0's --list-secret-keys implementation reads secring.gpg and
     * emits sec/ssb only for secret records. Its colon writer leaves field 15
     * empty for an ordinary disk-backed key, writes '#' for a simple stub,
     * and writes the token serial for external material. GnuPG 2.1 moved
     * private keys into gpg-agent and added '+' as explicit availability
     * evidence. Empty is therefore usable only after the caller has bound the
     * capture to a positively identified 2.0 helper. */
    if (field_len == 0) {
        return contract == GPG_SECRET_LISTING_20;
    }

    /* Field 15 is either the exact availability marker '+' or a token serial
     * encoded as whole bytes in hexadecimal. '#' is explicitly a simple stub;
     * odd-length, decorated, or non-hex strings are not usable secret
     * material. Substring tests (the old '+'/'>' check) accepted malformed
     * records and rejected real smartcard-backed signing keys. */
    if ((field_len % 2) != 0) {
        return false;
    }
    for (i = 0; i < field_len; i++) {
        if (!isxdigit((unsigned char)field[i])) {
            return false;
        }
    }
    return true;
}

static int gpg_resolve_secret_key_listing_contract(
    const char *listing, bool require_signing,
    gpg_secret_listing_contract_t contract, char *fingerprint,
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

        /* A capture made with --status-fd=1 deliberately interleaves GnuPG's
         * machine status records with the colon inventory. They are parsed as
         * result evidence by the caller and are not colon records; in
         * particular, they must not break the required sec -> fpr adjacency. */
        if (line_len >= 9 && memcmp(line, "[GNUPG:] ", 9) == 0) {
            if (!eol) break;
            line = eol + 1;
            continue;
        }

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
                    bool primary_secret = gpg_record_has_secret_material(
                        line, line_len, contract);
                    bool primary_secret_usable;

                    primary_usable =
                        gpg_record_is_currently_usable(line, line_len);
                    primary_secret_usable =
                        primary_usable && primary_secret;
                    have_secret_material = primary_secret_usable;
                    signing_usable = primary_secret_usable &&
                        gpg_record_has_direct_signing(line, line_len);
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
                bool subkey_secret = gpg_record_has_secret_material(
                    line, line_len, contract);
                bool subkey_secret_usable =
                    subkey_secret &&
                    gpg_record_is_currently_usable(line, line_len);

                have_secret_material =
                    have_secret_material || subkey_secret_usable;
                if (primary_usable && subkey_secret_usable &&
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

int gpg_manager_resolve_secret_key_listing(const char *listing,
                                           bool require_signing,
                                           char *fingerprint,
                                           size_t fingerprint_size) {
    /* A detached listing has no trustworthy producer-version evidence. Keep
     * this public parser on the modern explicit-material contract; production
     * resolution selects the 2.0 contract only after querying the same bound
     * executable that produced the capture. */
    return gpg_resolve_secret_key_listing_contract(
        listing, require_signing, GPG_SECRET_LISTING_MODERN, fingerprint,
        fingerprint_size);
}

static bool gpg_listing_has_empty_secret_material(const char *listing) {
    const char *line;

    if (!listing) return false;
    for (line = listing; *line; ) {
        const char *eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line) : strlen(line);
        const char *record;
        const char *material;
        size_t record_len;
        size_t material_len;
        bool secret_record;

        if (!(line_len >= 9 && memcmp(line, "[GNUPG:] ", 9) == 0) &&
            gpg_colon_field(line, line_len, 0, &record, &record_len)) {
            secret_record =
                record_len == 3 &&
                (memcmp(record, "sec", 3) == 0 ||
                 memcmp(record, "ssb", 3) == 0);
            if (secret_record &&
                gpg_colon_field(line, line_len, 14, &material,
                                &material_len) &&
                material_len == 0) {
                return true;
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
    return false;
}

typedef struct {
    bool malformed;
    bool keylist_error_seen;
    bool keylist_error_conflict;
    unsigned long long keylist_error;
    bool gpg_exit_failure_seen;
} gpg_listing_status_t;

enum { GPG_KEY_LISTING_CAP = 512 * 1024 };

static bool gpg_status_next_token(const char **cursor, const char *end,
                                  const char **token, size_t *token_len) {
    const char *start;

    while (*cursor < end && **cursor == ' ') (*cursor)++;
    if (*cursor >= end) return false;
    start = *cursor;
    while (*cursor < end && **cursor != ' ') (*cursor)++;
    *token = start;
    *token_len = (size_t)(*cursor - start);
    return *token_len > 0;
}

static bool gpg_status_error_code(const char *token, size_t token_len,
                                  unsigned long long *value_out) {
    unsigned long long value = 0;
    size_t i;

    if (!token || token_len == 0 || !value_out) return false;
    for (i = 0; i < token_len; i++) {
        unsigned int digit;
        if (token[i] < '0' || token[i] > '9') return false;
        digit = (unsigned int)(token[i] - '0');
        if (value > (0xffffffffULL - digit) / 10ULL) return false;
        value = value * 10ULL + digit;
    }
    *value_out = value;
    return true;
}

static bool gpg_status_token_is(const char *token, size_t token_len,
                                const char *expected) {
    size_t expected_len = strlen(expected);
    return token_len == expected_len &&
           memcmp(token, expected, expected_len) == 0;
}

/* Parse only the status records needed to classify key listing. Unknown
 * records are forward-compatible. ERROR and FAILURE records are structural
 * evidence, so an incomplete or non-decimal form makes the capture unusable. */
static void gpg_collect_listing_status(const char *capture,
                                       gpg_listing_status_t *status) {
    const char *line;

    memset(status, 0, sizeof(*status));
    for (line = capture; line && *line; ) {
        const char *eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line) : strlen(line);

        if (line_len >= 9 && memcmp(line, "[GNUPG:] ", 9) == 0) {
            const char *cursor = line + 9;
            const char *end = line + line_len;
            const char *kind;
            const char *location;
            const char *code_token;
            size_t kind_len;
            size_t location_len;
            size_t code_len;
            unsigned long long code;
            bool is_error;
            bool is_failure;

            if (!eol ||
                !gpg_status_next_token(&cursor, end, &kind, &kind_len)) {
                status->malformed = true;
                break;
            }
            is_error = gpg_status_token_is(kind, kind_len, "ERROR");
            is_failure = gpg_status_token_is(kind, kind_len, "FAILURE");
            if ((is_error || is_failure) &&
                (!gpg_status_next_token(&cursor, end, &location,
                                        &location_len) ||
                 !gpg_status_next_token(&cursor, end, &code_token,
                                        &code_len) ||
                 !gpg_status_error_code(code_token, code_len, &code))) {
                status->malformed = true;
                break;
            }
            if (is_error &&
                gpg_status_token_is(location, location_len,
                                    "keylist.getkey")) {
                if (status->keylist_error_seen &&
                    status->keylist_error != code) {
                    status->keylist_error_conflict = true;
                }
                status->keylist_error_seen = true;
                status->keylist_error = code;
            } else if (is_failure &&
                       gpg_status_token_is(location, location_len,
                                           "gpg-exit")) {
                status->gpg_exit_failure_seen = true;
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
}

/* Classify the runner result without collapsing transport/setup or keyring
 * failures into an ordinary key miss. Exit status 2 is shared by multiple
 * GnuPG failures; only complete machine status proving keylist.getkey's
 * GPG_ERR_NO_SECKEY (17) plus the terminal gpg-exit failure is a miss. */
static int gpg_classify_secret_listing_run(int run_rc,
                                           const run_result_t *res,
                                           const char *capture,
                                           const char *selector) {
    gpg_listing_status_t status;

    if (!res || !capture || !selector) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG key-listing result classification");
        return -1;
    }
    if (res->out_truncated) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG key-list/status output exceeds the one-shot %d-byte "
                  "capture limit for %s",
                  GPG_KEY_LISTING_CAP, selector);
        return -1;
    }
    if (run_rc == 0) {
        if (res->spawned && res->exit_code == 0 && res->term_signal == 0) {
            gpg_collect_listing_status(capture, &status);
            if (status.malformed || status.keylist_error_conflict ||
                status.keylist_error_seen || status.gpg_exit_failure_seen) {
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG secret-key helper returned inconsistent "
                          "structured success for %s",
                          selector);
                return -1;
            }
            return 0;
        }
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper returned inconsistent success for %s",
                  selector);
        return -1;
    }
    if (res->spawned && res->term_signal == 0 && res->exit_code == 2) {
        gpg_collect_listing_status(capture, &status);
        if (status.malformed) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key helper returned malformed structured "
                      "status output for %s",
                      selector);
            return -1;
        }
        if (status.keylist_error_conflict) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key helper returned contradictory structured "
                      "status output for %s",
                      selector);
            return -1;
        }
        /* libgpg-error stores the portable code in the low 16 bits; the high
         * source bits may be present or omitted in a status record. */
        if (status.keylist_error_seen &&
            (status.keylist_error & 0xffffULL) == 17ULL &&
            status.gpg_exit_failure_seen) {
            return 1;
        }
        if (status.keylist_error_seen) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key keyring/status error code %llu for %s",
                      status.keylist_error & 0xffffULL, selector);
        } else {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key helper exited 2 without complete "
                      "structured no-secret-key evidence for %s",
                      selector);
        }
        return -1;
    }
    if (!res->spawned) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper failed before spawn for %s",
                  selector);
    } else if (res->term_signal != 0) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper was terminated by signal %d for %s",
                  res->term_signal, selector);
    } else if (res->exit_code == 126 || res->exit_code == 127) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper failed during child setup or exec "
                  "(exit %d) for %s",
                  res->exit_code, selector);
    } else if (res->exit_code == 0) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper transport failed after exit 0 for %s",
                  selector);
    } else {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG secret-key helper failed with exit status %d for %s",
                  res->exit_code, selector);
    }
    return -1;
}

static bool gpg_parse_version_component(const char **cursor, const char *end,
                                        unsigned int *value_out) {
    unsigned int value = 0;
    bool have_digit = false;

    if (!cursor || !*cursor || !end || !value_out) return false;
    while (*cursor < end && isdigit((unsigned char)**cursor)) {
        unsigned int digit = (unsigned int)(**cursor - '0');

        if (value > (UINT_MAX - digit) / 10U) return false;
        value = value * 10U + digit;
        (*cursor)++;
        have_digit = true;
    }
    if (!have_digit) return false;
    *value_out = value;
    return true;
}

static bool gpg_version_suffix_is_valid(const char *cursor,
                                        const char *end) {
    if (cursor == end) return true;
    if (*cursor == '.') {
        cursor++;
        if (cursor == end || !isdigit((unsigned char)*cursor)) return false;
        while (cursor < end && isdigit((unsigned char)*cursor)) cursor++;
        if (cursor == end) return true;
    }
    if (*cursor++ != '-' || cursor == end ||
        !isalnum((unsigned char)*cursor)) {
        return false;
    }
    for (; cursor < end; cursor++) {
        unsigned char ch = (unsigned char)*cursor;

        if (!isalnum(ch) && ch != '.' && ch != '-' && ch != '+' &&
            ch != '~') {
            return false;
        }
    }
    return isalnum((unsigned char)end[-1]);
}

static int gpg_parse_listing_contract_version(
    const char *output, gpg_secret_listing_contract_t *contract) {
    static const char prefix[] = "gpg (GnuPG) ";
    const char *cursor;
    const char *end;
    unsigned int major;
    unsigned int minor;

    if (!output || !contract ||
        strncmp(output, prefix, sizeof(prefix) - 1U) != 0) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG version output does not identify a supported helper");
        return -1;
    }
    cursor = output + sizeof(prefix) - 1U;
    end = strchr(cursor, '\n');
    if (!end) end = cursor + strlen(cursor);
    if (end > cursor && end[-1] == '\r') end--;
    if (!gpg_parse_version_component(&cursor, end, &major) ||
        cursor >= end || *cursor++ != '.' ||
        !gpg_parse_version_component(&cursor, end, &minor) ||
        !gpg_version_suffix_is_valid(cursor, end)) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG version output is malformed or incomplete");
        return -1;
    }
    if (major < 2U) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG version %u.%u is below the supported 2.x contract",
                  major, minor);
        return -1;
    }
    *contract = major == 2U && minor == 0U
                    ? GPG_SECRET_LISTING_20
                    : GPG_SECRET_LISTING_MODERN;
    return 0;
}

static int gpg_query_secret_listing_contract(
    const gpg_config_t *gpg_config, const gpg_pinned_home_t *home,
    const gpg_source_home_t *source,
    gpg_secret_listing_contract_t *contract) {
    enum { GPG_VERSION_OUTPUT_CAP = 1024 };
    const char *env[2] = {"GNUPGHOME=.", NULL};
    const char *argv[] = {NULL, "--version", NULL};
    char output[GPG_VERSION_OUTPUT_CAP];
    run_opts_t opts;
    run_result_t result;
    int run_rc;

    if (!gpg_config || gpg_config->executable_path[0] != '/' ||
        (!home && !source) || (home && source) || !contract) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG version-contract query arguments");
        return -1;
    }
    output[0] = '\0';
    argv[0] = gpg_config->executable_path;
    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.stderr_to_devnull = true;
    opts.unset_env = g_gpg_child_unset_env;
    opts.extra_env = env;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;

    if (home) {
        if (gpg_validate_pinned_home(home) != 0) return -1;
        opts.cwd_fd = home->home_fd;
        opts.use_cwd_fd = true;
        run_rc = run_argv(argv, &opts, &result);
        if (gpg_validate_pinned_home(home) != 0) return -1;
    } else {
        if (gpg_validate_source_home(source) != 0) return -1;
        opts.cwd_fd = source->fd;
        opts.use_cwd_fd = true;
        run_rc = run_argv(argv, &opts, &result);
        if (gpg_validate_source_home(source) != 0) return -1;
    }
    if (result.out_truncated) {
        set_error(ERR_GPG_KEY_FAILED,
                  "GPG version output exceeds the %d-byte capture limit",
                  GPG_VERSION_OUTPUT_CAP);
        return -1;
    }
    if (run_rc != 0 || !result.spawned || result.exit_code != 0 ||
        result.term_signal != 0) {
        if (!result.spawned) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG version probe failed before spawn");
        } else if (result.term_signal != 0) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG version probe was terminated by signal %d",
                      result.term_signal);
        } else if (result.exit_code != 0) {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG version probe failed with exit status %d",
                      result.exit_code);
        } else {
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG version probe transport failed after exit 0");
        }
        return -1;
    }
    return gpg_parse_listing_contract_version(output, contract);
}

/* Return 0 for one validated key, 1 only for GnuPG's ordinary listing miss,
 * and -1 for incomplete, ambiguous, or operationally failed evidence. */
static int gpg_capture_secret_listing(const gpg_config_t *gpg_config,
                                      const gpg_pinned_home_t *home,
                                      const gpg_source_home_t *source,
                                      const char *selector,
                                      bool require_signing,
                                      char *fingerprint,
                                      size_t fingerprint_size) {
    const char *env[2] = {"GNUPGHOME=.", NULL};
    const char *argv[] = {
        NULL, "--batch", "--status-fd=1", "--with-colons",
        "--fixed-list-mode",
        "--list-secret-keys", "--fingerprint", "--fingerprint", selector,
        NULL
    };
    char *listing;
    run_opts_t opts;
    run_result_t res;
    gpg_secret_listing_contract_t contract = GPG_SECRET_LISTING_MODERN;
    int run_rc;
    int status;

    if (!gpg_config || gpg_config->executable_path[0] != '/' ||
        (!home && !source) || (home && source) || !selector || !*selector ||
        !fingerprint || fingerprint_size == 0) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG secret-key listing source");
        return -1;
    }
    fingerprint[0] = '\0';
    listing = malloc(GPG_KEY_LISTING_CAP);
    if (!listing) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Failed to allocate GPG key-listing buffer");
        return -1;
    }
    argv[0] = gpg_config->executable_path;
    memset(&opts, 0, sizeof(opts));
    opts.out = listing;
    opts.out_size = GPG_KEY_LISTING_CAP;
    opts.stderr_to_devnull = true;
    opts.unset_env = g_gpg_child_unset_env;
    opts.extra_env = env;
    memset(&res, 0, sizeof(res));
    res.exit_code = -1;
    if (home) {
        if (gpg_validate_pinned_home(home) != 0) {
            secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
            free(listing);
            return -1;
        }
        opts.cwd_fd = home->home_fd;
        opts.use_cwd_fd = true;
        run_rc = run_argv(argv, &opts, &res);
        if (gpg_validate_pinned_home(home) != 0) {
            secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
            free(listing);
            return -1;
        }
    } else {
        if (gpg_validate_source_home(source) != 0) {
            secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
            free(listing);
            return -1;
        }
        opts.cwd_fd = source->fd;
        opts.use_cwd_fd = true;
        run_rc = run_argv(argv, &opts, &res);
        if (gpg_validate_source_home(source) != 0) {
            secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
            free(listing);
            return -1;
        }
    }
    status = gpg_classify_secret_listing_run(run_rc, &res, listing, selector);
    if (status != 0) {
        secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
        free(listing);
        return status;
    }
    if (gpg_listing_has_empty_secret_material(listing) &&
        gpg_query_secret_listing_contract(gpg_config, home, source,
                                          &contract) != 0) {
        secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
        free(listing);
        return -1;
    }
    {
        int parse_rc = gpg_resolve_secret_key_listing_contract(
            listing, require_signing, contract, fingerprint,
            fingerprint_size);
        secure_zero_memory(listing, GPG_KEY_LISTING_CAP);
        free(listing);
        if (parse_rc == 0) {
            gpg_key_cache_store(gpg_config, home, source, fingerprint,
                                require_signing, &res.launch_witness);
            /* Preserve the selector-only compatibility memo for injected
             * runners. Production callers cannot consume these notes; their
             * reusable proof is the context-bound cache populated above. */
            if (!run_uses_default_runner()) {
                gpg_manager_note_key_available(fingerprint);
                gpg_manager_note_key_available(selector);
            }
        }
        return parse_rc;
    }
}

static int gpg_resolve_source_key(const gpg_config_t *gpg_config,
                                  const char *selector, bool require_signing,
                                  char *fingerprint,
                                  size_t fingerprint_size) {
    gpg_source_home_t source;
    int cache_rc;
    int open_rc;
    int rc;

    if (!gpg_config || gpg_config->executable_path[0] != '/' ||
        !selector || !*selector) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG key selector");
        return -1;
    }
    open_rc = gpg_open_user_source_home(&source);
    if (open_rc != 0) {
        if (open_rc > 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND,
                      "System GPG keyring home is absent");
        }
        return -1;
    }
    if (gpg_validate_source_home(&source) != 0) {
        gpg_close_source_home(&source);
        return -1;
    }
    cache_rc = gpg_key_cache_lookup(
        gpg_config, NULL, &source, selector, require_signing,
        fingerprint, fingerprint_size);
    if (cache_rc != 0) {
        gpg_close_source_home(&source);
        return cache_rc > 0 ? 0 : -1;
    }
    rc = gpg_capture_secret_listing(gpg_config, NULL, &source, selector,
                                    require_signing, fingerprint,
                                    fingerprint_size);
    gpg_close_source_home(&source);
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
    int cache_rc;

    if (gpg_validate_pinned_home(home) != 0) {
        return -1;
    }
    cache_rc = gpg_key_cache_lookup(
        gpg_config, home, NULL, selector, require_signing,
        fingerprint, fingerprint_size);
    if (cache_rc != 0) return cache_rc > 0 ? 0 : -1;
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
    /* AR-12 L12: run_argv has early-return paths that never touch the
     * capture buffer; initialize so a pre-spawn failure cannot format
     * uninitialized stack bytes into the user-facing diagnostic. */
    char import_diag[1024] = "";
    const char *env[2] = {"GNUPGHOME=.", NULL};
    char *key_data;
    char imported_fingerprint[GPG_FINGERPRINT_BUFSIZE];
    run_opts_t opts;
    run_result_t res;
    gpg_source_home_t source = { .fd = -1 };
    int source_rc;
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

    source_rc = gpg_open_user_source_home(&source);
    if (source_rc != 0) {
        if (source_rc > 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND,
                      "System GPG keyring home is absent");
        }
        return -1;
    }
    source_rc = gpg_capture_secret_listing(
        gpg_config, NULL, &source, selector, require_signing, fingerprint,
        fingerprint_size);
    if (source_rc != 0) {
        gpg_close_source_home(&source);
        if (source_rc > 0) {
            set_error(ERR_GPG_KEY_NOT_FOUND,
                      "GPG selector resolved no secret key: %s", selector);
        }
        return -1;
    }

    key_data = malloc(KEY_DATA_CAP);
    if (!key_data) {
        gpg_close_source_home(&source);
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
        const char *export_argv[] = {gpg_config->executable_path, "--armor",
                                     "--export-secret-keys",
                                     fingerprint, NULL};
        const char *export_env[2] = {"GNUPGHOME=.", NULL};
        int export_rc;
        memset(&opts, 0, sizeof(opts));
        memset(&res, 0, sizeof(res));
        res.exit_code = -1;
        opts.out = key_data;
        opts.out_size = KEY_DATA_CAP;
        opts.stderr_to_devnull = true;
        opts.unset_env = g_gpg_child_unset_env;
        opts.extra_env = export_env;
        opts.cwd_fd = source.fd;
        opts.use_cwd_fd = true;
        if (gpg_validate_source_home(&source) != 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            gpg_close_source_home(&source);
            return -1;
        }
        export_rc = run_argv(export_argv, &opts, &res);
        if (gpg_validate_source_home(&source) != 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            gpg_close_source_home(&source);
            return -1;
        }
        if (export_rc != 0 || res.out_len == 0) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            gpg_close_source_home(&source);
            if (!res.spawned) {
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG secret-key export failed before spawn");
            } else if (res.term_signal != 0) {
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG secret-key export was terminated by signal %d",
                          res.term_signal);
            } else if (res.exit_code == 2) {
                set_error(ERR_GPG_KEY_NOT_FOUND,
                          "GPG key disappeared from the system keyring before export");
            } else if (res.exit_code == 0) {
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG secret-key export produced no complete output");
            } else {
                set_error(ERR_GPG_KEY_FAILED,
                          "GPG secret-key export failed with exit status %d",
                          res.exit_code);
            }
            return -1;
        }
        /* An incomplete armor must never reach the import: gpg would reject
         * it ('Invalid packet', zero keys processed) and the whole switch
         * would abort with a misleading key-not-found error (AR-02 #4). */
        if (res.out_truncated) {
            secure_zero_memory(key_data, KEY_DATA_CAP);
            free(key_data);
            gpg_close_source_home(&source);
            set_error(ERR_GPG_KEY_FAILED,
                      "GPG secret-key export for %s exceeds %d bytes; refusing to "
                      "import a truncated key", fingerprint,
                      (int)KEY_DATA_CAP);
            return -1;
        }
    }
    gpg_close_source_home(&source);

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
        const char *import_argv[] = {gpg_config->executable_path, "--batch",
                                     "--import", NULL};
        int import_rc;
        memset(&opts, 0, sizeof(opts));
        opts.input = key_data;
        opts.input_len = res.out_len;
        opts.out = import_diag;
        opts.out_size = sizeof(import_diag);
        opts.merge_stderr = true;
        opts.unset_env = g_gpg_child_unset_env;
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
    return 0;
}

enum { GPG_AGENT_CONF_MAX = 64 * 1024 };

#define GPG_AGENT_RELOAD_STATE ".gitswitch-gpg-agent-reload.state"
enum { GPG_AGENT_RELOAD_STATE_MAX = 256 };

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
 * The comparator opens no write descriptor and performs no fsync or rename;
 * its caller still syncs the directory before accepting an identical retry. */
static int gpg_agent_conf_matches(int home_fd, const unsigned char *desired,
                                  size_t desired_len, int *matched_fd_out,
                                  struct stat *identity_out) {
    struct stat before;
    struct stat opened;
    struct stat after;
    unsigned char buf[4096];
    size_t offset = 0;
    int fd;
    int result = 0;

    if ((matched_fd_out == NULL) != (identity_out == NULL)) {
        set_error(ERR_INVALID_ARGS,
                  "Invalid GPG agent config comparison outputs");
        return -1;
    }
    if (matched_fd_out) *matched_fd_out = -1;

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
    if (result == 1 && matched_fd_out) {
        *matched_fd_out = fd;
        *identity_out = opened;
        fd = -1;
    }
    if (fd >= 0 && close(fd) != 0) result = -1;
    if (result < 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to compare installed gpg-agent.conf safely");
    }
    return result;
}

/* The retained state file is a durable reload obligation. Exact zero length
 * means a successful pinned-home reload is still required; nonzero contents
 * are only a candidate clean record and must match the installed config's
 * exact generation. Absence therefore forces one migration reload. Keeping
 * one inode and changing its contents avoids an identity-unsafe unlink race. */
static int gpg_open_agent_reload_state(int home_fd, int *fd_out,
                                       struct stat *identity_out,
                                       bool *present_out,
                                       bool *pending_out) {
    struct stat before;
    struct stat opened;
    struct stat after;
    int fd;

    if (home_fd < 0 || !fd_out || !identity_out || !present_out ||
        !pending_out) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent reload state outputs");
        return -1;
    }
    *fd_out = -1;
    *present_out = false;
    *pending_out = false;
    if (fstatat(home_fd, GPG_AGENT_RELOAD_STATE, &before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 0;
        set_system_error(ERR_FILE_IO,
                         "Failed to inspect GPG agent reload state");
        return -1;
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
        before.st_nlink != 1 || (before.st_mode & 0777) != 0600 ||
        before.st_size < 0 || before.st_size > GPG_AGENT_RELOAD_STATE_MAX) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe GPG agent reload state");
        return -1;
    }
    fd = openat(home_fd, GPG_AGENT_RELOAD_STATE,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        !gpg_same_file_version(&before, &opened) ||
        !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || (opened.st_mode & 0777) != 0600) {
        if (fd >= 0) close(fd);
        set_error(ERR_FILE_IO, "GPG agent reload state changed while opening");
        return -1;
    }
    if (fstat(fd, &after) != 0 ||
        fstatat(home_fd, GPG_AGENT_RELOAD_STATE, &before,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(&opened, &after) ||
        !gpg_same_file_version(&opened, &before)) {
        close(fd);
        set_error(ERR_FILE_IO,
                  "GPG agent reload state changed while being read");
        return -1;
    }
    *fd_out = fd;
    *identity_out = opened;
    *present_out = true;
    *pending_out = opened.st_size == 0;
    return 0;
}

/* A clean record certifies one exact installed config generation. Binding the
 * inode plus size/mtime/ctime closes both the pre-M20 migration gap (no record)
 * and non-cooperating same-uid rewrites which leave desired bytes unchanged
 * but may have reloaded a different intermediate configuration. */
static int gpg_format_agent_reload_clean(
    const struct stat *config_identity, unsigned char *output,
    size_t output_size, size_t *length_out) {
    int written;
    intmax_t mtime_sec;
    long mtime_nsec;
    intmax_t ctime_sec;
    long ctime_nsec;

    if (!config_identity || !output || output_size == 0 || !length_out ||
        config_identity->st_size < 0) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent clean-state record");
        return -1;
    }
#ifdef __APPLE__
    mtime_sec = (intmax_t)config_identity->st_mtimespec.tv_sec;
    mtime_nsec = config_identity->st_mtimespec.tv_nsec;
    ctime_sec = (intmax_t)config_identity->st_ctimespec.tv_sec;
    ctime_nsec = config_identity->st_ctimespec.tv_nsec;
#else
    mtime_sec = (intmax_t)config_identity->st_mtim.tv_sec;
    mtime_nsec = config_identity->st_mtim.tv_nsec;
    ctime_sec = (intmax_t)config_identity->st_ctim.tv_sec;
    ctime_nsec = config_identity->st_ctim.tv_nsec;
#endif
    written = snprintf(
        (char *)output, output_size,
        "C1:%ju:%ju:%ju:%jd:%ld:%jd:%ld\n",
        (uintmax_t)config_identity->st_dev,
        (uintmax_t)config_identity->st_ino,
        (uintmax_t)config_identity->st_size,
        mtime_sec, mtime_nsec, ctime_sec, ctime_nsec);
    if (written < 0 || (size_t)written >= output_size) {
        set_error(ERR_FILE_IO, "GPG agent clean-state record is too large");
        return -1;
    }
    *length_out = (size_t)written;
    return 0;
}

static int gpg_agent_reload_state_matches_config(
    int home_fd, int state_fd, const struct stat *state_identity,
    const struct stat *config_identity, bool *matches_out) {
    unsigned char expected[GPG_AGENT_RELOAD_STATE_MAX];
    unsigned char actual[GPG_AGENT_RELOAD_STATE_MAX] = {0};
    struct stat opened;
    struct stat named;
    size_t expected_len;
    size_t offset = 0;

    if (home_fd < 0 || state_fd < 0 || !state_identity ||
        !config_identity || !matches_out ||
        gpg_format_agent_reload_clean(config_identity, expected,
                                      sizeof(expected), &expected_len) != 0) {
        return -1;
    }
    *matches_out = false;
    if ((uintmax_t)state_identity->st_size == (uintmax_t)expected_len) {
        while (offset < expected_len) {
            ssize_t n = pread(state_fd, actual + offset,
                              expected_len - offset, (off_t)offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                if (n < 0) {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to read GPG agent clean state");
                } else {
                    set_error(ERR_FILE_IO,
                              "Short read of GPG agent clean state");
                }
                return -1;
            }
            offset += (size_t)n;
        }
        *matches_out = memcmp(actual, expected, expected_len) == 0;
    }
    if (fstat(state_fd, &opened) != 0 ||
        fstatat(home_fd, GPG_AGENT_RELOAD_STATE, &named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(state_identity, &opened) ||
        !gpg_same_file_version(state_identity, &named)) {
        set_error(ERR_FILE_IO,
                  "GPG agent clean state changed while being verified");
        return -1;
    }
    return 0;
}

static int gpg_validate_agent_update_entry(
    int home_fd, const char *name, int fd, const struct stat *identity,
    off_t required_size, const char *description) {
    struct stat opened;
    struct stat named;

    if (home_fd < 0 || !name || fd < 0 || !identity || !description ||
        fstat(fd, &opened) != 0 ||
        fstatat(home_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(identity, &opened) ||
        !gpg_same_file_version(identity, &named) ||
        !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || (opened.st_mode & 0777) != 0600 ||
        opened.st_size != required_size) {
        set_error(ERR_FILE_IO, "%s changed during GPG agent activation",
                  description);
        return -1;
    }
    return 0;
}

/* FreeBSD/UFS may expose the ctime caused by our own atomic publication only
 * after a later descriptor operation. This predicate is intentionally narrow:
 * callers may admit it only while holding an exact byte witness captured
 * before that publication. */
static bool gpg_file_ctime_only_change(const struct stat *before,
                                       const struct stat *after) {
    bool same_without_ctime;
    bool same_mtime;
    bool same_ctime;

    if (!before || !after) return false;
    same_without_ctime = gpg_same_reset_entry(before, after) &&
                         before->st_nlink == after->st_nlink &&
                         before->st_size == after->st_size;
#ifdef __APPLE__
    same_mtime =
        before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
        before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec;
    same_ctime =
        before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
        before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    same_mtime = before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
                 before->st_mtim.tv_nsec == after->st_mtim.tv_nsec;
    same_ctime = before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
                 before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
    return same_without_ctime && same_mtime && !same_ctime;
}

static int gpg_config_witness_matches_fd(
    int fd, const unsigned char *witness, size_t witness_length) {
    unsigned char observed[4096];
    unsigned char trailing;
    size_t offset = 0;
    ssize_t count = 0;

    if (fd < 0 || (!witness && witness_length != 0U)) {
        errno = EINVAL;
        return -1;
    }
    while (offset < witness_length) {
        size_t wanted = witness_length - offset;
        size_t received = 0;
        if (wanted > sizeof(observed)) wanted = sizeof(observed);
        while (received < wanted) {
            do {
                count = pread(fd, observed + received, wanted - received,
                              (off_t)(offset + received));
            } while (count < 0 && errno == EINTR);
            if (count <= 0) break;
            received += (size_t)count;
        }
        if (received != wanted ||
            memcmp(observed, witness + offset, wanted) != 0) {
            secure_zero_memory(observed, sizeof(observed));
            if (count >= 0) errno = ESTALE;
            return -1;
        }
        offset += wanted;
    }
    do {
        count = pread(fd, &trailing, 1, (off_t)witness_length);
    } while (count < 0 && errno == EINTR);
    secure_zero_memory(observed, sizeof(observed));
    if (count != 0) {
        if (count > 0) errno = ESTALE;
        return -1;
    }
    return 0;
}

/* Validate the retained config descriptor normally. If only ctime advanced
 * since this invocation published the file, re-prove every byte and refresh
 * the in-memory identity. This does not weaken cross-invocation clean-state
 * matching: a later same-inode rewrite still changes the persisted generation
 * and therefore forces another agent reload. */
static int gpg_validate_agent_config_update(
    int home_fd, gpg_agent_config_update_t *update) {
    struct stat opened_before;
    struct stat named_before;
    struct stat opened_after;
    struct stat named_after;
    bool opened_admissible;
    bool named_admissible;

    if (home_fd < 0 || !update || update->config_fd < 0 ||
        (!update->config_witness && update->config_witness_length != 0U) ||
        update->config_identity.st_size < 0 ||
        (uintmax_t)update->config_identity.st_size !=
            update->config_witness_length ||
        fstat(update->config_fd, &opened_before) != 0 ||
        fstatat(home_fd, "gpg-agent.conf", &named_before,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_error(ERR_FILE_IO,
                  "Installed gpg-agent.conf changed during GPG agent activation");
        return -1;
    }
    if (!S_ISREG(opened_before.st_mode) ||
        opened_before.st_uid != getuid() || opened_before.st_nlink != 1 ||
        (opened_before.st_mode & 0777) != 0600 ||
        !gpg_same_file_version(&opened_before, &named_before)) {
        set_error(ERR_FILE_IO,
                  "Installed gpg-agent.conf changed during GPG agent activation");
        return -1;
    }
    if (gpg_same_file_version(&update->config_identity, &opened_before)) {
        return 0;
    }
    opened_admissible = gpg_file_ctime_only_change(
        &update->config_identity, &opened_before);
    named_admissible = gpg_file_ctime_only_change(
        &update->config_identity, &named_before);
    if (!opened_admissible || !named_admissible ||
        gpg_config_witness_matches_fd(
            update->config_fd, update->config_witness,
            update->config_witness_length) != 0 ||
        fstat(update->config_fd, &opened_after) != 0 ||
        fstatat(home_fd, "gpg-agent.conf", &named_after,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(&opened_before, &opened_after) ||
        !gpg_same_file_version(&opened_after, &named_after)) {
        set_error(ERR_FILE_IO,
                  "Installed gpg-agent.conf changed during GPG agent activation");
        return -1;
    }
    update->config_identity = opened_after;
    return 0;
}

/* Persist the obligation before publishing changed config bytes. Existing
 * pending state is adopted after a failed attempt; clean state is changed in
 * place through its retained descriptor. */
static int gpg_set_agent_reload_pending(int home_fd,
                                        gpg_agent_config_update_t *update) {
    struct stat opened;
    struct stat named;
    bool present = false;
    bool pending = false;
    int fd = -1;

    if (home_fd < 0 || !update) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent reload transition");
        return -1;
    }
    if (update->marker_fd < 0) {
        if (gpg_open_agent_reload_state(home_fd, &fd, &opened, &present,
                                        &pending) != 0) {
            return -1;
        }
        if (!present) {
            fd = openat(home_fd, GPG_AGENT_RELOAD_STATE,
                        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
            if (fd < 0) {
                if (errno == EEXIST) {
                    if (gpg_open_agent_reload_state(
                            home_fd, &fd, &opened, &present, &pending) != 0 ||
                        !present) {
                        return -1;
                    }
                } else {
                    set_system_error(ERR_FILE_IO,
                                     "Failed to create GPG agent reload state");
                    return -1;
                }
            } else {
                if (fchmod(fd, 0600) != 0 || fstat(fd, &opened) != 0 ||
                    !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
                    opened.st_nlink != 1 ||
                    (opened.st_mode & 0777) != 0600 || opened.st_size != 0) {
                    close(fd);
                    set_error(ERR_PERMISSION_DENIED,
                              "Created unsafe GPG agent reload state");
                    return -1;
                }
                pending = true;
            }
        }
        update->marker_fd = fd;
        update->marker_identity = opened;
    } else {
        pending = update->marker_identity.st_size == 0;
    }

    if (!pending && ftruncate(update->marker_fd, 0) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to mark GPG agent reload pending");
        return -1;
    }
    if (g_agent_conf_sync(update->marker_fd, false) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to flush GPG agent reload obligation");
        return -1;
    }
    if (fstat(update->marker_fd, &opened) != 0 ||
        fstatat(home_fd, GPG_AGENT_RELOAD_STATE, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to inspect GPG agent reload obligation");
        return -1;
    }
    if (!gpg_same_reset_entry(&opened, &named) ||
        !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || named.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600 || opened.st_size != 0 ||
        named.st_size != 0) {
        set_error(ERR_FILE_IO,
                  "GPG agent reload obligation changed while synchronizing");
        return -1;
    }
    update->marker_identity = opened;
    if (g_agent_conf_sync(home_fd, true) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to publish GPG agent reload obligation");
        return -1;
    }
    if (gpg_validate_agent_update_entry(
            home_fd, GPG_AGENT_RELOAD_STATE, update->marker_fd,
            &update->marker_identity, 0, "GPG agent reload state") != 0) {
        return -1;
    }
    return 0;
}

static int gpg_set_agent_reload_clean(int home_fd,
                                      gpg_agent_config_update_t *update) {
    unsigned char clean[GPG_AGENT_RELOAD_STATE_MAX];
    struct stat opened;
    struct stat named;
    size_t clean_len;
    size_t offset = 0;
    bool matches = false;

    if (!update || update->marker_fd < 0 ||
        gpg_format_agent_reload_clean(&update->config_identity, clean,
                                      sizeof(clean), &clean_len) != 0 ||
        gpg_validate_agent_update_entry(
            home_fd, GPG_AGENT_RELOAD_STATE, update->marker_fd,
            &update->marker_identity, 0, "GPG agent reload state") != 0) {
        return -1;
    }
    while (offset < clean_len) {
        ssize_t n = pwrite(update->marker_fd, clean + offset,
                           clean_len - offset, (off_t)offset);
        if (n > 0) {
            offset += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0) {
            set_system_error(ERR_FILE_IO,
                             "Failed to write completed GPG agent reload");
            return -1;
        } else {
            set_error(ERR_FILE_IO,
                      "Short write recording completed GPG agent reload");
            return -1;
        }
    }
    if (ftruncate(update->marker_fd, (off_t)clean_len) != 0 ||
        g_agent_conf_sync(update->marker_fd, false) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to persist completed GPG agent reload");
        return -1;
    }
    if (fstat(update->marker_fd, &opened) != 0 ||
        fstatat(home_fd, GPG_AGENT_RELOAD_STATE, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to verify completed GPG agent reload");
        return -1;
    }
    if (!gpg_same_reset_entry(&opened, &named) ||
        !S_ISREG(opened.st_mode) || opened.st_uid != getuid() ||
        opened.st_nlink != 1 || named.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600 ||
        (uintmax_t)opened.st_size != (uintmax_t)clean_len ||
        (uintmax_t)named.st_size != (uintmax_t)clean_len) {
        set_error(ERR_FILE_IO,
                  "GPG agent reload state changed while completing");
        return -1;
    }
    update->marker_identity = opened;
    if (gpg_agent_reload_state_matches_config(
            home_fd, update->marker_fd, &update->marker_identity,
            &update->config_identity, &matches) != 0) {
        return -1;
    }
    if (!matches) {
        set_error(ERR_FILE_IO,
                  "Completed GPG agent reload state is corrupt");
        return -1;
    }
    return 0;
}

static int gpg_reload_agent_config(const gpg_pinned_home_t *home,
                                   gpg_agent_config_update_t *update) {
    const char *env[] = {"GNUPGHOME=.", NULL};
    const char *argv[4];
    run_opts_t opts;
    run_result_t result;
    int run_rc;

    if (!home || !update || !update->reload_required ||
        update->config_fd < 0 || update->marker_fd < 0 ||
        update->gpgconf_path[0] != '/') {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent reload request");
        return -1;
    }
    if (gpg_validate_pinned_home(home) != 0 ||
        gpg_validate_agent_config_update(home->home_fd, update) != 0 ||
        gpg_validate_agent_update_entry(
            home->home_fd, GPG_AGENT_RELOAD_STATE, update->marker_fd,
            &update->marker_identity, 0, "GPG agent reload state") != 0) {
        return -1;
    }

    argv[0] = update->gpgconf_path;
    argv[1] = "--reload";
    argv[2] = "gpg-agent";
    argv[3] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.unset_env = g_gpg_child_unset_env;
    opts.extra_env = env;
    opts.stderr_to_devnull = true;
    opts.cwd_fd = home->home_fd;
    opts.use_cwd_fd = true;
    run_rc = run_argv(argv, &opts, &result);
    if (run_rc != 0 || !result.spawned || result.exit_code != 0 ||
        result.term_signal != 0) {
        set_error(ERR_SYSTEM_COMMAND_FAILED,
                  "Failed to reload GPG agent configuration; retry required");
        return -1;
    }
    if (gpg_validate_pinned_home(home) != 0 ||
        gpg_validate_agent_config_update(home->home_fd, update) != 0 ||
        gpg_validate_agent_update_entry(
            home->home_fd, GPG_AGENT_RELOAD_STATE, update->marker_fd,
            &update->marker_identity, 0, "GPG agent reload state") != 0 ||
        gpg_set_agent_reload_clean(home->home_fd, update) != 0 ||
        gpg_validate_agent_config_update(home->home_fd, update) != 0 ||
        gpg_validate_pinned_home(home) != 0) {
        return -1;
    }
    log_debug("Reloaded GPG agent configuration for %s", home->path);
    return 0;
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

static gpg_source_path_class_t gpg_classify_managed_path(
    const char *base, const char *candidate) {
    char current[MAX_PATH_LEN];
    size_t base_len;
    size_t candidate_len;

    if (!base || !*base || !candidate || !*candidate) {
        return GPG_SOURCE_PATH_EXTERNAL;
    }
    if (strcmp(base, candidate) == 0 ||
        (gpg_current_path_from_base(base, current, sizeof(current)) == 0 &&
         strcmp(current, candidate) == 0) ||
        gpg_target_is_managed_child(base, candidate)) {
        return GPG_SOURCE_PATH_MANAGED_CANONICAL;
    }
    base_len = strlen(base);
    candidate_len = strlen(candidate);
    if (candidate_len > base_len &&
        strncmp(candidate, base, base_len) == 0 &&
        candidate[base_len] == '/') {
        return GPG_SOURCE_PATH_MANAGED_DESCENDANT;
    }
    return GPG_SOURCE_PATH_EXTERNAL;
}

/* Classify one source spelling: external paths are returned resolved;
 * canonical managed entry points may deliberately select HOME/.gnupg, while
 * deeper descendants are always fatal. Keeping descendants distinct prevents
 * arbitrary subdirectories of an isolated keyring from being recast as a
 * system source. -1 is resolution uncertainty. */
static int gpg_classify_source_path(const char *candidate,
                                    char *resolved_out,
                                    size_t resolved_out_size) {
    char base[MAX_PATH_LEN];
    char normalized_base[MAX_PATH_LEN];
    char normalized_candidate[MAX_PATH_LEN];
    char resolved_base[MAX_PATH_LEN];
    char resolved_candidate[MAX_PATH_LEN];
    gpg_source_path_class_t normalized_class;
    gpg_source_path_class_t resolved_class;

    if (!candidate || !*candidate || !resolved_out || resolved_out_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG source-home path");
        return -1;
    }
    if (gpg_get_base_dir(base, sizeof(base)) != 0) {
        return -1;
    }
    if (gpg_normalize_path(base, normalized_base, sizeof(normalized_base)) != 0 ||
        gpg_normalize_path(candidate, normalized_candidate,
                           sizeof(normalized_candidate)) != 0) {
        set_error(ERR_INVALID_PATH,
                  "GPG source-home path is invalid or too long: %s",
                  candidate);
        return -1;
    }
    normalized_class = gpg_classify_managed_path(
        normalized_base, normalized_candidate);

    /* Resolve aliases even when their final targets do not exist yet.  Any
     * uncertainty fails closed instead of letting an alias become managed
     * between classification and the GPG child spawn. A resolved descendant
     * dominates a canonical direct-child spelling: otherwise a symlink at a
     * canonical account path could hide a nested managed source and trigger
     * the ordinary HOME/.gnupg fallback. */
    if (gpg_resolve_path_aliases(normalized_base, resolved_base,
                                 sizeof(resolved_base)) != 0 ||
        gpg_resolve_path_aliases(normalized_candidate, resolved_candidate,
                                 sizeof(resolved_candidate)) != 0) {
        set_system_error(ERR_INVALID_PATH,
                         "Cannot safely resolve GPG source-home path: %s",
                         candidate);
        return -1;
    }
    resolved_class = gpg_classify_managed_path(
        resolved_base, resolved_candidate);
    if (normalized_class == GPG_SOURCE_PATH_MANAGED_DESCENDANT ||
        resolved_class == GPG_SOURCE_PATH_MANAGED_DESCENDANT) {
        return GPG_SOURCE_PATH_MANAGED_DESCENDANT;
    }
    if (normalized_class == GPG_SOURCE_PATH_MANAGED_CANONICAL ||
        resolved_class == GPG_SOURCE_PATH_MANAGED_CANONICAL) {
        return GPG_SOURCE_PATH_MANAGED_CANONICAL;
    }
    if (safe_strncpy(resolved_out, resolved_candidate,
                     resolved_out_size) != 0) {
        set_error(ERR_INVALID_PATH, "GPG source-home path is too long");
        return -1;
    }
    return 0;
}

/* Resolve the user's real gpg home to inherit agent settings from: their
 * configured GNUPGHOME when it isn't one of our isolated homes (avoids reading
 * our own generated conf), otherwise ~/.gnupg. Returns 0 on success. */
static int gpg_user_source_home(char *buf, size_t size) {
    const char *env_gh = getenv("GNUPGHOME");
    const char *home;
    char fallback[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    int classification;

    if (!buf || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG source-home destination");
        return -1;
    }
    if (env_gh && *env_gh) {
        classification = gpg_classify_source_path(
            env_gh, resolved, sizeof(resolved));
        if (classification < 0) {
            return -1;
        }
        if (classification == 0) {
            if (safe_strncpy(buf, resolved, size) != 0) {
                set_error(ERR_INVALID_PATH, "GPG source-home path is too long");
                return -1;
            }
            return 0;
        }
        if (classification == GPG_SOURCE_PATH_MANAGED_DESCENDANT) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing managed GPG descendant as the system keyring: %s",
                      env_gh);
            return -1;
        }
    }
    home = getenv("HOME");
    if (!home || !*home) {
        set_error(ERR_INVALID_PATH,
                  "HOME is unset; cannot resolve the system GPG keyring");
        return -1;
    }
    if (safe_snprintf(fallback, sizeof(fallback), "%s/.gnupg", home) != 0) {
        set_error(ERR_INVALID_PATH,
                  "HOME is too long to resolve the system GPG keyring");
        return -1;
    }
    classification = gpg_classify_source_path(
        fallback, resolved, sizeof(resolved));
    if (classification < 0) {
        return -1;
    }
    if (classification > 0) {
        if (classification == GPG_SOURCE_PATH_MANAGED_DESCENDANT) {
            set_error(ERR_PERMISSION_DENIED,
                      "Refusing managed GPG descendant as HOME/.gnupg");
        } else {
            set_error(ERR_INVALID_PATH,
                      "Refusing managed HOME/.gnupg as a system keyring");
        }
        return -1;
    }
    if (safe_strncpy(buf, resolved, size) != 0) {
        set_error(ERR_INVALID_PATH, "GPG source-home path is too long");
        return -1;
    }
    return 0;
}

typedef struct {
    size_t directories;
    size_t entries;
} gpg_source_proof_budget_t;

typedef struct {
    int fd;
    struct stat identity;
    gpg_mount_identity_t mount;
    bool versioned;
    bool has_parent;
    size_t parent_index;
    char name[NAME_MAX + 1];
} gpg_source_proof_entry_t;

struct gpg_source_proof {
    gpg_source_proof_entry_t *entries;
    size_t count;
    size_t capacity;
    bool base_absent;
    char base_path[MAX_PATH_LEN];
    struct stat base_identity;
    gpg_mount_identity_t base_mount;
};

static void gpg_source_proof_destroy(gpg_source_proof_t *proof) {
    size_t index;

    if (!proof) return;
    for (index = 0; index < proof->count; index++) {
        if (proof->entries[index].fd >= 0) {
            close(proof->entries[index].fd);
        }
    }
    free(proof->entries);
    free(proof);
}

/* Transfer one descriptor into the retained proof. Managed-tree entries keep
 * a full directory-version witness; a FreeBSD nullfs backing descriptor keeps
 * only stable object/mount identity because GnuPG may legitimately update an
 * external source directory while the helper is running. */
static int gpg_source_proof_add_owned(
    gpg_source_proof_t *proof, int fd, const struct stat *identity,
    const gpg_mount_identity_t *mount, bool versioned,
    size_t parent_index, const char *name, size_t *index_out) {
    const size_t maximum = GPG_SOURCE_PROOF_MAX_DIRECTORIES +
                           GPG_SOURCE_PROOF_MAX_NULLFS_HOPS + 1U;
    gpg_source_proof_entry_t *grown;
    gpg_source_proof_entry_t *entry;
    bool has_parent = parent_index != SIZE_MAX;
    size_t capacity;

    if (!proof || fd < 0 || !identity || !mount ||
        (has_parent && (!name || !*name || parent_index >= proof->count)) ||
        (!has_parent && name)) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid retained GPG source proof");
        return -1;
    }
    if (proof->count >= maximum) {
        errno = E2BIG;
        set_error(ERR_PERMISSION_DENIED,
                  "Managed GPG ancestry exceeds the retained proof bound");
        return -1;
    }
    if (proof->count == proof->capacity) {
        capacity = proof->capacity == 0 ? 16U : proof->capacity * 2U;
        if (capacity > maximum) capacity = maximum;
        grown = realloc(proof->entries, capacity * sizeof(*grown));
        if (!grown) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot retain the managed GPG ancestry proof");
            return -1;
        }
        proof->entries = grown;
        proof->capacity = capacity;
    }
    entry = &proof->entries[proof->count];
    memset(entry, 0, sizeof(*entry));
    if (has_parent && safe_strncpy(entry->name, name,
                                   sizeof(entry->name)) != 0) {
        errno = ENAMETOOLONG;
        set_error(ERR_INVALID_PATH,
                  "Managed GPG ancestry entry name is too long");
        return -1;
    }
    entry->fd = fd;
    entry->identity = *identity;
    entry->mount = *mount;
    entry->versioned = versioned;
    entry->has_parent = has_parent;
    entry->parent_index = parent_index;
    if (index_out) *index_out = proof->count;
    proof->count++;
    return 0;
}

/* The complete managed-tree witness remains open until the source helper is
 * done. Revalidating every retained directory immediately before and after a
 * helper prevents a cross-branch rename from entering an already-scanned
 * directory unnoticed. Every child is also reopened through its retained
 * parent/name edge so an overlay mount cannot hide behind the old child fd.
 * The public base name is rebound to the exact visible object that supplied
 * the witness. */
static int gpg_source_proof_revalidate(const gpg_source_proof_t *proof) {
    char current_base[MAX_PATH_LEN];
    bool absent = false;
    struct stat current;
    gpg_mount_identity_t current_mount;
    size_t index;
    int base_fd;

    if (!proof || !proof->base_path[0]) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid managed GPG ancestry witness");
        return -1;
    }
    base_fd = gpg_open_base_dir(current_base, sizeof(current_base),
                                false, &absent);
    if (proof->base_absent) {
        if (base_fd >= 0) close(base_fd);
        if (base_fd >= 0 || !absent ||
            strcmp(current_base, proof->base_path) != 0) {
            errno = ESTALE;
            set_error(ERR_PERMISSION_DENIED,
                      "Managed GPG base appeared or changed after source proof");
            return -1;
        }
        return 0;
    }
    if (base_fd < 0) {
        if (absent) {
            errno = ESTALE;
            set_error(ERR_PERMISSION_DENIED,
                      "Managed GPG base disappeared after source proof");
        }
        return -1;
    }
    errno = 0;
    if (strcmp(current_base, proof->base_path) != 0 ||
        fstat(base_fd, &current) != 0 ||
        gpg_mount_identity_fd(base_fd, &current_mount) != 0 ||
        !gpg_same_reset_entry(&proof->base_identity, &current) ||
        !gpg_same_mount(&proof->base_mount, &current_mount)) {
        int saved_errno = errno ? errno : ESTALE;
        close(base_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Managed GPG base changed after source proof");
        return -1;
    }
    close(base_fd);

    for (index = 0; index < proof->count; index++) {
        const gpg_source_proof_entry_t *entry = &proof->entries[index];
        struct stat named_before;
        struct stat named_after;
        struct stat reopened;
        gpg_mount_identity_t reopened_mount;
        int reopened_fd = -1;

        errno = 0;
        if (fstat(entry->fd, &current) != 0 ||
            gpg_mount_identity_fd(entry->fd, &current_mount) != 0 ||
            !gpg_same_mount(&entry->mount, &current_mount) ||
            !gpg_same_reset_entry(&entry->identity, &current) ||
            (entry->versioned &&
             !gpg_same_file_version(&entry->identity, &current))) {
            int saved_errno = errno ? errno : ESTALE;
            errno = saved_errno;
            set_system_error(
                ERR_PERMISSION_DENIED,
                "Managed GPG ancestry changed after source proof");
            return -1;
        }
        if (!entry->has_parent) continue;
        if (entry->parent_index >= index ||
            entry->parent_index >= proof->count) {
            errno = ESTALE;
            set_error(ERR_PERMISSION_DENIED,
                      "Managed GPG ancestry witness is internally inconsistent");
            return -1;
        }
        errno = 0;
        if (fstatat(proof->entries[entry->parent_index].fd, entry->name,
                    &named_before, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(named_before.st_mode) ||
            (reopened_fd = openat(
                 proof->entries[entry->parent_index].fd, entry->name,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
            fstat(reopened_fd, &reopened) != 0 ||
            gpg_mount_identity_fd(reopened_fd, &reopened_mount) != 0 ||
            fstatat(proof->entries[entry->parent_index].fd, entry->name,
                    &named_after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !gpg_same_file_version(&named_before, &reopened) ||
            !gpg_same_file_version(&reopened, &named_after) ||
            !gpg_same_mount(&entry->mount, &reopened_mount) ||
            !gpg_same_reset_entry(&entry->identity, &reopened) ||
            (entry->versioned &&
             !gpg_same_file_version(&entry->identity, &reopened))) {
            int saved_errno = errno ? errno : ESTALE;
            if (reopened_fd >= 0) close(reopened_fd);
            errno = saved_errno;
            set_system_error(
                ERR_PERMISSION_DENIED,
                "Managed GPG ancestry changed after source proof");
            return -1;
        }
        close(reopened_fd);
    }
    return 0;
}

#ifdef __FreeBSD__
static bool gpg_freebsd_mount_snapshot_valid(const struct statfs *mounted) {
    return mounted &&
           memchr(mounted->f_fstypename, '\0',
                  sizeof(mounted->f_fstypename)) != NULL &&
           memchr(mounted->f_mntonname, '\0',
                  sizeof(mounted->f_mntonname)) != NULL &&
           memchr(mounted->f_mntfromname, '\0',
                  sizeof(mounted->f_mntfromname)) != NULL;
}

static bool gpg_freebsd_same_mount_snapshot(const struct statfs *left,
                                            const struct statfs *right) {
    return gpg_freebsd_mount_snapshot_valid(left) &&
           gpg_freebsd_mount_snapshot_valid(right) &&
           memcmp(&left->f_fsid, &right->f_fsid,
                  sizeof(left->f_fsid)) == 0 &&
           strcmp(left->f_fstypename, right->f_fstypename) == 0 &&
           strcmp(left->f_mntonname, right->f_mntonname) == 0 &&
           strcmp(left->f_mntfromname, right->f_mntfromname) == 0;
}

/* mount_nullfs(8) guarantees that the virtual copy changes st_dev but is
 * otherwise indistinguishable from the lower object. Compare all stable
 * directory fields that matter to this proof while deliberately excluding
 * atime (descriptor reads may advance it) and st_dev. */
static bool gpg_freebsd_same_nullfs_directory(const struct stat *upper,
                                              const struct stat *lower) {
    return upper && lower && S_ISDIR(upper->st_mode) &&
           S_ISDIR(lower->st_mode) && upper->st_ino == lower->st_ino &&
           upper->st_mode == lower->st_mode &&
           upper->st_nlink == lower->st_nlink &&
           upper->st_uid == lower->st_uid &&
           upper->st_gid == lower->st_gid &&
           upper->st_size == lower->st_size &&
           upper->st_blocks == lower->st_blocks &&
           upper->st_blksize == lower->st_blksize &&
           upper->st_flags == lower->st_flags &&
           upper->st_gen == lower->st_gen &&
           upper->st_mtim.tv_sec == lower->st_mtim.tv_sec &&
           upper->st_mtim.tv_nsec == lower->st_mtim.tv_nsec &&
           upper->st_ctim.tv_sec == lower->st_ctim.tv_sec &&
           upper->st_ctim.tv_nsec == lower->st_ctim.tv_nsec;
}

/* Pin the terminal lower directory beneath a bounded stack of FreeBSD nullfs
 * mounts. f_mntonname supplies the visible prefix and f_mntfromname its lower
 * replacement. Each mapped path is resolved, opened without following the
 * leaf, matched to the upper vnode under the documented nullfs stat contract,
 * and revalidated. Renamed, truncated, cyclic, or ambiguous mount origins fail
 * closed instead of being treated as external. */
static int gpg_freebsd_unwrap_nullfs_directory(
    const char *visible_path, int visible_fd, char *backing_path,
    size_t backing_path_size, int *backing_fd, bool *backing_fd_owned,
    struct stat *backing_identity, gpg_mount_identity_t *backing_mount) {
    char current_path[MAX_PATH_LEN];
    int current_fd = visible_fd;
    bool current_owned = false;
    unsigned int hop;

    if (!visible_path || visible_fd < 0 || !backing_path ||
        backing_path_size == 0 || !backing_fd || !backing_fd_owned ||
        !backing_identity || !backing_mount ||
        safe_strncpy(current_path, visible_path, sizeof(current_path)) != 0) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid FreeBSD nullfs source proof");
        return -1;
    }
    for (hop = 0; ; hop++) {
        struct stat upper_before;
        struct stat upper_after;
        struct stat lower_opened;
        struct stat lower_named;
        struct statfs mount_before;
        struct statfs mount_after;
        const char *suffix;
        size_t mountpoint_len;
        char lower_raw[MAX_PATH_LEN];
        char lower_resolved[MAX_PATH_LEN];
        int lower_fd;

        errno = 0;
        if (fstat(current_fd, &upper_before) != 0 ||
            fstatfs(current_fd, &mount_before) != 0 ||
            !gpg_freebsd_mount_snapshot_valid(&mount_before)) {
            int saved_errno = errno ? errno : ESTALE;
            if (current_owned) close(current_fd);
            errno = saved_errno;
            set_system_error(ERR_PERMISSION_DENIED,
                             "Cannot inspect FreeBSD GPG mount lineage");
            return -1;
        }
        if (strcmp(mount_before.f_fstypename, "nullfs") != 0) {
            if (safe_strncpy(backing_path, current_path,
                             backing_path_size) != 0 ||
                gpg_mount_identity_fd(current_fd, backing_mount) != 0) {
                int saved_errno = errno ? errno : ENAMETOOLONG;
                if (current_owned) close(current_fd);
                errno = saved_errno;
                set_system_error(ERR_PERMISSION_DENIED,
                                 "Cannot retain FreeBSD GPG mount lineage");
                return -1;
            }
            *backing_fd = current_fd;
            *backing_fd_owned = current_owned;
            *backing_identity = upper_before;
            return 0;
        }
        if (hop >= GPG_SOURCE_PROOF_MAX_NULLFS_HOPS ||
            mount_before.f_mntonname[0] != '/' ||
            mount_before.f_mntfromname[0] != '/') {
            if (current_owned) close(current_fd);
            errno = ELOOP;
            set_error(ERR_PERMISSION_DENIED,
                      "FreeBSD nullfs GPG lineage is unbounded or non-absolute");
            return -1;
        }
        mountpoint_len = strlen(mount_before.f_mntonname);
        if (strcmp(mount_before.f_mntonname, "/") == 0) {
            suffix = strcmp(current_path, "/") == 0 ? "" : current_path;
        } else if (strcmp(current_path, mount_before.f_mntonname) == 0) {
            suffix = "";
        } else if (strncmp(current_path, mount_before.f_mntonname,
                           mountpoint_len) == 0 &&
                   current_path[mountpoint_len] == '/') {
            suffix = current_path + mountpoint_len;
        } else {
            if (current_owned) close(current_fd);
            errno = ESTALE;
            set_error(ERR_PERMISSION_DENIED,
                      "FreeBSD nullfs mount does not contain the pinned GPG path");
            return -1;
        }
        if ((strcmp(mount_before.f_mntfromname, "/") == 0
                 ? safe_snprintf(lower_raw, sizeof(lower_raw), "%s",
                                 suffix[0] ? suffix : "/")
                 : safe_snprintf(lower_raw, sizeof(lower_raw), "%s%s",
                                 mount_before.f_mntfromname, suffix)) != 0 ||
            !lower_raw[0] ||
            gpg_resolve_path_aliases(lower_raw, lower_resolved,
                                     sizeof(lower_resolved)) != 0 ||
            strcmp(lower_resolved, current_path) == 0) {
            int saved_errno = errno ? errno : ESTALE;
            if (current_owned) close(current_fd);
            errno = saved_errno;
            set_system_error(ERR_PERMISSION_DENIED,
                             "Cannot resolve FreeBSD nullfs GPG origin");
            return -1;
        }
        errno = 0;
        lower_fd = open(lower_resolved,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (lower_fd < 0 || fstat(lower_fd, &lower_opened) != 0 ||
            lstat(lower_resolved, &lower_named) != 0 ||
            fstat(current_fd, &upper_after) != 0 ||
            fstatfs(current_fd, &mount_after) != 0 ||
            !gpg_same_file_version(&upper_before, &upper_after) ||
            !gpg_freebsd_same_mount_snapshot(&mount_before, &mount_after) ||
            !gpg_freebsd_same_nullfs_directory(&upper_after, &lower_opened) ||
            !gpg_same_file_version(&lower_opened, &lower_named)) {
            int saved_errno = errno ? errno : ESTALE;
            if (lower_fd >= 0) close(lower_fd);
            if (current_owned) close(current_fd);
            errno = saved_errno;
            set_system_error(ERR_PERMISSION_DENIED,
                             "FreeBSD nullfs GPG origin changed during proof");
            return -1;
        }
        if (current_owned) close(current_fd);
        current_fd = lower_fd;
        current_owned = true;
        if (safe_strncpy(current_path, lower_resolved,
                         sizeof(current_path)) != 0) {
            close(current_fd);
            errno = ENAMETOOLONG;
            set_error(ERR_INVALID_PATH,
                      "FreeBSD nullfs GPG origin path is too long");
            return -1;
        }
    }
}
#endif

static int gpg_source_matches_managed_identity(
    const gpg_source_home_t *source, const struct stat *candidate,
    const gpg_mount_identity_t *candidate_mount) {
    if (!source || source->fd < 0 || !candidate || !candidate_mount) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid managed GPG source-provenance proof");
        return -1;
    }
    if (candidate->st_dev == source->identity.st_dev &&
        candidate->st_ino == source->identity.st_ino) {
        set_error(ERR_PERMISSION_DENIED,
                  gpg_same_mount(&source->mount, candidate_mount)
                      ? "Refusing managed GPG home as the system keyring: %s"
                      : "Refusing bind-mounted alias of a managed GPG home: %s",
                  source->path);
        return 1;
    }
    return 0;
}

/* Compare the pinned source against every descriptor-opened directory below
 * the managed base. Each entry is observed without following links, opened,
 * matched to that observation, recursively inspected, and then re-statted.
 * A source exposed through an external bind mount keeps the nested directory's
 * device/inode pair and is therefore rejected even though its mount ID differs.
 * Nested mounts and unstable/oversized trees fail closed: skipping either
 * would turn an incomplete search into false external provenance. */
static int gpg_source_matches_managed_tree_at(
    const gpg_source_home_t *source, int directory_fd,
    const gpg_mount_identity_t *base_mount, unsigned int depth,
    gpg_source_proof_budget_t *budget, gpg_source_proof_t *proof,
    size_t parent_index, const char *entry_name) {
    struct stat directory_before;
    struct stat directory_after;
    gpg_mount_identity_t directory_mount;
    int scan_fd;
    DIR *dir;
    struct dirent *entry;
    size_t directory_index;
    int match;

    if (!source || directory_fd < 0 || !base_mount || !budget || !proof) {
        if (directory_fd >= 0) close(directory_fd);
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid managed GPG ancestry proof");
        return -1;
    }
    if (depth > GPG_SOURCE_PROOF_MAX_DEPTH) {
        close(directory_fd);
        errno = E2BIG;
        set_error(ERR_PERMISSION_DENIED,
                  "Managed GPG ancestry exceeds the bounded source-proof depth");
        return -1;
    }
    if (++budget->directories > GPG_SOURCE_PROOF_MAX_DIRECTORIES) {
        close(directory_fd);
        errno = E2BIG;
        set_error(ERR_PERMISSION_DENIED,
                  "Managed GPG ancestry exceeds the retained directory bound");
        return -1;
    }
    errno = 0;
    if (fstat(directory_fd, &directory_before) != 0 ||
        !S_ISDIR(directory_before.st_mode) ||
        directory_before.st_uid != getuid() ||
        (directory_before.st_mode & 022) != 0) {
        int saved_errno = errno ? errno : EACCES;
        close(directory_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot prove a managed GPG descendant directory");
        return -1;
    }
    if (depth == 0) {
        directory_mount = *base_mount;
    } else if (gpg_mount_identity_fd(directory_fd, &directory_mount) != 0) {
        int saved_errno = errno;
        close(directory_fd);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot prove a managed GPG descendant mount");
        return -1;
    }
    match = gpg_source_matches_managed_identity(
        source, &directory_before, &directory_mount);
    if (match != 0) {
        close(directory_fd);
        return match;
    }
    if (!gpg_same_mount(base_mount, &directory_mount)) {
        close(directory_fd);
        errno = EXDEV;
        set_error(ERR_PERMISSION_DENIED,
                  "Cannot prove GPG source ancestry across a nested managed mount");
        return -1;
    }
    if (gpg_source_proof_add_owned(
            proof, directory_fd, &directory_before, &directory_mount, true,
            parent_index, entry_name, &directory_index) != 0) {
        close(directory_fd);
        return -1;
    }

    scan_fd = openat(directory_fd, ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        int saved_errno = errno;
        if (scan_fd >= 0) close(scan_fd);
        errno = saved_errno;
        set_system_error(ERR_FILE_IO,
                         "Cannot enumerate managed GPG descendants for source proof");
        return -1;
    }
    for (;;) {
        struct stat named;
        struct stat opened;
        struct stat revalidated;
        int child_fd;

        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                set_system_error(
                    ERR_FILE_IO,
                    "Cannot enumerate managed GPG descendants for source proof");
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (++budget->entries > GPG_SOURCE_PROOF_MAX_ENTRIES) {
            closedir(dir);
            errno = E2BIG;
            set_error(ERR_PERMISSION_DENIED,
                      "Managed GPG ancestry exceeds the bounded source-proof size");
            return -1;
        }
        if (fstatat(directory_fd, entry->d_name, &named,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            int saved_errno = errno;
            closedir(dir);
            errno = saved_errno;
            set_system_error(
                ERR_FILE_IO,
                "Cannot inspect a managed GPG descendant for source proof");
            return -1;
        }
        if (!S_ISDIR(named.st_mode)) continue;

        child_fd = openat(directory_fd, entry->d_name,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0 || fstat(child_fd, &opened) != 0 ||
            !S_ISDIR(opened.st_mode) || opened.st_uid != getuid() ||
            (opened.st_mode & 022) != 0 ||
            !gpg_same_reset_entry(&named, &opened)) {
            int saved_errno = errno ? errno : ESTALE;
            if (child_fd >= 0) close(child_fd);
            closedir(dir);
            errno = saved_errno;
            set_system_error(
                ERR_PERMISSION_DENIED,
                "Managed GPG descendant changed while proving source ancestry");
            return -1;
        }
        match = gpg_source_matches_managed_tree_at(
            source, child_fd, base_mount, depth + 1U, budget, proof,
            directory_index, entry->d_name);
        errno = 0;
        if (match == 0 &&
            (fstatat(directory_fd, entry->d_name, &revalidated,
                     AT_SYMLINK_NOFOLLOW) != 0 ||
             !gpg_same_file_version(&opened, &revalidated))) {
            errno = errno ? errno : ESTALE;
            set_system_error(
                ERR_PERMISSION_DENIED,
                "Managed GPG descendant changed during source ancestry proof");
            match = -1;
        }
        if (match != 0) {
            closedir(dir);
            return match;
        }
    }
    errno = 0;
    if (fstat(directory_fd, &directory_after) != 0 ||
        !gpg_same_file_version(&directory_before, &directory_after)) {
        int saved_errno = errno ? errno : ESTALE;
        closedir(dir);
        errno = saved_errno;
        set_system_error(
            ERR_PERMISSION_DENIED,
            "Managed GPG directory changed during source ancestry proof");
        return -1;
    }
    closedir(dir);
    return 0;
}

static int gpg_source_matches_managed_home(
    gpg_source_home_t *source) {
    char base[MAX_PATH_LEN];
    bool absent = false;
    struct stat base_identity;
    gpg_mount_identity_t base_mount;
    gpg_source_proof_budget_t budget;
    gpg_source_proof_t *proof;
    gpg_source_home_t proof_source;
    int base_fd;
    int tree_fd = -1;
    int match;
#ifdef __FreeBSD__
    char source_backing[MAX_PATH_LEN];
    char base_backing[MAX_PATH_LEN];
    struct stat source_backing_identity;
    struct stat base_backing_identity;
    gpg_mount_identity_t source_backing_mount;
    gpg_mount_identity_t base_backing_mount;
    int source_backing_fd = -1;
    int base_backing_fd = -1;
    bool source_backing_owned = false;
    bool base_backing_owned = false;
    gpg_source_path_class_t backing_class;
#endif

    if (!source || source->fd < 0 || source->proof) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS, "Invalid GPG source ancestry handle");
        return -1;
    }
    proof = calloc(1, sizeof(*proof));
    if (!proof) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate the managed GPG ancestry proof");
        return -1;
    }

    base_fd = gpg_open_base_dir(base, sizeof(base), false, &absent);
    if (base_fd < 0) {
        if (!absent || safe_strncpy(proof->base_path, base,
                                    sizeof(proof->base_path)) != 0) {
            gpg_source_proof_destroy(proof);
            return -1;
        }
        proof->base_absent = true;
        source->proof = proof;
        return 0;
    }
    errno = 0;
    if (fstat(base_fd, &base_identity) != 0 ||
        gpg_mount_identity_fd(base_fd, &base_mount) != 0 ||
        safe_strncpy(proof->base_path, base,
                     sizeof(proof->base_path)) != 0) {
        int saved_errno = errno ? errno : ENAMETOOLONG;
        close(base_fd);
        gpg_source_proof_destroy(proof);
        errno = saved_errno;
        set_system_error(ERR_PERMISSION_DENIED,
                         "Cannot pin the managed GPG base for source proof");
        return -1;
    }
    proof->base_identity = base_identity;
    proof->base_mount = base_mount;
    proof_source = *source;
    proof_source.proof = NULL;

#ifdef __FreeBSD__
    if (gpg_freebsd_unwrap_nullfs_directory(
            source->path, source->fd, source_backing,
            sizeof(source_backing), &source_backing_fd,
            &source_backing_owned, &source_backing_identity,
            &source_backing_mount) != 0 ||
        gpg_freebsd_unwrap_nullfs_directory(
            base, base_fd, base_backing, sizeof(base_backing),
            &base_backing_fd, &base_backing_owned,
            &base_backing_identity, &base_backing_mount) != 0) {
        if (source_backing_owned && source_backing_fd >= 0) {
            close(source_backing_fd);
        }
        close(base_fd);
        gpg_source_proof_destroy(proof);
        return -1;
    }
    proof_source.fd = source_backing_fd;
    proof_source.identity = source_backing_identity;
    proof_source.mount = source_backing_mount;
    if (source_backing_owned &&
        gpg_source_proof_add_owned(
            proof, source_backing_fd, &source_backing_identity,
            &source_backing_mount, false, SIZE_MAX, NULL, NULL) != 0) {
        close(source_backing_fd);
        if (base_backing_owned) close(base_backing_fd);
        close(base_fd);
        gpg_source_proof_destroy(proof);
        return -1;
    }
    source_backing_owned = false;
    backing_class = gpg_classify_managed_path(base_backing,
                                              source_backing);
    if (backing_class != GPG_SOURCE_PATH_EXTERNAL) {
        if (base_backing_owned) close(base_backing_fd);
        close(base_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing nullfs alias of a managed GPG home: %s",
                  source->path);
        gpg_source_proof_destroy(proof);
        return 1;
    }
    tree_fd = base_backing_fd;
    if (base_backing_owned) {
        close(base_fd);
        base_fd = -1;
    } else {
        base_fd = -1;
    }
    (void)base_backing_identity;
    base_mount = base_backing_mount;
#else
    tree_fd = base_fd;
    base_fd = -1;
#endif
    memset(&budget, 0, sizeof(budget));
    match = gpg_source_matches_managed_tree_at(
        &proof_source, tree_fd, &base_mount, 0, &budget, proof,
        SIZE_MAX, NULL);
    tree_fd = -1;
    if (match == 0 && gpg_source_proof_revalidate(proof) != 0) {
        match = -1;
    }
    if (match != 0) {
        if (base_fd >= 0) close(base_fd);
        gpg_source_proof_destroy(proof);
        return match;
    }
    source->proof = proof;
    return 0;
}

static int gpg_validate_source_home(const gpg_source_home_t *source) {
    struct stat current;
    gpg_mount_identity_t current_mount;

    if (!source || source->fd < 0 || !source->path[0] || !source->proof ||
        fstat(source->fd, &current) != 0 ||
        gpg_mount_identity_fd(source->fd, &current_mount) != 0 ||
        !S_ISDIR(current.st_mode) || current.st_uid != getuid() ||
        (current.st_mode & 022) != 0 ||
        current.st_dev != source->identity.st_dev ||
        current.st_ino != source->identity.st_ino ||
        !gpg_same_mount(&current_mount, &source->mount)) {
        set_error(ERR_PERMISSION_DENIED,
                  "Pinned GPG source home is no longer safe: %s",
                  source && source->path[0] ? source->path : "(unknown)");
        return -1;
    }
    return gpg_source_proof_revalidate(source->proof);
}

/* Cache acceptance is stricter than a real descriptor-pinned listing: no
 * helper runs on a hit, so the public source pathname must still reopen to the
 * exact retained directory and mount immediately before reuse. Real listings
 * intentionally keep operating on their already-pinned source if that public
 * name is concurrently replaced, then report the result from the object they
 * actually inspected. */
static int gpg_validate_source_home_binding(
    const gpg_source_home_t *source) {
    struct stat named;
    gpg_mount_identity_t named_mount;
    int named_fd;

    if (gpg_validate_source_home(source) != 0) return -1;
    named_fd = open(source->path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (named_fd < 0 || fstat(named_fd, &named) != 0 ||
        gpg_mount_identity_fd(named_fd, &named_mount) != 0 ||
        !S_ISDIR(named.st_mode) || named.st_uid != getuid() ||
        (named.st_mode & 022) != 0 ||
        named.st_dev != source->identity.st_dev ||
        named.st_ino != source->identity.st_ino ||
        !gpg_same_mount(&named_mount, &source->mount)) {
        if (named_fd >= 0) close(named_fd);
        set_error(ERR_PERMISSION_DENIED,
                  "GPG source pathname no longer names the pinned home: %s",
                  source->path);
        return -1;
    }
    close(named_fd);
    return 0;
}

/* Return 0 with a retained descriptor, 1 only for confirmed ENOENT, and -1
 * for every resolution/access/provenance error. */
static int gpg_open_user_source_home(gpg_source_home_t *source) {
    int provenance;

    if (!source) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG source-home handle");
        return -1;
    }
    memset(source, 0, sizeof(*source));
    source->fd = -1;
    if (gpg_user_source_home(source->path, sizeof(source->path)) != 0) {
        return -1;
    }
    source->fd = open(source->path,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (source->fd < 0) {
        if (errno == ENOENT) {
            return 1;
        }
        set_system_error(ERR_FILE_IO,
                         "Cannot open the system GPG keyring home: %s",
                         source->path);
        return -1;
    }
    if (fstat(source->fd, &source->identity) != 0 ||
        !S_ISDIR(source->identity.st_mode) ||
        source->identity.st_uid != getuid() ||
        (source->identity.st_mode & 022) != 0 ||
        gpg_mount_identity_fd(source->fd, &source->mount) != 0) {
        set_error(ERR_PERMISSION_DENIED,
                  "Refusing unsafe system GPG keyring home: %s",
                  source->path);
        gpg_close_source_home(source);
        return -1;
    }
    provenance = gpg_source_matches_managed_home(source);
    if (provenance != 0) {
        gpg_close_source_home(source);
        return -1;
    }
    return 0;
}

static void gpg_close_source_home(gpg_source_home_t *source) {
    if (!source) return;
    if (source->fd >= 0) close(source->fd);
    gpg_source_proof_destroy(source->proof);
    source->fd = -1;
    source->proof = NULL;
}

/* Set up gpg-agent.conf for the isolated environment.
 *
 * Inherits the user's real gpg-agent.conf (their pinentry choice — e.g. a GUI
 * pinentry — plus cache settings) so isolation never silently downgrades their
 * pinentry. Only when the user has no config of their own do we write minimal
 * defaults, and a *detected* pinentry is appended only if none is already set
 * (the compiled-in default can be wrong, e.g. on FreeBSD). Re-run each switch,
 * so edits to the user's real config propagate. */
static int setup_gpg_agent_config(int home_fd, const char *gnupg_home,
                                  gpg_agent_config_update_t *update) {
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
    char source_conf[MAX_PATH_LEN];
    unsigned char *desired = NULL;
    size_t desired_len = 0;
    bool inherited = false;
    struct stat created;
    struct stat fd_now;
    struct stat entry;
    bool have_created_identity = false;
    bool temp_registered = false;
    bool installed = false;
    bool state_present = false;
    bool state_pending = false;
    bool state_matches = false;
    int source_fd = -1;
    int fd = -1;
    int matched_fd = -1;
    int match;
    int source_rc;
    struct stat matched_identity;
    gpg_source_home_t source = { .fd = -1 };

    if (home_fd < 0 || !gnupg_home || !update) {
        set_error(ERR_INVALID_ARGS, "Invalid GPG agent config destination");
        return -1;
    }
    gpg_agent_config_update_init(update);
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
     * file. This is what makes the byte-identical path genuinely zero-write.
     * Only confirmed source-home/config absence selects defaults; path,
     * access, and provenance failures leave the installed config untouched. */
    source_rc = gpg_open_user_source_home(&source);
    if (source_rc < 0) {
        goto fail;
    }
    if (source_rc == 0) {
        struct stat before;
        struct stat opened;
        struct stat after;
        if (safe_snprintf(source_conf, sizeof(source_conf),
                          "%s/gpg-agent.conf", source.path) != 0) {
            set_error(ERR_INVALID_PATH,
                      "Inherited gpg-agent.conf path is too long");
            goto fail;
        }
        if (gpg_validate_source_home(&source) != 0) {
            goto fail;
        }
        if (fstatat(source.fd, "gpg-agent.conf", &before,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(before.st_mode) || before.st_uid != getuid() ||
                before.st_nlink != 1 || (before.st_mode & 022) != 0) {
                set_error(ERR_PERMISSION_DENIED,
                          "Refusing unsafe inherited gpg-agent.conf: %s",
                          source_conf);
                goto fail;
            }
            if (g_agent_conf_preopen) g_agent_conf_preopen(source_conf);
            source_fd = openat(source.fd, "gpg-agent.conf",
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
            if (fstatat(source.fd, "gpg-agent.conf", &after,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
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
            if (gpg_validate_source_home(&source) != 0) {
                goto fail;
            }
            inherited = true;
            log_debug("Inherited gpg-agent.conf from %s", source_conf);
        } else if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO,
                             "Failed to inspect inherited gpg-agent.conf: %s",
                             source_conf);
            goto fail;
        }
    }
    gpg_close_source_home(&source);

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

    match = gpg_agent_conf_matches(home_fd, desired, desired_len,
                                   &matched_fd, &matched_identity);
    if (match < 0) goto fail;
    if (match > 0) {
        /* Matching bytes do not prove that a prior rename is directory-durable.
         * Re-sync the pinned home so a retry after post-rename fsync failure
         * repairs that uncertain namespace commit before reporting success. */
        if (g_agent_conf_sync(home_fd, true) != 0) {
            set_system_error(
                ERR_FILE_IO,
                "Failed to synchronize unchanged installed gpg-agent.conf");
            goto fail;
        }
        if (gpg_open_agent_reload_state(
                home_fd, &update->marker_fd, &update->marker_identity,
                &state_present, &state_pending) != 0) {
            goto fail;
        }
        if (state_present && !state_pending &&
            gpg_agent_reload_state_matches_config(
                home_fd, update->marker_fd, &update->marker_identity,
                &matched_identity, &state_matches) != 0) {
            goto fail;
        }
        if (state_matches &&
            gpg_validate_agent_update_entry(
                home_fd, "gpg-agent.conf", matched_fd,
                &matched_identity, matched_identity.st_size,
                "Installed gpg-agent.conf") != 0) {
            goto fail;
        }
        if (state_matches) {
            update->config_fd = matched_fd;
            update->config_identity = matched_identity;
            matched_fd = -1;
            if (gpg_agent_config_update_close(update) != 0) {
                free(desired);
                set_system_error(
                    ERR_FILE_IO,
                    "Failed to close unchanged GPG agent configuration");
                return -1;
            }
            free(desired);
            log_debug("Reused unchanged GPG agent configuration: %s",
                      gpg_agent_conf_path);
            return 0;
        }
        if (find_command_path("gpgconf", update->gpgconf_path,
                              sizeof(update->gpgconf_path)) != 0) {
            int resolve_errno = errno;
            errno = resolve_errno;
            set_system_error(
                ERR_SYSTEM_COMMAND_FAILED,
                "Cannot resolve trusted gpgconf for GPG agent reload");
            errno = resolve_errno;
            goto fail;
        }
        update->config_fd = matched_fd;
        update->config_identity = matched_identity;
        matched_fd = -1;
        update->reload_required = true;
        if (gpg_set_agent_reload_pending(home_fd, update) != 0) {
            goto fail;
        }
        update->config_witness = desired;
        update->config_witness_length = desired_len;
        desired = NULL;
        log_debug("Reused pending GPG agent configuration: %s",
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
    if (signals_scratch_register(temp_path) != 0) {
        set_error(ERR_FILE_IO,
                  "Failed to register temporary gpg-agent.conf for cleanup");
        goto fail;
    }
    temp_registered = true;
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
    if (find_command_path("gpgconf", update->gpgconf_path,
                          sizeof(update->gpgconf_path)) != 0) {
        int resolve_errno = errno;
        errno = resolve_errno;
        set_system_error(
            ERR_SYSTEM_COMMAND_FAILED,
            "Cannot resolve trusted gpgconf for GPG agent reload");
        errno = resolve_errno;
        goto fail;
    }
    if (gpg_open_agent_reload_state(
            home_fd, &update->marker_fd, &update->marker_identity,
            &state_present, &state_pending) != 0 ||
        gpg_set_agent_reload_pending(home_fd, update) != 0) {
        goto fail;
    }
    if (renameat(home_fd, temp_name, home_fd, "gpg-agent.conf") != 0) {
        set_system_error(ERR_FILE_IO, "Failed to install gpg-agent.conf atomically");
        goto fail;
    }
    installed = true;
    signals_scratch_unregister(temp_path);
    temp_registered = false;
    if (fstat(fd, &fd_now) != 0 ||
        fstatat(home_fd, "gpg-agent.conf", &entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        entry.st_dev != created.st_dev || entry.st_ino != created.st_ino ||
        !gpg_same_file_version(&fd_now, &entry) ||
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
    if (fstat(fd, &fd_now) != 0 ||
        fstatat(home_fd, "gpg-agent.conf", &entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !gpg_same_file_version(&fd_now, &entry)) {
        set_error(ERR_FILE_IO,
                  "Installed gpg-agent.conf changed after synchronization");
        goto fail;
    }
    /* FreeBSD/UFS can materialize the final ctime only when the writable
     * descriptor is closed. Retaining it made a later, otherwise read-only
     * activation proof observe a false generation change. Close it now, then
     * re-open and byte-prove the published inode from the pinned directory
     * before handing a read-only proof descriptor to the reload phase. */
    if (close(fd) != 0) {
        fd = -1;
        set_system_error(ERR_FILE_IO,
                         "Failed to close installed gpg-agent.conf");
        goto fail;
    }
    fd = -1;
    match = gpg_agent_conf_matches(home_fd, desired, desired_len,
                                   &matched_fd, &matched_identity);
    if (match != 1 || matched_identity.st_dev != created.st_dev ||
        matched_identity.st_ino != created.st_ino) {
        if (match >= 0) {
            set_error(ERR_FILE_IO,
                      "Installed gpg-agent.conf changed after publication");
        }
        goto fail;
    }
    update->config_fd = matched_fd;
    update->config_identity = matched_identity;
    matched_fd = -1;
    update->reload_required = true;
    update->config_witness = desired;
    update->config_witness_length = desired_len;
    desired = NULL;

    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;

fail:
    if (source_fd >= 0) close(source_fd);
    gpg_close_source_home(&source);
    if (matched_fd >= 0) close(matched_fd);
    if (fd >= 0) close(fd);
    gpg_agent_config_update_close(update);
    /* A failed commit must never delete a pathname another process substituted.
     * Remove only names which still resolve to the inode created above. */
    if (!installed && have_created_identity && temp_name[0] &&
        fstatat(home_fd, temp_name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        entry.st_dev == created.st_dev && entry.st_ino == created.st_ino) {
        (void)unlinkat(home_fd, temp_name, 0);
    }
    if (temp_registered) signals_scratch_unregister(temp_path);
    free(desired);
    return -1;
}

int gpg_manager_setup_agent_config_for_test(int home_fd,
                                            const char *gnupg_home) {
    gpg_agent_config_update_t update;
    int close_rc;
    int rc;

    gpg_agent_config_update_init(&update);
    rc = setup_gpg_agent_config(home_fd, gnupg_home, &update);
    close_rc = gpg_agent_config_update_close(&update);
    if (rc == 0 && close_rc != 0) {
        set_system_error(ERR_FILE_IO,
                         "Failed to close staged GPG agent configuration");
        rc = -1;
    }
    return rc;
}
