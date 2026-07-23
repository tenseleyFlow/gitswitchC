/* AR-07 T11: GPG cleanup boundaries and byte-identical write avoidance. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "scratch_registry_test.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#endif

#ifdef __linux__
/* AR-10 L31: bare unshare(CLONE_NEWNS) needs CAP_SYS_ADMIN, so these
 * security regressions green-skipped on every non-root host — including
 * every CI lane, none of which required the capability. Fall back to a user
 * namespace: mapping the caller's own ids grants CAP_SYS_ADMIN over a fresh
 * mount namespace, so the bind-mount assertions actually run unprivileged.
 * Callers still _exit(77)->skip when both routes are unavailable (e.g.
 * kernels with unprivileged user namespaces disabled). */
static int write_exact(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    ssize_t length = (ssize_t)strlen(text);

    if (fd < 0) return -1;
    if (write(fd, text, (size_t)length) != length) {
        (void)close(fd);
        return -1;
    }
    return close(fd);
}

static int enter_private_mount_namespace(void) {
    char map[64];
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWNS) == 0) return 0;
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return -1;
    /* setgroups must be denied before an unprivileged gid_map write. */
    if (write_exact("/proc/self/setgroups", "deny") != 0) return -1;
    snprintf(map, sizeof(map), "%u %u 1", (unsigned)uid, (unsigned)uid);
    if (write_exact("/proc/self/uid_map", map) != 0) return -1;
    snprintf(map, sizeof(map), "%u %u 1", (unsigned)gid, (unsigned)gid);
    if (write_exact("/proc/self/gid_map", map) != 0) return -1;
    return 0;
}
#endif

static int g_runner_calls;

static int recording_null_runner(const char *const argv[],
                                 const run_opts_t *opts,
                                 run_result_t *result) {
    (void)argv;
    g_runner_calls++;
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    return 0;
}

static int make_file(const char *path, const char *content) {
    return write_string_to_file(path, content ? content : "x\n", 0600);
}

static char g_gpgconf_fixture_dir[MAX_PATH_LEN];
static char *g_gpgconf_saved_path;
static bool g_gpgconf_saved_path_present;
static bool g_gpgconf_fixture_active;

static void remove_gpgconf_fixture(void) {
    if (g_gpgconf_fixture_dir[0] != '\0') {
        ts_rm_rf(g_gpgconf_fixture_dir);
        g_gpgconf_fixture_dir[0] = '\0';
    }
}

static int restore_gpgconf_fixture(void) {
    int rc = 0;

    if (g_gpgconf_fixture_active) {
        rc = g_gpgconf_saved_path_present
                 ? setenv("PATH", g_gpgconf_saved_path, 1)
                 : unsetenv("PATH");
    }
    free(g_gpgconf_saved_path);
    g_gpgconf_saved_path = NULL;
    g_gpgconf_saved_path_present = false;
    g_gpgconf_fixture_active = false;
    remove_gpgconf_fixture();
    return rc;
}

/* These tests inject command results but intentionally exercise production's
 * trusted gpgconf resolution and reload bookkeeping. Homebrew's prefix is not
 * a production-trusted executable location, so give every host the same
 * private, runnable gpgconf fixture instead of depending on its package
 * manager layout. */
static int install_gpgconf_fixture(void) {
    static const char program[] = "#!/bin/sh\nexit 0\n";
    char executable[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *path = getenv("PATH");
    char *saved_path = path ? strdup(path) : NULL;
    char *fixture_path = NULL;
    size_t dir_len;
    size_t path_len = path ? strlen(path) : 0;
    size_t fixture_len;

    if (g_gpgconf_fixture_active || (path && !saved_path)) {
        free(saved_path);
        errno = g_gpgconf_fixture_active ? EALREADY : ENOMEM;
        return -1;
    }
    if (!ts_mkdtemp_trusted(g_gpgconf_fixture_dir,
                            sizeof(g_gpgconf_fixture_dir),
                            "gsw-ar11-gpgconf") ||
        safe_snprintf(executable, sizeof(executable), "%s/gpgconf",
                      g_gpgconf_fixture_dir) != 0 ||
        write_string_to_file(executable, program, 0700) != 0 ||
        chmod(executable, 0700) != 0) {
        free(saved_path);
        remove_gpgconf_fixture();
        return -1;
    }

    dir_len = strlen(g_gpgconf_fixture_dir);
    if (path_len > SIZE_MAX - dir_len - 2U) {
        free(saved_path);
        remove_gpgconf_fixture();
        errno = EOVERFLOW;
        return -1;
    }
    fixture_len = dir_len + (path_len > 0 ? path_len + 1U : 0U) + 1U;
    fixture_path = malloc(fixture_len);
    if (!fixture_path) {
        free(saved_path);
        remove_gpgconf_fixture();
        return -1;
    }
    memcpy(fixture_path, g_gpgconf_fixture_dir, dir_len);
    if (path_len > 0) {
        fixture_path[dir_len] = ':';
        memcpy(fixture_path + dir_len + 1U, path, path_len + 1U);
    } else {
        fixture_path[dir_len] = '\0';
    }

    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        free(saved_path);
        remove_gpgconf_fixture();
        return -1;
    }
    free(fixture_path);
    g_gpgconf_saved_path = saved_path;
    g_gpgconf_saved_path_present = path != NULL;
    g_gpgconf_fixture_active = true;
    if (find_command_path("gpgconf", resolved, sizeof(resolved)) != 0 ||
        strcmp(resolved, executable) != 0) {
        int saved_errno = errno;

        (void)restore_gpgconf_fixture();
        errno = saved_errno ? saved_errno : ENOEXEC;
        return -1;
    }
    return 0;
}

static int make_home(char *xdg, size_t xdg_size,
                     char *base, size_t base_size,
                     char *home, size_t home_size,
                     const char *account) {
    if (snprintf(xdg, xdg_size, "/tmp/gswar07gpg_XXXXXX") < 0 ||
        !ts_mkdtemp(xdg) || chmod(xdg, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", xdg, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        (size_t)snprintf(base, base_size, "%s/gitswitch-gpg", xdg) >=
            base_size ||
        (size_t)snprintf(home, home_size, "%s/%s", base, account) >=
            home_size ||
        mkdir(base, 0700) != 0 || chmod(base, 0700) != 0 ||
        mkdir(home, 0700) != 0 || chmod(home, 0700) != 0) {
        return -1;
    }
    return 0;
}

static bool base_contains_only_lock(const char *base) {
    DIR *dir = opendir(base);
    struct dirent *entry;
    bool saw_lock = false;

    if (!dir) return false;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, ".lock") == 0 && !saw_lock) {
            saw_lock = true;
            continue;
        }
        closedir(dir);
        return false;
    }
    closedir(dir);
    return saw_lock;
}

static bool has_agent_conf_scratch(const char *home) {
    static const char prefix[] = ".gpg-agent.conf.gitswitch.";
    DIR *dir = opendir(home);
    struct dirent *entry;

    if (!dir) return false;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) == 0) {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}

TEST(ordinary_same_mount_recursion_still_cleans) {
    char xdg[128], base[256], home[320];
    char nested[384], deeper[448], one[512], two[512];
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(nested, sizeof(nested), "%s/private-keys-v1.d", home);
    snprintf(deeper, sizeof(deeper), "%s/deeper", nested);
    snprintf(one, sizeof(one), "%s/key-one", home);
    snprintf(two, sizeof(two), "%s/key-two", deeper);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(mkdir(deeper, 0700), 0);
    CHECK_EQ_INT(make_file(one, "one\n"), 0);
    CHECK_EQ_INT(make_file(two, "two\n"), 0);

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(previous);

    CHECK(!path_exists(home));
    CHECK(path_exists(base));
}

static dev_t g_injected_mount_dev;
static ino_t g_injected_mount_ino;

static int injected_mount_identity(int fd, uint64_t *identity) {
    struct stat st;
    if (fd < 0 || !identity || fstat(fd, &st) != 0) return -1;
    *identity = st.st_dev == g_injected_mount_dev &&
                        st.st_ino == g_injected_mount_ino
                    ? 2U
                    : 1U;
    return 0;
}

/* Deterministic mutation witness for M19. The nested directory deliberately
 * shares st_dev with its home but receives a different injected mount ID. A
 * weakened st_dev-only comparison therefore deletes it and fails this test,
 * independent of whether the host permits the real bind-mount fixture. */
TEST(same_device_different_mount_identity_is_rejected) {
    char xdg[128], base[256], home[320], nested[384], marker[448];
    struct stat home_st;
    struct stat nested_st;
    gpg_mount_identity_probe_fn old_probe;
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(nested, sizeof(nested), "%s/injected-mount", home);
    snprintf(marker, sizeof(marker), "%s/precious", nested);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(make_file(marker, "keep\n"), 0);
    CHECK_EQ_INT(stat(home, &home_st), 0);
    CHECK_EQ_INT(stat(nested, &nested_st), 0);
    CHECK_EQ_INT(home_st.st_dev, nested_st.st_dev);
    g_injected_mount_dev = nested_st.st_dev;
    g_injected_mount_ino = nested_st.st_ino;

    g_runner_calls = 0;
    old_probe = gpg_manager_set_mount_identity_probe_fn(
        injected_mount_identity);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    run_set_runner(previous);
    gpg_manager_set_mount_identity_probe_fn(old_probe);

    CHECK_EQ_INT(g_runner_calls, 0);
    CHECK(path_exists(marker));
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(previous);
}

TEST(preexisting_hardlink_blocks_before_agent_stop_or_deletion) {
    char xdg[128], base[256], home[320], secret[384], outside[256];
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(secret, sizeof(secret), "%s/private.key", home);
    snprintf(outside, sizeof(outside), "%s/external-hardlink", xdg);
    CHECK_EQ_INT(make_file(secret, "secret\n"), 0);
    CHECK_EQ_INT(link(secret, outside), 0);

    g_runner_calls = 0;
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    run_set_runner(previous);

    CHECK_EQ_INT(g_runner_calls, 0);
    CHECK(path_exists(secret));
    CHECK(path_exists(outside));
    CHECK_EQ_INT(unlink(outside), 0);

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(previous);
    CHECK(!path_exists(home));
}

static char g_race_hardlink[MAX_PATH_LEN];
static bool g_race_hook_called;

static int add_hardlink_after_validation(int home_fd) {
    g_race_hook_called = true;
    return linkat(home_fd, "private.key", AT_FDCWD, g_race_hardlink, 0);
}

TEST(hardlink_added_between_validation_and_delete_is_rejected) {
    char xdg[128], base[256], home[320], secret[384];
    gpg_cleanup_predelete_fn old_hook;
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(secret, sizeof(secret), "%s/private.key", home);
    snprintf(g_race_hardlink, sizeof(g_race_hardlink), "%s/raced-hardlink",
             xdg);
    CHECK_EQ_INT(make_file(secret, "secret\n"), 0);

    g_race_hook_called = false;
    old_hook = gpg_manager_set_cleanup_predelete_fn(
        add_hardlink_after_validation);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), -1);
    run_set_runner(previous);
    gpg_manager_set_cleanup_predelete_fn(old_hook);

    CHECK(g_race_hook_called);
    CHECK(path_exists(secret));
    CHECK(path_exists(g_race_hardlink));
    CHECK_EQ_INT(unlink(g_race_hardlink), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(previous);
}

TEST(full_reset_rejects_every_unknown_base_entry_before_deletion) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    char orphan[320], hidden_link[320], stray[320], publish[384];
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    snprintf(orphan, sizeof(orphan), "%s/.orphan", base);
    snprintf(hidden_link, sizeof(hidden_link), "%s/.hidden-link", base);
    snprintf(stray, sizeof(stray), "%s/stray", base);
    snprintf(publish, sizeof(publish),
             "%s/.gitswitch-gpg-publish.interrupted", base);
    CHECK_EQ_INT(make_file(marker, "secret\n"), 0);
    CHECK_EQ_INT(symlink(home, current), 0);
    CHECK_EQ_INT(make_file(orphan, "unknown\n"), 0);

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(path_exists(marker));
    CHECK(path_exists(orphan));
    CHECK_EQ_INT(unlink(orphan), 0);

    CHECK_EQ_INT(symlink(home, hidden_link), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(path_exists(marker));
    CHECK_EQ_INT(unlink(hidden_link), 0);

    CHECK_EQ_INT(make_file(stray, "not-a-home\n"), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(path_exists(marker));
    CHECK_EQ_INT(unlink(stray), 0);

    /* AR-12 L11: a crash-orphaned publish/rollback quarantine SYMLINK no
     * longer bricks full reset forever — reset retires the owned residue
     * and completes the teardown it was asked for. */
    CHECK_EQ_INT(symlink(home, publish), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(previous);
    CHECK(lstat(publish, &(struct stat){0}) != 0 && errno == ENOENT);

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(previous);
    CHECK(!path_exists(home));
    CHECK(lstat(current, &(struct stat){0}) != 0 && errno == ENOENT);
    CHECK(base_contains_only_lock(base));
}

/* AR-13 M8: a quarantine name embeds the creating pid. A crash orphan has a
 * dead pid, but a quarantine whose pid belongs to a DIFFERENT live process is
 * the live retry handle of a concurrent gitswitch. Full reset must refuse
 * (leaving that owner's recovery intact) rather than unlink it before the
 * destructive pass; this process's own residue is still cleared. */
TEST(full_reset_refuses_live_owned_quarantine_but_retires_own) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    char live[416], mine[416];
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(make_file(marker, "secret\n"), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    /* pid 1 (init) is always live; kill(1,0) yields 0 or EPERM, both meaning
     * "process exists" -> the reset must refuse and preserve the quarantine. */
    snprintf(live, sizeof(live),
             "%s/.gitswitch-gpg-rollback.1.0123456789abcdef", base);
    CHECK_EQ_INT(symlink(home, live), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(lstat(live, &(struct stat){0}) == 0); /* live-owned: preserved */
    CHECK(path_exists(marker));                  /* nothing destroyed */
    CHECK_EQ_INT(unlink(live), 0);

    /* This process's own residue is a clearable orphan: reset retires it and
     * proceeds with the teardown it was asked for. */
    snprintf(mine, sizeof(mine),
             "%s/.gitswitch-gpg-rollback.%ld.0123456789abcdef",
             base, (long)getpid());
    CHECK_EQ_INT(symlink(home, mine), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(previous);
    CHECK(lstat(mine, &(struct stat){0}) != 0 && errno == ENOENT);
    CHECK(!path_exists(home));
}

/* AR-13 L34 / L11: an UNWITNESSED reset-prefix quarantine is the residue of an
 * interrupted reset whose completion witness never landed — its retry state is
 * indeterminate. Full reset must fail CLOSED: preserve the quarantine, block
 * the fresh teardown, and destroy nothing, rather than silently deleting an
 * incomplete transaction's only recovery handle. (The reset prefix has its own
 * quarantine+witness retry machinery, distinct from the rollback/publish
 * orphan path — a bare reset symlink is exactly this unwitnessed residue.) */
TEST(full_reset_fails_closed_on_unwitnessed_reset_quarantine) {
    char xdg[128], base[256], home[320], marker[384], current[320];
    char residue[416];
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(current, sizeof(current), "%s/current", base);
    CHECK_EQ_INT(make_file(marker, "secret\n"), 0);
    CHECK_EQ_INT(symlink(home, current), 0);

    snprintf(residue, sizeof(residue),
             "%s/.gitswitch-gpg-reset.1.0123456789abcdef", base);
    CHECK_EQ_INT(symlink(home, residue), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(strstr(get_last_error()->message,
                 "Unwitnessed GPG reset quarantine preserved") != NULL);
    CHECK(lstat(residue, &(struct stat){0}) == 0); /* residue preserved */
    CHECK(path_exists(marker));                    /* nothing destroyed */
    CHECK_EQ_INT(unlink(residue), 0);
}

/* AR-13 L34 / AR-12 P3: the removal walk is depth-bounded (each frame holds a
 * DIR stream and a child fd, so an adversarially deep home is both a stack and
 * an fd-exhaustion hazard). Nest a directory chain past GPG_SOURCE_PROOF_MAX_DEPTH
 * (64) under a managed home and assert reset refuses with the bounded-depth
 * diagnostic and destroys nothing, rather than descending without limit. */
TEST(reset_walk_refuses_adversarially_deep_home) {
    char xdg[128], base[256], home[320], marker[384], deep[2048];
    command_runner_fn previous;
    size_t len;
    size_t home_len;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    CHECK_EQ_INT(make_file(marker, "secret\n"), 0);

    home_len = strlen(home);
    len = (size_t)snprintf(deep, sizeof(deep), "%s", home);
    CHECK(len < sizeof(deep));
    /* 66 nested levels: strictly deeper than the depth-64 bound (home is walked
     * at depth 0, so a chain of >64 dirs forces a walk at depth 65). */
    for (int i = 0; i < 66; i++) {
        CHECK(len + 2U < sizeof(deep));
        deep[len++] = '/';
        deep[len++] = 'd';
        deep[len] = '\0';
        CHECK_EQ_INT(mkdir(deep, 0700), 0);
    }

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    CHECK(strstr(get_last_error()->message,
                 "bounded reset walk depth") != NULL);
    CHECK(path_exists(marker)); /* refused before destroying anything */

    /* Unwind the deep chain so fixture teardown can remove the tree. */
    while (len > home_len) {
        deep[len] = '\0';
        (void)rmdir(deep);
        len -= 2U;
    }
    deep[len] = '\0';
    (void)unlink(marker);
    (void)rmdir(home);
    (void)rmdir(base);
}

static int inject_late_residue(int base_fd) {
    int fd = openat(base_fd, ".late-residue",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (fd < 0) return -1;
    return close(fd);
}

TEST(final_enumeration_catches_late_unknown_survivor) {
    char xdg[128], base[256], home[320], marker[384], late[320];
    gpg_reset_final_hook_fn old_hook;
    command_runner_fn previous;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(marker, sizeof(marker), "%s/private.key", home);
    snprintf(late, sizeof(late), "%s/.late-residue", base);
    CHECK_EQ_INT(make_file(marker, "secret\n"), 0);

    old_hook = gpg_manager_set_reset_final_hook_fn(inject_late_residue);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), -1);
    run_set_runner(previous);
    gpg_manager_set_reset_final_hook_fn(old_hook);

    CHECK(!path_exists(home));
    CHECK(path_exists(late));
    CHECK_EQ_INT(unlink(late), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset(NULL), 0);
    run_set_runner(previous);
    CHECK(base_contains_only_lock(base));
}

#ifdef __linux__
TEST(nested_bind_mount_is_never_traversed) {
    char xdg[128], base[256], home[320], nested[384];
    char external[256], marker[320];
    pid_t child;
    int status = 0;
    bool mount_namespace_unavailable = false;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "work"), 0);
    snprintf(nested, sizeof(nested), "%s/mounted", home);
    snprintf(external, sizeof(external), "%s/external", xdg);
    snprintf(marker, sizeof(marker), "%s/precious", external);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(make_file(marker, "keep\n"), 0);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        command_runner_fn previous;
        int rc;
        if (enter_private_mount_namespace() != 0 ||
            mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ||
            mount(external, nested, NULL, MS_BIND, NULL) != 0) {
            _exit(77);
        }
        previous = run_set_runner(recording_null_runner);
        rc = gpg_manager_reset("work");
        run_set_runner(previous);
        if (rc != -1 || access(marker, F_OK) != 0 ||
            access(home, F_OK) != 0) {
            (void)umount2(nested, MNT_DETACH);
            _exit(9);
        }
        if (umount2(nested, MNT_DETACH) != 0) _exit(9);
        _exit(0);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
            mount_namespace_unavailable = true;
        } else {
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    CHECK(path_exists(marker));
    if (mount_namespace_unavailable) {
        TS_SKIP("mount-namespace",
                "private mount namespace/bind mount unavailable");
    }
}

TEST(bind_mounted_account_home_is_rejected_before_config_write) {
    char xdg[128], base[256], home[320], external[256], installed[320];
    pid_t child;
    int status = 0;
    bool mount_namespace_unavailable = false;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "mounted"), 0);
    snprintf(external, sizeof(external), "%s/external-home", xdg);
    snprintf(installed, sizeof(installed), "%s/gpg-agent.conf", external);
    CHECK_EQ_INT(mkdir(external, 0700), 0);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        gpg_config_t config;
        account_t account;
        int rc;

        if (enter_private_mount_namespace() != 0 ||
            mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ||
            mount(external, home, NULL, MS_BIND, NULL) != 0) {
            _exit(77);
        }
        memset(&config, 0, sizeof(config));
        config.mode = GPG_MODE_ISOLATED;
        memset(&account, 0, sizeof(account));
        snprintf(account.name, sizeof(account.name), "mounted");
        rc = gpg_create_isolated_home(&config, &account);
        if (rc != -1 || access(installed, F_OK) == 0 || errno != ENOENT) {
            (void)umount2(home, MNT_DETACH);
            _exit(9);
        }
        if (umount2(home, MNT_DETACH) != 0) _exit(9);
        _exit(0);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
            mount_namespace_unavailable = true;
        } else {
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    CHECK(!path_exists(installed));
    if (mount_namespace_unavailable) {
        TS_SKIP("mount-namespace",
                "private mount namespace/bind mount unavailable");
    }
}
#endif

static int g_precommit_calls;
static int g_file_syncs;
static int g_directory_syncs;
static bool g_fail_file_sync;
static bool g_fail_directory_sync;

static int count_agent_conf_commit(int home_fd, const char *temp_name) {
    (void)home_fd;
    (void)temp_name;
    g_precommit_calls++;
    return 0;
}

static int record_agent_conf_sync(int fd, bool directory) {
    if (directory) {
        g_directory_syncs++;
        if (g_fail_directory_sync) {
            errno = EIO;
            return -1;
        }
    } else {
        g_file_syncs++;
        if (g_fail_file_sync) {
            errno = EIO;
            return -1;
        }
    }
    return fsync(fd);
}

TEST(mounted_account_home_is_rejected_before_config_write) {
    char xdg[128], base[256], home[320], installed[384];
    struct stat home_st;
    gpg_mount_identity_probe_fn old_probe;
    gpg_agent_conf_precommit_fn old_hook;
    command_runner_fn previous;
    gpg_config_t config;
    account_t account;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "mounted"), 0);
    CHECK_EQ_INT(stat(home, &home_st), 0);
    snprintf(installed, sizeof(installed), "%s/gpg-agent.conf", home);
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    memset(&account, 0, sizeof(account));
    snprintf(account.name, sizeof(account.name), "mounted");

    g_injected_mount_dev = home_st.st_dev;
    g_injected_mount_ino = home_st.st_ino;
    g_precommit_calls = 0;
    old_probe = gpg_manager_set_mount_identity_probe_fn(
        injected_mount_identity);
    old_hook = gpg_manager_set_agent_conf_precommit_fn(
        count_agent_conf_commit);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), -1);
    gpg_manager_set_agent_conf_precommit_fn(old_hook);
    gpg_manager_set_mount_identity_probe_fn(old_probe);

    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    CHECK(strstr(get_last_error()->message, "mounted outside") != NULL);
    CHECK_EQ_INT(g_precommit_calls, 0);
    CHECK(!path_exists(installed));

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("mounted"), 0);
    run_set_runner(previous);
}

static bool same_mtime(const struct stat *left, const struct stat *right) {
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

TEST(byte_identical_agent_config_performs_no_commit) {
    static const char original[] =
        "default-cache-ttl 99\n"
        "pinentry-program /usr/bin/pinentry-test\n";
    static const char changed[] =
        "default-cache-ttl 123\n"
        "pinentry-program /usr/bin/pinentry-test\n";
    char xdg[128], base[256], source_home[256], source_conf[320];
    char installed[MAX_PATH_LEN], content[256];
    struct stat first;
    struct stat second;
    struct stat third;
    gpg_agent_conf_precommit_fn old_hook;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn previous;
    gpg_config_t config;
    account_t account;

    snprintf(xdg, sizeof(xdg), "/tmp/gswar07conf_XXXXXX");
    CHECK(ts_mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(source_home, sizeof(source_home), "%s/source-home", xdg);
    snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf",
             source_home);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(make_file(source_conf, original), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);
    CHECK_EQ_INT(setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);

    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    memset(&account, 0, sizeof(account));
    snprintf(account.name, sizeof(account.name), "work");
    snprintf(installed, sizeof(installed),
             "%s/gitswitch-gpg/work/gpg-agent.conf", xdg);

    g_precommit_calls = 0;
    g_file_syncs = 0;
    g_directory_syncs = 0;
    g_fail_file_sync = false;
    g_fail_directory_sync = false;
    old_hook = gpg_manager_set_agent_conf_precommit_fn(
        count_agent_conf_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(record_agent_conf_sync);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), 0);
    CHECK_EQ_INT(stat(installed, &first), 0);
    CHECK_EQ_INT(g_precommit_calls, 1);
    /* Config temp, durable reload obligation, then completed-reload state. */
    CHECK_EQ_INT(g_file_syncs, 3);
    CHECK_EQ_INT(g_directory_syncs, 2);

    g_file_syncs = 0;
    g_directory_syncs = 0;
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), 0);
    CHECK_EQ_INT(stat(installed, &second), 0);
    CHECK_EQ_INT(g_precommit_calls, 1);
    CHECK_EQ_INT(first.st_ino, second.st_ino);
    CHECK(same_mtime(&first, &second));
    CHECK(!has_agent_conf_scratch(config.gnupg_home));
    CHECK_EQ_INT(g_file_syncs, 0);
    CHECK_EQ_INT(g_directory_syncs, 1);

    CHECK_EQ_INT(make_file(source_conf, changed), 0);
    g_file_syncs = 0;
    g_directory_syncs = 0;
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &account), 0);
    CHECK_EQ_INT(stat(installed, &third), 0);
    CHECK_EQ_INT(g_precommit_calls, 2);
    CHECK(first.st_ino != third.st_ino);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(changed) - 1));
    CHECK_STR_EQ(content, changed);
    CHECK(!has_agent_conf_scratch(config.gnupg_home));
    CHECK_EQ_INT(g_file_syncs, 3);
    CHECK_EQ_INT(g_directory_syncs, 2);
    gpg_manager_set_agent_conf_precommit_fn(old_hook);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("work"), 0);
    run_set_runner(previous);
    CHECK(base_contains_only_lock(base));
    unsetenv("GNUPGHOME");
    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

TEST(agent_config_sync_failures_return_nonzero) {
    static const char original[] =
        "default-cache-ttl 10\n"
        "pinentry-program /usr/bin/pinentry-test\n";
    static const char changed[] =
        "default-cache-ttl 20\n"
        "pinentry-program /usr/bin/pinentry-test\n";
    char xdg[128], base[256], home[320], source_home[256];
    char source_conf[320], installed[384], content[256];
    struct stat st;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn previous;
    int home_fd;

    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "syncfault"), 0);
    snprintf(source_home, sizeof(source_home), "%s/source-home", xdg);
    snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf",
             source_home);
    snprintf(installed, sizeof(installed), "%s/gpg-agent.conf", home);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(make_file(source_conf, original), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(home_fd >= 0);

    old_sync = gpg_manager_set_agent_conf_sync_fn(record_agent_conf_sync);
    g_file_syncs = 0;
    g_directory_syncs = 0;
    g_fail_file_sync = true;
    g_fail_directory_sync = false;
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK_EQ_INT(g_file_syncs, 1);
    CHECK_EQ_INT(g_directory_syncs, 0);
    CHECK(lstat(installed, &st) != 0 && errno == ENOENT);
    CHECK(!has_agent_conf_scratch(home));

    g_file_syncs = 0;
    g_directory_syncs = 0;
    g_fail_file_sync = false;
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), 0);
    /* The focused writer publishes a durable pending obligation; only the
     * production prepare path may run gpgconf and mark it complete. */
    CHECK_EQ_INT(g_file_syncs, 2);
    CHECK_EQ_INT(g_directory_syncs, 2);
    CHECK_EQ_INT(make_file(source_conf, changed), 0);

    g_file_syncs = 0;
    g_directory_syncs = 0;
    g_fail_directory_sync = true;
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK_EQ_INT(g_file_syncs, 2);
    CHECK_EQ_INT(g_directory_syncs, 1);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(original) - 1));
    CHECK_STR_EQ(content, original);
    CHECK(!has_agent_conf_scratch(home));

    g_fail_directory_sync = false;
    g_file_syncs = 0;
    g_directory_syncs = 0;
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), 0);
    CHECK_EQ_INT(g_file_syncs, 2);
    CHECK_EQ_INT(g_directory_syncs, 2);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(changed) - 1));
    CHECK_STR_EQ(content, changed);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    if (home_fd >= 0) CHECK_EQ_INT(close(home_fd), 0);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("syncfault"), 0);
    run_set_runner(previous);
    unsetenv("GNUPGHOME");
}

TEST(agent_config_defaults_require_confirmed_source_absence) {
    static const char retained[] =
        "# retain this config on source resolution failure\n"
        "default-cache-ttl 17\n";
    char xdg[128], base[256], home[320], installed[384];
    char inaccessible[256], absent[256], content[512];
    char old_home[MAX_PATH_LEN] = "";
    char old_gnupghome[MAX_PATH_LEN] = "";
    char overlong[MAX_PATH_LEN + 64];
    bool had_home = getenv("HOME") != NULL;
    bool had_gnupghome = getenv("GNUPGHOME") != NULL;
    command_runner_fn previous;
    int home_fd;

    if (had_home) safe_strncpy(old_home, getenv("HOME"), sizeof(old_home));
    if (had_gnupghome) {
        safe_strncpy(old_gnupghome, getenv("GNUPGHOME"),
                     sizeof(old_gnupghome));
    }
    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "source-errors"), 0);
    snprintf(installed, sizeof(installed), "%s/gpg-agent.conf", home);
    snprintf(inaccessible, sizeof(inaccessible), "%s/inaccessible", xdg);
    snprintf(absent, sizeof(absent), "%s/confirmed-absent", xdg);
    CHECK_EQ_INT(make_file(installed, retained), 0);
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(home_fd >= 0);

    unsetenv("GNUPGHOME");
    unsetenv("HOME");
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK(strstr(get_last_error()->message, "HOME is unset") != NULL);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(retained) - 1));
    CHECK_STR_EQ(content, retained);

    memset(overlong, 'a', sizeof(overlong));
    overlong[0] = '/';
    overlong[sizeof(overlong) - 1] = '\0';
    CHECK_EQ_INT(setenv("GNUPGHOME", overlong, 1), 0);
    CHECK_EQ_INT(setenv("HOME", xdg, 1), 0);
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK(strstr(get_last_error()->message, "too long") != NULL);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(retained) - 1));
    CHECK_STR_EQ(content, retained);

    CHECK_EQ_INT(mkdir(inaccessible, 0700), 0);
    CHECK_EQ_INT(chmod(inaccessible, 0000), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", inaccessible, 1), 0);
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK(strstr(get_last_error()->message, "Cannot open") != NULL ||
          strstr(get_last_error()->message, "unsafe") != NULL);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(retained) - 1));
    CHECK_STR_EQ(content, retained);
    CHECK_EQ_INT(chmod(inaccessible, 0700), 0);

    /* ENOENT is the sole source-resolution outcome that may compose and
     * install defaults in place of the retained configuration. */
    CHECK_EQ_INT(setenv("GNUPGHOME", absent, 1), 0);
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), 0);
    CHECK(read_file_to_string(installed, content, sizeof(content)) > 0);
    CHECK(strstr(content, "GPG Agent configuration for gitswitch") != NULL);
    CHECK(strstr(content, "default-cache-ttl 3600") != NULL);
    CHECK(strstr(content, "retain this config") == NULL);
    CHECK(!has_agent_conf_scratch(home));

    if (home_fd >= 0) CHECK_EQ_INT(close(home_fd), 0);
    if (had_home) setenv("HOME", old_home, 1); else unsetenv("HOME");
    if (had_gnupghome) {
        setenv("GNUPGHOME", old_gnupghome, 1);
    } else {
        unsetenv("GNUPGHOME");
    }
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("source-errors"), 0);
    run_set_runner(previous);
}

TEST(managed_descendant_agent_config_is_rejected_without_mutation) {
    static const char retained[] =
        "# existing isolated policy\n"
        "default-cache-ttl 17\n";
    static const char managed_source[] =
        "# must never be inherited from managed state\n"
        "default-cache-ttl 999\n";
    char xdg[128], base[256], home[320], nested[384];
    char source_conf[448], installed[384], content[512];
    const char *inherited_gnupghome = getenv("GNUPGHOME");
    bool had_gnupghome = inherited_gnupghome != NULL;
    char *saved_gnupghome = had_gnupghome
                                ? strdup(inherited_gnupghome)
                                : NULL;
    command_runner_fn previous;
    int home_fd;

    if (had_gnupghome && !saved_gnupghome) {
        CHECK(!"failed to retain GNUPGHOME for managed-source fixture");
        return;
    }
    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "ancestry"), 0);
    CHECK_EQ_INT(safe_snprintf(nested, sizeof(nested), "%s/nested",
                               home), 0);
    CHECK_EQ_INT(safe_snprintf(source_conf, sizeof(source_conf),
                               "%s/gpg-agent.conf", nested), 0);
    CHECK_EQ_INT(safe_snprintf(installed, sizeof(installed),
                               "%s/gpg-agent.conf", home), 0);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(make_file(source_conf, managed_source), 0);
    CHECK_EQ_INT(make_file(installed, retained), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", nested, 1), 0);
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(home_fd >= 0);

    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(retained) - 1));
    CHECK_STR_EQ(content, retained);
    CHECK(!has_agent_conf_scratch(home));

    if (home_fd >= 0) CHECK_EQ_INT(close(home_fd), 0);
    if (had_gnupghome) {
        CHECK_EQ_INT(setenv("GNUPGHOME", saved_gnupghome, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
    }
    free(saved_gnupghome);
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("ancestry"), 0);
    run_set_runner(previous);
}

TEST(agent_config_registration_failure_is_atomic_and_retryable) {
    static const char source[] =
        "default-cache-ttl 31\n"
        "pinentry-program /usr/bin/pinentry-test\n";
    char scratch[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE];
    char xdg[128], base[256], home[320], source_home[256];
    char source_conf[320], installed[384], content[256];
    char old_gnupghome[MAX_PATH_LEN] = "";
    bool had_gnupghome = getenv("GNUPGHOME") != NULL;
    command_runner_fn previous;
    size_t registered;
    int home_fd;
    int before;

    if (had_gnupghome) {
        safe_strncpy(old_gnupghome, getenv("GNUPGHOME"),
                     sizeof(old_gnupghome));
    }
    CHECK_EQ_INT(make_home(xdg, sizeof(xdg), base, sizeof(base),
                           home, sizeof(home), "scratchfull"), 0);
    snprintf(source_home, sizeof(source_home), "%s/source-home", xdg);
    snprintf(source_conf, sizeof(source_conf), "%s/gpg-agent.conf",
             source_home);
    snprintf(installed, sizeof(installed), "%s/gpg-agent.conf", home);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(make_file(source_conf, source), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(home_fd >= 0);

    before = test_open_fd_count();
    registered = test_scratch_fill(scratch, "gpg-full");
    CHECK(registered > 0 && registered < TEST_SCRATCH_PROBE_MAX);
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), -1);
    CHECK(strstr(get_last_error()->message, "register") != NULL);
    errno = 0;
    CHECK(lstat(installed, &(struct stat){0}) != 0 && errno == ENOENT);
    CHECK(!has_agent_conf_scratch(home));

    test_scratch_release(scratch, registered);
    CHECK_EQ_INT(test_open_fd_count(), before);
    clear_error();
    CHECK_EQ_INT(gpg_manager_setup_agent_config_for_test(home_fd, home), 0);
    CHECK_EQ_INT(read_file_to_string(installed, content, sizeof(content)),
                 (int)(sizeof(source) - 1));
    CHECK_STR_EQ(content, source);
    CHECK(!has_agent_conf_scratch(home));

    if (home_fd >= 0) CHECK_EQ_INT(close(home_fd), 0);
    if (had_gnupghome) {
        setenv("GNUPGHOME", old_gnupghome, 1);
    } else {
        unsetenv("GNUPGHOME");
    }
    previous = run_set_runner(recording_null_runner);
    CHECK_EQ_INT(gpg_manager_reset("scratchfull"), 0);
    run_set_runner(previous);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    if (install_gpgconf_fixture() != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot install trusted gpgconf fixture\n");
        return 1;
    }
    RUN_TEST(ordinary_same_mount_recursion_still_cleans);
    RUN_TEST(same_device_different_mount_identity_is_rejected);
    RUN_TEST(preexisting_hardlink_blocks_before_agent_stop_or_deletion);
    RUN_TEST(hardlink_added_between_validation_and_delete_is_rejected);
    RUN_TEST(full_reset_rejects_every_unknown_base_entry_before_deletion);
    RUN_TEST(full_reset_refuses_live_owned_quarantine_but_retires_own);
    RUN_TEST(full_reset_fails_closed_on_unwitnessed_reset_quarantine);
    RUN_TEST(reset_walk_refuses_adversarially_deep_home);
    RUN_TEST(final_enumeration_catches_late_unknown_survivor);
#ifdef __linux__
    RUN_TEST(nested_bind_mount_is_never_traversed);
    RUN_TEST(bind_mounted_account_home_is_rejected_before_config_write);
#endif
    RUN_TEST(mounted_account_home_is_rejected_before_config_write);
    RUN_TEST(byte_identical_agent_config_performs_no_commit);
    RUN_TEST(agent_config_sync_failures_return_nonzero);
    RUN_TEST(agent_config_defaults_require_confirmed_source_absence);
    RUN_TEST(managed_descendant_agent_config_is_rejected_without_mutation);
    RUN_TEST(agent_config_registration_failure_is_atomic_and_retryable);
    if (restore_gpgconf_fixture() != 0) {
        fprintf(stderr,
                "HARNESS FAIL: cannot restore PATH after gpgconf tests\n");
        return 1;
    }
TEST_MAIN_END()
