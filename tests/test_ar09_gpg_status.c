/* AR-09 M15: real-GnuPG evidence that exit status 2 is not a result type. */
#ifdef __linux__
#define _XOPEN_SOURCE 700
#endif

#include "test.h"
#include "error.h"
#include "gpg_manager.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

static char g_trusted_gpg_dir[MAX_PATH_LEN];
static char *g_saved_path;
static bool g_saved_path_present;
static bool g_trusted_gpg_active;

static int run_gpg_version_path(const char *path) {
    int status;
    pid_t waited;
    pid_t pid = fork();

    if (pid < 0) return -1;
    if (pid == 0) {
        int null_fd = open("/dev/null", O_WRONLY);

        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        if (null_fd > STDERR_FILENO) close(null_fd);
        execl(path, path, "--version", (char *)NULL);
        _exit(127);
    }

    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

static int restore_trusted_gpg(void) {
    int rc;

    if (!g_trusted_gpg_active) return 0;
    rc = g_saved_path_present ? setenv("PATH", g_saved_path, 1)
                              : unsetenv("PATH");
    free(g_saved_path);
    g_saved_path = NULL;
    g_saved_path_present = false;
    g_trusted_gpg_active = false;
    return rc;
}

/* The executable resolver deliberately rejects Homebrew's group-writable
 * prefix. This suite is evidence for real-GnuPG result semantics rather than
 * executable-path trust, so place the already-provisioned binary in the same
 * private trusted fixture class used by the other external-runtime tests.
 * The copy remains a real GnuPG process; only its executable pathname changes. */
static int activate_trusted_gpg_copy(const char *source_path) {
    char canonical_source[MAX_PATH_LEN];
    char destination[MAX_PATH_LEN];
    const char *path = getenv("PATH");
    char *saved_path = NULL;
    char *fixture_path = NULL;
    size_t dir_len;
    size_t path_len = path ? strlen(path) : 0;
    size_t fixture_len;
    int preflight_rc;

    if (!source_path || !*source_path || g_trusted_gpg_active) {
        errno = EINVAL;
        return -1;
    }
    preflight_rc = run_gpg_version_path(source_path);
    if (preflight_rc <= 0) return preflight_rc;
    /* Homebrew command entries may be symlinks, while copy_file()
     * intentionally rejects symlink sources. Resolve the already-executed
     * fixture command to a regular byte source before copying it. */
    if (!realpath(source_path, canonical_source)) return -1;
    if (path) {
        saved_path = strdup(path);
        if (!saved_path) return -1;
    }
    if (!ts_mkdtemp_trusted(g_trusted_gpg_dir,
                            sizeof(g_trusted_gpg_dir),
                            "gsw-ar09-gpg-bin") ||
        safe_snprintf(destination, sizeof(destination), "%s/gpg",
                      g_trusted_gpg_dir) != 0 ||
        copy_file(canonical_source, destination) != 0 ||
        chmod(destination, 0700) != 0) {
        free(saved_path);
        return -1;
    }

    dir_len = strlen(g_trusted_gpg_dir);
    if (path_len > SIZE_MAX - dir_len - 2U) {
        free(saved_path);
        errno = EOVERFLOW;
        return -1;
    }
    fixture_len = dir_len + (path_len > 0 ? path_len + 1U : 0U) + 1U;
    fixture_path = malloc(fixture_len);
    if (!fixture_path) {
        free(saved_path);
        return -1;
    }
    memcpy(fixture_path, g_trusted_gpg_dir, dir_len);
    if (path_len > 0) {
        fixture_path[dir_len] = ':';
        memcpy(fixture_path + dir_len + 1U, path, path_len + 1U);
    } else {
        fixture_path[dir_len] = '\0';
    }

    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        free(saved_path);
        return -1;
    }
    free(fixture_path);
    g_saved_path = saved_path;
    g_saved_path_present = path != NULL;
    g_trusted_gpg_active = true;
    if (!command_exists("gpg") || run_gpg_version_path(destination) != 1) {
        int saved_errno = errno;

        (void)restore_trusted_gpg();
        errno = saved_errno ? saved_errno : ENOEXEC;
        return -1;
    }
    return 1;
}

static int prepare_real_gpg(void) {
    static const char *const homebrew_candidates[] = {
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        NULL
    };

    if (command_exists("gpg")) return 1;
    for (size_t i = 0; homebrew_candidates[i]; i++) {
        int rc = activate_trusted_gpg_copy(homebrew_candidates[i]);

        if (rc != 0) return rc;
    }
    return 0;
}

static int make_gpg_home(char *home, size_t size) {
    if (safe_snprintf(home, size, "/tmp/gswar09gpg_XXXXXX") != 0 ||
        !ts_mkdtemp(home) || chmod(home, 0700) != 0 ||
        setenv("GNUPGHOME", home, 1) != 0) {
        return -1;
    }
    return 0;
}

/* C16 regression: the fallback must move a runnable command out of a
 * rejected directory without relaxing the resolver. A tiny script is enough
 * to prove the fixture mechanics; the following cases exercise real GnuPG. */
TEST(untrusted_runtime_is_copied_to_a_trusted_test_path) {
    static const char probe[] = "#!/bin/sh\nexit 0\n";
    char source_dir[MAX_PATH_LEN];
    char source_path[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *path = getenv("PATH");
    char *saved_path = path ? strdup(path) : NULL;
    bool path_present = path != NULL;
    bool raw_path_installed = false;
    int activation_rc;

    if (path && !saved_path) {
        CHECK(false);
        return;
    }
    if (!ts_mkdtemp_trusted(source_dir, sizeof(source_dir),
                            "gsw-ar09-gpg-source") ||
        safe_snprintf(source_path, sizeof(source_path), "%s/gpg",
                      source_dir) != 0 ||
        write_string_to_file(source_path, probe, 0700) != 0 ||
        chmod(source_dir, 0770) != 0 ||
        setenv("PATH", source_dir, 1) != 0) {
        CHECK(false);
        goto cleanup;
    }
    raw_path_installed = true;
    CHECK(!command_exists("gpg"));
    activation_rc = activate_trusted_gpg_copy(source_path);
    CHECK_EQ_INT(activation_rc, 1);
    if (activation_rc == 1) {
        int find_rc;

        CHECK(command_exists("gpg"));
        find_rc = find_command_path("gpg", resolved, sizeof(resolved));
        CHECK_EQ_INT(find_rc, 0);
        if (find_rc == 0) CHECK_EQ_INT(run_gpg_version_path(resolved), 1);
    }

cleanup:
    if (restore_trusted_gpg() != 0) CHECK(false);
    if (raw_path_installed || !path_present) {
        int rc = path_present ? setenv("PATH", saved_path, 1)
                              : unsetenv("PATH");
        if (rc != 0) CHECK(false);
    }
    free(saved_path);
}

TEST(real_gpg_absent_selector_has_structured_miss_evidence) {
    char home[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    int home_rc;

    if (!command_exists("gpg")) {
        TS_SKIP("gpg", "gpg unavailable in trusted PATH");
    }
    home_rc = make_gpg_home(home, sizeof(home));
    CHECK_EQ_INT(home_rc, 0);
    if (home_rc != 0) return;
    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "0123456789ABCDEF", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_NOT_FOUND);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "resolved no secret key") != NULL);
    CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
}

TEST(real_gpg_corrupt_keybox_is_an_operational_failure) {
    char home[MAX_PATH_LEN];
    char keybox[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    int home_rc;
    int path_rc;
    int write_rc;

    if (!command_exists("gpg")) {
        TS_SKIP("gpg", "gpg unavailable in trusted PATH");
    }
    home_rc = make_gpg_home(home, sizeof(home));
    CHECK_EQ_INT(home_rc, 0);
    if (home_rc != 0) return;
    path_rc = safe_snprintf(keybox, sizeof(keybox), "%s/pubring.kbx", home);
    CHECK_EQ_INT(path_rc, 0);
    if (path_rc != 0) goto cleanup;
    write_rc = write_string_to_file(
        keybox, "not a valid OpenPGP keybox\n", 0600);
    CHECK_EQ_INT(write_rc, 0);
    if (write_rc != 0) goto cleanup;
    clear_error();
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "0123456789ABCDEF", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_GPG_KEY_FAILED);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "error code") != NULL);
cleanup:
    CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(untrusted_runtime_is_copied_to_a_trusted_test_path);
    int gpg_rc = prepare_real_gpg();
    if (gpg_rc < 0) {
        fprintf(stderr, "HARNESS FAIL: cannot prepare trusted real GPG\n");
        return 1;
    }
    RUN_TEST(real_gpg_absent_selector_has_structured_miss_evidence);
    RUN_TEST(real_gpg_corrupt_keybox_is_an_operational_failure);
    if (restore_trusted_gpg() != 0) {
        fprintf(stderr, "HARNESS FAIL: cannot restore PATH after GPG tests\n");
        return 1;
    }
    return ts_test_finish();
}
