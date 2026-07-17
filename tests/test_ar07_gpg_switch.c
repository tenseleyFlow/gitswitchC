/* AR-07 T10: adversarial GPG activation/identity/rollback regressions. */
#ifdef __linux__
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#endif

#define PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define SECOND_FPR  "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define SUBKEY_FPR  "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
#define V5_FPR \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define PRIMARY_SIGN \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define SECOND_SIGN \
    "sec:u:4096:1:89ABCDEF01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" SECOND_FPR ":\n"
#define V5_PRIMARY_SIGN \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" V5_FPR ":\n"
#define PRIMARY_CERT \
    "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::cC:::+:::23::0:\n" \
    "fpr:::::::::" PRIMARY_FPR ":\n"
#define AMBIGUOUS_KEYS \
    PRIMARY_SIGN \
    "sec:u:4096:1:89ABCDEF01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" SECOND_FPR ":\n"
#define STATUS_NO_SECRET_KEY \
    "[GNUPG:] ERROR keylist.getkey 17\n" \
    "[GNUPG:] FAILURE gpg-exit 33554433\n"
#define STATUS_INVALID_KEYBOX \
    "[GNUPG:] ERROR keylist.getkey 14\n" \
    "[GNUPG:] FAILURE gpg-exit 33554433\n"

#ifdef __linux__
/* AR-10 L31: see the twin helper in test_ar07_gpg_cleanup.c — user-namespace
 * fallback so the bind-mount security regression runs unprivileged instead
 * of green-skipping on every non-root host. */
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
    if (write_exact("/proc/self/setgroups", "deny") != 0) return -1;
    snprintf(map, sizeof(map), "%u %u 1", (unsigned)uid, (unsigned)uid);
    if (write_exact("/proc/self/uid_map", map) != 0) return -1;
    snprintf(map, sizeof(map), "%u %u 1", (unsigned)gid, (unsigned)gid);
    if (write_exact("/proc/self/gid_map", map) != 0) return -1;
    return 0;
}
#endif

#ifdef __FreeBSD__
static int freebsd_sudo_command(const char *command, const char *arg1,
                                const char *arg2, const char *arg3) {
    const char *sudo_path = access("/usr/local/bin/sudo", X_OK) == 0
                                ? "/usr/local/bin/sudo"
                                : "/usr/bin/sudo";
    pid_t child;
    int status;

    if (!command || !arg1 || access(sudo_path, X_OK) != 0) return -1;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDOUT_FILENO);
            (void)dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        if (arg3) {
            execl(sudo_path, "sudo", "-n", command, arg1, arg2, arg3,
                  (char *)NULL);
        } else if (arg2) {
            execl(sudo_path, "sudo", "-n", command, arg1, arg2,
                  (char *)NULL);
        } else {
            execl(sudo_path, "sudo", "-n", command, arg1, (char *)NULL);
        }
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int freebsd_mount_nullfs(const char *source, const char *target) {
    return freebsd_sudo_command("/sbin/mount_nullfs", source, target, NULL);
}

static int freebsd_unmount_nullfs(const char *target) {
    if (freebsd_sudo_command("/sbin/umount", target, NULL, NULL) == 0) {
        return 0;
    }
    return freebsd_sudo_command("/sbin/umount", "-f", target, NULL);
}
#endif

static int make_runtime(char *xdg, size_t size) {
    char canonical[MAX_PATH_LEN];
    size_t length;

    if (snprintf(xdg, size, "/tmp/gswar07gpg_XXXXXX") >= (int)size ||
        !ts_mkdtemp(xdg) || !realpath(xdg, canonical)) {
        return -1;
    }
    length = strlen(canonical);
    if (length >= size) {
        return -1;
    }
    memcpy(xdg, canonical, length + 1U);
    if (chmod(xdg, 0700) != 0 ||
        setenv("XDG_RUNTIME_DIR", xdg, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0) {
        return -1;
    }
    return 0;
}

TEST(strict_capability_parser_rejects_unusable_keys) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char expired[1024];
    const char *revoked =
        "sec:r:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *expired_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:1::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *disabled_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::sD:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *valid_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *token_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::D2760001240102000000000000010000:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *stub_subkey =
        PRIMARY_CERT
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::#:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";
    const char *malformed_secret_marker =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::++:::23::0:\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";
    const char *subkey_fpr_cannot_replace_missing_primary_fpr =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::cC:::+:::23::0:\n"
        "ssb:u:4096:1:FEDCBA9876543210:1700000000:::-:::s:::+:::23::0:\n"
        "fpr:::::::::" SUBKEY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_CERT, true, fingerprint, sizeof(fingerprint)),
                 -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     revoked, true, fingerprint, sizeof(fingerprint)), -1);
    snprintf(expired, sizeof(expired),
             "sec:u:4096:1:0123456789ABCDEF:1700000000:1::-:::scESC:::+:::23::0:\n"
             "fpr:::::::::%s:\n", PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     expired_subkey, true, fingerprint, sizeof(fingerprint)),
                 -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     disabled_subkey, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     valid_subkey, true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     token_subkey, true, fingerprint, sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     stub_subkey, true, fingerprint, sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     malformed_secret_marker, true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     subkey_fpr_cannot_replace_missing_primary_fpr, true,
                     fingerprint, sizeof(fingerprint)), -1);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message, "out of order") != NULL);
}

TEST(selector_inventory_is_exact_and_canonical) {
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *status_interleaved =
        "sec:u:4096:1:0123456789ABCDEF:1700000000:::-:::scESC:::+:::23::0:\n"
        "[GNUPG:] KEY_CONSIDERED " PRIMARY_FPR " 0\n"
        "fpr:::::::::" PRIMARY_FPR ":\n";

    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     AMBIGUOUS_KEYS, false, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK(strstr(get_last_error()->message, "Ambiguous") != NULL);
    CHECK(fingerprint[0] == '\0');
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     PRIMARY_SIGN, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK_EQ_INT(gpg_manager_resolve_secret_key_listing(
                     status_interleaved, true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
}

enum fake_mode {
    FAKE_PRESENT,
    FAKE_V5_FIRST_IMPORT,
    FAKE_AMBIGUOUS_SOURCE,
    FAKE_MISMATCHED_IMPORT,
    FAKE_FIRST_IMPORT
};
static enum fake_mode g_fake_mode;
static bool g_fake_imported;
static bool g_fake_exported;
static bool g_fake_export_used_fingerprint;
static bool g_fake_git_used_fingerprint;
static bool g_fake_listing_used_v5_selector;
static bool g_fake_git_used_v5_fingerprint;
static int g_fake_listing_calls;
static char g_fake_git_name[MAX_NAME_LEN];
static char g_fake_git_email[MAX_EMAIL_LEN];
static char g_fake_git_signingkey[MAX_GPG_FINGERPRINT_LEN];
static char g_fake_git_gpgsign[16];
static char g_fake_git_gpgformat[16];
static char g_fake_git_openpgp_program[MAX_PATH_LEN];
static bool g_fake_git_program_unset;
static bool g_fake_git_x509_program_unset;
static bool g_fake_git_ssh_program_unset;
enum fake_git_failure {
    FAKE_GIT_OK,
    FAKE_GIT_FAIL_SIGNINGKEY,
    FAKE_GIT_FAIL_GPGSIGN,
    FAKE_GIT_FAIL_PROGRAM_UNSET,
    FAKE_GIT_FAIL_X509_PROGRAM_UNSET,
    FAKE_GIT_FAIL_SSH_PROGRAM_UNSET,
    FAKE_GIT_FAIL_OPENPGP_PROGRAM_SET
};
static enum fake_git_failure g_fake_git_failure;

void git_ops_test_reset_caches(void);

static bool argv_has(const char *const argv[], const char *needle) {
    size_t i;
    for (i = 0; argv[i]; i++) {
        if (strcmp(argv[i], needle) == 0) return true;
    }
    return false;
}

static bool opts_unsets_environment(const run_opts_t *opts,
                                    const char *name) {
    const char *const *entry;

    for (entry = opts ? opts->unset_env : NULL; entry && *entry; entry++) {
        if (strcmp(*entry, name) == 0) return true;
    }
    return false;
}

static const char *git_config_set_value(const char *const argv[],
                                        const char *key) {
    if (!argv || !key || !argv[0] || !argv[1] || !argv[2] || !argv[3] ||
        !argv[4] || argv[5] || strcmp(argv[0], "git") != 0 ||
        strcmp(argv[1], "config") != 0 || strcmp(argv[3], key) != 0) {
        return NULL;
    }
    return argv[4];
}

static bool git_config_unsets(const char *const argv[], const char *key) {
    return argv && key && argv[0] && argv[1] && argv[2] && argv[3] &&
           argv[4] && !argv[5] && strcmp(argv[0], "git") == 0 &&
           strcmp(argv[1], "config") == 0 &&
           (strcmp(argv[3], "--unset") == 0 ||
            strcmp(argv[3], "--unset-all") == 0) &&
           strcmp(argv[4], key) == 0;
}

static int append_effective_record(char *output, size_t output_size,
                                   size_t *used, const char *key,
                                   const char *value) {
    static const char scope[] = "global";
    static const char origin[] = "file:/fake/global";
    size_t required;

    if (!output || !used || !key || !value) return -1;
    required = sizeof(scope) + sizeof(origin) + strlen(key) + 1U +
               strlen(value) + 1U;
    if (*used > output_size || required > output_size - *used) return -1;
    memcpy(output + *used, scope, sizeof(scope));
    *used += sizeof(scope);
    memcpy(output + *used, origin, sizeof(origin));
    *used += sizeof(origin);
    *used += (size_t)snprintf(output + *used, output_size - *used,
                             "%s\n%s", key, value) + 1U;
    return 0;
}

static int emit_fake_effective_config(const run_opts_t *opts,
                                      run_result_t *result) {
    size_t used = 0;

    if (!opts || !opts->out || opts->out_size == 0) return -1;
#define APPEND_FAKE_VALUE(key_, value_)                                      \
    do {                                                                      \
        if ((value_)[0] != '\0' &&                                          \
            append_effective_record(opts->out, opts->out_size, &used,         \
                                    (key_), (value_)) != 0) {                  \
            if (result) result->out_truncated = true;                          \
            return -1;                                                        \
        }                                                                     \
    } while (0)
    APPEND_FAKE_VALUE(GIT_CONFIG_USER_NAME, g_fake_git_name);
    APPEND_FAKE_VALUE(GIT_CONFIG_USER_EMAIL, g_fake_git_email);
    APPEND_FAKE_VALUE(GIT_CONFIG_USER_SIGNINGKEY, g_fake_git_signingkey);
    APPEND_FAKE_VALUE(GIT_CONFIG_COMMIT_GPGSIGN, g_fake_git_gpgsign);
    APPEND_FAKE_VALUE(GIT_CONFIG_GPG_FORMAT, g_fake_git_gpgformat);
    APPEND_FAKE_VALUE(GIT_CONFIG_GPG_OPENPGP_PROGRAM,
                      g_fake_git_openpgp_program);
#undef APPEND_FAKE_VALUE
    if (result) {
        result->exit_code = 0;
        result->out_len = used;
    }
    return 0;
}

static void prepare_fake_git_model(const account_t *account) {
    if (!account) return;
    git_ops_test_reset_caches();
    safe_strncpy(g_fake_git_name, account->name,
                 sizeof(g_fake_git_name));
    safe_strncpy(g_fake_git_email, account->email,
                 sizeof(g_fake_git_email));
    safe_strncpy(g_fake_git_gpgformat, "openpgp",
                 sizeof(g_fake_git_gpgformat));
    g_fake_git_signingkey[0] = '\0';
    g_fake_git_gpgsign[0] = '\0';
    g_fake_git_openpgp_program[0] = '\0';
    g_fake_git_program_unset = false;
    g_fake_git_x509_program_unset = false;
    g_fake_git_ssh_program_unset = false;
}

static void fill_account(account_t *account, const char *name,
                         const char *selector, bool signing);

enum listing_result_mode {
    LISTING_RESULT_MATCH,
    LISTING_RESULT_MISS,
    LISTING_RESULT_INVALID_KEYBOX,
    LISTING_RESULT_TRUNCATED_STATUS,
    LISTING_RESULT_SPAWN_FAILURE,
    LISTING_RESULT_SETUP_FAILURE,
    LISTING_RESULT_SIGNAL_FAILURE,
    LISTING_RESULT_PIPE_FAILURE,
    LISTING_RESULT_GPG_FAILURE,
    LISTING_RESULT_TRUNCATED
};

static enum listing_result_mode g_listing_result_mode;
static int g_listing_result_calls;
static int g_listing_result_exports;
static int g_listing_result_imports;
static size_t g_listing_result_capacity;
static bool g_listing_status_requested;

static int listing_result_runner(const char *const argv[],
                                 const run_opts_t *opts,
                                 run_result_t *result) {
    bool listing = argv_has(argv, "--list-secret-keys");
    bool export_key = argv_has(argv, "--export-secret-keys");
    bool import_key = argv_has(argv, "--import");

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (listing) {
        g_listing_result_calls++;
        g_listing_status_requested =
            g_listing_status_requested || argv_has(argv, "--status-fd=1");
        if (g_listing_result_calls == 1) {
            g_listing_result_capacity = opts ? opts->out_size : 0;
            switch (g_listing_result_mode) {
                case LISTING_RESULT_MISS:
                    if (opts && opts->out && opts->out_size > 0) {
                        snprintf(opts->out, opts->out_size, "%s",
                                 STATUS_NO_SECRET_KEY);
                        if (result) result->out_len = strlen(opts->out);
                    }
                    if (result) result->exit_code = 2;
                    return -1;
                case LISTING_RESULT_INVALID_KEYBOX:
                    if (opts && opts->out && opts->out_size > 0) {
                        snprintf(opts->out, opts->out_size, "%s",
                                 STATUS_INVALID_KEYBOX);
                        if (result) result->out_len = strlen(opts->out);
                    }
                    if (result) result->exit_code = 2;
                    return -1;
                case LISTING_RESULT_TRUNCATED_STATUS:
                    if (opts && opts->out && opts->out_size > 0) {
                        snprintf(opts->out, opts->out_size,
                                 "[GNUPG:] ERROR keylist.getkey 17\n"
                                 "[GNUPG:] FAILURE gpg-ex");
                        if (result) {
                            result->out_len = strlen(opts->out);
                            result->exit_code = 2;
                        }
                    }
                    return -1;
                case LISTING_RESULT_SPAWN_FAILURE:
                    if (result) {
                        result->spawned = false;
                        result->exit_code = -1;
                    }
                    return -1;
                case LISTING_RESULT_SETUP_FAILURE:
                    if (result) result->exit_code = 126;
                    return -1;
                case LISTING_RESULT_SIGNAL_FAILURE:
                    if (result) {
                        result->exit_code = -1;
                        result->term_signal = SIGTERM;
                    }
                    return -1;
                case LISTING_RESULT_PIPE_FAILURE:
                    return -1;
                case LISTING_RESULT_GPG_FAILURE:
                    if (result) result->exit_code = 1;
                    return -1;
                case LISTING_RESULT_TRUNCATED:
                    if (opts && opts->out && opts->out_size > 0) {
                        snprintf(opts->out, opts->out_size, "%s", PRIMARY_SIGN);
                        if (result) {
                            result->out_len = strlen(opts->out);
                            result->out_truncated = true;
                        }
                    }
                    return 0;
                case LISTING_RESULT_MATCH:
                    break;
                default:
                    return -1;
            }
        }
        if (opts && opts->out && opts->out_size > 0) {
            snprintf(opts->out, opts->out_size, "%s", PRIMARY_SIGN);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (export_key) {
        static const char armor[] =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "FAKE\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n";
        g_listing_result_exports++;
        if (opts && opts->out && opts->out_size > sizeof(armor)) {
            memcpy(opts->out, armor, sizeof(armor));
            if (result) result->out_len = sizeof(armor) - 1;
        }
        return 0;
    }
    if (import_key) {
        g_listing_result_imports++;
        return 0;
    }
    return 0;
}

#ifdef __linux__
static char g_source_overlay_from[MAX_PATH_LEN];
static char g_source_overlay_target[MAX_PATH_LEN];
static bool g_source_overlay_attempted;
static int g_source_overlay_rc;

/* Install an overlay while the source helper is in flight. The post-helper
 * ancestry proof must reopen the managed child through its parent and reject
 * the result; fstat-only retained descriptors cannot see this mount. */
static int overlay_listing_result_runner(const char *const argv[],
                                         const run_opts_t *opts,
                                         run_result_t *result) {
    if (argv_has(argv, "--list-secret-keys") &&
        !g_source_overlay_attempted) {
        g_source_overlay_attempted = true;
        g_source_overlay_rc = mount(g_source_overlay_from,
                                    g_source_overlay_target, NULL,
                                    MS_BIND, NULL);
    }
    return listing_result_runner(argv, opts, result);
}
#endif

static int run_listing_result_case(enum listing_result_mode mode,
                                   int *listing_calls,
                                   int *export_calls,
                                   int *import_calls,
                                   size_t *capacity,
                                   char *diagnostic,
                                   size_t diagnostic_size) {
    char xdg[128];
    char source_home[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;
    int rc;

    if (make_runtime(xdg, sizeof(xdg)) != 0 ||
        safe_snprintf(source_home, sizeof(source_home), "%s/source", xdg) != 0 ||
        mkdir(source_home, 0700) != 0 ||
        setenv("GNUPGHOME", source_home, 1) != 0) {
        return -2;
    }
    fill_account(&account, "matrix", "01234567", true);
    g_listing_result_mode = mode;
    g_listing_result_calls = 0;
    g_listing_result_exports = 0;
    g_listing_result_imports = 0;
    g_listing_result_capacity = 0;
    g_listing_status_requested = false;
    clear_error();
    previous = run_set_runner(listing_result_runner);
    rc = gpg_switch_account(&config, &account);
    if (diagnostic && diagnostic_size > 0) {
        safe_strncpy(diagnostic, get_last_error()->message, diagnostic_size);
    }
    if (listing_calls) *listing_calls = g_listing_result_calls;
    if (export_calls) *export_calls = g_listing_result_exports;
    if (import_calls) *import_calls = g_listing_result_imports;
    if (capacity) *capacity = g_listing_result_capacity;
    if (rc == 0) {
        (void)gpg_manager_cleanup(&config);
    }
    run_set_runner(previous);
    unsetenv("GNUPGHOME");
    return rc;
}

static int run_system_listing_result_case(enum listing_result_mode mode,
                                          error_code_t *error_code,
                                          char *fingerprint,
                                          size_t fingerprint_size,
                                          char *diagnostic,
                                          size_t diagnostic_size) {
    char xdg[128];
    char source_home[MAX_PATH_LEN];
    char resolved[GPG_FINGERPRINT_BUFSIZE];
    command_runner_fn previous;
    int rc;

    if (make_runtime(xdg, sizeof(xdg)) != 0 ||
        safe_snprintf(source_home, sizeof(source_home), "%s/source", xdg) != 0 ||
        mkdir(source_home, 0700) != 0 ||
        setenv("GNUPGHOME", source_home, 1) != 0) {
        return -2;
    }
    g_listing_result_mode = mode;
    g_listing_result_calls = 0;
    g_listing_result_exports = 0;
    g_listing_result_imports = 0;
    g_listing_result_capacity = 0;
    g_listing_status_requested = false;
    clear_error();
    previous = run_set_runner(listing_result_runner);
    rc = gpg_manager_resolve_system_key(
        "01234567", true, resolved, sizeof(resolved));
    run_set_runner(previous);
    if (error_code) *error_code = get_last_error()->code;
    if (fingerprint && fingerprint_size > 0) {
        safe_strncpy(fingerprint, resolved, fingerprint_size);
    }
    if (diagnostic && diagnostic_size > 0) {
        safe_strncpy(diagnostic, get_last_error()->message, diagnostic_size);
    }
    unsetenv("GNUPGHOME");
    return rc;
}

TEST(secret_listing_result_matrix_is_causal_and_exact) {
    static const struct {
        enum listing_result_mode mode;
        const char *diagnostic;
    } failures[] = {
        { LISTING_RESULT_SPAWN_FAILURE, "before spawn" },
        { LISTING_RESULT_SETUP_FAILURE, "child setup or exec" },
        { LISTING_RESULT_SIGNAL_FAILURE, "terminated by signal" },
        { LISTING_RESULT_PIPE_FAILURE, "transport failed" },
        { LISTING_RESULT_GPG_FAILURE, "exit status 1" }
    };
    char diagnostic[512];
    int listings;
    int exports;
    int imports;
    size_t capacity;
    size_t i;

    CHECK_EQ_INT(run_listing_result_case(
                     LISTING_RESULT_MATCH, &listings, &exports, &imports,
                     &capacity, diagnostic, sizeof(diagnostic)), 0);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(listings, 1);
    CHECK_EQ_INT(exports, 0);
    CHECK_EQ_INT(imports, 0);

    /* Only the documented spawned/normal exit-2 outcome is a miss. It alone
     * advances into the source listing, export, import, and verification
     * sequence; every operational failure stops at the first helper call. */
    CHECK_EQ_INT(run_listing_result_case(
                     LISTING_RESULT_MISS, &listings, &exports, &imports,
                     &capacity, diagnostic, sizeof(diagnostic)), 0);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(listings, 3);
    CHECK_EQ_INT(exports, 1);
    CHECK_EQ_INT(imports, 1);

    for (i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        CHECK_EQ_INT(run_listing_result_case(
                         failures[i].mode, &listings, &exports, &imports,
                         &capacity, diagnostic, sizeof(diagnostic)), -1);
        CHECK_EQ_INT(listings, 1);
        CHECK_EQ_INT(exports, 0);
        CHECK_EQ_INT(imports, 0);
        CHECK(strstr(diagnostic, failures[i].diagnostic) != NULL);
    }
}

TEST(structured_status_distinguishes_absence_from_keyring_failure) {
    char diagnostic[512];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    error_code_t error_code;

    CHECK_EQ_INT(run_system_listing_result_case(
                     LISTING_RESULT_MATCH, &error_code, fingerprint,
                     sizeof(fingerprint), diagnostic, sizeof(diagnostic)), 0);
    CHECK(g_listing_status_requested);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);

    CHECK_EQ_INT(run_system_listing_result_case(
                     LISTING_RESULT_MISS, &error_code, fingerprint,
                     sizeof(fingerprint), diagnostic, sizeof(diagnostic)), -1);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_NOT_FOUND);
    CHECK(strstr(diagnostic, "resolved no secret key") != NULL);

    CHECK_EQ_INT(run_system_listing_result_case(
                     LISTING_RESULT_INVALID_KEYBOX, &error_code, fingerprint,
                     sizeof(fingerprint), diagnostic, sizeof(diagnostic)), -1);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(diagnostic, "error code 14") != NULL);

    CHECK_EQ_INT(run_system_listing_result_case(
                     LISTING_RESULT_TRUNCATED_STATUS, &error_code, fingerprint,
                     sizeof(fingerprint), diagnostic, sizeof(diagnostic)), -1);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(diagnostic, "status output") != NULL);

    CHECK_EQ_INT(run_system_listing_result_case(
                     LISTING_RESULT_SETUP_FAILURE, &error_code, fingerprint,
                     sizeof(fingerprint), diagnostic, sizeof(diagnostic)), -1);
    CHECK(g_listing_status_requested);
    CHECK_EQ_INT(error_code, ERR_GPG_KEY_FAILED);
    CHECK(strstr(diagnostic, "child setup or exec") != NULL);
}

TEST(truncated_secret_listing_is_one_shot_at_the_documented_cap) {
    char diagnostic[512];
    int listings;
    int exports;
    int imports;
    size_t capacity;

    CHECK_EQ_INT(run_listing_result_case(
                     LISTING_RESULT_TRUNCATED, &listings, &exports, &imports,
                     &capacity, diagnostic, sizeof(diagnostic)), -1);
    CHECK_EQ_INT(listings, 1);
    CHECK_EQ_INT(exports, 0);
    CHECK_EQ_INT(imports, 0);
    CHECK_EQ_INT((long long)capacity, (long long)(512U * 1024U));
    CHECK(strstr(diagnostic, "one-shot 524288-byte capture limit") != NULL);
}

static char g_source_swap_original[MAX_PATH_LEN];
static char g_source_swap_moved[MAX_PATH_LEN];
static char g_source_swap_marker[MAX_PATH_LEN];
static bool g_source_swap_pinned;
static bool g_source_swap_done;

static int source_swap_runner(const char *const argv[],
                              const run_opts_t *opts,
                              run_result_t *result) {
    const char *const *env;
    struct stat before;
    struct stat after;
    struct stat moved;
    bool dot_home = false;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv_has(argv, "--list-secret-keys")) return 0;

    for (env = opts ? opts->extra_env : NULL; env && *env; env++) {
        if (strcmp(*env, "GNUPGHOME=.") == 0) dot_home = true;
    }
    if (opts && opts->use_cwd_fd && opts->cwd_fd >= 0 && dot_home &&
        fstat(opts->cwd_fd, &before) == 0 &&
        rename(g_source_swap_original, g_source_swap_moved) == 0 &&
        mkdir(g_source_swap_original, 0700) == 0 &&
        write_string_to_file(g_source_swap_marker, "replacement\n", 0600) == 0 &&
        fstat(opts->cwd_fd, &after) == 0 &&
        stat(g_source_swap_moved, &moved) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        after.st_dev == moved.st_dev && after.st_ino == moved.st_ino) {
        g_source_swap_pinned = true;
        g_source_swap_done = true;
    }
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", PRIMARY_SIGN);
        if (result) result->out_len = strlen(opts->out);
    }
    return 0;
}

TEST(system_key_helper_stays_on_pinned_source_after_directory_replacement) {
    char xdg[128];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(g_source_swap_original,
                               sizeof(g_source_swap_original),
                               "%s/source", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(g_source_swap_moved,
                               sizeof(g_source_swap_moved),
                               "%s/source.proved", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(g_source_swap_marker,
                               sizeof(g_source_swap_marker),
                               "%s/source/replacement", xdg), 0);
    CHECK_EQ_INT(mkdir(g_source_swap_original, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", g_source_swap_original, 1), 0);
    g_source_swap_pinned = false;
    g_source_swap_done = false;
    previous = run_set_runner(source_swap_runner);
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    run_set_runner(previous);

    CHECK(g_source_swap_done);
    CHECK(g_source_swap_pinned);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    CHECK(path_exists(g_source_swap_marker));
    unsetenv("GNUPGHOME");
}

#ifdef __linux__
TEST(bind_alias_of_managed_home_is_rejected_before_helper_launch) {
    char xdg[128], base[MAX_PATH_LEN], managed[MAX_PATH_LEN];
    char nested[MAX_PATH_LEN], overlay[MAX_PATH_LEN];
    char external[MAX_PATH_LEN];
    char alias[MAX_PATH_LEN];
    char trusted_program_dir[MAX_PATH_LEN];
    char trusted_gpg[MAX_PATH_LEN];
    char self_executable[MAX_PATH_LEN];
    const char *inherited_path;
    char *saved_path = NULL;
    bool saved_path_present;
    ssize_t self_length;
    int init_rc;
    int restore_path_rc;
    gpg_config_t config;
    account_t account;
    pid_t child;
    int status = 0;
    bool mount_namespace_unavailable = false;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(base, sizeof(base),
                               "%s/gitswitch-gpg", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(managed, sizeof(managed),
                               "%s/managed", base), 0);
    CHECK_EQ_INT(safe_snprintf(nested, sizeof(nested),
                               "%s/nested", managed), 0);
    CHECK_EQ_INT(safe_snprintf(overlay, sizeof(overlay),
                               "%s/overlay", managed), 0);
    CHECK_EQ_INT(safe_snprintf(external, sizeof(external),
                               "%s/external", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(alias, sizeof(alias),
                               "%s/bind-alias", xdg), 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(managed, 0700), 0);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(mkdir(overlay, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(mkdir(alias, 0700), 0);

    /* A user-namespace fallback maps host root-owned executables to the
     * overflow uid, which the hardened resolver correctly rejects. Give this
     * source-home test a self-owned native GPG stand-in; the fake runner below
     * prevents execution, while the resolver still proves real ELF shape and
     * trusted ancestry inside either namespace form. */
    self_length = readlink("/proc/self/exe", self_executable,
                           sizeof(self_executable) - 1U);
    if (self_length <= 0 || (size_t)self_length >= sizeof(self_executable) - 1U ||
        !ts_mkdtemp_trusted(trusted_program_dir,
                            sizeof(trusted_program_dir),
                            "gitswitch-ar11-bind-gpg") ||
        safe_snprintf(trusted_gpg, sizeof(trusted_gpg), "%s/gpg",
                      trusted_program_dir) != 0) {
        CHECK(!"failed to prepare trusted bind-alias GPG fixture");
        return;
    }
    self_executable[self_length] = '\0';
    if (copy_file(self_executable, trusted_gpg) != 0 ||
        chmod(trusted_gpg, 0700) != 0) {
        CHECK(!"failed to install trusted bind-alias GPG fixture");
        return;
    }
    inherited_path = getenv("PATH");
    saved_path_present = inherited_path != NULL;
    if (inherited_path) {
        saved_path = strdup(inherited_path);
        if (!saved_path) {
            CHECK(!"failed to retain PATH for bind-alias fixture");
            return;
        }
    }
    memset(&config, 0, sizeof(config));
    if (setenv("PATH", trusted_program_dir, 1) != 0) {
        free(saved_path);
        CHECK(!"failed to select trusted bind-alias PATH");
        return;
    }
    init_rc = gpg_manager_init(&config, GPG_MODE_SYSTEM);
    restore_path_rc = saved_path_present ? setenv("PATH", saved_path, 1)
                                         : unsetenv("PATH");
    free(saved_path);
    if (init_rc != 0 || restore_path_rc != 0) {
        CHECK(!"failed to bind trusted GPG before namespace entry");
        return;
    }
    fill_account(&account, "managed-alias", "01234567", true);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        command_runner_fn previous;
        gpg_config_t nested_config = config;
        gpg_config_t overlay_config = config;
        gpg_config_t external_config = config;
        int rc;

        if (enter_private_mount_namespace() != 0 ||
            mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
            _exit(77);
        }
        if (setenv("GNUPGHOME", alias, 1) != 0) {
            fprintf(stderr, "bind-alias child: environment setup failed: %s\n",
                    strerror(errno));
            _exit(9);
        }
        g_listing_result_calls = 0;
        g_listing_result_mode = LISTING_RESULT_MATCH;
        previous = run_set_runner(listing_result_runner);

        if (mount(managed, alias, NULL, MS_BIND, NULL) != 0) {
            run_set_runner(previous);
            _exit(77);
        }
        rc = gpg_switch_account(&config, &account);
        if (rc != -1 || g_listing_result_calls != 0 ||
            strstr(get_last_error()->message,
                   "bind-mounted alias of a managed GPG home") == NULL) {
            fprintf(stderr,
                    "bind-alias child: rc=%d calls=%d error=%d message=%s\n",
                    rc, g_listing_result_calls, get_last_error()->code,
                    get_last_error()->message);
            (void)umount2(alias, MNT_DETACH);
            _exit(9);
        }
        if (umount2(alias, MNT_DETACH) != 0) {
            fprintf(stderr, "direct bind-alias child: unmount failed: %s\n",
                    strerror(errno));
            _exit(9);
        }

        g_listing_result_calls = 0;
        if (mount(nested, alias, NULL, MS_BIND, NULL) != 0) {
            run_set_runner(previous);
            _exit(77);
        }
        rc = gpg_switch_account(&nested_config, &account);
        if (rc != -1 || g_listing_result_calls != 0 ||
            strstr(get_last_error()->message,
                   "bind-mounted alias of a managed GPG home") == NULL) {
            fprintf(stderr,
                    "nested bind-alias child: rc=%d calls=%d error=%d message=%s\n",
                    rc, g_listing_result_calls, get_last_error()->code,
                    get_last_error()->message);
            (void)umount2(alias, MNT_DETACH);
            _exit(9);
        }
        if (umount2(alias, MNT_DETACH) != 0) {
            fprintf(stderr, "nested bind-alias child: unmount failed: %s\n",
                    strerror(errno));
            _exit(9);
        }

        /* A managed child overlaid only after the initial traversal must be
         * detected by the retained parent/name edge before any helper result
         * is accepted. */
        g_listing_result_calls = 0;
        if (mount(external, alias, NULL, MS_BIND, NULL) != 0 ||
            safe_strncpy(g_source_overlay_from, external,
                         sizeof(g_source_overlay_from)) != 0 ||
            safe_strncpy(g_source_overlay_target, overlay,
                         sizeof(g_source_overlay_target)) != 0) {
            run_set_runner(previous);
            _exit(77);
        }
        g_source_overlay_attempted = false;
        g_source_overlay_rc = -1;
        run_set_runner(overlay_listing_result_runner);
        rc = gpg_switch_account(&overlay_config, &account);
        run_set_runner(listing_result_runner);
        if (!g_source_overlay_attempted || g_source_overlay_rc != 0) {
            (void)umount2(overlay, MNT_DETACH);
            (void)umount2(alias, MNT_DETACH);
            run_set_runner(previous);
            _exit(77);
        }
        if (rc != -1 || g_listing_result_calls != 1 ||
            strstr(get_last_error()->message,
                   "Managed GPG ancestry changed after source proof") == NULL) {
            fprintf(stderr,
                    "late overlay child: rc=%d calls=%d error=%d message=%s\n",
                    rc, g_listing_result_calls, get_last_error()->code,
                    get_last_error()->message);
            (void)umount2(overlay, MNT_DETACH);
            (void)umount2(alias, MNT_DETACH);
            _exit(9);
        }
        if (umount2(overlay, MNT_DETACH) != 0 ||
            umount2(alias, MNT_DETACH) != 0) {
            fprintf(stderr, "late overlay child: unmount failed: %s\n",
                    strerror(errno));
            _exit(9);
        }

        /* A distinct external bind mount is still a valid pinned source.
         * This positive control prevents replacing ancestry proof with a
         * blanket rejection of every mount alias. */
        g_listing_result_calls = 0;
        if (mount(external, alias, NULL, MS_BIND, NULL) != 0) {
            run_set_runner(previous);
            _exit(77);
        }
        rc = gpg_switch_account(&external_config, &account);
        if (rc != 0 || g_listing_result_calls != 1) {
            fprintf(stderr,
                    "external bind-alias child: rc=%d calls=%d error=%d message=%s\n",
                    rc, g_listing_result_calls, get_last_error()->code,
                    get_last_error()->message);
            (void)umount2(alias, MNT_DETACH);
            _exit(9);
        }
        if (umount2(alias, MNT_DETACH) != 0) {
            fprintf(stderr, "external bind-alias child: unmount failed: %s\n",
                    strerror(errno));
            _exit(9);
        }
        run_set_runner(previous);
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
    if (mount_namespace_unavailable) {
        TS_SKIP("mount-namespace",
                "private mount namespace/bind mount unavailable");
    }
}
#endif

static int strict_key_runner(const char *const argv[], const run_opts_t *opts,
                             run_result_t *result) {
    bool listing = argv_has(argv, "--list-secret-keys");
    bool export_key = argv_has(argv, "--export-secret-keys");
    bool import_key = argv_has(argv, "--import");

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") ||
         ts_command_is(argv[0], "gpg2") ||
         ts_command_is(argv[0], "gpgconf"))) {
        CHECK(opts_unsets_environment(opts, "GPG_AGENT_INFO"));
    }

    if (argv && argv[0] && argv[1] && argv[2] &&
        strcmp(argv[0], "git") == 0 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[2], "--show-origin") == 0) {
        return emit_fake_effective_config(opts, result);
    }

    if (listing) {
        bool source_listing;
        const char *inventory =
            g_fake_mode == FAKE_V5_FIRST_IMPORT ? V5_PRIMARY_SIGN
                                                 : PRIMARY_SIGN;

        g_fake_listing_calls++;
        source_listing = g_fake_listing_calls == 2 && !g_fake_imported;

        if (g_fake_mode == FAKE_V5_FIRST_IMPORT && argv_has(argv, V5_FPR)) {
            g_fake_listing_used_v5_selector = true;
        }

        if (g_fake_mode == FAKE_AMBIGUOUS_SOURCE && source_listing) {
            inventory = AMBIGUOUS_KEYS;
        } else if (g_fake_mode == FAKE_MISMATCHED_IMPORT &&
                   g_fake_imported) {
            inventory = SECOND_SIGN;
        } else if ((g_fake_mode == FAKE_AMBIGUOUS_SOURCE ||
                    g_fake_mode == FAKE_MISMATCHED_IMPORT ||
                    g_fake_mode == FAKE_FIRST_IMPORT ||
                    g_fake_mode == FAKE_V5_FIRST_IMPORT) &&
                   !source_listing && !g_fake_imported) {
            if (opts && opts->out && opts->out_size > 0) {
                snprintf(opts->out, opts->out_size, "%s",
                         STATUS_NO_SECRET_KEY);
                if (result) result->out_len = strlen(opts->out);
            }
            if (result) result->exit_code = 2;
            return -1;
        }
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", inventory);
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (export_key) {
        g_fake_exported = true;
        g_fake_export_used_fingerprint =
            argv_has(argv, g_fake_mode == FAKE_V5_FIRST_IMPORT
                                ? V5_FPR : PRIMARY_FPR);
        if (opts && opts->out) {
            snprintf(opts->out, opts->out_size,
                     "-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE\n"
                     "-----END PGP PRIVATE KEY BLOCK-----\n");
            if (result) result->out_len = strlen(opts->out);
        }
        return 0;
    }
    if (import_key) {
        g_fake_imported = true;
        return 0;
    }
    if (strcmp(argv[0], "git") == 0 && argv_has(argv, "user.signingkey") &&
        argv_has(argv, PRIMARY_FPR)) {
        g_fake_git_used_fingerprint = true;
    }
    if (strcmp(argv[0], "git") == 0 && argv_has(argv, "user.signingkey") &&
        argv_has(argv, V5_FPR)) {
        g_fake_git_used_v5_fingerprint = true;
    }
    if (strcmp(argv[0], "git") == 0) {
        const char *openpgp_program =
            git_config_set_value(argv, GIT_CONFIG_GPG_OPENPGP_PROGRAM);
        size_t i;

        if ((g_fake_git_failure == FAKE_GIT_FAIL_SIGNINGKEY &&
             git_config_set_value(argv, GIT_CONFIG_USER_SIGNINGKEY)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_GPGSIGN &&
             git_config_set_value(argv, GIT_CONFIG_COMMIT_GPGSIGN)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_PROGRAM_UNSET &&
             git_config_unsets(argv, GIT_CONFIG_GPG_PROGRAM)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_X509_PROGRAM_UNSET &&
             git_config_unsets(argv, GIT_CONFIG_GPG_X509_PROGRAM)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_SSH_PROGRAM_UNSET &&
             git_config_unsets(argv, GIT_CONFIG_GPG_SSH_PROGRAM)) ||
            (g_fake_git_failure == FAKE_GIT_FAIL_OPENPGP_PROGRAM_SET &&
             openpgp_program)) {
            if (result) result->exit_code = 2;
            return -1;
        }

        for (i = 0; argv[i]; i++) {
            if (strcmp(argv[i], GIT_CONFIG_USER_SIGNINGKEY) == 0 &&
                argv[i + 1]) {
                safe_strncpy(g_fake_git_signingkey, argv[i + 1],
                             sizeof(g_fake_git_signingkey));
            } else if (strcmp(argv[i], GIT_CONFIG_COMMIT_GPGSIGN) == 0 &&
                       argv[i + 1]) {
                safe_strncpy(g_fake_git_gpgsign, argv[i + 1],
                             sizeof(g_fake_git_gpgsign));
            }
        }
        if (git_config_unsets(argv, GIT_CONFIG_GPG_PROGRAM)) {
            g_fake_git_program_unset = true;
        } else if (git_config_unsets(argv, GIT_CONFIG_GPG_X509_PROGRAM)) {
            g_fake_git_x509_program_unset = true;
        } else if (git_config_unsets(argv, GIT_CONFIG_GPG_SSH_PROGRAM)) {
            g_fake_git_ssh_program_unset = true;
        }
        if (openpgp_program) {
            safe_strncpy(g_fake_git_openpgp_program, openpgp_program,
                         sizeof(g_fake_git_openpgp_program));
        }
    }
    return 0;
}

static void fill_account(account_t *account, const char *name,
                         const char *selector, bool signing) {
    memset(account, 0, sizeof(*account));
    snprintf(account->name, sizeof(account->name), "%s", name);
    snprintf(account->email, sizeof(account->email), "%s@example.test", name);
    snprintf(account->gpg_key_id, sizeof(account->gpg_key_id), "%s", selector);
    account->gpg_enabled = true;
    account->gpg_signing_enabled = signing;
}

TEST(ambiguous_selector_exports_and_imports_nothing) {
    char xdg[128], source_home[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(source_home, sizeof(source_home),
                               "%s/source", xdg), 0);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    fill_account(&account, "ambiguous", "01234567", false);
    g_fake_mode = FAKE_AMBIGUOUS_SOURCE;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_listing_calls = 0;
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    run_set_runner(previous);
    CHECK(!g_fake_exported);
    CHECK(!g_fake_imported);
    CHECK(strstr(get_last_error()->message, "Ambiguous") != NULL);
    unsetenv("GNUPGHOME");
}

TEST(unique_selector_threads_fingerprint_through_import_and_publication) {
    char xdg[128], source_home[MAX_PATH_LEN];
    char isolated_home[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(source_home, sizeof(source_home),
                               "%s/source", xdg), 0);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    fill_account(&account, "unique", "01234567", true);
    prepare_fake_git_model(&account);
    g_fake_mode = FAKE_FIRST_IMPORT;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_export_used_fingerprint = false;
    g_fake_git_used_fingerprint = false;
    g_fake_listing_calls = 0;
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);
    CHECK(g_fake_exported);
    CHECK(g_fake_imported);
    CHECK(g_fake_export_used_fingerprint);
    CHECK(g_fake_git_used_fingerprint);
    CHECK_STR_EQ(g_fake_git_openpgp_program, config.executable_path);
    CHECK_STR_EQ(config.current_key_id, PRIMARY_FPR);
    CHECK_EQ_INT(safe_strncpy(isolated_home, config.gnupg_home,
                              sizeof(isolated_home)), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    /* Cleanup ends the transaction and restores its process environment; the
     * explicit reset lifecycle, not cleanup, owns persistent-home deletion. */
    CHECK(path_exists(isolated_home));
    CHECK_STR_EQ(getenv("GNUPGHOME"), source_home);
    unsetenv("GNUPGHOME");
}

TEST(post_import_fingerprint_mismatch_is_not_signing_readiness) {
    char xdg[128], source_home[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(source_home, sizeof(source_home),
                               "%s/source", xdg), 0);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    fill_account(&account, "mismatch", "01234567", true);
    g_fake_mode = FAKE_MISMATCHED_IMPORT;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_listing_calls = 0;
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    run_set_runner(previous);

    CHECK(g_fake_exported);
    CHECK(g_fake_imported);
    CHECK(config.current_key_id[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "did not validate as fingerprint") != NULL);
    unsetenv("GNUPGHOME");
}

TEST(full_v5_fingerprint_selector_survives_switch_and_git_publication) {
    char xdg[128], source_home[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(source_home, sizeof(source_home),
                               "%s/source", xdg), 0);
    CHECK_EQ_INT(mkdir(source_home, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", source_home, 1), 0);
    fill_account(&account, "v5", V5_FPR, true);
    prepare_fake_git_model(&account);
    CHECK_EQ_INT((int)strlen(V5_FPR), 64);
    CHECK_EQ_INT((int)strlen(account.gpg_key_id), 64);
    CHECK_STR_EQ(account.gpg_key_id, V5_FPR);
    g_fake_mode = FAKE_V5_FIRST_IMPORT;
    g_fake_imported = false;
    g_fake_exported = false;
    g_fake_export_used_fingerprint = false;
    g_fake_listing_used_v5_selector = false;
    g_fake_git_used_v5_fingerprint = false;
    g_fake_listing_calls = 0;
    previous = run_set_runner(strict_key_runner);

    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);

    CHECK(g_fake_listing_used_v5_selector);
    CHECK(g_fake_exported);
    CHECK(g_fake_imported);
    CHECK(g_fake_export_used_fingerprint);
    CHECK(g_fake_git_used_v5_fingerprint);
    CHECK_STR_EQ(config.current_key_id, V5_FPR);
    CHECK_EQ_INT((int)strlen(config.current_key_id), 64);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), source_home);
    unsetenv("GNUPGHOME");
}

TEST(disabled_signing_keeps_canonical_identity_and_all_writes_are_fatal) {
    static const char bound_program[] = "/trusted/ar11/gpg";
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    fill_account(&account, "manual", "01234567", false);
    prepare_fake_git_model(&account);
    CHECK_EQ_INT(safe_strncpy(config.current_key_id, PRIMARY_FPR,
                              sizeof(config.current_key_id)), 0);
    CHECK_EQ_INT(safe_strncpy(config.executable_path, bound_program,
                              sizeof(config.executable_path)), 0);
    g_fake_git_failure = FAKE_GIT_OK;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), 0);
    run_set_runner(previous);
    CHECK_STR_EQ(g_fake_git_signingkey, PRIMARY_FPR);
    CHECK_STR_EQ(g_fake_git_gpgsign, "false");
    CHECK(g_fake_git_program_unset);
    CHECK(g_fake_git_x509_program_unset);
    CHECK(g_fake_git_ssh_program_unset);
    CHECK_STR_EQ(g_fake_git_openpgp_program, bound_program);

    g_fake_git_failure = FAKE_GIT_FAIL_SIGNINGKEY;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_GPGSIGN;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_PROGRAM_UNSET;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_X509_PROGRAM_UNSET;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_SSH_PROGRAM_UNSET;
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);

    g_fake_git_failure = FAKE_GIT_FAIL_OPENPGP_PROGRAM_SET;
    g_fake_git_openpgp_program[0] = '\0';
    git_ops_test_reset_caches();
    previous = run_set_runner(strict_key_runner);
    CHECK_EQ_INT(gpg_configure_git_signing(&config, &account,
                                           GIT_SCOPE_GLOBAL), -1);
    run_set_runner(previous);
    CHECK(g_fake_git_openpgp_program[0] == '\0');
    g_fake_git_failure = FAKE_GIT_OK;
}

static struct stat g_expected_source_identity;
static int g_source_identity_calls;
static bool g_source_identity_pinned;

static int source_identity_runner(const char *const argv[],
                                  const run_opts_t *opts,
                                  run_result_t *result) {
    const char *const *env;
    struct stat actual;
    bool dot_home = false;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv_has(argv, "--list-secret-keys")) return 0;

    g_source_identity_calls++;
    for (env = opts ? opts->extra_env : NULL; env && *env; env++) {
        if (strcmp(*env, "GNUPGHOME=.") == 0) dot_home = true;
    }
    g_source_identity_pinned =
        opts && opts->use_cwd_fd && opts->cwd_fd >= 0 && dot_home &&
        fstat(opts->cwd_fd, &actual) == 0 &&
        actual.st_dev == g_expected_source_identity.st_dev &&
        actual.st_ino == g_expected_source_identity.st_ino;
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", PRIMARY_SIGN);
        if (result) result->out_len = strlen(opts->out);
    }
    return 0;
}

enum source_proof_mutation_mode {
    SOURCE_PROOF_RENAME_MANAGED_CHILD,
    SOURCE_PROOF_CREATE_MANAGED_BASE
};

static enum source_proof_mutation_mode g_source_proof_mutation_mode;
static char g_source_proof_mutation_from[MAX_PATH_LEN];
static char g_source_proof_mutation_to[MAX_PATH_LEN];
static int g_source_proof_mutation_calls;
static int g_source_proof_mutation_rc;

static int source_proof_mutation_runner(const char *const argv[],
                                        const run_opts_t *opts,
                                        run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (!argv_has(argv, "--list-secret-keys")) return 0;

    g_source_proof_mutation_calls++;
    if (g_source_proof_mutation_calls == 1) {
        g_source_proof_mutation_rc =
            g_source_proof_mutation_mode ==
                    SOURCE_PROOF_RENAME_MANAGED_CHILD
                ? rename(g_source_proof_mutation_from,
                         g_source_proof_mutation_to)
                : mkdir(g_source_proof_mutation_to, 0700);
    }
    if (opts && opts->out && opts->out_size > 0) {
        snprintf(opts->out, opts->out_size, "%s", PRIMARY_SIGN);
        if (result) result->out_len = strlen(opts->out);
    }
    return 0;
}

TEST(source_proof_rejects_managed_tree_mutation_during_helper) {
    char xdg[128], base[MAX_PATH_LEN], account[MAX_PATH_LEN];
    char inside[MAX_PATH_LEN];
    char injected[MAX_PATH_LEN], external[MAX_PATH_LEN];
    char absent_xdg[128], absent_base[MAX_PATH_LEN];
    char absent_external[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char diagnostic[512];
    const char *inherited_gnupghome = getenv("GNUPGHOME");
    bool had_gnupghome = inherited_gnupghome != NULL;
    char *saved_gnupghome = had_gnupghome
                                ? strdup(inherited_gnupghome)
                                : NULL;
    command_runner_fn previous;
    int rc;

    if (had_gnupghome && !saved_gnupghome) {
        CHECK(!"failed to retain GNUPGHOME for source-proof fixture");
        return;
    }
    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(base, sizeof(base),
                               "%s/gitswitch-gpg", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(account, sizeof(account),
                               "%s/account", base), 0);
    CHECK_EQ_INT(safe_snprintf(inside, sizeof(inside),
                               "%s/inside", account), 0);
    CHECK_EQ_INT(safe_snprintf(injected, sizeof(injected),
                               "%s/injected", inside), 0);
    CHECK_EQ_INT(safe_snprintf(external, sizeof(external),
                               "%s/external", xdg), 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(account, 0700), 0);
    CHECK_EQ_INT(mkdir(inside, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", external, 1), 0);
    CHECK_EQ_INT(safe_strncpy(g_source_proof_mutation_from, external,
                              sizeof(g_source_proof_mutation_from)), 0);
    CHECK_EQ_INT(safe_strncpy(g_source_proof_mutation_to, injected,
                              sizeof(g_source_proof_mutation_to)), 0);
    g_source_proof_mutation_mode = SOURCE_PROOF_RENAME_MANAGED_CHILD;
    g_source_proof_mutation_calls = 0;
    g_source_proof_mutation_rc = -1;
    previous = run_set_runner(source_proof_mutation_runner);
    rc = gpg_manager_resolve_system_key("01234567", true, fingerprint,
                                        sizeof(fingerprint));
    safe_strncpy(diagnostic, get_last_error()->message, sizeof(diagnostic));
    run_set_runner(previous);
    CHECK_EQ_INT(g_source_proof_mutation_calls, 1);
    CHECK_EQ_INT(g_source_proof_mutation_rc, 0);
    CHECK_EQ_INT(rc, -1);
    CHECK(fingerprint[0] == '\0');
    CHECK(path_exists(injected));
    CHECK(strstr(diagnostic,
                 "Managed GPG ancestry changed after source proof") != NULL);

    /* The no-base state is a distinct witness. Creating the base while the
     * helper is in flight must invalidate the result instead of accepting a
     * proof that was complete only at the initial observation. */
    CHECK_EQ_INT(make_runtime(absent_xdg, sizeof(absent_xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(absent_base, sizeof(absent_base),
                               "%s/gitswitch-gpg", absent_xdg), 0);
    CHECK_EQ_INT(safe_snprintf(absent_external, sizeof(absent_external),
                               "%s/external", absent_xdg), 0);
    CHECK_EQ_INT(mkdir(absent_external, 0700), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", absent_external, 1), 0);
    g_source_proof_mutation_from[0] = '\0';
    CHECK_EQ_INT(safe_strncpy(g_source_proof_mutation_to, absent_base,
                              sizeof(g_source_proof_mutation_to)), 0);
    g_source_proof_mutation_mode = SOURCE_PROOF_CREATE_MANAGED_BASE;
    g_source_proof_mutation_calls = 0;
    g_source_proof_mutation_rc = -1;
    previous = run_set_runner(source_proof_mutation_runner);
    rc = gpg_manager_resolve_system_key("01234567", true, fingerprint,
                                        sizeof(fingerprint));
    safe_strncpy(diagnostic, get_last_error()->message, sizeof(diagnostic));
    run_set_runner(previous);
    CHECK_EQ_INT(g_source_proof_mutation_calls, 1);
    CHECK_EQ_INT(g_source_proof_mutation_rc, 0);
    CHECK_EQ_INT(rc, -1);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(diagnostic,
                 "Managed GPG base appeared or changed after source proof") !=
          NULL);

    if (had_gnupghome) {
        CHECK_EQ_INT(setenv("GNUPGHOME", saved_gnupghome, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
    }
    free(saved_gnupghome);
}

#ifdef __FreeBSD__
TEST(nullfs_alias_of_managed_home_is_rejected_before_helper_launch) {
    char xdg[128], base[MAX_PATH_LEN], managed[MAX_PATH_LEN];
    char nested[MAX_PATH_LEN], external[MAX_PATH_LEN];
    char alias[MAX_PATH_LEN], fingerprint[GPG_FINGERPRINT_BUFSIZE];
    char diagnostic[512];
    const char *inherited_gnupghome = getenv("GNUPGHOME");
    bool had_gnupghome = inherited_gnupghome != NULL;
    char *saved_gnupghome = had_gnupghome
                                ? strdup(inherited_gnupghome)
                                : NULL;
    command_runner_fn previous;
    int rc;

    if (had_gnupghome && !saved_gnupghome) {
        CHECK(!"failed to retain GNUPGHOME for nullfs fixture");
        return;
    }
    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(base, sizeof(base),
                               "%s/gitswitch-gpg", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(managed, sizeof(managed),
                               "%s/managed", base), 0);
    CHECK_EQ_INT(safe_snprintf(nested, sizeof(nested),
                               "%s/nested", managed), 0);
    CHECK_EQ_INT(safe_snprintf(external, sizeof(external),
                               "%s/external", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(alias, sizeof(alias),
                               "%s/nullfs-alias", xdg), 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(managed, 0700), 0);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(mkdir(alias, 0700), 0);

    if (freebsd_mount_nullfs(managed, alias) != 0) {
        free(saved_gnupghome);
        TS_SKIP("freebsd-nullfs",
                "passwordless sudo/nullfs mount unavailable");
    }
    previous = run_set_runner(source_identity_runner);
    CHECK_EQ_INT(setenv("GNUPGHOME", alias, 1), 0);
    g_source_identity_calls = 0;
    rc = gpg_manager_resolve_system_key("01234567", true, fingerprint,
                                        sizeof(fingerprint));
    safe_strncpy(diagnostic, get_last_error()->message, sizeof(diagnostic));
    if (freebsd_unmount_nullfs(alias) != 0) {
        CHECK(!"failed to unmount direct managed nullfs fixture");
        run_set_runner(previous);
        goto restore_environment;
    }
    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(strstr(diagnostic, "nullfs alias of a managed GPG home") != NULL);

    if (freebsd_mount_nullfs(nested, alias) != 0) {
        CHECK(!"failed to mount nested managed nullfs fixture");
        run_set_runner(previous);
        goto restore_environment;
    }
    g_source_identity_calls = 0;
    rc = gpg_manager_resolve_system_key("01234567", true, fingerprint,
                                        sizeof(fingerprint));
    safe_strncpy(diagnostic, get_last_error()->message, sizeof(diagnostic));
    if (freebsd_unmount_nullfs(alias) != 0) {
        CHECK(!"failed to unmount nested managed nullfs fixture");
        run_set_runner(previous);
        goto restore_environment;
    }
    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(strstr(diagnostic, "nullfs alias of a managed GPG home") != NULL);

    /* Positive control: the helper receives the pinned visible nullfs vnode,
     * while successful resolution proves that its terminal lower directory
     * was independently backed rather than managed. */
    if (freebsd_mount_nullfs(external, alias) != 0) {
        CHECK(!"failed to mount external nullfs fixture");
        run_set_runner(previous);
        goto restore_environment;
    }
    CHECK_EQ_INT(stat(alias, &g_expected_source_identity), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    rc = gpg_manager_resolve_system_key("01234567", true, fingerprint,
                                        sizeof(fingerprint));
    if (freebsd_unmount_nullfs(alias) != 0) {
        CHECK(!"failed to unmount external nullfs fixture");
        run_set_runner(previous);
        goto restore_environment;
    }
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);
    run_set_runner(previous);

restore_environment:
    if (had_gnupghome) {
        CHECK_EQ_INT(setenv("GNUPGHOME", saved_gnupghome, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
    }
    free(saved_gnupghome);
}
#endif

TEST(nested_managed_source_spellings_fail_before_helper_launch) {
    char xdg[128], home[MAX_PATH_LEN], fallback[MAX_PATH_LEN];
    char base[MAX_PATH_LEN], managed[MAX_PATH_LEN], nested[MAX_PATH_LEN];
    char deep[MAX_PATH_LEN], normalized[MAX_PATH_LEN];
    char managed_alias[MAX_PATH_LEN], direct_alias[MAX_PATH_LEN];
    char external[MAX_PATH_LEN], external_alias[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    const char *inherited_home = getenv("HOME");
    const char *inherited_gnupghome = getenv("GNUPGHOME");
    bool had_home = inherited_home != NULL;
    bool had_gnupghome = inherited_gnupghome != NULL;
    char *saved_home = had_home ? strdup(inherited_home) : NULL;
    char *saved_gnupghome = had_gnupghome
                                ? strdup(inherited_gnupghome)
                                : NULL;
    command_runner_fn previous;

    if ((had_home && !saved_home) || (had_gnupghome && !saved_gnupghome)) {
        free(saved_home);
        free(saved_gnupghome);
        CHECK(!"failed to retain source-classification environment");
        return;
    }
    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(home, sizeof(home), "%s/home", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(fallback, sizeof(fallback), "%s/.gnupg",
                               home), 0);
    CHECK_EQ_INT(safe_snprintf(base, sizeof(base), "%s/gitswitch-gpg",
                               xdg), 0);
    CHECK_EQ_INT(safe_snprintf(managed, sizeof(managed), "%s/account",
                               base), 0);
    CHECK_EQ_INT(safe_snprintf(nested, sizeof(nested), "%s/nested",
                               managed), 0);
    CHECK_EQ_INT(safe_snprintf(deep, sizeof(deep), "%s/deeper/leaf",
                               nested), 0);
    CHECK_EQ_INT(safe_snprintf(normalized, sizeof(normalized),
                               "%s/./child/../nested", managed), 0);
    CHECK_EQ_INT(safe_snprintf(managed_alias, sizeof(managed_alias),
                               "%s/managed-alias", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(direct_alias, sizeof(direct_alias),
                               "%s/canonical-alias", base), 0);
    CHECK_EQ_INT(safe_snprintf(external, sizeof(external), "%s/external",
                               xdg), 0);
    CHECK_EQ_INT(safe_snprintf(external_alias, sizeof(external_alias),
                               "%s/external-alias", xdg), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(mkdir(fallback, 0700), 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(managed, 0700), 0);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    {
        char deeper[MAX_PATH_LEN];
        CHECK_EQ_INT(safe_snprintf(deeper, sizeof(deeper), "%s/deeper",
                                   nested), 0);
        CHECK_EQ_INT(mkdir(deeper, 0700), 0);
    }
    CHECK_EQ_INT(mkdir(deep, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(symlink(deep, managed_alias), 0);
    CHECK_EQ_INT(symlink(deep, direct_alias), 0);
    CHECK_EQ_INT(symlink(external, external_alias), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    previous = run_set_runner(source_identity_runner);

    /* A symlink to a genuinely external home remains usable, and the helper
     * receives the resolved object through its pinned cwd descriptor. */
    CHECK_EQ_INT(stat(external, &g_expected_source_identity), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", external_alias, 1), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);

    CHECK_EQ_INT(setenv("GNUPGHOME", nested, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);

    /* A direct-child spelling is normally a canonical managed entry point,
     * but its resolved target is deeper managed state. Descendant
     * classification must dominate instead of selecting HOME/.gnupg. */
    CHECK_EQ_INT(setenv("GNUPGHOME", direct_alias, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);

    CHECK_EQ_INT(setenv("GNUPGHOME", normalized, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);

    CHECK_EQ_INT(setenv("GNUPGHOME", managed_alias, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);

    /* Canonical managed GNUPGHOME still selects HOME/.gnupg, but that
     * fallback is not allowed to resolve back into a nested managed object. */
    CHECK_EQ_INT(rmdir(fallback), 0);
    CHECK_EQ_INT(symlink(nested, fallback), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", managed, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK(fingerprint[0] == '\0');
    CHECK(strstr(get_last_error()->message,
                 "managed GPG descendant") != NULL);

    run_set_runner(previous);
    if (had_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    if (had_gnupghome) {
        CHECK_EQ_INT(setenv("GNUPGHOME", saved_gnupghome, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
    }
    free(saved_home);
    free(saved_gnupghome);
}

TEST(system_resolver_classifies_managed_aliases_before_helper_launch) {
    char xdg[128], home[MAX_PATH_LEN], base[MAX_PATH_LEN];
    char external[MAX_PATH_LEN], alias[MAX_PATH_LEN];
    char dangling_managed[MAX_PATH_LEN], fallback[MAX_PATH_LEN];
    char missing_child[MAX_PATH_LEN], managed_child[MAX_PATH_LEN];
    char fingerprint[GPG_FINGERPRINT_BUFSIZE];
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(safe_snprintf(home, sizeof(home), "%s/home", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(fallback, sizeof(fallback), "%s/.gnupg",
                               home), 0);
    CHECK_EQ_INT(safe_snprintf(external, sizeof(external),
                               "%s/gitswitch-gpg-backup", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(base, sizeof(base), "%s/gitswitch-gpg",
                               xdg), 0);
    CHECK_EQ_INT(safe_snprintf(managed_child, sizeof(managed_child),
                               "%s/account", base), 0);
    CHECK_EQ_INT(safe_snprintf(dangling_managed,
                               sizeof(dangling_managed), "%s/current",
                               base), 0);
    CHECK_EQ_INT(safe_snprintf(alias, sizeof(alias),
                               "%s/dangling-gpg-source", xdg), 0);
    CHECK_EQ_INT(safe_snprintf(missing_child, sizeof(missing_child),
                               "%s/missing-child", base), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(mkdir(fallback, 0700), 0);
    CHECK_EQ_INT(mkdir(external, 0700), 0);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(managed_child, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    previous = run_set_runner(source_identity_runner);

    /* A similarly prefixed but external directory is the exact object passed
     * to GPG, pinned by descriptor rather than returned as a path to a caller. */
    CHECK_EQ_INT(stat(external, &g_expected_source_identity), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", external, 1), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);
    CHECK_STR_EQ(fingerprint, PRIMARY_FPR);

    /* Every managed spelling, including a dangling external alias, falls back
     * to the separately pinned HOME/.gnupg object. */
    CHECK_EQ_INT(stat(fallback, &g_expected_source_identity), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", dangling_managed, 1), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);

    CHECK_EQ_INT(setenv("GNUPGHOME", managed_child, 1), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);

    CHECK_EQ_INT(symlink(dangling_managed, alias), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", alias, 1), 0);
    g_source_identity_calls = 0;
    g_source_identity_pinned = false;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), 0);
    CHECK_EQ_INT(g_source_identity_calls, 1);
    CHECK(g_source_identity_pinned);

    /* Falling back from a managed GNUPGHOME is not permission to follow a
     * HOME/.gnupg alias back into either live or not-yet-created managed state.
     * These failures must happen before the helper is launched. */
    CHECK_EQ_INT(rmdir(fallback), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(managed_child), 0);
    CHECK_EQ_INT(symlink(dangling_managed, fallback), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", dangling_managed, 1), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK_EQ_INT(unlink(fallback), 0);

    CHECK_EQ_INT(gpg_manager_drop_current(), 0);
    CHECK_EQ_INT(symlink(dangling_managed, fallback), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK_EQ_INT(unlink(fallback), 0);

    CHECK_EQ_INT(symlink(managed_child, fallback), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK_EQ_INT(unlink(fallback), 0);

    CHECK_EQ_INT(symlink(missing_child, fallback), 0);
    g_source_identity_calls = 0;
    CHECK_EQ_INT(gpg_manager_resolve_system_key(
                     "01234567", true, fingerprint,
                     sizeof(fingerprint)), -1);
    CHECK_EQ_INT(g_source_identity_calls, 0);
    CHECK_EQ_INT(unlink(fallback), 0);

    run_set_runner(previous);
}

TEST(busy_runtime_never_claims_requested_account_live) {
    char xdg[128], base[512];
    char home[MAX_PATH_LEN], lock_path[MAX_PATH_LEN];
    int ready[2];
    int release[2];
    pid_t child;
    bool live = true;
    int status;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(home, sizeof(home), "%s/other", base);
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(home), 0);
    CHECK_EQ_INT(pipe(ready), 0);
    CHECK_EQ_INT(pipe(release), 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char marker = 'x';
        int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        close(ready[0]);
        close(release[1]);
        if (fd < 0 || flock(fd, LOCK_EX) != 0 ||
            write(ready[1], &marker, 1) != 1) _exit(9);
        if (read(release[0], &marker, 1) != 1) _exit(10);
        flock(fd, LOCK_UN);
        close(fd);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    CHECK_EQ_INT((int)read(ready[0], base, 1), 1);
    close(ready[0]);
    CHECK_EQ_INT(gpg_manager_current_is_live_for_account("requested", &live),
                 -1);
    CHECK(!live);
    CHECK_EQ_INT((int)write(release[1], "x", 1), 1);
    close(release[1]);
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int fail_commit(int base_fd) {
    (void)base_fd;
    return -1;
}

static int g_restore_failures;
static int fail_first_restore(int base_fd) {
    (void)base_fd;
    if (g_restore_failures++ == 0) return -1;
    return 0;
}

static int read_current(char *target, size_t size) {
    char current[MAX_PATH_LEN];
    ssize_t n;
    if (gpg_manager_get_home_path(current, sizeof(current)) != 0) return -1;
    n = readlink(current, target, size - 1);
    if (n <= 0 || (size_t)n >= size - 1) return -1;
    target[n] = '\0';
    return 0;
}

static int make_cas_runtime(char *base, size_t base_size,
                            char *one, size_t one_size,
                            char *two, size_t two_size,
                            char *three, size_t three_size,
                            char *current, size_t current_size) {
    char xdg[128];

    if (make_runtime(xdg, sizeof(xdg)) != 0 ||
        snprintf(base, base_size, "%s/gitswitch-gpg", xdg) >=
            (int)base_size ||
        snprintf(one, one_size, "%s/one", base) >= (int)one_size ||
        snprintf(two, two_size, "%s/two", base) >= (int)two_size ||
        snprintf(three, three_size, "%s/three", base) >= (int)three_size ||
        snprintf(current, current_size, "%s/current", base) >=
            (int)current_size ||
        mkdir(base, 0700) != 0 || mkdir(one, 0700) != 0 ||
        mkdir(two, 0700) != 0 || mkdir(three, 0700) != 0) {
        return -1;
    }
    return 0;
}

static gpg_rollback_hook_stage_t g_writer_stage;
static const char *g_writer_target;
static int rollback_writer_hook(int base_fd,
                                gpg_rollback_hook_stage_t stage,
                                const char *quarantine) {
    (void)quarantine;
    if (stage != g_writer_stage) return 0;
    (void)unlinkat(base_fd, ".gpg-race-writer", 0);
    if (!g_writer_target ||
        symlinkat(g_writer_target, base_fd, ".gpg-race-writer") != 0 ||
        renameat(base_fd, ".gpg-race-writer", base_fd, "current") != 0) {
        return -1;
    }
    return 0;
}

static int unsupported_noreplace(int old_dir_fd, const char *old_name,
                                 int new_dir_fd, const char *new_name) {
    (void)old_dir_fd;
    (void)old_name;
    (void)new_dir_fd;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
}

/* Model FreeBSD's linkat-based fallback when publication succeeds but the
 * source-retirement unlink does not.  The rollback state machine must re-prove
 * both names instead of interpreting success as proof that the source moved. */
static int link_only_noreplace(int old_dir_fd, const char *old_name,
                               int new_dir_fd, const char *new_name) {
    return linkat(old_dir_fd, old_name, new_dir_fd, new_name, 0);
}

static const char *g_wrong_noreplace_target;
static int publish_replaced_source_noreplace(int old_dir_fd,
                                             const char *old_name,
                                             int new_dir_fd,
                                             const char *new_name) {
    if (!g_wrong_noreplace_target ||
        unlinkat(old_dir_fd, old_name, 0) != 0 ||
        symlinkat(g_wrong_noreplace_target, old_dir_fd, old_name) != 0 ||
        linkat(old_dir_fd, old_name, new_dir_fd, new_name, 0) != 0 ||
        unlinkat(old_dir_fd, old_name, 0) != 0) {
        return -1;
    }
    return 0;
}

static int g_sync_calls;
static int g_sync_fail_call;
static int fail_selected_base_sync(int base_fd) {
    g_sync_calls++;
    if (g_sync_calls == g_sync_fail_call) {
        errno = EIO;
        return -1;
    }
    return fsync(base_fd);
}

static int replace_current_writer(const char *base, const char *current,
                                  const char *target) {
    char prepared[MAX_PATH_LEN];

    if (snprintf(prepared, sizeof(prepared), "%s/.gpg-public-done-writer",
                 base) >= (int)sizeof(prepared)) {
        return -1;
    }
    (void)unlink(prepared);
    if (symlink(target, prepared) != 0 || rename(prepared, current) != 0) {
        (void)unlink(prepared);
        return -1;
    }
    return 0;
}

TEST(rollback_cas_preserves_same_target_and_distinct_later_writers) {
    char base[512], one[512], two[512], three[512], current[512], target[512];
    struct stat original;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = true;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    CHECK_EQ_INT(lstat(current, &original), 0);

    /* Same-target ABA: spelling equality must not authorize removal. The hook
     * installs a different inode after the retained identity was captured but
     * before the native no-replace move. */
    g_writer_stage = GPG_ROLLBACK_HOOK_BEFORE_QUARANTINE;
    g_writer_target = one;
    gpg_manager_set_rollback_hook_fn(rollback_writer_hook);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(original.st_dev != replacement.st_dev ||
          original.st_ino != replacement.st_ino);

    /* A distinct writer in the same window is likewise moved, classified as
     * foreign, and restored without ever being overwritten by `three`. */
    memset(&config, 0, sizeof(config));
    g_writer_target = two;
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* Writer-after-quarantine: current is empty only briefly; a later writer
     * occupying it wins and the owned quarantine alone is retired. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    g_writer_stage = GPG_ROLLBACK_HOOK_AFTER_QUARANTINE;
    g_writer_target = two;
    changed = true;
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);
    gpg_manager_set_rollback_hook_fn(NULL);
    g_writer_target = NULL;
}

TEST(rollback_cas_retries_stale_collision_unsupported_and_sync_states) {
    char base[512], one[512], two[512], three[512], current[512], target[512];
    char stale[640];
    struct stat current_stat;
    gpg_config_t config = {0};
    bool changed = false;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    snprintf(stale, sizeof(stale),
             "%s/.gitswitch-gpg-rollback.preplanted", base);
    CHECK_EQ_INT(symlink(two, stale), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    /* The stale artifact is a preflight blocker: no namespace mutation has
     * occurred yet, so there must be no fabricated rollback ownership. */
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    CHECK_EQ_INT(unlink(stale), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    gpg_manager_set_rename_noreplace_fn(unsupported_noreplace);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    gpg_manager_set_rename_noreplace_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    gpg_manager_set_rename_noreplace_fn(link_only_noreplace);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);
    gpg_manager_set_rename_noreplace_fn(NULL);

    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = false;
    gpg_manager_set_rename_noreplace_fn(link_only_noreplace);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);
    gpg_manager_set_rename_noreplace_fn(NULL);
    memset(&config, 0, sizeof(config));
    changed = false;
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, three, one,
                                                &changed), 0);
    CHECK(changed);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, one);

    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_wrong_noreplace_target = two;
    gpg_manager_set_rename_noreplace_fn(publish_replaced_source_noreplace);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), -1);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);
    gpg_manager_set_rename_noreplace_fn(NULL);
    g_wrong_noreplace_target = NULL;

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(!config.rollback.final_present);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK(lstat(current, &current_stat) != 0 && errno == ENOENT);
}

TEST(public_done_retry_reproves_owned_present_identity) {
    char base[MAX_PATH_LEN], one[MAX_PATH_LEN], two[MAX_PATH_LEN];
    char three[MAX_PATH_LEN], current[MAX_PATH_LEN], target[MAX_PATH_LEN];
    struct stat intended;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = false;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);

    /* An unchanged retry can truthfully report success after re-proving the
     * exact privately captured restoration inode. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(config.rollback.final_present);
    CHECK(config.rollback.final_link.valid);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* Same-target ABA after the failed PUBLIC_DONE fsync is a conflict because
     * spelling equality cannot prove ownership of the replacement inode. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK_EQ_INT(lstat(current, &intended), 0);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, three), 0);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(intended.st_dev != replacement.st_dev ||
          intended.st_ino != replacement.st_ino);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* Removal and a distinct managed writer after PUBLIC_DONE likewise retire
     * the old token as conflicts instead of returning stale success. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(unlink(current), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK(lstat(current, &replacement) != 0 && errno == ENOENT);

    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), -1);
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, two), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);
}

TEST(public_done_retry_reproves_absence_and_direct_publication) {
    char base[MAX_PATH_LEN], one[MAX_PATH_LEN], two[MAX_PATH_LEN];
    char three[MAX_PATH_LEN], current[MAX_PATH_LEN], target[MAX_PATH_LEN];
    struct stat intended;
    struct stat replacement;
    gpg_config_t config = {0};
    bool changed = true;

    CHECK_EQ_INT(make_cas_runtime(base, sizeof(base), one, sizeof(one),
                                  two, sizeof(two), three, sizeof(three),
                                  current, sizeof(current)), 0);

    /* A writer appearing after an absent restoration reached PUBLIC_DONE
     * invalidates success while remaining untouched. */
    CHECK_EQ_INT(gpg_manager_retarget_current(one), 0);
    g_sync_calls = 0;
    g_sync_fail_call = 2;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(!config.rollback.final_present);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, two), 0);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, one, NULL,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, two);

    /* Direct absent-to-present restoration uses the same private publication
     * identity. First prove its positive retry, including pending retirement. */
    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = false;
    g_sync_calls = 0;
    g_sync_fail_call = 1;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), -1);
    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(config.rollback.phase == GPG_ROLLBACK_PUBLIC_DONE);
    CHECK(config.rollback.final_state_valid);
    CHECK(config.rollback.final_present);
    CHECK(config.rollback.final_link.valid);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), 0);
    CHECK(changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);

    /* A same-target ABA before that direct retry is still a conflict. */
    CHECK_EQ_INT(unlink(current), 0);
    memset(&config, 0, sizeof(config));
    changed = true;
    g_sync_calls = 0;
    g_sync_fail_call = 1;
    gpg_manager_set_sync_base_fn(fail_selected_base_sync);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), -1);
    CHECK_EQ_INT(lstat(current, &intended), 0);
    gpg_manager_set_sync_base_fn(NULL);
    CHECK_EQ_INT(replace_current_writer(base, current, three), 0);
    CHECK_EQ_INT(lstat(current, &replacement), 0);
    CHECK(intended.st_dev != replacement.st_dev ||
          intended.st_ino != replacement.st_ino);
    CHECK_EQ_INT(gpg_manager_restore_current_if(&config, NULL, three,
                                                &changed), 0);
    CHECK(!changed);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, three);
}

TEST(failed_retarget_retains_dirty_state_until_controlled_retry) {
    char xdg[128], base[512];
    char old_home[MAX_PATH_LEN], target[MAX_PATH_LEN];
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    setenv("GNUPGHOME", "/external/before-rollback", 1);
    snprintf(base, sizeof(base), "%s/gitswitch-gpg", xdg);
    snprintf(old_home, sizeof(old_home), "%s/old", base);
    CHECK_EQ_INT(mkdir(base, 0700), 0);
    CHECK_EQ_INT(mkdir(old_home, 0700), 0);
    CHECK_EQ_INT(gpg_manager_retarget_current(old_home), 0);
    fill_account(&account, "new", "01234567", true);
    g_fake_mode = FAKE_PRESENT;
    previous = run_set_runner(strict_key_runner);
    g_restore_failures = 0;
    gpg_manager_set_retarget_commit_hook_fn(fail_commit);
    gpg_manager_set_retarget_restore_hook_fn(fail_first_restore);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    gpg_manager_set_retarget_commit_hook_fn(NULL);
    gpg_manager_set_retarget_restore_hook_fn(NULL);
    run_set_runner(previous);

    CHECK(gpg_manager_runtime_restore_pending(&config));
    CHECK(strstr(get_last_error()->message, "rollback failed") != NULL);
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK(strstr(target, "/new") != NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(!gpg_manager_runtime_restore_pending(&config));
    CHECK_EQ_INT(read_current(target, sizeof(target)), 0);
    CHECK_STR_EQ(target, old_home);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/before-rollback");
}

static const char *g_fail_env_set_name;
static const char *g_fail_env_unset_name;
static bool g_unset_before_failure;
static int fault_setenv(const char *name, const char *value, int overwrite) {
    if (g_fail_env_set_name && strcmp(name, g_fail_env_set_name) == 0) {
        errno = EIO;
        return -1;
    }
    return setenv(name, value, overwrite);
}

static int fault_unsetenv(const char *name) {
    if (g_fail_env_unset_name && strcmp(name, g_fail_env_unset_name) == 0) {
        if (g_unset_before_failure) {
            (void)unsetenv(name);
        }
        errno = EIO;
        return -1;
    }
    return unsetenv(name);
}

TEST(environment_failures_are_fatal_and_retryable) {
    char xdg[128], current[MAX_PATH_LEN];
    struct stat st;
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    setenv("GNUPGHOME", "/external/env-before", 1);
    fill_account(&account, "envset", "01234567", true);
    g_fake_mode = FAKE_PRESENT;
    previous = run_set_runner(strict_key_runner);
    g_fail_env_set_name = "GNUPGHOME";
    gpg_manager_set_setenv_fn(fault_setenv);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    CHECK_EQ_INT(gpg_manager_get_home_path(current, sizeof(current)), 0);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/env-before");
    g_fail_env_set_name = NULL;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    g_fail_env_set_name = "GNUPGHOME";
    gpg_manager_set_setenv_fn(fault_setenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(config.current_key_id[0] != '\0');
    g_fail_env_set_name = NULL;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/env-before");

    unsetenv("GNUPGHOME");
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "envunset", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    g_fail_env_unset_name = "GNUPGHOME";
    gpg_manager_set_unsetenv_fn(fault_unsetenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(config.current_key_id[0] != '\0');
    g_fail_env_unset_name = NULL;
    gpg_manager_set_unsetenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GNUPGHOME") == NULL);

    CHECK_EQ_INT(setenv("GNUPGHOME", "", 1), 0);
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "envempty", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GNUPGHOME") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), "");
    run_set_runner(previous);
}

TEST(legacy_agent_environment_failures_are_fatal_and_retryable) {
    char xdg[128], current[MAX_PATH_LEN];
    char overlong_agent[MAX_PATH_LEN + 1U];
    const char *seeded_agent = "/external/S.gpg-agent:4242:1";
    const char *inherited_home = getenv("GNUPGHOME");
    const char *inherited_agent = getenv("GPG_AGENT_INFO");
    char *saved_home = inherited_home ? strdup(inherited_home) : NULL;
    char *saved_agent = inherited_agent ? strdup(inherited_agent) : NULL;
    bool home_present = inherited_home != NULL;
    bool agent_present = inherited_agent != NULL;
    struct stat st;
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous;

    CHECK(!home_present || saved_home != NULL);
    CHECK(!agent_present || saved_agent != NULL);
    if ((home_present && !saved_home) || (agent_present && !saved_agent)) {
        free(saved_home);
        free(saved_agent);
        return;
    }

    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(setenv("GNUPGHOME", "/external/agent-before", 1), 0);
    g_fake_mode = FAKE_PRESENT;
    previous = run_set_runner(strict_key_runner);

    /* An unrestorable inherited selector is rejected before either process
     * variable is mutated or the stable runtime is published. */
    memset(overlong_agent, 'A', MAX_PATH_LEN);
    overlong_agent[MAX_PATH_LEN] = '\0';
    CHECK_EQ_INT(setenv("GPG_AGENT_INFO", overlong_agent, 1), 0);
    fill_account(&account, "agent-overlong", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    CHECK(strstr(get_last_error()->message,
                 "GPG_AGENT_INFO is too long") != NULL);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK(getenv("GPG_AGENT_INFO") != NULL);
    if (getenv("GPG_AGENT_INFO")) {
        CHECK_EQ_INT((long)strlen(getenv("GPG_AGENT_INFO")), MAX_PATH_LEN);
    }
    CHECK(!config.environment_installed);
    CHECK_EQ_INT(gpg_manager_get_home_path(current, sizeof(current)), 0);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);

    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    CHECK_EQ_INT(setenv("GPG_AGENT_INFO", seeded_agent, 1), 0);

    /* Suppression is part of installation, not a best-effort cleanup. Its
     * failure rolls GNUPGHOME back and publishes no stable runtime. */
    fill_account(&account, "agent-suppress", "01234567", true);
    g_fail_env_unset_name = "GPG_AGENT_INFO";
    gpg_manager_set_unsetenv_fn(fault_unsetenv);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK_STR_EQ(getenv("GPG_AGENT_INFO"), seeded_agent);
    CHECK(!config.environment_installed);
    CHECK(!config.gnupg_home_environment_installed);
    CHECK(!config.gpg_agent_info_suppressed);
    CHECK_EQ_INT(gpg_manager_get_home_path(current, sizeof(current)), 0);
    CHECK(lstat(current, &st) != 0 && errno == ENOENT);
    g_fail_env_unset_name = NULL;
    gpg_manager_set_unsetenv_fn(NULL);

    /* A failing environment primitive may have changed the process before
     * reporting its error. Rollback ownership is published before the call,
     * so this ambiguous failure still restores the exact inherited value. */
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    CHECK_EQ_INT(setenv("GPG_AGENT_INFO", seeded_agent, 1), 0);
    fill_account(&account, "agent-mutating-failure", "01234567", true);
    g_unset_before_failure = true;
    g_fail_env_unset_name = "GPG_AGENT_INFO";
    gpg_manager_set_unsetenv_fn(fault_unsetenv);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), -1);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK_STR_EQ(getenv("GPG_AGENT_INFO"), seeded_agent);
    CHECK(!config.environment_installed);
    CHECK(!config.gnupg_home_environment_installed);
    CHECK(!config.gpg_agent_info_suppressed);
    g_unset_before_failure = false;
    g_fail_env_unset_name = NULL;
    gpg_manager_set_unsetenv_fn(NULL);

    /* A failed exact-value restore keeps only the selector leg pending. The
     * already-restored GNUPGHOME is not rewritten during the retry. */
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "agent-restore", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK(getenv("GPG_AGENT_INFO") == NULL);
    g_fail_env_set_name = "GPG_AGENT_INFO";
    gpg_manager_set_setenv_fn(fault_setenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(!config.gnupg_home_environment_installed);
    CHECK(config.gpg_agent_info_suppressed);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK(getenv("GPG_AGENT_INFO") == NULL);
    CHECK_EQ_INT(gpg_set_environment(&config), -1);
    CHECK(strstr(get_last_error()->message,
                 "environment restoration is incomplete") != NULL);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK(getenv("GPG_AGENT_INFO") == NULL);
    g_fail_env_set_name = NULL;
    gpg_manager_set_setenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GPG_AGENT_INFO"), seeded_agent);

    /* Absence is also exact state. A failed unset remains retryable after the
     * home leg succeeds, then a second cleanup restores absence. */
    CHECK_EQ_INT(unsetenv("GPG_AGENT_INFO"), 0);
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "agent-absent", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    g_fail_env_unset_name = "GPG_AGENT_INFO";
    gpg_manager_set_unsetenv_fn(fault_unsetenv);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), -1);
    CHECK(config.environment_installed);
    CHECK(!config.gnupg_home_environment_installed);
    CHECK(config.gpg_agent_info_suppressed);
    CHECK_STR_EQ(getenv("GNUPGHOME"), "/external/agent-before");
    CHECK(getenv("GPG_AGENT_INFO") == NULL);
    g_fail_env_unset_name = NULL;
    gpg_manager_set_unsetenv_fn(NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GPG_AGENT_INFO") == NULL);

    /* Explicit emptiness remains distinct from absence for both variables. */
    CHECK_EQ_INT(setenv("GNUPGHOME", "", 1), 0);
    CHECK_EQ_INT(setenv("GPG_AGENT_INFO", "", 1), 0);
    memset(&config, 0, sizeof(config));
    config.mode = GPG_MODE_ISOLATED;
    fill_account(&account, "agent-empty", "01234567", true);
    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK(getenv("GNUPGHOME") != NULL);
    CHECK(getenv("GPG_AGENT_INFO") != NULL);
    if (getenv("GNUPGHOME")) CHECK_STR_EQ(getenv("GNUPGHOME"), "");
    if (getenv("GPG_AGENT_INFO")) {
        CHECK_STR_EQ(getenv("GPG_AGENT_INFO"), "");
    }

    run_set_runner(previous);
    g_fail_env_set_name = NULL;
    g_fail_env_unset_name = NULL;
    g_unset_before_failure = false;
    gpg_manager_set_setenv_fn(NULL);
    gpg_manager_set_unsetenv_fn(NULL);
    if (home_present) {
        CHECK_EQ_INT(setenv("GNUPGHOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GNUPGHOME"), 0);
    }
    if (agent_present) {
        CHECK_EQ_INT(setenv("GPG_AGENT_INFO", saved_agent, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GPG_AGENT_INFO"), 0);
    }
    free(saved_home);
    free(saved_agent);
}

TEST(legacy_agent_environment_is_suppressed_and_restored) {
    char xdg[128];
    const char *seeded_agent = "/external/S.gpg-agent:4242:1";
    char *saved_agent = NULL;
    const char *previous_agent = getenv("GPG_AGENT_INFO");
    gpg_config_t config = { .mode = GPG_MODE_ISOLATED };
    account_t account;
    command_runner_fn previous_runner;

    if (previous_agent) {
        saved_agent = strdup(previous_agent);
        CHECK(saved_agent != NULL);
        if (!saved_agent) return;
    }
    CHECK_EQ_INT(make_runtime(xdg, sizeof(xdg)), 0);
    CHECK_EQ_INT(setenv("GPG_AGENT_INFO", seeded_agent, 1), 0);
    fill_account(&account, "legacy-agent", "01234567", true);
    g_fake_mode = FAKE_PRESENT;
    previous_runner = run_set_runner(strict_key_runner);

    CHECK_EQ_INT(gpg_switch_account(&config, &account), 0);
    CHECK(getenv("GPG_AGENT_INFO") == NULL);
    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_STR_EQ(getenv("GPG_AGENT_INFO"), seeded_agent);

    run_set_runner(previous_runner);
    if (saved_agent) {
        CHECK_EQ_INT(setenv("GPG_AGENT_INFO", saved_agent, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("GPG_AGENT_INFO"), 0);
    }
    free(saved_agent);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(strict_capability_parser_rejects_unusable_keys);
    RUN_TEST(selector_inventory_is_exact_and_canonical);
    RUN_TEST(secret_listing_result_matrix_is_causal_and_exact);
    RUN_TEST(structured_status_distinguishes_absence_from_keyring_failure);
    RUN_TEST(truncated_secret_listing_is_one_shot_at_the_documented_cap);
    RUN_TEST(system_key_helper_stays_on_pinned_source_after_directory_replacement);
#ifdef __linux__
    RUN_TEST(bind_alias_of_managed_home_is_rejected_before_helper_launch);
#endif
#ifdef __FreeBSD__
    RUN_TEST(nullfs_alias_of_managed_home_is_rejected_before_helper_launch);
#endif
    RUN_TEST(source_proof_rejects_managed_tree_mutation_during_helper);
    RUN_TEST(ambiguous_selector_exports_and_imports_nothing);
    RUN_TEST(unique_selector_threads_fingerprint_through_import_and_publication);
    RUN_TEST(post_import_fingerprint_mismatch_is_not_signing_readiness);
    RUN_TEST(full_v5_fingerprint_selector_survives_switch_and_git_publication);
    RUN_TEST(disabled_signing_keeps_canonical_identity_and_all_writes_are_fatal);
    RUN_TEST(nested_managed_source_spellings_fail_before_helper_launch);
    RUN_TEST(system_resolver_classifies_managed_aliases_before_helper_launch);
    RUN_TEST(busy_runtime_never_claims_requested_account_live);
    RUN_TEST(failed_retarget_retains_dirty_state_until_controlled_retry);
    RUN_TEST(rollback_cas_preserves_same_target_and_distinct_later_writers);
    RUN_TEST(rollback_cas_retries_stale_collision_unsupported_and_sync_states);
    RUN_TEST(public_done_retry_reproves_owned_present_identity);
    RUN_TEST(public_done_retry_reproves_absence_and_direct_publication);
    RUN_TEST(environment_failures_are_fatal_and_retryable);
    RUN_TEST(legacy_agent_environment_failures_are_fatal_and_retryable);
    RUN_TEST(legacy_agent_environment_is_suppressed_and_restored);
TEST_MAIN_END()
